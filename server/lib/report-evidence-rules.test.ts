import { describe, it, expect } from "vitest";

// ─── Detection Rules Engine Tests ───────────────────────────────────────────

describe("Detection Rules Engine", () => {
  it("should extract IOCs from engagement assets", async () => {
    const { extractIOCsFromEngagement } = await import("./detection-rules-engine");
    const assets = [
      {
        hostname: "bwapp.example.com",
        ip: "192.168.1.100",
        technologies: ["Apache/2.4.49", "PHP/7.4", "MySQL/5.7"],
        knownPorts: [{ port: 80, service: "http" }, { port: 443, service: "https" }],
        vulns: [
          {
            attack: "' OR 1=1--",
            url: "/sqli.php",
            param: "id",
            evidence: "Parameter 'id' is vulnerable to SQL injection",
          },
        ],
        toolResults: [
          {
            rawOutput: "Found SQL injection in /sqli.php?id=1",
            findings: [{ attack: "UNION SELECT", param: "id", url: "/sqli.php" }],
          },
        ],
        exploitAttempts: [
          {
            payload: "' UNION SELECT username,password FROM users--",
            output: "admin:password123",
          },
        ],
      },
    ];

    const iocs = extractIOCsFromEngagement(assets);

    expect(iocs.targetIPs).toContain("192.168.1.100");
    expect(iocs.targetHostnames).toContain("bwapp.example.com");
    expect(iocs.attackPayloads.length).toBeGreaterThan(0);
    expect(iocs.attackPayloads).toContain("' OR 1=1--");
    expect(iocs.vulnerableURLs).toContain("/sqli.php");
    expect(iocs.vulnerableParams).toContain("id");
    expect(iocs.detectedSoftware.length).toBeGreaterThan(0);
    expect(iocs.detectedPorts).toContain(80);
    expect(iocs.detectedPorts).toContain(443);
  });

  it("should extract technologies with version parsing", async () => {
    const { extractIOCsFromEngagement } = await import("./detection-rules-engine");
    const assets = [
      {
        hostname: "test.com",
        technologies: ["Apache 2.4.49", "PHP 7.4.3", "jQuery"],
        knownPorts: [],
        vulns: [],
        toolResults: [],
        exploitAttempts: [],
      },
    ];

    const iocs = extractIOCsFromEngagement(assets);
    const apache = iocs.detectedSoftware.find(s => s.name === "Apache");
    expect(apache).toBeDefined();
    expect(apache!.version).toBe("2.4.49");
    const jquery = iocs.detectedSoftware.find(s => s.name === "jQuery");
    expect(jquery).toBeDefined();
  });

  it("should deduplicate IOCs", async () => {
    const { extractIOCsFromEngagement } = await import("./detection-rules-engine");
    const assets = [
      {
        hostname: "test.com",
        ip: "10.0.0.1",
        knownPorts: [80, 80, 443],
        vulns: [
          { attack: "' OR 1=1--", url: "/login", param: "user" },
          { attack: "' OR 1=1--", url: "/login", param: "user" },
        ],
        toolResults: [],
        exploitAttempts: [],
      },
    ];

    const iocs = extractIOCsFromEngagement(assets);
    // Should be deduplicated
    expect(iocs.targetIPs.filter(ip => ip === "10.0.0.1").length).toBe(1);
    expect(iocs.attackPayloads.filter(p => p === "' OR 1=1--").length).toBe(1);
  });

  it("should post-process LLM-generated rules with real IOCs for SQLi", async () => {
    const { postProcessDetectionRules } = await import("./detection-rules-engine");

    const findings = [
      {
        title: "SQL Injection in Login Form",
        severity: "Critical",
        cve: "CVE-2021-12345",
        cweId: "CWE-89",
        affectedAssets: ["bwapp.example.com"],
        owaspCategory: "A03:2021",
        detectionRules: {
          sigma: null,
          suricata: null,
          yara: null,
        },
      },
    ];

    const iocs = {
      targetIPs: ["192.168.1.100"],
      targetHostnames: ["bwapp.example.com"],
      detectedSoftware: [{ name: "Apache", version: "2.4" }],
      attackPayloads: ["' OR 1=1--"],
      vulnerableParams: ["username"],
      vulnerableURLs: ["/login.php"],
      exploitModules: [],
      detectedPorts: [80, 443],
    };

    postProcessDetectionRules(findings, iocs);

    // Sigma rule should now be populated with real data
    expect(findings[0].detectionRules.sigma).toBeDefined();
    expect(findings[0].detectionRules.sigma).not.toBeNull();
    expect(findings[0].detectionRules.sigma!).toContain("title:");
    expect(findings[0].detectionRules.sigma!).toContain("SQL");

    // Suricata rule should be populated
    expect(findings[0].detectionRules.suricata).toBeDefined();
    expect(findings[0].detectionRules.suricata).not.toBeNull();
  });

  it("should classify XSS findings correctly", async () => {
    const { postProcessDetectionRules } = await import("./detection-rules-engine");

    const xssFindings = [
      {
        title: "Cross-Site Scripting (XSS) in Search",
        severity: "Medium",
        cweId: "CWE-79",
        affectedAssets: ["test.com"],
        detectionRules: { sigma: null, suricata: null, yara: null },
      },
    ];

    const iocs = {
      targetIPs: ["10.0.0.1"],
      targetHostnames: ["test.com"],
      detectedSoftware: [],
      attackPayloads: ["<script>alert(1)</script>"],
      vulnerableParams: ["q"],
      vulnerableURLs: ["/search"],
      exploitModules: [],
      detectedPorts: [80],
    };

    postProcessDetectionRules(xssFindings, iocs);
    expect(xssFindings[0].detectionRules.sigma).toBeDefined();
    expect(xssFindings[0].detectionRules.sigma).not.toBeNull();
  });

  it("should replace placeholder rules", async () => {
    const { postProcessDetectionRules } = await import("./detection-rules-engine");

    const findings = [
      {
        title: "Command Injection",
        severity: "Critical",
        cweId: "CWE-78",
        affectedAssets: ["target.com"],
        detectionRules: {
          sigma: "# TODO: Add detection rule",
          suricata: "# Placeholder",
          yara: null,
        },
      },
    ];

    const iocs = {
      targetIPs: ["192.168.1.50"],
      targetHostnames: ["target.com"],
      detectedSoftware: [],
      attackPayloads: ["; cat /etc/passwd"],
      vulnerableParams: ["cmd"],
      vulnerableURLs: ["/api/exec"],
      exploitModules: [],
      detectedPorts: [80],
    };

    postProcessDetectionRules(findings, iocs);
    // Should have replaced placeholder with real rule
    expect(findings[0].detectionRules.sigma).not.toContain("TODO");
    expect(findings[0].detectionRules.sigma).not.toContain("Placeholder");
  });
});

// ─── Context-Aware Scanner Tests ────────────────────────────────────────────

describe("Context-Aware Scanner", () => {
  it("should detect WAF from response headers", async () => {
    const { detectWAF } = await import("./context-aware-scanner");
    const waf = detectWAF(
      { "server": "cloudflare", "cf-ray": "abc123-LAX" },
      [],
      "",
      200
    );

    expect(waf).toBeDefined();
    expect(waf.detected).toBe(true);
    expect(waf.vendor).toBe("cloudflare");
    expect(waf.confidence).toBeGreaterThan(0);
  });

  it("should return WAF profile with low confidence for generic headers", async () => {
    const { detectWAF } = await import("./context-aware-scanner");
    const waf = detectWAF(
      { "content-type": "text/html" },
      [],
      "<html>Hello</html>",
      200
    );

    expect(waf).toBeDefined();
    // With no WAF-specific headers, confidence should be low
    expect(waf.confidence).toBeLessThan(50);
  });

  it("should detect CDN from response headers", async () => {
    const { detectCDN } = await import("./context-aware-scanner");
    const cdn = detectCDN(
      { "x-amz-cf-id": "abc123", "via": "1.1 cloudfront.net" },
      ["d1234.cloudfront.net"]
    );

    expect(cdn).toBeDefined();
    expect(cdn.detected).toBe(true);
    expect(cdn.provider).toBe("cloudfront");
  });

  it("should not detect CDN when no signatures match", async () => {
    const { detectCDN } = await import("./context-aware-scanner");
    const cdn = detectCDN(
      { "server": "Apache/2.4.49" },
      []
    );

    expect(cdn).toBeDefined();
    expect(cdn.detected).toBe(false);
  });

  it("should classify asset roles correctly", async () => {
    const { classifyAssetRole } = await import("./context-aware-scanner");
    const result = classifyAssetRole(
      {
        serverHeader: "nginx/1.21.3",
        webServer: { name: "nginx", version: "1.21.3", role: "proxy" },
        appFramework: null,
        cms: null,
        os: null,
        tls: null,
        languages: [],
        jsFrameworks: [],
        databases: [],
        techTags: [],
        serviceBanners: {},
      },
      [80, 443],
      { "x-forwarded-for": "true", "x-real-ip": "true" }
    );

    expect(result).toBeDefined();
    expect(result.role).toBeDefined();
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.rationale).toBeDefined();
  });

  it("should generate scan strategy with phases", async () => {
    const { generateScanStrategy } = await import("./context-aware-scanner");
    const strategy = generateScanStrategy({
      hostname: "test.example.com",
      ips: ["192.168.1.100"],
      fingerprint: {
        serverHeader: "Apache/2.4.49",
        webServer: { name: "Apache", version: "2.4.49", role: "origin" },
        appFramework: { name: "PHP", version: "7.4", language: "PHP" },
        cms: null,
        os: null,
        tls: null,
        languages: ["PHP"],
        jsFrameworks: [],
        databases: ["MySQL"],
        techTags: ["Apache", "PHP", "MySQL"],
        serviceBanners: {},
      },
      waf: {
        detected: false,
        vendor: null,
        type: "unknown",
        confidence: 0,
        detectionMethod: "none",
        bypassTechniques: [],
        evasionProfile: {
          level: "none",
          techniques: [],
          toolFlags: {},
          rationale: "No WAF detected",
        },
        inScope: false,
        detectedRules: [],
      },
      cdn: {
        detected: false,
        provider: null,
        evidence: [],
        originIp: null,
        originDiscoveryMethod: null,
        originInScope: false,
        cdnHeaders: {},
        hasBuiltInWAF: false,
      },
      firewall: {
        detected: false,
        type: "unknown",
        filteredPorts: [],
        rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null },
        geoBlocking: false,
        ipReputationBlocking: false,
      },
      topology: {
        host: "test.example.com",
        role: "web_application",
        confidence: 80,
        backend: null,
        services: [{ port: 80, service: "http", version: "Apache/2.4.49" }, { port: 443, service: "https", version: null }],
        directlyReachable: true,
      },
      environment: "traditional",
      riskProfile: "standard",
      scopeConstraints: {
        wafBypassAuthorized: false,
        cdnOriginAuthorized: false,
        bruteForceAuthorized: true,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 10,
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "pentest",
      },
      profiledAt: Date.now(),
    });

    expect(strategy).toBeDefined();
    expect(strategy.phases.length).toBeGreaterThan(0);
    expect(strategy.name).toBeDefined();
    expect(strategy.evasionProfile).toBeDefined();
    expect(strategy.estimatedTimeMinutes).toBeGreaterThan(0);
    // Should have port discovery as first phase
    expect(strategy.phases[0].name).toContain("port");
  });
});

// ─── Asset Status Derivation Tests ──────────────────────────────────────────

describe("Asset Status Derivation", () => {
  it("should derive 'compromised' when exploits succeeded", () => {
    const asset = {
      exploitAttempts: [{ success: true, module: "sqli" }],
      vulns: [{ title: "SQLi" }],
      toolResults: [{ tool: "nuclei" }],
    };
    const status = deriveStatus(asset);
    expect(status).toBe("compromised");
  });

  it("should derive 'vulnerable' when vulns exist but no exploits", () => {
    const asset = {
      exploitAttempts: [],
      vulns: [{ title: "XSS" }],
      toolResults: [{ tool: "nuclei" }],
    };
    const status = deriveStatus(asset);
    expect(status).toBe("vulnerable");
  });

  it("should derive 'scanned' when tool results exist but no vulns", () => {
    const asset = {
      exploitAttempts: [],
      vulns: [],
      toolResults: [{ tool: "httpx" }],
    };
    const status = deriveStatus(asset);
    expect(status).toBe("scanned");
  });

  it("should derive 'enumerated' when only ports are known", () => {
    const asset = {
      exploitAttempts: [],
      vulns: [],
      toolResults: [],
      ports: [{ port: 80 }],
    };
    const status = deriveStatus(asset);
    expect(status).toBe("enumerated");
  });

  it("should derive 'discovered' as fallback", () => {
    const asset = {
      exploitAttempts: [],
      vulns: [],
      toolResults: [],
      ports: [],
    };
    const status = deriveStatus(asset);
    expect(status).toBe("discovered");
  });
});

// Helper function matching the one in reports-core.ts
function deriveStatus(asset: any): string {
  const hasExploits = (asset.exploitAttempts || []).some((ea: any) => ea.success);
  if (hasExploits) return "compromised";
  const hasVulns = (asset.vulns || []).length > 0;
  const hasToolResults = (asset.toolResults || []).length > 0;
  if (hasVulns) return "vulnerable";
  if (hasToolResults) return "scanned";
  const hasPorts = (asset.knownPorts || []).length > 0 || (asset.ports || []).length > 0;
  if (hasPorts) return "enumerated";
  return "discovered";
}

// ─── Scanforge Knowledge Tests ──────────────────────────────────────────────

describe("Scanforge Knowledge", () => {
  it("should include Nerva in the tool registry", async () => {
    const { SCANFORGE_TOOLS } = await import("./scanforge-knowledge");
    const nerva = SCANFORGE_TOOLS.find(t => t.name === "Nerva");
    expect(nerva).toBeDefined();
    expect(nerva!.accuracy).toBe("high");
    expect(nerva!.outputFormat).toContain("JSON");
    expect(nerva!.primaryUseCase).toContain("fingerprint");
  });

  it("should include httpx in the tool registry", async () => {
    const { SCANFORGE_TOOLS } = await import("./scanforge-knowledge");
    const httpx = SCANFORGE_TOOLS.find(t => t.name === "httpx");
    expect(httpx).toBeDefined();
    expect(httpx!.speed).toBe("fast");
  });

  it("should include SSH-related tools in the tool registry", async () => {
    const { SCANFORGE_TOOLS } = await import("./scanforge-knowledge");
    const sshTool = SCANFORGE_TOOLS.find(t => t.name.toLowerCase().includes("ssh"));
    expect(sshTool).toBeDefined();
  });

  it("should include technology signatures for WordPress", async () => {
    const { TECH_SIGNATURES } = await import("./scanforge-knowledge");
    const wp = TECH_SIGNATURES.find(t => t.technology === "WordPress");
    expect(wp).toBeDefined();
    expect(wp!.recommendedTools.length).toBeGreaterThan(0);
    expect(wp!.indicators).toContain("wordpress");
  });

  it("should include technology signatures for SSH", async () => {
    const { TECH_SIGNATURES } = await import("./scanforge-knowledge");
    const ssh = TECH_SIGNATURES.find(t => t.technology === "SSH");
    expect(ssh).toBeDefined();
    expect(ssh!.recommendedTools).toContain("ssh-audit");
  });

  it("should build optimal scanforge command pipeline", async () => {
    const { buildOptimalScanforgeCommand } = await import("./scanforge-knowledge");
    const pipeline = buildOptimalScanforgeCommand({
      detectedTech: ["Apache", "PHP"],
      stealthLevel: "medium",
      scanType: "full",
      target: "192.168.1.100",
      targetSize: "single",
    });

    expect(pipeline).toBeDefined();
    expect(pipeline.discoveryCmd).toBeDefined();
    expect(pipeline.fingerprintCmd).toBeDefined();
    expect(pipeline.vulnCmd).toBeDefined();
    expect(pipeline.pipeline).toBeDefined();
    // Pipeline should chain discovery → fingerprint → vuln
    expect(pipeline.pipeline).toContain("|");
  });

  it("should include boundary detection command", async () => {
    const { buildOptimalScanforgeCommand } = await import("./scanforge-knowledge");
    const pipeline = buildOptimalScanforgeCommand({
      detectedTech: ["nginx"],
      stealthLevel: "high",
      scanType: "recon",
      target: "example.com",
      isDomain: true,
    });

    expect(pipeline.boundaryDetectionCmd).toBeDefined();
  });

  it("should include protocol audit commands for SSH targets", async () => {
    const { buildOptimalScanforgeCommand } = await import("./scanforge-knowledge");
    const pipeline = buildOptimalScanforgeCommand({
      detectedTech: ["SSH"],
      stealthLevel: "low",
      scanType: "full",
      target: "10.0.0.1",
      hasSSH: true,
    });

    expect(pipeline.protocolAuditCmds.length).toBeGreaterThan(0);
    expect(pipeline.protocolAuditCmds.some(c => c.includes("ssh-audit"))).toBe(true);
  });
});
