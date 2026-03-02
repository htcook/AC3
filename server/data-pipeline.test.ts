import { describe, expect, it } from "vitest";

/**
 * Data Pipeline Tests
 *
 * Validates that the data structures used across the passive recon → LLM scan plan →
 * active scan pipeline are correctly shaped and that tool results persist properly.
 */

// ─── AssetPassiveRecon structure ─────────────────────────────────────────────

describe("AssetPassiveRecon structure", () => {
  it("should have all required fields for passive recon data", () => {
    const recon = {
      services: [
        { port: 443, service: "https", product: "nginx", version: "1.18", source: "shodan" },
        { port: 80, service: "http", product: "Apache", source: "censys" },
      ],
      technologies: ["nginx", "PHP", "WordPress", "CloudFlare"],
      certificates: [
        { subject: "*.example.com", issuer: "Let's Encrypt", expiry: "2026-06-01" },
      ],
      riskSignals: [
        { signal: "Exposed admin panel", severity: "high", source: "shodan" },
        { signal: "Outdated TLS version", severity: "medium", source: "censys" },
      ],
      subdomains: ["api.example.com", "admin.example.com", "dev.example.com"],
    };

    expect(recon.services).toHaveLength(2);
    expect(recon.services[0]).toHaveProperty("port");
    expect(recon.services[0]).toHaveProperty("service");
    expect(recon.services[0]).toHaveProperty("source");
    expect(recon.technologies).toContain("nginx");
    expect(recon.certificates[0]).toHaveProperty("subject");
    expect(recon.certificates[0]).toHaveProperty("issuer");
    expect(recon.riskSignals[0]).toHaveProperty("severity");
    expect(recon.riskSignals[0]).toHaveProperty("source");
    expect(recon.subdomains).toHaveLength(3);
  });

  it("should handle empty passive recon data gracefully", () => {
    const emptyRecon = {
      services: [],
      technologies: [],
      certificates: [],
      riskSignals: [],
      subdomains: [],
    };

    expect(emptyRecon.services).toHaveLength(0);
    expect(emptyRecon.technologies).toHaveLength(0);
    expect(emptyRecon.certificates).toHaveLength(0);
    expect(emptyRecon.riskSignals).toHaveLength(0);
    expect(emptyRecon.subdomains).toHaveLength(0);
  });
});

// ─── ToolResult structure ────────────────────────────────────────────────────

describe("ToolResult structure", () => {
  it("should have all required fields for a tool execution result", () => {
    const toolResult = {
      tool: "nmap",
      command: "nmap -Pn -sV -O -p- -f -T2 -D RND:5 --data-length 64 192.168.1.1",
      exitCode: 0,
      durationMs: 45000,
      timedOut: false,
      findingCount: 5,
      findings: [
        { severity: "info", title: "80/tcp http (nginx 1.18)" },
        { severity: "info", title: "443/tcp https (nginx 1.18)" },
        { severity: "info", title: "22/tcp ssh (OpenSSH 8.2)" },
        { severity: "info", title: "3306/tcp mysql (MySQL 5.7)" },
        { severity: "info", title: "8080/tcp http-proxy (Apache Tomcat)" },
      ],
      outputPreview: "Starting Nmap 7.94 ...\nPORT     STATE SERVICE\n80/tcp   open  http",
      executedAt: Date.now(),
      phase: "discovery",
    };

    expect(toolResult.tool).toBe("nmap");
    expect(toolResult.exitCode).toBe(0);
    expect(toolResult.timedOut).toBe(false);
    expect(toolResult.findingCount).toBe(5);
    expect(toolResult.findings).toHaveLength(5);
    expect(toolResult.findings[0]).toHaveProperty("severity");
    expect(toolResult.findings[0]).toHaveProperty("title");
    expect(toolResult.phase).toBe("discovery");
    expect(toolResult.executedAt).toBeGreaterThan(0);
  });

  it("should support multiple tool types with findings", () => {
    const tools = ["nmap", "nuclei", "nikto", "gobuster", "httpx", "hydra", "zap"];
    const phases = ["discovery", "targeted_enum", "vuln_detection", "credential_testing"];

    for (const tool of tools) {
      for (const phase of phases) {
        const result = {
          tool,
          command: `${tool} --test`,
          exitCode: 0,
          durationMs: 1000,
          timedOut: false,
          findingCount: 0,
          findings: [] as Array<{ severity: string; title: string; cve?: string }>,
          outputPreview: "",
          executedAt: Date.now(),
          phase,
        };
        expect(result.tool).toBe(tool);
        expect(result.phase).toBe(phase);
      }
    }
  });

  it("should handle timed out tool results", () => {
    const timedOut = {
      tool: "nmap",
      command: "nmap -p- -sV target.com",
      exitCode: 1,
      durationMs: 600000,
      timedOut: true,
      findingCount: 2,
      findings: [
        { severity: "info", title: "80/tcp http" },
        { severity: "info", title: "443/tcp https" },
      ],
      outputPreview: "Partial scan results...",
      executedAt: Date.now(),
      phase: "discovery",
    };

    expect(timedOut.timedOut).toBe(true);
    expect(timedOut.exitCode).not.toBe(0);
    // Even timed out scans should preserve partial findings
    expect(timedOut.findingCount).toBe(2);
  });
});

// ─── AssetStatus with toolResults and passiveRecon ───────────────────────────

describe("AssetStatus data persistence", () => {
  it("should accumulate tool results across scan phases", () => {
    const asset = {
      hostname: "target.example.com",
      ip: "192.168.1.1",
      type: "web_app",
      ports: [] as Array<{ port: number; service: string; version?: string }>,
      vulns: [] as Array<{ id: string; severity: string; title: string; cve?: string }>,
      zapFindings: [] as Array<{ alert: string; risk: string; url: string }>,
      exploitAttempts: [] as Array<{ module: string; success: boolean }>,
      status: "discovered",
      toolResults: [] as Array<{
        tool: string; command: string; exitCode: number; durationMs: number;
        timedOut: boolean; findingCount: number;
        findings: Array<{ severity: string; title: string; cve?: string }>;
        outputPreview: string; executedAt: number; phase: string;
      }>,
      passiveRecon: {
        services: [{ port: 443, service: "https", product: "nginx", source: "shodan" }],
        technologies: ["nginx", "PHP"],
        certificates: [{ subject: "*.example.com", issuer: "Let's Encrypt" }],
        riskSignals: [{ signal: "Exposed admin", severity: "high", source: "shodan" }],
        subdomains: ["api.example.com"],
      },
    };

    // Phase A: Discovery scan
    asset.toolResults.push({
      tool: "nmap",
      command: "nmap -Pn -sV -O -p- -f -T2 192.168.1.1",
      exitCode: 0,
      durationMs: 30000,
      timedOut: false,
      findingCount: 3,
      findings: [
        { severity: "info", title: "80/tcp http" },
        { severity: "info", title: "443/tcp https" },
        { severity: "info", title: "22/tcp ssh" },
      ],
      outputPreview: "PORT    STATE SERVICE\n80/tcp  open  http\n443/tcp open  https\n22/tcp  open  ssh",
      executedAt: Date.now(),
      phase: "discovery",
    });
    asset.ports = [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
      { port: 22, service: "ssh" },
    ];
    asset.status = "enumerated";

    expect(asset.toolResults).toHaveLength(1);
    expect(asset.toolResults[0].phase).toBe("discovery");
    expect(asset.ports).toHaveLength(3);

    // Phase B: Targeted nmap
    asset.toolResults.push({
      tool: "nmap",
      command: "nmap --script=vuln,http-enum -p 80,443 192.168.1.1",
      exitCode: 0,
      durationMs: 15000,
      timedOut: false,
      findingCount: 1,
      findings: [{ severity: "medium", title: "HTTP TRACE method enabled", cve: "CVE-2004-2320" }],
      outputPreview: "TRACE method enabled",
      executedAt: Date.now(),
      phase: "targeted_enum",
    });

    expect(asset.toolResults).toHaveLength(2);

    // Phase B: Nuclei scan
    asset.toolResults.push({
      tool: "nuclei",
      command: "nuclei -u https://target.example.com -severity critical,high,medium",
      exitCode: 0,
      durationMs: 60000,
      timedOut: false,
      findingCount: 2,
      findings: [
        { severity: "high", title: "WordPress xmlrpc.php exposed", cve: "CVE-2020-28037" },
        { severity: "medium", title: "Directory listing enabled" },
      ],
      outputPreview: "[wordpress-xmlrpc] [http] [high] https://target.example.com/xmlrpc.php",
      executedAt: Date.now(),
      phase: "vuln_detection",
    });

    expect(asset.toolResults).toHaveLength(3);

    // Verify we can query tool results by phase
    const discoveryResults = asset.toolResults.filter(tr => tr.phase === "discovery");
    const enumResults = asset.toolResults.filter(tr => tr.phase === "targeted_enum");
    const vulnResults = asset.toolResults.filter(tr => tr.phase === "vuln_detection");

    expect(discoveryResults).toHaveLength(1);
    expect(enumResults).toHaveLength(1);
    expect(vulnResults).toHaveLength(1);

    // Verify total findings across all tools
    const totalFindings = asset.toolResults.reduce((sum, tr) => sum + tr.findingCount, 0);
    expect(totalFindings).toBe(6);
  });

  it("should merge passive recon data with active scan data", () => {
    const passiveRecon = {
      services: [
        { port: 443, service: "https", product: "nginx", version: "1.18", source: "shodan" },
      ],
      technologies: ["nginx", "PHP", "WordPress"],
      certificates: [{ subject: "*.example.com", issuer: "Let's Encrypt" }],
      riskSignals: [{ signal: "Outdated software", severity: "medium", source: "shodan" }],
      subdomains: ["api.example.com", "admin.example.com"],
    };

    // Active scan discovers more ports than passive
    const activePorts = [
      { port: 80, service: "http", version: "nginx 1.18" },
      { port: 443, service: "https", version: "nginx 1.18" },
      { port: 22, service: "ssh", version: "OpenSSH 8.2" },
      { port: 3306, service: "mysql", version: "MySQL 5.7" },
    ];

    // Active scan should discover more than passive
    expect(activePorts.length).toBeGreaterThan(passiveRecon.services.length);

    // Passive recon data should still be accessible alongside active data
    expect(passiveRecon.technologies).toContain("WordPress");
    expect(passiveRecon.riskSignals[0].signal).toBe("Outdated software");
  });
});

// ─── ScanPlan structure with discovery + evasion ─────────────────────────────

describe("ScanPlan two-phase structure", () => {
  it("should include discovery strategy and evasion profile", () => {
    const scanPlan = {
      generatedAt: Date.now(),
      overallStrategy: "Two-phase approach: broad discovery then targeted exploitation",
      discoveryStrategy: "Full port sweep with service fingerprinting using evasion tactics",
      discoveryEvasionProfile: {
        timing: "T2",
        fragmentation: true,
        decoys: true,
        randomizeHosts: true,
        dataLengthPadding: true,
        sourcePortSpoofing: false,
        rationale: "Slow timing with fragmentation and decoys to avoid IDS detection",
      },
      assetPlans: [
        {
          hostname: "target.example.com",
          ip: "192.168.1.1",
          assetType: "web_app",
          discoveryNmapFlags: "-Pn -sV -O -p- -f -T2 -D RND:5 --data-length 64 --randomize-hosts",
          discoveryNmapRationale: "Full port sweep with evasion for web application",
          nmapFlags: "--script=vuln,http-enum,ssl-cert -p 80,443",
          nmapRationale: "Targeted vulnerability scripts on discovered web ports",
          evasionTechniques: ["fragmentation", "decoys", "slow-timing", "data-padding"],
          activeTools: [
            { tool: "nuclei", command: "nuclei -u https://{target} -severity critical,high,medium", rationale: "CVE scanning", priority: 1 },
            { tool: "nikto", command: "nikto -h {target}", rationale: "Web server misconfiguration", priority: 2 },
          ],
          riskNotes: "WAF detected, use evasion-aware scanning",
        },
      ],
      estimatedDuration: "15-25 minutes",
      riskAssessment: "Medium risk - WAF present, evasion required",
    };

    expect(scanPlan.discoveryStrategy).toBeTruthy();
    expect(scanPlan.discoveryEvasionProfile).toBeDefined();
    expect(scanPlan.discoveryEvasionProfile.timing).toBe("T2");
    expect(scanPlan.discoveryEvasionProfile.fragmentation).toBe(true);
    expect(scanPlan.discoveryEvasionProfile.decoys).toBe(true);
    expect(scanPlan.discoveryEvasionProfile.rationale).toBeTruthy();

    const assetPlan = scanPlan.assetPlans[0];
    expect(assetPlan.discoveryNmapFlags).toContain("-p-"); // Full port sweep
    expect(assetPlan.discoveryNmapFlags).toContain("-f"); // Fragmentation
    expect(assetPlan.discoveryNmapFlags).toContain("-T2"); // Slow timing
    expect(assetPlan.discoveryNmapFlags).toContain("-D RND"); // Decoys
    expect(assetPlan.discoveryNmapRationale).toBeTruthy();
    expect(assetPlan.nmapFlags).toContain("--script"); // Targeted scripts
    expect(assetPlan.evasionTechniques).toContain("fragmentation");
    expect(assetPlan.activeTools).toHaveLength(2);
    expect(assetPlan.activeTools[0].priority).toBeLessThanOrEqual(assetPlan.activeTools[1].priority);
  });

  it("should support multiple assets with different scan profiles", () => {
    const assetPlans = [
      {
        hostname: "web.example.com",
        assetType: "web_app",
        discoveryNmapFlags: "-Pn -sV -p- -f -T2",
        nmapFlags: "--script=http-vuln*,ssl-cert -p 80,443",
        evasionTechniques: ["fragmentation", "slow-timing"],
        activeTools: [
          { tool: "nuclei", command: "nuclei -u https://web.example.com", rationale: "CVE scan", priority: 1 },
          { tool: "gobuster", command: "gobuster dir -u https://web.example.com -w common.txt", rationale: "Directory enumeration", priority: 2 },
        ],
      },
      {
        hostname: "db.example.com",
        assetType: "database",
        discoveryNmapFlags: "-Pn -sV -p 3306,5432,27017,6379 -T2",
        nmapFlags: "--script=mysql-vuln*,pgsql-brute -p 3306,5432",
        evasionTechniques: ["slow-timing"],
        activeTools: [
          { tool: "hydra", command: "hydra -l root -P passwords.txt db.example.com mysql", rationale: "Default credential test", priority: 3 },
        ],
      },
    ];

    expect(assetPlans).toHaveLength(2);
    expect(assetPlans[0].assetType).toBe("web_app");
    expect(assetPlans[1].assetType).toBe("database");
    // Web app should have more evasion techniques
    expect(assetPlans[0].evasionTechniques.length).toBeGreaterThanOrEqual(assetPlans[1].evasionTechniques.length);
    // Web app should have more tools
    expect(assetPlans[0].activeTools.length).toBeGreaterThan(assetPlans[1].activeTools.length);
  });
});

// ─── Data flow: passive recon → LLM context ─────────────────────────────────

describe("Passive recon to LLM context data flow", () => {
  it("should build LLM-consumable asset summaries from passive recon", () => {
    const assets = [
      {
        hostname: "target.example.com",
        ip: "192.168.1.1",
        type: "web_app",
        ports: [{ port: 443, service: "https" }],
        passiveRecon: {
          services: [{ port: 443, service: "https", product: "nginx", version: "1.18", source: "shodan" }],
          technologies: ["nginx", "PHP", "WordPress 5.8"],
          certificates: [{ subject: "*.example.com", issuer: "Let's Encrypt" }],
          riskSignals: [
            { signal: "WordPress xmlrpc.php exposed", severity: "high", source: "shodan" },
            { signal: "Outdated PHP version", severity: "medium", source: "censys" },
          ],
          subdomains: ["api.example.com", "admin.example.com"],
        },
        toolResults: [] as any[],
      },
    ];

    // Simulate building LLM context from assets (mirrors generateScanPlan logic)
    const assetSummaries = assets.map(a => {
      const info: Record<string, any> = {
        hostname: a.hostname,
        ip: a.ip || "unknown",
        type: a.type || "unknown",
        knownPorts: a.ports.map(p => `${p.port}/${p.service}`),
        existingVulns: 0,
      };

      if (a.passiveRecon) {
        info.passiveRecon = {
          technologies: a.passiveRecon.technologies,
          services: a.passiveRecon.services.map(s => `${s.port}/${s.service} (${s.product || 'unknown'} ${s.version || ''}) [${s.source}]`),
          certificates: a.passiveRecon.certificates.map(c => `${c.subject} by ${c.issuer}`),
          riskSignals: a.passiveRecon.riskSignals.map(r => `[${r.severity}] ${r.signal} (${r.source})`),
          subdomains: a.passiveRecon.subdomains,
        };
      }

      return info;
    });

    expect(assetSummaries).toHaveLength(1);
    const summary = assetSummaries[0];
    expect(summary.passiveRecon).toBeDefined();
    expect(summary.passiveRecon.technologies).toContain("WordPress 5.8");
    expect(summary.passiveRecon.riskSignals[0]).toContain("[high]");
    expect(summary.passiveRecon.riskSignals[0]).toContain("WordPress xmlrpc.php exposed");
    expect(summary.passiveRecon.services[0]).toContain("443/https");
    expect(summary.passiveRecon.services[0]).toContain("nginx");
    expect(summary.passiveRecon.subdomains).toContain("api.example.com");
  });

  it("should include previous tool results in LLM context for Phase B planning", () => {
    const asset = {
      hostname: "target.example.com",
      toolResults: [
        {
          tool: "nmap",
          command: "nmap -Pn -sV -O -p- target.example.com",
          findingCount: 5,
          findings: [
            { severity: "info", title: "80/tcp http (nginx 1.18)" },
            { severity: "info", title: "443/tcp https (nginx 1.18)" },
            { severity: "info", title: "22/tcp ssh (OpenSSH 8.2)" },
            { severity: "info", title: "3306/tcp mysql (MySQL 5.7)" },
            { severity: "info", title: "8080/tcp http-proxy (Tomcat 9.0)" },
          ],
          phase: "discovery",
        },
      ],
    };

    // Simulate building LLM context with previous tool results
    const info: Record<string, any> = {
      hostname: asset.hostname,
      previousToolResults: asset.toolResults.map(tr => ({
        tool: tr.tool,
        phase: tr.phase,
        findingCount: tr.findingCount,
        findings: tr.findings.map(f => f.title),
      })),
    };

    expect(info.previousToolResults).toHaveLength(1);
    expect(info.previousToolResults[0].tool).toBe("nmap");
    expect(info.previousToolResults[0].phase).toBe("discovery");
    expect(info.previousToolResults[0].findings).toContain("80/tcp http (nginx 1.18)");
    expect(info.previousToolResults[0].findings).toContain("3306/tcp mysql (MySQL 5.7)");
  });
});

// ─── Stats tracking ──────────────────────────────────────────────────────────

describe("Stats tracking across phases", () => {
  it("should accumulate stats correctly across all scan phases", () => {
    const stats = {
      hostsScanned: 0,
      portsFound: 0,
      vulnsFound: 0,
      exploitsAttempted: 0,
      exploitsSucceeded: 0,
      sessionsOpened: 0,
      zapScansRun: 0,
      wafDetections: 0,
      assetsDiscovered: 0,
    };

    // Passive recon
    stats.assetsDiscovered = 3;

    // Phase A: Discovery
    stats.hostsScanned = 3;
    stats.portsFound = 12;

    // Phase B: Targeted enum
    stats.vulnsFound += 2; // From targeted nmap scripts

    // Vuln detection
    stats.vulnsFound += 5; // From nuclei
    stats.zapScansRun = 2;
    stats.wafDetections = 1;
    stats.vulnsFound += 3; // From ZAP

    // Exploitation
    stats.exploitsAttempted = 4;
    stats.exploitsSucceeded = 2;
    stats.sessionsOpened = 1;

    expect(stats.assetsDiscovered).toBe(3);
    expect(stats.hostsScanned).toBe(3);
    expect(stats.portsFound).toBe(12);
    expect(stats.vulnsFound).toBe(10); // 2 + 5 + 3
    expect(stats.exploitsAttempted).toBe(4);
    expect(stats.exploitsSucceeded).toBe(2);
    expect(stats.sessionsOpened).toBe(1);
    expect(stats.zapScansRun).toBe(2);
    expect(stats.wafDetections).toBe(1);
  });
});
