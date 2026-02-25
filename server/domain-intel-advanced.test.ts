import { describe, it, expect } from "vitest";

// ─── Test data factories ───────────────────────────────────────────────────
function makeScanAsset(overrides: Record<string, any> = {}) {
  return {
    hostname: "app.example.com",
    ip: "1.2.3.4",
    assetType: "web_application",
    technologies: ["nginx/1.18.0", "PHP/7.4.3", "WordPress/5.8"],
    dnsRecords: [{ type: "A", value: "1.2.3.4" }],
    ports: [
      { port: 80, transport: "tcp", product: "nginx", version: "1.18.0" },
      { port: 443, transport: "tcp", product: "nginx", version: "1.18.0" },
    ],
    discoveryMethod: "dns_verified",
    ...overrides,
  };
}

function makeSubdomain(overrides: Record<string, any> = {}) {
  return {
    name: "api.example.com",
    ip: "1.2.3.5",
    source: "crt.sh",
    tags: [],
    ...overrides,
  };
}

function makePort(overrides: Record<string, any> = {}) {
  return {
    ip: "1.2.3.4",
    port: 80,
    transport: "tcp",
    product: "nginx",
    version: "1.18.0",
    hostname: "app.example.com",
    cves: [],
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. SUBDOMAIN CHANGE DETECTION
// ═══════════════════════════════════════════════════════════════════════════
describe("Subdomain Change Detection", () => {
  it("should detect new subdomains between scans", () => {
    const previousSubs = [
      makeSubdomain({ name: "api.example.com" }),
      makeSubdomain({ name: "www.example.com" }),
    ];
    const currentSubs = [
      makeSubdomain({ name: "api.example.com" }),
      makeSubdomain({ name: "www.example.com" }),
      makeSubdomain({ name: "staging.example.com" }),
      makeSubdomain({ name: "dev.example.com" }),
    ];

    const previousNames = new Set(previousSubs.map((s) => s.name));
    const newSubs = currentSubs.filter((s) => !previousNames.has(s.name));

    expect(newSubs).toHaveLength(2);
    expect(newSubs.map((s) => s.name)).toContain("staging.example.com");
    expect(newSubs.map((s) => s.name)).toContain("dev.example.com");
  });

  it("should detect removed subdomains between scans", () => {
    const previousSubs = [
      makeSubdomain({ name: "api.example.com" }),
      makeSubdomain({ name: "old.example.com" }),
      makeSubdomain({ name: "legacy.example.com" }),
    ];
    const currentSubs = [makeSubdomain({ name: "api.example.com" })];

    const currentNames = new Set(currentSubs.map((s) => s.name));
    const removedSubs = previousSubs.filter((s) => !currentNames.has(s.name));

    expect(removedSubs).toHaveLength(2);
    expect(removedSubs.map((s) => s.name)).toContain("old.example.com");
    expect(removedSubs.map((s) => s.name)).toContain("legacy.example.com");
  });

  it("should detect IP address changes for the same subdomain", () => {
    const previousSubs = [
      makeSubdomain({ name: "api.example.com", ip: "1.2.3.4" }),
      makeSubdomain({ name: "www.example.com", ip: "5.6.7.8" }),
    ];
    const currentSubs = [
      makeSubdomain({ name: "api.example.com", ip: "10.20.30.40" }),
      makeSubdomain({ name: "www.example.com", ip: "5.6.7.8" }),
    ];

    const previousMap = new Map(previousSubs.map((s) => [s.name, s.ip]));
    const ipChanges = currentSubs
      .filter((s) => previousMap.has(s.name) && previousMap.get(s.name) !== s.ip)
      .map((s) => ({
        subdomain: s.name,
        previousIp: previousMap.get(s.name),
        currentIp: s.ip,
      }));

    expect(ipChanges).toHaveLength(1);
    expect(ipChanges[0].subdomain).toBe("api.example.com");
    expect(ipChanges[0].previousIp).toBe("1.2.3.4");
    expect(ipChanges[0].currentIp).toBe("10.20.30.40");
  });

  it("should detect port changes between scans", () => {
    const previousPorts = [
      makePort({ hostname: "api.example.com", port: 80 }),
      makePort({ hostname: "api.example.com", port: 443 }),
    ];
    const currentPorts = [
      makePort({ hostname: "api.example.com", port: 443 }),
      makePort({ hostname: "api.example.com", port: 8080, product: "tomcat" }),
      makePort({ hostname: "api.example.com", port: 3306, product: "mysql" }),
    ];

    const prevPortSet = new Set(previousPorts.map((p) => `${p.hostname}:${p.port}`));
    const currPortSet = new Set(currentPorts.map((p) => `${p.hostname}:${p.port}`));

    const newPorts = currentPorts.filter((p) => !prevPortSet.has(`${p.hostname}:${p.port}`));
    const closedPorts = previousPorts.filter((p) => !currPortSet.has(`${p.hostname}:${p.port}`));

    expect(newPorts).toHaveLength(2);
    expect(newPorts.map((p) => p.port)).toContain(8080);
    expect(newPorts.map((p) => p.port)).toContain(3306);
    expect(closedPorts).toHaveLength(1);
    expect(closedPorts[0].port).toBe(80);
  });

  it("should generate security alerts for high-risk changes", () => {
    const alerts: Array<{ type: string; severity: string; description: string }> = [];

    // New high-risk port opened
    const newPorts = [makePort({ port: 3306, product: "mysql" })];
    const highRiskPorts = [21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017];
    for (const p of newPorts) {
      if (highRiskPorts.includes(p.port)) {
        alerts.push({
          type: "new_high_risk_port",
          severity: "high",
          description: `High-risk port ${p.port} (${p.product}) newly opened on ${p.hostname}`,
        });
      }
    }

    // New subdomain with suspicious name
    const newSubs = [makeSubdomain({ name: "admin-staging.example.com" })];
    const suspiciousPatterns = ["admin", "staging", "test", "dev", "debug", "backup"];
    for (const s of newSubs) {
      if (suspiciousPatterns.some((p) => s.name.includes(p))) {
        alerts.push({
          type: "suspicious_subdomain",
          severity: "medium",
          description: `New subdomain with sensitive naming pattern: ${s.name}`,
        });
      }
    }

    expect(alerts).toHaveLength(2);
    expect(alerts[0].type).toBe("new_high_risk_port");
    expect(alerts[0].severity).toBe("high");
    expect(alerts[1].type).toBe("suspicious_subdomain");
  });

  it("should detect technology changes between scans", () => {
    const previousAssets = [
      makeScanAsset({ hostname: "app.example.com", technologies: ["nginx/1.18.0", "PHP/7.4.3"] }),
    ];
    const currentAssets = [
      makeScanAsset({ hostname: "app.example.com", technologies: ["nginx/1.20.0", "PHP/8.1.0", "Redis/6.2"] }),
    ];

    const prevTechMap = new Map(previousAssets.map((a) => [a.hostname, new Set(a.technologies)]));
    const techChanges = currentAssets
      .filter((a) => prevTechMap.has(a.hostname))
      .map((a) => {
        const prevTech = prevTechMap.get(a.hostname)!;
        const currTech = new Set(a.technologies);
        return {
          hostname: a.hostname,
          addedTech: a.technologies.filter((t: string) => !prevTech.has(t)),
          removedTech: [...prevTech].filter((t) => !currTech.has(t)),
        };
      })
      .filter((c) => c.addedTech.length > 0 || c.removedTech.length > 0);

    expect(techChanges).toHaveLength(1);
    expect(techChanges[0].addedTech).toContain("nginx/1.20.0");
    expect(techChanges[0].addedTech).toContain("PHP/8.1.0");
    expect(techChanges[0].addedTech).toContain("Redis/6.2");
    expect(techChanges[0].removedTech).toContain("nginx/1.18.0");
    expect(techChanges[0].removedTech).toContain("PHP/7.4.3");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. TECHNOLOGY VULNERABILITY CVE CROSS-REFERENCE
// ═══════════════════════════════════════════════════════════════════════════
describe("Technology Vulnerability CVE Cross-Reference", () => {
  // Known vulnerable technology database (subset for testing)
  const VULN_DB: Record<string, { cves: Array<{ cveId: string; severity: string; cvssScore: number; description: string }>; latestVersion: string; eolDate?: string }> = {
    "wordpress": {
      latestVersion: "6.4",
      cves: [
        { cveId: "CVE-2023-39999", severity: "medium", cvssScore: 6.1, description: "WordPress XSS in comment system" },
        { cveId: "CVE-2023-38000", severity: "high", cvssScore: 7.5, description: "WordPress SSRF via REST API" },
      ],
    },
    "php": {
      latestVersion: "8.3.0",
      eolDate: "2025-11-25",
      cves: [
        { cveId: "CVE-2024-2756", severity: "critical", cvssScore: 9.8, description: "PHP CGI argument injection" },
      ],
    },
    "nginx": {
      latestVersion: "1.25.4",
      cves: [
        { cveId: "CVE-2022-41741", severity: "high", cvssScore: 7.8, description: "nginx mp4 module memory corruption" },
      ],
    },
    "apache": {
      latestVersion: "2.4.58",
      cves: [
        { cveId: "CVE-2023-43622", severity: "high", cvssScore: 7.5, description: "Apache HTTP/2 DoS vulnerability" },
        { cveId: "CVE-2023-31122", severity: "high", cvssScore: 7.5, description: "Apache mod_macro buffer overflow" },
      ],
    },
  };

  function parseTechVersion(tech: string): { name: string; version: string | null } {
    const match = tech.match(/^([^/]+)(?:\/(.+))?$/);
    return match ? { name: match[1].toLowerCase(), version: match[2] || null } : { name: tech.toLowerCase(), version: null };
  }

  function isVersionOutdated(current: string | null, latest: string): boolean {
    if (!current) return false;
    const c = current.split(".").map(Number);
    const l = latest.split(".").map(Number);
    for (let i = 0; i < Math.max(c.length, l.length); i++) {
      if ((c[i] || 0) < (l[i] || 0)) return true;
      if ((c[i] || 0) > (l[i] || 0)) return false;
    }
    return false;
  }

  it("should parse technology names and versions correctly", () => {
    expect(parseTechVersion("nginx/1.18.0")).toEqual({ name: "nginx", version: "1.18.0" });
    expect(parseTechVersion("PHP/7.4.3")).toEqual({ name: "php", version: "7.4.3" });
    expect(parseTechVersion("WordPress/5.8")).toEqual({ name: "wordpress", version: "5.8" });
    expect(parseTechVersion("jQuery")).toEqual({ name: "jquery", version: null });
  });

  it("should detect outdated technology versions", () => {
    expect(isVersionOutdated("1.18.0", "1.25.4")).toBe(true);
    expect(isVersionOutdated("7.4.3", "8.3.0")).toBe(true);
    expect(isVersionOutdated("5.8", "6.4")).toBe(true);
    expect(isVersionOutdated("1.25.4", "1.25.4")).toBe(false);
    expect(isVersionOutdated("2.0.0", "1.25.4")).toBe(false);
  });

  it("should cross-reference technologies against CVE database", () => {
    const technologies = ["nginx/1.18.0", "PHP/7.4.3", "WordPress/5.8"];

    const profiles = technologies.map((tech) => {
      const { name, version } = parseTechVersion(tech);
      const dbEntry = VULN_DB[name];
      if (!dbEntry) return { technology: tech, name, version, cves: [], isOutdated: false, isEol: false };

      return {
        technology: tech,
        name,
        version,
        cves: dbEntry.cves,
        isOutdated: isVersionOutdated(version, dbEntry.latestVersion),
        latestVersion: dbEntry.latestVersion,
        isEol: false,
      };
    });

    expect(profiles).toHaveLength(3);

    const nginxProfile = profiles.find((p) => p.name === "nginx")!;
    expect(nginxProfile.isOutdated).toBe(true);
    expect(nginxProfile.cves).toHaveLength(1);
    expect(nginxProfile.cves[0].cveId).toBe("CVE-2022-41741");

    const phpProfile = profiles.find((p) => p.name === "php")!;
    expect(phpProfile.isOutdated).toBe(true);
    expect(phpProfile.cves).toHaveLength(1);
    expect(phpProfile.cves[0].severity).toBe("critical");

    const wpProfile = profiles.find((p) => p.name === "wordpress")!;
    expect(wpProfile.isOutdated).toBe(true);
    expect(wpProfile.cves).toHaveLength(2);
  });

  it("should compute summary statistics correctly", () => {
    const profiles = [
      { name: "nginx", cves: [{ severity: "high" }], isOutdated: true },
      { name: "php", cves: [{ severity: "critical" }], isOutdated: true },
      { name: "wordpress", cves: [{ severity: "medium" }, { severity: "high" }], isOutdated: true },
      { name: "jquery", cves: [], isOutdated: false },
    ];

    const summary = {
      totalTechnologies: profiles.length,
      vulnerableTechnologies: profiles.filter((p) => p.cves.length > 0).length,
      totalCves: profiles.reduce((sum, p) => sum + p.cves.length, 0),
      criticalCves: profiles.reduce((sum, p) => sum + p.cves.filter((c) => c.severity === "critical").length, 0),
      highCves: profiles.reduce((sum, p) => sum + p.cves.filter((c) => c.severity === "high").length, 0),
      outdatedTechnologies: profiles.filter((p) => p.isOutdated).length,
    };

    expect(summary.totalTechnologies).toBe(4);
    expect(summary.vulnerableTechnologies).toBe(3);
    expect(summary.totalCves).toBe(4);
    expect(summary.criticalCves).toBe(1);
    expect(summary.highCves).toBe(2);
    expect(summary.outdatedTechnologies).toBe(3);
  });

  it("should identify highest severity per technology", () => {
    const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

    function getHighestSeverity(cves: Array<{ severity: string }>): string {
      if (cves.length === 0) return "none";
      return cves.reduce((max, c) => (severityOrder[c.severity] || 0) > (severityOrder[max] || 0) ? c.severity : max, cves[0].severity);
    }

    expect(getHighestSeverity([{ severity: "medium" }, { severity: "high" }])).toBe("high");
    expect(getHighestSeverity([{ severity: "low" }, { severity: "critical" }])).toBe("critical");
    expect(getHighestSeverity([{ severity: "medium" }])).toBe("medium");
    expect(getHighestSeverity([])).toBe("none");
  });

  it("should map vulnerable technologies to affected assets", () => {
    const assets = [
      makeScanAsset({ hostname: "app.example.com", technologies: ["nginx/1.18.0", "PHP/7.4.3"] }),
      makeScanAsset({ hostname: "api.example.com", technologies: ["nginx/1.18.0", "Node.js/18.0"] }),
      makeScanAsset({ hostname: "blog.example.com", technologies: ["WordPress/5.8", "PHP/7.4.3"] }),
    ];

    const techToAssets = new Map<string, string[]>();
    for (const asset of assets) {
      for (const tech of asset.technologies) {
        const { name } = parseTechVersion(tech);
        if (!techToAssets.has(name)) techToAssets.set(name, []);
        techToAssets.get(name)!.push(asset.hostname);
      }
    }

    expect(techToAssets.get("nginx")).toEqual(["app.example.com", "api.example.com"]);
    expect(techToAssets.get("php")).toEqual(["app.example.com", "blog.example.com"]);
    expect(techToAssets.get("wordpress")).toEqual(["blog.example.com"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. SUBDOMAIN TAKEOVER DETECTION
// ═══════════════════════════════════════════════════════════════════════════
describe("Subdomain Takeover Detection", () => {
  // Known cloud service CNAME patterns
  const TAKEOVER_SIGNATURES: Record<string, { pattern: RegExp; service: string; severity: string }> = {
    s3: { pattern: /\.s3\.amazonaws\.com$/i, service: "AWS S3", severity: "critical" },
    github: { pattern: /\.github\.io$/i, service: "GitHub Pages", severity: "high" },
    heroku: { pattern: /\.herokuapp\.com$/i, service: "Heroku", severity: "high" },
    azure: { pattern: /\.azurewebsites\.net$/i, service: "Azure App Service", severity: "high" },
    azure_blob: { pattern: /\.blob\.core\.windows\.net$/i, service: "Azure Blob Storage", severity: "critical" },
    shopify: { pattern: /\.myshopify\.com$/i, service: "Shopify", severity: "medium" },
    fastly: { pattern: /\.fastly\.net$/i, service: "Fastly CDN", severity: "high" },
    ghost: { pattern: /\.ghost\.io$/i, service: "Ghost CMS", severity: "medium" },
    pantheon: { pattern: /\.pantheonsite\.io$/i, service: "Pantheon", severity: "medium" },
    netlify: { pattern: /\.netlify\.app$/i, service: "Netlify", severity: "high" },
    surge: { pattern: /\.surge\.sh$/i, service: "Surge.sh", severity: "medium" },
    cloudfront: { pattern: /\.cloudfront\.net$/i, service: "AWS CloudFront", severity: "high" },
    elastic_beanstalk: { pattern: /\.elasticbeanstalk\.com$/i, service: "AWS Elastic Beanstalk", severity: "high" },
  };

  function checkCnameForTakeover(cname: string): { vulnerable: boolean; service: string; severity: string } | null {
    for (const sig of Object.values(TAKEOVER_SIGNATURES)) {
      if (sig.pattern.test(cname)) {
        return { vulnerable: true, service: sig.service, severity: sig.severity };
      }
    }
    return null;
  }

  it("should detect dangling CNAME records pointing to cloud services", () => {
    const dnsRecords = [
      { type: "CNAME", value: "myapp-old.s3.amazonaws.com" },
      { type: "CNAME", value: "docs.example.com" },
      { type: "A", value: "1.2.3.4" },
    ];

    const cnameRecords = dnsRecords.filter((r) => r.type === "CNAME");
    const takeoverCandidates = cnameRecords
      .map((r) => checkCnameForTakeover(r.value))
      .filter(Boolean);

    expect(takeoverCandidates).toHaveLength(1);
    expect(takeoverCandidates[0]!.service).toBe("AWS S3");
    expect(takeoverCandidates[0]!.severity).toBe("critical");
  });

  it("should identify all known cloud service CNAME patterns", () => {
    const testCnames = [
      { cname: "bucket.s3.amazonaws.com", expected: "AWS S3" },
      { cname: "user.github.io", expected: "GitHub Pages" },
      { cname: "myapp.herokuapp.com", expected: "Heroku" },
      { cname: "site.azurewebsites.net", expected: "Azure App Service" },
      { cname: "store.myshopify.com", expected: "Shopify" },
      { cname: "cdn.fastly.net", expected: "Fastly CDN" },
      { cname: "blog.ghost.io", expected: "Ghost CMS" },
      { cname: "app.netlify.app", expected: "Netlify" },
      { cname: "dist.cloudfront.net", expected: "AWS CloudFront" },
    ];

    for (const tc of testCnames) {
      const result = checkCnameForTakeover(tc.cname);
      expect(result).not.toBeNull();
      expect(result!.service).toBe(tc.expected);
    }
  });

  it("should not flag non-cloud CNAME records", () => {
    const safeCnames = [
      "www.example.com",
      "cdn.example.com",
      "mail.google.com",
      "api.internal.corp",
    ];

    for (const cname of safeCnames) {
      const result = checkCnameForTakeover(cname);
      expect(result).toBeNull();
    }
  });

  it("should assess takeover risk based on DNS record type and service", () => {
    function assessTakeoverRisk(record: { type: string; value: string }): {
      riskLevel: string;
      confidence: number;
      service: string | null;
    } {
      if (record.type === "CNAME") {
        const match = checkCnameForTakeover(record.value);
        if (match) return { riskLevel: match.severity, confidence: 85, service: match.service };
      }
      if (record.type === "CNAME" && !record.value.includes(".")) {
        return { riskLevel: "high", confidence: 70, service: "Unknown (bare CNAME)" };
      }
      return { riskLevel: "none", confidence: 0, service: null };
    }

    const s3Risk = assessTakeoverRisk({ type: "CNAME", value: "old-bucket.s3.amazonaws.com" });
    expect(s3Risk.riskLevel).toBe("critical");
    expect(s3Risk.confidence).toBe(85);
    expect(s3Risk.service).toBe("AWS S3");

    const safeRisk = assessTakeoverRisk({ type: "A", value: "1.2.3.4" });
    expect(safeRisk.riskLevel).toBe("none");
  });

  it("should generate remediation guidance per service type", () => {
    const remediationMap: Record<string, string> = {
      "AWS S3": "Remove the CNAME record or create the S3 bucket to reclaim the endpoint. Verify bucket policy restricts public access.",
      "GitHub Pages": "Remove the CNAME record or configure the GitHub repository to serve from this domain. Add a CNAME file to the repository.",
      "Heroku": "Remove the CNAME record or add the custom domain to an active Heroku application.",
      "Azure App Service": "Remove the CNAME record or bind the custom domain to an active Azure App Service instance.",
      "Netlify": "Remove the CNAME record or configure the Netlify site to use this custom domain.",
    };

    expect(remediationMap["AWS S3"]).toContain("Remove the CNAME record");
    expect(remediationMap["GitHub Pages"]).toContain("CNAME file");
    expect(remediationMap["Heroku"]).toContain("Heroku application");
    expect(Object.keys(remediationMap)).toHaveLength(5);
  });

  it("should detect wildcard DNS that enables mass takeover", () => {
    function checkWildcardRisk(subdomains: Array<{ name: string; ip: string }>): {
      hasWildcard: boolean;
      wildcardIp: string | null;
      affectedCount: number;
    } {
      if (subdomains.length < 3) return { hasWildcard: false, wildcardIp: null, affectedCount: 0 };

      const ipCounts = new Map<string, number>();
      for (const s of subdomains) {
        if (s.ip) ipCounts.set(s.ip, (ipCounts.get(s.ip) || 0) + 1);
      }

      for (const [ip, count] of ipCounts) {
        const ratio = count / subdomains.length;
        if (ratio >= 0.8 && count >= 3) {
          return { hasWildcard: true, wildcardIp: ip, affectedCount: count };
        }
      }

      return { hasWildcard: false, wildcardIp: null, affectedCount: 0 };
    }

    const wildcardSubs = [
      { name: "a.example.com", ip: "1.2.3.4" },
      { name: "b.example.com", ip: "1.2.3.4" },
      { name: "c.example.com", ip: "1.2.3.4" },
      { name: "d.example.com", ip: "1.2.3.4" },
      { name: "e.example.com", ip: "5.6.7.8" },
    ];

    const result = checkWildcardRisk(wildcardSubs);
    expect(result.hasWildcard).toBe(true);
    expect(result.wildcardIp).toBe("1.2.3.4");
    expect(result.affectedCount).toBe(4);

    const normalSubs = [
      { name: "a.example.com", ip: "1.2.3.4" },
      { name: "b.example.com", ip: "5.6.7.8" },
      { name: "c.example.com", ip: "9.10.11.12" },
    ];

    const normalResult = checkWildcardRisk(normalSubs);
    expect(normalResult.hasWildcard).toBe(false);
  });

  it("should map takeover vulnerabilities to MITRE ATT&CK techniques", () => {
    const mitreMapping: Record<string, string> = {
      "subdomain_takeover": "T1584.001 - Compromise Infrastructure: Domains",
      "dns_hijacking": "T1584.002 - Compromise Infrastructure: DNS Server",
      "dangling_cname": "T1584.001 - Compromise Infrastructure: Domains",
      "wildcard_dns": "T1583.001 - Acquire Infrastructure: Domains",
    };

    expect(mitreMapping["subdomain_takeover"]).toContain("T1584.001");
    expect(mitreMapping["dns_hijacking"]).toContain("T1584.002");
    expect(Object.keys(mitreMapping)).toHaveLength(4);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. INTEGRATION — All three features work together
// ═══════════════════════════════════════════════════════════════════════════
describe("Domain Intel Advanced Features Integration", () => {
  it("should produce a unified risk assessment combining all three engines", () => {
    // Simulate outputs from all three engines
    const changeDetection = {
      newSubdomains: 3,
      removedSubdomains: 1,
      ipChanges: 2,
      securityAlerts: [{ severity: "high" }],
    };

    const techVulns = {
      totalCves: 5,
      criticalCves: 1,
      highCves: 2,
      vulnerableTechnologies: 3,
    };

    const takeoverDetection = {
      takeoverCandidates: 2,
      criticalCandidates: 1,
    };

    // Compute unified risk score
    let riskScore = 0;
    riskScore += changeDetection.securityAlerts.filter((a) => a.severity === "high").length * 15;
    riskScore += changeDetection.newSubdomains * 5;
    riskScore += changeDetection.ipChanges * 10;
    riskScore += techVulns.criticalCves * 25;
    riskScore += techVulns.highCves * 15;
    riskScore += takeoverDetection.criticalCandidates * 30;
    riskScore += (takeoverDetection.takeoverCandidates - takeoverDetection.criticalCandidates) * 15;

    expect(riskScore).toBeGreaterThan(0);
    expect(riskScore).toBe(15 + 15 + 20 + 25 + 30 + 30 + 15); // 150

    const riskBand = riskScore >= 100 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";
    expect(riskBand).toBe("critical");
  });

  it("should correlate change detection with takeover risk", () => {
    // A removed subdomain that had a CNAME to a cloud service = potential takeover
    const removedSubs = [
      { name: "old-docs.example.com", dnsRecords: [{ type: "CNAME", value: "docs.s3.amazonaws.com" }] },
      { name: "legacy.example.com", dnsRecords: [{ type: "A", value: "1.2.3.4" }] },
    ];

    const takeoverRisks = removedSubs.filter((s) =>
      s.dnsRecords.some((r) => r.type === "CNAME" && /\.(s3\.amazonaws|herokuapp|azurewebsites|github\.io)/.test(r.value))
    );

    expect(takeoverRisks).toHaveLength(1);
    expect(takeoverRisks[0].name).toBe("old-docs.example.com");
  });

  it("should correlate tech vulnerabilities with change detection", () => {
    // A newly appeared technology that has known CVEs = elevated risk
    const techChanges = [
      { hostname: "app.example.com", addedTech: ["PHP/7.4.3", "Redis/6.2"], removedTech: ["PHP/8.1.0"] },
    ];

    const knownVulnTech = new Set(["php/7.4.3", "wordpress/5.8", "apache/2.4.49"]);

    const elevatedRisks = techChanges.flatMap((c) =>
      c.addedTech
        .filter((t) => knownVulnTech.has(t.toLowerCase()))
        .map((t) => ({
          hostname: c.hostname,
          technology: t,
          reason: "Newly added technology has known CVEs — possible version downgrade",
        }))
    );

    expect(elevatedRisks).toHaveLength(1);
    expect(elevatedRisks[0].technology).toBe("PHP/7.4.3");
    expect(elevatedRisks[0].reason).toContain("version downgrade");
  });
});
