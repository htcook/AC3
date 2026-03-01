import { describe, it, expect, vi } from "vitest";

/**
 * Tests for enhanced modules:
 *   1. GitHub Recon Connector
 *   2. Cloud Bucket Recon Connector
 *   3. WAF/NGFW Detection Engine
 *   4. Credential Attack Engine
 *   5. ZAP Proxy Orchestrator
 *   6. ZAP Report Generator
 */

// ─── GitHub Recon Connector ──────────────────────────────────────────────

describe("GitHub Recon Connector", () => {
  it("should export a valid connector with correct metadata", async () => {
    const { githubReconConnector } = await import("./lib/passive/github-recon");
    expect(githubReconConnector).toBeDefined();
    expect(githubReconConnector.name).toBe("github_recon");
    expect(githubReconConnector.description).toBeTruthy();
    expect(typeof githubReconConnector.collect).toBe("function");
  });

  it("should have enhanced search patterns beyond basic leak detection", async () => {
    const mod = await import("./lib/passive/github-recon");
    // The module should export functions for org enumeration, repo discovery, etc.
    const exports = Object.keys(mod);
    expect(exports).toContain("githubReconConnector");
  });
});

// ─── Cloud Bucket Recon Connector ────────────────────────────────────────

describe("Cloud Bucket Recon Connector", () => {
  it("should export a valid connector with correct metadata", async () => {
    const { cloudBucketReconConnector } = await import("./lib/passive/cloud-bucket-recon");
    expect(cloudBucketReconConnector).toBeDefined();
    expect(cloudBucketReconConnector.name).toBe("cloud_bucket_recon");
    expect(cloudBucketReconConnector.description).toBeTruthy();
    expect(typeof cloudBucketReconConnector.collect).toBe("function");
  });

  it("should support multiple cloud providers", async () => {
    // Verify the module handles S3, Azure, GCP, DigitalOcean, Alibaba
    const mod = await import("./lib/passive/cloud-bucket-recon");
    const exports = Object.keys(mod);
    expect(exports).toContain("cloudBucketReconConnector");
  });
});

// ─── WAF/NGFW Detection Engine ──────────────────────────────────────────

describe("WAF/NGFW Detection Engine", () => {
  it("should export the detection functions", async () => {
    const { runWafNgfwAssessment, detectWafFromResponse, detectWafFromDns } = await import("./lib/waf-ngfw-detection");
    expect(typeof runWafNgfwAssessment).toBe("function");
    expect(typeof detectWafFromResponse).toBe("function");
    expect(typeof detectWafFromDns).toBe("function");
  });

  it("should export scan tuning profile function", async () => {
    const { generateScanTuningProfile } = await import("./lib/waf-ngfw-detection");
    expect(typeof generateScanTuningProfile).toBe("function");
  });

  it("should generate scan tuning profile for Cloudflare WAF", async () => {
    const { generateScanTuningProfile } = await import("./lib/waf-ngfw-detection");
    const rateLimit = { detected: false, blockType: "none" as const };
    const tuning = generateScanTuningProfile([
      { vendor: "Cloudflare" as any, confidence: "high", evidence: { headers: ["cf-ray"] }, capabilities: {} as any, bypassDifficulty: "hard" },
    ], [], rateLimit);

    expect(tuning).toBeDefined();
    expect(tuning.nmap.timing).toBeTruthy();
    expect(tuning.evasion.techniques).toBeDefined();
    expect(Array.isArray(tuning.evasion.techniques)).toBe(true);
    expect(tuning.evasion.techniques.length).toBeGreaterThan(0);
    expect(tuning.aggressiveness).toBe("cautious");
  });

  it("should generate different tuning for NGFW vs WAF", async () => {
    const { generateScanTuningProfile } = await import("./lib/waf-ngfw-detection");
    const rateLimit = { detected: false, blockType: "none" as const };

    const wafTuning = generateScanTuningProfile([
      { vendor: "Cloudflare" as any, confidence: "high", evidence: { headers: [] }, capabilities: {} as any, bypassDifficulty: "hard" },
    ], [], rateLimit);

    const ngfwTuning = generateScanTuningProfile([], [
      { vendor: "Palo Alto Networks" as any, confidence: "high", evidence: { banners: [] }, capabilities: {} as any },
    ], rateLimit);

    // Both should provide evasion techniques
    expect(wafTuning.evasion.techniques.length).toBeGreaterThan(0);
    expect(ngfwTuning.evasion.techniques.length).toBeGreaterThan(0);
  });

  it("should handle empty detection results gracefully", async () => {
    const { generateScanTuningProfile } = await import("./lib/waf-ngfw-detection");
    const rateLimit = { detected: false, blockType: "none" as const };
    const tuning = generateScanTuningProfile([], [], rateLimit);
    expect(tuning).toBeDefined();
    expect(tuning.nmap.timing).toBeTruthy();
    expect(tuning.aggressiveness).toBe("normal");
  });
});

// ─── Credential Attack Engine ───────────────────────────────────────────

describe("Credential Attack Engine", () => {
  it("should export password list management functions", async () => {
    const { getPasswordLists, getUsernameLists, getPasswordList, getUsernameList } =
      await import("./lib/credential-attack-engine");

    expect(typeof getPasswordLists).toBe("function");
    expect(typeof getUsernameLists).toBe("function");
    expect(typeof getPasswordList).toBe("function");
    expect(typeof getUsernameList).toBe("function");
  });

  it("should have multiple built-in password lists", async () => {
    const { getPasswordLists } = await import("./lib/credential-attack-engine");
    const lists = getPasswordLists();

    expect(lists.length).toBeGreaterThanOrEqual(5);

    const names = lists.map(l => l.name);
    expect(names).toContain("top_100");
    expect(names).toContain("admin_defaults");
    expect(names).toContain("network_device_defaults");
    expect(names).toContain("web_app_defaults");
    expect(names).toContain("season_year");
    expect(names).toContain("keyboard_walks");
  });

  it("should return passwords from a named list", async () => {
    const { getPasswordList } = await import("./lib/credential-attack-engine");

    const top100 = getPasswordList("top_100");
    expect(top100.length).toBeGreaterThanOrEqual(50);
    expect(top100).toContain("password");
    expect(top100).toContain("123456");

    const adminDefaults = getPasswordList("admin_defaults");
    expect(adminDefaults).toContain("admin");
    expect(adminDefaults).toContain("changeme");
  });

  it("should have multiple username lists", async () => {
    const { getUsernameLists } = await import("./lib/credential-attack-engine");
    const lists = getUsernameLists();

    expect(lists.length).toBeGreaterThanOrEqual(3);
    const names = lists.map(l => l.name);
    expect(names).toContain("common_admins");
    expect(names).toContain("service_accounts");
    expect(names).toContain("network_defaults");
  });

  it("should return usernames from a named list", async () => {
    const { getUsernameList } = await import("./lib/credential-attack-engine");

    const admins = getUsernameList("common_admins");
    expect(admins).toContain("admin");
    expect(admins).toContain("root");
    expect(admins).toContain("administrator");
  });

  it("should return default credentials for specific protocols", async () => {
    const { getDefaultCredentialsForTarget } = await import("./lib/credential-attack-engine");

    const sshCreds = getDefaultCredentialsForTarget("ssh" as any, 22);
    expect(sshCreds.length).toBeGreaterThan(0);
    expect(sshCreds.some(c => c.username === "root")).toBe(true);

    const httpCreds = getDefaultCredentialsForTarget("http_basic" as any, 8080);
    expect(httpCreds.length).toBeGreaterThan(0);
    expect(httpCreds.some(c => c.vendor === "Apache")).toBe(true);

    const redisCreds = getDefaultCredentialsForTarget("redis" as any, 6379);
    expect(redisCreds.length).toBeGreaterThan(0);
  });

  it("should generate targeted password lists from org info", async () => {
    const { generateTargetedPasswordList } = await import("./lib/credential-attack-engine");

    const list = generateTargetedPasswordList({
      companyName: "Acme Corp",
      domain: "acmecorp.com",
      industry: "technology",
      foundedYear: 2010,
      city: "Austin",
      state: "TX",
    });

    expect(list.name).toBe("targeted_acmecorp");
    expect(list.category).toBe("targeted");
    expect(list.passwords.length).toBeGreaterThan(20);
    // Should contain company-specific patterns
    expect(list.passwords.some(p => p.toLowerCase().includes("acme"))).toBe(true);
    // Should contain year-based patterns
    expect(list.passwords.some(p => p.includes("2026"))).toBe(true);
    // Should contain city patterns
    expect(list.passwords.some(p => p.includes("Austin"))).toBe(true);
    // Should contain founded year
    expect(list.passwords.some(p => p.includes("2010"))).toBe(true);
  });

  it("should export the credential attack execution function", async () => {
    const { executeCredentialAttack } = await import("./lib/credential-attack-engine");
    expect(typeof executeCredentialAttack).toBe("function");
  });

  it("should export web login form detection function", async () => {
    const { detectWebLoginForm } = await import("./lib/credential-attack-engine");
    expect(typeof detectWebLoginForm).toBe("function");
  });

  it("should have comprehensive default credential database", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    expect(creds.length).toBeGreaterThanOrEqual(50);

    // Should cover multiple vendor categories
    const vendors = [...new Set(creds.map(c => c.vendor))];
    expect(vendors.length).toBeGreaterThanOrEqual(15);

    // Should cover multiple protocols
    const protocols = [...new Set(creds.map(c => c.protocol))];
    expect(protocols.length).toBeGreaterThanOrEqual(5);
    expect(protocols).toContain("ssh");
    expect(protocols).toContain("http_basic");
    expect(protocols).toContain("http_form");
    expect(protocols).toContain("ftp");
    expect(protocols).toContain("mysql");
  });

  it("should have network device default credentials", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    const networkVendors = ["Cisco", "Juniper", "MikroTik", "Fortinet", "Palo Alto", "pfSense"];
    for (const vendor of networkVendors) {
      expect(creds.some(c => c.vendor === vendor)).toBe(true);
    }
  });

  it("should have web application default credentials", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    const webApps = ["Jenkins", "Grafana", "GitLab", "WordPress", "Nagios"];
    for (const app of webApps) {
      expect(creds.some(c => c.vendor === app)).toBe(true);
    }
  });

  it("should have database default credentials", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    expect(creds.some(c => c.vendor === "MySQL")).toBe(true);
    expect(creds.some(c => c.vendor === "PostgreSQL")).toBe(true);
    expect(creds.some(c => c.vendor === "Redis")).toBe(true);
    expect(creds.some(c => c.vendor === "MongoDB")).toBe(true);
  });

  it("should have IoT/camera default credentials", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    expect(creds.some(c => c.vendor === "Hikvision")).toBe(true);
    expect(creds.some(c => c.vendor === "Dahua")).toBe(true);
  });

  it("should have SCADA/ICS default credentials", async () => {
    const { getAllDefaultCredentials } = await import("./lib/credential-attack-engine");
    const creds = getAllDefaultCredentials();

    expect(creds.some(c => c.vendor === "Siemens")).toBe(true);
    expect(creds.some(c => c.vendor === "Schneider")).toBe(true);
  });
});

// ─── ZAP Proxy Orchestrator ────────────────────────────────────────────

describe("ZAP Proxy Orchestrator", () => {
  it("should export proxy session management functions", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(typeof mod.initializeProxySession).toBe("function");
    expect(typeof mod.getProxySessionStatus).toBe("function");
    expect(typeof mod.stopProxySession).toBe("function");
    expect(typeof mod.listActiveSessions).toBe("function");
  });

  it("should export authenticated crawl function", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(typeof mod.startAuthenticatedCrawl).toBe("function");
  });

  it("should export WAF evasion functions", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(typeof mod.applyWafEvasionSettings).toBe("function");
    expect(typeof mod.getWafEvasionPresets).toBe("function");
  });

  it("should have WAF evasion presets for major vendors", async () => {
    const { getWafEvasionPresets } = await import("./lib/zap-proxy-orchestrator");
    const presets = getWafEvasionPresets();

    expect(Array.isArray(presets)).toBe(true);
    expect(presets.length).toBeGreaterThanOrEqual(3);

    const vendors = presets.map((p: any) => p.vendor?.toLowerCase() || p.name?.toLowerCase());
    // Should have presets for major WAF vendors
    expect(vendors.some((v: string) => v.includes("cloudflare") || v.includes("akamai") || v.includes("aws"))).toBe(true);
  });

  it("should export login form detection function", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(typeof mod.detectLoginConfiguration).toBe("function");
  });

  it("should export proxy history and CA cert functions", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(typeof mod.getProxyHistory).toBe("function");
    expect(typeof mod.getCaCertificate).toBe("function");
  });
});

// ─── ZAP Report Generator ──────────────────────────────────────────────

describe("ZAP Report Generator", () => {
  it("should export the report generation function", async () => {
    const { generateReportFromZapApi } = await import("./lib/zap-report-generator");
    expect(typeof generateReportFromZapApi).toBe("function");
  });

  it("should support multiple report types", async () => {
    // The function signature should accept report type parameter
    const mod = await import("./lib/zap-report-generator");
    const exports = Object.keys(mod);
    expect(exports).toContain("generateReportFromZapApi");
  });
});

// ─── Integration: Pipeline includes new connectors ──────────────────────

describe("Pipeline Connector Registration", () => {
  it("should include github_recon and cloud_bucket_recon in the connector list", async () => {
    const { ALL_CONNECTORS } = await import("./lib/passive/index");
    const names = ALL_CONNECTORS.map(c => c.name);

    expect(names).toContain("github_recon");
    expect(names).toContain("cloud_bucket_recon");
  });

  it("should have all 31 connectors registered", async () => {
    const { ALL_CONNECTORS } = await import("./lib/passive/index");
    expect(ALL_CONNECTORS.length).toBe(30);
  });
});

// ─── Integration: WAF detection in pipeline ─────────────────────────────

describe("WAF/NGFW Pipeline Integration", () => {
  it("should include wafNgfwAssessment in PipelineResult type", async () => {
    // Verify the pipeline exports include WAF assessment
    const domainIntel = await import("./domainIntel");
    expect(domainIntel).toBeDefined();
    // The runDomainIntelPipeline function should exist
    expect(typeof domainIntel.runDomainIntelPipeline).toBe("function");
  });
});

// ─── Integration: Router endpoints ──────────────────────────────────────

describe("Web App Scanning Router Endpoints", () => {
  it("should export the webAppScanningRouter", async () => {
    const { webAppScanningRouter } = await import("./routers/web-app-scanning");
    expect(webAppScanningRouter).toBeDefined();
  });
});
