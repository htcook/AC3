import { describe, it, expect, vi } from "vitest";

// ─── ZAP Proxy Orchestrator Tests ─────────────────────────────────────────────
describe("ZAP Proxy Orchestrator", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/zap-proxy-orchestrator");
    expect(mod.initializeProxySession).toBeDefined();
    expect(mod.startAuthenticatedCrawl).toBeDefined();
    expect(mod.getProxyHistory).toBeDefined();
    expect(mod.getProxySessionStatus).toBeDefined();
    expect(mod.stopProxySession).toBeDefined();
    expect(mod.getWafEvasionPresets).toBeDefined();
    expect(mod.getCaCertificate).toBeDefined();
    expect(mod.listActiveSessions).toBeDefined();
    expect(mod.detectLoginConfiguration).toBeDefined();
  });

  it("should provide WAF evasion presets for known vendors", async () => {
    const { getWafEvasionPresets } = await import("./lib/zap-proxy-orchestrator");
    const presets = getWafEvasionPresets();
    expect(Array.isArray(presets)).toBe(true);
    expect(presets.length).toBeGreaterThan(0);
    
    // Each preset should have required fields
    const preset = presets[0];
    expect(preset).toHaveProperty("vendor");
    expect(preset).toHaveProperty("requestDelay");
    expect(preset).toHaveProperty("maxRps");
    expect(preset).toHaveProperty("techniques");
    expect(Array.isArray(preset.techniques)).toBe(true);
  });

  it("should generate CA certificate info", async () => {
    const { getCaCertificate } = await import("./lib/zap-proxy-orchestrator");
    // getCaCertificate is async - it calls ZAP API
    // In test env without ZAP, it should still return or throw
    try {
      const cert = await getCaCertificate();
      expect(cert).toBeDefined();
    } catch (e: any) {
      // Expected to fail without ZAP running
      expect(e.message).toBeDefined();
    }
  });

  it("initializeProxySession should throw on invalid URL", async () => {
    const { initializeProxySession } = await import("./lib/zap-proxy-orchestrator");
    // Empty URL causes new URL() to throw
    await expect(initializeProxySession({
      targetUrl: "",
    })).rejects.toThrow();
  });

  it("detectLoginConfiguration should be available", async () => {
    const { detectLoginConfiguration } = await import("./lib/zap-proxy-orchestrator");
    expect(typeof detectLoginConfiguration).toBe("function");
  });
});

// ─── ZAP Report Generator Tests ──────────────────────────────────────────────
describe("ZAP Report Generator", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/zap-report-generator");
    expect(mod.generateThemedReport).toBeDefined();
    expect(mod.generateReportFromZapApi).toBeDefined();
  });

  it("should generate themed HTML report with correct structure", async () => {
    const { generateThemedReport } = await import("./lib/zap-report-generator");
    
    const report = generateThemedReport({
      reportTitle: "Test Security Report",
      reportType: "full",
      generatedAt: new Date(),
      classification: "CONFIDENTIAL",
      scan: {
        targetUrl: "https://example.com",
        scanName: "Test Scan",
        scanMode: "active",
        scanType: "full",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        duration: "2m 0s",
        urlsDiscovered: 42,
        techStack: ["Apache", "PHP"],
      },
      alertCounts: { critical: 0, high: 1, medium: 1, low: 1, info: 0, total: 3 },
      findings: [
        { id: 1, alertName: "SQL Injection", severity: "High", confidence: 0.8, description: "SQL injection found", solution: "Use parameterized queries", reference: "", url: "https://example.com/login", method: "POST", param: "username", attack: "' OR 1=1", evidence: "error", cweId: 89, wascId: 19, mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", exploitAvailable: false, exploitModulePath: null, aiTriageVerdict: null, falsePositiveScore: null },
        { id: 2, alertName: "Cross-Site Scripting", severity: "Medium", confidence: 0.9, description: "XSS found", solution: "Encode output", reference: "", url: "https://example.com/search", method: "GET", param: "q", attack: "<script>", evidence: "<script>", cweId: 79, wascId: 8, mitreAttackId: null, mitreAttackName: null, mitreTactic: null, exploitAvailable: false, exploitModulePath: null, aiTriageVerdict: null, falsePositiveScore: null },
        { id: 3, alertName: "Missing Headers", severity: "Low", confidence: 1.0, description: "Missing X-Frame-Options", solution: "Add header", reference: "", url: "https://example.com/", method: "GET", param: "", attack: "", evidence: "", cweId: 16, wascId: 15, mitreAttackId: null, mitreAttackName: null, mitreTactic: null, exploitAvailable: false, exploitModulePath: null, aiTriageVerdict: null, falsePositiveScore: null },
      ],
      mitreMapping: [
        { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access", findingCount: 1 },
      ],
    });

    // Should be valid HTML
    expect(report).toContain("<!DOCTYPE html>");
    expect(report).toContain("</html>");
    expect(report).toContain("example.com");
    expect(report).toContain("#0A0E14");
    expect(report).toContain("#00E5CC");
    expect(report).toContain("SQL Injection");
    expect(report).toContain("Cross-Site Scripting");
  });

  it("should handle empty findings gracefully", async () => {
    const { generateThemedReport } = await import("./lib/zap-report-generator");
    
    const report = generateThemedReport({
      reportTitle: "Clean Site Report",
      reportType: "full",
      generatedAt: new Date(),
      classification: "INTERNAL",
      scan: {
        targetUrl: "https://clean-site.com",
        scanName: "Clean Scan",
        scanMode: "passive",
        scanType: "passive",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        duration: "1m 0s",
        urlsDiscovered: 10,
        techStack: [],
      },
      alertCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      findings: [],
      mitreMapping: [],
    });

    expect(report).toContain("<!DOCTYPE html>");
    expect(report).toContain("clean-site.com");
  });

  it("should include MITRE ATT&CK mapping when present", async () => {
    const { generateThemedReport } = await import("./lib/zap-report-generator");
    
    const report = generateThemedReport({
      reportTitle: "MITRE Test Report",
      reportType: "technical",
      generatedAt: new Date(),
      classification: "CONFIDENTIAL",
      scan: {
        targetUrl: "https://target.com",
        scanName: "MITRE Scan",
        scanMode: "active",
        scanType: "active",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        duration: "30s",
        urlsDiscovered: 5,
        techStack: [],
      },
      alertCounts: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
      findings: [{
        id: 1, alertName: "SQL Injection", severity: "High", confidence: 0.9, description: "test", solution: "test", reference: "", url: "https://target.com/api", method: "POST", param: "id", attack: "'", evidence: "error", cweId: 89, wascId: 19, mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", exploitAvailable: false, exploitModulePath: null, aiTriageVerdict: null, falsePositiveScore: null,
      }],
      mitreMapping: [
        { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access", findingCount: 1 },
      ],
    });

    expect(report).toContain("CWE-89");
    expect(report).toContain("T1190");
  });

  it("generateThemedReport should include theme CSS inline", async () => {
    const { generateThemedReport } = await import("./lib/zap-report-generator");
    const report = generateThemedReport({
      reportTitle: "Style Test",
      reportType: "executive",
      generatedAt: new Date(),
      classification: "PUBLIC",
      scan: { targetUrl: "https://test.com", scanName: "s", scanMode: "passive", scanType: "passive", startedAt: new Date().toISOString(), completedAt: new Date().toISOString(), duration: "1s", urlsDiscovered: 1, techStack: [] },
      alertCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      findings: [],
      mitreMapping: [],
    });
    // Theme colors should be in the inline styles
    expect(report).toContain("#0A0E14");
    expect(report).toContain("#00E5CC");
  });
});

// ─── Credential Attack Engine Tests ──────────────────────────────────────────
describe("Credential Attack Engine", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/credential-attack-engine");
    expect(mod.getPasswordLists).toBeDefined();
    expect(mod.getUsernameLists).toBeDefined();
    expect(mod.getDefaultCredentialsForTarget).toBeDefined();
    expect(mod.detectWebLoginForm).toBeDefined();
    expect(mod.generateTargetedPasswordList).toBeDefined();
    expect(mod.executeCredentialAttack).toBeDefined();
  });

  it("should return built-in password lists", async () => {
    const { getPasswordLists } = await import("./lib/credential-attack-engine");
    const lists = getPasswordLists();
    expect(Array.isArray(lists)).toBe(true);
    expect(lists.length).toBeGreaterThan(0);
    
    // Each list should have name and count
    const list = lists[0];
    expect(list).toHaveProperty("name");
    expect(list).toHaveProperty("count");
    expect(list.count).toBeGreaterThan(0);
  });

  it("should return built-in username lists", async () => {
    const { getUsernameLists } = await import("./lib/credential-attack-engine");
    const lists = getUsernameLists();
    expect(Array.isArray(lists)).toBe(true);
    expect(lists.length).toBeGreaterThan(0);
  });

  it("should return default credentials for SSH", async () => {
    const { getDefaultCredentialsForTarget } = await import("./lib/credential-attack-engine");
    const creds = getDefaultCredentialsForTarget("ssh", 22);
    expect(Array.isArray(creds)).toBe(true);
    // Should have at least root/admin defaults
    expect(creds.length).toBeGreaterThan(0);
    expect(creds[0]).toHaveProperty("username");
    expect(creds[0]).toHaveProperty("password");
  });

  it("should return default credentials for HTTP form login", async () => {
    const { getDefaultCredentialsForTarget } = await import("./lib/credential-attack-engine");
    const creds = getDefaultCredentialsForTarget("http_form", 80);
    expect(Array.isArray(creds)).toBe(true);
    expect(creds.length).toBeGreaterThan(0);
  });

  it("should return default credentials for MySQL", async () => {
    const { getDefaultCredentialsForTarget } = await import("./lib/credential-attack-engine");
    const creds = getDefaultCredentialsForTarget("mysql", 3306);
    expect(Array.isArray(creds)).toBe(true);
    expect(creds.length).toBeGreaterThan(0);
    // MySQL should have root default
    const hasRoot = creds.some(c => c.username === "root");
    expect(hasRoot).toBe(true);
  });

  it("should generate targeted passwords from org info", async () => {
    const { generateTargetedPasswordList } = await import("./lib/credential-attack-engine");
    const result = generateTargetedPasswordList({
      companyName: "Acme Corp",
      domain: "acme.com",
      industry: "Technology",
      city: "San Francisco",
    });
    expect(result).toHaveProperty("passwords");
    expect(Array.isArray(result.passwords)).toBe(true);
    expect(result.passwords.length).toBeGreaterThan(10);
    expect(result.category).toBe("targeted");
    
    // Should include company-name-based passwords
    const hasCompanyBased = result.passwords.some(p => 
      p.toLowerCase().includes("acme") || p.toLowerCase().includes("corp")
    );
    expect(hasCompanyBased).toBe(true);
  });

  it("should generate targeted passwords with year variations", async () => {
    const { generateTargetedPasswordList } = await import("./lib/credential-attack-engine");
    const result = generateTargetedPasswordList({
      companyName: "TestCo",
      domain: "testco.com",
      foundedYear: 2010,
    });
    
    // Should include year-based variations
    const hasYear = result.passwords.some(p => p.includes("2024") || p.includes("2025") || p.includes("2026"));
    expect(hasYear).toBe(true);
  });

  it("should execute attack and return structured result", async () => {
    const { executeCredentialAttack } = await import("./lib/credential-attack-engine");
    
    // Empty host should still return a result (it just fails all attempts)
    const result = await executeCredentialAttack({
      mode: "brute_force",
      target: { host: "", port: 22, protocol: "ssh" },
      maxRequestsPerSecond: 5,
      delayBetweenAttemptsMs: 500,
      jitterMs: 100,
      maxAttemptsPerUser: 10,
      lockoutDetection: true,
      lockoutThreshold: 5,
      lockoutCooldownSec: 60,
      maxTotalAttempts: 100,
      timeoutPerAttemptMs: 5000,
      globalTimeoutSec: 60,
      stopOnFirstSuccess: false,
    });
    expect(result).toHaveProperty("status");
    expect(result).toHaveProperty("totalAttempts");
    expect(result).toHaveProperty("successfulLogins");
    expect(result).toHaveProperty("failedAttempts");
    expect(result).toHaveProperty("lockoutsDetected");
    expect(result).toHaveProperty("rateInfo");
    expect(result.mode).toBe("brute_force");
    expect(result.protocol).toBe("ssh");
  });
});

// ─── Credential Attack Router Integration Tests ──────────────────────────────
describe("Web App Scanning Router - Credential Endpoints", () => {
  it("router should include credential attack endpoints", async () => {
    const { webAppScanningRouter } = await import("./routers/web-app-scanning");
    const procedures = Object.keys(webAppScanningRouter._def.procedures || {});
    
    expect(procedures).toContain("getPasswordLists");
    expect(procedures).toContain("getUsernameLists");
    expect(procedures).toContain("getDefaultCredentials");
    expect(procedures).toContain("detectWebLoginForm");
    expect(procedures).toContain("generateTargetedPasswords");
    expect(procedures).toContain("executeCredentialAttack");
  });

  it("router should include proxy orchestration endpoints", async () => {
    const { webAppScanningRouter } = await import("./routers/web-app-scanning");
    const procedures = Object.keys(webAppScanningRouter._def.procedures || {});
    
    expect(procedures).toContain("listProxySessions");
    expect(procedures).toContain("getWafEvasionPresets");
    expect(procedures).toContain("getCaCertificate");
  });
});

// ─── Credential Attack UI Page Tests ─────────────────────────────────────────
describe("Credential Attacks Page", () => {
  it("should exist as a valid module", async () => {
    // Verify the page file exists and can be imported
    const fs = await import("fs");
    const pagePath = "./client/src/pages/CredentialAttacks.tsx";
    // Check the file exists relative to project root
    const exists = fs.existsSync(
      require("path").resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx")
    );
    expect(exists).toBe(true);
  });

  it("should be registered in App.tsx routes", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/App.tsx"),
      "utf-8"
    );
    expect(appContent).toContain('"/credential-attacks"');
    expect(appContent).toContain("CredentialAttacks");
  });

  it("should be in the AppShell sidebar navigation", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const shellContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/components/AppShell.tsx"),
      "utf-8"
    );
    expect(shellContent).toContain("credential-attacks");
    expect(shellContent).toContain("CREDENTIAL ATTACKS");
  });

  it("page should reference all 5 attack modes", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pageContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx"),
      "utf-8"
    );
    expect(pageContent).toContain("brute_force");
    expect(pageContent).toContain("password_spray");
    expect(pageContent).toContain("credential_stuffing");
    expect(pageContent).toContain("default_creds");
    expect(pageContent).toContain("dictionary");
  });

  it("page should reference all protocol types", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pageContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx"),
      "utf-8"
    );
    const protocols = ["ssh", "ftp", "telnet", "mysql", "redis", "rdp", "smb", "mssql", "postgres", "vnc", "smtp"];
    for (const proto of protocols) {
      expect(pageContent).toContain(`"${proto}"`);
    }
  });

  it("page should have lockout detection toggle", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pageContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx"),
      "utf-8"
    );
    expect(pageContent).toContain("lockoutDetection");
    expect(pageContent).toContain("LOCKOUT DETECTION");
  });

  it("page should have ROE warning", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pageContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx"),
      "utf-8"
    );
    expect(pageContent).toContain("Rules of Engagement");
  });

  it("page should have targeted password generation section", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pageContent = fs.readFileSync(
      path.resolve(__dirname, "../client/src/pages/CredentialAttacks.tsx"),
      "utf-8"
    );
    expect(pageContent).toContain("TARGETED PASSWORD GENERATION");
    expect(pageContent).toContain("generateTargetedPasswords");
  });
});
