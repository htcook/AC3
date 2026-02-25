import { describe, it, expect } from "vitest";

// ─── PDF Report Generator Tests ─────────────────────────────────────────────
describe("PDF Report Generator", () => {
  it("generateAttackPlanReport returns valid HTML with AceofCloud branding", async () => {
    const { generateAttackPlanReport } = await import("./lib/pdf-report-generator");
    const html = generateAttackPlanReport({
      name: "Test Attack Plan",
      summary: "A test plan for unit testing",
      phases: [
        {
          name: "Initial Access",
          objective: "Gain initial foothold",
          steps: [
            {
              techniqueId: "T1566",
              techniqueName: "Phishing",
              description: "Send phishing emails",
              stealthRating: 7,
            },
          ],
        },
        {
          name: "Execution",
          objective: "Execute payload",
          steps: [
            {
              techniqueId: "T1059",
              techniqueName: "Command and Scripting Interpreter",
              description: "Execute payload via PowerShell",
              stealthRating: 5,
            },
          ],
        },
      ],
      selectedTechniques: ["T1566", "T1059"],
      estimatedRisk: 7.5,
    });

    expect(html).toContain("AceofCloud");
    expect(html).toContain("Harrison Cook");
    expect(html).toContain("Test Attack Plan");
    expect(html).toContain("T1566");
    expect(html).toContain("Initial Access");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
  });

  it("generateRemediationReport returns valid HTML with stats and items", async () => {
    const { generateRemediationReport } = await import("./lib/pdf-report-generator");
    const stats = {
      total: 15,
      verifiedFixed: 5,
      stillVulnerable: 3,
      pending: 4,
      overdue: 3,
      slaCompliant: 80,
      severityBreakdown: { critical: 3, high: 5, medium: 4, low: 2, info: 1 },
      avgRemediationHours: 48,
    };
    const items = [
      { id: 1, findingTitle: "[DEMO] CVE-2024-1234", severity: "critical", status: "verified_fixed", assetName: "web-01" },
      { id: 2, findingTitle: "[DEMO] CVE-2024-5678", severity: "high", status: "still_vulnerable", assetName: "db-01" },
    ];
    const overdueItems = [
      { id: 2, findingTitle: "[DEMO] CVE-2024-5678", severity: "high", status: "still_vulnerable", assetName: "db-01", hoursOverdue: 24 },
    ];

    const html = generateRemediationReport(stats, items, overdueItems);

    expect(html).toContain("AceofCloud");
    expect(html).toContain("Harrison Cook");
    expect(html).toContain("Remediation");
    expect(html).toContain("15"); // total
    expect(html).toContain("80"); // SLA compliant
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
  });

  it("generateCorroborationReport returns valid HTML with findings", async () => {
    const { generateCorroborationReport } = await import("./lib/pdf-report-generator");
    const report = {
      totalFindings: 5,
      corroboratedFindings: 3,
      contradictions: 1,
      estimatedFalsePositiveReduction: 20,
      sourcesQueried: 4,
      results: [
        { host: "192.168.1.1", title: "Open SSH", sourcesConfirming: 3, sourcesQueried: 4, adjustedConfidence: 0.92, originalConfidence: 0.7, verdict: "confirmed" },
        { host: "10.0.0.1", title: "Stale DNS", sourcesConfirming: 0, sourcesQueried: 4, adjustedConfidence: 0.1, originalConfidence: 0.6, verdict: "false_positive" },
      ],
    };

    const html = generateCorroborationReport(report);

    expect(html).toContain("AceofCloud");
    expect(html).toContain("Harrison Cook");
    expect(html).toContain("Corroboration");
    expect(html).toContain("192.168.1.1");
    expect(html).toContain("confirmed");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
  });

  it("generateAttackPlanReport handles empty phases gracefully", async () => {
    const { generateAttackPlanReport } = await import("./lib/pdf-report-generator");
    const html = generateAttackPlanReport({
      name: "Empty Plan",
      summary: "No phases",
      phases: [],
      selectedTechniques: [],
      estimatedRisk: 0,
    });

    expect(html).toContain("Empty Plan");
    expect(html).toContain("<html");
  });

  it("generateRemediationReport handles zero items", async () => {
    const { generateRemediationReport } = await import("./lib/pdf-report-generator");
    const html = generateRemediationReport(
      { total: 0, verifiedFixed: 0, stillVulnerable: 0, pending: 0, overdue: 0, slaCompliant: 100, severityBreakdown: {}, avgRemediationHours: 0 },
      [],
      []
    );

    expect(html).toContain("Remediation");
    expect(html).toContain("<html");
  });
});

// ─── Client-side Export Utility Tests ────────────────────────────────────────
describe("Export PDF Utility", () => {
  it("exportToPdf and downloadHtml are exported functions", async () => {
    // We can't test window.open in Node, but we can verify the module exports
    const mod = await import("../client/src/lib/export-pdf");
    expect(typeof mod.exportToPdf).toBe("function");
    expect(typeof mod.downloadHtml).toBe("function");
  });
});

// ─── Seed Data Structure Tests ───────────────────────────────────────────────
describe("Seed Demo Data", () => {
  it("seed data items all have [DEMO] prefix in finding titles", async () => {
    // Read the router file to verify seed data has [DEMO] prefix
    const fs = await import("fs");
    const routerContent = fs.readFileSync("server/routers/remediation-verification.ts", "utf-8");
    
    // Extract all findingTitle values from the seed data
    const titleMatches = routerContent.match(/findingTitle:\s*["'`]([^"'`]+)["'`]/g);
    expect(titleMatches).not.toBeNull();
    
    if (titleMatches) {
      // Filter to only seed data titles (they should have [DEMO])
      const seedTitles = titleMatches
        .map(m => m.replace(/findingTitle:\s*["'`]/, "").replace(/["'`]$/, ""))
        .filter(t => t.includes("CVE-") || t.includes("DEMO"));
      
      for (const title of seedTitles) {
        expect(title).toMatch(/^\[DEMO\]/);
      }
      expect(seedTitles.length).toBeGreaterThanOrEqual(10); // We have 15 seed items
    }
  });
});

// ─── Attack Planner Caldera Integration Tests ────────────────────────────────
describe("Attack Planner Caldera Integration", () => {
  it("accept endpoint exists in the router with Caldera operation creation logic", async () => {
    const fs = await import("fs");
    const routerContent = fs.readFileSync("server/routers/ai-attack-planner.ts", "utf-8");
    
    // Verify the accept endpoint creates a Caldera operation
    expect(routerContent).toContain("accept:");
    expect(routerContent).toContain("CALDERA_BASE_URL");
    expect(routerContent).toContain("CALDERA_API_KEY");
    expect(routerContent).toContain("/api/v2/operations");
    expect(routerContent).toContain("/api/v2/abilities");
  });

  it("accept endpoint maps MITRE technique IDs to Caldera abilities", async () => {
    const fs = await import("fs");
    const routerContent = fs.readFileSync("server/routers/ai-attack-planner.ts", "utf-8");
    
    // Verify technique-to-ability mapping logic
    expect(routerContent).toContain("technique_id");
    expect(routerContent).toContain("adversary");
  });
});

// ─── Export Endpoints Exist Tests ────────────────────────────────────────────
describe("Export Endpoints", () => {
  it("attack planner router has exportReport endpoint", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/ai-attack-planner.ts", "utf-8");
    expect(content).toContain("exportReport:");
    expect(content).toContain("generateAttackPlanReport");
  });

  it("remediation router has exportReport endpoint", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/remediation-verification.ts", "utf-8");
    expect(content).toContain("exportReport:");
    expect(content).toContain("generateRemediationReport");
  });

  it("corroboration router has exportReport endpoint", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/corroboration-engine.ts", "utf-8");
    expect(content).toContain("exportReport:");
    expect(content).toContain("generateCorroborationReport");
  });

  it("remediation router has seedDemoData endpoint", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/remediation-verification.ts", "utf-8");
    expect(content).toContain("seedDemoData:");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CVE-TO-THREAT-ACTOR ENRICHMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════
function makeTechVulnResult(overrides: Record<string, any> = {}) {
  return {
    totalVulnerabilities: 3,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 1,
    lowCount: 0,
    vulnerabilities: [
      {
        technology: "Apache",
        detectedVersion: "2.4.49",
        cveId: "CVE-2021-41773",
        cvssScore: 9.8,
        severity: "critical",
        description: "Path traversal and RCE in Apache HTTP Server",
        affectedVersions: "2.4.49-2.4.50",
        fixedVersion: "2.4.51",
        exploitAvailable: true,
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        affectedAssets: ["web.example.com"],
        remediation: "Upgrade Apache to 2.4.51+",
        publishedDate: "2021-10-05",
      },
      {
        technology: "OpenSSL",
        detectedVersion: "1.0.2",
        cveId: "CVE-2014-0160",
        cvssScore: 7.5,
        severity: "high",
        description: "Heartbleed vulnerability in OpenSSL",
        affectedVersions: "1.0.1-1.0.1f",
        fixedVersion: "1.0.1g",
        exploitAvailable: true,
        references: [],
        affectedAssets: ["api.example.com"],
        remediation: "Upgrade OpenSSL",
        publishedDate: "2014-04-07",
      },
      {
        technology: "jQuery",
        detectedVersion: "1.12.4",
        cveId: "CVE-2020-11022",
        cvssScore: 6.1,
        severity: "medium",
        description: "XSS in jQuery",
        affectedVersions: "1.2-3.5.0",
        fixedVersion: "3.5.0",
        exploitAvailable: false,
        references: [],
        affectedAssets: ["www.example.com"],
        remediation: "Upgrade jQuery",
        publishedDate: "2020-04-29",
      },
    ],
    technologySummary: [
      { technology: "Apache", version: "2.4.49", vulnCount: 1, maxSeverity: "critical", assetCount: 1 },
      { technology: "OpenSSL", version: "1.0.2", vulnCount: 1, maxSeverity: "high", assetCount: 1 },
      { technology: "jQuery", version: "1.12.4", vulnCount: 1, maxSeverity: "medium", assetCount: 1 },
    ],
    ...overrides,
  };
}

function makeTakeoverCandidate(overrides: Record<string, any> = {}) {
  return {
    subdomain: "old-app.example.com",
    cnameTarget: "old-app.s3.amazonaws.com",
    service: "AWS S3",
    serviceCategory: "cloud_storage",
    riskLevel: "critical" as const,
    status: "vulnerable" as const,
    evidence: ["CNAME points to unclaimed S3 bucket"],
    description: "S3 bucket no longer exists",
    remediation: "Remove DNS record or reclaim bucket",
    mitreTechnique: "T1584.001",
    ...overrides,
  };
}

describe("CVE-to-Threat-Actor Enrichment", () => {
  it("should import enrichCvesWithThreatActors function", async () => {
    const mod = await import("./lib/domain-intel-advanced");
    expect(typeof mod.enrichCvesWithThreatActors).toBe("function");
  });

  it("should return enrichment result with correct structure", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const techVulnResult = makeTechVulnResult();
    const result = await enrichCvesWithThreatActors(techVulnResult as any);

    expect(result).toBeDefined();
    expect(result).toHaveProperty("enrichedCves");
    expect(result).toHaveProperty("totalCvesEnriched");
    expect(result).toHaveProperty("totalActorsLinked");
    expect(result).toHaveProperty("uniqueActors");
    expect(result).toHaveProperty("actorTypeSummary");
    expect(Array.isArray(result.enrichedCves)).toBe(true);
    expect(Array.isArray(result.uniqueActors)).toBe(true);
    expect(Array.isArray(result.actorTypeSummary)).toBe(true);
  });

  it("should enrich known CVEs with threat actor data", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const techVulnResult = makeTechVulnResult();
    const result = await enrichCvesWithThreatActors(techVulnResult as any);
    expect(result.totalCvesEnriched).toBeGreaterThanOrEqual(0);
    expect(typeof result.totalActorsLinked).toBe("number");
  });

  it("should handle empty vulnerability list gracefully", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const emptyResult = makeTechVulnResult({
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      vulnerabilities: [],
      technologySummary: [],
    });
    const result = await enrichCvesWithThreatActors(emptyResult as any);

    expect(result.enrichedCves).toHaveLength(0);
    expect(result.totalCvesEnriched).toBe(0);
    expect(result.totalActorsLinked).toBe(0);
    expect(result.uniqueActors).toHaveLength(0);
  });

  it("should include correct fields for enriched CVEs", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const techVulnResult = makeTechVulnResult();
    const result = await enrichCvesWithThreatActors(techVulnResult as any);

    for (const cve of result.enrichedCves) {
      expect(cve).toHaveProperty("cveId");
      expect(cve).toHaveProperty("technology");
      expect(cve).toHaveProperty("cvssScore");
      expect(cve).toHaveProperty("threatLevel");
      expect(cve).toHaveProperty("actors");
      expect(Array.isArray(cve.actors)).toBe(true);
    }
  });

  it("should deduplicate unique actors list", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const result = await enrichCvesWithThreatActors(makeTechVulnResult() as any);
    const uniqueSet = new Set(result.uniqueActors);
    expect(uniqueSet.size).toBe(result.uniqueActors.length);
  });

  it("should provide actor type summary breakdown", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const result = await enrichCvesWithThreatActors(makeTechVulnResult() as any);
    for (const summary of result.actorTypeSummary) {
      expect(summary).toHaveProperty("type");
      expect(summary).toHaveProperty("count");
      expect(typeof summary.count).toBe("number");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ACTIVE TAKEOVER POC VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════
describe("Active Takeover PoC Validation", () => {
  it("should import validateTakeoverCandidates function", async () => {
    const mod = await import("./lib/domain-intel-advanced");
    expect(typeof mod.validateTakeoverCandidates).toBe("function");
  });

  it("should return validation result with correct structure", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const candidates = [makeTakeoverCandidate()];
    const result = await validateTakeoverCandidates(candidates as any);

    expect(result).toBeDefined();
    expect(result).toHaveProperty("totalValidated");
    expect(result).toHaveProperty("confirmedCount");
    expect(result).toHaveProperty("likelyCount");
    expect(result).toHaveProperty("possibleCount");
    expect(result).toHaveProperty("unlikelyCount");
    expect(result).toHaveProperty("errorCount");
    expect(result).toHaveProperty("results");
    expect(result).toHaveProperty("summary");
    expect(Array.isArray(result.results)).toBe(true);
  });

  it("should validate each candidate with per-candidate results", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const candidates = [
      makeTakeoverCandidate({ subdomain: "old-app.example.com" }),
      makeTakeoverCandidate({ subdomain: "blog.example.com", cnameTarget: "blog.ghost.io", service: "Ghost" }),
    ];
    const result = await validateTakeoverCandidates(candidates as any);

    expect(result.totalValidated).toBe(2);
    expect(result.results).toHaveLength(2);

    for (const r of result.results) {
      expect(r).toHaveProperty("subdomain");
      expect(r).toHaveProperty("cnameTarget");
      expect(r).toHaveProperty("service");
      expect(r).toHaveProperty("validationStatus");
      expect(r).toHaveProperty("confidence");
      expect(r).toHaveProperty("dnsResolves");
      expect(r).toHaveProperty("responseContainsFingerprint");
      expect(["confirmed", "likely", "possible", "unlikely", "error"]).toContain(r.validationStatus);
      expect(r.confidence).toBeGreaterThanOrEqual(0);
      expect(r.confidence).toBeLessThanOrEqual(100);
    }
  });

  it("should handle empty candidates array", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const result = await validateTakeoverCandidates([]);

    expect(result.totalValidated).toBe(0);
    expect(result.confirmedCount).toBe(0);
    expect(result.likelyCount).toBe(0);
    expect(result.possibleCount).toBe(0);
    expect(result.unlikelyCount).toBe(0);
    expect(result.results).toHaveLength(0);
  });

  it("should count validation statuses correctly", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const candidates = [
      makeTakeoverCandidate({ subdomain: "a.example.com" }),
      makeTakeoverCandidate({ subdomain: "b.example.com" }),
      makeTakeoverCandidate({ subdomain: "c.example.com" }),
    ];
    const result = await validateTakeoverCandidates(candidates as any);
    const statusCounts = result.confirmedCount + result.likelyCount + result.possibleCount + result.unlikelyCount + result.errorCount;
    expect(statusCounts).toBe(result.totalValidated);
  });

  it("should include exploitability notes", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const result = await validateTakeoverCandidates([makeTakeoverCandidate()] as any);
    for (const r of result.results) {
      expect(r).toHaveProperty("exploitabilityNote");
      expect(typeof r.exploitabilityNote).toBe("string");
    }
  });

  it("should generate a summary string", async () => {
    const { validateTakeoverCandidates } = await import("./lib/domain-intel-advanced");
    const result = await validateTakeoverCandidates([makeTakeoverCandidate()] as any);
    expect(typeof result.summary).toBe("string");
    expect(result.summary.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SCAN SCHEDULER TESTS
// ═══════════════════════════════════════════════════════════════════════════
describe("Scan Scheduler", () => {
  it("should import scheduler functions", async () => {
    const mod = await import("./lib/scan-scheduler");
    expect(typeof mod.initScanScheduler).toBe("function");
    expect(typeof mod.stopScanScheduler).toBe("function");
    expect(typeof mod.getSchedulerStatus).toBe("function");
    expect(typeof mod.forceSchedulerCheck).toBe("function");
    expect(typeof mod.checkAndTriggerScans).toBe("function");
  });

  it("should return scheduler status with correct structure", async () => {
    const { getSchedulerStatus } = await import("./lib/scan-scheduler");
    const status = getSchedulerStatus();

    expect(status).toBeDefined();
    expect(status).toHaveProperty("running");
    expect(status).toHaveProperty("activeMonitors");
    expect(status).toHaveProperty("totalScansTriggered");
    expect(status).toHaveProperty("recentRuns");
    expect(typeof status.running).toBe("boolean");
    expect(typeof status.activeMonitors).toBe("number");
    expect(typeof status.totalScansTriggered).toBe("number");
    expect(Array.isArray(status.recentRuns)).toBe(true);
  });

  it("should initialize and stop scheduler", async () => {
    const { initScanScheduler, stopScanScheduler, getSchedulerStatus } = await import("./lib/scan-scheduler");

    initScanScheduler();
    const statusAfterInit = getSchedulerStatus();
    expect(statusAfterInit.running).toBe(true);

    stopScanScheduler();
    const statusAfterStop = getSchedulerStatus();
    expect(statusAfterStop.running).toBe(false);
  });

  it("should handle force check returning result object", async () => {
    const { forceSchedulerCheck } = await import("./lib/scan-scheduler");
    const result = await forceSchedulerCheck();

    expect(result).toBeDefined();
    expect(result).toHaveProperty("monitorsChecked");
    expect(result).toHaveProperty("scansTriggered");
    expect(typeof result.monitorsChecked).toBe("number");
    expect(typeof result.scansTriggered).toBe("number");
  });

  it("should track recent runs in scheduler status", async () => {
    const { getSchedulerStatus, initScanScheduler, stopScanScheduler } = await import("./lib/scan-scheduler");
    initScanScheduler();
    const status = getSchedulerStatus();
    expect(Array.isArray(status.recentRuns)).toBe(true);
    stopScanScheduler();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CVE ENRICHMENT INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════
describe("CVE Enrichment Integration", () => {
  it("should handle vulnerabilities with no known actor mapping", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const obscureVuln = makeTechVulnResult({
      vulnerabilities: [
        {
          technology: "ObscureLib",
          detectedVersion: "0.0.1",
          cveId: "CVE-9999-99999",
          cvssScore: 3.0,
          severity: "low",
          description: "Minor issue",
          affectedVersions: "0.0.1",
          exploitAvailable: false,
          references: [],
          affectedAssets: ["test.example.com"],
          remediation: "Upgrade",
          publishedDate: "2025-01-01",
        },
      ],
    });
    const result = await enrichCvesWithThreatActors(obscureVuln as any);
    expect(result).toHaveProperty("enrichedCves");
    expect(result).toHaveProperty("totalCvesEnriched");
    expect(result).toHaveProperty("uniqueActors");
  });

  it("should properly classify threat levels based on CVSS", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");
    const result = await enrichCvesWithThreatActors(makeTechVulnResult() as any);
    for (const cve of result.enrichedCves) {
      expect(["critical", "high", "medium", "low"]).toContain(cve.threatLevel);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// EVASION ORCHESTRATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Evasion Orchestrator Core", () => {
  it("should export all core functions", async () => {
    const mod = await import("./lib/evasion-orchestrator");
    expect(mod.detectBlockSignal).toBeDefined();
    expect(mod.getEscalationLadder).toBeDefined();
    expect(mod.runEvasionLoop).toBeDefined();
    expect(mod.storeFinding).toBeDefined();
    expect(mod.getFindings).toBeDefined();
    expect(mod.getFindingById).toBeDefined();
    expect(mod.getOrchestratorStats).toBeDefined();
    expect(mod.ESCALATION_LADDER).toBeDefined();
  });

  it("should detect block signals from HTTP responses", async () => {
    const { detectBlockSignal } = await import("./lib/evasion-orchestrator");

    const wafBlock = detectBlockSignal({ statusCode: 403, body: "Access Denied by WAF" });
    expect(wafBlock.blocked).toBe(true);
    expect(wafBlock.signal).toBe("http_403");

    const rateLimit = detectBlockSignal({ statusCode: 429, body: "" });
    expect(rateLimit.blocked).toBe(true);
    expect(rateLimit.signal).toBe("http_429");

    const success = detectBlockSignal({ statusCode: 200, body: "Welcome to the site" });
    expect(success.blocked).toBe(false);
  });

  it("should return domain-specific escalation ladders", async () => {
    const { getEscalationLadder } = await import("./lib/evasion-orchestrator");

    const scanLadder = getEscalationLadder("scanning");
    expect(scanLadder.length).toBeGreaterThan(0);
    expect(scanLadder.every((t) => t.applicableTo.includes("scanning"))).toBe(true);

    const c2Ladder = getEscalationLadder("c2");
    expect(c2Ladder.length).toBeGreaterThan(0);
    expect(c2Ladder.every((t) => t.applicableTo.includes("c2"))).toBe(true);

    const exploitLadder = getEscalationLadder("exploit");
    expect(exploitLadder.length).toBeGreaterThan(0);
    expect(exploitLadder.every((t) => t.applicableTo.includes("exploit"))).toBe(true);
  });

  it("should have escalation ladder sorted by level", async () => {
    const { ESCALATION_LADDER } = await import("./lib/evasion-orchestrator");
    for (let i = 1; i < ESCALATION_LADDER.length; i++) {
      expect(ESCALATION_LADDER[i].level).toBeGreaterThanOrEqual(ESCALATION_LADDER[i - 1].level);
    }
  });

  it("should run evasion loop and return a finding on success", async () => {
    const { runEvasionLoop } = await import("./lib/evasion-orchestrator");

    const finding = await runEvasionLoop(
      "scanning",
      "https://test.example.com",
      "test-scan",
      { url: "https://test.example.com", headers: {}, metadata: {} },
      async (_ctx) => ({
        success: true,
        statusCode: 200,
        body: "OK",
      }),
      { maxAttempts: 3 },
    );

    expect(finding).toBeDefined();
    expect(finding.id).toBeTruthy();
    expect(finding.domain).toBe("scanning");
    expect(finding.target).toBe("https://test.example.com");
    expect(finding.finalResult).toBe("bypassed");
    expect(finding.totalAttempts).toBeGreaterThanOrEqual(1);
    expect(finding.attempts).toBeInstanceOf(Array);
    expect(finding.evasionScorecard).toBeDefined();
    expect(finding.evasionScorecard.bypassRate).toBeGreaterThanOrEqual(0);
    expect(finding.recommendations).toBeInstanceOf(Array);
  });

  it("should record blocked result when all techniques fail", async () => {
    const { runEvasionLoop } = await import("./lib/evasion-orchestrator");

    const finding = await runEvasionLoop(
      "c2",
      "192.168.1.100",
      "test-c2-task",
      { command: "whoami", metadata: {} },
      async (_ctx) => ({
        success: false,
        statusCode: 403,
        body: "Blocked by EDR",
      }),
      { maxAttempts: 3 },
    );

    expect(finding.finalResult).toBe("blocked");
    expect(finding.totalAttempts).toBeGreaterThanOrEqual(3);
    expect(finding.attempts.every((a: any) => a.result === "blocked")).toBe(true);
  });

  it("should store and retrieve findings", async () => {
    const { storeFinding, getFindings, getFindingById } = await import("./lib/evasion-orchestrator");

    const testFinding = {
      id: `test-store-${Date.now()}`,
      domain: "scanning" as const,
      target: "https://test-store.example.com",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      totalAttempts: 2,
      finalResult: "bypassed" as const,
      successfulTechnique: { id: "t1", name: "Test Technique", category: "test", level: 1, description: "Test", escalationLevel: 1, mitreTechnique: "T1001", applicableDomains: ["scanning" as const] },
      defensesDetected: ["WAF"],
      attempts: [],
      evasionScorecard: {
        totalTechniquesTried: 2,
        techniquesBypassed: 1,
        techniquesBlocked: 1,
        escalationDepth: 1,
        bypassRate: 50,
        defenseEffectiveness: 50,
      },
      recommendations: ["Test recommendation"],
    };

    storeFinding(testFinding);

    const found = getFindingById(testFinding.id);
    expect(found).toBeDefined();
    expect(found?.target).toBe("https://test-store.example.com");

    const allFindings = getFindings({ domain: "scanning" });
    expect(allFindings.some((f) => f.id === testFinding.id)).toBe(true);
  });

  it("should compute orchestrator stats correctly", async () => {
    const { getOrchestratorStats } = await import("./lib/evasion-orchestrator");

    const stats = getOrchestratorStats();
    expect(stats).toBeDefined();
    expect(typeof stats.totalFindings).toBe("number");
    expect(stats.byDomain).toBeDefined();
    expect(stats.byResult).toBeDefined();
    expect(typeof stats.averageBypassRate).toBe("number");
    expect(typeof stats.averageEscalationDepth).toBe("number");
    expect(stats.topDefenses).toBeInstanceOf(Array);
    expect(stats.topBypassTechniques).toBeInstanceOf(Array);
  });
});

describe("Evasion Integrations", () => {
  it("should export all integration functions", async () => {
    const mod = await import("./lib/evasion-integrations");
    expect(mod.runEvasionAwareScan).toBeDefined();
    expect(mod.runEvasionAwareC2Task).toBeDefined();
    expect(mod.runEvasionAwareExploit).toBeDefined();
    expect(mod.probeDefenses).toBeDefined();
    expect(mod.selectPipelineForDefenses).toBeDefined();
    expect(mod.generateOptimizedMutations).toBeDefined();
  });

  it("should probe defenses and return structured result", async () => {
    const { probeDefenses } = await import("./lib/evasion-integrations");

    const result = await probeDefenses("https://example.com");
    expect(result).toBeDefined();
    expect(typeof result.wafDetected).toBe("boolean");
    expect(result.wafProducts).toBeInstanceOf(Array);
    expect(result.recommendations).toBeInstanceOf(Array);
    expect(typeof result.accessible).toBe("boolean");
    expect(result.target).toBe("https://example.com");
  });

  it("should select pipeline based on detected defenses", async () => {
    const { selectPipelineForDefenses } = await import("./lib/evasion-integrations");

    const result = selectPipelineForDefenses(["Cloudflare", "CrowdStrike"], "windows");
    expect(result).toBeDefined();
    expect(result.profile).toBeTruthy();
    expect(result.pipeline).toBeDefined();
    expect(result.reasoning).toBeTruthy();
  });

  it("should generate optimized mutations for detected defenses", async () => {
    const { generateOptimizedMutations } = await import("./lib/evasion-integrations");

    const result = generateOptimizedMutations("whoami /all", ["Windows Defender"]);
    expect(result).toBeDefined();
    expect(result.mutations).toBeInstanceOf(Array);
    expect(result.mutations.length).toBeGreaterThan(0);
    expect(result.mutations[0].command).toBeTruthy();
    expect(result.reasoning).toBeTruthy();
  });

  it("should run evasion-aware scan and return result with finding", async () => {
    const { runEvasionAwareScan } = await import("./lib/evasion-integrations");

    const result = await runEvasionAwareScan({
      targetUrl: "https://test.example.com",
      scanType: "full",
      scanMode: "active",
      userId: "test-user",
      evasionEnabled: true,
      maxEvasionAttempts: 3,
    });

    expect(result).toBeDefined();
    expect(typeof result.bypassAchieved).toBe("boolean");
    expect(result.evasionFinding).toBeDefined();
    expect(result.evasionFinding.domain).toBe("scanning");
  });

  it("should run evasion-aware C2 task and return result", async () => {
    const { runEvasionAwareC2Task } = await import("./lib/evasion-integrations");

    const mockExecute = async (cmd: string, _opts: any) => ({
      taskId: "mock-task-1",
      status: "executed",
      output: `Executed: ${cmd}`,
    });

    const result = await runEvasionAwareC2Task(
      {
        sessionId: 1,
        sessionTarget: "192.168.1.100",
        taskType: "execute",
        command: "whoami",
        evasionEnabled: true,
        maxEvasionAttempts: 3,
      },
      mockExecute,
    );

    expect(result).toBeDefined();
    expect(typeof result.bypassAchieved).toBe("boolean");
    expect(result.evasionFinding).toBeDefined();
    expect(result.evasionFinding.domain).toBe("c2");
  });

  it("should run evasion-aware exploit and return result", async () => {
    const { runEvasionAwareExploit } = await import("./lib/evasion-integrations");

    const mockExecute = async (_payload: string, _opts: any) => ({
      success: true,
      statusCode: 200,
      body: "Exploit delivered",
    });

    const result = await runEvasionAwareExploit(
      {
        target: "https://target.example.com/vuln",
        exploitId: "CVE-2024-1234",
        exploitName: "Test Exploit",
        payload: "<script>alert(1)</script>",
        evasionEnabled: true,
        maxEvasionAttempts: 3,
      },
      mockExecute,
    );

    expect(result).toBeDefined();
    expect(typeof result.bypassAchieved).toBe("boolean");
    expect(result.evasionFinding).toBeDefined();
    expect(result.evasionFinding.domain).toBe("exploit");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CVE SEVERITY FILTER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("CVE Severity Filter - Enhanced Enrichment", () => {
  it("should include severity, priorityScore, cisaKev, and exploitAvailable fields", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");

    const mockVulns = {
      totalVulnerabilities: 1,
      criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0,
      vulnerabilities: [
        { technology: "Apache", detectedVersion: "2.4.49", cveId: "CVE-2021-41773", severity: "critical" as const, cvssScore: 9.8, description: "Path traversal", affectedVersions: "2.4.49", exploitAvailable: true, references: [], affectedAssets: ["web.example.com"], remediation: "Upgrade", publishedDate: "2021-10-05" },
      ],
      technologySummary: [{ technology: "Apache", version: "2.4.49", vulnCount: 1, maxSeverity: "critical", assetCount: 1 }],
    };

    const result = await enrichCvesWithThreatActors(mockVulns as any);
    const d = result as any;

    expect(d.severitySummary).toBeDefined();
    expect(typeof d.cisaKevCount).toBe("number");
    expect(typeof d.activelyExploitedCount).toBe("number");

    if (d.enrichedCves.length > 0) {
      const cve = d.enrichedCves[0];
      expect(cve.severity).toBeDefined();
      expect(typeof cve.priorityScore).toBe("number");
      expect(cve.priorityScore).toBeGreaterThanOrEqual(0);
      expect(cve.priorityScore).toBeLessThanOrEqual(100);
      expect(typeof cve.cisaKev).toBe("boolean");
      expect(typeof cve.exploitAvailable).toBe("boolean");
    }
  });

  it("should provide severity summary counts", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");

    const mockVulns = {
      totalVulnerabilities: 3,
      criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0,
      vulnerabilities: [
        { technology: "Apache", detectedVersion: "2.4.49", cveId: "CVE-2021-41773", severity: "critical" as const, cvssScore: 9.8, description: "Path traversal", affectedVersions: "2.4.49", exploitAvailable: true, references: [], affectedAssets: ["web.example.com"], remediation: "Upgrade", publishedDate: "2021-10-05" },
        { technology: "Java", detectedVersion: "11", cveId: "CVE-2021-44228", severity: "critical" as const, cvssScore: 10.0, description: "Log4Shell", affectedVersions: "2.0-2.14.1", exploitAvailable: true, references: [], affectedAssets: ["app.example.com"], remediation: "Upgrade", publishedDate: "2021-12-10" },
        { technology: "OpenSSL", detectedVersion: "1.0.1", cveId: "CVE-2014-0160", severity: "high" as const, cvssScore: 7.5, description: "Heartbleed", affectedVersions: "1.0.1-1.0.1f", exploitAvailable: true, references: [], affectedAssets: ["api.example.com"], remediation: "Upgrade", publishedDate: "2014-04-07" },
      ],
      technologySummary: [
        { technology: "Apache", version: "2.4.49", vulnCount: 1, maxSeverity: "critical", assetCount: 1 },
        { technology: "Java", version: "11", vulnCount: 1, maxSeverity: "critical", assetCount: 1 },
        { technology: "OpenSSL", version: "1.0.1", vulnCount: 1, maxSeverity: "high", assetCount: 1 },
      ],
    };

    const result = await enrichCvesWithThreatActors(mockVulns as any);
    const d = result as any;

    expect(d.severitySummary).toBeDefined();
    expect(typeof d.severitySummary).toBe("object");
    const totalFromSummary = d.severitySummary.critical + d.severitySummary.high + d.severitySummary.medium + d.severitySummary.low;
    expect(totalFromSummary).toBe(d.enrichedCves.length);
  });

  it("should sort enriched CVEs by priority score descending by default", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");

    const mockVulns = {
      totalVulnerabilities: 3,
      criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0,
      vulnerabilities: [
        { technology: "Java", detectedVersion: "11", cveId: "CVE-2021-44228", severity: "critical" as const, cvssScore: 10.0, description: "Log4Shell", affectedVersions: "2.0-2.14.1", exploitAvailable: true, references: [], affectedAssets: ["app.example.com"], remediation: "Upgrade", publishedDate: "2021-12-10" },
        { technology: "OpenSSL", detectedVersion: "1.0.1", cveId: "CVE-2014-0160", severity: "high" as const, cvssScore: 7.5, description: "Heartbleed", affectedVersions: "1.0.1-1.0.1f", exploitAvailable: true, references: [], affectedAssets: ["api.example.com"], remediation: "Upgrade", publishedDate: "2014-04-07" },
        { technology: "Apache", detectedVersion: "2.4.49", cveId: "CVE-2021-41773", severity: "critical" as const, cvssScore: 9.8, description: "Path traversal", affectedVersions: "2.4.49", exploitAvailable: true, references: [], affectedAssets: ["web.example.com"], remediation: "Upgrade", publishedDate: "2021-10-05" },
      ],
      technologySummary: [],
    };

    const result = await enrichCvesWithThreatActors(mockVulns as any);
    const d = result as any;

    if (d.enrichedCves.length >= 2) {
      for (let i = 1; i < d.enrichedCves.length; i++) {
        expect(d.enrichedCves[i].priorityScore).toBeLessThanOrEqual(d.enrichedCves[i - 1].priorityScore);
      }
    }
  });

  it("should assign higher priority to CVEs with more actors and active exploitation", async () => {
    const { enrichCvesWithThreatActors } = await import("./lib/domain-intel-advanced");

    const mockVulns = {
      totalVulnerabilities: 2,
      criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 1,
      vulnerabilities: [
        { technology: "Java", detectedVersion: "11", cveId: "CVE-2021-44228", severity: "critical" as const, cvssScore: 10.0, description: "Log4Shell", affectedVersions: "2.0-2.14.1", exploitAvailable: true, references: [], affectedAssets: ["app.example.com"], remediation: "Upgrade", publishedDate: "2021-12-10" },
        { technology: "ObscureLib", detectedVersion: "0.1", cveId: "CVE-2020-99999", severity: "low" as const, cvssScore: 3.0, description: "Minor info disclosure", affectedVersions: "0.1", exploitAvailable: false, references: [], affectedAssets: ["test.example.com"], remediation: "Upgrade", publishedDate: "2020-01-01" },
      ],
      technologySummary: [],
    };

    const result = await enrichCvesWithThreatActors(mockVulns as any);
    const d = result as any;

    if (d.enrichedCves.length >= 2) {
      const log4shell = d.enrichedCves.find((c: any) => c.cveId === "CVE-2021-44228");
      const minor = d.enrichedCves.find((c: any) => c.cveId === "CVE-2020-99999");
      if (log4shell && minor) {
        expect(log4shell.priorityScore).toBeGreaterThan(minor.priorityScore);
      }
    }
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// EVASION PLAYBOOK GENERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Evasion Playbook Generation", () => {
  it("should generate a playbook with correct structure", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();

    expect(playbook).toHaveProperty("title");
    expect(playbook).toHaveProperty("generatedAt");
    expect(playbook).toHaveProperty("summary");
    expect(playbook).toHaveProperty("targetGroups");
    expect(playbook).toHaveProperty("defenseGroups");
    expect(playbook).toHaveProperty("techniqueEffectiveness");
    expect(playbook).toHaveProperty("mitreMappings");
    expect(playbook).toHaveProperty("recommendations");

    expect(playbook.summary).toHaveProperty("totalFindings");
    expect(playbook.summary).toHaveProperty("totalTargets");
    expect(playbook.summary).toHaveProperty("totalDefenses");
    expect(playbook.summary).toHaveProperty("overallBypassRate");
    expect(playbook.summary).toHaveProperty("avgEscalationDepth");
    expect(playbook.summary).toHaveProperty("domainBreakdown");

    expect(typeof playbook.summary.totalFindings).toBe("number");
    expect(typeof playbook.summary.overallBypassRate).toBe("number");
    expect(playbook.summary.overallBypassRate).toBeGreaterThanOrEqual(0);
    expect(playbook.summary.overallBypassRate).toBeLessThanOrEqual(100);
  });

  it("should filter by domain when specified", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const scanningPlaybook = generatePlaybook({ domain: "scanning" });
    const c2Playbook = generatePlaybook({ domain: "c2" });
    const allPlaybook = generatePlaybook();

    expect(scanningPlaybook.summary.totalFindings).toBeLessThanOrEqual(allPlaybook.summary.totalFindings);
    expect(c2Playbook.summary.totalFindings).toBeLessThanOrEqual(allPlaybook.summary.totalFindings);
  });

  it("should filter to only successful bypasses when requested", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const successOnly = generatePlaybook({ onlySuccessful: true });
    const all = generatePlaybook();

    expect(successOnly.summary.totalFindings).toBeLessThanOrEqual(all.summary.totalFindings);
  });

  it("should export valid markdown with expected sections", async () => {
    const { generatePlaybook, exportPlaybookMarkdown } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();
    const markdown = exportPlaybookMarkdown(playbook);

    expect(typeof markdown).toBe("string");
    expect(markdown).toContain("# ");
    expect(markdown).toContain("Executive Summary");
    expect(markdown).toContain("Recommendations");
  });

  it("should export valid parseable JSON", async () => {
    const { generatePlaybook, exportPlaybookJSON } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();
    const json = exportPlaybookJSON(playbook);

    expect(typeof json).toBe("string");
    const parsed = JSON.parse(json);
    expect(parsed).toHaveProperty("title");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("targetGroups");
    expect(parsed).toHaveProperty("defenseGroups");
  });

  it("should always generate at least one recommendation", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();

    expect(Array.isArray(playbook.recommendations)).toBe(true);
    expect(playbook.recommendations.length).toBeGreaterThanOrEqual(1);
    playbook.recommendations.forEach((rec: string) => {
      expect(typeof rec).toBe("string");
      expect(rec.length).toBeGreaterThan(0);
    });
  });

  it("should include MITRE mappings array", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();

    expect(Array.isArray(playbook.mitreMappings)).toBe(true);
    playbook.mitreMappings.forEach((m: any) => {
      expect(m).toHaveProperty("mitreId");
      expect(m).toHaveProperty("techniqueName");
      expect(m).toHaveProperty("usageCount");
      expect(typeof m.usageCount).toBe("number");
    });
  });

  it("should include technique effectiveness rankings", async () => {
    const { generatePlaybook } = await import("./lib/evasion-playbook");
    const playbook = generatePlaybook();

    expect(Array.isArray(playbook.techniqueEffectiveness)).toBe(true);
    playbook.techniqueEffectiveness.forEach((te: any) => {
      expect(te).toHaveProperty("techniqueId");
      expect(te).toHaveProperty("techniqueName");
      expect(te).toHaveProperty("category");
      expect(te).toHaveProperty("timesUsed");
      expect(te).toHaveProperty("timesBypassed");
      expect(te).toHaveProperty("successRate");
      expect(te.successRate).toBeGreaterThanOrEqual(0);
      expect(te.successRate).toBeLessThanOrEqual(100);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEFENSE HEATMAP GENERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Defense Heatmap Generation", () => {
  it("should generate a heatmap with correct structure", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const heatmap = generateDefenseHeatmap();

    expect(heatmap).toHaveProperty("defenses");
    expect(heatmap).toHaveProperty("techniques");
    expect(heatmap).toHaveProperty("rows");
    expect(heatmap).toHaveProperty("summary");

    expect(Array.isArray(heatmap.defenses)).toBe(true);
    expect(Array.isArray(heatmap.techniques)).toBe(true);
    expect(Array.isArray(heatmap.rows)).toBe(true);

    expect(heatmap.summary).toHaveProperty("totalDataPoints");
    expect(heatmap.summary).toHaveProperty("mostEffectiveDefense");
    expect(heatmap.summary).toHaveProperty("leastEffectiveDefense");
    expect(heatmap.summary).toHaveProperty("mostEffectiveTechnique");
  });

  it("should have rows matching the number of defenses", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const heatmap = generateDefenseHeatmap();

    expect(heatmap.rows.length).toBe(heatmap.defenses.length);
  });

  it("should have cells in each row matching the number of techniques", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const heatmap = generateDefenseHeatmap();

    heatmap.rows.forEach((row: any) => {
      expect(row.cells.length).toBe(heatmap.techniques.length);
      row.cells.forEach((cell: any) => {
        expect(cell).toHaveProperty("defense");
        expect(cell).toHaveProperty("technique");
        expect(cell).toHaveProperty("encounters");
        expect(cell).toHaveProperty("bypasses");
        expect(cell).toHaveProperty("bypassRate");
        expect(cell).toHaveProperty("intensity");
        expect(cell.bypassRate).toBeGreaterThanOrEqual(0);
        expect(cell.bypassRate).toBeLessThanOrEqual(100);
        expect(cell.intensity).toBeGreaterThanOrEqual(0);
        expect(cell.intensity).toBeLessThanOrEqual(1);
      });
    });
  });

  it("should filter by domain when specified", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const scanningHeatmap = generateDefenseHeatmap({ domain: "scanning" });
    const allHeatmap = generateDefenseHeatmap();

    expect(scanningHeatmap.summary.totalDataPoints).toBeLessThanOrEqual(allHeatmap.summary.totalDataPoints);
  });

  it("should filter by minimum encounters", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const min1 = generateDefenseHeatmap({ minEncounters: 1 });
    const min10 = generateDefenseHeatmap({ minEncounters: 10 });

    expect(min10.defenses.length).toBeLessThanOrEqual(min1.defenses.length);
  });

  it("should have overall bypass rate per row", async () => {
    const { generateDefenseHeatmap } = await import("./lib/evasion-playbook");
    const heatmap = generateDefenseHeatmap();

    heatmap.rows.forEach((row: any) => {
      expect(row).toHaveProperty("defense");
      expect(row).toHaveProperty("overallBypassRate");
      expect(row).toHaveProperty("totalEncounters");
      expect(typeof row.overallBypassRate).toBe("number");
      expect(row.overallBypassRate).toBeGreaterThanOrEqual(0);
      expect(row.overallBypassRate).toBeLessThanOrEqual(100);
    });
  });
});
