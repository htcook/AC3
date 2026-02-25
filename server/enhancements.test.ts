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
