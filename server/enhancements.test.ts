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
