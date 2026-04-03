import { describe, it, expect } from "vitest";

// ─── Test Plan Generator Module ─────────────────────────────────────────
describe("Test Plan Generator Module", () => {
  it("should export generateTestPlan and testPlanToMarkdown functions", async () => {
    const mod = await import("./lib/test-plan-generator");
    expect(typeof mod.generateTestPlan).toBe("function");
    expect(typeof mod.testPlanToMarkdown).toBe("function");
  });

  it("testPlanToMarkdown should produce valid markdown from a TestPlan object", async () => {
    const { testPlanToMarkdown } = await import("./lib/test-plan-generator");

    // Build a mock TestPlan matching the actual TestPlan interface
    const mockPlan: any = {
      id: "TP-1-1234567890",
      engagementId: 1,
      planType: "penetration_test",
      version: "1.0",
      generatedAt: Date.now(),
      generatedBy: "test-runner",
      title: "Penetration Test Plan — example.com",
      subtitle: "External Penetration Test Assessment",
      classification: "CONFIDENTIAL — AceofCloud",
      documentControl: {
        version: "1.0",
        date: "2026-04-03",
        author: "Harrison Cook",
        status: "draft",
      },
      sections: [
        {
          id: "scope",
          title: "Scope and Objectives",
          content: "Test content for scope section.",
          nistReference: "NIST SP 800-115 §3.1",
          standardsReference: "PTES Pre-Engagement",
        },
        {
          id: "methodology",
          title: "Methodology",
          content: "Test content for methodology section.",
          nistReference: "NIST SP 800-115 §4",
        },
      ],
      structuredData: {
        estimatedDuration: "10 business days",
        attackVectors: [
          {
            id: "av2_external_network",
            name: "External Network Attack Surface",
            description: "Port scanning and service enumeration",
            targets: ["web.example.com"],
            methodology: "Nuclei + httpx",
            tools: ["nuclei", "httpx"],
            estimatedDuration: "2 days",
            riskLevel: "high",
            mitreTechniques: ["T1046", "T1190"],
          },
        ],
        toolInventory: [
          {
            tool: "Nuclei",
            purpose: "Vulnerability scanning",
            phase: "Vulnerability Analysis",
            license: "MIT",
          },
        ],
        schedule: [
          {
            phase: "Reconnaissance",
            startDay: 1,
            endDay: 2,
            activities: ["Passive recon", "OSINT"],
          },
        ],
        riskMitigation: [
          {
            risk: "Service disruption during port scanning",
            mitigation: "Use rate-limited scanning with --max-rate 100",
            owner: "Assessment Team Lead",
          },
        ],
        successCriteria: ["Identify all critical vulnerabilities"],
        deliverables: [
          {
            name: "Final Report",
            description: "Comprehensive penetration test report",
            dueDate: "Day 12",
          },
        ],
      },
      approvalStatus: "pending",
      approvalHistory: [],
    };

    const markdown = testPlanToMarkdown(mockPlan);

    // Document header
    expect(markdown).toContain("Penetration Test Plan");
    expect(markdown).toContain("CONFIDENTIAL");
    expect(markdown).toContain("Harrison Cook");

    // NIST references
    expect(markdown).toContain("NIST SP 800-115");

    // Sections
    expect(markdown).toContain("Scope and Objectives");
    expect(markdown).toContain("Methodology");

    // Attack vectors table
    expect(markdown).toContain("External Network Attack Surface");
    expect(markdown).toContain("T1046");

    // Tool inventory table
    expect(markdown).toContain("Nuclei");
    expect(markdown).toContain("Vulnerability scanning");

    // Schedule table
    expect(markdown).toContain("Reconnaissance");
    expect(markdown).toContain("Day 1");

    // Approval signature block
    expect(markdown).toContain("Approval Signatures");
    expect(markdown).toContain("Technical Reviewer");

    // Valid markdown structure
    expect(markdown).toContain("#");
    expect(markdown).toContain("|");
  });
});

// ─── Engagement Report Handoff Module ───────────────────────────────────
describe("Engagement Report Handoff Module", () => {
  it("should export generateTestPlanAdherence function", async () => {
    const mod = await import("./lib/engagement-report-handoff");
    expect(typeof mod.generateTestPlanAdherence).toBe("function");
  });

  it("should handle null test plan gracefully", async () => {
    const { generateTestPlanAdherence } = await import(
      "./lib/engagement-report-handoff"
    );

    const mockState: any = {
      engagementId: 1,
      engagementName: "Test Engagement",
      engagementType: "pentest",
      phase: "completed",
      assets: [],
      stats: {
        exploitsAttempted: 5,
        exploitsSucceeded: 2,
        exploitsFailed: 3,
        credentialsHarvested: 1,
        pivotsMade: 0,
        dataExfiltrated: 0,
        c2Established: 0,
      },
      log: [],
      startedAt: Date.now() - 86400000,
      completedAt: Date.now(),
      metadata: {},
    };

    const result = await generateTestPlanAdherence(mockState, null);

    // Should produce a valid adherence report even without a test plan
    expect(result).toBeDefined();
    expect(typeof result.adherencePercentage).toBe("number");
    expect(result.adherencePercentage).toBeGreaterThanOrEqual(0);
    expect(result.adherencePercentage).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.ptesPhaseCompletion)).toBe(true);
    expect(result.ptesPhaseCompletion.length).toBeGreaterThan(0);
    expect(typeof result.totalPlannedTests).toBe("number");
    expect(typeof result.executedTests).toBe("number");
    expect(typeof result.skippedTests).toBe("number");
    expect(typeof result.blockedTests).toBe("number");
    expect(Array.isArray(result.coverageGaps)).toBe(true);
    expect(Array.isArray(result.recommendations)).toBe(true);
    // generatedAt is a number (timestamp) in the actual interface
    expect(typeof result.generatedAt).toBe("number");
  });
});

// ─── Test Plan Generator Router ─────────────────────────────────────────
describe("Test Plan Generator Router", () => {
  it("should export testPlanGeneratorRouter", async () => {
    const mod = await import("./routers/test-plan-generator");
    expect(mod.testPlanGeneratorRouter).toBeDefined();
  });
});

// ─── CARVER Feedback Loop Module ────────────────────────────────────────
describe("CARVER Feedback Loop Module", () => {
  it("should export applyCarverFeedbackLoop function", async () => {
    const mod = await import("./lib/carver-feedback-loop");
    expect(typeof mod.applyCarverFeedbackLoop).toBe("function");
  });
});

// ─── New Passive Connectors ─────────────────────────────────────────────
describe("New Passive Connectors", () => {
  it("AlienVault OTX connector should have correct name and collect function", async () => {
    const mod = await import("./lib/passive/alienvault-otx");
    expect(mod.alienvaultOtxConnector).toBeDefined();
    expect(mod.alienvaultOtxConnector.name).toBe("alienvault-otx");
    expect(typeof mod.alienvaultOtxConnector.collect).toBe("function");
  });

  it("Google SafeBrowsing connector should have correct name and collect function", async () => {
    const mod = await import("./lib/passive/google-safebrowsing");
    expect(mod.googleSafeBrowsingConnector).toBeDefined();
    expect(mod.googleSafeBrowsingConnector.name).toBe("google-safebrowsing");
    expect(typeof mod.googleSafeBrowsingConnector.collect).toBe("function");
  });

  it("PhishTank connector should have correct name and collect function", async () => {
    const mod = await import("./lib/passive/phishtank");
    expect(mod.phishtankConnector).toBeDefined();
    expect(mod.phishtankConnector.name).toBe("phishtank");
    expect(typeof mod.phishtankConnector.collect).toBe("function");
  });

  it("Dehashed WHOIS connector should have correct name and collect function", async () => {
    const mod = await import("./lib/passive/dehashed-whois");
    expect(mod.dehashedWhoisConnector).toBeDefined();
    expect(mod.dehashedWhoisConnector.name).toBe("dehashed_whois");
    expect(typeof mod.dehashedWhoisConnector.collect).toBe("function");
  });

  it("Darkweb Cross-Reference connector should have correct name and collect function", async () => {
    const mod = await import("./lib/passive/darkweb-crossref");
    expect(mod.darkwebCrossrefConnector).toBeDefined();
    expect(mod.darkwebCrossrefConnector.name).toBe("darkweb_crossref");
    expect(typeof mod.darkwebCrossrefConnector.collect).toBe("function");
  });
});

// ─── Dehashed Connector ─────────────────────────────────────────────────
describe("Dehashed Connector", () => {
  it("should export dehashedConnector with correct name", async () => {
    const mod = await import("./lib/passive/dehashed");
    expect(mod.dehashedConnector).toBeDefined();
    expect(mod.dehashedConnector.name).toBe("dehashed");
    expect(typeof mod.dehashedConnector.collect).toBe("function");
  });
});

// ─── DI EASM Report Export ──────────────────────────────────────────────
// Note: The DI EASM report export is a client-side module at
// client/src/lib/export-di-report.ts (uses jsPDF in-browser).
// It cannot be tested in vitest server context due to DOM dependencies.
// The export function is: exportDiEasmReport()
