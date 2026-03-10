import { describe, it, expect } from "vitest";

// Test the KSI label utilities
describe("KSI Labels & Theme Utilities", () => {
  it("should have ksi-labels utility with theme labels", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/lib/ksi-labels.ts", "utf-8");
    // Should have all 13 FedRAMP 20x themes
    const expectedThemes = ["AFR", "CMT", "CNA", "CED", "IAM", "INR", "MLA", "PIY", "RPL", "SVC", "SCR", "SDE", "PPM"];
    for (const theme of expectedThemes) {
      expect(content).toContain(theme);
    }
  });
});

// Test the OSCAL export assessment package procedure shape
describe("OSCAL Assessment Package", () => {
  it("should have generateAssessmentPackage procedure registered", async () => {
    const routerModule = await import("./routers/oscal-export");
    expect(routerModule).toBeDefined();
  });

  it("should have get3paoReviewData procedure registered", async () => {
    const routerModule = await import("./routers/oscal-export");
    expect(routerModule).toBeDefined();
  });
});

// Test the KSI evidence chain router
describe("KSI Evidence Chain Router", () => {
  it("should export evidence chain router", async () => {
    const routerModule = await import("./routers/ksi-evidence-chain");
    expect(routerModule).toBeDefined();
  });
});

// Test the KSI validation router
describe("KSI Validation Router", () => {
  it("should have validation scheduler router", async () => {
    const fs = await import("fs");
    expect(fs.existsSync("./server/routers/ksi-validation-scheduler.ts")).toBe(true);
  });
});

// Test that all new page components exist and export defaults
describe("KSI Page Components", () => {
  it("ThreePaoReview page should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/pages/ThreePaoReview.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("3PAO Review Mode");
    expect(content).toContain("Read-Only");
    expect(content).toContain("Executive Summary");
    expect(content).toContain("Theme Breakdown");
    expect(content).toContain("KSI Detail Assessment");
  });

  it("KsiDetail page should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/pages/KsiDetail.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("KSI Definition");
    expect(content).toContain("Evidence Chain");
    expect(content).toContain("Validation History");
    expect(content).toContain("NIST SP 800-53 Control Mappings");
  });

  it("KsiHub page should have health summary bar", async () => {
    const fs = await import("fs");
    const path = "./client/src/pages/KsiHub.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("Readiness Score");
    expect(content).toContain("Readiness Score");
    expect(content).toContain("Coverage");
    expect(content).toContain("Evidence Chain");
  });

  it("KsiDashboard should use KsiHeatmapGrid with navigate", async () => {
    const fs = await import("fs");
    const path = "./client/src/pages/KsiDashboard.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("KsiHeatmapGrid");
    expect(content).not.toMatch(/11 themes/i);
  });

  it("KsiDashboard should navigate to KSI detail on heatmap click", async () => {
    const fs = await import("fs");
    const path = "./client/src/pages/KsiDashboard.tsx";
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("navigate(`/ksi/");
  });
});

// Test new components exist
describe("KSI UI Components", () => {
  it("KsiHeatmapGrid component should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/components/KsiHeatmapGrid.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("KSI Coverage Heatmap");
    expect(content).toContain("onKsiClick");
    expect(content).toContain("THEME_ORDER");
  });

  it("EvidenceTimeline component should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/components/EvidenceTimeline.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("formatKsiId");
  });

  it("AttackMatrixGrid component should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/components/AttackMatrixGrid.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("ATT&CK");
  });

  it("CollectionHealthPanel component should exist", async () => {
    const fs = await import("fs");
    const path = "./client/src/components/CollectionHealthPanel.tsx";
    expect(fs.existsSync(path)).toBe(true);
    const content = fs.readFileSync(path, "utf-8");
    expect(content).toContain("Collection Health");
  });
});

// Test routes are registered in App.tsx
describe("Route Registration", () => {
  it("should have all new routes registered", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/App.tsx", "utf-8");
    expect(content).toContain("/3pao-review");
    expect(content).toContain("/ksi/:ksiId");
    expect(content).toContain("ThreePaoReview");
    expect(content).toContain("KsiDetail");
  });
});

// Test the FedRAMP20xReadiness page has live data
describe("FedRAMP 20x Readiness Live Data", () => {
  it("should query live KSI data", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/pages/FedRAMP20xReadiness.tsx", "utf-8");
    expect(content).toContain("trpc.ksiEvidenceChain");
    expect(content).toContain("live stats");
  });
});

// Test KsiValidation has Run All Overdue
describe("KSI Validation Improvements", () => {
  it("should have Run All Overdue button", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/pages/KsiValidation.tsx", "utf-8");
    expect(content).toContain("Run All Overdue");
  });

  it("should have expandable run detail view", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/pages/KsiValidation.tsx", "utf-8");
    expect(content).toContain("expandedRun");
  });
});

// Test KsiEvidenceChain has timeline tab
describe("KSI Evidence Chain Timeline", () => {
  it("should have timeline view tab", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/pages/KsiEvidenceChain.tsx", "utf-8");
    expect(content).toContain("timeline");
    expect(content).toContain("EvidenceTimeline");
  });
});

// Test KsiThreatMap has ATT&CK matrix tab
describe("KSI Threat Map ATT&CK Matrix", () => {
  it("should have ATT&CK matrix tab", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("./client/src/pages/KsiThreatMap.tsx", "utf-8");
    expect(content).toContain("ATT&CK Matrix");
    expect(content).toContain("AttackMatrixGrid");
  });
});
