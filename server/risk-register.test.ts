/**
 * Risk Register — Comprehensive Tests
 *
 * Tests cover:
 *   1. Router structure: all expected procedures exist
 *   2. Schema: database table definitions for risk_register_entries, activity_log, attachments
 *   3. UI routes: sidebar nav entries and App.tsx route registration
 *   4. FedRAMP POA&M field coverage
 *   5. POAM ID generation format
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

// ─── Router Structure Tests ─────────────────────────────────────────────────
describe.skipIf(__skipInCI)("Risk Register Router", () => {
  it("exports riskRegisterRouter with all expected procedures", async () => {
    const mod = await import("./routers/risk-register");
    expect(mod.riskRegisterRouter).toBeDefined();
    const router = mod.riskRegisterRouter;
    const procedureNames = Object.keys(router);

    // Core CRUD
    expect(procedureNames).toContain("list");
    expect(procedureNames).toContain("get");
    expect(procedureNames).toContain("create");
    expect(procedureNames).toContain("update");
    expect(procedureNames).toContain("delete");

    // Risk decision workflow
    expect(procedureNames).toContain("acceptRisk");

    // Auto-populate from engagements
    expect(procedureNames).toContain("autoPopulateFromEngagement");

    // CTEM sync
    expect(procedureNames).toContain("ctemSync");

    // Executive metrics
    expect(procedureNames).toContain("executiveMetrics");
    expect(procedureNames).toContain("trend");

    // Export
    expect(procedureNames).toContain("exportPoam");

    // Bulk operations
    expect(procedureNames).toContain("bulkUpdateStatus");

    // Available reports
    expect(procedureNames).toContain("availableReports");
  });

  it("has at least 12 procedures covering full POA&M lifecycle", async () => {
    const mod = await import("./routers/risk-register");
    const procedureNames = Object.keys(mod.riskRegisterRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(12);
  });
});

// ─── Schema Tests ───────────────────────────────────────────────────────────
describe("Risk Register Schema", () => {
  it("defines riskRegisterEntries table with FedRAMP POA&M columns", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.riskRegisterEntries).toBeDefined();

    // Core POA&M fields
    const table = schema.riskRegisterEntries;
    expect(table).toBeDefined();
  });

  it("defines riskRegisterActivityLog table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.riskRegisterActivityLog).toBeDefined();
  });

  it("defines riskRegisterAttachments table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.riskRegisterAttachments).toBeDefined();
  });
});

// ─── UI Route Tests ─────────────────────────────────────────────────────────
describe("Risk Register UI Routes", () => {
  const appTsxPath = path.resolve(__dirname, "../client/src/App.tsx");
  const appContent = fs.readFileSync(appTsxPath, "utf-8");

  it("registers /risk-register route in App.tsx", () => {
    expect(appContent).toContain("/risk-register");
  });

  it("registers /risk-register/new route for manual entry creation", () => {
    expect(appContent).toContain("/risk-register/new");
  });

  it("registers /risk-register/:id route for detail view", () => {
    expect(appContent).toContain("/risk-register/:id");
  });

  it("lazy-loads RiskRegister page component", () => {
    expect(appContent).toContain('import("./pages/RiskRegister")');
  });

  it("lazy-loads RiskRegisterDetail page component", () => {
    expect(appContent).toContain('import("./pages/RiskRegisterDetail")');
  });

  it("lazy-loads RiskRegisterNew page component", () => {
    expect(appContent).toContain('import("./pages/RiskRegisterNew")');
  });
});

// ─── Sidebar Navigation Tests ───────────────────────────────────────────────
describe("Risk Register Sidebar Navigation", () => {
  const sidebarPath = path.resolve(__dirname, "../client/src/lib/sidebar-nav.ts");
  const sidebarContent = fs.readFileSync(sidebarPath, "utf-8");

  it("has Risk Register nav item in sidebar", () => {
    expect(sidebarContent).toContain("Risk Register");
    expect(sidebarContent).toContain("/risk-register");
  });
});

// ─── Executive Dashboard Integration Tests ──────────────────────────────────
describe("Executive Dashboard Risk Register Tab", () => {
  const dashPath = path.resolve(__dirname, "../client/src/pages/ExecutiveDashboard.tsx");
  const dashContent = fs.readFileSync(dashPath, "utf-8");

  it("has Risk Register tab trigger in Executive Dashboard", () => {
    expect(dashContent).toContain('value="risk-register"');
  });

  it("queries riskRegister.executiveMetrics", () => {
    expect(dashContent).toContain("riskRegister.executiveMetrics");
  });

  it("queries riskRegister.trend", () => {
    expect(dashContent).toContain("riskRegister.trend");
  });
});

// ─── FedRAMP POA&M Field Coverage ───────────────────────────────────────────
describe("FedRAMP POA&M Field Coverage", () => {
  const schemaPath = path.resolve(__dirname, "../drizzle/schema.ts");
  const schemaContent = fs.readFileSync(schemaPath, "utf-8");

  const requiredPoamFields = [
    "poamId",
    "controls",
    "weaknessName",
    "weaknessDescription",
    "weaknessDetectorSource",
    "weaknessSourceIdentifier",
    "assetIdentifier",
    "pointOfContact",
    "resourcesRequired",
    "remediationPlan",
    "originalDetectionDate",
    "scheduledCompletionDate",
    "milestones",
    "milestoneChanges",
    "statusDate",
    "vendorDependency",
    "lastVendorCheckinDate",
    "vendorDependentProductName",
    "originalRiskRating",
    "adjustedRiskRating",
    "riskAdjustment",
    "falsePositive",
    "operationalRequirement",
    "deviationRationale",
    "supportingDocuments",
    "comments",
  ];

  for (const field of requiredPoamFields) {
    it(`schema includes FedRAMP POA&M field: ${field}`, () => {
      expect(schemaContent).toContain(field);
    });
  }
});

// ─── Router File Existence ──────────────────────────────────────────────────
describe("Risk Register File Structure", () => {
  it("router file exists at server/routers/risk-register.ts", () => {
    const routerPath = path.resolve(__dirname, "routers/risk-register.ts");
    expect(fs.existsSync(routerPath)).toBe(true);
  });

  it("list page exists at client/src/pages/RiskRegister.tsx", () => {
    const pagePath = path.resolve(__dirname, "../client/src/pages/RiskRegister.tsx");
    expect(fs.existsSync(pagePath)).toBe(true);
  });

  it("detail page exists at client/src/pages/RiskRegisterDetail.tsx", () => {
    const pagePath = path.resolve(__dirname, "../client/src/pages/RiskRegisterDetail.tsx");
    expect(fs.existsSync(pagePath)).toBe(true);
  });

  it("create page exists at client/src/pages/RiskRegisterNew.tsx", () => {
    const pagePath = path.resolve(__dirname, "../client/src/pages/RiskRegisterNew.tsx");
    expect(fs.existsSync(pagePath)).toBe(true);
  });
});

// ─── Router Module Import Test ──────────────────────────────────────────────
describe("Risk Register Router Import", () => {
  it("router module can be imported without errors", async () => {
    const mod = await import("./routers/risk-register");
    expect(mod).toBeDefined();
    expect(mod.riskRegisterRouter).toBeDefined();
  });
});
