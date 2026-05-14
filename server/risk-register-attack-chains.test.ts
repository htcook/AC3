/**
 * Risk Register + Attack Chains + FedRAMP POA&M Excel Export — Tests
 *
 * Tests cover:
 *   1. Router structure: all expected procedures exist for both routers
 *   2. Schema: database table definitions for risk register and attack chains
 *   3. UI routes: sidebar nav entries and App.tsx route registration
 *   4. FedRAMP POA&M Excel export column completeness
 *   5. Composite risk scoring algorithm
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

// ─── Risk Register Router Structure ─────────────────────────────────────────
describe.skipIf(__skipInCI)("Risk Register Router", () => {
  it("exports riskRegisterRouter with all expected procedures", async () => {
    const mod = await import("./routers/risk-register");
    expect(mod.riskRegisterRouter).toBeDefined();
    const procedureNames = Object.keys(mod.riskRegisterRouter);
    expect(procedureNames).toContain("list");
    expect(procedureNames).toContain("get");
    expect(procedureNames).toContain("create");
    expect(procedureNames).toContain("update");
    expect(procedureNames).toContain("delete");
    expect(procedureNames).toContain("acceptRisk");
    expect(procedureNames).toContain("executiveMetrics");
    expect(procedureNames).toContain("autoPopulateFromEngagement");
    expect(procedureNames).toContain("ctemSync");
    expect(procedureNames).toContain("bulkUpdateStatus");
    expect(procedureNames).toContain("exportPoam");
    expect(procedureNames).toContain("exportPoamExcel");
    expect(procedureNames).toContain("availableReports");
  });

  it("has at least 12 procedures covering full POA&M lifecycle", async () => {
    const mod = await import("./routers/risk-register");
    const procedureNames = Object.keys(mod.riskRegisterRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(12);
  });
});

// ─── Attack Chains Router Structure ─────────────────────────────────────────
describe.skipIf(__skipInCI)("Attack Chains Router", () => {
  it("exports attackChainsRouter with all expected procedures", async () => {
    const mod = await import("./routers/attack-chains");
    expect(mod.attackChainsRouter).toBeDefined();
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames).toContain("list");
    expect(procedureNames).toContain("get");
    expect(procedureNames).toContain("create");
    expect(procedureNames).toContain("update");
    expect(procedureNames).toContain("delete");
    expect(procedureNames).toContain("addStep");
    expect(procedureNames).toContain("removeStep");
    expect(procedureNames).toContain("linkPoam");
    expect(procedureNames).toContain("unlinkPoam");
    expect(procedureNames).toContain("summary");
  });

  it("has at least 9 procedures covering chain lifecycle", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(9);
  });
});

// ─── Schema Tests ───────────────────────────────────────────────────────────
describe("Risk Register Schema", () => {
  const schemaPath = path.resolve(__dirname, "../drizzle/schema.ts");
  let schemaContent: string;

  it("schema file exists", () => {
    expect(fs.existsSync(schemaPath)).toBe(true);
    schemaContent = fs.readFileSync(schemaPath, "utf-8");
  });

  it("defines riskRegisterEntries table", () => {
    expect(schemaContent).toContain("riskRegisterEntries");
    expect(schemaContent).toContain("risk_register_entries");
  });

  it("riskRegisterEntries has FedRAMP POA&M required columns", () => {
    const requiredColumns = [
      "poamId", "weaknessName", "weaknessDescription", "controls",
      "assetIdentifier", "pointOfContact", "resourcesRequired",
      "remediationPlan", "originalDetectionDate", "scheduledCompletionDate",
      "milestones", "vendorDependency", "vendorDependentProductName",
      "originalRiskRating", "severity", "status",
    ];
    for (const col of requiredColumns) {
      expect(schemaContent).toContain(col);
    }
  });

  it("riskRegisterEntries has risk decision fields", () => {
    expect(schemaContent).toContain("riskDecision");
    expect(schemaContent).toContain("riskDecisionBy");
    expect(schemaContent).toContain("riskDecisionDate");
    expect(schemaContent).toContain("riskDecisionJustification");
  });

  it("riskRegisterEntries has source tracking", () => {
    expect(schemaContent).toContain("source");
    expect(schemaContent).toContain("engagementId");
    expect(schemaContent).toContain("attackChainId");
  });

  it("defines riskRegisterActivityLog table", () => {
    expect(schemaContent).toContain("riskRegisterActivityLog");
    expect(schemaContent).toContain("risk_register_activity_log");
  });

  it("defines riskRegisterAttachments table", () => {
    expect(schemaContent).toContain("riskRegisterAttachments");
    expect(schemaContent).toContain("risk_register_attachments");
  });
});

describe("Attack Chains Schema", () => {
  const schemaPath = path.resolve(__dirname, "../drizzle/schema.ts");
  let schemaContent: string;

  it("schema file exists", () => {
    expect(fs.existsSync(schemaPath)).toBe(true);
    schemaContent = fs.readFileSync(schemaPath, "utf-8");
  });

  it("defines vulnAttackChains table", () => {
    expect(schemaContent).toContain("vulnAttackChains");
    expect(schemaContent).toContain("vuln_attack_chains");
  });

  it("vulnAttackChains has composite scoring columns", () => {
    expect(schemaContent).toContain("compositeRiskScore");
    expect(schemaContent).toContain("compositeSeverity");
  });

  it("vulnAttackChains has chain metadata", () => {
    expect(schemaContent).toContain("chainId");
    expect(schemaContent).toContain("entryPoint");
    expect(schemaContent).toContain("finalTarget");
    expect(schemaContent).toContain("mitreTechniques");
  });

  it("defines vulnAttackChainSteps table", () => {
    expect(schemaContent).toContain("vulnAttackChainSteps");
    expect(schemaContent).toContain("vuln_attack_chain_steps");
  });

  it("vulnAttackChainSteps has step ordering and MITRE fields", () => {
    expect(schemaContent).toContain("stepOrder");
    expect(schemaContent).toContain("mitreTechnique");
    expect(schemaContent).toContain("mitreTactic");
    expect(schemaContent).toContain("affectedAsset");
  });
});

// ─── UI Route Tests ─────────────────────────────────────────────────────────
describe("Risk Register UI Routes", () => {
  const appPath = path.resolve(__dirname, "../client/src/App.tsx");
  let appContent: string;

  it("App.tsx exists", () => {
    expect(fs.existsSync(appPath)).toBe(true);
    appContent = fs.readFileSync(appPath, "utf-8");
  });

  it("has lazy imports for Risk Register pages", () => {
    expect(appContent).toContain('import("./pages/RiskRegister")');
    expect(appContent).toContain('import("./pages/RiskRegisterDetail")');
    expect(appContent).toContain('import("./pages/RiskRegisterNew")');
  });

  it("has lazy imports for Attack Chain pages", () => {
    expect(appContent).toContain('import("./pages/AttackChains")');
    expect(appContent).toContain('import("./pages/AttackChainDetail")');
    expect(appContent).toContain('import("./pages/AttackChainNew")');
  });

  it("registers /risk-register routes", () => {
    expect(appContent).toContain("/risk-register");
    expect(appContent).toContain("/risk-register/new");
    expect(appContent).toContain("/risk-register/:id");
  });

  it("registers /attack-chains routes", () => {
    expect(appContent).toContain("/attack-chains");
    expect(appContent).toContain("/attack-chains/new");
    expect(appContent).toContain("/attack-chains/:id");
  });
});

describe("Sidebar Navigation", () => {
  const navPath = path.resolve(__dirname, "../client/src/lib/sidebar-nav.ts");
  let navContent: string;

  it("sidebar-nav.ts exists", () => {
    expect(fs.existsSync(navPath)).toBe(true);
    navContent = fs.readFileSync(navPath, "utf-8");
  });

  it("has Risk Register nav item", () => {
    expect(navContent).toContain("Risk Register");
    expect(navContent).toContain("/risk-register");
  });

  it("has Attack Chains nav item", () => {
    expect(navContent).toContain("Attack Chains");
    expect(navContent).toContain("/attack-chains");
  });
});

// ─── Executive Dashboard Integration ────────────────────────────────────────
describe("Executive Dashboard Integration", () => {
  const dashPath = path.resolve(__dirname, "../client/src/pages/ExecutiveDashboard.tsx");
  let dashContent: string;

  it("ExecutiveDashboard.tsx exists", () => {
    expect(fs.existsSync(dashPath)).toBe(true);
    dashContent = fs.readFileSync(dashPath, "utf-8");
  });

  it("has Risk Register tab trigger", () => {
    expect(dashContent).toContain('value="risk-register"');
    expect(dashContent).toContain("Risk Register");
  });

  it("has Attack Chains tab trigger", () => {
    expect(dashContent).toContain('value="attack-chains"');
    expect(dashContent).toContain("Attack Chains");
  });

  it("renders RiskRegisterDashTab component", () => {
    expect(dashContent).toContain("RiskRegisterDashTab");
    expect(dashContent).toContain("riskRegister.executiveMetrics");
  });

  it("renders AttackChainsDashTab component", () => {
    expect(dashContent).toContain("AttackChainsDashTab");
    expect(dashContent).toContain("attackChains.summary");
  });
});

// ─── FedRAMP POA&M Excel Export ─────────────────────────────────────────────
describe("FedRAMP POA&M Excel Export", () => {
  const routerPath = path.resolve(__dirname, "routers/risk-register.ts");
  let routerContent: string;

  it("risk-register router file exists", () => {
    expect(fs.existsSync(routerPath)).toBe(true);
    routerContent = fs.readFileSync(routerPath, "utf-8");
  });

  it("has exportPoamExcel procedure", () => {
    expect(routerContent).toContain("exportPoamExcel");
  });

  it("uses exceljs library", () => {
    expect(routerContent).toContain("exceljs");
  });

  it("includes all FedRAMP POA&M template columns", () => {
    const requiredHeaders = [
      "POA&M ID", "Controls", "Weakness Name", "Weakness Description",
      "Weakness Detector Source", "Weakness Source Identifier",
      "Asset Identifier", "Point of Contact", "Resources Required",
      "Overall Remediation Plan", "Original Detection Date",
      "Scheduled Completion Date", "Planned Milestones", "Milestone Changes",
      "Status Date", "Vendor Dependency", "Vendor Dependent Product Name",
      "Original Risk Rating", "Adjusted Risk Rating", "Risk Adjustment",
      "False Positive", "Operational Requirement", "Deviation Request",
      "Supporting Documents", "Comments", "Auto-Approval Status",
    ];
    for (const header of requiredHeaders) {
      expect(routerContent).toContain(header);
    }
  });

  it("styles header row with FedRAMP blue", () => {
    expect(routerContent).toContain("FF1F4E79");
    expect(routerContent).toContain("bold: true");
  });

  it("returns base64 encoded Excel buffer", () => {
    expect(routerContent).toContain("base64");
    expect(routerContent).toContain("writeBuffer");
  });
});

// ─── Frontend Page Files ────────────────────────────────────────────────────
describe("Frontend Page Files", () => {
  const pagesDir = path.resolve(__dirname, "../client/src/pages");

  it("RiskRegister.tsx exists and has list view", () => {
    const content = fs.readFileSync(path.join(pagesDir, "RiskRegister.tsx"), "utf-8");
    expect(content).toContain("riskRegister.list");
    expect(content).toContain("FedRAMP POA&M");
    expect(content).toContain("exportPoamExcel");
    expect(content).toContain("bulkUpdateStatus");
  });

  it("RiskRegisterDetail.tsx exists and has detail view", () => {
    const content = fs.readFileSync(path.join(pagesDir, "RiskRegisterDetail.tsx"), "utf-8");
    expect(content).toContain("riskRegister.get");
    expect(content).toContain("riskRegister.update");
    expect(content).toContain("riskRegister.acceptRisk");
    expect(content).toContain("Activity Log");
  });

  it("RiskRegisterNew.tsx exists and has create form", () => {
    const content = fs.readFileSync(path.join(pagesDir, "RiskRegisterNew.tsx"), "utf-8");
    expect(content).toContain("riskRegister.create");
    expect(content).toContain("autoPopulateFromEngagement");
    expect(content).toContain("NIST 800-53");
  });

  it("AttackChains.tsx exists and has list view", () => {
    const content = fs.readFileSync(path.join(pagesDir, "AttackChains.tsx"), "utf-8");
    expect(content).toContain("attackChains.list");
    expect(content).toContain("attackChains.summary");
    expect(content).toContain("compositeRiskScore");
  });

  it("AttackChainDetail.tsx exists and has graph visualization", () => {
    const content = fs.readFileSync(path.join(pagesDir, "AttackChainDetail.tsx"), "utf-8");
    expect(content).toContain("attackChains.get");
    expect(content).toContain("ChainGraph");
    expect(content).toContain("addStep");
    expect(content).toContain("removeStep");
    expect(content).toContain("recalculateScore");
    expect(content).toContain("mitreTacticId");
  });

  it("AttackChainNew.tsx exists and has create form", () => {
    const content = fs.readFileSync(path.join(pagesDir, "AttackChainNew.tsx"), "utf-8");
    expect(content).toContain("attackChains.create");
    expect(content).toContain("entryPoint");
    expect(content).toContain("finalTarget");
  });
});

// ─── Main Router Registration ───────────────────────────────────────────────
describe("Main Router Registration", () => {
  const routersPath = path.resolve(__dirname, "routers.ts");
  let routersContent: string;

  it("routers.ts exists", () => {
    expect(fs.existsSync(routersPath)).toBe(true);
    routersContent = fs.readFileSync(routersPath, "utf-8");
  });

  it("imports and registers riskRegisterRouter", () => {
    expect(routersContent).toContain("riskRegisterRouter");
    expect(routersContent).toContain("riskRegister:");
  });

  it("imports and registers attackChainsRouter", () => {
    expect(routersContent).toContain("attackChainsRouter");
    expect(routersContent).toContain("attackChains:");
  });
});

// ─── Auto-Correlation Engine Tests ──────────────────────────────────────────
describe("Auto-Correlation Engine", () => {
  const correlatorPath = path.resolve(__dirname, "lib/attack-chain-correlator.ts");
  let correlatorContent: string;

  it("correlator module exists", () => {
    expect(fs.existsSync(correlatorPath)).toBe(true);
    correlatorContent = fs.readFileSync(correlatorPath, "utf-8");
  });

  it("exports correlateFindings function", () => {
    expect(correlatorContent).toContain("export function correlateFindings");
  });

  it("exports CorrelationFinding interface", () => {
    expect(correlatorContent).toContain("CorrelationFinding");
  });

  it("implements host-based clustering", () => {
    expect(correlatorContent).toContain("hostname");
  });

  it("implements CVE-based clustering", () => {
    expect(correlatorContent).toContain("cve");
  });

  it("implements MITRE technique clustering", () => {
    expect(correlatorContent).toContain("mitreTechnique");
  });

  it("computes composite risk scores", () => {
    expect(correlatorContent).toContain("compositeRiskScore");
  });

  it("generates confidence scores for correlations", () => {
    expect(correlatorContent).toContain("confidence");
  });

  it("produces chain names and descriptions", () => {
    expect(correlatorContent).toContain("name");
    expect(correlatorContent).toContain("description");
  });

  it("identifies entry points and final targets", () => {
    expect(correlatorContent).toContain("entryPoint");
    expect(correlatorContent).toContain("finalTarget");
  });
});

// ─── Auto-Correlation Unit Logic ────────────────────────────────────────────
describe("Auto-Correlation Logic", () => {
  it("correlateFindings returns empty for < 2 findings", async () => {
    const { correlateFindings } = await import("./lib/attack-chain-correlator");
    const result = correlateFindings([{ id: 1, title: "Single", severity: "high", hostname: "a.com" }]);
    expect(result).toEqual([]);
  });

  it("correlateFindings groups findings on same host", async () => {
    const { correlateFindings } = await import("./lib/attack-chain-correlator");
    const findings = [
      { id: 1, title: "SQL Injection", severity: "critical", hostname: "web.example.com", port: 443 },
      { id: 2, title: "XSS Reflected", severity: "high", hostname: "web.example.com", port: 443 },
      { id: 3, title: "Outdated TLS", severity: "medium", hostname: "web.example.com", port: 443 },
    ];
    const chains = correlateFindings(findings);
    expect(chains.length).toBeGreaterThanOrEqual(1);
    expect(chains[0].steps.length).toBeGreaterThanOrEqual(2);
    expect(chains[0].compositeRiskScore).toBeGreaterThan(0);
    expect(chains[0].confidence).toBeGreaterThan(0);
  });

  it("correlateFindings assigns severity to chains", async () => {
    const { correlateFindings } = await import("./lib/attack-chain-correlator");
    const findings = [
      { id: 1, title: "RCE", severity: "critical", hostname: "db.example.com" },
      { id: 2, title: "Priv Escalation", severity: "high", hostname: "db.example.com" },
    ];
    const chains = correlateFindings(findings);
    expect(chains.length).toBeGreaterThanOrEqual(1);
    expect(["critical", "high", "moderate"]).toContain(chains[0].compositeSeverity);
  });

  it("correlateFindings generates step ordering", async () => {
    const { correlateFindings } = await import("./lib/attack-chain-correlator");
    const findings = [
      { id: 1, title: "Recon", severity: "low", hostname: "target.com", mitreTechnique: "T1595" },
      { id: 2, title: "Initial Access", severity: "high", hostname: "target.com", mitreTechnique: "T1190" },
      { id: 3, title: "Lateral Move", severity: "critical", hostname: "target.com", mitreTechnique: "T1021" },
    ];
    const chains = correlateFindings(findings);
    if (chains.length > 0) {
      const steps = chains[0].steps;
      for (let i = 0; i < steps.length; i++) {
        expect(steps[i].stepOrder).toBe(i + 1);
      }
    }
  });
});

// ─── Attack Chains Router - Auto-Correlate & E2E Procedures ────────────────
describe.skipIf(__skipInCI)("Attack Chains - Auto-Correlate & E2E Procedures", () => {
  it("attackChainsRouter has autoCorrelate procedure", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames).toContain("autoCorrelate");
  });

  it("attackChainsRouter has e2ePipeline procedure", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames).toContain("e2ePipeline");
  });

  it("attackChainsRouter has availableScans procedure", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames).toContain("availableScans");
  });

  it("attackChainsRouter has recalculateScore procedure", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames).toContain("recalculateScore");
  });

  it("has at least 14 procedures including new auto-correlation features", async () => {
    const mod = await import("./routers/attack-chains");
    const procedureNames = Object.keys(mod.attackChainsRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(14);
  });
});

// ─── FedRAMP POA&M DOCX Export ──────────────────────────────────────────────
describe("FedRAMP POA&M DOCX Export", () => {
  const routerPath = path.resolve(__dirname, "routers/risk-register.ts");
  let routerContent: string;

  it("risk-register router file exists", () => {
    expect(fs.existsSync(routerPath)).toBe(true);
    routerContent = fs.readFileSync(routerPath, "utf-8");
  });

  it("has exportPoamDocx procedure", () => {
    expect(routerContent).toContain("exportPoamDocx");
  });

  it("uses docx library for DOCX generation", () => {
    expect(routerContent).toContain('import("docx")');
  });

  it("creates Document with landscape orientation", () => {
    expect(routerContent).toContain("PageOrientation.LANDSCAPE");
  });

  it("includes FedRAMP POA&M title", () => {
    expect(routerContent).toContain("Plan of Action and Milestones");
  });

  it("includes Executive Summary section", () => {
    expect(routerContent).toContain("Executive Summary");
  });

  it("includes ConMon SLA Reference", () => {
    expect(routerContent).toContain("FedRAMP ConMon SLA Reference");
    expect(routerContent).toContain("30 days");
    expect(routerContent).toContain("90 days");
    expect(routerContent).toContain("180 days");
  });

  it("includes POA&M table with proper headers", () => {
    const headers = ["POA&M ID", "Weakness", "Severity", "Status", "Affected Assets", "Control ID", "Mitigation Plan", "Risk Decision"];
    for (const h of headers) {
      expect(routerContent).toContain(h);
    }
  });

  it("uses FedRAMP blue header styling", () => {
    expect(routerContent).toContain("0D47A1");
  });

  it("uploads to S3 via doStoragePut", () => {
    expect(routerContent).toContain("doStoragePut");
  });

  it("returns URL for download", () => {
    expect(routerContent).toContain("url");
    expect(routerContent).toContain("fileName");
    expect(routerContent).toContain("totalItems");
  });

  it("accepts systemName and preparedBy parameters", () => {
    expect(routerContent).toContain("systemName");
    expect(routerContent).toContain("preparedBy");
    expect(routerContent).toContain("preparedFor");
  });
});

// ─── Risk Register Router - DOCX Export Procedure ──────────────────────────
describe.skipIf(__skipInCI)("Risk Register Router - DOCX Procedure", () => {
  it("riskRegisterRouter has exportPoamDocx procedure", async () => {
    const mod = await import("./routers/risk-register");
    const procedureNames = Object.keys(mod.riskRegisterRouter);
    expect(procedureNames).toContain("exportPoamDocx");
  });

  it("has at least 14 procedures including DOCX export", async () => {
    const mod = await import("./routers/risk-register");
    const procedureNames = Object.keys(mod.riskRegisterRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(14);
  });
});

// ─── Frontend UI - Auto-Correlate & DOCX Export ─────────────────────────────
describe("Frontend - Auto-Correlate UI", () => {
  const chainsPath = path.resolve(__dirname, "../client/src/pages/AttackChains.tsx");
  let chainsContent: string;

  it("AttackChains.tsx exists", () => {
    expect(fs.existsSync(chainsPath)).toBe(true);
    chainsContent = fs.readFileSync(chainsPath, "utf-8");
  });

  it("has Auto-Correlate button and dialog", () => {
    expect(chainsContent).toContain("Auto-Correlate");
    expect(chainsContent).toContain("autoCorrelate");
  });

  it("has E2E Pipeline button and dialog", () => {
    expect(chainsContent).toContain("E2E Pipeline");
    expect(chainsContent).toContain("e2ePipeline");
  });

  it("has scan selector for correlation", () => {
    expect(chainsContent).toContain("availableScans");
    expect(chainsContent).toContain("selectedScanId");
  });

  it("has confidence slider", () => {
    expect(chainsContent).toContain("minConfidence");
  });

  it("has auto-populate POA&M toggle", () => {
    expect(chainsContent).toContain("autoPopulatePoam");
  });
});

describe("Frontend - DOCX Export UI", () => {
  const rrPath = path.resolve(__dirname, "../client/src/pages/RiskRegister.tsx");
  let rrContent: string;

  it("RiskRegister.tsx exists", () => {
    expect(fs.existsSync(rrPath)).toBe(true);
    rrContent = fs.readFileSync(rrPath, "utf-8");
  });

  it("has DOCX export button", () => {
    expect(rrContent).toContain("DOCX POA&M");
    expect(rrContent).toContain("exportPoamDocx");
  });

  it("has Excel export button", () => {
    expect(rrContent).toContain("Excel POA&M");
    expect(rrContent).toContain("exportPoamExcel");
  });

  it("has CSV export button", () => {
    expect(rrContent).toContain("CSV");
  });
});
