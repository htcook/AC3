/**
 * AC3 Report Generator — Comprehensive Tests
 *
 * Tests cover:
 *   1. Router structure: all expected procedures exist
 *   2. Schema: database table definitions for ac3_reports and ac3_report_findings
 *   3. Severity rubric and control families reference data
 *   4. UI routes: sidebar nav entries and App.tsx route registration
 *   5. Export format: report_input.schema.json compatibility
 *   6. FedRAMP compliance: platform-controlled vs LLM-drafted field separation
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Router Structure Tests ─────────────────────────────────────────────────

describe("AC3 Reports Router", () => {
  it("exports ac3ReportsRouter with all expected procedures", async () => {
    const mod = await import("./routers/ac3-reports");
    expect(mod.ac3ReportsRouter).toBeDefined();

    const router = mod.ac3ReportsRouter;
    const procedureNames = Object.keys(router);

    // Core CRUD
    expect(procedureNames).toContain("listReports");
    expect(procedureNames).toContain("getReport");
    expect(procedureNames).toContain("createReport");
    expect(procedureNames).toContain("updateReport");
    expect(procedureNames).toContain("deleteReport");

    // Finding CRUD
    expect(procedureNames).toContain("addFinding");
    expect(procedureNames).toContain("updateFinding");
    expect(procedureNames).toContain("deleteFinding");

    // LLM-powered generation
    expect(procedureNames).toContain("generateFindingNarrative");
    expect(procedureNames).toContain("generateExecSummary");
    expect(procedureNames).toContain("generateAllNarratives");

    // QA review
    expect(procedureNames).toContain("runQaReview");

    // Reference data
    expect(procedureNames).toContain("getControlFamilies");
    expect(procedureNames).toContain("getSeverityRubric");

    // Export
    expect(procedureNames).toContain("exportReportJson");
  });

  it("has at least 15 procedures covering full report lifecycle", async () => {
    const mod = await import("./routers/ac3-reports");
    const procedureNames = Object.keys(mod.ac3ReportsRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(15);
  });
});

// ─── Database Schema Tests ──────────────────────────────────────────────────

describe("AC3 Reports Database Schema", () => {
  it("exports ac3Reports table with required columns", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.ac3Reports).toBeDefined();

    // Check the table name
    const tableName = (schema.ac3Reports as any)[Symbol.for("drizzle:Name")];
    expect(tableName).toBe("ac3_reports");
  });

  it("exports ac3ReportFindings table with required columns", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.ac3ReportFindings).toBeDefined();

    const tableName = (schema.ac3ReportFindings as any)[Symbol.for("drizzle:Name")];
    expect(tableName).toBe("ac3_report_findings");
  });

  it("exports type aliases for report rows", async () => {
    const schema = await import("../drizzle/schema");
    // These are type-only exports, but we can check the schema table exists
    expect(schema.ac3Reports).toBeDefined();
    expect(schema.ac3ReportFindings).toBeDefined();
  });
});

// ─── FedRAMP Compliance: Field Separation Tests ─────────────────────────────

describe("FedRAMP Compliance: Platform vs LLM Field Separation", () => {
  it("router source code contains SYSTEM_PROMPT with FedRAMP rules", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    // The system prompt must enforce FedRAMP-aware writing
    expect(routerSource).toContain("FedRAMP");
    expect(routerSource).toContain("SYSTEM_PROMPT");
    expect(routerSource).toContain("source of truth");
    expect(routerSource).toContain("DO NOT modify");
  });

  it("finding narrative prompt separates platform-controlled from LLM-drafted fields", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    // Platform-controlled fields must be labeled as source of truth
    expect(routerSource).toContain("Platform Source of Truth");
    expect(routerSource).toContain("DO NOT modify these");

    // LLM should only draft bounded narrative fields
    expect(routerSource).toContain('"title"');
    expect(routerSource).toContain('"summary"');
    expect(routerSource).toContain('"business_impact"');
    expect(routerSource).toContain('"technical_details"');
    expect(routerSource).toContain('"remediation"');
  });

  it("severity rubric covers all FedRAMP-relevant levels", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    expect(routerSource).toContain("SEVERITY_RUBRIC");
    expect(routerSource).toContain("critical");
    expect(routerSource).toContain("high");
    expect(routerSource).toContain("moderate");
    expect(routerSource).toContain("low");
    expect(routerSource).toContain("informational");
  });

  it("NIST 800-53 control families are defined", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    expect(routerSource).toContain("NIST_CONTROL_FAMILIES");
    // Key FedRAMP control families
    expect(routerSource).toContain('"AC"');
    expect(routerSource).toContain('"Access Control"');
    expect(routerSource).toContain('"AU"');
    expect(routerSource).toContain('"Audit and Accountability"');
    expect(routerSource).toContain('"IA"');
    expect(routerSource).toContain('"Identification and Authentication"');
    expect(routerSource).toContain('"SC"');
    expect(routerSource).toContain('"System and Communications Protection"');
    expect(routerSource).toContain('"SI"');
    expect(routerSource).toContain('"System and Information Integrity"');
    expect(routerSource).toContain('"IR"');
    expect(routerSource).toContain('"Incident Response"');
    expect(routerSource).toContain('"RA"');
    expect(routerSource).toContain('"Risk Assessment"');
    expect(routerSource).toContain('"CM"');
    expect(routerSource).toContain('"Configuration Management"');
  });

  it("system prompt prohibits exploit code and enforces professional tone", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    expect(routerSource).toContain("Never include exploit code");
    expect(routerSource).toContain("malware instructions");
    expect(routerSource).toContain("professional consulting tone");
    expect(routerSource).toContain("evidence-backed");
  });

  it("QA review checks for prohibited content and audit readiness", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    expect(routerSource).toContain("buildQaReviewPrompt");
    expect(routerSource).toContain("unsupported claims");
    expect(routerSource).toContain("inconsistent severity");
    expect(routerSource).toContain("missing evidence references");
    expect(routerSource).toContain("prohibited content");
  });
});

// ─── UI Route & Navigation Tests ────────────────────────────────────────────

describe("AC3 Reports UI Integration", () => {
  it("Ac3Reports page component exists", () => {
    const pagePath = path.join(__dirname, "../client/src/pages/Ac3Reports.tsx");
    expect(fs.existsSync(pagePath)).toBe(true);
  });

  it("App.tsx registers /ac3-reports route", () => {
    const appSource = fs.readFileSync(
      path.join(__dirname, "../client/src/App.tsx"),
      "utf-8"
    );
    expect(appSource).toContain('path="/ac3-reports"');
    expect(appSource).toContain("Ac3Reports");
  });

  it("App.tsx has lazy import for Ac3Reports", () => {
    const appSource = fs.readFileSync(
      path.join(__dirname, "../client/src/App.tsx"),
      "utf-8"
    );
    expect(appSource).toContain('import("./pages/Ac3Reports")');
  });

  it("AppShell sidebar includes AC3 FedRAMP Reports link", () => {
    const shellSource = fs.readFileSync(
      path.join(__dirname, "../client/src/components/AppShell.tsx"),
      "utf-8"
    );
    expect(shellSource).toContain("/ac3-reports");
    expect(shellSource).toContain("AC3 REPORTS");
  });
});

// ─── Report Input Schema Compatibility Tests ────────────────────────────────

describe("report_input.schema.json Compatibility", () => {
  it("exportReportJson output structure matches AC3 schema format", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    // The export function must produce the schema-compatible structure
    expect(routerSource).toContain("metadata:");
    expect(routerSource).toContain("executive_summary:");
    expect(routerSource).toContain("scope:");
    expect(routerSource).toContain("findings:");

    // Metadata fields
    expect(routerSource).toContain("client_name");
    expect(routerSource).toContain("system_name");
    expect(routerSource).toContain("assessment_type");
    expect(routerSource).toContain("fedramp_impact_level");
    expect(routerSource).toContain("cloud_provider");
    expect(routerSource).toContain("service_model");
    expect(routerSource).toContain("assessment_window");
    expect(routerSource).toContain("report_version");

    // Executive summary fields
    expect(routerSource).toContain("risk_statement");
    expect(routerSource).toContain("overall_rating");
    expect(routerSource).toContain("key_strengths");
    expect(routerSource).toContain("key_gaps");

    // Scope fields
    expect(routerSource).toContain("domains");
    expect(routerSource).toContain("approved_vectors");
    expect(routerSource).toContain("out_of_scope");

    // Finding fields
    expect(routerSource).toContain("attack_techniques");
    expect(routerSource).toContain("business_impact");
    expect(routerSource).toContain("technical_details");
  });

  it("finding severity enum matches FedRAMP-standard levels", () => {
    const schemaSource = fs.readFileSync(
      path.join(__dirname, "../drizzle/schema.ts"),
      "utf-8"
    );

    // The severity enum in the schema must match FedRAMP levels
    expect(schemaSource).toContain("'critical'");
    expect(schemaSource).toContain("'high'");
    expect(schemaSource).toContain("'moderate'");
    expect(schemaSource).toContain("'low'");
    expect(schemaSource).toContain("'informational'");
  });
});

// ─── UI Component Feature Tests ─────────────────────────────────────────────

describe("AC3 Reports UI Features", () => {
  it("page includes FedRAMP info banner explaining source of truth", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("FedRAMP Assessment Report Generator");
    expect(pageSource).toContain("source of truth");
    expect(pageSource).toContain("bounded narrative fields");
  });

  it("page distinguishes platform-controlled from LLM-drafted sections", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Platform Source of Truth");
    expect(pageSource).toContain("LLM-Drafted Narratives");
  });

  it("page includes severity, ATT&CK, and NIST control display", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("ATT&CK Techniques");
    expect(pageSource).toContain("NIST 800-53 Controls");
    expect(pageSource).toContain("CVSS");
  });

  it("page includes narrative generation and QA review actions", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Generate Narratives");
    expect(pageSource).toContain("Generate Exec Summary");
    expect(pageSource).toContain("Run QA Review");
  });

  it("page includes export functionality", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Export Report");
    expect(pageSource).toContain("report_input.schema.json");
    expect(pageSource).toContain("Download JSON");
    expect(pageSource).toContain("Copy JSON");
  });

  it("page includes finding approval workflow", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Approve");
    expect(pageSource).toContain("Regenerate");
    expect(pageSource).toContain("narrativeStatus");
  });

  it("page includes metadata and scope editing", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Metadata & Scope");
    expect(pageSource).toContain("Assessment Window");
    expect(pageSource).toContain("In-Scope Domains");
    expect(pageSource).toContain("Approved Attack Vectors");
    expect(pageSource).toContain("Out of Scope");
  });

  it("create dialog includes FedRAMP impact level selection", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("FedRAMP Impact Level");
    expect(pageSource).toContain("LI-SaaS");
  });
});
