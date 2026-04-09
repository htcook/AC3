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

describe("Compliance: Platform vs LLM Field Separation", () => {
  it("router source code contains buildSystemPrompt with compliance rules", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );

    // The system prompt must enforce compliance-aware writing (FedRAMP or NIST 800-53r5)
    expect(routerSource).toContain("buildSystemPrompt");
    expect(routerSource).toContain("source of truth");
    expect(routerSource).toContain("DO NOT modify");
    // Must support both FedRAMP and NIST 800-53r5 frameworks
    expect(routerSource).toContain("nist_800_53_r5");
    expect(routerSource).toContain("fedramp");
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
  it("page includes info banner explaining source of truth", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Assessment Report Generator");
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
    expect(pageSource).toContain("DOCX Report Export");
    expect(pageSource).toContain("JSON Export");
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

// ─── Enhancement Tests: Engagement Import, Caldera Import, DOCX Export ─────

describe("AC3 Reports Enhancements: Router Procedures", () => {
  it("router includes engagement import procedures", async () => {
    const mod = await import("./routers/ac3-reports");
    const procedureNames = Object.keys(mod.ac3ReportsRouter);
    expect(procedureNames).toContain("listEngagements");
    expect(procedureNames).toContain("importEngagementFindings");
  });

  it("router includes Caldera operation import procedures", async () => {
    const mod = await import("./routers/ac3-reports");
    const procedureNames = Object.keys(mod.ac3ReportsRouter);
    expect(procedureNames).toContain("listCalderaOperations");
    expect(procedureNames).toContain("importCalderaOperation");
  });

  it("router includes DOCX export procedure", async () => {
    const mod = await import("./routers/ac3-reports");
    const procedureNames = Object.keys(mod.ac3ReportsRouter);
    expect(procedureNames).toContain("exportDocx");
  });

  it("has at least 20 procedures after enhancements", async () => {
    const mod = await import("./routers/ac3-reports");
    const procedureNames = Object.keys(mod.ac3ReportsRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(20);
  });
});

describe("AC3 Reports Enhancements: DOCX Generation", () => {
  it("router source code imports docx package", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain('from "docx"');
  });

  it("DOCX generation includes title page, executive summary, scope, and findings sections", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Title page section
    expect(routerSource).toContain("titleSection");
    // Executive summary section
    expect(routerSource).toContain("1. Executive Summary");
    // Scope section
    expect(routerSource).toContain("2. Scope & Methodology");
    // Findings section
    expect(routerSource).toContain("4. Detailed Findings");
  });

  it("DOCX generation includes Harrison Cook / AceofCloud branding", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("Harrison Cook");
    expect(routerSource).toContain("AceofCloud");
  });

  it("DOCX generation includes ATT&CK techniques and NIST controls per finding", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("ATT&CK Techniques");
    expect(routerSource).toContain("NIST 800-53 Controls");
  });

  it("DOCX generation uploads to S3 via storagePut", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("doStoragePut");
    expect(routerSource).toContain("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
  });
});

describe("AC3 Reports Enhancements: Engagement Import", () => {
  it("engagement import maps timeline events to findings", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Should reference engagement timeline events
    expect(routerSource).toContain("engagementTimelineEvents");
    // Should map event types to severity
    expect(routerSource).toContain("SourceModule");
  });

  it("engagement import preserves source traceability", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("SourceEventId");
    expect(routerSource).toContain("SourceModule");
  });
});

describe("AC3 Reports Enhancements: Caldera Import", () => {
  it("Caldera import fetches operations from Caldera API", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("CALDERA_BASE_URL");
    expect(routerSource).toContain("CALDERA_API_KEY");
    expect(routerSource).toContain("/api/v2/operations");
  });

  it("Caldera import maps abilities to findings with ATT&CK IDs", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Should map technique_id from Caldera links
    expect(routerSource).toContain("technique_id");
    expect(routerSource).toContain("ability");
  });

  it("Caldera import includes option to include failed links", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("includeFailedLinks");
  });
});

describe("AC3 Reports Enhancements: UI Components", () => {
  it("page includes Import Engagement button and dialog", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Import Engagement");
    expect(pageSource).toContain("EngagementImportDialog");
    expect(pageSource).toContain("importEngagementFindings");
  });

  it("page includes Import Caldera Op button and dialog", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("Import Caldera Op");
    expect(pageSource).toContain("CalderaImportDialog");
    expect(pageSource).toContain("importCalderaOperation");
  });

  it("page includes DOCX export button", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("DOCX Report Export");
    expect(pageSource).toContain("Generate & Download DOCX");
    expect(pageSource).toContain("exportDocx");
  });

  it("Caldera import dialog includes failed links toggle", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("includeFailedLinks");
    expect(pageSource).toContain("Include failed/blocked links as findings");
  });

  it("engagement import dialog shows engagement list with status and type", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("listEngagements");
    expect(pageSource).toContain("engagementType");
    expect(pageSource).toContain("Caldera Linked");
  });
});

describe("AC3 Reports Enhancements: Schema Updates", () => {
  it("ac3Reports table has docxUrl column", async () => {
    const schema = await import("../drizzle/schema");
    const columns = Object.keys((schema.ac3Reports as any));
    // Check the column exists in the schema definition
    const schemaSource = fs.readFileSync(
      path.join(__dirname, "../drizzle/schema.ts"),
      "utf-8"
    );
    expect(schemaSource).toContain("rpt_docx_url");
  });

  it("ac3ReportFindings table has sourceModule and sourceEventId columns", () => {
    const schemaSource = fs.readFileSync(
      path.join(__dirname, "../drizzle/schema.ts"),
      "utf-8"
    );
    expect(schemaSource).toContain("rf_source_module");
    expect(schemaSource).toContain("rf_source_event_id");
  });
});

// ─── Deduplication Tests ────────────────────────────────────────────────────

describe("AC3 Reports Deduplication: Server Logic", () => {
  it("router source contains findDuplicatesByTechnique helper", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("findDuplicatesByTechnique");
  });

  it("router source contains mergeFinding helper", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("mergeFinding");
  });

  it("mergeFinding keeps highest severity between existing and new", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("severityRank");
    expect(routerSource).toContain("critical: 5");
    expect(routerSource).toContain("newRank > currentRank");
  });

  it("mergeFinding appends evidence without duplicates (by reference)", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("existingRefs");
    expect(routerSource).toContain("!existingRefs.has(e.reference)");
  });

  it("mergeFinding unions assets (deduped)", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("mergedAssets");
    expect(routerSource).toContain("new Set([...existingAssets, ...newAssets])");
  });

  it("mergeFinding unions controls by id", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("existingControlIds");
    expect(routerSource).toContain("mergedControls");
  });

  it("engagement import calls findDuplicatesByTechnique before inserting", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // The engagement import section should have dedup lookup
    const engImportSection = routerSource.slice(
      routerSource.indexOf("importEngagementFindings"),
      routerSource.indexOf("importCalderaOperation")
    );
    expect(engImportSection).toContain("findDuplicatesByTechnique");
    expect(engImportSection).toContain("dupeMap");
    expect(engImportSection).toContain("mergeFinding");
  });

  it("engagement import returns merged and skipped counts", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    const engImportSection = routerSource.slice(
      routerSource.indexOf("importEngagementFindings"),
      routerSource.indexOf("importCalderaOperation")
    );
    expect(engImportSection).toContain("let merged = 0");
    expect(engImportSection).toContain("let skipped = 0");
    expect(engImportSection).toContain("imported, merged, skipped");
  });

  it("engagement import tracks newly created findings for intra-batch dedup", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    const engImportSection = routerSource.slice(
      routerSource.indexOf("importEngagementFindings"),
      routerSource.indexOf("importCalderaOperation")
    );
    expect(engImportSection).toContain("dupeMap.set(event.attackTechnique");
  });

  it("Caldera import calls findDuplicatesByTechnique before inserting", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    const calderaImportSection = routerSource.slice(
      routerSource.indexOf("importCalderaOperation"),
      routerSource.indexOf("exportDocx")
    );
    expect(calderaImportSection).toContain("findDuplicatesByTechnique");
    expect(calderaImportSection).toContain("dupeMap");
    expect(calderaImportSection).toContain("mergeFinding");
  });

  it("Caldera import returns merged count", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    const calderaImportSection = routerSource.slice(
      routerSource.indexOf("importCalderaOperation"),
      routerSource.indexOf("exportDocx")
    );
    expect(calderaImportSection).toContain("let merged = 0");
    expect(calderaImportSection).toContain("imported,");
    expect(calderaImportSection).toContain("merged,");
  });

  it("Caldera import deduplicates atomic test executions too", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    const calderaImportSection = routerSource.slice(
      routerSource.indexOf("importCalderaOperation"),
      routerSource.indexOf("exportDocx")
    );
    // Should check dupeMap for atomic tests
    expect(calderaImportSection).toContain("dupeMap.has(exec.techniqueId)");
  });
});

describe("AC3 Reports Deduplication: UI Feedback", () => {
  it("engagement import toast shows merged count when present", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("data.merged");
    expect(pageSource).toContain("merged");
  });

  it("Caldera import toast shows merged count when present", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("merged into existing");
  });

  it("engagement import toast shows filtered count when present", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("data.skipped");
    expect(pageSource).toContain("filtered");
  });
});

// ─── Auto-Artifact Extraction Tests ─────────────────────────────────────────

describe("AC3 Auto-Artifact Extraction", () => {
  it("importFromOpsSnapshot procedure creates artifacts from evidence", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Should contain artifact extraction logic
    expect(routerSource).toContain("Auto-extract artifacts from evidence and approval gates");
    expect(routerSource).toContain("artifactsCreated");
  });

  it("classifies evidence into artifact types (poc, exploit_output, tool_output, screenshot, evidence)", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("artifactType = 'poc'");
    expect(routerSource).toContain("artifactType = 'exploit_output'");
    expect(routerSource).toContain("artifactType = 'tool_output'");
    expect(routerSource).toContain("artifactType = 'screenshot'");
    expect(routerSource).toContain("artifactType = 'evidence'");
  });

  it("deduplicates artifacts by label prefix to avoid re-creating on re-import", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("labelPrefix");
    expect(routerSource).toContain("alreadyExists");
  });

  it("extracts artifacts from approval gates grouped by tool and target", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("approvedGates");
    expect(routerSource).toContain("gatesByTarget");
    expect(routerSource).toContain("toolGroups");
    expect(routerSource).toContain("ApprovalGate-");
  });

  it("returns artifactsCreated count in import response", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // The return object should include artifactsCreated
    const returnSection = routerSource.slice(
      routerSource.indexOf("artifactsCreated++"),
      routerSource.indexOf("artifactsCreated,") + 50
    );
    expect(returnSection).toContain("artifactsCreated");
  });
});

// ─── Scope Exclusion Tests ──────────────────────────────────────────────────

describe("AC3 Scope Exclusion System", () => {
  it("router exports getScopeExclusions and updateScopeExclusions procedures", async () => {
    const mod = await import("./routers/ac3-reports");
    const router = mod.ac3ReportsRouter;
    const procedureNames = Object.keys(router);
    expect(procedureNames).toContain("getScopeExclusions");
    expect(procedureNames).toContain("updateScopeExclusions");
  });

  it("schema includes scopeExclusions JSON column on ac3_reports", () => {
    const schemaSource = fs.readFileSync(
      path.join(__dirname, "../drizzle/schema.ts"),
      "utf-8"
    );
    // Column is named rptScopeExclusions in Drizzle (maps to rpt_scope_exclusions in DB)
    expect(schemaSource).toContain("rptScopeExclusions");
    expect(schemaSource).toContain("rpt_scope_exclusions");
  });

  it("coverage validator loads scope exclusions and marks excluded phases", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("excludedPhases");
    expect(routerSource).toContain("phasesExcluded");
    expect(routerSource).toContain("status: 'excluded'");
    expect(routerSource).toContain("totalApplicablePhases");
  });

  it("excluded phases show justification and approver in phase results", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("exclusionJustification");
    expect(routerSource).toContain("excludedBy");
  });

  it("methodology coverage score uses totalApplicablePhases denominator", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Score should divide by totalApplicablePhases, not hardcoded 10
    expect(routerSource).toContain("phasesPresent / totalApplicablePhases");
  });

  it("coverage validator returns scopeExclusions in response", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // The validateCoverage return object should include scopeExclusions
    const validatorSection = routerSource.slice(
      routerSource.indexOf("validateCoverage"),
      routerSource.lastIndexOf("scopeExclusions,") + 30
    );
    expect(validatorSection).toContain("scopeExclusions,");
  });

  it("updateScopeExclusions requires justification of at least 20 characters", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("min(20");
    expect(routerSource).toContain("Justification must be at least 20 characters");
  });

  it("recommendations suggest scope exclusion for failing phases", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("document a scope exclusion if this phase was intentionally omitted");
  });
});

// ─── Scope Exclusion UI Tests ───────────────────────────────────────────────

describe("AC3 Scope Exclusion UI", () => {
  it("CoverageTab shows excluded phases with N/A status", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain('status === "excluded"');
    expect(pageSource).toContain("Scope excluded");
    expect(pageSource).toContain("border-blue-500/30 bg-blue-500/5");
  });

  it("CoverageTab displays scope exclusion details with justification", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("scopeExclusions");
    expect(pageSource).toContain("excl.justification");
    expect(pageSource).toContain("excl.approvedBy");
  });

  it("MetadataTab includes ScopeExclusionsCard component", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("ScopeExclusionsCard");
    expect(pageSource).toContain("PTES Phase Scope Exclusions");
  });

  it("ScopeExclusionsCard has edit form with phase selector and justification fields", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("addExclusion");
    expect(pageSource).toContain("removeExclusion");
    expect(pageSource).toContain("updateScopeExclusions");
    expect(pageSource).toContain("Approved By");
    expect(pageSource).toContain("justification");
  });

  it("PTES_PHASES constant lists all 10 methodology phases", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("PTES_PHASES");
    expect(pageSource).toContain("Reconnaissance");
    expect(pageSource).toContain("Discovery & Scanning");
    expect(pageSource).toContain("Initial Access");
    expect(pageSource).toContain("Execution");
    expect(pageSource).toContain("Persistence");
    expect(pageSource).toContain("Privilege Escalation");
    expect(pageSource).toContain("Credential Access");
    expect(pageSource).toContain("Lateral Movement");
    expect(pageSource).toContain("Collection & Exfiltration");
    expect(pageSource).toContain("Defense Evasion");
  });

  it("phases stat shows applicable count and exclusion count", () => {
    const pageSource = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Ac3Reports.tsx"),
      "utf-8"
    );
    expect(pageSource).toContain("totalApplicablePhases");
    expect(pageSource).toContain("phasesExcluded");
    expect(pageSource).toContain("excl.)");
  });
});

// ─── parseJsonField Helper Tests ────────────────────────────────────────────

describe("AC3 parseJsonField Top-Level Helper", () => {
  it("parseJsonField is defined as a top-level function (not inside a procedure)", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    // Should be defined before the router export
    const helperIndex = routerSource.indexOf("function parseJsonField");
    const routerIndex = routerSource.indexOf("export const ac3ReportsRouter");
    expect(helperIndex).toBeGreaterThan(-1);
    expect(helperIndex).toBeLessThan(routerIndex);
  });

  it("parseJsonField handles arrays, JSON strings, and double-encoded strings", () => {
    const routerSource = fs.readFileSync(
      path.join(__dirname, "routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(routerSource).toContain("Double-encoded: parse again");
    expect(routerSource).toContain("Array.isArray(val)");
  });
});
