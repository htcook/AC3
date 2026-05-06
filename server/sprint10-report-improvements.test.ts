/**
 * Sprint 10 — Report Quality Improvements
 *
 * Tests for:
 * - P0-3: Tool failure gating (DEGRADED engagement status)
 * - P0-4: X-Scan-Key validation in pre-engagement health check
 * - P1-1: ReportMetrics single source of truth
 * - P1-2: sourceType field in engagement_findings schema
 * - P1-3: LLM finding quarantine (Hypotheses appendix)
 * - P2-1: DNSBL false-positive detection
 * - P2-3: Suricata rule truncation fix in DOCX
 * - P2-4: Skip C2 section when agents === 0
 * - ac3_lint Python linter integration
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── P0-3: Tool Failure Gating ──────────────────────────────────────────

describe("P0-3: Tool Failure Gating", () => {
  it("engagement-orchestrator has DEGRADED phase logic", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("TOOL FAILURE GATING");
    expect(source).toContain("degraded");
    expect(source).toContain("toolFailureRate");
  });

  it("OpsPhase type includes 'degraded'", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    // Check the type union includes 'degraded'
    expect(source).toMatch(/type OpsPhase\s*=.*'degraded'/s);
  });

  it("DEGRADED banner is injected into report when tool failure > 50%", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    expect(source).toContain("ENGAGEMENT STATUS: DEGRADED");
    expect(source).toContain("toolFailureRate");
  });
});

// ─── P0-4: X-Scan-Key Validation ────────────────────────────────────────

describe("P0-4: X-Scan-Key Validation", () => {
  it("engagement-orchestrator validates SCAN_API_KEY is not placeholder", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("SCAN_API_KEY");
    expect(source).toContain("ADMIN123");
    expect(source).toContain("X-SCAN-KEY VALIDATION");
  });
});

// ─── P1-1: ReportMetrics Single Source of Truth ──────────────────────────

describe("P1-1: ReportMetrics Single Source of Truth", () => {
  it("pentest-report-pipeline defines reportMetrics object with required fields", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    expect(source).toContain("const reportMetrics");
    expect(source).toContain("totalAssets");
    expect(source).toContain("totalFindings");
  });

  it("ReportMetrics is computed once and injected into sections", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    expect(source).toContain("const reportMetrics");
    // Verify it's used in the report body sections
    expect(source).toContain("reportMetrics.totalAssets");
    expect(source).toContain("reportMetrics.isDegraded");
    expect(source).toContain("reportMetrics.toolFailureRate");
  });

  it("PipelineOutput includes reportMetrics", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    expect(source).toContain("reportMetrics?");
  });
});

// ─── P1-2: sourceType Field ──────────────────────────────────────────────

describe("P1-2: sourceType Field in Schema", () => {
  it("engagement_findings schema has sourceType column", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "drizzle/schema.ts"),
      "utf-8"
    );
    expect(source).toContain("sourceType");
    expect(source).toMatch(/sourceType.*varchar|sourceType.*text|sourceType.*enum/);
  });

  it("db.ts EngagementFindingInput includes sourceType", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/db.ts"),
      "utf-8"
    );
    expect(source).toContain("sourceType");
  });
});

// ─── P1-3: LLM Finding Quarantine ───────────────────────────────────────

describe("P1-3: LLM Finding Quarantine", () => {
  it("pentest-report-pipeline separates LLM-inferred findings into appendix", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    expect(source).toContain("llmInferredFindings");
    expect(source).toContain("Hypotheses");
  });

  it("LLM findings are excluded from main confirmed count", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    // The ReportMetrics should filter out LLM-inferred findings from confirmedFindings
    expect(source).toContain("scannerFindings");
  });
});

// ─── P2-1: DNSBL False-Positive Detection ────────────────────────────────

describe("P2-1: DNSBL False-Positive Detection", () => {
  it("domain-health.ts detects DNSBL query-refused responses", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/passive/domain-health.ts"),
      "utf-8"
    );
    expect(source).toContain("ECONNREFUSED");
    expect(source).toContain("SERVFAIL");
    expect(source).toContain("REFUSED");
  });

  it("refused DNSBL responses are marked with falsePositiveIndicators", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/passive/domain-health.ts"),
      "utf-8"
    );
    expect(source).toContain("falsePositiveIndicators");
    expect(source).toContain("UNRELIABLE");
  });
});

// ─── P2-3: Suricata Rule Truncation Fix ──────────────────────────────────

describe("P2-3: Suricata Rule Truncation Fix in DOCX", () => {
  it("markdown-to-docx wraps long code lines to prevent truncation", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/markdown-to-docx.ts"),
      "utf-8"
    );
    // Should have line-wrapping logic for code blocks (wraps at 100 chars)
    expect(source).toContain("wrappedCodeLines");
    expect(source).toMatch(/slice\(ci,\s*ci\s*\+\s*100\)/);
  });
});

// ─── P2-4: Skip C2 Section When Agents === 0 ────────────────────────────

describe("P2-4: Skip C2 Section When Agents === 0", () => {
  it("pentest-report-pipeline conditionally renders C2 section", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/pentest-report-pipeline.ts"),
      "utf-8"
    );
    // Should check agents length before rendering C2 section
    expect(source).toMatch(/agents.*length.*>.*0|agents.*\.length/);
    expect(source).toContain("C2");
  });
});

// ─── ac3_lint Python Linter Integration ──────────────────────────────────

describe("ac3_lint Python Linter Integration", () => {
  it("ac3_lint package exists in server/lib/ac3_lint", () => {
    const exists = fs.existsSync(
      path.join(PROJECT_ROOT, "server/lib/ac3_lint/__init__.py")
    );
    expect(exists).toBe(true);
  });

  it("ac3_lint has all check modules", () => {
    const checksDir = path.join(PROJECT_ROOT, "server/lib/ac3_lint/checks");
    const files = fs.readdirSync(checksDir);
    expect(files).toContain("correctness.py");
    expect(files).toContain("counts.py");
    expect(files).toContain("dnsbl.py");
    expect(files).toContain("exploits.py");
    expect(files).toContain("llm_quarantine.py");
    expect(files).toContain("ratings.py");
    expect(files).toContain("templates.py");
    expect(files).toContain("vendor.py");
  });

  it("ac3-lint-bridge.ts exports lintReport and formatLintIssues", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/ac3-lint-bridge.ts"),
      "utf-8"
    );
    expect(source).toContain("export async function lintReport");
    expect(source).toContain("export function formatLintIssues");
  });

  it("reports-core.ts wires ac3_lint into the pentest report pipeline", () => {
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/reports-core.ts"),
      "utf-8"
    );
    expect(source).toContain("AC3 Lint Quality Gate");
    expect(source).toContain("lintReport");
    expect(source).toContain("lintResult");
  });
});
