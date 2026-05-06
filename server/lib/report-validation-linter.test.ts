import { describe, it, expect } from "vitest";
import {
  validateReport,
  validateReportCritical,
  formatLintReport,
  checkCountReconciliation,
  checkExploitStatusValidation,
  checkVendorAssetExclusion,
  checkDnsblFalsePositives,
  checkLlmContentQuarantine,
  checkObjectSerialization,
  checkTemplateResiduals,
  checkToolFailureThreshold,
  checkSectionContradictions,
  isVendorDomain,
  isDnsblQueryError,
  type ReportData,
} from "./report-validation-linter";

describe("Report Validation Linter", () => {
  describe("isVendorDomain", () => {
    it("detects Google domains", () => {
      expect(isVendorDomain("mail.google.com")).toBe(true);
      expect(isVendorDomain("aspmx.l.google.com")).toBe(true);
      expect(isVendorDomain("googleapis.com")).toBe(true);
    });

    it("detects Microsoft domains", () => {
      expect(isVendorDomain("outlook.com")).toBe(true);
      expect(isVendorDomain("protection.outlook.com")).toBe(true);
      expect(isVendorDomain("microsoftonline.com")).toBe(true);
    });

    it("detects CDN/cloud domains", () => {
      expect(isVendorDomain("cdn.cloudflare.com")).toBe(true);
      expect(isVendorDomain("s3.amazonaws.com")).toBe(true);
      expect(isVendorDomain("edge.akamai.net")).toBe(true);
    });

    it("does not flag customer domains", () => {
      expect(isVendorDomain("example.com")).toBe(false);
      expect(isVendorDomain("mail.example.com")).toBe(false);
      expect(isVendorDomain("internal.corp.net")).toBe(false);
    });
  });

  describe("isDnsblQueryError", () => {
    it("detects query refused responses", () => {
      expect(isDnsblQueryError("Query Refused")).toBe(true);
      expect(isDnsblQueryError("rate limit exceeded")).toBe(true);
      expect(isDnsblQueryError("not authorized to query")).toBe(true);
    });

    it("does not flag legitimate listings", () => {
      expect(isDnsblQueryError("Listed for spam activity")).toBe(false);
      expect(isDnsblQueryError("Spamhaus SBL123456")).toBe(false);
    });
  });

  describe("checkCountReconciliation", () => {
    it("passes when counts match", () => {
      const data: ReportData = {
        type: "di",
        coverMetrics: { discoveredAssets: 15, confirmedFindings: 3 },
        execSummaryMetrics: { discoveredAssets: 15, confirmedFindings: 3 },
        actualCounts: { assetTableRows: 15, confirmedFindingRows: 3 },
      };
      const results = checkCountReconciliation(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when cover and exec summary disagree", () => {
      const data: ReportData = {
        type: "di",
        coverMetrics: { discoveredAssets: 15 },
        execSummaryMetrics: { discoveredAssets: 12 },
      };
      const results = checkCountReconciliation(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("15");
      expect(results[0].message).toContain("12");
    });

    it("warns when cover count differs from table rows", () => {
      const data: ReportData = {
        type: "di",
        coverMetrics: { discoveredAssets: 15 },
        execSummaryMetrics: { discoveredAssets: 15 },
        actualCounts: { assetTableRows: 12 },
      };
      const results = checkCountReconciliation(data);
      expect(results.some(r => r.severity === "warn")).toBe(true);
    });
  });

  describe("checkExploitStatusValidation", () => {
    it("passes for legitimate exploit results", () => {
      const data: ReportData = {
        type: "pentest",
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", accessLevel: "user", shell: true, proofContains: ["uid=1000"] },
          { id: "EXP-002", status: "FAILED", accessLevel: "none" },
        ],
      };
      const results = checkExploitStatusValidation(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when SUCCEEDED but access_level=none", () => {
      const data: ReportData = {
        type: "pentest",
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", accessLevel: "none" },
        ],
      };
      const results = checkExploitStatusValidation(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("access_level=none");
    });

    it("fails when proof contains failure indicators", () => {
      const data: ReportData = {
        type: "pentest",
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", accessLevel: "user", proofContains: ["EXPLOIT_FAILED", "error"] },
        ],
      };
      const results = checkExploitStatusValidation(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("failure indicators");
    });

    it("fails when X-Scan-Key auth blocks exploit", () => {
      const data: ReportData = {
        type: "pentest",
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", errorMessages: ["Invalid or missing X-Scan-Key"] },
        ],
      };
      const results = checkExploitStatusValidation(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("X-Scan-Key");
    });
  });

  describe("checkVendorAssetExclusion", () => {
    it("passes when vendor domains are excluded from grading", () => {
      const data: ReportData = {
        type: "di",
        assets: [
          { hostname: "example.com", includedInGrading: true, source: "subdomain" },
          { hostname: "mail.google.com", includedInGrading: false, isVendorManaged: true, source: "mx_target" },
        ],
      };
      const results = checkVendorAssetExclusion(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when vendor domain is included in grading", () => {
      const data: ReportData = {
        type: "di",
        assets: [
          { hostname: "aspmx.l.google.com", includedInGrading: true, source: "mx_target" },
        ],
      };
      const results = checkVendorAssetExclusion(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("google.com");
    });

    it("fails when MX target is treated as customer asset", () => {
      const data: ReportData = {
        type: "di",
        assets: [
          { hostname: "protection.outlook.com", isVendorManaged: false, source: "mx_target" },
        ],
      };
      const results = checkVendorAssetExclusion(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
    });
  });

  describe("checkDnsblFalsePositives", () => {
    it("passes for legitimate listings", () => {
      const data: ReportData = {
        type: "di",
        dnsblResults: [
          { provider: "Spamhaus", listed: true, txtRecord: "Listed for spam - SBL123456" },
        ],
      };
      const results = checkDnsblFalsePositives(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails for query-refused false positives", () => {
      const data: ReportData = {
        type: "di",
        dnsblResults: [
          { provider: "SORBS", listed: true, txtRecord: "Query Refused - rate limit exceeded" },
        ],
      };
      const results = checkDnsblFalsePositives(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("query error");
    });
  });

  describe("checkLlmContentQuarantine", () => {
    it("passes when LLM findings are properly quarantined", () => {
      const data: ReportData = {
        type: "di",
        findings: [
          { id: "F-001", title: "SQL Injection", sourceType: "scanner", inMainCount: true, inRiskMatrix: true },
          { id: "F-002", title: "Possible XSS", sourceType: "llm_inference", inMainCount: false, inRiskMatrix: false },
        ],
      };
      const results = checkLlmContentQuarantine(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when LLM finding is in main count", () => {
      const data: ReportData = {
        type: "di",
        findings: [
          { id: "F-001", title: "Inferred RCE", sourceType: "llm_inference", inMainCount: true, inRiskMatrix: false },
        ],
      };
      const results = checkLlmContentQuarantine(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
    });

    it("fails when low confidence has Very High likelihood", () => {
      const data: ReportData = {
        type: "di",
        findings: [
          { id: "F-001", title: "Possible vuln", confidence: "low", likelihood: "Very High" },
        ],
      };
      const results = checkLlmContentQuarantine(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
    });
  });

  describe("checkObjectSerialization", () => {
    it("passes for clean text", () => {
      const data: ReportData = {
        type: "di",
        renderedText: "This is a normal report with no serialization issues.",
      };
      const results = checkObjectSerialization(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails for [object Object]", () => {
      const data: ReportData = {
        type: "pentest",
        renderedText: "Risk signals: [object Object], [object Object]",
      };
      const results = checkObjectSerialization(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("2 instance(s)");
    });
  });

  describe("checkTemplateResiduals", () => {
    it("passes for clean narrative", () => {
      const data: ReportData = {
        type: "di",
        narrativeSections: [
          { section: "Executive Summary", text: "The organization demonstrates a strong security posture." },
        ],
      };
      const results = checkTemplateResiduals(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("detects processing error residuals", () => {
      const data: ReportData = {
        type: "di",
        narrativeSections: [
          { section: "Recommendations", text: "This section could not be generated due to a processing error." },
        ],
      };
      const results = checkTemplateResiduals(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
    });

    it("detects template placeholders", () => {
      const data: ReportData = {
        type: "di",
        narrativeSections: [
          { section: "BLUF", text: "The organization {{company_name}} has [INSERT RATING] risk." },
        ],
      };
      const results = checkTemplateResiduals(data);
      expect(results.some(r => r.severity !== "pass")).toBe(true);
    });
  });

  describe("checkToolFailureThreshold", () => {
    it("passes when most tools succeed", () => {
      const data: ReportData = {
        type: "pentest",
        toolExecutions: [
          { tool: "nmap", exitCode: 0, durationMs: 5000 },
          { tool: "nuclei", exitCode: 0, durationMs: 30000 },
          { tool: "zap", exitCode: 0, durationMs: 60000 },
          { tool: "nikto", exitCode: 1, durationMs: 2000 },
        ],
      };
      const results = checkToolFailureThreshold(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when >50% tools fail", () => {
      const data: ReportData = {
        type: "pentest",
        toolExecutions: [
          { tool: "nmap", exitCode: 1, durationMs: 50 },
          { tool: "nuclei", exitCode: 1, durationMs: 30 },
          { tool: "zap", exitCode: 1, durationMs: 20 },
          { tool: "nikto", exitCode: 0, durationMs: 5000 },
        ],
      };
      const results = checkToolFailureThreshold(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
      expect(results[0].message).toContain("75%");
    });

    it("fails for command-not-found (exit 127)", () => {
      const data: ReportData = {
        type: "pentest",
        toolExecutions: [
          { tool: "masscan", exitCode: 127, durationMs: 10 },
          { tool: "nmap", exitCode: 0, durationMs: 5000 },
        ],
      };
      const results = checkToolFailureThreshold(data);
      expect(results.some(r => r.severity === "fail" && r.message.includes("127"))).toBe(true);
    });

    it("fails when X-Scan-Key not configured", () => {
      const data: ReportData = {
        type: "pentest",
        toolExecutions: [
          { tool: "nmap", exitCode: 0, durationMs: 5000 },
        ],
        engagement: { scanKeyConfigured: false },
      };
      const results = checkToolFailureThreshold(data);
      expect(results.some(r => r.severity === "fail" && r.message.includes("X-Scan-Key"))).toBe(true);
    });
  });

  describe("checkSectionContradictions", () => {
    it("passes when no contradictions", () => {
      const data: ReportData = {
        type: "di",
        narrativeSections: [
          { section: "Methodology", text: "All findings were identified through automated scanning." },
        ],
      };
      const results = checkSectionContradictions(data);
      expect(results.every(r => r.severity === "pass")).toBe(true);
    });

    it("fails when manual verification claims contradict", () => {
      const data: ReportData = {
        type: "pentest",
        narrativeSections: [
          { section: "Exec Summary", text: "All findings validated through manual testing by our operators." },
          { section: "Appendix", text: "These findings have not been manually verified and require further investigation." },
        ],
      };
      const results = checkSectionContradictions(data);
      expect(results.some(r => r.severity === "fail")).toBe(true);
    });

    it("warns when C2 section exists but 0 agents", () => {
      const data: ReportData = {
        type: "pentest",
        engagement: { c2Agents: 0 },
        narrativeSections: [
          { section: "C2 Operations", text: "The Caldera operation deployed agents to the target network." },
        ],
      };
      const results = checkSectionContradictions(data);
      expect(results.some(r => r.severity === "warn")).toBe(true);
    });
  });

  describe("validateReport (full)", () => {
    it("returns overall PASS for clean report", () => {
      const data: ReportData = {
        type: "di",
        coverMetrics: { discoveredAssets: 10, confirmedFindings: 2 },
        execSummaryMetrics: { discoveredAssets: 10, confirmedFindings: 2 },
        actualCounts: { assetTableRows: 10, confirmedFindingRows: 2 },
        assets: [{ hostname: "example.com", includedInGrading: true }],
        findings: [
          { id: "F-001", title: "XSS", sourceType: "scanner", inMainCount: true },
        ],
        renderedText: "Clean report text with no issues.",
        narrativeSections: [
          { section: "Summary", text: "The organization has a moderate risk posture." },
        ],
      };
      const report = validateReport(data);
      expect(report.overallStatus).toBe("PASS");
      expect(report.failures).toBe(0);
    });

    it("returns overall FAIL for report with critical issues", () => {
      const data: ReportData = {
        type: "pentest",
        coverMetrics: { discoveredAssets: 15 },
        execSummaryMetrics: { discoveredAssets: 12 },
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", accessLevel: "none" },
        ],
        renderedText: "Risk: [object Object]",
      };
      const report = validateReport(data);
      expect(report.overallStatus).toBe("FAIL");
      expect(report.failures).toBeGreaterThan(0);
    });
  });

  describe("validateReportCritical (fast path)", () => {
    it("only runs P0 checks", () => {
      const data: ReportData = {
        type: "di",
        // No exploit data, no vendor issues, no tool failures, no serialization bugs
        assets: [{ hostname: "example.com", includedInGrading: true }],
        renderedText: "Clean text",
      };
      const report = validateReportCritical(data);
      expect(report.overallStatus).toBe("PASS");
    });
  });

  describe("formatLintReport", () => {
    it("formats failures and warnings into readable text", () => {
      const data: ReportData = {
        type: "pentest",
        exploitResults: [
          { id: "EXP-001", status: "SUCCEEDED", accessLevel: "none" },
        ],
        renderedText: "Risk: [object Object]",
      };
      const report = validateReport(data);
      const formatted = formatLintReport(report);
      expect(formatted).toContain("FAIL");
      expect(formatted).toContain("FAILURES");
      expect(formatted).toContain("access_level=none");
    });
  });
});
