import { describe, expect, it } from "vitest";
import { renderReportHTML, type ReportData } from "./lib/report-generator";

// ─── Unit Tests for ROE Compliance Features ─────────────────────────────────

describe("renderReportHTML with complianceAuthorization", () => {
  const baseReport: ReportData = {
    metadata: {
      title: "Test Report",
      subtitle: "Test Op",
      author: "Ace C3",
      company: "AceofCloud",
      website: "https://aceofcloud.com",
      date: "January 1, 2026",
      clientName: "Test Client",
      engagementType: "Red Team Assessment",
      operationId: "op-123",
      operationName: "Test Operation",
      classification: "CONFIDENTIAL",
    },
    executiveSummary: "Test executive summary.",
    scopeAndMethodology: "Test scope and methodology.",
    operationTimeline: [],
    attackChainResults: [],
    metrics: {
      totalSteps: 10,
      completedSteps: 8,
      successRate: 80,
      detectionRate: 20,
      techniquesAttempted: 5,
      techniquesSucceeded: 4,
      tacticsCovered: 3,
      avgConfidence: 75,
    },
    detectionCoverage: {
      totalTechniques: 5,
      fullCoverage: 2,
      partialCoverage: 1,
      noCoverage: 2,
      coveragePercentage: 60,
      gaps: [],
    },
    ruleValidation: {
      totalRules: 0,
      validRules: 0,
      avgEffectiveness: 0,
      rulesByType: {},
      topIssues: [],
    },
    mitreMapping: [],
    findings: [],
    recommendations: ["Implement detection rules"],
    conclusion: "Test conclusion.",
  };

  it("renders report without compliance section when complianceAuthorization is undefined", () => {
    const html = renderReportHTML(baseReport);
    expect(html).toContain("8. Recommendations");
    expect(html).toContain("9. Conclusion");
    expect(html).not.toContain("Compliance &amp; Authorization");
    expect(html).not.toContain("Offensive Action Audit Trail");
  });

  it("renders compliance section when complianceAuthorization is provided", () => {
    const report: ReportData = {
      ...baseReport,
      complianceAuthorization: {
        roeStatus: "signed",
        roeSignedDate: "January 1, 2026",
        roeExpiryDate: "March 1, 2026",
        roeSignerName: "John Doe",
        roeSignerEmail: "john@example.com",
        roeDocumentUrl: "https://s3.example.com/roe.pdf",
        roeScope: {
          domains: ["example.com", "test.com"],
          ipRanges: ["10.0.0.0/24"],
          exclusions: ["prod-db.example.com"],
          restrictions: "No destructive actions",
        },
        auditLogEntries: [
          {
            timestamp: "2026-01-15T10:00:00Z",
            operator: "operator1",
            actionType: "msf_check",
            riskTier: "orange",
            target: "10.0.0.5",
            module: "auxiliary/scanner/http/http_version",
            result: "success",
            roeStatus: "signed",
          },
          {
            timestamp: "2026-01-15T10:05:00Z",
            operator: "operator1",
            actionType: "phishing_launch",
            riskTier: "red",
            target: "example.com",
            module: "GoPhish Campaign",
            result: "success",
            roeStatus: "signed",
          },
        ],
        totalActions: 2,
        actionsUnderROE: 2,
        blockedActions: 0,
      },
    };

    const html = renderReportHTML(report);

    // Section numbering should shift
    expect(html).toContain("8. Compliance &amp; Authorization");
    expect(html).toContain("9. Recommendations");
    expect(html).toContain("10. Conclusion");

    // ROE Status table
    expect(html).toContain("SIGNED");
    expect(html).toContain("January 1, 2026");
    expect(html).toContain("March 1, 2026");
    expect(html).toContain("John Doe");
    expect(html).toContain("john@example.com");
    expect(html).toContain("View Signed ROE Document");

    // Scope section
    expect(html).toContain("example.com, test.com");
    expect(html).toContain("10.0.0.0/24");
    expect(html).toContain("prod-db.example.com");
    expect(html).toContain("No destructive actions");

    // Authorization summary
    expect(html).toContain("Actions Under Valid ROE");
    expect(html).toContain("Total Logged Actions");

    // Audit trail table
    expect(html).toContain("Offensive Action Audit Trail");
    expect(html).toContain("operator1");
    expect(html).toContain("msf check");
    expect(html).toContain("10.0.0.5");

    // Compliance statement for signed ROE
    expect(html).toContain("All offensive actions documented in this report were conducted under a valid, signed Rules of Engagement document.");
  });

  it("shows warning compliance statement when ROE is expired", () => {
    const report: ReportData = {
      ...baseReport,
      complianceAuthorization: {
        roeStatus: "expired",
        roeSignedDate: "January 1, 2025",
        roeExpiryDate: "June 1, 2025",
        roeSignerName: null,
        roeSignerEmail: null,
        roeDocumentUrl: null,
        roeScope: null,
        auditLogEntries: [],
        totalActions: 0,
        actionsUnderROE: 0,
        blockedActions: 0,
      },
    };

    const html = renderReportHTML(report);
    expect(html).toContain("WARNING: The Rules of Engagement for this engagement have expired");
  });

  it("shows warning compliance statement when ROE is none", () => {
    const report: ReportData = {
      ...baseReport,
      complianceAuthorization: {
        roeStatus: "none",
        roeSignedDate: null,
        roeExpiryDate: null,
        roeSignerName: null,
        roeSignerEmail: null,
        roeDocumentUrl: null,
        roeScope: null,
        auditLogEntries: [],
        totalActions: 0,
        actionsUnderROE: 0,
        blockedActions: 0,
      },
    };

    const html = renderReportHTML(report);
    expect(html).toContain("WARNING: No signed Rules of Engagement document was found");
  });

  it("shows blocked actions count when actions were blocked", () => {
    const report: ReportData = {
      ...baseReport,
      complianceAuthorization: {
        roeStatus: "signed",
        roeSignedDate: "January 1, 2026",
        roeExpiryDate: "March 1, 2026",
        roeSignerName: "Jane Smith",
        roeSignerEmail: "jane@example.com",
        roeDocumentUrl: null,
        roeScope: null,
        auditLogEntries: [
          {
            timestamp: "2026-01-15T10:00:00Z",
            operator: "operator1",
            actionType: "msf_exploit",
            riskTier: "red",
            target: "10.0.0.5",
            module: "exploit/windows/smb/ms17_010",
            result: "blocked",
            roeStatus: "expired",
          },
        ],
        totalActions: 5,
        actionsUnderROE: 3,
        blockedActions: 2,
      },
    };

    const html = renderReportHTML(report);
    expect(html).toContain("Blocked (No/Expired ROE)");
    // The blocked count should be visible
    expect(html).toContain(">2<");
    expect(html).toContain(">3<");
    expect(html).toContain(">5<");
  });

  it("handles empty audit log entries gracefully", () => {
    const report: ReportData = {
      ...baseReport,
      complianceAuthorization: {
        roeStatus: "signed",
        roeSignedDate: "January 1, 2026",
        roeExpiryDate: "March 1, 2026",
        roeSignerName: "Test Signer",
        roeSignerEmail: "signer@test.com",
        roeDocumentUrl: "https://s3.example.com/roe.pdf",
        roeScope: null,
        auditLogEntries: [],
        totalActions: 0,
        actionsUnderROE: 0,
        blockedActions: 0,
      },
    };

    const html = renderReportHTML(report);
    expect(html).toContain("No offensive actions were logged for this engagement.");
    expect(html).not.toContain("Offensive Action Audit Trail");
  });
});
