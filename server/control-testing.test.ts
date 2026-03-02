import { describe, it, expect } from "vitest";
import {
  generateTestSuite,
  executeTest,
  runTestSuite,
  exportReportAsMarkdown,
  exportEvidenceAsCSV,
  verifyEvidenceChain,
  getSupportedControlCategories,
  type ControlTestCase,
  type EvidenceRecord,
} from "./lib/control-testing-engine";

// ─── getSupportedControlCategories ──────────────────────────────────────────

describe("getSupportedControlCategories", () => {
  it("returns all supported control categories", () => {
    const categories = getSupportedControlCategories();
    expect(Array.isArray(categories)).toBe(true);
    expect(categories.length).toBeGreaterThan(0);
    for (const cat of categories) {
      expect(cat).toHaveProperty("category");
      expect(cat).toHaveProperty("testCount");
      expect(cat).toHaveProperty("categories");
      expect(cat).toHaveProperty("mitreTechniques");
      expect(cat).toHaveProperty("nistControls");
      expect(cat.testCount).toBeGreaterThan(0);
      expect(cat.mitreTechniques.length).toBeGreaterThan(0);
      expect(cat.nistControls.length).toBeGreaterThan(0);
    }
  });

  it("includes key control categories like WAF, IDS, MFA, EDR", () => {
    const categories = getSupportedControlCategories();
    const names = categories.map((c: any) => c.category.toLowerCase());
    // At least some of these common categories should exist
    const expected = ["waf", "ids_ips", "mfa", "edr", "network_segmentation"];
    const found = expected.filter(e => names.some((n: string) => n.includes(e) || e.includes(n)));
    expect(found.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── generateTestSuite ──────────────────────────────────────────────────────

describe("generateTestSuite", () => {
  it("generates a test suite for a valid control category", () => {
    const categories = getSupportedControlCategories();
    const firstCat = categories[0].category;
    const suite = generateTestSuite(firstCat, "Test Control Instance");

    expect(suite).toHaveProperty("suiteId");
    expect(suite).toHaveProperty("controlCategory", firstCat);
    expect(suite).toHaveProperty("controlName", "Test Control Instance");
    expect(suite).toHaveProperty("testCases");
    expect(Array.isArray(suite.testCases)).toBe(true);
    expect(suite.testCases.length).toBeGreaterThan(0);
  });

  it("each test case has all required fields", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Cloudflare WAF");

    for (const tc of suite.testCases) {
      expect(tc).toHaveProperty("testId");
      expect(tc).toHaveProperty("controlCategory");
      expect(tc).toHaveProperty("controlName");
      expect(tc).toHaveProperty("testCategory");
      expect(tc).toHaveProperty("title");
      expect(tc).toHaveProperty("description");
      expect(tc).toHaveProperty("procedure");
      expect(tc).toHaveProperty("expectedOutcome");
      expect(tc).toHaveProperty("failureCriteria");
      expect(tc).toHaveProperty("mitreTechniques");
      expect(tc).toHaveProperty("nistControls");
      expect(tc).toHaveProperty("automatable");
      expect(tc).toHaveProperty("estimatedDuration");
      expect(tc).toHaveProperty("prerequisites");
      expect(tc).toHaveProperty("riskLevel");
      expect(["low", "medium", "high"]).toContain(tc.riskLevel);
    }
  });

  it("respects excludeManual option", () => {
    const categories = getSupportedControlCategories();
    const fullSuite = generateTestSuite(categories[0].category, "Test");
    const autoSuite = generateTestSuite(categories[0].category, "Test", { excludeManual: true });

    // Auto-only suite should have equal or fewer tests
    expect(autoSuite.testCases.length).toBeLessThanOrEqual(fullSuite.testCases.length);
    for (const tc of autoSuite.testCases) {
      expect(tc.automatable).toBe(true);
    }
  });

  it("respects maxRiskLevel option", () => {
    const categories = getSupportedControlCategories();
    const lowSuite = generateTestSuite(categories[0].category, "Test", { maxRiskLevel: "low" });

    for (const tc of lowSuite.testCases) {
      expect(tc.riskLevel).toBe("low");
    }
  });

  it("respects includeCategories filter", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test", {
      includeCategories: ["configuration_audit"],
    });

    for (const tc of suite.testCases) {
      expect(tc.testCategory).toBe("configuration_audit");
    }
  });

  it("returns empty test suite for unknown category", () => {
    const suite = generateTestSuite("nonexistent_category", "Test");
    expect(suite.testCases.length).toBe(0);
  });
});

// ─── executeTest ────────────────────────────────────────────────────────────

describe("executeTest", () => {
  it("executes a test case and returns execution result with evidence", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test WAF");
    const testCase = suite.testCases[0];

    const result = executeTest(testCase, {
      executedBy: "test-user",
      environment: "staging",
      controlConfig: { blockingMode: true, loggingEnabled: true },
    });

    expect(result).toHaveProperty("execution");
    expect(result).toHaveProperty("evidenceRecords");
    expect(result.execution).toHaveProperty("executionId");
    expect(result.execution).toHaveProperty("testId", testCase.testId);
    expect(result.execution).toHaveProperty("status");
    expect(["passed", "failed", "inconclusive"]).toContain(result.execution.status);
    expect(result.execution).toHaveProperty("result");
    expect(result.execution.result).toHaveProperty("score");
    expect(result.execution.result.score).toBeGreaterThanOrEqual(0);
    expect(result.execution.result.score).toBeLessThanOrEqual(100);
  });

  it("generates evidence records with SHA-256 hashes", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const testCase = suite.testCases[0];

    const result = executeTest(testCase, {
      executedBy: "auditor",
      environment: "production",
    });

    expect(result.evidenceRecords.length).toBeGreaterThan(0);
    for (const ev of result.evidenceRecords) {
      expect(ev).toHaveProperty("evidenceId");
      expect(ev).toHaveProperty("executionId");
      expect(ev).toHaveProperty("timestamp");
      expect(ev).toHaveProperty("contentHash");
      expect(ev).toHaveProperty("chainHash");
      expect(ev).toHaveProperty("collector");
      expect(ev).toHaveProperty("retentionDays");
      expect(ev).toHaveProperty("classification");
      // SHA-256 hash is 64 hex characters
      expect(ev.contentHash).toMatch(/^[a-f0-9]{64}$/);
      expect(ev.chainHash).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("chains evidence records with previous hashes", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const testCase = suite.testCases[0];

    const result = executeTest(testCase, {
      executedBy: "auditor",
      environment: "production",
    });

    if (result.evidenceRecords.length >= 2) {
      // First record should have null previousHash
      expect(result.evidenceRecords[0].previousHash).toBeNull();
      // Subsequent records should reference the previous chain hash
      for (let i = 1; i < result.evidenceRecords.length; i++) {
        expect(result.evidenceRecords[i].previousHash).toBe(
          result.evidenceRecords[i - 1].chainHash
        );
      }
    }
  });

  it("supports previousEvidenceHash for cross-execution chaining", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const testCase = suite.testCases[0];

    const prevHash = "a".repeat(64);
    const result = executeTest(testCase, {
      executedBy: "auditor",
      environment: "production",
      previousEvidenceHash: prevHash,
    });

    // First evidence record should reference the previous execution's hash
    if (result.evidenceRecords.length > 0) {
      expect(result.evidenceRecords[0].previousHash).toBe(prevHash);
    }
  });
});

// ─── runTestSuite ───────────────────────────────────────────────────────────

describe("runTestSuite", () => {
  it("runs a full test suite and produces a validation report", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Production WAF");

    const report = runTestSuite(suite, {
      executedBy: "security-team",
      environment: "production",
      controlConfig: { blockingMode: true },
    });

    expect(report).toHaveProperty("reportId");
    expect(report).toHaveProperty("controlCategory");
    expect(report).toHaveProperty("controlName", "Production WAF");
    expect(report).toHaveProperty("generatedAt");
    expect(report).toHaveProperty("overallVerdict");
    expect(report).toHaveProperty("overallScore");
    expect(report).toHaveProperty("testResults");
    expect(report).toHaveProperty("complianceMapping");
    expect(report).toHaveProperty("riskAssessment");
    expect(report).toHaveProperty("signatureBlock");
    expect(["effective", "partially_effective", "ineffective"]).toContain(report.overallVerdict);
    expect(report.overallScore).toBeGreaterThanOrEqual(0);
    expect(report.overallScore).toBeLessThanOrEqual(100);
  });

  it("includes compliance mapping with NIST controls", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "staging",
    });

    expect(report.complianceMapping.length).toBeGreaterThan(0);
    for (const cm of report.complianceMapping) {
      expect(cm).toHaveProperty("framework");
      expect(cm).toHaveProperty("controlId");
      expect(cm).toHaveProperty("requirement");
      expect(cm).toHaveProperty("status");
      expect(cm).toHaveProperty("evidence");
      expect(["satisfied", "partially_satisfied", "not_satisfied"]).toContain(cm.status);
    }
  });

  it("includes risk assessment with expiration and conditions", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    expect(report.riskAssessment).toHaveProperty("residualRisk");
    expect(report.riskAssessment).toHaveProperty("mitigationEffectiveness");
    expect(report.riskAssessment).toHaveProperty("expirationDate");
    expect(report.riskAssessment).toHaveProperty("reviewFrequency");
    expect(report.riskAssessment).toHaveProperty("conditions");
    expect(["low", "medium", "high", "critical"]).toContain(report.riskAssessment.residualRisk);
    expect(report.riskAssessment.mitigationEffectiveness).toBeGreaterThanOrEqual(0);
    expect(report.riskAssessment.mitigationEffectiveness).toBeLessThanOrEqual(100);
  });

  it("includes signature block with report hash and chain validity", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    expect(report.signatureBlock).toHaveProperty("reportHash");
    expect(report.signatureBlock).toHaveProperty("evidenceChainValid");
    expect(report.signatureBlock).toHaveProperty("totalEvidenceRecords");
    expect(report.signatureBlock).toHaveProperty("integrityStatement");
    expect(report.signatureBlock.reportHash).toMatch(/^[a-f0-9]{64}$/);
    expect(typeof report.signatureBlock.evidenceChainValid).toBe("boolean");
  });
});

// ─── exportReportAsMarkdown ─────────────────────────────────────────────────

describe("exportReportAsMarkdown", () => {
  it("exports a validation report as Markdown", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Audit WAF");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    const md = exportReportAsMarkdown(report);
    expect(typeof md).toBe("string");
    expect(md.length).toBeGreaterThan(100);
    expect(md).toContain("Compensating Control Validation Report");
    expect(md).toContain(report.reportId);
    expect(md).toContain("Audit WAF");
    expect(md).toContain("Risk Assessment");
    expect(md).toContain("Compliance Mapping");
  });
});

// ─── exportEvidenceAsCSV ────────────────────────────────────────────────────

describe("exportEvidenceAsCSV", () => {
  it("exports evidence records as CSV with headers", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    const csv = exportEvidenceAsCSV(report);
    expect(typeof csv).toBe("string");
    const lines = csv.split("\n").filter(l => l.trim());
    expect(lines.length).toBeGreaterThan(1); // header + at least one row
    expect(lines[0]).toContain("Evidence ID");
    expect(lines[0]).toContain("Content Hash");
    expect(lines[0]).toContain("Chain Hash");
  });
});

// ─── verifyEvidenceChain ────────────────────────────────────────────────────

describe("verifyEvidenceChain", () => {
  it("verifies a valid evidence chain from a test suite run", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    const allEvidence = report.testResults.flatMap((tr: any) => tr.evidenceRecords);
    const result = verifyEvidenceChain(allEvidence);

    expect(result).toHaveProperty("valid");
    expect(result).toHaveProperty("totalRecords");
    expect(result).toHaveProperty("verifiedRecords");
    expect(result).toHaveProperty("details");
    expect(result.totalRecords).toBe(allEvidence.length);
    // Chain should be valid for freshly generated evidence
    expect(result.valid).toBe(true);
    expect(result.verifiedRecords).toBe(allEvidence.length);
  });

  it("detects a broken evidence chain when content is tampered", () => {
    const categories = getSupportedControlCategories();
    const suite = generateTestSuite(categories[0].category, "Test");
    const report = runTestSuite(suite, {
      executedBy: "auditor",
      environment: "production",
    });

    const allEvidence = report.testResults.flatMap((tr: any) => tr.evidenceRecords);
    if (allEvidence.length >= 2) {
      // Tamper with the second record's content hash
      const tampered = [...allEvidence];
      tampered[1] = { ...tampered[1], contentHash: "0".repeat(64) };

      const result = verifyEvidenceChain(tampered);
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(1);
    }
  });

  it("handles empty evidence chain", () => {
    const result = verifyEvidenceChain([]);
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
    expect(result.verifiedRecords).toBe(0);
  });
});
