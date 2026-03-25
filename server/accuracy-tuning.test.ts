import { describe, it, expect } from "vitest";

/**
 * Tests for the FP/FN analysis tuning improvements:
 * 1. Improved scoreAgainstGroundTruth with synonym matching and title normalization
 * 2. autoDetectable ground truth tiering
 * 3. New FP suppression rules for ZAP/Nuclei informational alerts
 * 4. Finding normalization (tool prefix stripping, deduplication)
 */

const importLearning = () => import("./lib/llm-self-learning");
const importFP = () => import("./lib/knowledge/fp-suppression-rules");

describe("Accuracy Tuning — Improved Matching Algorithm", () => {
  describe("scoreAgainstGroundTruth — synonym matching", () => {
    it("should match '[ZAP] SQL Injection' to ground truth 'SQL Injection'", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const sqlMatch = matched.find(m => m.groundTruth.title === "SQL Injection");
      expect(sqlMatch).toBeDefined();
    });

    it("should match 'Cross Site Scripting (Reflected)' to 'XSS - Reflected'", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Cross Site Scripting (Reflected)", severity: "high", category: "Cross-Site Scripting" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const xssMatch = matched.find(m => m.groundTruth.title === "XSS - Reflected");
      expect(xssMatch).toBeDefined();
    });

    it("should match 'Cross Site Scripting (Persistent)' to 'XSS - Stored'", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Cross Site Scripting (Persistent)", severity: "high", category: "Cross-Site Scripting" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const xssMatch = matched.find(m => m.groundTruth.title === "XSS - Stored");
      expect(xssMatch).toBeDefined();
    });

    it("should match '[sqlmap] SQL Injection' to 'SQL Injection'", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "[sqlmap] SQL Injection", severity: "critical", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const sqlMatch = matched.find(m => m.groundTruth.title === "SQL Injection");
      expect(sqlMatch).toBeDefined();
    });

    it("should match 'OS Command Injection' to 'Command Injection' via synonyms", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "OS Command Injection", severity: "critical", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const cmdMatch = matched.find(m => m.groundTruth.title === "Command Injection");
      expect(cmdMatch).toBeDefined();
    });

    it("should match 'Absence of Anti-CSRF Tokens' to 'CSRF' via synonyms", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Absence of Anti-CSRF Tokens", severity: "medium", category: "Cross-Site Request Forgery" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const csrfMatch = matched.find(m => m.groundTruth.title === "CSRF");
      expect(csrfMatch).toBeDefined();
    });

    it("should match 'Path Traversal' to 'File Inclusion - Local' via synonyms", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Path Traversal", severity: "high", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const fiMatch = matched.find(m =>
        m.groundTruth.title === "File Inclusion - Local" || m.groundTruth.title === "File Inclusion - Remote"
      );
      expect(fiMatch).toBeDefined();
    });
  });

  describe("scoreAgainstGroundTruth — autoDetectable tiering", () => {
    it("should return fewer ground truth items when autoDetectableOnly is true", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const fullResult = scoreAgainstGroundTruth("dvwa", []);
      const autoResult = scoreAgainstGroundTruth("dvwa", [], { autoDetectableOnly: true });
      expect(fullResult).not.toBeNull();
      expect(autoResult).not.toBeNull();
      expect(autoResult!.totalGroundTruth).toBeLessThanOrEqual(fullResult!.totalGroundTruth);
    });

    it("should exclude manual-only vulns (File Upload, Insecure CAPTCHA, Weak Session IDs) from auto-detectable scoring", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const autoResult = scoreAgainstGroundTruth("dvwa", [], { autoDetectableOnly: true });
      expect(autoResult).not.toBeNull();
      const groundTruthTitles = autoResult!.matchDetails.map(m => m.groundTruth.title);
      expect(groundTruthTitles).not.toContain("File Upload Vulnerability");
      expect(groundTruthTitles).not.toContain("Insecure CAPTCHA");
      expect(groundTruthTitles).not.toContain("Weak Session IDs");
    });

    it("should include auto-detectable vulns in auto-detectable scoring", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const autoResult = scoreAgainstGroundTruth("dvwa", [], { autoDetectableOnly: true });
      expect(autoResult).not.toBeNull();
      const groundTruthTitles = autoResult!.matchDetails.map(m => m.groundTruth.title);
      expect(groundTruthTitles).toContain("SQL Injection");
      expect(groundTruthTitles).toContain("XSS - Reflected");
      expect(groundTruthTitles).toContain("Command Injection");
      expect(groundTruthTitles).toContain("CSRF");
    });

    it("should have totalGroundTruthFull set to the full count", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const autoResult = scoreAgainstGroundTruth("dvwa", [], { autoDetectableOnly: true });
      expect(autoResult).not.toBeNull();
      expect(autoResult!.totalGroundTruthFull).toBeGreaterThanOrEqual(autoResult!.totalGroundTruth);
    });

    it("should set autoDetectableOnly flag in result", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const autoResult = scoreAgainstGroundTruth("dvwa", [], { autoDetectableOnly: true });
      expect(autoResult).not.toBeNull();
      expect(autoResult!.autoDetectableOnly).toBe(true);
    });

    it("Juice Shop should have manual-only vulns excluded from auto-detectable scoring", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const fullResult = scoreAgainstGroundTruth("juice-shop", []);
      const autoResult = scoreAgainstGroundTruth("juice-shop", [], { autoDetectableOnly: true });
      expect(fullResult).not.toBeNull();
      expect(autoResult).not.toBeNull();
      // Juice Shop has many manual-only vulns (business logic, 2FA bypass, etc.)
      expect(autoResult!.totalGroundTruth).toBeLessThan(fullResult!.totalGroundTruth);
    });
  });

  describe("scoreAgainstGroundTruth — improved F1 calculation", () => {
    it("should produce higher F1 for DVWA with normalized ZAP findings", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      // Simulate typical ZAP findings that previously didn't match
      const zapFindings = [
        { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
        { title: "[ZAP] Cross Site Scripting (Reflected)", severity: "high", category: "Cross-Site Scripting" },
        { title: "[ZAP] Cross Site Scripting (Persistent)", severity: "high", category: "Cross-Site Scripting" },
        { title: "[ZAP] Remote OS Command Injection", severity: "critical", category: "Injection" },
        { title: "[ZAP] Absence of Anti-CSRF Tokens", severity: "medium", category: "Cross-Site Request Forgery" },
        { title: "[ZAP] Path Traversal", severity: "high", category: "Injection" },
        { title: "[ZAP] Cross Site Scripting (DOM Based)", severity: "high", category: "Cross-Site Scripting" },
      ];
      const result = scoreAgainstGroundTruth("dvwa", zapFindings, { autoDetectableOnly: true });
      expect(result).not.toBeNull();
      // Should match at least 5 of the 7 findings to ground truth
      expect(result!.truePositives).toBeGreaterThanOrEqual(5);
      // F1 should be significantly better than the previous 25.8%
      expect(result!.f1Score).toBeGreaterThan(0.4);
    });

    it("should return null for unknown target preset", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("nonexistent-target", []);
      expect(result).toBeNull();
    });

    it("should handle empty findings array", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", []);
      expect(result).not.toBeNull();
      expect(result!.truePositives).toBe(0);
      expect(result!.falsePositives).toBe(0);
      expect(result!.precision).toBe(0);
      expect(result!.recall).toBe(0);
    });
  });
});

describe("Accuracy Tuning — New FP Suppression Rules", () => {
  it("should suppress ZAP informational alerts (Timestamp Disclosure)", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "Timestamp Disclosure - Unix", severity: "info", source: "zap" }, agentClass: "zap" },
    ];
    const result = applySuppressionRules(findings, "balanced");
    expect(result.suppressed.length).toBe(1);
  });

  it("should suppress ZAP CSP Header Not Set", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "Content Security Policy (CSP) Header Not Set", severity: "low", source: "zap" }, agentClass: "zap" },
    ];
    const result = applySuppressionRules(findings, "balanced");
    expect(result.suppressed.length).toBe(1);
  });

  it("should suppress ZAP Absence of Anti-CSRF Tokens (info/low)", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "Absence of Anti-CSRF Tokens", severity: "low", source: "zap" }, agentClass: "zap" },
    ];
    const result = applySuppressionRules(findings, "balanced");
    expect(result.suppressed.length).toBe(1);
  });

  it("should suppress Nuclei tech-detect templates", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "tech-detect-nginx", severity: "info", source: "nuclei" }, agentClass: "nuclei" },
    ];
    const result = applySuppressionRules(findings, "balanced");
    expect(result.suppressed.length).toBe(1);
  });

  it("should NOT suppress real ZAP XSS findings (high severity)", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "Cross Site Scripting (Reflected)", severity: "high", source: "zap" }, agentClass: "zap" },
    ];
    const result = applySuppressionRules(findings, "aggressive");
    expect(result.kept.length).toBe(1);
    expect(result.suppressed.length).toBe(0);
  });

  it("should NOT suppress real SQL Injection findings", async () => {
    const { applySuppressionRules } = await importFP();
    const findings = [
      { finding: { title: "SQL Injection", severity: "critical", source: "zap" }, agentClass: "zap" },
    ];
    const result = applySuppressionRules(findings, "aggressive");
    expect(result.kept.length).toBe(1);
    expect(result.suppressed.length).toBe(0);
  });

  it("new rules should have unique IDs", async () => {
    const { FP_SUPPRESSION_RULES } = await importFP();
    const ids = FP_SUPPRESSION_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("new rules should have valid categories", async () => {
    const { FP_SUPPRESSION_RULES } = await importFP();
    const validCategories = [
      "informational_header", "service_banner", "unverified_cve",
      "config_observation", "robots_disclosure", "cookie_flag",
      "http_method", "etag_leak", "redirect_info", "duplicate_finding"
    ];
    for (const rule of FP_SUPPRESSION_RULES) {
      expect(validCategories).toContain(rule.category);
    }
  });
});

describe("Accuracy Tuning — Ground Truth Library", () => {
  it("DVWA ground truth should have autoDetectable field on all entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
    expect(dvwa).toBeDefined();
    for (const vuln of dvwa) {
      expect(vuln).toHaveProperty("autoDetectable");
      expect(typeof vuln.autoDetectable).toBe("boolean");
    }
  });

  it("Juice Shop ground truth should have autoDetectable field on all entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const juiceShop = GROUND_TRUTH_LIBRARY["juice-shop"];
    expect(juiceShop).toBeDefined();
    for (const vuln of juiceShop) {
      expect(vuln).toHaveProperty("autoDetectable");
      expect(typeof vuln.autoDetectable).toBe("boolean");
    }
  });

  it("DVWA should have at least 10 auto-detectable vulns", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
    const autoDetectable = dvwa.filter(v => v.autoDetectable === true);
    expect(autoDetectable.length).toBeGreaterThanOrEqual(10);
  });

  it("Juice Shop should have at least 15 auto-detectable vulns", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const juiceShop = GROUND_TRUTH_LIBRARY["juice-shop"];
    const autoDetectable = juiceShop.filter(v => v.autoDetectable === true);
    expect(autoDetectable.length).toBeGreaterThanOrEqual(15);
  });

  it("DVWA top 5 critical vulns should all be auto-detectable", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
    const top5 = ["SQL Injection", "XSS - Reflected", "XSS - Stored", "Command Injection", "CSRF"];
    for (const title of top5) {
      const vuln = dvwa.find(v => v.title === title);
      expect(vuln).toBeDefined();
      expect(vuln!.autoDetectable).toBe(true);
    }
  });
});
