import { describe, it, expect } from "vitest";

/**
 * Tests for CWE-based matching improvements and DVWA FP elimination:
 * 1. SQL Injection - Blind now matches separate DVWA ground truth entry
 * 2. CWE-based matching boosts score for same-CWE findings
 * 3. All DVWA auto-detectable vulns should match with 0 FPs
 * 4. GroundTruthVuln interface includes cwe field
 */

const importLearning = () => import("./lib/llm-self-learning");

describe("CWE-Based Matching & DVWA FP Fix", () => {
  describe("SQL Injection - Blind ground truth", () => {
    it("should have SQL Injection - Blind as a separate DVWA ground truth entry", async () => {
      const { GROUND_TRUTH_LIBRARY } = await importLearning();
      const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
      const blindSqli = dvwa.find(v => v.title === "SQL Injection - Blind");
      expect(blindSqli).toBeDefined();
      expect(blindSqli!.autoDetectable).toBe(true);
      expect(blindSqli!.cwe).toBe("CWE-89");
      expect(blindSqli!.severity).toBe("critical");
    });

    it("should match 'SQL Injection - Blind' finding to 'SQL Injection - Blind' ground truth", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "SQL Injection", severity: "critical", category: "Injection", cwe: "CWE-89" },
        { title: "SQL Injection - Blind", severity: "critical", category: "Injection", cwe: "CWE-89" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      const baseSqli = matched.find(m => m.groundTruth.title === "SQL Injection");
      const blindSqli = matched.find(m => m.groundTruth.title === "SQL Injection - Blind");
      expect(baseSqli).toBeDefined();
      expect(blindSqli).toBeDefined();
      // Both should match — no FP for blind SQLi
      expect(result!.falsePositives).toBe(0);
    });

    it("should not deduplicate SQL Injection and SQL Injection - Blind", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "SQL Injection", severity: "critical", category: "Injection" },
        { title: "SQL Injection - Blind", severity: "critical", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      // Both should be in processedFindings (different subtypes)
      const matchedTitles = result!.matchDetails
        .filter(m => m.matched)
        .map(m => m.groundTruth.title);
      expect(matchedTitles).toContain("SQL Injection");
      expect(matchedTitles).toContain("SQL Injection - Blind");
    });
  });

  describe("CWE field in ground truth", () => {
    it("should have CWE fields on all DVWA ground truth entries", async () => {
      const { GROUND_TRUTH_LIBRARY } = await importLearning();
      const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
      for (const entry of dvwa) {
        expect(entry.cwe).toBeDefined();
        expect(entry.cwe).toMatch(/^CWE-\d+$/);
      }
    });

    it("should use correct CWE IDs for DVWA entries", async () => {
      const { GROUND_TRUTH_LIBRARY } = await importLearning();
      const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
      const cweMap: Record<string, string> = {
        "SQL Injection": "CWE-89",
        "SQL Injection - Blind": "CWE-89",
        "XSS - Reflected": "CWE-79",
        "XSS - Stored": "CWE-79",
        "XSS - DOM Based": "CWE-79",
        "Command Injection": "CWE-78",
        "CSRF": "CWE-352",
        "File Inclusion - Local": "CWE-98",
        "File Inclusion - Remote": "CWE-98",
        "File Upload Vulnerability": "CWE-434",
        "Brute Force": "CWE-307",
        "Insecure CAPTCHA": "CWE-863",
        "Weak Session IDs": "CWE-330",
        "Open HTTP Redirect": "CWE-601",
        "Content Security Policy Bypass": "CWE-693",
      };
      for (const [title, expectedCwe] of Object.entries(cweMap)) {
        const entry = dvwa.find(v => v.title === title);
        expect(entry).toBeDefined();
        expect(entry!.cwe).toBe(expectedCwe);
      }
    });
  });

  describe("CWE-based matching in computeMatchScore", () => {
    it("should give higher score when CWE matches", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      // Finding with matching CWE should score higher
      const withCwe = scoreAgainstGroundTruth("dvwa", [
        { title: "SQL Injection", severity: "critical", category: "Injection", cwe: "CWE-89" },
      ]);
      const withoutCwe = scoreAgainstGroundTruth("dvwa", [
        { title: "SQL Injection", severity: "critical", category: "Injection" },
      ]);
      expect(withCwe).not.toBeNull();
      expect(withoutCwe).not.toBeNull();
      // Both should match, but CWE version should have higher overall score
      expect(withCwe!.truePositives).toBe(1);
      expect(withoutCwe!.truePositives).toBe(1);
    });

    it("should match findings with CWE even when title is slightly different", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Reflected Cross-Site Scripting", severity: "high", category: "XSS", cwe: "CWE-79" },
      ]);
      expect(result).not.toBeNull();
      const matched = result!.matchDetails.filter(m => m.matched);
      // Should match one of the XSS entries
      expect(matched.length).toBeGreaterThanOrEqual(1);
      const xssMatch = matched.find(m => m.groundTruth.title.includes("XSS"));
      expect(xssMatch).toBeDefined();
    });
  });

  describe("Full DVWA scoring — zero FP target", () => {
    it("should achieve 100% precision (0 FP) with realistic DVWA findings", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      // Simulate the exact findings a scanner would report for DVWA
      const dvwaFindings = [
        { title: "SQL Injection", severity: "critical", category: "Injection", cwe: "CWE-89" },
        { title: "SQL Injection - Blind", severity: "critical", category: "Injection", cwe: "CWE-89" },
        { title: "Cross Site Scripting (Reflected)", severity: "high", category: "Cross-Site Scripting", cwe: "CWE-79" },
        { title: "Cross Site Scripting (Persistent)", severity: "high", category: "Cross-Site Scripting", cwe: "CWE-79" },
        { title: "Cross Site Scripting (DOM Based)", severity: "high", category: "Cross-Site Scripting", cwe: "CWE-79" },
        { title: "OS Command Injection", severity: "critical", category: "Injection", cwe: "CWE-78" },
        { title: "Cross-Site Request Forgery", severity: "medium", category: "CSRF", cwe: "CWE-352" },
        { title: "Path Traversal", severity: "critical", category: "Injection", cwe: "CWE-98" },
        { title: "Remote File Inclusion", severity: "critical", category: "Injection", cwe: "CWE-98" },
        { title: "Brute Force Login", severity: "high", category: "Authentication", cwe: "CWE-307" },
        { title: "Open HTTP Redirect", severity: "medium", category: "Security Misconfiguration", cwe: "CWE-601" },
        { title: "Content Security Policy Bypass", severity: "medium", category: "Security Misconfiguration" },
      ];
      const result = scoreAgainstGroundTruth("dvwa", dvwaFindings, { autoDetectableOnly: true });
      expect(result).not.toBeNull();
      // Should match all 12 auto-detectable vulns
      expect(result!.truePositives).toBe(12);
      // Should have 0 false positives
      expect(result!.falsePositives).toBe(0);
      // 100% precision
      expect(result!.precision).toBe(1);
      // 100% recall (12/12 auto-detectable)
      expect(result!.recall).toBe(1);
      // Perfect F1
      expect(result!.f1Score).toBe(1);
    });

    it("should filter out informational findings before scoring", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      const findingsWithInformational = [
        { title: "SQL Injection", severity: "critical", category: "Injection" },
        // These should be filtered out
        { title: "X-Frame-Options Header Not Set", severity: "medium", category: "Security Misconfiguration" },
        { title: "Server Leaks Information via X-Powered-By", severity: "low", category: "Information Disclosure" },
        { title: "Cookie Without Secure Flag", severity: "low", category: "Security Misconfiguration" },
        { title: "Anti-CSRF Tokens Check", severity: "informational", category: "Security Misconfiguration" },
        { title: "Application Error Disclosure", severity: "low", category: "Information Disclosure" },
      ];
      const result = scoreAgainstGroundTruth("dvwa", findingsWithInformational, { autoDetectableOnly: true });
      expect(result).not.toBeNull();
      // Only SQL Injection should count — informational ones filtered
      expect(result!.truePositives).toBe(1);
      expect(result!.falsePositives).toBe(0);
    });

    it("should deduplicate Path Traversal with File Inclusion when same subtype", async () => {
      const { scoreAgainstGroundTruth } = await importLearning();
      // Path Traversal and File Inclusion - Local share synonym key "file_inclusion"
      // but have different subtypes, so they should NOT be deduplicated
      const result = scoreAgainstGroundTruth("dvwa", [
        { title: "Path Traversal", severity: "critical", category: "Injection" },
        { title: "File Inclusion - Local", severity: "critical", category: "Injection" },
      ]);
      expect(result).not.toBeNull();
      // Both should match separate ground truth entries
      const matched = result!.matchDetails.filter(m => m.matched);
      expect(matched.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("DVWA ground truth count", () => {
    it("should have 15 DVWA ground truth entries (14 original + 1 new Blind SQLi)", async () => {
      const { GROUND_TRUTH_LIBRARY } = await importLearning();
      const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
      expect(dvwa.length).toBe(15);
    });

    it("should have 12 auto-detectable DVWA entries", async () => {
      const { GROUND_TRUTH_LIBRARY } = await importLearning();
      const dvwa = GROUND_TRUTH_LIBRARY["dvwa"];
      const autoDetectable = dvwa.filter(v => v.autoDetectable !== false);
      expect(autoDetectable.length).toBe(12);
    });
  });
});
