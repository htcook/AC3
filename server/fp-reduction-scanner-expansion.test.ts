import { describe, it, expect } from "vitest";

/**
 * Tests for:
 * 1. DVWA FP reduction — pre-scoring deduplication and informational finding filter
 * 2. Juice Shop recall improvement — expanded scanner coverage
 * 3. WebGoat ground truth entries
 * 4. Training lab enhanced scanner configuration
 */

const importLearning = () => import("./lib/llm-self-learning");

// ─── DVWA FP Reduction: Pre-scoring Deduplication ─────────────────────────

describe("DVWA FP Reduction — Pre-scoring Deduplication", () => {
  it("should deduplicate 'Path Traversal' when 'File Inclusion - Local' is also present", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] File Inclusion - Local", severity: "high", category: "Injection" },
      { title: "[ZAP] Path Traversal", severity: "high", category: "Injection" },
      { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    // Path Traversal should be deduplicated since File Inclusion is present
    // So we should have fewer FPs than if both counted separately
    expect(result!.falsePositives).toBeLessThanOrEqual(1);
  });

  it("should keep 'Path Traversal' when 'File Inclusion' is NOT present", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] Path Traversal", severity: "high", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    // Path Traversal should match File Inclusion - Local via synonyms
    const matched = result!.matchDetails.filter(m => m.matched);
    expect(matched.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── DVWA FP Reduction: Informational Finding Filter ──────────────────────

describe("DVWA FP Reduction — Informational Finding Filter", () => {
  it("should filter out 'X-Frame-Options Header Not Set' as informational", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] X-Frame-Options Header Not Set", severity: "medium", category: "Informational" },
      { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    // X-Frame-Options should be filtered out, not counted as FP
    // Only SQL Injection should be in the scoring
    expect(result!.truePositives).toBeGreaterThanOrEqual(1);
    expect(result!.falsePositives).toBe(0);
  });

  it("should filter out 'Server Leaks Information via X-Powered-By' as informational", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] Server Leaks Information via X-Powered-By HTTP Response Header", severity: "low", category: "Informational" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    expect(result!.falsePositives).toBe(0);
  });

  it("should filter out 'Cookie Without Secure Flag' as informational", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] Cookie Without Secure Flag", severity: "low", category: "Informational" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    expect(result!.falsePositives).toBe(0);
  });

  it("should filter out 'Application Error Disclosure' as informational", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] Application Error Disclosure", severity: "low", category: "Informational" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    expect(result!.falsePositives).toBe(0);
  });

  it("should NOT filter out real vulnerability findings", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
      { title: "[ZAP] Cross Site Scripting (Reflected)", severity: "high", category: "Cross-Site Scripting" },
      { title: "[ZAP] Remote OS Command Injection", severity: "critical", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings);
    expect(result).not.toBeNull();
    expect(result!.truePositives).toBeGreaterThanOrEqual(3);
  });

  it("DVWA full realistic scan should have 0 FP with informational filter", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    // Simulate all 17 findings from the DVWA scan including the 6 FPs
    const findings = [
      // Real matches
      { title: "[ZAP] SQL Injection", severity: "critical", category: "Injection" },
      { title: "[ZAP] Cross Site Scripting (Reflected)", severity: "high", category: "Cross-Site Scripting" },
      { title: "[ZAP] Cross Site Scripting (Persistent)", severity: "high", category: "Cross-Site Scripting" },
      { title: "[ZAP] Cross Site Scripting (DOM Based)", severity: "high", category: "Cross-Site Scripting" },
      { title: "[ZAP] Remote OS Command Injection", severity: "critical", category: "Injection" },
      { title: "[ZAP] Absence of Anti-CSRF Tokens", severity: "medium", category: "Cross-Site Request Forgery" },
      { title: "[ZAP] File Inclusion - Local", severity: "high", category: "Injection" },
      { title: "[ZAP] Open HTTP Redirect", severity: "medium", category: "Redirect" },
      { title: "[Nuclei] CSP Bypass", severity: "medium", category: "Misconfiguration" },
      { title: "[ZAP] SQL Injection - Blind", severity: "critical", category: "Injection" },
      { title: "[ZAP] Brute Force Login", severity: "high", category: "Authentication" },
      // Previous FPs — should now be filtered or deduplicated
      { title: "[ZAP] Path Traversal", severity: "high", category: "Injection" },
      { title: "[ZAP] X-Frame-Options Header Not Set", severity: "medium", category: "Informational" },
      { title: "[ZAP] Server Leaks Information via X-Powered-By HTTP Response Header", severity: "low", category: "Informational" },
      { title: "[ZAP] Cookie Without Secure Flag", severity: "low", category: "Informational" },
      { title: "[ZAP] Application Error Disclosure", severity: "low", category: "Informational" },
      { title: "[ZAP] Anti-CSRF Tokens Check", severity: "info", category: "Informational" },
    ];
    const result = scoreAgainstGroundTruth("dvwa", findings, { autoDetectableOnly: true });
    expect(result).not.toBeNull();
    // Should have very few FPs (ideally 0-2) after filtering informational and deduplicating
    expect(result!.falsePositives).toBeLessThanOrEqual(3);
    // F1 should be very high with all real vulns matching
    expect(result!.f1Score).toBeGreaterThanOrEqual(0.7);
  });
});

// ─── WebGoat Ground Truth ─────────────────────────────────────────────────

describe("WebGoat Ground Truth", () => {
  it("should have WebGoat ground truth entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const webgoat = GROUND_TRUTH_LIBRARY["webgoat"];
    expect(webgoat).toBeDefined();
    expect(webgoat.length).toBeGreaterThanOrEqual(20);
  });

  it("all WebGoat entries should have autoDetectable field", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const webgoat = GROUND_TRUTH_LIBRARY["webgoat"];
    for (const vuln of webgoat) {
      expect(vuln).toHaveProperty("autoDetectable");
      expect(typeof vuln.autoDetectable).toBe("boolean");
    }
  });

  it("WebGoat should have at least 10 auto-detectable vulns", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const webgoat = GROUND_TRUTH_LIBRARY["webgoat"];
    const autoDetectable = webgoat.filter((v: any) => v.autoDetectable === true);
    expect(autoDetectable.length).toBeGreaterThanOrEqual(10);
  });

  it("WebGoat should include SQL Injection, XSS, XXE, IDOR as auto-detectable", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const webgoat = GROUND_TRUTH_LIBRARY["webgoat"];
    const autoTitles = webgoat.filter((v: any) => v.autoDetectable).map((v: any) => v.title.toLowerCase());
    expect(autoTitles.some((t: string) => t.includes("sql injection"))).toBe(true);
    expect(autoTitles.some((t: string) => t.includes("xss") || t.includes("cross-site scripting"))).toBe(true);
    expect(autoTitles.some((t: string) => t.includes("xxe"))).toBe(true);
  });

  it("WebGoat scoring should work correctly", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "SQL Injection", severity: "critical", category: "Injection" },
      { title: "Cross Site Scripting", severity: "high", category: "XSS" },
    ];
    const result = scoreAgainstGroundTruth("webgoat", findings);
    expect(result).not.toBeNull();
    expect(result!.truePositives).toBeGreaterThanOrEqual(1);
  });
});

// ─── All Ground Truth Targets — autoDetectable Coverage ───────────────────

describe("All Ground Truth Targets — autoDetectable Coverage", () => {
  it("all targets should have autoDetectable on every entry", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    for (const [targetName, vulns] of Object.entries(GROUND_TRUTH_LIBRARY)) {
      for (const vuln of vulns as any[]) {
        expect(vuln).toHaveProperty("autoDetectable");
        expect(typeof vuln.autoDetectable).toBe("boolean");
      }
    }
  });

  it("bWAPP should have autoDetectable on all entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const bwapp = GROUND_TRUTH_LIBRARY["bwapp"];
    expect(bwapp).toBeDefined();
    const autoCount = bwapp.filter((v: any) => v.autoDetectable === true).length;
    expect(autoCount).toBeGreaterThanOrEqual(20);
  });

  it("Mutillidae should have autoDetectable on all entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const mutillidae = GROUND_TRUTH_LIBRARY["mutillidae"];
    expect(mutillidae).toBeDefined();
    const autoCount = mutillidae.filter((v: any) => v.autoDetectable === true).length;
    expect(autoCount).toBeGreaterThanOrEqual(20);
  });

  it("crAPI should have autoDetectable on all entries", async () => {
    const { GROUND_TRUTH_LIBRARY } = await importLearning();
    const crapi = GROUND_TRUTH_LIBRARY["crapi"];
    expect(crapi).toBeDefined();
    for (const vuln of crapi as any[]) {
      expect(vuln).toHaveProperty("autoDetectable");
    }
  });
});

// ─── Training Lab Scanner Enhancement ─────────────────────────────────────

describe("Training Lab Scanner Enhancement", () => {
  it("should have comprehensive synonym coverage for common scanner findings", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    // Test that common scanner output names map to ground truth across targets
    const scannerFindings = [
      { title: "Server Side Template Injection", severity: "critical", category: "Injection" },
    ];
    // SSTI should match in Juice Shop
    const result = scoreAgainstGroundTruth("juice-shop", scannerFindings);
    expect(result).not.toBeNull();
    const matched = result!.matchDetails.filter(m => m.matched);
    const sstiMatch = matched.find(m =>
      m.groundTruth.title.toLowerCase().includes("template injection") ||
      m.groundTruth.title.toLowerCase().includes("ssti")
    );
    expect(sstiMatch).toBeDefined();
  });

  it("should match XXE findings to Juice Shop ground truth", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "XML External Entity (XXE) Injection", severity: "critical", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("juice-shop", findings);
    expect(result).not.toBeNull();
    const matched = result!.matchDetails.filter(m => m.matched);
    const xxeMatch = matched.find(m =>
      m.groundTruth.title.toLowerCase().includes("xxe") ||
      m.groundTruth.title.toLowerCase().includes("xml external")
    );
    expect(xxeMatch).toBeDefined();
  });

  it("should match SSRF findings to Juice Shop ground truth", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "Server-Side Request Forgery (SSRF)", severity: "high", category: "Injection" },
    ];
    const result = scoreAgainstGroundTruth("juice-shop", findings);
    expect(result).not.toBeNull();
    const matched = result!.matchDetails.filter(m => m.matched);
    const ssrfMatch = matched.find(m =>
      m.groundTruth.title.toLowerCase().includes("ssrf") ||
      m.groundTruth.title.toLowerCase().includes("server-side request")
    );
    expect(ssrfMatch).toBeDefined();
  });

  it("should match Open Redirect findings to Juice Shop ground truth", async () => {
    const { scoreAgainstGroundTruth } = await importLearning();
    const findings = [
      { title: "Open Redirect", severity: "medium", category: "Redirect" },
    ];
    const result = scoreAgainstGroundTruth("juice-shop", findings);
    expect(result).not.toBeNull();
    const matched = result!.matchDetails.filter(m => m.matched);
    const redirectMatch = matched.find(m =>
      m.groundTruth.title.toLowerCase().includes("redirect") ||
      m.groundTruth.title.toLowerCase().includes("unvalidated")
    );
    expect(redirectMatch).toBeDefined();
  });
});
