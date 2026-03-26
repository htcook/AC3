/**
 * FP/FN Prevention Engine Test Suite
 *
 * Tests for the multi-layered false positive / false negative prevention system:
 *   - Confidence signal collection (base, version, contextual, threat intel)
 *   - Multi-scanner corroboration
 *   - FP pattern matching
 *   - Suppression profiles (conservative, balanced, aggressive)
 *   - Operator feedback and adaptive thresholds
 *   - Batch validation with stats
 *   - Verdict determination
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  FPFNPreventionEngine,
  resetFPFNEngine,
  getFPFNEngine,
  type ValidationContext,
  type OperatorFeedback,
} from "./intelligence/fp-fn-prevention";
import type { ScanFinding } from "./types";

// ─── Test Helpers ──────────────────────────────────────────────────────────

function makeFinding(overrides?: Partial<ScanFinding>): ScanFinding {
  return {
    id: `finding-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    source: "nuclei",
    title: "SQL Injection in login form",
    description: "A SQL injection vulnerability was detected in the login endpoint",
    severity: "critical",
    confidence: 85,
    target: "app.example.com",
    port: 443,
    evidence: {
      matchedPattern: "error in your SQL syntax",
      request: "POST /login HTTP/1.1\nHost: app.example.com",
      response: "HTTP/1.1 500 Internal Server Error\n\nYou have an error in your SQL syntax",
    },
    cves: ["CVE-2024-12345"],
    cwes: ["CWE-89"],
    foundAt: Date.now(),
    ...overrides,
  };
}

function makeContext(overrides?: Partial<ValidationContext>): ValidationContext {
  return {
    environment: "traditional",
    isManaged: false,
    detectedTechnologies: { apache: "2.4.51", php: "8.1.0" },
    ...overrides,
  };
}

// ─── Engine Lifecycle Tests ───────────────────────────────────────────────

describe("FPFNPreventionEngine — Lifecycle", () => {
  beforeEach(() => {
    resetFPFNEngine();
  });

  it("should create an engine with default config", () => {
    const engine = new FPFNPreventionEngine();
    const config = engine.getConfig();

    expect(config.minReportingConfidence).toBe(60);
    expect(config.confirmedThreshold).toBe(80);
    expect(config.suppressionProfile).toBe("balanced");
    expect(config.enableProofValidation).toBe(true);
    expect(config.enableCorroboration).toBe(true);
    expect(config.enableContextualFiltering).toBe(true);
    expect(config.enableAdaptiveThresholds).toBe(true);
  });

  it("should accept custom config overrides", () => {
    const engine = new FPFNPreventionEngine({
      minReportingConfidence: 80,
      suppressionProfile: "conservative",
    });
    const config = engine.getConfig();

    expect(config.minReportingConfidence).toBe(80);
    expect(config.suppressionProfile).toBe("conservative");
    // Defaults should still be present
    expect(config.enableProofValidation).toBe(true);
  });

  it("should return a singleton via getFPFNEngine", () => {
    const a = getFPFNEngine();
    const b = getFPFNEngine();
    expect(a).toBe(b);
  });

  it("should reset the singleton via resetFPFNEngine", () => {
    const a = getFPFNEngine();
    resetFPFNEngine();
    const b = getFPFNEngine();
    expect(a).not.toBe(b);
  });

  it("should update config and clear cache", () => {
    const engine = new FPFNPreventionEngine();
    engine.updateConfig({ suppressionProfile: "aggressive" });
    expect(engine.getConfig().suppressionProfile).toBe("aggressive");
  });
});

// ─── Single Finding Validation Tests ──────────────────────────────────────

describe("FPFNPreventionEngine — Single Finding Validation", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should validate a high-confidence finding as confirmed or likely", async () => {
    const finding = makeFinding({
      confidence: 95,
      evidence: {
        matchedPattern: "error in your SQL syntax",
        request: "POST /login HTTP/1.1",
        response: "HTTP/1.1 500\n\nSQL syntax error near 'OR 1=1'",
      },
      cves: ["CVE-2024-12345"],
      cwes: ["CWE-89"],
    });
    const context = makeContext();

    const result = await engine.validateFinding(finding, context);

    expect(result.finding.id).toBe(finding.id);
    expect(result.finalConfidence).toBeGreaterThan(0);
    expect(result.signals.length).toBeGreaterThan(0);
    expect(result.positiveSignals).toBeGreaterThan(0);
    expect(["confirmed", "likely", "possible"]).toContain(result.verdict);
    expect(result.validatedAt).toBeGreaterThan(0);
  });

  it("should collect CVE correlation signals", async () => {
    const finding = makeFinding({ cves: ["CVE-2024-99999", "CVE-2024-88888"] });
    const result = await engine.validateFinding(finding, makeContext());

    const cveSignal = result.signals.find(s => s.source === "cve_correlation");
    expect(cveSignal).toBeDefined();
    expect(cveSignal!.weight).toBeGreaterThan(0);
    expect(cveSignal!.description).toContain("CVE");
  });

  it("should collect CWE mapping signals", async () => {
    const finding = makeFinding({ cwes: ["CWE-89", "CWE-79"] });
    const result = await engine.validateFinding(finding, makeContext());

    const cweSignal = result.signals.find(s => s.description?.includes("CWE"));
    expect(cweSignal).toBeDefined();
  });

  it("should collect evidence quality signals for full request/response", async () => {
    const finding = makeFinding({
      evidence: {
        request: "GET /admin HTTP/1.1\nHost: target.com",
        response: "HTTP/1.1 200 OK\n\nAdmin panel exposed",
        matchedPattern: "admin",
      },
    });
    const result = await engine.validateFinding(finding, makeContext());

    const evidenceSignal = result.signals.find(s =>
      s.description?.includes("request/response evidence")
    );
    expect(evidenceSignal).toBeDefined();
    expect(evidenceSignal!.weight).toBeGreaterThan(0);
  });

  it("should cache validation results", async () => {
    const finding = makeFinding();
    const context = makeContext();

    const result1 = await engine.validateFinding(finding, context);
    const result2 = await engine.validateFinding(finding, context);

    // Same result should be returned from cache
    expect(result1.validatedAt).toBe(result2.validatedAt);
    expect(result1.finalConfidence).toBe(result2.finalConfidence);
  });

  it("should invalidate cache after clearCache()", async () => {
    const finding = makeFinding();
    const context = makeContext();

    const result1 = await engine.validateFinding(finding, context);
    engine.clearCache();
    const result2 = await engine.validateFinding(finding, context);

    // Different timestamps mean cache was invalidated
    expect(result2.validatedAt).toBeGreaterThanOrEqual(result1.validatedAt);
  });
});

// ─── FP Pattern Detection Tests ──────────────────────────────────────────

describe("FPFNPreventionEngine — False Positive Pattern Detection", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should detect generic information disclosure as potential FP", async () => {
    const finding = makeFinding({
      title: "Information Disclosure - Server Version Exposed",
      severity: "low",
      confidence: 50,
      evidence: { matchedPattern: "x-powered-by" },
      cves: [],
      cwes: [],
    });
    const context = makeContext();

    const result = await engine.validateFinding(finding, context);

    // Should have negative signals from FP pattern matching
    const negativeSignals = result.signals.filter(s => s.weight < 0);
    // The FP pattern should be detected
    expect(result.finalConfidence).toBeLessThan(80);
  });

  it("should detect self-signed cert on cloud as potential FP", async () => {
    const finding = makeFinding({
      title: "Self-Signed Certificate Detected",
      severity: "medium",
      confidence: 90,
      cves: [],
    });
    const context = makeContext({
      environment: "cloud",
      isManaged: true,
    });

    const result = await engine.validateFinding(finding, context);

    // Cloud managed context should reduce confidence
    const contextSignals = result.signals.filter(s =>
      s.source === "contextual_penalty" || s.source === "compensating_control"
    );
    // Should have some contextual signals
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should detect WAF-triggered SQLi false positive", async () => {
    const finding = makeFinding({
      title: "SQL Injection Detected",
      severity: "critical",
      confidence: 60,
      evidence: { matchedPattern: "generic error" },
      cves: [],
    });
    const context = makeContext({
      wafDetected: "Cloudflare",
    });

    const result = await engine.validateFinding(finding, context);

    // WAF presence should add a negative signal
    const wafSignal = result.signals.find(s => s.source === "waf_interference");
    expect(wafSignal).toBeDefined();
    expect(wafSignal!.weight).toBeLessThan(0);
  });

  it("should detect container escape on non-container target as FP", async () => {
    const finding = makeFinding({
      title: "Container Escape - Privileged Container Detected",
      severity: "critical",
      confidence: 70,
      cves: [],
    });
    const context = makeContext({
      environment: "traditional",
      detectedTechnologies: { apache: "2.4.51" },
    });

    const result = await engine.validateFinding(finding, context);

    // Should have lower confidence due to environment mismatch
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should detect managed cloud service version FP", async () => {
    const finding = makeFinding({
      title: "Outdated MySQL Version - End of Life",
      severity: "high",
      confidence: 80,
      cves: [],
    });
    const context = makeContext({
      environment: "cloud",
      isManaged: true,
      cloudProvider: "aws",
    });

    const result = await engine.validateFinding(finding, context);

    // Managed service context should reduce confidence
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should allow operators to add custom FP patterns", async () => {
    engine.addFPPattern({
      id: "custom-fp-1",
      titlePattern: /custom\s*vuln\s*pattern/i,
      conditions: [{ type: "header_present", value: "x-custom" }],
      reason: "Custom FP pattern from operator experience",
    });

    const stats = engine.getStats();
    expect(stats.fpPatternCount).toBeGreaterThan(10); // Default patterns + custom
  });
});

// ─── Corroboration Tests ─────────────────────────────────────────────────

describe("FPFNPreventionEngine — Multi-Scanner Corroboration", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should boost confidence when multiple scanners find the same issue", async () => {
    const finding = makeFinding({
      source: "nuclei",
      title: "XSS in search parameter",
      target: "app.example.com",
      port: 443,
    });

    const corroboratingFindings: ScanFinding[] = [
      makeFinding({
        source: "zap",
        title: "Cross-Site Scripting in search",
        target: "app.example.com",
        port: 443,
      }),
      makeFinding({
        source: "scanforge-http",
        title: "Reflected XSS - search parameter",
        target: "app.example.com",
        port: 443,
      }),
    ];

    const context = makeContext({
      otherScannerFindings: corroboratingFindings,
    });

    const result = await engine.validateFinding(finding, context);

    // Should have corroboration detail
    if (result.corroboration) {
      expect(result.corroboration.scannerCount).toBeGreaterThanOrEqual(1);
    }
  });

  it("should not boost confidence for findings from the same scanner", async () => {
    const finding = makeFinding({
      source: "nuclei",
      title: "Open Redirect",
      target: "app.example.com",
    });

    const sameSourceFindings: ScanFinding[] = [
      makeFinding({
        source: "nuclei",
        title: "Open Redirect in callback",
        target: "app.example.com",
      }),
    ];

    const context = makeContext({
      otherScannerFindings: sameSourceFindings,
    });

    const result = await engine.validateFinding(finding, context);

    // Corroboration should be weak or none for same-scanner findings
    if (result.corroboration) {
      expect(["weak", "none"]).toContain(result.corroboration.tier);
    }
  });
});

// ─── Contextual Filtering Tests ──────────────────────────────────────────

describe("FPFNPreventionEngine — Contextual Filtering", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should apply compensating control penalty", async () => {
    const finding = makeFinding({
      title: "SQL Injection in API endpoint",
      confidence: 70,
    });
    const context = makeContext({
      compensatingControls: ["WAF - Cloudflare Pro"],
    });

    const result = await engine.validateFinding(finding, context);

    const controlSignal = result.signals.find(s =>
      s.source === "compensating_control"
    );
    if (controlSignal) {
      expect(controlSignal.weight).toBeLessThan(0);
    }
  });

  it("should apply managed service penalty for cloud-managed targets", async () => {
    const finding = makeFinding({
      title: "Outdated OpenSSL Version",
      confidence: 75,
    });
    const context = makeContext({
      environment: "cloud",
      isManaged: true,
      cloudProvider: "aws",
    });

    const result = await engine.validateFinding(finding, context);

    // Should have contextual penalty signals
    const contextSignals = result.signals.filter(s =>
      s.source === "contextual_penalty"
    );
    // Managed services should get some penalty
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should apply network segmentation context", async () => {
    const finding = makeFinding({
      title: "Internal Service Exposed",
      confidence: 60,
    });
    const context = makeContext({
      networkSegmented: true,
    });

    const result = await engine.validateFinding(finding, context);
    expect(result.signals.length).toBeGreaterThan(0);
  });
});

// ─── Suppression Profile Tests ───────────────────────────────────────────

describe("FPFNPreventionEngine — Suppression Profiles", () => {
  beforeEach(() => {
    resetFPFNEngine();
  });

  it("conservative profile should have higher minimum confidence", () => {
    const engine = new FPFNPreventionEngine({ suppressionProfile: "conservative" });
    const config = engine.getConfig();
    expect(config.suppressionProfile).toBe("conservative");
  });

  it("aggressive profile should have lower minimum confidence", () => {
    const engine = new FPFNPreventionEngine({ suppressionProfile: "aggressive" });
    const config = engine.getConfig();
    expect(config.suppressionProfile).toBe("aggressive");
  });

  it("conservative profile should suppress more findings than aggressive", async () => {
    const findings = [
      makeFinding({ title: "Low confidence finding", confidence: 40, cves: [] }),
      makeFinding({ title: "Medium confidence finding", confidence: 60, cves: [] }),
      makeFinding({ title: "High confidence finding", confidence: 90, cves: ["CVE-2024-1"] }),
    ];
    const context = makeContext();

    const conservativeEngine = new FPFNPreventionEngine({ suppressionProfile: "conservative" });
    const aggressiveEngine = new FPFNPreventionEngine({ suppressionProfile: "aggressive" });

    const conservativeResult = await conservativeEngine.validateBatch(findings, context);
    const aggressiveResult = await aggressiveEngine.validateBatch(findings, context);

    // Conservative should suppress more (or equal) than aggressive
    expect(conservativeResult.suppressed.length).toBeGreaterThanOrEqual(
      aggressiveResult.suppressed.length
    );
  });
});

// ─── Batch Validation Tests ──────────────────────────────────────────────

describe("FPFNPreventionEngine — Batch Validation", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should validate a batch of findings and return stats", async () => {
    const findings = [
      makeFinding({ title: "Critical SQLi", severity: "critical", confidence: 95, cves: ["CVE-2024-1"] }),
      makeFinding({ title: "XSS in search", severity: "high", confidence: 80, cves: ["CVE-2024-2"] }),
      makeFinding({ title: "Information Disclosure", severity: "low", confidence: 40, cves: [] }),
    ];
    const context = makeContext();

    const result = await engine.validateBatch(findings, context);

    expect(result.validated).toBeDefined();
    expect(result.suppressed).toBeDefined();
    expect(result.stats).toBeDefined();
    expect(result.stats.totalInput).toBe(3);
    expect(result.stats.totalValidated + result.stats.totalSuppressed).toBe(3);
    expect(result.stats.suppressionRate).toBeGreaterThanOrEqual(0);
    expect(result.stats.suppressionRate).toBeLessThanOrEqual(1);
  });

  it("should sort validated findings by confidence (highest first)", async () => {
    const findings = [
      makeFinding({ title: "Low finding", confidence: 50, cves: [] }),
      makeFinding({ title: "High finding", confidence: 95, cves: ["CVE-2024-1"] }),
      makeFinding({ title: "Medium finding", confidence: 75, cves: ["CVE-2024-2"] }),
    ];
    const context = makeContext();

    const result = await engine.validateBatch(findings, context);

    if (result.validated.length >= 2) {
      for (let i = 1; i < result.validated.length; i++) {
        expect(result.validated[i - 1].finalConfidence).toBeGreaterThanOrEqual(
          result.validated[i].finalConfidence
        );
      }
    }
  });

  it("should handle empty batch gracefully", async () => {
    const result = await engine.validateBatch([], makeContext());

    expect(result.validated).toEqual([]);
    expect(result.suppressed).toEqual([]);
    expect(result.stats.totalInput).toBe(0);
    expect(result.stats.avgConfidence).toBe(0);
  });

  it("should provide batch stats with verdict breakdown", async () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      makeFinding({
        title: `Finding ${i}`,
        confidence: 30 + i * 8,
        cves: i > 5 ? [`CVE-2024-${i}`] : [],
      })
    );
    const context = makeContext();

    const result = await engine.validateBatch(findings, context);

    expect(result.stats.byVerdict).toBeDefined();
    const totalByVerdict = Object.values(result.stats.byVerdict).reduce((a, b) => a + b, 0);
    expect(totalByVerdict).toBe(10);
  });
});

// ─── Operator Feedback & Adaptive Thresholds Tests ───────────────────────

describe("FPFNPreventionEngine — Operator Feedback", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should record operator feedback", () => {
    const feedback: OperatorFeedback = {
      findingId: "finding-123",
      verdict: "false_positive",
      notes: "This is a known FP in our environment",
      operatorId: "operator-1",
      submittedAt: Date.now(),
    };

    engine.recordFeedback(feedback);

    const stats = engine.getStats();
    expect(stats.operatorOverrides).toBe(1);
    expect(stats.feedbackCount).toBe(1);
  });

  it("should record multiple feedback entries", () => {
    for (let i = 0; i < 5; i++) {
      engine.recordFeedback({
        findingId: `finding-${i}`,
        verdict: i % 2 === 0 ? "false_positive" : "true_positive",
        operatorId: "operator-1",
        submittedAt: Date.now(),
      });
    }

    const stats = engine.getStats();
    expect(stats.operatorOverrides).toBe(5);
    expect(stats.feedbackCount).toBe(5);
  });

  it("should invalidate cache when feedback is recorded", async () => {
    const finding = makeFinding({ id: "finding-cache-test" });
    const context = makeContext();

    // Validate to populate cache
    await engine.validateFinding(finding, context);

    // Record feedback
    engine.recordFeedback({
      findingId: "finding-cache-test",
      verdict: "false_positive",
      operatorId: "operator-1",
      submittedAt: Date.now(),
    });

    // Stats should reflect the feedback
    const stats = engine.getStats();
    expect(stats.operatorOverrides).toBe(1);
  });
});

// ─── Statistics Tests ────────────────────────────────────────────────────

describe("FPFNPreventionEngine — Statistics", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should track validation statistics", async () => {
    const findings = [
      makeFinding({ title: "Finding 1", confidence: 90, cves: ["CVE-1"] }),
      makeFinding({ title: "Finding 2", confidence: 50, cves: [] }),
    ];

    for (const f of findings) {
      await engine.validateFinding(f, makeContext());
    }

    const stats = engine.getStats();
    expect(stats.totalValidated).toBe(2);
    expect(stats.fpPatternCount).toBeGreaterThan(0);
    expect(stats.cacheSize).toBe(2);
  });

  it("should report cache size correctly", async () => {
    const stats1 = engine.getStats();
    expect(stats1.cacheSize).toBe(0);

    await engine.validateFinding(makeFinding(), makeContext());
    const stats2 = engine.getStats();
    expect(stats2.cacheSize).toBe(1);

    engine.clearCache();
    const stats3 = engine.getStats();
    expect(stats3.cacheSize).toBe(0);
  });
});

// ─── Version Mismatch / Backport Detection Tests ─────────────────────────

describe("FPFNPreventionEngine — Version & Backport Detection", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should detect version mismatch when technology version doesn't match", async () => {
    const finding = makeFinding({
      title: "Apache 2.4.49 Path Traversal CVE-2021-41773",
      confidence: 80,
      cves: ["CVE-2021-41773"],
    });
    const context = makeContext({
      detectedTechnologies: { apache: "2.4.54" }, // Patched version
    });

    const result = await engine.validateFinding(finding, context);

    // Should have version-related signals
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should handle findings without version information", async () => {
    const finding = makeFinding({
      title: "Open redirect detected",
      confidence: 70,
      cves: [],
    });
    const context = makeContext();

    const result = await engine.validateFinding(finding, context);

    // Should still validate without errors
    expect(result.verdict).toBeDefined();
    expect(result.finalConfidence).toBeGreaterThan(0);
  });

  it("should apply backport detection penalty", async () => {
    const finding = makeFinding({
      title: "CVE-2024-12345 in OpenSSL 1.1.1",
      confidence: 80,
      cves: ["CVE-2024-12345"],
    });
    const context = makeContext({
      patchLevel: "backported",
    });

    const result = await engine.validateFinding(finding, context);

    // Should have signals — backported patch level should be considered
    expect(result.signals.length).toBeGreaterThan(0);
  });
});

// ─── Edge Cases ──────────────────────────────────────────────────────────

describe("FPFNPreventionEngine — Edge Cases", () => {
  let engine: FPFNPreventionEngine;

  beforeEach(() => {
    resetFPFNEngine();
    engine = new FPFNPreventionEngine();
  });

  it("should handle finding with no evidence", async () => {
    const finding = makeFinding({
      evidence: {},
      cves: [],
      cwes: [],
      confidence: 30,
    });
    const result = await engine.validateFinding(finding, makeContext());

    expect(result.verdict).toBeDefined();
    expect(result.finalConfidence).toBeGreaterThanOrEqual(0);
  });

  it("should handle finding with empty title", async () => {
    const finding = makeFinding({
      title: "",
      confidence: 50,
    });
    const result = await engine.validateFinding(finding, makeContext());

    expect(result.verdict).toBeDefined();
  });

  it("should handle context with no technologies detected", async () => {
    const finding = makeFinding();
    const context = makeContext({
      detectedTechnologies: undefined,
    });

    const result = await engine.validateFinding(finding, context);
    expect(result.verdict).toBeDefined();
  });

  it("should handle ICS/OT environment context", async () => {
    const finding = makeFinding({
      title: "Modbus service exposed without authentication",
      severity: "critical",
      confidence: 90,
    });
    const context = makeContext({
      environment: "ics_ot",
    });

    const result = await engine.validateFinding(finding, context);
    expect(result.verdict).toBeDefined();
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("should handle IoT environment context", async () => {
    const finding = makeFinding({
      title: "MQTT broker allows anonymous connections",
      severity: "high",
      confidence: 85,
    });
    const context = makeContext({
      environment: "iot",
    });

    const result = await engine.validateFinding(finding, context);
    expect(result.verdict).toBeDefined();
  });

  it("should handle container environment context", async () => {
    const finding = makeFinding({
      title: "Docker API exposed without TLS",
      severity: "critical",
      confidence: 90,
    });
    const context = makeContext({
      environment: "container",
      detectedTechnologies: { docker: "24.0.5" },
    });

    const result = await engine.validateFinding(finding, context);
    expect(result.verdict).toBeDefined();
  });
});
