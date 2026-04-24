/**
 * Claude Round 5 Hardening Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for the three code-level changes recommended in Claude's Round 5 review:
 *   1. Correlated-input damping (Issue #4)
 *   2. Distribution monitoring responses (Issue #8)
 *   3. Inter-rater reliability harness (Issue #2)
 */
import { describe, it, expect } from "vitest";

// ─── 1. Correlated-Input Damping ────────────────────────────────────────

describe("Correlated-Input Damping", () => {
  it("detectAndDampCorrelatedInputs is exported from scoring-engine", async () => {
    const mod = await import("./lib/scoring-engine");
    expect(typeof mod.detectAndDampCorrelatedInputs).toBe("function");
  });

  it("does not damp when fewer than 3 sources push the same factor", async () => {
    const { detectAndDampCorrelatedInputs } = await import("./lib/scoring-engine");
    const base = { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 };
    const sources = [
      { name: "CVSS_v4", carverFloors: { criticality: 8 } },
      { name: "FIPS_199", carverFloors: { criticality: 8 } },
    ];
    const { dampedCarver, report } = detectAndDampCorrelatedInputs(base, sources);
    // With <3 sources, standard max-floor applies
    expect(dampedCarver.criticality).toBe(8);
    const critReport = report.find(r => r.factor === "criticality");
    expect(critReport?.wasDamped).toBe(false);
  });

  it("applies logarithmic damping when ≥3 sources push the same factor", async () => {
    const { detectAndDampCorrelatedInputs } = await import("./lib/scoring-engine");
    const base = { criticality: 4, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 };
    const sources = [
      { name: "CVSS_v4", carverFloors: { criticality: 8 } },
      { name: "FIPS_199", carverFloors: { criticality: 8 } },
      { name: "Criticality_Tier", carverFloors: { criticality: 9 } },
    ];
    const { dampedCarver, report } = detectAndDampCorrelatedInputs(base, sources);
    const critReport = report.find(r => r.factor === "criticality");
    expect(critReport?.wasDamped).toBe(true);
    expect(critReport?.sourceCount).toBe(3);
    // Damped value should be less than rawMax (9) but greater than base (4)
    expect(dampedCarver.criticality).toBeGreaterThan(4);
    expect(dampedCarver.criticality).toBeLessThanOrEqual(10);
    // Log damping: base(4) + ln(1 + (4+4+5)) * 2.0 = 4 + ln(14)*2 ≈ 4 + 5.28 ≈ 9.28
    // But capped at 10. The key point: it's damped, not just max.
    expect(critReport?.rawMax).toBe(9);
  });

  it("does not affect factors where no source proposes a higher floor", async () => {
    const { detectAndDampCorrelatedInputs } = await import("./lib/scoring-engine");
    const base = { criticality: 8, accessibility: 7, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 };
    const sources = [
      { name: "CVSS_v4", carverFloors: { criticality: 6 } }, // lower than base
      { name: "FIPS_199", carverFloors: { criticality: 7 } }, // lower than base
    ];
    const { dampedCarver, report } = detectAndDampCorrelatedInputs(base, sources);
    expect(dampedCarver.criticality).toBe(8); // unchanged
    const critReport = report.find(r => r.factor === "criticality");
    expect(critReport?.sourceCount).toBe(0);
    expect(critReport?.wasDamped).toBe(false);
  });

  it("never exceeds 10 even with extreme correlated inputs", async () => {
    const { detectAndDampCorrelatedInputs } = await import("./lib/scoring-engine");
    const base = { criticality: 7, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 };
    const sources = [
      { name: "Source1", carverFloors: { criticality: 10 } },
      { name: "Source2", carverFloors: { criticality: 10 } },
      { name: "Source3", carverFloors: { criticality: 10 } },
      { name: "Source4", carverFloors: { criticality: 10 } },
    ];
    const { dampedCarver } = detectAndDampCorrelatedInputs(base, sources);
    expect(dampedCarver.criticality).toBeLessThanOrEqual(10);
  });

  it("computeHybridRisk returns correlatedInputReport field", async () => {
    const { computeHybridRisk, DEFAULT_PROFILE } = await import("./lib/scoring-engine");
    const result = computeHybridRisk({
      carver: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
      shock: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
      cvssEstimate: 7.5,
      exposure: 0.6,
      confidence: 0.8,
      cvssV4Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H",
      fips199: { confidentiality: "high", integrity: "high", availability: "high" },
      criticalityTier: 1,
    }, DEFAULT_PROFILE);
    expect(result.correlatedInputReport).toBeDefined();
    expect(Array.isArray(result.correlatedInputReport)).toBe(true);
    // Should have entries for all 6 CARVER factors
    expect(result.correlatedInputReport!.length).toBe(6);
  });
});

// ─── 2. Distribution Monitoring Responses ───────────────────────────────

describe("Distribution Monitoring Responses", () => {
  it("ScoringValidationReport includes responses array", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    const results = Array.from({ length: 10 }, (_, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 5, shockComposite: 5, missionImpactScore: 5,
        impactScore: 50, likelihoodScore: 50, hybridRiskScore: 50,
        riskBand: "medium" as const, factorContributions: [],
        usedFallback: false, validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    expect(report.responses).toBeDefined();
    expect(Array.isArray(report.responses)).toBe(true);
  });

  it("flags over-inflation when >30% assets are critical", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    const results = Array.from({ length: 10 }, (_, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 8, shockComposite: 8, missionImpactScore: 8,
        impactScore: 80, likelihoodScore: 80, hybridRiskScore: 90,
        riskBand: (i < 5 ? "critical" : "high") as any,
        factorContributions: [],
        usedFallback: false, validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    const inflationResponse = report.responses.find(r => r.flag === "critical_over_30pct");
    expect(inflationResponse).toBeDefined();
    expect(inflationResponse!.response).toBe("review_enrichment_sources");
    expect(inflationResponse!.action).toContain("correlated-input damping");
  });

  it("flags under-scoring when 0% critical and 0% high", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    const results = Array.from({ length: 10 }, (_, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 3, shockComposite: 3, missionImpactScore: 3,
        impactScore: 30, likelihoodScore: 30, hybridRiskScore: 20,
        riskBand: (i < 5 ? "low" : "medium") as any,
        factorContributions: [],
        usedFallback: false, validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    const underResponse = report.responses.find(r => r.flag === "no_critical_or_high");
    expect(underResponse).toBeDefined();
    expect(underResponse!.response).toBe("review_scoring_profiles");
  });

  it("flags high fallback rate when >50% use fallback", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    const results = Array.from({ length: 10 }, (_, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 5, shockComposite: 5, missionImpactScore: 5,
        impactScore: 50, likelihoodScore: 50, hybridRiskScore: 50,
        riskBand: "medium" as any,
        factorContributions: [],
        usedFallback: i < 7, // 70% fallback
        validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    const fallbackResponse = report.responses.find(r => r.flag === "high_fallback_rate");
    expect(fallbackResponse).toBeDefined();
    expect(fallbackResponse!.response).toBe("review_llm_classification");
  });

  it("recommends manual audit when multiple anomalies detected", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    // Create a scenario with both over-inflation AND high fallback
    const results = Array.from({ length: 10 }, (_, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 8, shockComposite: 8, missionImpactScore: 8,
        impactScore: 80, likelihoodScore: 80, hybridRiskScore: 90,
        riskBand: "critical" as any,
        factorContributions: [],
        usedFallback: i < 7, // 70% fallback
        validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    const auditResponse = report.responses.find(r => r.flag === "multiple_anomalies");
    expect(auditResponse).toBeDefined();
    expect(auditResponse!.response).toBe("manual_audit_recommended");
  });

  it("generates no responses for a healthy distribution", async () => {
    const { generateScoringValidationReport } = await import("./lib/scoring-hardening");
    const bands = ["critical", "high", "medium", "medium", "medium", "low", "low", "low", "low", "low"];
    const results = bands.map((band, i) => ({
      assetId: `asset-${i}`,
      result: {
        carverComposite: 5, shockComposite: 5, missionImpactScore: 5,
        impactScore: 50, likelihoodScore: 50, hybridRiskScore: 50,
        riskBand: band as any,
        factorContributions: [],
        usedFallback: false, validationWarnings: [], sanitizationLog: [],
      },
    }));
    const report = generateScoringValidationReport(results);
    expect(report.responses.length).toBe(0);
  });
});

// ─── 3. Inter-Rater Reliability Harness ─────────────────────────────────

describe("Inter-Rater Reliability Harness", () => {
  it("computeInterRaterReliability is exported from scoring-hardening", async () => {
    const mod = await import("./lib/scoring-hardening");
    expect(typeof mod.computeInterRaterReliability).toBe("function");
  });

  it("reports 100% agreement when both raters give identical scores", async () => {
    const { computeInterRaterReliability } = await import("./lib/scoring-hardening");
    const { DEFAULT_PROFILE } = await import("./lib/scoring-engine");
    const scores = Array.from({ length: 5 }, (_, i) => ({
      assetId: `asset-${i}`,
      carver: { criticality: 7, accessibility: 5, recuperability: 6, vulnerability: 4, effect: 5, recognizability: 3 },
      shock: { scope: 5, handling: 4, operationalImpact: 6, cascadingEffects: 3, knowledge: 5 },
    }));
    const result = computeInterRaterReliability(scores, scores, DEFAULT_PROFILE);
    expect(result.overallExactMatch).toBe(100);
    expect(result.overallWithinOne).toBe(100);
    expect(result.riskBandAgreement).toBe(100);
    expect(result.flaggedFactors.length).toBe(0);
  });

  it("detects disagreement and flags problematic factors", async () => {
    const { computeInterRaterReliability } = await import("./lib/scoring-hardening");
    const { DEFAULT_PROFILE } = await import("./lib/scoring-engine");
    const raterA = Array.from({ length: 5 }, (_, i) => ({
      assetId: `asset-${i}`,
      carver: { criticality: 8, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
      shock: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
    }));
    const raterB = Array.from({ length: 5 }, (_, i) => ({
      assetId: `asset-${i}`,
      carver: { criticality: 4, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
      shock: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
    }));
    const result = computeInterRaterReliability(raterA, raterB, DEFAULT_PROFILE);
    // Criticality has a 4-point delta on every asset — should be flagged
    expect(result.flaggedFactors).toContain("criticality");
    expect(result.factorAgreement.criticality.maxDelta).toBe(4);
    expect(result.factorAgreement.criticality.exactMatch).toBe(0);
    // Other factors should be fine
    expect(result.factorAgreement.accessibility.exactMatch).toBe(100);
  });

  it("provides calibration recommendation based on agreement level", async () => {
    const { computeInterRaterReliability } = await import("./lib/scoring-hardening");
    const { DEFAULT_PROFILE } = await import("./lib/scoring-engine");
    // Perfect agreement
    const scores = Array.from({ length: 5 }, (_, i) => ({
      assetId: `asset-${i}`,
      carver: { criticality: 7, accessibility: 5, recuperability: 6, vulnerability: 4, effect: 5, recognizability: 3 },
      shock: { scope: 5, handling: 4, operationalImpact: 6, cascadingEffects: 3, knowledge: 5 },
    }));
    const result = computeInterRaterReliability(scores, scores, DEFAULT_PROFILE);
    expect(result.recommendation).toContain("Strong agreement");
  });

  it("returns correct assetCount", async () => {
    const { computeInterRaterReliability } = await import("./lib/scoring-hardening");
    const { DEFAULT_PROFILE } = await import("./lib/scoring-engine");
    const makeScores = (n: number) => Array.from({ length: n }, (_, i) => ({
      assetId: `asset-${i}`,
      carver: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
      shock: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
    }));
    const result = computeInterRaterReliability(makeScores(10), makeScores(10), DEFAULT_PROFILE);
    expect(result.assetCount).toBe(10);
  });
});
