/**
 * Tests for CARVER+Shock Scoring Hardening Layer
 */
import { describe, it, expect } from "vitest";
import {
  sanitizeCarverScores,
  sanitizeShockScores,
  sanitizeScoringInput,
  sanitizeScoringProfile,
  computeHybridRiskHardened,
  classifyAssetDeterministic,
  generateScoringValidationReport,
  DEFAULT_CARVER_SCORES,
  DEFAULT_SHOCK_SCORES,
  DEFAULT_SCORING_PROFILE,
} from "./lib/scoring-hardening";

describe("Input Sanitization", () => {
  it("returns defaults for null/undefined CARVER scores", () => {
    expect(sanitizeCarverScores(null)).toEqual(DEFAULT_CARVER_SCORES);
    expect(sanitizeCarverScores(undefined)).toEqual(DEFAULT_CARVER_SCORES);
    expect(sanitizeCarverScores("not an object")).toEqual(DEFAULT_CARVER_SCORES);
  });

  it("clamps out-of-range CARVER values", () => {
    const result = sanitizeCarverScores({
      criticality: 15,
      accessibility: -3,
      recuperability: NaN,
      vulnerability: Infinity,
      effect: 7,
      recognizability: 5,
    });
    expect(result.criticality).toBe(10);
    expect(result.accessibility).toBe(0);
    expect(result.recuperability).toBe(5); // default
    expect(result.vulnerability).toBe(3); // default (Infinity → default)
    expect(result.effect).toBe(7);
    expect(result.recognizability).toBe(5);
  });

  it("returns defaults for null/undefined Shock scores", () => {
    expect(sanitizeShockScores(null)).toEqual(DEFAULT_SHOCK_SCORES);
    expect(sanitizeShockScores(undefined)).toEqual(DEFAULT_SHOCK_SCORES);
  });

  it("clamps out-of-range Shock values", () => {
    const result = sanitizeShockScores({
      scope: 20,
      handling: -5,
      operationalImpact: NaN,
      cascadingEffects: 8,
      knowledge: undefined,
    });
    expect(result.scope).toBe(10);
    expect(result.handling).toBe(0);
    expect(result.operationalImpact).toBe(3); // default
    expect(result.cascadingEffects).toBe(8);
    expect(result.knowledge).toBe(5); // default
  });

  it("sanitizes full ScoringInput with missing fields", () => {
    const result = sanitizeScoringInput({});
    expect(result.carver).toEqual(DEFAULT_CARVER_SCORES);
    expect(result.shock).toEqual(DEFAULT_SHOCK_SCORES);
    expect(result.cvssEstimate).toBe(0);
    expect(result.exposure).toBe(0.5);
    expect(result.confidence).toBe(0.5);
  });

  it("sanitizes ScoringInput with invalid types", () => {
    const result = sanitizeScoringInput({
      carver: "not an object",
      shock: 42,
      cvssEstimate: "abc",
      exposure: true,
      confidence: null,
    });
    expect(result.carver).toEqual(DEFAULT_CARVER_SCORES);
    expect(result.shock).toEqual(DEFAULT_SHOCK_SCORES);
    expect(result.cvssEstimate).toBe(0);
    // true converts to 1 via Number(), which is a valid exposure value
    expect(result.exposure).toBe(1);
    expect(result.confidence).toBe(0.5);
  });

  it("validates businessImpactLevel enum", () => {
    const valid = sanitizeScoringInput({ businessImpactLevel: "mission_critical" });
    expect(valid.businessImpactLevel).toBe("mission_critical");

    const invalid = sanitizeScoringInput({ businessImpactLevel: "super_critical" });
    expect(invalid.businessImpactLevel).toBeUndefined();
  });

  it("validates FIPS 199 categories", () => {
    const valid = sanitizeScoringInput({
      fips199: { confidentiality: "high", integrity: "moderate", availability: "low" },
    });
    expect(valid.fips199).toBeDefined();

    const invalid = sanitizeScoringInput({
      fips199: { confidentiality: "extreme", integrity: "moderate", availability: "low" },
    });
    expect(invalid.fips199).toBeUndefined();
  });

  it("validates criticality tier range", () => {
    expect(sanitizeScoringInput({ criticalityTier: 1 }).criticalityTier).toBe(1);
    expect(sanitizeScoringInput({ criticalityTier: 5 }).criticalityTier).toBe(5);
    expect(sanitizeScoringInput({ criticalityTier: 0 }).criticalityTier).toBeUndefined();
    expect(sanitizeScoringInput({ criticalityTier: 6 }).criticalityTier).toBeUndefined();
    expect(sanitizeScoringInput({ criticalityTier: NaN }).criticalityTier).toBeUndefined();
  });

  it("sanitizes ScoringProfile with zero weights", () => {
    const result = sanitizeScoringProfile({
      carverWeight: 0,
      shockWeight: 0,
      carverWeights: {},
      shockWeights: {},
    });
    // Should clamp to minimum 0.01
    expect(result.carverWeight).toBeGreaterThan(0);
    expect(result.shockWeight).toBeGreaterThan(0);
  });
});

describe("Hardened Scoring", () => {
  it("produces valid scores for normal input", () => {
    const result = computeHybridRiskHardened(
      {
        carver: { criticality: 7, accessibility: 5, recuperability: 4, vulnerability: 6, effect: 5, recognizability: 3 },
        shock: { scope: 5, handling: 4, operationalImpact: 6, cascadingEffects: 3, knowledge: 4 },
        cvssEstimate: 7.5,
        exposure: 0.7,
        confidence: 0.8,
        confirmedVulnScore: 65,
      },
      DEFAULT_SCORING_PROFILE
    );
    expect(result.hybridRiskScore).toBeGreaterThanOrEqual(0);
    expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
    expect(result.usedFallback).toBe(false);
    expect(result.validationWarnings).toHaveLength(0);
    expect(["critical", "high", "medium", "low"]).toContain(result.riskBand);
  });

  it("handles completely empty input without crashing", () => {
    const result = computeHybridRiskHardened({}, {});
    expect(result.hybridRiskScore).toBeGreaterThanOrEqual(0);
    expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
    expect(result.sanitizationLog.length).toBeGreaterThan(0);
  });

  it("handles null input without crashing", () => {
    const result = computeHybridRiskHardened(null, null);
    expect(result.hybridRiskScore).toBeGreaterThanOrEqual(0);
    expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
  });

  it("handles NaN-filled CARVER scores", () => {
    const result = computeHybridRiskHardened(
      {
        carver: { criticality: NaN, accessibility: NaN, recuperability: NaN, vulnerability: NaN, effect: NaN, recognizability: NaN },
        shock: { scope: NaN, handling: NaN, operationalImpact: NaN, cascadingEffects: NaN, knowledge: NaN },
        cvssEstimate: NaN,
        exposure: NaN,
        confidence: NaN,
      },
      DEFAULT_SCORING_PROFILE
    );
    expect(isNaN(result.hybridRiskScore)).toBe(false);
    expect(result.sanitizationLog.length).toBeGreaterThan(0);
  });

  it("handles division-by-zero in profile weights", () => {
    const result = computeHybridRiskHardened(
      {
        carver: DEFAULT_CARVER_SCORES,
        shock: DEFAULT_SHOCK_SCORES,
        cvssEstimate: 5,
        exposure: 0.5,
        confidence: 0.5,
      },
      { carverWeight: 0, shockWeight: 0, carverWeights: {}, shockWeights: {} }
    );
    expect(isNaN(result.hybridRiskScore)).toBe(false);
    // Zero weights get clamped to 0.01 by sanitizeProfile, so the result should still be valid
    expect(isNaN(result.hybridRiskScore)).toBe(false);
  });

  it("records sanitization log for corrected inputs", () => {
    const result = computeHybridRiskHardened(
      {
        carver: { criticality: 15, accessibility: -3 },
        shock: { scope: 20 },
        cvssEstimate: 5,
        exposure: 0.5,
        confidence: 0.5,
      },
      DEFAULT_SCORING_PROFILE
    );
    expect(result.sanitizationLog.some(l => l.includes("CARVER.criticality"))).toBe(true);
    expect(result.sanitizationLog.some(l => l.includes("CARVER.accessibility"))).toBe(true);
    expect(result.sanitizationLog.some(l => l.includes("Shock.scope"))).toBe(true);
  });
});

describe("Deterministic Fallback Classification", () => {
  it("classifies database servers", () => {
    const result = classifyAssetDeterministic({
      hostname: "db-primary.example.com",
      assetType: "server",
      technologies: [{ name: "PostgreSQL" }],
    });
    expect(result.deviceType).toBe("database_server");
    expect(result.businessImpactLevel).toBe("business_essential");
    expect(result.criticalityTier).toBe(2);
  });

  it("classifies authentication systems", () => {
    const result = classifyAssetDeterministic({
      hostname: "sso.example.com",
      assetType: "server",
      technologies: [{ name: "Keycloak" }],
    });
    expect(result.deviceType).toBe("identity_provider");
    expect(result.businessImpactLevel).toBe("mission_critical");
    expect(result.criticalityTier).toBe(1);
  });

  it("classifies CDN nodes as low priority", () => {
    const result = classifyAssetDeterministic({
      hostname: "cdn.example.com",
      assetType: "server",
      technologies: [{ name: "CloudFront" }],
    });
    expect(result.deviceType).toBe("cdn_node");
    expect(result.businessImpactLevel).toBe("administrative");
    expect(result.criticalityTier).toBe(4);
  });

  it("classifies payment systems as mission critical", () => {
    const result = classifyAssetDeterministic({
      hostname: "checkout.example.com",
      assetType: "server",
      technologies: [{ name: "Stripe" }],
    });
    expect(result.deviceType).toBe("payment_processor");
    expect(result.businessImpactLevel).toBe("mission_critical");
    expect(result.criticalityTier).toBe(1);
  });

  it("handles unknown assets gracefully", () => {
    const result = classifyAssetDeterministic({
      hostname: "mystery-box.example.com",
      assetType: "unknown",
    });
    expect(result.deviceType).toBe("unknown");
    expect(result.classificationConfidence).toBe(0.4);
    expect(result.reasoning).toContain("Deterministic fallback");
  });
});

describe("Scoring Validation Report", () => {
  it("generates accurate report for mixed results", () => {
    const results = [
      {
        assetId: "a1",
        result: {
          hybridRiskScore: 85,
          riskBand: "critical" as const,
          usedFallback: false,
          validationWarnings: [],
          sanitizationLog: [],
          carverComposite: 7,
          shockComposite: 6,
          missionImpactScore: 7,
          impactScore: 70,
          likelihoodScore: 80,
          factorContributions: [],
        },
      },
      {
        assetId: "a2",
        result: {
          hybridRiskScore: 45,
          riskBand: "medium" as const,
          usedFallback: true,
          validationWarnings: ["NaN detected"],
          sanitizationLog: ["CARVER.criticality: NaN → 3"],
          carverComposite: 4,
          shockComposite: 3,
          missionImpactScore: 4,
          impactScore: 40,
          likelihoodScore: 50,
          factorContributions: [],
        },
      },
      {
        assetId: "a3",
        result: {
          hybridRiskScore: 20,
          riskBand: "low" as const,
          usedFallback: false,
          validationWarnings: [],
          sanitizationLog: [],
          carverComposite: 2,
          shockComposite: 2,
          missionImpactScore: 2,
          impactScore: 20,
          likelihoodScore: 20,
          factorContributions: [],
        },
      },
    ];

    const report = generateScoringValidationReport(results);
    expect(report.totalAssets).toBe(3);
    expect(report.scoredAssets).toBe(3);
    expect(report.fallbackAssets).toBe(1);
    expect(report.nanDetected).toBe(1);
    expect(report.correctedInputs).toBe(1);
    expect(report.riskDistribution.critical).toBe(1);
    expect(report.riskDistribution.medium).toBe(1);
    expect(report.riskDistribution.low).toBe(1);
  });
});
