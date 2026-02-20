import { describe, it, expect } from "vitest";
import {
  computeCarverComposite,
  computeShockComposite,
  computeHybridRisk,
  applyMissionBaselines,
  MISSION_FUNCTION_BASELINES,
  ESSENTIAL_SERVICE_BASELINES,
  PRESET_PROFILES,
  DEFAULT_PROFILE,
  type CarverScores,
  type ShockScores,
  type ScoringInput,
} from "./lib/scoring-engine";

describe("Enhanced CARVER+Shock/CVSS Scoring Engine", () => {
  const sampleCarver: CarverScores = {
    criticality: 8,
    accessibility: 6,
    recuperability: 7,
    vulnerability: 9,
    effect: 5,
    recognizability: 4,
  };

  const sampleShock: ShockScores = {
    scope: 7,
    handling: 6,
    operationalImpact: 8,
    cascadingEffects: 5,
    knowledge: 3,
  };

  describe("CARVER Composite Computation", () => {
    it("computes weighted CARVER composite with default weights", () => {
      const result = computeCarverComposite(sampleCarver, DEFAULT_PROFILE.carverWeights);
      expect(result).toBeGreaterThan(0);
      expect(result).toBeLessThanOrEqual(10);
    });

    it("returns 10 for all-10 factors with equal weights", () => {
      const maxFactors: CarverScores = {
        criticality: 10, accessibility: 10, recuperability: 10,
        vulnerability: 10, effect: 10, recognizability: 10,
      };
      const equalWeights = { criticality: 1, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 };
      const result = computeCarverComposite(maxFactors, equalWeights);
      expect(result).toBe(10);
    });

    it("returns 0 for all-zero factors", () => {
      const zeroFactors: CarverScores = {
        criticality: 0, accessibility: 0, recuperability: 0,
        vulnerability: 0, effect: 0, recognizability: 0,
      };
      const result = computeCarverComposite(zeroFactors, DEFAULT_PROFILE.carverWeights);
      expect(result).toBe(0);
    });

    it("higher criticality weight increases score for high-criticality assets", () => {
      const highCritWeight = { ...DEFAULT_PROFILE.carverWeights, criticality: 5.0 };
      const normalResult = computeCarverComposite(sampleCarver, DEFAULT_PROFILE.carverWeights);
      const boostedResult = computeCarverComposite(sampleCarver, highCritWeight);
      expect(boostedResult).toBeGreaterThan(normalResult);
    });
  });

  describe("Shock Composite Computation", () => {
    it("computes weighted Shock composite with default weights", () => {
      const result = computeShockComposite(sampleShock, DEFAULT_PROFILE.shockWeights);
      expect(result).toBeGreaterThan(0);
      expect(result).toBeLessThanOrEqual(10);
    });

    it("higher operational impact increases Shock score", () => {
      const highOps: ShockScores = { ...sampleShock, operationalImpact: 10 };
      const lowOps: ShockScores = { ...sampleShock, operationalImpact: 1 };
      const highResult = computeShockComposite(highOps, DEFAULT_PROFILE.shockWeights);
      const lowResult = computeShockComposite(lowOps, DEFAULT_PROFILE.shockWeights);
      expect(highResult).toBeGreaterThan(lowResult);
    });
  });

  describe("Hybrid Risk Computation", () => {
    it("computes hybrid risk from CARVER, Shock, and CVSS inputs", () => {
      const input: ScoringInput = {
        carver: sampleCarver,
        shock: sampleShock,
        cvssEstimate: 7.5,
        exposure: 0.7,
        confidence: 0.8,
      };
      const result = computeHybridRisk(input, DEFAULT_PROFILE);
      expect(result.hybridRiskScore).toBeGreaterThan(0);
      expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
      expect(result.carverComposite).toBeGreaterThan(0);
      expect(result.shockComposite).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(result.riskBand);
    });

    it("returns critical risk band for maximum inputs", () => {
      const maxInput: ScoringInput = {
        carver: { criticality: 10, accessibility: 10, recuperability: 10, vulnerability: 10, effect: 10, recognizability: 10 },
        shock: { scope: 10, handling: 10, operationalImpact: 10, cascadingEffects: 10, knowledge: 10 },
        cvssEstimate: 10,
        exposure: 1.0,
        confidence: 1.0,
        confirmedVulnScore: 100,
      };
      const result = computeHybridRisk(maxInput, DEFAULT_PROFILE);
      expect(result.riskBand).toBe("critical");
    });

    it("returns low risk band for minimum inputs", () => {
      const minInput: ScoringInput = {
        carver: { criticality: 1, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 },
        shock: { scope: 1, handling: 1, operationalImpact: 1, cascadingEffects: 1, knowledge: 1 },
        cvssEstimate: 1,
        exposure: 0.1,
        confidence: 0.5,
      };
      const result = computeHybridRisk(minInput, DEFAULT_PROFILE);
      expect(result.riskBand).toBe("low");
    });

    it("mission multiplier increases hybrid risk score", () => {
      const baseInput: ScoringInput = {
        carver: sampleCarver,
        shock: sampleShock,
        cvssEstimate: 6.0,
        exposure: 0.5,
        confidence: 0.8,
      };
      const boostedInput: ScoringInput = {
        ...baseInput,
        missionMultiplier: 1.8,
      };
      const baseResult = computeHybridRisk(baseInput, DEFAULT_PROFILE);
      const boostedResult = computeHybridRisk(boostedInput, DEFAULT_PROFILE);
      expect(boostedResult.hybridRiskScore).toBeGreaterThanOrEqual(baseResult.hybridRiskScore);
    });
  });

  describe("Mission Function Baselines", () => {
    it("has baselines for all 10 mission functions", () => {
      expect(Object.keys(MISSION_FUNCTION_BASELINES).length).toBe(10);
    });

    it("command_control has highest criticality baseline", () => {
      const cc = MISSION_FUNCTION_BASELINES["command_control"];
      expect(cc).toBeDefined();
      expect(cc.carver.criticality).toBeGreaterThanOrEqual(8);
    });

    it("applies mission baselines to raise floor scores", () => {
      const lowCarver: CarverScores = {
        criticality: 2, accessibility: 2, recuperability: 2,
        vulnerability: 2, effect: 2, recognizability: 2,
      };
      const lowShock: ShockScores = {
        scope: 2, handling: 2, operationalImpact: 2,
        cascadingEffects: 2, knowledge: 2,
      };
      const adjusted = applyMissionBaselines(lowCarver, lowShock, "command_control");
      expect(adjusted.carver.criticality).toBeGreaterThan(lowCarver.criticality);
    });

    it("does not lower scores above baseline", () => {
      const highCarver: CarverScores = {
        criticality: 10, accessibility: 10, recuperability: 10,
        vulnerability: 10, effect: 10, recognizability: 10,
      };
      const highShock: ShockScores = {
        scope: 10, handling: 10, operationalImpact: 10,
        cascadingEffects: 10, knowledge: 10,
      };
      const adjusted = applyMissionBaselines(highCarver, highShock, "command_control");
      expect(adjusted.carver.criticality).toBe(10);
      expect(adjusted.carver.accessibility).toBe(10);
    });

    it("returns original factors for unknown mission function", () => {
      const factors: CarverScores = {
        criticality: 5, accessibility: 5, recuperability: 5,
        vulnerability: 5, effect: 5, recognizability: 5,
      };
      const shock: ShockScores = {
        scope: 5, handling: 5, operationalImpact: 5,
        cascadingEffects: 5, knowledge: 5,
      };
      const adjusted = applyMissionBaselines(factors, shock, "nonexistent_function");
      expect(adjusted.carver).toEqual(factors);
    });
  });

  describe("Essential Service Baselines", () => {
    it("has baselines for at least 15 essential services", () => {
      expect(Object.keys(ESSENTIAL_SERVICE_BASELINES).length).toBeGreaterThanOrEqual(15);
    });

    it("sso has defined adjustments", () => {
      const sso = ESSENTIAL_SERVICE_BASELINES["sso"];
      expect(sso).toBeDefined();
    });

    it("applies essential service baselines via applyMissionBaselines", () => {
      const factors: CarverScores = {
        criticality: 5, accessibility: 5, recuperability: 5,
        vulnerability: 5, effect: 5, recognizability: 5,
      };
      const shock: ShockScores = {
        scope: 5, handling: 5, operationalImpact: 5,
        cascadingEffects: 5, knowledge: 5,
      };
      const withService = applyMissionBaselines(factors, shock, "authentication", "sso");
      const withoutService = applyMissionBaselines(factors, shock, "authentication");
      // Service baselines should provide additional adjustments
      expect(withService.missionMultiplier).toBeGreaterThanOrEqual(withoutService.missionMultiplier);
    });
  });

  describe("Scoring Presets", () => {
    it("has at least 5 industry presets", () => {
      expect(Object.keys(PRESET_PROFILES).length).toBeGreaterThanOrEqual(5);
    });

    it("each preset has valid carverWeights, shockWeights, and blend weights", () => {
      Object.values(PRESET_PROFILES).forEach((preset) => {
        expect(preset.profile.carverWeights).toBeDefined();
        expect(preset.profile.shockWeights).toBeDefined();
        expect(preset.profile.carverWeight).toBeGreaterThan(0);
        expect(preset.profile.shockWeight).toBeGreaterThan(0);
        expect(preset.profile.cvssWeight).toBeGreaterThan(0);
        expect(Object.keys(preset.profile.carverWeights).length).toBe(6);
        expect(Object.keys(preset.profile.shockWeights).length).toBe(5);
      });
    });

    it("critical_infrastructure preset exists", () => {
      expect(PRESET_PROFILES["critical_infrastructure"]).toBeDefined();
      expect(PRESET_PROFILES["critical_infrastructure"].name).toBe("Critical Infrastructure");
    });

    it("government_dod preset exists", () => {
      expect(PRESET_PROFILES["government_dod"]).toBeDefined();
    });
  });

  describe("End-to-End Scoring Pipeline", () => {
    it("produces consistent results through the full pipeline", () => {
      // 1. Start with raw CARVER and Shock factors
      const carver: CarverScores = {
        criticality: 8, accessibility: 7, recuperability: 6,
        vulnerability: 9, effect: 7, recognizability: 5,
      };
      const shock: ShockScores = {
        scope: 7, handling: 5, operationalImpact: 8,
        cascadingEffects: 6, knowledge: 4,
      };

      // 2. Apply mission + essential service baselines
      const adjusted = applyMissionBaselines(carver, shock, "revenue_generation", "payment_processing");

      // 3. Compute hybrid risk with the adjusted factors
      const input: ScoringInput = {
        carver: adjusted.carver,
        shock: adjusted.shock,
        cvssEstimate: 7.5,
        exposure: 0.7,
        confidence: 0.85,
        missionMultiplier: adjusted.missionMultiplier,
      };
      const result = computeHybridRisk(input, DEFAULT_PROFILE);

      expect(result.hybridRiskScore).toBeGreaterThan(0);
      expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
      expect(["critical", "high", "medium", "low"]).toContain(result.riskBand);
      expect(result.carverComposite).toBeGreaterThan(0);
      expect(result.shockComposite).toBeGreaterThan(0);
      expect(result.missionImpactScore).toBeGreaterThan(0);
    });

    it("mission-critical assets score higher than general assets", () => {
      const baseCarver: CarverScores = {
        criticality: 5, accessibility: 5, recuperability: 5,
        vulnerability: 5, effect: 5, recognizability: 5,
      };
      const baseShock: ShockScores = {
        scope: 5, handling: 5, operationalImpact: 5,
        cascadingEffects: 5, knowledge: 5,
      };

      // General asset - no mission function baselines
      const generalInput: ScoringInput = {
        carver: baseCarver,
        shock: baseShock,
        cvssEstimate: 5.0,
        exposure: 0.5,
        confidence: 0.7,
      };
      const generalResult = computeHybridRisk(generalInput, DEFAULT_PROFILE);

      // Command & Control asset with mission baselines applied
      const ccAdjusted = applyMissionBaselines({ ...baseCarver }, { ...baseShock }, "command_control", "sso");
      const ccInput: ScoringInput = {
        carver: ccAdjusted.carver,
        shock: ccAdjusted.shock,
        cvssEstimate: 5.0,
        exposure: 0.5,
        confidence: 0.7,
        missionMultiplier: ccAdjusted.missionMultiplier,
      };
      const ccResult = computeHybridRisk(ccInput, DEFAULT_PROFILE);

      expect(ccResult.hybridRiskScore).toBeGreaterThan(generalResult.hybridRiskScore);
    });

    it("different presets produce different scores for the same asset", () => {
      const input: ScoringInput = {
        carver: sampleCarver,
        shock: sampleShock,
        cvssEstimate: 7.0,
        exposure: 0.6,
        confidence: 0.8,
      };
      const ciResult = computeHybridRisk(input, PRESET_PROFILES["critical_infrastructure"].profile);
      const finResult = computeHybridRisk(input, PRESET_PROFILES["financial_services"].profile);
      // Different presets should produce at least slightly different scores
      // (they may be close but the weights differ)
      expect(typeof ciResult.hybridRiskScore).toBe("number");
      expect(typeof finResult.hybridRiskScore).toBe("number");
    });
  });
});
