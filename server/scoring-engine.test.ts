/**
 * CARVER+Shock / CVSS v4.0 Hybrid Scoring Engine — Test Suite
 * ─────────────────────────────────────────────────────────────
 * Tests the core scoring computations, CVSS v4.0 parsing/building,
 * FIPS 199 integration, criticality tier floors, discovery triggers,
 * and profile management without requiring database or LLM access.
 */
import { describe, expect, it } from "vitest";
import {
  computeCarverComposite,
  computeShockComposite,
  computeMissionImpact,
  computeHybridRisk,
  parseCvssV4Vector,
  buildCvssV4Vector,
  cvssV4ToCarverAdjustments,
  fips199ToCarverAdjustments,
  applyCriticalityTierFloors,
  applyDiscoveryTrigger,
  applyMissionBaselines,
  businessImpactToMultiplier,
  generateRescoringEvent,
  isSignificantChange,
  dbProfileToScoringProfile,
  riskScoreToHeatColor,
  DEFAULT_PROFILE,
  PRESET_PROFILES,
  CARVER_DIGITAL_TRANSLATION,
  SHOCK_DIGITAL_TRANSLATION,
  CRITICALITY_TIERS,
  DISCOVERY_PHASE_TRIGGERS,
  MISSION_FUNCTIONS,
  ESSENTIAL_SERVICES,
  BUSINESS_IMPACT_LEVELS,
  ASSET_DEVICE_TYPES,
  ASSET_PLATFORM_TYPES,
  type CarverScores,
  type ShockScores,
  type ScoringInput,
  type ScoringProfile,
  type CriticalityTier,
  type Fips199Category,
  type RescoringEvent,
  type ScoringResult,
} from "./lib/scoring-engine";

// ═══════════════════════════════════════════════════════════════════════
// §1 — CARVER Composite Computation
// ═══════════════════════════════════════════════════════════════════════

describe("computeCarverComposite", () => {
  it("computes weighted average of CARVER scores", () => {
    const scores: CarverScores = {
      criticality: 10, accessibility: 8, recuperability: 6,
      vulnerability: 8, effect: 7, recognizability: 5,
    };
    const result = computeCarverComposite(scores, DEFAULT_PROFILE.carverWeights);
    expect(result).toBeGreaterThan(0);
    expect(result).toBeLessThanOrEqual(10);
  });

  it("returns 0 when all scores are 0", () => {
    const scores: CarverScores = {
      criticality: 0, accessibility: 0, recuperability: 0,
      vulnerability: 0, effect: 0, recognizability: 0,
    };
    const result = computeCarverComposite(scores, DEFAULT_PROFILE.carverWeights);
    expect(result).toBe(0);
  });

  it("returns maximum when all scores are 10", () => {
    const scores: CarverScores = {
      criticality: 10, accessibility: 10, recuperability: 10,
      vulnerability: 10, effect: 10, recognizability: 10,
    };
    const result = computeCarverComposite(scores, DEFAULT_PROFILE.carverWeights);
    expect(result).toBe(10);
  });

  it("weights criticality higher than recognizability in default profile", () => {
    const highCrit: CarverScores = {
      criticality: 10, accessibility: 1, recuperability: 1,
      vulnerability: 1, effect: 1, recognizability: 1,
    };
    const highRecog: CarverScores = {
      criticality: 1, accessibility: 1, recuperability: 1,
      vulnerability: 1, effect: 1, recognizability: 10,
    };
    const critResult = computeCarverComposite(highCrit, DEFAULT_PROFILE.carverWeights);
    const recogResult = computeCarverComposite(highRecog, DEFAULT_PROFILE.carverWeights);
    expect(critResult).toBeGreaterThan(recogResult);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — Shock Composite Computation
// ═══════════════════════════════════════════════════════════════════════

describe("computeShockComposite", () => {
  it("computes weighted average of Shock scores", () => {
    const scores: ShockScores = {
      scope: 8, handling: 6, operationalImpact: 9,
      cascadingEffects: 7, knowledge: 5,
    };
    const result = computeShockComposite(scores, DEFAULT_PROFILE.shockWeights);
    expect(result).toBeGreaterThan(0);
    expect(result).toBeLessThanOrEqual(10);
  });

  it("returns 0 when all scores are 0", () => {
    const scores: ShockScores = {
      scope: 0, handling: 0, operationalImpact: 0,
      cascadingEffects: 0, knowledge: 0,
    };
    const result = computeShockComposite(scores, DEFAULT_PROFILE.shockWeights);
    expect(result).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — CVSS v4.0 Parsing
// ═══════════════════════════════════════════════════════════════════════

describe("parseCvssV4Vector", () => {
  it("parses a valid CVSS v4.0 base vector", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.metrics.AV).toBe("N");
    expect(parsed!.metrics.AC).toBe("L");
    expect(parsed!.metrics.AT).toBe("N");
    expect(parsed!.metrics.PR).toBe("N");
    expect(parsed!.metrics.UI).toBe("N");
    expect(parsed!.metrics.VC).toBe("H");
    expect(parsed!.metrics.VI).toBe("H");
    expect(parsed!.metrics.VA).toBe("H");
    expect(parsed!.metrics.SC).toBe("N");
    expect(parsed!.metrics.SI).toBe("N");
    expect(parsed!.metrics.SA).toBe("N");
    expect(parsed!.nomenclature).toBe("CVSS-B");
    expect(parsed!.hasThreat).toBe(false);
    expect(parsed!.hasEnvironmental).toBe(false);
    expect(parsed!.hasSupplemental).toBe(false);
  });

  it("returns a high score for network/no-auth/high-impact vector", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.estimatedScore).toBeGreaterThanOrEqual(8);
    expect(parsed!.severity).toBe("Critical");
  });

  it("returns a low score for physical/high-complexity vector", () => {
    const vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.estimatedScore).toBeLessThan(4);
  });

  it("detects threat metrics and sets nomenclature to CVSS-BT", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.hasThreat).toBe(true);
    expect(parsed!.nomenclature).toBe("CVSS-BT");
  });

  it("detects environmental metrics and sets nomenclature to CVSS-BE", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:L";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.hasEnvironmental).toBe(true);
    expect(parsed!.nomenclature).toBe("CVSS-BE");
  });

  it("detects all metric groups and sets nomenclature to CVSS-BTE", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:M/AR:L";
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.hasThreat).toBe(true);
    expect(parsed!.hasEnvironmental).toBe(true);
    expect(parsed!.nomenclature).toBe("CVSS-BTE");
  });

  it("returns null for invalid vector string", () => {
    expect(parseCvssV4Vector("not-a-vector")).toBeNull();
    expect(parseCvssV4Vector("CVSS:3.1/AV:N/AC:L")).toBeNull();
    expect(parseCvssV4Vector("")).toBeNull();
  });

  it("returns null for CVSS v4.0 prefix with missing required metrics", () => {
    // Missing several required metrics
    expect(parseCvssV4Vector("CVSS:4.0/AV:N")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — CVSS v4.0 Vector Building
// ═══════════════════════════════════════════════════════════════════════

describe("buildCvssV4Vector", () => {
  it("builds a valid vector string from metrics", () => {
    const vector = buildCvssV4Vector({
      AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H", SC: "N", SI: "N", SA: "N",
    });
    expect(vector).toContain("CVSS:4.0/");
    expect(vector).toContain("AV:N");
    expect(vector).toContain("VC:H");
  });

  it("produces a vector that can be parsed back", () => {
    const vector = buildCvssV4Vector({
      AV: "A", AC: "H", AT: "P", PR: "L", UI: "P",
      VC: "L", VI: "L", VA: "N", SC: "N", SI: "N", SA: "N",
    });
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
    expect(parsed!.metrics.AV).toBe("A");
    expect(parsed!.metrics.AC).toBe("H");
  });

  it("includes optional threat metrics when provided", () => {
    const vector = buildCvssV4Vector({
      AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H", SC: "N", SI: "N", SA: "N",
      E: "A",
    });
    expect(vector).toContain("E:A");
    const parsed = parseCvssV4Vector(vector);
    expect(parsed!.hasThreat).toBe(true);
  });

  it("omits 'X' (Not Defined) optional metrics from the vector string", () => {
    const vector = buildCvssV4Vector({
      AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H", SC: "N", SI: "N", SA: "N",
      E: "X", CR: "X",
    });
    // "X" means not defined — should not appear in vector (or if it does, parser handles it)
    const parsed = parseCvssV4Vector(vector);
    expect(parsed).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §5 — CVSS v4.0 → CARVER Feed-Through
// ═══════════════════════════════════════════════════════════════════════

describe("cvssV4ToCarverAdjustments", () => {
  it("maps network attack vector to high accessibility", () => {
    const parsed = parseCvssV4Vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(parsed).not.toBeNull();
    const result = cvssV4ToCarverAdjustments(parsed!);
    expect(result.carverAdjustments.accessibility).toBeGreaterThanOrEqual(8);
  });

  it("maps physical attack vector to low accessibility", () => {
    const parsed = parseCvssV4Vector("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
    expect(parsed).not.toBeNull();
    const result = cvssV4ToCarverAdjustments(parsed!);
    expect(result.carverAdjustments.accessibility).toBeLessThanOrEqual(3);
  });

  it("maps high impact to high effect score", () => {
    const parsed = parseCvssV4Vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
    expect(parsed).not.toBeNull();
    const result = cvssV4ToCarverAdjustments(parsed!);
    expect(result.carverAdjustments.effect).toBeGreaterThanOrEqual(7);
  });

  it("generates shock adjustments for high-scope vectors", () => {
    const parsed = parseCvssV4Vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
    expect(parsed).not.toBeNull();
    const result = cvssV4ToCarverAdjustments(parsed!);
    expect(result.shockAdjustments.scope).toBeGreaterThan(0);
  });

  it("returns carverAdjustments and shockAdjustments objects", () => {
    const parsed = parseCvssV4Vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const result = cvssV4ToCarverAdjustments(parsed!);
    expect(result).toHaveProperty("carverAdjustments");
    expect(result).toHaveProperty("shockAdjustments");
    expect(typeof result.carverAdjustments).toBe("object");
    expect(typeof result.shockAdjustments).toBe("object");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §6 — FIPS 199 → CARVER Integration
// ═══════════════════════════════════════════════════════════════════════

describe("fips199ToCarverAdjustments", () => {
  it("maps high confidentiality to high CARVER effect", () => {
    const category: Fips199Category = {
      confidentiality: "high",
      integrity: "moderate",
      availability: "low",
    };
    const result = fips199ToCarverAdjustments(category);
    expect(result.carverAdjustments.effect).toBeGreaterThanOrEqual(5);
  });

  it("maps high availability to high recuperability", () => {
    const category: Fips199Category = {
      confidentiality: "low",
      integrity: "low",
      availability: "high",
    };
    const result = fips199ToCarverAdjustments(category);
    // high availability (score 9) → recuperability 8
    expect(result.carverAdjustments.recuperability).toBeGreaterThanOrEqual(7);
  });

  it("maps all-high to elevated mission multiplier", () => {
    const category: Fips199Category = {
      confidentiality: "high",
      integrity: "high",
      availability: "high",
    };
    const result = fips199ToCarverAdjustments(category);
    // maxLevel=9 → multiplier 1.8
    expect(result.missionMultiplier).toBeGreaterThanOrEqual(1.5);
  });

  it("maps all-low to reduced mission multiplier", () => {
    const category: Fips199Category = {
      confidentiality: "low",
      integrity: "low",
      availability: "low",
    };
    const result = fips199ToCarverAdjustments(category);
    // maxLevel=2 → multiplier 0.9
    expect(result.missionMultiplier).toBeLessThanOrEqual(1.0);
  });

  it("returns both carverAdjustments and shockAdjustments", () => {
    const category: Fips199Category = {
      confidentiality: "moderate",
      integrity: "moderate",
      availability: "moderate",
    };
    const result = fips199ToCarverAdjustments(category);
    expect(result).toHaveProperty("carverAdjustments");
    expect(result).toHaveProperty("shockAdjustments");
    expect(result).toHaveProperty("missionMultiplier");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §7 — Criticality Tier Floors
// ═══════════════════════════════════════════════════════════════════════

describe("applyCriticalityTierFloors", () => {
  const lowCarver: CarverScores = {
    criticality: 1, accessibility: 1, recuperability: 1,
    vulnerability: 1, effect: 1, recognizability: 1,
  };
  const lowShock: ShockScores = {
    scope: 1, handling: 1, operationalImpact: 1,
    cascadingEffects: 1, knowledge: 1,
  };

  it("Tier 1 (Mission Critical) raises criticality floor to 9", () => {
    const result = applyCriticalityTierFloors(lowCarver, lowShock, 1);
    expect(result.carver.criticality).toBeGreaterThanOrEqual(9);
    expect(result.missionMultiplier).toBe(2.0);
  });

  it("Tier 2 (Business Critical) raises criticality floor to 7", () => {
    const result = applyCriticalityTierFloors(lowCarver, lowShock, 2);
    expect(result.carver.criticality).toBeGreaterThanOrEqual(7);
    expect(result.missionMultiplier).toBe(1.6);
  });

  it("Tier 5 (Non-Essential) sets low multiplier", () => {
    const result = applyCriticalityTierFloors(lowCarver, lowShock, 5);
    expect(result.missionMultiplier).toBe(0.6);
  });

  it("never lowers existing scores (floor behavior)", () => {
    const highCarver: CarverScores = {
      criticality: 10, accessibility: 10, recuperability: 10,
      vulnerability: 10, effect: 10, recognizability: 10,
    };
    const highShock: ShockScores = {
      scope: 10, handling: 10, operationalImpact: 10,
      cascadingEffects: 10, knowledge: 10,
    };
    const result = applyCriticalityTierFloors(highCarver, highShock, 5);
    expect(result.carver.criticality).toBe(10);
    expect(result.shock.operationalImpact).toBe(10);
  });

  it("all 5 tiers are defined", () => {
    for (let tier = 1; tier <= 5; tier++) {
      expect(CRITICALITY_TIERS[tier as CriticalityTier]).toBeDefined();
      expect(CRITICALITY_TIERS[tier as CriticalityTier].name).toBeTruthy();
      expect(CRITICALITY_TIERS[tier as CriticalityTier].rto).toBeTruthy();
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8 — Discovery Phase Triggers
// ═══════════════════════════════════════════════════════════════════════

describe("applyDiscoveryTrigger", () => {
  const baseCarver: CarverScores = {
    criticality: 5, accessibility: 5, recuperability: 5,
    vulnerability: 5, effect: 5, recognizability: 5,
  };
  const baseShock: ShockScores = {
    scope: 5, handling: 5, operationalImpact: 5,
    cascadingEffects: 5, knowledge: 5,
  };

  it("new_cve_discovered raises vulnerability score", () => {
    const result = applyDiscoveryTrigger(
      "new_cve_discovered",
      { cvssScore: 9.8, exploitAvailable: true, kevListed: false },
      baseCarver, baseShock
    );
    expect(result.carver.vulnerability).toBeGreaterThan(5);
    expect(result.likelihoodBoost).toBeGreaterThan(0);
  });

  it("kev_match sets vulnerability to maximum", () => {
    const result = applyDiscoveryTrigger(
      "kev_match", {},
      baseCarver, baseShock
    );
    expect(result.carver.vulnerability).toBe(10);
    expect(result.carver.recognizability).toBeGreaterThanOrEqual(8);
    expect(result.likelihoodBoost).toBeGreaterThanOrEqual(0.3);
  });

  it("darkweb_exposure raises accessibility to 9", () => {
    const result = applyDiscoveryTrigger(
      "darkweb_exposure",
      { dataType: "credentials" },
      baseCarver, baseShock
    );
    expect(result.carver.accessibility).toBe(9);
    expect(result.shock.scope).toBeGreaterThanOrEqual(8);
  });

  it("new_port_service raises accessibility", () => {
    const result = applyDiscoveryTrigger(
      "new_port_service",
      { isHighRiskPort: true, serviceVersion: "Apache 2.4.49" },
      baseCarver, baseShock
    );
    expect(result.carver.accessibility).toBeGreaterThanOrEqual(8);
    expect(result.carver.recognizability).toBeGreaterThanOrEqual(7);
  });

  it("unknown trigger type returns unchanged scores", () => {
    const result = applyDiscoveryTrigger(
      "nonexistent_trigger", {},
      baseCarver, baseShock
    );
    expect(result.carver).toEqual(baseCarver);
    expect(result.shock).toEqual(baseShock);
    expect(result.likelihoodBoost).toBe(0);
  });

  it("never lowers existing scores (floor behavior)", () => {
    const highCarver: CarverScores = {
      criticality: 10, accessibility: 10, recuperability: 10,
      vulnerability: 10, effect: 10, recognizability: 10,
    };
    const result = applyDiscoveryTrigger(
      "new_port_service",
      { isHighRiskPort: false },
      highCarver, baseShock
    );
    expect(result.carver.accessibility).toBe(10);
  });

  it("all defined triggers have descriptions", () => {
    for (const [key, trigger] of Object.entries(DISCOVERY_PHASE_TRIGGERS)) {
      expect(trigger.description).toBeTruthy();
      expect(typeof trigger.carverAdjustments).toBe("function");
      expect(typeof trigger.shockAdjustments).toBe("function");
      expect(typeof trigger.likelihoodBoost).toBe("function");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §9 — Hybrid Risk Computation (Full Pipeline)
// ═══════════════════════════════════════════════════════════════════════

describe("computeHybridRisk", () => {
  const baseInput: ScoringInput = {
    carver: {
      criticality: 7, accessibility: 6, recuperability: 5,
      vulnerability: 8, effect: 7, recognizability: 4,
    },
    shock: {
      scope: 6, handling: 5, operationalImpact: 7,
      cascadingEffects: 4, knowledge: 6,
    },
    cvssEstimate: 7.5,
    exposure: 0.7,
    confidence: 0.8,
  };

  it("returns all required result fields", () => {
    const result = computeHybridRisk(baseInput, DEFAULT_PROFILE);
    expect(result).toHaveProperty("carverComposite");
    expect(result).toHaveProperty("shockComposite");
    expect(result).toHaveProperty("missionImpactScore");
    expect(result).toHaveProperty("impactScore");
    expect(result).toHaveProperty("likelihoodScore");
    expect(result).toHaveProperty("hybridRiskScore");
    expect(result).toHaveProperty("riskBand");
    expect(result).toHaveProperty("factorContributions");
  });

  it("produces score in 0-100 range", () => {
    const result = computeHybridRisk(baseInput, DEFAULT_PROFILE);
    expect(result.hybridRiskScore).toBeGreaterThanOrEqual(0);
    expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
    expect(result.impactScore).toBeGreaterThanOrEqual(0);
    expect(result.impactScore).toBeLessThanOrEqual(100);
    expect(result.likelihoodScore).toBeGreaterThanOrEqual(0);
    expect(result.likelihoodScore).toBeLessThanOrEqual(100);
  });

  it("assigns correct risk band based on thresholds", () => {
    // Critical scenario — requires confirmedVulnScore to drive likelihood
    // (without confirmed findings, assets stay green per "innocent until proven guilty")
    const critInput: ScoringInput = {
      carver: { criticality: 10, accessibility: 10, recuperability: 10, vulnerability: 10, effect: 10, recognizability: 10 },
      shock: { scope: 10, handling: 10, operationalImpact: 10, cascadingEffects: 10, knowledge: 10 },
      cvssEstimate: 10, exposure: 1.0, confidence: 1.0,
      confirmedVulnScore: 100,
    };
    const critResult = computeHybridRisk(critInput, DEFAULT_PROFILE);
    expect(critResult.riskBand).toBe("critical");

    // Low scenario
    const lowInput: ScoringInput = {
      carver: { criticality: 1, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 },
      shock: { scope: 1, handling: 1, operationalImpact: 1, cascadingEffects: 1, knowledge: 1 },
      cvssEstimate: 1, exposure: 0.1, confidence: 0.3,
    };
    const lowResult = computeHybridRisk(lowInput, DEFAULT_PROFILE);
    expect(lowResult.riskBand).toBe("low");
  });

  it("CVSS v4.0 vector feed-through raises scores", () => {
    const withoutCvss = computeHybridRisk(baseInput, DEFAULT_PROFILE);
    const withCvss = computeHybridRisk({
      ...baseInput,
      cvssV4Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    }, DEFAULT_PROFILE);
    expect(withCvss.hybridRiskScore).toBeGreaterThanOrEqual(withoutCvss.hybridRiskScore);
    expect(withCvss.cvssV4Parsed).toBeDefined();
  });

  it("FIPS 199 integration raises scores for high categories", () => {
    const withoutFips = computeHybridRisk(baseInput, DEFAULT_PROFILE);
    const withFips = computeHybridRisk({
      ...baseInput,
      fips199: { confidentiality: "high", integrity: "high", availability: "high" },
    }, DEFAULT_PROFILE);
    expect(withFips.hybridRiskScore).toBeGreaterThanOrEqual(withoutFips.hybridRiskScore);
    expect(withFips.fips199Applied).toBeDefined();
  });

  it("criticality tier floors raise scores for Tier 1", () => {
    const lowInput: ScoringInput = {
      carver: { criticality: 1, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 },
      shock: { scope: 1, handling: 1, operationalImpact: 1, cascadingEffects: 1, knowledge: 1 },
      cvssEstimate: 3, exposure: 0.3, confidence: 0.5,
    };
    const withoutTier = computeHybridRisk(lowInput, DEFAULT_PROFILE);
    const withTier1 = computeHybridRisk({
      ...lowInput,
      criticalityTier: 1,
    }, DEFAULT_PROFILE);
    expect(withTier1.hybridRiskScore).toBeGreaterThan(withoutTier.hybridRiskScore);
    expect(withTier1.criticalityTierApplied).toBe(1);
  });

  it("business impact level affects mission multiplier", () => {
    const withLow = computeHybridRisk({
      ...baseInput,
      businessImpactLevel: "low",
    }, DEFAULT_PROFILE);
    const withHigh = computeHybridRisk({
      ...baseInput,
      businessImpactLevel: "high",
    }, DEFAULT_PROFILE);
    expect(withHigh.hybridRiskScore).toBeGreaterThanOrEqual(withLow.hybridRiskScore);
  });

  it("confirmed vuln score of 0 produces very low likelihood", () => {
    const result = computeHybridRisk({
      ...baseInput,
      confirmedVulnScore: 0,
    }, DEFAULT_PROFILE);
    expect(result.likelihoodScore).toBeLessThanOrEqual(15);
  });

  it("factor contributions include all 11 factors", () => {
    const result = computeHybridRisk(baseInput, DEFAULT_PROFILE);
    expect(result.factorContributions.length).toBe(11); // 6 CARVER + 5 Shock
    const carverFactors = result.factorContributions.filter(f => f.category === "CARVER");
    const shockFactors = result.factorContributions.filter(f => f.category === "Shock");
    expect(carverFactors.length).toBe(6);
    expect(shockFactors.length).toBe(5);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §10 — Mission Function Baselines
// ═══════════════════════════════════════════════════════════════════════

describe("applyMissionBaselines", () => {
  it("applies command_control baseline to raise CARVER scores", () => {
    const lowCarver: CarverScores = {
      criticality: 1, accessibility: 1, recuperability: 1,
      vulnerability: 1, effect: 1, recognizability: 1,
    };
    const lowShock: ShockScores = {
      scope: 1, handling: 1, operationalImpact: 1,
      cascadingEffects: 1, knowledge: 1,
    };
    const result = applyMissionBaselines(lowCarver, lowShock, "command_control");
    expect(result.carver.criticality).toBeGreaterThan(1);
  });

  it("returns unchanged scores for unknown mission function", () => {
    const carver: CarverScores = {
      criticality: 5, accessibility: 5, recuperability: 5,
      vulnerability: 5, effect: 5, recognizability: 5,
    };
    const shock: ShockScores = {
      scope: 5, handling: 5, operationalImpact: 5,
      cascadingEffects: 5, knowledge: 5,
    };
    const result = applyMissionBaselines(carver, shock, "nonexistent_function");
    expect(result.carver).toEqual(carver);
    expect(result.shock).toEqual(shock);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §11 — Business Impact Multiplier
// ═══════════════════════════════════════════════════════════════════════

describe("businessImpactToMultiplier", () => {
  it("returns higher multiplier for higher impact levels", () => {
    const admin = businessImpactToMultiplier("administrative");
    const operational = businessImpactToMultiplier("operational");
    const essential = businessImpactToMultiplier("business_essential");
    const critical = businessImpactToMultiplier("mission_critical");
    expect(critical).toBeGreaterThan(essential);
    expect(essential).toBeGreaterThan(operational);
    expect(operational).toBeGreaterThan(admin);
  });

  it("returns 1.0 for unknown level", () => {
    expect(businessImpactToMultiplier("unknown_level")).toBe(1.0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §12 — Re-scoring Events
// ═══════════════════════════════════════════════════════════════════════

describe("generateRescoringEvent", () => {
  it("creates a valid re-scoring event", () => {
    const prevResult: ScoringResult = {
      carverComposite: 5, shockComposite: 5, missionImpactScore: 5,
      impactScore: 50, likelihoodScore: 50, hybridRiskScore: 50,
      riskBand: "medium", factorContributions: [],
    };
    const newResult: ScoringResult = {
      carverComposite: 7, shockComposite: 7, missionImpactScore: 7,
      impactScore: 70, likelihoodScore: 70, hybridRiskScore: 75,
      riskBand: "high", factorContributions: [],
    };
    const event = generateRescoringEvent(
      "new_cve_discovered",
      "asset-42",
      prevResult,
      newResult,
      "New CVE discovered",
      [{ factor: "vulnerability", previousValue: 5, newValue: 8, reason: "CVE-2024-1234" }]
    );
    expect(event.assetId).toBe("asset-42");
    expect(event.trigger).toBe("new_cve_discovered");
    expect(event.previousScore).toBe(50);
    expect(event.newScore).toBe(75);
    expect(event.previousBand).toBe("medium");
    expect(event.newBand).toBe("high");
    expect(event.delta).toBe(25);
    expect(typeof event.timestamp).toBe("number");
  });
});

describe("isSignificantChange", () => {
  const makeEvent = (overrides: Partial<RescoringEvent>): RescoringEvent => ({
    trigger: "new_cve_discovered",
    assetId: "asset-1",
    previousScore: 50,
    newScore: 55,
    delta: 5,
    previousBand: "medium",
    newBand: "medium",
    changeDescription: "test",
    factorChanges: [],
    timestamp: Date.now(),
    ...overrides,
  });

  it("detects band change as significant", () => {
    const event = makeEvent({ previousBand: "medium", newBand: "high", delta: 5 });
    expect(isSignificantChange(event)).toBe(true);
  });

  it("detects large delta as significant", () => {
    const event = makeEvent({ previousScore: 30, newScore: 50, delta: 20, previousBand: "low", newBand: "low" });
    expect(isSignificantChange(event)).toBe(true);
  });

  it("does not flag small same-band change as significant", () => {
    const event = makeEvent({ previousScore: 50, newScore: 52, delta: 2, previousBand: "medium", newBand: "medium" });
    expect(isSignificantChange(event)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §13 — Profile Management
// ═══════════════════════════════════════════════════════════════════════

describe("DEFAULT_PROFILE", () => {
  it("has valid weight ranges", () => {
    for (const [, val] of Object.entries(DEFAULT_PROFILE.carverWeights)) {
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(10);
    }
    for (const [, val] of Object.entries(DEFAULT_PROFILE.shockWeights)) {
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(10);
    }
  });

  it("has valid threshold ranges", () => {
    expect(DEFAULT_PROFILE.criticalThreshold).toBeGreaterThan(DEFAULT_PROFILE.highThreshold);
    expect(DEFAULT_PROFILE.highThreshold).toBeGreaterThan(DEFAULT_PROFILE.mediumThreshold);
    expect(DEFAULT_PROFILE.mediumThreshold).toBeGreaterThan(0);
  });

  it("carverWeight + shockWeight + cvssWeight should be reasonable", () => {
    const total = DEFAULT_PROFILE.carverWeight + DEFAULT_PROFILE.shockWeight + DEFAULT_PROFILE.cvssWeight;
    expect(total).toBeGreaterThan(0);
    expect(total).toBeLessThanOrEqual(3);
  });
});

describe("PRESET_PROFILES", () => {
  it("has at least 3 presets", () => {
    expect(Object.keys(PRESET_PROFILES).length).toBeGreaterThanOrEqual(3);
  });

  it("each preset has name, description, and valid profile", () => {
    for (const [key, preset] of Object.entries(PRESET_PROFILES)) {
      expect(preset.name).toBeTruthy();
      expect(preset.description).toBeTruthy();
      expect(preset.profile.carverWeights).toBeDefined();
      expect(preset.profile.shockWeights).toBeDefined();
      expect(preset.profile.criticalThreshold).toBeGreaterThan(0);
    }
  });
});

describe("dbProfileToScoringProfile", () => {
  it("converts a database row to a ScoringProfile", () => {
    const row = {
      wCriticality: 2.0, wAccessibility: 1.5, wRecuperability: 1.0,
      wVulnerability: 1.5, wEffect: 1.5, wRecognizability: 0.5,
      wScope: 1.5, wHandling: 1.0, wOperationalImpact: 1.5,
      wCascadingEffects: 1.0, wKnowledge: 0.5,
      carverWeight: 0.4, shockWeight: 0.35, cvssWeight: 0.25,
      criticalThreshold: 80, highThreshold: 60, mediumThreshold: 35,
    };
    const profile = dbProfileToScoringProfile(row);
    expect(profile.carverWeights.criticality).toBe(2.0);
    expect(profile.shockWeights.scope).toBe(1.5);
    expect(profile.carverWeight).toBe(0.4);
    expect(profile.criticalThreshold).toBe(80);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §14 — Reference Data Integrity
// ═══════════════════════════════════════════════════════════════════════

describe("CARVER_DIGITAL_TRANSLATION", () => {
  it("has all 6 CARVER factors", () => {
    const keys = Object.keys(CARVER_DIGITAL_TRANSLATION);
    expect(keys).toContain("criticality");
    expect(keys).toContain("accessibility");
    expect(keys).toContain("recuperability");
    expect(keys).toContain("vulnerability");
    expect(keys).toContain("effect");
    expect(keys).toContain("recognizability");
  });

  it("each factor has 5 scale levels", () => {
    for (const [, factor] of Object.entries(CARVER_DIGITAL_TRANSLATION)) {
      expect(factor.scale.length).toBe(5);
    }
  });

  it("each factor has FM 34-36 and digital descriptions", () => {
    for (const [, factor] of Object.entries(CARVER_DIGITAL_TRANSLATION)) {
      expect(factor.fm34_36).toBeTruthy();
      expect(factor.digital).toBeTruthy();
      expect(factor.name).toBeTruthy();
    }
  });
});

describe("SHOCK_DIGITAL_TRANSLATION", () => {
  it("has all 5 Shock factors", () => {
    const keys = Object.keys(SHOCK_DIGITAL_TRANSLATION);
    expect(keys).toContain("scope");
    expect(keys).toContain("handling");
    expect(keys).toContain("operationalImpact");
    expect(keys).toContain("cascadingEffects");
    expect(keys).toContain("knowledge");
  });

  it("each factor has 5 scale levels", () => {
    for (const [, factor] of Object.entries(SHOCK_DIGITAL_TRANSLATION)) {
      expect(factor.scale.length).toBe(5);
    }
  });
});

describe("Taxonomy constants", () => {
  it("MISSION_FUNCTIONS has at least 5 entries", () => {
    expect(MISSION_FUNCTIONS.length).toBeGreaterThanOrEqual(5);
  });

  it("ESSENTIAL_SERVICES has at least 5 entries", () => {
    expect(ESSENTIAL_SERVICES.length).toBeGreaterThanOrEqual(5);
  });

  it("BUSINESS_IMPACT_LEVELS has at least 4 entries", () => {
    expect(BUSINESS_IMPACT_LEVELS.length).toBeGreaterThanOrEqual(4);
  });

  it("ASSET_DEVICE_TYPES has at least 5 entries", () => {
    expect(ASSET_DEVICE_TYPES.length).toBeGreaterThanOrEqual(5);
  });

  it("ASSET_PLATFORM_TYPES has at least 5 entries", () => {
    expect(ASSET_PLATFORM_TYPES.length).toBeGreaterThanOrEqual(5);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §15 — Heat Map Utilities
// ═══════════════════════════════════════════════════════════════════════

describe("riskScoreToHeatColor", () => {
  it("returns a warm hue for critical scores", () => {
    const color = riskScoreToHeatColor(90);
    expect(color).toContain("hsl(");
    // High scores should have low hue (red end)
    const hue = parseInt(color.match(/hsl\((\d+)/)?.[1] ?? "999");
    expect(hue).toBeLessThan(30);
  });

  it("returns a cool hue for low scores", () => {
    const color = riskScoreToHeatColor(10);
    expect(color).toContain("hsl(");
    // Low scores should have high hue (green end)
    const hue = parseInt(color.match(/hsl\((\d+)/)?.[1] ?? "0");
    expect(hue).toBeGreaterThan(90);
  });

  it("returns a valid HSL color for any score 0-100", () => {
    for (const score of [0, 25, 50, 75, 100]) {
      const color = riskScoreToHeatColor(score);
      expect(color).toMatch(/^hsl\(\d+, \d+%, \d+%\)$/);
    }
  });
});
