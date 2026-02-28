/**
 * Tests for Industry Baseline Scoring Module
 * Validates all scoring functions from the AceC3 Industry Asset Baseline
 * and Hybrid CARVER+SHOCK packages.
 */
import { describe, it, expect } from "vitest";
import {
  classifyAssetTier,
  inferBiaFromSignals,
  determineShockLevel,
  computeIndustryModifier,
  computeIndustryEnhancedScore,
  batchIndustryScore,
  getIndustryVerticals,
  getIndustryTierBreakdown,
  detectAllSignals,
  computeFips199HighWatermark,
  computeFips199Adjustments,
  getFips199IndustryDefault,
  INDUSTRY_ASSET_BASELINES,
  INDUSTRY_RISK_MODIFIERS,
  TIER_WEIGHTS,
  HYBRID_FORMULA,
  SHOCK_MULTIPLIER_GUIDANCE,
  AUTO_BIA_RULES,
  FIPS_199_LEVEL_MAP,
  FIPS_199_INDUSTRY_DEFAULTS,
  type IndustryVertical,
  type AssetTier,
  type Fips199Category,
  type Fips199Level,
} from "./lib/industry-baseline-scoring";

// ─── Constants Validation ───────────────────────────────────────────

describe("Industry Baseline Constants", () => {
  it("should have 6 industry verticals", () => {
    expect(Object.keys(INDUSTRY_ASSET_BASELINES)).toHaveLength(6);
  });

  it("should have tier weights matching spec", () => {
    expect(TIER_WEIGHTS.Tier_1_Strategic).toBe(1.5);
    expect(TIER_WEIGHTS.Tier_2_Operational).toBe(1.2);
    expect(TIER_WEIGHTS.Tier_3_Tactical).toBe(1.0);
  });

  it("should have hybrid formula weights summing to 1.0", () => {
    const sum = HYBRID_FORMULA.carverWeight + HYBRID_FORMULA.cvssWeight + HYBRID_FORMULA.biaWeight;
    expect(sum).toBeCloseTo(1.0, 5);
  });

  it("should have 4 SHOCK multiplier levels", () => {
    expect(SHOCK_MULTIPLIER_GUIDANCE).toHaveLength(4);
    expect(SHOCK_MULTIPLIER_GUIDANCE[0].level).toBe("Low");
    expect(SHOCK_MULTIPLIER_GUIDANCE[3].level).toBe("Extreme");
    expect(SHOCK_MULTIPLIER_GUIDANCE[3].multiplier).toBe(1.5);
  });

  it("should have 6 auto-BIA rules", () => {
    expect(AUTO_BIA_RULES).toHaveLength(6);
  });

  it("each industry should have all 3 tiers with at least 1 asset", () => {
    for (const [industry, tiers] of Object.entries(INDUSTRY_ASSET_BASELINES)) {
      expect(tiers.Tier_1_Strategic.length, `${industry} Tier 1`).toBeGreaterThan(0);
      expect(tiers.Tier_2_Operational.length, `${industry} Tier 2`).toBeGreaterThan(0);
      expect(tiers.Tier_3_Tactical.length, `${industry} Tier 3`).toBeGreaterThan(0);
    }
  });

  it("each industry should have risk modifiers", () => {
    for (const [industry, mods] of Object.entries(INDUSTRY_RISK_MODIFIERS)) {
      expect(Object.keys(mods).length, `${industry} modifiers`).toBeGreaterThan(0);
      for (const val of Object.values(mods)) {
        expect(val).toBeGreaterThanOrEqual(1.0);
        expect(val).toBeLessThanOrEqual(2.0);
      }
    }
  });
});

// ─── Asset Tier Classification ──────────────────────────────────────

describe("classifyAssetTier", () => {
  it("should classify SSO endpoint as Tier 1 Strategic for Corporate", () => {
    const result = classifyAssetTier(
      { hostname: "sso.company.com", assetType: "Identity Provider", services: ["SAML"] },
      "Corporate_Enterprise"
    );
    expect(result.tier).toBe("Tier_1_Strategic");
    expect(result.confidence).toBeGreaterThan(0.5);
  });

  it("should classify SCADA server as Tier 1 for OT/Manufacturing", () => {
    const result = classifyAssetTier(
      { hostname: "scada-control-server.plant.local", assetType: "SCADA Control Servers", services: ["Modbus"] },
      "Industrial_OT_Manufacturing"
    );
    expect(result.tier).toBe("Tier_1_Strategic");
  });

  it("should classify standard workstation as Tier 3", () => {
    const result = classifyAssetTier(
      { hostname: "ws-user-042.corp.local", assetType: "Workstation", description: "Standard employee workstation" },
      "Corporate_Enterprise"
    );
    expect(result.tier).toBe("Tier_3_Tactical");
  });

  it("should classify EHR system as Tier 1 for Healthcare", () => {
    const result = classifyAssetTier(
      { hostname: "ehr.hospital.org", assetType: "Electronic Health Record System", technologies: ["Epic", "EHR"], description: "Electronic Health Record EHR Systems" },
      "Healthcare"
    );
    expect(result.tier).toBe("Tier_1_Strategic");
  });

  it("should classify core banking as Tier 1 for Financial Services", () => {
    const result = classifyAssetTier(
      { hostname: "core-banking-prod.bank.com", assetType: "Application", description: "Core banking system" },
      "Financial_Services"
    );
    expect(result.tier).toBe("Tier_1_Strategic");
  });

  it("should default to Tier 3 for unknown assets", () => {
    const result = classifyAssetTier(
      { hostname: "random-server.local" },
      "Corporate_Enterprise"
    );
    expect(result.tier).toBe("Tier_3_Tactical");
    expect(result.confidence).toBeLessThanOrEqual(0.5);
  });

  it("should handle empty asset info gracefully", () => {
    const result = classifyAssetTier({}, "Corporate_Enterprise");
    expect(result.tier).toBe("Tier_3_Tactical");
  });
});

// ─── Auto-BIA Inference ─────────────────────────────────────────────

describe("inferBiaFromSignals", () => {
  it("should detect MX Record signal from mail hostname", () => {
    const result = inferBiaFromSignals({ hostname: "mail.company.com", services: ["SMTP"] });
    expect(result).not.toBeNull();
    expect(result!.signal).toBe("MX Record");
    expect(result!.biaMultiplier).toBe(1.4);
  });

  it("should detect SSO Endpoint signal", () => {
    const result = inferBiaFromSignals({ hostname: "sso.company.com", technologies: ["Okta"] });
    expect(result).not.toBeNull();
    expect(result!.signal).toBe("SSO Endpoint");
    expect(result!.biaMultiplier).toBe(1.5);
  });

  it("should detect Database Port Exposure from port numbers", () => {
    const result = inferBiaFromSignals({ ports: [3306, 80] });
    expect(result).not.toBeNull();
    expect(result!.signal).toBe("Database Port Exposure");
    expect(result!.biaMultiplier).toBe(1.5);
  });

  it("should detect Git Repository signal", () => {
    const result = inferBiaFromSignals({ hostname: "gitlab.internal.com", services: ["Git"] });
    expect(result).not.toBeNull();
    expect(result!.signal).toBe("Git Repository");
  });

  it("should detect Payment Page signal", () => {
    const result = inferBiaFromSignals({ hostname: "checkout.store.com", technologies: ["Stripe"] });
    expect(result).not.toBeNull();
    expect(result!.signal).toBe("Payment Page");
  });

  it("should return null for unrecognized assets", () => {
    const result = inferBiaFromSignals({ hostname: "static-cdn.company.com" });
    expect(result).toBeNull();
  });
});

// ─── SHOCK Level Determination ──────────────────────────────────────

describe("determineShockLevel", () => {
  it("should return Low for scores below 3.5", () => {
    expect(determineShockLevel(0).level).toBe("Low");
    expect(determineShockLevel(2.0).level).toBe("Low");
    expect(determineShockLevel(3.4).level).toBe("Low");
  });

  it("should return Moderate for scores 3.5-5.9", () => {
    expect(determineShockLevel(3.5).level).toBe("Moderate");
    expect(determineShockLevel(5.0).level).toBe("Moderate");
    expect(determineShockLevel(5.9).level).toBe("Moderate");
  });

  it("should return High for scores 6.0-7.9", () => {
    expect(determineShockLevel(6.0).level).toBe("High");
    expect(determineShockLevel(7.0).level).toBe("High");
    expect(determineShockLevel(7.9).level).toBe("High");
  });

  it("should return Extreme for scores 8.0+", () => {
    expect(determineShockLevel(8.0).level).toBe("Extreme");
    expect(determineShockLevel(10.0).level).toBe("Extreme");
  });

  it("should have correct multiplier values", () => {
    expect(determineShockLevel(1.0).multiplier).toBe(1.0);
    expect(determineShockLevel(4.0).multiplier).toBe(1.1);
    expect(determineShockLevel(7.0).multiplier).toBe(1.25);
    expect(determineShockLevel(9.0).multiplier).toBe(1.5);
  });
});

// ─── Industry Modifier Computation ──────────────────────────────────

describe("computeIndustryModifier", () => {
  it("should compute geometric mean for Corporate Enterprise", () => {
    const result = computeIndustryModifier("Corporate_Enterprise");
    expect(result.combined).toBeGreaterThan(1.0);
    expect(result.combined).toBeLessThan(1.3);
    expect(result.modifiers).toHaveProperty("regulatory_multiplier");
    expect(result.modifiers).toHaveProperty("reputation_multiplier");
  });

  it("should compute higher modifier for Energy/Utilities", () => {
    const energy = computeIndustryModifier("Energy_Utilities");
    const corporate = computeIndustryModifier("Corporate_Enterprise");
    expect(energy.combined).toBeGreaterThan(corporate.combined);
  });

  it("should compute modifier for all industries", () => {
    const industries: IndustryVertical[] = [
      "Corporate_Enterprise", "Industrial_OT_Manufacturing",
      "Government_Federal_State", "Healthcare",
      "Financial_Services", "Energy_Utilities",
    ];
    for (const ind of industries) {
      const result = computeIndustryModifier(ind);
      expect(result.combined).toBeGreaterThanOrEqual(1.0);
      expect(result.combined).toBeLessThanOrEqual(2.0);
    }
  });
});

// ─── Enhanced Hybrid Scoring ────────────────────────────────────────

describe("computeIndustryEnhancedScore", () => {
  it("should compute a valid score for a Tier 1 asset", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 50,
      cvssScore: 8.5,
      shockComposite: 7.0,
      industry: "Corporate_Enterprise",
      assetInfo: {
        hostname: "sso.company.com",
        assetType: "Identity Provider",
        services: ["SAML", "OAuth"],
      },
    });

    expect(result.industryAdjustedScore).toBeGreaterThan(0);
    expect(result.industryAdjustedScore).toBeLessThanOrEqual(100);
    expect(result.assetTier).toBe("Tier_1_Strategic");
    expect(result.tierWeight).toBe(1.5);
    expect(result.shockLevel.level).toBe("High");
    expect(result.formulaBreakdown.carverComponent).toBeGreaterThan(0);
    expect(result.formulaBreakdown.cvssComponent).toBeGreaterThan(0);
  });

  it("should produce higher scores for Tier 1 vs Tier 3 assets", () => {
    const tier1 = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "sso.company.com", assetType: "Identity Provider" },
    });

    const tier3 = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "ws-042.corp.local", assetType: "Workstation" },
    });

    expect(tier1.industryAdjustedScore).toBeGreaterThan(tier3.industryAdjustedScore);
  });

  it("should apply industry modifiers correctly", () => {
    const corporate = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "server.local" },
      tierOverride: "Tier_2_Operational",
    });

    const energy = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      industry: "Energy_Utilities",
      assetInfo: { hostname: "server.local" },
      tierOverride: "Tier_2_Operational",
    });

    // Both may cap at 100, so check combined modifier is higher for energy
    expect(energy.combinedModifier).toBeGreaterThan(corporate.combinedModifier);
    // If both cap at 100, at least verify the base scores reflect the difference
    expect(energy.industryAdjustedScore).toBeGreaterThanOrEqual(corporate.industryAdjustedScore);
  });

  it("should respect BIA multiplier override", () => {
    const withOverride = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "server.local" },
      biaMultiplierOverride: 1.5,
    });

    const withoutOverride = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "server.local" },
    });

    expect(withOverride.industryAdjustedScore).toBeGreaterThanOrEqual(withoutOverride.industryAdjustedScore);
  });

  it("should auto-detect BIA from signals", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 8.0,
      shockComposite: 6.0,
      industry: "Corporate_Enterprise",
      assetInfo: {
        hostname: "mail.company.com",
        services: ["SMTP", "IMAP"],
      },
    });

    expect(result.biaInference).toBeDefined();
    expect(result.biaInference!.signal).toBe("MX Record");
    expect(result.biaInference!.biaMultiplier).toBe(1.4);
  });

  it("should handle zero scores gracefully", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 0,
      cvssScore: 0,
      shockComposite: 0,
      industry: "Corporate_Enterprise",
      assetInfo: { hostname: "server.local" },
    });

    expect(result.industryAdjustedScore).toBe(0);
    expect(result.baseHybridScore).toBe(0);
  });

  it("should handle maximum scores", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 70,
      cvssScore: 10,
      shockComposite: 10,
      industry: "Energy_Utilities",
      assetInfo: { hostname: "scada-master.grid.local", assetType: "SCADA" },
      tierOverride: "Tier_1_Strategic",
      biaMultiplierOverride: 1.5,
    });

    expect(result.industryAdjustedScore).toBeLessThanOrEqual(100);
    expect(result.industryAdjustedScore).toBeGreaterThan(80);
  });
});

// ─── Batch Scoring ──────────────────────────────────────────────────

describe("batchIndustryScore", () => {
  const testAssets = [
    {
      assetId: "asset-1",
      carverTotal: 55,
      cvssScore: 9.0,
      shockComposite: 8.0,
      assetInfo: { hostname: "sso.company.com", assetType: "Identity Provider" },
    },
    {
      assetId: "asset-2",
      carverTotal: 30,
      cvssScore: 5.0,
      shockComposite: 3.0,
      assetInfo: { hostname: "ws-042.corp.local", assetType: "Workstation" },
    },
    {
      assetId: "asset-3",
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      assetInfo: { hostname: "backup.corp.local", assetType: "Backup Server", services: ["Veeam"] },
    },
  ];

  it("should score all assets and sort by risk", () => {
    const result = batchIndustryScore(testAssets, "Corporate_Enterprise");
    expect(result.scores).toHaveLength(3);
    // Should be sorted descending
    for (let i = 1; i < result.scores.length; i++) {
      expect(result.scores[i - 1].score.industryAdjustedScore)
        .toBeGreaterThanOrEqual(result.scores[i].score.industryAdjustedScore);
    }
  });

  it("should compute correct summary statistics", () => {
    const result = batchIndustryScore(testAssets, "Corporate_Enterprise");
    expect(result.summary.totalAssets).toBe(3);
    expect(result.summary.averageScore).toBeGreaterThan(0);
    expect(result.summary.maxScore).toBeGreaterThan(0);
    const bandTotal = result.summary.criticalCount + result.summary.highCount +
      result.summary.mediumCount + result.summary.lowCount;
    expect(bandTotal).toBe(3);
  });

  it("should compute tier distribution", () => {
    const result = batchIndustryScore(testAssets, "Corporate_Enterprise");
    const totalTiers = result.summary.tierDistribution.Tier_1_Strategic +
      result.summary.tierDistribution.Tier_2_Operational +
      result.summary.tierDistribution.Tier_3_Tactical;
    expect(totalTiers).toBe(3);
  });

  it("should handle empty asset list", () => {
    const result = batchIndustryScore([], "Corporate_Enterprise");
    expect(result.scores).toHaveLength(0);
    expect(result.summary.totalAssets).toBe(0);
    expect(result.summary.averageScore).toBe(0);
  });
});

// ─── Utility Functions ──────────────────────────────────────────────

describe("getIndustryVerticals", () => {
  it("should return 6 industry verticals", () => {
    const verticals = getIndustryVerticals();
    expect(verticals).toHaveLength(6);
    for (const v of verticals) {
      expect(v.id).toBeTruthy();
      expect(v.label).toBeTruthy();
      expect(v.assetCount).toBeGreaterThan(0);
    }
  });
});

describe("getIndustryTierBreakdown", () => {
  it("should return 3 tiers for each industry", () => {
    const breakdown = getIndustryTierBreakdown("Corporate_Enterprise");
    expect(breakdown).toHaveLength(3);
    expect(breakdown[0].tier).toBe("Tier_1_Strategic");
    expect(breakdown[0].weight).toBe(1.5);
    expect(breakdown[0].assets.length).toBeGreaterThan(0);
  });
});

describe("detectAllSignals", () => {
  it("should detect multiple signals from complex asset", () => {
    const signals = detectAllSignals({
      hostname: "admin-panel.company.com",
      services: ["SMTP", "MySQL"],
      ports: [3306, 25, 443],
    });
    expect(signals.length).toBeGreaterThanOrEqual(1);
  });

  it("should return empty array for assets with no signals", () => {
    const signals = detectAllSignals({ hostname: "static.cdn.com" });
    expect(signals).toHaveLength(0);
  });
});

// ─── FIPS 199 Constants ─────────────────────────────────────────────────────

describe("FIPS 199 Constants", () => {
  it("should have level map with correct values", () => {
    expect(FIPS_199_LEVEL_MAP.low).toBe(2);
    expect(FIPS_199_LEVEL_MAP.moderate).toBe(5);
    expect(FIPS_199_LEVEL_MAP.high).toBe(9);
  });

  it("should have industry defaults for all 6 verticals and 3 tiers", () => {
    const industries: IndustryVertical[] = [
      "Corporate_Enterprise", "Industrial_OT_Manufacturing",
      "Government_Federal_State", "Healthcare",
      "Financial_Services", "Energy_Utilities",
    ];
    const tiers: AssetTier[] = ["Tier_1_Strategic", "Tier_2_Operational", "Tier_3_Tactical"];
    for (const ind of industries) {
      for (const tier of tiers) {
        const defaults = FIPS_199_INDUSTRY_DEFAULTS[ind][tier];
        expect(defaults.access, `${ind}/${tier}/access`).toBeDefined();
        expect(defaults.storage, `${ind}/${tier}/storage`).toBeDefined();
        expect(defaults.transit, `${ind}/${tier}/transit`).toBeDefined();
        // Each state must have C/I/A
        for (const state of [defaults.access, defaults.storage, defaults.transit]) {
          expect(["low", "moderate", "high"]).toContain(state.confidentiality);
          expect(["low", "moderate", "high"]).toContain(state.integrity);
          expect(["low", "moderate", "high"]).toContain(state.availability);
        }
      }
    }
  });

  it("Healthcare Tier 1 should have high C for storage (ePHI)", () => {
    const hc = FIPS_199_INDUSTRY_DEFAULTS.Healthcare.Tier_1_Strategic;
    expect(hc.storage.confidentiality).toBe("high");
    expect(hc.storage.integrity).toBe("high");
  });

  it("Financial Tier 1 should have high across all states", () => {
    const fin = FIPS_199_INDUSTRY_DEFAULTS.Financial_Services.Tier_1_Strategic;
    for (const state of [fin.access, fin.storage, fin.transit]) {
      expect(state.confidentiality).toBe("high");
      expect(state.integrity).toBe("high");
      expect(state.availability).toBe("high");
    }
  });

  it("Energy Tier 1 should prioritize availability", () => {
    const energy = FIPS_199_INDUSTRY_DEFAULTS.Energy_Utilities.Tier_1_Strategic;
    expect(energy.access.availability).toBe("high");
    expect(energy.storage.availability).toBe("high");
    expect(energy.transit.availability).toBe("high");
  });

  it("OT/Manufacturing Tier 1 should prioritize integrity and availability over confidentiality", () => {
    const ot = FIPS_199_INDUSTRY_DEFAULTS.Industrial_OT_Manufacturing.Tier_1_Strategic;
    expect(ot.access.integrity).toBe("high");
    expect(ot.access.availability).toBe("high");
    expect(ot.access.confidentiality).toBe("moderate");
  });
});

// ─── FIPS 199 High Watermark ────────────────────────────────────────────

describe("computeFips199HighWatermark", () => {
  it("should take the max across all three states", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "low",  integrity: "high",     availability: "moderate" },
      storage: { confidentiality: "high", integrity: "low",      availability: "low" },
      transit: { confidentiality: "low",  integrity: "moderate", availability: "high" },
    };
    const hw = computeFips199HighWatermark(cat);
    expect(hw.confidentiality).toBe("high");  // max of low, high, low
    expect(hw.integrity).toBe("high");        // max of high, low, moderate
    expect(hw.availability).toBe("high");     // max of moderate, low, high
    expect(hw.overallLevel).toBe("high");
  });

  it("should return low when all states are low", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "low", integrity: "low", availability: "low" },
      storage: { confidentiality: "low", integrity: "low", availability: "low" },
      transit: { confidentiality: "low", integrity: "low", availability: "low" },
    };
    const hw = computeFips199HighWatermark(cat);
    expect(hw.overallLevel).toBe("low");
    expect(hw.confidentiality).toBe("low");
  });

  it("should return moderate when highest is moderate", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "moderate", integrity: "low",      availability: "low" },
      storage: { confidentiality: "low",      integrity: "moderate", availability: "low" },
      transit: { confidentiality: "low",      integrity: "low",      availability: "moderate" },
    };
    const hw = computeFips199HighWatermark(cat);
    expect(hw.overallLevel).toBe("moderate");
    expect(hw.confidentiality).toBe("moderate");
    expect(hw.integrity).toBe("moderate");
    expect(hw.availability).toBe("moderate");
  });
});

// ─── FIPS 199 Adjustments ───────────────────────────────────────────────

describe("computeFips199Adjustments", () => {
  it("should compute high mission multiplier for all-high categorization", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "high", integrity: "high", availability: "high" },
      storage: { confidentiality: "high", integrity: "high", availability: "high" },
      transit: { confidentiality: "high", integrity: "high", availability: "high" },
    };
    const adj = computeFips199Adjustments(cat);
    expect(adj.missionMultiplier).toBe(1.8);
    expect(adj.highWatermark.overallLevel).toBe("high");
    expect(adj.carverFloors.criticality).toBe(9);
    expect(adj.shockFloors.scope).toBe(8);
    expect(adj.stateImpacts.access).toBe("high");
    expect(adj.stateImpacts.storage).toBe("high");
    expect(adj.stateImpacts.transit).toBe("high");
  });

  it("should compute low mission multiplier for all-low categorization", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "low", integrity: "low", availability: "low" },
      storage: { confidentiality: "low", integrity: "low", availability: "low" },
      transit: { confidentiality: "low", integrity: "low", availability: "low" },
    };
    const adj = computeFips199Adjustments(cat);
    expect(adj.missionMultiplier).toBe(0.9);
    expect(adj.highWatermark.overallLevel).toBe("low");
    expect(adj.carverFloors.criticality).toBe(2);
  });

  it("should compute moderate mission multiplier for mixed categorization", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "moderate", integrity: "moderate", availability: "low" },
      storage: { confidentiality: "low",      integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "moderate", integrity: "low",      availability: "low" },
    };
    const adj = computeFips199Adjustments(cat);
    expect(adj.missionMultiplier).toBe(1.3);
    expect(adj.highWatermark.overallLevel).toBe("moderate");
  });

  it("should compute per-state impact levels correctly", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "high",     integrity: "low",      availability: "low" },
      storage: { confidentiality: "low",      integrity: "low",      availability: "low" },
      transit: { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
    };
    const adj = computeFips199Adjustments(cat);
    expect(adj.stateImpacts.access).toBe("high");     // high C
    expect(adj.stateImpacts.storage).toBe("low");     // all low
    expect(adj.stateImpacts.transit).toBe("moderate"); // all moderate
  });

  it("should preserve the original states in the result", () => {
    const cat: Fips199Category = {
      access:  { confidentiality: "high", integrity: "moderate", availability: "low" },
      storage: { confidentiality: "low",  integrity: "high",     availability: "moderate" },
      transit: { confidentiality: "moderate", integrity: "low",  availability: "high" },
    };
    const adj = computeFips199Adjustments(cat);
    expect(adj.states).toEqual(cat);
  });
});

// ─── FIPS 199 Industry Defaults ─────────────────────────────────────────

describe("getFips199IndustryDefault", () => {
  it("should return correct defaults for Healthcare Tier 1", () => {
    const def = getFips199IndustryDefault("Healthcare", "Tier_1_Strategic");
    expect(def.storage.confidentiality).toBe("high");
    expect(def.access.availability).toBe("high");
  });

  it("should return all-low for unknown combinations", () => {
    // @ts-ignore - testing fallback
    const def = getFips199IndustryDefault("Unknown_Industry" as any, "Tier_1_Strategic");
    expect(def.access.confidentiality).toBe("low");
    expect(def.storage.integrity).toBe("low");
    expect(def.transit.availability).toBe("low");
  });
});

// ─── FIPS 199 Integration in Enhanced Scoring ──────────────────────────

describe("FIPS 199 in computeIndustryEnhancedScore", () => {
  it("should auto-populate FIPS 199 from industry defaults", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      industry: "Healthcare",
      assetInfo: { hostname: "ehr.hospital.org", assetType: "Electronic Health Record System", description: "Electronic Health Record EHR Systems" },
    });
    expect(result.fips199).toBeDefined();
    expect(result.fips199!.adjustments.highWatermark.overallLevel).toBe("high");
    expect(result.formulaBreakdown.fips199Multiplier).toBe(1.8);
  });

  it("should use explicit FIPS 199 when provided", () => {
    const customFips: Fips199Category = {
      access:  { confidentiality: "low", integrity: "low", availability: "low" },
      storage: { confidentiality: "low", integrity: "low", availability: "low" },
      transit: { confidentiality: "low", integrity: "low", availability: "low" },
    };
    const result = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      industry: "Healthcare",
      assetInfo: { hostname: "server.local" },
      fips199: customFips,
    });
    expect(result.fips199).toBeDefined();
    expect(result.fips199!.adjustments.missionMultiplier).toBe(0.9);
    expect(result.formulaBreakdown.fips199Multiplier).toBe(0.9);
  });

  it("should skip FIPS 199 when skipFips199Defaults is true", () => {
    const result = computeIndustryEnhancedScore({
      carverTotal: 45,
      cvssScore: 7.5,
      shockComposite: 6.0,
      industry: "Healthcare",
      assetInfo: { hostname: "server.local" },
      skipFips199Defaults: true,
    });
    expect(result.fips199).toBeUndefined();
    expect(result.formulaBreakdown.fips199Multiplier).toBe(1.0);
  });

  it("should produce higher scores with high FIPS 199 vs low", () => {
    const highFips: Fips199Category = {
      access:  { confidentiality: "high", integrity: "high", availability: "high" },
      storage: { confidentiality: "high", integrity: "high", availability: "high" },
      transit: { confidentiality: "high", integrity: "high", availability: "high" },
    };
    const lowFips: Fips199Category = {
      access:  { confidentiality: "low", integrity: "low", availability: "low" },
      storage: { confidentiality: "low", integrity: "low", availability: "low" },
      transit: { confidentiality: "low", integrity: "low", availability: "low" },
    };
    const baseInput = {
      carverTotal: 35,
      cvssScore: 6.0,
      shockComposite: 4.0,
      industry: "Corporate_Enterprise" as const,
      assetInfo: { hostname: "server.local" },
      tierOverride: "Tier_2_Operational" as const,
    };
    const highResult = computeIndustryEnhancedScore({ ...baseInput, fips199: highFips });
    const lowResult = computeIndustryEnhancedScore({ ...baseInput, fips199: lowFips });
    expect(highResult.industryAdjustedScore).toBeGreaterThan(lowResult.industryAdjustedScore);
    expect(highResult.formulaBreakdown.fips199Multiplier).toBe(1.8);
    expect(lowResult.formulaBreakdown.fips199Multiplier).toBe(0.9);
  });

  it("should include per-state impacts in FIPS 199 result", () => {
    const mixedFips: Fips199Category = {
      access:  { confidentiality: "high",     integrity: "low",      availability: "moderate" },
      storage: { confidentiality: "low",      integrity: "moderate", availability: "low" },
      transit: { confidentiality: "moderate", integrity: "high",     availability: "high" },
    };
    const result = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Government_Federal_State",
      assetInfo: { hostname: "server.local" },
      fips199: mixedFips,
    });
    expect(result.fips199!.adjustments.stateImpacts.access).toBe("high");
    expect(result.fips199!.adjustments.stateImpacts.storage).toBe("moderate");
    expect(result.fips199!.adjustments.stateImpacts.transit).toBe("high");
  });

  it("should reflect transit-only high impact correctly", () => {
    const transitHigh: Fips199Category = {
      access:  { confidentiality: "low", integrity: "low", availability: "low" },
      storage: { confidentiality: "low", integrity: "low", availability: "low" },
      transit: { confidentiality: "high", integrity: "high", availability: "high" },
    };
    const result = computeIndustryEnhancedScore({
      carverTotal: 40,
      cvssScore: 7.0,
      shockComposite: 5.0,
      industry: "Financial_Services",
      assetInfo: { hostname: "api-gateway.bank.com" },
      fips199: transitHigh,
    });
    // High watermark should be high because transit is all high
    expect(result.fips199!.adjustments.highWatermark.overallLevel).toBe("high");
    expect(result.fips199!.adjustments.stateImpacts.transit).toBe("high");
    expect(result.fips199!.adjustments.stateImpacts.access).toBe("low");
    expect(result.fips199!.adjustments.stateImpacts.storage).toBe("low");
  });
});
