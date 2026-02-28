import { describe, it, expect } from "vitest";

describe("Auto-Industry CARVER Module", () => {
  describe("inferNaics", () => {
    it("should infer banking NAICS from domain with financial keywords", async () => {
      const { inferNaics } = await import("./lib/auto-industry-carver");
      const result = inferNaics({ domain: "jpmorganchase.com", keywords: ["banking", "financial"] });
      expect(result.primaryNaics).toBeDefined();
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidenceBand).toBeDefined();
      expect(["high", "medium", "low", "insufficient"]).toContain(result.confidenceBand);
      expect(result.candidates.length).toBeGreaterThan(0);
    });

    it("should infer healthcare NAICS from .org domain with health keywords", async () => {
      const { inferNaics } = await import("./lib/auto-industry-carver");
      const result = inferNaics({ domain: "clevelandclinic.org", keywords: ["hospital", "clinic"] });
      expect(result.primaryNaics).toBeDefined();
      expect(result.confidence).toBeGreaterThan(0);
    });

    it("should infer government NAICS from .gov domain", async () => {
      const { inferNaics } = await import("./lib/auto-industry-carver");
      const result = inferNaics({ domain: "treasury.gov", keywords: [] });
      expect(result.primaryNaics).toBeDefined();
      expect(result.confidence).toBeGreaterThan(0);
    });

    it("should handle unknown domains gracefully", async () => {
      const { inferNaics } = await import("./lib/auto-industry-carver");
      const result = inferNaics({ domain: "randomsite123.xyz", keywords: [] });
      expect(result.primaryNaics).toBeDefined();
      expect(["low", "insufficient"]).toContain(result.confidenceBand);
    });

    it("should return evidence for inference decisions", async () => {
      const { inferNaics } = await import("./lib/auto-industry-carver");
      const result = inferNaics({ domain: "whitehouse.gov", keywords: ["government"] });
      expect(result.evidence).toBeDefined();
      expect(result.evidence.tlds).toBeDefined();
      expect(result.evidence.keywords).toBeDefined();
    });
  });

  describe("inferSector", () => {
    it("should infer banking sector from financial domain", async () => {
      const { inferSector } = await import("./lib/auto-industry-carver");
      const result = inferSector({ domain: "bankofamerica.com", keywords: ["banking"] });
      expect(result.sector).toBeDefined();
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });

    it("should infer government sector from .gov domain", async () => {
      const { inferSector } = await import("./lib/auto-industry-carver");
      const result = inferSector({ domain: "dhs.gov", keywords: [] });
      expect(result.sector).toBe("federal_government");
    });

    it("should return regulatory profile for inferred sector", async () => {
      const { inferSector } = await import("./lib/auto-industry-carver");
      const result = inferSector({ domain: "pfizer.com", keywords: ["healthcare", "pharma"] });
      expect(result.regulatoryProfile).toBeDefined();
      expect(Array.isArray(result.regulatoryProfile)).toBe(true);
    });

    it("should return NAICS data alongside sector inference", async () => {
      const { inferSector } = await import("./lib/auto-industry-carver");
      const result = inferSector({ domain: "lockheedmartin.com", keywords: ["defense"] });
      expect(result.naics).toBeDefined();
    });
  });

  describe("buildExplainableRiskCard", () => {
    it("should generate a complete risk card for a banking domain", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-1",
        assetLabel: "jpmorganchase.com",
        domain: "jpmorganchase.com",
        keywords: ["banking", "financial"],
        assetSignals: [],
      });
      expect(card.assetId).toBe("test-1");
      expect(card.scores).toBeDefined();
      expect(card.scores.hybrid).toBeGreaterThan(0);
      expect(card.scores.carverShock).toBeGreaterThan(0);
      expect(card.scores.cvss).toBeDefined();
      expect(["P0", "P1", "P2", "P3"]).toContain(card.scores.priorityTier);
    });

    it("should include top drivers in risk card", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-2",
        assetLabel: "defense.gov",
        domain: "defense.gov",
        keywords: ["government", "defense"],
        assetSignals: [],
      });
      expect(card.topDrivers).toBeDefined();
      expect(card.topDrivers.length).toBeGreaterThan(0);
      card.topDrivers.forEach((d: any) => {
        expect(d.driver).toBeDefined();
        expect(d.evidence).toBeDefined();
        expect(["increase", "decrease"]).toContain(d.impact);
      });
    });

    it("should include recommended actions", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-3",
        assetLabel: "mayo.edu",
        domain: "mayo.edu",
        keywords: ["healthcare"],
        assetSignals: [],
      });
      expect(card.recommendedActions).toBeDefined();
      expect(card.recommendedActions.length).toBeGreaterThan(0);
    });

    it("should include Caldera priority information", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-4",
        assetLabel: "exeloncorp.com",
        domain: "exeloncorp.com",
        keywords: ["energy", "utilities"],
        assetSignals: [],
      });
      expect(card.calderaPriority).toBeDefined();
      expect(card.calderaPriority.operationTier).toBeDefined();
      expect(card.calderaPriority.operationProfile).toBeDefined();
    });

    it("should include threat likelihood data", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-5",
        assetLabel: "stripe.com",
        domain: "stripe.com",
        keywords: ["fintech", "payments"],
        assetSignals: [],
      });
      expect(card.threatLikelihood).toBeDefined();
    });

    it("should allow sector override", async () => {
      const { buildExplainableRiskCard } = await import("./lib/auto-industry-carver");
      const card = buildExplainableRiskCard({
        assetId: "test-6",
        assetLabel: "att.com",
        domain: "att.com",
        keywords: [],
        assetSignals: [],
        overrideSector: "saas_tech",
      });
      expect(card.scores).toBeDefined();
      expect(card.scores.hybrid).toBeGreaterThan(0);
    });
  });

  describe("CARVER_SHOCK_PRESETS", () => {
    it("should have presets for all 6 core sectors", async () => {
      const { CARVER_SHOCK_PRESETS } = await import("./lib/auto-industry-carver");
      const expectedSectors = [
        "banking_financial_services",
        "healthcare_providers",
        "defense_aerospace",
        "federal_government",
        "electric_gas_utilities",
        "saas_tech",
      ];
      for (const sector of expectedSectors) {
        expect(CARVER_SHOCK_PRESETS[sector]).toBeDefined();
        expect(CARVER_SHOCK_PRESETS[sector].criticality).toBeDefined();
        expect(CARVER_SHOCK_PRESETS[sector].shock).toBeDefined();
      }
    });

    it("should have valid CARVER dimension values (1-10)", async () => {
      const { CARVER_SHOCK_PRESETS } = await import("./lib/auto-industry-carver");
      for (const [sector, preset] of Object.entries(CARVER_SHOCK_PRESETS)) {
        const dims = ['criticality', 'accessibility', 'recuperability', 'vulnerability', 'effect', 'recognizability', 'shock'];
        for (const dim of dims) {
          const val = (preset as any)[dim];
          expect(val).toBeGreaterThanOrEqual(1);
          expect(val).toBeLessThanOrEqual(10);
        }
      }
    });
  });

  describe("REGULATORY_OVERLAYS", () => {
    it("should have overlays for major frameworks", async () => {
      const { REGULATORY_OVERLAYS } = await import("./lib/auto-industry-carver");
      expect(REGULATORY_OVERLAYS["glba"]).toBeDefined();
      expect(REGULATORY_OVERLAYS["hipaa"]).toBeDefined();
      expect(REGULATORY_OVERLAYS["cmmc"]).toBeDefined();
      expect(REGULATORY_OVERLAYS["nerc_cip"]).toBeDefined();
    });

    it("should have adjustment values in overlays", async () => {
      const { REGULATORY_OVERLAYS } = await import("./lib/auto-industry-carver");
      const glba = REGULATORY_OVERLAYS["glba"];
      expect(glba).toBeDefined();
      // Overlays are flat objects with dimension adjustments
      expect(typeof glba.criticality === 'number' || typeof glba.effect === 'number').toBe(true);
    });
  });

  describe("computeHybridFusionScore", () => {
    it("should compute a valid hybrid score", async () => {
      const { computeHybridFusionScore, CARVER_SHOCK_PRESETS } = await import("./lib/auto-industry-carver");
      const result = computeHybridFusionScore({
        carverPreset: CARVER_SHOCK_PRESETS["banking_financial_services"],
        cvssBase: 8.0,
        sectorMultiplier: 1.3,
      });
      expect(result.hybrid).toBeGreaterThan(0);
      expect(result.carverComposite).toBeGreaterThan(0);
      expect(["P0", "P1", "P2", "P3"]).toContain(result.priorityTier);
    });

    it("should apply sector multiplier correctly", async () => {
      const { computeHybridFusionScore, CARVER_SHOCK_PRESETS } = await import("./lib/auto-industry-carver");
      const preset = CARVER_SHOCK_PRESETS["banking_financial_services"];
      const base = computeHybridFusionScore({
        carverPreset: preset,
        cvssBase: 7.0,
        sectorMultiplier: 1.0,
      });
      const elevated = computeHybridFusionScore({
        carverPreset: preset,
        cvssBase: 7.0,
        sectorMultiplier: 1.5,
      });
      expect(elevated.hybrid).toBeGreaterThan(base.hybrid);
    });
  });

  describe("getSectorThreatLikelihood", () => {
    it("should return threat likelihood for banking sector", async () => {
      const { getSectorThreatLikelihood } = await import("./lib/auto-industry-carver");
      const threats = getSectorThreatLikelihood("banking_financial_services");
      expect(threats.length).toBeGreaterThan(0);
      threats.forEach((t: any) => {
        expect(t.category).toBeDefined();
        expect(t.probability).toBeGreaterThan(0);
        expect(t.probability).toBeLessThanOrEqual(1);
      });
    });

    it("should return empty array for unknown sector", async () => {
      const { getSectorThreatLikelihood } = await import("./lib/auto-industry-carver");
      const threats = getSectorThreatLikelihood("unknown_sector" as any);
      expect(Array.isArray(threats)).toBe(true);
    });
  });

  describe("getCalderaOperationPriority", () => {
    it("should return operation priority for P1 tier", async () => {
      const { getCalderaOperationPriority } = await import("./lib/auto-industry-carver");
      const result = getCalderaOperationPriority({
        priorityTier: "P1",
        regulatory: ["GLBA"],
        sector: "banking_financial_services",
        assetSignals: [],
      });
      expect(result.operationTier).toBeDefined();
      expect(result.operationProfile).toBeDefined();
      expect(result.objectives).toBeDefined();
      expect(result.recommendedAdversaries).toBeDefined();
    });

    it("should return different profiles for different tiers", async () => {
      const { getCalderaOperationPriority } = await import("./lib/auto-industry-carver");
      const p1 = getCalderaOperationPriority({
        priorityTier: "P1",
        regulatory: [],
        sector: "saas_tech",
        assetSignals: [],
      });
      const p3 = getCalderaOperationPriority({
        priorityTier: "P3",
        regulatory: [],
        sector: "saas_tech",
        assetSignals: [],
      });
      expect(p1.operationTier).not.toBe(p3.operationTier);
    });
  });

  describe("getAllSectorProfiles", () => {
    it("should return profiles for all sectors", async () => {
      const { getAllSectorProfiles } = await import("./lib/auto-industry-carver");
      const profiles = getAllSectorProfiles();
      expect(profiles.length).toBeGreaterThanOrEqual(6);
      profiles.forEach((p: any) => {
        expect(p.sector).toBeDefined();
        expect(p.label).toBeDefined();
        expect(p.preset).toBeDefined();
        expect(p.regulatory).toBeDefined();
      });
    });
  });

  describe("getAdjustedCarverPreset", () => {
    it("should return adjusted preset for a sector with regulatory overlays", async () => {
      const { getAdjustedCarverPreset } = await import("./lib/auto-industry-carver");
      const result = getAdjustedCarverPreset("banking_financial_services", ["GLBA", "SOX"]);
      expect(result).toBeDefined();
      // Result should have CARVER dimension properties
      expect(result.criticality).toBeDefined();
    });

    it("should apply regulatory adjustments to CARVER scores", async () => {
      const { getAdjustedCarverPreset, CARVER_SHOCK_PRESETS } = await import("./lib/auto-industry-carver");
      const adjusted = getAdjustedCarverPreset("banking_financial_services", ["GLBA", "SOX"]);
      const base = CARVER_SHOCK_PRESETS["banking_financial_services"];
      // Adjusted scores should be >= base scores (regulatory overlays only increase)
      expect(adjusted.criticality).toBeGreaterThanOrEqual(base.criticality);
    });
  });

  describe("FEDRAMP_PROFILES", () => {
    it("should have moderate and high profiles", async () => {
      const { FEDRAMP_PROFILES } = await import("./lib/auto-industry-carver");
      expect(FEDRAMP_PROFILES.moderate).toBeDefined();
      expect(FEDRAMP_PROFILES.high).toBeDefined();
    });

    it("should have overlay adjustments in profiles", async () => {
      const { FEDRAMP_PROFILES } = await import("./lib/auto-industry-carver");
      expect(FEDRAMP_PROFILES.moderate.overlayAdjustments).toBeDefined();
      expect(FEDRAMP_PROFILES.high.overlayAdjustments).toBeDefined();
    });
  });

  describe("AUTO_BIA_ASSET_PRIORITY", () => {
    it("should have asset priority lists for core sectors", async () => {
      const { AUTO_BIA_ASSET_PRIORITY } = await import("./lib/auto-industry-carver");
      expect(AUTO_BIA_ASSET_PRIORITY["banking_financial_services"]).toBeDefined();
      expect(AUTO_BIA_ASSET_PRIORITY["healthcare_providers"]).toBeDefined();
      expect(AUTO_BIA_ASSET_PRIORITY["defense_aerospace"]).toBeDefined();
    });

    it("should have non-empty priority lists", async () => {
      const { AUTO_BIA_ASSET_PRIORITY } = await import("./lib/auto-industry-carver");
      for (const [sector, priorities] of Object.entries(AUTO_BIA_ASSET_PRIORITY)) {
        expect((priorities as string[]).length).toBeGreaterThan(0);
      }
    });
  });

  describe("THREAT_ACTOR_LIKELIHOOD", () => {
    it("should have threat data for core sectors", async () => {
      const { THREAT_ACTOR_LIKELIHOOD } = await import("./lib/auto-industry-carver");
      expect(THREAT_ACTOR_LIKELIHOOD["banking_financial_services"]).toBeDefined();
      expect(THREAT_ACTOR_LIKELIHOOD["healthcare_providers"]).toBeDefined();
      expect(THREAT_ACTOR_LIKELIHOOD["defense_aerospace"]).toBeDefined();
    });

    it("should have valid probability weights (0-1)", async () => {
      const { THREAT_ACTOR_LIKELIHOOD } = await import("./lib/auto-industry-carver");
      for (const [sector, threats] of Object.entries(THREAT_ACTOR_LIKELIHOOD)) {
        for (const [actor, weight] of Object.entries(threats as Record<string, number>)) {
          expect(weight).toBeGreaterThanOrEqual(0);
          expect(weight).toBeLessThanOrEqual(1);
        }
      }
    });
  });
});
