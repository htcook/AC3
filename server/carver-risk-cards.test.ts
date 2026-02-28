import { describe, it, expect } from "vitest";
import {
  buildExplainableRiskCard,
  inferSector,
  getAllSectorProfiles,
  getCalderaOperationPriority,
  getSectorThreatLikelihood,
  FEDRAMP_PROFILES,
} from "./lib/auto-industry-carver";

describe("CARVER Risk Card Persistence & Batch Scanning", () => {
  describe("Risk card generation for batch domains", () => {
    const testDomains = [
      { domain: "jpmorgan.com", sector: "banking_financial_services", expectedTier: "P1" },
      { domain: "lockheedmartin.com", sector: "defense_aerospace", expectedTier: "P1" },
      { domain: "mayoclinic.org", sector: "healthcare_providers", expectedTier: "P1" },
      { domain: "duke-energy.com", sector: "electric_gas_utilities", expectedTier: "P1" },
      { domain: "state.gov", sector: "federal_government", expectedTier: "P1" },
      { domain: "shopify.com", sector: "saas_tech", expectedTier: "P2" },
    ];

    for (const td of testDomains) {
      it(`generates valid risk card for ${td.domain} (${td.sector})`, () => {
        const card = buildExplainableRiskCard({
          assetId: td.domain,
          assetLabel: `${td.domain} (Test)`,
          domain: td.domain,
          keywords: [],
          assetSignals: [],
          overrideSector: td.sector as any,
        });

        expect(card).toBeDefined();
        expect(card.assetId).toBe(td.domain);
        expect(card.sector).toBe(td.sector);
        expect(card.scores).toBeDefined();
        expect(card.scores.hybrid).toBeGreaterThan(0);
        expect(card.scores.priorityTier).toBeDefined();
        expect(["P0", "P1", "P2", "P3"]).toContain(card.scores.priorityTier);
        expect(card.topDrivers).toBeDefined();
        expect(Array.isArray(card.topDrivers)).toBe(true);
        expect(card.recommendedActions).toBeDefined();
        expect(Array.isArray(card.recommendedActions)).toBe(true);
      });
    }
  });

  describe("Batch scan sector mapping", () => {
    const SECTOR_MAP: Record<string, string> = {
      "Financial": "banking_financial_services",
      "Healthcare": "healthcare_providers",
      "Life Sciences": "pharmaceuticals_biotech",
      "LifeSciences": "pharmaceuticals_biotech",
      "Public Sector": "federal_government",
      "PublicSector": "federal_government",
      "Defense": "defense_aerospace",
      "Energy": "electric_gas_utilities",
      "Utilities": "electric_gas_utilities",
      "Telecom": "saas_tech",
      "Tech": "saas_tech",
      "Retail": "saas_tech",
      "Logistics": "saas_tech",
      "Transportation": "saas_tech",
      "Maritime": "saas_tech",
      "Education": "federal_government",
      "Research": "federal_government",
      "Industrial": "electric_gas_utilities",
      "Manufacturing": "electric_gas_utilities",
      "Media": "saas_tech",
      "Entertainment": "saas_tech",
      "Agriculture": "saas_tech",
      "Construction": "saas_tech",
      "Automotive": "electric_gas_utilities",
    };

    it("maps all CSV sectors to valid CARVER sectors", () => {
      const validSectors = [
        "banking_financial_services",
        "healthcare_providers",
        "pharmaceuticals_biotech",
        "federal_government",
        "defense_aerospace",
        "electric_gas_utilities",
        "saas_tech",
      ];

      for (const [csvSector, carverSector] of Object.entries(SECTOR_MAP)) {
        expect(validSectors).toContain(carverSector);
      }
    });

    it("generates risk cards for all mapped sectors", () => {
      const uniqueSectors = [...new Set(Object.values(SECTOR_MAP))];
      for (const sector of uniqueSectors) {
        const card = buildExplainableRiskCard({
          assetId: `test-${sector}.com`,
          assetLabel: `Test ${sector}`,
          domain: `test-${sector}.com`,
          keywords: [],
          assetSignals: [],
          overrideSector: sector as any,
        });
        expect(card.scores.hybrid).toBeGreaterThan(0);
      }
    });
  });

  describe("Discovery Engine CARVER integration", () => {
    it("generates risk card with asset signals from passive recon", () => {
      const card = buildExplainableRiskCard({
        assetId: "target.com",
        assetLabel: "target.com (Discovery Scan)",
        domain: "target.com",
        keywords: ["nginx", "apache", "mysql"],
        assetSignals: ["MX Record", "SSO", "VPN Gateway", "API Gateway"],
      });

      expect(card).toBeDefined();
      expect(card.scores.hybrid).toBeGreaterThan(0);
      // Asset signals should influence sector inference
      expect(card.sector).toBeDefined();
    });

    it("handles empty asset signals gracefully", () => {
      const card = buildExplainableRiskCard({
        assetId: "unknown.com",
        assetLabel: "unknown.com (Discovery Scan)",
        domain: "unknown.com",
        keywords: [],
        assetSignals: [],
      });

      expect(card).toBeDefined();
      expect(card.scores.hybrid).toBeGreaterThan(0);
      expect(card.sector).toBeDefined();
    });
  });

  describe("Risk card data completeness for DB persistence", () => {
    it("produces all fields needed for carver_risk_cards table", () => {
      const card = buildExplainableRiskCard({
        assetId: "example-bank.com",
        assetLabel: "Example Bank",
        domain: "example-bank.com",
        keywords: ["banking", "finance"],
        assetSignals: ["SSO"],
        overrideSector: "banking_financial_services" as any,
      });

      // Verify all DB-required fields are present
      expect(card.sector).toBeDefined();
      expect(typeof card.confidence).toBe("number");
      expect(card.scores).toBeDefined();
      expect(card.scores.hybrid).toBeDefined();
      expect(card.scores.priorityTier).toBeDefined();
      expect(card.scores.carverShock).toBeDefined();
      expect(card.topDrivers).toBeDefined();
      expect(card.recommendedActions).toBeDefined();
      expect(card.regulatoryProfile).toBeDefined();
      expect(card.calderaPriority).toBeDefined();
      expect(card.threatLikelihood).toBeDefined();
    });

    it("generates valid priority tiers", () => {
      const sectors = [
        "banking_financial_services",
        "defense_aerospace",
        "healthcare_providers",
        "electric_gas_utilities",
        "federal_government",
        "saas_tech",
      ];

      for (const sector of sectors) {
        const card = buildExplainableRiskCard({
          assetId: `test-${sector}.com`,
          assetLabel: `Test ${sector}`,
          domain: `test-${sector}.com`,
          keywords: [],
          assetSignals: [],
          overrideSector: sector as any,
        });

        expect(["P0", "P1", "P2", "P3"]).toContain(card.scores.priorityTier);
      }
    });
  });

  describe("Caldera operation prioritization per sector", () => {
    it("returns valid operation priority for all sectors", () => {
      const sectors = [
        "banking_financial_services",
        "defense_aerospace",
        "healthcare_providers",
        "electric_gas_utilities",
        "federal_government",
        "saas_tech",
      ] as const;

      for (const sector of sectors) {
        const ops = getCalderaOperationPriority({ sector, priorityTier: "P1", regulatory: [] });
        expect(ops).toBeDefined();
        expect(ops.operationTier).toBeDefined();
        expect(ops.operationProfile).toBeDefined();
        expect(ops.objectives).toBeDefined();
        expect(Array.isArray(ops.objectives)).toBe(true);
        expect(ops.recommendedAdversaries).toBeDefined();
        expect(Array.isArray(ops.recommendedAdversaries)).toBe(true);
        expect(ops.recommendedAbilitySets).toBeDefined();
        expect(Array.isArray(ops.recommendedAbilitySets)).toBe(true);
      }
    });
  });

  describe("Threat likelihood per sector", () => {
    it("returns valid threat probabilities for all sectors", () => {
      const sectors = [
        "banking_financial_services",
        "defense_aerospace",
        "healthcare_providers",
        "electric_gas_utilities",
        "federal_government",
        "saas_tech",
      ] as const;

      for (const sector of sectors) {
        const threats = getSectorThreatLikelihood(sector);
        expect(threats).toBeDefined();
        expect(Array.isArray(threats)).toBe(true);
        expect(threats.length).toBeGreaterThan(0);
        for (const t of threats) {
          expect(t.category).toBeDefined();
          expect(t.label).toBeDefined();
          expect(typeof t.probability).toBe("number");
          expect(t.probability).toBeGreaterThanOrEqual(0);
          expect(t.probability).toBeLessThanOrEqual(1);
        }
      }
    });
  });

  describe("FedRAMP profile integration", () => {
    it("returns valid FedRAMP profiles for moderate and high", () => {
      for (const level of ["moderate", "high"] as const) {
        const profile = FEDRAMP_PROFILES[level];
        expect(profile).toBeDefined();
        expect(profile).toHaveProperty('label');
        expect(profile).toHaveProperty('overlayAdjustments');
      }
    });
  });

  describe("Sector profile completeness", () => {
    it("returns profiles for all 6 core sectors", () => {
      const profiles = getAllSectorProfiles();
      expect(profiles.length).toBeGreaterThanOrEqual(6);
      
      const sectorNames = profiles.map(p => p.sector);
      expect(sectorNames).toContain("banking_financial_services");
      expect(sectorNames).toContain("defense_aerospace");
      expect(sectorNames).toContain("healthcare_providers");
      expect(sectorNames).toContain("electric_gas_utilities");
      expect(sectorNames).toContain("federal_government");
      expect(sectorNames).toContain("saas_tech");
    });
  });
});
