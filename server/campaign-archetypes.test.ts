import { describe, it, expect } from "vitest";
import {
  BUILT_IN_ARCHETYPES,
  computeActorArchetypeOverlap,
} from "./lib/campaign-archetypes";

describe("Campaign Archetypes", () => {
  describe("BUILT_IN_ARCHETYPES", () => {
    it("should have 8 built-in archetypes", () => {
      expect(BUILT_IN_ARCHETYPES.length).toBe(8);
    });

    it("each archetype should have required fields", () => {
      for (const arch of BUILT_IN_ARCHETYPES) {
        expect(arch.slug).toBeTruthy();
        expect(arch.name).toBeTruthy();
        expect(arch.category).toBeTruthy();
        expect(arch.description).toBeTruthy();
        expect(arch.killChainPhases.length).toBeGreaterThan(0);
        expect(arch.defaultTechniques.length).toBeGreaterThan(0);
        expect(arch.defaultAbilities.length).toBeGreaterThan(0);
        expect(arch.targetPlatforms.length).toBeGreaterThan(0);
        expect(arch.prerequisites.length).toBeGreaterThan(0);
        expect(arch.detectionGuidance).toBeTruthy();
        expect(["low", "medium", "high", "expert"]).toContain(arch.complexity);
      }
    });

    it("should have unique slugs", () => {
      const slugs = BUILT_IN_ARCHETYPES.map((a) => a.slug);
      expect(new Set(slugs).size).toBe(slugs.length);
    });

    it("each technique should have id, name, and tactic", () => {
      for (const arch of BUILT_IN_ARCHETYPES) {
        for (const tech of arch.defaultTechniques) {
          expect(tech.id).toMatch(/^T\d{4}/);
          expect(tech.name).toBeTruthy();
          expect(tech.tactic).toBeTruthy();
        }
      }
    });

    it("each ability should have sequential steps", () => {
      for (const arch of BUILT_IN_ARCHETYPES) {
        const steps = arch.defaultAbilities.map((a) => a.step);
        for (let i = 0; i < steps.length; i++) {
          expect(steps[i]).toBe(i + 1);
        }
      }
    });

    it("should cover all 8 categories", () => {
      const categories = new Set(BUILT_IN_ARCHETYPES.map((a) => a.category));
      expect(categories).toContain("saas_oauth_compromise");
      expect(categories).toContain("token_abuse");
      expect(categories).toContain("cloud_lateral_movement");
      expect(categories).toContain("supply_chain");
      expect(categories).toContain("credential_harvesting");
      expect(categories).toContain("ransomware_deployment");
      expect(categories).toContain("data_exfiltration");
      expect(categories).toContain("persistence_implant");
    });
  });

  describe("computeActorArchetypeOverlap", () => {
    it("should find exact technique matches", () => {
      const actorTechniques = [
        { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access", score: 80 },
        { id: "T1098.003", name: "Additional Cloud Roles", tactic: "persistence", score: 70 },
        { id: "T1999", name: "Unrelated Technique", tactic: "other", score: 50 },
      ];
      const archetype = BUILT_IN_ARCHETYPES.find((a) => a.slug === "saas-oauth-compromise")!;
      const overlap = computeActorArchetypeOverlap(actorTechniques, archetype);

      expect(overlap.length).toBe(2);
      expect(overlap[0].id).toBe("T1566.002");
      expect(overlap[0].actorScore).toBe(80);
      expect(overlap[1].id).toBe("T1098.003");
    });

    it("should match parent techniques (e.g., T1566 matches T1566.001)", () => {
      const actorTechniques = [
        { id: "T1566", name: "Phishing", tactic: "initial-access", score: 90 },
      ];
      const archetype = BUILT_IN_ARCHETYPES.find((a) => a.slug === "saas-oauth-compromise")!;
      const overlap = computeActorArchetypeOverlap(actorTechniques, archetype);

      // T1566 should match T1566.002 in the archetype
      expect(overlap.length).toBeGreaterThanOrEqual(1);
    });

    it("should return empty array when no overlap", () => {
      const actorTechniques = [
        { id: "T9999", name: "Fake Technique", tactic: "fake" },
      ];
      const archetype = BUILT_IN_ARCHETYPES.find((a) => a.slug === "saas-oauth-compromise")!;
      const overlap = computeActorArchetypeOverlap(actorTechniques, archetype);

      expect(overlap.length).toBe(0);
    });

    it("should sort results by actorScore descending", () => {
      const actorTechniques = [
        { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access", score: 30 },
        { id: "T1098.003", name: "Additional Cloud Roles", tactic: "persistence", score: 90 },
        { id: "T1114.002", name: "Remote Email Collection", tactic: "collection", score: 60 },
      ];
      const archetype = BUILT_IN_ARCHETYPES.find((a) => a.slug === "saas-oauth-compromise")!;
      const overlap = computeActorArchetypeOverlap(actorTechniques, archetype);

      for (let i = 1; i < overlap.length; i++) {
        expect(overlap[i - 1].actorScore).toBeGreaterThanOrEqual(overlap[i].actorScore);
      }
    });

    it("should default actorScore to 50 when not provided", () => {
      const actorTechniques = [
        { id: "T1566.002", name: "Spearphishing Link" },
      ];
      const archetype = BUILT_IN_ARCHETYPES.find((a) => a.slug === "saas-oauth-compromise")!;
      const overlap = computeActorArchetypeOverlap(actorTechniques, archetype);

      expect(overlap.length).toBe(1);
      expect(overlap[0].actorScore).toBe(50);
    });
  });
});
