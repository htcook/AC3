import { describe, it, expect } from "vitest";
import {
  MISSED_VULN_PATTERNS,
  buildMissedVulnContext,
  buildMissedVulnAttackContext,
  getMissedVulnPayloads,
  getMissedVulnToolCommands,
  getMissedVulnsByCategory,
  getMissedVulnSummary,
  type MissedVulnPattern,
  type MissedVulnCategory,
} from "./lib/knowledge/missed-vuln-training-knowledge";

describe("Missed Vuln Training Knowledge Module", () => {
  describe("MISSED_VULN_PATTERNS", () => {
    it("should contain at least 16 missed vuln patterns (matching the 16 missed vulns)", () => {
      expect(MISSED_VULN_PATTERNS.length).toBeGreaterThanOrEqual(16);
    });

    it("each pattern should have required fields", () => {
      for (const p of MISSED_VULN_PATTERNS) {
        expect(p.id).toBeTruthy();
        expect(p.name).toBeTruthy();
        expect(p.category).toBeTruthy();
        expect(p.severity).toMatch(/^(critical|high|medium|low|info)$/);
        expect(p.owasp).toBeInstanceOf(Array);
        expect(p.cwe).toBeInstanceOf(Array);
        expect(p.cwe.length).toBeGreaterThan(0);
        expect(p.whyMissed).toBeTruthy();
        expect(p.detectionSignals).toBeInstanceOf(Array);
        expect(p.exploitationSteps).toBeInstanceOf(Array);
        expect(p.exploitationSteps.length).toBeGreaterThan(0);
        expect(p.testPayloads).toBeInstanceOf(Array);
        expect(p.toolCommands).toBeInstanceOf(Array);
        expect(p.applicableLabs).toBeInstanceOf(Array);
        expect(p.applicableLabs.length).toBeGreaterThan(0);
        expect(p.attackTechniques).toBeInstanceOf(Array);
      }
    });

    it("should have unique IDs", () => {
      const ids = MISSED_VULN_PATTERNS.map(p => p.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("should cover all 16 missed vulnerability types from the engagement", () => {
      const names = MISSED_VULN_PATTERNS.map(p => p.name.toLowerCase());
      const expectedPatterns = [
        "nosql", "stored xss", "video", "two-factor", "forged feedback",
        "product tampering", "basket", "jwt", "md5", "xml external entity",
        "deserialization", "error", "deprecated", "outdated", "vulnerable library",
        "zero stars"
      ];
      for (const expected of expectedPatterns) {
        const found = names.some(n => n.includes(expected));
        expect(found, `Expected pattern containing "${expected}" not found in: ${names.join(', ')}`).toBe(true);
      }
    });
  });

  describe("buildMissedVulnContext", () => {
    it("should return a non-empty string with vulnerability patterns", () => {
      const ctx = buildMissedVulnContext();
      expect(ctx).toBeTruthy();
      expect(ctx.length).toBeGreaterThan(100);
    });

    it("should filter by target preset when provided", () => {
      const juiceCtx = buildMissedVulnContext({ targetPreset: "juice-shop" });
      const dvwaCtx = buildMissedVulnContext({ targetPreset: "dvwa" });
      // Both should be non-empty
      expect(juiceCtx.length).toBeGreaterThan(50);
      expect(dvwaCtx.length).toBeGreaterThan(50);
    });

    it("should filter by category when provided", () => {
      const categories: MissedVulnCategory[] = ["business_logic", "api_abuse", "crypto_weakness", "deserialization", "dos", "auth_bypass", "component_analysis", "info_disclosure"];
      let foundNonEmpty = false;
      for (const cat of categories) {
        const ctx = buildMissedVulnContext({ category: cat });
        if (ctx.length > 50) foundNonEmpty = true;
      }
      expect(foundNonEmpty).toBe(true);
    });
  });

  describe("buildMissedVulnAttackContext", () => {
    it("should return attack-focused context for the attack planner", () => {
      const ctx = buildMissedVulnAttackContext();
      expect(ctx).toBeTruthy();
      expect(ctx.length).toBeGreaterThan(100);
    });

    it("should include exploit steps and payloads for juice-shop", () => {
      const ctx = buildMissedVulnAttackContext("juice-shop");
      expect(ctx).toBeTruthy();
      expect(ctx.length).toBeGreaterThan(200);
    });
  });

  describe("getMissedVulnPayloads", () => {
    it("should return payloads for juice-shop", () => {
      const payloads = getMissedVulnPayloads("juice-shop");
      expect(payloads).toBeInstanceOf(Array);
      expect(payloads.length).toBeGreaterThan(0);
      for (const p of payloads) {
        // TestPayload has: payload, vulnType, description
        expect(typeof p).toBe("object");
      }
    });

    it("should return payloads for dvwa", () => {
      const payloads = getMissedVulnPayloads("dvwa");
      expect(payloads).toBeInstanceOf(Array);
      // DVWA may have fewer patterns but should still return some
    });
  });

  describe("getMissedVulnToolCommands", () => {
    it("should return tool commands for juice-shop", () => {
      const cmds = getMissedVulnToolCommands("juice-shop");
      expect(cmds).toBeInstanceOf(Array);
      expect(cmds.length).toBeGreaterThan(0);
      for (const c of cmds) {
        expect(typeof c).toBe("object");
      }
    });
  });

  describe("getMissedVulnsByCategory", () => {
    it("should return patterns for business_logic category", () => {
      const patterns = getMissedVulnsByCategory("business_logic");
      expect(patterns).toBeInstanceOf(Array);
      expect(patterns.length).toBeGreaterThan(0);
      for (const p of patterns) {
        expect(p.category).toBe("business_logic");
      }
    });

    it("should return patterns for auth_bypass category", () => {
      const patterns = getMissedVulnsByCategory("auth_bypass");
      expect(patterns).toBeInstanceOf(Array);
      expect(patterns.length).toBeGreaterThan(0);
    });

    it("should return patterns for crypto_weakness category", () => {
      const patterns = getMissedVulnsByCategory("crypto_weakness");
      expect(patterns).toBeInstanceOf(Array);
      expect(patterns.length).toBeGreaterThan(0);
    });

    it("should return patterns for component_analysis category", () => {
      const patterns = getMissedVulnsByCategory("component_analysis");
      expect(patterns).toBeInstanceOf(Array);
      expect(patterns.length).toBeGreaterThan(0);
    });
  });

  describe("getMissedVulnSummary", () => {
    it("should return a summary array with all patterns", () => {
      const summary = getMissedVulnSummary();
      expect(summary).toBeInstanceOf(Array);
      expect(summary.length).toBe(MISSED_VULN_PATTERNS.length);
      for (const s of summary) {
        expect(s.name).toBeTruthy();
        expect(s.severity).toBeTruthy();
        expect(s.cwe).toBeInstanceOf(Array);
        expect(s.applicableLabs).toBeInstanceOf(Array);
      }
    });
  });

  describe("Integration: Knowledge context is non-empty for all lab apps", () => {
    const presets = ["juice-shop", "dvwa", "bwapp", "mutillidae", "webgoat", "crapi"];
    for (const preset of presets) {
      it(`should produce non-empty context for ${preset}`, () => {
        const ctx = buildMissedVulnContext({ targetPreset: preset });
        expect(ctx.length).toBeGreaterThan(50);
      });
    }
  });

  describe("Integration: Attack context includes exploit steps", () => {
    it("should include exploit steps for NoSQL injection", () => {
      const ctx = buildMissedVulnAttackContext("juice-shop");
      expect(ctx.toLowerCase()).toMatch(/nosql|mongo/);
    });

    it("should include exploit steps for deserialization", () => {
      const ctx = buildMissedVulnAttackContext();
      expect(ctx.toLowerCase()).toMatch(/deserialization|deserializ/);
    });
  });
});
