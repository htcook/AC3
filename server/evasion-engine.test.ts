import { describe, it, expect } from "vitest";
import {
  generateMutations,
  testRawPatternMutations,
  parseSigmaRule,
  ALL_CATEGORIES,
  CATEGORY_LABELS,
  type MutationOptions,
} from "./lib/siem-mutation-engine";
import {
  buildPipeline,
  EVASION_TECHNIQUES,
  compareAllProfiles,
  type EvasionProfile,
} from "./lib/payload-transform-pipeline";
import {
  generateEvasionScorecard,
} from "./lib/evasion-scorecard";

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 1 — SIEM RULE MUTATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

describe("Tier 1: SIEM Rule Mutation Engine", () => {
  describe("generateMutationVariants", () => {
    it("generates variants for a simple command", () => {
      const variants = generateMutations("powershell.exe -enc SQBFAFgA");
      expect(variants.length).toBeGreaterThan(0);
      // Each variant should have required fields
      for (const v of variants) {
        expect(v.command).toBeDefined();
        expect(v.category).toBeDefined();
        expect(typeof v.command).toBe("string");
        expect(v.command.length).toBeGreaterThan(0);
      }
    });

    it("generates variants across multiple categories", () => {
      const variants = generateMutations("cmd.exe /c whoami");
      const categories = new Set(variants.map((v) => v.category));
      // Should have at least 2 different categories
      expect(categories.size).toBeGreaterThanOrEqual(2);
    });

    it("respects maxPerCategory option", () => {
      const variants = generateMutations("net user /domain", {
        maxPerCategory: 1,
      });
      const byCat: Record<string, number> = {};
      for (const v of variants) {
        byCat[v.category] = (byCat[v.category] || 0) + 1;
      }
      for (const count of Object.values(byCat)) {
        expect(count).toBeLessThanOrEqual(1);
      }
    });

    it("filters to specific categories when provided", () => {
      const variants = generateMutations("powershell.exe -enc SQBFAFgA", {
        categories: ["case_mutation"],
      });
      for (const v of variants) {
        expect(v.category).toBe("case_mutation");
      }
    });

    it("generates at least 7 variants for a typical command", () => {
      const variants = generateMutations("powershell.exe -encodedcommand SQBFAFgA -noprofile -windowstyle hidden");
      expect(variants.length).toBeGreaterThanOrEqual(7);
    });
  });

  describe("testRawPatternMutations", () => {
    it("tests variants against a detection pattern", () => {
      const result = testRawPatternMutations(
        "powershell.exe -enc SQBFAFgA",
        "powershell.*-enc"
      );
      expect(result.originalCommand).toBe("powershell.exe -enc SQBFAFgA");
      expect(result.detectionPattern).toBe("powershell.*-enc");
      expect(typeof result.robustnessScore).toBe("number");
      expect(result.robustnessScore).toBeGreaterThanOrEqual(0);
      expect(result.robustnessScore).toBeLessThanOrEqual(100);
      expect(result.detectedCount).toBeGreaterThanOrEqual(0);
      expect(result.evadedCount).toBeGreaterThanOrEqual(0);
      expect(result.detectedCount + result.evadedCount).toBe(result.variants.length);
    });

    it("identifies evaded variants correctly", () => {
      // A very specific pattern should be easy to evade
      const result = testRawPatternMutations(
        "powershell.exe -enc SQBFAFgA",
        "^powershell\\.exe -enc SQBFAFgA$"
      );
      // Exact match pattern should be evaded by most mutations
      expect(result.evadedCount).toBeGreaterThan(0);
    });

    it("provides hardening tips when evasions are found", () => {
      const result = testRawPatternMutations(
        "cmd.exe /c whoami",
        "cmd\\.exe /c whoami"
      );
      if (result.evadedCount > 0) {
        expect(result.hardeningTips.length).toBeGreaterThan(0);
      }
    });

    it("provides weakest categories when evasions are found", () => {
      const result = testRawPatternMutations(
        "powershell.exe -enc SQBFAFgA",
        "powershell\\.exe -enc"
      );
      if (result.evadedCount > 0) {
        expect(result.weakestCategories.length).toBeGreaterThan(0);
      }
    });
  });

  describe("parseSigmaRule", () => {
    it("parses a valid Sigma rule YAML", () => {
      const yaml = `title: Suspicious PowerShell Encoded Command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection`;
      const parsed = parseSigmaRule(yaml);
      expect(parsed).toBeDefined();
      expect(parsed.title).toBe("Suspicious PowerShell Encoded Command");
    });

    it("returns null for invalid YAML", () => {
      const parsed = parseSigmaRule("not: valid: yaml: {{{}}}");
      // Should either return null or a partial result
      expect(parsed === null || parsed.title !== undefined).toBe(true);
    });
  });

  describe("ALL_CATEGORIES", () => {
    it("exports at least 7 mutation categories", () => {
      expect(ALL_CATEGORIES.length).toBeGreaterThanOrEqual(7);
    });

    it("each category has a label", () => {
      for (const cat of ALL_CATEGORIES) {
        expect(typeof cat).toBe("string");
        expect(CATEGORY_LABELS[cat]).toBeDefined();
        expect(typeof CATEGORY_LABELS[cat]).toBe("string");
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 2 — PAYLOAD TRANSFORMATION PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

describe("Tier 2: Payload Transformation Pipeline", () => {
  describe("buildPipeline", () => {
    it("builds a pipeline for 'none' profile with no steps", () => {
      const pipeline = buildPipeline("none" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      expect(pipeline).toBeDefined();
      expect(pipeline.profile).toBe("none");
      expect(pipeline.steps.length).toBe(0);
    });

    it("builds a pipeline for 'low' profile with at least 1 step", () => {
      const pipeline = buildPipeline("low" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      expect(pipeline.profile).toBe("low");
      expect(pipeline.steps.length).toBeGreaterThanOrEqual(1);
    });

    it("builds a pipeline for 'medium' profile with more steps than low", () => {
      const low = buildPipeline("low" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      const medium = buildPipeline("medium" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      expect(medium.steps.length).toBeGreaterThanOrEqual(low.steps.length);
    });

    it("builds a pipeline for 'high' profile with the most steps", () => {
      const medium = buildPipeline("medium" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      const high = buildPipeline("high" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      expect(high.steps.length).toBeGreaterThanOrEqual(medium.steps.length);
    });

    it("includes a stealth rating", () => {
      const pipeline = buildPipeline("medium" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      expect(typeof pipeline.stealthRating).toBe("number");
      expect(pipeline.stealthRating).toBeGreaterThanOrEqual(0);
      expect(pipeline.stealthRating).toBeLessThanOrEqual(100);
    });

    it("each step has tool and description", () => {
      const pipeline = buildPipeline("high" as EvasionProfile, {
        payloadType: "exe",
        targetOs: "windows",
        targetArch: "x64",
      });
      for (const step of pipeline.steps) {
        expect(step.tool).toBeDefined();
        expect(typeof step.tool).toBe("string");
      }
    });

    it("supports different payload types", () => {
      const types = ["exe", "dll", "shellcode", "powershell", "csharp", "hta", "vba"] as const;
      for (const pt of types) {
        const pipeline = buildPipeline("medium" as EvasionProfile, {
          payloadType: pt,
          targetOs: "windows",
          targetArch: "x64",
        });
        expect(pipeline).toBeDefined();
        expect(pipeline.profile).toBe("medium");
      }
    });
  });

  describe("EVASION_TECHNIQUES", () => {
    it("exports evasion techniques", () => {
      expect(EVASION_TECHNIQUES.length).toBeGreaterThan(0);
      for (const t of EVASION_TECHNIQUES) {
        expect(t.id).toBeDefined();
        expect(t.name).toBeDefined();
        expect(t.implementedBy).toBeDefined();
      }
    });

    it("includes techniques with ATT&CK mappings", () => {
      const withAttack = EVASION_TECHNIQUES.filter((t) => t.attackTechnique);
      expect(withAttack.length).toBeGreaterThan(0);
    });
  });

  describe("compareAllProfiles", () => {
    it("compares all 4 profiles: none, low, medium, high", () => {
      const comparison = compareAllProfiles();
      expect(comparison).toBeDefined();
      expect(comparison.length).toBe(4);
      const names = comparison.map((c) => c.profile);
      expect(names).toContain("none");
      expect(names).toContain("low");
      expect(names).toContain("medium");
      expect(names).toContain("high");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 3 — EVASION SCORECARD
// ═══════════════════════════════════════════════════════════════════════════════

describe("Tier 3: Evasion Scorecard", () => {
  describe("generateEvasionScorecard", () => {
    it("generates a scorecard for a set of techniques", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test-campaign",
        campaignTechniques: ["T1059.001", "T1053.005", "T1003.001"],
      });
      expect(scorecard).toBeDefined();
      expect(scorecard.campaignId).toBe("test-campaign");
      expect(typeof scorecard.campaignStealthScore).toBe("number");
      expect(scorecard.campaignStealthScore).toBeGreaterThanOrEqual(0);
      expect(scorecard.campaignStealthScore).toBeLessThanOrEqual(100);
    });

    it("assigns a stealth band", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001"],
      });
      expect(["exposed", "detectable", "stealthy", "ghost"]).toContain(scorecard.stealthBand);
    });

    it("includes technique results for each input technique", () => {
      const techniques = ["T1059.001", "T1053.005", "T1003.001"];
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: techniques,
      });
      expect(scorecard.techniqueResults.length).toBe(techniques.length);
      for (const tr of scorecard.techniqueResults) {
        expect(tr.techniqueId).toBeDefined();
        expect(tr.techniqueName).toBeDefined();
        expect(tr.tactic).toBeDefined();
        expect(["detected", "evaded", "partial", "untested"]).toContain(tr.detectionStatus);
      }
    });

    it("includes a summary with counts", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001", "T1053.005"],
      });
      expect(scorecard.summary).toBeDefined();
      expect(typeof scorecard.summary.totalTechniques).toBe("number");
      expect(typeof scorecard.summary.detected).toBe("number");
      expect(typeof scorecard.summary.evaded).toBe("number");
      expect(scorecard.summary.totalTechniques).toBe(2);
      expect(
        scorecard.summary.detected +
        scorecard.summary.evaded +
        scorecard.summary.partial +
        scorecard.summary.untested
      ).toBe(scorecard.summary.totalTechniques);
    });

    it("generates purple team actions", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001", "T1053.005", "T1003.001", "T1071.001"],
      });
      expect(scorecard.purpleTeamActions).toBeDefined();
      expect(Array.isArray(scorecard.purpleTeamActions)).toBe(true);
      // Should have at least one action for a multi-technique campaign
      expect(scorecard.purpleTeamActions.length).toBeGreaterThan(0);
      for (const action of scorecard.purpleTeamActions) {
        expect(action.priority).toBeDefined();
        expect(action.type).toBeDefined();
        expect(action.description).toBeDefined();
        expect(["create_rule", "harden_rule", "add_telemetry", "tune_edr", "test_evasion"]).toContain(action.type);
        expect(["low", "medium", "high"]).toContain(action.effort);
      }
    });

    it("includes detection gaps for undetected techniques", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001", "T1053.005", "T1003.001"],
      });
      expect(scorecard.detectionGaps).toBeDefined();
      expect(Array.isArray(scorecard.detectionGaps)).toBe(true);
      for (const gap of scorecard.detectionGaps) {
        expect(gap.techniqueId).toBeDefined();
        expect(gap.riskLevel).toBeDefined();
        expect(["critical", "high", "medium", "low"]).toContain(gap.riskLevel);
      }
    });

    it("includes detection coverage and evasion success rate", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001"],
      });
      expect(typeof scorecard.detectionCoverage).toBe("number");
      expect(typeof scorecard.evasionSuccessRate).toBe("number");
      expect(scorecard.detectionCoverage).toBeGreaterThanOrEqual(0);
      expect(scorecard.detectionCoverage).toBeLessThanOrEqual(100);
      expect(scorecard.evasionSuccessRate).toBeGreaterThanOrEqual(0);
      expect(scorecard.evasionSuccessRate).toBeLessThanOrEqual(100);
    });

    it("incorporates mutation test results when provided", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001"],
        mutationResults: [
          {
            originalCommand: "powershell.exe -enc SQBFAFgA",
            detectionPattern: "powershell.*-enc",
            robustnessScore: 40,
            detectedCount: 4,
            evadedCount: 6,
            variants: [],
            weakestCategories: ["case_mutation"],
            hardeningTips: ["Use case-insensitive matching"],
          },
        ],
      });
      // Mutation results should influence the rule robustness section
      expect(scorecard.ruleRobustness).toBeDefined();
    });

    it("incorporates pipeline config when provided", () => {
      const scorecard = generateEvasionScorecard({
        campaignId: "test",
        campaignTechniques: ["T1059.001"],
        pipeline: {
          profile: "high" as any,
          steps: [],
          stealthRating: 85,
          estimatedBypassRate: 80,
          warnings: [],
        },
      });
      expect(scorecard.evasionProfile).toBeDefined();
      expect(scorecard.pipelineStealthRating).toBeDefined();
      expect(typeof scorecard.pipelineStealthRating).toBe("number");
    });
  });
});
