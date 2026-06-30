import { describe, it, expect } from "vitest";

const importModule = () => import("./lib/knowledge/fp-suppression-rules");

describe("FP Suppression Rules", () => {
  describe("FP_SUPPRESSION_RULES constant", () => {
    it("should export a non-empty array of rules", async () => {
      const { FP_SUPPRESSION_RULES } = await importModule();
      expect(Array.isArray(FP_SUPPRESSION_RULES)).toBe(true);
      expect(FP_SUPPRESSION_RULES.length).toBeGreaterThan(0);
    });

    it("each rule should have required fields", async () => {
      const { FP_SUPPRESSION_RULES } = await importModule();
      for (const rule of FP_SUPPRESSION_RULES) {
        expect(rule).toHaveProperty("id");
        expect(rule).toHaveProperty("name");
        expect(rule).toHaveProperty("description");
        expect(rule).toHaveProperty("category");
        expect(rule).toHaveProperty("enabledByDefault");
        expect(rule).toHaveProperty("severityFilter");
        expect(rule).toHaveProperty("sourcePatterns");
        expect(rule).toHaveProperty("titlePatterns");
        expect(rule).toHaveProperty("tpRisk");
        expect(rule).toHaveProperty("rationale");
      }
    });

    it("each rule should have a valid tpRisk level", async () => {
      const { FP_SUPPRESSION_RULES } = await importModule();
      for (const rule of FP_SUPPRESSION_RULES) {
        expect(["low", "medium", "high"]).toContain(rule.tpRisk);
      }
    });

    it("each rule should have a valid category", async () => {
      const { FP_SUPPRESSION_RULES } = await importModule();
      const validCategories = [
        "informational_header", "service_banner", "unverified_cve",
        "config_observation", "robots_disclosure", "cookie_flag",
        "http_method", "etag_leak", "redirect_info", "duplicate_finding"
      ];
      for (const rule of FP_SUPPRESSION_RULES) {
        expect(validCategories).toContain(rule.category);
      }
    });

    it("all rules should have unique IDs", async () => {
      const { FP_SUPPRESSION_RULES } = await importModule();
      const ids = FP_SUPPRESSION_RULES.map(r => r.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
  });

  describe("getSuppressionProfiles", () => {
    it("should return all profiles", async () => {
      const { getSuppressionProfiles } = await importModule();
      const profiles = getSuppressionProfiles();
      expect(Array.isArray(profiles)).toBe(true);
      expect(profiles.length).toBe(4);
    });

    it("should have aggressive, balanced, conservative, and none profiles", async () => {
      const { getSuppressionProfiles } = await importModule();
      const profiles = getSuppressionProfiles();
      const ids = profiles.map(p => p.id);
      expect(ids).toContain("aggressive");
      expect(ids).toContain("balanced");
      expect(ids).toContain("conservative");
      expect(ids).toContain("none");
    });

    it("aggressive should have more enabled rules than balanced", async () => {
      const { getSuppressionProfiles } = await importModule();
      const profiles = getSuppressionProfiles();
      const aggressive = profiles.find(p => p.id === "aggressive")!;
      const balanced = profiles.find(p => p.id === "balanced")!;
      expect(aggressive.enabledCount).toBeGreaterThanOrEqual(balanced.enabledCount);
    });

    it("none profile should have zero enabled rules", async () => {
      const { getSuppressionProfiles } = await importModule();
      const profiles = getSuppressionProfiles();
      const none = profiles.find(p => p.id === "none")!;
      expect(none.enabledCount).toBe(0);
    });
  });

  describe("applySuppressionRules", () => {
    const mockFindings = [
      // Nikto informational noise - should be suppressed
      { finding: { title: "[Nikto] Uncommon header 'x-frame-options' found", severity: "info", source: "nikto" }, agentClass: "nikto" },
      { finding: { title: "[Nikto] The anti-clickjacking X-Frame-Options header is not present", severity: "info", source: "nikto" }, agentClass: "nikto" },
      { finding: { title: "[Nikto] Server leaks inodes via ETags", severity: "info", source: "nikto" }, agentClass: "nikto" },
      { finding: { title: "[Nikto] Allowed HTTP Methods: GET, HEAD, POST, OPTIONS", severity: "info", source: "nikto" }, agentClass: "nikto" },
      // Real findings - should NOT be suppressed (high/critical severity)
      { finding: { title: "SQL Injection in login form", severity: "high", source: "zap" }, agentClass: "zap" },
      { finding: { title: "Cross-Site Scripting (XSS) Reflected", severity: "high", source: "nuclei" }, agentClass: "nuclei" },
      { finding: { title: "Remote Code Execution via deserialization", severity: "critical", source: "nuclei" }, agentClass: "nuclei" },
    ];

    it("aggressive profile should suppress informational noise but keep real findings", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "aggressive");
      expect(result.suppressed.length).toBeGreaterThan(0);
      // Real findings (high/critical) should always be kept
      const keptTitles = result.kept.map(f => f.finding.title);
      expect(keptTitles).toContain("SQL Injection in login form");
      expect(keptTitles).toContain("Cross-Site Scripting (XSS) Reflected");
      expect(keptTitles).toContain("Remote Code Execution via deserialization");
    });

    it("none profile should suppress nothing", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "none");
      expect(result.kept.length).toBe(mockFindings.length);
      expect(result.suppressed.length).toBe(0);
    });

    it("should return stats with total, kept, and suppressed counts", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "balanced");
      expect(result.stats).toHaveProperty("total");
      expect(result.stats).toHaveProperty("kept");
      expect(result.stats).toHaveProperty("suppressed");
      expect(result.stats.total).toBe(mockFindings.length);
      expect(result.stats.kept + result.stats.suppressed).toBe(result.stats.total);
    });

    it("should track suppression by rule in stats", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "aggressive");
      expect(result.stats).toHaveProperty("byRule");
      expect(typeof result.stats.byRule).toBe("object");
    });

    it("should track suppression by category in stats", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "aggressive");
      expect(result.stats).toHaveProperty("byCategory");
      expect(typeof result.stats.byCategory).toBe("object");
    });

    it("custom rules should override profile defaults", async () => {
      const { applySuppressionRules, FP_SUPPRESSION_RULES } = await importModule();
      // Disable all rules
      const allDisabled: Record<string, boolean> = {};
      FP_SUPPRESSION_RULES.forEach(r => { allDisabled[r.id] = false; });
      const result = applySuppressionRules(mockFindings, "aggressive", allDisabled);
      // With all rules disabled, nothing should be suppressed
      expect(result.suppressed.length).toBe(0);
      expect(result.kept.length).toBe(mockFindings.length);
    });

    it("should never suppress critical severity findings", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "aggressive");
      const suppressedSeverities = result.suppressed.map(f => f.finding.severity);
      expect(suppressedSeverities).not.toContain("critical");
    });

    it("should never suppress high severity findings", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules(mockFindings, "aggressive");
      const suppressedSeverities = result.suppressed.map(f => f.finding.severity);
      expect(suppressedSeverities).not.toContain("high");
    });

    it("should handle empty findings array", async () => {
      const { applySuppressionRules } = await importModule();
      const result = applySuppressionRules([], "balanced");
      expect(result.kept).toEqual([]);
      expect(result.suppressed).toEqual([]);
      expect(result.stats.total).toBe(0);
    });
  });

  describe("getSuppressionRuleSummary", () => {
    it("should return a formatted summary of all rules", async () => {
      const { getSuppressionRuleSummary } = await importModule();
      const summary = getSuppressionRuleSummary();
      expect(Array.isArray(summary)).toBe(true);
      expect(summary.length).toBeGreaterThan(0);
      for (const item of summary) {
        expect(item).toHaveProperty("id");
        expect(item).toHaveProperty("name");
        expect(item).toHaveProperty("description");
        expect(item).toHaveProperty("category");
        expect(item).toHaveProperty("tpRisk");
        expect(item).toHaveProperty("enabledByDefault");
        expect(item).toHaveProperty("estimatedSuppression");
      }
    });
  });

  describe("buildFPSuppressionContext", () => {
    it("should return a non-empty string for LLM injection", async () => {
      const { buildFPSuppressionContext } = await importModule();
      const context = buildFPSuppressionContext();
      expect(typeof context).toBe("string");
      expect(context.length).toBeGreaterThan(100);
      expect(context).toContain("false positive");
    });
  });

  describe("SUPPRESSION_PROFILES", () => {
    it("should have profiles with rules matching FP_SUPPRESSION_RULES IDs", async () => {
      const { SUPPRESSION_PROFILES, FP_SUPPRESSION_RULES } = await importModule();
      const ruleIds = new Set(FP_SUPPRESSION_RULES.map(r => r.id));
      for (const [profileName, profile] of Object.entries(SUPPRESSION_PROFILES)) {
        for (const ruleId of Object.keys(profile.rules)) {
          expect(ruleIds.has(ruleId)).toBe(true);
        }
      }
    });
  });
});
