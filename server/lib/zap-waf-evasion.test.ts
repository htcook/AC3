/**
 * Tests for ZAP smart knowledge-driven fallback and WAF evasion configuration.
 */
import { describe, it, expect } from "vitest";
import {
  getWafEvasionProfile,
  applyWafEvasionConfig,
  type LLMScanConfig,
} from "./zap-scanner";

// ─── Helper: create a base LLMScanConfig ──────────────────────────────────

function makeBaseConfig(overrides?: Partial<LLMScanConfig>): LLMScanConfig {
  return {
    scanPolicy: "Default Policy",
    useAjaxSpider: false,
    spiderConfig: {
      maxDepth: 8,
      maxChildren: 50,
      threadCount: 5,
      parseComments: true,
      parseGit: true,
      parseSitemapXml: true,
      postForm: true,
    },
    ajaxSpiderConfig: {
      maxCrawlDepth: 5,
      maxCrawlStates: 10000,
      maxDuration: 10,
      numberOfBrowsers: 2,
      clickDefaultElems: true,
    },
    activeScanConfig: {
      threadPerHost: 5,
      delayInMs: 20,
      handleAntiCSRFTokens: true,
      scanHeadersAllRequests: true,
      maxRuleDurationInMins: 10,
    },
    technologies: [],
    authStrategy: "none",
    authConfig: {},
    contextIncludes: [],
    contextExcludes: [".*\\.(js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$"],
    importSpec: null,
    customRules: [],
    rationale: "Test config",
    ...overrides,
  };
}

// ─── WAF Evasion Profile Tests ────────────────────────────────────────────

describe("getWafEvasionProfile", () => {
  it("returns Cloudflare profile for exact match", () => {
    const profile = getWafEvasionProfile("Cloudflare");
    expect(profile.name).toBe("Cloudflare Evasion");
    expect(profile.delayInMs).toBe(500);
    expect(profile.threadPerHost).toBe(1);
    expect(profile.maxReqPerSec).toBe(2);
    expect(profile.rotateUserAgents).toBe(true);
    expect(profile.techniques.length).toBeGreaterThan(0);
  });

  it("returns AWS WAF profile for exact match", () => {
    const profile = getWafEvasionProfile("AWS WAF");
    expect(profile.name).toBe("AWS WAF Evasion");
    expect(profile.delayInMs).toBe(200);
    expect(profile.threadPerHost).toBe(2);
  });

  it("returns Akamai profile for exact match", () => {
    const profile = getWafEvasionProfile("Akamai");
    expect(profile.name).toBe("Akamai Evasion");
    expect(profile.delayInMs).toBe(1000);
    expect(profile.threadPerHost).toBe(1);
  });

  it("returns Imperva profile for exact match", () => {
    const profile = getWafEvasionProfile("Imperva/Incapsula");
    expect(profile.name).toBe("Imperva Evasion");
    expect(profile.useAjaxSpider).toBe(true);
  });

  it("returns ModSecurity profile for exact match", () => {
    const profile = getWafEvasionProfile("ModSecurity");
    expect(profile.name).toBe("ModSecurity Evasion");
    expect(profile.rotateUserAgents).toBe(false);
    expect(profile.encodePayloads).toBe(true);
  });

  it("returns F5 BIG-IP profile for exact match", () => {
    const profile = getWafEvasionProfile("F5 BIG-IP ASM");
    expect(profile.name).toBe("F5 BIG-IP Evasion");
  });

  it("fuzzy matches Cloudflare variants", () => {
    const profile = getWafEvasionProfile("cloudflare");
    expect(profile.name).toBe("Cloudflare Evasion");
  });

  it("fuzzy matches AWS variants", () => {
    const profile = getWafEvasionProfile("aws waf");
    expect(profile.name).toBe("AWS WAF Evasion");
  });

  it("returns generic profile for unknown WAF", () => {
    const profile = getWafEvasionProfile("CustomWAF");
    expect(profile.name).toContain("Generic WAF Evasion");
    expect(profile.name).toContain("CustomWAF");
    expect(profile.delayInMs).toBe(500);
    expect(profile.threadPerHost).toBe(1);
    expect(profile.rotateUserAgents).toBe(true);
    expect(profile.techniques.length).toBeGreaterThan(0);
  });

  it("all profiles have required fields", () => {
    const vendors = ["Cloudflare", "AWS WAF", "Akamai", "Imperva/Incapsula", "ModSecurity", "F5 BIG-IP ASM", "UnknownWAF"];
    for (const vendor of vendors) {
      const profile = getWafEvasionProfile(vendor);
      expect(profile.name).toBeTruthy();
      expect(profile.maxReqPerSec).toBeGreaterThan(0);
      expect(profile.delayInMs).toBeGreaterThan(0);
      expect(profile.threadPerHost).toBeGreaterThan(0);
      expect(profile.spiderThreads).toBeGreaterThan(0);
      expect(profile.maxRuleDurationInMins).toBeGreaterThan(0);
      expect(typeof profile.useAjaxSpider).toBe("boolean");
      expect(typeof profile.rotateUserAgents).toBe("boolean");
      expect(typeof profile.encodePayloads).toBe("boolean");
      expect(profile.techniques.length).toBeGreaterThan(0);
    }
  });
});

// ─── applyWafEvasionConfig Tests ──────────────────────────────────────────

describe("applyWafEvasionConfig", () => {
  it("reduces thread count for Cloudflare", () => {
    const base = makeBaseConfig();
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.activeScanConfig.threadPerHost).toBe(1);
    expect(result.activeScanConfig.delayInMs).toBe(500);
    expect(result.spiderConfig.threadCount).toBeLessThanOrEqual(2);
  });

  it("increases delay for Akamai", () => {
    const base = makeBaseConfig();
    const result = applyWafEvasionConfig(base, "Akamai");
    expect(result.activeScanConfig.delayInMs).toBe(1000);
    expect(result.activeScanConfig.threadPerHost).toBe(1);
  });

  it("enables AJAX spider for Imperva", () => {
    const base = makeBaseConfig({ useAjaxSpider: false });
    const result = applyWafEvasionConfig(base, "Imperva/Incapsula");
    expect(result.useAjaxSpider).toBe(true);
  });

  it("adds WAF_EVASION custom rule", () => {
    const base = makeBaseConfig();
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.customRules.some(r => r.startsWith("WAF_EVASION:"))).toBe(true);
  });

  it("appends evasion techniques to custom rules", () => {
    const base = makeBaseConfig({ customRules: ["existing-rule"] });
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.customRules).toContain("existing-rule");
    expect(result.customRules.length).toBeGreaterThan(1);
  });

  it("updates rationale with WAF evasion info", () => {
    const base = makeBaseConfig({ rationale: "Original rationale" });
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.rationale).toContain("Original rationale");
    expect(result.rationale).toContain("WAF Evasion");
    expect(result.rationale).toContain("Cloudflare");
  });

  it("increases maxRuleDurationInMins for WAF targets", () => {
    const base = makeBaseConfig();
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.activeScanConfig.maxRuleDurationInMins).toBe(20);
  });

  it("preserves non-evasion config fields", () => {
    const base = makeBaseConfig({
      scanPolicy: "Custom Policy",
      technologies: ["PHP"],
      authStrategy: "form",
      authConfig: { loginUrl: "/login" },
      contextIncludes: [".*\\.php$"],
    });
    const result = applyWafEvasionConfig(base, "Cloudflare");
    expect(result.scanPolicy).toBe("Custom Policy");
    expect(result.technologies).toEqual(["PHP"]);
    expect(result.authStrategy).toBe("form");
    expect(result.authConfig).toEqual({ loginUrl: "/login" });
    expect(result.contextIncludes).toEqual([".*\\.php$"]);
  });

  it("spider threadCount is capped to profile.spiderThreads", () => {
    const base = makeBaseConfig();
    base.spiderConfig.threadCount = 10;
    const result = applyWafEvasionConfig(base, "Akamai");
    expect(result.spiderConfig.threadCount).toBe(1); // Akamai spiderThreads = 1
  });

  it("handles unknown WAF with conservative defaults", () => {
    const base = makeBaseConfig();
    const result = applyWafEvasionConfig(base, "SomeNewWAF");
    expect(result.activeScanConfig.delayInMs).toBe(500);
    expect(result.activeScanConfig.threadPerHost).toBe(1);
    expect(result.customRules.some(r => r.includes("Generic WAF Evasion"))).toBe(true);
  });
});

// ─── Smart Fallback Config Tests ──────────────────────────────────────────

describe("Smart knowledge-driven fallback", () => {
  // We test the fallback indirectly by importing the internal function
  // Since getDefaultScanConfig is not exported, we test via generateLLMScanConfig
  // which calls it on failure. For unit testing, we verify the knowledge module
  // data that feeds the fallback.

  it("TECH_SCAN_POLICIES has entries for all major stacks", async () => {
    const { TECH_SCAN_POLICIES } = await import("./knowledge/zap-pentesting-knowledge");
    const techs = TECH_SCAN_POLICIES.map((p: any) => p.technology);
    expect(techs).toContain("PHP");
    expect(techs).toContain("Java/Spring");
    expect(techs).toContain("Python/Django/Flask");
    expect(techs).toContain("Node.js/Express");
    expect(techs).toContain("ASP.NET");
    expect(techs).toContain("WordPress");
    expect(techs).toContain("API (REST/GraphQL)");
  });

  it("each tech policy has critical rules", async () => {
    const { TECH_SCAN_POLICIES } = await import("./knowledge/zap-pentesting-knowledge");
    for (const policy of TECH_SCAN_POLICIES) {
      expect(policy.criticalRules.length).toBeGreaterThan(0);
      for (const rule of policy.criticalRules) {
        expect(rule.id).toBeDefined();
        expect(rule.strength).toBeTruthy();
        expect(rule.threshold).toBeTruthy();
        expect(rule.reason).toBeTruthy();
      }
    }
  });

  it("each tech policy has fingerprints for matching", async () => {
    const { TECH_SCAN_POLICIES } = await import("./knowledge/zap-pentesting-knowledge");
    for (const policy of TECH_SCAN_POLICIES) {
      expect(policy.fingerprints.length).toBeGreaterThan(0);
    }
  });

  it("each tech policy has spider config", async () => {
    const { TECH_SCAN_POLICIES } = await import("./knowledge/zap-pentesting-knowledge");
    for (const policy of TECH_SCAN_POLICIES) {
      expect(policy.spiderConfig).toBeDefined();
      expect(typeof policy.spiderConfig.parseComments).toBe("boolean");
      expect(typeof policy.spiderConfig.parseGit).toBe("boolean");
      expect(typeof policy.spiderConfig.postForm).toBe("boolean");
    }
  });

  it("each tech policy has context excludes", async () => {
    const { TECH_SCAN_POLICIES } = await import("./knowledge/zap-pentesting-knowledge");
    for (const policy of TECH_SCAN_POLICIES) {
      expect(policy.contextExcludes.length).toBeGreaterThan(0);
    }
  });
});
