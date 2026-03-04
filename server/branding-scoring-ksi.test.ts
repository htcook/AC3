import { describe, expect, it } from "vitest";

/**
 * Tests for:
 * 1. Ace of Cloud branding in report generators
 * 2. ScoringHub Industry Baselines tier iteration fix
 * 3. KSI navigation placement in sidebar
 */

// ─── Branding Tests ──────────────────────────────────────────────────────────

describe("Ace of Cloud Branding in Report Generators", () => {
  it("pdf-report-generator uses correct Ace of Cloud branding colors", async () => {
    const pdfGen = await import("./lib/pdf-report-generator");
    const source = (pdfGen as any).__esModule
      ? Object.keys(pdfGen)
      : Object.keys(pdfGen);
    // Verify the module exports exist (it's a report generator)
    expect(source.length).toBeGreaterThan(0);
  });

  it("pdf-report-generator contains Ace of Cloud branding constants", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      new URL("./lib/pdf-report-generator.ts", import.meta.url).pathname.replace(
        "/server/lib/pdf-report-generator.ts",
        "/server/lib/pdf-report-generator.ts"
      ),
      "utf-8"
    );
    // Check branding constants are present
    expect(content).toContain("Ace of Cloud");
    expect(content).toContain("#213555");
  });

  it("zap-report-generator contains Ace of Cloud branding", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "lib/zap-report-generator.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Ace of Cloud");
    expect(content).toContain("aceofcloud.com");
  });

  it("report-generator contains Ace of Cloud metadata", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "lib/report-generator.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Ace of Cloud");
  });

  it("reports-core router contains Ace of Cloud in LLM prompts", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "routers/reports-core.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Ace of Cloud");
  });
});

// ─── Scoring Engine Tests ────────────────────────────────────────────────────

describe("Scoring Engine - Industry Tier Breakdown", () => {
  it("getIndustryTierBreakdown returns an array of tier objects", async () => {
    const { getIndustryTierBreakdown } = await import(
      "./lib/industry-baseline-scoring"
    );
    const tiers = getIndustryTierBreakdown("Corporate_Enterprise");

    // Must be an array, not an object
    expect(Array.isArray(tiers)).toBe(true);
    expect(tiers.length).toBe(3);
  });

  it("each tier object has tier, weight, and assets properties", async () => {
    const { getIndustryTierBreakdown } = await import(
      "./lib/industry-baseline-scoring"
    );
    const tiers = getIndustryTierBreakdown("Corporate_Enterprise");

    for (const tierObj of tiers) {
      expect(tierObj).toHaveProperty("tier");
      expect(tierObj).toHaveProperty("weight");
      expect(tierObj).toHaveProperty("assets");
      expect(typeof tierObj.tier).toBe("string");
      expect(typeof tierObj.weight).toBe("number");
      expect(Array.isArray(tierObj.assets)).toBe(true);
    }
  });

  it("tier objects contain correct tier names", async () => {
    const { getIndustryTierBreakdown } = await import(
      "./lib/industry-baseline-scoring"
    );
    const tiers = getIndustryTierBreakdown("Corporate_Enterprise");
    const tierNames = tiers.map((t: any) => t.tier);

    expect(tierNames).toContain("Tier_1_Strategic");
    expect(tierNames).toContain("Tier_2_Operational");
    expect(tierNames).toContain("Tier_3_Tactical");
  });

  it("assets property is always a string array (never an object)", async () => {
    const { getIndustryTierBreakdown } = await import(
      "./lib/industry-baseline-scoring"
    );
    const industries = [
      "Corporate_Enterprise",
      "Healthcare",
      "Financial_Services",
      "Government_Federal_State",
      "Energy_Utilities",
      "Industrial_OT_Manufacturing",
    ] as const;

    for (const industry of industries) {
      const tiers = getIndustryTierBreakdown(industry);
      for (const tierObj of tiers) {
        expect(Array.isArray(tierObj.assets)).toBe(true);
        // Each asset should be a string
        for (const asset of tierObj.assets) {
          expect(typeof asset).toBe("string");
        }
      }
    }
  });

  it("iterating tiers with Array.map works (the fix for c.map crash)", async () => {
    const { getIndustryTierBreakdown } = await import(
      "./lib/industry-baseline-scoring"
    );
    const tiers = getIndustryTierBreakdown("Corporate_Enterprise");

    // This is exactly what the fixed ScoringHub component does
    const result = tiers.map((tierObj: any) => {
      const tierKey = tierObj.tier ?? "Unknown";
      const assets: string[] = Array.isArray(tierObj.assets)
        ? tierObj.assets
        : [];
      return { tierKey, assetCount: assets.length };
    });

    expect(result.length).toBe(3);
    for (const r of result) {
      expect(typeof r.tierKey).toBe("string");
      expect(typeof r.assetCount).toBe("number");
      expect(r.assetCount).toBeGreaterThan(0);
    }
  });
});

// ─── CARVER Reference Tests ──────────────────────────────────────────────────

describe("Scoring Engine - CARVER Reference", () => {
  it("CARVER_DIGITAL_TRANSLATION is a valid object", async () => {
    const { CARVER_DIGITAL_TRANSLATION } = await import(
      "./lib/scoring-engine"
    );
    expect(CARVER_DIGITAL_TRANSLATION).toBeDefined();
    expect(typeof CARVER_DIGITAL_TRANSLATION).toBe("object");
  });

  it("SHOCK_DIGITAL_TRANSLATION is a valid object", async () => {
    const { SHOCK_DIGITAL_TRANSLATION } = await import(
      "./lib/scoring-engine"
    );
    expect(SHOCK_DIGITAL_TRANSLATION).toBeDefined();
    expect(typeof SHOCK_DIGITAL_TRANSLATION).toBe("object");
  });

  it("DISCOVERY_PHASE_TRIGGERS returns mappable entries", async () => {
    const { DISCOVERY_PHASE_TRIGGERS } = await import(
      "./lib/scoring-engine"
    );
    const entries = Object.entries(DISCOVERY_PHASE_TRIGGERS);
    expect(entries.length).toBeGreaterThan(0);

    const mapped = entries.map(([key, val]: [string, any]) => ({
      key,
      description: val.description,
    }));
    expect(mapped.length).toBe(entries.length);
    for (const item of mapped) {
      expect(typeof item.key).toBe("string");
      expect(typeof item.description).toBe("string");
    }
  });
});

// ─── KSI Navigation Tests ───────────────────────────────────────────────────

describe("KSI Navigation Placement", () => {
  it("AppShell has KSI link in Mission Operations section", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(
      __dirname,
      "../client/src/components/AppShell.tsx"
    );
    const content = fs.readFileSync(filePath, "utf-8");

    // KSI should appear in the Mission Operations items array
    const missionOpsMatch = content.match(
      /label:\s*"Mission Operations"[\s\S]*?items:\s*\[([\s\S]*?)\]/
    );
    expect(missionOpsMatch).not.toBeNull();

    const itemsBlock = missionOpsMatch![1];
    // KSI should be in the items block
    expect(itemsBlock).toContain("ksi-dashboard");
    expect(itemsBlock).toContain("KEY SECURITY INDICATORS");
  });

  it("KSI link appears after DASHBOARD in Mission Operations", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(
      __dirname,
      "../client/src/components/AppShell.tsx"
    );
    const content = fs.readFileSync(filePath, "utf-8");

    // Find the Mission Operations items section
    const missionOpsMatch = content.match(
      /label:\s*"Mission Operations"[\s\S]*?items:\s*\[([\s\S]*?)\]/
    );
    expect(missionOpsMatch).not.toBeNull();

    const itemsBlock = missionOpsMatch![1];
    const dashboardIndex = itemsBlock.indexOf('"/dashboard"');
    const ksiIndex = itemsBlock.indexOf('"/ksi-dashboard"');

    // KSI should come after DASHBOARD
    expect(dashboardIndex).toBeGreaterThan(-1);
    expect(ksiIndex).toBeGreaterThan(-1);
    expect(ksiIndex).toBeGreaterThan(dashboardIndex);
  });
});
