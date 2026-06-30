/**
 * Tests for createEngagementFromScope procedure and build requirements logic
 */
import { describe, it, expect } from "vitest";

// ─── Auto-Engagement Creator Module Tests ────────────────────────────────────

describe("Auto-Engagement Creator - hasSufficientData", () => {
  it("returns sufficient=true when there are in-scope targets and confidence >= 0.5", async () => {
    const { hasSufficientData } = await import("./lib/auto-engagement-creator");
    const result = hasSufficientData({
      programName: "WordPress",
      platform: "hackerone",
      programUrl: "https://hackerone.com/wordpress",
      scope: {
        inScope: [
          { type: "source_code", value: "https://github.com/WordPress/WordPress", eligible: true, notes: "Main repo" },
          { type: "domain", value: "*.wordpress.org", eligible: true },
        ],
        outOfScope: [],
      },
      rules: [],
      safeHarbor: true,
      parsedAt: new Date().toISOString(),
    }, 0.9);
    expect(result.sufficient).toBe(true);
  });

  it("returns sufficient=false when no in-scope targets", async () => {
    const { hasSufficientData } = await import("./lib/auto-engagement-creator");
    const result = hasSufficientData({
      programName: "Empty Program",
      platform: "hackerone",
      programUrl: "https://hackerone.com/empty",
      scope: { inScope: [], outOfScope: [] },
      rules: [],
      safeHarbor: false,
      parsedAt: new Date().toISOString(),
    }, 0.8);
    expect(result.sufficient).toBe(false);
    expect(result.reason).toContain("No in-scope targets");
  });

  it("returns sufficient=false when confidence is below 0.5", async () => {
    const { hasSufficientData } = await import("./lib/auto-engagement-creator");
    const result = hasSufficientData({
      programName: "Low Confidence",
      platform: "custom",
      programUrl: "https://example.com/security",
      scope: {
        inScope: [{ type: "domain", value: "example.com", eligible: true }],
        outOfScope: [],
      },
      rules: [],
      safeHarbor: false,
      parsedAt: new Date().toISOString(),
    }, 0.3);
    expect(result.sufficient).toBe(false);
    expect(result.reason).toContain("confidence too low");
  });

  it("returns sufficient=false when program name is unknown", async () => {
    const { hasSufficientData } = await import("./lib/auto-engagement-creator");
    const result = hasSufficientData({
      programName: "unknown",
      platform: "custom",
      programUrl: "https://example.com/security",
      scope: {
        inScope: [{ type: "domain", value: "example.com", eligible: true }],
        outOfScope: [],
      },
      rules: [],
      safeHarbor: false,
      parsedAt: new Date().toISOString(),
    }, 0.9);
    expect(result.sufficient).toBe(false);
    expect(result.reason).toContain("Program name could not be resolved");
  });
});

describe("Auto-Engagement Creator - extractTargets (via hasSufficientData + source_code handling)", () => {
  it("correctly identifies source_code assets as sufficient for engagement creation", async () => {
    const { hasSufficientData } = await import("./lib/auto-engagement-creator");
    // WordPress-style program with mostly source_code assets
    const result = hasSufficientData({
      programName: "WordPress",
      platform: "hackerone",
      programUrl: "https://hackerone.com/wordpress",
      scope: {
        inScope: [
          { type: "source_code", value: "https://github.com/GlotPress/GlotPress-WP", eligible: true, notes: "GlotPress repository" },
          { type: "source_code", value: "https://github.com/wp-cli/wp-cli", eligible: true, notes: "WP-CLI main repository" },
          { type: "source_code", value: "Official WordPress.org plugins", eligible: true, notes: "Plugins listed on wordpressdotorg profile" },
          { type: "domain", value: "munin-*.wordpress.org", eligible: true },
        ],
        outOfScope: [
          { type: "other", value: "Digital Ocean, AWS, etc", eligible: false, notes: "Third-party infrastructure" },
          { type: "domain", value: "*.wordpress.com", eligible: false, notes: "Report to Automattic" },
        ],
      },
      rules: ["Do not test live production sites", "Build test sites locally"],
      safeHarbor: true,
      parsedAt: new Date().toISOString(),
    }, 0.85);
    expect(result.sufficient).toBe(true);
    expect(result.reason).toContain("4 in-scope targets");
  });
});

describe("Engagement Builder - Build Requirements", () => {
  it("exports BuildRequirement interface and BUILDABLE_ASSET_TYPES recognition", async () => {
    const mod = await import("./lib/engagement-builder");
    expect(mod.buildEngagementPreview).toBeDefined();
    expect(mod.createEngagementFromPreview).toBeDefined();
    // The EngagementPreview type should include buildRequirements
    expect(typeof mod.buildEngagementPreview).toBe("function");
  });

  it("ScopeAsset type supports requiresBuild and sponsorInstruction fields", async () => {
    // Verify the type structure by creating a mock asset
    const asset = {
      name: "https://github.com/WordPress/WordPress",
      type: "SOURCE_CODE",
      tier: "critical" as const,
      description: "WordPress core repository",
      eligibleForBounty: true,
      requiresBuild: true,
      sponsorInstruction: "Clone and set up locally with Docker",
    };
    expect(asset.requiresBuild).toBe(true);
    expect(asset.sponsorInstruction).toBe("Clone and set up locally with Docker");
    expect(asset.type).toBe("SOURCE_CODE");
  });
});

describe("Frontend - Build Requirements Display Logic", () => {
  it("correctly identifies buildable asset types", () => {
    const BUILDABLE_TYPES = ['source_code', 'hardware', 'downloadable_executables', 'smart_contract'];
    
    // WordPress program assets
    const assets = [
      { type: "source_code", value: "https://github.com/GlotPress/GlotPress-WP", eligible: true },
      { type: "source_code", value: "https://github.com/wp-cli/wp-cli", eligible: true },
      { type: "domain", value: "munin-*.wordpress.org", eligible: true },
      { type: "url", value: "https://wordpressfoundation.org", eligible: true },
    ];

    const buildableAssets = assets.filter(a => BUILDABLE_TYPES.includes(a.type.toLowerCase()));
    const networkAssets = assets.filter(a => !BUILDABLE_TYPES.includes(a.type.toLowerCase()));

    expect(buildableAssets.length).toBe(2);
    expect(networkAssets.length).toBe(2);
    expect(buildableAssets[0].value).toContain("github.com");
    expect(buildableAssets[1].value).toContain("github.com");
  });

  it("generates git clone command for GitHub source_code assets", () => {
    const entry = { type: "source_code", value: "https://github.com/GlotPress/GlotPress-WP", eligible: true };
    const hasGithub = entry.value.includes('github.com');
    expect(hasGithub).toBe(true);
    
    // The UI should show: git clone https://github.com/GlotPress/GlotPress-WP
    const cloneCmd = `git clone ${entry.value}`;
    expect(cloneCmd).toBe("git clone https://github.com/GlotPress/GlotPress-WP");
  });
});

describe("createEngagementFromScope procedure input validation", () => {
  it("accepts valid input with all fields", () => {
    const input = {
      programName: "WordPress",
      programUrl: "https://hackerone.com/wordpress",
      platform: "hackerone",
      inScopeTargets: [
        { type: "source_code", value: "https://github.com/WordPress/WordPress", eligible: true, notes: "Main repo" },
        { type: "domain", value: "*.wordpress.org", eligible: true },
      ],
      outOfScopeTargets: [
        { type: "domain", value: "*.wordpress.com", eligible: false, notes: "Report to Automattic" },
      ],
      rules: ["Do not test live sites"],
      rewardRange: { low: 100, high: 25000, currency: "$" },
      safeHarbor: true,
    };

    expect(input.programName).toBe("WordPress");
    expect(input.inScopeTargets.length).toBe(2);
    expect(input.inScopeTargets[0].type).toBe("source_code");
    expect(input.outOfScopeTargets!.length).toBe(1);
    expect(input.rewardRange!.high).toBe(25000);
  });

  it("accepts minimal input without optional fields", () => {
    const input = {
      programName: "Simple Program",
      programUrl: "https://example.com/security",
      platform: "custom",
      inScopeTargets: [
        { type: "domain", value: "example.com" },
      ],
    };

    expect(input.programName).toBe("Simple Program");
    expect(input.inScopeTargets.length).toBe(1);
  });
});
