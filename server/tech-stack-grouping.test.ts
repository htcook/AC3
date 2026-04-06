/**
 * Tests for technology stack grouping module.
 * Validates fingerprinting, grouping, shared CVE computation,
 * and most widespread vulnerability ranking.
 */
import { describe, it, expect } from "vitest";
import { computeTechStackGrouping } from "./lib/tech-stack-grouping";

// Helper to create mock AssetAnalysis objects
function mockAsset(
  hostname: string,
  technologies: string[],
  technologyVersions: Record<string, string>,
  findings: Array<{ cveId: string; severity: number; cvssScore?: number; kevListed?: boolean; exploitAvailable?: boolean; corroborationTier?: string }> = [],
  hybridRiskScore: number = 30,
  suggestedTier: string = "tier2 medium"
): any {
  return {
    asset: {
      hostname,
      technologies,
      technologyVersions,
    },
    hybridRiskScore,
    riskBand: hybridRiskScore >= 70 ? "high" : hybridRiskScore >= 40 ? "medium" : "low",
    suggestedTier,
    postureFindings: findings.map((f, i) => ({
      id: `finding-${hostname}-${i}`,
      title: `${f.cveId}: Test finding on ${hostname}`,
      severity: f.severity,
      cvssScore: f.cvssScore || null,
      cveIds: [f.cveId],
      kevListed: f.kevListed || false,
      exploitAvailable: f.exploitAvailable || false,
      corroborationTier: f.corroborationTier || "confirmed",
    })),
    carverScores: {},
    shockScores: {},
    missionImpactScore: 0,
    cvssEstimate: 0,
    contextIndicators: { exposure: 0, recognizability: 0, confidence: 0 },
    testVectors: [],
    confidence: 0.5,
    assetCriticalityScore: 30,
    assetCriticalityBand: "low",
    vulnRiskScore: 30,
    vulnRiskBand: "low",
    impactScore: 30,
    likelihoodScore: 30,
    missionFunction: "web_hosting",
    essentialService: "web_server",
    businessImpactLevel: "moderate",
    deviceType: "server",
    platformType: "linux_server",
    missionJustification: "Test asset",
  };
}

describe("computeTechStackGrouping", () => {
  it("should return empty result for empty input", () => {
    const result = computeTechStackGrouping([]);
    expect(result.groups).toHaveLength(0);
    expect(result.mostWidespreadVulns).toHaveLength(0);
    expect(result.summary.totalGroups).toBe(0);
  });

  it("should group assets with identical tech stacks", () => {
    const analyses = [
      mockAsset("host1.com", ["Apache", "nginx"], { Apache: "2.4.51", nginx: "1.18.0" }),
      mockAsset("host2.com", ["Apache", "nginx"], { Apache: "2.4.51", nginx: "1.18.0" }),
      mockAsset("host3.com", ["Apache", "nginx"], { Apache: "2.4.51", nginx: "1.18.0" }),
    ];
    const result = computeTechStackGrouping(analyses);
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].assetCount).toBe(3);
    expect(result.groups[0].assetHostnames).toContain("host1.com");
    expect(result.groups[0].assetHostnames).toContain("host2.com");
    expect(result.groups[0].assetHostnames).toContain("host3.com");
  });

  it("should separate assets with different tech stacks", () => {
    const analyses = [
      mockAsset("host1.com", ["Apache"], { Apache: "2.4.51" }),
      mockAsset("host2.com", ["nginx"], { nginx: "1.18.0" }),
    ];
    const result = computeTechStackGrouping(analyses);
    expect(result.groups).toHaveLength(2);
    expect(result.groups[0].assetCount).toBe(1);
    expect(result.groups[1].assetCount).toBe(1);
  });

  it("should group by major.minor version, ignoring patch differences", () => {
    const analyses = [
      mockAsset("host1.com", ["Apache"], { Apache: "2.4.51" }),
      mockAsset("host2.com", ["Apache"], { Apache: "2.4.52" }),
      mockAsset("host3.com", ["Apache"], { Apache: "2.4.53" }),
    ];
    const result = computeTechStackGrouping(analyses);
    // All should be grouped together since major.minor is 2.4
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].assetCount).toBe(3);
  });

  it("should compute shared CVEs correctly", () => {
    const sharedCve = { cveId: "CVE-2024-1234", severity: 9, cvssScore: 9.8, kevListed: true };
    const uniqueCve = { cveId: "CVE-2024-5678", severity: 7, cvssScore: 7.5 };
    const analyses = [
      mockAsset("host1.com", ["Apache"], { Apache: "2.4.51" }, [sharedCve, uniqueCve]),
      mockAsset("host2.com", ["Apache"], { Apache: "2.4.52" }, [sharedCve]),
    ];
    const result = computeTechStackGrouping(analyses);
    expect(result.groups).toHaveLength(1);
    // CVE-2024-1234 is shared (on both assets), CVE-2024-5678 is only on host1
    expect(result.groups[0].sharedCves).toHaveLength(1);
    expect(result.groups[0].sharedCves[0].cveId).toBe("CVE-2024-1234");
    expect(result.groups[0].totalUniqueCves).toBe(2);
  });

  it("should rank most widespread vulnerabilities correctly", () => {
    const wideCve = { cveId: "CVE-2024-WIDE", severity: 8, cvssScore: 8.0 };
    const narrowCve = { cveId: "CVE-2024-NARROW", severity: 9, cvssScore: 9.0 };
    const analyses = [
      mockAsset("host1.com", ["Apache"], { Apache: "2.4.51" }, [wideCve, narrowCve]),
      mockAsset("host2.com", ["nginx"], { nginx: "1.18.0" }, [wideCve]),
      mockAsset("host3.com", ["jQuery"], { jQuery: "3.6.0" }, [wideCve]),
    ];
    const result = computeTechStackGrouping(analyses);
    // CVE-2024-WIDE affects 3 assets, CVE-2024-NARROW affects 1
    expect(result.mostWidespreadVulns).toHaveLength(1); // Only CVEs affecting 2+ assets
    expect(result.mostWidespreadVulns[0].cveId).toBe("CVE-2024-WIDE");
    expect(result.mostWidespreadVulns[0].affectedAssetCount).toBe(3);
    expect(result.mostWidespreadVulns[0].affectedPercentage).toBe(100);
  });

  it("should compute stack overlap percentage correctly", () => {
    const analyses = [
      mockAsset("host1.com", ["Apache"], { Apache: "2.4.51" }),
      mockAsset("host2.com", ["Apache"], { Apache: "2.4.52" }),
      mockAsset("host3.com", ["Apache"], { Apache: "2.4.53" }),
      mockAsset("host4.com", ["nginx"], { nginx: "1.18.0" }), // Unique stack
    ];
    const result = computeTechStackGrouping(analyses);
    // 3 out of 4 assets share a stack with at least one other asset
    expect(result.summary.stackOverlapPercentage).toBe(75);
    expect(result.summary.uniqueStacks).toBe(2);
    expect(result.summary.largestGroupSize).toBe(3);
  });

  it("should handle PBS-scale scenario with many shared stacks", () => {
    // 100 assets, 80 sharing Apache stack, 20 sharing nginx stack
    const apacheAssets = Array.from({ length: 80 }, (_, i) =>
      mockAsset(`apache${i}.pbs.org`, ["Apache", "jQuery"], { Apache: "2.4.51", jQuery: "3.6.0" }, [
        { cveId: "CVE-2024-1111", severity: 9, kevListed: true },
        { cveId: "CVE-2024-2222", severity: 7 },
      ])
    );
    const nginxAssets = Array.from({ length: 20 }, (_, i) =>
      mockAsset(`nginx${i}.pbs.org`, ["nginx", "PHP"], { nginx: "1.18.0", PHP: "8.1.0" }, [
        { cveId: "CVE-2024-3333", severity: 8 },
      ])
    );
    const result = computeTechStackGrouping([...apacheAssets, ...nginxAssets]);

    expect(result.summary.totalAssets).toBe(100);
    expect(result.summary.uniqueStacks).toBe(2);
    expect(result.summary.largestGroupSize).toBe(80);
    expect(result.summary.stackOverlapPercentage).toBe(100); // All assets share a stack

    // Most widespread: CVE-2024-1111 and CVE-2024-2222 affect 80 assets each
    expect(result.mostWidespreadVulns.length).toBeGreaterThanOrEqual(2);
    expect(result.mostWidespreadVulns[0].affectedAssetCount).toBe(80);
    expect(result.mostWidespreadVulns[0].affectedPercentage).toBe(80);

    // Shared CVEs in Apache group
    const apacheGroup = result.groups.find(g => g.assetCount === 80);
    expect(apacheGroup).toBeDefined();
    expect(apacheGroup!.sharedCves.length).toBe(2);
  });

  it("should create readable stack labels", () => {
    const analyses = [
      mockAsset("host1.com", ["Apache", "jQuery", "nginx", "OpenSSL", "PHP"], {
        Apache: "2.4.51",
        jQuery: "3.6.0",
        nginx: "1.18.0",
        OpenSSL: "1.1.1",
        PHP: "8.1.0",
      }),
    ];
    const result = computeTechStackGrouping(analyses);
    // Should show top 4 + "+1 more"
    expect(result.groups[0].stackLabel).toContain("+1 more");
  });

  it("should handle assets with no technologies gracefully", () => {
    const analyses = [
      mockAsset("host1.com", [], {}),
      mockAsset("host2.com", [], {}),
    ];
    const result = computeTechStackGrouping(analyses);
    // Both should be in the same "__no_tech__" group
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].assetCount).toBe(2);
  });

  it("should sort groups by asset count descending", () => {
    const analyses = [
      mockAsset("h1.com", ["Apache"], { Apache: "2.4" }),
      mockAsset("h2.com", ["nginx"], { nginx: "1.18" }),
      mockAsset("h3.com", ["nginx"], { nginx: "1.18" }),
      mockAsset("h4.com", ["nginx"], { nginx: "1.18" }),
    ];
    const result = computeTechStackGrouping(analyses);
    expect(result.groups[0].assetCount).toBe(3); // nginx group first
    expect(result.groups[1].assetCount).toBe(1); // Apache group second
  });

  it("should compute average risk score per group", () => {
    const analyses = [
      mockAsset("h1.com", ["Apache"], { Apache: "2.4" }, [], 80),
      mockAsset("h2.com", ["Apache"], { Apache: "2.4" }, [], 40),
      mockAsset("h3.com", ["Apache"], { Apache: "2.4" }, [], 60),
    ];
    const result = computeTechStackGrouping(analyses);
    expect(result.groups[0].avgRiskScore).toBe(60); // (80+40+60)/3
    expect(result.groups[0].maxRiskScore).toBe(80);
    expect(result.groups[0].riskBand).toBe("medium"); // 60 = medium
  });
});
