import { describe, expect, it } from "vitest";
import {
  generateBiaReport,
  type BiaAssetInput,
  type BiaOrgInput,
} from "./lib/bia-report-generator";

// ─── Test Fixtures ──────────────────────────────────────────────────────

function createMockOrg(overrides: Partial<BiaOrgInput> = {}): BiaOrgInput {
  return {
    customerName: "Acme Corp",
    primaryDomain: "acme.com",
    sector: "Technology",
    clientType: "enterprise",
    criticalFunctions: ["Email", "SSO", "Payment Processing"],
    complianceFlags: ["SOC2", "PCI-DSS"],
    ...overrides,
  };
}

function createMockAsset(overrides: Partial<BiaAssetInput> = {}): BiaAssetInput {
  return {
    id: 1,
    hostname: "sso.acme.com",
    assetType: "web_application",
    missionFunction: "authentication",
    essentialService: "sso",
    businessImpactLevel: "mission_critical",
    carverScores: {
      criticality: 9,
      accessibility: 7,
      recuperability: 8,
      vulnerability: 6,
      effect: 9,
      recognizability: 5,
    },
    shockScores: {
      scope: 8,
      handling: 7,
      operationalImpact: 9,
      cascadingEffects: 8,
      knowledge: 6,
    },
    hybridRiskScore: 88,
    riskBand: "critical",
    impactScore: 85,
    likelihoodScore: 72,
    assetCriticalityScore: 90,
    assetCriticalityBand: "critical",
    vulnRiskScore: 75,
    vulnRiskBand: "high",
    missionImpactScore: 9,
    fips199Category: {
      confidentiality: "high",
      integrity: "high",
      availability: "high",
    },
    criticalityTier: 1,
    missionDependencies: {
      upstreamAssets: ["ad.acme.com"],
      downstreamAssets: ["portal.acme.com", "api.acme.com", "mail.acme.com"],
      sharedServices: ["Active Directory", "DNS"],
    },
    postureFindings: [
      {
        title: "Outdated TLS Configuration",
        category: "cryptography",
        severity: 7,
        corroborationTier: "confirmed",
        kevListed: false,
        cveIds: [],
      },
      {
        title: "CVE-2024-1234 Remote Code Execution",
        category: "vulnerability",
        severity: 9,
        corroborationTier: "confirmed",
        kevListed: true,
        cveIds: ["CVE-2024-1234"],
      },
    ],
    deviceType: "server",
    platformType: "linux",
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────

describe("BIA Report Generator", () => {
  describe("generateBiaReport", () => {
    it("generates a report with all 8 sections", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset(),
        createMockAsset({
          id: 2,
          hostname: "api.acme.com",
          missionFunction: "revenue_generation",
          businessImpactLevel: "business_essential",
          hybridRiskScore: 72,
          riskBand: "high",
          fips199Category: { confidentiality: "moderate", integrity: "high", availability: "moderate" },
          criticalityTier: 2,
        }),
        createMockAsset({
          id: 3,
          hostname: "blog.acme.com",
          missionFunction: "external_communication",
          businessImpactLevel: "operational",
          hybridRiskScore: 35,
          riskBand: "low",
          fips199Category: { confidentiality: "low", integrity: "low", availability: "low" },
          criticalityTier: 4,
        }),
      ];

      const report = generateBiaReport(org, assets, 75, "high");

      expect(report.title).toContain("Acme Corp");
      expect(report.generatedAt).toBeTruthy();
      expect(report.organization.primaryDomain).toBe("acme.com");
      expect(report.overallRiskScore).toBe(75);
      expect(report.overallRiskBand).toBe("high");
      expect(report.assetCount).toBe(3);
      expect(report.criticalAssetCount).toBe(1);
      expect(report.highAssetCount).toBe(1);

      // All 8 sections present
      expect(report.sections).toHaveLength(8);
      const sectionIds = report.sections.map((s) => s.id);
      expect(sectionIds).toContain("executive-overview");
      expect(sectionIds).toContain("fips199");
      expect(sectionIds).toContain("mission-functions");
      expect(sectionIds).toContain("criticality");
      expect(sectionIds).toContain("recovery-objectives");
      expect(sectionIds).toContain("dependencies");
      expect(sectionIds).toContain("risk-distribution");
      expect(sectionIds).toContain("recommendations");
    });

    it("computes system-level FIPS 199 high-water mark correctly", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({
          fips199Category: { confidentiality: "high", integrity: "moderate", availability: "low" },
        }),
        createMockAsset({
          id: 2,
          hostname: "db.acme.com",
          fips199Category: { confidentiality: "moderate", integrity: "high", availability: "moderate" },
        }),
      ];

      const report = generateBiaReport(org, assets, 80, "high");

      // High-water mark: highest across all assets for each dimension
      expect(report.systemSecurityCategorization.confidentiality).toBe("HIGH");
      expect(report.systemSecurityCategorization.integrity).toBe("HIGH");
      expect(report.systemSecurityCategorization.availability).toBe("MODERATE");
      expect(report.systemSecurityCategorization.overall).toBe("HIGH");
    });

    it("infers FIPS 199 from mission function when not explicitly provided", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({
          fips199Category: undefined,
          missionFunction: "customer_data",
          businessImpactLevel: "mission_critical",
        }),
      ];

      const report = generateBiaReport(org, assets, 85, "critical");

      // customer_data + mission_critical should infer high across the board
      expect(report.systemSecurityCategorization.confidentiality).toBe("HIGH");
      expect(report.systemSecurityCategorization.integrity).toBe("HIGH");
      expect(report.systemSecurityCategorization.availability).toBe("HIGH");
    });

    it("includes KEV findings in executive overview", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({
          postureFindings: [
            { title: "KEV Vuln", severity: 9, kevListed: true, cveIds: ["CVE-2024-9999"] },
          ],
        }),
      ];

      const report = generateBiaReport(org, assets, 90, "critical");
      const execSection = report.sections.find((s) => s.id === "executive-overview");
      expect(execSection?.content).toContain("KEV-listed");
    });

    it("generates recovery objectives based on criticality tier", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({ criticalityTier: 1 }),
        createMockAsset({ id: 2, hostname: "blog.acme.com", criticalityTier: 4, hybridRiskScore: 30, riskBand: "low" }),
      ];

      const report = generateBiaReport(org, assets, 60, "medium");
      const recoverySection = report.sections.find((s) => s.id === "recovery-objectives");
      expect(recoverySection?.tables).toBeDefined();
      expect(recoverySection!.tables![0].rows.length).toBe(2);

      // Tier 1 should have < 1 hour RTO
      const tier1Row = recoverySection!.tables![0].rows.find((r) => r[1] === "Tier 1");
      expect(tier1Row?.[2]).toContain("1 hour");

      // Tier 4 should have 24-72 hours RTO
      const tier4Row = recoverySection!.tables![0].rows.find((r) => r[1] === "Tier 4");
      expect(tier4Row?.[2]).toContain("72");
    });

    it("includes dependency analysis for assets with dependencies", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({
          missionDependencies: {
            upstreamAssets: ["ad.acme.com"],
            downstreamAssets: ["portal.acme.com", "api.acme.com"],
            sharedServices: ["DNS"],
          },
        }),
      ];

      const report = generateBiaReport(org, assets, 80, "high");
      const depSection = report.sections.find((s) => s.id === "dependencies");
      expect(depSection?.content).toContain("1");
      expect(depSection?.tables?.[0].rows.length).toBe(1);
    });

    it("generates recommendations for KEV assets", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({
          postureFindings: [
            { title: "KEV Vuln", severity: 9, kevListed: true, cveIds: ["CVE-2024-9999"] },
          ],
        }),
      ];

      const report = generateBiaReport(org, assets, 90, "critical");
      const recSection = report.sections.find((s) => s.id === "recommendations");
      expect(recSection?.content).toContain("CISA KEV");
      expect(recSection?.content).toContain("BOD 22-01");
    });

    it("handles empty assets gracefully", () => {
      const org = createMockOrg();
      const report = generateBiaReport(org, [], 0, "low");

      expect(report.assetCount).toBe(0);
      expect(report.criticalAssetCount).toBe(0);
      expect(report.sections).toHaveLength(8);
    });

    it("groups assets by mission function correctly", () => {
      const org = createMockOrg();
      const assets = [
        createMockAsset({ missionFunction: "authentication" }),
        createMockAsset({ id: 2, hostname: "sso2.acme.com", missionFunction: "authentication" }),
        createMockAsset({ id: 3, hostname: "api.acme.com", missionFunction: "revenue_generation" }),
      ];

      const report = generateBiaReport(org, assets, 80, "high");
      const mfSection = report.sections.find((s) => s.id === "mission-functions");
      expect(mfSection?.tables?.[0].rows.length).toBe(2); // 2 unique mission functions
    });
  });
});
