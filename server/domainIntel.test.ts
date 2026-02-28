import { describe, it, expect, afterAll } from "vitest";

afterAll(async () => {
  // Clean up all test scans created during this test run
  for (const id of testScanIds) {
    try {
      await deleteDomainIntelScan(id);
    } catch (_) { /* scan may already be deleted */ }
  }
});
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import {
  createDomainIntelScan,
  getDomainIntelScans,
  getDomainIntelScanById,
  updateDomainIntelScan,
  createDiscoveredAsset,
  getDiscoveredAssetsByScan,
  deleteDomainIntelScan,
} from "./db";

// Track scan IDs created during tests for cleanup
const testScanIds: number[] = [];

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@aceofcloud.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

// ==================== DOMAIN INTEL SCAN DB TESTS ====================
describe("Domain Intel Scan DB operations", () => {
  it("should create a domain intel scan", async () => {
    const id = await createDomainIntelScan({
      primaryDomain: `test-scan-${Date.now()}.com`,
      additionalDomains: ["sub1.test.com"],
      clientType: "enterprise",
      sector: "Technology",
      customerName: "Test Corp",
      criticalFunctions: ["identity", "email"],
      complianceFlags: ["SOC2", "HIPAA"],
      status: "pending",
      createdBy: 1,
    });
    testScanIds.push(id);
    expect(id).toBeDefined();
    expect(typeof id).toBe("number");
    expect(id).toBeGreaterThan(0);
  });

  it("should list all scans", async () => {
    const scans = await getDomainIntelScans();
    expect(Array.isArray(scans)).toBe(true);
    expect(scans.length).toBeGreaterThan(0);
  });

  it("should get a scan by ID", async () => {
    const domain = `get-scan-${Date.now()}.com`;
    const id = await createDomainIntelScan({
      primaryDomain: domain,
      clientType: "msp",
      sector: "Financial Services",
      customerName: "MSP Corp",
      criticalFunctions: ["payments"],
      complianceFlags: ["PCI-DSS"],
      status: "pending",
      createdBy: 1,
    });
    testScanIds.push(id);
    const scan = await getDomainIntelScanById(id);
    expect(scan).toBeDefined();
    expect(scan!.primaryDomain).toBe(domain);
    expect(scan!.clientType).toBe("msp");
    expect(scan!.sector).toBe("Financial Services");
  });

  it("should update a scan", async () => {
    const id = await createDomainIntelScan({
      primaryDomain: `update-${Date.now()}.com`,
      clientType: "saas",
      sector: "Technology",
      customerName: "SaaS Inc",
      criticalFunctions: [],
      complianceFlags: [],
      status: "pending",
      createdBy: 1,
    });
    testScanIds.push(id);
    await updateDomainIntelScan(id, {
      status: "completed",
      overallRiskScore: 75,
      overallRiskBand: "high",
      totalAssets: 12,
      totalFindings: 8,
      executiveSummary: "High risk environment detected.",
    });
    const updated = await getDomainIntelScanById(id);
    expect(updated!.status).toBe("completed");
    expect(updated!.overallRiskScore).toBe(75);
    expect(updated!.overallRiskBand).toBe("high");
    expect(updated!.totalAssets).toBe(12);
    expect(updated!.totalFindings).toBe(8);
  });

  it("should handle all client types", async () => {
    const types = ["msp", "enterprise", "saas", "paas", "iaas", "mixed_hosting", "other"];
    for (const clientType of types) {
      const id = await createDomainIntelScan({
        primaryDomain: `${clientType}-${Date.now()}.com`,
        clientType,
        sector: "Technology",
        customerName: `${clientType} Corp`,
        criticalFunctions: [],
        complianceFlags: [],
        status: "pending",
        createdBy: 1,
      });
      expect(id).toBeGreaterThan(0);
    }
  });
});

// ==================== DISCOVERED ASSET DB TESTS ====================
describe("Discovered Asset DB operations", () => {
  it("should create a discovered asset", async () => {
    const scanId = await createDomainIntelScan({
      primaryDomain: `asset-test-${Date.now()}.com`,
      clientType: "enterprise",
      sector: "Healthcare",
      customerName: "Health Corp",
      criticalFunctions: ["customer_data"],
      complianceFlags: ["HIPAA"],
      status: "discovering",
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const assetId = await createDiscoveredAsset({
      scanId,
      assetId: `asset-${Date.now()}`,
      hostname: "sso.healthcorp.com",
      assetType: "sso_idp",
      assetClasses: ["identity", "authentication"],
      tags: ["okta", "saml", "critical"],
      carverScores: { criticality: 9, accessibility: 7, recuperability: 3, vulnerability: 6, effect: 8, recognizability: 5 },
      shockScores: { scope: 8, handling: 4, operationalImpact: 9, cascadingEffects: 7, knowledge: 6 },
      missionImpactScore: 85,
      cvssEstimate: 72,
      hybridRiskScore: 81,
      riskBand: "critical",
      confidence: 78,
      suggestedTier: "tier0_critical",
    });
    expect(assetId).toBeDefined();
    expect(typeof assetId).toBe("number");
  });

  it("should get assets by scan ID", async () => {
    const scanId = await createDomainIntelScan({
      primaryDomain: `multi-asset-${Date.now()}.com`,
      clientType: "saas",
      sector: "Technology",
      customerName: "SaaS Corp",
      criticalFunctions: [],
      complianceFlags: [],
      status: "discovering",
      createdBy: 1,
    });
    testScanIds.push(scanId);

    // Create multiple assets
    await createDiscoveredAsset({
      scanId,
      assetId: `a1-${Date.now()}`,
      hostname: "api.saascorp.com",
      assetType: "api_gateway",
      assetClasses: ["api"],
      tags: ["rest", "graphql"],
      hybridRiskScore: 65,
      riskBand: "medium",
      confidence: 80,
      suggestedTier: "tier2_medium",
    });

    await createDiscoveredAsset({
      scanId,
      assetId: `a2-${Date.now()}`,
      hostname: "mail.saascorp.com",
      assetType: "mail_server",
      assetClasses: ["email"],
      tags: ["smtp", "imap"],
      hybridRiskScore: 45,
      riskBand: "medium",
      confidence: 85,
      suggestedTier: "tier2_medium",
    });

    const assets = await getDiscoveredAssetsByScan(scanId);
    expect(assets.length).toBe(2);
    expect(assets.some((a: any) => a.hostname === "api.saascorp.com")).toBe(true);
    expect(assets.some((a: any) => a.hostname === "mail.saascorp.com")).toBe(true);
  });

  it("should store CARVER and SHOCK scores correctly", async () => {
    const scanId = await createDomainIntelScan({
      primaryDomain: `scores-${Date.now()}.com`,
      clientType: "iaas",
      sector: "Technology",
      customerName: "IaaS Corp",
      criticalFunctions: ["infrastructure"],
      complianceFlags: ["SOC2"],
      status: "discovering",
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const carver = { criticality: 8, accessibility: 6, recuperability: 4, vulnerability: 7, effect: 9, recognizability: 3 };
    const shock = { scope: 7, handling: 5, operationalImpact: 8, cascadingEffects: 6, knowledge: 4 };

    await createDiscoveredAsset({
      scanId,
      assetId: `scored-${Date.now()}`,
      hostname: "console.iaascorp.com",
      assetType: "cloud_console",
      assetClasses: ["management"],
      tags: ["aws", "console"],
      carverScores: carver,
      shockScores: shock,
      missionImpactScore: 90,
      cvssEstimate: 68,
      hybridRiskScore: 82,
      riskBand: "critical",
      confidence: 75,
      suggestedTier: "tier0_critical",
    });

    const assets = await getDiscoveredAssetsByScan(scanId);
    const asset = assets[0] as any;
    expect(asset.carverScores).toEqual(carver);
    expect(asset.shockScores).toEqual(shock);
    expect(asset.missionImpactScore).toBe(90);
    expect(asset.cvssEstimate).toBe(68);
    expect(asset.hybridRiskScore).toBe(82);
  });

  it("should store posture findings and test vectors", async () => {
    const scanId = await createDomainIntelScan({
      primaryDomain: `findings-${Date.now()}.com`,
      clientType: "mixed_hosting",
      sector: "Retail",
      customerName: "Retail Corp",
      criticalFunctions: ["payments", "customer_data"],
      complianceFlags: ["PCI-DSS"],
      status: "discovering",
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const findings = [
      { id: "f1", assetRef: "vpn.retailcorp.com", title: "Weak VPN cipher", severity: 7, likelihood: 6, recommendedControls: ["Upgrade TLS"] },
    ];
    const vectors = [
      { vectorType: "credential_spray", hypothesis: "Test default creds on VPN", suggestedEmulation: { technique: "T1110.003" } },
    ];

    await createDiscoveredAsset({
      scanId,
      assetId: `findings-${Date.now()}`,
      hostname: "vpn.retailcorp.com",
      assetType: "vpn_gateway",
      assetClasses: ["remote_access"],
      tags: ["vpn", "ipsec"],
      postureFindings: findings,
      testVectors: vectors,
      hybridRiskScore: 70,
      riskBand: "high",
      confidence: 72,
      suggestedTier: "tier1_high",
    });

    const assets = await getDiscoveredAssetsByScan(scanId);
    const asset = assets[0] as any;
    expect(asset.postureFindings).toEqual(findings);
    expect(asset.testVectors).toEqual(vectors);
  });
});

// ==================== TRPC ROUTER TESTS ====================
describe("Domain Intel tRPC procedures", () => {
  const caller = appRouter.createCaller(createAuthContext());

  it("should list scans via tRPC", async () => {
    const scans = await caller.domainIntel.listScans();
    expect(Array.isArray(scans)).toBe(true);
  });

  it("should get a scan by ID via tRPC", async () => {
    // Create a scan first
    const scanId = await createDomainIntelScan({
      primaryDomain: `trpc-get-${Date.now()}.com`,
      clientType: "enterprise",
      sector: "Government",
      customerName: "Gov Agency",
      criticalFunctions: ["compliance"],
      complianceFlags: ["FedRAMP", "NIST"],
      status: "completed",
      overallRiskScore: 60,
      overallRiskBand: "medium",
      totalAssets: 5,
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const result = await caller.domainIntel.getScan({ id: scanId });
    expect(result.scan).toBeDefined();
    expect(result.scan.primaryDomain).toContain("trpc-get-");
    expect(result.assets).toBeDefined();
    expect(Array.isArray(result.assets)).toBe(true);
  });

  it("should validate startScan input", async () => {
    // Should reject empty domain
    await expect(
      caller.domainIntel.startScan({
        primaryDomain: "",
        clientType: "enterprise",
        sector: "Technology",
        customerName: "Test",
        criticalFunctions: [],
        complianceFlags: [],
      })
    ).rejects.toThrow();
  });

  it("should handle campaign recommendations JSON storage", async () => {
    const scanId = await createDomainIntelScan({
      primaryDomain: `campaigns-${Date.now()}.com`,
      clientType: "msp",
      sector: "Technology",
      customerName: "MSP Test",
      criticalFunctions: ["identity"],
      complianceFlags: [],
      status: "completed",
      campaignRecommendations: [
        {
          id: "camp-1",
          name: "Credential Harvest via SSO Phish",
          type: "phishing",
          priority: "high",
          description: "Target SSO portal users",
          targetAssets: ["sso.msptest.com"],
          mitreTactics: ["Initial Access", "Credential Access"],
          attackChain: [
            { step: 1, phase: "Recon", technique: "T1589", action: "Gather employee emails", tool: "GoPhish" },
          ],
          calderaAbilities: [
            { name: "Credential Dump", tactic: "Credential Access", technique: "T1003", rationale: "Extract cached creds" },
          ],
          gophishTemplates: [
            { name: "SSO Reset", subject: "Password Reset Required", theme: "urgency", targetPersona: "IT Staff", rationale: "Exploit trust in SSO" },
          ],
        },
      ],
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const result = await caller.domainIntel.getScan({ id: scanId });
    expect(result.scan.campaignRecommendations).toBeDefined();
    const campaigns = result.scan.campaignRecommendations as any[];
    expect(campaigns.length).toBe(1);
    expect(campaigns[0].name).toBe("Credential Harvest via SSO Phish");
    expect(campaigns[0].calderaAbilities.length).toBe(1);
    expect(campaigns[0].gophishTemplates.length).toBe(1);
  });

  it("should store and retrieve threat model summary", async () => {
    const summary = "## Threat Model\n\nThis organization faces significant risk from credential-based attacks targeting their SSO infrastructure.";
    const scanId = await createDomainIntelScan({
      primaryDomain: `threat-model-${Date.now()}.com`,
      clientType: "saas",
      sector: "Technology",
      customerName: "SaaS Test",
      criticalFunctions: ["development"],
      complianceFlags: ["SOC2"],
      status: "completed",
      threatModelSummary: summary,
      executiveSummary: "Executive overview of findings.",
      createdBy: 1,
    });
    testScanIds.push(scanId);

    const result = await caller.domainIntel.getScan({ id: scanId });
    expect(result.scan.threatModelSummary).toBe(summary);
    expect(result.scan.executiveSummary).toBe("Executive overview of findings.");
  });
});

// ==================== DOMAIN INTEL ENGINE TYPE TESTS ====================
describe("Domain Intel Engine types", () => {
  it("should export correct OrgProfile interface shape", async () => {
    const { OrgProfile } = await import("./domainIntel") as any;
    // Just verify the module loads without errors
    const module = await import("./domainIntel");
    expect(module.discoverAssets).toBeDefined();
    expect(module.analyzeAssets).toBeDefined();
    expect(module.generateCampaignRecommendations).toBeDefined();
    expect(module.generateSummaries).toBeDefined();
    expect(module.runDomainIntelPipeline).toBeDefined();
    expect(typeof module.discoverAssets).toBe("function");
    expect(typeof module.analyzeAssets).toBe("function");
    expect(typeof module.generateCampaignRecommendations).toBe("function");
    expect(typeof module.generateSummaries).toBe("function");
    expect(typeof module.runDomainIntelPipeline).toBe("function");
  });
});
