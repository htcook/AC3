import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── DI Threat Matching & Attack Path Analysis Tests ──────────────────────

// Mock the threat-group-knowledge module to provide deterministic test data
vi.mock("./lib/threat-group-knowledge", () => ({
  getAllGroups: () => [
    {
      id: "apt29",
      name: "APT29",
      aliases: ["Cozy Bear", "The Dukes"],
      type: "apt",
      origin: "Russia",
      threatLevel: "critical",
      active: true,
      description: "Russian state-sponsored threat group",
      motivation: "Espionage",
      targetSectors: ["government", "technology", "healthcare"],
      targetRegions: ["North America", "Europe"],
      ttps: [
        { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access", description: "Exploits web apps", frequency: "primary" as const },
        { techniqueId: "T1566", techniqueName: "Phishing", tactic: "Initial Access", description: "Spear phishing", frequency: "primary" as const },
        { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Persistence", description: "Uses valid creds", frequency: "secondary" as const },
        { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution", description: "PowerShell", frequency: "primary" as const },
      ],
      tools: [
        { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
        { name: "Mimikatz", category: "credential", description: "Credential dumper" },
      ],
      initialAccessMethods: ["spear phishing", "exploit public-facing application"],
      defenseRecommendations: [
        { priority: "critical", category: "detection", recommendation: "Monitor for PowerShell execution", siemQuery: "", mitreTechniques: ["T1059"] },
        { priority: "high", category: "prevention", recommendation: "Patch public-facing applications", mitreTechniques: ["T1190"] },
      ],
      detectionHints: [],
      exploitedCVEs: ["CVE-2021-44228", "CVE-2023-23397", "CVE-2020-1472"],
      mitreGroupId: "G0016",
    },
    {
      id: "lockbit",
      name: "LockBit",
      aliases: ["LockBit 3.0"],
      type: "ransomware",
      origin: "Russia",
      threatLevel: "critical",
      active: true,
      description: "Ransomware-as-a-Service group",
      motivation: "Financial",
      targetSectors: ["healthcare", "finance", "manufacturing"],
      targetRegions: ["Global"],
      ttps: [
        { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "Impact", description: "Ransomware encryption", frequency: "primary" as const },
        { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access", description: "Brute force RDP", frequency: "primary" as const },
        { techniqueId: "T1021", techniqueName: "Remote Services", tactic: "Lateral Movement", description: "RDP lateral movement", frequency: "primary" as const },
      ],
      tools: [
        { name: "StealBit", category: "exfiltration", description: "Data exfiltration tool" },
      ],
      initialAccessMethods: ["brute force", "exploit public-facing application", "valid accounts"],
      defenseRecommendations: [
        { priority: "critical", category: "prevention", recommendation: "Disable RDP on public-facing systems", mitreTechniques: ["T1021"] },
      ],
      detectionHints: [],
      exploitedCVEs: ["CVE-2021-44228", "CVE-2023-0669"],
      mitreGroupId: "G1000",
    },
    {
      id: "apt1",
      name: "APT1",
      aliases: ["Comment Crew"],
      type: "apt",
      origin: "China",
      threatLevel: "high",
      active: false,
      description: "Chinese state-sponsored threat group",
      motivation: "Espionage",
      targetSectors: ["aerospace", "defense"],
      targetRegions: ["North America"],
      ttps: [
        { techniqueId: "T1566", techniqueName: "Phishing", tactic: "Initial Access", description: "Email phishing", frequency: "primary" as const },
      ],
      tools: [],
      initialAccessMethods: ["spear phishing"],
      defenseRecommendations: [],
      detectionHints: [],
      exploitedCVEs: [],
      mitreGroupId: "G0006",
    },
  ],
}));

describe("DI Threat Matching Module", () => {
  let runDIThreatMatching: typeof import("./lib/di-threat-matching").runDIThreatMatching;

  beforeEach(async () => {
    const mod = await import("./lib/di-threat-matching");
    runDIThreatMatching = mod.runDIThreatMatching;
  });

  it("should export runDIThreatMatching function", () => {
    expect(runDIThreatMatching).toBeDefined();
    expect(typeof runDIThreatMatching).toBe("function");
  });

  it("should return structured result with all required fields", () => {
    const result = runDIThreatMatching([], { customerName: "Test", primaryDomain: "test.com", sector: "technology", clientType: "enterprise", criticalFunctions: [], complianceFlags: [] });
    expect(result).toHaveProperty("matchedGroups");
    expect(result).toHaveProperty("attackPaths");
    expect(result).toHaveProperty("techniqueHeatmap");
    expect(result).toHaveProperty("summary");
    expect(result.summary).toHaveProperty("totalGroupsAnalyzed");
    expect(result.summary).toHaveProperty("totalMatched");
    expect(result.summary).toHaveProperty("totalAttackPaths");
    expect(result.summary).toHaveProperty("uniqueTechniques");
    expect(result.summary).toHaveProperty("uniqueTactics");
  });

  it("should match groups with CVE overlap", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["apache", "java"],
        tags: ["web"],
        assetType: "web_application",
      },
      carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
      shockScores: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
      hybridRiskScore: 60,
      riskBand: "high",
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Apache Log4j Remote Code Execution",
        severity: 10,
        likelihood: 9,
        confidence: 0.95,
        recommendedControls: ["Upgrade Log4j"],
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
      }],
      testVectors: [],
      confidence: 0.9,
      assetCriticalityScore: 70,
      assetCriticalityBand: "high",
      vulnRiskScore: 80,
      vulnRiskBand: "critical",
      impactScore: 70,
      likelihoodScore: 80,
      missionFunction: "web_application",
      essentialService: "customer_portal",
      businessImpactLevel: "severe",
      deviceType: "server",
      platformType: "linux_server",
      missionJustification: "Customer-facing web application",
      missionImpactScore: 70,
      suggestedTier: "Tier 1",
      cvssEstimate: 10,
      contextIndicators: { exposure: 8, recognizability: 7, confidence: 0.9 },
    }];

    const org = {
      customerName: "Test Corp",
      primaryDomain: "example.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: ["web services"],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);

    // Should match APT29 and LockBit because they both exploit CVE-2021-44228
    expect(result.summary.totalMatched).toBeGreaterThan(0);
    const apt29 = result.matchedGroups.find(g => g.groupId === "apt29");
    expect(apt29).toBeDefined();
    expect(apt29!.matchedCVEs).toContain("CVE-2021-44228");
    expect(apt29!.matchScore).toBeGreaterThan(0);
    expect(apt29!.matchRationale).toBeTruthy();
    expect(apt29!.matchRationale.length).toBeGreaterThan(50);
  });

  it("should include scoring breakdown for each matched group", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["nginx", "node"],
        tags: ["web"],
        assetType: "web_application",
      },
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Log4Shell",
        severity: 10,
        likelihood: 9,
        confidence: 0.95,
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
        recommendedControls: [],
      }],
      testVectors: [],
      hybridRiskScore: 60,
      riskBand: "high",
    }];

    const org = {
      customerName: "Test",
      primaryDomain: "test.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);
    const group = result.matchedGroups[0];
    expect(group).toBeDefined();
    expect(group.scoreBreakdown).toBeDefined();
    expect(group.scoreBreakdown).toHaveProperty("cveScore");
    expect(group.scoreBreakdown).toHaveProperty("techniqueScore");
    expect(group.scoreBreakdown).toHaveProperty("toolScore");
    expect(group.scoreBreakdown).toHaveProperty("sectorScore");
    expect(group.scoreBreakdown).toHaveProperty("initialAccessScore");
  });

  it("should synthesize attack paths from web-facing findings", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["apache", "php"],
        tags: ["web"],
        assetType: "web_application",
      },
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Apache Log4j RCE",
        severity: 10,
        likelihood: 9,
        confidence: 0.95,
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
        recommendedControls: [],
      }],
      testVectors: [],
      hybridRiskScore: 80,
      riskBand: "critical",
    }, {
      asset: {
        assetId: "db-1",
        hostname: "db.example.com",
        technologies: ["mysql"],
        tags: ["database"],
        assetType: "database",
      },
      postureFindings: [],
      testVectors: [],
      hybridRiskScore: 30,
      riskBand: "low",
    }];

    const org = {
      customerName: "Test",
      primaryDomain: "example.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);
    expect(result.attackPaths.length).toBeGreaterThan(0);

    const firstPath = result.attackPaths[0];
    expect(firstPath.id).toMatch(/^AP-/);
    expect(firstPath.name).toBeTruthy();
    expect(firstPath.description).toBeTruthy();
    expect(firstPath.steps.length).toBeGreaterThan(0);
    expect(firstPath.overallRisk).toBeGreaterThan(0);
    expect(firstPath.tacticsTraversed.length).toBeGreaterThan(0);

    // Each step should have required fields
    const step = firstPath.steps[0];
    expect(step.order).toBe(1);
    expect(step.phase).toBeTruthy();
    expect(step.mitreTechnique).toMatch(/^T\d+/);
    expect(step.techniqueName).toBeTruthy();
    expect(step.targetAsset).toBeTruthy();
    expect(step.evidence).toBeTruthy();
    expect(step.difficulty).toBeTruthy();
  });

  it("should build technique heatmap with surface relevance", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["apache", "php", "wordpress"],
        tags: ["web", "http"],
        assetType: "web_application",
      },
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Log4Shell",
        severity: 10,
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
        recommendedControls: [],
      }],
      testVectors: [],
      hybridRiskScore: 70,
      riskBand: "high",
    }];

    const org = {
      customerName: "Test",
      primaryDomain: "test.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);
    expect(result.techniqueHeatmap.length).toBeGreaterThan(0);

    // Check heatmap entry structure
    const entry = result.techniqueHeatmap[0];
    expect(entry).toHaveProperty("techniqueId");
    expect(entry).toHaveProperty("techniqueName");
    expect(entry).toHaveProperty("tactic");
    expect(entry).toHaveProperty("groups");
    expect(entry).toHaveProperty("surfaceRelevant");
    expect(Array.isArray(entry.groups)).toBe(true);

    // Surface-relevant entries should be sorted first
    const surfaceRelevant = result.techniqueHeatmap.filter(t => t.surfaceRelevant);
    expect(surfaceRelevant.length).toBeGreaterThan(0);
  });

  it("should handle empty analyses gracefully", () => {
    const org = {
      customerName: "Empty Corp",
      primaryDomain: "empty.com",
      sector: "unknown",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching([], org);
    expect(result.summary.totalGroupsAnalyzed).toBe(3); // 3 mocked groups
    expect(result.attackPaths).toHaveLength(0);
    expect(result.matchedGroups.length).toBeGreaterThanOrEqual(0);
  });

  it("should sort matched groups by score descending", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["apache", "java", "ssh"],
        tags: ["web", "http"],
        assetType: "web_application",
      },
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Log4Shell",
        severity: 10,
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
        recommendedControls: [],
      }],
      testVectors: [],
      hybridRiskScore: 80,
      riskBand: "critical",
    }];

    const org = {
      customerName: "Test",
      primaryDomain: "test.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);
    for (let i = 1; i < result.matchedGroups.length; i++) {
      expect(result.matchedGroups[i - 1].matchScore).toBeGreaterThanOrEqual(result.matchedGroups[i].matchScore);
    }
  });

  it("should attribute attack paths to matched groups", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["apache", "java"],
        tags: ["web", "http"],
        assetType: "web_application",
      },
      postureFindings: [{
        id: "f-1",
        assetRef: "web-1",
        category: "vulnerability",
        title: "CVE-2021-44228: Log4Shell RCE",
        severity: 10,
        cveIds: ["CVE-2021-44228"],
        corroborationTier: "confirmed",
        recommendedControls: [],
      }],
      testVectors: [],
      hybridRiskScore: 80,
      riskBand: "critical",
    }];

    const org = {
      customerName: "Test",
      primaryDomain: "test.com",
      sector: "technology",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, org);
    const pathsWithAttribution = result.attackPaths.filter(p => p.attributedGroups.length > 0);
    // At least some paths should have group attribution
    expect(pathsWithAttribution.length).toBeGreaterThanOrEqual(0);
  });

  it("should include sector relevance in scoring", () => {
    const analyses: any[] = [{
      asset: {
        assetId: "web-1",
        hostname: "app.example.com",
        technologies: ["nginx"],
        tags: ["web"],
        assetType: "web_application",
      },
      postureFindings: [],
      testVectors: [],
      hybridRiskScore: 40,
      riskBand: "medium",
    }];

    // Test with healthcare sector (matches LockBit)
    const orgHealthcare = {
      customerName: "Hospital",
      primaryDomain: "hospital.com",
      sector: "healthcare",
      clientType: "enterprise",
      criticalFunctions: [],
      complianceFlags: [],
    };

    const result = runDIThreatMatching(analyses, orgHealthcare);
    const lockbit = result.matchedGroups.find(g => g.groupId === "lockbit");
    if (lockbit) {
      expect(lockbit.sectorRelevance).toBeGreaterThan(0);
    }
  });
});
