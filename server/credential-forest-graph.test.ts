/**
 * Tests for Credential Rotation Alerts, AD Attack Path Graph, and Forest Mapper
 */
import { describe, it, expect } from "vitest";

// ─── Credential Rotation Alerts ─────────────────────────────────────────────

describe("Credential Rotation Alerts", () => {
  it("should import the credential rotation alerts module", async () => {
    const mod = await import("./lib/credential-rotation-alerts");
    expect(mod).toBeDefined();
    expect(mod.calculateDaysUntilExpiry).toBeDefined();
    expect(mod.determineSeverity).toBeDefined();
    expect(mod.determineAlertType).toBeDefined();
    expect(mod.checkCredentialAgainstRule).toBeDefined();
    expect(mod.batchCheckCredentials).toBeDefined();
    expect(mod.formatNotificationContent).toBeDefined();
    expect(mod.DEFAULT_ROTATION_THRESHOLDS).toBeDefined();
  });

  it("should have default rotation thresholds for all providers", async () => {
    const { DEFAULT_ROTATION_THRESHOLDS } = await import("./lib/credential-rotation-alerts");
    expect(DEFAULT_ROTATION_THRESHOLDS).toHaveProperty("aws");
    expect(DEFAULT_ROTATION_THRESHOLDS).toHaveProperty("azure");
    expect(DEFAULT_ROTATION_THRESHOLDS).toHaveProperty("gcp");
    expect(DEFAULT_ROTATION_THRESHOLDS.aws).toBe(90);
    expect(DEFAULT_ROTATION_THRESHOLDS.azure).toBe(180);
    expect(DEFAULT_ROTATION_THRESHOLDS.gcp).toBe(90);
  });

  it("should calculate days until expiry correctly", async () => {
    const { calculateDaysUntilExpiry } = await import("./lib/credential-rotation-alerts");
    const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const days = calculateDaysUntilExpiry(futureDate);
    expect(days).toBeGreaterThanOrEqual(29);
    expect(days).toBeLessThanOrEqual(31);

    const pastDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const pastDays = calculateDaysUntilExpiry(pastDate);
    expect(pastDays).toBeLessThan(0);

    expect(calculateDaysUntilExpiry(null)).toBeNull();
  });

  it("should determine severity based on days until expiry", async () => {
    const { determineSeverity } = await import("./lib/credential-rotation-alerts");
    expect(determineSeverity(1)).toBe("critical");
    expect(determineSeverity(3)).toBe("critical");
    expect(determineSeverity(5)).toBe("high");
    expect(determineSeverity(7)).toBe("high");
    expect(determineSeverity(15)).toBe("medium");
    expect(determineSeverity(30)).toBe("medium");
    expect(determineSeverity(90)).toBe("low");
    expect(determineSeverity(null)).toBe("low");
  });

  it("should determine alert type correctly", async () => {
    const { determineAlertType } = await import("./lib/credential-rotation-alerts");
    expect(determineAlertType(-5, "active", 30)).toBe("expired");
    expect(determineAlertType(10, "active", 30)).toBe("expiring_soon");
    expect(determineAlertType(null, "error", 30)).toBe("validation_failed");
    expect(determineAlertType(100, "active", 30)).toBe("rotation_due");
  });

  it("should check credential against rule and generate alert for expired", async () => {
    const { checkCredentialAgainstRule } = await import("./lib/credential-rotation-alerts");
    const cred = {
      credentialId: 1,
      credentialName: "prod-aws-key",
      provider: "aws",
      expiresAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      daysUntilExpiry: -5,
      status: "active",
      lastValidatedAt: new Date(),
    };
    const rule = {
      id: 1,
      credentialId: 1,
      alertName: "AWS Key Rotation",
      thresholdDays: 30,
      isEnabled: true,
      notifyOwner: true,
    };
    const result = checkCredentialAgainstRule(cred, rule);
    expect(result).not.toBeNull();
    expect(result!.alertType).toBe("expired");
    expect(result!.severity).toBe("critical");
    expect(result!.shouldNotify).toBe(true);
  });

  it("should skip disabled rules", async () => {
    const { checkCredentialAgainstRule } = await import("./lib/credential-rotation-alerts");
    const cred = {
      credentialId: 1,
      credentialName: "test",
      provider: "aws",
      expiresAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
      daysUntilExpiry: -100,
      status: "active",
      lastValidatedAt: new Date(),
    };
    const rule = {
      id: 1,
      credentialId: 1,
      alertName: "Disabled Rule",
      thresholdDays: 30,
      isEnabled: false,
      notifyOwner: true,
    };
    const result = checkCredentialAgainstRule(cred, rule);
    expect(result).toBeNull();
  });

  it("should batch check multiple credentials", async () => {
    const { batchCheckCredentials } = await import("./lib/credential-rotation-alerts");
    const credentials = [
      {
        credentialId: 1, credentialName: "expired-key", provider: "aws",
        expiresAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
        daysUntilExpiry: -10, status: "active", lastValidatedAt: new Date(),
      },
      {
        credentialId: 2, credentialName: "healthy-key", provider: "azure",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
        daysUntilExpiry: 90, status: "active", lastValidatedAt: new Date(),
      },
    ];
    const rules = [
      { id: 1, credentialId: 1, alertName: "Rule 1", thresholdDays: 30, isEnabled: true, notifyOwner: true },
      { id: 2, credentialId: 2, alertName: "Rule 2", thresholdDays: 30, isEnabled: true, notifyOwner: false },
    ];
    const results = batchCheckCredentials(credentials, rules);
    expect(results).toBeInstanceOf(Array);
    const expiredAlert = results.find((r: any) => r.credentialId === 1);
    expect(expiredAlert).toBeDefined();
  });

  it("should format notification content", async () => {
    const { formatNotificationContent } = await import("./lib/credential-rotation-alerts");
    const alerts = [
      { ruleId: 1, credentialId: 1, alertType: "expired" as const, severity: "critical" as const, message: "Key expired", daysUntilExpiry: -5, shouldNotify: true },
    ];
    const credentials = [
      { credentialId: 1, credentialName: "prod-key", provider: "aws", expiresAt: null, daysUntilExpiry: null, status: "active", lastValidatedAt: null },
    ];
    const result = formatNotificationContent(alerts, credentials);
    expect(result).toHaveProperty("title");
    expect(result).toHaveProperty("content");
    expect(result.title).toContain("Critical");
    expect(result.content).toContain("Credential Rotation Alert");
  });
});

// ─── AD Attack Path Graph ───────────────────────────────────────────────────

describe("AD Attack Path Graph", () => {
  it("should import the attack path graph module", async () => {
    const mod = await import("./lib/ad-attack-path-graph");
    expect(mod).toBeDefined();
    expect(mod.buildAttackGraph).toBeDefined();
    expect(mod.findShortestPath).toBeDefined();
    expect(mod.buildGraphFromADObjects).toBeDefined();
    expect(mod.findAttackPaths).toBeDefined();
    expect(mod.assignLayers).toBeDefined();
  });

  it("should have edge weights for all edge types", async () => {
    const { EDGE_WEIGHTS } = await import("./lib/ad-attack-path-graph");
    expect(EDGE_WEIGHTS).toBeDefined();
    expect(EDGE_WEIGHTS.memberOf).toBeDefined();
    expect(EDGE_WEIGHTS.adminTo).toBeDefined();
    expect(EDGE_WEIGHTS.kerberoastable).toBeDefined();
    expect(EDGE_WEIGHTS.dcsync).toBeDefined();
  });

  it("should build a graph from AD objects", async () => {
    const { buildGraphFromADObjects } = await import("./lib/ad-attack-path-graph");
    const users = [
      { id: 1, objectName: "user1", objectType: "user", distinguishedName: "CN=user1,DC=test", isPrivileged: false, properties: JSON.stringify({ memberOf: ["CN=Group1,DC=test"] }) },
    ];
    const groups = [
      { id: 2, objectName: "Group1", objectType: "group", distinguishedName: "CN=Group1,DC=test", isPrivileged: true, properties: JSON.stringify({ members: ["CN=user1,DC=test"] }) },
    ];
    const result = buildGraphFromADObjects(users, groups, [], [], [], []);
    expect(result.nodes).toBeInstanceOf(Array);
    expect(result.edges).toBeInstanceOf(Array);
    expect(result.nodes.length).toBeGreaterThanOrEqual(2);
  });

  it("should assign risk scores to privileged nodes", async () => {
    const { buildGraphFromADObjects } = await import("./lib/ad-attack-path-graph");
    const users = [
      { id: 1, samAccountName: "admin", displayName: "admin", distinguishedName: "CN=admin,DC=test", isPrivileged: true, properties: {} },
    ];
    const result = buildGraphFromADObjects(users, [], [], [], [], []);
    const adminNode = result.nodes.find((n: any) => n.label === "admin");
    expect(adminNode).toBeDefined();
    expect(adminNode!.isHighValue).toBe(true);
    expect(adminNode!.riskScore).toBeGreaterThan(0);
  });

  it("should return null for unreachable paths", async () => {
    const { findShortestPath } = await import("./lib/ad-attack-path-graph");
    const nodes = [
      { id: "a", label: "A", type: "user" as const, isHighValue: false, isCompromised: false, isEnabled: true, riskScore: 0, properties: {} },
      { id: "b", label: "B", type: "user" as const, isHighValue: false, isCompromised: false, isEnabled: true, riskScore: 0, properties: {} },
    ];
    const edges: any[] = [];
    const path = findShortestPath(nodes, edges, "a", "b");
    expect(path).toBeNull();
  });

  it("should find a path when one exists", async () => {
    const { findShortestPath } = await import("./lib/ad-attack-path-graph");
    const nodes = [
      { id: "a", label: "A", type: "user" as const, isHighValue: false, isCompromised: true, isEnabled: true, riskScore: 10, properties: {} },
      { id: "b", label: "B", type: "group" as const, isHighValue: false, isCompromised: false, isEnabled: true, riskScore: 30, properties: {} },
      { id: "c", label: "C", type: "group" as const, isHighValue: true, isCompromised: false, isEnabled: true, riskScore: 90, properties: {} },
    ];
    const edges = [
      { id: "e1", source: "a", target: "b", type: "memberOf" as const, weight: 1, isExploitable: true, properties: {} },
      { id: "e2", source: "b", target: "c", type: "memberOf" as const, weight: 1, isExploitable: true, properties: {} },
    ];
    const path = findShortestPath(nodes, edges, "a", "c");
    expect(path).not.toBeNull();
    expect(path!.nodes).toEqual(["a", "b", "c"]);
    expect(path!.hops).toBe(2);
    expect(path!.techniques).toBeInstanceOf(Array);
    expect(path!.riskLevel).toBeDefined();
  });

  it("should build full attack graph with stats", async () => {
    const { buildAttackGraph } = await import("./lib/ad-attack-path-graph");
    const result = buildAttackGraph([], [], [], [], [], []);
    expect(result).toHaveProperty("nodes");
    expect(result).toHaveProperty("edges");
    expect(result).toHaveProperty("paths");
    expect(result).toHaveProperty("stats");
    expect(result.stats).toHaveProperty("totalNodes");
    expect(result.stats).toHaveProperty("totalEdges");
    expect(result.stats).toHaveProperty("highValueTargets");
    expect(result.stats).toHaveProperty("totalAttackPaths");
  });

  it("should assign layers to nodes for hierarchical layout", async () => {
    const { assignLayers } = await import("./lib/ad-attack-path-graph");
    const nodes = [
      { id: "a", label: "A", type: "user" as const, isHighValue: false, isCompromised: true, isEnabled: true, riskScore: 10, properties: {} },
      { id: "b", label: "B", type: "group" as const, isHighValue: true, isCompromised: false, isEnabled: true, riskScore: 90, properties: {} },
    ];
    const edges = [
      { id: "e1", source: "a", target: "b", type: "memberOf" as const, weight: 1, isExploitable: true, properties: {} },
    ];
    const layered = assignLayers(nodes, edges);
    expect(layered).toBeInstanceOf(Array);
    expect(layered.length).toBe(2);
    for (const node of layered) {
      expect(node.x).toBeDefined();
      expect(node.y).toBeDefined();
    }
  });
});

// ─── Forest Mapper ──────────────────────────────────────────────────────────

describe("Forest Mapper", () => {
  it("should import the forest mapper module", async () => {
    const mod = await import("./lib/forest-mapper");
    expect(mod).toBeDefined();
    expect(mod.analyzeTrustVulnerabilities).toBeDefined();
    expect(mod.buildForestTopology).toBeDefined();
    expect(mod.generateForestLayout).toBeDefined();
    expect(mod.TRUST_VULNERABILITY_PATTERNS).toBeDefined();
  });

  it("should have trust vulnerability patterns", async () => {
    const { TRUST_VULNERABILITY_PATTERNS } = await import("./lib/forest-mapper");
    expect(TRUST_VULNERABILITY_PATTERNS).toBeInstanceOf(Array);
    expect(TRUST_VULNERABILITY_PATTERNS.length).toBeGreaterThan(0);
    const first = TRUST_VULNERABILITY_PATTERNS[0];
    expect(first).toHaveProperty("id");
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("severity");
    expect(first).toHaveProperty("description");
    expect(first).toHaveProperty("remediation");
    expect(first).toHaveProperty("check");
    expect(typeof first.check).toBe("function");
  });

  it("should detect SID filtering disabled vulnerability", async () => {
    const { analyzeTrustVulnerabilities } = await import("./lib/forest-mapper");
    const trusts: any[] = [{
      id: 1, sourceDomainId: 1, targetDomainId: 2,
      direction: "bidirectional", trustType: "forest", isTransitive: true,
      sidFilteringEnabled: false, selectiveAuth: false, trustAttributes: 0,
      isVulnerable: false, vulnerabilityNotes: null,
    }];
    const domains: any[] = [
      { id: 1, forestName: "corp.com", domainName: "corp.com", isForestRoot: true, totalUsers: 100, totalGroups: 10, totalComputers: 50, privilegedUsers: 5 },
      { id: 2, forestName: "partner.com", domainName: "partner.com", isForestRoot: true, totalUsers: 50, totalGroups: 5, totalComputers: 20, privilegedUsers: 2 },
    ];
    const vulns = analyzeTrustVulnerabilities(trusts, domains);
    expect(vulns).toBeInstanceOf(Array);
    expect(vulns.length).toBeGreaterThan(0);
    const sidVuln = vulns.find((v: any) => v.vulnerabilityType.includes("SID Filtering"));
    expect(sidVuln).toBeDefined();
    expect(sidVuln!.severity).toBe("critical");
  });

  it("should build forest topology from domains and trusts", async () => {
    const { buildForestTopology } = await import("./lib/forest-mapper");
    const domains: any[] = [
      { id: 1, forestName: "corp.com", domainName: "corp.com", isForestRoot: true, totalUsers: 500, totalComputers: 100, totalGroups: 50, privilegedUsers: 10 },
      { id: 2, forestName: "corp.com", domainName: "na.corp.com", isForestRoot: false, totalUsers: 200, totalComputers: 50, totalGroups: 20, privilegedUsers: 5, parentDomainId: 1 },
    ];
    const topology = buildForestTopology(domains, []);
    expect(topology).toHaveProperty("domains");
    expect(topology).toHaveProperty("trusts");
    expect(topology).toHaveProperty("forests");
    expect(topology).toHaveProperty("vulnerabilities");
    expect(topology).toHaveProperty("stats");
    expect(topology.forests.length).toBe(1);
    expect(topology.forests[0].forestName).toBe("corp.com");
    expect(topology.stats.totalDomains).toBe(2);
    expect(topology.stats.totalUsers).toBe(700);
  });

  it("should generate forest layout with positioned nodes", async () => {
    const { buildForestTopology, generateForestLayout } = await import("./lib/forest-mapper");
    const domains: any[] = [
      { id: 1, forestName: "corp.com", domainName: "corp.com", isForestRoot: true, totalUsers: 500, totalComputers: 100, totalGroups: 50, privilegedUsers: 10 },
      { id: 2, forestName: "corp.com", domainName: "child.corp.com", isForestRoot: false, totalUsers: 100, totalComputers: 20, totalGroups: 10, privilegedUsers: 2, parentDomainId: 1 },
    ];
    const topology = buildForestTopology(domains, []);
    const layout = generateForestLayout(topology);
    expect(layout).toHaveProperty("nodes");
    expect(layout).toHaveProperty("edges");
    expect(layout.nodes.length).toBe(2);
    const rootNode = layout.nodes.find((n: any) => n.type === "root");
    const childNode = layout.nodes.find((n: any) => n.type === "domain");
    expect(rootNode).toBeDefined();
    expect(childNode).toBeDefined();
    expect(rootNode!.y).toBeLessThan(childNode!.y);
  });

  it("should count cross-forest trusts correctly", async () => {
    const { buildForestTopology } = await import("./lib/forest-mapper");
    const domains: any[] = [
      { id: 1, forestName: "corp.com", domainName: "corp.com", isForestRoot: true, totalUsers: 500, totalComputers: 100, totalGroups: 50, privilegedUsers: 10 },
      { id: 2, forestName: "partner.com", domainName: "partner.com", isForestRoot: true, totalUsers: 200, totalComputers: 50, totalGroups: 20, privilegedUsers: 5 },
    ];
    const trusts: any[] = [{
      id: 1, sourceDomainId: 1, targetDomainId: 2, direction: "bidirectional",
      trustType: "forest", isTransitive: true, sidFilteringEnabled: true, selectiveAuth: true,
      trustAttributes: 0, isVulnerable: false, vulnerabilityNotes: null,
    }];
    const topology = buildForestTopology(domains, trusts);
    expect(topology.stats.crossForestTrusts).toBe(1);
    expect(topology.stats.totalForests).toBe(2);
  });
});
