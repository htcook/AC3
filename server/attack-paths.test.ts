import { describe, it, expect } from "vitest";
import {
  discoverAttackPaths,
  ingestVulnDataToGraph,
  type GraphNode,
  type GraphEdge,
} from "./lib/attack-path-discovery";

// ─── discoverAttackPaths ───

describe("discoverAttackPaths", () => {
  const baseNodes: GraphNode[] = [
    { id: 1, type: "user", name: "jdoe", riskScore: 20, isCrownJewel: false },
    { id: 2, type: "computer", name: "WS01", riskScore: 40, isCrownJewel: false },
    { id: 3, type: "group", name: "Domain Admins", riskScore: 90, isCrownJewel: true },
  ];

  const baseEdges: GraphEdge[] = [
    { id: 1, sourceNodeId: 1, targetNodeId: 2, edgeType: "hasSession", probability: 0.8 },
    { id: 2, sourceNodeId: 2, targetNodeId: 3, edgeType: "adminTo", probability: 0.6 },
  ];

  it("should discover paths from entry points to crown jewels", () => {
    const paths = discoverAttackPaths(baseNodes, baseEdges);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].crownJewelTarget).toBe("Domain Admins");
    // All paths should end at the crown jewel (node 3)
    for (const p of paths) {
      expect(p.nodes).toContain(3);
    }
    // At least one path should start from an entry point
    const entryNodeIds = [1, 2]; // user and computer are entry types
    const hasEntryPath = paths.some(p => entryNodeIds.includes(p.nodes[0]));
    expect(hasEntryPath).toBe(true);
  });

  it("should respect maxHops parameter", () => {
    // With maxHops=1, only 1-hop paths are found (computer->DA is 1 hop)
    // The 2-hop path (user->computer->DA) should not be found with maxHops=1
    const paths = discoverAttackPaths(baseNodes, baseEdges, 1);
    // computer type is an entry point, so computer->DA (1 hop) is found
    for (const p of paths) {
      expect(p.totalHops).toBeLessThanOrEqual(1);
    }
  });

  it("should respect maxPaths parameter", () => {
    const paths = discoverAttackPaths(baseNodes, baseEdges, 10, 1);
    expect(paths.length).toBeLessThanOrEqual(1);
  });

  it("should return empty array when no crown jewels exist", () => {
    const noJewels = baseNodes.map((n) => ({ ...n, isCrownJewel: false }));
    const paths = discoverAttackPaths(noJewels, baseEdges);
    expect(paths).toEqual([]);
  });

  it("should return empty array when no entry points exist", () => {
    // All nodes are crown jewels (no entry points)
    const allJewels = baseNodes.map((n) => ({ ...n, isCrownJewel: true }));
    const paths = discoverAttackPaths(allJewels, baseEdges);
    expect(paths).toEqual([]);
  });

  it("should return empty array when no edges exist", () => {
    const paths = discoverAttackPaths(baseNodes, []);
    expect(paths.length).toBe(0);
  });

  it("should calculate risk score for discovered paths", () => {
    const paths = discoverAttackPaths(baseNodes, baseEdges);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].riskScore).toBeGreaterThan(0);
    expect(typeof paths[0].riskScore).toBe("number");
  });

  it("should calculate totalHops correctly", () => {
    const paths = discoverAttackPaths(baseNodes, baseEdges);
    expect(paths.length).toBeGreaterThan(0);
    // totalHops = nodes.length - 1
    for (const p of paths) {
      expect(p.totalHops).toBe(p.nodes.length - 1);
    }
  });

  it("should name paths as 'entry → target'", () => {
    const paths = discoverAttackPaths(baseNodes, baseEdges);
    // All paths should end with the crown jewel target
    for (const p of paths) {
      expect(p.name).toContain("→ Domain Admins");
    }
  });

  it("should sort paths by risk score descending", () => {
    // Create a graph with multiple paths of different risks
    const nodes: GraphNode[] = [
      { id: 1, type: "user", name: "low-risk-user", riskScore: 10, isCrownJewel: false },
      { id: 2, type: "user", name: "high-risk-user", riskScore: 80, isCrownJewel: false },
      { id: 3, type: "computer", name: "server", riskScore: 50, isCrownJewel: false },
      { id: 4, type: "group", name: "DA", riskScore: 95, isCrownJewel: true },
    ];
    const edges: GraphEdge[] = [
      { id: 1, sourceNodeId: 1, targetNodeId: 3, edgeType: "hasSession", probability: 0.3 },
      { id: 2, sourceNodeId: 2, targetNodeId: 3, edgeType: "hasSession", probability: 0.9 },
      { id: 3, sourceNodeId: 3, targetNodeId: 4, edgeType: "adminTo", probability: 0.7 },
    ];
    const paths = discoverAttackPaths(nodes, edges);
    if (paths.length >= 2) {
      expect(paths[0].riskScore).toBeGreaterThanOrEqual(paths[1].riskScore);
    }
  });

  it("should compute choke points for nodes appearing in multiple paths", () => {
    // Create a graph where node 3 is a choke point
    const nodes: GraphNode[] = [
      { id: 1, type: "user", name: "user1", riskScore: 20, isCrownJewel: false },
      { id: 2, type: "user", name: "user2", riskScore: 20, isCrownJewel: false },
      { id: 3, type: "computer", name: "chokepoint-server", riskScore: 60, isCrownJewel: false },
      { id: 4, type: "group", name: "DA", riskScore: 95, isCrownJewel: true },
    ];
    const edges: GraphEdge[] = [
      { id: 1, sourceNodeId: 1, targetNodeId: 3, edgeType: "hasSession", probability: 0.8 },
      { id: 2, sourceNodeId: 2, targetNodeId: 3, edgeType: "hasSession", probability: 0.8 },
      { id: 3, sourceNodeId: 3, targetNodeId: 4, edgeType: "adminTo", probability: 0.7 },
    ];
    const paths = discoverAttackPaths(nodes, edges);
    expect(paths.length).toBeGreaterThanOrEqual(2);
    // Node 3 should be a choke point since both paths go through it
    const hasChokePoint = paths.some((p) =>
      p.chokePoints.some((cp) => cp.nodeId === 3)
    );
    expect(hasChokePoint).toBe(true);
  });
});

// ─── ingestVulnDataToGraph ───

describe("ingestVulnDataToGraph", () => {
  const existingNodes: GraphNode[] = [
    {
      id: 1,
      type: "computer",
      name: "Server1",
      riskScore: 50,
      isCrownJewel: false,
      properties: { ip: "10.0.0.1" },
    },
    {
      id: 2,
      type: "computer",
      name: "Server2",
      riskScore: 30,
      isCrownJewel: false,
      properties: { ip: "10.0.0.2" },
    },
  ];

  it("should create vulnerability nodes from findings", () => {
    const findings = [
      { cveId: "CVE-2024-1234", hostIp: "10.0.0.1", severity: "critical", exploitAvailable: true, cvssScore: 9.8 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes.length).toBe(1);
    expect(result.newNodes[0].type).toBe("vulnerability");
    expect(result.newNodes[0].name).toBe("CVE-2024-1234");
  });

  it("should create edges linking vulns to matching hosts", () => {
    const findings = [
      { cveId: "CVE-2024-1234", hostIp: "10.0.0.1", severity: "critical", exploitAvailable: true, cvssScore: 9.8 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newEdges.length).toBe(1);
    expect(result.newEdges[0].targetNodeId).toBe(1); // Server1
    expect(result.newEdges[0].edgeType).toBe("exploits");
  });

  it("should set higher probability for exploitable vulns", () => {
    const findings = [
      { cveId: "CVE-2024-1111", hostIp: "10.0.0.1", severity: "high", exploitAvailable: true, cvssScore: 8.0 },
      { cveId: "CVE-2024-2222", hostIp: "10.0.0.2", severity: "medium", exploitAvailable: false, cvssScore: 5.0 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    const exploitableEdge = result.newEdges.find((e) => e.technique === "CVE-2024-1111");
    const nonExploitableEdge = result.newEdges.find((e) => e.technique === "CVE-2024-2222");
    expect(exploitableEdge!.probability).toBe(0.8);
    expect(nonExploitableEdge!.probability).toBe(0.3);
  });

  it("should deduplicate CVEs", () => {
    const findings = [
      { cveId: "CVE-2024-1234", hostIp: "10.0.0.1", severity: "critical", exploitAvailable: true, cvssScore: 9.8 },
      { cveId: "CVE-2024-1234", hostIp: "10.0.0.2", severity: "critical", exploitAvailable: true, cvssScore: 9.8 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes.length).toBe(1); // Only one node for the CVE
  });

  it("should skip findings without CVE IDs", () => {
    const findings = [
      { cveId: null, hostIp: "10.0.0.1", severity: "low", exploitAvailable: false, cvssScore: null },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes.length).toBe(0);
    expect(result.newEdges.length).toBe(0);
  });

  it("should not create edges for unknown host IPs", () => {
    const findings = [
      { cveId: "CVE-2024-9999", hostIp: "192.168.1.1", severity: "high", exploitAvailable: true, cvssScore: 7.5 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes.length).toBe(1); // Node is still created
    expect(result.newEdges.length).toBe(0); // But no edge since host not in graph
  });

  it("should use cvssScore as risk score for vuln nodes", () => {
    const findings = [
      { cveId: "CVE-2024-5555", hostIp: "10.0.0.1", severity: "high", exploitAvailable: false, cvssScore: 7.2 },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes[0].riskScore).toBe(7.2);
  });

  it("should default risk score to 5.0 when cvssScore is null", () => {
    const findings = [
      { cveId: "CVE-2024-6666", hostIp: "10.0.0.1", severity: "medium", exploitAvailable: false, cvssScore: null },
    ];
    const result = ingestVulnDataToGraph(findings, existingNodes);
    expect(result.newNodes[0].riskScore).toBe(5.0);
  });
});
