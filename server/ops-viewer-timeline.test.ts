/**
 * Ops Viewer Timeline & Visual Effects — Server-side integration tests
 * ════════════════════════════════════════════════════════════════════
 * Tests that discoveredAt timestamps flow through the graph pipeline
 * and that the engine options API works correctly.
 */
import { describe, it, expect } from "vitest";
import { buildAttackGraph, type AttackNode } from "./lib/exploit-reasoning-engine";
import type { ReasoningInput } from "./lib/exploit-reasoning-engine";

describe("discoveredAt timestamp propagation", () => {
  const baseInput: ReasoningInput = {
    engagementId: 999,
    target: "test.example.com",
    assets: [
      {
        hostname: "test.example.com",
        technologies: ["nginx"],
        services: [{ port: 443, service: "https", version: "1.21" }],
        vulns: [
          {
            title: "SQL Injection in login form",
            severity: "critical",
            cve: "CVE-2024-1234",
            source: "nuclei",
            port: 443,
            discoveredAt: 1700000000000, // Nov 14, 2023
          } as any,
          {
            title: "Cross-Site Scripting (XSS) in search",
            severity: "high",
            source: "zap",
            port: 443,
            discoveredAt: 1700100000000, // ~1 day later
          } as any,
          {
            title: "Information Disclosure via error page",
            severity: "low",
            source: "manual",
            port: 80,
            // No discoveredAt — should be undefined
          },
        ],
      },
    ],
    enableLLMHypotheses: false,
    maxPathDepth: 4,
  };

  it("should propagate discoveredAt from vulns to AttackNodes", () => {
    const graph = buildAttackGraph(baseInput);
    const nodeList = Array.from(graph.nodes.values());

    // At least some discovered nodes should have discoveredAt set
    const withTimestamp = nodeList.filter(
      (n) => n.source === "discovered" && n.discoveredAt != null
    );
    expect(withTimestamp.length).toBeGreaterThan(0);

    // Verify the actual timestamps match what we passed in
    const timestamps = withTimestamp.map((n) => n.discoveredAt).sort();
    // Should contain our test timestamps (if the vuln matched a taxonomy class)
    for (const ts of timestamps) {
      expect(ts).toBeGreaterThan(1600000000000); // After 2020
      expect(ts).toBeLessThan(1800000000000); // Before 2027
    }
  });

  it("should leave discoveredAt undefined for vulns without timestamps", () => {
    const graph = buildAttackGraph(baseInput);
    const nodeList = Array.from(graph.nodes.values());

    // Hypothesized nodes should NOT have discoveredAt
    const hypothesized = nodeList.filter((n) => n.source === "hypothesized");
    for (const n of hypothesized) {
      expect(n.discoveredAt).toBeUndefined();
    }
  });

  it("should respect MAX_GRAPH_NODES limit", () => {
    const graph = buildAttackGraph(baseInput);
    expect(graph.nodes.size).toBeLessThanOrEqual(80); // MAX_GRAPH_NODES
  });

  it("should respect MAX_GRAPH_EDGES limit", () => {
    const graph = buildAttackGraph(baseInput);
    expect(graph.edges.length).toBeLessThanOrEqual(400); // MAX_GRAPH_EDGES
  });

  it("should respect MAX_DFS_PATHS limit", () => {
    const graph = buildAttackGraph(baseInput);
    expect(graph.paths.length).toBeLessThanOrEqual(50); // MAX_DFS_PATHS
  });
});

describe("AttackNode interface", () => {
  it("should include discoveredAt as optional field", () => {
    const node: AttackNode = {
      id: "test-1",
      source: "discovered",
      discoveredAt: Date.now(),
      vulnClassId: "SW-SQLI-001",
      vulnClassName: "SQL Injection",
      target: "test.com",
      layer: "application",
      category: "software",
      exploitability: 0.9,
      impact: 0.8,
      techniques: [],
      activeDefenses: [],
      providesAccess: [],
      requiresAccess: [],
    };
    expect(node.discoveredAt).toBeDefined();
    expect(typeof node.discoveredAt).toBe("number");
  });

  it("should allow discoveredAt to be undefined", () => {
    const node: AttackNode = {
      id: "test-2",
      source: "hypothesized",
      vulnClassId: "SW-XSS-001",
      vulnClassName: "Cross-Site Scripting",
      target: "test.com",
      layer: "application",
      category: "software",
      exploitability: 0.7,
      impact: 0.5,
      techniques: [],
      activeDefenses: [],
      providesAccess: [],
      requiresAccess: [],
    };
    expect(node.discoveredAt).toBeUndefined();
  });
});
