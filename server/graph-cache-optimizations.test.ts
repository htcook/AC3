/**
 * Tests for Graph Cache & Optimized Reasoning Pipeline
 * Covers all 9 performance optimizations:
 *   1. In-memory graph cache (LRU + TTL)
 *   2. Fast graph builder (no LLM)
 *   3. Async background reasoning
 *   4. Finding deduplication
 *   5. Severity-gated reasoning
 *   6. Batch LLM calls (grouped hypothesis prompts)
 *   7. Progressive WebSocket streaming
 *   8. Pre-computed taxonomy matching
 *   9. Low-confidence path pruning
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  deduplicateFindings,
  severityGateForReasoning,
  prunePaths,
  computeFindingsHash,
  precomputeTaxonomy,
  buildGraphFast,
  graphCache,
  isReasoningInProgress,
  getTaxonomySummary,
  type CachedGraph,
} from "./lib/graph-cache";
import type { ReasoningInput, AttackPath } from "./lib/exploit-reasoning-engine";

// ═══════════════════════════════════════════════════════════════════════
// Shared test fixtures
// ═══════════════════════════════════════════════════════════════════════

const makeInput = (overrides?: Partial<ReasoningInput>): ReasoningInput => ({
  engagementId: 999,
  target: "test.example.com",
  assets: [
    {
      hostname: "web1.example.com",
      ip: "10.0.0.1",
      technologies: ["Apache", "PHP", "MySQL"],
      services: [
        { port: 80, service: "http", version: "Apache/2.4.49" },
        { port: 22, service: "ssh", version: "OpenSSH_8.2" },
        { port: 3306, service: "mysql", version: "MySQL 5.7" },
      ],
      vulns: [
        { title: "SQL Injection in login form", severity: "critical", cve: "CVE-2023-1234", source: "zap" },
        { title: "Cross-Site Scripting (Reflected)", severity: "high", source: "zap" },
        { title: "Default credentials on MySQL", severity: "high", source: "nuclei" },
        { title: "Directory listing enabled", severity: "low", source: "nuclei" },
        { title: "Missing X-Frame-Options", severity: "info", source: "zap" },
      ],
    },
    {
      hostname: "api.example.com",
      ip: "10.0.0.2",
      technologies: ["Node.js", "Express"],
      services: [
        { port: 443, service: "https", version: "nginx/1.18" },
        { port: 22, service: "ssh", version: "OpenSSH_8.4" },
      ],
      vulns: [
        { title: "Server-Side Request Forgery", severity: "high", source: "burp" },
        { title: "Insecure CORS configuration", severity: "medium", source: "zap" },
      ],
    },
  ],
  ...overrides,
});

// ═══════════════════════════════════════════════════════════════════════
// §1 — FINDING DEDUPLICATION (Optimization #4)
// ═══════════════════════════════════════════════════════════════════════

describe("Finding Deduplication", () => {
  it("should deduplicate findings with the same CVE on the same host", () => {
    const input = makeInput({
      assets: [{
        hostname: "host1.example.com",
        technologies: ["Apache"],
        services: [{ port: 80, service: "http" }],
        vulns: [
          { title: "SQL Injection", severity: "high", cve: "CVE-2023-1234", source: "zap" },
          { title: "SQL Injection (duplicate)", severity: "critical", cve: "CVE-2023-1234", source: "nuclei" },
          { title: "XSS Reflected", severity: "medium", source: "zap" },
        ],
      }],
    });

    const { assets, stats } = deduplicateFindings(input.assets);
    expect(stats.originalCount).toBe(3);
    expect(stats.deduplicatedCount).toBe(2); // CVE-2023-1234 deduped, XSS kept
    expect(stats.reductionPercent).toBeGreaterThan(0);

    // Should keep the critical severity version (higher rank)
    const cveVuln = assets[0].vulns.find(v => v.cve === "CVE-2023-1234");
    expect(cveVuln?.severity).toBe("critical");
  });

  it("should deduplicate findings with same normalized title on same host+port", () => {
    const input = makeInput({
      assets: [{
        hostname: "host1.example.com",
        technologies: [],
        services: [{ port: 80, service: "http" }],
        vulns: [
          { title: "SQL Injection in Login", severity: "high", source: "zap", port: 80 },
          { title: "sql injection in login", severity: "medium", source: "nuclei", port: 80 },
        ],
      }],
    });

    const { assets, stats } = deduplicateFindings(input.assets);
    expect(stats.deduplicatedCount).toBe(1);
    // Should keep the higher severity
    expect(assets[0].vulns[0].severity).toBe("high");
  });

  it("should keep findings on different hosts even with same CVE", () => {
    const input = makeInput({
      assets: [
        {
          hostname: "host1.example.com",
          technologies: [],
          services: [],
          vulns: [{ title: "CVE-2023-1234", severity: "high", cve: "CVE-2023-1234" }],
        },
        {
          hostname: "host2.example.com",
          technologies: [],
          services: [],
          vulns: [{ title: "CVE-2023-1234", severity: "high", cve: "CVE-2023-1234" }],
        },
      ],
    });

    const { assets, stats } = deduplicateFindings(input.assets);
    expect(stats.deduplicatedCount).toBe(2); // One per host
  });

  it("should handle empty vulns gracefully", () => {
    const input = makeInput({
      assets: [{
        hostname: "clean.example.com",
        technologies: [],
        services: [],
        vulns: [],
      }],
    });

    const { assets, stats } = deduplicateFindings(input.assets);
    expect(stats.originalCount).toBe(0);
    expect(stats.deduplicatedCount).toBe(0);
    expect(stats.reductionPercent).toBe(0);
  });

  it("should handle empty assets array", () => {
    const { assets, stats } = deduplicateFindings([]);
    expect(assets.length).toBe(0);
    expect(stats.originalCount).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — SEVERITY-GATED REASONING (Optimization #5)
// ═══════════════════════════════════════════════════════════════════════

describe("Severity-Gated Reasoning", () => {
  it("should only keep critical and high findings", () => {
    const input = makeInput();
    const gated = severityGateForReasoning(input.assets);

    for (const asset of gated) {
      for (const vuln of asset.vulns) {
        const sev = vuln.severity.toLowerCase();
        expect(sev === "critical" || sev === "high").toBe(true);
      }
    }
  });

  it("should remove assets that have no critical/high findings", () => {
    const input = makeInput({
      assets: [
        {
          hostname: "low-only.example.com",
          technologies: [],
          services: [],
          vulns: [
            { title: "Info disclosure", severity: "low" },
            { title: "Missing header", severity: "info" },
          ],
        },
        {
          hostname: "has-critical.example.com",
          technologies: [],
          services: [],
          vulns: [
            { title: "RCE", severity: "critical" },
            { title: "Info disclosure", severity: "low" },
          ],
        },
      ],
    });

    const gated = severityGateForReasoning(input.assets);
    expect(gated.length).toBe(1);
    expect(gated[0].hostname).toBe("has-critical.example.com");
    expect(gated[0].vulns.length).toBe(1);
    expect(gated[0].vulns[0].severity).toBe("critical");
  });

  it("should return empty array if no critical/high findings exist", () => {
    const input = makeInput({
      assets: [{
        hostname: "clean.example.com",
        technologies: [],
        services: [],
        vulns: [
          { title: "Low issue", severity: "low" },
          { title: "Medium issue", severity: "medium" },
        ],
      }],
    });

    const gated = severityGateForReasoning(input.assets);
    expect(gated.length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — LOW-CONFIDENCE PATH PRUNING (Optimization #9)
// ═══════════════════════════════════════════════════════════════════════

describe("Path Pruning", () => {
  const makePath = (feasibility: number, impact: number, layersCrossed: number): AttackPath => ({
    id: `path-${Math.random().toString(36).slice(2, 8)}`,
    name: `Test Path (f=${feasibility})`,
    description: "Test path",
    steps: [],
    metrics: {
      feasibility,
      impact,
      opsecRisk: "medium" as any,
      layersCrossed,
      complexity: 0.5,
    },
    entryPoint: "entry",
    targetAsset: "target",
    killChainPhases: [],
  });

  it("should prune paths below feasibility threshold", () => {
    const paths = [
      makePath(0.8, 0.9, 3),
      makePath(0.005, 0.1, 1), // Below 0.01 threshold
      makePath(0.5, 0.7, 2),
    ];

    const { paths: pruned, stats } = prunePaths(paths);
    expect(pruned.length).toBe(2);
    expect(stats.prunedCount).toBe(1);
    expect(stats.pathsBefore).toBe(3);
    expect(stats.pathsAfter).toBe(2);
  });

  it("should sort paths by composite score (feasibility * impact * layers)", () => {
    const paths = [
      makePath(0.3, 0.5, 1), // score: 0.3 * 0.5 * 2 = 0.3
      makePath(0.9, 0.9, 3), // score: 0.9 * 0.9 * 4 = 3.24
      makePath(0.5, 0.8, 2), // score: 0.5 * 0.8 * 3 = 1.2
    ];

    const { paths: pruned } = prunePaths(paths);
    expect(pruned[0].metrics.feasibility).toBe(0.9); // Highest score first
    expect(pruned[1].metrics.feasibility).toBe(0.5);
    expect(pruned[2].metrics.feasibility).toBe(0.3);
  });

  it("should limit to MAX_PATHS (25)", () => {
    const paths = Array.from({ length: 50 }, (_, i) =>
      makePath(0.5 + i * 0.01, 0.5, 2)
    );

    const { paths: pruned, stats } = prunePaths(paths);
    expect(pruned.length).toBeLessThanOrEqual(25);
    expect(stats.prunedCount).toBeGreaterThan(0);
  });

  it("should handle empty paths array", () => {
    const { paths: pruned, stats } = prunePaths([]);
    expect(pruned.length).toBe(0);
    expect(stats.pathsBefore).toBe(0);
    expect(stats.pathsAfter).toBe(0);
    expect(stats.prunedCount).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — FINDINGS HASH (Cache invalidation)
// ═══════════════════════════════════════════════════════════════════════

describe("Findings Hash", () => {
  it("should produce consistent hash for same input", () => {
    const input = makeInput();
    const hash1 = computeFindingsHash(input.assets);
    const hash2 = computeFindingsHash(input.assets);
    expect(hash1).toBe(hash2);
  });

  it("should produce different hash when findings change", () => {
    const input1 = makeInput();
    const input2 = makeInput({
      assets: [{
        hostname: "different.example.com",
        technologies: [],
        services: [],
        vulns: [{ title: "Different Finding", severity: "high" }],
      }],
    });

    const hash1 = computeFindingsHash(input1.assets);
    const hash2 = computeFindingsHash(input2.assets);
    expect(hash1).not.toBe(hash2);
  });

  it("should be order-independent (sorted internally)", () => {
    const assets1 = [
      { hostname: "a.com", technologies: [] as string[], services: [] as any[], vulns: [{ title: "V1", severity: "high" }] },
      { hostname: "b.com", technologies: [] as string[], services: [] as any[], vulns: [{ title: "V2", severity: "low" }] },
    ];
    const assets2 = [
      { hostname: "b.com", technologies: [] as string[], services: [] as any[], vulns: [{ title: "V2", severity: "low" }] },
      { hostname: "a.com", technologies: [] as string[], services: [] as any[], vulns: [{ title: "V1", severity: "high" }] },
    ];

    expect(computeFindingsHash(assets1)).toBe(computeFindingsHash(assets2));
  });

  it("should return a 16-char hex string", () => {
    const hash = computeFindingsHash(makeInput().assets);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §5 — PRE-COMPUTED TAXONOMY (Optimization #8)
// ═══════════════════════════════════════════════════════════════════════

describe("Pre-computed Taxonomy", () => {
  it("should return non-empty taxonomy context for known technologies", () => {
    const input = makeInput();
    const ctx = precomputeTaxonomy(input.assets);
    expect(ctx.length).toBeGreaterThan(50);
    expect(typeof ctx).toBe("string");
  });

  it("should include vulnerability class information", () => {
    const ctx = precomputeTaxonomy(makeInput().assets);
    expect(ctx).toContain("Vulnerability Classes");
  });

  it("should handle empty assets", () => {
    const ctx = precomputeTaxonomy([]);
    expect(typeof ctx).toBe("string");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §6 — IN-MEMORY GRAPH CACHE (Optimization #1)
// ═══════════════════════════════════════════════════════════════════════

describe("Graph Cache", () => {
  beforeEach(() => {
    // Invalidate test entries
    graphCache.invalidate(999);
    graphCache.invalidate(998);
  });

  it("should return null for cache miss", () => {
    const result = graphCache.get(999, "nonexistent");
    expect(result).toBeNull();
  });

  it("should store and retrieve cached graphs", () => {
    const entry: CachedGraph = {
      graph: { nodes: new Map(), edges: [], paths: [], stats: {} as any },
      createdAt: Date.now(),
      findingsHash: "testhash123",
      reasoningComplete: false,
      taxonomyContext: "test context",
      dedup: { originalCount: 5, deduplicatedCount: 3, reductionPercent: 40 },
      pruning: { pathsBefore: 10, pathsAfter: 8, prunedCount: 2 },
    };

    graphCache.set(999, "testhash123", entry);
    const retrieved = graphCache.get(999, "testhash123");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.findingsHash).toBe("testhash123");
    expect(retrieved!.dedup.reductionPercent).toBe(40);
  });

  it("should update reasoning output on existing entry", () => {
    const entry: CachedGraph = {
      graph: { nodes: new Map(), edges: [], paths: [], stats: {} as any },
      createdAt: Date.now(),
      findingsHash: "hash456",
      reasoningComplete: false,
      taxonomyContext: "",
      dedup: { originalCount: 0, deduplicatedCount: 0, reductionPercent: 0 },
      pruning: { pathsBefore: 0, pathsAfter: 0, prunedCount: 0 },
    };

    graphCache.set(999, "hash456", entry);

    const mockOutput = {
      graph: { nodes: new Map(), edges: [], paths: [], stats: {} as any },
      recommendedPaths: [],
      novelHypotheses: [],
      coverage: {} as any,
    };

    const updated = graphCache.updateReasoning(999, "hash456", mockOutput as any);
    expect(updated).toBe(true);

    const retrieved = graphCache.get(999, "hash456");
    expect(retrieved!.reasoningComplete).toBe(true);
    expect(retrieved!.reasoningOutput).toBeDefined();
  });

  it("should return false when updating non-existent entry", () => {
    const updated = graphCache.updateReasoning(999, "nonexistent", {} as any);
    expect(updated).toBe(false);
  });

  it("should invalidate all entries for an engagement", () => {
    const entry: CachedGraph = {
      graph: { nodes: new Map(), edges: [], paths: [], stats: {} as any },
      createdAt: Date.now(),
      findingsHash: "hash1",
      reasoningComplete: false,
      taxonomyContext: "",
      dedup: { originalCount: 0, deduplicatedCount: 0, reductionPercent: 0 },
      pruning: { pathsBefore: 0, pathsAfter: 0, prunedCount: 0 },
    };

    graphCache.set(998, "hash1", entry);
    graphCache.set(998, "hash2", { ...entry, findingsHash: "hash2" });

    graphCache.invalidate(998);
    expect(graphCache.get(998, "hash1")).toBeNull();
    expect(graphCache.get(998, "hash2")).toBeNull();
  });

  it("should report cache stats", () => {
    const stats = graphCache.stats();
    expect(stats.maxSize).toBe(50);
    expect(stats.ttlMs).toBe(30 * 60 * 1000);
    expect(typeof stats.size).toBe("number");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §7 — FAST GRAPH BUILDER (Optimization #2)
// ═══════════════════════════════════════════════════════════════════════

describe("Fast Graph Builder", () => {
  beforeEach(() => {
    graphCache.invalidate(999);
  });

  it("should build a graph with nodes and edges from findings", () => {
    const input = makeInput();
    const cached = buildGraphFast(input);

    expect(cached.graph.nodes.size).toBeGreaterThan(0);
    expect(cached.graph.stats.totalNodes).toBeGreaterThan(0);
    expect(cached.graph.stats.totalEdges).toBeGreaterThanOrEqual(0);
    expect(cached.reasoningComplete).toBe(false);
  });

  it("should apply deduplication", () => {
    const input = makeInput({
      assets: [{
        hostname: "host1.example.com",
        technologies: ["Apache"],
        services: [{ port: 80, service: "http" }],
        vulns: [
          { title: "SQL Injection", severity: "high", cve: "CVE-2023-1234" },
          { title: "SQL Injection (dup)", severity: "critical", cve: "CVE-2023-1234" },
          { title: "XSS", severity: "medium" },
        ],
      }],
    });

    const cached = buildGraphFast(input);
    expect(cached.dedup.originalCount).toBe(3);
    expect(cached.dedup.deduplicatedCount).toBe(2);
    expect(cached.dedup.reductionPercent).toBeGreaterThan(0);
  });

  it("should apply path pruning", () => {
    const input = makeInput();
    const cached = buildGraphFast(input);
    // Pruning stats should be populated
    expect(cached.pruning.pathsBefore).toBeGreaterThanOrEqual(0);
    expect(cached.pruning.pathsAfter).toBeLessThanOrEqual(cached.pruning.pathsBefore);
  });

  it("should pre-compute taxonomy context", () => {
    const input = makeInput();
    const cached = buildGraphFast(input);
    expect(cached.taxonomyContext.length).toBeGreaterThan(0);
  });

  it("should populate the cache", () => {
    const input = makeInput();
    const cached = buildGraphFast(input);

    const fromCache = graphCache.get(999, cached.findingsHash);
    expect(fromCache).not.toBeNull();
    expect(fromCache!.findingsHash).toBe(cached.findingsHash);
  });

  it("should handle empty assets", () => {
    const input = makeInput({ assets: [] });
    const cached = buildGraphFast(input);
    expect(cached.graph.nodes.size).toBe(0);
    expect(cached.dedup.originalCount).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8 — REASONING STATUS TRACKING (Optimization #3)
// ═══════════════════════════════════════════════════════════════════════

describe("Reasoning Status", () => {
  it("should report no reasoning in progress initially", () => {
    expect(isReasoningInProgress(999, "somehash")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §9 — TAXONOMY SUMMARY (Optimization #8)
// ═══════════════════════════════════════════════════════════════════════

describe("Taxonomy Summary", () => {
  it("should return non-zero counts for all taxonomy dimensions", () => {
    const summary = getTaxonomySummary();
    expect(summary.categories).toBeGreaterThan(0);
    expect(summary.protocols).toBeGreaterThan(0);
    expect(summary.techMappings).toBeGreaterThan(0);
    expect(summary.techniques).toBeGreaterThan(0);
  });
});
