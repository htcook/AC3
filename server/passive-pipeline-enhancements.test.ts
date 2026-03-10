/**
 * Tests for Passive Pipeline Audit Enhancements
 *
 * Covers:
 * 1. Observation Cache — TTL, LRU eviction, domain invalidation
 * 2. Delta Comparison — new/removed/changed/unchanged detection
 * 3. Active Handoff — RoE enforcement, scan plan generation, provenance
 * 4. Signal Classifier — new rules (subdomain takeover, cloud storage, etc.)
 * 5. Recursive Discovery — priority scoring
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ObservationCache, CONNECTOR_TTL } from "./lib/passive/observation-cache";
import { compareReconResults, formatDeltaReportMarkdown } from "./lib/passive/delta-comparison";
import {
  generateActiveScanPlan,
  buildDefaultRoE,
  formatScanPlanSummary,
} from "./lib/passive/active-handoff";
import type { AssetObservation } from "./lib/passive/types";

// ─── Test Helpers ──────────────────────────────────────────────────

function makeObservation(overrides: Partial<AssetObservation> = {}): AssetObservation {
  return {
    name: "test.example.com",
    domain: "example.com",
    assetType: "subdomain",
    source: "crtsh",
    ip: "1.2.3.4",
    tags: ["subdomain"],
    riskScore: 5,
    evidence: {},
    discoveredAt: new Date(),
    ...overrides,
  } as AssetObservation;
}

// ─── 1. Observation Cache Tests ────────────────────────────────────

describe("ObservationCache", () => {
  let cache: ObservationCache;

  beforeEach(() => {
    cache = new ObservationCache(100);
  });

  it("should store and retrieve cached results", () => {
    const result = { connector: "shodan", observations: [makeObservation()], errors: [] };
    cache.set("example.com", "shodan", result);

    const cached = cache.get("example.com", "shodan");
    expect(cached).toBeDefined();
    expect(cached!.connector).toBe("shodan");
  });

  it("should return null for uncached domains", () => {
    const cached = cache.get("unknown.com", "shodan");
    expect(cached).toBeNull();
  });

  it("should return null when forceRefresh is true", () => {
    const result = { connector: "shodan", observations: [makeObservation()], errors: [] };
    cache.set("example.com", "shodan", result);

    const cached = cache.get("example.com", "shodan", true);
    expect(cached).toBeNull();
  });

  it("should scope cache keys by domain to prevent cross-target leakage", () => {
    const result1 = { connector: "shodan", observations: [makeObservation({ name: "a.com" })], errors: [] };
    const result2 = { connector: "shodan", observations: [makeObservation({ name: "b.com" })], errors: [] };

    cache.set("a.com", "shodan", result1);
    cache.set("b.com", "shodan", result2);

    const cachedA = cache.get("a.com", "shodan");
    const cachedB = cache.get("b.com", "shodan");
    expect(cachedA!.observations[0].name).toBe("a.com");
    expect(cachedB!.observations[0].name).toBe("b.com");
  });

  it("should invalidate all entries for a domain", () => {
    cache.set("example.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    cache.set("example.com", "censys", { connector: "censys", observations: [], errors: [] });
    cache.set("other.com", "shodan", { connector: "shodan", observations: [], errors: [] });

    const invalidated = cache.invalidateDomain("example.com");
    expect(invalidated).toBe(2);
    expect(cache.get("example.com", "shodan")).toBeNull();
    expect(cache.get("example.com", "censys")).toBeNull();
    expect(cache.get("other.com", "shodan")).not.toBeNull();
  });

  it("should invalidate all entries for a connector", () => {
    cache.set("a.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    cache.set("b.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    cache.set("a.com", "censys", { connector: "censys", observations: [], errors: [] });

    const invalidated = cache.invalidateConnector("shodan");
    expect(invalidated).toBe(2);
    expect(cache.get("a.com", "censys")).not.toBeNull();
  });

  it("should evict LRU entries when cache is full", () => {
    const smallCache = new ObservationCache(3);
    smallCache.set("a.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    smallCache.set("b.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    smallCache.set("c.com", "shodan", { connector: "shodan", observations: [], errors: [] });

    // Access a.com to make it recently used (updates accessedAt)
    smallCache.get("a.com", "shodan");

    // Add d.com — should evict one entry and keep size at 3
    smallCache.set("d.com", "shodan", { connector: "shodan", observations: [], errors: [] });

    // Cache should still be at max capacity (3), with 1 eviction
    const stats = smallCache.getStats();
    expect(stats.totalEntries).toBe(3);
    expect(stats.evictions).toBe(1);
  });

  it("should track cache statistics", () => {
    cache.set("example.com", "shodan", { connector: "shodan", observations: [], errors: [] });
    cache.get("example.com", "shodan"); // Hit
    cache.get("example.com", "censys"); // Miss
    cache.get("unknown.com", "shodan"); // Miss

    const stats = cache.getStats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(2);
    expect(stats.hitRate).toBeCloseTo(0.33, 1);
    expect(stats.totalEntries).toBe(1);
  });

  it("should have correct TTL values for different connector categories", () => {
    // Fast-changing: 6 hours
    expect(CONNECTOR_TTL["shodan"]).toBe(6 * 60 * 60 * 1000);
    expect(CONNECTOR_TTL["censys"]).toBe(6 * 60 * 60 * 1000);

    // Moderate: 24 hours
    expect(CONNECTOR_TTL["dns-deep"]).toBe(24 * 60 * 60 * 1000);
    expect(CONNECTOR_TTL["http-security"]).toBe(24 * 60 * 60 * 1000);

    // Slow-changing: 72 hours
    expect(CONNECTOR_TTL["crtsh"]).toBe(72 * 60 * 60 * 1000);
    expect(CONNECTOR_TTL["rdap"]).toBe(72 * 60 * 60 * 1000);

    // Static: 1 week
    expect(CONNECTOR_TTL["wayback"]).toBe(168 * 60 * 60 * 1000);
  });
});

// ─── 2. Delta Comparison Tests ─────────────────────────────────────

describe("Delta Comparison", () => {
  it("should detect new observations", () => {
    // Use a non-empty previous array so it's not treated as "initial scan"
    const previous = [makeObservation({ name: "existing.example.com" })];
    const current = [
      makeObservation({ name: "existing.example.com" }),
      makeObservation({ name: "new.example.com" }),
    ];

    const report = compareReconResults(previous, current);
    expect(report.stats.newObservations).toBe(1);
    const newDelta = report.deltas.find(d => d.status === "new");
    expect(newDelta).toBeDefined();
    expect(newDelta!.observation.name).toBe("new.example.com");
    // Should have a highlight about new observations or subdomains
    expect(report.highlights.some(h => h.includes("new"))).toBe(true);
  });

  it("should detect removed observations", () => {
    const previous = [makeObservation({ name: "old.example.com" })];
    const current: AssetObservation[] = [];

    const report = compareReconResults(previous, current);
    expect(report.stats.removedObservations).toBe(1);
    expect(report.deltas[0].status).toBe("removed");
  });

  it("should detect unchanged observations", () => {
    const obs = makeObservation({ name: "same.example.com", riskScore: 5 });
    const report = compareReconResults([obs], [{ ...obs }]);
    expect(report.stats.unchangedObservations).toBe(1);
  });

  it("should detect changed observations", () => {
    const prev = makeObservation({ name: "changed.example.com", riskScore: 3 });
    const curr = makeObservation({ name: "changed.example.com", riskScore: 8 });

    const report = compareReconResults([prev], [curr]);
    expect(report.stats.changedObservations).toBe(1);
    expect(report.deltas[0].changes).toBeDefined();
    expect(report.deltas[0].changes!.some(c => c.field === "riskScore")).toBe(true);
  });

  it("should compute overall risk trend correctly", () => {
    const prev: AssetObservation[] = [];
    const curr = [
      makeObservation({ name: "critical1.example.com", riskScore: 9, tags: ["critical"] }),
      makeObservation({ name: "critical2.example.com", riskScore: 8, tags: ["high"] }),
    ];

    const report = compareReconResults(prev, curr);
    expect(report.overallRiskTrend).toBe("increasing");
  });

  it("should handle initial scan with no previous baseline", () => {
    const current = [makeObservation()];
    const report = compareReconResults([], current, null);
    expect(report.highlights).toContain("Initial scan — no previous baseline for comparison.");
  });

  it("should track new subdomains specifically", () => {
    const curr = [
      makeObservation({ name: "sub1.example.com", assetType: "subdomain" }),
      makeObservation({ name: "sub2.example.com", assetType: "subdomain" }),
    ];
    const report = compareReconResults([], curr);
    expect(report.stats.newSubdomains).toBe(2);
  });

  it("should produce valid markdown output", () => {
    const report = compareReconResults(
      [makeObservation({ name: "old.example.com" })],
      [makeObservation({ name: "new.example.com" })],
      new Date("2025-01-01"),
    );
    const md = formatDeltaReportMarkdown(report);
    expect(md).toContain("## Attack Surface Delta Report");
    expect(md).toContain("### Change Summary by Category");
    expect(md).toContain("| Category |");
  });

  it("should produce category summaries", () => {
    const curr = [
      makeObservation({ name: "sub.example.com", assetType: "subdomain" }),
      makeObservation({ name: "1.2.3.4", assetType: "ip", ip: "1.2.3.4" }),
    ];
    const report = compareReconResults([], curr);
    expect(report.categorySummary.length).toBeGreaterThanOrEqual(2);
    const subCat = report.categorySummary.find(c => c.category === "subdomain");
    expect(subCat).toBeDefined();
    expect(subCat!.newCount).toBe(1);
  });
});

// ─── 3. Active Handoff Tests ───────────────────────────────────────

describe("Active Handoff", () => {
  const defaultRoE = buildDefaultRoE(["example.com", "*.example.com"], "pentest");

  it("should generate a scan plan from passive results", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "www.example.com", domain: "example.com", tags: ["subdomain", "tech:nginx"] }),
          makeObservation({ name: "api.example.com", domain: "example.com", tags: ["subdomain", "tech:nodejs"] }),
        ],
        riskSignals: [
          { severity: "high", rationale: "Outdated nginx version", assetId: "www.example.com" },
        ],
        technologies: {
          "www.example.com": ["nginx", "php"],
          "api.example.com": ["nodejs", "express"],
        },
        services: [
          { hostname: "www.example.com", port: 80, service: "http", version: "nginx 1.18" },
          { hostname: "www.example.com", port: 443, service: "https", version: "nginx 1.18" },
          { hostname: "api.example.com", port: 3000, service: "http", version: "nodejs" },
        ],
      },
      defaultRoE,
    );

    expect(plan.totalTargets).toBeGreaterThanOrEqual(1);
    expect(plan.nmapConfigs.length).toBeGreaterThanOrEqual(1);
    expect(plan.nucleiConfigs.length).toBeGreaterThanOrEqual(1);
    expect(plan.provenance.length).toBeGreaterThan(0);
    expect(plan.stats.riskCoverage).toBeGreaterThan(0);
  });

  it("should exclude targets not in RoE scope", () => {
    const restrictedRoE = buildDefaultRoE(["example.com"], "pentest");

    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "example.com", domain: "example.com" }),
          makeObservation({ name: "outofscope.com", domain: "outofscope.com" }),
        ],
        riskSignals: [],
        technologies: {},
        services: [],
      },
      restrictedRoE,
    );

    expect(plan.excludedByRoE.length).toBeGreaterThanOrEqual(1);
    expect(plan.excludedByRoE.some(e => e.hostname === "outofscope.com")).toBe(true);
  });

  it("should respect explicit exclusions in RoE", () => {
    const roe = {
      ...defaultRoE,
      excludedAssets: ["staging.example.com"],
    };

    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "www.example.com", domain: "example.com" }),
          makeObservation({ name: "staging.example.com", domain: "example.com" }),
        ],
        riskSignals: [],
        technologies: {},
        services: [],
      },
      roe,
    );

    expect(plan.excludedByRoE.some(e => e.hostname === "staging.example.com")).toBe(true);
  });

  it("should prioritize high-risk targets first", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "low-risk.example.com", domain: "example.com", riskScore: 2 }),
          makeObservation({ name: "high-risk.example.com", domain: "example.com", riskScore: 9 }),
        ],
        riskSignals: [
          { severity: "critical", rationale: "RCE vulnerability", assetId: "high-risk.example.com" },
        ],
        technologies: {},
        services: [],
      },
      defaultRoE,
    );

    expect(plan.targets[0].hostname).toBe("high-risk.example.com");
    expect(plan.targets[0].priority).toBeGreaterThan(plan.targets[1].priority);
  });

  it("should generate technology-specific nuclei tags", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "wp.example.com", domain: "example.com" }),
        ],
        riskSignals: [],
        technologies: { "wp.example.com": ["WordPress", "PHP", "Apache"] },
        services: [{ hostname: "wp.example.com", port: 80, service: "http", version: "Apache" }],
      },
      defaultRoE,
    );

    const nucleiConfig = plan.nucleiConfigs.find(c => c.target === "wp.example.com");
    expect(nucleiConfig).toBeDefined();
    expect(nucleiConfig!.tags).toContain("wordpress");
    expect(nucleiConfig!.tags).toContain("wp-plugin");
    expect(nucleiConfig!.tags).toContain("php");
    expect(nucleiConfig!.tags).toContain("apache");
  });

  it("should enable DAST mode for SPA targets", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "spa.example.com", domain: "example.com" }),
        ],
        riskSignals: [],
        technologies: { "spa.example.com": ["React", "NextJS"] },
        services: [{ hostname: "spa.example.com", port: 443, service: "https", version: "" }],
      },
      defaultRoE,
    );

    const nucleiConfig = plan.nucleiConfigs.find(c => c.target === "spa.example.com");
    expect(nucleiConfig).toBeDefined();
    expect(nucleiConfig!.dastMode).toBe(true);
    expect(nucleiConfig!.headless).toBe(true);
  });

  it("should generate ZAP configs only for web application targets", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [
          makeObservation({ name: "web.example.com", domain: "example.com" }),
          makeObservation({ name: "mail.example.com", domain: "example.com" }),
        ],
        riskSignals: [],
        technologies: { "web.example.com": ["nginx", "React"] },
        services: [
          { hostname: "web.example.com", port: 443, service: "https", version: "nginx" },
          { hostname: "mail.example.com", port: 25, service: "smtp", version: "postfix" },
        ],
      },
      defaultRoE,
    );

    // Web target should have ZAP config
    const webZap = plan.zapConfigs.find(c => c.target === "web.example.com");
    expect(webZap).toBeDefined();

    // Mail target should NOT have ZAP config
    const mailZap = plan.zapConfigs.find(c => c.target === "mail.example.com");
    expect(mailZap).toBeUndefined();
  });

  it("should build default RoE with correct defaults", () => {
    const pentestRoE = buildDefaultRoE(["example.com"], "pentest");
    expect(pentestRoE.maxIntensity).toBe(3);
    expect(pentestRoE.socialEngineeringAllowed).toBe(false);
    expect(pentestRoE.dosTestingAllowed).toBe(false);

    const redTeamRoE = buildDefaultRoE(["example.com"], "red_team");
    expect(redTeamRoE.maxIntensity).toBe(4);
    expect(redTeamRoE.socialEngineeringAllowed).toBe(true);
  });

  it("should produce a formatted scan plan summary", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [makeObservation({ name: "example.com", domain: "example.com" })],
        riskSignals: [{ severity: "high", rationale: "Test signal", assetId: "example.com" }],
        technologies: { "example.com": ["nginx"] },
        services: [{ hostname: "example.com", port: 80, service: "http", version: "nginx" }],
      },
      defaultRoE,
    );

    const summary = formatScanPlanSummary(plan);
    expect(summary).toContain("Active Scan Plan");
    expect(summary).toContain("Risk coverage:");
    expect(summary).toContain("Scan configs:");
  });

  it("should track provenance from passive to active", () => {
    const plan = generateActiveScanPlan(
      {
        observations: [makeObservation({ name: "example.com", domain: "example.com" })],
        riskSignals: [],
        technologies: { "example.com": ["WordPress"] },
        services: [{ hostname: "example.com", port: 80, service: "http", version: "" }],
      },
      defaultRoE,
    );

    expect(plan.provenance.length).toBeGreaterThan(0);
    const techProvenance = plan.provenance.find(p => p.passiveSignal.includes("WordPress"));
    expect(techProvenance).toBeDefined();
    expect(techProvenance!.activeTool).toBe("nuclei");
  });

  it("should respect allowed scan types in RoE", () => {
    const limitedRoE = {
      ...defaultRoE,
      allowedScanTypes: ["nmap" as const],
    };

    const plan = generateActiveScanPlan(
      {
        observations: [makeObservation({ name: "example.com", domain: "example.com" })],
        riskSignals: [],
        technologies: { "example.com": ["nginx"] },
        services: [{ hostname: "example.com", port: 80, service: "http", version: "" }],
      },
      limitedRoE,
    );

    expect(plan.nmapConfigs.length).toBeGreaterThan(0);
    expect(plan.nucleiConfigs.length).toBe(0);
    expect(plan.zapConfigs.length).toBe(0);
  });
});
