import { describe, it, expect } from "vitest";
import {
  computeDiscoveryCoverage,
  getRedTeamPriorityWeight,
  computeRedTeamAlignmentScore,
  RED_TEAM_PRIORITIES,
} from "./lib/redteam-discovery-coverage";

// ─── computeDiscoveryCoverage ─────────────────────────────────────

describe("computeDiscoveryCoverage", () => {
  it("returns 0% coverage when no connectors or observations are provided", () => {
    const report = computeDiscoveryCoverage([], []);
    expect(report.coverageScore).toBe(0);
    expect(report.prioritiesCovered).toBe(0);
    expect(report.totalPriorities).toBe(10);
    expect(report.coverageBand).toBe("limited");
    expect(report.structuralGaps.length).toBeGreaterThan(0);
  });

  it("marks a priority as covered when connector produces enough tagged observations", () => {
    const connectorResults = [
      {
        connector: "crtsh",
        observations: [
          { tags: ["subdomain", "certificate"], assetType: "subdomain" },
          { tags: ["subdomain"], assetType: "subdomain" },
          { tags: ["certificate", "domain"], assetType: "certificate" },
        ],
      },
    ];
    const allObservations = connectorResults[0].observations;

    const report = computeDiscoveryCoverage(connectorResults, allObservations);
    const dnsPriority = report.priorities.find(p => p.id === 1);
    expect(dnsPriority).toBeDefined();
    expect(dnsPriority!.covered).toBe(true);
    expect(dnsPriority!.observationCount).toBeGreaterThanOrEqual(3);
    expect(dnsPriority!.contributingConnectors).toContain("crtsh");
  });

  it("marks a priority as NOT covered when observations are below minObservations", () => {
    const connectorResults = [
      {
        connector: "crtsh",
        observations: [
          { tags: ["subdomain"], assetType: "subdomain" },
        ],
      },
    ];
    const allObservations = connectorResults[0].observations;

    const report = computeDiscoveryCoverage(connectorResults, allObservations);
    const dnsPriority = report.priorities.find(p => p.id === 1);
    // DNS Footprint requires minObservations: 3, we only provided 1
    expect(dnsPriority!.covered).toBe(false);
  });

  it("identifies structural gaps for priorities with no connectors", () => {
    const report = computeDiscoveryCoverage([], []);
    // Priority 6 (Key Personnel OSINT) and 10 (Code Repos) have no connectors
    expect(report.structuralGaps).toContain("Key Personnel OSINT");
    expect(report.structuralGaps).toContain("Code Repositories & Configuration Leaks");
  });

  it("identifies actionable gaps for priorities with connectors but no data", () => {
    // Provide some data for DNS but nothing for Shodan/Censys (ports)
    const connectorResults = [
      {
        connector: "crtsh",
        observations: [
          { tags: ["subdomain"], assetType: "subdomain" },
          { tags: ["subdomain"], assetType: "subdomain" },
          { tags: ["certificate", "domain"], assetType: "certificate" },
        ],
      },
    ];
    const allObservations = connectorResults[0].observations;

    const report = computeDiscoveryCoverage(connectorResults, allObservations);
    // Port Enumeration has connectors (shodan, censys, etc.) but no data
    expect(report.actionableGaps).toContain("Live Hosts, Open Ports & Services");
  });

  it("computes weighted coverage score correctly for partial coverage", () => {
    // Cover DNS (weight 1.0), IPs (weight 0.95), Ports (weight 0.90)
    const connectorResults = [
      {
        connector: "crtsh",
        observations: Array.from({ length: 6 }, (_, i) => ({
          tags: ["subdomain", "certificate"],
          assetType: "subdomain",
        })),
      },
      {
        connector: "shodan",
        observations: Array.from({ length: 5 }, (_, i) => ({
          tags: ["ip", "port", "service", "banner"],
          assetType: "ip",
        })),
      },
      {
        connector: "censys",
        observations: Array.from({ length: 3 }, (_, i) => ({
          tags: ["ip", "netblock", "hosting"],
          assetType: "ip",
        })),
      },
    ];
    const allObservations = connectorResults.flatMap(cr => cr.observations);

    const report = computeDiscoveryCoverage(connectorResults, allObservations);
    expect(report.coverageScore).toBeGreaterThan(0);
    expect(report.prioritiesCovered).toBeGreaterThanOrEqual(2);
    // With only 3 of 10 priorities covered, score may still be in "limited" band
    // but it should be non-zero
    expect(report.coverageScore).toBeGreaterThan(0);
  });

  it("assigns correct coverage band based on score", () => {
    // Provide comprehensive data across many connectors
    const connectorResults = [
      { connector: "crtsh", observations: Array.from({ length: 10 }, () => ({ tags: ["subdomain", "certificate", "dns"], assetType: "subdomain" })) },
      { connector: "securitytrails", observations: Array.from({ length: 5 }, () => ({ tags: ["subdomain", "dns"], assetType: "subdomain" })) },
      { connector: "dns-deep", observations: Array.from({ length: 8 }, () => ({ tags: ["dns", "ns_record", "soa_record", "cname"], assetType: "dns" })) },
      { connector: "shodan", observations: Array.from({ length: 10 }, () => ({ tags: ["ip", "port", "service", "banner"], assetType: "ip" })) },
      { connector: "censys", observations: Array.from({ length: 5 }, () => ({ tags: ["ip", "netblock", "hosting"], assetType: "ip" })) },
      { connector: "urlscan", observations: Array.from({ length: 5 }, () => ({ tags: ["technology", "web_app", "framework"], assetType: "web_app" })) },
      { connector: "http-security", observations: Array.from({ length: 4 }, () => ({ tags: ["waf", "security_header", "csp", "hsts"], assetType: "security" })) },
      { connector: "email-security", observations: Array.from({ length: 3 }, () => ({ tags: ["dmarc", "spf", "dkim", "email_security"], assetType: "email" })) },
      { connector: "dehashed", observations: Array.from({ length: 5 }, () => ({ tags: ["breach", "credential", "email", "breach_summary"], assetType: "breach" })) },
      { connector: "cloud-assets", observations: Array.from({ length: 3 }, () => ({ tags: ["cloud", "s3_bucket", "cloud_asset"], assetType: "cloud" })) },
    ];
    const allObservations = connectorResults.flatMap(cr => cr.observations);

    const report = computeDiscoveryCoverage(connectorResults, allObservations);
    // With 8+ priorities covered, should be "good" or "comprehensive"
    expect(report.prioritiesCovered).toBeGreaterThanOrEqual(7);
    expect(["good", "comprehensive"]).toContain(report.coverageBand);
  });

  it("generates a human-readable assessment", () => {
    const report = computeDiscoveryCoverage([], []);
    expect(report.assessment).toContain("Discovery coverage:");
    expect(report.assessment).toContain("limited");
    expect(report.assessment.length).toBeGreaterThan(50);
  });

  it("always returns exactly 10 priorities", () => {
    const report = computeDiscoveryCoverage([], []);
    expect(report.priorities).toHaveLength(10);
    expect(report.totalPriorities).toBe(10);
  });
});

// ─── getRedTeamPriorityWeight ─────────────────────────────────────

describe("getRedTeamPriorityWeight", () => {
  it("returns highest weight (1.0) for DNS-related tags", () => {
    const weight = getRedTeamPriorityWeight(["subdomain", "certificate"]);
    expect(weight).toBe(1.0);
  });

  it("returns default weight (0.65) for unrecognized tags", () => {
    const weight = getRedTeamPriorityWeight(["unknown_tag", "random"]);
    expect(weight).toBe(0.65);
  });

  it("returns the maximum weight when multiple priorities match", () => {
    // "ip" matches priority 2 (0.95), "port" matches priority 3 (0.90)
    const weight = getRedTeamPriorityWeight(["ip", "port"]);
    expect(weight).toBe(0.95);
  });

  it("matches by category string when tags don't match", () => {
    const weight = getRedTeamPriorityWeight([], "subdomain enumeration");
    expect(weight).toBeGreaterThan(0.65);
  });
});

// ─── computeRedTeamAlignmentScore ─────────────────────────────────

describe("computeRedTeamAlignmentScore", () => {
  it("returns 0 for empty findings", () => {
    expect(computeRedTeamAlignmentScore([])).toBe(0);
  });

  it("returns higher score for findings aligned with high-priority areas", () => {
    const highPriorityFindings = [
      { tags: ["subdomain", "dns"], severity: 8 },
      { tags: ["ip", "netblock"], severity: 7 },
    ];
    const lowPriorityFindings = [
      { tags: ["unknown_tag"], severity: 8 },
      { tags: ["random"], severity: 7 },
    ];

    const highScore = computeRedTeamAlignmentScore(highPriorityFindings);
    const lowScore = computeRedTeamAlignmentScore(lowPriorityFindings);
    expect(highScore).toBeGreaterThan(lowScore);
  });

  it("normalizes score to 0-100 range", () => {
    const findings = [
      { tags: ["subdomain"], severity: 10 },
      { tags: ["ip"], severity: 5 },
      { tags: ["port"], severity: 3 },
    ];
    const score = computeRedTeamAlignmentScore(findings);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("weights by severity when computing alignment", () => {
    // High-severity finding on high-priority area should dominate
    const findings = [
      { tags: ["subdomain"], severity: 10 }, // DNS = weight 1.0
      { tags: ["unknown"], severity: 1 },    // default = weight 0.65
    ];
    const score = computeRedTeamAlignmentScore(findings);
    // Should be close to 100 since the high-severity finding dominates
    expect(score).toBeGreaterThan(85);
  });
});

// ─── RED_TEAM_PRIORITIES constants ────────────────────────────────

describe("RED_TEAM_PRIORITIES", () => {
  it("has exactly 10 priorities", () => {
    expect(RED_TEAM_PRIORITIES).toHaveLength(10);
  });

  it("has unique IDs from 1 to 10", () => {
    const ids = RED_TEAM_PRIORITIES.map(p => p.id);
    expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("has weights that are generally higher for earlier priorities", () => {
    // First priority should have the highest weight
    expect(RED_TEAM_PRIORITIES[0].weight).toBe(1.0);
    // Last priority should have a lower weight than the first
    expect(RED_TEAM_PRIORITIES[9].weight).toBeLessThan(RED_TEAM_PRIORITIES[0].weight);
    // All weights should be between 0.5 and 1.0
    for (const p of RED_TEAM_PRIORITIES) {
      expect(p.weight).toBeGreaterThanOrEqual(0.5);
      expect(p.weight).toBeLessThanOrEqual(1.0);
    }
  });

  it("all priorities have at least one coverage tag", () => {
    for (const p of RED_TEAM_PRIORITIES) {
      expect(p.coverageTags.length).toBeGreaterThan(0);
    }
  });

  it("all priorities have attack techniques", () => {
    for (const p of RED_TEAM_PRIORITIES) {
      expect(p.attackTechniques.length).toBeGreaterThan(0);
    }
  });
});
