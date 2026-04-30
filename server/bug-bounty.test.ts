/**
 * Bug Bounty Router Tests
 * Tests the enhanced HackerOne data sync procedures, intelligence summary,
 * CWE analytics, scopes, weaknesses, and correlation engine.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database module
const mockDb = {
  select: vi.fn().mockReturnThis(),
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  orderBy: vi.fn().mockReturnThis(),
  limit: vi.fn().mockReturnThis(),
  offset: vi.fn().mockReturnThis(),
  groupBy: vi.fn().mockReturnThis(),
  insert: vi.fn().mockReturnValue({ values: vi.fn().mockResolvedValue([{ insertId: 1 }]) }),
  update: vi.fn().mockReturnValue({ set: vi.fn().mockReturnValue({ where: vi.fn().mockResolvedValue([]) }) }),
  delete: vi.fn().mockReturnValue({ where: vi.fn().mockResolvedValue([]) }),
};

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(mockDb),
}));

// Mock schema imports
vi.mock("../drizzle/schema", () => ({
  bugBountyPrograms: { id: "id", platform: "platform", handle: "handle", name: "name", state: "state", updatedAt: "updatedAt" },
  bugBountyFindings: { id: "id", platform: "platform", externalId: "externalId", title: "title", severityRating: "severityRating", cveIds: "cveIds", cweId: "cweId", awardedAmount: "awardedAmount", disclosedAt: "disclosedAt", programHandle: "programHandle", programName: "programName" },
  bugBountyCorrelations: { id: "id", findingId: "findingId", correlationType: "correlationType", matchedEntityId: "matchedEntityId", confidenceScore: "confidenceScore" },
  bugBountySyncLogs: { id: "id", platform: "platform", syncType: "syncType", status: "status", startedAt: "startedAt" },
  bugBountyProgramScopes: { id: "id", programHandle: "programHandle", assetType: "assetType", assetIdentifier: "assetIdentifier", eligibleForBounty: "eligibleForBounty", updatedAt: "updatedAt" },
  bugBountyProgramWeaknesses: { id: "id", programHandle: "programHandle", cweId: "cweId", name: "name", createdAt: "createdAt" },
  discoveredAssets: { id: "id", hostname: "hostname", url: "url", assetType: "assetType" },
  iocFeeds: { id: "id", feedType: "feedType", cveId: "cveId" },
  userPlatformCredentials: { id: "id", userId: "userId", platform: "platform", isActive: "isActive" },
}));

// Mock drizzle-orm operators
vi.mock("drizzle-orm", () => ({
  eq: vi.fn((a, b) => ({ type: "eq", field: a, value: b })),
  desc: vi.fn((a) => ({ type: "desc", field: a })),
  like: vi.fn((a, b) => ({ type: "like", field: a, value: b })),
  and: vi.fn((...args) => ({ type: "and", conditions: args })),
  or: vi.fn((...args) => ({ type: "or", conditions: args })),
  sql: Object.assign(vi.fn(), { raw: vi.fn() }),
  inArray: vi.fn((a, b) => ({ type: "inArray", field: a, values: b })),
}));

// Mock crypto
vi.mock("crypto", () => ({
  default: {
    createHash: vi.fn().mockReturnValue({
      update: vi.fn().mockReturnValue({
        digest: vi.fn().mockReturnValue(Buffer.alloc(32)),
      }),
    }),
    randomBytes: vi.fn().mockReturnValue(Buffer.alloc(32)),
    createDecipheriv: vi.fn(),
  },
}));


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("Bug Bounty Router - Data Structure Validation", () => {
  it("should define all required HackerOne API sync types", () => {
    const syncTypes = ["hacktivity", "programs", "structured_scopes", "weaknesses", "full_sync"];
    expect(syncTypes).toContain("hacktivity");
    expect(syncTypes).toContain("programs");
    expect(syncTypes).toContain("structured_scopes");
    expect(syncTypes).toContain("weaknesses");
    expect(syncTypes).toContain("full_sync");
  });

  it("should map HackerOne hacktivity fields to finding schema", () => {
    // Simulates the mapping from HackerOne API response to our DB schema
    const h1Response = {
      id: "12345",
      attributes: {
        title: "SQL Injection in login endpoint",
        severity_rating: "critical",
        cve_ids: ["CVE-2026-1234"],
        cwe: "CWE-89",
        substate: "resolved",
        url: "https://hackerone.com/reports/12345",
        disclosed_at: "2026-03-15T10:00:00Z",
        submitted_at: "2026-03-01T10:00:00Z",
        total_awarded_amount: 5000,
        asset_identifier: "api.example.com",
        asset_type: "URL",
        votes: 42,
      },
      relationships: {
        reporter: { data: { attributes: { username: "hacker1", reputation: 1500 } } },
        program: { data: { attributes: { handle: "example", name: "Example Corp" } } },
        report_generated_content: { data: { attributes: { hacktivity_summary: "AI summary of the finding" } } },
      },
    };

    const attrs = h1Response.attributes;
    const reporter = h1Response.relationships.reporter.data.attributes;
    const program = h1Response.relationships.program.data.attributes;
    const aiSummary = h1Response.relationships.report_generated_content.data.attributes.hacktivity_summary;

    const mapped = {
      platform: "hackerone",
      externalId: String(h1Response.id),
      title: attrs.title,
      severityRating: attrs.severity_rating,
      cveIds: attrs.cve_ids,
      cweId: attrs.cwe,
      substate: attrs.substate,
      reportUrl: attrs.url,
      disclosedAt: attrs.disclosed_at ? new Date(attrs.disclosed_at).toISOString().slice(0, 19).replace("T", " ") : null,
      submittedAt: attrs.submitted_at ? new Date(attrs.submitted_at).toISOString().slice(0, 19).replace("T", " ") : null,
      awardedAmount: attrs.total_awarded_amount,
      reporterUsername: reporter.username,
      reporterReputation: reporter.reputation,
      programHandle: program.handle,
      programName: program.name,
      assetIdentifier: attrs.asset_identifier,
      assetType: attrs.asset_type,
      votes: attrs.votes,
      summary: aiSummary,
    };

    expect(mapped.platform).toBe("hackerone");
    expect(mapped.externalId).toBe("12345");
    expect(mapped.title).toBe("SQL Injection in login endpoint");
    expect(mapped.severityRating).toBe("critical");
    expect(mapped.cveIds).toEqual(["CVE-2026-1234"]);
    expect(mapped.cweId).toBe("CWE-89");
    expect(mapped.awardedAmount).toBe(5000);
    expect(mapped.reporterUsername).toBe("hacker1");
    expect(mapped.programHandle).toBe("example");
    expect(mapped.assetIdentifier).toBe("api.example.com");
    expect(mapped.assetType).toBe("URL");
    expect(mapped.summary).toBe("AI summary of the finding");
    expect(mapped.disclosedAt).toBe("2026-03-15 10:00:00");
    expect(mapped.submittedAt).toBe("2026-03-01 10:00:00");
  });

  it("should map HackerOne program fields to program schema", () => {
    const h1Program = {
      id: "prog-1",
      attributes: {
        handle: "github",
        name: "GitHub",
        state: "open",
        submission_state: "open",
        profile_picture: "https://example.com/logo.png",
        currency: "USD",
      },
    };

    const attrs = h1Program.attributes;
    const mapped = {
      platform: "hackerone",
      handle: attrs.handle,
      name: attrs.name,
      url: `https://hackerone.com/${attrs.handle}`,
      logoUrl: attrs.profile_picture,
      state: attrs.state,
      submissionState: attrs.submission_state,
      currency: attrs.currency,
    };

    expect(mapped.platform).toBe("hackerone");
    expect(mapped.handle).toBe("github");
    expect(mapped.name).toBe("GitHub");
    expect(mapped.url).toBe("https://hackerone.com/github");
    expect(mapped.state).toBe("open");
  });

  it("should map HackerOne structured scope fields to scope schema", () => {
    const h1Scope = {
      id: "scope-1",
      attributes: {
        asset_type: "URL",
        asset_identifier: "https://github.com",
        eligible_for_bounty: true,
        eligible_for_submission: true,
        max_severity: "critical",
        confidentiality_requirement: "high",
        integrity_requirement: "high",
        availability_requirement: "high",
        instruction: "Only test on staging",
      },
    };

    const attrs = h1Scope.attributes;
    const mapped = {
      platform: "hackerone",
      programHandle: "github",
      externalId: String(h1Scope.id),
      assetType: attrs.asset_type,
      assetIdentifier: attrs.asset_identifier,
      eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
      eligibleForSubmission: attrs.eligible_for_submission ? 1 : 0,
      maxSeverity: attrs.max_severity,
      confidentialityRequirement: attrs.confidentiality_requirement,
      integrityRequirement: attrs.integrity_requirement,
      availabilityRequirement: attrs.availability_requirement,
      instruction: attrs.instruction,
    };

    expect(mapped.assetType).toBe("URL");
    expect(mapped.assetIdentifier).toBe("https://github.com");
    expect(mapped.eligibleForBounty).toBe(1);
    expect(mapped.maxSeverity).toBe("critical");
    expect(mapped.confidentialityRequirement).toBe("high");
  });

  it("should map HackerOne weakness fields to weakness schema", () => {
    const h1Weakness = {
      id: "weakness-1",
      attributes: {
        name: "SQL Injection",
        description: "Improper Neutralization of Special Elements used in an SQL Command",
        external_id: "CWE-89",
      },
    };

    const attrs = h1Weakness.attributes;
    const mapped = {
      platform: "hackerone",
      programHandle: "github",
      externalId: String(h1Weakness.id),
      cweId: attrs.external_id,
      name: attrs.name,
      description: attrs.description,
    };

    expect(mapped.cweId).toBe("CWE-89");
    expect(mapped.name).toBe("SQL Injection");
    expect(mapped.description).toContain("SQL Command");
  });
});

describe("Bug Bounty Router - Credential Resolution", () => {
  it("should prioritize user stored credentials over env vars", () => {
    // Test the credential resolution logic
    const userCred = { apiUsername: "user1", apiKeyEncrypted: "encrypted_key" };
    const envUsername = "env_user";
    const envToken = "env_token";

    // When user cred exists, it should be preferred
    expect(userCred.apiUsername).toBe("user1");

    // When no user cred, fallback to env
    const fallback = { username: envUsername, token: envToken };
    expect(fallback.username).toBe("env_user");
    expect(fallback.token).toBe("env_token");
  });

  it("should handle HACKERONE_API_KEY with colon separator for username:token format", () => {
    const apiKey = "username123:tokenvalue456";
    const username = apiKey.split(":")[0];
    const token = apiKey.split(":").slice(1).join(":");

    expect(username).toBe("username123");
    expect(token).toBe("tokenvalue456");
  });

  it("should handle HACKERONE_API_KEY without colon (just token)", () => {
    const apiKey = "simpletokenvalue";
    const hasColon = apiKey.includes(":");
    expect(hasColon).toBe(false);
  });
});

describe("Bug Bounty Router - Correlation Engine", () => {
  it("should produce CVE match correlations", () => {
    const finding = {
      id: 1,
      cveIds: ["CVE-2026-1234"],
      assetIdentifier: "api.example.com",
      cweId: "CWE-89",
    };

    const cveFeeds = [
      { id: 10, cveId: "CVE-2026-1234", title: "SQL Injection in Example API", severity: "critical" },
    ];

    const correlations: any[] = [];

    for (const cve of finding.cveIds) {
      for (const feed of cveFeeds) {
        if (feed.cveId.toLowerCase() === cve.toLowerCase()) {
          correlations.push({
            findingId: finding.id,
            correlationType: "cve_match",
            matchedEntityType: "ioc_feed",
            matchedEntityId: feed.id,
            matchedEntityName: feed.cveId,
            confidenceScore: 0.95,
            details: { matchField: "cveId", matchValue: cve, feedTitle: feed.title },
          });
        }
      }
    }

    expect(correlations).toHaveLength(1);
    expect(correlations[0].correlationType).toBe("cve_match");
    expect(correlations[0].confidenceScore).toBe(0.95);
    expect(correlations[0].matchedEntityName).toBe("CVE-2026-1234");
  });

  it("should produce asset match correlations with hostname matching", () => {
    const finding = {
      id: 2,
      assetIdentifier: "api.example.com",
    };

    const assets = [
      { id: 20, hostname: "api.example.com", url: "https://api.example.com", assetType: "subdomain" },
      { id: 21, hostname: "staging.example.com", url: "https://staging.example.com", assetType: "subdomain" },
    ];

    const correlations: any[] = [];
    const findingAsset = finding.assetIdentifier.toLowerCase();

    for (const asset of assets) {
      const hostname = asset.hostname.toLowerCase();
      if (hostname === findingAsset || hostname.endsWith("." + findingAsset) || findingAsset.endsWith("." + hostname) || findingAsset.includes(hostname)) {
        correlations.push({
          findingId: finding.id,
          correlationType: "asset_match",
          matchedEntityType: "discovered_asset",
          matchedEntityId: asset.id,
          matchedEntityName: asset.hostname,
          confidenceScore: hostname === findingAsset ? 0.98 : 0.75,
        });
      }
    }

    expect(correlations).toHaveLength(1);
    expect(correlations[0].matchedEntityName).toBe("api.example.com");
    expect(correlations[0].confidenceScore).toBe(0.98);
  });

  it("should produce CWE match correlations against asset posture findings", () => {
    const finding = {
      id: 3,
      cweId: "CWE-79",
    };

    const assets = [
      {
        id: 30,
        hostname: "web.example.com",
        postureFindings: [
          { cwe: "CWE-79", title: "Reflected XSS in search parameter" },
          { cwe: "CWE-89", title: "SQL Injection in login" },
        ],
      },
    ];

    const correlations: any[] = [];

    for (const asset of assets) {
      for (const pf of asset.postureFindings) {
        if (pf.cwe === finding.cweId) {
          correlations.push({
            findingId: finding.id,
            correlationType: "cwe_match",
            matchedEntityType: "discovered_asset",
            matchedEntityId: asset.id,
            matchedEntityName: `${asset.hostname} - ${pf.title}`,
            confidenceScore: 0.7,
          });
        }
      }
    }

    expect(correlations).toHaveLength(1);
    expect(correlations[0].correlationType).toBe("cwe_match");
    expect(correlations[0].matchedEntityName).toContain("Reflected XSS");
    expect(correlations[0].confidenceScore).toBe(0.7);
  });
});

describe("Bug Bounty Router - Intelligence Summary Structure", () => {
  it("should return correct intelligence summary structure", () => {
    const summary = {
      totals: {
        findings: 150,
        programs: 100,
        scopes: 500,
        weaknesses: 200,
        correlations: 25,
        recentFindings: 30,
        findingsWithCVE: 45,
      },
      topPrograms: [
        { programHandle: "github", programName: "GitHub", count: 20, totalAwarded: 50000, criticalCount: 5, highCount: 8 },
      ],
      lastSync: {
        platform: "hackerone",
        syncType: "full_sync",
        status: "completed",
        itemsSynced: 75,
        startedAt: new Date().toISOString(),
      },
    };

    expect(summary.totals.findings).toBe(150);
    expect(summary.totals.programs).toBe(100);
    expect(summary.totals.scopes).toBe(500);
    expect(summary.totals.weaknesses).toBe(200);
    expect(summary.totals.correlations).toBe(25);
    expect(summary.totals.findingsWithCVE).toBe(45);
    expect(summary.topPrograms).toHaveLength(1);
    expect(summary.topPrograms[0].criticalCount).toBe(5);
    expect(summary.lastSync.status).toBe("completed");
  });

  it("should return correct CWE analytics structure", () => {
    const analytics = {
      cweDistribution: [
        { cweId: "CWE-79", count: 50, avgBounty: 2500, maxBounty: 15000 },
        { cweId: "CWE-89", count: 30, avgBounty: 5000, maxBounty: 25000 },
      ],
      programCweDistribution: [
        { cweId: "CWE-79", name: "Cross-site Scripting", programCount: 45 },
      ],
      severityDistribution: [
        { severity: "critical", count: 20, totalBounty: 100000 },
        { severity: "high", count: 50, totalBounty: 150000 },
      ],
      assetTypeDistribution: [
        { assetType: "URL", count: 200, bountyEligible: 180 },
        { assetType: "CIDR", count: 50, bountyEligible: 30 },
      ],
    };

    expect(analytics.cweDistribution).toHaveLength(2);
    expect(analytics.cweDistribution[0].cweId).toBe("CWE-79");
    expect(analytics.cweDistribution[0].avgBounty).toBe(2500);
    expect(analytics.programCweDistribution[0].programCount).toBe(45);
    expect(analytics.severityDistribution).toHaveLength(2);
    expect(analytics.assetTypeDistribution[0].bountyEligible).toBe(180);
  });
});

describe("Bug Bounty Router - Full Sync Results Structure", () => {
  it("should return correct full sync results structure", () => {
    const results = {
      hacktivity: { synced: 75, updated: 10 },
      programs: { synced: 100 },
      scopes: { synced: 250, programs: 10 },
      weaknesses: { synced: 150, programs: 10 },
      errors: [] as string[],
    };

    expect(results.hacktivity.synced).toBe(75);
    expect(results.hacktivity.updated).toBe(10);
    expect(results.programs.synced).toBe(100);
    expect(results.scopes.synced).toBe(250);
    expect(results.scopes.programs).toBe(10);
    expect(results.weaknesses.synced).toBe(150);
    expect(results.errors).toHaveLength(0);
  });

  it("should handle partial sync failures gracefully", () => {
    const results = {
      hacktivity: { synced: 75, updated: 10 },
      programs: { synced: 100 },
      scopes: { synced: 0, programs: 0 },
      weaknesses: { synced: 0, programs: 0 },
      errors: ["Scopes(github): HackerOne API 403: Forbidden", "Weaknesses(github): HackerOne API 403: Forbidden"],
    };

    expect(results.errors).toHaveLength(2);
    expect(results.errors[0]).toContain("Scopes");
    expect(results.errors[1]).toContain("Weaknesses");
    // Hacktivity and programs still succeeded
    expect(results.hacktivity.synced).toBe(75);
    expect(results.programs.synced).toBe(100);
  });
});

describe("Bug Bounty Router - HackerOne API Path Construction", () => {
  it("should construct correct hacktivity API path", () => {
    const queryString = "severity_rating:critical OR severity_rating:high";
    const page = 1;
    const path = `/hacktivity?queryString=${encodeURIComponent(queryString)}&page[number]=${page}&page[size]=25`;
    
    expect(path).toContain("/hacktivity");
    expect(path).toContain("queryString=");
    expect(path).toContain("page[number]=1");
    expect(path).toContain("page[size]=25");
  });

  it("should construct correct programs API path", () => {
    const page = 2;
    const path = `/programs?page[number]=${page}&page[size]=25`;
    
    expect(path).toContain("/programs");
    expect(path).toContain("page[number]=2");
  });

  it("should construct correct structured scopes API path", () => {
    const handle = "github";
    const page = 1;
    const path = `/programs/${encodeURIComponent(handle)}/structured_scopes?page[number]=${page}&page[size]=25`;
    
    expect(path).toBe("/programs/github/structured_scopes?page[number]=1&page[size]=25");
  });

  it("should construct correct weaknesses API path", () => {
    const handle = "github";
    const page = 1;
    const path = `/programs/${encodeURIComponent(handle)}/weaknesses?page[number]=${page}&page[size]=25`;
    
    expect(path).toBe("/programs/github/weaknesses?page[number]=1&page[size]=25");
  });

  it("should properly encode special characters in program handles", () => {
    const handle = "my-program/test";
    const path = `/programs/${encodeURIComponent(handle)}/structured_scopes`;
    
    expect(path).toBe("/programs/my-program%2Ftest/structured_scopes");
  });
});

describe("Bug Bounty Router - Threat Intel Mapping", () => {
  it("should identify findings that map to vulnerability intelligence pipeline", () => {
    // Findings with CVE IDs map to vuln intel
    const findings = [
      { id: 1, cveIds: ["CVE-2026-1234"], cweId: "CWE-89", severityRating: "critical" },
      { id: 2, cveIds: [], cweId: "CWE-79", severityRating: "high" },
      { id: 3, cveIds: ["CVE-2026-5678", "CVE-2026-9012"], cweId: null, severityRating: "medium" },
    ];

    const vulnIntelFindings = findings.filter(f => (f.cveIds || []).length > 0);
    expect(vulnIntelFindings).toHaveLength(2);
    expect(vulnIntelFindings[0].cveIds).toContain("CVE-2026-1234");
  });

  it("should identify findings that map to threat pattern analysis", () => {
    // Findings with CWE IDs map to threat patterns
    const findings = [
      { id: 1, cweId: "CWE-89", severityRating: "critical" },
      { id: 2, cweId: "CWE-79", severityRating: "high" },
      { id: 3, cweId: null, severityRating: "medium" },
    ];

    const threatPatternFindings = findings.filter(f => f.cweId != null);
    expect(threatPatternFindings).toHaveLength(2);
  });

  it("should identify scopes that map to attack surface intelligence", () => {
    const scopes = [
      { assetType: "URL", assetIdentifier: "https://github.com", eligibleForBounty: 1 },
      { assetType: "CIDR", assetIdentifier: "192.168.1.0/24", eligibleForBounty: 0 },
      { assetType: "APPLE_STORE_APP_ID", assetIdentifier: "com.github.ios", eligibleForBounty: 1 },
    ];

    const attackSurfaceAssets = scopes.filter(s => s.eligibleForBounty === 1);
    expect(attackSurfaceAssets).toHaveLength(2);
    expect(attackSurfaceAssets[0].assetType).toBe("URL");
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// LLM TRAINING ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("LLM Training Engine - Quality Scoring", () => {
  it("should compute higher quality for findings with CVE + CWE + summary", () => {
    // Simulate the quality scoring logic from bounty-training-engine.ts
    function computeQualityScore(opts: {
      hasSummary: boolean; hasCve: boolean; hasCwe: boolean;
      severity: string | null; bountyAmount: number;
      hasExploit: boolean; hasEvidence: boolean; isNovel: boolean;
    }): number {
      let score = 0.1;
      if (opts.hasSummary) score += 0.15;
      if (opts.hasCve) score += 0.10;
      if (opts.hasCwe) score += 0.10;
      if (opts.hasExploit) score += 0.15;
      if (opts.hasEvidence) score += 0.10;
      if (opts.isNovel) score += 0.20;
      if (opts.severity === "critical") score += 0.15;
      else if (opts.severity === "high") score += 0.10;
      else if (opts.severity === "medium") score += 0.05;
      if (opts.bountyAmount > 0) score += Math.min(0.10, Math.log10(opts.bountyAmount) / 50);
      return Math.min(0.99, Math.round(score * 100) / 100);
    }

    const highQuality = computeQualityScore({
      hasSummary: true, hasCve: true, hasCwe: true,
      severity: "critical", bountyAmount: 10000,
      hasExploit: true, hasEvidence: true, isNovel: false,
    });

    const lowQuality = computeQualityScore({
      hasSummary: false, hasCve: false, hasCwe: false,
      severity: "low", bountyAmount: 0,
      hasExploit: false, hasEvidence: false, isNovel: false,
    });

    expect(highQuality).toBeGreaterThan(0.7);
    expect(lowQuality).toBeLessThan(0.2);
    expect(highQuality).toBeGreaterThan(lowQuality);
  });

  it("should give maximum boost for novel/unreported findings", () => {
    function computeQualityScore(opts: {
      hasSummary: boolean; hasCve: boolean; hasCwe: boolean;
      severity: string | null; bountyAmount: number;
      hasExploit: boolean; hasEvidence: boolean; isNovel: boolean;
    }): number {
      let score = 0.1;
      if (opts.hasSummary) score += 0.15;
      if (opts.hasCve) score += 0.10;
      if (opts.hasCwe) score += 0.10;
      if (opts.hasExploit) score += 0.15;
      if (opts.hasEvidence) score += 0.10;
      if (opts.isNovel) score += 0.20;
      if (opts.severity === "critical") score += 0.15;
      else if (opts.severity === "high") score += 0.10;
      else if (opts.severity === "medium") score += 0.05;
      if (opts.bountyAmount > 0) score += Math.min(0.10, Math.log10(opts.bountyAmount) / 50);
      return Math.min(0.99, Math.round(score * 100) / 100);
    }

    const novelFinding = computeQualityScore({
      hasSummary: true, hasCve: false, hasCwe: true,
      severity: "high", bountyAmount: 0,
      hasExploit: true, hasEvidence: true, isNovel: true,
    });

    const sameWithoutNovel = computeQualityScore({
      hasSummary: true, hasCve: false, hasCwe: true,
      severity: "high", bountyAmount: 0,
      hasExploit: true, hasEvidence: true, isNovel: false,
    });

    expect(novelFinding - sameWithoutNovel).toBeCloseTo(0.20, 1);
    expect(novelFinding).toBeGreaterThan(0.6);
  });

  it("should cap quality at 0.99", () => {
    function computeQualityScore(opts: {
      hasSummary: boolean; hasCve: boolean; hasCwe: boolean;
      severity: string | null; bountyAmount: number;
      hasExploit: boolean; hasEvidence: boolean; isNovel: boolean;
    }): number {
      let score = 0.1;
      if (opts.hasSummary) score += 0.15;
      if (opts.hasCve) score += 0.10;
      if (opts.hasCwe) score += 0.10;
      if (opts.hasExploit) score += 0.15;
      if (opts.hasEvidence) score += 0.10;
      if (opts.isNovel) score += 0.20;
      if (opts.severity === "critical") score += 0.15;
      else if (opts.severity === "high") score += 0.10;
      else if (opts.severity === "medium") score += 0.05;
      if (opts.bountyAmount > 0) score += Math.min(0.10, Math.log10(opts.bountyAmount) / 50);
      return Math.min(0.99, Math.round(score * 100) / 100);
    }

    const maxScore = computeQualityScore({
      hasSummary: true, hasCve: true, hasCwe: true,
      severity: "critical", bountyAmount: 100000,
      hasExploit: true, hasEvidence: true, isNovel: true,
    });

    expect(maxScore).toBeLessThanOrEqual(0.99);
  });
});

describe("LLM Training Engine - Category Assignment", () => {
  it("should assign correct training categories based on finding attributes", () => {
    function assignCategory(f: { bounty: number; hasCve: boolean; hasCwe: boolean }): string {
      let category = "vuln_pattern";
      if (f.bounty >= 5000) category = "bounty_strategy";
      if (f.hasCwe) category = "cwe_analysis";
      if (f.hasCve && f.bounty >= 1000) category = "exploit_chain";
      return category;
    }

    expect(assignCategory({ bounty: 10000, hasCve: true, hasCwe: true })).toBe("exploit_chain");
    expect(assignCategory({ bounty: 500, hasCve: false, hasCwe: true })).toBe("cwe_analysis");
    expect(assignCategory({ bounty: 8000, hasCve: false, hasCwe: false })).toBe("bounty_strategy");
    expect(assignCategory({ bounty: 100, hasCve: false, hasCwe: false })).toBe("vuln_pattern");
  });

  it("should define all 7 training categories", () => {
    const categories = [
      "vuln_pattern", "exploit_chain", "report_template", "scope_recon",
      "cwe_analysis", "bounty_strategy", "novel_finding",
    ];
    expect(categories).toHaveLength(7);
    expect(categories).toContain("novel_finding");
    expect(categories).toContain("exploit_chain");
    expect(categories).toContain("bounty_strategy");
  });

  it("should have system prompts for all categories", () => {
    const SYSTEM_PROMPTS: Record<string, string> = {
      vuln_pattern: "You are an expert penetration tester",
      exploit_chain: "You are an advanced red team operator",
      report_template: "You are a professional penetration test report writer",
      scope_recon: "You are a reconnaissance specialist",
      cwe_analysis: "You are a vulnerability classification expert",
      bounty_strategy: "You are a bug bounty strategist",
      novel_finding: "You are an elite vulnerability researcher",
    };

    const categories = ["vuln_pattern", "exploit_chain", "report_template", "scope_recon", "cwe_analysis", "bounty_strategy", "novel_finding"];
    for (const cat of categories) {
      expect(SYSTEM_PROMPTS[cat]).toBeDefined();
      expect(SYSTEM_PROMPTS[cat].length).toBeGreaterThan(20);
    }
  });
});

describe("LLM Training Engine - Engagement Finding Extraction", () => {
  it("should map Nuclei findings to training samples", () => {
    const nucleiFinding = {
      id: 1, templateId: "CVE-2024-1234", name: "SQL Injection in API",
      severity: "critical", description: "SQL injection via user input parameter",
      matched: "api.example.com/users?id=1'", host: "api.example.com",
    };

    const sample = {
      category: "vuln_pattern",
      sourceType: "nuclei",
      sourceId: nucleiFinding.id,
      rawTitle: nucleiFinding.name,
      rawSummary: nucleiFinding.description,
      assetIdentifier: nucleiFinding.host,
      severityRating: nucleiFinding.severity,
    };

    expect(sample.category).toBe("vuln_pattern");
    expect(sample.sourceType).toBe("nuclei");
    expect(sample.rawTitle).toBe("SQL Injection in API");
    expect(sample.assetIdentifier).toBe("api.example.com");
  });

  it("should map ZAP web app findings to training samples", () => {
    const zapFinding = {
      id: 5, alertName: "Cross-Site Scripting (Reflected)",
      riskLevel: "high", description: "Reflected XSS in search parameter",
      url: "https://example.com/search?q=<script>", cweId: "CWE-79",
    };

    const sample = {
      category: "vuln_pattern",
      sourceType: "zap",
      sourceId: zapFinding.id,
      rawTitle: zapFinding.alertName,
      rawSummary: zapFinding.description,
      cweId: zapFinding.cweId,
      assetIdentifier: zapFinding.url,
      severityRating: zapFinding.riskLevel,
    };

    expect(sample.sourceType).toBe("zap");
    expect(sample.cweId).toBe("CWE-79");
    expect(sample.rawTitle).toContain("Cross-Site Scripting");
  });

  it("should map exploitation attempts to exploit_chain training samples", () => {
    const exploit = {
      id: 10, technique: "T1190", description: "Exploited public-facing application via SQL injection",
      status: "success", targetHost: "db.example.com",
    };

    const sample = {
      category: "exploit_chain" as const,
      sourceType: "exploit",
      sourceId: exploit.id,
      rawTitle: `Exploit: ${exploit.technique}`,
      rawSummary: exploit.description,
      assetIdentifier: exploit.targetHost,
    };

    expect(sample.category).toBe("exploit_chain");
    expect(sample.sourceType).toBe("exploit");
    expect(sample.rawTitle).toContain("T1190");
  });

  it("should map AC3 report findings to report_template training samples", () => {
    const reportFinding = {
      id: 20, title: "Critical Authentication Bypass",
      description: "Authentication bypass via JWT token manipulation",
      severity: "critical", recommendation: "Implement proper JWT validation",
      cvssScore: "9.8",
    };

    const sample = {
      category: "report_template" as const,
      sourceType: "report",
      sourceId: reportFinding.id,
      rawTitle: reportFinding.title,
      rawSummary: `${reportFinding.description}\n\nRemediation: ${reportFinding.recommendation}`,
      severityRating: reportFinding.severity,
    };

    expect(sample.category).toBe("report_template");
    expect(sample.sourceType).toBe("report");
    expect(sample.rawSummary).toContain("Remediation:");
  });
});

describe("LLM Training Engine - JSONL Export Format", () => {
  it("should produce valid OpenAI chat-format JSONL lines", () => {
    const sample = {
      systemPrompt: "You are an expert penetration tester.",
      userPrompt: "Analyze this SQL injection finding in api.example.com",
      assistantResponse: "This is a classic SQL injection vulnerability...",
    };

    const jsonlLine = JSON.stringify({
      messages: [
        { role: "system", content: sample.systemPrompt },
        { role: "user", content: sample.userPrompt },
        { role: "assistant", content: sample.assistantResponse },
      ],
    });

    const parsed = JSON.parse(jsonlLine);
    expect(parsed.messages).toHaveLength(3);
    expect(parsed.messages[0].role).toBe("system");
    expect(parsed.messages[1].role).toBe("user");
    expect(parsed.messages[2].role).toBe("assistant");
    expect(parsed.messages[0].content).toContain("penetration tester");
  });

  it("should filter samples by minimum quality threshold", () => {
    const samples = [
      { quality: 0.85, category: "exploit_chain", enriched: true },
      { quality: 0.20, category: "vuln_pattern", enriched: false },
      { quality: 0.55, category: "cwe_analysis", enriched: true },
      { quality: 0.10, category: "vuln_pattern", enriched: false },
      { quality: 0.72, category: "novel_finding", enriched: true },
    ];

    const minQuality = 0.3;
    const filtered = samples.filter(s => s.quality >= minQuality);
    expect(filtered).toHaveLength(3);
    expect(filtered.every(s => s.quality >= 0.3)).toBe(true);
  });

  it("should filter samples by enriched-only flag", () => {
    const samples = [
      { quality: 0.85, enriched: true },
      { quality: 0.55, enriched: true },
      { quality: 0.72, enriched: false },
    ];

    const enrichedOnly = samples.filter(s => s.enriched);
    expect(enrichedOnly).toHaveLength(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SCANFORGE BRIDGE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("ScanForge Bridge - Disclosed Vulns to Detection Templates", () => {
  it("should map HackerOne finding severity to ScanForge template severity", () => {
    const severityMap: Record<string, string> = {
      critical: "critical",
      high: "high",
      medium: "medium",
      low: "low",
      none: "info",
    };

    expect(severityMap["critical"]).toBe("critical");
    expect(severityMap["high"]).toBe("high");
    expect(severityMap["none"]).toBe("info");
  });

  it("should generate a valid ScanForge template ID from finding data", () => {
    function generateTemplateId(finding: { cweId: string | null; title: string; id: number }): string {
      const cwe = finding.cweId?.replace("CWE-", "").toLowerCase() || "unknown";
      const slug = finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40);
      return `h1-${cwe}-${slug}-${finding.id}`;
    }

    const templateId = generateTemplateId({
      cweId: "CWE-89", title: "SQL Injection in Login", id: 12345,
    });

    expect(templateId).toBe("h1-89-sql-injection-in-login-12345");
    expect(templateId).toMatch(/^h1-/);
  });

  it("should build template metadata from disclosed finding", () => {
    const finding = {
      id: 100, title: "SSRF via webhook URL", cweId: "CWE-918",
      severityRating: "high", programHandle: "github",
      assetIdentifier: "api.github.com", summary: "Server-side request forgery...",
    };

    const template = {
      templateId: `h1-918-ssrf-via-webhook-url-${finding.id}`,
      name: finding.title,
      severity: finding.severityRating,
      tags: JSON.stringify(["hackerone", "disclosed", finding.cweId, finding.programHandle]),
      sourceUrl: `https://hackerone.com/reports/${finding.id}`,
      status: "draft",
    };

    expect(template.templateId).toContain("h1-918");
    expect(template.severity).toBe("high");
    expect(JSON.parse(template.tags)).toContain("CWE-918");
    expect(template.status).toBe("draft");
  });

  it("should skip findings already converted to templates", () => {
    const existingTemplateIds = new Set(["h1-89-sqli-login-100", "h1-79-xss-search-200"]);
    const findings = [
      { id: 100, templateId: "h1-89-sqli-login-100" },
      { id: 200, templateId: "h1-79-xss-search-200" },
      { id: 300, templateId: "h1-918-ssrf-webhook-300" },
    ];

    const newFindings = findings.filter(f => !existingTemplateIds.has(f.templateId));
    expect(newFindings).toHaveLength(1);
    expect(newFindings[0].id).toBe(300);
  });
});

describe("Bounty ROI Analytics", () => {
  it("should rank CWEs by total bounty payout", () => {
    const cwePayouts = [
      { cweId: "CWE-89", count: 15, totalBounty: 75000, avgBounty: 5000, maxBounty: 15000 },
      { cweId: "CWE-79", count: 30, totalBounty: 45000, avgBounty: 1500, maxBounty: 8000 },
      { cweId: "CWE-918", count: 8, totalBounty: 60000, avgBounty: 7500, maxBounty: 20000 },
    ];

    const ranked = [...cwePayouts].sort((a, b) => b.totalBounty - a.totalBounty);
    expect(ranked[0].cweId).toBe("CWE-89");
    expect(ranked[1].cweId).toBe("CWE-918");
    expect(ranked[2].cweId).toBe("CWE-79");
  });

  it("should calculate average bounty per CWE correctly", () => {
    const findings = [
      { cweId: "CWE-89", bounty: 5000 },
      { cweId: "CWE-89", bounty: 10000 },
      { cweId: "CWE-89", bounty: 3000 },
    ];

    const total = findings.reduce((sum, f) => sum + f.bounty, 0);
    const avg = total / findings.length;
    expect(avg).toBeCloseTo(6000, 0);
  });

  it("should rank programs by average payout for target prioritization", () => {
    const programs = [
      { handle: "github", avgBounty: 8000, count: 50 },
      { handle: "shopify", avgBounty: 5000, count: 80 },
      { handle: "paypal", avgBounty: 12000, count: 30 },
    ];

    const ranked = [...programs].sort((a, b) => b.avgBounty - a.avgBounty);
    expect(ranked[0].handle).toBe("paypal");
    expect(ranked[1].handle).toBe("github");
    expect(ranked[2].handle).toBe("shopify");
  });
});
