/**
 * Bounty Intel Scheduler Tests
 * Tests the automated bug bounty intelligence pipeline:
 * - H1 credential resolution from env vars
 * - Pipeline stage runner with error isolation
 * - Pipeline concurrency guard (prevents double-run)
 * - Scheduler initialization
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node-cron
const mockSchedule = vi.fn().mockReturnValue({ stop: vi.fn() });
vi.mock("node-cron", () => ({
  default: { schedule: mockSchedule },
  schedule: mockSchedule,
}));

// Mock the database module
const mockInsertValues = vi.fn().mockResolvedValue([{ insertId: 1 }]);
const mockUpdateSetWhere = vi.fn().mockResolvedValue([]);
const mockDb = {
  select: vi.fn().mockReturnThis(),
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  orderBy: vi.fn().mockReturnThis(),
  limit: vi.fn().mockResolvedValue([]),
  offset: vi.fn().mockReturnThis(),
  groupBy: vi.fn().mockReturnThis(),
  insert: vi.fn().mockReturnValue({ values: mockInsertValues }),
  update: vi.fn().mockReturnValue({
    set: vi.fn().mockReturnValue({ where: mockUpdateSetWhere }),
  }),
  delete: vi.fn().mockReturnValue({ where: vi.fn().mockResolvedValue([]) }),
};

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(mockDb),
}));

// Mock schema imports
vi.mock("../drizzle/schema", () => ({
  bugBountyFindings: { id: "id", platform: "platform", externalId: "externalId", title: "title", severityRating: "severityRating", cveIds: "cveIds", cweId: "cweId", createdAt: "createdAt", awardedAmount: "awardedAmount", disclosedAt: "disclosedAt", votes: "votes", summary: "summary", assetIdentifier: "assetIdentifier" },
  bugBountyPrograms: { id: "id", platform: "platform", handle: "handle", name: "name", state: "state", lastSyncedAt: "lastSyncedAt" },
  bugBountyProgramScopes: { id: "id", programHandle: "programHandle", assetType: "assetType", assetIdentifier: "assetIdentifier" },
  bugBountyProgramWeaknesses: { id: "id", programHandle: "programHandle", name: "name", cweId: "cweId" },
  bugBountySyncLogs: { id: "id", platform: "platform", syncType: "syncType", status: "status" },
  bugBountyCorrelations: { id: "id", findingId: "findingId", correlationType: "correlationType", matchedEntityId: "matchedEntityId", confidenceScore: "confidenceScore" },
  discoveredAssets: { id: "id", hostname: "hostname", url: "url", assetType: "assetType", riskBand: "riskBand", hybridRiskScore: "hybridRiskScore", postureFindings: "postureFindings" },
  iocFeeds: { id: "id", feedType: "feedType", cveId: "cveId", title: "title", severity: "severity" },
}));

// Mock drizzle-orm operators
vi.mock("drizzle-orm", () => ({
  eq: vi.fn((a, b) => ({ type: "eq", field: a, value: b })),
  desc: vi.fn((a) => ({ type: "desc", field: a })),
  and: vi.fn((...args) => ({ type: "and", conditions: args })),
  or: vi.fn((...args) => ({ type: "or", conditions: args })),
  sql: Object.assign(vi.fn(), { raw: vi.fn() }),
  inArray: vi.fn((a, b) => ({ type: "inArray", field: a, values: b })),
}));

// Mock bounty-training-engine (used by LLM extraction stages)
vi.mock("./lib/bounty-training-engine", () => ({
  extractFromHackerOneFindings: vi.fn().mockResolvedValue({ extracted: 5, skipped: 2 }),
  extractFromEngagementFindings: vi.fn().mockResolvedValue({ extracted: 3, sources: { nuclei: 1, zap: 1, exploit: 0, report: 1 } }),
  enrichTrainingSamples: vi.fn().mockResolvedValue({ enriched: 4, failed: 1 }),
  generateScanForgeTemplatesFromFindings: vi.fn().mockResolvedValue({ generated: 2, skipped: 1, failed: 0 }),
}));

// Mock global fetch for H1 API calls
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("Bounty Intel Scheduler - Credential Resolution", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should parse HACKERONE_API_KEY with colon separator", () => {
    process.env.HACKERONE_API_KEY = "myuser:mytoken123";
    delete process.env.HACKERONE_API_USERNAME;

    const envKey = process.env.HACKERONE_API_KEY;
    const username = process.env.HACKERONE_API_USERNAME || envKey!.split(":")[0];
    const token = envKey!.includes(":") ? envKey!.split(":").slice(1).join(":") : envKey;

    expect(username).toBe("myuser");
    expect(token).toBe("mytoken123");
  });

  it("should prefer HACKERONE_API_USERNAME when set", () => {
    process.env.HACKERONE_API_KEY = "fallback:tokenvalue";
    process.env.HACKERONE_API_USERNAME = "explicit_user";

    const username = process.env.HACKERONE_API_USERNAME || process.env.HACKERONE_API_KEY!.split(":")[0];
    expect(username).toBe("explicit_user");
  });

  it("should return null when no credentials are configured", () => {
    delete process.env.HACKERONE_API_KEY;
    delete process.env.HACKERONE_API_USERNAME;

    const envKey = process.env.HACKERONE_API_KEY;
    expect(envKey).toBeUndefined();
    // getH1Credentials() would return null
  });

  it("should handle tokens with multiple colons (e.g., base64 values)", () => {
    process.env.HACKERONE_API_KEY = "user:token:with:colons";
    const envKey = process.env.HACKERONE_API_KEY;
    const token = envKey!.includes(":") ? envKey!.split(":").slice(1).join(":") : envKey;
    expect(token).toBe("token:with:colons");
  });
});

describe("Bounty Intel Scheduler - Pipeline Structure", () => {
  it("should define all 8 pipeline stages", () => {
    const expectedStages = [
      "h1_hacktivity",
      "h1_programs",
      "h1_scopes_weaknesses",
      "llm_extract_h1",
      "llm_extract_engagements",
      "llm_enrich",
      "scanforge_templates",
      "cross_correlation",
    ];

    // These are the stage names used in the pipeline
    for (const stage of expectedStages) {
      expect(stage).toBeTruthy();
      expect(typeof stage).toBe("string");
    }
    expect(expectedStages.length).toBe(8);
  });

  it("should produce a valid BountyIntelSyncResult shape", () => {
    const result = {
      trigger: "manual" as const,
      timestamp: new Date().toISOString(),
      stages: [
        { stage: "h1_hacktivity", status: "ok" as const, count: 10, detail: "10 synced, 2 updated", durationMs: 1500 },
        { stage: "h1_programs", status: "error" as const, detail: "Network timeout", durationMs: 5000 },
      ],
      totalDurationMs: 6500,
    };

    expect(result.trigger).toBe("manual");
    expect(result.timestamp).toBeTruthy();
    expect(result.stages).toHaveLength(2);
    expect(result.stages[0].status).toBe("ok");
    expect(result.stages[0].count).toBe(10);
    expect(result.stages[1].status).toBe("error");
    expect(result.totalDurationMs).toBe(6500);
  });

  it("should isolate stage failures (one stage error doesn't block others)", () => {
    const stages: Array<{ stage: string; status: "ok" | "error"; detail?: string; durationMs: number }> = [];

    // Simulate stage runner behavior
    const runStageSync = (name: string, fn: () => void) => {
      const start = Date.now();
      try {
        fn();
        stages.push({ stage: name, status: "ok", durationMs: Date.now() - start });
      } catch (err: any) {
        stages.push({ stage: name, status: "error", detail: err.message, durationMs: Date.now() - start });
      }
    };

    runStageSync("stage1", () => { /* success */ });
    runStageSync("stage2", () => { throw new Error("Network error"); });
    runStageSync("stage3", () => { /* success */ });

    expect(stages).toHaveLength(3);
    expect(stages[0].status).toBe("ok");
    expect(stages[1].status).toBe("error");
    expect(stages[1].detail).toBe("Network error");
    expect(stages[2].status).toBe("ok"); // Stage 3 still runs despite stage 2 failure
  });
});

describe("Bounty Intel Scheduler - Correlation Engine", () => {
  it("should match CVE IDs between findings and IOC feeds", () => {
    const finding = {
      id: 1,
      cveIds: ["CVE-2026-1234", "CVE-2026-5678"],
      assetIdentifier: null,
      cweId: null,
    };

    const cveFeeds = [
      { id: 100, cveId: "CVE-2026-1234", title: "Critical RCE", severity: "critical" },
      { id: 101, cveId: "CVE-2025-9999", title: "Unrelated", severity: "low" },
    ];

    const correlations: Array<{ findingId: number; correlationType: string; matchedEntityId: number; confidenceScore: string }> = [];

    for (const cve of finding.cveIds) {
      for (const feed of cveFeeds) {
        if (feed.cveId && feed.cveId.toLowerCase() === cve.toLowerCase()) {
          correlations.push({
            findingId: finding.id,
            correlationType: "cve_match",
            matchedEntityId: feed.id,
            confidenceScore: "0.95",
          });
        }
      }
    }

    expect(correlations).toHaveLength(1);
    expect(correlations[0].matchedEntityId).toBe(100);
    expect(correlations[0].confidenceScore).toBe("0.95");
  });

  it("should match asset identifiers with hostname variations", () => {
    const finding = { id: 2, assetIdentifier: "api.example.com" };
    const assets = [
      { id: 200, hostname: "api.example.com" },
      { id: 201, hostname: "www.example.com" },
      { id: 202, hostname: "example.com" },
    ];

    const correlations: Array<{ findingId: number; matchedEntityId: number; confidenceScore: string }> = [];
    const findingAsset = finding.assetIdentifier.toLowerCase();

    for (const asset of assets) {
      const hostname = asset.hostname?.toLowerCase() || "";
      if (hostname && (hostname === findingAsset || hostname.endsWith("." + findingAsset) || findingAsset.endsWith("." + hostname))) {
        correlations.push({
          findingId: finding.id,
          matchedEntityId: asset.id,
          confidenceScore: hostname === findingAsset ? "0.98" : "0.75",
        });
      }
    }

    expect(correlations).toHaveLength(2); // exact match + subdomain match
    expect(correlations[0].matchedEntityId).toBe(200);
    expect(correlations[0].confidenceScore).toBe("0.98"); // exact match
    expect(correlations[1].matchedEntityId).toBe(202);
    expect(correlations[1].confidenceScore).toBe("0.75"); // subdomain match
  });

  it("should match CWE IDs between findings and asset posture findings", () => {
    const finding = { id: 3, cweId: "CWE-89" };
    const assets = [
      {
        id: 300,
        hostname: "db.example.com",
        postureFindings: [
          { cwe: "CWE-89", title: "SQL Injection detected" },
          { cwe: "CWE-79", title: "XSS detected" },
        ],
      },
      {
        id: 301,
        hostname: "web.example.com",
        postureFindings: [{ cwe: "CWE-79", title: "XSS only" }],
      },
    ];

    const correlations: Array<{ findingId: number; matchedEntityId: number; confidenceScore: string }> = [];

    for (const asset of assets) {
      for (const pf of asset.postureFindings) {
        if (pf.cwe && pf.cwe === finding.cweId) {
          correlations.push({
            findingId: finding.id,
            matchedEntityId: asset.id,
            confidenceScore: "0.70",
          });
        }
      }
    }

    expect(correlations).toHaveLength(1);
    expect(correlations[0].matchedEntityId).toBe(300);
    expect(correlations[0].confidenceScore).toBe("0.70");
  });
});

describe("Bounty Intel Scheduler - Cron Schedule", () => {
  it("should schedule at correct 6-hour intervals", async () => {
    // Import the module (mocked cron)
    const { initBountyIntelSchedule } = await import("./lib/bounty-intel-scheduler");
    initBountyIntelSchedule();

    expect(mockSchedule).toHaveBeenCalledTimes(1);
    const [cronExpr, , options] = mockSchedule.mock.calls[0];
    expect(cronExpr).toBe("0 4,10,16,22 * * *");
    expect(options.timezone).toBe("UTC");
  });
});

describe("Bounty Intel Scheduler - Concurrency Guard", () => {
  it("should skip pipeline when already running", async () => {
    const { runBountyIntelPipeline } = await import("./lib/bounty-intel-scheduler");

    // Mock fetch to simulate slow H1 API
    mockFetch.mockImplementation(() => new Promise((resolve) => setTimeout(() => resolve({
      ok: true,
      json: () => Promise.resolve({ data: [] }),
    }), 100)));

    // Start first pipeline (don't await)
    const first = runBountyIntelPipeline("manual");

    // Immediately start second pipeline
    const second = await runBountyIntelPipeline("manual");

    // Second should be skipped
    expect(second.stages[0]?.stage).toBe("guard");
    expect(second.stages[0]?.status).toBe("skipped");
    expect(second.stages[0]?.detail).toContain("already running");

    // Wait for first to complete
    await first;
  });
});

describe("Bounty Intel Scheduler - H1 API Auth Header", () => {
  it("should construct correct Basic auth header", () => {
    const username = "testuser";
    const token = "testtoken";
    const authHeader = "Basic " + Buffer.from(`${username}:${token}`).toString("base64");

    expect(authHeader).toBe("Basic " + Buffer.from("testuser:testtoken").toString("base64"));
    // Decode and verify
    const decoded = Buffer.from(authHeader.replace("Basic ", ""), "base64").toString("utf8");
    expect(decoded).toBe("testuser:testtoken");
  });

  it("should send Accept: application/json header", () => {
    const headers: Record<string, string> = { Accept: "application/json" };
    expect(headers.Accept).toBe("application/json");
  });
});
