import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock drizzle-orm ───────────────────────────────────────────────────────

vi.mock("drizzle-orm", () => {
  const sqlFn = (...args: any[]) => {
    const obj: any = { _sql: true, args };
    obj.as = () => obj;
    return obj;
  };
  return {
    eq: vi.fn((...args: any[]) => ({ _eq: true, args })),
    and: vi.fn((...args: any[]) => ({ _and: true, args })),
    desc: vi.fn((col: any) => ({ _desc: true, col })),
    sql: sqlFn,
    gte: vi.fn((...args: any[]) => ({ _gte: true, args })),
  };
});

// ─── Mock schema ────────────────────────────────────────────────────────────

vi.mock("../drizzle/schema", () => ({
  nexusShadowConfigs: {
    id: "nsc_id", enabled: "nsc_enabled", configName: "nsc_config_name",
    activeShadowTests: "nsc_active_shadow_tests", totalRuns: "nsc_total_runs",
    createdAt: "nsc_created_at",
  },
  nexusShadowTests: {
    id: "nst_id", configId: "nst_config_id", caller: "nst_caller",
    judgeVerdict: "nst_judge_verdict", status: "nst_status",
    createdAt: "nst_created_at", primaryScore: "nst_primary_score",
    experimentalScore: "nst_experimental_score", judgeScore: "nst_judge_score",
    primaryLatencyMs: "nst_primary_latency_ms",
    experimentalLatencyMs: "nst_experimental_latency_ms",
    primaryTokensIn: "nst_primary_tokens_in",
    primaryTokensOut: "nst_primary_tokens_out",
    experimentalTokensIn: "nst_experimental_tokens_in",
    experimentalTokensOut: "nst_experimental_tokens_out",
  },
}));

// ─── Chainable DB mock ──────────────────────────────────────────────────────
// Key insight: the top-level db object must NOT have a `then` property,
// otherwise `await getDb()` will treat it as a thenable and resolve to [].
// Only terminal chain positions (where we actually await results) should be thenable.

function createDbMock(terminalValue: any = []): any {
  // Use a Proxy so chains are lazy (no infinite recursion)
  // The top-level db must NOT be thenable (no `then` property)
  // Sub-chains ARE thenable so `await db.select().from().where()` resolves
  function makeChain(isRoot: boolean): any {
    return new Proxy({}, {
      get(_target, prop: string) {
        if (prop === 'then') {
          if (isRoot) return undefined; // top-level db is NOT thenable
          return (resolve: any) => resolve(terminalValue);
        }
        // Any method call returns a new sub-chain (thenable)
        return (..._args: any[]) => makeChain(false);
      },
    });
  }
  return makeChain(true);
}

let mockGetDb = vi.fn();
const mockInvokeLLM = vi.fn();

vi.mock("./db", () => ({
  getDb: (...args: any[]) => mockGetDb(...args),
  getDbRequired: (...args: any[]) => mockGetDb(...args),
}));

vi.mock("./_core/llm", () => ({
  invokeLLM: (...args: any[]) => mockInvokeLLM(...args),
}));

// ─── Import after mocks ────────────────────────────────────────────────────

import { shouldShadowTest, executeShadowTest, getShadowTestAnalytics, type ShadowConfig } from "./lib/shadow-testing";

// ─── Test Data ──────────────────────────────────────────────────────────────

const baseShadowConfig: ShadowConfig = {
  id: 1,
  configName: "Test Config",
  enabled: true,
  shadowPercentage: 100,
  primaryModel: "gemini-2.5-flash",
  experimentalModel: "gpt-4o",
  callerFilter: "",
  priorityFilter: "all",
  maxConcurrent: 10,
  activeShadowTests: 0,
  totalRuns: 0,
};

// ─── shouldShadowTest Tests ─────────────────────────────────────────────────

describe("shouldShadowTest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return null when db is unavailable", async () => {
    mockGetDb.mockResolvedValue(null);
    const result = await shouldShadowTest("test-caller");
    expect(result).toBeNull();
  });

  it("should return null when no configs are enabled", async () => {
    mockGetDb.mockResolvedValue(createDbMock([]));
    const result = await shouldShadowTest("test-caller");
    expect(result).toBeNull();
  });

  it("should return a config when conditions match (100% rate)", async () => {
    const configs = [{
      id: 1, nscConfigName: "Test Config", nscEnabled: 1, nscShadowPercentage: 100,
      nscPrimaryModel: "gemini-2.5-flash", nscExperimentalModel: "gpt-4o",
      nscCallerFilter: "", nscPriorityFilter: "all", nscMaxConcurrent: 10,
      nscActiveShadowTests: 0, nscTotalRuns: 0,
    }];
    mockGetDb.mockResolvedValue(createDbMock(configs));

    const result = await shouldShadowTest("specialist:osint-analyst:scan");
    expect(result).not.toBeNull();
    expect(result?.configName).toBe("Test Config");
    expect(result?.primaryModel).toBe("gemini-2.5-flash");
    expect(result?.experimentalModel).toBe("gpt-4o");
  });

  it("should filter by caller prefix - matching", async () => {
    const configs = [{
      id: 1, nscConfigName: "OSINT Only", nscEnabled: 1, nscShadowPercentage: 100,
      nscPrimaryModel: "gemini-2.5-flash", nscExperimentalModel: "gpt-4o",
      nscCallerFilter: "specialist:osint", nscPriorityFilter: "all", nscMaxConcurrent: 10,
      nscActiveShadowTests: 0, nscTotalRuns: 0,
    }];
    mockGetDb.mockResolvedValue(createDbMock(configs));

    const result = await shouldShadowTest("specialist:osint-analyst:scan");
    expect(result).not.toBeNull();
  });

  it("should filter by caller prefix - non-matching", async () => {
    const configs = [{
      id: 1, nscConfigName: "OSINT Only", nscEnabled: 1, nscShadowPercentage: 100,
      nscPrimaryModel: "gemini-2.5-flash", nscExperimentalModel: "gpt-4o",
      nscCallerFilter: "specialist:osint", nscPriorityFilter: "all", nscMaxConcurrent: 10,
      nscActiveShadowTests: 0, nscTotalRuns: 0,
    }];
    mockGetDb.mockResolvedValue(createDbMock(configs));

    const result = await shouldShadowTest("specialist:pentester:exploit");
    expect(result).toBeNull();
  });

  it("should filter by priority - matching", async () => {
    const configs = [{
      id: 1, nscConfigName: "Essential Only", nscEnabled: 1, nscShadowPercentage: 100,
      nscPrimaryModel: "gemini-2.5-flash", nscExperimentalModel: "gpt-4o",
      nscCallerFilter: "", nscPriorityFilter: "essential", nscMaxConcurrent: 10,
      nscActiveShadowTests: 0, nscTotalRuns: 0,
    }];
    mockGetDb.mockResolvedValue(createDbMock(configs));

    const result = await shouldShadowTest("test-caller", "essential");
    expect(result).not.toBeNull();
  });

  it("should filter by priority - non-matching", async () => {
    const configs = [{
      id: 1, nscConfigName: "Essential Only", nscEnabled: 1, nscShadowPercentage: 100,
      nscPrimaryModel: "gemini-2.5-flash", nscExperimentalModel: "gpt-4o",
      nscCallerFilter: "", nscPriorityFilter: "essential", nscMaxConcurrent: 10,
      nscActiveShadowTests: 0, nscTotalRuns: 0,
    }];
    mockGetDb.mockResolvedValue(createDbMock(configs));

    const result = await shouldShadowTest("test-caller", "bulk");
    expect(result).toBeNull();
  });

  it("should handle database errors gracefully", async () => {
    mockGetDb.mockRejectedValue(new Error("DB connection failed"));
    const result = await shouldShadowTest("test-caller");
    expect(result).toBeNull();
  });
});

// ─── executeShadowTest Tests ────────────────────────────────────────────────

describe("executeShadowTest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetDb.mockResolvedValue(createDbMock([{ insertId: 42 }]));
    mockInvokeLLM.mockResolvedValue({
      choices: [{ message: { content: JSON.stringify({
        primaryScore: 75, experimentalScore: 80,
        verdict: "experimental_better", reasoning: "Better specificity",
        confidenceScore: 85,
      }) } }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
  });

  it("should execute without throwing", async () => {
    const primaryResult = {
      choices: [{ message: { content: "Primary response" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    };

    await expect(
      executeShadowTest(
        baseShadowConfig,
        { messages: [{ role: "user" as const, content: "Test prompt" }], _caller: "test-caller" },
        primaryResult as any,
      )
    ).resolves.not.toThrow();
  });

  it("should call invokeLLM for the experimental model and judge", async () => {
    const primaryResult = {
      choices: [{ message: { content: "Primary response" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    };

    await executeShadowTest(
      baseShadowConfig,
      { messages: [{ role: "user" as const, content: "Test prompt" }], _caller: "test-caller" },
      primaryResult as any,
    );

    // Should have called invokeLLM at least once (experimental + judge)
    expect(mockInvokeLLM).toHaveBeenCalled();
  });

  it("should handle LLM errors gracefully", async () => {
    mockInvokeLLM.mockRejectedValue(new Error("Model unavailable"));

    const primaryResult = {
      choices: [{ message: { content: "Primary response" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    };

    await expect(
      executeShadowTest(
        baseShadowConfig,
        { messages: [{ role: "user" as const, content: "Test prompt" }], _caller: "test-caller" },
        primaryResult as any,
      )
    ).resolves.not.toThrow();
  });

  it("should handle null db gracefully", async () => {
    mockGetDb.mockResolvedValue(null);

    const primaryResult = {
      choices: [{ message: { content: "Primary response" } }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    };

    await expect(
      executeShadowTest(
        baseShadowConfig,
        { messages: [{ role: "user" as const, content: "Test prompt" }], _caller: "test-caller" },
        primaryResult as any,
      )
    ).resolves.not.toThrow();
  });
});

// ─── getShadowTestAnalytics Tests ───────────────────────────────────────────

describe("getShadowTestAnalytics", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return null when db is unavailable", async () => {
    mockGetDb.mockResolvedValue(null);
    const result = await getShadowTestAnalytics(30);
    expect(result).toBeNull();
  });

  it("should return analytics structure with empty data", async () => {
    mockGetDb.mockResolvedValue(createDbMock([]));
    const result = await getShadowTestAnalytics(30);
    expect(result).toBeDefined();
    expect(result).toHaveProperty("verdicts");
    expect(result).toHaveProperty("daily");
    expect(result).toHaveProperty("topCallers");
    expect(result).toHaveProperty("recentTests");
    expect(result).toHaveProperty("windowDays", 30);
  });

  it("should accept custom window days", async () => {
    mockGetDb.mockResolvedValue(createDbMock([]));
    const result = await getShadowTestAnalytics(7);
    expect(result).toBeDefined();
    expect(result?.windowDays).toBe(7);
  });
});

// ─── ShadowConfig Type Tests ────────────────────────────────────────────────

describe("ShadowConfig type validation", () => {
  it("should have all required fields", () => {
    const config: ShadowConfig = baseShadowConfig;
    expect(config.id).toBe(1);
    expect(config.configName).toBe("Test Config");
    expect(config.enabled).toBe(true);
    expect(config.shadowPercentage).toBe(100);
    expect(config.primaryModel).toBe("gemini-2.5-flash");
    expect(config.experimentalModel).toBe("gpt-4o");
    expect(config.maxConcurrent).toBe(10);
    expect(config.activeShadowTests).toBe(0);
    expect(config.totalRuns).toBe(0);
  });

  it("should enforce percentage range conceptually", () => {
    expect(baseShadowConfig.shadowPercentage).toBeGreaterThanOrEqual(1);
    expect(baseShadowConfig.shadowPercentage).toBeLessThanOrEqual(100);
  });

  it("should have non-negative counters", () => {
    expect(baseShadowConfig.activeShadowTests).toBeGreaterThanOrEqual(0);
    expect(baseShadowConfig.totalRuns).toBeGreaterThanOrEqual(0);
  });
});
