import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock DB ─────────────────────────────────────────────────────────────────
// The training-data-dashboard router uses getDb() which returns a Drizzle-like
// chainable query builder. We mock it to return controlled data.

function createChain(resolvedValue: any = []) {
  const chain: any = {};
  const methods = [
    "select", "from", "where", "groupBy", "orderBy",
    "limit", "offset", "leftJoin", "innerJoin",
  ];
  for (const m of methods) {
    chain[m] = vi.fn().mockReturnValue(chain);
  }
  // Terminal: when awaited, resolve to the value
  chain.then = (resolve: any) => resolve(resolvedValue);
  return chain;
}

vi.mock("./db", () => ({
  getDb: vi.fn(),
}));

// ─── Tests ───────────────────────────────────────────────────────────────────


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("training-data-dashboard router structure", () => {
  it("exports a trainingDataDashboardRouter with expected procedures", async () => {
    const mod = await import("./routers/training-data-dashboard");
    expect(mod.trainingDataDashboardRouter).toBeDefined();
    // The router should be a tRPC router object with _def.procedures
    const procedures = (mod.trainingDataDashboardRouter as any)._def?.procedures;
    if (procedures) {
      const names = Object.keys(procedures);
      expect(names).toContain("getOverview");
      expect(names).toContain("listDecisions");
      expect(names).toContain("getOutcomeDistribution");
      expect(names).toContain("getConfidenceTrends");
      expect(names).toContain("listTrainingExamples");
      expect(names).toContain("getTrainingQualityDistribution");
      expect(names).toContain("getTelemetryTrends");
      expect(names).toContain("getModelPerformance");
    }
  });

  it("has exactly 8 procedures", async () => {
    const mod = await import("./routers/training-data-dashboard");
    const procedures = (mod.trainingDataDashboardRouter as any)._def?.procedures;
    if (procedures) {
      expect(Object.keys(procedures)).toHaveLength(8);
    }
  });
});

describe("agent-definitions: 10 agents seeded", () => {
  it("ALL_OFFENSIVE_AGENTS contains exactly 10 agents", async () => {
    const mod = await import("./lib/agent-definitions");
    expect(mod.ALL_OFFENSIVE_AGENTS).toBeDefined();
    expect(mod.ALL_OFFENSIVE_AGENTS).toHaveLength(10);
  });

  it("each agent has required fields", async () => {
    const mod = await import("./lib/agent-definitions");
    for (const agent of mod.ALL_OFFENSIVE_AGENTS) {
      expect(agent.agentId).toBeTruthy();
      expect(agent.name).toBeTruthy();
      expect(agent.category).toBeTruthy();
      expect(agent.persona).toBeTruthy();
      expect(agent.mission).toBeTruthy();
      expect(agent.toolAccess).toBeDefined();
      expect(Array.isArray(JSON.parse(agent.toolAccess as string))).toBe(true);
    }
  });

  it("includes the 5 new specialist agents", async () => {
    const mod = await import("./lib/agent-definitions");
    const ids = mod.ALL_OFFENSIVE_AGENTS.map((a: any) => a.agentId);
    expect(ids).toContain("offensive-scan-analyst-v1");
    expect(ids).toContain("offensive-exploit-selector-v1");
    expect(ids).toContain("offensive-evasion-optimizer-v1");
    expect(ids).toContain("offensive-lateral-planner-v1");
    expect(ids).toContain("offensive-persistence-engineer-v1");
  });

  it("includes the original 5 agents", async () => {
    const mod = await import("./lib/agent-definitions");
    const ids = mod.ALL_OFFENSIVE_AGENTS.map((a: any) => a.agentId);
    expect(ids).toContain("offensive-osint-analyst-v1");
    expect(ids).toContain("offensive-pentester-v1");
    expect(ids).toContain("offensive-social-engineer-v1");
    expect(ids).toContain("offensive-red-team-operator-v1");
    expect(ids).toContain("offensive-report-writer-v1");
  });

  it("no duplicate agent IDs", async () => {
    const mod = await import("./lib/agent-definitions");
    const ids = mod.ALL_OFFENSIVE_AGENTS.map((a: any) => a.agentId);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("matchCallerToAgent covers new agents", () => {
  it("matches scan-related callers to scan-analyst", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("discovery-scan-handler");
    expect(result?.agentId).toBe("offensive-scan-analyst-v1");
  });

  it("matches exploit-related callers to exploit-selector", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("payload-builder-handler");
    expect(result?.agentId).toBe("offensive-exploit-selector-v1");
  });

  it("matches evasion-related callers to evasion-optimizer", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("evasion-engine-handler");
    expect(result?.agentId).toBe("offensive-evasion-optimizer-v1");
  });

  it("matches lateral-related callers to lateral-planner", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("lateral-movement-planner");
    expect(result?.agentId).toBe("offensive-lateral-planner-v1");
  });

  it("matches persistence-related callers to persistence-engineer", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("persistence-handler");
    expect(result?.agentId).toBe("offensive-persistence-engineer-v1");
  });

  it("returns null for unknown callers", async () => {
    const mod = await import("./lib/agent-definitions");
    const result = mod.matchCallerToAgent("completely-unknown-caller-xyz");
    expect(result).toBeUndefined();
  });
});
