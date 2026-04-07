/**
 * Tests for the adjustment effectiveness tracker module.
 * Uses the exact same pattern as bounty-intel-scheduler.test.ts:
 * - vi.fn() const declarations at top level
 * - vi.mock() with factory referencing those consts
 * - Dynamic import() inside tests
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock DB (vi.fn() consts at top level, before vi.mock) ───────────────

const mockInsertValues = vi.fn().mockResolvedValue([]);
const mockOrderBy = vi.fn().mockReturnValue([]);
const mockGroupBy = vi.fn().mockReturnValue([]);
const mockDb = {
  select: vi.fn().mockReturnThis(),
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  orderBy: mockOrderBy,
  groupBy: mockGroupBy,
  limit: vi.fn().mockReturnThis(),
  insert: vi.fn().mockReturnValue({ values: mockInsertValues }),
};

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(mockDb),
}));

vi.mock("../drizzle/schema", () => ({
  adjustmentEffectiveness: {
    aeAdjustmentType: "ae_adjustment_type",
    aeFailureCategory: "ae_failure_category",
    aeService: "ae_service",
    aeEngagementId: "ae_engagement_id",
    aeTarget: "ae_target",
    aePort: "ae_port",
    aeSuccess: "ae_success",
    aeRetryNumber: "ae_retry_number",
    aeBasePriority: "ae_base_priority",
    aeAdjustedPriority: "ae_adjusted_priority",
    aeExecDurationMs: "ae_exec_duration_ms",
    aeExploitOutput: "ae_exploit_output",
    aeCreatedAt: "ae_created_at",
  },
}));

vi.mock("drizzle-orm", () => ({
  eq: (...args: any[]) => ({ type: "eq", args }),
  and: (...args: any[]) => ({ type: "and", args }),
  sql: Object.assign(
    (strings: TemplateStringsArray, ...values: any[]) => ({
      type: "sql", strings, values,
      as: (_name: string) => ({ type: "sql_alias", strings, values }),
    }),
    {}
  ),
  desc: (col: any) => ({ type: "desc", col }),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────

function makeRows(successes: number, failures: number, durationMs: number = 5000) {
  const rows = [];
  const now = Date.now();
  for (let i = 0; i < successes; i++) {
    rows.push({ success: 1, durationMs, createdAt: new Date(now - i * 60000).toISOString() });
  }
  for (let i = 0; i < failures; i++) {
    rows.push({ success: 0, durationMs, createdAt: new Date(now - (successes + i) * 60000).toISOString() });
  }
  return rows;
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("Adjustment Effectiveness Tracker", () => {
  beforeEach(() => {
    mockInsertValues.mockClear().mockResolvedValue([]);
    mockOrderBy.mockClear().mockReturnValue([]);
    mockGroupBy.mockClear().mockReturnValue([]);
    mockDb.select.mockClear().mockReturnThis();
    mockDb.from.mockClear().mockReturnThis();
    mockDb.where.mockClear().mockReturnThis();
    mockDb.limit.mockClear().mockReturnThis();
    mockDb.insert.mockClear().mockReturnValue({ values: mockInsertValues });
  });

  describe("recordAdjustmentOutcome", () => {
    it("inserts a record into the database", async () => {
      mockOrderBy.mockReturnValue([]);
      const { recordAdjustmentOutcome } = await import("./lib/adjustment-effectiveness-tracker");

      await recordAdjustmentOutcome({
        adjustmentType: "add_evasion",
        failureCategory: "waf_blocked",
        service: "http",
        engagementId: 1,
        target: "10.0.0.1",
        port: 8080,
        success: true,
        retryNumber: 1,
        basePriority: 8,
        adjustedPriority: 9,
        execDurationMs: 5000,
        exploitOutput: "shell opened",
      });

      expect(mockInsertValues).toHaveBeenCalledWith(
        expect.objectContaining({
          aeAdjustmentType: "add_evasion",
          aeFailureCategory: "waf_blocked",
          aeService: "http",
          aeSuccess: 1,
        })
      );
    });

    it("truncates exploit output to 2000 chars", async () => {
      mockOrderBy.mockReturnValue([]);
      const { recordAdjustmentOutcome } = await import("./lib/adjustment-effectiveness-tracker");
      const longOutput = "x".repeat(5000);

      await recordAdjustmentOutcome({
        adjustmentType: "change_encoding",
        failureCategory: "input_filtered",
        service: "http",
        success: false,
        exploitOutput: longOutput,
      });

      const insertedValues = mockInsertValues.mock.calls[0][0];
      expect(insertedValues.aeExploitOutput.length).toBe(2000);
    });

    it("returns an effectiveness score after recording", async () => {
      mockOrderBy.mockReturnValue(makeRows(3, 2));
      const { recordAdjustmentOutcome } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await recordAdjustmentOutcome({
        adjustmentType: "add_evasion",
        failureCategory: "waf_blocked",
        service: "record_score_svc",
        success: true,
      });

      expect(score).toHaveProperty("adjustmentType", "add_evasion");
      expect(score).toHaveProperty("failureCategory", "waf_blocked");
      expect(score).toHaveProperty("service", "record_score_svc");
      expect(score).toHaveProperty("totalAttempts", 5);
      expect(score).toHaveProperty("successes", 3);
      expect(score.bayesianRate).toBeGreaterThan(0);
      expect(score.bayesianRate).toBeLessThan(1);
    });
  });

  describe("getEffectivenessScore — Bayesian smoothing", () => {
    it("returns prior rate with zero data", async () => {
      mockOrderBy.mockReturnValue([]);
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("add_evasion", "waf_blocked", "zero_svc");

      expect(score.totalAttempts).toBe(0);
      expect(score.successes).toBe(0);
      expect(score.bayesianRate).toBe(0.35);
      expect(score.priorityModifier).toBe(0);
      expect(score.trend).toBe("insufficient_data");
    });

    it("smooths toward prior with small sample", async () => {
      mockOrderBy.mockReturnValue(makeRows(1, 0));
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("change_encoding", "input_filtered", "small_svc");

      expect(score.rawSuccessRate).toBe(1);
      expect(score.bayesianRate).toBeGreaterThan(0.4);
      expect(score.bayesianRate).toBeLessThan(0.5);
    });

    it("converges to raw rate with large sample", async () => {
      mockOrderBy.mockReturnValue(makeRows(80, 20));
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("add_evasion", "waf_blocked", "large_svc");

      expect(score.rawSuccessRate).toBe(0.8);
      expect(score.bayesianRate).toBeGreaterThan(0.75);
      expect(score.bayesianRate).toBeLessThan(0.82);
    });

    it("applies positive priority modifier for high success rate", async () => {
      mockOrderBy.mockReturnValue(makeRows(80, 20));
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("fragment_payload", "waf_blocked", "pos_svc");

      expect(score.priorityModifier).toBeGreaterThan(0);
    });

    it("applies negative priority modifier for low success rate", async () => {
      mockOrderBy.mockReturnValue(makeRows(5, 45));
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("change_port", "port_closed", "neg_svc");

      expect(score.priorityModifier).toBeLessThan(0);
    });

    it("returns zero modifier with insufficient data", async () => {
      mockOrderBy.mockReturnValue(makeRows(1, 0));
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("time_delay", "timeout", "insuff_svc");

      expect(score.priorityModifier).toBe(0);
    });
  });

  describe("getAdjustedPriorities", () => {
    it("returns adjusted priorities for each adjustment", async () => {
      mockOrderBy.mockReturnValue(makeRows(8, 2));
      const { getAdjustedPriorities } = await import("./lib/adjustment-effectiveness-tracker");

      const adjustments = [
        { type: "change_encoding" as const, description: "Double URL encode", priority: 8 },
        { type: "add_evasion" as const, description: "Add WAF bypass", priority: 6 },
        { type: "fragment_payload" as const, description: "Chunk transfer", priority: 7 },
      ];

      const result = await getAdjustedPriorities(adjustments, "waf_blocked", "adj_svc");

      expect(result).toHaveLength(3);
      for (const r of result) {
        expect(r).toHaveProperty("originalPriority");
        expect(r).toHaveProperty("adjustedPriority");
        expect(r).toHaveProperty("effectiveness");
        expect(r.adjustedPriority).toBeGreaterThanOrEqual(1);
        expect(r.adjustedPriority).toBeLessThanOrEqual(10);
      }
    });

    it("clamps adjusted priorities to 1-10 range", async () => {
      mockOrderBy.mockReturnValue(makeRows(95, 5));
      const { getAdjustedPriorities } = await import("./lib/adjustment-effectiveness-tracker");

      const adjustments = [
        { type: "add_evasion" as const, description: "Add WAF bypass", priority: 9 },
      ];

      const result = await getAdjustedPriorities(adjustments, "waf_blocked", "clamp_svc");
      expect(result[0].adjustedPriority).toBeLessThanOrEqual(10);
      expect(result[0].adjustedPriority).toBeGreaterThanOrEqual(1);
    });
  });

  describe("recordBatchOutcomes", () => {
    it("records multiple outcomes and returns scores", async () => {
      mockOrderBy.mockReturnValue(makeRows(3, 2));
      const { recordBatchOutcomes } = await import("./lib/adjustment-effectiveness-tracker");

      const outcomes = [
        { adjustmentType: "add_evasion" as const, failureCategory: "waf_blocked" as const, service: "batch_1", success: true },
        { adjustmentType: "change_encoding" as const, failureCategory: "waf_blocked" as const, service: "batch_2", success: false },
      ];

      const scores = await recordBatchOutcomes(outcomes);
      expect(scores).toHaveLength(2);
      expect(mockInsertValues).toHaveBeenCalledTimes(2);
    });
  });

  describe("getEffectivenessSummary", () => {
    it("returns empty summary with no data", async () => {
      mockGroupBy.mockReturnValue([]);
      const { getEffectivenessSummary } = await import("./lib/adjustment-effectiveness-tracker");

      const summary = await getEffectivenessSummary();

      expect(summary.totalRecords).toBe(0);
      expect(summary.uniqueCombinations).toBe(0);
      expect(summary.topPerformers).toHaveLength(0);
      expect(summary.worstPerformers).toHaveLength(0);
    });

    it("returns populated summary with data", async () => {
      mockGroupBy.mockReturnValue([
        { adjType: "add_evasion", failCat: "waf_blocked", service: "http", total: 10, successes: 8, avgDuration: 5000 },
        { adjType: "change_encoding", failCat: "input_filtered", service: "http", total: 5, successes: 1, avgDuration: 3000 },
      ]);
      const { getEffectivenessSummary } = await import("./lib/adjustment-effectiveness-tracker");

      const summary = await getEffectivenessSummary();

      expect(summary.totalRecords).toBe(15);
      expect(summary.uniqueCombinations).toBe(2);
      expect(summary.topPerformers.length).toBeGreaterThan(0);
      expect(summary.topPerformers[0].adjustmentType).toBe("add_evasion");
      expect(summary.byFailureCategory).toHaveProperty("waf_blocked");
      expect(summary.byService).toHaveProperty("http");
    });
  });

  describe("buildEffectivenessPrompt", () => {
    it("returns empty string with no data", async () => {
      mockGroupBy.mockReturnValue([]);
      const { buildEffectivenessPrompt } = await import("./lib/adjustment-effectiveness-tracker");

      const prompt = await buildEffectivenessPrompt("waf_blocked", "prompt_empty");
      expect(prompt).toBe("");
    });

    it("returns formatted prompt with data", async () => {
      mockGroupBy.mockReturnValue([
        { adjType: "add_evasion", total: 10, successes: 8 },
        { adjType: "change_encoding", total: 5, successes: 1 },
      ]);
      const { buildEffectivenessPrompt } = await import("./lib/adjustment-effectiveness-tracker");

      const prompt = await buildEffectivenessPrompt("waf_blocked", "prompt_data");
      expect(prompt).toContain("Adjustment Effectiveness Intelligence");
      expect(prompt).toContain("add_evasion");
      expect(prompt).toContain("change_encoding");
      expect(prompt).toContain("PREFER");
      expect(prompt).toContain("AVOID");
    });
  });

  describe("trend calculation", () => {
    it("reports improving trend when recent results are better", async () => {
      mockOrderBy.mockReturnValue([
        ...Array(7).fill(null).map((_, i) => ({ success: 1, durationMs: 5000, createdAt: new Date(Date.now() - i * 60000).toISOString() })),
        { success: 0, durationMs: 5000, createdAt: new Date(Date.now() - 7 * 60000).toISOString() },
        ...Array(2).fill(null).map((_, i) => ({ success: 1, durationMs: 5000, createdAt: new Date(Date.now() - (8 + i) * 60000).toISOString() })),
        ...Array(6).fill(null).map((_, i) => ({ success: 0, durationMs: 5000, createdAt: new Date(Date.now() - (10 + i) * 60000).toISOString() })),
      ]);
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("add_evasion", "waf_blocked", "trend_up");
      expect(score.trend).toBe("improving");
    });

    it("reports degrading trend when recent results are worse", async () => {
      mockOrderBy.mockReturnValue([
        { success: 1, durationMs: 5000, createdAt: new Date(Date.now() - 0).toISOString() },
        ...Array(7).fill(null).map((_, i) => ({ success: 0, durationMs: 5000, createdAt: new Date(Date.now() - (1 + i) * 60000).toISOString() })),
        ...Array(6).fill(null).map((_, i) => ({ success: 1, durationMs: 5000, createdAt: new Date(Date.now() - (8 + i) * 60000).toISOString() })),
        ...Array(2).fill(null).map((_, i) => ({ success: 0, durationMs: 5000, createdAt: new Date(Date.now() - (14 + i) * 60000).toISOString() })),
      ]);
      const { getEffectivenessScore } = await import("./lib/adjustment-effectiveness-tracker");

      const score = await getEffectivenessScore("change_encoding", "input_filtered", "trend_down");
      expect(score.trend).toBe("degrading");
    });
  });
});
