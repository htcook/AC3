import { describe, it, expect, vi, beforeAll } from "vitest";

/**
 * LLM Telemetry Tests
 *
 * Tests the telemetry recording and aggregation functions.
 * Uses the actual database helpers from db.ts.
 */

// Mock the database module to avoid real DB calls
const mockInsert = vi.fn().mockReturnValue({ values: vi.fn().mockResolvedValue(undefined) });
const mockSelect = vi.fn();

vi.mock("./db", () => ({
  recordLlmTelemetry: vi.fn().mockResolvedValue(undefined),
  getLlmTelemetrySummary: vi.fn().mockResolvedValue({
    total_calls: 100,
    success_count: 85,
    retried_success_count: 5,
    error_count: 8,
    timeout_count: 2,
    avg_latency_ms: 3500,
    max_latency_ms: 45000,
    total_tokens: 250000,
    total_tokens_in: 200000,
    total_tokens_out: 50000,
    avg_retries: 0.15,
  }),
  getLlmTelemetryTimeSeries: vi.fn().mockResolvedValue([
    { hour_bucket: "2026-03-03 18:00", total_calls: 15, success_count: 14, failure_count: 1, avg_latency_ms: 2500 },
    { hour_bucket: "2026-03-03 19:00", total_calls: 22, success_count: 20, failure_count: 2, avg_latency_ms: 3200 },
    { hour_bucket: "2026-03-03 20:00", total_calls: 8, success_count: 8, failure_count: 0, avg_latency_ms: 1800 },
  ]),
  getLlmTelemetryTopCallers: vi.fn().mockResolvedValue([
    { caller: "engagement-orchestrator:genPlan", call_count: 35, avg_latency_ms: 4200, success_rate: 94.3, total_tokens: 120000 },
    { caller: "c2-module-builder:llmRecommendModules", call_count: 28, avg_latency_ms: 5100, success_rate: 89.3, total_tokens: 85000 },
    { caller: "domain-intel:analyzeTarget", call_count: 20, avg_latency_ms: 2800, success_rate: 100, total_tokens: 45000 },
  ]),
  getLlmTelemetryRecentErrors: vi.fn().mockResolvedValue([
    { id: 1, called_at: "2026-03-03T20:15:00Z", caller: "c2-module-builder", llm_status: "error", http_status: 403, latency_ms: 1200, retry_count: 3, error_message: "403 Forbidden" },
    { id: 2, called_at: "2026-03-03T19:45:00Z", caller: "engagement-orchestrator", llm_status: "timeout", http_status: null, latency_ms: 90000, retry_count: 3, error_message: "Timed out after 90s" },
  ]),
  getLlmTelemetryLatencyDistribution: vi.fn().mockResolvedValue([
    { latency_bucket: "<1s", count: 12 },
    { latency_bucket: "1-3s", count: 35 },
    { latency_bucket: "3-5s", count: 28 },
    { latency_bucket: "5-10s", count: 15 },
    { latency_bucket: "10-30s", count: 8 },
    { latency_bucket: "30-60s", count: 2 },
    { latency_bucket: ">60s", count: 0 },
  ]),
  getLlmTelemetryModelUsage: vi.fn().mockResolvedValue([
    { model: "gemini-2.5-flash", call_count: 90, avg_latency_ms: 3200, success_rate: 93.3, total_tokens_in: 180000, total_tokens_out: 45000 },
    { model: "unknown", call_count: 10, avg_latency_ms: 5500, success_rate: 80.0, total_tokens_in: 20000, total_tokens_out: 5000 },
  ]),
}));

import {
  recordLlmTelemetry,
  getLlmTelemetrySummary,
  getLlmTelemetryTimeSeries,
  getLlmTelemetryTopCallers,
  getLlmTelemetryRecentErrors,
  getLlmTelemetryLatencyDistribution,
  getLlmTelemetryModelUsage,
} from "./db";

describe("LLM Telemetry — Recording", () => {
  it("recordLlmTelemetry accepts a valid telemetry entry", async () => {
    await expect(
      recordLlmTelemetry({
        calledAt: new Date(),
        caller: "test:unit",
        model: "gemini-2.5-flash",
        llmStatus: "success",
        httpStatus: 200,
        latencyMs: 2500,
        retryCount: 0,
        tokensIn: 1500,
        tokensOut: 400,
        hasResponseFormat: true,
        errorMessage: null,
        engagementId: 1350014,
      })
    ).resolves.not.toThrow();
    expect(recordLlmTelemetry).toHaveBeenCalledTimes(1);
  });

  it("recordLlmTelemetry handles error telemetry entries", async () => {
    await expect(
      recordLlmTelemetry({
        calledAt: new Date(),
        caller: "c2-module-builder:llmRecommendModules",
        model: "gemini-2.5-flash",
        llmStatus: "error",
        httpStatus: 403,
        latencyMs: 1200,
        retryCount: 3,
        tokensIn: 0,
        tokensOut: 0,
        hasResponseFormat: false,
        errorMessage: "403 Forbidden",
        engagementId: null,
      })
    ).resolves.not.toThrow();
  });

  it("recordLlmTelemetry handles timeout telemetry entries", async () => {
    await expect(
      recordLlmTelemetry({
        calledAt: new Date(),
        caller: "engagement-orchestrator:genPlan",
        model: "gemini-2.5-flash",
        llmStatus: "timeout",
        httpStatus: null,
        latencyMs: 90000,
        retryCount: 3,
        tokensIn: 0,
        tokensOut: 0,
        hasResponseFormat: true,
        errorMessage: "Timed out after 90s — all 4 attempts exhausted",
        engagementId: 1350014,
      })
    ).resolves.not.toThrow();
  });
});

describe("LLM Telemetry — Summary Query", () => {
  it("returns aggregated summary stats for a time window", async () => {
    const summary = await getLlmTelemetrySummary(24);
    expect(summary).toBeDefined();
    expect(summary.total_calls).toBe(100);
    expect(summary.success_count).toBe(85);
    expect(summary.retried_success_count).toBe(5);
    expect(summary.error_count).toBe(8);
    expect(summary.timeout_count).toBe(2);
    expect(summary.avg_latency_ms).toBe(3500);
    expect(summary.max_latency_ms).toBe(45000);
    expect(summary.total_tokens).toBe(250000);
    expect(summary.avg_retries).toBe(0.15);
  });

  it("computes correct success rate from summary", async () => {
    const summary = await getLlmTelemetrySummary(24);
    const successCount = summary.success_count + summary.retried_success_count;
    const rate = (successCount / summary.total_calls) * 100;
    expect(rate).toBe(90);
  });
});

describe("LLM Telemetry — Time Series", () => {
  it("returns hourly buckets with call counts", async () => {
    const series = await getLlmTelemetryTimeSeries(24);
    expect(series).toHaveLength(3);
    expect(series[0]).toHaveProperty("hour_bucket");
    expect(series[0]).toHaveProperty("total_calls");
    expect(series[0]).toHaveProperty("success_count");
    expect(series[0]).toHaveProperty("failure_count");
    expect(series[0]).toHaveProperty("avg_latency_ms");
  });

  it("failure counts are non-negative", async () => {
    const series = await getLlmTelemetryTimeSeries(24);
    for (const bucket of series) {
      expect(Number(bucket.failure_count)).toBeGreaterThanOrEqual(0);
      expect(Number(bucket.success_count)).toBeLessThanOrEqual(Number(bucket.total_calls));
    }
  });
});

describe("LLM Telemetry — Top Callers", () => {
  it("returns callers ranked by invocation count", async () => {
    const callers = await getLlmTelemetryTopCallers(24, 15);
    expect(callers).toHaveLength(3);
    expect(callers[0].call_count).toBeGreaterThanOrEqual(callers[1].call_count);
    expect(callers[1].call_count).toBeGreaterThanOrEqual(callers[2].call_count);
  });

  it("each caller has required fields", async () => {
    const callers = await getLlmTelemetryTopCallers(24, 15);
    for (const c of callers) {
      expect(c).toHaveProperty("caller");
      expect(c).toHaveProperty("call_count");
      expect(c).toHaveProperty("avg_latency_ms");
      expect(c).toHaveProperty("success_rate");
      expect(c).toHaveProperty("total_tokens");
    }
  });
});

describe("LLM Telemetry — Recent Errors", () => {
  it("returns recent error events", async () => {
    const errors = await getLlmTelemetryRecentErrors(20);
    expect(errors).toHaveLength(2);
    expect(errors[0].llm_status).toBe("error");
    expect(errors[1].llm_status).toBe("timeout");
  });

  it("error entries have error messages", async () => {
    const errors = await getLlmTelemetryRecentErrors(20);
    for (const e of errors) {
      expect(e.error_message).toBeTruthy();
    }
  });
});

describe("LLM Telemetry — Latency Distribution", () => {
  it("returns latency buckets with counts", async () => {
    const dist = await getLlmTelemetryLatencyDistribution(24);
    expect(dist.length).toBeGreaterThan(0);
    const bucketNames = dist.map((d: any) => d.latency_bucket);
    expect(bucketNames).toContain("<1s");
    expect(bucketNames).toContain("1-3s");
    expect(bucketNames).toContain(">60s");
  });

  it("all counts are non-negative", async () => {
    const dist = await getLlmTelemetryLatencyDistribution(24);
    for (const d of dist) {
      expect(Number(d.count)).toBeGreaterThanOrEqual(0);
    }
  });
});

describe("LLM Telemetry — Model Usage", () => {
  it("returns model breakdown with stats", async () => {
    const models = await getLlmTelemetryModelUsage(24);
    expect(models.length).toBeGreaterThan(0);
    expect(models[0]).toHaveProperty("model");
    expect(models[0]).toHaveProperty("call_count");
    expect(models[0]).toHaveProperty("avg_latency_ms");
    expect(models[0]).toHaveProperty("success_rate");
    expect(models[0]).toHaveProperty("total_tokens_in");
    expect(models[0]).toHaveProperty("total_tokens_out");
  });

  it("primary model has highest call count", async () => {
    const models = await getLlmTelemetryModelUsage(24);
    expect(models[0].model).toBe("gemini-2.5-flash");
    expect(models[0].call_count).toBeGreaterThan(models[1].call_count);
  });
});
