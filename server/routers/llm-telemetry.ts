import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getLlmTelemetrySummary,
  getLlmTelemetryTimeSeries,
  getLlmTelemetryTopCallers,
  getLlmTelemetryRecentErrors,
  getLlmTelemetryLatencyDistribution,
  getLlmTelemetryModelUsage,
  getEngagementLlmCost,
  getEngagementLlmCostBreakdown,
  getAllEngagementLlmCosts,
  getEngagementLlmCostTimeSeries,
} from "../db";

export const llmTelemetryRouter = router({
  /**
   * Get summary stats (total calls, success rate, avg latency, token usage)
   * for a configurable time window (default 24h).
   */
  summary: protectedProcedure
    .input(z.object({ windowHours: z.number().min(1).max(720).default(24) }).optional())
    .query(async ({ input }) => {
      const hours = input?.windowHours ?? 24;
      return getLlmTelemetrySummary(hours);
    }),

  /**
   * Get hourly time series data for charting usage over time.
   */
  timeSeries: protectedProcedure
    .input(z.object({ windowHours: z.number().min(1).max(720).default(24) }).optional())
    .query(async ({ input }) => {
      const hours = input?.windowHours ?? 24;
      return getLlmTelemetryTimeSeries(hours);
    }),

  /**
   * Get top callers ranked by invocation count.
   */
  topCallers: protectedProcedure
    .input(
      z.object({
        windowHours: z.number().min(1).max(720).default(24),
        limit: z.number().min(1).max(50).default(15),
      }).optional()
    )
    .query(async ({ input }) => {
      const hours = input?.windowHours ?? 24;
      const limit = input?.limit ?? 15;
      return getLlmTelemetryTopCallers(hours, limit);
    }),

  /**
   * Get recent error events for debugging.
   */
  recentErrors: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(20) }).optional())
    .query(async ({ input }) => {
      const limit = input?.limit ?? 20;
      return getLlmTelemetryRecentErrors(limit);
    }),

  /**
   * Get latency distribution buckets for histogram visualization.
   */
  latencyDistribution: protectedProcedure
    .input(z.object({ windowHours: z.number().min(1).max(720).default(24) }).optional())
    .query(async ({ input }) => {
      const hours = input?.windowHours ?? 24;
      return getLlmTelemetryLatencyDistribution(hours);
    }),

  /**
   * Get model usage breakdown.
   */
  modelUsage: protectedProcedure
    .input(z.object({ windowHours: z.number().min(1).max(720).default(24) }).optional())
    .query(async ({ input }) => {
      const hours = input?.windowHours ?? 24;
      return getLlmTelemetryModelUsage(hours);
    }),

  // ─── Per-Engagement Cost Tracking ─────────────────────────────────────────

  /**
   * Get LLM cost summary for a single engagement.
   * Returns total calls, tokens, estimated USD cost.
   */
  engagementCost: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getEngagementLlmCost(input.engagementId);
    }),

  /**
   * Get per-caller cost breakdown for a single engagement.
   * Shows which pipeline stages consumed the most tokens.
   */
  engagementCostBreakdown: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getEngagementLlmCostBreakdown(input.engagementId);
    }),

  /**
   * Get all engagements ranked by total LLM cost.
   * Used in the telemetry dashboard for cross-engagement comparison.
   */
  allEngagementCosts: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }).optional())
    .query(async ({ input }) => {
      const limit = input?.limit ?? 50;
      return getAllEngagementLlmCosts(limit);
    }),

  /**
   * Get hourly cost time series for a single engagement.
   * Shows token consumption and cost accumulation over time.
   */
  engagementCostTimeSeries: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getEngagementLlmCostTimeSeries(input.engagementId);
    }),
});
