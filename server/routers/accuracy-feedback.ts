// @ts-nocheck
/**
 * Accuracy Feedback Loop Router
 * ─────────────────────────────
 * tRPC procedures for the accuracy feedback loop:
 *   - Run accuracy comparison after a lab scan
 *   - Get accuracy history and trends
 *   - Get per-target and per-vuln-type breakdowns
 *   - Get aggregate accuracy summary
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  runAccuracyComparison,
  getAccuracyHistory,
  getLatestComparisonPerTarget,
  getVulnTypeBreakdown,
  getAggregateVulnTypeAccuracy,
  getAccuracySummary,
} from "../lib/accuracy-feedback-loop";
import { seedAccuracyData } from "../lib/accuracy-seed";

export const accuracyFeedbackRouter = router({
  /** Run an accuracy comparison for a completed lab scan */
  runComparison: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      engagementId: z.string().optional(),
      targetPreset: z.string(),
      targetUrl: z.string().optional(),
      scanType: z.string().optional(),
      findings: z.array(z.object({
        name: z.string(),
        severity: z.string().optional(),
        cwe: z.string().optional(),
        owasp: z.string().optional(),
        endpoint: z.string().optional(),
        confidence: z.number().optional(),
      })),
      knowledgeModulesUsed: z.array(z.string()).optional(),
      scanDurationMs: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      return runAccuracyComparison(input);
    }),

  /** Get accuracy history for a target or all targets */
  history: protectedProcedure
    .input(z.object({
      targetPreset: z.string().optional(),
      limit: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getAccuracyHistory(input ?? undefined);
    }),

  /** Get the latest comparison for each target */
  latestPerTarget: protectedProcedure.query(async () => {
    return getLatestComparisonPerTarget();
  }),

  /** Get vuln type breakdown for a specific comparison */
  vulnTypeBreakdown: protectedProcedure
    .input(z.object({ comparisonId: z.number() }))
    .query(async ({ input }) => {
      return getVulnTypeBreakdown(input.comparisonId);
    }),

  /** Get aggregate vuln type accuracy across all comparisons */
  aggregateVulnAccuracy: protectedProcedure
    .input(z.object({ targetPreset: z.string().optional() }).optional())
    .query(async ({ input }) => {
      return getAggregateVulnTypeAccuracy(input?.targetPreset);
    }),

  /** Get overall accuracy summary statistics */
  summary: protectedProcedure.query(async () => {
    return getAccuracySummary();
  }),

  /** Seed accuracy data by running comparisons against the DO learning engine */
  seed: protectedProcedure.mutation(async () => {
    return seedAccuracyData();
  }),
});
