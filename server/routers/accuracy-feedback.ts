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
  runLocalAccuracyComparison,
  getAccuracyHistory,
  getLatestComparisonPerTarget,
  getVulnTypeBreakdown,
  getAggregateVulnTypeAccuracy,
  getAccuracySummary,
  rescoreAllTargets,
  rescoreLocalAllTargets,
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

  /** Rescore all targets using their latest findings against current ground truth */
  rescoreAll: protectedProcedure.mutation(async () => {
    return rescoreAllTargets();
  }),

  /** Run a local accuracy comparison using the improved matching algorithm */
  runLocalComparison: protectedProcedure
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
      autoDetectableOnly: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      return runLocalAccuracyComparison(input);
    }),

  /** Rescore all targets locally with both full and autoDetectable-only scoring */
  rescoreLocalAll: protectedProcedure.mutation(async () => {
    return rescoreLocalAllTargets();
  }),

  /** Get available ground truth targets and their autoDetectable counts */
  groundTruthTargets: protectedProcedure.query(async () => {
    const { GROUND_TRUTH_LIBRARY } = await import('../lib/llm-self-learning');
    return Object.entries(GROUND_TRUTH_LIBRARY).map(([key, vulns]) => {
      const total = vulns.length;
      const autoDetectable = vulns.filter((v: any) => v.autoDetectable !== false).length;
      const manualOnly = vulns.filter((v: any) => v.autoDetectable === false).length;
      return { target: key, total, autoDetectable, manualOnly };
    });
  }),
});
