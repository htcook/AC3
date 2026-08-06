// @ts-nocheck
/**
 * Learning Engine Router
 * ──────────────────────
 * tRPC procedures that proxy to the dual-stream learning engine on the DO droplet.
 * Two streams:
 *   1. Training Lab — scores LLM findings against ground truth vulnerabilities
 *   2. Threat Actor — scores TTP/CVE detection against the threat group catalog
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getLearningHealth,
  getLearningDashboard,
  scoreFindings,
  recordEngagement,
  recordLearningEvent,
  getAccuracyTrend,
  getAccuracyStats,
  getVulnAccuracyBreakdown,
  getGroundTruth,
  getEngagementRuns,
  getLearningEvents,
  scoreThreatAttribution,
  getThreatTrend,
  getThreatStats,
  getThreatGroupLearning,
  getThreatGroupProfile,
  listThreatGroups,
} from "../lib/learning-engine-api";

// ═══ Training Lab Stream ═════════════════════════════════════════════════════
const trainingLabRouter = router({
  /** Score findings from a scan against ground truth */
  scoreFindings: protectedProcedure
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
    }))
    .mutation(async ({ input }) => {
      return scoreFindings(input);
    }),

  /** Record a new engagement run */
  recordEngagement: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      targetPreset: z.string(),
      targetUrl: z.string().optional(),
      scanType: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return recordEngagement(input);
    }),

  /** Record a learning event (decision, context usage, etc.) */
  recordEvent: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      engagementId: z.string().optional(),
      targetPreset: z.string(),
      eventType: z.string(),
      phase: z.string().optional(),
      decision: z.string().optional(),
      contextUsed: z.string().optional(),
      knowledgeModules: z.array(z.string()).optional(),
      outcome: z.string().optional(),
      confidence: z.number().optional(),
      groundTruthMatch: z.boolean().optional(),
      metadata: z.record(z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      return recordLearningEvent(input);
    }),

  /** Get accuracy trend over time */
  accuracyTrend: protectedProcedure
    .input(z.object({
      target: z.string().optional(),
      limit: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getAccuracyTrend(input?.target, input?.limit);
    }),

  /** Get aggregate accuracy stats */
  accuracyStats: protectedProcedure.query(async () => {
    return getAccuracyStats();
  }),

  /** Get per-vuln-type accuracy breakdown */
  vulnAccuracy: protectedProcedure.query(async () => {
    return getVulnAccuracyBreakdown();
  }),

  /** Get ground truth for a target or all targets */
  groundTruth: protectedProcedure
    .input(z.object({ target: z.string().optional() }).optional())
    .query(async ({ input }) => {
      return getGroundTruth(input?.target);
    }),

  /** Get engagement run history */
  engagementRuns: protectedProcedure
    .input(z.object({
      target: z.string().optional(),
      limit: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getEngagementRuns(input?.target, input?.limit);
    }),

  /** Get learning events */
  learningEvents: protectedProcedure
    .input(z.object({
      target: z.string().optional(),
      session: z.string().optional(),
      limit: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getLearningEvents(input);
    }),
});

// ═══ Threat Actor Stream ═════════════════════════════════════════════════════
const threatActorRouter = router({
  /** Score TTPs/CVEs against the threat actor catalog */
  scoreAttribution: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      engagementId: z.string().optional(),
      targetUrl: z.string().optional(),
      scanType: z.string().optional(),
      ttps: z.array(z.object({
        techniqueId: z.string().optional(),
        techniqueName: z.string().optional(),
        tactic: z.string().optional(),
        cve: z.string().optional(),
        tool: z.string().optional(),
      })),
      cves: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      return scoreThreatAttribution(input);
    }),

  /** Get threat attribution trend */
  attributionTrend: protectedProcedure
    .input(z.object({ limit: z.number().optional() }).optional())
    .query(async ({ input }) => {
      return getThreatTrend(input?.limit);
    }),

  /** Get threat stats (top groups, techniques, CVEs) */
  threatStats: protectedProcedure.query(async () => {
    return getThreatStats();
  }),

  /** Get learning history for a specific threat group */
  groupLearning: protectedProcedure
    .input(z.object({ groupId: z.string() }))
    .query(async ({ input }) => {
      return getThreatGroupLearning(input.groupId);
    }),

  /** Get detailed threat group profile */
  groupProfile: protectedProcedure
    .input(z.object({ groupId: z.string() }))
    .query(async ({ input }) => {
      return getThreatGroupProfile(input.groupId);
    }),

  /** List all threat groups */
  listGroups: protectedProcedure.query(async () => {
    return listThreatGroups();
  }),
});

// ═══ Combined ════════════════════════════════════════════════════════════════
export const learningEngineRouter = router({
  /** Health check */
  health: protectedProcedure.query(async () => {
    return getLearningHealth();
  }),

  /** Combined dashboard stats for both streams */
  dashboard: protectedProcedure.query(async () => {
    return getLearningDashboard();
  }),

  trainingLab: trainingLabRouter,
  threatActor: threatActorRouter,
});
