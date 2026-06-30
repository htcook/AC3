/**
 * Training Data Dashboard Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Provides analytics and browsing for:
 *   1. LLM Decision Logs — every decision made by the engagement orchestrator
 *   2. LLM Training Examples — curated training data from lab scenarios & live engagements
 *   3. LLM Telemetry — raw call metrics (latency, tokens, error rates)
 *   4. Model Learning Progress — accuracy over time, confidence trends
 */

import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { getDb } from "../db";
import {
  llmDecisionLog,
  llmTrainingExamples,
  llmTelemetry,
} from "../../drizzle/schema";
import { eq, and, desc, sql, gte, lte, like, count } from "drizzle-orm";

export const trainingDataDashboardRouter = router({
  // ─── Overview Stats ────────────────────────────────────────────────────────
  getOverview: protectedProcedure
    .input(z.object({
      windowDays: z.number().min(1).max(365).default(30),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const days = input?.windowDays ?? 30;
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace("T", " ");

      // Decision log stats
      const [decisionStats] = await db
        .select({
          total: sql<number>`COUNT(*)`,
          success: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
          failure: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
          partial: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'partial' THEN 1 ELSE 0 END)`,
          pending: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'pending' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
          avgTokens: sql<number>`AVG(${llmDecisionLog.tokensUsed})`,
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff));

      // Training examples stats
      const [trainingStats] = await db
        .select({
          total: sql<number>`COUNT(*)`,
          high: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'high' THEN 1 ELSE 0 END)`,
          medium: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'medium' THEN 1 ELSE 0 END)`,
          low: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'low' THEN 1 ELSE 0 END)`,
          rejected: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'rejected' THEN 1 ELSE 0 END)`,
          avgQualityScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
        })
        .from(llmTrainingExamples);

      // Telemetry stats
      const [telemetryStats] = await db
        .select({
          total: sql<number>`COUNT(*)`,
          successCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
          errorCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          totalTokensIn: sql<number>`SUM(${llmTelemetry.tokensIn})`,
          totalTokensOut: sql<number>`SUM(${llmTelemetry.tokensOut})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.createdAt, cutoff));

      return {
        decisions: {
          total: Number(decisionStats.total) || 0,
          success: Number(decisionStats.success) || 0,
          failure: Number(decisionStats.failure) || 0,
          partial: Number(decisionStats.partial) || 0,
          pending: Number(decisionStats.pending) || 0,
          avgLatencyMs: Math.round(Number(decisionStats.avgLatency) || 0),
          avgTokens: Math.round(Number(decisionStats.avgTokens) || 0),
          avgStealthScore: Number(decisionStats.avgStealth?.toFixed(2)) || 0,
        },
        trainingExamples: {
          total: Number(trainingStats.total) || 0,
          high: Number(trainingStats.high) || 0,
          medium: Number(trainingStats.medium) || 0,
          low: Number(trainingStats.low) || 0,
          rejected: Number(trainingStats.rejected) || 0,
          avgQualityScore: Number(Number(trainingStats.avgQualityScore || 0).toFixed(2)),
        },
        telemetry: {
          totalCalls: Number(telemetryStats.total) || 0,
          successCalls: Number(telemetryStats.successCalls) || 0,
          errorCalls: Number(telemetryStats.errorCalls) || 0,
          errorRate: telemetryStats.total
            ? Number(((Number(telemetryStats.errorCalls) / Number(telemetryStats.total)) * 100).toFixed(2))
            : 0,
          avgLatencyMs: Math.round(Number(telemetryStats.avgLatency) || 0),
          totalTokensIn: Number(telemetryStats.totalTokensIn) || 0,
          totalTokensOut: Number(telemetryStats.totalTokensOut) || 0,
        },
        windowDays: days,
      };
    }),

  // ─── Decision Log List ─────────────────────────────────────────────────────
  listDecisions: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(10).max(100).default(25),
      outcome: z.enum(['success', 'failure', 'partial', 'pending', 'all']).default('all'),
      caller: z.string().optional(),
      phase: z.string().optional(),
      engagementId: z.number().optional(),
      dateFrom: z.string().optional(),
      dateTo: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const page = input?.page ?? 1;
      const pageSize = input?.pageSize ?? 25;
      const offset = (page - 1) * pageSize;

      const conditions: any[] = [];
      if (input?.outcome && input.outcome !== 'all') {
        conditions.push(eq(llmDecisionLog.outcome, input.outcome));
      }
      if (input?.caller) {
        conditions.push(like(llmDecisionLog.caller, `%${input.caller}%`));
      }
      if (input?.phase) {
        conditions.push(eq(llmDecisionLog.phase, input.phase));
      }
      if (input?.engagementId) {
        conditions.push(eq(llmDecisionLog.engagementId, input.engagementId));
      }
      if (input?.dateFrom) {
        conditions.push(gte(llmDecisionLog.createdAt, input.dateFrom));
      }
      if (input?.dateTo) {
        conditions.push(lte(llmDecisionLog.createdAt, input.dateTo));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db
        .select({ total: sql<number>`COUNT(*)` })
        .from(llmDecisionLog)
        .where(whereClause);

      const rows = await db
        .select()
        .from(llmDecisionLog)
        .where(whereClause)
        .orderBy(desc(llmDecisionLog.createdAt))
        .limit(pageSize)
        .offset(offset);

      return {
        rows,
        total: Number(countResult.total) || 0,
        page,
        pageSize,
        totalPages: Math.ceil((Number(countResult.total) || 0) / pageSize),
      };
    }),

  // ─── Decision Outcome Distribution ─────────────────────────────────────────
  getOutcomeDistribution: protectedProcedure
    .input(z.object({
      windowDays: z.number().min(1).max(365).default(30),
      groupBy: z.enum(['caller', 'phase', 'day']).default('day'),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const days = input?.windowDays ?? 30;
      const groupBy = input?.groupBy ?? 'day';
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace("T", " ");

      if (groupBy === 'day') {
        const rows = await db
          .select({
            day: sql<string>`DATE(${llmDecisionLog.createdAt})`.as('day'),
            total: sql<number>`COUNT(*)`,
            success: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
            failure: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
            partial: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'partial' THEN 1 ELSE 0 END)`,
            avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
            avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
          })
          .from(llmDecisionLog)
          .where(gte(llmDecisionLog.createdAt, cutoff))
          .groupBy(sql`DATE(${llmDecisionLog.createdAt})`)
          .orderBy(sql`day`);

        return rows.map(r => ({
          group: r.day,
          total: Number(r.total),
          success: Number(r.success),
          failure: Number(r.failure),
          partial: Number(r.partial),
          avgStealth: Number(Number(r.avgStealth || 0).toFixed(2)),
          avgLatencyMs: Math.round(Number(r.avgLatency) || 0),
        }));
      }

      if (groupBy === 'caller') {
        const rows = await db
          .select({
            caller: llmDecisionLog.caller,
            total: sql<number>`COUNT(*)`,
            success: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
            failure: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
            partial: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'partial' THEN 1 ELSE 0 END)`,
            avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
            avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
          })
          .from(llmDecisionLog)
          .where(gte(llmDecisionLog.createdAt, cutoff))
          .groupBy(llmDecisionLog.caller)
          .orderBy(desc(sql`COUNT(*)`))
          .limit(20);

        return rows.map(r => ({
          group: r.caller,
          total: Number(r.total),
          success: Number(r.success),
          failure: Number(r.failure),
          partial: Number(r.partial),
          avgStealth: Number(Number(r.avgStealth || 0).toFixed(2)),
          avgLatencyMs: Math.round(Number(r.avgLatency) || 0),
        }));
      }

      // groupBy === 'phase'
      const rows = await db
        .select({
          phase: llmDecisionLog.phase,
          total: sql<number>`COUNT(*)`,
          success: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
          failure: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
          partial: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'partial' THEN 1 ELSE 0 END)`,
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
          avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff))
        .groupBy(llmDecisionLog.phase)
        .orderBy(desc(sql`COUNT(*)`));

      return rows.map(r => ({
        group: r.phase,
        total: Number(r.total),
        success: Number(r.success),
        failure: Number(r.failure),
        partial: Number(r.partial),
        avgStealth: Number(Number(r.avgStealth || 0).toFixed(2)),
        avgLatencyMs: Math.round(Number(r.avgLatency) || 0),
      }));
    }),

  // ─── Confidence Trends ─────────────────────────────────────────────────────
  getConfidenceTrends: protectedProcedure
    .input(z.object({
      windowDays: z.number().min(1).max(365).default(30),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const days = input?.windowDays ?? 30;
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace("T", " ");

      // Daily stealth score and success rate trends
      const daily = await db
        .select({
          day: sql<string>`DATE(${llmDecisionLog.createdAt})`.as('day'),
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
          successRate: sql<number>`AVG(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 100.0 ELSE 0.0 END)`,
          avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
          decisionCount: sql<number>`COUNT(*)`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff))
        .groupBy(sql`DATE(${llmDecisionLog.createdAt})`)
        .orderBy(sql`day`);

      // Caller-level accuracy trends
      const callerTrends = await db
        .select({
          caller: llmDecisionLog.caller,
          total: sql<number>`COUNT(*)`,
          successRate: sql<number>`AVG(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 100.0 ELSE 0.0 END)`,
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
          avgLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff))
        .groupBy(llmDecisionLog.caller)
        .orderBy(desc(sql`COUNT(*)`))
        .limit(15);

      return {
        daily: daily.map(d => ({
          day: d.day,
          avgStealth: Number(Number(d.avgStealth || 0).toFixed(2)),
          successRate: Number(Number(d.successRate || 0).toFixed(1)),
          avgLatencyMs: Math.round(Number(d.avgLatency) || 0),
          decisionCount: Number(d.decisionCount),
        })),
        callerTrends: callerTrends.map(c => ({
          caller: c.caller,
          total: Number(c.total),
          successRate: Number(Number(c.successRate || 0).toFixed(1)),
          avgStealth: Number(Number(c.avgStealth || 0).toFixed(2)),
          avgLatencyMs: Math.round(Number(c.avgLatency) || 0),
        })),
      };
    }),

  // ─── Training Examples Browser ─────────────────────────────────────────────
  listTrainingExamples: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(10).max(100).default(25),
      quality: z.enum(['high', 'medium', 'low', 'rejected', 'all']).default('all'),
      source: z.enum(['lab_scenario', 'live_engagement', 'manual', 'synthetic', 'all']).default('all'),
      model: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const page = input?.page ?? 1;
      const pageSize = input?.pageSize ?? 25;
      const offset = (page - 1) * pageSize;

      const conditions: any[] = [];
      if (input?.quality && input.quality !== 'all') {
        conditions.push(eq(llmTrainingExamples.quality, input.quality));
      }
      if (input?.source && input.source !== 'all') {
        conditions.push(eq(llmTrainingExamples.source, input.source));
      }
      if (input?.model) {
        conditions.push(like(llmTrainingExamples.model, `%${input.model}%`));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db
        .select({ total: sql<number>`COUNT(*)` })
        .from(llmTrainingExamples)
        .where(whereClause);

      const rows = await db
        .select()
        .from(llmTrainingExamples)
        .where(whereClause)
        .orderBy(desc(llmTrainingExamples.createdAt))
        .limit(pageSize)
        .offset(offset);

      return {
        rows,
        total: Number(countResult.total) || 0,
        page,
        pageSize,
        totalPages: Math.ceil((Number(countResult.total) || 0) / pageSize),
      };
    }),

  // ─── Training Quality Distribution ─────────────────────────────────────────
  getTrainingQualityDistribution: protectedProcedure
    .query(async () => {
      const db = await getDb();

      const bySource = await db
        .select({
          source: llmTrainingExamples.source,
          quality: llmTrainingExamples.quality,
          count: sql<number>`COUNT(*)`,
          avgScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
        })
        .from(llmTrainingExamples)
        .groupBy(llmTrainingExamples.source, llmTrainingExamples.quality)
        .orderBy(llmTrainingExamples.source);

      const byModel = await db
        .select({
          model: llmTrainingExamples.model,
          count: sql<number>`COUNT(*)`,
          avgScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
          highCount: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'high' THEN 1 ELSE 0 END)`,
        })
        .from(llmTrainingExamples)
        .groupBy(llmTrainingExamples.model)
        .orderBy(desc(sql`COUNT(*)`));

      return {
        bySource: bySource.map(r => ({
          source: r.source,
          quality: r.quality,
          count: Number(r.count),
          avgScore: Number(Number(r.avgScore || 0).toFixed(2)),
        })),
        byModel: byModel.map(r => ({
          model: r.model,
          count: Number(r.count),
          avgScore: Number(Number(r.avgScore || 0).toFixed(2)),
          highCount: Number(r.highCount),
        })),
      };
    }),

  // ─── Telemetry Trends ──────────────────────────────────────────────────────
  getTelemetryTrends: protectedProcedure
    .input(z.object({
      windowDays: z.number().min(1).max(365).default(30),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const days = input?.windowDays ?? 30;
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace("T", " ");

      const daily = await db
        .select({
          day: sql<string>`DATE(${llmTelemetry.createdAt})`.as('day'),
          totalCalls: sql<number>`COUNT(*)`,
          errors: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          totalTokensIn: sql<number>`SUM(${llmTelemetry.tokensIn})`,
          totalTokensOut: sql<number>`SUM(${llmTelemetry.tokensOut})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.createdAt, cutoff))
        .groupBy(sql`DATE(${llmTelemetry.createdAt})`)
        .orderBy(sql`day`);

      const topCallers = await db
        .select({
          caller: llmTelemetry.caller,
          totalCalls: sql<number>`COUNT(*)`,
          errors: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          totalTokensIn: sql<number>`SUM(${llmTelemetry.tokensIn})`,
          totalTokensOut: sql<number>`SUM(${llmTelemetry.tokensOut})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.createdAt, cutoff))
        .groupBy(llmTelemetry.caller)
        .orderBy(desc(sql`COUNT(*)`))
        .limit(20);

      return {
        daily: daily.map(d => ({
          day: d.day,
          totalCalls: Number(d.totalCalls),
          errors: Number(d.errors),
          errorRate: d.totalCalls ? Number(((Number(d.errors) / Number(d.totalCalls)) * 100).toFixed(2)) : 0,
          avgLatencyMs: Math.round(Number(d.avgLatency) || 0),
          totalTokensIn: Number(d.totalTokensIn),
          totalTokensOut: Number(d.totalTokensOut),
        })),
        topCallers: topCallers.map(c => ({
          caller: c.caller,
          totalCalls: Number(c.totalCalls),
          errors: Number(c.errors),
          errorRate: c.totalCalls ? Number(((Number(c.errors) / Number(c.totalCalls)) * 100).toFixed(2)) : 0,
          avgLatencyMs: Math.round(Number(c.avgLatency) || 0),
          totalTokensIn: Number(c.totalTokensIn),
          totalTokensOut: Number(c.totalTokensOut),
        })),
      };
    }),

  // ─── Model Performance Comparison ──────────────────────────────────────────
  getModelPerformance: protectedProcedure
    .input(z.object({
      windowDays: z.number().min(1).max(365).default(30),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const days = input?.windowDays ?? 30;
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace("T", " ");

      const models = await db
        .select({
          model: llmTelemetry.model,
          totalCalls: sql<number>`COUNT(*)`,
          successCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
          errors: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          p95Latency: sql<number>`0`,
          avgTokensIn: sql<number>`AVG(${llmTelemetry.tokensIn})`,
          avgTokensOut: sql<number>`AVG(${llmTelemetry.tokensOut})`,
          totalRetries: sql<number>`SUM(${llmTelemetry.retryCount})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.createdAt, cutoff))
        .groupBy(llmTelemetry.model)
        .orderBy(desc(sql`COUNT(*)`));

      return models.map(m => ({
        model: m.model,
        totalCalls: Number(m.totalCalls),
        successRate: m.totalCalls
          ? Number(((Number(m.successCalls) / Number(m.totalCalls)) * 100).toFixed(1))
          : 0,
        errors: Number(m.errors),
        avgLatencyMs: Math.round(Number(m.avgLatency) || 0),
        p95LatencyMs: Math.round(Number(m.p95Latency) || 0),
        avgTokensIn: Math.round(Number(m.avgTokensIn) || 0),
        avgTokensOut: Math.round(Number(m.avgTokensOut) || 0),
        totalRetries: Number(m.totalRetries) || 0,
      }));
    }),
});
