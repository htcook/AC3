/**
 * Real-Time Engagement Monitoring Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Provides live data feeds for engagement monitoring:
 *   - Active engagement progress with phase tracking
 *   - Recent LLM decisions as they happen
 *   - Agent delegation events in real time
 *   - Live telemetry stream (latest calls, errors, latency)
 *
 * The frontend uses WebSocket (already wired via ws-event-hub) for push events
 * and these tRPC queries for initial state + periodic polling.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import {
  engagements,
  engagementTimelineEvents,
  llmTelemetry,
  llmDecisionLog,
} from "../../drizzle/schema";
import { eq, desc, sql, and, gte, inArray } from "drizzle-orm";
import { scopeEngagementWhere, scopedAnd, assertEngagementAccess } from "../lib/engagement-access-guard";

export const realtimeMonitorRouter = router({
  /**
   * Get active engagements with their latest progress
   */
  getActiveEngagements: protectedProcedure.query(async ({ ctx }) => {
    const db = await getDbRequired();
    const scope = scopeEngagementWhere(ctx.user);
    const statusFilter = inArray(engagements.status, ["active", "planning"]);
    const active = await db
      .select({
        id: engagements.id,
        name: engagements.name,
        customerName: engagements.customerName,
        engagementType: engagements.engagementType,
        status: engagements.status,
        startDate: engagements.startDate,
        targetDomain: engagements.targetDomain,
        targetIpRange: engagements.targetIpRange,
        scanMode: engagements.scanMode,
      })
      .from(engagements)
      .where(scope ? and(statusFilter, scope) : statusFilter)
      .orderBy(desc(engagements.createdAt))
      .limit(20);

    // Get latest timeline event per engagement for phase info
    const engIds = active.map((e) => e.id);
    if (engIds.length === 0) return { engagements: [], totalActive: 0 };

    const latestEvents = await db
      .select({
        engagementId: engagementTimelineEvents.engagementId,
        phase: engagementTimelineEvents.phase,
        eventType: engagementTimelineEvents.eventType,
        title: engagementTimelineEvents.title,
        severity: engagementTimelineEvents.severity,
        timestamp: engagementTimelineEvents.timestamp,
      })
      .from(engagementTimelineEvents)
      .where(inArray(engagementTimelineEvents.engagementId, engIds))
      .orderBy(desc(engagementTimelineEvents.timestamp))
      .limit(100);

    // Get event counts per engagement
    const eventCounts = await db
      .select({
        engagementId: engagementTimelineEvents.engagementId,
        total: sql<number>`COUNT(*)`,
        findings: sql<number>`SUM(CASE WHEN ${engagementTimelineEvents.eventType} = 'finding_discovered' THEN 1 ELSE 0 END)`,
        exploits: sql<number>`SUM(CASE WHEN ${engagementTimelineEvents.eventType} IN ('exploit_attempted', 'exploit_succeeded') THEN 1 ELSE 0 END)`,
        shells: sql<number>`SUM(CASE WHEN ${engagementTimelineEvents.eventType} = 'shell_obtained' THEN 1 ELSE 0 END)`,
      })
      .from(engagementTimelineEvents)
      .where(inArray(engagementTimelineEvents.engagementId, engIds))
      .groupBy(engagementTimelineEvents.engagementId);

    const enriched = active.map((eng) => {
      const events = latestEvents.filter((e) => e.engagementId === eng.id);
      const counts = eventCounts.find((c) => c.engagementId === eng.id);
      const latestEvent = events[0];

      return {
        ...eng,
        currentPhase: latestEvent?.phase || "planning",
        latestEvent: latestEvent
          ? {
              eventType: latestEvent.eventType,
              title: latestEvent.title,
              severity: latestEvent.severity,
              timestamp: Number(latestEvent.timestamp),
            }
          : null,
        stats: {
          totalEvents: Number(counts?.total ?? 0),
          findings: Number(counts?.findings ?? 0),
          exploits: Number(counts?.exploits ?? 0),
          shells: Number(counts?.shells ?? 0),
        },
      };
    });

    return { engagements: enriched, totalActive: active.length };
  }),

  /**
   * Get the live LLM decision feed — most recent decisions across all engagements
   */
  getLiveDecisionFeed: protectedProcedure
    .input(
      z
        .object({
          limit: z.number().min(1).max(100).default(50),
          engagementId: z.number().optional(),
        })
        .optional()
    )
    .query(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const limit = input?.limit ?? 50;

      const conditions = [];
      if (input?.engagementId) {
        conditions.push(eq(llmDecisionLog.engagementId, input.engagementId));
      }

      const decisions = await db
        .select({
          id: llmDecisionLog.id,
          engagementId: llmDecisionLog.engagementId,
          phase: llmDecisionLog.phase,
          caller: llmDecisionLog.caller,
          decision: llmDecisionLog.decision,
          reasoning: llmDecisionLog.reasoning,
          outcome: llmDecisionLog.outcome,
          outcomeDetail: llmDecisionLog.outcomeDetail,
          stealthScore: llmDecisionLog.stealthScore,
          latencyMs: llmDecisionLog.latencyMs,
          tokensUsed: llmDecisionLog.tokensUsed,
          contextSummary: llmDecisionLog.contextSummary,
          createdAt: llmDecisionLog.createdAt,
        })
        .from(llmDecisionLog)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(llmDecisionLog.createdAt))
        .limit(limit);

      return {
        decisions: decisions.map((d) => ({
          ...d,
          agentName: extractAgentName(d.caller),
          isSpecialist: d.caller.startsWith("specialist:"),
        })),
        total: decisions.length,
      };
    }),

  /**
   * Get the live telemetry stream — most recent LLM calls with status
   */
  getLiveTelemetryFeed: protectedProcedure
    .input(
      z
        .object({
          limit: z.number().min(1).max(100).default(30),
        })
        .optional()
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const limit = input?.limit ?? 30;

      const telemetry = await db
        .select({
          id: llmTelemetry.id,
          calledAt: llmTelemetry.calledAt,
          caller: llmTelemetry.caller,
          model: llmTelemetry.model,
          llmStatus: llmTelemetry.llmStatus,
          httpStatus: llmTelemetry.httpStatus,
          latencyMs: llmTelemetry.latencyMs,
          retryCount: llmTelemetry.retryCount,
          tokensIn: llmTelemetry.tokensIn,
          tokensOut: llmTelemetry.tokensOut,
          errorMessage: llmTelemetry.errorMessage,
          engagementId: llmTelemetry.engagementId,
        })
        .from(llmTelemetry)
        .orderBy(desc(llmTelemetry.calledAt))
        .limit(limit);

      // Compute live stats
      const last5min = new Date(Date.now() - 5 * 60 * 1000)
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      const [recentStats] = await db
        .select({
          totalCalls: sql<number>`COUNT(*)`,
          successCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
          errorCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.calledAt, last5min));

      return {
        telemetry: telemetry.map((t) => ({
          ...t,
          agentName: extractAgentName(t.caller),
        })),
        liveStats: {
          callsLast5min: Number(recentStats?.totalCalls ?? 0),
          successRate:
            Number(recentStats?.totalCalls ?? 0) > 0
              ? Math.round(
                  (Number(recentStats?.successCalls ?? 0) /
                    Number(recentStats?.totalCalls ?? 1)) *
                    100
                )
              : 0,
          errorRate:
            Number(recentStats?.totalCalls ?? 0) > 0
              ? Math.round(
                  (Number(recentStats?.errorCalls ?? 0) /
                    Number(recentStats?.totalCalls ?? 1)) *
                    100
                )
              : 0,
          avgLatency: Math.round(Number(recentStats?.avgLatency ?? 0)),
        },
      };
    }),

  /**
   * Get agent delegation events — which agents were invoked recently
   */
  getAgentDelegationFeed: protectedProcedure
    .input(
      z
        .object({
          limit: z.number().min(1).max(100).default(30),
        })
        .optional()
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const limit = input?.limit ?? 30;

      // Get recent decisions grouped by caller to show delegation events
      const delegations = await db
        .select({
          id: llmDecisionLog.id,
          engagementId: llmDecisionLog.engagementId,
          phase: llmDecisionLog.phase,
          caller: llmDecisionLog.caller,
          decision: llmDecisionLog.decision,
          outcome: llmDecisionLog.outcome,
          stealthScore: llmDecisionLog.stealthScore,
          latencyMs: llmDecisionLog.latencyMs,
          createdAt: llmDecisionLog.createdAt,
        })
        .from(llmDecisionLog)
        .orderBy(desc(llmDecisionLog.createdAt))
        .limit(limit);

      // Get delegation frequency per agent (last 24h)
      const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000)
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      const agentFrequency = await db
        .select({
          caller: llmDecisionLog.caller,
          count: sql<number>`COUNT(*)`,
          successCount: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, last24h))
        .groupBy(llmDecisionLog.caller)
        .orderBy(sql`count DESC`)
        .limit(15);

      return {
        delegations: delegations.map((d) => ({
          ...d,
          agentName: extractAgentName(d.caller),
          isSpecialist: d.caller.startsWith("specialist:"),
        })),
        agentFrequency: agentFrequency.map((a) => ({
          caller: a.caller,
          agentName: extractAgentName(a.caller),
          count: Number(a.count),
          successRate:
            Number(a.count) > 0
              ? Math.round(
                  (Number(a.successCount) / Number(a.count)) * 100
                )
              : 0,
        })),
      };
    }),

  /**
   * Get live timeline events for a specific engagement
   */
  getEngagementTimeline: protectedProcedure
    .input(
      z.object({
        engagementId: z.number(),
        limit: z.number().min(1).max(200).default(50),
      })
    )
    .query(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const db = await getDbRequired();

      const events = await db
        .select()
        .from(engagementTimelineEvents)
        .where(eq(engagementTimelineEvents.engagementId, input.engagementId))
        .orderBy(desc(engagementTimelineEvents.timestamp))
        .limit(input.limit);

      return {
        events: events.map((e) => ({
          ...e,
          timestamp: Number(e.timestamp),
        })),
        total: events.length,
      };
    }),
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractAgentName(caller: string): string {
  if (caller.startsWith("specialist:")) {
    return caller
      .replace("specialist:", "")
      .split("-")
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ");
  }
  if (caller.includes(".")) {
    return caller.split(".")[0].replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return caller.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
