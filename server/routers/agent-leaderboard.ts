/**
 * Agent Performance Leaderboard Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Ranks the 10 offensive security agents by delegation frequency, success rate,
 * average confidence score, token usage, and latency. Cross-references
 * agent_definitions with llm_telemetry and llm_decision_log tables.
 *
 * Provides:
 *   - Overall leaderboard with composite ranking
 *   - Per-agent performance detail (trends over time)
 *   - Agent comparison analytics
 *   - Delegation heatmap (which agents are invoked most by engagement phase)
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import {
  agentDefinitions,
  llmTelemetry,
  llmDecisionLog,
} from "../../drizzle/schema";
import { eq, desc, sql, and, gte, like } from "drizzle-orm";

// ─── Agent Performance Leaderboard Procedures ─────────────────────────────

export const agentLeaderboardRouter = router({
  /**
   * Get the full agent leaderboard — ranks all active agents by composite score.
   * Composite = 0.3 * successRate + 0.25 * avgConfidence + 0.2 * delegationFreq + 0.15 * avgLatencyScore + 0.1 * tokenEfficiency
   */
  getLeaderboard: protectedProcedure
    .input(
      z
        .object({
          windowDays: z.number().min(1).max(365).default(30),
          sortBy: z
            .enum([
              "composite",
              "delegations",
              "success_rate",
              "confidence",
              "latency",
              "tokens",
            ])
            .default("composite"),
        })
        .optional()
    )
    .query(async ({ input }) => {
      const days = input?.windowDays ?? 30;
      const sortBy = input?.sortBy ?? "composite";
      const db = await getDbRequired();
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      // Get all active agents
      const agents = await db
        .select()
        .from(agentDefinitions)
        .where(eq(agentDefinitions.status, "active"));

      // Get telemetry stats grouped by caller prefix
      const telemetryStats = await db
        .select({
          caller: llmTelemetry.caller,
          totalCalls: sql<number>`COUNT(*)`,
          successCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
          errorCalls: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          totalTokensIn: sql<number>`SUM(COALESCE(${llmTelemetry.tokensIn}, 0))`,
          totalTokensOut: sql<number>`SUM(COALESCE(${llmTelemetry.tokensOut}, 0))`,
          minLatency: sql<number>`MIN(${llmTelemetry.latencyMs})`,
          maxLatency: sql<number>`MAX(${llmTelemetry.latencyMs})`,
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.calledAt, cutoff))
        .groupBy(llmTelemetry.caller);

      // Get decision log stats grouped by caller
      const decisionStats = await db
        .select({
          caller: llmDecisionLog.caller,
          totalDecisions: sql<number>`COUNT(*)`,
          successDecisions: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
          failedDecisions: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
          partialDecisions: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'partial' THEN 1 ELSE 0 END)`,
          avgStealthScore: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
          avgDecisionLatency: sql<number>`AVG(${llmDecisionLog.latencyMs})`,
          totalTokensUsed: sql<number>`SUM(COALESCE(${llmDecisionLog.tokensUsed}, 0))`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff))
        .groupBy(llmDecisionLog.caller);

      // Map telemetry and decision data to agents by llmCallerPrefix
      const leaderboard = agents.map((agent) => {
        const prefix = agent.llmCallerPrefix || agent.agentId;

        // Aggregate telemetry for this agent (match by prefix)
        const matchedTelemetry = telemetryStats.filter(
          (t) => t.caller && t.caller.startsWith(prefix)
        );
        const matchedDecisions = decisionStats.filter(
          (d) => d.caller && d.caller.startsWith(prefix)
        );

        const totalCalls = matchedTelemetry.reduce(
          (s, t) => s + Number(t.totalCalls),
          0
        );
        const successCalls = matchedTelemetry.reduce(
          (s, t) => s + Number(t.successCalls),
          0
        );
        const errorCalls = matchedTelemetry.reduce(
          (s, t) => s + Number(t.errorCalls),
          0
        );
        const avgLatency =
          totalCalls > 0
            ? matchedTelemetry.reduce(
                (s, t) => s + Number(t.avgLatency) * Number(t.totalCalls),
                0
              ) / totalCalls
            : 0;
        const totalTokensIn = matchedTelemetry.reduce(
          (s, t) => s + Number(t.totalTokensIn),
          0
        );
        const totalTokensOut = matchedTelemetry.reduce(
          (s, t) => s + Number(t.totalTokensOut),
          0
        );

        const totalDecisions = matchedDecisions.reduce(
          (s, d) => s + Number(d.totalDecisions),
          0
        );
        const successDecisions = matchedDecisions.reduce(
          (s, d) => s + Number(d.successDecisions),
          0
        );
        const failedDecisions = matchedDecisions.reduce(
          (s, d) => s + Number(d.failedDecisions),
          0
        );
        const partialDecisions = matchedDecisions.reduce(
          (s, d) => s + Number(d.partialDecisions),
          0
        );
        const avgStealthScore =
          totalDecisions > 0
            ? matchedDecisions.reduce(
                (s, d) =>
                  s +
                  (Number(d.avgStealthScore) || 0) *
                    Number(d.totalDecisions),
                0
              ) / totalDecisions
            : 0;
        const totalTokensUsed = matchedDecisions.reduce(
          (s, d) => s + Number(d.totalTokensUsed),
          0
        );

        // Compute derived metrics
        const delegations = totalCalls + totalDecisions;
        const successRate =
          delegations > 0
            ? ((successCalls + successDecisions) / delegations) * 100
            : 0;
        const avgConfidence = avgStealthScore * 100; // stealth score is 0-1, convert to 0-100

        // Latency score: lower is better, normalize to 0-100 (5000ms = 0, 0ms = 100)
        const latencyScore = Math.max(
          0,
          Math.min(100, 100 - (avgLatency / 5000) * 100)
        );

        // Token efficiency: lower tokens per decision is better
        const tokensPerDecision =
          delegations > 0
            ? (totalTokensIn + totalTokensOut + totalTokensUsed) / delegations
            : 0;
        const tokenEfficiency = Math.max(
          0,
          Math.min(100, 100 - (tokensPerDecision / 10000) * 100)
        );

        // Composite score
        const composite =
          0.3 * successRate +
          0.25 * avgConfidence +
          0.2 * Math.min(100, (delegations / 10) * 100) + // delegation frequency normalized
          0.15 * latencyScore +
          0.1 * tokenEfficiency;

        return {
          agentId: agent.agentId,
          name: agent.name,
          category: agent.category,
          priority: agent.priority,
          status: agent.status,
          mitreTactics: agent.mitreTactics || [],
          // Raw metrics
          delegations,
          totalCalls,
          totalDecisions,
          successCalls,
          errorCalls,
          successDecisions,
          failedDecisions,
          partialDecisions,
          // Computed metrics
          successRate: Math.round(successRate * 10) / 10,
          avgConfidence: Math.round(avgConfidence * 10) / 10,
          avgLatencyMs: Math.round(avgLatency),
          latencyScore: Math.round(latencyScore * 10) / 10,
          tokenEfficiency: Math.round(tokenEfficiency * 10) / 10,
          totalTokens: totalTokensIn + totalTokensOut + totalTokensUsed,
          tokensPerDecision: Math.round(tokensPerDecision),
          avgStealthScore: Math.round(avgStealthScore * 100) / 100,
          compositeScore: Math.round(composite * 10) / 10,
        };
      });

      // Sort by requested field
      const sortFn: Record<string, (a: any, b: any) => number> = {
        composite: (a, b) => b.compositeScore - a.compositeScore,
        delegations: (a, b) => b.delegations - a.delegations,
        success_rate: (a, b) => b.successRate - a.successRate,
        confidence: (a, b) => b.avgConfidence - a.avgConfidence,
        latency: (a, b) => a.avgLatencyMs - b.avgLatencyMs, // lower is better
        tokens: (a, b) => a.tokensPerDecision - b.tokensPerDecision, // lower is better
      };
      leaderboard.sort(sortFn[sortBy] || sortFn.composite);

      // Assign ranks
      const ranked = leaderboard.map((entry, idx) => ({
        rank: idx + 1,
        ...entry,
      }));

      // Summary stats
      const totalDelegations = ranked.reduce((s, r) => s + r.delegations, 0);
      const totalTokensAll = ranked.reduce((s, r) => s + r.totalTokens, 0);
      const avgSuccessRate =
        ranked.length > 0
          ? ranked.reduce((s, r) => s + r.successRate, 0) / ranked.length
          : 0;

      return {
        leaderboard: ranked,
        summary: {
          totalAgents: ranked.length,
          totalDelegations,
          totalTokens: totalTokensAll,
          avgSuccessRate: Math.round(avgSuccessRate * 10) / 10,
          windowDays: days,
          topAgent: ranked[0]?.name || "N/A",
        },
      };
    }),

  /**
   * Get detailed performance for a single agent over time (daily breakdown)
   */
  getAgentPerformance: protectedProcedure
    .input(
      z.object({
        agentId: z.string(),
        windowDays: z.number().min(1).max(365).default(30),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const cutoff = new Date(
        Date.now() - input.windowDays * 24 * 60 * 60 * 1000
      )
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      // Get agent definition
      const [agent] = await db
        .select()
        .from(agentDefinitions)
        .where(eq(agentDefinitions.agentId, input.agentId))
        .limit(1);

      if (!agent) throw new Error(`Agent ${input.agentId} not found`);

      const prefix = agent.llmCallerPrefix || agent.agentId;

      // Daily telemetry breakdown
      const dailyTelemetry = await db
        .select({
          day: sql<string>`DATE(${llmTelemetry.calledAt})`.as("day"),
          calls: sql<number>`COUNT(*)`,
          successes: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
          errors: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          tokensIn: sql<number>`SUM(COALESCE(${llmTelemetry.tokensIn}, 0))`,
          tokensOut: sql<number>`SUM(COALESCE(${llmTelemetry.tokensOut}, 0))`,
        })
        .from(llmTelemetry)
        .where(
          and(
            gte(llmTelemetry.calledAt, cutoff),
            like(llmTelemetry.caller, `${prefix}%`)
          )
        )
        .groupBy(sql`DATE(${llmTelemetry.calledAt})`)
        .orderBy(sql`day`);

      // Daily decision breakdown
      const dailyDecisions = await db
        .select({
          day: sql<string>`DATE(${llmDecisionLog.createdAt})`.as("day"),
          decisions: sql<number>`COUNT(*)`,
          successes: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'success' THEN 1 ELSE 0 END)`,
          failures: sql<number>`SUM(CASE WHEN ${llmDecisionLog.outcome} = 'failure' THEN 1 ELSE 0 END)`,
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
          tokensUsed: sql<number>`SUM(COALESCE(${llmDecisionLog.tokensUsed}, 0))`,
        })
        .from(llmDecisionLog)
        .where(
          and(
            gte(llmDecisionLog.createdAt, cutoff),
            like(llmDecisionLog.caller, `${prefix}%`)
          )
        )
        .groupBy(sql`DATE(${llmDecisionLog.createdAt})`)
        .orderBy(sql`day`);

      // Recent decisions (last 20)
      const recentDecisions = await db
        .select({
          id: llmDecisionLog.id,
          engagementId: llmDecisionLog.engagementId,
          phase: llmDecisionLog.phase,
          decision: llmDecisionLog.decision,
          outcome: llmDecisionLog.outcome,
          stealthScore: llmDecisionLog.stealthScore,
          latencyMs: llmDecisionLog.latencyMs,
          tokensUsed: llmDecisionLog.tokensUsed,
          createdAt: llmDecisionLog.createdAt,
        })
        .from(llmDecisionLog)
        .where(
          and(
            gte(llmDecisionLog.createdAt, cutoff),
            like(llmDecisionLog.caller, `${prefix}%`)
          )
        )
        .orderBy(desc(llmDecisionLog.createdAt))
        .limit(20);

      // Phase distribution
      const phaseDistribution = await db
        .select({
          phase: llmDecisionLog.phase,
          count: sql<number>`COUNT(*)`,
          avgStealth: sql<number>`AVG(${llmDecisionLog.stealthScore})`,
        })
        .from(llmDecisionLog)
        .where(
          and(
            gte(llmDecisionLog.createdAt, cutoff),
            like(llmDecisionLog.caller, `${prefix}%`)
          )
        )
        .groupBy(llmDecisionLog.phase)
        .orderBy(sql`count DESC`);

      return {
        agent: {
          agentId: agent.agentId,
          name: agent.name,
          category: agent.category,
          persona: agent.persona,
          mission: agent.mission,
          priority: agent.priority,
          mitreTactics: agent.mitreTactics || [],
          toolAccess: agent.toolAccess || [],
        },
        dailyTelemetry: dailyTelemetry.map((d) => ({
          day: d.day,
          calls: Number(d.calls),
          successes: Number(d.successes),
          errors: Number(d.errors),
          successRate:
            Number(d.calls) > 0
              ? Math.round(
                  (Number(d.successes) / Number(d.calls)) * 100 * 10
                ) / 10
              : 0,
          avgLatency: Math.round(Number(d.avgLatency)),
          tokensIn: Number(d.tokensIn),
          tokensOut: Number(d.tokensOut),
        })),
        dailyDecisions: dailyDecisions.map((d) => ({
          day: d.day,
          decisions: Number(d.decisions),
          successes: Number(d.successes),
          failures: Number(d.failures),
          avgStealth: Math.round((Number(d.avgStealth) || 0) * 100) / 100,
          tokensUsed: Number(d.tokensUsed),
        })),
        recentDecisions,
        phaseDistribution: phaseDistribution.map((p) => ({
          phase: p.phase,
          count: Number(p.count),
          avgStealth: Math.round((Number(p.avgStealth) || 0) * 100) / 100,
        })),
        windowDays: input.windowDays,
      };
    }),

  /**
   * Get delegation heatmap — which agents are invoked most per engagement phase
   */
  getDelegationHeatmap: protectedProcedure
    .input(
      z
        .object({
          windowDays: z.number().min(1).max(365).default(30),
        })
        .optional()
    )
    .query(async ({ input }) => {
      const days = input?.windowDays ?? 30;
      const db = await getDbRequired();
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      // Get all active agents
      const agents = await db
        .select({
          agentId: agentDefinitions.agentId,
          name: agentDefinitions.name,
          llmCallerPrefix: agentDefinitions.llmCallerPrefix,
        })
        .from(agentDefinitions)
        .where(eq(agentDefinitions.status, "active"));

      // Get phase-caller counts from decision log
      const phaseCaller = await db
        .select({
          phase: llmDecisionLog.phase,
          caller: llmDecisionLog.caller,
          count: sql<number>`COUNT(*)`,
        })
        .from(llmDecisionLog)
        .where(gte(llmDecisionLog.createdAt, cutoff))
        .groupBy(llmDecisionLog.phase, llmDecisionLog.caller);

      // Build heatmap: phases × agents
      const phases = [...new Set(phaseCaller.map((pc) => pc.phase))].sort();
      const heatmap: Array<{
        phase: string;
        agents: Array<{ agentId: string; name: string; count: number }>;
        total: number;
      }> = [];

      for (const phase of phases) {
        const phaseEntries = phaseCaller.filter((pc) => pc.phase === phase);
        const agentCounts = agents.map((agent) => {
          const prefix = agent.llmCallerPrefix || agent.agentId;
          const matched = phaseEntries.filter(
            (pe) => pe.caller && pe.caller.startsWith(prefix)
          );
          return {
            agentId: agent.agentId,
            name: agent.name,
            count: matched.reduce((s, m) => s + Number(m.count), 0),
          };
        });
        heatmap.push({
          phase,
          agents: agentCounts.filter((ac) => ac.count > 0),
          total: agentCounts.reduce((s, ac) => s + ac.count, 0),
        });
      }

      return {
        heatmap,
        phases,
        agents: agents.map((a) => ({ agentId: a.agentId, name: a.name })),
        windowDays: days,
      };
    }),
});
