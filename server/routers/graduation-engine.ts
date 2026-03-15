/**
 * Graduation Engine Router
 *
 * Aggregates LLM telemetry data to compute graduation readiness scores
 * for each LLM caller (task). Tasks that consistently succeed with low
 * latency and stable output patterns are candidates for "graduation" —
 * replacement with deterministic code.
 *
 * Graduation Tiers:
 *   Tier 1 (Ready):    ≥97% success, ≥500 calls, <5s avg latency
 *   Tier 2 (Near):     ≥90% success, ≥200 calls, <10s avg latency
 *   Tier 3 (Emerging): ≥80% success, ≥50 calls
 *   Tier 4 (Training): <80% success or <50 calls
 *   Tier 5 (Keep LLM): Tasks requiring creativity/reasoning (manual flag)
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { llmTelemetry } from "../../drizzle/schema";
import { sql, desc, and, gte } from "drizzle-orm";

// ─── Graduation Criteria ────────────────────────────────────────────────────

const GRADUATION_THRESHOLDS = {
  tier1: { successRate: 97, minCalls: 500, maxAvgLatencyMs: 5000, label: "Ready to Graduate" },
  tier2: { successRate: 90, minCalls: 200, maxAvgLatencyMs: 10000, label: "Near Graduation" },
  tier3: { successRate: 80, minCalls: 50, maxAvgLatencyMs: 30000, label: "Emerging Pattern" },
  tier4: { successRate: 0, minCalls: 0, maxAvgLatencyMs: Infinity, label: "Still Training" },
};

// Tasks that should always remain LLM-powered (creative/reasoning tasks)
const KEEP_LLM_TASKS = new Set([
  "operator-cockpit.chat",
  "engagement-orchestrator.opsDecision",
  "specialist:attack-planner",
  "functional-exploit-generator",
  "ai-attack-planner",
  "continuous-training.iteration",
  "training-lab.llmAnalysis",
  "training-lab.rerunAnalysis",
  "c2-actor-feedback-loop",
]);

// Estimated cost per 1K tokens (input + output blended)
const COST_PER_1K_TOKENS = 0.0015; // ~$1.50 per 1M tokens

interface GraduationCandidate {
  caller: string;
  totalCalls: number;
  successRate: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  totalTokens: number;
  estimatedMonthlyCost: number;
  tier: 1 | 2 | 3 | 4 | 5;
  tierLabel: string;
  graduationScore: number; // 0-100
  replacementType: string;
  firstSeen: string;
  lastSeen: string;
  errorRate: number;
  retryRate: number;
  avgTokensPerCall: number;
  outputStability: number; // 0-100, how consistent outputs are
}

function computeTier(
  caller: string,
  successRate: number,
  totalCalls: number,
  avgLatencyMs: number
): { tier: 1 | 2 | 3 | 4 | 5; label: string } {
  if (KEEP_LLM_TASKS.has(caller)) {
    return { tier: 5, label: "Keep LLM (Creative/Reasoning)" };
  }
  if (
    successRate >= GRADUATION_THRESHOLDS.tier1.successRate &&
    totalCalls >= GRADUATION_THRESHOLDS.tier1.minCalls &&
    avgLatencyMs <= GRADUATION_THRESHOLDS.tier1.maxAvgLatencyMs
  ) {
    return { tier: 1, label: GRADUATION_THRESHOLDS.tier1.label };
  }
  if (
    successRate >= GRADUATION_THRESHOLDS.tier2.successRate &&
    totalCalls >= GRADUATION_THRESHOLDS.tier2.minCalls &&
    avgLatencyMs <= GRADUATION_THRESHOLDS.tier2.maxAvgLatencyMs
  ) {
    return { tier: 2, label: GRADUATION_THRESHOLDS.tier2.label };
  }
  if (
    successRate >= GRADUATION_THRESHOLDS.tier3.successRate &&
    totalCalls >= GRADUATION_THRESHOLDS.tier3.minCalls
  ) {
    return { tier: 3, label: GRADUATION_THRESHOLDS.tier3.label };
  }
  return { tier: 4, label: GRADUATION_THRESHOLDS.tier4.label };
}

function computeGraduationScore(
  successRate: number,
  totalCalls: number,
  avgLatencyMs: number,
  retryRate: number,
  outputStability: number
): number {
  // Weighted score: success rate (40%), call volume (20%), latency (15%), retry rate (10%), stability (15%)
  const successScore = Math.min(successRate, 100) * 0.4;
  const volumeScore = Math.min(totalCalls / 500, 1) * 100 * 0.2;
  const latencyScore = Math.max(0, 100 - (avgLatencyMs / 300)) * 0.15;
  const retryScore = Math.max(0, 100 - retryRate * 100) * 0.1;
  const stabilityScore = outputStability * 0.15;
  return Math.min(100, Math.round(successScore + volumeScore + latencyScore + retryScore + stabilityScore));
}

function inferReplacementType(caller: string): string {
  const c = caller.toLowerCase();
  if (c.includes("scan") || c.includes("analysis") || c.includes("analyst")) return "Rule Engine + Pattern Matching";
  if (c.includes("vuln") || c.includes("verif")) return "Scoring Model + Lookup Table";
  if (c.includes("threat") || c.includes("mapper")) return "Knowledge Base Lookup";
  if (c.includes("domain") || c.includes("intel")) return "WHOIS/DNS Parser + Rules";
  if (c.includes("zap") || c.includes("config")) return "Template Engine";
  if (c.includes("ops") || c.includes("decider")) return "Decision Tree";
  if (c.includes("exploit")) return "Exploit Metadata DB";
  if (c.includes("training") || c.includes("learning")) return "Fine-tuned Small Model";
  return "Deterministic Logic";
}

export const graduationEngineRouter = router({
  /**
   * Get all LLM callers with graduation readiness analysis
   */
  getCandidates: protectedProcedure
    .input(
      z.object({
        windowDays: z.number().min(1).max(90).default(30),
        tierFilter: z.number().min(1).max(5).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const days = input?.windowDays ?? 30;
      const db = getDbRequired();
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      const rows = await db
        .select({
          caller: llmTelemetry.caller,
          totalCalls: sql<number>`COUNT(*)`.as("total_calls"),
          successCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' OR ${llmTelemetry.llmStatus} = 'retried_success' THEN 1 ELSE 0 END)`.as("success_count"),
          errorCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`.as("error_count"),
          timeoutCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'timeout' THEN 1 ELSE 0 END)`.as("timeout_count"),
          retryCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.retryCount} > 0 THEN 1 ELSE 0 END)`.as("retry_count"),
          avgLatencyMs: sql<number>`AVG(${llmTelemetry.latencyMs})`.as("avg_latency"),
          p95LatencyMs: sql<number>`MAX(${llmTelemetry.latencyMs})`.as("p95_latency"),
          totalTokensIn: sql<number>`SUM(COALESCE(${llmTelemetry.tokensIn}, 0))`.as("total_tokens_in"),
          totalTokensOut: sql<number>`SUM(COALESCE(${llmTelemetry.tokensOut}, 0))`.as("total_tokens_out"),
          firstSeen: sql<string>`MIN(${llmTelemetry.calledAt})`.as("first_seen"),
          lastSeen: sql<string>`MAX(${llmTelemetry.calledAt})`.as("last_seen"),
          // Output stability: low stddev in token output = high stability
          tokenOutStddev: sql<number>`COALESCE(STDDEV_SAMP(COALESCE(${llmTelemetry.tokensOut}, 0)), 0)`.as("token_out_stddev"),
          tokenOutAvg: sql<number>`AVG(COALESCE(${llmTelemetry.tokensOut}, 0))`.as("token_out_avg"),
        })
        .from(llmTelemetry)
        .where(gte(llmTelemetry.calledAt, cutoff.toISOString().slice(0, 19).replace("T", " ")))
        .groupBy(llmTelemetry.caller)
        .orderBy(desc(sql`total_calls`));

      const candidates: GraduationCandidate[] = rows.map((row) => {
        const totalCalls = Number(row.totalCalls) || 0;
        const successCount = Number(row.successCount) || 0;
        const errorCount = Number(row.errorCount) || 0;
        const retryCount = Number(row.retryCount) || 0;
        const avgLatencyMs = Math.round(Number(row.avgLatencyMs) || 0);
        const p95LatencyMs = Math.round(Number(row.p95LatencyMs) || avgLatencyMs * 1.5);
        const totalTokensIn = Number(row.totalTokensIn) || 0;
        const totalTokensOut = Number(row.totalTokensOut) || 0;
        const totalTokens = totalTokensIn + totalTokensOut;
        const successRate = totalCalls > 0 ? (successCount / totalCalls) * 100 : 0;
        const errorRate = totalCalls > 0 ? (errorCount / totalCalls) * 100 : 0;
        const retryRate = totalCalls > 0 ? retryCount / totalCalls : 0;

        // Output stability: coefficient of variation (lower = more stable)
        const tokenOutStddev = Number(row.tokenOutStddev) || 0;
        const tokenOutAvg = Number(row.tokenOutAvg) || 1;
        const cv = tokenOutAvg > 0 ? tokenOutStddev / tokenOutAvg : 1;
        const outputStability = Math.max(0, Math.min(100, Math.round((1 - Math.min(cv, 1)) * 100)));

        // Extrapolate monthly cost from the window
        const dailyTokens = totalTokens / days;
        const estimatedMonthlyCost = (dailyTokens * 30 / 1000) * COST_PER_1K_TOKENS;

        const { tier, label: tierLabel } = computeTier(row.caller, successRate, totalCalls, avgLatencyMs);
        const graduationScore = tier === 5 ? 0 : computeGraduationScore(successRate, totalCalls, avgLatencyMs, retryRate, outputStability);

        return {
          caller: row.caller,
          totalCalls,
          successRate: Math.round(successRate * 10) / 10,
          avgLatencyMs,
          p95LatencyMs,
          totalTokens,
          estimatedMonthlyCost: Math.round(estimatedMonthlyCost * 100) / 100,
          tier,
          tierLabel,
          graduationScore,
          replacementType: inferReplacementType(row.caller),
          firstSeen: row.firstSeen || "",
          lastSeen: row.lastSeen || "",
          errorRate: Math.round(errorRate * 10) / 10,
          retryRate: Math.round(retryRate * 1000) / 10,
          avgTokensPerCall: totalCalls > 0 ? Math.round(totalTokens / totalCalls) : 0,
          outputStability,
        };
      });

      // Apply tier filter if specified
      const filtered = input?.tierFilter
        ? candidates.filter((c) => c.tier === input.tierFilter)
        : candidates;

      return {
        candidates: filtered,
        summary: {
          totalCallers: candidates.length,
          tier1Count: candidates.filter((c) => c.tier === 1).length,
          tier2Count: candidates.filter((c) => c.tier === 2).length,
          tier3Count: candidates.filter((c) => c.tier === 3).length,
          tier4Count: candidates.filter((c) => c.tier === 4).length,
          tier5Count: candidates.filter((c) => c.tier === 5).length,
          totalMonthlyCost: Math.round(candidates.reduce((s, c) => s + c.estimatedMonthlyCost, 0) * 100) / 100,
          potentialSavings: Math.round(
            candidates
              .filter((c) => c.tier <= 2)
              .reduce((s, c) => s + c.estimatedMonthlyCost, 0) * 100
          ) / 100,
          totalCalls: candidates.reduce((s, c) => s + c.totalCalls, 0),
          totalTokens: candidates.reduce((s, c) => s + c.totalTokens, 0),
        },
        thresholds: GRADUATION_THRESHOLDS,
        windowDays: days,
      };
    }),

  /**
   * Get graduation trend over time — how many callers are in each tier per week
   */
  getTrend: protectedProcedure
    .input(z.object({ weeks: z.number().min(1).max(12).default(8) }).optional())
    .query(async ({ input }) => {
      const weeks = input?.weeks ?? 8;
      const db = getDbRequired();

      // Build weekly snapshots
      const trend: Array<{
        weekStart: string;
        tier1: number;
        tier2: number;
        tier3: number;
        tier4: number;
        tier5: number;
        totalCost: number;
      }> = [];

      for (let w = weeks - 1; w >= 0; w--) {
        const weekEnd = new Date(Date.now() - w * 7 * 24 * 60 * 60 * 1000);
        const weekStart = new Date(weekEnd.getTime() - 7 * 24 * 60 * 60 * 1000);

        const rows = await db
          .select({
            caller: llmTelemetry.caller,
            totalCalls: sql<number>`COUNT(*)`,
            successCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} IN ('success','retried_success') THEN 1 ELSE 0 END)`,
            avgLatencyMs: sql<number>`AVG(${llmTelemetry.latencyMs})`,
            totalTokens: sql<number>`SUM(COALESCE(${llmTelemetry.tokensIn},0) + COALESCE(${llmTelemetry.tokensOut},0))`,
          })
          .from(llmTelemetry)
          .where(
            and(
              gte(llmTelemetry.calledAt, weekStart.toISOString().slice(0, 19).replace("T", " ")),
              sql`${llmTelemetry.calledAt} < ${weekEnd.toISOString().slice(0, 19).replace("T", " ")}`
            )
          )
          .groupBy(llmTelemetry.caller);

        let t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, cost = 0;
        for (const row of rows) {
          const tc = Number(row.totalCalls) || 0;
          const sc = Number(row.successCount) || 0;
          const sr = tc > 0 ? (sc / tc) * 100 : 0;
          const al = Number(row.avgLatencyMs) || 0;
          const tk = Number(row.totalTokens) || 0;
          const { tier } = computeTier(row.caller, sr, tc, al);
          if (tier === 1) t1++;
          else if (tier === 2) t2++;
          else if (tier === 3) t3++;
          else if (tier === 4) t4++;
          else t5++;
          cost += (tk / 1000) * COST_PER_1K_TOKENS;
        }

        trend.push({
          weekStart: weekStart.toISOString().slice(0, 10),
          tier1: t1,
          tier2: t2,
          tier3: t3,
          tier4: t4,
          tier5: t5,
          totalCost: Math.round(cost * 100) / 100,
        });
      }

      return { trend };
    }),

  /**
   * Get detailed caller history for a specific LLM task
   */
  getCallerDetail: protectedProcedure
    .input(z.object({ caller: z.string(), windowDays: z.number().min(1).max(90).default(30) }))
    .query(async ({ input }) => {
      const db = getDbRequired();
      const cutoff = new Date(Date.now() - input.windowDays * 24 * 60 * 60 * 1000);

      // Get daily aggregation
      const daily = await db
        .select({
          day: sql<string>`DATE(${llmTelemetry.calledAt})`.as("day"),
          calls: sql<number>`COUNT(*)`,
          successes: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} IN ('success','retried_success') THEN 1 ELSE 0 END)`,
          avgLatency: sql<number>`AVG(${llmTelemetry.latencyMs})`,
          tokens: sql<number>`SUM(COALESCE(${llmTelemetry.tokensIn},0) + COALESCE(${llmTelemetry.tokensOut},0))`,
          errors: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'error' THEN 1 ELSE 0 END)`,
        })
        .from(llmTelemetry)
        .where(
          and(
            sql`${llmTelemetry.caller} = ${input.caller}`,
            gte(llmTelemetry.calledAt, cutoff.toISOString().slice(0, 19).replace("T", " "))
          )
        )
        .groupBy(sql`DATE(${llmTelemetry.calledAt})`)
        .orderBy(sql`day`);

      // Get recent errors
      const recentErrors = await db
        .select({
          calledAt: llmTelemetry.calledAt,
          llmStatus: llmTelemetry.llmStatus,
          errorMessage: llmTelemetry.errorMessage,
          latencyMs: llmTelemetry.latencyMs,
          httpStatus: llmTelemetry.httpStatus,
        })
        .from(llmTelemetry)
        .where(
          and(
            sql`${llmTelemetry.caller} = ${input.caller}`,
            sql`${llmTelemetry.llmStatus} IN ('error','timeout')`,
            gte(llmTelemetry.calledAt, cutoff.toISOString().slice(0, 19).replace("T", " "))
          )
        )
        .orderBy(desc(llmTelemetry.calledAt))
        .limit(20);

      return {
        caller: input.caller,
        daily: daily.map((d) => ({
          day: d.day,
          calls: Number(d.calls) || 0,
          successes: Number(d.successes) || 0,
          avgLatency: Math.round(Number(d.avgLatency) || 0),
          tokens: Number(d.tokens) || 0,
          errors: Number(d.errors) || 0,
          successRate: Number(d.calls) > 0 ? Math.round((Number(d.successes) / Number(d.calls)) * 1000) / 10 : 0,
        })),
        recentErrors,
        isKeepLlm: KEEP_LLM_TASKS.has(input.caller),
        replacementType: inferReplacementType(input.caller),
      };
    }),
});
