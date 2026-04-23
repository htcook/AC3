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
import { llmTelemetry, llmTrainingExamples } from "../../drizzle/schema";
import { sql, desc, and, gte, like, eq } from "drizzle-orm";

// ─── Graduation Criteria ────────────────────────────────────────────────────

const GRADUATION_THRESHOLDS = {
  tier1: { successRate: 97, minCalls: 500, maxAvgLatencyMs: 5000, label: "Ready to Graduate" },
  tier2: { successRate: 90, minCalls: 200, maxAvgLatencyMs: 10000, label: "Near Graduation" },
  tier3: { successRate: 80, minCalls: 50, maxAvgLatencyMs: 30000, label: "Emerging Pattern" },
  tier4: { successRate: 0, minCalls: 0, maxAvgLatencyMs: Infinity, label: "Still Training" },
};

/**
 * Elevated graduation thresholds for exploit-category callers.
 *
 * Exploit-generating LLM callers operate in a higher-risk domain where
 * false positives (bad exploit code) can cause real damage.
 *
 * Exploit-category callers face elevated thresholds that reduce the
 * tolerated failure rate from 3% to 1% at Tier 1 and double the minimum
 * call volume (1,000 vs 500) to ensure statistical significance:
 *   - Tier 1: 99% success rate (vs 97%) with 1000 calls (vs 500)
 *   - Tier 2: 95% success rate (vs 90%) with 500 calls (vs 200)
 *   - Tier 3: 90% success rate (vs 80%) with 100 calls (vs 50)
 *
 * IMPORTANT: Graduation of an exploit-generating caller does NOT bypass
 * the quarantine queue for its outputs. Graduated code still produces
 * outputs that feed the quarantine queue and require human review before
 * entering the approved catalog. Graduation replaces the LLM caller with
 * deterministic code; the quarantine queue gates the *outputs* of that
 * code, not the *caller* itself.
 */
const EXPLOIT_GRADUATION_THRESHOLDS = {
  tier1: { successRate: 99, minCalls: 1000, maxAvgLatencyMs: 5000, label: "Ready to Graduate (Exploit — Elevated Bar)" },
  tier2: { successRate: 95, minCalls: 500, maxAvgLatencyMs: 10000, label: "Near Graduation (Exploit — Elevated Bar)" },
  tier3: { successRate: 90, minCalls: 100, maxAvgLatencyMs: 30000, label: "Emerging Pattern (Exploit — Elevated Bar)" },
  tier4: { successRate: 0, minCalls: 0, maxAvgLatencyMs: Infinity, label: "Still Training" },
};

/** Callers that use the elevated exploit graduation thresholds */
const EXPLOIT_CATEGORY_CALLERS = new Set([
  'functional-exploit-generator',
  'exploit-recipe-engine',
  'enhanced-exploit-orchestration',
  'nexus-pipeline.exploit',
  'specialist:exploit-selector',
]);

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

  // Use elevated thresholds for exploit-category callers
  const thresholds = EXPLOIT_CATEGORY_CALLERS.has(caller)
    ? EXPLOIT_GRADUATION_THRESHOLDS
    : GRADUATION_THRESHOLDS;

  if (
    successRate >= thresholds.tier1.successRate &&
    totalCalls >= thresholds.tier1.minCalls &&
    avgLatencyMs <= thresholds.tier1.maxAvgLatencyMs
  ) {
    return { tier: 1, label: thresholds.tier1.label };
  }
  if (
    successRate >= thresholds.tier2.successRate &&
    totalCalls >= thresholds.tier2.minCalls &&
    avgLatencyMs <= thresholds.tier2.maxAvgLatencyMs
  ) {
    return { tier: 2, label: thresholds.tier2.label };
  }
  if (
    successRate >= thresholds.tier3.successRate &&
    totalCalls >= thresholds.tier3.minCalls
  ) {
    return { tier: 3, label: thresholds.tier3.label };
  }
  return { tier: 4, label: thresholds.tier4.label };
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
  if (c.includes("zap")) return "ZAP API + Rule Engine";
  if (c.includes("burp") || c.includes("burpsuite")) return "Burp REST API + Scan Profiles";
  if (c.includes("config")) return "Template Engine";
  if (c.includes("ops") || c.includes("decider")) return "Decision Tree";
  if (c.includes("exploit")) return "Exploit Metadata DB";
  if (c.includes("training") || c.includes("learning")) return "Fine-tuned Small Model";
  return "Deterministic Logic";
}

// ─── Graduation Score Drift Detection ────────────────────────────────────────

/**
 * Drift Detection for Graduation Scores
 *
 * Detects two adversarial patterns in graduation telemetry:
 *
 * 1. Adversarial Target Responses: A compromised or adversarial target
 *    environment feeds scan results that look like success but are actually
 *    the target gaming the LLM's success criteria. Detected by comparing
 *    success rates across different target environments — a caller that
 *    succeeds 100% against one target but 60% against others is suspicious.
 *
 * 2. Slow-Drift Poisoning: An attacker gradually inflates success rates
 *    across many engagements to push an exploit-category caller toward
 *    graduation. Detected by computing a rolling z-score on weekly success
 *    rates — a sustained upward drift beyond 2 standard deviations triggers
 *    an alert.
 *
 * Both detections operate on server-side telemetry data and cannot be
 * influenced by client-submitted inputs.
 */

interface DriftAlert {
  caller: string;
  alertType: 'adversarial_target_success' | 'slow_drift_poisoning' | 'sudden_spike';
  severity: 'warning' | 'critical';
  description: string;
  evidence: {
    metric: string;
    currentValue: number;
    baselineValue: number;
    threshold: number;
    windowDays: number;
  };
  detectedAt: number;
}

/**
 * Detect adversarial target responses by comparing per-target success rates.
 * A caller with anomalously high success against specific targets (vs its
 * baseline across all targets) may indicate the target is gaming the results.
 *
 * Detection criteria:
 *   - Caller has ≥50 calls across ≥3 distinct targets
 *   - Per-target success rate exceeds overall average by >15 percentage points
 *   - The anomalous target accounts for >20% of total calls
 */
function detectAdversarialTargetSuccess(
  callerStats: Array<{ target: string; calls: number; successes: number }>,
  caller: string
): DriftAlert | null {
  const totalCalls = callerStats.reduce((s, t) => s + t.calls, 0);
  const totalSuccesses = callerStats.reduce((s, t) => s + t.successes, 0);
  const overallRate = totalCalls > 0 ? (totalSuccesses / totalCalls) * 100 : 0;
  const distinctTargets = callerStats.length;

  if (totalCalls < 50 || distinctTargets < 3) return null;

  for (const target of callerStats) {
    const targetRate = target.calls > 0 ? (target.successes / target.calls) * 100 : 0;
    const callShare = target.calls / totalCalls;
    const deviation = targetRate - overallRate;

    if (deviation > 15 && callShare > 0.2 && target.calls >= 10) {
      return {
        caller,
        alertType: 'adversarial_target_success',
        severity: deviation > 25 ? 'critical' : 'warning',
        description:
          `Caller "${caller}" shows ${targetRate.toFixed(1)}% success rate against target ` +
          `"${target.target}" vs ${overallRate.toFixed(1)}% overall (${deviation.toFixed(1)}pp deviation). ` +
          `This target accounts for ${(callShare * 100).toFixed(0)}% of calls. ` +
          `Possible adversarial target response gaming.`,
        evidence: {
          metric: 'per_target_success_rate_deviation',
          currentValue: targetRate,
          baselineValue: overallRate,
          threshold: 15,
          windowDays: 30,
        },
        detectedAt: Date.now(),
      };
    }
  }
  return null;
}

/**
 * Detect slow-drift poisoning by computing rolling z-scores on weekly
 * success rates. A sustained upward drift (z-score > 2.0 for ≥3 consecutive
 * weeks) triggers an alert.
 *
 * Detection criteria:
 *   - ≥6 weeks of data with ≥10 calls per week
 *   - Rolling z-score of weekly success rate exceeds 2.0
 *   - Drift is sustained for ≥3 consecutive weeks
 *   - For exploit-category callers, threshold is lowered to z-score > 1.5
 */
function detectSlowDriftPoisoning(
  weeklyRates: Array<{ week: string; successRate: number; calls: number }>,
  caller: string
): DriftAlert | null {
  // Need at least 6 weeks of meaningful data
  const validWeeks = weeklyRates.filter(w => w.calls >= 10);
  if (validWeeks.length < 6) return null;

  // Compute mean and stddev of success rates
  const rates = validWeeks.map(w => w.successRate);
  const mean = rates.reduce((s, r) => s + r, 0) / rates.length;
  const variance = rates.reduce((s, r) => s + Math.pow(r - mean, 2), 0) / rates.length;
  const stddev = Math.sqrt(variance);

  if (stddev < 0.5) return null; // Too little variation to detect drift

  // Use lower threshold for exploit-category callers
  const zThreshold = EXPLOIT_CATEGORY_CALLERS.has(caller) ? 1.5 : 2.0;
  const consecutiveThreshold = 3;

  // Check last N weeks for sustained upward drift
  let consecutiveHigh = 0;
  let peakZScore = 0;
  for (let i = Math.max(0, validWeeks.length - 8); i < validWeeks.length; i++) {
    const zScore = (validWeeks[i].successRate - mean) / stddev;
    if (zScore > zThreshold) {
      consecutiveHigh++;
      peakZScore = Math.max(peakZScore, zScore);
    } else {
      consecutiveHigh = 0;
    }
  }

  if (consecutiveHigh >= consecutiveThreshold) {
    const recentRate = validWeeks[validWeeks.length - 1].successRate;
    return {
      caller,
      alertType: 'slow_drift_poisoning',
      severity: peakZScore > 3.0 ? 'critical' : 'warning',
      description:
        `Caller "${caller}" shows sustained upward drift in success rate: ` +
        `${consecutiveHigh} consecutive weeks above z-score ${zThreshold.toFixed(1)} ` +
        `(peak z=${peakZScore.toFixed(2)}). Current rate: ${recentRate.toFixed(1)}%, ` +
        `historical mean: ${mean.toFixed(1)}%. Possible slow-drift poisoning.`,
      evidence: {
        metric: 'weekly_success_rate_zscore',
        currentValue: peakZScore,
        baselineValue: mean,
        threshold: zThreshold,
        windowDays: validWeeks.length * 7,
      },
      detectedAt: Date.now(),
    };
  }

  return null;
}

/**
 * Detect sudden success rate spikes that could indicate telemetry manipulation.
 * A week-over-week increase of >20 percentage points is flagged.
 */
function detectSuddenSpike(
  weeklyRates: Array<{ week: string; successRate: number; calls: number }>,
  caller: string
): DriftAlert | null {
  const validWeeks = weeklyRates.filter(w => w.calls >= 10);
  if (validWeeks.length < 2) return null;

  const current = validWeeks[validWeeks.length - 1];
  const previous = validWeeks[validWeeks.length - 2];
  const spike = current.successRate - previous.successRate;

  if (spike > 20) {
    return {
      caller,
      alertType: 'sudden_spike',
      severity: spike > 35 ? 'critical' : 'warning',
      description:
        `Caller "${caller}" success rate jumped ${spike.toFixed(1)}pp in one week ` +
        `(${previous.successRate.toFixed(1)}% → ${current.successRate.toFixed(1)}%). ` +
        `Possible telemetry manipulation or environmental change.`,
      evidence: {
        metric: 'week_over_week_success_rate_change',
        currentValue: current.successRate,
        baselineValue: previous.successRate,
        threshold: 20,
        windowDays: 14,
      },
      detectedAt: Date.now(),
    };
  }
  return null;
}

// Export for testing
export {
  detectAdversarialTargetSuccess,
  detectSlowDriftPoisoning,
  detectSuddenSpike,
  EXPLOIT_CATEGORY_CALLERS,
  EXPLOIT_GRADUATION_THRESHOLDS,
  GRADUATION_THRESHOLDS,
  computeTier,
  type DriftAlert,
};

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
      const db = await getDbRequired();
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
      const db = await getDbRequired();

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
   * Training Data Quality Gate — uses approved/rejected ratios from the
   * training data review pipeline as quality signals for graduation decisions.
   *
   * For each LLM caller (model), computes:
   *   - Total training examples and review completion rate
   *   - Approval rate (approved / (approved + rejected))
   *   - Average quality score of approved examples
   *   - Quality gate verdict: PASS / WARN / FAIL / INSUFFICIENT
   *
   * Quality Gate Thresholds:
   *   PASS:         ≥80% approval rate, ≥50 reviewed examples, avg score ≥0.75
   *   WARN:         ≥60% approval rate, ≥20 reviewed examples, avg score ≥0.5
   *   FAIL:         <60% approval rate or avg score <0.5
   *   INSUFFICIENT: <20 reviewed examples
   */
  getTrainingQualityGates: protectedProcedure
    .input(
      z.object({
        callerFilter: z.string().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();

      // Get per-model review stats from training examples
      const conditions: any[] = [];
      if (input?.callerFilter) {
        conditions.push(like(llmTrainingExamples.model, `%${input.callerFilter}%`));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const modelStats = await db
        .select({
          model: llmTrainingExamples.model,
          total: sql<number>`COUNT(*)`,
          approved: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'approved' THEN 1 ELSE 0 END)`,
          rejected: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'rejected' THEN 1 ELSE 0 END)`,
          flagged: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'flagged' THEN 1 ELSE 0 END)`,
          pending: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'pending_review' THEN 1 ELSE 0 END)`,
          avgQualityScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
          avgApprovedScore: sql<number>`AVG(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'approved' THEN ${llmTrainingExamples.qualityScore} ELSE NULL END)`,
          highQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'high' THEN 1 ELSE 0 END)`,
          mediumQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'medium' THEN 1 ELSE 0 END)`,
          lowQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'low' THEN 1 ELSE 0 END)`,
        })
        .from(llmTrainingExamples)
        .where(whereClause)
        .groupBy(llmTrainingExamples.model)
        .orderBy(desc(sql`COUNT(*)`));

      const gates = modelStats.map((row) => {
        const total = Number(row.total) || 0;
        const approved = Number(row.approved) || 0;
        const rejected = Number(row.rejected) || 0;
        const flagged = Number(row.flagged) || 0;
        const pending = Number(row.pending) || 0;
        const reviewed = approved + rejected;
        const approvalRate = reviewed > 0 ? (approved / reviewed) * 100 : 0;
        const reviewProgress = total > 0 ? ((reviewed + flagged) / total) * 100 : 0;
        const avgQualityScore = Number(row.avgQualityScore) || 0;
        const avgApprovedScore = Number(row.avgApprovedScore) || 0;

        // Compute quality gate verdict
        let verdict: 'pass' | 'warn' | 'fail' | 'insufficient';
        let verdictReason: string;

        if (reviewed < 20) {
          verdict = 'insufficient';
          verdictReason = `Only ${reviewed} examples reviewed (need ≥20 for assessment)`;
        } else if (approvalRate >= 80 && reviewed >= 50 && avgApprovedScore >= 0.75) {
          verdict = 'pass';
          verdictReason = `${approvalRate.toFixed(1)}% approval rate with ${reviewed} reviewed examples (avg score: ${avgApprovedScore.toFixed(2)})`;
        } else if (approvalRate >= 60 && reviewed >= 20 && avgQualityScore >= 0.5) {
          verdict = 'warn';
          verdictReason = `Approval rate ${approvalRate.toFixed(1)}% — needs improvement for graduation (target: ≥80%)`;
        } else {
          verdict = 'fail';
          verdictReason = approvalRate < 60
            ? `Low approval rate: ${approvalRate.toFixed(1)}% (need ≥60% to pass)`
            : `Low quality score: ${avgQualityScore.toFixed(2)} (need ≥0.5 to pass)`;
        }

        return {
          model: row.model,
          total,
          approved,
          rejected,
          flagged,
          pending,
          reviewed,
          approvalRate: Math.round(approvalRate * 10) / 10,
          reviewProgress: Math.round(reviewProgress * 10) / 10,
          avgQualityScore: Math.round(avgQualityScore * 100) / 100,
          avgApprovedScore: Math.round(avgApprovedScore * 100) / 100,
          qualityDistribution: {
            high: Number(row.highQuality) || 0,
            medium: Number(row.mediumQuality) || 0,
            low: Number(row.lowQuality) || 0,
          },
          verdict,
          verdictReason,
        };
      });

      // Overall summary
      const totalModels = gates.length;
      const passCount = gates.filter((g) => g.verdict === 'pass').length;
      const warnCount = gates.filter((g) => g.verdict === 'warn').length;
      const failCount = gates.filter((g) => g.verdict === 'fail').length;
      const insufficientCount = gates.filter((g) => g.verdict === 'insufficient').length;

      return {
        gates,
        summary: {
          totalModels,
          passCount,
          warnCount,
          failCount,
          insufficientCount,
          overallReadiness: totalModels > 0
            ? Math.round((passCount / totalModels) * 100)
            : 0,
          totalExamples: gates.reduce((s, g) => s + g.total, 0),
          totalApproved: gates.reduce((s, g) => s + g.approved, 0),
          totalRejected: gates.reduce((s, g) => s + g.rejected, 0),
        },
        thresholds: {
          pass: { minApprovalRate: 80, minReviewed: 50, minAvgScore: 0.75 },
          warn: { minApprovalRate: 60, minReviewed: 20, minAvgScore: 0.5 },
        },
      };
    }),

  /**
   * Get knowledge module attribution — which knowledge modules are driving
   * the best outcomes across engagements.
   */
  getKnowledgeAttribution: protectedProcedure
    .input(
      z.object({
        windowDays: z.number().min(1).max(90).default(30),
        engagementId: z.number().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const days = input?.windowDays ?? 30;
      const db = await getDbRequired();
      const { llmDecisionLog } = await import("../../drizzle/schema");
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      const conditions: any[] = [
        gte(llmDecisionLog.createdAt, cutoff.toISOString().slice(0, 19).replace("T", " ")),
      ];
      if (input?.engagementId) {
        conditions.push(eq(llmDecisionLog.engagementId, input.engagementId));
      }

      const rows = await db.select()
        .from(llmDecisionLog)
        .where(and(...conditions))
        .orderBy(desc(llmDecisionLog.id));

      // Aggregate by knowledge module
      const moduleStats: Record<string, {
        totalDecisions: number;
        successCount: number;
        failureCount: number;
        partialCount: number;
        pendingCount: number;
        phases: Record<string, number>;
        callers: Record<string, number>;
      }> = {};

      for (const row of rows) {
        const modules = (row.knowledgeModulesUsed as string[]) || [];
        const outcome = (row as any).dl_outcome || (row as any).dlOutcome || 'pending';

        for (const mod of modules) {
          if (!moduleStats[mod]) {
            moduleStats[mod] = {
              totalDecisions: 0, successCount: 0, failureCount: 0,
              partialCount: 0, pendingCount: 0, phases: {}, callers: {},
            };
          }
          const s = moduleStats[mod];
          s.totalDecisions++;
          if (outcome === 'success') s.successCount++;
          else if (outcome === 'failure') s.failureCount++;
          else if (outcome === 'partial') s.partialCount++;
          else s.pendingCount++;

          const phase = (row as any).dl_phase || (row as any).dlPhase || 'unknown';
          s.phases[phase] = (s.phases[phase] || 0) + 1;
          const caller = (row as any).dl_caller || (row as any).dlCaller || 'unknown';
          s.callers[caller] = (s.callers[caller] || 0) + 1;
        }
      }

      // Build attribution report
      const attribution = Object.entries(moduleStats).map(([module, stats]) => {
        const resolved = stats.successCount + stats.failureCount + stats.partialCount;
        const successRate = resolved > 0 ? (stats.successCount / resolved) * 100 : 0;
        return {
          module,
          totalDecisions: stats.totalDecisions,
          successCount: stats.successCount,
          failureCount: stats.failureCount,
          partialCount: stats.partialCount,
          pendingCount: stats.pendingCount,
          successRate: Math.round(successRate * 10) / 10,
          topPhases: Object.entries(stats.phases)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([phase, count]) => ({ phase, count })),
          topCallers: Object.entries(stats.callers)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([caller, count]) => ({ caller, count })),
        };
      }).sort((a, b) => b.totalDecisions - a.totalDecisions);

      // Cross-tool comparison
      const burpStats = moduleStats['burp_pentesting'] || { totalDecisions: 0, successCount: 0, failureCount: 0, partialCount: 0, pendingCount: 0, phases: {}, callers: {} };
      const zapStats = moduleStats['zap_pentesting'] || { totalDecisions: 0, successCount: 0, failureCount: 0, partialCount: 0, pendingCount: 0, phases: {}, callers: {} };
      const burpResolved = burpStats.successCount + burpStats.failureCount + burpStats.partialCount;
      const zapResolved = zapStats.successCount + zapStats.failureCount + zapStats.partialCount;

      return {
        attribution,
        crossToolComparison: {
          burp: {
            totalDecisions: burpStats.totalDecisions,
            successRate: burpResolved > 0 ? Math.round((burpStats.successCount / burpResolved) * 1000) / 10 : 0,
          },
          zap: {
            totalDecisions: zapStats.totalDecisions,
            successRate: zapResolved > 0 ? Math.round((zapStats.successCount / zapResolved) * 1000) / 10 : 0,
          },
        },
        totalDecisionsWithModules: rows.filter(r => (r.knowledgeModulesUsed as string[] || []).length > 0).length,
        totalDecisionsWithoutModules: rows.filter(r => !(r.knowledgeModulesUsed as string[] || []).length).length,
        windowDays: days,
      };
    }),

  /**
   * Get detailed caller history for a specific LLM task
   */
  getCallerDetail: protectedProcedure
    .input(z.object({ caller: z.string(), windowDays: z.number().min(1).max(90).default(30) }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
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
