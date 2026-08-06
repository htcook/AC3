/**
 * Adjustment Effectiveness Tracker
 *
 * Tracks which exploit adjustments (evasion, encoding, payload changes, etc.)
 * led to successful retries and feeds that data back into the priority scoring
 * so the system learns which adjustments work best against specific defense
 * configurations.
 *
 * Architecture:
 * - DB table `adjustment_effectiveness` is the source of truth
 * - In-memory cache with Bayesian-smoothed scores for fast priority lookups
 * - Automatic cache refresh on writes and periodic background refresh
 * - Composite key: (adjustmentType, failureCategory, service)
 *
 * @module adjustment-effectiveness-tracker
 */

import { getDb } from "../db";
import { adjustmentEffectiveness } from "../../drizzle/schema";
import { eq, and, sql, desc } from "drizzle-orm";
import type { StrategyAdjustment, FailureCategory } from "./exploit-retry-engine";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface AdjustmentOutcome {
  adjustmentType: StrategyAdjustment["type"];
  failureCategory: FailureCategory;
  service: string;
  engagementId?: number;
  target?: string;
  port?: number;
  success: boolean;
  retryNumber?: number;
  basePriority?: number;
  adjustedPriority?: number;
  execDurationMs?: number;
  exploitOutput?: string;
}

export interface EffectivenessScore {
  adjustmentType: StrategyAdjustment["type"];
  failureCategory: FailureCategory;
  service: string;
  totalAttempts: number;
  successes: number;
  failures: number;
  rawSuccessRate: number;
  /** Bayesian-smoothed success rate (accounts for low sample sizes) */
  bayesianRate: number;
  /** Priority modifier: positive = boost, negative = penalize */
  priorityModifier: number;
  avgDurationMs: number;
  lastUsed: number;
  trend: "improving" | "stable" | "degrading" | "insufficient_data";
}

export interface AdjustmentRanking {
  adjustmentType: StrategyAdjustment["type"];
  bayesianRate: number;
  priorityModifier: number;
  totalAttempts: number;
  trend: string;
  recommendation: string;
}

export interface EffectivenessSummary {
  totalRecords: number;
  uniqueCombinations: number;
  topPerformers: AdjustmentRanking[];
  worstPerformers: AdjustmentRanking[];
  byFailureCategory: Record<string, AdjustmentRanking[]>;
  byService: Record<string, AdjustmentRanking[]>;
  recentTrends: Array<{
    adjustmentType: string;
    failureCategory: string;
    service: string;
    trend: string;
    bayesianRate: number;
  }>;
}

// ─── Constants ─────────────────────────────────────────────────────────────

/** Bayesian prior: assumed success rate with zero data */
const BAYESIAN_PRIOR = 0.35;
/** Bayesian strength: how many virtual observations the prior represents */
const BAYESIAN_STRENGTH = 5;
/** Max priority boost for highly effective adjustments */
const MAX_PRIORITY_BOOST = 3;
/** Max priority penalty for ineffective adjustments */
const MAX_PRIORITY_PENALTY = -4;
/** Minimum attempts before trend analysis kicks in */
const MIN_TREND_SAMPLES = 4;
/** Recent window for trend calculation (last N attempts) */
const RECENT_WINDOW = 8;
/** Cache TTL in ms */
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// ─── In-Memory Cache ───────────────────────────────────────────────────────

interface CacheEntry {
  score: EffectivenessScore;
  updatedAt: number;
}

const scoreCache = new Map<string, CacheEntry>();
let lastFullRefresh = 0;

function cacheKey(adjType: string, failCat: string, service: string): string {
  return `${adjType}::${failCat}::${service}`;
}

function invalidateCache(adjType: string, failCat: string, service: string): void {
  scoreCache.delete(cacheKey(adjType, failCat, service));
}

// ─── Core Functions ────────────────────────────────────────────────────────

/**
 * Record the outcome of an adjustment application during a retry attempt.
 * This is the primary write path — called after each retry completes.
 */
export async function recordAdjustmentOutcome(outcome: AdjustmentOutcome): Promise<EffectivenessScore> {
  const db = await getDb();

  try {
    await db.insert(adjustmentEffectiveness).values({
      aeAdjustmentType: outcome.adjustmentType,
      aeFailureCategory: outcome.failureCategory,
      aeService: outcome.service,
      aeEngagementId: outcome.engagementId ?? null,
      aeTarget: outcome.target ?? null,
      aePort: outcome.port ?? null,
      aeSuccess: outcome.success ? 1 : 0,
      aeRetryNumber: outcome.retryNumber ?? null,
      aeBasePriority: outcome.basePriority ?? null,
      aeAdjustedPriority: outcome.adjustedPriority ?? null,
      aeExecDurationMs: outcome.execDurationMs ?? null,
      aeExploitOutput: outcome.exploitOutput?.slice(0, 2000) ?? null,
    });
  } catch (err) {
    console.warn("[AdjEffectiveness] Failed to record outcome:", err);
  }

  // Invalidate cache for this combination
  invalidateCache(outcome.adjustmentType, outcome.failureCategory, outcome.service);

  // Return fresh score
  return getEffectivenessScore(outcome.adjustmentType, outcome.failureCategory, outcome.service);
}

/**
 * Get the effectiveness score for a specific (adjustmentType, failureCategory, service) tuple.
 * Uses in-memory cache with Bayesian smoothing.
 */
export async function getEffectivenessScore(
  adjType: StrategyAdjustment["type"],
  failCat: FailureCategory,
  service: string
): Promise<EffectivenessScore> {
  const key = cacheKey(adjType, failCat, service);
  const cached = scoreCache.get(key);
  if (cached && Date.now() - cached.updatedAt < CACHE_TTL) {
    return cached.score;
  }

  const db = await getDb();
  const rows = await db
    .select({
      success: adjustmentEffectiveness.aeSuccess,
      durationMs: adjustmentEffectiveness.aeExecDurationMs,
      createdAt: adjustmentEffectiveness.aeCreatedAt,
    })
    .from(adjustmentEffectiveness)
    .where(
      and(
        eq(adjustmentEffectiveness.aeAdjustmentType, adjType),
        eq(adjustmentEffectiveness.aeFailureCategory, failCat),
        eq(adjustmentEffectiveness.aeService, service)
      )
    )
    .orderBy(desc(adjustmentEffectiveness.aeCreatedAt));

  const totalAttempts = rows.length;
  const successes = rows.filter(r => r.success === 1).length;
  const failures = totalAttempts - successes;
  const rawSuccessRate = totalAttempts > 0 ? successes / totalAttempts : 0;

  // Bayesian smoothing: (successes + prior * strength) / (total + strength)
  const bayesianRate = (successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (totalAttempts + BAYESIAN_STRENGTH);

  // Priority modifier: scale from MAX_PENALTY to MAX_BOOST based on bayesian rate
  // 0.0 rate → MAX_PENALTY, 0.5 rate → 0, 1.0 rate → MAX_BOOST
  const priorityModifier = totalAttempts >= 2
    ? Math.round((bayesianRate - 0.5) * 2 * (bayesianRate > 0.5 ? MAX_PRIORITY_BOOST : Math.abs(MAX_PRIORITY_PENALTY)))
    : 0;

  // Average duration
  const durationsValid = rows.filter(r => r.durationMs != null).map(r => r.durationMs!);
  const avgDurationMs = durationsValid.length > 0
    ? Math.round(durationsValid.reduce((a, b) => a + b, 0) / durationsValid.length)
    : 0;

  // Trend analysis
  const trend = calculateTrend(rows.map(r => r.success === 1));

  // Last used
  const lastUsed = rows.length > 0 && rows[0].createdAt
    ? new Date(rows[0].createdAt).getTime()
    : 0;

  const score: EffectivenessScore = {
    adjustmentType: adjType,
    failureCategory: failCat,
    service,
    totalAttempts,
    successes,
    failures,
    rawSuccessRate: Math.round(rawSuccessRate * 100) / 100,
    bayesianRate: Math.round(bayesianRate * 100) / 100,
    priorityModifier,
    avgDurationMs,
    lastUsed,
    trend,
  };

  scoreCache.set(key, { score, updatedAt: Date.now() });
  return score;
}

/**
 * Get adjusted priorities for a list of suggested adjustments based on historical effectiveness.
 * This is the primary read path — called by analyzeFailure() to reorder adjustments.
 */
export async function getAdjustedPriorities(
  adjustments: StrategyAdjustment[],
  failureCategory: FailureCategory,
  service: string
): Promise<Array<StrategyAdjustment & { originalPriority: number; adjustedPriority: number; effectiveness: EffectivenessScore }>> {
  const results = await Promise.all(
    adjustments.map(async (adj) => {
      const effectiveness = await getEffectivenessScore(adj.type, failureCategory, service);
      const adjustedPriority = Math.max(1, Math.min(10, adj.priority + effectiveness.priorityModifier));
      return {
        ...adj,
        originalPriority: adj.priority,
        priority: adjustedPriority,
        adjustedPriority,
        effectiveness,
      };
    })
  );

  // Sort by adjusted priority descending (highest = most likely to help)
  results.sort((a, b) => b.adjustedPriority - a.adjustedPriority);
  return results;
}

/**
 * Get a full effectiveness summary for dashboard display.
 */
export async function getEffectivenessSummary(): Promise<EffectivenessSummary> {
  const db = await getDb();

  // Get aggregate stats grouped by (type, category, service)
  const aggregates = await db
    .select({
      adjType: adjustmentEffectiveness.aeAdjustmentType,
      failCat: adjustmentEffectiveness.aeFailureCategory,
      service: adjustmentEffectiveness.aeService,
      total: sql<number>`COUNT(*)`.as("total"),
      successes: sql<number>`SUM(${adjustmentEffectiveness.aeSuccess})`.as("successes"),
      avgDuration: sql<number>`AVG(${adjustmentEffectiveness.aeExecDurationMs})`.as("avg_duration"),
    })
    .from(adjustmentEffectiveness)
    .groupBy(
      adjustmentEffectiveness.aeAdjustmentType,
      adjustmentEffectiveness.aeFailureCategory,
      adjustmentEffectiveness.aeService
    );

  const totalRecords = aggregates.reduce((sum, r) => sum + r.total, 0);
  const uniqueCombinations = aggregates.length;

  // Build rankings for each combination
  const rankings: AdjustmentRanking[] = [];
  const byFailureCategory: Record<string, AdjustmentRanking[]> = {};
  const byService: Record<string, AdjustmentRanking[]> = {};

  for (const agg of aggregates) {
    const rawRate = agg.total > 0 ? agg.successes / agg.total : 0;
    const bayesianRate = (agg.successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (agg.total + BAYESIAN_STRENGTH);
    const priorityModifier = agg.total >= 2
      ? Math.round((bayesianRate - 0.5) * 2 * (bayesianRate > 0.5 ? MAX_PRIORITY_BOOST : Math.abs(MAX_PRIORITY_PENALTY)))
      : 0;

    const ranking: AdjustmentRanking = {
      adjustmentType: agg.adjType as StrategyAdjustment["type"],
      bayesianRate: Math.round(bayesianRate * 100) / 100,
      priorityModifier,
      totalAttempts: agg.total,
      trend: agg.total >= MIN_TREND_SAMPLES ? "stable" : "insufficient_data",
      recommendation: generateRecommendation(agg.adjType, bayesianRate, agg.total, priorityModifier),
    };

    rankings.push(ranking);

    // Group by failure category
    if (!byFailureCategory[agg.failCat]) byFailureCategory[agg.failCat] = [];
    byFailureCategory[agg.failCat].push(ranking);

    // Group by service
    if (!byService[agg.service]) byService[agg.service] = [];
    byService[agg.service].push(ranking);
  }

  // Sort rankings by bayesian rate
  rankings.sort((a, b) => b.bayesianRate - a.bayesianRate);

  // Sort within groups
  for (const key of Object.keys(byFailureCategory)) {
    byFailureCategory[key].sort((a, b) => b.bayesianRate - a.bayesianRate);
  }
  for (const key of Object.keys(byService)) {
    byService[key].sort((a, b) => b.bayesianRate - a.bayesianRate);
  }

  // Recent trends
  const recentTrends = aggregates
    .filter(a => a.total >= MIN_TREND_SAMPLES)
    .map(a => {
      const rawRate = a.successes / a.total;
      const bayesianRate = (a.successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (a.total + BAYESIAN_STRENGTH);
      return {
        adjustmentType: a.adjType,
        failureCategory: a.failCat,
        service: a.service,
        trend: rawRate > 0.6 ? "improving" : rawRate < 0.3 ? "degrading" : "stable",
        bayesianRate: Math.round(bayesianRate * 100) / 100,
      };
    });

  return {
    totalRecords,
    uniqueCombinations,
    topPerformers: rankings.slice(0, 10),
    worstPerformers: [...rankings].reverse().slice(0, 10),
    byFailureCategory,
    byService,
    recentTrends,
  };
}

/**
 * Batch record multiple adjustment outcomes from a single retry attempt.
 * Used when multiple adjustments are applied simultaneously.
 */
export async function recordBatchOutcomes(
  outcomes: AdjustmentOutcome[]
): Promise<EffectivenessScore[]> {
  return Promise.all(outcomes.map(o => recordAdjustmentOutcome(o)));
}

/**
 * Build an LLM prompt section with effectiveness intelligence.
 * Injected into the exploit generator's system prompt.
 */
export async function buildEffectivenessPrompt(
  failureCategory: FailureCategory,
  service: string
): Promise<string> {
  const db = await getDb();

  const aggregates = await db
    .select({
      adjType: adjustmentEffectiveness.aeAdjustmentType,
      total: sql<number>`COUNT(*)`.as("total"),
      successes: sql<number>`SUM(${adjustmentEffectiveness.aeSuccess})`.as("successes"),
    })
    .from(adjustmentEffectiveness)
    .where(
      and(
        eq(adjustmentEffectiveness.aeFailureCategory, failureCategory),
        eq(adjustmentEffectiveness.aeService, service)
      )
    )
    .groupBy(adjustmentEffectiveness.aeAdjustmentType);

  if (aggregates.length === 0) return "";

  const lines = [
    `### Adjustment Effectiveness Intelligence (${failureCategory} → ${service})`,
    "Based on historical retry data, these adjustments have the following success rates:",
    "| Adjustment | Attempts | Success Rate | Recommendation |",
    "|-----------|----------|-------------|----------------|",
  ];

  for (const agg of aggregates) {
    const bayesianRate = (agg.successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (agg.total + BAYESIAN_STRENGTH);
    const pct = Math.round(bayesianRate * 100);
    const rec = pct > 60 ? "PREFER" : pct > 40 ? "NEUTRAL" : "AVOID";
    lines.push(`| ${agg.adjType} | ${agg.total} | ${pct}% | ${rec} |`);
  }

  lines.push("");
  lines.push("Use this data to prioritize which evasion/encoding techniques to apply.");
  return lines.join("\n");
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function calculateTrend(results: boolean[]): EffectivenessScore["trend"] {
  if (results.length < MIN_TREND_SAMPLES) return "insufficient_data";

  const recent = results.slice(0, Math.min(RECENT_WINDOW, results.length));
  const older = results.slice(RECENT_WINDOW);

  if (older.length < 2) return "insufficient_data";

  const recentRate = recent.filter(Boolean).length / recent.length;
  const olderRate = older.filter(Boolean).length / older.length;
  const delta = recentRate - olderRate;

  if (delta > 0.15) return "improving";
  if (delta < -0.15) return "degrading";
  return "stable";
}

function generateRecommendation(
  adjType: string,
  bayesianRate: number,
  totalAttempts: number,
  priorityModifier: number
): string {
  if (totalAttempts < 2) {
    return `Insufficient data (${totalAttempts} attempt${totalAttempts === 1 ? "" : "s"}). Continue collecting.`;
  }

  const pct = Math.round(bayesianRate * 100);

  if (bayesianRate > 0.7) {
    return `Highly effective (${pct}%). Boost priority by +${priorityModifier}. Prefer this adjustment.`;
  }
  if (bayesianRate > 0.5) {
    return `Moderately effective (${pct}%). Slight boost +${priorityModifier}. Use as secondary option.`;
  }
  if (bayesianRate > 0.3) {
    return `Below average (${pct}%). Penalty ${priorityModifier}. Consider alternatives first.`;
  }
  return `Ineffective (${pct}%). Penalty ${priorityModifier}. Avoid unless no alternatives exist.`;
}
