import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import {
  adjustmentEffectiveness,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/adjustment-effectiveness-tracker.ts
import { eq, and, sql, desc } from "drizzle-orm";
function cacheKey(adjType, failCat, service) {
  return `${adjType}::${failCat}::${service}`;
}
function invalidateCache(adjType, failCat, service) {
  scoreCache.delete(cacheKey(adjType, failCat, service));
}
async function recordAdjustmentOutcome(outcome) {
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
      aeExploitOutput: outcome.exploitOutput?.slice(0, 2e3) ?? null
    });
  } catch (err) {
    console.warn("[AdjEffectiveness] Failed to record outcome:", err);
  }
  invalidateCache(outcome.adjustmentType, outcome.failureCategory, outcome.service);
  return getEffectivenessScore(outcome.adjustmentType, outcome.failureCategory, outcome.service);
}
async function getEffectivenessScore(adjType, failCat, service) {
  const key = cacheKey(adjType, failCat, service);
  const cached = scoreCache.get(key);
  if (cached && Date.now() - cached.updatedAt < CACHE_TTL) {
    return cached.score;
  }
  const db = await getDb();
  const rows = await db.select({
    success: adjustmentEffectiveness.aeSuccess,
    durationMs: adjustmentEffectiveness.aeExecDurationMs,
    createdAt: adjustmentEffectiveness.aeCreatedAt
  }).from(adjustmentEffectiveness).where(
    and(
      eq(adjustmentEffectiveness.aeAdjustmentType, adjType),
      eq(adjustmentEffectiveness.aeFailureCategory, failCat),
      eq(adjustmentEffectiveness.aeService, service)
    )
  ).orderBy(desc(adjustmentEffectiveness.aeCreatedAt));
  const totalAttempts = rows.length;
  const successes = rows.filter((r) => r.success === 1).length;
  const failures = totalAttempts - successes;
  const rawSuccessRate = totalAttempts > 0 ? successes / totalAttempts : 0;
  const bayesianRate = (successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (totalAttempts + BAYESIAN_STRENGTH);
  const priorityModifier = totalAttempts >= 2 ? Math.round((bayesianRate - 0.5) * 2 * (bayesianRate > 0.5 ? MAX_PRIORITY_BOOST : Math.abs(MAX_PRIORITY_PENALTY))) : 0;
  const durationsValid = rows.filter((r) => r.durationMs != null).map((r) => r.durationMs);
  const avgDurationMs = durationsValid.length > 0 ? Math.round(durationsValid.reduce((a, b) => a + b, 0) / durationsValid.length) : 0;
  const trend = calculateTrend(rows.map((r) => r.success === 1));
  const lastUsed = rows.length > 0 && rows[0].createdAt ? new Date(rows[0].createdAt).getTime() : 0;
  const score = {
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
    trend
  };
  scoreCache.set(key, { score, updatedAt: Date.now() });
  return score;
}
async function getAdjustedPriorities(adjustments, failureCategory, service) {
  const results = await Promise.all(
    adjustments.map(async (adj) => {
      const effectiveness = await getEffectivenessScore(adj.type, failureCategory, service);
      const adjustedPriority = Math.max(1, Math.min(10, adj.priority + effectiveness.priorityModifier));
      return {
        ...adj,
        originalPriority: adj.priority,
        priority: adjustedPriority,
        adjustedPriority,
        effectiveness
      };
    })
  );
  results.sort((a, b) => b.adjustedPriority - a.adjustedPriority);
  return results;
}
async function getEffectivenessSummary() {
  const db = await getDb();
  const aggregates = await db.select({
    adjType: adjustmentEffectiveness.aeAdjustmentType,
    failCat: adjustmentEffectiveness.aeFailureCategory,
    service: adjustmentEffectiveness.aeService,
    total: sql`COUNT(*)`.as("total"),
    successes: sql`SUM(${adjustmentEffectiveness.aeSuccess})`.as("successes"),
    avgDuration: sql`AVG(${adjustmentEffectiveness.aeExecDurationMs})`.as("avg_duration")
  }).from(adjustmentEffectiveness).groupBy(
    adjustmentEffectiveness.aeAdjustmentType,
    adjustmentEffectiveness.aeFailureCategory,
    adjustmentEffectiveness.aeService
  );
  const totalRecords = aggregates.reduce((sum, r) => sum + r.total, 0);
  const uniqueCombinations = aggregates.length;
  const rankings = [];
  const byFailureCategory = {};
  const byService = {};
  for (const agg of aggregates) {
    const rawRate = agg.total > 0 ? agg.successes / agg.total : 0;
    const bayesianRate = (agg.successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (agg.total + BAYESIAN_STRENGTH);
    const priorityModifier = agg.total >= 2 ? Math.round((bayesianRate - 0.5) * 2 * (bayesianRate > 0.5 ? MAX_PRIORITY_BOOST : Math.abs(MAX_PRIORITY_PENALTY))) : 0;
    const ranking = {
      adjustmentType: agg.adjType,
      bayesianRate: Math.round(bayesianRate * 100) / 100,
      priorityModifier,
      totalAttempts: agg.total,
      trend: agg.total >= MIN_TREND_SAMPLES ? "stable" : "insufficient_data",
      recommendation: generateRecommendation(agg.adjType, bayesianRate, agg.total, priorityModifier)
    };
    rankings.push(ranking);
    if (!byFailureCategory[agg.failCat]) byFailureCategory[agg.failCat] = [];
    byFailureCategory[agg.failCat].push(ranking);
    if (!byService[agg.service]) byService[agg.service] = [];
    byService[agg.service].push(ranking);
  }
  rankings.sort((a, b) => b.bayesianRate - a.bayesianRate);
  for (const key of Object.keys(byFailureCategory)) {
    byFailureCategory[key].sort((a, b) => b.bayesianRate - a.bayesianRate);
  }
  for (const key of Object.keys(byService)) {
    byService[key].sort((a, b) => b.bayesianRate - a.bayesianRate);
  }
  const recentTrends = aggregates.filter((a) => a.total >= MIN_TREND_SAMPLES).map((a) => {
    const rawRate = a.successes / a.total;
    const bayesianRate = (a.successes + BAYESIAN_PRIOR * BAYESIAN_STRENGTH) / (a.total + BAYESIAN_STRENGTH);
    return {
      adjustmentType: a.adjType,
      failureCategory: a.failCat,
      service: a.service,
      trend: rawRate > 0.6 ? "improving" : rawRate < 0.3 ? "degrading" : "stable",
      bayesianRate: Math.round(bayesianRate * 100) / 100
    };
  });
  return {
    totalRecords,
    uniqueCombinations,
    topPerformers: rankings.slice(0, 10),
    worstPerformers: [...rankings].reverse().slice(0, 10),
    byFailureCategory,
    byService,
    recentTrends
  };
}
async function recordBatchOutcomes(outcomes) {
  return Promise.all(outcomes.map((o) => recordAdjustmentOutcome(o)));
}
async function buildEffectivenessPrompt(failureCategory, service) {
  const db = await getDb();
  const aggregates = await db.select({
    adjType: adjustmentEffectiveness.aeAdjustmentType,
    total: sql`COUNT(*)`.as("total"),
    successes: sql`SUM(${adjustmentEffectiveness.aeSuccess})`.as("successes")
  }).from(adjustmentEffectiveness).where(
    and(
      eq(adjustmentEffectiveness.aeFailureCategory, failureCategory),
      eq(adjustmentEffectiveness.aeService, service)
    )
  ).groupBy(adjustmentEffectiveness.aeAdjustmentType);
  if (aggregates.length === 0) return "";
  const lines = [
    `### Adjustment Effectiveness Intelligence (${failureCategory} \u2192 ${service})`,
    "Based on historical retry data, these adjustments have the following success rates:",
    "| Adjustment | Attempts | Success Rate | Recommendation |",
    "|-----------|----------|-------------|----------------|"
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
function calculateTrend(results) {
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
function generateRecommendation(adjType, bayesianRate, totalAttempts, priorityModifier) {
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
var BAYESIAN_PRIOR, BAYESIAN_STRENGTH, MAX_PRIORITY_BOOST, MAX_PRIORITY_PENALTY, MIN_TREND_SAMPLES, RECENT_WINDOW, CACHE_TTL, scoreCache;
var init_adjustment_effectiveness_tracker = __esm({
  "server/lib/adjustment-effectiveness-tracker.ts"() {
    init_db();
    init_schema();
    BAYESIAN_PRIOR = 0.35;
    BAYESIAN_STRENGTH = 5;
    MAX_PRIORITY_BOOST = 3;
    MAX_PRIORITY_PENALTY = -4;
    MIN_TREND_SAMPLES = 4;
    RECENT_WINDOW = 8;
    CACHE_TTL = 5 * 60 * 1e3;
    scoreCache = /* @__PURE__ */ new Map();
  }
});

export {
  recordAdjustmentOutcome,
  getEffectivenessScore,
  getAdjustedPriorities,
  getEffectivenessSummary,
  recordBatchOutcomes,
  buildEffectivenessPrompt,
  init_adjustment_effectiveness_tracker
};
