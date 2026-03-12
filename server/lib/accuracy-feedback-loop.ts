/**
 * Accuracy Feedback Loop
 * ──────────────────────
 * Auto-compares scan findings against ground truth after each lab scan,
 * stores accuracy metrics in the DB, and computes deltas over time.
 *
 * Flow:
 *   1. After a training lab scan completes, call `runAccuracyComparison()`
 *   2. It fetches ground truth from the DO learning engine
 *   3. Scores the findings via the DO learning engine's /score endpoint
 *   4. Stores the comparison result in `accuracy_comparisons` table
 *   5. Stores per-vuln-type breakdown in `vuln_type_accuracy` table
 *   6. Computes deltas from the previous comparison for the same target
 */

import { getDb, getDbRequired } from "../db";
import {
  accuracyComparisons,
  vulnTypeAccuracy,
  type InsertAccuracyComparison,
  type InsertVulnTypeAccuracy,
} from "../../drizzle/schema";
import { desc, eq, and, sql } from "drizzle-orm";
import {
  scoreFindings,
  getGroundTruth,
  getVulnAccuracyBreakdown,
} from "./learning-engine-api";

const LOG = "[AccuracyFeedback]";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AccuracyComparisonResult {
  sessionId: string;
  engagementId?: string;
  targetPreset: string;
  targetUrl?: string;
  scanType?: string;
  precision: number;
  recall: number;
  f1Score: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  totalFindings: number;
  totalGroundTruth: number;
  matchedFindings: string[];
  missedVulns: string[];
  falsePositiveFindings: string[];
  f1Delta: number | null;
  precisionDelta: number | null;
  recallDelta: number | null;
  vulnTypeBreakdown: Array<{
    vulnType: string;
    detectionRate: number;
    falsePositiveRate: number;
    timesFound: number;
    timesMissed: number;
  }>;
}

// ─── Core Comparison Logic ──────────────────────────────────────────────────

/**
 * Run an accuracy comparison for a completed training lab scan.
 * Scores findings against ground truth and stores the result in the DB.
 */
export async function runAccuracyComparison(opts: {
  sessionId: string;
  engagementId?: string;
  targetPreset: string;
  targetUrl?: string;
  scanType?: string;
  findings: Array<{
    name: string;
    severity?: string;
    cwe?: string;
    owasp?: string;
    endpoint?: string;
    confidence?: number;
  }>;
  knowledgeModulesUsed?: string[];
  scanDurationMs?: number;
}): Promise<AccuracyComparisonResult | null> {
  try {
    console.log(`${LOG} Running accuracy comparison for ${opts.targetPreset} (${opts.findings.length} findings)`);

    // 1. Score findings via the DO learning engine
    const scoreResult = await scoreFindings({
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: opts.scanType,
      findings: opts.findings,
    });

    if (!scoreResult) {
      console.warn(`${LOG} Score endpoint returned null`);
      return null;
    }

    // 2. Extract metrics from the score result
    // The DO endpoint wraps metrics in an `accuracy` object: { success, hasGroundTruth, accuracy: { ... } }
    const acc = scoreResult.accuracy ?? scoreResult;
    const precision = acc.precision ?? acc.precision_score ?? 0;
    const recall = acc.recall ?? acc.recall_score ?? 0;
    const f1Score = acc.f1Score ?? acc.f1 ?? acc.f1_score ?? 0;
    const truePositives = acc.truePositives ?? acc.true_positives ?? 0;
    const falsePositives = acc.falsePositives ?? acc.false_positives ?? 0;
    const falseNegatives = acc.falseNegatives ?? acc.false_negatives ?? 0;
    const matchedFindings = acc.matchedVulns ?? acc.matched_findings ?? acc.matchedFindings ?? [];
    const missedVulns = acc.missedVulns ?? acc.missed_vulns ?? [];
    const falsePositiveFindings = acc.falsePositiveFindings ?? acc.false_positive_findings ?? [];

    // 3. Get the previous comparison for delta calculation
    const deltas = await computeDeltas(opts.targetPreset, precision, recall, f1Score);

    // 4. Store the comparison in the DB
    const db = await getDbRequired();
    const insertData: InsertAccuracyComparison = {
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: opts.scanType,
      precision,
      recall,
      f1Score,
      truePositives,
      falsePositives,
      falseNegatives,
      totalFindings: opts.findings.length,
      totalGroundTruth: truePositives + falseNegatives,
      matchedFindings: matchedFindings,
      missedVulns: missedVulns,
      falsePositiveFindings: falsePositiveFindings,
      f1Delta: deltas.f1Delta,
      precisionDelta: deltas.precisionDelta,
      recallDelta: deltas.recallDelta,
      knowledgeModulesUsed: opts.knowledgeModulesUsed || [],
      scanDurationMs: opts.scanDurationMs,
    };

    const [inserted] = await db.insert(accuracyComparisons).values(insertData).$returningId();
    const comparisonId = inserted.id;

    // 5. Store per-vuln-type breakdown
    const vulnBreakdown = acc.per_vuln_type ?? acc.perVulnType ?? scoreResult.per_vuln_type ?? scoreResult.perVulnType ?? [];
    const vulnTypeRows: InsertVulnTypeAccuracy[] = vulnBreakdown.map((v: any) => ({
      comparisonId,
      vulnType: v.vuln_type ?? v.vulnType ?? v.name ?? "unknown",
      detectionRate: v.detection_rate ?? v.detectionRate ?? 0,
      falsePositiveRate: v.false_positive_rate ?? v.falsePositiveRate ?? 0,
      timesFound: v.times_found ?? v.timesFound ?? 0,
      timesMissed: v.times_missed ?? v.timesMissed ?? 0,
      timesFalsePositive: v.times_false_positive ?? v.timesFalsePositive ?? 0,
      targetPreset: opts.targetPreset,
    }));

    if (vulnTypeRows.length > 0) {
      await db.insert(vulnTypeAccuracy).values(vulnTypeRows);
    }

    const result: AccuracyComparisonResult = {
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: opts.scanType,
      precision,
      recall,
      f1Score,
      truePositives,
      falsePositives,
      falseNegatives,
      totalFindings: opts.findings.length,
      totalGroundTruth: truePositives + falseNegatives,
      matchedFindings,
      missedVulns,
      falsePositiveFindings,
      f1Delta: deltas.f1Delta,
      precisionDelta: deltas.precisionDelta,
      recallDelta: deltas.recallDelta,
      vulnTypeBreakdown: vulnBreakdown.map((v: any) => ({
        vulnType: v.vuln_type ?? v.vulnType ?? v.name ?? "unknown",
        detectionRate: v.detection_rate ?? v.detectionRate ?? 0,
        falsePositiveRate: v.false_positive_rate ?? v.falsePositiveRate ?? 0,
        timesFound: v.times_found ?? v.timesFound ?? 0,
        timesMissed: v.times_missed ?? v.timesMissed ?? 0,
      })),
    };

    console.log(`${LOG} Comparison stored: F1=${f1Score.toFixed(3)} (Δ${deltas.f1Delta?.toFixed(3) ?? 'N/A'}), P=${precision.toFixed(3)}, R=${recall.toFixed(3)}`);
    return result;
  } catch (err: any) {
    console.error(`${LOG} Failed to run accuracy comparison:`, err.message);
    return null;
  }
}

// ─── Delta Computation ──────────────────────────────────────────────────────

async function computeDeltas(
  targetPreset: string,
  currentPrecision: number,
  currentRecall: number,
  currentF1: number,
): Promise<{ f1Delta: number | null; precisionDelta: number | null; recallDelta: number | null }> {
  try {
    const db = await getDb();
    if (!db) return { f1Delta: null, precisionDelta: null, recallDelta: null };

    const [prev] = await db
      .select({
        precision: accuracyComparisons.precision,
        recall: accuracyComparisons.recall,
        f1Score: accuracyComparisons.f1Score,
      })
      .from(accuracyComparisons)
      .where(eq(accuracyComparisons.targetPreset, targetPreset))
      .orderBy(desc(accuracyComparisons.scoredAt))
      .limit(1);

    if (!prev) return { f1Delta: null, precisionDelta: null, recallDelta: null };

    return {
      f1Delta: currentF1 - (prev.f1Score ?? 0),
      precisionDelta: currentPrecision - (prev.precision ?? 0),
      recallDelta: currentRecall - (prev.recall ?? 0),
    };
  } catch {
    return { f1Delta: null, precisionDelta: null, recallDelta: null };
  }
}

// ─── Query Helpers ──────────────────────────────────────────────────────────

/**
 * Get the accuracy trend for a specific target (or all targets).
 */
export async function getAccuracyHistory(opts?: {
  targetPreset?: string;
  limit?: number;
}): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  const limit = opts?.limit ?? 50;
  const conditions = opts?.targetPreset
    ? eq(accuracyComparisons.targetPreset, opts.targetPreset)
    : undefined;

  return db
    .select()
    .from(accuracyComparisons)
    .where(conditions)
    .orderBy(desc(accuracyComparisons.scoredAt))
    .limit(limit);
}

/**
 * Get the latest comparison for each target preset.
 */
export async function getLatestComparisonPerTarget(): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  // Use a subquery to get the max scored_at per target
  const rows = await db.execute(sql`
    SELECT ac.*
    FROM accuracy_comparisons ac
    INNER JOIN (
      SELECT target_preset, MAX(scored_at) as max_scored
      FROM accuracy_comparisons
      GROUP BY target_preset
    ) latest ON ac.target_preset = latest.target_preset AND ac.scored_at = latest.max_scored
    ORDER BY ac.f1_score DESC
  `);

  return (rows as any)?.[0] ?? rows ?? [];
}

/**
 * Get vuln type accuracy breakdown for a specific comparison.
 */
export async function getVulnTypeBreakdown(comparisonId: number): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(vulnTypeAccuracy)
    .where(eq(vulnTypeAccuracy.comparisonId, comparisonId));
}

/**
 * Get aggregate vuln type accuracy across all comparisons for a target.
 */
export async function getAggregateVulnTypeAccuracy(targetPreset?: string): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  const condition = targetPreset
    ? sql`WHERE target_preset = ${targetPreset}`
    : sql``;

  const rows = await db.execute(sql`
    SELECT
      vuln_type,
      AVG(detection_rate) as avg_detection_rate,
      AVG(false_positive_rate) as avg_false_positive_rate,
      SUM(times_found) as total_found,
      SUM(times_missed) as total_missed,
      SUM(times_false_positive) as total_false_positive,
      COUNT(*) as sample_count
    FROM vuln_type_accuracy
    ${condition}
    GROUP BY vuln_type
    ORDER BY avg_detection_rate ASC
  `);

  return (rows as any)?.[0] ?? rows ?? [];
}

/**
 * Get accuracy summary statistics.
 */
export async function getAccuracySummary(): Promise<{
  totalComparisons: number;
  avgF1: number;
  avgPrecision: number;
  avgRecall: number;
  bestF1: number;
  worstF1: number;
  latestF1: number;
  f1Trend: "improving" | "declining" | "stable" | "insufficient_data";
  targetCount: number;
}> {
  const db = await getDb();
  if (!db) {
    return {
      totalComparisons: 0, avgF1: 0, avgPrecision: 0, avgRecall: 0,
      bestF1: 0, worstF1: 0, latestF1: 0, f1Trend: "insufficient_data", targetCount: 0,
    };
  }

  const [stats] = await db.execute(sql`
    SELECT
      COUNT(*) as total_comparisons,
      AVG(f1_score) as avg_f1,
      AVG(\`precision\`) as avg_precision,
      AVG(recall) as avg_recall,
      MAX(f1_score) as best_f1,
      MIN(f1_score) as worst_f1,
      COUNT(DISTINCT target_preset) as target_count
    FROM accuracy_comparisons
  `) as any;

  const row = Array.isArray(stats) ? stats[0] : stats;

  // Get latest F1 and compute trend
  const [latest] = await db
    .select({ f1Score: accuracyComparisons.f1Score })
    .from(accuracyComparisons)
    .orderBy(desc(accuracyComparisons.scoredAt))
    .limit(1);

  // Compute trend from last 5 comparisons
  const recentRows = await db
    .select({ f1Score: accuracyComparisons.f1Score })
    .from(accuracyComparisons)
    .orderBy(desc(accuracyComparisons.scoredAt))
    .limit(5);

  let f1Trend: "improving" | "declining" | "stable" | "insufficient_data" = "insufficient_data";
  if (recentRows.length >= 3) {
    const recent = recentRows.map(r => r.f1Score ?? 0);
    const avgRecent = recent.slice(0, 2).reduce((a, b) => a + b, 0) / 2;
    const avgOlder = recent.slice(2).reduce((a, b) => a + b, 0) / (recent.length - 2);
    if (avgRecent > avgOlder + 0.02) f1Trend = "improving";
    else if (avgRecent < avgOlder - 0.02) f1Trend = "declining";
    else f1Trend = "stable";
  }

  return {
    totalComparisons: Number(row?.total_comparisons ?? 0),
    avgF1: Number(row?.avg_f1 ?? 0),
    avgPrecision: Number(row?.avg_precision ?? 0),
    avgRecall: Number(row?.avg_recall ?? 0),
    bestF1: Number(row?.best_f1 ?? 0),
    worstF1: Number(row?.worst_f1 ?? 0),
    latestF1: latest?.f1Score ?? 0,
    f1Trend,
    targetCount: Number(row?.target_count ?? 0),
  };
}
