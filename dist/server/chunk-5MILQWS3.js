import {
  init_learning_engine_api,
  scoreFindings
} from "./chunk-Z63B6QCQ.js";
import {
  getDb,
  getDbRequired,
  init_db
} from "./chunk-JZVHFV6D.js";
import {
  accuracyComparisons,
  init_schema,
  vulnTypeAccuracy
} from "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/accuracy-feedback-loop.ts
import { desc, eq, sql } from "drizzle-orm";
async function runAccuracyComparison(opts) {
  try {
    console.log(`${LOG} Running accuracy comparison for ${opts.targetPreset} (${opts.findings.length} findings)`);
    const scoreResult = await scoreFindings({
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: opts.scanType,
      findings: opts.findings
    });
    if (!scoreResult) {
      console.warn(`${LOG} Score endpoint returned null`);
      return null;
    }
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
    const deltas = await computeDeltas(opts.targetPreset, precision, recall, f1Score);
    const db = await getDbRequired();
    const insertData = {
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
      knowledgeModulesUsed: opts.knowledgeModulesUsed || [],
      scanDurationMs: opts.scanDurationMs
    };
    const [inserted] = await db.insert(accuracyComparisons).values(insertData).$returningId();
    const comparisonId = inserted.id;
    let vulnBreakdown = acc.per_vuln_type ?? acc.perVulnType ?? scoreResult.per_vuln_type ?? scoreResult.perVulnType ?? [];
    if (vulnBreakdown.length === 0 && (matchedFindings.length > 0 || missedVulns.length > 0)) {
      vulnBreakdown = [
        ...matchedFindings.map((v) => ({ vulnType: v, detectionRate: 100, falsePositiveRate: 0, timesFound: 1, timesMissed: 0, timesFalsePositive: 0 })),
        ...missedVulns.map((v) => ({ vulnType: v, detectionRate: 0, falsePositiveRate: 0, timesFound: 0, timesMissed: 1, timesFalsePositive: 0 })),
        ...falsePositiveFindings.map((v) => ({ vulnType: v, detectionRate: 0, falsePositiveRate: 100, timesFound: 0, timesMissed: 0, timesFalsePositive: 1 }))
      ];
    }
    const vulnTypeRows = vulnBreakdown.map((v) => ({
      comparisonId,
      vulnType: v.vuln_type ?? v.vulnType ?? v.name ?? "unknown",
      detectionRate: v.detection_rate ?? v.detectionRate ?? 0,
      falsePositiveRate: v.false_positive_rate ?? v.falsePositiveRate ?? 0,
      timesFound: v.times_found ?? v.timesFound ?? 0,
      timesMissed: v.times_missed ?? v.timesMissed ?? 0,
      timesFalsePositive: v.times_false_positive ?? v.timesFalsePositive ?? 0,
      targetPreset: opts.targetPreset
    }));
    if (vulnTypeRows.length > 0) {
      await db.insert(vulnTypeAccuracy).values(vulnTypeRows);
    }
    const result = {
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
      vulnTypeBreakdown: vulnBreakdown.map((v) => ({
        vulnType: v.vuln_type ?? v.vulnType ?? v.name ?? "unknown",
        detectionRate: v.detection_rate ?? v.detectionRate ?? 0,
        falsePositiveRate: v.false_positive_rate ?? v.falsePositiveRate ?? 0,
        timesFound: v.times_found ?? v.timesFound ?? 0,
        timesMissed: v.times_missed ?? v.timesMissed ?? 0
      }))
    };
    console.log(`${LOG} Comparison stored: F1=${f1Score.toFixed(3)} (\u0394${deltas.f1Delta?.toFixed(3) ?? "N/A"}), P=${precision.toFixed(3)}, R=${recall.toFixed(3)}`);
    return result;
  } catch (err) {
    console.error(`${LOG} Failed to run accuracy comparison:`, err.message);
    return null;
  }
}
async function computeDeltas(targetPreset, currentPrecision, currentRecall, currentF1) {
  try {
    const db = await getDb();
    if (!db) return { f1Delta: null, precisionDelta: null, recallDelta: null };
    const [prev] = await db.select({
      precision: accuracyComparisons.precision,
      recall: accuracyComparisons.recall,
      f1Score: accuracyComparisons.f1Score
    }).from(accuracyComparisons).where(eq(accuracyComparisons.targetPreset, targetPreset)).orderBy(desc(accuracyComparisons.scoredAt)).limit(1);
    if (!prev) return { f1Delta: null, precisionDelta: null, recallDelta: null };
    return {
      f1Delta: currentF1 - (prev.f1Score ?? 0),
      precisionDelta: currentPrecision - (prev.precision ?? 0),
      recallDelta: currentRecall - (prev.recall ?? 0)
    };
  } catch {
    return { f1Delta: null, precisionDelta: null, recallDelta: null };
  }
}
async function getAccuracyHistory(opts) {
  const db = await getDb();
  if (!db) return [];
  const limit = opts?.limit ?? 50;
  const conditions = opts?.targetPreset ? eq(accuracyComparisons.targetPreset, opts.targetPreset) : void 0;
  return db.select().from(accuracyComparisons).where(conditions).orderBy(desc(accuracyComparisons.scoredAt)).limit(limit);
}
async function getLatestComparisonPerTarget() {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.execute(sql`
    SELECT ac.*
    FROM accuracy_comparisons ac
    INNER JOIN (
      SELECT target_preset, MAX(id) as max_id
      FROM accuracy_comparisons
      GROUP BY target_preset
    ) latest ON ac.id = latest.max_id
    ORDER BY ac.f1_score DESC
  `);
  return rows?.[0] ?? rows ?? [];
}
async function getVulnTypeBreakdown(comparisonId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(vulnTypeAccuracy).where(eq(vulnTypeAccuracy.comparisonId, comparisonId));
}
async function getAggregateVulnTypeAccuracy(targetPreset) {
  const db = await getDb();
  if (!db) return [];
  const condition = targetPreset ? sql`WHERE target_preset = ${targetPreset}` : sql``;
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
  return rows?.[0] ?? rows ?? [];
}
async function rescoreAllTargets() {
  const db = await getDb();
  if (!db) return { rescored: 0, failed: 0, results: [] };
  console.log(`${LOG} Starting rescore of all targets...`);
  const latestRows = await db.execute(sql`
    SELECT ac.*
    FROM accuracy_comparisons ac
    INNER JOIN (
      SELECT target_preset, MAX(id) as max_id
      FROM accuracy_comparisons
      GROUP BY target_preset
    ) latest ON ac.id = latest.max_id
  `);
  const targets = Array.isArray(latestRows?.[0]) ? latestRows[0] : Array.isArray(latestRows) ? latestRows : [];
  if (targets.length === 0) {
    console.log(`${LOG} No targets to rescore`);
    return { rescored: 0, failed: 0, results: [] };
  }
  const results = [];
  let rescored = 0;
  let failed = 0;
  for (const target of targets) {
    const preset = target.target_preset ?? target.targetPreset;
    const previousF1 = Number(target.f1_score ?? target.f1Score ?? 0);
    const matchedFindings = (() => {
      try {
        const raw = target.matched_findings ?? target.matchedFindings;
        return typeof raw === "string" ? JSON.parse(raw) : Array.isArray(raw) ? raw : [];
      } catch {
        return [];
      }
    })();
    const fpFindings = (() => {
      try {
        const raw = target.false_positive_findings ?? target.falsePositiveFindings;
        return typeof raw === "string" ? JSON.parse(raw) : Array.isArray(raw) ? raw : [];
      } catch {
        return [];
      }
    })();
    const findings = [
      ...matchedFindings.map((name) => ({ name, severity: "High" })),
      ...fpFindings.map((name) => ({ name, severity: "Medium" }))
    ];
    if (findings.length === 0) {
      results.push({ targetPreset: preset, previousF1, newF1: 0, f1Delta: 0, status: "skipped", error: "No findings data stored" });
      continue;
    }
    try {
      const compResult = await runAccuracyComparison({
        sessionId: `rescore-${preset}-${Date.now()}`,
        targetPreset: preset,
        targetUrl: target.target_url ?? target.targetUrl ?? void 0,
        scanType: "rescore",
        findings,
        knowledgeModulesUsed: (() => {
          try {
            const raw = target.knowledge_modules_used ?? target.knowledgeModulesUsed;
            return typeof raw === "string" ? JSON.parse(raw) : Array.isArray(raw) ? raw : [];
          } catch {
            return [];
          }
        })()
      });
      if (compResult) {
        const f1Delta = compResult.f1Score - previousF1;
        results.push({ targetPreset: preset, previousF1, newF1: compResult.f1Score, f1Delta, status: "success" });
        rescored++;
        console.log(`${LOG} Rescored ${preset}: F1 ${previousF1.toFixed(3)} \u2192 ${compResult.f1Score.toFixed(3)} (\u0394${f1Delta >= 0 ? "+" : ""}${f1Delta.toFixed(3)})`);
      } else {
        results.push({ targetPreset: preset, previousF1, newF1: 0, f1Delta: 0, status: "failed", error: "Score endpoint returned null" });
        failed++;
      }
    } catch (err) {
      results.push({ targetPreset: preset, previousF1, newF1: 0, f1Delta: 0, status: "failed", error: err.message });
      failed++;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  console.log(`${LOG} Rescore complete: ${rescored} rescored, ${failed} failed, ${results.length} total`);
  return { rescored, failed, results };
}
async function runLocalAccuracyComparison(opts) {
  try {
    const { scoreAgainstGroundTruth } = await import("./llm-self-learning-H3OKCPQI.js");
    const llmFindings = opts.findings.map((f) => ({
      title: f.name,
      severity: f.severity || "medium",
      category: f.owasp || void 0,
      cwe: f.cwe || void 0
    }));
    const localScore = scoreAgainstGroundTruth(
      opts.targetPreset,
      llmFindings,
      { autoDetectableOnly: opts.autoDetectableOnly ?? false }
    );
    if (!localScore) {
      console.warn(`${LOG} Local scoring returned null for ${opts.targetPreset}`);
      return null;
    }
    const { precision, recall, f1Score, truePositives, falsePositives, falseNegatives } = localScore;
    const matchedFindings = localScore.matchDetails.filter((m) => m.matched).map((m) => m.groundTruth.title);
    const missedVulns = localScore.matchDetails.filter((m) => !m.matched).map((m) => m.groundTruth.title);
    const falsePositiveFindings = localScore.unmatchedLlmFindings.map((f) => f.title || f.name || "Unknown");
    const deltas = await computeDeltas(opts.targetPreset, precision, recall, f1Score);
    const db = await getDbRequired();
    const scoringMode = opts.autoDetectableOnly ? "local-auto-detectable" : "local-full";
    const insertData = {
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: opts.scanType ? `${opts.scanType} (${scoringMode})` : scoringMode,
      precision,
      recall,
      f1Score,
      truePositives,
      falsePositives,
      falseNegatives,
      totalFindings: opts.findings.length,
      totalGroundTruth: localScore.totalGroundTruth,
      matchedFindings,
      missedVulns,
      falsePositiveFindings,
      f1Delta: deltas.f1Delta,
      precisionDelta: deltas.precisionDelta,
      recallDelta: deltas.recallDelta,
      knowledgeModulesUsed: opts.knowledgeModulesUsed || [],
      scanDurationMs: opts.scanDurationMs
    };
    const [inserted] = await db.insert(accuracyComparisons).values(insertData).$returningId();
    const comparisonId = inserted.id;
    const vulnBreakdown = [
      ...matchedFindings.map((v) => ({ vulnType: v, detectionRate: 100, falsePositiveRate: 0, timesFound: 1, timesMissed: 0, timesFalsePositive: 0 })),
      ...missedVulns.map((v) => ({ vulnType: v, detectionRate: 0, falsePositiveRate: 0, timesFound: 0, timesMissed: 1, timesFalsePositive: 0 })),
      ...falsePositiveFindings.map((v) => ({ vulnType: v, detectionRate: 0, falsePositiveRate: 100, timesFound: 0, timesMissed: 0, timesFalsePositive: 1 }))
    ];
    const vulnTypeRows = vulnBreakdown.map((v) => ({
      comparisonId,
      vulnType: v.vulnType,
      detectionRate: v.detectionRate,
      falsePositiveRate: v.falsePositiveRate,
      timesFound: v.timesFound,
      timesMissed: v.timesMissed,
      timesFalsePositive: v.timesFalsePositive,
      targetPreset: opts.targetPreset
    }));
    if (vulnTypeRows.length > 0) {
      await db.insert(vulnTypeAccuracy).values(vulnTypeRows);
    }
    const result = {
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetPreset: opts.targetPreset,
      targetUrl: opts.targetUrl,
      scanType: scoringMode,
      precision,
      recall,
      f1Score,
      truePositives,
      falsePositives,
      falseNegatives,
      totalFindings: opts.findings.length,
      totalGroundTruth: localScore.totalGroundTruth,
      matchedFindings,
      missedVulns,
      falsePositiveFindings,
      f1Delta: deltas.f1Delta,
      precisionDelta: deltas.precisionDelta,
      recallDelta: deltas.recallDelta,
      vulnTypeBreakdown: vulnBreakdown.map((v) => ({
        vulnType: v.vulnType,
        detectionRate: v.detectionRate,
        falsePositiveRate: v.falsePositiveRate,
        timesFound: v.timesFound,
        timesMissed: v.timesMissed
      }))
    };
    console.log(`${LOG} Local comparison (${scoringMode}): F1=${f1Score.toFixed(3)} P=${precision.toFixed(3)} R=${recall.toFixed(3)} TP=${truePositives} FP=${falsePositives} FN=${falseNegatives}`);
    return result;
  } catch (err) {
    console.error(`${LOG} Local accuracy comparison failed:`, err.message);
    return null;
  }
}
async function rescoreLocalAllTargets() {
  const db = await getDb();
  if (!db) return { rescored: 0, failed: 0, results: [] };
  console.log(`${LOG} Starting LOCAL rescore of all targets...`);
  const latestRows = await db.execute(sql`
    SELECT ac.*
    FROM accuracy_comparisons ac
    INNER JOIN (
      SELECT target_preset, MAX(id) as max_id
      FROM accuracy_comparisons
      GROUP BY target_preset
    ) latest ON ac.id = latest.max_id
  `);
  const targets = Array.isArray(latestRows?.[0]) ? latestRows[0] : Array.isArray(latestRows) ? latestRows : [];
  if (targets.length === 0) {
    console.log(`${LOG} No targets to rescore`);
    return { rescored: 0, failed: 0, results: [] };
  }
  const results = [];
  let rescored = 0;
  let failed = 0;
  for (const target of targets) {
    const preset = target.target_preset ?? target.targetPreset;
    const previousF1 = Number(target.f1_score ?? target.f1Score ?? 0);
    const matchedFindings = (() => {
      try {
        const raw = target.matched_findings ?? target.matchedFindings;
        return typeof raw === "string" ? JSON.parse(raw) : Array.isArray(raw) ? raw : [];
      } catch {
        return [];
      }
    })();
    const fpFindings = (() => {
      try {
        const raw = target.false_positive_findings ?? target.falsePositiveFindings;
        return typeof raw === "string" ? JSON.parse(raw) : Array.isArray(raw) ? raw : [];
      } catch {
        return [];
      }
    })();
    const findings = [
      ...matchedFindings.map((name) => ({ name, severity: "High" })),
      ...fpFindings.map((name) => ({ name, severity: "Medium" }))
    ];
    if (findings.length === 0) {
      results.push({ targetPreset: preset, previousF1, newF1Full: 0, newF1AutoDetectable: 0, f1DeltaFull: 0, f1DeltaAutoDetectable: 0, status: "skipped", error: "No findings data stored" });
      continue;
    }
    try {
      const fullResult = await runLocalAccuracyComparison({
        sessionId: `rescore-local-full-${preset}-${Date.now()}`,
        targetPreset: preset,
        targetUrl: target.target_url ?? target.targetUrl ?? void 0,
        scanType: "rescore",
        findings
      });
      const autoResult = await runLocalAccuracyComparison({
        sessionId: `rescore-local-auto-${preset}-${Date.now()}`,
        targetPreset: preset,
        targetUrl: target.target_url ?? target.targetUrl ?? void 0,
        scanType: "rescore",
        findings,
        autoDetectableOnly: true
      });
      const newF1Full = fullResult?.f1Score ?? 0;
      const newF1Auto = autoResult?.f1Score ?? 0;
      results.push({
        targetPreset: preset,
        previousF1,
        newF1Full,
        newF1AutoDetectable: newF1Auto,
        f1DeltaFull: newF1Full - previousF1,
        f1DeltaAutoDetectable: newF1Auto - previousF1,
        status: "success",
        matchedFindings: fullResult?.matchedFindings,
        missedVulns: fullResult?.missedVulns,
        falsePositiveFindings: fullResult?.falsePositiveFindings
      });
      rescored++;
      console.log(`${LOG} Rescored ${preset}: Full F1=${newF1Full.toFixed(3)} AutoDetectable F1=${newF1Auto.toFixed(3)} (prev=${previousF1.toFixed(3)})`);
    } catch (err) {
      results.push({ targetPreset: preset, previousF1, newF1Full: 0, newF1AutoDetectable: 0, f1DeltaFull: 0, f1DeltaAutoDetectable: 0, status: "failed", error: err.message });
      failed++;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  console.log(`${LOG} Local rescore complete: ${rescored} rescored, ${failed} failed`);
  return { rescored, failed, results };
}
async function getAccuracySummary() {
  const db = await getDb();
  if (!db) {
    return {
      totalComparisons: 0,
      avgF1: 0,
      avgPrecision: 0,
      avgRecall: 0,
      bestF1: 0,
      worstF1: 0,
      latestF1: 0,
      f1Trend: "insufficient_data",
      targetCount: 0
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
  `);
  const row = Array.isArray(stats) ? stats[0] : stats;
  const [latest] = await db.select({ f1Score: accuracyComparisons.f1Score }).from(accuracyComparisons).orderBy(desc(accuracyComparisons.scoredAt)).limit(1);
  const recentRows = await db.select({ f1Score: accuracyComparisons.f1Score }).from(accuracyComparisons).orderBy(desc(accuracyComparisons.scoredAt)).limit(5);
  let f1Trend = "insufficient_data";
  if (recentRows.length >= 3) {
    const recent = recentRows.map((r) => r.f1Score ?? 0);
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
    targetCount: Number(row?.target_count ?? 0)
  };
}
var LOG;
var init_accuracy_feedback_loop = __esm({
  "server/lib/accuracy-feedback-loop.ts"() {
    init_db();
    init_schema();
    init_learning_engine_api();
    LOG = "[AccuracyFeedback]";
  }
});

export {
  runAccuracyComparison,
  getAccuracyHistory,
  getLatestComparisonPerTarget,
  getVulnTypeBreakdown,
  getAggregateVulnTypeAccuracy,
  rescoreAllTargets,
  runLocalAccuracyComparison,
  rescoreLocalAllTargets,
  getAccuracySummary,
  init_accuracy_feedback_loop
};
