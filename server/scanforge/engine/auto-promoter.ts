/**
 * ScanForge Template Auto-Promotion Engine
 *
 * Automatically evaluates generated templates after each engagement and promotes
 * them to production when they meet configurable accuracy thresholds across
 * multiple engagements.
 *
 * Promotion Pipeline:
 *   draft → candidate → promoted → production
 *
 * Evaluation Criteria:
 *   - Minimum engagement count (template must have been used in N engagements)
 *   - Minimum precision (low false positive rate)
 *   - Minimum recall (catches real vulnerabilities)
 *   - Minimum F1 score (balanced accuracy)
 *   - Maximum false positive rate
 *   - Minimum effectiveness score
 *   - Generation confidence floor (LLM must have been confident in the template)
 */
import { getDbRequired } from "../../db";
import { eq, and, desc, sql, inArray, gte, lte } from "drizzle-orm";
import {
  scanforgeGeneratedTemplates,
  scanforgeTemplateMetrics,
  scanforgePromotionHistory,
  type ScanforgeGeneratedTemplateRow,
  type ScanforgeTemplateMetricsRow,
  type InsertScanforgePromotionHistory,
} from "../../../drizzle/schema";

// ─── Promotion Rules Configuration ─────────────────────────────────────────

export interface PromotionRules {
  /** Minimum number of engagements the template must have been used in */
  minEngagements: number;
  /** Minimum precision (0-1). Higher = fewer false positives required */
  minPrecision: number;
  /** Minimum recall (0-1). Higher = must catch more real vulns */
  minRecall: number;
  /** Minimum F1 score (0-1). Balanced accuracy threshold */
  minF1Score: number;
  /** Maximum false positive rate (0-1). Templates above this are rejected */
  maxFalsePositiveRate: number;
  /** Minimum effectiveness score (0-100) from the ranking engine */
  minEffectivenessScore: number;
  /** Minimum generation confidence from the LLM (0-1) */
  minGenerationConfidence: number;
  /** Minimum total scans before evaluation (prevents premature promotion) */
  minTotalScans: number;
}

/** Default promotion rules — conservative thresholds for production safety */
export const DEFAULT_PROMOTION_RULES: PromotionRules = {
  minEngagements: 3,
  minPrecision: 0.80,
  minRecall: 0.60,
  minF1Score: 0.70,
  maxFalsePositiveRate: 0.15,
  minEffectivenessScore: 65,
  minGenerationConfidence: 0.6,
  minTotalScans: 5,
};

/** Aggressive rules for fast-tracking high-confidence templates */
export const FAST_TRACK_RULES: PromotionRules = {
  minEngagements: 1,
  minPrecision: 0.95,
  minRecall: 0.80,
  minF1Score: 0.85,
  maxFalsePositiveRate: 0.05,
  minEffectivenessScore: 80,
  minGenerationConfidence: 0.85,
  minTotalScans: 3,
};

// ─── Evaluation Result Types ────────────────────────────────────────────────

export interface RuleEvaluation {
  rule: string;
  threshold: number;
  actual: number;
  passed: boolean;
}

export interface PromotionEvaluation {
  templateId: string;
  generatedTemplateDbId: number;
  currentStatus: string;
  decision: "promoted" | "deferred" | "rejected";
  newStatus: string;
  reason: string;
  rulesEvaluated: RuleEvaluation[];
  rulesPassed: number;
  rulesFailed: number;
  metricsSnapshot: {
    precision: number;
    recall: number;
    f1Score: number;
    effectivenessScore: number;
    totalScans: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    engagementCount: number;
    generationConfidence: number;
  };
}

// ─── Core Auto-Promotion Engine ─────────────────────────────────────────────

/**
 * Evaluate a single generated template against promotion rules.
 * Returns the evaluation result with decision and detailed rule breakdown.
 */
export function evaluateTemplate(
  template: ScanforgeGeneratedTemplateRow,
  metrics: ScanforgeTemplateMetricsRow | null,
  rules: PromotionRules = DEFAULT_PROMOTION_RULES,
): PromotionEvaluation {
  const templateId = template.templateId;
  const generationConfidence = template.generationConfidence ?? 0.5;

  // If no metrics exist yet, defer
  if (!metrics) {
    return {
      templateId,
      generatedTemplateDbId: template.id,
      currentStatus: template.status,
      decision: "deferred",
      newStatus: template.status,
      reason: "No accuracy metrics available yet — template has not been used in any engagement",
      rulesEvaluated: [],
      rulesPassed: 0,
      rulesFailed: 0,
      metricsSnapshot: {
        precision: 0, recall: 0, f1Score: 0, effectivenessScore: 0,
        totalScans: 0, truePositives: 0, falsePositives: 0, falseNegatives: 0,
        engagementCount: 0, generationConfidence,
      },
    };
  }

  const engagementWindow = (metrics.engagementWindow as string[] | null) ?? [];
  const engagementCount = engagementWindow.length;
  const totalScans = metrics.totalScans ?? 0;
  const precision = metrics.precision ?? 0;
  const recall = metrics.recall ?? 0;
  const f1Score = metrics.f1Score ?? 0;
  const effectivenessScore = metrics.effectivenessScore ?? 0;
  const tp = metrics.truePositives ?? 0;
  const fp = metrics.falsePositives ?? 0;
  const fn = metrics.falseNegatives ?? 0;
  const fpRate = (tp + fp) > 0 ? fp / (tp + fp) : 0;

  const metricsSnapshot = {
    precision, recall, f1Score, effectivenessScore,
    totalScans, truePositives: tp, falsePositives: fp, falseNegatives: fn,
    engagementCount, generationConfidence,
  };

  // Evaluate each rule
  const evaluations: RuleEvaluation[] = [
    { rule: "minEngagements", threshold: rules.minEngagements, actual: engagementCount, passed: engagementCount >= rules.minEngagements },
    { rule: "minTotalScans", threshold: rules.minTotalScans, actual: totalScans, passed: totalScans >= rules.minTotalScans },
    { rule: "minPrecision", threshold: rules.minPrecision, actual: precision, passed: precision >= rules.minPrecision },
    { rule: "minRecall", threshold: rules.minRecall, actual: recall, passed: recall >= rules.minRecall },
    { rule: "minF1Score", threshold: rules.minF1Score, actual: f1Score, passed: f1Score >= rules.minF1Score },
    { rule: "maxFalsePositiveRate", threshold: rules.maxFalsePositiveRate, actual: fpRate, passed: fpRate <= rules.maxFalsePositiveRate },
    { rule: "minEffectivenessScore", threshold: rules.minEffectivenessScore, actual: effectivenessScore, passed: effectivenessScore >= rules.minEffectivenessScore },
    { rule: "minGenerationConfidence", threshold: rules.minGenerationConfidence, actual: generationConfidence, passed: generationConfidence >= rules.minGenerationConfidence },
  ];

  const passed = evaluations.filter(e => e.passed).length;
  const failed = evaluations.filter(e => !e.passed).length;
  const failedRules = evaluations.filter(e => !e.passed);

  // Decision logic
  let decision: "promoted" | "deferred" | "rejected";
  let newStatus: string;
  let reason: string;

  if (failed === 0) {
    // All rules passed → promote
    decision = "promoted";
    newStatus = "promoted";
    reason = `All ${passed} promotion rules passed. Template meets production quality thresholds: ` +
      `precision=${(precision * 100).toFixed(1)}%, recall=${(recall * 100).toFixed(1)}%, ` +
      `F1=${(f1Score * 100).toFixed(1)}%, effectiveness=${effectivenessScore.toFixed(0)}/100 ` +
      `across ${engagementCount} engagements (${totalScans} scans)`;
  } else if (fpRate > rules.maxFalsePositiveRate * 2) {
    // Excessive false positives → reject
    decision = "rejected";
    newStatus = "rejected";
    reason = `Template rejected due to excessive false positive rate: ${(fpRate * 100).toFixed(1)}% ` +
      `(threshold: ${(rules.maxFalsePositiveRate * 100).toFixed(1)}%). ` +
      `${fp} false positives out of ${tp + fp} total detections`;
  } else if (engagementCount < rules.minEngagements || totalScans < rules.minTotalScans) {
    // Not enough data yet → defer
    decision = "deferred";
    newStatus = template.status === "draft" ? "review" : template.status;
    reason = `Insufficient data for promotion decision. ` +
      `Engagements: ${engagementCount}/${rules.minEngagements}, Scans: ${totalScans}/${rules.minTotalScans}. ` +
      `Template moved to review for continued evaluation`;
  } else {
    // Some rules failed but not catastrophic → defer with details
    decision = "deferred";
    newStatus = "review";
    reason = `${failed} of ${passed + failed} rules failed: ` +
      failedRules.map(r => `${r.rule} (actual=${r.actual.toFixed(2)}, threshold=${r.threshold})`).join(", ") +
      `. Template needs improvement before promotion`;
  }

  return {
    templateId,
    generatedTemplateDbId: template.id,
    currentStatus: template.status,
    decision,
    newStatus,
    reason,
    rulesEvaluated: evaluations,
    rulesPassed: passed,
    rulesFailed: failed,
    metricsSnapshot,
  };
}

/**
 * Run auto-promotion evaluation for all eligible generated templates.
 * Called after each engagement's post-analysis completes.
 */
export async function runAutoPromotion(
  triggerEngagementId?: string,
  rules: PromotionRules = DEFAULT_PROMOTION_RULES,
): Promise<PromotionEvaluation[]> {
  const db = await getDbRequired();

  // Get all generated templates that are eligible for evaluation
  // (status: draft, review, or approved — not already promoted or rejected)
  const eligibleTemplates = await db
    .select()
    .from(scanforgeGeneratedTemplates)
    .where(
      inArray(scanforgeGeneratedTemplates.status, ["draft", "review", "approved"])
    );

  if (eligibleTemplates.length === 0) {
    return [];
  }

  // Get metrics for all eligible template IDs
  const templateIds = eligibleTemplates.map(t => t.templateId);
  const allMetrics = await db
    .select()
    .from(scanforgeTemplateMetrics)
    .where(inArray(scanforgeTemplateMetrics.templateId, templateIds));

  const metricsMap = new Map<string, ScanforgeTemplateMetricsRow>();
  for (const m of allMetrics) {
    metricsMap.set(m.templateId, m);
  }

  // Evaluate each template
  const evaluations: PromotionEvaluation[] = [];

  for (const template of eligibleTemplates) {
    const metrics = metricsMap.get(template.templateId) ?? null;
    const evaluation = evaluateTemplate(template, metrics, rules);
    evaluations.push(evaluation);

    // Apply the decision
    if (evaluation.decision !== "deferred" || evaluation.newStatus !== template.status) {
      // Update template status
      await db
        .update(scanforgeGeneratedTemplates)
        .set({
          status: evaluation.newStatus,
          reviewNotes: evaluation.reason,
        })
        .where(eq(scanforgeGeneratedTemplates.id, template.id));

      // Record in promotion history
      const historyEntry: InsertScanforgePromotionHistory = {
        templateId: template.templateId,
        generatedTemplateDbId: template.id,
        decision: evaluation.decision,
        reason: evaluation.reason,
        metricsSnapshot: evaluation.metricsSnapshot,
        rulesEvaluated: evaluation.rulesEvaluated,
        triggerEngagementId: triggerEngagementId ?? null,
        previousStatus: template.status,
        newStatus: evaluation.newStatus,
        evaluatedBy: "auto",
      };

      await db.insert(scanforgePromotionHistory).values(historyEntry);
    }
  }

  return evaluations;
}

/**
 * Manually promote a template (bypasses auto-evaluation rules).
 * Used by admin/operator to force-promote a template they trust.
 */
export async function manualPromote(
  generatedTemplateDbId: number,
  reason: string,
  evaluatedBy: string = "manual",
): Promise<PromotionEvaluation | null> {
  const db = await getDbRequired();

  const [template] = await db
    .select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.id, generatedTemplateDbId));

  if (!template) return null;

  // Get metrics for snapshot
  const [metrics] = await db
    .select()
    .from(scanforgeTemplateMetrics)
    .where(eq(scanforgeTemplateMetrics.templateId, template.templateId));

  const metricsSnapshot = metrics ? {
    precision: metrics.precision ?? 0,
    recall: metrics.recall ?? 0,
    f1Score: metrics.f1Score ?? 0,
    effectivenessScore: metrics.effectivenessScore ?? 0,
    totalScans: metrics.totalScans ?? 0,
    truePositives: metrics.truePositives ?? 0,
    falsePositives: metrics.falsePositives ?? 0,
    falseNegatives: metrics.falseNegatives ?? 0,
    engagementCount: ((metrics.engagementWindow as string[] | null) ?? []).length,
    generationConfidence: template.generationConfidence ?? 0.5,
  } : {
    precision: 0, recall: 0, f1Score: 0, effectivenessScore: 0,
    totalScans: 0, truePositives: 0, falsePositives: 0, falseNegatives: 0,
    engagementCount: 0, generationConfidence: template.generationConfidence ?? 0.5,
  };

  // Update template status
  await db
    .update(scanforgeGeneratedTemplates)
    .set({ status: "promoted", reviewNotes: `[Manual] ${reason}` })
    .where(eq(scanforgeGeneratedTemplates.id, generatedTemplateDbId));

  // Record history
  await db.insert(scanforgePromotionHistory).values({
    templateId: template.templateId,
    generatedTemplateDbId,
    decision: "promoted",
    reason: `[Manual] ${reason}`,
    metricsSnapshot,
    rulesEvaluated: [{ rule: "manual_override", threshold: 0, actual: 1, passed: true }],
    triggerEngagementId: null,
    previousStatus: template.status,
    newStatus: "promoted",
    evaluatedBy,
  });

  return {
    templateId: template.templateId,
    generatedTemplateDbId,
    currentStatus: template.status,
    decision: "promoted",
    newStatus: "promoted",
    reason: `[Manual] ${reason}`,
    rulesEvaluated: [{ rule: "manual_override", threshold: 0, actual: 1, passed: true }],
    rulesPassed: 1,
    rulesFailed: 0,
    metricsSnapshot,
  };
}

/**
 * Manually reject a template.
 */
export async function manualReject(
  generatedTemplateDbId: number,
  reason: string,
  evaluatedBy: string = "manual",
): Promise<void> {
  const db = await getDbRequired();

  const [template] = await db
    .select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.id, generatedTemplateDbId));

  if (!template) return;

  await db
    .update(scanforgeGeneratedTemplates)
    .set({ status: "rejected", reviewNotes: `[Manual] ${reason}` })
    .where(eq(scanforgeGeneratedTemplates.id, generatedTemplateDbId));

  const [metrics] = await db
    .select()
    .from(scanforgeTemplateMetrics)
    .where(eq(scanforgeTemplateMetrics.templateId, template.templateId));

  await db.insert(scanforgePromotionHistory).values({
    templateId: template.templateId,
    generatedTemplateDbId,
    decision: "rejected",
    reason: `[Manual] ${reason}`,
    metricsSnapshot: metrics ? {
      precision: metrics.precision ?? 0, recall: metrics.recall ?? 0,
      f1Score: metrics.f1Score ?? 0, effectivenessScore: metrics.effectivenessScore ?? 0,
      totalScans: metrics.totalScans ?? 0, truePositives: metrics.truePositives ?? 0,
      falsePositives: metrics.falsePositives ?? 0, falseNegatives: metrics.falseNegatives ?? 0,
      engagementCount: ((metrics.engagementWindow as string[] | null) ?? []).length,
      generationConfidence: template.generationConfidence ?? 0.5,
    } : { precision: 0, recall: 0, f1Score: 0, effectivenessScore: 0, totalScans: 0, truePositives: 0, falsePositives: 0, falseNegatives: 0, engagementCount: 0, generationConfidence: 0.5 },
    rulesEvaluated: [{ rule: "manual_rejection", threshold: 0, actual: 0, passed: false }],
    triggerEngagementId: null,
    previousStatus: template.status,
    newStatus: "rejected",
    evaluatedBy,
  });
}

/**
 * Get promotion history for a template or all templates.
 */
export async function getPromotionHistory(
  templateId?: string,
  limit: number = 50,
): Promise<any[]> {
  const db = await getDbRequired();

  if (templateId) {
    return db
      .select()
      .from(scanforgePromotionHistory)
      .where(eq(scanforgePromotionHistory.templateId, templateId))
      .orderBy(desc(scanforgePromotionHistory.createdAt))
      .limit(limit);
  }

  return db
    .select()
    .from(scanforgePromotionHistory)
    .orderBy(desc(scanforgePromotionHistory.createdAt))
    .limit(limit);
}

/**
 * Get promotion statistics summary.
 */
export async function getPromotionStats(): Promise<{
  totalEvaluated: number;
  promoted: number;
  deferred: number;
  rejected: number;
  pendingReview: number;
  avgPrecisionAtPromotion: number;
  avgF1AtPromotion: number;
}> {
  const db = await getDbRequired();

  // Count by decision in history
  const historyStats = await db
    .select({
      decision: scanforgePromotionHistory.decision,
      count: sql<number>`COUNT(*)`,
    })
    .from(scanforgePromotionHistory)
    .groupBy(scanforgePromotionHistory.decision);

  const counts: Record<string, number> = {};
  for (const row of historyStats) {
    counts[row.decision] = row.count;
  }

  // Count pending review templates
  const [pendingResult] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scanforgeGeneratedTemplates)
    .where(inArray(scanforgeGeneratedTemplates.status, ["draft", "review", "approved"]));

  // Get average metrics at promotion time
  const promotedHistory = await db
    .select({ metricsSnapshot: scanforgePromotionHistory.metricsSnapshot })
    .from(scanforgePromotionHistory)
    .where(eq(scanforgePromotionHistory.decision, "promoted"))
    .limit(100);

  let avgPrecision = 0;
  let avgF1 = 0;
  if (promotedHistory.length > 0) {
    let totalPrecision = 0;
    let totalF1 = 0;
    for (const row of promotedHistory) {
      const snap = row.metricsSnapshot as any;
      totalPrecision += snap?.precision ?? 0;
      totalF1 += snap?.f1Score ?? 0;
    }
    avgPrecision = totalPrecision / promotedHistory.length;
    avgF1 = totalF1 / promotedHistory.length;
  }

  return {
    totalEvaluated: Object.values(counts).reduce((a, b) => a + b, 0),
    promoted: counts["promoted"] ?? 0,
    deferred: counts["deferred"] ?? 0,
    rejected: counts["rejected"] ?? 0,
    pendingReview: pendingResult?.count ?? 0,
    avgPrecisionAtPromotion: avgPrecision,
    avgF1AtPromotion: avgF1,
  };
}
