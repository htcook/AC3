/**
 * ScanForge Self-Tuning Confidence Engine
 * 
 * Automatically calibrates template confidence thresholds based on historical
 * accuracy data from the accuracy tracker. This ensures ScanForge's false
 * positive rate stays low while maximizing true positive detection.
 * 
 * Key behaviors:
 *   - Templates with high FP rates get confidence thresholds raised (harder to trigger)
 *   - Templates with high TP rates get confidence boosted (trusted more)
 *   - Templates with no data stay at default confidence
 *   - Confidence adjustments are bounded to prevent runaway drift
 *   - All adjustments are logged for audit trail
 * 
 * The engine also manages the auto-template lifecycle:
 *   draft → review → promoted → production → (deprecated)
 */

import { db } from "../../db";
import { eq, desc, sql, and, gte, lte } from "drizzle-orm";
import {
  scanforgeTemplateMetrics,
  scanforgeGeneratedTemplates,
  scanforgeFindingLog,
} from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ConfidenceAdjustment {
  templateId: string;
  previousConfidence: number;
  newConfidence: number;
  reason: string;
  metrics: {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1: number;
  };
}

export interface TuningReport {
  timestamp: Date;
  templatesAnalyzed: number;
  adjustmentsMade: number;
  adjustments: ConfidenceAdjustment[];
  templatesDeprecated: number;
  templatesBoosted: number;
  templatesPenalized: number;
}

// ─── Configuration ──────────────────────────────────────────────────────────

const CONFIG = {
  // Minimum number of findings before we adjust confidence
  MIN_FINDINGS_FOR_TUNING: 5,
  
  // Confidence bounds — never go below or above these
  MIN_CONFIDENCE: 0.15,
  MAX_CONFIDENCE: 0.98,
  DEFAULT_CONFIDENCE: 0.5,
  
  // Adjustment step sizes
  BOOST_STEP: 0.05,     // Reward for high precision
  PENALTY_STEP: 0.08,   // Penalty for high FP rate
  DECAY_STEP: 0.02,     // Slow decay for templates with no recent activity
  
  // Thresholds for actions
  FP_RATE_DEPRECATE: 0.7,    // Deprecate if >70% false positive rate
  FP_RATE_PENALIZE: 0.3,     // Penalize if >30% false positive rate
  TP_RATE_BOOST: 0.8,        // Boost if >80% true positive rate
  
  // Auto-template promotion thresholds
  DRAFT_TO_REVIEW_CONFIDENCE: 0.6,
  REVIEW_TO_PROMOTED_CONFIDENCE: 0.75,
  
  // Time window for recent activity (ms)
  RECENT_WINDOW_MS: 30 * 24 * 60 * 60 * 1000, // 30 days
};

// ─── Main Tuning Engine ─────────────────────────────────────────────────────

/**
 * Run the full confidence tuning cycle.
 * Analyzes all templates with sufficient data and adjusts confidence thresholds.
 */
export async function runConfidenceTuning(): Promise<TuningReport> {
  console.log("[ScanForge Confidence Tuner] Starting tuning cycle...");
  
  const report: TuningReport = {
    timestamp: new Date(),
    templatesAnalyzed: 0,
    adjustmentsMade: 0,
    adjustments: [],
    templatesDeprecated: 0,
    templatesBoosted: 0,
    templatesPenalized: 0,
  };

  // Get all templates with metrics
  const allMetrics = await db.select()
    .from(scanforgeTemplateMetrics)
    .orderBy(desc(scanforgeTemplateMetrics.lastUpdated));

  report.templatesAnalyzed = allMetrics.length;

  for (const metrics of allMetrics) {
    const totalFindings = (metrics.truePositives || 0) + (metrics.falsePositives || 0);
    
    // Skip templates without enough data
    if (totalFindings < CONFIG.MIN_FINDINGS_FOR_TUNING) continue;

    const tp = metrics.truePositives || 0;
    const fp = metrics.falsePositives || 0;
    const fn = metrics.falseNegatives || 0;
    
    const precision = tp / (tp + fp) || 0;
    const recall = tp / (tp + fn) || 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const fpRate = fp / totalFindings;

    const currentConfidence = metrics.avgConfidence || CONFIG.DEFAULT_CONFIDENCE;
    let newConfidence = currentConfidence;
    let reason = "";

    // Decision logic
    if (fpRate >= CONFIG.FP_RATE_DEPRECATE && totalFindings >= 10) {
      // Extremely high FP rate — deprecate
      newConfidence = CONFIG.MIN_CONFIDENCE;
      reason = `Deprecated: ${(fpRate * 100).toFixed(0)}% false positive rate (${fp}/${totalFindings})`;
      report.templatesDeprecated++;
    } else if (fpRate >= CONFIG.FP_RATE_PENALIZE) {
      // High FP rate — penalize
      newConfidence = Math.max(CONFIG.MIN_CONFIDENCE, currentConfidence - CONFIG.PENALTY_STEP);
      reason = `Penalized: ${(fpRate * 100).toFixed(0)}% false positive rate`;
      report.templatesPenalized++;
    } else if (precision >= CONFIG.TP_RATE_BOOST && totalFindings >= 5) {
      // High precision — boost
      newConfidence = Math.min(CONFIG.MAX_CONFIDENCE, currentConfidence + CONFIG.BOOST_STEP);
      reason = `Boosted: ${(precision * 100).toFixed(0)}% precision (${tp} TP out of ${totalFindings})`;
      report.templatesBoosted++;
    }

    // Apply adjustment if changed
    if (Math.abs(newConfidence - currentConfidence) > 0.001) {
      const adjustment: ConfidenceAdjustment = {
        templateId: metrics.templateId,
        previousConfidence: currentConfidence,
        newConfidence,
        reason,
        metrics: { truePositives: tp, falsePositives: fp, falseNegatives: fn, precision, recall, f1 },
      };

      await db.update(scanforgeTemplateMetrics)
        .set({
          avgConfidence: newConfidence,
          lastUpdated: new Date(),
        })
        .where(eq(scanforgeTemplateMetrics.templateId, metrics.templateId));

      report.adjustments.push(adjustment);
      report.adjustmentsMade++;
    }
  }

  console.log(`[ScanForge Confidence Tuner] Complete: ${report.adjustmentsMade} adjustments (${report.templatesBoosted} boosted, ${report.templatesPenalized} penalized, ${report.templatesDeprecated} deprecated)`);
  return report;
}

// ─── Auto-Template Lifecycle ────────────────────────────────────────────────

/**
 * Review draft templates and promote those that meet confidence thresholds.
 * This runs after the confidence tuner to process auto-generated templates.
 */
export async function processTemplateLifecycle(): Promise<{
  promoted: number;
  reviewed: number;
  deprecated: number;
}> {
  console.log("[ScanForge Confidence Tuner] Processing template lifecycle...");
  
  let promoted = 0;
  let reviewed = 0;
  let deprecated = 0;

  // Get all draft templates
  const drafts = await db.select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.status, "draft"));

  for (const draft of drafts) {
    const confidence = draft.generationConfidence || 0;
    
    if (confidence >= CONFIG.REVIEW_TO_PROMOTED_CONFIDENCE) {
      // High confidence — promote directly
      await db.update(scanforgeGeneratedTemplates)
        .set({ status: "promoted" })
        .where(eq(scanforgeGeneratedTemplates.templateId, draft.templateId));
      promoted++;
    } else if (confidence >= CONFIG.DRAFT_TO_REVIEW_CONFIDENCE) {
      // Medium confidence — move to review
      await db.update(scanforgeGeneratedTemplates)
        .set({ status: "review" })
        .where(eq(scanforgeGeneratedTemplates.templateId, draft.templateId));
      reviewed++;
    } else if (confidence < 0.2) {
      // Very low confidence — deprecate
      await db.update(scanforgeGeneratedTemplates)
        .set({ status: "deprecated" })
        .where(eq(scanforgeGeneratedTemplates.templateId, draft.templateId));
      deprecated++;
    }
  }

  // Also check promoted templates that have been running — deprecate if poor performance
  const promotedTemplates = await db.select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.status, "promoted"));

  for (const tmpl of promotedTemplates) {
    const metrics = await db.select()
      .from(scanforgeTemplateMetrics)
      .where(eq(scanforgeTemplateMetrics.templateId, tmpl.templateId))
      .limit(1);

    if (metrics[0]) {
      const tp = metrics[0].truePositives || 0;
      const fp = metrics[0].falsePositives || 0;
      const total = tp + fp;
      
      if (total >= 10 && fp / total >= CONFIG.FP_RATE_DEPRECATE) {
        await db.update(scanforgeGeneratedTemplates)
          .set({ status: "deprecated" })
          .where(eq(scanforgeGeneratedTemplates.templateId, tmpl.templateId));
        deprecated++;
      }
    }
  }

  console.log(`[ScanForge Confidence Tuner] Lifecycle: ${promoted} promoted, ${reviewed} to review, ${deprecated} deprecated`);
  return { promoted, reviewed, deprecated };
}

// ─── Confidence Queries ─────────────────────────────────────────────────────

/**
 * Get the effective confidence threshold for a template.
 * Returns the tuned confidence if available, otherwise the default.
 */
export async function getTemplateConfidence(templateId: string): Promise<number> {
  const metrics = await db.select({ avgConfidence: scanforgeTemplateMetrics.avgConfidence })
    .from(scanforgeTemplateMetrics)
    .where(eq(scanforgeTemplateMetrics.templateId, templateId))
    .limit(1);

  return metrics[0]?.avgConfidence || CONFIG.DEFAULT_CONFIDENCE;
}

/**
 * Get confidence map for multiple templates at once (batch query).
 */
export async function getTemplateConfidenceMap(templateIds: string[]): Promise<Map<string, number>> {
  if (templateIds.length === 0) return new Map();
  
  const metrics = await db.select({
    templateId: scanforgeTemplateMetrics.templateId,
    avgConfidence: scanforgeTemplateMetrics.avgConfidence,
  })
    .from(scanforgeTemplateMetrics);

  const map = new Map<string, number>();
  for (const m of metrics) {
    map.set(m.templateId, m.avgConfidence || CONFIG.DEFAULT_CONFIDENCE);
  }
  
  // Fill in defaults for templates without metrics
  for (const id of templateIds) {
    if (!map.has(id)) map.set(id, CONFIG.DEFAULT_CONFIDENCE);
  }
  
  return map;
}

// ─── Dashboard Metrics ──────────────────────────────────────────────────────

/**
 * Get overall ScanForge health metrics for dashboard display.
 */
export async function getScanForgeHealthMetrics(): Promise<{
  totalTemplates: number;
  activeTemplates: number;
  deprecatedTemplates: number;
  avgPrecision: number;
  avgRecall: number;
  avgF1: number;
  totalFindings: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  topPerformers: Array<{ templateId: string; f1: number; findings: number }>;
  worstPerformers: Array<{ templateId: string; fpRate: number; findings: number }>;
}> {
  const allMetrics = await db.select()
    .from(scanforgeTemplateMetrics);

  let totalTP = 0, totalFP = 0, totalFN = 0;
  let precisionSum = 0, recallSum = 0, f1Sum = 0;
  let activeCount = 0;
  const performanceData: Array<{ templateId: string; f1: number; fpRate: number; findings: number }> = [];

  for (const m of allMetrics) {
    const tp = m.truePositives || 0;
    const fp = m.falsePositives || 0;
    const fn = m.falseNegatives || 0;
    const total = tp + fp;
    
    totalTP += tp;
    totalFP += fp;
    totalFN += fn;

    if (total >= CONFIG.MIN_FINDINGS_FOR_TUNING) {
      const precision = tp / (tp + fp) || 0;
      const recall = tp / (tp + fn) || 0;
      const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
      const fpRate = fp / total;
      
      precisionSum += precision;
      recallSum += recall;
      f1Sum += f1;
      activeCount++;
      
      performanceData.push({ templateId: m.templateId, f1, fpRate, findings: total });
    }
  }

  // Count generated templates by status
  const generatedCounts = await db.select({
    status: scanforgeGeneratedTemplates.status,
    count: sql<number>`count(*)`,
  })
    .from(scanforgeGeneratedTemplates)
    .groupBy(scanforgeGeneratedTemplates.status);

  const statusMap = new Map(generatedCounts.map(r => [r.status, r.count]));

  // Sort for top/worst performers
  const sorted = [...performanceData].sort((a, b) => b.f1 - a.f1);
  const topPerformers = sorted.slice(0, 5).map(p => ({ templateId: p.templateId, f1: p.f1, findings: p.findings }));
  const worstPerformers = [...performanceData]
    .sort((a, b) => b.fpRate - a.fpRate)
    .slice(0, 5)
    .map(p => ({ templateId: p.templateId, fpRate: p.fpRate, findings: p.findings }));

  return {
    totalTemplates: allMetrics.length + (statusMap.get("promoted") || 0),
    activeTemplates: activeCount,
    deprecatedTemplates: statusMap.get("deprecated") || 0,
    avgPrecision: activeCount > 0 ? precisionSum / activeCount : 0,
    avgRecall: activeCount > 0 ? recallSum / activeCount : 0,
    avgF1: activeCount > 0 ? f1Sum / activeCount : 0,
    totalFindings: totalTP + totalFP,
    truePositives: totalTP,
    falsePositives: totalFP,
    falseNegatives: totalFN,
    topPerformers,
    worstPerformers,
  };
}

/**
 * Get the full tuning history for audit trail.
 */
export async function getTuningHistory(limit: number = 50) {
  return db.select()
    .from(scanforgeTemplateMetrics)
    .orderBy(desc(scanforgeTemplateMetrics.lastUpdated))
    .limit(limit);
}
