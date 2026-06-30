/**
 * ScanForge Accuracy Tracker
 * 
 * Tracks every ScanForge finding per engagement, computes TP/FP/FN verdicts,
 * and maintains rolling accuracy metrics per template. Powers the self-improvement loop.
 * 
 * Architecture:
 *   1. logFinding() — called after each ScanForge detection, stores raw finding
 *   2. assessFindings() — post-engagement: cross-references with Nuclei/ZAP/manual results
 *   3. updateTemplateMetrics() — recomputes precision/recall/F1 per template
 *   4. getTemplateEffectiveness() — returns ranked templates for the confidence engine
 */

import { getDbRequired } from "../../db";
import { eq, and, desc, sql, inArray } from "drizzle-orm";
import {
  scanforgeFindingLog,
  scanforgeTemplateMetrics,
  scanforgeEngagementReport,
  type InsertScanforgeFindingLog,
  type InsertScanforgeEngagementReport,
} from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export type Verdict = "TP" | "FP" | "FN" | "PENDING";

export interface FindingLogEntry {
  engagementId: string;
  templateId: string;
  templateVersion?: string;
  target: string;
  findingTitle: string;
  severity: string;
  confidence: number;
  proofVerified?: boolean;
  findingData?: Record<string, any>;
}

export interface CrossToolMatch {
  tool: string; // nuclei, zap, sqlmap, xsstrike, manual
  findingId?: string;
  title: string;
  severity: string;
  matchConfidence: number; // 0-1 how closely this matches the ScanForge finding
}

export interface TemplateEffectiveness {
  templateId: string;
  precision: number;
  recall: number;
  f1Score: number;
  calibratedConfidence: number;
  effectivenessScore: number;
  totalScans: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
}

export interface EngagementComparisonReport {
  engagementId: string;
  scanforgeFindings: number;
  nucleiFindings: number;
  zapFindings: number;
  sharedFindings: number;
  scanforgeOnly: number;
  legacyOnly: number;
  scanforgePrecision: number;
  scanforgeRecall: number;
  scanforgeF1: number;
}

// ─── Finding Logger ─────────────────────────────────────────────────────────

/**
 * Log a ScanForge finding for accuracy tracking.
 * Called immediately after each detection during the scan phase.
 */
export async function logFinding(entry: FindingLogEntry): Promise<number> {
  const _db = await getDbRequired();
  const result = await _db.insert(scanforgeFindingLog).values({
    engagementId: entry.engagementId,
    templateId: entry.templateId,
    templateVersion: entry.templateVersion || "1.0.0",
    target: entry.target,
    findingTitle: entry.findingTitle,
    severity: entry.severity,
    confidence: entry.confidence,
    proofVerified: entry.proofVerified || false,
    findingData: entry.findingData || {},
    verdict: "PENDING",
  });
  return Number(result[0].insertId);
}

/**
 * Log multiple findings in a single batch insert.
 */
export async function logFindingsBatch(entries: FindingLogEntry[]): Promise<void> {
  if (entries.length === 0) return;
  const values = entries.map(e => ({
    engagementId: e.engagementId,
    templateId: e.templateId,
    templateVersion: e.templateVersion || "1.0.0",
    target: e.target,
    findingTitle: e.findingTitle,
    severity: e.severity,
    confidence: e.confidence,
    proofVerified: e.proofVerified || false,
    findingData: e.findingData || {},
    verdict: "PENDING" as const,
  }));
  const _db = await getDbRequired();
  await _db.insert(scanforgeFindingLog).values(values);
}

// ─── Verdict Assessment ─────────────────────────────────────────────────────

/**
 * Assess all PENDING findings for an engagement by cross-referencing with other tool results.
 * Called post-engagement after all scans complete.
 * 
 * @param engagementId - The engagement to assess
 * @param legacyFindings - Findings from Nuclei, ZAP, SQLMap, etc.
 * @param verdictSource - What performed the assessment (e.g., "auto-crossref", "llm-reassessment")
 */
export async function assessFindings(
  engagementId: string,
  legacyFindings: Array<{ tool: string; title: string; target: string; severity: string; cve?: string }>,
  verdictSource: string = "auto-crossref"
): Promise<{ assessed: number; tp: number; fp: number; fn: number }> {
  // Get all PENDING ScanForge findings for this engagement
  const _db = await getDbRequired();
  const pendingFindings = await _db.select()
    .from(scanforgeFindingLog)
    .where(and(
      eq(scanforgeFindingLog.engagementId, engagementId),
      eq(scanforgeFindingLog.verdict, "PENDING")
    ));

  let tp = 0, fp = 0;

  // Build a normalized index of legacy findings for fast matching
  const legacyIndex = new Map<string, typeof legacyFindings>();
  for (const lf of legacyFindings) {
    const key = normalizeTarget(lf.target);
    if (!legacyIndex.has(key)) legacyIndex.set(key, []);
    legacyIndex.get(key)!.push(lf);
  }

  // Assess each ScanForge finding
  for (const finding of pendingFindings) {
    const targetKey = normalizeTarget(finding.target);
    const candidates = legacyIndex.get(targetKey) || [];
    
    const matches = findCrossToolMatches(finding, candidates);
    
    if (matches.length > 0) {
      // Confirmed by at least one other tool → True Positive
      tp++;
      await _db.update(scanforgeFindingLog)
        .set({
          verdict: "TP",
          verdictSource,
          verdictReason: `Confirmed by ${matches.map(m => m.tool).join(", ")}`,
          crossToolMatches: matches,
          assessedAt: sql`CURRENT_TIMESTAMP`,
        })
        .where(eq(scanforgeFindingLog.id, finding.id));
    } else if (finding.proofVerified) {
      // Proof-verified but no legacy match → still TP (ScanForge found something others missed)
      tp++;
      await _db.update(scanforgeFindingLog)
        .set({
          verdict: "TP",
          verdictSource: "proof-verified",
          verdictReason: "Proof-based verification confirmed this finding even without legacy tool match",
          assessedAt: sql`CURRENT_TIMESTAMP`,
        })
        .where(eq(scanforgeFindingLog.id, finding.id));
    } else {
      // No match and no proof → False Positive (pending manual review)
      fp++;
      await _db.update(scanforgeFindingLog)
        .set({
          verdict: "FP",
          verdictSource,
          verdictReason: "No matching finding from legacy tools and no proof verification",
          assessedAt: sql`CURRENT_TIMESTAMP`,
        })
        .where(eq(scanforgeFindingLog.id, finding.id));
    }
  }

  // Find False Negatives: legacy findings that ScanForge missed
  const allScanforgeFindings = await _db.select()
    .from(scanforgeFindingLog)
    .where(eq(scanforgeFindingLog.engagementId, engagementId));

  let fn = 0;
  for (const lf of legacyFindings) {
    const matched = allScanforgeFindings.some(sf => 
      isSameFinding(sf, lf)
    );
    if (!matched) {
      fn++;
      // Log the missed finding as FN
      await _db.insert(scanforgeFindingLog).values({
        engagementId,
        templateId: "MISSED",
        target: lf.target,
        findingTitle: `[MISSED] ${lf.title}`,
        severity: lf.severity,
        confidence: 0,
        verdict: "FN",
        verdictSource,
        verdictReason: `Found by ${lf.tool} but missed by ScanForge`,
        crossToolMatches: [{ tool: lf.tool, title: lf.title, severity: lf.severity, matchConfidence: 1.0 }],
        assessedAt: sql`CURRENT_TIMESTAMP`,
      });
    }
  }

  return { assessed: pendingFindings.length, tp, fp, fn };
}

// ─── Template Metrics ───────────────────────────────────────────────────────

/**
 * Recompute accuracy metrics for all templates that had findings in this engagement.
 * Called after assessFindings() completes.
 */
export async function updateTemplateMetrics(engagementId: string): Promise<void> {
  // Get all assessed findings for this engagement
  const _db = await getDbRequired();
  const findings = await _db.select()
    .from(scanforgeFindingLog)
    .where(and(
      eq(scanforgeFindingLog.engagementId, engagementId),
      sql`${scanforgeFindingLog.verdict} != 'PENDING'`
    ));

  // Group by template
  const byTemplate = new Map<string, { tp: number; fp: number; fn: number }>();
  for (const f of findings) {
    const tid = f.templateId;
    if (!byTemplate.has(tid)) byTemplate.set(tid, { tp: 0, fp: 0, fn: 0 });
    const stats = byTemplate.get(tid)!;
    if (f.verdict === "TP") stats.tp++;
    else if (f.verdict === "FP") stats.fp++;
    else if (f.verdict === "FN") stats.fn++;
  }

  // Update or insert metrics for each template
  for (const [templateId, stats] of byTemplate) {
    if (templateId === "MISSED") continue; // Skip the FN placeholder entries

    const existing = await _db.select()
      .from(scanforgeTemplateMetrics)
      .where(eq(scanforgeTemplateMetrics.templateId, templateId))
      .limit(1);

    const totalTP = (existing[0]?.truePositives || 0) + stats.tp;
    const totalFP = (existing[0]?.falsePositives || 0) + stats.fp;
    const totalFN = (existing[0]?.falseNegatives || 0) + stats.fn;
    const totalScans = (existing[0]?.totalScans || 0) + stats.tp + stats.fp;

    const precision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 0;
    const recall = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

    // Effectiveness score: weighted combination of F1, volume, and recency
    const volumeBonus = Math.min(totalScans / 100, 0.2); // Up to 20% bonus for high volume
    const effectivenessScore = Math.min(100, (f1 * 80) + (volumeBonus * 100));

    // Calibrated confidence: adjust based on historical precision
    const calibratedConfidence = precision > 0 ? Math.max(0.1, Math.min(0.95, precision * 0.9 + 0.05)) : 0.5;

    // Update engagement window (keep last 20 engagement IDs)
    const existingWindow: string[] = (existing[0]?.engagementWindow as string[]) || [];
    const newWindow = [...existingWindow, engagementId].slice(-20);

    if (existing.length > 0) {
      await _db.update(scanforgeTemplateMetrics)
        .set({
          totalScans,
          truePositives: totalTP,
          falsePositives: totalFP,
          falseNegatives: totalFN,
          precision,
          recall,
          f1Score: f1,
          calibratedConfidence,
          effectivenessScore,
          engagementWindow: newWindow,
        })
        .where(eq(scanforgeTemplateMetrics.id, existing[0].id));
    } else {
      await _db.insert(scanforgeTemplateMetrics).values({
        templateId,
        totalScans,
        truePositives: totalTP,
        falsePositives: totalFP,
        falseNegatives: totalFN,
        precision,
        recall,
        f1Score: f1,
        calibratedConfidence,
        effectivenessScore,
        engagementWindow: newWindow,
      });
    }
  }
}

// ─── Engagement Comparison Report ───────────────────────────────────────────

/**
 * Generate a side-by-side comparison report for an engagement.
 * Shows what ScanForge found vs what legacy tools found.
 */
export async function generateEngagementReport(
  engagementId: string,
  legacyCounts: { nuclei: number; zap: number }
): Promise<EngagementComparisonReport> {
  const _db = await getDbRequired();
  const findings = await _db.select()
    .from(scanforgeFindingLog)
    .where(eq(scanforgeFindingLog.engagementId, engagementId));

  const scanforgeFindings = findings.filter(f => f.templateId !== "MISSED").length;
  const tp = findings.filter(f => f.verdict === "TP" && f.templateId !== "MISSED").length;
  const fp = findings.filter(f => f.verdict === "FP").length;
  const fn = findings.filter(f => f.verdict === "FN").length;

  const totalLegacy = legacyCounts.nuclei + legacyCounts.zap;
  const sharedFindings = tp; // TPs are findings confirmed by both
  const scanforgeOnly = findings.filter(f => f.verdict === "TP" && f.verdictSource === "proof-verified").length;
  const legacyOnly = fn;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  const report: EngagementComparisonReport = {
    engagementId,
    scanforgeFindings,
    nucleiFindings: legacyCounts.nuclei,
    zapFindings: legacyCounts.zap,
    sharedFindings,
    scanforgeOnly,
    legacyOnly,
    scanforgePrecision: precision,
    scanforgeRecall: recall,
    scanforgeF1: f1,
  };

  // Persist to DB
  await _db.insert(scanforgeEngagementReport).values({
    engagementId,
    scanforgeFindings,
    nucleiFindings: legacyCounts.nuclei,
    zapFindings: legacyCounts.zap,
    sharedFindings,
    scanforgeOnly,
    legacyOnly,
    scanforgePrecision: precision,
    scanforgeRecall: recall,
    scanforgeF1: f1,
  });

  return report;
}

// ─── Query Helpers ──────────────────────────────────────────────────────────

/**
 * Get template effectiveness rankings (for the self-tuning confidence engine).
 */
export async function getTemplateEffectiveness(
  minScans: number = 5
): Promise<TemplateEffectiveness[]> {
  const _db = await getDbRequired();
  const metrics = await _db.select()
    .from(scanforgeTemplateMetrics)
    .where(sql`${scanforgeTemplateMetrics.totalScans} >= ${minScans}`)
    .orderBy(desc(scanforgeTemplateMetrics.effectivenessScore));

  return metrics.map(m => ({
    templateId: m.templateId,
    precision: m.precision || 0,
    recall: m.recall || 0,
    f1Score: m.f1Score || 0,
    calibratedConfidence: m.calibratedConfidence || 0.5,
    effectivenessScore: m.effectivenessScore || 50,
    totalScans: m.totalScans,
    truePositives: m.truePositives,
    falsePositives: m.falsePositives,
    falseNegatives: m.falseNegatives,
  }));
}

/**
 * Get the calibrated confidence for a specific template.
 * Returns the self-tuned threshold, or default 0.5 if no data.
 */
export async function getCalibratedConfidence(templateId: string): Promise<number> {
  const _db = await getDbRequired();
  const rows = await _db.select({ calibratedConfidence: scanforgeTemplateMetrics.calibratedConfidence })
    .from(scanforgeTemplateMetrics)
    .where(eq(scanforgeTemplateMetrics.templateId, templateId))
    .limit(1);
  return rows[0]?.calibratedConfidence || 0.5;
}

/**
 * Get engagement comparison reports for dashboard display.
 */
export async function getEngagementReports(limit: number = 20) {
  const _db = await getDbRequired();
  return _db.select()
    .from(scanforgeEngagementReport)
    .orderBy(desc(scanforgeEngagementReport.createdAt))
    .limit(limit);
}

/**
 * Get all findings for an engagement (for the reassessment agent).
 */
export async function getEngagementFindings(engagementId: string) {
  const _db = await getDbRequired();
  return _db.select()
    .from(scanforgeFindingLog)
    .where(eq(scanforgeFindingLog.engagementId, engagementId))
    .orderBy(desc(scanforgeFindingLog.createdAt));
}

// ─── Matching Helpers ───────────────────────────────────────────────────────

function normalizeTarget(target: string): string {
  return target.toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "").replace(/:\d+$/, "");
}

function findCrossToolMatches(
  scanforgeFinding: { findingTitle: string; target: string; severity: string },
  legacyCandidates: Array<{ tool: string; title: string; target: string; severity: string; cve?: string }>
): CrossToolMatch[] {
  const matches: CrossToolMatch[] = [];
  const sfTitle = scanforgeFinding.findingTitle.toLowerCase();

  for (const candidate of legacyCandidates) {
    const ltTitle = candidate.title.toLowerCase();
    
    // Exact title match
    if (sfTitle === ltTitle) {
      matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: 1.0 });
      continue;
    }

    // Fuzzy match: check for shared keywords (vuln type + target)
    const sfWords = new Set(sfTitle.split(/[\s\-_\/]+/).filter(w => w.length > 3));
    const ltWords = new Set(ltTitle.split(/[\s\-_\/]+/).filter(w => w.length > 3));
    const shared = [...sfWords].filter(w => ltWords.has(w));
    const jaccardSimilarity = shared.length / (sfWords.size + ltWords.size - shared.length);

    if (jaccardSimilarity > 0.3) {
      matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: jaccardSimilarity });
    }

    // CVE match
    const sfCves = extractCVEs(scanforgeFinding.findingTitle);
    const ltCves = extractCVEs(candidate.title);
    if (sfCves.length > 0 && ltCves.length > 0) {
      const sharedCves = sfCves.filter(c => ltCves.includes(c));
      if (sharedCves.length > 0) {
        matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: 0.95 });
      }
    }
  }

  return matches;
}

function isSameFinding(
  sf: { findingTitle: string; target: string },
  lf: { title: string; target: string }
): boolean {
  const sfNorm = normalizeTarget(sf.target);
  const lfNorm = normalizeTarget(lf.target);
  if (sfNorm !== lfNorm) return false;

  const sfTitle = sf.findingTitle.toLowerCase().replace(/\[missed\]\s*/i, "");
  const lfTitle = lf.title.toLowerCase();

  // Exact match
  if (sfTitle === lfTitle) return true;

  // CVE match
  const sfCves = extractCVEs(sfTitle);
  const lfCves = extractCVEs(lfTitle);
  if (sfCves.length > 0 && lfCves.length > 0) {
    return sfCves.some(c => lfCves.includes(c));
  }

  // Keyword overlap
  const sfWords = new Set(sfTitle.split(/[\s\-_\/]+/).filter(w => w.length > 3));
  const lfWords = new Set(lfTitle.split(/[\s\-_\/]+/).filter(w => w.length > 3));
  const shared = [...sfWords].filter(w => lfWords.has(w));
  return shared.length / Math.max(sfWords.size, lfWords.size) > 0.5;
}

function extractCVEs(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi);
  return matches ? matches.map(m => m.toUpperCase()) : [];
}
