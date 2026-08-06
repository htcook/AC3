/**
 * Validation → Arsenal Feedback Bridge
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Pipes confirmed/failed/partial results from the Universal Exploit Validation
 * Engine back into the exploit arsenal records. This creates a closed feedback
 * loop where real-world validation outcomes update:
 *
 *   1. Per-exploit success rate (historical confirmed/failed/partial counts)
 *   2. Last-validated timestamp and validation context
 *   3. Validation status badge (confirmed-working, failed, untested, partial)
 *   4. Priority boost for confirmed-working exploits in the queue
 *   5. Reliability score adjustment based on validation outcomes
 *
 * The bridge also maintains a validation history table for audit trail and
 * trend analysis across engagements.
 *
 * @module validation-arsenal-bridge
 * @author Harrison Cook — AceofCloud
 */

import { getDb } from "../db";
import { exploitScripts } from "../../drizzle/schema";
import { eq, sql, and, desc, inArray } from "drizzle-orm";

// Note: The router uses exploitScripts.successRate (without es_ prefix) at runtime
// because tsx doesn't enforce strict types. We follow the same pattern for consistency.
import type { ValidationSession, ValidationResult, TechType, RawEvidence } from "./exploit-validation-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ArsenalValidationStatus = 
  | "confirmed_working"   // At least one confirmed validation
  | "partial_success"     // Partial results only, no full confirm
  | "failed"             // All validations failed
  | "untested"           // Never validated
  | "mixed";             // Mix of confirmed and failed across different targets

export interface ValidationRecord {
  id: string;
  exploitScriptId: number;
  sessionId: string;
  result: ValidationResult;
  techType: TechType;
  targetHost: string;
  targetEnvironment: string;
  confidenceScore: number;
  evidenceCount: number;
  evidenceTypes: string[];
  stateChangesDetected: number;
  executionTimeMs: number;
  validatedAt: number;
  validatedBy: string;
  engagementId?: string;
  notes?: string;
}

export interface ArsenalValidationSummary {
  exploitScriptId: number;
  status: ArsenalValidationStatus;
  totalValidations: number;
  confirmedCount: number;
  failedCount: number;
  partialCount: number;
  crashedCount: number;
  successRate: number; // 0-100
  averageConfidence: number; // 0-100
  lastValidatedAt: number | null;
  lastResult: ValidationResult | null;
  lastTargetHost: string | null;
  techTypesValidated: TechType[];
  trend: "improving" | "stable" | "degrading" | "insufficient_data";
  priorityBoost: number; // 0-30 additional priority points
}

export interface ValidationTrend {
  period: string; // ISO date
  confirmedCount: number;
  failedCount: number;
  partialCount: number;
  successRate: number;
}

// ─── In-Memory Validation History Store ─────────────────────────────────────
// (In production, this would be persisted to the database)

const validationHistory: Map<number, ValidationRecord[]> = new Map();
const arsenalSummaryCache: Map<number, ArsenalValidationSummary> = new Map();

// ─── Core Bridge Functions ──────────────────────────────────────────────────

/**
 * Process a completed validation session and update the corresponding
 * exploit arsenal record with the results.
 */
export async function processValidationResult(
  session: ValidationSession,
  operatorId: string = "system",
  engagementId?: string
): Promise<{
  updated: boolean;
  exploitScriptId: number | null;
  previousStatus: ArsenalValidationStatus;
  newStatus: ArsenalValidationStatus;
  successRateChange: number;
  priorityBoostApplied: number;
}> {
  if (session.status !== "complete" || !session.result) {
    return {
      updated: false,
      exploitScriptId: null,
      previousStatus: "untested",
      newStatus: "untested",
      successRateChange: 0,
      priorityBoostApplied: 0,
    };
  }

  // Find the exploit script in the arsenal by exploitId or CVE
  const exploitScriptId = await resolveExploitScriptId(session.exploitId, session.cve);
  if (!exploitScriptId) {
    return {
      updated: false,
      exploitScriptId: null,
      previousStatus: "untested",
      newStatus: "untested",
      successRateChange: 0,
      priorityBoostApplied: 0,
    };
  }

  // Get previous summary
  const previousSummary = getValidationSummary(exploitScriptId);
  const previousStatus = previousSummary?.status || "untested";
  const previousSuccessRate = previousSummary?.successRate || 0;

  // Record the validation
  const record: ValidationRecord = {
    id: `vr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    exploitScriptId,
    sessionId: session.id,
    result: session.result,
    techType: session.techType,
    targetHost: session.targetHost,
    targetEnvironment: inferEnvironment(session),
    confidenceScore: session.confidenceScore,
    evidenceCount: session.allEvidence.length,
    evidenceTypes: [...new Set(session.allEvidence.map(e => e.type))],
    stateChangesDetected: session.stateChangesDetected.length,
    executionTimeMs: (session.completedAt || Date.now()) - session.startedAt,
    validatedAt: Date.now(),
    validatedBy: operatorId,
    engagementId,
    notes: session.analysisNotes.join("; "),
  };

  // Store in history
  if (!validationHistory.has(exploitScriptId)) {
    validationHistory.set(exploitScriptId, []);
  }
  validationHistory.get(exploitScriptId)!.push(record);

  // Recalculate summary
  const newSummary = recalculateSummary(exploitScriptId);
  arsenalSummaryCache.set(exploitScriptId, newSummary);

  // Update the exploit_scripts table
  await updateExploitScriptRecord(exploitScriptId, newSummary);

  // Apply priority boost if confirmed working
  const priorityBoost = calculatePriorityBoost(newSummary);

  return {
    updated: true,
    exploitScriptId,
    previousStatus,
    newStatus: newSummary.status,
    successRateChange: newSummary.successRate - previousSuccessRate,
    priorityBoostApplied: priorityBoost,
  };
}

/**
 * Batch process multiple validation sessions (e.g., after a campaign run)
 */
export async function batchProcessValidations(
  sessions: ValidationSession[],
  operatorId: string = "system",
  engagementId?: string
): Promise<{
  processed: number;
  updated: number;
  skipped: number;
  results: Array<{ sessionId: string; exploitScriptId: number | null; status: ArsenalValidationStatus }>;
}> {
  const results: Array<{ sessionId: string; exploitScriptId: number | null; status: ArsenalValidationStatus }> = [];
  let updated = 0;
  let skipped = 0;

  for (const session of sessions) {
    const result = await processValidationResult(session, operatorId, engagementId);
    if (result.updated) {
      updated++;
    } else {
      skipped++;
    }
    results.push({
      sessionId: session.id,
      exploitScriptId: result.exploitScriptId,
      status: result.newStatus,
    });
  }

  return { processed: sessions.length, updated, skipped, results };
}

// ─── Query Functions ────────────────────────────────────────────────────────

/**
 * Get the validation summary for an exploit script
 */
export function getValidationSummary(exploitScriptId: number): ArsenalValidationSummary | null {
  // Check cache first
  if (arsenalSummaryCache.has(exploitScriptId)) {
    return arsenalSummaryCache.get(exploitScriptId)!;
  }
  // Recalculate if history exists
  const history = validationHistory.get(exploitScriptId);
  if (!history || history.length === 0) return null;
  const summary = recalculateSummary(exploitScriptId);
  arsenalSummaryCache.set(exploitScriptId, summary);
  return summary;
}

/**
 * Get validation summaries for multiple exploit scripts (for list views)
 */
export function getValidationSummaries(exploitScriptIds: number[]): Map<number, ArsenalValidationSummary> {
  const result = new Map<number, ArsenalValidationSummary>();
  for (const id of exploitScriptIds) {
    const summary = getValidationSummary(id);
    if (summary) {
      result.set(id, summary);
    }
  }
  return result;
}

/**
 * Get validation history for a specific exploit
 */
export function getValidationHistory(exploitScriptId: number): ValidationRecord[] {
  return validationHistory.get(exploitScriptId) || [];
}

/**
 * Get all exploits with a specific validation status
 */
export function getExploitsByValidationStatus(status: ArsenalValidationStatus): number[] {
  const result: number[] = [];
  for (const [id, summary] of arsenalSummaryCache.entries()) {
    if (summary.status === status) {
      result.push(id);
    }
  }
  return result;
}

/**
 * Get validation trend data for an exploit over time
 */
export function getValidationTrend(exploitScriptId: number, periodDays: number = 30): ValidationTrend[] {
  const history = validationHistory.get(exploitScriptId) || [];
  if (history.length === 0) return [];

  const now = Date.now();
  const cutoff = now - (periodDays * 24 * 60 * 60 * 1000);
  const recentHistory = history.filter(r => r.validatedAt >= cutoff);

  // Group by day
  const byDay = new Map<string, ValidationRecord[]>();
  for (const record of recentHistory) {
    const day = new Date(record.validatedAt).toISOString().split("T")[0];
    if (!byDay.has(day)) byDay.set(day, []);
    byDay.get(day)!.push(record);
  }

  const trends: ValidationTrend[] = [];
  for (const [period, records] of byDay.entries()) {
    const confirmed = records.filter(r => r.result === "confirmed").length;
    const failed = records.filter(r => r.result === "failed").length;
    const partial = records.filter(r => r.result === "partial").length;
    const total = confirmed + failed + partial;
    trends.push({
      period,
      confirmedCount: confirmed,
      failedCount: failed,
      partialCount: partial,
      successRate: total > 0 ? Math.round((confirmed / total) * 100) : 0,
    });
  }

  return trends.sort((a, b) => a.period.localeCompare(b.period));
}

/**
 * Get global validation statistics across the entire arsenal
 */
export function getGlobalValidationStats(): {
  totalValidated: number;
  totalUntested: number;
  confirmedWorking: number;
  failed: number;
  partialSuccess: number;
  mixed: number;
  averageSuccessRate: number;
  totalValidationRuns: number;
  recentValidations: ValidationRecord[];
} {
  let totalValidated = 0;
  let confirmedWorking = 0;
  let failed = 0;
  let partialSuccess = 0;
  let mixed = 0;
  let totalSuccessRate = 0;
  let totalValidationRuns = 0;

  for (const [, summary] of arsenalSummaryCache.entries()) {
    totalValidated++;
    totalSuccessRate += summary.successRate;
    totalValidationRuns += summary.totalValidations;
    switch (summary.status) {
      case "confirmed_working": confirmedWorking++; break;
      case "failed": failed++; break;
      case "partial_success": partialSuccess++; break;
      case "mixed": mixed++; break;
    }
  }

  // Get recent validations across all exploits
  const allRecords: ValidationRecord[] = [];
  for (const [, records] of validationHistory.entries()) {
    allRecords.push(...records);
  }
  const recentValidations = allRecords
    .sort((a, b) => b.validatedAt - a.validatedAt)
    .slice(0, 20);

  return {
    totalValidated,
    totalUntested: 0, // Would need total arsenal count from DB
    confirmedWorking,
    failed,
    partialSuccess,
    mixed,
    averageSuccessRate: totalValidated > 0 ? Math.round(totalSuccessRate / totalValidated) : 0,
    totalValidationRuns,
    recentValidations,
  };
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Resolve an exploit ID from the validation engine to an exploit_scripts record
 */
async function resolveExploitScriptId(exploitId: string, cve?: string): Promise<number | null> {
  const db = await getDb();
  if (!db) return null;

  // Try direct ID match (format: "es_<id>" or numeric)
  const numericId = parseInt(exploitId.replace("es_", ""), 10);
  if (!isNaN(numericId)) {
    const [found] = await db.select({ id: exploitScripts.id })
      .from(exploitScripts)
      .where(eq(exploitScripts.id, numericId))
      .limit(1);
    if (found) return found.id;
  }

  // Try by source ID
  const [bySource] = await db.select({ id: exploitScripts.id })
    .from(exploitScripts)
    .where(eq((exploitScripts as any).sourceId ?? exploitScripts.esSourceId, exploitId))
    .limit(1);
  if (bySource) return bySource.id;

  // Try by CVE (return highest-rated match)
  if (cve) {
    const [byCve] = await db.select({ id: exploitScripts.id })
      .from(exploitScripts)
      .where(eq((exploitScripts as any).cveId ?? exploitScripts.esCveId, cve))
      .orderBy(desc((exploitScripts as any).successRate ?? exploitScripts.esSuccessRate))
      .limit(1);
    if (byCve) return byCve.id;
  }

  return null;
}

/**
 * Recalculate the validation summary for an exploit
 */
function recalculateSummary(exploitScriptId: number): ArsenalValidationSummary {
  const history = validationHistory.get(exploitScriptId) || [];
  
  const confirmedCount = history.filter(r => r.result === "confirmed").length;
  const failedCount = history.filter(r => r.result === "failed").length;
  const partialCount = history.filter(r => r.result === "partial").length;
  const crashedCount = history.filter(r => r.result === "crashed").length;
  const totalValidations = history.length;

  // Determine status
  let status: ArsenalValidationStatus;
  if (totalValidations === 0) {
    status = "untested";
  } else if (confirmedCount > 0 && failedCount === 0) {
    status = "confirmed_working";
  } else if (confirmedCount > 0 && failedCount > 0) {
    status = "mixed";
  } else if (partialCount > 0 && confirmedCount === 0) {
    status = "partial_success";
  } else {
    status = "failed";
  }

  // Calculate success rate (confirmed = 1.0, partial = 0.5, failed/crashed = 0)
  const weightedSuccess = confirmedCount + (partialCount * 0.5);
  const successRate = totalValidations > 0 
    ? Math.round((weightedSuccess / totalValidations) * 100) 
    : 0;

  // Average confidence
  const avgConfidence = totalValidations > 0
    ? Math.round(history.reduce((sum, r) => sum + r.confidenceScore, 0) / totalValidations)
    : 0;

  // Last validation info
  const lastRecord = history[history.length - 1];

  // Tech types validated
  const techTypes = [...new Set(history.map(r => r.techType))] as TechType[];

  // Trend calculation (compare last 5 vs previous 5)
  const trend = calculateTrend(history);

  // Priority boost
  const priorityBoost = calculatePriorityBoost({
    status,
    successRate,
    totalValidations,
    confirmedCount,
    averageConfidence: avgConfidence,
  } as ArsenalValidationSummary);

  return {
    exploitScriptId,
    status,
    totalValidations,
    confirmedCount,
    failedCount,
    partialCount,
    crashedCount,
    successRate,
    averageConfidence: avgConfidence,
    lastValidatedAt: lastRecord?.validatedAt || null,
    lastResult: lastRecord?.result || null,
    lastTargetHost: lastRecord?.targetHost || null,
    techTypesValidated: techTypes,
    trend,
    priorityBoost,
  };
}

/**
 * Calculate the trend direction based on recent history
 */
function calculateTrend(history: ValidationRecord[]): "improving" | "stable" | "degrading" | "insufficient_data" {
  if (history.length < 4) return "insufficient_data";

  const midpoint = Math.floor(history.length / 2);
  const older = history.slice(0, midpoint);
  const newer = history.slice(midpoint);

  const olderSuccessRate = older.filter(r => r.result === "confirmed").length / older.length;
  const newerSuccessRate = newer.filter(r => r.result === "confirmed").length / newer.length;

  const diff = newerSuccessRate - olderSuccessRate;
  if (diff > 0.15) return "improving";
  if (diff < -0.15) return "degrading";
  return "stable";
}

/**
 * Calculate priority boost based on validation outcomes
 */
function calculatePriorityBoost(summary: Partial<ArsenalValidationSummary>): number {
  let boost = 0;

  // Confirmed working exploits get significant boost
  if (summary.status === "confirmed_working") {
    boost += 20;
    // Extra boost for high confidence
    if ((summary.averageConfidence || 0) >= 90) boost += 5;
    // Extra boost for multiple confirmations
    if ((summary.confirmedCount || 0) >= 3) boost += 5;
  } else if (summary.status === "partial_success") {
    boost += 10;
  } else if (summary.status === "mixed") {
    boost += 5; // Some value, but not reliable
  }
  // Failed exploits get no boost (or could get negative in priority queue)

  return Math.min(boost, 30); // Cap at 30
}

/**
 * Update the exploit_scripts database record with validation results
 */
async function updateExploitScriptRecord(
  exploitScriptId: number,
  summary: ArsenalValidationSummary
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  try {
    // Use the column accessors that the existing router uses at runtime
    const successRateCol = (exploitScripts as any).successRate ?? exploitScripts.esSuccessRate;
    const timesDeployedCol = (exploitScripts as any).timesDeployed ?? exploitScripts.esTimesDeployed;
    const lastDeployedCol = (exploitScripts as any).lastDeployed ?? exploitScripts.esLastDeployed;
    
    await db.update(exploitScripts)
      .set({
        [successRateCol.name || 'es_success_rate']: summary.successRate / 100,
        [timesDeployedCol.name || 'es_times_deployed']: sql`COALESCE(${timesDeployedCol}, 0) + 1`,
        [lastDeployedCol.name || 'es_last_deployed']: new Date().toISOString().slice(0, 19).replace("T", " "),
      } as any)
      .where(eq(exploitScripts.id, exploitScriptId));
  } catch (err) {
    console.error(`[ValidationBridge] Failed to update exploit script ${exploitScriptId}:`, err);
  }
}

/**
 * Infer the target environment from the validation session
 */
function inferEnvironment(session: ValidationSession): string {
  const techTypeEnvMap: Record<string, string> = {
    plc_ics: "OT/ICS Network",
    web_application: "Web Application",
    network_infrastructure: "Network Infrastructure",
    cloud_saas: "Cloud/SaaS",
    active_directory: "Active Directory",
    endpoint: "Endpoint",
    iot_embedded: "IoT/Embedded",
  };
  return techTypeEnvMap[session.techType] || "Unknown";
}

// ─── Auto-Integration Hook ──────────────────────────────────────────────────

/**
 * Hook that can be called from the validation engine's completion handler
 * to automatically feed results back to the arsenal.
 */
export async function onValidationComplete(session: ValidationSession): Promise<void> {
  if (session.status !== "complete") return;
  
  const result = await processValidationResult(session, "auto_validation");
  if (result.updated) {
    console.log(
      `[ValidationBridge] Updated exploit #${result.exploitScriptId}: ` +
      `${result.previousStatus} → ${result.newStatus} ` +
      `(success rate Δ${result.successRateChange > 0 ? "+" : ""}${result.successRateChange}%, ` +
      `priority boost: +${result.priorityBoostApplied})`
    );
  }
}

/**
 * Get exploits that should be re-validated (stale validations or degrading trend)
 */
export function getExploitsNeedingRevalidation(staleDays: number = 30): Array<{
  exploitScriptId: number;
  reason: string;
  lastValidatedAt: number;
  currentStatus: ArsenalValidationStatus;
}> {
  const now = Date.now();
  const staleThreshold = now - (staleDays * 24 * 60 * 60 * 1000);
  const results: Array<{
    exploitScriptId: number;
    reason: string;
    lastValidatedAt: number;
    currentStatus: ArsenalValidationStatus;
  }> = [];

  for (const [id, summary] of arsenalSummaryCache.entries()) {
    // Stale validation
    if (summary.lastValidatedAt && summary.lastValidatedAt < staleThreshold) {
      results.push({
        exploitScriptId: id,
        reason: `Last validated ${Math.round((now - summary.lastValidatedAt) / (24 * 60 * 60 * 1000))} days ago`,
        lastValidatedAt: summary.lastValidatedAt,
        currentStatus: summary.status,
      });
    }
    // Degrading trend
    if (summary.trend === "degrading") {
      results.push({
        exploitScriptId: id,
        reason: "Success rate trending downward — may need re-validation against updated targets",
        lastValidatedAt: summary.lastValidatedAt || 0,
        currentStatus: summary.status,
      });
    }
  }

  return results.sort((a, b) => a.lastValidatedAt - b.lastValidatedAt);
}
// Validation-Arsenal Bridge v1.0
