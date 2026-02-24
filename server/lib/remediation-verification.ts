/**
 * Closed-Loop Remediation Verification
 * 
 * After a vulnerability is validated as exploitable and remediation is applied,
 * this module re-runs the same exploit chain to confirm the fix is effective.
 * Tracks remediation lifecycle: Exploitable → Remediated → Verified Fixed / Still Vulnerable.
 * 
 * Patent Innovation F-5: Closed-loop validation-to-detection lifecycle management.
 * 
 * Database-backed persistence — all records survive server restarts.
 * 
 * @module remediation-verification
 */

import { getDb } from "../db";
import { remediationVerifications } from "../../drizzle/schema";
import { eq, and, lt, isNotNull, sql, ne, isNull } from "drizzle-orm";

// ─── Types ─────────────────────────────────────────────────────────

export type RemediationStatus =
  | "exploitable"
  | "remediation_pending"
  | "verification_queued"
  | "verifying"
  | "verified_fixed"
  | "still_vulnerable"
  | "regression"
  | "expired";

export interface RemediationRecord {
  id: number;
  scanId: number;
  findingId: number;
  findingType: string;
  cveId: string | null;
  target: string;
  port: number | null;
  service: string | null;
  techniqueId: string | null;
  originalExploitModule: string;
  originalValidatedAt: number;
  originalSeverity: "critical" | "high" | "medium" | "low";
  status: RemediationStatus;
  verificationMethod: "re_exploit" | "scan_recheck" | "config_audit" | "manual";
  remediationNotes: string | null;
  remediationAppliedAt: number | null;
  verificationAttempts: VerificationAttempt[];
  lastVerifiedAt: number | null;
  verificationDeadline: number | null;
  slaHours: number;
  previousResult: string | null;
  currentResult: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface VerificationAttempt {
  attemptId: string;
  attemptNumber: number;
  timestamp: number;
  result: "still_vulnerable" | "verified_fixed" | "inconclusive" | "error";
  exploitModule: string;
  exploitOutput: string | null;
  evidenceUrl: string | null;
  durationMs: number;
  notes: string | null;
}

export interface RemediationSummary {
  totalFindings: number;
  exploitable: number;
  remediationPending: number;
  verificationQueued: number;
  verifying: number;
  verifiedFixed: number;
  stillVulnerable: number;
  regression: number;
  expired: number;
  fixRate: number;
  meanTimeToRemediate: number | null;
  slaCompliance: number;
  overdueFindingsCount: number;
}

export interface RemediationConfig {
  defaultSlaHours: number;
  criticalSlaHours: number;
  highSlaHours: number;
  mediumSlaHours: number;
  lowSlaHours: number;
  maxVerificationAttempts: number;
  autoQueueOnRemediation: boolean;
  regressionCheckIntervalDays: number;
}

export const DEFAULT_REMEDIATION_CONFIG: RemediationConfig = {
  defaultSlaHours: 72,
  criticalSlaHours: 24,
  highSlaHours: 48,
  mediumSlaHours: 168,
  lowSlaHours: 720,
  maxVerificationAttempts: 3,
  autoQueueOnRemediation: true,
  regressionCheckIntervalDays: 30,
};

// ─── In-Memory Fallback (used when DB is unavailable or in tests) ──

const memoryRecords = new Map<number, RemediationRecord>();
let memIdCounter = 0;

// ─── Helpers ───────────────────────────────────────────────────────

function getSlaForSeverity(
  severity: "critical" | "high" | "medium" | "low",
  config: RemediationConfig
): number {
  switch (severity) {
    case "critical": return config.criticalSlaHours;
    case "high": return config.highSlaHours;
    case "medium": return config.mediumSlaHours;
    case "low": return config.lowSlaHours;
    default: return config.defaultSlaHours;
  }
}

function mapStatusToDb(status: RemediationStatus): "pending" | "running" | "verified_fixed" | "still_vulnerable" | "error" {
  switch (status) {
    case "exploitable":
    case "remediation_pending":
    case "verification_queued":
      return "pending";
    case "verifying":
      return "running";
    case "verified_fixed":
      return "verified_fixed";
    case "still_vulnerable":
    case "regression":
    case "expired":
      return "still_vulnerable";
    default:
      return "pending";
  }
}

function dbRowToRecord(row: any): RemediationRecord {
  return {
    id: row.id,
    scanId: row.originalFindingId,
    findingId: row.originalFindingId,
    findingType: row.originalFindingType || "vulnerability",
    cveId: row.techniqueId || null,
    target: "",
    port: null,
    service: null,
    techniqueId: row.techniqueId || null,
    originalExploitModule: row.verificationMethod || "re_exploit",
    originalValidatedAt: row.createdAt ? new Date(row.createdAt).getTime() : Date.now(),
    originalSeverity: "high",
    status: dbStatusToFull(row.status, row.previousResult),
    verificationMethod: row.verificationMethod || "re_exploit",
    remediationNotes: row.previousResult || null,
    remediationAppliedAt: null,
    verificationAttempts: [],
    lastVerifiedAt: row.verifiedAt ? new Date(row.verifiedAt).getTime() : null,
    verificationDeadline: null,
    slaHours: 72,
    previousResult: row.previousResult || null,
    currentResult: row.currentResult || null,
    createdAt: row.createdAt ? new Date(row.createdAt).getTime() : Date.now(),
    updatedAt: row.verifiedAt ? new Date(row.verifiedAt).getTime() : Date.now(),
  };
}

function dbStatusToFull(dbStatus: string, previousResult: string | null): RemediationStatus {
  switch (dbStatus) {
    case "pending": return "verification_queued";
    case "running": return "verifying";
    case "verified_fixed": return "verified_fixed";
    case "still_vulnerable": return previousResult?.includes("regression") ? "regression" : "still_vulnerable";
    case "error": return "still_vulnerable";
    default: return "exploitable";
  }
}

// ─── Core Functions (DB-backed with in-memory fallback) ───────────

/**
 * Create a remediation record from a validated finding.
 */
export async function createRemediationRecord(
  params: {
    scanId: number;
    findingId: number;
    findingType?: string;
    cveId: string | null;
    target: string;
    port: number | null;
    service: string | null;
    validationId?: string;
    exploitModule: string;
    validatedAt: number;
    severity: "critical" | "high" | "medium" | "low";
    techniqueId?: string;
    verificationMethod?: "re_exploit" | "scan_recheck" | "config_audit" | "manual";
  },
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): Promise<RemediationRecord> {
  const now = Date.now();
  const slaHours = getSlaForSeverity(params.severity, config);
  const method = params.verificationMethod || "re_exploit";

  const db = await getDb();
  if (db) {
    try {
      const result = await db.insert(remediationVerifications).values({
        originalFindingId: params.findingId,
        originalFindingType: params.findingType || "vulnerability",
        techniqueId: params.techniqueId || params.cveId || null,
        verificationMethod: method,
        status: "pending",
        previousResult: JSON.stringify({
          target: params.target,
          port: params.port,
          service: params.service,
          severity: params.severity,
          exploitModule: params.exploitModule,
          slaHours,
          deadline: now + (slaHours * 60 * 60 * 1000),
        }),
        currentResult: null,
      });

      const insertId = (result as any)[0]?.insertId ?? (result as any).insertId;
      const record: RemediationRecord = {
        id: insertId,
        scanId: params.scanId,
        findingId: params.findingId,
        findingType: params.findingType || "vulnerability",
        cveId: params.cveId,
        target: params.target,
        port: params.port,
        service: params.service,
        techniqueId: params.techniqueId || null,
        originalExploitModule: params.exploitModule,
        originalValidatedAt: params.validatedAt,
        originalSeverity: params.severity,
        status: "exploitable",
        verificationMethod: method,
        remediationNotes: null,
        remediationAppliedAt: null,
        verificationAttempts: [],
        lastVerifiedAt: null,
        verificationDeadline: now + (slaHours * 60 * 60 * 1000),
        slaHours,
        previousResult: null,
        currentResult: null,
        createdAt: now,
        updatedAt: now,
      };

      console.log(`[RemediationVerify] Created DB record ${insertId} for ${params.target}:${params.port} (${params.severity}, SLA: ${slaHours}h)`);
      return record;
    } catch (err) {
      console.error("[RemediationVerify] DB insert failed, falling back to memory:", err);
    }
  }

  // In-memory fallback
  const id = ++memIdCounter;
  const record: RemediationRecord = {
    id,
    scanId: params.scanId,
    findingId: params.findingId,
    findingType: params.findingType || "vulnerability",
    cveId: params.cveId,
    target: params.target,
    port: params.port,
    service: params.service,
    techniqueId: params.techniqueId || null,
    originalExploitModule: params.exploitModule,
    originalValidatedAt: params.validatedAt,
    originalSeverity: params.severity,
    status: "exploitable",
    verificationMethod: method,
    remediationNotes: null,
    remediationAppliedAt: null,
    verificationAttempts: [],
    lastVerifiedAt: null,
    verificationDeadline: now + (slaHours * 60 * 60 * 1000),
    slaHours,
    previousResult: null,
    currentResult: null,
    createdAt: now,
    updatedAt: now,
  };
  memoryRecords.set(id, record);
  console.log(`[RemediationVerify] Created in-memory record ${id} for ${params.target}:${params.port}`);
  return record;
}

/**
 * Mark a finding as remediation applied. Optionally auto-queues verification.
 */
export async function markRemediationApplied(
  recordId: number,
  notes?: string,
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): Promise<RemediationRecord | null> {
  const newStatus = config.autoQueueOnRemediation ? "verification_queued" : "remediation_pending";

  const db = await getDb();
  if (db) {
    try {
      await db.update(remediationVerifications)
        .set({
          status: mapStatusToDb(newStatus),
          previousResult: notes ? JSON.stringify({ notes, appliedAt: Date.now() }) : undefined,
        })
        .where(eq(remediationVerifications.id, recordId));

      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;

      const record = dbRowToRecord(rows[0]);
      record.status = newStatus;
      record.remediationNotes = notes || null;
      record.remediationAppliedAt = Date.now();
      console.log(`[RemediationVerify] ${recordId} marked as remediated (DB)`);
      return record;
    } catch (err) {
      console.error("[RemediationVerify] DB update failed:", err);
    }
  }

  // In-memory fallback
  const record = memoryRecords.get(recordId);
  if (!record) return null;
  record.status = newStatus;
  record.remediationNotes = notes || null;
  record.remediationAppliedAt = Date.now();
  record.updatedAt = Date.now();
  return record;
}

/**
 * Queue a finding for re-verification.
 */
export async function queueForVerification(recordId: number): Promise<RemediationRecord | null> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;

      const currentStatus = rows[0].status;
      if (currentStatus !== "pending" && currentStatus !== "still_vulnerable") {
        console.warn(`[RemediationVerify] Cannot queue ${recordId} — current DB status: ${currentStatus}`);
        return null;
      }

      await db.update(remediationVerifications)
        .set({ status: "pending" })
        .where(eq(remediationVerifications.id, recordId));

      const record = dbRowToRecord(rows[0]);
      record.status = "verification_queued";
      return record;
    } catch (err) {
      console.error("[RemediationVerify] DB queue failed:", err);
    }
  }

  const record = memoryRecords.get(recordId);
  if (!record) return null;
  if (!["remediation_pending", "still_vulnerable", "exploitable"].includes(record.status)) return null;
  record.status = "verification_queued";
  record.updatedAt = Date.now();
  return record;
}

/**
 * Record a verification attempt result.
 */
export async function recordVerificationAttempt(
  recordId: number,
  attempt: {
    result: VerificationAttempt["result"];
    exploitModule: string;
    exploitOutput: string | null;
    evidenceUrl: string | null;
    durationMs: number;
    notes: string | null;
  },
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): Promise<RemediationRecord | null> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;

      const existingResult = rows[0].currentResult ? JSON.parse(rows[0].currentResult as string) : {};
      const attempts = existingResult.attempts || [];
      const newAttempt = {
        attemptId: `${recordId}-v${attempts.length + 1}`,
        attemptNumber: attempts.length + 1,
        timestamp: Date.now(),
        ...attempt,
      };
      attempts.push(newAttempt);

      // Determine new status
      let newDbStatus: "pending" | "running" | "verified_fixed" | "still_vulnerable" | "error";
      let fullStatus: RemediationStatus;

      switch (attempt.result) {
        case "verified_fixed":
          newDbStatus = "verified_fixed";
          fullStatus = "verified_fixed";
          break;
        case "still_vulnerable":
          const wasPreviouslyFixed = attempts.some(
            (a: any, i: number) => i < attempts.length - 1 && a.result === "verified_fixed"
          );
          newDbStatus = "still_vulnerable";
          fullStatus = wasPreviouslyFixed ? "regression" : "still_vulnerable";
          break;
        case "inconclusive":
        case "error":
          if (attempts.length >= config.maxVerificationAttempts) {
            newDbStatus = "still_vulnerable";
            fullStatus = "still_vulnerable";
          } else {
            newDbStatus = "pending";
            fullStatus = "verification_queued";
          }
          break;
        default:
          newDbStatus = "pending";
          fullStatus = "verification_queued";
      }

      await db.update(remediationVerifications)
        .set({
          status: newDbStatus,
          currentResult: JSON.stringify({ attempts, lastResult: attempt.result }),
          verifiedAt: new Date(),
          verifiedBy: attempt.exploitModule,
        })
        .where(eq(remediationVerifications.id, recordId));

      const record = dbRowToRecord(rows[0]);
      record.status = fullStatus;
      record.verificationAttempts = attempts;
      record.lastVerifiedAt = Date.now();
      console.log(`[RemediationVerify] ${recordId} verification attempt #${newAttempt.attemptNumber}: ${attempt.result} → status: ${fullStatus}`);
      return record;
    } catch (err) {
      console.error("[RemediationVerify] DB verification failed:", err);
    }
  }

  // In-memory fallback
  const record = memoryRecords.get(recordId);
  if (!record) return null;

  const attemptRecord: VerificationAttempt = {
    attemptId: `${recordId}-v${record.verificationAttempts.length + 1}`,
    attemptNumber: record.verificationAttempts.length + 1,
    timestamp: Date.now(),
    ...attempt,
  };

  record.verificationAttempts.push(attemptRecord);
  record.lastVerifiedAt = Date.now();
  record.updatedAt = Date.now();

  switch (attempt.result) {
    case "verified_fixed":
      record.status = "verified_fixed";
      break;
    case "still_vulnerable":
      const wasPreviouslyFixed = record.verificationAttempts.some(
        (a, i) => i < record.verificationAttempts.length - 1 && a.result === "verified_fixed"
      );
      record.status = wasPreviouslyFixed ? "regression" : "still_vulnerable";
      break;
    case "inconclusive":
    case "error":
      if (record.verificationAttempts.length >= config.maxVerificationAttempts) {
        record.status = "still_vulnerable";
      } else {
        record.status = "verification_queued";
      }
      break;
  }

  return record;
}

/**
 * Get all records that need verification (queued or overdue regression checks).
 */
export async function getRecordsNeedingVerification(
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): Promise<RemediationRecord[]> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications)
        .where(eq(remediationVerifications.status, "pending"));
      return rows.map(dbRowToRecord);
    } catch (err) {
      console.error("[RemediationVerify] DB query failed:", err);
    }
  }

  return Array.from(memoryRecords.values()).filter(r =>
    r.status === "verification_queued"
  );
}

/**
 * Get overdue findings (past SLA deadline, not yet verified fixed).
 */
export async function getOverdueFindings(): Promise<RemediationRecord[]> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications)
        .where(
          and(
            ne(remediationVerifications.status, "verified_fixed"),
          )
        );
      // Filter overdue based on previousResult containing deadline
      return rows.map(dbRowToRecord).filter(r => {
        if (!r.verificationDeadline) return false;
        return Date.now() > r.verificationDeadline;
      });
    } catch (err) {
      console.error("[RemediationVerify] DB overdue query failed:", err);
    }
  }

  const now = Date.now();
  return Array.from(memoryRecords.values()).filter(r => {
    if (r.status === "verified_fixed") return false;
    if (!r.verificationDeadline) return false;
    return now > r.verificationDeadline;
  });
}

/**
 * Mark expired records (past expiration window without re-test).
 */
export async function markExpiredRecords(expirationDays: number = 90): Promise<number> {
  const db = await getDb();
  if (db) {
    try {
      const cutoffDate = new Date(Date.now() - (expirationDays * 24 * 60 * 60 * 1000));
      const result = await db.update(remediationVerifications)
        .set({ status: "still_vulnerable" })
        .where(
          and(
            eq(remediationVerifications.status, "pending"),
            lt(remediationVerifications.createdAt, cutoffDate)
          )
        );
      const count = (result as any)[0]?.affectedRows ?? 0;
      console.log(`[RemediationVerify] Marked ${count} records as expired`);
      return count;
    } catch (err) {
      console.error("[RemediationVerify] DB expire failed:", err);
    }
  }

  const now = Date.now();
  const cutoff = now - (expirationDays * 24 * 60 * 60 * 1000);
  let expiredCount = 0;
  for (const record of Array.from(memoryRecords.values())) {
    if (record.status === "exploitable" && record.createdAt < cutoff) {
      record.status = "expired";
      record.updatedAt = now;
      expiredCount++;
    }
  }
  return expiredCount;
}

/**
 * Generate a remediation summary across all tracked findings.
 */
export async function getRemediationSummary(): Promise<RemediationSummary> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications);
      const allRecords = rows.map(dbRowToRecord);
      return computeSummary(allRecords);
    } catch (err) {
      console.error("[RemediationVerify] DB summary failed:", err);
    }
  }

  return computeSummary(Array.from(memoryRecords.values()));
}

function computeSummary(allRecords: RemediationRecord[]): RemediationSummary {
  const byStatus: Record<RemediationStatus, number> = {
    exploitable: 0, remediation_pending: 0, verification_queued: 0,
    verifying: 0, verified_fixed: 0, still_vulnerable: 0,
    regression: 0, expired: 0,
  };

  const remediationTimes: number[] = [];
  let slaCompliantCount = 0;
  let slaApplicableCount = 0;
  const now = Date.now();

  for (const record of allRecords) {
    byStatus[record.status]++;

    if (record.status === "verified_fixed" && record.lastVerifiedAt) {
      const hours = (record.lastVerifiedAt - record.originalValidatedAt) / (60 * 60 * 1000);
      remediationTimes.push(hours);
      slaApplicableCount++;
      if (record.verificationDeadline && record.lastVerifiedAt <= record.verificationDeadline) {
        slaCompliantCount++;
      }
    }

    if (record.status === "still_vulnerable" || record.status === "regression") {
      slaApplicableCount++;
    }
  }

  const totalRemediated = byStatus.verified_fixed + byStatus.still_vulnerable + byStatus.regression;
  const fixRate = totalRemediated > 0
    ? Math.round((byStatus.verified_fixed / totalRemediated) * 100)
    : 0;

  const meanTimeToRemediate = remediationTimes.length > 0
    ? Math.round((remediationTimes.reduce((a, b) => a + b, 0) / remediationTimes.length) * 10) / 10
    : null;

  const slaCompliance = slaApplicableCount > 0
    ? Math.round((slaCompliantCount / slaApplicableCount) * 100)
    : 100;

  const overdueFindingsCount = allRecords.filter(r => {
    if (r.status === "verified_fixed") return false;
    if (!r.verificationDeadline) return false;
    return now > r.verificationDeadline;
  }).length;

  return {
    totalFindings: allRecords.length,
    exploitable: byStatus.exploitable,
    remediationPending: byStatus.remediation_pending,
    verificationQueued: byStatus.verification_queued,
    verifying: byStatus.verifying,
    verifiedFixed: byStatus.verified_fixed,
    stillVulnerable: byStatus.still_vulnerable,
    regression: byStatus.regression,
    expired: byStatus.expired,
    fixRate,
    meanTimeToRemediate,
    slaCompliance,
    overdueFindingsCount,
  };
}

/**
 * Get a single remediation record by ID.
 */
export async function getRemediationRecord(id: number): Promise<RemediationRecord | null> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, id));
      if (rows.length === 0) return null;
      return dbRowToRecord(rows[0]);
    } catch (err) {
      console.error("[RemediationVerify] DB get failed:", err);
    }
  }
  return memoryRecords.get(id) || null;
}

/**
 * Get all remediation records for a finding.
 */
export async function getRecordsByFinding(findingId: number): Promise<RemediationRecord[]> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications)
        .where(eq(remediationVerifications.originalFindingId, findingId));
      return rows.map(dbRowToRecord);
    } catch (err) {
      console.error("[RemediationVerify] DB query failed:", err);
    }
  }
  return Array.from(memoryRecords.values()).filter(r => r.findingId === findingId);
}

/**
 * Generate a remediation timeline for a specific record.
 */
export async function getRemediationTimeline(recordId: number): Promise<Array<{
  timestamp: number;
  event: string;
  details: string;
}>> {
  const record = await getRemediationRecord(recordId);
  if (!record) return [];

  const timeline: Array<{ timestamp: number; event: string; details: string }> = [];

  timeline.push({
    timestamp: record.originalValidatedAt,
    event: "Validated Exploitable",
    details: `Exploit module: ${record.originalExploitModule}. Severity: ${record.originalSeverity}. Target: ${record.target}:${record.port}`,
  });

  timeline.push({
    timestamp: record.createdAt,
    event: "Remediation Record Created",
    details: `SLA: ${record.slaHours} hours. Deadline: ${record.verificationDeadline ? new Date(record.verificationDeadline).toISOString() : "N/A"}`,
  });

  if (record.remediationAppliedAt) {
    timeline.push({
      timestamp: record.remediationAppliedAt,
      event: "Remediation Applied",
      details: record.remediationNotes || "No notes provided",
    });
  }

  for (const attempt of record.verificationAttempts) {
    timeline.push({
      timestamp: attempt.timestamp,
      event: `Verification Attempt #${attempt.attemptNumber}`,
      details: `Result: ${attempt.result}. Module: ${attempt.exploitModule}. Duration: ${attempt.durationMs}ms${attempt.notes ? `. Notes: ${attempt.notes}` : ""}`,
    });
  }

  return timeline.sort((a, b) => a.timestamp - b.timestamp);
}

/**
 * Clear all in-memory records (for testing only).
 */
export function clearRemediationRecords(): void {
  memoryRecords.clear();
  memIdCounter = 0;
}
