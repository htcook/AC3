/**
 * Closed-Loop Remediation Verification
 * 
 * After a vulnerability is validated as exploitable and remediation is applied,
 * this module re-runs the same exploit chain to confirm the fix is effective.
 * Tracks remediation lifecycle: Exploitable → Remediated → Verified Fixed / Still Vulnerable.
 * 
 * Matches Horizon3 NodeZero's "1-Click Verify" capability.
 * 
 * @module remediation-verification
 */

// ─── Types ─────────────────────────────────────────────────────────

export type RemediationStatus =
  | "exploitable"         // Initial validation confirmed exploitable
  | "remediation_pending" // Marked for remediation, awaiting fix
  | "verification_queued" // Re-validation scheduled
  | "verifying"           // Re-validation in progress
  | "verified_fixed"      // Re-validation confirmed fix is effective
  | "still_vulnerable"    // Re-validation found vulnerability persists
  | "regression"          // Was fixed, but re-appeared in later check
  | "expired";            // Verification window expired without re-test

export interface RemediationRecord {
  id: string;
  scanId: number;
  findingId: string;
  cveId: string | null;
  target: string;
  port: number | null;
  service: string | null;
  originalValidationId: string;
  originalExploitModule: string;
  originalValidatedAt: number;
  originalSeverity: "critical" | "high" | "medium" | "low";
  status: RemediationStatus;
  remediationNotes: string | null;
  remediationAppliedAt: number | null;
  verificationAttempts: VerificationAttempt[];
  lastVerifiedAt: number | null;
  verificationDeadline: number | null;
  slaHours: number;
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
  fixRate: number;           // % of remediated findings that are verified fixed
  meanTimeToRemediate: number | null; // Average hours from exploitable → verified_fixed
  slaCompliance: number;     // % of findings verified within SLA
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
  mediumSlaHours: 168,   // 7 days
  lowSlaHours: 720,      // 30 days
  maxVerificationAttempts: 3,
  autoQueueOnRemediation: true,
  regressionCheckIntervalDays: 30,
};

// ─── In-Memory Store ───────────────────────────────────────────────

const records = new Map<string, RemediationRecord>();
let idCounter = 0;

function generateId(): string {
  return `rem-${Date.now()}-${++idCounter}`;
}

// ─── Core Functions ────────────────────────────────────────────────

/**
 * Create a remediation record from a validated finding.
 * Called automatically when validation confirms a finding is exploitable.
 */
export function createRemediationRecord(
  params: {
    scanId: number;
    findingId: string;
    cveId: string | null;
    target: string;
    port: number | null;
    service: string | null;
    validationId: string;
    exploitModule: string;
    validatedAt: number;
    severity: "critical" | "high" | "medium" | "low";
  },
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): RemediationRecord {
  const id = generateId();
  const now = Date.now();
  
  // Determine SLA based on severity
  const slaHours = getSlaForSeverity(params.severity, config);
  
  const record: RemediationRecord = {
    id,
    scanId: params.scanId,
    findingId: params.findingId,
    cveId: params.cveId,
    target: params.target,
    port: params.port,
    service: params.service,
    originalValidationId: params.validationId,
    originalExploitModule: params.exploitModule,
    originalValidatedAt: params.validatedAt,
    originalSeverity: params.severity,
    status: "exploitable",
    remediationNotes: null,
    remediationAppliedAt: null,
    verificationAttempts: [],
    lastVerifiedAt: null,
    verificationDeadline: now + (slaHours * 60 * 60 * 1000),
    slaHours,
    createdAt: now,
    updatedAt: now,
  };
  
  records.set(id, record);
  console.log(`[RemediationVerify] Created record ${id} for ${params.target}:${params.port} (${params.severity}, SLA: ${slaHours}h)`);
  return record;
}

/**
 * Mark a finding as remediation applied.
 * Optionally auto-queues verification.
 */
export function markRemediationApplied(
  recordId: string,
  notes?: string,
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): RemediationRecord | null {
  const record = records.get(recordId);
  if (!record) return null;
  
  record.status = config.autoQueueOnRemediation ? "verification_queued" : "remediation_pending";
  record.remediationNotes = notes || null;
  record.remediationAppliedAt = Date.now();
  record.updatedAt = Date.now();
  
  console.log(`[RemediationVerify] ${recordId} marked as remediated${config.autoQueueOnRemediation ? " (auto-queued for verification)" : ""}`);
  return record;
}

/**
 * Queue a finding for re-verification.
 */
export function queueForVerification(recordId: string): RemediationRecord | null {
  const record = records.get(recordId);
  if (!record) return null;
  
  if (record.status !== "remediation_pending" && record.status !== "still_vulnerable" && record.status !== "exploitable") {
    console.warn(`[RemediationVerify] Cannot queue ${recordId} — current status: ${record.status}`);
    return null;
  }
  
  record.status = "verification_queued";
  record.updatedAt = Date.now();
  return record;
}

/**
 * Record a verification attempt result.
 * This is called after the validation engine re-runs the exploit.
 */
export function recordVerificationAttempt(
  recordId: string,
  attempt: {
    result: VerificationAttempt["result"];
    exploitModule: string;
    exploitOutput: string | null;
    evidenceUrl: string | null;
    durationMs: number;
    notes: string | null;
  },
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): RemediationRecord | null {
  const record = records.get(recordId);
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
  
  // Determine new status based on result
  switch (attempt.result) {
    case "verified_fixed":
      record.status = "verified_fixed";
      break;
    case "still_vulnerable":
      // Check if this was previously fixed (regression)
      const wasPreviouslyFixed = record.verificationAttempts.some(
        (a, i) => i < record.verificationAttempts.length - 1 && a.result === "verified_fixed"
      );
      record.status = wasPreviouslyFixed ? "regression" : "still_vulnerable";
      break;
    case "inconclusive":
    case "error":
      // Keep current status, allow retry
      if (record.verificationAttempts.length >= config.maxVerificationAttempts) {
        record.status = "still_vulnerable"; // Assume still vulnerable after max attempts
      } else {
        record.status = "verification_queued"; // Re-queue for another attempt
      }
      break;
  }
  
  console.log(`[RemediationVerify] ${recordId} verification attempt #${attemptRecord.attemptNumber}: ${attempt.result} → status: ${record.status}`);
  return record;
}

/**
 * Get all records that need verification (queued or overdue).
 */
export function getRecordsNeedingVerification(
  config: RemediationConfig = DEFAULT_REMEDIATION_CONFIG
): RemediationRecord[] {
  const now = Date.now();
  const results: RemediationRecord[] = [];
  
  for (const record of Array.from(records.values())) {
    // Queued for verification
    if (record.status === "verification_queued") {
      results.push(record);
      continue;
    }
    
    // Previously fixed — check for regression
    if (record.status === "verified_fixed" && record.lastVerifiedAt) {
      const daysSinceVerification = (now - record.lastVerifiedAt) / (24 * 60 * 60 * 1000);
      if (daysSinceVerification >= config.regressionCheckIntervalDays) {
        results.push(record);
      }
    }
  }
  
  return results;
}

/**
 * Get overdue findings (past SLA deadline, not yet verified fixed).
 */
export function getOverdueFindings(): RemediationRecord[] {
  const now = Date.now();
  return Array.from(records.values()).filter(r => {
    if (r.status === "verified_fixed") return false;
    if (!r.verificationDeadline) return false;
    return now > r.verificationDeadline;
  });
}

/**
 * Check all records and mark expired ones.
 */
export function markExpiredRecords(expirationDays: number = 90): number {
  const now = Date.now();
  const cutoff = now - (expirationDays * 24 * 60 * 60 * 1000);
  let expiredCount = 0;
  
  for (const record of Array.from(records.values())) {
    if (
      record.status === "exploitable" &&
      record.createdAt < cutoff
    ) {
      record.status = "expired";
      record.updatedAt = now;
      expiredCount++;
    }
  }
  
  return expiredCount;
}

// ─── Summary & Reporting ───────────────────────────────────────────

/**
 * Generate a remediation summary across all tracked findings.
 */
export function getRemediationSummary(): RemediationSummary {
  const all = Array.from(records.values());
  const now = Date.now();
  
  const byStatus: Record<RemediationStatus, number> = {
    exploitable: 0,
    remediation_pending: 0,
    verification_queued: 0,
    verifying: 0,
    verified_fixed: 0,
    still_vulnerable: 0,
    regression: 0,
    expired: 0,
  };
  
  const remediationTimes: number[] = [];
  let slaCompliantCount = 0;
  let slaApplicableCount = 0;
  
  for (const record of all) {
    byStatus[record.status]++;
    
    // Calculate mean time to remediate for verified_fixed records
    if (record.status === "verified_fixed" && record.lastVerifiedAt) {
      const hours = (record.lastVerifiedAt - record.originalValidatedAt) / (60 * 60 * 1000);
      remediationTimes.push(hours);
      
      // SLA compliance
      slaApplicableCount++;
      if (record.verificationDeadline && record.lastVerifiedAt <= record.verificationDeadline) {
        slaCompliantCount++;
      }
    }
    
    // Also count still_vulnerable and regression for SLA tracking
    if (record.status === "still_vulnerable" || record.status === "regression") {
      slaApplicableCount++;
      // These are not compliant
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
  
  const overdueFindingsCount = all.filter(r => {
    if (r.status === "verified_fixed") return false;
    if (!r.verificationDeadline) return false;
    return now > r.verificationDeadline;
  }).length;
  
  return {
    totalFindings: all.length,
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
export function getRemediationRecord(id: string): RemediationRecord | null {
  return records.get(id) || null;
}

/**
 * Get all remediation records for a scan.
 */
export function getRecordsByScan(scanId: number): RemediationRecord[] {
  return Array.from(records.values()).filter(r => r.scanId === scanId);
}

/**
 * Get all remediation records for a specific target.
 */
export function getRecordsByTarget(target: string): RemediationRecord[] {
  return Array.from(records.values()).filter(r => r.target === target);
}

/**
 * Generate a remediation timeline for a specific record.
 * Returns a chronological list of events.
 */
export function getRemediationTimeline(recordId: string): Array<{
  timestamp: number;
  event: string;
  details: string;
}> {
  const record = records.get(recordId);
  if (!record) return [];
  
  const timeline: Array<{ timestamp: number; event: string; details: string }> = [];
  
  // Initial validation
  timeline.push({
    timestamp: record.originalValidatedAt,
    event: "Validated Exploitable",
    details: `Exploit module: ${record.originalExploitModule}. Severity: ${record.originalSeverity}. Target: ${record.target}:${record.port}`,
  });
  
  // Record created
  timeline.push({
    timestamp: record.createdAt,
    event: "Remediation Record Created",
    details: `SLA: ${record.slaHours} hours. Deadline: ${record.verificationDeadline ? new Date(record.verificationDeadline).toISOString() : "N/A"}`,
  });
  
  // Remediation applied
  if (record.remediationAppliedAt) {
    timeline.push({
      timestamp: record.remediationAppliedAt,
      event: "Remediation Applied",
      details: record.remediationNotes || "No notes provided",
    });
  }
  
  // Verification attempts
  for (const attempt of record.verificationAttempts) {
    timeline.push({
      timestamp: attempt.timestamp,
      event: `Verification Attempt #${attempt.attemptNumber}`,
      details: `Result: ${attempt.result}. Module: ${attempt.exploitModule}. Duration: ${attempt.durationMs}ms${attempt.notes ? `. Notes: ${attempt.notes}` : ""}`,
    });
  }
  
  return timeline.sort((a, b) => a.timestamp - b.timestamp);
}

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

/**
 * Clear all records (for testing).
 */
export function clearRemediationRecords(): void {
  records.clear();
  idCounter = 0;
}
