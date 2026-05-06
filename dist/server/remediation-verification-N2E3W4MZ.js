import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  remediationVerifications
} from "./chunk-GM677ZS3.js";
import "./chunk-KFQGP6VL.js";

// server/lib/remediation-verification.ts
init_db();
init_schema();
import { eq, and, lt, ne } from "drizzle-orm";
var DEFAULT_REMEDIATION_CONFIG = {
  defaultSlaHours: 72,
  criticalSlaHours: 24,
  highSlaHours: 48,
  mediumSlaHours: 168,
  lowSlaHours: 720,
  maxVerificationAttempts: 3,
  autoQueueOnRemediation: true,
  regressionCheckIntervalDays: 30
};
var memoryRecords = /* @__PURE__ */ new Map();
var memIdCounter = 0;
function getSlaForSeverity(severity, config) {
  switch (severity) {
    case "critical":
      return config.criticalSlaHours;
    case "high":
      return config.highSlaHours;
    case "medium":
      return config.mediumSlaHours;
    case "low":
      return config.lowSlaHours;
    default:
      return config.defaultSlaHours;
  }
}
function mapStatusToDb(status) {
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
function dbRowToRecord(row) {
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
    updatedAt: row.verifiedAt ? new Date(row.verifiedAt).getTime() : Date.now()
  };
}
function dbStatusToFull(dbStatus, previousResult) {
  switch (dbStatus) {
    case "pending":
      return "verification_queued";
    case "running":
      return "verifying";
    case "verified_fixed":
      return "verified_fixed";
    case "still_vulnerable":
      return previousResult?.includes("regression") ? "regression" : "still_vulnerable";
    case "error":
      return "still_vulnerable";
    default:
      return "exploitable";
  }
}
async function createRemediationRecord(params, config = DEFAULT_REMEDIATION_CONFIG) {
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
          deadline: now + slaHours * 60 * 60 * 1e3
        }),
        currentResult: null
      });
      const insertId = result[0]?.insertId ?? result.insertId;
      const record2 = {
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
        verificationDeadline: now + slaHours * 60 * 60 * 1e3,
        slaHours,
        previousResult: null,
        currentResult: null,
        createdAt: now,
        updatedAt: now
      };
      console.log(`[RemediationVerify] Created DB record ${insertId} for ${params.target}:${params.port} (${params.severity}, SLA: ${slaHours}h)`);
      return record2;
    } catch (err) {
      console.error("[RemediationVerify] DB insert failed, falling back to memory:", err);
    }
  }
  const id = ++memIdCounter;
  const record = {
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
    verificationDeadline: now + slaHours * 60 * 60 * 1e3,
    slaHours,
    previousResult: null,
    currentResult: null,
    createdAt: now,
    updatedAt: now
  };
  memoryRecords.set(id, record);
  console.log(`[RemediationVerify] Created in-memory record ${id} for ${params.target}:${params.port}`);
  return record;
}
async function markRemediationApplied(recordId, notes, config = DEFAULT_REMEDIATION_CONFIG) {
  const newStatus = config.autoQueueOnRemediation ? "verification_queued" : "remediation_pending";
  const db = await getDb();
  if (db) {
    try {
      await db.update(remediationVerifications).set({
        status: mapStatusToDb(newStatus),
        previousResult: notes ? JSON.stringify({ notes, appliedAt: Date.now() }) : void 0
      }).where(eq(remediationVerifications.id, recordId));
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;
      const record2 = dbRowToRecord(rows[0]);
      record2.status = newStatus;
      record2.remediationNotes = notes || null;
      record2.remediationAppliedAt = Date.now();
      console.log(`[RemediationVerify] ${recordId} marked as remediated (DB)`);
      return record2;
    } catch (err) {
      console.error("[RemediationVerify] DB update failed:", err);
    }
  }
  const record = memoryRecords.get(recordId);
  if (!record) return null;
  record.status = newStatus;
  record.remediationNotes = notes || null;
  record.remediationAppliedAt = Date.now();
  record.updatedAt = Date.now();
  return record;
}
async function queueForVerification(recordId) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;
      const currentStatus = rows[0].status;
      if (currentStatus !== "pending" && currentStatus !== "still_vulnerable") {
        console.warn(`[RemediationVerify] Cannot queue ${recordId} \u2014 current DB status: ${currentStatus}`);
        return null;
      }
      await db.update(remediationVerifications).set({ status: "pending" }).where(eq(remediationVerifications.id, recordId));
      const record2 = dbRowToRecord(rows[0]);
      record2.status = "verification_queued";
      return record2;
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
async function recordVerificationAttempt(recordId, attempt, config = DEFAULT_REMEDIATION_CONFIG) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.id, recordId));
      if (rows.length === 0) return null;
      const existingResult = rows[0].currentResult ? JSON.parse(rows[0].currentResult) : {};
      const attempts = existingResult.attempts || [];
      const newAttempt = {
        attemptId: `${recordId}-v${attempts.length + 1}`,
        attemptNumber: attempts.length + 1,
        timestamp: Date.now(),
        ...attempt
      };
      attempts.push(newAttempt);
      let newDbStatus;
      let fullStatus;
      switch (attempt.result) {
        case "verified_fixed":
          newDbStatus = "verified_fixed";
          fullStatus = "verified_fixed";
          break;
        case "still_vulnerable":
          const wasPreviouslyFixed = attempts.some(
            (a, i) => i < attempts.length - 1 && a.result === "verified_fixed"
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
      await db.update(remediationVerifications).set({
        status: newDbStatus,
        currentResult: JSON.stringify({ attempts, lastResult: attempt.result }),
        verifiedAt: /* @__PURE__ */ new Date(),
        verifiedBy: attempt.exploitModule
      }).where(eq(remediationVerifications.id, recordId));
      const record2 = dbRowToRecord(rows[0]);
      record2.status = fullStatus;
      record2.verificationAttempts = attempts;
      record2.lastVerifiedAt = Date.now();
      console.log(`[RemediationVerify] ${recordId} verification attempt #${newAttempt.attemptNumber}: ${attempt.result} \u2192 status: ${fullStatus}`);
      return record2;
    } catch (err) {
      console.error("[RemediationVerify] DB verification failed:", err);
    }
  }
  const record = memoryRecords.get(recordId);
  if (!record) return null;
  const attemptRecord = {
    attemptId: `${recordId}-v${record.verificationAttempts.length + 1}`,
    attemptNumber: record.verificationAttempts.length + 1,
    timestamp: Date.now(),
    ...attempt
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
async function getRecordsNeedingVerification(config = DEFAULT_REMEDIATION_CONFIG) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.status, "pending"));
      return rows.map(dbRowToRecord);
    } catch (err) {
      console.error("[RemediationVerify] DB query failed:", err);
    }
  }
  return Array.from(memoryRecords.values()).filter(
    (r) => r.status === "verification_queued"
  );
}
async function getOverdueFindings() {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(
        and(
          ne(remediationVerifications.status, "verified_fixed")
        )
      );
      return rows.map(dbRowToRecord).filter((r) => {
        if (!r.verificationDeadline) return false;
        return Date.now() > r.verificationDeadline;
      });
    } catch (err) {
      console.error("[RemediationVerify] DB overdue query failed:", err);
    }
  }
  const now = Date.now();
  return Array.from(memoryRecords.values()).filter((r) => {
    if (r.status === "verified_fixed") return false;
    if (!r.verificationDeadline) return false;
    return now > r.verificationDeadline;
  });
}
async function markExpiredRecords(expirationDays = 90) {
  const db = await getDb();
  if (db) {
    try {
      const cutoffDate = new Date(Date.now() - expirationDays * 24 * 60 * 60 * 1e3);
      const result = await db.update(remediationVerifications).set({ status: "still_vulnerable" }).where(
        and(
          eq(remediationVerifications.status, "pending"),
          lt(remediationVerifications.createdAt, cutoffDate)
        )
      );
      const count = result[0]?.affectedRows ?? 0;
      console.log(`[RemediationVerify] Marked ${count} records as expired`);
      return count;
    } catch (err) {
      console.error("[RemediationVerify] DB expire failed:", err);
    }
  }
  const now = Date.now();
  const cutoff = now - expirationDays * 24 * 60 * 60 * 1e3;
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
async function getRemediationSummary() {
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
function computeSummary(allRecords) {
  const byStatus = {
    exploitable: 0,
    remediation_pending: 0,
    verification_queued: 0,
    verifying: 0,
    verified_fixed: 0,
    still_vulnerable: 0,
    regression: 0,
    expired: 0
  };
  const remediationTimes = [];
  let slaCompliantCount = 0;
  let slaApplicableCount = 0;
  const now = Date.now();
  for (const record of allRecords) {
    byStatus[record.status]++;
    if (record.status === "verified_fixed" && record.lastVerifiedAt) {
      const hours = (record.lastVerifiedAt - record.originalValidatedAt) / (60 * 60 * 1e3);
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
  const fixRate = totalRemediated > 0 ? Math.round(byStatus.verified_fixed / totalRemediated * 100) : 0;
  const meanTimeToRemediate = remediationTimes.length > 0 ? Math.round(remediationTimes.reduce((a, b) => a + b, 0) / remediationTimes.length * 10) / 10 : null;
  const slaCompliance = slaApplicableCount > 0 ? Math.round(slaCompliantCount / slaApplicableCount * 100) : 100;
  const overdueFindingsCount = allRecords.filter((r) => {
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
    overdueFindingsCount
  };
}
async function getRemediationRecord(id) {
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
async function getRecordsByFinding(findingId) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(remediationVerifications).where(eq(remediationVerifications.originalFindingId, findingId));
      return rows.map(dbRowToRecord);
    } catch (err) {
      console.error("[RemediationVerify] DB query failed:", err);
    }
  }
  return Array.from(memoryRecords.values()).filter((r) => r.findingId === findingId);
}
async function getRemediationTimeline(recordId) {
  const record = await getRemediationRecord(recordId);
  if (!record) return [];
  const timeline = [];
  timeline.push({
    timestamp: record.originalValidatedAt,
    event: "Validated Exploitable",
    details: `Exploit module: ${record.originalExploitModule}. Severity: ${record.originalSeverity}. Target: ${record.target}:${record.port}`
  });
  timeline.push({
    timestamp: record.createdAt,
    event: "Remediation Record Created",
    details: `SLA: ${record.slaHours} hours. Deadline: ${record.verificationDeadline ? new Date(record.verificationDeadline).toISOString() : "N/A"}`
  });
  if (record.remediationAppliedAt) {
    timeline.push({
      timestamp: record.remediationAppliedAt,
      event: "Remediation Applied",
      details: record.remediationNotes || "No notes provided"
    });
  }
  for (const attempt of record.verificationAttempts) {
    timeline.push({
      timestamp: attempt.timestamp,
      event: `Verification Attempt #${attempt.attemptNumber}`,
      details: `Result: ${attempt.result}. Module: ${attempt.exploitModule}. Duration: ${attempt.durationMs}ms${attempt.notes ? `. Notes: ${attempt.notes}` : ""}`
    });
  }
  return timeline.sort((a, b) => a.timestamp - b.timestamp);
}
function clearRemediationRecords() {
  memoryRecords.clear();
  memIdCounter = 0;
}
export {
  DEFAULT_REMEDIATION_CONFIG,
  clearRemediationRecords,
  createRemediationRecord,
  getOverdueFindings,
  getRecordsByFinding,
  getRecordsNeedingVerification,
  getRemediationRecord,
  getRemediationSummary,
  getRemediationTimeline,
  markExpiredRecords,
  markRemediationApplied,
  queueForVerification,
  recordVerificationAttempt
};
