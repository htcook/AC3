import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/roe-guard.ts
import { TRPCError } from "@trpc/server";
function validateROE(engagement) {
  if (engagement.roeStatus === "none") {
    return {
      valid: false,
      reason: "No Rules of Engagement (ROE) have been uploaded for this engagement. A signed ROE is required before performing active testing operations."
    };
  }
  if (engagement.roeStatus === "pending") {
    return {
      valid: false,
      reason: "The ROE for this engagement is pending approval. It must be marked as 'signed' before active testing can begin."
    };
  }
  if (engagement.roeStatus === "expired") {
    return {
      valid: false,
      reason: "The ROE for this engagement has expired. Please upload a new ROE or extend the expiry date."
    };
  }
  if (engagement.roeExpiryDate && new Date(engagement.roeExpiryDate) < /* @__PURE__ */ new Date()) {
    return {
      valid: false,
      reason: `The ROE expired on ${new Date(engagement.roeExpiryDate).toLocaleDateString()}. Please upload a new ROE or extend the expiry date.`
    };
  }
  return { valid: true };
}
function enforceROE(engagement, riskTier, actionDescription) {
  if (riskTier === "yellow") {
    return;
  }
  const result = validateROE(engagement);
  if (!result.valid) {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[ROE REQUIRED] ${actionDescription}: ${result.reason}`
    });
  }
}
async function logOffensiveAction(entry) {
  try {
    const { getDb } = await import("./db-LSUZDHGJ.js");
    const { offensiveAuditLog } = await import("./schema-RDUWS2ES.js");
    const db = await getDb();
    if (!db) {
      console.warn("[AuditLog] Database not available, skipping audit log entry");
      return;
    }
    await db.insert(offensiveAuditLog).values({
      engagementId: entry.engagementId ?? null,
      operatorId: entry.operatorId,
      operatorName: entry.operatorName ?? null,
      actionType: entry.actionType,
      riskTier: entry.riskTier,
      target: entry.target,
      targetPort: entry.targetPort ?? null,
      moduleOrTool: entry.moduleOrTool ?? null,
      roeStatus: entry.roeStatus ?? null,
      roeDocumentUrl: entry.roeDocumentUrl ?? null,
      actionDetail: entry.actionDetail ?? null,
      resultStatus: entry.resultStatus,
      resultDetail: entry.resultDetail ?? null,
      ipAddress: entry.ipAddress ?? null
    });
  } catch (err) {
    console.error("[AuditLog] Failed to write audit entry:", err.message);
  }
}
async function getEngagementROE(engagementId) {
  try {
    const { getDb } = await import("./db-LSUZDHGJ.js");
    const { engagements } = await import("./schema-RDUWS2ES.js");
    const { eq } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return null;
    const [eng] = await db.select({
      roeStatus: engagements.roeStatus,
      roeSignedDate: engagements.roeSignedDate,
      roeExpiryDate: engagements.roeExpiryDate,
      roeDocumentUrl: engagements.roeDocumentUrl,
      roeScope: engagements.roeScope
    }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);
    return eng || null;
  } catch {
    return null;
  }
}
var ACTION_RISK_MAP, ACTION_DESCRIPTIONS;
var init_roe_guard = __esm({
  "server/lib/roe-guard.ts"() {
    ACTION_RISK_MAP = {
      active_probe: "orange",
      msf_check: "orange",
      msf_auxiliary: "orange",
      msf_exploit: "red",
      phishing_launch: "red",
      caldera_operation: "red",
      payload_delivery: "red",
      session_interaction: "red"
    };
    ACTION_DESCRIPTIONS = {
      active_probe: "Active Vulnerability Probe",
      msf_check: "Metasploit Module Check",
      msf_auxiliary: "Metasploit Auxiliary Scan",
      msf_exploit: "Metasploit Exploit Execution",
      phishing_launch: "Phishing Campaign Launch",
      caldera_operation: "Caldera Adversary Emulation",
      payload_delivery: "Payload Delivery",
      session_interaction: "Session Interaction"
    };
  }
});
init_roe_guard();
export {
  ACTION_DESCRIPTIONS,
  ACTION_RISK_MAP,
  enforceROE,
  getEngagementROE,
  logOffensiveAction,
  validateROE
};
