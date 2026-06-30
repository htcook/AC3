/**
 * ROE (Rules of Engagement) Guard & Offensive Audit Logger
 * 
 * Provides middleware and utilities to:
 * 1. Gate Orange/Red tier operations behind a valid ROE
 * 2. Log all offensive operations to the unified audit trail
 */
import { TRPCError } from "@trpc/server";

// ─── Types ───────────────────────────────────────────────────────────

export type RiskTier = "yellow" | "orange" | "red";

export type ActionType =
  | "active_probe"
  | "msf_check"
  | "msf_auxiliary"
  | "msf_exploit"
  | "phishing_launch"
  | "caldera_operation"
  | "payload_delivery"
  | "session_interaction";

export interface ROEStatus {
  roeStatus: "none" | "pending" | "signed" | "expired";
  roeSignedDate: Date | null;
  roeExpiryDate: Date | null;
  roeDocumentUrl: string | null;
  roeScope: any;
}

export interface AuditEntry {
  engagementId?: number | null;
  operatorId: string;
  operatorName?: string | null;
  actionType: ActionType;
  riskTier: RiskTier;
  target: string;
  targetPort?: number | null;
  moduleOrTool?: string | null;
  roeStatus?: string | null;
  roeDocumentUrl?: string | null;
  actionDetail?: any;
  resultStatus: "success" | "failure" | "blocked" | "pending_approval";
  resultDetail?: string | null;
  ipAddress?: string | null;
}

// ─── ROE Validation ──────────────────────────────────────────────────

/**
 * Validates that an engagement has a valid, non-expired ROE.
 * Returns the ROE details if valid, throws a TRPCError if not.
 */
export function validateROE(engagement: ROEStatus & { id?: number; name?: string }): {
  valid: boolean;
  reason?: string;
} {
  if (engagement.roeStatus === "none") {
    return {
      valid: false,
      reason: "No Rules of Engagement (ROE) have been uploaded for this engagement. A signed ROE is required before performing active testing operations.",
    };
  }

  if (engagement.roeStatus === "pending") {
    return {
      valid: false,
      reason: "The ROE for this engagement is pending approval. It must be marked as 'signed' before active testing can begin.",
    };
  }

  if (engagement.roeStatus === "expired") {
    return {
      valid: false,
      reason: "The ROE for this engagement has expired. Please upload a new ROE or extend the expiry date.",
    };
  }

  // Check expiry date
  if (engagement.roeExpiryDate && new Date(engagement.roeExpiryDate) < new Date()) {
    return {
      valid: false,
      reason: `The ROE expired on ${new Date(engagement.roeExpiryDate).toLocaleDateString()}. Please upload a new ROE or extend the expiry date.`,
    };
  }

  return { valid: true };
}

/**
 * Enforces ROE for Orange/Red operations. Throws TRPCError if ROE is invalid.
 * For YELLOW operations, logs a warning but does not block.
 */
export function enforceROE(
  engagement: ROEStatus & { id?: number; name?: string },
  riskTier: RiskTier,
  actionDescription: string
): void {
  if (riskTier === "yellow") {
    // YELLOW operations are allowed without ROE but should be logged
    return;
  }

  const result = validateROE(engagement);
  if (!result.valid) {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[ROE REQUIRED] ${actionDescription}: ${result.reason}`,
    });
  }
}

// ─── Audit Logger ────────────────────────────────────────────────────

/**
 * Logs an offensive operation to the audit trail.
 * This is a fire-and-forget operation — it should not block the main flow.
 */
export async function logOffensiveAction(entry: AuditEntry): Promise<void> {
  try {
    const { getDb } = await import("../db");
    const { offensiveAuditLog } = await import("../../drizzle/schema");
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
      ipAddress: entry.ipAddress ?? null,
    });
  } catch (err: any) {
    console.error("[AuditLog] Failed to write audit entry:", err.message);
  }
}

/**
 * Helper to look up an engagement's ROE status by ID.
 */
export async function getEngagementROE(engagementId: number): Promise<ROEStatus | null> {
  try {
    const { getDb } = await import("../db");
    const { engagements } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return null;

    const [eng] = await db
      .select({
        roeStatus: engagements.roeStatus,
        roeSignedDate: engagements.roeSignedDate,
        roeExpiryDate: engagements.roeExpiryDate,
        roeDocumentUrl: engagements.roeDocumentUrl,
        roeScope: engagements.roeScope,
      })
      .from(engagements)
      .where(eq(engagements.id, engagementId))
      .limit(1);

    return eng || null;
  } catch {
    return null;
  }
}

// ─── Risk Tier Mapping ───────────────────────────────────────────────

/** Maps operation types to their risk tier */
export const ACTION_RISK_MAP: Record<ActionType, RiskTier> = {
  active_probe: "orange",
  msf_check: "orange",
  msf_auxiliary: "orange",
  msf_exploit: "red",
  phishing_launch: "red",
  caldera_operation: "red",
  payload_delivery: "red",
  session_interaction: "red",
};

/** Human-readable descriptions for action types */
export const ACTION_DESCRIPTIONS: Record<ActionType, string> = {
  active_probe: "Active Vulnerability Probe",
  msf_check: "Metasploit Module Check",
  msf_auxiliary: "Metasploit Auxiliary Scan",
  msf_exploit: "Metasploit Exploit Execution",
  phishing_launch: "Phishing Campaign Launch",
  caldera_operation: "Caldera Adversary Emulation",
  payload_delivery: "Payload Delivery",
  session_interaction: "Session Interaction",
};
