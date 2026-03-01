/**
 * Auto-Persistence Middleware
 * 
 * Automatically emits engagement timeline events and OPSEC risk scores
 * whenever any module action (scan, exploit, pivot, credential attack) completes.
 * This ensures every operator action is recorded without manual intervention.
 */

import { getDb } from "../db";
import {
  engagementTimelineEvents,
  opsecEvents,
} from "../../drizzle/schema";
import { deterministicScoreActionRisk, ACTION_RISK_PROFILES } from "./opsec-risk-engine";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ActionCategory =
  | "recon"
  | "scanning"
  | "credential_attack"
  | "exploitation"
  | "lateral_movement"
  | "privilege_escalation"
  | "post_exploitation"
  | "exfiltration"
  | "phishing"
  | "c2";

export interface ActionEvent {
  /** Which engagement this belongs to (optional — if null, logged globally) */
  engagementId?: string;
  /** Kill chain phase */
  category: ActionCategory;
  /** Human-readable action name */
  actionName: string;
  /** Detailed description of what happened */
  description: string;
  /** The module/tool that performed the action */
  source: string;
  /** Target host/IP/domain */
  target?: string;
  /** Whether the action succeeded */
  success: boolean;
  /** Raw result data for drill-down */
  resultData?: Record<string, any>;
  /** User who initiated the action */
  userId?: string;
}

// ─── Category → Kill Chain Phase Mapping ─────────────────────────────────────

const CATEGORY_TO_PHASE: Record<ActionCategory, string> = {
  recon: "recon",
  scanning: "scanning",
  credential_attack: "gaining_access",
  exploitation: "gaining_access",
  lateral_movement: "lateral_movement",
  privilege_escalation: "escalation",
  post_exploitation: "maintaining_access",
  exfiltration: "exfiltration",
  phishing: "gaining_access",
  c2: "maintaining_access",
};

// ─── Category → OPSEC Action Type Mapping ────────────────────────────────────

const CATEGORY_TO_OPSEC_ACTION: Record<ActionCategory, string> = {
  recon: "dns_enumeration",
  scanning: "port_scan",
  credential_attack: "brute_force_attack",
  exploitation: "exploit_execution",
  lateral_movement: "lateral_movement_psexec",
  privilege_escalation: "privilege_escalation",
  post_exploitation: "credential_dumping",
  exfiltration: "data_exfiltration",
  phishing: "phishing_email",
  c2: "c2_beacon",
};

// ─── Core: Record Action ─────────────────────────────────────────────────────

/**
 * Record an action event — writes to both timeline and OPSEC scoring.
 * Call this from any module after completing an action.
 */
export async function recordAction(event: ActionEvent): Promise<{
  timelineEventId: string;
  opsecScore: number;
}> {
  const timestamp = Date.now();
  const phase = CATEGORY_TO_PHASE[event.category];
  const opsecActionType = CATEGORY_TO_OPSEC_ACTION[event.category];

  // 1. Write timeline event
  const timelineEventId = `evt_${timestamp}_${Math.random().toString(36).slice(2, 8)}`;
  const dbInstance = await getDb();
  try {
    if (!dbInstance) throw new Error("DB not available");
    await dbInstance.insert(engagementTimelineEvents).values({
      id: timelineEventId,
      engagementId: event.engagementId || "global",
      phase,
      eventType: event.success ? "action_completed" : "action_failed",
      title: event.actionName,
      description: event.description,
      source: event.source,
      metadata: JSON.stringify({
        category: event.category,
        target: event.target,
        success: event.success,
        resultData: event.resultData,
      }),
      createdAt: timestamp,
    });
  } catch (err) {
    // Don't let persistence failures break the main action
    console.error("[AutoPersistence] Timeline write failed:", err);
  }

  // 2. Calculate and write OPSEC score
  const opsecResult = deterministicScoreActionRisk(opsecActionType, event.description);
  const opsecScoreValue = opsecResult.riskScore ?? 50;

  try {
    if (!dbInstance) throw new Error("DB not available");
    await dbInstance.insert(opsecEvents).values({
      engagementId: parseInt(event.engagementId || "0") || 0,
      actionType: opsecActionType,
      actionDescription: event.description,
      riskScore: opsecScoreValue,
      sourceHost: event.source,
      targetHost: event.target || null,
      timestamp,
    });
  } catch (err) {
    console.error("[AutoPersistence] OPSEC score write failed:", err);
  }

  return { timelineEventId, opsecScore: opsecScoreValue };
}

// ─── Convenience Wrappers ────────────────────────────────────────────────────

/** Record a reconnaissance action */
export function recordRecon(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "recon" });
}

/** Record a scanning action */
export function recordScan(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "scanning" });
}

/** Record a credential attack */
export function recordCredentialAttack(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "credential_attack" });
}

/** Record an exploitation attempt */
export function recordExploit(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "exploitation" });
}

/** Record a lateral movement action */
export function recordLateralMovement(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "lateral_movement" });
}

/** Record a privilege escalation attempt */
export function recordPrivesc(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "privilege_escalation" });
}

/** Record a C2/post-exploitation action */
export function recordC2Action(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "c2" });
}

/** Record a phishing action */
export function recordPhishing(opts: {
  engagementId?: string;
  actionName: string;
  description: string;
  source: string;
  target?: string;
  success: boolean;
  resultData?: Record<string, any>;
}) {
  return recordAction({ ...opts, category: "phishing" });
}

// ─── Batch Recording ─────────────────────────────────────────────────────────

/**
 * Record multiple actions at once (e.g., after a scan discovers multiple findings).
 * Returns array of results in same order as input.
 */
export async function recordActions(events: ActionEvent[]): Promise<Array<{
  timelineEventId: string;
  opsecScore: number;
}>> {
  return Promise.all(events.map(recordAction));
}

// ─── Query Helpers ───────────────────────────────────────────────────────────

export { CATEGORY_TO_PHASE, CATEGORY_TO_OPSEC_ACTION };
