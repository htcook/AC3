import {
  deterministicScoreActionRisk
} from "./chunk-GH5X3RNV.js";
import {
  emitCredentialAttackComplete,
  emitEngagementTimelineEvent,
  emitLateralMovementExecuted,
  emitOpsecActionScored,
  emitOpsecThresholdWarning,
  emitPrivescAnalysisComplete,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  getDb,
  init_db
} from "./chunk-JZVHFV6D.js";
import "./chunk-GN2OC6SU.js";
import {
  engagementTimelineEvents,
  init_schema,
  opsecEvents
} from "./chunk-IG2G4XDA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/auto-persistence.ts
init_db();
init_schema();
init_ws_event_hub();
var CATEGORY_TO_PHASE = {
  recon: "recon",
  scanning: "scanning",
  credential_attack: "gaining_access",
  exploitation: "gaining_access",
  lateral_movement: "lateral_movement",
  privilege_escalation: "escalation",
  post_exploitation: "maintaining_access",
  exfiltration: "exfiltration",
  phishing: "gaining_access",
  c2: "maintaining_access"
};
var CATEGORY_TO_OPSEC_ACTION = {
  recon: "dns_enumeration",
  scanning: "port_scan",
  credential_attack: "brute_force_attack",
  exploitation: "exploit_execution",
  lateral_movement: "lateral_movement_psexec",
  privilege_escalation: "privilege_escalation",
  post_exploitation: "credential_dumping",
  exfiltration: "data_exfiltration",
  phishing: "phishing_email",
  c2: "c2_beacon"
};
async function recordAction(event) {
  const timestamp = Date.now();
  const phase = CATEGORY_TO_PHASE[event.category];
  const opsecActionType = CATEGORY_TO_OPSEC_ACTION[event.category];
  const timelineEventId = `evt_${timestamp}_${Math.random().toString(36).slice(2, 8)}`;
  const dbInstance = await getDb();
  try {
    if (!dbInstance) throw new Error("DB not available");
    await dbInstance.insert(engagementTimelineEvents).values({
      engagementId: typeof event.engagementId === "number" ? event.engagementId : 0,
      phase,
      eventType: event.success ? "tool_executed" : "scan_completed",
      title: event.actionName,
      description: event.description,
      sourceModule: event.source || "auto-persistence",
      metadata: JSON.stringify({
        category: event.category,
        target: event.target,
        success: event.success,
        resultData: event.resultData
      }),
      timestamp
    });
  } catch (err) {
    console.error("[AutoPersistence] Timeline write failed:", err);
  }
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
      timestamp
    });
  } catch (err) {
    console.error("[AutoPersistence] OPSEC score write failed:", err);
  }
  try {
    if (event.engagementId) {
      emitEngagementTimelineEvent({
        engagementId: parseInt(event.engagementId) || 0,
        eventType: event.success ? "action_completed" : "action_failed",
        title: event.actionName,
        description: event.description,
        phase
      });
    }
    emitOpsecActionScored({
      action: opsecActionType,
      riskScore: opsecScoreValue,
      detectionTechnologies: opsecResult.detectionTechnologies || [],
      mitigations: opsecResult.mitigations || [],
      engagementId: event.engagementId ? parseInt(event.engagementId) : void 0
    });
    if (opsecScoreValue >= 70) {
      emitOpsecThresholdWarning({
        cumulativeScore: opsecScoreValue,
        threshold: 70,
        recommendation: `High-risk action detected: ${event.actionName}. Consider using stealthier alternatives.`,
        engagementId: event.engagementId ? parseInt(event.engagementId) : void 0
      });
    }
    if (event.category === "credential_attack" && event.success) {
      emitCredentialAttackComplete({
        tool: event.source,
        protocol: event.resultData?.protocol || "unknown",
        target: event.target || "unknown",
        credentialsFound: event.resultData?.credentialsFound || 0,
        duration: event.resultData?.duration || 0,
        engagementId: event.engagementId ? parseInt(event.engagementId) : void 0
      });
    }
    if (event.category === "lateral_movement") {
      emitLateralMovementExecuted({
        sourceHost: event.source,
        targetHost: event.target || "unknown",
        technique: event.resultData?.technique || event.actionName,
        success: event.success,
        engagementId: event.engagementId ? parseInt(event.engagementId) : void 0
      });
    }
    if (event.category === "privilege_escalation" && event.success) {
      emitPrivescAnalysisComplete({
        os: event.resultData?.os || "unknown",
        pathsFound: event.resultData?.pathsFound || 1,
        highestConfidence: event.resultData?.confidence || 50,
        engagementId: event.engagementId ? parseInt(event.engagementId) : void 0
      });
    }
  } catch (wsErr) {
    console.error("[AutoPersistence] WebSocket emit failed:", wsErr);
  }
  return { timelineEventId, opsecScore: opsecScoreValue };
}
function recordRecon(opts) {
  return recordAction({ ...opts, category: "recon" });
}
function recordScan(opts) {
  return recordAction({ ...opts, category: "scanning" });
}
function recordCredentialAttack(opts) {
  return recordAction({ ...opts, category: "credential_attack" });
}
function recordExploit(opts) {
  return recordAction({ ...opts, category: "exploitation" });
}
function recordLateralMovement(opts) {
  return recordAction({ ...opts, category: "lateral_movement" });
}
function recordPrivesc(opts) {
  return recordAction({ ...opts, category: "privilege_escalation" });
}
function recordC2Action(opts) {
  return recordAction({ ...opts, category: "c2" });
}
function recordPhishing(opts) {
  return recordAction({ ...opts, category: "phishing" });
}
async function recordActions(events) {
  return Promise.all(events.map(recordAction));
}
export {
  CATEGORY_TO_OPSEC_ACTION,
  CATEGORY_TO_PHASE,
  recordAction,
  recordActions,
  recordC2Action,
  recordCredentialAttack,
  recordExploit,
  recordLateralMovement,
  recordPhishing,
  recordPrivesc,
  recordRecon,
  recordScan
};
