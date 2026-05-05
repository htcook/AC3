import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/ws-event-hub.ts
import { WebSocketServer, WebSocket } from "ws";
import jwt from "jsonwebtoken";
import { EventEmitter } from "events";
function emitExploitFired(data) {
  const event = {
    type: "exploit:fired",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitExploitResult(data) {
  const event = {
    type: "exploit:result",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitAgentDeployed(data) {
  const event = {
    type: "agent:deployed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitAgentCheckin(data) {
  eventHub.broadcastGlobal({
    type: "agent:checkin",
    timestamp: Date.now(),
    data
  });
}
function emitOperationUpdate(data) {
  const event = {
    type: data.state === "finished" ? "operation:finished" : "operation:step_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitReconComplete(data) {
  const event = {
    type: "recon:complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitCampaignEvent(data) {
  const typeMap = {
    launched: "campaign:launched",
    email_sent: "campaign:email_sent",
    email_opened: "campaign:email_opened",
    link_clicked: "campaign:link_clicked",
    creds_submitted: "campaign:creds_submitted"
  };
  const event = {
    type: typeMap[data.eventType] || "campaign:launched",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitPipelineStep(data) {
  const event = {
    type: data.status === "complete" && data.step === -1 ? "pipeline:finished" : "pipeline:step_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitMsfServerEvent(data) {
  const typeMap = {
    provisioning: "msf:server_provisioned",
    ready: "msf:server_ready",
    destroyed: "msf:server_destroyed",
    error: "system:alert"
  };
  eventHub.broadcastGlobal({
    type: typeMap[data.status] || "system:notification",
    timestamp: Date.now(),
    data
  });
}
function emitSystemNotification(data) {
  eventHub.broadcastGlobal({
    type: "system:notification",
    timestamp: Date.now(),
    data
  });
}
function emitSystemAlert(data) {
  eventHub.broadcastGlobal({
    type: "system:alert",
    timestamp: Date.now(),
    data
  });
}
function emitOpsecActionScored(data) {
  const event = {
    type: "opsec:action_scored",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitOpsecBurnDetected(data) {
  const event = {
    type: "opsec:burn_detected",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitOpsecThresholdWarning(data) {
  const event = {
    type: "opsec:threshold_warning",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitCredentialAttackStarted(data) {
  const event = {
    type: "credential:attack_started",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitCredentialAttackComplete(data) {
  const event = {
    type: "credential:attack_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitCredentialFound(data) {
  const event = {
    type: "credential:found",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitLateralPivotPlanned(data) {
  const event = {
    type: "lateral:pivot_planned",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitLateralMovementExecuted(data) {
  const event = {
    type: "lateral:movement_executed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitPrivescAnalysisComplete(data) {
  const event = {
    type: "privesc:analysis_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitPrivescEscalationFound(data) {
  const event = {
    type: "privesc:escalation_found",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitEngagementPhaseChanged(data) {
  eventHub.broadcastEngagement(data.engagementId, {
    type: "engagement:phase_changed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  });
}
function emitEngagementHandoff(data) {
  eventHub.broadcastEngagement(data.engagementId, {
    type: "engagement:handoff",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  });
}
function emitEngagementTimelineEvent(data) {
  eventHub.broadcastEngagement(data.engagementId, {
    type: "engagement:timeline_event",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  });
}
function emitEngagementProgressUpdate(data) {
  eventHub.broadcastEngagement(data.engagementId, {
    type: "engagement:progress_update",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  });
}
function emitAdvisorRecommendation(data) {
  const event = {
    type: "advisor:recommendation",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}
function emitReviewItemCreated(data) {
  const event = {
    type: data.autoApproved ? "review:item_approved" : "review:item_created",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitReviewItemApproved(data) {
  const event = {
    type: "review:item_approved",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitReviewItemRejected(data) {
  const event = {
    type: "review:item_rejected",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitReviewItemDeferred(data) {
  const event = {
    type: "review:item_deferred",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitReviewBulkApproved(data) {
  eventHub.broadcastGlobal({
    type: "review:bulk_approved",
    timestamp: Date.now(),
    data
  });
}
function emitJobEnqueued(data) {
  const event = {
    type: "job:enqueued",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitJobDispatched(data) {
  const event = {
    type: "job:dispatched",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitJobCompleted(data) {
  const event = {
    type: "job:completed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitJobFailed(data) {
  const event = {
    type: "job:failed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
}
function emitJobWorkerEvent(data) {
  eventHub.broadcastGlobal({
    type: data.event === "registered" ? "job:worker_registered" : "job:worker_lost",
    timestamp: Date.now(),
    data
  });
}
function emitTimelineEvent(event) {
  const wsEvent = {
    type: "engagement:timeline_event",
    timestamp: Date.now(),
    data: event
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitProfileGenerated(data) {
  const wsEvent = {
    type: "automation:profile_generated",
    timestamp: Date.now(),
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitProfilePushed(data) {
  const wsEvent = {
    type: "automation:profile_pushed",
    timestamp: Date.now(),
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitPlaybookTriggered(data) {
  const wsEvent = {
    type: "automation:playbook_triggered",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, wsEvent);
  }
}
function emitPipelineRun(data) {
  const wsEvent = {
    type: "automation:pipeline_run",
    timestamp: Date.now(),
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitEnrichmentComplete(data) {
  const wsEvent = {
    type: "automation:enrichment_complete",
    timestamp: Date.now(),
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitOpsecUpdate(data) {
  const wsEvent = {
    type: "opsec:risk_update",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcast(wsEvent, "cockpit:timeline");
  eventHub.broadcastGlobal(wsEvent);
}
function emitEmberAgentRegistered(data) {
  const event = {
    type: "ember:agent_registered",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberBeacon(data) {
  eventHub.broadcastGlobal({
    type: "ember:beacon",
    timestamp: Date.now(),
    data
  });
}
function emitEmberTaskComplete(data) {
  const event = {
    type: "ember:task_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberBurnResponse(data) {
  const event = {
    type: "ember:burn_response",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberKeyRotation(data) {
  eventHub.broadcastGlobal({
    type: "ember:key_rotation",
    timestamp: Date.now(),
    data
  });
}
function emitEmberOpsecScored(data) {
  const event = {
    type: "ember:opsec_scored",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitLLMDecision(data) {
  const event = {
    type: "llm:decision",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitLLMDelegation(data) {
  const event = {
    type: "llm:delegation",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitLLMStealthAlert(data) {
  const event = {
    type: "llm:stealth_alert",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitLLMTrainingCaptured(data) {
  const event = {
    type: "llm:training_captured",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitLLMShadowTestResult(data) {
  const event = {
    type: "llm:shadow_test_result",
    timestamp: Date.now(),
    data
  };
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitLLMEngagementProgress(data) {
  const event = {
    type: "llm:engagement_progress",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
  eventHub.broadcast(event, "llm:monitor");
}
function emitEvidenceGatePassed(data) {
  const event = {
    type: "evidence:gate_passed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceGateFlagged(data) {
  const event = {
    type: "evidence:gate_flagged",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceQuarantined(data) {
  const event = {
    type: "evidence:quarantined",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceChainFlushed(data) {
  const event = {
    type: "evidence:chain_flushed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceAnchorCreated(data) {
  const event = {
    type: "evidence:anchor_created",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceAnchorVerified(data) {
  const event = {
    type: "evidence:anchor_verified",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEvidenceTamperDetected(data) {
  const event = {
    type: "evidence:tamper_detected",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  eventHub.broadcastEngagement(data.engagementId, event);
  eventHub.broadcastGlobal(event);
}
function emitEmberLateralMovement(data) {
  const event = {
    type: "ember:lateral_movement",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberNetworkDiscovered(data) {
  const event = {
    type: "ember:network_discovered",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberCredentialHarvested(data) {
  const event = {
    type: "ember:credential_harvested",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberDataExfiltrated(data) {
  const event = {
    type: "ember:data_exfiltrated",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitEmberPersistenceEstablished(data) {
  const event = {
    type: "ember:persistence_established",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  }
  eventHub.broadcastGlobal(event);
}
function emitDIScanStarted(data) {
  eventHub.broadcastGlobal({
    type: "di:scan_started",
    timestamp: Date.now(),
    data
  });
}
function emitDIStageChanged(data) {
  eventHub.broadcastGlobal({
    type: "di:stage_changed",
    timestamp: Date.now(),
    data
  });
}
function emitDIAssetDiscovered(data) {
  eventHub.broadcastGlobal({
    type: "di:asset_discovered",
    timestamp: Date.now(),
    data
  });
}
function emitDIFindingDetected(data) {
  eventHub.broadcastGlobal({
    type: "di:finding_detected",
    timestamp: Date.now(),
    data
  });
}
function emitDIInterceptionDetected(data) {
  eventHub.broadcastGlobal({
    type: "di:interception_detected",
    timestamp: Date.now(),
    data
  });
}
function emitDIThreatMatched(data) {
  eventHub.broadcastGlobal({
    type: "di:threat_matched",
    timestamp: Date.now(),
    data
  });
}
function emitDIScanComplete(data) {
  eventHub.broadcastGlobal({
    type: "di:scan_complete",
    timestamp: Date.now(),
    data
  });
}
function emitDIConnectorProgress(data) {
  eventHub.broadcastGlobal({
    type: "di:connector_progress",
    timestamp: Date.now(),
    data
  });
}
var EventHub, eventHub;
var init_ws_event_hub = __esm({
  "server/lib/ws-event-hub.ts"() {
    EventHub = class extends EventEmitter {
      constructor() {
        super(...arguments);
        this.wss = null;
        this.clients = /* @__PURE__ */ new Map();
        this.heartbeatInterval = null;
        this.clientIdCounter = 0;
      }
      /**
       * Attach the WebSocket server to an existing HTTP server
       */
      attach(server) {
        if (this.wss) {
          console.warn("[WS EventHub] Already attached, skipping");
          return;
        }
        this.wss = new WebSocketServer({
          server,
          path: "/ws/events",
          // Verify origin in production
          verifyClient: (info, cb) => {
            cb(true);
          }
        });
        this.wss.on("connection", (ws, req) => {
          this.handleConnection(ws, req);
        });
        this.heartbeatInterval = setInterval(() => {
          this.heartbeat();
        }, 3e4);
        console.log("[WS EventHub] Attached to HTTP server on /ws/events");
      }
      /**
       * Handle new WebSocket connection
       */
      handleConnection(ws, req) {
        const clientId = `ws_${++this.clientIdCounter}_${Date.now()}`;
        let userId = null;
        try {
          const cookieHeader = req.headers.cookie || "";
          const cookies = Object.fromEntries(
            cookieHeader.split(";").map((c) => {
              const [k, ...v] = c.trim().split("=");
              return [k, v.join("=")];
            })
          );
          const token = cookies["caldera_session"];
          if (token) {
            const secret = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
            const decoded = jwt.verify(token, secret);
            userId = decoded.userId || decoded.id || null;
          }
        } catch {
        }
        const client = {
          ws,
          userId,
          channels: /* @__PURE__ */ new Set(["global"]),
          // Everyone subscribes to global
          lastPing: Date.now(),
          isAlive: true
        };
        this.clients.set(clientId, client);
        this.sendToClient(client, {
          type: "system:notification",
          timestamp: Date.now(),
          data: {
            message: "Connected to AC3 Event Stream",
            clientId,
            authenticated: userId !== null
          }
        });
        ws.on("message", (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            this.handleClientMessage(clientId, msg);
          } catch {
          }
        });
        ws.on("pong", () => {
          client.isAlive = true;
          client.lastPing = Date.now();
        });
        ws.on("close", () => {
          this.clients.delete(clientId);
        });
        ws.on("error", () => {
          this.clients.delete(clientId);
        });
        this.emit("client:connected", { clientId, userId });
      }
      /**
       * Handle messages from clients (subscribe, unsubscribe, ping)
       */
      handleClientMessage(clientId, msg) {
        const client = this.clients.get(clientId);
        if (!client) return;
        switch (msg.action) {
          case "subscribe":
            if (msg.channel) client.channels.add(msg.channel);
            if (msg.channels)
              msg.channels.forEach((ch) => client.channels.add(ch));
            this.sendToClient(client, {
              type: "system:notification",
              timestamp: Date.now(),
              data: {
                message: "Subscribed",
                channels: Array.from(client.channels)
              }
            });
            break;
          case "unsubscribe":
            if (msg.channel && msg.channel !== "global")
              client.channels.delete(msg.channel);
            break;
          case "ping":
            client.isAlive = true;
            client.lastPing = Date.now();
            this.sendToClient(client, {
              type: "system:notification",
              timestamp: Date.now(),
              data: { message: "pong" }
            });
            break;
        }
      }
      /**
       * Heartbeat — ping all clients, disconnect dead ones
       */
      heartbeat() {
        for (const [clientId, client] of Array.from(this.clients.entries())) {
          if (!client.isAlive) {
            client.ws.terminate();
            this.clients.delete(clientId);
            continue;
          }
          client.isAlive = false;
          try {
            client.ws.ping();
          } catch {
            this.clients.delete(clientId);
          }
        }
      }
      /**
       * Send an event to a specific client
       */
      sendToClient(client, event) {
        if (client.ws.readyState === WebSocket.OPEN) {
          try {
            client.ws.send(JSON.stringify(event));
          } catch {
          }
        }
      }
      /**
       * Broadcast an event to all clients subscribed to the relevant channel
       */
      broadcast(event, channel = "global") {
        const payload = JSON.stringify(event);
        for (const [, client] of Array.from(this.clients.entries())) {
          if (client.ws.readyState === WebSocket.OPEN && client.channels.has(channel)) {
            try {
              client.ws.send(payload);
            } catch {
            }
          }
        }
        this.emit("event", event, channel);
      }
      /**
       * Broadcast to global channel (all connected clients)
       */
      broadcastGlobal(event) {
        this.broadcast(event, "global");
      }
      /**
       * Broadcast to engagement-specific channel
       */
      broadcastEngagement(engagementId, event) {
        this.broadcast(
          { ...event, engagementId },
          `engagement:${engagementId}`
        );
        this.broadcastGlobal({ ...event, engagementId });
      }
      /**
       * Get connection stats
       */
      getStats() {
        const channels = {};
        let authenticated = 0;
        for (const [, client] of Array.from(this.clients.entries())) {
          if (client.userId) authenticated++;
          for (const ch of Array.from(client.channels)) {
            channels[ch] = (channels[ch] || 0) + 1;
          }
        }
        return {
          totalClients: this.clients.size,
          authenticatedClients: authenticated,
          channels
        };
      }
      /**
       * Cleanup on server shutdown
       */
      destroy() {
        if (this.heartbeatInterval) {
          clearInterval(this.heartbeatInterval);
          this.heartbeatInterval = null;
        }
        for (const [, client] of Array.from(this.clients.entries())) {
          client.ws.terminate();
        }
        this.clients.clear();
        if (this.wss) {
          this.wss.close();
          this.wss = null;
        }
      }
    };
    eventHub = new EventHub();
  }
});

export {
  eventHub,
  emitExploitFired,
  emitExploitResult,
  emitAgentDeployed,
  emitAgentCheckin,
  emitOperationUpdate,
  emitReconComplete,
  emitCampaignEvent,
  emitPipelineStep,
  emitMsfServerEvent,
  emitSystemNotification,
  emitSystemAlert,
  emitOpsecActionScored,
  emitOpsecBurnDetected,
  emitOpsecThresholdWarning,
  emitCredentialAttackStarted,
  emitCredentialAttackComplete,
  emitCredentialFound,
  emitLateralPivotPlanned,
  emitLateralMovementExecuted,
  emitPrivescAnalysisComplete,
  emitPrivescEscalationFound,
  emitEngagementPhaseChanged,
  emitEngagementHandoff,
  emitEngagementTimelineEvent,
  emitEngagementProgressUpdate,
  emitAdvisorRecommendation,
  emitReviewItemCreated,
  emitReviewItemApproved,
  emitReviewItemRejected,
  emitReviewItemDeferred,
  emitReviewBulkApproved,
  emitJobEnqueued,
  emitJobDispatched,
  emitJobCompleted,
  emitJobFailed,
  emitJobWorkerEvent,
  emitTimelineEvent,
  emitProfileGenerated,
  emitProfilePushed,
  emitPlaybookTriggered,
  emitPipelineRun,
  emitEnrichmentComplete,
  emitOpsecUpdate,
  emitEmberAgentRegistered,
  emitEmberBeacon,
  emitEmberTaskComplete,
  emitEmberBurnResponse,
  emitEmberKeyRotation,
  emitEmberOpsecScored,
  emitLLMDecision,
  emitLLMDelegation,
  emitLLMStealthAlert,
  emitLLMTrainingCaptured,
  emitLLMShadowTestResult,
  emitLLMEngagementProgress,
  emitEvidenceGatePassed,
  emitEvidenceGateFlagged,
  emitEvidenceQuarantined,
  emitEvidenceChainFlushed,
  emitEvidenceAnchorCreated,
  emitEvidenceAnchorVerified,
  emitEvidenceTamperDetected,
  emitEmberLateralMovement,
  emitEmberNetworkDiscovered,
  emitEmberCredentialHarvested,
  emitEmberDataExfiltrated,
  emitEmberPersistenceEstablished,
  emitDIScanStarted,
  emitDIStageChanged,
  emitDIAssetDiscovered,
  emitDIFindingDetected,
  emitDIInterceptionDetected,
  emitDIThreatMatched,
  emitDIScanComplete,
  emitDIConnectorProgress,
  init_ws_event_hub
};
