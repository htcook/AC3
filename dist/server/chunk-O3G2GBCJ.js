import {
  getFIPSCrypto
} from "./chunk-5CE4P7TD.js";
import {
  getDb,
  init_db
} from "./chunk-3OPUTHKA.js";
import {
  agentAuditLog,
  agentDeployments,
  init_schema
} from "./chunk-H7DAFEQB.js";

// server/lib/agent-heartbeat.ts
init_db();
init_schema();
import { eq, sql, inArray } from "drizzle-orm";
async function logHeartbeatEvent(agentId, eventType, actorType, details, ipAddress, userAgent) {
  const db = await getDb();
  if (!db) return;
  const fips = getFIPSCrypto();
  const [lastEntry] = await db.select({ recordHash: agentAuditLog.recordHash }).from(agentAuditLog).where(eq(agentAuditLog.agentId, agentId)).orderBy(sql`id DESC`).limit(1);
  const previousHash = lastEntry?.recordHash ?? "genesis";
  const recordData = JSON.stringify({
    agentId,
    eventType,
    actorType,
    details,
    previousHash,
    timestamp: Date.now()
  });
  const recordHash = fips.hmac(recordData).mac;
  await db.insert(agentAuditLog).values({
    agentId,
    eventType,
    actorId: null,
    actorType,
    details,
    recordHash,
    previousHash,
    ipAddress: ipAddress ?? null,
    userAgent: userAgent ?? null,
    createdAt: Date.now()
  });
}
async function processHeartbeat(payload) {
  const db = await getDb();
  if (!db) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus: null,
      newStatus: "unknown",
      message: "Database unavailable"
    };
  }
  const [agent] = await db.select().from(agentDeployments).where(eq(agentDeployments.id, payload.agentId));
  if (!agent) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus: null,
      newStatus: "unknown",
      message: "Agent not found"
    };
  }
  const previousStatus = agent.status;
  const now = Date.now();
  const terminalStates = ["terminated", "completed", "failed"];
  if (previousStatus && terminalStates.includes(previousStatus)) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus,
      newStatus: previousStatus,
      message: `Agent in terminal state (${previousStatus}); heartbeat rejected`
    };
  }
  const updateSet = {
    lastHeartbeat: now,
    updatedAt: now
  };
  if (payload.platform) updateSet.agentPlatform = payload.platform;
  if (payload.architecture) updateSet.agentArchitecture = payload.architecture;
  if (payload.username) updateSet.agentUsername = payload.username;
  if (payload.privilege) updateSet.agentPrivilege = payload.privilege;
  if (payload.executors) updateSet.agentExecutors = payload.executors;
  if (payload.pid) updateSet.agentPid = payload.pid;
  if (payload.hostname) updateSet.targetHostname = payload.hostname;
  if (payload.internalIp) updateSet.targetIp = payload.internalIp;
  let newStatus = previousStatus;
  let eventType = "heartbeat";
  if (previousStatus === "approved" || previousStatus === "deploying") {
    newStatus = "active";
    updateSet.status = "active";
    updateSet.deployedAt = now;
  } else if (previousStatus === "lost") {
    newStatus = "active";
    updateSet.status = "active";
    eventType = "reconnected";
  } else if (previousStatus === "pending_approval") {
    newStatus = "pending_approval";
  }
  await db.update(agentDeployments).set(updateSet).where(eq(agentDeployments.id, payload.agentId));
  await logHeartbeatEvent(
    payload.agentId,
    eventType,
    "agent",
    {
      previousStatus,
      newStatus,
      platform: payload.platform,
      hostname: payload.hostname,
      ip: payload.internalIp
    },
    payload.ipAddress,
    payload.userAgent
  );
  return {
    accepted: true,
    agentId: payload.agentId,
    previousStatus,
    newStatus: newStatus ?? "unknown",
    message: eventType === "reconnected" ? `Agent reconnected (was lost for ${agent.lastHeartbeat ? Math.round((now - agent.lastHeartbeat) / 1e3) : "unknown"}s)` : previousStatus === "approved" || previousStatus === "deploying" ? "First beacon received \u2014 agent now active" : "Heartbeat accepted"
  };
}
async function runWatchdogSweep() {
  const db = await getDb();
  if (!db) {
    return { scannedAgents: 0, markedLost: 0, lostAgentIds: [] };
  }
  const now = Date.now();
  const activeAgents = await db.select({
    id: agentDeployments.id,
    status: agentDeployments.agentStatus,
    lastHeartbeat: agentDeployments.lastHeartbeat,
    watchdogSeconds: agentDeployments.watchdogSeconds,
    deployedAt: agentDeployments.deployedAt
  }).from(agentDeployments).where(
    inArray(agentDeployments.agentStatus, ["active", "paused"])
  );
  const lostAgentIds = [];
  for (const agent of activeAgents) {
    const lastSeen = agent.lastHeartbeat ?? agent.deployedAt ?? 0;
    const thresholdMs = (agent.watchdogSeconds ?? 14400) * 1e3;
    if (now - lastSeen > thresholdMs) {
      await db.update(agentDeployments).set({ agentStatus: "lost", updatedAt: now }).where(eq(agentDeployments.id, agent.id));
      await logHeartbeatEvent(agent.id, "lost", "system", {
        lastHeartbeat: lastSeen,
        watchdogSeconds: agent.watchdogSeconds,
        silentForSeconds: Math.round((now - lastSeen) / 1e3)
      });
      lostAgentIds.push(agent.id);
    }
  }
  return {
    scannedAgents: activeAgents.length,
    markedLost: lostAgentIds.length,
    lostAgentIds
  };
}
var watchdogInterval = null;
function startWatchdogScheduler(intervalMs = 6e4) {
  if (watchdogInterval) {
    clearInterval(watchdogInterval);
  }
  console.log(`[AgentWatchdog] Starting watchdog sweep (interval: ${intervalMs / 1e3}s)`);
  watchdogInterval = setInterval(async () => {
    try {
      const result = await runWatchdogSweep();
      if (result.markedLost > 0) {
        console.log(
          `[AgentWatchdog] Sweep complete: ${result.scannedAgents} scanned, ${result.markedLost} marked lost (${result.lostAgentIds.join(", ")})`
        );
      }
    } catch (err) {
      console.error("[AgentWatchdog] Sweep failed:", err);
    }
  }, intervalMs);
}
function stopWatchdogScheduler() {
  if (watchdogInterval) {
    clearInterval(watchdogInterval);
    watchdogInterval = null;
    console.log("[AgentWatchdog] Watchdog scheduler stopped");
  }
}

export {
  processHeartbeat,
  runWatchdogSweep,
  startWatchdogScheduler,
  stopWatchdogScheduler
};
