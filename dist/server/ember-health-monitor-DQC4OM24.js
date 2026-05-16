import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  emberAgents,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ember-health-monitor.ts
init_db();
init_schema();
import { eq, desc } from "drizzle-orm";
var DEFAULT_CONFIG = {
  deadThresholdMultiplier: 3,
  staleThresholdMultiplier: 1.5,
  defaultBeaconIntervalSec: 60,
  sweepIntervalMs: 3e4,
  notificationsEnabled: true,
  notificationCooldownMs: 3e5
};
var notificationCooldowns = /* @__PURE__ */ new Map();
function canNotify(agentId, cooldownMs) {
  const lastNotified = notificationCooldowns.get(agentId) || 0;
  if (Date.now() - lastNotified < cooldownMs) return false;
  notificationCooldowns.set(agentId, Date.now());
  return true;
}
function calculateHealthScore(lastBeaconAt, beaconInterval, now) {
  if (!lastBeaconAt) return 0;
  const silentMs = now - lastBeaconAt;
  const expectedMs = beaconInterval * 1e3;
  if (silentMs <= expectedMs * 1.2) return 100;
  if (silentMs <= expectedMs * 1.5) return 80;
  if (silentMs <= expectedMs * 2) return 60;
  if (silentMs <= expectedMs * 3) return 30;
  if (silentMs <= expectedMs * 5) return 10;
  return 0;
}
function determineHealthStatus(silentMs, beaconInterval, config) {
  const expectedMs = beaconInterval * 1e3;
  if (silentMs <= expectedMs * config.staleThresholdMultiplier) return "healthy";
  if (silentMs <= expectedMs * config.deadThresholdMultiplier) return "stale";
  return "dead";
}
async function runEmberHealthSweep(config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const now = startTime;
  const db = await getDb();
  if (!db) {
    return {
      timestamp: now,
      sweepDurationMs: 0,
      totalAgents: 0,
      healthy: 0,
      stale: 0,
      dead: 0,
      unknown: 0,
      stateChanges: [],
      fleetHealthScore: 0,
      agents: []
    };
  }
  const allAgents = await db.select().from(emberAgents).orderBy(desc(emberAgents.emberUpdatedAt));
  const agentHealths = [];
  const stateChanges = [];
  for (const agent of allAgents) {
    const beaconInterval = agent.beaconInterval || cfg.defaultBeaconIntervalSec;
    const lastBeaconAt = agent.lastBeaconAt ? Number(agent.lastBeaconAt) : null;
    const silentMs = lastBeaconAt ? now - lastBeaconAt : Infinity;
    const silentForSeconds = Math.round(silentMs / 1e3);
    if (agent.state === "self_destruct") {
      agentHealths.push({
        agentId: agent.agentId,
        name: agent.name,
        profile: agent.profile,
        platform: agent.platform,
        hostname: agent.hostname,
        previousState: agent.state,
        currentState: agent.state,
        healthStatus: "dead",
        lastBeaconAt,
        beaconCount: agent.beaconCount || 0,
        beaconInterval,
        missedBeacons: 0,
        silentForSeconds,
        healthScore: 0,
        stateChanged: false
      });
      continue;
    }
    const healthStatus = lastBeaconAt ? determineHealthStatus(silentMs, beaconInterval, cfg) : agent.state === "initializing" ? "unknown" : "dead";
    const healthScore = calculateHealthScore(lastBeaconAt, beaconInterval, now);
    const missedBeacons = lastBeaconAt ? Math.max(0, Math.floor(silentMs / (beaconInterval * 1e3)) - 1) : 0;
    let newState = agent.state;
    let stateChanged = false;
    let changeReason = "";
    const aliveStates = ["active", "evading", "pivoting", "exfiltrating", "dormant"];
    if (healthStatus === "dead" && aliveStates.includes(agent.state)) {
      newState = "dead";
      stateChanged = true;
      changeReason = `No beacon for ${silentForSeconds}s (threshold: ${beaconInterval * cfg.deadThresholdMultiplier}s)`;
      await db.update(emberAgents).set({
        state: "dead",
        missedBeacons,
        updatedAt: now
      }).where(eq(emberAgents.agentId, agent.agentId));
      stateChanges.push({
        agentId: agent.agentId,
        name: agent.name,
        from: agent.state,
        to: "dead",
        reason: changeReason
      });
      if (cfg.notificationsEnabled && canNotify(agent.agentId, cfg.notificationCooldownMs)) {
        sendAgentNotification(
          "dead",
          agent.agentId,
          agent.name,
          agent.hostname || "unknown",
          changeReason
        ).catch(
          (err) => console.warn(`[EmberHealth] Notification failed for ${agent.agentId}:`, err.message)
        );
      }
    }
    if (agent.state === "dead" && healthStatus === "healthy" && lastBeaconAt) {
      newState = "active";
      stateChanged = true;
      changeReason = `Agent reconnected after ${silentForSeconds}s silence`;
      await db.update(emberAgents).set({
        state: "active",
        missedBeacons: 0,
        updatedAt: now
      }).where(eq(emberAgents.agentId, agent.agentId));
      stateChanges.push({
        agentId: agent.agentId,
        name: agent.name,
        from: "dead",
        to: "active",
        reason: changeReason
      });
      if (cfg.notificationsEnabled && canNotify(agent.agentId, cfg.notificationCooldownMs)) {
        sendAgentNotification(
          "reconnected",
          agent.agentId,
          agent.name,
          agent.hostname || "unknown",
          changeReason
        ).catch(
          (err) => console.warn(`[EmberHealth] Notification failed for ${agent.agentId}:`, err.message)
        );
      }
    }
    if (healthStatus === "stale" && aliveStates.includes(agent.state)) {
      await db.update(emberAgents).set({ missedBeacons, updatedAt: now }).where(eq(emberAgents.agentId, agent.agentId));
    }
    agentHealths.push({
      agentId: agent.agentId,
      name: agent.name,
      profile: agent.profile,
      platform: agent.platform,
      hostname: agent.hostname,
      previousState: agent.state,
      currentState: newState,
      healthStatus,
      lastBeaconAt,
      beaconCount: agent.beaconCount || 0,
      beaconInterval,
      missedBeacons,
      silentForSeconds,
      healthScore,
      stateChanged
    });
  }
  const activeAgents = agentHealths.filter(
    (a) => a.currentState !== "self_destruct" && a.currentState !== "initializing"
  );
  const fleetHealthScore = activeAgents.length > 0 ? Math.round(activeAgents.reduce((sum, a) => sum + a.healthScore, 0) / activeAgents.length) : 0;
  const sweepDurationMs = Date.now() - startTime;
  const result = {
    timestamp: now,
    sweepDurationMs,
    totalAgents: allAgents.length,
    healthy: agentHealths.filter((a) => a.healthStatus === "healthy").length,
    stale: agentHealths.filter((a) => a.healthStatus === "stale").length,
    dead: agentHealths.filter((a) => a.healthStatus === "dead").length,
    unknown: agentHealths.filter((a) => a.healthStatus === "unknown").length,
    stateChanges,
    fleetHealthScore,
    agents: agentHealths
  };
  if (stateChanges.length > 0) {
    console.log(
      `[EmberHealth] Sweep: ${result.totalAgents} agents, ${result.healthy} healthy, ${result.stale} stale, ${result.dead} dead | ${stateChanges.length} state changes | Fleet health: ${fleetHealthScore}% | ${sweepDurationMs}ms`
    );
  }
  return result;
}
async function sendAgentNotification(event, agentId, agentName, hostname, reason) {
  try {
    const { notifyOwner } = await import("./notification-Z5HC4QO5.js");
    const titles = {
      dead: `Ember Agent Down: ${agentName}`,
      reconnected: `Ember Agent Reconnected: ${agentName}`,
      stale: `Ember Agent Stale: ${agentName}`
    };
    const contents = {
      dead: `Agent "${agentName}" (${agentId}) on ${hostname} has gone offline.

Reason: ${reason}

The agent has been automatically marked as dead. Check the Agent Management dashboard for details.`,
      reconnected: `Agent "${agentName}" (${agentId}) on ${hostname} has come back online.

Details: ${reason}

The agent has been automatically restored to active status.`,
      stale: `Agent "${agentName}" (${agentId}) on ${hostname} is responding slowly.

Details: ${reason}

The agent may be experiencing network issues or high load.`
    };
    await notifyOwner({
      title: titles[event] || `Ember Agent Alert: ${agentName}`,
      content: contents[event] || reason
    });
    console.log(`[EmberHealth] Notification sent: ${event} for ${agentId}`);
  } catch (err) {
    console.warn(`[EmberHealth] Failed to send notification: ${err.message}`);
  }
}
var sweepInterval = null;
var lastSweepResult = null;
function startEmberHealthMonitor(config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  if (sweepInterval) {
    clearInterval(sweepInterval);
  }
  console.log(
    `[EmberHealth] Starting health monitor (sweep every ${cfg.sweepIntervalMs / 1e3}s, dead threshold: ${cfg.deadThresholdMultiplier}x, stale threshold: ${cfg.staleThresholdMultiplier}x)`
  );
  runEmberHealthSweep(cfg).then((result) => {
    lastSweepResult = result;
    console.log(
      `[EmberHealth] Initial sweep: ${result.totalAgents} agents, ${result.healthy} healthy, ${result.stale} stale, ${result.dead} dead | Fleet health: ${result.fleetHealthScore}%`
    );
  }).catch((err) => console.error("[EmberHealth] Initial sweep failed:", err));
  sweepInterval = setInterval(async () => {
    try {
      lastSweepResult = await runEmberHealthSweep(cfg);
    } catch (err) {
      console.error("[EmberHealth] Sweep failed:", err);
    }
  }, cfg.sweepIntervalMs);
}
function stopEmberHealthMonitor() {
  if (sweepInterval) {
    clearInterval(sweepInterval);
    sweepInterval = null;
    console.log("[EmberHealth] Health monitor stopped");
  }
}
function getLastSweepResult() {
  return lastSweepResult;
}
async function forceEmberHealthSweep(config = {}) {
  const result = await runEmberHealthSweep(config);
  lastSweepResult = result;
  return result;
}
export {
  forceEmberHealthSweep,
  getLastSweepResult,
  runEmberHealthSweep,
  startEmberHealthMonitor,
  stopEmberHealthMonitor
};
