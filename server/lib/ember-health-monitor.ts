/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * EMBER AGENT HEALTH MONITOR — Auto-Discovery & Dead Agent Detection
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Provides:
 *   1. Scheduled health sweep — monitors all Ember agents' beacon timestamps
 *   2. Auto-marking dead agents — marks agents as "dead" after configurable
 *      missed beacon threshold (default: 3x beacon interval)
 *   3. Stale detection — identifies agents that are lagging but not yet dead
 *   4. Owner notifications — sends alerts when agents go dead or come back alive
 *   5. Health scoring — computes per-agent and fleet-wide health scores
 *   6. Auto-discovery — detects new agents that register between sweeps
 *
 * The sweep runs on a configurable interval (default: 30 seconds) and is
 * designed to be idempotent — safe to run concurrently or after restarts.
 */

import { getDb } from "../db";
import { emberAgents, emberBeacons, emberTasks } from "../../drizzle/schema";
import { eq, and, sql, inArray, desc, count, gte, ne } from "drizzle-orm";

// ─── Configuration ──────────────────────────────────────────────────────

export interface EmberHealthConfig {
  /** How many missed beacon intervals before marking agent as dead (default: 3) */
  deadThresholdMultiplier: number;
  /** How many missed beacon intervals before marking agent as stale (default: 1.5) */
  staleThresholdMultiplier: number;
  /** Default beacon interval in seconds if agent doesn't specify one (default: 60) */
  defaultBeaconIntervalSec: number;
  /** Sweep interval in milliseconds (default: 30_000 = 30s) */
  sweepIntervalMs: number;
  /** Whether to send owner notifications on state changes (default: true) */
  notificationsEnabled: boolean;
  /** Minimum time between notifications for the same agent (ms) to prevent spam (default: 300_000 = 5min) */
  notificationCooldownMs: number;
}

const DEFAULT_CONFIG: EmberHealthConfig = {
  deadThresholdMultiplier: 3,
  staleThresholdMultiplier: 1.5,
  defaultBeaconIntervalSec: 60,
  sweepIntervalMs: 30_000,
  notificationsEnabled: true,
  notificationCooldownMs: 300_000,
};

// ─── Types ──────────────────────────────────────────────────────────────

export type EmberHealthStatus = "healthy" | "stale" | "dead" | "unknown";

export interface EmberAgentHealth {
  agentId: string;
  name: string;
  profile: string;
  platform: string;
  hostname: string | null;
  previousState: string;
  currentState: string;
  healthStatus: EmberHealthStatus;
  lastBeaconAt: number | null;
  beaconCount: number;
  beaconInterval: number;
  missedBeacons: number;
  silentForSeconds: number;
  healthScore: number; // 0-100
  stateChanged: boolean;
}

export interface EmberHealthSweepResult {
  timestamp: number;
  sweepDurationMs: number;
  totalAgents: number;
  healthy: number;
  stale: number;
  dead: number;
  unknown: number;
  stateChanges: Array<{
    agentId: string;
    name: string;
    from: string;
    to: string;
    reason: string;
  }>;
  fleetHealthScore: number; // 0-100
  agents: EmberAgentHealth[];
}

// ─── Notification Cooldown Tracker ──────────────────────────────────────

const notificationCooldowns = new Map<string, number>();

function canNotify(agentId: string, cooldownMs: number): boolean {
  const lastNotified = notificationCooldowns.get(agentId) || 0;
  if (Date.now() - lastNotified < cooldownMs) return false;
  notificationCooldowns.set(agentId, Date.now());
  return true;
}

// ─── Health Score Calculation ───────────────────────────────────────────

function calculateHealthScore(
  lastBeaconAt: number | null,
  beaconInterval: number,
  now: number,
): number {
  if (!lastBeaconAt) return 0;
  const silentMs = now - lastBeaconAt;
  const expectedMs = beaconInterval * 1000;

  if (silentMs <= expectedMs * 1.2) return 100; // Within expected + 20% jitter
  if (silentMs <= expectedMs * 1.5) return 80;  // Slightly late
  if (silentMs <= expectedMs * 2) return 60;    // Noticeably late
  if (silentMs <= expectedMs * 3) return 30;    // Very late (stale)
  if (silentMs <= expectedMs * 5) return 10;    // Nearly dead
  return 0; // Dead
}

function determineHealthStatus(
  silentMs: number,
  beaconInterval: number,
  config: EmberHealthConfig,
): EmberHealthStatus {
  const expectedMs = beaconInterval * 1000;
  if (silentMs <= expectedMs * config.staleThresholdMultiplier) return "healthy";
  if (silentMs <= expectedMs * config.deadThresholdMultiplier) return "stale";
  return "dead";
}

// ─── Core Sweep Logic ───────────────────────────────────────────────────

export async function runEmberHealthSweep(
  config: Partial<EmberHealthConfig> = {},
): Promise<EmberHealthSweepResult> {
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
      agents: [],
    };
  }

  // Fetch all non-dead Ember agents (we also check dead ones that might have reconnected)
  const allAgents = await db
    .select()
    .from(emberAgents)
    .orderBy(desc(emberAgents.emberUpdatedAt));

  const agentHealths: EmberAgentHealth[] = [];
  const stateChanges: EmberHealthSweepResult["stateChanges"] = [];

  for (const agent of allAgents) {
    const beaconInterval = agent.beaconInterval || cfg.defaultBeaconIntervalSec;
    const lastBeaconAt = agent.lastBeaconAt ? Number(agent.lastBeaconAt) : null;
    const silentMs = lastBeaconAt ? now - lastBeaconAt : Infinity;
    const silentForSeconds = Math.round(silentMs / 1000);

    // Skip agents that are already in terminal states and haven't beaconed recently
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
        stateChanged: false,
      });
      continue;
    }

    // Calculate health
    const healthStatus = lastBeaconAt
      ? determineHealthStatus(silentMs, beaconInterval, cfg)
      : agent.state === "initializing" ? "unknown" : "dead";

    const healthScore = calculateHealthScore(lastBeaconAt, beaconInterval, now);
    const missedBeacons = lastBeaconAt
      ? Math.max(0, Math.floor(silentMs / (beaconInterval * 1000)) - 1)
      : 0;

    let newState = agent.state;
    let stateChanged = false;
    let changeReason = "";

    // Auto-mark dead: active/evading/pivoting/exfiltrating → dead
    const aliveStates = ["active", "evading", "pivoting", "exfiltrating", "dormant"];
    if (healthStatus === "dead" && aliveStates.includes(agent.state)) {
      newState = "dead";
      stateChanged = true;
      changeReason = `No beacon for ${silentForSeconds}s (threshold: ${beaconInterval * cfg.deadThresholdMultiplier}s)`;

      await db
        .update(emberAgents)
        .set({
          state: "dead",
          missedBeacons,
          updatedAt: now,
        })
        .where(eq(emberAgents.agentId, agent.agentId));

      stateChanges.push({
        agentId: agent.agentId,
        name: agent.name,
        from: agent.state,
        to: "dead",
        reason: changeReason,
      });

      // Send notification
      if (cfg.notificationsEnabled && canNotify(agent.agentId, cfg.notificationCooldownMs)) {
        sendAgentNotification(
          "dead",
          agent.agentId,
          agent.name,
          agent.hostname || "unknown",
          changeReason,
        ).catch((err) =>
          console.warn(`[EmberHealth] Notification failed for ${agent.agentId}:`, err.message),
        );
      }
    }

    // Detect reconnection: dead → active (if agent beaconed recently)
    if (agent.state === "dead" && healthStatus === "healthy" && lastBeaconAt) {
      newState = "active";
      stateChanged = true;
      changeReason = `Agent reconnected after ${silentForSeconds}s silence`;

      await db
        .update(emberAgents)
        .set({
          state: "active",
          missedBeacons: 0,
          updatedAt: now,
        })
        .where(eq(emberAgents.agentId, agent.agentId));

      stateChanges.push({
        agentId: agent.agentId,
        name: agent.name,
        from: "dead",
        to: "active",
        reason: changeReason,
      });

      // Send reconnection notification
      if (cfg.notificationsEnabled && canNotify(agent.agentId, cfg.notificationCooldownMs)) {
        sendAgentNotification(
          "reconnected",
          agent.agentId,
          agent.name,
          agent.hostname || "unknown",
          changeReason,
        ).catch((err) =>
          console.warn(`[EmberHealth] Notification failed for ${agent.agentId}:`, err.message),
        );
      }
    }

    // Update missed beacon count for stale agents
    if (healthStatus === "stale" && aliveStates.includes(agent.state)) {
      await db
        .update(emberAgents)
        .set({ missedBeacons, updatedAt: now })
        .where(eq(emberAgents.agentId, agent.agentId));
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
      stateChanged,
    });
  }

  // Calculate fleet health score (weighted average)
  const activeAgents = agentHealths.filter(
    (a) => a.currentState !== "self_destruct" && a.currentState !== "initializing",
  );
  const fleetHealthScore = activeAgents.length > 0
    ? Math.round(activeAgents.reduce((sum, a) => sum + a.healthScore, 0) / activeAgents.length)
    : 0;

  const sweepDurationMs = Date.now() - startTime;

  const result: EmberHealthSweepResult = {
    timestamp: now,
    sweepDurationMs,
    totalAgents: allAgents.length,
    healthy: agentHealths.filter((a) => a.healthStatus === "healthy").length,
    stale: agentHealths.filter((a) => a.healthStatus === "stale").length,
    dead: agentHealths.filter((a) => a.healthStatus === "dead").length,
    unknown: agentHealths.filter((a) => a.healthStatus === "unknown").length,
    stateChanges,
    fleetHealthScore,
    agents: agentHealths,
  };

  if (stateChanges.length > 0) {
    console.log(
      `[EmberHealth] Sweep: ${result.totalAgents} agents, ${result.healthy} healthy, ` +
      `${result.stale} stale, ${result.dead} dead | ${stateChanges.length} state changes | ` +
      `Fleet health: ${fleetHealthScore}% | ${sweepDurationMs}ms`,
    );
  }

  return result;
}

// ─── Notification Helper ────────────────────────────────────────────────

async function sendAgentNotification(
  event: "dead" | "reconnected" | "stale",
  agentId: string,
  agentName: string,
  hostname: string,
  reason: string,
): Promise<void> {
  try {
    const { notifyOwner } = await import("../_core/notification");

    const titles: Record<string, string> = {
      dead: `Ember Agent Down: ${agentName}`,
      reconnected: `Ember Agent Reconnected: ${agentName}`,
      stale: `Ember Agent Stale: ${agentName}`,
    };

    const contents: Record<string, string> = {
      dead: `Agent "${agentName}" (${agentId}) on ${hostname} has gone offline.\n\nReason: ${reason}\n\nThe agent has been automatically marked as dead. Check the Agent Management dashboard for details.`,
      reconnected: `Agent "${agentName}" (${agentId}) on ${hostname} has come back online.\n\nDetails: ${reason}\n\nThe agent has been automatically restored to active status.`,
      stale: `Agent "${agentName}" (${agentId}) on ${hostname} is responding slowly.\n\nDetails: ${reason}\n\nThe agent may be experiencing network issues or high load.`,
    };

    await notifyOwner({
      title: titles[event] || `Ember Agent Alert: ${agentName}`,
      content: contents[event] || reason,
    });

    console.log(`[EmberHealth] Notification sent: ${event} for ${agentId}`);
  } catch (err: any) {
    // Don't throw — notifications are best-effort
    console.warn(`[EmberHealth] Failed to send notification: ${err.message}`);
  }
}

// ─── Scheduler ──────────────────────────────────────────────────────────

let sweepInterval: ReturnType<typeof setInterval> | null = null;
let lastSweepResult: EmberHealthSweepResult | null = null;

/**
 * Start the Ember health monitor sweep on a fixed interval.
 */
export function startEmberHealthMonitor(config: Partial<EmberHealthConfig> = {}): void {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  if (sweepInterval) {
    clearInterval(sweepInterval);
  }

  console.log(
    `[EmberHealth] Starting health monitor (sweep every ${cfg.sweepIntervalMs / 1000}s, ` +
    `dead threshold: ${cfg.deadThresholdMultiplier}x, stale threshold: ${cfg.staleThresholdMultiplier}x)`,
  );

  // Run initial sweep immediately
  runEmberHealthSweep(cfg)
    .then((result) => {
      lastSweepResult = result;
      console.log(
        `[EmberHealth] Initial sweep: ${result.totalAgents} agents, ` +
        `${result.healthy} healthy, ${result.stale} stale, ${result.dead} dead | ` +
        `Fleet health: ${result.fleetHealthScore}%`,
      );
    })
    .catch((err) => console.error("[EmberHealth] Initial sweep failed:", err));

  sweepInterval = setInterval(async () => {
    try {
      lastSweepResult = await runEmberHealthSweep(cfg);
    } catch (err) {
      console.error("[EmberHealth] Sweep failed:", err);
    }
  }, cfg.sweepIntervalMs);
}

/**
 * Stop the Ember health monitor.
 */
export function stopEmberHealthMonitor(): void {
  if (sweepInterval) {
    clearInterval(sweepInterval);
    sweepInterval = null;
    console.log("[EmberHealth] Health monitor stopped");
  }
}

/**
 * Get the most recent sweep result (cached).
 */
export function getLastSweepResult(): EmberHealthSweepResult | null {
  return lastSweepResult;
}

/**
 * Force an immediate sweep (bypasses interval timer).
 */
export async function forceEmberHealthSweep(
  config: Partial<EmberHealthConfig> = {},
): Promise<EmberHealthSweepResult> {
  const result = await runEmberHealthSweep(config);
  lastSweepResult = result;
  return result;
}
