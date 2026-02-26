/**
 * Agent Heartbeat Ingestion & Watchdog Service
 *
 * Provides:
 *   1. Heartbeat processing — updates agent lastHeartbeat, system info, and
 *      transitions agents from approved/deploying → active on first beacon.
 *   2. Watchdog sweep — periodically scans for agents whose lastHeartbeat
 *      exceeds their watchdogSeconds threshold, marking them as "lost".
 *   3. Reconnection detection — when a "lost" agent sends a heartbeat, it
 *      transitions back to "active" and logs a reconnection event.
 *
 * All mutations are audit-logged with HMAC-chained integrity.
 */

import { getDb } from "../db";
import {
  agentDeployments,
  agentAuditLog,
} from "../../drizzle/schema";
import { eq, and, sql, lte, inArray } from "drizzle-orm";
import { getFIPSCrypto } from "./fips-crypto";

// ─── Types ──────────────────────────────────────────────────────────────

export interface HeartbeatPayload {
  agentId: string;
  registrationToken?: string;
  // System info reported by agent
  platform?: string;
  architecture?: string;
  username?: string;
  privilege?: "user" | "elevated";
  executors?: string[];
  pid?: number;
  hostname?: string;
  internalIp?: string;
  // Beacon metadata
  ipAddress?: string;
  userAgent?: string;
}

export interface HeartbeatResult {
  accepted: boolean;
  agentId: string;
  previousStatus: string | null;
  newStatus: string;
  message: string;
}

// ─── Audit Logging Helper ───────────────────────────────────────────────

async function logHeartbeatEvent(
  agentId: string,
  eventType: "heartbeat" | "lost" | "reconnected",
  actorType: "agent" | "system",
  details?: Record<string, unknown>,
  ipAddress?: string,
  userAgent?: string,
) {
  const db = await getDb();
  if (!db) return;

  const fips = getFIPSCrypto();

  // Get last audit entry for this agent to chain hashes
  const [lastEntry] = await db
    .select({ recordHash: agentAuditLog.recordHash })
    .from(agentAuditLog)
    .where(eq(agentAuditLog.agentId, agentId))
    .orderBy(sql`id DESC`)
    .limit(1);

  const previousHash = lastEntry?.recordHash ?? "genesis";
  const recordData = JSON.stringify({
    agentId,
    eventType,
    actorType,
    details,
    previousHash,
    timestamp: Date.now(),
  });
  const recordHash = fips.hmac(recordData).mac;

  await db.insert(agentAuditLog).values({
    agentId,
    eventType: eventType as any,
    actorId: null,
    actorType,
    details,
    recordHash,
    previousHash,
    ipAddress: ipAddress ?? null,
    userAgent: userAgent ?? null,
    createdAt: Date.now(),
  });
}

// ─── Heartbeat Processing ───────────────────────────────────────────────

/**
 * Process an incoming agent heartbeat.
 *
 * State transitions:
 *   - approved/deploying → active (first beacon)
 *   - lost → active (reconnection)
 *   - active → active (normal heartbeat)
 *   - paused → paused (heartbeat received but agent stays paused)
 *   - terminated/completed/failed → rejected (agent should not beacon)
 */
export async function processHeartbeat(payload: HeartbeatPayload): Promise<HeartbeatResult> {
  const db = await getDb();
  if (!db) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus: null,
      newStatus: "unknown",
      message: "Database unavailable",
    };
  }

  // Look up agent
  const [agent] = await db
    .select()
    .from(agentDeployments)
    .where(eq(agentDeployments.id, payload.agentId));

  if (!agent) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus: null,
      newStatus: "unknown",
      message: "Agent not found",
    };
  }

  const previousStatus = agent.status;
  const now = Date.now();

  // Reject heartbeats from terminal-state agents
  const terminalStates = ["terminated", "completed", "failed"];
  if (previousStatus && terminalStates.includes(previousStatus)) {
    return {
      accepted: false,
      agentId: payload.agentId,
      previousStatus,
      newStatus: previousStatus,
      message: `Agent in terminal state (${previousStatus}); heartbeat rejected`,
    };
  }

  // Build update set
  const updateSet: Record<string, unknown> = {
    lastHeartbeat: now,
    updatedAt: now,
  };

  // Update system info if provided
  if (payload.platform) updateSet.agentPlatform = payload.platform;
  if (payload.architecture) updateSet.agentArchitecture = payload.architecture;
  if (payload.username) updateSet.agentUsername = payload.username;
  if (payload.privilege) updateSet.agentPrivilege = payload.privilege;
  if (payload.executors) updateSet.agentExecutors = payload.executors;
  if (payload.pid) updateSet.agentPid = payload.pid;
  if (payload.hostname) updateSet.targetHostname = payload.hostname;
  if (payload.internalIp) updateSet.targetIp = payload.internalIp;

  // Determine status transition
  let newStatus = previousStatus;
  let eventType: "heartbeat" | "reconnected" = "heartbeat";

  if (previousStatus === "approved" || previousStatus === "deploying") {
    // First beacon — agent is now active
    newStatus = "active";
    updateSet.status = "active";
    updateSet.deployedAt = now;
  } else if (previousStatus === "lost") {
    // Reconnection
    newStatus = "active";
    updateSet.status = "active";
    eventType = "reconnected";
  } else if (previousStatus === "pending_approval") {
    // Agent beaconing before approval — accept heartbeat but don't activate
    newStatus = "pending_approval";
  }
  // active/paused — keep current status, just update heartbeat

  await db
    .update(agentDeployments)
    .set(updateSet)
    .where(eq(agentDeployments.id, payload.agentId));

  // Log the event
  await logHeartbeatEvent(
    payload.agentId,
    eventType,
    "agent",
    {
      previousStatus,
      newStatus,
      platform: payload.platform,
      hostname: payload.hostname,
      ip: payload.internalIp,
    },
    payload.ipAddress,
    payload.userAgent,
  );

  return {
    accepted: true,
    agentId: payload.agentId,
    previousStatus,
    newStatus: newStatus ?? "unknown",
    message: eventType === "reconnected"
      ? `Agent reconnected (was lost for ${agent.lastHeartbeat ? Math.round((now - agent.lastHeartbeat) / 1000) : "unknown"}s)`
      : previousStatus === "approved" || previousStatus === "deploying"
        ? "First beacon received — agent now active"
        : "Heartbeat accepted",
  };
}

// ─── Watchdog Sweep ─────────────────────────────────────────────────────

export interface WatchdogResult {
  scannedAgents: number;
  markedLost: number;
  lostAgentIds: string[];
}

/**
 * Scan all active/approved/deploying agents and mark those whose
 * lastHeartbeat exceeds their watchdogSeconds threshold as "lost".
 */
export async function runWatchdogSweep(): Promise<WatchdogResult> {
  const db = await getDb();
  if (!db) {
    return { scannedAgents: 0, markedLost: 0, lostAgentIds: [] };
  }

  const now = Date.now();

  // Find agents that should be checked (active states with a heartbeat)
  const activeAgents = await db
    .select({
      id: agentDeployments.id,
      status: agentDeployments.status,
      lastHeartbeat: agentDeployments.lastHeartbeat,
      watchdogSeconds: agentDeployments.watchdogSeconds,
      deployedAt: agentDeployments.deployedAt,
    })
    .from(agentDeployments)
    .where(
      inArray(agentDeployments.status, ["active", "paused"])
    );

  const lostAgentIds: string[] = [];

  for (const agent of activeAgents) {
    const lastSeen = agent.lastHeartbeat ?? agent.deployedAt ?? 0;
    const thresholdMs = (agent.watchdogSeconds ?? 14400) * 1000;

    if (now - lastSeen > thresholdMs) {
      // Mark as lost
      await db
        .update(agentDeployments)
        .set({ status: "lost", updatedAt: now })
        .where(eq(agentDeployments.id, agent.id));

      await logHeartbeatEvent(agent.id, "lost", "system", {
        lastHeartbeat: lastSeen,
        watchdogSeconds: agent.watchdogSeconds,
        silentForSeconds: Math.round((now - lastSeen) / 1000),
      });

      lostAgentIds.push(agent.id);
    }
  }

  return {
    scannedAgents: activeAgents.length,
    markedLost: lostAgentIds.length,
    lostAgentIds,
  };
}

// ─── Watchdog Scheduler ─────────────────────────────────────────────────

let watchdogInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start the watchdog sweep on a fixed interval (default: every 60 seconds).
 */
export function startWatchdogScheduler(intervalMs: number = 60_000): void {
  if (watchdogInterval) {
    clearInterval(watchdogInterval);
  }

  console.log(`[AgentWatchdog] Starting watchdog sweep (interval: ${intervalMs / 1000}s)`);

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

/**
 * Stop the watchdog scheduler.
 */
export function stopWatchdogScheduler(): void {
  if (watchdogInterval) {
    clearInterval(watchdogInterval);
    watchdogInterval = null;
    console.log("[AgentWatchdog] Watchdog scheduler stopped");
  }
}
