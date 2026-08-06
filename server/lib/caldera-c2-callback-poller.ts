/**
 * Caldera C2 Callback Poller
 *
 * Polls the Caldera REST API for real-time C2 agent check-ins, ability executions,
 * and operation progress. Emits WebSocket events for each detected change so the
 * engagement monitor and cockpit can display live C2 activity.
 *
 * Lifecycle:
 *   startPolling(engagementId, operationId) → begins interval polling
 *   stopPolling(engagementId) → stops polling for that engagement
 *   getPollerState(engagementId) → returns current poller snapshot
 *
 * Events emitted:
 *   c2:agent_checkin     — new agent or agent heartbeat detected
 *   c2:ability_executed  — new link (ability execution) completed on an agent
 *   c2:operation_update  — operation state changed (running/paused/finished)
 *   c2:agent_lost        — agent missed heartbeat threshold
 */

import { ENV } from "../_core/env";
import {
  emitAgentCheckin,
  emitOperationUpdate,
  emitAgentDeployed,
  emitSystemNotification,
  eventHub,
} from "./ws-event-hub";

// ─── Types ──────────────────────────────────────────────────────────────

interface C2Agent {
  paw: string;
  host: string;
  platform: string;
  group: string;
  executors: string[];
  lastSeen: string;
  trusted: boolean;
  /** Internal tracking: when we first saw this agent */
  firstSeenAt: number;
  /** Internal tracking: last heartbeat we processed */
  lastProcessedHeartbeat: string;
}

interface C2Link {
  id: string;
  abilityId: string;
  abilityName: string;
  paw: string;
  status: number; // 0=success, 1=fail, -2=discarded, -3=collecting, -1=queued
  output?: string;
  collect?: string;
  finish?: string;
  /** Decoded output (base64 → string) */
  decodedOutput?: string;
}

interface C2OperationSnapshot {
  id: string;
  name: string;
  state: string;
  agentCount: number;
  linkCount: number;
  successCount: number;
  failCount: number;
  inProgressCount: number;
}

export interface C2PollerState {
  engagementId: number;
  operationId: string;
  isPolling: boolean;
  pollIntervalMs: number;
  lastPollAt: number;
  pollCount: number;
  /** All agents seen during this operation */
  agents: Map<string, C2Agent>;
  /** All links (ability executions) seen */
  processedLinkIds: Set<string>;
  /** Latest operation snapshot */
  operationSnapshot: C2OperationSnapshot | null;
  /** Event log for this poller session */
  events: Array<{
    timestamp: number;
    type: string;
    summary: string;
    data?: any;
  }>;
  /** Error count for circuit breaker */
  consecutiveErrors: number;
  /** Agent heartbeat miss tracking */
  agentHeartbeatMisses: Map<string, number>;
}

// ─── In-Memory Poller Registry ──────────────────────────────────────────

const pollers = new Map<number, {
  state: C2PollerState;
  intervalHandle: ReturnType<typeof setInterval> | null;
}>();

// ─── Caldera API Client ─────────────────────────────────────────────────

const getCalderaUrl = () => ENV.calderaBaseUrl || "";
const getCalderaKey = () => ENV.calderaApiKey || "";

async function calderaFetch(endpoint: string): Promise<{ ok: boolean; data: any }> {
  const baseUrl = getCalderaUrl();
  const apiKey = getCalderaKey();
  if (!baseUrl || !apiKey) return { ok: false, data: null };

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      headers: { KEY: apiKey, "Content-Type": "application/json" },
      signal: AbortSignal.timeout(15000),
    });
    const data = response.ok ? await response.json().catch(() => null) : null;
    return { ok: response.ok, data };
  } catch {
    return { ok: false, data: null };
  }
}

function decodeBase64(encoded: string): string {
  try {
    return Buffer.from(encoded, "base64").toString("utf-8");
  } catch {
    return encoded;
  }
}

// ─── Core Poll Logic ────────────────────────────────────────────────────

async function pollCalderaOperation(engagementId: number): Promise<void> {
  const poller = pollers.get(engagementId);
  if (!poller || !poller.state.isPolling) return;

  const state = poller.state;
  state.lastPollAt = Date.now();
  state.pollCount++;

  try {
    // 1. Poll operation status
    const opResult = await calderaFetch(`/api/v2/operations/${state.operationId}`);
    if (!opResult.ok || !opResult.data) {
      state.consecutiveErrors++;
      if (state.consecutiveErrors >= 5) {
        addPollerEvent(state, "error", `Circuit breaker: ${state.consecutiveErrors} consecutive poll failures. Backing off.`);
        // Don't stop, just slow down — the interval will handle it
      }
      return;
    }

    state.consecutiveErrors = 0;
    const op = opResult.data;

    // 2. Detect operation state changes
    const newSnapshot: C2OperationSnapshot = {
      id: String(op.id),
      name: op.name || "Unknown",
      state: op.state || "running",
      agentCount: op.host_group?.length || 0,
      linkCount: op.chain?.length || 0,
      successCount: op.chain?.filter((l: any) => l.status === 0).length || 0,
      failCount: op.chain?.filter((l: any) => l.status === 1 || l.status === -2).length || 0,
      inProgressCount: op.chain?.filter((l: any) => l.status === -3 || l.status === -1).length || 0,
    };

    const prevSnapshot = state.operationSnapshot;
    state.operationSnapshot = newSnapshot;

    if (prevSnapshot && prevSnapshot.state !== newSnapshot.state) {
      addPollerEvent(state, "c2:operation_update", `Operation state: ${prevSnapshot.state} → ${newSnapshot.state}`);
      emitOperationUpdate({
        operationId: state.operationId,
        name: newSnapshot.name,
        state: newSnapshot.state as any,
        agentCount: newSnapshot.agentCount,
        linkCount: newSnapshot.linkCount,
        successCount: newSnapshot.successCount,
        engagementId,
      });
    }

    // 3. Poll agents and detect new check-ins
    const agentsResult = await calderaFetch("/api/v2/agents");
    if (agentsResult.ok && Array.isArray(agentsResult.data)) {
      for (const rawAgent of agentsResult.data) {
        const paw = rawAgent.paw || "";
        if (!paw) continue;

        const existingAgent = state.agents.get(paw);
        const lastSeen = rawAgent.last_seen || "";

        if (!existingAgent) {
          // New agent discovered!
          const newAgent: C2Agent = {
            paw,
            host: rawAgent.host || "",
            platform: rawAgent.platform || "",
            group: rawAgent.group || "",
            executors: rawAgent.executors?.map((e: any) => e.name || e) || [],
            lastSeen,
            trusted: rawAgent.trusted ?? true,
            firstSeenAt: Date.now(),
            lastProcessedHeartbeat: lastSeen,
          };
          state.agents.set(paw, newAgent);
          state.agentHeartbeatMisses.set(paw, 0);

          addPollerEvent(state, "c2:agent_checkin", `New agent: ${paw} on ${newAgent.host} (${newAgent.platform})`, { agent: newAgent });

          emitAgentCheckin({
            paw,
            host: newAgent.host,
            platform: newAgent.platform,
          });

          // Also emit agent deployed for the engagement
          emitAgentDeployed({
            paw,
            host: newAgent.host,
            platform: newAgent.platform,
            executors: newAgent.executors,
            engagementId,
          });
        } else if (lastSeen !== existingAgent.lastProcessedHeartbeat) {
          // Agent heartbeat update
          existingAgent.lastSeen = lastSeen;
          existingAgent.lastProcessedHeartbeat = lastSeen;
          state.agentHeartbeatMisses.set(paw, 0);

          emitAgentCheckin({
            paw,
            host: existingAgent.host,
            platform: existingAgent.platform,
          });
        } else {
          // No new heartbeat — increment miss counter
          const misses = (state.agentHeartbeatMisses.get(paw) || 0) + 1;
          state.agentHeartbeatMisses.set(paw, misses);

          // If agent missed 5+ consecutive polls (50s at 10s interval), mark as lost
          if (misses === 5) {
            addPollerEvent(state, "c2:agent_lost", `Agent ${paw} on ${existingAgent.host} — no heartbeat for ${misses * (state.pollIntervalMs / 1000)}s`);
            eventHub.broadcastEngagement(engagementId, {
              type: "agent:lost",
              timestamp: Date.now(),
              engagementId,
              data: { paw, host: existingAgent.host, platform: existingAgent.platform, missedPolls: misses },
            });
          }
        }
      }
    }

    // 4. Process new links (ability executions)
    const chain = op.chain || [];
    for (const link of chain) {
      const linkId = String(link.id || link.unique || `${link.paw}-${link.ability?.ability_id}-${link.finish}`);
      if (state.processedLinkIds.has(linkId)) continue;

      // Only process completed links (status 0 = success, 1 = fail, -2 = discarded)
      if (link.status === -3 || link.status === -1) continue; // still collecting/queued

      state.processedLinkIds.add(linkId);

      const abilityName = link.ability?.name || link.ability_id || "Unknown";
      const abilityId = link.ability?.ability_id || link.ability_id || "";
      const paw = link.paw || "";
      const status = link.status;
      const output = link.output ? decodeBase64(link.output) : undefined;
      const statusLabel = status === 0 ? "success" : status === 1 ? "fail" : "discarded";

      addPollerEvent(
        state,
        "c2:ability_executed",
        `[${statusLabel}] ${abilityName} on agent ${paw}${output ? ` — ${output.substring(0, 200)}` : ""}`,
        { linkId, abilityId, abilityName, paw, status, outputPreview: output?.substring(0, 500) },
      );

      // Emit WebSocket event
      eventHub.broadcastEngagement(engagementId, {
        type: "operation:step_complete",
        timestamp: Date.now(),
        engagementId,
        data: {
          operationId: state.operationId,
          linkId,
          abilityId,
          abilityName,
          paw,
          status: statusLabel,
          output: output?.substring(0, 1000),
          collect: link.collect,
          finish: link.finish,
        },
      });
    }

    // 5. Check if operation finished
    if (newSnapshot.state === "finished" && (!prevSnapshot || prevSnapshot.state !== "finished")) {
      addPollerEvent(state, "c2:operation_complete", `Operation ${newSnapshot.name} finished. ${newSnapshot.successCount}/${newSnapshot.linkCount} abilities succeeded.`);

      emitSystemNotification({
        title: "C2 Operation Complete",
        message: `Operation "${newSnapshot.name}" finished with ${newSnapshot.successCount} successful and ${newSnapshot.failCount} failed ability executions across ${newSnapshot.agentCount} agents.`,
        severity: "info",
      });

      // Auto-stop polling when operation finishes
      stopPolling(engagementId);
    }
  } catch (err: any) {
    state.consecutiveErrors++;
    addPollerEvent(state, "error", `Poll error: ${err.message}`);
  }
}

function addPollerEvent(state: C2PollerState, type: string, summary: string, data?: any): void {
  state.events.push({ timestamp: Date.now(), type, summary, data });
  // Keep last 500 events
  if (state.events.length > 500) {
    state.events = state.events.slice(-500);
  }
  console.log(`[C2Poller] [eng#${state.engagementId}] ${type}: ${summary}`);
}

// ─── Public API ─────────────────────────────────────────────────────────

/**
 * Start polling a Caldera operation for an engagement.
 * Polls every `intervalMs` (default 10s) for agent check-ins and ability executions.
 */
export function startPolling(
  engagementId: number,
  operationId: string,
  intervalMs: number = 10000,
): C2PollerState {
  // Stop existing poller if any
  stopPolling(engagementId);

  const state: C2PollerState = {
    engagementId,
    operationId,
    isPolling: true,
    pollIntervalMs: intervalMs,
    lastPollAt: 0,
    pollCount: 0,
    agents: new Map(),
    processedLinkIds: new Set(),
    operationSnapshot: null,
    events: [],
    consecutiveErrors: 0,
    agentHeartbeatMisses: new Map(),
  };

  addPollerEvent(state, "started", `Polling Caldera operation ${operationId} every ${intervalMs / 1000}s`);

  const intervalHandle = setInterval(() => {
    pollCalderaOperation(engagementId).catch((err) => {
      console.error(`[C2Poller] Unhandled error for eng#${engagementId}:`, err.message);
    });
  }, intervalMs);

  pollers.set(engagementId, { state, intervalHandle });

  // Run first poll immediately
  pollCalderaOperation(engagementId).catch(() => {});

  return state;
}

/**
 * Stop polling for an engagement.
 */
export function stopPolling(engagementId: number): void {
  const poller = pollers.get(engagementId);
  if (!poller) return;

  poller.state.isPolling = false;
  if (poller.intervalHandle) {
    clearInterval(poller.intervalHandle);
    poller.intervalHandle = null;
  }

  addPollerEvent(poller.state, "stopped", `Polling stopped after ${poller.state.pollCount} polls`);
  console.log(`[C2Poller] Stopped polling for engagement #${engagementId}`);
}

/**
 * Get the current poller state for an engagement.
 */
export function getPollerState(engagementId: number): C2PollerState | null {
  const poller = pollers.get(engagementId);
  return poller?.state || null;
}

/**
 * Get a serializable snapshot of the poller state (for API responses).
 */
export function getPollerSnapshot(engagementId: number): any | null {
  const state = getPollerState(engagementId);
  if (!state) return null;

  return {
    engagementId: state.engagementId,
    operationId: state.operationId,
    isPolling: state.isPolling,
    pollIntervalMs: state.pollIntervalMs,
    lastPollAt: state.lastPollAt,
    pollCount: state.pollCount,
    agents: [...state.agents.values()],
    processedLinkCount: state.processedLinkIds.size,
    operationSnapshot: state.operationSnapshot,
    recentEvents: state.events.slice(-50),
    consecutiveErrors: state.consecutiveErrors,
  };
}

/**
 * List all active pollers.
 */
export function listActivePollers(): Array<{
  engagementId: number;
  operationId: string;
  isPolling: boolean;
  agentCount: number;
  linkCount: number;
  pollCount: number;
}> {
  return [...pollers.entries()].map(([engId, p]) => ({
    engagementId: engId,
    operationId: p.state.operationId,
    isPolling: p.state.isPolling,
    agentCount: p.state.agents.size,
    linkCount: p.state.processedLinkIds.size,
    pollCount: p.state.pollCount,
  }));
}
