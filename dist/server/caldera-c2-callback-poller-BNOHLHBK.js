import {
  emitAgentCheckin,
  emitAgentDeployed,
  emitOperationUpdate,
  emitSystemNotification,
  eventHub,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/caldera-c2-callback-poller.ts
async function calderaFetch(endpoint) {
  const baseUrl = getCalderaUrl();
  const apiKey = getCalderaKey();
  if (!baseUrl || !apiKey) return { ok: false, data: null };
  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      headers: { KEY: apiKey, "Content-Type": "application/json" },
      signal: AbortSignal.timeout(15e3)
    });
    const data = response.ok ? await response.json().catch(() => null) : null;
    return { ok: response.ok, data };
  } catch {
    return { ok: false, data: null };
  }
}
function decodeBase64(encoded) {
  try {
    return Buffer.from(encoded, "base64").toString("utf-8");
  } catch {
    return encoded;
  }
}
async function pollCalderaOperation(engagementId) {
  const poller = pollers.get(engagementId);
  if (!poller || !poller.state.isPolling) return;
  const state = poller.state;
  state.lastPollAt = Date.now();
  state.pollCount++;
  try {
    const opResult = await calderaFetch(`/api/v2/operations/${state.operationId}`);
    if (!opResult.ok || !opResult.data) {
      state.consecutiveErrors++;
      if (state.consecutiveErrors >= 5) {
        addPollerEvent(state, "error", `Circuit breaker: ${state.consecutiveErrors} consecutive poll failures. Backing off.`);
      }
      return;
    }
    state.consecutiveErrors = 0;
    const op = opResult.data;
    const newSnapshot = {
      id: String(op.id),
      name: op.name || "Unknown",
      state: op.state || "running",
      agentCount: op.host_group?.length || 0,
      linkCount: op.chain?.length || 0,
      successCount: op.chain?.filter((l) => l.status === 0).length || 0,
      failCount: op.chain?.filter((l) => l.status === 1 || l.status === -2).length || 0,
      inProgressCount: op.chain?.filter((l) => l.status === -3 || l.status === -1).length || 0
    };
    const prevSnapshot = state.operationSnapshot;
    state.operationSnapshot = newSnapshot;
    if (prevSnapshot && prevSnapshot.state !== newSnapshot.state) {
      addPollerEvent(state, "c2:operation_update", `Operation state: ${prevSnapshot.state} \u2192 ${newSnapshot.state}`);
      emitOperationUpdate({
        operationId: state.operationId,
        name: newSnapshot.name,
        state: newSnapshot.state,
        agentCount: newSnapshot.agentCount,
        linkCount: newSnapshot.linkCount,
        successCount: newSnapshot.successCount,
        engagementId
      });
    }
    const agentsResult = await calderaFetch("/api/v2/agents");
    if (agentsResult.ok && Array.isArray(agentsResult.data)) {
      for (const rawAgent of agentsResult.data) {
        const paw = rawAgent.paw || "";
        if (!paw) continue;
        const existingAgent = state.agents.get(paw);
        const lastSeen = rawAgent.last_seen || "";
        if (!existingAgent) {
          const newAgent = {
            paw,
            host: rawAgent.host || "",
            platform: rawAgent.platform || "",
            group: rawAgent.group || "",
            executors: rawAgent.executors?.map((e) => e.name || e) || [],
            lastSeen,
            trusted: rawAgent.trusted ?? true,
            firstSeenAt: Date.now(),
            lastProcessedHeartbeat: lastSeen
          };
          state.agents.set(paw, newAgent);
          state.agentHeartbeatMisses.set(paw, 0);
          addPollerEvent(state, "c2:agent_checkin", `New agent: ${paw} on ${newAgent.host} (${newAgent.platform})`, { agent: newAgent });
          emitAgentCheckin({
            paw,
            host: newAgent.host,
            platform: newAgent.platform
          });
          emitAgentDeployed({
            paw,
            host: newAgent.host,
            platform: newAgent.platform,
            executors: newAgent.executors,
            engagementId
          });
        } else if (lastSeen !== existingAgent.lastProcessedHeartbeat) {
          existingAgent.lastSeen = lastSeen;
          existingAgent.lastProcessedHeartbeat = lastSeen;
          state.agentHeartbeatMisses.set(paw, 0);
          emitAgentCheckin({
            paw,
            host: existingAgent.host,
            platform: existingAgent.platform
          });
        } else {
          const misses = (state.agentHeartbeatMisses.get(paw) || 0) + 1;
          state.agentHeartbeatMisses.set(paw, misses);
          if (misses === 5) {
            addPollerEvent(state, "c2:agent_lost", `Agent ${paw} on ${existingAgent.host} \u2014 no heartbeat for ${misses * (state.pollIntervalMs / 1e3)}s`);
            eventHub.broadcastEngagement(engagementId, {
              type: "agent:lost",
              timestamp: Date.now(),
              engagementId,
              data: { paw, host: existingAgent.host, platform: existingAgent.platform, missedPolls: misses }
            });
          }
        }
      }
    }
    const chain = op.chain || [];
    for (const link of chain) {
      const linkId = String(link.id || link.unique || `${link.paw}-${link.ability?.ability_id}-${link.finish}`);
      if (state.processedLinkIds.has(linkId)) continue;
      if (link.status === -3 || link.status === -1) continue;
      state.processedLinkIds.add(linkId);
      const abilityName = link.ability?.name || link.ability_id || "Unknown";
      const abilityId = link.ability?.ability_id || link.ability_id || "";
      const paw = link.paw || "";
      const status = link.status;
      const output = link.output ? decodeBase64(link.output) : void 0;
      const statusLabel = status === 0 ? "success" : status === 1 ? "fail" : "discarded";
      addPollerEvent(
        state,
        "c2:ability_executed",
        `[${statusLabel}] ${abilityName} on agent ${paw}${output ? ` \u2014 ${output.substring(0, 200)}` : ""}`,
        { linkId, abilityId, abilityName, paw, status, outputPreview: output?.substring(0, 500) }
      );
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
          output: output?.substring(0, 1e3),
          collect: link.collect,
          finish: link.finish
        }
      });
    }
    if (newSnapshot.state === "finished" && (!prevSnapshot || prevSnapshot.state !== "finished")) {
      addPollerEvent(state, "c2:operation_complete", `Operation ${newSnapshot.name} finished. ${newSnapshot.successCount}/${newSnapshot.linkCount} abilities succeeded.`);
      emitSystemNotification({
        title: "C2 Operation Complete",
        message: `Operation "${newSnapshot.name}" finished with ${newSnapshot.successCount} successful and ${newSnapshot.failCount} failed ability executions across ${newSnapshot.agentCount} agents.`,
        severity: "info"
      });
      stopPolling(engagementId);
    }
  } catch (err) {
    state.consecutiveErrors++;
    addPollerEvent(state, "error", `Poll error: ${err.message}`);
  }
}
function addPollerEvent(state, type, summary, data) {
  state.events.push({ timestamp: Date.now(), type, summary, data });
  if (state.events.length > 500) {
    state.events = state.events.slice(-500);
  }
  console.log(`[C2Poller] [eng#${state.engagementId}] ${type}: ${summary}`);
}
function startPolling(engagementId, operationId, intervalMs = 1e4) {
  stopPolling(engagementId);
  const state = {
    engagementId,
    operationId,
    isPolling: true,
    pollIntervalMs: intervalMs,
    lastPollAt: 0,
    pollCount: 0,
    agents: /* @__PURE__ */ new Map(),
    processedLinkIds: /* @__PURE__ */ new Set(),
    operationSnapshot: null,
    events: [],
    consecutiveErrors: 0,
    agentHeartbeatMisses: /* @__PURE__ */ new Map()
  };
  addPollerEvent(state, "started", `Polling Caldera operation ${operationId} every ${intervalMs / 1e3}s`);
  const intervalHandle = setInterval(() => {
    pollCalderaOperation(engagementId).catch((err) => {
      console.error(`[C2Poller] Unhandled error for eng#${engagementId}:`, err.message);
    });
  }, intervalMs);
  pollers.set(engagementId, { state, intervalHandle });
  pollCalderaOperation(engagementId).catch(() => {
  });
  return state;
}
function stopPolling(engagementId) {
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
function getPollerState(engagementId) {
  const poller = pollers.get(engagementId);
  return poller?.state || null;
}
function getPollerSnapshot(engagementId) {
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
    consecutiveErrors: state.consecutiveErrors
  };
}
function listActivePollers() {
  return [...pollers.entries()].map(([engId, p]) => ({
    engagementId: engId,
    operationId: p.state.operationId,
    isPolling: p.state.isPolling,
    agentCount: p.state.agents.size,
    linkCount: p.state.processedLinkIds.size,
    pollCount: p.state.pollCount
  }));
}
var pollers, getCalderaUrl, getCalderaKey;
var init_caldera_c2_callback_poller = __esm({
  "server/lib/caldera-c2-callback-poller.ts"() {
    init_env();
    init_ws_event_hub();
    pollers = /* @__PURE__ */ new Map();
    getCalderaUrl = () => ENV.calderaBaseUrl || "";
    getCalderaKey = () => ENV.calderaApiKey || "";
  }
});
init_caldera_c2_callback_poller();
export {
  getPollerSnapshot,
  getPollerState,
  listActivePollers,
  startPolling,
  stopPolling
};
