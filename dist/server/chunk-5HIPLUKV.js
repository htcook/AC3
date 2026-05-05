import {
  emitSystemNotification,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/caldera-operation-launcher.ts
async function calderaFetch(endpoint, method = "GET", body, retries = 2) {
  const baseUrl = getCalderaUrl();
  const apiKey = getCalderaKey();
  if (!baseUrl || !apiKey) {
    return { ok: false, status: 0, data: null };
  }
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(`${baseUrl}${endpoint}`, {
        method,
        headers: {
          KEY: apiKey,
          "Content-Type": "application/json"
        },
        body: body ? JSON.stringify(body) : void 0,
        signal: AbortSignal.timeout(3e4)
      });
      const data = response.ok ? await response.json().catch(() => null) : null;
      return { ok: response.ok, status: response.status, data };
    } catch (err) {
      if (attempt === retries) {
        return { ok: false, status: 0, data: null };
      }
      await new Promise((r) => setTimeout(r, 2e3));
    }
  }
  return { ok: false, status: 0, data: null };
}
async function launchOperation(config, launchedBy = "system", adversaryName = "") {
  if (!getCalderaUrl() || !getCalderaKey()) {
    return {
      success: false,
      error: "Caldera connection not configured. Set CALDERA_BASE_URL and CALDERA_API_KEY."
    };
  }
  const payload = {
    name: config.name,
    adversary: { adversary_id: config.adversaryId },
    group: config.group || "",
    planner: { id: config.planner || "batch" },
    source: { id: config.source || "basic" },
    jitter: config.jitter || "2/8",
    obfuscator: config.obfuscator || "plain-text",
    visibility: config.visibility ?? 50,
    autonomous: config.autonomous !== false ? 1 : 0,
    auto_close: config.autoClose ? 1 : 0
  };
  const result = await calderaFetch("/api/v2/operations", "POST", payload);
  if (!result.ok) {
    const v1Payload = {
      index: "operations",
      name: config.name,
      adversary_id: config.adversaryId,
      group: config.group || "",
      planner: config.planner || "batch",
      source: config.source || "basic",
      jitter: config.jitter || "2/8",
      obfuscator: config.obfuscator || "plain-text",
      visibility: config.visibility ?? 50,
      autonomous: config.autonomous !== false ? 1 : 0,
      phases_enabled: config.phasesEnabled !== false ? 1 : 0,
      auto_close: config.autoClose ? 1 : 0
    };
    const v1Result = await calderaFetch("/api/rest", "PUT", v1Payload);
    if (!v1Result.ok) {
      return {
        success: false,
        error: `Failed to create operation via both v2 (${result.status}) and v1 (${v1Result.status}) APIs`,
        calderaResponse: result.data || v1Result.data
      };
    }
    const opId2 = v1Result.data?.id || v1Result.data?.operation_id || v1Result.data?.name;
    trackOperation(opId2, config, launchedBy, adversaryName);
    return {
      success: true,
      operationId: opId2,
      operationName: config.name,
      calderaResponse: v1Result.data
    };
  }
  const opId = result.data?.id || result.data?.operation_id || result.data?.name;
  trackOperation(opId, config, launchedBy, adversaryName);
  emitSystemNotification({
    title: "Operation Launched",
    message: `Caldera operation "${config.name}" launched with adversary ${adversaryName || config.adversaryId}`,
    severity: "info"
  });
  return {
    success: true,
    operationId: opId,
    operationName: config.name,
    calderaResponse: result.data
  };
}
function trackOperation(operationId, config, launchedBy, adversaryName) {
  trackedOperations.unshift({
    operationId,
    adversaryId: config.adversaryId,
    adversaryName: adversaryName || config.name,
    name: config.name,
    launchedAt: Date.now(),
    launchedBy,
    state: "running",
    lastPolledAt: Date.now(),
    agentCount: 0,
    linkCount: 0,
    successCount: 0,
    failCount: 0
  });
  if (trackedOperations.length > MAX_TRACKED) {
    trackedOperations.splice(MAX_TRACKED);
  }
}
async function getOperationStatus(operationId) {
  const result = await calderaFetch(`/api/v2/operations/${operationId}`);
  if (result.ok && result.data) {
    const op = normalizeOperation(result.data);
    const tracked = trackedOperations.find((t) => String(t.operationId) === String(operationId));
    if (tracked) {
      tracked.state = op.state;
      tracked.lastPolledAt = Date.now();
      tracked.agentCount = op.hostGroup?.length || 0;
      tracked.linkCount = op.chain?.length || 0;
      tracked.successCount = op.chain?.filter((l) => l.status === 0).length || 0;
      tracked.failCount = op.chain?.filter((l) => l.status === 1 || l.status === -2).length || 0;
    }
    return { success: true, operation: op };
  }
  return {
    success: false,
    error: `Failed to fetch operation ${operationId} (status: ${result.status})`
  };
}
async function listOperations() {
  const result = await calderaFetch("/api/v2/operations");
  if (!result.ok) {
    return {
      success: false,
      operations: trackedOperations.map((t) => ({
        id: t.operationId,
        name: t.name,
        adversaryId: t.adversaryId,
        adversaryName: t.adversaryName,
        state: t.state,
        startedAt: new Date(t.launchedAt).toISOString(),
        agentCount: t.agentCount,
        linkCount: t.linkCount,
        successCount: t.successCount,
        failCount: t.failCount,
        inProgressCount: 0
      })),
      error: `Failed to fetch operations from Caldera (status: ${result.status})`
    };
  }
  const ops = (Array.isArray(result.data) ? result.data : []).map(
    (op) => ({
      id: op.id,
      name: op.name || "Unnamed",
      adversaryId: op.adversary?.adversary_id || op.adversary_id || "",
      adversaryName: op.adversary?.name || "",
      state: op.state || "finished",
      startedAt: op.start || (/* @__PURE__ */ new Date()).toISOString(),
      agentCount: op.host_group?.length || 0,
      linkCount: op.chain?.length || 0,
      successCount: op.chain?.filter((l) => l.status === 0).length || 0,
      failCount: op.chain?.filter((l) => l.status === 1 || l.status === -2).length || 0,
      inProgressCount: op.chain?.filter((l) => l.status === -3 || l.status === -1).length || 0
    })
  );
  return { success: true, operations: ops };
}
async function controlOperation(operationId, newState) {
  const result = await calderaFetch(`/api/v2/operations/${operationId}`, "PATCH", {
    state: newState
  });
  if (result.ok) {
    const tracked = trackedOperations.find((t) => String(t.operationId) === String(operationId));
    if (tracked) {
      tracked.state = newState;
      tracked.lastPolledAt = Date.now();
    }
    emitSystemNotification({
      title: "Operation State Changed",
      message: `Operation ${operationId} state changed to ${newState}`,
      severity: newState === "finished" ? "warning" : "info"
    });
    return { success: true };
  }
  const v1Result = await calderaFetch("/api/rest", "POST", {
    index: "operation",
    op_id: operationId,
    state: newState
  });
  if (v1Result.ok) {
    const tracked = trackedOperations.find((t) => String(t.operationId) === String(operationId));
    if (tracked) {
      tracked.state = newState;
    }
    return { success: true };
  }
  return {
    success: false,
    error: `Failed to change operation state (v2: ${result.status}, v1: ${v1Result.status})`
  };
}
async function deleteOperation(operationId) {
  const result = await calderaFetch(`/api/v2/operations/${operationId}`, "DELETE");
  if (result.ok) {
    const idx = trackedOperations.findIndex(
      (t) => String(t.operationId) === String(operationId)
    );
    if (idx >= 0) trackedOperations.splice(idx, 1);
    return { success: true };
  }
  return {
    success: false,
    error: `Failed to delete operation ${operationId} (status: ${result.status})`
  };
}
async function getOperationReport(operationId) {
  const result = await calderaFetch(`/api/v2/operations/${operationId}/report`);
  if (result.ok && result.data) {
    return { success: true, report: result.data };
  }
  const opResult = await getOperationStatus(operationId);
  if (opResult.success && opResult.operation) {
    return {
      success: true,
      report: {
        name: opResult.operation.name,
        adversaryId: opResult.operation.adversaryId,
        state: opResult.operation.state,
        steps: opResult.operation.chain || [],
        agents: opResult.operation.hostGroup || []
      }
    };
  }
  return {
    success: false,
    error: `Failed to get report for operation ${operationId}`
  };
}
async function getAvailableAgents() {
  const result = await calderaFetch("/api/v2/agents");
  if (!result.ok) {
    return { success: false, agents: [], error: `Failed to fetch agents (${result.status})` };
  }
  const agents = (Array.isArray(result.data) ? result.data : []).map((a) => ({
    paw: a.paw || "",
    host: a.host || "",
    platform: a.platform || "",
    group: a.group || "",
    trusted: a.trusted ?? true,
    lastSeen: a.last_seen || "",
    executors: a.executors?.map((e) => e.name || e) || []
  }));
  return { success: true, agents };
}
async function getAvailablePlanners() {
  const result = await calderaFetch("/api/v2/planners");
  if (!result.ok) {
    return {
      success: true,
      planners: [
        { id: "batch", name: "Batch", description: "Run all abilities in sequence by phase" },
        {
          id: "buckets",
          name: "Buckets",
          description: "Group abilities by tactic and run in order"
        },
        {
          id: "atomic",
          name: "Atomic",
          description: "Run each ability independently without dependencies"
        }
      ]
    };
  }
  const planners = (Array.isArray(result.data) ? result.data : []).map((p) => ({
    id: p.id || p.name || "",
    name: p.name || p.id || "",
    description: p.description || ""
  }));
  return { success: true, planners };
}
function getTrackedOperations() {
  return [...trackedOperations];
}
function getOperationStats() {
  const running = trackedOperations.filter((o) => o.state === "running").length;
  const completed = trackedOperations.filter((o) => o.state === "finished").length;
  const failed = trackedOperations.filter(
    (o) => o.state === "cleanup" || o.failCount > o.successCount
  ).length;
  const uniqueAdversaries = new Set(trackedOperations.map((o) => o.adversaryId)).size;
  return {
    totalLaunched: trackedOperations.length,
    running,
    completed,
    failed,
    uniqueAdversaries
  };
}
function normalizeOperation(raw) {
  return {
    id: raw.id,
    name: raw.name || "Unnamed",
    adversaryId: raw.adversary?.adversary_id || raw.adversary_id || "",
    state: raw.state || "finished",
    startedAt: raw.start || (/* @__PURE__ */ new Date()).toISOString(),
    group: raw.group || "",
    planner: raw.planner?.id || raw.planner || "batch",
    source: raw.source?.id || raw.source || "basic",
    jitter: raw.jitter || "2/8",
    obfuscator: raw.obfuscator || "plain-text",
    autonomous: raw.autonomous === 1 || raw.autonomous === true,
    visibility: raw.visibility ?? 50,
    hostGroup: raw.host_group?.map((a) => ({
      paw: a.paw || "",
      host: a.host || "",
      platform: a.platform || ""
    })),
    chain: raw.chain?.map((link) => ({
      id: link.id || "",
      abilityId: link.ability?.ability_id || link.ability_id || "",
      abilityName: link.ability?.name || "",
      status: link.status ?? -3,
      paw: link.paw || "",
      output: link.output || "",
      collect: link.collect || "",
      finish: link.finish || ""
    }))
  };
}
var trackedOperations, MAX_TRACKED, getCalderaUrl, getCalderaKey;
var init_caldera_operation_launcher = __esm({
  "server/lib/caldera-operation-launcher.ts"() {
    init_env();
    init_ws_event_hub();
    trackedOperations = [];
    MAX_TRACKED = 100;
    getCalderaUrl = () => ENV.calderaBaseUrl || "";
    getCalderaKey = () => ENV.calderaApiKey || "";
  }
});

export {
  launchOperation,
  getOperationStatus,
  listOperations,
  controlOperation,
  deleteOperation,
  getOperationReport,
  getAvailableAgents,
  getAvailablePlanners,
  getTrackedOperations,
  getOperationStats,
  init_caldera_operation_launcher
};
