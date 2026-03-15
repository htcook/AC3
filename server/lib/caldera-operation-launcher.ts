/**
 * Caldera Operation Launcher
 *
 * Creates, monitors, and manages Caldera operations from pushed adversary profiles.
 * Supports one-click launch, real-time status polling, operation control (pause/resume/stop),
 * and operation history with results.
 *
 * Uses both v1 REST API (PUT /api/rest for creation) and v2 API (GET /api/v2/operations for listing).
 */

import { ENV } from "../_core/env";
import { emitSystemNotification } from "./ws-event-hub";

// ─── Types ───────────────────────────────────────────────────────────────

export type OperationState = "running" | "paused" | "run_one_link" | "finished" | "cleanup";

export type PlannerType = "batch" | "buckets" | "atomic";

export interface OperationConfig {
  name: string;
  adversaryId: string;
  /** Agent group to target (empty string = all agents) */
  group?: string;
  /** Planner strategy */
  planner?: PlannerType;
  /** Fact source */
  source?: string;
  /** Jitter range e.g. "2/8" */
  jitter?: string;
  /** Obfuscator type */
  obfuscator?: "plain-text" | "base64" | "caesar";
  /** Visibility threshold (0-100) */
  visibility?: number;
  /** Run autonomously without manual approval */
  autonomous?: boolean;
  /** Enable phase-based execution */
  phasesEnabled?: boolean;
  /** Auto-close operation when complete */
  autoClose?: boolean;
}

export interface CalderaOperation {
  id: string | number;
  name: string;
  adversaryId: string;
  state: OperationState;
  startedAt: string;
  group: string;
  planner: string;
  source: string;
  jitter: string;
  obfuscator: string;
  autonomous: boolean;
  visibility: number;
  hostGroup?: Array<{ paw: string; host: string; platform: string }>;
  chain?: Array<{
    id: string;
    abilityId: string;
    abilityName: string;
    status: number;
    paw: string;
    output?: string;
    collect?: string;
    finish?: string;
  }>;
}

export interface OperationSummary {
  id: string | number;
  name: string;
  adversaryId: string;
  adversaryName?: string;
  state: OperationState;
  startedAt: string;
  agentCount: number;
  linkCount: number;
  successCount: number;
  failCount: number;
  inProgressCount: number;
}

export interface LaunchResult {
  success: boolean;
  operationId?: string | number;
  operationName?: string;
  error?: string;
  calderaResponse?: any;
}

// ─── In-Memory Operation Tracking ────────────────────────────────────────

interface TrackedOperation {
  operationId: string | number;
  adversaryId: string;
  adversaryName: string;
  name: string;
  launchedAt: number;
  launchedBy: string;
  state: OperationState;
  lastPolledAt: number;
  agentCount: number;
  linkCount: number;
  successCount: number;
  failCount: number;
}

const trackedOperations: TrackedOperation[] = [];
const MAX_TRACKED = 100;

// ─── Caldera API Client ──────────────────────────────────────────────────

const getCalderaUrl = () => ENV.calderaBaseUrl || "";
const getCalderaKey = () => ENV.calderaApiKey || "";

async function calderaFetch(
  endpoint: string,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" = "GET",
  body?: any,
  retries = 2,
): Promise<{ ok: boolean; status: number; data: any }> {
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
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(30000),
      });
      const data = response.ok ? await response.json().catch(() => null) : null;
      return { ok: response.ok, status: response.status, data };
    } catch (err: any) {
      if (attempt === retries) {
        return { ok: false, status: 0, data: null };
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  return { ok: false, status: 0, data: null };
}

// ─── Launch Operation ────────────────────────────────────────────────────

/**
 * Launch a new Caldera operation using a pushed adversary profile.
 * Uses the v2 API (POST /api/v2/operations) for creation.
 */
export async function launchOperation(
  config: OperationConfig,
  launchedBy: string = "system",
  adversaryName: string = "",
): Promise<LaunchResult> {
  if (!getCalderaUrl() || !getCalderaKey()) {
    return {
      success: false,
      error: "Caldera connection not configured. Set CALDERA_BASE_URL and CALDERA_API_KEY.",
    };
  }

  // Build the operation payload for v2 API
  const payload: any = {
    name: config.name,
    adversary: { adversary_id: config.adversaryId },
    group: config.group || "",
    planner: { id: config.planner || "batch" },
    source: { id: config.source || "basic" },
    jitter: config.jitter || "2/8",
    obfuscator: config.obfuscator || "plain-text",
    visibility: config.visibility ?? 50,
    autonomous: config.autonomous !== false ? 1 : 0,
    auto_close: config.autoClose ? 1 : 0,
  };

  const result = await calderaFetch("/api/v2/operations", "POST", payload);

  if (!result.ok) {
    // Fallback to v1 REST API
    const v1Payload: any = {
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
      auto_close: config.autoClose ? 1 : 0,
    };

    const v1Result = await calderaFetch("/api/rest", "PUT", v1Payload);

    if (!v1Result.ok) {
      return {
        success: false,
        error: `Failed to create operation via both v2 (${result.status}) and v1 (${v1Result.status}) APIs`,
        calderaResponse: result.data || v1Result.data,
      };
    }

    const opId = v1Result.data?.id || v1Result.data?.operation_id || v1Result.data?.name;
    trackOperation(opId, config, launchedBy, adversaryName);

    return {
      success: true,
      operationId: opId,
      operationName: config.name,
      calderaResponse: v1Result.data,
    };
  }

  const opId = result.data?.id || result.data?.operation_id || result.data?.name;
  trackOperation(opId, config, launchedBy, adversaryName);

  // Emit WS notification
  emitSystemNotification({
    title: "Operation Launched",
    message: `Caldera operation "${config.name}" launched with adversary ${adversaryName || config.adversaryId}`,
    severity: "info",
  });

  return {
    success: true,
    operationId: opId,
    operationName: config.name,
    calderaResponse: result.data,
  };
}

function trackOperation(
  operationId: string | number,
  config: OperationConfig,
  launchedBy: string,
  adversaryName: string,
): void {
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
    failCount: 0,
  });

  if (trackedOperations.length > MAX_TRACKED) {
    trackedOperations.splice(MAX_TRACKED);
  }
}

// ─── Get Operation Status ────────────────────────────────────────────────

/**
 * Get the current status of a specific operation from Caldera.
 */
export async function getOperationStatus(
  operationId: string | number,
): Promise<{ success: boolean; operation?: CalderaOperation; error?: string }> {
  // Try v2 API first
  const result = await calderaFetch(`/api/v2/operations/${operationId}`);

  if (result.ok && result.data) {
    const op = normalizeOperation(result.data);

    // Update tracked operation
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
    error: `Failed to fetch operation ${operationId} (status: ${result.status})`,
  };
}

/**
 * List all operations from Caldera.
 */
export async function listOperations(): Promise<{
  success: boolean;
  operations: OperationSummary[];
  error?: string;
}> {
  const result = await calderaFetch("/api/v2/operations");

  if (!result.ok) {
    // Return tracked operations as fallback
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
        inProgressCount: 0,
      })),
      error: `Failed to fetch operations from Caldera (status: ${result.status})`,
    };
  }

  const ops: OperationSummary[] = (Array.isArray(result.data) ? result.data : []).map(
    (op: any) => ({
      id: op.id,
      name: op.name || "Unnamed",
      adversaryId: op.adversary?.adversary_id || op.adversary_id || "",
      adversaryName: op.adversary?.name || "",
      state: (op.state || "finished") as OperationState,
      startedAt: op.start || new Date().toISOString(),
      agentCount: op.host_group?.length || 0,
      linkCount: op.chain?.length || 0,
      successCount: op.chain?.filter((l: any) => l.status === 0).length || 0,
      failCount: op.chain?.filter((l: any) => l.status === 1 || l.status === -2).length || 0,
      inProgressCount:
        op.chain?.filter((l: any) => l.status === -3 || l.status === -1).length || 0,
    }),
  );

  return { success: true, operations: ops };
}

// ─── Control Operation ───────────────────────────────────────────────────

/**
 * Change the state of a running operation.
 */
export async function controlOperation(
  operationId: string | number,
  newState: OperationState,
): Promise<{ success: boolean; error?: string }> {
  // Try v2 API first
  const result = await calderaFetch(`/api/v2/operations/${operationId}`, "PATCH", {
    state: newState,
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
      severity: newState === "finished" ? "warning" : "info",
    });

    return { success: true };
  }

  // Fallback to v1 API
  const v1Result = await calderaFetch("/api/rest", "POST", {
    index: "operation",
    op_id: operationId,
    state: newState,
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
    error: `Failed to change operation state (v2: ${result.status}, v1: ${v1Result.status})`,
  };
}

/**
 * Delete an operation from Caldera.
 */
export async function deleteOperation(
  operationId: string | number,
): Promise<{ success: boolean; error?: string }> {
  const result = await calderaFetch(`/api/v2/operations/${operationId}`, "DELETE");

  if (result.ok) {
    const idx = trackedOperations.findIndex(
      (t) => String(t.operationId) === String(operationId),
    );
    if (idx >= 0) trackedOperations.splice(idx, 1);
    return { success: true };
  }

  return {
    success: false,
    error: `Failed to delete operation ${operationId} (status: ${result.status})`,
  };
}

// ─── Operation Report ────────────────────────────────────────────────────

/**
 * Get the operation report/results from Caldera.
 */
export async function getOperationReport(
  operationId: string | number,
): Promise<{ success: boolean; report?: any; error?: string }> {
  // v2 API report endpoint
  const result = await calderaFetch(`/api/v2/operations/${operationId}/report`);

  if (result.ok && result.data) {
    return { success: true, report: result.data };
  }

  // Fallback: get operation details which include chain
  const opResult = await getOperationStatus(operationId);
  if (opResult.success && opResult.operation) {
    return {
      success: true,
      report: {
        name: opResult.operation.name,
        adversaryId: opResult.operation.adversaryId,
        state: opResult.operation.state,
        steps: opResult.operation.chain || [],
        agents: opResult.operation.hostGroup || [],
      },
    };
  }

  return {
    success: false,
    error: `Failed to get report for operation ${operationId}`,
  };
}

// ─── Get Available Agents ────────────────────────────────────────────────

/**
 * Get all available agents from Caldera for targeting.
 */
export async function getAvailableAgents(): Promise<{
  success: boolean;
  agents: Array<{
    paw: string;
    host: string;
    platform: string;
    group: string;
    trusted: boolean;
    lastSeen: string;
    executors: string[];
  }>;
  error?: string;
}> {
  const result = await calderaFetch("/api/v2/agents");

  if (!result.ok) {
    return { success: false, agents: [], error: `Failed to fetch agents (${result.status})` };
  }

  const agents = (Array.isArray(result.data) ? result.data : []).map((a: any) => ({
    paw: a.paw || "",
    host: a.host || "",
    platform: a.platform || "",
    group: a.group || "",
    trusted: a.trusted ?? true,
    lastSeen: a.last_seen || "",
    executors: a.executors?.map((e: any) => e.name || e) || [],
  }));

  return { success: true, agents };
}

// ─── Get Available Planners ──────────────────────────────────────────────

/**
 * Get available planners from Caldera.
 */
export async function getAvailablePlanners(): Promise<{
  success: boolean;
  planners: Array<{ id: string; name: string; description: string }>;
  error?: string;
}> {
  const result = await calderaFetch("/api/v2/planners");

  if (!result.ok) {
    // Return built-in defaults
    return {
      success: true,
      planners: [
        { id: "batch", name: "Batch", description: "Run all abilities in sequence by phase" },
        {
          id: "buckets",
          name: "Buckets",
          description: "Group abilities by tactic and run in order",
        },
        {
          id: "atomic",
          name: "Atomic",
          description: "Run each ability independently without dependencies",
        },
      ],
    };
  }

  const planners = (Array.isArray(result.data) ? result.data : []).map((p: any) => ({
    id: p.id || p.name || "",
    name: p.name || p.id || "",
    description: p.description || "",
  }));

  return { success: true, planners };
}

// ─── Tracked Operations ──────────────────────────────────────────────────

/**
 * Get locally tracked operations launched from this platform.
 */
export function getTrackedOperations(): TrackedOperation[] {
  return [...trackedOperations];
}

/**
 * Get operation launch statistics.
 */
export function getOperationStats(): {
  totalLaunched: number;
  running: number;
  completed: number;
  failed: number;
  uniqueAdversaries: number;
} {
  const running = trackedOperations.filter((o) => o.state === "running").length;
  const completed = trackedOperations.filter((o) => o.state === "finished").length;
  const failed = trackedOperations.filter(
    (o) => o.state === "cleanup" || o.failCount > o.successCount,
  ).length;
  const uniqueAdversaries = new Set(trackedOperations.map((o) => o.adversaryId)).size;

  return {
    totalLaunched: trackedOperations.length,
    running,
    completed,
    failed,
    uniqueAdversaries,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function normalizeOperation(raw: any): CalderaOperation {
  return {
    id: raw.id,
    name: raw.name || "Unnamed",
    adversaryId: raw.adversary?.adversary_id || raw.adversary_id || "",
    state: (raw.state || "finished") as OperationState,
    startedAt: raw.start || new Date().toISOString(),
    group: raw.group || "",
    planner: raw.planner?.id || raw.planner || "batch",
    source: raw.source?.id || raw.source || "basic",
    jitter: raw.jitter || "2/8",
    obfuscator: raw.obfuscator || "plain-text",
    autonomous: raw.autonomous === 1 || raw.autonomous === true,
    visibility: raw.visibility ?? 50,
    hostGroup: raw.host_group?.map((a: any) => ({
      paw: a.paw || "",
      host: a.host || "",
      platform: a.platform || "",
    })),
    chain: raw.chain?.map((link: any) => ({
      id: link.id || "",
      abilityId: link.ability?.ability_id || link.ability_id || "",
      abilityName: link.ability?.name || "",
      status: link.status ?? -3,
      paw: link.paw || "",
      output: link.output || "",
      collect: link.collect || "",
      finish: link.finish || "",
    })),
  };
}
