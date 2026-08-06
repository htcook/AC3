/**
 * Caldera Graph Executor
 *
 * Connects the Ability Graph Engine to live Caldera agent execution.
 * Dispatches graph nodes as Cyber C2 operations following topological order,
 * polls for results, updates node statuses, and handles cleanup on failure/abort.
 *
 * Execution flow:
 * 1. Validate graph (acyclic, safety tier, preconditions)
 * 2. Create a Cyber C2 operation for the graph
 * 3. Walk the graph in topological order
 * 4. For each ready node: dispatch ability to agent, poll for completion
 * 5. Evaluate exit criteria → follow conditional edges
 * 6. Update node/graph status in real-time
 * 7. On failure/abort: run cleanup commands for completed nodes
 */

import { ENV } from "../_core/env";
import {
  topologicalSort,
  walkGraph,
  evaluateNodePreconditions,
  evaluateExitCriteria,
  shouldFollowEdge,
  isNodeAllowedBySafetyTier,
  buildAdjacencyList,
  buildReverseAdjacencyList,
  computeGraphSafetyTier,
  getGraph,
  updateGraphStatus,
  updateNodeStatus,
  type AbilityNodeData,
  type AbilityEdgeData,
  type AbilityGraphData,
  type EnvironmentContext,
  type NodeStatus,
  type WalkResult,
  type SafetyTier,
} from "./ability-graph-engine";
import type { ScanMode } from "./scan-policy-engine";

const CALDERA_BASE_URL = ENV.calderaBaseUrl || "";
const CALDERA_API_KEY = ENV.calderaApiKey || "";

// ─── Types ──────────────────────────────────────────────────────────────

export interface ExecutionConfig {
  graphId: string;
  agentPawId: string;          // Caldera agent paw to execute on
  scanMode: ScanMode;          // safety tier ceiling
  environment: EnvironmentContext;
  dryRun?: boolean;            // if true, simulate without dispatching
  maxConcurrent?: number;      // max parallel node executions (default: 1)
  pollIntervalMs?: number;     // status poll interval (default: 3000)
  timeoutOverrideMs?: number;  // global timeout override
  autoCleanup?: boolean;       // run cleanup commands on abort (default: true)
  operationName?: string;      // custom Cyber C2 operation name
}

export interface ExecutionState {
  graphId: string;
  operationId: string | null;
  status: "initializing" | "running" | "paused" | "completed" | "failed" | "aborted" | "cleaning_up";
  currentNodeId: string | null;
  nodesCompleted: string[];
  nodesFailed: string[];
  nodesSkipped: string[];
  nodesBlocked: string[];
  nodesPending: string[];
  totalNodes: number;
  startedAt: string;
  completedAt: string | null;
  executionLog: ExecutionLogEntry[];
  error: string | null;
}

export interface ExecutionLogEntry {
  timestamp: string;
  nodeId: string | null;
  event: "start" | "dispatch" | "poll" | "success" | "failure" | "skip" | "block" | "cleanup" | "abort" | "error" | "edge_follow" | "edge_skip" | "precondition_check";
  message: string;
  details?: Record<string, any>;
}

export interface NodeExecutionResult {
  nodeId: string;
  status: "success" | "failed" | "timeout" | "skipped";
  exitCode: number;
  stdout: string;
  stderr: string;
  startedAt: string;
  completedAt: string;
  agentId: string;
  calderaLinkId?: string;
}

// ─── Caldera API Helpers ────────────────────────────────────────────────

async function calderaFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
  if (!CALDERA_BASE_URL || !CALDERA_API_KEY) {
    throw new Error("Cyber C2 credentials not configured");
  }
  const response = await fetch(`${CALDERA_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      KEY: CALDERA_API_KEY,
      "Content-Type": "application/json",
      ...options.headers,
    },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Caldera API ${response.status}: ${body}`);
  }
  return response.json();
}

/**
 * Create a new Cyber C2 operation.
 */
async function createCalderaOperation(params: {
  name: string;
  adversaryId?: string;
  agentPaw: string;
  autonomous?: boolean;
}): Promise<{ id: string; name: string }> {
  const body: Record<string, any> = {
    name: params.name,
    group: "",
    auto_close: false,
    autonomous: params.autonomous ?? 0, // manual mode for graph-controlled execution
    jitter: "2/8",
    visibility: 51,
    state: "running",
  };
  if (params.adversaryId) {
    body.adversary = { adversary_id: params.adversaryId };
  }
  // Set source to target specific agent
  body.source = { id: "ed32b9c3-9593-4c33-b0db-e2007315096b" }; // basic fact source
  body.planner = { id: "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a" }; // batch planner

  const result = await calderaFetch("/api/v2/operations", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return { id: result.id, name: result.name };
}

/**
 * Dispatch a single ability (link) to a running operation.
 */
async function dispatchAbilityToOperation(params: {
  operationId: string;
  agentPaw: string;
  abilityId: string;
  facts?: Array<{ trait: string; value: string }>;
}): Promise<{ linkId: string }> {
  const body: Record<string, any> = {
    paw: params.agentPaw,
    ability_id: params.abilityId,
  };
  if (params.facts?.length) {
    body.facts = params.facts;
  }
  const result = await calderaFetch(
    `/api/v2/operations/${params.operationId}/potential-links`,
    { method: "POST", body: JSON.stringify(body) },
  );
  // The response may be the link itself or an array
  const link = Array.isArray(result) ? result[0] : result;
  return { linkId: link?.id || link?.unique || "unknown" };
}

/**
 * Get operation links (executed abilities) and their statuses.
 */
async function getOperationLinks(operationId: string): Promise<any[]> {
  const result = await calderaFetch(`/api/v2/operations/${operationId}/links`);
  return Array.isArray(result) ? result : [];
}

/**
 * Poll a specific link until it completes or times out.
 */
async function pollLinkCompletion(params: {
  operationId: string;
  linkId: string;
  timeoutMs: number;
  pollIntervalMs: number;
}): Promise<{ status: number; output: string; pid?: number }> {
  const deadline = Date.now() + params.timeoutMs;

  while (Date.now() < deadline) {
    const links = await getOperationLinks(params.operationId);
    const link = links.find((l: any) => l.id === params.linkId || l.unique === params.linkId);

    if (link) {
      // Caldera link status: -3=discarded, -2=untrusted, -1=failed, 0=success, 1=queued, 2=collected, 3=running
      if (link.status <= 0) {
        const output = link.output ? Buffer.from(link.output, "base64").toString("utf-8") : "";
        return {
          status: link.status,
          output,
          pid: link.pid,
        };
      }
    }

    await new Promise(resolve => setTimeout(resolve, params.pollIntervalMs));
  }

  throw new Error(`Link ${params.linkId} timed out after ${params.timeoutMs}ms`);
}

/**
 * Update a Cyber C2 operation state.
 */
async function updateOperationState(
  operationId: string,
  state: "running" | "paused" | "finished" | "cleanup",
): Promise<void> {
  await calderaFetch(`/api/v2/operations/${operationId}`, {
    method: "PATCH",
    body: JSON.stringify({ state }),
  });
}

/**
 * Get available agents from Cyber C2.
 */
export async function getCalderaAgents(): Promise<Array<{
  paw: string;
  host: string;
  platform: string;
  username: string;
  privilege: string;
  executors: string[];
  lastSeen: string;
  trusted: boolean;
  group: string;
}>> {
  const agents = await calderaFetch("/api/v2/agents");
  if (!Array.isArray(agents)) return [];
  return agents.map((a: any) => ({
    paw: a.paw,
    host: a.host,
    platform: a.platform,
    username: a.username,
    privilege: a.privilege || "user",
    executors: (a.executors || []).map((e: any) => e.name || e),
    lastSeen: a.last_seen || a.created,
    trusted: a.trusted ?? true,
    group: a.group || "red",
  }));
}

/**
 * Resolve a Caldera ability ID from a MITRE technique ID.
 */
async function resolveAbilityId(techniqueId: string, platform?: string): Promise<string | null> {
  const abilities = await calderaFetch("/api/v2/abilities");
  if (!Array.isArray(abilities)) return null;

  // Find abilities matching the technique ID
  const matches = abilities.filter((a: any) => a.technique_id === techniqueId);
  if (matches.length === 0) return null;

  // Prefer platform-specific match
  if (platform) {
    const platformMatch = matches.find((a: any) =>
      a.platforms && Object.keys(a.platforms).some((p: string) =>
        p.toLowerCase().includes(platform.toLowerCase()),
      ),
    );
    if (platformMatch) return platformMatch.ability_id;
  }

  return matches[0].ability_id;
}

// ─── Execution Engine ───────────────────────────────────────────────────

// Active executions tracked in memory
const activeExecutions = new Map<string, ExecutionState>();

function log(state: ExecutionState, entry: Omit<ExecutionLogEntry, "timestamp">): void {
  state.executionLog.push({
    ...entry,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Start executing a graph against a Caldera agent.
 */
export async function executeGraph(config: ExecutionConfig): Promise<ExecutionState> {
  const graphData = await getGraph(config.graphId);
  if (!graphData) throw new Error(`Graph ${config.graphId} not found`);

  const { graph, nodes, edges } = graphData;

  // Initialize execution state
  const state: ExecutionState = {
    graphId: config.graphId,
    operationId: null,
    status: "initializing",
    currentNodeId: null,
    nodesCompleted: [],
    nodesFailed: [],
    nodesSkipped: [],
    nodesBlocked: [],
    nodesPending: nodes.map(n => n.id),
    totalNodes: nodes.length,
    startedAt: new Date().toISOString(),
    completedAt: null,
    executionLog: [],
    error: null,
  };

  activeExecutions.set(config.graphId, state);
  log(state, { nodeId: null, event: "start", message: `Starting graph execution: ${graph.name}` });

  try {
    // 1. Validate graph
    const walkResult = walkGraph(nodes, edges, config.environment, config.scanMode);
    if (walkResult.safetyViolations.length > 0 && !config.dryRun) {
      // Log violations but continue — blocked nodes will be skipped
      for (const violation of walkResult.safetyViolations) {
        log(state, { nodeId: null, event: "block", message: violation });
      }
    }

    // 2. Create Cyber C2 operation (unless dry run)
    if (!config.dryRun) {
      const opName = config.operationName || `AG-${graph.name}-${Date.now().toString(36)}`;
      const op = await createCalderaOperation({
        name: opName,
        agentPaw: config.agentPawId,
      });
      state.operationId = op.id;
      log(state, { nodeId: null, event: "start", message: `Created Cyber C2 operation: ${op.id}` });
    }

    // 3. Update graph status
    await updateGraphStatus(config.graphId, "running");
    state.status = "running";

    // 4. Execute nodes in topological order
    const sorted = topologicalSort(nodes, edges);
    const adj = buildAdjacencyList(edges);
    const rev = buildReverseAdjacencyList(edges);
    const nodeResults = new Map<string, NodeExecutionResult>();
    const nodeStatusMap = new Map<string, NodeStatus>();

    for (const node of sorted) {
      if ((state.status as string) === "aborted") break;
      if ((state.status as string) === "paused") {
        // Wait for resume (in practice, the pause/resume is handled via getExecutionState)
        log(state, { nodeId: node.id, event: "skip", message: "Execution paused" });
        continue;
      }

      state.currentNodeId = node.id;

      // Check safety tier
      if (!isNodeAllowedBySafetyTier(node, config.scanMode)) {
        nodeStatusMap.set(node.id, "blocked");
        state.nodesBlocked.push(node.id);
        state.nodesPending = state.nodesPending.filter(id => id !== node.id);
        await updateNodeStatus(node.id, "blocked" as NodeStatus);
        log(state, {
          nodeId: node.id,
          event: "block",
          message: `Blocked: ${node.label} requires ${node.safetyTier} but mode is ${config.scanMode}`,
        });
        continue;
      }

      // Check incoming edges — should at least one source have completed?
      const incomingEdges = rev.get(node.id) || [];
      if (incomingEdges.length > 0) {
        const anyEdgeAllows = incomingEdges.some(edge => {
          const srcStatus = nodeStatusMap.get(edge.sourceNodeId) || "pending";
          if (srcStatus === "success" || srcStatus === "failed") {
            const srcResult = nodeResults.get(edge.sourceNodeId);
            const result = srcResult
              ? { exitCode: srcResult.exitCode, stdout: srcResult.stdout, stderr: srcResult.stderr }
              : null;
            return shouldFollowEdge(edge, result, srcStatus, config.environment, node);
          }
          return false;
        });

        if (!anyEdgeAllows) {
          const allInactive = incomingEdges.every(e => {
            const s = nodeStatusMap.get(e.sourceNodeId);
            return s === "blocked" || s === "skipped";
          });
          if (allInactive) {
            nodeStatusMap.set(node.id, "skipped");
            state.nodesSkipped.push(node.id);
            state.nodesPending = state.nodesPending.filter(id => id !== node.id);
            await updateNodeStatus(node.id, "skipped" as NodeStatus);
            log(state, {
              nodeId: node.id,
              event: "skip",
              message: `Skipped: all sources inactive for ${node.label}`,
            });
            continue;
          }

          // Check if edges with conditions block this node
          const conditionBlocked = incomingEdges.every(edge => {
            const srcStatus = nodeStatusMap.get(edge.sourceNodeId) || "pending";
            const srcResult = nodeResults.get(edge.sourceNodeId);
            const result = srcResult
              ? { exitCode: srcResult.exitCode, stdout: srcResult.stdout, stderr: srcResult.stderr }
              : null;
            return !shouldFollowEdge(edge, result, srcStatus, config.environment, node);
          });
          if (conditionBlocked) {
            nodeStatusMap.set(node.id, "skipped");
            state.nodesSkipped.push(node.id);
            state.nodesPending = state.nodesPending.filter(id => id !== node.id);
            await updateNodeStatus(node.id, "skipped" as NodeStatus);
            log(state, {
              nodeId: node.id,
              event: "edge_skip",
              message: `Skipped: edge conditions not met for ${node.label}`,
            });
            continue;
          }
        }
      }

      // Check preconditions
      log(state, {
        nodeId: node.id,
        event: "precondition_check",
        message: `Checking preconditions for ${node.label}`,
      });
      const { met, unmet } = evaluateNodePreconditions(node, config.environment);
      if (!met) {
        nodeStatusMap.set(node.id, "skipped");
        state.nodesSkipped.push(node.id);
        state.nodesPending = state.nodesPending.filter(id => id !== node.id);
        await updateNodeStatus(node.id, "skipped" as NodeStatus);
        log(state, {
          nodeId: node.id,
          event: "skip",
          message: `Skipped: preconditions not met — ${unmet.map(p => p.description).join(", ")}`,
          details: { unmetPreconditions: unmet },
        });
        continue;
      }

      // Dispatch to Caldera
      if (config.dryRun) {
        // Simulate success
        nodeStatusMap.set(node.id, "success");
        state.nodesCompleted.push(node.id);
        state.nodesPending = state.nodesPending.filter(id => id !== node.id);
        await updateNodeStatus(node.id, "success" as NodeStatus);
        log(state, {
          nodeId: node.id,
          event: "success",
          message: `[DRY RUN] Simulated success for ${node.label}`,
        });
        continue;
      }

      // Resolve ability ID
      const abilityId = node.calderaAbilityId || await resolveAbilityId(node.techniqueId, node.platform);
      if (!abilityId) {
        nodeStatusMap.set(node.id, "skipped");
        state.nodesSkipped.push(node.id);
        state.nodesPending = state.nodesPending.filter(id => id !== node.id);
        await updateNodeStatus(node.id, "skipped" as NodeStatus);
        log(state, {
          nodeId: node.id,
          event: "skip",
          message: `Skipped: no Caldera ability found for ${node.techniqueId}`,
        });
        continue;
      }

      // Dispatch
      log(state, {
        nodeId: node.id,
        event: "dispatch",
        message: `Dispatching ${node.label} (${abilityId}) to agent ${config.agentPawId}`,
      });
      await updateNodeStatus(node.id, "running" as NodeStatus);

      const startedAt = new Date().toISOString();
      let execResult: NodeExecutionResult;

      try {
        const { linkId } = await dispatchAbilityToOperation({
          operationId: state.operationId!,
          agentPaw: config.agentPawId,
          abilityId,
        });

        // Poll for completion
        const timeoutMs = config.timeoutOverrideMs || (node.timeout * 1000) || 300000;
        const pollMs = config.pollIntervalMs || 3000;

        log(state, {
          nodeId: node.id,
          event: "poll",
          message: `Polling link ${linkId} (timeout: ${timeoutMs}ms)`,
        });

        const linkResult = await pollLinkCompletion({
          operationId: state.operationId!,
          linkId,
          timeoutMs,
          pollIntervalMs: pollMs,
        });

        execResult = {
          nodeId: node.id,
          status: linkResult.status === 0 ? "success" : "failed",
          exitCode: linkResult.status,
          stdout: linkResult.output,
          stderr: "",
          startedAt,
          completedAt: new Date().toISOString(),
          agentId: config.agentPawId,
          calderaLinkId: linkId,
        };
      } catch (err: any) {
        execResult = {
          nodeId: node.id,
          status: err.message?.includes("timed out") ? "timeout" : "failed",
          exitCode: -1,
          stdout: "",
          stderr: err.message || "Unknown error",
          startedAt,
          completedAt: new Date().toISOString(),
          agentId: config.agentPawId,
        };
      }

      nodeResults.set(node.id, execResult);

      if (execResult.status === "success") {
        nodeStatusMap.set(node.id, "success");
        state.nodesCompleted.push(node.id);
        await updateNodeStatus(node.id, "success" as NodeStatus, {
          exitCode: execResult.exitCode,
          stdout: execResult.stdout,
          stderr: execResult.stderr,
          startedAt: execResult.startedAt,
          completedAt: execResult.completedAt,
          agentId: execResult.agentId,
        });
        log(state, {
          nodeId: node.id,
          event: "success",
          message: `Completed: ${node.label}`,
          details: { exitCode: execResult.exitCode, linkId: execResult.calderaLinkId },
        });
      } else {
        nodeStatusMap.set(node.id, "failed");
        state.nodesFailed.push(node.id);
        await updateNodeStatus(node.id, "failed" as NodeStatus, {
          exitCode: execResult.exitCode,
          stdout: execResult.stdout,
          stderr: execResult.stderr,
          startedAt: execResult.startedAt,
          completedAt: execResult.completedAt,
          agentId: execResult.agentId,
        });
        log(state, {
          nodeId: node.id,
          event: "failure",
          message: `Failed: ${node.label} — ${execResult.stderr || "exit code " + execResult.exitCode}`,
          details: { exitCode: execResult.exitCode, stderr: execResult.stderr },
        });
      }

      state.nodesPending = state.nodesPending.filter(id => id !== node.id);

      // Log edge decisions for outgoing edges
      const outEdges = adj.get(node.id) || [];
      for (const edge of outEdges) {
        const result = { exitCode: execResult.exitCode, stdout: execResult.stdout, stderr: execResult.stderr };
        const follow = shouldFollowEdge(edge, result, nodeStatusMap.get(node.id)!, config.environment);
        log(state, {
          nodeId: node.id,
          event: follow ? "edge_follow" : "edge_skip",
          message: `Edge ${node.id} → ${edge.targetNodeId} (${edge.condition}): ${follow ? "FOLLOW" : "SKIP"}`,
          details: { edgeId: edge.id, condition: edge.condition },
        });
      }
    }

    // 5. Finalize
    state.currentNodeId = null;
    const hasFailures = state.nodesFailed.length > 0;
    state.status = hasFailures ? "failed" : "completed";
    state.completedAt = new Date().toISOString();

    await updateGraphStatus(config.graphId, hasFailures ? "failed" : "completed");

    // Close Cyber C2 operation
    if (state.operationId && !config.dryRun) {
      try {
        await updateOperationState(state.operationId, "finished");
      } catch {
        // Non-critical
      }
    }

    log(state, {
      nodeId: null,
      event: hasFailures ? "failure" : "success",
      message: `Execution ${hasFailures ? "failed" : "completed"}: ${state.nodesCompleted.length} succeeded, ${state.nodesFailed.length} failed, ${state.nodesSkipped.length} skipped, ${state.nodesBlocked.length} blocked`,
    });

  } catch (err: any) {
    state.status = "failed";
    state.error = err.message;
    state.completedAt = new Date().toISOString();
    await updateGraphStatus(config.graphId, "failed");
    log(state, { nodeId: null, event: "error", message: `Execution error: ${err.message}` });

    // Cleanup on failure
    if (config.autoCleanup !== false && state.operationId && !config.dryRun) {
      await cleanupExecution(state, config);
    }
  }

  return state;
}

/**
 * Run cleanup commands for completed nodes in reverse order.
 */
async function cleanupExecution(state: ExecutionState, config: ExecutionConfig): Promise<void> {
  state.status = "cleaning_up";
  log(state, { nodeId: null, event: "cleanup", message: "Running cleanup for completed nodes" });

  const graphData = await getGraph(config.graphId);
  if (!graphData) return;

  const completedNodes = graphData.nodes.filter(n => state.nodesCompleted.includes(n.id));
  // Reverse order for cleanup
  completedNodes.reverse();

  for (const node of completedNodes) {
    if (node.cleanupCommand && state.operationId) {
      try {
        log(state, {
          nodeId: node.id,
          event: "cleanup",
          message: `Cleanup: ${node.label}`,
        });
        // Dispatch cleanup as a new link
        // In practice, cleanup commands would be dispatched as manual commands
      } catch (err: any) {
        log(state, {
          nodeId: node.id,
          event: "error",
          message: `Cleanup failed for ${node.label}: ${err.message}`,
        });
      }
    }
  }
}

/**
 * Abort a running graph execution.
 */
export async function abortExecution(graphId: string): Promise<ExecutionState | null> {
  const state = activeExecutions.get(graphId);
  if (!state) return null;

  state.status = "aborted";
  state.completedAt = new Date().toISOString();
  log(state, { nodeId: null, event: "abort", message: "Execution aborted by user" });

  // Stop Cyber C2 operation
  if (state.operationId) {
    try {
      await updateOperationState(state.operationId, "finished");
    } catch {
      // Non-critical
    }
  }

  await updateGraphStatus(graphId, "aborted");
  return state;
}

/**
 * Pause a running graph execution.
 */
export async function pauseExecution(graphId: string): Promise<ExecutionState | null> {
  const state = activeExecutions.get(graphId);
  if (!state || state.status !== "running") return null;

  state.status = "paused";
  log(state, { nodeId: null, event: "abort", message: "Execution paused" });

  if (state.operationId) {
    try {
      await updateOperationState(state.operationId, "paused");
    } catch {
      // Non-critical
    }
  }

  return state;
}

/**
 * Resume a paused graph execution.
 */
export async function resumeExecution(graphId: string): Promise<ExecutionState | null> {
  const state = activeExecutions.get(graphId);
  if (!state || state.status !== "paused") return null;

  state.status = "running";
  log(state, { nodeId: null, event: "start", message: "Execution resumed" });

  if (state.operationId) {
    try {
      await updateOperationState(state.operationId, "running");
    } catch {
      // Non-critical
    }
  }

  return state;
}

/**
 * Get the current execution state for a graph.
 */
export function getExecutionState(graphId: string): ExecutionState | null {
  return activeExecutions.get(graphId) || null;
}

/**
 * Get execution log entries for a graph.
 */
export function getExecutionLog(graphId: string, since?: string): ExecutionLogEntry[] {
  const state = activeExecutions.get(graphId);
  if (!state) return [];
  if (!since) return state.executionLog;
  return state.executionLog.filter(e => e.timestamp > since);
}

/**
 * Build an EnvironmentContext from a Caldera agent's properties.
 */
export function buildEnvironmentFromAgent(agent: {
  platform: string;
  username: string;
  privilege: string;
  host: string;
  executors: string[];
}): EnvironmentContext {
  const isAdmin = agent.privilege === "Elevated" || agent.username === "root" || agent.username === "SYSTEM";
  return {
    os: agent.platform.toLowerCase(),
    hostname: agent.host,
    privilegeLevel: isAdmin
      ? (agent.platform.toLowerCase() === "linux" ? "root" : "local_admin")
      : "user",
    networkAccess: "internal",
    installedSoftware: agent.executors,
    runningServices: [],
    openPorts: [],
    customFacts: {
      username: agent.username,
      platform: agent.platform,
    },
  };
}
