/**
 * Ability Graph Engine
 *
 * Directed Acyclic Graph (DAG) engine for composing, ordering, and
 * executing Caldera abilities as structured attack emulation plans.
 *
 * Core capabilities:
 * - Build DAGs from MITRE ATT&CK technique chains
 * - Topological sort for correct execution ordering
 * - Precondition evaluation (OS, privileges, network, software)
 * - Conditional edge following based on exit criteria
 * - Safety tier gating via scan policy engine integration
 * - LLM-assisted technique-to-ability decomposition
 *
 * Author: Harrison Cook — AceofCloud
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import {
  abilityGraphs,
  abilityGraphNodes,
  abilityGraphEdges,
  ttpKnowledge,
  type InsertAbilityGraph,
  type InsertAbilityGraphNode,
  type InsertAbilityGraphEdge,
} from "../../drizzle/schema";
import { eq, and, sql, inArray, desc, isNotNull } from "drizzle-orm";
import { getScanPolicyEngine, type ScanMode } from "./scan-policy-engine";

// ─── Types ──────────────────────────────────────────────────────────────

export type NodeStatus = "pending" | "ready" | "running" | "success" | "failed" | "skipped" | "blocked";

export type EdgeCondition =
  | "always"           // unconditional — follow after source completes
  | "on_success"       // follow only if source succeeds
  | "on_failure"       // follow only if source fails (fallback path)
  | "on_output_match"  // follow if source output matches a pattern
  | "on_precondition"  // follow if target preconditions are met
  | "conditional";     // evaluate custom expression

export type SafetyTier =
  | "passive"          // read-only, no system changes
  | "low_impact"       // minor changes, easily reversible
  | "medium_impact"    // significant changes, may need cleanup
  | "high_impact"      // destructive or hard to reverse
  | "critical_impact"; // could cause outage or data loss

export interface Precondition {
  type: "os" | "privilege" | "network" | "software" | "file" | "service" | "registry" | "custom";
  key: string;           // e.g. "os_family", "privilege_level", "port_open"
  operator: "eq" | "neq" | "in" | "not_in" | "exists" | "gt" | "lt" | "contains" | "regex";
  value: string | string[] | number | boolean;
  description: string;
  required: boolean;     // if true, node is blocked when unmet
}

export interface ExitCriteria {
  type: "output_contains" | "exit_code" | "file_exists" | "process_running" | "custom";
  key: string;
  operator: "eq" | "neq" | "contains" | "regex" | "gt" | "lt";
  value: string | number | boolean;
  description: string;
}

export interface AbilityNodeData {
  id: string;                    // unique node ID within the graph
  graphId: string;               // parent graph ID
  label: string;                 // human-readable name
  description: string;
  techniqueId: string;           // MITRE ATT&CK technique ID (e.g. T1059.001)
  techniqueName: string;
  tactic: string;                // MITRE tactic (e.g. execution)
  // Caldera ability mapping
  calderaAbilityId?: string;     // mapped Caldera ability UUID
  executor?: string;             // psh, cmd, sh, bash, proc
  platform?: string;             // windows, linux, darwin
  command?: string;              // command template
  cleanupCommand?: string;       // cleanup/undo command
  payload?: string;              // payload file reference
  // Execution constraints
  preconditions: Precondition[];
  exitCriteria: ExitCriteria[];
  safetyTier: SafetyTier;
  timeout: number;               // max execution time in seconds
  retryCount: number;            // max retries on failure
  // Metadata
  status: NodeStatus;
  order: number;                 // topological order index
  layer: number;                 // visual layer (depth from root)
  x?: number;                    // visual x position
  y?: number;                    // visual y position
  executionResult?: {
    exitCode: number;
    stdout: string;
    stderr: string;
    startedAt: string;
    completedAt: string;
    agentId?: string;
  };
}

export interface AbilityEdgeData {
  id: string;
  graphId: string;
  sourceNodeId: string;
  targetNodeId: string;
  condition: EdgeCondition;
  conditionExpression?: string;  // for "conditional" type — JS-like expression
  outputMatchPattern?: string;   // for "on_output_match" — regex pattern
  weight: number;                // priority when multiple edges leave a node (lower = higher priority)
  label?: string;                // human-readable edge label
}

export interface AbilityGraphData {
  id: string;
  name: string;
  description: string;
  // Source context
  sourceType: "manual" | "technique_chain" | "actor_profile" | "incident_report" | "playbook";
  sourceId?: string;             // reference to source entity
  actorName?: string;
  // Graph metadata
  tactics: string[];             // ordered list of tactics covered
  techniqueCount: number;
  nodeCount: number;
  edgeCount: number;
  // Execution state
  status: "draft" | "validated" | "ready" | "running" | "completed" | "failed" | "aborted";
  safetyTier: SafetyTier;        // max safety tier across all nodes
  scanMode: ScanMode;            // required scan mode for execution
  // Execution tracking
  executionId?: string;
  startedAt?: string;
  completedAt?: string;
  nodesCompleted: number;
  nodesFailed: number;
  nodesSkipped: number;
  // Metadata
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

function generateNodeId(): string {
  return `agn-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function generateEdgeId(): string {
  return `age-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function generateGraphId(): string {
  return `ag-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

// ─── DAG Operations ─────────────────────────────────────────────────────

/**
 * Build an adjacency list from edges.
 */
export function buildAdjacencyList(edges: AbilityEdgeData[]): Map<string, AbilityEdgeData[]> {
  const adj = new Map<string, AbilityEdgeData[]>();
  for (const edge of edges) {
    if (!adj.has(edge.sourceNodeId)) adj.set(edge.sourceNodeId, []);
    adj.get(edge.sourceNodeId)!.push(edge);
  }
  return adj;
}

/**
 * Build a reverse adjacency list (incoming edges per node).
 */
export function buildReverseAdjacencyList(edges: AbilityEdgeData[]): Map<string, AbilityEdgeData[]> {
  const rev = new Map<string, AbilityEdgeData[]>();
  for (const edge of edges) {
    if (!rev.has(edge.targetNodeId)) rev.set(edge.targetNodeId, []);
    rev.get(edge.targetNodeId)!.push(edge);
  }
  return rev;
}

/**
 * Detect cycles in the graph using DFS.
 * Returns the first cycle found as an array of node IDs, or null if acyclic.
 */
export function detectCycle(nodes: AbilityNodeData[], edges: AbilityEdgeData[]): string[] | null {
  const adj = buildAdjacencyList(edges);
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  const parent = new Map<string, string | null>();

  for (const node of nodes) {
    color.set(node.id, WHITE);
    parent.set(node.id, null);
  }

  for (const node of nodes) {
    if (color.get(node.id) === WHITE) {
      const cycle = dfsVisit(node.id, adj, color, parent);
      if (cycle) return cycle;
    }
  }
  return null;
}

function dfsVisit(
  nodeId: string,
  adj: Map<string, AbilityEdgeData[]>,
  color: Map<string, number>,
  parent: Map<string, string | null>,
): string[] | null {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  color.set(nodeId, GRAY);

  for (const edge of adj.get(nodeId) || []) {
    const target = edge.targetNodeId;
    if (color.get(target) === GRAY) {
      // Back edge found — reconstruct cycle
      const cycle: string[] = [target, nodeId];
      let cur = nodeId;
      while (cur !== target) {
        cur = parent.get(cur) || "";
        if (!cur) break;
        cycle.push(cur);
      }
      return cycle.reverse();
    }
    if (color.get(target) === WHITE) {
      parent.set(target, nodeId);
      const cycle = dfsVisit(target, adj, color, parent);
      if (cycle) return cycle;
    }
  }

  color.set(nodeId, BLACK);
  return null;
}

/**
 * Topological sort using Kahn's algorithm.
 * Returns nodes in execution order, or throws if a cycle exists.
 */
export function topologicalSort(nodes: AbilityNodeData[], edges: AbilityEdgeData[]): AbilityNodeData[] {
  const cycle = detectCycle(nodes, edges);
  if (cycle) {
    throw new Error(`Graph contains a cycle: ${cycle.join(" → ")}`);
  }

  const inDegree = new Map<string, number>();
  const nodeMap = new Map<string, AbilityNodeData>();
  for (const node of nodes) {
    inDegree.set(node.id, 0);
    nodeMap.set(node.id, node);
  }
  for (const edge of edges) {
    inDegree.set(edge.targetNodeId, (inDegree.get(edge.targetNodeId) || 0) + 1);
  }

  const adj = buildAdjacencyList(edges);
  const queue: string[] = [];
  for (const [id, deg] of inDegree) {
    if (deg === 0) queue.push(id);
  }

  const sorted: AbilityNodeData[] = [];
  let order = 0;

  while (queue.length > 0) {
    // Sort queue by safety tier (passive first) for deterministic ordering
    queue.sort((a, b) => {
      const nodeA = nodeMap.get(a);
      const nodeB = nodeMap.get(b);
      const tierOrder: SafetyTier[] = ["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"];
      const tierA = tierOrder.indexOf(nodeA?.safetyTier || "passive");
      const tierB = tierOrder.indexOf(nodeB?.safetyTier || "passive");
      return tierA - tierB;
    });

    const current = queue.shift()!;
    const node = nodeMap.get(current);
    if (node) {
      node.order = order++;
      sorted.push(node);
    }

    for (const edge of adj.get(current) || []) {
      const newDeg = (inDegree.get(edge.targetNodeId) || 1) - 1;
      inDegree.set(edge.targetNodeId, newDeg);
      if (newDeg === 0) {
        queue.push(edge.targetNodeId);
      }
    }
  }

  if (sorted.length !== nodes.length) {
    throw new Error("Graph contains unreachable nodes or cycles");
  }

  return sorted;
}

/**
 * Assign visual layers (depth from root nodes) for graph visualization.
 */
export function assignLayers(nodes: AbilityNodeData[], edges: AbilityEdgeData[]): void {
  const inDegree = new Map<string, number>();
  const nodeMap = new Map<string, AbilityNodeData>();
  for (const node of nodes) {
    inDegree.set(node.id, 0);
    nodeMap.set(node.id, node);
  }
  for (const edge of edges) {
    inDegree.set(edge.targetNodeId, (inDegree.get(edge.targetNodeId) || 0) + 1);
  }

  const adj = buildAdjacencyList(edges);

  // BFS from root nodes (in-degree 0)
  const queue: { id: string; layer: number }[] = [];
  for (const [id, deg] of inDegree) {
    if (deg === 0) {
      queue.push({ id, layer: 0 });
      const node = nodeMap.get(id);
      if (node) node.layer = 0;
    }
  }

  while (queue.length > 0) {
    const { id, layer } = queue.shift()!;
    for (const edge of adj.get(id) || []) {
      const targetNode = nodeMap.get(edge.targetNodeId);
      if (targetNode) {
        const newLayer = layer + 1;
        if (targetNode.layer === undefined || newLayer > targetNode.layer) {
          targetNode.layer = newLayer;
        }
        queue.push({ id: edge.targetNodeId, layer: newLayer });
      }
    }
  }
}

// ─── Precondition Evaluation ────────────────────────────────────────────

export interface EnvironmentContext {
  os: string;                    // "windows", "linux", "darwin"
  osVersion?: string;
  hostname?: string;
  privilegeLevel: string;        // "user", "local_admin", "domain_admin", "system", "root"
  networkAccess: string;         // "local", "internal", "external"
  installedSoftware: string[];
  runningServices: string[];
  openPorts: number[];
  registryKeys?: string[];
  files?: string[];
  customFacts: Record<string, string | number | boolean>;
}

/**
 * Evaluate a single precondition against the environment context.
 */
export function evaluatePrecondition(precondition: Precondition, env: EnvironmentContext): boolean {
  const { type, key, operator, value } = precondition;

  let actual: string | string[] | number | boolean | undefined;

  switch (type) {
    case "os":
      if (key === "os_family") actual = env.os;
      else if (key === "os_version") actual = env.osVersion;
      else actual = env.customFacts[key];
      break;
    case "privilege":
      actual = env.privilegeLevel;
      break;
    case "network":
      if (key === "network_access") actual = env.networkAccess;
      else if (key === "port_open") actual = env.openPorts.map(String);
      else actual = env.customFacts[key];
      break;
    case "software":
      actual = env.installedSoftware;
      break;
    case "service":
      actual = env.runningServices;
      break;
    case "file":
      actual = env.files || [];
      break;
    case "registry":
      actual = env.registryKeys || [];
      break;
    case "custom":
      actual = env.customFacts[key];
      break;
    default:
      return false;
  }

  if (actual === undefined) return !precondition.required;

  switch (operator) {
    case "eq":
      return String(actual) === String(value);
    case "neq":
      return String(actual) !== String(value);
    case "in":
      if (Array.isArray(value)) return value.includes(String(actual));
      return false;
    case "not_in":
      if (Array.isArray(value)) return !value.includes(String(actual));
      return false;
    case "exists":
      if (Array.isArray(actual)) return actual.some(a => String(a) === String(value));
      return actual !== undefined && actual !== null;
    case "gt":
      return Number(actual) > Number(value);
    case "lt":
      return Number(actual) < Number(value);
    case "contains":
      if (Array.isArray(actual)) return actual.some(a => String(a).toLowerCase().includes(String(value).toLowerCase()));
      return String(actual).toLowerCase().includes(String(value).toLowerCase());
    case "regex":
      try {
        return new RegExp(String(value), "i").test(String(actual));
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * Evaluate all preconditions for a node.
 * Returns { met: boolean, unmet: Precondition[] }.
 */
export function evaluateNodePreconditions(
  node: AbilityNodeData,
  env: EnvironmentContext,
): { met: boolean; unmet: Precondition[] } {
  const unmet: Precondition[] = [];
  for (const pre of node.preconditions) {
    if (!evaluatePrecondition(pre, env)) {
      unmet.push(pre);
    }
  }
  const requiredUnmet = unmet.filter(p => p.required);
  return { met: requiredUnmet.length === 0, unmet };
}

// ─── Exit Criteria Evaluation ───────────────────────────────────────────

/**
 * Evaluate exit criteria against execution results.
 */
export function evaluateExitCriteria(
  criteria: ExitCriteria,
  result: { exitCode: number; stdout: string; stderr: string },
): boolean {
  const { type, key, operator, value } = criteria;
  let actual: string | number;

  switch (type) {
    case "exit_code":
      actual = result.exitCode;
      break;
    case "output_contains":
      actual = result.stdout + result.stderr;
      break;
    case "file_exists":
    case "process_running":
    case "custom":
      // These require agent-side evaluation — return true optimistically
      return true;
    default:
      return false;
  }

  switch (operator) {
    case "eq":
      return String(actual) === String(value);
    case "neq":
      return String(actual) !== String(value);
    case "contains":
      return String(actual).toLowerCase().includes(String(value).toLowerCase());
    case "regex":
      try {
        return new RegExp(String(value), "i").test(String(actual));
      } catch {
        return false;
      }
    case "gt":
      return Number(actual) > Number(value);
    case "lt":
      return Number(actual) < Number(value);
    default:
      return false;
  }
}

// ─── Safety Tier Gating ─────────────────────────────────────────────────

const SAFETY_TIER_TO_SCAN_MODE: Record<SafetyTier, ScanMode> = {
  passive: "passive",
  low_impact: "active-low",
  medium_impact: "active-standard",
  high_impact: "active-aggressive",
  critical_impact: "active-aggressive",
};

const SCAN_MODE_ORDER: ScanMode[] = ["passive", "active-low", "active-standard", "active-aggressive"];

/**
 * Check if a node's safety tier is allowed under the current scan mode.
 */
export function isNodeAllowedBySafetyTier(node: AbilityNodeData, allowedMode: ScanMode): boolean {
  const requiredMode = SAFETY_TIER_TO_SCAN_MODE[node.safetyTier];
  const requiredIdx = SCAN_MODE_ORDER.indexOf(requiredMode);
  const allowedIdx = SCAN_MODE_ORDER.indexOf(allowedMode);
  return requiredIdx <= allowedIdx;
}

/**
 * Filter graph nodes to only those allowed by the scan policy.
 * Returns { allowed: AbilityNodeData[], blocked: AbilityNodeData[] }.
 */
export function filterNodesBySafetyTier(
  nodes: AbilityNodeData[],
  allowedMode: ScanMode,
): { allowed: AbilityNodeData[]; blocked: AbilityNodeData[] } {
  const allowed: AbilityNodeData[] = [];
  const blocked: AbilityNodeData[] = [];
  for (const node of nodes) {
    if (isNodeAllowedBySafetyTier(node, allowedMode)) {
      allowed.push(node);
    } else {
      blocked.push({ ...node, status: "blocked" });
    }
  }
  return { allowed, blocked };
}

/**
 * Compute the maximum safety tier across all nodes in a graph.
 */
export function computeGraphSafetyTier(nodes: AbilityNodeData[]): SafetyTier {
  const tierOrder: SafetyTier[] = ["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"];
  let maxIdx = 0;
  for (const node of nodes) {
    const idx = tierOrder.indexOf(node.safetyTier);
    if (idx > maxIdx) maxIdx = idx;
  }
  return tierOrder[maxIdx];
}

// ─── Edge Condition Evaluation ──────────────────────────────────────────

/**
 * Determine if an edge should be followed based on the source node's result.
 */
export function shouldFollowEdge(
  edge: AbilityEdgeData,
  sourceResult: { exitCode: number; stdout: string; stderr: string } | null,
  sourceStatus: NodeStatus,
  targetEnv?: EnvironmentContext,
  targetNode?: AbilityNodeData,
): boolean {
  switch (edge.condition) {
    case "always":
      return sourceStatus === "success" || sourceStatus === "failed";
    case "on_success":
      return sourceStatus === "success";
    case "on_failure":
      return sourceStatus === "failed";
    case "on_output_match":
      if (!sourceResult || !edge.outputMatchPattern) return false;
      try {
        const regex = new RegExp(edge.outputMatchPattern, "i");
        return regex.test(sourceResult.stdout + sourceResult.stderr);
      } catch {
        return false;
      }
    case "on_precondition":
      if (!targetEnv || !targetNode) return true; // optimistic if no env
      return evaluateNodePreconditions(targetNode, targetEnv).met;
    case "conditional":
      // Custom expressions are evaluated server-side with limited scope
      if (!edge.conditionExpression) return true;
      try {
        // Simple expression evaluation — only supports basic comparisons
        const expr = edge.conditionExpression;
        if (sourceResult) {
          const ctx = {
            exitCode: sourceResult.exitCode,
            stdout: sourceResult.stdout,
            stderr: sourceResult.stderr,
            status: sourceStatus,
          };
          // Replace variable references
          let evaluated = expr;
          for (const [key, val] of Object.entries(ctx)) {
            evaluated = evaluated.replace(new RegExp(`\\$\\{${key}\\}`, "g"), String(val));
          }
          // Only allow simple comparisons
          if (/^[\w\s=!<>."']+$/.test(evaluated)) {
            return new Function(`return ${evaluated}`)() as boolean;
          }
        }
        return true;
      } catch {
        return true;
      }
    default:
      return true;
  }
}

// ─── Graph Walk (Execution Simulation) ──────────────────────────────────

export interface WalkResult {
  executionOrder: string[];      // node IDs in execution order
  skippedNodes: string[];        // nodes skipped due to conditions
  blockedNodes: string[];        // nodes blocked by safety tier
  failedNodes: string[];         // nodes that failed
  completedNodes: string[];      // nodes that completed successfully
  totalSteps: number;
  safetyViolations: string[];    // descriptions of safety violations
}

/**
 * Simulate walking the graph with the given environment context.
 * Does not actually execute anything — just determines the execution plan.
 */
export function walkGraph(
  nodes: AbilityNodeData[],
  edges: AbilityEdgeData[],
  env: EnvironmentContext,
  allowedMode: ScanMode,
): WalkResult {
  const result: WalkResult = {
    executionOrder: [],
    skippedNodes: [],
    blockedNodes: [],
    failedNodes: [],
    completedNodes: [],
    totalSteps: 0,
    safetyViolations: [],
  };

  // Topological sort
  let sorted: AbilityNodeData[];
  try {
    sorted = topologicalSort(nodes, edges);
  } catch (e: any) {
    result.safetyViolations.push(`Graph validation failed: ${e.message}`);
    return result;
  }

  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const adj = buildAdjacencyList(edges);
  const rev = buildReverseAdjacencyList(edges);
  const nodeStatus = new Map<string, NodeStatus>();

  for (const node of sorted) {
    // Check safety tier
    if (!isNodeAllowedBySafetyTier(node, allowedMode)) {
      nodeStatus.set(node.id, "blocked");
      result.blockedNodes.push(node.id);
      result.safetyViolations.push(
        `Node "${node.label}" (${node.techniqueId}) requires ${node.safetyTier} but scan mode is ${allowedMode}`,
      );
      continue;
    }

    // Check if all incoming edges allow this node to execute
    const incomingEdges = rev.get(node.id) || [];
    if (incomingEdges.length > 0) {
      const anyEdgeAllows = incomingEdges.some(edge => {
        const sourceStatus = nodeStatus.get(edge.sourceNodeId) || "pending";
        // Simulate: if source completed, check edge condition
        if (sourceStatus === "success" || sourceStatus === "failed") {
          return shouldFollowEdge(edge, null, sourceStatus, env, node);
        }
        return false;
      });

      if (!anyEdgeAllows) {
        // Check if all sources are blocked/skipped (propagate skip)
        const allSourcesInactive = incomingEdges.every(edge => {
          const s = nodeStatus.get(edge.sourceNodeId);
          return s === "blocked" || s === "skipped";
        });
        if (allSourcesInactive) {
          nodeStatus.set(node.id, "skipped");
          result.skippedNodes.push(node.id);
          continue;
        }
      }
    }

    // Check preconditions
    const { met, unmet } = evaluateNodePreconditions(node, env);
    if (!met) {
      nodeStatus.set(node.id, "skipped");
      result.skippedNodes.push(node.id);
      continue;
    }

    // Node is ready to execute
    nodeStatus.set(node.id, "success"); // simulate success for walk
    result.executionOrder.push(node.id);
    result.completedNodes.push(node.id);
    result.totalSteps++;
  }

  return result;
}

// ─── LLM-Assisted Technique Decomposition ───────────────────────────────

/**
 * Use LLM to decompose a list of MITRE ATT&CK techniques into an
 * ability graph with proper ordering, preconditions, and edges.
 */
export async function decomposeTechniquesToGraph(params: {
  techniques: Array<{ id: string; name: string; tactic: string }>;
  targetEnvironment: string;
  actorName?: string;
  objective?: string;
}): Promise<{ nodes: AbilityNodeData[]; edges: AbilityEdgeData[] }> {
  const graphId = generateGraphId();

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are an expert red team operator and Caldera adversary emulation designer.
Given a list of MITRE ATT&CK techniques, decompose them into an ordered ability graph:
1. Each technique becomes one or more ability nodes
2. Nodes are connected by edges representing execution flow
3. Each node has preconditions (what must be true before execution)
4. Each node has exit criteria (what indicates success/failure)
5. Each node has a safety tier (passive, low_impact, medium_impact, high_impact, critical_impact)
6. Edges have conditions (always, on_success, on_failure, on_output_match)

Return valid JSON matching the specified schema.`,
      },
      {
        role: "user",
        content: `Decompose these techniques into an ability graph:

Techniques:
${params.techniques.map(t => `- ${t.id}: ${t.name} (${t.tactic})`).join("\n")}

Target Environment: ${params.targetEnvironment}
${params.actorName ? `Threat Actor: ${params.actorName}` : ""}
${params.objective ? `Objective: ${params.objective}` : ""}

Return JSON with:
{
  "nodes": [
    {
      "label": "Human-readable step name",
      "description": "What this step does",
      "techniqueId": "T1059.001",
      "techniqueName": "PowerShell",
      "tactic": "execution",
      "executor": "psh|cmd|sh|bash",
      "platform": "windows|linux|darwin",
      "command": "Example command template",
      "cleanupCommand": "Cleanup command or null",
      "preconditions": [
        {
          "type": "os|privilege|network|software|service|file|registry|custom",
          "key": "os_family",
          "operator": "eq|neq|in|not_in|exists|gt|lt|contains|regex",
          "value": "windows",
          "description": "Requires Windows OS",
          "required": true
        }
      ],
      "exitCriteria": [
        {
          "type": "exit_code|output_contains|file_exists|process_running|custom",
          "key": "exit_code",
          "operator": "eq",
          "value": 0,
          "description": "Command exits successfully"
        }
      ],
      "safetyTier": "passive|low_impact|medium_impact|high_impact|critical_impact",
      "timeout": 300,
      "retryCount": 1
    }
  ],
  "edges": [
    {
      "sourceIndex": 0,
      "targetIndex": 1,
      "condition": "always|on_success|on_failure|on_output_match|on_precondition|conditional",
      "outputMatchPattern": "regex pattern (for on_output_match)",
      "weight": 1,
      "label": "Edge description"
    }
  ]
}`,
      },
    ],
    response_format: { type: "json_object" },
  });

  const content = String(response.choices?.[0]?.message?.content || "{}");
  let parsed: any;
  try {
    let cleaned = content.trim();
    if (cleaned.startsWith("```")) {
      cleaned = cleaned.replace(/^```(?:json)?\s*\n?/, "").replace(/\n?```\s*$/, "");
    }
    parsed = JSON.parse(cleaned);
  } catch {
    parsed = { nodes: [], edges: [] };
  }

  const rawNodes = Array.isArray(parsed.nodes) ? parsed.nodes : [];
  const rawEdges = Array.isArray(parsed.edges) ? parsed.edges : [];

  // Convert to typed nodes
  const nodes: AbilityNodeData[] = rawNodes.map((n: any, idx: number) => ({
    id: generateNodeId(),
    graphId,
    label: n.label || `Step ${idx + 1}`,
    description: n.description || "",
    techniqueId: n.techniqueId || params.techniques[idx]?.id || "T0000",
    techniqueName: n.techniqueName || params.techniques[idx]?.name || "Unknown",
    tactic: n.tactic || params.techniques[idx]?.tactic || "unknown",
    calderaAbilityId: n.calderaAbilityId || undefined,
    executor: n.executor || "sh",
    platform: n.platform || "linux",
    command: n.command || undefined,
    cleanupCommand: n.cleanupCommand || undefined,
    preconditions: Array.isArray(n.preconditions)
      ? n.preconditions.map((p: any) => ({
          type: p.type || "custom",
          key: p.key || "unknown",
          operator: p.operator || "eq",
          value: p.value ?? "",
          description: p.description || "",
          required: p.required !== false,
        }))
      : [],
    exitCriteria: Array.isArray(n.exitCriteria)
      ? n.exitCriteria.map((e: any) => ({
          type: e.type || "exit_code",
          key: e.key || "exit_code",
          operator: e.operator || "eq",
          value: e.value ?? 0,
          description: e.description || "",
        }))
      : [{ type: "exit_code" as const, key: "exit_code", operator: "eq" as const, value: 0, description: "Success" }],
    safetyTier: (["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"].includes(n.safetyTier)
      ? n.safetyTier
      : "medium_impact") as SafetyTier,
    timeout: n.timeout || 300,
    retryCount: n.retryCount ?? 1,
    status: "pending" as NodeStatus,
    order: idx,
    layer: 0,
  }));

  // Convert edges (using indices to reference nodes)
  const edges: AbilityEdgeData[] = rawEdges.map((e: any) => {
    const sourceIdx = typeof e.sourceIndex === "number" ? e.sourceIndex : 0;
    const targetIdx = typeof e.targetIndex === "number" ? e.targetIndex : 1;
    return {
      id: generateEdgeId(),
      graphId,
      sourceNodeId: nodes[sourceIdx]?.id || nodes[0]?.id || "",
      targetNodeId: nodes[targetIdx]?.id || nodes[nodes.length - 1]?.id || "",
      condition: (["always", "on_success", "on_failure", "on_output_match", "on_precondition", "conditional"].includes(e.condition)
        ? e.condition
        : "on_success") as EdgeCondition,
      conditionExpression: e.conditionExpression || undefined,
      outputMatchPattern: e.outputMatchPattern || undefined,
      weight: e.weight || 1,
      label: e.label || undefined,
    };
  });

  // Assign layers for visualization
  if (nodes.length > 0) {
    assignLayers(nodes, edges);
  }

  return { nodes, edges };
}

// ─── Graph CRUD (Database) ──────────────────────────────────────────────

/**
 * Create a new ability graph with nodes and edges.
 */
export async function createGraph(params: {
  name: string;
  description: string;
  sourceType: AbilityGraphData["sourceType"];
  sourceId?: string;
  actorName?: string;
  scanMode?: ScanMode;
  nodes: AbilityNodeData[];
  edges: AbilityEdgeData[];
  createdBy?: string;
}): Promise<{ graphId: string; nodeCount: number; edgeCount: number }> {
  const db = await requireDb();
  const graphId = generateGraphId();

  // Validate DAG
  const cycle = detectCycle(params.nodes, params.edges);
  if (cycle) {
    throw new Error(`Cannot create graph with cycle: ${cycle.join(" → ")}`);
  }

  // Sort and assign layers
  const sorted = topologicalSort(params.nodes, params.edges);
  assignLayers(sorted, params.edges);

  const tactics = [...new Set(sorted.map(n => n.tactic))];
  const maxSafetyTier = computeGraphSafetyTier(sorted);

  // Insert graph
  await db.insert(abilityGraphs).values({
    graphId,
    name: params.name,
    description: params.description,
    sourceType: params.sourceType,
    sourceId: params.sourceId || null,
    actorName: params.actorName || null,
    tactics: JSON.stringify(tactics),
    techniqueCount: new Set(sorted.map(n => n.techniqueId)).size,
    nodeCount: sorted.length,
    edgeCount: params.edges.length,
    status: "draft",
    safetyTier: maxSafetyTier,
    scanMode: params.scanMode || SAFETY_TIER_TO_SCAN_MODE[maxSafetyTier],
    nodesCompleted: 0,
    nodesFailed: 0,
    nodesSkipped: 0,
    createdBy: params.createdBy || null,
  });

  // Insert nodes
  for (const node of sorted) {
    await db.insert(abilityGraphNodes).values({
      nodeId: node.id,
      graphId,
      label: node.label,
      description: node.description,
      techniqueId: node.techniqueId,
      techniqueName: node.techniqueName,
      tactic: node.tactic,
      calderaAbilityId: node.calderaAbilityId || null,
      executor: node.executor || null,
      platform: node.platform || null,
      command: node.command || null,
      cleanupCommand: node.cleanupCommand || null,
      payload: node.payload || null,
      preconditions: JSON.stringify(node.preconditions),
      exitCriteria: JSON.stringify(node.exitCriteria),
      safetyTier: node.safetyTier,
      timeout: node.timeout,
      retryCount: node.retryCount,
      status: "pending",
      executionOrder: node.order,
      layer: node.layer,
    });
  }

  // Insert edges
  for (const edge of params.edges) {
    await db.insert(abilityGraphEdges).values({
      edgeId: edge.id,
      graphId,
      sourceNodeId: edge.sourceNodeId,
      targetNodeId: edge.targetNodeId,
      condition: edge.condition,
      conditionExpression: edge.conditionExpression || null,
      outputMatchPattern: edge.outputMatchPattern || null,
      weight: edge.weight,
      label: edge.label || null,
    });
  }

  return { graphId, nodeCount: sorted.length, edgeCount: params.edges.length };
}

/**
 * Get a graph with all its nodes and edges.
 */
export async function getGraph(graphId: string): Promise<{
  graph: AbilityGraphData;
  nodes: AbilityNodeData[];
  edges: AbilityEdgeData[];
} | null> {
  const db = await requireDb();

  const [graphRow] = await db.select().from(abilityGraphs).where(eq(abilityGraphs.graphId, graphId)).limit(1);
  if (!graphRow) return null;

  const nodeRows = await db.select().from(abilityGraphNodes)
    .where(eq(abilityGraphNodes.graphId, graphId))
    .orderBy(abilityGraphNodes.executionOrder);

  const edgeRows = await db.select().from(abilityGraphEdges)
    .where(eq(abilityGraphEdges.graphId, graphId));

  const graph: AbilityGraphData = {
    id: graphRow.graphId,
    name: graphRow.name,
    description: graphRow.description || "",
    sourceType: graphRow.sourceType as AbilityGraphData["sourceType"],
    sourceId: graphRow.sourceId || undefined,
    actorName: graphRow.actorName || undefined,
    tactics: safeParseJson(graphRow.tactics) || [],
    techniqueCount: graphRow.techniqueCount || 0,
    nodeCount: graphRow.nodeCount || 0,
    edgeCount: graphRow.edgeCount || 0,
    status: graphRow.status as AbilityGraphData["status"],
    safetyTier: graphRow.safetyTier as SafetyTier,
    scanMode: graphRow.scanMode as ScanMode,
    executionId: graphRow.executionId || undefined,
    startedAt: graphRow.startedAt?.toISOString(),
    completedAt: graphRow.completedAt?.toISOString(),
    nodesCompleted: graphRow.nodesCompleted || 0,
    nodesFailed: graphRow.nodesFailed || 0,
    nodesSkipped: graphRow.nodesSkipped || 0,
    createdBy: graphRow.createdBy || undefined,
    createdAt: graphRow.createdAt?.toISOString() || new Date().toISOString(),
    updatedAt: graphRow.updatedAt?.toISOString() || new Date().toISOString(),
  };

  const nodes: AbilityNodeData[] = nodeRows.map(r => ({
    id: r.nodeId,
    graphId: r.graphId,
    label: r.label,
    description: r.description || "",
    techniqueId: r.techniqueId,
    techniqueName: r.techniqueName,
    tactic: r.tactic,
    calderaAbilityId: r.calderaAbilityId || undefined,
    executor: r.executor || undefined,
    platform: r.platform || undefined,
    command: r.command || undefined,
    cleanupCommand: r.cleanupCommand || undefined,
    payload: r.payload || undefined,
    preconditions: safeParseJson(r.preconditions) || [],
    exitCriteria: safeParseJson(r.exitCriteria) || [],
    safetyTier: r.safetyTier as SafetyTier,
    timeout: r.timeout || 300,
    retryCount: r.retryCount || 1,
    status: r.status as NodeStatus,
    order: r.executionOrder || 0,
    layer: r.layer || 0,
    executionResult: r.executionResult ? safeParseJson(r.executionResult) : undefined,
  }));

  const edges: AbilityEdgeData[] = edgeRows.map(r => ({
    id: r.edgeId,
    graphId: r.graphId,
    sourceNodeId: r.sourceNodeId,
    targetNodeId: r.targetNodeId,
    condition: r.condition as EdgeCondition,
    conditionExpression: r.conditionExpression || undefined,
    outputMatchPattern: r.outputMatchPattern || undefined,
    weight: r.weight || 1,
    label: r.label || undefined,
  }));

  return { graph, nodes, edges };
}

/**
 * List all graphs with optional filtering.
 */
export async function listGraphs(params?: {
  status?: string;
  sourceType?: string;
  limit?: number;
  offset?: number;
}): Promise<{ items: AbilityGraphData[]; total: number }> {
  const db = await requireDb();
  const conditions: any[] = [];

  if (params?.status) {
    conditions.push(eq(abilityGraphs.status, params.status));
  }
  if (params?.sourceType) {
    conditions.push(eq(abilityGraphs.sourceType, params.sourceType));
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [items, countResult] = await Promise.all([
    db.select().from(abilityGraphs).where(where)
      .orderBy(desc(abilityGraphs.createdAt))
      .limit(params?.limit ?? 50)
      .offset(params?.offset ?? 0),
    db.select({ count: sql<number>`count(*)` }).from(abilityGraphs).where(where),
  ]);

  return {
    items: items.map(r => ({
      id: r.graphId,
      name: r.name,
      description: r.description || "",
      sourceType: r.sourceType as AbilityGraphData["sourceType"],
      sourceId: r.sourceId || undefined,
      actorName: r.actorName || undefined,
      tactics: safeParseJson(r.tactics) || [],
      techniqueCount: r.techniqueCount || 0,
      nodeCount: r.nodeCount || 0,
      edgeCount: r.edgeCount || 0,
      status: r.status as AbilityGraphData["status"],
      safetyTier: r.safetyTier as SafetyTier,
      scanMode: r.scanMode as ScanMode,
      executionId: r.executionId || undefined,
      startedAt: r.startedAt?.toISOString(),
      completedAt: r.completedAt?.toISOString(),
      nodesCompleted: r.nodesCompleted || 0,
      nodesFailed: r.nodesFailed || 0,
      nodesSkipped: r.nodesSkipped || 0,
      createdBy: r.createdBy || undefined,
      createdAt: r.createdAt?.toISOString() || new Date().toISOString(),
      updatedAt: r.updatedAt?.toISOString() || new Date().toISOString(),
    })),
    total: Number(countResult[0]?.count ?? 0),
  };
}

/**
 * Delete a graph and all its nodes and edges.
 */
export async function deleteGraph(graphId: string): Promise<boolean> {
  const db = await requireDb();
  await db.delete(abilityGraphEdges).where(eq(abilityGraphEdges.graphId, graphId));
  await db.delete(abilityGraphNodes).where(eq(abilityGraphNodes.graphId, graphId));
  await db.delete(abilityGraphs).where(eq(abilityGraphs.graphId, graphId));
  return true;
}

/**
 * Update graph status.
 */
export async function updateGraphStatus(graphId: string, status: AbilityGraphData["status"]): Promise<void> {
  const db = await requireDb();
  await db.update(abilityGraphs)
    .set({ status, updatedAt: new Date() })
    .where(eq(abilityGraphs.graphId, graphId));
}

/**
 * Update a node's status and execution result.
 */
export async function updateNodeStatus(
  nodeId: string,
  status: NodeStatus,
  executionResult?: AbilityNodeData["executionResult"],
): Promise<void> {
  const db = await requireDb();
  const updates: any = { status };
  if (executionResult) {
    updates.executionResult = JSON.stringify(executionResult);
  }
  await db.update(abilityGraphNodes)
    .set(updates)
    .where(eq(abilityGraphNodes.nodeId, nodeId));
}

// ─── Graph Generation from TTP Knowledge ────────────────────────────────

/**
 * Generate an ability graph from TTP knowledge base entries.
 * Pulls prerequisite/follow-up chains and environmental constraints.
 */
export async function generateGraphFromTtpChain(params: {
  techniqueIds: string[];
  name: string;
  targetEnvironment?: string;
  actorName?: string;
  scanMode?: ScanMode;
  createdBy?: string;
}): Promise<{ graphId: string; nodeCount: number; edgeCount: number }> {
  const db = await requireDb();

  // Fetch TTP knowledge for the requested techniques
  const ttpEntries = await db.select()
    .from(ttpKnowledge)
    .where(inArray(ttpKnowledge.techniqueId, params.techniqueIds));

  if (ttpEntries.length === 0) {
    // Fall back to LLM decomposition
    const techniques = params.techniqueIds.map(id => ({
      id,
      name: id,
      tactic: "unknown",
    }));
    const { nodes, edges } = await decomposeTechniquesToGraph({
      techniques,
      targetEnvironment: params.targetEnvironment || "hybrid",
      actorName: params.actorName,
    });
    return createGraph({
      name: params.name,
      description: `Auto-generated from technique chain: ${params.techniqueIds.join(", ")}`,
      sourceType: "technique_chain",
      actorName: params.actorName,
      scanMode: params.scanMode,
      nodes,
      edges,
      createdBy: params.createdBy,
    });
  }

  // Build nodes from TTP knowledge
  const TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
  ];

  // Sort by tactic order
  ttpEntries.sort((a, b) => {
    const idxA = TACTIC_ORDER.indexOf(a.tactic || "");
    const idxB = TACTIC_ORDER.indexOf(b.tactic || "");
    return (idxA === -1 ? 99 : idxA) - (idxB === -1 ? 99 : idxB);
  });

  const nodes: AbilityNodeData[] = ttpEntries.map((ttp, idx) => {
    const envConstraints = (ttp.environmentalConstraints as any) || {};
    const calderaAbilities = (ttp.calderaAbilities as any[]) || [];
    const executionMethods = (ttp.executionMethods as any[]) || [];
    const firstMethod = executionMethods[0] || {};
    const firstAbility = calderaAbilities[0];

    // Build preconditions from environmental constraints
    const preconditions: Precondition[] = [];
    if (envConstraints.requiredOS && Array.isArray(envConstraints.requiredOS)) {
      preconditions.push({
        type: "os",
        key: "os_family",
        operator: "in",
        value: envConstraints.requiredOS,
        description: `Requires ${envConstraints.requiredOS.join(" or ")}`,
        required: true,
      });
    }
    if (envConstraints.requiredPrivileges) {
      preconditions.push({
        type: "privilege",
        key: "privilege_level",
        operator: "in",
        value: ["system", "root", "domain_admin", "local_admin", envConstraints.requiredPrivileges],
        description: `Requires ${envConstraints.requiredPrivileges} or higher`,
        required: true,
      });
    }
    if (envConstraints.requiredSoftware && Array.isArray(envConstraints.requiredSoftware)) {
      for (const sw of envConstraints.requiredSoftware) {
        preconditions.push({
          type: "software",
          key: "installed_software",
          operator: "contains",
          value: sw,
          description: `Requires ${sw} installed`,
          required: false,
        });
      }
    }

    // Determine safety tier from red team value and technique nature
    let safetyTier: SafetyTier = "medium_impact";
    const tactic = ttp.tactic || "";
    if (["reconnaissance", "discovery"].includes(tactic)) {
      safetyTier = "passive";
    } else if (["resource-development"].includes(tactic)) {
      safetyTier = "low_impact";
    } else if (["initial-access", "execution", "persistence", "privilege-escalation"].includes(tactic)) {
      safetyTier = "medium_impact";
    } else if (["lateral-movement", "credential-access", "collection"].includes(tactic)) {
      safetyTier = "high_impact";
    } else if (["exfiltration", "impact"].includes(tactic)) {
      safetyTier = "critical_impact";
    }

    return {
      id: generateNodeId(),
      graphId: "",
      label: ttp.techniqueName || ttp.techniqueId,
      description: (ttp.description || "").substring(0, 500),
      techniqueId: ttp.techniqueId,
      techniqueName: ttp.techniqueName,
      tactic: ttp.tactic || "unknown",
      calderaAbilityId: firstAbility?.abilityId || undefined,
      executor: firstMethod.platforms?.[0] === "windows" ? "psh" : "sh",
      platform: firstMethod.platforms?.[0] || "linux",
      command: firstMethod.commands?.[0] || firstAbility?.command || undefined,
      cleanupCommand: undefined,
      preconditions,
      exitCriteria: [{
        type: "exit_code" as const,
        key: "exit_code",
        operator: "eq" as const,
        value: 0,
        description: "Command exits successfully",
      }],
      safetyTier,
      timeout: 300,
      retryCount: 1,
      status: "pending" as NodeStatus,
      order: idx,
      layer: 0,
    };
  });

  // Build edges — sequential chain with on_success condition
  const edges: AbilityEdgeData[] = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({
      id: generateEdgeId(),
      graphId: "",
      sourceNodeId: nodes[i].id,
      targetNodeId: nodes[i + 1].id,
      condition: "on_success",
      weight: 1,
      label: `${nodes[i].tactic} → ${nodes[i + 1].tactic}`,
    });
  }

  // Add follow-up technique edges from TTP knowledge
  for (const ttp of ttpEntries) {
    const followUps = (ttp.followUpTechniques as string[]) || [];
    const sourceNode = nodes.find(n => n.techniqueId === ttp.techniqueId);
    if (!sourceNode) continue;

    for (const followUpId of followUps) {
      const targetNode = nodes.find(n => n.techniqueId === followUpId);
      if (!targetNode) continue;

      // Check if edge already exists
      const exists = edges.some(
        e => e.sourceNodeId === sourceNode.id && e.targetNodeId === targetNode.id,
      );
      if (!exists) {
        edges.push({
          id: generateEdgeId(),
          graphId: "",
          sourceNodeId: sourceNode.id,
          targetNodeId: targetNode.id,
          condition: "on_success",
          weight: 2,
          label: `Follow-up: ${ttp.techniqueId} → ${followUpId}`,
        });
      }
    }
  }

  // Remove any edges that would create cycles
  const safeEdges: AbilityEdgeData[] = [];
  for (const edge of edges) {
    const testEdges = [...safeEdges, edge];
    const cycle = detectCycle(nodes, testEdges);
    if (!cycle) {
      safeEdges.push(edge);
    }
  }

  return createGraph({
    name: params.name,
    description: `Generated from TTP knowledge: ${params.techniqueIds.join(", ")}`,
    sourceType: "technique_chain",
    actorName: params.actorName,
    scanMode: params.scanMode,
    nodes,
    edges: safeEdges,
    createdBy: params.createdBy,
  });
}

// ─── Graph Statistics ───────────────────────────────────────────────────

export async function getGraphStats(): Promise<{
  totalGraphs: number;
  byStatus: Record<string, number>;
  bySourceType: Record<string, number>;
  totalNodes: number;
  totalEdges: number;
  avgNodesPerGraph: number;
}> {
  const db = await requireDb();

  const [graphCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(abilityGraphs);
  const statusCounts = await db.select({
    status: abilityGraphs.status,
    count: sql<number>`COUNT(*)`,
  }).from(abilityGraphs).groupBy(abilityGraphs.status);

  const sourceTypeCounts = await db.select({
    sourceType: abilityGraphs.sourceType,
    count: sql<number>`COUNT(*)`,
  }).from(abilityGraphs).groupBy(abilityGraphs.sourceType);

  const [nodeCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(abilityGraphNodes);
  const [edgeCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(abilityGraphEdges);

  const byStatus: Record<string, number> = {};
  for (const s of statusCounts) byStatus[s.status || "unknown"] = s.count;

  const bySourceType: Record<string, number> = {};
  for (const s of sourceTypeCounts) bySourceType[s.sourceType || "unknown"] = s.count;

  const total = graphCount?.count || 0;
  return {
    totalGraphs: total,
    byStatus,
    bySourceType,
    totalNodes: nodeCount?.count || 0,
    totalEdges: edgeCount?.count || 0,
    avgNodesPerGraph: total > 0 ? Math.round((nodeCount?.count || 0) / total) : 0,
  };
}

// ─── Utility ────────────────────────────────────────────────────────────

function safeParseJson(val: any): any {
  if (val === null || val === undefined) return null;
  if (typeof val === "object") return val;
  if (typeof val === "string") {
    try {
      return JSON.parse(val);
    } catch {
      return null;
    }
  }
  return null;
}
