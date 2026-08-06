/**
 * Actor Graph Templates
 *
 * Auto-generates ability graphs from threat actor profiles in the APT library.
 * Queries the threat intelligence catalog for actor techniques, maps them to
 * ability nodes with proper tactic ordering, and generates edges based on
 * technique dependencies and kill-chain progression.
 *
 * Supports diverse actor profiles: APT, ransomware, cybercrime, hacktivist groups.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { threatActors } from "../../drizzle/schema";
import { eq, desc, sql, like, inArray, isNotNull } from "drizzle-orm";
import {
  createGraph,
  type AbilityNodeData,
  type AbilityEdgeData,
  type SafetyTier,
  type EdgeCondition,
  type Precondition,
} from "./ability-graph-engine";
import type { ScanMode } from "./scan-policy-engine";
import { getGroupDetail, type ThreatGroupProfile, type ActorType } from "./threat-intel-catalog";

// ─── Tactic Kill-Chain Ordering ─────────────────────────────────────────

const TACTIC_ORDER: Record<string, number> = {
  "reconnaissance": 0,
  "resource-development": 1,
  "initial-access": 2,
  "execution": 3,
  "persistence": 4,
  "privilege-escalation": 5,
  "defense-evasion": 6,
  "credential-access": 7,
  "discovery": 8,
  "lateral-movement": 9,
  "collection": 10,
  "command-and-control": 11,
  "exfiltration": 12,
  "impact": 13,
};

/**
 * Map a tactic to a safety tier based on its position in the kill chain.
 */
function tacticToSafetyTier(tactic: string): SafetyTier {
  const order = TACTIC_ORDER[tactic.toLowerCase()] ?? 5;
  if (order <= 1) return "passive";           // recon, resource-dev
  if (order <= 3) return "low_impact";        // initial-access, execution
  if (order <= 6) return "medium_impact";     // persistence, privesc, defense-evasion
  if (order <= 9) return "high_impact";       // cred-access, discovery, lateral-movement
  return "critical_impact";                    // collection, c2, exfil, impact
}

/**
 * Generate default preconditions based on technique and tactic.
 */
function generatePreconditions(technique: { id: string; name: string; tactic: string }): Precondition[] {
  const preconditions: Precondition[] = [];
  const tactic = technique.tactic.toLowerCase();
  const name = technique.name.toLowerCase();

  // Privilege-related preconditions
  if (tactic === "privilege-escalation" || name.includes("admin") || name.includes("root")) {
    preconditions.push({
      type: "privilege",
      key: "privilege_level",
      operator: "in",
      value: ["user", "local_admin"],
      description: "Requires at least user-level access",
      required: true,
    });
  }

  // Lateral movement needs network access
  if (tactic === "lateral-movement") {
    preconditions.push({
      type: "network",
      key: "network_access",
      operator: "in",
      value: ["internal", "external"],
      description: "Requires network access for lateral movement",
      required: true,
    });
  }

  // PowerShell techniques need PowerShell
  if (name.includes("powershell") || technique.id === "T1059.001") {
    preconditions.push({
      type: "software",
      key: "installed",
      operator: "contains",
      value: "powershell",
      description: "Requires PowerShell",
      required: true,
    });
  }

  // Windows-specific techniques
  if (name.includes("registry") || name.includes("wmi") || name.includes("windows")) {
    preconditions.push({
      type: "os",
      key: "os_family",
      operator: "eq",
      value: "windows",
      description: "Requires Windows OS",
      required: true,
    });
  }

  // Linux-specific techniques
  if (name.includes("cron") || name.includes("bash") || name.includes("unix")) {
    preconditions.push({
      type: "os",
      key: "os_family",
      operator: "in",
      value: ["linux", "darwin"],
      description: "Requires Unix-like OS",
      required: true,
    });
  }

  return preconditions;
}

// ─── Graph Generation ───────────────────────────────────────────────────

function generateNodeId(): string {
  return `agn-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function generateEdgeId(): string {
  return `age-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

/**
 * Generate an ability graph from a threat actor profile.
 */
export async function generateGraphFromActorProfile(params: {
  actorId: string;
  targetEnvironment?: string;
  includeAlternatives?: boolean;
  createdBy?: string;
}): Promise<{
  graphId: string;
  name: string;
  nodeCount: number;
  edgeCount: number;
  tactics: string[];
  safetyTier: SafetyTier;
}> {
  // 1. Fetch actor profile from catalog
  const detail = await getGroupDetail(params.actorId);
  if (!detail || !detail.actor) {
    throw new Error(`Actor ${params.actorId} not found in threat catalog`);
  }

  const actor = detail.actor;
  const techniques: Array<{ id: string; name: string; tactic: string; description?: string }> =
    Array.isArray((actor as any).techniques) ? (actor as any).techniques : [];

  if (techniques.length === 0) {
    throw new Error(`Actor ${actor.name} has no techniques in the catalog`);
  }

  // 2. Sort techniques by tactic kill-chain order
  const sortedTechniques = [...techniques].sort((a, b) => {
    const orderA = TACTIC_ORDER[a.tactic?.toLowerCase()] ?? 99;
    const orderB = TACTIC_ORDER[b.tactic?.toLowerCase()] ?? 99;
    return orderA - orderB;
  });

  // 3. Group techniques by tactic
  const tacticGroups = new Map<string, typeof sortedTechniques>();
  for (const tech of sortedTechniques) {
    const tactic = tech.tactic?.toLowerCase() || "unknown";
    if (!tacticGroups.has(tactic)) tacticGroups.set(tactic, []);
    tacticGroups.get(tactic)!.push(tech);
  }

  const graphId = `ag-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const nodes: AbilityNodeData[] = [];
  const edges: AbilityEdgeData[] = [];

  // 4. Create nodes for each technique
  const tacticNodeIds = new Map<string, string[]>(); // tactic → node IDs

  for (const tech of sortedTechniques) {
    const nodeId = generateNodeId();
    const tactic = tech.tactic?.toLowerCase() || "unknown";

    if (!tacticNodeIds.has(tactic)) tacticNodeIds.set(tactic, []);
    tacticNodeIds.get(tactic)!.push(nodeId);

    nodes.push({
      id: nodeId,
      graphId,
      label: tech.name,
      description: tech.description || `${tech.name} (${tech.id})`,
      techniqueId: tech.id,
      techniqueName: tech.name,
      tactic,
      preconditions: generatePreconditions(tech),
      exitCriteria: [
        {
          type: "exit_code",
          key: "code",
          operator: "eq",
          value: 0,
          description: "Command exits successfully",
        },
      ],
      safetyTier: tacticToSafetyTier(tactic),
      timeout: 300,
      retryCount: 1,
      status: "pending",
      order: 0,
      layer: TACTIC_ORDER[tactic] ?? 0,
    });
  }

  // 5. Generate edges based on tactic ordering
  const orderedTactics = Array.from(tacticGroups.keys()).sort(
    (a, b) => (TACTIC_ORDER[a] ?? 99) - (TACTIC_ORDER[b] ?? 99),
  );

  for (let i = 0; i < orderedTactics.length - 1; i++) {
    const currentTactic = orderedTactics[i];
    const nextTactic = orderedTactics[i + 1];
    const currentNodes = tacticNodeIds.get(currentTactic) || [];
    const nextNodes = tacticNodeIds.get(nextTactic) || [];

    // Connect last node of current tactic to first node of next tactic
    if (currentNodes.length > 0 && nextNodes.length > 0) {
      const sourceId = currentNodes[currentNodes.length - 1];
      const targetId = nextNodes[0];

      edges.push({
        id: generateEdgeId(),
        graphId,
        sourceNodeId: sourceId,
        targetNodeId: targetId,
        condition: "on_success" as EdgeCondition,
        weight: 1,
        label: `${currentTactic} → ${nextTactic}`,
      });
    }

    // Within the same tactic, chain techniques sequentially
    for (const tactic of orderedTactics) {
      const nodeIds = tacticNodeIds.get(tactic) || [];
      for (let j = 0; j < nodeIds.length - 1; j++) {
        edges.push({
          id: generateEdgeId(),
          graphId,
          sourceNodeId: nodeIds[j],
          targetNodeId: nodeIds[j + 1],
          condition: "on_success" as EdgeCondition,
          weight: 1,
          label: `${tactic} chain`,
        });
      }
    }
  }

  // Handle single-tactic case: chain within the tactic
  if (orderedTactics.length === 1) {
    const tactic = orderedTactics[0];
    const nodeIds = tacticNodeIds.get(tactic) || [];
    for (let j = 0; j < nodeIds.length - 1; j++) {
      edges.push({
        id: generateEdgeId(),
        graphId,
        sourceNodeId: nodeIds[j],
        targetNodeId: nodeIds[j + 1],
        condition: "on_success" as EdgeCondition,
        weight: 1,
        label: `${tactic} chain`,
      });
    }
  }

  // 6. Deduplicate edges (same source→target pair)
  const edgeSet = new Set<string>();
  const uniqueEdges = edges.filter(e => {
    const key = `${e.sourceNodeId}->${e.targetNodeId}`;
    if (edgeSet.has(key)) return false;
    edgeSet.add(key);
    return true;
  });

  // 7. Compute overall safety tier
  const tierOrder: SafetyTier[] = ["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"];
  let maxTierIdx = 0;
  for (const node of nodes) {
    const idx = tierOrder.indexOf(node.safetyTier);
    if (idx > maxTierIdx) maxTierIdx = idx;
  }

  // 8. Persist the graph
  const graphName = `${actor.name} — Emulation Plan`;
  const tactics = orderedTactics;

  const graphResult = await createGraph({
    name: graphName,
    description: `Auto-generated ability graph from ${actor.name} threat actor profile. Covers ${tactics.length} tactics and ${nodes.length} techniques.`,
    sourceType: "actor_profile" as const,
    sourceId: params.actorId,
    actorName: actor.name as string,
    scanMode: "active-standard" as ScanMode,
    nodes,
    edges: uniqueEdges,
    createdBy: params.createdBy,
  });

  return {
    graphId,
    name: graphName,
    nodeCount: nodes.length,
    edgeCount: uniqueEdges.length,
    tactics,
    safetyTier: tierOrder[maxTierIdx],
  };
}

/**
 * Get available actor templates — actors that have techniques in the catalog.
 */
export async function getAvailableActorTemplates(params?: {
  type?: ActorType;
  limit?: number;
}): Promise<Array<{
  actorId: string;
  name: string;
  type: string;
  techniqueCount: number;
  threatLevel: string;
  sophistication: string;
  hasExistingGraph: boolean;
}>> {
  const db = await getDb();
  if (!db) return [];

  let query = db.select().from(threatActors);

  // We need to filter for actors that have techniques
  const actors = await query
    .where(isNotNull(threatActors.techniques))
    .orderBy(desc(threatActors.confidence))
    .limit(params?.limit || 50);

  const results = actors
    .filter(a => {
      const techs = a.techniques as any[];
      if (!Array.isArray(techs) || techs.length === 0) return false;
      if (params?.type && a.type !== params.type) return false;
      return true;
    })
    .map(a => ({
      actorId: a.actorId,
      name: a.name,
      type: a.type || "unknown",
      techniqueCount: Array.isArray(a.techniques) ? (a.techniques as any[]).length : 0,
      threatLevel: a.threatLevel || "medium",
      sophistication: a.sophistication || "intermediate",
      hasExistingGraph: false, // TODO: check ability_graphs table
    }));

  return results;
}
