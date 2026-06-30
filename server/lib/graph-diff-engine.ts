/**
 * Graph Diff Engine
 *
 * Computes structural and technique-level differences between two ability graphs.
 * Produces Jaccard similarity, shared/unique technique sets, tactic coverage
 * comparison, edge topology differences, and safety tier divergence.
 *
 * Used for:
 * - Comparing two APT emulation plans side-by-side
 * - Identifying TTP overlap between threat actors
 * - Finding gaps in defensive coverage
 * - Merging complementary attack graphs
 */

import {
  getGraph,
  type AbilityNodeData,
  type AbilityEdgeData,
  type AbilityGraphData,
  type SafetyTier,
} from "./ability-graph-engine";

// ─── Types ──────────────────────────────────────────────────────────────

export interface TechniqueOverlap {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  inA: boolean;
  inB: boolean;
  safetyTierA?: SafetyTier;
  safetyTierB?: SafetyTier;
}

export interface TacticCoverage {
  tactic: string;
  countA: number;
  countB: number;
  techniquesA: string[];
  techniquesB: string[];
  shared: string[];
}

export interface GraphDiffResult {
  graphA: {
    id: string;
    name: string;
    actorName?: string;
    nodeCount: number;
    edgeCount: number;
    tactics: string[];
    safetyTier: SafetyTier;
  };
  graphB: {
    id: string;
    name: string;
    actorName?: string;
    nodeCount: number;
    edgeCount: number;
    tactics: string[];
    safetyTier: SafetyTier;
  };
  // Similarity metrics
  jaccardSimilarity: number;        // 0-1 based on technique overlap
  diceCoefficient: number;          // 0-1 Sørensen–Dice coefficient
  overlapCoefficient: number;       // 0-1 Szymkiewicz–Simpson coefficient
  // Technique-level comparison
  sharedTechniques: TechniqueOverlap[];
  uniqueToA: TechniqueOverlap[];
  uniqueToB: TechniqueOverlap[];
  allTechniques: TechniqueOverlap[];
  // Tactic-level comparison
  tacticCoverage: TacticCoverage[];
  tacticsOnlyA: string[];
  tacticsOnlyB: string[];
  sharedTactics: string[];
  // Structural comparison
  edgeCountA: number;
  edgeCountB: number;
  avgFanOutA: number;
  avgFanOutB: number;
  maxDepthA: number;
  maxDepthB: number;
  // Safety comparison
  safetyTierDistributionA: Record<SafetyTier, number>;
  safetyTierDistributionB: Record<SafetyTier, number>;
  // Summary
  summary: string;
}

export interface OverlapMatrixEntry {
  graphIdA: string;
  graphIdB: string;
  nameA: string;
  nameB: string;
  jaccardSimilarity: number;
  sharedCount: number;
  totalUnion: number;
}

// ─── Helpers ────────────────────────────────────────────────────────────

function computeMaxDepth(nodes: AbilityNodeData[], edges: AbilityEdgeData[]): number {
  if (nodes.length === 0) return 0;

  const adj = new Map<string, string[]>();
  const inDegree = new Map<string, number>();

  for (const node of nodes) {
    adj.set(node.id, []);
    inDegree.set(node.id, 0);
  }
  for (const edge of edges) {
    if (adj.has(edge.sourceNodeId)) {
      adj.get(edge.sourceNodeId)!.push(edge.targetNodeId);
    }
    inDegree.set(edge.targetNodeId, (inDegree.get(edge.targetNodeId) || 0) + 1);
  }

  // BFS from roots
  const depth = new Map<string, number>();
  const queue: string[] = [];
  for (const [id, deg] of inDegree) {
    if (deg === 0) {
      queue.push(id);
      depth.set(id, 0);
    }
  }

  let maxDepth = 0;
  while (queue.length > 0) {
    const current = queue.shift()!;
    const currentDepth = depth.get(current) || 0;
    for (const neighbor of adj.get(current) || []) {
      const newDepth = currentDepth + 1;
      if (!depth.has(neighbor) || newDepth > depth.get(neighbor)!) {
        depth.set(neighbor, newDepth);
        if (newDepth > maxDepth) maxDepth = newDepth;
        queue.push(neighbor);
      }
    }
  }

  return maxDepth;
}

function computeAvgFanOut(nodes: AbilityNodeData[], edges: AbilityEdgeData[]): number {
  if (nodes.length === 0) return 0;
  const outDegree = new Map<string, number>();
  for (const node of nodes) outDegree.set(node.id, 0);
  for (const edge of edges) {
    outDegree.set(edge.sourceNodeId, (outDegree.get(edge.sourceNodeId) || 0) + 1);
  }
  const total = Array.from(outDegree.values()).reduce((sum, d) => sum + d, 0);
  return Math.round((total / nodes.length) * 100) / 100;
}

function computeSafetyDistribution(nodes: AbilityNodeData[]): Record<SafetyTier, number> {
  const dist: Record<SafetyTier, number> = {
    passive: 0,
    low_impact: 0,
    medium_impact: 0,
    high_impact: 0,
    critical_impact: 0,
  };
  for (const node of nodes) {
    dist[node.safetyTier] = (dist[node.safetyTier] || 0) + 1;
  }
  return dist;
}

function getMaxSafetyTier(nodes: AbilityNodeData[]): SafetyTier {
  const tierOrder: SafetyTier[] = ["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"];
  let maxIdx = 0;
  for (const node of nodes) {
    const idx = tierOrder.indexOf(node.safetyTier);
    if (idx > maxIdx) maxIdx = idx;
  }
  return tierOrder[maxIdx];
}

// ─── Core Comparison ────────────────────────────────────────────────────

/**
 * Compare two ability graphs and produce a comprehensive diff.
 */
export async function compareGraphs(graphIdA: string, graphIdB: string): Promise<GraphDiffResult | null> {
  const [dataA, dataB] = await Promise.all([getGraph(graphIdA), getGraph(graphIdB)]);
  if (!dataA || !dataB) return null;

  const { graph: gA, nodes: nodesA, edges: edgesA } = dataA;
  const { graph: gB, nodes: nodesB, edges: edgesB } = dataB;

  // Build technique sets
  const techSetA = new Set(nodesA.map(n => n.techniqueId));
  const techSetB = new Set(nodesB.map(n => n.techniqueId));

  const union = new Set([...techSetA, ...techSetB]);
  const intersection = new Set([...techSetA].filter(t => techSetB.has(t)));

  // Similarity metrics
  const jaccardSimilarity = union.size > 0 ? Math.round((intersection.size / union.size) * 1000) / 1000 : 0;
  const diceCoefficient = (techSetA.size + techSetB.size) > 0
    ? Math.round((2 * intersection.size / (techSetA.size + techSetB.size)) * 1000) / 1000
    : 0;
  const overlapCoefficient = Math.min(techSetA.size, techSetB.size) > 0
    ? Math.round((intersection.size / Math.min(techSetA.size, techSetB.size)) * 1000) / 1000
    : 0;

  // Build technique-level comparison
  const nodeMapA = new Map<string, AbilityNodeData>();
  const nodeMapB = new Map<string, AbilityNodeData>();
  for (const n of nodesA) nodeMapA.set(n.techniqueId, n);
  for (const n of nodesB) nodeMapB.set(n.techniqueId, n);

  const allTechniques: TechniqueOverlap[] = [];
  const sharedTechniques: TechniqueOverlap[] = [];
  const uniqueToA: TechniqueOverlap[] = [];
  const uniqueToB: TechniqueOverlap[] = [];

  for (const techId of union) {
    const nA = nodeMapA.get(techId);
    const nB = nodeMapB.get(techId);
    const entry: TechniqueOverlap = {
      techniqueId: techId,
      techniqueName: nA?.techniqueName || nB?.techniqueName || techId,
      tactic: nA?.tactic || nB?.tactic || "unknown",
      inA: techSetA.has(techId),
      inB: techSetB.has(techId),
      safetyTierA: nA?.safetyTier,
      safetyTierB: nB?.safetyTier,
    };
    allTechniques.push(entry);
    if (entry.inA && entry.inB) sharedTechniques.push(entry);
    else if (entry.inA) uniqueToA.push(entry);
    else uniqueToB.push(entry);
  }

  // Tactic-level comparison
  const allTactics = new Set<string>();
  for (const n of nodesA) allTactics.add(n.tactic);
  for (const n of nodesB) allTactics.add(n.tactic);

  const tacticsA = new Set(nodesA.map(n => n.tactic));
  const tacticsB = new Set(nodesB.map(n => n.tactic));
  const sharedTactics = [...tacticsA].filter(t => tacticsB.has(t));
  const tacticsOnlyA = [...tacticsA].filter(t => !tacticsB.has(t));
  const tacticsOnlyB = [...tacticsB].filter(t => !tacticsA.has(t));

  const tacticCoverage: TacticCoverage[] = [];
  for (const tactic of allTactics) {
    const techsA = nodesA.filter(n => n.tactic === tactic).map(n => n.techniqueId);
    const techsB = nodesB.filter(n => n.tactic === tactic).map(n => n.techniqueId);
    const shared = techsA.filter(t => techsB.includes(t));
    tacticCoverage.push({
      tactic,
      countA: techsA.length,
      countB: techsB.length,
      techniquesA: techsA,
      techniquesB: techsB,
      shared,
    });
  }

  // Sort by tactic order
  const TACTIC_ORDER: Record<string, number> = {
    "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
    "execution": 3, "persistence": 4, "privilege-escalation": 5,
    "defense-evasion": 6, "credential-access": 7, "discovery": 8,
    "lateral-movement": 9, "collection": 10, "command-and-control": 11,
    "exfiltration": 12, "impact": 13,
  };
  tacticCoverage.sort((a, b) => (TACTIC_ORDER[a.tactic] ?? 99) - (TACTIC_ORDER[b.tactic] ?? 99));

  // Structural metrics
  const maxDepthA = computeMaxDepth(nodesA, edgesA);
  const maxDepthB = computeMaxDepth(nodesB, edgesB);
  const avgFanOutA = computeAvgFanOut(nodesA, edgesA);
  const avgFanOutB = computeAvgFanOut(nodesB, edgesB);

  // Safety distribution
  const safetyTierDistributionA = computeSafetyDistribution(nodesA);
  const safetyTierDistributionB = computeSafetyDistribution(nodesB);

  // Generate summary
  const summary = generateDiffSummary({
    nameA: gA.name,
    nameB: gB.name,
    jaccardSimilarity,
    sharedCount: sharedTechniques.length,
    uniqueACount: uniqueToA.length,
    uniqueBCount: uniqueToB.length,
    sharedTactics,
    tacticsOnlyA,
    tacticsOnlyB,
  });

  return {
    graphA: {
      id: gA.id,
      name: gA.name,
      actorName: gA.actorName || undefined,
      nodeCount: nodesA.length,
      edgeCount: edgesA.length,
      tactics: [...tacticsA],
      safetyTier: getMaxSafetyTier(nodesA),
    },
    graphB: {
      id: gB.id,
      name: gB.name,
      actorName: gB.actorName || undefined,
      nodeCount: nodesB.length,
      edgeCount: edgesB.length,
      tactics: [...tacticsB],
      safetyTier: getMaxSafetyTier(nodesB),
    },
    jaccardSimilarity,
    diceCoefficient,
    overlapCoefficient,
    sharedTechniques,
    uniqueToA,
    uniqueToB,
    allTechniques,
    tacticCoverage,
    tacticsOnlyA,
    tacticsOnlyB,
    sharedTactics,
    edgeCountA: edgesA.length,
    edgeCountB: edgesB.length,
    avgFanOutA,
    avgFanOutB,
    maxDepthA,
    maxDepthB,
    safetyTierDistributionA,
    safetyTierDistributionB,
    summary,
  };
}

function generateDiffSummary(params: {
  nameA: string;
  nameB: string;
  jaccardSimilarity: number;
  sharedCount: number;
  uniqueACount: number;
  uniqueBCount: number;
  sharedTactics: string[];
  tacticsOnlyA: string[];
  tacticsOnlyB: string[];
}): string {
  const similarity = Math.round(params.jaccardSimilarity * 100);
  let level = "minimal";
  if (similarity > 70) level = "high";
  else if (similarity > 40) level = "moderate";
  else if (similarity > 15) level = "low";

  const parts: string[] = [];
  parts.push(
    `${params.nameA} and ${params.nameB} show ${level} technique overlap (${similarity}% Jaccard similarity).`,
  );
  parts.push(
    `They share ${params.sharedCount} technique(s), with ${params.uniqueACount} unique to the first and ${params.uniqueBCount} unique to the second.`,
  );

  if (params.sharedTactics.length > 0) {
    parts.push(`Common tactics: ${params.sharedTactics.join(", ")}.`);
  }
  if (params.tacticsOnlyA.length > 0) {
    parts.push(`Tactics only in ${params.nameA}: ${params.tacticsOnlyA.join(", ")}.`);
  }
  if (params.tacticsOnlyB.length > 0) {
    parts.push(`Tactics only in ${params.nameB}: ${params.tacticsOnlyB.join(", ")}.`);
  }

  return parts.join(" ");
}

/**
 * Compute an overlap matrix for multiple graphs.
 * Returns pairwise Jaccard similarity for all combinations.
 */
export async function computeOverlapMatrix(
  graphIds: string[],
): Promise<{
  graphs: Array<{ id: string; name: string; nodeCount: number }>;
  matrix: OverlapMatrixEntry[];
}> {
  // Load all graphs
  const graphsData = await Promise.all(graphIds.map(id => getGraph(id)));
  const validGraphs = graphsData.filter(g => g !== null) as NonNullable<typeof graphsData[0]>[];

  const graphs = validGraphs.map(g => ({
    id: g.graph.id,
    name: g.graph.name,
    nodeCount: g.nodes.length,
  }));

  // Compute pairwise comparisons
  const matrix: OverlapMatrixEntry[] = [];

  for (let i = 0; i < validGraphs.length; i++) {
    for (let j = i + 1; j < validGraphs.length; j++) {
      const gA = validGraphs[i];
      const gB = validGraphs[j];

      const techSetA = new Set(gA.nodes.map(n => n.techniqueId));
      const techSetB = new Set(gB.nodes.map(n => n.techniqueId));

      const union = new Set([...techSetA, ...techSetB]);
      const intersection = new Set([...techSetA].filter(t => techSetB.has(t)));

      matrix.push({
        graphIdA: gA.graph.id,
        graphIdB: gB.graph.id,
        nameA: gA.graph.name,
        nameB: gB.graph.name,
        jaccardSimilarity: union.size > 0 ? Math.round((intersection.size / union.size) * 1000) / 1000 : 0,
        sharedCount: intersection.size,
        totalUnion: union.size,
      });
    }
  }

  return { graphs, matrix };
}

/**
 * Pure function: compute Jaccard similarity between two technique sets.
 */
export function jaccardSimilarity(setA: Set<string>, setB: Set<string>): number {
  const union = new Set([...setA, ...setB]);
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  return union.size > 0 ? intersection.size / union.size : 0;
}

/**
 * Pure function: compute Dice coefficient between two technique sets.
 */
export function diceCoefficient(setA: Set<string>, setB: Set<string>): number {
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  return (setA.size + setB.size) > 0 ? (2 * intersection.size) / (setA.size + setB.size) : 0;
}

/**
 * Pure function: compute overlap coefficient between two technique sets.
 */
export function overlapCoefficient(setA: Set<string>, setB: Set<string>): number {
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const minSize = Math.min(setA.size, setB.size);
  return minSize > 0 ? intersection.size / minSize : 0;
}
