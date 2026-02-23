/**
 * Automated Attack Path Discovery Engine
 * Graph-based path computation from AD enumeration, cloud IAM policies,
 * and vulnerability scan data to automatically find paths to crown jewels.
 */

export interface GraphNode {
  id: number;
  type: string;
  name: string;
  riskScore: number;
  isCrownJewel: boolean;
  properties?: Record<string, any>;
}

export interface GraphEdge {
  id: number;
  sourceNodeId: number;
  targetNodeId: number;
  edgeType: string;
  technique?: string;
  probability: number;
}

export interface DiscoveredPath {
  name: string;
  nodes: number[];
  edges: number[];
  totalHops: number;
  riskScore: number;
  crownJewelTarget: string;
  chokePoints: ChokePoint[];
}

export interface ChokePoint {
  nodeId: number;
  nodeName: string;
  pathsThrough: number;
  remediationImpact: number;
}

/**
 * Build adjacency list from edges
 */
function buildAdjacencyList(edges: GraphEdge[]): Map<number, GraphEdge[]> {
  const adj = new Map<number, GraphEdge[]>();
  for (const edge of edges) {
    if (!adj.has(edge.sourceNodeId)) adj.set(edge.sourceNodeId, []);
    adj.get(edge.sourceNodeId)!.push(edge);
  }
  return adj;
}

/**
 * BFS-based path discovery from all entry points to crown jewels.
 * Entry points are nodes with type "user", "computer", or "cloud_identity"
 * that have incoming edges from external sources or are marked as initial access.
 */
export function discoverAttackPaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  maxHops: number = 10,
  maxPaths: number = 50
): DiscoveredPath[] {
  const adj = buildAdjacencyList(edges);
  const nodeMap = new Map<number, GraphNode>();
  nodes.forEach((n) => nodeMap.set(n.id, n));

  const crownJewels = nodes.filter((n) => n.isCrownJewel);
  const entryPoints = nodes.filter((n) =>
    ["user", "computer", "cloud_identity"].includes(n.type) && !n.isCrownJewel
  );

  if (crownJewels.length === 0 || entryPoints.length === 0) {
    return [];
  }

  const allPaths: DiscoveredPath[] = [];

  for (const target of crownJewels) {
    for (const entry of entryPoints) {
      if (allPaths.length >= maxPaths) break;

      const paths = bfsAllPaths(adj, entry.id, target.id, maxHops);
      for (const path of paths) {
        if (allPaths.length >= maxPaths) break;

        const pathEdgeIds = getEdgeIdsForPath(path, edges);
        const riskScore = calculatePathRisk(path, pathEdgeIds, nodeMap, edges);

        allPaths.push({
          name: `${entry.name} → ${target.name}`,
          nodes: path,
          edges: pathEdgeIds,
          totalHops: path.length - 1,
          riskScore,
          crownJewelTarget: target.name,
          chokePoints: [], // Computed separately
        });
      }
    }
  }

  // Sort by risk score descending
  allPaths.sort((a, b) => b.riskScore - a.riskScore);

  // Compute choke points across all discovered paths
  const chokePointMap = computeChokePoints(allPaths, nodeMap);
  for (const path of allPaths) {
    path.chokePoints = path.nodes
      .filter((nid) => chokePointMap.has(nid))
      .map((nid) => chokePointMap.get(nid)!)
      .sort((a, b) => b.pathsThrough - a.pathsThrough)
      .slice(0, 3);
  }

  return allPaths.slice(0, maxPaths);
}

/**
 * BFS to find all simple paths (up to maxHops) between source and target.
 * Returns at most 5 paths per source-target pair to avoid explosion.
 */
function bfsAllPaths(
  adj: Map<number, GraphEdge[]>,
  source: number,
  target: number,
  maxHops: number
): number[][] {
  const results: number[][] = [];
  const queue: { node: number; path: number[]; visited: Set<number> }[] = [
    { node: source, path: [source], visited: new Set([source]) },
  ];

  while (queue.length > 0 && results.length < 5) {
    const current = queue.shift()!;

    if (current.node === target) {
      results.push(current.path);
      continue;
    }

    if (current.path.length > maxHops) continue;

    const neighbors = adj.get(current.node) || [];
    for (const edge of neighbors) {
      if (!current.visited.has(edge.targetNodeId)) {
        const newVisited = new Set(current.visited);
        newVisited.add(edge.targetNodeId);
        queue.push({
          node: edge.targetNodeId,
          path: [...current.path, edge.targetNodeId],
          visited: newVisited,
        });
      }
    }
  }

  return results;
}

function getEdgeIdsForPath(path: number[], edges: GraphEdge[]): number[] {
  const edgeIds: number[] = [];
  for (let i = 0; i < path.length - 1; i++) {
    const edge = edges.find(
      (e) => e.sourceNodeId === path[i] && e.targetNodeId === path[i + 1]
    );
    if (edge) edgeIds.push(edge.id);
  }
  return edgeIds;
}

function calculatePathRisk(
  path: number[],
  edgeIds: number[],
  nodeMap: Map<number, GraphNode>,
  edges: GraphEdge[]
): number {
  // Risk = product of edge probabilities * max node risk * hop penalty
  let probability = 1.0;
  let maxNodeRisk = 0;

  for (const eid of edgeIds) {
    const edge = edges.find((e) => e.id === eid);
    if (edge) probability *= edge.probability || 0.5;
  }

  for (const nid of path) {
    const node = nodeMap.get(nid);
    if (node && node.riskScore > maxNodeRisk) maxNodeRisk = node.riskScore;
  }

  const hopPenalty = Math.max(0.1, 1 - (path.length - 1) * 0.05);
  return Math.round(probability * maxNodeRisk * hopPenalty * 100) / 10;
}

function computeChokePoints(
  paths: DiscoveredPath[],
  nodeMap: Map<number, GraphNode>
): Map<number, ChokePoint> {
  const nodePathCount = new Map<number, number>();

  for (const path of paths) {
    // Exclude first and last node (entry and target)
    for (let i = 1; i < path.nodes.length - 1; i++) {
      const nid = path.nodes[i];
      nodePathCount.set(nid, (nodePathCount.get(nid) || 0) + 1);
    }
  }

  const chokePoints = new Map<number, ChokePoint>();
  for (const [nodeId, count] of Array.from(nodePathCount)) {
    if (count >= 2) {
      // Node appears in 2+ paths — it's a choke point
      const node = nodeMap.get(nodeId);
      chokePoints.set(nodeId, {
        nodeId,
        nodeName: node?.name || `Node ${nodeId}`,
        pathsThrough: count,
        remediationImpact: Math.round((count / paths.length) * 100),
      });
    }
  }

  return chokePoints;
}

/**
 * Ingest vulnerability scan findings as graph nodes and edges.
 * Links CVEs to hosts and marks exploitable vulns as high-probability edges.
 */
export function ingestVulnDataToGraph(
  vulnFindings: Array<{
    cveId: string | null;
    hostIp: string | null;
    severity: string;
    exploitAvailable: boolean;
    cvssScore: number | null;
  }>,
  existingNodes: GraphNode[]
): { newNodes: Omit<GraphNode, "id">[]; newEdges: Omit<GraphEdge, "id">[] } {
  const newNodes: Omit<GraphNode, "id">[] = [];
  const newEdges: Omit<GraphEdge, "id">[] = [];

  const hostNodeMap = new Map<string, number>();
  for (const node of existingNodes) {
    if (node.type === "computer" && node.properties?.ip) {
      hostNodeMap.set(node.properties.ip, node.id);
    }
  }

  const seenCVEs = new Set<string>();
  let tempId = existingNodes.length + 1000;

  for (const vuln of vulnFindings) {
    if (!vuln.cveId || seenCVEs.has(vuln.cveId)) continue;
    seenCVEs.add(vuln.cveId);

    const vulnNodeId = tempId++;
    newNodes.push({
      type: "vulnerability",
      name: vuln.cveId,
      riskScore: vuln.cvssScore || 5.0,
      isCrownJewel: false,
      properties: {
        severity: vuln.severity,
        exploitAvailable: vuln.exploitAvailable,
        cvssScore: vuln.cvssScore,
      },
    });

    // Link vuln to host if host exists in graph
    if (vuln.hostIp && hostNodeMap.has(vuln.hostIp)) {
      const hostNodeId = hostNodeMap.get(vuln.hostIp)!;
      newEdges.push({
        sourceNodeId: vulnNodeId,
        targetNodeId: hostNodeId,
        edgeType: "exploits",
        technique: vuln.cveId,
        probability: vuln.exploitAvailable ? 0.8 : 0.3,
      });
    }
  }

  return { newNodes, newEdges };
}
