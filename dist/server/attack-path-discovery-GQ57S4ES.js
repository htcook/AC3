import "./chunk-KFQGP6VL.js";

// server/lib/attack-path-discovery.ts
function buildAdjacencyList(edges) {
  const adj = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    if (!adj.has(edge.sourceNodeId)) adj.set(edge.sourceNodeId, []);
    adj.get(edge.sourceNodeId).push(edge);
  }
  return adj;
}
function discoverAttackPaths(nodes, edges, maxHops = 10, maxPaths = 50) {
  const adj = buildAdjacencyList(edges);
  const nodeMap = /* @__PURE__ */ new Map();
  nodes.forEach((n) => nodeMap.set(n.id, n));
  const crownJewels = nodes.filter((n) => n.isCrownJewel);
  const entryPoints = nodes.filter(
    (n) => ["user", "computer", "cloud_identity"].includes(n.type) && !n.isCrownJewel
  );
  if (crownJewels.length === 0 || entryPoints.length === 0) {
    return [];
  }
  const allPaths = [];
  for (const target of crownJewels) {
    for (const entry of entryPoints) {
      if (allPaths.length >= maxPaths) break;
      const paths = bfsAllPaths(adj, entry.id, target.id, maxHops);
      for (const path of paths) {
        if (allPaths.length >= maxPaths) break;
        const pathEdgeIds = getEdgeIdsForPath(path, edges);
        const riskScore = calculatePathRisk(path, pathEdgeIds, nodeMap, edges);
        allPaths.push({
          name: `${entry.name} \u2192 ${target.name}`,
          nodes: path,
          edges: pathEdgeIds,
          totalHops: path.length - 1,
          riskScore,
          crownJewelTarget: target.name,
          chokePoints: []
          // Computed separately
        });
      }
    }
  }
  allPaths.sort((a, b) => b.riskScore - a.riskScore);
  const chokePointMap = computeChokePoints(allPaths, nodeMap);
  for (const path of allPaths) {
    path.chokePoints = path.nodes.filter((nid) => chokePointMap.has(nid)).map((nid) => chokePointMap.get(nid)).sort((a, b) => b.pathsThrough - a.pathsThrough).slice(0, 3);
  }
  return allPaths.slice(0, maxPaths);
}
function bfsAllPaths(adj, source, target, maxHops) {
  const results = [];
  const queue = [
    { node: source, path: [source], visited: /* @__PURE__ */ new Set([source]) }
  ];
  while (queue.length > 0 && results.length < 5) {
    const current = queue.shift();
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
          visited: newVisited
        });
      }
    }
  }
  return results;
}
function getEdgeIdsForPath(path, edges) {
  const edgeIds = [];
  for (let i = 0; i < path.length - 1; i++) {
    const edge = edges.find(
      (e) => e.sourceNodeId === path[i] && e.targetNodeId === path[i + 1]
    );
    if (edge) edgeIds.push(edge.id);
  }
  return edgeIds;
}
function calculatePathRisk(path, edgeIds, nodeMap, edges) {
  let probability = 1;
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
function computeChokePoints(paths, nodeMap) {
  const nodePathCount = /* @__PURE__ */ new Map();
  for (const path of paths) {
    for (let i = 1; i < path.nodes.length - 1; i++) {
      const nid = path.nodes[i];
      nodePathCount.set(nid, (nodePathCount.get(nid) || 0) + 1);
    }
  }
  const chokePoints = /* @__PURE__ */ new Map();
  for (const [nodeId, count] of Array.from(nodePathCount)) {
    if (count >= 2) {
      const node = nodeMap.get(nodeId);
      chokePoints.set(nodeId, {
        nodeId,
        nodeName: node?.name || `Node ${nodeId}`,
        pathsThrough: count,
        remediationImpact: Math.round(count / paths.length * 100)
      });
    }
  }
  return chokePoints;
}
function ingestVulnDataToGraph(vulnFindings, existingNodes) {
  const newNodes = [];
  const newEdges = [];
  const hostNodeMap = /* @__PURE__ */ new Map();
  for (const node of existingNodes) {
    if (node.type === "computer" && node.properties?.ip) {
      hostNodeMap.set(node.properties.ip, node.id);
    }
  }
  const seenCVEs = /* @__PURE__ */ new Set();
  let tempId = existingNodes.length + 1e3;
  for (const vuln of vulnFindings) {
    if (!vuln.cveId || seenCVEs.has(vuln.cveId)) continue;
    seenCVEs.add(vuln.cveId);
    const vulnNodeId = tempId++;
    newNodes.push({
      type: "vulnerability",
      name: vuln.cveId,
      riskScore: vuln.cvssScore || 5,
      isCrownJewel: false,
      properties: {
        severity: vuln.severity,
        exploitAvailable: vuln.exploitAvailable,
        cvssScore: vuln.cvssScore
      }
    });
    if (vuln.hostIp && hostNodeMap.has(vuln.hostIp)) {
      const hostNodeId = hostNodeMap.get(vuln.hostIp);
      newEdges.push({
        sourceNodeId: vulnNodeId,
        targetNodeId: hostNodeId,
        edgeType: "exploits",
        technique: vuln.cveId,
        probability: vuln.exploitAvailable ? 0.8 : 0.3
      });
    }
  }
  return { newNodes, newEdges };
}
export {
  discoverAttackPaths,
  ingestVulnDataToGraph
};
