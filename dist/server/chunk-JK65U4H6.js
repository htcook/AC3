// server/lib/ad-attack-path-graph.ts
var EDGE_WEIGHTS = {
  memberOf: 1,
  adminTo: 2,
  canRDP: 3,
  canPsRemote: 3,
  hasSession: 2,
  trustedBy: 4,
  gpLink: 5,
  contains: 1,
  dcsync: 1,
  kerberoastable: 3,
  asrepRoastable: 2,
  delegateTo: 3,
  writeDacl: 2,
  genericAll: 1,
  forceChangePassword: 2,
  addMember: 2,
  owns: 1
};
var HIGH_VALUE_GROUPS = [
  "domain admins",
  "enterprise admins",
  "schema admins",
  "administrators",
  "account operators",
  "backup operators",
  "server operators",
  "print operators",
  "dnsadmins",
  "group policy creator owners"
];
var HIGH_VALUE_PATTERNS = [
  /domain controller/i,
  /exchange server/i,
  /sql server/i,
  /certificate authority/i,
  /adfs/i,
  /azure ad connect/i
];
function buildGraphFromADObjects(users, groups, computers, gpos, ous, trusts) {
  const nodes = [];
  const edges = [];
  let edgeCounter = 0;
  for (const user of users) {
    const dn = user.distinguishedName || user.samAccountName || `user-${user.id || Math.random()}`;
    nodes.push({
      id: dn,
      label: user.displayName || user.samAccountName || dn,
      type: user.isPrivileged ? "service_account" : "user",
      isHighValue: user.isPrivileged || false,
      isCompromised: false,
      isEnabled: user.isEnabled !== false,
      riskScore: calculateNodeRisk(user),
      properties: {
        samAccountName: user.samAccountName,
        spn: user.properties?.servicePrincipalName,
        kerberoastable: user.properties?.kerberoastable,
        asrepRoastable: user.properties?.asrepRoastable,
        adminCount: user.properties?.adminCount,
        lastLogon: user.properties?.lastLogon
      }
    });
    if (user.memberOf && Array.isArray(user.memberOf)) {
      for (const groupDn of user.memberOf) {
        edges.push({
          id: `edge-${edgeCounter++}`,
          source: dn,
          target: groupDn,
          type: "memberOf",
          weight: EDGE_WEIGHTS.memberOf,
          isExploitable: true,
          properties: {}
        });
      }
    }
    if (user.properties?.kerberoastable) {
      edges.push({
        id: `edge-${edgeCounter++}`,
        source: dn,
        target: dn,
        type: "kerberoastable",
        weight: EDGE_WEIGHTS.kerberoastable,
        isExploitable: true,
        properties: { technique: "Kerberoasting" }
      });
    }
    if (user.properties?.asrepRoastable) {
      edges.push({
        id: `edge-${edgeCounter++}`,
        source: dn,
        target: dn,
        type: "asrepRoastable",
        weight: EDGE_WEIGHTS.asrepRoastable,
        isExploitable: true,
        properties: { technique: "AS-REP Roasting" }
      });
    }
  }
  for (const group of groups) {
    const dn = group.distinguishedName || group.samAccountName || `group-${group.id || Math.random()}`;
    const isHV = HIGH_VALUE_GROUPS.some((hvg) => (group.samAccountName || "").toLowerCase().includes(hvg));
    nodes.push({
      id: dn,
      label: group.displayName || group.samAccountName || dn,
      type: "group",
      isHighValue: isHV || group.isPrivileged || false,
      isCompromised: false,
      isEnabled: true,
      riskScore: isHV ? 90 : 30,
      properties: {
        samAccountName: group.samAccountName,
        memberCount: group.members?.length || 0
      }
    });
    if (group.members && Array.isArray(group.members)) {
      for (const memberDn of group.members) {
        edges.push({
          id: `edge-${edgeCounter++}`,
          source: memberDn,
          target: dn,
          type: "memberOf",
          weight: EDGE_WEIGHTS.memberOf,
          isExploitable: true,
          properties: {}
        });
      }
    }
  }
  for (const computer of computers) {
    const dn = computer.distinguishedName || computer.samAccountName || `computer-${computer.id || Math.random()}`;
    const isDC = computer.properties?.isDomainController || (computer.samAccountName || "").toUpperCase().includes("DC");
    const isHV = isDC || HIGH_VALUE_PATTERNS.some((p) => p.test(computer.displayName || computer.samAccountName || ""));
    nodes.push({
      id: dn,
      label: computer.displayName || computer.samAccountName || dn,
      type: isDC ? "dc" : "computer",
      isHighValue: isHV,
      isCompromised: false,
      isEnabled: computer.isEnabled !== false,
      riskScore: isDC ? 100 : isHV ? 80 : 20,
      properties: {
        os: computer.properties?.operatingSystem,
        isDC,
        laps: computer.properties?.lapsEnabled
      }
    });
  }
  for (const gpo of gpos) {
    const dn = gpo.distinguishedName || `gpo-${gpo.id || Math.random()}`;
    nodes.push({
      id: dn,
      label: gpo.displayName || dn,
      type: "gpo",
      isHighValue: false,
      isCompromised: false,
      isEnabled: true,
      riskScore: 10,
      properties: { gpoStatus: gpo.properties?.gpoStatus }
    });
  }
  for (const ou of ous) {
    const dn = ou.distinguishedName || `ou-${ou.id || Math.random()}`;
    nodes.push({
      id: dn,
      label: ou.displayName || dn,
      type: "ou",
      isHighValue: false,
      isCompromised: false,
      isEnabled: true,
      riskScore: 5,
      properties: {}
    });
  }
  for (const trust of trusts) {
    const sourceDn = trust.sourceDomain || trust.distinguishedName || `trust-source-${trust.id}`;
    const targetDn = trust.targetDomain || `trust-target-${trust.id}`;
    if (!nodes.find((n) => n.id === sourceDn)) {
      nodes.push({
        id: sourceDn,
        label: sourceDn,
        type: "domain",
        isHighValue: true,
        isCompromised: false,
        isEnabled: true,
        riskScore: 70,
        properties: { trustType: trust.properties?.trustType }
      });
    }
    if (!nodes.find((n) => n.id === targetDn)) {
      nodes.push({
        id: targetDn,
        label: targetDn,
        type: "domain",
        isHighValue: true,
        isCompromised: false,
        isEnabled: true,
        riskScore: 70,
        properties: { trustType: trust.properties?.trustType }
      });
    }
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: sourceDn,
      target: targetDn,
      type: "trustedBy",
      weight: EDGE_WEIGHTS.trustedBy,
      isExploitable: !trust.properties?.sidFiltering,
      properties: {
        trustDirection: trust.properties?.trustDirection,
        trustType: trust.properties?.trustType,
        isTransitive: trust.properties?.isTransitive
      }
    });
  }
  return { nodes, edges };
}
function findAttackPaths(nodes, edges, sourceNodeId, maxDepth = 10) {
  const paths = [];
  const highValueTargets = nodes.filter((n) => n.isHighValue).map((n) => n.id);
  const adjacency = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push({ targetId: edge.target, edge });
  }
  const queue = [];
  queue.push({
    nodeId: sourceNodeId,
    path: [sourceNodeId],
    edgePath: [],
    weight: 0,
    techniques: /* @__PURE__ */ new Set(),
    depth: 0
  });
  const visited = /* @__PURE__ */ new Set();
  let pathCounter = 0;
  while (queue.length > 0 && pathCounter < 50) {
    const current = queue.shift();
    if (current.depth > maxDepth) continue;
    if (current.nodeId !== sourceNodeId && highValueTargets.includes(current.nodeId)) {
      paths.push({
        id: `path-${pathCounter++}`,
        nodes: current.path,
        edges: current.edgePath,
        totalWeight: current.weight,
        hops: current.path.length - 1,
        techniques: Array.from(current.techniques),
        riskLevel: calculatePathRisk(current.weight, current.path.length - 1)
      });
      continue;
    }
    const neighbors = adjacency.get(current.nodeId) || [];
    for (const { targetId, edge } of neighbors) {
      if (current.path.includes(targetId)) continue;
      if (!edge.isExploitable) continue;
      const techniques = new Set(current.techniques);
      if (edge.type === "kerberoastable") techniques.add("Kerberoasting");
      if (edge.type === "asrepRoastable") techniques.add("AS-REP Roasting");
      if (edge.type === "dcsync") techniques.add("DCSync");
      if (edge.type === "adminTo") techniques.add("Local Admin");
      if (edge.type === "canRDP") techniques.add("RDP Access");
      if (edge.type === "delegateTo") techniques.add("Delegation Abuse");
      if (edge.type === "writeDacl") techniques.add("DACL Abuse");
      if (edge.type === "genericAll") techniques.add("GenericAll Abuse");
      if (edge.type === "forceChangePassword") techniques.add("Password Reset");
      if (edge.type === "addMember") techniques.add("Group Modification");
      if (edge.type === "trustedBy") techniques.add("Trust Exploitation");
      queue.push({
        nodeId: targetId,
        path: [...current.path, targetId],
        edgePath: [...current.edgePath, edge.id],
        weight: current.weight + edge.weight,
        techniques,
        depth: current.depth + 1
      });
    }
  }
  paths.sort((a, b) => a.totalWeight - b.totalWeight);
  return paths;
}
function findShortestPath(nodes, edges, sourceId, targetId) {
  const adjacency = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push({ targetId: edge.target, edge });
  }
  const queue = [];
  queue.push({ nodeId: sourceId, path: [sourceId], edgePath: [], weight: 0, techniques: /* @__PURE__ */ new Set() });
  const visited = /* @__PURE__ */ new Set();
  while (queue.length > 0) {
    const current = queue.shift();
    if (current.nodeId === targetId) {
      return {
        id: "shortest-path",
        nodes: current.path,
        edges: current.edgePath,
        totalWeight: current.weight,
        hops: current.path.length - 1,
        techniques: Array.from(current.techniques),
        riskLevel: calculatePathRisk(current.weight, current.path.length - 1)
      };
    }
    if (visited.has(current.nodeId)) continue;
    visited.add(current.nodeId);
    const neighbors = adjacency.get(current.nodeId) || [];
    for (const { targetId: nextId, edge } of neighbors) {
      if (visited.has(nextId)) continue;
      if (!edge.isExploitable) continue;
      const techniques = new Set(current.techniques);
      techniques.add(edge.type);
      queue.push({
        nodeId: nextId,
        path: [...current.path, nextId],
        edgePath: [...current.edgePath, edge.id],
        weight: current.weight + edge.weight,
        techniques
      });
    }
  }
  return null;
}
function assignLayers(nodes, edges) {
  const adjacency = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push(edge.target);
  }
  const startNodes = nodes.filter((n) => n.isCompromised);
  const queue = startNodes.length > 0 ? startNodes.map((n) => ({ id: n.id, layer: 0 })) : [{ id: nodes[0]?.id, layer: 0 }];
  const layerMap = /* @__PURE__ */ new Map();
  for (const item of queue) {
    if (item.id) layerMap.set(item.id, item.layer);
  }
  while (queue.length > 0) {
    const current = queue.shift();
    const neighbors = adjacency.get(current.id) || [];
    for (const neighborId of neighbors) {
      if (!layerMap.has(neighborId)) {
        layerMap.set(neighborId, current.layer + 1);
        queue.push({ id: neighborId, layer: current.layer + 1 });
      }
    }
  }
  const maxLayer = Math.max(0, ...Array.from(layerMap.values()));
  for (const node of nodes) {
    if (!layerMap.has(node.id)) {
      layerMap.set(node.id, maxLayer + 1);
    }
  }
  const layerCounts = /* @__PURE__ */ new Map();
  const layerPositions = /* @__PURE__ */ new Map();
  for (const [, layer] of Array.from(layerMap.entries())) {
    layerCounts.set(layer, (layerCounts.get(layer) || 0) + 1);
    layerPositions.set(layer, 0);
  }
  return nodes.map((node) => {
    const layer = layerMap.get(node.id) || 0;
    const posInLayer = layerPositions.get(layer) || 0;
    const totalInLayer = layerCounts.get(layer) || 1;
    layerPositions.set(layer, posInLayer + 1);
    return {
      ...node,
      layer,
      x: (posInLayer + 0.5) * (1e3 / totalInLayer),
      y: layer * 150 + 50
    };
  });
}
function calculateNodeRisk(obj) {
  let risk = 10;
  if (obj.isPrivileged) risk += 40;
  if (obj.properties?.kerberoastable) risk += 20;
  if (obj.properties?.asrepRoastable) risk += 15;
  if (obj.properties?.adminCount) risk += 25;
  if (obj.isEnabled === false) risk -= 10;
  return Math.min(100, Math.max(0, risk));
}
function calculatePathRisk(weight, hops) {
  const score = weight / Math.max(1, hops);
  if (score <= 2) return "critical";
  if (score <= 3) return "high";
  if (score <= 5) return "medium";
  return "low";
}
function buildAttackGraph(users, groups, computers, gpos, ous, trusts, sourceNodeId) {
  const { nodes: rawNodes, edges } = buildGraphFromADObjects(users, groups, computers, gpos, ous, trusts);
  const nodes = assignLayers(rawNodes, edges);
  let paths = [];
  if (sourceNodeId) {
    paths = findAttackPaths(nodes, edges, sourceNodeId);
  } else {
    const sourceUsers = nodes.filter((n) => n.type === "user" && !n.isHighValue).slice(0, 10);
    for (const user of sourceUsers) {
      const userPaths = findAttackPaths(nodes, edges, user.id, 6);
      paths.push(...userPaths);
    }
    paths.sort((a, b) => a.totalWeight - b.totalWeight);
    paths = paths.slice(0, 50);
  }
  const highValueTargets = nodes.filter((n) => n.isHighValue).length;
  const compromisedNodes = nodes.filter((n) => n.isCompromised).length;
  const shortestToDA = paths.length > 0 ? paths[0].hops : null;
  const avgPathLength = paths.length > 0 ? paths.reduce((sum, p) => sum + p.hops, 0) / paths.length : 0;
  return {
    nodes,
    edges,
    paths,
    stats: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      highValueTargets,
      compromisedNodes,
      shortestPathToDA: shortestToDA,
      totalAttackPaths: paths.length,
      avgPathLength: Math.round(avgPathLength * 10) / 10,
      maxRiskScore: Math.max(0, ...nodes.map((n) => n.riskScore))
    }
  };
}

export {
  EDGE_WEIGHTS,
  buildGraphFromADObjects,
  findAttackPaths,
  findShortestPath,
  assignLayers,
  buildAttackGraph
};
