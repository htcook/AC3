import "./chunk-KFQGP6VL.js";

// server/lib/network-topology.ts
var NODE_COLORS = {
  scanner: "#3b82f6",
  // blue
  target: "#ef4444",
  // red
  router: "#8b5cf6",
  // purple
  dns_server: "#f59e0b",
  // amber
  external: "#6b7280",
  // gray
  cdn: "#06b6d4",
  // cyan
  unknown: "#9ca3af"
  // light gray
};
var EDGE_COLORS = {
  scan_traffic: "#ef4444",
  // red
  route_hop: "#8b5cf6",
  // purple
  tcp_stream: "#3b82f6",
  // blue
  udp_flow: "#10b981",
  // green
  dns_query: "#f59e0b",
  // amber
  http_request: "#06b6d4",
  // cyan
  tls_handshake: "#22c55e",
  // green
  icmp: "#f97316",
  // orange
  arp: "#a855f7",
  // violet
  unknown: "#9ca3af"
  // gray
};
var SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#6b7280"
};
function calculateNodeSize(totalBytes, maxBytes) {
  if (maxBytes === 0) return 1;
  const ratio = totalBytes / maxBytes;
  return Math.max(0.5, Math.min(3, 0.5 + ratio * 2.5));
}
function calculateEdgeWidth(bytes, maxBytes) {
  if (maxBytes === 0) return 1;
  const ratio = bytes / maxBytes;
  return Math.max(1, Math.min(8, 1 + ratio * 7));
}
function getNodeRiskColor(findings) {
  if (findings.length === 0) return null;
  const severities = findings.map((f) => f.severity);
  if (severities.includes("critical")) return SEVERITY_COLORS.critical;
  if (severities.includes("high")) return SEVERITY_COLORS.high;
  if (severities.includes("medium")) return SEVERITY_COLORS.medium;
  return null;
}
function buildTopology(engagementId, data) {
  const nodeMap = /* @__PURE__ */ new Map();
  const edges = [];
  let edgeCounter = 0;
  const genEdgeId = () => `edge-${++edgeCounter}`;
  function getOrCreateNode(ip, defaults) {
    if (!nodeMap.has(ip)) {
      nodeMap.set(ip, {
        id: ip,
        label: ip,
        type: "unknown",
        ip,
        ports: [],
        status: "unknown",
        totalBytes: 0,
        totalPackets: 0,
        findings: [],
        visual: {
          size: 1,
          color: NODE_COLORS.unknown
        },
        ...defaults
      });
    }
    return nodeMap.get(ip);
  }
  const scannerNode = getOrCreateNode(data.scannerIp, {
    label: `Scanner (${data.scannerIp})`,
    type: "scanner",
    status: "up",
    visual: { size: 2, color: NODE_COLORS.scanner }
  });
  const discoverySources = data.discoveryResults?.length || 0;
  if (data.discoveryResults) {
    for (const result of data.discoveryResults) {
      const node = getOrCreateNode(result.targetIp, {
        label: result.targetHostname || result.targetIp,
        type: "target",
        hostname: result.targetHostname,
        os: result.os,
        status: "up"
      });
      node.type = "target";
      node.status = "up";
      if (result.targetHostname) node.hostname = result.targetHostname;
      if (result.os) node.os = result.os;
      for (const port of result.ports) {
        if (!node.ports.find((p) => p.port === port.port)) {
          node.ports.push({
            port: port.port,
            service: port.service,
            version: port.version,
            state: port.state || "open"
          });
        }
      }
      edges.push({
        id: genEdgeId(),
        source: data.scannerIp,
        target: result.targetIp,
        type: "scan_traffic",
        label: `discovery scan (${result.ports.length} ports)`,
        protocol: "tcp",
        bytes: 0,
        packets: 0,
        bidirectional: true,
        findings: [],
        visual: {
          width: 2,
          color: EDGE_COLORS.scan_traffic,
          dashed: false,
          animated: false
        }
      });
    }
  }
  let maxHopDistance = 0;
  if (data.tracerouteHops) {
    for (const trace of data.tracerouteHops) {
      let prevIp = data.scannerIp;
      for (const hop of trace.hops) {
        if (hop.ip === "*" || !hop.ip) continue;
        const hopNode = getOrCreateNode(hop.ip, {
          label: hop.hostname || hop.ip,
          type: "router",
          hostname: hop.hostname,
          hopDistance: hop.ttl,
          status: "up"
        });
        if (hopNode.type === "unknown") hopNode.type = "router";
        hopNode.hopDistance = hop.ttl;
        if (hop.ttl > maxHopDistance) maxHopDistance = hop.ttl;
        edges.push({
          id: genEdgeId(),
          source: prevIp,
          target: hop.ip,
          type: "route_hop",
          label: `TTL ${hop.ttl} (${hop.rtt.toFixed(1)}ms)`,
          protocol: "icmp",
          bytes: 0,
          packets: 1,
          bidirectional: false,
          findings: [],
          visual: {
            width: 1.5,
            color: EDGE_COLORS.route_hop,
            dashed: true,
            animated: false
          }
        });
        prevIp = hop.ip;
      }
    }
  }
  if (data.pcapConversations) {
    for (const conv of data.pcapConversations) {
      const srcNode = getOrCreateNode(conv.srcAddr);
      const dstNode = getOrCreateNode(conv.dstAddr);
      srcNode.totalBytes += conv.bytes;
      srcNode.totalPackets += conv.packets;
      dstNode.totalBytes += conv.bytes;
      dstNode.totalPackets += conv.packets;
      let edgeType = "tcp_stream";
      const proto = conv.protocol.toLowerCase();
      if (proto === "udp") edgeType = "udp_flow";
      else if (proto === "icmp") edgeType = "icmp";
      else if (proto === "arp") edgeType = "arp";
      if (conv.dstPort === 53 || conv.srcPort === 53) {
        edgeType = "dns_query";
        if (dstNode.type === "unknown") dstNode.type = "dns_server";
      } else if (conv.dstPort === 80 || conv.dstPort === 8080) {
        edgeType = "http_request";
      } else if (conv.dstPort === 443 || conv.dstPort === 8443) {
        edgeType = "tls_handshake";
      }
      edges.push({
        id: genEdgeId(),
        source: conv.srcAddr,
        target: conv.dstAddr,
        type: edgeType,
        label: conv.dstPort ? `${conv.protocol}/${conv.dstPort}` : conv.protocol,
        protocol: conv.protocol,
        port: conv.dstPort,
        bytes: conv.bytes,
        packets: conv.packets,
        bidirectional: true,
        findings: [],
        visual: {
          width: 1,
          color: EDGE_COLORS[edgeType] || EDGE_COLORS.unknown,
          dashed: false,
          animated: conv.packets > 100
        }
      });
    }
  }
  if (data.pcapFindings) {
    for (const finding of data.pcapFindings) {
      if (finding.srcIp) {
        const node = getOrCreateNode(finding.srcIp);
        node.findings.push({
          severity: finding.severity,
          title: finding.title,
          category: finding.category
        });
      }
      if (finding.dstIp) {
        const node = getOrCreateNode(finding.dstIp);
        node.findings.push({
          severity: finding.severity,
          title: finding.title,
          category: finding.category
        });
      }
      if (finding.srcIp && finding.dstIp) {
        const edge = edges.find(
          (e) => e.source === finding.srcIp && e.target === finding.dstIp || e.source === finding.dstIp && e.target === finding.srcIp
        );
        if (edge) {
          edge.findings.push({
            severity: finding.severity,
            title: finding.title
          });
        }
      }
    }
  }
  if (data.assets) {
    for (const asset of data.assets) {
      const ip = asset.ip;
      if (!ip) continue;
      const node = nodeMap.get(ip);
      if (!node) continue;
      node.hostname = node.hostname || asset.hostname;
      node.label = asset.hostname || node.label;
      node.type = "target";
      node.metadata = asset.passiveRecon;
      if (asset.ports) {
        for (const port of asset.ports) {
          if (!node.ports.find((p) => p.port === port.port)) {
            node.ports.push({
              port: port.port,
              service: port.service,
              version: port.version,
              state: "open"
            });
          }
        }
      }
      if (asset.passiveRecon?.cdn || asset.passiveRecon?.waf) {
        node.visual.group = "cdn_protected";
      }
    }
  }
  if (data.dnsQueries) {
    for (const query of data.dnsQueries) {
      const dnsNode = getOrCreateNode(query.serverIp, {
        type: "dns_server",
        label: `DNS (${query.serverIp})`
      });
      if (dnsNode.type === "unknown") dnsNode.type = "dns_server";
      edges.push({
        id: genEdgeId(),
        source: data.scannerIp,
        target: query.serverIp,
        type: "dns_query",
        label: query.queryName,
        protocol: "dns",
        port: 53,
        bytes: 0,
        packets: 1,
        bidirectional: true,
        findings: [],
        visual: {
          width: 1,
          color: EDGE_COLORS.dns_query,
          dashed: true,
          animated: false
        }
      });
    }
  }
  const allNodes = Array.from(nodeMap.values());
  const maxBytes = Math.max(...allNodes.map((n) => n.totalBytes), 1);
  const maxEdgeBytes = Math.max(...edges.map((e) => e.bytes), 1);
  for (const node of allNodes) {
    node.visual.size = calculateNodeSize(node.totalBytes, maxBytes);
    const riskColor = getNodeRiskColor(node.findings);
    node.visual.color = riskColor || NODE_COLORS[node.type] || NODE_COLORS.unknown;
  }
  for (const edge of edges) {
    edge.visual.width = calculateEdgeWidth(edge.bytes, maxEdgeBytes);
    if (edge.findings.length > 0) {
      const maxSev = edge.findings.reduce((max, f) => {
        const order = ["critical", "high", "medium", "low", "info"];
        return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max;
      }, "info");
      edge.visual.color = SEVERITY_COLORS[maxSev] || edge.visual.color;
    }
  }
  const edgeKeys = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    const key = `${edge.source}-${edge.target}-${edge.type}-${edge.port || ""}`;
    const reverseKey = `${edge.target}-${edge.source}-${edge.type}-${edge.port || ""}`;
    const existing = edgeKeys.get(key) || edgeKeys.get(reverseKey);
    if (existing) {
      existing.bytes += edge.bytes;
      existing.packets += edge.packets;
      existing.findings.push(...edge.findings);
      existing.bidirectional = true;
    } else {
      edgeKeys.set(key, edge);
    }
  }
  const dedupedEdges = Array.from(edgeKeys.values());
  const allProtocols = new Set(dedupedEdges.map((e) => e.protocol));
  const totalFindings = allNodes.reduce((sum, n) => sum + n.findings.length, 0);
  const totalBytesObserved = allNodes.reduce((sum, n) => sum + n.totalBytes, 0);
  const sources = [];
  if (discoverySources > 0) sources.push({ type: "scanforge-discovery", description: "Port scan results", recordCount: discoverySources });
  if (data.tracerouteHops?.length) sources.push({ type: "traceroute", description: "Network path hops", recordCount: data.tracerouteHops.length });
  if (data.pcapConversations?.length) sources.push({ type: "pcap", description: "Packet capture conversations", recordCount: data.pcapConversations.length });
  if (data.assets?.length) sources.push({ type: "asset", description: "Engagement asset metadata", recordCount: data.assets.length });
  if (data.dnsQueries?.length) sources.push({ type: "dns", description: "DNS query observations", recordCount: data.dnsQueries.length });
  return {
    id: `topology-${engagementId}-${Date.now()}`,
    engagementId,
    builtAt: Date.now(),
    nodes: allNodes,
    edges: dedupedEdges,
    stats: {
      totalNodes: allNodes.length,
      totalEdges: dedupedEdges.length,
      totalHosts: allNodes.filter((n) => n.type === "target" || n.type === "external").length,
      totalRouters: allNodes.filter((n) => n.type === "router").length,
      totalFindings,
      totalBytesObserved,
      protocols: Array.from(allProtocols),
      maxHopDistance
    },
    sources
  };
}
function buildTopologyFromEngagement(engagementId, state) {
  const scannerIp = state.scanServerIp || "10.0.0.1";
  const discoveryResults = state.assets.filter((a) => a.ip && a.ports && a.ports.length > 0).map((a) => ({
    targetIp: a.ip,
    targetHostname: a.hostname,
    ports: (a.ports || []).map((p) => ({
      port: p.port,
      service: p.service,
      version: p.version
    }))
  }));
  return buildTopology(engagementId, {
    scannerIp,
    discoveryResults,
    assets: state.assets.map((a) => ({
      hostname: a.hostname,
      ip: a.ip,
      type: a.type,
      ports: a.ports,
      passiveRecon: a.passiveRecon
    }))
  });
}
var topologyCache = /* @__PURE__ */ new Map();
function getTopology(engagementId) {
  return topologyCache.get(engagementId) || null;
}
function setTopology(engagementId, topology) {
  topologyCache.set(engagementId, topology);
}
function mergeIntoTopology(engagementId, newData) {
  const existing = topologyCache.get(engagementId);
  if (!existing) {
    const topology = buildTopology(engagementId, newData);
    topologyCache.set(engagementId, topology);
    return topology;
  }
  const newTopology = buildTopology(engagementId, newData);
  const mergedNodes = /* @__PURE__ */ new Map();
  for (const node of existing.nodes) mergedNodes.set(node.id, node);
  for (const node of newTopology.nodes) {
    const existingNode = mergedNodes.get(node.id);
    if (existingNode) {
      existingNode.totalBytes += node.totalBytes;
      existingNode.totalPackets += node.totalPackets;
      existingNode.findings.push(...node.findings);
      for (const port of node.ports) {
        if (!existingNode.ports.find((p) => p.port === port.port)) {
          existingNode.ports.push(port);
        }
      }
      if (node.hostname && !existingNode.hostname) existingNode.hostname = node.hostname;
      if (node.os && !existingNode.os) existingNode.os = node.os;
      if (node.type !== "unknown") existingNode.type = node.type;
    } else {
      mergedNodes.set(node.id, node);
    }
  }
  const mergedEdges = [...existing.edges, ...newTopology.edges];
  const edgeKeys = /* @__PURE__ */ new Map();
  for (const edge of mergedEdges) {
    const key = `${edge.source}-${edge.target}-${edge.type}-${edge.port || ""}`;
    const existing2 = edgeKeys.get(key);
    if (existing2) {
      existing2.bytes += edge.bytes;
      existing2.packets += edge.packets;
      existing2.findings.push(...edge.findings);
    } else {
      edgeKeys.set(key, { ...edge });
    }
  }
  const merged = {
    ...existing,
    builtAt: Date.now(),
    nodes: Array.from(mergedNodes.values()),
    edges: Array.from(edgeKeys.values()),
    stats: {
      ...existing.stats,
      totalNodes: mergedNodes.size,
      totalEdges: edgeKeys.size
    },
    sources: [...existing.sources, ...newTopology.sources.filter(
      (s) => !existing.sources.find((es) => es.type === s.type)
    )]
  };
  topologyCache.set(engagementId, merged);
  return merged;
}
function exportTopologyForVisualization(topology) {
  return {
    nodes: topology.nodes.map((n) => ({
      id: n.id,
      label: n.label,
      type: n.type,
      ip: n.ip,
      hostname: n.hostname,
      os: n.os,
      ports: n.ports.map((p) => p.port),
      services: n.ports.map((p) => p.service),
      findingCount: n.findings.length,
      maxSeverity: n.findings.length > 0 ? n.findings.reduce((max, f) => {
        const order = ["critical", "high", "medium", "low", "info"];
        return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max;
      }, "info") : "none",
      size: n.visual.size,
      color: n.visual.color,
      group: n.visual.group
    })),
    edges: topology.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: e.type,
      label: e.label,
      protocol: e.protocol,
      port: e.port,
      bytes: e.bytes,
      packets: e.packets,
      findingCount: e.findings.length,
      width: e.visual.width,
      color: e.visual.color,
      dashed: e.visual.dashed,
      animated: e.visual.animated
    })),
    stats: topology.stats
  };
}
export {
  buildTopology,
  buildTopologyFromEngagement,
  exportTopologyForVisualization,
  getTopology,
  mergeIntoTopology,
  setTopology
};
