/**
 * Network Topology Builder — Graph Construction from Scan & PCAP Data
 * ═══════════════════════════════════════════════════════════════════
 * Parses discovery results, traceroute data, and PCAP conversations into
 * an interactive graph model showing discovered hosts, routes, traffic
 * flows, and security findings.
 *
 * Data Sources:
 *   1. discovery scan results → hosts, ports, services, OS fingerprints
 *   2. traceroute (Scapy) → network path hops between scanner and targets
 *   3. PCAP conversations → actual traffic flows with volume data
 *   4. PCAP findings → security annotations on edges/nodes
 *   5. Engagement assets → enriched metadata from passive recon
 *
 * Output: A graph model (nodes + edges) suitable for frontend rendering
 * with D3.js, Cytoscape.js, or similar visualization libraries.
 *
 * @module network-topology
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

export type NodeType =
  | "scanner"       // Our scan server
  | "target"        // Primary target host
  | "router"        // Intermediate hop (from traceroute)
  | "dns_server"    // DNS server seen in traffic
  | "external"      // External host seen in PCAP
  | "cdn"           // CDN/WAF node
  | "unknown";

export type NodeStatus =
  | "up"
  | "down"
  | "filtered"
  | "unknown";

export type EdgeType =
  | "scan_traffic"    // Scanner → target scan traffic
  | "route_hop"       // Traceroute hop
  | "tcp_stream"      // TCP conversation
  | "udp_flow"        // UDP traffic
  | "dns_query"       // DNS query/response
  | "http_request"    // HTTP traffic
  | "tls_handshake"   // TLS/SSL connection
  | "icmp"            // ICMP traffic
  | "arp"             // ARP traffic
  | "unknown";

export interface TopologyNode {
  /** Unique node ID (typically IP address) */
  id: string;
  /** Display label */
  label: string;
  /** Node type */
  type: NodeType;
  /** IP address */
  ip: string;
  /** Hostname (if resolved) */
  hostname?: string;
  /** MAC address (if known from ARP/PCAP) */
  mac?: string;
  /** Operating system (from ScanForge discovery fingerprint) */
  os?: string;
  /** Open ports */
  ports: Array<{
    port: number;
    service: string;
    version?: string;
    state: "open" | "filtered" | "closed";
  }>;
  /** Node status */
  status: NodeStatus;
  /** TTL hop distance from scanner (from traceroute) */
  hopDistance?: number;
  /** Total bytes sent/received */
  totalBytes: number;
  /** Total packets sent/received */
  totalPackets: number;
  /** Security findings associated with this node */
  findings: Array<{
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    category: string;
  }>;
  /** Metadata from engagement asset */
  metadata?: Record<string, any>;
  /** Visual properties */
  visual: {
    /** Size multiplier based on traffic volume */
    size: number;
    /** Color based on risk level */
    color: string;
    /** X position hint (for layout) */
    x?: number;
    /** Y position hint (for layout) */
    y?: number;
    /** Group/cluster ID */
    group?: string;
  };
}

export interface TopologyEdge {
  /** Unique edge ID */
  id: string;
  /** Source node ID */
  source: string;
  /** Target node ID */
  target: string;
  /** Edge type */
  type: EdgeType;
  /** Display label */
  label?: string;
  /** Protocol */
  protocol: string;
  /** Port (if applicable) */
  port?: number;
  /** Total bytes transferred */
  bytes: number;
  /** Total packets */
  packets: number;
  /** Whether this is bidirectional */
  bidirectional: boolean;
  /** Security findings on this edge */
  findings: Array<{
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
  }>;
  /** Visual properties */
  visual: {
    /** Width based on traffic volume */
    width: number;
    /** Color based on edge type/risk */
    color: string;
    /** Whether to show as dashed (filtered/blocked) */
    dashed: boolean;
    /** Animation speed (for active flows) */
    animated: boolean;
  };
}

export interface NetworkTopology {
  /** Topology ID */
  id: string;
  /** Engagement ID */
  engagementId: number;
  /** When this topology was built */
  builtAt: number;
  /** All nodes */
  nodes: TopologyNode[];
  /** All edges */
  edges: TopologyEdge[];
  /** Summary statistics */
  stats: {
    totalNodes: number;
    totalEdges: number;
    totalHosts: number;
    totalRouters: number;
    totalFindings: number;
    totalBytesObserved: number;
    protocols: string[];
    maxHopDistance: number;
  };
  /** Data sources used to build this topology */
  sources: Array<{
    type: "scanforge-discovery" | "traceroute" | "pcap" | "asset" | "dns";
    description: string;
    recordCount: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════
// §2 — COLOR & SIZING UTILITIES
// ═══════════════════════════════════════════════════════════════

const NODE_COLORS: Record<NodeType, string> = {
  scanner: "#3b82f6",    // blue
  target: "#ef4444",     // red
  router: "#8b5cf6",     // purple
  dns_server: "#f59e0b", // amber
  external: "#6b7280",   // gray
  cdn: "#06b6d4",        // cyan
  unknown: "#9ca3af",    // light gray
};

const EDGE_COLORS: Record<EdgeType, string> = {
  scan_traffic: "#ef4444",   // red
  route_hop: "#8b5cf6",      // purple
  tcp_stream: "#3b82f6",     // blue
  udp_flow: "#10b981",       // green
  dns_query: "#f59e0b",      // amber
  http_request: "#06b6d4",   // cyan
  tls_handshake: "#22c55e",  // green
  icmp: "#f97316",           // orange
  arp: "#a855f7",            // violet
  unknown: "#9ca3af",        // gray
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#6b7280",
};

function calculateNodeSize(totalBytes: number, maxBytes: number): number {
  if (maxBytes === 0) return 1;
  const ratio = totalBytes / maxBytes;
  return Math.max(0.5, Math.min(3, 0.5 + ratio * 2.5));
}

function calculateEdgeWidth(bytes: number, maxBytes: number): number {
  if (maxBytes === 0) return 1;
  const ratio = bytes / maxBytes;
  return Math.max(1, Math.min(8, 1 + ratio * 7));
}

function getNodeRiskColor(findings: TopologyNode["findings"]): string | null {
  if (findings.length === 0) return null;
  const severities = findings.map(f => f.severity);
  if (severities.includes("critical")) return SEVERITY_COLORS.critical;
  if (severities.includes("high")) return SEVERITY_COLORS.high;
  if (severities.includes("medium")) return SEVERITY_COLORS.medium;
  return null;
}

// ═══════════════════════════════════════════════════════════════
// §3 — TOPOLOGY BUILDER
// ═══════════════════════════════════════════════════════════════

/**
 * Build a network topology from engagement data.
 * Combines discovery results, traceroute data, PCAP conversations, and asset metadata.
 */
export function buildTopology(
  engagementId: number,
  data: {
    /** Scanner IP (our scan server) */
    scannerIp: string;
    /** discovery results per target */
    discoveryResults?: Array<{
      targetIp: string;
      targetHostname?: string;
      os?: string;
      ports: Array<{ port: number; service: string; version?: string; state?: string }>;
    }>;
    /** Traceroute hops */
    tracerouteHops?: Array<{
      targetIp: string;
      hops: Array<{ ttl: number; ip: string; rtt: number; hostname?: string }>;
    }>;
    /** PCAP conversations */
    pcapConversations?: Array<{
      srcAddr: string;
      dstAddr: string;
      protocol: string;
      packets: number;
      bytes: number;
      srcPort?: number;
      dstPort?: number;
    }>;
    /** PCAP security findings */
    pcapFindings?: Array<{
      srcIp?: string;
      dstIp?: string;
      severity: string;
      title: string;
      category: string;
    }>;
    /** Engagement assets with enriched metadata */
    assets?: Array<{
      hostname: string;
      ip?: string;
      type?: string;
      ports?: Array<{ port: number; service: string; version?: string }>;
      passiveRecon?: Record<string, any>;
    }>;
    /** DNS queries observed */
    dnsQueries?: Array<{
      queryName: string;
      serverIp: string;
      responseIps: string[];
    }>;
  },
): NetworkTopology {
  const nodeMap = new Map<string, TopologyNode>();
  const edges: TopologyEdge[] = [];
  let edgeCounter = 0;

  const genEdgeId = () => `edge-${++edgeCounter}`;

  // ── Helper: Get or create a node ──────────────────────────────
  function getOrCreateNode(ip: string, defaults?: Partial<TopologyNode>): TopologyNode {
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
          color: NODE_COLORS.unknown,
        },
        ...defaults,
      });
    }
    return nodeMap.get(ip)!;
  }

  // ── Step 1: Add scanner node ──────────────────────────────────
  const scannerNode = getOrCreateNode(data.scannerIp, {
    label: `Scanner (${data.scannerIp})`,
    type: "scanner",
    status: "up",
    visual: { size: 2, color: NODE_COLORS.scanner },
  });

  // ── Step 2: Process discovery results ──────────────────────────────
  const discoverySources: number = data.discoveryResults?.length || 0;
  if (data.discoveryResults) {
    for (const result of data.discoveryResults) {
      const node = getOrCreateNode(result.targetIp, {
        label: result.targetHostname || result.targetIp,
        type: "target",
        hostname: result.targetHostname,
        os: result.os,
        status: "up",
      });
      node.type = "target";
      node.status = "up";
      if (result.targetHostname) node.hostname = result.targetHostname;
      if (result.os) node.os = result.os;

      // Add ports
      for (const port of result.ports) {
        if (!node.ports.find(p => p.port === port.port)) {
          node.ports.push({
            port: port.port,
            service: port.service,
            version: port.version,
            state: (port.state as any) || "open",
          });
        }
      }

      // Add scan traffic edge
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
          animated: false,
        },
      });
    }
  }

  // ── Step 3: Process traceroute hops ───────────────────────────
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
          status: "up",
        });
        if (hopNode.type === "unknown") hopNode.type = "router";
        hopNode.hopDistance = hop.ttl;
        if (hop.ttl > maxHopDistance) maxHopDistance = hop.ttl;

        // Add route hop edge
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
            animated: false,
          },
        });

        prevIp = hop.ip;
      }
    }
  }

  // ── Step 4: Process PCAP conversations ────────────────────────
  if (data.pcapConversations) {
    for (const conv of data.pcapConversations) {
      const srcNode = getOrCreateNode(conv.srcAddr);
      const dstNode = getOrCreateNode(conv.dstAddr);

      srcNode.totalBytes += conv.bytes;
      srcNode.totalPackets += conv.packets;
      dstNode.totalBytes += conv.bytes;
      dstNode.totalPackets += conv.packets;

      // Determine edge type from protocol/port
      let edgeType: EdgeType = "tcp_stream";
      const proto = conv.protocol.toLowerCase();
      if (proto === "udp") edgeType = "udp_flow";
      else if (proto === "icmp") edgeType = "icmp";
      else if (proto === "arp") edgeType = "arp";

      // Refine by port
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
          animated: conv.packets > 100,
        },
      });
    }
  }

  // ── Step 5: Process PCAP findings ─────────────────────────────
  if (data.pcapFindings) {
    for (const finding of data.pcapFindings) {
      // Add to source node
      if (finding.srcIp) {
        const node = getOrCreateNode(finding.srcIp);
        node.findings.push({
          severity: finding.severity as any,
          title: finding.title,
          category: finding.category,
        });
      }
      // Add to destination node
      if (finding.dstIp) {
        const node = getOrCreateNode(finding.dstIp);
        node.findings.push({
          severity: finding.severity as any,
          title: finding.title,
          category: finding.category,
        });
      }
      // Add to matching edge
      if (finding.srcIp && finding.dstIp) {
        const edge = edges.find(
          e => (e.source === finding.srcIp && e.target === finding.dstIp) ||
               (e.source === finding.dstIp && e.target === finding.srcIp),
        );
        if (edge) {
          edge.findings.push({
            severity: finding.severity as any,
            title: finding.title,
          });
        }
      }
    }
  }

  // ── Step 6: Enrich from engagement assets ─────────────────────
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

      // Merge ports
      if (asset.ports) {
        for (const port of asset.ports) {
          if (!node.ports.find(p => p.port === port.port)) {
            node.ports.push({
              port: port.port,
              service: port.service,
              version: port.version,
              state: "open",
            });
          }
        }
      }

      // Check for CDN
      if (asset.passiveRecon?.cdn || asset.passiveRecon?.waf) {
        node.visual.group = "cdn_protected";
      }
    }
  }

  // ── Step 7: Process DNS queries ───────────────────────────────
  if (data.dnsQueries) {
    for (const query of data.dnsQueries) {
      const dnsNode = getOrCreateNode(query.serverIp, {
        type: "dns_server",
        label: `DNS (${query.serverIp})`,
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
          animated: false,
        },
      });
    }
  }

  // ── Step 8: Calculate visual properties ───────────────────────
  const allNodes = Array.from(nodeMap.values());
  const maxBytes = Math.max(...allNodes.map(n => n.totalBytes), 1);
  const maxEdgeBytes = Math.max(...edges.map(e => e.bytes), 1);

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

  // ── Step 9: Deduplicate edges ─────────────────────────────────
  const edgeKeys = new Map<string, TopologyEdge>();
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

  // ── Step 10: Build summary ────────────────────────────────────
  const allProtocols = new Set(dedupedEdges.map(e => e.protocol));
  const totalFindings = allNodes.reduce((sum, n) => sum + n.findings.length, 0);
  const totalBytesObserved = allNodes.reduce((sum, n) => sum + n.totalBytes, 0);

  const sources: NetworkTopology["sources"] = [];
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
      totalHosts: allNodes.filter(n => n.type === "target" || n.type === "external").length,
      totalRouters: allNodes.filter(n => n.type === "router").length,
      totalFindings,
      totalBytesObserved,
      protocols: Array.from(allProtocols),
      maxHopDistance,
    },
    sources,
  };
}

// ═══════════════════════════════════════════════════════════════
// §4 — TOPOLOGY FROM ENGAGEMENT STATE
// ═══════════════════════════════════════════════════════════════

/**
 * Build topology directly from an engagement's ops state.
 * Extracts discovery results, PCAP captures, and asset data from the state object.
 */
export function buildTopologyFromEngagement(
  engagementId: number,
  state: {
    assets: Array<{
      hostname: string;
      ip?: string;
      type?: string;
      ports?: Array<{ port: number; service: string; version?: string }>;
      passiveRecon?: Record<string, any>;
      toolResults?: Array<{
        tool: string;
        findings?: Array<{ type?: string; port?: number; service?: string; product?: string; version?: string }>;
        outputPreview?: string;
      }>;
      pcapCaptures?: Array<{
        sessionId: string;
        pcapPath: string;
        packetsCaptured: number;
        analysisSummary?: {
          totalPackets: number;
          protocols: string[];
          conversations: number;
          findings: number;
        };
      }>;
    }>;
    scanServerIp?: string;
  },
): NetworkTopology {
  const scannerIp = state.scanServerIp || "10.0.0.1";

  // Extract discovery results from asset tool results
  const discoveryResults = state.assets
    .filter(a => a.ip && a.ports && a.ports.length > 0)
    .map(a => ({
      targetIp: a.ip!,
      targetHostname: a.hostname,
      ports: (a.ports || []).map(p => ({
        port: p.port,
        service: p.service,
        version: p.version,
      })),
    }));

  return buildTopology(engagementId, {
    scannerIp,
    discoveryResults,
    assets: state.assets.map(a => ({
      hostname: a.hostname,
      ip: a.ip,
      type: a.type,
      ports: a.ports,
      passiveRecon: a.passiveRecon,
    })),
  });
}

// ═══════════════════════════════════════════════════════════════
// §5 — LIVE TOPOLOGY UPDATE
// ═══════════════════════════════════════════════════════════════

/** In-memory topology cache per engagement */
const topologyCache = new Map<number, NetworkTopology>();

/**
 * Get or build topology for an engagement.
 * Returns cached version if available, otherwise builds from scratch.
 */
export function getTopology(engagementId: number): NetworkTopology | null {
  return topologyCache.get(engagementId) || null;
}

/**
 * Update the cached topology for an engagement.
 */
export function setTopology(engagementId: number, topology: NetworkTopology): void {
  topologyCache.set(engagementId, topology);
}

/**
 * Merge new data into an existing topology.
 * Used for incremental updates as new scan data arrives.
 */
export function mergeIntoTopology(
  engagementId: number,
  newData: Parameters<typeof buildTopology>[1],
): NetworkTopology {
  const existing = topologyCache.get(engagementId);
  if (!existing) {
    const topology = buildTopology(engagementId, newData);
    topologyCache.set(engagementId, topology);
    return topology;
  }

  // Build new topology from the new data
  const newTopology = buildTopology(engagementId, newData);

  // Merge nodes
  const mergedNodes = new Map<string, TopologyNode>();
  for (const node of existing.nodes) mergedNodes.set(node.id, node);
  for (const node of newTopology.nodes) {
    const existingNode = mergedNodes.get(node.id);
    if (existingNode) {
      // Merge: keep richer data
      existingNode.totalBytes += node.totalBytes;
      existingNode.totalPackets += node.totalPackets;
      existingNode.findings.push(...node.findings);
      for (const port of node.ports) {
        if (!existingNode.ports.find(p => p.port === port.port)) {
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

  // Merge edges (simple append + dedup by key)
  const mergedEdges = [...existing.edges, ...newTopology.edges];
  const edgeKeys = new Map<string, TopologyEdge>();
  for (const edge of mergedEdges) {
    const key = `${edge.source}-${edge.target}-${edge.type}-${edge.port || ""}`;
    const existing = edgeKeys.get(key);
    if (existing) {
      existing.bytes += edge.bytes;
      existing.packets += edge.packets;
      existing.findings.push(...edge.findings);
    } else {
      edgeKeys.set(key, { ...edge });
    }
  }

  const merged: NetworkTopology = {
    ...existing,
    builtAt: Date.now(),
    nodes: Array.from(mergedNodes.values()),
    edges: Array.from(edgeKeys.values()),
    stats: {
      ...existing.stats,
      totalNodes: mergedNodes.size,
      totalEdges: edgeKeys.size,
    },
    sources: [...existing.sources, ...newTopology.sources.filter(
      s => !existing.sources.find(es => es.type === s.type),
    )],
  };

  topologyCache.set(engagementId, merged);
  return merged;
}

/**
 * Export topology as a simplified JSON for frontend rendering.
 * Strips internal metadata and keeps only what the visualization needs.
 */
export function exportTopologyForVisualization(topology: NetworkTopology): {
  nodes: Array<{
    id: string;
    label: string;
    type: NodeType;
    ip: string;
    hostname?: string;
    os?: string;
    ports: number[];
    services: string[];
    findingCount: number;
    maxSeverity: string;
    size: number;
    color: string;
    group?: string;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    type: EdgeType;
    label?: string;
    protocol: string;
    port?: number;
    bytes: number;
    packets: number;
    findingCount: number;
    width: number;
    color: string;
    dashed: boolean;
    animated: boolean;
  }>;
  stats: NetworkTopology["stats"];
} {
  return {
    nodes: topology.nodes.map(n => ({
      id: n.id,
      label: n.label,
      type: n.type,
      ip: n.ip,
      hostname: n.hostname,
      os: n.os,
      ports: n.ports.map(p => p.port),
      services: n.ports.map(p => p.service),
      findingCount: n.findings.length,
      maxSeverity: n.findings.length > 0
        ? n.findings.reduce((max, f) => {
            const order = ["critical", "high", "medium", "low", "info"];
            return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max;
          }, "info")
        : "none",
      size: n.visual.size,
      color: n.visual.color,
      group: n.visual.group,
    })),
    edges: topology.edges.map(e => ({
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
      animated: e.visual.animated,
    })),
    stats: topology.stats,
  };
}
