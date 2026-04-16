/**
 * Battlespace Data Transformer
 * ═══════════════════════════════════════════════════════════════════════
 * Converts tRPC endpoint data into BattlespaceGraphData for the visualization engine.
 * Supports both engagement attack graph data and DI scan data.
 */
import type {
  BattlespaceNode,
  BattlespaceEdge,
  BattlespaceGraphData,
  BattlespaceNodeType,
  BattlespaceEdgeType,
  SeverityLevel,
  PlatformType,
  ProtocolType,
  KillChainPhase,
} from "./battlespace-types";

// ── Proxy / CDN / LB Detection Heuristics ─────────────────────────
const PROXY_SIGNATURES: Array<{ pattern: RegExp; vendor: string; role: BattlespaceNode["proxyRole"] }> = [
  { pattern: /nginx/i, vendor: "nginx", role: "reverse_proxy" },
  { pattern: /haproxy/i, vendor: "HAProxy", role: "load_balancer" },
  { pattern: /cloudflare/i, vendor: "Cloudflare", role: "cdn" },
  { pattern: /akamai/i, vendor: "Akamai", role: "cdn" },
  { pattern: /aws.?(?:alb|elb|cloudfront)/i, vendor: "AWS", role: "load_balancer" },
  { pattern: /azure.?(?:front.?door|app.?gateway|cdn)/i, vendor: "Azure", role: "cdn" },
  { pattern: /varnish/i, vendor: "Varnish", role: "reverse_proxy" },
  { pattern: /traefik/i, vendor: "Traefik", role: "reverse_proxy" },
  { pattern: /envoy/i, vendor: "Envoy", role: "reverse_proxy" },
  { pattern: /f5.?big.?ip/i, vendor: "F5 BIG-IP", role: "load_balancer" },
  { pattern: /imperva|incapsula/i, vendor: "Imperva", role: "waf_inline" },
  { pattern: /sucuri/i, vendor: "Sucuri", role: "waf_inline" },
  { pattern: /fastly/i, vendor: "Fastly", role: "cdn" },
  { pattern: /kong/i, vendor: "Kong", role: "reverse_proxy" },
  { pattern: /apache.?traffic.?server|ats/i, vendor: "Apache TS", role: "reverse_proxy" },
  { pattern: /squid/i, vendor: "Squid", role: "reverse_proxy" },
  { pattern: /caddy/i, vendor: "Caddy", role: "reverse_proxy" },
];

/** Detect if a technology/service string matches a known proxy */
function detectProxy(tech: any): { vendor: string; role: BattlespaceNode["proxyRole"] } | null {
  const t = String(tech || "");
  if (!t) return null;
  for (const sig of PROXY_SIGNATURES) {
    if (sig.pattern.test(t)) return { vendor: sig.vendor, role: sig.role };
  }
  return null;
}

/** Detect blue team interception indicators from asset data */
function detectInterception(asset: any): Array<{
  tapType: BattlespaceNode["tapType"];
  interceptedBy: string;
  evidence: string;
}> {
  const taps: Array<{ tapType: BattlespaceNode["tapType"]; interceptedBy: string; evidence: string }> = [];
  const waf = asset.wafDetected || asset.passiveRecon?.wafDetected;
  const techs = (asset.technologies || asset.passiveRecon?.technologies || []).map((t: any) => typeof t === "string" ? t : t.name || "");
  const allText = [String(waf || ""), ...techs, String(asset.hostname || ""), JSON.stringify(asset.passiveRecon?.riskSignals || [])].join(" ").toLowerCase();

  // SSL inspection: cert issuer mismatch (blue team MitM proxy)
  if (/ssl.?inspect|ssl.?bump|ssl.?decrypt|mitm.?proxy|bluecoat|zscaler|palo.?alto.?decrypt|fortigate.?ssl/i.test(allText)) {
    taps.push({ tapType: "ssl_inspection", interceptedBy: "SSL Inspection Proxy", evidence: "SSL decryption/inspection detected" });
  }
  // IDS/IPS inline
  if (/snort|suricata|ids.?inline|ips.?inline|zeek|bro.?ids/i.test(allText)) {
    taps.push({ tapType: "ids_inline", interceptedBy: "IDS/IPS", evidence: "Inline IDS/IPS signatures detected" });
  }
  // NGFW with deep packet inspection
  if (/ngfw|next.?gen.?firewall|palo.?alto|fortinet|fortigate|checkpoint|sophos.?xg/i.test(allText)) {
    taps.push({ tapType: "ids_inline", interceptedBy: "NGFW", evidence: "Next-gen firewall with DPI detected" });
  }
  // WAF in transparent/inline mode (not just CDN WAF)
  if (waf && !/cloudflare|akamai|fastly|sucuri/i.test(waf)) {
    taps.push({ tapType: "proxy_intercept", interceptedBy: `WAF: ${waf}`, evidence: "Inline WAF intercepting and analyzing traffic" });
  }
  // Traffic mirroring / SPAN indicators
  if (/span.?port|mirror|tap|packet.?broker|gigamon|ixia|network.?tap/i.test(allText)) {
    taps.push({ tapType: "span_port", interceptedBy: "Network TAP/SPAN", evidence: "Traffic mirroring detected" });
  }
  // SIEM/SOC logging indicators
  if (/splunk|elastic.?siem|sentinel|qradar|arcsight|siem/i.test(allText)) {
    taps.push({ tapType: "traffic_mirror", interceptedBy: "SIEM", evidence: "SIEM log collection detected" });
  }
  return taps;
}

// ── Engagement Attack Graph → Ops Viewer ───────────────────────────
export function transformEngagementGraph(graphData: any): BattlespaceGraphData {
  const nodes: BattlespaceNode[] = [];
  const edges: BattlespaceEdge[] = [];
  const hostNodes = new Map<string, string>(); // hostname → nodeId
  const proxyNodes = new Map<string, string>(); // proxyVendor-hostname → nodeId
  const tapNodes = new Map<string, string>();   // tapType-hostname → nodeId

  if (!graphData?.nodes) return { nodes: [], edges: [], mode: "engagement" };

  // ── Pass 1: Create host grouping nodes from unique targets ──
  const targets = new Set<string>();
  for (const n of graphData.nodes) {
    const target = n.details?.target || n.details?.hostname;
    if (target && !targets.has(target)) {
      targets.add(target);
      const hostId = `host-${target}`;
      hostNodes.set(target, hostId);
      nodes.push({
        id: hostId,
        type: "host",
        label: target,
        hostname: target,
        ip: n.details?.ip,
        os: n.details?.os,
        platform: guessPlatform(target, n.details),
        technologies: [],
        severity: "info",
        weaknessLevel: 0,
        priorityScore: 0.3,
        discoveredAt: (n as any).discoveredAt || undefined,
      });
    }
  }

  // ── Pass 2: Transform attack graph nodes ──
  for (const n of graphData.nodes) {
    const nodeType = mapNodeType(n.type, n.category, n.layer);
    const severity = normalizeSeverity(n.severity);
    const techs = (n.techniques || []) as string[];
    const target = n.details?.target;

    const bNode: BattlespaceNode = {
      id: n.id,
      type: nodeType,
      label: n.label,
      severity,
      weaknessLevel: n.exploitability || 0,
      priorityScore: (n.exploitability || 0) * (n.impact || 0),
      technologies: n.details?.technology ? [n.details.technology] : [],
      protocols: guessProtocols(n.details?.port, n.details?.service),
      port: n.details?.port,
      serviceName: n.details?.service,
      hostname: target,
      layer: n.layer,
      mitreIds: extractMitreIds(techs),
      killChainPhase: mapLayerToKillChain(n.layer),
      defenses: n.defenses || [],
      discoveredAt: (n as any).discoveredAt || undefined,
      affectedTechnology: n.details?.technology || n.details?.service || undefined,
    };
    nodes.push(bNode);

    // Link to host node
    if (target && hostNodes.has(target)) {
      edges.push({
        id: `link-${hostNodes.get(target)}-${n.id}`,
        source: hostNodes.get(target)!,
        target: n.id,
        type: "network_link",
        weight: 0.3,
        probability: 1,
      });
    }
  }

  // ── Pass 3: Transform edges ──
  for (const e of graphData.edges || []) {
    edges.push({
      id: `edge-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      type: mapEdgeType(e.type || e.label),
      weight: e.weight || 0.5,
      probability: e.weight || 0.5,
      dataFlow: e.dataFlow || e.label,
      protocol: guessEdgeProtocol(e.dataFlow),
    });
  }

  // ── Pass 4: Defense nodes ──
  const defenseSet = new Set<string>();
  for (const n of graphData.nodes) {
    for (const def of (n.defenses || [])) {
      const defId = `defense-${def}`;
      if (!defenseSet.has(defId)) {
        defenseSet.add(defId);
        nodes.push({
          id: defId,
          type: "defense",
          label: def.toUpperCase(),
          defenseType: def,
          severity: "info",
          priorityScore: 0.5,
        });
      }
      edges.push({
        id: `protect-${defId}-${n.id}`,
        source: defId,
        target: n.id,
        type: "protects",
        weight: 0.6,
        probability: 0.8,
      });
    }
  }

  // ── Pass 5: Detect proxies, CDNs, load balancers from asset data ──
  // Extract from engagement metadata (assets with waf/cdn/tech data)
  const engAssets = graphData.engagement?.assets || graphData.assets || [];
  for (const asset of engAssets) {
    const hostname = asset.hostname || asset.target;
    if (!hostname) continue;
    const hostId = hostNodes.get(hostname);
    const allTechs = [
      ...(asset.technologies || []),
      ...(asset.passiveRecon?.technologies || []),
      asset.wafDetected || "",
      asset.passiveRecon?.wafDetected || "",
    ].map((t: any) => typeof t === "string" ? t : t.name || "").filter(Boolean);

    // Detect proxies from technologies
    const detectedProxies = new Map<string, { vendor: string; role: BattlespaceNode["proxyRole"] }>();
    for (const tech of allTechs) {
      const proxy = detectProxy(tech);
      if (proxy && !detectedProxies.has(proxy.vendor)) {
        detectedProxies.set(proxy.vendor, proxy);
      }
    }

    // CDN detection from passiveRecon
    const cdnData = asset.passiveRecon?.riskSignals?.filter((r: any) => r.type === "cdn_waf") || [];
    for (const cdn of cdnData) {
      const cdnName = (cdn.rationale || "").replace(/CDN\/WAF detected:\s*/i, "").trim();
      if (cdnName && !detectedProxies.has(cdnName)) {
        detectedProxies.set(cdnName, { vendor: cdnName, role: "cdn" });
      }
    }

    // Create proxy nodes and wire them between internet and host
    for (const [, proxyInfo] of detectedProxies) {
      const proxyKey = `${proxyInfo.vendor}-${hostname}`;
      if (proxyNodes.has(proxyKey)) continue;
      const proxyId = `proxy-${proxyInfo.vendor.toLowerCase().replace(/\s+/g, "-")}-${hostname}`;
      proxyNodes.set(proxyKey, proxyId);
      const roleLabel = proxyInfo.role === "cdn" ? "CDN" : proxyInfo.role === "load_balancer" ? "LB" : proxyInfo.role === "waf_inline" ? "WAF" : "Proxy";
      nodes.push({
        id: proxyId,
        type: "proxy",
        label: `${proxyInfo.vendor} ${roleLabel}`,
        hostname,
        proxyVendor: proxyInfo.vendor,
        proxyRole: proxyInfo.role,
        severity: "info",
        priorityScore: 0.4,
        technologies: [proxyInfo.vendor],
      });
      // Edge: proxy → host (proxies_to)
      if (hostId) {
        edges.push({
          id: `proxies-${proxyId}-${hostId}`,
          source: proxyId,
          target: hostId,
          type: "proxies_to",
          weight: 0.8,
          probability: 0.95,
          dataFlow: `${roleLabel} forwarding`,
          protocol: "https",
        });
      }
    }

    // ── Pass 5b: Detect blue team interception / tap points ──
    const taps = detectInterception(asset);
    for (const tap of taps) {
      const tapKey = `${tap.tapType}-${hostname}`;
      if (tapNodes.has(tapKey)) continue;
      const tapId = `tap-${tap.tapType}-${hostname}`;
      tapNodes.set(tapKey, tapId);
      nodes.push({
        id: tapId,
        type: "tap_point",
        label: `${tap.interceptedBy}`,
        hostname,
        tapType: tap.tapType,
        interceptedBy: tap.interceptedBy,
        isIntercepted: true,
        severity: "high",
        priorityScore: 0.9,
      });
      // Edge: tap intercepts the host's traffic
      if (hostId) {
        edges.push({
          id: `intercept-${tapId}-${hostId}`,
          source: tapId,
          target: hostId,
          type: "intercepts",
          weight: 0.9,
          probability: 0.85,
          dataFlow: tap.evidence,
          isIntercepted: true,
          interceptionType: tap.tapType === "ssl_inspection" ? "ssl_decrypted" : tap.tapType === "ids_inline" ? "inline" : tap.tapType === "span_port" ? "mirrored" : "logged",
          interceptedBy: tap.interceptedBy,
        });
      }
      // Mark all edges to/from this host as intercepted
      for (const edge of edges) {
        if ((edge.source === hostId || edge.target === hostId) && edge.type !== "intercepts") {
          edge.isIntercepted = true;
          edge.interceptedBy = tap.interceptedBy;
          edge.interceptionType = tap.tapType === "ssl_inspection" ? "ssl_decrypted" : "logged";
        }
      }
    }
  }

  // ── Pass 6: C2 infrastructure nodes ──
  // Detect from engagement timeline log entries (c2_deploy events) and agent data
  const timeline = graphData.engagement?.timeline || graphData.timeline || [];
  const c2Hosts = new Set<string>();
  const agentHosts = new Set<string>();
  for (const entry of timeline) {
    if (entry.type === "c2_deploy" || entry.type === "exploit_success") {
      const target = entry.data?.target || entry.data?.hostname || entry.hostname;
      if (target) {
        if (entry.type === "c2_deploy") c2Hosts.add(target);
        if (entry.type === "exploit_success" && /session.*opened|shell|meterpreter/i.test(entry.detail || "")) {
          agentHosts.add(target);
        }
      }
    }
  }
  // Also check assets with status=compromised
  for (const asset of engAssets) {
    if (asset.status === "compromised") {
      agentHosts.add(asset.hostname || asset.target);
    }
  }

  // Create C2 server node (our infrastructure)
  if (c2Hosts.size > 0 || agentHosts.size > 0) {
    const c2ServerId = "c2-server-caldera";
    nodes.push({
      id: c2ServerId,
      type: "c2_server",
      label: "Caldera C2",
      c2Platform: "caldera",
      c2Protocol: "https",
      severity: "info",
      priorityScore: 0.8,
      killChainPhase: "c2",
    });

    // Create agent nodes on compromised hosts and link to C2
    for (const agentHost of agentHosts) {
      const agentId = `agent-${agentHost}`;
      // Check if agent node already exists
      if (!nodes.find(n => n.id === agentId)) {
        nodes.push({
          id: agentId,
          type: "agent",
          label: `Agent: ${agentHost}`,
          hostname: agentHost,
          c2Platform: "caldera",
          severity: "info",
          priorityScore: 0.7,
          killChainPhase: "c2",
        });
        // Link agent to its host
        const hostId = hostNodes.get(agentHost);
        if (hostId) {
          edges.push({
            id: `agent-host-${agentId}-${hostId}`,
            source: hostId,
            target: agentId,
            type: "network_link",
            weight: 0.5,
            probability: 1,
            dataFlow: "implant deployed",
          });
        }
      }
      // C2 channel: agent → C2 server
      edges.push({
        id: `c2-channel-${agentId}-${c2ServerId}`,
        source: agentId,
        target: c2ServerId,
        type: "c2_channel",
        weight: 0.9,
        probability: 0.95,
        dataFlow: "C2 callback (HTTPS)",
        protocol: "https",
        killChainPhase: "c2",
      });

      // Check if C2 traffic passes through any detected tap points
      const hostTaps = Array.from(tapNodes.entries()).filter(([key]) => key.includes(agentHost));
      for (const [, tapId] of hostTaps) {
        const c2Edge = edges.find(e => e.id === `c2-channel-${agentId}-${c2ServerId}`);
        if (c2Edge) {
          c2Edge.isIntercepted = true;
          c2Edge.interceptionType = "logged";
          c2Edge.interceptedBy = nodes.find(n => n.id === tapId)?.interceptedBy;
        }
      }
    }
  }

  // ── Pass 7: Intermediate gateway/hop nodes ──
  // Detect from traceroute data, DNS chain, or CDN origin resolution
  const tracerouteData = graphData.engagement?.traceroute || graphData.traceroute || [];
  for (const route of tracerouteData) {
    const targetHost = route.target;
    const hops = route.hops || [];
    let prevNodeId = "c2-server-caldera"; // Start from our infra
    if (!nodes.find(n => n.id === prevNodeId)) prevNodeId = hostNodes.values().next().value || "";

    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];
      const hopId = `gateway-hop${i}-${targetHost}`;
      nodes.push({
        id: hopId,
        type: "gateway",
        label: hop.ip || hop.hostname || `Hop ${i + 1}`,
        ip: hop.ip,
        hostname: hop.hostname,
        severity: "info",
        priorityScore: 0.2,
      });
      edges.push({
        id: `route-${prevNodeId}-${hopId}`,
        source: prevNodeId,
        target: hopId,
        type: "routes_through",
        weight: 0.3,
        probability: 1,
        dataFlow: `${hop.latency || "?"}ms`,
        protocol: "tcp",
      });
      prevNodeId = hopId;
    }
    // Final hop → target host
    const targetHostId = hostNodes.get(targetHost);
    if (targetHostId && prevNodeId) {
      edges.push({
        id: `route-${prevNodeId}-${targetHostId}`,
        source: prevNodeId,
        target: targetHostId,
        type: "routes_through",
        weight: 0.5,
        probability: 1,
      });
    }
  }

  // ── Pass 8: Aggregate host weakness levels ──
  for (const [hostname, hostId] of hostNodes) {
    const childNodes = nodes.filter(n => n.hostname === hostname && n.id !== hostId);
    const maxWeakness = Math.max(0, ...childNodes.map(n => n.weaknessLevel || 0));
    const maxPriority = Math.max(0, ...childNodes.map(n => n.priorityScore || 0));
    const hostNode = nodes.find(n => n.id === hostId);
    if (hostNode) {
      hostNode.weaknessLevel = maxWeakness;
      hostNode.priorityScore = maxPriority;
      hostNode.severity = maxWeakness > 0.8 ? "critical" : maxWeakness > 0.6 ? "high" : maxWeakness > 0.3 ? "medium" : "low";
      const allTechs = new Set<string>();
      for (const cn of childNodes) {
        for (const t of cn.technologies || []) allTechs.add(t);
      }
      hostNode.technologies = Array.from(allTechs);
      // Mark host as intercepted if any tap point monitors it
      const hasTap = Array.from(tapNodes.keys()).some(k => k.includes(hostname));
      if (hasTap) hostNode.isIntercepted = true;
    }
  }

  // ── Pass 9: Proxy bypass detection ──
  // When a proxy node exists for a host but the host also has direct network_link
  // edges (meaning the origin IP is reachable without going through the proxy),
  // flag it as a bypass opportunity.
  const proxyTargetHosts = new Map<string, string[]>(); // hostname → [proxyNodeId]
  for (const e of edges) {
    if (e.type === "proxies_to") {
      const tgtNode = nodes.find(n => n.id === e.target);
      if (tgtNode?.hostname) {
        const existing = proxyTargetHosts.get(tgtNode.hostname) || [];
        existing.push(e.source);
        proxyTargetHosts.set(tgtNode.hostname, existing);
      }
    }
  }
  // Check if any host behind a proxy also has direct network_link/exploits/enables edges
  // from non-proxy source nodes (indicating origin IP is directly reachable)
  for (const [hostname, proxyIds] of proxyTargetHosts) {
    const hostId = hostNodes.get(hostname);
    if (!hostId) continue;
    const directEdges = edges.filter(e =>
      e.target === hostId &&
      !proxyIds.includes(e.source) &&
      ["network_link", "exploits", "enables"].includes(e.type) &&
      !nodes.find(n => n.id === e.source && n.type === "proxy")
    );
    if (directEdges.length > 0) {
      // Mark the host as having a bypass opportunity
      const hostNode = nodes.find(n => n.id === hostId);
      if (hostNode) {
        hostNode.tags = [...(hostNode.tags || []), "PROXY_BYPASS"];
      }
      // Add explicit bypass edges from the direct source to the host
      for (const de of directEdges) {
        edges.push({
          source: de.source,
          target: hostId,
          type: "bypass",
          weight: 3,
          label: `Direct access bypasses ${proxyIds.map(pid => {
            const pn = nodes.find(n => n.id === pid);
            return pn?.label || "proxy";
          }).join(", ")}`,
          isBypassOpportunity: true,
          bypassesProxy: proxyIds[0],
        });
      }
      // Mark existing proxy edges as bypassable
      for (const e of edges) {
        if (e.type === "proxies_to" && proxyIds.includes(e.source)) {
          (e as any).isBypassed = true;
        }
      }
    }
  }

  // ── Pass 10: Interception Fingerprinting Report ──
  // When the server returns an interceptionReport from the fingerprinting engine,
  // create defense/tap nodes for each identified interception mechanism.
  const interceptionReport = graphData.interceptionReport;
  if (interceptionReport?.findings?.length > 0) {
    for (const finding of interceptionReport.findings) {
      const findingId = `fp-${finding.vendorId || finding.mechanism.replace(/\s+/g, "-").toLowerCase()}`;
      if (nodes.find(n => n.id === findingId)) continue;

      const tapType: BattlespaceNode["tapType"] = finding.domain === "network"
        ? (finding.mechanism.toLowerCase().includes("ssl") ? "ssl_inspection" : "ids_inline")
        : finding.domain === "endpoint"
          ? "proxy_intercept"
          : "traffic_mirror";

      nodes.push({
        id: findingId,
        type: "tap_point",
        label: `${finding.vendorName || finding.mechanism} [${finding.confidence.level}]`,
        tapType,
        interceptedBy: finding.vendorName || finding.mechanism,
        isIntercepted: true,
        severity: finding.confidence.level === "confirmed" || finding.confidence.level === "high" ? "critical" : "high",
        priorityScore: finding.confidence.score / 100,
        defenseType: finding.domain,
        tags: [
          ...(finding.mitreMapping ? [finding.mitreMapping.techniqueId] : []),
          `confidence:${finding.confidence.level}`,
          `domain:${finding.domain}`,
        ],
      });

      // Link interception finding to all host nodes
      for (const [, hostId] of hostNodes) {
        edges.push({
          id: `fp-intercept-${findingId}-${hostId}`,
          source: findingId,
          target: hostId,
          type: "intercepts",
          weight: finding.confidence.score / 100,
          probability: finding.confidence.score / 100,
          isIntercepted: true,
          interceptedBy: finding.vendorName || finding.mechanism,
          interceptionType: tapType === "ssl_inspection" ? "ssl_decrypted" : "logged",
        });
      }
    }
  }

  return {
    nodes,
    edges,
    mode: "engagement",
    metadata: {
      engagementName: graphData.engagement?.name,
      targetDomain: graphData.engagement?.name,
      taxonomyCoverage: graphData.taxonomy,
      interceptionReport: interceptionReport || undefined,
    },
  };
}

// ── DI Scan → Battlespace ───────────────────────────────────────────
export function transformDIScan(
  scan: any,
  assets: any[],
  threatMatch?: any
): BattlespaceGraphData {
  const nodes: BattlespaceNode[] = [];
  const edges: BattlespaceEdge[] = [];

  // Root domain node
  const rootId = `domain-${scan.primaryDomain}`;
  nodes.push({
    id: rootId,
    type: "domain",
    label: scan.primaryDomain,
    hostname: scan.primaryDomain,
    severity: normalizeSeverity(scan.overallRiskBand || "medium"),
    priorityScore: (scan.overallRiskScore || 50) / 100,
    weaknessLevel: (scan.overallRiskScore || 50) / 100,
  });

  // Asset nodes
  for (const asset of assets) {
    const assetId = `asset-${asset.id}`;
    const techs = Array.isArray(asset.technologies)
      ? asset.technologies.map((t: any) => typeof t === "string" ? t : t.name || t.technology || "")
      : [];
    const postureFindings = Array.isArray(asset.postureFindings) ? asset.postureFindings : [];

    // Build technologyVersions map from detectedTechnologies or technologyVersions
    const techVersions: Record<string, string> = {};
    if (asset.technologyVersions && typeof asset.technologyVersions === "object") {
      Object.assign(techVersions, asset.technologyVersions);
    } else if (Array.isArray(asset.detectedTechnologies)) {
      for (const dt of asset.detectedTechnologies) {
        if (dt.name && dt.version) techVersions[dt.name] = dt.version;
      }
    }

    // Extract open ports/services for this asset from pipelineOutput.discoveredPorts
    const assetPorts: Array<{ port?: number; name?: string }> = [];
    const pipelineOutput = scan.pipelineOutput as any;
    const discoveredPorts: any[] = pipelineOutput?.discoveredPorts || pipelineOutput?.trimmedOutput?.discoveredPorts || [];
    if (Array.isArray(discoveredPorts)) {
      for (const dp of discoveredPorts) {
        if (dp.hostname === asset.hostname || dp.ip === asset.hostname) {
          assetPorts.push({ port: dp.port, name: dp.product || dp.transport || 'tcp' });
        }
      }
    }

    nodes.push({
      id: assetId,
      type: asset.assetType === "subdomain" ? "subdomain" : "host",
      label: asset.hostname,
      hostname: asset.hostname,
      ip: asset.ip || undefined,
      severity: normalizeSeverity(asset.riskBand || "low"),
      weaknessLevel: (asset.hybridRiskScore || 0) / 100,
      priorityScore: (asset.missionImpactScore || asset.hybridRiskScore || 0) / 100,
      platform: (asset.platformType as PlatformType) || guessPlatform(asset.hostname, asset),
      technologies: techs,
      technologyVersions: Object.keys(techVersions).length > 0 ? techVersions : undefined,
      protocols: guessProtocolsFromTech(techs),
      exposedServices: assetPorts.length > 0 ? assetPorts : undefined,
    });

    // Add individual service nodes for each discovered port
    for (const sp of assetPorts) {
      if (!sp.port) continue;
      const svcId = `svc-${asset.id}-${sp.port}`;
      nodes.push({
        id: svcId,
        type: "service",
        label: `${sp.name || 'tcp'}:${sp.port}`,
        port: sp.port,
        serviceName: sp.name || 'tcp',
        hostname: asset.hostname,
        severity: "info",
        priorityScore: 0.3,
      });
      edges.push({
        id: `svc-link-${assetId}-${svcId}`,
        source: assetId,
        target: svcId,
        type: "network_link",
        weight: 0.4,
        probability: 1,
        protocol: sp.name === 'https' || sp.port === 443 ? 'https' : sp.name === 'ssh' || sp.port === 22 ? 'ssh' : 'tcp',
      });
    }

    // Connect to root domain
    edges.push({
      id: `dns-${rootId}-${assetId}`,
      source: rootId,
      target: assetId,
      type: "dns_resolve",
      weight: 0.5,
      probability: 1,
    });

    // Add posture finding nodes (vulnerabilities)
    for (let i = 0; i < postureFindings.length; i++) {
      const pf = postureFindings[i];
      const pfId = `finding-${asset.id}-${i}`;
      const findingTitle = typeof pf === "string" ? pf : pf.title || pf.finding || "Finding";
      // Extract affected technology from finding title — e.g. "CVE-2024-1234: Buffer Overflow (Apache HTTP Server)"
      const affectedTech = extractAffectedTech(findingTitle, techs);
      nodes.push({
        id: pfId,
        type: "vulnerability",
        label: findingTitle,
        severity: normalizeSeverity(typeof pf === "object" ? pf.severity : "medium"),
        weaknessLevel: typeof pf === "object" && pf.severity === "critical" ? 0.95 : 0.5,
        hostname: asset.hostname,
        affectedTechnology: affectedTech || undefined,
      });
      edges.push({
        id: `vuln-${assetId}-${pfId}`,
        source: assetId,
        target: pfId,
        type: "exploits",
        weight: 0.5,
        label: affectedTech || undefined,
      });
    }
  }

  // Threat actor overlay from DI threat matching
  if (threatMatch?.matchedGroups) {
    for (const group of threatMatch.matchedGroups) {
      const groupId = `threat-${group.groupId}`;
      nodes.push({
        id: groupId,
        type: "threat_actor",
        label: group.groupName,
        threatGroupId: group.groupId,
        threatLevel: group.riskLevel,
        severity: normalizeSeverity(group.riskLevel),
        priorityScore: group.matchScore / 100,
        mitreIds: group.matchedTechniques?.map((t: any) => t.id) || [],
      });

      // Connect threat actor to relevant assets based on matched techniques
      for (const asset of assets) {
        const assetId = `asset-${asset.id}`;
        if (group.matchScore > 50) {
          edges.push({
            id: `targets-${groupId}-${assetId}`,
            source: groupId,
            target: assetId,
            type: "targets",
            weight: group.matchScore / 100,
            probability: group.matchScore / 100,
          });
        }
      }

      // Add IOC nodes for this group
      if (group.matchedCVEs) {
        for (const cve of group.matchedCVEs.slice(0, 5)) {
          const iocId = `ioc-${groupId}-${cve}`;
          nodes.push({
            id: iocId,
            type: "ioc",
            label: cve,
            severity: "high",
            threatGroupId: group.groupId,
          });
          edges.push({
            id: `indicates-${iocId}-${groupId}`,
            source: iocId,
            target: groupId,
            type: "indicates",
            weight: 0.7,
          });
        }
      }
    }
  }

  // ── Proxy / CDN / LB detection for DI assets ──
  const diProxyNodes = new Map<string, string>();
  for (const asset of assets) {
    const assetId = `asset-${asset.id}`;
    const hostname = asset.hostname;
    const allTechs = [
      ...(Array.isArray(asset.technologies) ? asset.technologies.map((t: any) => typeof t === "string" ? t : t.name || "") : []),
      asset.wafDetected || "",
      asset.passiveRecon?.wafDetected || "",
    ].filter(Boolean);

    // Detect proxies from technologies
    for (const tech of allTechs) {
      const proxy = detectProxy(tech);
      if (proxy) {
        const proxyKey = `${proxy.vendor}-${hostname}`;
        if (diProxyNodes.has(proxyKey)) continue;
        const proxyId = `proxy-${proxy.vendor.toLowerCase().replace(/\s+/g, "-")}-${hostname}`;
        diProxyNodes.set(proxyKey, proxyId);
        const roleLabel = proxy.role === "cdn" ? "CDN" : proxy.role === "load_balancer" ? "LB" : proxy.role === "waf_inline" ? "WAF" : "Proxy";
        nodes.push({
          id: proxyId,
          type: "proxy",
          label: `${proxy.vendor} ${roleLabel}`,
          hostname,
          proxyVendor: proxy.vendor,
          proxyRole: proxy.role,
          severity: "info",
          priorityScore: 0.4,
          technologies: [proxy.vendor],
        });
        // Proxy sits between root domain and asset
        edges.push({
          id: `proxies-${proxyId}-${assetId}`,
          source: proxyId,
          target: assetId,
          type: "proxies_to",
          weight: 0.8,
          probability: 0.95,
          dataFlow: `${roleLabel} forwarding`,
          protocol: "https",
        });
        // Connect root → proxy instead of root → asset directly
        edges.push({
          id: `dns-${rootId}-${proxyId}`,
          source: rootId,
          target: proxyId,
          type: "dns_resolve",
          weight: 0.5,
          probability: 1,
        });
      }
    }

    // Detect blue team interception on DI assets
    const taps = detectInterception(asset);
    for (const tap of taps) {
      const tapId = `tap-${tap.tapType}-${hostname}`;
      nodes.push({
        id: tapId,
        type: "tap_point",
        label: tap.interceptedBy,
        hostname,
        tapType: tap.tapType,
        interceptedBy: tap.interceptedBy,
        isIntercepted: true,
        severity: "high",
        priorityScore: 0.9,
      });
      edges.push({
        id: `intercept-${tapId}-${assetId}`,
        source: tapId,
        target: assetId,
        type: "intercepts",
        weight: 0.9,
        probability: 0.85,
        dataFlow: tap.evidence,
        isIntercepted: true,
        interceptionType: tap.tapType === "ssl_inspection" ? "ssl_decrypted" : tap.tapType === "ids_inline" ? "inline" : "logged",
        interceptedBy: tap.interceptedBy,
      });
      // Mark the asset node as intercepted
      const assetNode = nodes.find(n => n.id === assetId);
      if (assetNode) assetNode.isIntercepted = true;
    }
  }

  // ── Platform Infrastructure Nodes ──────────────────────────────────
  // Show AC3 platform components and their connections to target assets
  const infraNodes: Array<{ id: string; label: string; type: BattlespaceNodeType; c2Platform?: string; c2Protocol?: string; technologies?: string[]; severity?: SeverityLevel }> = [
    { id: 'infra-scanforge', label: 'ScanForge', type: 'gateway', technologies: ['ScanForge', 'Naabu', 'Nuclei', 'Masscan'], severity: 'info' },
    { id: 'infra-caldera', label: 'Caldera C2', type: 'c2_server', c2Platform: 'caldera', c2Protocol: 'https', technologies: ['MITRE Caldera'], severity: 'info' },
    { id: 'infra-zap', label: 'ZAP DAST', type: 'gateway', technologies: ['OWASP ZAP'], severity: 'info' },
    { id: 'infra-gophish', label: 'GoPhish', type: 'gateway', technologies: ['GoPhish'], severity: 'info' },
  ];
  for (const infra of infraNodes) {
    nodes.push({
      id: infra.id,
      type: infra.type,
      label: infra.label,
      severity: infra.severity || 'info',
      priorityScore: 0.2,
      technologies: infra.technologies,
      c2Platform: infra.c2Platform,
      c2Protocol: infra.c2Protocol,
      platform: 'on_prem',
      clusterId: 'ac3-platform',
    });
  }
  // Connect ScanForge → all assets (it scans them)
  for (const asset of assets) {
    const assetId = `asset-${asset.id}`;
    edges.push({
      id: `infra-scan-${assetId}`,
      source: 'infra-scanforge',
      target: assetId,
      type: 'routes_through',
      weight: 0.3,
      probability: 0.9,
      dataFlow: 'port scan + vuln scan',
      protocol: 'https',
    });
  }
  // Connect ZAP → root domain (DAST scanning)
  edges.push({
    id: `infra-zap-${rootId}`,
    source: 'infra-zap',
    target: rootId,
    type: 'routes_through',
    weight: 0.3,
    probability: 0.8,
    dataFlow: 'DAST spider + active scan',
    protocol: 'https',
  });
  // Connect GoPhish → root domain (phishing campaigns)
  edges.push({
    id: `infra-gophish-${rootId}`,
    source: 'infra-gophish',
    target: rootId,
    type: 'routes_through',
    weight: 0.2,
    probability: 0.6,
    dataFlow: 'phishing campaign',
    protocol: 'https',
  });
  // Connect Caldera → compromised assets (C2 channel)
  for (const asset of assets) {
    const assetId = `asset-${asset.id}`;
    const assetNode = nodes.find(n => n.id === assetId);
    if (assetNode?.isCompromised) {
      edges.push({
        id: `infra-c2-${assetId}`,
        source: 'infra-caldera',
        target: assetId,
        type: 'c2_channel',
        weight: 0.8,
        probability: 0.95,
        dataFlow: 'C2 callback',
        protocol: 'https',
        isActive: true,
      });
    }
  }

  return {
    nodes,
    edges,
    mode: "di_scan",
    metadata: {
      targetDomain: scan.primaryDomain,
      scanId: scan.id,
      threatGroups: threatMatch?.matchedGroups?.map((g: any) => ({
        id: g.groupId,
        name: g.groupName,
        matchScore: g.matchScore,
        threatLevel: g.riskLevel,
      })),
    },
  };
}

// ── Helper Functions ────────────────────────────────────────────────
function mapNodeType(type: string, category: string, layer: string): BattlespaceNodeType {
  if (type === "target") return "host";
  if (type === "technique") return "service";
  if (type === "hypothesis") return "hypothesis";
  if (type === "credential") return "credential";
  if (type === "pivot") return "pivot_point";
  if (category === "device_iot_scada") return "host";
  if (category === "platform" || category === "infrastructure") return "cloud_resource";
  if (layer === "identity") return "credential";
  return "vulnerability";
}

function mapEdgeType(type: string): BattlespaceEdgeType {
  const t = String(type || "").toLowerCase();
  if (t.includes("exploit")) return "exploits";
  if (t.includes("chain")) return "chains_with";
  if (t.includes("enable") || t.includes("provide")) return "enables";
  if (t.includes("pivot") || t.includes("lateral")) return "pivots_to";
  if (t.includes("escalat")) return "escalates";
  if (t.includes("protect")) return "protects";
  if (t.includes("target")) return "targets";
  if (t.includes("dns")) return "dns_resolve";
  return "enables";
}

/**
 * Extract the affected technology from a finding title.
 * Looks for parenthesized product names like "(Apache HTTP Server)" or "(nginx 1.18)"
 * and cross-references with the asset's known technologies.
 */
function extractAffectedTech(title: string, assetTechs: string[]): string | null {
  // 1. Try parenthesized product: "CVE-2024-1234: Vuln Name (Apache HTTP Server)"
  const parenMatch = title.match(/\(([^)]+)\)\s*$/);
  if (parenMatch) {
    const product = parenMatch[1].trim();
    // Check if this matches any known tech on the asset
    const lower = product.toLowerCase();
    for (const tech of assetTechs) {
      if (lower.includes(tech.toLowerCase()) || tech.toLowerCase().includes(lower.split(/\s+/)[0])) {
        return tech;
      }
    }
    // Return the product name even if not in asset techs (it's still useful)
    return product;
  }
  // 2. Try matching known asset techs against the title text
  const titleLower = title.toLowerCase();
  for (const tech of assetTechs) {
    if (tech.length > 2 && titleLower.includes(tech.toLowerCase())) {
      return tech;
    }
  }
  return null;
}

function normalizeSeverity(s: any): SeverityLevel {
  // Handle numeric severity (e.g. CVSS-like scores from postureFindings)
  if (typeof s === "number") {
    if (s >= 9) return "critical";
    if (s >= 7) return "high";
    if (s >= 4) return "medium";
    if (s >= 1) return "low";
    return "info";
  }
  const sl = String(s || "").toLowerCase();
  if (sl === "critical") return "critical";
  if (sl === "high") return "high";
  if (sl === "medium") return "medium";
  if (sl === "low") return "low";
  return "info";
}

function guessPlatform(hostname: string, details: any): PlatformType {
  const h = String(hostname || "").toLowerCase();
  if (h.includes("aws") || h.includes("azure") || h.includes("gcp") || h.includes("cloud")) return "cloud";
  if (h.includes("docker") || h.includes("container") || h.includes("k8s")) return "container";
  if (h.includes("lambda") || h.includes("function")) return "serverless";
  if (h.includes("iot") || h.includes("sensor") || h.includes("scada")) return "iot";
  return "on_prem";
}

function guessProtocols(port?: number, service?: string): ProtocolType[] {
  if (!port && !service) return [];
  const protos: ProtocolType[] = [];
  if (port === 80 || service?.includes("http")) protos.push("http");
  if (port === 443 || service?.includes("https")) protos.push("https");
  if (port === 22 || service?.includes("ssh")) protos.push("ssh");
  if (port === 3389 || service?.includes("rdp")) protos.push("rdp");
  if (port === 445 || service?.includes("smb")) protos.push("smb");
  if (port === 53 || service?.includes("dns")) protos.push("dns");
  if (protos.length === 0) protos.push("tcp");
  return protos;
}

function guessProtocolsFromTech(techs: any[]): ProtocolType[] {
  const protos = new Set<ProtocolType>();
  for (const t of techs) {
    const tl = String(t || "").toLowerCase();
    if (tl.includes("http") || tl.includes("web") || tl.includes("nginx") || tl.includes("apache")) protos.add("https");
    if (tl.includes("ssh")) protos.add("ssh");
    if (tl.includes("dns")) protos.add("dns");
    if (tl.includes("smb") || tl.includes("windows")) protos.add("smb");
  }
  return Array.from(protos);
}

function guessEdgeProtocol(dataFlow?: string): ProtocolType | undefined {
  if (!dataFlow) return undefined;
  const df = dataFlow.toLowerCase();
  if (df.includes("http")) return "https";
  if (df.includes("ssh")) return "ssh";
  if (df.includes("smb") || df.includes("cred")) return "smb";
  if (df.includes("dns")) return "dns";
  return "tcp";
}

function extractMitreIds(techniques: string[]): string[] {
  const ids: string[] = [];
  for (const t of techniques) {
    const match = t.match(/T\d{4}(?:\.\d{3})?/);
    if (match) ids.push(match[0]);
  }
  return ids;
}

function mapLayerToKillChain(layer: any): KillChainPhase | undefined {
  const l = String(layer || "").toLowerCase();
  if (l === "network" || l === "transport") return "recon";
  if (l === "application" || l === "binary") return "exploit";
  if (l === "identity") return "deliver";
  if (l === "infrastructure") return "install";
  if (l === "operational") return "actions";
  return undefined;
}
