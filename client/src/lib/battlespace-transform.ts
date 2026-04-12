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

// ── Engagement Attack Graph → Battlespace ───────────────────────────
export function transformEngagementGraph(graphData: any): BattlespaceGraphData {
  const nodes: BattlespaceNode[] = [];
  const edges: BattlespaceEdge[] = [];
  const hostNodes = new Map<string, string>(); // hostname → nodeId

  if (!graphData?.nodes) return { nodes: [], edges: [], mode: "engagement" };

  // Pass 1: Create host grouping nodes from unique targets
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
      });
    }
  }

  // Pass 2: Transform attack graph nodes
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

  // Pass 3: Transform edges
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

  // Pass 4: Add defense nodes from node defense data
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
      // Connect defense to the node it protects
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

  // Aggregate host weakness levels
  for (const [hostname, hostId] of hostNodes) {
    const childNodes = nodes.filter(n => n.hostname === hostname && n.id !== hostId);
    const maxWeakness = Math.max(0, ...childNodes.map(n => n.weaknessLevel || 0));
    const maxPriority = Math.max(0, ...childNodes.map(n => n.priorityScore || 0));
    const hostNode = nodes.find(n => n.id === hostId);
    if (hostNode) {
      hostNode.weaknessLevel = maxWeakness;
      hostNode.priorityScore = maxPriority;
      hostNode.severity = maxWeakness > 0.8 ? "critical" : maxWeakness > 0.6 ? "high" : maxWeakness > 0.3 ? "medium" : "low";
      // Collect all technologies from children
      const allTechs = new Set<string>();
      for (const cn of childNodes) {
        for (const t of cn.technologies || []) allTechs.add(t);
      }
      hostNode.technologies = Array.from(allTechs);
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

    nodes.push({
      id: assetId,
      type: asset.assetType === "subdomain" ? "subdomain" : "host",
      label: asset.hostname,
      hostname: asset.hostname,
      severity: normalizeSeverity(asset.riskBand || "low"),
      weaknessLevel: (asset.hybridRiskScore || 0) / 100,
      priorityScore: (asset.missionImpactScore || asset.hybridRiskScore || 0) / 100,
      platform: (asset.platformType as PlatformType) || guessPlatform(asset.hostname, asset),
      technologies: techs,
      protocols: guessProtocolsFromTech(techs),
    });

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
      nodes.push({
        id: pfId,
        type: "vulnerability",
        label: typeof pf === "string" ? pf : pf.title || pf.finding || "Finding",
        severity: normalizeSeverity(typeof pf === "object" ? pf.severity : "medium"),
        weaknessLevel: typeof pf === "object" && pf.severity === "critical" ? 0.95 : 0.5,
        hostname: asset.hostname,
      });
      edges.push({
        id: `vuln-${assetId}-${pfId}`,
        source: assetId,
        target: pfId,
        type: "network_link",
        weight: 0.4,
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
  if (type === "hypothesis") return "hypothesis";
  if (type === "credential") return "credential";
  if (type === "pivot") return "pivot_point";
  if (category === "device_iot_scada") return "host";
  if (category === "platform" || category === "infrastructure") return "cloud_resource";
  if (layer === "identity") return "credential";
  return "vulnerability";
}

function mapEdgeType(type: string): BattlespaceEdgeType {
  const t = type.toLowerCase();
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

function normalizeSeverity(s: string): SeverityLevel {
  const sl = (s || "").toLowerCase();
  if (sl === "critical") return "critical";
  if (sl === "high") return "high";
  if (sl === "medium") return "medium";
  if (sl === "low") return "low";
  return "info";
}

function guessPlatform(hostname: string, details: any): PlatformType {
  const h = hostname.toLowerCase();
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

function guessProtocolsFromTech(techs: string[]): ProtocolType[] {
  const protos = new Set<ProtocolType>();
  for (const t of techs) {
    const tl = t.toLowerCase();
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

function mapLayerToKillChain(layer: string): KillChainPhase | undefined {
  const l = (layer || "").toLowerCase();
  if (l === "network" || l === "transport") return "recon";
  if (l === "application" || l === "binary") return "exploit";
  if (l === "identity") return "deliver";
  if (l === "infrastructure") return "install";
  if (l === "operational") return "actions";
  return undefined;
}
