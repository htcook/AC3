/**
 * StructuredLiveView — Static hierarchical view of engagement/DI scan data.
 *
 * Replaces the animated D3-force graph with a clean, structured layout:
 *   Domain → Hosts → Services/Ports → Findings/Vulnerabilities
 *
 * Design principles:
 *  - NO physics simulation, NO bouncing, NO jittering
 *  - Static tree/table layout with expandable rows
 *  - Full data fidelity — every port, service, proxy, connection visible
 *  - Live-updating — new discoveries append without layout shifts
 *  - Clickable — every item opens detail view
 *  - MIL-STD-2525D inspired brutalist styling (consistent with OpsViewer)
 */
import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import {
  ChevronRight, ChevronDown, Globe, Server, Shield, AlertTriangle,
  Network, Lock, Cpu, Zap, Eye, Radio, Target, Skull, Database,
  Cloud, Activity, ExternalLink, Wifi,
} from "lucide-react";
import type { BattlespaceNode, BattlespaceEdge, SeverityLevel } from "@/lib/battlespace-types";
import { SEVERITY_COLORS } from "@/lib/battlespace-types";

// ── Types ──────────────────────────────────────────────────────────

interface StructuredHost {
  id: string;
  hostname: string;
  ip?: string;
  os?: string;
  platform?: string;
  severity: SeverityLevel;
  technologies: string[];
  services: StructuredService[];
  findings: StructuredFinding[];
  defenses: string[];
  proxy?: { vendor: string; role: string } | null;
  isNew?: boolean;
  discoveredAt?: number;
}

interface StructuredService {
  id: string;
  port: number;
  name: string;
  protocol?: string;
  version?: string;
  severity: SeverityLevel;
  isNew?: boolean;
}

interface StructuredFinding {
  id: string;
  title: string;
  severity: SeverityLevel;
  type: string; // vulnerability, hypothesis, technique
  killChainPhase?: string;
  mitreIds?: string[];
  exploitability?: number;
  impact?: number;
  source?: string;
  affectedTech?: string;
  isNew?: boolean;
  discoveredAt?: number;
}

interface StructuredThreatActor {
  id: string;
  name: string;
  threatLevel?: string;
  matchScore?: number;
  mitreIds?: string[];
}

interface StructuredData {
  domain: string;
  hosts: StructuredHost[];
  threatActors: StructuredThreatActor[];
  stats: {
    totalHosts: number;
    totalServices: number;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

interface StructuredLiveViewProps {
  nodes: BattlespaceNode[];
  edges: BattlespaceEdge[];
  mode: "engagement" | "di_scan";
  onNodeClick?: (node: BattlespaceNode) => void;
  isScanning?: boolean;
  liveEventCount?: number;
}

// ── Severity Utilities ──────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_BADGE_CLASSES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/40",
  low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
};

function sevColor(sev: SeverityLevel): string {
  return SEVERITY_COLORS[sev] || SEVERITY_COLORS.info || "#6b7280";
}

// ── Transform graph nodes into structured hierarchy ─────────────────

function buildStructuredData(nodes: BattlespaceNode[], edges: BattlespaceEdge[]): StructuredData {
  const hostMap = new Map<string, StructuredHost>();
  const threatActors: StructuredThreatActor[] = [];
  let domain = "";

  // Pass 1: Identify domain root and hosts
  for (const node of nodes) {
    if (node.type === "domain") {
      domain = node.label || node.hostname || "";
      continue;
    }
    if (node.type === "threat_actor") {
      threatActors.push({
        id: node.id,
        name: node.label,
        threatLevel: node.threatLevel,
        matchScore: node.priorityScore ? Math.round(node.priorityScore * 100) : undefined,
        mitreIds: node.mitreIds,
      });
      continue;
    }
    if (node.type === "host" || node.type === "subdomain") {
      const key = node.hostname || node.label || node.id;
      if (!hostMap.has(key)) {
        hostMap.set(key, {
          id: node.id,
          hostname: key,
          ip: node.ip,
          os: node.os,
          platform: node.platform,
          severity: node.severity || "info",
          technologies: node.technologies || [],
          services: [],
          findings: [],
          defenses: node.defenses || [],
          isNew: node.isNew,
          discoveredAt: node.discoveredAt,
        });
      }
    }
  }

  // Pass 2: Assign services and findings to hosts
  for (const node of nodes) {
    if (node.type === "service") {
      const hostKey = node.hostname || "";
      const host = hostMap.get(hostKey);
      if (host) {
        host.services.push({
          id: node.id,
          port: node.port || 0,
          name: node.serviceName || node.label || "unknown",
          protocol: node.protocols?.[0],
          version: node.version,
          severity: node.severity || "info",
          isNew: node.isNew,
        });
      }
    }
    if (node.type === "vulnerability" || node.type === "hypothesis") {
      // Find parent host via edges
      const parentEdge = edges.find(e => {
        const tgt = typeof e.target === "string" ? e.target : (e.target as any)?.id;
        return tgt === node.id;
      });
      const parentId = parentEdge ? (typeof parentEdge.source === "string" ? parentEdge.source : (parentEdge.source as any)?.id) : null;
      let parentHost: StructuredHost | undefined;
      if (parentId) {
        // Find the host node
        const parentNode = nodes.find(n => n.id === parentId);
        if (parentNode) {
          parentHost = hostMap.get(parentNode.hostname || parentNode.label || parentNode.id);
        }
      }
      // Fallback: match by hostname
      if (!parentHost && node.hostname) {
        parentHost = hostMap.get(node.hostname);
      }
      if (parentHost) {
        parentHost.findings.push({
          id: node.id,
          title: node.label,
          severity: node.severity || "medium",
          type: node.type,
          killChainPhase: node.killChainPhase,
          mitreIds: node.mitreIds,
          exploitability: node.weaknessLevel,
          impact: node.priorityScore,
          source: node.discoveredBy,
          affectedTech: node.affectedTechnology,
          isNew: node.isNew,
          discoveredAt: node.discoveredAt,
        });
        // Update host severity to worst finding
        if ((SEV_ORDER[node.severity || "info"] ?? 4) < (SEV_ORDER[parentHost.severity] ?? 4)) {
          parentHost.severity = node.severity || "info";
        }
      }
    }
    if (node.type === "proxy") {
      const hostKey = node.hostname || "";
      const host = hostMap.get(hostKey);
      if (host) {
        host.proxy = { vendor: node.proxyVendor || node.label, role: node.proxyRole || "proxy" };
      }
    }
  }

  // Sort hosts by severity, then alphabetically
  const hosts = Array.from(hostMap.values()).sort((a, b) => {
    const sevDiff = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    return a.hostname.localeCompare(b.hostname);
  });

  // Sort findings within each host by severity
  for (const host of hosts) {
    host.findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));
    host.services.sort((a, b) => a.port - b.port);
  }

  // Compute stats
  let totalFindings = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, totalServices = 0;
  for (const h of hosts) {
    totalServices += h.services.length;
    for (const f of h.findings) {
      totalFindings++;
      if (f.severity === "critical") criticalCount++;
      else if (f.severity === "high") highCount++;
      else if (f.severity === "medium") mediumCount++;
      else if (f.severity === "low") lowCount++;
    }
  }

  return {
    domain: domain || "Target",
    hosts,
    threatActors,
    stats: {
      totalHosts: hosts.length,
      totalServices,
      totalFindings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
    },
  };
}

// ── Sub-components ──────────────────────────────────────────────────

function SeverityBadge({ severity, size = "xs" }: { severity: SeverityLevel; size?: "xs" | "sm" }) {
  const cls = SEV_BADGE_CLASSES[severity] || SEV_BADGE_CLASSES.info;
  return (
    <span className={`inline-flex items-center px-1.5 py-0 rounded border font-mono uppercase tracking-wider ${cls} ${size === "xs" ? "text-[8px]" : "text-[9px]"}`}>
      {severity}
    </span>
  );
}

function ServiceRow({ service }: { service: StructuredService }) {
  return (
    <div className={`flex items-center gap-2 py-0.5 px-2 text-[10px] font-mono ${service.isNew ? "bg-teal-500/5" : ""}`}>
      <Wifi size={9} className="text-blue-400 shrink-0" />
      <span className="text-blue-300 font-bold w-12 text-right">{service.port}</span>
      <span className="text-gray-400">/</span>
      <span className="text-gray-300 w-16">{service.protocol || "tcp"}</span>
      <span className="text-gray-200 flex-1 truncate">{service.name}</span>
      {service.version && <span className="text-gray-500 text-[9px]">{service.version}</span>}
    </div>
  );
}

function FindingRow({ finding, onClick }: { finding: StructuredFinding; onClick?: () => void }) {
  const icon = finding.type === "hypothesis"
    ? <Eye size={9} className="text-violet-400 shrink-0" />
    : <AlertTriangle size={9} className="text-amber-400 shrink-0" />;

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 py-1 px-2 text-[10px] font-mono w-full text-left hover:bg-white/[0.02] transition-colors ${finding.isNew ? "bg-teal-500/5" : ""}`}
    >
      {icon}
      <SeverityBadge severity={finding.severity} />
      <span className="text-gray-200 flex-1 truncate">{finding.title}</span>
      {finding.source && (
        <span className="text-gray-600 text-[8px] uppercase shrink-0">{finding.source}</span>
      )}
      {finding.killChainPhase && (
        <span className="text-cyan-500/60 text-[8px] uppercase shrink-0">{finding.killChainPhase}</span>
      )}
      {finding.mitreIds && finding.mitreIds.length > 0 && (
        <span className="text-violet-400/60 text-[8px] shrink-0">{finding.mitreIds[0]}</span>
      )}
    </button>
  );
}

function HostCard({
  host,
  isExpanded,
  onToggle,
  onFindingClick,
}: {
  host: StructuredHost;
  isExpanded: boolean;
  onToggle: () => void;
  onFindingClick?: (finding: StructuredFinding) => void;
}) {
  const findingCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of host.findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    return counts;
  }, [host.findings]);

  return (
    <div className={`border border-[#1A2332] ${host.isNew ? "border-l-teal-500/50 border-l-2" : ""}`}>
      {/* Host Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-[#111820]/50 transition-colors text-left"
      >
        {isExpanded ? <ChevronDown size={12} className="text-gray-500 shrink-0" /> : <ChevronRight size={12} className="text-gray-500 shrink-0" />}

        {/* Severity indicator dot */}
        <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: sevColor(host.severity) }} />

        {/* Host icon */}
        {host.platform === "cloud" ? <Cloud size={12} className="text-blue-400 shrink-0" /> : <Server size={12} className="text-gray-400 shrink-0" />}

        {/* Hostname */}
        <span className="font-mono text-[11px] text-white font-medium truncate">{host.hostname}</span>

        {/* IP */}
        {host.ip && <span className="font-mono text-[9px] text-gray-500 shrink-0">({host.ip})</span>}

        {/* Proxy badge */}
        {host.proxy && (
          <span className="text-[8px] px-1.5 py-0 rounded border border-orange-500/30 bg-orange-500/10 text-orange-400 uppercase tracking-wider shrink-0">
            {host.proxy.vendor} {host.proxy.role === "cdn" ? "CDN" : host.proxy.role === "load_balancer" ? "LB" : "PROXY"}
          </span>
        )}

        {/* Defense badges */}
        {host.defenses.length > 0 && (
          <span className="text-[8px] px-1.5 py-0 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400 shrink-0">
            <Shield size={8} className="inline mr-0.5" />{host.defenses.length}
          </span>
        )}

        {/* Spacer */}
        <span className="flex-1" />

        {/* Tech stack (compact) */}
        {host.technologies.length > 0 && (
          <span className="text-[8px] text-gray-500 font-mono truncate max-w-[150px] shrink-0">
            {host.technologies.slice(0, 3).join(" · ")}
            {host.technologies.length > 3 && ` +${host.technologies.length - 3}`}
          </span>
        )}

        {/* Finding count badges */}
        <div className="flex items-center gap-1 shrink-0">
          {findingCounts.critical && <span className="text-[8px] font-mono font-bold text-red-400">{findingCounts.critical}C</span>}
          {findingCounts.high && <span className="text-[8px] font-mono font-bold text-orange-400">{findingCounts.high}H</span>}
          {findingCounts.medium && <span className="text-[8px] font-mono text-amber-400">{findingCounts.medium}M</span>}
          {findingCounts.low && <span className="text-[8px] font-mono text-emerald-400">{findingCounts.low}L</span>}
        </div>

        {/* Port count */}
        <span className="text-[9px] font-mono text-gray-500 shrink-0">{host.services.length} ports</span>
      </button>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="border-t border-[#1A2332]/50">
          {/* Services Section */}
          {host.services.length > 0 && (
            <div className="border-b border-[#1A2332]/30">
              <div className="px-3 py-1 text-[8px] uppercase tracking-widest text-gray-600 bg-[#0A0E14]/50">
                OPEN PORTS ({host.services.length})
              </div>
              <div className="divide-y divide-[#1A2332]/20">
                {host.services.map(svc => (
                  <ServiceRow key={svc.id} service={svc} />
                ))}
              </div>
            </div>
          )}

          {/* Findings Section */}
          {host.findings.length > 0 && (
            <div>
              <div className="px-3 py-1 text-[8px] uppercase tracking-widest text-gray-600 bg-[#0A0E14]/50">
                FINDINGS ({host.findings.length})
              </div>
              <div className="divide-y divide-[#1A2332]/20">
                {host.findings.map(f => (
                  <FindingRow key={f.id} finding={f} onClick={() => onFindingClick?.(f)} />
                ))}
              </div>
            </div>
          )}

          {/* Technologies */}
          {host.technologies.length > 0 && (
            <div className="px-3 py-1.5 flex flex-wrap gap-1 border-t border-[#1A2332]/30">
              {host.technologies.map((tech, i) => (
                <span key={i} className="text-[8px] px-1.5 py-0 rounded border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 font-mono">
                  {tech}
                </span>
              ))}
            </div>
          )}

          {/* OS / Platform */}
          {(host.os || host.platform) && (
            <div className="px-3 py-1 text-[9px] text-gray-500 font-mono border-t border-[#1A2332]/30">
              {host.os && <span>OS: {host.os}</span>}
              {host.os && host.platform && <span className="mx-2">|</span>}
              {host.platform && <span>Platform: {host.platform}</span>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatActorRow({ actor }: { actor: StructuredThreatActor }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 border border-[#1A2332] text-[10px] font-mono">
      <Skull size={10} className="text-red-400 shrink-0" />
      <span className="text-red-300 font-medium">{actor.name}</span>
      {actor.threatLevel && (
        <SeverityBadge severity={actor.threatLevel as SeverityLevel} />
      )}
      {actor.matchScore && (
        <span className="text-gray-500">{actor.matchScore}% match</span>
      )}
      {actor.mitreIds && actor.mitreIds.length > 0 && (
        <span className="text-violet-400/60 text-[8px]">{actor.mitreIds.slice(0, 3).join(", ")}</span>
      )}
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

export default function StructuredLiveView({
  nodes,
  edges,
  mode,
  onNodeClick,
  isScanning,
  liveEventCount,
}: StructuredLiveViewProps) {
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<"all" | "critical" | "high" | "findings">("all");
  const prevNodeCountRef = useRef(0);

  // Build structured data from graph nodes
  const structured = useMemo(() => buildStructuredData(nodes, edges), [nodes, edges]);

  // Auto-expand hosts with critical/high findings
  useEffect(() => {
    const autoExpand = new Set<string>();
    for (const host of structured.hosts) {
      if (host.findings.some(f => f.severity === "critical" || f.severity === "high")) {
        autoExpand.add(host.id);
      }
    }
    if (autoExpand.size > 0 && expandedHosts.size === 0) {
      setExpandedHosts(autoExpand);
    }
  }, [structured.hosts]);

  // Track new nodes for live indicator
  useEffect(() => {
    prevNodeCountRef.current = nodes.length;
  }, [nodes.length]);

  const toggleHost = useCallback((hostId: string) => {
    setExpandedHosts(prev => {
      const next = new Set(prev);
      if (next.has(hostId)) next.delete(hostId);
      else next.add(hostId);
      return next;
    });
  }, []);

  const expandAll = useCallback(() => {
    setExpandedHosts(new Set(structured.hosts.map(h => h.id)));
  }, [structured.hosts]);

  const collapseAll = useCallback(() => {
    setExpandedHosts(new Set());
  }, []);

  // Filter hosts
  const filteredHosts = useMemo(() => {
    if (filter === "all") return structured.hosts;
    if (filter === "critical") return structured.hosts.filter(h => h.findings.some(f => f.severity === "critical"));
    if (filter === "high") return structured.hosts.filter(h => h.findings.some(f => f.severity === "critical" || f.severity === "high"));
    if (filter === "findings") return structured.hosts.filter(h => h.findings.length > 0);
    return structured.hosts;
  }, [structured.hosts, filter]);

  const handleFindingClick = useCallback((finding: StructuredFinding) => {
    // Find the original node and emit click
    const node = nodes.find(n => n.id === finding.id);
    if (node && onNodeClick) onNodeClick(node);
  }, [nodes, onNodeClick]);

  return (
    <div className="h-full flex flex-col bg-[#0A0E14] overflow-hidden font-mono">
      {/* Stats Bar — responsive: wraps on narrow viewports */}
      <div className="shrink-0 border-b border-[#1A2332] px-2 sm:px-4 py-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px] uppercase tracking-widest overflow-x-auto">
        <div className="flex items-center gap-1.5 shrink-0">
          <Globe size={10} className="text-teal-400" />
          <span className="text-white font-bold truncate max-w-[120px] sm:max-w-[200px]">{structured.domain}</span>
        </div>
        <div className="h-4 w-px bg-[#1A2332] hidden sm:block" />
        <span className="text-gray-400 shrink-0">
          <span className="text-blue-400 font-bold">{structured.stats.totalHosts}</span> hosts
        </span>
        <span className="text-gray-400 shrink-0">
          <span className="text-cyan-400 font-bold">{structured.stats.totalServices}</span> ports
        </span>
        <span className="text-gray-400 shrink-0">
          <span className="text-amber-400 font-bold">{structured.stats.totalFindings}</span> findings
        </span>
        {structured.stats.criticalCount > 0 && (
          <span className="text-red-400 font-bold shrink-0">{structured.stats.criticalCount} CRIT</span>
        )}
        {structured.stats.highCount > 0 && (
          <span className="text-orange-400 font-bold shrink-0">{structured.stats.highCount} HIGH</span>
        )}

        <div className="flex-1 min-w-[8px]" />

        {/* Live indicator */}
        {isScanning && (
          <div className="flex items-center gap-1.5 shrink-0">
            <div className="w-1.5 h-1.5 rounded-full bg-teal-400" />
            <span className="text-teal-400">LIVE</span>
            {liveEventCount != null && liveEventCount > 0 && (
              <span className="text-gray-500">{liveEventCount} events</span>
            )}
          </div>
        )}

        {/* Filter */}
        <div className="flex items-center gap-0.5 sm:gap-1 border border-[#1A2332] p-0.5 shrink-0">
          {(["all", "findings", "high", "critical"] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-1.5 sm:px-2 py-0.5 text-[8px] uppercase tracking-wider transition-colors ${
                filter === f ? "bg-[#1A2332] text-teal-400" : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Expand/Collapse */}
        <button onClick={expandAll} className="text-[8px] text-gray-500 hover:text-teal-400 transition-colors uppercase shrink-0 hidden sm:block">
          Expand All
        </button>
        <button onClick={collapseAll} className="text-[8px] text-gray-500 hover:text-teal-400 transition-colors uppercase shrink-0 hidden sm:block">
          Collapse
        </button>
      </div>

      {/* Host List */}
      <div className="flex-1 overflow-y-auto">
        {/* Threat Actors (if any) */}
        {structured.threatActors.length > 0 && (
          <div className="border-b border-[#1A2332] p-2">
            <div className="text-[8px] uppercase tracking-widest text-gray-600 px-1 mb-1">
              THREAT ACTORS ({structured.threatActors.length})
            </div>
            <div className="space-y-1">
              {structured.threatActors.map(actor => (
                <ThreatActorRow key={actor.id} actor={actor} />
              ))}
            </div>
          </div>
        )}

        {/* Hosts */}
        <div className="divide-y divide-[#1A2332]/50 p-2 space-y-1">
          {filteredHosts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-600">
              <Network size={32} className="mb-3 opacity-30" />
              <span className="text-[10px] uppercase tracking-widest">
                {nodes.length === 0 ? "No data available" : "No hosts match filter"}
              </span>
              {isScanning && nodes.length === 0 && (
                <span className="text-[9px] text-gray-700 mt-1">Waiting for scan results...</span>
              )}
            </div>
          ) : (
            filteredHosts.map(host => (
              <HostCard
                key={host.id}
                host={host}
                isExpanded={expandedHosts.has(host.id)}
                onToggle={() => toggleHost(host.id)}
                onFindingClick={handleFindingClick}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
