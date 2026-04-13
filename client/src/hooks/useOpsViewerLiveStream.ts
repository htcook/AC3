/**
 * useOpsViewerLiveStream — Real-time progressive rendering for the Ops Viewer
 * ═══════════════════════════════════════════════════════════════════════════
 * Subscribes to WebSocket events for an active engagement and incrementally
 * adds nodes/edges to the BattlespaceEngine as discoveries happen in real-time.
 *
 * Event → Node/Edge mapping:
 * - recon:finding       → host + service + vulnerability nodes
 * - exploit:fired       → exploit edge (attack in progress)
 * - exploit:result      → updates exploit edge (success/fail)
 * - exploit:session_opened → agent node + c2_channel edge
 * - agent:deployed      → agent node + c2_channel edge
 * - agent:checkin       → updates agent node status
 * - credential:found    → credential node + enables edge
 * - engagement:phase_changed → phase indicator update
 * - pipeline:step_complete → scan progress nodes
 * - lateral:movement_executed → pivot edge
 * - privesc:escalation_found → escalation edge
 * - opsec:burn_detected → defense/tap_point node
 */

import { useEffect, useRef, useCallback } from "react";
import { useWebSocket, type WsEvent, type WsEventType } from "./useWebSocket";
import type { BattlespaceNode, BattlespaceEdge, BattlespaceNodeType, SeverityLevel } from "@/lib/battlespace-types";

/** Events that produce graph updates */
const GRAPH_EVENT_TYPES: WsEventType[] = [
  "recon:finding",
  "recon:started",
  "recon:complete",
  "exploit:fired",
  "exploit:result",
  "exploit:session_opened",
  "agent:deployed",
  "agent:checkin",
  "agent:lost",
  "credential:found",
  "credential:validated",
  "engagement:phase_changed",
  "engagement:progress_update",
  "pipeline:step_complete",
  "pipeline:started",
  "pipeline:finished",
  "lateral:pivot_planned",
  "lateral:tunnel_opened",
  "lateral:movement_executed",
  "privesc:escalation_found",
  "privesc:kerberos_attack",
  "opsec:burn_detected",
  "opsec:threshold_warning",
  "c2:agent_checkin",
  "c2:ability_executed",
  "c2:operation_update",
  "operation:started",
  "operation:step_complete",
  "operation:finished",
];

interface LiveStreamOptions {
  engagementId: number | null;
  /** The engine's addNodes method — call to incrementally add nodes/edges */
  onNodesDiscovered?: (nodes: BattlespaceNode[], edges: BattlespaceEdge[]) => void;
  /** Called when engagement phase changes */
  onPhaseChanged?: (phase: string, previousPhase: string) => void;
  /** Called with live event count for status display */
  onEventCount?: (count: number) => void;
  enabled?: boolean;
}

/** Deduplicate node IDs already added to the engine */
const addedNodeIds = new Set<string>();
const addedEdgeKeys = new Set<string>();

function edgeKey(src: string, tgt: string, type: string): string {
  return `${src}→${tgt}:${type}`;
}

function makeSeverity(sev?: string): SeverityLevel {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

/**
 * Convert a WebSocket event into Ops Viewer nodes and edges.
 * Returns { nodes, edges } to be added to the engine.
 */
function eventToGraphDelta(event: WsEvent): { nodes: BattlespaceNode[]; edges: BattlespaceEdge[] } {
  const nodes: BattlespaceNode[] = [];
  const edges: BattlespaceEdge[] = [];
  const d = event.data || {};

  switch (event.type) {
    // ── Recon findings: hosts, services, vulns ──────────────────────
    case "recon:finding": {
      const target = d.target || d.host || d.ip || d.domain;
      if (!target) break;

      // Host node
      const hostId = `host-${target}`;
      if (!addedNodeIds.has(hostId)) {
        addedNodeIds.add(hostId);
        nodes.push({
          id: hostId,
          type: "host",
          label: target,
          hostname: target,
          severity: makeSeverity(d.severity),
          weaknessLevel: 0,
          priorityScore: 0,
          tags: ["LIVE_DISCOVERY"],
        });
      }

      // Service node (if port info present)
      if (d.port || d.service) {
        const svcId = `svc-${target}-${d.port || d.service}`;
        if (!addedNodeIds.has(svcId)) {
          addedNodeIds.add(svcId);
          nodes.push({
            id: svcId,
            type: "service",
            label: `${d.service || "svc"}:${d.port || "?"}`,
            hostname: target,
            severity: "info",
            weaknessLevel: 0,
            priorityScore: 0,
            tags: ["LIVE_DISCOVERY"],
          });
          const ek = edgeKey(hostId, svcId, "network_link");
          if (!addedEdgeKeys.has(ek)) {
            addedEdgeKeys.add(ek);
            edges.push({
              source: hostId,
              target: svcId,
              type: "network_link",
              weight: 1,
              label: `${d.port || ""}/${d.protocol || "tcp"}`,
              protocol: (d.protocol || "tcp") as any,
            });
          }
        }
      }

      // Vulnerability node (if vuln data present)
      if (d.vulnerability || d.cve || d.templateId || d.finding) {
        const vulnLabel = d.vulnerability || d.cve || d.templateId || d.finding;
        const vulnId = `vuln-${target}-${vulnLabel}`;
        if (!addedNodeIds.has(vulnId)) {
          addedNodeIds.add(vulnId);
          nodes.push({
            id: vulnId,
            type: "vulnerability",
            label: vulnLabel,
            hostname: target,
            severity: makeSeverity(d.severity),
            weaknessLevel: d.severity === "critical" ? 1.0 : d.severity === "high" ? 0.7 : 0.3,
            priorityScore: d.severity === "critical" ? 10 : d.severity === "high" ? 7 : 3,
            tags: ["LIVE_DISCOVERY"],
          });
          const svcId = d.port ? `svc-${target}-${d.port}` : hostId;
          const ek = edgeKey(svcId, vulnId, "exploits");
          if (!addedEdgeKeys.has(ek)) {
            addedEdgeKeys.add(ek);
            edges.push({
              source: svcId,
              target: vulnId,
              type: "exploits",
              weight: d.severity === "critical" ? 3 : 2,
              label: vulnLabel,
            });
          }
        }
      }

      // Subdomain node
      if (d.subdomain) {
        const subId = `sub-${d.subdomain}`;
        if (!addedNodeIds.has(subId)) {
          addedNodeIds.add(subId);
          nodes.push({
            id: subId,
            type: "subdomain",
            label: d.subdomain,
            hostname: d.subdomain,
            severity: "info",
            weaknessLevel: 0,
            priorityScore: 0,
            tags: ["LIVE_DISCOVERY"],
          });
          const ek = edgeKey(subId, hostId, "dns_resolve");
          if (!addedEdgeKeys.has(ek)) {
            addedEdgeKeys.add(ek);
            edges.push({ source: subId, target: hostId, type: "dns_resolve", weight: 1 });
          }
        }
      }

      // Technology/proxy detection from finding
      if (d.technology || d.waf || d.cdn) {
        const techName = d.technology || d.waf || d.cdn;
        const proxyPatterns = /nginx|haproxy|cloudflare|akamai|aws.*(?:alb|elb|cloudfront)|varnish|traefik|envoy|f5|imperva|incapsula|sucuri|fastly|kong|caddy|squid/i;
        if (proxyPatterns.test(techName)) {
          const proxyId = `proxy-${techName.toLowerCase().replace(/\s+/g, "-")}-${target}`;
          if (!addedNodeIds.has(proxyId)) {
            addedNodeIds.add(proxyId);
            nodes.push({
              id: proxyId,
              type: "proxy",
              label: techName,
              hostname: target,
              severity: "info",
              weaknessLevel: 0,
              priorityScore: 0,
              proxyRole: d.cdn ? "cdn" : d.waf ? "waf_inline" : "reverse_proxy",
              tags: ["LIVE_DISCOVERY", "PROXY"],
            });
            const ek = edgeKey(proxyId, hostId, "proxies_to");
            if (!addedEdgeKeys.has(ek)) {
              addedEdgeKeys.add(ek);
              edges.push({ source: proxyId, target: hostId, type: "proxies_to", weight: 2, label: techName });
            }
          }
        }
      }
      break;
    }

    // ── Exploit fired: attack edge in progress ──────────────────────
    case "exploit:fired": {
      const target = d.targetIp || d.target || d.host;
      const module = d.module || d.exploit || "exploit";
      if (!target) break;

      const hostId = `host-${target}`;
      // Ensure host exists
      if (!addedNodeIds.has(hostId)) {
        addedNodeIds.add(hostId);
        nodes.push({
          id: hostId, type: "host", label: target, hostname: target,
          severity: "high", weaknessLevel: 0.5, priorityScore: 5,
          tags: ["LIVE_DISCOVERY", "UNDER_ATTACK"],
        });
      }

      const exploitEdgeId = `exploit-${module}-${target}`;
      const ek = edgeKey("platform", hostId, `exploits:${module}`);
      if (!addedEdgeKeys.has(ek)) {
        addedEdgeKeys.add(ek);
        edges.push({
          source: hostId,
          target: hostId, // self-loop indicates active attack
          type: "exploits",
          weight: 3,
          label: `⚡ ${module}`,
          killChainPhase: "exploitation",
        });
      }
      break;
    }

    // ── Exploit result: update success/fail ──────────────────────────
    case "exploit:result": {
      const target = d.targetIp || d.target || d.host;
      if (!target) break;
      const hostId = `host-${target}`;
      // If success, mark host as compromised
      if (d.success) {
        const pivotId = `pivot-${target}`;
        if (!addedNodeIds.has(pivotId)) {
          addedNodeIds.add(pivotId);
          nodes.push({
            id: pivotId, type: "pivot_point", label: `Compromised: ${target}`,
            hostname: target, severity: "critical", weaknessLevel: 1.0, priorityScore: 10,
            tags: ["COMPROMISED", "LIVE_DISCOVERY"],
          });
          edges.push({
            source: hostId, target: pivotId, type: "enables", weight: 3,
            label: d.module || "exploit", killChainPhase: "exploitation",
          });
        }
      }
      break;
    }

    // ── Agent deployed / session opened ──────────────────────────────
    case "exploit:session_opened":
    case "agent:deployed": {
      const host = d.host || d.targetIp || d.target;
      const paw = d.paw || d.sessionId || d.agentId || `agent-${Date.now()}`;
      if (!host) break;

      const hostId = `host-${host}`;
      const agentId = `agent-${paw}`;
      if (!addedNodeIds.has(agentId)) {
        addedNodeIds.add(agentId);
        nodes.push({
          id: agentId, type: "agent", label: `Agent ${paw}`,
          hostname: host, severity: "critical", weaknessLevel: 1.0, priorityScore: 10,
          tags: ["LIVE_DISCOVERY", "C2_IMPLANT"],
        });
        edges.push({
          source: hostId, target: agentId, type: "enables", weight: 3,
          label: "implant deployed", killChainPhase: "installation",
        });
      }

      // C2 channel back to our infrastructure
      const c2Id = "c2-caldera";
      if (!addedNodeIds.has(c2Id)) {
        addedNodeIds.add(c2Id);
        nodes.push({
          id: c2Id, type: "c2_server", label: "Caldera C2",
          severity: "info", weaknessLevel: 0, priorityScore: 0,
          tags: ["OUR_INFRA"],
        });
      }
      const c2ek = edgeKey(agentId, c2Id, "c2_channel");
      if (!addedEdgeKeys.has(c2ek)) {
        addedEdgeKeys.add(c2ek);
        edges.push({
          source: agentId, target: c2Id, type: "c2_channel", weight: 2,
          label: `C2 callback: ${paw}`, killChainPhase: "command_and_control",
        });
      }
      break;
    }

    // ── Agent check-in: heartbeat pulse ─────────────────────────────
    case "agent:checkin":
    case "c2:agent_checkin": {
      // No new nodes — just a heartbeat. Could update agent node status.
      break;
    }

    // ── Agent lost: mark as dead ────────────────────────────────────
    case "agent:lost":
    case "c2:agent_lost": {
      const paw = d.paw || d.agentId;
      if (!paw) break;
      const agentId = `agent-${paw}`;
      // We can't remove nodes, but we could add a "lost" indicator
      // For now, add a defense node indicating detection
      const defId = `def-detected-${paw}`;
      if (!addedNodeIds.has(defId)) {
        addedNodeIds.add(defId);
        nodes.push({
          id: defId, type: "defense", label: `Agent ${paw} detected/lost`,
          severity: "high", weaknessLevel: 0, priorityScore: 0,
          tags: ["BLUE_TEAM_WIN"],
        });
        if (addedNodeIds.has(agentId)) {
          edges.push({
            source: defId, target: agentId, type: "protects", weight: 2,
            label: "agent terminated",
          });
        }
      }
      break;
    }

    // ── Credential found ────────────────────────────────────────────
    case "credential:found":
    case "credential:validated": {
      const target = d.target || d.host;
      const username = d.username || d.credential || "cred";
      const credId = `cred-${username}-${target || "unknown"}`;
      if (!addedNodeIds.has(credId)) {
        addedNodeIds.add(credId);
        nodes.push({
          id: credId, type: "credential", label: `${username}@${target || "?"}`,
          hostname: target, severity: "high", weaknessLevel: 0.8, priorityScore: 8,
          tags: ["LIVE_DISCOVERY", "CREDENTIAL"],
        });
        if (target) {
          const hostId = `host-${target}`;
          edges.push({
            source: credId, target: hostId, type: "enables", weight: 2,
            label: `${d.tool || "harvested"}: ${username}`, killChainPhase: "exploitation",
          });
        }
      }
      break;
    }

    // ── Lateral movement ────────────────────────────────────────────
    case "lateral:movement_executed": {
      const src = d.sourceHost || d.source;
      const tgt = d.targetHost || d.target;
      if (!src || !tgt) break;

      const srcId = `host-${src}`;
      const tgtId = `host-${tgt}`;
      // Ensure both hosts exist
      for (const [id, label] of [[srcId, src], [tgtId, tgt]] as const) {
        if (!addedNodeIds.has(id)) {
          addedNodeIds.add(id);
          nodes.push({
            id, type: "host", label, hostname: label,
            severity: "high", weaknessLevel: 0.5, priorityScore: 5,
            tags: ["LIVE_DISCOVERY"],
          });
        }
      }
      const ek = edgeKey(srcId, tgtId, "pivots_to");
      if (!addedEdgeKeys.has(ek)) {
        addedEdgeKeys.add(ek);
        edges.push({
          source: srcId, target: tgtId, type: "pivots_to", weight: 3,
          label: d.technique || "lateral move",
          killChainPhase: "lateral_movement",
        });
      }
      break;
    }

    // ── Privilege escalation ────────────────────────────────────────
    case "privesc:escalation_found":
    case "privesc:kerberos_attack": {
      const target = d.host || d.target;
      if (!target) break;
      const hostId = `host-${target}`;
      const escId = `esc-${d.technique || "privesc"}-${target}`;
      if (!addedNodeIds.has(escId)) {
        addedNodeIds.add(escId);
        nodes.push({
          id: escId, type: "vulnerability", label: `PrivEsc: ${d.technique || "unknown"}`,
          hostname: target, severity: "critical", weaknessLevel: 0.9, priorityScore: 9,
          tags: ["LIVE_DISCOVERY", "PRIVESC"],
        });
        edges.push({
          source: hostId, target: escId, type: "escalates", weight: 3,
          label: d.technique || "escalation", killChainPhase: "privilege_escalation",
        });
      }
      break;
    }

    // ── OPSEC burn detected: blue team interception ─────────────────
    case "opsec:burn_detected": {
      const indicator = d.indicator || d.description || "burn";
      const tapId = `tap-burn-${Date.now()}`;
      if (!addedNodeIds.has(tapId)) {
        addedNodeIds.add(tapId);
        nodes.push({
          id: tapId, type: "tap_point",
          label: `🔴 BURN: ${indicator}`,
          severity: "critical", weaknessLevel: 0, priorityScore: 0,
          isIntercepted: true,
          tapType: "ids_inline",
          interceptedBy: d.source || "Blue Team",
          tags: ["BLUE_TEAM", "BURN_DETECTED"],
        });
      }
      break;
    }

    // ── C2 operation events ─────────────────────────────────────────
    case "operation:started":
    case "c2:operation_update": {
      // These are informational — the operation is running
      break;
    }

    case "operation:step_complete":
    case "c2:ability_executed": {
      const host = d.host || d.paw;
      const ability = d.ability || d.abilityName || d.step || "ability";
      if (!host) break;
      // Add an edge showing the ability execution
      const hostId = `host-${host}`;
      const ek = edgeKey(hostId, hostId, `c2_exec:${ability}`);
      if (!addedEdgeKeys.has(ek)) {
        addedEdgeKeys.add(ek);
        edges.push({
          source: hostId, target: hostId, type: "enables", weight: 1,
          label: `C2: ${ability}`, killChainPhase: "actions_on_objectives",
        });
      }
      break;
    }

    // ── Pipeline progress ───────────────────────────────────────────
    case "pipeline:step_complete": {
      // Could add a phase indicator node, but these are high-frequency
      // Just track for event count
      break;
    }

    default:
      break;
  }

  return { nodes, edges };
}

/**
 * Hook: Subscribe to WebSocket events for an engagement and progressively
 * render discoveries in the Ops Viewer engine.
 */
export function useOpsViewerLiveStream(options: LiveStreamOptions) {
  const { engagementId, onNodesDiscovered, onPhaseChanged, onEventCount, enabled = true } = options;
  const eventCountRef = useRef(0);
  const processedEventsRef = useRef(new Set<string>());

  // Subscribe to the engagement channel + global
  const channels = engagementId
    ? [`engagement:${engagementId}`, "global"]
    : ["global"];

  const { events, lastEvent, status } = useWebSocket({
    channels,
    filterTypes: GRAPH_EVENT_TYPES,
    maxEvents: 500,
    showToasts: false, // Don't double-toast — EngagementOps already handles toasts
    enabled: enabled && !!engagementId,
  });

  // Process new events as they arrive
  useEffect(() => {
    if (!lastEvent || !onNodesDiscovered) return;

    // Deduplicate by event timestamp + type
    const eventKey = `${lastEvent.type}:${lastEvent.timestamp}:${JSON.stringify(lastEvent.data).slice(0, 100)}`;
    if (processedEventsRef.current.has(eventKey)) return;
    processedEventsRef.current.add(eventKey);

    // Keep processed set bounded
    if (processedEventsRef.current.size > 2000) {
      const arr = Array.from(processedEventsRef.current);
      processedEventsRef.current = new Set(arr.slice(-1000));
    }

    // Handle phase changes
    if (lastEvent.type === "engagement:phase_changed" && onPhaseChanged) {
      onPhaseChanged(lastEvent.data.newPhase, lastEvent.data.previousPhase);
    }

    // Convert event to graph delta
    const { nodes, edges } = eventToGraphDelta(lastEvent);
    if (nodes.length > 0 || edges.length > 0) {
      onNodesDiscovered(nodes, edges);
      eventCountRef.current += 1;
      onEventCount?.(eventCountRef.current);
    }
  }, [lastEvent, onNodesDiscovered, onPhaseChanged, onEventCount]);

  // Reset dedup sets when engagement changes
  useEffect(() => {
    addedNodeIds.clear();
    addedEdgeKeys.clear();
    eventCountRef.current = 0;
    processedEventsRef.current.clear();
  }, [engagementId]);

  return {
    isConnected: status === "connected",
    eventCount: eventCountRef.current,
    totalEvents: events.length,
  };
}
