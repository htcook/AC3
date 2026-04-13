/**
 * useWebSocket — React hook for real-time event streaming
 *
 * **SSE-first transport:** Connects via Server-Sent Events at /api/events/stream
 * as the primary transport. WebSocket (/ws/events) is attempted as an optional
 * upgrade only after SSE is confirmed working. This ensures instant connectivity
 * on platforms like DigitalOcean App Platform where WebSocket upgrades fail.
 *
 * Features:
 * - SSE primary transport with auto-reconnection and exponential backoff
 * - Optional WebSocket upgrade for bidirectional communication
 * - Channel subscription management
 * - Event filtering by type
 * - Connection status tracking
 * - Toast notifications for critical events
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { toast } from "sonner";

// ─── Types ──────────────────────────────────────────────────────────

export type WsEventType =
  | "exploit:fired"
  | "exploit:progress"
  | "exploit:result"
  | "exploit:session_opened"
  | "agent:deployed"
  | "agent:checkin"
  | "agent:lost"
  | "operation:started"
  | "operation:step_complete"
  | "operation:finished"
  | "recon:started"
  | "recon:complete"
  | "recon:finding"
  | "campaign:launched"
  | "campaign:email_sent"
  | "campaign:email_opened"
  | "campaign:link_clicked"
  | "campaign:creds_submitted"
  | "pipeline:started"
  | "pipeline:step_complete"
  | "pipeline:finished"
  | "domain:scan_complete"
  | "domain:typosquat_purchased"
  | "msf:server_provisioned"
  | "msf:server_ready"
  | "msf:server_destroyed"
  // OPSEC events
  | "opsec:action_scored"
  | "opsec:burn_detected"
  | "opsec:threshold_warning"
  | "opsec:risk_update"
  // Credential attack events
  | "credential:attack_started"
  | "credential:attack_complete"
  | "credential:found"
  | "credential:validated"
  // Lateral movement events
  | "lateral:pivot_planned"
  | "lateral:tunnel_opened"
  | "lateral:movement_executed"
  // Privilege escalation events
  | "privesc:analysis_complete"
  | "privesc:escalation_found"
  | "privesc:kerberos_attack"
  // C2 callback poller events
  | "c2:agent_checkin"
  | "c2:ability_executed"
  | "c2:operation_update"
  | "c2:agent_lost"
  | "c2:operation_complete"
  // Engagement workflow events
  | "engagement:phase_changed"
  | "engagement:handoff"
  | "engagement:timeline_event"
  | "engagement:progress_update"
  // Campaign advisor events
  | "advisor:recommendation"
  // Review queue events
  | "review:item_created"
  | "review:item_approved"
  | "review:item_rejected"
  | "review:item_deferred"
  | "review:bulk_approved"
  | "review:item_expired"
  // Job queue events
  | "job:enqueued"
  | "job:dispatched"
  | "job:completed"
  | "job:failed"
  | "job:cancelled"
  | "job:worker_registered"
  | "job:worker_lost"
  // System events
  | "system:notification"
  | "system:alert"
  // Cockpit timeline events
  | "cockpit:timeline_event"
  | "cockpit:opsec_update"
  // Automation pipeline events
  | "automation:profile_generated"
  | "automation:profile_pushed"
  | "automation:playbook_triggered"
  | "automation:pipeline_run"
  | "automation:enrichment_complete"
  // Evidence integrity events
  | "evidence:gate_passed"
  | "evidence:gate_flagged"
  | "evidence:quarantined"
  | "evidence:chain_flushed"
  | "evidence:anchor_created"
  | "evidence:anchor_verified"
  | "evidence:tamper_detected"
  // DI scan live stream events
  | "di:scan_started"
  | "di:stage_changed"
  | "di:asset_discovered"
  | "di:finding_detected"
  | "di:interception_detected"
  | "di:threat_matched"
  | "di:scan_complete"
  | "di:connector_progress";

export interface WsEvent {
  type: WsEventType;
  timestamp: number;
  engagementId?: number | null;
  data: Record<string, any>;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";
export type TransportMode = "websocket" | "sse" | "none";

interface UseWebSocketOptions {
  /** Channels to subscribe to (default: ["global"]) */
  channels?: string[];
  /** Event types to filter (default: all) */
  filterTypes?: WsEventType[];
  /** Max events to keep in buffer (default: 100) */
  maxEvents?: number;
  /** Show toast notifications for critical events (default: true) */
  showToasts?: boolean;
  /** Auto-reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  /** Enable connection (default: true) — set false to disable */
  enabled?: boolean;
}

// ─── Critical event types that trigger toast notifications ──────────

const TOAST_EVENT_TYPES: WsEventType[] = [
  "exploit:result",
  "agent:deployed",
  "agent:lost",
  "operation:finished",
  "recon:complete",
  "pipeline:finished",
  "msf:server_ready",
  "msf:server_destroyed",
  "system:alert",
  "opsec:burn_detected",
  "opsec:threshold_warning",
  "credential:found",
  "credential:attack_complete",
  "lateral:movement_executed",
  "privesc:escalation_found",
  "engagement:phase_changed",
  "advisor:recommendation",
  "review:item_created",
  "review:item_approved",
  "review:item_rejected",
  "job:completed",
  "job:failed",
  "job:worker_lost",
  "evidence:gate_flagged",
  "evidence:quarantined",
  "evidence:anchor_created",
  "evidence:tamper_detected",
];

function getToastInfo(event: WsEvent): { title: string; description: string; variant?: "default" | "destructive" } | null {
  switch (event.type) {
    case "exploit:result":
      return event.data.success
        ? { title: "Exploit Succeeded", description: `${event.data.module} on ${event.data.targetIp}` }
        : { title: "Exploit Failed", description: `${event.data.module}: ${event.data.error || "unknown error"}`, variant: "destructive" };
    case "agent:deployed":
      return { title: "Agent Deployed", description: `${event.data.paw} on ${event.data.host} (${event.data.platform})` };
    case "agent:lost":
      return { title: "Agent Lost", description: `${event.data.paw} on ${event.data.host}`, variant: "destructive" };
    case "operation:finished":
      return { title: "Operation Complete", description: `${event.data.name} — ${event.data.state}` };
    case "recon:complete":
      return { title: "Recon Complete", description: `${event.data.domain}: ${event.data.findings} findings` };
    case "pipeline:finished":
      return { title: "Pipeline Complete", description: `Engagement pipeline finished` };
    case "msf:server_ready":
      return { title: "Exploit Server Ready", description: `${event.data.name || "Server"} is online at ${event.data.ip || "unknown"}` };
    case "msf:server_destroyed":
      return { title: "Exploit Server Destroyed", description: `${event.data.name || "Server"} has been terminated`, variant: "destructive" };
    case "system:alert":
      return { title: event.data.title || "Alert", description: event.data.message || "", variant: event.data.severity === "critical" || event.data.severity === "error" ? "destructive" : "default" };
    case "opsec:burn_detected":
      return { title: "BURN DETECTED", description: `${event.data.indicator}: ${event.data.description}`, variant: "destructive" };
    case "opsec:threshold_warning":
      return { title: "OPSEC Threshold Warning", description: `Cumulative risk: ${event.data.cumulativeScore} — ${event.data.recommendation}`, variant: "destructive" };
    case "credential:found":
      return { title: "Credential Found", description: `${event.data.username}@${event.data.target} via ${event.data.tool}` };
    case "credential:attack_complete":
      return { title: "Credential Attack Complete", description: `${event.data.tool}: ${event.data.credentialsFound} found on ${event.data.target}` };
    case "lateral:movement_executed":
      return event.data.success
        ? { title: "Lateral Movement Success", description: `${event.data.sourceHost} → ${event.data.targetHost} via ${event.data.technique}` }
        : { title: "Lateral Movement Failed", description: `${event.data.technique} to ${event.data.targetHost}`, variant: "destructive" };
    case "privesc:escalation_found":
      return { title: "Privesc Path Found", description: `${event.data.technique} (${event.data.os}) — ${event.data.confidence}% confidence` };
    case "engagement:phase_changed":
      return { title: "Phase Changed", description: `${event.data.previousPhase} → ${event.data.newPhase}` };
    case "advisor:recommendation":
      return { title: "Campaign Advisor", description: event.data.recommendation?.slice(0, 80) || "New recommendation available" };
    case "review:item_created":
      return { title: "Review Required", description: `${event.data.category}: ${event.data.title?.slice(0, 60) || "New item"}` };
    case "review:item_approved":
      return { title: "Item Approved", description: `${event.data.title?.slice(0, 60) || "Review item"} by ${event.data.reviewedBy || "operator"}` };
    case "review:item_rejected":
      return { title: "Item Rejected", description: `${event.data.title?.slice(0, 60) || "Review item"}`, variant: "destructive" };
    case "job:completed":
      return { title: "Job Completed", description: `${event.data.type || "scan"} on ${event.data.workerHost || "worker"} (${event.data.durationMs || 0}ms)` };
    case "job:failed":
      return { title: "Job Failed", description: `${event.data.type || "scan"}: ${event.data.error || "unknown error"}`, variant: "destructive" };
    case "job:worker_lost":
      return { title: "Worker Lost", description: `${event.data.workerHost || "worker"} (${event.data.workerType || "unknown"})`, variant: "destructive" };
    case "evidence:gate_flagged":
      return { title: "Evidence Flagged", description: `${event.data.evidenceType || "evidence"} from ${event.data.sourceTool || "unknown"} — score: ${event.data.score}`, variant: "destructive" };
    case "evidence:quarantined":
      return { title: "Evidence Quarantined", description: `${event.data.evidenceType || "evidence"}: ${event.data.reason || "integrity check failed"}`, variant: "destructive" };
    case "evidence:anchor_created":
      return { title: "Integrity Anchor Created", description: `Chain length: ${event.data.chainLength || 0} — Merkle root sealed` };
    case "evidence:tamper_detected":
      return { title: "TAMPER DETECTED", description: `Evidence ${event.data.evidenceId || "unknown"} hash mismatch`, variant: "destructive" };
    default:
      return null;
  }
}

// ─── SSE-First Transport ─────────────────────────────────────────────

/**
 * Delay (ms) before attempting optional WebSocket upgrade after SSE connects.
 * Keeps SSE as primary; WS upgrade is a nice-to-have for bidirectional comms.
 */
const WS_UPGRADE_DELAY = 10_000;

/**
 * If the WebSocket upgrade fails this many times, stop trying and stay on SSE.
 */
const WS_UPGRADE_MAX_FAILURES = 2;

// ─── Hook ───────────────────────────────────────────────────────────

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    channels = ["global"],
    filterTypes,
    maxEvents = 100,
    showToasts = true,
    autoReconnect = true,
    enabled = true,
  } = options;

  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);
  const [transport, setTransport] = useState<TransportMode>("none");
  const wsRef = useRef<WebSocket | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wsUpgradeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sseReconnectAttemptsRef = useRef(0);
  const wsUpgradeFailuresRef = useRef(0);
  const channelsRef = useRef(channels);
  const lastSseIdRef = useRef(0);
  const mountedRef = useRef(true);
  const transportRef = useRef<TransportMode>("none");
  const enabledRef = useRef(enabled);
  const autoReconnectRef = useRef(autoReconnect);

  // Keep refs up to date without causing re-renders
  channelsRef.current = channels;
  enabledRef.current = enabled;
  autoReconnectRef.current = autoReconnect;

  // ─── Shared event handler (stable via ref) ────────────────────
  const handleEventRef = useRef<(event: WsEvent) => void>(() => {});
  handleEventRef.current = (event: WsEvent) => {
    // Filter by type if specified
    if (filterTypes && filterTypes.length > 0 && !filterTypes.includes(event.type)) {
      return;
    }

    setLastEvent(event);
    setEvents((prev) => {
      const next = [event, ...prev];
      return next.length > maxEvents ? next.slice(0, maxEvents) : next;
    });

    // Show toast for critical events
    if (showToasts && TOAST_EVENT_TYPES.includes(event.type)) {
      const toastInfo = getToastInfo(event);
      if (toastInfo) {
        if (toastInfo.variant === "destructive") {
          toast.error(toastInfo.title, { description: toastInfo.description });
        } else {
          toast.success(toastInfo.title, { description: toastInfo.description });
        }
      }
    }
  };

  // ─── Forward-declared refs for stable cross-references ────────
  const connectSSERef = useRef<() => void>(() => {});
  const attemptWsUpgradeRef = useRef<() => void>(() => {});

  // ─── Optional WebSocket Upgrade ───────────────────────────────
  attemptWsUpgradeRef.current = () => {
    if (!enabledRef.current || !mountedRef.current) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    if (wsUpgradeFailuresRef.current >= WS_UPGRADE_MAX_FAILURES) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/events`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      // Give WS 5 seconds to open, otherwise abort
      const upgradeTimeout = setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          ws.close();
        }
      }, 5000);

      ws.onopen = () => {
        clearTimeout(upgradeTimeout);
        if (!mountedRef.current) { ws.close(); return; }

        // WS connected — promote to primary transport, close SSE
        console.log("[EventStream] WebSocket upgrade succeeded, switching from SSE");
        wsUpgradeFailuresRef.current = 0;
        transportRef.current = "websocket";
        setTransport("websocket");

        // Close SSE since WS is now active
        if (sseRef.current) {
          sseRef.current.close();
          sseRef.current = null;
        }

        // Subscribe to channels
        if (channelsRef.current.length > 0) {
          ws.send(JSON.stringify({ action: "subscribe", channels: channelsRef.current }));
        }
      };

      ws.onmessage = (msg) => {
        try {
          const event: WsEvent = JSON.parse(msg.data);
          handleEventRef.current(event);
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        clearTimeout(upgradeTimeout);
        wsRef.current = null;

        if (!mountedRef.current) return;

        // If WS was the active transport, fall back to SSE
        if (transportRef.current === "websocket" || !sseRef.current) {
          console.log("[EventStream] WebSocket closed, reverting to SSE");
          wsUpgradeFailuresRef.current++;
          transportRef.current = "sse";
          setTransport("sse");
          // Reconnect SSE if it was closed
          if (!sseRef.current) {
            connectSSERef.current();
          }
        } else {
          // WS upgrade failed silently — SSE is still active, no disruption
          wsUpgradeFailuresRef.current++;
          console.log(`[EventStream] WebSocket upgrade failed (${wsUpgradeFailuresRef.current}/${WS_UPGRADE_MAX_FAILURES}), staying on SSE`);
        }
      };

      ws.onerror = () => {
        clearTimeout(upgradeTimeout);
        // Silently handled by onclose — no user-visible error since SSE is still active
      };
    } catch {
      wsUpgradeFailuresRef.current++;
      console.log(`[EventStream] WebSocket upgrade exception (${wsUpgradeFailuresRef.current}/${WS_UPGRADE_MAX_FAILURES}), staying on SSE`);
    }
  };

  // ─── SSE Connect (Primary Transport) ──────────────────────────
  connectSSERef.current = () => {
    if (!enabledRef.current) return;
    if (sseRef.current) return;

    try {
      const channelStr = channelsRef.current.join(",");
      const url = `/api/events/stream?channels=${encodeURIComponent(channelStr)}`;
      const sse = new EventSource(url);
      sseRef.current = sse;
      setStatus("connecting");
      transportRef.current = "sse";
      setTransport("sse");

      sse.addEventListener("connected", () => {
        if (!mountedRef.current) return;
        setStatus("connected");
        sseReconnectAttemptsRef.current = 0;
        console.log("[EventStream] Connected via SSE (primary transport)");

        // After SSE is confirmed working, optionally try WebSocket upgrade
        if (wsUpgradeFailuresRef.current < WS_UPGRADE_MAX_FAILURES) {
          if (wsUpgradeTimeoutRef.current) clearTimeout(wsUpgradeTimeoutRef.current);
          wsUpgradeTimeoutRef.current = setTimeout(() => attemptWsUpgradeRef.current(), WS_UPGRADE_DELAY);
        }
      });

      sse.addEventListener("message", (msg) => {
        try {
          const event: WsEvent = JSON.parse(msg.data);
          if (msg.lastEventId) {
            lastSseIdRef.current = parseInt(msg.lastEventId) || 0;
          }
          handleEventRef.current(event);
        } catch {
          // Ignore malformed messages
        }
      });

      sse.onerror = () => {
        if (sse.readyState === EventSource.CLOSED) {
          sseRef.current = null;
          if (!mountedRef.current) return;

          // Only show error if WS isn't active as backup
          if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
            setStatus("error");
          }

          // Exponential backoff reconnect
          if (autoReconnectRef.current && enabledRef.current) {
            const attempts = sseReconnectAttemptsRef.current;
            const delay = Math.min(5000 * Math.pow(2, attempts), 60000);
            sseReconnectAttemptsRef.current++;
            console.log(`[EventStream] SSE reconnect attempt ${attempts + 1}, waiting ${delay}ms`);
            reconnectTimeoutRef.current = setTimeout(() => connectSSERef.current(), delay);
          }
        }
      };
    } catch {
      setStatus("error");
    }
  };

  // ─── Stable public API (never changes reference) ──────────────
  const connect = useCallback(() => {
    connectSSERef.current();
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsUpgradeTimeoutRef.current) {
      clearTimeout(wsUpgradeTimeoutRef.current);
      wsUpgradeTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (sseRef.current) {
      sseRef.current.close();
      sseRef.current = null;
    }
    transportRef.current = "none";
    setStatus("disconnected");
    setTransport("none");
  }, []);

  const subscribe = useCallback((channel: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: "subscribe", channel }));
    }
  }, []);

  const unsubscribe = useCallback((channel: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: "unsubscribe", channel }));
    }
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setLastEvent(null);
  }, []);

  // Connect on mount, disconnect on unmount
  useEffect(() => {
    mountedRef.current = true;
    if (enabled) {
      connectSSERef.current();
    }
    return () => {
      mountedRef.current = false;
      disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  // Re-subscribe when channels change (compare serialized value)
  const channelKey = channels.join(",");
  const prevChannelKeyRef = useRef(channelKey);
  useEffect(() => {
    // Skip the initial run — connection is handled by the mount effect
    if (prevChannelKeyRef.current === channelKey) return;
    prevChannelKeyRef.current = channelKey;

    // WebSocket: send subscribe message
    if (wsRef.current?.readyState === WebSocket.OPEN && channels.length > 0) {
      wsRef.current.send(JSON.stringify({ action: "subscribe", channels }));
    }
    // SSE: reconnect with new channels (SSE channels are set at connect time)
    if (sseRef.current && transportRef.current === "sse") {
      sseRef.current.close();
      sseRef.current = null;
      connectSSERef.current();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channelKey]);

  // Memoize event counts by type
  const eventCounts = useMemo(() => {
    const counts: Partial<Record<WsEventType, number>> = {};
    for (const e of events) {
      counts[e.type] = (counts[e.type] || 0) + 1;
    }
    return counts;
  }, [events]);

  return {
    status,
    events,
    lastEvent,
    eventCounts,
    transport,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    clearEvents,
    isConnected: status === "connected",
  };
}

// ─── Specialized hooks for specific pages ───────────────────────────

/** Hook for the Kill Chain Timeline page — all events */
export function useTimelineEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  return useWebSocket({ channels, maxEvents: 200 });
}

/** Hook for the Dashboard — summary events only */
export function useDashboardEvents() {
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "exploit:result",
      "agent:deployed",
      "agent:checkin",
      "agent:lost",
      "operation:finished",
      "recon:complete",
      "pipeline:finished",
      "campaign:launched",
      "system:alert",
      "system:notification",
      "automation:profile_generated",
      "automation:profile_pushed",
      "automation:playbook_triggered",
      "automation:pipeline_run",
      "automation:enrichment_complete",
    ],
    []
  );
  return useWebSocket({ filterTypes, maxEvents: 50 });
}

/** Hook for the Exploit Arsenal — exploit and agent events */
export function useExploitEvents() {
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "exploit:fired",
      "exploit:progress",
      "exploit:result",
      "exploit:session_opened",
      "agent:deployed",
    ],
    []
  );
  return useWebSocket({ filterTypes, maxEvents: 50 });
}

/** Hook for Exploit Servers page — server lifecycle events */
export function useMsfServerEvents() {
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "msf:server_provisioned",
      "msf:server_ready",
      "msf:server_destroyed",
      "exploit:fired",
      "exploit:result",
    ],
    []
  );
  return useWebSocket({ filterTypes, maxEvents: 30 });
}

// ─── OPSEC Dashboard hooks ──────────────────────────────────────────
/** Hook for the OPSEC Dashboard — real-time risk scoring events */
export function useOpsecEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => ["opsec:action_scored", "opsec:burn_detected", "opsec:threshold_warning", "opsec:risk_update"],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 100, showToasts: true });
}

// ─── Credential Attack hooks ────────────────────────────────────────
/** Hook for Credential Attacks page — credential attack events */
export function useCredentialEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => ["credential:attack_started", "credential:attack_complete", "credential:found", "credential:validated"],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 100 });
}

// ─── Lateral Movement hooks ─────────────────────────────────────────
/** Hook for Lateral Movement page — pivot and tunnel events */
export function useLateralMovementEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => ["lateral:pivot_planned", "lateral:tunnel_opened", "lateral:movement_executed"],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 50 });
}

// ─── Privilege Escalation hooks ─────────────────────────────────────
/** Hook for Privilege Escalation page — privesc analysis events */
export function usePrivescEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => ["privesc:analysis_complete", "privesc:escalation_found", "privesc:kerberos_attack"],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 50 });
}

// ─── Operator Cockpit hooks ────────────────────────────────────────
/** Hook for the Operator Cockpit — real-time timeline events from all sources */
export function useCockpitTimeline() {
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      // Scan/recon events
      "recon:started", "recon:complete", "recon:finding", "domain:scan_complete",
      // Exploit/agent events
      "exploit:fired", "exploit:result", "exploit:session_opened",
      "agent:deployed", "agent:checkin", "agent:lost",
      // Operation events
      "operation:started", "operation:step_complete", "operation:finished",
      // OPSEC events
      "opsec:action_scored", "opsec:burn_detected", "opsec:threshold_warning", "opsec:risk_update",
      // Credential events
      "credential:attack_started", "credential:attack_complete", "credential:found",
      // Lateral/privesc events
      "lateral:movement_executed", "privesc:escalation_found",
      // Campaign events
      "campaign:launched", "campaign:creds_submitted",
      // Engagement events
      "engagement:phase_changed", "engagement:timeline_event",
      // Pipeline events
      "pipeline:started", "pipeline:finished",
      // Job events
      "job:completed", "job:failed",
      // System events
      "system:alert", "system:notification",
      // Automation events
      "automation:profile_generated", "automation:profile_pushed",
      "automation:playbook_triggered", "automation:pipeline_run", "automation:enrichment_complete",
      // Cockpit-specific
      "cockpit:timeline_event", "cockpit:opsec_update",
    ],
    []
  );
  return useWebSocket({ filterTypes, maxEvents: 100, showToasts: true });
}

// ─── Engagement Workflow hooks ──────────────────────────────────────
/** Hook for Kill Chain Visualizer — engagement workflow events */
export function useEngagementWorkflowEvents(engagementId: number) {
  const channels = useMemo(
    () => ["global", `engagement:${engagementId}`],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => ["engagement:phase_changed", "engagement:handoff", "engagement:timeline_event", "engagement:progress_update"],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 100 });
}

// ─── Campaign Advisor hooks ─────────────────────────────────────────
/** Hook for Campaign Advisor — recommendation events */
export function useAdvisorEvents() {
  const filterTypes = useMemo<WsEventType[]>(
    () => ["advisor:recommendation"],
    []
  );
  return useWebSocket({ filterTypes, maxEvents: 20 });
}

// ─── Combined Operator Feed ─────────────────────────────────────────
/** Hook for Operator Home — all operational events in a unified feed */
export function useOperatorFeed(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "opsec:action_scored", "opsec:burn_detected", "opsec:threshold_warning",
      "credential:attack_complete", "credential:found",
      "lateral:movement_executed", "privesc:escalation_found",
      "exploit:result", "agent:deployed",
      "engagement:phase_changed", "engagement:handoff",
      "advisor:recommendation", "system:alert",
    ],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 100 });
}

// ─── Review Queue hooks ────────────────────────────────────────────
/** Hook for Review Queue page — real-time review item events */
export function useReviewQueueEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "review:item_created",
      "review:item_approved",
      "review:item_rejected",
      "review:item_deferred",
      "review:bulk_approved",
      "review:item_expired",
    ],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 100, showToasts: true });
}

// ─── Job Queue hooks ───────────────────────────────────────────────
/** Hook for Job Queue Dashboard — real-time job execution events */
export function useJobQueueEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "job:enqueued",
      "job:dispatched",
      "job:completed",
      "job:failed",
      "job:cancelled",
      "job:worker_registered",
      "job:worker_lost",
    ],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 200, showToasts: true });
}

// ─── Evidence Integrity hooks ─────────────────────────────────────
/** Hook for Evidence Integrity dashboard — real-time evidence gate and anchor events */
export function useEvidenceIntegrityEvents(engagementId?: number) {
  const channels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const filterTypes = useMemo<WsEventType[]>(
    () => [
      "evidence:gate_passed",
      "evidence:gate_flagged",
      "evidence:quarantined",
      "evidence:chain_flushed",
      "evidence:anchor_created",
      "evidence:anchor_verified",
      "evidence:tamper_detected",
    ],
    []
  );
  return useWebSocket({ channels, filterTypes, maxEvents: 200, showToasts: true });
}
