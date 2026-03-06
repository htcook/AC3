/**
 * useWebSocket — React hook for real-time event streaming
 *
 * Connects to the WebSocket event hub at /ws/events and provides:
 * - Auto-reconnection with exponential backoff
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
  | "system:alert";

export interface WsEvent {
  type: WsEventType;
  timestamp: number;
  engagementId?: number | null;
  data: Record<string, any>;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

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
    default:
      return null;
  }
}

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
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const channelsRef = useRef(channels);


  // Keep channels ref up to date
  channelsRef.current = channels;

  const connect = useCallback(() => {
    if (!enabled) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/events`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      setStatus("connecting");

      ws.onopen = () => {
        setStatus("connected");
        reconnectAttemptsRef.current = 0;

        // Subscribe to channels
        if (channelsRef.current.length > 0) {
          ws.send(JSON.stringify({ action: "subscribe", channels: channelsRef.current }));
        }
      };

      ws.onmessage = (msg) => {
        try {
          const event: WsEvent = JSON.parse(msg.data);

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
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        setStatus("disconnected");
        wsRef.current = null;

        // Auto-reconnect with exponential backoff
        if (autoReconnect && enabled) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectAttemptsRef.current++;
          reconnectTimeoutRef.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => {
        setStatus("error");
      };
    } catch {
      setStatus("error");
    }
  }, [enabled, filterTypes, maxEvents, showToasts, autoReconnect, toast]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus("disconnected");
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
    if (enabled) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [enabled, connect, disconnect]);

  // Re-subscribe when channels change
  useEffect(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN && channels.length > 0) {
      wsRef.current.send(JSON.stringify({ action: "subscribe", channels }));
    }
  }, [channels]);

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
