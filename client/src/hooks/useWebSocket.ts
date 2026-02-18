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
      return { title: "MSF Server Ready", description: `${event.data.name || "Server"} is online at ${event.data.ip || "unknown"}` };
    case "msf:server_destroyed":
      return { title: "MSF Server Destroyed", description: `${event.data.name || "Server"} has been terminated`, variant: "destructive" };
    case "system:alert":
      return { title: event.data.title || "Alert", description: event.data.message || "", variant: event.data.severity === "critical" || event.data.severity === "error" ? "destructive" : "default" };
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

/** Hook for MSF Servers page — server lifecycle events */
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
