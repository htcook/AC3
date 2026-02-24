/**
 * WebSocket Event Hub — Real-time event broadcasting for the kill chain timeline
 *
 * Provides a centralized event bus that:
 * 1. Manages WebSocket connections with authentication
 * 2. Broadcasts events to all connected clients or specific channels
 * 3. Supports channel subscriptions (engagement-specific, global, page-specific)
 * 4. Handles reconnection and heartbeat
 */

import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";
import type { IncomingMessage } from "http";
import jwt from "jsonwebtoken";
import { EventEmitter } from "events";

// ─── Event Types ────────────────────────────────────────────────────

export type WsEventType =
  // Exploit pipeline events
  | "exploit:fired"
  | "exploit:progress"
  | "exploit:result"
  | "exploit:session_opened"
  // Agent events
  | "agent:deployed"
  | "agent:checkin"
  | "agent:lost"
  // Caldera operation events
  | "operation:started"
  | "operation:step_complete"
  | "operation:finished"
  // Recon events
  | "recon:started"
  | "recon:complete"
  | "recon:finding"
  // Campaign/phishing events
  | "campaign:launched"
  | "campaign:email_sent"
  | "campaign:email_opened"
  | "campaign:link_clicked"
  | "campaign:creds_submitted"
  // Pipeline events
  | "pipeline:started"
  | "pipeline:step_complete"
  | "pipeline:finished"
  // Domain events
  | "domain:scan_complete"
  | "domain:typosquat_purchased"
  // Exploit server events
  | "msf:server_provisioned"
  | "msf:server_ready"
  | "msf:server_destroyed"
  // System events
  | "system:notification"
  | "system:alert";

export interface WsEvent {
  type: WsEventType;
  timestamp: number;
  engagementId?: number | null;
  data: Record<string, any>;
}

interface WsClient {
  ws: WebSocket;
  userId: number | null;
  channels: Set<string>;
  lastPing: number;
  isAlive: boolean;
}

// ─── Singleton Event Hub ────────────────────────────────────────────

class EventHub extends EventEmitter {
  private wss: WebSocketServer | null = null;
  private clients: Map<string, WsClient> = new Map();
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private clientIdCounter = 0;

  /**
   * Attach the WebSocket server to an existing HTTP server
   */
  attach(server: Server): void {
    if (this.wss) {
      console.warn("[WS EventHub] Already attached, skipping");
      return;
    }

    this.wss = new WebSocketServer({
      server,
      path: "/ws/events",
      // Verify origin in production
      verifyClient: (info, cb) => {
        // Allow all origins in development, verify in production
        cb(true);
      },
    });

    this.wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
      this.handleConnection(ws, req);
    });

    // Heartbeat every 30 seconds
    this.heartbeatInterval = setInterval(() => {
      this.heartbeat();
    }, 30000);

    console.log("[WS EventHub] Attached to HTTP server on /ws/events");
  }

  /**
   * Handle new WebSocket connection
   */
  private handleConnection(ws: WebSocket, req: IncomingMessage): void {
    const clientId = `ws_${++this.clientIdCounter}_${Date.now()}`;

    // Try to authenticate from cookie
    let userId: number | null = null;
    try {
      const cookieHeader = req.headers.cookie || "";
      const cookies = Object.fromEntries(
        cookieHeader.split(";").map((c) => {
          const [k, ...v] = c.trim().split("=");
          return [k, v.join("=")];
        })
      );
      const token = cookies["caldera_session"];
      if (token) {
        const secret =
          process.env.CALDERA_JWT_SECRET ||
          "caldera-dashboard-secret-key-2024";
        const decoded = jwt.verify(token, secret) as any;
        userId = decoded.userId || decoded.id || null;
      }
    } catch {
      // Allow unauthenticated connections for public feeds
    }

    const client: WsClient = {
      ws,
      userId,
      channels: new Set(["global"]), // Everyone subscribes to global
      lastPing: Date.now(),
      isAlive: true,
    };

    this.clients.set(clientId, client);

    // Send welcome message
    this.sendToClient(client, {
      type: "system:notification",
      timestamp: Date.now(),
      data: {
        message: "Connected to Ace C3 Event Stream",
        clientId,
        authenticated: userId !== null,
      },
    });

    // Handle incoming messages (subscriptions, pings)
    ws.on("message", (raw: Buffer) => {
      try {
        const msg = JSON.parse(raw.toString());
        this.handleClientMessage(clientId, msg);
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on("pong", () => {
      client.isAlive = true;
      client.lastPing = Date.now();
    });

    ws.on("close", () => {
      this.clients.delete(clientId);
    });

    ws.on("error", () => {
      this.clients.delete(clientId);
    });

    this.emit("client:connected", { clientId, userId });
  }

  /**
   * Handle messages from clients (subscribe, unsubscribe, ping)
   */
  private handleClientMessage(
    clientId: string,
    msg: { action: string; channel?: string; channels?: string[] }
  ): void {
    const client = this.clients.get(clientId);
    if (!client) return;

    switch (msg.action) {
      case "subscribe":
        if (msg.channel) client.channels.add(msg.channel);
        if (msg.channels)
          msg.channels.forEach((ch) => client.channels.add(ch));
        this.sendToClient(client, {
          type: "system:notification",
          timestamp: Date.now(),
          data: {
            message: "Subscribed",
            channels: Array.from(client.channels),
          },
        });
        break;

      case "unsubscribe":
        if (msg.channel && msg.channel !== "global")
          client.channels.delete(msg.channel);
        break;

      case "ping":
        client.isAlive = true;
        client.lastPing = Date.now();
        this.sendToClient(client, {
          type: "system:notification",
          timestamp: Date.now(),
          data: { message: "pong" },
        });
        break;
    }
  }

  /**
   * Heartbeat — ping all clients, disconnect dead ones
   */
  private heartbeat(): void {
    for (const [clientId, client] of Array.from(this.clients.entries())) {
      if (!client.isAlive) {
        client.ws.terminate();
        this.clients.delete(clientId);
        continue;
      }
      client.isAlive = false;
      try {
        client.ws.ping();
      } catch {
        this.clients.delete(clientId);
      }
    }
  }

  /**
   * Send an event to a specific client
   */
  private sendToClient(client: WsClient, event: WsEvent): void {
    if (client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(JSON.stringify(event));
      } catch {
        // Client disconnected
      }
    }
  }

  /**
   * Broadcast an event to all clients subscribed to the relevant channel
   */
  broadcast(event: WsEvent, channel: string = "global"): void {
    const payload = JSON.stringify(event);

    for (const [, client] of Array.from(this.clients.entries())) {
      if (
        client.ws.readyState === WebSocket.OPEN &&
        client.channels.has(channel)
      ) {
        try {
          client.ws.send(payload);
        } catch {
          // Skip failed sends
        }
      }
    }

    // Also emit locally for server-side listeners
    this.emit("event", event, channel);
  }

  /**
   * Broadcast to global channel (all connected clients)
   */
  broadcastGlobal(event: WsEvent): void {
    this.broadcast(event, "global");
  }

  /**
   * Broadcast to engagement-specific channel
   */
  broadcastEngagement(engagementId: number, event: WsEvent): void {
    this.broadcast(
      { ...event, engagementId },
      `engagement:${engagementId}`
    );
    // Also broadcast to global for the timeline
    this.broadcastGlobal({ ...event, engagementId });
  }

  /**
   * Get connection stats
   */
  getStats(): {
    totalClients: number;
    authenticatedClients: number;
    channels: Record<string, number>;
  } {
    const channels: Record<string, number> = {};
    let authenticated = 0;

    for (const [, client] of Array.from(this.clients.entries())) {
      if (client.userId) authenticated++;
      for (const ch of Array.from(client.channels)) {
        channels[ch] = (channels[ch] || 0) + 1;
      }
    }

    return {
      totalClients: this.clients.size,
      authenticatedClients: authenticated,
      channels,
    };
  }

  /**
   * Cleanup on server shutdown
   */
  destroy(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    for (const [, client] of Array.from(this.clients.entries())) {
      client.ws.terminate();
    }
    this.clients.clear();
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
  }
}

// ─── Singleton Export ───────────────────────────────────────────────

export const eventHub = new EventHub();

// ─── Convenience Emitters ───────────────────────────────────────────

/** Emit when an MSF exploit is fired */
export function emitExploitFired(data: {
  jobId: number;
  module: string;
  targetIp: string;
  targetPort: number;
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: "exploit:fired",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when an MSF exploit returns a result */
export function emitExploitResult(data: {
  jobId: number;
  module: string;
  targetIp: string;
  success: boolean;
  sessionId?: number;
  error?: string;
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: "exploit:result",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when a Caldera agent is deployed */
export function emitAgentDeployed(data: {
  paw: string;
  host: string;
  platform: string;
  executors: string[];
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: "agent:deployed",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when a Caldera agent checks in */
export function emitAgentCheckin(data: {
  paw: string;
  host: string;
  lastSeen: string;
}): void {
  eventHub.broadcastGlobal({
    type: "agent:checkin",
    timestamp: Date.now(),
    data,
  });
}

/** Emit when a Caldera operation updates */
export function emitOperationUpdate(data: {
  operationId: string;
  name: string;
  state: string;
  progress?: number;
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: data.state === "finished" ? "operation:finished" : "operation:step_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when recon completes */
export function emitReconComplete(data: {
  scanId: number;
  domain: string;
  findings: number;
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: "recon:complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when a phishing campaign event occurs */
export function emitCampaignEvent(data: {
  campaignId: number;
  eventType: "launched" | "email_sent" | "email_opened" | "link_clicked" | "creds_submitted";
  email?: string;
  engagementId?: number;
}): void {
  const typeMap: Record<string, WsEventType> = {
    launched: "campaign:launched",
    email_sent: "campaign:email_sent",
    email_opened: "campaign:email_opened",
    link_clicked: "campaign:link_clicked",
    creds_submitted: "campaign:creds_submitted",
  };
  const event: WsEvent = {
    type: typeMap[data.eventType] || "campaign:launched",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit when a pipeline step completes */
export function emitPipelineStep(data: {
  pipelineId: number;
  step: number;
  stepName: string;
  status: "running" | "complete" | "failed";
  engagementId?: number;
}): void {
  const event: WsEvent = {
    type: data.status === "complete" && data.step === -1
      ? "pipeline:finished"
      : "pipeline:step_complete",
    timestamp: Date.now(),
    engagementId: data.engagementId,
    data,
  };
  if (data.engagementId) {
    eventHub.broadcastEngagement(data.engagementId, event);
  } else {
    eventHub.broadcastGlobal(event);
  }
}

/** Emit exploit server lifecycle events */
export function emitMsfServerEvent(data: {
  serverId: number;
  status: "provisioning" | "ready" | "destroyed" | "error";
  ip?: string;
  name?: string;
}): void {
  const typeMap: Record<string, WsEventType> = {
    provisioning: "msf:server_provisioned",
    ready: "msf:server_ready",
    destroyed: "msf:server_destroyed",
    error: "system:alert",
  };
  eventHub.broadcastGlobal({
    type: typeMap[data.status] || "system:notification",
    timestamp: Date.now(),
    data,
  });
}

/** Emit a system notification */
export function emitSystemNotification(data: {
  title: string;
  message: string;
  severity: "info" | "warning" | "error" | "critical";
}): void {
  eventHub.broadcastGlobal({
    type: "system:notification",
    timestamp: Date.now(),
    data,
  });
}

/** Emit a system alert */
export function emitSystemAlert(data: {
  title: string;
  message: string;
  severity: "warning" | "error" | "critical";
  actionUrl?: string;
}): void {
  eventHub.broadcastGlobal({
    type: "system:alert",
    timestamp: Date.now(),
    data,
  });
}
