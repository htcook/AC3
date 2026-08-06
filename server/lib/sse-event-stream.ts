/**
 * SSE Event Stream — Polling fallback for environments where WebSocket upgrades fail
 *
 * Cloud Run, Cloudflare, and many reverse proxies strip WebSocket upgrade headers.
 * This SSE endpoint provides the same real-time event stream over plain HTTP,
 * so the client can auto-fallback when WebSocket connections fail.
 *
 * Endpoint: GET /api/events/stream?channels=global,engagement:123
 *
 * The EventHub already emits every broadcast locally via EventEmitter ("event"),
 * so we simply listen to that and push matching events to the SSE response.
 */

import type { Request, Response, Router } from "express";
import { eventHub } from "./ws-event-hub";
import type { WsEvent } from "./ws-event-hub";

// ─── In-memory ring buffer for catch-up on reconnect ───────────────
const EVENT_BUFFER_SIZE = 200;
const eventBuffer: Array<{ event: WsEvent; channel: string; id: number }> = [];
let eventIdCounter = 0;

// Listen to all hub broadcasts and buffer them
eventHub.on("event", (event: WsEvent, channel: string) => {
  eventIdCounter++;
  eventBuffer.push({ event, channel, id: eventIdCounter });
  if (eventBuffer.length > EVENT_BUFFER_SIZE) {
    eventBuffer.shift();
  }
});

/**
 * Register the SSE event stream route on an Express router/app
 */
export function registerSSEEventStream(app: Router): void {
  app.get("/api/events/stream", (req: Request, res: Response) => {
    // Parse channel subscriptions from query string
    const channelParam = (req.query.channels as string) || "global";
    const channels = new Set(channelParam.split(",").map((c) => c.trim()).filter(Boolean));
    if (!channels.has("global")) channels.add("global");

    // Parse Last-Event-ID for catch-up
    const lastEventId = parseInt(req.headers["last-event-id"] as string) || 0;

    // Set SSE headers
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no", // Disable nginx buffering
      "Access-Control-Allow-Origin": "*",
    });

    // Send initial connection event
    res.write(
      `id: ${eventIdCounter}\nevent: connected\ndata: ${JSON.stringify({
        type: "system:notification",
        timestamp: Date.now(),
        data: { message: "Connected to AC3 Event Stream (SSE)", channels: Array.from(channels) },
      })}\n\n`
    );

    // Catch-up: replay missed events since lastEventId
    if (lastEventId > 0) {
      for (const entry of eventBuffer) {
        if (entry.id > lastEventId && channels.has(entry.channel)) {
          res.write(`id: ${entry.id}\nevent: message\ndata: ${JSON.stringify(entry.event)}\n\n`);
        }
      }
    }

    // Forward live events
    const onEvent = (event: WsEvent, channel: string) => {
      if (channels.has(channel)) {
        eventIdCounter; // use current counter
        const id = eventIdCounter;
        try {
          res.write(`id: ${id}\nevent: message\ndata: ${JSON.stringify(event)}\n\n`);
        } catch {
          // Client disconnected
        }
      }
    };

    eventHub.on("event", onEvent);

    // Heartbeat every 25 seconds to keep the connection alive through proxies
    const heartbeat = setInterval(() => {
      try {
        res.write(`: heartbeat ${Date.now()}\n\n`);
      } catch {
        clearInterval(heartbeat);
      }
    }, 25_000);

    // Cleanup on disconnect
    req.on("close", () => {
      eventHub.off("event", onEvent);
      clearInterval(heartbeat);
    });

    res.on("error", () => {
      eventHub.off("event", onEvent);
      clearInterval(heartbeat);
    });
  });

  console.log("[SSE EventStream] Registered at /api/events/stream");
}
