import {
  eventHub,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import "./chunk-KFQGP6VL.js";

// server/lib/sse-event-stream.ts
init_ws_event_hub();
var EVENT_BUFFER_SIZE = 200;
var eventBuffer = [];
var eventIdCounter = 0;
eventHub.on("event", (event, channel) => {
  eventIdCounter++;
  eventBuffer.push({ event, channel, id: eventIdCounter });
  if (eventBuffer.length > EVENT_BUFFER_SIZE) {
    eventBuffer.shift();
  }
});
function registerSSEEventStream(app) {
  app.get("/api/events/stream", (req, res) => {
    const channelParam = req.query.channels || "global";
    const channels = new Set(channelParam.split(",").map((c) => c.trim()).filter(Boolean));
    if (!channels.has("global")) channels.add("global");
    const lastEventId = parseInt(req.headers["last-event-id"]) || 0;
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      // Disable nginx buffering
      "Access-Control-Allow-Origin": "*"
    });
    res.write(
      `id: ${eventIdCounter}
event: connected
data: ${JSON.stringify({
        type: "system:notification",
        timestamp: Date.now(),
        data: { message: "Connected to AC3 Event Stream (SSE)", channels: Array.from(channels) }
      })}

`
    );
    if (lastEventId > 0) {
      for (const entry of eventBuffer) {
        if (entry.id > lastEventId && channels.has(entry.channel)) {
          res.write(`id: ${entry.id}
event: message
data: ${JSON.stringify(entry.event)}

`);
        }
      }
    }
    const onEvent = (event, channel) => {
      if (channels.has(channel)) {
        eventIdCounter;
        const id = eventIdCounter;
        try {
          res.write(`id: ${id}
event: message
data: ${JSON.stringify(event)}

`);
        } catch {
        }
      }
    };
    eventHub.on("event", onEvent);
    const heartbeat = setInterval(() => {
      try {
        res.write(`: heartbeat ${Date.now()}

`);
      } catch {
        clearInterval(heartbeat);
      }
    }, 25e3);
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
export {
  registerSSEEventStream
};
