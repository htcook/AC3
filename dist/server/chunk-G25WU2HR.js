// server/lib/session-activity-logger.ts
import { sql } from "drizzle-orm";
var eventBuffer = [];
var FLUSH_INTERVAL_MS = 5e3;
var MAX_BUFFER_SIZE = 50;
var flushTimer = null;
var dbGetter = null;
function initSessionLogger(getDb) {
  dbGetter = getDb;
  if (!flushTimer) {
    flushTimer = setInterval(flushEvents, FLUSH_INTERVAL_MS);
    flushTimer.unref();
  }
}
function logSessionEvent(event) {
  eventBuffer.push({ event, timestamp: Date.now() });
  const level = event.type.includes("error") || event.type.includes("mismatch") ? "warn" : "info";
  const msg = `[SessionLog] ${event.type}: user=${event.userId || event.email || event.username || "unknown"} method=${event.loginMethod || "unknown"} ip=${event.ipAddress || "unknown"}`;
  if (level === "warn") {
    console.warn(msg, event.detail || "");
  } else {
    console.log(msg);
  }
  if (eventBuffer.length >= MAX_BUFFER_SIZE) {
    flushEvents();
  }
}
async function flushEvents() {
  if (eventBuffer.length === 0 || !dbGetter) return;
  const batch = eventBuffer.splice(0, eventBuffer.length);
  try {
    const db = await dbGetter();
    for (const { event, timestamp } of batch) {
      await db.execute(sql`
        INSERT INTO activity_logs (action, details, ipAddress, createdAt)
        VALUES (
          ${`session:${event.type}`},
          ${JSON.stringify({
        userId: event.userId || null,
        email: event.email || null,
        username: event.username || null,
        loginMethod: event.loginMethod || null,
        sessionId: event.sessionId || null,
        userAgent: event.userAgent?.substring(0, 500) || null,
        detail: event.detail || null,
        durationMs: event.durationMs || null,
        timestamp: new Date(timestamp).toISOString()
      })},
          ${event.ipAddress || null},
          ${new Date(timestamp).toISOString()}
        )
      `);
    }
  } catch (err) {
    console.error("[SessionLog] Failed to flush events:", err.message);
  }
}
async function flushSessionEvents() {
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
  await flushEvents();
}
function extractRequestInfo(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ipAddress = typeof forwarded === "string" ? forwarded.split(",")[0].trim() : req.ip || "unknown";
  const userAgent = req.headers["user-agent"] || "unknown";
  return { ipAddress, userAgent };
}

export {
  initSessionLogger,
  logSessionEvent,
  flushSessionEvents,
  extractRequestInfo
};
