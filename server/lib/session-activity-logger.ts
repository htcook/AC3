/**
 * Session Activity Logger
 * 
 * Tracks session lifecycle events for security monitoring and debugging:
 * - Session creation (login success)
 * - Session validation (each authenticated request)
 * - Session invalidation (logout, expiry, JWT mismatch)
 * - Session errors (malformed tokens, verification failures)
 * 
 * Events are logged to the existing activity_logs table with structured JSON details
 * for FedRAMP AU-2/AU-3 compliance. Designed to be non-blocking — logging failures
 * never interrupt the request pipeline.
 */
import { sql } from "drizzle-orm";

export type SessionEventType =
  | "session_created"        // New session established (login)
  | "session_validated"      // Session token verified on request
  | "session_expired"        // JWT token expired
  | "session_invalidated"    // Explicit logout or forced invalidation
  | "session_error"          // Token verification error (malformed, wrong secret)
  | "session_mismatch"       // JWT format mismatch (e.g., email token read as service token)
  | "session_context_fallback" // Manus OAuth failed, fell back to caldera_session
  | "session_not_found";     // No session cookie present on protected route

export interface SessionEvent {
  type: SessionEventType;
  userId?: number | string;
  email?: string;
  username?: string;
  loginMethod?: string;       // "email" | "caldera" | "manus_oauth" | "saml"
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  detail?: string;
  durationMs?: number;        // Time since session was created
}

// In-memory buffer for batch writes (reduces DB pressure)
const eventBuffer: Array<{ event: SessionEvent; timestamp: number }> = [];
const FLUSH_INTERVAL_MS = 5000;  // Flush every 5 seconds
const MAX_BUFFER_SIZE = 50;      // Or when buffer hits 50 events
let flushTimer: ReturnType<typeof setInterval> | null = null;
let dbGetter: (() => Promise<any>) | null = null;

/**
 * Initialize the session logger with a database getter function.
 * Must be called once during server startup.
 */
export function initSessionLogger(getDb: () => Promise<any>) {
  dbGetter = getDb;
  if (!flushTimer) {
    flushTimer = setInterval(flushEvents, FLUSH_INTERVAL_MS);
    flushTimer.unref(); // Don't keep process alive just for logging
  }
}

/**
 * Log a session activity event. Non-blocking — returns immediately.
 * Events are buffered and flushed periodically to reduce DB load.
 */
export function logSessionEvent(event: SessionEvent) {
  eventBuffer.push({ event, timestamp: Date.now() });
  
  // Also log to console for immediate visibility in server logs
  const level = event.type.includes("error") || event.type.includes("mismatch") ? "warn" : "info";
  const msg = `[SessionLog] ${event.type}: user=${event.userId || event.email || event.username || 'unknown'} method=${event.loginMethod || 'unknown'} ip=${event.ipAddress || 'unknown'}`;
  if (level === "warn") {
    console.warn(msg, event.detail || "");
  } else {
    console.log(msg);
  }

  // Flush immediately if buffer is full
  if (eventBuffer.length >= MAX_BUFFER_SIZE) {
    flushEvents();
  }
}

/**
 * Flush buffered events to the database.
 * Called periodically and on buffer overflow.
 */
async function flushEvents() {
  if (eventBuffer.length === 0 || !dbGetter) return;

  // Drain the buffer
  const batch = eventBuffer.splice(0, eventBuffer.length);

  try {
    const db = await dbGetter();
    // Batch insert all events
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
            timestamp: new Date(timestamp).toISOString(),
          })},
          ${event.ipAddress || null},
          ${new Date(timestamp).toISOString()}
        )
      `);
    }
  } catch (err) {
    // Logging should never break the application
    console.error("[SessionLog] Failed to flush events:", (err as Error).message);
    // Don't re-add events — they're already in console logs
  }
}

/**
 * Force flush all pending events. Call during graceful shutdown.
 */
export async function flushSessionEvents() {
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
  await flushEvents();
}

/**
 * Extract session-relevant info from an Express request.
 * Helper for use in context.ts and auth procedures.
 */
export function extractRequestInfo(req: { 
  ip?: string; 
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
}) {
  const forwarded = req.headers["x-forwarded-for"];
  const ipAddress = typeof forwarded === "string" 
    ? forwarded.split(",")[0].trim() 
    : req.ip || "unknown";
  const userAgent = (req.headers["user-agent"] as string) || "unknown";
  
  return { ipAddress, userAgent };
}
