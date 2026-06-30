/**
 * Server Instance Identity
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Generates a unique ID for each server process. Used by the auto-resume
 * system to distinguish which server instance "owns" a running engagement.
 *
 * This prevents false crash-loop detection when multiple server instances
 * (e.g., local dev + production) share the same database.
 *
 * Format: {hostname}-{pid}-{startTimestamp}-{random}
 * Example: "manus-prod-1-1774151384-a3f2"
 */

import os from "os";
import crypto from "crypto";

/** Unique identifier for this server process, generated once at import time */
export const SERVER_INSTANCE_ID = [
  os.hostname().replace(/[^a-zA-Z0-9-]/g, "").slice(0, 20),
  process.pid,
  Math.floor(Date.now() / 1000),
  crypto.randomBytes(2).toString("hex"),
].join("-");

/** When this server instance started */
export const SERVER_START_TIME = Date.now();

console.log(`[ServerInstance] ID: ${SERVER_INSTANCE_ID}`);
