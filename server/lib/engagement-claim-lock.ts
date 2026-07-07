/**
 * Engagement Claim Lock — Atomic Ownership for Multi-Server Environments
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Prevents dual-execution when multiple server instances (e.g., local dev +
 * production) share the same database. Uses an atomic compare-and-swap (CAS)
 * pattern on the server_instance_id column:
 *
 *   UPDATE engagement_ops_snapshots
 *   SET server_instance_id = :ourId
 *   WHERE engagement_id = :engId
 *     AND (server_instance_id IS NULL OR server_instance_id = :ourId)
 *
 * If another server already claimed the row, affectedRows = 0 → claim denied.
 *
 * Heartbeat: The owning server must refresh its claim every HEARTBEAT_INTERVAL_MS.
 * If a claim is stale (older than CLAIM_EXPIRY_MS), other servers may steal it.
 */

import { SERVER_INSTANCE_ID } from "./server-instance";

// ─── Configuration ──────────────────────────────────────────────────────────

/** How often the owning server refreshes its claim (30s) */
const HEARTBEAT_INTERVAL_MS = 30_000;

/** If a claim hasn't been refreshed in this window, it's considered stale (2 min) */
const CLAIM_EXPIRY_MS = 2 * 60 * 1000;

// Active heartbeat timers per engagement
const heartbeatTimers = new Map<number, NodeJS.Timeout>();

// ─── Core Claim Operations ──────────────────────────────────────────────────

/**
 * Attempt to atomically claim ownership of an engagement.
 * Returns true if this server instance now owns it, false if another instance does.
 *
 * Claim succeeds when:
 *   - server_instance_id IS NULL (unclaimed / legacy)
 *   - server_instance_id = our ID (we already own it)
 *   - server_instance_id belongs to another server BUT updated_at is stale (expired claim)
 */
export async function claimEngagement(engagementId: number, options?: { force?: boolean }): Promise<{
  claimed: boolean;
  currentOwner: string | null;
  reason: string;
}> {
  const force = options?.force ?? false;
  try {
    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots } = await import("../../drizzle/schema");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();

    // Step 1: Read current state
    const rows = await db
      .select({
        id: engagementOpsSnapshots.id,
        serverInstanceId: engagementOpsSnapshots.serverInstanceId,
        updatedAt: engagementOpsSnapshots.updatedAt,
      })
      .from(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.engagementId, engagementId))
      .limit(1);

    if (rows.length === 0) {
      // No snapshot exists yet — this is a brand new engagement.
      // Create the snapshot row and claim it for this server instance.
      try {
        await db.execute(
          sql`INSERT INTO engagement_ops_snapshots (engagement_id, server_instance_id, phase, is_running, state_json, updated_at)
              VALUES (${engagementId}, ${SERVER_INSTANCE_ID}, 'idle', 0, '{}', NOW())`
        );
        console.log(`[ClaimLock] Engagement #${engagementId}: created snapshot and claimed by "${SERVER_INSTANCE_ID}"`);
        startHeartbeat(engagementId);
        return { claimed: true, currentOwner: SERVER_INSTANCE_ID, reason: "Created snapshot and claimed" };
      } catch (insertErr: any) {
        // Race condition: another server created it first — retry claim
        console.warn(`[ClaimLock] Engagement #${engagementId}: snapshot insert race — retrying claim`);
        return claimEngagement(engagementId, options);
      }
    }

    const row = rows[0];
    const currentOwner = row.serverInstanceId as string | null;

    // Already ours
    if (currentOwner === SERVER_INSTANCE_ID) {
      return { claimed: true, currentOwner, reason: "Already owned by this instance" };
    }

    // Check if the existing claim is stale
    if (currentOwner && currentOwner !== SERVER_INSTANCE_ID) {
      const updatedAt = row.updatedAt ? new Date(row.updatedAt).getTime() : 0;
      const age = Date.now() - updatedAt;
      if (age < CLAIM_EXPIRY_MS && !force) {
        // Another server has a fresh claim — deny (unless force=true for user-initiated actions)
        return {
          claimed: false,
          currentOwner,
          reason: `Owned by "${currentOwner}" (last heartbeat ${Math.round(age / 1000)}s ago, expiry=${CLAIM_EXPIRY_MS / 1000}s)`,
        };
      }
      if (force && age < CLAIM_EXPIRY_MS) {
        console.log(
          `[ClaimLock] Engagement #${engagementId}: FORCE-claiming from "${currentOwner}" ` +
          `(${Math.round(age / 1000)}s old, user-initiated override)`
        );
      } else {
        // Stale claim — we can steal it
        console.log(
          `[ClaimLock] Engagement #${engagementId}: claim by "${currentOwner}" is stale ` +
          `(${Math.round(age / 1000)}s old, expiry=${CLAIM_EXPIRY_MS / 1000}s). Stealing claim.`
        );
      }
    }

    // Step 2: Atomic CAS — claim only if still unclaimed, stale, or force-override
    const result = force
      ? await db.execute(
          sql`UPDATE engagement_ops_snapshots
              SET server_instance_id = ${SERVER_INSTANCE_ID},
                  updated_at = NOW()
              WHERE engagement_id = ${engagementId}`
        )
      : await db.execute(
          sql`UPDATE engagement_ops_snapshots
              SET server_instance_id = ${SERVER_INSTANCE_ID},
                  updated_at = NOW()
              WHERE engagement_id = ${engagementId}
                AND (server_instance_id IS NULL
                     OR server_instance_id = ${SERVER_INSTANCE_ID}
                     OR updated_at < DATE_SUB(NOW(), INTERVAL ${Math.floor(CLAIM_EXPIRY_MS / 1000)} SECOND))`
        );

    const affectedRows = (result as any)[0]?.affectedRows ?? (result as any)?.affectedRows ?? 0;

    if (affectedRows > 0) {
      console.log(`[ClaimLock] Engagement #${engagementId}: claimed by "${SERVER_INSTANCE_ID}"`);
      startHeartbeat(engagementId);
      return { claimed: true, currentOwner: SERVER_INSTANCE_ID, reason: "Claim acquired" };
    } else {
      // Race condition: another server claimed it between our read and write
      return {
        claimed: false,
        currentOwner: currentOwner || "unknown (race)",
        reason: "CAS failed — another instance claimed it first",
      };
    }
  } catch (err: any) {
    console.error(`[ClaimLock] Failed to claim engagement #${engagementId}:`, err.message);
    return { claimed: false, currentOwner: null, reason: `Error: ${err.message}` };
  }
}

/**
 * Release ownership of an engagement (e.g., on completion, error, or shutdown).
 */
export async function releaseEngagement(engagementId: number): Promise<boolean> {
  try {
    stopHeartbeat(engagementId);

    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots } = await import("../../drizzle/schema");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();

    // Only release if we own it
    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET server_instance_id = NULL
          WHERE engagement_id = ${engagementId}
            AND server_instance_id = ${SERVER_INSTANCE_ID}`
    );

    const affectedRows = (result as any)[0]?.affectedRows ?? (result as any)?.affectedRows ?? 0;
    if (affectedRows > 0) {
      console.log(`[ClaimLock] Engagement #${engagementId}: released by "${SERVER_INSTANCE_ID}"`);
    }
    return affectedRows > 0;
  } catch (err: any) {
    console.error(`[ClaimLock] Failed to release engagement #${engagementId}:`, err.message);
    return false;
  }
}

/**
 * Refresh the claim heartbeat (updates updated_at to prove we're still alive).
 */
export async function refreshClaim(engagementId: number): Promise<boolean> {
  try {
    const { getDbRequired } = await import("../db");
    const { sql } = await import("drizzle-orm");
    const db = await getDbRequired();

    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET updated_at = NOW()
          WHERE engagement_id = ${engagementId}
            AND server_instance_id = ${SERVER_INSTANCE_ID}`
    );

    const affectedRows = (result as any)[0]?.affectedRows ?? (result as any)?.affectedRows ?? 0;
    return affectedRows > 0;
  } catch (err: any) {
    console.error(`[ClaimLock] Heartbeat failed for engagement #${engagementId}:`, err.message);
    return false;
  }
}

// ─── Heartbeat Management ───────────────────────────────────────────────────

function startHeartbeat(engagementId: number): void {
  stopHeartbeat(engagementId); // Clear any existing
  const timer = setInterval(async () => {
    const ok = await refreshClaim(engagementId);
    if (!ok) {
      console.warn(`[ClaimLock] Lost claim on engagement #${engagementId} — stopping heartbeat`);
      stopHeartbeat(engagementId);
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeatTimers.set(engagementId, timer);
}

function stopHeartbeat(engagementId: number): void {
  const timer = heartbeatTimers.get(engagementId);
  if (timer) {
    clearInterval(timer);
    heartbeatTimers.delete(engagementId);
  }
}

/**
 * Release all claims held by this server instance (graceful shutdown).
 */
export async function releaseAllClaims(): Promise<number> {
  let released = 0;
  // Stop all heartbeats
  for (const [engId] of heartbeatTimers) {
    stopHeartbeat(engId);
  }

  try {
    const { getDbRequired } = await import("../db");
    const { sql } = await import("drizzle-orm");
    const db = await getDbRequired();

    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET server_instance_id = NULL
          WHERE server_instance_id = ${SERVER_INSTANCE_ID}`
    );
    released = (result as any)[0]?.affectedRows ?? (result as any)?.affectedRows ?? 0;
    if (released > 0) {
      console.log(`[ClaimLock] Released ${released} claim(s) during shutdown`);
    }
  } catch (err: any) {
    console.error(`[ClaimLock] Failed to release claims during shutdown:`, err.message);
  }
  return released;
}

// ─── Query Helpers ──────────────────────────────────────────────────────────

/**
 * Check who currently owns an engagement (without trying to claim it).
 */
export async function getClaimOwner(engagementId: number): Promise<{
  owner: string | null;
  isOurs: boolean;
  isStale: boolean;
  lastHeartbeat: number;
}> {
  try {
    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");
    const db = await getDbRequired();

    const rows = await db
      .select({
        serverInstanceId: engagementOpsSnapshots.serverInstanceId,
        updatedAt: engagementOpsSnapshots.updatedAt,
      })
      .from(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.engagementId, engagementId))
      .limit(1);

    if (rows.length === 0) {
      return { owner: null, isOurs: false, isStale: true, lastHeartbeat: 0 };
    }

    const owner = rows[0].serverInstanceId as string | null;
    const updatedAt = rows[0].updatedAt ? new Date(rows[0].updatedAt).getTime() : 0;
    const age = Date.now() - updatedAt;

    return {
      owner,
      isOurs: owner === SERVER_INSTANCE_ID,
      isStale: !owner || age > CLAIM_EXPIRY_MS,
      lastHeartbeat: updatedAt,
    };
  } catch {
    return { owner: null, isOurs: false, isStale: true, lastHeartbeat: 0 };
  }
}

// ─── Exports ────────────────────────────────────────────────────────────────

export const CLAIM_LOCK_CONFIG = {
  HEARTBEAT_INTERVAL_MS,
  CLAIM_EXPIRY_MS,
  SERVER_INSTANCE_ID,
} as const;
