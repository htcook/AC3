/**
 * Ops State Persistence — DB-backed state recovery for engagement operations
 *
 * Solves the problem of in-memory scan state being lost on server restart.
 * Provides:
 *   1. Periodic state snapshots to DB during long-running operations
 *   2. State recovery on server restart (load from DB)
 *   3. State cleanup for completed engagements
 *   4. Integrity verification via HMAC checksums
 *
 * Uses the existing engagement_ops_snapshots table:
 *   - id (auto-increment)
 *   - engagement_id (FK)
 *   - state_json (JSON blob)
 *   - phase (varchar)
 *   - is_running (tinyint)
 *   - asset_count (int)
 *   - created_at / updated_at (timestamps)
 */
import crypto from "crypto";
import { ENV } from "../_core/env";
import { getDb } from "../db";
import { sql, eq, desc, and } from "drizzle-orm";
import * as schema from "../../drizzle/schema";
import { SERVER_INSTANCE_ID } from "./server-instance";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface OpsStateSnapshot {
  engagementId: number;
  phase: string;
  isRunning: boolean;
  assetCount: number;
  stateJson: Record<string, any>;
  checksum: string;
  snapshotType: "periodic" | "phase_change" | "manual" | "shutdown" | "recovery";
  createdAt: number;
}

export interface StateRecoveryResult {
  recovered: boolean;
  engagementId: number;
  phase: string | null;
  assetCount: number;
  stateAge: number; // ms since snapshot
  integrityValid: boolean;
  state: Record<string, any> | null;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const SNAPSHOT_INTERVAL = 30_000; // 30 seconds between periodic snapshots
const MAX_SNAPSHOTS_PER_ENGAGEMENT = 50; // Keep last 50 snapshots per engagement
const STATE_EXPIRY_HOURS = 72; // Clean up states older than 72 hours
const CHECKSUM_KEY = crypto
  .createHash("sha256")
  .update(ENV.JWT_SECRET || "ops-state-integrity-key")
  .digest();

// Active snapshot timers
const snapshotTimers = new Map<number, NodeJS.Timeout>();
// In-memory state cache for fast access
const stateCache = new Map<number, { state: Record<string, any>; lastSnapshot: number }>();

// ─── Checksum Helpers ───────────────────────────────────────────────────────

function computeChecksum(data: string): string {
  return crypto
    .createHmac("sha256", CHECKSUM_KEY)
    .update(data)
    .digest("hex")
    .substring(0, 16); // Short checksum for storage
}

function verifyChecksum(data: string, checksum: string): boolean {
  const expected = computeChecksum(data);
  if (expected.length !== checksum.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(checksum, "hex")
  );
}

// ─── Core Persistence Operations ────────────────────────────────────────────

/**
 * Save a state snapshot to the database.
 */
/**
 * Trim state before persisting to keep state_json under MAX_STATE_KB.
 * Preserves assets and findings but aggressively trims logs and tool output.
 */
function trimStateForPersistence(state: Record<string, any>): Record<string, any> {
  const MAX_STATE_KB = 256; // Target max 256KB per engagement state
  const MAX_LOGS = 50;     // Keep only last 50 logs in persisted state
  const MAX_OUTPUT_CHARS = 256; // Trim tool output previews

  // Deep clone to avoid mutating in-memory state
  const trimmed = JSON.parse(JSON.stringify(state));

  // 1. Trim logs to last N entries
  if (Array.isArray(trimmed.log) && trimmed.log.length > MAX_LOGS) {
    trimmed.log = trimmed.log.slice(-MAX_LOGS);
  }

  // 2. Trim tool output previews on all assets
  if (Array.isArray(trimmed.assets)) {
    for (const asset of trimmed.assets) {
      if (Array.isArray(asset.toolResults)) {
        for (const tr of asset.toolResults) {
          if (tr.outputPreview && tr.outputPreview.length > MAX_OUTPUT_CHARS) {
            tr.outputPreview = tr.outputPreview.slice(0, MAX_OUTPUT_CHARS) + '...[trimmed]';
          }
          // Cap findings arrays
          if (tr.findings && tr.findings.length > 20) {
            tr.findings = tr.findings.slice(0, 20);
          }
        }
      }
      // Trim large raw data arrays (e.g. ports, services)
      if (Array.isArray(asset.openPorts) && asset.openPorts.length > 200) {
        asset.openPorts = asset.openPorts.slice(0, 200);
      }
    }
  }

  // 3. If still too large, progressively reduce logs further
  let jsonStr = JSON.stringify(trimmed);
  if (jsonStr.length > MAX_STATE_KB * 1024 && Array.isArray(trimmed.log)) {
    trimmed.log = trimmed.log.slice(-20);
    jsonStr = JSON.stringify(trimmed);
  }
  if (jsonStr.length > MAX_STATE_KB * 1024 && Array.isArray(trimmed.log)) {
    trimmed.log = trimmed.log.slice(-5);
  }

  return trimmed;
}

export async function saveStateSnapshot(
  engagementId: number,
  state: Record<string, any>,
  options: {
    phase?: string;
    isRunning?: boolean;
    snapshotType?: OpsStateSnapshot["snapshotType"];
  } = {}
): Promise<{ id: number; checksum: string }> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // Trim state before persisting to cap DB size and prevent memory bloat on recovery
  const trimmedState = trimStateForPersistence(state);
  const stateStr = JSON.stringify(trimmedState);
  const checksum = computeChecksum(stateStr);
  const assetCount = Array.isArray(state.assets) ? state.assets.length : 0;
  const phase = options.phase || state.phase || state.currentPhase || "unknown";

  // Upsert: update existing snapshot or create new one
  const existing = await db
    .select({ id: schema.engagementOpsSnapshots.id })
    .from(schema.engagementOpsSnapshots)
    .where(eq(schema.engagementOpsSnapshots.engagementId, engagementId))
    .limit(1);

  let snapshotId: number;

  if (existing.length > 0) {
    // Update existing snapshot
    await db
      .update(schema.engagementOpsSnapshots)
      .set({
        stateJson: { ...trimmedState, _checksum: checksum, _snapshotType: options.snapshotType || "periodic" },
        phase,
        isRunning: options.isRunning ? 1 : 0,
        assetCount,
        serverInstanceId: SERVER_INSTANCE_ID,
      })
      .where(eq(schema.engagementOpsSnapshots.id, existing[0].id));
    snapshotId = existing[0].id;
  } else {
    // Insert new snapshot
    const result = await db
      .insert(schema.engagementOpsSnapshots)
      .values({
        engagementId,
        stateJson: { ...trimmedState, _checksum: checksum, _snapshotType: options.snapshotType || "periodic" },
        phase,
        isRunning: options.isRunning ? 1 : 0,
        assetCount,
        serverInstanceId: SERVER_INSTANCE_ID,
      });
    snapshotId = (result as any)[0]?.insertId || 0;
  }

  // Update cache
  stateCache.set(engagementId, { state, lastSnapshot: Date.now() });

  console.log(
    `[OpsState] Snapshot saved for engagement ${engagementId}: phase=${phase}, assets=${assetCount}, type=${options.snapshotType || "periodic"}`
  );

  return { id: snapshotId, checksum };
}

/**
 * Recover state from the database for an engagement.
 */
export async function recoverState(engagementId: number): Promise<StateRecoveryResult> {
  const db = await getDb();
  if (!db) {
    return {
      recovered: false,
      engagementId,
      phase: null,
      assetCount: 0,
      stateAge: Infinity,
      integrityValid: false,
      state: null,
    };
  }

  const snapshots = await db
    .select()
    .from(schema.engagementOpsSnapshots)
    .where(eq(schema.engagementOpsSnapshots.engagementId, engagementId))
    .orderBy(desc(schema.engagementOpsSnapshots.updatedAt))
    .limit(1);

  if (snapshots.length === 0) {
    return {
      recovered: false,
      engagementId,
      phase: null,
      assetCount: 0,
      stateAge: Infinity,
      integrityValid: false,
      state: null,
    };
  }

  const snapshot = snapshots[0];
  const stateJson = snapshot.stateJson as Record<string, any>;
  const storedChecksum = stateJson._checksum as string | undefined;
  const snapshotType = stateJson._snapshotType as string | undefined;

  // Remove internal metadata before returning
  const cleanState = { ...stateJson };
  delete cleanState._checksum;
  delete cleanState._snapshotType;

  // Verify integrity
  let integrityValid = true;
  if (storedChecksum) {
    const stateStr = JSON.stringify(cleanState);
    integrityValid = verifyChecksum(stateStr, storedChecksum);
    if (!integrityValid) {
      console.warn(`[OpsState] INTEGRITY WARNING: Checksum mismatch for engagement ${engagementId}`);
    }
  }

  const updatedAt = snapshot.updatedAt ? new Date(snapshot.updatedAt).getTime() : Date.now();
  const stateAge = Date.now() - updatedAt;

  // Cache the recovered state
  stateCache.set(engagementId, { state: cleanState, lastSnapshot: updatedAt });

  console.log(
    `[OpsState] State recovered for engagement ${engagementId}: phase=${snapshot.phase}, assets=${snapshot.assetCount}, age=${Math.round(stateAge / 1000)}s, integrity=${integrityValid}`
  );

  return {
    recovered: true,
    engagementId,
    phase: snapshot.phase,
    assetCount: snapshot.assetCount || 0,
    stateAge,
    integrityValid,
    state: cleanState,
  };
}

/**
 * Start periodic state snapshots for an engagement.
 * Call this when an engagement starts running.
 */
export function startPeriodicSnapshots(
  engagementId: number,
  getState: () => Record<string, any> | null
): void {
  // Clear any existing timer
  stopPeriodicSnapshots(engagementId);

  const timer = setInterval(async () => {
    try {
      const state = getState();
      if (!state) {
        console.log(`[OpsState] No state available for engagement ${engagementId}, skipping snapshot`);
        return;
      }

      // Check if state has changed since last snapshot (compare trimmed versions)
      const cached = stateCache.get(engagementId);
      if (cached) {
        const currentTrimmed = trimStateForPersistence(state);
        const currentStr = JSON.stringify(currentTrimmed);
        const cachedStr = JSON.stringify(cached.state);
        if (currentStr === cachedStr) {
          return; // No changes, skip snapshot
        }
      }

      await saveStateSnapshot(engagementId, state, {
        isRunning: true,
        snapshotType: "periodic",
      });
    } catch (err) {
      console.error(`[OpsState] Periodic snapshot failed for engagement ${engagementId}:`, err);
    }
  }, SNAPSHOT_INTERVAL);

  snapshotTimers.set(engagementId, timer);
  console.log(`[OpsState] Started periodic snapshots for engagement ${engagementId} (every ${SNAPSHOT_INTERVAL / 1000}s)`);
}

/**
 * Stop periodic snapshots for an engagement.
 */
export function stopPeriodicSnapshots(engagementId: number): void {
  const timer = snapshotTimers.get(engagementId);
  if (timer) {
    clearInterval(timer);
    snapshotTimers.delete(engagementId);
    console.log(`[OpsState] Stopped periodic snapshots for engagement ${engagementId}`);
  }
}

/**
 * Save a final snapshot when an engagement phase changes.
 */
export async function savePhaseChangeSnapshot(
  engagementId: number,
  state: Record<string, any>,
  newPhase: string
): Promise<void> {
  await saveStateSnapshot(engagementId, state, {
    phase: newPhase,
    isRunning: true,
    snapshotType: "phase_change",
  });
}

/**
 * Save a shutdown snapshot for all running engagements.
 * Call this during graceful server shutdown.
 */
export async function saveShutdownSnapshots(
  getRunningStates: () => Map<number, Record<string, any>>
): Promise<number> {
  const states = getRunningStates();
  let saved = 0;

  for (const [engagementId, state] of states) {
    try {
      await saveStateSnapshot(engagementId, state, {
        isRunning: false,
        snapshotType: "shutdown",
      });
      saved++;
    } catch (err) {
      console.error(`[OpsState] Shutdown snapshot failed for engagement ${engagementId}:`, err);
    }
  }

  // Stop all periodic timers
  for (const [engId] of snapshotTimers) {
    stopPeriodicSnapshots(engId);
  }

  console.log(`[OpsState] Saved ${saved} shutdown snapshots`);
  return saved;
}

/**
 * Recover all previously-running engagements on server startup.
 */
export async function recoverRunningEngagements(): Promise<StateRecoveryResult[]> {
  const db = await getDb();
  if (!db) return [];

  const runningSnapshots = await db
    .select()
    .from(schema.engagementOpsSnapshots)
    .where(eq(schema.engagementOpsSnapshots.isRunning, 1));

  const results: StateRecoveryResult[] = [];

  for (const snapshot of runningSnapshots) {
    const result = await recoverState(snapshot.engagementId);
    if (result.recovered) {
      results.push(result);
      // Mark as no longer running (will be re-started by operator)
      await db
        .update(schema.engagementOpsSnapshots)
        .set({ isRunning: 0 })
        .where(eq(schema.engagementOpsSnapshots.id, snapshot.id));
    }
  }

  console.log(`[OpsState] Recovered ${results.length} previously-running engagements`);
  return results;
}

/**
 * Clean up old snapshots beyond the retention period.
 */
export async function cleanupOldSnapshots(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;

  const cutoff = new Date(Date.now() - STATE_EXPIRY_HOURS * 60 * 60 * 1000);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace("T", " ");

  const result = await db
    .delete(schema.engagementOpsSnapshots)
    .where(
      and(
        eq(schema.engagementOpsSnapshots.isRunning, 0),
        sql`${schema.engagementOpsSnapshots.updatedAt} < ${cutoffStr}`
      )
    );

  const deleted = (result as any)[0]?.affectedRows || 0;
  if (deleted > 0) {
    console.log(`[OpsState] Cleaned up ${deleted} old snapshots (older than ${STATE_EXPIRY_HOURS}h)`);
  }
  return deleted;
}

/**
 * Get snapshot history for an engagement (for audit trail).
 */
export async function getSnapshotHistory(engagementId: number): Promise<{
  snapshots: Array<{
    id: number;
    phase: string | null;
    isRunning: boolean;
    assetCount: number;
    snapshotType: string;
    createdAt: string;
    updatedAt: string;
  }>;
}> {
  const db = await getDb();
  if (!db) return { snapshots: [] };

  const rows = await db
    .select({
      id: schema.engagementOpsSnapshots.id,
      phase: schema.engagementOpsSnapshots.phase,
      isRunning: schema.engagementOpsSnapshots.isRunning,
      assetCount: schema.engagementOpsSnapshots.assetCount,
      stateJson: schema.engagementOpsSnapshots.stateJson,
      createdAt: schema.engagementOpsSnapshots.createdAt,
      updatedAt: schema.engagementOpsSnapshots.updatedAt,
    })
    .from(schema.engagementOpsSnapshots)
    .where(eq(schema.engagementOpsSnapshots.engagementId, engagementId))
    .orderBy(desc(schema.engagementOpsSnapshots.updatedAt))
    .limit(MAX_SNAPSHOTS_PER_ENGAGEMENT);

  return {
    snapshots: rows.map((r) => ({
      id: r.id,
      phase: r.phase,
      isRunning: !!r.isRunning,
      assetCount: r.assetCount || 0,
      snapshotType: (r.stateJson as any)?._snapshotType || "unknown",
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    })),
  };
}

/**
 * Get cached state for an engagement (fast, no DB hit).
 */
export function getCachedState(engagementId: number): Record<string, any> | null {
  return stateCache.get(engagementId)?.state || null;
}

/**
 * Clear cached state for an engagement.
 */
export function clearCachedState(engagementId: number): void {
  stateCache.delete(engagementId);
  stopPeriodicSnapshots(engagementId);
}
