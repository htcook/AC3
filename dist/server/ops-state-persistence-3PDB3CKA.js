import {
  SERVER_INSTANCE_ID,
  init_server_instance
} from "./chunk-KUPDIQVG.js";
import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  engagementOpsSnapshots,
  init_schema
} from "./chunk-GM677ZS3.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ops-state-persistence.ts
init_env();
init_db();
init_schema();
init_server_instance();
import crypto from "crypto";
import { sql, eq, desc, and } from "drizzle-orm";
var SNAPSHOT_INTERVAL = 3e4;
var MAX_SNAPSHOTS_PER_ENGAGEMENT = 50;
var STATE_EXPIRY_HOURS = 72;
var CHECKSUM_KEY = crypto.createHash("sha256").update(ENV.JWT_SECRET || "ops-state-integrity-key").digest();
var snapshotTimers = /* @__PURE__ */ new Map();
var stateCache = /* @__PURE__ */ new Map();
function computeChecksum(data) {
  return crypto.createHmac("sha256", CHECKSUM_KEY).update(data).digest("hex").substring(0, 16);
}
function verifyChecksum(data, checksum) {
  const expected = computeChecksum(data);
  if (expected.length !== checksum.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(checksum, "hex")
  );
}
function trimStateForPersistence(state) {
  const MAX_STATE_KB = 256;
  const MAX_LOGS = 50;
  const MAX_OUTPUT_CHARS = 256;
  const trimmed = JSON.parse(JSON.stringify(state));
  if (Array.isArray(trimmed.log) && trimmed.log.length > MAX_LOGS) {
    trimmed.log = trimmed.log.slice(-MAX_LOGS);
  }
  if (Array.isArray(trimmed.assets)) {
    for (const asset of trimmed.assets) {
      if (Array.isArray(asset.toolResults)) {
        for (const tr of asset.toolResults) {
          if (tr.outputPreview && tr.outputPreview.length > MAX_OUTPUT_CHARS) {
            tr.outputPreview = tr.outputPreview.slice(0, MAX_OUTPUT_CHARS) + "...[trimmed]";
          }
          if (tr.findings && tr.findings.length > 20) {
            tr.findings = tr.findings.slice(0, 20);
          }
        }
      }
      if (Array.isArray(asset.openPorts) && asset.openPorts.length > 200) {
        asset.openPorts = asset.openPorts.slice(0, 200);
      }
    }
  }
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
async function saveStateSnapshot(engagementId, state, options = {}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const trimmedState = trimStateForPersistence(state);
  const stateStr = JSON.stringify(trimmedState);
  const checksum = computeChecksum(stateStr);
  const assetCount = Array.isArray(state.assets) ? state.assets.length : 0;
  const phase = options.phase || state.phase || state.currentPhase || "unknown";
  const existing = await db.select({ id: engagementOpsSnapshots.id }).from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).limit(1);
  let snapshotId;
  if (existing.length > 0) {
    await db.update(engagementOpsSnapshots).set({
      stateJson: { ...trimmedState, _checksum: checksum, _snapshotType: options.snapshotType || "periodic" },
      phase,
      isRunning: options.isRunning ? 1 : 0,
      assetCount,
      serverInstanceId: SERVER_INSTANCE_ID
    }).where(eq(engagementOpsSnapshots.id, existing[0].id));
    snapshotId = existing[0].id;
  } else {
    const result = await db.insert(engagementOpsSnapshots).values({
      engagementId,
      stateJson: { ...trimmedState, _checksum: checksum, _snapshotType: options.snapshotType || "periodic" },
      phase,
      isRunning: options.isRunning ? 1 : 0,
      assetCount,
      serverInstanceId: SERVER_INSTANCE_ID
    });
    snapshotId = result[0]?.insertId || 0;
  }
  stateCache.set(engagementId, { state, lastSnapshot: Date.now() });
  console.log(
    `[OpsState] Snapshot saved for engagement ${engagementId}: phase=${phase}, assets=${assetCount}, type=${options.snapshotType || "periodic"}`
  );
  return { id: snapshotId, checksum };
}
async function recoverState(engagementId) {
  const db = await getDb();
  if (!db) {
    return {
      recovered: false,
      engagementId,
      phase: null,
      assetCount: 0,
      stateAge: Infinity,
      integrityValid: false,
      state: null
    };
  }
  const snapshots = await db.select().from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).orderBy(desc(engagementOpsSnapshots.updatedAt)).limit(1);
  if (snapshots.length === 0) {
    return {
      recovered: false,
      engagementId,
      phase: null,
      assetCount: 0,
      stateAge: Infinity,
      integrityValid: false,
      state: null
    };
  }
  const snapshot = snapshots[0];
  const stateJson = snapshot.stateJson;
  const storedChecksum = stateJson._checksum;
  const snapshotType = stateJson._snapshotType;
  const cleanState = { ...stateJson };
  delete cleanState._checksum;
  delete cleanState._snapshotType;
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
  stateCache.set(engagementId, { state: cleanState, lastSnapshot: updatedAt });
  console.log(
    `[OpsState] State recovered for engagement ${engagementId}: phase=${snapshot.phase}, assets=${snapshot.assetCount}, age=${Math.round(stateAge / 1e3)}s, integrity=${integrityValid}`
  );
  return {
    recovered: true,
    engagementId,
    phase: snapshot.phase,
    assetCount: snapshot.assetCount || 0,
    stateAge,
    integrityValid,
    state: cleanState
  };
}
function startPeriodicSnapshots(engagementId, getState) {
  stopPeriodicSnapshots(engagementId);
  const timer = setInterval(async () => {
    try {
      const state = getState();
      if (!state) {
        console.log(`[OpsState] No state available for engagement ${engagementId}, skipping snapshot`);
        return;
      }
      const cached = stateCache.get(engagementId);
      if (cached) {
        const currentTrimmed = trimStateForPersistence(state);
        const currentStr = JSON.stringify(currentTrimmed);
        const cachedStr = JSON.stringify(cached.state);
        if (currentStr === cachedStr) {
          return;
        }
      }
      await saveStateSnapshot(engagementId, state, {
        isRunning: true,
        snapshotType: "periodic"
      });
    } catch (err) {
      console.error(`[OpsState] Periodic snapshot failed for engagement ${engagementId}:`, err);
    }
  }, SNAPSHOT_INTERVAL);
  snapshotTimers.set(engagementId, timer);
  console.log(`[OpsState] Started periodic snapshots for engagement ${engagementId} (every ${SNAPSHOT_INTERVAL / 1e3}s)`);
}
function stopPeriodicSnapshots(engagementId) {
  const timer = snapshotTimers.get(engagementId);
  if (timer) {
    clearInterval(timer);
    snapshotTimers.delete(engagementId);
    console.log(`[OpsState] Stopped periodic snapshots for engagement ${engagementId}`);
  }
}
async function savePhaseChangeSnapshot(engagementId, state, newPhase) {
  await saveStateSnapshot(engagementId, state, {
    phase: newPhase,
    isRunning: true,
    snapshotType: "phase_change"
  });
}
async function saveShutdownSnapshots(getRunningStates) {
  const states = getRunningStates();
  let saved = 0;
  for (const [engagementId, state] of states) {
    try {
      await saveStateSnapshot(engagementId, state, {
        isRunning: false,
        snapshotType: "shutdown"
      });
      saved++;
    } catch (err) {
      console.error(`[OpsState] Shutdown snapshot failed for engagement ${engagementId}:`, err);
    }
  }
  for (const [engId] of snapshotTimers) {
    stopPeriodicSnapshots(engId);
  }
  console.log(`[OpsState] Saved ${saved} shutdown snapshots`);
  return saved;
}
async function recoverRunningEngagements() {
  const db = await getDb();
  if (!db) return [];
  const runningSnapshots = await db.select().from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.isRunning, 1));
  const results = [];
  for (const snapshot of runningSnapshots) {
    const result = await recoverState(snapshot.engagementId);
    if (result.recovered) {
      results.push(result);
      await db.update(engagementOpsSnapshots).set({ isRunning: 0 }).where(eq(engagementOpsSnapshots.id, snapshot.id));
    }
  }
  console.log(`[OpsState] Recovered ${results.length} previously-running engagements`);
  return results;
}
async function cleanupOldSnapshots() {
  const db = await getDb();
  if (!db) return 0;
  const cutoff = new Date(Date.now() - STATE_EXPIRY_HOURS * 60 * 60 * 1e3);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace("T", " ");
  const result = await db.delete(engagementOpsSnapshots).where(
    and(
      eq(engagementOpsSnapshots.isRunning, 0),
      sql`${engagementOpsSnapshots.updatedAt} < ${cutoffStr}`
    )
  );
  const deleted = result[0]?.affectedRows || 0;
  if (deleted > 0) {
    console.log(`[OpsState] Cleaned up ${deleted} old snapshots (older than ${STATE_EXPIRY_HOURS}h)`);
  }
  return deleted;
}
async function getSnapshotHistory(engagementId) {
  const db = await getDb();
  if (!db) return { snapshots: [] };
  const rows = await db.select({
    id: engagementOpsSnapshots.id,
    phase: engagementOpsSnapshots.phase,
    isRunning: engagementOpsSnapshots.isRunning,
    assetCount: engagementOpsSnapshots.assetCount,
    stateJson: engagementOpsSnapshots.stateJson,
    createdAt: engagementOpsSnapshots.createdAt,
    updatedAt: engagementOpsSnapshots.updatedAt
  }).from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).orderBy(desc(engagementOpsSnapshots.updatedAt)).limit(MAX_SNAPSHOTS_PER_ENGAGEMENT);
  return {
    snapshots: rows.map((r) => ({
      id: r.id,
      phase: r.phase,
      isRunning: !!r.isRunning,
      assetCount: r.assetCount || 0,
      snapshotType: r.stateJson?._snapshotType || "unknown",
      createdAt: r.createdAt,
      updatedAt: r.updatedAt
    }))
  };
}
function getCachedState(engagementId) {
  return stateCache.get(engagementId)?.state || null;
}
function clearCachedState(engagementId) {
  stateCache.delete(engagementId);
  stopPeriodicSnapshots(engagementId);
}
export {
  cleanupOldSnapshots,
  clearCachedState,
  getCachedState,
  getSnapshotHistory,
  recoverRunningEngagements,
  recoverState,
  savePhaseChangeSnapshot,
  saveShutdownSnapshots,
  saveStateSnapshot,
  startPeriodicSnapshots,
  stopPeriodicSnapshots
};
