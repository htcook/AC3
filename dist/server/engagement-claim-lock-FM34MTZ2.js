import {
  SERVER_INSTANCE_ID,
  init_server_instance
} from "./chunk-KUPDIQVG.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-claim-lock.ts
async function claimEngagement(engagementId, options) {
  const force = options?.force ?? false;
  try {
    const { getDbRequired } = await import("./db-65DPEQYH.js");
    const { engagementOpsSnapshots } = await import("./schema-TGCU627K.js");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    const rows = await db.select({
      id: engagementOpsSnapshots.id,
      serverInstanceId: engagementOpsSnapshots.serverInstanceId,
      updatedAt: engagementOpsSnapshots.updatedAt
    }).from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).limit(1);
    if (rows.length === 0) {
      return { claimed: false, currentOwner: null, reason: "No snapshot exists for this engagement" };
    }
    const row = rows[0];
    const currentOwner = row.serverInstanceId;
    if (currentOwner === SERVER_INSTANCE_ID) {
      return { claimed: true, currentOwner, reason: "Already owned by this instance" };
    }
    if (currentOwner && currentOwner !== SERVER_INSTANCE_ID) {
      const updatedAt = row.updatedAt ? new Date(row.updatedAt).getTime() : 0;
      const age = Date.now() - updatedAt;
      if (age < CLAIM_EXPIRY_MS && !force) {
        return {
          claimed: false,
          currentOwner,
          reason: `Owned by "${currentOwner}" (last heartbeat ${Math.round(age / 1e3)}s ago, expiry=${CLAIM_EXPIRY_MS / 1e3}s)`
        };
      }
      if (force && age < CLAIM_EXPIRY_MS) {
        console.log(
          `[ClaimLock] Engagement #${engagementId}: FORCE-claiming from "${currentOwner}" (${Math.round(age / 1e3)}s old, user-initiated override)`
        );
      } else {
        console.log(
          `[ClaimLock] Engagement #${engagementId}: claim by "${currentOwner}" is stale (${Math.round(age / 1e3)}s old, expiry=${CLAIM_EXPIRY_MS / 1e3}s). Stealing claim.`
        );
      }
    }
    const result = force ? await db.execute(
      sql`UPDATE engagement_ops_snapshots
              SET server_instance_id = ${SERVER_INSTANCE_ID},
                  updated_at = NOW()
              WHERE engagement_id = ${engagementId}`
    ) : await db.execute(
      sql`UPDATE engagement_ops_snapshots
              SET server_instance_id = ${SERVER_INSTANCE_ID},
                  updated_at = NOW()
              WHERE engagement_id = ${engagementId}
                AND (server_instance_id IS NULL
                     OR server_instance_id = ${SERVER_INSTANCE_ID}
                     OR updated_at < DATE_SUB(NOW(), INTERVAL ${Math.floor(CLAIM_EXPIRY_MS / 1e3)} SECOND))`
    );
    const affectedRows = result[0]?.affectedRows ?? result?.affectedRows ?? 0;
    if (affectedRows > 0) {
      console.log(`[ClaimLock] Engagement #${engagementId}: claimed by "${SERVER_INSTANCE_ID}"`);
      startHeartbeat(engagementId);
      return { claimed: true, currentOwner: SERVER_INSTANCE_ID, reason: "Claim acquired" };
    } else {
      return {
        claimed: false,
        currentOwner: currentOwner || "unknown (race)",
        reason: "CAS failed \u2014 another instance claimed it first"
      };
    }
  } catch (err) {
    console.error(`[ClaimLock] Failed to claim engagement #${engagementId}:`, err.message);
    return { claimed: false, currentOwner: null, reason: `Error: ${err.message}` };
  }
}
async function releaseEngagement(engagementId) {
  try {
    stopHeartbeat(engagementId);
    const { getDbRequired } = await import("./db-65DPEQYH.js");
    const { engagementOpsSnapshots } = await import("./schema-TGCU627K.js");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET server_instance_id = NULL
          WHERE engagement_id = ${engagementId}
            AND server_instance_id = ${SERVER_INSTANCE_ID}`
    );
    const affectedRows = result[0]?.affectedRows ?? result?.affectedRows ?? 0;
    if (affectedRows > 0) {
      console.log(`[ClaimLock] Engagement #${engagementId}: released by "${SERVER_INSTANCE_ID}"`);
    }
    return affectedRows > 0;
  } catch (err) {
    console.error(`[ClaimLock] Failed to release engagement #${engagementId}:`, err.message);
    return false;
  }
}
async function refreshClaim(engagementId) {
  try {
    const { getDbRequired } = await import("./db-65DPEQYH.js");
    const { sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET updated_at = NOW()
          WHERE engagement_id = ${engagementId}
            AND server_instance_id = ${SERVER_INSTANCE_ID}`
    );
    const affectedRows = result[0]?.affectedRows ?? result?.affectedRows ?? 0;
    return affectedRows > 0;
  } catch (err) {
    console.error(`[ClaimLock] Heartbeat failed for engagement #${engagementId}:`, err.message);
    return false;
  }
}
function startHeartbeat(engagementId) {
  stopHeartbeat(engagementId);
  const timer = setInterval(async () => {
    const ok = await refreshClaim(engagementId);
    if (!ok) {
      console.warn(`[ClaimLock] Lost claim on engagement #${engagementId} \u2014 stopping heartbeat`);
      stopHeartbeat(engagementId);
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeatTimers.set(engagementId, timer);
}
function stopHeartbeat(engagementId) {
  const timer = heartbeatTimers.get(engagementId);
  if (timer) {
    clearInterval(timer);
    heartbeatTimers.delete(engagementId);
  }
}
async function releaseAllClaims() {
  let released = 0;
  for (const [engId] of heartbeatTimers) {
    stopHeartbeat(engId);
  }
  try {
    const { getDbRequired } = await import("./db-65DPEQYH.js");
    const { sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    const result = await db.execute(
      sql`UPDATE engagement_ops_snapshots
          SET server_instance_id = NULL
          WHERE server_instance_id = ${SERVER_INSTANCE_ID}`
    );
    released = result[0]?.affectedRows ?? result?.affectedRows ?? 0;
    if (released > 0) {
      console.log(`[ClaimLock] Released ${released} claim(s) during shutdown`);
    }
  } catch (err) {
    console.error(`[ClaimLock] Failed to release claims during shutdown:`, err.message);
  }
  return released;
}
async function getClaimOwner(engagementId) {
  try {
    const { getDbRequired } = await import("./db-65DPEQYH.js");
    const { engagementOpsSnapshots } = await import("./schema-TGCU627K.js");
    const { eq } = await import("drizzle-orm");
    const db = await getDbRequired();
    const rows = await db.select({
      serverInstanceId: engagementOpsSnapshots.serverInstanceId,
      updatedAt: engagementOpsSnapshots.updatedAt
    }).from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).limit(1);
    if (rows.length === 0) {
      return { owner: null, isOurs: false, isStale: true, lastHeartbeat: 0 };
    }
    const owner = rows[0].serverInstanceId;
    const updatedAt = rows[0].updatedAt ? new Date(rows[0].updatedAt).getTime() : 0;
    const age = Date.now() - updatedAt;
    return {
      owner,
      isOurs: owner === SERVER_INSTANCE_ID,
      isStale: !owner || age > CLAIM_EXPIRY_MS,
      lastHeartbeat: updatedAt
    };
  } catch {
    return { owner: null, isOurs: false, isStale: true, lastHeartbeat: 0 };
  }
}
var HEARTBEAT_INTERVAL_MS, CLAIM_EXPIRY_MS, heartbeatTimers, CLAIM_LOCK_CONFIG;
var init_engagement_claim_lock = __esm({
  "server/lib/engagement-claim-lock.ts"() {
    init_server_instance();
    HEARTBEAT_INTERVAL_MS = 3e4;
    CLAIM_EXPIRY_MS = 2 * 60 * 1e3;
    heartbeatTimers = /* @__PURE__ */ new Map();
    CLAIM_LOCK_CONFIG = {
      HEARTBEAT_INTERVAL_MS,
      CLAIM_EXPIRY_MS,
      SERVER_INSTANCE_ID
    };
  }
});
init_engagement_claim_lock();
export {
  CLAIM_LOCK_CONFIG,
  claimEngagement,
  getClaimOwner,
  refreshClaim,
  releaseAllClaims,
  releaseEngagement
};
