import {
  getDb,
  init_db
} from "./chunk-AX6SVAQZ.js";
import {
  init_schema,
  threatIntelUpdates
} from "./chunk-DQZ564DJ.js";

// server/lib/last-active-updater.ts
init_db();
init_schema();
import mysql from "mysql2/promise";
function toYYYYMM(d) {
  const date = typeof d === "string" ? new Date(d) : d;
  if (isNaN(date.getTime())) return "";
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
function isMoreRecent(a, b) {
  if (!b) return !!a;
  return a > b;
}
async function getRawConnection() {
  return mysql.createConnection(process.env.DATABASE_URL);
}
async function updateFromThreatGroupEvents() {
  const start = Date.now();
  const result = {
    source: "threat_group_events",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0
  };
  let conn = null;
  try {
    conn = await getRawConnection();
    const [rows] = await conn.execute(`
      SELECT tgeActorId, MAX(eventDate) as latestEvent
      FROM threat_group_events
      WHERE eventDate IS NOT NULL
      GROUP BY tgeActorId
    `);
    result.actorsScanned = rows.length;
    for (const row of rows) {
      const actorId = row.tgeActorId;
      const latestEvent = row.latestEvent;
      if (!actorId || !latestEvent) continue;
      const newLastActive = toYYYYMM(latestEvent);
      if (!newLastActive) continue;
      try {
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors WHERE LOWER(actorId) = LOWER(?)`,
          [actorId]
        );
        if (existing.length === 0) continue;
        const current = existing[0].lastActive;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE LOWER(actorId) = LOWER(?)`,
            [newLastActive, actorId]
          );
          result.actorsUpdated++;
        }
      } catch (e) {
        result.errors.push(`TGE ${actorId}: ${e.message}`);
      }
    }
  } catch (e) {
    result.errors.push(`TGE query failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function updateFromUndergroundIntelEvents() {
  const start = Date.now();
  const result = {
    source: "underground_intel_events",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0
  };
  let conn = null;
  try {
    conn = await getRawConnection();
    const [rows] = await conn.execute(`
      SELECT uie_actor_name, MAX(uie_event_date) as latestEvent
      FROM underground_intel_events
      WHERE uie_actor_name IS NOT NULL AND uie_actor_name != ''
      GROUP BY uie_actor_name
    `);
    result.actorsScanned = rows.length;
    for (const row of rows) {
      const actorName = row.uie_actor_name;
      const latestEvent = row.latestEvent;
      if (!actorName || !latestEvent) continue;
      const newLastActive = toYYYYMM(latestEvent);
      if (!newLastActive) continue;
      try {
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors
           WHERE LOWER(name) = LOWER(?) OR LOWER(actorId) = LOWER(?)
           LIMIT 1`,
          [actorName, actorName]
        );
        if (existing.length === 0) continue;
        const current = existing[0].lastActive;
        const matchedActorId = existing[0].actorId;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE actorId = ?`,
            [newLastActive, matchedActorId]
          );
          result.actorsUpdated++;
        }
      } catch (e) {
        result.errors.push(`UIE ${actorName}: ${e.message}`);
      }
    }
  } catch (e) {
    result.errors.push(`UIE query failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function updateFromRansomwareLiveVictims() {
  const start = Date.now();
  const result = {
    source: "ransomware_live_victims",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0
  };
  let conn = null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3e4);
    let victims;
    try {
      const res = await fetch("https://api.ransomware.live/v1/recentvictims", {
        signal: controller.signal
      });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      victims = await res.json();
    } catch (fetchErr) {
      clearTimeout(timer);
      result.errors.push(`API fetch failed: ${fetchErr.message}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const groupLatest = /* @__PURE__ */ new Map();
    for (const v of victims) {
      const groupName = v.group_name;
      const published = v.published || v.discovered;
      if (!groupName || !published) continue;
      const ym = toYYYYMM(published);
      if (!ym) continue;
      const existing = groupLatest.get(groupName.toLowerCase());
      if (!existing || ym > existing) {
        groupLatest.set(groupName.toLowerCase(), ym);
      }
    }
    result.actorsScanned = groupLatest.size;
    conn = await getRawConnection();
    for (const [groupNameLower, newLastActive] of groupLatest) {
      try {
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors
           WHERE LOWER(name) = ? OR LOWER(actorId) = ?
           LIMIT 1`,
          [groupNameLower, groupNameLower]
        );
        if (existing.length === 0) continue;
        const current = existing[0].lastActive;
        const matchedActorId = existing[0].actorId;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE actorId = ?`,
            [newLastActive, matchedActorId]
          );
          result.actorsUpdated++;
        }
      } catch (e) {
        result.errors.push(`RLV ${groupNameLower}: ${e.message}`);
      }
    }
  } catch (e) {
    result.errors.push(`RLV pipeline failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }
  result.durationMs = Date.now() - start;
  return result;
}
var isRunning = false;
async function runLastActiveUpdate(trigger = "manual") {
  if (isRunning) {
    console.warn("[LastActiveUpdater] Already running, skipping");
    return {
      totalActorsUpdated: 0,
      sources: [],
      auditLogId: null,
      durationMs: 0
    };
  }
  isRunning = true;
  const start = Date.now();
  const sources = [];
  console.log(`[LastActiveUpdater] \u2550\u2550\u2550 Starting ${trigger} update at ${(/* @__PURE__ */ new Date()).toISOString()} \u2550\u2550\u2550`);
  try {
    console.log("[LastActiveUpdater] Source 1: threat_group_events...");
    const tgeResult = await updateFromThreatGroupEvents();
    sources.push(tgeResult);
    console.log(`[LastActiveUpdater]   \u2192 Scanned ${tgeResult.actorsScanned}, updated ${tgeResult.actorsUpdated} (${tgeResult.durationMs}ms)${tgeResult.errors.length ? ` [${tgeResult.errors.length} errors]` : ""}`);
    console.log("[LastActiveUpdater] Source 2: underground_intel_events...");
    const uieResult = await updateFromUndergroundIntelEvents();
    sources.push(uieResult);
    console.log(`[LastActiveUpdater]   \u2192 Scanned ${uieResult.actorsScanned}, updated ${uieResult.actorsUpdated} (${uieResult.durationMs}ms)${uieResult.errors.length ? ` [${uieResult.errors.length} errors]` : ""}`);
    console.log("[LastActiveUpdater] Source 3: ransomware.live /v1/recentvictims...");
    const rlvResult = await updateFromRansomwareLiveVictims();
    sources.push(rlvResult);
    console.log(`[LastActiveUpdater]   \u2192 Scanned ${rlvResult.actorsScanned}, updated ${rlvResult.actorsUpdated} (${rlvResult.durationMs}ms)${rlvResult.errors.length ? ` [${rlvResult.errors.length} errors]` : ""}`);
    const totalUpdated = sources.reduce((sum, s) => sum + s.actorsUpdated, 0);
    const totalScanned = sources.reduce((sum, s) => sum + s.actorsScanned, 0);
    const totalErrors = sources.reduce((sum, s) => sum + s.errors.length, 0);
    const durationMs = Date.now() - start;
    let auditLogId = null;
    try {
      const db = await getDb();
      const [insertResult] = await db.insert(threatIntelUpdates).values({
        sweepType: trigger === "scheduled" ? "scheduled" : "manual",
        tiuStatus: totalErrors > 0 ? "completed" : "completed",
        groupsScanned: totalScanned,
        updatesApplied: totalUpdated,
        newEventsFound: 0,
        newIocsFound: 0,
        newTtpsFound: 0,
        tiuSummary: `lastActive updater: ${totalUpdated} actors updated from ${sources.length} sources (${totalScanned} scanned, ${totalErrors} errors)`,
        tiuDetails: JSON.stringify({
          source: "last_active_updater",
          trigger,
          sources: sources.map((s) => ({
            name: s.source,
            scanned: s.actorsScanned,
            updated: s.actorsUpdated,
            errors: s.errors.length,
            durationMs: s.durationMs
          }))
        }),
        tiuErrors: totalErrors > 0 ? JSON.stringify(sources.flatMap((s) => s.errors).slice(0, 50)) : null,
        tiuStartedAt: new Date(start).toISOString(),
        tiuCompletedAt: (/* @__PURE__ */ new Date()).toISOString(),
        durationMs
      });
      auditLogId = insertResult.insertId || null;
    } catch (auditErr) {
      console.error("[LastActiveUpdater] Failed to write audit log:", auditErr.message);
    }
    console.log(`[LastActiveUpdater] \u2550\u2550\u2550 Complete: ${totalUpdated} actors updated, ${totalScanned} scanned, ${totalErrors} errors (${durationMs}ms) \u2550\u2550\u2550`);
    return {
      totalActorsUpdated: totalUpdated,
      sources,
      auditLogId,
      durationMs
    };
  } finally {
    isRunning = false;
  }
}
function isLastActiveUpdateRunning() {
  return isRunning;
}

export {
  updateFromThreatGroupEvents,
  updateFromUndergroundIntelEvents,
  updateFromRansomwareLiveVictims,
  runLastActiveUpdate,
  isLastActiveUpdateRunning
};
