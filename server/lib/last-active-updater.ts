/**
 * Threat Actor lastActive Updater Service
 *
 * Dynamically updates threat_actors.lastActive (YYYY-MM format) from real event data:
 *
 *   Source 1: threat_group_events — most recent eventDate per tgeActorId
 *   Source 2: underground_intel_events — most recent uie_event_date per uie_actor_name
 *   Source 3: ransomware.live /v1/recentvictims API — fresh victim claims matched to actors
 *
 * Only updates lastActive if the new date is MORE RECENT than the existing value.
 * Logs an audit trail to threat_intel_updates after each run.
 *
 * Designed to run daily after the main darkweb feed sync (08:15 UTC).
 */

import { getDb } from "../db";
import {
  threatActors,
  threatIntelUpdates,
} from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";
import mysql from "mysql2/promise";

// ─── Types ───────────────────────────────────────────────────────────────

export interface LastActiveUpdateResult {
  source: string;
  actorsScanned: number;
  actorsUpdated: number;
  errors: string[];
  durationMs: number;
}

export interface LastActiveRunResult {
  totalActorsUpdated: number;
  sources: LastActiveUpdateResult[];
  auditLogId: number | null;
  durationMs: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/** Convert a Date or date string to YYYY-MM format */
function toYYYYMM(d: Date | string): string {
  const date = typeof d === "string" ? new Date(d) : d;
  if (isNaN(date.getTime())) return "";
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

/** Compare two YYYY-MM strings. Returns true if `a` is more recent than `b`. */
function isMoreRecent(a: string, b: string | null | undefined): boolean {
  if (!b) return !!a;
  return a > b;
}

/** Get a raw mysql2 connection for parameterized queries (TiDB compatibility) */
async function getRawConnection(): Promise<mysql.Connection> {
  return mysql.createConnection(process.env.DATABASE_URL!);
}

// ─── Source 1: threat_group_events ───────────────────────────────────────

/**
 * Query the most recent eventDate per tgeActorId from threat_group_events,
 * then update threat_actors.lastActive where the event date is newer.
 */
export async function updateFromThreatGroupEvents(): Promise<LastActiveUpdateResult> {
  const start = Date.now();
  const result: LastActiveUpdateResult = {
    source: "threat_group_events",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0,
  };

  let conn: mysql.Connection | null = null;
  try {
    conn = await getRawConnection();

    // Get the most recent eventDate per actor from threat_group_events
    const [rows] = await conn.execute(`
      SELECT tgeActorId, MAX(eventDate) as latestEvent
      FROM threat_group_events
      WHERE eventDate IS NOT NULL
      GROUP BY tgeActorId
    `) as any[];

    result.actorsScanned = rows.length;

    for (const row of rows) {
      const actorId = row.tgeActorId as string;
      const latestEvent = row.latestEvent as string;
      if (!actorId || !latestEvent) continue;

      const newLastActive = toYYYYMM(latestEvent);
      if (!newLastActive) continue;

      try {
        // Get current lastActive for this actor (match by actorId, case-insensitive)
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors WHERE LOWER(actorId) = LOWER(?)`,
          [actorId]
        ) as any[];

        if (existing.length === 0) continue;

        const current = existing[0].lastActive as string | null;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE LOWER(actorId) = LOWER(?)`,
            [newLastActive, actorId]
          );
          result.actorsUpdated++;
        }
      } catch (e: any) {
        result.errors.push(`TGE ${actorId}: ${e.message}`);
      }
    }
  } catch (e: any) {
    result.errors.push(`TGE query failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── Source 2: underground_intel_events ──────────────────────────────────

/**
 * Query the most recent uie_event_date per uie_actor_name from underground_intel_events,
 * then match to threat_actors by name or actorId and update lastActive.
 */
export async function updateFromUndergroundIntelEvents(): Promise<LastActiveUpdateResult> {
  const start = Date.now();
  const result: LastActiveUpdateResult = {
    source: "underground_intel_events",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0,
  };

  let conn: mysql.Connection | null = null;
  try {
    conn = await getRawConnection();

    // Get the most recent event date per actor name
    const [rows] = await conn.execute(`
      SELECT uie_actor_name, MAX(uie_event_date) as latestEvent
      FROM underground_intel_events
      WHERE uie_actor_name IS NOT NULL AND uie_actor_name != ''
      GROUP BY uie_actor_name
    `) as any[];

    result.actorsScanned = rows.length;

    for (const row of rows) {
      const actorName = row.uie_actor_name as string;
      const latestEvent = row.latestEvent as string;
      if (!actorName || !latestEvent) continue;

      const newLastActive = toYYYYMM(latestEvent);
      if (!newLastActive) continue;

      try {
        // Try matching by name first, then by actorId (case-insensitive)
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors
           WHERE LOWER(name) = LOWER(?) OR LOWER(actorId) = LOWER(?)
           LIMIT 1`,
          [actorName, actorName]
        ) as any[];

        if (existing.length === 0) continue;

        const current = existing[0].lastActive as string | null;
        const matchedActorId = existing[0].actorId as string;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE actorId = ?`,
            [newLastActive, matchedActorId]
          );
          result.actorsUpdated++;
        }
      } catch (e: any) {
        result.errors.push(`UIE ${actorName}: ${e.message}`);
      }
    }
  } catch (e: any) {
    result.errors.push(`UIE query failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── Source 3: ransomware.live /v1/recentvictims ─────────────────────────

/**
 * Fetch recent victims from ransomware.live API, extract group names,
 * and update threat_actors.lastActive for matched groups.
 */
export async function updateFromRansomwareLiveVictims(): Promise<LastActiveUpdateResult> {
  const start = Date.now();
  const result: LastActiveUpdateResult = {
    source: "ransomware_live_victims",
    actorsScanned: 0,
    actorsUpdated: 0,
    errors: [],
    durationMs: 0,
  };

  let conn: mysql.Connection | null = null;
  try {
    // Fetch recent victims from ransomware.live
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    let victims: any[];
    try {
      const res = await fetch("https://api.ransomware.live/v1/recentvictims", {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      victims = (await res.json()) as any[];
    } catch (fetchErr: any) {
      clearTimeout(timer);
      result.errors.push(`API fetch failed: ${fetchErr.message}`);
      result.durationMs = Date.now() - start;
      return result;
    }

    // Build a map: group_name → most recent published date
    const groupLatest = new Map<string, string>();
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
        // Match by name or actorId (case-insensitive)
        const [existing] = await conn.execute(
          `SELECT actorId, lastActive FROM threat_actors
           WHERE LOWER(name) = ? OR LOWER(actorId) = ?
           LIMIT 1`,
          [groupNameLower, groupNameLower]
        ) as any[];

        if (existing.length === 0) continue;

        const current = existing[0].lastActive as string | null;
        const matchedActorId = existing[0].actorId as string;
        if (isMoreRecent(newLastActive, current)) {
          await conn.execute(
            `UPDATE threat_actors SET lastActive = ? WHERE actorId = ?`,
            [newLastActive, matchedActorId]
          );
          result.actorsUpdated++;
        }
      } catch (e: any) {
        result.errors.push(`RLV ${groupNameLower}: ${e.message}`);
      }
    }
  } catch (e: any) {
    result.errors.push(`RLV pipeline failed: ${e.message}`);
  } finally {
    if (conn) await conn.end();
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── Orchestrator ────────────────────────────────────────────────────────

let isRunning = false;

/**
 * Run the full lastActive update pipeline:
 *   1. Update from threat_group_events
 *   2. Update from underground_intel_events
 *   3. Update from ransomware.live /v1/recentvictims
 *   4. Log audit trail to threat_intel_updates
 */
export async function runLastActiveUpdate(
  trigger: "scheduled" | "manual" = "manual"
): Promise<LastActiveRunResult> {
  if (isRunning) {
    console.warn("[LastActiveUpdater] Already running, skipping");
    return {
      totalActorsUpdated: 0,
      sources: [],
      auditLogId: null,
      durationMs: 0,
    };
  }

  isRunning = true;
  const start = Date.now();
  const sources: LastActiveUpdateResult[] = [];

  console.log(`[LastActiveUpdater] ═══ Starting ${trigger} update at ${new Date().toISOString()} ═══`);

  try {
    // Source 1: threat_group_events
    console.log("[LastActiveUpdater] Source 1: threat_group_events...");
    const tgeResult = await updateFromThreatGroupEvents();
    sources.push(tgeResult);
    console.log(`[LastActiveUpdater]   → Scanned ${tgeResult.actorsScanned}, updated ${tgeResult.actorsUpdated} (${tgeResult.durationMs}ms)${tgeResult.errors.length ? ` [${tgeResult.errors.length} errors]` : ""}`);

    // Source 2: underground_intel_events
    console.log("[LastActiveUpdater] Source 2: underground_intel_events...");
    const uieResult = await updateFromUndergroundIntelEvents();
    sources.push(uieResult);
    console.log(`[LastActiveUpdater]   → Scanned ${uieResult.actorsScanned}, updated ${uieResult.actorsUpdated} (${uieResult.durationMs}ms)${uieResult.errors.length ? ` [${uieResult.errors.length} errors]` : ""}`);

    // Source 3: ransomware.live
    console.log("[LastActiveUpdater] Source 3: ransomware.live /v1/recentvictims...");
    const rlvResult = await updateFromRansomwareLiveVictims();
    sources.push(rlvResult);
    console.log(`[LastActiveUpdater]   → Scanned ${rlvResult.actorsScanned}, updated ${rlvResult.actorsUpdated} (${rlvResult.durationMs}ms)${rlvResult.errors.length ? ` [${rlvResult.errors.length} errors]` : ""}`);

    const totalUpdated = sources.reduce((sum, s) => sum + s.actorsUpdated, 0);
    const totalScanned = sources.reduce((sum, s) => sum + s.actorsScanned, 0);
    const totalErrors = sources.reduce((sum, s) => sum + s.errors.length, 0);
    const durationMs = Date.now() - start;

    // Log audit trail to threat_intel_updates
    let auditLogId: number | null = null;
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
            durationMs: s.durationMs,
          })),
        }),
        tiuErrors: totalErrors > 0 ? JSON.stringify(sources.flatMap((s) => s.errors).slice(0, 50)) : null,
        tiuStartedAt: new Date(start).toISOString(),
        tiuCompletedAt: new Date().toISOString(),
        durationMs,
      });
      auditLogId = (insertResult as any).insertId || null;
    } catch (auditErr: any) {
      console.error("[LastActiveUpdater] Failed to write audit log:", auditErr.message);
    }

    console.log(`[LastActiveUpdater] ═══ Complete: ${totalUpdated} actors updated, ${totalScanned} scanned, ${totalErrors} errors (${durationMs}ms) ═══`);

    return {
      totalActorsUpdated: totalUpdated,
      sources,
      auditLogId,
      durationMs,
    };
  } finally {
    isRunning = false;
  }
}

/** Check if the updater is currently running */
export function isLastActiveUpdateRunning(): boolean {
  return isRunning;
}
