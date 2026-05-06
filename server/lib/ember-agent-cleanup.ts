/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * EMBER AGENT CLEANUP — Self-Destruct & Dead Agent Purge
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Provides:
 *   1. Scheduled cleanup job — purges dead agents after configurable retention
 *   2. Cascade cleanup — removes associated beacons, tasks, and payloads
 *   3. Manual purge — allows operators to force-purge specific agents or all dead
 *   4. Retention policy — configurable retention period (default: 7 days)
 *   5. Audit trail — logs all cleanup actions for accountability
 *
 * The cleanup runs on a configurable interval (default: 1 hour) and only
 * targets agents that have been in "dead" or "self_destruct" state for
 * longer than the retention period.
 */

import { getDb } from "../db";
import { emberAgents, emberBeacons, emberTasks } from "../../drizzle/schema";
import { eq, and, sql, inArray, lte, or } from "drizzle-orm";

// ─── Configuration ──────────────────────────────────────────────────────

export interface EmberCleanupConfig {
  /** How long to retain dead agents before purging, in hours (default: 168 = 7 days) */
  retentionHours: number;
  /** Whether to also clean up associated beacons (default: true) */
  cleanBeacons: boolean;
  /** Whether to also clean up associated tasks (default: true) */
  cleanTasks: boolean;
  /** Whether to send notifications on purge (default: true) */
  notifyOnPurge: boolean;
}

const DEFAULT_CONFIG: EmberCleanupConfig = {
  retentionHours: 168, // 7 days
  cleanBeacons: true,
  cleanTasks: true,
  notifyOnPurge: true,
};

// ─── Types ──────────────────────────────────────────────────────────────

export interface CleanupResult {
  timestamp: number;
  durationMs: number;
  agentsPurged: number;
  beaconsDeleted: number;
  tasksDeleted: number;
  purgedAgents: Array<{
    agentId: string;
    name: string;
    state: string;
    deadSinceHours: number;
    beaconsRemoved: number;
    tasksRemoved: number;
  }>;
  errors: string[];
}

// ─── State ──────────────────────────────────────────────────────────────

let cleanupInterval: ReturnType<typeof setInterval> | null = null;
let lastCleanupResult: CleanupResult | null = null;

// ─── Core Cleanup Logic ─────────────────────────────────────────────────

/**
 * Run a cleanup sweep — finds dead/self-destructed agents past retention
 * and purges them along with their beacons and tasks.
 */
export async function runEmberCleanup(
  configOverrides?: Partial<EmberCleanupConfig>,
): Promise<CleanupResult> {
  const config = { ...DEFAULT_CONFIG, ...(configOverrides || {}) };
  const startTime = Date.now();
  const errors: string[] = [];
  const purgedAgents: CleanupResult["purgedAgents"] = [];
  let totalBeacons = 0;
  let totalTasks = 0;

  try {
    const db = await getDb();
    if (!db) {
      // DB not yet connected — skip this sweep silently
      const result: CleanupResult = {
        timestamp: Date.now(),
        durationMs: Date.now() - startTime,
        agentsPurged: 0,
        beaconsDeleted: 0,
        tasksDeleted: 0,
        purgedAgents: [],
        errors: ["Database not yet available — skipping sweep"],
      };
      lastCleanupResult = result;
      return result;
    }
    const cutoffMs = Date.now() - config.retentionHours * 60 * 60 * 1000;

    // Find agents eligible for cleanup:
    // - State is "dead" or "self_destruct"
    // - Last beacon was before the cutoff time
    const eligibleAgents = await db
      .select({
        id: emberAgents.id,
        agentId: emberAgents.agentId,
        name: emberAgents.emberName,
        state: emberAgents.emberState,
        lastBeaconAt: emberAgents.lastBeaconAt,
        createdAt: emberAgents.emberCreatedAt,
      })
      .from(emberAgents)
      .where(
        and(
          or(
            eq(emberAgents.emberState, "dead"),
            eq(emberAgents.emberState, "self_destruct"),
          ),
          lte(emberAgents.lastBeaconAt, cutoffMs),
        ),
      );

    if (eligibleAgents.length === 0) {
      const result: CleanupResult = {
        timestamp: Date.now(),
        durationMs: Date.now() - startTime,
        agentsPurged: 0,
        beaconsDeleted: 0,
        tasksDeleted: 0,
        purgedAgents: [],
        errors: [],
      };
      lastCleanupResult = result;
      return result;
    }

    // Process each eligible agent
    for (const agent of eligibleAgents) {
      try {
        let beaconsRemoved = 0;
        let tasksRemoved = 0;
        const deadSinceHours = Math.round(
          (Date.now() - (agent.lastBeaconAt || agent.createdAt || 0)) / (60 * 60 * 1000),
        );

        // Delete associated beacons
        if (config.cleanBeacons) {
          const beaconResult = await db
            .delete(emberBeacons)
            .where(eq(emberBeacons.agentId, agent.agentId));
          beaconsRemoved = (beaconResult as any)?.[0]?.affectedRows || 0;
          totalBeacons += beaconsRemoved;
        }

        // Delete associated tasks
        if (config.cleanTasks) {
          const taskResult = await db
            .delete(emberTasks)
            .where(eq(emberTasks.agentId, agent.agentId));
          tasksRemoved = (taskResult as any)?.[0]?.affectedRows || 0;
          totalTasks += tasksRemoved;
        }

        // Delete the agent itself
        await db
          .delete(emberAgents)
          .where(eq(emberAgents.agentId, agent.agentId));

        purgedAgents.push({
          agentId: agent.agentId,
          name: agent.name || agent.agentId,
          state: agent.state || "dead",
          deadSinceHours,
          beaconsRemoved,
          tasksRemoved,
        });

        console.log(
          `[EmberCleanup] Purged agent ${agent.name || agent.agentId} ` +
          `(dead ${deadSinceHours}h, ${beaconsRemoved} beacons, ${tasksRemoved} tasks)`,
        );
      } catch (err: any) {
        const msg = `Failed to purge agent ${agent.agentId}: ${err.message}`;
        console.error(`[EmberCleanup] ${msg}`);
        errors.push(msg);
      }
    }

    // Send notification if agents were purged
    if (purgedAgents.length > 0 && config.notifyOnPurge) {
      try {
        const { notifyOwner } = await import("../_core/notification");
        const agentList = purgedAgents
          .map((a) => `  • ${a.name} (dead ${a.deadSinceHours}h)`)
          .join("\n");
        await notifyOwner({
          title: `🧹 Ember Cleanup: ${purgedAgents.length} agent(s) purged`,
          content:
            `Retention policy (${config.retentionHours}h) triggered cleanup:\n\n` +
            agentList +
            `\n\nTotal removed: ${totalBeacons} beacons, ${totalTasks} tasks`,
        });
      } catch {
        // Notification failure is non-fatal
      }
    }
  } catch (err: any) {
    console.error(`[EmberCleanup] Sweep error: ${err.message}`);
    errors.push(`Sweep error: ${err.message}`);
  }

  const result: CleanupResult = {
    timestamp: Date.now(),
    durationMs: Date.now() - startTime,
    agentsPurged: purgedAgents.length,
    beaconsDeleted: totalBeacons,
    tasksDeleted: totalTasks,
    purgedAgents,
    errors,
  };

  lastCleanupResult = result;
  return result;
}

// ─── Manual Purge ───────────────────────────────────────────────────────

/**
 * Force-purge a specific agent by ID, regardless of retention period.
 */
export async function purgeAgent(agentId: string): Promise<{
  success: boolean;
  beaconsDeleted: number;
  tasksDeleted: number;
  error?: string;
}> {
  try {
    const db = await getDb();

    // Verify agent exists
    const [agent] = await db
      .select()
      .from(emberAgents)
      .where(eq(emberAgents.agentId, agentId))
      .limit(1);

    if (!agent) {
      return { success: false, beaconsDeleted: 0, tasksDeleted: 0, error: "Agent not found" };
    }

    // Delete beacons
    const beaconResult = await db
      .delete(emberBeacons)
      .where(eq(emberBeacons.agentId, agentId));
    const beaconsDeleted = (beaconResult as any)?.[0]?.affectedRows || 0;

    // Delete tasks
    const taskResult = await db
      .delete(emberTasks)
      .where(eq(emberTasks.agentId, agentId));
    const tasksDeleted = (taskResult as any)?.[0]?.affectedRows || 0;

    // Delete agent
    await db.delete(emberAgents).where(eq(emberAgents.agentId, agentId));

    console.log(
      `[EmberCleanup] Force-purged agent ${agent.emberName || agentId} ` +
      `(${beaconsDeleted} beacons, ${tasksDeleted} tasks)`,
    );

    return { success: true, beaconsDeleted, tasksDeleted };
  } catch (err: any) {
    return { success: false, beaconsDeleted: 0, tasksDeleted: 0, error: err.message };
  }
}

/**
 * Purge all dead agents regardless of retention period.
 */
export async function purgeAllDead(): Promise<CleanupResult> {
  return runEmberCleanup({ retentionHours: 0 });
}

// ─── Scheduler ──────────────────────────────────────────────────────────

export function startEmberCleanupScheduler(opts?: {
  intervalMs?: number;
  config?: Partial<EmberCleanupConfig>;
}) {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }

  const intervalMs = opts?.intervalMs || 3_600_000; // Default: 1 hour
  const config = opts?.config;

  console.log(
    `[EmberCleanup] Starting cleanup scheduler (every ${Math.round(intervalMs / 60000)}min, ` +
    `retention: ${config?.retentionHours || DEFAULT_CONFIG.retentionHours}h)`,
  );

  // Run initial cleanup after DB has time to connect (30s delay)
  setTimeout(() => {
    runEmberCleanup(config).then((result) => {
      if (result.agentsPurged > 0) {
        console.log(
          `[EmberCleanup] Initial sweep: purged ${result.agentsPurged} agents, ` +
          `${result.beaconsDeleted} beacons, ${result.tasksDeleted} tasks`,
        );
      }
    }).catch((err) => {
      console.warn(`[EmberCleanup] Initial sweep failed: ${err.message}`);
    });
  }, 30_000);

  cleanupInterval = setInterval(() => {
    runEmberCleanup(config).then((result) => {
      if (result.agentsPurged > 0) {
        console.log(
          `[EmberCleanup] Scheduled sweep: purged ${result.agentsPurged} agents`,
        );
      }
    }).catch((err) => {
      console.warn(`[EmberCleanup] Scheduled sweep failed: ${err.message}`);
    });
  }, intervalMs);
}

export function stopEmberCleanupScheduler() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log("[EmberCleanup] Cleanup scheduler stopped");
  }
}

export function getLastCleanupResult(): CleanupResult | null {
  return lastCleanupResult;
}
