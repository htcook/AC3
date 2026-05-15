import {
  getDb,
  init_db
} from "./chunk-TY7YEWON.js";
import "./chunk-NRYVRXXR.js";
import {
  emberAgents,
  emberBeacons,
  emberTasks,
  init_schema
} from "./chunk-2DDCINQV.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ember-agent-cleanup.ts
init_db();
init_schema();
import { eq, and, lte, or } from "drizzle-orm";
var DEFAULT_CONFIG = {
  retentionHours: 168,
  // 7 days
  cleanBeacons: true,
  cleanTasks: true,
  notifyOnPurge: true
};
var cleanupInterval = null;
var lastCleanupResult = null;
async function runEmberCleanup(configOverrides) {
  const config = { ...DEFAULT_CONFIG, ...configOverrides || {} };
  const startTime = Date.now();
  const errors = [];
  const purgedAgents = [];
  let totalBeacons = 0;
  let totalTasks = 0;
  try {
    const db = await getDb();
    if (!db) {
      const result2 = {
        timestamp: Date.now(),
        durationMs: Date.now() - startTime,
        agentsPurged: 0,
        beaconsDeleted: 0,
        tasksDeleted: 0,
        purgedAgents: [],
        errors: ["Database not yet available \u2014 skipping sweep"]
      };
      lastCleanupResult = result2;
      return result2;
    }
    const cutoffMs = Date.now() - config.retentionHours * 60 * 60 * 1e3;
    const eligibleAgents = await db.select({
      id: emberAgents.id,
      agentId: emberAgents.agentId,
      name: emberAgents.emberName,
      state: emberAgents.emberState,
      lastBeaconAt: emberAgents.lastBeaconAt,
      createdAt: emberAgents.emberCreatedAt
    }).from(emberAgents).where(
      and(
        or(
          eq(emberAgents.emberState, "dead"),
          eq(emberAgents.emberState, "self_destruct")
        ),
        lte(emberAgents.lastBeaconAt, cutoffMs)
      )
    );
    if (eligibleAgents.length === 0) {
      const result2 = {
        timestamp: Date.now(),
        durationMs: Date.now() - startTime,
        agentsPurged: 0,
        beaconsDeleted: 0,
        tasksDeleted: 0,
        purgedAgents: [],
        errors: []
      };
      lastCleanupResult = result2;
      return result2;
    }
    for (const agent of eligibleAgents) {
      try {
        let beaconsRemoved = 0;
        let tasksRemoved = 0;
        const deadSinceHours = Math.round(
          (Date.now() - (agent.lastBeaconAt || agent.createdAt || 0)) / (60 * 60 * 1e3)
        );
        if (config.cleanBeacons) {
          const beaconResult = await db.delete(emberBeacons).where(eq(emberBeacons.agentId, agent.agentId));
          beaconsRemoved = beaconResult?.[0]?.affectedRows || 0;
          totalBeacons += beaconsRemoved;
        }
        if (config.cleanTasks) {
          const taskResult = await db.delete(emberTasks).where(eq(emberTasks.agentId, agent.agentId));
          tasksRemoved = taskResult?.[0]?.affectedRows || 0;
          totalTasks += tasksRemoved;
        }
        await db.delete(emberAgents).where(eq(emberAgents.agentId, agent.agentId));
        purgedAgents.push({
          agentId: agent.agentId,
          name: agent.name || agent.agentId,
          state: agent.state || "dead",
          deadSinceHours,
          beaconsRemoved,
          tasksRemoved
        });
        console.log(
          `[EmberCleanup] Purged agent ${agent.name || agent.agentId} (dead ${deadSinceHours}h, ${beaconsRemoved} beacons, ${tasksRemoved} tasks)`
        );
      } catch (err) {
        const msg = `Failed to purge agent ${agent.agentId}: ${err.message}`;
        console.error(`[EmberCleanup] ${msg}`);
        errors.push(msg);
      }
    }
    if (purgedAgents.length > 0 && config.notifyOnPurge) {
      try {
        const { notifyOwner } = await import("./notification-4RFY3TAD.js");
        const agentList = purgedAgents.map((a) => `  \u2022 ${a.name} (dead ${a.deadSinceHours}h)`).join("\n");
        await notifyOwner({
          title: `\u{1F9F9} Ember Cleanup: ${purgedAgents.length} agent(s) purged`,
          content: `Retention policy (${config.retentionHours}h) triggered cleanup:

` + agentList + `

Total removed: ${totalBeacons} beacons, ${totalTasks} tasks`
        });
      } catch {
      }
    }
  } catch (err) {
    console.error(`[EmberCleanup] Sweep error: ${err.message}`);
    errors.push(`Sweep error: ${err.message}`);
  }
  const result = {
    timestamp: Date.now(),
    durationMs: Date.now() - startTime,
    agentsPurged: purgedAgents.length,
    beaconsDeleted: totalBeacons,
    tasksDeleted: totalTasks,
    purgedAgents,
    errors
  };
  lastCleanupResult = result;
  return result;
}
async function purgeAgent(agentId) {
  try {
    const db = await getDb();
    const [agent] = await db.select().from(emberAgents).where(eq(emberAgents.agentId, agentId)).limit(1);
    if (!agent) {
      return { success: false, beaconsDeleted: 0, tasksDeleted: 0, error: "Agent not found" };
    }
    const beaconResult = await db.delete(emberBeacons).where(eq(emberBeacons.agentId, agentId));
    const beaconsDeleted = beaconResult?.[0]?.affectedRows || 0;
    const taskResult = await db.delete(emberTasks).where(eq(emberTasks.agentId, agentId));
    const tasksDeleted = taskResult?.[0]?.affectedRows || 0;
    await db.delete(emberAgents).where(eq(emberAgents.agentId, agentId));
    console.log(
      `[EmberCleanup] Force-purged agent ${agent.emberName || agentId} (${beaconsDeleted} beacons, ${tasksDeleted} tasks)`
    );
    return { success: true, beaconsDeleted, tasksDeleted };
  } catch (err) {
    return { success: false, beaconsDeleted: 0, tasksDeleted: 0, error: err.message };
  }
}
async function purgeAllDead() {
  return runEmberCleanup({ retentionHours: 0 });
}
function startEmberCleanupScheduler(opts) {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  const intervalMs = opts?.intervalMs || 36e5;
  const config = opts?.config;
  console.log(
    `[EmberCleanup] Starting cleanup scheduler (every ${Math.round(intervalMs / 6e4)}min, retention: ${config?.retentionHours || DEFAULT_CONFIG.retentionHours}h)`
  );
  setTimeout(() => {
    runEmberCleanup(config).then((result) => {
      if (result.agentsPurged > 0) {
        console.log(
          `[EmberCleanup] Initial sweep: purged ${result.agentsPurged} agents, ${result.beaconsDeleted} beacons, ${result.tasksDeleted} tasks`
        );
      }
    }).catch((err) => {
      console.warn(`[EmberCleanup] Initial sweep failed: ${err.message}`);
    });
  }, 3e4);
  cleanupInterval = setInterval(() => {
    runEmberCleanup(config).then((result) => {
      if (result.agentsPurged > 0) {
        console.log(
          `[EmberCleanup] Scheduled sweep: purged ${result.agentsPurged} agents`
        );
      }
    }).catch((err) => {
      console.warn(`[EmberCleanup] Scheduled sweep failed: ${err.message}`);
    });
  }, intervalMs);
}
function stopEmberCleanupScheduler() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log("[EmberCleanup] Cleanup scheduler stopped");
  }
}
function getLastCleanupResult() {
  return lastCleanupResult;
}
export {
  getLastCleanupResult,
  purgeAgent,
  purgeAllDead,
  runEmberCleanup,
  startEmberCleanupScheduler,
  stopEmberCleanupScheduler
};
