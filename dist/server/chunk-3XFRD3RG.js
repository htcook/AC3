import {
  pushProfileToCaldera
} from "./chunk-RMBJXXOW.js";
import {
  generateAdversaryProfile,
  init_c2_tactical_knowledge,
  scoreProfileCompleteness
} from "./chunk-MOHDLHEH.js";
import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";

// server/lib/threat-intel-auto-enrich.ts
init_db();
init_c2_tactical_knowledge();
import { sql } from "drizzle-orm";
var AUTO_GENERATION_CONFIG = {
  /** Minimum completeness score to trigger auto-generation */
  minScore: 60,
  /** Whether to auto-push generated profiles to Caldera */
  autoPushToCaldera: true,
  /** Cooldown period between auto-generation attempts for the same actor (ms) */
  cooldownMs: 60 * 60 * 1e3,
  // 1 hour
  /** Maximum auto-generations per pipeline run */
  maxPerRun: 20
};
var autoGenHistory = [];
var lastCheckTimestamps = /* @__PURE__ */ new Map();
var stats = {
  totalChecks: 0,
  totalGenerated: 0,
  totalPushed: 0,
  totalSkipped: 0,
  totalFailed: 0,
  lastRunAt: null,
  configuredThreshold: AUTO_GENERATION_CONFIG.minScore,
  autoPushEnabled: AUTO_GENERATION_CONFIG.autoPushToCaldera
};
async function checkAndTriggerProfileGeneration(actorId, triggerSource = "manual") {
  const triggeredAt = (/* @__PURE__ */ new Date()).toISOString();
  stats.totalChecks++;
  stats.lastRunAt = triggeredAt;
  const lastCheck = lastCheckTimestamps.get(actorId);
  if (lastCheck && Date.now() - lastCheck < AUTO_GENERATION_CONFIG.cooldownMs) {
    const event = {
      actorId,
      actorName: actorId,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: 0,
      thresholdMet: false,
      profileGenerated: false,
      pushedToCaldera: false,
      error: "Cooldown period active \u2014 skipped"
    };
    stats.totalSkipped++;
    recordEvent(event);
    return event;
  }
  lastCheckTimestamps.set(actorId, Date.now());
  try {
    const score = await scoreProfileCompleteness(actorId);
    if (!score) {
      const event2 = {
        actorId,
        actorName: actorId,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: 0,
        thresholdMet: false,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Actor not found or scoring failed"
      };
      stats.totalSkipped++;
      recordEvent(event2);
      return event2;
    }
    const thresholdMet = score.readyForAutoGeneration && score.score >= AUTO_GENERATION_CONFIG.minScore;
    if (!thresholdMet) {
      const event2 = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: false,
        profileGenerated: false,
        pushedToCaldera: false
      };
      stats.totalSkipped++;
      recordEvent(event2);
      return event2;
    }
    if (score.hasCalderaProfile) {
      const event2 = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: true,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Profile already exists \u2014 skipped"
      };
      stats.totalSkipped++;
      recordEvent(event2);
      return event2;
    }
    console.log(
      `[AutoEnrich] Threshold met for ${score.actorName} (score: ${score.score}). Generating profile...`
    );
    const profile = await generateAdversaryProfile(actorId);
    if (!profile) {
      const event2 = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: true,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Profile generation returned null \u2014 insufficient abilities"
      };
      stats.totalFailed++;
      recordEvent(event2);
      return event2;
    }
    stats.totalGenerated++;
    console.log(
      `[AutoEnrich] Generated profile for ${score.actorName}: ${profile.abilityCount} abilities, ${profile.killChainPhases.length} phases`
    );
    try {
      const { emitProfileGenerated } = await import("./ws-event-hub-GYTLNKYI.js");
      emitProfileGenerated({
        actorId,
        actorName: score.actorName,
        completenessScore: score.score,
        techniquesCount: score.techniqueCount,
        tacticsCount: score.tacticsCovered
      });
    } catch (e) {
      console.warn(`[AutoEnrich] WS event emission failed:`, e.message);
    }
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      await notifyOwner({
        title: `Adversary Profile Auto-Generated \u2014 ${score.actorName}`,
        content: `An adversary emulation profile was automatically generated for ${score.actorName} (completeness score: ${score.score}/100).

Abilities: ${profile.abilityCount}
Kill Chain Phases: ${profile.killChainPhases.join(", ")}
Trigger: ${triggerSource}

Review in the C2 Knowledge Base \u2192 Deploy & Pipeline tab.`
      });
    } catch (e) {
      console.warn(`[AutoEnrich] Notification failed:`, e.message);
    }
    let pushedToCaldera = false;
    if (AUTO_GENERATION_CONFIG.autoPushToCaldera) {
      try {
        const pushResult = await pushProfileToCaldera(actorId);
        pushedToCaldera = pushResult.success;
        if (pushedToCaldera) {
          stats.totalPushed++;
          console.log(`[AutoEnrich] Auto-pushed profile for ${score.actorName} to Caldera`);
          try {
            const { emitProfilePushed } = await import("./ws-event-hub-GYTLNKYI.js");
            emitProfilePushed({
              actorId,
              actorName: score.actorName,
              success: true
            });
          } catch (e) {
            console.warn(`[AutoEnrich] WS push event emission failed:`, e.message);
          }
          try {
            const { notifyOwner } = await import("./notification-4RFY3TAD.js");
            await notifyOwner({
              title: `Profile Deployed to Caldera \u2014 ${score.actorName}`,
              content: `The adversary profile for ${score.actorName} was automatically pushed to the Caldera server.

Abilities: ${profile.abilityCount}
Phases: ${profile.killChainPhases.join(", ")}

The profile is now available for adversary emulation operations.`
            });
          } catch (e) {
            console.warn(`[AutoEnrich] Push notification failed:`, e.message);
          }
        }
      } catch (pushErr) {
        console.warn(`[AutoEnrich] Auto-push failed for ${score.actorName}:`, pushErr.message);
      }
    }
    const event = {
      actorId,
      actorName: score.actorName,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: score.score,
      thresholdMet: true,
      profileGenerated: true,
      pushedToCaldera
    };
    recordEvent(event);
    return event;
  } catch (err) {
    const event = {
      actorId,
      actorName: actorId,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: 0,
      thresholdMet: false,
      profileGenerated: false,
      pushedToCaldera: false,
      error: err.message
    };
    stats.totalFailed++;
    recordEvent(event);
    return event;
  }
}
async function runAutoGenerationPipeline(triggerSource = "scheduled") {
  const db = await getDb();
  if (!db) return { checked: 0, generated: 0, pushed: 0, skipped: 0, failed: 0, events: [] };
  console.log("[AutoEnrich] Running auto-generation pipeline...");
  const candidates = await db.execute(
    sql`SELECT ta.actorId, ta.name, COUNT(taa.id) as abilityCount
        FROM threat_actors ta
        JOIN threat_actor_abilities taa ON ta.actorId = taa.actorId
        WHERE ta.calderaProfile IS NULL OR ta.calderaProfile = 'null'
        GROUP BY ta.actorId, ta.name
        HAVING abilityCount >= 10
        ORDER BY abilityCount DESC
        LIMIT ${AUTO_GENERATION_CONFIG.maxPerRun}`
  );
  const rows = candidates[0] || [];
  const events = [];
  let generated = 0, pushed = 0, skipped = 0, failed = 0;
  for (const row of rows) {
    const event = await checkAndTriggerProfileGeneration(row.actorId, triggerSource);
    events.push(event);
    if (event.profileGenerated) generated++;
    if (event.pushedToCaldera) pushed++;
    if (event.error && !event.profileGenerated) {
      if (event.error.includes("skipped") || event.error.includes("Cooldown")) skipped++;
      else failed++;
    }
    if (!event.thresholdMet && !event.error) skipped++;
  }
  console.log(
    `[AutoEnrich] Pipeline complete: ${rows.length} checked, ${generated} generated, ${pushed} pushed, ${skipped} skipped, ${failed} failed`
  );
  return { checked: rows.length, generated, pushed, skipped, failed, events };
}
async function onActorEnriched(actorId) {
  try {
    return await checkAndTriggerProfileGeneration(actorId, "intel_enrichment");
  } catch (err) {
    console.warn(`[AutoEnrich] onActorEnriched hook failed for ${actorId}:`, err.message);
    return null;
  }
}
async function onCalderaSyncComplete(syncedActorIds) {
  const events = [];
  for (const actorId of syncedActorIds.slice(0, AUTO_GENERATION_CONFIG.maxPerRun)) {
    const event = await checkAndTriggerProfileGeneration(actorId, "caldera_sync");
    events.push(event);
  }
  return events;
}
function recordEvent(event) {
  autoGenHistory.push(event);
  if (autoGenHistory.length > 500) {
    autoGenHistory.splice(0, autoGenHistory.length - 500);
  }
}
function getAutoGenerationHistory(limit = 20) {
  return [...autoGenHistory].reverse().slice(0, limit);
}
function getAutoGenerationStats() {
  return { ...stats };
}
function updateAutoGenerationConfig(updates) {
  if (updates.minScore !== void 0) {
    AUTO_GENERATION_CONFIG.minScore = updates.minScore;
    stats.configuredThreshold = updates.minScore;
  }
  if (updates.autoPushToCaldera !== void 0) {
    AUTO_GENERATION_CONFIG.autoPushToCaldera = updates.autoPushToCaldera;
    stats.autoPushEnabled = updates.autoPushToCaldera;
  }
  if (updates.cooldownMs !== void 0) {
    AUTO_GENERATION_CONFIG.cooldownMs = updates.cooldownMs;
  }
  if (updates.maxPerRun !== void 0) {
    AUTO_GENERATION_CONFIG.maxPerRun = updates.maxPerRun;
  }
}

export {
  checkAndTriggerProfileGeneration,
  runAutoGenerationPipeline,
  onActorEnriched,
  onCalderaSyncComplete,
  getAutoGenerationHistory,
  getAutoGenerationStats,
  updateAutoGenerationConfig
};
