/**
 * Threat Intel Auto-Enrich Pipeline
 *
 * Monitors threat actor enrichment events and automatically triggers
 * adversary profile generation when an actor's completeness score
 * crosses the threshold.
 *
 * Integration points:
 *   1. threat-actor-crawler.ts — enrichActorFromIntel() calls our hook
 *   2. caldera-sync.ts — syncCalderaAdversaries() triggers re-evaluation
 *   3. c2-tactical-knowledge.ts — scoreProfileCompleteness() + generateAdversaryProfile()
 *   4. caldera-profile-push.ts — pushProfileToCaldera() for auto-deployment
 *
 * Flow:
 *   Intel ingested → actor enriched → score checked → threshold met →
 *   profile generated → optionally pushed to Caldera → notification emitted
 */

import { getDb } from "../db";
import { threatActors } from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";
import {
  scoreProfileCompleteness,
  generateAdversaryProfile,
  type ProfileCompletenessScore,
} from "./c2-tactical-knowledge";
import { pushProfileToCaldera } from "./caldera-profile-push";

// ─── Configuration ──────────────────────────────────────────────────────

const AUTO_GENERATION_CONFIG = {
  /** Minimum completeness score to trigger auto-generation */
  minScore: 60,
  /** Whether to auto-push generated profiles to Caldera */
  autoPushToCaldera: true,
  /** Cooldown period between auto-generation attempts for the same actor (ms) */
  cooldownMs: 60 * 60 * 1000, // 1 hour
  /** Maximum auto-generations per pipeline run */
  maxPerRun: 20,
};

// ─── Types ───────────────────────────────────────────────────────────────

export interface AutoGenerationEvent {
  actorId: string;
  actorName: string;
  triggeredAt: string;
  triggerSource: "intel_enrichment" | "caldera_sync" | "manual" | "scheduled";
  previousScore: number | null;
  newScore: number;
  thresholdMet: boolean;
  profileGenerated: boolean;
  pushedToCaldera: boolean;
  error?: string;
}

export interface AutoGenerationStats {
  totalChecks: number;
  totalGenerated: number;
  totalPushed: number;
  totalSkipped: number;
  totalFailed: number;
  lastRunAt: string | null;
  configuredThreshold: number;
  autoPushEnabled: boolean;
}

// ─── In-Memory State ────────────────────────────────────────────────────

const autoGenHistory: AutoGenerationEvent[] = [];
const lastCheckTimestamps = new Map<string, number>();
let stats: AutoGenerationStats = {
  totalChecks: 0,
  totalGenerated: 0,
  totalPushed: 0,
  totalSkipped: 0,
  totalFailed: 0,
  lastRunAt: null,
  configuredThreshold: AUTO_GENERATION_CONFIG.minScore,
  autoPushEnabled: AUTO_GENERATION_CONFIG.autoPushToCaldera,
};

// ─── Core Pipeline Functions ────────────────────────────────────────────

/**
 * Check a single actor's completeness and trigger profile generation
 * if the threshold is met. Called after intel enrichment or manually.
 */
export async function checkAndTriggerProfileGeneration(
  actorId: string,
  triggerSource: AutoGenerationEvent["triggerSource"] = "manual",
): Promise<AutoGenerationEvent> {
  const triggeredAt = new Date().toISOString();
  stats.totalChecks++;
  stats.lastRunAt = triggeredAt;

  // Cooldown check
  const lastCheck = lastCheckTimestamps.get(actorId);
  if (lastCheck && Date.now() - lastCheck < AUTO_GENERATION_CONFIG.cooldownMs) {
    const event: AutoGenerationEvent = {
      actorId,
      actorName: actorId,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: 0,
      thresholdMet: false,
      profileGenerated: false,
      pushedToCaldera: false,
      error: "Cooldown period active — skipped",
    };
    stats.totalSkipped++;
    recordEvent(event);
    return event;
  }

  lastCheckTimestamps.set(actorId, Date.now());

  try {
    // Score the actor's profile completeness
    const score = await scoreProfileCompleteness(actorId);
    if (!score) {
      const event: AutoGenerationEvent = {
        actorId,
        actorName: actorId,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: 0,
        thresholdMet: false,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Actor not found or scoring failed",
      };
      stats.totalSkipped++;
      recordEvent(event);
      return event;
    }

    const thresholdMet = score.readyForAutoGeneration && score.score >= AUTO_GENERATION_CONFIG.minScore;

    if (!thresholdMet) {
      const event: AutoGenerationEvent = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: false,
        profileGenerated: false,
        pushedToCaldera: false,
      };
      stats.totalSkipped++;
      recordEvent(event);
      return event;
    }

    // Skip if already has a deployed profile
    if (score.hasCalderaProfile) {
      const event: AutoGenerationEvent = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: true,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Profile already exists — skipped",
      };
      stats.totalSkipped++;
      recordEvent(event);
      return event;
    }

    // Generate the adversary profile
    console.log(
      `[AutoEnrich] Threshold met for ${score.actorName} (score: ${score.score}). Generating profile...`,
    );

    const profile = await generateAdversaryProfile(actorId);
    if (!profile) {
      const event: AutoGenerationEvent = {
        actorId,
        actorName: score.actorName,
        triggeredAt,
        triggerSource,
        previousScore: null,
        newScore: score.score,
        thresholdMet: true,
        profileGenerated: false,
        pushedToCaldera: false,
        error: "Profile generation returned null — insufficient abilities",
      };
      stats.totalFailed++;
      recordEvent(event);
      return event;
    }

    stats.totalGenerated++;
    console.log(
      `[AutoEnrich] Generated profile for ${score.actorName}: ${profile.abilityCount} abilities, ${profile.killChainPhases.length} phases`,
    );

    // Notify operator about auto-generated profile
    try {
      const { notifyOwner } = await import("../_core/notification");
      await notifyOwner({
        title: `Adversary Profile Auto-Generated — ${score.actorName}`,
        content: `An adversary emulation profile was automatically generated for ${score.actorName} (completeness score: ${score.score}/100).\n\nAbilities: ${profile.abilityCount}\nKill Chain Phases: ${profile.killChainPhases.join(', ')}\nTrigger: ${triggerSource}\n\nReview in the C2 Knowledge Base → Deploy & Pipeline tab.`,
      });
    } catch (e: any) {
      console.warn(`[AutoEnrich] Notification failed:`, e.message);
    }

    // Auto-push to Caldera if enabled
    let pushedToCaldera = false;
    if (AUTO_GENERATION_CONFIG.autoPushToCaldera) {
      try {
        const pushResult = await pushProfileToCaldera(actorId);
        pushedToCaldera = pushResult.success;
        if (pushedToCaldera) {
          stats.totalPushed++;
          console.log(`[AutoEnrich] Auto-pushed profile for ${score.actorName} to Caldera`);

          // Notify operator about auto-push to Caldera
          try {
            const { notifyOwner } = await import("../_core/notification");
            await notifyOwner({
              title: `Profile Deployed to Caldera — ${score.actorName}`,
              content: `The adversary profile for ${score.actorName} was automatically pushed to the Caldera server.\n\nAbilities: ${profile.abilityCount}\nPhases: ${profile.killChainPhases.join(', ')}\n\nThe profile is now available for adversary emulation operations.`,
            });
          } catch (e: any) {
            console.warn(`[AutoEnrich] Push notification failed:`, e.message);
          }
        }
      } catch (pushErr: any) {
        console.warn(`[AutoEnrich] Auto-push failed for ${score.actorName}:`, pushErr.message);
      }
    }

    const event: AutoGenerationEvent = {
      actorId,
      actorName: score.actorName,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: score.score,
      thresholdMet: true,
      profileGenerated: true,
      pushedToCaldera,
    };
    recordEvent(event);
    return event;
  } catch (err: any) {
    const event: AutoGenerationEvent = {
      actorId,
      actorName: actorId,
      triggeredAt,
      triggerSource,
      previousScore: null,
      newScore: 0,
      thresholdMet: false,
      profileGenerated: false,
      pushedToCaldera: false,
      error: err.message,
    };
    stats.totalFailed++;
    recordEvent(event);
    return event;
  }
}

/**
 * Batch check all actors that might be eligible for auto-generation.
 * Called by the scheduled pipeline or manually.
 */
export async function runAutoGenerationPipeline(
  triggerSource: AutoGenerationEvent["triggerSource"] = "scheduled",
): Promise<{
  checked: number;
  generated: number;
  pushed: number;
  skipped: number;
  failed: number;
  events: AutoGenerationEvent[];
}> {
  const db = await getDb();
  if (!db) return { checked: 0, generated: 0, pushed: 0, skipped: 0, failed: 0, events: [] };

  console.log("[AutoEnrich] Running auto-generation pipeline...");

  // Find actors with abilities but no caldera profile
  const candidates = await db.execute(
    sql`SELECT ta.actorId, ta.name, COUNT(taa.id) as abilityCount
        FROM threat_actors ta
        JOIN threat_actor_abilities taa ON ta.actorId = taa.actorId
        WHERE ta.calderaProfile IS NULL OR ta.calderaProfile = 'null'
        GROUP BY ta.actorId, ta.name
        HAVING abilityCount >= 10
        ORDER BY abilityCount DESC
        LIMIT ${AUTO_GENERATION_CONFIG.maxPerRun}`,
  );

  const rows = (candidates[0] as any[]) || [];
  const events: AutoGenerationEvent[] = [];
  let generated = 0,
    pushed = 0,
    skipped = 0,
    failed = 0;

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
    `[AutoEnrich] Pipeline complete: ${rows.length} checked, ${generated} generated, ${pushed} pushed, ${skipped} skipped, ${failed} failed`,
  );

  return { checked: rows.length, generated, pushed, skipped, failed, events };
}

// ─── Hook for Threat Actor Crawler ──────────────────────────────────────

/**
 * Hook to be called after enrichActorFromIntel() in threat-actor-crawler.ts.
 * Checks if the enrichment pushed the actor over the auto-generation threshold.
 *
 * Usage in threat-actor-crawler.ts:
 *   import { onActorEnriched } from "./threat-intel-auto-enrich";
 *   // After enrichActorFromIntel():
 *   await onActorEnriched(actorId);
 */
export async function onActorEnriched(actorId: string): Promise<AutoGenerationEvent | null> {
  try {
    return await checkAndTriggerProfileGeneration(actorId, "intel_enrichment");
  } catch (err: any) {
    console.warn(`[AutoEnrich] onActorEnriched hook failed for ${actorId}:`, err.message);
    return null;
  }
}

/**
 * Hook to be called after syncCalderaAdversaries() in caldera-sync.ts.
 * Re-evaluates all actors that were updated during the sync.
 */
export async function onCalderaSyncComplete(
  syncedActorIds: string[],
): Promise<AutoGenerationEvent[]> {
  const events: AutoGenerationEvent[] = [];
  for (const actorId of syncedActorIds.slice(0, AUTO_GENERATION_CONFIG.maxPerRun)) {
    const event = await checkAndTriggerProfileGeneration(actorId, "caldera_sync");
    events.push(event);
  }
  return events;
}

// ─── History & Stats ────────────────────────────────────────────────────

function recordEvent(event: AutoGenerationEvent): void {
  autoGenHistory.push(event);
  // Keep bounded
  if (autoGenHistory.length > 500) {
    autoGenHistory.splice(0, autoGenHistory.length - 500);
  }
}

export function getAutoGenerationHistory(limit = 20): AutoGenerationEvent[] {
  return [...autoGenHistory].reverse().slice(0, limit);
}

export function getAutoGenerationStats(): AutoGenerationStats {
  return { ...stats };
}

/**
 * Update auto-generation configuration at runtime.
 */
export function updateAutoGenerationConfig(updates: {
  minScore?: number;
  autoPushToCaldera?: boolean;
  cooldownMs?: number;
  maxPerRun?: number;
}): void {
  if (updates.minScore !== undefined) {
    AUTO_GENERATION_CONFIG.minScore = updates.minScore;
    stats.configuredThreshold = updates.minScore;
  }
  if (updates.autoPushToCaldera !== undefined) {
    AUTO_GENERATION_CONFIG.autoPushToCaldera = updates.autoPushToCaldera;
    stats.autoPushEnabled = updates.autoPushToCaldera;
  }
  if (updates.cooldownMs !== undefined) {
    AUTO_GENERATION_CONFIG.cooldownMs = updates.cooldownMs;
  }
  if (updates.maxPerRun !== undefined) {
    AUTO_GENERATION_CONFIG.maxPerRun = updates.maxPerRun;
  }
}
