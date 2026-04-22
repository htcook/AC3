/**
 * Catalog Enrichment Scheduler — Daily automated enrichment of threat actors
 * 
 * Runs daily at 03:00 UTC to auto-enrich the lowest-completeness actors.
 * Uses the keyword-enrichment pipeline with hallucination guardrails.
 * Records all runs in enrichment_history for audit trail.
 * 
 * Configuration:
 * - BATCH_SIZE: Number of actors to enrich per run (default: 10)
 * - COMPLETENESS_THRESHOLD: Only enrich actors below this % (default: 60)
 * - CRON_HOUR_UTC: Hour to run (default: 3 = 03:00 UTC)
 */

import { getDb } from "../db";
import * as schema from "../../drizzle/schema";
import { eq, sql, asc, lt, and, isNotNull } from "drizzle-orm";

// ─── Configuration ────────────────────────────────────────────────────

export interface CatalogEnrichmentConfig {
  /** Number of actors to enrich per scheduled run */
  batchSize: number;
  /** Only enrich actors below this completeness % */
  completenessThreshold: number;
  /** Hour (UTC) to run the daily enrichment */
  cronHourUtc: number;
  /** Minute (UTC) to run the daily enrichment */
  cronMinuteUtc: number;
  /** Whether the scheduler is enabled */
  enabled: boolean;
}

const DEFAULT_CONFIG: CatalogEnrichmentConfig = {
  batchSize: 10,
  completenessThreshold: 60,
  cronHourUtc: 3,
  cronMinuteUtc: 0,
  enabled: true,
};

// ─── State ────────────────────────────────────────────────────────────

let _config: CatalogEnrichmentConfig = { ...DEFAULT_CONFIG };
let _running = false;
let _schedulerTimer: ReturnType<typeof setTimeout> | null = null;
let _lastRunAt: Date | null = null;
let _lastRunResult: CatalogEnrichmentRunResult | null = null;
let _lastError: string | null = null;
let _totalRunsCompleted = 0;
let _totalActorsEnriched = 0;

export interface CatalogEnrichmentRunResult {
  startedAt: string;
  completedAt: string;
  durationMs: number;
  actorsProcessed: number;
  actorsSucceeded: number;
  actorsFailed: number;
  totalFieldsUpdated: number;
  totalFieldsDiscovered: number;
  triggeredBy: "scheduled" | "manual";
  results: Array<{
    actorId: string;
    actorName: string;
    status: "success" | "failed";
    fieldsUpdated: number;
    fieldsDiscovered: number;
    qualityBefore: number;
    qualityAfter: number;
    error?: string;
  }>;
}

// ─── Completeness Calculator ──────────────────────────────────────────

function computeCompleteness(actor: any): number {
  if (!actor) return 0;
  const fields = [
    { name: "description", weight: 15 },
    { name: "origin", weight: 10 },
    { name: "motivation", weight: 10 },
    { name: "firstSeen", weight: 5 },
    { name: "aliases", weight: 10 },
    { name: "mitreTechniques", weight: 15 },
    { name: "tools", weight: 10 },
    { name: "targetSectors", weight: 10 },
    { name: "targetRegions", weight: 10 },
    { name: "notableAttacks", weight: 5 },
  ];
  let score = 0;
  for (const f of fields) {
    const val = actor[f.name];
    if (!val) continue;
    if (typeof val === "string" && val.trim().length > 0) score += f.weight;
    else if (Array.isArray(val) && val.length > 0) score += f.weight;
    else if (typeof val === "object" && val !== null) {
      const arr = Array.isArray(val) ? val : Object.keys(val);
      if (arr.length > 0) score += f.weight;
    }
  }
  return score;
}

// ─── Core Enrichment Run ──────────────────────────────────────────────

export async function runCatalogEnrichment(
  triggeredBy: "scheduled" | "manual" = "scheduled",
  overrideBatchSize?: number,
  overrideThreshold?: number
): Promise<CatalogEnrichmentRunResult> {
  if (_running) {
    throw new Error("Catalog enrichment is already running");
  }

  _running = true;
  const startTime = Date.now();
  const batchSize = overrideBatchSize ?? _config.batchSize;
  const threshold = overrideThreshold ?? _config.completenessThreshold;

  console.log(
    `[CatalogEnrichScheduler] Starting ${triggeredBy} enrichment run: ` +
    `batch=${batchSize}, threshold=${threshold}%`
  );

  const results: CatalogEnrichmentRunResult["results"] = [];

  try {
    const db = await getDb();
    const { enrichActorWithKeywords } = await import("./keyword-enrichment");

    // Find actors below completeness threshold, ordered by lowest completeness first
    const allActors = await db
      .select({
        actorId: schema.threatActors.actorId,
        name: schema.threatActors.name,
        description: schema.threatActors.description,
        origin: schema.threatActors.origin,
        motivation: schema.threatActors.motivation,
        firstSeen: schema.threatActors.firstSeen,
        aliases: schema.threatActors.aliases,
        mitreTechniques: schema.threatActors.mitreTechniques,
        tools: schema.threatActors.tools,
        targetSectors: schema.threatActors.targetSectors,
        targetRegions: schema.threatActors.targetRegions,
        notableAttacks: schema.threatActors.notableAttacks,
      })
      .from(schema.threatActors)
      .limit(batchSize * 3); // Fetch extra to filter by completeness

    // Calculate completeness and filter
    const incompleteActors = allActors
      .map((a) => ({ ...a, completeness: computeCompleteness(a) }))
      .filter((a) => a.completeness < threshold)
      .sort((a, b) => a.completeness - b.completeness)
      .slice(0, batchSize);

    if (incompleteActors.length === 0) {
      console.log("[CatalogEnrichScheduler] No actors below threshold — skipping");
      const result: CatalogEnrichmentRunResult = {
        startedAt: new Date(startTime).toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime,
        actorsProcessed: 0,
        actorsSucceeded: 0,
        actorsFailed: 0,
        totalFieldsUpdated: 0,
        totalFieldsDiscovered: 0,
        triggeredBy,
        results: [],
      };
      _lastRunResult = result;
      _lastRunAt = new Date();
      return result;
    }

    console.log(
      `[CatalogEnrichScheduler] Found ${incompleteActors.length} actors below ${threshold}% completeness`
    );

    // Process each actor
    for (const actor of incompleteActors) {
      const actorStartTime = Date.now();
      try {
        const enrichResult = await enrichActorWithKeywords(actor.actorId);
        const qualityAfter = enrichResult.dataQualityScore || actor.completeness;

        // Record in enrichment_history
        await db.insert(schema.enrichmentHistory).values({
          actorId: actor.actorId,
          actorName: actor.name || actor.actorId,
          triggeredBy: triggeredBy === "scheduled" ? "scheduled" : "bulk",
          fieldsUpdated: JSON.stringify(enrichResult.fieldsUpdated || []),
          fieldsDiscovered: JSON.stringify(enrichResult.fieldsDiscovered || []),
          sourcesUsed: JSON.stringify(
            (enrichResult.sources || []).map((s: any) => ({
              source: s.source,
              sourceType: s.sourceType,
            }))
          ),
          keywordsUsed: JSON.stringify(enrichResult.keywordsUsed || {}),
          dataQualityBefore: actor.completeness,
          dataQualityAfter: qualityAfter,
          summary: enrichResult.summary || "",
          status: "success",
          durationMs: Date.now() - actorStartTime,
        });

        results.push({
          actorId: actor.actorId,
          actorName: actor.name || actor.actorId,
          status: "success",
          fieldsUpdated: enrichResult.fieldsUpdated?.length || 0,
          fieldsDiscovered: enrichResult.fieldsDiscovered?.length || 0,
          qualityBefore: actor.completeness,
          qualityAfter,
        });

        console.log(
          `[CatalogEnrichScheduler] ✓ ${actor.name}: ${actor.completeness}% → ${qualityAfter}%`
        );
      } catch (err: any) {
        await db
          .insert(schema.enrichmentHistory)
          .values({
            actorId: actor.actorId,
            actorName: actor.name || actor.actorId,
            triggeredBy: triggeredBy === "scheduled" ? "scheduled" : "bulk",
            status: "failed",
            errorMessage: err?.message || "Unknown error",
            durationMs: Date.now() - actorStartTime,
          })
          .catch(() => {});

        results.push({
          actorId: actor.actorId,
          actorName: actor.name || actor.actorId,
          status: "failed",
          fieldsUpdated: 0,
          fieldsDiscovered: 0,
          qualityBefore: actor.completeness,
          qualityAfter: actor.completeness,
          error: err?.message || "Unknown error",
        });

        console.error(
          `[CatalogEnrichScheduler] ✗ ${actor.name}: ${err?.message}`
        );
      }
    }

    const succeeded = results.filter((r) => r.status === "success").length;
    const totalFieldsUpdated = results.reduce((s, r) => s + r.fieldsUpdated, 0);
    const totalFieldsDiscovered = results.reduce((s, r) => s + r.fieldsDiscovered, 0);

    _totalRunsCompleted++;
    _totalActorsEnriched += succeeded;

    const runResult: CatalogEnrichmentRunResult = {
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      actorsProcessed: results.length,
      actorsSucceeded: succeeded,
      actorsFailed: results.length - succeeded,
      totalFieldsUpdated,
      totalFieldsDiscovered,
      triggeredBy,
      results,
    };

    _lastRunResult = runResult;
    _lastRunAt = new Date();
    _lastError = null;

    console.log(
      `[CatalogEnrichScheduler] Run complete: ${succeeded}/${results.length} succeeded, ` +
      `${totalFieldsUpdated} fields updated, ${totalFieldsDiscovered} fields discovered ` +
      `(${((Date.now() - startTime) / 1000).toFixed(1)}s)`
    );

    return runResult;
  } catch (err: any) {
    _lastError = err?.message || String(err);
    _lastRunAt = new Date();
    console.error("[CatalogEnrichScheduler] Run failed:", err);
    throw err;
  } finally {
    _running = false;
  }
}

// ─── Scheduler ────────────────────────────────────────────────────────

function msUntilNextRun(): number {
  const now = new Date();
  const next = new Date(now);
  next.setUTCHours(_config.cronHourUtc, _config.cronMinuteUtc, 0, 0);
  if (next <= now) {
    next.setUTCDate(next.getUTCDate() + 1);
  }
  return next.getTime() - now.getTime();
}

function scheduleNextRun(): void {
  if (!_config.enabled) return;

  const delay = msUntilNextRun();
  const nextRun = new Date(Date.now() + delay);

  console.log(
    `[CatalogEnrichScheduler] Next run scheduled for ${nextRun.toISOString()} ` +
    `(in ${(delay / 1000 / 60).toFixed(0)} minutes)`
  );

  _schedulerTimer = setTimeout(async () => {
    try {
      await runCatalogEnrichment("scheduled");
    } catch (err) {
      console.error("[CatalogEnrichScheduler] Scheduled run failed:", err);
    }
    // Schedule the next one
    scheduleNextRun();
  }, delay);
}

export function startCatalogEnrichmentScheduler(
  config?: Partial<CatalogEnrichmentConfig>
): void {
  if (_schedulerTimer) {
    console.log("[CatalogEnrichScheduler] Scheduler already running");
    return;
  }

  if (config) {
    _config = { ..._config, ...config };
  }

  if (!_config.enabled) {
    console.log("[CatalogEnrichScheduler] Scheduler disabled by config");
    return;
  }

  console.log(
    `[CatalogEnrichScheduler] Starting scheduler: daily at ${String(_config.cronHourUtc).padStart(2, "0")}:${String(_config.cronMinuteUtc).padStart(2, "0")} UTC, ` +
    `batch=${_config.batchSize}, threshold=${_config.completenessThreshold}%`
  );

  scheduleNextRun();
}

export function stopCatalogEnrichmentScheduler(): void {
  if (_schedulerTimer) {
    clearTimeout(_schedulerTimer);
    _schedulerTimer = null;
    console.log("[CatalogEnrichScheduler] Scheduler stopped");
  }
}

// ─── Status & Config ──────────────────────────────────────────────────

export function getCatalogEnrichmentStatus() {
  const nextRunMs = _config.enabled ? msUntilNextRun() : null;
  return {
    config: { ..._config },
    running: _running,
    schedulerActive: _schedulerTimer !== null,
    lastRunAt: _lastRunAt?.toISOString() || null,
    lastRunResult: _lastRunResult,
    lastError: _lastError,
    nextRunAt: nextRunMs
      ? new Date(Date.now() + nextRunMs).toISOString()
      : null,
    stats: {
      totalRunsCompleted: _totalRunsCompleted,
      totalActorsEnriched: _totalActorsEnriched,
    },
  };
}

export function updateCatalogEnrichmentConfig(
  updates: Partial<CatalogEnrichmentConfig>
): CatalogEnrichmentConfig {
  const wasEnabled = _config.enabled;
  _config = { ..._config, ...updates };

  // If enabled state changed, start/stop scheduler
  if (!wasEnabled && _config.enabled) {
    startCatalogEnrichmentScheduler();
  } else if (wasEnabled && !_config.enabled) {
    stopCatalogEnrichmentScheduler();
  } else if (_config.enabled && _schedulerTimer) {
    // Reschedule if time changed
    stopCatalogEnrichmentScheduler();
    scheduleNextRun();
  }

  console.log("[CatalogEnrichScheduler] Config updated:", _config);
  return { ..._config };
}

export function isEnrichmentSchedulerRunning(): boolean {
  return _running;
}
