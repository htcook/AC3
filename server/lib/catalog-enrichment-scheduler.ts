/**
 * Catalog Enrichment Scheduler — Daily automated enrichment of threat actors
 * + Auto-Discovery — Discovers new threat actors using LLM with rotating strategies
 * 
 * Runs daily at 03:00 UTC to:
 * 1. Auto-enrich the lowest-completeness actors (keyword enrichment + guardrails)
 * 2. Run LLM discovery with a rotating strategy to find new threat actors
 * 
 * All runs are recorded in enrichment_history for audit trail.
 * Discovered actors go to a pending review queue (enrichment_history with type='discovery').
 * 
 * Configuration:
 * - BATCH_SIZE: Number of actors to enrich per run (default: 10)
 * - COMPLETENESS_THRESHOLD: Only enrich actors below this % (default: 60)
 * - CRON_HOUR_UTC: Hour to run (default: 3 = 03:00 UTC)
 * - discoveryEnabled: Whether auto-discovery runs after enrichment (default: true)
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
  /** Whether auto-discovery runs after enrichment */
  discoveryEnabled: boolean;
}

const DEFAULT_CONFIG: CatalogEnrichmentConfig = {
  batchSize: 10,
  completenessThreshold: 60,
  cronHourUtc: 3,
  cronMinuteUtc: 0,
  enabled: true,
  discoveryEnabled: true,
};

// ─── Discovery Strategy Rotation ──────────────────────────────────────

const DISCOVERY_STRATEGIES = [
  "related_actors",
  "sector_gaps",
  "recent_campaigns",
  "emerging_threats",
  "geographic_coverage",
] as const;

let _discoveryStrategyIndex = 0;

export function getNextDiscoveryStrategy(): typeof DISCOVERY_STRATEGIES[number] {
  const strategy = DISCOVERY_STRATEGIES[_discoveryStrategyIndex % DISCOVERY_STRATEGIES.length];
  _discoveryStrategyIndex++;
  return strategy;
}

export function getCurrentDiscoveryStrategyIndex(): number {
  return _discoveryStrategyIndex;
}

export function resetDiscoveryStrategyIndex(): void {
  _discoveryStrategyIndex = 0;
}

// ─── State ────────────────────────────────────────────────────────────

let _config: CatalogEnrichmentConfig = { ...DEFAULT_CONFIG };
let _running = false;
let _schedulerTimer: ReturnType<typeof setTimeout> | null = null;
let _lastRunAt: Date | null = null;
let _lastRunResult: CatalogEnrichmentRunResult | null = null;
let _lastError: string | null = null;
let _totalRunsCompleted = 0;
let _totalActorsEnriched = 0;
let _lastDiscoveryResult: DiscoveryRunResult | null = null;
let _totalDiscoveryRuns = 0;
let _totalActorsDiscovered = 0;
let _pendingDiscoveries = 0;

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
  discovery?: DiscoveryRunResult;
}

export interface DiscoveryRunResult {
  strategy: string;
  actorsDiscovered: number;
  actorsAlreadyKnown: number;
  pendingReview: number;
  timestamp: string;
  error?: string;
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
    { name: "techniques", weight: 15 },
    { name: "tools", weight: 10 },
    { name: "targetSectors", weight: 10 },
    { name: "targetRegions", weight: 10 },
    // notableAttacks not on threat_actors table
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
        techniques: schema.threatActors.techniques,
        tools: schema.threatActors.tools,
        targetSectors: schema.threatActors.targetSectors,
        targetRegions: schema.threatActors.targetRegions,
        // notableAttacks not on threat_actors table
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
      console.log("[CatalogEnrichScheduler] No actors below threshold — skipping enrichment");
    } else {
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
    }

    const succeeded = results.filter((r) => r.status === "success").length;
    const totalFieldsUpdated = results.reduce((s, r) => s + r.fieldsUpdated, 0);
    const totalFieldsDiscovered = results.reduce((s, r) => s + r.fieldsDiscovered, 0);

    _totalRunsCompleted++;
    _totalActorsEnriched += succeeded;

    // ─── Auto-Discovery Phase ──────────────────────────────────────
    let discoveryResult: DiscoveryRunResult | undefined;

    if (_config.discoveryEnabled && triggeredBy === "scheduled") {
      discoveryResult = await runAutoDiscovery();
    }

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
      discovery: discoveryResult,
    };

    _lastRunResult = runResult;
    _lastRunAt = new Date();
    _lastError = null;

    console.log(
      `[CatalogEnrichScheduler] Run complete: ${succeeded}/${results.length} succeeded, ` +
      `${totalFieldsUpdated} fields updated, ${totalFieldsDiscovered} fields discovered ` +
      `(${((Date.now() - startTime) / 1000).toFixed(1)}s)` +
      (discoveryResult ? `, discovery: ${discoveryResult.actorsDiscovered} new actors found` : "")
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

// ─── Auto-Discovery ──────────────────────────────────────────────────

export async function runAutoDiscovery(): Promise<DiscoveryRunResult> {
  const strategy = getNextDiscoveryStrategy();
  console.log(`[CatalogEnrichScheduler] Running auto-discovery with strategy: ${strategy}`);

  try {
    const { discoverNewActors } = await import("./threat-actor-discovery");
    const result = await discoverNewActors(strategy as any);

    const discovered = result.discoveredActors || [];
    const alreadyKnown = result.alreadyKnown || [];

    // Store discovered actors in enrichment_history as pending discoveries
    if (discovered.length > 0) {
      const db = await getDb();
      for (const actor of discovered) {
        try {
          await db.insert(schema.enrichmentHistory).values({
            actorId: `discovery-${actor.suggestedId || actor.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
            actorName: actor.name,
            triggeredBy: "scheduled",
            status: "pending_review",
            summary: `[AUTO-DISCOVERY] Strategy: ${strategy}. ${actor.discoveryReason || 'Discovered via automated scan'}`,
            fieldsDiscovered: JSON.stringify(["name", "description", "actorType", "origin", "techniques", "tools", "targetSectors"]),
            sourcesUsed: JSON.stringify(
              (actor.sources || []).slice(0, 5).map((s: any) => ({
                source: s.sourceName,
                sourceType: s.sourceType,
              }))
            ),
            dataQualityBefore: 0,
            dataQualityAfter: actor.confidenceScore || 0,
            durationMs: 0,
            // Store the full actor data in keywordsUsed field (JSON) for retrieval
            keywordsUsed: JSON.stringify({
              _discoveryData: actor,
              _strategy: strategy,
              _timestamp: new Date().toISOString(),
            }),
          });
        } catch (err: any) {
          console.warn(`[CatalogEnrichScheduler] Failed to store discovery for ${actor.name}:`, err?.message);
        }
      }

      _pendingDiscoveries += discovered.length;
    }

    _totalDiscoveryRuns++;
    _totalActorsDiscovered += discovered.length;

    const discoveryResult: DiscoveryRunResult = {
      strategy,
      actorsDiscovered: discovered.length,
      actorsAlreadyKnown: alreadyKnown.length,
      pendingReview: discovered.length,
      timestamp: new Date().toISOString(),
    };

    _lastDiscoveryResult = discoveryResult;

    console.log(
      `[CatalogEnrichScheduler] Discovery complete: ${discovered.length} new, ${alreadyKnown.length} already known, strategy=${strategy}`
    );

    return discoveryResult;
  } catch (err: any) {
    console.error(`[CatalogEnrichScheduler] Auto-discovery failed (strategy=${strategy}):`, err?.message);
    const errorResult: DiscoveryRunResult = {
      strategy,
      actorsDiscovered: 0,
      actorsAlreadyKnown: 0,
      pendingReview: 0,
      timestamp: new Date().toISOString(),
      error: err?.message || "Unknown error",
    };
    _lastDiscoveryResult = errorResult;
    return errorResult;
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
    `batch=${_config.batchSize}, threshold=${_config.completenessThreshold}%, ` +
    `discovery=${_config.discoveryEnabled ? "enabled" : "disabled"}`
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
    discovery: {
      enabled: _config.discoveryEnabled,
      lastResult: _lastDiscoveryResult,
      totalRuns: _totalDiscoveryRuns,
      totalDiscovered: _totalActorsDiscovered,
      pendingReview: _pendingDiscoveries,
      currentStrategyIndex: _discoveryStrategyIndex,
      nextStrategy: DISCOVERY_STRATEGIES[_discoveryStrategyIndex % DISCOVERY_STRATEGIES.length],
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
