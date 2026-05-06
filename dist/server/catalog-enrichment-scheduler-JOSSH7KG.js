import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import "./chunk-NRYVRXXR.js";
import {
  enrichmentHistory,
  init_schema,
  threatActors
} from "./chunk-YQRYZ5JK.js";
import "./chunk-KFQGP6VL.js";

// server/lib/catalog-enrichment-scheduler.ts
init_db();
init_schema();
var DEFAULT_CONFIG = {
  batchSize: 10,
  completenessThreshold: 60,
  cronHourUtc: 3,
  cronMinuteUtc: 0,
  enabled: true,
  discoveryEnabled: true
};
var DISCOVERY_STRATEGIES = [
  "related_actors",
  "sector_gaps",
  "recent_campaigns",
  "emerging_threats",
  "geographic_coverage"
];
var _discoveryStrategyIndex = 0;
function getNextDiscoveryStrategy() {
  const strategy = DISCOVERY_STRATEGIES[_discoveryStrategyIndex % DISCOVERY_STRATEGIES.length];
  _discoveryStrategyIndex++;
  return strategy;
}
function getCurrentDiscoveryStrategyIndex() {
  return _discoveryStrategyIndex;
}
function resetDiscoveryStrategyIndex() {
  _discoveryStrategyIndex = 0;
}
var _config = { ...DEFAULT_CONFIG };
var _running = false;
var _schedulerTimer = null;
var _lastRunAt = null;
var _lastRunResult = null;
var _lastError = null;
var _totalRunsCompleted = 0;
var _totalActorsEnriched = 0;
var _lastDiscoveryResult = null;
var _totalDiscoveryRuns = 0;
var _totalActorsDiscovered = 0;
var _pendingDiscoveries = 0;
function computeCompleteness(actor) {
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
    { name: "targetRegions", weight: 10 }
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
async function runCatalogEnrichment(triggeredBy = "scheduled", overrideBatchSize, overrideThreshold) {
  if (_running) {
    throw new Error("Catalog enrichment is already running");
  }
  _running = true;
  const startTime = Date.now();
  const batchSize = overrideBatchSize ?? _config.batchSize;
  const threshold = overrideThreshold ?? _config.completenessThreshold;
  console.log(
    `[CatalogEnrichScheduler] Starting ${triggeredBy} enrichment run: batch=${batchSize}, threshold=${threshold}%`
  );
  const results = [];
  try {
    const db = await getDb();
    const { enrichActorWithKeywords } = await import("./keyword-enrichment-BVUA5WRT.js");
    const allActors = await db.select({
      actorId: threatActors.actorId,
      name: threatActors.name,
      description: threatActors.description,
      origin: threatActors.origin,
      motivation: threatActors.motivation,
      firstSeen: threatActors.firstSeen,
      aliases: threatActors.aliases,
      techniques: threatActors.techniques,
      tools: threatActors.tools,
      targetSectors: threatActors.targetSectors,
      targetRegions: threatActors.targetRegions
      // notableAttacks not on threat_actors table
    }).from(threatActors).limit(batchSize * 3);
    const incompleteActors = allActors.map((a) => ({ ...a, completeness: computeCompleteness(a) })).filter((a) => a.completeness < threshold).sort((a, b) => a.completeness - b.completeness).slice(0, batchSize);
    if (incompleteActors.length === 0) {
      console.log("[CatalogEnrichScheduler] No actors below threshold \u2014 skipping enrichment");
    } else {
      console.log(
        `[CatalogEnrichScheduler] Found ${incompleteActors.length} actors below ${threshold}% completeness`
      );
      for (const actor of incompleteActors) {
        const actorStartTime = Date.now();
        try {
          const enrichResult = await enrichActorWithKeywords(actor.actorId);
          const qualityAfter = enrichResult.dataQualityScore || actor.completeness;
          await db.insert(enrichmentHistory).values({
            actorId: actor.actorId,
            actorName: actor.name || actor.actorId,
            triggeredBy: triggeredBy === "scheduled" ? "scheduled" : "bulk",
            fieldsUpdated: JSON.stringify(enrichResult.fieldsUpdated || []),
            fieldsDiscovered: JSON.stringify(enrichResult.fieldsDiscovered || []),
            sourcesUsed: JSON.stringify(
              (enrichResult.sources || []).map((s) => ({
                source: s.source,
                sourceType: s.sourceType
              }))
            ),
            keywordsUsed: JSON.stringify(enrichResult.keywordsUsed || {}),
            dataQualityBefore: actor.completeness,
            dataQualityAfter: qualityAfter,
            summary: enrichResult.summary || "",
            status: "success",
            durationMs: Date.now() - actorStartTime
          });
          results.push({
            actorId: actor.actorId,
            actorName: actor.name || actor.actorId,
            status: "success",
            fieldsUpdated: enrichResult.fieldsUpdated?.length || 0,
            fieldsDiscovered: enrichResult.fieldsDiscovered?.length || 0,
            qualityBefore: actor.completeness,
            qualityAfter
          });
          console.log(
            `[CatalogEnrichScheduler] \u2713 ${actor.name}: ${actor.completeness}% \u2192 ${qualityAfter}%`
          );
        } catch (err) {
          await db.insert(enrichmentHistory).values({
            actorId: actor.actorId,
            actorName: actor.name || actor.actorId,
            triggeredBy: triggeredBy === "scheduled" ? "scheduled" : "bulk",
            status: "failed",
            errorMessage: err?.message || "Unknown error",
            durationMs: Date.now() - actorStartTime
          }).catch(() => {
          });
          results.push({
            actorId: actor.actorId,
            actorName: actor.name || actor.actorId,
            status: "failed",
            fieldsUpdated: 0,
            fieldsDiscovered: 0,
            qualityBefore: actor.completeness,
            qualityAfter: actor.completeness,
            error: err?.message || "Unknown error"
          });
          console.error(
            `[CatalogEnrichScheduler] \u2717 ${actor.name}: ${err?.message}`
          );
        }
      }
    }
    const succeeded = results.filter((r) => r.status === "success").length;
    const totalFieldsUpdated = results.reduce((s, r) => s + r.fieldsUpdated, 0);
    const totalFieldsDiscovered = results.reduce((s, r) => s + r.fieldsDiscovered, 0);
    _totalRunsCompleted++;
    _totalActorsEnriched += succeeded;
    let discoveryResult;
    if (_config.discoveryEnabled && triggeredBy === "scheduled") {
      discoveryResult = await runAutoDiscovery();
    }
    const runResult = {
      startedAt: new Date(startTime).toISOString(),
      completedAt: (/* @__PURE__ */ new Date()).toISOString(),
      durationMs: Date.now() - startTime,
      actorsProcessed: results.length,
      actorsSucceeded: succeeded,
      actorsFailed: results.length - succeeded,
      totalFieldsUpdated,
      totalFieldsDiscovered,
      triggeredBy,
      results,
      discovery: discoveryResult
    };
    _lastRunResult = runResult;
    _lastRunAt = /* @__PURE__ */ new Date();
    _lastError = null;
    console.log(
      `[CatalogEnrichScheduler] Run complete: ${succeeded}/${results.length} succeeded, ${totalFieldsUpdated} fields updated, ${totalFieldsDiscovered} fields discovered (${((Date.now() - startTime) / 1e3).toFixed(1)}s)` + (discoveryResult ? `, discovery: ${discoveryResult.actorsDiscovered} new actors found` : "")
    );
    return runResult;
  } catch (err) {
    _lastError = err?.message || String(err);
    _lastRunAt = /* @__PURE__ */ new Date();
    console.error("[CatalogEnrichScheduler] Run failed:", err);
    throw err;
  } finally {
    _running = false;
  }
}
async function runAutoDiscovery() {
  const strategy = getNextDiscoveryStrategy();
  console.log(`[CatalogEnrichScheduler] Running auto-discovery with strategy: ${strategy}`);
  try {
    const { discoverNewActors } = await import("./threat-actor-discovery-EYPSCM4F.js");
    const result = await discoverNewActors(strategy);
    const discovered = result.discoveredActors || [];
    const alreadyKnown = result.alreadyKnown || [];
    if (discovered.length > 0) {
      const db = await getDb();
      for (const actor of discovered) {
        try {
          await db.insert(enrichmentHistory).values({
            actorId: `discovery-${actor.suggestedId || actor.name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`,
            actorName: actor.name,
            triggeredBy: "scheduled",
            status: "pending_review",
            summary: `[AUTO-DISCOVERY] Strategy: ${strategy}. ${actor.discoveryReason || "Discovered via automated scan"}`,
            fieldsDiscovered: JSON.stringify(["name", "description", "actorType", "origin", "techniques", "tools", "targetSectors"]),
            sourcesUsed: JSON.stringify(
              (actor.sources || []).slice(0, 5).map((s) => ({
                source: s.sourceName,
                sourceType: s.sourceType
              }))
            ),
            dataQualityBefore: 0,
            dataQualityAfter: actor.confidenceScore || 0,
            durationMs: 0,
            // Store the full actor data in keywordsUsed field (JSON) for retrieval
            keywordsUsed: JSON.stringify({
              _discoveryData: actor,
              _strategy: strategy,
              _timestamp: (/* @__PURE__ */ new Date()).toISOString()
            })
          });
        } catch (err) {
          console.warn(`[CatalogEnrichScheduler] Failed to store discovery for ${actor.name}:`, err?.message);
        }
      }
      _pendingDiscoveries += discovered.length;
    }
    _totalDiscoveryRuns++;
    _totalActorsDiscovered += discovered.length;
    const discoveryResult = {
      strategy,
      actorsDiscovered: discovered.length,
      actorsAlreadyKnown: alreadyKnown.length,
      pendingReview: discovered.length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    _lastDiscoveryResult = discoveryResult;
    console.log(
      `[CatalogEnrichScheduler] Discovery complete: ${discovered.length} new, ${alreadyKnown.length} already known, strategy=${strategy}`
    );
    return discoveryResult;
  } catch (err) {
    console.error(`[CatalogEnrichScheduler] Auto-discovery failed (strategy=${strategy}):`, err?.message);
    const errorResult = {
      strategy,
      actorsDiscovered: 0,
      actorsAlreadyKnown: 0,
      pendingReview: 0,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      error: err?.message || "Unknown error"
    };
    _lastDiscoveryResult = errorResult;
    return errorResult;
  }
}
function msUntilNextRun() {
  const now = /* @__PURE__ */ new Date();
  const next = new Date(now);
  next.setUTCHours(_config.cronHourUtc, _config.cronMinuteUtc, 0, 0);
  if (next <= now) {
    next.setUTCDate(next.getUTCDate() + 1);
  }
  return next.getTime() - now.getTime();
}
function scheduleNextRun() {
  if (!_config.enabled) return;
  const delay = msUntilNextRun();
  const nextRun = new Date(Date.now() + delay);
  console.log(
    `[CatalogEnrichScheduler] Next run scheduled for ${nextRun.toISOString()} (in ${(delay / 1e3 / 60).toFixed(0)} minutes)`
  );
  _schedulerTimer = setTimeout(async () => {
    try {
      await runCatalogEnrichment("scheduled");
    } catch (err) {
      console.error("[CatalogEnrichScheduler] Scheduled run failed:", err);
    }
    scheduleNextRun();
  }, delay);
}
function startCatalogEnrichmentScheduler(config) {
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
    `[CatalogEnrichScheduler] Starting scheduler: daily at ${String(_config.cronHourUtc).padStart(2, "0")}:${String(_config.cronMinuteUtc).padStart(2, "0")} UTC, batch=${_config.batchSize}, threshold=${_config.completenessThreshold}%, discovery=${_config.discoveryEnabled ? "enabled" : "disabled"}`
  );
  scheduleNextRun();
}
function stopCatalogEnrichmentScheduler() {
  if (_schedulerTimer) {
    clearTimeout(_schedulerTimer);
    _schedulerTimer = null;
    console.log("[CatalogEnrichScheduler] Scheduler stopped");
  }
}
function getCatalogEnrichmentStatus() {
  const nextRunMs = _config.enabled ? msUntilNextRun() : null;
  return {
    config: { ..._config },
    running: _running,
    schedulerActive: _schedulerTimer !== null,
    lastRunAt: _lastRunAt?.toISOString() || null,
    lastRunResult: _lastRunResult,
    lastError: _lastError,
    nextRunAt: nextRunMs ? new Date(Date.now() + nextRunMs).toISOString() : null,
    stats: {
      totalRunsCompleted: _totalRunsCompleted,
      totalActorsEnriched: _totalActorsEnriched
    },
    discovery: {
      enabled: _config.discoveryEnabled,
      lastResult: _lastDiscoveryResult,
      totalRuns: _totalDiscoveryRuns,
      totalDiscovered: _totalActorsDiscovered,
      pendingReview: _pendingDiscoveries,
      currentStrategyIndex: _discoveryStrategyIndex,
      nextStrategy: DISCOVERY_STRATEGIES[_discoveryStrategyIndex % DISCOVERY_STRATEGIES.length]
    }
  };
}
function updateCatalogEnrichmentConfig(updates) {
  const wasEnabled = _config.enabled;
  _config = { ..._config, ...updates };
  if (!wasEnabled && _config.enabled) {
    startCatalogEnrichmentScheduler();
  } else if (wasEnabled && !_config.enabled) {
    stopCatalogEnrichmentScheduler();
  } else if (_config.enabled && _schedulerTimer) {
    stopCatalogEnrichmentScheduler();
    scheduleNextRun();
  }
  console.log("[CatalogEnrichScheduler] Config updated:", _config);
  return { ..._config };
}
function isEnrichmentSchedulerRunning() {
  return _running;
}
export {
  getCatalogEnrichmentStatus,
  getCurrentDiscoveryStrategyIndex,
  getNextDiscoveryStrategy,
  isEnrichmentSchedulerRunning,
  resetDiscoveryStrategyIndex,
  runAutoDiscovery,
  runCatalogEnrichment,
  startCatalogEnrichmentScheduler,
  stopCatalogEnrichmentScheduler,
  updateCatalogEnrichmentConfig
};
