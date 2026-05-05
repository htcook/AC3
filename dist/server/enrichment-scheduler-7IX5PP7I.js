import {
  runEnrichmentPipeline
} from "./chunk-Z4A44CCF.js";
import "./chunk-QVLHR5UA.js";
import "./chunk-5LTCMVR2.js";
import "./chunk-Z4F6I6ND.js";
import "./chunk-QMJ22FU6.js";
import "./chunk-PFTNS476.js";
import "./chunk-NIB6SN7A.js";
import "./chunk-TNB3JNVK.js";
import "./chunk-XI75CWCV.js";
import "./chunk-SD56WPOS.js";
import "./chunk-AGW4B7XR.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import "./chunk-YB6W7YNA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/enrichment-scheduler.ts
init_env();
var _running = false;
var _lastResult = null;
var _lastRunAt = null;
var _lastError = null;
var _nextScheduledRun = null;
var _schedulerInterval = null;
function isEnrichmentRunning() {
  return _running;
}
function getEnrichmentStatus() {
  return {
    running: _running,
    lastRunAt: _lastRunAt?.toISOString() || null,
    lastResult: _lastResult,
    lastError: _lastError,
    nextScheduledRun: _nextScheduledRun?.toISOString() || null,
    schedulerActive: _schedulerInterval !== null
  };
}
function startEnrichment() {
  if (_running) return;
  _running = true;
  _lastError = null;
  console.log("[EnrichmentScheduler] Starting enrichment pipeline...");
  const calderaUrl = ENV.calderaBaseUrl || "";
  runEnrichmentPipeline(calderaUrl).then((result) => {
    _lastResult = result;
    _lastRunAt = /* @__PURE__ */ new Date();
    _lastError = null;
    console.log(
      `[EnrichmentScheduler] Enrichment complete: ${result.totalProcessed} processed, ${result.phishingAdded + result.metasploitAdded + result.exploitDbAdded + result.calderaStockpileAdded} added, ${result.errors.length} errors`
    );
  }).catch((err) => {
    _lastError = err.message || String(err);
    _lastRunAt = /* @__PURE__ */ new Date();
    console.error("[EnrichmentScheduler] Enrichment failed:", err);
  }).finally(() => {
    _running = false;
  });
}
function startScheduler(intervalMs = 7 * 24 * 60 * 60 * 1e3) {
  if (_schedulerInterval) return;
  console.log(`[EnrichmentScheduler] Scheduler started (interval: ${(intervalMs / 1e3 / 60 / 60).toFixed(1)}h)`);
  _nextScheduledRun = new Date(Date.now() + intervalMs);
  _schedulerInterval = setInterval(() => {
    if (!_running) {
      console.log("[EnrichmentScheduler] Scheduled enrichment triggered");
      startEnrichment();
    } else {
      console.log("[EnrichmentScheduler] Skipping scheduled run \u2014 already running");
    }
    _nextScheduledRun = new Date(Date.now() + intervalMs);
  }, intervalMs);
}
function stopScheduler() {
  if (_schedulerInterval) {
    clearInterval(_schedulerInterval);
    _schedulerInterval = null;
    _nextScheduledRun = null;
    console.log("[EnrichmentScheduler] Scheduler stopped");
  }
}
startScheduler();
export {
  getEnrichmentStatus,
  isEnrichmentRunning,
  startEnrichment,
  startScheduler,
  stopScheduler
};
