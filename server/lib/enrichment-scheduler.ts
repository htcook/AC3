/**
 * Enrichment Scheduler — manages background enrichment pipeline runs
 * with concurrency protection and status tracking.
 */

import { runEnrichmentPipeline, type EnrichmentResult } from "./exploit-catalog";
import { ENV } from "../_core/env";

// ─── State ────────────────────────────────────────────────────────────────

let _running = false;
let _lastResult: EnrichmentResult | null = null;
let _lastRunAt: Date | null = null;
let _lastError: string | null = null;
let _nextScheduledRun: Date | null = null;
let _schedulerInterval: ReturnType<typeof setInterval> | null = null;

// ─── Public API ───────────────────────────────────────────────────────────

export function isEnrichmentRunning(): boolean {
  return _running;
}

export function getEnrichmentStatus() {
  return {
    running: _running,
    lastRunAt: _lastRunAt?.toISOString() || null,
    lastResult: _lastResult,
    lastError: _lastError,
    nextScheduledRun: _nextScheduledRun?.toISOString() || null,
    schedulerActive: _schedulerInterval !== null,
  };
}

/**
 * Start the enrichment pipeline in the background.
 * Returns immediately — check status via getEnrichmentStatus().
 */
export function startEnrichment(): void {
  if (_running) return;

  _running = true;
  _lastError = null;

  console.log("[EnrichmentScheduler] Starting enrichment pipeline...");

  const calderaUrl = ENV.calderaBaseUrl || "";

  runEnrichmentPipeline(calderaUrl)
    .then((result) => {
      _lastResult = result;
      _lastRunAt = new Date();
      _lastError = null;
      console.log(
        `[EnrichmentScheduler] Enrichment complete: ${result.totalProcessed} processed, ` +
        `${result.phishingAdded + result.metasploitAdded + result.exploitDbAdded + result.calderaStockpileAdded} added, ` +
        `${result.errors.length} errors`
      );
    })
    .catch((err) => {
      _lastError = err.message || String(err);
      _lastRunAt = new Date();
      console.error("[EnrichmentScheduler] Enrichment failed:", err);
    })
    .finally(() => {
      _running = false;
    });
}

/**
 * Start the weekly scheduler. Runs enrichment every 7 days.
 * Safe to call multiple times — only one scheduler will be active.
 */
export function startScheduler(intervalMs: number = 7 * 24 * 60 * 60 * 1000): void {
  if (_schedulerInterval) return; // Already running

  console.log(`[EnrichmentScheduler] Scheduler started (interval: ${(intervalMs / 1000 / 60 / 60).toFixed(1)}h)`);

  _nextScheduledRun = new Date(Date.now() + intervalMs);

  _schedulerInterval = setInterval(() => {
    if (!_running) {
      console.log("[EnrichmentScheduler] Scheduled enrichment triggered");
      startEnrichment();
    } else {
      console.log("[EnrichmentScheduler] Skipping scheduled run — already running");
    }
    _nextScheduledRun = new Date(Date.now() + intervalMs);
  }, intervalMs);
}

/**
 * Stop the scheduler.
 */
export function stopScheduler(): void {
  if (_schedulerInterval) {
    clearInterval(_schedulerInterval);
    _schedulerInterval = null;
    _nextScheduledRun = null;
    console.log("[EnrichmentScheduler] Scheduler stopped");
  }
}

// ─── Auto-start scheduler on module load ──────────────────────────────────
// Start weekly scheduler automatically when the server boots
startScheduler();
