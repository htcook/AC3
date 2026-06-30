/**
 * CISA KEV Catalog Refresh Scheduler
 * 
 * Automatically refreshes the CISA Known Exploited Vulnerabilities catalog
 * on a daily schedule to ensure CVE-to-product mappings stay current.
 * 
 * Schedule: Daily at 03:00 UTC
 * 
 * Features:
 * - Initial load on server boot (deferred 30s to avoid startup congestion)
 * - Daily cron refresh via node-cron
 * - Retry with exponential backoff on failure (up to 3 retries)
 * - Logs new CVE counts, classification stats, and ransomware-linked entries
 * - Exposes status for monitoring via getKEVRefreshStatus()
 */

import cron from "node-cron";
import { loadKEVCatalog, getKEVStats, getRansomwareLinkedCVEs } from "./cisa-kev-product-map";

// ─── State ──────────────────────────────────────────────────────────────────

interface KEVRefreshStatus {
  lastRefreshAttempt: number;
  lastSuccessfulRefresh: number;
  totalRefreshes: number;
  consecutiveFailures: number;
  lastError: string | null;
  lastClassifiedCount: number;
  lastRansomwareCount: number;
  schedulerActive: boolean;
}

const status: KEVRefreshStatus = {
  lastRefreshAttempt: 0,
  lastSuccessfulRefresh: 0,
  totalRefreshes: 0,
  consecutiveFailures: 0,
  lastError: null,
  lastClassifiedCount: 0,
  lastRansomwareCount: 0,
  schedulerActive: false,
};

let cronTask: ReturnType<typeof cron.schedule> | null = null;

// ─── Refresh Logic ──────────────────────────────────────────────────────────

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY = 5000; // 5 seconds, doubles each retry

async function refreshWithRetry(trigger: string): Promise<boolean> {
  status.lastRefreshAttempt = Date.now();

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`[KEV Scheduler] Refresh attempt ${attempt}/${MAX_RETRIES} (trigger: ${trigger})`);

      const classified = await loadKEVCatalog();
      const stats = getKEVStats();
      const ransomwareCVEs = getRansomwareLinkedCVEs();

      status.lastSuccessfulRefresh = Date.now();
      status.totalRefreshes++;
      status.consecutiveFailures = 0;
      status.lastError = null;
      status.lastClassifiedCount = classified;
      status.lastRansomwareCount = ransomwareCVEs.length;

      console.log(
        `[KEV Scheduler] ✓ Refresh complete: ${classified} CVEs classified across ${stats.families} families, ` +
        `${ransomwareCVEs.length} ransomware-linked, ${stats.staticFallbackCount} static fallback entries`
      );

      return true;
    } catch (err: any) {
      const errMsg = err?.message || String(err);
      console.warn(`[KEV Scheduler] Attempt ${attempt} failed: ${errMsg}`);

      if (attempt < MAX_RETRIES) {
        const delay = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
        console.log(`[KEV Scheduler] Retrying in ${delay / 1000}s...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        status.consecutiveFailures++;
        status.lastError = errMsg;
        console.error(`[KEV Scheduler] ✗ All ${MAX_RETRIES} attempts failed. Will retry at next scheduled time.`);
      }
    }
  }

  return false;
}

// ─── Scheduler Init ─────────────────────────────────────────────────────────

/**
 * Initialize the daily KEV catalog refresh scheduler.
 * - Schedules daily refresh at 03:00 UTC
 * - Deferred initial load 30s after server start
 */
export function initKEVRefreshScheduler(): void {
  if (status.schedulerActive) {
    console.warn("[KEV Scheduler] Already initialized, skipping duplicate init");
    return;
  }

  // Daily cron at 03:00 UTC
  cronTask = cron.schedule("0 3 * * *", async () => {
    try {
      await refreshWithRetry("cron");
    } catch (err) {
      console.error("[KEV Scheduler] Cron refresh failed:", err);
    }
  }, {
    timezone: "UTC",
  });

  status.schedulerActive = true;
  console.log("[KEV Scheduler] Daily refresh scheduled at 03:00 UTC");

  // Deferred initial load — 30 seconds after server start
  setTimeout(async () => {
    console.log("[KEV Scheduler] Running initial KEV catalog load...");
    await refreshWithRetry("startup");
  }, 30_000);
}

/**
 * Stop the KEV refresh scheduler (for graceful shutdown / tests)
 */
export function stopKEVRefreshScheduler(): void {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
  }
  status.schedulerActive = false;
  console.log("[KEV Scheduler] Stopped");
}

/**
 * Get the current KEV refresh scheduler status
 */
export function getKEVRefreshStatus(): KEVRefreshStatus {
  return { ...status };
}

/**
 * Force an immediate KEV refresh (for manual triggers / tRPC endpoints)
 */
export async function forceKEVRefresh(): Promise<boolean> {
  return refreshWithRetry("manual");
}
