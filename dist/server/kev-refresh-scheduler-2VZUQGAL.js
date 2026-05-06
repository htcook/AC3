import {
  getKEVStats,
  getRansomwareLinkedCVEs,
  init_cisa_kev_product_map,
  loadKEVCatalog
} from "./chunk-SUY74CRT.js";
import "./chunk-KFQGP6VL.js";

// server/lib/kev-refresh-scheduler.ts
init_cisa_kev_product_map();
import cron from "node-cron";
var status = {
  lastRefreshAttempt: 0,
  lastSuccessfulRefresh: 0,
  totalRefreshes: 0,
  consecutiveFailures: 0,
  lastError: null,
  lastClassifiedCount: 0,
  lastRansomwareCount: 0,
  schedulerActive: false
};
var cronTask = null;
var MAX_RETRIES = 3;
var RETRY_BASE_DELAY = 5e3;
async function refreshWithRetry(trigger) {
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
        `[KEV Scheduler] \u2713 Refresh complete: ${classified} CVEs classified across ${stats.families} families, ${ransomwareCVEs.length} ransomware-linked, ${stats.staticFallbackCount} static fallback entries`
      );
      return true;
    } catch (err) {
      const errMsg = err?.message || String(err);
      console.warn(`[KEV Scheduler] Attempt ${attempt} failed: ${errMsg}`);
      if (attempt < MAX_RETRIES) {
        const delay = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
        console.log(`[KEV Scheduler] Retrying in ${delay / 1e3}s...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      } else {
        status.consecutiveFailures++;
        status.lastError = errMsg;
        console.error(`[KEV Scheduler] \u2717 All ${MAX_RETRIES} attempts failed. Will retry at next scheduled time.`);
      }
    }
  }
  return false;
}
function initKEVRefreshScheduler() {
  if (status.schedulerActive) {
    console.warn("[KEV Scheduler] Already initialized, skipping duplicate init");
    return;
  }
  cronTask = cron.schedule("0 3 * * *", async () => {
    try {
      await refreshWithRetry("cron");
    } catch (err) {
      console.error("[KEV Scheduler] Cron refresh failed:", err);
    }
  }, {
    timezone: "UTC"
  });
  status.schedulerActive = true;
  console.log("[KEV Scheduler] Daily refresh scheduled at 03:00 UTC");
  setTimeout(async () => {
    console.log("[KEV Scheduler] Running initial KEV catalog load...");
    await refreshWithRetry("startup");
  }, 3e4);
}
function stopKEVRefreshScheduler() {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
  }
  status.schedulerActive = false;
  console.log("[KEV Scheduler] Stopped");
}
function getKEVRefreshStatus() {
  return { ...status };
}
async function forceKEVRefresh() {
  return refreshWithRetry("manual");
}
export {
  forceKEVRefresh,
  getKEVRefreshStatus,
  initKEVRefreshScheduler,
  stopKEVRefreshScheduler
};
