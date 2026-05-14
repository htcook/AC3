import {
  getDefaultThresholds,
  runIABSpikeCheck
} from "./chunk-3GD7BL5Z.js";
import {
  runIABIngestionPipeline
} from "./chunk-Q42REVIX.js";
import "./chunk-5DFXFIVE.js";
import "./chunk-V73EMRJ6.js";
import "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-TYPEU32S.js";
import "./chunk-KFQGP6VL.js";

// server/lib/iab-ingestion-scheduler.ts
import cron from "node-cron";
var schedulerInitialized = false;
var activeTasks = [];
async function runScheduledIngestion() {
  console.log("[IABScheduler] Starting daily IAB ingestion pipeline...");
  const start = Date.now();
  try {
    const result = await runIABIngestionPipeline();
    const duration = Date.now() - start;
    const sourceResults = result.results.map((r) => `${r.source}: ${r.inserted} new, ${r.skipped} skipped${r.error ? ` (ERROR: ${r.error})` : ""}`).join("; ");
    console.log(
      `[IABScheduler] Ingestion complete in ${duration}ms: ${result.totalInserted} new listings, ${result.totalErrors} errors. Sources: ${sourceResults}`
    );
  } catch (e) {
    console.error(`[IABScheduler] Ingestion pipeline failed: ${e.message}`);
  }
}
async function runScheduledSpikeCheck() {
  console.log("[IABScheduler] Starting daily spike detection...");
  const start = Date.now();
  try {
    const thresholds = getDefaultThresholds();
    const result = await runIABSpikeCheck(thresholds);
    const duration = Date.now() - start;
    if (result.alerts.length === 0) {
      console.log(`[IABScheduler] Spike check complete in ${duration}ms: No anomalies detected.`);
    } else {
      const critical = result.alerts.filter((a) => a.severity === "critical").length;
      const high = result.alerts.filter((a) => a.severity === "high").length;
      const medium = result.alerts.filter((a) => a.severity === "medium").length;
      const low = result.alerts.filter((a) => a.severity === "low").length;
      console.log(
        `[IABScheduler] Spike check complete in ${duration}ms: ${result.alerts.length} alerts (${critical} critical, ${high} high, ${medium} medium, ${low} low). ${result.notificationsSent} notifications sent, ${result.notificationsFailed} failed.`
      );
      result.alerts.forEach((alert) => {
        console.log(`[IABScheduler] [${alert.severity.toUpperCase()}] ${alert.title}`);
      });
    }
  } catch (e) {
    console.error(`[IABScheduler] Spike detection failed: ${e.message}`);
  }
}
function initIABIngestionScheduler() {
  if (schedulerInitialized) {
    console.log("[IABScheduler] Already initialized, skipping");
    return;
  }
  activeTasks.push(
    cron.schedule("0 45 8 * * *", runScheduledIngestion, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 15 9 * * *", runScheduledSpikeCheck, { timezone: "UTC" })
  );
  schedulerInitialized = true;
  console.log("[IABScheduler] IAB ingestion & spike detection scheduler initialized:");
  console.log("  - IAB ingestion pipeline: daily at 08:45 UTC");
  console.log("  - Spike detection + alerting: daily at 09:15 UTC");
}
function stopIABIngestionScheduler() {
  activeTasks.forEach((t) => t.stop());
  activeTasks.length = 0;
  schedulerInitialized = false;
  console.log("[IABScheduler] All scheduled tasks stopped");
}
function isIABSchedulerActive() {
  return schedulerInitialized;
}
export {
  initIABIngestionScheduler,
  isIABSchedulerActive,
  stopIABIngestionScheduler
};
