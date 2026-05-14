import {
  runLastActiveUpdate
} from "./chunk-PH2D57VN.js";
import "./chunk-26A2QP6T.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-NWJ2JNWL.js";
import "./chunk-KFQGP6VL.js";

// server/lib/last-active-scheduler.ts
import cron from "node-cron";
var schedulerInitialized = false;
var scheduledTask = null;
function initLastActiveScheduler() {
  if (schedulerInitialized) {
    console.log("[LastActiveScheduler] Already initialized, skipping");
    return;
  }
  scheduledTask = cron.schedule(
    "0 15 8 * * *",
    async () => {
      console.log("[LastActiveScheduler] Triggering scheduled lastActive update...");
      try {
        const result = await runLastActiveUpdate("scheduled");
        console.log(
          `[LastActiveScheduler] Completed: ${result.totalActorsUpdated} actors updated from ${result.sources.length} sources (${result.durationMs}ms)`
        );
      } catch (err) {
        console.error("[LastActiveScheduler] Scheduled update failed:", err.message);
      }
    },
    { timezone: "UTC" }
  );
  schedulerInitialized = true;
  console.log("[LastActiveScheduler] Initialized \u2014 daily at 08:15 UTC");
}
function stopLastActiveScheduler() {
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }
  schedulerInitialized = false;
  console.log("[LastActiveScheduler] Stopped");
}
function isLastActiveSchedulerActive() {
  return schedulerInitialized;
}
export {
  initLastActiveScheduler,
  isLastActiveSchedulerActive,
  stopLastActiveScheduler
};
