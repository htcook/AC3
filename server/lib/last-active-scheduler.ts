/**
 * lastActive Updater Scheduler
 *
 * Registers a daily cron job at 08:15 UTC to update threat_actors.lastActive
 * from real event data sources. Runs AFTER the main darkweb feed sync
 * (abuse.ch at :00, ransomware.live at :30, DDW RSS at 08:30) and BEFORE
 * IAB ingestion at 08:45 UTC.
 *
 * Timeline:
 *   06:00-08:00 — Feed syncs populate threat_group_events & underground_intel_events
 *   08:15 UTC   — lastActive updater derives dates from those events ← THIS
 *   08:45 UTC   — IAB ingestion pipeline
 *   09:15 UTC   — IAB spike detection
 */

import cron from "node-cron";
import { runLastActiveUpdate } from "./last-active-updater";

let schedulerInitialized = false;
let scheduledTask: ReturnType<typeof cron.schedule> | null = null;

/**
 * Initialize the lastActive updater cron schedule.
 * Runs daily at 08:15 UTC — after feed syncs, before IAB ingestion.
 */
export function initLastActiveScheduler(): void {
  if (schedulerInitialized) {
    console.log("[LastActiveScheduler] Already initialized, skipping");
    return;
  }

  // Daily at 08:15 UTC
  scheduledTask = cron.schedule(
    "0 15 8 * * *",
    async () => {
      console.log("[LastActiveScheduler] Triggering scheduled lastActive update...");
      try {
        const result = await runLastActiveUpdate("scheduled");
        console.log(
          `[LastActiveScheduler] Completed: ${result.totalActorsUpdated} actors updated from ${result.sources.length} sources (${result.durationMs}ms)`
        );
      } catch (err: any) {
        console.error("[LastActiveScheduler] Scheduled update failed:", err.message);
      }
    },
    { timezone: "UTC" }
  );

  schedulerInitialized = true;
  console.log("[LastActiveScheduler] Initialized — daily at 08:15 UTC");
}

/** Stop the scheduled task (for testing/shutdown). */
export function stopLastActiveScheduler(): void {
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }
  schedulerInitialized = false;
  console.log("[LastActiveScheduler] Stopped");
}

/** Check if the scheduler is active. */
export function isLastActiveSchedulerActive(): boolean {
  return schedulerInitialized;
}
