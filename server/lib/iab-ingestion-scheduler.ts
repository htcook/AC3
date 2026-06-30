/**
 * IAB Ingestion & Spike Detection Scheduler
 *
 * Automated cron-based scheduler for Initial Access Broker data ingestion
 * and anomaly detection. Runs daily after the main darkweb feed sync.
 *
 * Schedule:
 *   - Daily at 08:45 UTC: Full IAB ingestion pipeline (5 sources)
 *   - Daily at 09:15 UTC: Spike detection + alerting (after ingestion + enrichment)
 *
 * Sources:
 *   1. ransomware.live groups (IAB-related filtering)
 *   2. ransomware.live victim attribution (sector/country extraction)
 *   3. CISA KEV exploits (IAB-relevant vulns from last 12 months)
 *   4. RansomLook markets (darkweb market monitoring)
 *   5. LLM enrichment (AI-powered data enrichment for low-confidence listings)
 */

import cron from "node-cron";
import { runIABIngestionPipeline } from "./iab-ingestion-service";
import { runIABSpikeCheck, getDefaultThresholds } from "./iab-spike-alerting";

let schedulerInitialized = false;
const activeTasks: ReturnType<typeof cron.schedule>[] = [];

/**
 * Run the full IAB ingestion pipeline as a scheduled job.
 * Logs results and handles errors gracefully.
 */
async function runScheduledIngestion(): Promise<void> {
  console.log("[IABScheduler] Starting daily IAB ingestion pipeline...");
  const start = Date.now();

  try {
    const result = await runIABIngestionPipeline();
    const duration = Date.now() - start;

    const sourceResults = result.results
      .map(r => `${r.source}: ${r.inserted} new, ${r.skipped} skipped${r.error ? ` (ERROR: ${r.error})` : ""}`)
      .join("; ");

    console.log(
      `[IABScheduler] Ingestion complete in ${duration}ms: ` +
      `${result.totalInserted} new listings, ${result.totalErrors} errors. ` +
      `Sources: ${sourceResults}`
    );
  } catch (e: any) {
    console.error(`[IABScheduler] Ingestion pipeline failed: ${e.message}`);
  }
}

/**
 * Run spike detection after ingestion to catch anomalies.
 * Uses default thresholds. Notifications are sent automatically
 * for critical/high severity alerts.
 */
async function runScheduledSpikeCheck(): Promise<void> {
  console.log("[IABScheduler] Starting daily spike detection...");
  const start = Date.now();

  try {
    const thresholds = getDefaultThresholds();
    const result = await runIABSpikeCheck(thresholds);
    const duration = Date.now() - start;

    if (result.alerts.length === 0) {
      console.log(`[IABScheduler] Spike check complete in ${duration}ms: No anomalies detected.`);
    } else {
      const critical = result.alerts.filter(a => a.severity === "critical").length;
      const high = result.alerts.filter(a => a.severity === "high").length;
      const medium = result.alerts.filter(a => a.severity === "medium").length;
      const low = result.alerts.filter(a => a.severity === "low").length;

      console.log(
        `[IABScheduler] Spike check complete in ${duration}ms: ` +
        `${result.alerts.length} alerts (${critical} critical, ${high} high, ${medium} medium, ${low} low). ` +
        `${result.notificationsSent} notifications sent, ${result.notificationsFailed} failed.`
      );

      // Log each alert for visibility
      result.alerts.forEach(alert => {
        console.log(`[IABScheduler] [${alert.severity.toUpperCase()}] ${alert.title}`);
      });
    }
  } catch (e: any) {
    console.error(`[IABScheduler] Spike detection failed: ${e.message}`);
  }
}

/**
 * Initialize the IAB ingestion and spike detection cron jobs.
 * Safe to call multiple times — will skip if already initialized.
 */
export function initIABIngestionScheduler(): void {
  if (schedulerInitialized) {
    console.log("[IABScheduler] Already initialized, skipping");
    return;
  }

  // Daily IAB ingestion at 08:45 UTC (after main darkweb sync at 08:00)
  activeTasks.push(
    cron.schedule("0 45 8 * * *", runScheduledIngestion, { timezone: "UTC" })
  );

  // Daily spike detection at 09:15 UTC (after ingestion + LLM enrichment at 09:00)
  activeTasks.push(
    cron.schedule("0 15 9 * * *", runScheduledSpikeCheck, { timezone: "UTC" })
  );

  schedulerInitialized = true;
  console.log("[IABScheduler] IAB ingestion & spike detection scheduler initialized:");
  console.log("  - IAB ingestion pipeline: daily at 08:45 UTC");
  console.log("  - Spike detection + alerting: daily at 09:15 UTC");
}

/** Stop all scheduled IAB tasks (for testing/shutdown). */
export function stopIABIngestionScheduler(): void {
  activeTasks.forEach(t => t.stop());
  activeTasks.length = 0;
  schedulerInitialized = false;
  console.log("[IABScheduler] All scheduled tasks stopped");
}

/** Check if the IAB scheduler is running. */
export function isIABSchedulerActive(): boolean {
  return schedulerInitialized;
}
