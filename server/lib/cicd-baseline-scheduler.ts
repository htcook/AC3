/**
 * CI/CD Baseline Auto-Refresh Scheduler
 * 
 * Runs weekly (every Sunday at 03:00 UTC) to auto-promote the latest
 * passing run as the new baseline for each pipeline. This prevents
 * baseline drift where old baselines accumulate stale findings.
 * 
 * Can also be triggered manually via the refreshBaselines tRPC mutation.
 */
import cron from "node-cron";

export async function refreshAllBaselines(): Promise<{ updated: number; checked: number }> {
  const { getDb } = await import("../db");
  const { sql } = await import("drizzle-orm");
  const db = await getDb();
  if (!db) {
    console.warn("[CICD-Baseline] Database unavailable, skipping refresh");
    return { updated: 0, checked: 0 };
  }

  try {
    // Count active pipelines
    const countResult = await db.execute(sql.raw(
      `SELECT COUNT(*) as cnt FROM cicd_pipelines WHERE cicd_is_active = 1`
    ));
    const checked = Number(((countResult as any).rows || countResult)?.[0]?.cnt) || 0;

    // For each active pipeline, find the latest passing run and set it as the baseline
    const result = await db.execute(sql.raw(
      `UPDATE cicd_pipelines p
       INNER JOIN (
         SELECT cicd_run_pipeline_id, MAX(id) as latest_passing_id
         FROM cicd_runs
         WHERE cicd_run_status = 'passed'
         GROUP BY cicd_run_pipeline_id
       ) latest ON p.id = latest.cicd_run_pipeline_id
       SET p.cicd_last_baseline_id = latest.latest_passing_id
       WHERE p.cicd_is_active = 1
         AND (p.cicd_last_baseline_id IS NULL OR p.cicd_last_baseline_id != latest.latest_passing_id)`
    ));
    const updated = Number((result as any)?.[0]?.affectedRows || (result as any)?.rowsAffected) || 0;

    console.log(`[CICD-Baseline] Refresh complete: ${updated}/${checked} pipelines updated`);

    // Notify owner if any baselines were updated
    if (updated > 0) {
      try {
        const { notifyOwner } = await import("../_core/notification");
        await notifyOwner({
          title: `CI/CD Baseline Auto-Refresh: ${updated} pipeline(s) updated`,
          content: `The weekly baseline auto-refresh has completed.\n\n${updated} of ${checked} active pipeline(s) had their baselines promoted to the latest passing run.\n\nThis ensures findings are compared against recent passing scans rather than stale baselines.`,
        });
      } catch (notifyErr: any) {
        console.warn(`[CICD-Baseline] Failed to send notification: ${notifyErr.message}`);
      }
    }

    return { updated, checked };
  } catch (err: any) {
    console.error(`[CICD-Baseline] Refresh failed: ${err.message}`);
    return { updated: 0, checked: 0 };
  }
}

export function initCicdBaselineScheduler() {
  // Run every Sunday at 03:00 UTC
  const task = cron.schedule("0 3 * * 0", async () => {
    console.log("[CICD-Baseline] Starting weekly baseline auto-refresh...");
    try {
      await refreshAllBaselines();
    } catch (err: any) {
      console.error("[CICD-Baseline] Scheduled refresh failed:", err);
    }
  }, {
    timezone: "UTC",
  });

  console.log("[CICD-Baseline] Weekly baseline auto-refresh scheduled (Sundays at 03:00 UTC)");
  return task;
}
