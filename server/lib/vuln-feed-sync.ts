/**
 * Vulnerability Feed Sync Scheduler
 * 
 * Runs a daily cron job at 05:00 UTC to pre-warm all vulnerability feed caches:
 * - CISA KEV catalog
 * - Google Project Zero 0-day tracker
 * - NVD recent CVEs
 * - CIRCL recent CVEs
 * - Exploit-DB entries
 * 
 * This ensures the unified vulnerability map is always fresh when users
 * access the Vulnerability Intelligence dashboard or chain builder.
 */

import cron from "node-cron";

let syncRunning = false;

/**
 * Run a full refresh of all vulnerability feed caches.
 * Forces cache invalidation and re-fetches from all sources.
 */
export async function runVulnFeedSync(trigger: "scheduled" | "manual" = "manual"): Promise<{
  trigger: string;
  timestamp: string;
  results: Array<{ source: string; status: "ok" | "error"; count?: number; error?: string }>;
  totalEntries: number;
  durationMs: number;
}> {
  if (syncRunning) {
    console.warn("[Vuln Feed Sync] Sync already in progress, skipping");
    return {
      trigger,
      timestamp: new Date().toISOString(),
      results: [],
      totalEntries: 0,
      durationMs: 0,
    };
  }

  syncRunning = true;
  const start = Date.now();
  console.log(`[Vuln Feed Sync] Starting ${trigger} sync at ${new Date().toISOString()}`);

  const results: Array<{ source: string; status: "ok" | "error"; count?: number; error?: string }> = [];

  try {
    // Import all feed fetchers
    const {
      fetchProjectZero,
      fetchNvdRecent,
      fetchCirclRecent,
      fetchExploitDb,
      buildUnifiedMap,
    } = await import("./vuln-feeds");

    const { fetchKevCatalog } = await import("./kev-service");

    // Fetch all feeds in parallel
    const [kevResult, pzResult, nvdResult, circlResult, edbResult] = await Promise.allSettled([
      fetchKevCatalog().then(catalog => {
        const count = catalog.vulnerabilities?.length || 0;
        results.push({ source: "cisa_kev", status: "ok", count });
        console.log(`  [KEV] ${count} entries loaded`);
        return count;
      }),
      fetchProjectZero().then(entries => {
        results.push({ source: "project_zero", status: "ok", count: entries.length });
        console.log(`  [Project Zero] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchNvdRecent().then(entries => {
        results.push({ source: "nvd", status: "ok", count: entries.length });
        console.log(`  [NVD] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchCirclRecent().then(entries => {
        results.push({ source: "circl", status: "ok", count: entries.length });
        console.log(`  [CIRCL] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchExploitDb().then(entries => {
        results.push({ source: "exploit_db", status: "ok", count: entries.length });
        console.log(`  [Exploit-DB] ${entries.length} entries loaded`);
        return entries.length;
      }),
    ]);

    // Log any failures
    [kevResult, pzResult, nvdResult, circlResult, edbResult].forEach((r, i) => {
      const sources = ["cisa_kev", "project_zero", "nvd", "circl", "exploit_db"];
      if (r.status === "rejected") {
        const errMsg = r.reason?.message || String(r.reason);
        // Only add if not already in results (from the .then handler)
        if (!results.find(res => res.source === sources[i])) {
          results.push({ source: sources[i], status: "error", error: errMsg });
        }
        console.error(`  [${sources[i]}] FAILED: ${errMsg}`);
      }
    });

    // Build the unified map to warm the cache
    const unifiedMap = await buildUnifiedMap();
    const totalEntries = unifiedMap.size;

    const durationMs = Date.now() - start;
    console.log(`[Vuln Feed Sync] Completed in ${durationMs}ms: ${totalEntries} unified entries from ${results.filter(r => r.status === "ok").length}/${results.length} feeds`);

    return {
      trigger,
      timestamp: new Date().toISOString(),
      results,
      totalEntries,
      durationMs,
    };
  } catch (err: any) {
    const durationMs = Date.now() - start;
    console.error(`[Vuln Feed Sync] Fatal error after ${durationMs}ms:`, err.message);
    return {
      trigger,
      timestamp: new Date().toISOString(),
      results,
      totalEntries: 0,
      durationMs,
    };
  } finally {
    syncRunning = false;
  }
}

/**
 * Initialize the scheduled vulnerability feed sync cron job.
 * Runs daily at 05:00 UTC (1 hour before IOC sync at 06:00).
 */
export function initVulnFeedSyncSchedule() {
  const task = cron.schedule("0 5 * * *", async () => {
    try {
      await runVulnFeedSync("scheduled");
    } catch (err) {
      console.error("[Vuln Feed Sync Cron] Scheduled sync failed:", err);
    }
  }, {
    timezone: "UTC",
  });

  console.log("[Vuln Feed Sync] Scheduled daily refresh at 05:00 UTC");

  // Also run an initial warm-up 30 seconds after server start
  setTimeout(async () => {
    try {
      console.log("[Vuln Feed Sync] Running initial cache warm-up...");
      await runVulnFeedSync("manual");
    } catch (err) {
      console.warn("[Vuln Feed Sync] Initial warm-up failed (non-fatal):", err);
    }
  }, 30_000);

  return task;
}
