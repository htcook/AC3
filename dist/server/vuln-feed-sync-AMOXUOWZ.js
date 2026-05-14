import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-feed-sync.ts
import cron from "node-cron";
async function runVulnFeedSync(trigger = "manual") {
  if (syncRunning) {
    console.warn("[Vuln Feed Sync] Sync already in progress, skipping");
    return {
      trigger,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      results: [],
      totalEntries: 0,
      durationMs: 0
    };
  }
  syncRunning = true;
  const start = Date.now();
  console.log(`[Vuln Feed Sync] Starting ${trigger} sync at ${(/* @__PURE__ */ new Date()).toISOString()}`);
  const results = [];
  try {
    const {
      fetchProjectZero,
      fetchNvdRecent,
      fetchCirclRecent,
      fetchExploitDb,
      buildUnifiedMap
    } = await import("./vuln-feeds-3ZYWGLNW.js");
    const { fetchKevCatalog } = await import("./kev-service-UTFPRZA3.js");
    const [kevResult, pzResult, nvdResult, circlResult, edbResult] = await Promise.allSettled([
      fetchKevCatalog().then((catalog) => {
        const count = catalog.vulnerabilities?.length || 0;
        results.push({ source: "cisa_kev", status: "ok", count });
        console.log(`  [KEV] ${count} entries loaded`);
        return count;
      }),
      fetchProjectZero().then((entries) => {
        results.push({ source: "project_zero", status: "ok", count: entries.length });
        console.log(`  [Project Zero] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchNvdRecent().then((entries) => {
        results.push({ source: "nvd", status: "ok", count: entries.length });
        console.log(`  [NVD] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchCirclRecent().then((entries) => {
        results.push({ source: "circl", status: "ok", count: entries.length });
        console.log(`  [CIRCL] ${entries.length} entries loaded`);
        return entries.length;
      }),
      fetchExploitDb().then((entries) => {
        results.push({ source: "exploit_db", status: "ok", count: entries.length });
        console.log(`  [Exploit-DB] ${entries.length} entries loaded`);
        return entries.length;
      })
    ]);
    [kevResult, pzResult, nvdResult, circlResult, edbResult].forEach((r, i) => {
      const sources = ["cisa_kev", "project_zero", "nvd", "circl", "exploit_db"];
      if (r.status === "rejected") {
        const errMsg = r.reason?.message || String(r.reason);
        if (!results.find((res) => res.source === sources[i])) {
          results.push({ source: sources[i], status: "error", error: errMsg });
        }
        console.error(`  [${sources[i]}] FAILED: ${errMsg}`);
      }
    });
    const unifiedMap = await buildUnifiedMap();
    const totalEntries = unifiedMap.size;
    const durationMs = Date.now() - start;
    console.log(`[Vuln Feed Sync] Completed in ${durationMs}ms: ${totalEntries} unified entries from ${results.filter((r) => r.status === "ok").length}/${results.length} feeds`);
    return {
      trigger,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      results,
      totalEntries,
      durationMs
    };
  } catch (err) {
    const durationMs = Date.now() - start;
    console.error(`[Vuln Feed Sync] Fatal error after ${durationMs}ms:`, err.message);
    return {
      trigger,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      results,
      totalEntries: 0,
      durationMs
    };
  } finally {
    syncRunning = false;
  }
}
function initVulnFeedSyncSchedule() {
  const task = cron.schedule("0 5 * * *", async () => {
    try {
      await runVulnFeedSync("scheduled");
    } catch (err) {
      console.error("[Vuln Feed Sync Cron] Scheduled sync failed:", err);
    }
  }, {
    timezone: "UTC"
  });
  console.log("[Vuln Feed Sync] Scheduled daily refresh at 05:00 UTC");
  setTimeout(async () => {
    try {
      console.log("[Vuln Feed Sync] Running initial cache warm-up...");
      await runVulnFeedSync("manual");
    } catch (err) {
      console.warn("[Vuln Feed Sync] Initial warm-up failed (non-fatal):", err);
    }
  }, 3e5);
  return task;
}
var syncRunning;
var init_vuln_feed_sync = __esm({
  "server/lib/vuln-feed-sync.ts"() {
    syncRunning = false;
  }
});
init_vuln_feed_sync();
export {
  initVulnFeedSyncSchedule,
  runVulnFeedSync
};
