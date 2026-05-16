import {
  enrichBatch,
  processBatch,
  syncRansomwareActors
} from "./chunk-QSSP2AW3.js";
import {
  runFullIngest
} from "./chunk-YZ3CMPBY.js";
import {
  fetchAlienVaultOTX,
  fetchBlocklistDe,
  fetchFeodoTracker,
  fetchHIBPBreaches,
  fetchMalwareBazaar,
  fetchOpenPhish,
  fetchRansomwareLiveGroups,
  fetchRansomwareLiveVictims,
  fetchSSLBlacklist,
  fetchSpamhausDrop,
  fetchTorExitNodes,
  init_darkweb_osint_service,
  isDarkwebSyncRunning
} from "./chunk-IFPCLGTY.js";
import "./chunk-2CCDF2QL.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-AX6SVAQZ.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-DQZ564DJ.js";
import "./chunk-KFQGP6VL.js";

// server/lib/darkweb-feed-scheduler.ts
init_darkweb_osint_service();
import cron from "node-cron";
var schedulerInitialized = false;
var activeTasks = [];
async function runAbuseCHSync() {
  if (isDarkwebSyncRunning()) {
    console.log("[DarkwebScheduler] Skipping abuse.ch sync \u2014 another sync is running");
    return;
  }
  console.log("[DarkwebScheduler] Starting abuse.ch feed sync...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchFeodoTracker(),
      fetchMalwareBazaar(),
      fetchSSLBlacklist()
    ]);
    const summary = results.map((r, i) => {
      const name = ["Feodo", "MalwareBazaar", "SSLBlacklist"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${r.reason.message})`;
    });
    console.log(`[DarkwebScheduler] abuse.ch sync done in ${Date.now() - start}ms \u2014 ${summary.join(", ")}`);
  } catch (err) {
    console.error("[DarkwebScheduler] abuse.ch sync error:", err.message);
  }
}
async function runRansomwareLiveSync() {
  if (isDarkwebSyncRunning()) {
    console.log("[DarkwebScheduler] Skipping ransomware.live sync \u2014 another sync is running");
    return;
  }
  console.log("[DarkwebScheduler] Starting ransomware.live sync...");
  const start = Date.now();
  try {
    const [victims, groups] = await Promise.allSettled([
      fetchRansomwareLiveVictims(),
      fetchRansomwareLiveGroups()
    ]);
    const vMsg = victims.status === "fulfilled" ? `${victims.value.fetched} victims` : `FAILED`;
    const gMsg = groups.status === "fulfilled" ? `${groups.value.fetched} groups` : `FAILED`;
    console.log(`[DarkwebScheduler] ransomware.live sync done in ${Date.now() - start}ms \u2014 ${vMsg}, ${gMsg}`);
    try {
      await syncRansomwareActors();
      console.log("[DarkwebScheduler] Ransomware actor enrichment complete");
    } catch (e) {
      console.warn("[DarkwebScheduler] Actor enrichment failed:", e.message);
    }
  } catch (err) {
    console.error("[DarkwebScheduler] ransomware.live sync error:", err.message);
  }
}
async function runSecondaryFeedSync() {
  console.log("[DarkwebScheduler] Starting secondary feed sync (OTX, OpenPhish, Tor)...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchAlienVaultOTX(),
      fetchOpenPhish(),
      fetchTorExitNodes()
    ]);
    const summary = results.map((r, i) => {
      const name = ["OTX", "OpenPhish", "TorExitNodes"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${r.reason.message})`;
    });
    console.log(`[DarkwebScheduler] Secondary feeds done in ${Date.now() - start}ms \u2014 ${summary.join(", ")}`);
  } catch (err) {
    console.error("[DarkwebScheduler] Secondary feed sync error:", err.message);
  }
}
async function runDailyFeedSync() {
  console.log("[DarkwebScheduler] Starting daily feed sync (Blocklist.de, Spamhaus, HIBP)...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchBlocklistDe(),
      fetchSpamhausDrop(),
      fetchHIBPBreaches()
    ]);
    const summary = results.map((r, i) => {
      const name = ["Blocklist.de", "Spamhaus", "HIBP"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${r.reason.message})`;
    });
    console.log(`[DarkwebScheduler] Daily feeds done in ${Date.now() - start}ms \u2014 ${summary.join(", ")}`);
  } catch (err) {
    console.error("[DarkwebScheduler] Daily feed sync error:", err.message);
  }
}
async function runDarkwebFeedSyncJob() {
  console.log("[DarkwebScheduler] Starting IAB + IO campaign feed sync...");
  const start = Date.now();
  try {
    const { syncAllDarkwebFeeds } = await import("./darkweb-feeds-3ALB4VBA.js");
    const result = await syncAllDarkwebFeeds();
    console.log(
      `[DarkwebScheduler] IAB/IO sync done in ${Date.now() - start}ms \u2014 IABs: ${result.accessBrokers.inserted} new/${result.accessBrokers.updated} updated, IOs: ${result.infoOps.inserted} new/${result.infoOps.updated} updated`
    );
  } catch (err) {
    console.error("[DarkwebScheduler] IAB/IO sync error:", err.message);
  }
}
async function runEnrichmentBatch() {
  console.log("[DarkwebScheduler] Starting LLM enrichment batch for un-enriched records...");
  const start = Date.now();
  try {
    const result = await enrichBatch(20);
    console.log(
      `[DarkwebScheduler] Enrichment batch done in ${Date.now() - start}ms \u2014 ${result.enriched} enriched, ${result.failed} failed, ${result.skipped} skipped`
    );
  } catch (err) {
    console.error("[DarkwebScheduler] Enrichment batch error:", err.message);
  }
}
async function runFullDarkwebSync() {
  const start = Date.now();
  const results = [];
  try {
    await runAbuseCHSync();
    results.push("abuse.ch: done");
  } catch {
    results.push("abuse.ch: failed");
  }
  try {
    await runRansomwareLiveSync();
    results.push("ransomware.live: done");
  } catch {
    results.push("ransomware.live: failed");
  }
  try {
    await runSecondaryFeedSync();
    results.push("secondary feeds: done");
  } catch {
    results.push("secondary feeds: failed");
  }
  try {
    await runDailyFeedSync();
    results.push("daily feeds: done");
  } catch {
    results.push("daily feeds: failed");
  }
  try {
    await runDarkwebFeedSyncJob();
    results.push("IAB/IO: done");
  } catch {
    results.push("IAB/IO: failed");
  }
  try {
    const { syncDailyDarkWebRSS } = await import("./dailydarkweb-rss-TGPNKBVZ.js");
    const rssResult = await syncDailyDarkWebRSS(false);
    results.push(`DDW RSS: ${rssResult.totalEventsIngested} events ingested`);
  } catch {
    results.push("DDW RSS: failed");
  }
  try {
    const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss-GK25BQKP.js");
    const multiResult = await syncAllThreatIntelFeeds({});
    results.push(`Multi-RSS: ${multiResult.feedsSucceeded}/${multiResult.totalFeeds} feeds, TGE:${multiResult.totalThreatGroupEvents} RE:${multiResult.totalRansomwareEvents} UIE:${multiResult.totalUndergroundEvents} IR:${multiResult.totalIncidentReports}`);
  } catch {
    results.push("Multi-RSS: failed");
  }
  return {
    success: true,
    duration: Date.now() - start,
    results
  };
}
function initDarkwebFeedScheduler() {
  if (schedulerInitialized) {
    console.log("[DarkwebScheduler] Already initialized, skipping");
    return;
  }
  activeTasks.push(
    cron.schedule("0 0 */6 * * *", runAbuseCHSync, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 30 0,6,12,18 * * *", runRansomwareLiveSync, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 3,15 * * *", runSecondaryFeedSync, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 4 * * *", runDailyFeedSync, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 8 * * *", runDarkwebFeedSyncJob, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 9 * * *", runEnrichmentBatch, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 15 */8 * * *", async () => {
      console.log("[DarkwebScheduler] Starting threat intel report ingestion...");
      try {
        const result = await runFullIngest();
        const totalNew = result.results.reduce((sum, r) => sum + r.newRecords, 0);
        console.log(`[DarkwebScheduler] Threat intel ingestion complete: ${totalNew} new reports from ${result.results.length} sources`);
      } catch (e) {
        console.error(`[DarkwebScheduler] Threat intel ingestion error: ${e.message}`);
      }
    }, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 10 * * *", async () => {
      console.log("[DarkwebScheduler] Starting attack sequence extraction...");
      try {
        const results = await processBatch(10);
        const successful = results.filter((r) => r.phasesExtracted > 0).length;
        console.log(`[DarkwebScheduler] Attack sequence extraction complete: ${successful}/${results.length} reports processed`);
      } catch (e) {
        console.error(`[DarkwebScheduler] Attack sequence extraction error: ${e.message}`);
      }
    }, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 30 8 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Daily Dark Web RSS sync...");
      try {
        const { syncDailyDarkWebRSS } = await import("./dailydarkweb-rss-TGPNKBVZ.js");
        const result = await syncDailyDarkWebRSS(false);
        console.log(`[DarkwebScheduler] DDW RSS: ${result.totalItemsFetched} items, ${result.totalEventsIngested} ingested (${result.duration}ms)`);
      } catch (e) {
        console.error("[DarkwebScheduler] DDW RSS sync failed:", e.message);
      }
    }, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 7 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Tier 1 (critical) RSS sync...");
      try {
        const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss-GK25BQKP.js");
        const result = await syncAllThreatIntelFeeds({ tiers: [1] });
        console.log(`[DarkwebScheduler] Tier 1 RSS: ${result.totalFeeds} feeds, ${result.totalItemsFetched} items, TGE:${result.totalThreatGroupEvents} RE:${result.totalRansomwareEvents} UIE:${result.totalUndergroundEvents} IR:${result.totalIncidentReports} (${result.duration}ms)`);
      } catch (e) {
        console.error("[DarkwebScheduler] Tier 1 RSS sync failed:", e.message);
      }
    }, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 11 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Tier 2-4 RSS sync...");
      try {
        const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss-GK25BQKP.js");
        const result = await syncAllThreatIntelFeeds({ tiers: [2, 3, 4] });
        console.log(`[DarkwebScheduler] Tier 2-4 RSS: ${result.totalFeeds} feeds, ${result.totalItemsFetched} items, TGE:${result.totalThreatGroupEvents} RE:${result.totalRansomwareEvents} UIE:${result.totalUndergroundEvents} IR:${result.totalIncidentReports} (${result.duration}ms)`);
      } catch (e) {
        console.error("[DarkwebScheduler] Tier 2-4 RSS sync failed:", e.message);
      }
    }, { timezone: "UTC" })
  );
  schedulerInitialized = true;
  console.log("[DarkwebScheduler] Feed sync scheduler initialized:");
  console.log("  - abuse.ch feeds: every 6h at :00");
  console.log("  - ransomware.live: every 6h at :30");
  console.log("  - OTX/OpenPhish/Tor: every 12h (03:00, 15:00 UTC)");
  console.log("  - Blocklist.de/Spamhaus/HIBP: daily at 04:00 UTC");
  console.log("  - Multi-source Tier 1 RSS: daily at 07:00 UTC");
  console.log("  - IAB/IO campaigns: daily at 08:00 UTC");
  console.log("  - Daily Dark Web RSS: daily at 08:30 UTC");
  console.log("  - LLM enrichment: daily at 09:00 UTC");
  console.log("  - Threat intel ingestion: every 8h at :15");
  console.log("  - Attack sequence extraction: daily at 10:00 UTC");
  console.log("  - Multi-source Tier 2-4 RSS: daily at 11:00 UTC");
}
function stopDarkwebFeedScheduler() {
  activeTasks.forEach((t) => t.stop());
  activeTasks.length = 0;
  schedulerInitialized = false;
  console.log("[DarkwebScheduler] All scheduled tasks stopped");
}
function isDarkwebSchedulerActive() {
  return schedulerInitialized;
}
export {
  initDarkwebFeedScheduler,
  isDarkwebSchedulerActive,
  runFullDarkwebSync,
  stopDarkwebFeedScheduler
};
