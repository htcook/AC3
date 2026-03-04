/**
 * Darkweb Feed Sync Scheduler
 *
 * Automated cron-based scheduler for all darkweb intelligence feeds.
 * Runs on staggered schedules to avoid API rate limits:
 *
 *   - Every 6 hours: abuse.ch feeds (Feodo, ThreatFox/URLhaus, MalwareBazaar, SSL Blacklist)
 *   - Every 6 hours (offset): ransomware.live (victims + groups)
 *   - Every 12 hours: AlienVault OTX, OpenPhish, Tor exit nodes
 *   - Every 24 hours: Blocklist.de, Spamhaus DROP, HIBP Breaches
 *   - Every 24 hours: IAB + Influence Ops feed sync
 *   - Every 24 hours: LLM enrichment batch for un-enriched records
 *
 * Each job logs its results and updates the feed registry health tracking.
 */

import cron from "node-cron";
import {
  runDarkwebFeedSync,
  isDarkwebSyncRunning,
  fetchFeodoTracker,
  fetchMalwareBazaar,
  fetchSSLBlacklist,
  fetchRansomwareLiveVictims,
  fetchRansomwareLiveGroups,
  fetchAlienVaultOTX,
  fetchOpenPhish,
  fetchTorExitNodes,
  fetchBlocklistDe,
  fetchSpamhausDrop,
  fetchHIBPBreaches,
} from "./darkweb-osint-service";
import { enrichBatch } from "./darkweb-enrichment-service";
import { syncRansomwareActors } from "./darkweb-intel-service";
import { runFullIngest } from "./threat-intel-ingest";
import { processBatch as processAttackSequences } from "./attack-sequence-learner";

// Track scheduler state
let schedulerInitialized = false;
const activeTasks: ReturnType<typeof cron.schedule>[] = [];

// ─── Individual Sync Jobs ─────────────────────────────────────────────

async function runAbuseCHSync(): Promise<void> {
  if (isDarkwebSyncRunning()) {
    console.log("[DarkwebScheduler] Skipping abuse.ch sync — another sync is running");
    return;
  }
  console.log("[DarkwebScheduler] Starting abuse.ch feed sync...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchFeodoTracker(),
      fetchMalwareBazaar(),
      fetchSSLBlacklist(),
    ]);
    const summary = results.map((r, i) => {
      const name = ["Feodo", "MalwareBazaar", "SSLBlacklist"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${(r.reason as Error).message})`;
    });
    console.log(`[DarkwebScheduler] abuse.ch sync done in ${Date.now() - start}ms — ${summary.join(", ")}`);
  } catch (err: any) {
    console.error("[DarkwebScheduler] abuse.ch sync error:", err.message);
  }
}

async function runRansomwareLiveSync(): Promise<void> {
  if (isDarkwebSyncRunning()) {
    console.log("[DarkwebScheduler] Skipping ransomware.live sync — another sync is running");
    return;
  }
  console.log("[DarkwebScheduler] Starting ransomware.live sync...");
  const start = Date.now();
  try {
    const [victims, groups] = await Promise.allSettled([
      fetchRansomwareLiveVictims(),
      fetchRansomwareLiveGroups(),
    ]);
    const vMsg = victims.status === "fulfilled" ? `${victims.value.fetched} victims` : `FAILED`;
    const gMsg = groups.status === "fulfilled" ? `${groups.value.fetched} groups` : `FAILED`;
    console.log(`[DarkwebScheduler] ransomware.live sync done in ${Date.now() - start}ms — ${vMsg}, ${gMsg}`);
    
    // Also sync actor enrichment after getting fresh ransomware data
    try {
      await syncRansomwareActors();
      console.log("[DarkwebScheduler] Ransomware actor enrichment complete");
    } catch (e) {
      console.warn("[DarkwebScheduler] Actor enrichment failed:", (e as Error).message);
    }
  } catch (err: any) {
    console.error("[DarkwebScheduler] ransomware.live sync error:", err.message);
  }
}

async function runSecondaryFeedSync(): Promise<void> {
  console.log("[DarkwebScheduler] Starting secondary feed sync (OTX, OpenPhish, Tor)...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchAlienVaultOTX(),
      fetchOpenPhish(),
      fetchTorExitNodes(),
    ]);
    const summary = results.map((r, i) => {
      const name = ["OTX", "OpenPhish", "TorExitNodes"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${(r.reason as Error).message})`;
    });
    console.log(`[DarkwebScheduler] Secondary feeds done in ${Date.now() - start}ms — ${summary.join(", ")}`);
  } catch (err: any) {
    console.error("[DarkwebScheduler] Secondary feed sync error:", err.message);
  }
}

async function runDailyFeedSync(): Promise<void> {
  console.log("[DarkwebScheduler] Starting daily feed sync (Blocklist.de, Spamhaus, HIBP)...");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      fetchBlocklistDe(),
      fetchSpamhausDrop(),
      fetchHIBPBreaches(),
    ]);
    const summary = results.map((r, i) => {
      const name = ["Blocklist.de", "Spamhaus", "HIBP"][i];
      if (r.status === "fulfilled") return `${name}: ${r.value.fetched} fetched`;
      return `${name}: FAILED (${(r.reason as Error).message})`;
    });
    console.log(`[DarkwebScheduler] Daily feeds done in ${Date.now() - start}ms — ${summary.join(", ")}`);
  } catch (err: any) {
    console.error("[DarkwebScheduler] Daily feed sync error:", err.message);
  }
}

async function runDarkwebFeedSyncJob(): Promise<void> {
  console.log("[DarkwebScheduler] Starting IAB + IO campaign feed sync...");
  const start = Date.now();
  try {
    const { syncAllDarkwebFeeds } = await import("./darkweb-feeds");
    const result = await syncAllDarkwebFeeds();
    console.log(
      `[DarkwebScheduler] IAB/IO sync done in ${Date.now() - start}ms — ` +
      `IABs: ${result.accessBrokers.inserted} new/${result.accessBrokers.updated} updated, ` +
      `IOs: ${result.infoOps.inserted} new/${result.infoOps.updated} updated`
    );
  } catch (err: any) {
    console.error("[DarkwebScheduler] IAB/IO sync error:", err.message);
  }
}

async function runEnrichmentBatch(): Promise<void> {
  console.log("[DarkwebScheduler] Starting LLM enrichment batch for un-enriched records...");
  const start = Date.now();
  try {
    // Enrich up to 20 un-enriched records
    const result = await enrichBatch(20);
    console.log(
      `[DarkwebScheduler] Enrichment batch done in ${Date.now() - start}ms — ` +
      `${result.enriched} enriched, ${result.failed} failed, ${result.skipped} skipped`
    );
  } catch (err: any) {
    console.error("[DarkwebScheduler] Enrichment batch error:", err.message);
  }
}

// ─── Full Sync (all feeds at once) ────────────────────────────────────

export async function runFullDarkwebSync(): Promise<{
  success: boolean;
  duration: number;
  results: string[];
}> {
  const start = Date.now();
  const results: string[] = [];

  try {
    await runAbuseCHSync();
    results.push("abuse.ch: done");
  } catch { results.push("abuse.ch: failed"); }

  try {
    await runRansomwareLiveSync();
    results.push("ransomware.live: done");
  } catch { results.push("ransomware.live: failed"); }

  try {
    await runSecondaryFeedSync();
    results.push("secondary feeds: done");
  } catch { results.push("secondary feeds: failed"); }

  try {
    await runDailyFeedSync();
    results.push("daily feeds: done");
  } catch { results.push("daily feeds: failed"); }

  try {
    await runDarkwebFeedSyncJob();
    results.push("IAB/IO: done");
  } catch { results.push("IAB/IO: failed"); }

  try {
    const { syncDailyDarkWebRSS } = await import("./dailydarkweb-rss");
    const rssResult = await syncDailyDarkWebRSS(false);
    results.push(`DDW RSS: ${rssResult.totalEventsIngested} events ingested`);
  } catch { results.push("DDW RSS: failed"); }

  try {
    const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss");
    const multiResult = await syncAllThreatIntelFeeds({});
    results.push(`Multi-RSS: ${multiResult.feedsSucceeded}/${multiResult.totalFeeds} feeds, TGE:${multiResult.totalThreatGroupEvents} RE:${multiResult.totalRansomwareEvents} UIE:${multiResult.totalUndergroundEvents} IR:${multiResult.totalIncidentReports}`);
  } catch { results.push("Multi-RSS: failed"); }

  return {
    success: true,
    duration: Date.now() - start,
    results,
  };
}

// ─── Scheduler Initialization ─────────────────────────────────────────

export function initDarkwebFeedScheduler(): void {
  if (schedulerInitialized) {
    console.log("[DarkwebScheduler] Already initialized, skipping");
    return;
  }

  // abuse.ch feeds — every 6 hours at :00 (00:00, 06:00, 12:00, 18:00 UTC)
  activeTasks.push(
    cron.schedule("0 0 */6 * * *", runAbuseCHSync, { timezone: "UTC" })
  );

  // ransomware.live — every 6 hours at :30 (00:30, 06:30, 12:30, 18:30 UTC)
  activeTasks.push(
    cron.schedule("0 30 0,6,12,18 * * *", runRansomwareLiveSync, { timezone: "UTC" })
  );

  // Secondary feeds (OTX, OpenPhish, Tor) — every 12 hours (03:00, 15:00 UTC)
  activeTasks.push(
    cron.schedule("0 0 3,15 * * *", runSecondaryFeedSync, { timezone: "UTC" })
  );

  // Daily feeds (Blocklist.de, Spamhaus, HIBP) — daily at 04:00 UTC
  activeTasks.push(
    cron.schedule("0 0 4 * * *", runDailyFeedSync, { timezone: "UTC" })
  );

  // IAB + IO campaign sync — daily at 08:00 UTC
  activeTasks.push(
    cron.schedule("0 0 8 * * *", runDarkwebFeedSyncJob, { timezone: "UTC" })
  );

  // LLM enrichment batch — daily at 09:00 UTC
  activeTasks.push(
    cron.schedule("0 0 9 * * *", runEnrichmentBatch, { timezone: "UTC" })
  );

   // Threat intel report ingestion — every 8 hours at :15
  activeTasks.push(
    cron.schedule("0 15 */8 * * *", async () => {
      console.log("[DarkwebScheduler] Starting threat intel report ingestion...");
      try {
        const result = await runFullIngest();
        const totalNew = result.results.reduce((sum, r) => sum + r.newRecords, 0);
        console.log(`[DarkwebScheduler] Threat intel ingestion complete: ${totalNew} new reports from ${result.results.length} sources`);
      } catch (e: any) {
        console.error(`[DarkwebScheduler] Threat intel ingestion error: ${e.message}`);
      }
    }, { timezone: "UTC" })
  );
  // Attack sequence extraction — daily at 10:00 UTC (after enrichment)
  activeTasks.push(
    cron.schedule("0 0 10 * * *", async () => {
      console.log("[DarkwebScheduler] Starting attack sequence extraction...");
      try {
        const results = await processAttackSequences(10);
        const successful = results.filter(r => r.phasesExtracted > 0).length;
        console.log(`[DarkwebScheduler] Attack sequence extraction complete: ${successful}/${results.length} reports processed`);
      } catch (e: any) {
        console.error(`[DarkwebScheduler] Attack sequence extraction error: ${e.message}`);
      }
    }, { timezone: "UTC" })
  );
  // Daily Dark Web RSS auto-ingestion — daily at 08:30 UTC
  activeTasks.push(
    cron.schedule("0 30 8 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Daily Dark Web RSS sync...");
      try {
        const { syncDailyDarkWebRSS } = await import("./dailydarkweb-rss");
        const result = await syncDailyDarkWebRSS(false);
        console.log(`[DarkwebScheduler] DDW RSS: ${result.totalItemsFetched} items, ${result.totalEventsIngested} ingested (${result.duration}ms)`);
      } catch (e: any) {
        console.error("[DarkwebScheduler] DDW RSS sync failed:", e.message);
      }
    }, { timezone: "UTC" })
  );

  // Multi-source threat intel RSS — Tier 1 at 07:00 UTC, Tier 2-4 at 11:00 UTC
  activeTasks.push(
    cron.schedule("0 0 7 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Tier 1 (critical) RSS sync...");
      try {
        const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss");
        const result = await syncAllThreatIntelFeeds({ tiers: [1] });
        console.log(`[DarkwebScheduler] Tier 1 RSS: ${result.totalFeeds} feeds, ${result.totalItemsFetched} items, TGE:${result.totalThreatGroupEvents} RE:${result.totalRansomwareEvents} UIE:${result.totalUndergroundEvents} IR:${result.totalIncidentReports} (${result.duration}ms)`);
      } catch (e: any) {
        console.error("[DarkwebScheduler] Tier 1 RSS sync failed:", e.message);
      }
    }, { timezone: "UTC" })
  );
  activeTasks.push(
    cron.schedule("0 0 11 * * *", async () => {
      console.log("[DarkwebScheduler] Starting Tier 2-4 RSS sync...");
      try {
        const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss");
        const result = await syncAllThreatIntelFeeds({ tiers: [2, 3, 4] });
        console.log(`[DarkwebScheduler] Tier 2-4 RSS: ${result.totalFeeds} feeds, ${result.totalItemsFetched} items, TGE:${result.totalThreatGroupEvents} RE:${result.totalRansomwareEvents} UIE:${result.totalUndergroundEvents} IR:${result.totalIncidentReports} (${result.duration}ms)`);
      } catch (e: any) {
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

/** Stop all scheduled tasks (for testing/shutdown). */
export function stopDarkwebFeedScheduler(): void {
  activeTasks.forEach((t) => t.stop());
  activeTasks.length = 0;
  schedulerInitialized = false;
  console.log("[DarkwebScheduler] All scheduled tasks stopped");
}

/** Check if the scheduler is running. */
export function isDarkwebSchedulerActive(): boolean {
  return schedulerInitialized;
}
