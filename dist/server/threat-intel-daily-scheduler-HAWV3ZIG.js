import "./chunk-KFQGP6VL.js";

// server/lib/threat-intel-daily-scheduler.ts
import cron from "node-cron";
var schedulerInitialized = false;
var scheduledTask = null;
var lastRunResult = null;
var isRunning = false;
function initThreatIntelDailyScheduler() {
  if (schedulerInitialized) {
    console.log("[ThreatIntelDaily-Cron] Already initialized, skipping");
    return;
  }
  scheduledTask = cron.schedule(
    "0 30 3 * * *",
    async () => {
      if (isRunning) {
        console.log("[ThreatIntelDaily-Cron] Previous run still in progress, skipping");
        return;
      }
      console.log("[ThreatIntelDaily-Cron] Starting scheduled daily threat intel pipeline...");
      isRunning = true;
      const start = Date.now();
      try {
        lastRunResult = await runDailyThreatIntelPipeline();
        lastRunResult.durationMs = Date.now() - start;
        console.log(`[ThreatIntelDaily-Cron] Completed in ${lastRunResult.durationMs}ms: ${lastRunResult.summary}`);
      } catch (err) {
        console.error("[ThreatIntelDaily-Cron] Pipeline failed:", err.message);
        lastRunResult = { error: err.message, timestamp: (/* @__PURE__ */ new Date()).toISOString() };
      } finally {
        isRunning = false;
      }
    },
    { timezone: "UTC" }
  );
  schedulerInitialized = true;
  console.log("[ThreatIntelDaily-Cron] Initialized \u2014 daily at 03:30 UTC");
}
async function runDailyThreatIntelPipeline() {
  const results = { timestamp: (/* @__PURE__ */ new Date()).toISOString(), phases: [] };
  try {
    const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss-24UWIARI.js");
    const rssResult = await syncAllThreatIntelFeeds();
    results.phases.push({ phase: "rss_sync", success: true, ...rssResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 1 (RSS): ${rssResult.newArticles || 0} new articles`);
  } catch (err) {
    results.phases.push({ phase: "rss_sync", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 1 (RSS) failed:", err.message);
  }
  try {
    const { runFullIngest } = await import("./threat-intel-ingest-NSV532RE.js");
    const ingestResult = await runFullIngest();
    results.phases.push({ phase: "full_ingest", success: true, ...ingestResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 2 (Ingest): ${ingestResult.totalNewRecords || 0} new records`);
  } catch (err) {
    results.phases.push({ phase: "full_ingest", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 2 (Ingest) failed:", err.message);
  }
  try {
    const { runIntelligenceCrawl } = await import("./threat-actor-crawler-JXKCH2FT.js");
    const crawlResult = await runIntelligenceCrawl({ maxArticles: 50, maxGroups: 20 });
    results.phases.push({ phase: "actor_crawl", success: true, ...crawlResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 3 (Crawl): ${crawlResult.newEvents || crawlResult.eventsRecorded || 0} events`);
  } catch (err) {
    results.phases.push({ phase: "actor_crawl", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 3 (Crawl) failed:", err.message);
  }
  try {
    const { runTargetedEnrichment } = await import("./threat-actor-crawler-JXKCH2FT.js");
    const enrichResult = await runTargetedEnrichment({ maxActors: 10 });
    results.phases.push({ phase: "targeted_enrichment", success: true, ...enrichResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 4 (Enrichment): complete`);
  } catch (err) {
    results.phases.push({ phase: "targeted_enrichment", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 4 (Enrichment) failed:", err.message);
  }
  try {
    const { runGovernmentIntelIngest } = await import("./government-intel-sources-422O7623.js");
    const govResult = await runGovernmentIntelIngest();
    results.phases.push({ phase: "government_intel", success: true, ...govResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 5 (Gov Intel): ${govResult.totalNewRecords} new records from ${govResult.successfulSources}/${govResult.totalSources} sources`);
  } catch (err) {
    results.phases.push({ phase: "government_intel", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 5 (Gov Intel) failed:", err.message);
  }
  try {
    const { runIcsScadaIntelIngest } = await import("./ics-scada-intel-4I4GAVZN.js");
    const icsResult = await runIcsScadaIntelIngest();
    results.phases.push({ phase: "ics_scada_intel", success: true, ...icsResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 5.5 (ICS/SCADA): ${icsResult.totalNewRecords || 0} new records`);
  } catch (err) {
    results.phases.push({ phase: "ics_scada_intel", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 5.5 (ICS/SCADA) failed:", err.message);
  }
  try {
    const { runLeakSiteMonitor } = await import("./ransomware-leak-monitor-QJGJ5ORE.js");
    const leakResult = await runLeakSiteMonitor();
    results.phases.push({ phase: "ransomware_leak_monitor", success: true, ...leakResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 6 (Ransomware): complete`);
  } catch (err) {
    results.phases.push({ phase: "ransomware_leak_monitor", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 6 (Ransomware) failed:", err.message);
  }
  try {
    const { refreshCveDatabase, getCveRefreshStats } = await import("./nvd-cve-refresh-KOXORVRR.js");
    const techWatchlist = ["streamlit", "jupyter", "langchain", "faiss", "firebase", "github_actions", "wordpress", "cpanel", "cisco_asa", "bitwarden"];
    const cveResult = await refreshCveDatabase(techWatchlist);
    results.phases.push({ phase: "cve_refresh", success: true, ...cveResult, stats: getCveRefreshStats() });
    console.log(`[ThreatIntelDaily-Cron] Phase 7 (CVE): ${cveResult.totalNew || 0} new CVEs`);
  } catch (err) {
    results.phases.push({ phase: "cve_refresh", success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 7 (CVE) failed:", err.message);
  }
  try {
    const { getDb } = await import("./db-EEYUM2OC.js");
    const db = await getDb();
    if (db) {
      const { incidentReports } = await import("./schema-AEHUE7AH.js");
      const { desc: descOrder, and: andOp, gte, eq: eqOp } = await import("drizzle-orm");
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1e3);
      const recentCritical = await db.select().from(incidentReports).where(andOp(
        gte(incidentReports.irCreatedAt, oneDayAgo.toISOString()),
        eqOp(incidentReports.irSeverity, "critical")
      )).orderBy(descOrder(incidentReports.irCreatedAt)).limit(10);
      results.phases.push({
        phase: "zero_day_monitor",
        success: true,
        criticalCount: recentCritical.length,
        items: recentCritical.map((r) => ({ title: r.title, source: r.source, severity: r.irSeverity }))
      });
      if (recentCritical.length > 0) {
        console.log(`[ThreatIntelDaily-Cron] Phase 8 (Zero-Day): ${recentCritical.length} critical items detected`);
      }
    }
  } catch (err) {
    results.phases.push({ phase: "zero_day_monitor", success: false, error: err.message });
  }
  try {
    const { notifyOwner } = await import("./notification-4RFY3TAD.js");
    const successCount2 = results.phases.filter((p) => p.success).length;
    const totalPhases = results.phases.length;
    const rssPhase = results.phases.find((p) => p.phase === "rss_sync");
    const ingestPhase = results.phases.find((p) => p.phase === "full_ingest");
    const crawlPhase = results.phases.find((p) => p.phase === "actor_crawl");
    const govPhase = results.phases.find((p) => p.phase === "government_intel");
    const icsPhase = results.phases.find((p) => p.phase === "ics_scada_intel");
    const cvePhase = results.phases.find((p) => p.phase === "cve_refresh");
    const zeroDayPhase = results.phases.find((p) => p.phase === "zero_day_monitor");
    const summaryLines = [
      `Daily Threat Intel Update (Internal Cron) \u2014 ${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}`,
      `Phases: ${successCount2}/${totalPhases} successful`,
      ""
    ];
    if (rssPhase?.success) summaryLines.push(`RSS Feeds: ${rssPhase.newArticles || 0} new articles from ${rssPhase.feedsProcessed || 0} feeds`);
    if (ingestPhase?.success) summaryLines.push(`Multi-source ingest: ${ingestPhase.totalNewRecords || 0} new records from ${ingestPhase.successfulSources || 0} sources`);
    if (crawlPhase?.success) summaryLines.push(`Actor crawl: ${crawlPhase.newEvents || crawlPhase.eventsRecorded || 0} new events, ${crawlPhase.groupsEnriched || 0} groups enriched`);
    if (govPhase?.success) summaryLines.push(`Gov Intel: ${govPhase.totalNewRecords || 0} new records from ${govPhase.successfulSources || 0}/${govPhase.totalSources || 0} sources (OFAC, RFJ, FBI, DOJ, NSA, ACSC, CCCS)`);
    if (icsPhase?.success) summaryLines.push(`ICS/SCADA: ${icsPhase.totalNewRecords || 0} new records (CISA ICS, CSAF, Siemens, malware KB)`);
    if (cvePhase?.success) summaryLines.push(`CVE refresh: ${cvePhase.totalNew || 0} new CVEs`);
    if (zeroDayPhase?.success && zeroDayPhase.criticalCount > 0) {
      summaryLines.push(`\u26A0\uFE0F ZERO-DAY ALERT: ${zeroDayPhase.criticalCount} critical items in last 24h`);
      for (const item of (zeroDayPhase.items || []).slice(0, 5)) {
        summaryLines.push(`  \u2022 ${item.title}`);
      }
    }
    await notifyOwner({
      title: `\u{1F4E1} Daily Threat Intel Summary (${successCount2}/${totalPhases} OK)`,
      content: summaryLines.join("\n")
    });
    results.phases.push({ phase: "owner_notification", success: true });
  } catch (err) {
    results.phases.push({ phase: "owner_notification", success: false, error: err.message });
  }
  const successCount = results.phases.filter((p) => p.success).length;
  results.summary = `${successCount}/${results.phases.length} phases completed successfully`;
  return results;
}
function stopThreatIntelDailyScheduler() {
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }
  schedulerInitialized = false;
  isRunning = false;
  console.log("[ThreatIntelDaily-Cron] Stopped");
}
function isThreatIntelDailySchedulerActive() {
  return schedulerInitialized;
}
function isThreatIntelDailyRunning() {
  return isRunning;
}
function getLastRunResult() {
  return lastRunResult;
}
export {
  getLastRunResult,
  initThreatIntelDailyScheduler,
  isThreatIntelDailyRunning,
  isThreatIntelDailySchedulerActive,
  runDailyThreatIntelPipeline,
  stopThreatIntelDailyScheduler
};
