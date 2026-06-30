/**
 * Threat Intelligence Daily Scheduler
 *
 * Internal cron-based scheduler that runs the full threat intelligence
 * ingestion pipeline daily at 03:30 UTC. This replaces the dependency on
 * external Manus scheduled task triggers — the pipeline now runs
 * autonomously inside the ECS container.
 *
 * Pipeline phases (same as /api/scheduled/threat-intel-daily):
 *   1. RSS feed sync (18+ sources)
 *   2. Full multi-source ingestion (DFIR, CISA, Unit42, etc.)
 *   3. Threat actor intelligence crawl (LLM-powered)
 *   4. Targeted enrichment for high-priority actors
 *   5. Government intelligence sources (OFAC, RFJ, FBI, DOJ, NSA, ACSC, CCCS)
 *   6. Ransomware leak site monitoring
 *   7. CVE refresh
 *   8. Zero-day monitoring
 *   9. Owner notification with daily summary
 *
 * Schedule: Daily at 03:30 UTC
 * This runs BEFORE the lastActive updater (08:15 UTC) and feed syncs (06:00 UTC)
 * to ensure fresh data is available for downstream processors.
 */

import cron from "node-cron";

let schedulerInitialized = false;
let scheduledTask: ReturnType<typeof cron.schedule> | null = null;
let lastRunResult: any = null;
let isRunning = false;

/**
 * Initialize the daily threat intelligence scheduler.
 * Runs at 03:30 UTC every day.
 */
export function initThreatIntelDailyScheduler(): void {
  if (schedulerInitialized) {
    console.log("[ThreatIntelDaily-Cron] Already initialized, skipping");
    return;
  }

  // Daily at 03:30 UTC
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
      } catch (err: any) {
        console.error("[ThreatIntelDaily-Cron] Pipeline failed:", err.message);
        lastRunResult = { error: err.message, timestamp: new Date().toISOString() };
      } finally {
        isRunning = false;
      }
    },
    { timezone: "UTC" }
  );

  schedulerInitialized = true;
  console.log("[ThreatIntelDaily-Cron] Initialized — daily at 03:30 UTC");
}

/**
 * Run the full daily threat intelligence pipeline.
 * This is the same logic as the /api/scheduled/threat-intel-daily endpoint
 * but runs internally without requiring an HTTP trigger.
 */
export async function runDailyThreatIntelPipeline(): Promise<any> {
  const results: any = { timestamp: new Date().toISOString(), phases: [] };

  // Phase 1: RSS feed sync (all threat intel feeds)
  try {
    const { syncAllThreatIntelFeeds } = await import("./threat-intel-rss");
    const rssResult = await syncAllThreatIntelFeeds();
    results.phases.push({ phase: 'rss_sync', success: true, ...rssResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 1 (RSS): ${rssResult.newArticles || 0} new articles`);
  } catch (err: any) {
    results.phases.push({ phase: 'rss_sync', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 1 (RSS) failed:", err.message);
  }

  // Phase 2: Full multi-source ingestion (DFIR, CISA, Unit42, etc.)
  try {
    const { runFullIngest } = await import("./threat-intel-ingest");
    const ingestResult = await runFullIngest();
    results.phases.push({ phase: 'full_ingest', success: true, ...ingestResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 2 (Ingest): ${ingestResult.totalNewRecords || 0} new records`);
  } catch (err: any) {
    results.phases.push({ phase: 'full_ingest', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 2 (Ingest) failed:", err.message);
  }

  // Phase 3: Threat actor intelligence crawl (LLM-powered enrichment)
  try {
    const { runIntelligenceCrawl } = await import("./threat-actor-crawler");
    const crawlResult = await runIntelligenceCrawl({ maxArticles: 50, maxGroups: 20 });
    results.phases.push({ phase: 'actor_crawl', success: true, ...crawlResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 3 (Crawl): ${crawlResult.newEvents || crawlResult.eventsRecorded || 0} events`);
  } catch (err: any) {
    results.phases.push({ phase: 'actor_crawl', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 3 (Crawl) failed:", err.message);
  }

  // Phase 4: Targeted enrichment for high-priority actors
  try {
    const { runTargetedEnrichment } = await import("./threat-actor-crawler");
    const enrichResult = await runTargetedEnrichment({ maxActors: 10 });
    results.phases.push({ phase: 'targeted_enrichment', success: true, ...enrichResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 4 (Enrichment): complete`);
  } catch (err: any) {
    results.phases.push({ phase: 'targeted_enrichment', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 4 (Enrichment) failed:", err.message);
  }

  // Phase 5: Government intelligence sources (NEW)
  try {
    const { runGovernmentIntelIngest } = await import("./government-intel-sources");
    const govResult = await runGovernmentIntelIngest();
    results.phases.push({ phase: 'government_intel', success: true, ...govResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 5 (Gov Intel): ${govResult.totalNewRecords} new records from ${govResult.successfulSources}/${govResult.totalSources} sources`);
  } catch (err: any) {
    results.phases.push({ phase: 'government_intel', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 5 (Gov Intel) failed:", err.message);
  }

  // Phase 5.5: ICS/SCADA threat intelligence
  try {
    const { runIcsScadaIntelIngest } = await import("./ics-scada-intel");
    const icsResult = await runIcsScadaIntelIngest();
    results.phases.push({ phase: 'ics_scada_intel', success: true, ...icsResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 5.5 (ICS/SCADA): ${icsResult.totalNewRecords || 0} new records`);
  } catch (err: any) {
    results.phases.push({ phase: 'ics_scada_intel', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 5.5 (ICS/SCADA) failed:", err.message);
  }

  // Phase 6: Ransomware leak site monitoring
  try {
    const { runLeakSiteMonitor } = await import("./ransomware-leak-monitor");
    const leakResult = await runLeakSiteMonitor();
    results.phases.push({ phase: 'ransomware_leak_monitor', success: true, ...leakResult });
    console.log(`[ThreatIntelDaily-Cron] Phase 6 (Ransomware): complete`);
  } catch (err: any) {
    results.phases.push({ phase: 'ransomware_leak_monitor', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 6 (Ransomware) failed:", err.message);
  }

  // Phase 7: CVE refresh
  try {
    const { refreshCveDatabase, getCveRefreshStats } = await import("./nvd-cve-refresh");
    const techWatchlist = ['streamlit', 'jupyter', 'langchain', 'faiss', 'firebase', 'github_actions', 'wordpress', 'cpanel', 'cisco_asa', 'bitwarden'];
    const cveResult = await refreshCveDatabase(techWatchlist);
    results.phases.push({ phase: 'cve_refresh', success: true, ...cveResult, stats: getCveRefreshStats() });
    console.log(`[ThreatIntelDaily-Cron] Phase 7 (CVE): ${cveResult.totalNew || 0} new CVEs`);
  } catch (err: any) {
    results.phases.push({ phase: 'cve_refresh', success: false, error: err.message });
    console.warn("[ThreatIntelDaily-Cron] Phase 7 (CVE) failed:", err.message);
  }

  // Phase 8: Zero-day monitoring
  try {
    const { getDb } = await import("../db");
    const db = await getDb();
    if (db) {
      const { incidentReports } = await import("../../drizzle/schema");
      const { desc: descOrder, and: andOp, gte, eq: eqOp } = await import("drizzle-orm");
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const recentCritical = await db.select()
        .from(incidentReports)
        .where(andOp(
          gte(incidentReports.irCreatedAt, oneDayAgo.toISOString()),
          eqOp(incidentReports.irSeverity, 'critical')
        ))
        .orderBy(descOrder(incidentReports.irCreatedAt))
        .limit(10);
      results.phases.push({
        phase: 'zero_day_monitor',
        success: true,
        criticalCount: recentCritical.length,
        items: recentCritical.map(r => ({ title: r.title, source: r.source, severity: r.irSeverity })),
      });
      if (recentCritical.length > 0) {
        console.log(`[ThreatIntelDaily-Cron] Phase 8 (Zero-Day): ${recentCritical.length} critical items detected`);
      }
    }
  } catch (err: any) {
    results.phases.push({ phase: 'zero_day_monitor', success: false, error: err.message });
  }

  // Phase 9: Owner notification with daily summary
  try {
    const { notifyOwner } = await import("../_core/notification");
    const successCount = results.phases.filter((p: any) => p.success).length;
    const totalPhases = results.phases.length;

    const rssPhase = results.phases.find((p: any) => p.phase === 'rss_sync');
    const ingestPhase = results.phases.find((p: any) => p.phase === 'full_ingest');
    const crawlPhase = results.phases.find((p: any) => p.phase === 'actor_crawl');
    const govPhase = results.phases.find((p: any) => p.phase === 'government_intel');
    const icsPhase = results.phases.find((p: any) => p.phase === 'ics_scada_intel');
    const cvePhase = results.phases.find((p: any) => p.phase === 'cve_refresh');
    const zeroDayPhase = results.phases.find((p: any) => p.phase === 'zero_day_monitor');

    const summaryLines: string[] = [
      `Daily Threat Intel Update (Internal Cron) — ${new Date().toISOString().slice(0, 10)}`,
      `Phases: ${successCount}/${totalPhases} successful`,
      '',
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
        summaryLines.push(`  • ${item.title}`);
      }
    }

    await notifyOwner({
      title: `\u{1F4E1} Daily Threat Intel Summary (${successCount}/${totalPhases} OK)`,
      content: summaryLines.join('\n'),
    });
    results.phases.push({ phase: 'owner_notification', success: true });
  } catch (err: any) {
    results.phases.push({ phase: 'owner_notification', success: false, error: err.message });
  }

  const successCount = results.phases.filter((p: any) => p.success).length;
  results.summary = `${successCount}/${results.phases.length} phases completed successfully`;

  return results;
}

/** Stop the scheduled task (for testing/shutdown). */
export function stopThreatIntelDailyScheduler(): void {
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }
  schedulerInitialized = false;
  isRunning = false;
  console.log("[ThreatIntelDaily-Cron] Stopped");
}

/** Check if the scheduler is active. */
export function isThreatIntelDailySchedulerActive(): boolean {
  return schedulerInitialized;
}

/** Check if a pipeline run is currently in progress. */
export function isThreatIntelDailyRunning(): boolean {
  return isRunning;
}

/** Get the result of the last completed run. */
export function getLastRunResult(): any {
  return lastRunResult;
}
