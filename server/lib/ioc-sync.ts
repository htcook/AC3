/**
 * IOC Feed Auto-Sync Service
 * 
 * Runs as a scheduled background task to fetch IOCs from:
 * - CISA Known Exploited Vulnerabilities (KEV)
 * - abuse.ch URLhaus (malicious URLs)
 * - abuse.ch ThreatFox (IOCs from malware campaigns)
 * 
 * Stores results in the ioc_feeds table and logs sync history.
 * Designed to run daily at 06:00 UTC.
 */

import cron from "node-cron";
import * as db from "../db";
import type { InsertIocFeed } from "../../drizzle/schema";

let syncRunning = false;

/** Fetch CISA KEV vulnerabilities */
async function fetchCisaKev(): Promise<{ source: string; fetched: number; error?: string }> {
  try {
    const response = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!response.ok) return { source: "cisa_kev", fetched: 0, error: `HTTP ${response.status}` };
    const data = (await response.json()) as any;
    const vulnerabilities = data.vulnerabilities || [];

    const entries: InsertIocFeed[] = vulnerabilities.slice(0, 500).map((v: any) => ({
      feedSource: "cisa_kev",
      feedType: "vulnerability",
      title: v.vulnerabilityName || v.cveID,
      description: v.shortDescription,
      severity: "critical" as const,
      iocType: "cve",
      iocValue: v.cveID,
      cveId: v.cveID,
      vendorProduct: `${v.vendorProject || ""} ${v.product || ""}`.trim(),
      knownRansomware: v.knownRansomwareCampaignUse === "Known",
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      linkedActors: [],
      tags: [v.vendorProject, v.product].filter(Boolean),
      rawData: v,
    }));

    if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
    return { source: "cisa_kev", fetched: entries.length };
  } catch (err: any) {
    return { source: "cisa_kev", fetched: 0, error: err.message };
  }
}

/** Fetch abuse.ch URLhaus recent malicious URLs */
async function fetchAbuseCh(): Promise<{ source: string; fetched: number; error?: string }> {
  try {
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "limit=100",
    });
    if (!response.ok) return { source: "abusech_urlhaus", fetched: 0, error: `HTTP ${response.status}` };
    const data = (await response.json()) as any;
    const urls = data.urls || [];

    const entries: InsertIocFeed[] = urls.map((u: any) => ({
      feedSource: "abusech_urlhaus",
      feedType: "url",
      title: u.threat || "Malicious URL",
      description: `URL: ${u.url} | Threat: ${u.threat} | Status: ${u.url_status}`,
      severity: u.threat === "malware_download" ? ("high" as const) : ("medium" as const),
      iocType: "url",
      iocValue: u.url,
      dateAdded: u.date_added,
      linkedActors: [],
      tags: u.tags || [],
      rawData: u,
    }));

    if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
    return { source: "abusech_urlhaus", fetched: entries.length };
  } catch (err: any) {
    return { source: "abusech_urlhaus", fetched: 0, error: err.message };
  }
}

/** Fetch abuse.ch ThreatFox IOCs from last 7 days */
async function fetchThreatFox(): Promise<{ source: string; fetched: number; error?: string }> {
  try {
    const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 7 }),
    });
    if (!response.ok) return { source: "abusech_threatfox", fetched: 0, error: `HTTP ${response.status}` };
    const data = (await response.json()) as any;
    const iocs = Array.isArray(data.data) ? data.data.slice(0, 200) : [];

    const entries: InsertIocFeed[] = iocs.map((i: any) => ({
      feedSource: "abusech_threatfox",
      feedType: i.ioc_type || "unknown",
      title: i.malware_printable || i.threat_type || "IOC",
      description: `${i.ioc_type}: ${i.ioc} | Malware: ${i.malware_printable} | Confidence: ${i.confidence_level}%`,
      severity: (i.confidence_level || 0) > 75 ? ("high" as const) : ("medium" as const),
      iocType: i.ioc_type?.includes("hash") ? "hash" : i.ioc_type?.includes("domain") ? "domain" : i.ioc_type?.includes("ip") ? "ip" : "url",
      iocValue: i.ioc,
      dateAdded: i.first_seen_utc,
      linkedActors: i.malware_alias ? [i.malware_alias] : [],
      tags: i.tags || [],
      rawData: i,
    }));

    if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
    return { source: "abusech_threatfox", fetched: entries.length };
  } catch (err: any) {
    return { source: "abusech_threatfox", fetched: 0, error: err.message };
  }
}

/** Run a full IOC sync across all feeds */
export async function runIocSync(syncType: "scheduled" | "manual" = "scheduled"): Promise<{
  logId: number;
  results: Array<{ source: string; fetched: number; error?: string }>;
  totalFetched: number;
}> {
  if (syncRunning) {
    throw new Error("IOC sync is already running");
  }
  syncRunning = true;

  // Create sync log entry
  const logId = await db.createIocSyncLog({
    syncType,
    status: "running",
    results: [],
    totalFetched: 0,
  });

  try {
    console.log(`[IOC Sync] Starting ${syncType} sync (log #${logId})...`);

    // Run all feeds in parallel
    const [cisaResult, abuseChResult, threatFoxResult] = await Promise.all([
      fetchCisaKev(),
      fetchAbuseCh(),
      fetchThreatFox(),
    ]);

    const results = [cisaResult, abuseChResult, threatFoxResult];
    const totalFetched = results.reduce((sum, r) => sum + r.fetched, 0);
    const hasErrors = results.some((r) => r.error);

    await db.updateIocSyncLog(logId, {
      status: hasErrors ? "completed" : "completed",
      results,
      totalFetched,
      errorMessage: hasErrors ? results.filter((r) => r.error).map((r) => `${r.source}: ${r.error}`).join("; ") : undefined,
      completedAt: new Date(),
    });

    console.log(`[IOC Sync] Completed: ${totalFetched} IOCs fetched from ${results.length} feeds`);
    results.forEach((r) => {
      console.log(`  - ${r.source}: ${r.fetched} entries${r.error ? ` (error: ${r.error})` : ""}`);
    });

    return { logId, results, totalFetched };
  } catch (err: any) {
    await db.updateIocSyncLog(logId, {
      status: "failed",
      errorMessage: err.message,
      completedAt: new Date(),
    });
    console.error(`[IOC Sync] Failed:`, err.message);
    throw err;
  } finally {
    syncRunning = false;
  }
}

/** Check if sync is currently running */
export function isSyncRunning(): boolean {
  return syncRunning;
}

/** Initialize the scheduled IOC sync cron job */
export function initIocSyncSchedule() {
  // Run daily at 06:00 UTC
  const task = cron.schedule("0 6 * * *", async () => {
    try {
      await runIocSync("scheduled");
    } catch (err) {
      console.error("[IOC Sync Cron] Scheduled sync failed:", err);
    }
  }, {
    timezone: "UTC",
  });

  console.log("[IOC Sync] Scheduled daily sync at 06:00 UTC");

  return task;
}
