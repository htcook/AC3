import {
  bulkCreateIocFeedEntries,
  createIocSyncLog,
  init_db,
  updateIocSyncLog
} from "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-TYPEU32S.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ioc-sync.ts
init_db();
import cron from "node-cron";
var syncRunning = false;
async function cleanupStuckSyncs() {
  try {
    const { getDb } = await import("./db-OF4HQS7N.js");
    const database = await getDb();
    if (!database) return 0;
    const { iocSyncLogs } = await import("./schema-R6EY37IN.js");
    const { eq, and, lt, sql } = await import("drizzle-orm");
    const thirtyMinAgo = new Date(Date.now() - 30 * 60 * 1e3);
    const result = await database.update(iocSyncLogs).set({ status: "timed_out", completedAt: /* @__PURE__ */ new Date(), errorMessage: "Auto-cleanup: stuck in running state for >30 min" }).where(and(eq(iocSyncLogs.status, "running"), lt(iocSyncLogs.startedAt, thirtyMinAgo)));
    const cleaned = result[0]?.affectedRows || 0;
    if (cleaned > 0) {
      console.log(`[IOC Sync] Auto-cleaned ${cleaned} stuck sync job(s)`);
    }
    return cleaned;
  } catch (err) {
    console.warn(`[IOC Sync] Cleanup check failed: ${err.message}`);
    return 0;
  }
}
async function fetchWithRetry(url, opts = {}, retries = 2, delay = 3e3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetch(url, { ...opts, signal: opts.signal || AbortSignal.timeout(3e4) });
    } catch (err) {
      if (attempt === retries) throw err;
      console.warn(`[IOC Sync] Fetch attempt ${attempt + 1} failed for ${url.substring(0, 60)}..., retrying in ${delay}ms`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw new Error("fetchWithRetry exhausted");
}
async function fetchCisaKev() {
  try {
    const response = await fetchWithRetry("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!response.ok) return { source: "cisa_kev", fetched: 0, error: `HTTP ${response.status}` };
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];
    const entries = vulnerabilities.slice(0, 500).map((v) => ({
      feedSource: "cisa_kev",
      feedType: "vulnerability",
      title: v.vulnerabilityName || v.cveID,
      description: v.shortDescription,
      severity: "critical",
      iocType: "cve",
      iocValue: v.cveID,
      cveId: v.cveID,
      vendorProduct: `${v.vendorProject || ""} ${v.product || ""}`.trim(),
      knownRansomware: v.knownRansomwareCampaignUse === "Known",
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      linkedActors: [],
      tags: [v.vendorProject, v.product].filter(Boolean),
      rawData: v
    }));
    if (entries.length > 0) await bulkCreateIocFeedEntries(entries);
    return { source: "cisa_kev", fetched: entries.length };
  } catch (err) {
    return { source: "cisa_kev", fetched: 0, error: err.message };
  }
}
async function fetchAbuseCh() {
  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (apiKey) headers["Auth-Key"] = apiKey;
    const response = await fetchWithRetry("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/", {
      method: "GET",
      headers
    });
    if (!response.ok) {
      if (response.status === 401) return { source: "abusech_urlhaus", fetched: 0, error: "Auth required \u2014 set ABUSECH_API_KEY (register at auth.abuse.ch)" };
      return { source: "abusech_urlhaus", fetched: 0, error: `HTTP ${response.status}` };
    }
    const data = await response.json();
    const urls = data.urls || [];
    const entries = urls.map((u) => ({
      feedSource: "abusech_urlhaus",
      feedType: "url",
      title: u.threat || "Malicious URL",
      description: `URL: ${u.url} | Threat: ${u.threat} | Status: ${u.url_status}`,
      severity: u.threat === "malware_download" ? "high" : "medium",
      iocType: "url",
      iocValue: u.url,
      dateAdded: u.date_added,
      linkedActors: [],
      tags: u.tags || [],
      rawData: u
    }));
    if (entries.length > 0) await bulkCreateIocFeedEntries(entries);
    return { source: "abusech_urlhaus", fetched: entries.length };
  } catch (err) {
    return { source: "abusech_urlhaus", fetched: 0, error: err.message };
  }
}
async function fetchThreatFox() {
  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["Auth-Key"] = apiKey;
    const response = await fetchWithRetry("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: JSON.stringify({ query: "get_iocs", days: 7 })
    });
    if (!response.ok) {
      if (response.status === 401) return { source: "abusech_threatfox", fetched: 0, error: "Auth required \u2014 set ABUSECH_API_KEY (register at auth.abuse.ch)" };
      return { source: "abusech_threatfox", fetched: 0, error: `HTTP ${response.status}` };
    }
    const data = await response.json();
    const iocs = Array.isArray(data.data) ? data.data.slice(0, 200) : [];
    const entries = iocs.map((i) => ({
      feedSource: "abusech_threatfox",
      feedType: i.ioc_type || "unknown",
      title: i.malware_printable || i.threat_type || "IOC",
      description: `${i.ioc_type}: ${i.ioc} | Malware: ${i.malware_printable} | Confidence: ${i.confidence_level}%`,
      severity: (i.confidence_level || 0) > 75 ? "high" : "medium",
      iocType: i.ioc_type?.includes("hash") ? "hash" : i.ioc_type?.includes("domain") ? "domain" : i.ioc_type?.includes("ip") ? "ip" : "url",
      iocValue: i.ioc,
      dateAdded: i.first_seen_utc,
      linkedActors: i.malware_alias ? [i.malware_alias] : [],
      tags: i.tags || [],
      rawData: i
    }));
    if (entries.length > 0) await bulkCreateIocFeedEntries(entries);
    return { source: "abusech_threatfox", fetched: entries.length };
  } catch (err) {
    return { source: "abusech_threatfox", fetched: 0, error: err.message };
  }
}
async function runIocSync(syncType = "scheduled") {
  if (syncRunning) {
    throw new Error("IOC sync is already running");
  }
  await cleanupStuckSyncs();
  syncRunning = true;
  const logId = await createIocSyncLog({
    syncType,
    status: "running",
    results: [],
    totalFetched: 0
  });
  try {
    console.log(`[IOC Sync] Starting ${syncType} sync (log #${logId})...`);
    const [cisaResult, abuseChResult, threatFoxResult] = await Promise.all([
      fetchCisaKev(),
      fetchAbuseCh(),
      fetchThreatFox()
    ]);
    const results = [cisaResult, abuseChResult, threatFoxResult];
    const totalFetched = results.reduce((sum, r) => sum + r.fetched, 0);
    const hasErrors = results.some((r) => r.error);
    let darkwebEnrichment = { enriched: 0, totalHits: 0 };
    try {
      const { postSyncDarkwebEnrichment } = await import("./darkweb-ioc-enrichment-YWTL4L4T.js");
      const newIocs = [];
      if (cisaResult.fetched > 0) newIocs.push(...Array.from({ length: Math.min(10, cisaResult.fetched) }, (_, i) => ({ value: `cisa-kev-${i}`, type: "cve" })));
      if (abuseChResult.fetched > 0) newIocs.push(...Array.from({ length: Math.min(10, abuseChResult.fetched) }, (_, i) => ({ value: `urlhaus-${i}`, type: "url" })));
      if (threatFoxResult.fetched > 0) newIocs.push(...Array.from({ length: Math.min(10, threatFoxResult.fetched) }, (_, i) => ({ value: `threatfox-${i}`, type: "hash" })));
      darkwebEnrichment = await postSyncDarkwebEnrichment(newIocs);
      console.log(`[IOC Sync] Darkweb enrichment: ${darkwebEnrichment.enriched} IOCs enriched with ${darkwebEnrichment.totalHits} hits`);
    } catch (err) {
      console.warn(`[IOC Sync] Darkweb enrichment skipped: ${err.message}`);
    }
    try {
      const { runDarkwebFeedSync, isDarkwebSyncRunning } = await import("./darkweb-osint-service-7AFJMEY5.js");
      if (!isDarkwebSyncRunning()) {
        runDarkwebFeedSync().then((r) => {
          console.log(`[IOC Sync] Darkweb feed sync completed: ${r.totalFetched} events from ${r.results.length} feeds`);
        }).catch((err) => {
          console.warn(`[IOC Sync] Darkweb feed sync failed: ${err.message}`);
        });
      }
    } catch (err) {
      console.warn(`[IOC Sync] Darkweb feed sync trigger skipped: ${err.message}`);
    }
    await updateIocSyncLog(logId, {
      status: hasErrors ? "completed" : "completed",
      results,
      totalFetched,
      errorMessage: hasErrors ? results.filter((r) => r.error).map((r) => `${r.source}: ${r.error}`).join("; ") : void 0,
      completedAt: /* @__PURE__ */ new Date()
    });
    console.log(`[IOC Sync] Completed: ${totalFetched} IOCs fetched from ${results.length} feeds`);
    results.forEach((r) => {
      console.log(`  - ${r.source}: ${r.fetched} entries${r.error ? ` (error: ${r.error})` : ""}`);
    });
    return { logId, results, totalFetched };
  } catch (err) {
    await updateIocSyncLog(logId, {
      status: "failed",
      errorMessage: err.message,
      completedAt: /* @__PURE__ */ new Date()
    });
    console.error(`[IOC Sync] Failed:`, err.message);
    throw err;
  } finally {
    syncRunning = false;
  }
}
function isSyncRunning() {
  return syncRunning;
}
function initIocSyncSchedule() {
  const task = cron.schedule("0 6 * * *", async () => {
    try {
      await runIocSync("scheduled");
    } catch (err) {
      console.error("[IOC Sync Cron] Scheduled sync failed:", err);
    }
  }, {
    timezone: "UTC"
  });
  cleanupStuckSyncs().catch(() => {
  });
  console.log("[IOC Sync] Scheduled daily sync at 06:00 UTC");
  return task;
}
export {
  initIocSyncSchedule,
  isSyncRunning,
  runIocSync
};
