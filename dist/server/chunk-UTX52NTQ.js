import {
  getDb,
  init_db
} from "./chunk-JZVHFV6D.js";
import {
  credentialExposures,
  darkwebFeedRegistry,
  init_schema,
  networkEvents,
  undergroundIntelEvents
} from "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/darkweb-osint-service.ts
import { eq, sql } from "drizzle-orm";
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function safeFetch(url, opts, timeoutMs = 3e4) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}
function abusechHeaders() {
  const key = process.env.ABUSECH_API_KEY || "";
  const h = {};
  if (key) h["Auth-Key"] = key;
  return h;
}
async function initFeedRegistry() {
  const db = await requireDb();
  for (const feed of BUILT_IN_FEEDS) {
    try {
      await db.insert(darkwebFeedRegistry).values(feed).onDuplicateKeyUpdate({ set: { dfrFeedUrl: feed.dfrFeedUrl, dfrDescription: feed.dfrDescription } });
    } catch {
    }
  }
  console.log(`[DarkwebOSINT] Feed registry initialized with ${BUILT_IN_FEEDS.length} built-in feeds`);
}
async function updateFeedStatus(feedName, status, fetched, error) {
  const db = await requireDb();
  const updates = {
    dfrStatus: status,
    dfrLastSyncAt: /* @__PURE__ */ new Date(),
    dfrTotalSyncs: sql`dfr_total_syncs + 1`,
    dfrTotalRecordsFetched: sql`dfr_total_records_fetched + ${fetched}`
  };
  if (error) {
    updates.dfrLastError = error;
    updates.dfrConsecutiveFailures = sql`dfr_consecutive_failures + 1`;
  } else {
    updates.dfrLastError = null;
    updates.dfrConsecutiveFailures = 0;
  }
  await db.update(darkwebFeedRegistry).set(updates).where(eq(darkwebFeedRegistry.dfrFeedName, feedName));
}
async function fetchFeodoTracker() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const db = await requireDb();
    let count = 0;
    const batch = [];
    for (const entry of (data || []).slice(0, 500)) {
      batch.push({
        neEventType: "c2_server",
        neSource: "feodo_tracker",
        neIpAddress: entry.ip_address || entry.dst_ip,
        nePort: entry.dst_port || entry.port,
        neHostname: entry.hostname,
        neProtocol: "tcp",
        neMalwareFamily: entry.malware || "unknown",
        neDescription: `Feodo C2: ${entry.malware || "unknown"} at ${entry.ip_address || entry.dst_ip}:${entry.dst_port || entry.port}`,
        neSeverity: "high",
        neConfidence: 90,
        neCountry: entry.country,
        neAsn: entry.as_number ? String(entry.as_number) : void 0,
        neAsnOrg: entry.as_name,
        neStatus: entry.status === "online" ? "active" : "inactive",
        neFirstSeen: entry.first_seen ? new Date(entry.first_seen) : void 0,
        neLastSeen: entry.last_online ? new Date(entry.last_online) : void 0,
        neTags: [entry.malware, "c2", "botnet"].filter(Boolean),
        neRawData: entry
      });
      count++;
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("abusech_feodo", "active", count);
    return { feed: "feodo_tracker", fetched: count, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("abusech_feodo", "down", 0, err.message).catch(() => {
    });
    return { feed: "feodo_tracker", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchMalwareBazaar() {
  const start = Date.now();
  try {
    const headers = { "Content-Type": "application/x-www-form-urlencoded", ...abusechHeaders() };
    const res = await safeFetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: "query=get_recent&selector=100"
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const samples = Array.isArray(data.data) ? data.data.slice(0, 200) : [];
    const db = await requireDb();
    const batch = samples.map((s) => ({
      uieCategory: "malware",
      uieSource: "malwarebazaar",
      uieTitle: `${s.signature || s.file_type || "Unknown"} sample: ${s.sha256_hash?.substring(0, 16)}...`,
      uieDescription: `Malware sample: ${s.file_name || "unknown"} | Type: ${s.file_type} | Signature: ${s.signature || "none"} | SHA256: ${s.sha256_hash}`,
      uieSeverity: (s.intelligence?.clamav || []).length > 0 ? "high" : "medium",
      uieConfidence: 85,
      uieIocType: "hash",
      uieIocValue: s.sha256_hash,
      uieActorName: s.signature || void 0,
      uieTags: [...s.tags || [], s.file_type, "malware"].filter(Boolean),
      uieRawData: s,
      uieEventDate: s.first_seen ? new Date(s.first_seen) : /* @__PURE__ */ new Date()
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("abusech_malwarebazaar", "active", batch.length);
    return { feed: "malwarebazaar", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("abusech_malwarebazaar", "down", 0, err.message).catch(() => {
    });
    return { feed: "malwarebazaar", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchSSLBlacklist() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
    if (lines.length === 0) {
      await updateFeedStatus("abusech_sslbl", "inactive", 0, "Feed deprecated by abuse.ch (2025-01-03)");
      return { feed: "ssl_blacklist", fetched: 0, error: "Feed deprecated by abuse.ch", durationMs: Date.now() - start };
    }
    const db = await requireDb();
    const batch = [];
    for (const line of lines.slice(0, 300)) {
      const [firstSeen, dstIp, dstPort] = line.split(",").map((s) => s.trim());
      if (!dstIp || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(dstIp)) continue;
      batch.push({
        neEventType: "ssl_blacklist",
        neSource: "sslbl_abusech",
        neIpAddress: dstIp,
        nePort: dstPort ? parseInt(dstPort, 10) : void 0,
        neDescription: `SSL Blacklist C2: ${dstIp}:${dstPort || "?"}`,
        neSeverity: "high",
        neConfidence: 85,
        neStatus: "active",
        neFirstSeen: firstSeen ? new Date(firstSeen) : void 0,
        neTags: ["ssl", "c2", "botnet"],
        neRawData: { firstSeen, dstIp, dstPort }
      });
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("abusech_sslbl", "active", batch.length);
    return { feed: "ssl_blacklist", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("abusech_sslbl", "down", 0, err.message).catch(() => {
    });
    return { feed: "ssl_blacklist", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchRansomwareLiveVictims() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://api.ransomware.live/v1/recentvictims", {}, 6e4);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const victims = await res.json();
    const db = await requireDb();
    const recent = victims.slice(0, 200);
    const batch = recent.map((v) => ({
      uieCategory: "ransomware",
      uieSource: "ransomware_live",
      uieSourceUrl: v.post_url || v.website,
      uieTitle: `${v.group_name || "Unknown"} \u2192 ${v.post_title || v.victim || "Unknown victim"}`,
      uieDescription: `Ransomware victim: ${v.post_title || v.victim || "unknown"} | Group: ${v.group_name} | Country: ${v.country || "unknown"} | Sector: ${v.activity || "unknown"} | Published: ${v.published}`,
      uieSeverity: "critical",
      uieConfidence: 85,
      uieActorName: v.group_name,
      uieVictimName: v.post_title || v.victim,
      uieVictimSector: v.activity,
      uieVictimCountry: v.country,
      uieTags: [v.group_name, "ransomware", "leak_site", v.activity].filter(Boolean),
      uieRawData: v,
      uieEventDate: v.published ? new Date(v.published) : v.discovered ? new Date(v.discovered) : /* @__PURE__ */ new Date()
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("ransomware_live_victims", "active", batch.length);
    return { feed: "ransomware_live_victims", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("ransomware_live_victims", "down", 0, err.message).catch(() => {
    });
    return { feed: "ransomware_live_victims", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchRansomwareLiveGroups() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://api.ransomware.live/v2/groups", {}, 6e4);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const groups = await res.json();
    const db = await requireDb();
    const batch = groups.map((g) => ({
      uieCategory: "ransomware",
      uieSource: "ransomware_live_groups",
      uieSourceUrl: g.url,
      uieTitle: `Group profile: ${g.name}`,
      uieDescription: `Ransomware group: ${g.name} | Locations: ${JSON.stringify(g.locations || [])} | Profile: ${g.description?.substring(0, 500) || "No description"}`,
      uieSeverity: "high",
      uieConfidence: 90,
      uieActorName: g.name,
      uieTags: ["ransomware_group", "profile", ...g.locations || []].filter(Boolean),
      uieRawData: g
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("ransomware_live_groups", "active", batch.length);
    return { feed: "ransomware_live_groups", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("ransomware_live_groups", "down", 0, err.message).catch(() => {
    });
    return { feed: "ransomware_live_groups", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchAlienVaultOTX() {
  const start = Date.now();
  try {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) {
      return { feed: "alienvault_otx", fetched: 0, error: "OTX_API_KEY not set \u2014 register free at otx.alienvault.com", durationMs: Date.now() - start };
    }
    const res = await safeFetch("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=7d", {
      headers: { "X-OTX-API-KEY": apiKey }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const pulses = data.results || [];
    const db = await requireDb();
    const batch = [];
    for (const pulse of pulses) {
      const indicators = pulse.indicators || [];
      batch.push({
        uieCategory: "malware",
        uieSource: "alienvault_otx",
        uieSourceUrl: `https://otx.alienvault.com/pulse/${pulse.id}`,
        uieTitle: pulse.name || "OTX Pulse",
        uieDescription: `${pulse.description?.substring(0, 1e3) || "No description"} | Indicators: ${indicators.length} | TLP: ${pulse.TLP || "white"}`,
        uieSeverity: indicators.length > 20 ? "high" : "medium",
        uieConfidence: 75,
        uieActorName: pulse.adversary || void 0,
        uieMitreTechniques: pulse.attack_ids?.map((a) => a.id) || [],
        uieTags: [...pulse.tags || [], "otx", pulse.adversary].filter(Boolean),
        uieRawData: { ...pulse, indicators: indicators.slice(0, 50) },
        uieEventDate: pulse.modified ? new Date(pulse.modified) : /* @__PURE__ */ new Date()
      });
      for (const ind of indicators.slice(0, 10)) {
        batch.push({
          uieCategory: "malware",
          uieSource: "alienvault_otx",
          uieTitle: `OTX IOC: ${ind.indicator?.substring(0, 80)}`,
          uieDescription: `Type: ${ind.type} | Indicator: ${ind.indicator} | Pulse: ${pulse.name}`,
          uieSeverity: "medium",
          uieConfidence: 70,
          uieIocType: ind.type?.includes("IPv") ? "ip" : ind.type?.includes("domain") ? "domain" : ind.type?.includes("URL") ? "url" : "hash",
          uieIocValue: ind.indicator,
          uieTags: ["otx", "ioc", ind.type].filter(Boolean),
          uieRawData: ind
        });
      }
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("alienvault_otx", "active", batch.length);
    return { feed: "alienvault_otx", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("alienvault_otx", "down", 0, err.message).catch(() => {
    });
    return { feed: "alienvault_otx", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchOpenPhish() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://openphish.com/feed.txt");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const urls = text.split("\n").filter((l) => l.trim().startsWith("http")).slice(0, 200);
    const db = await requireDb();
    const batch = urls.map((url) => {
      let domain = "";
      try {
        domain = new URL(url).hostname;
      } catch {
        domain = url;
      }
      return {
        uieCategory: "phishing",
        uieSource: "openphish",
        uieSourceUrl: url,
        uieTitle: `Phishing URL: ${domain}`,
        uieDescription: `Phishing URL detected: ${url}`,
        uieSeverity: "high",
        uieConfidence: 80,
        uieIocType: "url",
        uieIocValue: url,
        uieTags: ["phishing", "url", domain],
        uieRawData: { url, domain }
      };
    });
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("openphish", "active", batch.length);
    return { feed: "openphish", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("openphish", "down", 0, err.message).catch(() => {
    });
    return { feed: "openphish", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchTorExitNodes() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://check.torproject.org/torbulkexitlist");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const ips = text.split("\n").filter((l) => l.trim() && !l.startsWith("#")).slice(0, 500);
    const db = await requireDb();
    const batch = ips.map((ip) => ({
      neEventType: "tor_exit_node",
      neSource: "torproject",
      neIpAddress: ip.trim(),
      neDescription: `Tor exit node: ${ip.trim()}`,
      neSeverity: "info",
      neConfidence: 95,
      neStatus: "active",
      neTags: ["tor", "exit_node", "anonymization"],
      neRawData: { ip: ip.trim() }
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("tor_exit_nodes", "active", batch.length);
    return { feed: "tor_exit_nodes", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("tor_exit_nodes", "down", 0, err.message).catch(() => {
    });
    return { feed: "tor_exit_nodes", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchBlocklistDe() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://lists.blocklist.de/lists/all.txt");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const IP_REGEX = /^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)$/;
    const ips = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("<") && IP_REGEX.test(l)).slice(0, 300);
    const db = await requireDb();
    const batch = ips.map((ip) => ({
      neEventType: "malicious_ip",
      neSource: "blocklist_de",
      neIpAddress: ip.trim(),
      neDescription: `Attack IP (last 24h): ${ip.trim()}`,
      neSeverity: "medium",
      neConfidence: 70,
      neStatus: "active",
      neTags: ["blocklist", "attack_ip"],
      neRawData: { ip: ip.trim() }
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("blocklist_de", "active", batch.length);
    return { feed: "blocklist_de", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("blocklist_de", "down", 0, err.message).catch(() => {
    });
    return { feed: "blocklist_de", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchSpamhausDrop() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://www.spamhaus.org/drop/drop.txt");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith(";")).slice(0, 200);
    const db = await requireDb();
    const batch = lines.map((line) => {
      const [cidr, sbl] = line.split(";").map((s) => s.trim());
      return {
        neEventType: "malicious_ip",
        neSource: "spamhaus_drop",
        neIpAddress: cidr,
        neDescription: `Spamhaus DROP: ${cidr} (SBL: ${sbl || "unknown"}) \u2014 hijacked/leased IP range`,
        neSeverity: "high",
        neConfidence: 95,
        neStatus: "active",
        neTags: ["spamhaus", "drop", "hijacked_ip", "bgp"],
        neRawData: { cidr, sbl }
      };
    });
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("spamhaus_drop", "active", batch.length);
    return { feed: "spamhaus_drop", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("spamhaus_drop", "down", 0, err.message).catch(() => {
    });
    return { feed: "spamhaus_drop", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchHIBPBreaches() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "CyberC2Dashboard-ThreatIntel" }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const breaches = await res.json();
    const db = await requireDb();
    const cutoff = /* @__PURE__ */ new Date();
    cutoff.setFullYear(cutoff.getFullYear() - 2);
    const recent = breaches.filter((b) => {
      const d = new Date(b.BreachDate || b.AddedDate);
      return d >= cutoff;
    }).slice(0, 300);
    const batch = recent.map((b) => ({
      ceSource: "hibp",
      ceBreachName: b.Name || b.Title,
      ceBreachDate: b.BreachDate ? new Date(b.BreachDate) : void 0,
      ceDomain: b.Domain,
      ceEmailCount: b.PwnCount || 0,
      ceTotalRecords: b.PwnCount || 0,
      ceDataClasses: b.DataClasses || [],
      ceSeverity: (b.PwnCount || 0) > 1e6 ? "critical" : (b.PwnCount || 0) > 1e5 ? "high" : "medium",
      ceIsVerified: b.IsVerified || false,
      ceIsSensitive: b.IsSensitive || false,
      ceIsRetired: b.IsRetired || false,
      ceIsSpamList: b.IsSpamList || false,
      ceDescription: `${b.Title || b.Name}: ${b.Description?.substring(0, 500) || "No description"} | Records: ${b.PwnCount?.toLocaleString() || "unknown"}`,
      ceTags: [...(b.DataClasses || []).slice(0, 10), "breach", "hibp"],
      ceRawData: b
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(credentialExposures).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("hibp_breaches", "active", batch.length);
    return { feed: "hibp_breaches", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("hibp_breaches", "down", 0, err.message).catch(() => {
    });
    return { feed: "hibp_breaches", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function runDarkwebFeedSync(feedNames) {
  if (darkwebSyncRunning) throw new Error("Darkweb feed sync is already running");
  darkwebSyncRunning = true;
  const startedAt = /* @__PURE__ */ new Date();
  try {
    console.log("[DarkwebOSINT] Starting feed sync...");
    const batch1 = await Promise.all([
      !feedNames || feedNames.includes("feodo_tracker") ? fetchFeodoTracker() : null,
      !feedNames || feedNames.includes("malwarebazaar") ? fetchMalwareBazaar() : null,
      !feedNames || feedNames.includes("ssl_blacklist") ? fetchSSLBlacklist() : null
    ]);
    const batch2 = await Promise.all([
      !feedNames || feedNames.includes("ransomware_live_victims") ? fetchRansomwareLiveVictims() : null,
      !feedNames || feedNames.includes("ransomware_live_groups") ? fetchRansomwareLiveGroups() : null,
      !feedNames || feedNames.includes("alienvault_otx") ? fetchAlienVaultOTX() : null
    ]);
    const batch3 = await Promise.all([
      !feedNames || feedNames.includes("openphish") ? fetchOpenPhish() : null,
      !feedNames || feedNames.includes("tor_exit_nodes") ? fetchTorExitNodes() : null,
      !feedNames || feedNames.includes("blocklist_de") ? fetchBlocklistDe() : null,
      !feedNames || feedNames.includes("spamhaus_drop") ? fetchSpamhausDrop() : null
    ]);
    const batch4 = await Promise.all([
      !feedNames || feedNames.includes("hibp_breaches") ? fetchHIBPBreaches() : null
    ]);
    const allResults = [...batch1, ...batch2, ...batch3, ...batch4].filter(Boolean);
    const completedAt = /* @__PURE__ */ new Date();
    const totalFetched = allResults.reduce((sum, r) => sum + r.fetched, 0);
    const totalErrors = allResults.filter((r) => r.error).length;
    console.log(`[DarkwebOSINT] Sync complete: ${totalFetched} records from ${allResults.length} feeds (${totalErrors} errors)`);
    allResults.forEach((r) => {
      console.log(`  - ${r.feed}: ${r.fetched} records (${r.durationMs}ms)${r.error ? ` ERROR: ${r.error}` : ""}`);
    });
    return { startedAt, completedAt, results: allResults, totalFetched, totalErrors };
  } finally {
    darkwebSyncRunning = false;
  }
}
function isDarkwebSyncRunning() {
  return darkwebSyncRunning;
}
async function getFeedHealthSummary() {
  const db = await requireDb();
  const feeds = await db.select().from(darkwebFeedRegistry).orderBy(darkwebFeedRegistry.dfrFeedName);
  return feeds.map((f) => ({
    name: f.dfrFeedName,
    type: f.dfrFeedType,
    provider: f.dfrProvider,
    status: f.dfrStatus,
    enabled: f.dfrEnabled,
    lastSync: f.dfrLastSyncAt,
    totalSyncs: f.dfrTotalSyncs,
    totalRecords: f.dfrTotalRecordsFetched,
    consecutiveFailures: f.dfrConsecutiveFailures,
    lastError: f.dfrLastError,
    requiresAuth: f.dfrRequiresAuth,
    authEnvVar: f.dfrAuthEnvVar
  }));
}
async function fetchIntelXForDomain(domain) {
  const start = Date.now();
  const apiKey = process.env.INTELX_API_KEY;
  if (!apiKey) return { feed: "intelx_search", fetched: 0, error: "No API key", durationMs: 0 };
  try {
    const searchRes = await safeFetch("https://2.intelx.io/intelligent/search", {
      method: "POST",
      headers: { "x-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        term: domain,
        buckets: ["pastes", "leaks", "darknet.tor"],
        maxresults: 100,
        timeout: 10,
        sort: 2
        // date descending
      })
    });
    if (!searchRes.ok) throw new Error(`HTTP ${searchRes.status}`);
    const searchData = await searchRes.json();
    const searchId = searchData.id;
    if (!searchId) return { feed: "intelx_search", fetched: 0, durationMs: Date.now() - start };
    await new Promise((r) => setTimeout(r, 3e3));
    const resultRes = await safeFetch(`https://2.intelx.io/intelligent/search/result?id=${searchId}&limit=100`, {
      headers: { "x-key": apiKey }
    });
    if (!resultRes.ok) throw new Error(`Result HTTP ${resultRes.status}`);
    const resultData = await resultRes.json();
    const records = Array.isArray(resultData.records) ? resultData.records : [];
    const db = await requireDb();
    let count = 0;
    const batch = [];
    for (const record of records.slice(0, 200)) {
      const bucket = record.bucket || "unknown";
      const isDarknet = bucket === "darknet.tor" || bucket === "darknet.i2p";
      batch.push({
        uieCategory: isDarknet ? "darkweb_mention" : "credential_leak",
        uieSource: "intelx",
        uieTitle: `IntelX: ${record.name || record.systemid || "unknown"} (${bucket})`,
        uieDescription: `Found in ${bucket}: ${record.name || ""} | Media: ${record.media || "unknown"} | Added: ${record.added || "unknown"}`,
        uieSeverity: isDarknet ? "high" : "medium",
        uieConfidence: 75,
        uieIocType: record.type === 2 ? "domain" : record.type === 3 ? "email" : "other",
        uieIocValue: domain,
        uieTags: [bucket, "intelx", domain].filter(Boolean),
        uieRawData: record,
        uieEventDate: record.added ? new Date(record.added) : /* @__PURE__ */ new Date()
      });
      count++;
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("intelx_search", "active", count);
    return { feed: "intelx_search", fetched: count, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("intelx_search", "down", 0, err.message).catch(() => {
    });
    return { feed: "intelx_search", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchHudsonRockForDomain(domain) {
  const start = Date.now();
  const apiKey = process.env.HUDSON_ROCK_API_KEY;
  if (!apiKey) return { feed: "hudson_rock", fetched: 0, error: "No API key", durationMs: 0 };
  try {
    const res = await safeFetch(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`,
      { headers: { "api-key": apiKey } }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const db = await requireDb();
    let count = 0;
    const batch = [];
    const stealers = Array.isArray(data.stealers) ? data.stealers : [];
    for (const stealer of stealers.slice(0, 200)) {
      batch.push({
        ceSource: "hudson_rock",
        ceBreachName: `Stealer: ${stealer.stealer_type || "unknown"}`,
        ceBreachDate: stealer.date_compromised ? new Date(stealer.date_compromised) : void 0,
        ceDomain: domain,
        ceEmailCount: 1,
        ceTotalRecords: 1,
        ceDataClasses: ["stealer_log", "credentials"],
        ceSeverity: "critical",
        ceIsVerified: true,
        ceDescription: `Hudson Rock stealer log: ${stealer.email || "unknown"} compromised via ${stealer.stealer_type || "unknown"} stealer`,
        ceTags: ["hudson_rock", "stealer_log", domain],
        ceRawData: stealer
      });
      count++;
    }
    const thirdParty = Array.isArray(data.third_party) ? data.third_party : [];
    for (const tp of thirdParty.slice(0, 100)) {
      batch.push({
        ceSource: "hudson_rock",
        ceBreachName: `Third-party: ${tp.origin || "unknown"}`,
        ceBreachDate: tp.date_compromised ? new Date(tp.date_compromised) : void 0,
        ceDomain: domain,
        ceEmailCount: 1,
        ceTotalRecords: 1,
        ceDataClasses: ["third_party_exposure", "credentials"],
        ceSeverity: "high",
        ceDescription: `Hudson Rock third-party exposure: ${tp.email || "unknown"} via ${tp.origin || "unknown"}`,
        ceTags: ["hudson_rock", "third_party", domain],
        ceRawData: tp
      });
      count++;
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(credentialExposures).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("hudson_rock", "active", count);
    return { feed: "hudson_rock", fetched: count, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("hudson_rock", "down", 0, err.message).catch(() => {
    });
    return { feed: "hudson_rock", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function fetchLeakCheckForDomain(domain) {
  const start = Date.now();
  const apiKey = process.env.LEAKCHECK_API_KEY;
  if (!apiKey) return { feed: "leakcheck", fetched: 0, error: "No API key", durationMs: 0 };
  try {
    const res = await safeFetch(
      `https://leakcheck.io/api/v2/query/${encodeURIComponent(domain)}?type=domain`,
      { headers: { "X-API-Key": apiKey } }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const db = await requireDb();
    let count = 0;
    const results = Array.isArray(data.result) ? data.result : [];
    const batch = [];
    for (const entry of results.slice(0, 300)) {
      const sources = Array.isArray(entry.sources) ? entry.sources : [];
      batch.push({
        ceSource: "leakcheck",
        ceBreachName: sources.join(", ") || "unknown",
        ceBreachDate: entry.last_breach ? new Date(entry.last_breach) : void 0,
        ceDomain: domain,
        ceEmailCount: 1,
        ceTotalRecords: 1,
        ceDataClasses: [
          "credential_leak",
          ...entry.has_password ? ["password"] : [],
          ...entry.has_hash ? ["password_hash"] : []
        ],
        ceSeverity: entry.has_password ? "critical" : entry.has_hash ? "high" : "medium",
        ceDescription: `LeakCheck: ${entry.email || entry.username || "unknown"} found in ${sources.join(", ") || "unknown breach"}`,
        ceTags: ["leakcheck", "credential_leak", domain],
        ceRawData: entry
      });
      count++;
    }
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(credentialExposures).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("leakcheck", "active", count);
    return { feed: "leakcheck", fetched: count, durationMs: Date.now() - start };
  } catch (err) {
    await updateFeedStatus("leakcheck", "down", 0, err.message).catch(() => {
    });
    return { feed: "leakcheck", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function runDomainDarkwebSync(domain) {
  const startedAt = /* @__PURE__ */ new Date();
  try {
    console.log(`[DarkwebOSINT] Starting domain-specific darkweb sync for ${domain}...`);
    const results = await Promise.all([
      fetchIntelXForDomain(domain),
      fetchHudsonRockForDomain(domain),
      fetchLeakCheckForDomain(domain)
    ]);
    const completedAt = /* @__PURE__ */ new Date();
    const totalFetched = results.reduce((sum, r) => sum + r.fetched, 0);
    const totalErrors = results.filter((r) => r.error).length;
    console.log(`[DarkwebOSINT] Domain sync complete for ${domain}: ${totalFetched} records from ${results.length} feeds (${totalErrors} errors)`);
    results.forEach((r) => {
      console.log(`  - ${r.feed}: ${r.fetched} records (${r.durationMs}ms)${r.error ? ` ERROR: ${r.error}` : ""}`);
    });
    return { startedAt, completedAt, results, totalFetched, totalErrors };
  } catch (err) {
    console.error(`[DarkwebOSINT] Domain sync failed for ${domain}:`, err.message);
    return { startedAt, completedAt: /* @__PURE__ */ new Date(), results: [], totalFetched: 0, totalErrors: 1 };
  }
}
var BUILT_IN_FEEDS, darkwebSyncRunning;
var init_darkweb_osint_service = __esm({
  "server/lib/darkweb-osint-service.ts"() {
    init_db();
    init_schema();
    BUILT_IN_FEEDS = [
      { dfrFeedName: "abusech_urlhaus", dfrFeedUrl: "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", dfrFeedType: "ioc", dfrProvider: "abuse.ch", dfrDescription: "Malicious URL feed from URLhaus", dfrRequiresAuth: 0, dfrAuthType: "api_key", dfrAuthEnvVar: "ABUSECH_API_KEY", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "abusech_threatfox", dfrFeedUrl: "https://threatfox-api.abuse.ch/api/v1/", dfrFeedType: "ioc", dfrProvider: "abuse.ch", dfrDescription: "IOCs from malware campaigns via ThreatFox", dfrRequiresAuth: 0, dfrAuthType: "api_key", dfrAuthEnvVar: "ABUSECH_API_KEY", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "abusech_feodo", dfrFeedUrl: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", dfrFeedType: "c2", dfrProvider: "abuse.ch", dfrDescription: "Feodo Tracker \u2014 botnet C2 IP blocklist", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "abusech_malwarebazaar", dfrFeedUrl: "https://mb-api.abuse.ch/api/v1/", dfrFeedType: "malware", dfrProvider: "abuse.ch", dfrDescription: "MalwareBazaar \u2014 recent malware samples", dfrRequiresAuth: 0, dfrAuthType: "api_key", dfrAuthEnvVar: "ABUSECH_API_KEY", dfrSyncInterval: "12h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "abusech_sslbl", dfrFeedUrl: "https://sslbl.abuse.ch/blacklist/sslblacklist.json", dfrFeedType: "c2", dfrProvider: "abuse.ch", dfrDescription: "SSL Blacklist \u2014 malicious SSL certificates", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "ransomware_live_victims", dfrFeedUrl: "https://api.ransomware.live/v2/victims", dfrFeedType: "ransomware", dfrProvider: "ransomware.live", dfrDescription: "Ransomware victim reports from leak sites", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "ransomware_live_groups", dfrFeedUrl: "https://api.ransomware.live/v2/groups", dfrFeedType: "ransomware", dfrProvider: "ransomware.live", dfrDescription: "Ransomware group profiles and activity", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "alienvault_otx", dfrFeedUrl: "https://otx.alienvault.com/api/v1/pulses/subscribed", dfrFeedType: "ioc", dfrProvider: "AlienVault", dfrDescription: "Community threat intel pulses from OTX", dfrRequiresAuth: 1, dfrAuthType: "api_key", dfrAuthEnvVar: "OTX_API_KEY", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "openphish", dfrFeedUrl: "https://openphish.com/feed.txt", dfrFeedType: "phishing", dfrProvider: "OpenPhish", dfrDescription: "Community phishing URL feed", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "tor_exit_nodes", dfrFeedUrl: "https://check.torproject.org/torbulkexitlist", dfrFeedType: "blocklist", dfrProvider: "TorProject", dfrDescription: "Tor exit node IP list", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "blocklist_de", dfrFeedUrl: "https://api.blocklist.de/getlast.php?time=86400", dfrFeedType: "blocklist", dfrProvider: "blocklist.de", dfrDescription: "Attack IPs from last 24h", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "spamhaus_drop", dfrFeedUrl: "https://www.spamhaus.org/drop/drop.json", dfrFeedType: "blocklist", dfrProvider: "Spamhaus", dfrDescription: "Don't Route Or Peer \u2014 hijacked IP ranges", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "hibp_breaches", dfrFeedUrl: "https://haveibeenpwned.com/api/v3/breaches", dfrFeedType: "credential", dfrProvider: "HIBP", dfrDescription: "Have I Been Pwned breach catalog", dfrRequiresAuth: 0, dfrAuthType: "none", dfrSyncInterval: "daily", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      // --- New darkweb intelligence sources (OSINT Pipeline Expansion) ---
      { dfrFeedName: "intelx_search", dfrFeedUrl: "https://2.intelx.io/intelligent/search", dfrFeedType: "credential", dfrProvider: "Intelligence X", dfrDescription: "Intelligence X \u2014 darkweb/paste/leak search for breached credentials and stealer logs", dfrRequiresAuth: 1, dfrAuthType: "api_key", dfrAuthEnvVar: "INTELX_API_KEY", dfrSyncInterval: "6h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "hudson_rock", dfrFeedUrl: "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain", dfrFeedType: "credential", dfrProvider: "Hudson Rock", dfrDescription: "Hudson Rock Cavalier \u2014 stealer log exposure and compromised employee detection", dfrRequiresAuth: 1, dfrAuthType: "api_key", dfrAuthEnvVar: "HUDSON_ROCK_API_KEY", dfrSyncInterval: "12h", dfrIsBuiltIn: 1, dfrEnabled: 1 },
      { dfrFeedName: "leakcheck", dfrFeedUrl: "https://leakcheck.io/api/v2/query", dfrFeedType: "credential", dfrProvider: "LeakCheck", dfrDescription: "LeakCheck \u2014 credential leak search across breach databases", dfrRequiresAuth: 1, dfrAuthType: "api_key", dfrAuthEnvVar: "LEAKCHECK_API_KEY", dfrSyncInterval: "12h", dfrIsBuiltIn: 1, dfrEnabled: 1 }
    ];
    darkwebSyncRunning = false;
  }
});

export {
  initFeedRegistry,
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
  runDarkwebFeedSync,
  isDarkwebSyncRunning,
  getFeedHealthSummary,
  fetchIntelXForDomain,
  fetchHudsonRockForDomain,
  fetchLeakCheckForDomain,
  runDomainDarkwebSync,
  init_darkweb_osint_service
};
