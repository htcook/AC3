/**
 * Darkweb OSINT Feed Service
 *
 * Self-contained feed ingestion from clearnet threat intelligence APIs:
 *   - abuse.ch: URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, SSL Blacklist
 *   - ransomware.live: Groups, Victims, IOCs, Negotiations, YARA
 *   - AlienVault OTX: Community threat intel pulses
 *   - OpenPhish: Phishing URL feed
 *   - Tor Exit Nodes: TorProject bulk exit list
 *   - Blocklist.de: Attack IP blocklists
 *   - Spamhaus DROP: Hijacked IP ranges
 *   - HIBP Breaches: Breach catalog (public endpoint)
 *
 * All feeds are clearnet — no Tor router required.
 */

import { getDb } from "../db";
import {
  undergroundIntelEvents,
  networkEvents,
  credentialExposures,
  darkwebFeedRegistry,
  type InsertUndergroundIntelEvent,
  type InsertNetworkEvent,
  type InsertCredentialExposure,
  type InsertDarkwebFeedRegistry,
} from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";

// ─── Helpers ─────────────────────────────────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

interface FeedResult {
  feed: string;
  fetched: number;
  error?: string;
  durationMs: number;
}

async function safeFetch(url: string, opts?: RequestInit, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

function abusechHeaders(): Record<string, string> {
  const key = process.env.ABUSECH_API_KEY || "";
  const h: Record<string, string> = {};
  if (key) h["Auth-Key"] = key;
  return h;
}

// ─── Feed Registry Management ────────────────────────────────────────────

const BUILT_IN_FEEDS: Omit<InsertDarkwebFeedRegistry, "id">[] = [
  { feedName: "abusech_urlhaus", feedUrl: "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", feedType: "ioc", provider: "abuse.ch", description: "Malicious URL feed from URLhaus", requiresAuth: false, authType: "api_key", authEnvVar: "ABUSECH_API_KEY", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "abusech_threatfox", feedUrl: "https://threatfox-api.abuse.ch/api/v1/", feedType: "ioc", provider: "abuse.ch", description: "IOCs from malware campaigns via ThreatFox", requiresAuth: false, authType: "api_key", authEnvVar: "ABUSECH_API_KEY", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "abusech_feodo", feedUrl: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", feedType: "c2", provider: "abuse.ch", description: "Feodo Tracker — botnet C2 IP blocklist", requiresAuth: false, authType: "none", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "abusech_malwarebazaar", feedUrl: "https://mb-api.abuse.ch/api/v1/", feedType: "malware", provider: "abuse.ch", description: "MalwareBazaar — recent malware samples", requiresAuth: false, authType: "api_key", authEnvVar: "ABUSECH_API_KEY", syncInterval: "12h", isBuiltIn: true, enabled: true },
  { feedName: "abusech_sslbl", feedUrl: "https://sslbl.abuse.ch/blacklist/sslblacklist.json", feedType: "c2", provider: "abuse.ch", description: "SSL Blacklist — malicious SSL certificates", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  { feedName: "ransomware_live_victims", feedUrl: "https://api.ransomware.live/v2/victims", feedType: "ransomware", provider: "ransomware.live", description: "Ransomware victim reports from leak sites", requiresAuth: false, authType: "none", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "ransomware_live_groups", feedUrl: "https://api.ransomware.live/v2/groups", feedType: "ransomware", provider: "ransomware.live", description: "Ransomware group profiles and activity", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  { feedName: "alienvault_otx", feedUrl: "https://otx.alienvault.com/api/v1/pulses/subscribed", feedType: "ioc", provider: "AlienVault", description: "Community threat intel pulses from OTX", requiresAuth: true, authType: "api_key", authEnvVar: "OTX_API_KEY", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "openphish", feedUrl: "https://openphish.com/feed.txt", feedType: "phishing", provider: "OpenPhish", description: "Community phishing URL feed", requiresAuth: false, authType: "none", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "tor_exit_nodes", feedUrl: "https://check.torproject.org/torbulkexitlist", feedType: "blocklist", provider: "TorProject", description: "Tor exit node IP list", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  { feedName: "blocklist_de", feedUrl: "https://api.blocklist.de/getlast.php?time=86400", feedType: "blocklist", provider: "blocklist.de", description: "Attack IPs from last 24h", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  { feedName: "spamhaus_drop", feedUrl: "https://www.spamhaus.org/drop/drop.json", feedType: "blocklist", provider: "Spamhaus", description: "Don't Route Or Peer — hijacked IP ranges", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  { feedName: "hibp_breaches", feedUrl: "https://haveibeenpwned.com/api/v3/breaches", feedType: "credential", provider: "HIBP", description: "Have I Been Pwned breach catalog", requiresAuth: false, authType: "none", syncInterval: "daily", isBuiltIn: true, enabled: true },
  // --- New darkweb intelligence sources (OSINT Pipeline Expansion) ---
  { feedName: "intelx_search", feedUrl: "https://2.intelx.io/intelligent/search", feedType: "credential", provider: "Intelligence X", description: "Intelligence X — darkweb/paste/leak search for breached credentials and stealer logs", requiresAuth: true, authType: "api_key", authEnvVar: "INTELX_API_KEY", syncInterval: "6h", isBuiltIn: true, enabled: true },
  { feedName: "hudson_rock", feedUrl: "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain", feedType: "credential", provider: "Hudson Rock", description: "Hudson Rock Cavalier — stealer log exposure and compromised employee detection", requiresAuth: true, authType: "api_key", authEnvVar: "HUDSON_ROCK_API_KEY", syncInterval: "12h", isBuiltIn: true, enabled: true },
  { feedName: "leakcheck", feedUrl: "https://leakcheck.io/api/v2/query", feedType: "credential", provider: "LeakCheck", description: "LeakCheck — credential leak search across breach databases", requiresAuth: true, authType: "api_key", authEnvVar: "LEAKCHECK_API_KEY", syncInterval: "12h", isBuiltIn: true, enabled: true },
];

export async function initFeedRegistry(): Promise<void> {
  const db = await requireDb();
  for (const feed of BUILT_IN_FEEDS) {
    try {
      await db.insert(darkwebFeedRegistry).values(feed as any)
        .onDuplicateKeyUpdate({ set: { feedUrl: feed.feedUrl, description: feed.description } });
    } catch {
      // ignore duplicate key errors
    }
  }
  console.log(`[DarkwebOSINT] Feed registry initialized with ${BUILT_IN_FEEDS.length} built-in feeds`);
}

async function updateFeedStatus(feedName: string, status: "active" | "degraded" | "down", fetched: number, error?: string) {
  const db = await requireDb();
  const updates: any = {
    status,
    lastSyncAt: new Date(),
    totalSyncs: sql`dfr_total_syncs + 1`,
    totalRecordsFetched: sql`dfr_total_records_fetched + ${fetched}`,
  };
  if (error) {
    updates.lastError = error;
    updates.consecutiveFailures = sql`dfr_consecutive_failures + 1`;
  } else {
    updates.lastError = null;
    updates.consecutiveFailures = 0;
  }
  await db.update(darkwebFeedRegistry).set(updates).where(eq(darkwebFeedRegistry.feedName, feedName));
}

// ─── abuse.ch Feodo Tracker ──────────────────────────────────────────────

export async function fetchFeodoTracker(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any[];
    const db = await requireDb();
    let count = 0;
    const batch: InsertNetworkEvent[] = [];
    for (const entry of (data || []).slice(0, 500)) {
      batch.push({
        eventType: "c2_server",
        source: "feodo_tracker",
        ipAddress: entry.ip_address || entry.dst_ip,
        port: entry.dst_port || entry.port,
        hostname: entry.hostname,
        protocol: "tcp",
        malwareFamily: entry.malware || "unknown",
        description: `Feodo C2: ${entry.malware || "unknown"} at ${entry.ip_address || entry.dst_ip}:${entry.dst_port || entry.port}`,
        severity: "high",
        confidence: 90,
        country: entry.country,
        asn: entry.as_number ? String(entry.as_number) : undefined,
        asnOrg: entry.as_name,
        status: entry.status === "online" ? "active" : "inactive",
        firstSeen: entry.first_seen ? new Date(entry.first_seen) : undefined,
        lastSeen: entry.last_online ? new Date(entry.last_online) : undefined,
        tags: [entry.malware, "c2", "botnet"].filter(Boolean),
        rawData: entry,
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
  } catch (err: any) {
    await updateFeedStatus("abusech_feodo", "down", 0, err.message).catch(() => {});
    return { feed: "feodo_tracker", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── abuse.ch MalwareBazaar ──────────────────────────────────────────────

export async function fetchMalwareBazaar(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", ...abusechHeaders() };
    const res = await safeFetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: "query=get_recent&selector=100",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    const samples = Array.isArray(data.data) ? data.data.slice(0, 200) : [];
    const db = await requireDb();
    const batch: InsertUndergroundIntelEvent[] = samples.map((s: any) => ({
      category: "malware" as const,
      source: "malwarebazaar",
      title: `${s.signature || s.file_type || "Unknown"} sample: ${s.sha256_hash?.substring(0, 16)}...`,
      description: `Malware sample: ${s.file_name || "unknown"} | Type: ${s.file_type} | Signature: ${s.signature || "none"} | SHA256: ${s.sha256_hash}`,
      severity: (s.intelligence?.clamav || []).length > 0 ? "high" as const : "medium" as const,
      confidence: 85,
      iocType: "hash",
      iocValue: s.sha256_hash,
      actorName: s.signature || undefined,
      tags: [...(s.tags || []), s.file_type, "malware"].filter(Boolean),
      rawData: s,
      eventDate: s.first_seen ? new Date(s.first_seen) : new Date(),
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("abusech_malwarebazaar", "active", batch.length);
    return { feed: "malwarebazaar", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("abusech_malwarebazaar", "down", 0, err.message).catch(() => {});
    return { feed: "malwarebazaar", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── abuse.ch SSL Blacklist ──────────────────────────────────────────────

export async function fetchSSLBlacklist(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://sslbl.abuse.ch/blacklist/sslblacklist.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any[];
    const db = await requireDb();
    const entries = (data || []).slice(0, 300);
    const batch: InsertNetworkEvent[] = entries.map((e: any) => ({
      eventType: "ssl_blacklist" as const,
      source: "sslbl_abusech",
      ipAddress: e.dst_ip,
      port: e.dst_port,
      hostname: e.listing_reason,
      malwareFamily: e.listing_reason || "unknown",
      description: `SSL Blacklist: ${e.listing_reason || "malicious cert"} at ${e.dst_ip}:${e.dst_port} | SHA1: ${e.sha1}`,
      severity: "high" as const,
      confidence: 85,
      status: "active" as const,
      firstSeen: e.listing_date ? new Date(e.listing_date) : undefined,
      tags: ["ssl", "malicious_cert", e.listing_reason].filter(Boolean),
      rawData: e,
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("abusech_sslbl", "active", batch.length);
    return { feed: "ssl_blacklist", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("abusech_sslbl", "down", 0, err.message).catch(() => {});
    return { feed: "ssl_blacklist", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── ransomware.live Victims ─────────────────────────────────────────────

export async function fetchRansomwareLiveVictims(): Promise<FeedResult> {
  const start = Date.now();
  try {
    // Use the v2 free API (no auth, rate limited)
    const res = await safeFetch("https://api.ransomware.live/v2/victims", {}, 60000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const victims = (await res.json()) as any[];
    const db = await requireDb();
    // Take only the most recent 200 victims
    const recent = victims.slice(0, 200);
    const batch: InsertUndergroundIntelEvent[] = recent.map((v: any) => ({
      category: "ransomware" as const,
      source: "ransomware_live",
      sourceUrl: v.post_url || v.website,
      title: `${v.group_name || "Unknown"} → ${v.victim || "Unknown victim"}`,
      description: `Ransomware victim: ${v.victim} | Group: ${v.group_name} | Country: ${v.country || "unknown"} | Sector: ${v.activity || "unknown"} | Published: ${v.published}`,
      severity: "critical" as const,
      confidence: 85,
      actorName: v.group_name,
      victimName: v.victim,
      victimSector: v.activity,
      victimCountry: v.country,
      tags: [v.group_name, "ransomware", "leak_site", v.activity].filter(Boolean),
      rawData: v,
      eventDate: v.published ? new Date(v.published) : v.discovered ? new Date(v.discovered) : new Date(),
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("ransomware_live_victims", "active", batch.length);
    return { feed: "ransomware_live_victims", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("ransomware_live_victims", "down", 0, err.message).catch(() => {});
    return { feed: "ransomware_live_victims", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── ransomware.live Groups ──────────────────────────────────────────────

export async function fetchRansomwareLiveGroups(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://api.ransomware.live/v2/groups", {}, 60000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const groups = (await res.json()) as any[];
    const db = await requireDb();
    const batch: InsertUndergroundIntelEvent[] = groups.map((g: any) => ({
      category: "ransomware" as const,
      source: "ransomware_live_groups",
      sourceUrl: g.url,
      title: `Group profile: ${g.name}`,
      description: `Ransomware group: ${g.name} | Locations: ${JSON.stringify(g.locations || [])} | Profile: ${g.description?.substring(0, 500) || "No description"}`,
      severity: "high" as const,
      confidence: 90,
      actorName: g.name,
      tags: ["ransomware_group", "profile", ...(g.locations || [])].filter(Boolean),
      rawData: g,
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("ransomware_live_groups", "active", batch.length);
    return { feed: "ransomware_live_groups", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("ransomware_live_groups", "down", 0, err.message).catch(() => {});
    return { feed: "ransomware_live_groups", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── AlienVault OTX ──────────────────────────────────────────────────────

export async function fetchAlienVaultOTX(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) {
      return { feed: "alienvault_otx", fetched: 0, error: "OTX_API_KEY not set — register free at otx.alienvault.com", durationMs: Date.now() - start };
    }
    const res = await safeFetch("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=7d", {
      headers: { "X-OTX-API-KEY": apiKey },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    const pulses = data.results || [];
    const db = await requireDb();
    const batch: InsertUndergroundIntelEvent[] = [];
    for (const pulse of pulses) {
      const indicators = pulse.indicators || [];
      // Create one event per pulse
      batch.push({
        category: "malware" as const,
        source: "alienvault_otx",
        sourceUrl: `https://otx.alienvault.com/pulse/${pulse.id}`,
        title: pulse.name || "OTX Pulse",
        description: `${pulse.description?.substring(0, 1000) || "No description"} | Indicators: ${indicators.length} | TLP: ${pulse.TLP || "white"}`,
        severity: indicators.length > 20 ? "high" as const : "medium" as const,
        confidence: 75,
        actorName: pulse.adversary || undefined,
        mitreTechniques: pulse.attack_ids?.map((a: any) => a.id) || [],
        tags: [...(pulse.tags || []), "otx", pulse.adversary].filter(Boolean),
        rawData: { ...pulse, indicators: indicators.slice(0, 50) },
        eventDate: pulse.modified ? new Date(pulse.modified) : new Date(),
      });
      // Also create individual IOC events for high-value indicators
      for (const ind of indicators.slice(0, 10)) {
        batch.push({
          category: "malware" as const,
          source: "alienvault_otx",
          title: `OTX IOC: ${ind.indicator?.substring(0, 80)}`,
          description: `Type: ${ind.type} | Indicator: ${ind.indicator} | Pulse: ${pulse.name}`,
          severity: "medium" as const,
          confidence: 70,
          iocType: ind.type?.includes("IPv") ? "ip" : ind.type?.includes("domain") ? "domain" : ind.type?.includes("URL") ? "url" : "hash",
          iocValue: ind.indicator,
          tags: ["otx", "ioc", ind.type].filter(Boolean),
          rawData: ind,
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
  } catch (err: any) {
    await updateFeedStatus("alienvault_otx", "down", 0, err.message).catch(() => {});
    return { feed: "alienvault_otx", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── OpenPhish ───────────────────────────────────────────────────────────

export async function fetchOpenPhish(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://openphish.com/feed.txt");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const urls = text.split("\n").filter((l) => l.trim().startsWith("http")).slice(0, 200);
    const db = await requireDb();
    const batch: InsertUndergroundIntelEvent[] = urls.map((url) => {
      let domain = "";
      try { domain = new URL(url).hostname; } catch { domain = url; }
      return {
        category: "phishing" as const,
        source: "openphish",
        sourceUrl: url,
        title: `Phishing URL: ${domain}`,
        description: `Phishing URL detected: ${url}`,
        severity: "high" as const,
        confidence: 80,
        iocType: "url",
        iocValue: url,
        tags: ["phishing", "url", domain],
        rawData: { url, domain },
      };
    });
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(undergroundIntelEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("openphish", "active", batch.length);
    return { feed: "openphish", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("openphish", "down", 0, err.message).catch(() => {});
    return { feed: "openphish", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Tor Exit Nodes ──────────────────────────────────────────────────────

export async function fetchTorExitNodes(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://check.torproject.org/torbulkexitlist");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const ips = text.split("\n").filter((l) => l.trim() && !l.startsWith("#")).slice(0, 500);
    const db = await requireDb();
    const batch: InsertNetworkEvent[] = ips.map((ip) => ({
      eventType: "tor_exit_node" as const,
      source: "torproject",
      ipAddress: ip.trim(),
      description: `Tor exit node: ${ip.trim()}`,
      severity: "info" as const,
      confidence: 95,
      status: "active" as const,
      tags: ["tor", "exit_node", "anonymization"],
      rawData: { ip: ip.trim() },
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("tor_exit_nodes", "active", batch.length);
    return { feed: "tor_exit_nodes", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("tor_exit_nodes", "down", 0, err.message).catch(() => {});
    return { feed: "tor_exit_nodes", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Blocklist.de ────────────────────────────────────────────────────────

export async function fetchBlocklistDe(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://api.blocklist.de/getlast.php?time=86400");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const ips = text.split("\n").filter((l) => l.trim() && !l.startsWith("#")).slice(0, 300);
    const db = await requireDb();
    const batch: InsertNetworkEvent[] = ips.map((ip) => ({
      eventType: "malicious_ip" as const,
      source: "blocklist_de",
      ipAddress: ip.trim(),
      description: `Attack IP (last 24h): ${ip.trim()}`,
      severity: "medium" as const,
      confidence: 70,
      status: "active" as const,
      tags: ["blocklist", "attack_ip"],
      rawData: { ip: ip.trim() },
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("blocklist_de", "active", batch.length);
    return { feed: "blocklist_de", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("blocklist_de", "down", 0, err.message).catch(() => {});
    return { feed: "blocklist_de", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Spamhaus DROP ───────────────────────────────────────────────────────

export async function fetchSpamhausDrop(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://www.spamhaus.org/drop/drop.txt");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith(";")).slice(0, 200);
    const db = await requireDb();
    const batch: InsertNetworkEvent[] = lines.map((line) => {
      const [cidr, sbl] = line.split(";").map((s) => s.trim());
      return {
        eventType: "malicious_ip" as const,
        source: "spamhaus_drop",
        ipAddress: cidr,
        description: `Spamhaus DROP: ${cidr} (SBL: ${sbl || "unknown"}) — hijacked/leased IP range`,
        severity: "high" as const,
        confidence: 95,
        status: "active" as const,
        tags: ["spamhaus", "drop", "hijacked_ip", "bgp"],
        rawData: { cidr, sbl },
      };
    });
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(networkEvents).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("spamhaus_drop", "active", batch.length);
    return { feed: "spamhaus_drop", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("spamhaus_drop", "down", 0, err.message).catch(() => {});
    return { feed: "spamhaus_drop", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── HIBP Breaches (public catalog) ──────────────────────────────────────

export async function fetchHIBPBreaches(): Promise<FeedResult> {
  const start = Date.now();
  try {
    const res = await safeFetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "CyberC2Dashboard-ThreatIntel" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const breaches = (await res.json()) as any[];
    const db = await requireDb();
    // Only insert recent breaches (last 2 years)
    const cutoff = new Date();
    cutoff.setFullYear(cutoff.getFullYear() - 2);
    const recent = breaches.filter((b) => {
      const d = new Date(b.BreachDate || b.AddedDate);
      return d >= cutoff;
    }).slice(0, 300);
    const batch: InsertCredentialExposure[] = recent.map((b: any) => ({
      source: "hibp",
      breachName: b.Name || b.Title,
      breachDate: b.BreachDate ? new Date(b.BreachDate) : undefined,
      domain: b.Domain,
      emailCount: b.PwnCount || 0,
      totalRecords: b.PwnCount || 0,
      dataClasses: b.DataClasses || [],
      severity: (b.PwnCount || 0) > 1000000 ? "critical" as const : (b.PwnCount || 0) > 100000 ? "high" as const : "medium" as const,
      isVerified: b.IsVerified || false,
      isSensitive: b.IsSensitive || false,
      isRetired: b.IsRetired || false,
      isSpamList: b.IsSpamList || false,
      description: `${b.Title || b.Name}: ${b.Description?.substring(0, 500) || "No description"} | Records: ${b.PwnCount?.toLocaleString() || "unknown"}`,
      tags: [...(b.DataClasses || []).slice(0, 10), "breach", "hibp"],
      rawData: b,
    }));
    if (batch.length > 0) {
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(credentialExposures).values(batch.slice(i, i + 50));
      }
    }
    await updateFeedStatus("hibp_breaches", "active", batch.length);
    return { feed: "hibp_breaches", fetched: batch.length, durationMs: Date.now() - start };
  } catch (err: any) {
    await updateFeedStatus("hibp_breaches", "down", 0, err.message).catch(() => {});
    return { feed: "hibp_breaches", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Unified Sync Orchestrator ───────────────────────────────────────────

let darkwebSyncRunning = false;

export interface DarkwebSyncResult {
  startedAt: Date;
  completedAt: Date;
  results: FeedResult[];
  totalFetched: number;
  totalErrors: number;
}

/**
 * Run a full darkweb feed sync across all enabled feeds.
 * Feeds run in parallel batches to avoid overwhelming APIs.
 */
export async function runDarkwebFeedSync(feedNames?: string[]): Promise<DarkwebSyncResult> {
  if (darkwebSyncRunning) throw new Error("Darkweb feed sync is already running");
  darkwebSyncRunning = true;
  const startedAt = new Date();

  try {
    console.log("[DarkwebOSINT] Starting feed sync...");

    // Batch 1: abuse.ch feeds (they share rate limits)
    const batch1 = await Promise.all([
      (!feedNames || feedNames.includes("feodo_tracker")) ? fetchFeodoTracker() : null,
      (!feedNames || feedNames.includes("malwarebazaar")) ? fetchMalwareBazaar() : null,
      (!feedNames || feedNames.includes("ssl_blacklist")) ? fetchSSLBlacklist() : null,
    ]);

    // Batch 2: ransomware + community feeds
    const batch2 = await Promise.all([
      (!feedNames || feedNames.includes("ransomware_live_victims")) ? fetchRansomwareLiveVictims() : null,
      (!feedNames || feedNames.includes("ransomware_live_groups")) ? fetchRansomwareLiveGroups() : null,
      (!feedNames || feedNames.includes("alienvault_otx")) ? fetchAlienVaultOTX() : null,
    ]);

    // Batch 3: blocklists + phishing
    const batch3 = await Promise.all([
      (!feedNames || feedNames.includes("openphish")) ? fetchOpenPhish() : null,
      (!feedNames || feedNames.includes("tor_exit_nodes")) ? fetchTorExitNodes() : null,
      (!feedNames || feedNames.includes("blocklist_de")) ? fetchBlocklistDe() : null,
      (!feedNames || feedNames.includes("spamhaus_drop")) ? fetchSpamhausDrop() : null,
    ]);

    // Batch 4: credential feeds
    const batch4 = await Promise.all([
      (!feedNames || feedNames.includes("hibp_breaches")) ? fetchHIBPBreaches() : null,
    ]);

    const allResults = [...batch1, ...batch2, ...batch3, ...batch4].filter(Boolean) as FeedResult[];
    const completedAt = new Date();
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

export function isDarkwebSyncRunning(): boolean {
  return darkwebSyncRunning;
}

// ─── Feed Health Summary ─────────────────────────────────────────────────

export async function getFeedHealthSummary() {
  const db = await requireDb();
  const feeds = await db.select().from(darkwebFeedRegistry).orderBy(darkwebFeedRegistry.feedName);
  return feeds.map((f) => ({
    name: f.feedName,
    type: f.feedType,
    provider: f.provider,
    status: f.status,
    enabled: f.enabled,
    lastSync: f.lastSyncAt,
    totalSyncs: f.totalSyncs,
    totalRecords: f.totalRecordsFetched,
    consecutiveFailures: f.consecutiveFailures,
    lastError: f.lastError,
    requiresAuth: f.requiresAuth,
    authEnvVar: f.authEnvVar,
  }));
}


// ─── Intelligence X — Domain-specific darkweb/paste/leak search ─────────

export async function fetchIntelXForDomain(domain: string): Promise<FeedResult> {
  const start = Date.now();
  const apiKey = process.env.INTELX_API_KEY;
  if (!apiKey) return { feed: "intelx_search", fetched: 0, error: "No API key", durationMs: 0 };

  try {
    // Start search
    const searchRes = await safeFetch("https://2.intelx.io/intelligent/search", {
      method: "POST",
      headers: { "x-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        term: domain,
        buckets: ["pastes", "leaks", "darknet.tor"],
        maxresults: 100,
        timeout: 10,
        sort: 2, // date descending
      }),
    });
    if (!searchRes.ok) throw new Error(`HTTP ${searchRes.status}`);
    const searchData = (await searchRes.json()) as any;
    const searchId = searchData.id;
    if (!searchId) return { feed: "intelx_search", fetched: 0, durationMs: Date.now() - start };

    // Wait briefly then fetch results
    await new Promise(r => setTimeout(r, 3000));
    const resultRes = await safeFetch(`https://2.intelx.io/intelligent/search/result?id=${searchId}&limit=100`, {
      headers: { "x-key": apiKey },
    });
    if (!resultRes.ok) throw new Error(`Result HTTP ${resultRes.status}`);
    const resultData = (await resultRes.json()) as any;
    const records = Array.isArray(resultData.records) ? resultData.records : [];

    const db = await requireDb();
    let count = 0;
    const batch: InsertUndergroundIntelEvent[] = [];

    for (const record of records.slice(0, 200)) {
      const bucket = record.bucket || "unknown";
      const isDarknet = bucket === "darknet.tor" || bucket === "darknet.i2p";
      batch.push({
        category: isDarknet ? "darkweb_mention" as any : "credential_leak" as any,
        source: "intelx",
        title: `IntelX: ${record.name || record.systemid || "unknown"} (${bucket})`,
        description: `Found in ${bucket}: ${record.name || ""} | Media: ${record.media || "unknown"} | Added: ${record.added || "unknown"}`,
        severity: isDarknet ? "high" as const : "medium" as const,
        confidence: 75,
        iocType: record.type === 2 ? "domain" : record.type === 3 ? "email" : "other",
        iocValue: domain,
        tags: [bucket, "intelx", domain].filter(Boolean),
        rawData: record,
        eventDate: record.added ? new Date(record.added) : new Date(),
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
  } catch (err: any) {
    await updateFeedStatus("intelx_search", "down", 0, err.message).catch(() => {});
    return { feed: "intelx_search", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Hudson Rock — Stealer log exposure for domain ──────────────────────

export async function fetchHudsonRockForDomain(domain: string): Promise<FeedResult> {
  const start = Date.now();
  const apiKey = process.env.HUDSON_ROCK_API_KEY;
  if (!apiKey) return { feed: "hudson_rock", fetched: 0, error: "No API key", durationMs: 0 };

  try {
    const res = await safeFetch(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`,
      { headers: { "api-key": apiKey } }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;

    const db = await requireDb();
    let count = 0;
    const batch: InsertCredentialExposure[] = [];

    // Process stealers (compromised employees)
    const stealers = Array.isArray(data.stealers) ? data.stealers : [];
    for (const stealer of stealers.slice(0, 200)) {
      batch.push({
        source: "hudson_rock",
        breachName: `Stealer: ${stealer.stealer_type || "unknown"}`,
        breachDate: stealer.date_compromised ? new Date(stealer.date_compromised) : undefined,
        domain,
        emailCount: 1,
        totalRecords: 1,
        dataClasses: ["stealer_log", "credentials"],
        severity: "critical" as const,
        isVerified: true,
        description: `Hudson Rock stealer log: ${stealer.email || "unknown"} compromised via ${stealer.stealer_type || "unknown"} stealer`,
        tags: ["hudson_rock", "stealer_log", domain],
        rawData: stealer,
      });
      count++;
    }

    // Process third-party exposures
    const thirdParty = Array.isArray(data.third_party) ? data.third_party : [];
    for (const tp of thirdParty.slice(0, 100)) {
      batch.push({
        source: "hudson_rock",
        breachName: `Third-party: ${tp.origin || "unknown"}`,
        breachDate: tp.date_compromised ? new Date(tp.date_compromised) : undefined,
        domain,
        emailCount: 1,
        totalRecords: 1,
        dataClasses: ["third_party_exposure", "credentials"],
        severity: "high" as const,
        description: `Hudson Rock third-party exposure: ${tp.email || "unknown"} via ${tp.origin || "unknown"}`,
        tags: ["hudson_rock", "third_party", domain],
        rawData: tp,
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
  } catch (err: any) {
    await updateFeedStatus("hudson_rock", "down", 0, err.message).catch(() => {});
    return { feed: "hudson_rock", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── LeakCheck — Credential leak search ─────────────────────────────────

export async function fetchLeakCheckForDomain(domain: string): Promise<FeedResult> {
  const start = Date.now();
  const apiKey = process.env.LEAKCHECK_API_KEY;
  if (!apiKey) return { feed: "leakcheck", fetched: 0, error: "No API key", durationMs: 0 };

  try {
    const res = await safeFetch(
      `https://leakcheck.io/api/v2/query/${encodeURIComponent(domain)}?type=domain`,
      { headers: { "X-API-Key": apiKey } }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;

    const db = await requireDb();
    let count = 0;
    const results = Array.isArray(data.result) ? data.result : [];
    const batch: InsertCredentialExposure[] = [];

    for (const entry of results.slice(0, 300)) {
      const sources = Array.isArray(entry.sources) ? entry.sources : [];
      batch.push({
        source: "leakcheck",
        breachName: sources.join(", ") || "unknown",
        breachDate: entry.last_breach ? new Date(entry.last_breach) : undefined,
        domain,
        emailCount: 1,
        totalRecords: 1,
        dataClasses: [
          "credential_leak",
          ...(entry.has_password ? ["password"] : []),
          ...(entry.has_hash ? ["password_hash"] : []),
        ],
        severity: (entry.has_password ? "critical" : entry.has_hash ? "high" : "medium") as any,
        description: `LeakCheck: ${entry.email || entry.username || "unknown"} found in ${sources.join(", ") || "unknown breach"}`,
        tags: ["leakcheck", "credential_leak", domain],
        rawData: entry,
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
  } catch (err: any) {
    await updateFeedStatus("leakcheck", "down", 0, err.message).catch(() => {});
    return { feed: "leakcheck", fetched: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Domain-Specific Darkweb Sync ───────────────────────────────────────

/**
 * Run darkweb intelligence feeds for a specific domain.
 * Queries IntelX, Hudson Rock, and LeakCheck for domain-specific data.
 */
export async function runDomainDarkwebSync(domain: string): Promise<DarkwebSyncResult> {
  const startedAt = new Date();

  try {
    console.log(`[DarkwebOSINT] Starting domain-specific darkweb sync for ${domain}...`);

    const results = await Promise.all([
      fetchIntelXForDomain(domain),
      fetchHudsonRockForDomain(domain),
      fetchLeakCheckForDomain(domain),
    ]);

    const completedAt = new Date();
    const totalFetched = results.reduce((sum, r) => sum + r.fetched, 0);
    const totalErrors = results.filter((r) => r.error).length;

    console.log(`[DarkwebOSINT] Domain sync complete for ${domain}: ${totalFetched} records from ${results.length} feeds (${totalErrors} errors)`);
    results.forEach((r) => {
      console.log(`  - ${r.feed}: ${r.fetched} records (${r.durationMs}ms)${r.error ? ` ERROR: ${r.error}` : ""}`);
    });

    return { startedAt, completedAt, results, totalFetched, totalErrors };
  } catch (err: any) {
    console.error(`[DarkwebOSINT] Domain sync failed for ${domain}:`, err.message);
    return { startedAt, completedAt: new Date(), results: [], totalFetched: 0, totalErrors: 1 };
  }
}
