import "./chunk-KFQGP6VL.js";

// server/lib/jarm-community-feeds.ts
import { eq, desc, sql } from "drizzle-orm";
var DEFAULT_FEED_SOURCES = [
  {
    feedId: "salesforce-jarm",
    name: "Salesforce JARM Known Hashes",
    feedType: "github_json",
    url: "https://raw.githubusercontent.com/salesforce/jarm/master/jarm_known_hashes.json",
    description: "Official JARM fingerprint database from Salesforce, the creators of JARM. Contains known hashes for common TLS implementations.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 168
    // Weekly
  },
  {
    feedId: "c2-jarm-ioc",
    name: "C2 JARM Indicators of Compromise",
    feedType: "github_csv",
    url: "https://raw.githubusercontent.com/cedowens/C2-JARM/main/JARM_table.csv",
    description: "Community-maintained C2 framework JARM fingerprints. Covers Cobalt Strike, Metasploit, Sliver, Covenant, PoshC2, and more.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 24
  },
  {
    feedId: "tls-fingerprint-db",
    name: "TLS Fingerprint Database",
    feedType: "github_json",
    url: "https://raw.githubusercontent.com/AresS31/jarm-online/main/data/fingerprints.json",
    description: "Community TLS fingerprint database with JARM hashes for various server software and services.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 72
  }
];
function parseGithubCsv(content, feedId) {
  const signatures = [];
  const lines = content.trim().split("\n");
  if (lines.length < 2) return signatures;
  const header = lines[0].toLowerCase().split(",").map((h) => h.trim().replace(/"/g, ""));
  const jarmIdx = header.findIndex((h) => h.includes("jarm") || h.includes("hash") || h.includes("fingerprint"));
  const nameIdx = header.findIndex((h) => h.includes("name") || h.includes("tool") || h.includes("server") || h.includes("provider"));
  const typeIdx = header.findIndex((h) => h.includes("type") || h.includes("category"));
  if (jarmIdx === -1) return signatures;
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",").map((c) => c.trim().replace(/"/g, ""));
    const jarmHash = cols[jarmIdx];
    if (!jarmHash || jarmHash.length < 10) continue;
    const provider = nameIdx >= 0 ? cols[nameIdx] || "Unknown" : "Unknown";
    const typeStr = typeIdx >= 0 ? (cols[typeIdx] || "").toLowerCase() : "";
    let matchType = "unknown";
    if (typeStr.includes("c2") || typeStr.includes("malware") || typeStr.includes("rat")) {
      matchType = "c2";
    } else if (typeStr.includes("cdn") || typeStr.includes("waf")) {
      matchType = "cdn";
    } else if (typeStr.includes("cloud")) {
      matchType = "cloud";
    } else if (typeStr.includes("server") || typeStr.includes("web")) {
      matchType = "server";
    }
    const providerLower = provider.toLowerCase();
    const c2Tools = ["cobalt strike", "cobaltstrike", "metasploit", "sliver", "covenant", "poshc2", "havoc", "brute ratel", "merlin", "mythic", "empire", "deimos"];
    if (c2Tools.some((t) => providerLower.includes(t))) {
      matchType = "c2";
    }
    signatures.push({
      jarmHash,
      provider,
      matchType,
      confidence: matchType === "c2" ? 0.85 : 0.7,
      description: `From ${feedId}: ${provider}`,
      isPrefix: jarmHash.length < 62,
      tags: matchType === "c2" ? ["c2", "threat-intel"] : [matchType]
    });
  }
  return signatures;
}
function parseGithubJson(content, feedId) {
  const signatures = [];
  try {
    const data = JSON.parse(content);
    const items = Array.isArray(data) ? data : Object.entries(data).map(([k, v]) => {
      if (typeof v === "string") return { jarm: k, name: v };
      if (typeof v === "object" && v !== null) return { jarm: k, ...v };
      return { jarm: k, name: String(v) };
    });
    for (const item of items) {
      const jarmHash = item.jarm || item.jarm_hash || item.hash || item.fingerprint || "";
      if (!jarmHash || jarmHash.length < 10) continue;
      const provider = item.name || item.provider || item.server || item.tool || "Unknown";
      const typeStr = (item.type || item.category || item.match_type || "").toLowerCase();
      let matchType = "unknown";
      if (typeStr.includes("c2") || typeStr.includes("malware")) matchType = "c2";
      else if (typeStr.includes("cdn") || typeStr.includes("waf")) matchType = "cdn";
      else if (typeStr.includes("cloud")) matchType = "cloud";
      else if (typeStr.includes("server")) matchType = "server";
      const providerLower = String(provider).toLowerCase();
      const c2Tools = ["cobalt strike", "cobaltstrike", "metasploit", "sliver", "covenant", "poshc2", "havoc", "brute ratel", "merlin"];
      if (c2Tools.some((t) => providerLower.includes(t))) matchType = "c2";
      signatures.push({
        jarmHash: String(jarmHash),
        provider: String(provider),
        matchType,
        confidence: item.confidence ? Number(item.confidence) : matchType === "c2" ? 0.85 : 0.7,
        description: item.description || `From ${feedId}: ${provider}`,
        isPrefix: String(jarmHash).length < 62,
        tags: item.tags || [matchType]
      });
    }
  } catch {
    console.error(`[JARM Feeds] Failed to parse JSON from ${feedId}`);
  }
  return signatures;
}
function parseFeedContent(content, feedType, feedId) {
  switch (feedType) {
    case "github_csv":
      return parseGithubCsv(content, feedId);
    case "github_json":
    case "censys_dataset":
    case "custom_api":
      return parseGithubJson(content, feedId);
    default:
      return [];
  }
}
async function refreshFeed(db, schema, feed) {
  const startTime = Date.now();
  const result = {
    feedId: feed.feedId,
    success: false,
    signaturesAdded: 0,
    signaturesUpdated: 0,
    signaturesTotal: 0,
    error: null,
    durationMs: 0
  };
  try {
    const response = await fetch(feed.url, {
      headers: {
        "User-Agent": "AceC3-JARM-Feed-Fetcher/1.0",
        Accept: "text/plain, application/json, text/csv"
      },
      signal: AbortSignal.timeout(3e4)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const content = await response.text();
    if (!content || content.length < 10) {
      throw new Error("Empty or invalid response body");
    }
    const parsed = parseFeedContent(content, feed.feedType, feed.feedId);
    if (parsed.length === 0) {
      throw new Error("No valid signatures parsed from feed content");
    }
    const now = Date.now();
    for (const sig of parsed) {
      const signatureId = `${feed.feedId}:${sig.jarmHash}:${sig.provider}`;
      const existing = await db.select().from(schema.jarmCommunitySignatures).where(eq(schema.jarmCommunitySignatures.signatureId, signatureId)).limit(1);
      if (existing.length > 0) {
        await db.update(schema.jarmCommunitySignatures).set({
          confidence: sig.confidence,
          description: sig.description,
          tags: JSON.stringify(sig.tags),
          lastSeenAt: now
        }).where(eq(schema.jarmCommunitySignatures.signatureId, signatureId));
        result.signaturesUpdated++;
      } else {
        await db.insert(schema.jarmCommunitySignatures).values({
          signatureId,
          jarmHash: sig.jarmHash,
          provider: sig.provider,
          matchType: sig.matchType,
          confidence: sig.confidence,
          description: sig.description,
          feedSource: feed.feedId,
          feedUrl: feed.url,
          isPrefix: sig.isPrefix ? 1 : 0,
          tags: JSON.stringify(sig.tags),
          lastSeenAt: now,
          firstSeenAt: now,
          enabled: 1
        });
        result.signaturesAdded++;
      }
    }
    result.signaturesTotal = parsed.length;
    result.success = true;
    await db.update(schema.jarmFeedSources).set({
      lastRefreshAt: now,
      lastRefreshStatus: "success",
      lastRefreshError: null,
      totalSignatures: sql`${schema.jarmFeedSources.totalSignatures} + ${result.signaturesAdded}`,
      lastSignatureCount: parsed.length
    }).where(eq(schema.jarmFeedSources.feedId, feed.feedId));
  } catch (err) {
    result.error = err.message || "Unknown error";
    try {
      await db.update(schema.jarmFeedSources).set({
        lastRefreshAt: Date.now(),
        lastRefreshStatus: "error",
        lastRefreshError: result.error
      }).where(eq(schema.jarmFeedSources.feedId, feed.feedId));
    } catch {
    }
  }
  result.durationMs = Date.now() - startTime;
  return result;
}
async function refreshAllFeeds(db, schema) {
  const feeds = await db.select().from(schema.jarmFeedSources).where(eq(schema.jarmFeedSources.enabled, 1));
  const results = [];
  for (const feedRow of feeds) {
    const feed = {
      id: feedRow.id,
      feedId: feedRow.feedId,
      name: feedRow.name,
      feedType: feedRow.feedType,
      url: feedRow.url,
      description: feedRow.description,
      enabled: feedRow.enabled === 1,
      autoRefresh: feedRow.autoRefresh === 1,
      refreshIntervalHours: feedRow.refreshIntervalHours,
      lastRefreshAt: feedRow.lastRefreshAt,
      lastRefreshStatus: feedRow.lastRefreshStatus,
      lastRefreshError: feedRow.lastRefreshError,
      totalSignatures: feedRow.totalSignatures,
      lastSignatureCount: feedRow.lastSignatureCount
    };
    if (feed.lastRefreshAt) {
      const hoursSinceRefresh = (Date.now() - feed.lastRefreshAt) / (1e3 * 60 * 60);
      if (hoursSinceRefresh < feed.refreshIntervalHours) {
        continue;
      }
    }
    const result = await refreshFeed(db, schema, feed);
    results.push(result);
  }
  return results;
}
async function initializeDefaultFeeds(db, schema) {
  let added = 0;
  for (const feed of DEFAULT_FEED_SOURCES) {
    const existing = await db.select().from(schema.jarmFeedSources).where(eq(schema.jarmFeedSources.feedId, feed.feedId)).limit(1);
    if (existing.length === 0) {
      await db.insert(schema.jarmFeedSources).values({
        feedId: feed.feedId,
        name: feed.name,
        feedType: feed.feedType,
        url: feed.url,
        description: feed.description,
        enabled: feed.enabled ? 1 : 0,
        autoRefresh: feed.autoRefresh ? 1 : 0,
        refreshIntervalHours: feed.refreshIntervalHours,
        totalSignatures: 0,
        lastSignatureCount: 0
      });
      added++;
    }
  }
  return added;
}
async function getCommunitySignatures(db, schema) {
  const rows = await db.select().from(schema.jarmCommunitySignatures).where(eq(schema.jarmCommunitySignatures.enabled, 1));
  return rows.map((r) => ({
    id: r.id,
    signatureId: r.signatureId,
    jarmHash: r.jarmHash,
    provider: r.provider,
    matchType: r.matchType,
    confidence: r.confidence,
    description: r.description,
    feedSource: r.feedSource,
    feedUrl: r.feedUrl,
    isPrefix: r.isPrefix === 1,
    tags: r.tags ? typeof r.tags === "string" ? JSON.parse(r.tags) : r.tags : null,
    lastSeenAt: r.lastSeenAt,
    firstSeenAt: r.firstSeenAt,
    enabled: r.enabled === 1
  }));
}
async function getFeedSources(db, schema) {
  const rows = await db.select().from(schema.jarmFeedSources).orderBy(desc(schema.jarmFeedSources.id));
  return rows.map((r) => ({
    id: r.id,
    feedId: r.feedId,
    name: r.name,
    feedType: r.feedType,
    url: r.url,
    description: r.description,
    enabled: r.enabled === 1,
    autoRefresh: r.autoRefresh === 1,
    refreshIntervalHours: r.refreshIntervalHours,
    lastRefreshAt: r.lastRefreshAt,
    lastRefreshStatus: r.lastRefreshStatus,
    lastRefreshError: r.lastRefreshError,
    totalSignatures: r.totalSignatures,
    lastSignatureCount: r.lastSignatureCount
  }));
}
async function addFeedSource(db, schema, feed) {
  await db.insert(schema.jarmFeedSources).values({
    feedId: feed.feedId,
    name: feed.name,
    feedType: feed.feedType,
    url: feed.url,
    description: feed.description,
    enabled: feed.enabled ? 1 : 0,
    autoRefresh: feed.autoRefresh ? 1 : 0,
    refreshIntervalHours: feed.refreshIntervalHours,
    totalSignatures: 0,
    lastSignatureCount: 0
  });
}
async function toggleFeedSource(db, schema, feedId, enabled) {
  await db.update(schema.jarmFeedSources).set({ enabled: enabled ? 1 : 0 }).where(eq(schema.jarmFeedSources.feedId, feedId));
}
async function deleteFeedSource(db, schema, feedId) {
  await db.delete(schema.jarmCommunitySignatures).where(eq(schema.jarmCommunitySignatures.feedSource, feedId));
  await db.delete(schema.jarmFeedSources).where(eq(schema.jarmFeedSources.feedId, feedId));
}
async function getFeedStats(db, schema) {
  const feeds = await db.select().from(schema.jarmFeedSources);
  const sigs = await db.select().from(schema.jarmCommunitySignatures).where(eq(schema.jarmCommunitySignatures.enabled, 1));
  const enabledFeeds = feeds.filter((f) => f.enabled === 1).length;
  const c2Sigs = sigs.filter((s) => s.matchType === "c2").length;
  const lastRefresh = feeds.reduce((max, f) => {
    if (!f.lastRefreshAt) return max;
    return max === null ? f.lastRefreshAt : Math.max(max, f.lastRefreshAt);
  }, null);
  return {
    totalFeeds: feeds.length,
    enabledFeeds,
    totalSignatures: sigs.length,
    c2Signatures: c2Sigs,
    lastRefresh
  };
}
export {
  DEFAULT_FEED_SOURCES,
  addFeedSource,
  deleteFeedSource,
  getCommunitySignatures,
  getFeedSources,
  getFeedStats,
  initializeDefaultFeeds,
  refreshAllFeeds,
  refreshFeed,
  toggleFeedSource
};
