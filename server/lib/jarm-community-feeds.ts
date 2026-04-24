/**
 * JARM Community Signature Feed Integration
 *
 * Fetches JARM fingerprint signatures from public community repositories
 * and threat intelligence feeds. Signatures are stored in the database
 * and merged with the built-in signature database at inference time.
 *
 * Supported feed types:
 * - github_csv: CSV files from GitHub repos (e.g., JARM hash lists)
 * - github_json: JSON files from GitHub repos
 * - censys_dataset: Censys JARM dataset exports
 * - custom_api: Custom REST API endpoints returning JARM signatures
 */

import { eq, and, desc, sql } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface FeedSource {
  id?: number;
  feedId: string;
  name: string;
  feedType: "github_csv" | "github_json" | "censys_dataset" | "custom_api";
  url: string;
  description: string | null;
  enabled: boolean;
  autoRefresh: boolean;
  refreshIntervalHours: number;
  lastRefreshAt: number | null;
  lastRefreshStatus: string | null;
  lastRefreshError: string | null;
  totalSignatures: number;
  lastSignatureCount: number | null;
}

export interface CommunitySignature {
  id?: number;
  signatureId: string;
  jarmHash: string;
  provider: string;
  matchType: "cdn" | "cloud" | "server" | "c2" | "unknown";
  confidence: number;
  description: string | null;
  feedSource: string;
  feedUrl: string | null;
  isPrefix: boolean;
  tags: string[] | null;
  lastSeenAt: number | null;
  firstSeenAt: number | null;
  enabled: boolean;
}

export interface FeedRefreshResult {
  feedId: string;
  success: boolean;
  signaturesAdded: number;
  signaturesUpdated: number;
  signaturesTotal: number;
  error: string | null;
  durationMs: number;
}

// ─── Default Feed Sources ───────────────────────────────────────────────────

export const DEFAULT_FEED_SOURCES: Omit<FeedSource, "id" | "lastRefreshAt" | "lastRefreshStatus" | "lastRefreshError" | "totalSignatures" | "lastSignatureCount">[] = [
  {
    feedId: "salesforce-jarm",
    name: "Salesforce JARM Known Hashes",
    feedType: "github_json",
    url: "https://raw.githubusercontent.com/salesforce/jarm/master/jarm_known_hashes.json",
    description: "Official JARM fingerprint database from Salesforce, the creators of JARM. Contains known hashes for common TLS implementations.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 168, // Weekly
  },
  {
    feedId: "c2-jarm-ioc",
    name: "C2 JARM Indicators of Compromise",
    feedType: "github_csv",
    url: "https://raw.githubusercontent.com/cedowens/C2-JARM/main/JARM_table.csv",
    description: "Community-maintained C2 framework JARM fingerprints. Covers Cobalt Strike, Metasploit, Sliver, Covenant, PoshC2, and more.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 24,
  },
  {
    feedId: "tls-fingerprint-db",
    name: "TLS Fingerprint Database",
    feedType: "github_json",
    url: "https://raw.githubusercontent.com/AresS31/jarm-online/main/data/fingerprints.json",
    description: "Community TLS fingerprint database with JARM hashes for various server software and services.",
    enabled: true,
    autoRefresh: true,
    refreshIntervalHours: 72,
  },
];

// ─── Feed Parsers ───────────────────────────────────────────────────────────

interface ParsedSignature {
  jarmHash: string;
  provider: string;
  matchType: "cdn" | "cloud" | "server" | "c2" | "unknown";
  confidence: number;
  description: string | null;
  isPrefix: boolean;
  tags: string[];
}

function parseGithubCsv(content: string, feedId: string): ParsedSignature[] {
  const signatures: ParsedSignature[] = [];
  const lines = content.trim().split("\n");
  if (lines.length < 2) return signatures;

  // Parse header
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

    let matchType: ParsedSignature["matchType"] = "unknown";
    if (typeStr.includes("c2") || typeStr.includes("malware") || typeStr.includes("rat")) {
      matchType = "c2";
    } else if (typeStr.includes("cdn") || typeStr.includes("waf")) {
      matchType = "cdn";
    } else if (typeStr.includes("cloud")) {
      matchType = "cloud";
    } else if (typeStr.includes("server") || typeStr.includes("web")) {
      matchType = "server";
    }

    // Infer C2 from known tool names
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
      tags: matchType === "c2" ? ["c2", "threat-intel"] : [matchType],
    });
  }

  return signatures;
}

function parseGithubJson(content: string, feedId: string): ParsedSignature[] {
  const signatures: ParsedSignature[] = [];

  try {
    const data = JSON.parse(content);

    // Handle array of objects
    const items = Array.isArray(data) ? data : Object.entries(data).map(([k, v]) => {
      if (typeof v === "string") return { jarm: k, name: v };
      if (typeof v === "object" && v !== null) return { jarm: k, ...(v as Record<string, unknown>) };
      return { jarm: k, name: String(v) };
    });

    for (const item of items) {
      const jarmHash = item.jarm || item.jarm_hash || item.hash || item.fingerprint || "";
      if (!jarmHash || jarmHash.length < 10) continue;

      const provider = item.name || item.provider || item.server || item.tool || "Unknown";
      const typeStr = (item.type || item.category || item.match_type || "").toLowerCase();

      let matchType: ParsedSignature["matchType"] = "unknown";
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
        tags: item.tags || [matchType],
      });
    }
  } catch {
    console.error(`[JARM Feeds] Failed to parse JSON from ${feedId}`);
  }

  return signatures;
}

function parseFeedContent(content: string, feedType: string, feedId: string): ParsedSignature[] {
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

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Refresh a single feed source: fetch content, parse signatures, upsert into DB.
 */
export async function refreshFeed(
  db: any,
  schema: any,
  feed: FeedSource,
): Promise<FeedRefreshResult> {
  const startTime = Date.now();
  const result: FeedRefreshResult = {
    feedId: feed.feedId,
    success: false,
    signaturesAdded: 0,
    signaturesUpdated: 0,
    signaturesTotal: 0,
    error: null,
    durationMs: 0,
  };

  try {
    // Fetch feed content
    const response = await fetch(feed.url, {
      headers: {
        "User-Agent": "AceC3-JARM-Feed-Fetcher/1.0",
        Accept: "text/plain, application/json, text/csv",
      },
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const content = await response.text();
    if (!content || content.length < 10) {
      throw new Error("Empty or invalid response body");
    }

    // Parse signatures
    const parsed = parseFeedContent(content, feed.feedType, feed.feedId);
    if (parsed.length === 0) {
      throw new Error("No valid signatures parsed from feed content");
    }

    // Upsert signatures into database
    const now = Date.now();
    for (const sig of parsed) {
      const signatureId = `${feed.feedId}:${sig.jarmHash}:${sig.provider}`;

      // Check if signature exists
      const existing = await db
        .select()
        .from(schema.jarmCommunitySignatures)
        .where(eq(schema.jarmCommunitySignatures.signatureId, signatureId))
        .limit(1);

      if (existing.length > 0) {
        // Update existing
        await db
          .update(schema.jarmCommunitySignatures)
          .set({
            confidence: sig.confidence,
            description: sig.description,
            tags: JSON.stringify(sig.tags),
            lastSeenAt: now,
          })
          .where(eq(schema.jarmCommunitySignatures.signatureId, signatureId));
        result.signaturesUpdated++;
      } else {
        // Insert new
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
          enabled: 1,
        });
        result.signaturesAdded++;
      }
    }

    result.signaturesTotal = parsed.length;
    result.success = true;

    // Update feed source record
    await db
      .update(schema.jarmFeedSources)
      .set({
        lastRefreshAt: now,
        lastRefreshStatus: "success",
        lastRefreshError: null,
        totalSignatures: sql`${schema.jarmFeedSources.totalSignatures} + ${result.signaturesAdded}`,
        lastSignatureCount: parsed.length,
      })
      .where(eq(schema.jarmFeedSources.feedId, feed.feedId));
  } catch (err: any) {
    result.error = err.message || "Unknown error";

    // Update feed source with error
    try {
      await db
        .update(schema.jarmFeedSources)
        .set({
          lastRefreshAt: Date.now(),
          lastRefreshStatus: "error",
          lastRefreshError: result.error,
        })
        .where(eq(schema.jarmFeedSources.feedId, feed.feedId));
    } catch {
      // Ignore update errors
    }
  }

  result.durationMs = Date.now() - startTime;
  return result;
}

/**
 * Refresh all enabled feed sources.
 */
export async function refreshAllFeeds(
  db: any,
  schema: any,
): Promise<FeedRefreshResult[]> {
  const feeds = await db
    .select()
    .from(schema.jarmFeedSources)
    .where(eq(schema.jarmFeedSources.enabled, 1));

  const results: FeedRefreshResult[] = [];
  for (const feedRow of feeds) {
    const feed: FeedSource = {
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
      lastSignatureCount: feedRow.lastSignatureCount,
    };

    // Skip if not due for refresh
    if (feed.lastRefreshAt) {
      const hoursSinceRefresh = (Date.now() - feed.lastRefreshAt) / (1000 * 60 * 60);
      if (hoursSinceRefresh < feed.refreshIntervalHours) {
        continue;
      }
    }

    const result = await refreshFeed(db, schema, feed);
    results.push(result);
  }

  return results;
}

/**
 * Initialize default feed sources if they don't exist.
 */
export async function initializeDefaultFeeds(
  db: any,
  schema: any,
): Promise<number> {
  let added = 0;

  for (const feed of DEFAULT_FEED_SOURCES) {
    const existing = await db
      .select()
      .from(schema.jarmFeedSources)
      .where(eq(schema.jarmFeedSources.feedId, feed.feedId))
      .limit(1);

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
        lastSignatureCount: 0,
      });
      added++;
    }
  }

  return added;
}

/**
 * Get all community signatures (for merging with built-in database).
 */
export async function getCommunitySignatures(
  db: any,
  schema: any,
): Promise<CommunitySignature[]> {
  const rows = await db
    .select()
    .from(schema.jarmCommunitySignatures)
    .where(eq(schema.jarmCommunitySignatures.enabled, 1));

  return rows.map((r: any) => ({
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
    tags: r.tags ? (typeof r.tags === "string" ? JSON.parse(r.tags) : r.tags) : null,
    lastSeenAt: r.lastSeenAt,
    firstSeenAt: r.firstSeenAt,
    enabled: r.enabled === 1,
  }));
}

/**
 * Get all feed sources with their status.
 */
export async function getFeedSources(
  db: any,
  schema: any,
): Promise<FeedSource[]> {
  const rows = await db
    .select()
    .from(schema.jarmFeedSources)
    .orderBy(desc(schema.jarmFeedSources.id));

  return rows.map((r: any) => ({
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
    lastSignatureCount: r.lastSignatureCount,
  }));
}

/**
 * Add a custom feed source.
 */
export async function addFeedSource(
  db: any,
  schema: any,
  feed: Omit<FeedSource, "id" | "lastRefreshAt" | "lastRefreshStatus" | "lastRefreshError" | "totalSignatures" | "lastSignatureCount">,
): Promise<void> {
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
    lastSignatureCount: 0,
  });
}

/**
 * Toggle a feed source enabled/disabled.
 */
export async function toggleFeedSource(
  db: any,
  schema: any,
  feedId: string,
  enabled: boolean,
): Promise<void> {
  await db
    .update(schema.jarmFeedSources)
    .set({ enabled: enabled ? 1 : 0 })
    .where(eq(schema.jarmFeedSources.feedId, feedId));
}

/**
 * Delete a feed source and its signatures.
 */
export async function deleteFeedSource(
  db: any,
  schema: any,
  feedId: string,
): Promise<void> {
  await db
    .delete(schema.jarmCommunitySignatures)
    .where(eq(schema.jarmCommunitySignatures.feedSource, feedId));
  await db
    .delete(schema.jarmFeedSources)
    .where(eq(schema.jarmFeedSources.feedId, feedId));
}

/**
 * Get feed statistics summary.
 */
export async function getFeedStats(
  db: any,
  schema: any,
): Promise<{
  totalFeeds: number;
  enabledFeeds: number;
  totalSignatures: number;
  c2Signatures: number;
  lastRefresh: number | null;
}> {
  const feeds = await db.select().from(schema.jarmFeedSources);
  const sigs = await db.select().from(schema.jarmCommunitySignatures).where(eq(schema.jarmCommunitySignatures.enabled, 1));

  const enabledFeeds = feeds.filter((f: any) => f.enabled === 1).length;
  const c2Sigs = sigs.filter((s: any) => s.matchType === "c2").length;
  const lastRefresh = feeds.reduce((max: number | null, f: any) => {
    if (!f.lastRefreshAt) return max;
    return max === null ? f.lastRefreshAt : Math.max(max, f.lastRefreshAt);
  }, null);

  return {
    totalFeeds: feeds.length,
    enabledFeeds,
    totalSignatures: sigs.length,
    c2Signatures: c2Sigs,
    lastRefresh,
  };
}
