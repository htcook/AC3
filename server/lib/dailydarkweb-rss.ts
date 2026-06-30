/**
 * Daily Dark Web RSS Feed Scraper & Auto-Ingestion
 *
 * Fetches and parses the dailydarkweb.net RSS feed to automatically:
 *   - Discover new ransomware victim claims
 *   - Extract threat actor names from article categories
 *   - Create threat group events with cited sources
 *   - Update existing threat actor activity timelines
 *
 * Feed URLs:
 *   - Main: https://dailydarkweb.net/feed/
 *   - Ransomware: https://dailydarkweb.net/category/ransomware-news/feed/
 *   - Data Breaches: https://dailydarkweb.net/category/data-breaches/feed/
 *   - Cyber Attacks: https://dailydarkweb.net/category/cyber-attacks/feed/
 *   - Unauthorized Access: https://dailydarkweb.net/category/unauthorized-accesses/feed/
 */

import { getDb } from "../db";
import {
  threatGroupEvents,
  threatActors,
  ransomwareGroups,
} from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";

// ─── Feed Configuration ──────────────────────────────────────────────

export const DDW_RSS_FEEDS = [
  { url: "https://dailydarkweb.net/feed/", category: "all", label: "Main Feed" },
  { url: "https://dailydarkweb.net/category/ransomware-news/feed/", category: "ransomware-news", label: "Ransomware News" },
  { url: "https://dailydarkweb.net/category/data-breaches/feed/", category: "data-breaches", label: "Data Breaches" },
  { url: "https://dailydarkweb.net/category/cyber-attacks/feed/", category: "cyber-attacks", label: "Cyber Attacks" },
  { url: "https://dailydarkweb.net/category/unauthorized-accesses/feed/", category: "unauthorized-accesses", label: "Unauthorized Access" },
];

// Known threat group name patterns for extraction from titles and categories
const KNOWN_THREAT_GROUPS = [
  "Qilin", "Dragonforce", "Akira", "Play", "Rhysida", "Anubis",
  "FULCRUMSEC", "FulcrumSec", "Vect", "AiLock", "RuskiNet",
  "Handala", "LockBit", "BlackCat", "ALPHV", "Cl0p", "Clop",
  "RansomHub", "Medusa", "BianLian", "Black Basta", "Royal",
  "Hunters International", "INC Ransom", "Cactus", "8Base",
  "NoEscape", "Trigona", "Snatch", "Vice Society", "Karakurt",
  "BlackByte", "Hive", "Cuba", "Conti", "REvil", "Sodinokibi",
  "DarkSide", "BlackMatter", "Ragnar Locker", "Everest",
  "Mallox", "Fog", "Lynx", "Sarcoma", "NightSpire", "Morpheus",
  "Termite", "SafePay", "Nitrogen", "Space Bears", "Embargo",
];

// ─── RSS Parser ──────────────────────────────────────────────────────

interface RSSItem {
  title: string;
  link: string;
  pubDate: string;
  categories: string[];
  description: string;
  contentEncoded: string;
  creator: string;
}

interface ParsedFeed {
  title: string;
  lastBuildDate: string;
  items: RSSItem[];
}

/**
 * Parse RSS XML into structured items.
 * Uses regex-based extraction to avoid heavy XML parser dependency.
 */
function parseRSSXml(xml: string): ParsedFeed {
  const getTag = (src: string, tag: string): string => {
    const re = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([\\s\\S]*?)</${tag}>`);
    const m = src.match(re);
    return (m?.[1] ?? m?.[2] ?? "").trim();
  };

  const getAllTags = (src: string, tag: string): string[] => {
    const re = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "g");
    const results: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      results.push((m[1] ?? m[2] ?? "").trim());
    }
    return results;
  };

  const channelTitle = getTag(xml, "title");
  const lastBuildDate = getTag(xml, "lastBuildDate");

  const items: RSSItem[] = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let itemMatch: RegExpExecArray | null;
  while ((itemMatch = itemRegex.exec(xml)) !== null) {
    const itemXml = itemMatch[1];
    items.push({
      title: getTag(itemXml, "title"),
      link: getTag(itemXml, "link"),
      pubDate: getTag(itemXml, "pubDate"),
      categories: getAllTags(itemXml, "category"),
      description: getTag(itemXml, "description"),
      contentEncoded: getTag(itemXml, "content:encoded"),
      creator: getTag(itemXml, "dc:creator"),
    });
  }

  return { title: channelTitle, lastBuildDate, items };
}

// ─── Threat Actor Extraction ─────────────────────────────────────────

interface ExtractedThreatEvent {
  actorName: string;
  actorId: string;
  title: string;
  description: string;
  eventType: "attack" | "data_leak" | "ransomware_claim" | "defacement";
  severity: "critical" | "high" | "medium" | "low";
  victims: { name: string; sector?: string; country?: string }[];
  sourceUrl: string;
  pubDate: string;
  categories: string[];
}

/**
 * Extract threat actor name from article title and categories.
 */
function extractThreatActor(item: RSSItem): string | null {
  // Check title for known group names
  for (const group of KNOWN_THREAT_GROUPS) {
    if (item.title.toLowerCase().includes(group.toLowerCase())) {
      return group;
    }
  }
  // Check categories for known group names
  for (const cat of item.categories) {
    for (const group of KNOWN_THREAT_GROUPS) {
      if (cat.toLowerCase() === group.toLowerCase()) {
        return group;
      }
    }
  }
  // Try to extract from common title patterns like "X Hacks Y" or "X Attacks Y"
  const titlePatterns = [
    /^(\w[\w\s]*?)\s+(?:Hacks?|Attacks?|Breaches?|Claims?|Targets?)\s/i,
    /Ransomware Attack by (\w[\w\s]*?)(?:\s+Group)?$/i,
    /(?:by|from)\s+(\w[\w\s]*?)(?:\s+Group|\s+Ransomware)?$/i,
  ];
  for (const pattern of titlePatterns) {
    const m = item.title.match(pattern);
    if (m?.[1] && m[1].length < 40) {
      return m[1].trim();
    }
  }
  return null;
}

/**
 * Determine event severity based on content analysis.
 */
function assessSeverity(item: RSSItem): "critical" | "high" | "medium" | "low" {
  const text = (item.title + " " + item.description + " " + item.contentEncoded).toLowerCase();
  if (text.includes("government") || text.includes("military") || text.includes("critical infrastructure") ||
      text.includes("healthcare") || text.includes("hospital") || text.includes("federal")) {
    return "critical";
  }
  if (text.includes("ransomware") || text.includes("data breach") || text.includes("exfiltrat") ||
      text.includes("million") || text.includes("database")) {
    return "high";
  }
  if (text.includes("unauthorized access") || text.includes("credentials") || text.includes("defac")) {
    return "medium";
  }
  return "medium";
}

/**
 * Determine event type from categories and content.
 */
function classifyEventType(item: RSSItem): "attack" | "data_leak" | "ransomware_claim" | "defacement" {
  const cats = item.categories.map(c => c.toLowerCase());
  if (cats.includes("ransomware news") || cats.some(c => c.includes("ransomware"))) return "ransomware_claim";
  if (cats.includes("data-breaches") || cats.includes("data breaches")) return "data_leak";
  if (item.title.toLowerCase().includes("defac")) return "defacement";
  return "attack";
}

/**
 * Extract victim names from article content.
 */
function extractVictims(item: RSSItem): { name: string; sector?: string; country?: string }[] {
  const victims: { name: string; sector?: string; country?: string }[] = [];
  // Look for bold names in content (common DDW pattern)
  const boldPattern = /<strong>([^<]+)<\/strong>/g;
  let m: RegExpExecArray | null;
  const content = item.contentEncoded || item.description;
  while ((m = boldPattern.exec(content)) !== null) {
    const name = m[1].trim();
    // Filter out common non-victim bold text
    if (name.length > 2 && name.length < 100 &&
        !name.toLowerCase().includes("according") &&
        !name.toLowerCase().includes("the ") &&
        !name.toLowerCase().includes("note:") &&
        !name.match(/^\d/)) {
      // Try to extract country from flag emoji nearby
      const surrounding = content.substring(Math.max(0, m.index - 20), m.index + m[0].length + 50);
      const countryMatch = surrounding.match(/\(([^)]+)\)/);
      victims.push({
        name,
        country: countryMatch?.[1]?.replace(/[^\w\s]/g, "").trim() || undefined,
      });
    }
  }
  return victims.slice(0, 10); // Cap at 10 victims per article
}

/**
 * Process a single RSS item into a structured threat event.
 */
function processItem(item: RSSItem): ExtractedThreatEvent | null {
  const actorName = extractThreatActor(item);
  if (!actorName) return null; // Skip articles without identifiable threat actors

  return {
    actorName,
    actorId: actorName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, ""),
    title: item.title,
    description: item.description.replace(/<[^>]+>/g, "").replace(/\[&#8230;\]/g, "...").trim(),
    eventType: classifyEventType(item),
    severity: assessSeverity(item),
    victims: extractVictims(item),
    sourceUrl: item.link,
    pubDate: item.pubDate,
    categories: item.categories,
  };
}

// ─── Database Ingestion ──────────────────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

export interface RSSFetchResult {
  feed: string;
  itemsFetched: number;
  eventsExtracted: number;
  eventsIngested: number;
  actorsUpdated: number;
  errors: string[];
}

/**
 * Fetch a single RSS feed and ingest extracted events.
 */
export async function fetchAndIngestFeed(feedUrl: string, feedLabel: string): Promise<RSSFetchResult> {
  const result: RSSFetchResult = {
    feed: feedLabel,
    itemsFetched: 0,
    eventsExtracted: 0,
    eventsIngested: 0,
    actorsUpdated: 0,
    errors: [],
  };

  try {
    const response = await fetch(feedUrl, {
      headers: { "User-Agent": "AC3-ThreatIntel/1.0 (Darkweb Feed Aggregator)" },
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      result.errors.push(`HTTP ${response.status}: ${response.statusText}`);
      return result;
    }

    const xml = await response.text();
    const feed = parseRSSXml(xml);
    result.itemsFetched = feed.items.length;

    const db = await requireDb();
    const updatedActors = new Set<string>();

    for (const item of feed.items) {
      const event = processItem(item);
      if (!event) continue;
      result.eventsExtracted++;

      // Check for duplicate events
      const [existing] = await db.select().from(threatGroupEvents)
        .where(sql`${threatGroupEvents.tgeSourceUrl} = ${event.sourceUrl} AND ${threatGroupEvents.tgeActorId} = ${event.actorId}`)
        .limit(1);

      if (existing) continue; // Already ingested

      // Map actorId to existing threat actor if possible
      const [existingActor] = await db.select().from(threatActors)
        .where(sql`LOWER(${threatActors.name}) = ${event.actorName.toLowerCase()} OR ${threatActors.actorId} = ${event.actorId}`)
        .limit(1);

      const resolvedActorId = existingActor?.actorId ?? event.actorId;

      // Insert the event
      try {
        await db.insert(threatGroupEvents).values({
          tgeActorId: resolvedActorId,
          eventType: event.eventType === "ransomware_claim" ? "attack" : event.eventType,
          tgeTitle: event.title.substring(0, 500),
          tgeDescription: event.description.substring(0, 2000),
          tgeSeverity: event.severity,
          tgeVictimName: event.victims[0]?.name ?? "Unknown",
          tgeVictimSector: event.victims[0]?.sector ?? null,
          tgeVictimCountry: event.victims[0]?.country ?? null,
          tgeMitreTechniques: event.eventType === "ransomware_claim" ? ["T1486"] : ["T1190"],
          tgeIocs: [],
          tgeSource: "Daily Dark Web (RSS)",
          tgeSourceUrl: event.sourceUrl,
          tgeConfidence: 70,
          eventDate: new Date(event.pubDate),
        });
        result.eventsIngested++;
      } catch (e: any) {
        result.errors.push(`Event insert failed: ${e.message}`);
      }

      // Update actor's lastActive if we have them
      if (existingActor && !updatedActors.has(resolvedActorId)) {
        try {
          await db.update(threatActors).set({
            lastActive: new Date(event.pubDate).toISOString().substring(0, 7), // YYYY-MM
          }).where(eq(threatActors.actorId, resolvedActorId));
          updatedActors.add(resolvedActorId);
          result.actorsUpdated++;
        } catch { /* ignore update failures */ }
      }

      // Also update ransomwareGroups if applicable
      if (event.eventType === "ransomware_claim") {
        try {
          const [rwGroup] = await db.select().from(ransomwareGroups)
            .where(sql`LOWER(${ransomwareGroups.groupName}) = ${event.actorName.toLowerCase()}`)
            .limit(1);
          if (rwGroup) {
            await db.update(ransomwareGroups).set({
              lastActive: new Date(event.pubDate).toISOString().substring(0, 7),
              victims7d: sql`${ransomwareGroups.victims7D} + 1`,
              victims30d: sql`${ransomwareGroups.victims30D} + 1`,
              totalVictims: sql`${ransomwareGroups.totalVictims} + ${event.victims.length || 1}`,
            }).where(eq(ransomwareGroups.id, rwGroup.id));
          }
        } catch { /* ignore update failures */ }
      }
    }

    return result;
  } catch (e: any) {
    result.errors.push(`Fetch failed: ${e.message}`);
    return result;
  }
}

// ─── Full RSS Sync ───────────────────────────────────────────────────

export interface FullRSSSyncResult {
  totalItemsFetched: number;
  totalEventsExtracted: number;
  totalEventsIngested: number;
  totalActorsUpdated: number;
  feedResults: RSSFetchResult[];
  duration: number;
}

/**
 * Fetch all Daily Dark Web RSS feeds and ingest new events.
 * Uses the main feed only by default to avoid duplicates across category feeds.
 */
export async function syncDailyDarkWebRSS(useAllFeeds = false): Promise<FullRSSSyncResult> {
  const start = Date.now();
  const feeds = useAllFeeds ? DDW_RSS_FEEDS : [DDW_RSS_FEEDS[0]]; // Main feed has all articles
  const feedResults: RSSFetchResult[] = [];

  for (const feed of feeds) {
    const result = await fetchAndIngestFeed(feed.url, feed.label);
    feedResults.push(result);
    // Small delay between feeds to be polite
    if (feeds.length > 1) await new Promise(r => setTimeout(r, 1000));
  }

  const totals: FullRSSSyncResult = {
    totalItemsFetched: feedResults.reduce((s, r) => s + r.itemsFetched, 0),
    totalEventsExtracted: feedResults.reduce((s, r) => s + r.eventsExtracted, 0),
    totalEventsIngested: feedResults.reduce((s, r) => s + r.eventsIngested, 0),
    totalActorsUpdated: feedResults.reduce((s, r) => s + r.actorsUpdated, 0),
    feedResults,
    duration: Date.now() - start,
  };

  console.log(`[DailyDarkWeb RSS] Sync complete: ${totals.totalItemsFetched} items fetched, ${totals.totalEventsExtracted} events extracted, ${totals.totalEventsIngested} ingested, ${totals.totalActorsUpdated} actors updated (${totals.duration}ms)`);
  return totals;
}

// ─── RSS Parser Export (for testing) ─────────────────────────────────

export { parseRSSXml, extractThreatActor, processItem, assessSeverity, classifyEventType, extractVictims };
export type { RSSItem, ParsedFeed, ExtractedThreatEvent };
