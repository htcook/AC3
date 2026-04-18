/**
 * Multi-Source Threat Intel RSS Ingestion Engine
 *
 * Aggregates 18+ RSS feeds across 4 tiers and ingests events into:
 *   - threatGroupEvents (actor activity history)
 *   - ransomwareEvents (victim claims)
 *   - undergroundIntelEvents (normalized darkweb events)
 *   - incidentReports (breach/incident reports for extraction)
 *   - darkwebFeedRegistry (feed health tracking)
 *
 * Tiers:
 *   1 — Ransomware & Breach Focused (Critical)
 *   2 — Threat Intel & Zero-Day (High)
 *   3 — Vendor Threat Research (Medium)
 *   4 — Geopolitical & OSINT
 */

import { getDb } from "../db";
import {
  threatGroupEvents,
  threatActors,
  ransomwareGroups,
  ransomwareEvents,
  undergroundIntelEvents,
  incidentReports,
  darkwebFeedRegistry,
} from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";

// ─── Feed Registry ──────────────────────────────────────────────────

export interface FeedSource {
  id: string;
  name: string;
  url: string;
  tier: 1 | 2 | 3 | 4;
  category: "ransomware" | "breach" | "threat_intel" | "zero_day" | "vendor_research" | "geopolitical" | "darkweb" | "general";
  /** Which tables this feed should populate */
  targets: ("threat_group_events" | "ransomware_events" | "underground_intel" | "incident_reports")[];
  enabled: boolean;
}

export const THREAT_INTEL_FEEDS: FeedSource[] = [
  // ── Tier 1: Ransomware & Breach Focused ──
  {
    id: "dailydarkweb-main",
    name: "Daily Dark Web",
    url: "https://dailydarkweb.net/feed/",
    tier: 1,
    category: "darkweb",
    targets: ["threat_group_events", "ransomware_events", "underground_intel", "incident_reports"],
    enabled: true,
  },
  {
    id: "dailydarkweb-ransomware",
    name: "Daily Dark Web — Ransomware",
    url: "https://dailydarkweb.net/category/ransomware-news/feed/",
    tier: 1,
    category: "ransomware",
    targets: ["threat_group_events", "ransomware_events", "underground_intel"],
    enabled: false, // Covered by main feed
  },
  {
    id: "dailydarkweb-breaches",
    name: "Daily Dark Web — Data Breaches",
    url: "https://dailydarkweb.net/category/data-breaches/feed/",
    tier: 1,
    category: "breach",
    targets: ["threat_group_events", "underground_intel", "incident_reports"],
    enabled: false, // Covered by main feed
  },
  {
    id: "ransomware-live",
    name: "Ransomware.live",
    url: "https://ransomware.live/rss.xml",
    tier: 1,
    category: "ransomware",
    targets: ["ransomware_events", "underground_intel"],
    enabled: true,
  },
  {
    id: "databreaches-net",
    name: "DataBreaches.net",
    url: "https://databreaches.net/feed/",
    tier: 1,
    category: "breach",
    targets: ["underground_intel", "incident_reports"],
    enabled: true,
  },
  {
    id: "bleepingcomputer",
    name: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    tier: 1,
    category: "general",
    targets: ["incident_reports", "underground_intel"],
    enabled: true,
  },
  {
    id: "hackernews",
    name: "The Hacker News",
    url: "https://feeds.feedburner.com/TheHackersNews",
    tier: 1,
    category: "threat_intel",
    targets: ["incident_reports", "underground_intel"],
    enabled: true,
  },
  {
    id: "therecord",
    name: "The Record (Recorded Future)",
    url: "https://therecord.media/feed",
    tier: 1,
    category: "threat_intel",
    targets: ["incident_reports", "underground_intel", "threat_group_events"],
    enabled: true,
  },
  // ── Tier 2: Threat Intel & Zero-Day ──
  {
    id: "krebsonsecurity",
    name: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    tier: 2,
    category: "threat_intel",
    targets: ["incident_reports"],
    enabled: true,
  },
  {
    id: "darkreading",
    name: "Dark Reading",
    url: "https://www.darkreading.com/rss.xml",
    tier: 2,
    category: "general",
    targets: ["incident_reports", "underground_intel"],
    enabled: true,
  },
  {
    id: "cisa-alerts",
    name: "CISA Cybersecurity Advisories",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    tier: 2,
    category: "zero_day",
    targets: ["incident_reports"],
    enabled: true,
  },
  {
    id: "sans-isc",
    name: "SANS Internet Storm Center",
    url: "https://isc.sans.edu/rssfeed_full.xml",
    tier: 2,
    category: "threat_intel",
    targets: ["incident_reports"],
    enabled: true,
  },
  // ── Tier 3: Vendor Threat Research ──
  {
    id: "mandiant",
    name: "Mandiant (Google)",
    url: "https://www.mandiant.com/resources/blog/rss.xml",
    tier: 3,
    category: "vendor_research",
    targets: ["incident_reports", "threat_group_events"],
    enabled: true,
  },
  {
    id: "unit42",
    name: "Unit 42 (Palo Alto)",
    url: "https://unit42.paloaltonetworks.com/feed/",
    tier: 3,
    category: "vendor_research",
    targets: ["incident_reports", "threat_group_events"],
    enabled: true,
  },
  {
    id: "talos",
    name: "Talos Intelligence (Cisco)",
    url: "https://blog.talosintelligence.com/rss/",
    tier: 3,
    category: "vendor_research",
    targets: ["incident_reports"],
    enabled: true,
  },
  {
    id: "microsoft-security",
    name: "Microsoft Security Blog",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    tier: 3,
    category: "vendor_research",
    targets: ["incident_reports", "threat_group_events"],
    enabled: true,
  },
  {
    id: "sentinelone",
    name: "SentinelOne Labs",
    url: "https://www.sentinelone.com/labs/feed/",
    tier: 3,
    category: "vendor_research",
    targets: ["incident_reports"],
    enabled: true,
  },
  // ── Tier 4: Geopolitical & OSINT ──
  {
    id: "bellingcat",
    name: "Bellingcat",
    url: "https://www.bellingcat.com/feed/",
    tier: 4,
    category: "geopolitical",
    targets: ["incident_reports"],
    enabled: true,
  },
];

// ─── Known Threat Groups for Extraction ─────────────────────────────

const KNOWN_THREAT_GROUPS = [
  // Ransomware
  "Qilin", "Dragonforce", "Akira", "Play", "Rhysida", "Anubis",
  "FULCRUMSEC", "FulcrumSec", "Vect", "AiLock", "RuskiNet",
  "LockBit", "BlackCat", "ALPHV", "Cl0p", "Clop",
  "RansomHub", "Medusa", "BianLian", "Black Basta", "Royal",
  "Hunters International", "INC Ransom", "Cactus", "8Base",
  "NoEscape", "Trigona", "Snatch", "Vice Society", "Karakurt",
  "BlackByte", "Hive", "Cuba", "Conti", "REvil", "Sodinokibi",
  "DarkSide", "BlackMatter", "Ragnar Locker", "Everest",
  "Mallox", "Fog", "Lynx", "Sarcoma", "NightSpire", "Morpheus",
  "Termite", "SafePay", "Nitrogen", "Space Bears", "Embargo",
  // APT / Nation-State
  "APT28", "APT29", "APT41", "Lazarus", "Kimsuky", "Sandworm",
  "Cozy Bear", "Fancy Bear", "Turla", "Gamaredon", "Volt Typhoon",
  "Salt Typhoon", "Silk Typhoon", "Charming Kitten", "MuddyWater",
  "Scattered Spider", "Star Blizzard", "Midnight Blizzard",
  // Hacktivist
  "Handala", "Anonymous", "KillNet", "NoName057",
  "CyberAv3ngers", "SiegedSec", "GhostSec",
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
  guid: string;
}

interface ParsedFeed {
  title: string;
  lastBuildDate: string;
  items: RSSItem[];
}

/**
 * Parse RSS/Atom XML into structured items.
 * Handles both RSS 2.0 and Atom formats.
 */
export function parseRSSXml(xml: string): ParsedFeed {
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

  // Handle Atom feeds (e.g., CISA)
  const isAtom = xml.includes("<feed") && xml.includes("xmlns=\"http://www.w3.org/2005/Atom\"");

  if (isAtom) {
    const channelTitle = getTag(xml, "title");
    const items: RSSItem[] = [];
    const entryRegex = /<entry>([\s\S]*?)<\/entry>/g;
    let entryMatch: RegExpExecArray | null;
    while ((entryMatch = entryRegex.exec(xml)) !== null) {
      const entryXml = entryMatch[1];
      const linkMatch = entryXml.match(/<link[^>]*href="([^"]*)"[^>]*\/?>/);
      items.push({
        title: getTag(entryXml, "title"),
        link: linkMatch?.[1] ?? "",
        pubDate: getTag(entryXml, "published") || getTag(entryXml, "updated"),
        categories: getAllTags(entryXml, "category").map(c => {
          const termMatch = c.match(/term="([^"]*)"/);
          return termMatch?.[1] ?? c;
        }),
        description: getTag(entryXml, "summary"),
        contentEncoded: getTag(entryXml, "content"),
        creator: getTag(entryXml, "author") ? getTag(getTag(entryXml, "author"), "name") : "",
        guid: getTag(entryXml, "id"),
      });
    }
    return { title: channelTitle, lastBuildDate: "", items };
  }

  // Standard RSS 2.0
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
      pubDate: getTag(itemXml, "pubDate") || getTag(itemXml, "dc:date"),
      categories: getAllTags(itemXml, "category"),
      description: getTag(itemXml, "description"),
      contentEncoded: getTag(itemXml, "content:encoded"),
      creator: getTag(itemXml, "dc:creator") || getTag(itemXml, "author"),
      guid: getTag(itemXml, "guid") || getTag(itemXml, "link"),
    });
  }

  return { title: channelTitle, lastBuildDate, items };
}

// ─── Event Classification ───────────────────────────────────────────

type EventCategory = "ransomware" | "credential" | "iab" | "malware" | "influence" |
  "botnet" | "phishing" | "exploit" | "data_leak" | "other";

type IncidentType = "ransomware" | "apt" | "data_breach" | "supply_chain" | "phishing" |
  "zero_day" | "ddos" | "defacement" | "espionage" | "other";

function classifyForUnderground(item: RSSItem, feed: FeedSource): EventCategory {
  const text = (item.title + " " + item.description).toLowerCase();
  if (text.includes("ransomware") || text.includes("ransom")) return "ransomware";
  if (text.includes("credential") || text.includes("password") || text.includes("leak")) return "credential";
  if (text.includes("initial access") || text.includes("access broker")) return "iab";
  if (text.includes("malware") || text.includes("trojan") || text.includes("backdoor")) return "malware";
  if (text.includes("phishing") || text.includes("social engineering")) return "phishing";
  if (text.includes("botnet") || text.includes("c2") || text.includes("command and control")) return "botnet";
  if (text.includes("exploit") || text.includes("zero-day") || text.includes("0-day") || text.includes("cve-")) return "exploit";
  if (text.includes("data breach") || text.includes("data leak") || text.includes("exfiltrat")) return "data_leak";
  if (text.includes("influence") || text.includes("disinformation")) return "influence";
  if (feed.category === "ransomware") return "ransomware";
  if (feed.category === "breach") return "data_leak";
  return "other";
}

function classifyIncidentType(item: RSSItem): IncidentType {
  const text = (item.title + " " + item.description).toLowerCase();
  if (text.includes("ransomware") || text.includes("ransom")) return "ransomware";
  if (text.includes("apt") || text.includes("nation-state") || text.includes("espionage")) return "apt";
  if (text.includes("supply chain") || text.includes("supply-chain")) return "supply_chain";
  if (text.includes("phishing")) return "phishing";
  if (text.includes("zero-day") || text.includes("0-day") || text.includes("cve-")) return "zero_day";
  if (text.includes("ddos") || text.includes("denial of service")) return "ddos";
  if (text.includes("defac")) return "defacement";
  if (text.includes("data breach") || text.includes("data leak")) return "data_breach";
  return "other";
}

function assessSeverity(item: RSSItem): "critical" | "high" | "medium" | "low" {
  const text = (item.title + " " + item.description).toLowerCase();
  if (text.includes("government") || text.includes("military") || text.includes("critical infrastructure") ||
      text.includes("healthcare") || text.includes("hospital") || text.includes("federal") ||
      text.includes("zero-day") || text.includes("actively exploited")) {
    return "critical";
  }
  if (text.includes("ransomware") || text.includes("data breach") || text.includes("exfiltrat") ||
      text.includes("million") || text.includes("database") || text.includes("cve-")) {
    return "high";
  }
  if (text.includes("unauthorized access") || text.includes("credentials") || text.includes("vulnerability")) {
    return "medium";
  }
  return "medium";
}

/**
 * Extract threat actor name from article title and categories.
 */
function extractThreatActor(item: RSSItem): string | null {
  const fullText = item.title + " " + item.categories.join(" ");
  for (const group of KNOWN_THREAT_GROUPS) {
    if (fullText.toLowerCase().includes(group.toLowerCase())) {
      return group;
    }
  }
  // Pattern-based extraction
  const patterns = [
    /(?:by|from|attributed to|linked to)\s+(?:the\s+)?(\w[\w\s]{2,30}?)(?:\s+(?:group|gang|ransomware|threat actor|APT|hackers?))/i,
    /^(\w[\w\s]*?)\s+(?:Hacks?|Attacks?|Breaches?|Claims?|Targets?)\s/i,
  ];
  for (const pattern of patterns) {
    const m = fullText.match(pattern);
    if (m?.[1] && m[1].length < 40 && m[1].length > 2) {
      return m[1].trim();
    }
  }
  return null;
}

/**
 * Extract CVE IDs from text.
 */
function extractCVEs(text: string): string[] {
  const cvePattern = /CVE-\d{4}-\d{4,7}/gi;
  const matches = text.match(cvePattern) || [];
  return [...new Set(matches.map(c => c.toUpperCase()))];
}

/**
 * Generate a deterministic source ID for deduplication.
 */
function makeSourceId(feedId: string, item: RSSItem): string {
  const raw = item.guid || item.link || (item.title + item.pubDate);
  // Simple hash
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = ((hash << 5) - hash + raw.charCodeAt(i)) | 0;
  }
  return `${feedId}:${Math.abs(hash).toString(36)}`;
}

// ─── Database Ingestion ─────────────────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

export interface FeedSyncResult {
  feedId: string;
  feedName: string;
  tier: number;
  itemsFetched: number;
  threatGroupEventsIngested: number;
  ransomwareEventsIngested: number;
  undergroundEventsIngested: number;
  incidentReportsIngested: number;
  actorsUpdated: number;
  duplicatesSkipped: number;
  errors: string[];
}

/**
 * Fetch and ingest a single RSS feed into all target tables.
 */
export async function fetchAndIngestFeed(feed: FeedSource): Promise<FeedSyncResult> {
  const result: FeedSyncResult = {
    feedId: feed.id,
    feedName: feed.name,
    tier: feed.tier,
    itemsFetched: 0,
    threatGroupEventsIngested: 0,
    ransomwareEventsIngested: 0,
    undergroundEventsIngested: 0,
    incidentReportsIngested: 0,
    actorsUpdated: 0,
    duplicatesSkipped: 0,
    errors: [],
  };

  try {
    const response = await fetch(feed.url, {
      headers: { "User-Agent": "AC3-ThreatIntel/2.0 (Multi-Source RSS Aggregator)" },
      signal: AbortSignal.timeout(20000),
    });

    if (!response.ok) {
      result.errors.push(`HTTP ${response.status}: ${response.statusText}`);
      await updateFeedRegistry(feed, "error", `HTTP ${response.status}`);
      return result;
    }

    const xml = await response.text();
    const parsed = parseRSSXml(xml);
    result.itemsFetched = parsed.items.length;

    const db = await requireDb();
    const updatedActors = new Set<string>();

    for (const item of parsed.items) {
      const sourceId = makeSourceId(feed.id, item);
      const severity = assessSeverity(item);
      const actorName = extractThreatActor(item);
      const cves = extractCVEs(item.title + " " + item.description + " " + (item.contentEncoded || ""));
      const cleanDesc = (item.description || "").replace(/<[^>]+>/g, "").replace(/&[^;]+;/g, " ").trim();
      const pubDate = item.pubDate ? new Date(item.pubDate) : new Date();

      // ── 1. Threat Group Events ──
      if (feed.targets.includes("threat_group_events") && actorName) {
        const actorId = actorName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
        try {
          const [existing] = await db.select({ id: threatGroupEvents.id }).from(threatGroupEvents)
            .where(sql`${threatGroupEvents.tgeSourceUrl} = ${item.link} AND ${threatGroupEvents.tgeActorId} = ${actorId}`)
            .limit(1);

          if (!existing) {
            const [existingActor] = await db.select().from(threatActors)
              .where(sql`LOWER(${threatActors.name}) = ${actorName.toLowerCase()} OR ${threatActors.actorId} = ${actorId}`)
              .limit(1);
            const resolvedActorId = existingActor?.actorId ?? actorId;

            await db.insert(threatGroupEvents).values({
              tgeActorId: resolvedActorId,
              eventType: classifyForUnderground(item, feed) === "ransomware" ? "ransomware_claim" : "attack",
              tgeTitle: item.title.substring(0, 500),
              tgeDescription: cleanDesc.substring(0, 2000),
              tgeSeverity: severity,
              tgeVictimName: "See article",
              tgeMitreTechniques: cves.length > 0 ? ["T1190"] : ["T1190"],
              tgeIocs: cves,
              tgeSource: `${feed.name} (RSS)`,
              tgeSourceUrl: item.link,
              tgeConfidence: feed.tier <= 2 ? 75 : 60,
              eventDate: pubDate,
            });
            result.threatGroupEventsIngested++;

            // Update actor lastActive
            if (existingActor && !updatedActors.has(resolvedActorId)) {
              await db.update(threatActors).set({
                lastActive: pubDate.toISOString().substring(0, 7),
              }).where(eq(threatActors.actorId, resolvedActorId));
              updatedActors.add(resolvedActorId);
              result.actorsUpdated++;
            }
          } else {
            result.duplicatesSkipped++;
          }
        } catch (e: any) {
          result.errors.push(`TGE: ${e.message?.substring(0, 100)}`);
        }
      }

      // ── 2. Ransomware Events ──
      if (feed.targets.includes("ransomware_events") && classifyForUnderground(item, feed) === "ransomware") {
        try {
          const [existing] = await db.select({ id: ransomwareEvents.id }).from(ransomwareEvents)
            .where(sql`${ransomwareEvents.sourceUrl} = ${item.link}`)
            .limit(1);

          if (!existing) {
            await db.insert(ransomwareEvents).values({
              groupName: actorName || "Unknown",
              victimName: item.title.substring(0, 500),
              victimSector: null,
              victimCountry: null,
              claimDate: pubDate,
              sourceUrl: item.link,
              source: feed.name,
              status: "claimed",
            });
            result.ransomwareEventsIngested++;

            // Also update ransomwareGroups stats if actor is known
            if (actorName) {
              try {
                const [rwGroup] = await db.select().from(ransomwareGroups)
                  .where(sql`LOWER(${ransomwareGroups.groupName}) = ${actorName.toLowerCase()}`)
                  .limit(1);
                if (rwGroup) {
                  await db.update(ransomwareGroups).set({
                    lastActive: pubDate.toISOString().substring(0, 7),
                    victims30d: sql`${ransomwareGroups.victims30D} + 1`,
                    totalVictims: sql`${ransomwareGroups.totalVictims} + 1`,
                  }).where(eq(ransomwareGroups.id, rwGroup.id));
                }
              } catch { /* ignore */ }
            }
          } else {
            result.duplicatesSkipped++;
          }
        } catch (e: any) {
          result.errors.push(`RE: ${e.message?.substring(0, 100)}`);
        }
      }

      // ── 3. Underground Intel Events ──
      if (feed.targets.includes("underground_intel")) {
        try {
          const [existing] = await db.select({ id: undergroundIntelEvents.id }).from(undergroundIntelEvents)
            .where(sql`${undergroundIntelEvents.sourceUrl} = ${item.link} AND ${undergroundIntelEvents.source} = ${feed.id}`)
            .limit(1);

          if (!existing) {
            const uieCategory = classifyForUnderground(item, feed);
            await db.insert(undergroundIntelEvents).values({
              category: uieCategory,
              source: feed.id,
              title: item.title.substring(0, 500),
              summary: cleanDesc.substring(0, 2000),
              actorName: actorName || null,
              severity,
              sourceUrl: item.link,
              discoveredAt: pubDate,
              rawData: {
                feedName: feed.name,
                feedTier: feed.tier,
                categories: item.categories,
                cves,
                creator: item.creator,
              },
            });
            result.undergroundEventsIngested++;
          } else {
            result.duplicatesSkipped++;
          }
        } catch (e: any) {
          result.errors.push(`UIE: ${e.message?.substring(0, 100)}`);
        }
      }

      // ── 4. Incident Reports ──
      if (feed.targets.includes("incident_reports")) {
        try {
          const [existing] = await db.select({ id: incidentReports.id }).from(incidentReports)
            .where(sql`${incidentReports.sourceId} = ${sourceId}`)
            .limit(1);

          if (!existing) {
            await db.insert(incidentReports).values({
              sourceId,
              source: feed.id,
              title: item.title.substring(0, 1000),
              url: item.link,
              publishedAt: item.pubDate || pubDate.toISOString(),
              summary: cleanDesc.substring(0, 3000),
              threatActors: actorName ? [actorName] : [],
              cves,
              incidentType: classifyIncidentType(item),
              severity,
              status: "raw",
              rawContent: (item.contentEncoded || item.description || "").substring(0, 10000),
            });
            result.incidentReportsIngested++;
          } else {
            result.duplicatesSkipped++;
          }
        } catch (e: any) {
          result.errors.push(`IR: ${e.message?.substring(0, 100)}`);
        }
      }
    }

    // Update feed registry with success
    await updateFeedRegistry(feed, "healthy", null, result.itemsFetched);
    return result;

  } catch (e: any) {
    result.errors.push(`Fetch failed: ${e.message}`);
    await updateFeedRegistry(feed, "error", e.message);
    return result;
  }
}

// ─── Feed Registry Management ───────────────────────────────────────

async function updateFeedRegistry(
  feed: FeedSource,
  status: "healthy" | "error" | "degraded",
  errorMsg: string | null,
  itemCount?: number,
) {
  try {
    const db = await requireDb();
    const [existing] = await db.select().from(darkwebFeedRegistry)
      .where(eq(darkwebFeedRegistry.feedName, feed.id))
      .limit(1);

    if (existing) {
      await db.update(darkwebFeedRegistry).set({
        status,
        lastFetchAt: new Date(),
        lastError: errorMsg,
        ...(itemCount !== undefined ? { itemsLastFetch: itemCount } : {}),
      }).where(eq(darkwebFeedRegistry.id, existing.id));
    } else {
      await db.insert(darkwebFeedRegistry).values({
        feedName: feed.id,
        feedUrl: feed.url,
        feedType: feed.category === "ransomware" ? "ransomware" :
                  feed.category === "breach" ? "credential" :
                  feed.category === "zero_day" ? "vulnerability" : "other",
        provider: feed.name,
        status: status as any,
        lastFetchAt: new Date(),
        lastError: errorMsg,
        itemsLastFetch: itemCount ?? 0,
      });
    }
  } catch { /* non-critical */ }
}

// ─── Full Multi-Source Sync ─────────────────────────────────────────

export interface FullMultiSourceSyncResult {
  totalFeeds: number;
  feedsSucceeded: number;
  feedsFailed: number;
  totalItemsFetched: number;
  totalThreatGroupEvents: number;
  totalRansomwareEvents: number;
  totalUndergroundEvents: number;
  totalIncidentReports: number;
  totalActorsUpdated: number;
  totalDuplicatesSkipped: number;
  feedResults: FeedSyncResult[];
  duration: number;
}

/**
 * Sync all enabled RSS feeds across all tiers.
 * Optionally filter by tier (1-4) or sync all.
 */
export async function syncAllThreatIntelFeeds(
  options: { tiers?: number[]; feedIds?: string[] } = {}
): Promise<FullMultiSourceSyncResult> {
  const start = Date.now();
  let feeds = THREAT_INTEL_FEEDS.filter(f => f.enabled);

  if (options.tiers?.length) {
    feeds = feeds.filter(f => options.tiers!.includes(f.tier));
  }
  if (options.feedIds?.length) {
    feeds = feeds.filter(f => options.feedIds!.includes(f.id));
  }

  const feedResults: FeedSyncResult[] = [];

  for (const feed of feeds) {
    console.log(`[ThreatIntelRSS] Syncing ${feed.name} (Tier ${feed.tier})...`);
    const result = await fetchAndIngestFeed(feed);
    feedResults.push(result);
    // Polite delay between feeds
    await new Promise(r => setTimeout(r, 800));
  }

  const totals: FullMultiSourceSyncResult = {
    totalFeeds: feeds.length,
    feedsSucceeded: feedResults.filter(r => r.errors.length === 0).length,
    feedsFailed: feedResults.filter(r => r.errors.length > 0 && r.itemsFetched === 0).length,
    totalItemsFetched: feedResults.reduce((s, r) => s + r.itemsFetched, 0),
    totalThreatGroupEvents: feedResults.reduce((s, r) => s + r.threatGroupEventsIngested, 0),
    totalRansomwareEvents: feedResults.reduce((s, r) => s + r.ransomwareEventsIngested, 0),
    totalUndergroundEvents: feedResults.reduce((s, r) => s + r.undergroundEventsIngested, 0),
    totalIncidentReports: feedResults.reduce((s, r) => s + r.incidentReportsIngested, 0),
    totalActorsUpdated: feedResults.reduce((s, r) => s + r.actorsUpdated, 0),
    totalDuplicatesSkipped: feedResults.reduce((s, r) => s + r.duplicatesSkipped, 0),
    feedResults,
    duration: Date.now() - start,
  };

  console.log(`[ThreatIntelRSS] Full sync complete: ${totals.totalFeeds} feeds, ${totals.totalItemsFetched} items, ${totals.totalThreatGroupEvents} TGE, ${totals.totalRansomwareEvents} RE, ${totals.totalUndergroundEvents} UIE, ${totals.totalIncidentReports} IR (${totals.duration}ms)`);
  return totals;
}

/**
 * Get feed health status for all registered feeds.
 */
export function getFeedCatalog(): { enabled: FeedSource[]; disabled: FeedSource[] } {
  return {
    enabled: THREAT_INTEL_FEEDS.filter(f => f.enabled),
    disabled: THREAT_INTEL_FEEDS.filter(f => !f.enabled),
  };
}

// ─── Exports for testing ────────────────────────────────────────────

export { extractThreatActor, classifyForUnderground, classifyIncidentType, assessSeverity, extractCVEs, makeSourceId };
export type { RSSItem, ParsedFeed, FeedSyncResult as RSSFetchResult };
