import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  ransomwareGroups,
  threatActors,
  threatGroupEvents
} from "./chunk-GM677ZS3.js";
import "./chunk-KFQGP6VL.js";

// server/lib/dailydarkweb-rss.ts
init_db();
init_schema();
import { eq, sql } from "drizzle-orm";
var DDW_RSS_FEEDS = [
  { url: "https://dailydarkweb.net/feed/", category: "all", label: "Main Feed" },
  { url: "https://dailydarkweb.net/category/ransomware-news/feed/", category: "ransomware-news", label: "Ransomware News" },
  { url: "https://dailydarkweb.net/category/data-breaches/feed/", category: "data-breaches", label: "Data Breaches" },
  { url: "https://dailydarkweb.net/category/cyber-attacks/feed/", category: "cyber-attacks", label: "Cyber Attacks" },
  { url: "https://dailydarkweb.net/category/unauthorized-accesses/feed/", category: "unauthorized-accesses", label: "Unauthorized Access" }
];
var KNOWN_THREAT_GROUPS = [
  "Qilin",
  "Dragonforce",
  "Akira",
  "Play",
  "Rhysida",
  "Anubis",
  "FULCRUMSEC",
  "FulcrumSec",
  "Vect",
  "AiLock",
  "RuskiNet",
  "Handala",
  "LockBit",
  "BlackCat",
  "ALPHV",
  "Cl0p",
  "Clop",
  "RansomHub",
  "Medusa",
  "BianLian",
  "Black Basta",
  "Royal",
  "Hunters International",
  "INC Ransom",
  "Cactus",
  "8Base",
  "NoEscape",
  "Trigona",
  "Snatch",
  "Vice Society",
  "Karakurt",
  "BlackByte",
  "Hive",
  "Cuba",
  "Conti",
  "REvil",
  "Sodinokibi",
  "DarkSide",
  "BlackMatter",
  "Ragnar Locker",
  "Everest",
  "Mallox",
  "Fog",
  "Lynx",
  "Sarcoma",
  "NightSpire",
  "Morpheus",
  "Termite",
  "SafePay",
  "Nitrogen",
  "Space Bears",
  "Embargo"
];
function parseRSSXml(xml) {
  const getTag = (src, tag) => {
    const re = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([\\s\\S]*?)</${tag}>`);
    const m = src.match(re);
    return (m?.[1] ?? m?.[2] ?? "").trim();
  };
  const getAllTags = (src, tag) => {
    const re = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "g");
    const results = [];
    let m;
    while ((m = re.exec(src)) !== null) {
      results.push((m[1] ?? m[2] ?? "").trim());
    }
    return results;
  };
  const channelTitle = getTag(xml, "title");
  const lastBuildDate = getTag(xml, "lastBuildDate");
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let itemMatch;
  while ((itemMatch = itemRegex.exec(xml)) !== null) {
    const itemXml = itemMatch[1];
    items.push({
      title: getTag(itemXml, "title"),
      link: getTag(itemXml, "link"),
      pubDate: getTag(itemXml, "pubDate"),
      categories: getAllTags(itemXml, "category"),
      description: getTag(itemXml, "description"),
      contentEncoded: getTag(itemXml, "content:encoded"),
      creator: getTag(itemXml, "dc:creator")
    });
  }
  return { title: channelTitle, lastBuildDate, items };
}
function extractThreatActor(item) {
  for (const group of KNOWN_THREAT_GROUPS) {
    if (item.title.toLowerCase().includes(group.toLowerCase())) {
      return group;
    }
  }
  for (const cat of item.categories) {
    for (const group of KNOWN_THREAT_GROUPS) {
      if (cat.toLowerCase() === group.toLowerCase()) {
        return group;
      }
    }
  }
  const titlePatterns = [
    /^(\w[\w\s]*?)\s+(?:Hacks?|Attacks?|Breaches?|Claims?|Targets?)\s/i,
    /Ransomware Attack by (\w[\w\s]*?)(?:\s+Group)?$/i,
    /(?:by|from)\s+(\w[\w\s]*?)(?:\s+Group|\s+Ransomware)?$/i
  ];
  for (const pattern of titlePatterns) {
    const m = item.title.match(pattern);
    if (m?.[1] && m[1].length < 40) {
      return m[1].trim();
    }
  }
  return null;
}
function assessSeverity(item) {
  const text = (item.title + " " + item.description + " " + item.contentEncoded).toLowerCase();
  if (text.includes("government") || text.includes("military") || text.includes("critical infrastructure") || text.includes("healthcare") || text.includes("hospital") || text.includes("federal")) {
    return "critical";
  }
  if (text.includes("ransomware") || text.includes("data breach") || text.includes("exfiltrat") || text.includes("million") || text.includes("database")) {
    return "high";
  }
  if (text.includes("unauthorized access") || text.includes("credentials") || text.includes("defac")) {
    return "medium";
  }
  return "medium";
}
function classifyEventType(item) {
  const cats = item.categories.map((c) => c.toLowerCase());
  if (cats.includes("ransomware news") || cats.some((c) => c.includes("ransomware"))) return "ransomware_claim";
  if (cats.includes("data-breaches") || cats.includes("data breaches")) return "data_leak";
  if (item.title.toLowerCase().includes("defac")) return "defacement";
  return "attack";
}
function extractVictims(item) {
  const victims = [];
  const boldPattern = /<strong>([^<]+)<\/strong>/g;
  let m;
  const content = item.contentEncoded || item.description;
  while ((m = boldPattern.exec(content)) !== null) {
    const name = m[1].trim();
    if (name.length > 2 && name.length < 100 && !name.toLowerCase().includes("according") && !name.toLowerCase().includes("the ") && !name.toLowerCase().includes("note:") && !name.match(/^\d/)) {
      const surrounding = content.substring(Math.max(0, m.index - 20), m.index + m[0].length + 50);
      const countryMatch = surrounding.match(/\(([^)]+)\)/);
      victims.push({
        name,
        country: countryMatch?.[1]?.replace(/[^\w\s]/g, "").trim() || void 0
      });
    }
  }
  return victims.slice(0, 10);
}
function processItem(item) {
  const actorName = extractThreatActor(item);
  if (!actorName) return null;
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
    categories: item.categories
  };
}
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function fetchAndIngestFeed(feedUrl, feedLabel) {
  const result = {
    feed: feedLabel,
    itemsFetched: 0,
    eventsExtracted: 0,
    eventsIngested: 0,
    actorsUpdated: 0,
    errors: []
  };
  try {
    const response = await fetch(feedUrl, {
      headers: { "User-Agent": "AC3-ThreatIntel/1.0 (Darkweb Feed Aggregator)" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) {
      result.errors.push(`HTTP ${response.status}: ${response.statusText}`);
      return result;
    }
    const xml = await response.text();
    const feed = parseRSSXml(xml);
    result.itemsFetched = feed.items.length;
    const db = await requireDb();
    const updatedActors = /* @__PURE__ */ new Set();
    for (const item of feed.items) {
      const event = processItem(item);
      if (!event) continue;
      result.eventsExtracted++;
      const [existing] = await db.select().from(threatGroupEvents).where(sql`${threatGroupEvents.tgeSourceUrl} = ${event.sourceUrl} AND ${threatGroupEvents.tgeActorId} = ${event.actorId}`).limit(1);
      if (existing) continue;
      const [existingActor] = await db.select().from(threatActors).where(sql`LOWER(${threatActors.name}) = ${event.actorName.toLowerCase()} OR ${threatActors.actorId} = ${event.actorId}`).limit(1);
      const resolvedActorId = existingActor?.actorId ?? event.actorId;
      try {
        await db.insert(threatGroupEvents).values({
          tgeActorId: resolvedActorId,
          eventType: event.eventType === "ransomware_claim" ? "attack" : event.eventType,
          tgeTitle: event.title.substring(0, 500),
          tgeDescription: event.description.substring(0, 2e3),
          tgeSeverity: event.severity,
          tgeVictimName: event.victims[0]?.name ?? "Unknown",
          tgeVictimSector: event.victims[0]?.sector ?? null,
          tgeVictimCountry: event.victims[0]?.country ?? null,
          tgeMitreTechniques: event.eventType === "ransomware_claim" ? ["T1486"] : ["T1190"],
          tgeIocs: [],
          tgeSource: "Daily Dark Web (RSS)",
          tgeSourceUrl: event.sourceUrl,
          tgeConfidence: 70,
          eventDate: new Date(event.pubDate)
        });
        result.eventsIngested++;
      } catch (e) {
        result.errors.push(`Event insert failed: ${e.message}`);
      }
      if (existingActor && !updatedActors.has(resolvedActorId)) {
        try {
          await db.update(threatActors).set({
            lastActive: new Date(event.pubDate).toISOString().substring(0, 7)
            // YYYY-MM
          }).where(eq(threatActors.actorId, resolvedActorId));
          updatedActors.add(resolvedActorId);
          result.actorsUpdated++;
        } catch {
        }
      }
      if (event.eventType === "ransomware_claim") {
        try {
          const [rwGroup] = await db.select().from(ransomwareGroups).where(sql`LOWER(${ransomwareGroups.groupName}) = ${event.actorName.toLowerCase()}`).limit(1);
          if (rwGroup) {
            await db.update(ransomwareGroups).set({
              lastActive: new Date(event.pubDate).toISOString().substring(0, 7),
              victims7d: sql`${ransomwareGroups.victims7D} + 1`,
              victims30d: sql`${ransomwareGroups.victims30D} + 1`,
              totalVictims: sql`${ransomwareGroups.totalVictims} + ${event.victims.length || 1}`
            }).where(eq(ransomwareGroups.id, rwGroup.id));
          }
        } catch {
        }
      }
    }
    return result;
  } catch (e) {
    result.errors.push(`Fetch failed: ${e.message}`);
    return result;
  }
}
async function syncDailyDarkWebRSS(useAllFeeds = false) {
  const start = Date.now();
  const feeds = useAllFeeds ? DDW_RSS_FEEDS : [DDW_RSS_FEEDS[0]];
  const feedResults = [];
  for (const feed of feeds) {
    const result = await fetchAndIngestFeed(feed.url, feed.label);
    feedResults.push(result);
    if (feeds.length > 1) await new Promise((r) => setTimeout(r, 1e3));
  }
  const totals = {
    totalItemsFetched: feedResults.reduce((s, r) => s + r.itemsFetched, 0),
    totalEventsExtracted: feedResults.reduce((s, r) => s + r.eventsExtracted, 0),
    totalEventsIngested: feedResults.reduce((s, r) => s + r.eventsIngested, 0),
    totalActorsUpdated: feedResults.reduce((s, r) => s + r.actorsUpdated, 0),
    feedResults,
    duration: Date.now() - start
  };
  console.log(`[DailyDarkWeb RSS] Sync complete: ${totals.totalItemsFetched} items fetched, ${totals.totalEventsExtracted} events extracted, ${totals.totalEventsIngested} ingested, ${totals.totalActorsUpdated} actors updated (${totals.duration}ms)`);
  return totals;
}
export {
  DDW_RSS_FEEDS,
  assessSeverity,
  classifyEventType,
  extractThreatActor,
  extractVictims,
  fetchAndIngestFeed,
  parseRSSXml,
  processItem,
  syncDailyDarkWebRSS
};
