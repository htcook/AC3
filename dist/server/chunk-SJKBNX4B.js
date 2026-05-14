import {
  autoDiscoverGroup,
  recordGroupEvent
} from "./chunk-53N6MU6I.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-TP4TYLYW.js";
import {
  getDb,
  init_db
} from "./chunk-JP5I5SRV.js";
import {
  incidentReports,
  init_schema,
  threatActorIocs,
  threatActors,
  threatIntelUpdates
} from "./chunk-FLBHZBVD.js";

// server/lib/threat-actor-crawler.ts
init_llm();
init_db();
init_schema();
import { eq, and, like, or, inArray } from "drizzle-orm";
import crypto from "crypto";
var CRAWL_SOURCES = [
  // ── Security News ──
  {
    id: "the_hacker_news",
    name: "The Hacker News",
    type: "rss",
    url: "https://feeds.feedburner.com/TheHackersNews",
    category: "news",
    refreshIntervalMs: 18e5,
    enabled: true,
    priority: 9
  },
  {
    id: "dark_reading",
    name: "Dark Reading",
    type: "rss",
    url: "https://www.darkreading.com/rss.xml",
    category: "news",
    refreshIntervalMs: 18e5,
    enabled: true,
    priority: 8
  },
  {
    id: "bleeping_computer",
    name: "BleepingComputer",
    type: "rss",
    url: "https://www.bleepingcomputer.com/feed/",
    category: "news",
    refreshIntervalMs: 18e5,
    enabled: true,
    priority: 9
  },
  {
    id: "cyberscoop",
    name: "CyberScoop",
    type: "rss",
    url: "https://cyberscoop.com/feed/",
    category: "news",
    refreshIntervalMs: 36e5,
    enabled: true,
    priority: 7
  },
  {
    id: "the_record",
    name: "The Record by Recorded Future",
    type: "rss",
    url: "https://therecord.media/feed",
    category: "news",
    refreshIntervalMs: 18e5,
    enabled: true,
    priority: 9
  },
  {
    id: "security_affairs",
    name: "Security Affairs",
    type: "rss",
    url: "https://securityaffairs.com/feed",
    category: "news",
    refreshIntervalMs: 36e5,
    enabled: true,
    priority: 7
  },
  {
    id: "krebs_on_security",
    name: "Krebs on Security",
    type: "rss",
    url: "https://krebsonsecurity.com/feed/",
    category: "news",
    refreshIntervalMs: 72e5,
    enabled: true,
    priority: 8
  },
  // ── Security Research ──
  {
    id: "mandiant_blog",
    name: "Mandiant Blog",
    type: "rss",
    url: "https://www.mandiant.com/resources/blog/rss.xml",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 10
  },
  {
    id: "crowdstrike_blog",
    name: "CrowdStrike Blog",
    type: "rss",
    url: "https://www.crowdstrike.com/blog/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 10
  },
  {
    id: "microsoft_threat",
    name: "Microsoft Threat Intelligence",
    type: "rss",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 10
  },
  {
    id: "unit42",
    name: "Unit 42 (Palo Alto)",
    type: "rss",
    url: "https://unit42.paloaltonetworks.com/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 9
  },
  {
    id: "talos_intelligence",
    name: "Cisco Talos",
    type: "rss",
    url: "https://blog.talosintelligence.com/feeds/posts/default",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 9
  },
  {
    id: "sentinelone_labs",
    name: "SentinelOne Labs",
    type: "rss",
    url: "https://www.sentinelone.com/labs/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 8
  },
  {
    id: "welivesecurity",
    name: "WeLiveSecurity (ESET)",
    type: "rss",
    url: "https://www.welivesecurity.com/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 8
  },
  {
    id: "securelist",
    name: "Securelist (Kaspersky)",
    type: "rss",
    url: "https://securelist.com/feed/",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 9
  },
  {
    id: "proofpoint_blog",
    name: "Proofpoint Threat Insight",
    type: "rss",
    url: "https://www.proofpoint.com/us/blog/threat-insight/feed",
    category: "research",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 8
  },
  // ── Government Advisories ──
  {
    id: "cisa_alerts",
    name: "CISA Cybersecurity Alerts",
    type: "rss",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    category: "advisory",
    refreshIntervalMs: 36e5,
    enabled: true,
    priority: 10
  },
  {
    id: "ncsc_uk",
    name: "UK NCSC",
    type: "rss",
    url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    category: "advisory",
    refreshIntervalMs: 72e5,
    enabled: true,
    priority: 8
  },
  {
    id: "cert_eu",
    name: "CERT-EU",
    type: "rss",
    url: "https://cert.europa.eu/publications/security-advisories/rss",
    category: "advisory",
    refreshIntervalMs: 72e5,
    enabled: true,
    priority: 7
  },
  // ── Breach / Ransomware Tracking ──
  {
    id: "ransomware_live",
    name: "Ransomware.live",
    type: "api",
    url: "https://api.ransomware.live/recentvictims",
    category: "breach",
    refreshIntervalMs: 36e5,
    enabled: true,
    priority: 9
  },
  // ── Regional / Geopolitical (Iran focus) ──
  {
    id: "iran_intl",
    name: "Iran International",
    type: "rss",
    url: "https://www.iranintl.com/en/feed",
    category: "diplomatic",
    region: "iran",
    refreshIntervalMs: 72e5,
    enabled: true,
    priority: 7
  },
  {
    id: "al_jazeera_iran",
    name: "Al Jazeera Iran Coverage",
    type: "rss",
    url: "https://www.aljazeera.com/tag/iran/rss",
    category: "diplomatic",
    region: "iran_border",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 6
  },
  {
    id: "middle_east_eye",
    name: "Middle East Eye",
    type: "rss",
    url: "https://www.middleeasteye.net/rss",
    category: "diplomatic",
    region: "iran_border",
    refreshIntervalMs: 144e5,
    enabled: true,
    priority: 6
  }
];
var crawlRunning = false;
var lastCrawlResult = null;
var sourceFailCounts = /* @__PURE__ */ new Map();
var crawlHistory = [];
async function runIntelligenceCrawl(params) {
  if (crawlRunning) throw new Error("Crawl already in progress");
  crawlRunning = true;
  const crawlId = `crawl-${Date.now().toString(36)}`;
  const result = {
    crawlId,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    sourcesChecked: 0,
    articlesFound: 0,
    articlesProcessed: 0,
    actorsEnriched: 0,
    newActorsDiscovered: 0,
    newEventsRecorded: 0,
    newIocsFound: 0,
    newTtpsFound: 0,
    errors: [],
    summary: ""
  };
  try {
    let sources = CRAWL_SOURCES.filter((s) => s.enabled);
    if (params?.sourceIds) {
      sources = sources.filter((s) => params.sourceIds.includes(s.id));
    }
    if (params?.regionFocus) {
      sources = sources.filter((s) => !s.region || s.region === params.regionFocus || s.region?.includes(params.regionFocus));
    }
    sources.sort((a, b) => b.priority - a.priority);
    const maxPerSource = params?.maxArticlesPerSource || 20;
    const totalSources = sources.length;
    for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      result.sourcesChecked++;
      params?.onProgress?.(`Crawling ${source.name}...`, Math.round(i / totalSources * 100));
      try {
        const articles = await fetchSourceArticles(source, maxPerSource);
        result.articlesFound += articles.length;
        for (const article of articles) {
          if (params?.skipProcessed !== false) {
            const hash = hashString(article.url);
            const db = await getDb();
            if (db) {
              const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(
                eq(incidentReports.source, source.id),
                eq(incidentReports.sourceId, hash)
              )).limit(1);
              if (existing.length > 0) continue;
            }
          }
          const intel = await extractIntelligence(article, params?.actorFocus);
          result.articlesProcessed++;
          for (const mention of intel.actorMentions) {
            const matchResult = await matchActorToCatalog(mention);
            if (matchResult.matched) {
              mention.actorId = matchResult.actorId;
              await enrichActorFromIntel(matchResult.actorId, intel);
              result.actorsEnriched++;
            } else if (matchResult.isNew && mention.confidence >= 70) {
              try {
                const newId = await autoDiscoverGroup(mention.actorName, "unknown", source.id);
                mention.actorId = newId;
                result.newActorsDiscovered++;
              } catch {
              }
            }
          }
          for (const event of intel.events) {
            for (const mention of intel.actorMentions.filter((m) => m.actorId)) {
              try {
                await recordGroupEvent({
                  actorId: mention.actorId,
                  eventType: mapEventType(event.type),
                  title: event.title,
                  description: event.description,
                  severity: event.severity,
                  victimName: event.victimName,
                  victimSector: event.victimSector,
                  victimCountry: event.victimCountry,
                  source: source.id,
                  sourceUrl: article.url,
                  confidence: mention.confidence,
                  eventDate: new Date(event.date || article.publishedAt)
                });
                result.newEventsRecorded++;
              } catch {
              }
            }
          }
          for (const ioc of intel.newIocs) {
            for (const mention of intel.actorMentions.filter((m) => m.actorId)) {
              try {
                const db = await getDb();
                if (db) {
                  await db.insert(threatActorIocs).values({
                    actorId: mention.actorId,
                    iocType: ioc.type,
                    value: ioc.value,
                    description: ioc.description,
                    iocConfidence: ioc.confidence >= 80 ? "high" : ioc.confidence >= 50 ? "medium" : "low",
                    source: source.id
                  });
                  result.newIocsFound++;
                }
              } catch {
              }
            }
          }
          result.newTtpsFound += intel.newTechniques.length;
          await storeArticle(article, intel, source.id);
          await sleep(500);
        }
        source.lastCrawled = (/* @__PURE__ */ new Date()).toISOString();
        sourceFailCounts.set(source.id, 0);
      } catch (err) {
        const failCount = (sourceFailCounts.get(source.id) || 0) + 1;
        sourceFailCounts.set(source.id, failCount);
        result.errors.push(`${source.name}: ${err.message}`);
      }
    }
    result.summary = `Crawled ${result.sourcesChecked} sources, found ${result.articlesFound} articles, processed ${result.articlesProcessed}. Enriched ${result.actorsEnriched} actors, discovered ${result.newActorsDiscovered} new. Recorded ${result.newEventsRecorded} events, ${result.newIocsFound} IOCs, ${result.newTtpsFound} TTPs. ${result.errors.length} errors.`;
    result.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    await recordCrawlResult(result);
    lastCrawlResult = result;
    crawlHistory.push(result);
    if (crawlHistory.length > 50) crawlHistory.shift();
    return result;
  } finally {
    crawlRunning = false;
  }
}
async function runTargetedEnrichment(params) {
  const gaps = await analyzeDataGaps(params?.actorIds);
  const prioritized = gaps.filter((g) => g.enrichmentPriority === "critical" || g.enrichmentPriority === "high").slice(0, params?.maxActors || 20);
  if (prioritized.length === 0) {
    return {
      crawlId: `enrichment-${Date.now().toString(36)}`,
      startedAt: (/* @__PURE__ */ new Date()).toISOString(),
      completedAt: (/* @__PURE__ */ new Date()).toISOString(),
      sourcesChecked: 0,
      articlesFound: 0,
      articlesProcessed: 0,
      actorsEnriched: 0,
      newActorsDiscovered: 0,
      newEventsRecorded: 0,
      newIocsFound: 0,
      newTtpsFound: 0,
      errors: [],
      summary: "No actors require enrichment at this time."
    };
  }
  const result = {
    crawlId: `enrichment-${Date.now().toString(36)}`,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    sourcesChecked: 0,
    articlesFound: 0,
    articlesProcessed: 0,
    actorsEnriched: 0,
    newActorsDiscovered: 0,
    newEventsRecorded: 0,
    newIocsFound: 0,
    newTtpsFound: 0,
    errors: [],
    summary: ""
  };
  for (let i = 0; i < prioritized.length; i++) {
    const gap = prioritized[i];
    params?.onProgress?.(`Enriching ${gap.actorName}...`, Math.round(i / prioritized.length * 100));
    try {
      const enrichment = await llmEnrichActor(gap);
      if (enrichment) {
        await applyEnrichment(gap.actorId, enrichment);
        result.actorsEnriched++;
        result.newEventsRecorded += enrichment.newEvents?.length || 0;
        result.newIocsFound += enrichment.newIocs?.length || 0;
        result.newTtpsFound += enrichment.newTechniques?.length || 0;
      }
    } catch (err) {
      result.errors.push(`${gap.actorName}: ${err.message}`);
    }
    await sleep(1e3);
  }
  result.completedAt = (/* @__PURE__ */ new Date()).toISOString();
  result.summary = `Targeted enrichment of ${prioritized.length} actors. Enriched ${result.actorsEnriched}, ${result.newEventsRecorded} events, ${result.newIocsFound} IOCs, ${result.newTtpsFound} TTPs.`;
  lastCrawlResult = result;
  crawlHistory.push(result);
  return result;
}
async function analyzeDataGaps(actorIds) {
  const db = await getDb();
  if (!db) return [];
  let actors;
  if (actorIds && actorIds.length > 0) {
    actors = await db.select().from(threatActors).where(inArray(threatActors.actorId, actorIds));
  } else {
    actors = await db.select().from(threatActors);
  }
  const gaps = [];
  for (const actor of actors) {
    const missingFields = [];
    const suggestedSearches = [];
    if (!actor.description || actor.description.length < 50) {
      missingFields.push("description");
      suggestedSearches.push(`${actor.name} threat actor profile`);
    }
    if (!actor.motivation || actor.motivation === "unknown") {
      missingFields.push("motivation");
      suggestedSearches.push(`${actor.name} motivation objectives`);
    }
    if (!actor.origin || actor.origin === "Unknown") {
      missingFields.push("origin");
      suggestedSearches.push(`${actor.name} country origin attribution`);
    }
    if (!actor.firstSeen) {
      missingFields.push("firstSeen");
      suggestedSearches.push(`${actor.name} first observed activity`);
    }
    if (!actor.targetSectors || actor.targetSectors?.length === 0) {
      missingFields.push("targetSectors");
      suggestedSearches.push(`${actor.name} targeted industries sectors`);
    }
    if (!actor.targetRegions || actor.targetRegions?.length === 0) {
      missingFields.push("targetRegions");
      suggestedSearches.push(`${actor.name} targeted countries regions`);
    }
    if (!actor.techniques || actor.techniques?.length === 0) {
      missingFields.push("techniques");
      suggestedSearches.push(`${actor.name} MITRE ATT&CK techniques TTPs`);
    }
    if (!actor.tools || actor.tools?.length === 0) {
      missingFields.push("tools");
      suggestedSearches.push(`${actor.name} tools software used`);
    }
    if (!actor.malware || actor.malware?.length === 0) {
      missingFields.push("malware");
      suggestedSearches.push(`${actor.name} malware families`);
    }
    if (!actor.activityTimeline || actor.activityTimeline?.length === 0) {
      missingFields.push("activityTimeline");
      suggestedSearches.push(`${actor.name} attack history timeline campaigns`);
    }
    if (!actor.aliases || actor.aliases?.length === 0) {
      missingFields.push("aliases");
      suggestedSearches.push(`${actor.name} aliases other names`);
    }
    const lastUpdate = actor.updatedAt ? new Date(actor.updatedAt).getTime() : 0;
    const staleness = Math.floor((Date.now() - lastUpdate) / (1e3 * 60 * 60 * 24));
    const targetConfidence = 80;
    const confidenceGap = Math.max(0, targetConfidence - (actor.confidence || 0));
    let priority = "low";
    if (missingFields.length >= 5 || staleness > 90) priority = "critical";
    else if (missingFields.length >= 3 || staleness > 60) priority = "high";
    else if (missingFields.length >= 1 || staleness > 30) priority = "medium";
    if (missingFields.length > 0 || staleness > 14) {
      gaps.push({
        actorId: actor.actorId,
        actorName: actor.name,
        missingFields,
        staleness,
        confidenceGap,
        enrichmentPriority: priority,
        suggestedSearches
      });
    }
  }
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  gaps.sort((a, b) => priorityOrder[a.enrichmentPriority] - priorityOrder[b.enrichmentPriority]);
  return gaps;
}
async function fetchSourceArticles(source, maxItems) {
  switch (source.type) {
    case "rss":
      return fetchRssArticles(source, maxItems);
    case "api":
      return fetchApiArticles(source, maxItems);
    default:
      return fetchRssArticles(source, maxItems);
  }
}
async function fetchRssArticles(source, maxItems) {
  const response = await safeFetch(source.url, {}, 2e4);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const xml = await response.text();
  const items = parseRss(xml);
  return items.slice(0, maxItems).map((item) => ({
    sourceId: source.id,
    url: item.link,
    title: item.title,
    content: stripHtml(item.content || item.description || ""),
    publishedAt: item.pubDate || (/* @__PURE__ */ new Date()).toISOString(),
    author: item.author
  }));
}
async function fetchApiArticles(source, maxItems) {
  if (source.id === "ransomware_live") {
    return fetchRansomwareLiveArticles(source, maxItems);
  }
  return [];
}
async function fetchRansomwareLiveArticles(source, maxItems) {
  const response = await safeFetch(source.url, {}, 15e3);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const victims = await response.json();
  return victims.slice(0, maxItems).map((v) => ({
    sourceId: source.id,
    url: v.post_url || `https://ransomware.live/#/victim/${v.victim}`,
    title: `${v.group_name} claims ${v.victim}`,
    content: `Ransomware group ${v.group_name} has claimed ${v.victim} (${v.country || "unknown country"}) as a victim. Activity: ${v.activity || "unknown"}. Website: ${v.website || "N/A"}. Sector: ${v.sector || "unknown"}.`,
    publishedAt: v.discovered || (/* @__PURE__ */ new Date()).toISOString()
  }));
}
async function extractIntelligence(article, actorFocus) {
  const focusInstruction = actorFocus ? `Pay special attention to these actors: ${actorFocus.join(", ")}.` : "";
  const response = await invokeLLM({
    _caller: "threat-actor-crawler.extractIntelligence",
    _priority: "bulk",
    messages: [
      {
        role: "system",
        content: `You are a cyber threat intelligence analyst. Extract structured intelligence from the following article. Identify threat actors, TTPs, IOCs, events, and geopolitical context. Be precise and factual \u2014 only extract what is explicitly stated or strongly implied. ${focusInstruction}`
      },
      {
        role: "user",
        content: `Title: ${article.title}
Source: ${article.sourceId}
Published: ${article.publishedAt}

Content:
${article.content.slice(0, 8e3)}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "intelligence_extraction",
        strict: true,
        schema: {
          type: "object",
          properties: {
            actorMentions: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  actorName: { type: "string" },
                  aliases: { type: "array", items: { type: "string" } },
                  confidence: { type: "number" },
                  context: { type: "string" }
                },
                required: ["actorName", "aliases", "confidence", "context"],
                additionalProperties: false
              }
            },
            newTechniques: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  name: { type: "string" },
                  tactic: { type: "string" },
                  description: { type: "string" }
                },
                required: ["id", "name", "tactic", "description"],
                additionalProperties: false
              }
            },
            newIocs: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string" },
                  value: { type: "string" },
                  description: { type: "string" },
                  confidence: { type: "number" }
                },
                required: ["type", "value", "description", "confidence"],
                additionalProperties: false
              }
            },
            newMalware: { type: "array", items: { type: "string" } },
            newTools: { type: "array", items: { type: "string" } },
            events: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string" },
                  title: { type: "string" },
                  description: { type: "string" },
                  severity: { type: "string" },
                  date: { type: "string" },
                  victimName: { type: "string" },
                  victimSector: { type: "string" },
                  victimCountry: { type: "string" }
                },
                required: ["type", "title", "description", "severity", "date", "victimName", "victimSector", "victimCountry"],
                additionalProperties: false
              }
            },
            geopoliticalContext: { type: "string" },
            summary: { type: "string" }
          },
          required: ["actorMentions", "newTechniques", "newIocs", "newMalware", "newTools", "events", "geopoliticalContext", "summary"],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices[0]?.message?.content || "{}";
  const parsed = JSON.parse(content);
  return {
    article,
    actorMentions: parsed.actorMentions || [],
    newTechniques: parsed.newTechniques || [],
    newIocs: parsed.newIocs || [],
    newMalware: parsed.newMalware || [],
    newTools: parsed.newTools || [],
    events: parsed.events || [],
    geopoliticalContext: parsed.geopoliticalContext,
    summary: parsed.summary || ""
  };
}
async function matchActorToCatalog(mention) {
  const db = await getDb();
  if (!db) return { matched: false, isNew: false };
  const normalizedName = mention.actorName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const directMatch = await db.select({ actorId: threatActors.actorId }).from(threatActors).where(
    or(
      eq(threatActors.actorId, normalizedName),
      eq(threatActors.name, mention.actorName),
      like(threatActors.name, `%${mention.actorName}%`)
    )
  ).limit(1);
  if (directMatch.length > 0) {
    return { matched: true, actorId: directMatch[0].actorId, isNew: false };
  }
  const allActors = await db.select({
    actorId: threatActors.actorId,
    aliases: threatActors.aliases
  }).from(threatActors);
  for (const actor of allActors) {
    const aliases = actor.aliases || [];
    const allNames = [...aliases, ...mention.aliases];
    for (const alias of allNames) {
      if (alias.toLowerCase().replace(/[^a-z0-9]/g, "") === normalizedName) {
        return { matched: true, actorId: actor.actorId, isNew: false };
      }
    }
  }
  return { matched: false, isNew: true };
}
async function enrichActorFromIntel(actorId, intel) {
  const db = await getDb();
  if (!db) return;
  const actor = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (actor.length === 0) return;
  const current = actor[0];
  const updates = {};
  if (intel.newTechniques.length > 0) {
    const existingTechniques = current.techniques || [];
    const existingIds = new Set(existingTechniques.map((t) => t.id));
    const newTechs = intel.newTechniques.filter((t) => !existingIds.has(t.id));
    if (newTechs.length > 0) {
      updates.techniques = [...existingTechniques, ...newTechs];
    }
  }
  if (intel.newMalware.length > 0) {
    const existingMalware = current.malware || [];
    const newMalware = intel.newMalware.filter((m) => !existingMalware.includes(m));
    if (newMalware.length > 0) {
      updates.malware = [...existingMalware, ...newMalware];
    }
  }
  if (intel.newTools.length > 0) {
    const existingTools = current.tools || [];
    const newTools = intel.newTools.filter((t) => !existingTools.includes(t));
    if (newTools.length > 0) {
      updates.tools = [...existingTools, ...newTools];
    }
  }
  if (intel.events.length > 0) {
    const existingTimeline = current.activityTimeline || [];
    const newEntries = intel.events.map((e) => ({
      date: e.date || intel.article.publishedAt,
      event: e.title,
      source: intel.article.sourceId
    }));
    updates.activityTimeline = [...existingTimeline, ...newEntries];
  }
  if (intel.article.publishedAt) {
    const articleDate = intel.article.publishedAt.split("T")[0];
    if (!current.lastActive || articleDate > current.lastActive) {
      updates.lastActive = articleDate;
    }
  }
  if (Object.keys(updates).length > 0 && current.confidence && current.confidence < 95) {
    updates.confidence = Math.min(95, current.confidence + 2);
  }
  if (Object.keys(updates).length > 0) {
    await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actorId));
    try {
      const { onActorEnriched } = await import("./threat-intel-auto-enrich-IY6ZABTJ.js");
      onActorEnriched(actorId).catch((err) => {
        console.warn(`[ThreatIntel] Auto-enrich profile generation failed for ${actorId}:`, err.message);
      });
    } catch (e) {
    }
  }
}
async function llmEnrichActor(gap) {
  const response = await invokeLLM({
    _caller: "threat-actor-crawler.llmEnrichActor",
    _priority: "bulk",
    messages: [
      {
        role: "system",
        content: `You are a cyber threat intelligence analyst. Fill in missing data for the following threat actor. Only provide information you are confident about. Use publicly available threat intelligence sources.`
      },
      {
        role: "user",
        content: `Threat Actor: ${gap.actorName} (ID: ${gap.actorId})
Missing fields: ${gap.missingFields.join(", ")}
Staleness: ${gap.staleness} days since last update

Please provide the missing information. For each field, include only factual, well-sourced data.`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "actor_enrichment",
        strict: true,
        schema: {
          type: "object",
          properties: {
            description: { type: "string" },
            motivation: { type: "string" },
            origin: { type: "string" },
            firstSeen: { type: "string" },
            targetSectors: { type: "array", items: { type: "string" } },
            targetRegions: { type: "array", items: { type: "string" } },
            techniques: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  name: { type: "string" },
                  tactic: { type: "string" },
                  description: { type: "string" }
                },
                required: ["id", "name", "tactic", "description"],
                additionalProperties: false
              }
            },
            tools: { type: "array", items: { type: "string" } },
            malware: { type: "array", items: { type: "string" } },
            aliases: { type: "array", items: { type: "string" } },
            activityTimeline: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  date: { type: "string" },
                  event: { type: "string" },
                  source: { type: "string" }
                },
                required: ["date", "event", "source"],
                additionalProperties: false
              }
            },
            recentEvents: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string" },
                  title: { type: "string" },
                  description: { type: "string" },
                  severity: { type: "string" },
                  date: { type: "string" }
                },
                required: ["type", "title", "description", "severity", "date"],
                additionalProperties: false
              }
            }
          },
          required: ["description", "motivation", "origin", "firstSeen", "targetSectors", "targetRegions", "techniques", "tools", "malware", "aliases", "activityTimeline", "recentEvents"],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices[0]?.message?.content || "{}";
  const parsed = JSON.parse(content);
  return {
    description: parsed.description || void 0,
    motivation: parsed.motivation || void 0,
    origin: parsed.origin || void 0,
    firstSeen: parsed.firstSeen || void 0,
    targetSectors: parsed.targetSectors?.length > 0 ? parsed.targetSectors : void 0,
    targetRegions: parsed.targetRegions?.length > 0 ? parsed.targetRegions : void 0,
    newTechniques: parsed.techniques?.length > 0 ? parsed.techniques : void 0,
    newTools: parsed.tools?.length > 0 ? parsed.tools : void 0,
    newMalware: parsed.malware?.length > 0 ? parsed.malware : void 0,
    aliases: parsed.aliases?.length > 0 ? parsed.aliases : void 0,
    activityTimeline: parsed.activityTimeline?.length > 0 ? parsed.activityTimeline : void 0,
    newEvents: parsed.recentEvents?.length > 0 ? parsed.recentEvents : void 0,
    newIocs: []
  };
}
async function applyEnrichment(actorId, enrichment) {
  const db = await getDb();
  if (!db) return;
  const actor = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (actor.length === 0) return;
  const current = actor[0];
  const updates = {};
  if (enrichment.description && (!current.description || current.description.length < 50)) {
    updates.description = enrichment.description;
  }
  if (enrichment.motivation && (!current.motivation || current.motivation === "unknown")) {
    updates.motivation = enrichment.motivation;
  }
  if (enrichment.origin && (!current.origin || current.origin === "Unknown")) {
    updates.origin = enrichment.origin;
  }
  if (enrichment.firstSeen && !current.firstSeen) {
    updates.firstSeen = enrichment.firstSeen;
  }
  if (enrichment.targetSectors && (!current.targetSectors || current.targetSectors.length === 0)) {
    updates.targetSectors = enrichment.targetSectors;
  }
  if (enrichment.targetRegions && (!current.targetRegions || current.targetRegions.length === 0)) {
    updates.targetRegions = enrichment.targetRegions;
  }
  if (enrichment.newTechniques && enrichment.newTechniques.length > 0) {
    const existing = current.techniques || [];
    const existingIds = new Set(existing.map((t) => t.id));
    const newTechs = enrichment.newTechniques.filter((t) => !existingIds.has(t.id));
    if (newTechs.length > 0) updates.techniques = [...existing, ...newTechs];
  }
  if (enrichment.newTools && enrichment.newTools.length > 0) {
    const existing = current.tools || [];
    const newTools = enrichment.newTools.filter((t) => !existing.includes(t));
    if (newTools.length > 0) updates.tools = [...existing, ...newTools];
  }
  if (enrichment.newMalware && enrichment.newMalware.length > 0) {
    const existing = current.malware || [];
    const newMalware = enrichment.newMalware.filter((m) => !existing.includes(m));
    if (newMalware.length > 0) updates.malware = [...existing, ...newMalware];
  }
  if (enrichment.aliases && enrichment.aliases.length > 0) {
    const existing = current.aliases || [];
    const newAliases = enrichment.aliases.filter((a) => !existing.includes(a));
    if (newAliases.length > 0) updates.aliases = [...existing, ...newAliases];
  }
  if (enrichment.activityTimeline && enrichment.activityTimeline.length > 0) {
    const existing = current.activityTimeline || [];
    updates.activityTimeline = [...existing, ...enrichment.activityTimeline];
  }
  if (Object.keys(updates).length > 0) {
    updates.confidence = Math.min(95, (current.confidence || 50) + 5);
    updates.dataSource = "crawler-enriched";
    await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actorId));
  }
  if (enrichment.newEvents) {
    for (const event of enrichment.newEvents) {
      try {
        await recordGroupEvent({
          actorId,
          eventType: mapEventType(event.type),
          title: event.title,
          description: event.description,
          severity: event.severity,
          source: "llm-enrichment",
          confidence: 70,
          eventDate: new Date(event.date)
        });
      } catch {
      }
    }
  }
}
async function storeArticle(article, intel, sourceId) {
  const db = await getDb();
  if (!db) return;
  const hash = hashString(article.url);
  try {
    await db.insert(incidentReports).values({
      sourceId: hash,
      source: sourceId,
      title: article.title,
      url: article.url,
      publishedAt: article.publishedAt,
      summary: intel.summary.slice(0, 2e3),
      fullContent: article.content.slice(0, 3e4),
      ttpsExtracted: intel.newTechniques.map((t) => ({ techniqueId: t.id, confidence: 85 })),
      iocsExtracted: intel.newIocs.map((i) => ({ type: i.type, value: i.value, context: i.description })),
      actorsIdentified: intel.actorMentions.map((m) => ({
        name: m.actorName,
        aliases: m.aliases,
        type: "unknown",
        confidence: m.confidence
      })),
      malwareIdentified: intel.newMalware,
      incidentType: categorizeArticle(article, intel),
      status: "extracted"
    });
  } catch {
  }
}
async function recordCrawlResult(result) {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(threatIntelUpdates).values({
      sweepType: "triggered",
      tiuStatus: "completed",
      groupsScanned: result.sourcesChecked,
      updatesApplied: result.actorsEnriched,
      newEventsFound: result.newEventsRecorded,
      newIocsFound: result.newIocsFound,
      newTtpsFound: result.newTtpsFound,
      tiuSummary: result.summary,
      tiuDetails: result.errors.length > 0 ? [{ errors: result.errors }] : [],
      tiuCompletedAt: /* @__PURE__ */ new Date()
    });
  } catch {
  }
}
function getCrawlerStats() {
  const sourceHealth = CRAWL_SOURCES.map((s) => ({
    sourceId: s.id,
    name: s.name,
    lastSuccess: s.lastCrawled,
    failCount: sourceFailCounts.get(s.id) || 0
  }));
  return {
    totalCrawls: crawlHistory.length,
    lastCrawlAt: lastCrawlResult?.completedAt,
    totalArticlesProcessed: crawlHistory.reduce((sum, c) => sum + c.articlesProcessed, 0),
    totalActorsEnriched: crawlHistory.reduce((sum, c) => sum + c.actorsEnriched, 0),
    totalNewActors: crawlHistory.reduce((sum, c) => sum + c.newActorsDiscovered, 0),
    totalNewEvents: crawlHistory.reduce((sum, c) => sum + c.newEventsRecorded, 0),
    totalNewIocs: crawlHistory.reduce((sum, c) => sum + c.newIocsFound, 0),
    sourceHealth,
    enrichmentCoverage: 0
    // Calculated on demand
  };
}
function getLastCrawlResult() {
  return lastCrawlResult;
}
function getCrawlHistory() {
  return [...crawlHistory];
}
function isCrawlRunning() {
  return crawlRunning;
}
function getCrawlSources() {
  return [...CRAWL_SOURCES];
}
function toggleCrawlSource(sourceId, enabled) {
  const source = CRAWL_SOURCES.find((s) => s.id === sourceId);
  if (!source) return false;
  source.enabled = enabled;
  return true;
}
function hashString(str) {
  return crypto.createHash("sha256").update(str).digest("hex").slice(0, 32);
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function safeFetch(url, options = {}, timeoutMs = 15e3) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
function parseRss(xml) {
  const items = [];
  const itemRegex = /<item[\s>]([\s\S]*?)<\/item>|<entry[\s>]([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1] || match[2] || "";
    const title = extractTag(block, "title");
    const link = extractTag(block, "link") || extractAttr(block, "link", "href");
    const description = extractTag(block, "description") || extractTag(block, "summary");
    const content = extractTag(block, "content:encoded") || extractTag(block, "content");
    const pubDate = extractTag(block, "pubDate") || extractTag(block, "published") || extractTag(block, "updated");
    const author = extractTag(block, "author") || extractTag(block, "dc:creator");
    if (title && link) {
      items.push({ title, link, description: description || "", content, pubDate: pubDate || "", author });
    }
  }
  return items;
}
function extractTag(xml, tag) {
  const regex = new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`, "i");
  const match = xml.match(regex);
  return match ? match[1].trim() : "";
}
function extractAttr(xml, tag, attr) {
  const regex = new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i");
  const match = xml.match(regex);
  return match ? match[1] : "";
}
function stripHtml(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
}
function mapEventType(type) {
  const map = {
    attack: "attack",
    campaign: "campaign",
    infrastructure_change: "infrastructure_change",
    malware_update: "malware_update",
    law_enforcement: "law_enforcement",
    ttp_evolution: "ttp_evolution",
    new_tool: "new_tool",
    zero_day: "zero_day",
    breach: "attack",
    ransomware: "attack",
    vulnerability: "zero_day",
    phishing: "campaign"
  };
  return map[type.toLowerCase()] || "campaign";
}
function categorizeArticle(article, intel) {
  const lower = (article.title + " " + article.content).toLowerCase();
  if (lower.includes("ransomware")) return "ransomware";
  if (lower.includes("breach") || lower.includes("data leak")) return "data_breach";
  if (lower.includes("apt") || lower.includes("nation-state")) return "apt";
  if (lower.includes("phishing")) return "phishing";
  if (lower.includes("vulnerability") || lower.includes("cve-")) return "vulnerability";
  if (lower.includes("malware")) return "malware";
  if (lower.includes("supply chain")) return "supply_chain";
  return "news";
}

export {
  runIntelligenceCrawl,
  runTargetedEnrichment,
  analyzeDataGaps,
  getCrawlerStats,
  getLastCrawlResult,
  getCrawlHistory,
  isCrawlRunning,
  getCrawlSources,
  toggleCrawlSource
};
