import {
  getDb,
  init_db
} from "./chunk-26A2QP6T.js";
import "./chunk-NRYVRXXR.js";
import {
  credentialExposures,
  darkwebEnrichedRecords,
  iabActivity,
  init_schema,
  networkEvents,
  undergroundIntelEvents
} from "./chunk-NWJ2JNWL.js";
import "./chunk-KFQGP6VL.js";

// server/lib/darkweb-ioc-enrichment.ts
init_db();
init_schema();
import { eq, like, or, desc } from "drizzle-orm";
async function enrichIocWithDarkweb(ioc, iocType) {
  const hits = [];
  const checks = await Promise.allSettled([
    checkNetworkEvents(ioc, iocType),
    checkUndergroundEvents(ioc, iocType),
    checkCredentialExposures(ioc, iocType),
    checkIabActivity(ioc, iocType),
    checkEnrichedRecords(ioc, iocType),
    checkLiveFeodoTracker(ioc, iocType),
    checkLiveThreatFox(ioc, iocType),
    checkLiveUrlhaus(ioc, iocType)
  ]);
  for (const result of checks) {
    if (result.status === "fulfilled" && result.value.length > 0) {
      hits.push(...result.value);
    }
  }
  const riskElevation = calculateRiskElevation(hits);
  const summary = generateEnrichmentSummary(ioc, iocType, hits, riskElevation);
  return {
    ioc,
    iocType,
    darkwebHits: hits,
    riskElevation,
    summary,
    enrichedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
async function enrichIocBatchWithDarkweb(iocs) {
  const batchSize = 5;
  const results = [];
  for (let i = 0; i < iocs.length; i += batchSize) {
    const batch = iocs.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((ioc) => enrichIocWithDarkweb(ioc.value, ioc.type))
    );
    results.push(...batchResults);
  }
  return results;
}
async function checkNetworkEvents(ioc, iocType) {
  const db = await getDb();
  if (!db) return [];
  try {
    const conditions = [];
    if (iocType === "ip") {
      conditions.push(eq(networkEvents.neIpAddress, ioc));
    } else if (iocType === "domain") {
      conditions.push(like(networkEvents.neHostname, `%${ioc}%`));
    } else if (iocType === "hash") {
      conditions.push(like(networkEvents.neDescription, `%${ioc}%`));
    } else {
      return [];
    }
    const events = await db.select().from(networkEvents).where(conditions[0]).orderBy(desc(networkEvents.neCreatedAt)).limit(10);
    return events.map((e) => ({
      source: `network_events (${e.neSource || "local"})`,
      matchType: "exact",
      category: e.neEventType || "network",
      severity: e.neSeverity === "critical" ? "critical" : e.neSeverity === "high" ? "high" : e.neSeverity === "medium" ? "medium" : "low",
      description: `${e.neEventType || "Network event"}: ${e.neIpAddress || "N/A"}:${e.nePort || "N/A"} | ${e.neMalwareFamily || "Unknown"} | ${e.neSource}`,
      malwareFamily: e.neMalwareFamily || void 0,
      firstSeen: e.neFirstSeen?.toString() || void 0,
      lastSeen: e.neLastSeen?.toString() || void 0,
      confidence: 85
    }));
  } catch {
    return [];
  }
}
async function checkUndergroundEvents(ioc, iocType) {
  const db = await getDb();
  if (!db) return [];
  try {
    const pattern = `%${ioc}%`;
    const events = await db.select().from(undergroundIntelEvents).where(
      or(
        like(undergroundIntelEvents.uieTitle, pattern),
        like(undergroundIntelEvents.uieDescription, pattern),
        like(undergroundIntelEvents.uieIocValue, pattern),
        like(undergroundIntelEvents.uieVictimName, pattern)
      )
    ).orderBy(desc(undergroundIntelEvents.uieCreatedAt)).limit(10);
    return events.map((e) => ({
      source: `underground_intel (${e.uieSource || "darkweb"})`,
      matchType: "partial",
      category: e.uieCategory || "underground",
      severity: e.uieSeverity === "critical" ? "critical" : e.uieSeverity === "high" ? "high" : e.uieSeverity === "medium" ? "medium" : "low",
      description: `${e.uieCategory}: ${e.uieTitle} | Actor: ${e.uieActorName || "Unknown"} | Victim: ${e.uieVictimName || "N/A"}`,
      actor: e.uieActorName || void 0,
      firstSeen: e.uieEventDate?.toString() || void 0,
      confidence: 70
    }));
  } catch {
    return [];
  }
}
async function checkCredentialExposures(ioc, iocType) {
  const db = await getDb();
  if (!db) return [];
  try {
    if (iocType !== "email" && iocType !== "domain") return [];
    const pattern = `%${ioc}%`;
    const exposures = await db.select().from(credentialExposures).where(
      or(
        like(credentialExposures.ceBreachName, pattern),
        like(credentialExposures.ceDomain, pattern),
        like(credentialExposures.ceDescription, pattern)
      )
    ).orderBy(desc(credentialExposures.ceCreatedAt)).limit(10);
    return exposures.map((e) => ({
      source: `credential_exposures (${e.ceSource || "breach"})`,
      matchType: "related",
      category: "credential",
      severity: e.ceSeverity === "critical" ? "critical" : e.ceSeverity === "high" ? "high" : "medium",
      description: `Breach: ${e.ceBreachName} | ${e.ceTotalRecords || 0} records | Domain: ${e.ceDomain || "unknown"} | Actor: ${e.ceActorName || "Unknown"}`,
      actor: e.ceActorName || void 0,
      firstSeen: e.ceBreachDate || void 0,
      confidence: 75
    }));
  } catch {
    return [];
  }
}
async function checkIabActivity(ioc, iocType) {
  const db = await getDb();
  if (!db) return [];
  try {
    if (iocType !== "domain" && iocType !== "ip") return [];
    const pattern = `%${ioc}%`;
    const listings = await db.select().from(iabActivity).where(
      or(
        like(iabActivity.iabVictimName, pattern),
        like(iabActivity.iabDescription, pattern),
        like(iabActivity.iabBrokerName, pattern)
      )
    ).orderBy(desc(iabActivity.iabCreatedAt)).limit(5);
    return listings.map((l) => ({
      source: "iab_activity",
      matchType: "related",
      category: "iab",
      severity: "critical",
      description: `IAB Listing: ${l.iabBrokerName} (${l.iabListingType || "access"}) | Price: ${l.iabAskingPrice || "N/A"} | Victim: ${l.iabVictimName || "Unknown"} | Sector: ${l.iabVictimSector || "N/A"}`,
      actor: l.iabBrokerName || void 0,
      firstSeen: l.iabFirstSeen || void 0,
      confidence: 80
    }));
  } catch {
    return [];
  }
}
async function checkEnrichedRecords(ioc, iocType) {
  const db = await getDb();
  if (!db) return [];
  try {
    const pattern = `%${ioc}%`;
    const records = await db.select().from(darkwebEnrichedRecords).where(
      or(
        like(darkwebEnrichedRecords.derSummary, pattern),
        like(darkwebEnrichedRecords.derThreatAssessment, pattern),
        like(darkwebEnrichedRecords.derRelatedIocs, pattern)
      )
    ).orderBy(desc(darkwebEnrichedRecords.derRiskScore)).limit(5);
    return records.map((r) => ({
      source: "darkweb_enriched",
      matchType: "related",
      category: "enriched_intel",
      severity: (r.derRiskScore || 0) >= 80 ? "critical" : (r.derRiskScore || 0) >= 60 ? "high" : (r.derRiskScore || 0) >= 40 ? "medium" : "low",
      description: `Enriched Intel: ${r.derSummary?.substring(0, 200) || "N/A"} | Risk: ${r.derRiskScore}/100`,
      confidence: r.derRiskScore || 50
    }));
  } catch {
    return [];
  }
}
async function checkLiveFeodoTracker(ioc, iocType) {
  if (iocType !== "ip") return [];
  try {
    const response = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", {
      signal: AbortSignal.timeout(5e3)
    });
    if (!response.ok) return [];
    const text = await response.text();
    const lines = text.split("\n").filter((l) => !l.startsWith("#") && l.trim());
    if (lines.includes(ioc)) {
      return [{
        source: "feodo_tracker (live)",
        matchType: "exact",
        category: "c2_botnet",
        severity: "critical",
        description: `IP ${ioc} is listed on Feodo Tracker as a known C2 server (Dridex, Emotet, TrickBot, QakBot)`,
        confidence: 95
      }];
    }
    return [];
  } catch {
    return [];
  }
}
async function checkLiveThreatFox(ioc, iocType) {
  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["Auth-Key"] = apiKey;
    const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: JSON.stringify({ query: "search_ioc", search_term: ioc }),
      signal: AbortSignal.timeout(8e3)
    });
    if (!response.ok) return [];
    const data = await response.json();
    if (data.query_status !== "ok" || !Array.isArray(data.data)) return [];
    return data.data.slice(0, 5).map((hit) => ({
      source: "threatfox (live)",
      matchType: "exact",
      category: hit.threat_type || "malware",
      severity: (hit.confidence_level || 0) > 75 ? "high" : "medium",
      description: `ThreatFox: ${hit.ioc_type} | Malware: ${hit.malware_printable} | Confidence: ${hit.confidence_level}%`,
      malwareFamily: hit.malware_printable || void 0,
      firstSeen: hit.first_seen_utc || void 0,
      lastSeen: hit.last_seen_utc || void 0,
      confidence: hit.confidence_level || 60
    }));
  } catch {
    return [];
  }
}
async function checkLiveUrlhaus(ioc, iocType) {
  if (iocType !== "url" && iocType !== "domain") return [];
  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (apiKey) headers["Auth-Key"] = apiKey;
    const endpoint = iocType === "url" ? "https://urlhaus-api.abuse.ch/v1/url/" : "https://urlhaus-api.abuse.ch/v1/host/";
    const body = iocType === "url" ? `url=${encodeURIComponent(ioc)}` : `host=${encodeURIComponent(ioc)}`;
    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(8e3)
    });
    if (!response.ok) return [];
    const data = await response.json();
    if (data.query_status === "no_results") return [];
    const hits = [];
    if (data.urls && Array.isArray(data.urls)) {
      for (const u of data.urls.slice(0, 5)) {
        hits.push({
          source: "urlhaus (live)",
          matchType: "exact",
          category: "malicious_url",
          severity: u.threat === "malware_download" ? "critical" : "high",
          description: `URLhaus: ${u.url} | Threat: ${u.threat} | Status: ${u.url_status}`,
          firstSeen: u.date_added || void 0,
          confidence: 90
        });
      }
    } else if (data.url_status) {
      hits.push({
        source: "urlhaus (live)",
        matchType: "exact",
        category: "malicious_url",
        severity: data.threat === "malware_download" ? "critical" : "high",
        description: `URLhaus: ${data.url || ioc} | Threat: ${data.threat} | Status: ${data.url_status}`,
        firstSeen: data.date_added || void 0,
        confidence: 90
      });
    }
    return hits;
  } catch {
    return [];
  }
}
function calculateRiskElevation(hits) {
  if (hits.length === 0) return 0;
  let elevation = 0;
  for (const hit of hits) {
    const severityWeight = hit.severity === "critical" ? 25 : hit.severity === "high" ? 15 : hit.severity === "medium" ? 8 : 3;
    const matchWeight = hit.matchType === "exact" ? 1 : hit.matchType === "partial" ? 0.6 : 0.3;
    const confidenceWeight = hit.confidence / 100;
    elevation += severityWeight * matchWeight * confidenceWeight;
  }
  return Math.min(100, Math.round(elevation));
}
function generateEnrichmentSummary(ioc, iocType, hits, riskElevation) {
  if (hits.length === 0) {
    return `No darkweb intelligence found for ${iocType} indicator ${ioc}.`;
  }
  const sources = Array.from(new Set(hits.map((h) => h.source.split(" (")[0])));
  const categories = Array.from(new Set(hits.map((h) => h.category)));
  const criticalCount = hits.filter((h) => h.severity === "critical").length;
  const actors = Array.from(new Set(hits.filter((h) => h.actor).map((h) => h.actor)));
  let summary = `Found ${hits.length} darkweb hit(s) for ${iocType} "${ioc}" across ${sources.length} source(s): ${sources.join(", ")}.`;
  if (criticalCount > 0) {
    summary += ` ${criticalCount} critical-severity match(es) detected.`;
  }
  if (categories.length > 0) {
    summary += ` Categories: ${categories.join(", ")}.`;
  }
  if (actors.length > 0) {
    summary += ` Associated actors: ${actors.join(", ")}.`;
  }
  summary += ` Risk elevation: +${riskElevation} points.`;
  return summary;
}
async function postSyncDarkwebEnrichment(newIocs) {
  let enriched = 0;
  let totalHits = 0;
  const sample = newIocs.slice(0, 50);
  for (const ioc of sample) {
    try {
      const result = await enrichIocWithDarkweb(
        ioc.value,
        ioc.type
      );
      if (result.darkwebHits.length > 0) {
        enriched++;
        totalHits += result.darkwebHits.length;
      }
    } catch {
    }
  }
  console.log(`[DarkwebEnrichment] Post-sync: ${enriched}/${sample.length} IOCs enriched with ${totalHits} darkweb hits`);
  return { enriched, totalHits };
}
export {
  enrichIocBatchWithDarkweb,
  enrichIocWithDarkweb,
  postSyncDarkwebEnrichment
};
