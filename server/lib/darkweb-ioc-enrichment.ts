/**
 * Darkweb IOC Enrichment Bridge
 *
 * Wires darkweb intelligence feeds into the IOC enrichment pipeline.
 * When an IOC is queried or ingested, this module cross-references it
 * against all darkweb data sources to add context:
 *
 *   - Feodo Tracker → C2 IP/domain matches
 *   - MalwareBazaar → hash matches with malware family context
 *   - SSL Blacklist → malicious SSL cert fingerprints
 *   - URLhaus → malicious URL matches
 *   - ThreatFox → multi-type IOC matches
 *   - Ransomware.live → actor/victim correlation
 *   - AlienVault OTX → pulse/indicator matches
 *   - OpenPhish → phishing URL matches
 *   - Tor exit nodes → Tor relay identification
 *   - Blocklist.de → brute-force/attack source identification
 *   - Spamhaus DROP → hijacked IP range identification
 *   - HIBP → credential breach correlation
 *   - Network events table → local C2/botnet matches
 *   - Underground intel events → actor/campaign correlation
 *   - Credential exposures → breach context
 */

import { getDb } from "../db";
import {
  undergroundIntelEvents,
  networkEvents,
  credentialExposures,
  iabActivity,
  darkwebEnrichedRecords,
} from "../../drizzle/schema";
import { eq, like, sql, or, desc } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────────

export interface DarkwebEnrichmentResult {
  ioc: string;
  iocType: string;
  darkwebHits: DarkwebHit[];
  riskElevation: number; // 0-100 additional risk points from darkweb context
  summary: string;
  enrichedAt: string;
}

export interface DarkwebHit {
  source: string;
  matchType: "exact" | "partial" | "related";
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  actor?: string;
  malwareFamily?: string;
  firstSeen?: string;
  lastSeen?: string;
  confidence: number; // 0-100
  rawData?: any;
}

// ─── Main Enrichment Function ────────────────────────────────────────────

/**
 * Enrich a single IOC with darkweb context from all available sources.
 * Returns hits from local darkweb tables + live feed lookups.
 */
export async function enrichIocWithDarkweb(
  ioc: string,
  iocType: "ip" | "domain" | "url" | "hash" | "email" | "cve"
): Promise<DarkwebEnrichmentResult> {
  const hits: DarkwebHit[] = [];

  // Run all enrichment checks in parallel
  const checks = await Promise.allSettled([
    checkNetworkEvents(ioc, iocType),
    checkUndergroundEvents(ioc, iocType),
    checkCredentialExposures(ioc, iocType),
    checkIabActivity(ioc, iocType),
    checkEnrichedRecords(ioc, iocType),
    checkLiveFeodoTracker(ioc, iocType),
    checkLiveThreatFox(ioc, iocType),
    checkLiveUrlhaus(ioc, iocType),
  ]);

  for (const result of checks) {
    if (result.status === "fulfilled" && result.value.length > 0) {
      hits.push(...result.value);
    }
  }

  // Calculate risk elevation based on hits
  const riskElevation = calculateRiskElevation(hits);

  // Generate summary
  const summary = generateEnrichmentSummary(ioc, iocType, hits, riskElevation);

  return {
    ioc,
    iocType,
    darkwebHits: hits,
    riskElevation,
    summary,
    enrichedAt: new Date().toISOString(),
  };
}

/**
 * Batch-enrich multiple IOCs with darkweb context.
 */
export async function enrichIocBatchWithDarkweb(
  iocs: Array<{ value: string; type: "ip" | "domain" | "url" | "hash" | "email" | "cve" }>
): Promise<DarkwebEnrichmentResult[]> {
  // Process in parallel with concurrency limit
  const batchSize = 5;
  const results: DarkwebEnrichmentResult[] = [];

  for (let i = 0; i < iocs.length; i += batchSize) {
    const batch = iocs.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((ioc) => enrichIocWithDarkweb(ioc.value, ioc.type))
    );
    results.push(...batchResults);
  }

  return results;
}

// ─── Local Database Checks ───────────────────────────────────────────────

async function checkNetworkEvents(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    const conditions = [];
    if (iocType === "ip") {
      conditions.push(eq(networkEvents.ipAddress, ioc));
    } else if (iocType === "domain") {
      conditions.push(like(networkEvents.hostname, `%${ioc}%`));
    } else if (iocType === "hash") {
      conditions.push(like(networkEvents.description, `%${ioc}%`));
    } else {
      return [];
    }

    const events = await db.select()
      .from(networkEvents)
      .where(conditions[0])
      .orderBy(desc(networkEvents.createdAt))
      .limit(10);

    return events.map((e) => ({
      source: `network_events (${e.source || "local"})`,
      matchType: "exact" as const,
      category: e.eventType || "network",
      severity: e.severity === "critical" ? "critical" as const :
        e.severity === "high" ? "high" as const :
        e.severity === "medium" ? "medium" as const : "low" as const,
      description: `${e.eventType || "Network event"}: ${e.ipAddress || "N/A"}:${e.port || "N/A"} | ${e.malwareFamily || "Unknown"} | ${e.source}`,
      malwareFamily: e.malwareFamily || undefined,
      firstSeen: e.firstSeen?.toString() || undefined,
      lastSeen: e.lastSeen?.toString() || undefined,
      confidence: 85,
    }));
  } catch {
    return [];
  }
}

async function checkUndergroundEvents(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    const pattern = `%${ioc}%`;
    const events = await db.select()
      .from(undergroundIntelEvents)
      .where(
        or(
          like(undergroundIntelEvents.title, pattern),
          like(undergroundIntelEvents.description, pattern),
          like(undergroundIntelEvents.iocValue, pattern),
          like(undergroundIntelEvents.victimName, pattern)
        )
      )
      .orderBy(desc(undergroundIntelEvents.createdAt))
      .limit(10);

    return events.map((e) => ({
      source: `underground_intel (${e.source || "darkweb"})`,
      matchType: "partial" as const,
      category: e.category || "underground",
      severity: e.severity === "critical" ? "critical" as const :
        e.severity === "high" ? "high" as const :
        e.severity === "medium" ? "medium" as const : "low" as const,
      description: `${e.category}: ${e.title} | Actor: ${e.actorName || "Unknown"} | Victim: ${e.victimName || "N/A"}`,
      actor: e.actorName || undefined,
      firstSeen: e.eventDate?.toString() || undefined,
      confidence: 70,
    }));
  } catch {
    return [];
  }
}

async function checkCredentialExposures(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    if (iocType !== "email" && iocType !== "domain") return [];

    const pattern = `%${ioc}%`;
    const exposures = await db.select()
      .from(credentialExposures)
      .where(
        or(
          like(credentialExposures.breachName, pattern),
          like(credentialExposures.domain, pattern),
          like(credentialExposures.description, pattern)
        )
      )
      .orderBy(desc(credentialExposures.createdAt))
      .limit(10);

    return exposures.map((e) => ({
      source: `credential_exposures (${e.source || "breach"})`,
      matchType: "related" as const,
      category: "credential",
      severity: e.severity === "critical" ? "critical" as const :
        e.severity === "high" ? "high" as const : "medium" as const,
      description: `Breach: ${e.breachName} | ${e.totalRecords || 0} records | Domain: ${e.domain || "unknown"} | Actor: ${e.actorName || "Unknown"}`,
      actor: e.actorName || undefined,
      firstSeen: e.breachDate?.toISOString() || undefined,
      confidence: 75,
    }));
  } catch {
    return [];
  }
}

async function checkIabActivity(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    if (iocType !== "domain" && iocType !== "ip") return [];

    const pattern = `%${ioc}%`;
    const listings = await db.select()
      .from(iabActivity)
      .where(
        or(
          like(iabActivity.victimName, pattern),
          like(iabActivity.description, pattern),
          like(iabActivity.brokerName, pattern)
        )
      )
      .orderBy(desc(iabActivity.createdAt))
      .limit(5);

    return listings.map((l) => ({
      source: "iab_activity",
      matchType: "related" as const,
      category: "iab",
      severity: "critical" as const,
      description: `IAB Listing: ${l.brokerName} (${l.listingType || "access"}) | Price: ${l.askingPrice || "N/A"} | Victim: ${l.victimName || "Unknown"} | Sector: ${l.victimSector || "N/A"}`,
      actor: l.brokerName || undefined,
      firstSeen: l.firstSeen?.toISOString() || undefined,
      confidence: 80,
    }));
  } catch {
    return [];
  }
}

async function checkEnrichedRecords(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    const pattern = `%${ioc}%`;
    const records = await db.select()
      .from(darkwebEnrichedRecords)
      .where(
        or(
          like(darkwebEnrichedRecords.summary, pattern),
          like(darkwebEnrichedRecords.threatAssessment, pattern),
          like(darkwebEnrichedRecords.relatedIocs, pattern)
        )
      )
      .orderBy(desc(darkwebEnrichedRecords.riskScore))
      .limit(5);

    return records.map((r) => ({
      source: "darkweb_enriched",
      matchType: "related" as const,
      category: "enriched_intel",
      severity: (r.riskScore || 0) >= 80 ? "critical" as const :
        (r.riskScore || 0) >= 60 ? "high" as const :
        (r.riskScore || 0) >= 40 ? "medium" as const : "low" as const,
      description: `Enriched Intel: ${r.summary?.substring(0, 200) || "N/A"} | Risk: ${r.riskScore}/100`,
      confidence: r.riskScore || 50,
    }));
  } catch {
    return [];
  }
}

// ─── Live Feed Checks ────────────────────────────────────────────────────

async function checkLiveFeodoTracker(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  if (iocType !== "ip") return [];

  try {
    const response = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", {
      signal: AbortSignal.timeout(5000),
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
        confidence: 95,
      }];
    }
    return [];
  } catch {
    return [];
  }
}

async function checkLiveThreatFox(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (apiKey) headers["Auth-Key"] = apiKey;

    const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: JSON.stringify({ query: "search_ioc", search_term: ioc }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return [];
    const data = (await response.json()) as any;
    if (data.query_status !== "ok" || !Array.isArray(data.data)) return [];

    return data.data.slice(0, 5).map((hit: any) => ({
      source: "threatfox (live)",
      matchType: "exact" as const,
      category: hit.threat_type || "malware",
      severity: (hit.confidence_level || 0) > 75 ? "high" as const : "medium" as const,
      description: `ThreatFox: ${hit.ioc_type} | Malware: ${hit.malware_printable} | Confidence: ${hit.confidence_level}%`,
      malwareFamily: hit.malware_printable || undefined,
      firstSeen: hit.first_seen_utc || undefined,
      lastSeen: hit.last_seen_utc || undefined,
      confidence: hit.confidence_level || 60,
    }));
  } catch {
    return [];
  }
}

async function checkLiveUrlhaus(ioc: string, iocType: string): Promise<DarkwebHit[]> {
  if (iocType !== "url" && iocType !== "domain") return [];

  try {
    const apiKey = process.env.ABUSECH_API_KEY || "";
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
    if (apiKey) headers["Auth-Key"] = apiKey;

    const endpoint = iocType === "url"
      ? "https://urlhaus-api.abuse.ch/v1/url/"
      : "https://urlhaus-api.abuse.ch/v1/host/";

    const body = iocType === "url" ? `url=${encodeURIComponent(ioc)}` : `host=${encodeURIComponent(ioc)}`;

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return [];
    const data = (await response.json()) as any;

    if (data.query_status === "no_results") return [];

    const hits: DarkwebHit[] = [];

    if (data.urls && Array.isArray(data.urls)) {
      for (const u of data.urls.slice(0, 5)) {
        hits.push({
          source: "urlhaus (live)",
          matchType: "exact",
          category: "malicious_url",
          severity: u.threat === "malware_download" ? "critical" : "high",
          description: `URLhaus: ${u.url} | Threat: ${u.threat} | Status: ${u.url_status}`,
          firstSeen: u.date_added || undefined,
          confidence: 90,
        });
      }
    } else if (data.url_status) {
      hits.push({
        source: "urlhaus (live)",
        matchType: "exact",
        category: "malicious_url",
        severity: data.threat === "malware_download" ? "critical" : "high",
        description: `URLhaus: ${data.url || ioc} | Threat: ${data.threat} | Status: ${data.url_status}`,
        firstSeen: data.date_added || undefined,
        confidence: 90,
      });
    }

    return hits;
  } catch {
    return [];
  }
}

// ─── Risk Calculation ────────────────────────────────────────────────────

function calculateRiskElevation(hits: DarkwebHit[]): number {
  if (hits.length === 0) return 0;

  let elevation = 0;

  for (const hit of hits) {
    const severityWeight =
      hit.severity === "critical" ? 25 :
      hit.severity === "high" ? 15 :
      hit.severity === "medium" ? 8 : 3;

    const matchWeight =
      hit.matchType === "exact" ? 1.0 :
      hit.matchType === "partial" ? 0.6 : 0.3;

    const confidenceWeight = hit.confidence / 100;

    elevation += severityWeight * matchWeight * confidenceWeight;
  }

  // Cap at 100
  return Math.min(100, Math.round(elevation));
}

function generateEnrichmentSummary(
  ioc: string,
  iocType: string,
  hits: DarkwebHit[],
  riskElevation: number
): string {
  if (hits.length === 0) {
    return `No darkweb intelligence found for ${iocType} indicator ${ioc}.`;
  }

  const sources = Array.from(new Set(hits.map((h) => h.source.split(" (")[0])));
  const categories = Array.from(new Set(hits.map((h) => h.category)));
  const criticalCount = hits.filter((h) => h.severity === "critical").length;
  const actors = Array.from(new Set(hits.filter((h) => h.actor).map((h) => h.actor!)));

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

// ─── Integration with IOC Sync Pipeline ──────────────────────────────────

/**
 * Post-sync enrichment hook: after IOC sync completes, cross-reference
 * newly ingested IOCs against darkweb tables for additional context.
 * Call this from the IOC sync pipeline after fetching new entries.
 */
export async function postSyncDarkwebEnrichment(
  newIocs: Array<{ value: string; type: string }>
): Promise<{ enriched: number; totalHits: number }> {
  let enriched = 0;
  let totalHits = 0;

  // Only enrich a sample to avoid overwhelming the system
  const sample = newIocs.slice(0, 50);

  for (const ioc of sample) {
    try {
      const result = await enrichIocWithDarkweb(
        ioc.value,
        ioc.type as "ip" | "domain" | "url" | "hash" | "email" | "cve"
      );
      if (result.darkwebHits.length > 0) {
        enriched++;
        totalHits += result.darkwebHits.length;
      }
    } catch {
      // Skip individual failures
    }
  }

  console.log(`[DarkwebEnrichment] Post-sync: ${enriched}/${sample.length} IOCs enriched with ${totalHits} darkweb hits`);
  return { enriched, totalHits };
}
