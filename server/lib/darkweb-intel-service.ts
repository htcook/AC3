/**
 * Darkweb Intelligence Analysis Service
 *
 * Higher-order analysis functions:
 *   - Ransomware actor sync & affiliate tracking
 *   - Ransomware victim sync & stats
 *   - Sector-based enrichment
 *   - Cross-source correlation
 *   - Trend analysis
 */

import { getDb } from "../db";
import {
  undergroundIntelEvents,
  ransomwareAffiliates,
  credentialExposures,
  networkEvents,
  darkwebEnrichedRecords,
  
} from "../../drizzle/schema";
import { eq, desc, sql, and, gte, like, or } from "drizzle-orm";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Ransomware Actor Sync ───────────────────────────────────────────────

/**
 * Sync ransomware group data from underground_intel_events into ransomware_affiliates.
 * Aggregates victim counts, sectors, countries from ingested events.
 */
export async function syncRansomwareActors(): Promise<{ synced: number; updated: number }> {
  const db = await requireDb();

  // Get distinct actor names from ransomware events
  const actors = await db.select({
    actorName: undergroundIntelEvents.uieActorName,
    victimCount: sql<number>`COUNT(*)`,
    sectors: sql<string>`CONCAT('["', GROUP_CONCAT(DISTINCT uie_victim_sector SEPARATOR '","'), '"]')`,
    countries: sql<string>`CONCAT('["', GROUP_CONCAT(DISTINCT uie_victim_country SEPARATOR '","'), '"]')`,
    firstSeen: sql<string>`MIN(uie_event_date)`,
    lastActive: sql<string>`MAX(uie_event_date)`,
  })
    .from(undergroundIntelEvents)
    .where(
      and(
        eq(undergroundIntelEvents.uieCategory, "ransomware"),
        sql`uie_actor_name IS NOT NULL AND uie_actor_name != ''`
      )
    )
    .groupBy(undergroundIntelEvents.uieActorName);

  let synced = 0;
  let updated = 0;

  for (const actor of actors) {
    if (!actor.actorName) continue;

    const sectors = safeJsonParse(actor.sectors, []).filter((s: string) => s && s !== "null");
    const countries = safeJsonParse(actor.countries, []).filter((c: string) => c && c !== "null");

    // Check if affiliate already exists
    const [existing] = await db.select()
      .from(ransomwareAffiliates)
      .where(eq(ransomwareAffiliates.raAffiliateName, actor.actorName))
      .limit(1);

    if (existing) {
      await db.update(ransomwareAffiliates)
        .set({
          raTotalVictims: actor.victimCount,
          topSectors: sectors.slice(0, 10),
          topCountries: countries.slice(0, 10),
          lastActive: actor.lastActive || undefined,
          activityScore: calculateActivityScore(actor.victimCount, actor.lastActive),
          status: "active",
        })
        .where(eq(ransomwareAffiliates.id, existing.id));
      updated++;
    } else {
      await db.insert(ransomwareAffiliates).values({
        affiliateId: `rw-${actor.actorName.toLowerCase().replace(/\s+/g, "-")}`,
        affiliateName: actor.actorName,
        primaryGroup: actor.actorName,
        raTotalVictims: actor.victimCount,
        topSectors: sectors.slice(0, 10),
        topCountries: countries.slice(0, 10),
        firstSeen: actor.firstSeen || undefined,
        lastActive: actor.lastActive || undefined,
        activityScore: calculateActivityScore(actor.victimCount, actor.lastActive),
        status: "active",
        confidence: 80,
      });
      synced++;
    }
  }

  console.log(`[DarkwebIntel] Actor sync: ${synced} new, ${updated} updated`);
  return { synced, updated };
}

function calculateActivityScore(victimCount: number, lastActive: string | null): number {
  let score = Math.min(50, victimCount * 5);
  if (lastActive) {
    const daysSince = (Date.now() - new Date(lastActive).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSince < 7) score += 50;
    else if (daysSince < 30) score += 35;
    else if (daysSince < 90) score += 20;
    else score += 5;
  }
  return Math.min(100, score);
}

function safeJsonParse(val: any, fallback: any[]): any[] {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return fallback; }
  }
  return fallback;
}

// ─── Sector Enrichment ───────────────────────────────────────────────────

export interface SectorThreatProfile {
  sector: string;
  ransomwareVictims: number;
  topGroups: string[];
  credentialExposures: number;
  iabListings: number;
  riskLevel: "critical" | "high" | "medium" | "low";
}

/**
 * Generate sector-based threat profiles from aggregated darkweb data.
 */
export async function getSectorThreatProfiles(): Promise<SectorThreatProfile[]> {
  const db = await requireDb();

  // Ransomware victims by sector
  const sectorVictims = await db.select({
    sector: undergroundIntelEvents.uieVictimSector,
    count: sql<number>`COUNT(*)`,
    groups: sql<string>`CONCAT('["', GROUP_CONCAT(DISTINCT uie_actor_name SEPARATOR '","'), '"]')`,
  })
    .from(undergroundIntelEvents)
    .where(
      and(
        eq(undergroundIntelEvents.uieCategory, "ransomware"),
        sql`uie_victim_sector IS NOT NULL AND uie_victim_sector != ''`
      )
    )
    .groupBy(undergroundIntelEvents.uieVictimSector)
    .orderBy(sql`COUNT(*) DESC`)
    .limit(20);

  return sectorVictims.map((sv) => {
    const groups = safeJsonParse(sv.groups, []).filter((g: string) => g && g !== "null");
    const count = sv.count || 0;
    return {
      sector: sv.sector || "Unknown",
      ransomwareVictims: count,
      topGroups: groups.slice(0, 5),
      credentialExposures: 0, // Would need a join or separate query
      iabListings: 0,
      riskLevel: count > 50 ? "critical" : count > 20 ? "high" : count > 5 ? "medium" : "low",
    };
  });
}

// ─── Trend Analysis ──────────────────────────────────────────────────────

export interface DarkwebTrend {
  date: string;
  ransomware: number;
  malware: number;
  phishing: number;
  credential: number;
  network: number;
  total: number;
}

/**
 * Get daily event trends for the last N days.
 */
export async function getDarkwebTrends(days = 30): Promise<DarkwebTrend[]> {
  const db = await requireDb();
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);

  const trends = await db.select({
    date: sql<string>`DATE(uie_created_at)`,
    ransomware: sql<number>`SUM(CASE WHEN uie_category = 'ransomware' THEN 1 ELSE 0 END)`,
    malware: sql<number>`SUM(CASE WHEN uie_category = 'malware' THEN 1 ELSE 0 END)`,
    phishing: sql<number>`SUM(CASE WHEN uie_category = 'phishing' THEN 1 ELSE 0 END)`,
    credential: sql<number>`SUM(CASE WHEN uie_category = 'credential' THEN 1 ELSE 0 END)`,
    total: sql<number>`COUNT(*)`,
  })
    .from(undergroundIntelEvents)
    .where(gte(undergroundIntelEvents.uieCreatedAt, cutoff))
    .groupBy(sql`DATE(uie_created_at)`)
    .orderBy(sql`DATE(uie_created_at)`);

  // Also get network event trends
  const netTrends = await db.select({
    date: sql<string>`DATE(ne_created_at)`,
    count: sql<number>`COUNT(*)`,
  })
    .from(networkEvents)
    .where(gte(networkEvents.neCreatedAt, cutoff))
    .groupBy(sql`DATE(ne_created_at)`);

  const netMap = new Map(netTrends.map((t) => [t.date, t.count]));

  return trends.map((t) => ({
    date: String(t.date),
    ransomware: t.ransomware || 0,
    malware: t.malware || 0,
    phishing: t.phishing || 0,
    credential: t.credential || 0,
    network: netMap.get(String(t.date)) || 0,
    total: (t.total || 0) + (netMap.get(String(t.date)) || 0),
  }));
}

// ─── Cross-Source Correlation ────────────────────────────────────────────

export interface ThreatCorrelation {
  actor: string;
  ransomwareEvents: number;
  networkIndicators: number;
  credentialBreaches: number;
  enrichedRecords: number;
  avgRiskScore: number;
  lastSeen: string | null;
}

/**
 * Correlate threat data across all darkweb tables for a given actor/keyword.
 */
export async function correlateActor(actorName: string): Promise<ThreatCorrelation> {
  const db = await requireDb();
  const pattern = `%${actorName}%`;

  const [rwEvents] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(undergroundIntelEvents)
    .where(like(undergroundIntelEvents.uieActorName, pattern));

  const [netEvents] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(networkEvents)
    .where(like(networkEvents.neMalwareFamily, pattern));

  const [credEvents] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(credentialExposures)
    .where(like(credentialExposures.ceActorName, pattern));

  const [enriched] = await db.select({
    count: sql<number>`COUNT(*)`,
    avgRisk: sql<number>`AVG(der_risk_score)`,
  }).from(darkwebEnrichedRecords)
    .where(sql`JSON_CONTAINS(der_related_actors, ${JSON.stringify([actorName])})`);

  const [lastEvent] = await db.select({
    lastSeen: sql<string>`MAX(uie_event_date)`,
  }).from(undergroundIntelEvents)
    .where(like(undergroundIntelEvents.uieActorName, pattern));

  return {
    actor: actorName,
    ransomwareEvents: rwEvents?.count || 0,
    networkIndicators: netEvents?.count || 0,
    credentialBreaches: credEvents?.count || 0,
    enrichedRecords: enriched?.count || 0,
    avgRiskScore: Math.round(enriched?.avgRisk || 0),
    lastSeen: lastEvent?.lastSeen || null,
  };
}

// ─── Recent High-Priority Events ─────────────────────────────────────────

export async function getHighPriorityEvents(limit = 20) {
  const db = await requireDb();
  return db.select()
    .from(undergroundIntelEvents)
    .where(
      or(
        eq(undergroundIntelEvents.uieSeverity, "critical"),
        eq(undergroundIntelEvents.uieSeverity, "high"),
      )
    )
    .orderBy(desc(undergroundIntelEvents.uieCreatedAt))
    .limit(limit);
}
