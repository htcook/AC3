/**
 * Darkweb Intelligence Bridge Router
 *
 * Serves threat intelligence data to the Darkweb Intelligence dashboard
 * by querying the LOCAL DATABASE (iocFeeds, ransomwareGroups,
 * threatGroupEvents, threatActors) instead of relying on external
 * SpicyThreatIntel bridge or third-party APIs.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import {
  iocFeeds,
  ransomwareGroups,
  threatGroupEvents,
  threatActors,
  threatActorIocs,
  accessBrokerListings,
  infoOpsCampaigns,
} from "../../drizzle/schema";
import { desc, eq, sql, and, like } from "drizzle-orm";

// JSON parsing helper for columns that may be strings or already-parsed
function safeParseJson(val: unknown): any[] {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try { const parsed = JSON.parse(val); return Array.isArray(parsed) ? parsed : []; }
    catch { return []; }
  }
  if (val && typeof val === 'object') return [val];
  return [];
}

// Optional SpicyTIP bridge imports (used as fallback only)
import {
  checkBridgeHealth,
  corroborateAssets,
  syncDarkwebIntelligence,
} from "../lib/spicy-tip-bridge";

// ─── Router ─────────────────────────────────────────────────────────────

export const darkwebBridgeRouter = router({
  /**
   * Health check — reports local data availability + bridge status.
   */
  health: protectedProcedure.query(async () => {
    const bridgeHealth = await checkBridgeHealth();
    return {
      configured: true,
      reachable: true, // Local DB is always reachable
      hasFallback: true,
      source: "local_database",
      baseUrl: bridgeHealth.baseUrl || "",
      bridgeReachable: bridgeHealth.reachable,
    };
  }),

  /**
   * Bridge configuration status.
   */
  status: protectedProcedure.query(async () => {
    return {
      configured: true,
      hasFallback: true,
      source: "local_database",
      timestamp: new Date().toISOString(),
    };
  }),

  /**
   * Ransomware victim statistics from local ransomware_groups table.
   * 318 groups with activity scores, threat levels, victim counts.
   */
  ransomwareVictimStats: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const groups = await db
        .select({
          groupName: ransomwareGroups.groupName,
          totalVictims: ransomwareGroups.totalVictims,
          victims7d: ransomwareGroups.victims7d,
          victims30d: ransomwareGroups.victims30d,
          activityScore: ransomwareGroups.activityScore,
          trend: ransomwareGroups.trend,
          threatLevel: ransomwareGroups.threatLevel, // Drizzle name for "rwThreatLevel" column
          topSectors: ransomwareGroups.topSectors,
          topCountries: ransomwareGroups.topCountries,
        })
        .from(ransomwareGroups)
        .orderBy(desc(ransomwareGroups.activityScore))
        .limit(input?.limit || 50);

      const data = groups.map((g) => ({
        groupName: g.groupName,
        totalVictims: g.totalVictims || 0,
        victims7d: g.victims7d || 0,
        victims30d: g.victims30d || 0,
        activityScore: g.activityScore || 0,
        trend: g.trend || "unknown",
        threatLevel: g.threatLevel || "medium",
        topSectors: g.topSectors || [],
        topCountries: g.topCountries || [],
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * IOCs from local ioc_feeds table (3,300+ CISA KEV entries).
   * Mapped to ThreatFox-compatible format for the frontend.
   */
  threatFoxIOCs: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(500).optional(),
        type: z.enum(["ip", "domain", "url", "hash", "email"]).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const conditions: any[] = [];
      if (input?.type) {
        conditions.push(eq(iocFeeds.iocType, input.type));
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const entries = await db
        .select()
        .from(iocFeeds)
        .where(where)
        .orderBy(desc(iocFeeds.id))
        .limit(input?.limit || 100);

      const data = entries.map((e) => ({
        iocType: e.iocType || "cve",
        type: e.iocType || "cve",
        value: e.iocValue,
        ioc: e.iocValue,
        malwareFamily: e.vendorProduct || null,
        confidence: e.severity === "critical" ? 95 : e.severity === "high" ? 80 : 60,
        firstSeen: e.dateAdded || e.fetchedAt?.toISOString(),
        tags: e.tags || [],
        title: e.title,
        description: e.description,
        source: e.feedSource,
        cveId: e.cveId,
        knownRansomware: e.knownRansomware,
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Activity ratings from local ransomware_groups table.
   */
  activityRatings: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

    const groups = await db
      .select({
        groupName: ransomwareGroups.groupName,
        activityScore: ransomwareGroups.activityScore,
        trend: ransomwareGroups.trend,
        threatLevel: ransomwareGroups.threatLevel,
        victims30d: ransomwareGroups.victims30d,
      })
      .from(ransomwareGroups)
      .orderBy(desc(ransomwareGroups.activityScore))
      .limit(30);

    const data = groups.map((g) => ({
      groupName: g.groupName,
      rating: g.activityScore || 0,
      trend: g.trend || "unknown",
      threatLevel: g.threatLevel || "medium",
      recentVictims: g.victims30d || 0,
    }));

    return { data, source: "local_database", fetchedAt: new Date().toISOString() };
  }),

  /**
   * Global threat actors from local threat_actors table (1,653 actors).
   */
  globalThreatActors: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(500).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const actors = await db
        .select()
        .from(threatActors)
        .orderBy(desc(threatActors.id))
        .limit(input?.limit || 100);

      const data = actors.map((a) => ({
        name: a.name,
        aliases: a.aliases || [],
        attributionCountry: a.origin,
        actorType: a.type, // Drizzle name is "type" for "actorType" column
        threatLevel: a.threatLevel,
        mitreAttackTechniques: a.techniques || [],
        malwareFamilies: a.malware || [],
        targetSectors: a.targetSectors || [],
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * CISA KEV from local ioc_feeds table (feedSource = 'cisa_kev', 3,300 entries).
   */
  cisaKEV: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const entries = await db
        .select()
        .from(iocFeeds)
        .where(eq(iocFeeds.feedSource, "cisa_kev"))
        .orderBy(desc(iocFeeds.id))
        .limit(input?.limit || 50);

      const data = entries.map((e) => ({
        cveId: e.cveId,
        cveID: e.cveId,
        vulnerabilityName: e.title,
        shortDescription: e.description,
        vendorProject: e.vendorProduct?.split(" ")[0] || "",
        product: e.vendorProduct || "",
        dateAdded: e.dateAdded,
        dueDate: e.dueDate,
        knownRansomwareCampaignUse: e.knownRansomware ? "Known" : "Unknown",
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Recent victim events from local threat_group_events table (112 events).
   */
  recentVictimEvents: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.actorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.title,
          description: threatGroupEvents.description,
          severity: threatGroupEvents.severity,
          victimName: threatGroupEvents.victimName,
          victimSector: threatGroupEvents.victimSector,
          victimCountry: threatGroupEvents.victimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.source,
          sourceUrl: threatGroupEvents.sourceUrl,
          actorName: threatActors.name,
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.actorId, threatActors.actorId))
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(input?.limit || 50);

      const data = events.map((e) => ({
        actorName: e.actorName || e.actorId,
        eventType: e.eventType,
        title: e.title,
        description: e.description,
        severity: e.severity,
        victimName: e.victimName,
        victimSector: e.victimSector,
        victimCountry: e.victimCountry,
        eventDate: e.eventDate,
        source: e.source,
        sourceUrl: e.sourceUrl,
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * OTX-style pulses — synthesized from threat_group_events + threat_actors.
   * Groups recent events by actor to create "pulse"-like summaries.
   */
  otxPulses: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      // Get recent events grouped by actor as "pulses"
      const events = await db
        .select({
          actorId: threatGroupEvents.actorId,
          actorName: threatActors.name,
          actorType: threatActors.type, // Drizzle name is "type"
          eventCount: sql<number>`COUNT(*)`,
          latestEvent: sql<string>`MAX(${threatGroupEvents.eventDate})`,
          techniques: threatActors.techniques,
          targetSectors: threatActors.targetSectors,
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.actorId, threatActors.actorId))
        .groupBy(threatGroupEvents.actorId, threatActors.name, threatActors.type, threatActors.techniques, threatActors.targetSectors)
        .orderBy(sql`MAX(${threatGroupEvents.eventDate}) DESC`)
        .limit(input?.limit || 25);

      const data = events.map((e) => ({
        name: `${e.actorName || e.actorId} — Recent Activity`,
        title: `${e.actorName || e.actorId} — ${e.eventCount} events`,
        description: `${e.actorType || "Unknown"} group with ${e.eventCount} tracked events. Sectors: ${(e.targetSectors as string[] || []).slice(0, 3).join(", ") || "Various"}`,
        created: e.latestEvent,
        modified: e.latestEvent,
        indicatorCount: e.eventCount,
        tags: [...(e.targetSectors as string[] || []).slice(0, 3), e.actorType].filter(Boolean),
        author: "Local Threat Intel",
        adversary: e.actorName,
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Malware intelligence — from ransomware_groups with associated malware data.
   */
  malwareBazaar: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const groups = await db
        .select({
          groupName: ransomwareGroups.groupName,
          ransomwareFamily: ransomwareGroups.ransomwareFamily,
          associatedMalware: ransomwareGroups.associatedMalware,
          activityScore: ransomwareGroups.activityScore,
          trend: ransomwareGroups.trend,
          threatLevel: ransomwareGroups.threatLevel,
          updatedAt: ransomwareGroups.updatedAt,
        })
        .from(ransomwareGroups)
        .where(sql`${ransomwareGroups.associatedMalware} IS NOT NULL OR ${ransomwareGroups.ransomwareFamily} IS NOT NULL`)
        .orderBy(desc(ransomwareGroups.activityScore))
        .limit(input?.limit || 50);

      const data = groups.map((g) => ({
        sha256: null,
        sha256_hash: null,
        signature: g.ransomwareFamily || g.groupName,
        fileType: "ransomware",
        fileName: null,
        fileSize: null,
        firstSeen: g.updatedAt?.toISOString(),
        lastSeen: g.updatedAt?.toISOString(),
        tags: [g.groupName, g.ransomwareFamily, g.trend].filter(Boolean),
        reporter: "Local Intel",
        groupName: g.groupName,
        malwareFamily: g.ransomwareFamily,
        associatedMalware: g.associatedMalware,
        activityScore: g.activityScore,
        threatLevel: g.threatLevel,
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Adaptive keywords — derived from threat actor names and ransomware families.
   */
  adaptiveKeywords: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

    const groups = await db
      .select({
        groupName: ransomwareGroups.groupName,
        ransomwareFamily: ransomwareGroups.ransomwareFamily,
        activityScore: ransomwareGroups.activityScore,
      })
      .from(ransomwareGroups)
      .orderBy(desc(ransomwareGroups.activityScore))
      .limit(50);

    const data = groups.map((g) => ({
      keyword: g.groupName,
      category: "ransomware_group",
      priority: g.activityScore && g.activityScore > 50 ? "high" : "medium",
      relatedFamily: g.ransomwareFamily,
      source: "local_database",
    }));

    return { data, source: "local_database", fetchedAt: new Date().toISOString() };
  }),

  /**
   * Escalation alerts — high/critical severity events from threat_group_events.
   */
  escalationAlerts: protectedProcedure
    .input(
      z.object({
        severity: z.enum(["critical", "high", "medium", "low"]).optional(),
        limit: z.number().min(1).max(100).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const conditions: any[] = [];
      if (input?.severity) {
        conditions.push(eq(threatGroupEvents.severity, input.severity));
      } else {
        conditions.push(sql`${threatGroupEvents.severity} IN ('critical', 'high')`);
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.actorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.title,
          description: threatGroupEvents.description,
          severity: threatGroupEvents.severity,
          victimName: threatGroupEvents.victimName,
          victimSector: threatGroupEvents.victimSector,
          victimCountry: threatGroupEvents.victimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.source,
          actorName: threatActors.name,
          actorType: threatActors.type, // Drizzle name is "type"
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.actorId, threatActors.actorId))
        .where(where)
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(input?.limit || 25);

      const data = events.map((e) => ({
        id: e.id,
        actorId: e.actorId,
        severity: e.severity || "high",
        title: e.title,
        description: e.description,
        actorName: e.actorName || e.actorId,
        actorType: e.actorType,
        eventType: e.eventType,
        victimName: e.victimName,
        victimSector: e.victimSector,
        victimCountry: e.victimCountry,
        eventDate: e.eventDate,
        source: e.source,
      }));

      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Corroborate discovered assets against local IOC feeds.
   */
  corroborateAssets: protectedProcedure
    .input(
      z.object({
        assets: z.array(
          z.object({
            value: z.string(),
            type: z.enum(["ip", "domain", "url", "hash", "email"]),
          })
        ),
      })
    )
    .mutation(async ({ input }) => {
      // Try SpicyTIP bridge first for corroboration
      const bridgeResult = await corroborateAssets(input.assets);
      if (bridgeResult && bridgeResult.length > 0) {
        return { matches: bridgeResult, source: "spicy_tip", fetchedAt: new Date().toISOString() };
      }

      // Fallback: check against local IOC feeds
      const db = await getDb();
      if (!db) return { matches: [], source: "local_database", fetchedAt: new Date().toISOString() };

      const matches: any[] = [];
      for (const asset of input.assets) {
        const found = await db
          .select()
          .from(iocFeeds)
          .where(like(iocFeeds.iocValue, `%${asset.value}%`))
          .limit(5);

        for (const f of found) {
          matches.push({
            asset: asset.value,
            assetType: asset.type,
            matchedIOC: {
              iocType: f.iocType,
              value: f.iocValue,
              malwareFamily: f.vendorProduct,
              confidence: f.severity === "critical" ? 95 : 70,
            },
            corroborationTier: f.severity === "critical" ? "confirmed" : "probable",
          });
        }
      }

      return { matches, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Access Broker Listings — list all known IABs.
   */
  accessBrokers: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      status: z.enum(["active", "sold", "expired", "removed", "law_enforcement", "all"]).default("all"),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const limit = input?.limit ?? 50;
      const status = input?.status ?? "all";
      const conditions = status !== "all"
        ? [eq(accessBrokerListings.status, status as any)]
        : [];
      const rows = conditions.length > 0
        ? await db.select().from(accessBrokerListings).where(and(...conditions)).limit(limit)
        : await db.select().from(accessBrokerListings).limit(limit);
      return rows;
    }),

  /**
   * Access Broker detail by brokerId.
   */
  accessBrokerDetail: protectedProcedure
    .input(z.object({ brokerId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return null;
      const rows = await db.select().from(accessBrokerListings)
        .where(eq(accessBrokerListings.brokerId, input.brokerId))
        .limit(1);
      return rows[0] || null;
    }),

  /**
   * Information Operations Campaigns — list all known IO campaigns.
   */
  infoOpsCampaigns: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      sponsorState: z.string().optional(),
      status: z.enum(["active", "disrupted", "dormant", "attributed", "ongoing", "all"]).default("all"),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const limit = input?.limit ?? 50;
      const status = input?.status ?? "all";
      const sponsorState = input?.sponsorState;
      const conditions: any[] = [];
      if (status !== "all") conditions.push(eq(infoOpsCampaigns.status, status as any));
      if (sponsorState) conditions.push(eq(infoOpsCampaigns.sponsorState, sponsorState));
      const rows = conditions.length > 0
        ? await db.select().from(infoOpsCampaigns).where(and(...conditions)).limit(limit)
        : await db.select().from(infoOpsCampaigns).limit(limit);
      return rows;
    }),

  /**
   * Info Ops Campaign detail by campaignId.
   */
  infoOpsCampaignDetail: protectedProcedure
    .input(z.object({ campaignId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return null;
      const rows = await db.select().from(infoOpsCampaigns)
        .where(eq(infoOpsCampaigns.campaignId, input.campaignId))
        .limit(1);
      return rows[0] || null;
    }),

  /**
   * Alert detail — full enrichment for a single escalation alert.
   * Returns the event, full threat actor profile, related events, IOCs, and techniques.
   */
  alertDetail: protectedProcedure
    .input(z.object({ eventId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return null;

      // 1. Get the event itself with actor join
      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.actorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.title,
          description: threatGroupEvents.description,
          severity: threatGroupEvents.severity,
          victimName: threatGroupEvents.victimName,
          victimSector: threatGroupEvents.victimSector,
          victimCountry: threatGroupEvents.victimCountry,
          mitreTechniques: threatGroupEvents.mitreTechniques,
          iocs: threatGroupEvents.iocs,
          source: threatGroupEvents.source,
          sourceUrl: threatGroupEvents.sourceUrl,
          confidence: threatGroupEvents.confidence,
          eventDate: threatGroupEvents.eventDate,
          discoveredAt: threatGroupEvents.discoveredAt,
          createdAt: threatGroupEvents.createdAt,
        })
        .from(threatGroupEvents)
        .where(eq(threatGroupEvents.id, input.eventId))
        .limit(1);

      if (!events.length) return null;
      const event = events[0];

      // 2. Get the full threat actor profile
      const actors = await db
        .select()
        .from(threatActors)
        .where(eq(threatActors.actorId, event.actorId))
        .limit(1);
      const actor = actors[0] || null;

      // 3. Get related events by the same actor (last 10)
      const relatedEvents = await db
        .select({
          id: threatGroupEvents.id,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.title,
          severity: threatGroupEvents.severity,
          victimName: threatGroupEvents.victimName,
          victimSector: threatGroupEvents.victimSector,
          victimCountry: threatGroupEvents.victimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.source,
        })
        .from(threatGroupEvents)
        .where(and(
          eq(threatGroupEvents.actorId, event.actorId),
          sql`${threatGroupEvents.id} != ${input.eventId}`
        ))
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(10);

      // 4. Get IOCs linked to this actor
      const actorIocs = await db
        .select()
        .from(threatActorIocs)
        .where(eq(threatActorIocs.actorId, event.actorId))
        .limit(20);

      // 5. Check if actor is also a ransomware group
      let ransomwareProfile = null;
      if (actor) {
        const rwGroups = await db
          .select()
          .from(ransomwareGroups)
          .where(sql`${ransomwareGroups.groupName} = ${actor.name} OR ${ransomwareGroups.calderaActorId} = ${actor.actorId}`)
          .limit(1);
        ransomwareProfile = rwGroups[0] || null;
      }

      // 6. Check for access broker listings mentioning this actor
      let brokerListings: any[] = [];
      if (actor) {
        brokerListings = await db
          .select({
            brokerId: accessBrokerListings.brokerId,
            brokerName: accessBrokerListings.brokerName,
            victimSector: accessBrokerListings.victimSector,
            victimCountry: accessBrokerListings.victimCountry,
            accessType: accessBrokerListings.accessType,
            askingPrice: accessBrokerListings.askingPrice,
            status: accessBrokerListings.status,
          })
          .from(accessBrokerListings)
          .where(sql`JSON_CONTAINS(${accessBrokerListings.linkedActorIds}, JSON_QUOTE(${actor.actorId}))`)
          .limit(5);
      }

      return {
        event: {
          ...event,
          mitreTechniques: safeParseJson(event.mitreTechniques),
          iocs: safeParseJson(event.iocs),
        },
        actor: actor ? {
          actorId: actor.actorId,
          name: actor.name,
          aliases: safeParseJson(actor.aliases),
          type: actor.type,
          origin: actor.origin,
          description: actor.description,
          motivation: actor.motivation,
          firstSeen: actor.firstSeen,
          lastActive: actor.lastActive,
          threatLevel: actor.threatLevel,
          sophistication: actor.sophistication,
          targetSectors: safeParseJson(actor.targetSectors),
          targetRegions: safeParseJson(actor.targetRegions),
          techniques: safeParseJson(actor.techniques),
          tools: safeParseJson(actor.tools),
          malware: safeParseJson(actor.malware),
          activityTimeline: safeParseJson(actor.activityTimeline),
          confidence: actor.confidence,
          dataSource: actor.dataSource,
        } : null,
        relatedEvents,
        actorIocs: actorIocs.map(ioc => ({
          type: ioc.type,
          value: ioc.value,
          description: ioc.description,
          firstSeen: ioc.firstSeen,
          lastSeen: ioc.lastSeen,
          confidence: ioc.confidence,
          source: ioc.source,
        })),
        ransomwareProfile: ransomwareProfile ? {
          groupName: ransomwareProfile.groupName,
          activityScore: ransomwareProfile.activityScore,
          trend: ransomwareProfile.trend,
          threatLevel: ransomwareProfile.threatLevel,
          victims7d: ransomwareProfile.victims7d,
          victims30d: ransomwareProfile.victims30d,
          totalVictims: ransomwareProfile.totalVictims,
          topSectors: ransomwareProfile.topSectors,
          topCountries: ransomwareProfile.topCountries,
          ransomwareFamily: ransomwareProfile.ransomwareFamily,
          extortionModel: ransomwareProfile.extortionModel,
          knownInfrastructure: safeParseJson(ransomwareProfile.knownInfrastructure),
        } : null,
        brokerListings,
      };
    }),

  /**
   * Sync darkweb feeds — IABs + IO campaigns.
   */
  syncDarkwebFeeds: protectedProcedure.mutation(async () => {
    const { syncAllDarkwebFeeds } = await import("../lib/darkweb-feeds");
    const result = await syncAllDarkwebFeeds();
    return result;
  }),

  /**
   * Full sync — triggers the existing IOC sync + threat intel connectors.
   */
  syncAll: protectedProcedure.mutation(async () => {
    // Try SpicyTIP sync first
    const bridgeResult = await syncDarkwebIntelligence();

    // Also trigger local IOC sync
    try {
      const { runIocSync, isSyncRunning } = await import("../lib/ioc-sync");
      if (!isSyncRunning()) {
        const iocResult = await runIocSync("manual");
        return {
          actorsImported: bridgeResult?.actorsImported || 0,
          iocsImported: (bridgeResult?.iocsImported || 0) + (iocResult?.totalFetched || 0),
          eventsImported: bridgeResult?.eventsImported || 0,
          ratingsUpdated: bridgeResult?.ratingsUpdated || 0,
          errors: bridgeResult?.errors || [],
          source: "local_database + ioc_sync",
        };
      }
    } catch (err: any) {
      console.error("[DarkwebBridge] IOC sync fallback failed:", err.message);
    }

    return bridgeResult || {
      actorsImported: 0,
      iocsImported: 0,
      eventsImported: 0,
      ratingsUpdated: 0,
      errors: ["Sync completed with local data only"],
    };
  }),
});
