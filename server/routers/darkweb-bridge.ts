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
} from "../../drizzle/schema";
import { desc, eq, sql, and, like } from "drizzle-orm";

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
