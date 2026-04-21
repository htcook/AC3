import * as db from "../db";
/**
 * Darkweb Intelligence Router
 *
 * Self-contained tRPC router for the darkweb intelligence pipeline.
 * Provides endpoints for:
 *   - Feed management (registry, sync, health)
 *   - Underground intel events (CRUD, stats, search)
 *   - Network events (C2, botnets, Tor, blocklists)
 *   - Credential exposures (HIBP breaches)
 *   - IAB activity
 *   - Influence operations
 *   - Ransomware affiliates
 *   - LLM enrichment
 *   - Trend analysis & sector profiles
 *   - Cross-source correlation
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
  infoOpsCampaigns as infoOpsCampaignsTable,
} from "../../drizzle/schema";
import { desc, eq, sql, and, count, gte } from "drizzle-orm";
import {
  initFeedRegistry,
  runDarkwebFeedSync,
  isDarkwebSyncRunning,
  getFeedHealthSummary,
  fetchFeodoTracker,
  fetchMalwareBazaar,
  fetchSSLBlacklist,
  fetchRansomwareLiveVictims,
  fetchRansomwareLiveGroups,
  fetchAlienVaultOTX,
  fetchOpenPhish,
  fetchTorExitNodes,
  fetchBlocklistDe,
  fetchSpamhausDrop,
  fetchHIBPBreaches,
} from "../lib/darkweb-osint-service";
import {
  enrichEvent,
  enrichBatch,
  getEnrichmentStats,
} from "../lib/darkweb-enrichment-service";
import {
  getUndergroundEvents,
  getUndergroundEventById,
  getUndergroundEventStats,
  getNetworkEvents,
  getNetworkEventStats,
  getIabActivities,
  getCredentialExposures,
  getCredentialExposureStats,
  getInfluenceOperations,
  getEnrichedRecords,
  getRansomwareAffiliates,
  getFeedRegistry,
  toggleFeed,
  getDarkwebDashboardStats,
} from "../lib/darkweb-mysql-service";
import {
  syncRansomwareActors,
  getSectorThreatProfiles,
  getDarkwebTrends,
  correlateActor,
  getHighPriorityEvents,
} from "../lib/darkweb-intel-service";
import { classifyAllListings, classifyListing } from "../lib/iab-priority-classifier";

// ─── Router ─────────────────────────────────────────────────────────────

export const darkwebIntelRouter = router({
  // ── Feed Management ──────────────────────────────────────────────────

  /** Initialize the feed registry with all built-in feeds. */
  initFeeds: protectedProcedure.mutation(async () => {
    await initFeedRegistry();
    return { success: true };
  }),

  /** Get feed health summary for all registered feeds. */
  feedHealth: protectedProcedure.query(async () => {
    return getFeedHealthSummary();
  }),

  /** Get full feed registry. */
  feedRegistry: protectedProcedure.query(async () => {
    return getFeedRegistry();
  }),

  /** Toggle a feed on/off. */
  toggleFeed: protectedProcedure
    .input(z.object({ feedName: z.string(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      await toggleFeed(input.feedName, input.enabled);
      return { success: true };
    }),

  /** Run a full feed sync across all enabled feeds. */
  syncAllFeeds: protectedProcedure
    .input(z.object({ feedNames: z.array(z.string()).optional() }).optional())
    .mutation(async ({ input }) => {
      if (isDarkwebSyncRunning()) {
        return { error: "Feed sync is already running", running: true };
      }
      const result = await runDarkwebFeedSync(input?.feedNames);
      return { ...result, running: false };
    }),

  /** Sync a single feed by name. */
  syncSingleFeed: protectedProcedure
    .input(z.object({ feedName: z.string() }))
    .mutation(async ({ input }) => {
      const feedMap: Record<string, () => Promise<any>> = {
        feodo_tracker: fetchFeodoTracker,
        malwarebazaar: fetchMalwareBazaar,
        ssl_blacklist: fetchSSLBlacklist,
        ransomware_live_victims: fetchRansomwareLiveVictims,
        ransomware_live_groups: fetchRansomwareLiveGroups,
        alienvault_otx: fetchAlienVaultOTX,
        openphish: fetchOpenPhish,
        tor_exit_nodes: fetchTorExitNodes,
        blocklist_de: fetchBlocklistDe,
        spamhaus_drop: fetchSpamhausDrop,
        hibp_breaches: fetchHIBPBreaches,
      };
      const fn = feedMap[input.feedName];
      if (!fn) return { error: `Unknown feed: ${input.feedName}` };
      return fn();
    }),

  /** Check if a sync is currently running. */
  syncStatus: protectedProcedure.query(() => {
    return { running: isDarkwebSyncRunning() };
  }),

  // ── Underground Intel Events ─────────────────────────────────────────

  /** List underground intel events with filtering. */
  listEvents: protectedProcedure
    .input(z.object({
      category: z.string().optional(),
      source: z.string().optional(),
      severity: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getUndergroundEvents(input || {});
    }),

  /** Get a single event by ID. */
  getEvent: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      return getUndergroundEventById(input.id);
    }),

  /** Get event statistics by category and severity. */
  eventStats: protectedProcedure.query(async () => {
    return getUndergroundEventStats();
  }),

  /** Get high-priority events (critical + high severity). */
  highPriorityEvents: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).optional() }).optional())
    .query(async ({ input }) => {
      return getHighPriorityEvents(input?.limit);
    }),

  // ── Network Events ───────────────────────────────────────────────────

  /** List network events (C2, botnets, Tor, blocklists). */
  listNetworkEvents: protectedProcedure
    .input(z.object({
      eventType: z.string().optional(),
      source: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getNetworkEvents(input || {});
    }),

  /** Get network event statistics. */
  networkEventStats: protectedProcedure.query(async () => {
    return getNetworkEventStats();
  }),

  // ── Credential Exposures ─────────────────────────────────────────────

  /** List credential exposures / breaches. */
  listCredentialExposures: protectedProcedure
    .input(z.object({
      severity: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getCredentialExposures(input || {});
    }),

  /** Get credential exposure statistics. */
  credentialStats: protectedProcedure.query(async () => {
    return getCredentialExposureStats();
  }),

  // ── IAB Activity ─────────────────────────────────────────────────────

  /** List initial access broker activity. */
  listIabActivity: protectedProcedure
    .input(z.object({
      status: z.string().optional(),
      listingType: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getIabActivities(input || {});
    }),

  // ── Influence Operations ─────────────────────────────────────────────

  /** List influence operations. */
  listInfluenceOps: protectedProcedure
    .input(z.object({
      status: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getInfluenceOperations(input || {});
    }),

  // ── Ransomware Affiliates ────────────────────────────────────────────

  /** List ransomware affiliates. */
  listAffiliates: protectedProcedure
    .input(z.object({
      status: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getRansomwareAffiliates(input || {});
    }),

  /** Sync ransomware actors from event data into affiliates table. */
  syncActors: protectedProcedure.mutation(async () => {
    return syncRansomwareActors();
  }),

  // ── Enrichment ───────────────────────────────────────────────────────

  /** Enrich a single event with LLM analysis. */
  enrichEvent: protectedProcedure
    .input(z.object({ eventId: z.number() }))
    .mutation(async ({ input }) => {
      return enrichEvent(input.eventId);
    }),

  /** Batch-enrich unenriched events. */
  enrichBatch: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(50).optional() }).optional())
    .mutation(async ({ input }) => {
      return enrichBatch(input?.limit);
    }),

  /** Get enrichment statistics. */
  enrichmentStats: protectedProcedure.query(async () => {
    return getEnrichmentStats();
  }),

  /** Get enriched records (sorted by risk score). */
  listEnrichedRecords: protectedProcedure
    .input(z.object({
      minRiskScore: z.number().min(0).max(100).optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getEnrichedRecords(input || {});
    }),

  // ── Analysis ─────────────────────────────────────────────────────────

  /** Get sector-based threat profiles. */
  sectorProfiles: protectedProcedure.query(async () => {
    return getSectorThreatProfiles();
  }),

  /** Get daily event trends for the last N days. */
  trends: protectedProcedure
    .input(z.object({ days: z.number().min(7).max(365).optional() }).optional())
    .query(async ({ input }) => {
      return getDarkwebTrends(input?.days);
    }),

  /** Correlate a threat actor across all darkweb tables. */
  correlateActor: protectedProcedure
    .input(z.object({ actorName: z.string() }))
    .query(async ({ input }) => {
      return correlateActor(input.actorName);
    }),

  // ── IOC Enrichment ──────────────────────────────────────────────────

  /** Enrich a single IOC with darkweb context from all sources. */
  enrichIoc: protectedProcedure
    .input(z.object({
      ioc: z.string(),
      iocType: z.enum(["ip", "domain", "url", "hash", "email", "cve"]),
    }))
    .query(async ({ input }) => {
      const { enrichIocWithDarkweb } = await import("../lib/darkweb-ioc-enrichment");
      return enrichIocWithDarkweb(input.ioc, input.iocType);
    }),

  /** Batch-enrich multiple IOCs with darkweb context. */
  enrichIocBatch: protectedProcedure
    .input(z.object({
      iocs: z.array(z.object({
        value: z.string(),
        type: z.enum(["ip", "domain", "url", "hash", "email", "cve"]),
      })).max(50),
    }))
    .mutation(async ({ input }) => {
      const { enrichIocBatchWithDarkweb } = await import("../lib/darkweb-ioc-enrichment");
      return enrichIocBatchWithDarkweb(input.iocs);
    }),

   // ── Dashboard ────────────────────────────────────────────────────────
  /** Get aggregated dashboard statistics across all darkweb tables. */
  dashboardStats: protectedProcedure.query(async () => {
    return getDarkwebDashboardStats();
  }),

  // ══════════════════════════════════════════════════════════════════════
  // Bridge-equivalent procedures (migrated from darkwebBridge router)
  // These query the same local tables so the UI can switch over fully.
  // ══════════════════════════════════════════════════════════════════════

  /** Health check — always reports local data availability. */
  health: protectedProcedure.query(async () => {
    return {
      configured: true,
      reachable: true,
      hasFallback: true,
      source: "local_database",
      baseUrl: "",
      bridgeReachable: false,
    };
  }),

  /** Ransomware victim statistics from local ransomware_groups table. */
  ransomwareVictimStats: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const groups = await db
        .select({
          groupName: ransomwareGroups.groupName,
          totalVictims: ransomwareGroups.totalVictims,
          victims7d: ransomwareGroups.victims7D,
          victims30d: ransomwareGroups.victims30D,
          activityScore: ransomwareGroups.activityScore,
          trend: ransomwareGroups.trend,
          threatLevel: ransomwareGroups.rwThreatLevel,
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

  /** IOCs from local ioc_feeds table mapped to ThreatFox-compatible format. */
  threatFoxIOCs: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(500).optional(),
      type: z.enum(["ip", "domain", "url", "hash", "email"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const conditions: any[] = [];
      if (input?.type) conditions.push(eq(iocFeeds.feedIocType, input.type));
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const entries = await db.select().from(iocFeeds).where(where).orderBy(desc(iocFeeds.fetchedAt), desc(iocFeeds.id)).limit(input?.limit || 100);
      const data = entries.map((e) => ({
        iocType: e.feedIocType || "cve",
        type: e.feedIocType || "cve",
        value: e.iocValue,
        ioc: e.iocValue,
        malwareFamily: e.vendorProduct || null,
        confidence: e.feedSeverity === "critical" ? 95 : e.feedSeverity === "high" ? 80 : 60,
        firstSeen: e.dateAdded || e.fetchedAt?.toISOString(),
        tags: e.feedTags || [],
        title: e.title,
        description: e.description,
        source: e.feedSource,
        cveId: e.cveId,
        knownRansomware: e.knownRansomware,
      }));
      return { data, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /** Activity ratings from ransomware_groups. */
  activityRatings: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
    const groups = await db
      .select({
        groupName: ransomwareGroups.groupName,
        activityScore: ransomwareGroups.activityScore,
        trend: ransomwareGroups.trend,
        threatLevel: ransomwareGroups.rwThreatLevel,
        victims7d: ransomwareGroups.victims7D,
        victims30d: ransomwareGroups.victims30D,
      })
      .from(ransomwareGroups)
      .orderBy(desc(ransomwareGroups.activityScore))
      .limit(30);
    const data = groups.map((g) => ({
      groupName: g.groupName,
      activityScore: g.activityScore || 0,
      trend: g.trend || "stable",
      threatLevel: g.threatLevel || "medium",
      victims7d: g.victims7d || 0,
      victims30d: g.victims30d || 0,
    }));
    return { data, source: "local_database", fetchedAt: new Date().toISOString() };
  }),

  /** CISA KEV entries from ioc_feeds. */
  cisaKEV: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const entries = await db.select().from(iocFeeds)
        .where(eq(iocFeeds.feedSource, "cisa_kev"))
        .orderBy(desc(iocFeeds.fetchedAt), desc(iocFeeds.id))
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

  /** Recent victim events from threat_group_events. */
  recentVictimEvents: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).optional(),
      search: z.string().optional(),
      country: z.string().optional(),
      sector: z.string().optional(),
      actorName: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString(), filters: { countries: [], sectors: [], actors: [] } };
      // Build WHERE conditions
      const conditions: any[] = [];
      if (input?.country) conditions.push(eq(threatGroupEvents.tgeVictimCountry, input.country));
      if (input?.sector) conditions.push(eq(threatGroupEvents.tgeVictimSector, input.sector));
      if (input?.actorName) conditions.push(eq(threatActors.name, input.actorName));
      if (input?.search) {
        const term = `%${input.search}%`;
        conditions.push(sql`(${threatGroupEvents.tgeVictimName} LIKE ${term} OR ${threatGroupEvents.tgeDescription} LIKE ${term} OR ${threatGroupEvents.tgeTitle} LIKE ${term})`);
      }
      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.tgeActorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.tgeTitle,
          description: threatGroupEvents.tgeDescription,
          severity: threatGroupEvents.tgeSeverity,
          victimName: threatGroupEvents.tgeVictimName,
          victimSector: threatGroupEvents.tgeVictimSector,
          victimCountry: threatGroupEvents.tgeVictimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.tgeSource,
          sourceUrl: threatGroupEvents.tgeSourceUrl,
          actorName: threatActors.name,
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.tgeActorId, threatActors.actorId))
        .where(whereClause)
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(input?.limit || 100);
      // Get IOC counts per actor for enrichment badges
      const actorIds = [...new Set(events.map(e => e.actorId))];
      const iocCountMap: Record<string, number> = {};
      if (actorIds.length > 0) {
        const iocCounts = await db
          .select({ actorId: threatActorIocs.actorId, count: sql<number>`COUNT(*)` })
          .from(threatActorIocs)
          .where(sql`${threatActorIocs.actorId} IN (${sql.join(actorIds.map(id => sql`${id}`), sql`, `)})`)
          .groupBy(threatActorIocs.actorId);
        for (const row of iocCounts) iocCountMap[row.actorId] = row.count;
      }
      const data = events.map((e) => ({
        id: e.id,
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
        iocCount: iocCountMap[e.actorId] || 0,
      }));
      // Get filter options
      const [countries, sectors, actors] = await Promise.all([
        db.selectDistinct({ value: threatGroupEvents.tgeVictimCountry }).from(threatGroupEvents).where(sql`${threatGroupEvents.tgeVictimCountry} IS NOT NULL AND ${threatGroupEvents.tgeVictimCountry} != ''`).orderBy(threatGroupEvents.tgeVictimCountry),
        db.selectDistinct({ value: threatGroupEvents.tgeVictimSector }).from(threatGroupEvents).where(sql`${threatGroupEvents.tgeVictimSector} IS NOT NULL AND ${threatGroupEvents.tgeVictimSector} != ''`).orderBy(threatGroupEvents.tgeVictimSector),
        db.selectDistinct({ value: threatActors.name }).from(threatGroupEvents).leftJoin(threatActors, eq(threatGroupEvents.tgeActorId, threatActors.actorId)).where(sql`${threatActors.name} IS NOT NULL`).orderBy(threatActors.name),
      ]);
      return {
        data,
        source: "local_database",
        fetchedAt: new Date().toISOString(),
        filters: {
          countries: countries.map(c => c.value).filter(Boolean) as string[],
          sectors: sectors.map(s => s.value).filter(Boolean) as string[],
          actors: actors.map(a => a.value).filter(Boolean) as string[],
        },
      };
    }),

  /** OTX-style pulses synthesized from threat_group_events + threat_actors. */
  otxPulses: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const events = await db
        .select({
          actorId: threatGroupEvents.tgeActorId,
          actorName: threatActors.name,
          actorType: threatActors.actorType,
          eventCount: sql<number>`COUNT(*)`,
          latestEvent: sql<string>`MAX(${threatGroupEvents.eventDate})`,
          techniques: threatActors.techniques,
          targetSectors: threatActors.targetSectors,
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.tgeActorId, threatActors.actorId))
        .groupBy(threatGroupEvents.tgeActorId, threatActors.name, threatActors.actorType, threatActors.techniques, threatActors.targetSectors)
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

  /** Malware intelligence from ransomware_groups. */
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
          threatLevel: ransomwareGroups.rwThreatLevel,
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

  /** Adaptive keywords derived from threat actor names and ransomware families. */
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

  /** Escalation alerts — high/critical severity events. */
  escalationAlerts: protectedProcedure
    .input(z.object({
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      limit: z.number().min(1).max(100).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { data: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const conditions: any[] = [];
      if (input?.severity) {
        conditions.push(eq(threatGroupEvents.tgeSeverity, input.severity));
      } else {
        conditions.push(sql`${threatGroupEvents.tgeSeverity} IN ('critical', 'high')`);
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.tgeActorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.tgeTitle,
          description: threatGroupEvents.tgeDescription,
          severity: threatGroupEvents.tgeSeverity,
          victimName: threatGroupEvents.tgeVictimName,
          victimSector: threatGroupEvents.tgeVictimSector,
          victimCountry: threatGroupEvents.tgeVictimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.tgeSource,
          actorName: threatActors.name,
          actorType: threatActors.actorType,
        })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.tgeActorId, threatActors.actorId))
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

  /** Access broker listings. */
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
        ? [eq(accessBrokerListings.iabStatus, status as any)]
        : [];
      const rows = conditions.length > 0
        ? await db.select().from(accessBrokerListings).where(and(...conditions)).orderBy(desc(accessBrokerListings.postedAt), desc(accessBrokerListings.iabCreatedAt)).limit(limit)
        : await db.select().from(accessBrokerListings).orderBy(desc(accessBrokerListings.postedAt), desc(accessBrokerListings.iabCreatedAt)).limit(limit);
      return rows;
    }),

  /** Information Operations Campaigns. */
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
      if (status !== "all") conditions.push(eq(infoOpsCampaignsTable.ioStatus, status as any));
      if (sponsorState) conditions.push(eq(infoOpsCampaignsTable.sponsorState, sponsorState));
      const rows = conditions.length > 0
        ? await db.select().from(infoOpsCampaignsTable).where(and(...conditions)).limit(limit)
        : await db.select().from(infoOpsCampaignsTable).limit(limit);
      return rows;
    }),

  /** Alert detail — full enrichment for a single escalation alert. */
  alertDetail: protectedProcedure
    .input(z.object({ eventId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return null;
      function safeParseJson(val: unknown): any[] {
        if (Array.isArray(val)) return val;
        if (typeof val === 'string') { try { return JSON.parse(val); } catch { return []; } }
        if (val && typeof val === 'object') return [val];
        return [];
      }
      const events = await db
        .select({
          id: threatGroupEvents.id,
          actorId: threatGroupEvents.tgeActorId,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.tgeTitle,
          description: threatGroupEvents.tgeDescription,
          severity: threatGroupEvents.tgeSeverity,
          victimName: threatGroupEvents.tgeVictimName,
          victimSector: threatGroupEvents.tgeVictimSector,
          victimCountry: threatGroupEvents.tgeVictimCountry,
          mitreTechniques: threatGroupEvents.tgeMitreTechniques,
          iocs: threatGroupEvents.tgeIocs,
          source: threatGroupEvents.tgeSource,
          sourceUrl: threatGroupEvents.tgeSourceUrl,
          confidence: threatGroupEvents.tgeConfidence,
          eventDate: threatGroupEvents.eventDate,
          discoveredAt: threatGroupEvents.discoveredAt,
          createdAt: threatGroupEvents.tgeCreatedAt,
        })
        .from(threatGroupEvents)
        .where(eq(threatGroupEvents.id, input.eventId))
        .limit(1);
      if (!events.length) return null;
      const event = events[0];
      const actors = await db.select().from(threatActors)
        .where(eq(threatActors.actorId, event.actorId)).limit(1);
      const actor = actors[0] || null;
      const relatedEvents = await db
        .select({
          id: threatGroupEvents.id,
          eventType: threatGroupEvents.eventType,
          title: threatGroupEvents.tgeTitle,
          severity: threatGroupEvents.tgeSeverity,
          victimName: threatGroupEvents.tgeVictimName,
          victimSector: threatGroupEvents.tgeVictimSector,
          victimCountry: threatGroupEvents.tgeVictimCountry,
          eventDate: threatGroupEvents.eventDate,
          source: threatGroupEvents.tgeSource,
        })
        .from(threatGroupEvents)
        .where(and(
          eq(threatGroupEvents.tgeActorId, event.actorId),
          sql`${threatGroupEvents.id} != ${input.eventId}`
        ))
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(10);
      const actorIocs = await db.select().from(threatActorIocs)
        .where(eq(threatActorIocs.actorId, event.actorId)).limit(20);
      let ransomwareProfile = null;
      if (actor) {
        const rwGroups = await db.select().from(ransomwareGroups)
          .where(sql`${ransomwareGroups.groupName} = ${actor.name} OR ${ransomwareGroups.calderaActorId} = ${actor.actorId}`)
          .limit(1);
        ransomwareProfile = rwGroups[0] || null;
      }
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
            status: accessBrokerListings.iabStatus,
          })
          .from(accessBrokerListings)
          .where(sql`JSON_CONTAINS(${accessBrokerListings.linkedActorIds}, JSON_QUOTE(${actor.actorId}))`)
          .limit(5);
      }
      // Also fetch IOCs from ioc_feeds table for enrichment
      let feedIocs: any[] = [];
      if (actor && actor.name) {
        try {
          feedIocs = await db.select({
            id: iocFeeds.id,
            iocType: iocFeeds.feedIocType,
            iocValue: iocFeeds.iocValue,
            feedSource: iocFeeds.feedSource,
            feedType: iocFeeds.feedType,
            severity: iocFeeds.feedSeverity,
            title: iocFeeds.title,
            vendorProduct: iocFeeds.vendorProduct,
            tags: iocFeeds.feedTags,
            dateAdded: iocFeeds.dateAdded,
          }).from(iocFeeds)
            .where(sql`CAST(${iocFeeds.feedTags} AS CHAR) LIKE ${'%' + actor.name + '%'} OR ${iocFeeds.vendorProduct} LIKE ${'%' + actor.name + '%'} OR ${iocFeeds.title} LIKE ${'%' + actor.name + '%'}`)
            .limit(50);
        } catch {
          feedIocs = [];
        }
      }
      return {
        event: { ...event, mitreTechniques: safeParseJson(event.mitreTechniques), iocs: safeParseJson(event.iocs) },
        actor: actor ? {
          actorId: actor.actorId, name: actor.name, aliases: safeParseJson(actor.aliases),
          type: actor.actorType, origin: actor.origin, description: actor.description,
          motivation: actor.motivation, firstSeen: actor.firstSeen, lastActive: actor.lastActive,
          threatLevel: actor.threatLevel, sophistication: actor.sophistication,
          targetSectors: safeParseJson(actor.targetSectors), targetRegions: safeParseJson(actor.targetRegions),
          techniques: safeParseJson(actor.techniques), tools: safeParseJson(actor.tools),
          malware: safeParseJson(actor.malware), activityTimeline: safeParseJson(actor.activityTimeline),
          confidence: actor.confidence, dataSource: actor.dataSource,
        } : null,
        relatedEvents,
        actorIocs: actorIocs.map(ioc => ({
          type: ioc.iocType, value: ioc.value, description: ioc.description,
          firstSeen: ioc.iocFirstSeen, lastSeen: ioc.iocLastSeen, confidence: ioc.iocConfidence, source: ioc.source,
        })),
        feedIocs: feedIocs.map(ioc => ({
          id: ioc.id, iocType: ioc.iocType, iocValue: ioc.iocValue,
          threatType: ioc.feedType, malwareFamily: ioc.vendorProduct,
          confidence: ioc.severity === 'critical' ? 95 : ioc.severity === 'high' ? 80 : 60,
          source: ioc.feedSource,
          firstSeen: ioc.dateAdded, lastSeen: null,
        })),
        ransomwareProfile: ransomwareProfile ? {
          groupName: ransomwareProfile.groupName, activityScore: ransomwareProfile.activityScore,
          trend: ransomwareProfile.trend, threatLevel: ransomwareProfile.rwThreatLevel,
          victims7d: ransomwareProfile.victims7D, victims30d: ransomwareProfile.victims30D,
          totalVictims: ransomwareProfile.totalVictims, topSectors: ransomwareProfile.topSectors,
          topCountries: ransomwareProfile.topCountries, ransomwareFamily: ransomwareProfile.ransomwareFamily,
          extortionModel: ransomwareProfile.extortionModel,
          knownInfrastructure: safeParseJson(ransomwareProfile.knownInfrastructure),
        } : null,
        brokerListings,
      };
    }),

  /** Corroborate assets against local IOC feeds. */
  corroborateAssets: protectedProcedure
    .input(z.object({
      assets: z.array(z.object({
        value: z.string(),
        type: z.enum(["ip", "domain", "url", "hash", "email"]),
      })),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) return { matches: [], source: "local_database", fetchedAt: new Date().toISOString() };
      const matches: any[] = [];
      for (const asset of input.assets) {
        const rows = await db.select().from(iocFeeds)
          .where(eq(iocFeeds.iocValue, asset.value)).limit(5);
        if (rows.length > 0) {
          matches.push({
            asset: asset.value,
            type: asset.type,
            hits: rows.map(r => ({
              feedSource: r.feedSource,
              severity: r.feedSeverity,
              title: r.title,
              cveId: r.cveId,
              knownRansomware: r.knownRansomware,
            })),
          });
        }
      }
      return { matches, source: "local_database", fetchedAt: new Date().toISOString() };
    }),

  /** Sync darkweb feeds — IABs + IO campaigns + Daily Dark Web. */
  syncDarkwebFeeds: protectedProcedure.mutation(async () => {
    const { syncAllDarkwebFeeds } = await import("../lib/darkweb-feeds");
    const result = await syncAllDarkwebFeeds();
    return result;
  }),

  /** Sync Daily Dark Web feed only — threat actors, IOCs, events. */
  syncDailyDarkWeb: protectedProcedure.mutation(async () => {
    const { syncDailyDarkWebFeed } = await import("../lib/dailydarkweb-feed");
    const result = await syncDailyDarkWebFeed();
    return result;
  }),

  /** Full sync — triggers IOC sync + darkweb feed sync. */
  syncAll: protectedProcedure.mutation(async () => {
    // Trigger local IOC sync
    try {
      const { runIocSync, isSyncRunning } = await import("../lib/ioc-sync");
      if (!isSyncRunning()) {
        const iocResult = await runIocSync("manual");
        // Also trigger darkweb feed sync
        let darkwebResult: any = null;
        try {
          darkwebResult = await runDarkwebFeedSync();
        } catch (e) { /* ignore */ }
        // Also trigger multi-source RSS sync (Tier 1 only for speed)
        let rssResult: any = null;
        try {
          const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
          rssResult = await syncAllThreatIntelFeeds({ tiers: [1] });
        } catch (e) { /* ignore */ }
        return {
          actorsImported: rssResult?.totalActorsUpdated || 0,
          iocsImported: iocResult?.totalFetched || 0,
          eventsImported: (darkwebResult?.totalInserted || 0) + (rssResult?.totalThreatGroupEvents || 0) + (rssResult?.totalRansomwareEvents || 0) + (rssResult?.totalUndergroundEvents || 0) + (rssResult?.totalIncidentReports || 0),
          ratingsUpdated: 0,
          errors: [],
          source: "local_database + darkweb_feeds + multi_source_rss",
        };
      }
    } catch (err: any) {
      console.error("[DarkwebIntel] IOC sync failed:", err.message);
    }
    return {
      actorsImported: 0,
      iocsImported: 0,
      eventsImported: 0,
      ratingsUpdated: 0,
      errors: ["Sync already running"],
    };
  }),

  // ─── Scheduler Management ─────────────────────────────────────────

  schedulerStatus: protectedProcedure.query(async () => {
    const { isDarkwebSchedulerActive } = await import("../lib/darkweb-feed-scheduler");
    return {
      active: isDarkwebSchedulerActive(),
      schedules: [
        { feed: "abuse.ch (Feodo, MalwareBazaar, SSL Blacklist)", interval: "Every 6 hours", nextApprox: "xx:00 UTC" },
        { feed: "ransomware.live (victims + groups)", interval: "Every 6 hours", nextApprox: "xx:30 UTC" },
        { feed: "AlienVault OTX, OpenPhish, Tor Exit Nodes", interval: "Every 12 hours", nextApprox: "03:00 / 15:00 UTC" },
        { feed: "Blocklist.de, Spamhaus DROP, HIBP", interval: "Daily", nextApprox: "04:00 UTC" },
        { feed: "IAB + Influence Ops", interval: "Daily", nextApprox: "08:00 UTC" },
        { feed: "Daily Dark Web (threat actors, IOCs, events)", interval: "Daily", nextApprox: "08:30 UTC" },
        { feed: "LLM Enrichment Batch", interval: "Daily", nextApprox: "09:00 UTC" },
      ],
    };
  }),

  triggerFullSync: protectedProcedure.mutation(async () => {
    const { runFullDarkwebSync } = await import("../lib/darkweb-feed-scheduler");
    const result = await runFullDarkwebSync();
    return result;
  }),

  // ─── RSS Automation ──────────────────────────────────────────────

  /** Fetch Daily Dark Web RSS feed and auto-ingest new threat events. */
  syncDailyDarkWebRSS: protectedProcedure
    .input(z.object({ useAllFeeds: z.boolean().optional() }).optional())
    .mutation(async ({ input }) => {
      const { syncDailyDarkWebRSS } = await import("../lib/dailydarkweb-rss");
      const result = await syncDailyDarkWebRSS(input?.useAllFeeds ?? false);
      return result;
    }),

  /** Get available RSS feed URLs for Daily Dark Web. */
  getDDWRSSFeeds: protectedProcedure.query(async () => {
    const { DDW_RSS_FEEDS } = await import("../lib/dailydarkweb-rss");
    return DDW_RSS_FEEDS;
  }),

  // ─── IOC Cross-Reference ─────────────────────────────────────────

  /** Cross-reference threat actor IOCs against discovered engagement assets. */
  crossReferenceIOCs: protectedProcedure
    .input(z.object({
      actorId: z.string().optional(),
      engagementId: z.number().optional(),
      scanId: z.number().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { crossReferenceIOCs } = await import("../lib/ioc-cross-reference");
      const result = await crossReferenceIOCs(input ?? undefined);
      return result;
    }),

  /** Cross-reference FULCRUMSEC IOCs specifically against all engagement assets. */
  crossReferenceFulcrumsec: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { crossReferenceIOCs } = await import("../lib/ioc-cross-reference");
      const result = await crossReferenceIOCs({
        actorId: "fulcrumsec",
        engagementId: input?.engagementId,
      });
      return result;
    }),

  /** Sync ALL threat intel RSS feeds (18 sources across 4 tiers). */
  syncAllThreatIntelRSS: protectedProcedure
    .input(z.object({
      tiers: z.array(z.number()).optional(),
      feedIds: z.array(z.string()).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
      const result = await syncAllThreatIntelFeeds(input ?? {});
      return result;
    }),

  /** Get the full feed catalog with enabled/disabled status. */
  getThreatIntelFeedCatalog: protectedProcedure.query(async () => {
    const { getFeedCatalog } = await import("../lib/threat-intel-rss");
    return getFeedCatalog();
  }),

  /** Sync only Tier 1 feeds (ransomware & breach focused). */
  syncTier1Feeds: protectedProcedure.mutation(async () => {
    const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
    return syncAllThreatIntelFeeds({ tiers: [1] });
  }),

  /** Sync only Tier 2 feeds (threat intel & zero-day). */
  syncTier2Feeds: protectedProcedure.mutation(async () => {
    const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
    return syncAllThreatIntelFeeds({ tiers: [2] });
  }),

  /** Sync only Tier 3 feeds (vendor threat research). */
  syncTier3Feeds: protectedProcedure.mutation(async () => {
    const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
    return syncAllThreatIntelFeeds({ tiers: [3] });
  }),

  /** Sync only Tier 4 feeds (geopolitical & OSINT). */
  syncTier4Feeds: protectedProcedure.mutation(async () => {
    const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
    return syncAllThreatIntelFeeds({ tiers: [4] });
  }),

  /**
   * Breach Events Feed — aggregates breach notifications and ransomware events from all sources.
   * Combines: ransomware_events + underground_intel_events (data_leak, ransomware, credential) + incident_reports
   */
  getBreachEvents: protectedProcedure.query(async () => {
    const db = await getDb();
    const { ransomwareEvents, undergroundIntelEvents, incidentReports } = await import("../../drizzle/schema");

    // 1. Ransomware events
    const rwEvents = await db.select().from(ransomwareEvents).orderBy(desc(ransomwareEvents.publishedAt)).limit(500);
    const rwMapped = rwEvents.map((r: any) => ({
      id: r.id,
      type: "ransomware" as const,
      groupName: r.reGroupName || "Unknown",
      victimName: r.victimName || "Unknown",
      country: r.reCountry,
      sector: r.reSector,
      description: r.reDescription,
      publishedAt: r.publishedAt ? new Date(r.publishedAt).toISOString() : new Date().toISOString(),
      source: r.reSource || "ransomware_feed",
      sourceUrl: null,
      verified: r.verified ?? false,
      severity: "high",
    }));

    // 2. Underground intel events (data_leak, ransomware, credential types)
    const uieEvents = await db.select().from(undergroundIntelEvents)
      .where(sql`${undergroundIntelEvents.uieCategory} IN ('data_leak', 'ransomware', 'credential', 'exploit_kit')`)
      .orderBy(desc(undergroundIntelEvents.uieEventDate)).limit(500);
    const uieMapped = uieEvents.map((u: any) => ({
      id: u.id + 100000, // offset to avoid ID collision
      type: (u.uieCategory === "ransomware" ? "ransomware" : u.uieCategory === "credential" ? "unauthorized_access" : "data_leak") as any,
      groupName: u.uieActorName || u.uieSource || "Unknown",
      victimName: u.uieTitle || "Unknown",
      country: u.uieVictimCountry,
      sector: u.uieVictimSector,
      description: u.uieDescription,
      publishedAt: u.uieEventDate ? new Date(u.uieEventDate).toISOString() : new Date().toISOString(),
      source: u.uieSource || "underground_intel",
      sourceUrl: u.uieSourceUrl || null,
      verified: false,
      severity: u.uieSeverity,
    }));

    // 3. Incident reports
    const irEvents = await db.select().from(incidentReports).orderBy(desc(incidentReports.publishedAt)).limit(200);
    const irMapped = irEvents.map((ir: any) => ({
      id: ir.id + 200000, // offset to avoid ID collision
      type: "incident" as const,
      groupName: "Unknown",
      victimName: ir.title || "Unknown",
      country: null,
      sector: null,
      description: ir.summary || ir.fullContent?.slice(0, 500),
      publishedAt: ir.publishedAt ? new Date(ir.publishedAt).toISOString() : new Date().toISOString(),
      source: ir.source || "incident_report",
      sourceUrl: ir.url || null,
      verified: ir.irStatus === "completed",
      severity: ir.irSeverity,
    }));

    // Combine and sort by date descending
    const allEvents = [...rwMapped, ...uieMapped, ...irMapped]
      .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
      .slice(0, 1000);

    return allEvents;
  }),

  /**
   * Get breach event detail — full threat actor profile, IOCs, MITRE techniques.
   * Accepts the breach event type + original DB ID to look up the correct table.
   */
  getBreachEventDetail: protectedProcedure
    .input(z.object({
      eventId: z.number(),
      eventType: z.enum(["ransomware", "data_leak", "unauthorized_access", "incident"]),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return null;
      const { ransomwareEvents, undergroundIntelEvents, incidentReports } = await import("../../drizzle/schema");

      function safeParseJson(val: unknown): any[] {
        if (Array.isArray(val)) return val;
        if (typeof val === 'string') { try { return JSON.parse(val); } catch { return []; } }
        if (val && typeof val === 'object') return [val];
        return [];
      }

      let groupName = "Unknown";
      let eventDetail: any = null;

      // Determine source table from the ID offset used in getBreachEvents
      if (input.eventId >= 200000) {
        // Incident report
        const realId = input.eventId - 200000;
        const rows = await db.select().from(incidentReports).where(eq(incidentReports.id, realId)).limit(1);
        if (rows[0]) {
          const ir = rows[0] as any;
          groupName = ir.actorsIdentified?.[0]?.name || "Unknown";
          eventDetail = {
            id: input.eventId,
            type: "incident",
            title: ir.title,
            description: ir.summary || ir.fullContent?.slice(0, 500),
            publishedAt: ir.publishedAt,
            source: ir.source,
            sourceUrl: ir.url,
            severity: ir.severity,
            incidentType: ir.incidentType,
            attackSequence: safeParseJson(ir.attackSequence),
            ttpsExtracted: safeParseJson(ir.ttpsExtracted),
            iocsExtracted: safeParseJson(ir.iocsExtracted),
            actorsIdentified: safeParseJson(ir.actorsIdentified),
            malwareIdentified: safeParseJson(ir.malwareIdentified),
            cvesMentioned: safeParseJson(ir.cvesMentioned),
            targetSectors: safeParseJson(ir.targetSectors),
            targetCountries: safeParseJson(ir.targetCountries),
            attackNarrative: ir.attackNarrative,
            lessonsLearned: ir.lessonsLearned,
          };
        }
      } else if (input.eventId >= 100000) {
        // Underground intel event
        const realId = input.eventId - 100000;
        const rows = await db.select().from(undergroundIntelEvents).where(eq(undergroundIntelEvents.id, realId)).limit(1);
        if (rows[0]) {
          const u = rows[0] as any;
          groupName = u.uieActorName || u.uieSource || "Unknown";
          eventDetail = {
            id: input.eventId,
            type: u.uieCategory === "ransomware" ? "ransomware" : u.uieCategory === "credential" ? "unauthorized_access" : "data_leak",
            title: u.uieTitle,
            description: u.uieDescription,
            publishedAt: u.uieEventDate || u.uieIngestedAt,
            source: u.uieSource,
            sourceUrl: u.uieSourceUrl,
            severity: u.uieSeverity,
            actorName: u.uieActorName,
            actorAliases: safeParseJson(u.uieActorAliases),
            victimName: u.uieVictimName,
            victimSector: u.uieVictimSector,
            victimCountry: u.uieVictimCountry,
            mitreTechniques: safeParseJson(u.uieMitreTechniques),
            iocType: u.uieIocType,
            iocValue: u.uieIocValue,
            tags: safeParseJson(u.uieTags),
            enrichmentData: u.uieEnrichmentData ? safeParseJson(u.uieEnrichmentData) : null,
          };
        }
      } else {
        // Ransomware event
        const rows = await db.select().from(ransomwareEvents).where(eq(ransomwareEvents.id, input.eventId)).limit(1);
        if (rows[0]) {
          const r = rows[0] as any;
          groupName = r.groupName || "Unknown";
          eventDetail = {
            id: input.eventId,
            type: "ransomware",
            title: `${r.groupName} — ${r.victimName}`,
            description: r.description,
            publishedAt: r.publishedAt,
            source: r.source,
            sourceUrl: r.victimUrl,
            severity: "high",
            groupName: r.groupName,
            victimName: r.victimName,
            victimUrl: r.victimUrl,
            country: r.country,
            sector: r.sector,
            verified: r.verified,
          };
        }
      }

      if (!eventDetail) return null;

      // Look up threat actor profile by group name
      let actor: any = null;
      if (groupName && groupName !== "Unknown") {
        const actors = await db.select().from(threatActors)
          .where(sql`${threatActors.name} = ${groupName} OR ${threatActors.actorId} = ${groupName.toLowerCase().replace(/\s+/g, '_')} OR JSON_CONTAINS(${threatActors.aliases}, JSON_QUOTE(${groupName}))`)
          .limit(1);
        actor = actors[0] || null;
      }

      // Get IOCs from threat_actor_iocs table
      let actorIocs: any[] = [];
      if (actor) {
        actorIocs = await db.select().from(threatActorIocs)
          .where(eq(threatActorIocs.actorId, actor.actorId)).limit(30);
      }

      // Get ransomware group profile
      let ransomwareProfile: any = null;
      if (groupName && groupName !== "Unknown") {
        const rwGroups = await db.select().from(ransomwareGroups)
          .where(sql`${ransomwareGroups.groupName} = ${groupName}`)
          .limit(1);
        ransomwareProfile = rwGroups[0] || null;
      }

      // Get related threat group events
      let relatedEvents: any[] = [];
      if (actor) {
        relatedEvents = await db
          .select({
            id: threatGroupEvents.id,
            eventType: threatGroupEvents.eventType,
            title: threatGroupEvents.tgeTitle,
            severity: threatGroupEvents.tgeSeverity,
            victimName: threatGroupEvents.tgeVictimName,
            victimSector: threatGroupEvents.tgeVictimSector,
            victimCountry: threatGroupEvents.tgeVictimCountry,
            eventDate: threatGroupEvents.eventDate,
            source: threatGroupEvents.tgeSource,
            sourceUrl: threatGroupEvents.tgeSourceUrl,
            mitreTechniques: threatGroupEvents.tgeMitreTechniques,
            iocs: threatGroupEvents.tgeIocs,
          })
          .from(threatGroupEvents)
          .where(eq(threatGroupEvents.tgeActorId, actor.actorId))
          .orderBy(desc(threatGroupEvents.eventDate))
          .limit(15);
      }

      return {
        event: eventDetail,
        actor: actor ? {
          actorId: actor.actorId, name: actor.name, aliases: safeParseJson(actor.aliases),
          type: actor.actorType, origin: actor.origin, description: actor.description,
          motivation: actor.motivation, firstSeen: actor.firstSeen, lastActive: actor.lastActive,
          threatLevel: actor.threatLevel, sophistication: actor.sophistication,
          targetSectors: safeParseJson(actor.targetSectors), targetRegions: safeParseJson(actor.targetRegions),
          techniques: safeParseJson(actor.techniques), tools: safeParseJson(actor.tools),
          malware: safeParseJson(actor.malware), activityTimeline: safeParseJson(actor.activityTimeline),
          confidence: actor.confidence, dataSource: actor.dataSource,
        } : null,
        actorIocs: actorIocs.map(ioc => ({
          type: ioc.iocType, value: ioc.value, description: ioc.description,
          firstSeen: ioc.iocFirstSeen, lastSeen: ioc.iocLastSeen, confidence: ioc.iocConfidence, source: ioc.source,
        })),
        ransomwareProfile: ransomwareProfile ? {
          groupName: ransomwareProfile.groupName, activityScore: ransomwareProfile.activityScore,
          trend: ransomwareProfile.trend, threatLevel: ransomwareProfile.rwThreatLevel,
          victims7d: ransomwareProfile.victims7D, victims30d: ransomwareProfile.victims30D,
          totalVictims: ransomwareProfile.totalVictims,
          topSectors: safeParseJson(ransomwareProfile.topSectors),
          topCountries: safeParseJson(ransomwareProfile.topCountries),
          ransomwareFamily: ransomwareProfile.ransomwareFamily,
          extortionModel: ransomwareProfile.extortionModel,
          mitreTechniques: safeParseJson(ransomwareProfile.mitreTechniques),
          knownInfrastructure: safeParseJson(ransomwareProfile.knownInfrastructure),
          notableAttacks: safeParseJson(ransomwareProfile.notableAttacks),
        } : null,
        relatedEvents: relatedEvents.map(e => ({
          ...e,
          mitreTechniques: safeParseJson(e.mitreTechniques),
          iocs: safeParseJson(e.iocs),
        })),
      };
    }),

  /**
   * Get recent breach events for the ticker — lightweight, returns only what the ticker needs.
   */
  getBreachTickerItems: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return [];
    const { ransomwareEvents, undergroundIntelEvents, incidentReports } = await import("../../drizzle/schema");

    // Get most recent 10 ransomware events
    const rwEvents = await db.select({
      id: ransomwareEvents.id,
      groupName: ransomwareEvents.reGroupName,
      victimName: ransomwareEvents.victimName,
      publishedAt: ransomwareEvents.publishedAt,
    }).from(ransomwareEvents).orderBy(desc(ransomwareEvents.publishedAt)).limit(10);

    const rwMapped = rwEvents.map((r: any) => ({
      id: r.id,
      type: "ransomware" as const,
      label: `${r.groupName} → ${r.victimName}`,
      severity: "high" as const,
      tag: "RANSOMWARE",
      publishedAt: r.publishedAt ? new Date(r.publishedAt).toISOString() : new Date().toISOString(),
    }));

    // Get most recent 10 underground intel events (data leaks, ransomware, credentials)
    const uieEvents = await db.select({
      id: undergroundIntelEvents.id,
      category: undergroundIntelEvents.uieCategory,
      title: undergroundIntelEvents.uieTitle,
      severity: undergroundIntelEvents.uieSeverity,
      actorName: undergroundIntelEvents.uieActorName,
      eventDate: undergroundIntelEvents.uieEventDate,
    }).from(undergroundIntelEvents)
      .where(sql`${undergroundIntelEvents.uieCategory} IN ('data_leak', 'ransomware', 'credential', 'exploit')`)
      .orderBy(desc(undergroundIntelEvents.uieEventDate)).limit(10);

    const uieMapped = uieEvents.map((u: any) => ({
      id: u.id + 100000,
      type: (u.category === "ransomware" ? "ransomware" : u.category === "credential" ? "unauthorized_access" : "data_leak") as any,
      label: u.actorName ? `${u.actorName} — ${u.title?.slice(0, 60)}` : (u.title?.slice(0, 80) || "Unknown event"),
      severity: (u.severity || "medium") as any,
      tag: u.category === "ransomware" ? "RANSOMWARE" : u.category === "credential" ? "CREDENTIAL" : "DATA LEAK",
      publishedAt: u.eventDate ? new Date(u.eventDate).toISOString() : new Date().toISOString(),
    }));

    // Get most recent 5 incident reports
    const irEvents = await db.select({
      id: incidentReports.id,
      title: incidentReports.title,
      severity: incidentReports.irSeverity,
      publishedAt: incidentReports.publishedAt,
      source: incidentReports.source,
    }).from(incidentReports).orderBy(desc(incidentReports.publishedAt)).limit(5);

    const irMapped = irEvents.map((ir: any) => ({
      id: ir.id + 200000,
      type: "incident" as const,
      label: ir.title?.slice(0, 80) || "Incident Report",
      severity: (ir.severity || "medium") as any,
      tag: "INCIDENT",
      publishedAt: ir.publishedAt || new Date().toISOString(),
    }));

    return [...rwMapped, ...uieMapped, ...irMapped]
      .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
      .slice(0, 20);
  }),

  /** Broker listing timeline data for charts: activity trends, price patterns, agency targeting. */
  brokerTimeline: protectedProcedure
    .input(z.object({
      days: z.number().min(7).max(365).default(90),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { activityByWeek: [], priceByType: [], sectorBreakdown: [], topBrokers: [], govTargeting: [] };
      const days = input?.days ?? 90;
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();

      // 1. Activity by week (listings posted per week)
      const activityRaw = await db.select({
        week: sql<string>`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`,
        weekStart: sql<string>`DATE_FORMAT(DATE_SUB(${accessBrokerListings.postedAt}, INTERVAL WEEKDAY(${accessBrokerListings.postedAt}) DAY), '%Y-%m-%d')`,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
      }).from(accessBrokerListings)
        .where(gte(accessBrokerListings.postedAt, cutoff))
        .groupBy(sql`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`, sql`DATE_FORMAT(DATE_SUB(${accessBrokerListings.postedAt}, INTERVAL WEEKDAY(${accessBrokerListings.postedAt}) DAY), '%Y-%m-%d')`)
        .orderBy(sql`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`);

      // 2. Price distribution by listing type
      const priceByType = await db.select({
        listingType: accessBrokerListings.listingType,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
        minPrice: sql<number>`MIN(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
        maxPrice: sql<number>`MAX(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
      }).from(accessBrokerListings)
        .where(gte(accessBrokerListings.postedAt, cutoff))
        .groupBy(accessBrokerListings.listingType)
        .orderBy(sql`COUNT(*) DESC`);

      // 3. Sector breakdown
      const sectorBreakdown = await db.select({
        sector: accessBrokerListings.victimSector,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
      }).from(accessBrokerListings)
        .where(gte(accessBrokerListings.postedAt, cutoff))
        .groupBy(accessBrokerListings.victimSector)
        .orderBy(sql`COUNT(*) DESC`)
        .limit(15);

      // 4. Top brokers by volume
      const topBrokers = await db.select({
        brokerId: accessBrokerListings.brokerId,
        brokerName: accessBrokerListings.brokerName,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(REPLACE(REPLACE(${accessBrokerListings.askingPrice}, '$', ''), ',', ''), '') AS DECIMAL))`,
        reputation: accessBrokerListings.brokerReputation,
      }).from(accessBrokerListings)
        .where(gte(accessBrokerListings.postedAt, cutoff))
        .groupBy(accessBrokerListings.brokerId, accessBrokerListings.brokerName, accessBrokerListings.brokerReputation)
        .orderBy(sql`COUNT(*) DESC`)
        .limit(10);

      // 5. Gov-targeting listings (country = US, sector contains gov/federal/defense/military)
      const govTargeting = await db.select({
        week: sql<string>`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`,
        weekStart: sql<string>`DATE_FORMAT(DATE_SUB(${accessBrokerListings.postedAt}, INTERVAL WEEKDAY(${accessBrokerListings.postedAt}) DAY), '%Y-%m-%d')`,
        count: count(),
        sector: accessBrokerListings.victimSector,
      }).from(accessBrokerListings)
        .where(and(
          gte(accessBrokerListings.postedAt, cutoff),
          sql`(${accessBrokerListings.victimCountry} LIKE '%US%' OR ${accessBrokerListings.victimCountry} LIKE '%United States%')`,
          sql`(${accessBrokerListings.victimSector} LIKE '%gov%' OR ${accessBrokerListings.victimSector} LIKE '%federal%' OR ${accessBrokerListings.victimSector} LIKE '%defense%' OR ${accessBrokerListings.victimSector} LIKE '%military%' OR ${accessBrokerListings.victimSector} LIKE '%agency%')`,
        ))
        .groupBy(sql`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`, sql`DATE_FORMAT(DATE_SUB(${accessBrokerListings.postedAt}, INTERVAL WEEKDAY(${accessBrokerListings.postedAt}) DAY), '%Y-%m-%d')`, accessBrokerListings.victimSector)
        .orderBy(sql`DATE_FORMAT(${accessBrokerListings.postedAt}, '%Y-%u')`);

      return {
        activityByWeek: activityRaw.map(r => ({
          week: r.week,
          weekStart: r.weekStart,
          listings: r.count,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        })),
        priceByType: priceByType.map(r => ({
          type: r.listingType,
          count: r.count,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
          minPrice: r.minPrice ? Math.round(r.minPrice) : null,
          maxPrice: r.maxPrice ? Math.round(r.maxPrice) : null,
        })),
        sectorBreakdown: sectorBreakdown.filter(r => r.sector).map(r => ({
          sector: r.sector!,
          count: r.count,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        })),
        topBrokers: topBrokers.map(r => ({
          brokerId: r.brokerId,
          name: r.brokerName,
          listings: r.count,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
          reputation: r.reputation,
        })),
        govTargeting: govTargeting.map(r => ({
          week: r.week,
          weekStart: r.weekStart,
          count: r.count,
          sector: r.sector,
        })),
      };
    }),

  /**
   * IAB Trend Analytics — monthly volume, sector shifts, access type distribution,
   * price evolution, top brokers, and gov-targeting trends.
   * Combines data from access_broker_listings (primary) and iab_activity (if populated).
   */
  iabTrends: protectedProcedure
    .input(z.object({
      days: z.number().min(30).max(730).default(365),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return {
        monthlyVolume: [], sectorShifts: [], accessTypeDistribution: [],
        priceEvolution: [], topBrokersRanked: [], govTargetingTrend: [],
        summary: { totalListings: 0, activeBrokers: 0, avgPrice: 0, govListings: 0, topSector: '', topAccessType: '' },
      };
      const days = input?.days ?? 365;
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();

      // 1. Monthly volume — listings posted per month with running total
      // Use raw SQL to avoid TiDB ONLY_FULL_GROUP_BY mismatch between SELECT and GROUP BY
      const monthlyRaw = await db.execute(
        sql`SELECT DATE_FORMAT(postedAt, '%Y-%m') as month, COUNT(*) as count, AVG(CAST(NULLIF(askingPrice, '0') AS DECIMAL)) as avgPrice FROM access_broker_listings WHERE postedAt >= ${cutoff} AND postedAt IS NOT NULL GROUP BY DATE_FORMAT(postedAt, '%Y-%m') ORDER BY month`
      ).then(r => (r as any)[0] as Array<{month: string; count: number; avgPrice: number | null}>);

      let runningTotal = 0;
      const monthlyVolume = monthlyRaw.map(r => {
        runningTotal += r.count;
        return {
          month: r.month,
          listings: r.count,
          cumulative: runningTotal,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        };
      });

      // 2. Sector shifts — monthly breakdown by sector (top 8 sectors)
      const sectorMonthly = await db.execute(
        sql`SELECT DATE_FORMAT(postedAt, '%Y-%m') as month, victimSector as sector, COUNT(*) as count FROM access_broker_listings WHERE postedAt >= ${cutoff} AND postedAt IS NOT NULL AND victimSector IS NOT NULL GROUP BY DATE_FORMAT(postedAt, '%Y-%m'), victimSector ORDER BY month`
      ).then(r => (r as any)[0] as Array<{month: string; sector: string; count: number}>);

      // Normalize multi-sector entries and aggregate
      const sectorCounts: Record<string, number> = {};
      const sectorMonthMap: Record<string, Record<string, number>> = {};
      for (const row of sectorMonthly) {
        const sectors = (row.sector || '').split(',').map(s => s.trim()).filter(Boolean);
        for (const s of sectors) {
          const normalized = s.charAt(0).toUpperCase() + s.slice(1);
          sectorCounts[normalized] = (sectorCounts[normalized] || 0) + row.count;
          if (!sectorMonthMap[row.month]) sectorMonthMap[row.month] = {};
          sectorMonthMap[row.month][normalized] = (sectorMonthMap[row.month][normalized] || 0) + row.count;
        }
      }
      const topSectors = Object.entries(sectorCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([s]) => s);

      const sectorShifts = Object.entries(sectorMonthMap)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([month, sectors]) => ({
          month,
          ...Object.fromEntries(topSectors.map(s => [s, sectors[s] || 0])),
        }));

      // 3. Access type distribution — pie chart data
      const accessTypes = await db.select({
        type: accessBrokerListings.listingType,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(${accessBrokerListings.askingPrice}, '0') AS DECIMAL))`,
      }).from(accessBrokerListings)
        .groupBy(accessBrokerListings.listingType)
        .orderBy(sql`COUNT(*) DESC`);

      const TYPE_LABELS: Record<string, string> = {
        vpn_access: 'VPN Access', rdp_access: 'RDP Access', citrix_access: 'Citrix',
        webshell: 'Web Shell', domain_admin: 'Domain Admin', cloud_access: 'Cloud Access',
        email_access: 'Email Access', database_access: 'Database', zero_day: 'Zero-Day',
        exploit_kit: 'Exploit Kit', credential_dump: 'Credential Dump', other: 'Other',
      };
      const accessTypeDistribution = accessTypes.map(r => ({
        type: r.type,
        label: TYPE_LABELS[r.type || ''] || r.type || 'Unknown',
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));

      // 4. Price evolution — monthly median/avg/max prices
      const priceMonthly = await db.execute(
        sql`SELECT DATE_FORMAT(postedAt, '%Y-%m') as month, AVG(CAST(NULLIF(askingPrice, '0') AS DECIMAL)) as avgPrice, MAX(CAST(NULLIF(askingPrice, '0') AS DECIMAL)) as maxPrice, MIN(CAST(NULLIF(askingPrice, '0') AS DECIMAL)) as minPrice, COUNT(*) as count FROM access_broker_listings WHERE postedAt >= ${cutoff} AND postedAt IS NOT NULL AND askingPrice IS NOT NULL AND askingPrice != '0' GROUP BY DATE_FORMAT(postedAt, '%Y-%m') ORDER BY month`
      ).then(r => (r as any)[0] as Array<{month: string; avgPrice: number | null; maxPrice: number | null; minPrice: number | null; count: number}>);

      const priceEvolution = priceMonthly.map(r => ({
        month: r.month,
        avg: r.avgPrice ? Math.round(r.avgPrice) : null,
        max: r.maxPrice ? Math.round(r.maxPrice) : null,
        min: r.minPrice ? Math.round(r.minPrice) : null,
        listings: r.count,
      }));

      // 5. Top brokers ranked — by listing count with price and sector info
      const topBrokersRaw = await db.select({
        brokerId: accessBrokerListings.brokerId,
        brokerName: accessBrokerListings.brokerName,
        count: count(),
        avgPrice: sql<number>`AVG(CAST(NULLIF(${accessBrokerListings.askingPrice}, '0') AS DECIMAL))`,
        reputation: accessBrokerListings.brokerReputation,
        topSector: sql<string>`(SELECT victimSector FROM access_broker_listings abl2 WHERE abl2.brokerId = access_broker_listings.brokerId GROUP BY victimSector ORDER BY COUNT(*) DESC LIMIT 1)`,
        topType: sql<string>`(SELECT listingType FROM access_broker_listings abl3 WHERE abl3.brokerId = access_broker_listings.brokerId GROUP BY listingType ORDER BY COUNT(*) DESC LIMIT 1)`,
      }).from(accessBrokerListings)
        .groupBy(accessBrokerListings.brokerId, accessBrokerListings.brokerName, accessBrokerListings.brokerReputation)
        .orderBy(sql`COUNT(*) DESC`)
        .limit(15);

      const topBrokersRanked = topBrokersRaw.map(r => ({
        brokerId: r.brokerId,
        name: r.brokerName,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        reputation: r.reputation,
        topSector: r.topSector,
        topType: TYPE_LABELS[r.topType || ''] || r.topType,
      }));

      // 6. Gov-targeting trend — monthly gov-related listings
      const govMonthly = await db.execute(
        sql`SELECT DATE_FORMAT(postedAt, '%Y-%m') as month, COUNT(*) as count, AVG(CAST(NULLIF(askingPrice, '0') AS DECIMAL)) as avgPrice FROM access_broker_listings WHERE postedAt >= ${cutoff} AND postedAt IS NOT NULL AND (victimSector LIKE '%gov%' OR victimSector LIKE '%Government%' OR victimSector LIKE '%federal%' OR victimSector LIKE '%defense%' OR victimSector LIKE '%military%' OR victimSector LIKE '%Defense%' OR victimSector LIKE '%Military%') GROUP BY DATE_FORMAT(postedAt, '%Y-%m') ORDER BY month`
      ).then(r => (r as any)[0] as Array<{month: string; count: number; avgPrice: number | null}>);

      const govTargetingTrend = govMonthly.map(r => ({
        month: r.month,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));

      // Summary stats
      const totalListings = monthlyVolume.reduce((sum, m) => sum + m.listings, 0) || accessTypes.reduce((sum, t) => sum + t.count, 0);
      const activeBrokers = topBrokersRanked.length;
      const allPrices = accessTypes.filter(t => t.avgPrice != null && !isNaN(Number(t.avgPrice))).map(t => Number(t.avgPrice));
      const avgPrice = allPrices.length > 0 ? Math.round(allPrices.reduce((a, b) => a + b, 0) / allPrices.length) : 0;
      const govListings = govTargetingTrend.reduce((sum, g) => sum + g.listings, 0);
      const topSector = topSectors[0] || 'Unknown';
      const topAccessType = accessTypeDistribution[0]?.label || 'Unknown';

      return {
        monthlyVolume,
        sectorShifts,
        accessTypeDistribution,
        priceEvolution,
        topBrokersRanked,
        govTargetingTrend,
        summary: { totalListings, activeBrokers, avgPrice, govListings, topSector, topAccessType },
        topSectors,
      };
    }),

  /**
   * IAB Spike Alerting — run spike detection checks and send notifications.
   */
  iabSpikeCheck: protectedProcedure
    .input(z.object({
      monthlyVolumeThreshold: z.number().optional(),
      govTargetingThreshold: z.number().optional(),
      highValuePriceThreshold: z.number().optional(),
      newBrokerDailyThreshold: z.number().optional(),
      volumeSpikePercent: z.number().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { runIABSpikeCheck } = await import("../lib/iab-spike-alerting");
      return runIABSpikeCheck(input || undefined);
    }),

  /**
   * IAB Alert Thresholds — get current default thresholds.
   */
  iabAlertThresholds: protectedProcedure.query(async () => {
    const { getDefaultThresholds } = await import("../lib/iab-spike-alerting");
    return getDefaultThresholds();
  }),

  /**
   * IAB Ingestion Pipeline — run automated ingestion from multiple threat intel sources.
   * Sources: ransomware.live groups, victim attribution, CISA KEV, RansomLook markets, LLM enrichment.
   */
  iabIngest: protectedProcedure.mutation(async () => {
    const { runIABIngestionPipeline } = await import("../lib/iab-ingestion-service");
    return runIABIngestionPipeline();
  }),

  /**
   * IAB Ingestion — run a specific source only.
   */
  iabIngestSource: protectedProcedure
    .input(z.object({ source: z.enum(["ransomware_live_groups", "victim_attribution", "cisa_kev", "ransomlook_markets"]) }))
    .mutation(async ({ input }) => {
      const svc = await import("../lib/iab-ingestion-service");
      switch (input.source) {
        case "ransomware_live_groups": return svc.ingestRansomwareLiveGroups();
        case "victim_attribution": return svc.ingestVictimIABAttribution();
        case "cisa_kev": return svc.ingestCISAKEVExploits();
        case "ransomlook_markets": return svc.ingestRansomLookMarkets();
      }
    }),

  /**
   * Admin-only: run pending DB migrations for tables that may be missing on production.
   * Creates info_ops_campaigns, influence_operations, darkweb_feed_registry, iab_activity
   * if they don't already exist.
   */
  /**
   * Classify all IAB listings with priority tags (US Gov, ICS/SCADA, Defense Contractor).
   * Uses keyword-based detection on real data only — no LLM fabrication.
   */
  iabClassifyAll: protectedProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    return classifyAllListings(db);
  }),

  /**
   * Get IAB listings filtered by priority level or category.
   */
  iabPriorityListings: protectedProcedure
    .input(z.object({
      priorityLevel: z.enum(['critical', 'high', 'medium', 'low', 'all']).default('all'),
      category: z.enum(['us_gov', 'ics_scada', 'defense_contractor', 'critical_infrastructure', 'general', 'all']).default('all'),
      limit: z.number().min(1).max(500).default(100),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const mysql2 = await import('mysql2/promise');
      const conn = await mysql2.createConnection(process.env.DATABASE_URL!);
      try {
        let whereClause = 'WHERE 1=1';
        const params: any[] = [];

        if (input.priorityLevel !== 'all') {
          whereClause += ' AND priority_level = ?';
          params.push(input.priorityLevel);
        }

        if (input.category !== 'all') {
          whereClause += ' AND JSON_CONTAINS(priority_tags, ?, \"$.categories\")';
          params.push(JSON.stringify(input.category));
        }

        const [countRows] = await conn.execute(
          `SELECT COUNT(*) as total FROM access_broker_listings ${whereClause}`,
          params
        );
        const total = (countRows as any[])[0]?.total || 0;

        const [rows] = await conn.execute(
          `SELECT * FROM access_broker_listings ${whereClause} ORDER BY priority_score DESC, postedAt DESC LIMIT ${Number(input.limit)} OFFSET ${Number(input.offset)}`
          , params
        );

        return {
          listings: rows as any[],
          total,
          offset: input.offset,
          limit: input.limit,
        };
      } finally {
        await conn.end();
      }
    }),

  /**
   * Get priority distribution summary for the IAB dashboard.
   */
  iabPrioritySummary: protectedProcedure.query(async () => {
    const mysql2 = await import('mysql2/promise');
    const conn = await mysql2.createConnection(process.env.DATABASE_URL!);
    try {
      const [levelRows] = await conn.execute(
        `SELECT priority_level, COUNT(*) as count, AVG(priority_score) as avg_score
         FROM access_broker_listings
         GROUP BY priority_level
         ORDER BY FIELD(priority_level, 'critical', 'high', 'medium', 'low')`
      );

      const [allRows] = await conn.execute(
        `SELECT priority_tags FROM access_broker_listings WHERE priority_tags IS NOT NULL`
      );

      const categoryCounts: Record<string, number> = {};
      for (const row of allRows as any[]) {
        try {
          const tags = typeof row.priority_tags === 'string' ? JSON.parse(row.priority_tags) : row.priority_tags;
          for (const cat of tags?.categories || []) {
            categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
          }
        } catch { /* skip malformed */ }
      }

      const [criticalRows] = await conn.execute(
        `SELECT id, brokerName, victimSector, victimCountry, accessType,
                priority_level, priority_score, priority_tags, iabDataSource, postedAt
         FROM access_broker_listings
         WHERE priority_level IN ('critical', 'high')
         ORDER BY priority_score DESC, postedAt DESC
         LIMIT 20`
      );

      return {
        byLevel: levelRows as any[],
        byCategory: categoryCounts,
        topCritical: criticalRows as any[],
        totalClassified: (allRows as any[]).length,
      };
    } finally {
      await conn.end();
    }
  }),

  runMigrations: protectedProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    const migrations = [
      {
        name: 'info_ops_campaigns',
        sql: `CREATE TABLE IF NOT EXISTS \`info_ops_campaigns\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`ioCampaignId\` varchar(128) NOT NULL,
  \`ioCampaignName\` varchar(255) NOT NULL,
  \`ioAliases\` json DEFAULT NULL,
  \`attributedTo\` varchar(255) DEFAULT NULL,
  \`sponsorState\` varchar(128) DEFAULT NULL,
  \`operatorGroup\` varchar(255) DEFAULT NULL,
  \`ioLinkedActorIds\` json DEFAULT NULL,
  \`operationType\` enum('disinformation','influence','hack_and_leak','astroturfing','election_interference','propaganda','cyber_espionage_io','economic_coercion','diplomatic_pressure','other') NOT NULL DEFAULT 'other',
  \`ioStatus\` enum('active','disrupted','dormant','attributed','ongoing') DEFAULT 'active',
  \`ioTargetCountries\` json DEFAULT NULL,
  \`targetAudiences\` json DEFAULT NULL,
  \`ioTargetPlatforms\` json DEFAULT NULL,
  \`targetNarratives\` json DEFAULT NULL,
  \`estimatedReach\` varchar(128) DEFAULT NULL,
  \`accountsIdentified\` int DEFAULT '0',
  \`contentPiecesIdentified\` int DEFAULT '0',
  \`platformActionsTaken\` json DEFAULT NULL,
  \`ioTechniques\` json DEFAULT NULL,
  \`cyberComponent\` tinyint(1) DEFAULT '0',
  \`linkedCyberOps\` json DEFAULT NULL,
  \`ioMitreTechniques\` json DEFAULT NULL,
  \`primarySource\` varchar(255) DEFAULT NULL,
  \`sourceUrls\` json DEFAULT NULL,
  \`reportTitle\` varchar(512) DEFAULT NULL,
  \`ioStartDate\` varchar(32) DEFAULT NULL,
  \`ioEndDate\` varchar(32) DEFAULT NULL,
  \`discoveredDate\` varchar(32) DEFAULT NULL,
  \`ioThreatLevel\` enum('critical','high','medium','low') DEFAULT 'medium',
  \`ioConfidence\` int DEFAULT '75',
  \`ioDescription\` text DEFAULT NULL,
  \`ioDataSource\` varchar(128) DEFAULT NULL,
  \`ioLastEnriched\` timestamp NULL DEFAULT NULL,
  \`ioCreatedAt\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`ioUpdatedAt\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`info_ops_campaigns_ioCampaignId_unique\` (\`ioCampaignId\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      },
      {
        name: 'influence_operations',
        sql: `CREATE TABLE IF NOT EXISTS \`influence_operations\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`io_operation_name\` varchar(512) NOT NULL,
  \`io_attributed_to\` varchar(255) DEFAULT NULL,
  \`io_nation_state\` varchar(128) DEFAULT NULL,
  \`io_description\` text DEFAULT NULL,
  \`io_target_countries\` json DEFAULT NULL,
  \`io_target_sectors\` json DEFAULT NULL,
  \`io_target_narratives\` json DEFAULT NULL,
  \`io_platforms\` json DEFAULT NULL,
  \`io_techniques\` json DEFAULT NULL,
  \`io_mitre_techniques\` json DEFAULT NULL,
  \`io_accounts_identified\` int DEFAULT '0',
  \`io_content_pieces\` int DEFAULT '0',
  \`io_source\` varchar(255) DEFAULT NULL,
  \`io_source_url\` varchar(1024) DEFAULT NULL,
  \`io_report_date\` timestamp NULL DEFAULT NULL,
  \`io_status\` enum('active','disrupted','dormant','attributed') DEFAULT 'active',
  \`io_confidence\` int DEFAULT '75',
  \`io_tags\` json DEFAULT NULL,
  \`io_raw_data\` json DEFAULT NULL,
  \`io_created_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`io_updated_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      },
      {
        name: 'darkweb_feed_registry',
        sql: `CREATE TABLE IF NOT EXISTS \`darkweb_feed_registry\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`dfr_feed_name\` varchar(255) NOT NULL,
  \`dfr_feed_url\` varchar(1024) NOT NULL,
  \`dfr_feed_type\` enum('ioc','malware','ransomware','credential','phishing','botnet','c2','blocklist','vulnerability','influence','other') NOT NULL,
  \`dfr_provider\` varchar(255) DEFAULT NULL,
  \`dfr_description\` text DEFAULT NULL,
  \`dfr_requires_auth\` tinyint(1) DEFAULT '0',
  \`dfr_auth_type\` enum('none','api_key','bearer','basic','custom') DEFAULT 'none',
  \`dfr_auth_env_var\` varchar(128) DEFAULT NULL,
  \`dfr_sync_interval\` varchar(32) DEFAULT 'daily',
  \`dfr_last_sync_at\` timestamp NULL DEFAULT NULL,
  \`dfr_next_sync_at\` timestamp NULL DEFAULT NULL,
  \`dfr_status\` enum('active','degraded','down','disabled','pending') DEFAULT 'pending',
  \`dfr_last_error\` text DEFAULT NULL,
  \`dfr_consecutive_failures\` int DEFAULT '0',
  \`dfr_total_syncs\` int DEFAULT '0',
  \`dfr_total_records_fetched\` int DEFAULT '0',
  \`dfr_avg_response_time_ms\` int DEFAULT NULL,
  \`dfr_is_built_in\` tinyint(1) DEFAULT '1',
  \`dfr_enabled\` tinyint(1) DEFAULT '1',
  \`dfr_config\` json DEFAULT NULL,
  \`dfr_created_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`dfr_updated_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`dfr_feed_name\` (\`dfr_feed_name\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      },
      {
        name: 'iab_activity',
        sql: `CREATE TABLE IF NOT EXISTS \`iab_activity\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`iab_broker_id\` varchar(128) NOT NULL,
  \`iab_broker_name\` varchar(255) NOT NULL,
  \`iab_listing_type\` enum('vpn_access','rdp_access','citrix_access','webshell','domain_admin','cloud_access','email_access','database_access','zero_day','exploit_kit','credential_dump','other') NOT NULL,
  \`iab_access_type\` varchar(255) DEFAULT NULL,
  \`iab_description\` text DEFAULT NULL,
  \`iab_victim_name\` varchar(512) DEFAULT NULL,
  \`iab_victim_sector\` varchar(128) DEFAULT NULL,
  \`iab_victim_country\` varchar(128) DEFAULT NULL,
  \`iab_victim_revenue\` varchar(64) DEFAULT NULL,
  \`iab_asking_price\` varchar(64) DEFAULT NULL,
  \`iab_currency\` varchar(16) DEFAULT 'USD',
  \`iab_forum_source\` varchar(255) DEFAULT NULL,
  \`iab_linked_rw_groups\` json DEFAULT NULL,
  \`iab_mitre_techniques\` json DEFAULT NULL,
  \`iab_status\` enum('active','sold','expired','removed','law_enforcement') DEFAULT 'active',
  \`iab_confidence\` int DEFAULT '75',
  \`iab_first_seen\` timestamp NULL DEFAULT NULL,
  \`iab_last_active\` timestamp NULL DEFAULT NULL,
  \`iab_tags\` json DEFAULT NULL,
  \`iab_raw_data\` json DEFAULT NULL,
  \`iab_created_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`iab_updated_at\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      }
    ];

    const results: { table: string; status: string }[] = [];
    for (const m of migrations) {
      try {
        await db.execute(sql.raw(m.sql));
        results.push({ table: m.name, status: 'created_or_exists' });
      } catch (e: any) {
        results.push({ table: m.name, status: `error: ${e.message}` });
      }
    }
    return { results, timestamp: new Date().toISOString() };
  }),

  describeTable: protectedProcedure
    .input(z.object({ table: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new Error('Database not available');
      const rows = await db.execute(sql.raw(`DESCRIBE \`${input.table}\``));
      return { table: input.table, columns: rows[0] };
    }),

  renameColumns: protectedProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new Error('Database not available');

    // Map of table -> old column name -> new column name
    const renames: Record<string, Record<string, { newName: string; colDef: string }>> = {
      network_events: {
        event_type: { newName: 'ne_event_type', colDef: "enum('c2_server','botnet_controller','malicious_ip','tor_exit_node','proxy_node','vpn_endpoint','dns_sinkhole','fast_flux','ssl_blacklist','spam_source','scanner','other') NOT NULL" },
        source: { newName: 'ne_source', colDef: 'varchar(128) NOT NULL' },
        ip_address: { newName: 'ne_ip_address', colDef: 'varchar(45) DEFAULT NULL' },
        port: { newName: 'ne_port', colDef: 'int DEFAULT NULL' },
        hostname: { newName: 'ne_hostname', colDef: 'varchar(512) DEFAULT NULL' },
        protocol: { newName: 'ne_protocol', colDef: 'varchar(32) DEFAULT NULL' },
        malware_family: { newName: 'ne_malware_family', colDef: 'varchar(255) DEFAULT NULL' },
        description: { newName: 'ne_description', colDef: 'text DEFAULT NULL' },
        severity: { newName: 'ne_severity', colDef: "enum('critical','high','medium','low','info') DEFAULT 'medium'" },
        confidence: { newName: 'ne_confidence', colDef: 'int DEFAULT 75' },
        country: { newName: 'ne_country', colDef: 'varchar(128) DEFAULT NULL' },
        asn: { newName: 'ne_asn', colDef: 'varchar(64) DEFAULT NULL' },
        asn_org: { newName: 'ne_asn_org', colDef: 'varchar(255) DEFAULT NULL' },
        status: { newName: 'ne_status', colDef: "enum('active','inactive','sinkholed','takedown') DEFAULT 'active'" },
        first_seen: { newName: 'ne_first_seen', colDef: 'timestamp NULL DEFAULT NULL' },
        last_seen: { newName: 'ne_last_seen', colDef: 'timestamp NULL DEFAULT NULL' },
        tags: { newName: 'ne_tags', colDef: 'json DEFAULT NULL' },
        raw_data: { newName: 'ne_raw_data', colDef: 'json DEFAULT NULL' },
        created_at: { newName: 'ne_created_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP' },
        updated_at: { newName: 'ne_updated_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP' },
      },
      underground_intel_events: {
        category: { newName: 'uie_category', colDef: "enum('forum_post','marketplace_listing','paste_site','ransomware_claim','data_leak','zero_day_sale','exploit_kit','credential_dump','access_sale','other') NOT NULL" },
        source: { newName: 'uie_source', colDef: 'varchar(255) NOT NULL' },
        source_url: { newName: 'uie_source_url', colDef: 'varchar(1024) DEFAULT NULL' },
        title: { newName: 'uie_title', colDef: 'varchar(512) NOT NULL' },
        description: { newName: 'uie_description', colDef: 'text DEFAULT NULL' },
        severity: { newName: 'uie_severity', colDef: "enum('critical','high','medium','low','info') DEFAULT 'medium'" },
        confidence: { newName: 'uie_confidence', colDef: 'int DEFAULT 75' },
        ioc_type: { newName: 'uie_ioc_type', colDef: 'varchar(64) DEFAULT NULL' },
        ioc_value: { newName: 'uie_ioc_value', colDef: 'varchar(1024) DEFAULT NULL' },
        actor_handle: { newName: 'uie_actor_handle', colDef: 'varchar(255) DEFAULT NULL' },
        actor_reputation: { newName: 'uie_actor_reputation', colDef: 'varchar(64) DEFAULT NULL' },
        price: { newName: 'uie_price', colDef: 'varchar(64) DEFAULT NULL' },
        currency: { newName: 'uie_currency', colDef: "varchar(16) DEFAULT 'USD'" },
        target_org: { newName: 'uie_target_org', colDef: 'varchar(255) DEFAULT NULL' },
        target_sector: { newName: 'uie_target_sector', colDef: 'varchar(128) DEFAULT NULL' },
        target_country: { newName: 'uie_target_country', colDef: 'varchar(128) DEFAULT NULL' },
        tags: { newName: 'uie_tags', colDef: 'json DEFAULT NULL' },
        raw_data: { newName: 'uie_raw_data', colDef: 'json DEFAULT NULL' },
        created_at: { newName: 'uie_created_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP' },
        updated_at: { newName: 'uie_updated_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP' },
      },
      credential_exposures: {
        source: { newName: 'ce_source', colDef: 'varchar(255) NOT NULL' },
        breach_name: { newName: 'ce_breach_name', colDef: 'varchar(255) DEFAULT NULL' },
        breach_date: { newName: 'ce_breach_date', colDef: 'varchar(32) DEFAULT NULL' },
        domain: { newName: 'ce_domain', colDef: 'varchar(255) DEFAULT NULL' },
        email_count: { newName: 'ce_email_count', colDef: 'int DEFAULT 0' },
        total_records: { newName: 'ce_total_records', colDef: 'int DEFAULT 0' },
        data_classes: { newName: 'ce_data_classes', colDef: 'json DEFAULT NULL' },
        actor_name: { newName: 'ce_actor_name', colDef: 'varchar(255) DEFAULT NULL' },
        severity: { newName: 'ce_severity', colDef: "enum('critical','high','medium','low','info') DEFAULT 'medium'" },
        confidence: { newName: 'ce_confidence', colDef: 'int DEFAULT 75' },
        affected_orgs: { newName: 'ce_affected_orgs', colDef: 'json DEFAULT NULL' },
        affected_sectors: { newName: 'ce_affected_sectors', colDef: 'json DEFAULT NULL' },
        affected_countries: { newName: 'ce_affected_countries', colDef: 'json DEFAULT NULL' },
        password_hashes_leaked: { newName: 'ce_password_hashes_leaked', colDef: 'tinyint(1) DEFAULT 0' },
        plaintext_passwords: { newName: 'ce_plaintext_passwords', colDef: 'tinyint(1) DEFAULT 0' },
        pii_exposed: { newName: 'ce_pii_exposed', colDef: 'tinyint(1) DEFAULT 0' },
        financial_data_exposed: { newName: 'ce_financial_data_exposed', colDef: 'tinyint(1) DEFAULT 0' },
        tags: { newName: 'ce_tags', colDef: 'json DEFAULT NULL' },
        raw_data: { newName: 'ce_raw_data', colDef: 'json DEFAULT NULL' },
        created_at: { newName: 'ce_created_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP' },
        updated_at: { newName: 'ce_updated_at', colDef: 'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP' },
      },
    };

    const results: { table: string; column: string; status: string }[] = [];

    for (const [tableName, columns] of Object.entries(renames)) {
      // First check if the table exists and get current columns
      try {
        const descRows = await db.execute(sql.raw(`DESCRIBE \`${tableName}\``));
        const existingCols = new Set((descRows[0] as any[]).map((r: any) => r.Field));

        for (const [oldName, { newName, colDef }] of Object.entries(columns)) {
          if (existingCols.has(oldName) && !existingCols.has(newName)) {
            try {
              await db.execute(sql.raw(`ALTER TABLE \`${tableName}\` CHANGE COLUMN \`${oldName}\` \`${newName}\` ${colDef}`));
              results.push({ table: tableName, column: `${oldName} -> ${newName}`, status: 'renamed' });
            } catch (e: any) {
              results.push({ table: tableName, column: `${oldName} -> ${newName}`, status: `error: ${e.message}` });
            }
          } else if (existingCols.has(newName)) {
            results.push({ table: tableName, column: newName, status: 'already_correct' });
          } else {
            results.push({ table: tableName, column: oldName, status: 'not_found' });
          }
        }
      } catch (e: any) {
        results.push({ table: tableName, column: '*', status: `table_error: ${e.message}` });
      }
    }

    return { results, timestamp: new Date().toISOString() };
  }),
});
