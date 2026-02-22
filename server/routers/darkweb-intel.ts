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
});
