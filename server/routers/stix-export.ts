import * as db from "../db";
/**
 * STIX/TAXII Export Router
 * 
 * Provides tRPC endpoints for generating STIX 2.1 bundles from AC3 data,
 * plus TAXII 2.1 compatible collection endpoints for automated intel sharing.
 */
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import {
  threatActors,
  threatActorIocs,
  iocFeeds,
  engagements,
  unifiedExploitCatalog,
} from "../../drizzle/schema";
import { desc, sql, eq, and, inArray } from "drizzle-orm";
import {
  threatActorToStix,
  iocToStix,
  iocFeedToStix,
  engagementToStix,
  exploitToStix,
  createStixBundle,
  getBundleStats,
  TAXII_COLLECTIONS,
  type StixObject,
  type ThreatActorInput,
  type IocInput,
  type IocFeedInput,
  type EngagementInput,
  type ExploitInput,
} from "../lib/stix-generator";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

export const stixExportRouter = router({
  // ─── Export Stats ─────────────────────────────────────────────────────────
  stats: protectedProcedure.query(async () => {
    const db = await requireDb();
    const [actorCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(threatActors);
    const [iocCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(threatActorIocs);
    const [feedCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds);
    const [engCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(engagements);
    const [exploitCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(unifiedExploitCatalog);

    return {
      collections: TAXII_COLLECTIONS,
      dataCounts: {
        threatActors: actorCount.count,
        iocs: iocCount.count,
        feedEntries: feedCount.count,
        engagements: engCount.count,
        exploits: exploitCount.count,
      },
      supportedFormats: ["STIX 2.1 JSON Bundle", "TAXII 2.1 REST API"],
    };
  }),

  // ─── Export Threat Actors as STIX Bundle ───────────────────────────────────
  exportThreatActors: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(500).default(100),
      type: z.string().default("all"),
      threatLevel: z.string().default("all"),
      search: z.string().default(""),
    }))
    .mutation(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const db = await requireDb();
      const conditions: any[] = [];

      if (input.type !== "all") {
        conditions.push(eq(threatActors.actorType, input.type as any));
      }
      if (input.threatLevel !== "all") {
        conditions.push(eq(threatActors.threatLevel, input.threatLevel as any));
      }
      if (input.search) {
        conditions.push(
          sql`(${threatActors.name} LIKE ${`%${input.search}%`} OR ${threatActors.description} LIKE ${`%${input.search}%`})`
        );
      }

      const actors = await db
        .select()
        .from(threatActors)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(threatActors.confidence))
        .limit(input.limit);

      // Get IOCs for these actors
      const actorIds = actors.map((a: any) => a.actorId);
      let iocs: any[] = [];
      if (actorIds.length > 0) {
        iocs = await db
          .select()
          .from(threatActorIocs)
          .where(inArray(threatActorIocs.actorId, actorIds));
      }

      // Convert to STIX
      const stixObjects: StixObject[] = [];
      for (const actor of actors) {
        stixObjects.push(...threatActorToStix(actor as ThreatActorInput));
      }
      for (const ioc of iocs) {
        const indicator = iocToStix(ioc as IocInput);
        if (indicator) stixObjects.push(indicator);
      }

      const bundle = createStixBundle(stixObjects);
      return {
        bundle,
        stats: getBundleStats(bundle),
        exportedActors: actors.length,
        exportedIocs: iocs.length,
      };
    }),

  // ─── Export IOC Feed as STIX Bundle ────────────────────────────────────────
  exportIocFeed: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(1000).default(200),
      feedSource: z.string().default("all"),
      severity: z.string().default("all"),
      search: z.string().default(""),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const conditions: any[] = [];

      if (input.feedSource !== "all") {
        conditions.push(eq(iocFeeds.feedSource, input.feedSource));
      }
      if (input.severity !== "all") {
        conditions.push(eq(iocFeeds.feedSeverity, input.severity as any));
      }
      if (input.search) {
        conditions.push(
          sql`(${iocFeeds.title} LIKE ${`%${input.search}%`} OR ${iocFeeds.iocValue} LIKE ${`%${input.search}%`})`
        );
      }

      const entries = await db
        .select()
        .from(iocFeeds)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(iocFeeds.createdAt))
        .limit(input.limit);

      const stixObjects: StixObject[] = [];
      for (const entry of entries) {
        stixObjects.push(...iocFeedToStix(entry as IocFeedInput));
      }

      const bundle = createStixBundle(stixObjects);
      return {
        bundle,
        stats: getBundleStats(bundle),
        exportedEntries: entries.length,
      };
    }),

  // ─── Export Vulnerabilities as STIX Bundle ─────────────────────────────────
  exportVulnerabilities: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(500).default(200),
      severity: z.string().default("all"),
      source: z.string().default("all"),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const conditions: any[] = [];

      conditions.push(sql`${unifiedExploitCatalog.exploitCveIds} IS NOT NULL`);
      if (input.severity !== "all") {
        conditions.push(eq(unifiedExploitCatalog.exploitSeverity, input.severity));
      }
      if (input.source !== "all") {
        conditions.push(eq(unifiedExploitCatalog.exploitSource, input.source));
      }

      const exploits = await db
        .select()
        .from(unifiedExploitCatalog)
        .where(and(...conditions))
        .orderBy(desc(unifiedExploitCatalog.exploitCvssScore))
        .limit(input.limit);

      const stixObjects: StixObject[] = [];
      for (const exploit of exploits) {
        stixObjects.push(...exploitToStix(exploit as ExploitInput));
      }

      // Also get KEV entries from IOC feed
      const kevEntries = await db
        .select()
        .from(iocFeeds)
        .where(eq(iocFeeds.feedSource, "cisa_kev"))
        .orderBy(desc(iocFeeds.createdAt))
        .limit(100);

      for (const entry of kevEntries) {
        stixObjects.push(...iocFeedToStix(entry as IocFeedInput));
      }

      const bundle = createStixBundle(stixObjects);
      return {
        bundle,
        stats: getBundleStats(bundle),
        exportedExploits: exploits.length,
        exportedKev: kevEntries.length,
      };
    }),

  // ─── Export Campaigns/Engagements as STIX Bundle ───────────────────────────
  exportCampaigns: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      status: z.string().default("all"),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const conditions: any[] = [];

      if (input.status !== "all") {
        conditions.push(eq(engagements.status, input.status as any));
      }

      const engs = await db
        .select()
        .from(engagements)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(engagements.createdAt))
        .limit(input.limit);

      const stixObjects: StixObject[] = [];
      for (const eng of engs) {
        stixObjects.push(engagementToStix(eng as EngagementInput));
      }

      const bundle = createStixBundle(stixObjects);
      return {
        bundle,
        stats: getBundleStats(bundle),
        exportedCampaigns: engs.length,
      };
    }),

  // ─── Export All Intelligence as STIX Bundle ────────────────────────────────
  exportAll: protectedProcedure
    .input(z.object({
      maxActors: z.number().min(1).max(200).default(50),
      maxIocs: z.number().min(1).max(500).default(100),
      maxExploits: z.number().min(1).max(200).default(50),
      maxEngagements: z.number().min(1).max(50).default(20),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const stixObjects: StixObject[] = [];

      // Threat Actors
      const actors = await db
        .select().from(threatActors)
        .orderBy(desc(threatActors.confidence))
        .limit(input.maxActors);
      for (const actor of actors) {
        stixObjects.push(...threatActorToStix(actor as ThreatActorInput));
      }

      // Actor IOCs
      const actorIds = actors.map((a: any) => a.actorId);
      if (actorIds.length > 0) {
        const iocs = await db
          .select().from(threatActorIocs)
          .where(inArray(threatActorIocs.actorId, actorIds));
        for (const ioc of iocs) {
          const indicator = iocToStix(ioc as IocInput);
          if (indicator) stixObjects.push(indicator);
        }
      }

      // IOC Feed
      const feedEntries = await db
        .select().from(iocFeeds)
        .orderBy(desc(iocFeeds.createdAt))
        .limit(input.maxIocs);
      for (const entry of feedEntries) {
        stixObjects.push(...iocFeedToStix(entry as IocFeedInput));
      }

      // Exploits with CVEs
      const exploits = await db
        .select().from(unifiedExploitCatalog)
        .where(sql`${unifiedExploitCatalog.exploitCveIds} IS NOT NULL`)
        .orderBy(desc(unifiedExploitCatalog.exploitCvssScore))
        .limit(input.maxExploits);
      for (const exploit of exploits) {
        stixObjects.push(...exploitToStix(exploit as ExploitInput));
      }

      // Engagements
      const engs = await db
        .select().from(engagements)
        .orderBy(desc(engagements.createdAt))
        .limit(input.maxEngagements);
      for (const eng of engs) {
        stixObjects.push(engagementToStix(eng as EngagementInput));
      }

      const bundle = createStixBundle(stixObjects);
      return {
        bundle,
        stats: getBundleStats(bundle),
        exported: {
          actors: actors.length,
          feedEntries: feedEntries.length,
          exploits: exploits.length,
          engagements: engs.length,
        },
      };
    }),

  // ─── TAXII 2.1 Discovery ──────────────────────────────────────────────────
  taxiiDiscovery: publicProcedure.query(() => {
    return {
      title: "AC3 TAXII Server",
      description: "TAXII 2.1 compatible endpoint for AC3 threat intelligence",
      contact: "https://aceofcloud.com",
      default: "/api/trpc/stixExport.taxiiApiRoot",
      api_roots: ["/api/trpc/stixExport.taxiiApiRoot"],
    };
  }),

  // ─── TAXII 2.1 API Root ───────────────────────────────────────────────────
  taxiiApiRoot: publicProcedure.query(() => {
    return {
      title: "AC3 Intelligence",
      description: "AC3 threat intelligence collections",
      versions: ["application/taxii+json;version=2.1"],
      max_content_length: 10485760,
    };
  }),

  // ─── TAXII 2.1 Collections ────────────────────────────────────────────────
  taxiiCollections: publicProcedure.query(() => {
    return {
      collections: TAXII_COLLECTIONS,
    };
  }),

  // ─── TAXII 2.1 Get Collection ─────────────────────────────────────────────
  taxiiGetCollection: publicProcedure
    .input(z.object({ collectionId: z.string() }))
    .query(({ input }) => {
      const collection = TAXII_COLLECTIONS.find(c => c.id === input.collectionId);
      if (!collection) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Collection not found" });
      }
      return collection;
    }),

  // ─── TAXII 2.1 Get Collection Objects ──────────────────────────────────────
  taxiiGetObjects: protectedProcedure
    .input(z.object({
      collectionId: z.string(),
      limit: z.number().min(1).max(500).default(100),
    }))
    .query(async ({ input }) => {
      const collection = TAXII_COLLECTIONS.find(c => c.id === input.collectionId);
      if (!collection) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Collection not found" });
      }

      const db = await requireDb();
      const stixObjects: StixObject[] = [];

      switch (input.collectionId) {
        case "ac3-threat-actors": {
          const actors = await db.select().from(threatActors)
            .orderBy(desc(threatActors.confidence))
            .limit(input.limit);
          for (const actor of actors) {
            stixObjects.push(...threatActorToStix(actor as ThreatActorInput));
          }
          break;
        }
        case "ac3-indicators": {
          const entries = await db.select().from(iocFeeds)
            .orderBy(desc(iocFeeds.createdAt))
            .limit(input.limit);
          for (const entry of entries) {
            stixObjects.push(...iocFeedToStix(entry as IocFeedInput));
          }
          break;
        }
        case "ac3-vulnerabilities": {
          const exploits = await db.select().from(unifiedExploitCatalog)
            .where(sql`${unifiedExploitCatalog.exploitCveIds} IS NOT NULL`)
            .orderBy(desc(unifiedExploitCatalog.exploitCvssScore))
            .limit(input.limit);
          for (const exploit of exploits) {
            stixObjects.push(...exploitToStix(exploit as ExploitInput));
          }
          break;
        }
        case "ac3-campaigns": {
          const engs = await db.select().from(engagements)
            .orderBy(desc(engagements.createdAt))
            .limit(input.limit);
          for (const eng of engs) {
            stixObjects.push(engagementToStix(eng as EngagementInput));
          }
          break;
        }
        case "ac3-all": {
          const lim = Math.floor(input.limit / 4);
          const actors = await db.select().from(threatActors).orderBy(desc(threatActors.confidence)).limit(lim);
          for (const actor of actors) stixObjects.push(...threatActorToStix(actor as ThreatActorInput));
          const entries = await db.select().from(iocFeeds).orderBy(desc(iocFeeds.createdAt)).limit(lim);
          for (const entry of entries) stixObjects.push(...iocFeedToStix(entry as IocFeedInput));
          const exploits = await db.select().from(unifiedExploitCatalog).where(sql`${unifiedExploitCatalog.exploitCveIds} IS NOT NULL`).orderBy(desc(unifiedExploitCatalog.exploitCvssScore)).limit(lim);
          for (const exploit of exploits) stixObjects.push(...exploitToStix(exploit as ExploitInput));
          const engs = await db.select().from(engagements).orderBy(desc(engagements.createdAt)).limit(lim);
          for (const eng of engs) stixObjects.push(engagementToStix(eng as EngagementInput));
          break;
        }
      }

      const bundle = createStixBundle(stixObjects);
      return {
        ...bundle,
        more: false,
        next: undefined,
      };
    }),
});
