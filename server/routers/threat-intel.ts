import * as db from "../db";
/**
 * Threat Intelligence Router — Master Catalog API
 * 
 * Provides CRUD, full catalog sync, LLM enrichment, monitoring, and stats
 * for the unified threat actor catalog.
 */

import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import {
  threatActors, threatGroupEvents, threatIntelUpdates,
  ransomwareGroups, threatActorIocs, enrichmentHistory,
} from "../../drizzle/schema";
import { eq, sql, desc, and, like, inArray } from "drizzle-orm";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

function safeParseArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
}
function safeParseObj(v: unknown): any {
  if (!v) return null;
  if (typeof v === "object" && !Array.isArray(v)) return v;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } }
  return null;
}

export const threatIntelRouter = router({

  // ─── Catalog Stats ─────────────────────────────────────────────────────────
  stats: protectedProcedure.query(async () => {
    const { getCatalogStats } = await import("../lib/threat-intel-connectors");
    return getCatalogStats();
  }),

  // ─── List All Actors (paginated, filterable) ──────────────────────────────
  list: protectedProcedure
    .input(z.object({
      page: z.number().default(1),
      pageSize: z.number().default(50),
      type: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops", "unknown", "all"]).default("all"),
      threatLevel: z.enum(["critical", "high", "medium", "low", "all"]).default("all"),
      updatedLast24h: z.boolean().optional(),
      conflict: z.string().optional(),
      search: z.string().optional(),
      sortBy: z.enum(["name", "threatLevel", "lastActive", "confidence"]).default("name"),
      sortOrder: z.enum(["asc", "desc"]).default("asc"),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { page: 1, pageSize: 50, type: "all", threatLevel: "all", sortBy: "name", sortOrder: "asc" };
      const offset = ((opts.page || 1) - 1) * (opts.pageSize || 50);

      const conditions: any[] = [];
      if (opts.type && opts.type !== "all") conditions.push(eq(threatActors.actorType, opts.type));
      if (opts.threatLevel && opts.threatLevel !== "all") conditions.push(eq(threatActors.threatLevel, opts.threatLevel));
      if (opts.search) conditions.push(sql`(${threatActors.name} LIKE ${'%' + opts.search + '%'} OR ${threatActors.actorId} LIKE ${'%' + opts.search + '%'})`);
      if (opts.conflict && opts.conflict !== 'all') conditions.push(sql`${threatActors.conflicts} LIKE ${'%' + opts.conflict + '%'}`);
      if (opts.updatedLast24h) conditions.push(sql`${threatActors.updatedAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const sortCol = opts.sortBy === "threatLevel" ? threatActors.threatLevel
        : opts.sortBy === "lastActive" ? threatActors.lastActive
        : opts.sortBy === "confidence" ? threatActors.confidence
        : threatActors.name;
      const order = opts.sortOrder === "desc" ? desc(sortCol) : sortCol;

      const [actors, countResult] = await Promise.all([
        db.select().from(threatActors).where(where).orderBy(order).limit(opts.pageSize || 50).offset(offset),
        db.select({ count: sql<number>`count(*)` }).from(threatActors).where(where),
      ]);

      return {
        actors: actors.map(a => ({
          ...a,
          type: a.actorType, // alias for frontend compatibility
          aliases: safeParseArr(a.aliases),
          targetSectors: safeParseArr(a.targetSectors),
          targetRegions: safeParseArr(a.targetRegions),
          techniques: safeParseArr(a.techniques),
          tools: safeParseArr(a.tools),
          malware: safeParseArr(a.malware),
          activityTimeline: safeParseArr(a.activityTimeline),
          calderaProfile: safeParseObj(a.calderaProfile),
        })),
        total: countResult[0]?.count || 0,
        page: opts.page || 1,
        pageSize: opts.pageSize || 50,
      };
    }),

  // ─── Get Single Actor Detail ──────────────────────────────────────────────
  getActor: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [actor] = await db.select().from(threatActors)
        .where(eq(threatActors.actorId, input.actorId))
        .limit(1);
      if (!actor) throw new TRPCError({ code: "NOT_FOUND", message: "Actor not found" });

      // Get events
      const events = await db.select().from(threatGroupEvents)
        .where(eq(threatGroupEvents.tgeActorId, input.actorId))
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(100);

      // Get IOCs
      const iocs = await db.select().from(threatActorIocs)
        .where(eq(threatActorIocs.actorId, input.actorId))
        .limit(200);

      // Get ransomware extension if applicable
      let ransomwareProfile = null;
      if (actor.actorType === "ransomware") {
        const [rg] = await db.select().from(ransomwareGroups)
          .where(eq(ransomwareGroups.calderaActorId, input.actorId))
          .limit(1);
        if (!rg) {
          // Try by name match
          const [rgByName] = await db.select().from(ransomwareGroups)
            .where(eq(ransomwareGroups.groupName, actor.name))
            .limit(1);
          ransomwareProfile = rgByName || null;
        } else {
          ransomwareProfile = rg;
        }
      }

      return {
        actor: {
          ...actor,
          type: actor.actorType, // alias for frontend compatibility
          aliases: safeParseArr(actor.aliases),
          targetSectors: safeParseArr(actor.targetSectors),
          targetRegions: safeParseArr(actor.targetRegions),
          techniques: safeParseArr(actor.techniques),
          tools: safeParseArr(actor.tools),
          malware: safeParseArr(actor.malware),
          activityTimeline: safeParseArr(actor.activityTimeline),
          calderaProfile: safeParseObj(actor.calderaProfile),
        },
        events: events.map(e => ({
          ...e,
          actorId: e.tgeActorId,
          title: e.tgeTitle,
          description: e.tgeDescription,
          severity: e.tgeSeverity,
          victimName: e.tgeVictimName,
          victimSector: e.tgeVictimSector,
          victimCountry: e.tgeVictimCountry,
          mitreTechniques: safeParseArr(e.tgeMitreTechniques),
          iocs: safeParseArr(e.tgeIocs),
          source: e.tgeSource,
          sourceUrl: e.tgeSourceUrl,
          confidence: e.tgeConfidence,
        })),
        iocs: iocs.map(ioc => ({
          ...ioc,
          type: ioc.iocType,
          confidence: ioc.iocConfidence,
          firstSeen: ioc.iocFirstSeen,
          lastSeen: ioc.iocLastSeen,
        })),
        ransomwareProfile: ransomwareProfile ? {
          ...ransomwareProfile,
          aliases: safeParseArr(ransomwareProfile.aliases),
          topSectors: safeParseArr(ransomwareProfile.topSectors),
          topCountries: safeParseArr(ransomwareProfile.topCountries),
          associatedMalware: safeParseArr(ransomwareProfile.associatedMalware),
          mitreTechniques: safeParseArr(ransomwareProfile.mitreTechniques),
          knownInfrastructure: safeParseArr(ransomwareProfile.knownInfrastructure),
          notableAttacks: safeParseArr(ransomwareProfile.notableAttacks),
        } : null,
      };
    }),

  // ─── Full Catalog Sync (all sources) ──────────────────────────────────────
  syncCatalog: protectedProcedure
    .input(z.object({
      sources: z.array(z.enum(["mitre-attack", "ransomware-live", "malpedia", "caldera"])).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const sources = input?.sources;
      if (sources && sources.length > 0) {
        const results = [];
        for (const src of sources) {
          if (src === "mitre-attack") {
            const { ingestMitreAttack } = await import("../lib/threat-intel-connectors");
            results.push(await ingestMitreAttack());
          } else if (src === "ransomware-live") {
            const { ingestRansomwareLive } = await import("../lib/threat-intel-connectors");
            results.push(await ingestRansomwareLive());
          } else if (src === "malpedia") {
            const { ingestMalpedia } = await import("../lib/threat-intel-connectors");
            results.push(await ingestMalpedia());
          } else if (src === "caldera") {
            const { ingestCalderaAdversaries } = await import("../lib/threat-intel-connectors");
            results.push(await ingestCalderaAdversaries());
          }
        }
        return { results, totalNew: results.reduce((s, r) => s + r.groupsIngested, 0), totalUpdated: results.reduce((s, r) => s + r.groupsUpdated, 0) };
      }
      const { runFullCatalogSync } = await import("../lib/threat-intel-connectors");
      return runFullCatalogSync();
    }),

  // ─── LLM Enrichment for a specific actor ──────────────────────────────────
  enrichActor: protectedProcedure
    .input(z.object({ actorId: z.string(), actorType: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops", "unknown"]).default("apt") }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const startTime = Date.now();
      const { enrichActorWithKeywords } = await import("../lib/keyword-enrichment");
      // Get actor for pre-quality score
      const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, input.actorId)).limit(1);
      const qualityBefore = computeCompleteness(actor);
      const result = await enrichActorWithKeywords(input.actorId);
      const qualityAfter = result.dataQualityScore || qualityBefore;
      // Record in enrichment_history
      await db.insert(enrichmentHistory).values({
        actorId: input.actorId,
        actorName: actor?.name || input.actorId,
        triggeredBy: 'manual',
        fieldsUpdated: JSON.stringify(result.fieldsUpdated || []),
        fieldsDiscovered: JSON.stringify(result.fieldsDiscovered || []),
        sourcesUsed: JSON.stringify((result.sources || []).map((s: any) => ({ source: s.source, sourceType: s.sourceType }))),
        keywordsUsed: JSON.stringify(result.keywordsUsed || {}),
        dataQualityBefore: qualityBefore,
        dataQualityAfter: qualityAfter,
        summary: result.summary || '',
        status: 'success',
        durationMs: Date.now() - startTime,
      }).catch(() => {});
      return {
        actorId: result.actorId,
        keywordsUsed: result.keywordsUsed,
        fieldsUpdated: result.fieldsUpdated,
        fieldsDiscovered: result.fieldsDiscovered,
        sources: result.sources,
        enrichedData: result.enrichedData,
        summary: result.summary,
        dataQualityScore: result.dataQualityScore,
      };
    }),

  // ─── LLM Monitoring Sweep ────────────────────────────────────────────────
  runMonitoringSweep: protectedProcedure
    .input(z.object({
      actorIds: z.array(z.string()).optional(),
      limit: z.number().default(20),
    }).optional())
    .mutation(async ({ input }) => {
      const { runMonitoringSweep } = await import("../lib/threat-intel-catalog");
      return runMonitoringSweep(undefined, input?.actorIds);
    }),

  // ─── Get Recent Events (across all groups) ───────────────────────────────
  recentEvents: protectedProcedure
    .input(z.object({
      limit: z.number().default(50),
      eventType: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const conditions: any[] = [];
      if (input?.eventType) conditions.push(eq(threatGroupEvents.eventType, input.eventType as any));
      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const events = await db.select({
        event: threatGroupEvents,
        actorName: threatActors.name,
        actorType: threatActors.actorType,
      })
        .from(threatGroupEvents)
        .leftJoin(threatActors, eq(threatGroupEvents.tgeActorId, threatActors.actorId))
        .where(where)
        .orderBy(desc(threatGroupEvents.eventDate))
        .limit(input?.limit || 50);

      return events.map(e => ({
        ...e.event,
        // Map tge-prefixed Drizzle fields to frontend-expected names
        actorId: e.event.tgeActorId,
        title: e.event.tgeTitle,
        description: e.event.tgeDescription,
        severity: e.event.tgeSeverity,
        victimName: e.event.tgeVictimName,
        victimSector: e.event.tgeVictimSector,
        victimCountry: e.event.tgeVictimCountry,
        mitreTechniques: safeParseArr(e.event.tgeMitreTechniques),
        iocs: safeParseArr(e.event.tgeIocs),
        source: e.event.tgeSource,
        sourceUrl: e.event.tgeSourceUrl,
        confidence: e.event.tgeConfidence,
        actorName: e.actorName,
        actorType: e.actorType,
      }));
    }),

  // ─── Get Sync History ────────────────────────────────────────────────────
  syncHistory: protectedProcedure
    .input(z.object({ limit: z.number().default(20) }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      return db.select().from(threatIntelUpdates)
        .orderBy(desc(threatIntelUpdates.tiuStartedAt))
        .limit(input?.limit || 20);
    }),

  // ─── Auto-discover actor from pipeline ───────────────────────────────────
  ensureActor: protectedProcedure
    .input(z.object({
      name: z.string(),
      type: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops"]).optional(),
      description: z.string().optional(),
      nationState: z.string().optional(),
      ttps: z.array(z.string()).optional(),
      source: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { ensureActorInCatalog } = await import("../lib/threat-intel-connectors");
      const actorId = await ensureActorInCatalog(input.name, {
        type: input.type,
        description: input.description,
        nationState: input.nationState,
        ttps: input.ttps,
        source: input.source,
      });
      return { actorId };
    }),

  // ─── Ransomware-specific stats ───────────────────────────────────────────
  ransomwareStats: protectedProcedure.query(async () => {
    const db = await requireDb();

    const groups = await db.select().from(ransomwareGroups);
    const totalVictims = groups.reduce((s, g) => s + (g.totalVictims || 0), 0);
    const activeGroups = groups.filter(g => g.trend === "surging" || g.trend === "active").length;
    const surgingGroups = groups.filter(g => g.trend === "surging");

    const recentEvents = await db.select({ count: sql<number>`count(*)` })
      .from(threatGroupEvents)
      .where(sql`${threatGroupEvents.eventType} = 'attack' AND ${threatGroupEvents.eventDate} > DATE_SUB(NOW(), INTERVAL 7 DAY)`);

    return {
      totalGroups: groups.length,
      activeGroups,
      totalVictims,
      recentAttacks7d: recentEvents[0]?.count || 0,
      surgingGroups: surgingGroups.map(g => ({
        name: g.groupName,
        activityScore: g.activityScore,
        victims30d: g.victims30D,
      })),
      topGroups: groups
        .sort((a, b) => (b.activityScore || 0) - (a.activityScore || 0))
        .slice(0, 10)
        .map(g => ({
          name: g.groupName,
          activityScore: g.activityScore,
          trend: g.trend,
          threatLevel: g.rwThreatLevel,
          totalVictims: g.totalVictims,
          extortionModel: g.extortionModel,
        })),
    };
  }),

  // ─── Ransomware Group List (paginated) ──────────────────────────────────
  ransomwareList: protectedProcedure
    .input(z.object({
      page: z.number().default(1),
      pageSize: z.number().default(50),
      trend: z.enum(["surging", "active", "declining", "dormant", "all"]).default("all"),
      search: z.string().optional(),
      sortBy: z.enum(["groupName", "activityScore", "totalVictims", "victims30d"]).default("activityScore"),
      sortOrder: z.enum(["asc", "desc"]).default("desc"),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { page: 1, pageSize: 50, trend: "all", sortBy: "activityScore", sortOrder: "desc" };
      const offset = ((opts.page || 1) - 1) * (opts.pageSize || 50);

      const conditions: any[] = [];
      if (opts.trend && opts.trend !== "all") conditions.push(eq(ransomwareGroups.trend, opts.trend));
      if (opts.search) conditions.push(sql`${ransomwareGroups.groupName} LIKE ${'%' + opts.search + '%'}`);

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const sortCol = opts.sortBy === "groupName" ? ransomwareGroups.groupName
        : opts.sortBy === "totalVictims" ? ransomwareGroups.totalVictims
        : opts.sortBy === "victims30d" ? ransomwareGroups.victims30D
        : ransomwareGroups.activityScore;
      const order = opts.sortOrder === "desc" ? desc(sortCol) : sortCol;

      const [groups, countResult] = await Promise.all([
        db.select().from(ransomwareGroups).where(where).orderBy(order).limit(opts.pageSize || 50).offset(offset),
        db.select({ count: sql<number>`count(*)` }).from(ransomwareGroups).where(where),
      ]);

      return {
        groups: groups.map(g => ({
          ...g,
          aliases: safeParseArr(g.aliases),
          topSectors: safeParseArr(g.topSectors),
          topCountries: safeParseArr(g.topCountries),
          associatedMalware: safeParseArr(g.associatedMalware),
          mitreTechniques: safeParseArr(g.mitreTechniques),
          knownInfrastructure: safeParseArr(g.knownInfrastructure),
          notableAttacks: safeParseArr(g.notableAttacks),
        })),
        total: countResult[0]?.count || 0,
        page: opts.page || 1,
        pageSize: opts.pageSize || 50,
      };
    }),

  // ─── Ransomware Group Detail ───────────────────────────────────────────
  ransomwareDetail: protectedProcedure
    .input(z.object({ groupName: z.string() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [group] = await db.select().from(ransomwareGroups)
        .where(eq(ransomwareGroups.groupName, input.groupName))
        .limit(1);
      if (!group) throw new TRPCError({ code: "NOT_FOUND", message: "Ransomware group not found" });

      // Get recent victim events
      const { ransomwareEvents } = await import("../../drizzle/schema");
      const events = await db.select().from(ransomwareEvents)
        .where(eq(ransomwareEvents.reGroupName, input.groupName))
        .orderBy(desc(ransomwareEvents.publishedAt))
        .limit(50);

      // Get linked threat actor if exists
      let linkedActor = null;
      if (group.calderaActorId) {
        const [actor] = await db.select().from(threatActors)
          .where(eq(threatActors.actorId, group.calderaActorId))
          .limit(1);
        linkedActor = actor ? {
          ...actor,
          aliases: safeParseArr(actor.aliases),
          techniques: safeParseArr(actor.techniques),
          tools: safeParseArr(actor.tools),
        } : null;
      }

      return {
        group: {
          ...group,
          aliases: safeParseArr(group.aliases),
          topSectors: safeParseArr(group.topSectors),
          topCountries: safeParseArr(group.topCountries),
          associatedMalware: safeParseArr(group.associatedMalware),
          mitreTechniques: safeParseArr(group.mitreTechniques),
          knownInfrastructure: safeParseArr(group.knownInfrastructure),
          notableAttacks: safeParseArr(group.notableAttacks),
        },
        events,
        linkedActor,
      };
    }),

  // ─── MITRE ATT&CK Technique Coverage ─────────────────────────────────────
  techniqueCoverage: protectedProcedure.query(async () => {
    const db = await requireDb();
    const actors = await db.select({
      actorId: threatActors.actorId,
      name: threatActors.name,
      actorType: threatActors.actorType,
      techniques: threatActors.techniques,
    }).from(threatActors);

    const techMap = new Map<string, { id: string; name: string; tactic: string; actors: string[] }>();
    for (const a of actors) {
      let techs: any[] = [];
      try {
        techs = typeof a.techniques === "string" ? JSON.parse(a.techniques || "[]") : Array.isArray(a.techniques) ? a.techniques : [];
      } catch { techs = []; }
      for (const t of techs) {
        const id = typeof t === "string" ? t : t.id;
        const name = typeof t === "string" ? t : t.name || t.id;
        const tactic = typeof t === "string" ? "unknown" : t.tactic || "unknown";
        if (!techMap.has(id)) techMap.set(id, { id, name, tactic, actors: [] });
        techMap.get(id)!.actors.push(a.name);
      }
    }

    const techniques = Array.from(techMap.values())
      .sort((a, b) => b.actors.length - a.actors.length);

    const byTactic = new Map<string, number>();
    for (const t of techniques) {
      byTactic.set(t.tactic, (byTactic.get(t.tactic) || 0) + 1);
    }

    return {
      totalTechniques: techniques.length,
      topTechniques: techniques.slice(0, 30),
      byTactic: Array.from(byTactic.entries()).map(([tactic, count]) => ({ tactic, count })).sort((a, b) => b.count - a.count),
    };
  }),

  // ─── Featured Actors for Homepage (most detailed, randomized) ───────────
  featuredActors: protectedProcedure
    .input(z.object({ count: z.number().min(1).max(20).default(6) }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const count = input?.count ?? 6;

      // Fetch all actors with their raw fields so we can score completeness
      const allActors = await db.select().from(threatActors);

      // Score each actor by data completeness across all fields
      const scored = allActors.map(a => {
        let score = 0;
        const aliases = safeParseArr(a.aliases);
        const techniques = safeParseArr(a.techniques);
        const tools = safeParseArr(a.tools);
        const malware = safeParseArr(a.malware);
        const targetSectors = safeParseArr(a.targetSectors);
        const targetRegions = safeParseArr(a.targetRegions);
        const activityTimeline = safeParseArr(a.activityTimeline);
        const calderaProfile = safeParseObj(a.calderaProfile);

        // Core identity fields (weighted higher)
        if (a.description && a.description.length > 50) score += 15;
        else if (a.description) score += 5;
        if (a.origin) score += 5;
        if (a.motivation) score += 5;
        if (a.firstSeen) score += 3;
        if (a.lastActive) score += 5;

        // Threat level & sophistication
        if (a.threatLevel === 'critical') score += 10;
        else if (a.threatLevel === 'high') score += 7;
        else if (a.threatLevel === 'medium') score += 3;
        if (a.sophistication === 'nation-state') score += 8;
        else if (a.sophistication === 'advanced') score += 5;

        // Richness of structured data
        score += Math.min(aliases.length * 2, 10);
        score += Math.min(techniques.length, 20);
        score += Math.min(tools.length * 2, 12);
        score += Math.min(malware.length * 2, 12);
        score += Math.min(targetSectors.length * 2, 10);
        score += Math.min(targetRegions.length * 2, 10);
        score += Math.min(activityTimeline.length * 3, 15);
        if (calderaProfile) score += 10;
        if (a.confidence && a.confidence >= 80) score += 5;
        if (a.stixId) score += 3;

        return {
          ...a,
          aliases,
          techniques,
          tools,
          malware,
          targetSectors,
          targetRegions,
          activityTimeline,
          calderaProfile,
          _completenessScore: score,
        };
      });

      // Sort by completeness score descending, take top pool (3x requested count)
      scored.sort((a, b) => b._completenessScore - a._completenessScore);
      const poolSize = Math.min(scored.length, count * 3);
      const pool = scored.slice(0, poolSize);

      // Fisher-Yates shuffle the pool
      for (let i = pool.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [pool[i], pool[j]] = [pool[j], pool[i]];
      }

      // Return the requested count
      return pool.slice(0, count).map(a => {
        const { _completenessScore, ...rest } = a;
        return rest;
      });
    }),

  // ─── Incomplete Actors (below completeness threshold) ──────────────────
  incompleteActors: protectedProcedure
    .input(z.object({ threshold: z.number().min(0).max(100).default(60), limit: z.number().default(50) }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const threshold = input?.threshold ?? 60;
      const limit = input?.limit ?? 50;
      const actors = await db.select().from(threatActors);
      const scored = actors.map(a => {
        const fields = [
          { label: "Description", val: a.description && a.description !== "unknown" },
          { label: "Motivation", val: a.motivation && a.motivation !== "unknown" },
          { label: "Origin", val: a.origin && a.origin !== "unknown" && a.origin !== "Unknown" },
          { label: "Aliases", val: safeParseArr(a.aliases).length > 0 },
          { label: "Target Sectors", val: safeParseArr(a.targetSectors).length > 0 },
          { label: "Target Regions", val: safeParseArr(a.targetRegions).length > 0 },
          { label: "Techniques", val: safeParseArr(a.techniques).length > 0 },
          { label: "Tools", val: safeParseArr(a.tools).length > 0 },
          { label: "Malware", val: safeParseArr(a.malware).length > 0 },
          { label: "First Seen", val: !!a.firstSeen },
          { label: "Last Active", val: !!a.lastActive },
        ];
        const filled = fields.filter(f => f.val).length;
        const completeness = Math.round((filled / fields.length) * 100);
        const missing = fields.filter(f => !f.val).map(f => f.label);
        return { actorId: a.actorId, name: a.name, actorType: a.actorType, completeness, missing };
      });
      const incomplete = scored.filter(s => s.completeness < threshold);
      incomplete.sort((a, b) => a.completeness - b.completeness);
      return { total: incomplete.length, actors: incomplete.slice(0, limit), threshold };
    }),

  // ─── Bulk Enrich ──────────────────────────────────────────────────────
  bulkEnrich: protectedProcedure
    .input(z.object({
      actorIds: z.array(z.string()).min(1).max(50),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { enrichActorWithKeywords } = await import("../lib/keyword-enrichment");
      const results: Array<{ actorId: string; status: string; fieldsUpdated: number; fieldsDiscovered: number; error?: string }> = [];
      for (const actorId of input.actorIds) {
        const startTime = Date.now();
        try {
          // Get actor for name and pre-quality score
          const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
          const qualityBefore = computeCompleteness(actor);
          const result = await enrichActorWithKeywords(actorId);
          const qualityAfter = result.dataQualityScore || qualityBefore;
          // Record in enrichment_history
          await db.insert(enrichmentHistory).values({
            actorId,
            actorName: actor?.name || actorId,
            triggeredBy: 'bulk',
            fieldsUpdated: JSON.stringify(result.fieldsUpdated || []),
            fieldsDiscovered: JSON.stringify(result.fieldsDiscovered || []),
            sourcesUsed: JSON.stringify((result.sources || []).map((s: any) => ({ source: s.source, sourceType: s.sourceType }))),
            keywordsUsed: JSON.stringify(result.keywordsUsed || {}),
            dataQualityBefore: qualityBefore,
            dataQualityAfter: qualityAfter,
            summary: result.summary || '',
            status: 'success',
            durationMs: Date.now() - startTime,
          });
          results.push({ actorId, status: 'success', fieldsUpdated: result.fieldsUpdated?.length || 0, fieldsDiscovered: result.fieldsDiscovered?.length || 0 });
        } catch (err: any) {
          // Record failure
          await db.insert(enrichmentHistory).values({
            actorId,
            actorName: actorId,
            triggeredBy: 'bulk',
            status: 'failed',
            errorMessage: err?.message || 'Unknown error',
            durationMs: Date.now() - startTime,
          }).catch(() => {});
          results.push({ actorId, status: 'failed', fieldsUpdated: 0, fieldsDiscovered: 0, error: err?.message || 'Unknown error' });
        }
      }
      const succeeded = results.filter(r => r.status === 'success').length;
      return { total: results.length, succeeded, failed: results.length - succeeded, results };
    }),

  // ─── Enrichment History ───────────────────────────────────────────────
  enrichmentHistoryList: protectedProcedure
    .input(z.object({
      actorId: z.string().optional(),
      limit: z.number().default(50),
      page: z.number().default(1),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { limit: 50, page: 1 };
      const offset = ((opts.page || 1) - 1) * (opts.limit || 50);
      const conditions: any[] = [];
      if (opts.actorId) conditions.push(eq(enrichmentHistory.actorId, opts.actorId));
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const [rows, countResult] = await Promise.all([
        db.select().from(enrichmentHistory).where(where).orderBy(desc(enrichmentHistory.createdAt)).limit(opts.limit || 50).offset(offset),
        db.select({ count: sql<number>`count(*)` }).from(enrichmentHistory).where(where),
      ]);
      return {
        history: rows.map(r => ({
          ...r,
          fieldsUpdated: safeParseArr(r.fieldsUpdated),
          fieldsDiscovered: safeParseArr(r.fieldsDiscovered),
          sourcesUsed: safeParseArr(r.sourcesUsed),
          keywordsUsed: safeParseObj(r.keywordsUsed),
        })),
        total: Number(countResult[0]?.count || 0),
        page: opts.page || 1,
        pageSize: opts.limit || 50,
      };
    }),

  // ─── CSV Export ───────────────────────────────────────────────────────
  exportCsv: protectedProcedure
    .input(z.object({
      type: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops", "unknown", "all"]).default("all"),
      threatLevel: z.enum(["critical", "high", "medium", "low", "all"]).default("all"),
      updatedLast24h: z.boolean().optional(),
      conflict: z.string().optional(),
      search: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { type: "all", threatLevel: "all" };
      const conditions: any[] = [];
      if (opts.type && opts.type !== "all") conditions.push(eq(threatActors.actorType, opts.type));
      if (opts.threatLevel && opts.threatLevel !== "all") conditions.push(eq(threatActors.threatLevel, opts.threatLevel));
      if (opts.search) conditions.push(sql`(${threatActors.name} LIKE ${'%' + opts.search + '%'} OR ${threatActors.actorId} LIKE ${'%' + opts.search + '%'})`);
      if (opts.conflict && opts.conflict !== 'all') conditions.push(sql`${threatActors.conflicts} LIKE ${'%' + opts.conflict + '%'}`);
      if (opts.updatedLast24h) conditions.push(sql`${threatActors.updatedAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const actors = await db.select().from(threatActors).where(where).orderBy(threatActors.name);
      // Build CSV
      const headers = ['Actor ID','Name','Type','Threat Level','Sophistication','Origin','Motivation','First Seen','Last Active','Aliases','Target Sectors','Target Regions','Techniques','Tools','Malware','Confidence','STIX ID','Conflicts','Description'];
      const rows = actors.map(a => [
        a.actorId, a.name, a.actorType, a.threatLevel, a.sophistication, a.origin || '', a.motivation || '',
        a.firstSeen || '', a.lastActive || '',
        safeParseArr(a.aliases).join('; '),
        safeParseArr(a.targetSectors).join('; '),
        safeParseArr(a.targetRegions).join('; '),
        safeParseArr(a.techniques).map((t: any) => typeof t === 'string' ? t : `${t.id || ''}:${t.name || ''}`).join('; '),
        safeParseArr(a.tools).join('; '),
        safeParseArr(a.malware).join('; '),
        String(a.confidence || ''),
        a.stixId || '',
        a.conflicts || '',
        (a.description || '').replace(/[\r\n]+/g, ' ').replace(/"/g, '""'),
      ]);
      const csvContent = [headers.join(','), ...rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))].join('\n');
      return { csv: csvContent, count: actors.length };
    }),

  // ─── STIX 2.1 Export ──────────────────────────────────────────────────
  exportStix: protectedProcedure
    .input(z.object({
      type: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops", "unknown", "all"]).default("all"),
      threatLevel: z.enum(["critical", "high", "medium", "low", "all"]).default("all"),
      updatedLast24h: z.boolean().optional(),
      conflict: z.string().optional(),
      search: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { type: "all", threatLevel: "all" };
      const conditions: any[] = [];
      if (opts.type && opts.type !== "all") conditions.push(eq(threatActors.actorType, opts.type));
      if (opts.threatLevel && opts.threatLevel !== "all") conditions.push(eq(threatActors.threatLevel, opts.threatLevel));
      if (opts.search) conditions.push(sql`(${threatActors.name} LIKE ${'%' + opts.search + '%'} OR ${threatActors.actorId} LIKE ${'%' + opts.search + '%'})`);
      if (opts.conflict && opts.conflict !== 'all') conditions.push(sql`${threatActors.conflicts} LIKE ${'%' + opts.conflict + '%'}`);
      if (opts.updatedLast24h) conditions.push(sql`${threatActors.updatedAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const actors = await db.select().from(threatActors).where(where).orderBy(threatActors.name);
      // Map type to STIX threat-actor-type
      const typeMap: Record<string, string> = {
        apt: 'nation-state', ransomware: 'criminal', cybercrime: 'criminal',
        hacktivist: 'activist', access_broker: 'criminal', influence_ops: 'unknown', unknown: 'unknown',
      };
      const sophisticationMap: Record<string, string> = {
        'nation-state': 'strategic', advanced: 'expert', intermediate: 'intermediate', basic: 'minimal',
      };
      const stixObjects: any[] = [];
      for (const a of actors) {
        const stixActor: any = {
          type: 'threat-actor',
          spec_version: '2.1',
          id: a.stixId || `threat-actor--${a.actorId}`,
          created: a.createdAt || new Date().toISOString(),
          modified: a.updatedAt || new Date().toISOString(),
          name: a.name,
          description: a.description || '',
          threat_actor_types: [typeMap[a.actorType || 'unknown'] || 'unknown'],
          aliases: safeParseArr(a.aliases),
          first_seen: a.firstSeen || undefined,
          last_seen: a.lastActive || undefined,
          roles: a.actorType === 'access_broker' ? ['agent'] : ['director'],
          goals: a.motivation ? [a.motivation] : [],
          sophistication: sophisticationMap[a.sophistication || 'intermediate'] || 'intermediate',
          resource_level: a.sophistication === 'nation-state' ? 'government' : a.sophistication === 'advanced' ? 'organization' : 'individual',
          primary_motivation: a.motivation || 'personal-gain',
          confidence: a.confidence || 50,
        };
        // Clean undefined values
        Object.keys(stixActor).forEach(k => { if (stixActor[k] === undefined) delete stixActor[k]; });
        stixObjects.push(stixActor);
        // Add attack-pattern objects for techniques
        const techniques = safeParseArr(a.techniques);
        for (const tech of techniques) {
          if (!tech.id) continue;
          stixObjects.push({
            type: 'attack-pattern',
            spec_version: '2.1',
            id: `attack-pattern--${tech.id}`,
            created: a.createdAt || new Date().toISOString(),
            modified: a.updatedAt || new Date().toISOString(),
            name: tech.name || tech.id,
            description: tech.description || '',
            external_references: [{ source_name: 'mitre-attack', external_id: tech.id }],
          });
          stixObjects.push({
            type: 'relationship',
            spec_version: '2.1',
            id: `relationship--${a.actorId}--uses--${tech.id}`,
            created: a.createdAt || new Date().toISOString(),
            modified: a.updatedAt || new Date().toISOString(),
            relationship_type: 'uses',
            source_ref: stixActor.id,
            target_ref: `attack-pattern--${tech.id}`,
          });
        }
      }
      const bundle = {
        type: 'bundle',
        id: `bundle--ac3-export-${Date.now()}`,
        objects: stixObjects,
      };
      return { stix: JSON.stringify(bundle, null, 2), actorCount: actors.length, objectCount: stixObjects.length };
    }),

});

// Helper: compute completeness percentage for an actor
function computeCompleteness(actor: any): number {
  if (!actor) return 0;
  const fields = [
    actor.description && actor.description !== 'unknown',
    actor.motivation && actor.motivation !== 'unknown',
    actor.origin && actor.origin !== 'unknown' && actor.origin !== 'Unknown',
    safeParseArr(actor.aliases).length > 0,
    safeParseArr(actor.targetSectors).length > 0,
    safeParseArr(actor.targetRegions).length > 0,
    safeParseArr(actor.techniques).length > 0,
    safeParseArr(actor.tools).length > 0,
    safeParseArr(actor.malware).length > 0,
    !!actor.firstSeen,
    !!actor.lastActive,
  ];
  const filled = fields.filter(Boolean).length;
  return Math.round((filled / fields.length) * 100);
}
