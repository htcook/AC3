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
  classificationAuditLog,
} from "../../drizzle/schema";
import * as schema from "../../drizzle/schema";
import { eq, sql, desc, and, like, inArray, gte } from "drizzle-orm";

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

      let actors: any[];
      let countResult: any[];
      try {
        [actors, countResult] = await Promise.all([
          db.select().from(threatActors).where(where).orderBy(order).limit(opts.pageSize || 50).offset(offset),
          db.select({ count: sql<number>`count(*)` }).from(threatActors).where(where),
        ]);
      } catch (err: any) {
        const cause = (err as any).cause || err;
        console.error('[threatIntel.list] DB error:', err.message);
        console.error('[threatIntel.list] Cause details:', JSON.stringify({
          causeName: cause?.name, causeCode: cause?.code, causeErrno: cause?.errno,
          causeSqlMessage: cause?.sqlMessage, causeSqlState: cause?.sqlState,
          causeMessage: cause?.message,
          errKeys: Object.keys(err),
          causeKeys: cause ? Object.keys(cause) : [],
          fullErr: String(err),
        }));
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `DB query failed: ${cause?.sqlMessage || cause?.message || err.message}`, cause: err });
      }

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
    .input(z.object({ threshold: z.number().min(0).max(100).default(60), limit: z.number().default(2000) }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const threshold = input?.threshold ?? 60;
      const limit = input?.limit ?? 2000;
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
      actorIds: z.array(z.string()).min(1).max(2000),
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

  // ─── Catalog Enrichment Scheduler ─────────────────────────────────
  catalogEnrichmentStatus: protectedProcedure
    .query(async () => {
      const { getCatalogEnrichmentStatus } = await import("../lib/catalog-enrichment-scheduler");
      return getCatalogEnrichmentStatus();
    }),

  catalogEnrichmentTrigger: protectedProcedure
    .input(z.object({
      batchSize: z.number().min(1).max(100).optional(),
      completenessThreshold: z.number().min(0).max(100).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { runCatalogEnrichment, isEnrichmentSchedulerRunning } = await import("../lib/catalog-enrichment-scheduler");
      if (isEnrichmentSchedulerRunning()) {
        throw new TRPCError({ code: "CONFLICT", message: "Enrichment is already running" });
      }
      // Run in background, return immediately
      const promise = runCatalogEnrichment("manual", input?.batchSize, input?.completenessThreshold);
      promise.catch(() => {}); // prevent unhandled rejection
      return { started: true, message: "Enrichment started in background" };
    }),

  catalogEnrichmentConfig: protectedProcedure
    .input(z.object({
      batchSize: z.number().min(1).max(100).optional(),
      completenessThreshold: z.number().min(0).max(100).optional(),
      cronHourUtc: z.number().min(0).max(23).optional(),
      cronMinuteUtc: z.number().min(0).max(59).optional(),
      enabled: z.boolean().optional(),
      discoveryEnabled: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { updateCatalogEnrichmentConfig } = await import("../lib/catalog-enrichment-scheduler");
      return updateCatalogEnrichmentConfig(input);
    }),

  // ─── Guardrail Threshold Tuning ──────────────────────────────────────
  guardrailConfig: protectedProcedure
    .query(async () => {
      const { GUARDRAIL_CONFIG } = await import("../lib/enrichment-guardrails");
      return {
        confidenceAcceptThreshold: GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD,
        confidenceRejectThreshold: GUARDRAIL_CONFIG.CONFIDENCE_REJECT_THRESHOLD,
        llmOnlyMinConfidence: GUARDRAIL_CONFIG.LLM_ONLY_MIN_CONFIDENCE,
        maxAliases: GUARDRAIL_CONFIG.MAX_ALIASES,
        maxTechniques: GUARDRAIL_CONFIG.MAX_TECHNIQUES,
        maxTools: GUARDRAIL_CONFIG.MAX_TOOLS,
        maxNotableAttacks: GUARDRAIL_CONFIG.MAX_NOTABLE_ATTACKS,
        maxTimelineEntries: GUARDRAIL_CONFIG.MAX_TIMELINE_ENTRIES,
        minDescriptionLength: GUARDRAIL_CONFIG.MIN_DESCRIPTION_LENGTH,
        mitreValidation: true,
        sourceCitationCheck: true,
        localDbCrossRef: true,
        suspiciousSourceDetection: true,
      };
    }),

  guardrailConfigUpdate: protectedProcedure
    .input(z.object({
      confidenceAcceptThreshold: z.number().min(0).max(100).optional(),
      confidenceRejectThreshold: z.number().min(0).max(100).optional(),
      llmOnlyMinConfidence: z.number().min(0).max(100).optional(),
      maxAliases: z.number().min(1).max(200).optional(),
      maxTechniques: z.number().min(1).max(200).optional(),
      maxTools: z.number().min(1).max(200).optional(),
      maxNotableAttacks: z.number().min(1).max(200).optional(),
      maxTimelineEntries: z.number().min(1).max(500).optional(),
      minDescriptionLength: z.number().min(0).max(500).optional(),
    }))
    .mutation(async ({ input }) => {
      const guardrails = await import("../lib/enrichment-guardrails");
      const config = guardrails.GUARDRAIL_CONFIG;
      if (input.confidenceAcceptThreshold !== undefined) config.CONFIDENCE_ACCEPT_THRESHOLD = input.confidenceAcceptThreshold;
      if (input.confidenceRejectThreshold !== undefined) config.CONFIDENCE_REJECT_THRESHOLD = input.confidenceRejectThreshold;
      if (input.llmOnlyMinConfidence !== undefined) config.LLM_ONLY_MIN_CONFIDENCE = input.llmOnlyMinConfidence;
      if (input.maxAliases !== undefined) config.MAX_ALIASES = input.maxAliases;
      if (input.maxTechniques !== undefined) config.MAX_TECHNIQUES = input.maxTechniques;
      if (input.maxTools !== undefined) config.MAX_TOOLS = input.maxTools;
      if (input.maxNotableAttacks !== undefined) config.MAX_NOTABLE_ATTACKS = input.maxNotableAttacks;
      if (input.maxTimelineEntries !== undefined) config.MAX_TIMELINE_ENTRIES = input.maxTimelineEntries;
      if (input.minDescriptionLength !== undefined) config.MIN_DESCRIPTION_LENGTH = input.minDescriptionLength;
      return {
        confidenceAcceptThreshold: config.CONFIDENCE_ACCEPT_THRESHOLD,
        confidenceRejectThreshold: config.CONFIDENCE_REJECT_THRESHOLD,
        llmOnlyMinConfidence: config.LLM_ONLY_MIN_CONFIDENCE,
        maxAliases: config.MAX_ALIASES,
        maxTechniques: config.MAX_TECHNIQUES,
        maxTools: config.MAX_TOOLS,
        maxNotableAttacks: config.MAX_NOTABLE_ATTACKS,
        maxTimelineEntries: config.MAX_TIMELINE_ENTRIES,
        minDescriptionLength: config.MIN_DESCRIPTION_LENGTH,
      };
    }),

  // ─── MITRE ATT&CK Navigator Layer Export ─────────────────────────────
  navigatorLayer: protectedProcedure
    .input(z.object({
      actorId: z.string().optional(),
      // If no actorId, use filters to generate multi-actor layer
      type: z.string().optional(),
      threatLevel: z.string().optional(),
      conflict: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      let actors: any[] = [];

      if (input.actorId) {
        // Single actor
        actors = await db.select().from(threatActors).where(eq(threatActors.actorId, input.actorId)).limit(1);
      } else {
        // Multi-actor based on filters
        const conditions: any[] = [];
        if (input.type) conditions.push(eq(threatActors.actorType, input.type));
        if (input.threatLevel) conditions.push(eq(threatActors.threatLevel, input.threatLevel));
        if (input.conflict) conditions.push(sql`JSON_SEARCH(${threatActors.conflicts}, 'one', ${input.conflict}) IS NOT NULL`);
        const query = conditions.length > 0
          ? db.select().from(threatActors).where(and(...conditions)).limit(500)
          : db.select().from(threatActors).limit(500);
        actors = await query;
      }

      // Build technique frequency map
      const techniqueMap = new Map<string, { count: number; actors: string[]; name?: string }>();

      for (const actor of actors) {
        let techniques: any[] = [];
        try {
          if (typeof actor.mitreTechniques === "string") techniques = JSON.parse(actor.mitreTechniques);
          else if (Array.isArray(actor.mitreTechniques)) techniques = actor.mitreTechniques;
        } catch {}

        // Also check techniques field
        if (techniques.length === 0) {
          try {
            const t = (actor as any).techniques;
            if (typeof t === "string") techniques = JSON.parse(t);
            else if (Array.isArray(t)) techniques = t;
          } catch {}
        }

        for (const tech of techniques) {
          const id = typeof tech === "string" ? tech : tech?.id || tech?.techniqueId || tech?.technique_id;
          const name = typeof tech === "string" ? undefined : tech?.name || tech?.technique_name;
          if (!id || typeof id !== "string") continue;
          // Normalize: ensure T prefix
          const normalizedId = id.match(/^T\d{4}/) ? id : null;
          if (!normalizedId) continue;

          const existing = techniqueMap.get(normalizedId);
          if (existing) {
            existing.count++;
            if (!existing.actors.includes(actor.name || actor.actorId)) {
              existing.actors.push(actor.name || actor.actorId);
            }
            if (name && !existing.name) existing.name = name;
          } else {
            techniqueMap.set(normalizedId, {
              count: 1,
              actors: [actor.name || actor.actorId],
              name,
            });
          }
        }
      }

      // Determine max count for color scaling
      const maxCount = Math.max(1, ...Array.from(techniqueMap.values()).map((t) => t.count));

      // Build Navigator layer JSON
      const techniques = Array.from(techniqueMap.entries()).map(([techId, data]) => {
        // Split technique and subtechnique
        const parts = techId.split(".");
        const tactic = parts[0];
        const subtechnique = parts.length > 1 ? techId : undefined;

        // Color intensity based on frequency (1=light, max=dark red)
        const intensity = data.count / maxCount;
        const r = Math.round(255);
        const g = Math.round(255 * (1 - intensity * 0.8));
        const b = Math.round(255 * (1 - intensity * 0.9));
        const color = `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;

        return {
          techniqueID: techId,
          tactic: undefined as string | undefined, // Navigator auto-maps
          color,
          comment: `Used by ${data.count} actor(s): ${data.actors.slice(0, 10).join(", ")}${data.actors.length > 10 ? ` (+${data.actors.length - 10} more)` : ""}`,
          score: data.count,
          enabled: true,
          metadata: [],
          links: [],
          showSubtechniques: parts.length === 1,
        };
      });

      const layerName = input.actorId
        ? `ATT&CK Coverage: ${actors[0]?.name || input.actorId}`
        : `ATT&CK Coverage: ${actors.length} Threat Actors${input.type ? ` (${input.type})` : ""}${input.threatLevel ? ` [${input.threatLevel}]` : ""}`;

      const layer = {
        name: layerName,
        versions: {
          attack: "15",
          navigator: "5.0.1",
          layer: "4.5",
        },
        domain: "enterprise-attack",
        description: `Generated by AC3 Threat Intelligence Platform on ${new Date().toISOString().split("T")[0]}. ` +
          `Covers ${actors.length} threat actor(s) with ${techniques.length} unique techniques mapped.`,
        filters: {
          platforms: [
            "Linux", "macOS", "Windows", "Network", "PRE",
            "Containers", "Office 365", "SaaS", "Google Workspace",
            "IaaS", "Azure AD",
          ],
        },
        sorting: 3, // Sort by score descending
        layout: {
          layout: "side",
          aggregateFunction: "average",
          showID: true,
          showName: true,
          showAggregateScores: true,
          countUnscored: false,
        },
        hideDisabled: false,
        techniques,
        gradient: {
          colors: ["#ffffff", "#ff6666", "#cc0000"],
          minValue: 0,
          maxValue: maxCount,
        },
        legendItems: [
          { label: "1 actor", color: "#ffcccc" },
          { label: `${Math.ceil(maxCount / 2)} actors`, color: "#ff6666" },
          { label: `${maxCount} actors`, color: "#cc0000" },
        ],
        metadata: [
          { name: "generated_by", value: "AC3 Threat Intelligence Platform" },
          { name: "generated_at", value: new Date().toISOString() },
          { name: "actor_count", value: String(actors.length) },
          { name: "technique_count", value: String(techniques.length) },
        ],
        showTacticRowBackground: true,
        tacticRowBackground: "#1a1a2e",
        selectTechniquesAcrossTactics: true,
        selectSubtechniquesWithParent: false,
      };

      return {
        layer: JSON.stringify(layer, null, 2),
        actorCount: actors.length,
        techniqueCount: techniques.length,
        layerName,
      };
    }),

  // ─── Threat Actor Discovery ──────────────────────────────────────────

  discoverActors: protectedProcedure
    .input(z.object({
      strategy: z.enum(["related_actors", "sector_gaps", "recent_campaigns", "emerging_threats", "geographic_coverage"]),
      seedActorNames: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { discoverNewActors } = await import("../lib/threat-actor-discovery");
      return discoverNewActors(input.strategy, input.seedActorNames);
    }),

  commitDiscoveredActor: protectedProcedure
    .input(z.object({
      actor: z.any(),
    }))
    .mutation(async ({ input }) => {
      const { commitDiscoveredActor } = await import("../lib/threat-actor-discovery");
      return commitDiscoveredActor(input.actor);
    }),

  bulkCommitDiscoveredActors: protectedProcedure
    .input(z.object({
      actors: z.array(z.any()),
    }))
    .mutation(async ({ input }) => {
      const { commitDiscoveredActor } = await import("../lib/threat-actor-discovery");
      const results = [];
      for (const actor of input.actors) {
        const result = await commitDiscoveredActor(actor);
        results.push(result);
      }
      return {
        total: results.length,
        succeeded: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        results,
      };
    }),

  // ─── Technique Heatmap ─────────────────────────────────────────────────
  techniqueHeatmap: protectedProcedure.query(async () => {
    const db = await requireDb();

    // MITRE ATT&CK Tactic mapping
    const TACTIC_MAP: Record<string, { id: string; name: string; order: number }> = {
      'reconnaissance': { id: 'TA0043', name: 'Reconnaissance', order: 0 },
      'resource-development': { id: 'TA0042', name: 'Resource Development', order: 1 },
      'initial-access': { id: 'TA0001', name: 'Initial Access', order: 2 },
      'execution': { id: 'TA0002', name: 'Execution', order: 3 },
      'persistence': { id: 'TA0003', name: 'Persistence', order: 4 },
      'privilege-escalation': { id: 'TA0004', name: 'Privilege Escalation', order: 5 },
      'defense-evasion': { id: 'TA0005', name: 'Defense Evasion', order: 6 },
      'credential-access': { id: 'TA0006', name: 'Credential Access', order: 7 },
      'discovery': { id: 'TA0007', name: 'Discovery', order: 8 },
      'lateral-movement': { id: 'TA0008', name: 'Lateral Movement', order: 9 },
      'collection': { id: 'TA0009', name: 'Collection', order: 10 },
      'command-and-control': { id: 'TA0011', name: 'Command and Control', order: 11 },
      'exfiltration': { id: 'TA0010', name: 'Exfiltration', order: 12 },
      'impact': { id: 'TA0040', name: 'Impact', order: 13 },
    };

    // Fetch all actors with techniques
    const actors = await db.select({
      actorId: threatActors.actorId,
      name: threatActors.name,
      techniques: threatActors.techniques,
    }).from(threatActors);

    // Aggregate technique usage
    const techniqueAgg: Record<string, {
      id: string;
      name: string;
      tactic: string;
      count: number;
      actors: string[];
    }> = {};

    let totalActorsWithTechniques = 0;

    for (const actor of actors) {
      const techniques = safeParseArr(actor.techniques);
      if (techniques.length === 0) continue;
      totalActorsWithTechniques++;

      for (const tech of techniques) {
        if (!tech.id) continue;
        const key = tech.id;
        if (!techniqueAgg[key]) {
          techniqueAgg[key] = {
            id: tech.id,
            name: tech.name || tech.id,
            tactic: (tech.tactic || 'unknown').toLowerCase().replace(/\s+/g, '-'),
            count: 0,
            actors: [],
          };
        }
        techniqueAgg[key].count++;
        if (techniqueAgg[key].actors.length < 20) {
          techniqueAgg[key].actors.push(actor.name);
        }
      }
    }

    // Group by tactic
    const tacticGroups: Record<string, typeof techniqueAgg[string][]> = {};
    for (const tech of Object.values(techniqueAgg)) {
      const tacticKey = tech.tactic;
      if (!tacticGroups[tacticKey]) tacticGroups[tacticKey] = [];
      tacticGroups[tacticKey].push(tech);
    }

    // Sort techniques within each tactic by count descending
    for (const key of Object.keys(tacticGroups)) {
      tacticGroups[key].sort((a, b) => b.count - a.count);
    }

    // Build ordered result
    const result = Object.entries(TACTIC_MAP)
      .sort((a, b) => a[1].order - b[1].order)
      .map(([key, meta]) => ({
        tacticId: meta.id,
        tacticKey: key,
        tacticName: meta.name,
        order: meta.order,
        techniques: (tacticGroups[key] || []).map(t => ({
          id: t.id,
          name: t.name,
          count: t.count,
          actors: t.actors,
        })),
        totalTechniques: (tacticGroups[key] || []).length,
        totalUsage: (tacticGroups[key] || []).reduce((s, t) => s + t.count, 0),
      }));

    // Compute max count for color scaling
    const allCounts = Object.values(techniqueAgg).map(t => t.count);
    const maxCount = allCounts.length > 0 ? Math.max(...allCounts) : 1;

    return {
      tactics: result,
      totalTechniques: Object.keys(techniqueAgg).length,
      totalActorsWithTechniques,
      totalActors: actors.length,
      maxCount,
    };
  }),

  // ─── Daily Run Summary (for dashboard widget) ─────────────────────────────
  dailyRunSummary: protectedProcedure.query(async () => {
    const db = await requireDb();
    const runs = await db.select().from(threatIntelUpdates)
      .orderBy(desc(threatIntelUpdates.tiuStartedAt))
      .limit(7);
    const latest = runs[0] || null;
    const last24h = runs.filter(r => {
      const started = new Date(r.tiuStartedAt).getTime();
      return Date.now() - started < 24 * 60 * 60 * 1000;
    });
    // Aggregate stats from recent events in last 24h
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const recentEvents = await db.select().from(threatGroupEvents)
      .where(gte(threatGroupEvents.eventDate, cutoff))
      .orderBy(desc(threatGroupEvents.eventDate))
      .limit(100);
    const criticalEvents = recentEvents.filter((e: any) => e.tgeSeverity === 'critical');
    const highEvents = recentEvents.filter((e: any) => e.tgeSeverity === 'high');
    return {
      latestRun: latest ? {
        status: latest.tiuStatus,
        startedAt: latest.tiuStartedAt,
        completedAt: latest.tiuCompletedAt,
        durationMs: latest.durationMs,
        groupsScanned: latest.groupsScanned,
        updatesApplied: latest.updatesApplied,
        newEventsFound: latest.newEventsFound,
        newIocsFound: latest.newIocsFound,
        newTtpsFound: latest.newTtpsFound,
        summary: latest.tiuSummary,
        details: latest.tiuDetails as any,
      } : null,
      runsLast7Days: runs.length,
      runsLast24h: last24h.length,
      eventsLast24h: recentEvents.length,
      criticalAlerts: criticalEvents.length,
      highAlerts: highEvents.length,
      topCritical: criticalEvents.slice(0, 3).map((e: any) => ({
        title: e.tgeTitle,
        actorId: e.tgeActorId,
        severity: e.tgeSeverity,
        date: e.eventDate,
      })),
      };
  }),

  // ─── Auto-Classification Engine ─────────────────────────────────────────────

  classifyProgress: protectedProcedure.query(async () => {
    const { getProgress } = await import("../lib/threat-actor-classifier");
    return getProgress();
  }),

  classifySingle: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { classifyActor } = await import("../lib/threat-actor-classifier");

      const [actor] = await db.select().from(threatActors)
        .where(eq(threatActors.actorId, input.actorId)).limit(1);
      if (!actor) throw new TRPCError({ code: "NOT_FOUND", message: "Actor not found" });

      const result = await classifyActor({
        actorId: actor.actorId,
        name: actor.name,
        description: actor.description,
        aliases: safeParseArr(actor.aliases),
        origin: actor.origin,
        motivation: actor.motivation,
        targetSectors: safeParseArr(actor.targetSectors),
        targetRegions: safeParseArr(actor.targetRegions),
        techniques: safeParseArr(actor.techniques),
        tools: safeParseArr(actor.tools),
        malware: safeParseArr(actor.malware),
        firstSeen: actor.firstSeen,
        lastActive: actor.lastActive,
        sophistication: actor.sophistication,
      });

      return result;
    }),

  classifyApply: protectedProcedure
    .input(z.object({ actorId: z.string(), classifiedType: z.enum(["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"]) }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(threatActors)
        .set({ actorType: input.classifiedType })
        .where(eq(threatActors.actorId, input.actorId));
      return { success: true };
    }),

  classifyBatchStart: protectedProcedure
    .input(z.object({
      targetType: z.enum(["unknown", "all"]).default("unknown"),
      batchSize: z.number().min(1).max(20).default(5),
      autoApplyThreshold: z.number().min(0).max(100).default(75),
      limit: z.number().min(1).max(2000).default(928),
    }).optional())
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { classifyBatch, resetProgress } = await import("../lib/threat-actor-classifier");
      const opts = input || { targetType: "unknown", batchSize: 5, autoApplyThreshold: 75, limit: 928 };

      // Get actors to classify
      const condition = opts.targetType === "unknown"
        ? eq(threatActors.actorType, "unknown")
        : undefined;

      const actors = await db.select().from(threatActors)
        .where(condition)
        .limit(opts.limit);

      if (actors.length === 0) {
        return { started: false, message: "No actors to classify" };
      }

      // Reset progress and start batch (non-blocking)
      resetProgress();

      const actorInputs = actors.map(a => ({
        actorId: a.actorId,
        name: a.name,
        description: a.description,
        aliases: safeParseArr(a.aliases),
        origin: a.origin,
        motivation: a.motivation,
        targetSectors: safeParseArr(a.targetSectors),
        targetRegions: safeParseArr(a.targetRegions),
        techniques: safeParseArr(a.techniques),
        tools: safeParseArr(a.tools),
        malware: safeParseArr(a.malware),
        firstSeen: a.firstSeen,
        lastActive: a.lastActive,
        sophistication: a.sophistication,
      }));

      // Fire and forget — progress tracked via classifyProgress
      classifyBatch(actorInputs, {
        batchSize: opts.batchSize,
        delayMs: 1500,
        autoApplyThreshold: opts.autoApplyThreshold,
        onResult: async (result) => {
          // Auto-apply high-confidence classifications
          if (result.confidence >= opts.autoApplyThreshold) {
            const db2 = await requireDb();
            await db2.update(threatActors)
              .set({ actorType: result.classifiedType as any })
              .where(eq(threatActors.actorId, result.actorId));
          }
        },
      }).catch(err => {
        console.error("[Classifier] Batch failed:", err);
      });

      return { started: true, total: actorInputs.length, message: `Classification started for ${actorInputs.length} actors` };
    }),

  classifyCancel: protectedProcedure.mutation(async () => {
    const { cancelBatch } = await import("../lib/threat-actor-classifier");
    cancelBatch();
    return { cancelled: true };
  }),

  classifyReview: protectedProcedure
    .input(z.object({ minConfidence: z.number().default(0), maxConfidence: z.number().default(74) }).optional())
    .query(async () => {
      const { getProgress } = await import("../lib/threat-actor-classifier");
      const progress = getProgress();
      // Return low-confidence results that need manual review
      const reviewItems = progress.results.filter(r => r.confidence < 75);
      return {
        items: reviewItems,
        total: reviewItems.length,
        batchStatus: progress.status,
      };
    }),

  classifyBulkApply: protectedProcedure
    .input(z.object({
      classifications: z.array(z.object({
        actorId: z.string(),
        classifiedType: z.enum(["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"]),
      }))
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      let applied = 0;
      for (const c of input.classifications) {
        await db.update(threatActors)
          .set({ actorType: c.classifiedType as any })
          .where(eq(threatActors.actorId, c.actorId));
        applied++;
      }
      return { applied };
    }),

  // ─── Classification Audit Log ─────────────────────────────────────────
  classifyAuditLog: protectedProcedure
    .input(z.object({
      actorId: z.string().optional(),
      source: z.string().optional(),
      method: z.string().optional(),
      batchId: z.string().optional(),
      limit: z.number().default(50),
      offset: z.number().default(0),
    }))
    .query(async ({ input }) => {
      const { queryAuditLog } = await import("../lib/threat-actor-classifier");
      return queryAuditLog(input);
    }),

  classifyAuditSummary: protectedProcedure
    .query(async () => {
      const { getAuditSummary } = await import("../lib/threat-actor-classifier");
      return getAuditSummary();
    }),

  classifyAuditRevert: protectedProcedure
    .input(z.object({ auditId: z.number(), actorId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      // Get the audit entry
      const [entry] = await db.select().from(schema.classificationAuditLog)
        .where(eq(schema.classificationAuditLog.id, input.auditId))
        .limit(1);
      if (!entry) throw new TRPCError({ code: 'NOT_FOUND', message: 'Audit entry not found' });

      // Revert the actor type
      await db.update(threatActors)
        .set({ actorType: entry.previousType as any })
        .where(eq(threatActors.actorId, input.actorId));

      // Mark the audit entry as reverted
      await db.update(schema.classificationAuditLog)
        .set({ wasReverted: 1, revertedAt: Date.now(), revertedBy: ctx.user?.name || 'admin' })
        .where(eq(schema.classificationAuditLog.id, input.auditId));

      // Log the revert action
      const { logManualClassificationAudit } = await import("../lib/threat-actor-classifier");
      await logManualClassificationAudit({
        actorId: input.actorId,
        actorName: entry.actorName || input.actorId,
        previousType: entry.newType,
        newType: entry.previousType,
        confidence: 100,
        reasoning: `Reverted classification from ${entry.newType} back to ${entry.previousType}`,
        appliedBy: ctx.user?.name || 'admin',
        method: 'revert',
      });

      return { success: true };
    }),

  // ─── Pipeline Status ──────────────────────────────────────────────────
  pipelineStatus: protectedProcedure
    .query(async () => {
      const { getAllPipelineStatuses } = await import("../lib/llm-context-updater");
      return getAllPipelineStatuses();
    }),

  pipelineHistory: protectedProcedure
    .input(z.object({ pipelineName: z.string().optional(), limit: z.number().default(20) }))
    .query(async ({ input }) => {
      const { getPipelineHistory } = await import("../lib/llm-context-updater");
      return getPipelineHistory(input.pipelineName, input.limit);
    }),

  // ─── Trigger Pipeline (manual run) ─────────────────────────────────────
  triggerPipeline: protectedProcedure
    .input(z.object({
      pipelineKey: z.enum(["dfir-ingest", "ioc-ttp-mapping", "catalog-enrichment", "playbook-promotion", "graph-generation", "exploit-triage"]),
    }))
    .mutation(async ({ input }) => {
      const { getPipelineStatus, markPipelineRunning } = await import("../lib/llm-context-updater");
      const status = getPipelineStatus(input.pipelineKey);
      if (status?.running) {
        throw new TRPCError({ code: "CONFLICT", message: `Pipeline ${input.pipelineKey} is already running` });
      }

      // Map pipeline keys to their scheduled endpoint paths
      const endpointMap: Record<string, string> = {
        'dfir-ingest': '/api/scheduled/dfir-bulk-ingest',
        'ioc-ttp-mapping': '/api/scheduled/ioc-ttp-mapping',
        'catalog-enrichment': '/api/scheduled/catalog-enrichment',
        'playbook-promotion': '/api/scheduled/playbook-promotion',
        'graph-generation': '/api/scheduled/graph-generation',
        'exploit-triage': '/api/scheduled/exploit-triage',
      };

      const endpoint = endpointMap[input.pipelineKey];
      if (!endpoint) throw new TRPCError({ code: "BAD_REQUEST", message: "Unknown pipeline" });

      // Fire-and-forget: call the local endpoint
      markPipelineRunning(input.pipelineKey);
      const port = process.env.PORT || 3000;
      fetch(`http://localhost:${port}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `caldera_session=${process.env.CALDERA_INTERNAL_TOKEN || ''}` },
        body: JSON.stringify({ triggeredBy: 'manual_dashboard' }),
      }).catch(err => {
        console.error(`[TriggerPipeline] Failed to call ${endpoint}:`, err.message);
      });

      return { triggered: true, pipelineKey: input.pipelineKey, message: `Pipeline ${input.pipelineKey} triggered successfully` };
    }),

  // ─── Force Refresh Actor LLM Context ───────────────────────────────────
  refreshActorContext: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .mutation(async ({ input }) => {
      const { refreshActorLLMContext } = await import("../lib/llm-context-updater");
      const result = await refreshActorLLMContext(input.actorId);

      // Also log to enrichment history
      try {
        const db = await getDb();
        if (db) {
          await db.insert(enrichmentHistory).values({
            actorId: input.actorId,
            actorName: input.actorId,
            triggeredBy: 'manual_refresh',
            fieldsUpdated: JSON.stringify(result.sourcesUsed),
            fieldsDiscovered: [],
            sourcesUsed: result.sourcesUsed,
            summary: `Manual LLM context refresh: ${result.contextLength} tokens from ${result.sourcesUsed.length} sources (${result.sourcesUsed.join(', ')})`,
            status: 'success',
            durationMs: 0,
          });
        }
      } catch (err: any) {
        console.error('[RefreshActorContext] Failed to log:', err.message);
      }

      return {
        success: true,
        contextLength: result.contextLength,
        sourcesUsed: result.sourcesUsed,
      };
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
