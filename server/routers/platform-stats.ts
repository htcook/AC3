import { TRPCError } from "@trpc/server";
import { publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { count, max, min, not, or } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const platformStatsRouter = router({
    getHomepageStats: publicProcedure.query(async () => {
      const { getCatalogStats } = await import('../lib/exploit-catalog');
      const catalogStats = await getCatalogStats();

      // Threat actors count from DB
      const threatActorCount = await db.getThreatActorCount();

      // Caldera abilities count (from catalog or live API)
      const calderaAbilities = catalogStats.bySource['caldera_stockpile'] || 0;

      // Metasploit modules count (from catalog)
      const metasploitModules = catalogStats.bySource['metasploit'] || 0;

      // Phishing exploits count (from catalog)
      const phishingExploits = catalogStats.bySource['phishing_library'] || 0;

      // Platform modules count — 8 nav groups × ~4 sub-sections each
      const platformModules = 32;

      return {
        exploitCatalogTotal: catalogStats.total,
        metasploitModules,
        calderaAbilities,
        threatActors: threatActorCount,
        phishingExploits,
        platformModules,
        byTier: catalogStats.byTier,
        bySource: catalogStats.bySource,
        byCategory: catalogStats.byCategory,
        calderaSynced: catalogStats.calderaSynced,
        withStagers: catalogStats.withStagers,
        lastUpdated: Date.now(),
      };
    }),
    // Public feed of recent threat actors for homepage (limited fields, no sensitive data)
    recentThreatActors: publicProcedure
      .input(z.object({ limit: z.number().min(1).max(50).default(20) }).optional())
      .query(async ({ input }) => {
        const limit = input?.limit ?? 20;
        const result = await db.listThreatActors({ limit, offset: 0 });
        // Return only safe public fields — no calderaProfile, no stixId, no internal IDs
        return {
          actors: result.actors.map(a => ({
            actorId: a.actorId,
            name: a.name,
            type: a.type,
            origin: a.origin,
            threatLevel: a.threatLevel,
            sophistication: a.sophistication,
            motivation: a.motivation,
            firstSeen: a.firstSeen,
            lastActive: a.lastActive,
            description: a.description,
            aliases: a.aliases,
            targetSectors: a.targetSectors,
            targetRegions: a.targetRegions,
            techniques: a.techniques,
            tools: a.tools,
            malware: a.malware,
          })),
          total: result.total,
        };
      }),
    // Public single threat actor detail for homepage modal (limited fields)
    publicActorDetail: publicProcedure
      .input(z.object({ actorId: z.string() }))
      .query(async ({ input }) => {
        const a = await db.getThreatActor(input.actorId);
        if (!a) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        return {
          actorId: a.actorId,
          name: a.name,
          type: a.type,
          origin: a.origin,
          threatLevel: a.threatLevel,
          sophistication: a.sophistication,
          motivation: a.motivation,
          firstSeen: a.firstSeen,
          lastActive: a.lastActive,
          description: a.description,
          aliases: a.aliases,
          targetSectors: a.targetSectors,
          targetRegions: a.targetRegions,
          techniques: a.techniques,
          tools: a.tools,
          malware: a.malware,
          activityTimeline: a.activityTimeline,
        };
      }),
  });
