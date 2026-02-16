/**
 * Campaign Archetype Router — manages archetype templates,
 * actor-specific auto-population, and archetype-to-campaign conversion.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { eq, and, sql } from "drizzle-orm";
import { getDb } from "../db";
import {
  campaignArchetypes,
  archetypeActorMappings,
  threatActors,
} from "../../drizzle/schema";
import {
  BUILT_IN_ARCHETYPES,
  computeActorArchetypeOverlap,
} from "../lib/campaign-archetypes";

// Safe JSON parse helper
function safeParseArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try { return JSON.parse(v); } catch { return []; }
  }
  return [];
}

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

function parseArchetype(r: any) {
  return {
    ...r,
    killChainPhases: safeParseArr(r.killChainPhases),
    defaultTechniques: safeParseArr(r.defaultTechniques),
    defaultAbilities: safeParseArr(r.defaultAbilities),
    targetPlatforms: safeParseArr(r.targetPlatforms),
    targetServices: safeParseArr(r.targetServices),
    prerequisites: safeParseArr(r.prerequisites),
  };
}

export const campaignArchetypeRouter = router({
  /**
   * List all archetypes (built-in + custom)
   */
  list: protectedProcedure
    .input(
      z.object({
        category: z.string().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await requireDb();
      let rows = await db.select().from(campaignArchetypes);

      if (input?.category) {
        rows = rows.filter((r) => r.category === input.category);
      }

      return rows.map(parseArchetype);
    }),

  /**
   * Get a single archetype by slug
   */
  getBySlug: protectedProcedure
    .input(z.object({ slug: z.string() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [row] = await db
        .select()
        .from(campaignArchetypes)
        .where(eq(campaignArchetypes.slug, input.slug));

      if (!row) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Archetype not found" });
      }

      return parseArchetype(row);
    }),

  /**
   * Seed / refresh built-in archetypes
   */
  seedBuiltIns: protectedProcedure.mutation(async () => {
    const db = await requireDb();
    let created = 0;
    let updated = 0;

    for (const arch of BUILT_IN_ARCHETYPES) {
      const [existing] = await db
        .select()
        .from(campaignArchetypes)
        .where(eq(campaignArchetypes.slug, arch.slug));

      if (existing) {
        await db
          .update(campaignArchetypes)
          .set({
            name: arch.name,
            category: arch.category as any,
            description: arch.description,
            killChainPhases: arch.killChainPhases,
            defaultTechniques: arch.defaultTechniques,
            defaultAbilities: arch.defaultAbilities,
            targetPlatforms: arch.targetPlatforms,
            targetServices: arch.targetServices,
            prerequisites: arch.prerequisites,
            detectionGuidance: arch.detectionGuidance,
            complexity: arch.complexity,
            isBuiltIn: true,
          })
          .where(eq(campaignArchetypes.id, existing.id));
        updated++;
      } else {
        await db.insert(campaignArchetypes).values({
          slug: arch.slug,
          name: arch.name,
          category: arch.category as any,
          description: arch.description,
          killChainPhases: arch.killChainPhases,
          defaultTechniques: arch.defaultTechniques,
          defaultAbilities: arch.defaultAbilities,
          targetPlatforms: arch.targetPlatforms,
          targetServices: arch.targetServices,
          prerequisites: arch.prerequisites,
          detectionGuidance: arch.detectionGuidance,
          complexity: arch.complexity,
          isBuiltIn: true,
        });
        created++;
      }
    }

    return { created, updated, total: BUILT_IN_ARCHETYPES.length };
  }),

  /**
   * Auto-populate an archetype with actor-specific techniques.
   */
  populateForActor: protectedProcedure
    .input(
      z.object({
        archetypeSlug: z.string(),
        actorId: z.string(),
      })
    )
    .query(async ({ input }) => {
      const db = await requireDb();

      // Get the archetype
      const [archetype] = await db
        .select()
        .from(campaignArchetypes)
        .where(eq(campaignArchetypes.slug, input.archetypeSlug));

      if (!archetype) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Archetype not found" });
      }

      // Get the actor
      const [actor] = await db
        .select()
        .from(threatActors)
        .where(eq(threatActors.actorId, input.actorId));

      if (!actor) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Actor not found" });
      }

      // Find the built-in archetype template for overlap computation
      const template = BUILT_IN_ARCHETYPES.find((a) => a.slug === input.archetypeSlug);
      if (!template) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Built-in archetype template not found" });
      }

      // Compute overlap
      const actorTechniques = safeParseArr(actor.techniques);
      const overlap = computeActorArchetypeOverlap(actorTechniques, template);

      // Check for existing mapping
      const [existingMapping] = await db
        .select()
        .from(archetypeActorMappings)
        .where(
          and(
            eq(archetypeActorMappings.archetypeId, archetype.id),
            eq(archetypeActorMappings.actorId, input.actorId)
          )
        );

      return {
        archetype: parseArchetype(archetype),
        actor: {
          actorId: actor.actorId,
          name: actor.name,
          type: actor.type,
          techniques: actorTechniques,
          tools: safeParseArr(actor.tools),
          malware: safeParseArr(actor.malware),
        },
        overlap: {
          matchedTechniques: overlap,
          matchCount: overlap.length,
          totalArchetypeTechniques: template.defaultTechniques.length,
          coveragePercent: Math.round(
            (overlap.length / template.defaultTechniques.length) * 100
          ),
        },
        existingMapping: existingMapping
          ? {
              id: existingMapping.id,
              confidence: existingMapping.confidence,
              actorTechniques: safeParseArr(existingMapping.actorTechniques),
            }
          : null,
      };
    }),

  /**
   * Save an actor-archetype mapping
   */
  saveActorMapping: protectedProcedure
    .input(
      z.object({
        archetypeId: z.number(),
        actorId: z.string(),
        actorTechniques: z.array(
          z.object({
            id: z.string(),
            name: z.string(),
            tactic: z.string(),
            actorScore: z.number(),
          })
        ),
        confidence: z.number().min(0).max(100).default(50),
        evidence: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await requireDb();

      // Check for existing mapping
      const [existing] = await db
        .select()
        .from(archetypeActorMappings)
        .where(
          and(
            eq(archetypeActorMappings.archetypeId, input.archetypeId),
            eq(archetypeActorMappings.actorId, input.actorId)
          )
        );

      if (existing) {
        await db
          .update(archetypeActorMappings)
          .set({
            actorTechniques: input.actorTechniques,
            confidence: input.confidence,
            evidence: input.evidence,
          })
          .where(eq(archetypeActorMappings.id, existing.id));
        return { id: existing.id, action: "updated" as const };
      }

      const [result] = await db.insert(archetypeActorMappings).values({
        archetypeId: input.archetypeId,
        actorId: input.actorId,
        actorTechniques: input.actorTechniques,
        confidence: input.confidence,
        evidence: input.evidence,
      });

      return { id: result.insertId, action: "created" as const };
    }),

  /**
   * Get all actor mappings for an archetype
   */
  getActorMappings: protectedProcedure
    .input(z.object({ archetypeId: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const mappings = await db
        .select()
        .from(archetypeActorMappings)
        .where(eq(archetypeActorMappings.archetypeId, input.archetypeId));

      return mappings.map((m) => ({
        ...m,
        actorTechniques: safeParseArr(m.actorTechniques),
        actorAbilities: safeParseArr(m.actorAbilities),
      }));
    }),

  /**
   * Get archetype categories with counts
   */
  categories: protectedProcedure.query(async () => {
    const db = await requireDb();
    const rows = await db
      .select({
        category: campaignArchetypes.category,
        count: sql<number>`count(*)`,
      })
      .from(campaignArchetypes)
      .groupBy(campaignArchetypes.category);

    return rows;
  }),

  /**
   * Create a custom archetype
   */
  create: protectedProcedure
    .input(
      z.object({
        slug: z.string().min(1),
        name: z.string().min(1),
        category: z.string(),
        description: z.string().optional(),
        killChainPhases: z.array(z.string()).optional(),
        defaultTechniques: z
          .array(z.object({ id: z.string(), name: z.string(), tactic: z.string() }))
          .optional(),
        defaultAbilities: z
          .array(
            z.object({
              abilityId: z.string(),
              name: z.string(),
              step: z.number(),
              description: z.string(),
            })
          )
          .optional(),
        targetPlatforms: z.array(z.string()).optional(),
        targetServices: z.array(z.string()).optional(),
        prerequisites: z.array(z.string()).optional(),
        detectionGuidance: z.string().optional(),
        complexity: z.enum(["low", "medium", "high", "expert"]).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await requireDb();
      const [result] = await db.insert(campaignArchetypes).values({
        slug: input.slug,
        name: input.name,
        category: input.category as any,
        description: input.description,
        killChainPhases: input.killChainPhases || [],
        defaultTechniques: input.defaultTechniques || [],
        defaultAbilities: input.defaultAbilities || [],
        targetPlatforms: input.targetPlatforms || [],
        targetServices: input.targetServices || [],
        prerequisites: input.prerequisites || [],
        detectionGuidance: input.detectionGuidance,
        complexity: input.complexity || "medium",
        isBuiltIn: false,
        createdBy: ctx.user.id,
      });

      return { id: result.insertId };
    }),
});
