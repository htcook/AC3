/**
 * Active Directory Attack Simulation Router
 * Manages AD environments, object enumeration, attack simulations,
 * and attack path discovery (Kerberoasting, DCSync, Golden Ticket, etc.)
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  FULL_AD_CATALOG,
  KERBEROS_ATTACKS,
  CREDENTIAL_ATTACKS,
  PERSISTENCE_ATTACKS,
  DELEGATION_ATTACKS,
  getADMitreTechniques,
} from "../lib/ad-attack-engine";

const adAttackTypeEnum = z.enum([
  "kerberoasting", "as_rep_roasting", "dcsync",
  "golden_ticket", "silver_ticket", "pass_the_hash",
  "pass_the_ticket", "overpass_the_hash", "skeleton_key",
  "dcshadow", "sid_history_injection", "gpo_abuse",
  "certificate_abuse", "constrained_delegation", "unconstrained_delegation",
  "resource_based_constrained_delegation", "ad_enumeration"
]);

export const adAttackSimRouter = router({
  /** Get the full AD attack catalog */
  getCatalog: protectedProcedure
    .input(z.object({ category: z.string().optional() }).optional())
    .query(({ input }) => {
      const category = input?.category;
      const categoryMap: Record<string, typeof FULL_AD_CATALOG> = {
        kerberos: KERBEROS_ATTACKS,
        credential: CREDENTIAL_ATTACKS,
        persistence: PERSISTENCE_ATTACKS,
        delegation: DELEGATION_ATTACKS,
      };
      const attacks = category && categoryMap[category] ? categoryMap[category] : FULL_AD_CATALOG;
      const cats = Array.from(new Set(FULL_AD_CATALOG.map((a) => a.attackType)));
      return {
        attacks,
        total: attacks.length,
        mitreTechniques: getADMitreTechniques(),
        categories: cats,
      };
    }),

  /** Get prerequisites for a specific attack */
  getPrerequisites: protectedProcedure
    .input(z.object({ attackId: z.string() }))
    .query(({ input }) => {
      const attack = FULL_AD_CATALOG.find((a: { id: string }) => a.id === input.attackId);
      if (!attack) throw new TRPCError({ code: "NOT_FOUND", message: "Attack not found" });
      return attack;
    }),

  /** List AD environments */
  listEnvironments: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adEnvironments } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input?.engagementId
        ? db.select().from(adEnvironments).where(eq(adEnvironments.engagementId, input.engagementId))
        : db.select().from(adEnvironments);
      return await query;
    }),

  /** Add an AD environment */
  addEnvironment: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      domainName: z.string(),
      domainController: z.string().optional(),
      forestName: z.string().optional(),
      functionalLevel: z.string().optional(),
      connectionConfig: z.any().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate domain controller and domain are in scope ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.domainName, "AD Environment Registration", ctx);
        if (input.domainController) {
          await enforceTargetScope(input.engagementId, input.domainController, "AD Domain Controller", ctx);
        }
      }
      const { getDb } = await import("../db");
      const { adEnvironments } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(adEnvironments).values({
        engagementId: input.engagementId ?? null,
        domainName: input.domainName,
        domainController: input.domainController ?? null,
        forestName: input.forestName ?? null,
        functionalLevel: input.functionalLevel ?? null,
        connectionConfig: input.connectionConfig ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List AD objects in an environment */
  listObjects: protectedProcedure
    .input(z.object({
      environmentId: z.number(),
      objectType: z.enum(["user", "group", "computer", "gpo", "ou", "trust", "spn", "certificate_template"]).optional(),
      privilegedOnly: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adObjects } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and } = await import("drizzle-orm");

      const conditions = [eq(adObjects.environmentId, input.environmentId)];
      if (input.objectType) conditions.push(eq(adObjects.objectType, input.objectType));
      if (input.privilegedOnly) conditions.push(eq(adObjects.isPrivileged, true));

      return await db.select().from(adObjects).where(and(...conditions));
    }),

  /** List attack simulations */
  listSimulations: protectedProcedure
    .input(z.object({
      environmentId: z.number().optional(),
      engagementId: z.number().optional(),
      attackType: adAttackTypeEnum.optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adAttackSimulations } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input.environmentId) conditions.push(eq(adAttackSimulations.environmentId, input.environmentId));
      if (input.engagementId) conditions.push(eq(adAttackSimulations.engagementId, input.engagementId));
      if (input.attackType) conditions.push(eq(adAttackSimulations.attackType, input.attackType));

      const sims = conditions.length > 0
        ? await db.select().from(adAttackSimulations).where(and(...conditions)).orderBy(desc(adAttackSimulations.createdAt))
        : await db.select().from(adAttackSimulations).orderBy(desc(adAttackSimulations.createdAt));
      return sims;
    }),

  /** Create an attack simulation */
  createSimulation: protectedProcedure
    .input(z.object({
      environmentId: z.number(),
      engagementId: z.number().optional(),
      attackType: adAttackTypeEnum,
      targetObject: z.string().optional(),
      sourceObject: z.string().optional(),
      description: z.string().optional(),
      riskScore: z.number().optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      mitreTechniques: z.any().optional(),
      prerequisites: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adAttackSimulations } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(adAttackSimulations).values({
        environmentId: input.environmentId,
        engagementId: input.engagementId ?? null,
        attackType: input.attackType,
        targetObject: input.targetObject ?? null,
        sourceObject: input.sourceObject ?? null,
        description: input.description ?? null,
        riskScore: input.riskScore ?? null,
        severity: input.severity ?? "high",
        mitreTechniques: input.mitreTechniques ?? null,
        prerequisites: input.prerequisites ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List attack paths */
  listAttackPaths: protectedProcedure
    .input(z.object({ environmentId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adAttackPaths } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");

      return await db.select().from(adAttackPaths)
        .where(eq(adAttackPaths.environmentId, input.environmentId))
        .orderBy(desc(adAttackPaths.riskScore));
    }),

  /** Get AD attack statistics */
  getStats: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { adEnvironments, adObjects, adAttackSimulations, adAttackPaths } = await import("../../drizzle/schema");
      const { count } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [envCount] = await db.select({ count: count() }).from(adEnvironments);
      const [objCount] = await db.select({ count: count() }).from(adObjects);
      const [simCount] = await db.select({ count: count() }).from(adAttackSimulations);
      const [pathCount] = await db.select({ count: count() }).from(adAttackPaths);

      return {
        totalEnvironments: envCount.count,
        totalObjects: objCount.count,
        totalSimulations: simCount.count,
        totalAttackPaths: pathCount.count,
        catalogSize: FULL_AD_CATALOG.length,
      };
    }),
});
