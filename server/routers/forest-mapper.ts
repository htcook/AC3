/**
 * Multi-Domain Forest Mapping Router
 * Manages forest domains, trust relationships, and topology visualization.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const forestMapperRouter = router({
  /** List all forest domains */
  listDomains: protectedProcedure
    .input(z.object({
      forestName: z.string().optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestDomains } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.forestName) conditions.push(eq(forestDomains.forestName, input.forestName));
      if (input?.engagementId) conditions.push(eq(forestDomains.engagementId, input.engagementId));

      const domains = conditions.length > 0
        ? await db.select().from(forestDomains).where(and(...conditions)).orderBy(desc(forestDomains.createdAt))
        : await db.select().from(forestDomains).orderBy(desc(forestDomains.createdAt));

      return domains;
    }),

  /** Add a domain to the forest map */
  addDomain: protectedProcedure
    .input(z.object({
      forestName: z.string().min(1),
      domainName: z.string().min(1),
      connectionId: z.number().nullable().optional(),
      parentDomainId: z.number().nullable().optional(),
      engagementId: z.number().nullable().optional(),
      domainSid: z.string().nullable().optional(),
      domainFunctionalLevel: z.string().nullable().optional(),
      forestFunctionalLevel: z.string().nullable().optional(),
      isForestRoot: z.boolean().default(false),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestDomains } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(forestDomains).values({
        forestName: input.forestName,
        domainName: input.domainName,
        connectionId: input.connectionId || null,
        parentDomainId: input.parentDomainId || null,
        engagementId: input.engagementId || null,
        domainSid: input.domainSid || null,
        domainFunctionalLevel: input.domainFunctionalLevel || null,
        forestFunctionalLevel: input.forestFunctionalLevel || null,
        isForestRoot: input.isForestRoot,
      });

      return { id: result.insertId, success: true };
    }),

  /** Update domain stats after enumeration */
  updateDomainStats: protectedProcedure
    .input(z.object({
      domainId: z.number(),
      totalUsers: z.number().optional(),
      totalGroups: z.number().optional(),
      totalComputers: z.number().optional(),
      privilegedUsers: z.number().optional(),
      metadata: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestDomains } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const updates: Record<string, any> = { lastEnumeratedAt: new Date() };
      if (input.totalUsers !== undefined) updates.totalUsers = input.totalUsers;
      if (input.totalGroups !== undefined) updates.totalGroups = input.totalGroups;
      if (input.totalComputers !== undefined) updates.totalComputers = input.totalComputers;
      if (input.privilegedUsers !== undefined) updates.privilegedUsers = input.privilegedUsers;
      if (input.metadata) updates.metadata = input.metadata;

      await db.update(forestDomains).set(updates).where(eq(forestDomains.id, input.domainId));
      return { success: true };
    }),

  /** Delete a domain */
  deleteDomain: protectedProcedure
    .input(z.object({ domainId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestDomains, forestTrusts } = await import("../../drizzle/schema");
      const { eq, or } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Delete associated trusts
      await db.delete(forestTrusts).where(
        or(
          eq(forestTrusts.sourceDomainId, input.domainId),
          eq(forestTrusts.targetDomainId, input.domainId)
        )
      );
      await db.delete(forestDomains).where(eq(forestDomains.id, input.domainId));
      return { success: true };
    }),

  /** List all trust relationships */
  listTrusts: protectedProcedure
    .input(z.object({ domainId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestTrusts } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, or, desc } = await import("drizzle-orm");

      if (input?.domainId) {
        return db.select().from(forestTrusts).where(
          or(
            eq(forestTrusts.sourceDomainId, input.domainId),
            eq(forestTrusts.targetDomainId, input.domainId)
          )
        ).orderBy(desc(forestTrusts.createdAt));
      }
      return db.select().from(forestTrusts).orderBy(desc(forestTrusts.createdAt));
    }),

  /** Add a trust relationship */
  addTrust: protectedProcedure
    .input(z.object({
      sourceDomainId: z.number(),
      targetDomainId: z.number(),
      direction: z.enum(["inbound", "outbound", "bidirectional"]),
      trustType: z.enum(["parent_child", "tree_root", "shortcut", "forest", "external", "realm"]),
      isTransitive: z.boolean().default(true),
      sidFilteringEnabled: z.boolean().default(true),
      selectiveAuth: z.boolean().default(false),
      trustAttributes: z.number().default(0),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestTrusts } = await import("../../drizzle/schema");
      const { analyzeTrustVulnerabilities } = await import("../lib/forest-mapper");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Check for vulnerabilities
      const tempTrust = {
        id: 0,
        sourceDomainId: input.sourceDomainId,
        targetDomainId: input.targetDomainId,
        direction: input.direction,
        trustType: input.trustType,
        isTransitive: input.isTransitive,
        sidFilteringEnabled: input.sidFilteringEnabled,
        selectiveAuth: input.selectiveAuth,
        trustAttributes: input.trustAttributes,
        isVulnerable: false,
        vulnerabilityNotes: null,
      };
      const vulns = analyzeTrustVulnerabilities([tempTrust], []);
      const isVulnerable = vulns.length > 0;
      const vulnerabilityNotes = vulns.map(v => v.vulnerabilityType).join(", ") || null;

      const [result] = await db.insert(forestTrusts).values({
        sourceDomainId: input.sourceDomainId,
        targetDomainId: input.targetDomainId,
        trustDirection: input.direction,
        trustType: input.trustType,
        isTransitive: input.isTransitive,
        sidFilteringEnabled: input.sidFilteringEnabled,
        selectiveAuth: input.selectiveAuth,
        trustAttributes: input.trustAttributes,
        isVulnerable,
        vulnerabilityNotes,
      });

      return { id: result.insertId, isVulnerable, vulnerabilityNotes, success: true };
    }),

  /** Delete a trust */
  deleteTrust: protectedProcedure
    .input(z.object({ trustId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestTrusts } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(forestTrusts).where(eq(forestTrusts.id, input.trustId));
      return { success: true };
    }),

  /** Get full forest topology with vulnerability analysis */
  getTopology: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { forestDomains, forestTrusts } = await import("../../drizzle/schema");
      const { buildForestTopology, generateForestLayout } = await import("../lib/forest-mapper");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");

      const domains = input?.engagementId
        ? await db.select().from(forestDomains).where(eq(forestDomains.engagementId, input.engagementId)).orderBy(desc(forestDomains.createdAt))
        : await db.select().from(forestDomains).orderBy(desc(forestDomains.createdAt));

      const trusts = await db.select().from(forestTrusts);

      // Map DB rows to library types
      const mappedDomains = domains.map(d => ({
        id: d.id,
        forestName: d.forestName,
        domainName: d.domainName,
        connectionId: d.connectionId,
        parentDomainId: d.parentDomainId,
        domainSid: d.domainSid,
        domainFunctionalLevel: d.domainFunctionalLevel,
        forestFunctionalLevel: d.forestFunctionalLevel,
        isForestRoot: d.isForestRoot,
        totalUsers: d.totalUsers || 0,
        totalGroups: d.totalGroups || 0,
        totalComputers: d.totalComputers || 0,
        privilegedUsers: d.privilegedUsers || 0,
        lastEnumeratedAt: d.lastEnumeratedAt,
        metadata: d.metadata as Record<string, any> | null,
        engagementId: d.engagementId,
      }));

      const mappedTrusts = trusts.map(t => ({
        id: t.id,
        sourceDomainId: t.sourceDomainId,
        targetDomainId: t.targetDomainId,
        direction: t.trustDirection as "inbound" | "outbound" | "bidirectional",
        trustType: t.trustType as "parent_child" | "tree_root" | "shortcut" | "forest" | "external" | "realm",
        isTransitive: t.isTransitive,
        sidFilteringEnabled: t.sidFilteringEnabled,
        selectiveAuth: t.selectiveAuth,
        trustAttributes: t.trustAttributes || 0,
        isVulnerable: t.isVulnerable,
        vulnerabilityNotes: t.vulnerabilityNotes,
      }));

      const topology = buildForestTopology(mappedDomains, mappedTrusts);
      const layout = generateForestLayout(topology);

      return { ...topology, layout };
    }),

  /** Get forest stats */
  getStats: protectedProcedure
    .input(z.object({}).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { forestDomains, forestTrusts } = await import("../../drizzle/schema");
      const { count, eq, sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [domainCount] = await db.select({ count: count() }).from(forestDomains);
      const [trustCount] = await db.select({ count: count() }).from(forestTrusts);
      const [vulnerableTrustCount] = await db.select({ count: count() }).from(forestTrusts).where(eq(forestTrusts.isVulnerable, true));
      const [userSum] = await db.select({ total: sql<number>`COALESCE(SUM(${forestDomains.totalUsers}), 0)` }).from(forestDomains);

      // Count distinct forests
      const forests = await db.selectDistinct({ forestName: forestDomains.forestName }).from(forestDomains);

      return {
        totalForests: forests.length,
        totalDomains: domainCount.count,
        totalTrusts: trustCount.count,
        vulnerableTrusts: vulnerableTrustCount.count,
        totalUsers: userSum.total || 0,
      };
    }),
});
