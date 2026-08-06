import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const attackPathDiscoveryRouter = router({
  listNodes: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { attackPathGraphNodes } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(attackPathGraphNodes).orderBy(desc(attackPathGraphNodes.createdAt));
  }),
  addNode: protectedProcedure
    .input(z.object({
      nodeType: z.enum(["user", "computer", "group", "service", "cloud_identity", "vulnerability", "crown_jewel"]),
      name: z.string(),
      properties: z.string().optional(),
      riskScore: z.number().optional(),
      isCrownJewel: z.boolean().optional(),
      source: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { attackPathGraphNodes } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(attackPathGraphNodes).values({ ...input });
      return { id: result[0].insertId };
    }),
  addEdge: protectedProcedure
    .input(z.object({
      sourceNodeId: z.number(),
      targetNodeId: z.number(),
      edgeType: z.string(),
      technique: z.string().optional(),
      probability: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { attackPathGraphEdges } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(attackPathGraphEdges).values({ ...input });
      return { id: result[0].insertId };
    }),
  discoverPaths: protectedProcedure
    .input(z.object({
      maxHops: z.number().optional(),
      maxPaths: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { attackPathGraphNodes, attackPathGraphEdges, discoveredAttackPaths } = await import("../../drizzle/schema");
      const { discoverAttackPaths } = await import("../lib/attack-path-discovery");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const rawNodes = await db.select().from(attackPathGraphNodes);
      const rawEdges = await db.select().from(attackPathGraphEdges);
      const nodes = rawNodes.map(n => ({ id: n.id, type: n.nodeType, name: n.name, riskScore: n.riskScore ?? 0, isCrownJewel: n.isCrownJewel ?? false, properties: typeof n.properties === 'string' ? JSON.parse(n.properties as string) : (n.properties as Record<string, any> || {}) }));
      const edges = rawEdges.map(e => ({ id: e.id, sourceNodeId: e.sourceNodeId, targetNodeId: e.targetNodeId, edgeType: e.edgeType, technique: e.technique ?? undefined, probability: e.probability ?? 0.5 }));

      const paths = await discoverAttackPaths(nodes, edges, input.maxHops, input.maxPaths);

      if (paths.length > 0) {
        const pathValues = paths.map((path: any) => ({
          name: path.name || "Discovered Path",
          pathNodes: path.pathNodes ? JSON.stringify(path.pathNodes) : "[]",
          pathEdges: path.pathEdges ? JSON.stringify(path.pathEdges) : "[]",
          totalHops: path.totalHops || 0,
          riskScore: path.riskScore || 0,
          chokePoints: path.chokePoints ? JSON.stringify(path.chokePoints) : "[]",
          status: "active" as const,
        }));
        await db.insert(discoveredAttackPaths).values(pathValues);
      }

      return { discovered: paths.length, paths };
    }),
  listDiscoveredPaths: protectedProcedure
    .input(z.object({ status: z.enum(["active", "mitigated", "accepted"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { discoveredAttackPaths } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");
      if (input.status) {
        return db.select().from(discoveredAttackPaths).where(eq(discoveredAttackPaths.status, input.status)).orderBy(desc(discoveredAttackPaths.discoveredAt));
      }
      return db.select().from(discoveredAttackPaths).orderBy(desc(discoveredAttackPaths.discoveredAt));
    }),
  updatePathStatus: protectedProcedure
    .input(z.object({
      id: z.number(),
      status: z.enum(["active", "mitigated", "accepted"]),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { discoveredAttackPaths } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(discoveredAttackPaths).set({ status: input.status }).where(eq(discoveredAttackPaths.id, input.id));
      return { success: true };
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { discoveredAttackPaths } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { eq, count, avg } = await import("drizzle-orm");
    const totalPaths = await db.select({ value: count() }).from(discoveredAttackPaths);
    const activePaths = await db.select({ value: count() }).from(discoveredAttackPaths).where(eq(discoveredAttackPaths.status, "active"));
    const avgRisk = await db.select({ value: avg(discoveredAttackPaths.riskScore) }).from(discoveredAttackPaths);
    return {
      totalPaths: totalPaths[0].value,
      activePaths: activePaths[0].value,
      avgRiskScore: Number(avgRisk[0].value || 0),
    };
  }),
});
