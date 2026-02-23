/**
 * AD Attack Path Graph Router
 * Provides endpoints for building and querying attack path graphs
 * from AD enumeration data.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const adAttackPathGraphRouter = router({
  /** Build attack graph from an AD environment's enumerated objects */
  buildGraph: protectedProcedure
    .input(z.object({
      environmentId: z.number(),
      sourceNodeId: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adObjects } = await import("../../drizzle/schema");
      const { buildAttackGraph } = await import("../lib/ad-attack-path-graph");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const objects = await db.select().from(adObjects).where(eq(adObjects.environmentId, input.environmentId));

      const users = objects.filter(o => o.objectType === "user");
      const groups = objects.filter(o => o.objectType === "group");
      const computers = objects.filter(o => o.objectType === "computer");
      const gpos = objects.filter(o => o.objectType === "gpo");
      const ous = objects.filter(o => o.objectType === "ou");
      const trusts = objects.filter(o => o.objectType === "trust");

      if (objects.length === 0) {
        return {
          nodes: [],
          edges: [],
          paths: [],
          stats: {
            totalNodes: 0, totalEdges: 0, highValueTargets: 0,
            compromisedNodes: 0, shortestPathToDA: null,
            totalAttackPaths: 0, avgPathLength: 0, maxRiskScore: 0,
          },
        };
      }

      return buildAttackGraph(users, groups, computers, gpos, ous, trusts, input.sourceNodeId);
    }),

  /** Find shortest path between two nodes */
  findPath: protectedProcedure
    .input(z.object({
      environmentId: z.number(),
      sourceNodeId: z.string(),
      targetNodeId: z.string(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adObjects } = await import("../../drizzle/schema");
      const { buildGraphFromADObjects, findShortestPath } = await import("../lib/ad-attack-path-graph");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const objects = await db.select().from(adObjects).where(eq(adObjects.environmentId, input.environmentId));
      const { nodes, edges } = buildGraphFromADObjects(
        objects.filter(o => o.objectType === "user"),
        objects.filter(o => o.objectType === "group"),
        objects.filter(o => o.objectType === "computer"),
        objects.filter(o => o.objectType === "gpo"),
        objects.filter(o => o.objectType === "ou"),
        objects.filter(o => o.objectType === "trust"),
      );

      const path = findShortestPath(nodes, edges, input.sourceNodeId, input.targetNodeId);
      return path;
    }),

  /** Get graph statistics for an environment */
  getStats: protectedProcedure
    .input(z.object({ environmentId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adObjects } = await import("../../drizzle/schema");
      const { eq, count } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [total] = await db.select({ count: count() }).from(adObjects).where(eq(adObjects.environmentId, input.environmentId));
      const [privileged] = await db.select({ count: count() }).from(adObjects).where(eq(adObjects.isPrivileged, true));

      return {
        totalObjects: total.count,
        privilegedObjects: privileged.count,
      };
    }),

  /** List available environments for graph building */
  listEnvironments: protectedProcedure
    .input(z.object({}).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { adEnvironments } = await import("../../drizzle/schema");
      const { desc } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      return db.select().from(adEnvironments).orderBy(desc(adEnvironments.createdAt));
    }),
});
