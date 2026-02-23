import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const riskTrendingRouter = router({
  listSnapshots: protectedProcedure
    .input(z.object({
      limit: z.number().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { riskTrendSnapshots } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, and, gte, lte } = await import("drizzle-orm");
      const conditions = [];
      if (input.startDate) conditions.push(gte(riskTrendSnapshots.snapshotDate, new Date(input.startDate)));
      if (input.endDate) conditions.push(lte(riskTrendSnapshots.snapshotDate, new Date(input.endDate)));
      return db.select().from(riskTrendSnapshots)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(riskTrendSnapshots.snapshotDate))
        .limit(input.limit ?? 100);
    }),
  createSnapshot: protectedProcedure
    .input(z.object({
      overallScore: z.number(),
      detectionCoveragePercent: z.number().optional(),
      preventionCoveragePercent: z.number().optional(),
      criticalVulnCount: z.number().optional(),
      openFindingsCount: z.number().optional(),
      meanTimeToDetectMs: z.number().optional(),
      meanTimeToRespondMs: z.number().optional(),
      tacticScores: z.string().optional(),
      source: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { riskTrendSnapshots } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(riskTrendSnapshots).values({
        snapshotDate: new Date(),
        ...input,
      });
      return { id: result[0].insertId };
    }),
  getLatest: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { riskTrendSnapshots } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    const result = await db.select().from(riskTrendSnapshots).orderBy(desc(riskTrendSnapshots.snapshotDate)).limit(1);
    return result[0] || null;
  }),
  getTrend: protectedProcedure
    .input(z.object({ days: z.number().default(30) }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { riskTrendSnapshots } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, gte } = await import("drizzle-orm");
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - input.days);
      return db.select().from(riskTrendSnapshots)
        .where(gte(riskTrendSnapshots.snapshotDate, startDate))
        .orderBy(desc(riskTrendSnapshots.snapshotDate));
    }),
  deleteSnapshot: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { riskTrendSnapshots } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(riskTrendSnapshots).where(eq(riskTrendSnapshots.id, input.id));
      return { success: true };
    }),
});
