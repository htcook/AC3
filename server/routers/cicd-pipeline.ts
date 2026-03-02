import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const cicdPipelineRouter = router({
  listPipelines: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { cicdPipelines } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(cicdPipelines).orderBy(desc(cicdPipelines.createdAt));
  }),
  createPipeline: protectedProcedure
    .input(z.object({
      name: z.string(),
      provider: z.enum(["github_actions", "jenkins", "gitlab_ci", "azure_devops", "custom"]),
      webhookUrl: z.string().optional(),
      triggerOn: z.enum(["push", "pull_request", "release", "manual", "schedule"]).optional(),
      failThreshold: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(cicdPipelines).values({ ...input, createdBy: String(ctx.user.id) });
      return { id: result[0].insertId };
    }),
  updatePipeline: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      webhookUrl: z.string().optional(),
      triggerOn: z.enum(["push", "pull_request", "release", "manual", "schedule"]).optional(),
      isActive: z.boolean().optional(),
      failThreshold: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { id, ...updates } = input;
      await db.update(cicdPipelines).set(updates as any).where(eq(cicdPipelines.id, id));
      return { success: true };
    }),
  deletePipeline: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(cicdPipelines).where(eq(cicdPipelines.id, input.id));
      return { success: true };
    }),
  listRuns: protectedProcedure
    .input(z.object({ pipelineId: z.number().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");
      if (input.pipelineId) {
        return db.select().from(cicdRuns).where(eq(cicdRuns.pipelineId, input.pipelineId)).orderBy(desc(cicdRuns.createdAt));
      }
      return db.select().from(cicdRuns).orderBy(desc(cicdRuns.createdAt));
    }),
  triggerRun: protectedProcedure
    .input(z.object({ pipelineId: z.number(), commitSha: z.string().optional(), branch: z.string().optional() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(cicdRuns).values({ ...input, status: "pending" });
      return { id: result[0].insertId };
    }),
  getRunDetails: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const run = await db.select().from(cicdRuns).where(eq(cicdRuns.id, input.runId));
      if (!run[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Run not found" });
      return run[0];
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { cicdRuns, cicdPipelines } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { count, sql } = await import("drizzle-orm");
    const totalPipelines = await db.select({ value: count() }).from(cicdPipelines);
    const totalRuns = await db.select({ value: count() }).from(cicdRuns);
    return {
      totalPipelines: totalPipelines[0].value,
      totalRuns: totalRuns[0].value,
    };
  }),
});
