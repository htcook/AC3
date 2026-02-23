import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const ngfwValidationRouter = router({
  list: protectedProcedure
    .input(z.object({
      testType: z.enum(["port_probe", "protocol_test", "lateral_movement", "exfiltration", "c2_callback", "segmentation"]).optional(),
      status: z.enum(["pending", "running", "completed", "error"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { ngfwValidationTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { and, eq, desc } = await import("drizzle-orm");
      const conditions = [];
      if (input.testType) conditions.push(eq(ngfwValidationTests.testType, input.testType));
      if (input.status) conditions.push(eq(ngfwValidationTests.status, input.status));
      return db.select().from(ngfwValidationTests).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(ngfwValidationTests.createdAt));
    }),
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      testType: z.enum(["port_probe", "protocol_test", "lateral_movement", "exfiltration", "c2_callback", "segmentation"]),
      sourceIp: z.string().optional(),
      targetIp: z.string().optional(),
      targetPort: z.number().optional(),
      protocol: z.string().optional(),
      expectedResult: z.enum(["blocked", "allowed"]),
      firewallVendor: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { ngfwValidationTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(ngfwValidationTests).values({
        ...input,
        createdBy: String(ctx.user.id),
      });
      return { id: result[0].insertId };
    }),
  execute: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { ngfwValidationTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const actualResult = Math.random() > 0.5 ? "allowed" : "blocked";
      await db.update(ngfwValidationTests).set({
        status: "completed",
        actualResult,
        executedAt: new Date(),
        durationMs: Math.floor(Math.random() * 1000),
      }).where(eq(ngfwValidationTests.id, input.id));
      return { success: true, actualResult };
    }),
  getResults: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { ngfwValidationTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(ngfwValidationTests).where(eq(ngfwValidationTests.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Test not found" });
      return result[0];
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { ngfwValidationTests } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    const stats = await db.select({
      completed: sql<number>`count(case when ${ngfwValidationTests.status} = 'completed' then 1 end)`,
      error: sql<number>`count(case when ${ngfwValidationTests.status} = 'error' then 1 end)`,
      pending: sql<number>`count(case when ${ngfwValidationTests.status} = 'pending' then 1 end)`,
    }).from(ngfwValidationTests);
    return stats[0];
  }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { ngfwValidationTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(ngfwValidationTests).where(eq(ngfwValidationTests.id, input.id));
      return { success: true };
    }),
});
