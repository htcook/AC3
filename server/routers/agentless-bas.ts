import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const agentlessBASRouter = router({
  list: protectedProcedure
    .input(z.object({
      status: z.enum(["pending", "running", "completed", "failed"]).optional(),
      testType: z.enum(["cloud_api", "network_probe", "email_payload", "dns_exfil", "http_c2_sim"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { agentlessBASTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, and, eq } = await import("drizzle-orm");
      const conditions = [];
      if (input.status) conditions.push(eq(agentlessBASTests.status, input.status));
      if (input.testType) conditions.push(eq(agentlessBASTests.testType, input.testType));
      return db.select().from(agentlessBASTests)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(agentlessBASTests.createdAt));
    }),
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      testType: z.enum(["cloud_api", "network_probe", "email_payload", "dns_exfil", "http_c2_sim"]),
      targetDescription: z.string().optional(),
      techniqueId: z.string().optional(),
      techniqueName: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { agentlessBASTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(agentlessBASTests).values({
        ...input,
        createdBy: String(ctx.user.id),
      });
      return { id: result[0].insertId };
    }),
  execute: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { agentlessBASTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(agentlessBASTests).set({ status: "running", executedAt: new Date() }).where(eq(agentlessBASTests.id, input.id));
      // Simulate
      const blocked = Math.random() > 0.3;
      const resultVal = blocked ? ("blocked" as const) : ("missed" as const);
      await db.update(agentlessBASTests).set({
        status: "completed",
        result: resultVal,
        resultDetails: blocked ? "Control blocked the simulated attack" : "Simulated attack was not detected",
        durationMs: Math.floor(Math.random() * 5000 + 500),
      }).where(eq(agentlessBASTests.id, input.id));
      return { success: true, result: resultVal };
    }),
  getResults: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { agentlessBASTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(agentlessBASTests).where(eq(agentlessBASTests.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Test not found" });
      return result[0];
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { agentlessBASTests } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    const stats = await db.select({
      status: agentlessBASTests.status,
      total: sql<number>`count(*)`,
    }).from(agentlessBASTests).groupBy(agentlessBASTests.status);
    return stats;
  }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { agentlessBASTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(agentlessBASTests).where(eq(agentlessBASTests.id, input.id));
      return { success: true };
    }),
});
