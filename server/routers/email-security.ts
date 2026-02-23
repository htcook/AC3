import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const emailSecurityRouter = router({
  list: protectedProcedure
    .input(z.object({
      gatewayType: z.enum(["proofpoint", "mimecast", "defender", "barracuda", "custom"]).optional(),
      status: z.enum(["pending", "sent", "delivered", "blocked", "quarantined", "error"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { emailSecurityTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, and, eq } = await import("drizzle-orm");
      const filters = [];
      if (input.gatewayType) filters.push(eq(emailSecurityTests.gatewayType, input.gatewayType));
      if (input.status) filters.push(eq(emailSecurityTests.status, input.status));
      return db.select().from(emailSecurityTests).where(filters.length ? and(...filters) : undefined).orderBy(desc(emailSecurityTests.createdAt));
    }),
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      gatewayType: z.enum(["proofpoint", "mimecast", "defender", "barracuda", "custom"]),
      targetEmail: z.string(),
      payloadType: z.enum(["phishing_link", "malware_attachment", "credential_harvest", "bec_impersonation", "macro_doc"]),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { emailSecurityTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(emailSecurityTests).values({ ...input, createdBy: String(ctx.user.id) });
      return { id: result[0].insertId };
    }),
  execute: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { emailSecurityTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(emailSecurityTests).set({ status: "sent", sentAt: new Date() }).where(eq(emailSecurityTests.id, input.id));
      return { success: true };
    }),
  getResults: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { emailSecurityTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(emailSecurityTests).where(eq(emailSecurityTests.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Test not found" });
      return result[0];
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { emailSecurityTests } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { count, sql } = await import("drizzle-orm");
    const stats = await db.select({
      gateway: emailSecurityTests.gatewayType,
      result: emailSecurityTests.deliveryResult,
      total: count(emailSecurityTests.id),
    }).from(emailSecurityTests).groupBy(emailSecurityTests.gatewayType, emailSecurityTests.deliveryResult);
    return stats;
  }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { emailSecurityTests } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(emailSecurityTests).where(eq(emailSecurityTests.id, input.id));
      return { success: true };
    }),
});
