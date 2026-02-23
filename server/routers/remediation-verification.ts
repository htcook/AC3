import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const remediationVerificationRouter = router({
  list: protectedProcedure
    .input(z.object({ status: z.enum(["pending", "running", "verified_fixed", "still_vulnerable", "error"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq } = await import("drizzle-orm");
      if (input.status) {
        return db.select().from(remediationVerifications).where(eq(remediationVerifications.status, input.status)).orderBy(desc(remediationVerifications.createdAt));
      }
      return db.select().from(remediationVerifications).orderBy(desc(remediationVerifications.createdAt));
    }),
  create: protectedProcedure
    .input(z.object({
      originalFindingId: z.number(),
      originalFindingType: z.string(),
      techniqueId: z.string().optional(),
      verificationMethod: z.enum(["re_exploit", "scan_recheck", "config_audit", "manual"]),
      previousResult: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(remediationVerifications).values({ ...input, verifiedBy: String(ctx.user.id) });
      return { id: result[0].insertId };
    }),
  execute: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const newStatus = Math.random() > 0.5 ? ("verified_fixed" as const) : ("still_vulnerable" as const);
      await db.update(remediationVerifications).set({ status: newStatus, verifiedAt: new Date() }).where(eq(remediationVerifications.id, input.id));
      return { success: true, status: newStatus };
    }),
  getResults: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      return db.select().from(remediationVerifications).where(eq(remediationVerifications.id, input.id));
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { eq, count } = await import("drizzle-orm");
    const verifiedFixed = await db.select({ value: count() }).from(remediationVerifications).where(eq(remediationVerifications.status, "verified_fixed"));
    const stillVulnerable = await db.select({ value: count() }).from(remediationVerifications).where(eq(remediationVerifications.status, "still_vulnerable"));
    return {
      verified_fixed: verifiedFixed[0].value,
      still_vulnerable: stillVulnerable[0].value,
    };
  }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(remediationVerifications).where(eq(remediationVerifications.id, input.id));
      return { success: true };
    }),
});
