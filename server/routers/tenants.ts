import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const tenantRouter = router({
  listTenants: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { tenants } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(tenants).orderBy(desc(tenants.createdAt));
  }),
  createTenant: protectedProcedure
    .input(z.object({
      name: z.string(),
      slug: z.string(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
      plan: z.enum(["free", "pro", "enterprise"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenants } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(tenants).values({
        name: input.name,
        slug: input.slug,
        logoUrl: input.logoUrl,
        primaryColor: input.primaryColor,
        plan: input.plan,
      });
      return { id: result[0].insertId };
    }),
  updateTenant: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      slug: z.string().optional(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
      isActive: z.boolean().optional(),
      maxUsers: z.number().optional(),
      plan: z.enum(["free", "pro", "enterprise"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenants } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(tenants).set({
        name: input.name,
        slug: input.slug,
        logoUrl: input.logoUrl,
        primaryColor: input.primaryColor,
        isActive: input.isActive,
        maxUsers: input.maxUsers,
        plan: input.plan,
        updatedAt: new Date(),
      }).where(eq(tenants.id, input.id));
      return { success: true };
    }),
  deleteTenant: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenants } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(tenants).where(eq(tenants.id, input.id));
      return { success: true };
    }),
  listMembers: protectedProcedure
    .input(z.object({ tenantId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenantMemberships } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      return db.select().from(tenantMemberships).where(eq(tenantMemberships.tenantId, input.tenantId));
    }),
  addMember: protectedProcedure
    .input(z.object({
      tenantId: z.number(),
      userId: z.number(),
      role: z.enum(["owner", "admin", "operator", "viewer"]),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenantMemberships } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(tenantMemberships).values({
        tenantId: input.tenantId,
        userId: input.userId,
        role: input.role,
      });
      return { id: result[0].insertId };
    }),
  updateMemberRole: protectedProcedure
    .input(z.object({ id: z.number(), role: z.enum(["owner", "admin", "operator", "viewer"]) }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenantMemberships } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(tenantMemberships).set({ role: input.role }).where(eq(tenantMemberships.id, input.id));
      return { success: true };
    }),
  removeMember: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { tenantMemberships } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(tenantMemberships).where(eq(tenantMemberships.id, input.id));
      return { success: true };
    }),
  getMyTenants: protectedProcedure.query(async ({ ctx }) => {
    const { getDb } = await import("../db");
    const { tenants, tenantMemberships } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { eq } = await import("drizzle-orm");
    return db.select().from(tenants)
      .innerJoin(tenantMemberships, eq(tenants.id, tenantMemberships.tenantId))
      .where(eq(tenantMemberships.userId, ctx.user.id));
  }),
});
