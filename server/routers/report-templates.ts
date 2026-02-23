import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const reportTemplatesRouter = router({
  list: protectedProcedure
    .input(z.object({ templateType: z.enum(["engagement", "executive", "compliance", "vulnerability", "custom"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq } = await import("drizzle-orm");
      if (input.templateType) {
        return db.select().from(reportTemplates).where(eq(reportTemplates.templateType, input.templateType)).orderBy(desc(reportTemplates.createdAt));
      }
      return db.select().from(reportTemplates).orderBy(desc(reportTemplates.createdAt));
    }),
  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      return result[0];
    }),
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string().optional(),
      templateType: z.enum(["engagement", "executive", "compliance", "vulnerability", "custom"]),
      templateContent: z.string(),
      headerHtml: z.string().optional(),
      footerHtml: z.string().optional(),
      cssOverrides: z.string().optional(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(reportTemplates).values({ ...input, createdBy: String(ctx.user.id) });
      return { id: result[0].insertId };
    }),
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      description: z.string().optional(),
      templateContent: z.string().optional(),
      headerHtml: z.string().optional(),
      footerHtml: z.string().optional(),
      cssOverrides: z.string().optional(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
      isDefault: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { id, ...updates } = input;
      await db.update(reportTemplates).set(updates).where(eq(reportTemplates.id, id));
      return { success: true };
    }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(reportTemplates).where(eq(reportTemplates.id, input.id));
      return { success: true };
    }),
  duplicate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const original = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!original[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      const { id: _id, createdAt: _ca, updatedAt: _ua, ...rest } = original[0];
      const result = await db.insert(reportTemplates).values({
        ...rest,
        name: `${rest.name} (Copy)`,
        isDefault: false,
        createdBy: String(ctx.user.id),
      });
      return { id: result[0].insertId };
    }),
  renderPreview: protectedProcedure
    .input(z.object({ id: z.number(), sampleData: z.record(z.string(), z.any()) }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const template = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!template[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      let renderedContent = template[0].templateContent;
      for (const key in input.sampleData) {
        const value = input.sampleData[key];
        renderedContent = renderedContent.replace(new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, "g"), String(value));
      }
      return { html: renderedContent };
    }),
});
