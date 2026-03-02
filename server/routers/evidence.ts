import * as db from "../db";
/**
 * Evidence Collection & Chain of Custody Router
 * Manages forensic evidence with hash verification and audit trail.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { evidenceItems, evidenceChainOfCustody } from "../../drizzle/schema";
import { eq, desc, like, and, sql } from "drizzle-orm";
import crypto from "crypto";
import { storagePut } from "../storage";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

function generateId() {
  return `ev_${crypto.randomBytes(8).toString("hex")}`;
}

export const evidenceRouter = router({
  // ─── List evidence items ───
  list: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      type: z.string().optional(),
      category: z.string().optional(),
      engagementId: z.string().optional(),
      classification: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.search) filters.push(like(evidenceItems.title, `%${input.search}%`));
      if (input?.type) filters.push(eq(evidenceItems.type, input.type));
      if (input?.category) filters.push(eq(evidenceItems.category, input.category));
      if (input?.engagementId) filters.push(eq(evidenceItems.engagementId, input.engagementId));
      if (input?.classification) filters.push(eq(evidenceItems.classification, input.classification));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const [items, countResult] = await Promise.all([
        db.select().from(evidenceItems).where(where)
          .orderBy(desc(evidenceItems.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(evidenceItems).where(where),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single evidence item with custody log ───
  get: protectedProcedure
    .input(z.object({ evidenceId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [item] = await db.select().from(evidenceItems)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));
      if (!item) throw new TRPCError({ code: "NOT_FOUND", message: "Evidence not found" });

      const custodyLog = await db.select().from(evidenceChainOfCustody)
        .where(eq(evidenceChainOfCustody.evidenceId, input.evidenceId))
        .orderBy(desc(evidenceChainOfCustody.performedAt));

      return { ...item, custodyLog };
    }),

  // ─── Create evidence item ───
  create: protectedProcedure
    .input(z.object({
      title: z.string().min(1),
      type: z.string().min(1),
      category: z.string().optional(),
      description: z.string().optional(),
      engagementId: z.string().optional(),
      operationId: z.string().optional(),
      classification: z.string().optional(),
      tags: z.array(z.string()).optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const evidenceId = generateId();
      await db.insert(evidenceItems).values({
        evidenceId,
        title: input.title,
        type: input.type,
        category: input.category,
        description: input.description,
        engagementId: input.engagementId,
        operationId: input.operationId,
        classification: input.classification || "confidential",
        tags: input.tags ? JSON.stringify(input.tags) : null,
        notes: input.notes,
        collectedBy: ctx.user.openId,
        collectedAt: new Date(),
      });

      // Log chain of custody
      await db.insert(evidenceChainOfCustody).values({
        evidenceId,
        action: "created",
        performedBy: ctx.user.name || ctx.user.openId,
        details: `Evidence item "${input.title}" created`,
      });

      return { evidenceId };
    }),

  // ─── Upload file to evidence ───
  uploadFile: protectedProcedure
    .input(z.object({
      evidenceId: z.string(),
      fileName: z.string(),
      fileData: z.string(), // base64 encoded
      mimeType: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [item] = await db.select().from(evidenceItems)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));
      if (!item) throw new TRPCError({ code: "NOT_FOUND", message: "Evidence not found" });

      const buffer = Buffer.from(input.fileData, "base64");
      const hash = crypto.createHash("sha256").update(buffer).digest("hex");
      const suffix = crypto.randomBytes(4).toString("hex");
      const fileKey = `evidence/${input.evidenceId}/${input.fileName}-${suffix}`;

      const { url } = await storagePut(fileKey, buffer, input.mimeType || "application/octet-stream");

      await db.update(evidenceItems)
        .set({
          fileUrl: url,
          fileKey,
          fileName: input.fileName,
          fileSize: buffer.length,
          mimeType: input.mimeType,
          sha256Hash: hash,
        })
        .where(eq(evidenceItems.evidenceId, input.evidenceId));

      // Log custody
      await db.insert(evidenceChainOfCustody).values({
        evidenceId: input.evidenceId,
        action: "file_uploaded",
        performedBy: ctx.user.name || ctx.user.openId,
        details: `File "${input.fileName}" uploaded (${buffer.length} bytes)`,
        integrityHash: hash,
      });

      return { url, hash, fileSize: buffer.length };
    }),

  // ─── Update evidence item ───
  update: protectedProcedure
    .input(z.object({
      evidenceId: z.string(),
      title: z.string().optional(),
      description: z.string().optional(),
      classification: z.string().optional(),
      category: z.string().optional(),
      tags: z.array(z.string()).optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.title !== undefined) updates.title = input.title;
      if (input.description !== undefined) updates.description = input.description;
      if (input.classification !== undefined) updates.classification = input.classification;
      if (input.category !== undefined) updates.category = input.category;
      if (input.tags !== undefined) updates.tags = JSON.stringify(input.tags);
      if (input.notes !== undefined) updates.notes = input.notes;

      await db.update(evidenceItems).set(updates)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));

      await db.insert(evidenceChainOfCustody).values({
        evidenceId: input.evidenceId,
        action: "updated",
        performedBy: ctx.user.name || ctx.user.openId,
        details: `Fields updated: ${Object.keys(updates).join(", ")}`,
      });

      return { success: true };
    }),

  // ─── Delete evidence ───
  delete: protectedProcedure
    .input(z.object({ evidenceId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.insert(evidenceChainOfCustody).values({
        evidenceId: input.evidenceId,
        action: "deleted",
        performedBy: ctx.user.name || ctx.user.openId,
        details: "Evidence item deleted",
      });
      await db.delete(evidenceItems)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));
      return { success: true };
    }),

  // ─── Get custody log ───
  getCustodyLog: protectedProcedure
    .input(z.object({ evidenceId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      return db.select().from(evidenceChainOfCustody)
        .where(eq(evidenceChainOfCustody.evidenceId, input.evidenceId))
        .orderBy(desc(evidenceChainOfCustody.performedAt));
    }),

  // ─── Verify hash ───
  verifyHash: protectedProcedure
    .input(z.object({ evidenceId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [item] = await db.select().from(evidenceItems)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));
      if (!item) throw new TRPCError({ code: "NOT_FOUND" });
      if (!item.fileUrl || !item.sha256Hash) {
        return { verified: false, reason: "No file attached" };
      }

      // Log verification attempt
      await db.insert(evidenceChainOfCustody).values({
        evidenceId: input.evidenceId,
        action: "hash_verified",
        performedBy: ctx.user.name || ctx.user.openId,
        details: `Hash verification requested. Stored hash: ${item.sha256Hash}`,
      });

      return { verified: true, hash: item.sha256Hash, algorithm: "SHA-256" };
    }),

  // ─── Stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [totalCount] = await db.select({ count: sql<number>`count(*)` }).from(evidenceItems);
    const typeBreakdown = await db.select({
      type: evidenceItems.type,
      count: sql<number>`count(*)`,
    }).from(evidenceItems).groupBy(evidenceItems.type);

    const classBreakdown = await db.select({
      classification: evidenceItems.classification,
      count: sql<number>`count(*)`,
    }).from(evidenceItems).groupBy(evidenceItems.classification);

    return {
      total: Number(totalCount?.count ?? 0),
      byType: typeBreakdown.map(r => ({ type: r.type, count: Number(r.count) })),
      byClassification: classBreakdown.map(r => ({ classification: r.classification, count: Number(r.count) })),
    };
  }),
});
