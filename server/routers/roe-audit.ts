import * as db from "../db";
/**
 * ROE Management & Audit Log Router
 * 
 * Provides procedures for:
 * - Managing ROE status on engagements (upload, sign, expire)
 * - Uploading signed ROE documents (PDF) to S3
 * - Viewing the unified offensive audit trail
 * - Checking ROE validity for a given engagement
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { TRPCError } from "@trpc/server";

export const roeAuditRouter = router({
  /** Get ROE status for an engagement */
  getROEStatus: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const { getDb } = await import("../db");
      const { engagements } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [eng] = await db
        .select({
          id: engagements.id,
          name: engagements.name,
          roeStatus: engagements.roeStatus,
          roeSignedDate: engagements.roeSignedDate,
          roeExpiryDate: engagements.roeExpiryDate,
          roeDocumentUrl: engagements.roeDocumentUrl,
          roeScope: engagements.roeScope,
          roeSignerName: engagements.roeSignerName,
          roeSignerEmail: engagements.roeSignerEmail,
        })
        .from(engagements)
        .where(eq(engagements.id, input.engagementId))
        .limit(1);

      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      // Auto-expire if past expiry date
      if (eng.roeStatus === "signed" && eng.roeExpiryDate && new Date(eng.roeExpiryDate) < new Date()) {
        await db.update(engagements)
          .set({ roeStatus: "expired" })
          .where(eq(engagements.id, input.engagementId));
        return { ...eng, roeStatus: "expired" as const };
      }

      return eng;
    }),

  /** Update ROE for an engagement */
  updateROE: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      roeStatus: z.enum(["none", "pending", "signed", "expired"]),
      roeSignedDate: z.string().optional(),
      roeExpiryDate: z.string().optional(),
      roeDocumentUrl: z.string().optional(),
      roeScope: z.object({
        domains: z.array(z.string()).optional(),
        ipRanges: z.array(z.string()).optional(),
        excludedTargets: z.array(z.string()).optional(),
        allowedActions: z.array(z.string()).optional(),
        restrictions: z.string().optional(),
      }).optional(),
      roeSignerName: z.string().optional(),
      roeSignerEmail: z.string().email().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { engagements } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { logOffensiveAction } = await import("../lib/roe-guard");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [eng] = await db.select({ id: engagements.id, name: engagements.name })
        .from(engagements).where(eq(engagements.id, input.engagementId)).limit(1);
      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      const updateData: Record<string, any> = { roeStatus: input.roeStatus };
      if (input.roeSignedDate) updateData.roeSignedDate = new Date(input.roeSignedDate);
      if (input.roeExpiryDate) updateData.roeExpiryDate = new Date(input.roeExpiryDate);
      if (input.roeDocumentUrl !== undefined) updateData.roeDocumentUrl = input.roeDocumentUrl;
      if (input.roeScope !== undefined) updateData.roeScope = input.roeScope;
      if (input.roeSignerName !== undefined) updateData.roeSignerName = input.roeSignerName;
      if (input.roeSignerEmail !== undefined) updateData.roeSignerEmail = input.roeSignerEmail;

      await db.update(engagements).set(updateData).where(eq(engagements.id, input.engagementId));

      return { success: true, engagementId: input.engagementId, roeStatus: input.roeStatus };
    }),

  /** Upload ROE document (PDF) to S3 and update engagement */
  uploadROEDocument: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      fileName: z.string(),
      fileData: z.string(), // base64 encoded PDF
      mimeType: z.string().default("application/pdf"),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { engagements } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { doStoragePut } = await import("../do-storage");
      const crypto = await import("crypto");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [eng] = await db.select({ id: engagements.id, name: engagements.name })
        .from(engagements).where(eq(engagements.id, input.engagementId)).limit(1);
      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      const buffer = Buffer.from(input.fileData, "base64");
      if (buffer.length > 20 * 1024 * 1024) {
        throw new TRPCError({ code: "PAYLOAD_TOO_LARGE", message: "ROE document must be under 20 MB" });
      }

      const suffix = crypto.randomBytes(4).toString("hex");
      const fileKey = `roe-documents/${input.engagementId}/${input.fileName}-${suffix}`;
      const { url } = await doStoragePut(fileKey, buffer, input.mimeType);

      await db.update(engagements)
        .set({ roeDocumentUrl: url })
        .where(eq(engagements.id, input.engagementId));

      return { url, fileSize: buffer.length, fileName: input.fileName };
    }),

  /** Validate ROE for an engagement (used by frontend before starting operations) */
  validateROE: protectedProcedure
    .input(z.object({ engagementId: z.number(), riskTier: z.enum(["yellow", "orange", "red"]) }))
    .query(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const { getEngagementROE, validateROE } = await import("../lib/roe-guard");
      const roe = await getEngagementROE(input.engagementId);
      if (!roe) return { valid: false, reason: "Engagement not found" };

      if (input.riskTier === "yellow") {
        return { valid: true, reason: "YELLOW tier operations do not require ROE" };
      }

      return validateROE(roe);
    }),

  /** Get audit log entries with filtering */
  getAuditLog: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      riskTier: z.enum(["yellow", "orange", "red"]).optional(),
      actionType: z.string().optional(),
      operatorId: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const { getDb } = await import("../db");
      const { offensiveAuditLog } = await import("../../drizzle/schema");
      const { eq, desc, and, sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const conditions: any[] = [];
      if (input.engagementId) conditions.push(eq(offensiveAuditLog.engagementId, input.engagementId));
      if (input.riskTier) conditions.push(eq(offensiveAuditLog.riskTier, input.riskTier));
      if (input.actionType) conditions.push(eq(offensiveAuditLog.actionType, input.actionType as any));
      if (input.operatorId) conditions.push(eq(offensiveAuditLog.operatorId, input.operatorId));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [entries, countResult] = await Promise.all([
        db.select().from(offensiveAuditLog)
          .where(where)
          .orderBy(desc(offensiveAuditLog.createdAt))
          .limit(input.limit)
          .offset(input.offset),
        db.select({ count: sql<number>`COUNT(*)` }).from(offensiveAuditLog).where(where),
      ]);

      return {
        entries,
        total: countResult[0]?.count ?? 0,
        limit: input.limit,
        offset: input.offset,
      };
    }),

  /** Get audit log summary stats */
  getAuditStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { offensiveAuditLog } = await import("../../drizzle/schema");
    const { sql } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return { total: 0, byTier: {}, byAction: {}, byResult: {}, recentCount: 0 };

    const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(offensiveAuditLog);
    const byTier = await db.select({
      tier: offensiveAuditLog.riskTier,
      count: sql<number>`COUNT(*)`,
    }).from(offensiveAuditLog).groupBy(offensiveAuditLog.riskTier);
    const byAction = await db.select({
      action: offensiveAuditLog.actionType,
      count: sql<number>`COUNT(*)`,
    }).from(offensiveAuditLog).groupBy(offensiveAuditLog.actionType);
    const byResult = await db.select({
      result: offensiveAuditLog.resultStatus,
      count: sql<number>`COUNT(*)`,
    }).from(offensiveAuditLog).groupBy(offensiveAuditLog.resultStatus);
    const [recent] = await db.select({ count: sql<number>`COUNT(*)` })
      .from(offensiveAuditLog)
      .where(sql`${offensiveAuditLog.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);

    return {
      total: total?.count ?? 0,
      byTier: Object.fromEntries(byTier.map(r => [r.tier, r.count])),
      byAction: Object.fromEntries(byAction.map(r => [r.action, r.count])),
      byResult: Object.fromEntries(byResult.map(r => [r.result, r.count])),
      recentCount: recent?.count ?? 0,
    };
  }),
});
