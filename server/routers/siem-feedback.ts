import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const siemFeedbackRouter = router({
  listIntegrations: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { siemIntegrations } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(siemIntegrations).orderBy(desc(siemIntegrations.createdAt));
  }),
  createIntegration: protectedProcedure
    .input(z.object({
      name: z.string(),
      provider: z.enum(["splunk", "elastic", "sentinel", "qradar", "custom"]),
      baseUrl: z.string(),
      apiKeyEncrypted: z.string().optional(),
      queryTemplate: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { siemIntegrations } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(siemIntegrations).values({ ...input });
      return { id: result[0].insertId };
    }),
  testConnection: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { siemIntegrations } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const rows = await db.select().from(siemIntegrations).where(eq(siemIntegrations.id, input.id));
      const integration = rows[0];
      if (!integration) throw new TRPCError({ code: "NOT_FOUND", message: "SIEM integration not found" });
      const { testSIEMConnection } = await import("../lib/siem-feedback");
      return await testSIEMConnection({
        provider: integration.provider as any,
        baseUrl: integration.baseUrl,
        apiKey: integration.apiKeyEncrypted || "",
        queryTemplate: integration.queryTemplate || undefined,
      });
    }),
  deleteIntegration: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { siemIntegrations } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(siemIntegrations).where(eq(siemIntegrations.id, input.id));
      return { success: true };
    }),
  listResults: protectedProcedure
    .input(z.object({ siemId: z.number().optional(), techniqueId: z.string().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { detectionFeedbackResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { and, eq, desc } = await import("drizzle-orm");
      const conditions = [];
      if (input.siemId) conditions.push(eq(detectionFeedbackResults.siemIntegrationId, input.siemId));
      if (input.techniqueId) conditions.push(eq(detectionFeedbackResults.techniqueId, input.techniqueId));
      return db.select().from(detectionFeedbackResults)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(detectionFeedbackResults.createdAt));
    }),
  executeDetection: protectedProcedure
    .input(z.object({
      siemId: z.number(),
      techniqueId: z.string(),
      techniqueName: z.string().optional(),
      executedAt: z.string(),
      queryWindowSec: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { siemIntegrations, detectionFeedbackResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const rows = await db.select().from(siemIntegrations).where(eq(siemIntegrations.id, input.siemId));
      const integration = rows[0];
      if (!integration) throw new TRPCError({ code: "NOT_FOUND", message: "SIEM integration not found" });
      const { executeDetectionQuery } = await import("../lib/siem-feedback");
      const result = await executeDetectionQuery(
        {
          provider: integration.provider as any,
          baseUrl: integration.baseUrl,
          apiKey: integration.apiKeyEncrypted || "",
          queryTemplate: integration.queryTemplate || undefined,
        },
        {
          techniqueId: input.techniqueId,
          techniqueName: input.techniqueName,
          executedAt: new Date(input.executedAt),
          queryWindowSec: input.queryWindowSec,
        }
      );
      // Store result
      await db.insert(detectionFeedbackResults).values({
        siemIntegrationId: input.siemId,
        techniqueId: input.techniqueId,
        techniqueName: input.techniqueName || input.techniqueId,
        executedAt: new Date(input.executedAt),
        queryWindowSec: input.queryWindowSec || 300,
        alertsFound: result.alertsFound,
        detectionResult: result.result,
        alertDetails: JSON.stringify(result.alerts),
        queryUsed: result.queryUsed,
        latencyMs: result.latencyMs,
      });
      return result;
    }),
  getDetectionSummary: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { detectionFeedbackResults } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    const result = await db.select({
      detected: sql<number>`SUM(CASE WHEN ${detectionFeedbackResults.detectionResult} = 'detected' THEN 1 ELSE 0 END)`,
      missed: sql<number>`SUM(CASE WHEN ${detectionFeedbackResults.detectionResult} = 'missed' THEN 1 ELSE 0 END)`,
      partial: sql<number>`SUM(CASE WHEN ${detectionFeedbackResults.detectionResult} = 'partial' THEN 1 ELSE 0 END)`,
      errored: sql<number>`SUM(CASE WHEN ${detectionFeedbackResults.detectionResult} = 'error' THEN 1 ELSE 0 END)`,
    }).from(detectionFeedbackResults);
    const summary = result[0] || {};
    return {
      detected: Number(summary.detected || 0),
      missed: Number(summary.missed || 0),
      partial: Number(summary.partial || 0),
      errored: Number(summary.errored || 0),
    };
  }),
});
