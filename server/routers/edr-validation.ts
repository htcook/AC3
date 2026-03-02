import * as db from "../db";
/**
 * EDR Effectiveness Validation Router
 * Manages EDR products, test catalogs, test execution, and coverage matrix.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  EDR_TEST_CATALOG,
  KNOWN_EDR_PRODUCTS,
  calculateEDRCoverage,
  generateEDRSummary,
} from "../lib/edr-validation";

export const edrValidationRouter = router({
  /** Get the built-in EDR test catalog */
  getTestCatalog: protectedProcedure
    .input(z.object({ category: z.string().optional() }).optional())
    .query(({ input }) => {
      const category = input?.category;
      const tests = category
        ? EDR_TEST_CATALOG.filter(t => t.category === category)
        : EDR_TEST_CATALOG;
      const cats = Array.from(new Set(EDR_TEST_CATALOG.map(t => t.category)));
      return { tests, total: tests.length, categories: cats };
    }),

  /** Get known EDR products list */
  getKnownProducts: protectedProcedure.query(() => {
    return KNOWN_EDR_PRODUCTS;
  }),

  /** List EDR products configured for an engagement */
  listProducts: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrProducts } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input?.engagementId
        ? db.select().from(edrProducts).where(eq(edrProducts.engagementId, input.engagementId))
        : db.select().from(edrProducts);
      return await query;
    }),

  /** Add an EDR product */
  addProduct: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      productName: z.string(),
      vendor: z.string(),
      version: z.string().optional(),
      deploymentType: z.enum(["endpoint", "network", "cloud", "hybrid"]).optional(),
      agentCount: z.number().optional(),
      config: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrProducts } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(edrProducts).values({
        engagementId: input.engagementId ?? null,
        productName: input.productName,
        vendor: input.vendor,
        version: input.version ?? null,
        deploymentType: input.deploymentType ?? "endpoint",
        agentCount: input.agentCount ?? null,
        config: input.config ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List test results for an EDR product */
  listTestResults: protectedProcedure
    .input(z.object({
      edrProductId: z.number(),
      engagementId: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrTestResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [eq(edrTestResults.edrProductId, input.edrProductId)];
      if (input.engagementId) conditions.push(eq(edrTestResults.engagementId, input.engagementId));

      return await db.select().from(edrTestResults)
        .where(and(...conditions))
        .orderBy(desc(edrTestResults.createdAt));
    }),

  /** Record a test result */
  recordTestResult: protectedProcedure
    .input(z.object({
      edrProductId: z.number(),
      testCatalogId: z.number(),
      engagementId: z.number().optional(),
      detectionResult: z.enum(["detected", "missed", "partial", "delayed", "blocked"]),
      detectionTimeMs: z.number().optional(),
      alertSeverity: z.string().optional(),
      alertTitle: z.string().optional(),
      responseAction: z.string().optional(),
      falsePositive: z.boolean().optional(),
      evidence: z.any().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrTestResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(edrTestResults).values({
        edrProductId: input.edrProductId,
        testCatalogId: input.testCatalogId,
        engagementId: input.engagementId ?? null,
        executionStatus: "completed",
        detectionResult: input.detectionResult,
        detectionTimeMs: input.detectionTimeMs ?? null,
        alertSeverity: input.alertSeverity ?? null,
        alertTitle: input.alertTitle ?? null,
        responseAction: input.responseAction ?? null,
        falsePositive: input.falsePositive ?? false,
        evidence: input.evidence ?? null,
        notes: input.notes ?? null,
        executedAt: new Date(),
        detectedAt: input.detectionResult !== "missed" ? new Date() : null,
      });
      return { id: result.insertId, success: true };
    }),

  /** Get coverage matrix for an EDR product */
  getCoverageMatrix: protectedProcedure
    .input(z.object({ edrProductId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrCoverageMatrix } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      return await db.select().from(edrCoverageMatrix)
        .where(eq(edrCoverageMatrix.edrProductId, input.edrProductId));
    }),

  /** Calculate coverage summary for an EDR product from its test results */
  getCoverageSummary: protectedProcedure
    .input(z.object({ edrProductId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { edrTestResults, edrTestCatalog, edrProducts } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const [product] = await db.select().from(edrProducts).where(eq(edrProducts.id, input.edrProductId));
      if (!product) throw new TRPCError({ code: "NOT_FOUND", message: "EDR product not found" });

      const results = await db.select({
        detectionResult: edrTestResults.detectionResult,
        category: edrTestCatalog.category,
      })
        .from(edrTestResults)
        .innerJoin(edrTestCatalog, eq(edrTestResults.testCatalogId, edrTestCatalog.id))
        .where(eq(edrTestResults.edrProductId, input.edrProductId));

      const coverage = calculateEDRCoverage(results);
      const summary = generateEDRSummary(product.productName, product.vendor, coverage);
      return { coverage, summary, product };
    }),

  /** Get EDR validation statistics */
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { edrProducts, edrTestResults } = await import("../../drizzle/schema");
    const { count } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const [productCount] = await db.select({ count: count() }).from(edrProducts);
    const [resultCount] = await db.select({ count: count() }).from(edrTestResults);

    return {
      totalProducts: productCount.count,
      totalTestResults: resultCount.count,
      catalogSize: EDR_TEST_CATALOG.length,
      knownProducts: KNOWN_EDR_PRODUCTS.length,
    };
  }),
});
