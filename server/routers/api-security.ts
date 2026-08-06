import * as db from "../db";
/**
 * API Security Testing Router
 * Manages API targets, endpoint discovery, OWASP API Top 10 testing,
 * fuzzing runs, and vulnerability results.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  OWASP_API_TOP_10,
  API_SECURITY_TESTS,
  FUZZING_STRATEGIES,
  calculateAPISecurityScore,
} from "../lib/api-security-engine";

const owaspCategoryEnum = z.enum([
  "API1_BOLA", "API2_BROKEN_AUTH", "API3_OBJECT_PROPERTY",
  "API4_UNRESTRICTED_CONSUMPTION", "API5_BROKEN_FUNCTION_AUTH",
  "API6_SERVER_SIDE_REQUEST_FORGERY", "API7_SECURITY_MISCONFIGURATION",
  "API8_LACK_OF_PROTECTION", "API9_IMPROPER_INVENTORY",
  "API10_UNSAFE_API_CONSUMPTION"
]);

export const apiSecurityRouter = router({
  /** Get the OWASP API Top 10 reference */
  getOwaspReference: protectedProcedure.query(() => {
    return OWASP_API_TOP_10;
  }),

  /** Get the built-in API security test catalog */
  getTestCatalog: protectedProcedure
    .input(z.object({ owaspCategory: z.string().optional() }).optional())
    .query(({ input }) => {
      const cat = input?.owaspCategory;
      const tests = cat
        ? API_SECURITY_TESTS.filter(t => t.owaspCategory === cat)
        : API_SECURITY_TESTS;
      return { tests, total: tests.length };
    }),

  /** Get fuzzing strategies */
  getFuzzingStrategies: protectedProcedure.query(() => {
    return FUZZING_STRATEGIES;
  }),

  /** List API targets */
  listTargets: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiTargets } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input?.engagementId
        ? db.select().from(apiTargets).where(eq(apiTargets.engagementId, input.engagementId))
        : db.select().from(apiTargets);
      return await query;
    }),

  /** Add an API target */
  addTarget: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      name: z.string(),
      baseUrl: z.string(),
      specType: z.enum(["openapi_3", "openapi_2", "swagger", "graphql", "grpc", "manual"]).optional(),
      specUrl: z.string().optional(),
      authType: z.enum(["none", "api_key", "bearer", "basic", "oauth2", "custom"]).optional(),
      authConfig: z.any().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate API target URL ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.baseUrl, "API Security Target", ctx);
      }
      const { getDb } = await import("../db");
      const { apiTargets } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(apiTargets).values({
        engagementId: input.engagementId ?? null,
        name: input.name,
        baseUrl: input.baseUrl,
        specType: input.specType ?? "manual",
        specUrl: input.specUrl ?? null,
        authType: input.authType ?? "none",
        authConfig: input.authConfig ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List endpoints for an API target */
  listEndpoints: protectedProcedure
    .input(z.object({ targetId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiEndpoints } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      return await db.select().from(apiEndpoints).where(eq(apiEndpoints.targetId, input.targetId));
    }),

  /** Add an API endpoint */
  addEndpoint: protectedProcedure
    .input(z.object({
      targetId: z.number(),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
      path: z.string(),
      operationId: z.string().optional(),
      summary: z.string().optional(),
      parameters: z.any().optional(),
      requestBody: z.any().optional(),
      responseSchemas: z.any().optional(),
      authRequired: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiEndpoints } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(apiEndpoints).values({
        targetId: input.targetId,
        method: input.method,
        path: input.path,
        operationId: input.operationId ?? null,
        summary: input.summary ?? null,
        parameters: input.parameters ?? null,
        requestBody: input.requestBody ?? null,
        responseSchemas: input.responseSchemas ?? null,
        authRequired: input.authRequired ?? false,
      });
      return { id: result.insertId, success: true };
    }),

  /** List test results */
  listTestResults: protectedProcedure
    .input(z.object({
      endpointId: z.number().optional(),
      engagementId: z.number().optional(),
      result: z.enum(["vulnerable", "secure", "error", "inconclusive", "skipped"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiTestResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input.endpointId) conditions.push(eq(apiTestResults.endpointId, input.endpointId));
      if (input.engagementId) conditions.push(eq(apiTestResults.engagementId, input.engagementId));
      if (input.result) conditions.push(eq(apiTestResults.result, input.result));

      return conditions.length > 0
        ? await db.select().from(apiTestResults).where(and(...conditions)).orderBy(desc(apiTestResults.createdAt))
        : await db.select().from(apiTestResults).orderBy(desc(apiTestResults.createdAt));
    }),

  /** Record a test result */
  recordTestResult: protectedProcedure
    .input(z.object({
      endpointId: z.number(),
      testId: z.number(),
      engagementId: z.number().optional(),
      result: z.enum(["vulnerable", "secure", "error", "inconclusive", "skipped"]),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      requestSent: z.any().optional(),
      responseReceived: z.any().optional(),
      evidence: z.any().optional(),
      notes: z.string().optional(),
      falsePositive: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiTestResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(apiTestResults).values({
        endpointId: input.endpointId,
        testId: input.testId,
        engagementId: input.engagementId ?? null,
        result: input.result,
        severity: input.severity ?? null,
        requestSent: input.requestSent ?? null,
        responseReceived: input.responseReceived ?? null,
        evidence: input.evidence ?? null,
        notes: input.notes ?? null,
        falsePositive: input.falsePositive ?? false,
        executedAt: new Date(),
      });
      return { id: result.insertId, success: true };
    }),

  /** List fuzzing runs */
  listFuzzingRuns: protectedProcedure
    .input(z.object({ targetId: z.number().optional(), engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiFuzzingRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.targetId) conditions.push(eq(apiFuzzingRuns.targetId, input.targetId));
      if (input?.engagementId) conditions.push(eq(apiFuzzingRuns.engagementId, input.engagementId));

      return conditions.length > 0
        ? await db.select().from(apiFuzzingRuns).where(and(...conditions)).orderBy(desc(apiFuzzingRuns.createdAt))
        : await db.select().from(apiFuzzingRuns).orderBy(desc(apiFuzzingRuns.createdAt));
    }),

  /** Start a fuzzing run */
  startFuzzingRun: protectedProcedure
    .input(z.object({
      targetId: z.number(),
      engagementId: z.number().optional(),
      fuzzType: z.enum(["parameter_mutation", "injection", "auth_bypass", "rate_limit", "schema_violation"]),
      config: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiFuzzingRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(apiFuzzingRuns).values({
        targetId: input.targetId,
        engagementId: input.engagementId ?? null,
        fuzzType: input.fuzzType,
        config: input.config ?? null,
        startedAt: new Date(),
      });
      return { id: result.insertId, success: true };
    }),

  /** Get API security score for an engagement */
  getSecurityScore: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { apiTestResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const results = await db.select({
        result: apiTestResults.result,
        severity: apiTestResults.severity,
      }).from(apiTestResults).where(eq(apiTestResults.engagementId, input.engagementId));

      return calculateAPISecurityScore(results.map(r => ({
        result: r.result,
        severity: r.severity ?? "medium",
      })));
    }),

  /** Get API security statistics */
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { apiTargets, apiEndpoints, apiTestResults, apiFuzzingRuns } = await import("../../drizzle/schema");
    const { count } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const [targetCount] = await db.select({ count: count() }).from(apiTargets);
    const [endpointCount] = await db.select({ count: count() }).from(apiEndpoints);
    const [resultCount] = await db.select({ count: count() }).from(apiTestResults);
    const [fuzzCount] = await db.select({ count: count() }).from(apiFuzzingRuns);

    return {
      totalTargets: targetCount.count,
      totalEndpoints: endpointCount.count,
      totalTestResults: resultCount.count,
      totalFuzzingRuns: fuzzCount.count,
      catalogSize: API_SECURITY_TESTS.length,
      owaspCategories: Object.keys(OWASP_API_TOP_10).length,
    };
  }),
});
