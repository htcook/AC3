import * as db from "../db";
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
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate target email domain is in scope ──
      if (input.engagementId && input.targetEmail) {
        const emailDomain = input.targetEmail.split("@")[1];
        if (emailDomain) {
          const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceTargetScope(input.engagementId, emailDomain, "Email Security Test", ctx);
        }
      }
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
  analyzeDomain: protectedProcedure
    .input(z.object({ domain: z.string().min(1), engagementId: z.number().optional() }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate domain is in scope ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.domain, "Email Security Analysis", ctx);
      }
      const { analyzeEmailSecurity } = await import("../lib/email-security-analyzer");
      const report = await analyzeEmailSecurity(input.domain);
      return report;
    }),
  analyzeMultipleDomains: protectedProcedure
    .input(z.object({ domains: z.array(z.string().min(1)).min(1).max(20) }))
    .mutation(async ({ input }) => {
      const { analyzeEmailSecurity } = await import("../lib/email-security-analyzer");
      const results = await Promise.all(
        input.domains.map(async (domain) => {
          try {
            return await analyzeEmailSecurity(domain);
          } catch (err: any) {
            return {
              domain,
              analyzedAt: new Date().toISOString(),
              overallScore: 0,
              overallGrade: "F",
              totalWeaknesses: 0,
              criticalWeaknesses: 0,
              phishingDifficultyRating: "unknown" as const,
              phishingSummary: `Analysis failed: ${err.message}`,
              recommendations: [],
              spf: { exists: false, record: null, score: 0, mechanisms: [], includes: [], allMechanism: null, weaknesses: [] },
              dkim: { selectorsFound: [], selectorsChecked: [], selectorResults: [], weaknesses: [], score: 0 },
              dmarc: { exists: false, record: null, policy: null, subdomainPolicy: null, percentage: 100, reportingEnabled: false, ruaAddresses: [], rufAddresses: [], weaknesses: [], score: 0 },
              mx: { records: [], provider: null, supportsStartTls: null, weaknesses: [] },
              error: err.message,
            };
          }
        })
      );
      return results;
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
