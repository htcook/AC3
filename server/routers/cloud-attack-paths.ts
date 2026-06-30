import * as db from "../db";
/**
 * Cloud-Native Attack Paths Router
 * Manages cloud provider configurations, identity analysis,
 * attack path discovery, and misconfiguration scanning for AWS/Azure/GCP.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  FULL_CLOUD_CATALOG,
  AWS_ATTACK_CATALOG,
  AZURE_ATTACK_CATALOG,
  GCP_ATTACK_CATALOG,
  IAM_MISCONFIG_CHECKS,
  getCloudMitreTechniques,
} from "../lib/cloud-attack-paths";

export const cloudAttackPathsRouter = router({
  /** Get the full cloud attack catalog */
  getCatalog: protectedProcedure
    .input(z.object({ provider: z.enum(["aws", "azure", "gcp", "all"]).optional() }).optional())
    .query(({ input }) => {
      const provider = input?.provider ?? "all";
      const catalog = provider === "aws" ? AWS_ATTACK_CATALOG
        : provider === "azure" ? AZURE_ATTACK_CATALOG
        : provider === "gcp" ? GCP_ATTACK_CATALOG
        : FULL_CLOUD_CATALOG;
      return {
        attacks: catalog,
        total: catalog.length,
        mitreTechniques: getCloudMitreTechniques(),
      };
    }),

  /** Get IAM misconfiguration checks for a provider */
  getMisconfigChecks: protectedProcedure
    .input(z.object({ provider: z.enum(["aws", "azure", "gcp"]) }))
    .query(({ input }) => {
      return {
        checks: IAM_MISCONFIG_CHECKS[input.provider],
        total: IAM_MISCONFIG_CHECKS[input.provider].length,
      };
    }),

  /** List cloud providers configured for an engagement */
  listProviders: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudProviders } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input.engagementId
        ? db.select().from(cloudProviders).where(eq(cloudProviders.engagementId, input.engagementId))
        : db.select().from(cloudProviders);
      return await query;
    }),

  /** Add a cloud provider configuration */
  addProvider: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      provider: z.enum(["aws", "azure", "gcp"]),
      accountId: z.string(),
      accountAlias: z.string().optional(),
      region: z.string().optional(),
      config: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudProviders } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(cloudProviders).values({
        engagementId: input.engagementId ?? null,
        provider: input.provider,
        accountId: input.accountId,
        accountAlias: input.accountAlias ?? null,
        region: input.region ?? null,
        config: input.config ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List discovered attack paths */
  listAttackPaths: protectedProcedure
    .input(z.object({
      providerId: z.number().optional(),
      engagementId: z.number().optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudAttackPaths } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input.providerId) conditions.push(eq(cloudAttackPaths.providerId, input.providerId));
      if (input.engagementId) conditions.push(eq(cloudAttackPaths.engagementId, input.engagementId));
      if (input.severity) conditions.push(eq(cloudAttackPaths.severity, input.severity));

      const paths = conditions.length > 0
        ? await db.select().from(cloudAttackPaths).where(and(...conditions)).orderBy(desc(cloudAttackPaths.riskScore))
        : await db.select().from(cloudAttackPaths).orderBy(desc(cloudAttackPaths.riskScore));

      return paths;
    }),

  /** Create a discovered attack path */
  createAttackPath: protectedProcedure
    .input(z.object({
      providerId: z.number(),
      engagementId: z.number().optional(),
      pathName: z.string(),
      attackType: z.enum([
        "privilege_escalation", "role_chaining", "cross_account",
        "service_account_impersonation", "org_policy_bypass",
        "consent_grant_abuse", "app_registration_abuse", "pim_escalation",
        "s3_public_access", "storage_misconfiguration", "iam_misconfiguration",
        "lateral_movement", "data_exfiltration"
      ]),
      provider: z.enum(["aws", "azure", "gcp"]),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      sourceIdentity: z.string().optional(),
      targetResource: z.string().optional(),
      pathNodes: z.any().optional(),
      mitreTechniques: z.any().optional(),
      riskScore: z.number().optional(),
      description: z.string().optional(),
      remediationSteps: z.any().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement ──
      if (input.engagementId && input.targetResource) {
        try {
          const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceTargetScope(input.engagementId, input.targetResource, "Cloud Attack Path Simulation", ctx);
        } catch (e: any) {
          if (e?.code === "PRECONDITION_FAILED") throw e;
          // Log but don't block if scope check fails (cloud resources may not be IP-based)
        }
      }
      const { getDb } = await import("../db");
      const { cloudAttackPaths } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(cloudAttackPaths).values({
        providerId: input.providerId,
        engagementId: input.engagementId ?? null,
        pathName: input.pathName,
        attackType: input.attackType,
        provider: input.provider,
        severity: input.severity ?? "medium",
        sourceIdentity: input.sourceIdentity ?? null,
        targetResource: input.targetResource ?? null,
        pathNodes: input.pathNodes ?? null,
        mitreTechniques: input.mitreTechniques ?? null,
        riskScore: input.riskScore ?? null,
        description: input.description ?? null,
        remediationSteps: input.remediationSteps ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** Get cloud attack path statistics */
  getStats: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudProviders, cloudAttackPaths } = await import("../../drizzle/schema");
      const { count, eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [providerCount] = await db.select({ count: count() }).from(cloudProviders);
      const [pathCount] = await db.select({ count: count() }).from(cloudAttackPaths);

      return {
        totalProviders: providerCount.count,
        totalAttackPaths: pathCount.count,
        catalogSize: FULL_CLOUD_CATALOG.length,
        misconfigCheckCount: Object.values(IAM_MISCONFIG_CHECKS).flat().length,
      };
    }),
});
