import * as db from "../db";
/**
 * Cloud Security Validation Router
 *
 * tRPC endpoints for running CIS Benchmark assessments against
 * AWS, Azure, and GCP cloud environments.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  ALL_CIS_CHECKS,
  AWS_CIS_CHECKS,
  AZURE_CIS_CHECKS,
  GCP_CIS_CHECKS,
  getChecksByProvider,
  getChecksByDomain,
  getCheckById,
  runAssessment,
  generateComplianceSummary,
  getProviderStats,
  type CloudProvider,
  type CheckDomain,
} from "../lib/cloud-security-validation";

export const cloudSecurityValidationRouter = router({
  /** Get provider statistics and available checks */
  getProviderStats: protectedProcedure.query(() => {
    return getProviderStats();
  }),

  /** List all CIS checks, optionally filtered by provider and/or domain */
  listChecks: protectedProcedure
    .input(
      z.object({
        provider: z.enum(["aws", "azure", "gcp"]).optional(),
        domain: z.enum(["iam", "networking", "storage", "compute", "logging"]).optional(),
      }).optional()
    )
    .query(({ input }) => {
      let checks = ALL_CIS_CHECKS;
      if (input?.provider) {
        checks = input.domain
          ? getChecksByDomain(input.provider, input.domain)
          : getChecksByProvider(input.provider);
      } else if (input?.domain) {
        checks = ALL_CIS_CHECKS.filter(c => c.domain === input.domain);
      }
      return {
        checks,
        total: checks.length,
        bySeverity: {
          critical: checks.filter(c => c.severity === "critical").length,
          high: checks.filter(c => c.severity === "high").length,
          medium: checks.filter(c => c.severity === "medium").length,
          low: checks.filter(c => c.severity === "low").length,
        },
      };
    }),

  /** Get a single check by ID */
  getCheck: protectedProcedure
    .input(z.object({ checkId: z.string() }))
    .query(({ input }) => {
      const check = getCheckById(input.checkId);
      if (!check) throw new TRPCError({ code: "NOT_FOUND", message: `Check ${input.checkId} not found` });
      return check;
    }),

  /** Run a cloud security validation assessment */
  runAssessment: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      accountId: z.string().min(1),
      accountAlias: z.string().default(""),
      config: z.record(z.any()).default({}),
      domains: z.array(z.enum(["iam", "networking", "storage", "compute", "logging"])).optional(),
    }))
    .mutation(async ({ input }) => {
      const assessment = runAssessment(
        input.provider,
        input.accountId,
        input.accountAlias || input.accountId,
        input.config,
        input.domains as CheckDomain[] | undefined,
      );

      // Persist to database
      try {
        const { getDb } = await import("../db");
        const { cloudMisconfigurations, cloudProviders } = await import("../../drizzle/schema");
        const db = await getDb();
        if (db) {
          // Store failed findings as misconfigurations
          const failedResults = assessment.results.filter(r => r.status === "fail");
          for (const result of failedResults) {
            const check = getCheckById(result.checkId);
            if (!check) continue;
            await db.insert(cloudMisconfigurations).values({
              providerId: 0, // Will be linked when provider is registered
              resourceType: check.domain,
              resourceName: result.resourceName,
              misconfigType: result.checkId,
              severity: check.severity,
              description: check.description,
              currentValue: result.currentValue,
              expectedValue: result.expectedValue,
              remediationSteps: JSON.stringify(check.remediationSteps),
              complianceFrameworks: JSON.stringify({ cisBenchmark: check.cisBenchmark }),
              status: "open",
            });
          }
        }
      } catch {
        // Non-fatal — assessment still returns results
      }

      return assessment;
    }),

  /** Generate compliance summary from an assessment */
  getComplianceSummary: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      accountId: z.string(),
      accountAlias: z.string().default(""),
      config: z.record(z.any()).default({}),
    }))
    .query(({ input }) => {
      const assessment = runAssessment(input.provider, input.accountId, input.accountAlias, input.config);
      return generateComplianceSummary(assessment);
    }),

  /** Get MITRE ATT&CK Cloud technique coverage from checks */
  getMitreCoverage: protectedProcedure
    .input(z.object({ provider: z.enum(["aws", "azure", "gcp"]).optional() }).optional())
    .query(({ input }) => {
      const checks = input?.provider ? getChecksByProvider(input.provider) : ALL_CIS_CHECKS;
      const techniqueMap = new Map<string, { technique: string; checks: string[]; domains: Set<string> }>();

      for (const check of checks) {
        for (const tech of check.mitreTechniques) {
          if (!techniqueMap.has(tech)) {
            techniqueMap.set(tech, { technique: tech, checks: [], domains: new Set() });
          }
          const entry = techniqueMap.get(tech)!;
          entry.checks.push(check.id);
          entry.domains.add(check.domain);
        }
      }

      return {
        techniques: Array.from(techniqueMap.entries()).map(([id, data]) => ({
          techniqueId: id,
          checkCount: data.checks.length,
          checks: data.checks,
          domains: Array.from(data.domains),
        })),
        totalTechniques: techniqueMap.size,
        totalChecks: checks.length,
      };
    }),

  /** Get domain breakdown for a provider */
  getDomainBreakdown: protectedProcedure
    .input(z.object({ provider: z.enum(["aws", "azure", "gcp"]) }))
    .query(({ input }) => {
      const domains: CheckDomain[] = ["iam", "networking", "storage", "compute", "logging"];
      return {
        provider: input.provider,
        domains: domains.map(domain => {
          const checks = getChecksByDomain(input.provider, domain);
          return {
            domain,
            totalChecks: checks.length,
            bySeverity: {
              critical: checks.filter(c => c.severity === "critical").length,
              high: checks.filter(c => c.severity === "high").length,
              medium: checks.filter(c => c.severity === "medium").length,
              low: checks.filter(c => c.severity === "low").length,
            },
          };
        }),
      };
    }),
});
