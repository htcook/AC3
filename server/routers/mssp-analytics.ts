import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import {
  PRICING_TIERS,
  getPricingTier,
  calculateTenantCost,
  calculateRiskScore,
  getRiskLevel,
  buildCrossTenantSummary,
  SLA_DEFINITIONS,
  checkSLACompliance,
  buildExecutiveReport,
  type RiskFactors,
  type TenantSecurityPosture,
  type UsageMeter,
} from "../lib/mssp-analytics";

export const msspAnalyticsRouter = router({
  /** Get all pricing tiers */
  listPricingTiers: protectedProcedure.query(() => {
    return PRICING_TIERS;
  }),

  /** Get a specific pricing tier */
  getPricingTier: protectedProcedure
    .input(z.object({ tierId: z.string() }))
    .query(({ input }) => {
      const tier = getPricingTier(input.tierId);
      if (!tier) throw new Error(`Pricing tier not found: ${input.tierId}`);
      return tier;
    }),

  /** Calculate cost for a tenant's usage */
  calculateCost: protectedProcedure
    .input(z.object({
      tierId: z.string(),
      scansRun: z.number().min(0),
      llmCallsMade: z.number().min(0),
      llmTokensUsed: z.number().min(0),
      storageUsedMb: z.number().min(0),
      agentHours: z.number().min(0),
      engagementsCreated: z.number().min(0),
      reportsGenerated: z.number().min(0),
      apiCallsMade: z.number().min(0),
    }))
    .query(({ input }) => {
      const { tierId, ...usage } = input;
      return {
        estimatedCost: calculateTenantCost(
          { ...usage, tenantId: 0, tenantName: "", period: "" } as any,
          tierId,
        ),
        tier: getPricingTier(tierId),
      };
    }),

  /** Calculate risk score for a tenant */
  calculateRisk: protectedProcedure
    .input(z.object({
      criticalVulns: z.number().min(0),
      highVulns: z.number().min(0),
      mediumVulns: z.number().min(0),
      lowVulns: z.number().min(0),
      daysSinceLastAssessment: z.number().nullable(),
      owaspCoveragePercent: z.number().min(0).max(100),
      agentCoverage: z.number().min(0).max(1),
      complianceGaps: z.number().min(0),
      exposedServices: z.number().min(0),
      unpatched: z.number().min(0),
    }))
    .query(({ input }) => {
      const score = calculateRiskScore(input as RiskFactors);
      return { score, level: getRiskLevel(score) };
    }),

  /** Build cross-tenant security summary */
  getCrossTenantSummary: adminProcedure
    .input(z.object({
      tenantPostures: z.array(z.object({
        tenantId: z.number(),
        tenantName: z.string(),
        riskScore: z.number(),
        riskLevel: z.enum(["critical", "high", "medium", "low"]),
        openVulnerabilities: z.object({
          critical: z.number(),
          high: z.number(),
          medium: z.number(),
          low: z.number(),
        }),
        lastEngagement: z.number().nullable(),
        lastScan: z.number().nullable(),
        agentsDeployed: z.number(),
        agentsActive: z.number(),
        owaspCoverageScore: z.number(),
        complianceStatus: z.enum(["compliant", "at_risk", "non_compliant"]),
        daysSinceLastAssessment: z.number().nullable(),
      })),
    }))
    .query(({ input }) => {
      return buildCrossTenantSummary(input.tenantPostures as TenantSecurityPosture[]);
    }),

  /** Get SLA definitions */
  listSLADefinitions: protectedProcedure.query(() => {
    return SLA_DEFINITIONS;
  }),

  /** Check SLA compliance for a tenant */
  checkSLA: protectedProcedure
    .input(z.object({
      tenantId: z.number(),
      tenantName: z.string(),
      lastAssessmentDate: z.number().nullable(),
      lastReportDate: z.number().nullable(),
      openCriticalFindings: z.array(z.object({
        foundAt: z.number(),
        resolvedAt: z.number().nullable(),
      })),
      slaTargets: z.record(z.number()).optional(),
    }))
    .query(({ input }) => {
      return checkSLACompliance(
        input.tenantId,
        input.tenantName,
        input.lastAssessmentDate,
        input.lastReportDate,
        input.openCriticalFindings,
        input.slaTargets as any,
      );
    }),

  /** Generate executive report data */
  generateExecutiveReport: adminProcedure
    .input(z.object({
      period: z.string(),
      tenantPostures: z.array(z.any()),
      slaStatuses: z.array(z.any()).default([]),
    }))
    .mutation(({ input }) => {
      const summary = buildCrossTenantSummary(input.tenantPostures as TenantSecurityPosture[]);
      return buildExecutiveReport(summary, null, input.slaStatuses as any[], input.period);
    }),
});
