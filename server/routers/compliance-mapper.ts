/**
 * Compliance Framework Mapping Router
 * Manages compliance frameworks (SOC 2, ISO 27001, NIST CSF, PCI DSS, FedRAMP, DoD STIG, CMMC),
 * control mappings, gap analysis, and compliance report generation.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  ALL_FRAMEWORKS,
  autoMapFindings,
  calculateComplianceScore,
} from "../lib/compliance-mapper";

const frameworkTypeEnum = z.enum(["soc2", "iso27001", "nist_csf", "pci_dss", "hipaa", "cis", "fedramp", "dod_stig", "cmmc", "custom"]);

export const complianceMapperRouter = router({
  /** Get all built-in framework definitions */
  getFrameworkCatalog: protectedProcedure.query(() => {
    return Object.entries(ALL_FRAMEWORKS).map(([key, fw]) => ({
      key,
      name: fw.name,
      version: fw.version,
      controlCount: fw.controls.length,
    }));
  }),

  /** Get controls for a specific built-in framework */
  getFrameworkControls: protectedProcedure
    .input(z.object({ frameworkKey: z.string() }))
    .query(({ input }) => {
      const fw = ALL_FRAMEWORKS[input.frameworkKey as keyof typeof ALL_FRAMEWORKS];
      if (!fw) throw new TRPCError({ code: "NOT_FOUND", message: "Framework not found" });
      return { name: fw.name, version: fw.version, controls: fw.controls };
    }),

  /** Auto-map findings to a framework */
  autoMap: protectedProcedure
    .input(z.object({
      frameworkKey: z.enum(["soc2", "iso27001", "nist_csf", "pci_dss", "fedramp", "dod_stig", "cmmc"]),
      findings: z.array(z.object({
        type: z.string(),
        severity: z.string(),
        category: z.string(),
      })),
    }))
    .mutation(({ input }) => {
      const mappings = autoMapFindings(input.frameworkKey, input.findings);
      const score = calculateComplianceScore(mappings);
      return { mappings, score };
    }),

  /** List configured frameworks from database */
  listFrameworks: protectedProcedure
    .input(z.object({ activeOnly: z.boolean().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceFrameworks } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input?.activeOnly
        ? db.select().from(complianceFrameworks).where(eq(complianceFrameworks.isActive, true))
        : db.select().from(complianceFrameworks);
      return await query;
    }),

  /** Add a framework configuration to the database */
  addFramework: protectedProcedure
    .input(z.object({
      frameworkName: z.string(),
      frameworkVersion: z.string().optional(),
      frameworkType: frameworkTypeEnum,
      description: z.string().optional(),
      totalControls: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceFrameworks } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(complianceFrameworks).values({
        frameworkName: input.frameworkName,
        frameworkVersion: input.frameworkVersion ?? null,
        frameworkType: input.frameworkType,
        description: input.description ?? null,
        totalControls: input.totalControls ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List compliance mappings for an engagement */
  listMappings: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      controlId: z.number().optional(),
      status: z.enum(["covered", "gap", "partial", "not_applicable", "compensating"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceMappings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and } = await import("drizzle-orm");

      const conditions = [];
      if (input.engagementId) conditions.push(eq(complianceMappings.engagementId, input.engagementId));
      if (input.controlId) conditions.push(eq(complianceMappings.controlId, input.controlId));
      if (input.status) conditions.push(eq(complianceMappings.mappingStatus, input.status));

      return conditions.length > 0
        ? await db.select().from(complianceMappings).where(and(...conditions))
        : await db.select().from(complianceMappings);
    }),

  /** Create a compliance mapping */
  createMapping: protectedProcedure
    .input(z.object({
      controlId: z.number(),
      engagementId: z.number().optional(),
      findingType: z.string().optional(),
      findingId: z.number().optional(),
      findingSource: z.enum(["vulnerability", "misconfiguration", "attack_path", "edr_test", "pentest", "manual"]),
      mappingStatus: z.enum(["covered", "gap", "partial", "not_applicable", "compensating"]),
      evidenceNotes: z.string().optional(),
      compensatingControl: z.string().optional(),
      assessedBy: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { complianceMappings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(complianceMappings).values({
        controlId: input.controlId,
        engagementId: input.engagementId ?? null,
        findingType: input.findingType ?? null,
        findingId: input.findingId ?? null,
        findingSource: input.findingSource,
        mappingStatus: input.mappingStatus,
        evidenceNotes: input.evidenceNotes ?? null,
        compensatingControl: input.compensatingControl ?? null,
        assessedBy: input.assessedBy ?? ctx.user.name ?? null,
        assessedAt: new Date(),
      });
      return { id: result.insertId, success: true };
    }),

  /** List compliance reports */
  listReports: protectedProcedure
    .input(z.object({ engagementId: z.number().optional(), frameworkId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceReports } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.engagementId) conditions.push(eq(complianceReports.engagementId, input.engagementId));
      if (input?.frameworkId) conditions.push(eq(complianceReports.frameworkId, input.frameworkId));

      return conditions.length > 0
        ? await db.select().from(complianceReports).where(and(...conditions)).orderBy(desc(complianceReports.createdAt))
        : await db.select().from(complianceReports).orderBy(desc(complianceReports.createdAt));
    }),

  /** Generate a compliance report */
  generateReport: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      frameworkId: z.number(),
      reportName: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { complianceMappings, complianceReports } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and } = await import("drizzle-orm");

      // Get all mappings for this engagement and framework's controls
      const mappings = await db.select().from(complianceMappings)
        .where(eq(complianceMappings.engagementId, input.engagementId));

      const score = calculateComplianceScore(mappings.map(m => ({ status: m.mappingStatus })));

      const [result] = await db.insert(complianceReports).values({
        engagementId: input.engagementId,
        frameworkId: input.frameworkId,
        reportName: input.reportName,
        totalControls: score.covered + score.gap + score.partial + score.na,
        coveredControls: score.covered,
        gapControls: score.gap,
        partialControls: score.partial,
        naControls: score.na,
        overallScore: score.score,
        reportData: { mappings, score },
        generatedBy: ctx.user.name ?? ctx.user.openId,
      });
      return { id: result.insertId, score, success: true };
    }),

  /** Get compliance statistics */
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { complianceFrameworks, complianceMappings, complianceReports } = await import("../../drizzle/schema");
    const { count } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const [fwCount] = await db.select({ count: count() }).from(complianceFrameworks);
    const [mapCount] = await db.select({ count: count() }).from(complianceMappings);
    const [rptCount] = await db.select({ count: count() }).from(complianceReports);

    return {
      totalFrameworks: fwCount.count,
      totalMappings: mapCount.count,
      totalReports: rptCount.count,
      builtInFrameworks: Object.keys(ALL_FRAMEWORKS).length,
      totalBuiltInControls: Object.values(ALL_FRAMEWORKS).reduce((sum, fw) => sum + fw.controls.length, 0),
    };
  }),
});
