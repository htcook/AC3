import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";

export const compensatingControlsRouter = router({
  /**
   * Evaluate compensating controls for a given vulnerability/finding
   */
  evaluate: protectedProcedure
    .input(z.object({
      cveId: z.string().optional(),
      techniqueId: z.string().optional(),
      targetService: z.string().optional(),
      targetPort: z.number().optional(),
      existingControls: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { evaluateCompensatingControls } = await import("../lib/compensating-controls");
      return evaluateCompensatingControls({
        cveId: input.cveId,
        techniqueId: input.techniqueId,
        targetService: input.targetService,
        targetPort: input.targetPort,
        existingControls: input.existingControls || [],
      });
    }),

  /**
   * Get the full control catalog
   */
  getCatalog: protectedProcedure.query(async () => {
    const { getControlCatalog } = await import("../lib/compensating-controls");
    return getControlCatalog();
  }),

  /**
   * Calculate risk adjustment based on active controls
   */
  calculateRiskAdjustment: protectedProcedure
    .input(z.object({
      baseRiskScore: z.number().min(0).max(10),
      activeControlIds: z.array(z.string()).min(1),
    }))
    .mutation(async ({ input }) => {
      const { calculateRiskAdjustment } = await import("../lib/compensating-controls");
      return calculateRiskAdjustment(input.baseRiskScore, input.activeControlIds);
    }),

  // ─── Control Testing Endpoints ────────────────────────────────────

  /**
   * Get all supported control categories with test coverage info
   */
  getSupportedTestCategories: protectedProcedure.query(async () => {
    const { getSupportedControlCategories } = await import("../lib/control-testing-engine");
    return getSupportedControlCategories();
  }),

  /**
   * Generate a test suite for a specific compensating control
   */
  generateTestSuite: protectedProcedure
    .input(z.object({
      controlCategory: z.string(),
      controlName: z.string(),
      includeCategories: z.array(z.enum([
        "technique_validation",
        "configuration_audit",
        "bypass_resistance",
        "coverage_gap",
        "degradation_test",
      ])).optional(),
      excludeManual: z.boolean().optional(),
      maxRiskLevel: z.enum(["low", "medium", "high"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { generateTestSuite } = await import("../lib/control-testing-engine");
      return generateTestSuite(input.controlCategory, input.controlName, {
        includeCategories: input.includeCategories,
        excludeManual: input.excludeManual,
        maxRiskLevel: input.maxRiskLevel,
      });
    }),

  /**
   * Execute a single test case against a compensating control
   */
  executeTest: protectedProcedure
    .input(z.object({
      testCase: z.object({
        testId: z.string(),
        controlCategory: z.string(),
        controlName: z.string(),
        testCategory: z.enum([
          "technique_validation",
          "configuration_audit",
          "bypass_resistance",
          "coverage_gap",
          "degradation_test",
        ]),
        title: z.string(),
        description: z.string(),
        procedure: z.string(),
        expectedOutcome: z.string(),
        failureCriteria: z.string(),
        mitreTechniques: z.array(z.string()),
        nistControls: z.array(z.string()),
        automatable: z.boolean(),
        estimatedDuration: z.string(),
        prerequisites: z.array(z.string()),
        riskLevel: z.enum(["low", "medium", "high"]),
      }),
      environment: z.string(),
      controlConfig: z.record(z.any()).optional(),
      previousEvidenceHash: z.string().nullable().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { executeTest } = await import("../lib/control-testing-engine");
      return executeTest(input.testCase, {
        executedBy: ctx.user?.openId || "unknown",
        environment: input.environment,
        controlConfig: input.controlConfig,
        previousEvidenceHash: input.previousEvidenceHash || null,
      });
    }),

  /**
   * Run a full test suite and produce a complete validation report
   */
  runFullTestSuite: protectedProcedure
    .input(z.object({
      controlCategory: z.string(),
      controlName: z.string(),
      environment: z.string(),
      controlConfig: z.record(z.any()).optional(),
      includeCategories: z.array(z.enum([
        "technique_validation",
        "configuration_audit",
        "bypass_resistance",
        "coverage_gap",
        "degradation_test",
      ])).optional(),
      excludeManual: z.boolean().optional(),
      maxRiskLevel: z.enum(["low", "medium", "high"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { generateTestSuite, runTestSuite } = await import("../lib/control-testing-engine");
      const suite = generateTestSuite(input.controlCategory, input.controlName, {
        includeCategories: input.includeCategories,
        excludeManual: input.excludeManual,
        maxRiskLevel: input.maxRiskLevel,
      });
      return runTestSuite(suite, {
        executedBy: ctx.user?.openId || "unknown",
        environment: input.environment,
        controlConfig: input.controlConfig,
      });
    }),

  /**
   * Export a validation report as Markdown for auditor review
   */
  exportReportMarkdown: protectedProcedure
    .input(z.object({
      reportData: z.any(), // Full ValidationReport object
    }))
    .mutation(async ({ input }) => {
      const { exportReportAsMarkdown } = await import("../lib/control-testing-engine");
      return { markdown: exportReportAsMarkdown(input.reportData) };
    }),

  /**
   * Export evidence records as CSV for auditor import
   */
  exportEvidenceCSV: protectedProcedure
    .input(z.object({
      reportData: z.any(), // Full ValidationReport object
    }))
    .mutation(async ({ input }) => {
      const { exportEvidenceAsCSV } = await import("../lib/control-testing-engine");
      return { csv: exportEvidenceAsCSV(input.reportData) };
    }),

  /**
   * Verify the integrity of an evidence chain
   */
  verifyEvidenceChain: protectedProcedure
    .input(z.object({
      evidenceRecords: z.array(z.object({
        evidenceId: z.string(),
        executionId: z.string(),
        timestamp: z.string(),
        type: z.string(),
        classification: z.string(),
        title: z.string(),
        content: z.string(),
        contentHash: z.string(),
        previousHash: z.string().nullable(),
        chainHash: z.string(),
        collector: z.string(),
        retentionDays: z.number(),
        metadata: z.record(z.any()),
      })),
    }))
    .mutation(async ({ input }) => {
      const { verifyEvidenceChain } = await import("../lib/control-testing-engine");
      return verifyEvidenceChain(input.evidenceRecords);
    }),
});
