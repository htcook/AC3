/**
 * AI Security Validation Router
 * ──────────────────────────────
 * tRPC procedures for MITRE ATLAS-aligned AI/LLM security testing.
 *
 * Author: Harrison Cook — AceofCloud
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  startAISecurityScan,
  getScanResult,
  getAllScans,
  deleteScan,
  runQuickAssessment,
  getATLASTechniques,
  getTestPayloadsByCategory,
  getCategoryDescriptions,
  ATLAS_TECHNIQUES,
  PROMPT_INJECTION_PAYLOADS,
  MODEL_EXTRACTION_PAYLOADS,
  ADVERSARIAL_EVASION_PAYLOADS,
  DATA_POISONING_PAYLOADS,
  SUPPLY_CHAIN_PAYLOADS,
  type AITargetConfig,
  type TestCategory,
} from "../lib/ai-security-validation";

const testCategoryEnum = z.enum([
  "prompt-injection",
  "model-extraction",
  "adversarial-evasion",
  "data-poisoning",
  "supply-chain",
  "model-inversion",
  "membership-inference",
  "denial-of-service",
]);

export const aiSecurityValidationRouter = router({
  /**
   * Get the full MITRE ATLAS technique catalog
   */
  getTechniques: protectedProcedure.query(() => {
    return getATLASTechniques();
  }),

  /**
   * Get test payloads grouped by category
   */
  getPayloads: protectedProcedure.query(() => {
    return getTestPayloadsByCategory();
  }),

  /**
   * Get category descriptions for UI display
   */
  getCategories: protectedProcedure.query(() => {
    return getCategoryDescriptions();
  }),

  /**
   * Get dashboard overview stats
   */
  getOverview: protectedProcedure.query(() => {
    const scans = getAllScans();
    const totalPayloads =
      PROMPT_INJECTION_PAYLOADS.length +
      MODEL_EXTRACTION_PAYLOADS.length +
      ADVERSARIAL_EVASION_PAYLOADS.length +
      DATA_POISONING_PAYLOADS.length +
      SUPPLY_CHAIN_PAYLOADS.length;

    const completedScans = scans.filter(s => s.status === "completed");
    const avgScore = completedScans.length > 0
      ? Math.round(completedScans.reduce((sum, s) => sum + s.postureScore.overall, 0) / completedScans.length)
      : null;

    return {
      totalTechniques: ATLAS_TECHNIQUES.length,
      totalPayloads,
      totalScans: scans.length,
      completedScans: completedScans.length,
      runningScans: scans.filter(s => s.status === "running").length,
      averagePostureScore: avgScore,
      recentScans: scans.slice(0, 5).map(s => ({
        scanId: s.scanId,
        targetName: s.targetName,
        status: s.status,
        postureScore: s.postureScore,
        startedAt: s.startedAt,
        completedAt: s.completedAt,
      })),
    };
  }),

  /**
   * Start a full AI security validation scan against a target endpoint
   */
  startScan: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
      type: z.enum(["llm-api", "chat-endpoint", "classification-api", "embedding-api", "rag-system", "custom"]),
      endpoint: z.string().url(),
      auth: z.object({
        type: z.enum(["bearer", "api-key", "basic", "none"]),
        token: z.string().optional(),
        headerName: z.string().optional(),
      }).optional(),
      requestFormat: z.object({
        method: z.enum(["POST", "GET"]).default("POST"),
        bodyTemplate: z.string().optional(),
        contentType: z.string().optional(),
        responseField: z.string().optional(),
      }).optional(),
      enabledCategories: z.array(testCategoryEnum).optional(),
      maxConcurrency: z.number().min(1).max(10).optional(),
      timeoutMs: z.number().min(5000).max(120000).optional(),
    }))
    .mutation(async ({ input }) => {
      const target: AITargetConfig = {
        name: input.name,
        type: input.type,
        endpoint: input.endpoint,
        auth: input.auth,
        requestFormat: input.requestFormat,
        enabledCategories: input.enabledCategories as TestCategory[] | undefined,
        maxConcurrency: input.maxConcurrency,
        timeoutMs: input.timeoutMs,
      };

      const scan = await startAISecurityScan(target);
      return { scanId: scan.scanId, status: scan.status, totalTests: scan.totalTests };
    }),

  /**
   * Get scan status and results
   */
  getScan: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const scan = getScanResult(input.scanId);
      if (!scan) return null;
      return scan;
    }),

  /**
   * List all scans
   */
  listScans: protectedProcedure.query(() => {
    return getAllScans().map(s => ({
      scanId: s.scanId,
      targetName: s.targetName,
      targetType: s.targetType,
      status: s.status,
      totalTests: s.totalTests,
      completedTests: s.completedTests,
      postureScore: s.postureScore,
      summary: s.summary,
      startedAt: s.startedAt,
      completedAt: s.completedAt,
    }));
  }),

  /**
   * Delete a scan
   */
  deleteScan: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .mutation(({ input }) => {
      return { deleted: deleteScan(input.scanId) };
    }),

  /**
   * Run a quick posture assessment (checklist-based, no live endpoint needed)
   */
  quickAssessment: protectedProcedure
    .input(z.object({
      hasInputValidation: z.boolean(),
      hasOutputFiltering: z.boolean(),
      hasRateLimiting: z.boolean(),
      hasModelAccessControls: z.boolean(),
      hasDataProvenance: z.boolean(),
      hasDependencyScanning: z.boolean(),
      hasPromptGuardrails: z.boolean(),
      hasAuditLogging: z.boolean(),
      hasAdversarialTesting: z.boolean(),
      hasIncidentResponse: z.boolean(),
    }))
    .mutation(({ input }) => {
      return runQuickAssessment(input);
    }),
});
