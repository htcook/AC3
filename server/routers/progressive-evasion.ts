// @ts-nocheck
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

const evasionLevelSchema = z.enum(["stealth", "low", "medium", "aggressive", "noisy"]);

const evasionOverridesSchema = z.object({
  nmapTiming: z.string().optional(),
  requestsPerSecond: z.number().min(1).max(1000).optional(),
  delayBetweenRequestsMs: z.number().min(0).optional(),
  jitterRangeMs: z.number().min(0).optional(),
  fragmentation: z.boolean().optional(),
  decoys: z.boolean().optional(),
  randomizeHosts: z.boolean().optional(),
  dataLengthPadding: z.boolean().optional(),
  sourcePortSpoofing: z.boolean().optional(),
  userAgentStrategy: z.enum(["browser_mimic", "scanner", "bot", "custom"]).optional(),
  customUserAgent: z.string().optional(),
  encodingTricks: z.array(z.string()).optional(),
  headerManipulation: z.boolean().optional(),
  chunkedTransfer: z.boolean().optional(),
  useHttp2: z.boolean().optional(),
  ipRotation: z.enum(["none", "proxy_chain", "tor"]).optional(),
  scanBatchSize: z.number().min(1).max(500).optional(),
  cooldownBetweenBatchesMs: z.number().min(0).optional(),
  maxConcurrentTargets: z.number().min(1).max(50).optional(),
  autoEscalate: z.boolean().optional(),
  customNmapFlags: z.array(z.string()).optional(),
  nucleiRateLimit: z.number().min(1).optional(),
  httpxThreads: z.number().min(1).optional(),
}).strict();

const pipelineConfigSchema = z.object({
  pauseBetweenScans: z.boolean().optional(),
  pauseBeforeExploit: z.boolean().optional(),
  pauseOnDetection: z.boolean().optional(),
  requireClientApproval: z.boolean().optional(),
}).strict();

export const progressiveEvasionRouter = router({
  /**
   * Get all available evasion levels with descriptions (for UI dropdown/selector).
   */
  getEvasionLevels: protectedProcedure.query(async () => {
    const { getEvasionLevels } = await import("../lib/progressive-evasion-pipeline");
    return getEvasionLevels();
  }),

  /**
   * Initialize the progressive evasion pipeline for an engagement.
   * Called when starting a pentest or red_team engagement.
   */
  initPipeline: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      engagementType: z.enum(["pentest", "red_team"]),
      startingLevel: evasionLevelSchema.default("stealth"),
      config: pipelineConfigSchema.optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { initProgressiveEvasion } = await import("../lib/progressive-evasion-pipeline");
      const state = initProgressiveEvasion(
        input.engagementId,
        input.engagementType,
        input.startingLevel,
        String(ctx.user.id),
        input.config
      );
      return {
        success: true,
        currentLevel: state.currentLevel,
        pipelineConfig: state.pipelineConfig,
      };
    }),

  /**
   * Get the current progressive evasion state for an engagement.
   */
  getState: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      const state = getProgressiveEvasionState(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No progressive evasion pipeline found for this engagement" });
      return {
        currentLevel: state.currentLevel,
        overrides: state.overrides,
        levelHistory: state.levelHistory,
        detectionEvents: state.detectionEvents.slice(-50), // Last 50
        targetDetectionMap: state.targetDetectionMap,
        pendingGates: state.pauseGates.filter(g => g.status === "pending"),
        resolvedGates: state.pauseGates.filter(g => g.status === "resolved").slice(-20),
        scanHistory: state.scanHistory.slice(-20),
        autoEscalateEnabled: state.autoEscalateEnabled,
        pipelineConfig: state.pipelineConfig,
      };
    }),

  /**
   * Get the effective evasion config (base level + overrides merged).
   * This is what scan tools will actually use.
   */
  getEffectiveConfig: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getEffectiveEvasionConfig, getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      const state = getProgressiveEvasionState(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No progressive evasion pipeline found" });
      const config = getEffectiveEvasionConfig(input.engagementId);
      return {
        currentLevel: state.currentLevel,
        hasOverrides: Object.keys(state.overrides).length > 0,
        overrides: state.overrides,
        effectiveConfig: config,
      };
    }),

  /**
   * Change the evasion level (escalate or de-escalate).
   */
  changeLevel: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      newLevel: evasionLevelSchema,
      reason: z.string().min(1).max(500),
      currentPhase: z.string().default("manual_change"),
    }))
    .mutation(async ({ input, ctx }) => {
      const { changeEvasionLevel, getEffectiveEvasionConfig } = await import("../lib/progressive-evasion-pipeline");
      const result = changeEvasionLevel(
        input.engagementId,
        input.newLevel,
        String(ctx.user.id),
        input.reason,
        input.currentPhase
      );
      if (!result.success) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      const effectiveConfig = getEffectiveEvasionConfig(input.engagementId);
      return { ...result, effectiveConfig };
    }),

  /**
   * Update evasion overrides (fine-tune individual settings within current level).
   */
  updateOverrides: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      overrides: evasionOverridesSchema,
    }))
    .mutation(async ({ input }) => {
      const { updateEvasionOverrides } = await import("../lib/progressive-evasion-pipeline");
      const result = updateEvasionOverrides(input.engagementId, input.overrides);
      if (!result.success) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return result;
    }),

  /**
   * Reset all overrides back to the base level defaults.
   */
  resetOverrides: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { resetEvasionOverrides, getEffectiveEvasionConfig } = await import("../lib/progressive-evasion-pipeline");
      const success = resetEvasionOverrides(input.engagementId);
      if (!success) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return { success: true, effectiveConfig: getEffectiveEvasionConfig(input.engagementId) };
    }),

  /**
   * Get the nmap flags that would be generated from current evasion config.
   * Useful for operator preview before running a scan.
   */
  previewNmapFlags: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      /** Preview for a specific level (without changing current) */
      previewLevel: evasionLevelSchema.optional(),
    }))
    .query(async ({ input }) => {
      const { getEffectiveEvasionConfig, evasionToNmapFlags, EVASION_LEVELS } = await import("../lib/progressive-evasion-pipeline");
      let config;
      if (input.previewLevel) {
        config = { ...EVASION_LEVELS[input.previewLevel] };
      } else {
        config = getEffectiveEvasionConfig(input.engagementId);
      }
      const flags = evasionToNmapFlags(config);
      return {
        flags,
        commandPreview: `nmap ${flags.join(" ")} <targets>`,
        level: input.previewLevel || "current",
      };
    }),

  /**
   * Get nuclei config that would be generated from current evasion config.
   */
  previewNucleiConfig: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      previewLevel: evasionLevelSchema.optional(),
    }))
    .query(async ({ input }) => {
      const { getEffectiveEvasionConfig, evasionToNucleiConfig, EVASION_LEVELS, getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      let config;
      const state = getProgressiveEvasionState(input.engagementId);
      if (input.previewLevel) {
        config = { ...EVASION_LEVELS[input.previewLevel] };
      } else {
        config = getEffectiveEvasionConfig(input.engagementId);
      }
      return evasionToNucleiConfig(config, state?.overrides);
    }),

  /**
   * Resolve a pipeline pause gate with the operator's decision.
   */
  resolveGate: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      gateId: z.string(),
      action: z.enum([
        "resume", "rescan_same_level", "rescan_different_level",
        "escalate", "deescalate", "upload_manual_results",
        "send_to_client", "skip_phase", "abort"
      ]),
      newEvasionLevel: evasionLevelSchema.optional(),
      newOverrides: evasionOverridesSchema.optional(),
      notes: z.string().max(2000).optional(),
      manualResultsUploaded: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { resolvePauseGate } = await import("../lib/progressive-evasion-pipeline");
      const result = resolvePauseGate(input.engagementId, input.gateId, {
        action: input.action,
        operatorId: String(ctx.user.id),
        newEvasionLevel: input.newEvasionLevel,
        newOverrides: input.newOverrides,
        notes: input.notes,
        manualResultsUploaded: input.manualResultsUploaded,
      });
      if (!result.success) throw new TRPCError({ code: "BAD_REQUEST", message: result.error });
      return result;
    }),

  /**
   * Get detection summary — shows which targets were detected at which levels.
   */
  getDetectionSummary: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getDetectionSummary } = await import("../lib/progressive-evasion-pipeline");
      const summary = getDetectionSummary(input.engagementId);
      if (!summary) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return summary;
    }),

  /**
   * Record a detection event manually (operator observed a block).
   */
  recordDetection: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      target: z.string(),
      evasionLevel: evasionLevelSchema,
      detectedBy: z.enum(["waf", "ids", "ips", "rate_limiter", "captcha", "ip_ban", "siem", "unknown"]),
      detectionProduct: z.string().optional(),
      evidence: z.string(),
      statusCode: z.number().optional(),
      responseSnippet: z.string().max(2000).optional(),
      scanTool: z.string(),
      impact: z.enum(["scan_blocked", "scan_degraded", "scan_unaffected"]),
      notes: z.string().max(2000).optional(),
    }))
    .mutation(async ({ input }) => {
      const { recordDetection } = await import("../lib/progressive-evasion-pipeline");
      const event = recordDetection(input.engagementId, {
        ...input,
        timestamp: Date.now(),
      });
      if (!event) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return event;
    }),

  /**
   * Update pipeline configuration (pause settings).
   */
  updatePipelineConfig: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      config: pipelineConfigSchema,
    }))
    .mutation(async ({ input }) => {
      const { getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      const state = getProgressiveEvasionState(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      Object.assign(state.pipelineConfig, input.config);
      return { success: true, pipelineConfig: state.pipelineConfig };
    }),

  /**
   * Get scan history with evasion levels used (for operator review of what worked).
   */
  getScanHistory: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const { getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      const state = getProgressiveEvasionState(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return state.scanHistory.slice(-input.limit);
    }),

  // ─── wafw00f WAF Fingerprinting ────────────────────────────────────

  /**
   * Trigger wafw00f scan against one or more targets.
   * Dispatches wafw00f via scan-server-executor and stores results in pipeline state.
   * Creates a pause gate if WAF is detected with high confidence.
   */
  triggerWafw00fScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().url()).min(1).max(50),
      /** Optional header-based WAF results to merge with wafw00f output */
      headerResults: z.record(
        z.string(),
        z.object({
          detected: z.boolean(),
          vendor: z.string().nullable(),
          confidence: z.number(),
          bypassTechniques: z.array(z.string()),
        })
      ).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runWafw00fBatch, getProgressiveEvasionState } = await import("../lib/progressive-evasion-pipeline");
      const state = getProgressiveEvasionState(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No progressive evasion pipeline found. Initialize the pipeline first." });

      const results = await runWafw00fBatch(
        input.engagementId,
        input.targets,
        input.headerResults
      );

      const detected = results.filter(r => r.detected);
      const errors = results.filter(r => !!r.error);

      return {
        success: true,
        totalScanned: results.length,
        wafDetected: detected.length,
        errors: errors.length,
        results: results.map(r => ({
          target: r.target,
          detected: r.detected,
          wafName: r.wafName,
          manufacturer: r.manufacturer,
          combinedConfidence: r.combinedConfidence,
          methodsAgree: r.methodsAgree,
          allDetected: r.allDetected,
          error: r.error,
        })),
      };
    }),

  /**
   * Get wafw00f fingerprint results for an engagement.
   */
  getWafFingerprints: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getWafFingerprintResults } = await import("../lib/progressive-evasion-pipeline");
      const results = getWafFingerprintResults(input.engagementId);
      if (!results) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return results;
    }),

  /**
   * Get a summary of WAF fingerprinting across all targets.
   */
  getWafFingerprintSummary: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getWafFingerprintSummary } = await import("../lib/progressive-evasion-pipeline");
      const summary = getWafFingerprintSummary(input.engagementId);
      if (!summary) throw new TRPCError({ code: "NOT_FOUND", message: "No pipeline found" });
      return summary;
    }),
});
