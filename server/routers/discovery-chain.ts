/**
 * Discovery Chain Router
 * 
 * tRPC endpoints for the automated discovery chain orchestrator:
 * - Start a new chain run (Amass → Nmap → Service Fingerprinter → Nuclei)
 * - Get chain run status and progress (with DB fallback)
 * - Cancel a running chain
 * - Get chain run history (DB-backed with pagination)
 * - Get chain stage definitions
 * - Estimate chain duration
 * - Get data flow between stages
 * 
 * Each chain run automatically sequences discovery tools, feeding
 * each stage's output into the next stage's input with scope enforcement
 * at every boundary. Results are persisted to the database.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";
import {
  createChainRun,
  getChainRun,
  getChainRuns,
  cancelChainRun,
  executeChain,
  getChainStageDefinitions,
  estimateChainDuration,
  extractNmapTargetsFromAmass,
  extractFingerprintTargetsFromNmap,
  extractNucleiTargetsFromResults,
  selectNucleiTemplates,
  type ChainRunConfig,
  type ChainRunStatus,
  type ChainExecutionCallbacks,
} from "../lib/discovery-chain-orchestrator";
import { buildPersistentCallbacks } from "../lib/chain-execution-callbacks";
import {
  insertChainRun as insertChainRunDb,
  updateChainRunDb,
  getChainRunByChainId,
  listChainRunsDb,
  getChainStageResultsDb,
  deleteChainRunDb,
} from "../db";

// ─── Input Schemas ──────────────────────────────────────────────────

const chainStageIdSchema = z.enum(["amass", "nmap", "service_fingerprinter", "nuclei", "service_audit"]);

const chainRunConfigSchema = z.object({
  domains: z.array(z.string().min(1)).min(1).max(20),
  seedIps: z.array(z.string()).optional(),
  seedUrls: z.array(z.string()).optional(),
  engagementId: z.number().int().positive().optional(),
  skipStages: z.array(chainStageIdSchema).optional(),
  stageConfig: z.object({
    amass: z.object({
      mode: z.enum(["passive", "active"]).optional(),
      timeout: z.number().int().positive().optional(),
      maxSubdomains: z.number().int().positive().optional(),
    }).optional(),
    nmap: z.object({
      profile: z.enum(["quick", "standard", "deep", "stealth", "service", "vuln"]).optional(),
      topPorts: z.number().int().min(1).max(65535).optional(),
      timeout: z.number().int().positive().optional(),
    }).optional(),
    service_fingerprinter: z.object({
      timeout: z.number().int().positive().optional(),
      concurrency: z.number().int().min(1).max(50).optional(),
      tryDefaultCreds: z.boolean().optional(),
    }).optional(),
    nuclei: z.object({
      severity: z.array(z.enum(["critical", "high", "medium", "low", "info"])).optional(),
      templateCategories: z.array(z.string()).optional(),
      rateLimit: z.number().int().min(1).max(1000).optional(),
      timeout: z.number().int().positive().optional(),
    }).optional(),
  }).optional(),
  maxDurationSec: z.number().int().min(60).max(14400).optional(),
  continueOnPartialFailure: z.boolean().optional(),
});

// ─── Router ─────────────────────────────────────────────────────────

export const discoveryChainRouter = router({
  /**
   * Start a new discovery chain run.
   * Sequences: Amass → Nmap → Service Fingerprinter → Nuclei
   * Uses real tool callbacks and persists results to DB.
   */
  start: protectedProcedure
    .input(chainRunConfigSchema)
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement on initial domains
      if (input.engagementId) {
        await enforceMultiTargetScope(
          input.engagementId,
          input.domains,
          "discovery_chain",
          { user: ctx.user },
        );
      }

      // Create the chain run config
      const config: ChainRunConfig = {
        ...input,
        operatorId: String(ctx.user.id),
      };

      // Build persistent callbacks that wire to real engines + DB
      const callbacks = buildPersistentCallbacks(
        `chain-${Date.now()}`, // temp ID, will be replaced by actual chain ID
        {
          onProgress: (run) => {
            // Could push WebSocket updates here
          },
          onStageComplete: (run, stageId) => {
            console.log(`[DiscoveryChain] Stage ${stageId} completed for chain ${run.id}`);
          },
        }
      );

      // Execute the chain (runs asynchronously for long-running stages)
      const run = await executeChain(config, callbacks);

      // Persist the chain run to DB
      try {
        await insertChainRunDb({
          chainId: run.id,
          status: run.status,
          progress: run.progress,
          currentStage: run.currentStage || null,
          cancelled: run.cancelled || false,
          domains: run.config.domains,
          seedIps: run.config.seedIps || [],
          seedUrls: run.config.seedUrls || [],
          engagementId: run.config.engagementId || null,
          operatorId: run.config.operatorId || null,
          skipStages: run.config.skipStages || [],
          stageConfig: run.config.stageConfig || {},
          maxDurationSec: run.config.maxDurationSec || 3600,
          continueOnPartialFailure: run.config.continueOnPartialFailure || false,
          totalFindings: run.summary?.totalFindings || 0,
          totalSubdomains: run.summary?.totalSubdomains || 0,
          totalHosts: run.summary?.totalHosts || 0,
          totalOpenPorts: run.summary?.totalOpenPorts || 0,
          totalServices: run.summary?.totalServices || 0,
          totalVulnerabilities: run.summary?.totalVulnerabilities || 0,
          findingsBySeverity: run.summary?.findingsBySeverity || {},
          findingsByStage: run.summary?.findingsByStage || {},
          stagesCompleted: run.summary?.stagesCompleted || 0,
          stagesTotal: run.summary?.stagesTotal || 4,
          stagesFailed: run.summary?.stagesFailed || 0,
          stagesSkipped: run.summary?.stagesSkipped || 0,
          uniqueCves: run.summary?.uniqueCves || [],
          attackTechniques: run.summary?.attackTechniques || [],
          startedAt: run.startedAt,
          completedAt: run.completedAt || null,
          durationMs: run.durationMs || null,
        });
      } catch (err) {
        console.warn("[DiscoveryChain] Failed to persist chain run to DB:", err);
      }

      return {
        chainId: run.id,
        status: run.status,
        progress: run.progress,
        stages: run.stages.map(s => ({
          stageId: s.stageId,
          status: s.status,
          inputTargetCount: s.inputTargetCount,
          outputCount: s.outputCount,
          errors: s.errors,
        })),
        summary: run.summary,
      };
    }),

  /**
   * Get the status and results of a chain run.
   * Checks in-memory first, then falls back to DB.
   */
  getStatus: protectedProcedure
    .input(z.object({ chainId: z.string() }))
    .query(async ({ input }) => {
      // Try in-memory first
      const run = getChainRun(input.chainId);
      if (run) {
        return {
          id: run.id,
          status: run.status,
          progress: run.progress,
          currentStage: run.currentStage,
          config: run.config,
          stages: run.stages.map(s => ({
            stageId: s.stageId,
            status: s.status,
            startedAt: s.startedAt,
            completedAt: s.completedAt,
            durationMs: s.durationMs,
            inputTargetCount: s.inputTargetCount,
            outputCount: s.outputCount,
            findingCount: s.findings.length,
            errors: s.errors,
          })),
          summary: run.summary,
          startedAt: run.startedAt,
          completedAt: run.completedAt,
          durationMs: run.durationMs,
          source: "memory" as const,
        };
      }

      // Fall back to DB
      const dbRun = await getChainRunByChainId(input.chainId);
      if (!dbRun) {
        throw new TRPCError({ code: "NOT_FOUND", message: `Chain run ${input.chainId} not found` });
      }

      const dbStages = await getChainStageResultsDb(input.chainId);

      return {
        id: dbRun.chainId,
        status: dbRun.status,
        progress: dbRun.progress,
        currentStage: dbRun.currentStage,
        config: {
          domains: dbRun.domains as string[],
          seedIps: dbRun.seedIps as string[] || [],
          seedUrls: dbRun.seedUrls as string[] || [],
          engagementId: dbRun.engagementId,
          skipStages: dbRun.skipStages as string[] || [],
          stageConfig: dbRun.stageConfig as any || {},
          maxDurationSec: dbRun.maxDurationSec || 3600,
          continueOnPartialFailure: dbRun.continueOnPartialFailure || false,
          operatorId: dbRun.operatorId,
        },
        stages: dbStages.map(s => ({
          stageId: s.stageId,
          status: s.status,
          startedAt: s.startedAt || 0,
          completedAt: s.completedAt || null,
          durationMs: s.durationMs || null,
          inputTargetCount: s.inputTargetCount || 0,
          outputCount: s.outputCount || 0,
          findingCount: s.findingCount || 0,
          errors: s.errors as string[] || [],
        })),
        summary: {
          totalFindings: dbRun.totalFindings || 0,
          totalSubdomains: dbRun.totalSubdomains || 0,
          totalHosts: dbRun.totalHosts || 0,
          totalOpenPorts: dbRun.totalOpenPorts || 0,
          totalServices: dbRun.totalServices || 0,
          totalVulnerabilities: dbRun.totalVulnerabilities || 0,
          findingsBySeverity: dbRun.findingsBySeverity as any || {},
          findingsByStage: dbRun.findingsByStage as any || {},
          stagesCompleted: dbRun.stagesCompleted || 0,
          stagesTotal: dbRun.stagesTotal || 4,
          stagesFailed: dbRun.stagesFailed || 0,
          stagesSkipped: dbRun.stagesSkipped || 0,
          uniqueCves: dbRun.uniqueCves as string[] || [],
          attackTechniques: dbRun.attackTechniques as string[] || [],
        },
        startedAt: dbRun.startedAt,
        completedAt: dbRun.completedAt || null,
        durationMs: dbRun.durationMs || null,
        source: "database" as const,
      };
    }),

  /**
   * Get full findings from a chain run, optionally filtered by stage.
   * Checks in-memory first, then falls back to DB.
   */
  getFindings: protectedProcedure
    .input(z.object({
      chainId: z.string(),
      stageId: chainStageIdSchema.optional(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      limit: z.number().int().min(1).max(500).optional(),
      offset: z.number().int().min(0).optional(),
    }))
    .query(async ({ input }) => {
      // Try in-memory first
      const run = getChainRun(input.chainId);
      if (run) {
        let findings = run.allFindings;
        if (input.stageId) {
          const stage = run.stages.find(s => s.stageId === input.stageId);
          findings = stage ? stage.findings : [];
        }
        if (input.severity) {
          findings = findings.filter(f => f.severity === input.severity);
        }
        const total = findings.length;
        const offset = input.offset || 0;
        const limit = input.limit || 100;
        return { total, findings: findings.slice(offset, offset + limit), source: "memory" as const };
      }

      // Fall back to DB
      const dbStages = await getChainStageResultsDb(input.chainId);
      if (dbStages.length === 0) {
        const dbRun = await getChainRunByChainId(input.chainId);
        if (!dbRun) {
          throw new TRPCError({ code: "NOT_FOUND", message: `Chain run ${input.chainId} not found` });
        }
      }

      let findings: any[] = [];
      for (const stage of dbStages) {
        if (input.stageId && stage.stageId !== input.stageId) continue;
        const stageFindings = (stage.findings as any[]) || [];
        findings.push(...stageFindings);
      }
      if (input.severity) {
        findings = findings.filter(f => f.severity === input.severity);
      }
      const total = findings.length;
      const offset = input.offset || 0;
      const limit = input.limit || 100;
      return { total, findings: findings.slice(offset, offset + limit), source: "database" as const };
    }),

  /**
   * Cancel a running chain.
   */
  cancel: protectedProcedure
    .input(z.object({ chainId: z.string() }))
    .mutation(async ({ input }) => {
      const success = cancelChainRun(input.chainId);
      if (!success) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `Chain run ${input.chainId} cannot be cancelled (not running or not found)`,
        });
      }

      // Update DB
      try {
        await updateChainRunDb(input.chainId, {
          status: "cancelled",
          cancelled: true,
          completedAt: Date.now(),
        });
      } catch (err) {
        console.warn("[DiscoveryChain] Failed to persist cancel to DB:", err);
      }

      return { cancelled: true };
    }),

  /**
   * Delete a chain run from history (DB only).
   */
  delete: protectedProcedure
    .input(z.object({ chainId: z.string() }))
    .mutation(async ({ input }) => {
      await deleteChainRunDb(input.chainId);
      return { deleted: true };
    }),

  /**
   * Get chain run history with optional filtering.
   * Returns DB-backed results with pagination.
   */
  getHistory: protectedProcedure
    .input(z.object({
      status: z.enum(["pending", "running", "completed", "failed", "cancelled", "paused"]).optional(),
      engagementId: z.number().int().positive().optional(),
      limit: z.number().int().min(1).max(100).optional(),
      offset: z.number().int().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      // Merge in-memory and DB results
      const memResult = getChainRuns({
        status: input?.status as ChainRunStatus | undefined,
        engagementId: input?.engagementId,
        limit: input?.limit,
        offset: input?.offset,
      });

      // Also query DB for persisted runs
      const dbResult = await listChainRunsDb({
        status: input?.status,
        engagementId: input?.engagementId,
        limit: input?.limit || 25,
        offset: input?.offset || 0,
      });

      // Merge: prefer in-memory for active runs, DB for completed
      const memIds = new Set(memResult.runs.map(r => r.id));
      const mergedRuns = [
        ...memResult.runs.map(r => ({
          id: r.id,
          status: r.status,
          progress: r.progress,
          domains: r.config.domains,
          engagementId: r.config.engagementId,
          stagesCompleted: r.summary.stagesCompleted,
          stagesTotal: r.summary.stagesTotal,
          totalFindings: r.summary.totalFindings,
          findingsBySeverity: r.summary.findingsBySeverity,
          startedAt: r.startedAt,
          completedAt: r.completedAt,
          durationMs: r.durationMs,
          source: "memory" as const,
        })),
        ...dbResult.runs
          .filter(r => !memIds.has(r.chainId))
          .map(r => ({
            id: r.chainId,
            status: r.status,
            progress: r.progress,
            domains: r.domains as string[],
            engagementId: r.engagementId,
            stagesCompleted: r.stagesCompleted || 0,
            stagesTotal: r.stagesTotal || 4,
            totalFindings: r.totalFindings || 0,
            findingsBySeverity: r.findingsBySeverity as any || {},
            startedAt: r.startedAt,
            completedAt: r.completedAt || null,
            durationMs: r.durationMs || null,
            source: "database" as const,
          })),
      ];

      // Sort by startedAt descending
      mergedRuns.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));

      return {
        total: Math.max(memResult.total, dbResult.total),
        runs: mergedRuns,
      };
    }),

  /**
   * Get the chain stage definitions (for UI display).
   */
  getStageDefinitions: protectedProcedure
    .query(() => {
      return getChainStageDefinitions();
    }),

  /**
   * Estimate chain duration based on configuration.
   */
  estimateDuration: protectedProcedure
    .input(chainRunConfigSchema)
    .query(({ input }) => {
      return estimateChainDuration(input);
    }),

  /**
   * Get the data flow between stages for a specific chain run.
   * Shows what targets were extracted and fed into each stage.
   */
  getDataFlow: protectedProcedure
    .input(z.object({ chainId: z.string() }))
    .query(async ({ input }) => {
      // Try in-memory first
      const run = getChainRun(input.chainId);
      if (run) {
        return buildDataFlow(run);
      }

      // Fall back to DB
      const dbRun = await getChainRunByChainId(input.chainId);
      if (!dbRun) {
        throw new TRPCError({ code: "NOT_FOUND", message: `Chain run ${input.chainId} not found` });
      }

      const dbStages = await getChainStageResultsDb(input.chainId);
      const amassStage = dbStages.find(s => s.stageId === "amass");
      const nmapStage = dbStages.find(s => s.stageId === "nmap");
      const fpStage = dbStages.find(s => s.stageId === "service_fingerprinter");

      const amassRaw = amassStage?.rawOutput ? JSON.parse(amassStage.rawOutput) : null;
      const nmapRaw = nmapStage?.rawOutput ? JSON.parse(nmapStage.rawOutput) : null;
      const fpRaw = fpStage?.rawOutput ? JSON.parse(fpStage.rawOutput) : null;

      const nmapTargets = amassRaw ? extractNmapTargetsFromAmass(amassRaw) : [];
      const fpTargets = nmapRaw ? extractFingerprintTargetsFromNmap(nmapRaw) : [];
      const nucleiTargets = extractNucleiTargetsFromResults(nmapRaw, fpRaw);
      const templateSelection = selectNucleiTemplates(nmapRaw, fpRaw);

      return {
        initialDomains: dbRun.domains as string[],
        seedIps: dbRun.seedIps as string[] || [],
        seedUrls: dbRun.seedUrls as string[] || [],
        flows: [
          {
            from: "input" as const,
            to: "amass" as const,
            targetCount: (dbRun.domains as string[]).length,
            targets: dbRun.domains as string[],
          },
          {
            from: "amass" as const,
            to: "nmap" as const,
            targetCount: nmapTargets.length,
            targets: nmapTargets.slice(0, 50),
          },
          {
            from: "nmap" as const,
            to: "service_fingerprinter" as const,
            targetCount: fpTargets.length,
            targets: fpTargets.slice(0, 50).map(t => `${t.host}:${t.port}`),
          },
          {
            from: "nmap+service_fingerprinter" as const,
            to: "nuclei" as const,
            targetCount: nucleiTargets.length,
            targets: nucleiTargets.slice(0, 50),
          },
        ],
        nucleiTemplateSelection: templateSelection,
        source: "database" as const,
      };
    }),
});

// ─── Helpers ──────────────────────────────────────────────────────────

function buildDataFlow(run: any) {
  const amassStage = run.stages.find((s: any) => s.stageId === "amass");
  const nmapStage = run.stages.find((s: any) => s.stageId === "nmap");
  const fpStage = run.stages.find((s: any) => s.stageId === "service_fingerprinter");

  const nmapTargets = amassStage?.rawOutput
    ? extractNmapTargetsFromAmass(amassStage.rawOutput)
    : [];
  const fpTargets = nmapStage?.rawOutput
    ? extractFingerprintTargetsFromNmap(nmapStage.rawOutput)
    : [];
  const nucleiTargets = extractNucleiTargetsFromResults(
    nmapStage?.rawOutput,
    fpStage?.rawOutput
  );
  const templateSelection = selectNucleiTemplates(
    nmapStage?.rawOutput,
    fpStage?.rawOutput
  );

  return {
    initialDomains: run.config.domains,
    seedIps: run.config.seedIps || [],
    seedUrls: run.config.seedUrls || [],
    flows: [
      {
        from: "input" as const,
        to: "amass" as const,
        targetCount: run.config.domains.length,
        targets: run.config.domains,
      },
      {
        from: "amass" as const,
        to: "nmap" as const,
        targetCount: nmapTargets.length,
        targets: nmapTargets.slice(0, 50),
      },
      {
        from: "nmap" as const,
        to: "service_fingerprinter" as const,
        targetCount: fpTargets.length,
        targets: fpTargets.slice(0, 50).map(t => `${t.host}:${t.port}`),
      },
      {
        from: "nmap+service_fingerprinter" as const,
        to: "nuclei" as const,
        targetCount: nucleiTargets.length,
        targets: nucleiTargets.slice(0, 50),
      },
    ],
    nucleiTemplateSelection: templateSelection,
    source: "memory" as const,
  };
}
