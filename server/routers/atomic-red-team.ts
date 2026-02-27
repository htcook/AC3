/**
 * Atomic Red Team tRPC Router
 * 
 * Provides endpoints for browsing, executing, and tracking ATT&CK-mapped
 * atomic tests. Includes cross-module integration endpoints used by
 * Attack Planner, Purple Team, Detection Rules, EDR Validation, etc.
 */
import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import * as atomicRT from "../lib/atomic-red-team";

export const atomicRedTeamRouter = router({
  // ─── Stats & Overview ────────────────────────────────────────────────────

  /** Get overall Atomic Red Team library statistics */
  getStats: protectedProcedure.query(async () => {
    try {
      return await atomicRT.getStats();
    } catch (err: any) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
    }
  }),

  // ─── GitHub Sync ─────────────────────────────────────────────────────────

  /** Sync atomic tests from GitHub (full or partial) */
  syncFromGitHub: protectedProcedure
    .input(z.object({
      techniques: z.array(z.string()).optional(),
      forceRefresh: z.boolean().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      try {
        return await atomicRT.syncFromGitHub(input || undefined);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Seed demo data for testing */
  seedDemoData: protectedProcedure.mutation(async () => {
    try {
      return await atomicRT.seedDemoData();
    } catch (err: any) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
    }
  }),

  /** Clear demo data */
  clearDemoData: protectedProcedure.mutation(async () => {
    try {
      return await atomicRT.clearDemoData();
    } catch (err: any) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
    }
  }),

  // ─── Test Browsing & Search ──────────────────────────────────────────────

  /** List tests with filters */
  listTests: protectedProcedure
    .input(z.object({
      techniqueId: z.string().optional(),
      tactic: z.string().optional(),
      platform: z.string().optional(),
      executorType: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      try {
        return await atomicRT.listTests(input || undefined);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Get a single test by GUID */
  getTest: protectedProcedure
    .input(z.object({ guid: z.string() }))
    .query(async ({ input }) => {
      const test = await atomicRT.getTestByGuid(input.guid);
      if (!test) throw new TRPCError({ code: "NOT_FOUND", message: "Test not found" });
      return test;
    }),

  /** Get all tests for a specific ATT&CK technique */
  getTestsForTechnique: protectedProcedure
    .input(z.object({ techniqueId: z.string() }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.getTestsForTechnique(input.techniqueId);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  // ─── Coverage Map ────────────────────────────────────────────────────────

  /** Get ATT&CK technique coverage with execution history */
  getTechniqueCoverage: protectedProcedure.query(async () => {
    try {
      return await atomicRT.getTechniqueCoverage();
    } catch (err: any) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
    }
  }),

  // ─── Execution Management ────────────────────────────────────────────────

  /** Queue a test for execution */
  executeTest: protectedProcedure
    .input(z.object({
      atomicTestId: z.number(),
      guid: z.string(),
      techniqueId: z.string(),
      testName: z.string(),
      targetHost: z.string().optional(),
      targetPlatform: z.string().optional(),
      executorType: z.string().optional(),
      commandExecuted: z.string().optional(),
      inputArgs: z.record(z.string(), z.any()).optional(),
      attackChainId: z.string().optional(),
      calderaOperationId: z.string().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate target host ──
      if (input.engagementId && input.targetHost) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.targetHost, `Atomic Red Team: ${input.techniqueId}`, ctx);
      }
      try {
        const executionId = await atomicRT.createExecution({
          ...input,
          executedBy: ctx.user.openId,
        });
        return { executionId, status: "queued" };
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Update execution status */
  updateExecution: protectedProcedure
    .input(z.object({
      executionId: z.number(),
      status: z.enum(["running", "success", "failed", "blocked", "cleanup"]).optional(),
      stdout: z.string().optional(),
      stderr: z.string().optional(),
      exitCode: z.number().optional(),
      detectionTriggered: z.boolean().optional(),
      detectionDetails: z.string().optional(),
      cleanupRan: z.boolean().optional(),
      cleanupOutput: z.string().optional(),
      durationMs: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { executionId, ...update } = input;
      try {
        await atomicRT.updateExecution(executionId, {
          ...update,
          completedAt: (update.status === "success" || update.status === "failed" || update.status === "blocked")
            ? new Date() : undefined,
        });
        return { success: true };
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** List execution history */
  listExecutions: protectedProcedure
    .input(z.object({
      techniqueId: z.string().optional(),
      status: z.string().optional(),
      attackChainId: z.string().optional(),
      limit: z.number().min(1).max(200).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      try {
        return await atomicRT.listExecutions(input || undefined);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  // ─── Cross-Module Integration Endpoints ──────────────────────────────────

  /** Find atomic tests for given ATT&CK technique IDs
   *  Used by: Attack Planner, Emulation Playbooks, Purple Team */
  findTestsForTechniques: protectedProcedure
    .input(z.object({ techniqueIds: z.array(z.string()) }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.findTestsForTechniques(input.techniqueIds);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Find atomic tests that validate detection rules
   *  Used by: Detection Rules, SIEM Connectors, EDR Validation */
  findTestsForDetectionRule: protectedProcedure
    .input(z.object({
      mitreTechniqueIds: z.array(z.string()).optional(),
      keywords: z.array(z.string()).optional(),
      platform: z.string().optional(),
    }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.findTestsForDetectionRule(input);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Map Caldera abilities to matching atomic tests
   *  Used by: Caldera Operations, Emulation Playbooks */
  mapCalderaAbilities: protectedProcedure
    .input(z.object({
      abilities: z.array(z.object({
        abilityId: z.string(),
        techniqueId: z.string(),
        name: z.string(),
      })),
    }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.mapCalderaAbilities(input.abilities);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Find atomic tests relevant to web vulnerability findings
   *  Used by: Web App Scanner, Corroboration Engine */
  findTestsForWebFindings: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        mitreAttackId: z.string().nullable().optional(),
        cweId: z.number().nullable().optional(),
        alertName: z.string(),
      })),
    }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.findTestsForWebFindings(input.findings);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  /** Generate a purple team exercise plan from technique IDs
   *  Used by: Purple Team, Attack Planner */
  generatePurpleTeamPlan: protectedProcedure
    .input(z.object({
      techniqueIds: z.array(z.string()),
      targetPlatform: z.string().optional(),
      includeCleanup: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      try {
        return await atomicRT.generatePurpleTeamPlan(input);
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),
});
