/**
 * Campaign Orchestrator Router
 *
 * tRPC procedures for creating, managing, and executing multi-stage
 * red team campaigns with conditional logic.
 *
 * Endpoints:
 *   - list: List all campaigns with optional status filter
 *   - getById: Get campaign details with stages and logs
 *   - create: Create a new campaign (draft)
 *   - update: Update campaign metadata
 *   - delete: Delete a draft campaign
 *   - addStage: Add a stage to a campaign
 *   - updateStage: Update a stage's configuration
 *   - removeStage: Remove a stage from a campaign
 *   - reorderStages: Reorder stages within a campaign
 *   - execute: Start campaign execution
 *   - pause: Pause a running campaign
 *   - resume: Resume a paused campaign
 *   - abort: Abort a running campaign
 *   - getLogs: Get campaign execution logs
 *   - getStatus: Get real-time campaign status
 *   - generatePlan: AI-generate a campaign plan
 *   - applyPlan: Apply an AI-generated plan to a campaign
 *   - listEngagements: List available engagements for stage linking
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { assertEngagementAccess, scopeEngagementWhere } from "../lib/engagement-access-guard";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import {
  redteamCampaigns,
  redteamCampaignStages,
  redteamCampaignLogs,
  engagements,
  ac3Reports,
  ac3ReportFindings,
} from "../../drizzle/schema";
import { eq, desc, asc, and, sql, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";

// ─── Helpers ────────────────────────────────────────────────────────────────

async function getDbSafe() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const conditionSchema = z.object({
  field: z.string(),
  operator: z.enum([">", ">=", "<", "<=", "==", "!=", "contains", "exists"]),
  value: z.union([z.string(), z.number(), z.boolean()]),
});

const stageConfigSchema = z.object({
  targets: z.array(z.string()).optional(),
  tools: z.array(z.string()).optional(),
  scanProfile: z.enum(["quick", "standard", "deep", "stealth"]).optional(),
  phishingTemplate: z.string().optional(),
  exploitIds: z.array(z.string()).optional(),
  customCommand: z.string().optional(),
  safetyOverride: z.string().optional(),
}).passthrough();

const stageTypeEnum = z.enum([
  "recon", "enumeration", "vuln_scan", "phishing", "exploitation",
  "post_exploit", "lateral_move", "c2_deploy", "exfiltration", "cleanup", "custom",
]);

// ─── Router ─────────────────────────────────────────────────────────────────

export const campaignOrchestratorRouter = router({

  // ═══ LIST CAMPAIGNS ═══════════════════════════════════════════════════════
  list: protectedProcedure
    .input(z.object({
      status: z.enum(["draft", "ready", "running", "paused", "completed", "failed", "aborted", "all"]).optional().default("all"),
      limit: z.number().min(1).max(100).optional().default(50),
      offset: z.number().min(0).optional().default(0),
    }).optional().default({}))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.status !== "all") {
        conditions.push(eq(redteamCampaigns.status, input.status as any));
      }

      const rows = await db.select().from(redteamCampaigns)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(redteamCampaigns.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      // Get stage counts for each campaign
      const campaignIds = rows.map((r) => r.id);
      let stageCounts: Record<number, { total: number; completed: number; failed: number; running: number }> = {};

      if (campaignIds.length > 0) {
        const stageStats = await db.select({
          campaignId: redteamCampaignStages.campaignId,
          total: sql<number>`COUNT(*)`,
          completed: sql<number>`SUM(CASE WHEN ${redteamCampaignStages.status} = 'completed' THEN 1 ELSE 0 END)`,
          failed: sql<number>`SUM(CASE WHEN ${redteamCampaignStages.status} = 'failed' THEN 1 ELSE 0 END)`,
          running: sql<number>`SUM(CASE WHEN ${redteamCampaignStages.status} = 'running' THEN 1 ELSE 0 END)`,
        }).from(redteamCampaignStages)
          .where(inArray(redteamCampaignStages.campaignId, campaignIds))
          .groupBy(redteamCampaignStages.campaignId);

        for (const s of stageStats) {
          stageCounts[s.campaignId] = {
            total: Number(s.total),
            completed: Number(s.completed),
            failed: Number(s.failed),
            running: Number(s.running),
          };
        }
      }

      // Get total count
      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
        .from(redteamCampaigns)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return {
        campaigns: rows.map((r) => ({
          ...r,
          stages: stageCounts[r.id] || { total: 0, completed: 0, failed: 0, running: 0 },
        })),
        total: Number(countResult?.count || 0),
      };
    }),

  // ═══ GET CAMPAIGN BY ID ═══════════════════════════════════════════════════
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.id));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND", message: "Campaign not found" });

      const stages = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.id))
        .orderBy(asc(redteamCampaignStages.stageOrder));

      // Get recent logs
      const logs = await db.select().from(redteamCampaignLogs)
        .where(eq(redteamCampaignLogs.campaignId, input.id))
        .orderBy(desc(redteamCampaignLogs.createdAt))
        .limit(100);

      // Check if running
      const { getCampaignRunState } = await import("../lib/campaign-orchestrator");
      const runState = getCampaignRunState(input.id);

      return {
        ...campaign,
        stages,
        logs: logs.reverse(),
        isLiveRunning: !!runState?.isRunning,
        isLivePaused: !!runState?.isPaused,
        currentStageId: runState?.currentStageId,
      };
    }),

  // ═══ CREATE CAMPAIGN ══════════════════════════════════════════════════════
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      customerName: z.string().optional(),
      objective: z.string().optional(),
      safetyLevel: z.enum(["passive_only", "low_impact", "standard", "full_exploitation"]).optional().default("standard"),
      maxDurationHours: z.number().min(1).max(720).optional().default(72),
      autoAdvance: z.boolean().optional().default(true),
      notifyOnStageComplete: z.boolean().optional().default(true),
      notifyOnCampaignComplete: z.boolean().optional().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(redteamCampaigns).values({
        name: input.name,
        description: input.description,
        customerName: input.customerName,
        objective: input.objective,
        safetyLevel: input.safetyLevel as any,
        maxDurationHours: input.maxDurationHours,
        autoAdvance: input.autoAdvance ? 1 : 0,
        notifyOnStageComplete: input.notifyOnStageComplete ? 1 : 0,
        notifyOnCampaignComplete: input.notifyOnCampaignComplete ? 1 : 0,
        createdBy: ctx.user.id,
        status: "draft" as any,
      });
      return { id: Number(result.insertId) };
    }),

  // ═══ UPDATE CAMPAIGN ══════════════════════════════════════════════════════
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().min(1).max(255).optional(),
      description: z.string().optional(),
      customerName: z.string().optional(),
      objective: z.string().optional(),
      safetyLevel: z.enum(["passive_only", "low_impact", "standard", "full_exploitation"]).optional(),
      maxDurationHours: z.number().min(1).max(720).optional(),
      autoAdvance: z.boolean().optional(),
      notifyOnStageComplete: z.boolean().optional(),
      notifyOnCampaignComplete: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.id));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot update a running campaign" });
      }

      const updates: Record<string, any> = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.description !== undefined) updates.description = input.description;
      if (input.customerName !== undefined) updates.customerName = input.customerName;
      if (input.objective !== undefined) updates.objective = input.objective;
      if (input.safetyLevel !== undefined) updates.safetyLevel = input.safetyLevel;
      if (input.maxDurationHours !== undefined) updates.maxDurationHours = input.maxDurationHours;
      if (input.autoAdvance !== undefined) updates.autoAdvance = input.autoAdvance ? 1 : 0;
      if (input.notifyOnStageComplete !== undefined) updates.notifyOnStageComplete = input.notifyOnStageComplete ? 1 : 0;
      if (input.notifyOnCampaignComplete !== undefined) updates.notifyOnCampaignComplete = input.notifyOnCampaignComplete ? 1 : 0;

      if (Object.keys(updates).length > 0) {
        await db.update(redteamCampaigns).set(updates).where(eq(redteamCampaigns.id, input.id));
      }
      return { success: true };
    }),

  // ═══ DELETE CAMPAIGN ══════════════════════════════════════════════════════
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.id));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot delete a running campaign. Abort it first." });
      }

      // Delete logs, stages, then campaign
      await db.delete(redteamCampaignLogs).where(eq(redteamCampaignLogs.campaignId, input.id));
      await db.delete(redteamCampaignStages).where(eq(redteamCampaignStages.campaignId, input.id));
      await db.delete(redteamCampaigns).where(eq(redteamCampaigns.id, input.id));
      return { success: true };
    }),

  // ═══ ADD STAGE ════════════════════════════════════════════════════════════
  addStage: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      stageType: stageTypeEnum,
      engagementId: z.number().optional(),
      config: stageConfigSchema.optional(),
      entryConditions: z.array(conditionSchema).optional(),
      exitConditions: z.array(conditionSchema).optional(),
      onSuccess: z.enum(["next", "skip_to", "complete", "pause"]).optional().default("next"),
      onSuccessTarget: z.number().optional(),
      onFailure: z.enum(["abort", "skip", "retry", "pause", "fallback"]).optional().default("pause"),
      onFailureTarget: z.number().optional(),
      maxRetries: z.number().min(0).max(5).optional().default(1),
      timeoutMinutes: z.number().min(1).max(1440).optional().default(60),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND", message: "Campaign not found" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot modify a running campaign" });
      }

      // Get next stage order
      const existingStages = await db.select({ maxOrder: sql<number>`MAX(${redteamCampaignStages.stageOrder})` })
        .from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId));
      const nextOrder = (Number(existingStages[0]?.maxOrder) || 0) + 1;

      const [result] = await db.insert(redteamCampaignStages).values({
        campaignId: input.campaignId,
        name: input.name,
        description: input.description,
        stageOrder: nextOrder,
        stageType: input.stageType as any,
        engagementId: input.engagementId,
        config: input.config || {},
        entryConditions: input.entryConditions || [],
        exitConditions: input.exitConditions || [],
        onSuccess: input.onSuccess as any,
        onSuccessTarget: input.onSuccessTarget,
        onFailure: input.onFailure as any,
        onFailureTarget: input.onFailureTarget,
        maxRetries: input.maxRetries,
        timeoutMinutes: input.timeoutMinutes,
        status: "pending" as any,
      });

      return { id: Number(result.insertId), stageOrder: nextOrder };
    }),

  // ═══ UPDATE STAGE ═════════════════════════════════════════════════════════
  updateStage: protectedProcedure
    .input(z.object({
      stageId: z.number(),
      name: z.string().min(1).max(255).optional(),
      description: z.string().optional(),
      stageType: stageTypeEnum.optional(),
      engagementId: z.number().nullable().optional(),
      config: stageConfigSchema.optional(),
      entryConditions: z.array(conditionSchema).optional(),
      exitConditions: z.array(conditionSchema).optional(),
      onSuccess: z.enum(["next", "skip_to", "complete", "pause"]).optional(),
      onSuccessTarget: z.number().nullable().optional(),
      onFailure: z.enum(["abort", "skip", "retry", "pause", "fallback"]).optional(),
      onFailureTarget: z.number().nullable().optional(),
      maxRetries: z.number().min(0).max(5).optional(),
      timeoutMinutes: z.number().min(1).max(1440).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [stage] = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.id, input.stageId));
      if (!stage) throw new TRPCError({ code: "NOT_FOUND" });

      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, stage.campaignId));
      if (campaign?.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot modify stages of a running campaign" });
      }

      const updates: Record<string, any> = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.description !== undefined) updates.description = input.description;
      if (input.stageType !== undefined) updates.stageType = input.stageType;
      if (input.engagementId !== undefined) updates.engagementId = input.engagementId;
      if (input.config !== undefined) updates.config = input.config;
      if (input.entryConditions !== undefined) updates.entryConditions = input.entryConditions;
      if (input.exitConditions !== undefined) updates.exitConditions = input.exitConditions;
      if (input.onSuccess !== undefined) updates.onSuccess = input.onSuccess;
      if (input.onSuccessTarget !== undefined) updates.onSuccessTarget = input.onSuccessTarget;
      if (input.onFailure !== undefined) updates.onFailure = input.onFailure;
      if (input.onFailureTarget !== undefined) updates.onFailureTarget = input.onFailureTarget;
      if (input.maxRetries !== undefined) updates.maxRetries = input.maxRetries;
      if (input.timeoutMinutes !== undefined) updates.timeoutMinutes = input.timeoutMinutes;

      if (Object.keys(updates).length > 0) {
        await db.update(redteamCampaignStages).set(updates).where(eq(redteamCampaignStages.id, input.stageId));
      }
      return { success: true };
    }),

  // ═══ REMOVE STAGE ═════════════════════════════════════════════════════════
  removeStage: protectedProcedure
    .input(z.object({ stageId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [stage] = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.id, input.stageId));
      if (!stage) throw new TRPCError({ code: "NOT_FOUND" });

      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, stage.campaignId));
      if (campaign?.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot modify stages of a running campaign" });
      }

      await db.delete(redteamCampaignStages).where(eq(redteamCampaignStages.id, input.stageId));

      // Re-order remaining stages
      const remaining = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, stage.campaignId))
        .orderBy(asc(redteamCampaignStages.stageOrder));

      for (let i = 0; i < remaining.length; i++) {
        if (remaining[i].stageOrder !== i + 1) {
          await db.update(redteamCampaignStages)
            .set({ stageOrder: i + 1 })
            .where(eq(redteamCampaignStages.id, remaining[i].id));
        }
      }

      return { success: true };
    }),

  // ═══ REORDER STAGES ═══════════════════════════════════════════════════════
  reorderStages: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      stageIds: z.array(z.number()), // Ordered list of stage IDs
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot reorder stages of a running campaign" });
      }

      for (let i = 0; i < input.stageIds.length; i++) {
        await db.update(redteamCampaignStages)
          .set({ stageOrder: i + 1 })
          .where(and(
            eq(redteamCampaignStages.id, input.stageIds[i]),
            eq(redteamCampaignStages.campaignId, input.campaignId),
          ));
      }
      return { success: true };
    }),

  // ═══ EXECUTE CAMPAIGN ═════════════════════════════════════════════════════
  execute: protectedProcedure
    .input(z.object({ campaignId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "CONFLICT", message: "Campaign is already running" });
      }

      // Verify campaign has stages
      const stages = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId));
      if (stages.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Campaign has no stages. Add at least one stage before executing." });
      }

      // Reset stage statuses for re-execution
      for (const stage of stages) {
        await db.update(redteamCampaignStages)
          .set({ status: "pending", retryCount: 0, startedAt: null, completedAt: null, results: null, errorMessage: null } as any)
          .where(eq(redteamCampaignStages.id, stage.id));
      }

      // Fire and forget — campaign runs asynchronously
      const { executeCampaign } = await import("../lib/campaign-orchestrator");
      executeCampaign(input.campaignId, {
        id: String(ctx.user.id),
        name: ctx.user.name || undefined,
      }).catch((err: any) => {
        console.error(`[CampaignOrch] Campaign ${input.campaignId} crashed:`, err.message);
      });

      return { success: true, message: "Campaign execution started" };
    }),

  // ═══ PAUSE CAMPAIGN ═══════════════════════════════════════════════════════
  pause: protectedProcedure
    .input(z.object({ campaignId: z.number() }))
    .mutation(async ({ input }) => {
      const { pauseCampaign } = await import("../lib/campaign-orchestrator");
      const success = pauseCampaign(input.campaignId);
      if (!success) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Campaign is not running or already paused" });
      }

      const db = await getDbSafe();
      await db.update(redteamCampaigns)
        .set({ status: "paused", pausedAt: new Date().toISOString() } as any)
        .where(eq(redteamCampaigns.id, input.campaignId));

      return { success: true };
    }),

  // ═══ RESUME CAMPAIGN ══════════════════════════════════════════════════════
  resume: protectedProcedure
    .input(z.object({ campaignId: z.number() }))
    .mutation(async ({ input }) => {
      const { resumeCampaign } = await import("../lib/campaign-orchestrator");
      const success = resumeCampaign(input.campaignId);
      if (!success) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Campaign is not paused" });
      }

      const db = await getDbSafe();
      await db.update(redteamCampaigns)
        .set({ status: "running" } as any)
        .where(eq(redteamCampaigns.id, input.campaignId));

      return { success: true };
    }),

  // ═══ ABORT CAMPAIGN ═══════════════════════════════════════════════════════
  abort: protectedProcedure
    .input(z.object({ campaignId: z.number() }))
    .mutation(async ({ input }) => {
      const { abortCampaign } = await import("../lib/campaign-orchestrator");
      const success = abortCampaign(input.campaignId);

      const db = await getDbSafe();
      await db.update(redteamCampaigns)
        .set({ status: "aborted", completedAt: new Date().toISOString() } as any)
        .where(eq(redteamCampaigns.id, input.campaignId));

      // Abort any running stages
      await db.update(redteamCampaignStages)
        .set({ status: "aborted" } as any)
        .where(and(
          eq(redteamCampaignStages.campaignId, input.campaignId),
          eq(redteamCampaignStages.status, "running" as any),
        ));

      return { success: true };
    }),

  // ═══ GET LOGS ═════════════════════════════════════════════════════════════
  getLogs: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      stageId: z.number().optional(),
      logType: z.string().optional(),
      limit: z.number().min(1).max(500).optional().default(100),
      offset: z.number().min(0).optional().default(0),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [eq(redteamCampaignLogs.campaignId, input.campaignId)];
      if (input.stageId) conditions.push(eq(redteamCampaignLogs.stageId, input.stageId));
      if (input.logType) conditions.push(eq(redteamCampaignLogs.logType, input.logType as any));

      const logs = await db.select().from(redteamCampaignLogs)
        .where(and(...conditions))
        .orderBy(desc(redteamCampaignLogs.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      return { logs: logs.reverse() };
    }),

  // ═══ GET STATUS ═══════════════════════════════════════════════════════════
  getStatus: protectedProcedure
    .input(z.object({ campaignId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });

      const stages = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId))
        .orderBy(asc(redteamCampaignStages.stageOrder));

      const { getCampaignRunState } = await import("../lib/campaign-orchestrator");
      const runState = getCampaignRunState(input.campaignId);

      const completedCount = stages.filter((s) => s.status === "completed").length;
      const failedCount = stages.filter((s) => s.status === "failed" || s.status === "timed_out").length;
      const progress = stages.length > 0 ? Math.round((completedCount / stages.length) * 100) : 0;

      return {
        status: campaign.status,
        isLiveRunning: !!runState?.isRunning,
        isLivePaused: !!runState?.isPaused,
        currentStageOrder: campaign.currentStageOrder,
        currentStageId: runState?.currentStageId,
        progress,
        stagesSummary: stages.map((s) => ({
          id: s.id,
          name: s.name,
          stageOrder: s.stageOrder,
          stageType: s.stageType,
          status: s.status,
          startedAt: s.startedAt,
          completedAt: s.completedAt,
          errorMessage: s.errorMessage,
          results: s.results,
        })),
        resultsSummary: campaign.resultsSummary,
        startedAt: campaign.startedAt,
        completedAt: campaign.completedAt,
      };
    }),

  // ═══ GENERATE AI CAMPAIGN PLAN ════════════════════════════════════════════
  generatePlan: protectedProcedure
    .input(z.object({
      targetDescription: z.string().min(1),
      objective: z.string().min(1),
      engagementType: z.enum(["red_team", "pentest", "purple_team"]).optional().default("red_team"),
      safetyLevel: z.enum(["passive_only", "low_impact", "standard", "full_exploitation"]).optional().default("standard"),
    }))
    .mutation(async ({ input }) => {
      const { generateCampaignPlan } = await import("../lib/campaign-orchestrator");
      const plan = await generateCampaignPlan(
        input.targetDescription,
        input.objective,
        input.engagementType,
        input.safetyLevel
      );
      return plan;
    }),

  // ═══ APPLY AI PLAN TO CAMPAIGN ════════════════════════════════════════════
  applyPlan: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      plan: z.object({
        name: z.string(),
        objective: z.string(),
        stages: z.array(z.object({
          name: z.string(),
          stageType: z.string(),
          description: z.string(),
          entryConditions: z.array(z.any()),
          exitConditions: z.array(z.any()),
          onSuccess: z.string(),
          onFailure: z.string(),
          timeoutMinutes: z.number(),
          config: z.any(),
        })),
        estimatedDurationHours: z.number(),
        riskAssessment: z.string(),
      }),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND" });
      if (campaign.status === "running") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot modify a running campaign" });
      }

      // Update campaign metadata
      await db.update(redteamCampaigns).set({
        name: input.plan.name,
        objective: input.plan.objective,
        maxDurationHours: Math.ceil(input.plan.estimatedDurationHours),
      }).where(eq(redteamCampaigns.id, input.campaignId));

      // Delete existing stages
      await db.delete(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId));

      // Insert new stages
      for (let i = 0; i < input.plan.stages.length; i++) {
        const s = input.plan.stages[i];
        await db.insert(redteamCampaignStages).values({
          campaignId: input.campaignId,
          name: s.name,
          description: s.description,
          stageOrder: i + 1,
          stageType: s.stageType as any,
          config: s.config || {},
          entryConditions: s.entryConditions || [],
          exitConditions: s.exitConditions || [],
          onSuccess: (s.onSuccess || "next") as any,
          onFailure: (s.onFailure || "pause") as any,
          timeoutMinutes: s.timeoutMinutes || 60,
          maxRetries: 1,
          status: "pending" as any,
        });
      }

      return { success: true, stagesCreated: input.plan.stages.length };
    }),

  // ═══ LIST ENGAGEMENTS (for stage linking) ═════════════════════════════════
  listEngagements: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).optional().default(50),
    }).optional().default({}))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const rows = await db.select({
        id: engagements.id,
        name: engagements.name,
        customerName: engagements.customerName,
        engagementType: engagements.engagementType,
        status: engagements.status,
        targetDomain: engagements.targetDomain,
        roeStatus: engagements.roeStatus,
      }).from(engagements)
        .orderBy(desc(engagements.createdAt))
        .limit(input.limit);
      return rows;
    }),

  // ═══ CAMPAIGN CLONING ═══════════════════════════════════════════════════════
  clone: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      name: z.string().min(1).max(255),
      customerName: z.string().optional(),
      objective: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [source] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!source) throw new TRPCError({ code: "NOT_FOUND", message: "Source campaign not found" });

      const [result] = await db.insert(redteamCampaigns).values({
        name: input.name,
        description: source.description ? `Cloned from: ${source.name}. ${source.description}` : `Cloned from: ${source.name}`,
        customerName: input.customerName || source.customerName,
        objective: input.objective || source.objective,
        safetyLevel: source.safetyLevel as any,
        maxDurationHours: source.maxDurationHours,
        autoAdvance: source.autoAdvance,
        notifyOnStageComplete: source.notifyOnStageComplete,
        notifyOnCampaignComplete: source.notifyOnCampaignComplete,
        createdBy: ctx.user.id,
        status: "draft" as any,
      });
      const newCampaignId = Number(result.insertId);

      const stages = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId))
        .orderBy(asc(redteamCampaignStages.stageOrder));

      for (const stage of stages) {
        await db.insert(redteamCampaignStages).values({
          campaignId: newCampaignId,
          name: stage.name,
          description: stage.description,
          stageOrder: stage.stageOrder,
          stageType: stage.stageType as any,
          engagementId: stage.engagementId,
          config: stage.config || {},
          entryConditions: stage.entryConditions || [],
          exitConditions: stage.exitConditions || [],
          onSuccess: stage.onSuccess as any,
          onSuccessTarget: stage.onSuccessTarget,
          onFailure: stage.onFailure as any,
          onFailureTarget: stage.onFailureTarget,
          maxRetries: stage.maxRetries,
          timeoutMinutes: stage.timeoutMinutes,
          status: "pending" as any,
        });
      }

      return { id: newCampaignId, stagesCloned: stages.length };
    }),

  // ═══ CAMPAIGN-TO-REPORT PIPELINE ═══════════════════════════════════════════
  generateReport: protectedProcedure
    .input(z.object({
      campaignId: z.number(),
      reportName: z.string().optional(),
      assessmentType: z.enum(["penetration_test", "red_team", "purple_team", "vulnerability_assessment", "hybrid"]).optional(),
      complianceFramework: z.enum(["fedramp", "nist_800_53_r5"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      const [campaign] = await db.select().from(redteamCampaigns)
        .where(eq(redteamCampaigns.id, input.campaignId));
      if (!campaign) throw new TRPCError({ code: "NOT_FOUND", message: "Campaign not found" });

      const stages = await db.select().from(redteamCampaignStages)
        .where(eq(redteamCampaignStages.campaignId, input.campaignId))
        .orderBy(asc(redteamCampaignStages.stageOrder));

      const now = Date.now();
      const reportId = `rpt-${randomUUID().slice(0, 12)}`;
      await db.insert(ac3Reports).values({
        reportId,
        name: input.reportName || `${campaign.name} \u2014 Assessment Report`,
        status: "draft",
        complianceFramework: input.complianceFramework ?? "nist_800_53_r5",
        clientName: campaign.customerName ?? null,
        systemName: null,
        assessmentType: input.assessmentType ?? "red_team",
        fedrampImpactLevel: null,
        cloudProvider: null,
        serviceModel: null,
        assessmentWindowStart: campaign.startedAt ? new Date(campaign.startedAt).getTime() : null,
        assessmentWindowEnd: campaign.completedAt ? new Date(campaign.completedAt).getTime() : null,
        reportVersion: "1.0",
        scopeDomains: [],
        scopeAssets: [],
        approvedVectors: [],
        outOfScope: [],
        campaignId: String(campaign.id),
        createdBy: ctx.user?.name ?? "operator",
        createdAt: now,
        updatedAt: now,
      });

      // ATT&CK technique mapping per stage type
      const STAGE_TO_TECHNIQUE: Record<string, { id: string; name: string; tactic: string }> = {
        recon: { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
        enumeration: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
        vuln_scan: { id: "T1595.002", name: "Vulnerability Scanning", tactic: "Reconnaissance" },
        phishing: { id: "T1566", name: "Phishing", tactic: "Initial Access" },
        exploitation: { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
        post_exploit: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
        lateral_move: { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
        c2_deploy: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
        exfiltration: { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
        cleanup: { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
      };

      // NIST control mapping per stage type
      const STAGE_TO_CONTROL: Record<string, { id: string; title: string }> = {
        recon: { id: "RA-5", title: "Vulnerability Monitoring and Scanning" },
        enumeration: { id: "CM-8", title: "System Component Inventory" },
        vuln_scan: { id: "RA-5", title: "Vulnerability Monitoring and Scanning" },
        phishing: { id: "AT-2", title: "Literacy Training and Awareness" },
        exploitation: { id: "SI-3", title: "Malicious Code Protection" },
        post_exploit: { id: "AU-6", title: "Audit Record Review, Analysis, and Reporting" },
        lateral_move: { id: "AC-4", title: "Information Flow Enforcement" },
        c2_deploy: { id: "SC-7", title: "Boundary Protection" },
        exfiltration: { id: "SC-28", title: "Protection of Information at Rest" },
        cleanup: { id: "IR-4", title: "Incident Handling" },
      };

      function deriveSeverity(stage: typeof stages[0]): "critical" | "high" | "moderate" | "low" | "informational" {
        const results = (stage.results || {}) as Record<string, any>;
        if (results.criticalVulns > 0 || results.exploitsSucceeded > 0) return "critical";
        if (results.highVulns > 0 || results.c2Agents > 0) return "high";
        if (results.vulnsFound > 0 || results.credsHarvested > 0) return "moderate";
        if (stage.status === "completed") return "low";
        return "informational";
      }

      let findingsCreated = 0;
      for (const stage of stages) {
        if (stage.status === "skipped" || stage.status === "pending") continue;

        const results = (stage.results || {}) as Record<string, any>;
        const technique = STAGE_TO_TECHNIQUE[stage.stageType] || { id: "T1000", name: stage.stageType, tactic: "Unknown" };
        const control = STAGE_TO_CONTROL[stage.stageType] || { id: "CA-8", title: "Penetration Testing" };
        const severity = deriveSeverity(stage);

        const evidence: Array<{ type: string; reference: string; description: string }> = [];
        if (results.vulnsFound) evidence.push({ type: "scan_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.vulnsFound} vulnerabilities found (${results.criticalVulns || 0} critical, ${results.highVulns || 0} high)` });
        if (results.exploitsSucceeded) evidence.push({ type: "exploit_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.exploitsSucceeded}/${results.exploitsAttempted || 0} exploits succeeded` });
        if (results.c2Agents) evidence.push({ type: "c2_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.c2Agents} C2 agent(s) deployed` });
        if (results.credsHarvested) evidence.push({ type: "credential_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.credsHarvested} credential(s) harvested` });
        if (results.dataExfilMb) evidence.push({ type: "exfil_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.dataExfilMb}MB data exfiltrated` });
        if (results.phishingClicks) evidence.push({ type: "phishing_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `${results.phishingClicks} phishing click(s) recorded` });
        if (evidence.length === 0) {
          evidence.push({ type: "stage_result", reference: `Stage ${stage.stageOrder}: ${stage.name}`, description: `Stage ${stage.status}: ${stage.stageType}` });
        }

        const findingId = `f-${randomUUID().slice(0, 12)}`;
        await db.insert(ac3ReportFindings).values({
          findingId,
          reportId,
          sortOrder: findingsCreated,
          severity,
          title: `${stage.name} \u2014 ${technique.name}`,
          evidence,
          attackTechniques: [technique],
          controls: [control],
          assets: [],
          cvssScore: null,
          cvssVector: null,
          summary: null,
          businessImpact: null,
          technicalDetails: null,
          remediation: null,
          sourceTaskId: null,
          sourceCampaignId: String(campaign.id),
          sourceAgentId: null,
          sourceModule: stage.stageType,
          sourceEventId: null,
          narrativeStatus: "pending",
          createdAt: now,
          updatedAt: now,
        });
        findingsCreated++;
      }

      return { reportId, findingsCreated, campaignName: campaign.name };
    }),
});
