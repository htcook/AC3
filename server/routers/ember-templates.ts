import { z } from "zod";
import { protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { emberCustomTemplates, emberCampaigns, emberCampaignPhases, emberCampaignLogs, emberTasks } from "../../drizzle/schema";
import { eq, desc, and, sql, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const taskStepSchema = z.object({
  taskType: z.string(),
  params: z.record(z.string()),
  priority: z.number().default(5),
  requiresElevation: z.boolean().default(false),
  delayMs: z.number().optional(),
});

const phaseConditionSchema = z.object({
  onSuccess: z.enum(["continue", "skip_next", "jump_to", "complete"]).default("continue"),
  onFailure: z.enum(["abort", "skip", "retry", "continue"]).default("abort"),
  onTimeout: z.enum(["abort", "skip", "retry", "continue"]).default("abort"),
  jumpToPhaseIndex: z.number().optional(),
  maxRetries: z.number().default(1),
  timeoutSeconds: z.number().default(600),
  delayBeforeMs: z.number().default(0),
  conditionExpression: z.string().optional(),
});

// ─── Template Procedures ────────────────────────────────────────────────────

export const emberTemplatesRouter = {
  // List all custom templates
  listTemplates: protectedProcedure.query(async () => {
      const db = await getDbRequired();
    const rows = await db.select().from(emberCustomTemplates).orderBy(desc(emberCustomTemplates.updatedAt));
    return rows;
  }),

  // Get a single template by ID
  getTemplate: protectedProcedure
    .input(z.object({ templateId: z.string() }))
    .query(async ({ input }) => {
        const db = await getDbRequired();
      const [row] = await db.select().from(emberCustomTemplates)
        .where(eq(emberCustomTemplates.templateId, input.templateId));
      return row ?? null;
    }),

  // Save a custom template (create or update)
  saveTemplate: protectedProcedure
    .input(z.object({
      templateId: z.string().optional(),
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      category: z.enum(["recon", "credential", "persistence", "lateral", "exfil", "custom"]),
      risk: z.enum(["low", "medium", "high", "critical"]),
      estimatedDuration: z.string().optional(),
      tags: z.array(z.string()).optional(),
      steps: z.array(taskStepSchema).min(1),
      clonedFrom: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
        const db = await getDbRequired();
      const now = Date.now();
      const templateId = input.templateId || `tpl-${randomUUID().slice(0, 12)}`;

      // Check if updating existing
      const [existing] = await db.select().from(emberCustomTemplates)
        .where(eq(emberCustomTemplates.templateId, templateId));

      if (existing) {
        await db.update(emberCustomTemplates)
          .set({
            name: input.name,
            description: input.description ?? null,
            category: input.category,
            risk: input.risk,
            estimatedDuration: input.estimatedDuration ?? null,
            tags: input.tags ?? [],
            steps: input.steps,
            updatedAt: now,
          })
          .where(eq(emberCustomTemplates.templateId, templateId));
      } else {
        await db.insert(emberCustomTemplates).values({
          templateId,
          name: input.name,
          description: input.description ?? null,
          category: input.category,
          risk: input.risk,
          estimatedDuration: input.estimatedDuration ?? null,
          tags: input.tags ?? [],
          steps: input.steps,
          clonedFrom: input.clonedFrom ?? null,
          createdBy: ctx.user?.name ?? "operator",
          isShared: 1,
          usageCount: 0,
          createdAt: now,
          updatedAt: now,
        });
      }
      return { templateId, saved: true };
    }),

  // Clone a built-in template to custom
  cloneTemplate: protectedProcedure
    .input(z.object({
      sourceId: z.string(),
      name: z.string(),
      description: z.string().optional(),
      category: z.enum(["recon", "credential", "persistence", "lateral", "exfil", "custom"]),
      risk: z.enum(["low", "medium", "high", "critical"]),
      estimatedDuration: z.string().optional(),
      tags: z.array(z.string()).optional(),
      steps: z.array(taskStepSchema).min(1),
    }))
    .mutation(async ({ input, ctx }) => {
        const db = await getDbRequired();
      const now = Date.now();
      const templateId = `tpl-${randomUUID().slice(0, 12)}`;
      await db.insert(emberCustomTemplates).values({
        templateId,
        name: input.name,
        description: input.description ?? null,
        category: input.category,
        risk: input.risk,
        estimatedDuration: input.estimatedDuration ?? null,
        tags: input.tags ?? [],
        steps: input.steps,
        clonedFrom: input.sourceId,
        createdBy: ctx.user?.name ?? "operator",
        isShared: 1,
        usageCount: 0,
        createdAt: now,
        updatedAt: now,
      });
      return { templateId, cloned: true };
    }),

  // Delete a custom template
  deleteTemplate: protectedProcedure
    .input(z.object({ templateId: z.string() }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      await db.delete(emberCustomTemplates)
        .where(eq(emberCustomTemplates.templateId, input.templateId));
      return { deleted: true };
    }),

  // Increment usage count
  trackTemplateUsage: protectedProcedure
    .input(z.object({ templateId: z.string() }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      await db.update(emberCustomTemplates)
        .set({
          usageCount: sql`${emberCustomTemplates.usageCount} + 1`,
          lastUsedAt: Date.now(),
        })
        .where(eq(emberCustomTemplates.templateId, input.templateId));
      return { tracked: true };
    }),

  // ─── Campaign Procedures ──────────────────────────────────────────────────

  // List all campaigns
  listCampaigns: protectedProcedure.query(async () => {
      const db = await getDbRequired();
    const campaigns = await db.select().from(emberCampaigns).orderBy(desc(emberCampaigns.updatedAt));
    return campaigns;
  }),

  // Get campaign with phases and logs
  getCampaign: protectedProcedure
    .input(z.object({ campaignId: z.string() }))
    .query(async ({ input }) => {
        const db = await getDbRequired();
      const [campaign] = await db.select().from(emberCampaigns)
        .where(eq(emberCampaigns.campaignId, input.campaignId));
      if (!campaign) return null;

      const phases = await db.select().from(emberCampaignPhases)
        .where(eq(emberCampaignPhases.campaignId, input.campaignId))
        .orderBy(emberCampaignPhases.phaseIndex);

      const logs = await db.select().from(emberCampaignLogs)
        .where(eq(emberCampaignLogs.campaignId, input.campaignId))
        .orderBy(desc(emberCampaignLogs.createdAt))
        .limit(100);

      return { ...campaign, phases, logs };
    }),

  // Create a new campaign
  createCampaign: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      objective: z.string().optional(),
      targetInfo: z.object({
        primaryTarget: z.string().optional(),
        network: z.string().optional(),
        scope: z.string().optional(),
      }).optional(),
      agentIds: z.array(z.string()).optional(),
      phases: z.array(z.object({
        name: z.string(),
        description: z.string().optional(),
        templateId: z.string().optional(),
        templateName: z.string().optional(),
        taskSteps: z.array(taskStepSchema).min(1),
        agentId: z.string().optional(),
        targetIp: z.string().optional(),
        customParams: z.record(z.string()).optional(),
        conditions: phaseConditionSchema.optional(),
      })),
    }))
    .mutation(async ({ input, ctx }) => {
        const db = await getDbRequired();
      const now = Date.now();
      const campaignId = `cmp-${randomUUID().slice(0, 12)}`;

      await db.insert(emberCampaigns).values({
        campaignId,
        name: input.name,
        description: input.description ?? null,
        objective: input.objective ?? null,
        status: "draft",
        targetInfo: input.targetInfo ?? null,
        phaseCount: input.phases.length,
        currentPhaseIndex: 0,
        phasesCompleted: 0,
        phasesFailed: 0,
        phasesSkipped: 0,
        agentIds: input.agentIds ?? [],
        createdBy: ctx.user?.name ?? "operator",
        createdAt: now,
        updatedAt: now,
      });

      // Insert phases
      for (let i = 0; i < input.phases.length; i++) {
        const p = input.phases[i];
        const cond = p.conditions ?? {};
        await db.insert(emberCampaignPhases).values({
          phaseId: `ph-${randomUUID().slice(0, 12)}`,
          campaignId,
          phaseIndex: i,
          name: p.name,
          description: p.description ?? null,
          templateId: p.templateId ?? null,
          templateName: p.templateName ?? null,
          taskSteps: p.taskSteps,
          agentId: p.agentId ?? null,
          targetIp: p.targetIp ?? null,
          customParams: p.customParams ?? null,
          status: "pending",
          onSuccess: cond.onSuccess ?? "continue",
          onFailure: cond.onFailure ?? "abort",
          onTimeout: cond.onTimeout ?? "abort",
          jumpToPhaseIndex: cond.jumpToPhaseIndex ?? null,
          maxRetries: cond.maxRetries ?? 1,
          retriesUsed: 0,
          timeoutSeconds: cond.timeoutSeconds ?? 600,
          delayBeforeMs: cond.delayBeforeMs ?? 0,
          conditionExpression: cond.conditionExpression ?? null,
          createdAt: now,
        });
      }

      // Log creation
      await db.insert(emberCampaignLogs).values({
        campaignId,
        level: "info",
        message: `Campaign "${input.name}" created with ${input.phases.length} phases`,
        createdAt: now,
      });

      return { campaignId, created: true };
    }),

  // Update campaign status
  updateCampaignStatus: protectedProcedure
    .input(z.object({
      campaignId: z.string(),
      status: z.enum(["draft", "ready", "running", "paused", "completed", "failed", "aborted"]),
    }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      const now = Date.now();
      const updates: any = { status: input.status, updatedAt: now };
      if (input.status === "running") updates.startedAt = now;
      if (["completed", "failed", "aborted"].includes(input.status)) updates.completedAt = now;

      await db.update(emberCampaigns)
        .set(updates)
        .where(eq(emberCampaigns.campaignId, input.campaignId));

      await db.insert(emberCampaignLogs).values({
        campaignId: input.campaignId,
        level: input.status === "failed" || input.status === "aborted" ? "error" : "info",
        message: `Campaign status changed to ${input.status}`,
        createdAt: now,
      });

      return { updated: true };
    }),

  // Execute next phase of a campaign
  executePhase: protectedProcedure
    .input(z.object({
      campaignId: z.string(),
      phaseId: z.string(),
    }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      const now = Date.now();

      // Get the phase
      const [phase] = await db.select().from(emberCampaignPhases)
        .where(and(
          eq(emberCampaignPhases.campaignId, input.campaignId),
          eq(emberCampaignPhases.phaseId, input.phaseId),
        ));
      if (!phase) throw new Error("Phase not found");

      // Mark phase as running
      await db.update(emberCampaignPhases)
        .set({ status: "running", startedAt: now })
        .where(eq(emberCampaignPhases.phaseId, input.phaseId));

      // Queue tasks for this phase
      const steps = (phase.taskSteps as any[]) || [];
      const agentId = phase.agentId;
      if (!agentId) throw new Error("No agent assigned to this phase");

      const taskIds: string[] = [];
      for (const step of steps) {
        const taskId = `et-${randomUUID().slice(0, 12)}`;
        await db.insert(emberTasks).values({
          taskId,
          agentId,
          type: step.taskType,
          priority: step.priority ?? 5,
          params: step.params ?? {},
          requiresElevation: step.requiresElevation ? 1 : 0,
          assignedBy: "campaign",
          cognitiveReasoning: `Campaign phase: ${phase.name}`,
          status: "pending",
          createdAt: now,
        });
        taskIds.push(taskId);
      }

      await db.insert(emberCampaignLogs).values({
        campaignId: input.campaignId,
        phaseId: input.phaseId,
        level: "info",
        message: `Phase "${phase.name}" started: ${taskIds.length} tasks queued for agent ${agentId}`,
        metadata: { taskIds },
        createdAt: now,
      });

      // Update campaign current phase
      await db.update(emberCampaigns)
        .set({ currentPhaseIndex: phase.phaseIndex, status: "running", updatedAt: now })
        .where(eq(emberCampaigns.campaignId, input.campaignId));

      return { phaseId: input.phaseId, taskIds, started: true };
    }),

  // Complete a phase and determine next action
  completePhase: protectedProcedure
    .input(z.object({
      campaignId: z.string(),
      phaseId: z.string(),
      result: z.enum(["success", "failed", "timeout"]),
      output: z.string().optional(),
      error: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      const now = Date.now();

      // Update phase status
      await db.update(emberCampaignPhases)
        .set({
          status: input.result,
          completedAt: now,
          output: input.output ?? null,
          error: input.error ?? null,
        })
        .where(eq(emberCampaignPhases.phaseId, input.phaseId));

      // Get the phase to check conditions
      const [phase] = await db.select().from(emberCampaignPhases)
        .where(eq(emberCampaignPhases.phaseId, input.phaseId));
      if (!phase) throw new Error("Phase not found");

      // Get all phases for this campaign
      const allPhases = await db.select().from(emberCampaignPhases)
        .where(eq(emberCampaignPhases.campaignId, input.campaignId))
        .orderBy(emberCampaignPhases.phaseIndex);

      // Determine next action based on conditions
      let conditionKey: "onSuccess" | "onFailure" | "onTimeout";
      if (input.result === "success") conditionKey = "onSuccess";
      else if (input.result === "timeout") conditionKey = "onTimeout";
      else conditionKey = "onFailure";

      const action = phase[conditionKey];
      let nextAction = "none";
      let nextPhaseId: string | null = null;

      // Update campaign counters
      const counterUpdate: any = { updatedAt: now };
      if (input.result === "success") counterUpdate.phasesCompleted = sql`${emberCampaigns.phasesCompleted} + 1`;
      else if (input.result === "failed") counterUpdate.phasesFailed = sql`${emberCampaigns.phasesFailed} + 1`;

      if (action === "continue") {
        const nextIdx = phase.phaseIndex + 1;
        const nextPhase = allPhases.find(p => p.phaseIndex === nextIdx);
        if (nextPhase) {
          nextAction = "execute_next";
          nextPhaseId = nextPhase.phaseId;
        } else {
          nextAction = "campaign_complete";
          counterUpdate.status = "completed";
          counterUpdate.completedAt = now;
        }
      } else if (action === "skip_next") {
        const skipIdx = phase.phaseIndex + 2;
        const skipPhase = allPhases.find(p => p.phaseIndex === skipIdx);
        if (skipPhase) {
          // Mark the skipped phase
          const skippedPhase = allPhases.find(p => p.phaseIndex === phase.phaseIndex + 1);
          if (skippedPhase) {
            await db.update(emberCampaignPhases)
              .set({ status: "skipped", completedAt: now })
              .where(eq(emberCampaignPhases.phaseId, skippedPhase.phaseId));
            counterUpdate.phasesSkipped = sql`${emberCampaigns.phasesSkipped} + 1`;
          }
          nextAction = "execute_next";
          nextPhaseId = skipPhase.phaseId;
        } else {
          nextAction = "campaign_complete";
          counterUpdate.status = "completed";
          counterUpdate.completedAt = now;
        }
      } else if (action === "jump_to" && phase.jumpToPhaseIndex != null) {
        const jumpPhase = allPhases.find(p => p.phaseIndex === phase.jumpToPhaseIndex);
        if (jumpPhase) {
          nextAction = "execute_next";
          nextPhaseId = jumpPhase.phaseId;
        } else {
          nextAction = "campaign_complete";
          counterUpdate.status = "completed";
          counterUpdate.completedAt = now;
        }
      } else if (action === "complete") {
        nextAction = "campaign_complete";
        counterUpdate.status = "completed";
        counterUpdate.completedAt = now;
      } else if (action === "abort") {
        nextAction = "campaign_aborted";
        counterUpdate.status = "failed";
        counterUpdate.completedAt = now;
      } else if (action === "skip") {
        const nextIdx = phase.phaseIndex + 1;
        const nextPhase = allPhases.find(p => p.phaseIndex === nextIdx);
        if (nextPhase) {
          nextAction = "execute_next";
          nextPhaseId = nextPhase.phaseId;
        } else {
          nextAction = "campaign_complete";
          counterUpdate.status = "completed";
          counterUpdate.completedAt = now;
        }
      } else if (action === "retry") {
        if ((phase.retriesUsed ?? 0) < (phase.maxRetries ?? 1)) {
          await db.update(emberCampaignPhases)
            .set({
              status: "pending",
              retriesUsed: (phase.retriesUsed ?? 0) + 1,
              startedAt: null,
              completedAt: null,
              output: null,
              error: null,
            })
            .where(eq(emberCampaignPhases.phaseId, input.phaseId));
          nextAction = "retry_phase";
          nextPhaseId = input.phaseId;
        } else {
          nextAction = "campaign_aborted";
          counterUpdate.status = "failed";
          counterUpdate.completedAt = now;
        }
      }

      await db.update(emberCampaigns).set(counterUpdate)
        .where(eq(emberCampaigns.campaignId, input.campaignId));

      await db.insert(emberCampaignLogs).values({
        campaignId: input.campaignId,
        phaseId: input.phaseId,
        level: input.result === "success" ? "success" : "error",
        message: `Phase "${phase.name}" ${input.result}. Next action: ${nextAction}`,
        metadata: { nextPhaseId, action },
        createdAt: now,
      });

      return { nextAction, nextPhaseId };
    }),

  // Delete a campaign
  deleteCampaign: protectedProcedure
    .input(z.object({ campaignId: z.string() }))
    .mutation(async ({ input }) => {
        const db = await getDbRequired();
      await db.delete(emberCampaignLogs).where(eq(emberCampaignLogs.campaignId, input.campaignId));
      await db.delete(emberCampaignPhases).where(eq(emberCampaignPhases.campaignId, input.campaignId));
      await db.delete(emberCampaigns).where(eq(emberCampaigns.campaignId, input.campaignId));
      return { deleted: true };
    }),

  // Get campaign logs
  getCampaignLogs: protectedProcedure
    .input(z.object({ campaignId: z.string(), limit: z.number().default(50) }))
    .query(async ({ input }) => {
        const db = await getDbRequired();
      const logs = await db.select().from(emberCampaignLogs)
        .where(eq(emberCampaignLogs.campaignId, input.campaignId))
        .orderBy(desc(emberCampaignLogs.createdAt))
        .limit(input.limit);
      return logs;
    }),
};
