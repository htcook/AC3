/**
 * Agent Registry & NEXUS Pipeline Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Manages offensive security agent definitions and the NEXUS-Micro code
 * generation pipeline. Provides:
 *   - Agent CRUD (list, get, seed, activate, deactivate)
 *   - NEXUS pipeline execution (trigger, monitor, quality gates)
 *   - Agent-to-LLM caller mapping for prompt injection
 *   - Pipeline execution history and analytics
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import {
  agentDefinitions,
  nexusPipelineExecutions,
  nexusQualityGates,
  nexusShadowConfigs,
  nexusShadowTests,
} from "../../drizzle/schema";
import { eq, desc, sql, and, gte } from "drizzle-orm";
import {
  ALL_OFFENSIVE_AGENTS,
  buildAgentSystemPrompt,
  matchCallerToAgent,
  getAgentByCategory,
} from "../lib/agent-definitions";
import {
  executeNexusPipeline,
  type NexusPipelineInput,
} from "../lib/nexus-pipeline";
import { getShadowTestAnalytics } from "../lib/shadow-testing";

// ─── Agent Registry Procedures ─────────────────────────────────────────────

export const agentRegistryRouter = router({
  /**
   * List all agent definitions with optional status/category filter
   */
  listAgents: protectedProcedure
    .input(
      z.object({
        status: z.enum(["active", "draft", "deprecated", "testing"]).optional(),
        category: z.string().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions: any[] = [];
      if (input?.status) conditions.push(eq(agentDefinitions.status, input.status));

      const rows = conditions.length > 0
        ? await db.select().from(agentDefinitions).where(and(...conditions)).orderBy(agentDefinitions.name)
        : await db.select().from(agentDefinitions).orderBy(agentDefinitions.name);

      return {
        agents: rows.map((r) => ({
          ...r,
          coreRules: r.coreRules,
          evidenceTags: r.evidenceTags,
          deliverableTemplates: r.deliverableTemplates,
          workflowSteps: r.workflowSteps,
          toolAccess: r.toolAccess,
          mitreTactics: r.mitreTactics,
        })),
        total: rows.length,
        byCategory: rows.reduce((acc, r) => {
          acc[r.category] = (acc[r.category] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
      };
    }),

  /**
   * Get a single agent definition by agentId
   */
  getAgent: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [row] = await db
        .select()
        .from(agentDefinitions)
        .where(eq(agentDefinitions.agentId, input.agentId))
        .limit(1);
      if (!row) throw new Error(`Agent ${input.agentId} not found`);
      return row;
    }),

  /**
   * Seed all 5 offensive security agent definitions from code into the DB.
   * Upserts by agentId — safe to call multiple times.
   */
  seedAgents: protectedProcedure.mutation(async () => {
    const db = await getDbRequired();
    let created = 0;
    let updated = 0;

    for (const agent of ALL_OFFENSIVE_AGENTS) {
      const [existing] = await db
        .select({ id: agentDefinitions.id, version: agentDefinitions.version })
        .from(agentDefinitions)
        .where(eq(agentDefinitions.agentId, agent.agentId))
        .limit(1);

      if (existing) {
        await db
          .update(agentDefinitions)
          .set({
            name: agent.name,
            category: agent.category,
            persona: agent.persona,
            mission: agent.mission,
            coreRules: agent.coreRules,
            evidenceTags: agent.evidenceTags,
            deliverableTemplates: agent.deliverableTemplates,
            workflowSteps: agent.workflowSteps,
            toolAccess: agent.toolAccess,
            mitreTactics: agent.mitreTactics,
            llmCallerPrefix: agent.llmCallerPrefix,
            priority: agent.priority,
            version: (existing.version || 1) + 1,
            updatedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
          })
          .where(eq(agentDefinitions.id, existing.id));
        updated++;
      } else {
        await db.insert(agentDefinitions).values({
          agentId: agent.agentId,
          name: agent.name,
          category: agent.category,
          persona: agent.persona,
          mission: agent.mission,
          coreRules: agent.coreRules,
          evidenceTags: agent.evidenceTags,
          deliverableTemplates: agent.deliverableTemplates,
          workflowSteps: agent.workflowSteps,
          toolAccess: agent.toolAccess,
          mitreTactics: agent.mitreTactics,
          llmCallerPrefix: agent.llmCallerPrefix,
          priority: agent.priority,
          status: "active",
          version: 1,
        });
        created++;
      }
    }

    return { created, updated, total: ALL_OFFENSIVE_AGENTS.length };
  }),

  /**
   * Activate or deactivate an agent definition
   */
  setAgentStatus: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      status: z.enum(["active", "draft", "deprecated", "testing"]),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const result = await db
        .update(agentDefinitions)
        .set({
          status: input.status,
          updatedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
        })
        .where(eq(agentDefinitions.agentId, input.agentId));
      return { success: true, agentId: input.agentId, newStatus: input.status };
    }),

  /**
   * Build a system prompt for a given caller — used by the LLM routing layer
   * to inject agent-specific persona and rules into invokeLLM calls.
   */
  buildPromptForCaller: protectedProcedure
    .input(z.object({
      caller: z.string(),
      additionalContext: z.string().optional(),
    }))
    .query(async ({ input }) => {
      // First check DB for active agent definitions
      const db = await getDbRequired();
      const activeAgents = await db
        .select()
        .from(agentDefinitions)
        .where(eq(agentDefinitions.status, "active"));

      // Try to match caller to a DB agent
      for (const agent of activeAgents) {
        if (agent.llmCallerPrefix && input.caller.startsWith(agent.llmCallerPrefix)) {
          return {
            matched: true,
            agentId: agent.agentId,
            agentName: agent.name,
            systemPrompt: buildAgentSystemPrompt(agent, input.additionalContext),
            priority: agent.priority,
          };
        }
      }

      // Fallback to code-defined agents
      const codeAgent = matchCallerToAgent(input.caller);
      if (codeAgent) {
        return {
          matched: true,
          agentId: codeAgent.agentId,
          agentName: codeAgent.name,
          systemPrompt: buildAgentSystemPrompt(codeAgent, input.additionalContext),
          priority: codeAgent.priority,
        };
      }

      return { matched: false, agentId: null, agentName: null, systemPrompt: null, priority: "standard" as const };
    }),

  // ─── NEXUS Pipeline Procedures ─────────────────────────────────────────────

  /**
   * Trigger a NEXUS-Micro code generation pipeline for a graduation candidate.
   * This takes a caller name and its telemetry data, then runs the full
   * 6-stage pipeline: Requirement Analysis → Architecture → Code Generation →
   * QA Validation → Security Review → Integration Test
   */
  triggerPipeline: protectedProcedure
    .input(z.object({
      callerName: z.string(),
      graduationTier: z.number().min(1).max(5),
      triggerType: z.enum(["auto", "manual", "scheduled"]).default("manual"),
      sampleInputs: z.array(z.unknown()).optional(),
      sampleOutputs: z.array(z.unknown()).optional(),
      constraints: z.array(z.string()).optional(),
      performanceTargets: z.object({
        maxLatencyMs: z.number().default(5000),
        minAccuracy: z.number().default(95),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const executionId = `nexus-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      // Match caller to an agent for specialized code generation
      const agent = matchCallerToAgent(input.callerName);

      const pipelineInput: NexusPipelineInput = {
        executionId,
        callerName: input.callerName,
        graduationTier: input.graduationTier,
        triggerType: input.triggerType,
        agentDefinition: agent || undefined,
        requirementSpec: {
          inputSchema: {},
          outputSchema: {},
          sampleInputs: input.sampleInputs || [],
          sampleOutputs: input.sampleOutputs || [],
          constraints: input.constraints || [],
          performanceTargets: input.performanceTargets || { maxLatencyMs: 5000, minAccuracy: 95 },
        },
      };

      // Execute pipeline asynchronously (fire-and-forget with DB tracking)
      executeNexusPipeline(pipelineInput).catch((err) => {
        console.error(`[NEXUS] Pipeline ${executionId} failed:`, err);
      });

      return {
        executionId,
        callerName: input.callerName,
        status: "running",
        message: `NEXUS pipeline started for ${input.callerName}. Track progress via getPipelineStatus.`,
      };
    }),

  /**
   * Get the status of a NEXUS pipeline execution
   */
  getPipelineStatus: protectedProcedure
    .input(z.object({ executionId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [execution] = await db
        .select()
        .from(nexusPipelineExecutions)
        .where(eq(nexusPipelineExecutions.executionId, input.executionId))
        .limit(1);

      if (!execution) throw new Error(`Pipeline execution ${input.executionId} not found`);

      // Get quality gates for this execution
      const gates = await db
        .select()
        .from(nexusQualityGates)
        .where(eq(nexusQualityGates.executionId, input.executionId))
        .orderBy(nexusQualityGates.evaluatedAt);

      return {
        execution,
        qualityGates: gates,
        progress: computeProgress(execution.currentStage),
      };
    }),

  /**
   * List recent NEXUS pipeline executions
   */
  listPipelines: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(100).default(20),
        status: z.enum(["running", "completed", "failed", "rolled_back", "paused"]).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions: any[] = [];
      if (input?.status) conditions.push(eq(nexusPipelineExecutions.status, input.status));

      const rows = conditions.length > 0
        ? await db.select().from(nexusPipelineExecutions)
            .where(and(...conditions))
            .orderBy(desc(nexusPipelineExecutions.startedAt))
            .limit(input?.limit ?? 20)
        : await db.select().from(nexusPipelineExecutions)
            .orderBy(desc(nexusPipelineExecutions.startedAt))
            .limit(input?.limit ?? 20);

      // Summary stats
      const allRows = await db
        .select({
          status: nexusPipelineExecutions.status,
          count: sql<number>`COUNT(*)`,
          avgScore: sql<number>`AVG(${nexusPipelineExecutions.overallScore})`,
          totalCostSaved: sql<string>`SUM(COALESCE(${nexusPipelineExecutions.costSaved}, 0))`,
        })
        .from(nexusPipelineExecutions)
        .groupBy(nexusPipelineExecutions.status);

      return {
        executions: rows.map((r) => ({
          ...r,
          progress: computeProgress(r.currentStage),
        })),
        summary: {
          total: allRows.reduce((s, r) => s + Number(r.count), 0),
          byStatus: allRows.reduce((acc, r) => {
            if (r.status) acc[r.status] = Number(r.count);
            return acc;
          }, {} as Record<string, number>),
          avgScore: Math.round(
            allRows.reduce((s, r) => s + (Number(r.avgScore) || 0), 0) /
            Math.max(allRows.length, 1)
          ),
          totalCostSaved: allRows.reduce((s, r) => s + parseFloat(r.totalCostSaved || "0"), 0),
        },
      };
    }),

  /**
   * Get pipeline analytics — success rates, average scores, cost savings over time
   */
  getPipelineAnalytics: protectedProcedure
    .input(z.object({ windowDays: z.number().min(1).max(90).default(30) }).optional())
    .query(async ({ input }) => {
      const days = input?.windowDays ?? 30;
      const db = await getDbRequired();
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      // Daily pipeline execution stats
      const daily = await db
        .select({
          day: sql<string>`DATE(${nexusPipelineExecutions.startedAt})`.as("day"),
          total: sql<number>`COUNT(*)`,
          completed: sql<number>`SUM(CASE WHEN ${nexusPipelineExecutions.status} = 'completed' THEN 1 ELSE 0 END)`,
          failed: sql<number>`SUM(CASE WHEN ${nexusPipelineExecutions.status} = 'failed' THEN 1 ELSE 0 END)`,
          avgScore: sql<number>`AVG(${nexusPipelineExecutions.overallScore})`,
          totalCostSaved: sql<string>`SUM(COALESCE(${nexusPipelineExecutions.costSaved}, 0))`,
          totalTokens: sql<number>`SUM(COALESCE(${nexusPipelineExecutions.tokensConsumed}, 0))`,
        })
        .from(nexusPipelineExecutions)
        .where(gte(nexusPipelineExecutions.startedAt, cutoff.toISOString().slice(0, 19).replace("T", " ")))
        .groupBy(sql`DATE(${nexusPipelineExecutions.startedAt})`)
        .orderBy(sql`day`);

      // Quality gate pass rates by type
      const gateStats = await db
        .select({
          gateType: nexusQualityGates.gateType,
          total: sql<number>`COUNT(*)`,
          passed: sql<number>`SUM(${nexusQualityGates.passed})`,
          avgScore: sql<number>`AVG(${nexusQualityGates.score})`,
        })
        .from(nexusQualityGates)
        .where(gte(nexusQualityGates.evaluatedAt, cutoff.toISOString().slice(0, 19).replace("T", " ")))
        .groupBy(nexusQualityGates.gateType);

      // Top graduated callers (completed pipelines with high scores)
      const topGraduated = await db
        .select({
          callerName: nexusPipelineExecutions.callerName,
          overallScore: nexusPipelineExecutions.overallScore,
          costSaved: nexusPipelineExecutions.costSaved,
          completedAt: nexusPipelineExecutions.completedAt,
        })
        .from(nexusPipelineExecutions)
        .where(
          and(
            eq(nexusPipelineExecutions.status, "completed"),
            gte(nexusPipelineExecutions.startedAt, cutoff.toISOString().slice(0, 19).replace("T", " "))
          )
        )
        .orderBy(desc(nexusPipelineExecutions.overallScore))
        .limit(10);

      return {
        daily: daily.map((d) => ({
          day: d.day,
          total: Number(d.total),
          completed: Number(d.completed),
          failed: Number(d.failed),
          successRate: Number(d.total) > 0 ? Math.round((Number(d.completed) / Number(d.total)) * 100) : 0,
          avgScore: Math.round(Number(d.avgScore) || 0),
          costSaved: parseFloat(d.totalCostSaved || "0"),
          tokens: Number(d.totalTokens),
        })),
        gateStats: gateStats.map((g) => ({
          gateType: g.gateType,
          total: Number(g.total),
          passed: Number(g.passed),
          passRate: Number(g.total) > 0 ? Math.round((Number(g.passed) / Number(g.total)) * 100) : 0,
          avgScore: Math.round(Number(g.avgScore) || 0),
        })),
        topGraduated,
        windowDays: days,
      };
    }),

  // ─── Shadow Testing Procedures ──────────────────────────────────────────

  /**
   * List all shadow testing configurations
   */
  listShadowConfigs: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const configs = await db.select().from(nexusShadowConfigs).orderBy(desc(nexusShadowConfigs.createdAt));
    return { configs };
  }),

  /**
   * Create or update a shadow testing configuration
   */
  upsertShadowConfig: protectedProcedure
    .input(z.object({
      id: z.number().optional(),
      configName: z.string().min(1).max(128),
      enabled: z.boolean().default(false),
      shadowPercentage: z.number().min(1).max(100).default(5),
      primaryModel: z.string().default('gemini-2.5-flash'),
      experimentalModel: z.string().default('gpt-4o'),
      callerFilter: z.string().default(''),
      priorityFilter: z.enum(['all', 'essential', 'standard', 'bulk']).default('all'),
      maxConcurrent: z.number().min(1).max(50).default(10),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

      if (input.id) {
        await db.update(nexusShadowConfigs)
          .set({
            configName: input.configName,
            enabled: input.enabled ? 1 : 0,
            shadowPercentage: input.shadowPercentage,
            primaryModel: input.primaryModel,
            experimentalModel: input.experimentalModel,
            callerFilter: input.callerFilter,
            priorityFilter: input.priorityFilter,
            maxConcurrent: input.maxConcurrent,
            updatedAt: now,
          })
          .where(eq(nexusShadowConfigs.id, input.id));
        return { success: true, action: 'updated', id: input.id };
      } else {
        const [result] = await db.insert(nexusShadowConfigs).values({
          configName: input.configName,
          enabled: input.enabled ? 1 : 0,
          shadowPercentage: input.shadowPercentage,
          primaryModel: input.primaryModel,
          experimentalModel: input.experimentalModel,
          callerFilter: input.callerFilter,
          priorityFilter: input.priorityFilter,
          maxConcurrent: input.maxConcurrent,
        });
        return { success: true, action: 'created', id: result.insertId };
      }
    }),

  /**
   * Toggle a shadow config on/off
   */
  toggleShadowConfig: protectedProcedure
    .input(z.object({ id: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.update(nexusShadowConfigs)
        .set({
          enabled: input.enabled ? 1 : 0,
          updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
        })
        .where(eq(nexusShadowConfigs.id, input.id));
      return { success: true, id: input.id, enabled: input.enabled };
    }),

  /**
   * Delete a shadow config
   */
  deleteShadowConfig: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(nexusShadowConfigs).where(eq(nexusShadowConfigs.id, input.id));
      return { success: true };
    }),

  /**
   * Get shadow testing analytics
   */
  getShadowAnalytics: protectedProcedure
    .input(z.object({ windowDays: z.number().min(1).max(90).default(30) }).optional())
    .query(async ({ input }) => {
      const analytics = await getShadowTestAnalytics(input?.windowDays ?? 30);
      return analytics;
    }),

  /**
   * List recent shadow test results
   */
  listShadowTests: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(20),
      verdict: z.enum(['primary_better', 'experimental_better', 'tie', 'error']).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions: any[] = [];
      if (input?.verdict) conditions.push(eq(nexusShadowTests.judgeVerdict, input.verdict));

      const rows = conditions.length > 0
        ? await db.select().from(nexusShadowTests)
            .where(and(...conditions))
            .orderBy(desc(nexusShadowTests.createdAt))
            .limit(input?.limit ?? 20)
        : await db.select().from(nexusShadowTests)
            .orderBy(desc(nexusShadowTests.createdAt))
            .limit(input?.limit ?? 20);

      return { tests: rows };
    }),
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function computeProgress(stage: string | null): number {
  const stageOrder = [
    "requirement_analysis", "architecture", "code_generation",
    "qa_validation", "security_review", "integration_test", "completed",
  ];
  if (!stage) return 0;
  if (stage === "failed" || stage === "rolled_back") return -1;
  const idx = stageOrder.indexOf(stage);
  return idx >= 0 ? Math.round(((idx + 1) / stageOrder.length) * 100) : 0;
}
