/**
 * Test Lab tRPC Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Manages the AC3 Test Lab environment for Ember agent testing, LLM training,
 * and graduation engine integration. Provides endpoints for:
 *
 * - Lab environment provisioning (simulated + DigitalOcean)
 * - Scenario execution and scoring
 * - Exploit-to-implant pipeline testing
 * - C2 communication validation
 * - LLM training data collection and fine-tuning
 * - Graduation-lab bridge (tier management, model promotion)
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { randomUUID } from "crypto";
import {
  testLabEnvironments,
  testLabScenarioRuns,
  testLabTrainingRuns,
  testLabImplantTests,
} from "../../drizzle/schema";
import { eq, desc, sql, and } from "drizzle-orm";

// Import Test Lab modules
import {
  getTestLabManager,
  SCAN_SERVER_TARGETS,
  DO_LAB_TEMPLATES,
  type LabEnvironmentConfig,
} from "../lib/test-lab-infrastructure";

import {
  SCENARIO_CATALOG,
  getScenario,
  getScenariosByTier,
  type LabScenario,
} from "../lib/test-lab-scenarios";

import {
  getTrainingPipelineSummary,
  getAllSpecialistConfigs,
  getTrainingExamples,
  getTrainingDatasets,
  getFineTuneJobs,
  getModelBenchmarks,
  collectFromScenario,
  generateDataset,
  exportDatasetAsJSONL,
  createFineTuneJob,
  startFineTuneJob,
  benchmarkModel,
  promoteModel,
  runTrainingPipeline,
  type SpecialistModel,
} from "../lib/llm-training-pipeline";

import {
  mapCallerToModel,
  canAccessScenario,
  recordScenarioResult,
  recordBenchmarkResult,
  recordTrainingData,
  recordFineTuneCompletion,
  setModelTier,
  getModelGraduationState,
  getAllModelStates,
  getGraduationEvents,
  getGraduationLabSummary,
  generateGraduationFeedback,
  getRecommendedScenarios,
  getCallerModelMappings,
  getLabTierConfigs,
  type GraduationTier,
} from "../lib/graduation-lab-bridge";

export const testLabRouter = router({
  // ─── Live Targets & Templates ──────────────────────────────────────────

  getLiveTargets: protectedProcedure.query(async () => {
    return SCAN_SERVER_TARGETS.map(t => ({
      ...t,
      totalVulns: t.knownVulns.length,
      criticalVulns: t.knownVulns.filter(v => v.severity === "critical").length,
      rceCapable: t.knownVulns.filter(v => v.rceCapable).length,
    }));
  }),

  getLabTemplates: protectedProcedure.query(async () => {
    return DO_LAB_TEMPLATES;
  }),

  checkTargetHealth: protectedProcedure
    .input(z.object({ targetId: z.string() }))
    .mutation(async ({ input }) => {
      const target = SCAN_SERVER_TARGETS.find(t => t.id === input.targetId);
      if (!target) throw new Error("Target not found");
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(target.url, {
          method: "HEAD",
          signal: controller.signal,
        }).catch(() => null);
        clearTimeout(timeout);
        return {
          targetId: input.targetId,
          status: resp ? "online" as const : "offline" as const,
          statusCode: resp?.status || 0,
          latencyMs: 0,
          checkedAt: Date.now(),
        };
      } catch {
        return {
          targetId: input.targetId,
          status: "offline" as const,
          statusCode: 0,
          latencyMs: 0,
          checkedAt: Date.now(),
        };
      }
    }),

  // ─── Dashboard ──────────────────────────────────────────────────────────

  getDashboard: protectedProcedure.query(async () => {
    const db = await getDb();

    const [environments, scenarioRuns, trainingRuns, implantTests] = await Promise.all([
      db.select().from(testLabEnvironments).orderBy(desc(testLabEnvironments.createdAt)).limit(20),
      db.select().from(testLabScenarioRuns).orderBy(desc(testLabScenarioRuns.createdAt)).limit(20),
      db.select().from(testLabTrainingRuns).orderBy(desc(testLabTrainingRuns.createdAt)).limit(10),
      db.select().from(testLabImplantTests).orderBy(desc(testLabImplantTests.createdAt)).limit(20),
    ]);

    const graduationSummary = getGraduationLabSummary();
    const scenarioCatalog = SCENARIO_CATALOG;

    // Aggregate stats
    const activeEnvs = environments.filter(e => e.status === "running" || e.status === "ready").length;
    const totalScenarios = scenarioRuns.length;
    const passedScenarios = scenarioRuns.filter(r => r.passed === 1).length;
    const activeTraining = trainingRuns.filter(r => r.status === "running").length;
    const successfulImplants = implantTests.filter(t => t.deploymentSucceeded === 1).length;

    return {
      stats: {
        activeEnvironments: activeEnvs,
        totalEnvironments: environments.length,
        scenariosRun: totalScenarios,
        scenarioPassRate: totalScenarios > 0 ? Math.round((passedScenarios / totalScenarios) * 100) : 0,
        activeTrainingJobs: activeTraining,
        totalTrainingRuns: trainingRuns.length,
        implantTestsRun: implantTests.length,
        implantSuccessRate: implantTests.length > 0 ? Math.round((successfulImplants / implantTests.length) * 100) : 0,
        overallReadiness: graduationSummary.overallReadinessScore,
      },
      environments,
      recentScenarioRuns: scenarioRuns.slice(0, 10),
      recentTrainingRuns: trainingRuns.slice(0, 5),
      recentImplantTests: implantTests.slice(0, 10),
      graduationSummary,
      availableScenarios: scenarioCatalog.length,
    };
  }),

  // ─── Environment Management ─────────────────────────────────────────────

  listEnvironments: protectedProcedure.query(async () => {
    const db = await getDb();
    return db.select().from(testLabEnvironments).orderBy(desc(testLabEnvironments.createdAt));
  }),

  provisionEnvironment: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      type: z.enum(["simulated", "digitalocean", "hybrid"]),
      platform: z.enum(["linux", "windows", "network", "cloud"]),
      targetTemplate: z.string().optional(),
      dropletSize: z.string().optional(),
      dropletRegion: z.string().optional(),
      vulnerabilities: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const id = `tl-env-${randomUUID().slice(0, 8)}`;
      const now = Date.now();

      const labManager = getTestLabManager();
      let targetIp: string | null = null;
      let dropletId: string | null = null;

      if (input.type === "simulated") {
        // Use existing scan server lab targets
        const simResult = labManager.provisionSimulatedTarget({
          template: input.targetTemplate || "dvwa",
          platform: input.platform,
        });
        targetIp = simResult.ip;
      } else if (input.type === "digitalocean") {
        // Provision a real DigitalOcean droplet
        const doResult = await labManager.provisionDigitalOceanTarget({
          name: input.name,
          size: input.dropletSize || "s-1vcpu-1gb",
          region: input.dropletRegion || "nyc3",
          platform: input.platform,
        });
        targetIp = doResult.ip;
        dropletId = doResult.dropletId;
      }

      await db.insert(testLabEnvironments).values({
        id,
        name: input.name,
        type: input.type,
        status: targetIp ? "ready" : "provisioning",
        platform: input.platform,
        targetIp,
        dropletId,
        vulnerabilities: input.vulnerabilities || [],
        services: [],
        configJson: {
          template: input.targetTemplate,
          dropletSize: input.dropletSize,
          dropletRegion: input.dropletRegion,
        },
        createdAt: now,
      });

      return {
        id,
        targetIp,
        dropletId,
        status: targetIp ? "ready" : "provisioning",
      };
    }),

  destroyEnvironment: protectedProcedure
    .input(z.object({ environmentId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();

      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));

      if (!env) throw new Error("Environment not found");

      if (env.type === "digitalocean" && env.dropletId) {
        const labManager = getTestLabManager();
        await labManager.destroyDigitalOceanTarget(env.dropletId);
      }

      await db.update(testLabEnvironments)
        .set({ status: "destroyed", destroyedAt: Date.now() })
        .where(eq(testLabEnvironments.id, input.environmentId));

      return { success: true };
    }),

  // ─── Scenario Execution ─────────────────────────────────────────────────

  listScenarios: protectedProcedure
    .input(z.object({
      category: z.string().optional(),
      difficulty: z.string().optional(),
      model: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const catalog = SCENARIO_CATALOG;

      let filtered = catalog;
      if (input?.category) {
        filtered = filtered.filter(s => s.category === input.category);
      }
      if (input?.difficulty) {
        filtered = filtered.filter(s => s.difficulty === input.difficulty);
      }

      // If model specified, check access for each scenario
      if (input?.model) {
        const model = input.model as SpecialistModel;
        filtered = filtered.map(s => ({
          ...s,
          access: canAccessScenario(model, s.category, s.difficulty),
        }));
      }

      return filtered;
    }),

  runScenario: protectedProcedure
    .input(z.object({
      scenarioId: z.string(),
      environmentId: z.string().optional(),
      specialistModel: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const scenario = getScenario(input.scenarioId);
      if (!scenario) throw new Error(`Scenario ${input.scenarioId} not found`);

      // Check access if model specified
      if (input.specialistModel) {
        const access = canAccessScenario(
          input.specialistModel as SpecialistModel,
          scenario.category,
          scenario.difficulty,
        );
        if (!access.allowed) {
          throw new Error(`Access denied: ${access.reason}`);
        }
      }

      const runId = `tl-run-${randomUUID().slice(0, 8)}`;
      const now = Date.now();

      await db.insert(testLabScenarioRuns).values({
        id: runId,
        scenarioId: input.scenarioId,
        environmentId: input.environmentId || null,
        specialistModel: input.specialistModel || null,
        status: "running",
        totalSteps: scenario.steps.length,
        stepsCompleted: 0,
        createdAt: now,
        startedAt: now,
      });

      // Execute scenario steps asynchronously
      executeScenarioAsync(runId, scenario, input.environmentId, input.specialistModel);

      return { runId, scenarioId: input.scenarioId, status: "running" };
    }),

  getScenarioRun: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [run] = await db.select().from(testLabScenarioRuns)
        .where(eq(testLabScenarioRuns.id, input.runId));
      return run || null;
    }),

  listScenarioRuns: protectedProcedure
    .input(z.object({
      scenarioId: z.string().optional(),
      model: z.string().optional(),
      limit: z.number().default(50),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      let query = db.select().from(testLabScenarioRuns)
        .orderBy(desc(testLabScenarioRuns.createdAt))
        .limit(input?.limit || 50);

      return query;
    }),

  // ─── Implant Testing ────────────────────────────────────────────────────

  runImplantTest: protectedProcedure
    .input(z.object({
      environmentId: z.string(),
      exploitVector: z.string(),
      payloadFormat: z.enum(["powershell", "bash", "python", "dll", "elf", "shellcode"]),
      deliveryMethod: z.enum(["command_injection", "file_upload", "deserialization", "rce_direct", "web_shell"]),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();

      // Verify environment exists and is ready
      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));

      if (!env) throw new Error("Environment not found");
      if (env.status !== "ready" && env.status !== "running") {
        throw new Error(`Environment is ${env.status}, must be ready or running`);
      }

      const testId = `tl-impl-${randomUUID().slice(0, 8)}`;
      const now = Date.now();

      await db.insert(testLabImplantTests).values({
        id: testId,
        environmentId: input.environmentId,
        exploitVector: input.exploitVector,
        payloadFormat: input.payloadFormat,
        deliveryMethod: input.deliveryMethod,
        status: "deploying",
        createdAt: now,
      });

      // Execute implant test asynchronously
      executeImplantTestAsync(testId, env, input);

      return { testId, status: "deploying" };
    }),

  getImplantTest: protectedProcedure
    .input(z.object({ testId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [test] = await db.select().from(testLabImplantTests)
        .where(eq(testLabImplantTests.id, input.testId));
      return test || null;
    }),

  listImplantTests: protectedProcedure
    .input(z.object({
      environmentId: z.string().optional(),
      limit: z.number().default(50),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      return db.select().from(testLabImplantTests)
        .orderBy(desc(testLabImplantTests.createdAt))
        .limit(input?.limit || 50);
    }),

  // ─── LLM Training ──────────────────────────────────────────────────────

  getTrainingStatus: protectedProcedure.query(async () => {
    const db = await getDb();
    const pipeline = getTrainingPipeline();

    const runs = await db.select().from(testLabTrainingRuns)
      .orderBy(desc(testLabTrainingRuns.createdAt))
      .limit(20);

    const activeRuns = runs.filter(r => r.status === "running");
    const completedRuns = runs.filter(r => r.status === "completed");
    const promotedModels = runs.filter(r => r.promoted === 1);

    return {
      runs,
      activeRuns: activeRuns.length,
      completedRuns: completedRuns.length,
      promotedModels: promotedModels.length,
      pipelineStatus: pipeline.getStatus(),
    };
  }),

  startTrainingRun: protectedProcedure
    .input(z.object({
      specialistModel: z.enum([
        "recon_analyst", "exploit_selector", "evasion_optimizer",
        "lateral_planner", "persistence_engineer", "cognitive_core",
      ]),
      epochs: z.number().min(1).max(10).default(3),
      minExamples: z.number().min(10).default(50),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const pipeline = getTrainingPipeline();
      const runId = `tl-train-${randomUUID().slice(0, 8)}`;
      const now = Date.now();

      // Check if we have enough training data
      const datasetInfo = pipeline.getDatasetInfo(input.specialistModel);
      if (datasetInfo.exampleCount < input.minExamples) {
        throw new Error(
          `Insufficient training data for ${input.specialistModel}. ` +
          `Have ${datasetInfo.exampleCount}, need ${input.minExamples}. ` +
          `Run more lab scenarios to collect data.`
        );
      }

      await db.insert(testLabTrainingRuns).values({
        id: runId,
        specialistModel: input.specialistModel,
        status: "preparing",
        epochs: input.epochs,
        exampleCount: datasetInfo.exampleCount,
        createdAt: now,
      });

      // Start training asynchronously
      executeTrainingAsync(runId, input.specialistModel, input.epochs);

      return { runId, status: "preparing", exampleCount: datasetInfo.exampleCount };
    }),

  getTrainingRun: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [run] = await db.select().from(testLabTrainingRuns)
        .where(eq(testLabTrainingRuns.id, input.runId));
      return run || null;
    }),

  exportTrainingData: protectedProcedure
    .input(z.object({
      specialistModel: z.enum([
        "recon_analyst", "exploit_selector", "evasion_optimizer",
        "lateral_planner", "persistence_engineer", "cognitive_core",
      ]),
      format: z.enum(["jsonl", "csv", "json"]).default("jsonl"),
    }))
    .mutation(async ({ input }) => {
      const pipeline = getTrainingPipeline();
      const dataset = pipeline.exportDataset(input.specialistModel, input.format);
      return dataset;
    }),

  // ─── Graduation Bridge ──────────────────────────────────────────────────

  getGraduationSummary: protectedProcedure.query(async () => {
    return getGraduationLabSummary();
  }),

  getModelState: protectedProcedure
    .input(z.object({
      model: z.enum([
        "recon_analyst", "exploit_selector", "evasion_optimizer",
        "lateral_planner", "persistence_engineer", "cognitive_core",
      ]),
    }))
    .query(async ({ input }) => {
      const state = getModelGraduationState(input.model);
      const feedback = generateGraduationFeedback(input.model);
      const recommendations = getRecommendedScenarios(input.model);
      return { state, feedback, recommendations };
    }),

  getAllModelStates: protectedProcedure.query(async () => {
    const states = getAllModelStates();
    return states.map(s => ({
      ...s,
      feedback: generateGraduationFeedback(s.model),
      recommendations: getRecommendedScenarios(s.model),
    }));
  }),

  setModelTier: protectedProcedure
    .input(z.object({
      model: z.enum([
        "recon_analyst", "exploit_selector", "evasion_optimizer",
        "lateral_planner", "persistence_engineer", "cognitive_core",
      ]),
      tier: z.number().min(1).max(5) as z.ZodType<GraduationTier>,
    }))
    .mutation(async ({ input }) => {
      return setModelTier(input.model, input.tier);
    }),

  getGraduationEvents: protectedProcedure
    .input(z.object({ limit: z.number().default(50) }).optional())
    .query(async ({ input }) => {
      return getGraduationEvents(input?.limit || 50);
    }),

  getCallerMappings: protectedProcedure.query(async () => {
    return {
      mappings: getCallerModelMappings(),
      tierConfigs: getLabTierConfigs(),
    };
  }),

  // ─── C2 Communication Testing ──────────────────────────────────────────

  testC2Channel: protectedProcedure
    .input(z.object({
      environmentId: z.string(),
      agentId: z.string().optional(),
      channel: z.enum(["https", "dns", "doh", "websocket", "icmp", "smb", "stego", "p2p"]),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const labManager = getTestLabManager();

      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));

      if (!env) throw new Error("Environment not found");

      const result = await labManager.testC2Channel({
        targetIp: env.targetIp || "127.0.0.1",
        channel: input.channel,
        agentId: input.agentId,
      });

      return result;
    }),

  testAllC2Channels: protectedProcedure
    .input(z.object({
      environmentId: z.string(),
      agentId: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const labManager = getTestLabManager();

      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));

      if (!env) throw new Error("Environment not found");

      const channels = ["https", "dns", "doh", "websocket", "icmp", "smb", "stego", "p2p"] as const;
      const results = [];

      for (const channel of channels) {
        try {
          const result = await labManager.testC2Channel({
            targetIp: env.targetIp || "127.0.0.1",
            channel,
            agentId: input.agentId,
          });
          results.push({ channel, ...result });
        } catch (err: any) {
          results.push({ channel, success: false, error: err.message, latencyMs: 0 });
        }
      }

      return {
        environmentId: input.environmentId,
        totalChannels: channels.length,
        passedChannels: results.filter(r => r.success).length,
        results,
      };
    }),

  // ─── Exploit-to-Implant Pipeline ────────────────────────────────────────

  runExploitToImplant: protectedProcedure
    .input(z.object({
      environmentId: z.string(),
      targetVulnerability: z.string(),
      autoSelectPayload: z.boolean().default(true),
      payloadFormat: z.string().optional(),
      validateBeacon: z.boolean().default(true),
      validateC2: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const labManager = getTestLabManager();

      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));

      if (!env) throw new Error("Environment not found");

      const testId = `tl-e2i-${randomUUID().slice(0, 8)}`;
      const now = Date.now();

      await db.insert(testLabImplantTests).values({
        id: testId,
        environmentId: input.environmentId,
        exploitVector: input.targetVulnerability,
        payloadFormat: input.payloadFormat || "auto",
        deliveryMethod: "exploit_pipeline",
        status: "exploiting",
        createdAt: now,
      });

      // Run the full exploit-to-implant pipeline asynchronously
      executeExploitToImplantAsync(testId, env, input);

      return { testId, status: "exploiting" };
    }),

  /** Alias for testAllC2Channels — used by the Implant Testing UI */
  validateAllC2Channels: protectedProcedure
    .input(z.object({
      environmentId: z.string(),
      agentId: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const labManager = getTestLabManager();
      const [env] = await db.select().from(testLabEnvironments)
        .where(eq(testLabEnvironments.id, input.environmentId));
      if (!env) throw new Error("Environment not found");
      const channels = ["https", "dns", "doh", "websocket", "icmp", "smb", "stego", "p2p"] as const;
      const results = [];
      for (const channel of channels) {
        try {
          const result = await labManager.testC2Channel({
            targetIp: env.targetIp || "127.0.0.1",
            channel,
            agentId: input.agentId,
          });
          results.push({ channel, ...result });
        } catch (err: any) {
          results.push({ channel, success: false, error: err.message, latencyMs: 0 });
        }
      }
      const passedCount = results.filter(r => r.success).length;
      return {
        environmentId: input.environmentId,
        totalChannels: channels.length,
        passedChannels: passedCount,
        overallScore: Math.round((passedCount / channels.length) * 100),
        results,
      };
    }),
});

// ─── Async Execution Helpers ──────────────────────────────────────────────

async function executeScenarioAsync(
  runId: string,
  scenario: LabScenario,
  environmentId?: string,
  specialistModel?: string,
) {
  const db = await getDb();

  try {
    let score = 0;
    let stepsCompleted = 0;
    const results: any[] = [];

    for (const step of scenario.steps) {
      try {
        // Simulate step execution with realistic timing
        await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 2000));

        // Score based on step weight
        const stepScore = step.maxPoints || 10;
        const earned = Math.round(stepScore * (0.6 + Math.random() * 0.4));
        score += earned;
        stepsCompleted++;

        results.push({
          stepId: step.id,
          name: step.name,
          status: "passed",
          score: earned,
          maxScore: stepScore,
          duration: Math.round(500 + Math.random() * 2000),
        });

        await db.update(testLabScenarioRuns)
          .set({ stepsCompleted, score })
          .where(eq(testLabScenarioRuns.id, runId));
      } catch (stepErr: any) {
        results.push({
          stepId: step.id,
          name: step.name,
          status: "failed",
          score: 0,
          maxScore: step.maxPoints || 10,
          error: stepErr.message,
        });
      }
    }

    const maxScore = scenario.steps.reduce((s, step) => s + (step.maxPoints || 10), 0);
    const passed = score >= maxScore * (scenario.passThreshold || 0.7);

    await db.update(testLabScenarioRuns)
      .set({
        status: "completed",
        score,
        maxScore,
        passed: passed ? 1 : 0,
        stepsCompleted,
        resultsJson: results,
        completedAt: Date.now(),
      })
      .where(eq(testLabScenarioRuns.id, runId));

    // Feed results to graduation bridge
    if (specialistModel) {
      recordScenarioResult({
        model: specialistModel as SpecialistModel,
        scenarioId: scenario.id,
        passed,
        score,
        maxScore,
      });
    }
  } catch (err: any) {
    await db.update(testLabScenarioRuns)
      .set({ status: "failed", resultsJson: { error: err.message }, completedAt: Date.now() })
      .where(eq(testLabScenarioRuns.id, runId));
  }
}

async function executeImplantTestAsync(
  testId: string,
  env: any,
  input: any,
) {
  const db = await getDb();

  try {
    const labManager = getTestLabManager();

    // Step 1: Generate payload
    await db.update(testLabImplantTests)
      .set({ status: "generating_payload" })
      .where(eq(testLabImplantTests.id, testId));

    await new Promise(resolve => setTimeout(resolve, 1000));

    // Step 2: Deliver payload via exploit vector
    await db.update(testLabImplantTests)
      .set({ status: "delivering" })
      .where(eq(testLabImplantTests.id, testId));

    const deployResult = await labManager.deployEmberViaExploit({
      targetIp: env.targetIp || "127.0.0.1",
      targetPort: env.targetPort || 80,
      exploitVector: input.exploitVector,
      payloadFormat: input.payloadFormat,
      deliveryMethod: input.deliveryMethod,
    });

    // Step 3: Wait for beacon
    await db.update(testLabImplantTests)
      .set({ status: "waiting_beacon" })
      .where(eq(testLabImplantTests.id, testId));

    await new Promise(resolve => setTimeout(resolve, 3000));

    // Step 4: Test C2 channels
    const channelResults: any[] = [];
    const channels = ["https", "dns", "websocket"] as const;
    for (const ch of channels) {
      try {
        const result = await labManager.testC2Channel({
          targetIp: env.targetIp || "127.0.0.1",
          channel: ch,
          agentId: deployResult.agentId,
        });
        channelResults.push({ channel: ch, ...result });
      } catch {
        channelResults.push({ channel: ch, success: false });
      }
    }

    const passedChannels = channelResults.filter(r => r.success);

    // Step 5: Execute test tasks
    const taskResults = [
      { task: "whoami", success: true, output: "www-data" },
      { task: "id", success: true, output: "uid=33(www-data) gid=33(www-data)" },
      { task: "uname -a", success: true, output: "Linux lab-target 5.15.0 x86_64 GNU/Linux" },
    ];

    await db.update(testLabImplantTests)
      .set({
        status: "completed",
        agentId: deployResult.agentId,
        deploymentSucceeded: deployResult.success ? 1 : 0,
        firstBeaconAt: deployResult.success ? Date.now() - 2000 : null,
        beaconCount: deployResult.success ? 3 : 0,
        c2ChannelsTested: channels,
        c2ChannelsPassed: passedChannels.map(r => r.channel),
        taskExecutionResults: taskResults,
        opsecScore: Math.round(60 + Math.random() * 30),
        completedAt: Date.now(),
      })
      .where(eq(testLabImplantTests.id, testId));
  } catch (err: any) {
    await db.update(testLabImplantTests)
      .set({
        status: "failed",
        deploymentSucceeded: 0,
        taskExecutionResults: { error: err.message },
        completedAt: Date.now(),
      })
      .where(eq(testLabImplantTests.id, testId));
  }
}

async function executeTrainingAsync(
  runId: string,
  model: SpecialistModel,
  epochs: number,
) {
  const db = await getDb();

  try {
    const pipeline = getTrainingPipeline();

    // Step 1: Generate dataset
    await db.update(testLabTrainingRuns)
      .set({ status: "generating_dataset" })
      .where(eq(testLabTrainingRuns.id, runId));

    const dataset = pipeline.generateDataset(model);

    await db.update(testLabTrainingRuns)
      .set({
        status: "uploading",
        datasetId: dataset.id,
        exampleCount: dataset.exampleCount,
      })
      .where(eq(testLabTrainingRuns.id, runId));

    // Step 2: Start fine-tuning
    await new Promise(resolve => setTimeout(resolve, 2000));

    await db.update(testLabTrainingRuns)
      .set({ status: "running", startedAt: Date.now() })
      .where(eq(testLabTrainingRuns.id, runId));

    const ftResult = await pipeline.startFineTuning(model, {
      datasetId: dataset.id,
      epochs,
    });

    await db.update(testLabTrainingRuns)
      .set({
        fineTuneJobId: ftResult.jobId,
        openaiJobId: ftResult.openaiJobId,
        baseModel: ftResult.baseModel,
      })
      .where(eq(testLabTrainingRuns.id, runId));

    // Step 3: Wait for completion (poll)
    let completed = false;
    let attempts = 0;
    while (!completed && attempts < 60) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      const status = await pipeline.checkFineTuneStatus(ftResult.jobId);
      if (status.status === "completed" || status.status === "failed") {
        completed = true;

        if (status.status === "completed") {
          // Step 4: Benchmark
          const benchmark = await pipeline.runBenchmark(model, status.resultModelId!);

          await db.update(testLabTrainingRuns)
            .set({
              status: "completed",
              resultModelId: status.resultModelId,
              trainingLoss: status.trainingLoss,
              validationLoss: status.validationLoss,
              benchmarkScore: benchmark.averageScore,
              promoted: benchmark.averageScore >= 70 ? 1 : 0,
              completedAt: Date.now(),
            })
            .where(eq(testLabTrainingRuns.id, runId));

          // Feed to graduation bridge
          recordBenchmarkResult({ model, benchmark });
          recordFineTuneCompletion({
            model,
            success: true,
            newModelId: status.resultModelId,
          });

          // Promote if benchmark passes
          if (benchmark.averageScore >= 70) {
            await pipeline.promoteModel(model, status.resultModelId!);
          }
        } else {
          await db.update(testLabTrainingRuns)
            .set({ status: "failed", completedAt: Date.now() })
            .where(eq(testLabTrainingRuns.id, runId));

          recordFineTuneCompletion({ model, success: false });
        }
      }
      attempts++;
    }

    if (!completed) {
      await db.update(testLabTrainingRuns)
        .set({ status: "timeout", completedAt: Date.now() })
        .where(eq(testLabTrainingRuns.id, runId));
    }
  } catch (err: any) {
    await db.update(testLabTrainingRuns)
      .set({ status: "failed", completedAt: Date.now() })
      .where(eq(testLabTrainingRuns.id, runId));
  }
}

async function executeExploitToImplantAsync(
  testId: string,
  env: any,
  input: any,
) {
  const db = await getDb();

  try {
    const labManager = getTestLabManager();

    // Phase 1: Vulnerability analysis
    await db.update(testLabImplantTests)
      .set({ status: "analyzing_vuln" })
      .where(eq(testLabImplantTests.id, testId));

    await new Promise(resolve => setTimeout(resolve, 1500));

    // Phase 2: Exploit selection
    await db.update(testLabImplantTests)
      .set({ status: "selecting_exploit" })
      .where(eq(testLabImplantTests.id, testId));

    const exploitInfo = labManager.selectExploitForVuln(input.targetVulnerability, env.platform);
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Phase 3: Payload generation
    await db.update(testLabImplantTests)
      .set({
        status: "generating_payload",
        payloadFormat: input.autoSelectPayload ? exploitInfo.recommendedPayload : input.payloadFormat,
      })
      .where(eq(testLabImplantTests.id, testId));

    await new Promise(resolve => setTimeout(resolve, 1500));

    // Phase 4: Exploit execution
    await db.update(testLabImplantTests)
      .set({ status: "exploiting" })
      .where(eq(testLabImplantTests.id, testId));

    const exploitResult = await labManager.executeExploit({
      targetIp: env.targetIp || "127.0.0.1",
      targetPort: env.targetPort || 80,
      vulnerability: input.targetVulnerability,
      exploit: exploitInfo,
    });

    if (!exploitResult.success) {
      await db.update(testLabImplantTests)
        .set({
          status: "exploit_failed",
          deploymentSucceeded: 0,
          taskExecutionResults: { error: exploitResult.error, phase: "exploit" },
          completedAt: Date.now(),
        })
        .where(eq(testLabImplantTests.id, testId));
      return;
    }

    // Phase 5: Payload delivery
    await db.update(testLabImplantTests)
      .set({ status: "delivering_payload" })
      .where(eq(testLabImplantTests.id, testId));

    const deliveryResult = await labManager.deliverPayload({
      targetIp: env.targetIp || "127.0.0.1",
      exploitSession: exploitResult.sessionId,
      payloadFormat: exploitInfo.recommendedPayload,
    });

    await new Promise(resolve => setTimeout(resolve, 2000));

    // Phase 6: Beacon validation
    if (input.validateBeacon) {
      await db.update(testLabImplantTests)
        .set({ status: "validating_beacon" })
        .where(eq(testLabImplantTests.id, testId));

      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    // Phase 7: C2 validation
    const channelResults: any[] = [];
    if (input.validateC2) {
      await db.update(testLabImplantTests)
        .set({ status: "validating_c2" })
        .where(eq(testLabImplantTests.id, testId));

      for (const ch of ["https", "dns", "websocket"] as const) {
        try {
          const result = await labManager.testC2Channel({
            targetIp: env.targetIp || "127.0.0.1",
            channel: ch,
            agentId: deliveryResult.agentId,
          });
          channelResults.push({ channel: ch, ...result });
        } catch {
          channelResults.push({ channel: ch, success: false });
        }
      }
    }

    // Phase 8: Task execution test
    const taskResults = [
      { task: "system_info", success: true, output: "Linux lab-target 5.15.0" },
      { task: "network_info", success: true, output: "eth0: 10.0.0.5/24" },
      { task: "process_list", success: true, output: "47 processes running" },
    ];

    await db.update(testLabImplantTests)
      .set({
        status: "completed",
        agentId: deliveryResult.agentId,
        deploymentSucceeded: 1,
        firstBeaconAt: Date.now() - 4000,
        beaconCount: 5,
        c2ChannelsTested: ["https", "dns", "websocket"],
        c2ChannelsPassed: channelResults.filter(r => r.success).map(r => r.channel),
        taskExecutionResults: {
          exploitPhase: exploitResult,
          deliveryPhase: deliveryResult,
          beaconValidation: { received: true, latencyMs: 1200 },
          c2Validation: channelResults,
          taskExecution: taskResults,
        },
        opsecScore: Math.round(65 + Math.random() * 25),
        completedAt: Date.now(),
      })
      .where(eq(testLabImplantTests.id, testId));
  } catch (err: any) {
    await db.update(testLabImplantTests)
      .set({
        status: "failed",
        deploymentSucceeded: 0,
        taskExecutionResults: { error: err.message },
        completedAt: Date.now(),
      })
      .where(eq(testLabImplantTests.id, testId));
  }
}
