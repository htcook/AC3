import * as db from "../db";
/**
 * Evasion Engine Router
 * ─────────────────────
 * Exposes the 3-tier SIEM/EDR evasion architecture:
 *   Tier 1: SIEM Rule Mutation Engine
 *   Tier 2: Payload Transformation Pipeline
 *   Tier 3: Evasion Scorecard + Purple Team Loop
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { evasionSessions, ruleRobustnessResults } from "../../drizzle/schema";
import { eq, desc, sql } from "drizzle-orm";

// Tier 1
import {
  testRuleMutations,
  testRawPatternMutations,
  parseSigmaRule,
  generateMutations,
  type MutationTestResult,
  type MutationCategory,
} from "../lib/siem-mutation-engine";

// Tier 2
import {
  buildPipeline,
  EVASION_TECHNIQUES,
  type EvasionProfile,
} from "../lib/payload-transform-pipeline";

// Tier 3
import {
  generateEvasionScorecard,
  generatePurpleTeamCycle,
  ATTACK_TECHNIQUE_CATALOG,
} from "../lib/evasion-scorecard";

async function getDbSafe() {
  const db = await _getDb();
  if (!db)
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Database unavailable",
    });
  return db;
}

export const evasionEngineRouter = router({
  // ═══════════════════════════════════════════════════════════════════
  // TIER 1 — SIEM RULE MUTATION ENGINE
  // ═══════════════════════════════════════════════════════════════════

  /** Test a command against a raw detection pattern (regex/string) */
  testRawPattern: protectedProcedure
    .input(
      z.object({
        command: z.string().min(1),
        pattern: z.string().min(1),
        categories: z
          .array(
            z.enum([
              "case_mutation",
              "path_mutation",
              "env_var_substitution",
              "encoding_mutation",
              "separator_mutation",
              "argument_mutation",
              "alias_substitution",
              "whitespace_mutation",
              "string_concat",
            ])
          )
          .optional(),
        maxVariantsPerCategory: z.number().min(1).max(50).optional(),
      })
    )
    .mutation(async ({ input }) => {
      const result = testRawPatternMutations(input.command, input.pattern, {
        categories: input.categories as MutationCategory[] | undefined,
        maxPerCategory: input.maxVariantsPerCategory,
      });
      return result;
    }),

  /** Test a command against a Sigma rule (YAML content) */
  testSigmaRule: protectedProcedure
    .input(
      z.object({
        command: z.string().min(1),
        sigmaYaml: z.string().min(1),
        categories: z
          .array(z.string())
          .optional(),
        maxVariantsPerCategory: z.number().min(1).max(50).optional(),
      })
    )
    .mutation(async ({ input }) => {
      const sigmaRule = parseSigmaRule(input.sigmaYaml);
      const result = testRuleMutations(input.command, sigmaRule, {
        categories: input.categories as MutationCategory[] | undefined,
        maxPerCategory: input.maxVariantsPerCategory,
      });
      return { ...result, parsedRule: sigmaRule };
    }),

  /** Generate mutation variants for a command (preview, no testing) */
  generateVariants: protectedProcedure
    .input(
      z.object({
        command: z.string().min(1),
        categories: z.array(z.string()).optional(),
        maxVariantsPerCategory: z.number().min(1).max(50).optional(),
      })
    )
    .query(({ input }) => {
      const variants = generateMutations(input.command, {
        categories: input.categories as MutationCategory[] | undefined,
        maxPerCategory: input.maxVariantsPerCategory,
      });
      return {
        originalCommand: input.command,
        totalVariants: variants.length,
        variants,
        categoryCounts: variants.reduce(
          (acc, v) => {
            acc[v.category] = (acc[v.category] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
      };
    }),

  /** Batch test multiple commands against multiple patterns */
  batchTest: protectedProcedure
    .input(
      z.object({
        tests: z.array(
          z.object({
            command: z.string(),
            pattern: z.string(),
          })
        ),
        saveSession: z.boolean().default(true),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const results: MutationTestResult[] = [];
      for (const test of input.tests) {
        results.push(testRawPatternMutations(test.command, test.pattern));
      }

      // Persist to DB if requested
      let sessionId: number | undefined;
      if (input.saveSession) {
        const db = await getDbSafe();
        const [session] = await db.insert(evasionSessions).values({
          sessionType: "mutation_test",
          techniques: [],
          mutationData: results,
          totalTechniques: results.length,
          detectedCount: results.filter((r) => r.robustnessClass === "robust").length,
          evadedCount: results.filter((r) => r.robustnessClass === "bypassed").length,
          robustRules: results.filter((r) => r.robustnessScore >= 70).length,
          fragileRules: results.filter((r) => r.robustnessScore < 70).length,
          totalRules: results.length,
          status: "completed",
          completedAt: new Date(),
          createdBy: ctx.user.id,
        });
        sessionId = Number(session.insertId);

        // Save individual results
        for (const r of results) {
          await db.insert(ruleRobustnessResults).values({
            sessionId: sessionId!,
            ruleId: r.detectionPattern.slice(0, 255),
            ruleTitle: r.detectionPattern.slice(0, 500),
            originalCommand: r.originalCommand,
            detectionPattern: r.detectionPattern,
            robustnessScore: r.robustnessScore,
            robustnessClass: r.robustnessClass,
            totalVariants: r.totalVariants,
            detectedCount: r.detectedCount,
            evadedCount: r.evadedCount,
            weakestCategories: r.weakestCategories,
            hardeningTips: r.hardeningTips,
            variantDetails: r.variants,
          });
        }
      }

      const avgRobustness =
        results.length > 0
          ? Math.round(
              results.reduce((s, r) => s + r.robustnessScore, 0) /
                results.length
            )
          : 0;

      return {
        sessionId,
        results,
        summary: {
          totalTests: results.length,
          avgRobustnessScore: avgRobustness,
          robust: results.filter((r) => r.robustnessClass === "robust").length,
          moderate: results.filter((r) => r.robustnessClass === "moderate").length,
          fragile: results.filter((r) => r.robustnessClass === "fragile").length,
          bypassed: results.filter((r) => r.robustnessClass === "bypassed").length,
        },
      };
    }),

  // ═══════════════════════════════════════════════════════════════════
  // TIER 2 — PAYLOAD TRANSFORMATION PIPELINE
  // ═══════════════════════════════════════════════════════════════════

  /** Get available evasion techniques */
  getEvasionTechniques: protectedProcedure.query(() => {
    return {
      techniques: EVASION_TECHNIQUES,
      profiles: ["none", "low", "medium", "high"] as EvasionProfile[],
    };
  }),

  /** Build a transform pipeline for a payload */
  buildPipeline: protectedProcedure
    .input(
      z.object({
        payloadType: z.enum([
          "exe",
          "dll",
          "shellcode",
          "powershell",
          "csharp",
          "hta",
          "vba",
        ]),
        targetArch: z.enum(["x64", "x86"]).default("x64"),
        targetOs: z.enum(["windows", "linux", "macos"]).default("windows"),
        profile: z.enum(["none", "low", "medium", "high"]).default("medium"),
        customTechniques: z.array(z.string()).optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const pipeline = buildPipeline(
        input.profile as EvasionProfile,
        {
          targetArch: input.targetArch,
          targetOS: input.targetOs,
          inputFormat: input.payloadType as any,
        }
      );

      // Save to DB
      const db = await getDbSafe();
      const [session] = await db.insert(evasionSessions).values({
        sessionType: "pipeline_config",
        evasionProfile: input.profile as EvasionProfile,
        pipelineData: pipeline,
        status: "completed",
        completedAt: new Date(),
        createdBy: ctx.user.id,
      });

      return {
        sessionId: Number(session.insertId),
        pipeline,
      };
    }),

  /** Get available techniques for a specific payload/OS/arch combination */
  getAvailableTechniques: protectedProcedure
    .input(
      z.object({
        payloadType: z.string(),
        targetOs: z.string().default("windows"),
        targetArch: z.string().default("x64"),
      })
    )
    .query(({ input }) => {
      // Return techniques filtered by category relevance
      return EVASION_TECHNIQUES.filter(
        (t) =>
          // All techniques are relevant; filter by tool availability for the target
          t.implementedBy.length > 0
      );
    }),

  // ═══════════════════════════════════════════════════════════════════
  // TIER 3 — EVASION SCORECARD
  // ═══════════════════════════════════════════════════════════════════

  /** Generate a full evasion scorecard */
  generateScorecard: protectedProcedure
    .input(
      z.object({
        campaignId: z.string().default("manual"),
        techniques: z.array(z.string()).min(1),
        /** Optional: run mutation tests inline */
        runMutationTests: z
          .array(
            z.object({
              command: z.string(),
              pattern: z.string(),
            })
          )
          .optional(),
        /** Optional: build pipeline inline */
        pipelineConfig: z
          .object({
            payloadType: z.enum([
              "exe",
              "dll",
              "shellcode",
              "powershell",
              "csharp",
              "hta",
              "vba",
            ]),
            targetArch: z.enum(["x64", "x86"]).default("x64"),
            targetOs: z.enum(["windows", "linux", "macos"]).default("windows"),
            profile: z.enum(["none", "low", "medium", "high"]).default("medium"),
          })
          .optional(),
        /** Known detected techniques */
        detectedTechniques: z.array(z.string()).optional(),
        /** Known evaded techniques */
        evadedTechniques: z.array(z.string()).optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Run inline mutation tests if provided
      const mutationResults: MutationTestResult[] = [];
      if (input.runMutationTests) {
        for (const test of input.runMutationTests) {
          mutationResults.push(
            testRawPatternMutations(test.command, test.pattern)
          );
        }
      }

      // Build pipeline if config provided
      const pipeline = input.pipelineConfig
        ? buildPipeline(
            input.pipelineConfig.profile as EvasionProfile,
            {
              targetArch: input.pipelineConfig.targetArch,
              targetOS: input.pipelineConfig.targetOs,
              inputFormat: input.pipelineConfig.payloadType as any,
            }
          )
        : undefined;

      // Generate the scorecard
      const scorecard = generateEvasionScorecard({
        campaignId: input.campaignId,
        campaignTechniques: input.techniques,
        mutationResults,
        commandMutationResults: [],
        pipeline,
        detectedTechniques: input.detectedTechniques,
        evadedTechniques: input.evadedTechniques,
      });

      // Save to DB
      const db = await getDbSafe();
      const [session] = await db.insert(evasionSessions).values({
        campaignId: input.campaignId,
        sessionType: "scorecard",
        techniques: input.techniques,
        evasionProfile: input.pipelineConfig?.profile as EvasionProfile || "none",
        stealthScore: scorecard.campaignStealthScore,
        stealthBand: scorecard.stealthBand,
        detectionCoverage: scorecard.detectionCoverage,
        evasionSuccessRate: scorecard.evasionSuccessRate,
        scorecardData: scorecard,
        mutationData: mutationResults.length > 0 ? mutationResults : null,
        pipelineData: pipeline || null,
        totalTechniques: scorecard.summary.totalTechniques,
        detectedCount: scorecard.summary.detected,
        evadedCount: scorecard.summary.evaded,
        partialCount: scorecard.summary.partial,
        untestedCount: scorecard.summary.untested,
        totalRules: scorecard.summary.totalRules,
        robustRules: scorecard.summary.robustRules,
        fragileRules: scorecard.summary.fragileRules,
        criticalGaps: scorecard.summary.criticalGaps,
        status: "completed",
        completedAt: new Date(),
        createdBy: ctx.user.id,
      });

      return {
        sessionId: Number(session.insertId),
        scorecard,
      };
    }),

  /** Generate a purple team cycle plan */
  generatePurpleCycle: protectedProcedure
    .input(
      z.object({
        techniques: z.array(z.string()).min(1),
        /** Optional: use an existing scorecard session for context */
        scorecardSessionId: z.number().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      let existingScorecard;

      if (input.scorecardSessionId) {
        const db = await getDbSafe();
        const [session] = await db
          .select()
          .from(evasionSessions)
          .where(eq(evasionSessions.id, input.scorecardSessionId))
          .limit(1);
        if (session?.scorecardData) {
          existingScorecard = session.scorecardData as any;
        }
      }

      const cycle = generatePurpleTeamCycle(
        input.techniques,
        existingScorecard
      );

      // Save to DB
      const db = await getDbSafe();
      const [session] = await db.insert(evasionSessions).values({
        sessionType: "purple_cycle",
        techniques: input.techniques,
        purpleCycleData: cycle,
        status: "completed",
        completedAt: new Date(),
        createdBy: ctx.user.id,
      });

      return {
        sessionId: Number(session.insertId),
        cycle,
      };
    }),

  // ═══════════════════════════════════════════════════════════════════
  // SESSION MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════

  /** List evasion sessions */
  listSessions: protectedProcedure
    .input(
      z.object({
        type: z
          .enum(["mutation_test", "pipeline_config", "scorecard", "purple_cycle"])
          .optional(),
        limit: z.number().min(1).max(100).default(20),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = input.type
        ? eq(evasionSessions.sessionType, input.type)
        : undefined;

      const sessions = await db
        .select({
          id: evasionSessions.id,
          campaignId: evasionSessions.campaignId,
          sessionType: evasionSessions.sessionType,
          evasionProfile: evasionSessions.evasionProfile,
          stealthScore: evasionSessions.stealthScore,
          stealthBand: evasionSessions.stealthBand,
          detectionCoverage: evasionSessions.detectionCoverage,
          evasionSuccessRate: evasionSessions.evasionSuccessRate,
          totalTechniques: evasionSessions.totalTechniques,
          detectedCount: evasionSessions.detectedCount,
          evadedCount: evasionSessions.evadedCount,
          totalRules: evasionSessions.totalRules,
          robustRules: evasionSessions.robustRules,
          fragileRules: evasionSessions.fragileRules,
          criticalGaps: evasionSessions.criticalGaps,
          status: evasionSessions.status,
          createdAt: evasionSessions.createdAt,
        })
        .from(evasionSessions)
        .where(conditions)
        .orderBy(desc(evasionSessions.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      const [countResult] = await db
        .select({ count: sql<number>`COUNT(*)` })
        .from(evasionSessions)
        .where(conditions);

      return {
        sessions,
        total: countResult?.count || 0,
      };
    }),

  /** Get a single session with full data */
  getSession: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db
        .select()
        .from(evasionSessions)
        .where(eq(evasionSessions.id, input.id))
        .limit(1);

      if (!session) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      }

      // Get associated rule results
      const rules = await db
        .select()
        .from(ruleRobustnessResults)
        .where(eq(ruleRobustnessResults.sessionId, input.id))
        .orderBy(ruleRobustnessResults.robustnessScore);

      return { session, rules };
    }),

  /** Get ATT&CK technique catalog for the UI */
  getAttackCatalog: protectedProcedure.query(() => {
    return ATTACK_TECHNIQUE_CATALOG;
  }),

  /** Get dashboard stats */
  getDashboardStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const [totalSessions] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(evasionSessions);

    const [scorecardSessions] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(evasionSessions)
      .where(eq(evasionSessions.sessionType, "scorecard"));

    const [avgStealth] = await db
      .select({ avg: sql<number>`AVG(stealth_score)` })
      .from(evasionSessions)
      .where(eq(evasionSessions.sessionType, "scorecard"));

    const [totalRules] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(ruleRobustnessResults);

    const [fragileRules] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(ruleRobustnessResults)
      .where(eq(ruleRobustnessResults.robustnessClass, "fragile"));

    const [bypassedRules] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(ruleRobustnessResults)
      .where(eq(ruleRobustnessResults.robustnessClass, "bypassed"));

    // Recent sessions
    const recentSessions = await db
      .select({
        id: evasionSessions.id,
        sessionType: evasionSessions.sessionType,
        stealthScore: evasionSessions.stealthScore,
        stealthBand: evasionSessions.stealthBand,
        totalTechniques: evasionSessions.totalTechniques,
        criticalGaps: evasionSessions.criticalGaps,
        createdAt: evasionSessions.createdAt,
      })
      .from(evasionSessions)
      .orderBy(desc(evasionSessions.createdAt))
      .limit(5);

    return {
      totalSessions: totalSessions?.count || 0,
      totalScorecards: scorecardSessions?.count || 0,
      avgStealthScore: Math.round(avgStealth?.avg || 0),
      totalRulesTested: totalRules?.count || 0,
      fragileRules: fragileRules?.count || 0,
      bypassedRules: bypassedRules?.count || 0,
      recentSessions,
    };
  }),

  // ═══════════════════════════════════════════════════════════════════
  // ADAPTIVE EVASION ORCHESTRATOR ENDPOINTS
  // ═══════════════════════════════════════════════════════════════════

  /** Probe a target for WAF/EDR defenses before running operations */
  probeDefenses: protectedProcedure
    .input(z.object({ targetUrl: z.string().url(), engagementId: z.number().optional() }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.targetUrl, "Evasion Engine", ctx);
      }
      const { probeDefenses } = await import("../lib/evasion-integrations");
      return probeDefenses(input.targetUrl);
    }),

  /** Run an evasion-aware scan against a target */
  evasionScan: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      scanType: z.enum(["spider_only", "active", "full"]).default("full"),
      scanMode: z.enum(["passive", "active"]).default("passive"),
      scanName: z.string().optional(),
      maxEvasionAttempts: z.number().min(1).max(20).default(10),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement ──
      {
        const { checkScopeForMutation } = await import("../lib/scope-enforcement-middleware");
        await checkScopeForMutation(input, ctx, "evasionEngine.evasionScan");
      }
      const { runEvasionAwareScan } = await import("../lib/evasion-integrations");
      return runEvasionAwareScan({
        targetUrl: input.targetUrl,
        scanType: input.scanType,
        scanMode: input.scanMode,
        scanName: input.scanName,
        userId: String(ctx.user.id),
        evasionEnabled: true,
        maxEvasionAttempts: input.maxEvasionAttempts,
      });
    }),

  /** Run an evasion-aware C2 task */
  evasionC2Task: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      sessionTarget: z.string(),
      taskType: z.string(),
      command: z.string().min(1),
      transport: z.string().optional(),
      maxEvasionAttempts: z.number().min(1).max(20).default(10),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareC2Task } = await import("../lib/evasion-integrations");
      // The actual C2 execution function — simulated here since Sliver
      // calls are proxied through the Caldera API
      const mockC2Execute = async (command: string, options: any) => {
        // In production, this would call the Sliver gRPC API
        // For now, simulate the C2 task execution with realistic behavior
        const taskId = `task-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        return {
          taskId,
          status: "executed",
          output: `Task ${taskId} executed: ${command.substring(0, 50)}`,
        };
      };
      return runEvasionAwareC2Task(
        {
          sessionId: input.sessionId,
          sessionTarget: input.sessionTarget,
          taskType: input.taskType,
          command: input.command,
          evasionEnabled: true,
          maxEvasionAttempts: input.maxEvasionAttempts,
          transport: input.transport,
        },
        mockC2Execute,
      );
    }),

  /** Run an evasion-aware exploit */
  evasionExploit: protectedProcedure
    .input(z.object({
      target: z.string(),
      exploitId: z.string(),
      exploitName: z.string(),
      payload: z.string(),
      maxEvasionAttempts: z.number().min(1).max(20).default(12),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareExploit } = await import("../lib/evasion-integrations");
      // The actual exploit execution function
      const mockExploitExecute = async (payload: string, options: any) => {
        // In production, this would call the exploit framework
        return {
          success: true,
          statusCode: 200,
          body: `Exploit delivered: ${input.exploitName}`,
        };
      };
      return runEvasionAwareExploit(
        {
          target: input.target,
          exploitId: input.exploitId,
          exploitName: input.exploitName,
          payload: input.payload,
          evasionEnabled: true,
          maxEvasionAttempts: input.maxEvasionAttempts,
        },
        mockExploitExecute,
      );
    }),

  /** Select optimal pipeline based on detected defenses */
  selectPipeline: protectedProcedure
    .input(z.object({
      defensesDetected: z.array(z.string()),
      targetOS: z.enum(["windows", "linux", "macos"]).default("windows"),
    }))
    .mutation(async ({ input }) => {
      const { selectPipelineForDefenses } = await import("../lib/evasion-integrations");
      return selectPipelineForDefenses(input.defensesDetected, input.targetOS);
    }),

  /** Generate optimized command mutations for detected defenses */
  optimizedMutations: protectedProcedure
    .input(z.object({
      command: z.string().min(1),
      defensesDetected: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      const { generateOptimizedMutations } = await import("../lib/evasion-integrations");
      return generateOptimizedMutations(input.command, input.defensesDetected);
    }),

  /** Get orchestrator findings and stats */
  orchestratorFindings: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]).optional(),
      result: z.enum(["bypassed", "blocked", "partial", "error"]).optional(),
      target: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
    }).optional())
    .query(async ({ input }) => {
      const { getFindings, getOrchestratorStats } = await import("../lib/evasion-orchestrator");
      return {
        findings: getFindings(input || {}),
        stats: getOrchestratorStats(),
      };
    }),

  /** Get a specific evasion finding by ID */
  orchestratorFinding: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const { getFindingById } = await import("../lib/evasion-orchestrator");
      const finding = getFindingById(input.id);
      if (!finding) throw new TRPCError({ code: "NOT_FOUND", message: "Finding not found" });
      return finding;
    }),

  /** Get the escalation ladder for a domain */
  escalationLadder: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]),
    }))
    .query(async ({ input }) => {
      const { getEscalationLadder } = await import("../lib/evasion-orchestrator");
      return getEscalationLadder(input.domain).map(t => ({
        id: t.id,
        name: t.name,
        category: t.category,
        level: t.level,
        description: t.description,
        mitreTechnique: t.mitreTechnique,
      }));
    }),

  // ═══════════════════════════════════════════════════════════════════
  // EVASION PLAYBOOK & DEFENSE HEATMAP
  // ═══════════════════════════════════════════════════════════════════

  /** Generate an Evasion Playbook report from stored findings */
  generatePlaybook: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]).optional(),
      target: z.string().optional(),
      onlySuccessful: z.boolean().optional(),
      title: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { generatePlaybook } = await import("../lib/evasion-playbook");
      return generatePlaybook(input || undefined);
    }),

  /** Export playbook as Markdown */
  exportPlaybookMarkdown: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]).optional(),
      target: z.string().optional(),
      onlySuccessful: z.boolean().optional(),
      title: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { generatePlaybook, exportPlaybookMarkdown } = await import("../lib/evasion-playbook");
      const playbook = generatePlaybook(input || undefined);
      return { markdown: exportPlaybookMarkdown(playbook), playbook };
    }),

  /** Export playbook as JSON */
  exportPlaybookJSON: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]).optional(),
      target: z.string().optional(),
      onlySuccessful: z.boolean().optional(),
      title: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { generatePlaybook, exportPlaybookJSON } = await import("../lib/evasion-playbook");
      const playbook = generatePlaybook(input || undefined);
      return { json: exportPlaybookJSON(playbook), playbook };
    }),

  /** Generate defense heatmap data */
  defenseHeatmap: protectedProcedure
    .input(z.object({
      domain: z.enum(["scanning", "c2", "exploit"]).optional(),
      minEncounters: z.number().min(1).optional(),
    }).optional())
    .query(async ({ input }) => {
      const { generateDefenseHeatmap } = await import("../lib/evasion-playbook");
      return generateDefenseHeatmap(input || undefined);
    }),

  // ═════════════════════════════════════════════════════════════════
  // EVASION-AWARE VALIDATION TESTING
  // ═════════════════════════════════════════════════════════════════

  /** Run probe scan with adaptive evasion bypass */
  evasionProbeScan: protectedProcedure
    .input(z.object({
      target: z.string().min(1),
      port: z.number().optional(),
      cveIds: z.array(z.string()).optional(),
      probeIds: z.array(z.string()).optional(),
      maxAttempts: z.number().min(1).max(10).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareProbeScan } = await import("../lib/evasion-validation");
      return runEvasionAwareProbeScan(input.target, {
        port: input.port,
        cveIds: input.cveIds,
        probeIds: input.probeIds,
        evasionConfig: { maxAttempts: input.maxAttempts },
      });
    }),

  /** Run verification suite with adaptive evasion bypass */
  evasionVerificationSuite: protectedProcedure
    .input(z.object({
      targetHost: z.string().min(1),
      targetPort: z.number().optional().default(443),
      protocol: z.enum(["http", "https"]).optional().default("https"),
      cveIds: z.array(z.string()).optional(),
      tags: z.array(z.string()).optional(),
      maxAttempts: z.number().min(1).max(10).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareVerificationSuite } = await import("../lib/evasion-validation");
      return runEvasionAwareVerificationSuite(
        input.targetHost,
        input.targetPort,
        input.protocol,
        { cveIds: input.cveIds, tags: input.tags },
        { maxAttempts: input.maxAttempts },
      );
    }),

  /** Run takeover PoC validation with adaptive evasion bypass */
  evasionTakeoverValidation: protectedProcedure
    .input(z.object({
      candidates: z.array(z.object({
        subdomain: z.string(),
        cnameTarget: z.string(),
        service: z.string(),
      })),
      maxAttempts: z.number().min(1).max(10).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareTakeoverValidation } = await import("../lib/evasion-validation");
      return runEvasionAwareTakeoverValidation(
        input.candidates,
        { maxAttempts: input.maxAttempts },
      );
    }),

  /** Validate KEV-matched exploits with adaptive evasion bypass */
  evasionExploitValidation: protectedProcedure
    .input(z.object({
      target: z.string().min(1),
      kevFindings: z.array(z.object({
        id: z.string(),
        cveIds: z.array(z.string()),
        title: z.string(),
        linkedExploits: z.array(z.object({
          cveId: z.string(),
          bestExploit: z.any(),
          isRemoteAccess: z.boolean(),
        })).optional(),
      })),
      maxAttempts: z.number().min(1).max(10).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runEvasionAwareExploitValidation } = await import("../lib/evasion-validation");
      return runEvasionAwareExploitValidation(
        input.target,
        input.kevFindings,
        { maxAttempts: input.maxAttempts },
      );
    }),

  /** Detect defenses on a target URL for validation planning */
  detectDefenses: protectedProcedure
    .input(z.object({ targetUrl: z.string().min(1) }))
    .mutation(async ({ input }) => {
      try {
        const response = await fetch(input.targetUrl, {
          signal: AbortSignal.timeout(10000),
          redirect: "follow",
        });
        const body = await response.text().catch(() => "");
        const headers: Record<string, string> = {};
        response.headers.forEach((v, k) => { headers[k] = v; });
        const { detectValidationBlock } = await import("../lib/evasion-validation");
        return {
          ...detectValidationBlock({ statusCode: response.status, body, headers }),
          statusCode: response.status,
          responseSize: body.length,
        };
      } catch (err: any) {
        const { detectValidationBlock } = await import("../lib/evasion-validation");
        return {
          ...detectValidationBlock({ error: err.message }),
          statusCode: 0,
          responseSize: 0,
        };
      }
    }),
});
