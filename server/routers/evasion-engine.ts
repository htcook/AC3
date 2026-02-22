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
});
