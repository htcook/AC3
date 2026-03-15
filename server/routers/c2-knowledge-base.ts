/**
 * C2 Knowledge Base Router
 *
 * tRPC endpoints for:
 * 1. Framework profiles and tactical intelligence
 * 2. C2 framework selection recommendations
 * 3. Threat actor TTP → C2 module mapping
 * 4. Adversary profile auto-generation
 * 5. Post-exploitation playbook generation
 * 6. Profile completeness scoring
 * 7. Caldera server deployment (push profiles)
 * 8. Post-exploitation auto-trigger on shell callback
 * 9. Threat intel auto-enrich pipeline
 *
 * Author: Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  pushProfileToCaldera,
  batchPushProfilesToCaldera,
  getDeploymentStatus,
  verifyDeployedProfile,
} from "../lib/caldera-profile-push";
import {
  triggerPostExploitPlaybook,
  getPostExploitPlaybookForEngagement,
} from "../lib/post-exploit-auto-trigger";
import {
  checkAndTriggerProfileGeneration,
  getAutoGenerationHistory,
  getAutoGenerationStats,
} from "../lib/threat-intel-auto-enrich";
import {
  executePipelineRun,
  getPipelineStatus,
  getPipelineRunHistory,
  getCurrentRun,
  updateSchedulerConfig,
  getSchedulerConfig,
} from "../lib/auto-generation-scheduler";
import {
  FRAMEWORK_PROFILES,
  selectC2Framework,
  mapActorTTPs,
  scoreProfileCompleteness,
  generateAdversaryProfile,
  generatePostExploitPlaybook,
  buildC2SystemPromptContext,
  type C2FrameworkType,
  type EngagementPhase,
  type C2FrameworkProfile,
} from "../lib/c2-tactical-knowledge";
import { getDb } from "../db";
import { threatActors } from "../../drizzle/schema";
import { sql, desc, isNotNull, and, ne } from "drizzle-orm";

const frameworkTypeSchema = z.enum([
  "caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka",
]);

const engagementPhaseSchema = z.enum([
  "reconnaissance", "initial_access", "execution", "persistence",
  "privilege_escalation", "defense_evasion", "credential_access",
  "discovery", "lateral_movement", "collection_exfiltration", "impact",
]);

export const c2KnowledgeBaseRouter = router({
  /**
   * Get all C2 framework profiles with tactical intelligence
   */
  getFrameworkProfiles: protectedProcedure.query(async () => {
    const profiles = Object.entries(FRAMEWORK_PROFILES).map(([key, profile]) => ({
      id: key,
      ...profile,
      totalTechniques: Object.keys(profile.techniqueModuleMap).length,
      totalPostExploitCapabilities: profile.postExploitCapabilities.length,
      totalEvasionCapabilities: profile.evasionCapabilities.length,
    }));
    return profiles;
  }),

  /**
   * Get a single framework profile
   */
  getFrameworkProfile: protectedProcedure
    .input(z.object({ framework: frameworkTypeSchema }))
    .query(async ({ input }) => {
      const profile = FRAMEWORK_PROFILES[input.framework];
      if (!profile) return null;
      return {
        ...profile,
        totalTechniques: Object.keys(profile.techniqueModuleMap).length,
        totalPostExploitCapabilities: profile.postExploitCapabilities.length,
      };
    }),

  /**
   * Get C2 framework recommendation for engagement context
   */
  getRecommendation: protectedProcedure
    .input(z.object({
      targetPlatform: z.enum(["windows", "linux", "macos", "mixed"]),
      engagementPhase: engagementPhaseSchema,
      targetDefenses: z.array(z.string()).default([]),
      stealthRequired: z.enum(["maximum", "high", "moderate", "low"]).default("high"),
      hasActiveDirectory: z.boolean().default(false),
      threatActorToEmulate: z.string().optional(),
      availableFrameworks: z.array(frameworkTypeSchema).default(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      currentShellPrivilege: z.enum(["user", "admin", "system"]).optional(),
    }))
    .query(async ({ input }) => {
      return selectC2Framework(input);
    }),

  /**
   * Map a threat actor's TTPs to C2 framework modules
   */
  mapActorToC2: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return mapActorTTPs(input.actorId);
    }),

  /**
   * Score profile completeness for adversary profile generation
   */
  scoreCompleteness: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return scoreProfileCompleteness(input.actorId);
    }),

  /**
   * Batch score completeness for multiple actors (for the dashboard)
   */
  batchScoreCompleteness: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(20),
      minAbilities: z.number().default(5),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      // Get actors with ability mappings
      const actors = await db.execute(
        sql`SELECT ta.actorId, ta.name, ta.calderaProfile,
                   COUNT(taa.id) as abilityCount
            FROM threat_actors ta
            JOIN threat_actor_abilities taa ON ta.actorId = taa.actorId
            GROUP BY ta.actorId, ta.name, ta.calderaProfile
            HAVING abilityCount >= ${input.minAbilities}
            ORDER BY abilityCount DESC
            LIMIT ${input.limit}`,
      );

      const rows = (actors[0] as any[]) || [];
      const results = [];

      for (const row of rows) {
        const score = await scoreProfileCompleteness(row.actorId);
        if (score) results.push(score);
      }

      return results;
    }),

  /**
   * Auto-generate a Caldera adversary profile from actor abilities
   */
  generateProfile: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .mutation(async ({ input }) => {
      // First check completeness
      const score = await scoreProfileCompleteness(input.actorId);
      if (!score) {
        return { success: false, error: "Actor not found", profile: null };
      }
      if (!score.readyForAutoGeneration) {
        return {
          success: false,
          error: `Profile not ready for auto-generation. Score: ${score.score}/100. Need 15+ TTPs (have ${score.totalTTPs}), 10+ abilities (have ${score.totalAbilities}), 3+ tactics (have ${score.tacticsRepresented}).`,
          profile: null,
          score,
        };
      }

      const profile = await generateAdversaryProfile(input.actorId);
      if (!profile) {
        return { success: false, error: "Failed to generate profile", profile: null };
      }

      return { success: true, profile, score };
    }),

  /**
   * Batch auto-generate profiles for all eligible actors
   */
  batchGenerateProfiles: protectedProcedure
    .input(z.object({
      minScore: z.number().default(60),
      dryRun: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) return { generated: 0, skipped: 0, errors: 0, results: [] };

      // Get actors with abilities but no profile
      const actors = await db.execute(
        sql`SELECT ta.actorId, ta.name, ta.calderaProfile,
                   COUNT(taa.id) as abilityCount
            FROM threat_actors ta
            JOIN threat_actor_abilities taa ON ta.actorId = taa.actorId
            WHERE ta.calderaProfile IS NULL OR ta.calderaProfile = 'null'
            GROUP BY ta.actorId, ta.name, ta.calderaProfile
            HAVING abilityCount >= 10
            ORDER BY abilityCount DESC`,
      );

      const rows = (actors[0] as any[]) || [];
      const results: Array<{
        actorId: string;
        actorName: string;
        action: "generated" | "skipped" | "error";
        score: number;
        reason?: string;
      }> = [];

      let generated = 0, skipped = 0, errors = 0;

      for (const row of rows) {
        const score = await scoreProfileCompleteness(row.actorId);
        if (!score || score.score < input.minScore) {
          skipped++;
          results.push({
            actorId: row.actorId,
            actorName: row.name,
            action: "skipped",
            score: score?.score ?? 0,
            reason: `Score ${score?.score ?? 0} below threshold ${input.minScore}`,
          });
          continue;
        }

        if (input.dryRun) {
          results.push({
            actorId: row.actorId,
            actorName: row.name,
            action: "generated",
            score: score.score,
            reason: "Would generate (dry run)",
          });
          generated++;
          continue;
        }

        try {
          const profile = await generateAdversaryProfile(row.actorId);
          if (profile) {
            generated++;
            results.push({
              actorId: row.actorId,
              actorName: row.name,
              action: "generated",
              score: score.score,
            });
          } else {
            errors++;
            results.push({
              actorId: row.actorId,
              actorName: row.name,
              action: "error",
              score: score.score,
              reason: "Generation returned null",
            });
          }
        } catch (err) {
          errors++;
          results.push({
            actorId: row.actorId,
            actorName: row.name,
            action: "error",
            score: score.score,
            reason: String(err),
          });
        }
      }

      return { generated, skipped, errors, results };
    }),

  /**
   * Generate post-exploitation playbook for a shell/agent callback
   */
  generatePlaybook: protectedProcedure
    .input(z.object({
      shellPrivilege: z.enum(["user", "admin", "system", "root"]),
      targetPlatform: z.enum(["windows", "linux", "macos"]),
      objectives: z.array(z.string()).default(["Full compromise assessment"]),
      availableFrameworks: z.array(frameworkTypeSchema).default(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      hasActiveDirectory: z.boolean().default(false),
      targetDefenses: z.array(z.string()).default([]),
      threatActorToEmulate: z.string().optional(),
    }))
    .query(async ({ input }) => {
      return generatePostExploitPlaybook(input);
    }),

  /**
   * Build LLM system prompt context for C2 operations
   */
  buildLLMContext: protectedProcedure
    .input(z.object({
      engagementPhase: engagementPhaseSchema,
      targetPlatform: z.string().default("windows"),
      availableFrameworks: z.array(frameworkTypeSchema).default(["caldera", "metasploit", "sliver", "empire"]),
      threatActorToEmulate: z.string().optional(),
    }))
    .query(async ({ input }) => {
      return buildC2SystemPromptContext({
        activeAgents: [],
        engagementPhase: input.engagementPhase,
        targetPlatform: input.targetPlatform,
        availableFrameworks: input.availableFrameworks,
        threatActorToEmulate: input.threatActorToEmulate,
      });
    }),

  /**
   * Get framework comparison matrix
   */
  getComparisonMatrix: protectedProcedure.query(async () => {
    const matrix = Object.entries(FRAMEWORK_PROFILES).map(([key, profile]) => ({
      framework: key as C2FrameworkType,
      displayName: profile.displayName,
      platforms: profile.platforms,
      protocols: profile.protocols.length,
      evasionCapabilities: profile.evasionCapabilities.length,
      detectionDifficulty: profile.opsecProfile.detectionDifficulty,
      networkNoise: profile.opsecProfile.networkNoise,
      diskArtifacts: profile.opsecProfile.diskArtifacts,
      postExploitModules: profile.postExploitCapabilities.length,
      techniquesCovered: Object.keys(profile.techniqueModuleMap).length,
      bestPhases: profile.bestPhases,
      primaryUseCases: profile.primaryUseCases,
    }));
    return matrix;
  }),

  /**
   * Get actors with highest profile completeness scores
   */
  getTopActors: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(50).default(10),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      const actors = await db.execute(
        sql`SELECT ta.actorId, ta.name, ta.aliases, ta.country, ta.motivations,
                   ta.calderaProfile,
                   COUNT(taa.id) as abilityCount
            FROM threat_actors ta
            JOIN threat_actor_abilities taa ON ta.actorId = taa.actorId
            GROUP BY ta.actorId, ta.name, ta.aliases, ta.country, ta.motivations, ta.calderaProfile
            ORDER BY abilityCount DESC
            LIMIT ${input.limit}`,
      );

      return ((actors[0] as any[]) || []).map((row: any) => ({
        actorId: row.actorId,
        name: row.name,
        aliases: row.aliases,
        country: row.country,
        motivations: row.motivations,
        abilityCount: Number(row.abilityCount),
        hasCalderaProfile: !!row.calderaProfile && row.calderaProfile !== "null",
      }));
    }),

  // ─── Caldera Server Deployment ──────────────────────────────────────────

  /**
   * Push a generated adversary profile to the live Caldera C2 server
   */
  pushToCaldera: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .mutation(async ({ input }) => {
      return pushProfileToCaldera(input.actorId);
    }),

  /**
   * Batch push all eligible profiles to Caldera
   */
  batchPushToCaldera: protectedProcedure
    .input(z.object({
      minScore: z.number().default(60),
      maxBatch: z.number().default(50),
      dryRun: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      return batchPushProfilesToCaldera(input);
    }),

  /**
   * Get deployment status for all actors with profiles
   */
  getDeploymentStatus: protectedProcedure.query(async () => {
    return getDeploymentStatus();
  }),

  /**
   * Verify a deployed profile still exists on the Caldera server
   */
  verifyDeployment: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return verifyDeployedProfile(input.actorId);
    }),

  // ─── Post-Exploitation Auto-Trigger ────────────────────────────────────

  /**
   * Trigger post-exploitation playbook generation for a shell callback
   */
  triggerPostExploit: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targetHost: z.string(),
      targetPort: z.number().optional(),
      shellPrivilege: z.enum(["user", "admin", "system", "root"]),
      targetPlatform: z.enum(["windows", "linux", "macos"]),
      shellSessionId: z.string().optional(),
      shellType: z.string().optional(),
      hasActiveDirectory: z.boolean().default(false),
      objectives: z.array(z.string()).default(["Full compromise assessment"]),
      threatActorToEmulate: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return triggerPostExploitPlaybook(input);
    }),

  /**
   * Get the post-exploitation playbook for an engagement
   */
  getEngagementPlaybook: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getPostExploitPlaybookForEngagement(input.engagementId);
    }),

  // ─── Threat Intel Auto-Enrich Pipeline ─────────────────────────────────

  /**
   * Manually trigger profile generation check for an actor
   */
  checkAutoGeneration: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .mutation(async ({ input }) => {
      return checkAndTriggerProfileGeneration(input.actorId);
    }),

  /**
   * Get auto-generation history
   */
  getAutoGenerationHistory: protectedProcedure
    .input(z.object({ limit: z.number().default(20) }))
    .query(async ({ input }) => {
      return getAutoGenerationHistory(input.limit);
    }),

  /**
   * Get auto-generation pipeline stats
   */
  getAutoGenerationStats: protectedProcedure.query(async () => {
    return getAutoGenerationStats();
  }),

  /**
   * Get summary stats for the knowledge base dashboard
   */
  getSummaryStats: protectedProcedure.query(async () => {
    const db = await getDb();

    let totalActors = 0;
    let actorsWithAbilities = 0;
    let totalAbilityMappings = 0;
    let actorsWithProfiles = 0;

    if (db) {
      const [actorCount] = await db.execute(sql`SELECT COUNT(*) as cnt FROM threat_actors`);
      totalActors = (actorCount as any)[0]?.cnt ?? 0;

      const [withAbilities] = await db.execute(
        sql`SELECT COUNT(DISTINCT actorId) as cnt FROM threat_actor_abilities`,
      );
      actorsWithAbilities = (withAbilities as any)[0]?.cnt ?? 0;

      const [abilityCount] = await db.execute(
        sql`SELECT COUNT(*) as cnt FROM threat_actor_abilities`,
      );
      totalAbilityMappings = (abilityCount as any)[0]?.cnt ?? 0;

      const [profileCount] = await db.execute(
        sql`SELECT COUNT(*) as cnt FROM threat_actors WHERE calderaProfile IS NOT NULL AND calderaProfile != 'null'`,
      );
      actorsWithProfiles = (profileCount as any)[0]?.cnt ?? 0;
    }

    return {
      totalFrameworks: Object.keys(FRAMEWORK_PROFILES).length,
      totalTechniques: Object.values(FRAMEWORK_PROFILES).reduce(
        (sum, p) => sum + Object.keys(p.techniqueModuleMap).length, 0,
      ),
      totalPostExploitCapabilities: Object.values(FRAMEWORK_PROFILES).reduce(
        (sum, p) => sum + p.postExploitCapabilities.length, 0,
      ),
      totalEvasionCapabilities: Object.values(FRAMEWORK_PROFILES).reduce(
        (sum, p) => sum + p.evasionCapabilities.length, 0,
      ),
      totalActors,
      actorsWithAbilities,
      totalAbilityMappings,
      actorsWithProfiles,
    };
  }),

  // ── Pipeline Scheduler Endpoints ──────────────────────────────────────

  /**
   * Get pipeline scheduler status and stats
   */
  getPipelineStatus: protectedProcedure.query(async () => {
    return getPipelineStatus();
  }),

  /**
   * Get pipeline run history
   */
  getPipelineHistory: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(50).default(20) }).optional())
    .query(async ({ input }) => {
      return getPipelineRunHistory(input?.limit ?? 20);
    }),

  /**
   * Get current pipeline run (if any)
   */
  getCurrentPipelineRun: protectedProcedure.query(async () => {
    return getCurrentRun();
  }),

  /**
   * Manually trigger a pipeline run
   */
  triggerPipelineRun: protectedProcedure.mutation(async () => {
    const result = await executePipelineRun("manual");
    return result;
  }),

  /**
   * Update scheduler configuration
   */
  updateSchedulerConfig: protectedProcedure
    .input(z.object({
      enabled: z.boolean().optional(),
      cronExpression: z.string().optional(),
      timezone: z.string().optional(),
      notifyOnComplete: z.boolean().optional(),
      autoPushToCaldera: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      return updateSchedulerConfig(input);
    }),

  /**
   * Get scheduler configuration
   */
  getSchedulerConfig: protectedProcedure.query(async () => {
    return getSchedulerConfig();
  }),
});
