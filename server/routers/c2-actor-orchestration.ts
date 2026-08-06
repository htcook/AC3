/**
 * C2 Actor Orchestration Router
 * 
 * tRPC endpoints for actor-driven C2 orchestration planning,
 * phishing template selection, and emulation narrative generation.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";

export const c2ActorOrchestrationRouter = router({
  /**
   * Build an actor-driven orchestration profile
   */
  buildProfile: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      targetRegion: z.string().optional(),
      technologies: z.array(z.string()).optional(),
      platform: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { buildActorOrchestrationProfile } = await import("../lib/c2-actor-orchestration");
      return buildActorOrchestrationProfile(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
        targetRegion: input.targetRegion,
        technologies: input.technologies,
        platform: input.platform,
      });
    }),

  /**
   * Generate framework overrides from an actor profile
   */
  getFrameworkOverrides: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      technologies: z.array(z.string()).optional(),
      platform: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { buildActorOrchestrationProfile, generateFrameworkOverrides } = await import("../lib/c2-actor-orchestration");
      const profile = await buildActorOrchestrationProfile(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
        technologies: input.technologies,
        platform: input.platform,
      });
      return {
        overrides: generateFrameworkOverrides(profile),
        frameworkPreferences: profile.frameworkPreferences,
        actorType: profile.actorType,
      };
    }),

  /**
   * Generate an emulation narrative for reporting
   */
  generateNarrative: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      technologies: z.array(z.string()).optional(),
      platform: z.string().optional(),
      steps: z.array(z.object({
        label: z.string(),
        techniqueId: z.string().optional(),
        phase: z.string(),
        framework: z.string(),
      })).optional(),
    }))
    .mutation(async ({ input }) => {
      const { buildActorOrchestrationProfile, generateEmulationNarrative } = await import("../lib/c2-actor-orchestration");
      const profile = await buildActorOrchestrationProfile(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
        technologies: input.technologies,
        platform: input.platform,
      });
      const narrative = generateEmulationNarrative(profile, input.steps || []);
      return {
        narrative,
        profile: {
          actorName: profile.actorName,
          actorType: profile.actorType,
          timingProfile: profile.timingProfile,
          opsecProfile: profile.opsecProfile,
          predictedPaths: profile.predictedPaths.slice(0, 3),
          techniqueChainCount: profile.techniqueChaining.length,
        },
      };
    }),

  /**
   * Get actor-specific phishing template recommendations
   */
  getPhishingRecommendations: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      technologies: z.array(z.string()).optional(),
      usesSSO: z.boolean().optional(),
      usesMfa: z.boolean().optional(),
      idpProvider: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { getActorPhishingRecommendations } = await import("../lib/c2-actor-orchestration");
      return getActorPhishingRecommendations(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
        technologies: input.technologies,
        usesSSO: input.usesSSO,
        usesMfa: input.usesMfa,
        idpProvider: input.idpProvider,
      });
    }),

  /**
   * Get all known actor phishing patterns
   */
  getKnownPhishingPatterns: protectedProcedure.query(async () => {
    const { getKnownActorPhishingPatterns } = await import("../lib/c2-actor-orchestration");
    return getKnownActorPhishingPatterns();
  }),

  /**
   * Calculate actor-aware delays between orchestration steps
   */
  calculateDelays: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      steps: z.array(z.object({
        techniqueId: z.string().optional(),
        phase: z.string(),
      })),
    }))
    .mutation(async ({ input }) => {
      const { buildActorOrchestrationProfile, calculateActorDelays } = await import("../lib/c2-actor-orchestration");
      const profile = await buildActorOrchestrationProfile(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
      });
      const delays = calculateActorDelays(input.steps, profile);
      return {
        delays,
        timingProfile: profile.timingProfile,
        totalEstimatedMs: delays.reduce((sum, d) => sum + d, 0),
      };
    }),

  /**
   * Reorder orchestration steps to match actor behavioral sequences
   */
  reorderSteps: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetSector: z.string().optional(),
      steps: z.array(z.object({
        id: z.string(),
        techniqueId: z.string().optional(),
        order: z.number(),
        phase: z.string(),
      })),
    }))
    .mutation(async ({ input }) => {
      const { buildActorOrchestrationProfile, reorderStepsForActor } = await import("../lib/c2-actor-orchestration");
      const profile = await buildActorOrchestrationProfile(input.actorName, {
        targetDomain: input.targetDomain,
        targetSector: input.targetSector,
      });
      const reordered = reorderStepsForActor(input.steps, profile);
      return {
        steps: reordered,
        techniqueChainCount: profile.techniqueChaining.length,
        actorType: profile.actorType,
      };
    }),
});
