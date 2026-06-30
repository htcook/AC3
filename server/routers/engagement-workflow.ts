import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  evaluateEngagementState,
  deterministicEvaluateState,
  createTimelineEvent,
  validatePhaseTransition,
  generatePhaseHandoff,
  initializeEngagementWorkflow,
  getPhaseDefinition,
  getAllPhaseDefinitions,
  calculateOverallProgress,
  KILL_CHAIN_PHASES,
  PHASE_DEFINITIONS,
} from "../lib/engagement-workflow-engine";

export const engagementWorkflowRouter = router({
  /** LLM-driven engagement state evaluation and next-action recommendation */
  evaluateState: protectedProcedure
    .input(z.object({
      currentPhase: z.string(),
      engagementData: z.record(z.any()),
      engagementType: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return evaluateEngagementState(input.currentPhase as any, input.engagementData, input.engagementType);
    }),

  /** Quick deterministic state evaluation (no LLM) */
  quickEvaluate: protectedProcedure
    .input(z.object({
      currentPhase: z.string(),
      engagementData: z.record(z.any()),
    }))
    .query(({ input }) => {
      return deterministicEvaluateState(input.currentPhase as any, input.engagementData);
    }),

  /** Validate a phase transition */
  validateTransition: protectedProcedure
    .input(z.object({
      fromPhase: z.string(),
      toPhase: z.string(),
    }))
    .query(({ input }) => validatePhaseTransition(input.fromPhase as any, input.toPhase as any)),

  /** LLM-driven phase handoff generation */
  generateHandoff: protectedProcedure
    .input(z.object({
      fromPhase: z.string(),
      toPhase: z.string(),
      engagementData: z.record(z.any()),
    }))
    .mutation(async ({ input }) => {
      return generatePhaseHandoff(input.fromPhase as any, input.toPhase as any, input.engagementData);
    }),

  /** Initialize a new engagement workflow */
  initialize: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      engagementType: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return initializeEngagementWorkflow(input.engagementId, input.engagementType);
    }),

  /** Create a timeline event */
  createEvent: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      phase: z.string(),
      action: z.string(),
      details: z.string(),
      operator: z.string().optional(),
    }))
    .mutation(({ input }) => {
      return createTimelineEvent(input.engagementId, input.phase as any, input.action, input.details, input.operator);
    }),

  /** Get all kill chain phase definitions */
  phases: protectedProcedure.query(() => getAllPhaseDefinitions()),

  /** Get a specific phase definition */
  phase: protectedProcedure
    .input(z.object({ phase: z.string() }))
    .query(({ input }) => getPhaseDefinition(input.phase as any)),

  /** Calculate overall engagement progress */
  progress: protectedProcedure
    .input(z.object({
      phaseProgress: z.record(z.number()),
    }))
    .query(({ input }) => calculateOverallProgress(input.phaseProgress as any)),

  /** Get full kill chain knowledge base */
  killChain: protectedProcedure.query(() => ({
    phases: KILL_CHAIN_PHASES,
    definitions: PHASE_DEFINITIONS,
    totalPhases: KILL_CHAIN_PHASES.length,
  })),
});
