/**
 * Workflow Router — tRPC endpoints for guided workflow state persistence.
 * Allows users to start, resume, advance, and abandon multi-step workflows.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  WORKFLOW_DEFINITIONS,
  startWorkflow,
  getActiveWorkflows,
  getWorkflowSession,
  advanceWorkflowStep,
  updateStepData,
  abandonWorkflow,
  getWorkflowHistory,
} from "../lib/workflow-persistence";

export const workflowRouter = router({
  /** List all available workflow definitions */
  listDefinitions: protectedProcedure.query(() => {
    return WORKFLOW_DEFINITIONS.map(w => ({
      workflowId: w.workflowId,
      workflowName: w.workflowName,
      totalSteps: w.steps.length,
      steps: w.steps.map(s => ({ stepId: s.stepId, stepName: s.stepName, route: s.route })),
    }));
  }),

  /** Get active (in-progress) workflows for the current user */
  getActive: protectedProcedure.query(async ({ ctx }) => {
    return getActiveWorkflows(ctx.user.openId);
  }),

  /** Get workflow history for the current user */
  getHistory: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).optional() }).optional())
    .query(async ({ ctx, input }) => {
      return getWorkflowHistory(ctx.user.openId, input?.limit ?? 20);
    }),

  /** Get a specific workflow session with all step details */
  getSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .query(async ({ input }) => {
      return getWorkflowSession(input.sessionId);
    }),

  /** Start a new workflow */
  start: protectedProcedure
    .input(z.object({ workflowId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const sessionId = await startWorkflow(ctx.user.openId, input.workflowId);
      return getWorkflowSession(sessionId);
    }),

  /** Advance to the next step in a workflow */
  advanceStep: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      completedStepIndex: z.number(),
      outputData: z.record(z.string(), z.any()).optional(),
      linkedEntity: z.object({
        type: z.string(),
        id: z.string(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      return advanceWorkflowStep(
        input.sessionId,
        input.completedStepIndex,
        input.outputData,
        input.linkedEntity
      );
    }),

  /** Save data for a specific step */
  saveStepData: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      stepIndex: z.number(),
      inputData: z.record(z.string(), z.any()),
    }))
    .mutation(async ({ input }) => {
      await updateStepData(input.sessionId, input.stepIndex, input.inputData);
      return { success: true };
    }),

  /** Abandon a workflow */
  abandon: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      await abandonWorkflow(input.sessionId);
      return { success: true };
    }),
});
