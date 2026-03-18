/**
 * TEMPORARY: Public trigger for live engagement test.
 * This will be removed after the test is complete.
 */
import { publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";

export const liveTriggerTempRouter = router({
  /** Trigger autonomous engagement execution (TEMP - no auth) */
  triggerExecution: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) throw new Error('Engagement not found');

      if (!engagement.targetDomain && !engagement.targetIpRange) {
        throw new Error('No targets defined');
      }

      const { executeEngagement, initOpsState, getOpsState } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) {
        state = initOpsState(input.engagementId, engagement.engagementType);
      }
      if (state.isRunning) {
        return { started: false, message: 'Already running', engagementId: input.engagementId };
      }

      // Fire and forget
      executeEngagement(input.engagementId, { id: '0', name: 'LiveTest' })
        .catch((err: any) => {
          console.error('[LiveTrigger] executeEngagement crashed:', err.message);
        });

      return { started: true, engagementId: input.engagementId };
    }),

  /** Approve a pending gate (TEMP - no auth) */
  approveGate: publicProcedure
    .input(z.object({ gateId: z.string() }))
    .mutation(async ({ input }) => {
      const { resolveApproval } = await import('../lib/engagement-orchestrator');
      const resolved = resolveApproval(input.gateId, true, 'LiveTest-AutoApprove');
      return { resolved: !!resolved, gateId: input.gateId };
    }),

  /** List pending approval gates (TEMP - no auth) */
  listPendingGates: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState } = await import('../lib/engagement-orchestrator');
      const state = getOpsState(input.engagementId);
      if (!state) return [];
      return (state.approvalGates || []).filter((g: any) => g.status === 'pending').map((g: any) => ({
        id: g.id, title: g.title, phase: g.phase, riskTier: g.riskTier, description: g.description
      }));
    }),

  /** Get current ops state (TEMP - no auth) */
  getState: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, normalizeOpsState } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (state) state = normalizeOpsState(state);
      if (state && state.skippedDomains instanceof Set) {
        return { ...state, skippedDomains: [...state.skippedDomains] };
      }
      return state;
    }),
});
