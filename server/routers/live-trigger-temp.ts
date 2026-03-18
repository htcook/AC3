/**
 * TEMPORARY: Public trigger for live engagement test.
 * This will be removed after the test is complete.
 *
 * Uses getOpsStateWithRecovery() for automatic DB snapshot fallback
 * when in-memory state is lost (e.g., after server restart).
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

      const { executeEngagement, initOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = await getOpsStateWithRecovery(input.engagementId);
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
      const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      const state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return [];
      return (state.approvalGates || []).filter((g: any) => g.status === 'pending').map((g: any) => ({
        id: g.id, title: g.title, phase: g.phase, riskTier: g.riskTier, description: g.description
      }));
    }),

  /** Get current ops state with automatic DB recovery (TEMP - no auth) */
  getState: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      const state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return null;
      // Serialize Set to array for JSON transport
      if (state.skippedDomains instanceof Set) {
        return { ...state, skippedDomains: [...state.skippedDomains] };
      }
      return state;
    }),

  /** Get summary of all active/recent engagement snapshots from DB */
  listSnapshots: publicProcedure
    .query(async () => {
      const { getDb } = await import('../db');
      const { engagementOpsSnapshots } = await import('../../drizzle/schema');
      const { desc } = await import('drizzle-orm');
      const dbConn = await getDb();
      const rows = await dbConn.select({
        id: engagementOpsSnapshots.id,
        engagementId: engagementOpsSnapshots.engagementId,
        phase: engagementOpsSnapshots.phase,
        isRunning: engagementOpsSnapshots.isRunning,
        assetCount: engagementOpsSnapshots.assetCount,
        updatedAt: engagementOpsSnapshots.updatedAt,
      })
        .from(engagementOpsSnapshots)
        .orderBy(desc(engagementOpsSnapshots.updatedAt))
        .limit(20);
      return rows;
    }),
});
