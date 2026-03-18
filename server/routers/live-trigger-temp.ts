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

const PHASE_ORDER = ['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit'] as const;
const PHASE_LABELS: Record<string, string> = {
  idle: 'Idle',
  recon: 'Phase 1: Recon & Discovery',
  enumeration: 'Phase 2: Enumeration & Fingerprinting',
  vuln_detection: 'Phase 3: Vulnerability Detection',
  exploitation: 'Phase 4: Exploitation',
  post_exploit: 'Phase 5: Post-Exploit',
  completed: 'Completed',
  error: 'Error',
};

export const liveTriggerTempRouter = router({
  /** Trigger autonomous engagement execution with optional resume (TEMP - no auth) */
  triggerExecution: publicProcedure
    .input(z.object({
      engagementId: z.number(),
      resume: z.boolean().optional().default(false),
      startPhase: z.enum(['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit']).optional(),
    }))
    .mutation(async ({ input }) => {
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) throw new Error('Engagement not found');

      if (!engagement.targetDomain && !engagement.targetIpRange) {
        throw new Error('No targets defined');
      }

      const { executeEngagement, initOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = await getOpsStateWithRecovery(input.engagementId);

      // Check if already running
      if (state?.isRunning) {
        return {
          started: false,
          resumed: false,
          message: 'Already running',
          engagementId: input.engagementId,
          currentPhase: state.phase,
          currentPhaseLabel: PHASE_LABELS[state.phase] || state.phase,
          progress: state.progress,
        };
      }

      // Determine resume capability
      const canResume = !!(state && state.phase !== 'completed' && state.phase !== 'error' && state.phase !== 'idle' && state.assets.length > 0);
      const willResume = input.resume && canResume;

      // Build execution options
      const execOptions: any = {};
      if (willResume) {
        execOptions.resume = true;
        // Resume from the NEXT phase after the last completed one
        const lastPhaseIdx = PHASE_ORDER.indexOf(state!.phase as any);
        if (lastPhaseIdx >= 0 && lastPhaseIdx < PHASE_ORDER.length - 1) {
          execOptions.startPhase = PHASE_ORDER[lastPhaseIdx + 1];
        } else {
          execOptions.startPhase = state!.phase;
        }
      } else if (input.startPhase) {
        execOptions.startPhase = input.startPhase;
      }

      // Fire and forget
      executeEngagement(input.engagementId, { id: '0', name: 'LiveTest' }, execOptions)
        .catch((err: any) => {
          console.error('[LiveTrigger] executeEngagement crashed:', err.message);
        });

      return {
        started: true,
        resumed: willResume,
        message: willResume
          ? `Resumed from ${PHASE_LABELS[state!.phase] || state!.phase} → continuing at ${PHASE_LABELS[execOptions.startPhase] || execOptions.startPhase}`
          : 'Engagement started from scratch',
        engagementId: input.engagementId,
        resumedFromPhase: willResume ? state!.phase : undefined,
        startingPhase: execOptions.startPhase || 'recon',
        startingPhaseLabel: PHASE_LABELS[execOptions.startPhase || 'recon'],
        preservedAssets: willResume ? state!.assets.length : 0,
        preservedVulns: willResume ? state!.stats.vulnsFound : 0,
      };
    }),

  /** Check if an engagement can be resumed from a saved state */
  checkResumeCapability: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      const state = await getOpsStateWithRecovery(input.engagementId);

      if (!state) {
        return { canResume: false, reason: 'No saved state found', hasSnapshot: false };
      }

      if (state.isRunning) {
        return {
          canResume: false,
          reason: 'Engagement is currently running',
          hasSnapshot: true,
          currentPhase: state.phase,
          currentPhaseLabel: PHASE_LABELS[state.phase] || state.phase,
          progress: state.progress,
          isRunning: true,
        };
      }

      if (state.phase === 'completed') {
        return {
          canResume: false,
          reason: 'Engagement already completed',
          hasSnapshot: true,
          currentPhase: 'completed',
          currentPhaseLabel: 'Completed',
          progress: 100,
          stats: state.stats,
        };
      }

      if (state.phase === 'idle' || state.assets.length === 0) {
        return {
          canResume: false,
          reason: 'No meaningful progress to resume from',
          hasSnapshot: true,
          currentPhase: state.phase,
        };
      }

      // Can resume!
      const lastPhaseIdx = PHASE_ORDER.indexOf(state.phase as any);
      const nextPhase = lastPhaseIdx >= 0 && lastPhaseIdx < PHASE_ORDER.length - 1
        ? PHASE_ORDER[lastPhaseIdx + 1]
        : state.phase;

      return {
        canResume: true,
        reason: `Can resume from ${PHASE_LABELS[state.phase]} → ${PHASE_LABELS[nextPhase]}`,
        hasSnapshot: true,
        currentPhase: state.phase,
        currentPhaseLabel: PHASE_LABELS[state.phase] || state.phase,
        nextPhase,
        nextPhaseLabel: PHASE_LABELS[nextPhase] || nextPhase,
        progress: state.progress,
        preservedAssets: state.assets.length,
        preservedVulns: state.stats.vulnsFound,
        preservedPorts: state.stats.portsFound,
        preservedExploits: state.stats.exploitsSucceeded,
        logCount: state.logs.length,
        lastUpdated: state.completedAt || state.startedAt,
        stats: state.stats,
      };
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

  /** Start C2 callback polling for an engagement */
  startC2Poller: publicProcedure
    .input(z.object({
      engagementId: z.number(),
      operationId: z.string(),
      intervalMs: z.number().optional().default(10000),
    }))
    .mutation(async ({ input }) => {
      const { startPolling, getPollerSnapshot } = await import('../lib/caldera-c2-callback-poller');
      startPolling(input.engagementId, input.operationId, input.intervalMs);
      return { started: true, engagementId: input.engagementId, operationId: input.operationId };
    }),

  /** Stop C2 callback polling for an engagement */
  stopC2Poller: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { stopPolling } = await import('../lib/caldera-c2-callback-poller');
      stopPolling(input.engagementId);
      return { stopped: true, engagementId: input.engagementId };
    }),

  /** Get C2 poller state for an engagement */
  getC2PollerState: publicProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getPollerSnapshot } = await import('../lib/caldera-c2-callback-poller');
      return getPollerSnapshot(input.engagementId);
    }),

  /** List all active C2 pollers */
  listC2Pollers: publicProcedure
    .query(async () => {
      const { listActivePollers } = await import('../lib/caldera-c2-callback-poller');
      return listActivePollers();
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
