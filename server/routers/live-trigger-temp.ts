/**
 * TEMPORARY: Public trigger for live engagement test.
 * This will be removed after the test is complete.
 *
 * Uses getOpsStateWithRecovery() for automatic DB snapshot fallback
 * when in-memory state is lost (e.g., after server restart).
 */
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";

const PHASE_ORDER = ['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit'] as const;
const PHASE_LABELS: Record<string, string> = {
  idle: 'Idle',
  recon: 'Phase 1: Recon & Domain Discovery',
  passive_discovery: 'Phase 2: Passive Discovery',
  scoping: 'Phase 3: Scoping & RoE Review',
  test_plan: 'Phase 4: Test Plan Generation',
  test_plan_approval: 'Phase 4b: Test Plan Approval',
  enumeration: 'Phase 5: Active Enumeration & Fingerprinting',
  vuln_detection: 'Phase 6: Vulnerability Detection',
  social_engineering: 'Phase 6b: Social Engineering',
  exploitation: 'Phase 7: Exploitation',
  post_exploit: 'Phase 8: Post-Exploitation',
  reporting: 'Phase 9: Reporting',
  completed: 'Completed',
  error: 'Error',
};

/** Infer the last active phase from the ops state log entries (for error recovery).
 * Prioritizes phase_complete/phaseCheckpoint markers to find the last COMPLETED phase,
 * then falls back to the last log entry with a valid phase tag.
 * Returns { lastCompleted, lastActive } where:
 *   - lastCompleted: the last phase that fully finished (has a completion marker)
 *   - lastActive: the phase that was running when the crash occurred
 */
function inferLastActivePhase(state: any): typeof PHASE_ORDER[number] | null {
  if (!state?.log?.length) return null;

  let lastCompleted: typeof PHASE_ORDER[number] | null = null;
  let lastActive: typeof PHASE_ORDER[number] | null = null;

  // First pass: find the highest completed phase (phase_complete or phaseCheckpoint markers)
  for (let i = state.log.length - 1; i >= 0; i--) {
    const entry = state.log[i];
    if (!lastCompleted && entry.type === 'phase_complete' && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      lastCompleted = entry.phase as typeof PHASE_ORDER[number];
    }
    // Also check for checkpoint titles that indicate phase completion
    if (!lastCompleted && entry.title && (entry.title.includes('complete') || entry.title.includes('checkpoint')) && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      lastCompleted = entry.phase as typeof PHASE_ORDER[number];
    }
  }

  // Second pass: find the last active phase (any valid phase in log)
  for (let i = state.log.length - 1; i >= 0; i--) {
    const entry = state.log[i];
    const phase = entry.phase;
    if (phase && phase !== 'error' && phase !== 'idle' && PHASE_ORDER.includes(phase as any)) {
      lastActive = phase as typeof PHASE_ORDER[number];
      break;
    }
  }

  // Return the lastActive phase (the one that was running when crash occurred)
  // The caller can use this to resume from the SAME phase
  return lastActive;
}

/** Get the last fully COMPLETED phase from state logs */
function inferLastCompletedPhase(state: any): typeof PHASE_ORDER[number] | null {
  if (!state?.log?.length) return null;
  for (let i = state.log.length - 1; i >= 0; i--) {
    const entry = state.log[i];
    if (entry.type === 'phase_complete' && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      return entry.phase as typeof PHASE_ORDER[number];
    }
    if (entry.title && (entry.title.includes('complete') || entry.title.includes('checkpoint')) && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      return entry.phase as typeof PHASE_ORDER[number];
    }
  }
  return null;
}

export const liveTriggerTempRouter = router({
  /** Trigger autonomous engagement execution with optional resume (TEMP - no auth) */
  triggerExecution: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      resume: z.boolean().optional().default(false),
      startPhase: z.enum(['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit']).optional(),
    }))
    .mutation(async ({ input }) => {
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) throw new Error('Engagement not found');

      if (!engagement.targetDomain && !engagement.targetIpRange) {
        throw new Error('No targets defined');
      }

      const { executeEngagement, initOpsState, getOpsStateWithRecovery, clearOpsState, persistOpsStateNow } = await import('../lib/engagement-orchestrator');
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

      // Determine resume capability — also allow resuming from 'error' state
      const canResume = !!(state && state.phase !== 'completed' && state.phase !== 'idle' && state.assets.length > 0);
      const willResume = input.resume && canResume;

      // Build execution options
      const execOptions: any = {};
      if (willResume) {
        execOptions.resume = true;
        // When resuming from error: resume from the SAME phase that crashed
        // (not the next one). The phase's internal progress tracking will skip
        // already-completed work (e.g., completedScans for nuclei/zap).
        if (state!.phase === 'error') {
          const lastActive = inferLastActivePhase(state);
          const lastCompleted = inferLastCompletedPhase(state);
          if (lastActive && lastActive !== lastCompleted) {
            execOptions.startPhase = lastActive; // Resume the crashed phase
          } else if (lastCompleted) {
            const completedIdx = PHASE_ORDER.indexOf(lastCompleted as any);
            execOptions.startPhase = completedIdx >= 0 && completedIdx < PHASE_ORDER.length - 1
              ? PHASE_ORDER[completedIdx + 1]
              : lastCompleted;
          } else {
            execOptions.startPhase = lastActive || 'recon';
          }
        } else if (state!.phase === 'scanning') {
          execOptions.startPhase = 'vuln_detection';
        } else if (PHASE_ORDER.includes(state!.phase as any)) {
          // Resume from the same phase (it was interrupted, not completed)
          execOptions.startPhase = state!.phase;
        } else {
          execOptions.startPhase = 'recon';
        }
      } else if (input.startPhase) {
        execOptions.startPhase = input.startPhase;
      }

      // ── Training Lab Detection ──
      // Auto-detect training lab targets and set trainingLabMode so the approval
      // gate auto-approves red-tier exploit plans instead of timing out and denying.
      const isTrainingLab = !!(engagement as any).labName ||
        engagement.engagementType === 'pentest' && (
          (engagement.targetDomain || '').includes('aceofcloud.io') ||
          (engagement.targetDomain || '').includes('aceofcloud.com')
        );

      if (isTrainingLab && !willResume) {
        // For fresh starts on lab targets, init state with trainingLabMode
        await clearOpsState(input.engagementId);
        state = initOpsState(input.engagementId, engagement.engagementType || 'pentest');
        state.trainingLabMode = true;
        await persistOpsStateNow(input.engagementId);
        console.log(`[LiveTrigger] Training lab detected for #${input.engagementId} — trainingLabMode=true`);
      } else if (isTrainingLab && willResume && state) {
        // For resumes, ensure trainingLabMode is set on existing state
        state.trainingLabMode = true;
        await persistOpsStateNow(input.engagementId);
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
  checkResumeCapability: protectedProcedure
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
      // Map non-standard phases (e.g. 'scanning', 'error') to the closest valid PHASE_ORDER entry
      // so the frontend can pass a valid startPhase to triggerExecution
      let resumePhase: string;
      if (state.phase === 'error') {
        // On error: resume from the SAME phase that crashed (not the next one)
        // This allows the phase's internal progress tracking (completedScans, etc.) to skip
        // already-finished work within that phase
        const lastActive = inferLastActivePhase(state);
        const lastCompleted = inferLastCompletedPhase(state);
        // If we know which phase was active when it crashed, resume from THAT phase
        // If we only know the last completed phase, resume from the NEXT one
        if (lastActive && lastActive !== lastCompleted) {
          resumePhase = lastActive; // Resume the crashed phase
        } else if (lastCompleted) {
          const completedIdx = PHASE_ORDER.indexOf(lastCompleted as any);
          resumePhase = completedIdx >= 0 && completedIdx < PHASE_ORDER.length - 1
            ? PHASE_ORDER[completedIdx + 1]
            : lastCompleted;
        } else {
          resumePhase = lastActive || 'recon';
        }
      } else if (state.phase === 'scanning') {
        resumePhase = 'vuln_detection';
      } else if (state.phase === 'idle' || state.phase === 'completed') {
        resumePhase = 'recon';
      } else {
        // State is in a valid running phase (e.g. paused mid-phase) — resume from same phase
        resumePhase = PHASE_ORDER.includes(state.phase as any) ? state.phase : 'recon';
      }

      return {
        canResume: true,
        reason: `Can resume from ${PHASE_LABELS[resumePhase] || resumePhase}`,
        hasSnapshot: true,
        currentPhase: state.phase,
        currentPhaseLabel: PHASE_LABELS[state.phase] || state.phase,
        nextPhase: resumePhase,
        nextPhaseLabel: PHASE_LABELS[resumePhase] || resumePhase,
        progress: state.progress,
        preservedAssets: state.assets.length,
        preservedVulns: state.stats.vulnsFound,
        preservedPorts: state.stats.portsFound,
        preservedExploits: state.stats.exploitsSucceeded,
        logCount: state.log.length,
        lastUpdated: state.completedAt || state.startedAt,
        stats: state.stats,
      };
    }),

  /** Approve a pending gate (TEMP - no auth) */
  approveGate: protectedProcedure
    .input(z.object({ gateId: z.string() }))
    .mutation(async ({ input }) => {
      const { resolveApproval } = await import('../lib/engagement-orchestrator');
      const resolved = resolveApproval(input.gateId, true, 'LiveTest-AutoApprove');
      return { resolved: !!resolved, gateId: input.gateId };
    }),

  /** List pending approval gates (TEMP - no auth) */
  listPendingGates: protectedProcedure
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
  getState: protectedProcedure
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
  startC2Poller: protectedProcedure
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
  stopC2Poller: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { stopPolling } = await import('../lib/caldera-c2-callback-poller');
      stopPolling(input.engagementId);
      return { stopped: true, engagementId: input.engagementId };
    }),

  /** Get C2 poller state for an engagement */
  getC2PollerState: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getPollerSnapshot } = await import('../lib/caldera-c2-callback-poller');
      return getPollerSnapshot(input.engagementId);
    }),

  /** List all active C2 pollers */
  listC2Pollers: protectedProcedure
    .query(async () => {
      const { listActivePollers } = await import('../lib/caldera-c2-callback-poller');
      return listActivePollers();
    }),

  /** Get summary of all active/recent engagement snapshots from DB */
  listSnapshots: protectedProcedure
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

  /** Get interrupted engagements detected at server startup */
  getInterruptedEngagements: protectedProcedure
    .query(async () => {
      const { getDetectedInterruptions } = await import('../lib/engagement-auto-resume');
      return getDetectedInterruptions();
    }),

  /** Dismiss/acknowledge interrupted engagement notifications */
  dismissInterruptions: protectedProcedure
    .mutation(async () => {
      const { clearDetectedInterruptions } = await import('../lib/engagement-auto-resume');
      clearDetectedInterruptions();
      return { success: true };
    }),

  /** Auto-resume a specific interrupted engagement */
  autoResumeEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { autoResumeEngagement } = await import('../lib/engagement-auto-resume');
      return autoResumeEngagement(input.engagementId);
    }),
});
