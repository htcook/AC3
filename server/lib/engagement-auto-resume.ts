/**
 * Engagement Auto-Resume — Server Startup Hook
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Detects interrupted engagements on server restart by checking the
 * engagement_ops_snapshots table for entries with is_running=1.
 * Emits WebSocket notifications and auto-resumes engagements that have
 * the autoResumeOnRestart flag enabled (with crash-loop protection).
 *
 * Crash-Loop Guard:
 *   - Tracks interrupt_count and last_interrupted_at per engagement snapshot.
 *   - If an engagement has been interrupted >= MAX_INTERRUPTS_BEFORE_BLOCK (3)
 *     times within CRASH_LOOP_WINDOW_MS (24 hours), auto-resume is blocked.
 *   - The operator is notified and must manually resume or reset the counter.
 */

import { eventHub } from "./ws-event-hub";
import { SERVER_INSTANCE_ID } from "./server-instance";

// ─── Configuration ──────────────────────────────────────────────────────────

/** Maximum interrupts within the crash-loop window before blocking auto-resume */
const MAX_INTERRUPTS_BEFORE_BLOCK = 10; // Raised from 3: deployment restarts are expected, not crash loops

/** Time window for crash-loop detection (24 hours in ms) */
const CRASH_LOOP_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Delay after server startup before auto-resuming (30 seconds — fast recovery) */
const AUTO_RESUME_DELAY_MS = 30 * 1000;

/** Grace period after auto-resume is scheduled, during which operator can cancel (30 seconds) */
const CANCEL_GRACE_PERIOD_MS = 30 * 1000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface InterruptedEngagement {
  engagementId: number;
  phase: string;
  progress: number;
  assetsCount: number;
  vulnsFound: number;
  portsFound: number;
  lastUpdated: string;
  canResume: boolean;
  autoResumeEnabled: boolean;
  crashLoopBlocked: boolean;
  interruptCount: number;
  scheduledResumeAt?: number;
}

// ─── State ──────────────────────────────────────────────────────────────────

// In-memory cache of interrupted engagements detected at startup
let detectedInterruptions: InterruptedEngagement[] = [];

// Timers for scheduled auto-resumes (can be cancelled by operator)
const scheduledResumeTimers = new Map<number, NodeJS.Timeout>();

// ─── Core Detection ─────────────────────────────────────────────────────────

/**
 * Scan the database for interrupted engagements (is_running=1 snapshots)
 * and emit WebSocket notifications for each one.
 * Also increments interrupt_count and checks crash-loop guard.
 */
export async function detectInterruptedEngagements(): Promise<InterruptedEngagement[]> {
  try {
    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots, engagements } = await import("../../drizzle/schema");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();

    // Find all snapshots where is_running = 1 (interrupted by server restart)
    const interrupted = await db
      .select()
      .from(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.isRunning, true));

    if (interrupted.length === 0) {
      console.log("[AutoResume] No interrupted engagements found at startup");
      return [];
    }

    const results: InterruptedEngagement[] = [];

    for (const snap of interrupted) {
      const engId = snap.engagementId;

      // Check if this engagement was owned by a DIFFERENT server (hostname).
      // We compare only the hostname prefix (not pid/timestamp/random) to allow
      // the SAME server to resume after a restart (where pid/timestamp change).
      // If the snapshot is older than ORPHAN_CLAIM_TIMEOUT_MS, any server can claim it
      // (handles engagements started from dev server that need to resume on production).
      const ORPHAN_CLAIM_TIMEOUT_MS = parseInt(process.env.ORPHAN_CLAIM_TIMEOUT_MS || '300000', 10); // 5 min default
      const snapshotOwner = snap.serverInstanceId as string | null;
      if (snapshotOwner) {
        const ownerHostname = snapshotOwner.split("-").slice(0, -3).join("-") || snapshotOwner;
        const ourHostname = SERVER_INSTANCE_ID.split("-").slice(0, -3).join("-") || SERVER_INSTANCE_ID;
        if (ownerHostname !== ourHostname) {
          // Check if the snapshot is old enough to be considered orphaned
          const snapshotAge = snap.updatedAt
            ? Date.now() - new Date(snap.updatedAt).getTime()
            : Infinity;
          if (snapshotAge < ORPHAN_CLAIM_TIMEOUT_MS) {
            console.log(
              `[AutoResume] Engagement #${engId} is owned by a different server "${ownerHostname}" ` +
              `(we are "${ourHostname}"). Snapshot is ${Math.round(snapshotAge/1000)}s old (< ${ORPHAN_CLAIM_TIMEOUT_MS/1000}s threshold). ` +
              `Skipping — not a real interrupt on this server.`
            );
            continue;
          }
          console.log(
            `[AutoResume] Engagement #${engId} was owned by "${ownerHostname}" but snapshot is ` +
            `${Math.round(snapshotAge/1000)}s old (> ${ORPHAN_CLAIM_TIMEOUT_MS/1000}s threshold). ` +
            `Claiming orphaned engagement for this server ("${ourHostname}").`
          );
        } else {
          console.log(
            `[AutoResume] Engagement #${engId} was owned by same hostname "${ownerHostname}" ` +
            `(old instance: "${snapshotOwner}", new instance: "${SERVER_INSTANCE_ID}"). ` +
            `This is a server restart — proceeding with auto-resume.`
          );
        }
      }

      // Increment interrupt_count and set last_interrupted_at
      const currentInterruptCount = (snap.interruptCount || 0) + 1;
      const now = new Date();

      await db
        .update(engagementOpsSnapshots)
        .set({
          isRunning: false,
          interruptCount: currentInterruptCount,
          lastInterruptedAt: now.toISOString().slice(0, 19).replace('T', ' '),
        })
        .where(eq(engagementOpsSnapshots.engagementId, engId));

      // Parse the snapshot to get stats
      let assetsCount = 0;
      let vulnsFound = 0;
      let portsFound = 0;
      let phase = "unknown";
      let progress = 0;

      try {
        const stateData = typeof snap.stateJson === "string"
          ? JSON.parse(snap.stateJson as string)
          : snap.stateJson;
        assetsCount = stateData?.assets?.length || 0;
        vulnsFound = stateData?.stats?.vulnsFound || 0;
        portsFound = stateData?.stats?.portsFound || 0;
        phase = stateData?.phase || "unknown";
        progress = stateData?.progress || 0;
      } catch {
        // Ignore parse errors
      }

      // Include both old orchestrator phases AND new rerunFullPipeline phases
      const RESUMABLE_PHASES = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit", "scanning", "recon_complete"];
      const canResume = assetsCount > 0 && RESUMABLE_PHASES.includes(phase);

      // Check if auto-resume is enabled for this engagement
      let autoResumeEnabled = false;
      try {
        const engRows = await db
          .select({ autoResumeOnRestart: engagements.autoResumeOnRestart })
          .from(engagements)
          .where(eq(engagements.id, engId))
          .limit(1);
        autoResumeEnabled = engRows.length > 0 && engRows[0].autoResumeOnRestart === 1;
      } catch {
        // If we can't read the engagement, don't auto-resume
      }

      // Crash-loop guard: check if too many interrupts in the window
      let crashLoopBlocked = false;
      if (currentInterruptCount >= MAX_INTERRUPTS_BEFORE_BLOCK) {
        const lastInterruptedAt = snap.lastInterruptedAt
          ? new Date(snap.lastInterruptedAt).getTime()
          : 0;
        const windowStart = Date.now() - CRASH_LOOP_WINDOW_MS;
        // If the previous interrupt was within the crash-loop window, block
        if (lastInterruptedAt > windowStart) {
          crashLoopBlocked = true;
          console.warn(
            `[AutoResume] CRASH-LOOP GUARD: Engagement #${engId} has been interrupted ` +
            `${currentInterruptCount} times. Auto-resume blocked. Manual intervention required.`
          );
        } else {
          // Outside the window — reset the counter
          await db
            .update(engagementOpsSnapshots)
            .set({ interruptCount: 1 })
            .where(eq(engagementOpsSnapshots.engagementId, engId));
          console.log(
            `[AutoResume] Engagement #${engId} interrupt count reset (previous interrupts outside 24h window)`
          );
        }
      }

      const entry: InterruptedEngagement = {
        engagementId: engId,
        phase,
        progress,
        assetsCount,
        vulnsFound,
        portsFound,
        lastUpdated: snap.updatedAt || "unknown",
        canResume,
        autoResumeEnabled,
        crashLoopBlocked,
        interruptCount: currentInterruptCount,
      };
      results.push(entry);

      // Emit WebSocket notification for this interrupted engagement
      const resumeStatus = crashLoopBlocked
        ? "Auto-resume BLOCKED (crash-loop guard). Manual resume required."
        : autoResumeEnabled
          ? `Auto-resume scheduled in ${AUTO_RESUME_DELAY_MS / 1000}s.`
          : "Auto-resume not enabled. Use Resume button or enable auto-resume in engagement settings.";

      eventHub.broadcastEngagement(engId, {
        type: "engagement:interrupted",
        engagementId: engId,
        phase,
        progress,
        assetsCount,
        vulnsFound,
        portsFound,
        canResume,
        autoResumeEnabled,
        crashLoopBlocked,
        interruptCount: currentInterruptCount,
        message: `Engagement #${engId} was interrupted during ${phase} (${progress}% complete). ${resumeStatus}`,
      });

      console.log(
        `[AutoResume] Detected interrupted engagement #${engId}: ` +
        `phase=${phase}, progress=${progress}%, assets=${assetsCount}, vulns=${vulnsFound}, ` +
        `canResume=${canResume}, autoResume=${autoResumeEnabled}, crashLoop=${crashLoopBlocked}, ` +
        `interrupts=${currentInterruptCount}`
      );
    }

    detectedInterruptions = results;
    return results;
  } catch (err: any) {
    console.warn("[AutoResume] Failed to detect interrupted engagements:", err.message);
    return [];
  }
}

// ─── Auto-Resume Scheduling ─────────────────────────────────────────────────

/**
 * Schedule auto-resume for all eligible interrupted engagements.
 * Called after detection, with a configurable delay to allow operator cancellation.
 */
export function scheduleAutoResumes(): void {
  for (const entry of detectedInterruptions) {
    if (!entry.canResume || !entry.autoResumeEnabled || entry.crashLoopBlocked) {
      continue;
    }

    const resumeAt = Date.now() + AUTO_RESUME_DELAY_MS;
    entry.scheduledResumeAt = resumeAt;

    console.log(
      `[AutoResume] Scheduling auto-resume for engagement #${entry.engagementId} ` +
      `in ${AUTO_RESUME_DELAY_MS / 1000}s (at ${new Date(resumeAt).toISOString()}). ` +
      `Cancel within ${CANCEL_GRACE_PERIOD_MS / 1000}s via cancelAutoResume().`
    );

    // Emit a "resume scheduled" notification so the UI can show a countdown
    eventHub.broadcastEngagement(entry.engagementId, {
      type: "engagement:auto_resume_scheduled",
      engagementId: entry.engagementId,
      resumeAt,
      cancelDeadline: Date.now() + CANCEL_GRACE_PERIOD_MS,
      phase: entry.phase,
      message: `Auto-resume scheduled for engagement #${entry.engagementId} from ${entry.phase} phase. Resuming in ${AUTO_RESUME_DELAY_MS / 1000}s.`,
    });

    const timer = setTimeout(async () => {
      scheduledResumeTimers.delete(entry.engagementId);
      await executeAutoResume(entry.engagementId);
    }, AUTO_RESUME_DELAY_MS);

    scheduledResumeTimers.set(entry.engagementId, timer);
  }
}

/**
 * Execute the actual auto-resume for a single engagement.
 */
async function executeAutoResume(engagementId: number): Promise<void> {
  try {
    const interruption = detectedInterruptions.find(e => e.engagementId === engagementId);
    if (!interruption) {
      console.warn(`[AutoResume] No interrupted state found for engagement #${engagementId}, skipping`);
      return;
    }

    // ── Claim Lock: only proceed if we can atomically claim ownership ──
    const { claimEngagement } = await import("./engagement-claim-lock");
    const claim = await claimEngagement(engagementId);
    if (!claim.claimed) {
      console.log(
        `[AutoResume] Engagement #${engagementId}: claim denied — ${claim.reason}. ` +
        `Another server instance is handling it. Skipping auto-resume.`
      );
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:auto_resume_skipped",
        engagementId,
        reason: claim.reason,
        currentOwner: claim.currentOwner,
        message: `Auto-resume skipped for #${engagementId}: another server (${claim.currentOwner}) owns it.`,
      });
      // Remove from detected list since another server is handling it
      detectedInterruptions = detectedInterruptions.filter(e => e.engagementId !== engagementId);
      return;
    }

    // ── Memory Pressure Guard: skip auto-resume if RSS is above 75% of container limit ──
    const memUsage = process.memoryUsage();
    const rssGB = memUsage.rss / (1024 * 1024 * 1024);
    const CONTAINER_LIMIT_GB = parseFloat(process.env.CONTAINER_MEMORY_LIMIT_GB || '8');
    const MAX_RSS_RATIO = 0.75;
    if (rssGB > CONTAINER_LIMIT_GB * MAX_RSS_RATIO) {
      console.warn(
        `[AutoResume] MEMORY GUARD: RSS=${rssGB.toFixed(2)}GB exceeds ${(MAX_RSS_RATIO * 100)}% of ` +
        `${CONTAINER_LIMIT_GB}GB container limit. Skipping auto-resume for engagement #${engagementId} ` +
        `to prevent OOM. Manual resume required after memory stabilizes.`
      );
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:auto_resume_skipped",
        engagementId,
        reason: `Memory pressure too high (RSS=${rssGB.toFixed(1)}GB/${CONTAINER_LIMIT_GB}GB)`,
        message: `Auto-resume skipped for #${engagementId}: memory pressure too high. Resume manually.`,
      });
      return;
    }

    console.log(`[AutoResume] Executing auto-resume for engagement #${engagementId} from ${interruption.phase} (RSS=${rssGB.toFixed(2)}GB)...`);

    // ── Dismiss stale approval gates from the interrupted run ──
    // After server restart, in-memory resolvers are lost. Any pending approval gates
    // are now orphaned and can never resolve. Dismiss them before resuming.
    try {
      const { dismissAllStaleApprovals } = await import("./engagement-orchestrator");
      const staleCount = dismissAllStaleApprovals(engagementId, `auto-resume:server-restart`);
      if (staleCount > 0) {
        console.log(`[AutoResume] Dismissed ${staleCount} stale approval gate(s) for engagement #${engagementId}`);
      }
    } catch (gateErr: any) {
      console.warn(`[AutoResume] Failed to dismiss stale gates for #${engagementId}:`, gateErr.message);
    }

    // Notify owner before resuming
    try {
      const { notifyOwner } = await import("../_core/notification");
      await notifyOwner({
        title: `🔄 Auto-Resuming Engagement #${engagementId}`,
        content: [
          `Engagement #${engagementId} was interrupted by a server restart and is now being auto-resumed.`,
          ``,
          `Phase: ${interruption.phase} (${interruption.progress}% complete)`,
          `Assets: ${interruption.assetsCount} | Vulns: ${interruption.vulnsFound} | Ports: ${interruption.portsFound}`,
          `Interrupt count: ${interruption.interruptCount}`,
          ``,
          `If this engagement should not be resumed, stop it from the Engagement Ops page.`,
        ].join("\n"),
      });
    } catch (notifErr: any) {
      console.warn(`[AutoResume] Notification failed for #${engagementId}:`, notifErr.message);
    }

    // ── Resume via rerunFullPipeline (same code path as the UI) ──
    // Load the state to get the stored pipelinePhases config
    const { getOpsStateWithRecovery, initOpsState, addLog: addOpsLog, broadcastOpsUpdate, persistOpsStateNow } = await import("./engagement-orchestrator");
    let state = await getOpsStateWithRecovery(engagementId);
    
    // Add a recovery log entry to the state so the operator sees what happened
    // IMPORTANT: Use the interruption.phase (original phase from snapshot) instead of state.phase
    // which may have been set to 'error' by the recovery process. Using 'error' as the log phase
    // would poison the resumeEngagement phase computation which searches backwards through logs.
    if (state) {
      const recoveryLogPhase = interruption.phase || state.phase || 'recon';
      addOpsLog(state, {
        phase: recoveryLogPhase as any,
        type: 'warning',
        title: '\u26a0\ufe0f Scan Interrupted \u2014 State Recovered',
        detail: `The server restarted while the scan was running. ${state.assets?.length || 0} assets have been recovered from the last snapshot (was in ${recoveryLogPhase} phase). You can reset and re-run the scan.`,
      });
      await persistOpsStateNow(engagementId, state);
    }
    
    // Determine which phases to run based on stored config and current progress
    const storedPhases = (state as any)?.pipelinePhases || { passive: true, active: true, llmAnalysis: true, exploitGeneration: true };
    const currentPhase = interruption.phase;
    
    // Skip phases that have already completed based on current phase
    // Phase order: recon -> enumeration -> vuln_detection -> exploitation -> completed
    const phaseOrder = ['recon', 'enumeration', 'scanning', 'vuln_detection', 'exploitation', 'post_exploit', 'completed'];
    const currentIdx = phaseOrder.indexOf(currentPhase);
    const phaseComplete = {
      passive: currentIdx > phaseOrder.indexOf('recon'),
      active: currentIdx > phaseOrder.indexOf('vuln_detection'),
      llmAnalysis: currentIdx > phaseOrder.indexOf('vuln_detection'),
      exploitGeneration: currentIdx >= phaseOrder.indexOf('completed'),
    };
    
    const resumePhases = {
      passive: storedPhases.passive && !phaseComplete.passive,
      active: storedPhases.active && !phaseComplete.active,
      llmAnalysis: storedPhases.llmAnalysis && !phaseComplete.llmAnalysis,
      exploitGeneration: storedPhases.exploitGeneration && !phaseComplete.exploitGeneration,
    };
    
    console.log(`[AutoResume] Engagement #${engagementId}: currentPhase=${currentPhase}, resumePhases=${JSON.stringify(resumePhases)}`);
    
    // Call rerunFullPipeline via internal HTTP (uses the same code path as the UI)
    // We need to get the owner's JWT to authenticate the internal call
    try {
      const { sign } = await import("jsonwebtoken");
      const jwtSecret = process.env.JWT_SECRET;
      const ownerOpenId = process.env.OWNER_OPEN_ID;
      const ownerName = process.env.OWNER_NAME || "Auto-Resume System";
      
      if (!jwtSecret || !ownerOpenId) {
        throw new Error("Missing JWT_SECRET or OWNER_OPEN_ID for internal auth");
      }
      
      // Create a short-lived internal JWT for the owner
      const internalToken = sign(
        { sub: ownerOpenId, name: ownerName, iat: Math.floor(Date.now() / 1000) },
        jwtSecret,
        { expiresIn: "5m" }
      );
      
      const port = process.env.PORT || 3000;
      const response = await fetch(`http://localhost:${port}/api/trpc/engagementOps.rerunFullPipeline`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Cookie": `token=${internalToken}`,
        },
        body: JSON.stringify({
          json: {
            engagementId,
            phases: resumePhases,
            resetState: false,
            exhaustiveExploit: (state as any)?.exhaustiveExploit ?? true,
          },
        }),
      });
      
      const responseData = await response.json().catch(() => null);
      
      if (response.ok && responseData?.result?.data?.json?.started) {
        console.log(`[AutoResume] Successfully resumed engagement #${engagementId} via rerunFullPipeline`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resumed",
          engagementId,
          resumePhase: currentPhase,
          message: `Engagement #${engagementId} auto-resumed from ${currentPhase} via full pipeline.`,
        });
      } else {
        const errorMsg = responseData?.error?.json?.message || responseData?.error?.message || `HTTP ${response.status}`;
        console.error(`[AutoResume] rerunFullPipeline failed for #${engagementId}: ${errorMsg}`);
        
        // Fallback to the old resumeEngagement path
        console.log(`[AutoResume] Falling back to orchestrator resumeEngagement for #${engagementId}...`);
        const { resumeEngagement } = await import("./engagement-orchestrator");
        const result = await resumeEngagement(engagementId, {
          id: "system-auto-resume",
          name: "Auto-Resume System",
        });
        
        if (result.success) {
          console.log(`[AutoResume] Fallback resume succeeded for #${engagementId}: ${result.message}`);
          eventHub.broadcastEngagement(engagementId, {
            type: "engagement:auto_resumed",
            engagementId,
            resumePhase: result.resumePhase,
            message: `Engagement #${engagementId} auto-resumed (fallback) from ${result.resumePhase}.`,
          });
        } else {
          console.error(`[AutoResume] Fallback resume also failed for #${engagementId}: ${result.message}`);
          eventHub.broadcastEngagement(engagementId, {
            type: "engagement:auto_resume_failed",
            engagementId,
            error: `Primary: ${errorMsg}. Fallback: ${result.message}`,
          });
        }
      }
    } catch (httpErr: any) {
      console.error(`[AutoResume] Internal HTTP call failed for #${engagementId}: ${httpErr.message}`);
      
      // Fallback to the old resumeEngagement path
      console.log(`[AutoResume] Falling back to orchestrator resumeEngagement for #${engagementId}...`);
      const { resumeEngagement } = await import("./engagement-orchestrator");
      const result = await resumeEngagement(engagementId, {
        id: "system-auto-resume",
        name: "Auto-Resume System",
      });
      
      if (result.success) {
        console.log(`[AutoResume] Fallback resume succeeded for #${engagementId}: ${result.message}`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resumed",
          engagementId,
          resumePhase: result.resumePhase,
          message: `Engagement #${engagementId} auto-resumed (fallback) from ${result.resumePhase}.`,
        });
      } else {
        console.error(`[AutoResume] All resume attempts failed for #${engagementId}: ${result.message}`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resume_failed",
          engagementId,
          error: result.message,
        });
      }
    }

    // Remove from detected list
    detectedInterruptions = detectedInterruptions.filter(e => e.engagementId !== engagementId);
  } catch (err: any) {
    console.error(`[AutoResume] Auto-resume failed for engagement #${engagementId}:`, err.message);
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:auto_resume_failed",
      engagementId,
      error: err.message,
    });
  }
}

// ─── Cancellation ───────────────────────────────────────────────────────────

/**
 * Cancel a scheduled auto-resume for a specific engagement.
 * Returns true if a scheduled resume was found and cancelled.
 */
export function cancelAutoResume(engagementId: number): boolean {
  const timer = scheduledResumeTimers.get(engagementId);
  if (timer) {
    clearTimeout(timer);
    scheduledResumeTimers.delete(engagementId);

    // Update the entry
    const entry = detectedInterruptions.find(e => e.engagementId === engagementId);
    if (entry) {
      entry.scheduledResumeAt = undefined;
    }

    console.log(`[AutoResume] Cancelled scheduled auto-resume for engagement #${engagementId}`);
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:auto_resume_cancelled",
      engagementId,
      message: `Auto-resume cancelled for engagement #${engagementId}. Use Resume button to manually resume.`,
    });
    return true;
  }
  return false;
}

/**
 * Cancel ALL scheduled auto-resumes (e.g., on operator request).
 */
export function cancelAllAutoResumes(): number {
  let cancelled = 0;
  for (const [engId, timer] of scheduledResumeTimers.entries()) {
    clearTimeout(timer);
    scheduledResumeTimers.delete(engId);
    cancelled++;
  }
  if (cancelled > 0) {
    console.log(`[AutoResume] Cancelled ${cancelled} scheduled auto-resume(s)`);
  }
  return cancelled;
}

// ─── Crash-Loop Guard Management ────────────────────────────────────────────

/**
 * Reset the interrupt counter for an engagement (after operator acknowledges crash-loop).
 * This unblocks auto-resume for the next restart.
 */
export async function resetInterruptCounter(engagementId: number): Promise<boolean> {
  try {
    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");
    const db = await getDbRequired();

    await db
      .update(engagementOpsSnapshots)
      .set({ interruptCount: 0, lastInterruptedAt: null })
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));

    // Also update in-memory state
    const entry = detectedInterruptions.find(e => e.engagementId === engagementId);
    if (entry) {
      entry.interruptCount = 0;
      entry.crashLoopBlocked = false;
    }

    console.log(`[AutoResume] Reset interrupt counter for engagement #${engagementId}`);
    return true;
  } catch (err: any) {
    console.error(`[AutoResume] Failed to reset interrupt counter for #${engagementId}:`, err.message);
    return false;
  }
}

// ─── Accessors ──────────────────────────────────────────────────────────────

/**
 * Get the list of interrupted engagements detected at last startup
 */
export function getDetectedInterruptions(): InterruptedEngagement[] {
  return detectedInterruptions;
}

/**
 * Clear the detected interruptions (after user acknowledges)
 */
export function clearDetectedInterruptions(): void {
  cancelAllAutoResumes();
  detectedInterruptions = [];
}

/**
 * Manual auto-resume trigger for a specific engagement (called from API)
 */
export async function autoResumeEngagement(engagementId: number): Promise<{
  success: boolean;
  message: string;
}> {
  try {
    const interruption = detectedInterruptions.find(e => e.engagementId === engagementId);
    if (!interruption) {
      return { success: false, message: "No interrupted state found for this engagement" };
    }
    if (!interruption.canResume) {
      return { success: false, message: "This engagement cannot be auto-resumed (insufficient progress)" };
    }

    await executeAutoResume(engagementId);
    return {
      success: true,
      message: `Engagement #${engagementId} resume initiated from ${interruption.phase}`,
    };
  } catch (err: any) {
    return { success: false, message: `Auto-resume failed: ${err.message}` };
  }
}

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the auto-resume detection hook.
 * Call this during server startup (after DB is ready).
 *
 * Flow:
 *   1. Detect interrupted engagements from DB
 *   2. Increment interrupt counters and check crash-loop guard
 *   3. Notify owner of all interrupted engagements
 *   4. Schedule auto-resume for eligible engagements (with delay for cancellation)
 */
export async function initAutoResumeHook(): Promise<void> {
  console.log("[AutoResume] Scanning for interrupted engagements...");
  const interrupted = await detectInterruptedEngagements();

  if (interrupted.length > 0) {
    console.log(
      `[AutoResume] Found ${interrupted.length} interrupted engagement(s): ` +
      interrupted.map(e =>
        `#${e.engagementId}(${e.phase}, autoResume=${e.autoResumeEnabled}, crashLoop=${e.crashLoopBlocked})`
      ).join(", ")
    );

    // Notify owner about all interrupted engagements
    try {
      const { notifyOwner } = await import("../_core/notification");
      const autoResumeCount = interrupted.filter(e => e.autoResumeEnabled && !e.crashLoopBlocked && e.canResume).length;
      const blockedCount = interrupted.filter(e => e.crashLoopBlocked).length;

      const engList = interrupted
        .map(e => {
          let status = "Manual resume required";
          if (e.crashLoopBlocked) status = "⛔ CRASH-LOOP BLOCKED";
          else if (e.autoResumeEnabled && e.canResume) status = `🔄 Auto-resuming in ${AUTO_RESUME_DELAY_MS / 1000}s`;
          return `  • #${e.engagementId}: ${e.phase} (${e.progress}%), ${e.assetsCount} assets, ${e.vulnsFound} vulns — ${status}`;
        })
        .join("\n");

      await notifyOwner({
        title: `⚠️ ${interrupted.length} Interrupted Engagement${interrupted.length > 1 ? "s" : ""} Detected`,
        content: [
          `The server restarted and ${interrupted.length} engagement${interrupted.length > 1 ? "s were" : " was"} interrupted.`,
          ``,
          engList,
          ``,
          autoResumeCount > 0
            ? `${autoResumeCount} engagement${autoResumeCount > 1 ? "s" : ""} will auto-resume in ${AUTO_RESUME_DELAY_MS / 1000} seconds.`
            : "No engagements have auto-resume enabled.",
          blockedCount > 0
            ? `⛔ ${blockedCount} engagement${blockedCount > 1 ? "s are" : " is"} blocked by the crash-loop guard (${MAX_INTERRUPTS_BEFORE_BLOCK}+ interrupts in 24h). Reset the counter from Engagement Ops to re-enable.`
            : "",
        ].filter(Boolean).join("\n"),
      });
    } catch (notifErr: any) {
      console.warn("[AutoResume] Owner notification failed:", notifErr.message);
    }

    // Schedule auto-resumes for eligible engagements
    scheduleAutoResumes();
  }
}

// ─── Exports for configuration (used by tests) ─────────────────────────────

export const AUTO_RESUME_CONFIG = {
  MAX_INTERRUPTS_BEFORE_BLOCK,
  CRASH_LOOP_WINDOW_MS,
  AUTO_RESUME_DELAY_MS,
  CANCEL_GRACE_PERIOD_MS,
} as const;
