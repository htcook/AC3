/**
 * Engagement Auto-Resume — Server Startup Hook
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Detects interrupted engagements on server restart by checking the
 * engagement_ops_snapshots table for entries with is_running=1.
 * Emits WebSocket notifications and optionally auto-resumes.
 */

import { eventHub } from "./ws-event-hub";

interface InterruptedEngagement {
  engagementId: number;
  phase: string;
  progress: number;
  assetsCount: number;
  vulnsFound: number;
  portsFound: number;
  lastUpdated: string;
  canResume: boolean;
}

// In-memory cache of interrupted engagements detected at startup
let detectedInterruptions: InterruptedEngagement[] = [];

/**
 * Scan the database for interrupted engagements (is_running=1 snapshots)
 * and emit WebSocket notifications for each one.
 */
export async function detectInterruptedEngagements(): Promise<InterruptedEngagement[]> {
  try {
    const { getDbRequired } = await import("../db");
    const { engagementOpsSnapshots } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");
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
      // Mark as no longer running in DB (server restarted, so it's not actually running)
      await db
        .update(engagementOpsSnapshots)
        .set({ isRunning: false })
        .where(eq(engagementOpsSnapshots.engagementId, snap.engagementId));

      // Parse the snapshot to get stats
      let assetsCount = 0;
      let vulnsFound = 0;
      let portsFound = 0;
      let phase = "unknown";
      let progress = 0;

      try {
        const stateData = typeof snap.stateJson === "string"
          ? JSON.parse(snap.stateJson)
          : snap.stateJson;
        assetsCount = stateData?.assets?.length || 0;
        vulnsFound = stateData?.stats?.vulnsFound || 0;
        portsFound = stateData?.stats?.portsFound || 0;
        phase = stateData?.phase || "unknown";
        progress = stateData?.progress || 0;
      } catch {
        // Ignore parse errors
      }

      const PHASE_ORDER = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];
      const canResume = assetsCount > 0 && PHASE_ORDER.includes(phase);

      const entry: InterruptedEngagement = {
        engagementId: snap.engagementId,
        phase,
        progress,
        assetsCount,
        vulnsFound,
        portsFound,
        lastUpdated: snap.updatedAt || "unknown",
        canResume,
      };
      results.push(entry);

      // Emit WebSocket notification for this interrupted engagement
      eventHub.broadcastEngagement(snap.engagementId, {
        type: "engagement:interrupted",
        engagementId: snap.engagementId,
        phase,
        progress,
        assetsCount,
        vulnsFound,
        portsFound,
        canResume,
        message: `Engagement #${snap.engagementId} was interrupted during ${phase} (${progress}% complete). ${canResume ? "Resume available." : "Cannot auto-resume."}`,
      });

      console.log(
        `[AutoResume] Detected interrupted engagement #${snap.engagementId}: ` +
        `phase=${phase}, progress=${progress}%, assets=${assetsCount}, vulns=${vulnsFound}, ` +
        `canResume=${canResume}`
      );
    }

    detectedInterruptions = results;
    return results;
  } catch (err: any) {
    console.warn("[AutoResume] Failed to detect interrupted engagements:", err.message);
    return [];
  }
}

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
  detectedInterruptions = [];
}

/**
 * Auto-resume a specific interrupted engagement
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

    // Use the orchestrator's resume capability
    const { executeEngagement } = await import("./engagement-orchestrator");
    
    // Fire-and-forget the resume
    executeEngagement(engagementId, { resume: true }).catch((err: any) => {
      console.error(`[AutoResume] Resume failed for engagement #${engagementId}:`, err.message);
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:resume_failed",
        engagementId,
        error: err.message,
      });
    });

    // Remove from detected list
    detectedInterruptions = detectedInterruptions.filter(e => e.engagementId !== engagementId);

    return {
      success: true,
      message: `Engagement #${engagementId} resume initiated from ${interruption.phase}`,
    };
  } catch (err: any) {
    return { success: false, message: `Auto-resume failed: ${err.message}` };
  }
}

/**
 * Initialize the auto-resume detection hook.
 * Call this during server startup (after DB is ready).
 */
export async function initAutoResumeHook(): Promise<void> {
  console.log("[AutoResume] Scanning for interrupted engagements...");
  const interrupted = await detectInterruptedEngagements();
  if (interrupted.length > 0) {
    console.log(
      `[AutoResume] Found ${interrupted.length} interrupted engagement(s): ` +
      interrupted.map(e => `#${e.engagementId}(${e.phase})`).join(", ")
    );
  }
}
