import {
  eventHub,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  SERVER_INSTANCE_ID,
  init_server_instance
} from "./chunk-KUPDIQVG.js";
import "./chunk-KFQGP6VL.js";

// server/lib/engagement-auto-resume.ts
init_ws_event_hub();
init_server_instance();
var MAX_INTERRUPTS_BEFORE_BLOCK = 5;
var CRASH_LOOP_WINDOW_MS = 24 * 60 * 60 * 1e3;
var AUTO_RESUME_DELAY_MS = 30 * 1e3;
var CANCEL_GRACE_PERIOD_MS = 30 * 1e3;
var detectedInterruptions = [];
var scheduledResumeTimers = /* @__PURE__ */ new Map();
async function detectInterruptedEngagements() {
  try {
    const { getDbRequired } = await import("./db-MOHZQFM5.js");
    const { engagementOpsSnapshots, engagements } = await import("./schema-XOTPZHKC.js");
    const { eq, sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    const interrupted = await db.select().from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.isRunning, true));
    if (interrupted.length === 0) {
      console.log("[AutoResume] No interrupted engagements found at startup");
      return [];
    }
    const results = [];
    for (const snap of interrupted) {
      const engId = snap.engagementId;
      const ORPHAN_CLAIM_TIMEOUT_MS = parseInt(process.env.ORPHAN_CLAIM_TIMEOUT_MS || "300000", 10);
      const snapshotOwner = snap.serverInstanceId;
      if (snapshotOwner) {
        const ownerHostname = snapshotOwner.split("-").slice(0, -3).join("-") || snapshotOwner;
        const ourHostname = SERVER_INSTANCE_ID.split("-").slice(0, -3).join("-") || SERVER_INSTANCE_ID;
        if (ownerHostname !== ourHostname) {
          const snapshotAge = snap.updatedAt ? Date.now() - new Date(snap.updatedAt).getTime() : Infinity;
          if (snapshotAge < ORPHAN_CLAIM_TIMEOUT_MS) {
            console.log(
              `[AutoResume] Engagement #${engId} is owned by a different server "${ownerHostname}" (we are "${ourHostname}"). Snapshot is ${Math.round(snapshotAge / 1e3)}s old (< ${ORPHAN_CLAIM_TIMEOUT_MS / 1e3}s threshold). Skipping \u2014 not a real interrupt on this server.`
            );
            continue;
          }
          console.log(
            `[AutoResume] Engagement #${engId} was owned by "${ownerHostname}" but snapshot is ${Math.round(snapshotAge / 1e3)}s old (> ${ORPHAN_CLAIM_TIMEOUT_MS / 1e3}s threshold). Claiming orphaned engagement for this server ("${ourHostname}").`
          );
        } else {
          console.log(
            `[AutoResume] Engagement #${engId} was owned by same hostname "${ownerHostname}" (old instance: "${snapshotOwner}", new instance: "${SERVER_INSTANCE_ID}"). This is a server restart \u2014 proceeding with auto-resume.`
          );
        }
      }
      const currentInterruptCount = (snap.interruptCount || 0) + 1;
      const now = /* @__PURE__ */ new Date();
      await db.update(engagementOpsSnapshots).set({
        isRunning: false,
        interruptCount: currentInterruptCount,
        lastInterruptedAt: now.toISOString().slice(0, 19).replace("T", " ")
      }).where(eq(engagementOpsSnapshots.engagementId, engId));
      let assetsCount = 0;
      let vulnsFound = 0;
      let portsFound = 0;
      let phase = "unknown";
      let progress = 0;
      try {
        const stateData = typeof snap.stateJson === "string" ? JSON.parse(snap.stateJson) : snap.stateJson;
        assetsCount = stateData?.assets?.length || 0;
        vulnsFound = stateData?.stats?.vulnsFound || 0;
        portsFound = stateData?.stats?.portsFound || 0;
        phase = stateData?.phase || "unknown";
        progress = stateData?.progress || 0;
      } catch {
      }
      const RESUMABLE_PHASES = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit", "scanning", "recon_complete"];
      const canResume = assetsCount > 0 && RESUMABLE_PHASES.includes(phase);
      let autoResumeEnabled = false;
      try {
        const engRows = await db.select({ autoResumeOnRestart: engagements.autoResumeOnRestart }).from(engagements).where(eq(engagements.id, engId)).limit(1);
        autoResumeEnabled = engRows.length > 0 && engRows[0].autoResumeOnRestart === 1;
      } catch {
      }
      let crashLoopBlocked = false;
      if (currentInterruptCount >= MAX_INTERRUPTS_BEFORE_BLOCK) {
        const lastInterruptedAt = snap.lastInterruptedAt ? new Date(snap.lastInterruptedAt).getTime() : 0;
        const windowStart = Date.now() - CRASH_LOOP_WINDOW_MS;
        if (lastInterruptedAt > windowStart) {
          crashLoopBlocked = true;
          console.warn(
            `[AutoResume] CRASH-LOOP GUARD: Engagement #${engId} has been interrupted ${currentInterruptCount} times. Auto-resume blocked. Manual intervention required.`
          );
        } else {
          await db.update(engagementOpsSnapshots).set({ interruptCount: 1 }).where(eq(engagementOpsSnapshots.engagementId, engId));
          console.log(
            `[AutoResume] Engagement #${engId} interrupt count reset (previous interrupts outside 24h window)`
          );
        }
      }
      const entry = {
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
        interruptCount: currentInterruptCount
      };
      results.push(entry);
      const resumeStatus = crashLoopBlocked ? "Auto-resume BLOCKED (crash-loop guard). Manual resume required." : autoResumeEnabled ? `Auto-resume scheduled in ${AUTO_RESUME_DELAY_MS / 1e3}s.` : "Auto-resume not enabled. Use Resume button or enable auto-resume in engagement settings.";
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
        message: `Engagement #${engId} was interrupted during ${phase} (${progress}% complete). ${resumeStatus}`
      });
      console.log(
        `[AutoResume] Detected interrupted engagement #${engId}: phase=${phase}, progress=${progress}%, assets=${assetsCount}, vulns=${vulnsFound}, canResume=${canResume}, autoResume=${autoResumeEnabled}, crashLoop=${crashLoopBlocked}, interrupts=${currentInterruptCount}`
      );
    }
    detectedInterruptions = results;
    return results;
  } catch (err) {
    console.warn("[AutoResume] Failed to detect interrupted engagements:", err.message);
    return [];
  }
}
function scheduleAutoResumes() {
  for (const entry of detectedInterruptions) {
    if (!entry.canResume || !entry.autoResumeEnabled || entry.crashLoopBlocked) {
      continue;
    }
    const resumeAt = Date.now() + AUTO_RESUME_DELAY_MS;
    entry.scheduledResumeAt = resumeAt;
    console.log(
      `[AutoResume] Scheduling auto-resume for engagement #${entry.engagementId} in ${AUTO_RESUME_DELAY_MS / 1e3}s (at ${new Date(resumeAt).toISOString()}). Cancel within ${CANCEL_GRACE_PERIOD_MS / 1e3}s via cancelAutoResume().`
    );
    eventHub.broadcastEngagement(entry.engagementId, {
      type: "engagement:auto_resume_scheduled",
      engagementId: entry.engagementId,
      resumeAt,
      cancelDeadline: Date.now() + CANCEL_GRACE_PERIOD_MS,
      phase: entry.phase,
      message: `Auto-resume scheduled for engagement #${entry.engagementId} from ${entry.phase} phase. Resuming in ${AUTO_RESUME_DELAY_MS / 1e3}s.`
    });
    const timer = setTimeout(async () => {
      scheduledResumeTimers.delete(entry.engagementId);
      await executeAutoResume(entry.engagementId);
    }, AUTO_RESUME_DELAY_MS);
    scheduledResumeTimers.set(entry.engagementId, timer);
  }
}
async function executeAutoResume(engagementId) {
  try {
    const interruption = detectedInterruptions.find((e) => e.engagementId === engagementId);
    if (!interruption) {
      console.warn(`[AutoResume] No interrupted state found for engagement #${engagementId}, skipping`);
      return;
    }
    const { claimEngagement } = await import("./engagement-claim-lock-DXXWY2FD.js");
    const claim = await claimEngagement(engagementId);
    if (!claim.claimed) {
      console.log(
        `[AutoResume] Engagement #${engagementId}: claim denied \u2014 ${claim.reason}. Another server instance is handling it. Skipping auto-resume.`
      );
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:auto_resume_skipped",
        engagementId,
        reason: claim.reason,
        currentOwner: claim.currentOwner,
        message: `Auto-resume skipped for #${engagementId}: another server (${claim.currentOwner}) owns it.`
      });
      detectedInterruptions = detectedInterruptions.filter((e) => e.engagementId !== engagementId);
      return;
    }
    const memUsage = process.memoryUsage();
    const rssGB = memUsage.rss / (1024 * 1024 * 1024);
    const CONTAINER_LIMIT_GB = parseFloat(process.env.CONTAINER_MEMORY_LIMIT_GB || "8");
    const MAX_RSS_RATIO = 0.75;
    if (rssGB > CONTAINER_LIMIT_GB * MAX_RSS_RATIO) {
      console.warn(
        `[AutoResume] MEMORY GUARD: RSS=${rssGB.toFixed(2)}GB exceeds ${MAX_RSS_RATIO * 100}% of ${CONTAINER_LIMIT_GB}GB container limit. Skipping auto-resume for engagement #${engagementId} to prevent OOM. Manual resume required after memory stabilizes.`
      );
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:auto_resume_skipped",
        engagementId,
        reason: `Memory pressure too high (RSS=${rssGB.toFixed(1)}GB/${CONTAINER_LIMIT_GB}GB)`,
        message: `Auto-resume skipped for #${engagementId}: memory pressure too high. Resume manually.`
      });
      return;
    }
    try {
      const eventLoopOk = await new Promise((resolve) => {
        const start = Date.now();
        setImmediate(() => {
          const lag = Date.now() - start;
          if (lag > 2e3) {
            console.warn(`[AutoResume] Event loop lag: ${lag}ms \u2014 server is under heavy load`);
            resolve(false);
          } else {
            resolve(true);
          }
        });
        setTimeout(() => resolve(false), 5e3);
      });
      if (!eventLoopOk) {
        console.warn(`[AutoResume] Event loop health check FAILED for #${engagementId}. Deferring auto-resume.`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resume_skipped",
          engagementId,
          reason: "Event loop overloaded \u2014 server cannot accept new work",
          message: `Auto-resume deferred for #${engagementId}: server event loop is overloaded. Will retry on next restart.`
        });
        return;
      }
    } catch {
    }
    console.log(`[AutoResume] Executing auto-resume for engagement #${engagementId} from ${interruption.phase} (RSS=${rssGB.toFixed(2)}GB)...`);
    try {
      const { dismissAllStaleApprovals } = await import("./engagement-orchestrator-XSONXYFE.js");
      const staleCount = dismissAllStaleApprovals(engagementId, `auto-resume:server-restart`);
      if (staleCount > 0) {
        console.log(`[AutoResume] Dismissed ${staleCount} stale approval gate(s) for engagement #${engagementId}`);
      }
    } catch (gateErr) {
      console.warn(`[AutoResume] Failed to dismiss stale gates for #${engagementId}:`, gateErr.message);
    }
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      await notifyOwner({
        title: `\u{1F504} Auto-Resuming Engagement #${engagementId}`,
        content: [
          `Engagement #${engagementId} was interrupted by a server restart and is now being auto-resumed.`,
          ``,
          `Phase: ${interruption.phase} (${interruption.progress}% complete)`,
          `Assets: ${interruption.assetsCount} | Vulns: ${interruption.vulnsFound} | Ports: ${interruption.portsFound}`,
          `Interrupt count: ${interruption.interruptCount}`,
          ``,
          `If this engagement should not be resumed, stop it from the Engagement Ops page.`
        ].join("\n")
      });
    } catch (notifErr) {
      console.warn(`[AutoResume] Notification failed for #${engagementId}:`, notifErr.message);
    }
    const { getOpsStateWithRecovery, initOpsState, addLog: addOpsLog, broadcastOpsUpdate, persistOpsStateNow } = await import("./engagement-orchestrator-XSONXYFE.js");
    let state = await getOpsStateWithRecovery(engagementId);
    if (state) {
      const recoveryLogPhase = interruption.phase || state.phase || "recon";
      addOpsLog(state, {
        phase: recoveryLogPhase,
        type: "warning",
        title: "\u26A0\uFE0F Scan Interrupted \u2014 State Recovered",
        detail: `The server restarted while the scan was running. ${state.assets?.length || 0} assets have been recovered from the last snapshot (was in ${recoveryLogPhase} phase). You can reset and re-run the scan.`
      });
      await persistOpsStateNow(engagementId, state);
    }
    const storedPhases = state?.pipelinePhases || { passive: true, active: true, llmAnalysis: true, exploitGeneration: true };
    const currentPhase = interruption.phase;
    const phaseOrder = ["recon", "enumeration", "scanning", "vuln_detection", "exploitation", "post_exploit", "completed"];
    const currentIdx = phaseOrder.indexOf(currentPhase);
    const phaseComplete = {
      passive: currentIdx > phaseOrder.indexOf("recon"),
      active: currentIdx > phaseOrder.indexOf("vuln_detection"),
      llmAnalysis: currentIdx > phaseOrder.indexOf("vuln_detection"),
      exploitGeneration: currentIdx >= phaseOrder.indexOf("completed")
    };
    const resumePhases = {
      passive: storedPhases.passive && !phaseComplete.passive,
      active: storedPhases.active && !phaseComplete.active,
      llmAnalysis: storedPhases.llmAnalysis && !phaseComplete.llmAnalysis,
      exploitGeneration: storedPhases.exploitGeneration && !phaseComplete.exploitGeneration
    };
    console.log(`[AutoResume] Engagement #${engagementId}: currentPhase=${currentPhase}, resumePhases=${JSON.stringify(resumePhases)}`);
    try {
      const jwt = await import("jsonwebtoken");
      const signFn = jwt.default?.sign || jwt.sign;
      if (typeof signFn !== "function") {
        throw new Error(`JWT sign not available: got ${typeof signFn} from jsonwebtoken import`);
      }
      const jwtSecret = process.env.JWT_SECRET;
      const ownerOpenId = process.env.OWNER_OPEN_ID;
      const ownerName = process.env.OWNER_NAME || "Auto-Resume System";
      if (!jwtSecret || !ownerOpenId) {
        throw new Error("Missing JWT_SECRET or OWNER_OPEN_ID for internal auth");
      }
      const internalToken = signFn(
        { sub: ownerOpenId, name: ownerName, iat: Math.floor(Date.now() / 1e3) },
        jwtSecret,
        { expiresIn: "5m" }
      );
      const port = process.env.PORT || 3e3;
      const response = await fetch(`http://localhost:${port}/api/trpc/engagementOps.rerunFullPipeline`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Cookie": `token=${internalToken}`
        },
        body: JSON.stringify({
          json: {
            engagementId,
            phases: resumePhases,
            resetState: false,
            exhaustiveExploit: state?.exhaustiveExploit ?? true
          }
        })
      });
      const responseData = await response.json().catch(() => null);
      if (response.ok && responseData?.result?.data?.json?.started) {
        console.log(`[AutoResume] Successfully resumed engagement #${engagementId} via rerunFullPipeline`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resumed",
          engagementId,
          resumePhase: currentPhase,
          message: `Engagement #${engagementId} auto-resumed from ${currentPhase} via full pipeline.`
        });
      } else {
        const errorMsg = responseData?.error?.json?.message || responseData?.error?.message || `HTTP ${response.status}`;
        console.error(`[AutoResume] rerunFullPipeline failed for #${engagementId}: ${errorMsg}`);
        console.log(`[AutoResume] Falling back to orchestrator resumeEngagement for #${engagementId}...`);
        const { resumeEngagement } = await import("./engagement-orchestrator-XSONXYFE.js");
        const result = await resumeEngagement(engagementId, {
          id: "system-auto-resume",
          name: "Auto-Resume System"
        });
        if (result.success) {
          console.log(`[AutoResume] Fallback resume succeeded for #${engagementId}: ${result.message}`);
          eventHub.broadcastEngagement(engagementId, {
            type: "engagement:auto_resumed",
            engagementId,
            resumePhase: result.resumePhase,
            message: `Engagement #${engagementId} auto-resumed (fallback) from ${result.resumePhase}.`
          });
        } else {
          console.error(`[AutoResume] Fallback resume also failed for #${engagementId}: ${result.message}`);
          eventHub.broadcastEngagement(engagementId, {
            type: "engagement:auto_resume_failed",
            engagementId,
            error: `Primary: ${errorMsg}. Fallback: ${result.message}`
          });
        }
      }
    } catch (httpErr) {
      console.error(`[AutoResume] Internal HTTP call failed for #${engagementId}: ${httpErr.message}`);
      console.log(`[AutoResume] Falling back to orchestrator resumeEngagement for #${engagementId}...`);
      const { resumeEngagement } = await import("./engagement-orchestrator-XSONXYFE.js");
      const result = await resumeEngagement(engagementId, {
        id: "system-auto-resume",
        name: "Auto-Resume System"
      });
      if (result.success) {
        console.log(`[AutoResume] Fallback resume succeeded for #${engagementId}: ${result.message}`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resumed",
          engagementId,
          resumePhase: result.resumePhase,
          message: `Engagement #${engagementId} auto-resumed (fallback) from ${result.resumePhase}.`
        });
      } else {
        console.error(`[AutoResume] All resume attempts failed for #${engagementId}: ${result.message}`);
        eventHub.broadcastEngagement(engagementId, {
          type: "engagement:auto_resume_failed",
          engagementId,
          error: result.message
        });
      }
    }
    detectedInterruptions = detectedInterruptions.filter((e) => e.engagementId !== engagementId);
  } catch (err) {
    console.error(`[AutoResume] Auto-resume failed for engagement #${engagementId}:`, err.message);
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:auto_resume_failed",
      engagementId,
      error: err.message
    });
  }
}
function cancelAutoResume(engagementId) {
  const timer = scheduledResumeTimers.get(engagementId);
  if (timer) {
    clearTimeout(timer);
    scheduledResumeTimers.delete(engagementId);
    const entry = detectedInterruptions.find((e) => e.engagementId === engagementId);
    if (entry) {
      entry.scheduledResumeAt = void 0;
    }
    console.log(`[AutoResume] Cancelled scheduled auto-resume for engagement #${engagementId}`);
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:auto_resume_cancelled",
      engagementId,
      message: `Auto-resume cancelled for engagement #${engagementId}. Use Resume button to manually resume.`
    });
    return true;
  }
  return false;
}
function cancelAllAutoResumes() {
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
async function resetInterruptCounter(engagementId) {
  try {
    const { getDbRequired } = await import("./db-MOHZQFM5.js");
    const { engagementOpsSnapshots } = await import("./schema-XOTPZHKC.js");
    const { eq } = await import("drizzle-orm");
    const db = await getDbRequired();
    await db.update(engagementOpsSnapshots).set({ interruptCount: 0, lastInterruptedAt: null }).where(eq(engagementOpsSnapshots.engagementId, engagementId));
    const entry = detectedInterruptions.find((e) => e.engagementId === engagementId);
    if (entry) {
      entry.interruptCount = 0;
      entry.crashLoopBlocked = false;
    }
    console.log(`[AutoResume] Reset interrupt counter for engagement #${engagementId}`);
    return true;
  } catch (err) {
    console.error(`[AutoResume] Failed to reset interrupt counter for #${engagementId}:`, err.message);
    return false;
  }
}
function getDetectedInterruptions() {
  return detectedInterruptions;
}
function clearDetectedInterruptions() {
  cancelAllAutoResumes();
  detectedInterruptions = [];
}
async function autoResumeEngagement(engagementId) {
  try {
    const interruption = detectedInterruptions.find((e) => e.engagementId === engagementId);
    if (!interruption) {
      return { success: false, message: "No interrupted state found for this engagement" };
    }
    if (!interruption.canResume) {
      return { success: false, message: "This engagement cannot be auto-resumed (insufficient progress)" };
    }
    await executeAutoResume(engagementId);
    return {
      success: true,
      message: `Engagement #${engagementId} resume initiated from ${interruption.phase}`
    };
  } catch (err) {
    return { success: false, message: `Auto-resume failed: ${err.message}` };
  }
}
async function initAutoResumeHook() {
  console.log("[AutoResume] Scanning for interrupted engagements...");
  const interrupted = await detectInterruptedEngagements();
  if (interrupted.length > 0) {
    console.log(
      `[AutoResume] Found ${interrupted.length} interrupted engagement(s): ` + interrupted.map(
        (e) => `#${e.engagementId}(${e.phase}, autoResume=${e.autoResumeEnabled}, crashLoop=${e.crashLoopBlocked})`
      ).join(", ")
    );
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      const autoResumeCount = interrupted.filter((e) => e.autoResumeEnabled && !e.crashLoopBlocked && e.canResume).length;
      const blockedCount = interrupted.filter((e) => e.crashLoopBlocked).length;
      const engList = interrupted.map((e) => {
        let status = "Manual resume required";
        if (e.crashLoopBlocked) status = "\u26D4 CRASH-LOOP BLOCKED";
        else if (e.autoResumeEnabled && e.canResume) status = `\u{1F504} Auto-resuming in ${AUTO_RESUME_DELAY_MS / 1e3}s`;
        return `  \u2022 #${e.engagementId}: ${e.phase} (${e.progress}%), ${e.assetsCount} assets, ${e.vulnsFound} vulns \u2014 ${status}`;
      }).join("\n");
      await notifyOwner({
        title: `\u26A0\uFE0F ${interrupted.length} Interrupted Engagement${interrupted.length > 1 ? "s" : ""} Detected`,
        content: [
          `The server restarted and ${interrupted.length} engagement${interrupted.length > 1 ? "s were" : " was"} interrupted.`,
          ``,
          engList,
          ``,
          autoResumeCount > 0 ? `${autoResumeCount} engagement${autoResumeCount > 1 ? "s" : ""} will auto-resume in ${AUTO_RESUME_DELAY_MS / 1e3} seconds.` : "No engagements have auto-resume enabled.",
          blockedCount > 0 ? `\u26D4 ${blockedCount} engagement${blockedCount > 1 ? "s are" : " is"} blocked by the crash-loop guard (${MAX_INTERRUPTS_BEFORE_BLOCK}+ interrupts in 24h). Reset the counter from Engagement Ops to re-enable.` : ""
        ].filter(Boolean).join("\n")
      });
    } catch (notifErr) {
      console.warn("[AutoResume] Owner notification failed:", notifErr.message);
    }
    scheduleAutoResumes();
  }
}
var AUTO_RESUME_CONFIG = {
  MAX_INTERRUPTS_BEFORE_BLOCK,
  CRASH_LOOP_WINDOW_MS,
  AUTO_RESUME_DELAY_MS,
  CANCEL_GRACE_PERIOD_MS
};
export {
  AUTO_RESUME_CONFIG,
  autoResumeEngagement,
  cancelAllAutoResumes,
  cancelAutoResume,
  clearDetectedInterruptions,
  detectInterruptedEngagements,
  getDetectedInterruptions,
  initAutoResumeHook,
  resetInterruptCounter,
  scheduleAutoResumes
};
