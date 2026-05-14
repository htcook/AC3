import {
  getAutoGenerationStats,
  runAutoGenerationPipeline
} from "./chunk-XXH57QWE.js";
import {
  init_notification,
  notifyOwner
} from "./chunk-V73EMRJ6.js";

// server/lib/auto-generation-scheduler.ts
import cron from "node-cron";
init_notification();
var runHistory = [];
var currentRun = null;
var cronTask = null;
var schedulerConfig = {
  enabled: true,
  cronExpression: "0 2 * * *",
  // Daily at 02:00 UTC
  timezone: "UTC",
  notifyOnComplete: true,
  autoPushToCaldera: false
};
function generateRunId() {
  const now = /* @__PURE__ */ new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const time = now.toISOString().slice(11, 19).replace(/:/g, "");
  const rand = Math.random().toString(36).slice(2, 6);
  return `pipeline-${date}-${time}-${rand}`;
}
async function executePipelineRun(trigger = "manual") {
  if (currentRun && currentRun.status === "running") {
    return currentRun;
  }
  const run = {
    runId: generateRunId(),
    startedAt: Date.now(),
    completedAt: null,
    status: "running",
    trigger,
    actorsScanned: 0,
    profilesGenerated: 0,
    profilesPushed: 0,
    errors: []
  };
  currentRun = run;
  try {
    const { emitPipelineRun } = await import("./ws-event-hub-GYTLNKYI.js");
    emitPipelineRun({
      runId: run.runId,
      status: "started"
    });
  } catch {
  }
  try {
    console.log(`[AutoGenPipeline] Run ${run.runId} started (trigger: ${trigger})`);
    const result = await runAutoGenerationPipeline();
    run.actorsScanned = result.totalActorsScanned;
    run.profilesGenerated = result.profilesGenerated;
    run.profilesPushed = result.profilesPushedToCaldera;
    run.status = "completed";
    run.completedAt = Date.now();
    console.log(
      `[AutoGenPipeline] Run ${run.runId} completed: ${run.actorsScanned} scanned, ${run.profilesGenerated} generated, ${run.profilesPushed} pushed`
    );
    if (schedulerConfig.notifyOnComplete && (run.profilesGenerated > 0 || run.profilesPushed > 0)) {
      const duration = ((run.completedAt - run.startedAt) / 1e3).toFixed(1);
      await notifyOwner({
        title: "Auto-Generation Pipeline Complete",
        content: [
          `Pipeline run ${run.runId} completed in ${duration}s.`,
          `Actors scanned: ${run.actorsScanned}`,
          `Profiles generated: ${run.profilesGenerated}`,
          `Profiles pushed to Caldera: ${run.profilesPushed}`,
          `Trigger: ${trigger}`
        ].join("\n")
      });
    }
    try {
      const { emitPipelineRun } = await import("./ws-event-hub-GYTLNKYI.js");
      emitPipelineRun({
        runId: run.runId,
        status: "completed",
        actorsScanned: run.actorsScanned,
        profilesGenerated: run.profilesGenerated,
        profilesPushed: run.profilesPushed
      });
    } catch {
    }
  } catch (err) {
    run.status = "failed";
    run.completedAt = Date.now();
    run.errors.push(err.message || "Unknown error");
    console.error(`[AutoGenPipeline] Run ${run.runId} failed:`, err.message);
    await notifyOwner({
      title: "Auto-Generation Pipeline Failed",
      content: `Pipeline run ${run.runId} failed after ${((Date.now() - run.startedAt) / 1e3).toFixed(1)}s.
Error: ${err.message}`
    });
    try {
      const { emitPipelineRun } = await import("./ws-event-hub-GYTLNKYI.js");
      emitPipelineRun({
        runId: run.runId,
        status: "failed",
        error: err.message
      });
    } catch {
    }
  }
  runHistory.unshift(run);
  if (runHistory.length > 50) runHistory.length = 50;
  currentRun = null;
  return run;
}
function initAutoGenerationSchedule() {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
  }
  if (!schedulerConfig.enabled) {
    console.log("[AutoGenPipeline] Scheduler disabled");
    return;
  }
  console.log(
    `[AutoGenPipeline] Scheduling auto-generation pipeline: ${schedulerConfig.cronExpression} (${schedulerConfig.timezone})`
  );
  cronTask = cron.schedule(
    schedulerConfig.cronExpression,
    async () => {
      console.log(`[AutoGenPipeline] Scheduled run starting at ${(/* @__PURE__ */ new Date()).toISOString()}`);
      await executePipelineRun("scheduled");
    },
    { timezone: schedulerConfig.timezone }
  );
  cronTask.start();
  console.log("[AutoGenPipeline] Auto-generation pipeline scheduler active");
}
function stopAutoGenerationSchedule() {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
    console.log("[AutoGenPipeline] Scheduler stopped");
  }
}
function updateSchedulerConfig(updates) {
  Object.assign(schedulerConfig, updates);
  if (updates.cronExpression || updates.timezone || updates.enabled !== void 0) {
    initAutoGenerationSchedule();
  }
  return { ...schedulerConfig };
}
function getSchedulerConfig() {
  return { ...schedulerConfig };
}
function getPipelineRunHistory(limit = 20) {
  return runHistory.slice(0, limit);
}
function getCurrentRun() {
  return currentRun ? { ...currentRun } : null;
}
function getPipelineStatus() {
  const stats = getAutoGenerationStats();
  const lastRun = runHistory.length > 0 ? runHistory[0] : null;
  return {
    schedulerEnabled: schedulerConfig.enabled,
    cronExpression: schedulerConfig.cronExpression,
    timezone: schedulerConfig.timezone,
    currentRun: currentRun ? { ...currentRun } : null,
    lastRun,
    totalRuns: runHistory.length,
    totalProfilesGenerated: runHistory.reduce((sum, r) => sum + r.profilesGenerated, 0),
    totalProfilesPushed: runHistory.reduce((sum, r) => sum + r.profilesPushed, 0),
    autoGenerationStats: stats
  };
}

export {
  executePipelineRun,
  initAutoGenerationSchedule,
  stopAutoGenerationSchedule,
  updateSchedulerConfig,
  getSchedulerConfig,
  getPipelineRunHistory,
  getCurrentRun,
  getPipelineStatus
};
