/**
 * Auto-Generation Pipeline Scheduler
 * 
 * Runs the adversary profile auto-generation pipeline on a configurable schedule.
 * Default: daily at 02:00 UTC. Scans all threat actors, auto-generates profiles
 * for those above the completeness threshold, and optionally pushes to Caldera.
 * 
 * Also provides a manual trigger endpoint and run status tracking.
 */
import cron from "node-cron";
import { runAutoGenerationPipeline, getAutoGenerationStats, getAutoGenerationHistory } from "./threat-intel-auto-enrich";
import { notifyOwner } from "../_core/notification";
import { eventHub } from "./ws-event-hub";

// ─── Pipeline Run Status ──────────────────────────────────────────────
export interface PipelineRunResult {
  runId: string;
  startedAt: number;
  completedAt: number | null;
  status: "running" | "completed" | "failed";
  trigger: "scheduled" | "manual";
  actorsScanned: number;
  profilesGenerated: number;
  profilesPushed: number;
  errors: string[];
}

const runHistory: PipelineRunResult[] = [];
let currentRun: PipelineRunResult | null = null;
let cronTask: cron.ScheduledTask | null = null;
let schedulerConfig = {
  enabled: true,
  cronExpression: "0 2 * * *", // Daily at 02:00 UTC
  timezone: "UTC",
  notifyOnComplete: true,
  autoPushToCaldera: false,
};

// ─── Generate unique run ID ───────────────────────────────────────────
function generateRunId(): string {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const time = now.toISOString().slice(11, 19).replace(/:/g, "");
  const rand = Math.random().toString(36).slice(2, 6);
  return `pipeline-${date}-${time}-${rand}`;
}

// ─── Execute Pipeline Run ─────────────────────────────────────────────
export async function executePipelineRun(
  trigger: "scheduled" | "manual" = "manual"
): Promise<PipelineRunResult> {
  // Prevent concurrent runs
  if (currentRun && currentRun.status === "running") {
    return currentRun;
  }

  const run: PipelineRunResult = {
    runId: generateRunId(),
    startedAt: Date.now(),
    completedAt: null,
    status: "running",
    trigger,
    actorsScanned: 0,
    profilesGenerated: 0,
    profilesPushed: 0,
    errors: [],
  };

  currentRun = run;

  // Broadcast pipeline start event
  try {
    const { emitPipelineRun } = await import("./ws-event-hub");
    emitPipelineRun({
      runId: run.runId,
      status: "started",
    });
  } catch { /* WS hub may not be ready */ }

  try {
    console.log(`[AutoGenPipeline] Run ${run.runId} started (trigger: ${trigger})`);

    const result = await runAutoGenerationPipeline();

    run.actorsScanned = result.totalActorsScanned;
    run.profilesGenerated = result.profilesGenerated;
    run.profilesPushed = result.profilesPushedToCaldera;
    run.status = "completed";
    run.completedAt = Date.now();

    console.log(
      `[AutoGenPipeline] Run ${run.runId} completed: ` +
      `${run.actorsScanned} scanned, ${run.profilesGenerated} generated, ${run.profilesPushed} pushed`
    );

    // Notify owner on completion
    if (schedulerConfig.notifyOnComplete && (run.profilesGenerated > 0 || run.profilesPushed > 0)) {
      const duration = ((run.completedAt - run.startedAt) / 1000).toFixed(1);
      await notifyOwner({
        title: "Auto-Generation Pipeline Complete",
        content: [
          `Pipeline run ${run.runId} completed in ${duration}s.`,
          `Actors scanned: ${run.actorsScanned}`,
          `Profiles generated: ${run.profilesGenerated}`,
          `Profiles pushed to Caldera: ${run.profilesPushed}`,
          `Trigger: ${trigger}`,
        ].join("\n"),
      });
    }

    // Broadcast pipeline complete event
    try {
      const { emitPipelineRun } = await import("./ws-event-hub");
      emitPipelineRun({
        runId: run.runId,
        status: "completed",
        actorsScanned: run.actorsScanned,
        profilesGenerated: run.profilesGenerated,
        profilesPushed: run.profilesPushed,
      });
    } catch { /* WS hub may not be ready */ }

  } catch (err: any) {
    run.status = "failed";
    run.completedAt = Date.now();
    run.errors.push(err.message || "Unknown error");
    console.error(`[AutoGenPipeline] Run ${run.runId} failed:`, err.message);

    // Notify owner on failure
    await notifyOwner({
      title: "Auto-Generation Pipeline Failed",
      content: `Pipeline run ${run.runId} failed after ${((Date.now() - run.startedAt) / 1000).toFixed(1)}s.\nError: ${err.message}`,
    });

    // Broadcast pipeline failure event
    try {
      const { emitPipelineRun } = await import("./ws-event-hub");
      emitPipelineRun({
        runId: run.runId,
        status: "failed",
        error: err.message,
      });
    } catch { /* WS hub may not be ready */ }
  }

  // Store in history (keep last 50 runs)
  runHistory.unshift(run);
  if (runHistory.length > 50) runHistory.length = 50;
  currentRun = null;

  return run;
}

// ─── Scheduler Management ─────────────────────────────────────────────
export function initAutoGenerationSchedule(): void {
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
      console.log(`[AutoGenPipeline] Scheduled run starting at ${new Date().toISOString()}`);
      await executePipelineRun("scheduled");
    },
    { timezone: schedulerConfig.timezone }
  );

  cronTask.start();
  console.log("[AutoGenPipeline] Auto-generation pipeline scheduler active");
}

export function stopAutoGenerationSchedule(): void {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
    console.log("[AutoGenPipeline] Scheduler stopped");
  }
}

// ─── Configuration ────────────────────────────────────────────────────
export function updateSchedulerConfig(updates: {
  enabled?: boolean;
  cronExpression?: string;
  timezone?: string;
  notifyOnComplete?: boolean;
  autoPushToCaldera?: boolean;
}): typeof schedulerConfig {
  Object.assign(schedulerConfig, updates);

  // Reinitialize if schedule changed
  if (updates.cronExpression || updates.timezone || updates.enabled !== undefined) {
    initAutoGenerationSchedule();
  }

  return { ...schedulerConfig };
}

export function getSchedulerConfig(): typeof schedulerConfig {
  return { ...schedulerConfig };
}

// ─── Status & History ─────────────────────────────────────────────────
export function getPipelineRunHistory(limit = 20): PipelineRunResult[] {
  return runHistory.slice(0, limit);
}

export function getCurrentRun(): PipelineRunResult | null {
  return currentRun ? { ...currentRun } : null;
}

export function getPipelineStatus(): {
  schedulerEnabled: boolean;
  cronExpression: string;
  timezone: string;
  currentRun: PipelineRunResult | null;
  lastRun: PipelineRunResult | null;
  totalRuns: number;
  totalProfilesGenerated: number;
  totalProfilesPushed: number;
  autoGenerationStats: ReturnType<typeof getAutoGenerationStats>;
} {
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
    autoGenerationStats: stats,
  };
}
