/**
 * Job Queue Bridge — Transparent replacement for direct SSH executeTool() calls
 *
 * This module provides `executeToolViaQueue()` which has the same signature as
 * `executeTool()` from scan-server-executor.ts but routes execution through the
 * Redis job queue when healthy DO workers are available, falling back to direct
 * SSH execution when they're not.
 *
 * The engagement-orchestrator imports this instead of scan-server-executor for
 * all scan execution, making the queue integration transparent to the rest of
 * the pipeline.
 *
 * Architecture:
 *   Orchestrator → executeToolViaQueue() → [healthy workers?]
 *                                            ├─ YES → enqueue job → poll for result → return ToolExecResult
 *                                            └─ NO  → executeTool() via SSH (fallback)
 */
import type { ToolExecConfig, ToolExecResult } from "./scan-server-executor";
import {
  dispatchScanJob,
  getJobStatus,
  getJobResult,
  hasHealthyWorker,
  onJobEvent,
  offJobEvent,
  type JobResult,
} from "./job-queue";
import { eventHub } from "./ws-event-hub";

// ─── Configuration ──────────────────────────────────────────────────────────

/** How often to poll for job completion (ms) */
const POLL_INTERVAL_MS = 2000;

/** Maximum time to wait for a queued job before timing out (ms) */
const MAX_QUEUE_WAIT_MS = 900_000; // 15 minutes

/** Log prefix */
const LOG = "[JobQueueBridge]";

// ─── Metrics ────────────────────────────────────────────────────────────────

interface BridgeMetrics {
  totalDispatched: number;
  queuedToWorker: number;
  fellBackToSSH: number;
  completedViaQueue: number;
  failedViaQueue: number;
  timedOutViaQueue: number;
  avgQueueLatencyMs: number;
  avgSSHLatencyMs: number;
}

const metrics: BridgeMetrics = {
  totalDispatched: 0,
  queuedToWorker: 0,
  fellBackToSSH: 0,
  completedViaQueue: 0,
  failedViaQueue: 0,
  timedOutViaQueue: 0,
  avgQueueLatencyMs: 0,
  avgSSHLatencyMs: 0,
};

export function getBridgeMetrics(): BridgeMetrics {
  return { ...metrics };
}

// ─── Core: executeToolViaQueue ──────────────────────────────────────────────

/**
 * Execute a tool command through the job queue (if workers available) or SSH fallback.
 *
 * Drop-in replacement for `executeTool()` from scan-server-executor.ts.
 * Returns the same ToolExecResult interface so the orchestrator doesn't need changes
 * to its result parsing logic.
 */
export async function executeToolViaQueue(
  config: ToolExecConfig,
  options?: {
    /** Engagement ID for RoE scope enforcement */
    engagementId?: number;
    /** RoE authorized targets for scope guard */
    roeScope?: string[];
    /** Operator ID for audit trail */
    operatorId?: string;
    /** Force local SSH execution (bypass queue) */
    forceLocal?: boolean;
    /** Force queue execution (fail if no workers) */
    forceQueue?: boolean;
  }
): Promise<ToolExecResult & { executionMode: "queue" | "local" }> {
  const startTime = Date.now();
  metrics.totalDispatched++;

  const engagementId = options?.engagementId || config.engagementId || 0;
  const roeScope = options?.roeScope || [];
  const target = config.target || "unknown";

  // ── Decision: queue vs local ──────────────────────────────────────────
  const useQueue = !options?.forceLocal && (options?.forceQueue || hasHealthyWorker("scan"));

  if (!useQueue) {
    // Fallback to direct SSH execution
    metrics.fellBackToSSH++;
    console.log(`${LOG} No healthy workers or forceLocal — SSH fallback for ${config.tool} on ${target}`);

    const { executeTool } = await import("./scan-server-executor");
    const result = await executeTool(config);
    const latency = Date.now() - startTime;

    // Update average SSH latency
    metrics.avgSSHLatencyMs = metrics.fellBackToSSH === 1
      ? latency
      : Math.round((metrics.avgSSHLatencyMs * (metrics.fellBackToSSH - 1) + latency) / metrics.fellBackToSSH);

    // Broadcast execution event
    broadcastJobEvent(engagementId, {
      type: "job:executed_local",
      tool: config.tool,
      target,
      durationMs: latency,
      exitCode: result.exitCode,
    });

    return { ...result, executionMode: "local" };
  }

  // ── Queue dispatch ────────────────────────────────────────────────────
  metrics.queuedToWorker++;
  console.log(`${LOG} Dispatching ${config.tool} on ${target} to job queue (engagement #${engagementId})`);

  const { jobId, mode } = await dispatchScanJob({
    engagementId,
    targets: [target],
    tool: config.tool,
    args: config.args,
    roeScope,
    operatorId: options?.operatorId,
    timeoutSeconds: config.timeoutSeconds,
    sudo: config.sudo,
  });

  // If dispatchScanJob fell back to local (no workers at dispatch time), return immediately
  if (mode === "local") {
    const result = getJobResult(jobId);
    if (result) {
      const latency = Date.now() - startTime;
      metrics.fellBackToSSH++;
      metrics.queuedToWorker--; // Correct the count
      return {
        tool: config.tool,
        command: `${config.tool} ${config.args}`,
        stdout: result.results[0]?.findings?.join("\n") || "",
        stderr: "",
        exitCode: result.status === "completed" ? 0 : -1,
        durationMs: latency,
        timedOut: false,
        executionMode: "local",
      };
    }
  }

  // Broadcast queued event
  broadcastJobEvent(engagementId, {
    type: "job:queued",
    jobId,
    tool: config.tool,
    target,
  });

  // ── Wait for job completion ───────────────────────────────────────────
  const toolResult = await waitForJobCompletion(jobId, config, startTime);

  // Broadcast completion event
  broadcastJobEvent(engagementId, {
    type: toolResult.exitCode === 0 ? "job:completed" : "job:failed",
    jobId,
    tool: config.tool,
    target,
    durationMs: toolResult.durationMs,
    exitCode: toolResult.exitCode,
  });

  return { ...toolResult, executionMode: "queue" };
}

/**
 * Execute a raw command through the job queue or SSH fallback.
 * Drop-in replacement for `executeRawCommand()` from scan-server-executor.ts.
 */
export async function executeRawCommandViaQueue(
  command: string,
  timeoutSeconds: number = 300,
  options?: {
    engagementId?: number;
    roeScope?: string[];
    forceLocal?: boolean;
  }
): Promise<ToolExecResult & { executionMode: "queue" | "local" }> {
  // Raw commands always go through SSH — they're typically pipe commands
  // that need shell interpretation which workers don't support yet
  const { executeRawCommand } = await import("./scan-server-executor");
  const result = await executeRawCommand(command, timeoutSeconds);
  return { ...result, executionMode: "local" };
}

// ─── Job Completion Polling ─────────────────────────────────────────────────

/**
 * Wait for a queued job to complete, with polling and event-based notification.
 */
async function waitForJobCompletion(
  jobId: string,
  config: ToolExecConfig,
  startTime: number
): Promise<ToolExecResult> {
  const timeoutMs = (config.timeoutSeconds || 300) * 1000 + 30_000; // Add 30s buffer for queue overhead
  const deadline = startTime + Math.min(timeoutMs, MAX_QUEUE_WAIT_MS);

  return new Promise<ToolExecResult>((resolve) => {
    let resolved = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    // Event-based completion handler (fires immediately when result arrives)
    const onComplete = (result: JobResult) => {
      if (result.jobId !== jobId || resolved) return;
      resolved = true;
      cleanup();
      resolve(jobResultToToolExecResult(result, config, startTime));
    };

    // Register event listener
    onJobEvent("job:completed", onComplete);

    // Polling fallback (in case event is missed)
    pollTimer = setInterval(() => {
      if (resolved) return;

      // Check timeout
      if (Date.now() > deadline) {
        resolved = true;
        cleanup();
        metrics.timedOutViaQueue++;
        console.warn(`${LOG} Job ${jobId} timed out after ${Date.now() - startTime}ms`);
        resolve({
          tool: config.tool,
          command: `${config.tool} ${config.args}`,
          stdout: "",
          stderr: `Job ${jobId} timed out waiting for worker completion`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          timedOut: true,
          error: "Queue job timed out",
        });
        return;
      }

      // Poll for result
      const status = getJobStatus(jobId);
      if (status.status === "completed" || status.status === "failed") {
        const result = getJobResult(jobId);
        if (result) {
          resolved = true;
          cleanup();
          resolve(jobResultToToolExecResult(result, config, startTime));
        }
      }
    }, POLL_INTERVAL_MS);

    function cleanup() {
      if (pollTimer) clearInterval(pollTimer);
      offJobEvent("job:completed", onComplete);
    }
  });
}

// ─── Conversion Helpers ─────────────────────────────────────────────────────

/**
 * Convert a JobResult into a ToolExecResult so the orchestrator's existing
 * parsing logic works unchanged.
 */
function jobResultToToolExecResult(
  jobResult: JobResult,
  config: ToolExecConfig,
  startTime: number
): ToolExecResult {
  const isSuccess = jobResult.status === "completed";
  const toolResult = jobResult.results.find(r => r.tool === config.tool) || jobResult.results[0];
  const durationMs = toolResult?.duration_ms || (Date.now() - startTime);

  if (isSuccess) {
    metrics.completedViaQueue++;
    // Update average queue latency
    metrics.avgQueueLatencyMs = metrics.completedViaQueue === 1
      ? durationMs
      : Math.round((metrics.avgQueueLatencyMs * (metrics.completedViaQueue - 1) + durationMs) / metrics.completedViaQueue);
  } else {
    metrics.failedViaQueue++;
  }

  // Reconstruct stdout from findings if available (workers send structured data)
  // The orchestrator's parseToolOutput() will re-parse this
  const stdout = toolResult?.findings?.length
    ? toolResult.findings.map((f: any) =>
        typeof f === "string" ? f : JSON.stringify(f)
      ).join("\n")
    : "";

  return {
    tool: config.tool,
    command: `${config.tool} ${config.args}`,
    stdout,
    stderr: isSuccess ? "" : `Job ${jobResult.jobId} failed on worker ${jobResult.metadata.workerHost}`,
    exitCode: isSuccess ? 0 : -1,
    durationMs,
    timedOut: false,
    error: isSuccess ? undefined : `Worker execution failed`,
  };
}

// ─── WebSocket Broadcasting ─────────────────────────────────────────────────

function broadcastJobEvent(engagementId: number, data: Record<string, any>) {
  try {
    if (engagementId > 0) {
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:progress_update",
        timestamp: Date.now(),
        engagementId,
        data: { ...data, source: "job-queue-bridge" },
      });
    }
  } catch {
    // Non-critical — don't fail scan execution if WS broadcast fails
  }
}

// ─── Batch Execution ────────────────────────────────────────────────────────

/**
 * Execute multiple tool commands in parallel through the queue.
 * Respects concurrency limits and returns results in order.
 */
export async function executeToolBatchViaQueue(
  configs: Array<ToolExecConfig & { purpose?: string }>,
  options?: {
    engagementId?: number;
    roeScope?: string[];
    operatorId?: string;
    concurrency?: number;
  }
): Promise<Array<ToolExecResult & { executionMode: "queue" | "local" }>> {
  const concurrency = options?.concurrency || 3;
  const results: Array<ToolExecResult & { executionMode: "queue" | "local" }> = [];

  for (let i = 0; i < configs.length; i += concurrency) {
    const batch = configs.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(config =>
        executeToolViaQueue(config, {
          engagementId: options?.engagementId,
          roeScope: options?.roeScope,
          operatorId: options?.operatorId,
        })
      )
    );

    for (const r of batchResults) {
      if (r.status === "fulfilled") {
        results.push(r.value);
      } else {
        results.push({
          tool: "unknown",
          command: "",
          stdout: "",
          stderr: r.reason?.message || "Batch execution failed",
          exitCode: -1,
          durationMs: 0,
          timedOut: false,
          error: r.reason?.message,
          executionMode: "local",
        });
      }
    }
  }

  return results;
}

// ─── Health Check ───────────────────────────────────────────────────────────

/**
 * Check if the job queue bridge is operational.
 * Returns the current routing mode and worker availability.
 */
export function getBridgeStatus(): {
  mode: "queue" | "local" | "hybrid";
  hasWorkers: boolean;
  metrics: BridgeMetrics;
} {
  const hasWorkers = hasHealthyWorker("scan");
  const mode = hasWorkers ? "queue" : "local";
  return { mode, hasWorkers, metrics: getBridgeMetrics() };
}
