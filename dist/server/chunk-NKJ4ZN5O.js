import {
  dispatchScanJob,
  getJobResult,
  getJobStatus,
  hasHealthyWorker,
  init_job_queue,
  offJobEvent,
  onJobEvent
} from "./chunk-HX4THWTN.js";
import {
  getSafetyEngine,
  init_safety_engine
} from "./chunk-4SXJ2GAM.js";
import {
  eventHub,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/job-queue-bridge.ts
function getBridgeMetrics() {
  return { ...metrics };
}
async function executeToolViaQueue(config, options) {
  const startTime = Date.now();
  metrics.totalDispatched++;
  const engagementId = options?.engagementId || config.engagementId || 0;
  const roeScope = options?.roeScope || [];
  const target = config.target || "unknown";
  if (engagementId > 0) {
    try {
      const safetyEngine = getSafetyEngine(engagementId);
      const assessment = safetyEngine.assess(
        config.tool,
        config.args,
        target
      );
      broadcastJobEvent(engagementId, {
        type: "safety:assessed",
        tool: config.tool,
        target,
        allowed: assessment.allowed,
        safetyLevel: assessment.safetyLevel,
        blastRadius: assessment.blastRadius.riskScore,
        reason: assessment.reason
      });
      if (!assessment.allowed) {
        metrics.totalDispatched--;
        console.warn(
          `${LOG} [SAFETY BLOCKED] ${config.tool} on ${target} \u2014 Level: ${assessment.safetyLevel}, Reason: ${assessment.reason}`
        );
        return {
          tool: config.tool,
          command: `${config.tool} ${config.args}`,
          stdout: "",
          stderr: `[SAFETY ENGINE] Command blocked at safety level '${assessment.safetyLevel}': ${assessment.reason}`,
          exitCode: -2,
          // -2 = safety blocked (distinct from -1 = error)
          durationMs: Date.now() - startTime,
          timedOut: false,
          error: `Safety blocked: ${assessment.reason}`,
          executionMode: "local"
        };
      }
    } catch (safetyErr) {
      console.warn(`${LOG} Safety engine error (non-blocking): ${safetyErr.message}`);
    }
  }
  const useQueue = !options?.forceLocal && (options?.forceQueue || hasHealthyWorker("scan"));
  if (!useQueue) {
    if (!options?.forceLocal) {
      try {
        const { executeToolViaHttp } = await import("./do-scan-api-IENIHCQI.js");
        const httpResult = await executeToolViaHttp(config, options?.engagementAbortSignal);
        const latency = Date.now() - startTime;
        metrics.fellBackToSSH++;
        metrics.avgSSHLatencyMs = metrics.fellBackToSSH === 1 ? latency : Math.round((metrics.avgSSHLatencyMs * (metrics.fellBackToSSH - 1) + latency) / metrics.fellBackToSSH);
        broadcastJobEvent(engagementId, {
          type: "job:executed_http",
          tool: config.tool,
          target,
          durationMs: latency,
          exitCode: httpResult.exitCode
        });
        return { ...httpResult, executionMode: "local" };
      } catch (httpErr) {
        console.warn(`${LOG} HTTP API failed for ${config.tool}: ${httpErr.message}, falling back to SSH`);
      }
    }
    metrics.fellBackToSSH++;
    console.log(`${LOG} SSH fallback for ${config.tool} on ${target}`);
    try {
      const { executeTool } = await import("./scan-server-executor-NMDOA3SN.js");
      const result = await executeTool(config);
      const latency = Date.now() - startTime;
      metrics.avgSSHLatencyMs = metrics.fellBackToSSH === 1 ? latency : Math.round((metrics.avgSSHLatencyMs * (metrics.fellBackToSSH - 1) + latency) / metrics.fellBackToSSH);
      broadcastJobEvent(engagementId, {
        type: "job:executed_local",
        tool: config.tool,
        target,
        durationMs: latency,
        exitCode: result.exitCode
      });
      return { ...result, executionMode: "local" };
    } catch (sshErr) {
      console.error(`${LOG} SSH fallback also failed for ${config.tool}: ${sshErr.message}`);
      trackDeferredScan(engagementId, config, sshErr.message);
      return {
        tool: config.tool,
        command: `${config.tool} ${config.args || ""}`,
        stdout: "",
        stderr: `All execution paths failed. HTTP: scan service unavailable. SSH: ${sshErr.message}`,
        exitCode: -1,
        durationMs: Date.now() - startTime,
        timedOut: false,
        error: `All execution paths failed for ${config.tool}`,
        executionMode: "local"
      };
    }
  }
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
    sudo: config.sudo
  });
  if (mode === "local") {
    const result = getJobResult(jobId);
    if (result) {
      const latency = Date.now() - startTime;
      metrics.fellBackToSSH++;
      metrics.queuedToWorker--;
      return {
        tool: config.tool,
        command: `${config.tool} ${config.args}`,
        stdout: result.results[0]?.findings?.join("\n") || "",
        stderr: "",
        exitCode: result.status === "completed" ? 0 : -1,
        durationMs: latency,
        timedOut: false,
        executionMode: "local"
      };
    }
  }
  broadcastJobEvent(engagementId, {
    type: "job:queued",
    jobId,
    tool: config.tool,
    target
  });
  const toolResult = await waitForJobCompletion(jobId, config, startTime);
  broadcastJobEvent(engagementId, {
    type: toolResult.exitCode === 0 ? "job:completed" : "job:failed",
    jobId,
    tool: config.tool,
    target,
    durationMs: toolResult.durationMs,
    exitCode: toolResult.exitCode
  });
  return { ...toolResult, executionMode: "queue" };
}
async function executeRawCommandViaQueue(command, timeoutSeconds = 300, options) {
  const engagementId = options?.engagementId || 0;
  if (engagementId > 0) {
    try {
      const safetyEngine = getSafetyEngine(engagementId);
      const cmdParts = command.trim().split(/\s+/);
      const rawTool = cmdParts[0]?.replace(/^sudo\s+/, "") || "raw";
      const assessment = safetyEngine.assess(rawTool, command, "raw-command");
      if (!assessment.allowed) {
        console.warn(`${LOG} [SAFETY BLOCKED] Raw command: ${command.slice(0, 100)} \u2014 ${assessment.reason}`);
        return {
          tool: "raw",
          command,
          stdout: "",
          stderr: `[SAFETY ENGINE] Raw command blocked at safety level '${assessment.safetyLevel}': ${assessment.reason}`,
          exitCode: -2,
          durationMs: 0,
          timedOut: false,
          error: `Safety blocked: ${assessment.reason}`,
          executionMode: "local"
        };
      }
    } catch (safetyErr) {
      console.warn(`${LOG} Safety engine error for raw command (non-blocking): ${safetyErr.message}`);
    }
  }
  if (!options?.forceLocal) {
    try {
      console.log(`[RawCmdViaQueue] Using DO HTTP API for: ${command.slice(0, 80)}...`);
      const { executeRawCommandViaHttp } = await import("./do-scan-api-IENIHCQI.js");
      const result2 = await executeRawCommandViaHttp(command, timeoutSeconds, options?.engagementAbortSignal);
      console.log(`[RawCmdViaQueue] HTTP completed: exit=${result2.exitCode}, stdout=${result2.stdout.length}b`);
      return { ...result2, executionMode: "local" };
    } catch (httpErr) {
      console.warn(`[RawCmdViaQueue] HTTP API failed: ${httpErr.message}, falling back to SSH`);
    }
  }
  console.log(`[RawCmdViaQueue] Using child_process SSH for: ${command.slice(0, 80)}...`);
  const { executeViaChildProcessSSH } = await import("./scan-server-executor-NMDOA3SN.js");
  const result = await executeViaChildProcessSSH(command, timeoutSeconds);
  console.log(`[RawCmdViaQueue] SSH completed: exit=${result.exitCode}, stdout=${result.stdout.length}b, stderr=${result.stderr.length}b`);
  return { ...result, executionMode: "local" };
}
async function waitForJobCompletion(jobId, config, startTime) {
  const timeoutMs = (config.timeoutSeconds || 300) * 1e3 + 3e4;
  const deadline = startTime + Math.min(timeoutMs, MAX_QUEUE_WAIT_MS);
  return new Promise((resolve) => {
    let resolved = false;
    let pollTimer = null;
    const onComplete = (result) => {
      if (result.jobId !== jobId || resolved) return;
      resolved = true;
      cleanup();
      resolve(jobResultToToolExecResult(result, config, startTime));
    };
    onJobEvent("job:completed", onComplete);
    pollTimer = setInterval(() => {
      if (resolved) return;
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
          error: "Queue job timed out"
        });
        return;
      }
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
function jobResultToToolExecResult(jobResult, config, startTime) {
  const isSuccess = jobResult.status === "completed";
  const toolResult = jobResult.results.find((r) => r.tool === config.tool) || jobResult.results[0];
  const durationMs = toolResult?.duration_ms || Date.now() - startTime;
  if (isSuccess) {
    metrics.completedViaQueue++;
    metrics.avgQueueLatencyMs = metrics.completedViaQueue === 1 ? durationMs : Math.round((metrics.avgQueueLatencyMs * (metrics.completedViaQueue - 1) + durationMs) / metrics.completedViaQueue);
  } else {
    metrics.failedViaQueue++;
  }
  const stdout = toolResult?.findings?.length ? toolResult.findings.map(
    (f) => typeof f === "string" ? f : JSON.stringify(f)
  ).join("\n") : "";
  return {
    tool: config.tool,
    command: `${config.tool} ${config.args}`,
    stdout,
    stderr: isSuccess ? "" : `Job ${jobResult.jobId} failed on worker ${jobResult.metadata.workerHost}`,
    exitCode: isSuccess ? 0 : -1,
    durationMs,
    timedOut: false,
    error: isSuccess ? void 0 : `Worker execution failed`
  };
}
function broadcastJobEvent(engagementId, data) {
  try {
    if (engagementId > 0) {
      eventHub.broadcastEngagement(engagementId, {
        type: "engagement:progress_update",
        timestamp: Date.now(),
        engagementId,
        data: { ...data, source: "job-queue-bridge" }
      });
    }
  } catch {
  }
}
async function executeToolBatchViaQueue(configs, options) {
  const concurrency = options?.concurrency || 3;
  const results = [];
  for (let i = 0; i < configs.length; i += concurrency) {
    const batch = configs.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(
        (config) => executeToolViaQueue(config, {
          engagementId: options?.engagementId,
          roeScope: options?.roeScope,
          operatorId: options?.operatorId
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
          executionMode: "local"
        });
      }
    }
  }
  return results;
}
function getBridgeStatus() {
  const hasWorkers = hasHealthyWorker("scan");
  const mode = hasWorkers ? "queue" : "local";
  return { mode, hasWorkers, metrics: getBridgeMetrics() };
}
function trackDeferredScan(engagementId, config, reason) {
  if (!deferredScans.has(engagementId)) {
    deferredScans.set(engagementId, []);
  }
  const list = deferredScans.get(engagementId);
  const exists = list.some((d) => d.config.tool === config.tool && d.config.args === config.args);
  if (!exists) {
    list.push({ config, failedAt: Date.now(), reason, retryCount: 0 });
    console.log(`${LOG} Tracked deferred scan: ${config.tool} for engagement #${engagementId} (reason: ${reason})`);
  }
}
function getDeferredScans(engagementId) {
  return deferredScans.get(engagementId) || [];
}
async function retryDeferredScans(engagementId, options) {
  const deferred = deferredScans.get(engagementId);
  if (!deferred || deferred.length === 0) {
    console.log(`${LOG} No deferred scans to retry for engagement #${engagementId}`);
    return [];
  }
  const maxRetries = options?.maxRetries ?? 1;
  const results = [];
  console.log(`${LOG} Retrying ${deferred.length} deferred scans for engagement #${engagementId}`);
  try {
    const { isDedicatedHealthy } = await import("./scan-service-url-CBKAYLTJ.js");
    const healthy = await isDedicatedHealthy();
    console.log(`${LOG} ScanForge health before deferred retry: ${healthy ? "healthy" : "unhealthy"}`);
  } catch {
  }
  for (const scan of deferred) {
    if (scan.retryCount >= maxRetries) {
      console.log(`${LOG} Skipping deferred scan ${scan.config.tool} \u2014 max retries (${maxRetries}) reached`);
      continue;
    }
    if (options?.engagementAbortSignal?.aborted) {
      console.log(`${LOG} Engagement aborted \u2014 stopping deferred scan retries`);
      break;
    }
    scan.retryCount++;
    console.log(`${LOG} Deferred retry ${scan.retryCount}/${maxRetries}: ${scan.config.tool}`);
    try {
      const result = await executeToolViaQueue(scan.config, {
        engagementId,
        engagementAbortSignal: options?.engagementAbortSignal
      });
      if (result.exitCode === 0 || result.stdout && result.stdout.length > 0) {
        results.push({ tool: scan.config.tool, result });
        console.log(`${LOG} Deferred scan ${scan.config.tool} succeeded on retry! stdout=${result.stdout?.length || 0}b`);
      } else {
        console.log(`${LOG} Deferred scan ${scan.config.tool} retry returned exit=${result.exitCode}`);
      }
    } catch (retryErr) {
      console.warn(`${LOG} Deferred scan ${scan.config.tool} retry failed: ${retryErr.message}`);
    }
  }
  const remaining = deferred.filter((d) => d.retryCount < maxRetries && !results.some((r) => r.tool === d.config.tool));
  if (remaining.length === 0) {
    deferredScans.delete(engagementId);
  } else {
    deferredScans.set(engagementId, remaining);
  }
  console.log(`${LOG} Deferred retry complete: ${results.length}/${deferred.length} succeeded`);
  return results;
}
function clearDeferredScans(engagementId) {
  deferredScans.delete(engagementId);
}
var POLL_INTERVAL_MS, MAX_QUEUE_WAIT_MS, LOG, metrics, deferredScans;
var init_job_queue_bridge = __esm({
  "server/lib/job-queue-bridge.ts"() {
    init_job_queue();
    init_ws_event_hub();
    init_safety_engine();
    POLL_INTERVAL_MS = 2e3;
    MAX_QUEUE_WAIT_MS = 9e5;
    LOG = "[JobQueueBridge]";
    metrics = {
      totalDispatched: 0,
      queuedToWorker: 0,
      fellBackToSSH: 0,
      completedViaQueue: 0,
      failedViaQueue: 0,
      timedOutViaQueue: 0,
      avgQueueLatencyMs: 0,
      avgSSHLatencyMs: 0
    };
    deferredScans = /* @__PURE__ */ new Map();
  }
});

export {
  getBridgeMetrics,
  executeToolViaQueue,
  executeRawCommandViaQueue,
  executeToolBatchViaQueue,
  getBridgeStatus,
  trackDeferredScan,
  getDeferredScans,
  retryDeferredScans,
  clearDeferredScans,
  init_job_queue_bridge
};
