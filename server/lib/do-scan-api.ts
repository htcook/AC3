/**
 * DO Scan API Client — HTTP-based scan execution via the DigitalOcean scan service
 *
 * Replaces SSH-based tool execution with HTTP API calls to the DO scan service
 * running at https://scan.aceofcloud.io. This eliminates SSH connection overhead,
 * prevents event loop blocking from SSH crypto, and provides better error handling.
 *
 * v1.1 — Added retry with exponential backoff, HTTP keep-alive, and improved
 *         timeout handling to prevent unnecessary SSH fallbacks during event loop pressure.
 *
 * Architecture:
 *   Dashboard → HTTP POST → DO Scan Service (Express) → local exec → results
 *
 * Endpoints:
 *   POST /api/scan/tool  — Execute a whitelisted tool (ScanForge discovery, nuclei, etc.)
 *   POST /api/scan/raw   — Execute a raw shell command (for piped commands)
 *   GET  /api/tools       — Get installed tool manifest
 *   GET  /health          — Health check
 */

import type { ToolExecConfig, ToolExecResult } from "./scan-server-executor";

// ─── Configuration ──────────────────────────────────────────────────────────

import { SCAN_SERVICE_URL, SCAN_API_KEY, getActiveScanUrl, LEGACY_SCAN_URL } from "./scan-service-url";

const LOG = "[DO-ScanAPI]";

/** Retry configuration */
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelayMs: 1500,  // 1.5s, 3s, 6s exponential backoff
  backoffMultiplier: 2,
};

// ─── Metrics ────────────────────────────────────────────────────────────────

interface DoApiMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  avgLatencyMs: number;
  httpFallbackToSSH: number;
  retriesPerformed: number;
}

const metrics: DoApiMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  avgLatencyMs: 0,
  httpFallbackToSSH: 0,
  retriesPerformed: 0,
};

export function getDoApiMetrics(): DoApiMetrics {
  return { ...metrics };
}

// ─── Scan State Tracker ────────────────────────────────────────────────────

/**
 * Tracks the state of active scan executions to detect stalls, freezes, and errors.
 * Provides real-time visibility into whether a scan is running, stalled, or errored.
 */
export type ScanExecutionState = "queued" | "running" | "stalled" | "completed" | "errored" | "timed_out";

export interface ActiveScanStatus {
  id: string;
  tool: string;
  target?: string;
  state: ScanExecutionState;
  startedAt: number;
  lastActivityAt: number;
  elapsedMs: number;
  timeoutMs: number;
  stallThresholdMs: number;
  error?: string;
  /** How long since last activity (ms). If > stallThresholdMs, state = "stalled" */
  silentMs: number;
}

interface TrackedScan {
  id: string;
  tool: string;
  target?: string;
  startedAt: number;
  lastActivityAt: number;
  timeoutMs: number;
  state: ScanExecutionState;
  error?: string;
  completedAt?: number;
}

/** Default stall threshold: 90 seconds of no activity = stalled */
const STALL_THRESHOLD_MS = 90_000;

/** Keep completed/errored scans in history for 5 minutes */
const HISTORY_RETENTION_MS = 5 * 60 * 1000;

const _activeScans = new Map<string, TrackedScan>();
let _scanCounter = 0;

/** Register a new scan execution for tracking */
function trackScanStart(tool: string, timeoutMs: number, target?: string): string {
  const id = `scan_${++_scanCounter}_${Date.now()}`;
  const now = Date.now();
  _activeScans.set(id, {
    id,
    tool,
    target,
    startedAt: now,
    lastActivityAt: now,
    timeoutMs,
    state: "running",
  });
  // Prune old completed entries
  pruneHistory();
  return id;
}

/** Update the last activity timestamp (call periodically to indicate scan is alive) */
function trackScanActivity(id: string): void {
  const scan = _activeScans.get(id);
  if (scan && (scan.state === "running" || scan.state === "stalled")) {
    scan.lastActivityAt = Date.now();
    scan.state = "running"; // Reset from stalled if activity resumes
  }
}

/** Mark a scan as completed */
function trackScanComplete(id: string): void {
  const scan = _activeScans.get(id);
  if (scan) {
    scan.state = "completed";
    scan.completedAt = Date.now();
  }
}

/** Mark a scan as errored */
function trackScanError(id: string, error: string): void {
  const scan = _activeScans.get(id);
  if (scan) {
    scan.state = "errored";
    scan.error = error;
    scan.completedAt = Date.now();
  }
}

/** Mark a scan as timed out */
function trackScanTimeout(id: string): void {
  const scan = _activeScans.get(id);
  if (scan) {
    scan.state = "timed_out";
    scan.error = `Timed out after ${Math.round(scan.timeoutMs / 1000)}s`;
    scan.completedAt = Date.now();
  }
}

/** Prune completed/errored scans older than retention period */
function pruneHistory(): void {
  const cutoff = Date.now() - HISTORY_RETENTION_MS;
  for (const [id, scan] of _activeScans) {
    if (scan.completedAt && scan.completedAt < cutoff) {
      _activeScans.delete(id);
    }
  }
}

/**
 * Get the current status of all tracked scans.
 * Automatically detects stalled scans (no activity for > STALL_THRESHOLD_MS).
 */
export function getActiveScanStatuses(): ActiveScanStatus[] {
  const now = Date.now();
  const statuses: ActiveScanStatus[] = [];

  for (const scan of _activeScans.values()) {
    const silentMs = now - scan.lastActivityAt;
    const elapsedMs = now - scan.startedAt;

    // Auto-detect stalls for running scans
    if (scan.state === "running" && silentMs > STALL_THRESHOLD_MS) {
      scan.state = "stalled";
    }

    statuses.push({
      id: scan.id,
      tool: scan.tool,
      target: scan.target,
      state: scan.state,
      startedAt: scan.startedAt,
      lastActivityAt: scan.lastActivityAt,
      elapsedMs,
      timeoutMs: scan.timeoutMs,
      stallThresholdMs: STALL_THRESHOLD_MS,
      silentMs,
      error: scan.error,
    });
  }

  return statuses;
}

/**
 * Get a summary of scan execution health.
 * Useful for the engagement ops page to show real-time scan status.
 */
export function getScanExecutionSummary(): {
  running: number;
  stalled: number;
  errored: number;
  completed: number;
  timedOut: number;
  total: number;
  stalledScans: Array<{ tool: string; target?: string; silentSeconds: number }>;
} {
  const statuses = getActiveScanStatuses();
  const summary = {
    running: 0,
    stalled: 0,
    errored: 0,
    completed: 0,
    timedOut: 0,
    total: statuses.length,
    stalledScans: [] as Array<{ tool: string; target?: string; silentSeconds: number }>,
  };

  for (const s of statuses) {
    summary[s.state === "timed_out" ? "timedOut" : s.state]++;
    if (s.state === "stalled") {
      summary.stalledScans.push({
        tool: s.tool,
        target: s.target,
        silentSeconds: Math.round(s.silentMs / 1000),
      });
    }
  }

  return summary;
}

// ─── Retry Helper ───────────────────────────────────────────────────────────

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  timeoutMs: number,
  label: string,
  engagementAbortSignal?: AbortSignal
): Promise<Response> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
    // Check if the engagement has been aborted (e.g., server shutdown)
    if (engagementAbortSignal?.aborted) {
      throw new DOMException(
        `Engagement aborted before ${label} attempt ${attempt}`,
        "AbortError"
      );
    }

    if (attempt > 0) {
      const delay = RETRY_CONFIG.baseDelayMs * Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1);
      console.log(`${LOG} Retry ${attempt}/${RETRY_CONFIG.maxRetries} for ${label} after ${delay}ms`);
      await sleep(delay);
      metrics.retriesPerformed++;
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      // If the engagement abort signal fires, also abort this request
      const onEngagementAbort = () => controller.abort();
      engagementAbortSignal?.addEventListener("abort", onEngagementAbort, { once: true });

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });

        clearTimeout(timeout);
        engagementAbortSignal?.removeEventListener("abort", onEngagementAbort);
        return response;
      } catch (err: any) {
        clearTimeout(timeout);
        engagementAbortSignal?.removeEventListener("abort", onEngagementAbort);
        throw err;
      }
    } catch (err: any) {
      lastError = err;

      // If aborted by engagement signal, don't retry — propagate immediately
      if (engagementAbortSignal?.aborted) {
        throw new DOMException(
          `Engagement aborted during ${label}: ${err.message}`,
          "AbortError"
        );
      }

      const isRetryable = err.name === "AbortError" ||
        err.message?.includes("fetch failed") ||
        err.message?.includes("ECONNRESET") ||
        err.message?.includes("ECONNREFUSED") ||
        err.message?.includes("UND_ERR_CONNECT_TIMEOUT") ||
        err.message?.includes("This operation was aborted") ||
        err.message?.includes("HTTP 5") || // Retry on 5xx server errors
        err.message?.includes("ETIMEDOUT") ||
        err.message?.includes("ENOTFOUND");

      if (!isRetryable || attempt === RETRY_CONFIG.maxRetries) {
        break;
      }
    }
  }

  throw lastError || new Error("All retries exhausted");
}

// ─── Core: HTTP-based tool execution ────────────────────────────────────────

/**
 * Execute a tool via the DO scan service HTTP API.
 * Drop-in replacement for executeTool() from scan-server-executor.ts.
 *
 * v1.2: Async submit + poll mode for long-running scans (nuclei, ZAP, etc.).
 *       Submits with `async: true`, receives a jobId, then polls until complete.
 *       Eliminates the 6-minute hard cap that caused SSH fallback storms.
 *       Falls back to synchronous mode if the bridge doesn't support async.
 */
export async function executeToolViaHttp(
  config: ToolExecConfig,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();
  metrics.totalRequests++;

  // ── Scan State Tracking ──────────────────────────────────────────────────
  const isLongRunningTool = /^(nuclei|zap|sqlmap|nikto|gobuster|ffuf|wfuzz|masscan|testssl|burp)$/i.test(tool)
    || timeoutSeconds > 300;
  const trackingTimeoutMs = isLongRunningTool
    ? Math.min((timeoutSeconds + 120) * 1000, 900_000)
    : Math.min((timeoutSeconds + 60) * 1000, 360_000);
  const trackId = trackScanStart(tool, trackingTimeoutMs, config.target);

  // Early exit if engagement already aborted
  if (engagementAbortSignal?.aborted) {
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: "Engagement aborted before execution",
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: "Engagement aborted",
    };
  }

  try {
    // Use dynamic URL with health-check failover (dedicated → legacy)
    const activeUrl = await getActiveScanUrl();
    console.log(`${LOG} Executing tool: ${tool} ${(args || "").slice(0, 80)}... via ${activeUrl}`);

    // ── Async Submit + Poll (v1.2) ──────────────────────────────────────────
    // Uses the isLongRunningTool flag from the tracking section above.
    // Extended timeout (up to 15 min) for long-running tools; original 6-min cap for short tools.
    // When the ScanBridge is upgraded to support async mode, it will return
    // { jobId, status: "accepted" } within seconds, and we'll switch to the poll path.
    const submitTimeoutMs = isLongRunningTool
      ? Math.min((timeoutSeconds + 120) * 1000, 900_000) // up to 15 min for nuclei/ZAP/etc.
      : Math.min((timeoutSeconds + 60) * 1000, 360_000); // short tools: original 6-min cap

    const response = await fetchWithRetry(
      `${activeUrl}/api/scan/tool`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY,
        },
        body: JSON.stringify({
          tool,
          args: args || "",
          target: config.target,
          timeoutSeconds,
          engagementId: config.engagementId,
          sudo,
          async: isLongRunningTool, // Request async execution from bridge
        }),
      },
      submitTimeoutMs,
      `${tool} ${(args || "").slice(0, 40)}`,
      engagementAbortSignal
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json() as any;

    // ── Async mode: bridge returned a jobId → poll for completion ──────────
    if (data.jobId && data.status === "accepted") {
      console.log(`${LOG} Tool ${tool} accepted async (jobId=${data.jobId}). Polling for results...`);
      trackScanActivity(trackId); // Bridge acknowledged the job
      const result = await pollForJobResult(activeUrl, data.jobId, tool, args || "", timeoutSeconds, startTime, engagementAbortSignal);
      if (result.exitCode === 0) trackScanComplete(trackId);
      else if (result.timedOut) trackScanTimeout(trackId);
      else trackScanError(trackId, result.error || `exit code ${result.exitCode}`);
      return result;
    }

    // ── Detect response format: flat (scan bridge) vs wrapped (legacy) ─────
    // Flat format: { stdout, stderr, exitCode, command, durationMs, timedOut }
    // Wrapped format: { success: boolean, result: { stdout, stderr, exitCode, ... } }
    const isFlatResponse = 'exitCode' in data && 'stdout' in data && !('success' in data);

    if (isFlatResponse) {
      // Handle flat response from scan bridge directly
      const durationMs = data.durationMs || (Date.now() - startTime);
      metrics.successfulRequests++;
      updateAvgLatency(durationMs);
      trackScanComplete(trackId);
      console.log(`${LOG} Tool ${tool} completed via HTTP (flat): exit=${data.exitCode} stdout=${(data.stdout || "").length}b in ${durationMs}ms`);
      return {
        tool,
        command: `${tool} ${args}`,
        stdout: (data.stdout || "").slice(0, 500_000),
        stderr: (data.stderr || "").slice(0, 50_000),
        exitCode: data.exitCode ?? 0,
        durationMs,
        timedOut: data.timedOut || false,
      };
    }

    // ── Wrapped format: bridge returned { success, result } ────────────────
    if (!data.success) {
      trackScanError(trackId, data.error || "Scan service returned failure");
      throw new Error(data.error || "Scan service returned failure");
    }

    const durationMs = Date.now() - startTime;
    metrics.successfulRequests++;
    updateAvgLatency(durationMs);
    trackScanComplete(trackId);

    console.log(`${LOG} Tool ${tool} completed via HTTP (sync): exit=${data.result!.exitCode} stdout=${data.result!.stdout?.length || 0}b in ${durationMs}ms`);

    return {
      tool,
      command: `${tool} ${args}`,
      stdout: (data.result!.stdout || "").slice(0, 500_000),
      stderr: (data.result!.stderr || "").slice(0, 50_000),
      exitCode: data.result!.exitCode ?? 0,
      durationMs,
      timedOut: data.result!.timedOut || false,
    };
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    // Determine if this was a timeout (stall/freeze) or a connection error
    const isTimeout = err.name === "AbortError" || err.message?.includes("aborted");
    if (isTimeout) {
      trackScanTimeout(trackId);
    } else {
      trackScanError(trackId, err.message);
    }
    metrics.failedRequests++;

    console.error(`${LOG} Tool ${tool} failed after retries: ${err.message} (${durationMs}ms)`);

    // Fallback to SSH if HTTP fails — use child process SSH (non-blocking)
    return fallbackToSSH(config, err, startTime);
  }
}

// ─── Async Job Polling ─────────────────────────────────────────────────────

/** Poll interval for async job status checks */
const ASYNC_POLL_INTERVAL_MS = 5_000; // 5 seconds

/** Maximum poll duration (overrides per-tool timeout if longer) */
const ASYNC_MAX_POLL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Poll the ScanBridge for async job completion.
 * Returns a ToolExecResult when the job completes, fails, or times out.
 */
async function pollForJobResult(
  baseUrl: string,
  jobId: string,
  tool: string,
  args: string,
  timeoutSeconds: number,
  startTime: number,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  // Use the greater of: tool timeout + 2 min buffer, or 30 min max
  const pollDeadline = startTime + Math.min((timeoutSeconds + 120) * 1000, ASYNC_MAX_POLL_MS);

  while (Date.now() < pollDeadline) {
    // Check if engagement was aborted
    if (engagementAbortSignal?.aborted) {
      console.warn(`${LOG} Engagement aborted while polling job ${jobId}`);
      // Try to cancel the remote job
      try {
        await fetch(`${baseUrl}/api/scan/jobs/${jobId}/cancel`, {
          method: "POST",
          headers: { "X-Scan-Key": SCAN_API_KEY },
        });
      } catch { /* best effort */ }
      return {
        tool,
        command: `${tool} ${args}`,
        stdout: "",
        stderr: "Engagement aborted during async execution",
        exitCode: -1,
        durationMs: Date.now() - startTime,
        timedOut: false,
        error: "Engagement aborted",
      };
    }

    await sleep(ASYNC_POLL_INTERVAL_MS);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);

      const pollResp = await fetch(`${baseUrl}/api/scan/jobs/${jobId}`, {
        headers: { "X-Scan-Key": SCAN_API_KEY },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!pollResp.ok) {
        // Non-200 from poll endpoint — might be 404 if bridge doesn't support it
        const errText = await pollResp.text().catch(() => "");
        if (pollResp.status === 404) {
          // Bridge doesn't support async job polling — fall back to waiting
          console.warn(`${LOG} Bridge does not support /api/scan/jobs/${jobId} (404). Falling back to extended sync wait.`);
          return await fallbackExtendedSyncWait(baseUrl, tool, args, timeoutSeconds, startTime, engagementAbortSignal);
        }
        console.warn(`${LOG} Poll error for job ${jobId}: HTTP ${pollResp.status} ${errText}`);
        continue; // Retry on transient errors
      }

      const jobData = await pollResp.json() as {
        status: "running" | "completed" | "failed" | "queued" | "cancelled";
        progress?: number;
        result?: ToolExecResult;
        error?: string;
      };

      if (jobData.status === "completed" && jobData.result) {
        const durationMs = Date.now() - startTime;
        metrics.successfulRequests++;
        updateAvgLatency(durationMs);
        console.log(`${LOG} Tool ${tool} completed async (jobId=${jobId}): exit=${jobData.result.exitCode} stdout=${jobData.result.stdout?.length || 0}b in ${durationMs}ms`);
        return {
          tool,
          command: `${tool} ${args}`,
          stdout: (jobData.result.stdout || "").slice(0, 500_000),
          stderr: (jobData.result.stderr || "").slice(0, 50_000),
          exitCode: jobData.result.exitCode ?? 0,
          durationMs,
          timedOut: jobData.result.timedOut || false,
        };
      }

      if (jobData.status === "failed") {
        const durationMs = Date.now() - startTime;
        console.error(`${LOG} Tool ${tool} failed async (jobId=${jobId}): ${jobData.error}`);
        return {
          tool,
          command: `${tool} ${args}`,
          stdout: jobData.result?.stdout || "",
          stderr: jobData.result?.stderr || jobData.error || "Job failed on scan server",
          exitCode: jobData.result?.exitCode ?? -1,
          durationMs,
          timedOut: false,
          error: jobData.error || "Async job failed",
        };
      }

      if (jobData.status === "cancelled") {
        return {
          tool,
          command: `${tool} ${args}`,
          stdout: "",
          stderr: "Job was cancelled on the scan server",
          exitCode: -1,
          durationMs: Date.now() - startTime,
          timedOut: false,
          error: "Job cancelled",
        };
      }

      // Still running or queued — log progress and continue polling
      if (jobData.progress !== undefined && jobData.progress > 0) {
        console.log(`${LOG} Job ${jobId} progress: ${jobData.progress}% (${tool})`);
      }
    } catch (pollErr: any) {
      // Transient network error during poll — continue polling
      console.warn(`${LOG} Poll network error for job ${jobId}: ${pollErr.message}`);
    }
  }

  // Timed out waiting for async job
  const durationMs = Date.now() - startTime;
  metrics.failedRequests++;
  console.error(`${LOG} Tool ${tool} async poll timed out after ${durationMs}ms (jobId=${jobId})`);

  // Try to cancel the stale job
  try {
    await fetch(`${baseUrl}/api/scan/jobs/${jobId}/cancel`, {
      method: "POST",
      headers: { "X-Scan-Key": SCAN_API_KEY },
    });
  } catch { /* best effort */ }

  return {
    tool,
    command: `${tool} ${args}`,
    stdout: "",
    stderr: `Async job ${jobId} timed out after ${Math.round(durationMs / 1000)}s`,
    exitCode: -1,
    durationMs,
    timedOut: true,
    error: "Async job poll timeout",
  };
}

/**
 * Fallback for when the bridge doesn't support the /api/scan/jobs/:id endpoint.
 * Retries the original synchronous request with a much longer timeout (up to 15 min).
 * This handles the case where the bridge is an older version without async support.
 */
async function fallbackExtendedSyncWait(
  baseUrl: string,
  tool: string,
  args: string,
  timeoutSeconds: number,
  startTime: number,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  console.log(`${LOG} Extended sync wait for ${tool} (up to ${timeoutSeconds}s + 120s buffer)`);

  // Allow up to timeoutSeconds + 2 min buffer, max 15 min
  const extendedTimeoutMs = Math.min((timeoutSeconds + 120) * 1000, 900_000);

  try {
    const response = await fetchWithRetry(
      `${baseUrl}/api/scan/tool`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY,
        },
        body: JSON.stringify({
          tool,
          args,
          timeoutSeconds,
        }),
      },
      extendedTimeoutMs,
      `${tool} extended-sync`,
      engagementAbortSignal
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json() as { success: boolean; result: ToolExecResult; error?: string };
    if (!data.success) throw new Error(data.error || "Extended sync failed");

    const durationMs = Date.now() - startTime;
    metrics.successfulRequests++;
    updateAvgLatency(durationMs);

    return {
      tool,
      command: `${tool} ${args}`,
      stdout: (result.stdout || "").slice(0, 500_000),
      stderr: (result.stderr || "").slice(0, 50_000),
      exitCode: result.exitCode ?? 0,
      durationMs,
      timedOut: result.timedOut || false,
    };
  } catch (err: any) {
    // Extended sync also failed — this will trigger SSH fallback upstream
    throw new Error(`Extended sync wait failed for ${tool}: ${err.message}`);
  }
}

/**
 * Execute a raw command via the DO scan service HTTP API.
 * Drop-in replacement for executeRawCommand() / executeViaChildProcessSSH().
 * Used for piped commands like "echo URL | httpx ..." or "echo URL | nuclei ...".
 *
 * v1.2: Async submit + poll for long-running raw commands (nuclei piped, etc.).
 *       Removes the 6-min hard cap for commands that take longer.
 */
export async function executeRawCommandViaHttp(
  command: string,
  timeoutSeconds: number = 300,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  const startTime = Date.now();
  metrics.totalRequests++;

  // ── Scan State Tracking for raw commands ──────────────────────────────────
  const toolName = (command.match(/\b(nuclei|zap|sqlmap|nikto|gobuster|ffuf|masscan|testssl|nmap|httpx)\b/i)?.[1] || "raw").toLowerCase();
  const isLongRunning = timeoutSeconds > 300
    || /nuclei|sqlmap|nikto|gobuster|ffuf|masscan|testssl/i.test(command);
  const trackingTimeoutMs = isLongRunning
    ? Math.min((timeoutSeconds + 120) * 1000, 900_000)
    : Math.min((timeoutSeconds + 60) * 1000, 360_000);
  const trackId = trackScanStart(toolName, trackingTimeoutMs, command.slice(0, 60));

  // Early exit if engagement already aborted
  if (engagementAbortSignal?.aborted) {
    trackScanError(trackId, "Engagement aborted before execution");
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: "Engagement aborted before execution",
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: "Engagement aborted",
    };
  }

  try {
    // Use dynamic URL with health-check failover (dedicated → legacy)
    const activeUrl = await getActiveScanUrl();
    console.log(`${LOG} Raw command: ${command.slice(0, 100)}... via ${activeUrl}`);

    // Timeout: extended for long-running commands (up to 15 min), original cap for short ones
    const submitTimeoutMs = isLongRunning
      ? Math.min((timeoutSeconds + 120) * 1000, 900_000) // up to 15 min
      : Math.min((timeoutSeconds + 60) * 1000, 360_000);

    const response = await fetchWithRetry(
      `${activeUrl}/api/scan/raw`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY,
        },
        body: JSON.stringify({
          command,
          timeoutSeconds,
          async: isLongRunning, // Request async execution from bridge
        }),
      },
      submitTimeoutMs,
      `raw: ${command.slice(0, 40)}`,
      engagementAbortSignal
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      console.error(`${LOG} Raw command HTTP ${response.status}: ${errorText.slice(0, 300)} | cmd=${command.slice(0, 60)}`);
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json() as any;

    // Async mode: bridge returned a jobId → poll for completion
    if (data.jobId && data.status === "accepted") {
      console.log(`${LOG} Raw command accepted async (jobId=${data.jobId}). Polling...`);
      trackScanActivity(trackId);
      const result = await pollForJobResult(activeUrl, data.jobId, "raw", command.slice(0, 100), timeoutSeconds, startTime, engagementAbortSignal);
      if (result.exitCode === 0) trackScanComplete(trackId);
      else if (result.timedOut) trackScanTimeout(trackId);
      else trackScanError(trackId, result.error || `exit code ${result.exitCode}`);
      return result;
    }

    // Detect response format: flat (scan bridge) vs wrapped (legacy)
    const isFlatResponse = 'exitCode' in data && 'stdout' in data && !('success' in data);

    if (isFlatResponse) {
      // Handle flat response from scan bridge directly
      const durationMs = data.durationMs || (Date.now() - startTime);
      metrics.successfulRequests++;
      updateAvgLatency(durationMs);
      trackScanComplete(trackId);
      console.log(`${LOG} Raw command completed via HTTP (flat): exit=${data.exitCode} stdout=${(data.stdout || "").length}b in ${durationMs}ms`);
      return {
        tool: "raw",
        command,
        stdout: (data.stdout || "").slice(0, 500_000),
        stderr: (data.stderr || "").slice(0, 50_000),
        exitCode: data.exitCode ?? 0,
        durationMs,
        timedOut: data.timedOut || false,
      };
    }

    // Wrapped format: { success, result }
    if (!data.success) {
      trackScanError(trackId, data.error || "Scan service returned failure");
      throw new Error(data.error || "Scan service returned failure");
    }

    const durationMs = Date.now() - startTime;
    metrics.successfulRequests++;
    updateAvgLatency(durationMs);
    trackScanComplete(trackId);

    console.log(`${LOG} Raw command completed via HTTP: exit=${data.result!.exitCode} stdout=${data.result!.stdout?.length || 0}b in ${durationMs}ms`);

    return {
      tool: "raw",
      command,
      stdout: (data.result!.stdout || "").slice(0, 500_000),
      stderr: (data.result!.stderr || "").slice(0, 50_000),
      exitCode: data.result!.exitCode ?? 0,
      durationMs,
      timedOut: result.timedOut || false,
    };
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    const isTimeout = err.name === "AbortError" || err.message?.includes("aborted");
    if (isTimeout) {
      trackScanTimeout(trackId);
    } else {
      trackScanError(trackId, err.message);
    }
    metrics.failedRequests++;

    console.error(`${LOG} Raw command HTTP bridge FAILED: err=${err.message} duration=${durationMs}ms cmd=${command.slice(0, 80)}`);
    console.error(`${LOG} HTTP bridge failure details: name=${err.name} cause=${err.cause || 'none'} stack=${(err.stack || '').split('\n')[1]?.trim() || 'none'}`);

    // Fallback to SSH — use child process SSH (non-blocking)
    return fallbackToSSHRaw(command, timeoutSeconds, startTime);
  }
}

/**
 * Check the DO scan service health via HTTP.
 */
export async function checkDoScanServiceHealth(): Promise<{
  healthy: boolean;
  uptime?: number;
  memory?: Record<string, number>;
  error?: string;
}> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const activeUrl = await getActiveScanUrl();
    const response = await fetch(`${activeUrl}/health`, {
      headers: { "X-Scan-Key": SCAN_API_KEY },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json() as any;
    return {
      healthy: data.status === "ok",
      uptime: data.uptime,
      memory: data.memory,
    };
  } catch (err: any) {
    return { healthy: false, error: err.message };
  }
}

/**
 * Get installed tools from the DO scan service.
 */
export async function getDoScanTools(): Promise<Record<string, { installed: boolean; path?: string }>> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(`${SCAN_SERVICE_URL}/api/tools`, {
      headers: { "X-Scan-Key": SCAN_API_KEY },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json() as any;
    return data.tools || {};
  } catch {
    return {};
  }
}

// ─── SSH Fallback ───────────────────────────────────────────────────────────

async function fallbackToSSH(
  config: ToolExecConfig,
  originalError: Error,
  startTime: number
): Promise<ToolExecResult> {
  metrics.httpFallbackToSSH++;

  // In deployed environments (DO App Platform, containers), ssh binary is not available.
  // Check SCAN_SERVER_SSH_KEY existence as a proxy for SSH capability.
  const sshKeyConfigured = !!(process.env.SCAN_SERVER_SSH_KEY && process.env.SCAN_SERVER_HOST);
  if (!sshKeyConfigured) {
    console.warn(`${LOG} SSH fallback skipped for ${config.tool} — no SSH key configured (deployed env). HTTP error: ${originalError.message}`);
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: "",
      stderr: `HTTP execution failed: ${originalError.message}. SSH fallback unavailable (no SSH key configured).`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: `HTTP execution failed, SSH fallback unavailable`,
    };
  }

  console.log(`${LOG} Falling back to SSH for ${config.tool} (HTTP error: ${originalError.message})`);

  try {
    // Use child process SSH (non-blocking) instead of recursive executeTool
    const { executeViaChildProcessSSH } = await import("./scan-server-executor");
    const cmd = config.sudo
      ? `sudo ${config.tool} ${config.args || ""}`
      : `${config.tool} ${config.args || ""}`;
    const result = await executeViaChildProcessSSH(cmd, config.timeoutSeconds || 300);
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: result.stdout.slice(0, 500_000),
      stderr: result.stderr.slice(0, 50_000),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false,
    };
  } catch (sshErr: any) {
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: "",
      stderr: `HTTP failed: ${originalError.message}; SSH fallback also failed: ${sshErr.message}`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: `Both HTTP and SSH execution failed`,
    };
  }
}

async function fallbackToSSHRaw(
  command: string,
  timeoutSeconds: number,
  startTime: number
): Promise<ToolExecResult> {
  metrics.httpFallbackToSSH++;

  // In deployed environments, ssh binary is not available.
  const sshKeyConfigured = !!(process.env.SCAN_SERVER_SSH_KEY && process.env.SCAN_SERVER_HOST);
  if (!sshKeyConfigured) {
    console.warn(`${LOG} SSH fallback skipped for raw command — no SSH key configured (deployed env)`);
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: `HTTP execution failed. SSH fallback unavailable (no SSH key configured).`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: "HTTP execution failed, SSH fallback unavailable",
    };
  }

  console.log(`${LOG} Falling back to SSH for raw command`);

  try {
    const { executeViaChildProcessSSH } = await import("./scan-server-executor");
    const result = await executeViaChildProcessSSH(command, timeoutSeconds);
    return {
      tool: "raw",
      command,
      stdout: result.stdout.slice(0, 500_000),
      stderr: result.stderr.slice(0, 50_000),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false,
    };
  } catch (sshErr: any) {
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: `HTTP failed; SSH fallback also failed: ${sshErr.message}`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: "Both HTTP and SSH execution failed",
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function updateAvgLatency(latencyMs: number) {
  const n = metrics.successfulRequests;
  metrics.avgLatencyMs = n === 1
    ? latencyMs
    : Math.round((metrics.avgLatencyMs * (n - 1) + latencyMs) / n);
}
