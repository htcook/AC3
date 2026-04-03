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
        err.message?.includes("This operation was aborted");

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
 * v1.1: Added retry with exponential backoff and +60s timeout buffer.
 */
export async function executeToolViaHttp(
  config: ToolExecConfig,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();
  metrics.totalRequests++;

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

    const timeoutMs = (timeoutSeconds + 60) * 1000; // +60s buffer (was +30s)

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
        }),
      },
      timeoutMs,
      `${tool} ${(args || "").slice(0, 40)}`,
      engagementAbortSignal
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json() as {
      success: boolean;
      result: ToolExecResult;
      error?: string;
    };

    if (!data.success) {
      throw new Error(data.error || "Scan service returned failure");
    }

    const durationMs = Date.now() - startTime;
    metrics.successfulRequests++;
    updateAvgLatency(durationMs);

    console.log(`${LOG} Tool ${tool} completed via HTTP: exit=${data.result.exitCode} stdout=${data.result.stdout?.length || 0}b in ${durationMs}ms`);

    return {
      tool,
      command: `${tool} ${args}`,
      stdout: (data.result.stdout || "").slice(0, 500_000),
      stderr: (data.result.stderr || "").slice(0, 50_000),
      exitCode: data.result.exitCode ?? 0,
      durationMs,
      timedOut: data.result.timedOut || false,
    };
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    metrics.failedRequests++;

    console.error(`${LOG} Tool ${tool} failed after retries: ${err.message} (${durationMs}ms)`);

    // Fallback to SSH if HTTP fails — use child process SSH (non-blocking)
    return fallbackToSSH(config, err, startTime);
  }
}

/**
 * Execute a raw command via the DO scan service HTTP API.
 * Drop-in replacement for executeRawCommand() / executeViaChildProcessSSH().
 * Used for piped commands like "echo URL | httpx ..." or "echo URL | nuclei ...".
 *
 * v1.1: Added retry with exponential backoff.
 */
export async function executeRawCommandViaHttp(
  command: string,
  timeoutSeconds: number = 300,
  engagementAbortSignal?: AbortSignal
): Promise<ToolExecResult> {
  const startTime = Date.now();
  metrics.totalRequests++;

  // Early exit if engagement already aborted
  if (engagementAbortSignal?.aborted) {
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

    const timeoutMs = (timeoutSeconds + 60) * 1000;

    const response = await fetchWithRetry(
      `${activeUrl}/api/scan/raw`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY,
        },
        body: JSON.stringify({ command, timeoutSeconds }),
      },
      timeoutMs,
      `raw: ${command.slice(0, 40)}`,
      engagementAbortSignal
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json() as {
      success: boolean;
      result: { stdout: string; stderr?: string; exitCode: number };
      error?: string;
    };

    if (!data.success) {
      throw new Error(data.error || "Scan service returned failure");
    }

    const durationMs = Date.now() - startTime;
    metrics.successfulRequests++;
    updateAvgLatency(durationMs);

    console.log(`${LOG} Raw command completed via HTTP: exit=${data.result.exitCode} stdout=${data.result.stdout?.length || 0}b in ${durationMs}ms`);

    return {
      tool: "raw",
      command,
      stdout: (data.result.stdout || "").slice(0, 500_000),
      stderr: (data.result.stderr || "").slice(0, 50_000),
      exitCode: data.result.exitCode ?? 0,
      durationMs,
      timedOut: false,
    };
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    metrics.failedRequests++;

    console.error(`${LOG} Raw command failed after retries: ${err.message} (${durationMs}ms), falling back to SSH`);

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
