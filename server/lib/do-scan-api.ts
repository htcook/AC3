/**
 * DO Scan API Client — HTTP-based scan execution via the DigitalOcean scan service
 *
 * Replaces SSH-based tool execution with HTTP API calls to the DO scan service
 * running at http://159.223.152.190. This eliminates SSH connection overhead,
 * prevents event loop blocking from SSH crypto, and provides better error handling.
 *
 * Architecture:
 *   Dashboard → HTTP POST → DO Scan Service (Express) → local exec → results
 *
 * Endpoints:
 *   POST /api/scan/tool  — Execute a whitelisted tool (nmap, nuclei, etc.)
 *   POST /api/scan/raw   — Execute a raw shell command (for piped commands)
 *   GET  /api/tools       — Get installed tool manifest
 *   GET  /health          — Health check
 */

import type { ToolExecConfig, ToolExecResult } from "./scan-server-executor";

// ─── Configuration ──────────────────────────────────────────────────────────

const SCAN_SERVICE_URL = process.env.SCAN_SERVER_HOST
  ? `http://${process.env.SCAN_SERVER_HOST}`
  : "http://159.223.152.190";

const SCAN_API_KEY = process.env.CALDERA_API_KEY || "ADMIN123";

const LOG = "[DO-ScanAPI]";

// ─── Metrics ────────────────────────────────────────────────────────────────

interface DoApiMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  avgLatencyMs: number;
  httpFallbackToSSH: number;
}

const metrics: DoApiMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  avgLatencyMs: 0,
  httpFallbackToSSH: 0,
};

export function getDoApiMetrics(): DoApiMetrics {
  return { ...metrics };
}

// ─── Core: HTTP-based tool execution ────────────────────────────────────────

/**
 * Execute a tool via the DO scan service HTTP API.
 * Drop-in replacement for executeTool() from scan-server-executor.ts.
 */
export async function executeToolViaHttp(
  config: ToolExecConfig
): Promise<ToolExecResult> {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();
  metrics.totalRequests++;

  try {
    console.log(`${LOG} Executing tool: ${tool} ${(args || "").slice(0, 80)}...`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), (timeoutSeconds + 30) * 1000);

    const response = await fetch(`${SCAN_SERVICE_URL}/api/scan/tool`, {
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
      signal: controller.signal,
    });

    clearTimeout(timeout);

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

    console.log(`${LOG} Tool ${tool} completed: exit=${data.result.exitCode} stdout=${data.result.stdout?.length || 0}b in ${durationMs}ms`);

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
    const timedOut = err.name === "AbortError" || err.message?.includes("timed out");

    console.error(`${LOG} Tool ${tool} failed: ${err.message} (${durationMs}ms)`);

    // Fallback to SSH if HTTP fails
    return fallbackToSSH(config, err, startTime);
  }
}

/**
 * Execute a raw command via the DO scan service HTTP API.
 * Drop-in replacement for executeRawCommand() / executeViaChildProcessSSH().
 * Used for piped commands like "echo URL | httpx ..." or "echo URL | nuclei ...".
 */
export async function executeRawCommandViaHttp(
  command: string,
  timeoutSeconds: number = 300
): Promise<ToolExecResult> {
  const startTime = Date.now();
  metrics.totalRequests++;

  try {
    console.log(`${LOG} Raw command: ${command.slice(0, 100)}...`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), (timeoutSeconds + 30) * 1000);

    const response = await fetch(`${SCAN_SERVICE_URL}/api/scan/raw`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Scan-Key": SCAN_API_KEY,
      },
      body: JSON.stringify({ command, timeoutSeconds }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

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

    console.log(`${LOG} Raw command completed: exit=${data.result.exitCode} stdout=${data.result.stdout?.length || 0}b in ${durationMs}ms`);

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

    console.error(`${LOG} Raw command failed: ${err.message} (${durationMs}ms), falling back to SSH`);

    // Fallback to SSH
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

    const response = await fetch(`${SCAN_SERVICE_URL}/health`, {
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
  console.log(`${LOG} Falling back to SSH for ${config.tool} (HTTP error: ${originalError.message})`);

  try {
    const { executeTool } = await import("./scan-server-executor");
    return await executeTool(config);
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
