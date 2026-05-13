import {
  SCAN_API_KEY,
  SCAN_SERVICE_URL,
  getActiveScanUrl,
  init_scan_service_url
} from "./chunk-JPJQZXKW.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/do-scan-api.ts
function getDoApiMetrics() {
  return { ...metrics };
}
async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function fetchWithRetry(url, options, timeoutMs, label, engagementAbortSignal) {
  let lastError = null;
  for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
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
      const onEngagementAbort = () => controller.abort();
      engagementAbortSignal?.addEventListener("abort", onEngagementAbort, { once: true });
      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal
        });
        clearTimeout(timeout);
        engagementAbortSignal?.removeEventListener("abort", onEngagementAbort);
        return response;
      } catch (err) {
        clearTimeout(timeout);
        engagementAbortSignal?.removeEventListener("abort", onEngagementAbort);
        throw err;
      }
    } catch (err) {
      lastError = err;
      if (engagementAbortSignal?.aborted) {
        throw new DOMException(
          `Engagement aborted during ${label}: ${err.message}`,
          "AbortError"
        );
      }
      const isRetryable = err.name === "AbortError" || err.message?.includes("fetch failed") || err.message?.includes("ECONNRESET") || err.message?.includes("ECONNREFUSED") || err.message?.includes("UND_ERR_CONNECT_TIMEOUT") || err.message?.includes("This operation was aborted");
      if (!isRetryable || attempt === RETRY_CONFIG.maxRetries) {
        break;
      }
    }
  }
  throw lastError || new Error("All retries exhausted");
}
async function executeToolViaHttp(config, engagementAbortSignal) {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();
  metrics.totalRequests++;
  if (engagementAbortSignal?.aborted) {
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: "Engagement aborted before execution",
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: "Engagement aborted"
    };
  }
  try {
    const activeUrl = await getActiveScanUrl();
    console.log(`${LOG} Executing tool: ${tool} ${(args || "").slice(0, 80)}... via ${activeUrl}`);
    const timeoutMs = Math.min((timeoutSeconds + 60) * 1e3, 36e4);
    const response = await fetchWithRetry(
      `${activeUrl}/api/scan/tool`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY
        },
        body: JSON.stringify({
          tool,
          args: args || "",
          target: config.target,
          timeoutSeconds,
          engagementId: config.engagementId,
          sudo
        })
      },
      timeoutMs,
      `${tool} ${(args || "").slice(0, 40)}`,
      engagementAbortSignal
    );
    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }
    const data = await response.json();
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
      stdout: (data.result.stdout || "").slice(0, 5e5),
      stderr: (data.result.stderr || "").slice(0, 5e4),
      exitCode: data.result.exitCode ?? 0,
      durationMs,
      timedOut: data.result.timedOut || false
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;
    metrics.failedRequests++;
    console.error(`${LOG} Tool ${tool} failed after retries: ${err.message} (${durationMs}ms)`);
    return fallbackToSSH(config, err, startTime);
  }
}
async function executeRawCommandViaHttp(command, timeoutSeconds = 300, engagementAbortSignal) {
  const startTime = Date.now();
  metrics.totalRequests++;
  if (engagementAbortSignal?.aborted) {
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: "Engagement aborted before execution",
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: "Engagement aborted"
    };
  }
  try {
    const activeUrl = await getActiveScanUrl();
    console.log(`${LOG} Raw command: ${command.slice(0, 100)}... via ${activeUrl}`);
    const timeoutMs = Math.min((timeoutSeconds + 60) * 1e3, 36e4);
    const response = await fetchWithRetry(
      `${activeUrl}/api/scan/raw`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": SCAN_API_KEY
        },
        body: JSON.stringify({ command, timeoutSeconds })
      },
      timeoutMs,
      `raw: ${command.slice(0, 40)}`,
      engagementAbortSignal
    );
    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }
    const data = await response.json();
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
      stdout: (data.result.stdout || "").slice(0, 5e5),
      stderr: (data.result.stderr || "").slice(0, 5e4),
      exitCode: data.result.exitCode ?? 0,
      durationMs,
      timedOut: false
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;
    metrics.failedRequests++;
    console.error(`${LOG} Raw command failed after retries: ${err.message} (${durationMs}ms), falling back to SSH`);
    return fallbackToSSHRaw(command, timeoutSeconds, startTime);
  }
}
async function checkDoScanServiceHealth() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1e4);
    const activeUrl = await getActiveScanUrl();
    const response = await fetch(`${activeUrl}/health`, {
      headers: { "X-Scan-Key": SCAN_API_KEY },
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    return {
      healthy: data.status === "ok",
      uptime: data.uptime,
      memory: data.memory
    };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}
async function getDoScanTools() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1e4);
    const response = await fetch(`${SCAN_SERVICE_URL}/api/tools`, {
      headers: { "X-Scan-Key": SCAN_API_KEY },
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    return data.tools || {};
  } catch {
    return {};
  }
}
async function fallbackToSSH(config, originalError, startTime) {
  metrics.httpFallbackToSSH++;
  const sshKeyConfigured = !!(process.env.SCAN_SERVER_SSH_KEY && process.env.SCAN_SERVER_HOST);
  if (!sshKeyConfigured) {
    console.warn(`${LOG} SSH fallback skipped for ${config.tool} \u2014 no SSH key configured (deployed env). HTTP error: ${originalError.message}`);
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: "",
      stderr: `HTTP execution failed: ${originalError.message}. SSH fallback unavailable (no SSH key configured).`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: `HTTP execution failed, SSH fallback unavailable`
    };
  }
  console.log(`${LOG} Falling back to SSH for ${config.tool} (HTTP error: ${originalError.message})`);
  try {
    const { executeViaChildProcessSSH } = await import("./scan-server-executor-OQA5G5FJ.js");
    const cmd = config.sudo ? `sudo ${config.tool} ${config.args || ""}` : `${config.tool} ${config.args || ""}`;
    const result = await executeViaChildProcessSSH(cmd, config.timeoutSeconds || 300);
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: result.stdout.slice(0, 5e5),
      stderr: result.stderr.slice(0, 5e4),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false
    };
  } catch (sshErr) {
    return {
      tool: config.tool,
      command: `${config.tool} ${config.args}`,
      stdout: "",
      stderr: `HTTP failed: ${originalError.message}; SSH fallback also failed: ${sshErr.message}`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: `Both HTTP and SSH execution failed`
    };
  }
}
async function fallbackToSSHRaw(command, timeoutSeconds, startTime) {
  metrics.httpFallbackToSSH++;
  const sshKeyConfigured = !!(process.env.SCAN_SERVER_SSH_KEY && process.env.SCAN_SERVER_HOST);
  if (!sshKeyConfigured) {
    console.warn(`${LOG} SSH fallback skipped for raw command \u2014 no SSH key configured (deployed env)`);
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: `HTTP execution failed. SSH fallback unavailable (no SSH key configured).`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: "HTTP execution failed, SSH fallback unavailable"
    };
  }
  console.log(`${LOG} Falling back to SSH for raw command`);
  try {
    const { executeViaChildProcessSSH } = await import("./scan-server-executor-OQA5G5FJ.js");
    const result = await executeViaChildProcessSSH(command, timeoutSeconds);
    return {
      tool: "raw",
      command,
      stdout: result.stdout.slice(0, 5e5),
      stderr: result.stderr.slice(0, 5e4),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false
    };
  } catch (sshErr) {
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: `HTTP failed; SSH fallback also failed: ${sshErr.message}`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: false,
      error: "Both HTTP and SSH execution failed"
    };
  }
}
function updateAvgLatency(latencyMs) {
  const n = metrics.successfulRequests;
  metrics.avgLatencyMs = n === 1 ? latencyMs : Math.round((metrics.avgLatencyMs * (n - 1) + latencyMs) / n);
}
var LOG, RETRY_CONFIG, metrics;
var init_do_scan_api = __esm({
  "server/lib/do-scan-api.ts"() {
    init_scan_service_url();
    LOG = "[DO-ScanAPI]";
    RETRY_CONFIG = {
      maxRetries: 3,
      baseDelayMs: 1500,
      // 1.5s, 3s, 6s exponential backoff
      backoffMultiplier: 2
    };
    metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      avgLatencyMs: 0,
      httpFallbackToSSH: 0,
      retriesPerformed: 0
    };
  }
});

export {
  getDoApiMetrics,
  executeToolViaHttp,
  executeRawCommandViaHttp,
  checkDoScanServiceHealth,
  getDoScanTools,
  init_do_scan_api
};
