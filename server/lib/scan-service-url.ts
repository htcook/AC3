/**
 * Shared scan-service URL resolver
 * ─────────────────────────────────
 * Routes scan tool execution to the dedicated ScanForge droplet (primary).
 *
 * Architecture:
 *   Primary:  scanforge.aceofcloud.io (137.184.71.192) — CPU-optimized 4vCPU/8GB, scan tools only
 *             HTTPS on port 4443 with Let's Encrypt TLS certificate
 *   Legacy:   scan.aceofcloud.io (137.184.211.238) — shared server with lab containers + ZAP
 *
 * IMPORTANT: The legacy server is perpetually at memory capacity (~15.5GB/16GB used)
 * because it hosts Juice Shop, ZAP, Burp, WebGoat, and other Docker containers.
 * We MUST NOT fall back to it for scan execution — only use it for ZAP API access
 * (which is already running there as a daemon).
 *
 * SCAN_SERVER_HOST env var is still respected for override scenarios.
 */

const SCAN_HOST_RAW = process.env.SCAN_SERVER_HOST || "";

// ─── Dedicated ScanForge Droplet ────────────────────────────────────────────
export const SCANFORGE_DEDICATED_IP = "137.184.71.192";
export const SCANFORGE_DEDICATED_DOMAIN = "scanforge.aceofcloud.io";
export const SCANFORGE_DEDICATED_URL = `https://${SCANFORGE_DEDICATED_DOMAIN}:4443`;
// Legacy HTTP fallback (kept for reference, not used in production)
export const SCANFORGE_DEDICATED_URL_HTTP = `http://${SCANFORGE_DEDICATED_IP}:4000`;

// ─── Legacy Shared Scan Server (also hosts ZAP + lab containers) ────────────
export const LEGACY_SCAN_URL = "https://scan.aceofcloud.io";
export const LEGACY_SCAN_IP = process.env.SCAN_SERVER_HOST || "137.184.211.238";
export const LEGACY_ZAP_URL = process.env.ZAP_BASE_URL || `http://${LEGACY_SCAN_IP}:8092`;

// ─── Primary URL (used by do-scan-api.ts and job-queue-bridge.ts) ───────────
export const SCAN_SERVICE_URL = (() => {
  // If env var explicitly set, honour it (for override scenarios)
  if (SCAN_HOST_RAW && !/^\d{1,3}(\.\d{1,3}){3}$/.test(SCAN_HOST_RAW)) {
    return SCAN_HOST_RAW.startsWith("http") ? SCAN_HOST_RAW : `https://${SCAN_HOST_RAW}`;
  }
  // Default: use the dedicated ScanForge droplet
  return SCANFORGE_DEDICATED_URL;
})();

// The scan service uses its own API key, separate from the Caldera C2 API key.
// Do NOT use CALDERA_API_KEY here — that was rotated for the Caldera v2 REST API.
// Reads from SCAN_API_KEY env var; falls back to the rotated key for backward compat.
export const SCAN_API_KEY = process.env.SCAN_API_KEY || "2f7aec9e8d3ab1e9b2fe2bb94dfc57a1cb142f4a7cbd5443";

// ─── Health Check & Failover ────────────────────────────────────────────────
let _dedicatedHealthy = true;
let _lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL_MS = 30_000; // 30s

/**
 * Check if the dedicated ScanForge droplet is healthy.
 * Caches the result for 30s to avoid excessive health checks.
 */
export async function isDedicatedHealthy(): Promise<boolean> {
  const now = Date.now();
  if (now - _lastHealthCheck < HEALTH_CHECK_INTERVAL_MS) return _dedicatedHealthy;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    const resp = await fetch(`${SCANFORGE_DEDICATED_URL}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    _dedicatedHealthy = resp.ok;
  } catch {
    _dedicatedHealthy = false;
  }
  _lastHealthCheck = now;
  return _dedicatedHealthy;
}

/**
 * Get the scan service URL for tool execution.
 *
 * ALWAYS returns the dedicated ScanForge URL — no legacy fallback.
 * The legacy server (137.184.211.238) is perpetually overloaded with Docker
 * containers (Juice Shop, WebGoat, Burp, ZAP, etc.) consuming 15.5GB/16GB RAM.
 * Falling back to it for scan execution causes OOM conditions and pipeline failures.
 *
 * If the dedicated server is unhealthy, we return it anyway and let the
 * do-scan-api.ts retry/timeout logic handle the failure gracefully rather than
 * sending traffic to an overloaded machine that will hang indefinitely.
 */
export async function getActiveScanUrl(): Promise<string> {
  const healthy = await isDedicatedHealthy();
  if (!healthy) {
    console.warn("[ScanServiceURL] Dedicated ScanForge droplet unhealthy — NOT falling back to legacy (overloaded). Returning dedicated URL for retry.");
  }
  // Always return dedicated — legacy fallback disabled due to chronic OOM
  return SCANFORGE_DEDICATED_URL;
}

/**
 * Get the ZAP base URL.
 * ZAP runs on the legacy shared scan server via nginx reverse proxy on port 8092.
 * The nginx proxy forwards to localhost:8090 inside the server, preventing
 * ZAP's self-referencing loop when requests arrive on the public IP.
 * NOT on the dedicated ScanForge droplet (which only runs the Node.js scan service).
 * The dedicated droplet does not have ZAP installed.
 */
let _zapHealthy = true;
let _lastZapCheck = 0;

export async function getActiveZapUrl(): Promise<string> {
  // ZAP always runs on the legacy scan server
  const zapUrl = LEGACY_ZAP_URL;

  // Optional health check to detect if ZAP is down
  const now = Date.now();
  if (now - _lastZapCheck > 60_000) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5_000);
      const resp = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: ctrl.signal });
      clearTimeout(timer);
      _zapHealthy = resp.ok;
    } catch {
      _zapHealthy = false;
    }
    _lastZapCheck = now;
  }

  if (!_zapHealthy) {
    console.warn(`[ScanServiceURL] ZAP unhealthy at ${zapUrl}`);
  }
  return zapUrl;
}
