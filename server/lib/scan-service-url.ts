/**
 * Shared scan-service URL resolver
 * ─────────────────────────────────
 * Routes scan tool execution to the dedicated ScanForge droplet (primary)
 * with automatic failover to the legacy shared scan server.
 *
 * Architecture:
 *   Primary:  scanforge-dedicated (137.184.71.192) — CPU-optimized 4vCPU/8GB, scan tools only
 *   Fallback: scan.aceofcloud.io (159.223.152.190) — shared server with lab containers
 *
 * The dedicated droplet runs scan tools without competing for resources with
 * Docker lab containers, resulting in 2-3x faster scan execution.
 *
 * SCAN_SERVER_HOST env var is still respected for override scenarios.
 */

const SCAN_HOST_RAW = process.env.SCAN_SERVER_HOST || "";

// ─── Dedicated ScanForge Droplet ────────────────────────────────────────────
export const SCANFORGE_DEDICATED_IP = "137.184.71.192";
export const SCANFORGE_DEDICATED_URL = `http://${SCANFORGE_DEDICATED_IP}:4000`;

// ─── Legacy Shared Scan Server ──────────────────────────────────────────────
export const LEGACY_SCAN_URL = "https://scan.aceofcloud.io";

// ─── Primary URL (used by do-scan-api.ts and job-queue-bridge.ts) ───────────
export const SCAN_SERVICE_URL = (() => {
  // If env var explicitly set, honour it (for override scenarios)
  if (SCAN_HOST_RAW && !/^\d{1,3}(\.\d{1,3}){3}$/.test(SCAN_HOST_RAW)) {
    return SCAN_HOST_RAW.startsWith("http") ? SCAN_HOST_RAW : `https://${SCAN_HOST_RAW}`;
  }
  // Default: use the dedicated ScanForge droplet
  return SCANFORGE_DEDICATED_URL;
})();

// The scan service uses its own API key (ADMIN123), separate from the Caldera C2 API key.
// Do NOT use CALDERA_API_KEY here — that was rotated for the Caldera v2 REST API.
export const SCAN_API_KEY = "ADMIN123";

// ─── Health Check & Failover ────────────────────────────────────────────────
let _dedicatedHealthy = true;
let _lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL_MS = 30_000; // 30s — reduced from 60s for faster ScanForge recovery detection

/**
 * Check if the dedicated ScanForge droplet is healthy.
 * Caches the result for 1 minute to avoid excessive health checks.
 */
export async function isDedicatedHealthy(): Promise<boolean> {
  const now = Date.now();
  if (now - _lastHealthCheck < HEALTH_CHECK_INTERVAL_MS) return _dedicatedHealthy;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000); // 10s timeout (was 5s — ScanForge can be slow under load)
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
 * Get the best available scan service URL with automatic failover.
 * Returns the dedicated droplet URL if healthy, otherwise falls back to legacy.
 */
export async function getActiveScanUrl(): Promise<string> {
  const healthy = await isDedicatedHealthy();
  if (healthy) return SCANFORGE_DEDICATED_URL;
  console.warn("[ScanServiceURL] Dedicated ScanForge droplet unhealthy, falling back to legacy scan server");
  return LEGACY_SCAN_URL;
}

/**
 * Get the ZAP base URL — dedicated droplet runs ZAP on port 8080.
 * Falls back to the env var ZAP_BASE_URL if the dedicated droplet is unhealthy.
 */
export async function getActiveZapUrl(): Promise<string> {
  const healthy = await isDedicatedHealthy();
  if (healthy) return `http://${SCANFORGE_DEDICATED_IP}:8090`;
  return process.env.ZAP_BASE_URL || "http://localhost:8090";
}
