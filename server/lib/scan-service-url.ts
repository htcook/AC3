/**
 * Shared scan-service URL resolver
 * ─────────────────────────────────
 * Routes scan tool execution to the dedicated ScanForge EC2 instance (primary).
 *
 * Architecture:
 *   Primary:  EC2 Auto-Discovery — queries AWS DescribeInstances to find the
 *             ScanForge instance's current public IP (handles IP changes on restart)
 *   Fallback: Static env vars (SCANFORGE_URL, SCAN_SERVER_HOST)
 *   Legacy:   Shared scan server with lab containers + ZAP
 *
 * All infrastructure runs on AWS EC2. Auto-discovery eliminates stale IP issues.
 */

import { getDiscoveredScanUrl, getDiscoveredScanIp } from "./scan-server-discovery";

const SCAN_HOST_RAW = process.env.SCAN_SERVER_HOST || "";

// ─── Dedicated ScanForge EC2 Instance (static fallbacks) ────────────────────
export const SCANFORGE_DEDICATED_IP = process.env.SCANFORGE_HOST || process.env.SCAN_SERVER_HOST || "";
export const SCANFORGE_DEDICATED_DOMAIN = process.env.SCANFORGE_DOMAIN || "scanforge.aceofcloud.io";
// Prefer explicit SCANFORGE_URL env; then fall back to IP-based URL (avoids DNS
// resolution failures inside VPCs where the domain record isn't reachable); only
// use the domain as a last resort.
export const SCANFORGE_DEDICATED_URL = process.env.SCANFORGE_URL
  || (SCANFORGE_DEDICATED_IP ? `https://${SCANFORGE_DEDICATED_IP}:4443` : `https://${SCANFORGE_DEDICATED_DOMAIN}:4443`);
// Legacy HTTP fallback (kept for reference, not used in production)
export const SCANFORGE_DEDICATED_URL_HTTP = SCANFORGE_DEDICATED_IP ? `http://${SCANFORGE_DEDICATED_IP}:4000` : "";

// ─── Legacy Shared Scan Server (also hosts ZAP + lab containers on AWS EC2) ─
export const LEGACY_SCAN_URL = process.env.LEGACY_SCAN_URL || "https://scan.aceofcloud.io";
export const LEGACY_SCAN_IP = process.env.SCAN_SERVER_HOST || "";
export const LEGACY_ZAP_URL = process.env.ZAP_BASE_URL || (LEGACY_SCAN_IP ? `http://${LEGACY_SCAN_IP}:8092` : "");

// ─── Primary URL (synchronous fallback for imports that need a static value) ─
export const SCAN_SERVICE_URL = (() => {
  if (SCAN_HOST_RAW && !/^\d{1,3}(\.\d{1,3}){3}$/.test(SCAN_HOST_RAW)) {
    return SCAN_HOST_RAW.startsWith("http") ? SCAN_HOST_RAW : `https://${SCAN_HOST_RAW}`;
  }
  return SCANFORGE_DEDICATED_URL;
})();

// The scan service uses its own API key, separate from the Caldera C2 API key.
export const SCAN_API_KEY = process.env.SCAN_API_KEY || "";

// Startup diagnostic: log resolved scan service configuration
console.log(`[ScanServiceURL-Boot] SCAN_SERVICE_URL=${SCAN_SERVICE_URL} | SCANFORGE_DEDICATED_URL=${SCANFORGE_DEDICATED_URL} | LEGACY_ZAP_URL=${LEGACY_ZAP_URL} | SCAN_API_KEY_present=${!!SCAN_API_KEY}`);

// ─── Health Check & Failover ──────────────────────────────────────────────────────
let _dedicatedHealthy = true;
let _lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL_MS = 30_000; // 30s

/**
 * Check if the dedicated ScanForge EC2 instance is healthy.
 * Now uses auto-discovered URL instead of static env var.
 */
export async function isDedicatedHealthy(): Promise<boolean> {
  const now = Date.now();
  if (now - _lastHealthCheck < HEALTH_CHECK_INTERVAL_MS) return _dedicatedHealthy;

  try {
    const url = await getDiscoveredScanUrl();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    const resp = await fetch(`${url}/health`, { signal: ctrl.signal });
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
 * PRIMARY: Uses EC2 auto-discovery to get the current public IP.
 * FALLBACK: Returns static SCANFORGE_URL env var if discovery fails.
 */
export async function getActiveScanUrl(): Promise<string> {
  const healthy = await isDedicatedHealthy();
  if (!healthy) {
    console.warn(`[ScanServiceURL] ScanForge EC2 instance unhealthy — returning URL for retry logic. URL=${SCANFORGE_DEDICATED_URL || SCAN_SERVICE_URL}`);
  }
  // Diagnostic: log resolved URL on first call
  if (!_diagLogged) {
    _diagLogged = true;
    console.log(`[ScanServiceURL-Diag] SCAN_SERVER_HOST=${process.env.SCAN_SERVER_HOST || '(unset)'} SCANFORGE_URL=${process.env.SCANFORGE_URL || '(unset)'} SCANFORGE_HOST=${process.env.SCANFORGE_HOST || '(unset)'} resolvedUrl=${SCANFORGE_DEDICATED_URL || SCAN_SERVICE_URL}`);
  }

  // Fallback to static config
  console.warn("[ScanServiceURL] Auto-discovery failed — using static SCANFORGE_URL.");
  return SCANFORGE_DEDICATED_URL || SCAN_SERVICE_URL;
}
let _diagLogged = false;

/**
 * Get the ZAP base URL.
 * ZAP runs on the scan server via nginx reverse proxy on port 8092.
 * Uses auto-discovered IP for ZAP as well (same host).
 */
let _zapHealthy = true;
let _lastZapCheck = 0;

export async function getActiveZapUrl(): Promise<string> {
  // Try auto-discovered IP for ZAP (same server, different port)
  const scanIp = await getDiscoveredScanIp();
  const zapUrl = scanIp
    ? `http://${scanIp}:8092`
    : LEGACY_ZAP_URL;

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
