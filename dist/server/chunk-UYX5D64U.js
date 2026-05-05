import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scan-service-url.ts
async function isDedicatedHealthy() {
  const now = Date.now();
  if (now - _lastHealthCheck < HEALTH_CHECK_INTERVAL_MS) return _dedicatedHealthy;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1e4);
    const resp = await fetch(`${SCANFORGE_DEDICATED_URL}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    _dedicatedHealthy = resp.ok;
  } catch {
    _dedicatedHealthy = false;
  }
  _lastHealthCheck = now;
  return _dedicatedHealthy;
}
async function getActiveScanUrl() {
  const healthy = await isDedicatedHealthy();
  if (healthy) return SCANFORGE_DEDICATED_URL;
  console.warn("[ScanServiceURL] Dedicated ScanForge droplet unhealthy, falling back to legacy scan server");
  return LEGACY_SCAN_URL;
}
async function getActiveZapUrl() {
  const zapUrl = LEGACY_ZAP_URL;
  const now = Date.now();
  if (now - _lastZapCheck > 6e4) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5e3);
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
var SCAN_HOST_RAW, SCANFORGE_DEDICATED_IP, SCANFORGE_DEDICATED_URL, LEGACY_SCAN_URL, LEGACY_SCAN_IP, LEGACY_ZAP_URL, SCAN_SERVICE_URL, SCAN_API_KEY, _dedicatedHealthy, _lastHealthCheck, HEALTH_CHECK_INTERVAL_MS, _zapHealthy, _lastZapCheck;
var init_scan_service_url = __esm({
  "server/lib/scan-service-url.ts"() {
    SCAN_HOST_RAW = process.env.SCAN_SERVER_HOST || "";
    SCANFORGE_DEDICATED_IP = "137.184.71.192";
    SCANFORGE_DEDICATED_URL = `http://${SCANFORGE_DEDICATED_IP}:4000`;
    LEGACY_SCAN_URL = "https://scan.aceofcloud.io";
    LEGACY_SCAN_IP = process.env.SCAN_SERVER_HOST || "137.184.211.238";
    LEGACY_ZAP_URL = process.env.ZAP_BASE_URL || `http://${LEGACY_SCAN_IP}:8092`;
    SCAN_SERVICE_URL = (() => {
      if (SCAN_HOST_RAW && !/^\d{1,3}(\.\d{1,3}){3}$/.test(SCAN_HOST_RAW)) {
        return SCAN_HOST_RAW.startsWith("http") ? SCAN_HOST_RAW : `https://${SCAN_HOST_RAW}`;
      }
      return SCANFORGE_DEDICATED_URL;
    })();
    SCAN_API_KEY = "ADMIN123";
    _dedicatedHealthy = true;
    _lastHealthCheck = 0;
    HEALTH_CHECK_INTERVAL_MS = 3e4;
    _zapHealthy = true;
    _lastZapCheck = 0;
  }
});

export {
  SCANFORGE_DEDICATED_IP,
  SCANFORGE_DEDICATED_URL,
  LEGACY_SCAN_URL,
  LEGACY_SCAN_IP,
  LEGACY_ZAP_URL,
  SCAN_SERVICE_URL,
  SCAN_API_KEY,
  isDedicatedHealthy,
  getActiveScanUrl,
  getActiveZapUrl,
  init_scan_service_url
};
