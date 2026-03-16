/**
 * Shared scan-service URL resolver
 * ─────────────────────────────────
 * SCAN_SERVER_HOST is often a bare IP (e.g. 159.223.152.190).
 * The TLS certificate is issued for the domain name scan.aceofcloud.io,
 * so Node.js `fetch` will reject HTTPS connections to the raw IP with
 * ERR_TLS_CERT_ALTNAME_INVALID.
 *
 * This module centralises the fallback logic so every consumer gets the
 * same, working base URL.
 */

const SCAN_HOST_RAW = process.env.SCAN_SERVER_HOST || "";

export const SCAN_SERVICE_URL = (() => {
  // If the env var is empty or looks like a bare IPv4, use the domain name
  if (!SCAN_HOST_RAW || /^\d{1,3}(\.\d{1,3}){3}$/.test(SCAN_HOST_RAW)) {
    return "https://scan.aceofcloud.io";
  }
  // Already a domain name — use as-is
  return SCAN_HOST_RAW.startsWith("http") ? SCAN_HOST_RAW : `https://${SCAN_HOST_RAW}`;
})();

// The scan service uses its own API key (ADMIN123), separate from the Caldera C2 API key.
// Do NOT use CALDERA_API_KEY here — that was rotated for the Caldera v2 REST API.
export const SCAN_API_KEY = "ADMIN123";
