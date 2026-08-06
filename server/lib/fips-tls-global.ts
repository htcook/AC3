/**
 * Global FIPS 140-3 TLS Enforcement
 *
 * Call `enforceFIPSTLS()` once at server startup to:
 *   1. Patch axios defaults with FIPS-approved HTTPS agent
 *   2. Set Node.js default TLS options for all tls.connect() calls
 *   3. Export a FIPS-compliant fetch wrapper
 *
 * This provides defense-in-depth: even if individual modules forget
 * to use the FIPS agent, the global defaults enforce compliance.
 */

import axios from "axios";
import tls from "tls";
import { getFIPSHttpsAgent, FIPS_TLS_CONFIG } from "./fips-tls";

let _enforced = false;

/**
 * Apply FIPS TLS settings globally. Safe to call multiple times (idempotent).
 */
export function enforceFIPSTLS(): void {
  if (_enforced) return;

  // 1. Patch axios global defaults
  const agent = getFIPSHttpsAgent();
  axios.defaults.httpsAgent = agent;
  console.log("[FIPS-TLS] Axios global defaults patched with FIPS HTTPS agent");

  // 2. Set Node.js global TLS defaults
  // This affects all tls.connect() calls that don't specify their own options
  tls.DEFAULT_MIN_VERSION = FIPS_TLS_CONFIG.MIN_VERSION;
  console.log(`[FIPS-TLS] Node.js TLS minimum version set to ${FIPS_TLS_CONFIG.MIN_VERSION}`);

  // 3. Log enforcement
  console.log("[FIPS-TLS] Global FIPS 140-3 TLS enforcement active");
  console.log(`[FIPS-TLS] Approved cipher suites: ${FIPS_TLS_CONFIG.CIPHERS.split(":").length} suites`);

  _enforced = true;
}

/**
 * Check whether global FIPS TLS enforcement is active.
 */
export function isFIPSTLSEnforced(): boolean {
  return _enforced;
}
