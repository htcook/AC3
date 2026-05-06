import {
  FIPS_TLS_CONFIG,
  getFIPSHttpsAgent,
  init_fips_tls
} from "./chunk-HRFBKKXV.js";

// server/lib/fips-tls-global.ts
init_fips_tls();
import axios from "axios";
import tls from "tls";
var _enforced = false;
function enforceFIPSTLS() {
  if (_enforced) return;
  const agent = getFIPSHttpsAgent();
  axios.defaults.httpsAgent = agent;
  console.log("[FIPS-TLS] Axios global defaults patched with FIPS HTTPS agent");
  tls.DEFAULT_MIN_VERSION = FIPS_TLS_CONFIG.MIN_VERSION;
  console.log(`[FIPS-TLS] Node.js TLS minimum version set to ${FIPS_TLS_CONFIG.MIN_VERSION}`);
  console.log("[FIPS-TLS] Global FIPS 140-3 TLS enforcement active");
  console.log(`[FIPS-TLS] Approved cipher suites: ${FIPS_TLS_CONFIG.CIPHERS.split(":").length} suites`);
  _enforced = true;
}
function isFIPSTLSEnforced() {
  return _enforced;
}

export {
  enforceFIPSTLS,
  isFIPSTLSEnforced
};
