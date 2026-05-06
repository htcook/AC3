import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/orchestrator-types.ts
function isInRoeScope(state, hostname, ip) {
  const guard = state.roeScopeGuard;
  if (!guard) return true;
  const normalizedHost = hostname.toLowerCase().trim();
  const normalizedIp = (ip || "").trim();
  const hostWithoutPort = normalizedHost.includes(":") ? normalizedHost.split(":")[0] : normalizedHost;
  if (guard.authorizedDomains.some((d) => {
    const nd = d.toLowerCase().trim();
    return nd === normalizedHost || nd === hostWithoutPort;
  })) return true;
  if (normalizedIp && guard.authorizedIps.some((i) => i.trim() === normalizedIp)) return true;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostWithoutPort)) {
    if (guard.authorizedIps.some((i) => i.trim() === hostWithoutPort)) return true;
  }
  return false;
}
function fmtTarget(asset, fallbackTarget) {
  if (!asset) return fallbackTarget || "unknown";
  if (asset.ip && asset.ip !== asset.hostname) return `${asset.hostname} (${asset.ip})`;
  return asset.hostname;
}
var init_orchestrator_types = __esm({
  "shared/orchestrator-types.ts"() {
    "use strict";
  }
});

export {
  isInRoeScope,
  fmtTarget,
  init_orchestrator_types
};
