import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit/operation-launcher.ts
function buildOperationName(engagementId, source) {
  const prefix = source === "auto" ? "AC3-AutoLaunch" : "AC3-AutoBuild";
  return `${prefix}-Eng${engagementId}-${Date.now()}`;
}
function buildLaunchConfig(name, adversaryId) {
  return { name, adversaryId, autonomous: true, autoClose: true, jitter: DEFAULT_JITTER, planner: DEFAULT_PLANNER };
}
function buildAttackPath(state) {
  const successfulExploits = [];
  let targetPlatform = "linux";
  for (const asset of state.assets || []) {
    for (const attempt of asset.exploitAttempts || []) {
      if (attempt.success) {
        successfulExploits.push({ hostname: asset.hostname, ip: asset.ip, cve: attempt.cve, module: attempt.module, output: attempt.output });
        if (asset.platform === "windows") targetPlatform = "windows";
      }
    }
  }
  const attackPath = successfulExploits.map((e) => `${e.hostname || e.ip}: ${e.cve} via ${e.module}`).join("\n");
  return { successfulExploits, attackPath, targetPlatform };
}
function selectAdversaryProfile(state, profiles) {
  if (!profiles || profiles.length === 0) return null;
  const { targetPlatform } = buildAttackPath(state);
  const platformMatches = profiles.filter((p) => p.platform === targetPlatform || p.platform === "all");
  return platformMatches.length > 0 ? platformMatches[0] : profiles[0];
}
async function launchCalderaOperation(ctx) {
  const { state } = ctx;
  const { addLog } = ctx.helpers;
  const result = { success: false };
  const { successfulExploits, attackPath, targetPlatform } = buildAttackPath(state);
  if (successfulExploits.length === 0) {
    addLog(state, { phase: "post_exploit", type: "info", title: "No Exploits for Operation", detail: "No successful exploits to base an adversary operation on." });
    return result;
  }
  try {
    const calderaBaseUrl = process.env.CALDERA_BASE_URL || "http://localhost:8888";
    const calderaApiKey = process.env.CALDERA_API_KEY || "";
    const profilesRes = await fetch(`${calderaBaseUrl}/api/v2/adversaries`, {
      headers: { "KEY": calderaApiKey },
      signal: AbortSignal.timeout(CALDERA_LAUNCH_TIMEOUT_MS)
    }).catch(() => null);
    let profiles = [];
    if (profilesRes?.ok) profiles = await profilesRes.json().catch(() => []);
    const selectedProfile = selectAdversaryProfile(state, profiles);
    if (selectedProfile) {
      const opName = buildOperationName(state.engagementId, "auto");
      const config = buildLaunchConfig(opName, selectedProfile.adversary_id);
      const launchRes = await fetch(`${calderaBaseUrl}/api/v2/operations`, {
        method: "POST",
        headers: { "KEY": calderaApiKey, "Content-Type": "application/json" },
        body: JSON.stringify(config),
        signal: AbortSignal.timeout(CALDERA_LAUNCH_TIMEOUT_MS)
      }).catch(() => null);
      if (launchRes?.ok) {
        const op = await launchRes.json().catch(() => ({}));
        result.success = true;
        result.operationId = op.id || opName;
        result.adversaryName = selectedProfile.name || selectedProfile.adversary_id;
        result.source = "profile_match";
      }
    }
    if (!result.success) {
      result.source = "builder_fallback";
      addLog(state, { phase: "post_exploit", type: "info", title: "Builder Fallback", detail: `No suitable adversary profile. Attack path: ${attackPath.substring(0, 200)}` });
    }
  } catch (err) {
    addLog(state, { phase: "post_exploit", type: "error", title: "\u274C Operation Launch Failed", detail: err.message });
  }
  return result;
}
var CALDERA_LAUNCH_TIMEOUT_MS, DEFAULT_JITTER, DEFAULT_PLANNER;
var init_operation_launcher = __esm({
  "server/lib/post-exploit/operation-launcher.ts"() {
    CALDERA_LAUNCH_TIMEOUT_MS = 45e3;
    DEFAULT_JITTER = "4/8";
    DEFAULT_PLANNER = "batch";
  }
});
init_operation_launcher();
export {
  buildAttackPath,
  buildLaunchConfig,
  buildOperationName,
  launchCalderaOperation,
  selectAdversaryProfile
};
