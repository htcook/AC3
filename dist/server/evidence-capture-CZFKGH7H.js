import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit/evidence-capture.ts
function isValidEvidenceType(type) {
  return EVIDENCE_TYPES.includes(type);
}
function buildEvidenceMetadata(asset, type, engagementId) {
  return { hostname: asset.hostname || "unknown", ip: asset.ip || "unknown", type, engagementId, capturedAt: (/* @__PURE__ */ new Date()).toISOString() };
}
function shouldCaptureCalderaEvidence(state) {
  return state.engagementType === "red_team" && (state.assets || []).some((a) => a.c2Deployed === true);
}
function getCompromisedAssets(state) {
  return (state.assets || []).filter((a) => a.compromised === true);
}
function buildLearningStats(state) {
  let totalExploitAttempts = 0, successfulExploits = 0, c2Deployments = 0;
  for (const asset of state.assets || []) {
    for (const attempt of asset.exploitAttempts || []) {
      totalExploitAttempts++;
      if (attempt.success) successfulExploits++;
    }
    if (asset.c2Deployed) c2Deployments++;
  }
  return { totalExploitAttempts, successfulExploits, successRate: totalExploitAttempts > 0 ? successfulExploits / totalExploitAttempts : 0, c2Deployments, evidenceItems: state.evidenceChain?.length || 0 };
}
async function capturePostExploitEvidence(ctx) {
  const { state, operatorCtx } = ctx;
  const { addLog, genId } = ctx.helpers;
  const { evidenceGate, createIntegrityEnvelope, buildProvenance, recordCustodyEvent } = ctx.evidence;
  const result = { pentestEvidenceCount: 0, calderaEvidenceCaptured: false, persistedPanelCount: 0, integrityGatePassed: false };
  const compromised = getCompromisedAssets(state);
  for (const asset of compromised) {
    try {
      const metadata = buildEvidenceMetadata(asset, "session_log", state.engagementId);
      const content = JSON.stringify({ ...metadata, exploitAttempts: asset.exploitAttempts?.filter((a) => a.success) || [], accessLevel: asset.accessLevel || "user" });
      const envelope = createIntegrityEnvelope(content, "post_exploit_capture");
      const provenance = buildProvenance("post_exploit", "evidence_capture", operatorCtx);
      const evidenceId = genId();
      await evidenceGate(state, { id: evidenceId, type: "session_log", content, envelope, provenance, asset: asset.hostname || asset.ip });
      recordCustodyEvent(state, { evidenceId, event: "evidence_captured", actor: operatorCtx.id, timestamp: Date.now() });
      result.pentestEvidenceCount++;
    } catch (err) {
      addLog(state, { phase: "post_exploit", type: "error", title: "Evidence Capture Failed", detail: `${asset.hostname}: ${err.message}` });
    }
  }
  if (shouldCaptureCalderaEvidence(state)) {
    try {
      const calderaBaseUrl = process.env.CALDERA_BASE_URL || "http://localhost:8888";
      const calderaApiKey = process.env.CALDERA_API_KEY || "";
      const opsRes = await fetch(`${calderaBaseUrl}/api/v2/operations`, { headers: { "KEY": calderaApiKey }, signal: AbortSignal.timeout(15e3) }).catch(() => null);
      if (opsRes?.ok) {
        const operations = await opsRes.json().catch(() => []);
        const engOps = operations.filter((op) => op.name?.includes(`Eng${state.engagementId}`));
        if (engOps.length > 0) {
          result.calderaEvidenceCaptured = true;
          result.persistedPanelCount = engOps.length;
        }
      }
    } catch {
    }
  }
  const stats = buildLearningStats(state);
  addLog(state, { phase: "post_exploit", type: "info", title: "\u{1F4CA} Post-Exploit Summary", detail: `Exploits: ${stats.successfulExploits}/${stats.totalExploitAttempts} (${(stats.successRate * 100).toFixed(1)}%) | C2: ${stats.c2Deployments} | Evidence: ${result.pentestEvidenceCount}` });
  result.integrityGatePassed = true;
  return result;
}
var EVIDENCE_TYPES;
var init_evidence_capture = __esm({
  "server/lib/post-exploit/evidence-capture.ts"() {
    EVIDENCE_TYPES = ["screenshot", "config_dump", "data_sample", "credential", "session_log", "caldera_output"];
  }
});
init_evidence_capture();
export {
  buildEvidenceMetadata,
  buildLearningStats,
  capturePostExploitEvidence,
  getCompromisedAssets,
  isValidEvidenceType,
  shouldCaptureCalderaEvidence
};
