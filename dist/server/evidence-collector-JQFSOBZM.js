import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploitation/evidence-collector.ts
async function collectExploitEvidence(ctx) {
  const { state, addLog, broadcastOpsUpdate } = ctx;
  let calderaEvidenceCaptured = false;
  let agentCount = 0;
  let learningStats = null;
  try {
    const { getPersistedLearningStats } = await import("./exploit-learning-engine-NIACEN2V.js");
    const persistedStats = await getPersistedLearningStats();
    const { inMemory, database } = persistedStats;
    if (inMemory.totalOutcomes > 0 || database.totalOutcomes > 0) {
      learningStats = {
        totalOutcomes: inMemory.totalOutcomes + database.totalOutcomes,
        successRate: inMemory.totalOutcomes > 0 ? inMemory.successRate : database.successRate,
        patternsLearned: inMemory.patternsLearned + database.patternsStored,
        chainsDiscovered: inMemory.chainsDiscovered + database.chainsStored
      };
      addLog(state, {
        phase: "exploitation",
        type: "info",
        title: "\u{1F9E0} Learning Engine Summary",
        detail: `This session: ${inMemory.totalOutcomes} outcomes, ${Math.round(inMemory.successRate * 100)}% success rate, ${inMemory.patternsLearned} patterns, ${inMemory.chainsDiscovered} chains, ${inMemory.falsePositivesDetected} FP detected, ${inMemory.guardrailBlocks} guardrail blocks
Cross-engagement DB: ${database.totalOutcomes} total outcomes, ${database.patternsStored} patterns, ${database.chainsStored} chains stored, ${Math.round(database.successRate * 100)}% lifetime success rate`
      });
    }
  } catch (e) {
    console.warn(`[LearningEngine] Stats summary failed: ${e.message}`);
  }
  state.progress = 75;
  addLog(state, {
    phase: "exploitation",
    type: "phase_complete",
    title: "\u2705 Phase 7 Complete",
    detail: `${state.stats.exploitsAttempted} attempts, ${state.stats.exploitsSucceeded} succeeded, ${state.stats.sessionsOpened} sessions`
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
  if (state.stats.exploitsSucceeded > 0) {
    try {
      addLog(state, {
        phase: "exploitation",
        type: "info",
        title: "\u{1F4F8} Capturing Exploitation Evidence",
        detail: "Auto-collecting C2 agent data, operation results, and network metadata for report artifacts."
      });
      const { captureCalderaEvidence } = await import("../caldera-evidence-capture");
      const engagement = ctx.engagement;
      const exploitEvidence = await captureCalderaEvidence({
        engagementId: state.engagementId,
        engagementName: engagement?.name || `Engagement-${state.engagementId}`,
        targets: state.assets.filter((a) => a.status === "compromised").map((a) => ({ hostname: a.hostname, ip: a.ip || "" }))
      });
      if (exploitEvidence) {
        calderaEvidenceCaptured = true;
        agentCount = exploitEvidence.agents.length;
        state.__calderaExploitEvidence = exploitEvidence;
        await validateEvidenceIntegrity(ctx, exploitEvidence);
      }
    } catch (e) {
      addLog(state, { phase: "exploitation", type: "warning", title: "\u26A0\uFE0F Caldera Evidence Capture Failed", detail: e.message });
    }
  }
  return { calderaEvidenceCaptured, agentCount, learningStats };
}
async function validateEvidenceIntegrity(ctx, exploitEvidence) {
  const { state, addLog, scanServerHost } = ctx;
  try {
    const { buildProvenance, evidenceGate, createIntegrityEnvelope, recordCustodyEvent } = await import("./evidence-integrity-E4ASVYFK.js");
    const exploitEvidenceContent = JSON.stringify(exploitEvidence);
    const exploitProvenance = buildProvenance({
      tool: "caldera",
      command: "captureCalderaEvidence:exploitation",
      collectorHost: process.env.SCAN_SERVER_HOST || "ac3-platform",
      rawOutput: exploitEvidenceContent,
      targetHost: exploitEvidence.agents[0]?.hostIp || state.assets[0]?.hostname || "unknown",
      sourceIp: exploitEvidence.calderaServerIp || "127.0.0.1",
      destinationIp: exploitEvidence.agents[0]?.hostIp || "unknown"
    });
    const exploitGateResult = evidenceGate({
      content: exploitEvidenceContent,
      provenance: exploitProvenance,
      knownAssets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ip || "", ports: a.ports.map((p) => p.port) })),
      strictness: "moderate"
    });
    const gateEmoji = exploitGateResult.passed ? "\u2705" : "\u26A0\uFE0F";
    addLog(state, {
      phase: "exploitation",
      type: "evidence",
      title: `\u{1F4F8} Exploitation Evidence Captured ${gateEmoji}`,
      detail: `Captured ${exploitEvidence.agents.length} agent(s) from Caldera. Source: ${exploitEvidence.calderaServerIp}
Integrity: hash=${exploitGateResult.contentHash.slice(0, 12)}... provenance=${exploitGateResult.provenanceValid ? "valid" : "INVALID"}${exploitGateResult.warnings.length > 0 ? ` (${exploitGateResult.warnings.length} warnings)` : ""}`,
      data: {
        agentCount: exploitEvidence.agents.length,
        calderaServerUrl: exploitEvidence.calderaServerUrl,
        calderaServerIp: exploitEvidence.calderaServerIp,
        capturedAt: exploitEvidence.capturedAt,
        integrityGate: {
          passed: exploitGateResult.passed,
          contentHash: exploitGateResult.contentHash,
          provenanceValid: exploitGateResult.provenanceValid,
          warnings: exploitGateResult.warnings
        }
      }
    });
    const evidenceId = `caldera-exploit-${state.engagementId}-${Date.now()}`;
    createIntegrityEnvelope({
      engagementId: String(state.engagementId),
      evidenceId,
      content: exploitEvidenceContent,
      provenance: exploitProvenance,
      sourceTool: "caldera"
    });
    recordCustodyEvent({
      engagementId: String(state.engagementId),
      evidenceId,
      action: exploitGateResult.passed ? "integrity_verified" : "integrity_flagged",
      performedBy: "Evidence Gate",
      details: `Caldera exploitation evidence: ${exploitGateResult.passed ? "passed" : "flagged"} integrity check`
    });
  } catch (e) {
    addLog(state, { phase: "exploitation", type: "warning", title: "\u26A0\uFE0F Evidence Integrity Gate Error", detail: e.message });
  }
}
var init_evidence_collector = __esm({
  "server/lib/exploitation/evidence-collector.ts"() {
  }
});
init_evidence_collector();
export {
  collectExploitEvidence,
  validateEvidenceIntegrity
};
