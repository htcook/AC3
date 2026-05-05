import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/memory-manager.ts
function midScanCleanup(state) {
  let freed = 0;
  for (const asset of state.assets || []) {
    if (asset.toolResults && asset.toolResults.length > MAX_TOOL_RESULTS_PER_ASSET) {
      const excess = asset.toolResults.length - MAX_TOOL_RESULTS_PER_ASSET;
      for (let i = 0; i < excess; i++) {
        const tr = asset.toolResults[i];
        freed += (tr.outputPreview?.length || 0) * 2;
        freed += (tr.findings?.length || 0) * 200;
      }
      asset.toolResults = asset.toolResults.slice(-MAX_TOOL_RESULTS_PER_ASSET);
    }
    for (const tr of asset.toolResults || []) {
      if (tr.outputPreview && tr.outputPreview.length > MID_SCAN_OUTPUT_PREVIEW_CAP) {
        freed += (tr.outputPreview.length - MID_SCAN_OUTPUT_PREVIEW_CAP) * 2;
        tr.outputPreview = tr.outputPreview.slice(0, MID_SCAN_OUTPUT_PREVIEW_CAP) + "\u2026";
      }
    }
    if (asset.vulns && asset.vulns.length > MAX_VULNS_IN_MEMORY) {
      freed += (asset.vulns.length - MAX_VULNS_IN_MEMORY) * 300;
      asset.vulns = asset.vulns.slice(-MAX_VULNS_IN_MEMORY);
    }
  }
  if (state.log && state.log.length > MAX_IN_MEMORY_LOGS) {
    freed += (state.log.length - MAX_IN_MEMORY_LOGS) * 500;
    state.log = state.log.slice(-MAX_IN_MEMORY_LOGS);
  }
  if (global.gc) global.gc();
  return { freedEstimateBytes: freed };
}
function estimateStateSize(state) {
  const breakdown = {};
  let assetBytes = 0;
  for (const asset of state.assets || []) {
    for (const tr of asset.toolResults || []) {
      assetBytes += (tr.outputPreview?.length || 0) * 2;
      assetBytes += (tr.findings?.length || 0) * 200;
      assetBytes += 200;
    }
    assetBytes += (asset.vulns?.length || 0) * 300;
    assetBytes += (asset.zapFindings?.length || 0) * 200;
    assetBytes += (asset.pendingVulns?.length || 0) * 250;
    assetBytes += (asset.exploitAttempts?.length || 0) * 500;
    if (asset.passiveRecon) {
      assetBytes += JSON.stringify(asset.passiveRecon).length * 2;
    }
    assetBytes += (asset.confirmedCredentials?.length || 0) * 200;
    assetBytes += 500;
  }
  breakdown.assets = assetBytes;
  let logBytes = 0;
  for (const log of state.log || []) {
    logBytes += (log.detail?.length || 0) * 2;
    logBytes += (log.title?.length || 0) * 2;
    logBytes += log.data ? JSON.stringify(log.data).length * 2 : 0;
    logBytes += 200;
  }
  breakdown.logs = logBytes;
  if (state.passiveReconResults) {
    try {
      breakdown.passiveReconResults = JSON.stringify(state.passiveReconResults).length * 2;
    } catch {
      breakdown.passiveReconResults = 5e4;
    }
  }
  if (state.scanPlan) {
    try {
      breakdown.scanPlan = JSON.stringify(state.scanPlan).length * 2;
    } catch {
      breakdown.scanPlan = 1e4;
    }
  }
  for (const key of ["vulnAnalysis", "vulnAnalysisSuppressed", "attackChains", "scanFeedbackLoop", "essIntelligence", "cloudDetection", "engagementContext"]) {
    if (state[key]) {
      try {
        breakdown[key] = JSON.stringify(state[key]).length * 2;
      } catch {
        breakdown[key] = 2e4;
      }
    }
  }
  if (state.llmPlan) {
    breakdown.llmPlan = state.llmPlan.length * 2;
  }
  const totalBytes = Object.values(breakdown).reduce((sum, v) => sum + v, 0);
  return { totalBytes, breakdown };
}
function postPhaseCleanup(state, completedPhase) {
  const actions = [];
  let freedEstimate = 0;
  for (const asset of state.assets || []) {
    for (const tr of asset.toolResults || []) {
      if (tr.outputPreview && tr.outputPreview.length > POST_PHASE_OUTPUT_PREVIEW_CAP) {
        freedEstimate += (tr.outputPreview.length - POST_PHASE_OUTPUT_PREVIEW_CAP) * 2;
        tr.outputPreview = tr.outputPreview.slice(0, POST_PHASE_OUTPUT_PREVIEW_CAP) + "\u2026";
      }
      if (tr.findings && tr.findings.length > POST_PHASE_FINDINGS_CAP) {
        freedEstimate += (tr.findings.length - POST_PHASE_FINDINGS_CAP) * 200;
        tr.findings = tr.findings.slice(0, POST_PHASE_FINDINGS_CAP);
      }
    }
    actions.push(`toolResults trimmed for ${asset.hostname}`);
    if (asset.zapFindings && asset.zapFindings.length > MAX_ZAP_FINDINGS_IN_MEMORY) {
      freedEstimate += (asset.zapFindings.length - MAX_ZAP_FINDINGS_IN_MEMORY) * 200;
      asset.zapFindings = asset.zapFindings.slice(0, MAX_ZAP_FINDINGS_IN_MEMORY);
    }
    if (asset.pendingVulns && asset.pendingVulns.length > MAX_PENDING_VULNS_IN_MEMORY) {
      freedEstimate += (asset.pendingVulns.length - MAX_PENDING_VULNS_IN_MEMORY) * 250;
      asset.pendingVulns = asset.pendingVulns.slice(0, MAX_PENDING_VULNS_IN_MEMORY);
    }
  }
  if (state.passiveReconResults && ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit", "completed"].includes(completedPhase)) {
    try {
      freedEstimate += JSON.stringify(state.passiveReconResults).length * 2;
    } catch {
      freedEstimate += 5e4;
    }
    delete state.passiveReconResults;
    actions.push("passiveReconResults cleared");
  }
  const phaseCleanupMap = {
    vuln_detection: ["vulnAnalysis", "vulnAnalysisSuppressed", "fpSuppressionStats", "scanFeedbackLoop"],
    exploitation: ["attackChains", "essIntelligence"],
    post_exploit: ["cloudDetection"],
    completed: ["vulnAnalysis", "vulnAnalysisSuppressed", "fpSuppressionStats", "scanFeedbackLoop", "attackChains", "essIntelligence", "cloudDetection", "engagementContext"]
  };
  const keysToClean = phaseCleanupMap[completedPhase] || [];
  for (const key of keysToClean) {
    if (state[key]) {
      try {
        freedEstimate += JSON.stringify(state[key]).length * 2;
      } catch {
        freedEstimate += 2e4;
      }
      delete state[key];
      actions.push(`${key} cleared`);
    }
  }
  if (state.log && state.log.length > MAX_IN_MEMORY_LOGS) {
    const trimmed = state.log.length - MAX_IN_MEMORY_LOGS;
    freedEstimate += trimmed * 500;
    state.log = state.log.slice(-MAX_IN_MEMORY_LOGS);
    actions.push(`${trimmed} old logs trimmed`);
  }
  for (const log of state.log || []) {
    if (log.detail && log.detail.length > MAX_LOG_DETAIL_LENGTH) {
      freedEstimate += (log.detail.length - MAX_LOG_DETAIL_LENGTH) * 2;
      log.detail = log.detail.slice(0, MAX_LOG_DETAIL_LENGTH) + "\u2026";
    }
    if (log.data) {
      try {
        freedEstimate += JSON.stringify(log.data).length * 2;
      } catch {
        freedEstimate += 1e3;
      }
      delete log.data;
    }
  }
  for (const asset of state.assets || []) {
    if (asset.passiveRecon?.historicalUrls?.length > 5) {
      freedEstimate += (asset.passiveRecon.historicalUrls.length - 5) * 100;
      asset.passiveRecon.historicalUrls = asset.passiveRecon.historicalUrls.slice(0, 5);
    }
    if (asset.passiveRecon?.subdomains?.length > 10) {
      freedEstimate += (asset.passiveRecon.subdomains.length - 10) * 50;
      asset.passiveRecon.subdomains = asset.passiveRecon.subdomains.slice(0, 10);
    }
  }
  if (global.gc) {
    global.gc();
    actions.push("GC triggered");
  }
  return { freedEstimateBytes: freedEstimate, actions };
}
function capLLMContext(contexts, maxChars = MAX_LLM_CONTEXT_CHARS) {
  const nonEmpty = contexts.filter((c) => c.content && c.content.length > 0);
  if (nonEmpty.length === 0) return "";
  const totalChars = nonEmpty.reduce((sum, c) => sum + c.content.length, 0);
  if (totalChars <= maxChars) {
    return nonEmpty.map((c) => c.content).join("\n\n");
  }
  const sorted = [...nonEmpty].sort((a, b) => a.content.length - b.content.length);
  let remainingBudget = maxChars;
  const allocations = /* @__PURE__ */ new Map();
  for (let i = 0; i < sorted.length; i++) {
    const remaining = sorted.length - i;
    const fairShare = Math.floor(remainingBudget / remaining);
    const allocation = Math.min(sorted[i].content.length, fairShare);
    allocations.set(sorted[i].label, allocation);
    remainingBudget -= allocation;
  }
  const parts = [];
  for (const ctx of nonEmpty) {
    const budget = allocations.get(ctx.label) || 0;
    if (budget <= 0) continue;
    if (ctx.content.length <= budget) {
      parts.push(ctx.content);
    } else {
      parts.push(ctx.content.slice(0, budget) + "\n[...truncated for memory]");
    }
  }
  return parts.join("\n\n");
}
function emergencyEviction(state) {
  const actions = [];
  let freedEstimate = 0;
  for (const asset of state.assets || []) {
    for (const tr of asset.toolResults || []) {
      if (tr.outputPreview) {
        freedEstimate += tr.outputPreview.length * 2;
        tr.outputPreview = "";
      }
      if (tr.findings && tr.findings.length > 0) {
        freedEstimate += tr.findings.length * 200;
        tr.findings = [];
      }
    }
    if (asset.zapFindings && asset.zapFindings.length > 5) {
      freedEstimate += (asset.zapFindings.length - 5) * 200;
      asset.zapFindings = asset.zapFindings.slice(0, 5);
    }
    if (asset.passiveRecon) {
      try {
        freedEstimate += JSON.stringify(asset.passiveRecon).length * 2;
      } catch {
        freedEstimate += 5e3;
      }
      asset.passiveRecon = {
        technologies: (asset.passiveRecon.technologies || []).slice(0, 5),
        cloudProvider: asset.passiveRecon.cloudProvider,
        wafDetected: asset.passiveRecon.wafDetected,
        rawObservationCount: asset.passiveRecon.rawObservationCount || 0,
        sources: [],
        subdomains: [],
        ipAddresses: [],
        services: [],
        certificates: [],
        riskSignals: [],
        historicalUrls: []
      };
    }
    for (const ea of asset.exploitAttempts || []) {
      if (ea.reasoning && ea.reasoning.length > 100) {
        freedEstimate += (ea.reasoning.length - 100) * 2;
        ea.reasoning = ea.reasoning.slice(0, 100) + "\u2026";
      }
      if (ea.errorDetail && ea.errorDetail.length > 100) {
        freedEstimate += (ea.errorDetail.length - 100) * 2;
        ea.errorDetail = ea.errorDetail.slice(0, 100) + "\u2026";
      }
    }
  }
  actions.push("all toolResults/passiveRecon stripped");
  for (const key of [
    "vulnAnalysis",
    "vulnAnalysisSuppressed",
    "fpSuppressionStats",
    "scanFeedbackLoop",
    "attackChains",
    "essIntelligence",
    "cloudDetection",
    "engagementContext",
    "passiveReconResults",
    "metadata"
  ]) {
    if (state[key]) {
      try {
        freedEstimate += JSON.stringify(state[key]).length * 2;
      } catch {
        freedEstimate += 2e4;
      }
      delete state[key];
      actions.push(`${key} deleted`);
    }
  }
  if (state.log && state.log.length > 15) {
    freedEstimate += (state.log.length - 15) * 500;
    state.log = state.log.slice(-15);
  }
  for (const log of state.log || []) {
    if (log.detail && log.detail.length > 100) {
      freedEstimate += (log.detail.length - 100) * 2;
      log.detail = log.detail.slice(0, 100) + "\u2026";
    }
    if (log.data) {
      delete log.data;
      freedEstimate += 500;
    }
  }
  actions.push("logs aggressively trimmed");
  if (state.scanPlan) {
    try {
      freedEstimate += JSON.stringify(state.scanPlan).length * 2;
    } catch {
      freedEstimate += 1e4;
    }
    state.scanPlan = {
      overallStrategy: state.scanPlan.overallStrategy?.slice(0, 200) || "",
      assetPlans: [],
      generatedAt: state.scanPlan.generatedAt
    };
    actions.push("scanPlan stripped");
  }
  if (state.llmPlan && state.llmPlan.length > 200) {
    freedEstimate += (state.llmPlan.length - 200) * 2;
    state.llmPlan = state.llmPlan.slice(0, 200) + "\u2026";
    actions.push("llmPlan truncated");
  }
  if (global.gc) {
    global.gc();
    actions.push("GC triggered");
  }
  return { freedEstimateBytes: freedEstimate, actions };
}
function logMemoryProfile(engagementId, state, phase) {
  const mem = process.memoryUsage();
  const { totalBytes, breakdown } = estimateStateSize(state);
  const sorted = Object.entries(breakdown).sort(([, a], [, b]) => b - a).map(([k, v]) => `${k}=${(v / 1024).toFixed(0)}KB`).join(", ");
  console.log(
    `[MemProfile] Eng#${engagementId} phase=${phase}: stateEst=${(totalBytes / 1024).toFixed(0)}KB, heap=${(mem.heapUsed / 1024 / 1024).toFixed(0)}MB, rss=${(mem.rss / 1024 / 1024).toFixed(0)}MB | ` + sorted
  );
}
var MAX_LLM_CONTEXT_CHARS, POST_PHASE_OUTPUT_PREVIEW_CAP, POST_PHASE_FINDINGS_CAP, MAX_IN_MEMORY_LOGS, MAX_LOG_DETAIL_LENGTH, MAX_ZAP_FINDINGS_IN_MEMORY, MAX_VULNS_IN_MEMORY, MAX_PENDING_VULNS_IN_MEMORY, MAX_TOOL_RESULTS_PER_ASSET, MID_SCAN_OUTPUT_PREVIEW_CAP;
var init_memory_manager = __esm({
  "server/lib/memory-manager.ts"() {
    MAX_LLM_CONTEXT_CHARS = 12e3;
    POST_PHASE_OUTPUT_PREVIEW_CAP = 64;
    POST_PHASE_FINDINGS_CAP = 5;
    MAX_IN_MEMORY_LOGS = 40;
    MAX_LOG_DETAIL_LENGTH = 256;
    MAX_ZAP_FINDINGS_IN_MEMORY = 20;
    MAX_VULNS_IN_MEMORY = 50;
    MAX_PENDING_VULNS_IN_MEMORY = 20;
    MAX_TOOL_RESULTS_PER_ASSET = 30;
    MID_SCAN_OUTPUT_PREVIEW_CAP = 128;
  }
});

export {
  MAX_LLM_CONTEXT_CHARS,
  POST_PHASE_OUTPUT_PREVIEW_CAP,
  POST_PHASE_FINDINGS_CAP,
  MAX_IN_MEMORY_LOGS,
  MAX_LOG_DETAIL_LENGTH,
  MAX_ZAP_FINDINGS_IN_MEMORY,
  MAX_VULNS_IN_MEMORY,
  MAX_PENDING_VULNS_IN_MEMORY,
  MAX_TOOL_RESULTS_PER_ASSET,
  MID_SCAN_OUTPUT_PREVIEW_CAP,
  midScanCleanup,
  estimateStateSize,
  postPhaseCleanup,
  capLLMContext,
  emergencyEviction,
  logMemoryProfile,
  init_memory_manager
};
