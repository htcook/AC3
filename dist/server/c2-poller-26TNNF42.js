import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit/c2-poller.ts
function getPollingConfig() {
  return { intervalMs: POLL_INTERVAL_MS, maxCycles: MAX_POLL_CYCLES, stallThreshold: STALL_THRESHOLD_CYCLES, timeoutMs: POLL_TIMEOUT_MS };
}
function isOperationComplete(operationState) {
  return ["finished", "cleanup", "paused", "out_of_time"].includes(operationState);
}
function detectStall(pollHistory, threshold) {
  if (pollHistory.length < threshold) return false;
  const lastN = pollHistory.slice(-threshold);
  return lastN.every((count) => count === 0);
}
function buildPollUrl(calderaBaseUrl, operationId) {
  return `${calderaBaseUrl}/api/v2/operations/${operationId}`;
}
function extractNewLinks(currentLinks, previousLinkIds) {
  return currentLinks.filter((link) => !previousLinkIds.has(link.id || link.unique));
}
async function monitorC2Callbacks(ctx, operationId) {
  const { state } = ctx;
  const { addLog, broadcastOpsUpdate } = ctx.helpers;
  const result = { agentCount: 0, processedLinkCount: 0, operationState: "unknown", pollCount: 0 };
  const calderaBaseUrl = process.env.CALDERA_BASE_URL || "http://localhost:8888";
  const calderaApiKey = process.env.CALDERA_API_KEY || "";
  const pollUrl = buildPollUrl(calderaBaseUrl, operationId);
  const previousLinkIds = /* @__PURE__ */ new Set();
  const pollHistory = [];
  for (let cycle = 0; cycle < MAX_POLL_CYCLES; cycle++) {
    result.pollCount++;
    try {
      const res = await fetch(pollUrl, { headers: { "KEY": calderaApiKey }, signal: AbortSignal.timeout(POLL_TIMEOUT_MS) });
      if (!res.ok) {
        pollHistory.push(0);
        continue;
      }
      const operation = await res.json();
      result.operationState = operation.state || "unknown";
      result.agentCount = (operation.host_group || []).length;
      const allLinks = operation.chain || [];
      const newLinks = extractNewLinks(allLinks, previousLinkIds);
      pollHistory.push(newLinks.length);
      for (const link of newLinks) {
        previousLinkIds.add(link.id || link.unique);
        result.processedLinkCount++;
        broadcastOpsUpdate(state.engagementId, { type: "c2_link_processed", operationId, linkId: link.id, ability: link.ability?.name || "unknown", status: link.status });
      }
      if (isOperationComplete(result.operationState)) break;
      if (detectStall(pollHistory, STALL_THRESHOLD_CYCLES)) break;
    } catch (err) {
      pollHistory.push(0);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return result;
}
var POLL_INTERVAL_MS, MAX_POLL_CYCLES, STALL_THRESHOLD_CYCLES, POLL_TIMEOUT_MS;
var init_c2_poller = __esm({
  "server/lib/post-exploit/c2-poller.ts"() {
    POLL_INTERVAL_MS = 15e3;
    MAX_POLL_CYCLES = 40;
    STALL_THRESHOLD_CYCLES = 6;
    POLL_TIMEOUT_MS = 1e4;
  }
});
init_c2_poller();
export {
  buildPollUrl,
  detectStall,
  extractNewLinks,
  getPollingConfig,
  isOperationComplete,
  monitorC2Callbacks
};
