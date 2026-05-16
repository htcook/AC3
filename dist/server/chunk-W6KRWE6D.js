import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/context-engine-tracker.ts
var context_engine_tracker_exports = {};
__export(context_engine_tracker_exports, {
  buildContributionFromBlocks: () => buildContributionFromBlocks,
  clearContributionBuffer: () => clearContributionBuffer,
  getContextContributions: () => getContextContributions,
  getContextEngineStats: () => getContextEngineStats,
  recordContextContribution: () => recordContextContribution
});
function recordContextContribution(contribution) {
  contributionBuffer.push(contribution);
  if (contributionBuffer.length > MAX_BUFFER_SIZE) {
    contributionBuffer.shift();
  }
}
function buildContributionFromBlocks(engagementId, target, cve, blocks, cappedResult, outcome) {
  const SOURCE_MAP = {
    "exploitRecipes": { name: "Exploit Knowledge Store (P0)", category: "knowledge_store" },
    "prioritizedVulns": { name: "Exploit Learning Engine (P1)", category: "learning_engine" },
    "selfCorrection": { name: "Self-Correction Prompts (P2)", category: "learning_engine" },
    "injectionTools": { name: "Injection Tools Knowledge (P3)", category: "tools" },
    "offensiveTools": { name: "Offensive Tools Knowledge (P3)", category: "tools" },
    "exploitSelection": { name: "Exploit Selection Intelligence (P4)", category: "knowledge_store" },
    "preflightChecks": { name: "Exploit Preflight (P5)", category: "knowledge_store" },
    "threatActorCatalog": { name: "Threat Actor Catalog (P6)", category: "threat_intel" },
    "threatActorLearning": { name: "Threat Actor Learning (P7)", category: "threat_intel" },
    "hackingArticles": { name: "Hacking Articles Playbooks (P8)", category: "knowledge_store" },
    "dfirObservations": { name: "DFIR Report Observations", category: "dfir" },
    "iocTtpMappings": { name: "IOC-to-TTP Mappings", category: "ioc" },
    "diThreatEnrichment": { name: "DI Threat Enrichment", category: "threat_intel" },
    "phishingKnowledge": { name: "Phishing Catalog", category: "phishing" },
    "c2TacticalKnowledge": { name: "C2 Tactical Knowledge", category: "c2" },
    // Catch-all for other context blocks
    "chains": { name: "Attack Chains", category: "threat_intel" },
    "ontology": { name: "Ontology Context", category: "knowledge_store" },
    "bugBounty": { name: "Bug Bounty Intel", category: "knowledge_store" },
    "owasp": { name: "OWASP Context", category: "knowledge_store" },
    "zapFindings": { name: "ZAP Findings", category: "tools" },
    "burpFindings": { name: "Burp Findings", category: "tools" },
    "nucleiFindings": { name: "Nuclei Findings", category: "tools" },
    "bankingDomain": { name: "Banking Domain Knowledge", category: "knowledge_store" }
  };
  const sources = blocks.map((block) => {
    const mapping = SOURCE_MAP[block.label] || { name: block.label, category: "knowledge_store" };
    return {
      sourceId: block.label,
      sourceName: mapping.name,
      category: mapping.category,
      tokensContributed: Math.ceil(block.content.length / 4),
      // rough token estimate
      itemCount: (block.content.match(/\n---\n|\n###\s/g) || []).length + (block.content.length > 0 ? 1 : 0),
      wasActive: block.content.length > 0,
      detail: block.content.length > 200 ? block.content.substring(0, 200) + "..." : block.content
    };
  });
  const contribution = {
    id: `ctx-${engagementId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    engagementId,
    exploitTarget: target,
    exploitCve: cve,
    timestamp: Date.now(),
    sources,
    totalContextLength: blocks.reduce((sum, b) => sum + b.content.length, 0),
    cappedContextLength: cappedResult.length,
    decisionOutcome: outcome
  };
  recordContextContribution(contribution);
  return contribution;
}
async function getContextContributions(options) {
  const { engagementId, limit = 20 } = options;
  let filtered = [...contributionBuffer];
  if (engagementId) {
    filtered = filtered.filter((c) => c.engagementId === engagementId);
  }
  filtered.sort((a, b) => b.timestamp - a.timestamp);
  return {
    contributions: filtered.slice(0, limit),
    total: filtered.length
  };
}
async function getContextEngineStats() {
  const sourceAgg = /* @__PURE__ */ new Map();
  const outcomeBreakdown = {};
  const engagementMap = /* @__PURE__ */ new Map();
  for (const c of contributionBuffer) {
    outcomeBreakdown[c.decisionOutcome] = (outcomeBreakdown[c.decisionOutcome] || 0) + 1;
    const eng = engagementMap.get(c.engagementId) || { count: 0, last: 0 };
    eng.count++;
    eng.last = Math.max(eng.last, c.timestamp);
    engagementMap.set(c.engagementId, eng);
    for (const src of c.sources) {
      const agg = sourceAgg.get(src.sourceId) || {
        sourceName: src.sourceName,
        category: src.category,
        totalContributions: 0,
        totalTokens: 0,
        activeCount: 0
      };
      agg.totalContributions++;
      agg.totalTokens += src.tokensContributed;
      if (src.wasActive) agg.activeCount++;
      sourceAgg.set(src.sourceId, agg);
    }
  }
  const totalDecisions = contributionBuffer.length;
  const avgContextLength = totalDecisions > 0 ? Math.round(contributionBuffer.reduce((s, c) => s + c.totalContextLength, 0) / totalDecisions) : 0;
  const avgCappedLength = totalDecisions > 0 ? Math.round(contributionBuffer.reduce((s, c) => s + c.cappedContextLength, 0) / totalDecisions) : 0;
  const sourceBreakdown = [...sourceAgg.entries()].map(([sourceId, agg]) => ({
    sourceId,
    sourceName: agg.sourceName,
    category: agg.category,
    totalContributions: agg.totalContributions,
    avgTokens: agg.totalContributions > 0 ? Math.round(agg.totalTokens / agg.totalContributions) : 0,
    activationRate: agg.totalContributions > 0 ? Math.round(agg.activeCount / agg.totalContributions * 100) : 0
  })).sort((a, b) => b.totalContributions - a.totalContributions);
  const recentEngagements = [...engagementMap.entries()].map(([engagementId, { count, last }]) => ({ engagementId, decisionCount: count, lastDecision: last })).sort((a, b) => b.lastDecision - a.lastDecision).slice(0, 10);
  let articleIngestionStats = {
    totalPlaybooks: 0,
    totalObservations: 0,
    totalChains: 0,
    bySource: {},
    byPlatform: {},
    byDifficulty: {}
  };
  try {
    const { getIngestionStats } = await import("./hacking-articles-ingestion-YR2M6WXW.js");
    articleIngestionStats = await getIngestionStats();
  } catch {
  }
  return {
    totalDecisions,
    sourceBreakdown,
    avgContextLength,
    avgCappedLength,
    outcomeBreakdown,
    recentEngagements,
    articleIngestionStats
  };
}
function clearContributionBuffer() {
  contributionBuffer.length = 0;
}
var contributionBuffer, MAX_BUFFER_SIZE;
var init_context_engine_tracker = __esm({
  "server/lib/context-engine-tracker.ts"() {
    contributionBuffer = [];
    MAX_BUFFER_SIZE = 500;
  }
});

export {
  recordContextContribution,
  buildContributionFromBlocks,
  getContextContributions,
  getContextEngineStats,
  clearContributionBuffer,
  context_engine_tracker_exports,
  init_context_engine_tracker
};
