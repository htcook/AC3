/**
 * Context Engine Contribution Tracker
 *
 * Records which knowledge sources contributed to each exploit decision in the
 * engagement orchestrator. This enables the dashboard widget to show a breakdown
 * of what intelligence informed each LLM call.
 *
 * Sources tracked:
 *  - P0: exploit-knowledge-store (recipe DB)
 *  - P1: exploit-learning-engine (prioritization)
 *  - P2: self-correction prompts (retry context)
 *  - P3: injection-tools-knowledge + offensive-tools-knowledge
 *  - P4: exploit-selection-intelligence
 *  - P5: exploit-preflight checks
 *  - P6: ember-catalog-intelligence (threat actor catalog)
 *  - P7: threat-actor-learning-context
 *  - P8: hacking-articles playbooks
 *  - DFIR: dfir-report-ingestion observations
 *  - IOC: ioc-ttp-reverse-engineer mappings
 *  - DI: di-threat-enrichment
 *  - Phishing: phishing-catalog-integration
 *  - C2: c2-tactical-knowledge
 */

import { getDb } from "../db";
import { sql } from "drizzle-orm";

// ─── In-Memory Contribution Log ─────────────────────────────────────────────
// We keep a rolling buffer in memory and flush to DB periodically.
// This avoids blocking the hot exploit path with DB writes.

export interface ContextContribution {
  id: string;
  engagementId: number;
  exploitTarget: string;
  exploitCve: string;
  timestamp: number;
  sources: ContextSourceEntry[];
  totalContextLength: number;
  cappedContextLength: number;
  decisionOutcome: "exploit_attempted" | "exploit_skipped" | "exploit_deferred";
}

export interface ContextSourceEntry {
  sourceId: string;
  sourceName: string;
  category: "knowledge_store" | "learning_engine" | "threat_intel" | "tools" | "dfir" | "ioc" | "phishing" | "c2";
  tokensContributed: number;
  itemCount: number;
  wasActive: boolean;
  detail?: string;
}

const contributionBuffer: ContextContribution[] = [];
const MAX_BUFFER_SIZE = 500;

// ─── Recording API ──────────────────────────────────────────────────────────

/**
 * Record a context engine contribution for an exploit decision.
 * Called from the engagement orchestrator during the exploit phase.
 */
export function recordContextContribution(contribution: ContextContribution): void {
  contributionBuffer.push(contribution);
  if (contributionBuffer.length > MAX_BUFFER_SIZE) {
    contributionBuffer.shift(); // Drop oldest
  }
}

/**
 * Build a contribution record from the context blocks assembled by _capLLMContext.
 * This is the main integration point — called right after context assembly.
 */
export function buildContributionFromBlocks(
  engagementId: number,
  target: string,
  cve: string,
  blocks: Array<{ label: string; content: string }>,
  cappedResult: string,
  outcome: "exploit_attempted" | "exploit_skipped" | "exploit_deferred",
): ContextContribution {
  const SOURCE_MAP: Record<string, { name: string; category: ContextSourceEntry["category"] }> = {
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
    "bankingDomain": { name: "Banking Domain Knowledge", category: "knowledge_store" },
  };

  const sources: ContextSourceEntry[] = blocks.map(block => {
    const mapping = SOURCE_MAP[block.label] || { name: block.label, category: "knowledge_store" as const };
    return {
      sourceId: block.label,
      sourceName: mapping.name,
      category: mapping.category,
      tokensContributed: Math.ceil(block.content.length / 4), // rough token estimate
      itemCount: (block.content.match(/\n---\n|\n###\s/g) || []).length + (block.content.length > 0 ? 1 : 0),
      wasActive: block.content.length > 0,
      detail: block.content.length > 200 ? block.content.substring(0, 200) + "..." : block.content,
    };
  });

  const contribution: ContextContribution = {
    id: `ctx-${engagementId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    engagementId,
    exploitTarget: target,
    exploitCve: cve,
    timestamp: Date.now(),
    sources,
    totalContextLength: blocks.reduce((sum, b) => sum + b.content.length, 0),
    cappedContextLength: cappedResult.length,
    decisionOutcome: outcome,
  };

  recordContextContribution(contribution);
  return contribution;
}

// ─── Query API ──────────────────────────────────────────────────────────────

/**
 * Get context contributions for the dashboard widget.
 */
export async function getContextContributions(options: {
  engagementId?: number;
  limit?: number;
}): Promise<{
  contributions: ContextContribution[];
  total: number;
}> {
  const { engagementId, limit = 20 } = options;

  let filtered = [...contributionBuffer];
  if (engagementId) {
    filtered = filtered.filter(c => c.engagementId === engagementId);
  }

  // Sort by most recent first
  filtered.sort((a, b) => b.timestamp - a.timestamp);

  return {
    contributions: filtered.slice(0, limit),
    total: filtered.length,
  };
}

/**
 * Get aggregate stats for the context engine dashboard widget.
 */
export async function getContextEngineStats(): Promise<{
  totalDecisions: number;
  sourceBreakdown: Array<{
    sourceId: string;
    sourceName: string;
    category: string;
    totalContributions: number;
    avgTokens: number;
    activationRate: number;
  }>;
  avgContextLength: number;
  avgCappedLength: number;
  outcomeBreakdown: Record<string, number>;
  recentEngagements: Array<{ engagementId: number; decisionCount: number; lastDecision: number }>;
  articleIngestionStats: {
    totalPlaybooks: number;
    totalObservations: number;
    totalChains: number;
    bySource: Record<string, number>;
    byPlatform: Record<string, number>;
    byDifficulty: Record<string, number>;
  };
}> {
  // Source aggregation
  const sourceAgg = new Map<string, {
    sourceName: string;
    category: string;
    totalContributions: number;
    totalTokens: number;
    activeCount: number;
  }>();

  const outcomeBreakdown: Record<string, number> = {};
  const engagementMap = new Map<number, { count: number; last: number }>();

  for (const c of contributionBuffer) {
    // Outcomes
    outcomeBreakdown[c.decisionOutcome] = (outcomeBreakdown[c.decisionOutcome] || 0) + 1;

    // Engagements
    const eng = engagementMap.get(c.engagementId) || { count: 0, last: 0 };
    eng.count++;
    eng.last = Math.max(eng.last, c.timestamp);
    engagementMap.set(c.engagementId, eng);

    // Sources
    for (const src of c.sources) {
      const agg = sourceAgg.get(src.sourceId) || {
        sourceName: src.sourceName,
        category: src.category,
        totalContributions: 0,
        totalTokens: 0,
        activeCount: 0,
      };
      agg.totalContributions++;
      agg.totalTokens += src.tokensContributed;
      if (src.wasActive) agg.activeCount++;
      sourceAgg.set(src.sourceId, agg);
    }
  }

  const totalDecisions = contributionBuffer.length;
  const avgContextLength = totalDecisions > 0
    ? Math.round(contributionBuffer.reduce((s, c) => s + c.totalContextLength, 0) / totalDecisions)
    : 0;
  const avgCappedLength = totalDecisions > 0
    ? Math.round(contributionBuffer.reduce((s, c) => s + c.cappedContextLength, 0) / totalDecisions)
    : 0;

  const sourceBreakdown = [...sourceAgg.entries()].map(([sourceId, agg]) => ({
    sourceId,
    sourceName: agg.sourceName,
    category: agg.category,
    totalContributions: agg.totalContributions,
    avgTokens: agg.totalContributions > 0 ? Math.round(agg.totalTokens / agg.totalContributions) : 0,
    activationRate: agg.totalContributions > 0 ? Math.round((agg.activeCount / agg.totalContributions) * 100) : 0,
  })).sort((a, b) => b.totalContributions - a.totalContributions);

  const recentEngagements = [...engagementMap.entries()]
    .map(([engagementId, { count, last }]) => ({ engagementId, decisionCount: count, lastDecision: last }))
    .sort((a, b) => b.lastDecision - a.lastDecision)
    .slice(0, 10);

  // Get article ingestion stats
  let articleIngestionStats = {
    totalPlaybooks: 0,
    totalObservations: 0,
    totalChains: 0,
    bySource: {} as Record<string, number>,
    byPlatform: {} as Record<string, number>,
    byDifficulty: {} as Record<string, number>,
  };
  try {
    const { getIngestionStats } = await import("./hacking-articles-ingestion");
    articleIngestionStats = await getIngestionStats();
  } catch { /* non-fatal */ }

  return {
    totalDecisions,
    sourceBreakdown,
    avgContextLength,
    avgCappedLength,
    outcomeBreakdown,
    recentEngagements,
    articleIngestionStats,
  };
}

/**
 * Clear the contribution buffer (for testing).
 */
export function clearContributionBuffer(): void {
  contributionBuffer.length = 0;
}
