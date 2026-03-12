/**
 * Threat Actor Learning Context Builder
 * ──────────────────────────────────────
 * Pulls live threat attribution data from the DO learning engine and formats it
 * as LLM context for injection into the engagement orchestrator pipeline.
 *
 * This bridges the gap between:
 *   - Static threat group knowledge (threat-group-knowledge.ts) — curated TTPs, tools, CVEs
 *   - Live learning data (learning-engine-api.ts) — actual attribution scores from scans
 *
 * The combined context helps the LLM make better exploitation decisions by knowing
 * which threat groups are most relevant to the current target and how confident
 * the learning engine is about those attributions.
 */

import {
  getThreatStats,
  getThreatTrend,
  getLearningDashboard,
  type ThreatScoreInput,
  scoreThreatAttribution,
} from "./learning-engine-api";

const LOG = "[ThreatActorLearning]";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ThreatLearningContext {
  topGroups: Array<{
    groupId: string;
    groupName: string;
    matchCount: number;
    avgConfidence: number;
  }>;
  topTechniques: Array<{
    techniqueId: string;
    techniqueName: string;
    detections: number;
  }>;
  topCVEs: Array<{
    cve: string;
    detections: number;
  }>;
  catalogSummary: {
    totalGroups: number;
    totalTTPs: number;
    totalCVEs: number;
  };
  recentTrend: Array<{
    topGroup: string;
    ttpsMatched: number;
    cvesMatched: number;
    confidence: number;
    timestamp: string;
  }>;
}

// ─── Cache ──────────────────────────────────────────────────────────────────

let _cachedContext: ThreatLearningContext | null = null;
let _cacheTimestamp = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ─── Data Fetchers ──────────────────────────────────────────────────────────

/**
 * Fetch live threat learning data from the DO learning engine.
 * Caches for 5 minutes to avoid hammering the API during multi-asset scans.
 */
export async function fetchThreatLearningData(): Promise<ThreatLearningContext | null> {
  const now = Date.now();
  if (_cachedContext && now - _cacheTimestamp < CACHE_TTL_MS) {
    return _cachedContext;
  }

  try {
    const [statsResult, trendResult, dashboardResult] = await Promise.allSettled([
      getThreatStats(),
      getThreatTrend(10),
      getLearningDashboard(),
    ]);

    const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
    const trend = trendResult.status === "fulfilled" ? trendResult.value : null;
    const dashboard = dashboardResult.status === "fulfilled" ? dashboardResult.value : null;

    const ctx: ThreatLearningContext = {
      topGroups: stats?.topGroups || [],
      topTechniques: (stats?.topTechniques || []).map((t: any) => ({
        techniqueId: t.technique_id || t.techniqueId || "",
        techniqueName: t.technique_name || t.techniqueName || "",
        detections: t.detections ?? 0,
      })),
      topCVEs: (stats?.topCVEs || []).map((c: any) => ({
        cve: c.cve || c.cve_id || "",
        detections: c.detections ?? 0,
      })),
      catalogSummary: {
        totalGroups: dashboard?.threatActor?.totalGroups ?? stats?.catalogSummary?.totalGroups ?? 0,
        totalTTPs: dashboard?.threatActor?.totalTTPs ?? stats?.catalogSummary?.totalTTPs ?? 0,
        totalCVEs: dashboard?.threatActor?.totalCVEs ?? stats?.catalogSummary?.totalCVEs ?? 0,
      },
      recentTrend: trend?.trend || [],
    };

    _cachedContext = ctx;
    _cacheTimestamp = now;
    console.log(`${LOG} Fetched threat learning data: ${ctx.topGroups.length} groups, ${ctx.topTechniques.length} techniques`);
    return ctx;
  } catch (err: any) {
    console.warn(`${LOG} Failed to fetch threat learning data: ${err.message}`);
    return _cachedContext; // return stale cache if available
  }
}

// ─── Context Builders for LLM Injection ─────────────────────────────────────

/**
 * Build threat actor learning context for scan plan generation.
 * Enriches the static threat group knowledge with live attribution data.
 */
export async function buildThreatActorLearningContext(): Promise<string> {
  const data = await fetchThreatLearningData();
  if (!data || (data.topGroups.length === 0 && data.topTechniques.length === 0)) {
    return "";
  }

  let ctx = `\n=== THREAT ACTOR LEARNING ENGINE — LIVE ATTRIBUTION DATA ===\n`;
  ctx += `The learning engine has analyzed scans against ${data.catalogSummary.totalGroups} threat groups, `;
  ctx += `${data.catalogSummary.totalTTPs} TTPs, and ${data.catalogSummary.totalCVEs} CVEs.\n\n`;

  // Top threat groups by detection frequency
  if (data.topGroups.length > 0) {
    ctx += `TOP THREAT GROUPS BY DETECTION FREQUENCY:\n`;
    for (const g of data.topGroups.slice(0, 10)) {
      ctx += `  - ${g.groupName} (${g.matchCount} matches, ${Math.round(g.avgConfidence)}% avg confidence)\n`;
    }
    ctx += `\n`;
  }

  // Top techniques detected
  if (data.topTechniques.length > 0) {
    ctx += `MOST FREQUENTLY DETECTED TECHNIQUES:\n`;
    for (const t of data.topTechniques.slice(0, 10)) {
      ctx += `  - ${t.techniqueId} ${t.techniqueName} (${t.detections} detections)\n`;
    }
    ctx += `\n`;
  }

  // Top CVEs detected
  if (data.topCVEs.length > 0) {
    ctx += `MOST FREQUENTLY DETECTED CVEs:\n`;
    for (const c of data.topCVEs.slice(0, 10)) {
      ctx += `  - ${c.cve} (${c.detections} detections)\n`;
    }
    ctx += `\n`;
  }

  // Recent attribution trend
  if (data.recentTrend.length > 0) {
    ctx += `RECENT ATTRIBUTION TREND:\n`;
    for (const t of data.recentTrend.slice(0, 5)) {
      ctx += `  - ${t.topGroup}: ${t.ttpsMatched} TTPs, ${t.cvesMatched} CVEs, ${Math.round(t.confidence)}% confidence\n`;
    }
    ctx += `\n`;
  }

  ctx += `INSTRUCTIONS: Use this live threat attribution data to prioritize scanning for techniques and CVEs `;
  ctx += `associated with the most frequently detected threat groups. If the target's technology stack matches `;
  ctx += `patterns associated with specific groups, escalate those checks. Cross-reference findings against the `;
  ctx += `top CVEs list to identify high-confidence threat actor overlap.\n`;

  return ctx;
}

/**
 * Build threat actor learning context for vulnerability synthesis.
 * Helps the LLM correlate discovered vulns with known threat group patterns.
 */
export async function buildThreatActorVulnContext(
  discoveredCVEs: string[],
  discoveredTechniques: string[],
): Promise<string> {
  const data = await fetchThreatLearningData();
  if (!data || data.topGroups.length === 0) {
    return "";
  }

  let ctx = `\n=== THREAT ACTOR CORRELATION — LIVE LEARNING DATA ===\n`;

  // Cross-reference discovered CVEs with top detected CVEs
  const matchedCVEs = discoveredCVEs.filter(cve =>
    data.topCVEs.some(tc => tc.cve === cve)
  );
  if (matchedCVEs.length > 0) {
    ctx += `DISCOVERED CVEs MATCHING THREAT ACTOR PATTERNS:\n`;
    for (const cve of matchedCVEs) {
      const match = data.topCVEs.find(tc => tc.cve === cve);
      ctx += `  - ${cve} (detected ${match?.detections ?? 0} times in threat actor scans)\n`;
    }
    ctx += `  → These CVEs are actively exploited by known threat groups. BOOST severity.\n\n`;
  }

  // Cross-reference discovered techniques
  const matchedTechs = discoveredTechniques.filter(tech =>
    data.topTechniques.some(tt =>
      tt.techniqueId === tech || tt.techniqueName.toLowerCase().includes(tech.toLowerCase())
    )
  );
  if (matchedTechs.length > 0) {
    ctx += `DISCOVERED TECHNIQUES MATCHING THREAT ACTOR PATTERNS:\n`;
    for (const tech of matchedTechs) {
      const match = data.topTechniques.find(tt =>
        tt.techniqueId === tech || tt.techniqueName.toLowerCase().includes(tech.toLowerCase())
      );
      ctx += `  - ${tech} → ${match?.techniqueName || tech} (${match?.detections ?? 0} detections)\n`;
    }
    ctx += `  → These techniques are commonly used by tracked threat groups. Flag for further investigation.\n\n`;
  }

  // Top groups to watch
  ctx += `TOP THREAT GROUPS TO CORRELATE AGAINST:\n`;
  for (const g of data.topGroups.slice(0, 5)) {
    ctx += `  - ${g.groupName}: ${g.matchCount} matches, ${Math.round(g.avgConfidence)}% confidence\n`;
  }

  return ctx;
}

/**
 * Score findings from an engagement against the threat actor catalog.
 * Called after vuln detection to record learning events.
 */
export async function scoreEngagementThreatAttribution(opts: {
  sessionId: string;
  engagementId: string;
  targetUrl?: string;
  ttps: { techniqueId?: string; techniqueName?: string; tactic?: string; cve?: string; tool?: string }[];
  cves: string[];
}): Promise<any> {
  try {
    const result = await scoreThreatAttribution({
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetUrl: opts.targetUrl,
      scanType: "engagement",
      ttps: opts.ttps,
      cves: opts.cves,
    });
    console.log(`${LOG} Scored threat attribution for engagement ${opts.engagementId}: ${JSON.stringify(result?.summary || {})}`);
    // Invalidate cache so next context build picks up new data
    _cachedContext = null;
    _cacheTimestamp = 0;
    return result;
  } catch (err: any) {
    console.warn(`${LOG} Failed to score threat attribution: ${err.message}`);
    return null;
  }
}

/**
 * Clear the cached threat learning data (useful after a new scan completes).
 */
export function clearThreatLearningCache(): void {
  _cachedContext = null;
  _cacheTimestamp = 0;
}
