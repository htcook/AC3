/**
 * ═══════════════════════════════════════════════════════════════════════
 * EPSS (Exploit Prediction Scoring System) Service
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Fetches EPSS scores from the FIRST.org EPSS API as a standalone source,
 * independent of Coalition ESS. Provides dual-axis prioritization when
 * combined with CISA KEV status.
 *
 * EPSS scores represent the probability (0.0–1.0) that a CVE will be
 * exploited in the wild within the next 30 days.
 *
 * Used by:
 *   - engagement-orchestrator.ts (KEV enrichment phase)
 *   - enhanced-exploit-orchestration.ts (exploit prioritization)
 *   - functional-exploit-generator.ts (LLM context enrichment)
 */

// ─── Types ──────────────────────────────────────────────────────────────

export interface EpssScore {
  cve: string;
  epss: number;       // 0.0–1.0 probability of exploitation in next 30 days
  percentile: number;  // 0.0–1.0 percentile rank among all scored CVEs
}

export interface EpssBatchResult {
  scores: EpssScore[];
  /** CVEs that had no EPSS data */
  missing: string[];
  /** Fetch timestamp */
  fetchedAt: number;
}

export interface EpssPrioritization {
  cve: string;
  epss: number;
  percentile: number;
  kevListed: boolean;
  /** Combined priority tier based on EPSS + KEV */
  priorityTier: 'critical' | 'high' | 'medium' | 'low';
  /** Human-readable rationale */
  rationale: string;
}

// ─── In-Memory Cache ────────────────────────────────────────────────────

const epssCache = new Map<string, { score: EpssScore; cachedAt: number }>();
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

// ─── FIRST.org EPSS API ─────────────────────────────────────────────────

const EPSS_API_BASE = 'https://api.first.org/data/v1/epss';

/**
 * Fetch EPSS scores for a batch of CVEs from the FIRST.org API.
 * Handles batching (max 100 CVEs per request) and caching.
 */
export async function fetchEpssScores(cves: string[]): Promise<EpssBatchResult> {
  const uniqueCves = [...new Set(cves.filter(c => c.startsWith('CVE-')))];
  if (uniqueCves.length === 0) {
    return { scores: [], missing: [], fetchedAt: Date.now() };
  }

  const results: EpssScore[] = [];
  const toFetch: string[] = [];

  // Check cache first
  for (const cve of uniqueCves) {
    const cached = epssCache.get(cve);
    if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
      results.push(cached.score);
    } else {
      toFetch.push(cve);
    }
  }

  // Fetch uncached CVEs in batches of 100
  const BATCH_SIZE = 100;
  for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
    const batch = toFetch.slice(i, i + BATCH_SIZE);
    try {
      const url = `${EPSS_API_BASE}?cve=${batch.join(',')}`;
      const response = await fetch(url, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(15000),
      });

      if (!response.ok) {
        console.error(`[EPSS] API returned ${response.status} for batch ${i / BATCH_SIZE + 1}`);
        continue;
      }

      const data = await response.json() as {
        status: string;
        'status-code': number;
        version: string;
        total: number;
        data: Array<{ cve: string; epss: string; percentile: string; date: string }>;
      };

      if (data.data) {
        for (const entry of data.data) {
          const score: EpssScore = {
            cve: entry.cve,
            epss: parseFloat(entry.epss) || 0,
            percentile: parseFloat(entry.percentile) || 0,
          };
          results.push(score);
          epssCache.set(entry.cve, { score, cachedAt: Date.now() });
        }
      }
    } catch (err: any) {
      console.error(`[EPSS] Failed to fetch batch ${i / BATCH_SIZE + 1}:`, err.message);
    }
  }

  const fetchedCves = new Set(results.map(r => r.cve));
  const missing = uniqueCves.filter(c => !fetchedCves.has(c));

  return { scores: results, missing, fetchedAt: Date.now() };
}

/**
 * Get a single CVE's EPSS score (cached).
 */
export async function getEpssScore(cve: string): Promise<EpssScore | null> {
  const result = await fetchEpssScores([cve]);
  return result.scores[0] || null;
}

// ─── Dual-Axis Prioritization ───────────────────────────────────────────

/**
 * Combine EPSS scores with KEV status to produce a dual-axis priority tier.
 *
 * Priority Matrix:
 *   KEV + EPSS >= 0.1  → CRITICAL (actively exploited + high prediction)
 *   KEV + EPSS < 0.1   → HIGH (actively exploited, lower prediction)
 *   !KEV + EPSS >= 0.4 → HIGH (not KEV but very likely to be exploited)
 *   !KEV + EPSS >= 0.1 → MEDIUM (moderate exploitation probability)
 *   !KEV + EPSS < 0.1  → LOW (low exploitation probability)
 */
export function prioritizeCveWithEpss(
  cve: string,
  epssScore: number,
  percentile: number,
  kevListed: boolean,
): EpssPrioritization {
  let priorityTier: EpssPrioritization['priorityTier'];
  let rationale: string;

  if (kevListed && epssScore >= 0.1) {
    priorityTier = 'critical';
    rationale = `CRITICAL: ${cve} is on CISA KEV (actively exploited) AND has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Immediate exploitation testing required.`;
  } else if (kevListed) {
    priorityTier = 'high';
    rationale = `HIGH: ${cve} is on CISA KEV (actively exploited) with ${(epssScore * 100).toFixed(1)}% EPSS probability. KEV listing alone warrants priority testing.`;
  } else if (epssScore >= 0.4) {
    priorityTier = 'high';
    rationale = `HIGH: ${cve} has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Very high likelihood of exploitation within 30 days.`;
  } else if (epssScore >= 0.1) {
    priorityTier = 'medium';
    rationale = `MEDIUM: ${cve} has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Moderate exploitation likelihood.`;
  } else {
    priorityTier = 'low';
    rationale = `LOW: ${cve} has ${(epssScore * 100).toFixed(2)}% EPSS probability. Lower exploitation likelihood, but still worth testing if resources allow.`;
  }

  return { cve, epss: epssScore, percentile, kevListed, priorityTier, rationale };
}

/**
 * Batch prioritize CVEs with EPSS + KEV dual-axis scoring.
 * Returns sorted by priority (critical first, then by EPSS score descending).
 */
export async function batchPrioritizeCves(
  cves: string[],
  kevCveSet: Set<string>,
): Promise<EpssPrioritization[]> {
  const epssResult = await fetchEpssScores(cves);
  const epssMap = new Map(epssResult.scores.map(s => [s.cve, s]));

  const prioritized: EpssPrioritization[] = cves.map(cve => {
    const epss = epssMap.get(cve);
    return prioritizeCveWithEpss(
      cve,
      epss?.epss ?? 0,
      epss?.percentile ?? 0,
      kevCveSet.has(cve),
    );
  });

  // Sort: critical > high > medium > low, then by EPSS descending
  const tierOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  prioritized.sort((a, b) => {
    const tierDiff = tierOrder[a.priorityTier] - tierOrder[b.priorityTier];
    if (tierDiff !== 0) return tierDiff;
    return b.epss - a.epss;
  });

  return prioritized;
}

// ─── LLM Context Builder ────────────────────────────────────────────────

/**
 * Build EPSS context string for injection into LLM exploit generation prompts.
 */
export function buildEpssContextForLlm(prioritizations: EpssPrioritization[]): string {
  if (prioritizations.length === 0) return '';

  const critical = prioritizations.filter(p => p.priorityTier === 'critical');
  const high = prioritizations.filter(p => p.priorityTier === 'high');

  let context = '\n\n📊 EPSS EXPLOIT PREDICTION SCORING:\n';
  context += `Analyzed ${prioritizations.length} CVEs against FIRST.org EPSS model.\n`;

  if (critical.length > 0) {
    context += `\n🔴 CRITICAL PRIORITY (KEV + High EPSS):\n`;
    for (const p of critical.slice(0, 10)) {
      context += `  - ${p.cve}: EPSS ${(p.epss * 100).toFixed(1)}% (${(p.percentile * 100).toFixed(0)}th pctl) — KEV-listed, actively exploited\n`;
    }
  }

  if (high.length > 0) {
    context += `\n🟠 HIGH PRIORITY:\n`;
    for (const p of high.slice(0, 10)) {
      context += `  - ${p.cve}: EPSS ${(p.epss * 100).toFixed(1)}% (${(p.percentile * 100).toFixed(0)}th pctl)${p.kevListed ? ' — KEV-listed' : ''}\n`;
    }
  }

  const topEpss = prioritizations.slice(0, 5);
  if (topEpss.length > 0) {
    context += `\nExploit these CVEs FIRST based on dual-axis EPSS+KEV scoring:\n`;
    context += topEpss.map((p, i) => `  ${i + 1}. ${p.cve} (${p.priorityTier.toUpperCase()}: EPSS ${(p.epss * 100).toFixed(1)}%${p.kevListed ? ', KEV' : ''})`).join('\n');
    context += '\n';
  }

  return context;
}

// ─── Cache Management ───────────────────────────────────────────────────

export function clearEpssCache(): void {
  epssCache.clear();
}

export function getEpssCacheStats(): { size: number; oldestMs: number } {
  let oldest = Date.now();
  for (const [, entry] of epssCache) {
    if (entry.cachedAt < oldest) oldest = entry.cachedAt;
  }
  return { size: epssCache.size, oldestMs: oldest };
}
