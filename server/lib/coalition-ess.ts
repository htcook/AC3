/**
 * Coalition Exploit Scoring System (ESS) API Client
 *
 * Free, no-auth API for CVE intelligence enrichment.
 * Provides CESS (ML exploit probability), CVSS, EPSS, exploit availability,
 * social visibility, and CISA KEV flags for any CVE ID.
 *
 * API docs: https://ess-api.coalitioninc.com/docs
 * Base URL: https://ess-api.coalitioninc.com
 */

const ESS_BASE_URL = "https://ess-api.coalitioninc.com";
const REQUEST_TIMEOUT_MS = 10_000;
const BATCH_CONCURRENCY = 5;
const BATCH_DELAY_MS = 200; // Polite delay between batches

// ─── Types ──────────────────────────────────────────────────────────

export interface CessScore {
  probabilityExploitUsage: number;       // 0.0–1.0 ML-based exploit probability
  probabilityExploitUsageVariation: number;
}

export interface CvssScore {
  type: string;           // "Primary" | "Secondary"
  version: string;        // "3.1" | "2.0"
  baseScore: number;      // 0.0–10.0
  impactScore: number;
  exploitabilityScore: number;
  vectorString: string;   // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
}

export interface EpssScore {
  score: number;          // 0.0–1.0
  variation: number;
}

export interface ExploitAvailability {
  exploitdb: { numExploits: number; numVerifiedExploits: number };
  metasploit: { numExploits: number };
}

export interface SocialVisibility {
  twitter: { numTweets: number; numRetweets: number };
  github: { numRepos: number; numReposWithPocKeyword: number; numReposWithExploitKeyword: number };
}

export interface ThreatFlags {
  cisaKev: boolean;
  vulncheckKev: boolean;
  coalitionHoneypots: boolean;
  exploitdb: boolean;
  metasploit: boolean;
  github: boolean;
  twitter: boolean;
}

export interface EssEnrichment {
  cveId: string;
  description: string;
  publishedDate?: string;
  lastModifiedDate?: string;
  cess: CessScore;
  cvss: CvssScore;
  epss: EpssScore;
  exploits: ExploitAvailability;
  social: SocialVisibility;
  visibility: ThreatFlags;
  /** Computed risk tier based on CESS + EPSS + exploit availability */
  riskTier: "critical" | "high" | "medium" | "low" | "informational";
  /** Human-readable risk summary */
  riskSummary: string;
}

export interface EssBatchResult {
  enrichments: Map<string, EssEnrichment>;
  errors: Array<{ cveId: string; error: string }>;
  durationMs: number;
  cacheHits: number;
  apiCalls: number;
}

// ─── In-memory cache (TTL: 1 hour) ─────────────────────────────────

interface CacheEntry {
  data: EssEnrichment;
  expiresAt: number;
}

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const cache = new Map<string, CacheEntry>();

function getCached(cveId: string): EssEnrichment | null {
  const entry = cache.get(cveId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(cveId);
    return null;
  }
  return entry.data;
}

function setCache(cveId: string, data: EssEnrichment): void {
  cache.set(cveId, { data, expiresAt: Date.now() + CACHE_TTL_MS });
  // Evict old entries if cache grows too large
  if (cache.size > 2000) {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (now > entry.expiresAt) cache.delete(key);
    }
  }
}

export function clearCache(): void {
  cache.clear();
}

export function getCacheSize(): number {
  return cache.size;
}

// ─── API Fetching ───────────────────────────────────────────────────

function normalizeResponse(raw: any): Omit<EssEnrichment, "riskTier" | "riskSummary"> {
  return {
    cveId: raw.cve_id || "",
    description: raw.description || "",
    publishedDate: raw.published_date,
    lastModifiedDate: raw.last_modified_date,
    cess: {
      probabilityExploitUsage: raw.cess?.probability_exploit_usage ?? 0,
      probabilityExploitUsageVariation: raw.cess?.probability_exploit_usage_variation ?? 0,
    },
    cvss: {
      type: raw.cvss?.type || "Unknown",
      version: raw.cvss?.version || "N/A",
      baseScore: raw.cvss?.base_score ?? 0,
      impactScore: raw.cvss?.impact_score ?? 0,
      exploitabilityScore: raw.cvss?.exploitability_score ?? 0,
      vectorString: raw.cvss?.vector_string || "",
    },
    epss: {
      score: raw.epss?.score ?? 0,
      variation: raw.epss?.variation ?? 0,
    },
    exploits: {
      exploitdb: {
        numExploits: raw.exploits?.exploitdb?.num_exploits ?? 0,
        numVerifiedExploits: raw.exploits?.exploitdb?.num_verified_exploits ?? 0,
      },
      metasploit: {
        numExploits: raw.exploits?.metasploit?.num_exploits ?? 0,
      },
    },
    social: {
      twitter: {
        numTweets: raw.mentions?.twitter?.num_tweets ?? 0,
        numRetweets: raw.mentions?.twitter?.num_retweets ?? 0,
      },
      github: {
        numRepos: raw.repositories?.github?.num_repos ?? 0,
        numReposWithPocKeyword: raw.repositories?.github?.num_repos_with_poc_keyword ?? 0,
        numReposWithExploitKeyword: raw.repositories?.github?.num_repos_with_exploit_keyword ?? 0,
      },
    },
    visibility: {
      cisaKev: raw.visibility?.cisa_kev ?? false,
      vulncheckKev: raw.visibility?.vulncheck_kev ?? false,
      coalitionHoneypots: raw.visibility?.coalition_honeypots ?? false,
      exploitdb: raw.visibility?.exploitdb ?? false,
      metasploit: raw.visibility?.metasploit ?? false,
      github: raw.visibility?.github ?? false,
      twitter: raw.visibility?.twitter ?? false,
    },
  };
}

/**
 * Compute a risk tier based on multiple signals:
 * - CESS probability (ML exploit likelihood)
 * - EPSS score (statistical exploit prediction)
 * - CVSS base score
 * - Known exploit availability (ExploitDB, Metasploit)
 * - CISA KEV listing
 */
export function computeRiskTier(enrichment: Omit<EssEnrichment, "riskTier" | "riskSummary">): "critical" | "high" | "medium" | "low" | "informational" {
  const { cess, cvss, epss, exploits, visibility } = enrichment;

  // CISA KEV + high CESS = always critical
  if (visibility.cisaKev && cess.probabilityExploitUsage >= 0.7) return "critical";

  // Known exploits in Metasploit + high CVSS = critical
  if (exploits.metasploit.numExploits > 0 && cvss.baseScore >= 9.0) return "critical";

  // High CESS + high EPSS = critical
  if (cess.probabilityExploitUsage >= 0.8 && epss.score >= 0.5) return "critical";

  // CISA KEV alone = high
  if (visibility.cisaKev) return "high";

  // Known exploits available = high
  if (exploits.metasploit.numExploits > 0 || exploits.exploitdb.numExploits > 0) return "high";

  // High CESS or high EPSS = high
  if (cess.probabilityExploitUsage >= 0.6 || epss.score >= 0.3) return "high";

  // Medium CVSS + some exploit signals = medium
  if (cvss.baseScore >= 7.0) return "medium";
  if (cess.probabilityExploitUsage >= 0.3 || epss.score >= 0.1) return "medium";

  // Low CVSS with some visibility = low
  if (cvss.baseScore >= 4.0) return "low";

  return "informational";
}

export function generateRiskSummary(enrichment: EssEnrichment): string {
  const parts: string[] = [];
  const { cess, cvss, epss, exploits, visibility } = enrichment;

  if (visibility.cisaKev) parts.push("CISA KEV listed");
  if (exploits.metasploit.numExploits > 0) parts.push(`${exploits.metasploit.numExploits} Metasploit module(s)`);
  if (exploits.exploitdb.numExploits > 0) parts.push(`${exploits.exploitdb.numExploits} ExploitDB entry(ies)`);
  if (cess.probabilityExploitUsage >= 0.5) parts.push(`CESS ${(cess.probabilityExploitUsage * 100).toFixed(0)}% exploit probability`);
  if (epss.score >= 0.1) parts.push(`EPSS ${(epss.score * 100).toFixed(1)}%`);
  parts.push(`CVSS ${cvss.baseScore}/10`);

  if (enrichment.social.github.numReposWithPocKeyword > 0) {
    parts.push(`${enrichment.social.github.numReposWithPocKeyword} GitHub PoC(s)`);
  }

  return parts.join(" · ");
}

/**
 * Fetch ESS enrichment for a single CVE ID.
 * Returns null if the CVE is not found or the API is unreachable.
 */
export async function fetchCveEnrichment(cveId: string): Promise<EssEnrichment | null> {
  // Validate CVE ID format
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null;

  // Check cache first
  const cached = getCached(cveId);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const response = await fetch(`${ESS_BASE_URL}/cve/${cveId}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" },
    });
    clearTimeout(timeout);

    if (!response.ok) {
      if (response.status === 404) return null; // CVE not in database
      return null;
    }

    const raw = await response.json();
    const normalized = normalizeResponse(raw);
    const riskTier = computeRiskTier(normalized);
    const enrichment: EssEnrichment = {
      ...normalized,
      riskTier,
      riskSummary: "",
    };
    enrichment.riskSummary = generateRiskSummary(enrichment);

    setCache(cveId, enrichment);
    return enrichment;
  } catch (err: any) {
    // Network error, timeout, etc.
    return null;
  }
}

/**
 * Fetch ESS enrichment for multiple CVE IDs in parallel batches.
 * Respects rate limits with configurable concurrency and delay.
 */
export async function batchEnrichCves(
  cveIds: string[],
  options?: { concurrency?: number; delayMs?: number }
): Promise<EssBatchResult> {
  const start = Date.now();
  const concurrency = options?.concurrency ?? BATCH_CONCURRENCY;
  const delayMs = options?.delayMs ?? BATCH_DELAY_MS;

  // Deduplicate and validate
  const uniqueCves = [...new Set(cveIds.filter(id => /^CVE-\d{4}-\d{4,}$/.test(id)))];

  const enrichments = new Map<string, EssEnrichment>();
  const errors: Array<{ cveId: string; error: string }> = [];
  let cacheHits = 0;
  let apiCalls = 0;

  // Separate cached from uncached
  const uncached: string[] = [];
  for (const cveId of uniqueCves) {
    const cached = getCached(cveId);
    if (cached) {
      enrichments.set(cveId, cached);
      cacheHits++;
    } else {
      uncached.push(cveId);
    }
  }

  // Process uncached in batches
  for (let i = 0; i < uncached.length; i += concurrency) {
    const batch = uncached.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (cveId) => {
        apiCalls++;
        const result = await fetchCveEnrichment(cveId);
        return { cveId, result };
      })
    );

    for (const r of results) {
      if (r.status === "fulfilled" && r.value.result) {
        enrichments.set(r.value.cveId, r.value.result);
      } else if (r.status === "fulfilled" && !r.value.result) {
        errors.push({ cveId: r.value.cveId, error: "CVE not found in Coalition ESS database" });
      } else if (r.status === "rejected") {
        errors.push({ cveId: "unknown", error: r.reason?.message || "Unknown error" });
      }
    }

    // Polite delay between batches
    if (i + concurrency < uncached.length && delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  return {
    enrichments,
    errors,
    durationMs: Date.now() - start,
    cacheHits,
    apiCalls,
  };
}

/**
 * Enrich a list of vulnerability findings with ESS data.
 * Returns the findings with an added `essEnrichment` field.
 */
export async function enrichVulnFindings(
  findings: Array<{ severity: string; title: string; cve?: string }>
): Promise<Array<{ severity: string; title: string; cve?: string; essEnrichment?: EssEnrichment }>> {
  // Extract unique CVE IDs
  const cveIds = findings
    .map(f => f.cve)
    .filter((cve): cve is string => !!cve && /^CVE-\d{4}-\d{4,}$/.test(cve));

  if (cveIds.length === 0) return findings.map(f => ({ ...f }));

  const { enrichments } = await batchEnrichCves(cveIds);

  return findings.map(f => ({
    ...f,
    essEnrichment: f.cve ? enrichments.get(f.cve) : undefined,
  }));
}

/**
 * Get exploit intelligence summary for a set of CVEs.
 * Useful for the LLM attack planner to understand weaponization status.
 */
export function summarizeExploitIntelligence(enrichments: Map<string, EssEnrichment>): {
  totalCves: number;
  cisaKevCount: number;
  metasploitCount: number;
  exploitdbCount: number;
  highCessCount: number;
  highEpssCount: number;
  criticalRiskCount: number;
  highRiskCount: number;
  topThreats: Array<{ cveId: string; riskTier: string; riskSummary: string; cessScore: number }>;
} {
  let cisaKevCount = 0, metasploitCount = 0, exploitdbCount = 0;
  let highCessCount = 0, highEpssCount = 0;
  let criticalRiskCount = 0, highRiskCount = 0;
  const allEntries: Array<{ cveId: string; riskTier: string; riskSummary: string; cessScore: number }> = [];

  for (const [cveId, e] of enrichments) {
    if (e.visibility.cisaKev) cisaKevCount++;
    if (e.exploits.metasploit.numExploits > 0) metasploitCount++;
    if (e.exploits.exploitdb.numExploits > 0) exploitdbCount++;
    if (e.cess.probabilityExploitUsage >= 0.5) highCessCount++;
    if (e.epss.score >= 0.1) highEpssCount++;
    if (e.riskTier === "critical") criticalRiskCount++;
    if (e.riskTier === "high") highRiskCount++;
    allEntries.push({ cveId, riskTier: e.riskTier, riskSummary: e.riskSummary, cessScore: e.cess.probabilityExploitUsage });
  }

  // Sort by CESS score descending for top threats
  allEntries.sort((a, b) => b.cessScore - a.cessScore);

  return {
    totalCves: enrichments.size,
    cisaKevCount,
    metasploitCount,
    exploitdbCount,
    highCessCount,
    highEpssCount,
    criticalRiskCount,
    highRiskCount,
    topThreats: allEntries.slice(0, 10),
  };
}
