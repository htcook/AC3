import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/coalition-ess.ts
function getCached(cveId) {
  const entry = cache.get(cveId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(cveId);
    return null;
  }
  return entry.data;
}
function setCache(cveId, data) {
  cache.set(cveId, { data, expiresAt: Date.now() + CACHE_TTL_MS });
  if (cache.size > 2e3) {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (now > entry.expiresAt) cache.delete(key);
    }
  }
}
function clearCache() {
  cache.clear();
}
function getCacheSize() {
  return cache.size;
}
function normalizeResponse(raw) {
  return {
    cveId: raw.cve_id || "",
    description: raw.description || "",
    publishedDate: raw.published_date,
    lastModifiedDate: raw.last_modified_date,
    cess: {
      probabilityExploitUsage: raw.cess?.probability_exploit_usage ?? 0,
      probabilityExploitUsageVariation: raw.cess?.probability_exploit_usage_variation ?? 0
    },
    cvss: {
      type: raw.cvss?.type || "Unknown",
      version: raw.cvss?.version || "N/A",
      baseScore: raw.cvss?.base_score ?? 0,
      impactScore: raw.cvss?.impact_score ?? 0,
      exploitabilityScore: raw.cvss?.exploitability_score ?? 0,
      vectorString: raw.cvss?.vector_string || ""
    },
    epss: {
      score: raw.epss?.score ?? 0,
      variation: raw.epss?.variation ?? 0
    },
    exploits: {
      exploitdb: {
        numExploits: raw.exploits?.exploitdb?.num_exploits ?? 0,
        numVerifiedExploits: raw.exploits?.exploitdb?.num_verified_exploits ?? 0
      },
      metasploit: {
        numExploits: raw.exploits?.metasploit?.num_exploits ?? 0
      }
    },
    social: {
      twitter: {
        numTweets: raw.mentions?.twitter?.num_tweets ?? 0,
        numRetweets: raw.mentions?.twitter?.num_retweets ?? 0
      },
      github: {
        numRepos: raw.repositories?.github?.num_repos ?? 0,
        numReposWithPocKeyword: raw.repositories?.github?.num_repos_with_poc_keyword ?? 0,
        numReposWithExploitKeyword: raw.repositories?.github?.num_repos_with_exploit_keyword ?? 0
      }
    },
    visibility: {
      cisaKev: raw.visibility?.cisa_kev ?? false,
      vulncheckKev: raw.visibility?.vulncheck_kev ?? false,
      coalitionHoneypots: raw.visibility?.coalition_honeypots ?? false,
      exploitdb: raw.visibility?.exploitdb ?? false,
      metasploit: raw.visibility?.metasploit ?? false,
      github: raw.visibility?.github ?? false,
      twitter: raw.visibility?.twitter ?? false
    }
  };
}
function computeRiskTier(enrichment) {
  const { cess, cvss, epss, exploits, visibility } = enrichment;
  if (visibility.cisaKev && cess.probabilityExploitUsage >= 0.7) return "critical";
  if (exploits.metasploit.numExploits > 0 && cvss.baseScore >= 9) return "critical";
  if (cess.probabilityExploitUsage >= 0.8 && epss.score >= 0.5) return "critical";
  if (visibility.cisaKev) return "high";
  if (exploits.metasploit.numExploits > 0 || exploits.exploitdb.numExploits > 0) return "high";
  if (cess.probabilityExploitUsage >= 0.6 || epss.score >= 0.3) return "high";
  if (cvss.baseScore >= 7) return "medium";
  if (cess.probabilityExploitUsage >= 0.3 || epss.score >= 0.1) return "medium";
  if (cvss.baseScore >= 4) return "low";
  return "informational";
}
function generateRiskSummary(enrichment) {
  const parts = [];
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
  return parts.join(" \xB7 ");
}
async function fetchCveEnrichment(cveId) {
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null;
  const cached = getCached(cveId);
  if (cached) return cached;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const response = await fetch(`${ESS_BASE_URL}/cve/${cveId}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });
    clearTimeout(timeout);
    if (!response.ok) {
      if (response.status === 404) return null;
      return null;
    }
    const raw = await response.json();
    const normalized = normalizeResponse(raw);
    const riskTier = computeRiskTier(normalized);
    const enrichment = {
      ...normalized,
      riskTier,
      riskSummary: ""
    };
    enrichment.riskSummary = generateRiskSummary(enrichment);
    setCache(cveId, enrichment);
    return enrichment;
  } catch (err) {
    return null;
  }
}
async function batchEnrichCves(cveIds, options) {
  const start = Date.now();
  const concurrency = options?.concurrency ?? BATCH_CONCURRENCY;
  const delayMs = options?.delayMs ?? BATCH_DELAY_MS;
  const uniqueCves = [...new Set(cveIds.filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)))];
  const enrichments = /* @__PURE__ */ new Map();
  const errors = [];
  let cacheHits = 0;
  let apiCalls = 0;
  const uncached = [];
  for (const cveId of uniqueCves) {
    const cached = getCached(cveId);
    if (cached) {
      enrichments.set(cveId, cached);
      cacheHits++;
    } else {
      uncached.push(cveId);
    }
  }
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
    if (i + concurrency < uncached.length && delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  return {
    enrichments,
    errors,
    durationMs: Date.now() - start,
    cacheHits,
    apiCalls
  };
}
async function enrichVulnFindings(findings) {
  const cveIds = findings.map((f) => f.cve).filter((cve) => !!cve && /^CVE-\d{4}-\d{4,}$/.test(cve));
  if (cveIds.length === 0) return findings.map((f) => ({ ...f }));
  const { enrichments } = await batchEnrichCves(cveIds);
  return findings.map((f) => ({
    ...f,
    essEnrichment: f.cve ? enrichments.get(f.cve) : void 0
  }));
}
function summarizeExploitIntelligence(enrichments) {
  let cisaKevCount = 0, metasploitCount = 0, exploitdbCount = 0;
  let highCessCount = 0, highEpssCount = 0;
  let criticalRiskCount = 0, highRiskCount = 0;
  const allEntries = [];
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
    topThreats: allEntries.slice(0, 10)
  };
}
var ESS_BASE_URL, REQUEST_TIMEOUT_MS, BATCH_CONCURRENCY, BATCH_DELAY_MS, CACHE_TTL_MS, cache;
var init_coalition_ess = __esm({
  "server/lib/coalition-ess.ts"() {
    ESS_BASE_URL = "https://ess-api.coalitioninc.com";
    REQUEST_TIMEOUT_MS = 1e4;
    BATCH_CONCURRENCY = 5;
    BATCH_DELAY_MS = 200;
    CACHE_TTL_MS = 60 * 60 * 1e3;
    cache = /* @__PURE__ */ new Map();
  }
});
init_coalition_ess();
export {
  batchEnrichCves,
  clearCache,
  computeRiskTier,
  enrichVulnFindings,
  fetchCveEnrichment,
  generateRiskSummary,
  getCacheSize,
  summarizeExploitIntelligence
};
