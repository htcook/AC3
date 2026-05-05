import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/epss-service.ts
async function fetchEpssScores(cves) {
  const uniqueCves = [...new Set(cves.filter((c) => c.startsWith("CVE-")))];
  if (uniqueCves.length === 0) {
    return { scores: [], missing: [], fetchedAt: Date.now() };
  }
  const results = [];
  const toFetch = [];
  for (const cve of uniqueCves) {
    const cached = epssCache.get(cve);
    if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
      results.push(cached.score);
    } else {
      toFetch.push(cve);
    }
  }
  const BATCH_SIZE = 100;
  for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
    const batch = toFetch.slice(i, i + BATCH_SIZE);
    try {
      const url = `${EPSS_API_BASE}?cve=${batch.join(",")}`;
      const response = await fetch(url, {
        headers: { "Accept": "application/json" },
        signal: AbortSignal.timeout(15e3)
      });
      if (!response.ok) {
        console.error(`[EPSS] API returned ${response.status} for batch ${i / BATCH_SIZE + 1}`);
        continue;
      }
      const data = await response.json();
      if (data.data) {
        for (const entry of data.data) {
          const score = {
            cve: entry.cve,
            epss: parseFloat(entry.epss) || 0,
            percentile: parseFloat(entry.percentile) || 0
          };
          results.push(score);
          epssCache.set(entry.cve, { score, cachedAt: Date.now() });
        }
      }
    } catch (err) {
      console.error(`[EPSS] Failed to fetch batch ${i / BATCH_SIZE + 1}:`, err.message);
    }
  }
  const fetchedCves = new Set(results.map((r) => r.cve));
  const missing = uniqueCves.filter((c) => !fetchedCves.has(c));
  return { scores: results, missing, fetchedAt: Date.now() };
}
async function getEpssScore(cve) {
  const result = await fetchEpssScores([cve]);
  return result.scores[0] || null;
}
function prioritizeCveWithEpss(cve, epssScore, percentile, kevListed) {
  let priorityTier;
  let rationale;
  if (kevListed && epssScore >= 0.1) {
    priorityTier = "critical";
    rationale = `CRITICAL: ${cve} is on CISA KEV (actively exploited) AND has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Immediate exploitation testing required.`;
  } else if (kevListed) {
    priorityTier = "high";
    rationale = `HIGH: ${cve} is on CISA KEV (actively exploited) with ${(epssScore * 100).toFixed(1)}% EPSS probability. KEV listing alone warrants priority testing.`;
  } else if (epssScore >= 0.4) {
    priorityTier = "high";
    rationale = `HIGH: ${cve} has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Very high likelihood of exploitation within 30 days.`;
  } else if (epssScore >= 0.1) {
    priorityTier = "medium";
    rationale = `MEDIUM: ${cve} has ${(epssScore * 100).toFixed(1)}% EPSS probability (${(percentile * 100).toFixed(0)}th percentile). Moderate exploitation likelihood.`;
  } else {
    priorityTier = "low";
    rationale = `LOW: ${cve} has ${(epssScore * 100).toFixed(2)}% EPSS probability. Lower exploitation likelihood, but still worth testing if resources allow.`;
  }
  return { cve, epss: epssScore, percentile, kevListed, priorityTier, rationale };
}
async function batchPrioritizeCves(cves, kevCveSet) {
  const epssResult = await fetchEpssScores(cves);
  const epssMap = new Map(epssResult.scores.map((s) => [s.cve, s]));
  const prioritized = cves.map((cve) => {
    const epss = epssMap.get(cve);
    return prioritizeCveWithEpss(
      cve,
      epss?.epss ?? 0,
      epss?.percentile ?? 0,
      kevCveSet.has(cve)
    );
  });
  const tierOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  prioritized.sort((a, b) => {
    const tierDiff = tierOrder[a.priorityTier] - tierOrder[b.priorityTier];
    if (tierDiff !== 0) return tierDiff;
    return b.epss - a.epss;
  });
  return prioritized;
}
function buildEpssContextForLlm(prioritizations) {
  if (prioritizations.length === 0) return "";
  const critical = prioritizations.filter((p) => p.priorityTier === "critical");
  const high = prioritizations.filter((p) => p.priorityTier === "high");
  let context = "\n\n\u{1F4CA} EPSS EXPLOIT PREDICTION SCORING:\n";
  context += `Analyzed ${prioritizations.length} CVEs against FIRST.org EPSS model.
`;
  if (critical.length > 0) {
    context += `
\u{1F534} CRITICAL PRIORITY (KEV + High EPSS):
`;
    for (const p of critical.slice(0, 10)) {
      context += `  - ${p.cve}: EPSS ${(p.epss * 100).toFixed(1)}% (${(p.percentile * 100).toFixed(0)}th pctl) \u2014 KEV-listed, actively exploited
`;
    }
  }
  if (high.length > 0) {
    context += `
\u{1F7E0} HIGH PRIORITY:
`;
    for (const p of high.slice(0, 10)) {
      context += `  - ${p.cve}: EPSS ${(p.epss * 100).toFixed(1)}% (${(p.percentile * 100).toFixed(0)}th pctl)${p.kevListed ? " \u2014 KEV-listed" : ""}
`;
    }
  }
  const topEpss = prioritizations.slice(0, 5);
  if (topEpss.length > 0) {
    context += `
Exploit these CVEs FIRST based on dual-axis EPSS+KEV scoring:
`;
    context += topEpss.map((p, i) => `  ${i + 1}. ${p.cve} (${p.priorityTier.toUpperCase()}: EPSS ${(p.epss * 100).toFixed(1)}%${p.kevListed ? ", KEV" : ""})`).join("\n");
    context += "\n";
  }
  return context;
}
function clearEpssCache() {
  epssCache.clear();
}
function getEpssCacheStats() {
  let oldest = Date.now();
  for (const [, entry] of epssCache) {
    if (entry.cachedAt < oldest) oldest = entry.cachedAt;
  }
  return { size: epssCache.size, oldestMs: oldest };
}
var epssCache, CACHE_TTL_MS, EPSS_API_BASE;
var init_epss_service = __esm({
  "server/lib/epss-service.ts"() {
    epssCache = /* @__PURE__ */ new Map();
    CACHE_TTL_MS = 6 * 60 * 60 * 1e3;
    EPSS_API_BASE = "https://api.first.org/data/v1/epss";
  }
});
init_epss_service();
export {
  batchPrioritizeCves,
  buildEpssContextForLlm,
  clearEpssCache,
  fetchEpssScores,
  getEpssCacheStats,
  getEpssScore,
  prioritizeCveWithEpss
};
