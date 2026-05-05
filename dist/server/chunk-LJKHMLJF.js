import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/nvd-cve-lookup.ts
function evictStaleEntries() {
  const now = Date.now();
  for (const [key, entry] of cache) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      cache.delete(key);
    }
  }
  if (cache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(cache.entries()).sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toRemove = entries.slice(0, cache.size - MAX_CACHE_SIZE);
    for (const [key] of toRemove) {
      cache.delete(key);
    }
  }
}
function isRateLimited(apiKey) {
  const now = Date.now();
  const limit = apiKey ? RATE_LIMIT_WITH_KEY : RATE_LIMIT_NO_KEY;
  while (requestTimestamps.length > 0 && now - requestTimestamps[0] > RATE_LIMIT_WINDOW_MS) {
    requestTimestamps.shift();
  }
  return requestTimestamps.length >= limit;
}
function recordRequest() {
  requestTimestamps.push(Date.now());
}
async function lookupCve(cveId, options) {
  const normalized = cveId.toUpperCase().trim();
  if (!options?.skipCache) {
    const cached = cache.get(normalized);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
      return { ...cached.result, cached: true };
    }
  }
  if (isRateLimited(options?.apiKey)) {
    return {
      cveId: normalized,
      cwes: [],
      cached: false,
      error: "Rate limited \u2014 too many requests to NVD API. Try again in 30 seconds."
    };
  }
  try {
    recordRequest();
    const url = new URL(NVD_API_BASE);
    url.searchParams.set("cveId", normalized);
    const headers = {
      "Accept": "application/json"
    };
    if (options?.apiKey) {
      headers["apiKey"] = options.apiKey;
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const response = await fetch(url.toString(), {
      headers,
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      return {
        cveId: normalized,
        cwes: [],
        cached: false,
        error: `NVD API returned ${response.status}: ${errorText.slice(0, 200)}`
      };
    }
    const data = await response.json();
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      const result2 = {
        cveId: normalized,
        cwes: [],
        cached: false,
        error: "CVE not found in NVD"
      };
      cache.set(normalized, { result: result2, timestamp: Date.now() });
      return result2;
    }
    const vuln = data.vulnerabilities[0].cve;
    const cwes = [];
    if (vuln.weaknesses) {
      for (const weakness of vuln.weaknesses) {
        for (const desc of weakness.description) {
          if (desc.value && desc.value.startsWith("CWE-") && desc.value !== "CWE-noinfo") {
            cwes.push(desc.value);
          }
        }
      }
    }
    const description = vuln.descriptions?.find((d) => d.lang === "en")?.value;
    const cvssV31 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvss = cvssV31 || cvssV30;
    const references = vuln.references?.map((r) => r.url).slice(0, 10);
    const result = {
      cveId: normalized,
      cwes: [...new Set(cwes)],
      // deduplicate
      description,
      cvssV3Score: cvss?.baseScore,
      cvssV3Vector: cvss?.vectorString,
      publishedDate: vuln.published,
      lastModifiedDate: vuln.lastModified,
      references,
      cached: false
    };
    cache.set(normalized, { result, timestamp: Date.now() });
    evictStaleEntries();
    return result;
  } catch (err) {
    if (err.name === "AbortError") {
      return {
        cveId: normalized,
        cwes: [],
        cached: false,
        error: "NVD API request timed out after 10 seconds"
      };
    }
    return {
      cveId: normalized,
      cwes: [],
      cached: false,
      error: `NVD API error: ${err.message || "Unknown error"}`
    };
  }
}
async function batchLookupCves(cveIds, options) {
  const results = [];
  const uniqueCves = [...new Set(cveIds.map((id) => id.toUpperCase().trim()))];
  for (const cveId of uniqueCves) {
    if (isRateLimited(options?.apiKey)) {
      const waitTime = RATE_LIMIT_WINDOW_MS - (Date.now() - (requestTimestamps[0] || Date.now()));
      if (waitTime > 0) {
        await new Promise((resolve) => setTimeout(resolve, Math.min(waitTime + 100, 5e3)));
      }
    }
    const result = await lookupCve(cveId, options);
    results.push(result);
    if (!result.cached) {
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  }
  return results;
}
async function resolveCvesToCwes(cveIds, options) {
  const results = await batchLookupCves(cveIds, options);
  const map = /* @__PURE__ */ new Map();
  for (const result of results) {
    if (result.cwes.length > 0) {
      map.set(result.cveId, result.cwes);
    }
  }
  return map;
}
function getCacheStats() {
  return {
    size: cache.size,
    maxSize: MAX_CACHE_SIZE,
    hitRate: "N/A",
    // Would need hit/miss counters for real tracking
    recentRequests: requestTimestamps.filter((t) => Date.now() - t < RATE_LIMIT_WINDOW_MS).length
  };
}
function clearCache() {
  cache.clear();
  requestTimestamps.length = 0;
}
var NVD_API_BASE, CACHE_TTL_MS, MAX_CACHE_SIZE, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_NO_KEY, RATE_LIMIT_WITH_KEY, REQUEST_TIMEOUT_MS, cache, requestTimestamps;
var init_nvd_cve_lookup = __esm({
  "server/lib/nvd-cve-lookup.ts"() {
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    CACHE_TTL_MS = 24 * 60 * 60 * 1e3;
    MAX_CACHE_SIZE = 1e3;
    RATE_LIMIT_WINDOW_MS = 3e4;
    RATE_LIMIT_NO_KEY = 5;
    RATE_LIMIT_WITH_KEY = 50;
    REQUEST_TIMEOUT_MS = 1e4;
    cache = /* @__PURE__ */ new Map();
    requestTimestamps = [];
  }
});

export {
  lookupCve,
  batchLookupCves,
  resolveCvesToCwes,
  getCacheStats,
  clearCache,
  init_nvd_cve_lookup
};
