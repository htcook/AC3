import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-inference-optimizer.ts
import { createHash } from "crypto";
function estimateCost(tokensIn, tokensOut, model) {
  const pricing = MODEL_PRICING[model] || MODEL_PRICING["gpt-4o"];
  return tokensIn / 1e6 * pricing.inputPer1M + tokensOut / 1e6 * pricing.outputPer1M;
}
function buildCostReport(engagementId, telemetryRows, assetCount) {
  const callSiteMap = /* @__PURE__ */ new Map();
  const modelMap = /* @__PURE__ */ new Map();
  let totalCost = 0;
  let totalTokensIn = 0;
  let totalTokensOut = 0;
  const minuteBuckets = /* @__PURE__ */ new Map();
  const engagementStart = telemetryRows.length > 0 ? new Date(telemetryRows[0].calledAt).getTime() : Date.now();
  for (const row of telemetryRows) {
    const cost = estimateCost(row.tokensIn || 0, row.tokensOut || 0, row.model);
    totalCost += cost;
    totalTokensIn += row.tokensIn || 0;
    totalTokensOut += row.tokensOut || 0;
    const existing = callSiteMap.get(row.caller) || {
      calls: 0,
      tokensIn: 0,
      tokensOut: 0,
      cost: 0,
      latencies: [],
      errors: 0
    };
    existing.calls++;
    existing.tokensIn += row.tokensIn || 0;
    existing.tokensOut += row.tokensOut || 0;
    existing.cost += cost;
    existing.latencies.push(row.latencyMs);
    if (row.llmStatus === "error" || row.llmStatus === "timeout") existing.errors++;
    callSiteMap.set(row.caller, existing);
    const modelEntry = modelMap.get(row.model) || { calls: 0, tokensIn: 0, tokensOut: 0, cost: 0 };
    modelEntry.calls++;
    modelEntry.tokensIn += row.tokensIn || 0;
    modelEntry.tokensOut += row.tokensOut || 0;
    modelEntry.cost += cost;
    modelMap.set(row.model, modelEntry);
    const calledAt = new Date(row.calledAt).getTime();
    const minuteOffset = Math.floor((calledAt - engagementStart) / 6e4);
    const bucket = minuteBuckets.get(minuteOffset) || { calls: 0, cost: 0 };
    bucket.calls++;
    bucket.cost += cost;
    minuteBuckets.set(minuteOffset, bucket);
  }
  const callSiteBreakdown = Array.from(callSiteMap.entries()).map(([caller, data]) => ({
    caller,
    calls: data.calls,
    tokensIn: data.tokensIn,
    tokensOut: data.tokensOut,
    estimatedCost: data.cost,
    percentOfTotalCost: totalCost > 0 ? data.cost / totalCost * 100 : 0,
    avgLatencyMs: data.latencies.length > 0 ? data.latencies.reduce((s, l) => s + l, 0) / data.latencies.length : 0,
    errorRate: data.calls > 0 ? data.errors / data.calls : 0,
    primaryPriority: inferPriority(caller)
  })).sort((a, b) => b.estimatedCost - a.estimatedCost);
  const modelBreakdown = Array.from(modelMap.entries()).map(([model, data]) => ({
    model,
    calls: data.calls,
    tokensIn: data.tokensIn,
    tokensOut: data.tokensOut,
    estimatedCost: data.cost,
    percentOfTotal: totalCost > 0 ? data.cost / totalCost * 100 : 0
  })).sort((a, b) => b.estimatedCost - a.estimatedCost);
  const graduationCandidates = identifyGraduationCandidates(callSiteBreakdown, telemetryRows.length);
  const callsPerMinute = Array.from(minuteBuckets.entries()).map(([minute, data]) => ({ minute, ...data })).sort((a, b) => a.minute - b.minute);
  return {
    engagementId,
    totalCalls: telemetryRows.length,
    totalTokensIn,
    totalTokensOut,
    totalEstimatedCost: totalCost,
    costPerAsset: assetCount > 0 ? totalCost / assetCount : totalCost,
    assetCount,
    callSiteBreakdown,
    modelBreakdown,
    graduationCandidates,
    callsPerMinute
  };
}
function identifyGraduationCandidates(callSites, totalCalls) {
  const candidates = [];
  const GRADUATION_PATTERNS = [
    {
      pattern: /format|normaliz|template|render|stringify/i,
      reason: "Formatting/normalization \u2014 likely replaceable with templates",
      confidence: 0.85
    },
    {
      pattern: /classif|categoriz|label|tag/i,
      reason: "Classification \u2014 may be replaceable with rule-based classifier",
      confidence: 0.7
    },
    {
      pattern: /validat|check|verify|confirm/i,
      reason: "Validation \u2014 may be replaceable with deterministic checks",
      confidence: 0.65
    },
    {
      pattern: /summar|extract|parse|convert/i,
      reason: "Summarization/extraction \u2014 consider regex or structured parsing",
      confidence: 0.6
    },
    {
      pattern: /enrich|lookup|resolve/i,
      reason: "Enrichment \u2014 consider caching or lookup tables",
      confidence: 0.55
    },
    {
      pattern: /dedup|merge|consolidat/i,
      reason: "Deduplication/merging \u2014 typically deterministic",
      confidence: 0.8
    }
  ];
  for (const site of callSites) {
    if (site.calls < totalCalls * 0.02) continue;
    for (const gp of GRADUATION_PATTERNS) {
      if (gp.pattern.test(site.caller)) {
        candidates.push({
          caller: site.caller,
          reason: gp.reason,
          calls: site.calls,
          estimatedCost: site.estimatedCost,
          potentialSavings: site.estimatedCost * gp.confidence,
          graduationConfidence: gp.confidence
        });
        break;
      }
    }
    if (site.calls > totalCalls * 0.1 && !candidates.find((c) => c.caller === site.caller)) {
      candidates.push({
        caller: site.caller,
        reason: `High volume (${(site.calls / totalCalls * 100).toFixed(1)}% of all calls) \u2014 investigate for batching or caching opportunities`,
        calls: site.calls,
        estimatedCost: site.estimatedCost,
        potentialSavings: site.estimatedCost * 0.3,
        // Conservative 30% savings estimate
        graduationConfidence: 0.4
      });
    }
  }
  return candidates.sort((a, b) => b.potentialSavings - a.potentialSavings);
}
function inferPriority(caller) {
  const essentialPatterns = /exploit|attack-plan|vuln-verif|hybrid-scor/i;
  const bulkPatterns = /enrich|summar|report|classif|format|normaliz/i;
  if (essentialPatterns.test(caller)) return "essential";
  if (bulkPatterns.test(caller)) return "bulk";
  return "standard";
}
function deduplicateBatch(calls) {
  const hashMap = /* @__PURE__ */ new Map();
  for (const call of calls) {
    const hash = inferenceCache.computeSemanticHash(call.messages, call.responseFormat);
    const existing = hashMap.get(hash);
    if (existing) {
      existing.duplicateIds.push(call.id);
    } else {
      hashMap.set(hash, { call, duplicateIds: [] });
    }
  }
  const unique = Array.from(hashMap.values()).map(({ call, duplicateIds }) => ({
    ...call,
    duplicateIds
  }));
  const duplicateCount = calls.length - unique.length;
  return {
    unique,
    duplicateCount,
    deduplicationRate: calls.length > 0 ? duplicateCount / calls.length : 0
  };
}
var DEFAULT_CACHE_CONFIG, SemanticInferenceCache, MODEL_PRICING, CallSiteVolumeTracker, inferenceCache, callSiteTracker;
var init_llm_inference_optimizer = __esm({
  "server/lib/llm-inference-optimizer.ts"() {
    DEFAULT_CACHE_CONFIG = {
      maxEntries: 2e3,
      defaultTtlMs: 30 * 60 * 1e3,
      // 30 minutes
      noCacheCallers: [
        "exploit-generator",
        "c2-deployer",
        "credential-spray",
        "lateral-planner"
      ],
      minTokensToCache: 50
    };
    SemanticInferenceCache = class {
      constructor(config) {
        this.cache = /* @__PURE__ */ new Map();
        // Stats
        this.totalLookups = 0;
        this.totalHits = 0;
        this.totalMisses = 0;
        this.totalEvictions = 0;
        this.tokensSaved = 0;
        this.config = { ...DEFAULT_CACHE_CONFIG, ...config };
      }
      /**
       * Compute a semantic hash from LLM input messages.
       * Normalizes whitespace, strips timestamps/IDs, and sorts JSON keys
       * to produce a stable hash for semantically-equivalent inputs.
       */
      computeSemanticHash(messages, responseFormat) {
        const normalized = messages.map((m) => {
          let content = typeof m.content === "string" ? m.content : JSON.stringify(m.content);
          content = content.replace(/\s+/g, " ").trim();
          content = content.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\dZ]*/g, "<TIMESTAMP>");
          content = content.replace(/\b1[6-7]\d{8,11}\b/g, "<UNIX_TS>");
          content = content.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<UUID>");
          content = content.replace(/ops-\d+-\d+/g, "<OPS_ID>");
          return `${m.role}:${content}`;
        }).join("|");
        const formatStr = responseFormat ? JSON.stringify(responseFormat) : "";
        return createHash("sha256").update(normalized + "||" + formatStr).digest("hex");
      }
      /**
       * Look up a cached response for the given input.
       * Returns null if no cache hit or if the caller is in the no-cache list.
       */
      lookup(messages, caller, responseFormat) {
        this.totalLookups++;
        if (caller && this.config.noCacheCallers.some((nc) => caller.includes(nc))) {
          this.totalMisses++;
          return null;
        }
        const hash = this.computeSemanticHash(messages, responseFormat);
        const entry = this.cache.get(hash);
        if (!entry) {
          this.totalMisses++;
          return null;
        }
        if (Date.now() - entry.cachedAt > entry.ttlMs) {
          this.cache.delete(hash);
          this.totalMisses++;
          this.totalEvictions++;
          return null;
        }
        entry.hitCount++;
        this.totalHits++;
        this.tokensSaved += entry.tokensIn + entry.tokensOut;
        return {
          content: entry.responseContent,
          model: entry.model,
          fromCache: true
        };
      }
      /**
       * Store a response in the cache.
       */
      store(messages, responseContent, model, tokensIn, tokensOut, caller, responseFormat, ttlMs) {
        if (caller && this.config.noCacheCallers.some((nc) => caller.includes(nc))) {
          return;
        }
        if (tokensIn < this.config.minTokensToCache) {
          return;
        }
        if (this.cache.size >= this.config.maxEntries) {
          this.evictOldest();
        }
        const hash = this.computeSemanticHash(messages, responseFormat);
        this.cache.set(hash, {
          responseContent,
          model,
          tokensIn,
          tokensOut,
          cachedAt: Date.now(),
          hitCount: 0,
          caller: caller || "unknown",
          ttlMs: ttlMs || this.config.defaultTtlMs
        });
      }
      /**
       * Evict the least-recently-used entries to make room.
       */
      evictOldest() {
        const entries = Array.from(this.cache.entries()).sort((a, b) => a[1].cachedAt - b[1].cachedAt);
        const toRemove = Math.max(1, Math.floor(entries.length * 0.1));
        for (let i = 0; i < toRemove; i++) {
          this.cache.delete(entries[i][0]);
          this.totalEvictions++;
        }
      }
      /**
       * Get cache statistics.
       */
      getStats() {
        return {
          totalEntries: this.cache.size,
          maxEntries: this.config.maxEntries,
          totalLookups: this.totalLookups,
          totalHits: this.totalHits,
          totalMisses: this.totalMisses,
          hitRate: this.totalLookups > 0 ? this.totalHits / this.totalLookups : 0,
          totalEvictions: this.totalEvictions,
          tokensSaved: this.tokensSaved,
          estimatedCostSaved: estimateCost(this.tokensSaved, 0, "gpt-4o")
          // Conservative estimate
        };
      }
      /**
       * Clear the entire cache.
       */
      clear() {
        this.cache.clear();
      }
      /**
       * Get the most frequently hit cache entries (graduation candidates).
       */
      getGraduationCandidates(minHits = 5) {
        const callerHits = /* @__PURE__ */ new Map();
        for (const entry of this.cache.values()) {
          if (entry.hitCount >= minHits) {
            const existing = callerHits.get(entry.caller) || { hitCount: 0, tokensSaved: 0 };
            existing.hitCount += entry.hitCount;
            existing.tokensSaved += (entry.tokensIn + entry.tokensOut) * entry.hitCount;
            callerHits.set(entry.caller, existing);
          }
        }
        return Array.from(callerHits.entries()).map(([caller, stats]) => ({
          caller,
          hitCount: stats.hitCount,
          tokensSaved: stats.tokensSaved,
          estimatedCostSaved: estimateCost(stats.tokensSaved, 0, "gpt-4o")
        })).sort((a, b) => b.hitCount - a.hitCount);
      }
    };
    MODEL_PRICING = {
      "gpt-4o": { inputPer1M: 2.5, outputPer1M: 10 },
      "gpt-4o-mini": { inputPer1M: 0.15, outputPer1M: 0.6 },
      "gpt-4-turbo": { inputPer1M: 10, outputPer1M: 30 },
      "gpt-4": { inputPer1M: 30, outputPer1M: 60 },
      "gpt-3.5-turbo": { inputPer1M: 0.5, outputPer1M: 1.5 },
      "gemini-2.5-flash": { inputPer1M: 0.15, outputPer1M: 0.6 },
      "gemini-2.5-pro": { inputPer1M: 1.25, outputPer1M: 10 },
      "gemini-2.0-flash": { inputPer1M: 0.1, outputPer1M: 0.4 },
      // Forge-routed calls (cost is effectively the Forge tier pricing)
      "forge-standard": { inputPer1M: 0.15, outputPer1M: 0.6 },
      "forge-bulk": { inputPer1M: 0.1, outputPer1M: 0.4 }
    };
    CallSiteVolumeTracker = class {
      constructor() {
        this.counters = /* @__PURE__ */ new Map();
        this.engagementCounters = /* @__PURE__ */ new Map();
      }
      /**
       * Record a call from a specific caller.
       */
      recordCall(caller, tokensIn, tokensOut, isError, engagementId) {
        const existing = this.counters.get(caller) || {
          calls: 0,
          tokensIn: 0,
          tokensOut: 0,
          errors: 0,
          lastCallAt: 0,
          recentCalls: []
        };
        existing.calls++;
        existing.tokensIn += tokensIn;
        existing.tokensOut += tokensOut;
        if (isError) existing.errors++;
        existing.lastCallAt = Date.now();
        const minuteBucket = Math.floor(Date.now() / 6e4);
        existing.recentCalls.push(minuteBucket);
        const cutoff = minuteBucket - 5;
        existing.recentCalls = existing.recentCalls.filter((m) => m > cutoff);
        this.counters.set(caller, existing);
        if (engagementId) {
          const engEntry = this.engagementCounters.get(engagementId) || {
            totalCalls: 0,
            totalTokensIn: 0,
            totalTokensOut: 0,
            startedAt: Date.now()
          };
          engEntry.totalCalls++;
          engEntry.totalTokensIn += tokensIn;
          engEntry.totalTokensOut += tokensOut;
          this.engagementCounters.set(engagementId, engEntry);
        }
      }
      /**
       * Get the current call rate for a caller (calls per minute, last 5 min).
       */
      getCallRate(caller) {
        const entry = this.counters.get(caller);
        if (!entry) return 0;
        return entry.recentCalls.length / 5;
      }
      /**
       * Get top callers by volume.
       */
      getTopCallers(limit = 20) {
        return Array.from(this.counters.entries()).map(([caller, data]) => ({
          caller,
          calls: data.calls,
          tokensTotal: data.tokensIn + data.tokensOut,
          estimatedCost: estimateCost(data.tokensIn, data.tokensOut, "gpt-4o"),
          callsPerMinute: this.getCallRate(caller)
        })).sort((a, b) => b.calls - a.calls).slice(0, limit);
      }
      /**
       * Get per-engagement summary.
       */
      getEngagementSummary(engagementId) {
        const entry = this.engagementCounters.get(engagementId);
        if (!entry) return null;
        const durationMs = Date.now() - entry.startedAt;
        const durationMinutes = Math.max(1, durationMs / 6e4);
        return {
          totalCalls: entry.totalCalls,
          totalTokens: entry.totalTokensIn + entry.totalTokensOut,
          estimatedCost: estimateCost(entry.totalTokensIn, entry.totalTokensOut, "gpt-4o"),
          callsPerMinute: entry.totalCalls / durationMinutes,
          durationMinutes
        };
      }
      /**
       * Detect anomalous call patterns (potential loops or runaway inference).
       */
      detectAnomalies() {
        const anomalies = [];
        for (const [caller, data] of this.counters) {
          const rate = this.getCallRate(caller);
          if (rate > 20) {
            anomalies.push({
              caller,
              anomalyType: "high_rate",
              details: `${rate.toFixed(1)} calls/min (threshold: 20). Possible LLM-in-loop pattern.`,
              severity: rate > 50 ? "critical" : "warning"
            });
          }
          if (data.calls > 10 && data.errors / data.calls > 0.3) {
            anomalies.push({
              caller,
              anomalyType: "high_error_rate",
              details: `${(data.errors / data.calls * 100).toFixed(0)}% error rate over ${data.calls} calls.`,
              severity: data.errors / data.calls > 0.5 ? "critical" : "warning"
            });
          }
        }
        return anomalies;
      }
      /**
       * Reset all counters.
       */
      reset() {
        this.counters.clear();
        this.engagementCounters.clear();
      }
    };
    inferenceCache = new SemanticInferenceCache();
    callSiteTracker = new CallSiteVolumeTracker();
  }
});

export {
  SemanticInferenceCache,
  estimateCost,
  buildCostReport,
  CallSiteVolumeTracker,
  inferenceCache,
  callSiteTracker,
  deduplicateBatch,
  init_llm_inference_optimizer
};
