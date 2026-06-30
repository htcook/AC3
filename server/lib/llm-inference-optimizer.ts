/**
 * LLM Inference Optimizer
 * 
 * Implements three key optimizations from the architectural review:
 * 
 * 1. SEMANTIC DEDUPLICATION — Caches LLM responses keyed on semantic hash of input
 *    rather than literal hash, catching 30-50% redundancy in real-world workloads.
 * 
 * 2. CALL-SITE INSTRUMENTATION — Tracks per-caller, per-engagement call volume and
 *    token usage to identify graduation candidates (LLM calls that should be deterministic).
 * 
 * 3. COST ATTRIBUTION — Computes per-engagement and per-caller cost estimates using
 *    token-based pricing models, surfacing which call sites produce highest-value output
 *    vs. which are graduation candidates.
 * 
 * Design principle: This module wraps around the existing invokeLLM infrastructure
 * without modifying the core LLM module. It reads from the llm_telemetry table and
 * provides aggregation + caching layers on top.
 */

import { createHash } from 'crypto';

// ─── Semantic Hash Cache ─────────────────────────────────────────────────────

/**
 * Semantic hash strategy: normalize the input to remove trivial variations
 * (whitespace, ordering of non-ordered fields, timestamp noise) before hashing.
 * This catches cases where the same inference is requested with slightly different
 * framings — a pattern that accounts for 30-50% of redundant LLM calls.
 */

interface CacheEntry {
  responseContent: string;
  model: string;
  tokensIn: number;
  tokensOut: number;
  cachedAt: number;
  hitCount: number;
  caller: string;
  /** TTL in ms — entries expire after this duration */
  ttlMs: number;
}

interface SemanticCacheConfig {
  /** Maximum number of cached entries */
  maxEntries: number;
  /** Default TTL in ms (default: 30 minutes) */
  defaultTtlMs: number;
  /** Callers whose results should never be cached (e.g., exploit generation) */
  noCacheCallers: string[];
  /** Minimum input token count to bother caching (very short prompts aren't worth it) */
  minTokensToCache: number;
}

const DEFAULT_CACHE_CONFIG: SemanticCacheConfig = {
  maxEntries: 2000,
  defaultTtlMs: 30 * 60 * 1000, // 30 minutes
  noCacheCallers: [
    'exploit-generator',
    'c2-deployer',
    'credential-spray',
    'lateral-planner',
  ],
  minTokensToCache: 50,
};

export class SemanticInferenceCache {
  private cache: Map<string, CacheEntry> = new Map();
  private config: SemanticCacheConfig;
  
  // Stats
  private totalLookups = 0;
  private totalHits = 0;
  private totalMisses = 0;
  private totalEvictions = 0;
  private tokensSaved = 0;

  constructor(config?: Partial<SemanticCacheConfig>) {
    this.config = { ...DEFAULT_CACHE_CONFIG, ...config };
  }

  /**
   * Compute a semantic hash from LLM input messages.
   * Normalizes whitespace, strips timestamps/IDs, and sorts JSON keys
   * to produce a stable hash for semantically-equivalent inputs.
   */
  computeSemanticHash(messages: Array<{ role: string; content: string | any }>, responseFormat?: any): string {
    const normalized = messages.map(m => {
      let content = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
      
      // Normalize whitespace (collapse multiple spaces/newlines)
      content = content.replace(/\s+/g, ' ').trim();
      
      // Strip timestamps (ISO dates, Unix timestamps)
      content = content.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\dZ]*/g, '<TIMESTAMP>');
      content = content.replace(/\b1[6-7]\d{8,11}\b/g, '<UNIX_TS>');
      
      // Strip UUIDs
      content = content.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<UUID>');
      
      // Strip generated IDs (ops-TIMESTAMP-COUNTER pattern)
      content = content.replace(/ops-\d+-\d+/g, '<OPS_ID>');
      
      // Normalize IP addresses to class (preserve structure, not exact values)
      // This is intentionally NOT done — IPs are meaningful for scan context
      
      return `${m.role}:${content}`;
    }).join('|');
    
    // Include response format in hash (different schemas = different cache keys)
    const formatStr = responseFormat ? JSON.stringify(responseFormat) : '';
    
    return createHash('sha256').update(normalized + '||' + formatStr).digest('hex');
  }

  /**
   * Look up a cached response for the given input.
   * Returns null if no cache hit or if the caller is in the no-cache list.
   */
  lookup(
    messages: Array<{ role: string; content: string | any }>,
    caller?: string,
    responseFormat?: any
  ): { content: string; model: string; fromCache: true } | null {
    this.totalLookups++;
    
    // Never cache certain callers (security-sensitive operations)
    if (caller && this.config.noCacheCallers.some(nc => caller.includes(nc))) {
      this.totalMisses++;
      return null;
    }
    
    const hash = this.computeSemanticHash(messages, responseFormat);
    const entry = this.cache.get(hash);
    
    if (!entry) {
      this.totalMisses++;
      return null;
    }
    
    // Check TTL
    if (Date.now() - entry.cachedAt > entry.ttlMs) {
      this.cache.delete(hash);
      this.totalMisses++;
      this.totalEvictions++;
      return null;
    }
    
    // Cache hit
    entry.hitCount++;
    this.totalHits++;
    this.tokensSaved += entry.tokensIn + entry.tokensOut;
    
    return {
      content: entry.responseContent,
      model: entry.model,
      fromCache: true,
    };
  }

  /**
   * Store a response in the cache.
   */
  store(
    messages: Array<{ role: string; content: string | any }>,
    responseContent: string,
    model: string,
    tokensIn: number,
    tokensOut: number,
    caller?: string,
    responseFormat?: any,
    ttlMs?: number
  ): void {
    // Don't cache if caller is in no-cache list
    if (caller && this.config.noCacheCallers.some(nc => caller.includes(nc))) {
      return;
    }
    
    // Don't cache very short inputs (not worth the memory)
    if (tokensIn < this.config.minTokensToCache) {
      return;
    }
    
    // Evict oldest entries if at capacity
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
      caller: caller || 'unknown',
      ttlMs: ttlMs || this.config.defaultTtlMs,
    });
  }

  /**
   * Evict the least-recently-used entries to make room.
   */
  private evictOldest(): void {
    const entries = Array.from(this.cache.entries())
      .sort((a, b) => a[1].cachedAt - b[1].cachedAt);
    
    // Remove bottom 10%
    const toRemove = Math.max(1, Math.floor(entries.length * 0.1));
    for (let i = 0; i < toRemove; i++) {
      this.cache.delete(entries[i][0]);
      this.totalEvictions++;
    }
  }

  /**
   * Get cache statistics.
   */
  getStats(): SemanticCacheStats {
    return {
      totalEntries: this.cache.size,
      maxEntries: this.config.maxEntries,
      totalLookups: this.totalLookups,
      totalHits: this.totalHits,
      totalMisses: this.totalMisses,
      hitRate: this.totalLookups > 0 ? this.totalHits / this.totalLookups : 0,
      totalEvictions: this.totalEvictions,
      tokensSaved: this.tokensSaved,
      estimatedCostSaved: estimateCost(this.tokensSaved, 0, 'gpt-4o'), // Conservative estimate
    };
  }

  /**
   * Clear the entire cache.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get the most frequently hit cache entries (graduation candidates).
   */
  getGraduationCandidates(minHits: number = 5): Array<{
    caller: string;
    hitCount: number;
    tokensSaved: number;
    estimatedCostSaved: number;
  }> {
    const callerHits = new Map<string, { hitCount: number; tokensSaved: number }>();
    
    for (const entry of this.cache.values()) {
      if (entry.hitCount >= minHits) {
        const existing = callerHits.get(entry.caller) || { hitCount: 0, tokensSaved: 0 };
        existing.hitCount += entry.hitCount;
        existing.tokensSaved += (entry.tokensIn + entry.tokensOut) * entry.hitCount;
        callerHits.set(entry.caller, existing);
      }
    }
    
    return Array.from(callerHits.entries())
      .map(([caller, stats]) => ({
        caller,
        hitCount: stats.hitCount,
        tokensSaved: stats.tokensSaved,
        estimatedCostSaved: estimateCost(stats.tokensSaved, 0, 'gpt-4o'),
      }))
      .sort((a, b) => b.hitCount - a.hitCount);
  }
}

export interface SemanticCacheStats {
  totalEntries: number;
  maxEntries: number;
  totalLookups: number;
  totalHits: number;
  totalMisses: number;
  hitRate: number;
  totalEvictions: number;
  tokensSaved: number;
  estimatedCostSaved: number;
}

// ─── Cost Attribution Engine ─────────────────────────────────────────────────

/**
 * Pricing models for LLM cost estimation.
 * Prices are per 1M tokens as of early 2026.
 */
const MODEL_PRICING: Record<string, { inputPer1M: number; outputPer1M: number }> = {
  'gpt-4o': { inputPer1M: 2.50, outputPer1M: 10.00 },
  'gpt-4o-mini': { inputPer1M: 0.15, outputPer1M: 0.60 },
  'gpt-4-turbo': { inputPer1M: 10.00, outputPer1M: 30.00 },
  'gpt-4': { inputPer1M: 30.00, outputPer1M: 60.00 },
  'gpt-3.5-turbo': { inputPer1M: 0.50, outputPer1M: 1.50 },
  'gemini-2.5-flash': { inputPer1M: 0.15, outputPer1M: 0.60 },
  'gemini-2.5-pro': { inputPer1M: 1.25, outputPer1M: 10.00 },
  'gemini-2.0-flash': { inputPer1M: 0.10, outputPer1M: 0.40 },
  // Forge-routed calls (cost is effectively the Forge tier pricing)
  'forge-standard': { inputPer1M: 0.15, outputPer1M: 0.60 },
  'forge-bulk': { inputPer1M: 0.10, outputPer1M: 0.40 },
};

/**
 * Estimate cost for a given number of tokens.
 */
export function estimateCost(tokensIn: number, tokensOut: number, model: string): number {
  const pricing = MODEL_PRICING[model] || MODEL_PRICING['gpt-4o'];
  return (tokensIn / 1_000_000) * pricing.inputPer1M + (tokensOut / 1_000_000) * pricing.outputPer1M;
}

/**
 * Per-engagement cost and call-site attribution.
 * Aggregates telemetry data to produce actionable cost reports.
 */
export interface EngagementCostReport {
  engagementId: number;
  totalCalls: number;
  totalTokensIn: number;
  totalTokensOut: number;
  totalEstimatedCost: number;
  costPerAsset: number;
  assetCount: number;
  
  /** Call-site breakdown: which callers contribute most volume/cost */
  callSiteBreakdown: CallSiteAttribution[];
  
  /** Model routing breakdown: how calls split across models */
  modelBreakdown: Array<{
    model: string;
    calls: number;
    tokensIn: number;
    tokensOut: number;
    estimatedCost: number;
    percentOfTotal: number;
  }>;
  
  /** Graduation candidates: callers with high volume that could be deterministic */
  graduationCandidates: GraduationCandidate[];
  
  /** Time-series: calls per minute for the engagement */
  callsPerMinute: Array<{ minute: number; calls: number; cost: number }>;
}

export interface CallSiteAttribution {
  caller: string;
  calls: number;
  tokensIn: number;
  tokensOut: number;
  estimatedCost: number;
  percentOfTotalCost: number;
  avgLatencyMs: number;
  errorRate: number;
  /** Priority tier this caller typically uses */
  primaryPriority: string;
}

export interface GraduationCandidate {
  caller: string;
  reason: string;
  calls: number;
  estimatedCost: number;
  /** Estimated cost savings if graduated to deterministic */
  potentialSavings: number;
  /** Confidence that this can be graduated (0-1) */
  graduationConfidence: number;
}

/**
 * Build a cost attribution report from raw telemetry data.
 */
export function buildCostReport(
  engagementId: number,
  telemetryRows: Array<{
    caller: string;
    model: string;
    llmStatus: string;
    latencyMs: number;
    tokensIn: number;
    tokensOut: number;
    calledAt: string | Date;
  }>,
  assetCount: number
): EngagementCostReport {
  const callSiteMap = new Map<string, {
    calls: number;
    tokensIn: number;
    tokensOut: number;
    cost: number;
    latencies: number[];
    errors: number;
  }>();
  
  const modelMap = new Map<string, {
    calls: number;
    tokensIn: number;
    tokensOut: number;
    cost: number;
  }>();
  
  let totalCost = 0;
  let totalTokensIn = 0;
  let totalTokensOut = 0;
  
  // Time-series buckets (1-minute resolution)
  const minuteBuckets = new Map<number, { calls: number; cost: number }>();
  const engagementStart = telemetryRows.length > 0
    ? new Date(telemetryRows[0].calledAt).getTime()
    : Date.now();
  
  for (const row of telemetryRows) {
    const cost = estimateCost(row.tokensIn || 0, row.tokensOut || 0, row.model);
    totalCost += cost;
    totalTokensIn += row.tokensIn || 0;
    totalTokensOut += row.tokensOut || 0;
    
    // Call-site attribution
    const existing = callSiteMap.get(row.caller) || {
      calls: 0, tokensIn: 0, tokensOut: 0, cost: 0, latencies: [], errors: 0,
    };
    existing.calls++;
    existing.tokensIn += row.tokensIn || 0;
    existing.tokensOut += row.tokensOut || 0;
    existing.cost += cost;
    existing.latencies.push(row.latencyMs);
    if (row.llmStatus === 'error' || row.llmStatus === 'timeout') existing.errors++;
    callSiteMap.set(row.caller, existing);
    
    // Model breakdown
    const modelEntry = modelMap.get(row.model) || { calls: 0, tokensIn: 0, tokensOut: 0, cost: 0 };
    modelEntry.calls++;
    modelEntry.tokensIn += row.tokensIn || 0;
    modelEntry.tokensOut += row.tokensOut || 0;
    modelEntry.cost += cost;
    modelMap.set(row.model, modelEntry);
    
    // Time-series
    const calledAt = new Date(row.calledAt).getTime();
    const minuteOffset = Math.floor((calledAt - engagementStart) / 60000);
    const bucket = minuteBuckets.get(minuteOffset) || { calls: 0, cost: 0 };
    bucket.calls++;
    bucket.cost += cost;
    minuteBuckets.set(minuteOffset, bucket);
  }
  
  // Build call-site breakdown
  const callSiteBreakdown: CallSiteAttribution[] = Array.from(callSiteMap.entries())
    .map(([caller, data]) => ({
      caller,
      calls: data.calls,
      tokensIn: data.tokensIn,
      tokensOut: data.tokensOut,
      estimatedCost: data.cost,
      percentOfTotalCost: totalCost > 0 ? (data.cost / totalCost) * 100 : 0,
      avgLatencyMs: data.latencies.length > 0
        ? data.latencies.reduce((s, l) => s + l, 0) / data.latencies.length
        : 0,
      errorRate: data.calls > 0 ? data.errors / data.calls : 0,
      primaryPriority: inferPriority(caller),
    }))
    .sort((a, b) => b.estimatedCost - a.estimatedCost);
  
  // Build model breakdown
  const modelBreakdown = Array.from(modelMap.entries())
    .map(([model, data]) => ({
      model,
      calls: data.calls,
      tokensIn: data.tokensIn,
      tokensOut: data.tokensOut,
      estimatedCost: data.cost,
      percentOfTotal: totalCost > 0 ? (data.cost / totalCost) * 100 : 0,
    }))
    .sort((a, b) => b.estimatedCost - a.estimatedCost);
  
  // Identify graduation candidates
  const graduationCandidates = identifyGraduationCandidates(callSiteBreakdown, telemetryRows.length);
  
  // Build time-series
  const callsPerMinute = Array.from(minuteBuckets.entries())
    .map(([minute, data]) => ({ minute, ...data }))
    .sort((a, b) => a.minute - b.minute);
  
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
    callsPerMinute,
  };
}

/**
 * Identify callers that are strong graduation candidates.
 * These are high-volume callers whose work could potentially be
 * moved to deterministic code or smaller models.
 */
function identifyGraduationCandidates(
  callSites: CallSiteAttribution[],
  totalCalls: number
): GraduationCandidate[] {
  const candidates: GraduationCandidate[] = [];
  
  // Patterns that suggest graduation potential
  const GRADUATION_PATTERNS: Array<{
    pattern: RegExp;
    reason: string;
    confidence: number;
  }> = [
    {
      pattern: /format|normaliz|template|render|stringify/i,
      reason: 'Formatting/normalization — likely replaceable with templates',
      confidence: 0.85,
    },
    {
      pattern: /classif|categoriz|label|tag/i,
      reason: 'Classification — may be replaceable with rule-based classifier',
      confidence: 0.70,
    },
    {
      pattern: /validat|check|verify|confirm/i,
      reason: 'Validation — may be replaceable with deterministic checks',
      confidence: 0.65,
    },
    {
      pattern: /summar|extract|parse|convert/i,
      reason: 'Summarization/extraction — consider regex or structured parsing',
      confidence: 0.60,
    },
    {
      pattern: /enrich|lookup|resolve/i,
      reason: 'Enrichment — consider caching or lookup tables',
      confidence: 0.55,
    },
    {
      pattern: /dedup|merge|consolidat/i,
      reason: 'Deduplication/merging — typically deterministic',
      confidence: 0.80,
    },
  ];
  
  for (const site of callSites) {
    // Only consider high-volume callers (>2% of total calls)
    if (site.calls < totalCalls * 0.02) continue;
    
    for (const gp of GRADUATION_PATTERNS) {
      if (gp.pattern.test(site.caller)) {
        candidates.push({
          caller: site.caller,
          reason: gp.reason,
          calls: site.calls,
          estimatedCost: site.estimatedCost,
          potentialSavings: site.estimatedCost * gp.confidence,
          graduationConfidence: gp.confidence,
        });
        break; // Only one reason per caller
      }
    }
    
    // Also flag callers with very high volume regardless of name
    if (site.calls > totalCalls * 0.10 && !candidates.find(c => c.caller === site.caller)) {
      candidates.push({
        caller: site.caller,
        reason: `High volume (${((site.calls / totalCalls) * 100).toFixed(1)}% of all calls) — investigate for batching or caching opportunities`,
        calls: site.calls,
        estimatedCost: site.estimatedCost,
        potentialSavings: site.estimatedCost * 0.3, // Conservative 30% savings estimate
        graduationConfidence: 0.40,
      });
    }
  }
  
  return candidates.sort((a, b) => b.potentialSavings - a.potentialSavings);
}

/**
 * Infer the priority tier from a caller name.
 */
function inferPriority(caller: string): string {
  const essentialPatterns = /exploit|attack-plan|vuln-verif|hybrid-scor/i;
  const bulkPatterns = /enrich|summar|report|classif|format|normaliz/i;
  
  if (essentialPatterns.test(caller)) return 'essential';
  if (bulkPatterns.test(caller)) return 'bulk';
  return 'standard';
}

// ─── Call-Site Volume Tracker ────────────────────────────────────────────────

/**
 * In-memory tracker for real-time call-site volume monitoring.
 * Complements the DB-persisted telemetry with live counters.
 */
export class CallSiteVolumeTracker {
  private counters = new Map<string, {
    calls: number;
    tokensIn: number;
    tokensOut: number;
    errors: number;
    lastCallAt: number;
    /** Rolling window: calls in the last 5 minutes */
    recentCalls: number[];
  }>();
  
  private engagementCounters = new Map<number, {
    totalCalls: number;
    totalTokensIn: number;
    totalTokensOut: number;
    startedAt: number;
  }>();

  /**
   * Record a call from a specific caller.
   */
  recordCall(caller: string, tokensIn: number, tokensOut: number, isError: boolean, engagementId?: number): void {
    // Per-caller tracking
    const existing = this.counters.get(caller) || {
      calls: 0, tokensIn: 0, tokensOut: 0, errors: 0, lastCallAt: 0, recentCalls: [],
    };
    existing.calls++;
    existing.tokensIn += tokensIn;
    existing.tokensOut += tokensOut;
    if (isError) existing.errors++;
    existing.lastCallAt = Date.now();
    
    // Rolling window (5-minute buckets)
    const minuteBucket = Math.floor(Date.now() / 60000);
    existing.recentCalls.push(minuteBucket);
    // Keep only last 5 minutes
    const cutoff = minuteBucket - 5;
    existing.recentCalls = existing.recentCalls.filter(m => m > cutoff);
    
    this.counters.set(caller, existing);
    
    // Per-engagement tracking
    if (engagementId) {
      const engEntry = this.engagementCounters.get(engagementId) || {
        totalCalls: 0, totalTokensIn: 0, totalTokensOut: 0, startedAt: Date.now(),
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
  getCallRate(caller: string): number {
    const entry = this.counters.get(caller);
    if (!entry) return 0;
    return entry.recentCalls.length / 5; // Average over 5-minute window
  }

  /**
   * Get top callers by volume.
   */
  getTopCallers(limit: number = 20): Array<{
    caller: string;
    calls: number;
    tokensTotal: number;
    estimatedCost: number;
    callsPerMinute: number;
  }> {
    return Array.from(this.counters.entries())
      .map(([caller, data]) => ({
        caller,
        calls: data.calls,
        tokensTotal: data.tokensIn + data.tokensOut,
        estimatedCost: estimateCost(data.tokensIn, data.tokensOut, 'gpt-4o'),
        callsPerMinute: this.getCallRate(caller),
      }))
      .sort((a, b) => b.calls - a.calls)
      .slice(0, limit);
  }

  /**
   * Get per-engagement summary.
   */
  getEngagementSummary(engagementId: number): {
    totalCalls: number;
    totalTokens: number;
    estimatedCost: number;
    callsPerMinute: number;
    durationMinutes: number;
  } | null {
    const entry = this.engagementCounters.get(engagementId);
    if (!entry) return null;
    
    const durationMs = Date.now() - entry.startedAt;
    const durationMinutes = Math.max(1, durationMs / 60000);
    
    return {
      totalCalls: entry.totalCalls,
      totalTokens: entry.totalTokensIn + entry.totalTokensOut,
      estimatedCost: estimateCost(entry.totalTokensIn, entry.totalTokensOut, 'gpt-4o'),
      callsPerMinute: entry.totalCalls / durationMinutes,
      durationMinutes,
    };
  }

  /**
   * Detect anomalous call patterns (potential loops or runaway inference).
   */
  detectAnomalies(): Array<{
    caller: string;
    anomalyType: 'high_rate' | 'high_volume' | 'high_error_rate';
    details: string;
    severity: 'warning' | 'critical';
  }> {
    const anomalies: Array<{
      caller: string;
      anomalyType: 'high_rate' | 'high_volume' | 'high_error_rate';
      details: string;
      severity: 'warning' | 'critical';
    }> = [];
    
    for (const [caller, data] of this.counters) {
      const rate = this.getCallRate(caller);
      
      // High rate: >20 calls/minute sustained
      if (rate > 20) {
        anomalies.push({
          caller,
          anomalyType: 'high_rate',
          details: `${rate.toFixed(1)} calls/min (threshold: 20). Possible LLM-in-loop pattern.`,
          severity: rate > 50 ? 'critical' : 'warning',
        });
      }
      
      // High error rate: >30% errors
      if (data.calls > 10 && data.errors / data.calls > 0.3) {
        anomalies.push({
          caller,
          anomalyType: 'high_error_rate',
          details: `${((data.errors / data.calls) * 100).toFixed(0)}% error rate over ${data.calls} calls.`,
          severity: data.errors / data.calls > 0.5 ? 'critical' : 'warning',
        });
      }
    }
    
    return anomalies;
  }

  /**
   * Reset all counters.
   */
  reset(): void {
    this.counters.clear();
    this.engagementCounters.clear();
  }
}

// ─── Singleton Instances ─────────────────────────────────────────────────────

/** Global semantic cache instance */
export const inferenceCache = new SemanticInferenceCache();

/** Global call-site volume tracker */
export const callSiteTracker = new CallSiteVolumeTracker();

// ─── Batch Deduplication ─────────────────────────────────────────────────────

/**
 * Deduplicate a batch of LLM calls that are about to be made.
 * Groups semantically-equivalent calls and returns deduplicated set.
 * Useful for loop patterns where the same inference is requested per-item.
 */
export function deduplicateBatch(
  calls: Array<{
    id: string;
    messages: Array<{ role: string; content: string | any }>;
    responseFormat?: any;
  }>
): {
  unique: Array<{ id: string; messages: Array<{ role: string; content: string | any }>; responseFormat?: any; duplicateIds: string[] }>;
  duplicateCount: number;
  deduplicationRate: number;
} {
  const hashMap = new Map<string, { call: typeof calls[0]; duplicateIds: string[] }>();
  
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
    duplicateIds,
  }));
  
  const duplicateCount = calls.length - unique.length;
  
  return {
    unique,
    duplicateCount,
    deduplicationRate: calls.length > 0 ? duplicateCount / calls.length : 0,
  };
}
