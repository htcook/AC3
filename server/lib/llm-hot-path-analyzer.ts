/**
 * LLM Hot Path Analyzer
 * 
 * Addresses Claude's review recommendation: "60K calls per engagement is the operational
 * metric most worth understanding. Bring me the call sites that produce the most volume."
 * 
 * This module provides:
 * 1. AUTOMATED HOT PATH IDENTIFICATION — Finds the top N call sites by volume, cost,
 *    and latency impact per engagement.
 * 2. GRADUATION SCORING — For each hot-path call site, computes a graduation readiness
 *    score based on output stability, determinism, and pattern repetition.
 * 3. REDUNDANCY DETECTION — Identifies call sites making semantically equivalent requests
 *    that could be batched or deduplicated.
 * 4. OPTIMIZATION RECOMMENDATIONS — Generates prioritized, actionable recommendations
 *    for reducing LLM call volume without losing capability.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HotPathCallSite {
  caller: string;
  
  /** Volume metrics */
  totalCalls: number;
  callsPerEngagement: number;
  percentOfTotal: number;
  
  /** Cost metrics */
  totalTokensIn: number;
  totalTokensOut: number;
  estimatedCost: number;
  costPercentOfTotal: number;
  
  /** Latency impact */
  avgLatencyMs: number;
  p95LatencyMs: number;
  totalLatencyMs: number;
  
  /** Output stability (key for graduation) */
  outputStability: number; // 0-1, how consistent are outputs for similar inputs
  outputDeterminism: number; // 0-1, same input → same output?
  
  /** Graduation readiness */
  graduationScore: number; // 0-1 composite score
  graduationRecommendation: GraduationRecommendation;
  graduationReason: string;
}

export type GraduationRecommendation =
  | 'graduate_now'       // High stability, deterministic, pattern is clear
  | 'graduate_partial'   // Some outputs are stable, others aren't
  | 'batch_optimize'     // Can't graduate but can batch similar calls
  | 'cache_optimize'     // Can't graduate but caching would help
  | 'keep_llm'           // Genuinely needs LLM reasoning
  | 'investigate';       // Unclear — needs manual review

export interface RedundancyCluster {
  /** Representative caller from the cluster */
  primaryCaller: string;
  
  /** All callers in this redundancy cluster */
  callers: string[];
  
  /** How similar the calls are (0-1) */
  similarity: number;
  
  /** Total calls across all callers in cluster */
  totalCalls: number;
  
  /** Estimated savings if deduplicated */
  estimatedSavings: {
    callsReduced: number;
    tokensReduced: number;
    costReduced: number;
  };
  
  /** Recommendation */
  recommendation: string;
}

export interface HotPathAnalysis {
  engagementId?: number;
  analyzedAt: number;
  
  /** Summary */
  summary: {
    totalCalls: number;
    totalCost: number;
    totalLatencyMs: number;
    uniqueCallers: number;
    avgCallsPerCaller: number;
    top5CallerPercent: number; // What % of calls come from top 5 callers
  };
  
  /** Top call sites ranked by impact */
  hotPaths: HotPathCallSite[];
  
  /** Redundancy clusters */
  redundancyClusters: RedundancyCluster[];
  
  /** Prioritized optimization recommendations */
  recommendations: OptimizationRecommendation[];
  
  /** Estimated savings if all recommendations implemented */
  projectedSavings: {
    callsReduced: number;
    callReductionPercent: number;
    costReduced: number;
    costReductionPercent: number;
    latencyReduced: number;
  };
}

export interface OptimizationRecommendation {
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: 'graduation' | 'batching' | 'caching' | 'elimination' | 'restructuring';
  caller: string;
  title: string;
  description: string;
  estimatedImpact: {
    callsReduced: number;
    costReduced: number;
    latencyReduced: number;
  };
  implementationComplexity: 'trivial' | 'moderate' | 'complex';
  confidence: number; // 0-1
}

// ─── Telemetry Record (matches what's stored in DB) ──────────────────────────

export interface TelemetryRecord {
  caller: string;
  model: string;
  llmStatus: string;
  latencyMs: number;
  tokensIn: number;
  tokensOut: number;
  calledAt: string;
  engagementId?: number;
  errorMessage?: string;
}

// ─── Cost Estimation ─────────────────────────────────────────────────────────

const MODEL_PRICING: Record<string, { inputPer1M: number; outputPer1M: number }> = {
  'gpt-4o': { inputPer1M: 2.50, outputPer1M: 10.00 },
  'gpt-4o-mini': { inputPer1M: 0.15, outputPer1M: 0.60 },
  'gpt-3.5-turbo': { inputPer1M: 0.50, outputPer1M: 1.50 },
  'gemini-2.5-flash': { inputPer1M: 0.15, outputPer1M: 0.60 },
};

function estimateCallCost(tokensIn: number, tokensOut: number, model: string = 'gpt-4o'): number {
  const pricing = MODEL_PRICING[model] || MODEL_PRICING['gpt-4o'];
  return (tokensIn * pricing.inputPer1M + tokensOut * pricing.outputPer1M) / 1_000_000;
}

// ─── Output Stability Analysis ───────────────────────────────────────────────

/**
 * Analyze output stability for a caller based on response patterns.
 * High stability = outputs are consistent for similar inputs = graduation candidate.
 */
function analyzeOutputStability(records: TelemetryRecord[]): { stability: number; determinism: number } {
  if (records.length < 5) return { stability: 0.5, determinism: 0.5 }; // Insufficient data
  
  // Stability heuristic: consistent token output counts suggest stable patterns
  const outputTokens = records.filter(r => r.tokensOut > 0).map(r => r.tokensOut);
  if (outputTokens.length < 3) return { stability: 0.5, determinism: 0.5 };
  
  const mean = outputTokens.reduce((s, v) => s + v, 0) / outputTokens.length;
  const variance = outputTokens.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / outputTokens.length;
  const cv = mean > 0 ? Math.sqrt(variance) / mean : 1; // Coefficient of variation
  
  // Low CV = high stability (outputs are consistent length)
  const stability = Math.max(0, Math.min(1, 1 - cv));
  
  // Determinism heuristic: if latency is very consistent, likely deterministic
  const latencies = records.filter(r => r.latencyMs > 0).map(r => r.latencyMs);
  const latencyMean = latencies.reduce((s, v) => s + v, 0) / latencies.length;
  const latencyCV = latencyMean > 0
    ? Math.sqrt(latencies.reduce((s, v) => s + Math.pow(v - latencyMean, 2), 0) / latencies.length) / latencyMean
    : 1;
  const determinism = Math.max(0, Math.min(1, 1 - latencyCV * 0.5));
  
  return { stability, determinism };
}

// ─── Graduation Scoring ──────────────────────────────────────────────────────

/** Callers that are known to require LLM reasoning (never graduate) */
const NON_GRADUATABLE_CALLERS = new Set([
  'engagement-orchestrator.generateScanPlan',
  'engagement-orchestrator.generateExploitChain',
  'engagement-orchestrator.triageFinding',
  'engagement-orchestrator.generateReport',
  'bounty-report-generator',
  'bia-enrichment',
  'campaign-builder.generateTTP',
]);

/** Callers that are strong graduation candidates (format/classify/normalize) */
const GRADUATION_CANDIDATE_PATTERNS = [
  /format/i, /normalize/i, /classify/i, /categorize/i,
  /parse/i, /extract/i, /summarize/i, /template/i,
  /score/i, /rank/i, /label/i, /tag/i,
];

function computeGraduationScore(
  caller: string,
  stability: number,
  determinism: number,
  callVolume: number,
  errorRate: number
): { score: number; recommendation: GraduationRecommendation; reason: string } {
  // Non-graduatable callers
  if (NON_GRADUATABLE_CALLERS.has(caller)) {
    return {
      score: 0.1,
      recommendation: 'keep_llm',
      reason: `${caller} requires genuine LLM reasoning — not a graduation candidate`,
    };
  }
  
  // Base score from stability and determinism
  let score = (stability * 0.5 + determinism * 0.3);
  
  // Bonus for matching graduation candidate patterns
  const matchesPattern = GRADUATION_CANDIDATE_PATTERNS.some(p => p.test(caller));
  if (matchesPattern) score += 0.15;
  
  // Bonus for high volume (more data = more confidence in stability)
  if (callVolume > 100) score += 0.05;
  if (callVolume > 500) score += 0.05;
  
  // Penalty for high error rate
  if (errorRate > 0.1) score -= 0.1;
  if (errorRate > 0.3) score -= 0.2;
  
  score = Math.max(0, Math.min(1, score));
  
  // Determine recommendation
  let recommendation: GraduationRecommendation;
  let reason: string;
  
  if (score >= 0.8) {
    recommendation = 'graduate_now';
    reason = `High stability (${(stability * 100).toFixed(0)}%) and determinism (${(determinism * 100).toFixed(0)}%) — outputs are predictable enough to replace with deterministic code`;
  } else if (score >= 0.65) {
    recommendation = 'graduate_partial';
    reason = `Moderate stability — some output patterns are predictable. Consider graduating the common cases and keeping LLM for edge cases`;
  } else if (score >= 0.5 && callVolume > 50) {
    recommendation = 'cache_optimize';
    reason = `Not stable enough to graduate, but high volume suggests caching would significantly reduce calls`;
  } else if (score >= 0.4 && callVolume > 20) {
    recommendation = 'batch_optimize';
    reason = `Multiple calls with similar patterns — consider batching into fewer, larger calls`;
  } else if (score < 0.3) {
    recommendation = 'keep_llm';
    reason = `Low stability and determinism — this caller genuinely needs LLM reasoning for each call`;
  } else {
    recommendation = 'investigate';
    reason = `Unclear pattern — manual review recommended to determine if optimization is possible`;
  }
  
  return { score, recommendation, reason };
}

// ─── Redundancy Detection ────────────────────────────────────────────────────

/**
 * Detect callers that are making semantically similar requests.
 * Groups callers by name similarity and call pattern overlap.
 */
function detectRedundancyClusters(
  callerStats: Map<string, { calls: number; avgTokensIn: number; avgTokensOut: number; totalCost: number }>
): RedundancyCluster[] {
  const callers = Array.from(callerStats.entries());
  const clusters: RedundancyCluster[] = [];
  const clustered = new Set<string>();
  
  for (let i = 0; i < callers.length; i++) {
    if (clustered.has(callers[i][0])) continue;
    
    const cluster: string[] = [callers[i][0]];
    
    for (let j = i + 1; j < callers.length; j++) {
      if (clustered.has(callers[j][0])) continue;
      
      const similarity = computeCallerSimilarity(
        callers[i][0], callers[i][1],
        callers[j][0], callers[j][1]
      );
      
      if (similarity > 0.7) {
        cluster.push(callers[j][0]);
        clustered.add(callers[j][0]);
      }
    }
    
    if (cluster.length > 1) {
      clustered.add(callers[i][0]);
      
      const totalCalls = cluster.reduce((s, c) => s + (callerStats.get(c)?.calls || 0), 0);
      const totalCost = cluster.reduce((s, c) => s + (callerStats.get(c)?.totalCost || 0), 0);
      const deduplicatedCalls = Math.floor(totalCalls * 0.4); // Estimate 40% dedup
      
      clusters.push({
        primaryCaller: cluster[0],
        callers: cluster,
        similarity: 0.75,
        totalCalls,
        estimatedSavings: {
          callsReduced: deduplicatedCalls,
          tokensReduced: deduplicatedCalls * 2000, // Avg tokens per call estimate
          costReduced: totalCost * 0.4,
        },
        recommendation: `Callers ${cluster.join(', ')} appear to perform similar work. Consider unifying into a single caller with parameterized behavior.`,
      });
    }
  }
  
  return clusters;
}

function computeCallerSimilarity(
  name1: string, stats1: { calls: number; avgTokensIn: number; avgTokensOut: number },
  name2: string, stats2: { calls: number; avgTokensIn: number; avgTokensOut: number }
): number {
  // Name similarity (Jaccard on tokens)
  const tokens1 = new Set(name1.toLowerCase().split(/[.\-_/]/));
  const tokens2 = new Set(name2.toLowerCase().split(/[.\-_/]/));
  const intersection = new Set([...tokens1].filter(t => tokens2.has(t)));
  const union = new Set([...tokens1, ...tokens2]);
  const nameSimilarity = union.size > 0 ? intersection.size / union.size : 0;
  
  // Token profile similarity
  const tokenRatio = Math.min(stats1.avgTokensIn, stats2.avgTokensIn) / Math.max(stats1.avgTokensIn, stats2.avgTokensIn) || 0;
  const outputRatio = Math.min(stats1.avgTokensOut, stats2.avgTokensOut) / Math.max(stats1.avgTokensOut, stats2.avgTokensOut) || 0;
  
  return nameSimilarity * 0.5 + tokenRatio * 0.25 + outputRatio * 0.25;
}

// ─── Main Analysis Function ──────────────────────────────────────────────────

/**
 * Perform a comprehensive hot path analysis on LLM telemetry data.
 * This is the main entry point — call it with telemetry records from the database.
 */
export function analyzeHotPaths(
  telemetry: TelemetryRecord[],
  options: {
    engagementId?: number;
    topN?: number;
    minCallsForAnalysis?: number;
  } = {}
): HotPathAnalysis {
  const { engagementId, topN = 20, minCallsForAnalysis = 5 } = options;
  
  // Filter by engagement if specified
  const records = engagementId
    ? telemetry.filter(r => r.engagementId === engagementId)
    : telemetry;
  
  if (records.length === 0) {
    return {
      engagementId,
      analyzedAt: Date.now(),
      summary: { totalCalls: 0, totalCost: 0, totalLatencyMs: 0, uniqueCallers: 0, avgCallsPerCaller: 0, top5CallerPercent: 0 },
      hotPaths: [],
      redundancyClusters: [],
      recommendations: [],
      projectedSavings: { callsReduced: 0, callReductionPercent: 0, costReduced: 0, costReductionPercent: 0, latencyReduced: 0 },
    };
  }
  
  // Group by caller
  const callerGroups = new Map<string, TelemetryRecord[]>();
  for (const record of records) {
    const caller = record.caller || 'unknown';
    if (!callerGroups.has(caller)) callerGroups.set(caller, []);
    callerGroups.get(caller)!.push(record);
  }
  
  // Compute per-caller stats
  const totalCalls = records.length;
  let totalCost = 0;
  let totalLatency = 0;
  
  const callerStats = new Map<string, { calls: number; avgTokensIn: number; avgTokensOut: number; totalCost: number }>();
  const hotPaths: HotPathCallSite[] = [];
  
  for (const [caller, callerRecords] of callerGroups) {
    if (callerRecords.length < minCallsForAnalysis) continue;
    
    const calls = callerRecords.length;
    const tokensIn = callerRecords.reduce((s, r) => s + (r.tokensIn || 0), 0);
    const tokensOut = callerRecords.reduce((s, r) => s + (r.tokensOut || 0), 0);
    const latencies = callerRecords.map(r => r.latencyMs).filter(l => l > 0).sort((a, b) => a - b);
    const errors = callerRecords.filter(r => r.llmStatus === 'error' || r.llmStatus === 'timeout').length;
    const errorRate = errors / calls;
    
    const cost = callerRecords.reduce((s, r) => s + estimateCallCost(r.tokensIn || 0, r.tokensOut || 0, r.model), 0);
    totalCost += cost;
    const callerLatency = latencies.reduce((s, v) => s + v, 0);
    totalLatency += callerLatency;
    
    callerStats.set(caller, {
      calls,
      avgTokensIn: tokensIn / calls,
      avgTokensOut: tokensOut / calls,
      totalCost: cost,
    });
    
    // Output stability analysis
    const { stability, determinism } = analyzeOutputStability(callerRecords);
    
    // Graduation scoring
    const { score: graduationScore, recommendation, reason } = computeGraduationScore(
      caller, stability, determinism, calls, errorRate
    );
    
    const avgLatency = latencies.length > 0 ? latencies.reduce((s, v) => s + v, 0) / latencies.length : 0;
    const p95Idx = Math.floor(latencies.length * 0.95);
    const p95Latency = latencies[p95Idx] || avgLatency;
    
    hotPaths.push({
      caller,
      totalCalls: calls,
      callsPerEngagement: calls, // Will be divided if multi-engagement
      percentOfTotal: (calls / totalCalls) * 100,
      totalTokensIn: tokensIn,
      totalTokensOut: tokensOut,
      estimatedCost: cost,
      costPercentOfTotal: 0, // Computed after loop
      avgLatencyMs: avgLatency,
      p95LatencyMs: p95Latency,
      totalLatencyMs: callerLatency,
      outputStability: stability,
      outputDeterminism: determinism,
      graduationScore,
      graduationRecommendation: recommendation,
      graduationReason: reason,
    });
  }
  
  // Sort by total calls (descending) and take top N
  hotPaths.sort((a, b) => b.totalCalls - a.totalCalls);
  const topHotPaths = hotPaths.slice(0, topN);
  
  // Fill in cost percentages
  for (const hp of topHotPaths) {
    hp.costPercentOfTotal = totalCost > 0 ? (hp.estimatedCost / totalCost) * 100 : 0;
  }
  
  // Redundancy detection
  const redundancyClusters = detectRedundancyClusters(callerStats);
  
  // Generate recommendations
  const recommendations = generateRecommendations(topHotPaths, redundancyClusters, totalCalls, totalCost);
  
  // Project savings
  const projectedSavings = projectSavings(recommendations, totalCalls, totalCost, totalLatency);
  
  // Summary
  const top5Calls = topHotPaths.slice(0, 5).reduce((s, hp) => s + hp.totalCalls, 0);
  
  return {
    engagementId,
    analyzedAt: Date.now(),
    summary: {
      totalCalls,
      totalCost,
      totalLatencyMs: totalLatency,
      uniqueCallers: callerGroups.size,
      avgCallsPerCaller: totalCalls / callerGroups.size,
      top5CallerPercent: (top5Calls / totalCalls) * 100,
    },
    hotPaths: topHotPaths,
    redundancyClusters,
    recommendations,
    projectedSavings,
  };
}

// ─── Recommendation Generation ───────────────────────────────────────────────

function generateRecommendations(
  hotPaths: HotPathCallSite[],
  clusters: RedundancyCluster[],
  totalCalls: number,
  totalCost: number
): OptimizationRecommendation[] {
  const recommendations: OptimizationRecommendation[] = [];
  
  // 1. Graduation recommendations (highest impact)
  for (const hp of hotPaths) {
    if (hp.graduationRecommendation === 'graduate_now') {
      recommendations.push({
        priority: hp.percentOfTotal > 10 ? 'critical' : 'high',
        category: 'graduation',
        caller: hp.caller,
        title: `Graduate "${hp.caller}" to deterministic code`,
        description: `This caller accounts for ${hp.percentOfTotal.toFixed(1)}% of all LLM calls with ${(hp.outputStability * 100).toFixed(0)}% output stability. ${hp.graduationReason}`,
        estimatedImpact: {
          callsReduced: Math.floor(hp.totalCalls * 0.9), // 90% can be graduated
          costReduced: hp.estimatedCost * 0.9,
          latencyReduced: hp.totalLatencyMs * 0.9,
        },
        implementationComplexity: 'moderate',
        confidence: hp.graduationScore,
      });
    } else if (hp.graduationRecommendation === 'graduate_partial') {
      recommendations.push({
        priority: hp.percentOfTotal > 5 ? 'high' : 'medium',
        category: 'graduation',
        caller: hp.caller,
        title: `Partially graduate "${hp.caller}"`,
        description: `${hp.graduationReason}. Estimated 50% of calls can be handled deterministically.`,
        estimatedImpact: {
          callsReduced: Math.floor(hp.totalCalls * 0.5),
          costReduced: hp.estimatedCost * 0.5,
          latencyReduced: hp.totalLatencyMs * 0.5,
        },
        implementationComplexity: 'complex',
        confidence: hp.graduationScore,
      });
    } else if (hp.graduationRecommendation === 'cache_optimize') {
      recommendations.push({
        priority: 'medium',
        category: 'caching',
        caller: hp.caller,
        title: `Optimize caching for "${hp.caller}"`,
        description: `${hp.graduationReason}. Extend cache TTL or implement caller-specific caching strategy.`,
        estimatedImpact: {
          callsReduced: Math.floor(hp.totalCalls * 0.3),
          costReduced: hp.estimatedCost * 0.3,
          latencyReduced: hp.totalLatencyMs * 0.3,
        },
        implementationComplexity: 'trivial',
        confidence: 0.7,
      });
    }
  }
  
  // 2. Redundancy elimination recommendations
  for (const cluster of clusters) {
    recommendations.push({
      priority: cluster.totalCalls > 100 ? 'high' : 'medium',
      category: 'elimination',
      caller: cluster.primaryCaller,
      title: `Unify redundant callers: ${cluster.callers.join(', ')}`,
      description: cluster.recommendation,
      estimatedImpact: {
        callsReduced: cluster.estimatedSavings.callsReduced,
        costReduced: cluster.estimatedSavings.costReduced,
        latencyReduced: cluster.estimatedSavings.callsReduced * 1500, // Avg 1.5s per call
      },
      implementationComplexity: 'moderate',
      confidence: cluster.similarity,
    });
  }
  
  // 3. Batching recommendations for high-volume callers
  for (const hp of hotPaths) {
    if (hp.graduationRecommendation === 'batch_optimize' && hp.totalCalls > 20) {
      recommendations.push({
        priority: 'medium',
        category: 'batching',
        caller: hp.caller,
        title: `Batch calls for "${hp.caller}"`,
        description: `${hp.totalCalls} individual calls could be batched into fewer, larger requests. ${hp.graduationReason}`,
        estimatedImpact: {
          callsReduced: Math.floor(hp.totalCalls * 0.6),
          costReduced: hp.estimatedCost * 0.2, // Batching reduces calls but not tokens much
          latencyReduced: hp.totalLatencyMs * 0.5,
        },
        implementationComplexity: 'moderate',
        confidence: 0.6,
      });
    }
  }
  
  // Sort by priority then by estimated call reduction
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  recommendations.sort((a, b) => {
    const pDiff = priorityOrder[a.priority] - priorityOrder[b.priority];
    if (pDiff !== 0) return pDiff;
    return b.estimatedImpact.callsReduced - a.estimatedImpact.callsReduced;
  });
  
  return recommendations;
}

function projectSavings(
  recommendations: OptimizationRecommendation[],
  totalCalls: number,
  totalCost: number,
  totalLatency: number
): { callsReduced: number; callReductionPercent: number; costReduced: number; costReductionPercent: number; latencyReduced: number } {
  // Sum up all recommendation impacts (with overlap discount)
  let callsReduced = 0;
  let costReduced = 0;
  let latencyReduced = 0;
  
  for (const rec of recommendations) {
    callsReduced += rec.estimatedImpact.callsReduced;
    costReduced += rec.estimatedImpact.costReduced;
    latencyReduced += rec.estimatedImpact.latencyReduced;
  }
  
  // Apply overlap discount (recommendations may target same calls)
  const overlapFactor = 0.7; // Assume 30% overlap
  callsReduced = Math.floor(callsReduced * overlapFactor);
  costReduced *= overlapFactor;
  latencyReduced *= overlapFactor;
  
  // Cap at reasonable maximums
  callsReduced = Math.min(callsReduced, Math.floor(totalCalls * 0.6));
  costReduced = Math.min(costReduced, totalCost * 0.6);
  latencyReduced = Math.min(latencyReduced, totalLatency * 0.6);
  
  return {
    callsReduced,
    callReductionPercent: totalCalls > 0 ? (callsReduced / totalCalls) * 100 : 0,
    costReduced,
    costReductionPercent: totalCost > 0 ? (costReduced / totalCost) * 100 : 0,
    latencyReduced,
  };
}

// ─── Convenience: Quick Summary ──────────────────────────────────────────────

/**
 * Generate a quick human-readable summary of the hot path analysis.
 * Useful for logging or dashboard display.
 */
export function formatHotPathSummary(analysis: HotPathAnalysis): string {
  const lines: string[] = [
    `=== LLM Hot Path Analysis ===`,
    `Total Calls: ${analysis.summary.totalCalls} | Cost: $${analysis.summary.totalCost.toFixed(2)} | Callers: ${analysis.summary.uniqueCallers}`,
    `Top 5 callers account for ${analysis.summary.top5CallerPercent.toFixed(0)}% of all calls`,
    ``,
    `--- Top Hot Paths ---`,
  ];
  
  for (const hp of analysis.hotPaths.slice(0, 10)) {
    lines.push(
      `  ${hp.caller}: ${hp.totalCalls} calls (${hp.percentOfTotal.toFixed(1)}%) | $${hp.estimatedCost.toFixed(2)} | ${hp.graduationRecommendation}`
    );
  }
  
  if (analysis.recommendations.length > 0) {
    lines.push(``, `--- Recommendations (${analysis.recommendations.length}) ---`);
    for (const rec of analysis.recommendations.slice(0, 5)) {
      lines.push(`  [${rec.priority.toUpperCase()}] ${rec.title} → -${rec.estimatedImpact.callsReduced} calls, -$${rec.estimatedImpact.costReduced.toFixed(2)}`);
    }
  }
  
  lines.push(
    ``,
    `--- Projected Savings ---`,
    `Calls: -${analysis.projectedSavings.callsReduced} (${analysis.projectedSavings.callReductionPercent.toFixed(0)}%)`,
    `Cost: -$${analysis.projectedSavings.costReduced.toFixed(2)} (${analysis.projectedSavings.costReductionPercent.toFixed(0)}%)`,
  );
  
  return lines.join('\n');
}
