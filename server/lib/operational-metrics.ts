/**
 * Operational Metrics Instrumentation
 * 
 * Addresses the review's call for production-grade observability:
 * 
 * 1. PER-ENGAGEMENT METRICS — Track scan coverage, finding rates, tool utilization,
 *    and time-to-detection per engagement. Enables comparison across engagements.
 * 
 * 2. FINDING LINEAGE — Documents the complete lifecycle of each finding from
 *    initial detection through triage, validation, and reporting. When a finding
 *    is disputed, lineage shows exactly which tool detected it, what evidence
 *    supported it, and what cross-training signals influenced the confidence.
 * 
 * 3. DETECTION RULE EFFECTIVENESS — Tracks which detection rules (Nuclei templates,
 *    Nikto checks, SQLMap payloads) produce true positives vs false positives.
 *    Enables pruning of noisy rules and promotion of effective ones.
 * 
 * 4. COST ATTRIBUTION — Integrates with the LLM inference optimizer to provide
 *    per-engagement cost breakdowns. Answers: "How much did this engagement cost
 *    in LLM inference, and which call sites contributed most?"
 */

import type { EngagementCostReport } from './llm-inference-optimizer';

// ─── Finding Lineage ─────────────────────────────────────────────────────────

export type FindingLifecycleStage =
  | 'detected'           // Tool initially flagged the finding
  | 'deduplicated'       // Finding was merged with a duplicate
  | 'enriched'           // Additional context was added (CVE, CVSS, etc.)
  | 'confidence_scored'  // Confidence score was computed
  | 'cross_trained'      // Cross-training signal was applied
  | 'triaged'            // Human or automated triage decision
  | 'validated'          // Finding was confirmed (true positive)
  | 'rejected'           // Finding was rejected (false positive)
  | 'reported'           // Finding was included in a report
  | 'remediated'         // Finding was fixed
  | 'retested';          // Finding was retested after remediation

export interface FindingLineageEvent {
  id: string;
  timestamp: number;
  stage: FindingLifecycleStage;
  
  /** What triggered this event */
  trigger: string; // e.g., 'nuclei:CVE-2021-44228', 'cross-training:bug_bounty', 'human:analyst'
  
  /** What changed */
  changes: Record<string, { before: any; after: any }>;
  
  /** Evidence or reasoning */
  evidence?: string;
  
  /** Cross-training signal that influenced this event (if any) */
  crossTrainingSignalId?: string;
  
  /** LLM call that influenced this event (if any) */
  llmCallId?: string;
}

export interface FindingLineage {
  findingId: string;
  engagementId: number;
  assetId?: number;
  
  /** The tool that first detected this finding */
  originTool: string;
  
  /** The detection rule/template that triggered */
  originRule?: string;
  
  /** Complete lifecycle events */
  events: FindingLineageEvent[];
  
  /** Current stage */
  currentStage: FindingLifecycleStage;
  
  /** Time from detection to current stage (ms) */
  timeToCurrentStage: number;
  
  /** All tools that contributed to this finding */
  contributingTools: string[];
  
  /** All cross-training signals that influenced this finding */
  crossTrainingSignals: string[];
}

export class FindingLineageTracker {
  private lineages = new Map<string, FindingLineage>();
  
  /**
   * Start tracking a new finding.
   */
  startTracking(params: {
    findingId: string;
    engagementId: number;
    assetId?: number;
    originTool: string;
    originRule?: string;
    initialEvidence?: string;
  }): FindingLineage {
    const lineage: FindingLineage = {
      findingId: params.findingId,
      engagementId: params.engagementId,
      assetId: params.assetId,
      originTool: params.originTool,
      originRule: params.originRule,
      events: [{
        id: `fle-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        timestamp: Date.now(),
        stage: 'detected',
        trigger: `${params.originTool}${params.originRule ? ':' + params.originRule : ''}`,
        changes: { stage: { before: null, after: 'detected' } },
        evidence: params.initialEvidence,
      }],
      currentStage: 'detected',
      timeToCurrentStage: 0,
      contributingTools: [params.originTool],
      crossTrainingSignals: [],
    };
    
    this.lineages.set(params.findingId, lineage);
    return lineage;
  }
  
  /**
   * Record a lifecycle event for a finding.
   */
  recordEvent(findingId: string, event: Omit<FindingLineageEvent, 'id' | 'timestamp'>): FindingLineageEvent | null {
    const lineage = this.lineages.get(findingId);
    if (!lineage) return null;
    
    const fullEvent: FindingLineageEvent = {
      ...event,
      id: `fle-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
    };
    
    lineage.events.push(fullEvent);
    lineage.currentStage = event.stage;
    lineage.timeToCurrentStage = fullEvent.timestamp - lineage.events[0].timestamp;
    
    // Track contributing tools
    const toolMatch = event.trigger.split(':')[0];
    if (toolMatch && !lineage.contributingTools.includes(toolMatch)) {
      lineage.contributingTools.push(toolMatch);
    }
    
    // Track cross-training signals
    if (event.crossTrainingSignalId) {
      lineage.crossTrainingSignals.push(event.crossTrainingSignalId);
    }
    
    return fullEvent;
  }
  
  /**
   * Get the complete lineage for a finding.
   */
  getLineage(findingId: string): FindingLineage | null {
    return this.lineages.get(findingId) || null;
  }
  
  /**
   * Get all findings for an engagement.
   */
  getEngagementFindings(engagementId: number): FindingLineage[] {
    return Array.from(this.lineages.values())
      .filter(l => l.engagementId === engagementId);
  }
  
  /**
   * Get findings by current stage.
   */
  getFindingsByStage(stage: FindingLifecycleStage): FindingLineage[] {
    return Array.from(this.lineages.values())
      .filter(l => l.currentStage === stage);
  }
  
  /**
   * Get the count of tracked findings.
   */
  getTrackedCount(): number {
    return this.lineages.size;
  }
  
  /**
   * Export all lineages.
   */
  exportAll(): FindingLineage[] {
    return Array.from(this.lineages.values());
  }
}

// ─── Detection Rule Effectiveness ────────────────────────────────────────────

export interface DetectionRuleStats {
  ruleId: string;
  toolName: string;
  
  /** Total times this rule fired */
  totalFirings: number;
  
  /** True positives (confirmed findings) */
  truePositives: number;
  
  /** False positives (rejected findings) */
  falsePositives: number;
  
  /** True positive rate */
  truePositiveRate: number;
  
  /** False positive rate */
  falsePositiveRate: number;
  
  /** Precision: TP / (TP + FP) */
  precision: number;
  
  /** Average severity of true positive findings */
  avgTruePoseSeverity: number;
  
  /** Vulnerability classes this rule detects */
  vulnClasses: string[];
  
  /** Recommendation based on effectiveness */
  recommendation: 'keep' | 'tune' | 'disable' | 'promote';
  
  /** Explanation for the recommendation */
  recommendationReason: string;
}

export class DetectionRuleEffectivenessTracker {
  private rules = new Map<string, {
    toolName: string;
    firings: number;
    truePositives: number;
    falsePositives: number;
    severities: number[];
    vulnClasses: Set<string>;
  }>();
  
  /**
   * Record a rule firing.
   */
  recordFiring(ruleId: string, toolName: string, vulnClass: string): void {
    const entry = this.rules.get(ruleId) || {
      toolName,
      firings: 0,
      truePositives: 0,
      falsePositives: 0,
      severities: [],
      vulnClasses: new Set<string>(),
    };
    entry.firings++;
    entry.vulnClasses.add(vulnClass);
    this.rules.set(ruleId, entry);
  }
  
  /**
   * Record the outcome of a rule firing.
   */
  recordOutcome(ruleId: string, isTruePositive: boolean, severity?: number): void {
    const entry = this.rules.get(ruleId);
    if (!entry) return;
    
    if (isTruePositive) {
      entry.truePositives++;
      if (severity !== undefined) entry.severities.push(severity);
    } else {
      entry.falsePositives++;
    }
  }
  
  /**
   * Get effectiveness stats for a specific rule.
   */
  getRuleStats(ruleId: string): DetectionRuleStats | null {
    const entry = this.rules.get(ruleId);
    if (!entry) return null;
    
    const tpRate = entry.firings > 0 ? entry.truePositives / entry.firings : 0;
    const fpRate = entry.firings > 0 ? entry.falsePositives / entry.firings : 0;
    const precision = (entry.truePositives + entry.falsePositives) > 0
      ? entry.truePositives / (entry.truePositives + entry.falsePositives)
      : 0;
    const avgSeverity = entry.severities.length > 0
      ? entry.severities.reduce((s, v) => s + v, 0) / entry.severities.length
      : 0;
    
    const { recommendation, reason } = computeRuleRecommendation(entry, tpRate, precision, avgSeverity);
    
    return {
      ruleId,
      toolName: entry.toolName,
      totalFirings: entry.firings,
      truePositives: entry.truePositives,
      falsePositives: entry.falsePositives,
      truePositiveRate: tpRate,
      falsePositiveRate: fpRate,
      precision,
      avgTruePoseSeverity: avgSeverity,
      vulnClasses: Array.from(entry.vulnClasses),
      recommendation,
      recommendationReason: reason,
    };
  }
  
  /**
   * Get all rules sorted by effectiveness.
   */
  getAllRuleStats(): DetectionRuleStats[] {
    return Array.from(this.rules.keys())
      .map(ruleId => this.getRuleStats(ruleId)!)
      .filter(Boolean)
      .sort((a, b) => b.precision - a.precision);
  }
  
  /**
   * Get rules that should be disabled (high FP, low value).
   */
  getNoisyRules(minFirings: number = 10, maxPrecision: number = 0.3): DetectionRuleStats[] {
    return this.getAllRuleStats()
      .filter(r => r.totalFirings >= minFirings && r.precision < maxPrecision);
  }
  
  /**
   * Get rules that should be promoted (high TP, high severity).
   */
  getHighValueRules(minPrecision: number = 0.7, minSeverity: number = 6): DetectionRuleStats[] {
    return this.getAllRuleStats()
      .filter(r => r.precision >= minPrecision && r.avgTruePoseSeverity >= minSeverity);
  }
  
  /**
   * Get the count of tracked rules.
   */
  getTrackedRuleCount(): number {
    return this.rules.size;
  }
}

function computeRuleRecommendation(
  entry: { firings: number; truePositives: number; falsePositives: number; severities: number[] },
  tpRate: number,
  precision: number,
  avgSeverity: number
): { recommendation: 'keep' | 'tune' | 'disable' | 'promote'; reason: string } {
  // Not enough data
  if (entry.firings < 5) {
    return { recommendation: 'keep', reason: 'Insufficient data for recommendation (< 5 firings)' };
  }
  
  // High precision + high severity = promote
  if (precision >= 0.8 && avgSeverity >= 7) {
    return { recommendation: 'promote', reason: `High precision (${(precision * 100).toFixed(0)}%) with high-severity findings (avg ${avgSeverity.toFixed(1)})` };
  }
  
  // Very low precision = disable
  if (precision < 0.15 && entry.firings >= 10) {
    return { recommendation: 'disable', reason: `Very low precision (${(precision * 100).toFixed(0)}%) over ${entry.firings} firings — generating noise` };
  }
  
  // Low precision but some value = tune
  if (precision < 0.5) {
    return { recommendation: 'tune', reason: `Moderate precision (${(precision * 100).toFixed(0)}%) — consider tuning thresholds or adding context filters` };
  }
  
  // Good precision = keep
  return { recommendation: 'keep', reason: `Good precision (${(precision * 100).toFixed(0)}%) — rule is performing well` };
}

// ─── Per-Engagement Metrics Dashboard ────────────────────────────────────────

export interface EngagementMetrics {
  engagementId: number;
  
  /** Timing metrics */
  timing: {
    startedAt: number;
    currentPhase: string;
    totalDurationMs: number;
    phaseTimings: Record<string, number>; // phase → duration in ms
    timeToFirstFinding: number | null;
    avgTimePerAsset: number;
  };
  
  /** Coverage metrics */
  coverage: {
    totalAssets: number;
    assetsScanned: number;
    scanCoveragePercent: number;
    toolsUsed: string[];
    toolCoverage: Record<string, number>; // tool → assets scanned
    uniquePortsDiscovered: number;
    uniqueServicesDiscovered: number;
  };
  
  /** Finding metrics */
  findings: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byVulnClass: Record<string, number>;
    byTool: Record<string, number>;
    truePositiveRate: number;
    falsePositiveRate: number;
    avgConfidence: number;
    findingsPerAsset: number;
  };
  
  /** Cost metrics (from LLM inference optimizer) */
  cost: EngagementCostReport | null;
  
  /** Quality indicators */
  quality: {
    /** How many findings had cross-training signal applied */
    crossTrainedFindings: number;
    /** How many findings had CVE matches */
    cveMatchedFindings: number;
    /** Average match quality for CVE matches */
    avgCveMatchQuality: number;
    /** Detection rule effectiveness summary */
    ruleEffectiveness: {
      totalRulesFired: number;
      avgPrecision: number;
      noisyRules: number;
      highValueRules: number;
    };
  };
}

/**
 * Build a comprehensive metrics dashboard for an engagement.
 */
export function buildEngagementMetrics(params: {
  engagementId: number;
  startedAt: number;
  currentPhase: string;
  phaseTimings: Record<string, number>;
  assets: Array<{ id: number; scanned: boolean; toolsUsed: string[] }>;
  findings: Array<{
    severity: string;
    vulnClass: string;
    tool: string;
    confidence: number;
    isTruePositive: boolean | null;
    hasCveMatch: boolean;
    cveMatchQuality: number;
    hasCrossTrainingSignal: boolean;
    detectedAt: number;
  }>;
  portsDiscovered: number;
  servicesDiscovered: number;
  costReport: EngagementCostReport | null;
  ruleStats: DetectionRuleStats[];
}): EngagementMetrics {
  const now = Date.now();
  const totalDuration = now - params.startedAt;
  
  // Timing
  const findingTimes = params.findings.map(f => f.detectedAt - params.startedAt).filter(t => t > 0);
  const timeToFirstFinding = findingTimes.length > 0 ? Math.min(...findingTimes) : null;
  const scannedAssets = params.assets.filter(a => a.scanned);
  const avgTimePerAsset = scannedAssets.length > 0 ? totalDuration / scannedAssets.length : 0;
  
  // Coverage
  const allTools = new Set<string>();
  const toolCoverage: Record<string, number> = {};
  for (const asset of params.assets) {
    for (const tool of asset.toolsUsed) {
      allTools.add(tool);
      toolCoverage[tool] = (toolCoverage[tool] || 0) + 1;
    }
  }
  
  // Findings
  const bySeverity: Record<string, number> = {};
  const byVulnClass: Record<string, number> = {};
  const byTool: Record<string, number> = {};
  let tpCount = 0;
  let fpCount = 0;
  let validatedCount = 0;
  let totalConfidence = 0;
  let cveMatchedCount = 0;
  let totalCveQuality = 0;
  let crossTrainedCount = 0;
  
  for (const f of params.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byVulnClass[f.vulnClass] = (byVulnClass[f.vulnClass] || 0) + 1;
    byTool[f.tool] = (byTool[f.tool] || 0) + 1;
    totalConfidence += f.confidence;
    
    if (f.isTruePositive === true) { tpCount++; validatedCount++; }
    if (f.isTruePositive === false) { fpCount++; validatedCount++; }
    if (f.hasCveMatch) { cveMatchedCount++; totalCveQuality += f.cveMatchQuality; }
    if (f.hasCrossTrainingSignal) crossTrainedCount++;
  }
  
  // Rule effectiveness summary
  const totalRulesFired = params.ruleStats.length;
  const avgPrecision = totalRulesFired > 0
    ? params.ruleStats.reduce((s, r) => s + r.precision, 0) / totalRulesFired
    : 0;
  const noisyRules = params.ruleStats.filter(r => r.recommendation === 'disable').length;
  const highValueRules = params.ruleStats.filter(r => r.recommendation === 'promote').length;
  
  return {
    engagementId: params.engagementId,
    timing: {
      startedAt: params.startedAt,
      currentPhase: params.currentPhase,
      totalDurationMs: totalDuration,
      phaseTimings: params.phaseTimings,
      timeToFirstFinding,
      avgTimePerAsset,
    },
    coverage: {
      totalAssets: params.assets.length,
      assetsScanned: scannedAssets.length,
      scanCoveragePercent: params.assets.length > 0 ? (scannedAssets.length / params.assets.length) * 100 : 0,
      toolsUsed: Array.from(allTools),
      toolCoverage,
      uniquePortsDiscovered: params.portsDiscovered,
      uniqueServicesDiscovered: params.servicesDiscovered,
    },
    findings: {
      totalFindings: params.findings.length,
      bySeverity,
      byVulnClass,
      byTool,
      truePositiveRate: validatedCount > 0 ? tpCount / validatedCount : 0,
      falsePositiveRate: validatedCount > 0 ? fpCount / validatedCount : 0,
      avgConfidence: params.findings.length > 0 ? totalConfidence / params.findings.length : 0,
      findingsPerAsset: scannedAssets.length > 0 ? params.findings.length / scannedAssets.length : 0,
    },
    cost: params.costReport,
    quality: {
      crossTrainedFindings: crossTrainedCount,
      cveMatchedFindings: cveMatchedCount,
      avgCveMatchQuality: cveMatchedCount > 0 ? totalCveQuality / cveMatchedCount : 0,
      ruleEffectiveness: {
        totalRulesFired,
        avgPrecision,
        noisyRules,
        highValueRules,
      },
    },
  };
}

// ─── Engagement Comparison ───────────────────────────────────────────────────

export interface EngagementComparison {
  engagementIds: number[];
  
  /** Which engagement found more */
  findingComparison: {
    engagementId: number;
    totalFindings: number;
    uniqueFindings: number;
    avgConfidence: number;
  }[];
  
  /** Tool effectiveness comparison across engagements */
  toolComparison: Record<string, {
    engagementId: number;
    findingsCount: number;
    truePositiveRate: number;
  }[]>;
  
  /** Cost efficiency comparison */
  costComparison: {
    engagementId: number;
    totalCost: number;
    costPerFinding: number;
    costPerTruePositive: number;
  }[];
  
  /** Recommendations based on comparison */
  recommendations: string[];
}

/**
 * Compare metrics across multiple engagements to identify trends and improvements.
 */
export function compareEngagements(metrics: EngagementMetrics[]): EngagementComparison {
  const findingComparison = metrics.map(m => ({
    engagementId: m.engagementId,
    totalFindings: m.findings.totalFindings,
    uniqueFindings: m.findings.totalFindings, // Would need dedup across engagements
    avgConfidence: m.findings.avgConfidence,
  }));
  
  // Tool comparison
  const allTools = new Set<string>();
  for (const m of metrics) {
    for (const tool of m.coverage.toolsUsed) allTools.add(tool);
  }
  
  const toolComparison: Record<string, { engagementId: number; findingsCount: number; truePositiveRate: number }[]> = {};
  for (const tool of allTools) {
    toolComparison[tool] = metrics.map(m => ({
      engagementId: m.engagementId,
      findingsCount: m.findings.byTool[tool] || 0,
      truePositiveRate: m.findings.truePositiveRate,
    }));
  }
  
  // Cost comparison
  const costComparison = metrics
    .filter(m => m.cost)
    .map(m => ({
      engagementId: m.engagementId,
      totalCost: m.cost!.totalEstimatedCost,
      costPerFinding: m.findings.totalFindings > 0
        ? m.cost!.totalEstimatedCost / m.findings.totalFindings
        : 0,
      costPerTruePositive: m.findings.totalFindings * m.findings.truePositiveRate > 0
        ? m.cost!.totalEstimatedCost / (m.findings.totalFindings * m.findings.truePositiveRate)
        : 0,
    }));
  
  // Generate recommendations
  const recommendations: string[] = [];
  
  if (metrics.length >= 2) {
    const latest = metrics[metrics.length - 1];
    const previous = metrics[metrics.length - 2];
    
    if (latest.findings.truePositiveRate > previous.findings.truePositiveRate) {
      recommendations.push(
        `True positive rate improved from ${(previous.findings.truePositiveRate * 100).toFixed(0)}% to ${(latest.findings.truePositiveRate * 100).toFixed(0)}% — cross-training is working.`
      );
    } else if (latest.findings.truePositiveRate < previous.findings.truePositiveRate - 0.05) {
      recommendations.push(
        `True positive rate declined from ${(previous.findings.truePositiveRate * 100).toFixed(0)}% to ${(latest.findings.truePositiveRate * 100).toFixed(0)}% — investigate cross-training signal quality.`
      );
    }
    
    if (latest.quality.ruleEffectiveness.noisyRules > previous.quality.ruleEffectiveness.noisyRules) {
      recommendations.push(
        `Noisy rules increased from ${previous.quality.ruleEffectiveness.noisyRules} to ${latest.quality.ruleEffectiveness.noisyRules} — consider pruning low-precision detection rules.`
      );
    }
  }
  
  return {
    engagementIds: metrics.map(m => m.engagementId),
    findingComparison,
    toolComparison,
    costComparison,
    recommendations,
  };
}

// ─── Singleton Instances ─────────────────────────────────────────────────────

/** Global finding lineage tracker */
export const findingLineageTracker = new FindingLineageTracker();

/** Global detection rule effectiveness tracker */
export const ruleEffectivenessTracker = new DetectionRuleEffectivenessTracker();
