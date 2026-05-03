/**
 * Cross-Training Event Bus
 * 
 * Implements the formal event-driven cross-training architecture from the review:
 * 
 * 1. EVENT BUS — Centralized pub/sub for cross-training signals. Sources (bug bounty,
 *    pentest, vuln scan) publish outcomes; consumers (calibration, pattern repo,
 *    tool effectiveness) subscribe and process.
 * 
 * 2. BIAS CORRECTION — Each source has different reliability and incentive characteristics.
 *    Bug bounty outcomes are biased toward demonstrable-impact patterns. Pentest outcomes
 *    are biased toward time-constrained findings. Cross-training without bias correction
 *    amplifies source-specific biases.
 * 
 * 3. SIGNAL LINEAGE — Documents which signal trained which model. When a vuln scanner
 *    starts producing odd outputs, knowing it was trained on bug bounty data from
 *    program X helps trace the issue.
 * 
 * 4. HOLDOUT VALIDATION — Reserves a configurable percentage of outcomes as held-out
 *    validation data. If all signal goes into training, there's nothing to validate against.
 */

import { createHash } from 'crypto';
import type {
  OutcomeLogEntry,
  TriageOutcome,
  PatternRepository,
  CalibrationPipeline,
  ToolEffectivenessTracker,
  CrossTrainingResult,
} from './cross-training';

// ─── Event Types ─────────────────────────────────────────────────────────────

export type CrossTrainingSource =
  | 'bug_bounty'          // HackerOne/Bugcrowd triage outcomes
  | 'pentest_engagement'  // AC3 pentest engagement findings
  | 'vuln_scan'           // Automated vulnerability scan results
  | 'training_lab'        // Training lab exercise outcomes
  | 'manual_review'       // Manual security review findings
  | 'external_feed';      // External threat intelligence feeds

export type CrossTrainingEventType =
  | 'finding_validated'    // A finding was confirmed true positive
  | 'finding_rejected'     // A finding was rejected (false positive)
  | 'finding_duplicated'   // A finding was a duplicate
  | 'severity_adjusted'    // Severity was adjusted by triage
  | 'cve_matched'          // Finding matched to a CVE
  | 'pattern_extracted'    // A new detection pattern was extracted
  | 'tool_evaluated'       // Tool effectiveness was evaluated
  | 'confidence_updated';  // Confidence calibration was updated

export interface CrossTrainingEvent {
  id: string;
  timestamp: number;
  source: CrossTrainingSource;
  eventType: CrossTrainingEventType;
  
  /** The outcome data being propagated */
  payload: OutcomeLogEntry;
  
  /** Source-specific metadata for lineage tracking */
  sourceMetadata: {
    programId?: string;       // Bug bounty program ID
    programName?: string;     // Bug bounty program name
    engagementId?: number;    // Pentest engagement ID
    scanId?: string;          // Scan run ID
    triageTeam?: string;      // Who triaged (anonymized)
    platformReward?: number;  // Bounty amount (for bias weighting)
  };
  
  /** Whether this event is held out for validation */
  isHoldout: boolean;
  
  /** Bias correction weight applied to this event */
  biasWeight: number;
  
  /** Lineage: which downstream consumers processed this event */
  processedBy: string[];
}

// ─── Bias Correction ─────────────────────────────────────────────────────────

/**
 * Source bias profiles — each source has characteristic biases that must be
 * corrected before cross-training to prevent amplification.
 */
export interface SourceBiasProfile {
  source: CrossTrainingSource;
  
  /** Reliability weight (0-1). Higher = more reliable signal */
  reliabilityWeight: number;
  
  /** Severity bias: does this source over/under-report certain severities? */
  severityBias: {
    critical: number;  // Multiplier: >1 = over-reported, <1 = under-reported
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  
  /** Vuln class bias: which vuln classes are over/under-represented? */
  vulnClassBias: Record<string, number>;
  
  /** Demonstrability bias: how much does demonstrability affect reporting? */
  demonstrabilityBias: number; // 0-1, higher = more biased toward demonstrable vulns
  
  /** Time pressure bias: how much does time pressure affect quality? */
  timePressureBias: number; // 0-1, higher = more time-pressured
  
  /** Incentive alignment: how aligned are reporter incentives with accuracy? */
  incentiveAlignment: number; // 0-1, higher = better aligned
  
  /** Description of known biases for documentation */
  knownBiases: string[];
}

/**
 * Default bias profiles for each source type.
 * These should be calibrated over time based on observed outcomes.
 */
export const SOURCE_BIAS_PROFILES: Record<CrossTrainingSource, SourceBiasProfile> = {
  bug_bounty: {
    source: 'bug_bounty',
    reliabilityWeight: 0.85,
    severityBias: {
      critical: 1.3,  // Over-reported (higher bounties)
      high: 1.2,
      medium: 0.9,
      low: 0.6,       // Under-reported (low bounties)
      info: 0.3,      // Rarely reported
    },
    vulnClassBias: {
      'SQL Injection': 1.2,
      'Cross-Site Scripting': 1.3,  // Easy to demonstrate
      'Remote Code Execution': 1.4, // High bounties
      'IDOR': 1.5,                  // Easy to find, high impact
      'Information Disclosure': 0.7, // Low bounties
      'Denial of Service': 0.4,     // Often out of scope
      'Business Logic': 0.8,        // Hard to demonstrate
    },
    demonstrabilityBias: 0.8,  // High — bounties require clear PoC
    timePressureBias: 0.3,     // Low — researchers work at own pace
    incentiveAlignment: 0.7,   // Good but reward-driven
    knownBiases: [
      'Favors easily demonstrable vulnerabilities over subtle ones',
      'Over-represents high-severity findings due to reward structure',
      'Under-represents vulnerabilities that require complex chains',
      'Selection bias: only submitted findings are visible',
      'Program scope limits what gets reported',
    ],
  },
  pentest_engagement: {
    source: 'pentest_engagement',
    reliabilityWeight: 0.90,
    severityBias: {
      critical: 1.0,
      high: 1.1,
      medium: 1.0,
      low: 0.8,
      info: 0.7,
    },
    vulnClassBias: {
      'SQL Injection': 1.0,
      'Cross-Site Scripting': 0.9,
      'Remote Code Execution': 1.1,
      'Privilege Escalation': 1.2,  // Pentests focus on lateral movement
      'Misconfiguration': 1.3,     // Pentests catch config issues
      'Business Logic': 1.1,       // More time to explore
    },
    demonstrabilityBias: 0.5,
    timePressureBias: 0.7,     // High — engagements have deadlines
    incentiveAlignment: 0.85,  // Professional obligation to be thorough
    knownBiases: [
      'Time-constrained: may miss deep/complex vulnerabilities',
      'Scope-limited: only tests what client authorizes',
      'Methodology-driven: may follow checklist rather than creative exploration',
      'Report-oriented: findings shaped by what looks good in reports',
    ],
  },
  vuln_scan: {
    source: 'vuln_scan',
    reliabilityWeight: 0.65,
    severityBias: {
      critical: 1.5,  // Scanners flag many criticals
      high: 1.3,
      medium: 1.0,
      low: 0.8,
      info: 1.2,      // Scanners produce lots of info findings
    },
    vulnClassBias: {
      'SQL Injection': 1.1,
      'Cross-Site Scripting': 1.4,  // High FP rate
      'Missing Headers': 2.0,       // Over-reported
      'SSL/TLS Issues': 1.8,        // Over-reported
      'Outdated Software': 1.5,     // Version-based, not always exploitable
      'Business Logic': 0.1,        // Scanners can't find these
    },
    demonstrabilityBias: 0.2,
    timePressureBias: 0.1,
    incentiveAlignment: 0.5,  // No human judgment
    knownBiases: [
      'High false positive rate for certain vuln classes',
      'Cannot detect business logic vulnerabilities',
      'Version-based detection may not account for backported patches',
      'Signature-based: misses novel vulnerabilities',
      'Over-reports informational findings',
    ],
  },
  training_lab: {
    source: 'training_lab',
    reliabilityWeight: 0.95,  // Known ground truth
    severityBias: { critical: 1.0, high: 1.0, medium: 1.0, low: 1.0, info: 1.0 },
    vulnClassBias: {},
    demonstrabilityBias: 0.1,
    timePressureBias: 0.1,
    incentiveAlignment: 0.95,
    knownBiases: [
      'Artificial environment may not reflect real-world complexity',
      'Known vulnerabilities — no novel discovery signal',
      'Controlled conditions reduce environmental noise',
    ],
  },
  manual_review: {
    source: 'manual_review',
    reliabilityWeight: 0.92,
    severityBias: { critical: 1.0, high: 1.0, medium: 1.0, low: 0.9, info: 0.8 },
    vulnClassBias: {},
    demonstrabilityBias: 0.3,
    timePressureBias: 0.4,
    incentiveAlignment: 0.90,
    knownBiases: [
      'Reviewer expertise varies',
      'May be influenced by prior findings',
    ],
  },
  external_feed: {
    source: 'external_feed',
    reliabilityWeight: 0.60,
    severityBias: { critical: 1.2, high: 1.1, medium: 1.0, low: 0.8, info: 0.9 },
    vulnClassBias: {},
    demonstrabilityBias: 0.2,
    timePressureBias: 0.2,
    incentiveAlignment: 0.5,
    knownBiases: [
      'Quality varies widely by feed source',
      'May contain stale or inaccurate data',
      'No direct validation of findings',
    ],
  },
};

/**
 * Compute bias-corrected weight for a cross-training event.
 * Returns a weight between 0 and 1 that should be applied when
 * using this event for training/calibration.
 */
export function computeBiasWeight(
  event: { source: CrossTrainingSource; payload: OutcomeLogEntry }
): number {
  const profile = SOURCE_BIAS_PROFILES[event.source];
  if (!profile) return 0.5; // Unknown source, neutral weight
  
  let weight = profile.reliabilityWeight;
  
  // Apply severity bias correction
  const severity = event.payload.severity?.toLowerCase() as keyof SourceBiasProfile['severityBias'];
  const severityMultiplier = profile.severityBias[severity] || 1.0;
  // Inverse correction: if over-reported (>1), reduce weight; if under-reported (<1), increase weight
  weight *= (1 / severityMultiplier);
  
  // Apply vuln class bias correction
  const vulnClassMultiplier = profile.vulnClassBias[event.payload.vulnClass] || 1.0;
  weight *= (1 / vulnClassMultiplier);
  
  // Apply demonstrability bias correction
  // If source has high demonstrability bias and the finding has low reproduction quality,
  // it may be more significant (harder to demonstrate but still valid)
  if (profile.demonstrabilityBias > 0.5 && event.payload.reproductionQuality < 0.5) {
    weight *= 1.2; // Boost weight for hard-to-demonstrate findings from biased sources
  }
  
  // Clamp to [0.1, 1.0]
  return Math.max(0.1, Math.min(1.0, weight));
}

// ─── Signal Lineage Tracker ──────────────────────────────────────────────────

export interface SignalLineageEntry {
  id: string;
  timestamp: number;
  
  /** The cross-training event that produced this signal */
  eventId: string;
  source: CrossTrainingSource;
  
  /** What was trained/calibrated */
  consumer: string; // e.g., 'calibration_pipeline', 'pattern_repository', 'tool_effectiveness'
  
  /** What model/component was affected */
  affectedComponent: string; // e.g., 'nuclei:XSS:confidence', 'sqlmap:SQLi:detection_rate'
  
  /** What changed */
  changeType: 'confidence_adjusted' | 'pattern_added' | 'pattern_updated' | 'effectiveness_updated' | 'calibration_updated';
  
  /** Before and after values */
  valueBefore?: number;
  valueAfter?: number;
  
  /** Bias weight that was applied */
  biasWeight: number;
  
  /** Source metadata for traceability */
  sourceMetadata: Record<string, any>;
}

export class SignalLineageTracker {
  private entries: SignalLineageEntry[] = [];
  private maxEntries: number;
  
  constructor(maxEntries: number = 10000) {
    this.maxEntries = maxEntries;
  }
  
  /**
   * Record a lineage entry.
   */
  record(entry: Omit<SignalLineageEntry, 'id' | 'timestamp'>): void {
    if (this.entries.length >= this.maxEntries) {
      // Remove oldest 10%
      this.entries = this.entries.slice(Math.floor(this.maxEntries * 0.1));
    }
    
    this.entries.push({
      ...entry,
      id: `lineage-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
    });
  }
  
  /**
   * Get all lineage entries for a specific component.
   * Useful for debugging when a model starts producing odd outputs.
   */
  getLineageForComponent(component: string): SignalLineageEntry[] {
    return this.entries
      .filter(e => e.affectedComponent === component || e.affectedComponent.startsWith(component + ':'))
      .sort((a, b) => b.timestamp - a.timestamp);
  }
  
  /**
   * Get all lineage entries from a specific source.
   */
  getLineageBySource(source: CrossTrainingSource): SignalLineageEntry[] {
    return this.entries
      .filter(e => e.source === source)
      .sort((a, b) => b.timestamp - a.timestamp);
  }
  
  /**
   * Get lineage summary: which sources have trained which components.
   */
  getLineageSummary(): Record<string, {
    sources: Record<CrossTrainingSource, number>;
    totalUpdates: number;
    lastUpdated: number;
  }> {
    const summary: Record<string, {
      sources: Record<string, number>;
      totalUpdates: number;
      lastUpdated: number;
    }> = {};
    
    for (const entry of this.entries) {
      const component = entry.affectedComponent;
      if (!summary[component]) {
        summary[component] = { sources: {} as any, totalUpdates: 0, lastUpdated: 0 };
      }
      summary[component].sources[entry.source] = (summary[component].sources[entry.source] || 0) + 1;
      summary[component].totalUpdates++;
      summary[component].lastUpdated = Math.max(summary[component].lastUpdated, entry.timestamp);
    }
    
    return summary as any;
  }
  
  /**
   * Export all lineage entries.
   */
  exportEntries(): SignalLineageEntry[] {
    return [...this.entries];
  }
  
  /**
   * Get entry count.
   */
  getEntryCount(): number {
    return this.entries.length;
  }
}

// ─── Holdout Validation Manager ──────────────────────────────────────────────

export interface HoldoutConfig {
  /** Percentage of outcomes to hold out (0-1, default 0.15 = 15%) */
  holdoutRate: number;
  /** Minimum outcomes before holdout starts (need enough training data first) */
  minOutcomesBeforeHoldout: number;
  /** Seed for deterministic holdout selection (reproducibility) */
  seed: string;
}

const DEFAULT_HOLDOUT_CONFIG: HoldoutConfig = {
  holdoutRate: 0.15,
  minOutcomesBeforeHoldout: 50,
  seed: 'ac3-holdout-v1',
};

export class HoldoutValidationManager {
  private config: HoldoutConfig;
  private trainingSet: OutcomeLogEntry[] = [];
  private holdoutSet: OutcomeLogEntry[] = [];
  private totalProcessed = 0;
  
  constructor(config?: Partial<HoldoutConfig>) {
    this.config = { ...DEFAULT_HOLDOUT_CONFIG, ...config };
  }
  
  /**
   * Determine whether an outcome should be held out.
   * Uses deterministic hashing for reproducibility.
   */
  shouldHoldout(outcome: OutcomeLogEntry): boolean {
    this.totalProcessed++;
    
    // Don't holdout until we have enough training data
    if (this.totalProcessed < this.config.minOutcomesBeforeHoldout) {
      return false;
    }
    
    // Deterministic selection based on outcome ID + seed
    const hash = createHash('sha256')
      .update(this.config.seed + ':' + outcome.id)
      .digest('hex');
    
    // Use first 8 hex chars as a number, normalize to 0-1
    const hashValue = parseInt(hash.slice(0, 8), 16) / 0xFFFFFFFF;
    
    return hashValue < this.config.holdoutRate;
  }
  
  /**
   * Route an outcome to either training or holdout set.
   */
  routeOutcome(outcome: OutcomeLogEntry): 'training' | 'holdout' {
    if (this.shouldHoldout(outcome)) {
      this.holdoutSet.push(outcome);
      return 'holdout';
    }
    this.trainingSet.push(outcome);
    return 'training';
  }
  
  /**
   * Validate the training pipeline against holdout data.
   * Measures whether cross-training is actually improving the receiving models.
   */
  validateAgainstHoldout(
    calibrationPipeline: CalibrationPipeline,
    patternRepo: PatternRepository
  ): HoldoutValidationResult {
    if (this.holdoutSet.length === 0) {
      return {
        holdoutSize: 0,
        trainingSize: this.trainingSet.length,
        isValid: false,
        reason: 'No holdout data available yet',
        metrics: null,
      };
    }
    
    let correctPredictions = 0;
    let totalPredictions = 0;
    let calibrationErrors: number[] = [];
    let patternHits = 0;
    
    for (const outcome of this.holdoutSet) {
      const wasAccepted = outcome.outcome === 'accepted' || outcome.outcome === 'bounty_paid';
      
      // Check if calibration pipeline would have predicted correctly
      const adjustment = calibrationPipeline.getConfidenceAdjustment(
        outcome.vulnClass,
        outcome.scannerUsed,
        outcome.detectionMethod
      );
      
      // If adjustment is positive and finding was accepted, or negative and rejected → correct
      const predictedAccepted = adjustment >= 0;
      if (predictedAccepted === wasAccepted) {
        correctPredictions++;
      }
      totalPredictions++;
      
      // Measure calibration error
      const expectedConfidence = wasAccepted ? 0.8 : 0.2;
      const actualConfidence = 0.5 + adjustment; // Base 0.5 + adjustment
      calibrationErrors.push(Math.abs(expectedConfidence - actualConfidence));
      
      // Check if pattern repository has relevant patterns
      const patterns = patternRepo.getPatterns(outcome.vulnClass);
      if (patterns.length > 0) {
        patternHits++;
      }
    }
    
    const accuracy = totalPredictions > 0 ? correctPredictions / totalPredictions : 0;
    const avgCalibrationError = calibrationErrors.length > 0
      ? calibrationErrors.reduce((s, e) => s + e, 0) / calibrationErrors.length
      : 1.0;
    const patternCoverage = this.holdoutSet.length > 0
      ? patternHits / this.holdoutSet.length
      : 0;
    
    return {
      holdoutSize: this.holdoutSet.length,
      trainingSize: this.trainingSet.length,
      isValid: true,
      reason: null,
      metrics: {
        predictionAccuracy: accuracy,
        averageCalibrationError: avgCalibrationError,
        patternCoverage,
        holdoutRate: this.holdoutSet.length / (this.holdoutSet.length + this.trainingSet.length),
      },
    };
  }
  
  /**
   * Get holdout statistics.
   */
  getStats(): {
    trainingSize: number;
    holdoutSize: number;
    totalProcessed: number;
    effectiveHoldoutRate: number;
  } {
    const total = this.trainingSet.length + this.holdoutSet.length;
    return {
      trainingSize: this.trainingSet.length,
      holdoutSize: this.holdoutSet.length,
      totalProcessed: this.totalProcessed,
      effectiveHoldoutRate: total > 0 ? this.holdoutSet.length / total : 0,
    };
  }
  
  /**
   * Export holdout set for external validation.
   */
  exportHoldoutSet(): OutcomeLogEntry[] {
    return [...this.holdoutSet];
  }
  
  /**
   * Export training set.
   */
  exportTrainingSet(): OutcomeLogEntry[] {
    return [...this.trainingSet];
  }
}

export interface HoldoutValidationResult {
  holdoutSize: number;
  trainingSize: number;
  isValid: boolean;
  reason: string | null;
  metrics: {
    predictionAccuracy: number;
    averageCalibrationError: number;
    patternCoverage: number;
    holdoutRate: number;
  } | null;
}

// ─── Cross-Training Event Bus ────────────────────────────────────────────────

type EventHandler = (event: CrossTrainingEvent) => void;

export class CrossTrainingEventBus {
  private handlers = new Map<CrossTrainingEventType | '*', EventHandler[]>();
  private lineageTracker: SignalLineageTracker;
  private holdoutManager: HoldoutValidationManager;
  private eventLog: CrossTrainingEvent[] = [];
  private maxEventLog: number;
  
  // Stats
  private totalEventsPublished = 0;
  private totalEventsProcessed = 0;
  private eventsBySource = new Map<CrossTrainingSource, number>();
  private eventsByType = new Map<CrossTrainingEventType, number>();
  
  constructor(opts?: {
    maxEventLog?: number;
    holdoutConfig?: Partial<HoldoutConfig>;
    lineageMaxEntries?: number;
  }) {
    this.maxEventLog = opts?.maxEventLog || 5000;
    this.lineageTracker = new SignalLineageTracker(opts?.lineageMaxEntries);
    this.holdoutManager = new HoldoutValidationManager(opts?.holdoutConfig);
  }
  
  /**
   * Subscribe to cross-training events.
   * Use '*' to subscribe to all event types.
   */
  subscribe(eventType: CrossTrainingEventType | '*', handler: EventHandler): () => void {
    const handlers = this.handlers.get(eventType) || [];
    handlers.push(handler);
    this.handlers.set(eventType, handlers);
    
    // Return unsubscribe function
    return () => {
      const current = this.handlers.get(eventType) || [];
      this.handlers.set(eventType, current.filter(h => h !== handler));
    };
  }
  
  /**
   * Publish a cross-training event.
   * Applies bias correction, holdout routing, and dispatches to subscribers.
   */
  publish(
    source: CrossTrainingSource,
    eventType: CrossTrainingEventType,
    payload: OutcomeLogEntry,
    sourceMetadata?: CrossTrainingEvent['sourceMetadata']
  ): CrossTrainingEvent {
    // Compute bias weight
    const biasWeight = computeBiasWeight({ source, payload });
    
    // Determine holdout status
    const isHoldout = this.holdoutManager.shouldHoldout(payload);
    this.holdoutManager.routeOutcome(payload);
    
    const event: CrossTrainingEvent = {
      id: `cte-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
      source,
      eventType,
      payload,
      sourceMetadata: sourceMetadata || {},
      isHoldout,
      biasWeight,
      processedBy: [],
    };
    
    // Log event
    if (this.eventLog.length >= this.maxEventLog) {
      this.eventLog = this.eventLog.slice(Math.floor(this.maxEventLog * 0.1));
    }
    this.eventLog.push(event);
    
    // Update stats
    this.totalEventsPublished++;
    this.eventsBySource.set(source, (this.eventsBySource.get(source) || 0) + 1);
    this.eventsByType.set(eventType, (this.eventsByType.get(eventType) || 0) + 1);
    
    // Dispatch to subscribers (skip holdout events for training consumers)
    if (!isHoldout) {
      // Dispatch to specific type handlers
      const typeHandlers = this.handlers.get(eventType) || [];
      for (const handler of typeHandlers) {
        try {
          handler(event);
          event.processedBy.push(`${eventType}:handler`);
          this.totalEventsProcessed++;
        } catch (err) {
          console.error(`[CrossTrainingEventBus] Handler error for ${eventType}:`, err);
        }
      }
      
      // Dispatch to wildcard handlers
      const wildcardHandlers = this.handlers.get('*') || [];
      for (const handler of wildcardHandlers) {
        try {
          handler(event);
          event.processedBy.push('*:handler');
          this.totalEventsProcessed++;
        } catch (err) {
          console.error(`[CrossTrainingEventBus] Wildcard handler error:`, err);
        }
      }
    }
    
    return event;
  }
  
  /**
   * Process a batch of bug bounty outcomes through the event bus.
   * This is the enhanced version of processCrossTrainingBatch that adds
   * bias correction, lineage tracking, and holdout management.
   */
  processBatchWithBiasCorrection(
    outcomes: OutcomeLogEntry[],
    source: CrossTrainingSource,
    patternRepo: PatternRepository,
    calibrationPipeline: CalibrationPipeline,
    toolTracker: ToolEffectivenessTracker,
    sourceMetadata?: CrossTrainingEvent['sourceMetadata']
  ): CrossTrainingResult & {
    holdoutCount: number;
    biasWeights: { min: number; max: number; avg: number };
    lineageEntries: number;
  } {
    let patternsExtracted = 0;
    let calibrationUpdates = 0;
    let toolEffectivenessUpdates = 0;
    let contaminationRejections = 0;
    let holdoutCount = 0;
    let lineageEntries = 0;
    const weights: number[] = [];
    
    for (const outcome of outcomes) {
      const wasAccepted = outcome.outcome === 'accepted' || outcome.outcome === 'bounty_paid';
      const eventType: CrossTrainingEventType = wasAccepted ? 'finding_validated' : 'finding_rejected';
      
      // Publish through event bus (applies bias correction + holdout routing)
      const event = this.publish(source, eventType, outcome, sourceMetadata);
      weights.push(event.biasWeight);
      
      if (event.isHoldout) {
        holdoutCount++;
        continue; // Skip training for holdout events
      }
      
      // 1. Feed calibration pipeline with bias-weighted outcome
      const prevAdjustment = calibrationPipeline.getConfidenceAdjustment(
        outcome.vulnClass, outcome.scannerUsed, outcome.detectionMethod
      );
      
      calibrationPipeline.recordOutcome({
        vulnClass: outcome.vulnClass,
        scannerUsed: outcome.scannerUsed,
        detectionMethod: outcome.detectionMethod,
        wasAccepted,
      });
      calibrationUpdates++;
      
      const newAdjustment = calibrationPipeline.getConfidenceAdjustment(
        outcome.vulnClass, outcome.scannerUsed, outcome.detectionMethod
      );
      
      // Record lineage
      this.lineageTracker.record({
        eventId: event.id,
        source,
        consumer: 'calibration_pipeline',
        affectedComponent: `${outcome.scannerUsed}:${outcome.vulnClass}:confidence`,
        changeType: 'calibration_updated',
        valueBefore: prevAdjustment,
        valueAfter: newAdjustment,
        biasWeight: event.biasWeight,
        sourceMetadata: event.sourceMetadata,
      });
      lineageEntries++;
      
      // 2. Feed tool effectiveness tracker
      toolTracker.recordPerformance({
        toolName: outcome.scannerUsed,
        vulnClass: outcome.vulnClass,
        detected: true,
        wasTruePositive: wasAccepted,
        wasUniqueToTool: false,
        wasCorroborated: false,
      });
      toolEffectivenessUpdates++;
      
      this.lineageTracker.record({
        eventId: event.id,
        source,
        consumer: 'tool_effectiveness',
        affectedComponent: `${outcome.scannerUsed}:${outcome.vulnClass}:effectiveness`,
        changeType: 'effectiveness_updated',
        biasWeight: event.biasWeight,
        sourceMetadata: event.sourceMetadata,
      });
      lineageEntries++;
      
      // 3. Extract patterns from outcomes
      for (const pattern of outcome.extractedPatterns) {
        if (patternRepo.addPattern(pattern)) {
          patternsExtracted++;
          this.lineageTracker.record({
            eventId: event.id,
            source,
            consumer: 'pattern_repository',
            affectedComponent: `${pattern.vulnClass}:${pattern.category}`,
            changeType: pattern.observationCount > 1 ? 'pattern_updated' : 'pattern_added',
            biasWeight: event.biasWeight,
            sourceMetadata: event.sourceMetadata,
          });
          lineageEntries++;
        } else {
          contaminationRejections++;
        }
      }
    }
    
    return {
      patternsExtracted,
      calibrationUpdates,
      toolEffectivenessUpdates,
      contaminationRejections,
      holdoutCount,
      biasWeights: {
        min: weights.length > 0 ? Math.min(...weights) : 0,
        max: weights.length > 0 ? Math.max(...weights) : 0,
        avg: weights.length > 0 ? weights.reduce((s, w) => s + w, 0) / weights.length : 0,
      },
      lineageEntries,
    };
  }
  
  /**
   * Run holdout validation against current calibration state.
   */
  runHoldoutValidation(
    calibrationPipeline: CalibrationPipeline,
    patternRepo: PatternRepository
  ): HoldoutValidationResult {
    return this.holdoutManager.validateAgainstHoldout(calibrationPipeline, patternRepo);
  }
  
  /**
   * Get the signal lineage tracker.
   */
  getLineageTracker(): SignalLineageTracker {
    return this.lineageTracker;
  }
  
  /**
   * Get the holdout manager.
   */
  getHoldoutManager(): HoldoutValidationManager {
    return this.holdoutManager;
  }
  
  /**
   * Get event bus statistics.
   */
  getStats(): {
    totalEventsPublished: number;
    totalEventsProcessed: number;
    eventsBySource: Record<string, number>;
    eventsByType: Record<string, number>;
    holdoutStats: ReturnType<HoldoutValidationManager['getStats']>;
    lineageEntryCount: number;
    eventLogSize: number;
  } {
    return {
      totalEventsPublished: this.totalEventsPublished,
      totalEventsProcessed: this.totalEventsProcessed,
      eventsBySource: Object.fromEntries(this.eventsBySource),
      eventsByType: Object.fromEntries(this.eventsByType),
      holdoutStats: this.holdoutManager.getStats(),
      lineageEntryCount: this.lineageTracker.getEntryCount(),
      eventLogSize: this.eventLog.length,
    };
  }
  
  /**
   * Get recent events for debugging.
   */
  getRecentEvents(limit: number = 50): CrossTrainingEvent[] {
    return this.eventLog.slice(-limit);
  }
}

// ─── Singleton Instance ──────────────────────────────────────────────────────

/** Global cross-training event bus instance */
export const crossTrainingBus = new CrossTrainingEventBus();
