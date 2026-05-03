/**
 * Negative Example Feedback Loop
 * 
 * Connects the Negative Example Pipeline (bounty-negative-examples.ts) to the
 * bounty training engine's calibration loop via the CrossTrainingEventBus.
 * 
 * When a submission is rejected:
 *   1. NegativeExampleRepository records the rejection and generates training signals
 *   2. This module converts those signals into CrossTrainingEventBus events
 *   3. The ConfidenceCalibrationEngine receives the events and updates its Bayesian curves
 *   4. Drift detection runs automatically, flagging systematic over/under-confidence
 *   5. Future hypothesis generation uses the corrected calibration for better predictions
 * 
 * Architecture:
 *   Rejected submission → NegativeExampleRepo → [THIS MODULE] → CrossTrainingEventBus
 *                                                                    ↓
 *                                               ConfidenceCalibrationEngine.recordOutcome()
 *                                                                    ↓
 *                                               Bayesian curve update + drift detection
 */

import type { NegativeExample, TrainingSignal, NegativeExampleStats } from './bounty-negative-examples';
import type { CalibrationRecord, DriftReport } from './bounty-confidence-calibration';
import type { CrossTrainingEvent, CrossTrainingEventType, CrossTrainingSource } from './cross-training-event-bus';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FeedbackLoopConfig {
  /** Enable automatic calibration updates on every rejection (default: true) */
  autoCalibrate: boolean;
  /** Minimum negative examples before triggering drift detection (default: 5) */
  driftDetectionThreshold: number;
  /** Weight multiplier for false positives (most informative rejections) */
  falsePositiveWeightBoost: number;
  /** Weight multiplier for out-of-scope rejections */
  outOfScopeWeightBoost: number;
  /** Enable cross-training event bus integration (default: true) */
  enableEventBus: boolean;
  /** Maximum calibration records to keep in memory */
  maxCalibrationRecords: number;
}

const DEFAULT_CONFIG: FeedbackLoopConfig = {
  autoCalibrate: true,
  driftDetectionThreshold: 5,
  falsePositiveWeightBoost: 1.5,
  outOfScopeWeightBoost: 1.2,
  enableEventBus: true,
  maxCalibrationRecords: 10000,
};

export interface FeedbackLoopStats {
  totalRejectionsProcessed: number;
  totalCalibrationUpdates: number;
  totalEventBusPublications: number;
  driftDetectionsRun: number;
  lastDriftReport: DriftReport | null;
  rejectionsByReason: Record<string, number>;
  calibrationRecordCount: number;
  averageConfidenceAdjustment: number;
}

export interface RejectionFeedbackResult {
  processed: boolean;
  calibrationUpdated: boolean;
  eventPublished: boolean;
  driftDetected: boolean;
  driftReport?: DriftReport;
  calibrationRecord: CalibrationRecord;
  trainingSignals: TrainingSignal[];
}

// ─── Rejection → CalibrationRecord Mapping ───────────────────────────────────

/**
 * Map a rejection reason to the calibration outcome type.
 * The calibration engine uses 'accepted'|'rejected'|'duplicate'|'informational'.
 */
function mapRejectionToOutcome(rejectionReason: string): CalibrationRecord['actualOutcome'] {
  switch (rejectionReason) {
    case 'duplicate':
      return 'duplicate';
    case 'informational_only':
    case 'insufficient_impact':
      return 'informational';
    default:
      return 'rejected';
  }
}

/**
 * Estimate the predicted confidence that was used when the finding was submitted.
 * Since we don't always have the original confidence, we infer from severity.
 */
function estimatePredictedConfidence(severity: string, rejectionReason: string): number {
  // Base confidence by severity (what the system likely predicted)
  const severityBase: Record<string, number> = {
    critical: 0.85,
    high: 0.75,
    medium: 0.6,
    low: 0.45,
    info: 0.3,
    none: 0.2,
  };
  
  let base = severityBase[severity.toLowerCase()] || 0.5;
  
  // Adjust based on rejection reason — false positives suggest higher original confidence
  if (rejectionReason === 'false_positive') base = Math.max(base, 0.7);
  if (rejectionReason === 'intended_behavior') base = Math.max(base, 0.65);
  if (rejectionReason === 'invalid_vulnerability') base = Math.max(base, 0.6);
  
  return base;
}

/**
 * Convert a NegativeExample into a CalibrationRecord for the ConfidenceCalibrationEngine.
 */
export function negativeExampleToCalibrationRecord(
  example: NegativeExample,
  config: FeedbackLoopConfig = DEFAULT_CONFIG
): CalibrationRecord {
  const predictedConfidence = estimatePredictedConfidence(example.severity, example.rejectionReason);
  
  return {
    vulnClass: example.vulnClass,
    predictedConfidence,
    actualOutcome: mapRejectionToOutcome(example.rejectionReason),
    programHandle: example.programHandle,
    timestamp: example.rejectedAt ? new Date(example.rejectedAt).getTime() : Date.now(),
  };
}

/**
 * Convert a NegativeExample into OutcomeLogEntry format for the CrossTrainingEventBus.
 */
export function negativeExampleToOutcomeEntry(example: NegativeExample): {
  vulnClass: string;
  scannerUsed: string;
  detectionMethod: string;
  outcome: string;
  extractedPatterns: Array<{ pattern: string; vulnClass: string; confidence: number }>;
} {
  return {
    vulnClass: example.vulnClass,
    scannerUsed: 'hypothesis_generator',
    detectionMethod: 'automated_analysis',
    outcome: example.rejectionReason === 'duplicate' ? 'duplicate' : 'rejected',
    extractedPatterns: example.lessonsLearned.map(lesson => ({
      pattern: lesson,
      vulnClass: example.vulnClass,
      confidence: 0.7,
    })),
  };
}

// ─── Feedback Loop Engine ────────────────────────────────────────────────────

export class NegativeExampleFeedbackLoop {
  private config: FeedbackLoopConfig;
  private stats: FeedbackLoopStats;
  private calibrationRecords: CalibrationRecord[] = [];
  private unsubscribeFns: Array<() => void> = [];

  constructor(config?: Partial<FeedbackLoopConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.stats = {
      totalRejectionsProcessed: 0,
      totalCalibrationUpdates: 0,
      totalEventBusPublications: 0,
      driftDetectionsRun: 0,
      lastDriftReport: null,
      rejectionsByReason: {},
      calibrationRecordCount: 0,
      averageConfidenceAdjustment: 0,
    };
  }

  /**
   * Wire up the feedback loop to the CrossTrainingEventBus.
   * Subscribes to 'finding_rejected' events and routes them to the calibration engine.
   */
  wireToEventBus(
    eventBus: { subscribe: (eventType: string, handler: (event: CrossTrainingEvent) => void) => () => void },
    calibrationEngine: { recordOutcome: (record: CalibrationRecord) => void; detectDrift: () => DriftReport }
  ): void {
    // Subscribe to rejection events from the event bus
    const unsub = eventBus.subscribe('finding_rejected', (event: CrossTrainingEvent) => {
      const payload = event.payload as any;
      if (!payload?.vulnClass) return;

      // Convert event payload to calibration record
      const record: CalibrationRecord = {
        vulnClass: payload.vulnClass,
        predictedConfidence: payload.predictedConfidence || estimatePredictedConfidence(payload.severity || 'medium', payload.outcome || 'rejected'),
        actualOutcome: mapRejectionToOutcome(payload.rejectionReason || payload.outcome || 'rejected'),
        programHandle: payload.programHandle,
        timestamp: event.timestamp,
      };

      // Apply bias weight from event bus
      if (event.biasWeight && event.biasWeight !== 1.0) {
        record.predictedConfidence *= event.biasWeight;
      }

      calibrationEngine.recordOutcome(record);
      this.calibrationRecords.push(record);
      this.stats.totalCalibrationUpdates++;
      this.stats.calibrationRecordCount = this.calibrationRecords.length;

      // Run drift detection periodically
      if (this.calibrationRecords.length % this.config.driftDetectionThreshold === 0) {
        const drift = calibrationEngine.detectDrift();
        this.stats.driftDetectionsRun++;
        this.stats.lastDriftReport = drift;
      }
    });

    this.unsubscribeFns.push(unsub);
  }

  /**
   * Process a single rejected submission through the feedback loop.
   * This is the main entry point for manual/direct rejection processing.
   */
  processRejection(
    example: NegativeExample,
    calibrationEngine: { recordOutcome: (record: CalibrationRecord) => void; detectDrift: () => DriftReport },
    eventBus?: { publish: (source: CrossTrainingSource, eventType: CrossTrainingEventType, payload: any, meta?: any) => CrossTrainingEvent }
  ): RejectionFeedbackResult {
    // 1. Convert to calibration record
    const calibrationRecord = negativeExampleToCalibrationRecord(example, this.config);

    // 2. Apply weight boost for informative rejection types
    if (example.rejectionReason === 'false_positive') {
      calibrationRecord.predictedConfidence = Math.min(
        calibrationRecord.predictedConfidence * this.config.falsePositiveWeightBoost,
        0.99
      );
    }
    if (example.rejectionReason === 'out_of_scope') {
      calibrationRecord.predictedConfidence = Math.min(
        calibrationRecord.predictedConfidence * this.config.outOfScopeWeightBoost,
        0.99
      );
    }

    // 3. Feed calibration engine
    let calibrationUpdated = false;
    if (this.config.autoCalibrate) {
      calibrationEngine.recordOutcome(calibrationRecord);
      this.calibrationRecords.push(calibrationRecord);
      calibrationUpdated = true;
      this.stats.totalCalibrationUpdates++;
    }

    // 4. Publish to event bus
    let eventPublished = false;
    if (this.config.enableEventBus && eventBus) {
      const outcomeEntry = negativeExampleToOutcomeEntry(example);
      eventBus.publish('bug_bounty', 'finding_rejected', outcomeEntry, {
        rejectionReason: example.rejectionReason,
        programHandle: example.programHandle,
        technology: example.technology,
      });
      eventPublished = true;
      this.stats.totalEventBusPublications++;
    }

    // 5. Track stats
    this.stats.totalRejectionsProcessed++;
    this.stats.rejectionsByReason[example.rejectionReason] = 
      (this.stats.rejectionsByReason[example.rejectionReason] || 0) + 1;
    this.stats.calibrationRecordCount = this.calibrationRecords.length;

    // 6. Generate training signals
    const trainingSignals: TrainingSignal[] = [
      {
        vulnClass: example.vulnClass,
        endpoint: example.affectedEndpoint,
        technology: example.technology,
        isPositive: false,
        weight: this.calculateSignalWeight(example),
        reason: `Rejected: ${example.rejectionReason} — ${example.rejectionDetail}`,
        source: 'negative_pipeline',
      },
    ];

    // Add lesson-based signals
    for (const lesson of example.lessonsLearned) {
      trainingSignals.push({
        vulnClass: example.vulnClass,
        endpoint: example.affectedEndpoint,
        technology: example.technology,
        isPositive: false,
        weight: 0.5,
        reason: `Lesson: ${lesson}`,
        source: 'calibration',
      });
    }

    // 7. Check for drift
    let driftDetected = false;
    let driftReport: DriftReport | undefined;
    if (this.calibrationRecords.length >= this.config.driftDetectionThreshold &&
        this.calibrationRecords.length % this.config.driftDetectionThreshold === 0) {
      driftReport = calibrationEngine.detectDrift();
      driftDetected = driftReport.hasDrift;
      this.stats.driftDetectionsRun++;
      this.stats.lastDriftReport = driftReport;
    }

    // 8. Update average confidence adjustment
    const totalAdj = this.calibrationRecords.reduce((sum, r) => sum + (1 - r.predictedConfidence), 0);
    this.stats.averageConfidenceAdjustment = this.calibrationRecords.length > 0
      ? totalAdj / this.calibrationRecords.length
      : 0;

    return {
      processed: true,
      calibrationUpdated,
      eventPublished,
      driftDetected,
      driftReport,
      calibrationRecord,
      trainingSignals,
    };
  }

  /**
   * Process a batch of rejections (e.g., from a program sync).
   */
  processBatch(
    examples: NegativeExample[],
    calibrationEngine: { recordOutcome: (record: CalibrationRecord) => void; detectDrift: () => DriftReport },
    eventBus?: { publish: (source: CrossTrainingSource, eventType: CrossTrainingEventType, payload: any, meta?: any) => CrossTrainingEvent }
  ): {
    processed: number;
    calibrationUpdates: number;
    eventsPublished: number;
    driftDetected: boolean;
    driftReport?: DriftReport;
  } {
    let calibrationUpdates = 0;
    let eventsPublished = 0;

    for (const example of examples) {
      const result = this.processRejection(example, calibrationEngine, eventBus);
      if (result.calibrationUpdated) calibrationUpdates++;
      if (result.eventPublished) eventsPublished++;
    }

    // Final drift check after batch
    let driftDetected = false;
    let driftReport: DriftReport | undefined;
    if (this.calibrationRecords.length >= this.config.driftDetectionThreshold) {
      driftReport = calibrationEngine.detectDrift();
      driftDetected = driftReport.hasDrift;
      this.stats.driftDetectionsRun++;
      this.stats.lastDriftReport = driftReport;
    }

    return {
      processed: examples.length,
      calibrationUpdates,
      eventsPublished,
      driftDetected,
      driftReport,
    };
  }

  /**
   * Get feedback loop statistics.
   */
  getStats(): FeedbackLoopStats {
    return { ...this.stats };
  }

  /**
   * Get calibration records for analysis.
   */
  getCalibrationRecords(): CalibrationRecord[] {
    return [...this.calibrationRecords];
  }

  /**
   * Clean up event bus subscriptions.
   */
  dispose(): void {
    for (const unsub of this.unsubscribeFns) {
      unsub();
    }
    this.unsubscribeFns = [];
  }

  /**
   * Reset all state (for testing).
   */
  reset(): void {
    this.calibrationRecords = [];
    this.stats = {
      totalRejectionsProcessed: 0,
      totalCalibrationUpdates: 0,
      totalEventBusPublications: 0,
      driftDetectionsRun: 0,
      lastDriftReport: null,
      rejectionsByReason: {},
      calibrationRecordCount: 0,
      averageConfidenceAdjustment: 0,
    };
  }

  private calculateSignalWeight(example: NegativeExample): number {
    const baseWeights: Record<string, number> = {
      false_positive: 1.0,
      duplicate: 0.7,
      out_of_scope: 0.8,
      informational_only: 0.6,
      not_reproducible: 0.5,
      intended_behavior: 0.9,
      insufficient_impact: 0.6,
      known_issue: 0.4,
      wont_fix: 0.3,
      spam: 0.1,
      invalid_vulnerability: 0.9,
      already_patched: 0.2,
    };
    return baseWeights[example.rejectionReason] || 0.5;
  }
}

// ─── Singleton Instance ──────────────────────────────────────────────────────

export const feedbackLoop = new NegativeExampleFeedbackLoop();
