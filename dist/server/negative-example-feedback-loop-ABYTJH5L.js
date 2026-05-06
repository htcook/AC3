import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/negative-example-feedback-loop.ts
function mapRejectionToOutcome(rejectionReason) {
  switch (rejectionReason) {
    case "duplicate":
      return "duplicate";
    case "informational_only":
    case "insufficient_impact":
      return "informational";
    default:
      return "rejected";
  }
}
function estimatePredictedConfidence(severity, rejectionReason) {
  const severityBase = {
    critical: 0.85,
    high: 0.75,
    medium: 0.6,
    low: 0.45,
    info: 0.3,
    none: 0.2
  };
  let base = severityBase[severity.toLowerCase()] || 0.5;
  if (rejectionReason === "false_positive") base = Math.max(base, 0.7);
  if (rejectionReason === "intended_behavior") base = Math.max(base, 0.65);
  if (rejectionReason === "invalid_vulnerability") base = Math.max(base, 0.6);
  return base;
}
function negativeExampleToCalibrationRecord(example, config = DEFAULT_CONFIG) {
  const predictedConfidence = estimatePredictedConfidence(example.severity, example.rejectionReason);
  return {
    vulnClass: example.vulnClass,
    predictedConfidence,
    actualOutcome: mapRejectionToOutcome(example.rejectionReason),
    programHandle: example.programHandle,
    timestamp: example.rejectedAt ? new Date(example.rejectedAt).getTime() : Date.now()
  };
}
function negativeExampleToOutcomeEntry(example) {
  return {
    vulnClass: example.vulnClass,
    scannerUsed: "hypothesis_generator",
    detectionMethod: "automated_analysis",
    outcome: example.rejectionReason === "duplicate" ? "duplicate" : "rejected",
    extractedPatterns: example.lessonsLearned.map((lesson) => ({
      pattern: lesson,
      vulnClass: example.vulnClass,
      confidence: 0.7
    }))
  };
}
var DEFAULT_CONFIG, NegativeExampleFeedbackLoop, feedbackLoop;
var init_negative_example_feedback_loop = __esm({
  "server/lib/negative-example-feedback-loop.ts"() {
    DEFAULT_CONFIG = {
      autoCalibrate: true,
      driftDetectionThreshold: 5,
      falsePositiveWeightBoost: 1.5,
      outOfScopeWeightBoost: 1.2,
      enableEventBus: true,
      maxCalibrationRecords: 1e4
    };
    NegativeExampleFeedbackLoop = class {
      constructor(config) {
        this.calibrationRecords = [];
        this.unsubscribeFns = [];
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.stats = {
          totalRejectionsProcessed: 0,
          totalCalibrationUpdates: 0,
          totalEventBusPublications: 0,
          driftDetectionsRun: 0,
          lastDriftReport: null,
          rejectionsByReason: {},
          calibrationRecordCount: 0,
          averageConfidenceAdjustment: 0
        };
      }
      /**
       * Wire up the feedback loop to the CrossTrainingEventBus.
       * Subscribes to 'finding_rejected' events and routes them to the calibration engine.
       */
      wireToEventBus(eventBus, calibrationEngine) {
        const unsub = eventBus.subscribe("finding_rejected", (event) => {
          const payload = event.payload;
          if (!payload?.vulnClass) return;
          const record = {
            vulnClass: payload.vulnClass,
            predictedConfidence: payload.predictedConfidence || estimatePredictedConfidence(payload.severity || "medium", payload.outcome || "rejected"),
            actualOutcome: mapRejectionToOutcome(payload.rejectionReason || payload.outcome || "rejected"),
            programHandle: payload.programHandle,
            timestamp: event.timestamp
          };
          if (event.biasWeight && event.biasWeight !== 1) {
            record.predictedConfidence *= event.biasWeight;
          }
          calibrationEngine.recordOutcome(record);
          this.calibrationRecords.push(record);
          this.stats.totalCalibrationUpdates++;
          this.stats.calibrationRecordCount = this.calibrationRecords.length;
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
      processRejection(example, calibrationEngine, eventBus) {
        const calibrationRecord = negativeExampleToCalibrationRecord(example, this.config);
        if (example.rejectionReason === "false_positive") {
          calibrationRecord.predictedConfidence = Math.min(
            calibrationRecord.predictedConfidence * this.config.falsePositiveWeightBoost,
            0.99
          );
        }
        if (example.rejectionReason === "out_of_scope") {
          calibrationRecord.predictedConfidence = Math.min(
            calibrationRecord.predictedConfidence * this.config.outOfScopeWeightBoost,
            0.99
          );
        }
        let calibrationUpdated = false;
        if (this.config.autoCalibrate) {
          calibrationEngine.recordOutcome(calibrationRecord);
          this.calibrationRecords.push(calibrationRecord);
          calibrationUpdated = true;
          this.stats.totalCalibrationUpdates++;
        }
        let eventPublished = false;
        if (this.config.enableEventBus && eventBus) {
          const outcomeEntry = negativeExampleToOutcomeEntry(example);
          eventBus.publish("bug_bounty", "finding_rejected", outcomeEntry, {
            rejectionReason: example.rejectionReason,
            programHandle: example.programHandle,
            technology: example.technology
          });
          eventPublished = true;
          this.stats.totalEventBusPublications++;
        }
        this.stats.totalRejectionsProcessed++;
        this.stats.rejectionsByReason[example.rejectionReason] = (this.stats.rejectionsByReason[example.rejectionReason] || 0) + 1;
        this.stats.calibrationRecordCount = this.calibrationRecords.length;
        const trainingSignals = [
          {
            vulnClass: example.vulnClass,
            endpoint: example.affectedEndpoint,
            technology: example.technology,
            isPositive: false,
            weight: this.calculateSignalWeight(example),
            reason: `Rejected: ${example.rejectionReason} \u2014 ${example.rejectionDetail}`,
            source: "negative_pipeline"
          }
        ];
        for (const lesson of example.lessonsLearned) {
          trainingSignals.push({
            vulnClass: example.vulnClass,
            endpoint: example.affectedEndpoint,
            technology: example.technology,
            isPositive: false,
            weight: 0.5,
            reason: `Lesson: ${lesson}`,
            source: "calibration"
          });
        }
        let driftDetected = false;
        let driftReport;
        if (this.calibrationRecords.length >= this.config.driftDetectionThreshold && this.calibrationRecords.length % this.config.driftDetectionThreshold === 0) {
          driftReport = calibrationEngine.detectDrift();
          driftDetected = driftReport.hasDrift;
          this.stats.driftDetectionsRun++;
          this.stats.lastDriftReport = driftReport;
        }
        const totalAdj = this.calibrationRecords.reduce((sum, r) => sum + (1 - r.predictedConfidence), 0);
        this.stats.averageConfidenceAdjustment = this.calibrationRecords.length > 0 ? totalAdj / this.calibrationRecords.length : 0;
        return {
          processed: true,
          calibrationUpdated,
          eventPublished,
          driftDetected,
          driftReport,
          calibrationRecord,
          trainingSignals
        };
      }
      /**
       * Process a batch of rejections (e.g., from a program sync).
       */
      processBatch(examples, calibrationEngine, eventBus) {
        let calibrationUpdates = 0;
        let eventsPublished = 0;
        for (const example of examples) {
          const result = this.processRejection(example, calibrationEngine, eventBus);
          if (result.calibrationUpdated) calibrationUpdates++;
          if (result.eventPublished) eventsPublished++;
        }
        let driftDetected = false;
        let driftReport;
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
          driftReport
        };
      }
      /**
       * Get feedback loop statistics.
       */
      getStats() {
        return { ...this.stats };
      }
      /**
       * Get calibration records for analysis.
       */
      getCalibrationRecords() {
        return [...this.calibrationRecords];
      }
      /**
       * Clean up event bus subscriptions.
       */
      dispose() {
        for (const unsub of this.unsubscribeFns) {
          unsub();
        }
        this.unsubscribeFns = [];
      }
      /**
       * Reset all state (for testing).
       */
      reset() {
        this.calibrationRecords = [];
        this.stats = {
          totalRejectionsProcessed: 0,
          totalCalibrationUpdates: 0,
          totalEventBusPublications: 0,
          driftDetectionsRun: 0,
          lastDriftReport: null,
          rejectionsByReason: {},
          calibrationRecordCount: 0,
          averageConfidenceAdjustment: 0
        };
      }
      calculateSignalWeight(example) {
        const baseWeights = {
          false_positive: 1,
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
          already_patched: 0.2
        };
        return baseWeights[example.rejectionReason] || 0.5;
      }
    };
    feedbackLoop = new NegativeExampleFeedbackLoop();
  }
});
init_negative_example_feedback_loop();
export {
  NegativeExampleFeedbackLoop,
  feedbackLoop,
  negativeExampleToCalibrationRecord,
  negativeExampleToOutcomeEntry
};
