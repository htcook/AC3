import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cross-training-event-bus.ts
import { createHash } from "crypto";
function computeBiasWeight(event) {
  const profile = SOURCE_BIAS_PROFILES[event.source];
  if (!profile) return 0.5;
  let weight = profile.reliabilityWeight;
  const severity = event.payload.severity?.toLowerCase();
  const severityMultiplier = profile.severityBias[severity] || 1;
  weight *= 1 / severityMultiplier;
  const vulnClassMultiplier = profile.vulnClassBias[event.payload.vulnClass] || 1;
  weight *= 1 / vulnClassMultiplier;
  if (profile.demonstrabilityBias > 0.5 && event.payload.reproductionQuality < 0.5) {
    weight *= 1.2;
  }
  return Math.max(0.1, Math.min(1, weight));
}
var SOURCE_BIAS_PROFILES, SignalLineageTracker, DEFAULT_HOLDOUT_CONFIG, HoldoutValidationManager, CrossTrainingEventBus, crossTrainingBus;
var init_cross_training_event_bus = __esm({
  "server/lib/cross-training-event-bus.ts"() {
    SOURCE_BIAS_PROFILES = {
      bug_bounty: {
        source: "bug_bounty",
        reliabilityWeight: 0.85,
        severityBias: {
          critical: 1.3,
          // Over-reported (higher bounties)
          high: 1.2,
          medium: 0.9,
          low: 0.6,
          // Under-reported (low bounties)
          info: 0.3
          // Rarely reported
        },
        vulnClassBias: {
          "SQL Injection": 1.2,
          "Cross-Site Scripting": 1.3,
          // Easy to demonstrate
          "Remote Code Execution": 1.4,
          // High bounties
          "IDOR": 1.5,
          // Easy to find, high impact
          "Information Disclosure": 0.7,
          // Low bounties
          "Denial of Service": 0.4,
          // Often out of scope
          "Business Logic": 0.8
          // Hard to demonstrate
        },
        demonstrabilityBias: 0.8,
        // High — bounties require clear PoC
        timePressureBias: 0.3,
        // Low — researchers work at own pace
        incentiveAlignment: 0.7,
        // Good but reward-driven
        knownBiases: [
          "Favors easily demonstrable vulnerabilities over subtle ones",
          "Over-represents high-severity findings due to reward structure",
          "Under-represents vulnerabilities that require complex chains",
          "Selection bias: only submitted findings are visible",
          "Program scope limits what gets reported"
        ]
      },
      pentest_engagement: {
        source: "pentest_engagement",
        reliabilityWeight: 0.9,
        severityBias: {
          critical: 1,
          high: 1.1,
          medium: 1,
          low: 0.8,
          info: 0.7
        },
        vulnClassBias: {
          "SQL Injection": 1,
          "Cross-Site Scripting": 0.9,
          "Remote Code Execution": 1.1,
          "Privilege Escalation": 1.2,
          // Pentests focus on lateral movement
          "Misconfiguration": 1.3,
          // Pentests catch config issues
          "Business Logic": 1.1
          // More time to explore
        },
        demonstrabilityBias: 0.5,
        timePressureBias: 0.7,
        // High — engagements have deadlines
        incentiveAlignment: 0.85,
        // Professional obligation to be thorough
        knownBiases: [
          "Time-constrained: may miss deep/complex vulnerabilities",
          "Scope-limited: only tests what client authorizes",
          "Methodology-driven: may follow checklist rather than creative exploration",
          "Report-oriented: findings shaped by what looks good in reports"
        ]
      },
      vuln_scan: {
        source: "vuln_scan",
        reliabilityWeight: 0.65,
        severityBias: {
          critical: 1.5,
          // Scanners flag many criticals
          high: 1.3,
          medium: 1,
          low: 0.8,
          info: 1.2
          // Scanners produce lots of info findings
        },
        vulnClassBias: {
          "SQL Injection": 1.1,
          "Cross-Site Scripting": 1.4,
          // High FP rate
          "Missing Headers": 2,
          // Over-reported
          "SSL/TLS Issues": 1.8,
          // Over-reported
          "Outdated Software": 1.5,
          // Version-based, not always exploitable
          "Business Logic": 0.1
          // Scanners can't find these
        },
        demonstrabilityBias: 0.2,
        timePressureBias: 0.1,
        incentiveAlignment: 0.5,
        // No human judgment
        knownBiases: [
          "High false positive rate for certain vuln classes",
          "Cannot detect business logic vulnerabilities",
          "Version-based detection may not account for backported patches",
          "Signature-based: misses novel vulnerabilities",
          "Over-reports informational findings"
        ]
      },
      training_lab: {
        source: "training_lab",
        reliabilityWeight: 0.95,
        // Known ground truth
        severityBias: { critical: 1, high: 1, medium: 1, low: 1, info: 1 },
        vulnClassBias: {},
        demonstrabilityBias: 0.1,
        timePressureBias: 0.1,
        incentiveAlignment: 0.95,
        knownBiases: [
          "Artificial environment may not reflect real-world complexity",
          "Known vulnerabilities \u2014 no novel discovery signal",
          "Controlled conditions reduce environmental noise"
        ]
      },
      manual_review: {
        source: "manual_review",
        reliabilityWeight: 0.92,
        severityBias: { critical: 1, high: 1, medium: 1, low: 0.9, info: 0.8 },
        vulnClassBias: {},
        demonstrabilityBias: 0.3,
        timePressureBias: 0.4,
        incentiveAlignment: 0.9,
        knownBiases: [
          "Reviewer expertise varies",
          "May be influenced by prior findings"
        ]
      },
      external_feed: {
        source: "external_feed",
        reliabilityWeight: 0.6,
        severityBias: { critical: 1.2, high: 1.1, medium: 1, low: 0.8, info: 0.9 },
        vulnClassBias: {},
        demonstrabilityBias: 0.2,
        timePressureBias: 0.2,
        incentiveAlignment: 0.5,
        knownBiases: [
          "Quality varies widely by feed source",
          "May contain stale or inaccurate data",
          "No direct validation of findings"
        ]
      }
    };
    SignalLineageTracker = class {
      constructor(maxEntries = 1e4) {
        this.entries = [];
        this.maxEntries = maxEntries;
      }
      /**
       * Record a lineage entry.
       */
      record(entry) {
        if (this.entries.length >= this.maxEntries) {
          this.entries = this.entries.slice(Math.floor(this.maxEntries * 0.1));
        }
        this.entries.push({
          ...entry,
          id: `lineage-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          timestamp: Date.now()
        });
      }
      /**
       * Get all lineage entries for a specific component.
       * Useful for debugging when a model starts producing odd outputs.
       */
      getLineageForComponent(component) {
        return this.entries.filter((e) => e.affectedComponent === component || e.affectedComponent.startsWith(component + ":")).sort((a, b) => b.timestamp - a.timestamp);
      }
      /**
       * Get all lineage entries from a specific source.
       */
      getLineageBySource(source) {
        return this.entries.filter((e) => e.source === source).sort((a, b) => b.timestamp - a.timestamp);
      }
      /**
       * Get lineage summary: which sources have trained which components.
       */
      getLineageSummary() {
        const summary = {};
        for (const entry of this.entries) {
          const component = entry.affectedComponent;
          if (!summary[component]) {
            summary[component] = { sources: {}, totalUpdates: 0, lastUpdated: 0 };
          }
          summary[component].sources[entry.source] = (summary[component].sources[entry.source] || 0) + 1;
          summary[component].totalUpdates++;
          summary[component].lastUpdated = Math.max(summary[component].lastUpdated, entry.timestamp);
        }
        return summary;
      }
      /**
       * Export all lineage entries.
       */
      exportEntries() {
        return [...this.entries];
      }
      /**
       * Get entry count.
       */
      getEntryCount() {
        return this.entries.length;
      }
    };
    DEFAULT_HOLDOUT_CONFIG = {
      holdoutRate: 0.15,
      minOutcomesBeforeHoldout: 50,
      seed: "ac3-holdout-v1"
    };
    HoldoutValidationManager = class {
      constructor(config) {
        this.trainingSet = [];
        this.holdoutSet = [];
        this.totalProcessed = 0;
        this.config = { ...DEFAULT_HOLDOUT_CONFIG, ...config };
      }
      /**
       * Determine whether an outcome should be held out.
       * Uses deterministic hashing for reproducibility.
       */
      shouldHoldout(outcome) {
        this.totalProcessed++;
        if (this.totalProcessed < this.config.minOutcomesBeforeHoldout) {
          return false;
        }
        const hash = createHash("sha256").update(this.config.seed + ":" + outcome.id).digest("hex");
        const hashValue = parseInt(hash.slice(0, 8), 16) / 4294967295;
        return hashValue < this.config.holdoutRate;
      }
      /**
       * Route an outcome to either training or holdout set.
       */
      routeOutcome(outcome) {
        if (this.shouldHoldout(outcome)) {
          this.holdoutSet.push(outcome);
          return "holdout";
        }
        this.trainingSet.push(outcome);
        return "training";
      }
      /**
       * Validate the training pipeline against holdout data.
       * Measures whether cross-training is actually improving the receiving models.
       */
      validateAgainstHoldout(calibrationPipeline, patternRepo) {
        if (this.holdoutSet.length === 0) {
          return {
            holdoutSize: 0,
            trainingSize: this.trainingSet.length,
            isValid: false,
            reason: "No holdout data available yet",
            metrics: null
          };
        }
        let correctPredictions = 0;
        let totalPredictions = 0;
        let calibrationErrors = [];
        let patternHits = 0;
        for (const outcome of this.holdoutSet) {
          const wasAccepted = outcome.outcome === "accepted" || outcome.outcome === "bounty_paid";
          const adjustment = calibrationPipeline.getConfidenceAdjustment(
            outcome.vulnClass,
            outcome.scannerUsed,
            outcome.detectionMethod
          );
          const predictedAccepted = adjustment >= 0;
          if (predictedAccepted === wasAccepted) {
            correctPredictions++;
          }
          totalPredictions++;
          const expectedConfidence = wasAccepted ? 0.8 : 0.2;
          const actualConfidence = 0.5 + adjustment;
          calibrationErrors.push(Math.abs(expectedConfidence - actualConfidence));
          const patterns = patternRepo.getPatterns(outcome.vulnClass);
          if (patterns.length > 0) {
            patternHits++;
          }
        }
        const accuracy = totalPredictions > 0 ? correctPredictions / totalPredictions : 0;
        const avgCalibrationError = calibrationErrors.length > 0 ? calibrationErrors.reduce((s, e) => s + e, 0) / calibrationErrors.length : 1;
        const patternCoverage = this.holdoutSet.length > 0 ? patternHits / this.holdoutSet.length : 0;
        return {
          holdoutSize: this.holdoutSet.length,
          trainingSize: this.trainingSet.length,
          isValid: true,
          reason: null,
          metrics: {
            predictionAccuracy: accuracy,
            averageCalibrationError: avgCalibrationError,
            patternCoverage,
            holdoutRate: this.holdoutSet.length / (this.holdoutSet.length + this.trainingSet.length)
          }
        };
      }
      /**
       * Get holdout statistics.
       */
      getStats() {
        const total = this.trainingSet.length + this.holdoutSet.length;
        return {
          trainingSize: this.trainingSet.length,
          holdoutSize: this.holdoutSet.length,
          totalProcessed: this.totalProcessed,
          effectiveHoldoutRate: total > 0 ? this.holdoutSet.length / total : 0
        };
      }
      /**
       * Export holdout set for external validation.
       */
      exportHoldoutSet() {
        return [...this.holdoutSet];
      }
      /**
       * Export training set.
       */
      exportTrainingSet() {
        return [...this.trainingSet];
      }
    };
    CrossTrainingEventBus = class {
      constructor(opts) {
        this.handlers = /* @__PURE__ */ new Map();
        this.eventLog = [];
        // Stats
        this.totalEventsPublished = 0;
        this.totalEventsProcessed = 0;
        this.eventsBySource = /* @__PURE__ */ new Map();
        this.eventsByType = /* @__PURE__ */ new Map();
        this.maxEventLog = opts?.maxEventLog || 5e3;
        this.lineageTracker = new SignalLineageTracker(opts?.lineageMaxEntries);
        this.holdoutManager = new HoldoutValidationManager(opts?.holdoutConfig);
      }
      /**
       * Subscribe to cross-training events.
       * Use '*' to subscribe to all event types.
       */
      subscribe(eventType, handler) {
        const handlers = this.handlers.get(eventType) || [];
        handlers.push(handler);
        this.handlers.set(eventType, handlers);
        return () => {
          const current = this.handlers.get(eventType) || [];
          this.handlers.set(eventType, current.filter((h) => h !== handler));
        };
      }
      /**
       * Publish a cross-training event.
       * Applies bias correction, holdout routing, and dispatches to subscribers.
       */
      publish(source, eventType, payload, sourceMetadata) {
        const biasWeight = computeBiasWeight({ source, payload });
        const isHoldout = this.holdoutManager.shouldHoldout(payload);
        this.holdoutManager.routeOutcome(payload);
        const event = {
          id: `cte-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          timestamp: Date.now(),
          source,
          eventType,
          payload,
          sourceMetadata: sourceMetadata || {},
          isHoldout,
          biasWeight,
          processedBy: []
        };
        if (this.eventLog.length >= this.maxEventLog) {
          this.eventLog = this.eventLog.slice(Math.floor(this.maxEventLog * 0.1));
        }
        this.eventLog.push(event);
        this.totalEventsPublished++;
        this.eventsBySource.set(source, (this.eventsBySource.get(source) || 0) + 1);
        this.eventsByType.set(eventType, (this.eventsByType.get(eventType) || 0) + 1);
        if (!isHoldout) {
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
          const wildcardHandlers = this.handlers.get("*") || [];
          for (const handler of wildcardHandlers) {
            try {
              handler(event);
              event.processedBy.push("*:handler");
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
      processBatchWithBiasCorrection(outcomes, source, patternRepo, calibrationPipeline, toolTracker, sourceMetadata) {
        let patternsExtracted = 0;
        let calibrationUpdates = 0;
        let toolEffectivenessUpdates = 0;
        let contaminationRejections = 0;
        let holdoutCount = 0;
        let lineageEntries = 0;
        const weights = [];
        for (const outcome of outcomes) {
          const wasAccepted = outcome.outcome === "accepted" || outcome.outcome === "bounty_paid";
          const eventType = wasAccepted ? "finding_validated" : "finding_rejected";
          const event = this.publish(source, eventType, outcome, sourceMetadata);
          weights.push(event.biasWeight);
          if (event.isHoldout) {
            holdoutCount++;
            continue;
          }
          const prevAdjustment = calibrationPipeline.getConfidenceAdjustment(
            outcome.vulnClass,
            outcome.scannerUsed,
            outcome.detectionMethod
          );
          calibrationPipeline.recordOutcome({
            vulnClass: outcome.vulnClass,
            scannerUsed: outcome.scannerUsed,
            detectionMethod: outcome.detectionMethod,
            wasAccepted
          });
          calibrationUpdates++;
          const newAdjustment = calibrationPipeline.getConfidenceAdjustment(
            outcome.vulnClass,
            outcome.scannerUsed,
            outcome.detectionMethod
          );
          this.lineageTracker.record({
            eventId: event.id,
            source,
            consumer: "calibration_pipeline",
            affectedComponent: `${outcome.scannerUsed}:${outcome.vulnClass}:confidence`,
            changeType: "calibration_updated",
            valueBefore: prevAdjustment,
            valueAfter: newAdjustment,
            biasWeight: event.biasWeight,
            sourceMetadata: event.sourceMetadata
          });
          lineageEntries++;
          toolTracker.recordPerformance({
            toolName: outcome.scannerUsed,
            vulnClass: outcome.vulnClass,
            detected: true,
            wasTruePositive: wasAccepted,
            wasUniqueToTool: false,
            wasCorroborated: false
          });
          toolEffectivenessUpdates++;
          this.lineageTracker.record({
            eventId: event.id,
            source,
            consumer: "tool_effectiveness",
            affectedComponent: `${outcome.scannerUsed}:${outcome.vulnClass}:effectiveness`,
            changeType: "effectiveness_updated",
            biasWeight: event.biasWeight,
            sourceMetadata: event.sourceMetadata
          });
          lineageEntries++;
          for (const pattern of outcome.extractedPatterns) {
            if (patternRepo.addPattern(pattern)) {
              patternsExtracted++;
              this.lineageTracker.record({
                eventId: event.id,
                source,
                consumer: "pattern_repository",
                affectedComponent: `${pattern.vulnClass}:${pattern.category}`,
                changeType: pattern.observationCount > 1 ? "pattern_updated" : "pattern_added",
                biasWeight: event.biasWeight,
                sourceMetadata: event.sourceMetadata
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
            avg: weights.length > 0 ? weights.reduce((s, w) => s + w, 0) / weights.length : 0
          },
          lineageEntries
        };
      }
      /**
       * Run holdout validation against current calibration state.
       */
      runHoldoutValidation(calibrationPipeline, patternRepo) {
        return this.holdoutManager.validateAgainstHoldout(calibrationPipeline, patternRepo);
      }
      /**
       * Get the signal lineage tracker.
       */
      getLineageTracker() {
        return this.lineageTracker;
      }
      /**
       * Get the holdout manager.
       */
      getHoldoutManager() {
        return this.holdoutManager;
      }
      /**
       * Get event bus statistics.
       */
      getStats() {
        return {
          totalEventsPublished: this.totalEventsPublished,
          totalEventsProcessed: this.totalEventsProcessed,
          eventsBySource: Object.fromEntries(this.eventsBySource),
          eventsByType: Object.fromEntries(this.eventsByType),
          holdoutStats: this.holdoutManager.getStats(),
          lineageEntryCount: this.lineageTracker.getEntryCount(),
          eventLogSize: this.eventLog.length
        };
      }
      /**
       * Get recent events for debugging.
       */
      getRecentEvents(limit = 50) {
        return this.eventLog.slice(-limit);
      }
    };
    crossTrainingBus = new CrossTrainingEventBus();
  }
});
init_cross_training_event_bus();
export {
  CrossTrainingEventBus,
  HoldoutValidationManager,
  SOURCE_BIAS_PROFILES,
  SignalLineageTracker,
  computeBiasWeight,
  crossTrainingBus
};
