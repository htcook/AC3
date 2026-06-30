/**
 * Graduation Engine ↔ Telemetry Integration
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Wires the telemetry system into the post-pipeline graduation engine so that:
 *   1. Each specialist model scoring emits a telemetry event
 *   2. Training data collection is tracked (volume, quality, source)
 *   3. Graduation pass/fail decisions are recorded as pipeline decisions
 *   4. Methodology bonus computations are instrumented
 *   5. Knowledge gaps in LLM-scored models are detected and reported
 *   6. Graduation health metrics are included in diagnostic summaries
 *
 * Usage:
 *   import { runGraduationWithTelemetry } from './graduation-telemetry';
 *   const result = await runGraduationWithTelemetry(metrics, engagementId);
 *
 * @module graduation-telemetry
 * @author Harrison Cook
 */

import type { TelemetryContext, TelemetryEvent } from "./telemetry-logger";
import {
  createTelemetryContext,
  forkContext,
  emitEvent,
  emitToolCall,
  emitToolResponse,
  emitDecision,
  emitError,
  emitPhaseTransition,
  withTelemetry,
  flushEvents,
} from "./telemetry-logger";
import {
  initEngagementTelemetry,
  getTelemetryContext,
  recordPhaseTransition,
  recordPipelineDecision,
  recordPipelineError,
} from "./telemetry-integration";
import type { PipelineMetrics, GraduationResult } from "./post-pipeline-graduation";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GraduationTelemetryResult extends GraduationResult {
  telemetry: {
    totalEvents: number;
    durationMs: number;
    modelsScored: number;
    modelsPassed: number;
    modelsFailed: number;
    trainingExamplesCollected: number;
    methodologyBonusApplied: boolean;
    knowledgeGapsDetected: number;
    scoringBreakdown: Array<{
      model: string;
      score: number;
      passed: boolean;
      threshold: number;
      durationMs: number;
    }>;
  };
}

export interface GraduationHealthMetrics {
  avgScore: number;
  passRate: number;
  scoreTrend: "improving" | "stable" | "declining";
  weakestModel: string;
  strongestModel: string;
  trainingDataQuality: "high" | "medium" | "low";
  consecutiveFailures: number;
  recommendedActions: string[];
}

// ─── Thresholds (mirrored from post-pipeline-graduation) ────────────────────

const GRADUATION_THRESHOLDS: Record<string, number> = {
  recon_analyst: 30,
  exploit_selector: 20,
  evasion_optimizer: 50,
  cognitive_core: 40,
  cloud_assessor: 10,
  supply_chain_analyst: 10,
};

// ─── Main Instrumented Graduation ───────────────────────────────────────────

/**
 * Run post-pipeline graduation with full telemetry instrumentation.
 * This wraps `runPostPipelineGraduation` and emits events for each step.
 */
export async function runGraduationWithTelemetry(
  metrics: PipelineMetrics,
  engagementId?: number,
): Promise<GraduationTelemetryResult> {
  const startTime = Date.now();

  // Get or create telemetry context
  let ctx: TelemetryContext;
  let ownsContext = false;

  if (engagementId) {
    const existing = getTelemetryContext(engagementId);
    if (existing) {
      ctx = forkContext(existing, "graduation-engine");
    } else {
      ctx = createTelemetryContext({
        engagementId,
        phase: "graduation",
        sourceModule: "graduation-engine",
        consoleLog: process.env.NODE_ENV !== "test",
      });
      ownsContext = true;
    }
  } else {
    ctx = createTelemetryContext({
      engagementId: Number(metrics.pipelineId) || 0,
      phase: "graduation",
      sourceModule: "graduation-engine",
      consoleLog: process.env.NODE_ENV !== "test",
    });
    ownsContext = true;
  }

  // Emit phase transition to graduation
  emitPhaseTransition(ctx, {
    fromPhase: ctx.phase === "graduation" ? "pipeline_complete" : ctx.phase,
    toPhase: "graduation",
  });

  // Emit the graduation start event
  emitToolCall(ctx, {
    step: "graduation_start",
    inputSummary: `Pipeline: ${metrics.pipelineType} | ID: ${metrics.pipelineId} | Domain: ${metrics.domain || "N/A"} | Vulns: ${metrics.totalVulns} | Exploits: ${metrics.exploitsSucceeded}/${metrics.exploitsAttempted}`,
  });

  // Run the actual graduation
  const { result: graduationResult, durationMs: gradDuration } = await withTelemetry(
    ctx,
    {
      step: "run_graduation_scoring",
      inputSummary: `Score 6 specialist models for ${metrics.pipelineType} pipeline ${metrics.pipelineId}`,
    },
    async () => {
      const { runPostPipelineGraduation } = await import("./post-pipeline-graduation");
      return runPostPipelineGraduation(metrics);
    },
  );

  if (!graduationResult) {
    emitError(ctx, {
      step: "graduation_scoring",
      error: "Graduation scoring returned null/undefined",
    });

    // Merge events back to parent if we forked
    if (engagementId) {
      const parent = getTelemetryContext(engagementId);
      if (parent && parent !== ctx) {
        parent.events.push(...ctx.events);
      }
    }

    throw new Error("Graduation scoring failed");
  }

  // Emit individual model scoring events
  const scoringBreakdown: GraduationTelemetryResult["telemetry"]["scoringBreakdown"] = [];
  const modelScoringStart = Date.now();

  for (const [model, score] of Object.entries(graduationResult.scores)) {
    const threshold = GRADUATION_THRESHOLDS[model] || 0;
    const passed = graduationResult.passed[model as keyof typeof graduationResult.passed];
    const modelDuration = Math.round((Date.now() - modelScoringStart) / Object.keys(graduationResult.scores).length);

    scoringBreakdown.push({
      model,
      score,
      passed,
      threshold,
      durationMs: modelDuration,
    });

    // Emit scoring event for each model
    emitToolResponse(ctx, {
      step: `score_${model}`,
      outputSummary: `${model}: ${score}/100 (threshold: ${threshold}) → ${passed ? "PASS" : "FAIL"}`,
      durationMs: modelDuration,
      success: passed,
    });

    // Detect knowledge gaps for low-scoring models
    if (score < threshold && score > 0) {
      emitDecision(ctx, {
        step: `graduation_gap_${model}`,
        decision: `Model ${model} scored ${score}/${threshold} — below graduation threshold`,
        reasoning: buildGapReasoning(model, score, threshold, metrics),
      });
    }
  }

  // Emit training data collection event
  if (graduationResult.trainingExamplesCollected > 0) {
    emitToolResponse(ctx, {
      step: "training_data_collection",
      outputSummary: `Collected ${graduationResult.trainingExamplesCollected} training examples from ${metrics.pipelineType} pipeline`,
      durationMs: 0,
      success: true,
    });
  }

  // Emit overall graduation decision
  const modelsPassed = Object.values(graduationResult.passed).filter(Boolean).length;
  const modelsFailed = Object.values(graduationResult.passed).length - modelsPassed;
  const avgScore = Math.round(
    Object.values(graduationResult.scores).reduce((s, v) => s + v, 0) /
    Object.values(graduationResult.scores).length
  );

  emitDecision(ctx, {
    step: "graduation_verdict",
    decision: `${modelsPassed}/${Object.keys(graduationResult.scores).length} models passed | Avg score: ${avgScore}/100 | Training examples: ${graduationResult.trainingExamplesCollected}`,
    reasoning: graduationResult.summary,
  });

  // Detect knowledge gaps from low-scoring areas
  let knowledgeGapsDetected = 0;
  for (const [model, score] of Object.entries(graduationResult.scores)) {
    if (score === 0 && shouldHaveScored(model, metrics)) {
      knowledgeGapsDetected++;
      emitEvent(ctx, {
        eventType: "knowledge_gap",
        step: `graduation_knowledge_gap_${model}`,
        success: false,
        errorClass: "knowledge_gap",
        errorMessage: `Model ${model} scored 0 despite relevant metrics being present`,
        contextSnapshot: {
          model,
          relevantMetrics: getRelevantMetrics(model, metrics),
        },
      });
    }
  }

  // Check for methodology bonus telemetry
  const methodologyBonusApplied = graduationResult.summary.includes("|");

  const totalDuration = Date.now() - startTime;

  // Build telemetry result
  const telemetryResult: GraduationTelemetryResult = {
    ...graduationResult,
    telemetry: {
      totalEvents: ctx.events.length,
      durationMs: totalDuration,
      modelsScored: Object.keys(graduationResult.scores).length,
      modelsPassed,
      modelsFailed,
      trainingExamplesCollected: graduationResult.trainingExamplesCollected,
      methodologyBonusApplied,
      knowledgeGapsDetected,
      scoringBreakdown,
    },
  };

  // Merge events back to parent context
  if (engagementId) {
    const parent = getTelemetryContext(engagementId);
    if (parent && parent !== ctx) {
      parent.events.push(...ctx.events);
    }
  }

  // Flush if we own the context
  if (ownsContext) {
    try {
      await flushEvents(ctx);
    } catch { /* non-fatal */ }
  }

  return telemetryResult;
}

// ─── Graduation Health Metrics ──────────────────────────────────────────────

/**
 * Compute graduation health metrics from telemetry events.
 * Used by the diagnostic summary to include graduation-specific insights.
 */
export function computeGraduationHealth(events: TelemetryEvent[]): GraduationHealthMetrics | null {
  // Filter graduation-related events
  const gradEvents = events.filter(
    (e) => e.step?.startsWith("score_") || e.step?.startsWith("graduation_") || e.step === "training_data_collection"
  );

  if (gradEvents.length === 0) return null;

  // Extract model scores from events
  const modelScores: Record<string, number[]> = {};
  for (const e of gradEvents) {
    if (e.step?.startsWith("score_") && e.outputSummary) {
      const model = e.step.replace("score_", "");
      const match = e.outputSummary.match(/(\d+)\/100/);
      if (match) {
        if (!modelScores[model]) modelScores[model] = [];
        modelScores[model].push(parseInt(match[1]));
      }
    }
  }

  if (Object.keys(modelScores).length === 0) return null;

  // Compute averages
  const avgScores: Record<string, number> = {};
  for (const [model, scores] of Object.entries(modelScores)) {
    avgScores[model] = Math.round(scores.reduce((s, v) => s + v, 0) / scores.length);
  }

  const allAvgs = Object.values(avgScores);
  const overallAvg = Math.round(allAvgs.reduce((s, v) => s + v, 0) / allAvgs.length);

  // Find weakest/strongest
  const sorted = Object.entries(avgScores).sort((a, b) => a[1] - b[1]);
  const weakestModel = sorted[0]?.[0] || "unknown";
  const strongestModel = sorted[sorted.length - 1]?.[0] || "unknown";

  // Compute pass rate
  const passEvents = gradEvents.filter((e) => e.step?.startsWith("score_") && e.success);
  const totalScoreEvents = gradEvents.filter((e) => e.step?.startsWith("score_"));
  const passRate = totalScoreEvents.length > 0
    ? passEvents.length / totalScoreEvents.length
    : 0;

  // Determine trend (compare first half vs second half of scores)
  let scoreTrend: "improving" | "stable" | "declining" = "stable";
  const allScoreValues = Object.values(modelScores).flat();
  if (allScoreValues.length >= 4) {
    const mid = Math.floor(allScoreValues.length / 2);
    const firstHalf = allScoreValues.slice(0, mid);
    const secondHalf = allScoreValues.slice(mid);
    const firstAvg = firstHalf.reduce((s, v) => s + v, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((s, v) => s + v, 0) / secondHalf.length;
    if (secondAvg > firstAvg + 5) scoreTrend = "improving";
    else if (secondAvg < firstAvg - 5) scoreTrend = "declining";
  }

  // Training data quality
  const trainingEvents = gradEvents.filter((e) => e.step === "training_data_collection");
  const totalTraining = trainingEvents.reduce((sum, e) => {
    const match = e.outputSummary?.match(/Collected (\d+)/);
    return sum + (match ? parseInt(match[1]) : 0);
  }, 0);
  const trainingDataQuality: "high" | "medium" | "low" =
    totalTraining >= 10 ? "high" : totalTraining >= 3 ? "medium" : "low";

  // Consecutive failures
  const verdictEvents = gradEvents.filter((e) => e.step === "graduation_verdict");
  let consecutiveFailures = 0;
  for (let i = verdictEvents.length - 1; i >= 0; i--) {
    const match = verdictEvents[i].inputSummary?.match(/(\d+)\/(\d+) models passed/);
    if (match && parseInt(match[1]) < parseInt(match[2])) {
      consecutiveFailures++;
    } else {
      break;
    }
  }

  // Recommended actions
  const recommendedActions: string[] = [];
  if (avgScores[weakestModel] < (GRADUATION_THRESHOLDS[weakestModel] || 30)) {
    recommendedActions.push(`Focus training on ${weakestModel} (avg ${avgScores[weakestModel]}/${GRADUATION_THRESHOLDS[weakestModel] || 30})`);
  }
  if (trainingDataQuality === "low") {
    recommendedActions.push("Increase pipeline runs to collect more training data");
  }
  if (scoreTrend === "declining") {
    recommendedActions.push("Investigate score regression — check for data quality issues or target difficulty changes");
  }
  if (consecutiveFailures >= 3) {
    recommendedActions.push(`${consecutiveFailures} consecutive partial failures — consider adjusting thresholds or retraining`);
  }
  if (passRate < 0.5) {
    recommendedActions.push("Less than 50% of models passing — review pipeline quality and target selection");
  }

  return {
    avgScore: overallAvg,
    passRate,
    scoreTrend,
    weakestModel,
    strongestModel,
    trainingDataQuality,
    consecutiveFailures,
    recommendedActions,
  };
}

// ─── Graduation Diagnostic Section ─────────────────────────────────────────

/**
 * Generate a markdown section for graduation health to include in diagnostic reports.
 */
export function generateGraduationDiagnosticSection(events: TelemetryEvent[]): string {
  const health = computeGraduationHealth(events);
  if (!health) return "";

  const lines: string[] = [];
  lines.push("## Graduation Engine Health");
  lines.push("");
  lines.push(`**Average Score:** ${health.avgScore}/100`);
  lines.push(`**Pass Rate:** ${(health.passRate * 100).toFixed(1)}%`);
  lines.push(`**Trend:** ${health.scoreTrend}`);
  lines.push(`**Weakest Model:** ${health.weakestModel}`);
  lines.push(`**Strongest Model:** ${health.strongestModel}`);
  lines.push(`**Training Data Quality:** ${health.trainingDataQuality}`);
  lines.push("");

  if (health.consecutiveFailures > 0) {
    lines.push(`> **Warning:** ${health.consecutiveFailures} consecutive partial failures detected`);
    lines.push("");
  }

  if (health.recommendedActions.length > 0) {
    lines.push("### Recommended Actions");
    lines.push("");
    for (const action of health.recommendedActions) {
      lines.push(`- ${action}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildGapReasoning(model: string, score: number, threshold: number, metrics: PipelineMetrics): string {
  const gap = threshold - score;
  const parts: string[] = [`Score ${score} is ${gap} points below threshold ${threshold}.`];

  switch (model) {
    case "recon_analyst":
      parts.push(`Assets: ${metrics.assetsDiscovered}, Subdomains: ${metrics.subdomainsFound}, Ports: ${metrics.portsFound}`);
      if (metrics.assetsDiscovered === 0) parts.push("No assets discovered — possible target hardening or scan misconfiguration");
      break;
    case "exploit_selector":
      parts.push(`Exploits: ${metrics.exploitsSucceeded}/${metrics.exploitsAttempted}, Vulns: ${metrics.totalVulns}`);
      if (metrics.exploitsAttempted === 0 && metrics.totalVulns > 0) parts.push("Vulns found but no exploits attempted — missing exploit selection logic");
      break;
    case "evasion_optimizer":
      parts.push(`WAF: ${metrics.wafDetected ? "detected" : "none"}, Blocked: ${metrics.scanBlocked}, Recovered: ${metrics.scanRecovered}`);
      if (metrics.scanBlocked && !metrics.scanRecovered) parts.push("Scan blocked without recovery — evasion escalation failed");
      break;
    case "cognitive_core":
      parts.push(`OWASP: ${metrics.owaspCategoriesTested}/${metrics.owaspCategoriesTotal}, FP rate: ${(metrics.falsePositiveRate * 100).toFixed(1)}%`);
      if (metrics.falsePositiveRate > 0.3) parts.push("High false positive rate degrading cognitive core score");
      break;
    case "cloud_assessor":
      parts.push(`Cloud: ${metrics.cloudAssetsFound}, Storage: ${metrics.storageAssetsFound}, Container: ${metrics.containerAssetsFound}`);
      break;
    case "supply_chain_analyst":
      parts.push(`Repos: ${metrics.repoExposuresFound}, Platforms: ${metrics.platformAssetsFound}, Techs: ${metrics.technologiesDetected}`);
      break;
  }

  return parts.join(" ");
}

function shouldHaveScored(model: string, metrics: PipelineMetrics): boolean {
  switch (model) {
    case "recon_analyst":
      return metrics.assetsDiscovered > 0 || metrics.subdomainsFound > 0 || metrics.portsFound > 0;
    case "exploit_selector":
      return metrics.exploitsAttempted > 0 || metrics.totalVulns > 0;
    case "evasion_optimizer":
      return metrics.wafDetected || metrics.scanBlocked;
    case "cognitive_core":
      return metrics.totalVulns > 0 || metrics.owaspCategoriesTested > 0;
    case "cloud_assessor":
      return metrics.cloudAssetsFound > 0 || metrics.storageAssetsFound > 0;
    case "supply_chain_analyst":
      return metrics.repoExposuresFound > 0 || metrics.platformAssetsFound > 0;
    default:
      return false;
  }
}

function getRelevantMetrics(model: string, metrics: PipelineMetrics): Record<string, number> {
  switch (model) {
    case "recon_analyst":
      return { assets: metrics.assetsDiscovered, subdomains: metrics.subdomainsFound, ports: metrics.portsFound };
    case "exploit_selector":
      return { attempted: metrics.exploitsAttempted, succeeded: metrics.exploitsSucceeded, vulns: metrics.totalVulns };
    case "evasion_optimizer":
      return { wafDetected: metrics.wafDetected ? 1 : 0, blocked: metrics.scanBlocked ? 1 : 0 };
    case "cognitive_core":
      return { owasp: metrics.owaspCategoriesTested, fpRate: metrics.falsePositiveRate };
    case "cloud_assessor":
      return { cloud: metrics.cloudAssetsFound, storage: metrics.storageAssetsFound };
    case "supply_chain_analyst":
      return { repos: metrics.repoExposuresFound, platforms: metrics.platformAssetsFound };
    default:
      return {};
  }
}

// ─── Exports ────────────────────────────────────────────────────────────────

export {
  GRADUATION_THRESHOLDS,
  buildGapReasoning,
  shouldHaveScored,
  getRelevantMetrics,
};
