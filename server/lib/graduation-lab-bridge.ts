/**
 * Graduation-Lab Bridge
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Connects the Test Lab environment with the Graduation Engine to create
 * a closed-loop training and evaluation system for Ember's specialist models.
 *
 * Flow:
 *   1. Graduation Engine identifies LLM callers at each tier
 *   2. Bridge maps callers to specialist models
 *   3. Lab scenarios are unlocked based on graduation tier
 *   4. Lab performance feeds back into graduation scoring
 *   5. Models that pass lab benchmarks get promoted
 *
 * Tier → Lab Access:
 *   Tier 4 (Training):  Basic scenarios only (deployment, simple C2 tests)
 *   Tier 3 (Emerging):  + Operational scenarios (recon, exploit selection)
 *   Tier 2 (Near):      + Advanced scenarios (stealth, lateral movement, swarm)
 *   Tier 1 (Ready):     + Full red team scenarios, exploit-to-implant pipeline
 *
 * Lab → Graduation Feedback:
 *   - Lab scenario success/failure feeds training data collection
 *   - Benchmark scores influence graduation tier assessment
 *   - Promoted models get registered as new LLM callers for telemetry
 */

import { randomUUID } from "crypto";
import type { SpecialistModel, ModelBenchmark, TrainingExample } from "./llm-training-pipeline";

// ─── Types ──────────────────────────────────────────────────────────────────

export type GraduationTier = 1 | 2 | 3 | 4 | 5;

export type LabAccessLevel = "basic" | "operational" | "advanced" | "full";

export interface CallerToModelMapping {
  callerPattern: string;
  specialistModel: SpecialistModel;
  description: string;
}

export interface LabTierConfig {
  tier: GraduationTier;
  accessLevel: LabAccessLevel;
  allowedScenarioCategories: string[];
  allowedDifficulties: string[];
  requiresMinExamples: number;
  requiresMinBenchmarkScore: number;
  unlockMessage: string;
}

export interface LabGraduationEvent {
  id: string;
  timestamp: number;
  eventType: "tier_change" | "scenario_completed" | "benchmark_passed" | "model_promoted" | "model_rollback" | "training_started" | "training_completed";
  specialistModel: SpecialistModel;
  previousTier?: GraduationTier;
  newTier?: GraduationTier;
  scenarioId?: string;
  benchmarkId?: string;
  score?: number;
  details: string;
}

export interface ModelGraduationState {
  model: SpecialistModel;
  currentTier: GraduationTier;
  labAccessLevel: LabAccessLevel;
  scenariosCompleted: number;
  scenariosPassed: number;
  scenariosFailed: number;
  averageScore: number;
  lastBenchmarkScore: number;
  lastBenchmarkDate?: number;
  trainingExamples: number;
  fineTuneRuns: number;
  lastPromotedAt?: number;
  currentModelVersion: number;
  events: LabGraduationEvent[];
}

export interface GraduationLabSummary {
  models: ModelGraduationState[];
  totalScenariosRun: number;
  totalTrainingExamples: number;
  totalFineTuneRuns: number;
  modelsAtTier1: number;
  modelsAtTier2: number;
  modelsAtTier3: number;
  modelsAtTier4: number;
  overallReadinessScore: number;
  nextRecommendedAction: string;
}

// ─── Caller → Model Mapping ────────────────────────────────────────────────

const CALLER_MODEL_MAPPINGS: CallerToModelMapping[] = [
  {
    callerPattern: "recon",
    specialistModel: "recon_analyst",
    description: "Reconnaissance and target analysis LLM callers",
  },
  {
    callerPattern: "scan",
    specialistModel: "recon_analyst",
    description: "Scan result analysis callers",
  },
  {
    callerPattern: "exploit",
    specialistModel: "exploit_selector",
    description: "Exploit selection and generation callers",
  },
  {
    callerPattern: "vuln",
    specialistModel: "exploit_selector",
    description: "Vulnerability analysis callers",
  },
  {
    callerPattern: "evasion",
    specialistModel: "evasion_optimizer",
    description: "Evasion and stealth optimization callers",
  },
  {
    callerPattern: "ops",
    specialistModel: "evasion_optimizer",
    description: "OPSEC decision callers",
  },
  {
    callerPattern: "lateral",
    specialistModel: "lateral_planner",
    description: "Lateral movement planning callers",
  },
  {
    callerPattern: "pivot",
    specialistModel: "lateral_planner",
    description: "Network pivot planning callers",
  },
  {
    callerPattern: "persist",
    specialistModel: "persistence_engineer",
    description: "Persistence mechanism callers",
  },
  {
    callerPattern: "c2",
    specialistModel: "persistence_engineer",
    description: "C2 configuration callers",
  },
  {
    callerPattern: "orchestrat",
    specialistModel: "cognitive_core",
    description: "Engagement orchestration callers",
  },
  {
    callerPattern: "attack-planner",
    specialistModel: "cognitive_core",
    description: "Attack planning callers",
  },
  {
    callerPattern: "cockpit",
    specialistModel: "cognitive_core",
    description: "Operator cockpit AI callers",
  },
];

// ─── Tier → Lab Access Configuration ────────────────────────────────────────

const LAB_TIER_CONFIGS: LabTierConfig[] = [
  {
    tier: 4,
    accessLevel: "basic",
    allowedScenarioCategories: ["deployment", "c2_communication"],
    allowedDifficulties: ["beginner"],
    requiresMinExamples: 0,
    requiresMinBenchmarkScore: 0,
    unlockMessage: "Basic lab access: deployment and C2 communication tests",
  },
  {
    tier: 3,
    accessLevel: "operational",
    allowedScenarioCategories: ["deployment", "c2_communication", "operational", "training"],
    allowedDifficulties: ["beginner", "intermediate"],
    requiresMinExamples: 25,
    requiresMinBenchmarkScore: 40,
    unlockMessage: "Operational lab access: + recon, exploit selection, and training scenarios",
  },
  {
    tier: 2,
    accessLevel: "advanced",
    allowedScenarioCategories: ["deployment", "c2_communication", "operational", "stealth", "training", "graduation"],
    allowedDifficulties: ["beginner", "intermediate", "advanced"],
    requiresMinExamples: 100,
    requiresMinBenchmarkScore: 65,
    unlockMessage: "Advanced lab access: + stealth operations, lateral movement, swarm coordination",
  },
  {
    tier: 1,
    accessLevel: "full",
    allowedScenarioCategories: ["deployment", "c2_communication", "operational", "stealth", "training", "graduation"],
    allowedDifficulties: ["beginner", "intermediate", "advanced", "expert"],
    requiresMinExamples: 250,
    requiresMinBenchmarkScore: 80,
    unlockMessage: "Full lab access: all scenarios including exploit-to-implant and full red team",
  },
];

// ─── In-Memory State ────────────────────────────────────────────────────────

const modelStates = new Map<SpecialistModel, ModelGraduationState>();
const graduationEvents: LabGraduationEvent[] = [];

// Initialize model states
function initializeModelState(model: SpecialistModel): ModelGraduationState {
  const existing = modelStates.get(model);
  if (existing) return existing;

  const state: ModelGraduationState = {
    model,
    currentTier: 4,
    labAccessLevel: "basic",
    scenariosCompleted: 0,
    scenariosPassed: 0,
    scenariosFailed: 0,
    averageScore: 0,
    lastBenchmarkScore: 0,
    trainingExamples: 0,
    fineTuneRuns: 0,
    currentModelVersion: 1,
    events: [],
  };

  modelStates.set(model, state);
  return state;
}

// Initialize all models
const ALL_MODELS: SpecialistModel[] = [
  "recon_analyst",
  "exploit_selector",
  "evasion_optimizer",
  "lateral_planner",
  "persistence_engineer",
  "cognitive_core",
];

for (const model of ALL_MODELS) {
  initializeModelState(model);
}

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Map a graduation engine caller to a specialist model.
 */
export function mapCallerToModel(caller: string): SpecialistModel | null {
  const lowerCaller = caller.toLowerCase();
  for (const mapping of CALLER_MODEL_MAPPINGS) {
    if (lowerCaller.includes(mapping.callerPattern)) {
      return mapping.specialistModel;
    }
  }
  return null;
}

/**
 * Get the lab access level for a given graduation tier.
 */
export function getLabAccessForTier(tier: GraduationTier): LabTierConfig {
  return LAB_TIER_CONFIGS.find(c => c.tier === tier) || LAB_TIER_CONFIGS[0];
}

/**
 * Check if a model can access a specific scenario.
 */
export function canAccessScenario(
  model: SpecialistModel,
  scenarioCategory: string,
  scenarioDifficulty: string,
): { allowed: boolean; reason: string } {
  const state = modelStates.get(model);
  if (!state) return { allowed: false, reason: "Model not initialized" };

  const tierConfig = getLabAccessForTier(state.currentTier);

  if (!tierConfig.allowedScenarioCategories.includes(scenarioCategory)) {
    return {
      allowed: false,
      reason: `Scenario category "${scenarioCategory}" requires tier ${
        LAB_TIER_CONFIGS.find(c => c.allowedScenarioCategories.includes(scenarioCategory))?.tier || "unknown"
      } or higher. Current tier: ${state.currentTier}`,
    };
  }

  if (!tierConfig.allowedDifficulties.includes(scenarioDifficulty)) {
    return {
      allowed: false,
      reason: `Difficulty "${scenarioDifficulty}" requires tier ${
        LAB_TIER_CONFIGS.find(c => c.allowedDifficulties.includes(scenarioDifficulty))?.tier || "unknown"
      } or higher. Current tier: ${state.currentTier}`,
    };
  }

  if (state.trainingExamples < tierConfig.requiresMinExamples) {
    return {
      allowed: false,
      reason: `Requires ${tierConfig.requiresMinExamples} training examples. Current: ${state.trainingExamples}`,
    };
  }

  if (state.lastBenchmarkScore < tierConfig.requiresMinBenchmarkScore) {
    return {
      allowed: false,
      reason: `Requires benchmark score ≥${tierConfig.requiresMinBenchmarkScore}. Current: ${state.lastBenchmarkScore}`,
    };
  }

  return { allowed: true, reason: "Access granted" };
}

/**
 * Record a scenario completion and update model state.
 */
export function recordScenarioResult(params: {
  model: SpecialistModel;
  scenarioId: string;
  passed: boolean;
  score: number;
  maxScore: number;
}): LabGraduationEvent {
  const state = initializeModelState(params.model);

  state.scenariosCompleted++;
  if (params.passed) {
    state.scenariosPassed++;
  } else {
    state.scenariosFailed++;
  }

  // Update rolling average score
  const totalScores = state.averageScore * (state.scenariosCompleted - 1) + (params.score / params.maxScore * 100);
  state.averageScore = Math.round(totalScores / state.scenariosCompleted * 100) / 100;

  const event: LabGraduationEvent = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "scenario_completed",
    specialistModel: params.model,
    scenarioId: params.scenarioId,
    score: params.score,
    details: `Scenario ${params.scenarioId}: ${params.passed ? "PASSED" : "FAILED"} (${params.score}/${params.maxScore})`,
  };

  state.events.push(event);
  graduationEvents.push(event);

  // Check for tier advancement
  checkTierAdvancement(params.model);

  return event;
}

/**
 * Record a benchmark result and check for model promotion.
 */
export function recordBenchmarkResult(params: {
  model: SpecialistModel;
  benchmark: ModelBenchmark;
}): LabGraduationEvent {
  const state = initializeModelState(params.model);

  state.lastBenchmarkScore = params.benchmark.averageScore;
  state.lastBenchmarkDate = params.benchmark.benchmarkDate;

  const event: LabGraduationEvent = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "benchmark_passed",
    specialistModel: params.model,
    benchmarkId: params.benchmark.id,
    score: params.benchmark.averageScore,
    details: `Benchmark score: ${params.benchmark.averageScore}% (${params.benchmark.improvementOverBaseline > 0 ? "+" : ""}${params.benchmark.improvementOverBaseline}% vs baseline)`,
  };

  state.events.push(event);
  graduationEvents.push(event);

  // Check for tier advancement based on benchmark
  checkTierAdvancement(params.model);

  return event;
}

/**
 * Record training data collection event.
 */
export function recordTrainingData(
  model: SpecialistModel,
  examples: TrainingExample[],
): void {
  const state = initializeModelState(model);
  state.trainingExamples += examples.length;
}

/**
 * Record a fine-tuning completion.
 */
export function recordFineTuneCompletion(params: {
  model: SpecialistModel;
  success: boolean;
  newModelId?: string;
}): LabGraduationEvent {
  const state = initializeModelState(params.model);
  state.fineTuneRuns++;

  const eventType = params.success ? "training_completed" : "model_rollback";

  if (params.success && params.newModelId) {
    state.currentModelVersion++;
    state.lastPromotedAt = Date.now();
  }

  const event: LabGraduationEvent = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType,
    specialistModel: params.model,
    details: params.success
      ? `Fine-tune completed. New model: ${params.newModelId}. Version: ${state.currentModelVersion}`
      : `Fine-tune failed. Staying on version ${state.currentModelVersion}`,
  };

  state.events.push(event);
  graduationEvents.push(event);

  return event;
}

/**
 * Check if a model should advance to a higher tier.
 */
function checkTierAdvancement(model: SpecialistModel): void {
  const state = modelStates.get(model);
  if (!state) return;

  const previousTier = state.currentTier;

  // Evaluate against each tier's requirements (highest first)
  for (const config of [...LAB_TIER_CONFIGS].reverse()) {
    if (
      state.trainingExamples >= config.requiresMinExamples &&
      state.lastBenchmarkScore >= config.requiresMinBenchmarkScore &&
      state.scenariosPassed >= Math.ceil(config.requiresMinExamples * 0.1) // 10% of examples should be from passed scenarios
    ) {
      if (config.tier < state.currentTier) {
        state.currentTier = config.tier;
        state.labAccessLevel = config.accessLevel;

        const event: LabGraduationEvent = {
          id: `gle-${randomUUID().slice(0, 8)}`,
          timestamp: Date.now(),
          eventType: "tier_change",
          specialistModel: model,
          previousTier,
          newTier: config.tier,
          details: `${model} advanced from Tier ${previousTier} to Tier ${config.tier}: ${config.unlockMessage}`,
        };

        state.events.push(event);
        graduationEvents.push(event);
      }
      break;
    }
  }
}

/**
 * Manually set a model's tier (admin override).
 */
export function setModelTier(model: SpecialistModel, tier: GraduationTier): ModelGraduationState {
  const state = initializeModelState(model);
  const previousTier = state.currentTier;
  const config = getLabAccessForTier(tier);

  state.currentTier = tier;
  state.labAccessLevel = config.accessLevel;

  const event: LabGraduationEvent = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "tier_change",
    specialistModel: model,
    previousTier,
    newTier: tier,
    details: `Admin override: ${model} set to Tier ${tier} (was Tier ${previousTier})`,
  };

  state.events.push(event);
  graduationEvents.push(event);

  return state;
}

// ─── Feedback Loop: Lab → Graduation Engine ─────────────────────────────────

/**
 * Generate graduation engine feedback from lab performance.
 * This creates synthetic telemetry entries that the graduation engine
 * can use to assess specialist model readiness.
 */
export function generateGraduationFeedback(model: SpecialistModel): {
  caller: string;
  successRate: number;
  totalCalls: number;
  avgLatencyMs: number;
  suggestedTier: GraduationTier;
  recommendation: string;
} {
  const state = modelStates.get(model);
  if (!state) {
    return {
      caller: `ember-specialist:${model}`,
      successRate: 0,
      totalCalls: 0,
      avgLatencyMs: 0,
      suggestedTier: 4,
      recommendation: "Model not initialized. Start with basic lab scenarios.",
    };
  }

  const successRate = state.scenariosCompleted > 0
    ? (state.scenariosPassed / state.scenariosCompleted) * 100
    : 0;

  // Estimate latency from benchmark scores (higher score = better optimization = lower latency)
  const estimatedLatencyMs = Math.max(500, 10000 - (state.lastBenchmarkScore * 80));

  let recommendation: string;
  if (state.currentTier === 1) {
    recommendation = `${model} is ready for production. Consider graduating to deterministic logic where possible.`;
  } else if (state.currentTier === 2) {
    recommendation = `${model} is near graduation. Run ${250 - state.trainingExamples} more training examples and achieve benchmark score ≥80.`;
  } else if (state.currentTier === 3) {
    recommendation = `${model} is emerging. Focus on operational scenarios and collect more training data.`;
  } else {
    recommendation = `${model} is still training. Complete basic deployment and C2 scenarios first.`;
  }

  return {
    caller: `ember-specialist:${model}`,
    successRate: Math.round(successRate * 10) / 10,
    totalCalls: state.scenariosCompleted,
    avgLatencyMs: Math.round(estimatedLatencyMs),
    suggestedTier: state.currentTier,
    recommendation,
  };
}

/**
 * Get recommended next scenarios for a model based on its current tier and gaps.
 */
export function getRecommendedScenarios(model: SpecialistModel): {
  scenarioIds: string[];
  reason: string;
  priority: "high" | "medium" | "low";
}[] {
  const state = modelStates.get(model);
  if (!state) return [];

  const recommendations: { scenarioIds: string[]; reason: string; priority: "high" | "medium" | "low" }[] = [];

  const tierConfig = getLabAccessForTier(state.currentTier);

  // If no scenarios completed, recommend starting scenarios
  if (state.scenariosCompleted === 0) {
    recommendations.push({
      scenarioIds: ["sc-ember-deploy", "sc-c2-https-basic"],
      reason: "Start with basic deployment and C2 communication tests",
      priority: "high",
    });
  }

  // If low pass rate, recommend easier scenarios
  if (state.scenariosCompleted > 5 && state.averageScore < 50) {
    recommendations.push({
      scenarioIds: ["sc-ember-deploy", "sc-c2-multi-channel"],
      reason: "Low average score — practice with deployment and communication scenarios",
      priority: "high",
    });
  }

  // If ready for advancement, recommend scenarios from the next tier
  const nextTierConfig = LAB_TIER_CONFIGS.find(c => c.tier === state.currentTier - 1);
  if (nextTierConfig) {
    const newCategories = nextTierConfig.allowedScenarioCategories
      .filter(c => !tierConfig.allowedScenarioCategories.includes(c));

    if (newCategories.length > 0) {
      recommendations.push({
        scenarioIds: newCategories.map(c => `sc-${c}-intro`),
        reason: `Prepare for Tier ${state.currentTier - 1} by practicing ${newCategories.join(", ")} scenarios`,
        priority: "medium",
      });
    }
  }

  // If benchmark score is low, recommend training-focused scenarios
  if (state.lastBenchmarkScore < 60 && state.scenariosCompleted > 10) {
    recommendations.push({
      scenarioIds: ["sc-training-cognitive", "sc-training-specialist"],
      reason: "Benchmark score below threshold — run training scenarios to collect more data",
      priority: "high",
    });
  }

  // If enough examples but no fine-tune, recommend fine-tuning
  if (state.trainingExamples >= 50 && state.fineTuneRuns === 0) {
    recommendations.push({
      scenarioIds: [],
      reason: `${state.trainingExamples} training examples collected. Ready for first fine-tuning run.`,
      priority: "high",
    });
  }

  return recommendations;
}

// ─── Getters ────────────────────────────────────────────────────────────────

export function getModelGraduationState(model: SpecialistModel): ModelGraduationState | undefined {
  return modelStates.get(model);
}

export function getAllModelStates(): ModelGraduationState[] {
  return Array.from(modelStates.values());
}

export function getGraduationEvents(limit: number = 50): LabGraduationEvent[] {
  return graduationEvents.slice(-limit).reverse();
}

export function getGraduationLabSummary(): GraduationLabSummary {
  const models = getAllModelStates();

  const totalScenariosRun = models.reduce((s, m) => s + m.scenariosCompleted, 0);
  const totalTrainingExamples = models.reduce((s, m) => s + m.trainingExamples, 0);
  const totalFineTuneRuns = models.reduce((s, m) => s + m.fineTuneRuns, 0);

  const modelsAtTier1 = models.filter(m => m.currentTier === 1).length;
  const modelsAtTier2 = models.filter(m => m.currentTier === 2).length;
  const modelsAtTier3 = models.filter(m => m.currentTier === 3).length;
  const modelsAtTier4 = models.filter(m => m.currentTier === 4).length;

  // Overall readiness: weighted by tier
  const tierWeights = { 1: 100, 2: 75, 3: 50, 4: 25, 5: 0 };
  const totalWeight = models.reduce((s, m) => s + (tierWeights[m.currentTier] || 0), 0);
  const overallReadinessScore = models.length > 0 ? Math.round(totalWeight / models.length) : 0;

  // Determine next recommended action
  let nextRecommendedAction: string;
  if (modelsAtTier4 === models.length) {
    nextRecommendedAction = "All models at Tier 4. Start with basic deployment scenarios to begin training.";
  } else if (modelsAtTier1 >= 3) {
    nextRecommendedAction = "Multiple models ready for graduation. Consider deploying fine-tuned models to production.";
  } else if (totalTrainingExamples < 50) {
    nextRecommendedAction = "Collect more training data. Run operational and stealth scenarios.";
  } else if (totalFineTuneRuns === 0) {
    nextRecommendedAction = "Sufficient training data collected. Start first fine-tuning run.";
  } else {
    const lowestTierModel = models.reduce((a, b) => a.currentTier > b.currentTier ? a : b);
    nextRecommendedAction = `Focus on ${lowestTierModel.model} — currently at Tier ${lowestTierModel.currentTier}. ${
      getRecommendedScenarios(lowestTierModel.model)[0]?.reason || "Run more scenarios."
    }`;
  }

  return {
    models,
    totalScenariosRun,
    totalTrainingExamples,
    totalFineTuneRuns,
    modelsAtTier1,
    modelsAtTier2,
    modelsAtTier3,
    modelsAtTier4,
    overallReadinessScore,
    nextRecommendedAction,
  };
}

export function getCallerModelMappings(): CallerToModelMapping[] {
  return CALLER_MODEL_MAPPINGS;
}

export function getLabTierConfigs(): LabTierConfig[] {
  return LAB_TIER_CONFIGS;
}
