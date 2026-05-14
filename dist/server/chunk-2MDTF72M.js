import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/graduation-lab-bridge.ts
import { randomUUID } from "crypto";
function initializeModelState(model) {
  const existing = modelStates.get(model);
  if (existing) return existing;
  const state = {
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
    events: []
  };
  modelStates.set(model, state);
  return state;
}
function mapCallerToModel(caller) {
  const lowerCaller = caller.toLowerCase();
  for (const mapping of CALLER_MODEL_MAPPINGS) {
    if (lowerCaller.includes(mapping.callerPattern)) {
      return mapping.specialistModel;
    }
  }
  return null;
}
function getLabAccessForTier(tier) {
  return LAB_TIER_CONFIGS.find((c) => c.tier === tier) || LAB_TIER_CONFIGS[0];
}
function canAccessScenario(model, scenarioCategory, scenarioDifficulty) {
  const state = modelStates.get(model);
  if (!state) return { allowed: false, reason: "Model not initialized" };
  const tierConfig = getLabAccessForTier(state.currentTier);
  if (!tierConfig.allowedScenarioCategories.includes(scenarioCategory)) {
    return {
      allowed: false,
      reason: `Scenario category "${scenarioCategory}" requires tier ${LAB_TIER_CONFIGS.find((c) => c.allowedScenarioCategories.includes(scenarioCategory))?.tier || "unknown"} or higher. Current tier: ${state.currentTier}`
    };
  }
  if (!tierConfig.allowedDifficulties.includes(scenarioDifficulty)) {
    return {
      allowed: false,
      reason: `Difficulty "${scenarioDifficulty}" requires tier ${LAB_TIER_CONFIGS.find((c) => c.allowedDifficulties.includes(scenarioDifficulty))?.tier || "unknown"} or higher. Current tier: ${state.currentTier}`
    };
  }
  if (state.trainingExamples < tierConfig.requiresMinExamples) {
    return {
      allowed: false,
      reason: `Requires ${tierConfig.requiresMinExamples} training examples. Current: ${state.trainingExamples}`
    };
  }
  if (state.lastBenchmarkScore < tierConfig.requiresMinBenchmarkScore) {
    return {
      allowed: false,
      reason: `Requires benchmark score \u2265${tierConfig.requiresMinBenchmarkScore}. Current: ${state.lastBenchmarkScore}`
    };
  }
  return { allowed: true, reason: "Access granted" };
}
function recordScenarioResult(params) {
  const state = initializeModelState(params.model);
  state.scenariosCompleted++;
  if (params.passed) {
    state.scenariosPassed++;
  } else {
    state.scenariosFailed++;
  }
  const totalScores = state.averageScore * (state.scenariosCompleted - 1) + params.score / params.maxScore * 100;
  state.averageScore = Math.round(totalScores / state.scenariosCompleted * 100) / 100;
  const event = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "scenario_completed",
    specialistModel: params.model,
    scenarioId: params.scenarioId,
    score: params.score,
    details: `Scenario ${params.scenarioId}: ${params.passed ? "PASSED" : "FAILED"} (${params.score}/${params.maxScore})`
  };
  state.events.push(event);
  graduationEvents.push(event);
  checkTierAdvancement(params.model);
  return event;
}
function recordBenchmarkResult(params) {
  const state = initializeModelState(params.model);
  state.lastBenchmarkScore = params.benchmark.averageScore;
  state.lastBenchmarkDate = params.benchmark.benchmarkDate;
  const event = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "benchmark_passed",
    specialistModel: params.model,
    benchmarkId: params.benchmark.id,
    score: params.benchmark.averageScore,
    details: `Benchmark score: ${params.benchmark.averageScore}% (${params.benchmark.improvementOverBaseline > 0 ? "+" : ""}${params.benchmark.improvementOverBaseline}% vs baseline)`
  };
  state.events.push(event);
  graduationEvents.push(event);
  checkTierAdvancement(params.model);
  return event;
}
function recordTrainingData(model, examples) {
  const state = initializeModelState(model);
  state.trainingExamples += examples.length;
}
function recordFineTuneCompletion(params) {
  const state = initializeModelState(params.model);
  state.fineTuneRuns++;
  const eventType = params.success ? "training_completed" : "model_rollback";
  if (params.success && params.newModelId) {
    state.currentModelVersion++;
    state.lastPromotedAt = Date.now();
  }
  const event = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType,
    specialistModel: params.model,
    details: params.success ? `Fine-tune completed. New model: ${params.newModelId}. Version: ${state.currentModelVersion}` : `Fine-tune failed. Staying on version ${state.currentModelVersion}`
  };
  state.events.push(event);
  graduationEvents.push(event);
  return event;
}
function checkTierAdvancement(model) {
  const state = modelStates.get(model);
  if (!state) return;
  const previousTier = state.currentTier;
  for (const config of [...LAB_TIER_CONFIGS].reverse()) {
    if (state.trainingExamples >= config.requiresMinExamples && state.lastBenchmarkScore >= config.requiresMinBenchmarkScore && state.scenariosPassed >= Math.ceil(config.requiresMinExamples * 0.1)) {
      if (config.tier < state.currentTier) {
        const requiredApprovals = config.tier <= 2 ? 2 : 1;
        const promotionId = `promo-${randomUUID().slice(0, 8)}`;
        const promotion = {
          promotionId,
          model,
          fromTier: previousTier,
          toTier: config.tier,
          requestedAt: Date.now(),
          requestedBy: "system:checkTierAdvancement",
          approvals: [],
          requiredApprovals,
          status: "pending",
          expiresAt: Date.now() + PROMOTION_EXPIRY_MS
        };
        pendingPromotions.push(promotion);
        const event = {
          id: `gle-${randomUUID().slice(0, 8)}`,
          timestamp: Date.now(),
          eventType: "tier_change",
          specialistModel: model,
          previousTier,
          newTier: config.tier,
          details: `${model} qualifies for Tier ${previousTier} \u2192 Tier ${config.tier} \u2014 PENDING ${requiredApprovals}-person approval (promotion: ${promotionId})`
        };
        state.events.push(event);
        graduationEvents.push(event);
        console.log(`[GraduationLab] Promotion ${promotionId}: ${model} Tier ${previousTier} \u2192 ${config.tier} \u2014 requires ${requiredApprovals} approvals`);
      }
      break;
    }
  }
}
function setModelTier(model, tier, operatorId = "admin") {
  const state = initializeModelState(model);
  const previousTier = state.currentTier;
  if (tier >= previousTier) {
    const config = getLabAccessForTier(tier);
    state.currentTier = tier;
    state.labAccessLevel = config.accessLevel;
    const event2 = {
      id: `gle-${randomUUID().slice(0, 8)}`,
      timestamp: Date.now(),
      eventType: tier > previousTier ? "model_rollback" : "tier_change",
      specialistModel: model,
      previousTier,
      newTier: tier,
      details: `Admin override (${operatorId}): ${model} set to Tier ${tier} (was Tier ${previousTier})`
    };
    state.events.push(event2);
    graduationEvents.push(event2);
    return state;
  }
  const requiredApprovals = tier <= 2 ? 2 : 1;
  const promotionId = `promo-${randomUUID().slice(0, 8)}`;
  const promotion = {
    promotionId,
    model,
    fromTier: previousTier,
    toTier: tier,
    requestedAt: Date.now(),
    requestedBy: `admin:${operatorId}`,
    approvals: [],
    requiredApprovals,
    status: "pending",
    expiresAt: Date.now() + PROMOTION_EXPIRY_MS
  };
  pendingPromotions.push(promotion);
  const event = {
    id: `gle-${randomUUID().slice(0, 8)}`,
    timestamp: Date.now(),
    eventType: "tier_change",
    specialistModel: model,
    previousTier,
    newTier: tier,
    details: `Admin override (${operatorId}): ${model} Tier ${previousTier} \u2192 ${tier} \u2014 PENDING ${requiredApprovals}-person approval (promotion: ${promotionId})`
  };
  state.events.push(event);
  graduationEvents.push(event);
  return { pendingPromotionId: promotionId, message: `Promotion requires ${requiredApprovals} approvals. ID: ${promotionId}` };
}
function generateGraduationFeedback(model) {
  const state = modelStates.get(model);
  if (!state) {
    return {
      caller: `ember-specialist:${model}`,
      successRate: 0,
      totalCalls: 0,
      avgLatencyMs: 0,
      suggestedTier: 4,
      recommendation: "Model not initialized. Start with basic lab scenarios."
    };
  }
  const successRate = state.scenariosCompleted > 0 ? state.scenariosPassed / state.scenariosCompleted * 100 : 0;
  const estimatedLatencyMs = Math.max(500, 1e4 - state.lastBenchmarkScore * 80);
  let recommendation;
  if (state.currentTier === 1) {
    recommendation = `${model} is ready for production. Consider graduating to deterministic logic where possible.`;
  } else if (state.currentTier === 2) {
    recommendation = `${model} is near graduation. Run ${250 - state.trainingExamples} more training examples and achieve benchmark score \u226580.`;
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
    recommendation
  };
}
function getRecommendedScenarios(model) {
  const state = modelStates.get(model);
  if (!state) return [];
  const recommendations = [];
  const tierConfig = getLabAccessForTier(state.currentTier);
  if (state.scenariosCompleted === 0) {
    recommendations.push({
      scenarioIds: ["sc-ember-deploy", "sc-c2-https-basic"],
      reason: "Start with basic deployment and C2 communication tests",
      priority: "high"
    });
  }
  if (state.scenariosCompleted > 5 && state.averageScore < 50) {
    recommendations.push({
      scenarioIds: ["sc-ember-deploy", "sc-c2-multi-channel"],
      reason: "Low average score \u2014 practice with deployment and communication scenarios",
      priority: "high"
    });
  }
  const nextTierConfig = LAB_TIER_CONFIGS.find((c) => c.tier === state.currentTier - 1);
  if (nextTierConfig) {
    const newCategories = nextTierConfig.allowedScenarioCategories.filter((c) => !tierConfig.allowedScenarioCategories.includes(c));
    if (newCategories.length > 0) {
      recommendations.push({
        scenarioIds: newCategories.map((c) => `sc-${c}-intro`),
        reason: `Prepare for Tier ${state.currentTier - 1} by practicing ${newCategories.join(", ")} scenarios`,
        priority: "medium"
      });
    }
  }
  if (state.lastBenchmarkScore < 60 && state.scenariosCompleted > 10) {
    recommendations.push({
      scenarioIds: ["sc-training-cognitive", "sc-training-specialist"],
      reason: "Benchmark score below threshold \u2014 run training scenarios to collect more data",
      priority: "high"
    });
  }
  if (state.trainingExamples >= 50 && state.fineTuneRuns === 0) {
    recommendations.push({
      scenarioIds: [],
      reason: `${state.trainingExamples} training examples collected. Ready for first fine-tuning run.`,
      priority: "high"
    });
  }
  return recommendations;
}
function getModelGraduationState(model) {
  return modelStates.get(model);
}
function getAllModelStates() {
  return Array.from(modelStates.values());
}
function getGraduationEvents(limit = 50) {
  return graduationEvents.slice(-limit).reverse();
}
function getGraduationLabSummary() {
  const models = getAllModelStates();
  const totalScenariosRun = models.reduce((s, m) => s + m.scenariosCompleted, 0);
  const totalTrainingExamples = models.reduce((s, m) => s + m.trainingExamples, 0);
  const totalFineTuneRuns = models.reduce((s, m) => s + m.fineTuneRuns, 0);
  const modelsAtTier1 = models.filter((m) => m.currentTier === 1).length;
  const modelsAtTier2 = models.filter((m) => m.currentTier === 2).length;
  const modelsAtTier3 = models.filter((m) => m.currentTier === 3).length;
  const modelsAtTier4 = models.filter((m) => m.currentTier === 4).length;
  const tierWeights = { 1: 100, 2: 75, 3: 50, 4: 25, 5: 0 };
  const totalWeight = models.reduce((s, m) => s + (tierWeights[m.currentTier] || 0), 0);
  const overallReadinessScore = models.length > 0 ? Math.round(totalWeight / models.length) : 0;
  let nextRecommendedAction;
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
    nextRecommendedAction = `Focus on ${lowestTierModel.model} \u2014 currently at Tier ${lowestTierModel.currentTier}. ${getRecommendedScenarios(lowestTierModel.model)[0]?.reason || "Run more scenarios."}`;
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
    nextRecommendedAction
  };
}
function getCallerModelMappings() {
  return CALLER_MODEL_MAPPINGS;
}
function getLabTierConfigs() {
  return LAB_TIER_CONFIGS;
}
function approvePromotion(promotionId, operatorId, comment) {
  const promotion = pendingPromotions.find((p) => p.promotionId === promotionId);
  if (!promotion) {
    return { success: false, promotion: null, message: `Promotion ${promotionId} not found` };
  }
  if (Date.now() > promotion.expiresAt) {
    promotion.status = "expired";
    return { success: false, promotion, message: `Promotion ${promotionId} has expired` };
  }
  if (promotion.status !== "pending") {
    return { success: false, promotion, message: `Promotion ${promotionId} is already ${promotion.status}` };
  }
  if (promotion.requestedBy === `admin:${operatorId}`) {
    return { success: false, promotion, message: `Operator ${operatorId} cannot approve their own promotion request` };
  }
  if (promotion.approvals.some((a) => a.operator === operatorId)) {
    return { success: false, promotion, message: `Operator ${operatorId} has already approved this promotion` };
  }
  promotion.approvals.push({
    operator: operatorId,
    approvedAt: Date.now(),
    comment
  });
  if (promotion.approvals.length >= promotion.requiredApprovals) {
    promotion.status = "approved";
    const state = initializeModelState(promotion.model);
    const config = getLabAccessForTier(promotion.toTier);
    state.currentTier = promotion.toTier;
    state.labAccessLevel = config.accessLevel;
    state.lastPromotedAt = Date.now();
    const event = {
      id: `gle-${randomUUID().slice(0, 8)}`,
      timestamp: Date.now(),
      eventType: "model_promoted",
      specialistModel: promotion.model,
      previousTier: promotion.fromTier,
      newTier: promotion.toTier,
      details: `${promotion.model} PROMOTED Tier ${promotion.fromTier} \u2192 ${promotion.toTier} \u2014 approved by: ${promotion.approvals.map((a) => a.operator).join(", ")}`
    };
    state.events.push(event);
    graduationEvents.push(event);
    logPromotionToEvidenceChain(promotion).catch(() => {
    });
    console.log(`[GraduationLab] Promotion ${promotionId} APPROVED: ${promotion.model} \u2192 Tier ${promotion.toTier} (${promotion.approvals.length}/${promotion.requiredApprovals} approvals)`);
    return { success: true, promotion, message: `Promotion approved and executed. ${promotion.model} is now Tier ${promotion.toTier}.` };
  }
  console.log(`[GraduationLab] Promotion ${promotionId}: approval ${promotion.approvals.length}/${promotion.requiredApprovals} by ${operatorId}`);
  return { success: true, promotion, message: `Approval recorded (${promotion.approvals.length}/${promotion.requiredApprovals}). Waiting for additional approvals.` };
}
function rejectPromotion(promotionId, operatorId, reason) {
  const promotion = pendingPromotions.find((p) => p.promotionId === promotionId);
  if (!promotion) {
    return { success: false, promotion: null, message: `Promotion ${promotionId} not found` };
  }
  if (promotion.status !== "pending") {
    return { success: false, promotion, message: `Promotion ${promotionId} is already ${promotion.status}` };
  }
  promotion.status = "rejected";
  promotion.rejectedBy = operatorId;
  promotion.rejectionReason = reason;
  const state = modelStates.get(promotion.model);
  if (state) {
    const event = {
      id: `gle-${randomUUID().slice(0, 8)}`,
      timestamp: Date.now(),
      eventType: "model_rollback",
      specialistModel: promotion.model,
      previousTier: promotion.fromTier,
      newTier: promotion.fromTier,
      details: `Promotion ${promotionId} REJECTED by ${operatorId}: ${reason}`
    };
    state.events.push(event);
    graduationEvents.push(event);
  }
  console.log(`[GraduationLab] Promotion ${promotionId} REJECTED by ${operatorId}: ${reason}`);
  return { success: true, promotion, message: `Promotion rejected.` };
}
function getPendingPromotions(status) {
  const now = Date.now();
  for (const p of pendingPromotions) {
    if (p.status === "pending" && now > p.expiresAt) {
      p.status = "expired";
    }
  }
  if (status) {
    return pendingPromotions.filter((p) => p.status === status);
  }
  return [...pendingPromotions];
}
async function logPromotionToEvidenceChain(promotion) {
  try {
    const { hashAndChainEvidence } = await import("./evidence-integrity-T673CCIH.js");
    const evidenceContent = JSON.stringify({
      type: "graduation_promotion",
      promotionId: promotion.promotionId,
      model: promotion.model,
      fromTier: promotion.fromTier,
      toTier: promotion.toTier,
      requestedBy: promotion.requestedBy,
      requestedAt: promotion.requestedAt,
      approvals: promotion.approvals,
      approvedAt: Date.now()
    });
    const systemEngagementId = "system:graduation-events";
    const evidenceId = `graduation-${promotion.promotionId}`;
    await hashAndChainEvidence(
      evidenceId,
      systemEngagementId,
      evidenceContent,
      { filename: `promotion-${promotion.promotionId}.json`, mimeType: "application/json" }
    );
    console.log(`[GraduationLab] Promotion ${promotion.promotionId} logged to evidence integrity chain`);
  } catch (err) {
    console.error(`[GraduationLab] Failed to log promotion to evidence chain:`, err);
  }
}
async function logGraduationEventToEvidenceChain(event) {
  try {
    const { hashAndChainEvidence } = await import("./evidence-integrity-T673CCIH.js");
    const evidenceContent = JSON.stringify({
      type: "graduation_event",
      eventId: event.id,
      eventType: event.eventType,
      model: event.specialistModel,
      previousTier: event.previousTier,
      newTier: event.newTier,
      details: event.details,
      timestamp: event.timestamp
    });
    const systemEngagementId = "system:graduation-events";
    const evidenceId = `graduation-event-${event.id}`;
    await hashAndChainEvidence(
      evidenceId,
      systemEngagementId,
      evidenceContent,
      { filename: `graduation-event-${event.id}.json`, mimeType: "application/json" }
    );
  } catch (err) {
    console.error(`[GraduationLab] Failed to log event to evidence chain:`, err);
  }
}
var CALLER_MODEL_MAPPINGS, LAB_TIER_CONFIGS, modelStates, graduationEvents, pendingPromotions, PROMOTION_EXPIRY_MS, ALL_MODELS;
var init_graduation_lab_bridge = __esm({
  "server/lib/graduation-lab-bridge.ts"() {
    CALLER_MODEL_MAPPINGS = [
      {
        callerPattern: "recon",
        specialistModel: "recon_analyst",
        description: "Reconnaissance and target analysis LLM callers"
      },
      {
        callerPattern: "scan",
        specialistModel: "recon_analyst",
        description: "Scan result analysis callers"
      },
      {
        callerPattern: "exploit",
        specialistModel: "exploit_selector",
        description: "Exploit selection and generation callers"
      },
      {
        callerPattern: "vuln",
        specialistModel: "exploit_selector",
        description: "Vulnerability analysis callers"
      },
      {
        callerPattern: "evasion",
        specialistModel: "evasion_optimizer",
        description: "Evasion and stealth optimization callers"
      },
      {
        callerPattern: "ops",
        specialistModel: "evasion_optimizer",
        description: "OPSEC decision callers"
      },
      {
        callerPattern: "lateral",
        specialistModel: "lateral_planner",
        description: "Lateral movement planning callers"
      },
      {
        callerPattern: "pivot",
        specialistModel: "lateral_planner",
        description: "Network pivot planning callers"
      },
      {
        callerPattern: "persist",
        specialistModel: "persistence_engineer",
        description: "Persistence mechanism callers"
      },
      {
        callerPattern: "c2",
        specialistModel: "persistence_engineer",
        description: "C2 configuration callers"
      },
      {
        callerPattern: "orchestrat",
        specialistModel: "cognitive_core",
        description: "Engagement orchestration callers"
      },
      {
        callerPattern: "attack-planner",
        specialistModel: "cognitive_core",
        description: "Attack planning callers"
      },
      {
        callerPattern: "cockpit",
        specialistModel: "cognitive_core",
        description: "Operator cockpit AI callers"
      }
    ];
    LAB_TIER_CONFIGS = [
      {
        tier: 4,
        accessLevel: "basic",
        allowedScenarioCategories: ["deployment", "c2_communication"],
        allowedDifficulties: ["beginner"],
        requiresMinExamples: 0,
        requiresMinBenchmarkScore: 0,
        unlockMessage: "Basic lab access: deployment and C2 communication tests"
      },
      {
        tier: 3,
        accessLevel: "operational",
        allowedScenarioCategories: ["deployment", "c2_communication", "operational", "training"],
        allowedDifficulties: ["beginner", "intermediate"],
        requiresMinExamples: 25,
        requiresMinBenchmarkScore: 40,
        unlockMessage: "Operational lab access: + recon, exploit selection, and training scenarios"
      },
      {
        tier: 2,
        accessLevel: "advanced",
        allowedScenarioCategories: ["deployment", "c2_communication", "operational", "stealth", "training", "graduation"],
        allowedDifficulties: ["beginner", "intermediate", "advanced"],
        requiresMinExamples: 100,
        requiresMinBenchmarkScore: 65,
        unlockMessage: "Advanced lab access: + stealth operations, lateral movement, swarm coordination"
      },
      {
        tier: 1,
        accessLevel: "full",
        allowedScenarioCategories: ["deployment", "c2_communication", "operational", "stealth", "training", "graduation"],
        allowedDifficulties: ["beginner", "intermediate", "advanced", "expert"],
        requiresMinExamples: 250,
        requiresMinBenchmarkScore: 80,
        unlockMessage: "Full lab access: all scenarios including exploit-to-implant and full red team"
      }
    ];
    modelStates = /* @__PURE__ */ new Map();
    graduationEvents = [];
    pendingPromotions = [];
    PROMOTION_EXPIRY_MS = 72 * 60 * 60 * 1e3;
    ALL_MODELS = [
      "recon_analyst",
      "exploit_selector",
      "evasion_optimizer",
      "lateral_planner",
      "persistence_engineer",
      "cognitive_core"
    ];
    for (const model of ALL_MODELS) {
      initializeModelState(model);
    }
  }
});

export {
  mapCallerToModel,
  getLabAccessForTier,
  canAccessScenario,
  recordScenarioResult,
  recordBenchmarkResult,
  recordTrainingData,
  recordFineTuneCompletion,
  setModelTier,
  generateGraduationFeedback,
  getRecommendedScenarios,
  getModelGraduationState,
  getAllModelStates,
  getGraduationEvents,
  getGraduationLabSummary,
  getCallerModelMappings,
  getLabTierConfigs,
  approvePromotion,
  rejectPromotion,
  getPendingPromotions,
  logGraduationEventToEvidenceChain,
  init_graduation_lab_bridge
};
