import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/scanforge/engine/exploit-reasoning-narratives.ts
function startReasoningScenario(engagementId, scenario) {
  const newScenario = {
    ...scenario,
    steps: [],
    outcome: "in_progress",
    success: false,
    startedAt: Date.now()
  };
  if (!_narrativeStore.has(engagementId)) {
    _narrativeStore.set(engagementId, []);
  }
  _narrativeStore.get(engagementId).push(newScenario);
  return newScenario;
}
function addReasoningStep(engagementId, scenarioId, step) {
  const scenarios = _narrativeStore.get(engagementId);
  if (!scenarios) return;
  const scenario = scenarios.find((s) => s.id === scenarioId);
  if (!scenario) return;
  scenario.steps.push({
    ...step,
    stepNumber: scenario.steps.length + 1,
    timestamp: Date.now()
  });
}
function completeReasoningScenario(engagementId, scenarioId, outcome, success) {
  const scenarios = _narrativeStore.get(engagementId);
  if (!scenarios) return;
  const scenario = scenarios.find((s) => s.id === scenarioId);
  if (!scenario) return;
  scenario.outcome = outcome;
  scenario.success = success;
  scenario.completedAt = Date.now();
}
function getReasoningSummary(engagementId) {
  const scenarios = _narrativeStore.get(engagementId);
  if (!scenarios || scenarios.length === 0) return null;
  const totalSteps = scenarios.reduce((sum, s) => sum + s.steps.length, 0);
  const successfulScenarios = scenarios.filter((s) => s.success).length;
  const allConfidences = scenarios.flatMap((s) => s.steps.filter((st) => st.confidence != null).map((st) => st.confidence));
  const avgConfidence = allConfidences.length > 0 ? allConfidences.reduce((a, b) => a + b, 0) / allConfidences.length : 0;
  const totalDurationMs = scenarios.reduce((sum, s) => {
    if (s.completedAt && s.startedAt) return sum + (s.completedAt - s.startedAt);
    return sum;
  }, 0);
  return {
    engagementId,
    scenarios,
    totalSteps,
    stats: {
      totalScenarios: scenarios.length,
      successfulScenarios,
      failedScenarios: scenarios.length - successfulScenarios,
      avgStepsPerScenario: scenarios.length > 0 ? Math.round(totalSteps / scenarios.length) : 0,
      avgConfidence: Math.round(avgConfidence),
      totalDurationMs
    }
  };
}
var _narrativeStore;
var init_exploit_reasoning_narratives = __esm({
  "server/scanforge/engine/exploit-reasoning-narratives.ts"() {
    "use strict";
    _narrativeStore = /* @__PURE__ */ new Map();
  }
});

export {
  startReasoningScenario,
  addReasoningStep,
  completeReasoningScenario,
  getReasoningSummary,
  init_exploit_reasoning_narratives
};
