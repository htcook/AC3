import {
  init_llm,
  invokeLLM
} from "./chunk-NLTQ4N7G.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KDOLKO2A.js";
import "./chunk-KFQGP6VL.js";

// server/lib/c2-actor-feedback-loop.ts
init_llm();
var performanceStore = /* @__PURE__ */ new Map();
var feedbackEventLog = [];
var MAX_EVENTS = 5e3;
async function processActorFeedback(feedback, outcome, actorName, campaignContext) {
  const result = {
    performanceUpdated: false,
    novelVariationsFound: 0,
    artifactsDiscovered: 0,
    feedbackEvents: []
  };
  const actorPerf = performanceStore.get(actorName) || [];
  let techPerf = actorPerf.find((p) => p.techniqueId === feedback.techniqueId);
  if (!techPerf) {
    techPerf = {
      techniqueId: feedback.techniqueId,
      techniqueName: feedback.techniqueId,
      // Will be enriched
      actorName,
      emulationSuccessRate: 0,
      totalAttempts: 0,
      successCount: 0,
      successfulEnvironments: [],
      failedEnvironments: [],
      blockedByDefenses: [],
      evadedDefenses: [],
      discoveredArtifacts: [],
      novelVariations: [],
      lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
    };
    actorPerf.push(techPerf);
  }
  techPerf.totalAttempts++;
  if (outcome.success) {
    techPerf.successCount++;
  }
  techPerf.emulationSuccessRate = Math.round(techPerf.successCount / techPerf.totalAttempts * 100);
  techPerf.lastUpdated = (/* @__PURE__ */ new Date()).toISOString();
  const envProfile = {
    os: feedback.targetContext?.os || "unknown",
    platform: feedback.targetContext?.platform || "unknown",
    defenses: feedback.targetContext?.defenses || [],
    networkSegment: feedback.targetContext?.networkSegment,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
  if (outcome.success) {
    techPerf.successfulEnvironments.push(envProfile);
    for (const defense of envProfile.defenses) {
      if (!techPerf.evadedDefenses.includes(defense)) {
        techPerf.evadedDefenses.push(defense);
      }
    }
    const event = {
      type: "technique_success",
      actorName,
      techniqueId: feedback.techniqueId,
      data: { environment: envProfile, confidence: outcome.confidenceAdjustment },
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  } else {
    techPerf.failedEnvironments.push(envProfile);
    for (const defense of envProfile.defenses) {
      if (!techPerf.blockedByDefenses.includes(defense)) {
        techPerf.blockedByDefenses.push(defense);
      }
    }
    const event = {
      type: "technique_failure",
      actorName,
      techniqueId: feedback.techniqueId,
      data: { environment: envProfile, blockers: envProfile.defenses },
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  }
  for (const artifact of outcome.extractedArtifacts || []) {
    const discovered = {
      type: categorizeArtifact(artifact),
      value: artifact.value || JSON.stringify(artifact),
      context: artifact.context || `Discovered during ${feedback.techniqueId} execution`,
      discoveredAt: (/* @__PURE__ */ new Date()).toISOString(),
      feedbackApplied: false
    };
    techPerf.discoveredArtifacts.push(discovered);
    result.artifactsDiscovered++;
    if (discovered.type === "new_technique") {
      const event = {
        type: "new_artifact",
        actorName,
        techniqueId: feedback.techniqueId,
        data: discovered,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      feedbackEventLog.unshift(event);
      result.feedbackEvents.push(event);
    }
  }
  const novelVariations = await detectNovelVariations(feedback, outcome, actorName);
  for (const variation of novelVariations) {
    techPerf.novelVariations.push(variation);
    result.novelVariationsFound++;
    const event = {
      type: "novel_ttp",
      actorName,
      techniqueId: feedback.techniqueId,
      data: variation,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  }
  performanceStore.set(actorName, actorPerf);
  result.performanceUpdated = true;
  if (feedbackEventLog.length > MAX_EVENTS) {
    feedbackEventLog.length = MAX_EVENTS;
  }
  return result;
}
function categorizeArtifact(artifact) {
  const type = (artifact.type || "").toLowerCase();
  if (type.includes("ioc") || type.includes("hash") || type.includes("ip") || type.includes("domain")) return "ioc";
  if (type.includes("credential") || type.includes("password") || type.includes("token")) return "credential";
  if (type.includes("config") || type.includes("setting")) return "config";
  if (type.includes("technique") || type.includes("novel")) return "new_technique";
  return "tool_output";
}
async function detectNovelVariations(feedback, outcome, actorName) {
  if (!outcome.success) return [];
  const output = feedback.taskResult?.stdout || "";
  if (output.length < 50) return [];
  const novelLessons = (outcome.lessonsLearned || []).filter(
    (l) => l.toLowerCase().includes("novel") || l.toLowerCase().includes("unexpected") || l.toLowerCase().includes("new method") || l.toLowerCase().includes("variant")
  );
  if (novelLessons.length === 0 && (outcome.crossFrameworkNotes || []).length === 0) {
    return [];
  }
  try {
    const response = await invokeLLM({
      _caller: "c2-actor-feedback-loop.detectNovelVariations",
      messages: [
        {
          role: "system",
          content: `You are a threat intelligence analyst reviewing C2 execution output. Determine if the execution reveals a novel variation of the base technique. A "novel variation" is a new method, tool combination, or approach that differs from the standard execution of this MITRE technique. Return JSON with "variations" array, each with: description, differentiator, noveltyConfidence (0-100). Return empty array if nothing novel.`
        },
        {
          role: "user",
          content: `Base technique: ${feedback.techniqueId}
Actor: ${actorName}
Lessons: ${novelLessons.join("; ")}
Cross-framework notes: ${(outcome.crossFrameworkNotes || []).join("; ")}
Output excerpt: ${output.slice(0, 500)}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "novel_variations",
          strict: true,
          schema: {
            type: "object",
            properties: {
              variations: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    description: { type: "string" },
                    differentiator: { type: "string" },
                    noveltyConfidence: { type: "number" }
                  },
                  required: ["description", "differentiator", "noveltyConfidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["variations"],
            additionalProperties: false
          }
        }
      }
    });
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return (parsed.variations || []).filter((v) => v.noveltyConfidence > 30).map((v) => ({
      baseTechniqueId: feedback.techniqueId,
      description: v.description,
      differentiator: v.differentiator,
      noveltyConfidence: v.noveltyConfidence,
      sourceExecutionId: `exec-${Date.now()}`,
      fedBack: false
    }));
  } catch {
    return [];
  }
}
function buildActorLearningProfile(actorName) {
  const actorPerf = performanceStore.get(actorName);
  if (!actorPerf || actorPerf.length === 0) return null;
  const totalEmulations = actorPerf.reduce((sum, p) => sum + p.totalAttempts, 0);
  const totalSuccesses = actorPerf.reduce((sum, p) => sum + p.successCount, 0);
  const mostReliable = [...actorPerf].filter((p) => p.totalAttempts >= 2).sort((a, b) => b.emulationSuccessRate - a.emulationSuccessRate).slice(0, 10).map((p) => ({ techniqueId: p.techniqueId, successRate: p.emulationSuccessRate }));
  const unreliable = [...actorPerf].filter((p) => p.totalAttempts >= 2 && p.emulationSuccessRate < 50).sort((a, b) => a.emulationSuccessRate - b.emulationSuccessRate).slice(0, 10).map((p) => ({
    techniqueId: p.techniqueId,
    failureRate: 100 - p.emulationSuccessRate,
    commonBlocker: p.blockedByDefenses[0] || "Unknown"
  }));
  const defenseMap = /* @__PURE__ */ new Map();
  for (const perf of actorPerf) {
    for (const defense of perf.evadedDefenses) {
      const entry = defenseMap.get(defense) || { evaded: [], blocked: [] };
      entry.evaded.push(perf.techniqueId);
      defenseMap.set(defense, entry);
    }
    for (const defense of perf.blockedByDefenses) {
      const entry = defenseMap.get(defense) || { evaded: [], blocked: [] };
      entry.blocked.push(perf.techniqueId);
      defenseMap.set(defense, entry);
    }
  }
  const defenseEvasionProfile = Array.from(defenseMap.entries()).map(([defense, data]) => ({
    defense,
    evasionRate: data.evaded.length / (data.evaded.length + data.blocked.length) * 100,
    techniquesThatEvade: [...new Set(data.evaded)],
    techniquesThatFail: [...new Set(data.blocked)]
  }));
  const discoveredTTPs = actorPerf.flatMap((p) => p.novelVariations);
  const lastEmulation = actorPerf.map((p) => p.lastUpdated).sort().reverse()[0] || "Never";
  return {
    actorName,
    techniquePerformance: actorPerf,
    overallSuccessRate: totalEmulations > 0 ? Math.round(totalSuccesses / totalEmulations * 100) : 0,
    mostReliableTechniques: mostReliable,
    unreliableTechniques: unreliable,
    defenseEvasionProfile,
    discoveredTTPs,
    totalEmulations,
    lastEmulation
  };
}
function getFeedbackForSigmaRules(actorName) {
  const events = actorName ? feedbackEventLog.filter((e) => e.actorName === actorName) : feedbackEventLog;
  const successfulTechniques = events.filter((e) => e.type === "technique_success").map((e) => ({
    techniqueId: e.techniqueId,
    environments: [e.data.environment]
  }));
  const failedTechniques = events.filter((e) => e.type === "technique_failure").map((e) => ({
    techniqueId: e.techniqueId,
    blockers: e.data.blockers || []
  }));
  const novelVariations = events.filter((e) => e.type === "novel_ttp").map((e) => e.data);
  return {
    successfulTechniques,
    failedTechniques,
    novelVariations,
    telemetrySignals: events.filter((e) => e.type === "new_artifact").map((e) => e.data)
  };
}
function getFeedbackForCampaignAdvisor(actorName) {
  const profile = buildActorLearningProfile(actorName);
  if (!profile) {
    return { recommendedTechniques: [], avoidTechniques: [], environmentalInsights: [] };
  }
  const recommended = profile.mostReliableTechniques.map((t) => ({
    techniqueId: t.techniqueId,
    successRate: t.successRate,
    reason: `${t.successRate}% success rate in emulations`
  }));
  const avoid = profile.unreliableTechniques.map((t) => ({
    techniqueId: t.techniqueId,
    failureRate: t.failureRate,
    reason: `${t.failureRate}% failure rate, commonly blocked by ${t.commonBlocker}`
  }));
  const environmentalInsights = profile.defenseEvasionProfile.map(
    (d) => `${d.defense}: ${Math.round(d.evasionRate)}% evasion rate (${d.techniquesThatEvade.length} techniques evade, ${d.techniquesThatFail.length} blocked)`
  );
  return { recommendedTechniques: recommended, avoidTechniques: avoid, environmentalInsights };
}
function getFeedbackForSequenceEngine(actorName) {
  const events = actorName ? feedbackEventLog.filter((e) => e.actorName === actorName) : feedbackEventLog;
  const executionOrders = events.filter((e) => e.type === "technique_success" || e.type === "technique_failure").map((e, i) => ({
    techniqueId: e.techniqueId,
    position: i,
    success: e.type === "technique_success",
    timestamp: e.timestamp
  }));
  const chainBreaks = [];
  for (let i = 0; i < executionOrders.length - 1; i++) {
    if (!executionOrders[i].success) {
      chainBreaks.push({
        fromTechnique: executionOrders[i].techniqueId,
        toTechnique: executionOrders[i + 1]?.techniqueId || "end",
        reason: "Technique failure interrupted sequence"
      });
    }
  }
  return { executionOrders, chainBreaks };
}
function getProfiledActors() {
  return Array.from(performanceStore.keys());
}
function getRecentFeedbackEvents(limit = 50, actorName) {
  const events = actorName ? feedbackEventLog.filter((e) => e.actorName === actorName) : feedbackEventLog;
  return events.slice(0, limit);
}
function getFeedbackLoopStats() {
  let totalNovel = 0;
  let totalArtifacts = 0;
  let totalSuccess = 0;
  let totalAttempts = 0;
  const actorRates = [];
  for (const [actorName, perfs] of performanceStore) {
    let actorTotal = 0;
    let actorSuccess = 0;
    for (const perf of perfs) {
      totalNovel += perf.novelVariations.length;
      totalArtifacts += perf.discoveredArtifacts.length;
      totalSuccess += perf.successCount;
      totalAttempts += perf.totalAttempts;
      actorTotal += perf.totalAttempts;
      actorSuccess += perf.successCount;
    }
    if (actorTotal > 0) {
      actorRates.push({ name: actorName, successRate: Math.round(actorSuccess / actorTotal * 100) });
    }
  }
  actorRates.sort((a, b) => b.successRate - a.successRate);
  const oneDayAgo = new Date(Date.now() - 864e5).toISOString();
  const recentEvents = feedbackEventLog.filter((e) => e.timestamp > oneDayAgo).length;
  return {
    totalFeedbackEvents: feedbackEventLog.length,
    actorsProfiled: performanceStore.size,
    totalNovelVariations: totalNovel,
    totalArtifactsDiscovered: totalArtifacts,
    avgSuccessRate: totalAttempts > 0 ? Math.round(totalSuccess / totalAttempts * 100) : 0,
    topPerformingActors: actorRates.slice(0, 5),
    recentEvents
  };
}
export {
  buildActorLearningProfile,
  getFeedbackForCampaignAdvisor,
  getFeedbackForSequenceEngine,
  getFeedbackForSigmaRules,
  getFeedbackLoopStats,
  getProfiledActors,
  getRecentFeedbackEvents,
  processActorFeedback
};
