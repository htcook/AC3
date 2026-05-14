import {
  init_llm,
  invokeLLM
} from "./chunk-L5VXSJ4F.js";
import {
  getDb,
  init_db
} from "./chunk-JZVHFV6D.js";
import {
  init_schema,
  ttpKnowledge
} from "./chunk-IG2G4XDA.js";

// server/lib/c2-learning-engine.ts
init_db();
init_schema();
init_llm();
import { eq } from "drizzle-orm";
var executionHistory = [];
var MAX_HISTORY = 1e4;
async function processExecutionFeedback(feedback) {
  const outcome = await analyzeExecution(feedback);
  await updateTtpKnowledge(feedback.techniqueId, outcome);
  const record = {
    id: `exec-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    feedback,
    outcome,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
  executionHistory.unshift(record);
  if (executionHistory.length > MAX_HISTORY) {
    executionHistory.length = MAX_HISTORY;
  }
  return outcome;
}
async function analyzeExecution(feedback) {
  const { techniqueId, framework, taskResult, targetContext } = feedback;
  const success = taskResult.status === "success" && taskResult.exitCode === 0;
  const outcome = {
    techniqueId,
    framework,
    success,
    confidenceAdjustment: 0,
    newConstraints: [],
    observedTelemetry: [],
    extractedArtifacts: [],
    lessonsLearned: [],
    crossFrameworkNotes: [],
    analyzedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
  outcome.confidenceAdjustment = calculateConfidenceAdjustment(success, targetContext, feedback);
  outcome.extractedArtifacts = extractArtifactsFromOutput(
    taskResult.stdout + "\n" + taskResult.stderr,
    framework
  );
  outcome.newConstraints = deriveConstraints(feedback, success);
  const outputLength = (taskResult.stdout + taskResult.stderr).length;
  if (outputLength > 50 && outputLength < 1e4) {
    try {
      const llmAnalysis = await llmAnalyzeExecution(feedback, success);
      if (llmAnalysis) {
        outcome.observedTelemetry.push(...llmAnalysis.telemetry);
        outcome.lessonsLearned.push(...llmAnalysis.lessons);
        outcome.crossFrameworkNotes.push(...llmAnalysis.crossFramework);
        outcome.extractedArtifacts.push(...llmAnalysis.additionalArtifacts);
      }
    } catch {
      outcome.lessonsLearned.push(
        success ? `Technique ${techniqueId} succeeded on ${targetContext.platform} via ${framework}` : `Technique ${techniqueId} failed on ${targetContext.platform} via ${framework}: ${taskResult.stderr.slice(0, 200)}`
      );
    }
  }
  const historicalData = getHistoryForTechnique(techniqueId);
  if (historicalData.length > 0) {
    const otherFrameworks = historicalData.filter((h) => h.feedback.framework !== framework).map((h) => h.feedback.framework);
    const uniqueFrameworks = [...new Set(otherFrameworks)];
    if (uniqueFrameworks.length > 0) {
      const otherSuccessRates = uniqueFrameworks.map((fw) => {
        const fwRecords = historicalData.filter((h) => h.feedback.framework === fw);
        const fwSuccess = fwRecords.filter((h) => h.outcome.success).length;
        return `${fw}: ${Math.round(fwSuccess / fwRecords.length * 100)}%`;
      });
      outcome.crossFrameworkNotes.push(
        `Cross-framework comparison for ${techniqueId}: ${otherSuccessRates.join(", ")}`
      );
    }
  }
  return outcome;
}
function calculateConfidenceAdjustment(success, targetContext, feedback) {
  let adjustment = success ? 5 : -3;
  if (success && targetContext.defenses && targetContext.defenses.length > 0) {
    adjustment += Math.min(targetContext.defenses.length * 2, 8);
  }
  if (success && targetContext.privileges === "user") {
    adjustment += 3;
  }
  if (!success && (targetContext.privileges === "system" || targetContext.privileges === "admin")) {
    adjustment -= 3;
  }
  if (success && feedback.graphContext) {
    const positionBonus = Math.min(feedback.graphContext.executionOrder / feedback.graphContext.totalNodes * 5, 5);
    adjustment += Math.round(positionBonus);
  }
  return Math.max(-20, Math.min(20, adjustment));
}
function extractArtifactsFromOutput(output, framework) {
  const artifacts = [];
  if (!output || output.length < 5) return artifacts;
  const winPaths = output.match(/[A-Z]:\\[\w\\.-]+/g);
  if (winPaths) {
    for (const p of [...new Set(winPaths)].slice(0, 10)) {
      artifacts.push({ type: "file_path", value: p, context: "Observed in output", framework });
    }
  }
  const unixPaths = output.match(/\/(?:usr|etc|var|tmp|home|opt|root|proc|sys)\/[\w/.-]+/g);
  if (unixPaths) {
    for (const p of [...new Set(unixPaths)].slice(0, 10)) {
      artifacts.push({ type: "file_path", value: p, context: "Observed in output", framework });
    }
  }
  const regKeys = output.match(/HK(?:LM|CU|CR|U|CC)\\[\w\\.-]+/g);
  if (regKeys) {
    for (const k of [...new Set(regKeys)].slice(0, 10)) {
      artifacts.push({ type: "registry_key", value: k, context: "Observed in output", framework });
    }
  }
  const ips = output.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  if (ips) {
    for (const ip of [...new Set(ips)].filter((ip2) => !ip2.startsWith("0.") && !ip2.startsWith("255.")).slice(0, 10)) {
      artifacts.push({ type: "network_connection", value: ip, context: "Observed in output", framework });
    }
  }
  const domains = output.match(/\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}\b/gi);
  if (domains) {
    for (const d of [...new Set(domains)].slice(0, 10)) {
      artifacts.push({ type: "dns_query", value: d, context: "Observed in output", framework });
    }
  }
  const hashes = output.match(/\b[a-f0-9]{32,64}\b/gi);
  if (hashes) {
    for (const h of [...new Set(hashes)].slice(0, 5)) {
      artifacts.push({ type: "hash", value: h, context: "Observed in output", framework });
    }
  }
  const processes = output.match(/(?:^|\s)([\w.-]+\.exe)\b/gi);
  if (processes) {
    for (const p of [...new Set(processes.map((s) => s.trim()))].slice(0, 10)) {
      artifacts.push({ type: "process", value: p, context: "Observed in output", framework });
    }
  }
  return artifacts;
}
function deriveConstraints(feedback, success) {
  const constraints = [];
  const { targetContext, taskResult } = feedback;
  if (success) {
    constraints.push({
      type: "required_os",
      value: targetContext.platform,
      confidence: 90,
      source: "execution_result"
    });
    if (targetContext.privileges === "user") {
      constraints.push({
        type: "required_privilege",
        value: "user",
        confidence: 85,
        source: "execution_result"
      });
    }
  } else {
    const stderr = taskResult.stderr.toLowerCase();
    if (stderr.includes("access denied") || stderr.includes("permission denied") || stderr.includes("insufficient privileges")) {
      constraints.push({
        type: "required_privilege",
        value: "admin",
        confidence: 80,
        source: "execution_result"
      });
    }
    if (stderr.includes("not found") || stderr.includes("no such file") || stderr.includes("command not found")) {
      constraints.push({
        type: "required_software",
        value: `Missing dependency on ${targetContext.platform}`,
        confidence: 70,
        source: "execution_result"
      });
    }
    if (stderr.includes("blocked") || stderr.includes("quarantined") || stderr.includes("detected")) {
      const defense = targetContext.defenses?.[0] || "unknown_defense";
      constraints.push({
        type: "defense_bypass",
        value: `Blocked by ${defense}`,
        confidence: 85,
        source: "execution_result"
      });
    }
    if (stderr.includes("timeout") || stderr.includes("timed out") || stderr.includes("connection refused")) {
      constraints.push({
        type: "network_access",
        value: `Network access required to target`,
        confidence: 75,
        source: "execution_result"
      });
    }
  }
  return constraints;
}
async function llmAnalyzeExecution(feedback, success) {
  const { techniqueId, framework, taskResult, targetContext } = feedback;
  const prompt = `Analyze this C2 execution result and extract security intelligence.

Technique: ${techniqueId}
Framework: ${framework}
Platform: ${targetContext.platform} (${targetContext.architecture})
Privileges: ${targetContext.privileges}
Defenses: ${(targetContext.defenses || []).join(", ") || "none detected"}
Success: ${success}
Exit Code: ${taskResult.exitCode}

STDOUT (truncated):
${taskResult.stdout.slice(0, 3e3)}

STDERR (truncated):
${taskResult.stderr.slice(0, 1e3)}

Provide analysis in the following JSON format:
{
  "telemetry": [{ "source": "log source", "eventId": "optional", "description": "what was observed", "detectable": true/false, "confidence": 0-100, "phase": "execution|persistence|cleanup" }],
  "lessons": ["lesson learned for future execution"],
  "crossFramework": ["notes on how this applies to other C2 frameworks"],
  "additionalArtifacts": [{ "type": "file_path|registry_key|process|network_connection|dns_query|command_line|hash|mutex", "value": "artifact value", "context": "why it matters" }]
}`;
  try {
    const response = await invokeLLM({
      _caller: "c2-learning-engine.llmAnalyzeExecution",
      messages: [
        { role: "system", content: "You are a red team analyst specializing in C2 framework operations and MITRE ATT&CK technique analysis. Extract actionable intelligence from execution results. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "execution_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              telemetry: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    source: { type: "string" },
                    eventId: { type: "string" },
                    description: { type: "string" },
                    detectable: { type: "boolean" },
                    confidence: { type: "integer" },
                    phase: { type: "string" }
                  },
                  required: ["source", "eventId", "description", "detectable", "confidence", "phase"],
                  additionalProperties: false
                }
              },
              lessons: { type: "array", items: { type: "string" } },
              crossFramework: { type: "array", items: { type: "string" } },
              additionalArtifacts: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    type: { type: "string" },
                    value: { type: "string" },
                    context: { type: "string" }
                  },
                  required: ["type", "value", "context"],
                  additionalProperties: false
                }
              }
            },
            required: ["telemetry", "lessons", "crossFramework", "additionalArtifacts"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) return null;
    const contentStr = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(contentStr);
    return {
      telemetry: (parsed.telemetry || []).map((t) => ({
        source: t.source,
        eventId: t.eventId,
        description: t.description,
        detectable: t.detectable,
        confidence: t.confidence,
        phase: t.phase
      })),
      lessons: parsed.lessons || [],
      crossFramework: parsed.crossFramework || [],
      additionalArtifacts: (parsed.additionalArtifacts || []).map((a) => ({
        type: a.type,
        value: a.value,
        context: a.context,
        framework
      }))
    };
  } catch {
    return null;
  }
}
async function updateTtpKnowledge(techniqueId, outcome) {
  const db = await getDb();
  if (!db) return;
  try {
    const existing = await db.select().from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, techniqueId)).limit(1);
    if (existing.length === 0) return;
    const entry = existing[0];
    const currentConfidence = entry.confidence || 50;
    const newConfidence = Math.max(0, Math.min(100, currentConfidence + outcome.confidenceAdjustment));
    const existingConstraints = entry.environmentalConstraints || {};
    const mergedConstraints = mergeConstraints(existingConstraints, outcome.newConstraints);
    const existingTelemetry = entry.expectedTelemetry || [];
    const mergedTelemetry = mergeTelemetry(existingTelemetry, outcome.observedTelemetry);
    const existingIocs = entry.iocPatterns || [];
    const newIocs = outcome.extractedArtifacts.map((a) => ({
      type: a.type,
      pattern: a.value,
      description: a.context,
      confidence: 70,
      volatility: "medium",
      source: `c2-learning-${a.framework}`
    }));
    const mergedIocs = deduplicateIocs([...existingIocs, ...newIocs]);
    const existingNotes = entry.purpleTeamNotes || "";
    const newNotes = outcome.lessonsLearned.length > 0 ? `${existingNotes}

[${outcome.analyzedAt}] C2 Learning (${outcome.framework}):
${outcome.lessonsLearned.join("\n")}` : existingNotes;
    await db.update(ttpKnowledge).set({
      confidence: newConfidence,
      environmentalConstraints: mergedConstraints,
      expectedTelemetry: mergedTelemetry,
      iocPatterns: mergedIocs,
      purpleTeamNotes: newNotes.slice(0, 1e4),
      // Prevent unbounded growth
      lastEnriched: /* @__PURE__ */ new Date()
    }).where(eq(ttpKnowledge.techniqueId, techniqueId));
  } catch (err) {
    console.error(`[C2Learning] Failed to update TTP knowledge for ${techniqueId}:`, err);
  }
}
function mergeConstraints(existing, newConstraints) {
  const merged = { ...existing };
  for (const c of newConstraints) {
    switch (c.type) {
      case "required_os": {
        const osList = merged.requiredOS || [];
        if (!osList.includes(c.value)) osList.push(c.value);
        merged.requiredOS = osList;
        break;
      }
      case "required_privilege": {
        merged.privileges = merged.privileges || [];
        if (!merged.privileges.includes(c.value)) merged.privileges.push(c.value);
        break;
      }
      case "required_software": {
        merged.dependencies = merged.dependencies || [];
        if (!merged.dependencies.includes(c.value)) merged.dependencies.push(c.value);
        break;
      }
      case "network_access": {
        merged.networkAccess = merged.networkAccess || [];
        if (!merged.networkAccess.includes(c.value)) merged.networkAccess.push(c.value);
        break;
      }
      case "defense_bypass": {
        merged.contraindications = merged.contraindications || [];
        if (!merged.contraindications.includes(c.value)) merged.contraindications.push(c.value);
        break;
      }
      case "contraindication": {
        merged.contraindications = merged.contraindications || [];
        if (!merged.contraindications.includes(c.value)) merged.contraindications.push(c.value);
        break;
      }
    }
  }
  return merged;
}
function mergeTelemetry(existing, observed) {
  const merged = [...existing];
  for (const obs of observed) {
    const exists = merged.some(
      (e) => e.source === obs.source && e.eventId === obs.eventId && e.description === obs.description
    );
    if (!exists) {
      merged.push(obs);
    }
  }
  return merged.slice(0, 50);
}
function deduplicateIocs(iocs) {
  const seen = /* @__PURE__ */ new Set();
  return iocs.filter((ioc) => {
    const key = `${ioc.type}:${ioc.pattern}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 100);
}
function getHistoryForTechnique(techniqueId) {
  return executionHistory.filter((r) => r.feedback.techniqueId === techniqueId);
}
function getHistoryForFramework(framework) {
  return executionHistory.filter((r) => r.feedback.framework === framework);
}
function getExecutionHistory(params) {
  let filtered = [...executionHistory];
  if (params?.framework) {
    filtered = filtered.filter((r) => r.feedback.framework === params.framework);
  }
  if (params?.techniqueId) {
    filtered = filtered.filter((r) => r.feedback.techniqueId === params.techniqueId);
  }
  if (params?.successOnly !== void 0) {
    filtered = filtered.filter((r) => r.outcome.success === params.successOnly);
  }
  const total = filtered.length;
  const offset = params?.offset || 0;
  const limit = params?.limit || 50;
  return {
    records: filtered.slice(offset, offset + limit),
    total
  };
}
function calculateTechniqueReliability(techniqueId) {
  const records = getHistoryForTechnique(techniqueId);
  if (records.length === 0) return null;
  const byFramework = {};
  const byPlatform = {};
  const byPrivilege = {};
  const failureReasons = [];
  let totalConfidence = 0;
  let successCount = 0;
  let failureCount = 0;
  for (const record of records) {
    const fw = record.feedback.framework;
    const platform = record.feedback.targetContext.platform;
    const privilege = record.feedback.targetContext.privileges;
    const success = record.outcome.success;
    if (success) successCount++;
    else {
      failureCount++;
      if (record.feedback.taskResult.stderr) {
        failureReasons.push(record.feedback.taskResult.stderr.slice(0, 100));
      }
    }
    totalConfidence += 50 + record.outcome.confidenceAdjustment;
    if (!byFramework[fw]) byFramework[fw] = { success: 0, failure: 0 };
    if (success) byFramework[fw].success++;
    else byFramework[fw].failure++;
    if (!byPlatform[platform]) byPlatform[platform] = { success: 0, failure: 0 };
    if (success) byPlatform[platform].success++;
    else byPlatform[platform].failure++;
    if (!byPrivilege[privilege]) byPrivilege[privilege] = { success: 0, failure: 0 };
    if (success) byPrivilege[privilege].success++;
    else byPrivilege[privilege].failure++;
  }
  const toRate = (stats) => ({
    ...stats,
    rate: stats.success / (stats.success + stats.failure)
  });
  const frameworkRates = Object.fromEntries(
    Object.entries(byFramework).map(([k, v]) => [k, toRate(v)])
  );
  const platformRates = Object.fromEntries(
    Object.entries(byPlatform).map(([k, v]) => [k, toRate(v)])
  );
  const privilegeRates = Object.fromEntries(
    Object.entries(byPrivilege).map(([k, v]) => [k, toRate(v)])
  );
  let bestFramework = null;
  let bestFrameworkRate = 0;
  for (const [fw, stats] of Object.entries(frameworkRates)) {
    if (stats.rate > bestFrameworkRate && stats.success + stats.failure >= 2) {
      bestFrameworkRate = stats.rate;
      bestFramework = fw;
    }
  }
  let bestPlatform = null;
  let bestPlatformRate = 0;
  for (const [p, stats] of Object.entries(platformRates)) {
    if (stats.rate > bestPlatformRate && stats.success + stats.failure >= 2) {
      bestPlatformRate = stats.rate;
      bestPlatform = p;
    }
  }
  const reasonCounts = /* @__PURE__ */ new Map();
  for (const r of failureReasons) {
    const key = r.toLowerCase().trim();
    reasonCounts.set(key, (reasonCounts.get(key) || 0) + 1);
  }
  const commonFailures = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([reason]) => reason);
  return {
    techniqueId,
    techniqueName: records[0]?.feedback.techniqueId || techniqueId,
    totalExecutions: records.length,
    successCount,
    failureCount,
    successRate: successCount / records.length,
    avgConfidence: totalConfidence / records.length,
    byFramework: frameworkRates,
    byPlatform: platformRates,
    byPrivilege: privilegeRates,
    commonFailureReasons: commonFailures,
    bestFramework,
    bestPlatform,
    lastExecuted: records[0]?.timestamp || ""
  };
}
function getLearningStats() {
  const byFramework = {};
  const byTechnique = {};
  let totalArtifacts = 0;
  let totalConstraints = 0;
  const recentLessons = [];
  for (const record of executionHistory) {
    const fw = record.feedback.framework;
    const tech = record.feedback.techniqueId;
    if (!byFramework[fw]) byFramework[fw] = { total: 0, success: 0 };
    byFramework[fw].total++;
    if (record.outcome.success) byFramework[fw].success++;
    if (!byTechnique[tech]) byTechnique[tech] = { total: 0, success: 0 };
    byTechnique[tech].total++;
    if (record.outcome.success) byTechnique[tech].success++;
    totalArtifacts += record.outcome.extractedArtifacts.length;
    totalConstraints += record.outcome.newConstraints.length;
    if (recentLessons.length < 20) {
      recentLessons.push(...record.outcome.lessonsLearned.slice(0, 2));
    }
  }
  const totalSuccess = executionHistory.filter((r) => r.outcome.success).length;
  const topTechniques = Object.entries(byTechnique).map(([techniqueId, stats]) => ({
    techniqueId,
    executions: stats.total,
    successRate: stats.success / stats.total
  })).sort((a, b) => b.executions - a.executions).slice(0, 10);
  return {
    totalExecutions: executionHistory.length,
    totalSuccess,
    totalFailure: executionHistory.length - totalSuccess,
    overallSuccessRate: executionHistory.length > 0 ? totalSuccess / executionHistory.length : 0,
    uniqueTechniques: Object.keys(byTechnique).length,
    byFramework: Object.fromEntries(
      Object.entries(byFramework).map(([k, v]) => [k, { ...v, rate: v.success / v.total }])
    ),
    topTechniques,
    recentLessons: recentLessons.slice(0, 10),
    totalArtifactsExtracted: totalArtifacts,
    totalConstraintsLearned: totalConstraints
  };
}
async function batchProcessFeedback(feedbacks) {
  const outcomes = [];
  for (const feedback of feedbacks) {
    const outcome = await processExecutionFeedback(feedback);
    outcomes.push(outcome);
  }
  return outcomes;
}
function recommendFramework(techniqueId, targetPlatform) {
  const reliability = calculateTechniqueReliability(techniqueId);
  if (!reliability || reliability.totalExecutions < 3) return null;
  const platformData = reliability.byPlatform[targetPlatform];
  if (!platformData || platformData.success + platformData.failure < 2) {
    if (reliability.bestFramework) {
      const fwData = reliability.byFramework[reliability.bestFramework];
      return {
        framework: reliability.bestFramework,
        confidence: Math.round(fwData.rate * 100),
        reason: `Best overall framework for ${techniqueId} (${Math.round(fwData.rate * 100)}% success rate across ${fwData.success + fwData.failure} executions)`
      };
    }
    return null;
  }
  let bestFw = null;
  let bestRate = 0;
  for (const [fw, stats] of Object.entries(reliability.byFramework)) {
    const fwPlatformRecords = executionHistory.filter(
      (r) => r.feedback.techniqueId === techniqueId && r.feedback.framework === fw && r.feedback.targetContext.platform === targetPlatform
    );
    if (fwPlatformRecords.length < 2) continue;
    const fwPlatformSuccess = fwPlatformRecords.filter((r) => r.outcome.success).length;
    const rate = fwPlatformSuccess / fwPlatformRecords.length;
    if (rate > bestRate) {
      bestRate = rate;
      bestFw = fw;
    }
  }
  if (bestFw) {
    return {
      framework: bestFw,
      confidence: Math.round(bestRate * 100),
      reason: `Best framework for ${techniqueId} on ${targetPlatform} (${Math.round(bestRate * 100)}% success rate)`
    };
  }
  return null;
}

export {
  processExecutionFeedback,
  getHistoryForTechnique,
  getHistoryForFramework,
  getExecutionHistory,
  calculateTechniqueReliability,
  getLearningStats,
  batchProcessFeedback,
  recommendFramework
};
