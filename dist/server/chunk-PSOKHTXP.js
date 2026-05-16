import {
  collectFromEngagement,
  init_llm_training_pipeline
} from "./chunk-MJGBFYEG.js";
import {
  getDb,
  init_db
} from "./chunk-CKIMRR6W.js";
import {
  c2ExecutionLog,
  init_schema,
  llmDecisionLog,
  llmTrainingExamples
} from "./chunk-Q4QB2XQC.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-training-bridge.ts
async function captureDecision(capture) {
  try {
    const db = await getDb();
    const result = await db.insert(llmDecisionLog).values({
      engagementId: capture.engagementId,
      dlPhase: capture.phase,
      dlCaller: capture.caller,
      dlDecision: capture.decision,
      dlReasoning: capture.reasoning,
      dlActions: capture.actions,
      contextSummary: capture.contextSummary?.slice(0, 5e3),
      knowledgeModulesUsed: capture.knowledgeModules || null,
      dlLatencyMs: capture.latencyMs,
      tokensUsed: capture.tokensUsed
    });
    const insertId = result?.[0]?.insertId ?? null;
    console.log(`[TrainingBridge] Decision captured for engagement #${capture.engagementId} phase=${capture.phase} caller=${capture.caller}`);
    return insertId;
  } catch (err) {
    console.error(`[TrainingBridge] Failed to capture decision:`, err.message);
    return null;
  }
}
async function updateDecisionOutcome(update) {
  try {
    const db = await getDb();
    const { eq, and, desc } = await import("drizzle-orm");
    const rows = await db.select().from(llmDecisionLog).where(and(
      eq(llmDecisionLog.engagementId, update.engagementId),
      eq(llmDecisionLog.dlPhase, update.phase),
      eq(llmDecisionLog.dlCaller, update.caller)
    )).orderBy(desc(llmDecisionLog.id)).limit(1);
    if (rows.length > 0) {
      const row = rows[0];
      await db.update(llmDecisionLog).set({
        dlOutcome: update.outcome,
        outcomeDetail: update.outcomeDetail?.slice(0, 5e3),
        stealthScore: update.stealthScore
      }).where(eq(llmDecisionLog.id, row.id));
      await persistTrainingExample({
        model: callerToSpecialist(update.caller),
        engagementId: String(update.engagementId),
        context: row.contextSummary || row.dlDecision,
        decision: row.dlDecision,
        reasoning: row.dlReasoning || "",
        outcome: update.outcome,
        stealthScore: update.stealthScore ?? 0.5
      });
      console.log(`[TrainingBridge] Outcome updated for engagement #${update.engagementId}: ${update.outcome}`);
    }
  } catch (err) {
    console.error(`[TrainingBridge] Failed to update outcome:`, err.message);
  }
}
async function persistTrainingExample(params) {
  try {
    const example = collectFromEngagement(params);
    const db = await getDb();
    await db.insert(llmTrainingExamples).values({
      exampleId: example.id,
      teModel: example.model,
      teSource: "live_engagement",
      sourceId: params.engagementId,
      teQuality: example.quality,
      qualityScore: example.qualityScore,
      teMessages: example.messages,
      teMetadata: example.metadata
    });
    console.log(`[TrainingBridge] Training example persisted: ${example.id} (${example.quality}, score=${example.qualityScore.toFixed(2)})`);
  } catch (err) {
    console.error(`[TrainingBridge] Failed to persist training example:`, err.message);
  }
}
async function persistC2Execution(capture) {
  try {
    const db = await getDb();
    await db.insert(c2ExecutionLog).values({
      techniqueId: capture.techniqueId,
      celFramework: capture.framework,
      celSuccess: capture.success ? 1 : 0,
      confidenceAdjustment: capture.confidenceAdjustment,
      targetPlatform: capture.targetPlatform,
      targetArch: capture.targetArch,
      exitCode: capture.exitCode,
      lessonsLearned: capture.lessonsLearned,
      celExtractedArtifacts: capture.extractedArtifacts,
      observedTelemetry: capture.observedTelemetry,
      celConstraints: capture.constraints,
      celEngagementId: capture.engagementId
    });
    console.log(`[TrainingBridge] C2 execution persisted: ${capture.techniqueId} (${capture.framework}) success=${capture.success}`);
  } catch (err) {
    console.error(`[TrainingBridge] Failed to persist C2 execution:`, err.message);
  }
}
async function captureExploitOutcome(params) {
  try {
    await captureDecision({
      engagementId: params.engagementId,
      phase: "exploitation",
      caller: "exploit-execution",
      decision: `Exploit ${params.cve || params.module || "unknown"} on ${params.target}:${params.port}`,
      reasoning: params.planReasoning || `Attempting ${params.module || params.cve || "auto"} exploit against ${params.service || "service"} on ${params.target}:${params.port}`,
      actions: [{
        type: "exploit_attempt",
        params: {
          target: params.target,
          port: params.port,
          cve: params.cve,
          service: params.service,
          module: params.module
        }
      }],
      contextSummary: `Target: ${params.target}:${params.port}, CVE: ${params.cve || "N/A"}, Service: ${params.service || "N/A"}`
    });
    await persistTrainingExample({
      model: "exploit_selector",
      engagementId: String(params.engagementId),
      context: `Target: ${params.target}:${params.port}
Service: ${params.service || "unknown"}
CVE: ${params.cve || "N/A"}
Module: ${params.module || "auto"}`,
      decision: params.success ? "Exploit succeeded" : "Exploit failed",
      reasoning: params.success ? `Shell obtained via ${params.module || params.cve || "auto"}. Shell type: ${params.shellType || "reverse_shell"}` : `Exploit failed. Output: ${params.exploitOutput.slice(0, 500)}`,
      outcome: params.success ? "success" : "failure",
      stealthScore: params.success ? 0.6 : 0.3,
      timeToDecision: void 0
    });
  } catch (err) {
    console.error(`[TrainingBridge] Failed to capture exploit outcome:`, err.message);
  }
}
function callerToSpecialist(caller) {
  if (caller.includes("exploit") || caller.includes("msf")) return "exploit_selector";
  if (caller.includes("recon") || caller.includes("scan-analyst")) return "recon_analyst";
  if (caller.includes("evasion") || caller.includes("stealth")) return "evasion_optimizer";
  if (caller.includes("lateral") || caller.includes("pivot")) return "lateral_planner";
  if (caller.includes("persist")) return "persistence_engineer";
  if (caller.includes("burp") || caller.includes("burpsuite")) return "burp_scanner";
  if (caller.includes("zap") || caller.includes("owasp-zap")) return "zap_scanner";
  return "cognitive_core";
}
async function captureToolCorrelation(params) {
  try {
    await captureDecision({
      engagementId: params.engagementId,
      phase: "cross_tool_correlation",
      caller: `${params.primaryTool}-${params.secondaryTool}-correlation`,
      decision: `${params.correlationType}: ${params.findingType}`,
      reasoning: params.detail || `${params.primaryTool} finding ${params.correlationType} by ${params.secondaryTool}`,
      actions: [{
        type: "tool_correlation",
        params: {
          primaryTool: params.primaryTool,
          secondaryTool: params.secondaryTool,
          correlationType: params.correlationType,
          primaryFindingId: params.primaryFindingId,
          secondaryFindingId: params.secondaryFindingId
        }
      }],
      contextSummary: `Cross-tool: ${params.primaryTool} \u2192 ${params.secondaryTool} (${params.correlationType})`,
      knowledgeModules: ["cross_tool_intelligence", params.primaryTool, params.secondaryTool]
    });
    console.log(`[TrainingBridge] Cross-tool correlation: ${params.primaryTool} \u2192 ${params.secondaryTool} (${params.correlationType}: ${params.findingType})`);
  } catch (err) {
    console.error(`[TrainingBridge] Failed to capture tool correlation:`, err.message);
  }
}
async function getCrossToolStats(engagementId) {
  try {
    const db = await getDb();
    const { eq, and, like } = await import("drizzle-orm");
    const rows = await db.select().from(llmDecisionLog).where(and(
      eq(llmDecisionLog.engagementId, engagementId),
      eq(llmDecisionLog.dlPhase, "cross_tool_correlation")
    ));
    const byType = {};
    const byToolPair = {};
    let confirmed = 0;
    for (const r of rows) {
      const actions = r.dlActions || [];
      for (const a of actions) {
        if (a?.type === "tool_correlation") {
          const ct = a.params?.correlationType || "unknown";
          byType[ct] = (byType[ct] || 0) + 1;
          if (ct === "confirmed") confirmed++;
          const pair = `${a.params?.primaryTool}\u2192${a.params?.secondaryTool}`;
          byToolPair[pair] = (byToolPair[pair] || 0) + 1;
        }
      }
    }
    return {
      totalCorrelations: rows.length,
      byType,
      byToolPair,
      confirmationRate: rows.length > 0 ? confirmed / rows.length : 0
    };
  } catch (err) {
    console.error(`[TrainingBridge] Failed to get cross-tool stats:`, err.message);
    return { totalCorrelations: 0, byType: {}, byToolPair: {}, confirmationRate: 0 };
  }
}
async function getDecisionLog(engagementId, limit = 100) {
  try {
    const db = await getDb();
    const { eq, desc } = await import("drizzle-orm");
    return await db.select().from(llmDecisionLog).where(eq(llmDecisionLog.engagementId, engagementId)).orderBy(desc(llmDecisionLog.id)).limit(limit);
  } catch (err) {
    console.error(`[TrainingBridge] Failed to get decision log:`, err.message);
    return [];
  }
}
async function getTrainingExamples(params) {
  try {
    const db = await getDb();
    const { desc } = await import("drizzle-orm");
    const conditions = [];
    if (params.model) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.teModel, params.model));
    }
    if (params.source) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.teSource, params.source));
    }
    if (params.quality) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.teQuality, params.quality));
    }
    const { and } = await import("drizzle-orm");
    const where = conditions.length > 0 ? and(...conditions) : void 0;
    return await db.select().from(llmTrainingExamples).where(where).orderBy(desc(llmTrainingExamples.id)).limit(params.limit || 100);
  } catch (err) {
    console.error(`[TrainingBridge] Failed to get training examples:`, err.message);
    return [];
  }
}
async function getTrainingStats() {
  try {
    const db = await getDb();
    const { sql, count } = await import("drizzle-orm");
    const examples = await db.select().from(llmTrainingExamples);
    const byModel = {};
    const bySource = {};
    const byQuality = {};
    for (const ex of examples) {
      byModel[ex.model] = (byModel[ex.model] || 0) + 1;
      bySource[ex.source] = (bySource[ex.source] || 0) + 1;
      byQuality[ex.quality] = (byQuality[ex.quality] || 0) + 1;
    }
    const decisions = await db.select().from(llmDecisionLog);
    const decisionOutcomes = {};
    const callerBreakdown = {};
    for (const d of decisions) {
      const o = d.outcome || "pending";
      decisionOutcomes[o] = (decisionOutcomes[o] || 0) + 1;
      const c = d.caller || "unknown";
      callerBreakdown[c] = (callerBreakdown[c] || 0) + 1;
    }
    const c2Execs = await db.select().from(c2ExecutionLog);
    const c2Successes = c2Execs.filter((e) => e.success === 1).length;
    return {
      totalExamples: examples.length,
      byModel,
      bySource,
      byQuality,
      totalDecisions: decisions.length,
      decisionOutcomes,
      callerBreakdown,
      totalC2Executions: c2Execs.length,
      c2SuccessRate: c2Execs.length > 0 ? c2Successes / c2Execs.length : 0
    };
  } catch (err) {
    console.error(`[TrainingBridge] Failed to get training stats:`, err.message);
    return {
      totalExamples: 0,
      byModel: {},
      bySource: {},
      byQuality: {},
      totalDecisions: 0,
      decisionOutcomes: {},
      callerBreakdown: {},
      totalC2Executions: 0,
      c2SuccessRate: 0
    };
  }
}
var init_engagement_training_bridge = __esm({
  "server/lib/engagement-training-bridge.ts"() {
    init_db();
    init_schema();
    init_llm_training_pipeline();
  }
});

export {
  captureDecision,
  updateDecisionOutcome,
  persistTrainingExample,
  persistC2Execution,
  captureExploitOutcome,
  captureToolCorrelation,
  getCrossToolStats,
  getDecisionLog,
  getTrainingExamples,
  getTrainingStats,
  init_engagement_training_bridge
};
