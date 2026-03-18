/**
 * Engagement Training Bridge
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Bridges the gap between live engagement LLM decisions and the training
 * pipeline. Captures every LLM decision during engagements into:
 *   1. llm_decision_log — structured decision log for analysis
 *   2. llm_training_examples — formatted training examples for fine-tuning
 *   3. c2_execution_log — C2 technique execution outcomes
 *
 * Also wires exploit outcomes back to collectFromEngagement() so the
 * specialist models can learn from real engagement results.
 */

import { getDb } from "../db";
import { llmDecisionLog, llmTrainingExamples, c2ExecutionLog } from "../../drizzle/schema";
import { collectFromEngagement, type SpecialistModel } from "./llm-training-pipeline";
import { randomUUID } from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

interface DecisionCapture {
  engagementId: number;
  phase: string;
  caller: string;
  decision: string;
  reasoning: string;
  actions: Array<{ type: string; params: Record<string, any> }>;
  contextSummary?: string;
  latencyMs?: number;
  tokensUsed?: number;
}

interface OutcomeUpdate {
  engagementId: number;
  phase: string;
  caller: string;
  outcome: 'success' | 'failure' | 'partial';
  outcomeDetail: string;
  stealthScore?: number;
}

interface C2ExecutionCapture {
  techniqueId: string;
  framework: string;
  success: boolean;
  confidenceAdjustment?: number;
  targetPlatform?: string;
  targetArch?: string;
  exitCode?: number;
  lessonsLearned?: string[];
  extractedArtifacts?: any[];
  observedTelemetry?: any[];
  constraints?: any;
  engagementId?: number;
}

// ─── Decision Capture ───────────────────────────────────────────────────────

/**
 * Capture an LLM decision made during an engagement.
 * Called immediately after llmDecide() returns in the orchestrator.
 */
export async function captureDecision(capture: DecisionCapture): Promise<number | null> {
  try {
    const db = await getDb();
    const result = await db.insert(llmDecisionLog).values({
      engagementId: capture.engagementId,
      phase: capture.phase,
      caller: capture.caller,
      decision: capture.decision,
      reasoning: capture.reasoning,
      actions: capture.actions,
      contextSummary: capture.contextSummary?.slice(0, 5000),
      latencyMs: capture.latencyMs,
      tokensUsed: capture.tokensUsed,
    });
    const insertId = (result as any)?.[0]?.insertId ?? null;
    console.log(`[TrainingBridge] Decision captured for engagement #${capture.engagementId} phase=${capture.phase} caller=${capture.caller}`);
    return insertId;
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to capture decision:`, err.message);
    return null;
  }
}

/**
 * Update the outcome of a previously captured decision.
 * Called when we know the result of the LLM's recommendation.
 */
export async function updateDecisionOutcome(update: OutcomeUpdate): Promise<void> {
  try {
    const db = await getDb();
    const { eq, and, desc } = await import("drizzle-orm");
    // Find the most recent decision for this engagement/phase/caller
    const rows = await db.select()
      .from(llmDecisionLog)
      .where(and(
        eq(llmDecisionLog.engagementId, update.engagementId),
        eq(llmDecisionLog.phase, update.phase),
        eq(llmDecisionLog.caller, update.caller),
      ))
      .orderBy(desc(llmDecisionLog.id))
      .limit(1);

    if (rows.length > 0) {
      const row = rows[0];
      await db.update(llmDecisionLog)
        .set({
          outcome: update.outcome,
          outcomeDetail: update.outcomeDetail?.slice(0, 5000),
          stealthScore: update.stealthScore,
        })
        .where(eq(llmDecisionLog.id, row.id));

      // Also generate a training example from this completed decision
      await persistTrainingExample({
        model: callerToSpecialist(update.caller),
        engagementId: String(update.engagementId),
        context: row.contextSummary || row.decision,
        decision: row.decision,
        reasoning: row.reasoning || '',
        outcome: update.outcome,
        stealthScore: update.stealthScore ?? 0.5,
      });

      console.log(`[TrainingBridge] Outcome updated for engagement #${update.engagementId}: ${update.outcome}`);
    }
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to update outcome:`, err.message);
  }
}

// ─── Training Example Persistence ───────────────────────────────────────────

/**
 * Persist a training example to the database AND the in-memory training pipeline.
 */
export async function persistTrainingExample(params: {
  model: SpecialistModel;
  engagementId: string;
  context: string;
  decision: string;
  reasoning: string;
  outcome: 'success' | 'failure' | 'partial';
  stealthScore: number;
  timeToDecision?: number;
}): Promise<void> {
  try {
    // Feed into the in-memory training pipeline (for dataset generation, fine-tuning)
    const example = collectFromEngagement(params);

    // Persist to database so it survives restarts
    const db = await getDb();
    await db.insert(llmTrainingExamples).values({
      exampleId: example.id,
      model: example.model,
      source: 'live_engagement',
      sourceId: params.engagementId,
      quality: example.quality,
      qualityScore: example.qualityScore,
      messages: example.messages,
      metadata: example.metadata,
    });

    console.log(`[TrainingBridge] Training example persisted: ${example.id} (${example.quality}, score=${example.qualityScore.toFixed(2)})`);
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to persist training example:`, err.message);
  }
}

// ─── C2 Execution Persistence ───────────────────────────────────────────────

/**
 * Persist a C2 execution record to the database.
 * Called from the c2-learning-engine after processExecutionFeedback.
 */
export async function persistC2Execution(capture: C2ExecutionCapture): Promise<void> {
  try {
    const db = await getDb();
    await db.insert(c2ExecutionLog).values({
      techniqueId: capture.techniqueId,
      framework: capture.framework,
      success: capture.success ? 1 : 0,
      confidenceAdjustment: capture.confidenceAdjustment,
      targetPlatform: capture.targetPlatform,
      targetArch: capture.targetArch,
      exitCode: capture.exitCode,
      lessonsLearned: capture.lessonsLearned,
      extractedArtifacts: capture.extractedArtifacts,
      observedTelemetry: capture.observedTelemetry,
      constraints: capture.constraints,
      engagementId: capture.engagementId,
    });
    console.log(`[TrainingBridge] C2 execution persisted: ${capture.techniqueId} (${capture.framework}) success=${capture.success}`);
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to persist C2 execution:`, err.message);
  }
}

// ─── Exploit Outcome Capture ────────────────────────────────────────────────

/**
 * Capture an exploit attempt outcome for training the exploit_selector specialist.
 */
export async function captureExploitOutcome(params: {
  engagementId: number;
  target: string;
  port: number;
  cve?: string;
  service?: string;
  module?: string;
  success: boolean;
  exploitOutput: string;
  shellType?: string;
  planConfidence?: number;
  planReasoning?: string;
}): Promise<void> {
  try {
    // Capture as a decision with outcome
    await captureDecision({
      engagementId: params.engagementId,
      phase: 'exploitation',
      caller: 'exploit-execution',
      decision: `Exploit ${params.cve || params.module || 'unknown'} on ${params.target}:${params.port}`,
      reasoning: params.planReasoning || `Attempting ${params.module || params.cve || 'auto'} exploit against ${params.service || 'service'} on ${params.target}:${params.port}`,
      actions: [{
        type: 'exploit_attempt',
        params: {
          target: params.target,
          port: params.port,
          cve: params.cve,
          service: params.service,
          module: params.module,
        },
      }],
      contextSummary: `Target: ${params.target}:${params.port}, CVE: ${params.cve || 'N/A'}, Service: ${params.service || 'N/A'}`,
    });

    // Generate training example for the exploit_selector specialist
    await persistTrainingExample({
      model: 'exploit_selector',
      engagementId: String(params.engagementId),
      context: `Target: ${params.target}:${params.port}\nService: ${params.service || 'unknown'}\nCVE: ${params.cve || 'N/A'}\nModule: ${params.module || 'auto'}`,
      decision: params.success ? 'Exploit succeeded' : 'Exploit failed',
      reasoning: params.success
        ? `Shell obtained via ${params.module || params.cve || 'auto'}. Shell type: ${params.shellType || 'reverse_shell'}`
        : `Exploit failed. Output: ${params.exploitOutput.slice(0, 500)}`,
      outcome: params.success ? 'success' : 'failure',
      stealthScore: params.success ? 0.6 : 0.3,
      timeToDecision: undefined,
    });
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to capture exploit outcome:`, err.message);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Map a caller string to the most appropriate specialist model.
 */
function callerToSpecialist(caller: string): SpecialistModel {
  if (caller.includes('exploit') || caller.includes('msf')) return 'exploit_selector';
  if (caller.includes('recon') || caller.includes('scan-analyst')) return 'recon_analyst';
  if (caller.includes('evasion') || caller.includes('stealth')) return 'evasion_optimizer';
  if (caller.includes('lateral') || caller.includes('pivot')) return 'lateral_planner';
  if (caller.includes('persist')) return 'persistence_engineer';
  return 'cognitive_core';
}

// ─── Query Helpers ──────────────────────────────────────────────────────────

/**
 * Get decision log entries for an engagement.
 */
export async function getDecisionLog(engagementId: number, limit = 100): Promise<any[]> {
  try {
    const db = await getDb();
    const { eq, desc } = await import("drizzle-orm");
    return await db.select()
      .from(llmDecisionLog)
      .where(eq(llmDecisionLog.engagementId, engagementId))
      .orderBy(desc(llmDecisionLog.id))
      .limit(limit);
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to get decision log:`, err.message);
    return [];
  }
}

/**
 * Get training examples by model and source.
 */
export async function getTrainingExamples(params: {
  model?: SpecialistModel;
  source?: 'lab_scenario' | 'live_engagement' | 'manual' | 'synthetic';
  quality?: 'high' | 'medium' | 'low' | 'rejected';
  limit?: number;
}): Promise<any[]> {
  try {
    const db = await getDb();
    const { desc } = await import("drizzle-orm");
    const conditions: any[] = [];
    if (params.model) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.model, params.model));
    }
    if (params.source) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.source, params.source));
    }
    if (params.quality) {
      const { eq } = await import("drizzle-orm");
      conditions.push(eq(llmTrainingExamples.quality, params.quality));
    }
    const { and } = await import("drizzle-orm");
    const where = conditions.length > 0 ? and(...conditions) : undefined;
    return await db.select()
      .from(llmTrainingExamples)
      .where(where)
      .orderBy(desc(llmTrainingExamples.id))
      .limit(params.limit || 100);
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to get training examples:`, err.message);
    return [];
  }
}

/**
 * Get aggregate training stats.
 */
export async function getTrainingStats(): Promise<{
  totalExamples: number;
  byModel: Record<string, number>;
  bySource: Record<string, number>;
  byQuality: Record<string, number>;
  totalDecisions: number;
  decisionOutcomes: Record<string, number>;
  totalC2Executions: number;
  c2SuccessRate: number;
}> {
  try {
    const db = await getDb();
    const { sql, count } = await import("drizzle-orm");

    // Training examples stats
    const examples = await db.select().from(llmTrainingExamples);
    const byModel: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    const byQuality: Record<string, number> = {};
    for (const ex of examples) {
      byModel[ex.model] = (byModel[ex.model] || 0) + 1;
      bySource[ex.source] = (bySource[ex.source] || 0) + 1;
      byQuality[ex.quality] = (byQuality[ex.quality] || 0) + 1;
    }

    // Decision log stats
    const decisions = await db.select().from(llmDecisionLog);
    const decisionOutcomes: Record<string, number> = {};
    for (const d of decisions) {
      const o = d.outcome || 'pending';
      decisionOutcomes[o] = (decisionOutcomes[o] || 0) + 1;
    }

    // C2 execution stats
    const c2Execs = await db.select().from(c2ExecutionLog);
    const c2Successes = c2Execs.filter(e => e.success === 1).length;

    return {
      totalExamples: examples.length,
      byModel,
      bySource,
      byQuality,
      totalDecisions: decisions.length,
      decisionOutcomes,
      totalC2Executions: c2Execs.length,
      c2SuccessRate: c2Execs.length > 0 ? c2Successes / c2Execs.length : 0,
    };
  } catch (err: any) {
    console.error(`[TrainingBridge] Failed to get training stats:`, err.message);
    return {
      totalExamples: 0, byModel: {}, bySource: {}, byQuality: {},
      totalDecisions: 0, decisionOutcomes: {},
      totalC2Executions: 0, c2SuccessRate: 0,
    };
  }
}
