/**
 * Continuous Training Loop
 *
 * Implements an automated scan → score → learn → re-analyze cycle that
 * continues until the LLM achieves 100% accuracy (recall + precision)
 * on vulnerability detection and exploit attempt identification against
 * known training targets.
 *
 * The loop works by:
 * 1. Running LLM analysis on scan data
 * 2. Scoring against ground truth
 * 3. Auto-generating learning entries for all misses and false positives
 * 4. Re-running LLM analysis with enriched learning context
 * 5. Repeating until F1 = 100% or max iterations reached
 *
 * This is the "keep scanning until the LLM gets 100%" feature.
 */

import type { AccuracyScore } from "./llm-self-learning";

export interface ContinuousTrainingConfig {
  sessionId: string;
  targetPreset: string;
  targetUrl: string;
  maxIterations: number;       // Default: 10
  targetF1: number;            // Default: 1.0 (100%)
  targetRecall: number;        // Default: 1.0 (100%)
  targetPrecision: number;     // Default: 0.9 (90% — allow some FPs)
  delayBetweenIterations: number; // ms, default: 2000
}

export interface TrainingIteration {
  iteration: number;
  f1Score: number;
  precision: number;
  recall: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  severityAccuracy: number;
  overallScore: number;
  learningEntriesGenerated: number;
  timestamp: number;
}

export interface ContinuousTrainingResult {
  sessionId: string;
  targetPreset: string;
  iterations: TrainingIteration[];
  finalF1: number;
  finalRecall: number;
  finalPrecision: number;
  achieved100Percent: boolean;
  totalIterations: number;
  totalLearningEntries: number;
  improvementDelta: number; // F1 improvement from first to last
  durationMs: number;
}

// In-memory state for active training loops
const activeLoops = new Map<string, {
  isRunning: boolean;
  currentIteration: number;
  config: ContinuousTrainingConfig;
  iterations: TrainingIteration[];
}>();

export function getActiveLoop(sessionId: string) {
  return activeLoops.get(sessionId);
}

export function cancelLoop(sessionId: string) {
  const loop = activeLoops.get(sessionId);
  if (loop) {
    loop.isRunning = false;
  }
}

export function listActiveLoops() {
  return Array.from(activeLoops.entries()).map(([id, loop]) => ({
    sessionId: id,
    isRunning: loop.isRunning,
    currentIteration: loop.currentIteration,
    totalIterations: loop.config.maxIterations,
    targetPreset: loop.config.targetPreset,
    latestF1: loop.iterations.length > 0
      ? loop.iterations[loop.iterations.length - 1].f1Score
      : 0,
  }));
}

/**
 * Auto-generate learning entries from ground truth scoring results.
 * This is the key mechanism that teaches the LLM from its mistakes
 * without requiring operator intervention.
 */
export async function autoGenerateLearningEntries(
  sessionId: string,
  targetPreset: string,
  targetUrl: string,
  accuracyScore: AccuracyScore,
  iteration: number,
): Promise<number> {
  const { storeLearningEntry } = await import("./llm-self-learning");
  let entriesGenerated = 0;

  // Generate entries for FALSE NEGATIVES (missed vulns)
  for (const detail of accuracyScore.matchDetails) {
    if (!detail.matched) {
      const gt = detail.groundTruth;
      await storeLearningEntry({
        targetPreset,
        targetUrl,
        sessionId: `${sessionId}-iter${iteration}`,
        findingTitle: gt.title,
        correctSeverity: gt.severity,
        correctCategory: gt.category,
        feedbackType: "missed_finding",
        operatorNotes: `Auto-generated (iteration ${iteration}): Pipeline missed this known vulnerability. Detection hint: ${gt.detectionHint || "N/A"}`,
      });
      entriesGenerated++;
    }
  }

  // Generate entries for FALSE POSITIVES (incorrect findings)
  for (const fp of accuracyScore.unmatchedLlmFindings) {
    await storeLearningEntry({
      targetPreset,
      targetUrl,
      sessionId: `${sessionId}-iter${iteration}`,
      findingTitle: fp.title || "Unknown",
      llmSeverity: fp.severity,
      llmCategory: fp.category,
      feedbackType: "false_positive",
      operatorNotes: `Auto-generated (iteration ${iteration}): LLM reported this vuln but it does not match any ground truth entry.`,
    });
    entriesGenerated++;
  }

  // Generate entries for SEVERITY MISMATCHES (correct vuln, wrong severity)
  for (const detail of accuracyScore.matchDetails) {
    if (detail.matched && !detail.severityMatch && detail.llmFinding) {
      await storeLearningEntry({
        targetPreset,
        targetUrl,
        sessionId: `${sessionId}-iter${iteration}`,
        findingTitle: detail.groundTruth.title,
        llmSeverity: detail.llmFinding.severity,
        correctSeverity: detail.groundTruth.severity,
        llmCategory: detail.llmFinding.category,
        correctCategory: detail.groundTruth.category,
        feedbackType: "partial",
        operatorNotes: `Auto-generated (iteration ${iteration}): Severity mismatch — LLM said ${detail.llmFinding.severity}, correct is ${detail.groundTruth.severity}.`,
      });
      entriesGenerated++;
    }
  }

  // Generate CONFIRMATION entries for TRUE POSITIVES (reinforce correct behavior)
  for (const detail of accuracyScore.matchDetails) {
    if (detail.matched && detail.severityMatch && detail.llmFinding) {
      await storeLearningEntry({
        targetPreset,
        targetUrl,
        sessionId: `${sessionId}-iter${iteration}`,
        findingTitle: detail.groundTruth.title,
        llmSeverity: detail.llmFinding.severity,
        correctSeverity: detail.groundTruth.severity,
        feedbackType: "correct",
        operatorNotes: `Auto-confirmed (iteration ${iteration}): Correctly identified with matching severity.`,
      });
      entriesGenerated++;
    }
  }

  return entriesGenerated;
}

/**
 * Run a single LLM re-analysis iteration with current learning context.
 * Returns the new accuracy score.
 */
export async function runAnalysisIteration(
  sessionId: string,
  targetPreset: string,
  targetUrl: string,
  assets: any[],
): Promise<{ llmAnalysis: any; accuracyScore: AccuracyScore | null }> {
  const { invokeLLM } = await import("../_core/llm");
  const { buildLearningContext, scoreAgainstGroundTruth, saveAccuracyScore } = await import("./llm-self-learning");

  const asset = assets[0];
  if (!asset) throw new Error("No asset data available");

  // Build learning context (includes corrections from previous iterations)
  let learningContext = "";
  try {
    learningContext = await buildLearningContext(targetPreset);
  } catch { /* ignore */ }

  const findingsSummary = (asset.vulns || []).map((v: any) =>
    `[${(v.severity || "info").toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`
  ).join("\n");

  const toolOutputSummary = (asset.toolResults || []).map((t: any) =>
    `=== ${t.tool} (${t.findingCount} findings, ${t.durationMs}ms) ===\n${t.outputPreview}`
  ).join("\n\n");

  const portsSummary = (asset.ports || []).map((p: any) =>
    `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
  ).join(", ");

  // Build technology context
  const httpxMeta = asset as any;
  const techFingerprint: string[] = [];
  if (httpxMeta.httpxTitle) techFingerprint.push(`Page Title: ${httpxMeta.httpxTitle}`);
  if (httpxMeta.httpxTech?.length) techFingerprint.push(`Detected Stack: ${httpxMeta.httpxTech.join(', ')}`);
  if (portsSummary) techFingerprint.push(`Open Ports: ${portsSummary}`);

  const result = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are an expert red team operator and penetration tester. You are being evaluated for accuracy against KNOWN ground truth vulnerabilities. Your goal is to achieve 100% recall (find ALL known vulnerabilities) while maintaining high precision (minimize false positives).

CRITICAL INSTRUCTIONS:
- This is a TRAINING environment with KNOWN vulnerabilities
- Your accuracy is being measured — be EXHAUSTIVE
- Find EVERY vulnerability the application is known to have
- Use SPECIFIC, DESCRIPTIVE titles that name the exact vulnerability type and location
- Cite specific tool output or reasoning for each finding
- Generate 15-25 findings for known-vulnerable apps
- Include BOTH confirmed (tool-verified) AND inferred (context-based) findings
- Pay close attention to the LEARNING CONTEXT below — it tells you what you previously missed

Always respond with valid JSON.`,
      },
      {
        role: "user",
        content: `Analyze the following scan results from a training lab session.

TARGET: ${asset.hostname} (${targetUrl})
OPEN PORTS: ${portsSummary || "None detected"}
${techFingerprint.join('\n')}

SCAN FINDINGS:
${findingsSummary || "No vulnerabilities detected by automated tools."}

RAW TOOL OUTPUT:
${toolOutputSummary.slice(0, 8000)}

${learningContext}

Respond with a JSON object containing: executiveSummary, riskScore (1-10), riskRating, findings (array with title, severity, category, description, exploitationPath, impact, remediation, cve, confidence), attackChains (array with name, description, steps, impact, likelihood), missedAreas (array of strings), recommendations (array of strings).`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "security_analysis",
        strict: false,
        schema: {
          type: "object",
          properties: {
            executiveSummary: { type: "string" },
            riskScore: { type: "integer" },
            riskRating: { type: "string" },
            findings: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  title: { type: "string" },
                  severity: { type: "string" },
                  category: { type: "string" },
                  cve: { type: "string" },
                  description: { type: "string" },
                  confidence: { type: "string" },
                  mitre_attack: { type: "string" },
                  evidence: { type: "string" },
                  remediation: { type: "string" },
                  cvss: { type: "number" },
                },
                required: ["title", "severity", "category", "description"],
              },
            },
            attackChains: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  steps: { type: "array", items: { type: "string" } },
                  impact: { type: "string" },
                  likelihood: { type: "string" },
                },
                required: ["name", "steps", "impact", "likelihood"],
              },
            },
            missedAreas: { type: "array", items: { type: "string" } },
            recommendations: { type: "array", items: { type: "string" } },
          },
          required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"],
        },
      },
    },
    _caller: "continuous-training.iteration",
  });

  const content = result.choices?.[0]?.message?.content;
  let llmAnalysis: any = null;
  if (typeof content === "string") {
    try {
      llmAnalysis = JSON.parse(content);
    } catch {
      const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (jsonMatch) llmAnalysis = JSON.parse(jsonMatch[1]);
    }
  }

  // Score against ground truth
  let accuracyScore: AccuracyScore | null = null;
  if (llmAnalysis && targetPreset !== "custom") {
    const llmFindings = (llmAnalysis.findings || []).map((f: any) => ({
      title: f.title || "",
      severity: f.severity || "info",
      category: f.category || "",
      cve: f.cve || undefined,
    }));
    accuracyScore = scoreAgainstGroundTruth(targetPreset, llmFindings);
    if (accuracyScore) {
      await saveAccuracyScore(`${sessionId}-continuous`, targetPreset, accuracyScore);
    }
  }

  return { llmAnalysis, accuracyScore };
}

/**
 * Main continuous training loop.
 * Runs analysis → score → learn → repeat until 100% or max iterations.
 */
export async function runContinuousTrainingLoop(
  config: ContinuousTrainingConfig,
  assets: any[],
  onProgress?: (iteration: TrainingIteration) => void,
): Promise<ContinuousTrainingResult> {
  const startTime = Date.now();
  const iterations: TrainingIteration[] = [];
  let totalLearningEntries = 0;

  // Register active loop
  const loopState = {
    isRunning: true,
    currentIteration: 0,
    config,
    iterations,
  };
  activeLoops.set(config.sessionId, loopState);

  try {
    for (let i = 1; i <= config.maxIterations; i++) {
      if (!loopState.isRunning) {
        console.log(`[ContinuousTraining] Loop cancelled at iteration ${i}`);
        break;
      }

      loopState.currentIteration = i;
      console.log(`[ContinuousTraining] Iteration ${i}/${config.maxIterations} for ${config.targetPreset}`);

      // Run LLM analysis
      const { llmAnalysis, accuracyScore } = await runAnalysisIteration(
        config.sessionId,
        config.targetPreset,
        config.targetUrl,
        assets,
      );

      if (!accuracyScore) {
        console.log(`[ContinuousTraining] No ground truth available for ${config.targetPreset}, stopping`);
        break;
      }

      // Record iteration metrics
      const iteration: TrainingIteration = {
        iteration: i,
        f1Score: accuracyScore.f1Score,
        precision: accuracyScore.precision,
        recall: accuracyScore.recall,
        truePositives: accuracyScore.truePositives,
        falsePositives: accuracyScore.falsePositives,
        falseNegatives: accuracyScore.falseNegatives,
        severityAccuracy: accuracyScore.severityAccuracy,
        overallScore: accuracyScore.overallScore,
        learningEntriesGenerated: 0,
        timestamp: Date.now(),
      };

      // Check if we've reached the target
      const reachedTarget =
        accuracyScore.recall >= config.targetRecall &&
        accuracyScore.precision >= config.targetPrecision &&
        accuracyScore.f1Score >= config.targetF1;

      if (reachedTarget) {
        console.log(`[ContinuousTraining] 🎯 Target reached at iteration ${i}! F1=${(accuracyScore.f1Score * 100).toFixed(1)}% Recall=${(accuracyScore.recall * 100).toFixed(1)}% Precision=${(accuracyScore.precision * 100).toFixed(1)}%`);
        iterations.push(iteration);
        onProgress?.(iteration);
        break;
      }

      // Auto-generate learning entries from misses/FPs
      const entriesGenerated = await autoGenerateLearningEntries(
        config.sessionId,
        config.targetPreset,
        config.targetUrl,
        accuracyScore,
        i,
      );
      iteration.learningEntriesGenerated = entriesGenerated;
      totalLearningEntries += entriesGenerated;

      iterations.push(iteration);
      onProgress?.(iteration);

      console.log(`[ContinuousTraining] Iteration ${i}: F1=${(accuracyScore.f1Score * 100).toFixed(1)}% | Recall=${(accuracyScore.recall * 100).toFixed(1)}% | Precision=${(accuracyScore.precision * 100).toFixed(1)}% | Generated ${entriesGenerated} learning entries`);

      // Delay before next iteration
      if (i < config.maxIterations) {
        await new Promise(r => setTimeout(r, config.delayBetweenIterations));
      }
    }

    const finalIteration = iterations[iterations.length - 1];
    const firstIteration = iterations[0];

    return {
      sessionId: config.sessionId,
      targetPreset: config.targetPreset,
      iterations,
      finalF1: finalIteration?.f1Score || 0,
      finalRecall: finalIteration?.recall || 0,
      finalPrecision: finalIteration?.precision || 0,
      achieved100Percent: (finalIteration?.recall || 0) >= config.targetRecall &&
        (finalIteration?.precision || 0) >= config.targetPrecision,
      totalIterations: iterations.length,
      totalLearningEntries,
      improvementDelta: (finalIteration?.f1Score || 0) - (firstIteration?.f1Score || 0),
      durationMs: Date.now() - startTime,
    };
  } finally {
    loopState.isRunning = false;
    // Clean up after a delay
    setTimeout(() => activeLoops.delete(config.sessionId), 300000); // 5 min
  }
}
