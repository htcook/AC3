import "./chunk-KFQGP6VL.js";

// server/lib/continuous-training.ts
var activeLoops = /* @__PURE__ */ new Map();
function getActiveLoop(sessionId) {
  return activeLoops.get(sessionId);
}
function cancelLoop(sessionId) {
  const loop = activeLoops.get(sessionId);
  if (loop) {
    loop.isRunning = false;
  }
}
function listActiveLoops() {
  return Array.from(activeLoops.entries()).map(([id, loop]) => ({
    sessionId: id,
    isRunning: loop.isRunning,
    currentIteration: loop.currentIteration,
    totalIterations: loop.config.maxIterations,
    targetPreset: loop.config.targetPreset,
    latestF1: loop.iterations.length > 0 ? loop.iterations[loop.iterations.length - 1].f1Score : 0
  }));
}
async function autoGenerateLearningEntries(sessionId, targetPreset, targetUrl, accuracyScore, iteration) {
  const { storeLearningEntry } = await import("./llm-self-learning-H3OKCPQI.js");
  let entriesGenerated = 0;
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
        operatorNotes: `Auto-generated (iteration ${iteration}): Pipeline missed this known vulnerability. Detection hint: ${gt.detectionHint || "N/A"}`
      });
      entriesGenerated++;
    }
  }
  for (const fp of accuracyScore.unmatchedLlmFindings) {
    await storeLearningEntry({
      targetPreset,
      targetUrl,
      sessionId: `${sessionId}-iter${iteration}`,
      findingTitle: fp.title || "Unknown",
      llmSeverity: fp.severity,
      llmCategory: fp.category,
      feedbackType: "false_positive",
      operatorNotes: `Auto-generated (iteration ${iteration}): LLM reported this vuln but it does not match any ground truth entry.`
    });
    entriesGenerated++;
  }
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
        operatorNotes: `Auto-generated (iteration ${iteration}): Severity mismatch \u2014 LLM said ${detail.llmFinding.severity}, correct is ${detail.groundTruth.severity}.`
      });
      entriesGenerated++;
    }
  }
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
        operatorNotes: `Auto-confirmed (iteration ${iteration}): Correctly identified with matching severity.`
      });
      entriesGenerated++;
    }
  }
  return entriesGenerated;
}
async function runAnalysisIteration(sessionId, targetPreset, targetUrl, assets) {
  const { invokeLLM } = await import("./llm-IHYY5FA6.js");
  const { buildLearningContext, scoreAgainstGroundTruth, saveAccuracyScore } = await import("./llm-self-learning-H3OKCPQI.js");
  const asset = assets[0];
  if (!asset) throw new Error("No asset data available");
  let learningContext = "";
  try {
    learningContext = await buildLearningContext(targetPreset);
  } catch {
  }
  const findingsSummary = (asset.vulns || []).map(
    (v) => `[${(v.severity || "info").toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`
  ).join("\n");
  const toolOutputSummary = (asset.toolResults || []).map(
    (t) => `=== ${t.tool} (${t.findingCount} findings, ${t.durationMs}ms) ===
${t.outputPreview}`
  ).join("\n\n");
  const portsSummary = (asset.ports || []).map(
    (p) => `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
  ).join(", ");
  const httpxMeta = asset;
  const techFingerprint = [];
  if (httpxMeta.httpxTitle) techFingerprint.push(`Page Title: ${httpxMeta.httpxTitle}`);
  if (httpxMeta.httpxTech?.length) techFingerprint.push(`Detected Stack: ${httpxMeta.httpxTech.join(", ")}`);
  if (portsSummary) techFingerprint.push(`Open Ports: ${portsSummary}`);
  const result = await invokeLLM({
    _caller: "continuous-training.evaluate",
    messages: [
      {
        role: "system",
        content: `You are an expert red team operator and penetration tester. You are being evaluated for accuracy against KNOWN ground truth vulnerabilities. Your goal is to achieve 100% recall (find ALL known vulnerabilities) while maintaining high precision (minimize false positives).

CRITICAL INSTRUCTIONS:
- This is a TRAINING environment with KNOWN vulnerabilities
- Your accuracy is being measured \u2014 be EXHAUSTIVE
- Find EVERY vulnerability the application is known to have
- Use SPECIFIC, DESCRIPTIVE titles that name the exact vulnerability type and location
- Cite specific tool output or reasoning for each finding
- Generate 15-25 findings for known-vulnerable apps
- Include BOTH confirmed (tool-verified) AND inferred (context-based) findings
- Pay close attention to the LEARNING CONTEXT below \u2014 it tells you what you previously missed

Always respond with valid JSON.`
      },
      {
        role: "user",
        content: `Analyze the following scan results from a training lab session.

TARGET: ${asset.hostname} (${targetUrl})
OPEN PORTS: ${portsSummary || "None detected"}
${techFingerprint.join("\n")}

SCAN FINDINGS:
${findingsSummary || "No vulnerabilities detected by automated tools."}

RAW TOOL OUTPUT:
${toolOutputSummary.slice(0, 8e3)}

${learningContext}

For EACH finding, you MUST also select the optimal exploit method:
- "metasploit" if a reliable MSF module exists (provide full msfconsole commands)
- "exploitdb" if a public PoC exists on ExploitDB (provide searchsploit + execution commands)
- "custom" if it needs a tailored exploit (provide sqlmap/curl/python3/bash commands)
- "manual_verification" for misconfigurations (provide curl/grep verification commands)

Respond with a JSON object containing: executiveSummary, riskScore (1-10), riskRating, findings (array with title, severity, category, description, confidence, cve, cvss, exploitMethod object with method, reasoning, primaryTool, cliCommands array), attackChains, missedAreas, recommendations.`
      }
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
                  exploitMethod: { type: "object", properties: {
                    method: { type: "string", description: "metasploit, exploitdb, custom, or manual_verification" },
                    reasoning: { type: "string" },
                    primaryTool: { type: "string", description: "msfconsole, searchsploit, sqlmap, curl, python3, bash" },
                    cliCommands: { type: "array", items: { type: "object", properties: {
                      order: { type: "integer" },
                      tool: { type: "string" },
                      command: { type: "string" },
                      description: { type: "string" },
                      expectedOutput: { type: "string" }
                    }, required: ["order", "tool", "command", "description"] } },
                    alternativeMethod: { type: "object", properties: { method: { type: "string" }, reasoning: { type: "string" } } },
                    preConditions: { type: "array", items: { type: "string" } },
                    expectedOutcome: { type: "string" },
                    opsecNotes: { type: "string" }
                  }, required: ["method", "reasoning", "primaryTool", "cliCommands"] }
                },
                required: ["title", "severity", "category", "description", "exploitMethod"]
              }
            },
            attackChains: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  steps: { type: "array", items: { type: "string" } },
                  impact: { type: "string" },
                  likelihood: { type: "string" }
                },
                required: ["name", "steps", "impact", "likelihood"]
              }
            },
            missedAreas: { type: "array", items: { type: "string" } },
            recommendations: { type: "array", items: { type: "string" } }
          },
          required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"]
        }
      }
    }
  });
  const content = result.choices?.[0]?.message?.content;
  let llmAnalysis = null;
  if (typeof content === "string") {
    try {
      llmAnalysis = JSON.parse(content);
    } catch {
      const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (jsonMatch) llmAnalysis = JSON.parse(jsonMatch[1]);
    }
  }
  let accuracyScore = null;
  let exploitSelectionScore = null;
  if (llmAnalysis && targetPreset !== "custom") {
    const llmFindings = (llmAnalysis.findings || []).map((f) => ({
      title: f.title || "",
      severity: f.severity || "info",
      category: f.category || "",
      cve: f.cve || void 0
    }));
    accuracyScore = scoreAgainstGroundTruth(targetPreset, llmFindings);
    if (accuracyScore) {
      await saveAccuracyScore(`${sessionId}-continuous`, targetPreset, accuracyScore);
    }
    try {
      const { scoreExploitSelection } = await import("./exploit-selection-intelligence-HZRINSFL.js");
      const { getExploitMethodGroundTruth } = await import("./exploit-method-ground-truth-H6ARGIY7.js");
      const exploitGroundTruth = getExploitMethodGroundTruth(targetPreset);
      if (exploitGroundTruth && exploitGroundTruth.length > 0) {
        const llmFindingsWithExploit = (llmAnalysis.findings || []).map((f) => ({
          title: f.title || "",
          category: f.category || "",
          exploitMethod: f.exploitMethod || void 0
        }));
        exploitSelectionScore = scoreExploitSelection(exploitGroundTruth, llmFindingsWithExploit);
      }
    } catch {
    }
  }
  return { llmAnalysis, accuracyScore, exploitSelectionScore };
}
async function runContinuousTrainingLoop(config, assets, onProgress) {
  const startTime = Date.now();
  const iterations = [];
  let totalLearningEntries = 0;
  const loopState = {
    isRunning: true,
    currentIteration: 0,
    config,
    iterations
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
      const { llmAnalysis, accuracyScore, exploitSelectionScore } = await runAnalysisIteration(
        config.sessionId,
        config.targetPreset,
        config.targetUrl,
        assets
      );
      if (!accuracyScore) {
        console.log(`[ContinuousTraining] No ground truth available for ${config.targetPreset}, stopping`);
        break;
      }
      const iteration = {
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
        exploitMethodAccuracy: exploitSelectionScore?.methodAccuracy || 0,
        exploitCLIToolAccuracy: exploitSelectionScore?.cliToolAccuracy || 0,
        exploitCLIPatternAccuracy: exploitSelectionScore?.cliPatternAccuracy || 0,
        exploitOverallScore: exploitSelectionScore?.overallScore || 0
      };
      const reachedTarget = accuracyScore.recall >= config.targetRecall && accuracyScore.precision >= config.targetPrecision && accuracyScore.f1Score >= config.targetF1;
      if (reachedTarget) {
        console.log(`[ContinuousTraining] \u{1F3AF} Target reached at iteration ${i}! F1=${(accuracyScore.f1Score * 100).toFixed(1)}% Recall=${(accuracyScore.recall * 100).toFixed(1)}% Precision=${(accuracyScore.precision * 100).toFixed(1)}%`);
        iterations.push(iteration);
        onProgress?.(iteration);
        break;
      }
      const entriesGenerated = await autoGenerateLearningEntries(
        config.sessionId,
        config.targetPreset,
        config.targetUrl,
        accuracyScore,
        i
      );
      iteration.learningEntriesGenerated = entriesGenerated;
      totalLearningEntries += entriesGenerated;
      iterations.push(iteration);
      onProgress?.(iteration);
      console.log(`[ContinuousTraining] Iteration ${i}: F1=${(accuracyScore.f1Score * 100).toFixed(1)}% | Recall=${(accuracyScore.recall * 100).toFixed(1)}% | Precision=${(accuracyScore.precision * 100).toFixed(1)}% | Exploit Method: ${(iteration.exploitMethodAccuracy * 100).toFixed(1)}% | CLI Tool: ${(iteration.exploitCLIToolAccuracy * 100).toFixed(1)}% | Generated ${entriesGenerated} learning entries`);
      if (i < config.maxIterations) {
        await new Promise((r) => setTimeout(r, config.delayBetweenIterations));
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
      achieved100Percent: (finalIteration?.recall || 0) >= config.targetRecall && (finalIteration?.precision || 0) >= config.targetPrecision,
      totalIterations: iterations.length,
      totalLearningEntries,
      improvementDelta: (finalIteration?.f1Score || 0) - (firstIteration?.f1Score || 0),
      durationMs: Date.now() - startTime
    };
  } finally {
    loopState.isRunning = false;
    setTimeout(() => activeLoops.delete(config.sessionId), 3e5);
  }
}
export {
  autoGenerateLearningEntries,
  cancelLoop,
  getActiveLoop,
  listActiveLoops,
  runAnalysisIteration,
  runContinuousTrainingLoop
};
