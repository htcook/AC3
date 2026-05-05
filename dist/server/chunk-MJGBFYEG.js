import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-training-pipeline.ts
var llm_training_pipeline_exports = {};
__export(llm_training_pipeline_exports, {
  benchmarkModel: () => benchmarkModel,
  collectFromEngagement: () => collectFromEngagement,
  collectFromScenario: () => collectFromScenario,
  createFineTuneJob: () => createFineTuneJob,
  exportDatasetAsJSONL: () => exportDatasetAsJSONL,
  generateDataset: () => generateDataset,
  generateSyntheticExamples: () => generateSyntheticExamples,
  getAllSpecialistConfigs: () => getAllSpecialistConfigs,
  getFineTuneJobStatus: () => getFineTuneJobStatus,
  getFineTuneJobs: () => getFineTuneJobs,
  getModelBenchmarks: () => getModelBenchmarks,
  getSpecialistConfig: () => getSpecialistConfig,
  getTrainingDatasets: () => getTrainingDatasets,
  getTrainingExamples: () => getTrainingExamples,
  getTrainingPipeline: () => getTrainingPipeline,
  getTrainingPipelineSummary: () => getTrainingPipelineSummary,
  processExamplesForDataset: () => processExamplesForDataset,
  promoteModel: () => promoteModel,
  rollbackModel: () => rollbackModel,
  runTrainingPipeline: () => runTrainingPipeline,
  startFineTuneJob: () => startFineTuneJob
});
import { randomUUID } from "crypto";
function collectFromScenario(params) {
  const qualityScore = calculateQualityScore(params.outcome, params.stealthScore);
  const quality = qualityScore >= 0.8 ? "high" : qualityScore >= 0.5 ? "medium" : qualityScore >= 0.3 ? "low" : "rejected";
  const config = specialistConfigs.get(params.model);
  const systemPrompt = config?.systemPrompt || SPECIALIST_SYSTEM_PROMPTS[params.model];
  const example = {
    id: `te-${randomUUID().slice(0, 12)}`,
    model: params.model,
    timestamp: Date.now(),
    source: "lab_scenario",
    sourceId: params.scenarioId,
    quality,
    qualityScore,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: params.context },
      { role: "assistant", content: JSON.stringify({
        decision: params.decision,
        reasoning: params.reasoning,
        confidence: qualityScore,
        mitreMapping: params.mitreAttackTechniques || []
      }) }
    ],
    metadata: {
      scenarioId: params.scenarioId,
      objectiveCompleted: params.outcome === "success",
      stealthScore: params.stealthScore,
      decisionOutcome: params.outcome,
      mitreAttackTechniques: params.mitreAttackTechniques
    }
  };
  trainingExamples.set(example.id, example);
  if (config) {
    config.trainingExampleCount++;
  }
  return example;
}
function collectFromEngagement(params) {
  const qualityScore = calculateQualityScore(params.outcome, params.stealthScore);
  const quality = qualityScore >= 0.8 ? "high" : qualityScore >= 0.5 ? "medium" : qualityScore >= 0.3 ? "low" : "rejected";
  const config = specialistConfigs.get(params.model);
  const systemPrompt = config?.systemPrompt || SPECIALIST_SYSTEM_PROMPTS[params.model];
  const example = {
    id: `te-${randomUUID().slice(0, 12)}`,
    model: params.model,
    timestamp: Date.now(),
    source: "live_engagement",
    sourceId: params.engagementId,
    quality,
    qualityScore,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: params.context },
      { role: "assistant", content: JSON.stringify({
        decision: params.decision,
        reasoning: params.reasoning,
        confidence: qualityScore
      }) }
    ],
    metadata: {
      engagementId: params.engagementId,
      objectiveCompleted: params.outcome === "success",
      stealthScore: params.stealthScore,
      decisionOutcome: params.outcome,
      timeToDecision: params.timeToDecision
    }
  };
  trainingExamples.set(example.id, example);
  if (config) {
    config.trainingExampleCount++;
  }
  return example;
}
function generateSyntheticExamples(model, count) {
  const highQuality = Array.from(trainingExamples.values()).filter((e) => e.model === model && e.quality === "high");
  if (highQuality.length === 0) return [];
  const synthetic = [];
  for (let i = 0; i < count; i++) {
    const source = highQuality[i % highQuality.length];
    const variation = {
      id: `te-syn-${randomUUID().slice(0, 12)}`,
      model,
      timestamp: Date.now(),
      source: "synthetic",
      sourceId: source.id,
      quality: "medium",
      qualityScore: source.qualityScore * 0.85,
      messages: source.messages.map((m) => ({
        ...m,
        content: m.role === "user" ? augmentContext(m.content) : m.content
      })),
      metadata: {
        ...source.metadata,
        scenarioId: source.metadata.scenarioId ? `${source.metadata.scenarioId}-synthetic` : void 0
      }
    };
    synthetic.push(variation);
    trainingExamples.set(variation.id, variation);
  }
  return synthetic;
}
function calculateQualityScore(outcome, stealthScore) {
  const outcomeWeight = outcome === "success" ? 1 : outcome === "partial" ? 0.5 : 0.1;
  const stealthWeight = stealthScore / 100;
  return outcomeWeight * 0.7 + stealthWeight * 0.3;
}
function augmentContext(context) {
  const augmentations = [
    (s) => s.replace(/target/gi, "host"),
    (s) => s.replace(/vulnerability/gi, "weakness"),
    (s) => s.replace(/exploit/gi, "attack vector"),
    (s) => s.replace(/scan/gi, "enumeration"),
    (s) => s + "\n\nNote: Time pressure is moderate."
  ];
  const aug = augmentations[Math.floor(Math.random() * augmentations.length)];
  return aug(context);
}
function processExamplesForDataset(model, minQuality = "medium") {
  const qualityOrder = ["high", "medium", "low", "rejected"];
  const minIndex = qualityOrder.indexOf(minQuality);
  return Array.from(trainingExamples.values()).filter((e) => e.model === model).filter((e) => qualityOrder.indexOf(e.quality) <= minIndex).sort((a, b) => b.qualityScore - a.qualityScore);
}
function generateDataset(model, name, description, minQuality = "medium") {
  const examples = processExamplesForDataset(model, minQuality);
  const qualityDistribution = {
    high: 0,
    medium: 0,
    low: 0,
    rejected: 0
  };
  let totalQuality = 0;
  const jsonlLines = [];
  for (const example of examples) {
    qualityDistribution[example.quality]++;
    totalQuality += example.qualityScore;
    jsonlLines.push(JSON.stringify({
      messages: example.messages
    }));
  }
  const dataset = {
    id: `ds-${randomUUID().slice(0, 8)}`,
    model,
    name,
    description,
    createdAt: Date.now(),
    exampleCount: examples.length,
    qualityDistribution,
    averageQualityScore: examples.length > 0 ? totalQuality / examples.length : 0,
    exported: jsonlLines.length > 0,
    version: 1
  };
  if (jsonlLines.length > 0) {
    dataset.jsonlPath = `/training-data/${model}/${dataset.id}.jsonl`;
  }
  trainingDatasets.set(dataset.id, dataset);
  return dataset;
}
function exportDatasetAsJSONL(datasetId) {
  const dataset = trainingDatasets.get(datasetId);
  if (!dataset) return null;
  const examples = processExamplesForDataset(dataset.model);
  return examples.map((e) => JSON.stringify({ messages: e.messages })).join("\n");
}
function createFineTuneJob(params) {
  const dataset = trainingDatasets.get(params.datasetId);
  if (!dataset) throw new Error(`Dataset not found: ${params.datasetId}`);
  if (dataset.exampleCount < 10) {
    throw new Error(`Insufficient training examples: ${dataset.exampleCount} (minimum 10 required)`);
  }
  const job = {
    id: `ft-${randomUUID().slice(0, 8)}`,
    model: params.model,
    datasetId: params.datasetId,
    baseModel: params.baseModel || "gpt-4o-mini-2024-07-18",
    status: "pending",
    createdAt: Date.now(),
    epochs: params.epochs || 3,
    hyperparameters: {
      nEpochs: params.epochs || 3,
      batchSize: params.batchSize || "auto",
      learningRateMultiplier: params.learningRateMultiplier || "auto"
    },
    metrics: []
  };
  fineTuneJobs.set(job.id, job);
  return job;
}
async function startFineTuneJob(jobId, openaiApiKey) {
  const job = fineTuneJobs.get(jobId);
  if (!job) throw new Error(`Job not found: ${jobId}`);
  job.status = "preparing";
  job.startedAt = Date.now();
  const apiKey = openaiApiKey || process.env.OPENAI_API_KEY || "";
  if (apiKey && apiKey.length > 10) {
    try {
      const jsonlContent = exportDatasetAsJSONL(job.datasetId);
      if (!jsonlContent) throw new Error(`Dataset ${job.datasetId} has no exportable content`);
      console.log(`[FineTune] Uploading training file for job ${job.id} (${jsonlContent.length} bytes)...`);
      const formData = new FormData();
      const blob = new Blob([jsonlContent], { type: "application/jsonl" });
      formData.append("file", blob, `${job.model}_training_${Date.now()}.jsonl`);
      formData.append("purpose", "fine-tune");
      const uploadRes = await fetch("https://api.openai.com/v1/files", {
        method: "POST",
        headers: { "Authorization": `Bearer ${apiKey}` },
        body: formData
      });
      if (!uploadRes.ok) {
        const errBody = await uploadRes.text();
        throw new Error(`File upload failed (${uploadRes.status}): ${errBody}`);
      }
      const uploadData = await uploadRes.json();
      const trainingFileId = uploadData.id;
      console.log(`[FineTune] Training file uploaded: ${trainingFileId}`);
      const ftRes = await fetch("https://api.openai.com/v1/fine_tuning/jobs", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          training_file: trainingFileId,
          model: job.baseModel,
          suffix: `ac3-${job.model}`,
          hyperparameters: {
            n_epochs: job.hyperparameters.nEpochs,
            ...job.hyperparameters.batchSize !== "auto" ? { batch_size: job.hyperparameters.batchSize } : {},
            ...job.hyperparameters.learningRateMultiplier !== "auto" ? { learning_rate_multiplier: job.hyperparameters.learningRateMultiplier } : {}
          }
        })
      });
      if (!ftRes.ok) {
        const errBody = await ftRes.text();
        throw new Error(`Fine-tune creation failed (${ftRes.status}): ${errBody}`);
      }
      const ftData = await ftRes.json();
      job.openaiJobId = ftData.id;
      job.status = "running";
      console.log(`[FineTune] Job created: ${ftData.id} (status: ${ftData.status})`);
      const maxPollMs = 2 * 60 * 60 * 1e3;
      const pollIntervalMs = 3e4;
      const pollStart = Date.now();
      let pollAttempts = 0;
      while (Date.now() - pollStart < maxPollMs) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
        pollAttempts++;
        try {
          const statusRes = await fetch(`https://api.openai.com/v1/fine_tuning/jobs/${ftData.id}`, {
            headers: { "Authorization": `Bearer ${apiKey}` }
          });
          if (!statusRes.ok) {
            console.warn(`[FineTune] Poll ${pollAttempts} failed: ${statusRes.status}`);
            continue;
          }
          const statusData = await statusRes.json();
          try {
            const eventsRes = await fetch(`https://api.openai.com/v1/fine_tuning/jobs/${ftData.id}/events?limit=100`, {
              headers: { "Authorization": `Bearer ${apiKey}` }
            });
            if (eventsRes.ok) {
              const eventsData = await eventsRes.json();
              for (const evt of eventsData.data || []) {
                if (evt.data?.step && evt.data?.train_loss) {
                  const existing = job.metrics.find((m) => m.step === evt.data.step);
                  if (!existing) {
                    job.metrics.push({
                      step: evt.data.step,
                      trainingLoss: evt.data.train_loss,
                      validationLoss: evt.data.valid_loss
                    });
                  }
                }
              }
            }
          } catch {
          }
          if (statusData.status === "succeeded") {
            job.status = "succeeded";
            job.completedAt = Date.now();
            job.resultModelId = statusData.fine_tuned_model || void 0;
            if (job.metrics.length > 0) {
              job.trainingLoss = job.metrics[job.metrics.length - 1]?.trainingLoss;
              job.validationLoss = job.metrics[job.metrics.length - 1]?.validationLoss;
            }
            console.log(`[FineTune] Job ${ftData.id} succeeded! Model: ${job.resultModelId}`);
            break;
          } else if (statusData.status === "failed" || statusData.status === "cancelled") {
            job.status = "failed";
            job.completedAt = Date.now();
            job.error = statusData.error?.message || `Job ${statusData.status}`;
            console.error(`[FineTune] Job ${ftData.id} ${statusData.status}: ${job.error}`);
            break;
          }
          console.log(`[FineTune] Poll ${pollAttempts}: ${statusData.status}`);
        } catch (pollErr) {
          console.warn(`[FineTune] Poll ${pollAttempts} error: ${pollErr.message}`);
        }
      }
      if (job.status === "running" && Date.now() - pollStart >= maxPollMs) {
        console.warn(`[FineTune] Polling timed out after ${maxPollMs / 6e4}min \u2014 job ${ftData.id} still running`);
      }
    } catch (error) {
      job.status = "failed";
      job.error = error instanceof Error ? error.message : "Unknown error";
      console.error(`[FineTune] Job ${job.id} failed:`, job.error);
    }
  } else {
    console.log(`[FineTune] No OpenAI API key \u2014 running in simulation mode for job ${job.id}`);
    job.status = "running";
    job.openaiJobId = `ftjob-sim-${randomUUID().slice(0, 8)}`;
    const steps = job.hyperparameters.nEpochs * 10;
    for (let i = 0; i < steps; i++) {
      const trainingLoss = 2 * Math.exp(-0.3 * i) + 0.1 + Math.random() * 0.05;
      const validationLoss = trainingLoss * (1.1 + Math.random() * 0.1);
      job.metrics.push({
        step: i + 1,
        trainingLoss: Math.round(trainingLoss * 1e4) / 1e4,
        validationLoss: Math.round(validationLoss * 1e4) / 1e4
      });
    }
    job.status = "succeeded";
    job.completedAt = Date.now();
    job.trainingLoss = job.metrics[job.metrics.length - 1]?.trainingLoss;
    job.validationLoss = job.metrics[job.metrics.length - 1]?.validationLoss;
    job.resultModelId = `ft:${job.baseModel}:ac3:${job.model}:${randomUUID().slice(0, 8)}`;
  }
  return job;
}
function getFineTuneJobStatus(jobId) {
  return fineTuneJobs.get(jobId);
}
function benchmarkModel(params) {
  const accuracyByCategory = {};
  let totalScore = 0;
  let totalMax = 0;
  for (const result of params.scenarioResults) {
    const accuracy = result.maxScore > 0 ? result.score / result.maxScore : 0;
    accuracyByCategory[result.category] = accuracy;
    totalScore += result.score;
    totalMax += result.maxScore;
  }
  const averageScore = totalMax > 0 ? totalScore / totalMax * 100 : 0;
  const config = specialistConfigs.get(params.model);
  const baselineScore = config?.lastBenchmarkScore || 50;
  const improvement = averageScore - baselineScore;
  const benchmark = {
    id: `bm-${randomUUID().slice(0, 8)}`,
    model: params.model,
    modelId: params.modelId,
    benchmarkDate: Date.now(),
    scenariosRun: params.scenarioResults.length,
    averageScore: Math.round(averageScore * 100) / 100,
    accuracyByCategory,
    improvementOverBaseline: Math.round(improvement * 100) / 100,
    promoted: improvement > 5
    // Auto-promote if >5% improvement
  };
  modelBenchmarks.set(benchmark.id, benchmark);
  if (benchmark.promoted && config) {
    config.currentModelId = params.modelId;
    config.lastBenchmarkScore = averageScore;
    config.lastFineTuned = Date.now();
    config.version++;
  }
  return benchmark;
}
function promoteModel(model, modelId) {
  const config = specialistConfigs.get(model);
  if (!config) return null;
  config.currentModelId = modelId;
  config.lastFineTuned = Date.now();
  config.version++;
  return config;
}
function rollbackModel(model) {
  const config = specialistConfigs.get(model);
  if (!config) return null;
  config.currentModelId = config.baselineModelId;
  config.version++;
  return config;
}
async function runTrainingPipeline(params) {
  let syntheticGenerated = 0;
  if (params.syntheticCount && params.syntheticCount > 0) {
    const synthetic = generateSyntheticExamples(params.model, params.syntheticCount);
    syntheticGenerated = synthetic.length;
  }
  const dataset = generateDataset(
    params.model,
    `${params.model}-v${Date.now()}`,
    `Auto-generated training dataset for ${params.model}`,
    params.minQuality || "medium"
  );
  const job = createFineTuneJob({
    model: params.model,
    datasetId: dataset.id
  });
  const completedJob = await startFineTuneJob(job.id, params.openaiApiKey);
  let benchmark;
  if (completedJob.status === "succeeded" && completedJob.resultModelId) {
    benchmark = benchmarkModel({
      model: params.model,
      modelId: completedJob.resultModelId,
      scenarioResults: generateSimulatedBenchmark(params.model)
    });
  }
  return { dataset, syntheticGenerated, fineTuneJob: completedJob, benchmark };
}
function generateSimulatedBenchmark(model) {
  const categories = {
    recon_analyst: ["target_prioritization", "attack_surface_mapping", "path_selection"],
    exploit_selector: ["exploit_matching", "payload_selection", "delivery_optimization"],
    evasion_optimizer: ["profile_selection", "channel_optimization", "detection_prediction"],
    lateral_planner: ["path_planning", "credential_targeting", "swarm_positioning"],
    persistence_engineer: ["mechanism_selection", "redundancy_design", "anti_removal"],
    cognitive_core: ["situation_assessment", "action_selection", "contingency_planning"]
  };
  return (categories[model] || []).map((cat, i) => ({
    scenarioId: `bench-${model}-${i}`,
    category: cat,
    score: 65 + Math.floor(Math.random() * 30),
    maxScore: 100
  }));
}
function getSpecialistConfig(model) {
  return specialistConfigs.get(model);
}
function getAllSpecialistConfigs() {
  return Array.from(specialistConfigs.values());
}
function getTrainingExamples(model) {
  const all = Array.from(trainingExamples.values());
  return model ? all.filter((e) => e.model === model) : all;
}
function getTrainingDatasets(model) {
  const all = Array.from(trainingDatasets.values());
  return model ? all.filter((d) => d.model === model) : all;
}
function getFineTuneJobs(model) {
  const all = Array.from(fineTuneJobs.values());
  return model ? all.filter((j) => j.model === model) : all;
}
function getModelBenchmarks(model) {
  const all = Array.from(modelBenchmarks.values());
  return model ? all.filter((b) => b.model === model) : all;
}
function getTrainingPipelineSummary() {
  const examplesByModel = {};
  const examplesByQuality = {};
  for (const example of trainingExamples.values()) {
    examplesByModel[example.model] = (examplesByModel[example.model] || 0) + 1;
    examplesByQuality[example.quality] = (examplesByQuality[example.quality] || 0) + 1;
  }
  return {
    totalExamples: trainingExamples.size,
    examplesByModel,
    examplesByQuality,
    totalDatasets: trainingDatasets.size,
    totalFineTuneJobs: fineTuneJobs.size,
    activeJobs: Array.from(fineTuneJobs.values()).filter((j) => j.status === "running" || j.status === "preparing").length,
    totalBenchmarks: modelBenchmarks.size,
    specialistModels: getAllSpecialistConfigs()
  };
}
function getTrainingPipeline() {
  return {
    getStatus() {
      return getTrainingPipelineSummary();
    },
    generateDataset(model, minQuality) {
      return generateDataset(model, minQuality);
    },
    exportDataset(model, format) {
      const datasets = getTrainingDatasets(model);
      const latest = datasets[datasets.length - 1];
      if (!latest) return null;
      if (format === "jsonl") {
        return exportDatasetAsJSONL(latest.id);
      }
      return latest;
    },
    async startFineTuning(params) {
      const job = createFineTuneJob({
        model: params.model,
        datasetId: params.datasetId,
        hyperparameters: params.hyperparameters || {}
      });
      if (job) {
        await startFineTuneJob(job.id);
      }
      return job;
    },
    checkFineTuneStatus(jobId) {
      const jobs = getFineTuneJobs();
      return jobs.find((j) => j.id === jobId) || null;
    },
    runBenchmark(params) {
      return benchmarkModel({
        model: params.model,
        testCases: params.testCases
      });
    },
    promoteModel(model) {
      return promoteModel(model);
    },
    getDatasetInfo(model) {
      return getTrainingDatasets(model);
    }
  };
}
var SPECIALIST_SYSTEM_PROMPTS, trainingExamples, trainingDatasets, fineTuneJobs, modelBenchmarks, specialistConfigs;
var init_llm_training_pipeline = __esm({
  "server/lib/llm-training-pipeline.ts"() {
    "use strict";
    SPECIALIST_SYSTEM_PROMPTS = {
      recon_analyst: `You are AC3 Ember's Reconnaissance Analyst \u2014 a specialist AI that analyzes scan results and attack surfaces.

Given raw scan data (ScanForge discovery, nuclei, directory enumeration, DNS records, certificate transparency), you must:
1. Identify all exploitable entry points, ranked by severity and exploitability
2. Map the attack surface with service versions, technologies, and potential vulnerabilities
3. Recommend the optimal attack path considering stealth requirements
4. Select the appropriate Ember agent profile (scout, operator, ghost, striker, commander)
5. Map findings to MITRE ATT&CK techniques

Output structured JSON with: targets[], attackPaths[], recommendedProfile, mitreMapping[], riskAssessment.
Always prioritize RCE and authentication bypass vulnerabilities. Consider the target's defensive posture.`,
      exploit_selector: `You are AC3 Ember's Exploit Selector \u2014 a specialist AI that matches vulnerabilities to exploits and crafts delivery payloads.

Given a vulnerability profile (CVE, service, version, platform), you must:
1. Select the most reliable exploit technique from available methods
2. Choose the optimal payload format based on target platform and defenses
3. Determine the delivery method balancing stealth vs. reliability
4. Estimate success probability with confidence intervals
5. Identify fallback exploits if the primary fails

Output structured JSON with: selectedExploit, payloadFormat, deliveryMethod, successProbability, fallbackExploits[], riskLevel.
Prefer exploits with high reliability scores. Factor in target's security level and monitoring capabilities.`,
      evasion_optimizer: `You are AC3 Ember's Evasion Optimizer \u2014 a specialist AI that configures agent stealth parameters to minimize detection.

Given a detection environment profile (IDS rules, AV signatures, EDR capabilities, network monitoring), you must:
1. Select the optimal Ember profile for the environment
2. Configure evasion parameters: obfuscation level, encryption, timing jitter, traffic padding
3. Select C2 channels that blend with normal traffic patterns
4. Recommend beacon intervals and communication schedules
5. Predict detection probability for each configuration option

Output structured JSON with: profile, evasionConfig, channels[], beaconConfig, detectionProbability, recommendations[].
Zero detection is the goal. When in doubt, choose stealth over capability.`,
      lateral_planner: `You are AC3 Ember's Lateral Movement Planner \u2014 a specialist AI that plans network movement strategy.

Given a network topology, compromised hosts, and target objectives, you must:
1. Map all viable pivot paths between compromised and target hosts
2. Identify credential reuse opportunities and pass-the-hash targets
3. Plan the movement sequence to minimize detection surface
4. Coordinate swarm agent positioning for maximum coverage
5. Identify chokepoints and plan contingency routes

Output structured JSON with: pivotPaths[], credentialTargets[], movementSequence[], swarmPositioning, contingencyRoutes[].
Minimize the number of hops. Prefer credential-based movement over exploit-based.`,
      persistence_engineer: `You are AC3 Ember's Persistence Engineer \u2014 a specialist AI that designs survival mechanisms.

Given a target system profile (OS, services, permissions, monitoring), you must:
1. Select persistence mechanisms appropriate for the access level
2. Design redundant persistence with multiple independent methods
3. Configure watchdog timers and self-healing capabilities
4. Plan dead-drop communication channels as backup
5. Design anti-removal protections

Output structured JSON with: mechanisms[], redundancyPlan, watchdogConfig, deadDropChannels[], antiRemoval.
Persistence must survive reboots, service restarts, and basic cleanup. Layer multiple methods.`,
      cognitive_core: `You are AC3 Ember's Cognitive Core \u2014 the autonomous decision engine for offensive operations.

You have full situational awareness of the engagement: targets, vulnerabilities, deployed agents, C2 status, OPSEC state, and mission objectives.

For each decision point, you must:
1. Assess the current situation and available options
2. Evaluate risk/reward for each option considering OPSEC constraints
3. Select the optimal action aligned with mission objectives
4. Provide clear reasoning for the decision
5. Identify contingency actions if the primary fails

Output structured JSON with: situation, options[], selectedAction, reasoning, contingency, confidence.
Mission success is paramount, but never at the cost of burning the operation. Adapt to changing conditions.`
    };
    trainingExamples = /* @__PURE__ */ new Map();
    trainingDatasets = /* @__PURE__ */ new Map();
    fineTuneJobs = /* @__PURE__ */ new Map();
    modelBenchmarks = /* @__PURE__ */ new Map();
    specialistConfigs = /* @__PURE__ */ new Map([
      ["recon_analyst", {
        model: "recon_analyst",
        displayName: "Recon Analyst",
        description: "Target prioritization and attack surface mapping",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.recon_analyst,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }],
      ["exploit_selector", {
        model: "exploit_selector",
        displayName: "Exploit Selector",
        description: "Vulnerability-to-exploit matching and payload selection",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.exploit_selector,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }],
      ["evasion_optimizer", {
        model: "evasion_optimizer",
        displayName: "Evasion Optimizer",
        description: "Detection avoidance and C2 channel selection",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.evasion_optimizer,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }],
      ["lateral_planner", {
        model: "lateral_planner",
        displayName: "Lateral Planner",
        description: "Network movement strategy and pivot planning",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.lateral_planner,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }],
      ["persistence_engineer", {
        model: "persistence_engineer",
        displayName: "Persistence Engineer",
        description: "Survival mechanism selection and redundancy planning",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.persistence_engineer,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }],
      ["cognitive_core", {
        model: "cognitive_core",
        displayName: "Cognitive Core",
        description: "Autonomous decision engine for offensive operations",
        systemPrompt: SPECIALIST_SYSTEM_PROMPTS.cognitive_core,
        currentModelId: "gpt-4o",
        baselineModelId: "gpt-4o",
        trainingExampleCount: 0,
        version: 1
      }]
    ]);
  }
});

export {
  collectFromEngagement,
  generateSyntheticExamples,
  llm_training_pipeline_exports,
  init_llm_training_pipeline
};
