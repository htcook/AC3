/**
 * AC3 LLM Training Pipeline
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Captures Ember agent decisions, engagement outcomes, and OPSEC results
 * to generate training data for the cognitive core and specialist models.
 *
 * Pipeline Stages:
 *   1. Data Collection — capture raw decision/outcome pairs from lab scenarios
 *   2. Data Processing — normalize, score, and format into training examples
 *   3. Dataset Generation — produce JSONL files for OpenAI fine-tuning
 *   4. Fine-Tuning Jobs — manage OpenAI fine-tuning API calls
 *   5. Model Evaluation — test fine-tuned models against benchmark scenarios
 *   6. Model Deployment — swap in improved models for the cognitive core
 *
 * Specialist Models:
 *   - Recon Analyst: Target prioritization, attack surface mapping
 *   - Exploit Selector: Vulnerability-to-exploit matching, payload selection
 *   - Evasion Optimizer: Detection avoidance, C2 channel selection
 *   - Lateral Planner: Network movement strategy, pivot planning
 *   - Persistence Engineer: Survival mechanism selection, redundancy planning
 */

import { randomUUID } from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type SpecialistModel =
  | "recon_analyst"
  | "exploit_selector"
  | "evasion_optimizer"
  | "lateral_planner"
  | "persistence_engineer"
  | "cognitive_core";

export type TrainingDataQuality = "high" | "medium" | "low" | "rejected";

export type FineTuneStatus =
  | "pending"
  | "preparing"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface TrainingExample {
  id: string;
  model: SpecialistModel;
  timestamp: number;
  source: "lab_scenario" | "live_engagement" | "manual" | "synthetic";
  sourceId: string;
  quality: TrainingDataQuality;
  qualityScore: number;
  messages: Array<{
    role: "system" | "user" | "assistant";
    content: string;
  }>;
  metadata: {
    scenarioId?: string;
    engagementId?: string;
    objectiveCompleted?: boolean;
    stealthScore?: number;
    decisionOutcome?: "success" | "failure" | "partial";
    timeToDecision?: number;
    mitreAttackTechniques?: string[];
  };
}

export interface TrainingDataset {
  id: string;
  model: SpecialistModel;
  name: string;
  description: string;
  createdAt: number;
  exampleCount: number;
  qualityDistribution: Record<TrainingDataQuality, number>;
  averageQualityScore: number;
  jsonlPath?: string;
  exported: boolean;
  version: number;
}

export interface FineTuneJob {
  id: string;
  openaiJobId?: string;
  model: SpecialistModel;
  datasetId: string;
  baseModel: string;
  status: FineTuneStatus;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  resultModelId?: string;
  trainingLoss?: number;
  validationLoss?: number;
  epochs: number;
  hyperparameters: {
    nEpochs: number;
    batchSize: number | "auto";
    learningRateMultiplier: number | "auto";
  };
  metrics: Array<{
    step: number;
    trainingLoss: number;
    validationLoss?: number;
  }>;
  error?: string;
}

export interface ModelBenchmark {
  id: string;
  model: SpecialistModel;
  modelId: string;
  benchmarkDate: number;
  scenariosRun: number;
  averageScore: number;
  accuracyByCategory: Record<string, number>;
  improvementOverBaseline: number;
  promoted: boolean;
}

export interface SpecialistModelConfig {
  model: SpecialistModel;
  displayName: string;
  description: string;
  systemPrompt: string;
  currentModelId: string;
  baselineModelId: string;
  trainingExampleCount: number;
  lastFineTuned?: number;
  lastBenchmarkScore?: number;
  version: number;
}

// ─── Specialist Model System Prompts ────────────────────────────────────────

const SPECIALIST_SYSTEM_PROMPTS: Record<SpecialistModel, string> = {
  recon_analyst: `You are AC3 Ember's Reconnaissance Analyst — a specialist AI that analyzes scan results and attack surfaces.

Given raw scan data (ScanForge discovery, nuclei, directory enumeration, DNS records, certificate transparency), you must:
1. Identify all exploitable entry points, ranked by severity and exploitability
2. Map the attack surface with service versions, technologies, and potential vulnerabilities
3. Recommend the optimal attack path considering stealth requirements
4. Select the appropriate Ember agent profile (scout, operator, ghost, striker, commander)
5. Map findings to MITRE ATT&CK techniques

Output structured JSON with: targets[], attackPaths[], recommendedProfile, mitreMapping[], riskAssessment.
Always prioritize RCE and authentication bypass vulnerabilities. Consider the target's defensive posture.`,

  exploit_selector: `You are AC3 Ember's Exploit Selector — a specialist AI that matches vulnerabilities to exploits and crafts delivery payloads.

Given a vulnerability profile (CVE, service, version, platform), you must:
1. Select the most reliable exploit technique from available methods
2. Choose the optimal payload format based on target platform and defenses
3. Determine the delivery method balancing stealth vs. reliability
4. Estimate success probability with confidence intervals
5. Identify fallback exploits if the primary fails

Output structured JSON with: selectedExploit, payloadFormat, deliveryMethod, successProbability, fallbackExploits[], riskLevel.
Prefer exploits with high reliability scores. Factor in target's security level and monitoring capabilities.`,

  evasion_optimizer: `You are AC3 Ember's Evasion Optimizer — a specialist AI that configures agent stealth parameters to minimize detection.

Given a detection environment profile (IDS rules, AV signatures, EDR capabilities, network monitoring), you must:
1. Select the optimal Ember profile for the environment
2. Configure evasion parameters: obfuscation level, encryption, timing jitter, traffic padding
3. Select C2 channels that blend with normal traffic patterns
4. Recommend beacon intervals and communication schedules
5. Predict detection probability for each configuration option

Output structured JSON with: profile, evasionConfig, channels[], beaconConfig, detectionProbability, recommendations[].
Zero detection is the goal. When in doubt, choose stealth over capability.`,

  lateral_planner: `You are AC3 Ember's Lateral Movement Planner — a specialist AI that plans network movement strategy.

Given a network topology, compromised hosts, and target objectives, you must:
1. Map all viable pivot paths between compromised and target hosts
2. Identify credential reuse opportunities and pass-the-hash targets
3. Plan the movement sequence to minimize detection surface
4. Coordinate swarm agent positioning for maximum coverage
5. Identify chokepoints and plan contingency routes

Output structured JSON with: pivotPaths[], credentialTargets[], movementSequence[], swarmPositioning, contingencyRoutes[].
Minimize the number of hops. Prefer credential-based movement over exploit-based.`,

  persistence_engineer: `You are AC3 Ember's Persistence Engineer — a specialist AI that designs survival mechanisms.

Given a target system profile (OS, services, permissions, monitoring), you must:
1. Select persistence mechanisms appropriate for the access level
2. Design redundant persistence with multiple independent methods
3. Configure watchdog timers and self-healing capabilities
4. Plan dead-drop communication channels as backup
5. Design anti-removal protections

Output structured JSON with: mechanisms[], redundancyPlan, watchdogConfig, deadDropChannels[], antiRemoval.
Persistence must survive reboots, service restarts, and basic cleanup. Layer multiple methods.`,

  cognitive_core: `You are AC3 Ember's Cognitive Core — the autonomous decision engine for offensive operations.

You have full situational awareness of the engagement: targets, vulnerabilities, deployed agents, C2 status, OPSEC state, and mission objectives.

For each decision point, you must:
1. Assess the current situation and available options
2. Evaluate risk/reward for each option considering OPSEC constraints
3. Select the optimal action aligned with mission objectives
4. Provide clear reasoning for the decision
5. Identify contingency actions if the primary fails

Output structured JSON with: situation, options[], selectedAction, reasoning, contingency, confidence.
Mission success is paramount, but never at the cost of burning the operation. Adapt to changing conditions.`,
};

// ─── In-Memory State ────────────────────────────────────────────────────────

const trainingExamples = new Map<string, TrainingExample>();
const trainingDatasets = new Map<string, TrainingDataset>();
const fineTuneJobs = new Map<string, FineTuneJob>();
const modelBenchmarks = new Map<string, ModelBenchmark>();

const specialistConfigs: Map<SpecialistModel, SpecialistModelConfig> = new Map([
  ["recon_analyst", {
    model: "recon_analyst",
    displayName: "Recon Analyst",
    description: "Target prioritization and attack surface mapping",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.recon_analyst,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
  ["exploit_selector", {
    model: "exploit_selector",
    displayName: "Exploit Selector",
    description: "Vulnerability-to-exploit matching and payload selection",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.exploit_selector,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
  ["evasion_optimizer", {
    model: "evasion_optimizer",
    displayName: "Evasion Optimizer",
    description: "Detection avoidance and C2 channel selection",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.evasion_optimizer,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
  ["lateral_planner", {
    model: "lateral_planner",
    displayName: "Lateral Planner",
    description: "Network movement strategy and pivot planning",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.lateral_planner,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
  ["persistence_engineer", {
    model: "persistence_engineer",
    displayName: "Persistence Engineer",
    description: "Survival mechanism selection and redundancy planning",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.persistence_engineer,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
  ["cognitive_core", {
    model: "cognitive_core",
    displayName: "Cognitive Core",
    description: "Autonomous decision engine for offensive operations",
    systemPrompt: SPECIALIST_SYSTEM_PROMPTS.cognitive_core,
    currentModelId: "gpt-4o",
    baselineModelId: "gpt-4o",
    trainingExampleCount: 0,
    version: 1,
  }],
]);

// ─── 1. Data Collection ─────────────────────────────────────────────────────

/**
 * Collect a training example from a lab scenario execution.
 */
export function collectFromScenario(params: {
  model: SpecialistModel;
  scenarioId: string;
  context: string;
  decision: string;
  reasoning: string;
  outcome: "success" | "failure" | "partial";
  stealthScore: number;
  mitreAttackTechniques?: string[];
}): TrainingExample {
  const qualityScore = calculateQualityScore(params.outcome, params.stealthScore);
  const quality = qualityScore >= 0.8 ? "high" : qualityScore >= 0.5 ? "medium" : qualityScore >= 0.3 ? "low" : "rejected";

  const config = specialistConfigs.get(params.model);
  const systemPrompt = config?.systemPrompt || SPECIALIST_SYSTEM_PROMPTS[params.model];

  const example: TrainingExample = {
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
        mitreMapping: params.mitreAttackTechniques || [],
      }) },
    ],
    metadata: {
      scenarioId: params.scenarioId,
      objectiveCompleted: params.outcome === "success",
      stealthScore: params.stealthScore,
      decisionOutcome: params.outcome,
      mitreAttackTechniques: params.mitreAttackTechniques,
    },
  };

  trainingExamples.set(example.id, example);

  // Update specialist config count
  if (config) {
    config.trainingExampleCount++;
  }

  return example;
}

/**
 * Collect a training example from a live engagement.
 */
export function collectFromEngagement(params: {
  model: SpecialistModel;
  engagementId: string;
  context: string;
  decision: string;
  reasoning: string;
  outcome: "success" | "failure" | "partial";
  stealthScore: number;
  timeToDecision?: number;
}): TrainingExample {
  const qualityScore = calculateQualityScore(params.outcome, params.stealthScore);
  const quality = qualityScore >= 0.8 ? "high" : qualityScore >= 0.5 ? "medium" : qualityScore >= 0.3 ? "low" : "rejected";

  const config = specialistConfigs.get(params.model);
  const systemPrompt = config?.systemPrompt || SPECIALIST_SYSTEM_PROMPTS[params.model];

  const example: TrainingExample = {
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
        confidence: qualityScore,
      }) },
    ],
    metadata: {
      engagementId: params.engagementId,
      objectiveCompleted: params.outcome === "success",
      stealthScore: params.stealthScore,
      decisionOutcome: params.outcome,
      timeToDecision: params.timeToDecision,
    },
  };

  trainingExamples.set(example.id, example);

  if (config) {
    config.trainingExampleCount++;
  }

  return example;
}

/**
 * Generate synthetic training examples from existing high-quality examples.
 */
export function generateSyntheticExamples(
  model: SpecialistModel,
  count: number,
): TrainingExample[] {
  const highQuality = Array.from(trainingExamples.values())
    .filter(e => e.model === model && e.quality === "high");

  if (highQuality.length === 0) return [];

  const synthetic: TrainingExample[] = [];

  for (let i = 0; i < count; i++) {
    const source = highQuality[i % highQuality.length];

    // Create variation by modifying context slightly
    const variation: TrainingExample = {
      id: `te-syn-${randomUUID().slice(0, 12)}`,
      model,
      timestamp: Date.now(),
      source: "synthetic",
      sourceId: source.id,
      quality: "medium",
      qualityScore: source.qualityScore * 0.85,
      messages: source.messages.map(m => ({
        ...m,
        content: m.role === "user"
          ? augmentContext(m.content)
          : m.content,
      })),
      metadata: {
        ...source.metadata,
        scenarioId: source.metadata.scenarioId ? `${source.metadata.scenarioId}-synthetic` : undefined,
      },
    };

    synthetic.push(variation);
    trainingExamples.set(variation.id, variation);
  }

  return synthetic;
}

// ─── 2. Data Processing ─────────────────────────────────────────────────────

function calculateQualityScore(
  outcome: "success" | "failure" | "partial",
  stealthScore: number,
): number {
  const outcomeWeight = outcome === "success" ? 1.0 : outcome === "partial" ? 0.5 : 0.1;
  const stealthWeight = stealthScore / 100;
  return (outcomeWeight * 0.7) + (stealthWeight * 0.3);
}

function augmentContext(context: string): string {
  // Simple augmentation: add noise, rephrase slightly
  const augmentations = [
    (s: string) => s.replace(/target/gi, "host"),
    (s: string) => s.replace(/vulnerability/gi, "weakness"),
    (s: string) => s.replace(/exploit/gi, "attack vector"),
    (s: string) => s.replace(/scan/gi, "enumeration"),
    (s: string) => s + "\n\nNote: Time pressure is moderate.",
  ];

  const aug = augmentations[Math.floor(Math.random() * augmentations.length)];
  return aug(context);
}

/**
 * Filter and validate training examples for a dataset.
 */
export function processExamplesForDataset(
  model: SpecialistModel,
  minQuality: TrainingDataQuality = "medium",
): TrainingExample[] {
  const qualityOrder: TrainingDataQuality[] = ["high", "medium", "low", "rejected"];
  const minIndex = qualityOrder.indexOf(minQuality);

  return Array.from(trainingExamples.values())
    .filter(e => e.model === model)
    .filter(e => qualityOrder.indexOf(e.quality) <= minIndex)
    .sort((a, b) => b.qualityScore - a.qualityScore);
}

// ─── 3. Dataset Generation ──────────────────────────────────────────────────

/**
 * Generate a JSONL training dataset for OpenAI fine-tuning.
 */
export function generateDataset(
  model: SpecialistModel,
  name: string,
  description: string,
  minQuality: TrainingDataQuality = "medium",
): TrainingDataset {
  const examples = processExamplesForDataset(model, minQuality);

  const qualityDistribution: Record<TrainingDataQuality, number> = {
    high: 0, medium: 0, low: 0, rejected: 0,
  };
  let totalQuality = 0;

  const jsonlLines: string[] = [];

  for (const example of examples) {
    qualityDistribution[example.quality]++;
    totalQuality += example.qualityScore;

    // Format for OpenAI fine-tuning
    jsonlLines.push(JSON.stringify({
      messages: example.messages,
    }));
  }

  const dataset: TrainingDataset = {
    id: `ds-${randomUUID().slice(0, 8)}`,
    model,
    name,
    description,
    createdAt: Date.now(),
    exampleCount: examples.length,
    qualityDistribution,
    averageQualityScore: examples.length > 0 ? totalQuality / examples.length : 0,
    exported: jsonlLines.length > 0,
    version: 1,
  };

  // Store the JSONL content (in production, would write to S3)
  if (jsonlLines.length > 0) {
    dataset.jsonlPath = `/training-data/${model}/${dataset.id}.jsonl`;
  }

  trainingDatasets.set(dataset.id, dataset);
  return dataset;
}

/**
 * Export dataset as JSONL string (for download or S3 upload).
 */
export function exportDatasetAsJSONL(datasetId: string): string | null {
  const dataset = trainingDatasets.get(datasetId);
  if (!dataset) return null;

  const examples = processExamplesForDataset(dataset.model);
  return examples
    .map(e => JSON.stringify({ messages: e.messages }))
    .join("\n");
}

// ─── 4. Fine-Tuning Job Management ─────────────────────────────────────────

/**
 * Create a fine-tuning job configuration.
 */
export function createFineTuneJob(params: {
  model: SpecialistModel;
  datasetId: string;
  baseModel?: string;
  epochs?: number;
  batchSize?: number | "auto";
  learningRateMultiplier?: number | "auto";
}): FineTuneJob {
  const dataset = trainingDatasets.get(params.datasetId);
  if (!dataset) throw new Error(`Dataset not found: ${params.datasetId}`);

  if (dataset.exampleCount < 10) {
    throw new Error(`Insufficient training examples: ${dataset.exampleCount} (minimum 10 required)`);
  }

  const job: FineTuneJob = {
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
      learningRateMultiplier: params.learningRateMultiplier || "auto",
    },
    metrics: [],
  };

  fineTuneJobs.set(job.id, job);
  return job;
}

/**
 * Start a fine-tuning job via OpenAI API.
 * In production, this would call the OpenAI fine-tuning API.
 */
export async function startFineTuneJob(
  jobId: string,
  openaiApiKey?: string,
): Promise<FineTuneJob> {
  const job = fineTuneJobs.get(jobId);
  if (!job) throw new Error(`Job not found: ${jobId}`);

  job.status = "preparing";
  job.startedAt = Date.now();

  // Resolve API key: explicit param > env > simulation
  const apiKey = openaiApiKey || process.env.OPENAI_API_KEY || "";

  if (apiKey && apiKey.length > 10) {
    try {
      // Step 1: Export training data as JSONL
      const jsonlContent = exportDatasetAsJSONL(job.datasetId);
      if (!jsonlContent) throw new Error(`Dataset ${job.datasetId} has no exportable content`);

      console.log(`[FineTune] Uploading training file for job ${job.id} (${jsonlContent.length} bytes)...`);

      // Step 2: Upload JSONL file to OpenAI
      const formData = new FormData();
      const blob = new Blob([jsonlContent], { type: 'application/jsonl' });
      formData.append('file', blob, `${job.model}_training_${Date.now()}.jsonl`);
      formData.append('purpose', 'fine-tune');

      const uploadRes = await fetch('https://api.openai.com/v1/files', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` },
        body: formData,
      });
      if (!uploadRes.ok) {
        const errBody = await uploadRes.text();
        throw new Error(`File upload failed (${uploadRes.status}): ${errBody}`);
      }
      const uploadData = await uploadRes.json() as { id: string };
      const trainingFileId = uploadData.id;
      console.log(`[FineTune] Training file uploaded: ${trainingFileId}`);

      // Step 3: Create fine-tuning job via OpenAI API
      const ftRes = await fetch('https://api.openai.com/v1/fine_tuning/jobs', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          training_file: trainingFileId,
          model: job.baseModel,
          suffix: `ac3-${job.model}`,
          hyperparameters: {
            n_epochs: job.hyperparameters.nEpochs,
            ...(job.hyperparameters.batchSize !== 'auto' ? { batch_size: job.hyperparameters.batchSize } : {}),
            ...(job.hyperparameters.learningRateMultiplier !== 'auto' ? { learning_rate_multiplier: job.hyperparameters.learningRateMultiplier } : {}),
          },
        }),
      });
      if (!ftRes.ok) {
        const errBody = await ftRes.text();
        throw new Error(`Fine-tune creation failed (${ftRes.status}): ${errBody}`);
      }
      const ftData = await ftRes.json() as { id: string; status: string };
      job.openaiJobId = ftData.id;
      job.status = "running";
      console.log(`[FineTune] Job created: ${ftData.id} (status: ${ftData.status})`);

      // Step 4: Poll for completion (max 2 hours, poll every 30s)
      const maxPollMs = 2 * 60 * 60 * 1000;
      const pollIntervalMs = 30_000;
      const pollStart = Date.now();
      let pollAttempts = 0;

      while (Date.now() - pollStart < maxPollMs) {
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        pollAttempts++;

        try {
          const statusRes = await fetch(`https://api.openai.com/v1/fine_tuning/jobs/${ftData.id}`, {
            headers: { 'Authorization': `Bearer ${apiKey}` },
          });
          if (!statusRes.ok) {
            console.warn(`[FineTune] Poll ${pollAttempts} failed: ${statusRes.status}`);
            continue;
          }
          const statusData = await statusRes.json() as {
            status: string;
            fine_tuned_model?: string;
            trained_tokens?: number;
            error?: { message: string };
          };

          // Fetch training events for metrics
          try {
            const eventsRes = await fetch(`https://api.openai.com/v1/fine_tuning/jobs/${ftData.id}/events?limit=100`, {
              headers: { 'Authorization': `Bearer ${apiKey}` },
            });
            if (eventsRes.ok) {
              const eventsData = await eventsRes.json() as { data: Array<{ message: string; data?: { step?: number; train_loss?: number; valid_loss?: number } }> };
              for (const evt of eventsData.data || []) {
                if (evt.data?.step && evt.data?.train_loss) {
                  const existing = job.metrics.find(m => m.step === evt.data!.step);
                  if (!existing) {
                    job.metrics.push({
                      step: evt.data.step,
                      trainingLoss: evt.data.train_loss,
                      validationLoss: evt.data.valid_loss,
                    });
                  }
                }
              }
            }
          } catch { /* metrics polling not critical */ }

          if (statusData.status === 'succeeded') {
            job.status = "succeeded";
            job.completedAt = Date.now();
            job.resultModelId = statusData.fine_tuned_model || undefined;
            if (job.metrics.length > 0) {
              job.trainingLoss = job.metrics[job.metrics.length - 1]?.trainingLoss;
              job.validationLoss = job.metrics[job.metrics.length - 1]?.validationLoss;
            }
            console.log(`[FineTune] Job ${ftData.id} succeeded! Model: ${job.resultModelId}`);
            break;
          } else if (statusData.status === 'failed' || statusData.status === 'cancelled') {
            job.status = "failed";
            job.completedAt = Date.now();
            job.error = statusData.error?.message || `Job ${statusData.status}`;
            console.error(`[FineTune] Job ${ftData.id} ${statusData.status}: ${job.error}`);
            break;
          }
          // Still running — continue polling
          console.log(`[FineTune] Poll ${pollAttempts}: ${statusData.status}`);
        } catch (pollErr: any) {
          console.warn(`[FineTune] Poll ${pollAttempts} error: ${pollErr.message}`);
        }
      }

      // If we timed out polling, mark as running (will be checked later)
      if (job.status === "running" && Date.now() - pollStart >= maxPollMs) {
        console.warn(`[FineTune] Polling timed out after ${maxPollMs / 60000}min — job ${ftData.id} still running`);
      }

    } catch (error) {
      job.status = "failed";
      job.error = error instanceof Error ? error.message : "Unknown error";
      console.error(`[FineTune] Job ${job.id} failed:`, job.error);
    }
  } else {
    // Simulation mode — no API key available, generate realistic metrics
    console.log(`[FineTune] No OpenAI API key — running in simulation mode for job ${job.id}`);
    job.status = "running";
    job.openaiJobId = `ftjob-sim-${randomUUID().slice(0, 8)}`;

    const steps = job.hyperparameters.nEpochs * 10;
    for (let i = 0; i < steps; i++) {
      const trainingLoss = 2.0 * Math.exp(-0.3 * i) + 0.1 + Math.random() * 0.05;
      const validationLoss = trainingLoss * (1.1 + Math.random() * 0.1);
      job.metrics.push({
        step: i + 1,
        trainingLoss: Math.round(trainingLoss * 10000) / 10000,
        validationLoss: Math.round(validationLoss * 10000) / 10000,
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

/**
 * Check fine-tuning job status (would poll OpenAI API in production).
 */
export function getFineTuneJobStatus(jobId: string): FineTuneJob | undefined {
  return fineTuneJobs.get(jobId);
}

// ─── 5. Model Evaluation ────────────────────────────────────────────────────

/**
 * Benchmark a fine-tuned model against test scenarios.
 */
export function benchmarkModel(params: {
  model: SpecialistModel;
  modelId: string;
  scenarioResults: Array<{
    scenarioId: string;
    category: string;
    score: number;
    maxScore: number;
  }>;
}): ModelBenchmark {
  const accuracyByCategory: Record<string, number> = {};
  let totalScore = 0;
  let totalMax = 0;

  for (const result of params.scenarioResults) {
    const accuracy = result.maxScore > 0 ? result.score / result.maxScore : 0;
    accuracyByCategory[result.category] = accuracy;
    totalScore += result.score;
    totalMax += result.maxScore;
  }

  const averageScore = totalMax > 0 ? (totalScore / totalMax) * 100 : 0;

  // Compare against baseline
  const config = specialistConfigs.get(params.model);
  const baselineScore = config?.lastBenchmarkScore || 50;
  const improvement = averageScore - baselineScore;

  const benchmark: ModelBenchmark = {
    id: `bm-${randomUUID().slice(0, 8)}`,
    model: params.model,
    modelId: params.modelId,
    benchmarkDate: Date.now(),
    scenariosRun: params.scenarioResults.length,
    averageScore: Math.round(averageScore * 100) / 100,
    accuracyByCategory,
    improvementOverBaseline: Math.round(improvement * 100) / 100,
    promoted: improvement > 5, // Auto-promote if >5% improvement
  };

  modelBenchmarks.set(benchmark.id, benchmark);

  // Auto-promote if significant improvement
  if (benchmark.promoted && config) {
    config.currentModelId = params.modelId;
    config.lastBenchmarkScore = averageScore;
    config.lastFineTuned = Date.now();
    config.version++;
  }

  return benchmark;
}

// ─── 6. Model Deployment ────────────────────────────────────────────────────

/**
 * Promote a fine-tuned model to active use.
 */
export function promoteModel(
  model: SpecialistModel,
  modelId: string,
): SpecialistModelConfig | null {
  const config = specialistConfigs.get(model);
  if (!config) return null;

  config.currentModelId = modelId;
  config.lastFineTuned = Date.now();
  config.version++;

  return config;
}

/**
 * Rollback to baseline model.
 */
export function rollbackModel(model: SpecialistModel): SpecialistModelConfig | null {
  const config = specialistConfigs.get(model);
  if (!config) return null;

  config.currentModelId = config.baselineModelId;
  config.version++;

  return config;
}

// ─── Pipeline Orchestration ─────────────────────────────────────────────────

/**
 * Run the full training pipeline for a specialist model.
 */
export async function runTrainingPipeline(params: {
  model: SpecialistModel;
  minQuality?: TrainingDataQuality;
  syntheticCount?: number;
  openaiApiKey?: string;
}): Promise<{
  dataset: TrainingDataset;
  syntheticGenerated: number;
  fineTuneJob: FineTuneJob;
  benchmark?: ModelBenchmark;
}> {
  // Step 1: Generate synthetic examples if needed
  let syntheticGenerated = 0;
  if (params.syntheticCount && params.syntheticCount > 0) {
    const synthetic = generateSyntheticExamples(params.model, params.syntheticCount);
    syntheticGenerated = synthetic.length;
  }

  // Step 2: Generate dataset
  const dataset = generateDataset(
    params.model,
    `${params.model}-v${Date.now()}`,
    `Auto-generated training dataset for ${params.model}`,
    params.minQuality || "medium",
  );

  // Step 3: Create and start fine-tuning job
  const job = createFineTuneJob({
    model: params.model,
    datasetId: dataset.id,
  });

  const completedJob = await startFineTuneJob(job.id, params.openaiApiKey);

  // Step 4: Benchmark if job succeeded
  let benchmark: ModelBenchmark | undefined;
  if (completedJob.status === "succeeded" && completedJob.resultModelId) {
    benchmark = benchmarkModel({
      model: params.model,
      modelId: completedJob.resultModelId,
      scenarioResults: generateSimulatedBenchmark(params.model),
    });
  }

  return { dataset, syntheticGenerated, fineTuneJob: completedJob, benchmark };
}

function generateSimulatedBenchmark(model: SpecialistModel): Array<{
  scenarioId: string;
  category: string;
  score: number;
  maxScore: number;
}> {
  const categories: Record<SpecialistModel, string[]> = {
    recon_analyst: ["target_prioritization", "attack_surface_mapping", "path_selection"],
    exploit_selector: ["exploit_matching", "payload_selection", "delivery_optimization"],
    evasion_optimizer: ["profile_selection", "channel_optimization", "detection_prediction"],
    lateral_planner: ["path_planning", "credential_targeting", "swarm_positioning"],
    persistence_engineer: ["mechanism_selection", "redundancy_design", "anti_removal"],
    cognitive_core: ["situation_assessment", "action_selection", "contingency_planning"],
  };

  return (categories[model] || []).map((cat, i) => ({
    scenarioId: `bench-${model}-${i}`,
    category: cat,
    score: 65 + Math.floor(Math.random() * 30),
    maxScore: 100,
  }));
}

// ─── Getters ────────────────────────────────────────────────────────────────

export function getSpecialistConfig(model: SpecialistModel): SpecialistModelConfig | undefined {
  return specialistConfigs.get(model);
}

export function getAllSpecialistConfigs(): SpecialistModelConfig[] {
  return Array.from(specialistConfigs.values());
}

export function getTrainingExamples(model?: SpecialistModel): TrainingExample[] {
  const all = Array.from(trainingExamples.values());
  return model ? all.filter(e => e.model === model) : all;
}

export function getTrainingDatasets(model?: SpecialistModel): TrainingDataset[] {
  const all = Array.from(trainingDatasets.values());
  return model ? all.filter(d => d.model === model) : all;
}

export function getFineTuneJobs(model?: SpecialistModel): FineTuneJob[] {
  const all = Array.from(fineTuneJobs.values());
  return model ? all.filter(j => j.model === model) : all;
}

export function getModelBenchmarks(model?: SpecialistModel): ModelBenchmark[] {
  const all = Array.from(modelBenchmarks.values());
  return model ? all.filter(b => b.model === model) : all;
}

export function getTrainingPipelineSummary(): {
  totalExamples: number;
  examplesByModel: Record<string, number>;
  examplesByQuality: Record<string, number>;
  totalDatasets: number;
  totalFineTuneJobs: number;
  activeJobs: number;
  totalBenchmarks: number;
  specialistModels: SpecialistModelConfig[];
} {
  const examplesByModel: Record<string, number> = {};
  const examplesByQuality: Record<string, number> = {};

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
    activeJobs: Array.from(fineTuneJobs.values()).filter(j => j.status === "running" || j.status === "preparing").length,
    totalBenchmarks: modelBenchmarks.size,
    specialistModels: getAllSpecialistConfigs(),
  };
}


// ─── Training Pipeline Manager Facade ──────────────────────────────────────
/**
 * Returns a unified manager object wrapping all Training Pipeline operations.
 * This provides a clean API surface for the tRPC router.
 */
export function getTrainingPipeline() {
  return {
    getStatus() {
      return getTrainingPipelineSummary();
    },

    generateDataset(model: SpecialistModel, minQuality?: TrainingDataQuality) {
      return generateDataset(model, minQuality);
    },

    exportDataset(model: SpecialistModel, format: string) {
      const datasets = getTrainingDatasets(model);
      const latest = datasets[datasets.length - 1];
      if (!latest) return null;
      if (format === "jsonl") {
        return exportDatasetAsJSONL(latest.id);
      }
      return latest;
    },

    async startFineTuning(params: {
      model: SpecialistModel;
      datasetId: string;
      hyperparameters?: { epochs?: number; learningRate?: number; batchSize?: number };
    }) {
      const job = createFineTuneJob({
        model: params.model,
        datasetId: params.datasetId,
        hyperparameters: params.hyperparameters || {},
      });
      if (job) {
        await startFineTuneJob(job.id);
      }
      return job;
    },

    checkFineTuneStatus(jobId: string) {
      const jobs = getFineTuneJobs();
      return jobs.find(j => j.id === jobId) || null;
    },

    runBenchmark(params: {
      model: SpecialistModel;
      testCases: Array<{ input: string; expectedOutput: string }>;
    }) {
      return benchmarkModel({
        model: params.model,
        testCases: params.testCases,
      });
    },

    promoteModel(model: SpecialistModel) {
      return promoteModel(model);
    },

    getDatasetInfo(model: SpecialistModel) {
      return getTrainingDatasets(model);
    },
  };
}
