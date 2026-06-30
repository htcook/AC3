/**
 * Cloud Security Knowledge Module — loads cloud misconfiguration patterns,
 * cloud attack paths, detection rules, and training examples from the
 * AC3 Cloud Security Training Bundle v3.
 *
 * Provides filtered retrieval by cloud provider, service, risk level,
 * MITRE technique, or keyword for injection into LLM prompts during
 * scan planning, vuln correlation, asset classification, and hunt
 * hypothesis generation.
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __esm_dirname = dirname(fileURLToPath(import.meta.url));

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CloudMisconfigPattern {
  id: string;
  cloud_provider: string;
  service: string;
  misconfiguration: string;
  signals: string[];
  risk_level: string;
  impact: string;
  remediation: string[];
  references: string[];
}

export interface CloudAttackPathStep {
  step: number;
  action: string;
  goal: string;
  evidence: string[];
  mitre: string[];
  fedramp_controls: string[];
  ksi_tags: string[];
}

export interface CloudAttackPath {
  id: string;
  title: string;
  cloud_provider: string;
  initial_condition: string;
  steps: CloudAttackPathStep[];
  impact: string[];
  detections: string[];
  remediation: string[];
}

export interface CloudTrainingExample {
  input: {
    observations: string[];
  };
  output: {
    hypothesis: string;
    risk: string;
    next_checks: string[];
    remediation: string[];
  };
}

export interface CloudDetectionRule {
  name: string;
  conditions: string[];
  inference: {
    misconfiguration: string;
    confidence: number;
  };
}

// ─── Singleton loaders ─────────────────────────────────────────────────────

let _misconfigPatterns: CloudMisconfigPattern[] | null = null;
let _attackPaths: CloudAttackPath[] | null = null;
let _trainingExamples: CloudTrainingExample[] | null = null;
let _detectionRules: CloudDetectionRule[] | null = null;
let _analysisPrompt: string | null = null;
let _attackPathPrompt: string | null = null;

function loadMisconfigPatterns(): CloudMisconfigPattern[] {
  if (_misconfigPatterns) return _misconfigPatterns;
  try {
    const raw = readFileSync(join(__esm_dirname, "cloud_misconfig_patterns.json"), "utf-8");
    _misconfigPatterns = JSON.parse(raw) as CloudMisconfigPattern[];
    console.log(`[CloudSecurityKnowledge] Loaded ${_misconfigPatterns.length} misconfiguration patterns`);
    return _misconfigPatterns;
  } catch (e: any) {
    console.warn("[CloudSecurityKnowledge] Failed to load misconfig patterns:", e.message);
    _misconfigPatterns = [];
    return _misconfigPatterns;
  }
}

function loadAttackPaths(): CloudAttackPath[] {
  if (_attackPaths) return _attackPaths;
  try {
    const raw = readFileSync(join(__esm_dirname, "cloud_attack_paths.json"), "utf-8");
    _attackPaths = JSON.parse(raw) as CloudAttackPath[];
    console.log(`[CloudSecurityKnowledge] Loaded ${_attackPaths.length} cloud attack paths`);
    return _attackPaths;
  } catch (e: any) {
    console.warn("[CloudSecurityKnowledge] Failed to load attack paths:", e.message);
    _attackPaths = [];
    return _attackPaths;
  }
}

function loadTrainingExamples(): CloudTrainingExample[] {
  if (_trainingExamples) return _trainingExamples;
  try {
    const raw = readFileSync(join(__esm_dirname, "cloud_training_examples.jsonl"), "utf-8");
    _trainingExamples = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line) as CloudTrainingExample);
    console.log(`[CloudSecurityKnowledge] Loaded ${_trainingExamples.length} training examples`);
    return _trainingExamples;
  } catch (e: any) {
    console.warn("[CloudSecurityKnowledge] Failed to load training examples:", e.message);
    _trainingExamples = [];
    return _trainingExamples;
  }
}

function loadDetectionRules(): CloudDetectionRule[] {
  if (_detectionRules) return _detectionRules;
  try {
    const raw = readFileSync(join(__esm_dirname, "cloud_detection_rules.yaml"), "utf-8");
    // Simple YAML parser for our known structure
    const rules: CloudDetectionRule[] = [];
    const ruleBlocks = raw.split("- name:").slice(1);
    for (const block of ruleBlocks) {
      const lines = block.split("\n").map((l) => l.trim());
      const name = lines[0]?.trim() || "";
      const conditions: string[] = [];
      const inference: any = {};
      let inConditions = false;
      let inInference = false;
      for (const line of lines.slice(1)) {
        if (line === "conditions:") { inConditions = true; inInference = false; continue; }
        if (line === "inference:") { inInference = true; inConditions = false; continue; }
        if (inConditions && line.startsWith("- ")) {
          conditions.push(line.slice(2).trim());
        }
        if (inInference && line.startsWith("misconfiguration:")) {
          inference.misconfiguration = line.split(":").slice(1).join(":").trim();
        }
        if (inInference && line.startsWith("confidence:")) {
          inference.confidence = parseFloat(line.split(":")[1].trim());
        }
      }
      rules.push({ name, conditions, inference });
    }
    _detectionRules = rules;
    console.log(`[CloudSecurityKnowledge] Loaded ${_detectionRules.length} detection rules`);
    return _detectionRules;
  } catch (e: any) {
    console.warn("[CloudSecurityKnowledge] Failed to load detection rules:", e.message);
    _detectionRules = [];
    return _detectionRules;
  }
}

function loadAnalysisPrompt(): string {
  if (_analysisPrompt) return _analysisPrompt;
  try {
    _analysisPrompt = readFileSync(join(__esm_dirname, "cloud_analysis_prompt.md"), "utf-8");
    return _analysisPrompt;
  } catch {
    _analysisPrompt = "";
    return _analysisPrompt;
  }
}

function loadAttackPathPrompt(): string {
  if (_attackPathPrompt) return _attackPathPrompt;
  try {
    _attackPathPrompt = readFileSync(join(__esm_dirname, "cloud_attack_path_prompt.md"), "utf-8");
    return _attackPathPrompt;
  } catch {
    _attackPathPrompt = "";
    return _attackPathPrompt;
  }
}

// ─── Cloud provider detection from observations ────────────────────────────

const CLOUD_PROVIDER_SIGNALS: Record<string, string[]> = {
  AWS: [
    "amazonaws.com", "s3.amazonaws", "ec2", "aws", "lambda",
    "cloudfront", "elasticbeanstalk", "ecs", "eks", "rds",
    "dynamodb", "sqs", "sns", "iam", "route53", "elb",
    "cloudwatch", "kinesis", "redshift", "apigateway",
  ],
  Azure: [
    "azure", "microsoft.com", "blob.core.windows.net", "azurewebsites.net",
    "azurefd.net", "trafficmanager.net", "cosmos", "servicebus",
    "eventhub", "keyvault", "aad", "entra", "active directory",
  ],
  GCP: [
    "googleapis.com", "google cloud", "gcp", "appspot.com",
    "cloudfunctions.net", "run.app", "firestore", "bigquery",
    "pubsub", "gke", "cloud storage", "compute engine",
  ],
};

export function detectCloudProviders(observations: string[]): string[] {
  const text = observations.join(" ").toLowerCase();
  const detected: string[] = [];
  for (const [provider, signals] of Object.entries(CLOUD_PROVIDER_SIGNALS)) {
    if (signals.some((s) => text.includes(s.toLowerCase()))) {
      detected.push(provider);
    }
  }
  return detected;
}

// ─── Retrieval functions ───────────────────────────────────────────────────

/** Get all misconfiguration patterns, optionally filtered by provider */
export function getMisconfigPatterns(provider?: string): CloudMisconfigPattern[] {
  const patterns = loadMisconfigPatterns();
  if (!provider) return patterns;
  return patterns.filter((p) => p.cloud_provider.toLowerCase() === provider.toLowerCase());
}

/** Get all cloud attack paths, optionally filtered by provider */
export function getCloudAttackPaths(provider?: string): CloudAttackPath[] {
  const paths = loadAttackPaths();
  if (!provider) return paths;
  return paths.filter((p) => p.cloud_provider.toLowerCase() === provider.toLowerCase());
}

/** Get attack paths matching a MITRE technique ID */
export function getAttackPathsByMitre(techniqueId: string): CloudAttackPath[] {
  const paths = loadAttackPaths();
  return paths.filter((p) =>
    p.steps.some((s) => s.mitre.some((m) => m.toLowerCase() === techniqueId.toLowerCase()))
  );
}

/** Get misconfig patterns matching observation signals */
export function matchMisconfigsToObservations(observations: string[]): CloudMisconfigPattern[] {
  const patterns = loadMisconfigPatterns();
  const text = observations.join(" ").toLowerCase();
  return patterns.filter((p) =>
    p.signals.some((s) => text.includes(s.toLowerCase())) ||
    text.includes(p.misconfiguration.toLowerCase())
  );
}

/** Get detection rules that match given conditions */
export function matchDetectionRules(conditions: string[]): CloudDetectionRule[] {
  const rules = loadDetectionRules();
  const condSet = new Set(conditions.map((c) => c.toLowerCase()));
  return rules.filter((r) =>
    r.conditions.some((c) => condSet.has(c.toLowerCase()))
  );
}

/** Get all training examples */
export function getTrainingExamples(): CloudTrainingExample[] {
  return loadTrainingExamples();
}

/** Get the cloud analysis system prompt */
export function getCloudAnalysisPrompt(): string {
  return loadAnalysisPrompt();
}

/** Get the cloud attack path modeling prompt */
export function getCloudAttackPathPrompt(): string {
  return loadAttackPathPrompt();
}

// ─── LLM Context Builders ──────────────────────────────────────────────────

/**
 * Build a comprehensive cloud security context block for LLM injection.
 * Detects cloud providers from observations and returns relevant
 * misconfigurations, attack paths, and training examples.
 */
export function buildCloudSecurityContext(observations: string[]): string {
  const providers = detectCloudProviders(observations);
  if (providers.length === 0 && observations.length === 0) {
    // Return general cloud security awareness even without specific observations
    return buildGeneralCloudContext();
  }

  const sections: string[] = [];
  sections.push("## CLOUD SECURITY KNOWLEDGE (AC3 Training Bundle v3)");

  if (providers.length > 0) {
    sections.push(`Detected cloud providers: ${providers.join(", ")}`);
  }

  // Matched misconfigurations
  const matchedMisconfigs = matchMisconfigsToObservations(observations);
  if (matchedMisconfigs.length > 0) {
    sections.push("\n### Matched Cloud Misconfigurations:");
    for (const m of matchedMisconfigs) {
      sections.push(`- **${m.id}** [${m.cloud_provider}/${m.service}] ${m.misconfiguration}`);
      sections.push(`  Risk: ${m.risk_level} | Impact: ${m.impact}`);
      sections.push(`  Signals: ${m.signals.join("; ")}`);
      sections.push(`  Remediation: ${m.remediation.join("; ")}`);
    }
  }

  // Provider-specific attack paths
  for (const provider of providers) {
    const paths = getCloudAttackPaths(provider);
    if (paths.length > 0) {
      sections.push(`\n### ${provider} Cloud Attack Paths:`);
      for (const p of paths) {
        sections.push(`- **${p.id}**: ${p.title}`);
        sections.push(`  Initial condition: ${p.initial_condition}`);
        for (const step of p.steps) {
          const mitre = step.mitre.join(",");
          const controls = step.fedramp_controls.join(",");
          sections.push(`  Step ${step.step}: ${step.action} [MITRE: ${mitre}] [FedRAMP: ${controls}]`);
        }
        sections.push(`  Impact: ${p.impact.join("; ")}`);
        sections.push(`  Detections: ${p.detections.join("; ")}`);
      }
    }
  }

  // Training examples as few-shot context
  const examples = getTrainingExamples();
  if (examples.length > 0) {
    sections.push("\n### Cloud Security Analysis Examples (few-shot):");
    for (const ex of examples.slice(0, 3)) {
      sections.push(`Input observations: ${ex.input.observations.join("; ")}`);
      sections.push(`→ Hypothesis: ${ex.output.hypothesis}`);
      sections.push(`→ Risk: ${ex.output.risk}`);
      sections.push(`→ Next checks: ${ex.output.next_checks.join("; ")}`);
      sections.push("");
    }
  }

  return sections.join("\n");
}

/**
 * Build general cloud security context (for scan planning when
 * cloud providers haven't been detected yet but might be present).
 */
export function buildGeneralCloudContext(): string {
  const patterns = loadMisconfigPatterns();
  const paths = loadAttackPaths();

  const sections: string[] = [];
  sections.push("## CLOUD SECURITY AWARENESS (AC3 Training Bundle v3)");
  sections.push("During scanning, watch for cloud infrastructure indicators:");
  sections.push("");

  // Summarize all known misconfig patterns
  sections.push("### Known Cloud Misconfiguration Patterns:");
  for (const p of patterns) {
    sections.push(`- **${p.id}** [${p.cloud_provider}] ${p.misconfiguration} (${p.risk_level})`);
    sections.push(`  Signals to detect: ${p.signals.join("; ")}`);
  }

  // Summarize attack path models
  sections.push("\n### Cloud Attack Path Models:");
  for (const ap of paths) {
    const allMitre = ap.steps.flatMap((s) => s.mitre);
    const allControls = [...new Set(ap.steps.flatMap((s) => s.fedramp_controls))];
    sections.push(`- **${ap.id}**: ${ap.title} [${ap.cloud_provider}]`);
    sections.push(`  MITRE: ${allMitre.join(",")} | FedRAMP: ${allControls.join(",")}`);
  }

  // Cloud provider detection signals
  sections.push("\n### Cloud Provider Detection Signals:");
  for (const [provider, signals] of Object.entries(CLOUD_PROVIDER_SIGNALS)) {
    sections.push(`- ${provider}: ${signals.slice(0, 8).join(", ")}`);
  }

  return sections.join("\n");
}

/**
 * Build cloud-specific hunt hypothesis context for the hunt engine.
 * Returns cloud attack paths formatted for threat hunting.
 */
export function buildCloudHuntContext(): string {
  const paths = loadAttackPaths();
  const patterns = loadMisconfigPatterns();

  const sections: string[] = [];
  sections.push("## CLOUD THREAT HUNTING CONTEXT");
  sections.push("Use these cloud attack paths to generate hunt hypotheses:");
  sections.push("");

  for (const ap of paths) {
    sections.push(`### ${ap.id}: ${ap.title}`);
    sections.push(`Provider: ${ap.cloud_provider} | Initial: ${ap.initial_condition}`);
    for (const step of ap.steps) {
      sections.push(`  Hunt Step ${step.step}: ${step.action}`);
      sections.push(`    Evidence to look for: ${step.evidence.join("; ")}`);
      sections.push(`    MITRE: ${step.mitre.join(",")} | KSI Tags: ${step.ksi_tags.join(",")}`);
    }
    sections.push(`  Detections: ${ap.detections.join("; ")}`);
    sections.push("");
  }

  sections.push("### Cloud Misconfig Hunt Signals:");
  for (const p of patterns) {
    sections.push(`- ${p.cloud_provider}/${p.service}: ${p.signals.join("; ")} → ${p.misconfiguration}`);
  }

  return sections.join("\n");
}

/**
 * Build cloud scoring context for the CARVER/Shock scoring engine.
 * Returns cloud-specific risk factors for asset classification.
 */
export function buildCloudScoringContext(observations: string[]): string {
  const providers = detectCloudProviders(observations);
  const matched = matchMisconfigsToObservations(observations);

  if (providers.length === 0 && matched.length === 0) return "";

  const sections: string[] = [];
  sections.push("## CLOUD RISK FACTORS");

  if (matched.length > 0) {
    sections.push("Detected cloud misconfigurations affecting risk score:");
    for (const m of matched) {
      sections.push(`- ${m.id}: ${m.misconfiguration} [${m.risk_level}] → ${m.impact}`);
    }
  }

  if (providers.length > 0) {
    const paths = providers.flatMap((p) => getCloudAttackPaths(p));
    if (paths.length > 0) {
      sections.push("\nApplicable cloud attack paths (increase blast radius):");
      for (const p of paths) {
        sections.push(`- ${p.title}: ${p.impact.join("; ")}`);
      }
    }
  }

  return sections.join("\n");
}
