/**
 * AC3 LLM Specialist — ScanForge Reasoning Pipeline
 *
 * Chains the ScanForge prompt pack through findings for:
 *   1. Triage — structured state classification
 *   2. Finding Enrichment — analyst-ready summaries
 *   3. Attack Mapping — MITRE ATT&CK alignment
 *   4. FedRAMP Alignment — NIST 800-53 control mapping
 *   5. False Positive Review — FP likelihood assessment
 *   6. Remediation Planning — actionable fix guidance
 *
 * Runs after the vuln-verifier specialist to add ScanForge-specific reasoning.
 */
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt } from "./core-policy";
import {
  buildPromptMessages,
  getResponseFormat,
  TRIAGE_SYSTEM_PROMPT,
  type ScanForgePromptId,
} from "../../scanforge/engine/llm-prompts";
import {
  computeHybridScore,
  type HybridScoringInput,
  type HybridScoringResult,
  type AttackPathCategory,
  type ExposureLevel,
} from "../../scanforge/engine/hybrid-scoring";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ScanForgeReasoningInput {
  finding: {
    id: string;
    title: string;
    description: string;
    severity: string;
    cveIds?: string[];
    evidence: string;
    tool: string;
    port?: number;
    service?: string;
    product?: string;
    version?: string;
  };
  asset: {
    hostname: string;
    ip?: string;
    exposure: ExposureLevel;
    businessRole?: string;
    assetClass?: string;
    environment?: string;
    services?: Array<{ port: number; protocol: string; service_name?: string; product?: string }>;
  };
  engagement?: {
    type: string;
    clientName?: string;
    industry?: string;
    scope?: string;
  };
  /** Which prompts to run (default: all applicable) */
  promptIds?: ScanForgePromptId[];
  /** Skip triage if vuln-verifier already classified */
  skipTriage?: boolean;
}

export interface ScanForgeReasoningResult {
  findingId: string;
  triage?: {
    state: string;
    confidence: number;
    why: string;
    missingEvidence: string[];
    recommendedNextValidation: string[];
    attackPathNotes: string[];
    remediationPriorityNotes: string[];
  };
  enrichment?: {
    titleRefined: string;
    analystSummary: string;
    affectedSurface: string;
    exploitabilityAssessment: string;
    businessRelevance: string;
    remediationSummary: string;
    validationStatusNote: string;
  };
  attackMapping?: {
    mappings: Array<{
      techniqueId: string;
      techniqueName: string;
      confidence: number;
      rationale: string;
    }>;
    nonMappedReason: string;
  };
  fedramp?: {
    likelyControls: Array<{
      controlId: string;
      relationship: string;
      rationale: string;
    }>;
    poamCandidate: boolean;
    recommendedOwnerRoles: string[];
  };
  falsePositive?: {
    falsePositiveLikelihood: number;
    mainConcerns: string[];
    evidenceGaps: string[];
    nextBestCheck: string;
    recommendedState: string;
  };
  remediation?: {
    immediateActions: string[];
    durableFixes: string[];
    validationSteps: string[];
    ownerSuggestions: string[];
    changeRiskNotes: string[];
  };
  hybridScore?: HybridScoringResult;
  /** Total LLM calls made */
  llmCallCount: number;
  /** Total processing time in ms */
  processingTimeMs: number;
}

// ─── Main Reasoning Function ────────────────────────────────────────────────

/**
 * Run the ScanForge reasoning pipeline on a finding.
 *
 * By default runs: triage → enrichment → attack_mapping → fedramp → remediation
 * For suspected false positives, also runs: false_positive
 */
export async function runScanForgeReasoning(input: ScanForgeReasoningInput): Promise<ScanForgeReasoningResult> {
  const startTime = Date.now();
  let llmCallCount = 0;

  const findingJson = JSON.stringify(input.finding, null, 2);
  const assetJson = JSON.stringify(input.asset, null, 2);

  const result: ScanForgeReasoningResult = {
    findingId: input.finding.id,
    llmCallCount: 0,
    processingTimeMs: 0,
  };

  // Determine which prompts to run
  const promptIds = input.promptIds ?? getDefaultPromptIds(input);

  // ─── 1. Triage ───
  if (promptIds.includes("triage") && !input.skipTriage) {
    try {
      const triageResult = await runPrompt("triage", findingJson, assetJson);
      llmCallCount++;
      if (triageResult) {
        result.triage = {
          state: triageResult.state,
          confidence: triageResult.confidence,
          why: triageResult.why,
          missingEvidence: triageResult.missing_evidence ?? [],
          recommendedNextValidation: triageResult.recommended_next_validation ?? [],
          attackPathNotes: triageResult.attack_path_notes ?? [],
          remediationPriorityNotes: triageResult.remediation_priority_notes ?? [],
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Triage failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 2. Enrichment ───
  if (promptIds.includes("enrichment")) {
    try {
      const enrichResult = await runPrompt("enrichment", findingJson, assetJson);
      llmCallCount++;
      if (enrichResult) {
        result.enrichment = {
          titleRefined: enrichResult.title_refined,
          analystSummary: enrichResult.analyst_summary,
          affectedSurface: enrichResult.affected_surface,
          exploitabilityAssessment: enrichResult.exploitability_assessment,
          businessRelevance: enrichResult.business_relevance,
          remediationSummary: enrichResult.remediation_summary,
          validationStatusNote: enrichResult.validation_status_note,
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Enrichment failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 3. Attack Mapping ───
  if (promptIds.includes("attack_mapping")) {
    try {
      const attackResult = await runPrompt("attack_mapping", findingJson, assetJson);
      llmCallCount++;
      if (attackResult) {
        result.attackMapping = {
          mappings: (attackResult.mappings ?? []).map((m: any) => ({
            techniqueId: m.technique_id,
            techniqueName: m.technique_name,
            confidence: m.confidence,
            rationale: m.rationale,
          })),
          nonMappedReason: attackResult.non_mapped_reason ?? "",
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Attack mapping failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 4. FedRAMP Alignment ───
  if (promptIds.includes("fedramp")) {
    try {
      const fedrampResult = await runPrompt("fedramp", findingJson, assetJson);
      llmCallCount++;
      if (fedrampResult) {
        result.fedramp = {
          likelyControls: (fedrampResult.likely_controls ?? []).map((c: any) => ({
            controlId: c.control_id,
            relationship: c.relationship,
            rationale: c.rationale,
          })),
          poamCandidate: fedrampResult.poam_candidate ?? false,
          recommendedOwnerRoles: fedrampResult.recommended_owner_roles ?? [],
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] FedRAMP alignment failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 5. False Positive Review (conditional) ───
  if (promptIds.includes("false_positive")) {
    try {
      const fpResult = await runPrompt("false_positive", findingJson, assetJson);
      llmCallCount++;
      if (fpResult) {
        result.falsePositive = {
          falsePositiveLikelihood: fpResult.false_positive_likelihood,
          mainConcerns: fpResult.main_concerns ?? [],
          evidenceGaps: fpResult.evidence_gaps ?? [],
          nextBestCheck: fpResult.next_best_check ?? "",
          recommendedState: fpResult.recommended_state ?? "",
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] FP review failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 6. Remediation Planning ───
  if (promptIds.includes("remediation")) {
    try {
      const remResult = await runPrompt("remediation", findingJson, assetJson);
      llmCallCount++;
      if (remResult) {
        result.remediation = {
          immediateActions: remResult.immediate_actions ?? [],
          durableFixes: remResult.durable_fixes ?? [],
          validationSteps: remResult.validation_steps ?? [],
          ownerSuggestions: remResult.owner_suggestions ?? [],
          changeRiskNotes: remResult.change_risk_notes ?? [],
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Remediation planning failed for ${input.finding.id}:`, e);
    }
  }

  // ─── 7. Hybrid Scoring (deterministic, no LLM) ───
  try {
    const attackPaths: AttackPathCategory[] = [];
    if (result.attackMapping?.mappings) {
      for (const m of result.attackMapping.mappings) {
        const cat = techniqueToAttackPath(m.techniqueId);
        if (cat) attackPaths.push(cat);
      }
    }

    const scoringInput: HybridScoringInput = {
      cvssBase: guessCvssFromSeverity(input.finding.severity),
      kevListed: false, // Would need KEV lookup
      epss: 0,
      exposure: input.asset.exposure,
      assetCriticality: input.asset.businessRole ? 7 : 5,
      businessRole: input.asset.businessRole ?? "unknown",
      attackPathCategories: attackPaths,
      compensatingControlsConfidence: 0,
      dataSensitivity: 5,
      operationalCriticality: 5,
      state: (result.triage?.state as any) ?? "probable",
      exploitabilityConfidence: result.triage?.confidence,
    };

    result.hybridScore = computeHybridScore(scoringInput);
  } catch (e) {
    console.warn(`[ScanForgeReasoning] Hybrid scoring failed for ${input.finding.id}:`, e);
  }

  result.llmCallCount = llmCallCount;
  result.processingTimeMs = Date.now() - startTime;

  return result;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function getDefaultPromptIds(input: ScanForgeReasoningInput): ScanForgePromptId[] {
  const ids: ScanForgePromptId[] = ["enrichment", "attack_mapping", "remediation"];

  // Add triage unless skipped
  if (!input.skipTriage) {
    ids.unshift("triage");
  }

  // Add FedRAMP for government/regulated targets
  const roleHints = (input.asset.businessRole ?? "").toLowerCase() + " " + (input.engagement?.industry ?? "").toLowerCase();
  if (roleHints.includes("gov") || roleHints.includes("fedramp") || roleHints.includes("federal") || roleHints.includes("nist") || roleHints.includes("regulated") || roleHints.includes("compliance")) {
    ids.push("fedramp");
  }

  // Add false positive review for suspected findings
  if (input.finding.severity === "informational" || input.finding.severity === "low") {
    ids.push("false_positive");
  }

  return ids;
}

async function runPrompt(promptId: ScanForgePromptId, findingJson: string, assetJson: string): Promise<any> {
  const messages = buildPromptMessages(promptId, findingJson, assetJson);
  const responseFormat = getResponseFormat(promptId);

  const response = await throttledLLMCall(
    () => invokeLLM({ messages, response_format: responseFormat, _caller: `scanforge-reasoning:${promptId}` }),
    `scanforge-${promptId}`,
  );

  const content = response?.choices?.[0]?.message?.content;
  if (!content) return null;

  try {
    return JSON.parse(content);
  } catch {
    console.warn(`[ScanForgeReasoning] Failed to parse ${promptId} response as JSON`);
    return null;
  }
}

function techniqueToAttackPath(techniqueId: string): AttackPathCategory | null {
  const prefix = techniqueId.split(".")[0];
  const mapping: Record<string, AttackPathCategory> = {
    "T1190": "initial_access",
    "T1133": "initial_access",
    "T1078": "initial_access",
    "T1566": "initial_access",
    "T1068": "privilege_escalation",
    "T1548": "privilege_escalation",
    "T1134": "privilege_escalation",
    "T1110": "credential_access",
    "T1003": "credential_access",
    "T1552": "credential_access",
    "T1021": "lateral_movement",
    "T1570": "lateral_movement",
    "T1048": "data_exfiltration",
    "T1567": "data_exfiltration",
    "T1098": "persistence",
    "T1136": "persistence",
    "T1562": "defense_evasion",
    "T1071": "command_and_control",
    "T1059": "execution",
    "T1046": "discovery",
    "T1018": "discovery",
    "T1005": "collection",
    "T1486": "impact",
    "T1489": "impact",
  };
  return mapping[prefix] ?? null;
}

function guessCvssFromSeverity(severity: string): number {
  switch (severity.toLowerCase()) {
    case "critical": return 9.5;
    case "high": return 7.5;
    case "medium": return 5.5;
    case "low": return 3.0;
    case "informational": return 0.5;
    default: return 5.0;
  }
}

// ─── Batch Processing ───────────────────────────────────────────────────────

/**
 * Run ScanForge reasoning on multiple findings with concurrency control.
 */
export async function batchRunScanForgeReasoning(
  inputs: ScanForgeReasoningInput[],
  options?: { concurrency?: number; onProgress?: (completed: number, total: number) => void },
): Promise<ScanForgeReasoningResult[]> {
  const concurrency = options?.concurrency ?? 3;
  const results: ScanForgeReasoningResult[] = [];
  let completed = 0;

  // Process in batches
  for (let i = 0; i < inputs.length; i += concurrency) {
    const batch = inputs.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(input => runScanForgeReasoning(input)),
    );

    for (const r of batchResults) {
      if (r.status === "fulfilled") {
        results.push(r.value);
      } else {
        console.warn("[ScanForgeReasoning] Batch item failed:", r.reason);
      }
      completed++;
      options?.onProgress?.(completed, inputs.length);
    }
  }

  return results;
}

// ─── Executive Summary ──────────────────────────────────────────────────────

/**
 * Generate an executive summary from a batch of ScanForge reasoning results.
 */
export async function generateExecutiveSummary(
  results: ScanForgeReasoningResult[],
  engagementContext?: { type: string; clientName?: string; scope?: string },
): Promise<{ summary: string; topRisks: string[]; urgentActions: string[]; confidenceNotes: string } | null> {
  const findingsSummary = results.map(r => ({
    id: r.findingId,
    state: r.triage?.state ?? "unknown",
    severity: r.hybridScore?.severityBand ?? "unknown",
    score: r.hybridScore?.hybridPriorityScore ?? 0,
    title: r.enrichment?.titleRefined ?? r.findingId,
    attackTechniques: r.attackMapping?.mappings?.map(m => m.techniqueId) ?? [],
    fedrampControls: r.fedramp?.likelyControls?.map(c => c.controlId) ?? [],
  }));

  const messages = buildPromptMessages(
    "executive_summary",
    JSON.stringify(findingsSummary, null, 2),
    engagementContext ? JSON.stringify(engagementContext, null, 2) : undefined,
  );

  const response = await throttledLLMCall(
    () => invokeLLM({ messages, response_format: getResponseFormat("executive_summary"), _caller: "scanforge-reasoning:executive_summary" }),
    "scanforge-exec-summary",
  );

  const content = response?.choices?.[0]?.message?.content;
  if (!content) return null;

  try {
    const parsed = JSON.parse(content);
    return {
      summary: parsed.summary,
      topRisks: parsed.top_risks ?? [],
      urgentActions: parsed.urgent_actions ?? [],
      confidenceNotes: parsed.confidence_notes ?? "",
    };
  } catch {
    return null;
  }
}
