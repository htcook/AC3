import {
  buildPromptMessages,
  computeHybridScore,
  getResponseFormat,
  init_hybrid_scoring,
  init_llm_prompts
} from "./chunk-IECUZIQV.js";
import {
  init_llm_json_parser,
  parseLLMJson
} from "./chunk-UQ7CH3JX.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-UJVJACSD.js";
import "./chunk-4BQS7LEI.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/scanforge-reasoning.ts
async function runScanForgeReasoning(input) {
  const startTime = Date.now();
  let llmCallCount = 0;
  const findingJson = JSON.stringify(input.finding, null, 2);
  const assetJson = JSON.stringify(input.asset, null, 2);
  const result = {
    findingId: input.finding.id,
    llmCallCount: 0,
    processingTimeMs: 0
  };
  const promptIds = input.promptIds ?? getDefaultPromptIds(input);
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
          remediationPriorityNotes: triageResult.remediation_priority_notes ?? []
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Triage failed for ${input.finding.id}:`, e);
    }
  }
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
          validationStatusNote: enrichResult.validation_status_note
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Enrichment failed for ${input.finding.id}:`, e);
    }
  }
  if (promptIds.includes("attack_mapping")) {
    try {
      const attackResult = await runPrompt("attack_mapping", findingJson, assetJson);
      llmCallCount++;
      if (attackResult) {
        result.attackMapping = {
          mappings: (attackResult.mappings ?? []).map((m) => ({
            techniqueId: m.technique_id,
            techniqueName: m.technique_name,
            confidence: m.confidence,
            rationale: m.rationale
          })),
          nonMappedReason: attackResult.non_mapped_reason ?? ""
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Attack mapping failed for ${input.finding.id}:`, e);
    }
  }
  if (promptIds.includes("fedramp")) {
    try {
      const fedrampResult = await runPrompt("fedramp", findingJson, assetJson);
      llmCallCount++;
      if (fedrampResult) {
        result.fedramp = {
          likelyControls: (fedrampResult.likely_controls ?? []).map((c) => ({
            controlId: c.control_id,
            relationship: c.relationship,
            rationale: c.rationale
          })),
          poamCandidate: fedrampResult.poam_candidate ?? false,
          recommendedOwnerRoles: fedrampResult.recommended_owner_roles ?? []
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] FedRAMP alignment failed for ${input.finding.id}:`, e);
    }
  }
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
          recommendedState: fpResult.recommended_state ?? ""
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] FP review failed for ${input.finding.id}:`, e);
    }
  }
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
          changeRiskNotes: remResult.change_risk_notes ?? []
        };
      }
    } catch (e) {
      console.warn(`[ScanForgeReasoning] Remediation planning failed for ${input.finding.id}:`, e);
    }
  }
  try {
    const attackPaths = [];
    if (result.attackMapping?.mappings) {
      for (const m of result.attackMapping.mappings) {
        const cat = techniqueToAttackPath(m.techniqueId);
        if (cat) attackPaths.push(cat);
      }
    }
    const scoringInput = {
      cvssBase: guessCvssFromSeverity(input.finding.severity),
      kevListed: false,
      // Would need KEV lookup
      epss: 0,
      exposure: input.asset.exposure,
      assetCriticality: input.asset.businessRole ? 7 : 5,
      businessRole: input.asset.businessRole ?? "unknown",
      attackPathCategories: attackPaths,
      compensatingControlsConfidence: 0,
      dataSensitivity: 5,
      operationalCriticality: 5,
      state: result.triage?.state ?? "probable",
      exploitabilityConfidence: result.triage?.confidence
    };
    result.hybridScore = computeHybridScore(scoringInput);
  } catch (e) {
    console.warn(`[ScanForgeReasoning] Hybrid scoring failed for ${input.finding.id}:`, e);
  }
  result.llmCallCount = llmCallCount;
  result.processingTimeMs = Date.now() - startTime;
  return result;
}
function getDefaultPromptIds(input) {
  const ids = ["enrichment", "attack_mapping", "remediation"];
  if (!input.skipTriage) {
    ids.unshift("triage");
  }
  const roleHints = (input.asset.businessRole ?? "").toLowerCase() + " " + (input.engagement?.industry ?? "").toLowerCase();
  if (roleHints.includes("gov") || roleHints.includes("fedramp") || roleHints.includes("federal") || roleHints.includes("nist") || roleHints.includes("regulated") || roleHints.includes("compliance")) {
    ids.push("fedramp");
  }
  if (input.finding.severity === "informational" || input.finding.severity === "low") {
    ids.push("false_positive");
  }
  return ids;
}
async function runPrompt(promptId, findingJson, assetJson) {
  const messages = buildPromptMessages(promptId, findingJson, assetJson);
  const responseFormat = getResponseFormat(promptId);
  const response = await throttledLLMCall({
    messages,
    response_format: responseFormat,
    _caller: `scanforge-reasoning:${promptId}`
  });
  const content = response?.choices?.[0]?.message?.content;
  if (!content) return null;
  try {
    return JSON.parse(content);
  } catch {
    console.warn(`[ScanForgeReasoning] Failed to parse ${promptId} response as JSON`);
    return null;
  }
}
function techniqueToAttackPath(techniqueId) {
  const prefix = techniqueId.split(".")[0];
  const mapping = {
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
    "T1489": "impact"
  };
  return mapping[prefix] ?? null;
}
function guessCvssFromSeverity(severity) {
  switch (severity.toLowerCase()) {
    case "critical":
      return 9.5;
    case "high":
      return 7.5;
    case "medium":
      return 5.5;
    case "low":
      return 3;
    case "informational":
      return 0.5;
    default:
      return 5;
  }
}
async function batchRunScanForgeReasoning(inputs, options) {
  const concurrency = options?.concurrency ?? 3;
  const results = [];
  let completed = 0;
  for (let i = 0; i < inputs.length; i += concurrency) {
    const batch = inputs.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map((input) => runScanForgeReasoning(input))
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
async function generateExecutiveSummary(results, engagementContext) {
  const findingsSummary = results.map((r) => ({
    id: r.findingId,
    state: r.triage?.state ?? "unknown",
    severity: r.hybridScore?.severityBand ?? "unknown",
    score: r.hybridScore?.hybridPriorityScore ?? 0,
    title: r.enrichment?.titleRefined ?? r.findingId,
    attackTechniques: r.attackMapping?.mappings?.map((m) => m.techniqueId) ?? [],
    fedrampControls: r.fedramp?.likelyControls?.map((c) => c.controlId) ?? []
  }));
  const messages = buildPromptMessages(
    "executive_summary",
    JSON.stringify(findingsSummary, null, 2),
    engagementContext ? JSON.stringify(engagementContext, null, 2) : void 0
  );
  const response = await throttledLLMCall({
    messages,
    response_format: getResponseFormat("executive_summary"),
    _caller: "scanforge-reasoning:executive_summary"
  });
  const content = response?.choices?.[0]?.message?.content;
  if (!content) return null;
  try {
    const parsed = parseLLMJson(content, { fallback: {} }).data;
    return {
      summary: parsed.summary,
      topRisks: parsed.top_risks ?? [],
      urgentActions: parsed.urgent_actions ?? [],
      confidenceNotes: parsed.confidence_notes ?? ""
    };
  } catch {
    return null;
  }
}
var init_scanforge_reasoning = __esm({
  "server/lib/llm-specialists/scanforge-reasoning.ts"() {
    init_llm_throttle();
    init_llm_prompts();
    init_hybrid_scoring();
    init_llm_json_parser();
  }
});
init_scanforge_reasoning();
export {
  batchRunScanForgeReasoning,
  generateExecutiveSummary,
  runScanForgeReasoning
};
