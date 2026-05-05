import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/scanforge/engine/llm-prompts.ts
function buildPromptMessages(promptId, findingJson, assetJson, scoringJson, additionalContext) {
  const config = PROMPT_REGISTRY[promptId];
  const messages = [];
  if (config.systemPrompt) {
    messages.push({ role: "system", content: config.systemPrompt });
  } else {
    messages.push({
      role: "system",
      content: "You are a ScanForge security analyst for Ace C3. Follow the task instructions precisely. Return structured JSON output as specified. Use only the evidence provided \u2014 do not invent findings."
    });
  }
  let userContent = config.userPrompt + "\n\n";
  userContent += `## Finding
\`\`\`json
${findingJson}
\`\`\`

`;
  if (assetJson) {
    userContent += `## Asset
\`\`\`json
${assetJson}
\`\`\`

`;
  }
  if (scoringJson) {
    userContent += `## Scoring
\`\`\`json
${scoringJson}
\`\`\`

`;
  }
  if (additionalContext) {
    userContent += `## Additional Context
${additionalContext}
`;
  }
  messages.push({ role: "user", content: userContent });
  return messages;
}
function getResponseFormat(promptId) {
  return PROMPT_REGISTRY[promptId].responseSchema;
}
function getPromptsForStage(stage) {
  return Object.values(PROMPT_REGISTRY).filter((p) => p.stage === stage).map((p) => p.id);
}
var TRIAGE_SYSTEM_PROMPT, TRIAGE_RESPONSE_SCHEMA, FINDING_ENRICHMENT_PROMPT, FINDING_ENRICHMENT_SCHEMA, ATTACK_MAPPING_PROMPT, ATTACK_MAPPING_SCHEMA, FEDRAMP_ALIGNMENT_PROMPT, FEDRAMP_ALIGNMENT_SCHEMA, FALSE_POSITIVE_REVIEWER_PROMPT, FALSE_POSITIVE_REVIEWER_SCHEMA, REMEDIATION_PLANNER_PROMPT, REMEDIATION_PLANNER_SCHEMA, REPORT_WRITER_PROMPT, REPORT_WRITER_SCHEMA, EXECUTIVE_SUMMARY_PROMPT, EXECUTIVE_SUMMARY_SCHEMA, PROMPT_REGISTRY, SCANFORGE_WORKFLOW_STAGES, STRICT_PASSIVE_MODE_POLICY;
var init_llm_prompts = __esm({
  "server/scanforge/engine/llm-prompts.ts"() {
    "use strict";
    TRIAGE_SYSTEM_PROMPT = `You are the ScanForge Triage Analyst for Ace C3.
Your job is to analyze structured vulnerability and exposure findings, determine whether each item is verified, probable, suspected, or informational, and return concise, evidence-based reasoning.

Operating rules:
1. Use only the evidence provided.
2. Never upgrade a finding to verified without direct confirming evidence.
3. Separate technical severity from mission impact.
4. Highlight likely false positives and missing evidence.
5. Produce structured output first.

Required JSON output:
{
  "finding_id": "",
  "state": "verified|probable|suspected|informational|not_affected",
  "confidence": 0.0,
  "why": "",
  "missing_evidence": [],
  "recommended_next_validation": [],
  "attack_path_notes": [],
  "remediation_priority_notes": []
}`;
    TRIAGE_RESPONSE_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_triage",
        strict: true,
        schema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            state: { type: "string", enum: ["verified", "probable", "suspected", "informational", "not_affected"] },
            confidence: { type: "number" },
            why: { type: "string" },
            missing_evidence: { type: "array", items: { type: "string" } },
            recommended_next_validation: { type: "array", items: { type: "string" } },
            attack_path_notes: { type: "array", items: { type: "string" } },
            remediation_priority_notes: { type: "array", items: { type: "string" } }
          },
          required: ["finding_id", "state", "confidence", "why", "missing_evidence", "recommended_next_validation", "attack_path_notes", "remediation_priority_notes"],
          additionalProperties: false
        }
      }
    };
    FINDING_ENRICHMENT_PROMPT = `Task: Enrich a ScanForge finding for analyst review and reporting.

Input: finding JSON, asset JSON, scoring JSON, optional intel JSON.

Instructions:
1. Summarize what was observed.
2. Explain why it matters on this specific asset.
3. Note preconditions and practical exploitability.
4. Produce clean remediation language.
5. Keep wording suitable for a professional pentest or security assessment report.`;
    FINDING_ENRICHMENT_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_enrichment",
        strict: true,
        schema: {
          type: "object",
          properties: {
            title_refined: { type: "string" },
            analyst_summary: { type: "string" },
            affected_surface: { type: "string" },
            exploitability_assessment: { type: "string" },
            business_relevance: { type: "string" },
            remediation_summary: { type: "string" },
            validation_status_note: { type: "string" }
          },
          required: ["title_refined", "analyst_summary", "affected_surface", "exploitability_assessment", "business_relevance", "remediation_summary", "validation_status_note"],
          additionalProperties: false
        }
      }
    };
    ATTACK_MAPPING_PROMPT = `Task: Map a verified or probable ScanForge finding to realistic MITRE ATT&CK techniques.

Rules:
- Map only when the weakness plausibly supports a real adversary action.
- Do not map generic hygiene issues unless there is a credible ATT&CK relationship.
- Prefer the narrowest justified technique/sub-technique.
- Explain the bridge from evidence to ATT&CK.`;
    ATTACK_MAPPING_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_attack_mapping",
        strict: true,
        schema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            mappings: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  technique_id: { type: "string" },
                  technique_name: { type: "string" },
                  confidence: { type: "number" },
                  rationale: { type: "string" }
                },
                required: ["technique_id", "technique_name", "confidence", "rationale"],
                additionalProperties: false
              }
            },
            non_mapped_reason: { type: "string" }
          },
          required: ["finding_id", "mappings", "non_mapped_reason"],
          additionalProperties: false
        }
      }
    };
    FEDRAMP_ALIGNMENT_PROMPT = `Task: Align a ScanForge finding to likely FedRAMP / NIST SP 800-53 Rev. 5 control considerations.

Instructions:
- Focus on control implications, not full compliance conclusions.
- Differentiate between likely implementation weakness, monitoring gap, or documentation gap.
- Use concise language appropriate for SSP, SAR, or POA&M support.

Common control families:
- RA-5: Vulnerability monitoring and assessment
- CA-7: Ongoing monitoring and status reporting
- SI-2: Flaw remediation tracking
- CM-6: Secure configuration implications
- SC-8/SC-13: Transport encryption / crypto weaknesses
- AC/IA: Auth and access weaknesses
- AU: Logging/visibility gaps`;
    FEDRAMP_ALIGNMENT_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_fedramp",
        strict: true,
        schema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            likely_controls: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  control_id: { type: "string" },
                  relationship: { type: "string", enum: ["implementation", "monitoring", "documentation"] },
                  rationale: { type: "string" }
                },
                required: ["control_id", "relationship", "rationale"],
                additionalProperties: false
              }
            },
            poam_candidate: { type: "boolean" },
            recommended_owner_roles: { type: "array", items: { type: "string" } }
          },
          required: ["finding_id", "likely_controls", "poam_candidate", "recommended_owner_roles"],
          additionalProperties: false
        }
      }
    };
    FALSE_POSITIVE_REVIEWER_PROMPT = `Task: Review whether a ScanForge finding may be a false positive.

Instructions:
- Examine whether evidence is incomplete, contradictory, or stale.
- Check if fingerprinting confidence is too low.
- Check whether the plugin logic may over-match.
- Suggest the least invasive next validation step.`;
    FALSE_POSITIVE_REVIEWER_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_fp_review",
        strict: true,
        schema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            false_positive_likelihood: { type: "number" },
            main_concerns: { type: "array", items: { type: "string" } },
            evidence_gaps: { type: "array", items: { type: "string" } },
            next_best_check: { type: "string" },
            recommended_state: { type: "string", enum: ["verified", "probable", "suspected", "informational", "not_affected"] }
          },
          required: ["finding_id", "false_positive_likelihood", "main_concerns", "evidence_gaps", "next_best_check", "recommended_state"],
          additionalProperties: false
        }
      }
    };
    REMEDIATION_PLANNER_PROMPT = `Task: Create remediation guidance for a ScanForge finding.

Requirements:
- Prioritize actionable changes.
- Order immediate containment, durable fix, and validation steps.
- Mention rollback or outage considerations when relevant.
- Keep recommendations technically precise.`;
    REMEDIATION_PLANNER_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_remediation",
        strict: true,
        schema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            immediate_actions: { type: "array", items: { type: "string" } },
            durable_fixes: { type: "array", items: { type: "string" } },
            validation_steps: { type: "array", items: { type: "string" } },
            owner_suggestions: { type: "array", items: { type: "string" } },
            change_risk_notes: { type: "array", items: { type: "string" } }
          },
          required: ["finding_id", "immediate_actions", "durable_fixes", "validation_steps", "owner_suggestions", "change_risk_notes"],
          additionalProperties: false
        }
      }
    };
    REPORT_WRITER_PROMPT = `Task: Convert the finding package into report-ready prose.

Requirements:
- Write in professional assessment language.
- Keep it factual and concise.
- Include condition, risk, evidence, impact, and recommendation.
- Avoid sensational language.
- Reflect verified/probable state accurately.

Output format:
## Title
Condition:
Risk:
Evidence:
Impact:
Recommendation:`;
    REPORT_WRITER_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_report",
        strict: true,
        schema: {
          type: "object",
          properties: {
            title: { type: "string" },
            condition: { type: "string" },
            risk: { type: "string" },
            evidence: { type: "string" },
            impact: { type: "string" },
            recommendation: { type: "string" }
          },
          required: ["title", "condition", "risk", "evidence", "impact", "recommendation"],
          additionalProperties: false
        }
      }
    };
    EXECUTIVE_SUMMARY_PROMPT = `Task: Produce a short executive summary of the assessment wave.

Requirements:
- Summarize the most important risks in plain English.
- State what was verified vs probable.
- Mention exposure and business impact.
- Avoid deep technical detail.
- Keep tone suitable for leadership.`;
    EXECUTIVE_SUMMARY_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scanforge_exec_summary",
        strict: true,
        schema: {
          type: "object",
          properties: {
            summary: { type: "string" },
            top_risks: { type: "array", items: { type: "string" } },
            urgent_actions: { type: "array", items: { type: "string" } },
            confidence_notes: { type: "string" }
          },
          required: ["summary", "top_risks", "urgent_actions", "confidence_notes"],
          additionalProperties: false
        }
      }
    };
    PROMPT_REGISTRY = {
      triage: {
        id: "triage",
        name: "Triage Analyst",
        description: "Classify finding state (verified/probable/suspected) with evidence-based reasoning",
        systemPrompt: TRIAGE_SYSTEM_PROMPT,
        userPrompt: "Analyze the following ScanForge finding and asset data. Determine the finding state and provide evidence-based reasoning.",
        responseSchema: TRIAGE_RESPONSE_SCHEMA,
        stage: "reasoning"
      },
      enrichment: {
        id: "enrichment",
        name: "Finding Enrichment",
        description: "Enrich findings with analyst summaries, exploitability assessment, and remediation language",
        userPrompt: FINDING_ENRICHMENT_PROMPT,
        responseSchema: FINDING_ENRICHMENT_SCHEMA,
        stage: "reasoning"
      },
      attack_mapping: {
        id: "attack_mapping",
        name: "ATT&CK Mapper",
        description: "Map findings to MITRE ATT&CK techniques with confidence and rationale",
        userPrompt: ATTACK_MAPPING_PROMPT,
        responseSchema: ATTACK_MAPPING_SCHEMA,
        stage: "reasoning"
      },
      fedramp: {
        id: "fedramp",
        name: "FedRAMP Alignment",
        description: "Align findings to NIST 800-53 Rev. 5 controls for SSP/SAR/POA&M support",
        userPrompt: FEDRAMP_ALIGNMENT_PROMPT,
        responseSchema: FEDRAMP_ALIGNMENT_SCHEMA,
        stage: "reasoning"
      },
      false_positive: {
        id: "false_positive",
        name: "False Positive Reviewer",
        description: "Assess false positive likelihood and suggest next validation steps",
        userPrompt: FALSE_POSITIVE_REVIEWER_PROMPT,
        responseSchema: FALSE_POSITIVE_REVIEWER_SCHEMA,
        stage: "verification"
      },
      remediation: {
        id: "remediation",
        name: "Remediation Planner",
        description: "Generate actionable remediation guidance with containment, fix, and validation steps",
        userPrompt: REMEDIATION_PLANNER_PROMPT,
        responseSchema: REMEDIATION_PLANNER_SCHEMA,
        stage: "reporting"
      },
      report_writer: {
        id: "report_writer",
        name: "Report Writer",
        description: "Convert findings into professional assessment prose",
        userPrompt: REPORT_WRITER_PROMPT,
        responseSchema: REPORT_WRITER_SCHEMA,
        stage: "reporting"
      },
      executive_summary: {
        id: "executive_summary",
        name: "Executive Summary",
        description: "Produce leadership-ready assessment summary",
        userPrompt: EXECUTIVE_SUMMARY_PROMPT,
        responseSchema: EXECUTIVE_SUMMARY_SCHEMA,
        stage: "reporting"
      }
    };
    SCANFORGE_WORKFLOW_STAGES = [
      { name: "intake", actions: ["normalize_assets", "de_duplicate_targets", "classify_exposure"] },
      { name: "passive_enrichment", actions: ["dns_enrichment", "certificate_metadata", "cloud_provider_inference"] },
      { name: "fingerprinting", actions: ["banner_grab", "http_header_probe", "tls_matrix"] },
      { name: "detection", actions: ["run_safe_plugins", "attach_evidence"] },
      { name: "verification", actions: ["bounded_rechecks", "classify_state"] },
      { name: "scoring", actions: ["compute_cvss_context", "apply_hybrid_priority"] },
      { name: "reasoning", actions: ["triage_prompt", "attack_mapping_prompt", "fedramp_alignment_prompt"] },
      { name: "reporting", actions: ["report_writer_prompt", "executive_summary_prompt"] }
    ];
    STRICT_PASSIVE_MODE_POLICY = {
      allowed: [
        "DNS resolution and passive DNS lookups",
        "Certificate transparency review",
        "Public metadata and OSINT enrichment",
        "Third-party exposure intelligence from authorized providers",
        "Internal correlation against prior results"
      ],
      prohibited: [
        "Direct service probing",
        "Authentication attempts",
        "Payload-based validation",
        "Content retrieval beyond public metadata",
        "Rate-based discovery that touches the target directly"
      ],
      outputLabels: {
        collection_mode: "passive",
        direct_interaction: false
      },
      analystNote: "Passive mode is valuable for exposure intelligence but is not a substitute for direct technical validation."
    };
  }
});

// server/scanforge/engine/hybrid-scoring.ts
function computeTechnicalSeverity(input) {
  let score = input.cvssBase ?? 5;
  if (input.kevListed) {
    score += 0.5;
  }
  for (const band of EPSS_BANDS) {
    if (input.epss >= band.threshold) {
      score += band.boost;
      break;
    }
  }
  return Math.min(10, Math.max(0, score));
}
function computeExposureModifier(exposure) {
  return EXPOSURE_MODIFIERS[exposure] ?? 1;
}
function computeMissionImpact(input) {
  let score = input.assetCriticality;
  score = score + input.dataSensitivity * 0.3 + input.operationalCriticality * 0.3;
  const roleLower = input.businessRole.toLowerCase();
  const keywordMatches = HIGH_MISSION_IMPACT_KEYWORDS.filter((kw) => roleLower.includes(kw));
  if (keywordMatches.length > 0) {
    score += Math.min(2, keywordMatches.length * 0.4);
  }
  return Math.min(10, Math.max(0, score));
}
function computeAttackPathModifier(categories) {
  if (categories.length === 0) {
    return { modifier: 1, description: "No specific attack path identified" };
  }
  let maxWeight = 0.8;
  let primaryCategory = "";
  for (const cat of categories) {
    const weight = ATTACK_PATH_WEIGHTS[cat] ?? 1;
    if (weight > maxWeight) {
      maxWeight = weight;
      primaryCategory = cat;
    }
  }
  if (categories.length >= 3) {
    maxWeight = Math.min(1.3, maxWeight + 0.1);
  }
  const description = categories.map((c) => c.replace(/_/g, " ")).join(", ");
  return { modifier: maxWeight, description };
}
function computeExploitabilityConfidence(input) {
  if (input.exploitabilityConfidence !== void 0) {
    return input.exploitabilityConfidence;
  }
  let confidence = 0.5;
  if (input.state === "verified") confidence += 0.3;
  else if (input.state === "probable") confidence += 0.15;
  else if (input.state === "suspected") confidence -= 0.1;
  if (input.kevListed) confidence += 0.15;
  if (input.epss > 0.5) confidence += 0.1;
  else if (input.epss > 0.2) confidence += 0.05;
  return Math.min(1, Math.max(0, confidence));
}
function computeHybridScore(input) {
  const technicalSeverity = computeTechnicalSeverity(input);
  const exposureModifier = computeExposureModifier(input.exposure);
  const missionImpactScore = computeMissionImpact(input);
  const { modifier: attackPathModifier, description: attackPathValue } = computeAttackPathModifier(input.attackPathCategories);
  const exploitabilityConfidence = computeExploitabilityConfidence(input);
  const stateMultiplier = STATE_MULTIPLIERS[input.state] ?? 1;
  const controlsMitigation = 1 - input.compensatingControlsConfidence * 0.3;
  const exposureComponent = technicalSeverity * exposureModifier;
  const attackPathComponent = technicalSeverity * attackPathModifier * 0.5;
  const missionComponent = missionImpactScore * 0.8;
  const rawScore = (exposureComponent + attackPathComponent + missionComponent) * stateMultiplier * controlsMitigation;
  const maxTheoretical = 28.5;
  const hybridPriorityScore = Math.min(100, Math.max(0, Math.round(rawScore / maxTheoretical * 100 * 10) / 10));
  const severityBand = deriveSeverityBand(hybridPriorityScore);
  const rationale = buildRationale(input, {
    technicalSeverity,
    exposureModifier,
    missionImpactScore,
    attackPathModifier,
    exploitabilityConfidence,
    hybridPriorityScore,
    severityBand
  });
  return {
    hybridPriorityScore,
    severityBand,
    technicalSeverity,
    exposureModifier,
    missionImpactScore,
    attackPathModifier,
    exploitabilityConfidence,
    attackPathValue,
    rationale,
    breakdown: {
      baseComponent: Math.round(technicalSeverity * 10) / 10,
      exposureComponent: Math.round(exposureComponent * 10) / 10,
      attackPathComponent: Math.round(attackPathComponent * 10) / 10,
      missionComponent: Math.round(missionComponent * 10) / 10,
      stateAdjustment: stateMultiplier,
      controlsMitigation: Math.round(controlsMitigation * 100) / 100
    }
  };
}
function deriveSeverityBand(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}
function buildRationale(input, computed) {
  const parts = [];
  parts.push(`Technical severity: ${computed.technicalSeverity.toFixed(1)}/10`);
  if (input.cvssBase !== null) {
    parts.push(`CVSS base: ${input.cvssBase}`);
  }
  if (input.kevListed) {
    parts.push("CISA KEV listed (+0.5 boost)");
  }
  if (input.epss > 0.05) {
    parts.push(`EPSS: ${(input.epss * 100).toFixed(1)}%`);
  }
  parts.push(`Exposure: ${input.exposure} (\xD7${computed.exposureModifier})`);
  parts.push(`Mission impact: ${computed.missionImpactScore.toFixed(1)}/10`);
  if (input.attackPathCategories.length > 0) {
    parts.push(`Attack path: ${input.attackPathCategories.join(", ")} (\xD7${computed.attackPathModifier})`);
  }
  if (input.compensatingControlsConfidence > 0) {
    parts.push(`Compensating controls: ${(input.compensatingControlsConfidence * 100).toFixed(0)}% confidence`);
  }
  parts.push(`State: ${input.state} (\xD7${STATE_MULTIPLIERS[input.state]})`);
  parts.push(`Hybrid priority: ${computed.hybridPriorityScore}/100 \u2192 ${computed.severityBand.toUpperCase()}`);
  return parts.join(". ");
}
function batchScore(findings) {
  return findings.map((f) => ({ id: f.id, result: computeHybridScore(f.input) })).sort((a, b) => b.result.hybridPriorityScore - a.result.hybridPriorityScore);
}
function quickSeverityFromCvss(cvss) {
  if (cvss === null) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  if (cvss >= 0.1) return "low";
  return "informational";
}
var EXPOSURE_MODIFIERS, EPSS_BANDS, ATTACK_PATH_WEIGHTS, STATE_MULTIPLIERS, HIGH_MISSION_IMPACT_KEYWORDS;
var init_hybrid_scoring = __esm({
  "server/scanforge/engine/hybrid-scoring.ts"() {
    "use strict";
    EXPOSURE_MODIFIERS = {
      external: 1.4,
      internal: 1.1,
      segmented: 0.9,
      unknown: 1
    };
    EPSS_BANDS = [
      { threshold: 0.7, boost: 1 },
      // Very high exploit probability
      { threshold: 0.4, boost: 0.75 },
      // High
      { threshold: 0.2, boost: 0.5 },
      // Moderate
      { threshold: 0.05, boost: 0.25 },
      // Low-moderate
      { threshold: 0, boost: 0 }
      // Minimal
    ];
    ATTACK_PATH_WEIGHTS = {
      initial_access: 1.3,
      privilege_escalation: 1.25,
      credential_access: 1.2,
      lateral_movement: 1.2,
      data_exfiltration: 1.15,
      persistence: 1.1,
      defense_evasion: 1.1,
      command_and_control: 1.05,
      impact: 1.3,
      collection: 1,
      execution: 1.15,
      discovery: 0.9,
      resource_development: 0.85
    };
    STATE_MULTIPLIERS = {
      verified: 1,
      probable: 0.85,
      suspected: 0.6,
      informational: 0.3,
      not_affected: 0
    };
    HIGH_MISSION_IMPACT_KEYWORDS = [
      "identity",
      "auth",
      "authentication",
      "sso",
      "iam",
      "admin",
      "management",
      "control plane",
      "payment",
      "billing",
      "financial",
      "pci",
      "customer data",
      "pii",
      "phi",
      "hipaa",
      "production",
      "prod",
      "primary",
      "backup",
      "recovery",
      "disaster",
      "ci/cd",
      "pipeline",
      "deployment",
      "database",
      "data warehouse",
      "analytics",
      "api gateway",
      "load balancer",
      "dns",
      "certificate",
      "key management",
      "vault",
      "monitoring",
      "logging",
      "siem"
    ];
  }
});

export {
  TRIAGE_SYSTEM_PROMPT,
  TRIAGE_RESPONSE_SCHEMA,
  FINDING_ENRICHMENT_PROMPT,
  FINDING_ENRICHMENT_SCHEMA,
  ATTACK_MAPPING_PROMPT,
  ATTACK_MAPPING_SCHEMA,
  FEDRAMP_ALIGNMENT_PROMPT,
  FEDRAMP_ALIGNMENT_SCHEMA,
  FALSE_POSITIVE_REVIEWER_PROMPT,
  FALSE_POSITIVE_REVIEWER_SCHEMA,
  REMEDIATION_PLANNER_PROMPT,
  REMEDIATION_PLANNER_SCHEMA,
  REPORT_WRITER_PROMPT,
  REPORT_WRITER_SCHEMA,
  EXECUTIVE_SUMMARY_PROMPT,
  EXECUTIVE_SUMMARY_SCHEMA,
  PROMPT_REGISTRY,
  buildPromptMessages,
  getResponseFormat,
  SCANFORGE_WORKFLOW_STAGES,
  getPromptsForStage,
  STRICT_PASSIVE_MODE_POLICY,
  init_llm_prompts,
  computeTechnicalSeverity,
  computeExposureModifier,
  computeMissionImpact,
  computeAttackPathModifier,
  computeExploitabilityConfidence,
  computeHybridScore,
  batchScore,
  quickSeverityFromCvss,
  init_hybrid_scoring
};
