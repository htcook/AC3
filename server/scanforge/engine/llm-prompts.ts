/**
 * ScanForge LLM Prompt Pack
 *
 * Eight specialized prompts for the ScanForge reasoning pipeline:
 *   1. Triage System Prompt — finding state classification
 *   2. Finding Enrichment — analyst-ready summaries
 *   3. Attack Mapping — MITRE ATT&CK alignment
 *   4. FedRAMP Alignment — NIST 800-53 Rev. 5 control mapping
 *   5. False Positive Review — FP likelihood assessment
 *   6. Remediation Planner — actionable fix guidance
 *   7. Report Writer — professional assessment prose
 *   8. Executive Summary — leadership-ready overview
 *
 * Each prompt returns a structured JSON schema for deterministic LLM output.
 */

// ─── Triage System Prompt ───────────────────────────────────────────────────

export const TRIAGE_SYSTEM_PROMPT = `You are the ScanForge Triage Analyst for Ace C3.
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

export const TRIAGE_RESPONSE_SCHEMA = {
  type: "json_schema" as const,
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
        remediation_priority_notes: { type: "array", items: { type: "string" } },
      },
      required: ["finding_id", "state", "confidence", "why", "missing_evidence", "recommended_next_validation", "attack_path_notes", "remediation_priority_notes"],
      additionalProperties: false,
    },
  },
};

// ─── Finding Enrichment Prompt ──────────────────────────────────────────────

export const FINDING_ENRICHMENT_PROMPT = `Task: Enrich a ScanForge finding for analyst review and reporting.

Input: finding JSON, asset JSON, scoring JSON, optional intel JSON.

Instructions:
1. Summarize what was observed.
2. Explain why it matters on this specific asset.
3. Note preconditions and practical exploitability.
4. Produce clean remediation language.
5. Keep wording suitable for a professional pentest or security assessment report.`;

export const FINDING_ENRICHMENT_SCHEMA = {
  type: "json_schema" as const,
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
        validation_status_note: { type: "string" },
      },
      required: ["title_refined", "analyst_summary", "affected_surface", "exploitability_assessment", "business_relevance", "remediation_summary", "validation_status_note"],
      additionalProperties: false,
    },
  },
};

// ─── Attack Mapping Prompt ──────────────────────────────────────────────────

export const ATTACK_MAPPING_PROMPT = `Task: Map a verified or probable ScanForge finding to realistic MITRE ATT&CK techniques.

Rules:
- Map only when the weakness plausibly supports a real adversary action.
- Do not map generic hygiene issues unless there is a credible ATT&CK relationship.
- Prefer the narrowest justified technique/sub-technique.
- Explain the bridge from evidence to ATT&CK.`;

export const ATTACK_MAPPING_SCHEMA = {
  type: "json_schema" as const,
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
              rationale: { type: "string" },
            },
            required: ["technique_id", "technique_name", "confidence", "rationale"],
            additionalProperties: false,
          },
        },
        non_mapped_reason: { type: "string" },
      },
      required: ["finding_id", "mappings", "non_mapped_reason"],
      additionalProperties: false,
    },
  },
};

// ─── FedRAMP Alignment Prompt ───────────────────────────────────────────────

export const FEDRAMP_ALIGNMENT_PROMPT = `Task: Align a ScanForge finding to likely FedRAMP / NIST SP 800-53 Rev. 5 control considerations.

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

export const FEDRAMP_ALIGNMENT_SCHEMA = {
  type: "json_schema" as const,
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
              rationale: { type: "string" },
            },
            required: ["control_id", "relationship", "rationale"],
            additionalProperties: false,
          },
        },
        poam_candidate: { type: "boolean" },
        recommended_owner_roles: { type: "array", items: { type: "string" } },
      },
      required: ["finding_id", "likely_controls", "poam_candidate", "recommended_owner_roles"],
      additionalProperties: false,
    },
  },
};

// ─── False Positive Reviewer Prompt ─────────────────────────────────────────

export const FALSE_POSITIVE_REVIEWER_PROMPT = `Task: Review whether a ScanForge finding may be a false positive.

Instructions:
- Examine whether evidence is incomplete, contradictory, or stale.
- Check if fingerprinting confidence is too low.
- Check whether the plugin logic may over-match.
- Suggest the least invasive next validation step.`;

export const FALSE_POSITIVE_REVIEWER_SCHEMA = {
  type: "json_schema" as const,
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
        recommended_state: { type: "string", enum: ["verified", "probable", "suspected", "informational", "not_affected"] },
      },
      required: ["finding_id", "false_positive_likelihood", "main_concerns", "evidence_gaps", "next_best_check", "recommended_state"],
      additionalProperties: false,
    },
  },
};

// ─── Remediation Planner Prompt ─────────────────────────────────────────────

export const REMEDIATION_PLANNER_PROMPT = `Task: Create remediation guidance for a ScanForge finding.

Requirements:
- Prioritize actionable changes.
- Order immediate containment, durable fix, and validation steps.
- Mention rollback or outage considerations when relevant.
- Keep recommendations technically precise.`;

export const REMEDIATION_PLANNER_SCHEMA = {
  type: "json_schema" as const,
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
        change_risk_notes: { type: "array", items: { type: "string" } },
      },
      required: ["finding_id", "immediate_actions", "durable_fixes", "validation_steps", "owner_suggestions", "change_risk_notes"],
      additionalProperties: false,
    },
  },
};

// ─── Report Writer Prompt ───────────────────────────────────────────────────

export const REPORT_WRITER_PROMPT = `Task: Convert the finding package into report-ready prose.

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

export const REPORT_WRITER_SCHEMA = {
  type: "json_schema" as const,
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
        recommendation: { type: "string" },
      },
      required: ["title", "condition", "risk", "evidence", "impact", "recommendation"],
      additionalProperties: false,
    },
  },
};

// ─── Executive Summary Prompt ───────────────────────────────────────────────

export const EXECUTIVE_SUMMARY_PROMPT = `Task: Produce a short executive summary of the assessment wave.

Requirements:
- Summarize the most important risks in plain English.
- State what was verified vs probable.
- Mention exposure and business impact.
- Avoid deep technical detail.
- Keep tone suitable for leadership.`;

export const EXECUTIVE_SUMMARY_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "scanforge_exec_summary",
    strict: true,
    schema: {
      type: "object",
      properties: {
        summary: { type: "string" },
        top_risks: { type: "array", items: { type: "string" } },
        urgent_actions: { type: "array", items: { type: "string" } },
        confidence_notes: { type: "string" },
      },
      required: ["summary", "top_risks", "urgent_actions", "confidence_notes"],
      additionalProperties: false,
    },
  },
};

// ─── Prompt Registry ────────────────────────────────────────────────────────

export type ScanForgePromptId =
  | "triage"
  | "enrichment"
  | "attack_mapping"
  | "fedramp"
  | "false_positive"
  | "remediation"
  | "report_writer"
  | "executive_summary";

export interface ScanForgePromptConfig {
  id: ScanForgePromptId;
  name: string;
  description: string;
  systemPrompt?: string;
  userPrompt: string;
  responseSchema: any;
  /** Pipeline stage where this prompt is typically used */
  stage: "reasoning" | "reporting" | "verification";
}

export const PROMPT_REGISTRY: Record<ScanForgePromptId, ScanForgePromptConfig> = {
  triage: {
    id: "triage",
    name: "Triage Analyst",
    description: "Classify finding state (verified/probable/suspected) with evidence-based reasoning",
    systemPrompt: TRIAGE_SYSTEM_PROMPT,
    userPrompt: "Analyze the following ScanForge finding and asset data. Determine the finding state and provide evidence-based reasoning.",
    responseSchema: TRIAGE_RESPONSE_SCHEMA,
    stage: "reasoning",
  },
  enrichment: {
    id: "enrichment",
    name: "Finding Enrichment",
    description: "Enrich findings with analyst summaries, exploitability assessment, and remediation language",
    userPrompt: FINDING_ENRICHMENT_PROMPT,
    responseSchema: FINDING_ENRICHMENT_SCHEMA,
    stage: "reasoning",
  },
  attack_mapping: {
    id: "attack_mapping",
    name: "ATT&CK Mapper",
    description: "Map findings to MITRE ATT&CK techniques with confidence and rationale",
    userPrompt: ATTACK_MAPPING_PROMPT,
    responseSchema: ATTACK_MAPPING_SCHEMA,
    stage: "reasoning",
  },
  fedramp: {
    id: "fedramp",
    name: "FedRAMP Alignment",
    description: "Align findings to NIST 800-53 Rev. 5 controls for SSP/SAR/POA&M support",
    userPrompt: FEDRAMP_ALIGNMENT_PROMPT,
    responseSchema: FEDRAMP_ALIGNMENT_SCHEMA,
    stage: "reasoning",
  },
  false_positive: {
    id: "false_positive",
    name: "False Positive Reviewer",
    description: "Assess false positive likelihood and suggest next validation steps",
    userPrompt: FALSE_POSITIVE_REVIEWER_PROMPT,
    responseSchema: FALSE_POSITIVE_REVIEWER_SCHEMA,
    stage: "verification",
  },
  remediation: {
    id: "remediation",
    name: "Remediation Planner",
    description: "Generate actionable remediation guidance with containment, fix, and validation steps",
    userPrompt: REMEDIATION_PLANNER_PROMPT,
    responseSchema: REMEDIATION_PLANNER_SCHEMA,
    stage: "reporting",
  },
  report_writer: {
    id: "report_writer",
    name: "Report Writer",
    description: "Convert findings into professional assessment prose",
    userPrompt: REPORT_WRITER_PROMPT,
    responseSchema: REPORT_WRITER_SCHEMA,
    stage: "reporting",
  },
  executive_summary: {
    id: "executive_summary",
    name: "Executive Summary",
    description: "Produce leadership-ready assessment summary",
    userPrompt: EXECUTIVE_SUMMARY_PROMPT,
    responseSchema: EXECUTIVE_SUMMARY_SCHEMA,
    stage: "reporting",
  },
};

// ─── Prompt Builder Helpers ─────────────────────────────────────────────────

/**
 * Build a complete LLM message array for a ScanForge prompt.
 */
export function buildPromptMessages(
  promptId: ScanForgePromptId,
  findingJson: string,
  assetJson?: string,
  scoringJson?: string,
  additionalContext?: string,
): Array<{ role: "system" | "user"; content: string }> {
  const config = PROMPT_REGISTRY[promptId];
  const messages: Array<{ role: "system" | "user"; content: string }> = [];

  // System prompt (triage has its own, others use a generic one)
  if (config.systemPrompt) {
    messages.push({ role: "system", content: config.systemPrompt });
  } else {
    messages.push({
      role: "system",
      content: "You are a ScanForge security analyst for Ace C3. Follow the task instructions precisely. Return structured JSON output as specified. Use only the evidence provided — do not invent findings.",
    });
  }

  // User prompt with data
  let userContent = config.userPrompt + "\n\n";
  userContent += `## Finding\n\`\`\`json\n${findingJson}\n\`\`\`\n\n`;

  if (assetJson) {
    userContent += `## Asset\n\`\`\`json\n${assetJson}\n\`\`\`\n\n`;
  }

  if (scoringJson) {
    userContent += `## Scoring\n\`\`\`json\n${scoringJson}\n\`\`\`\n\n`;
  }

  if (additionalContext) {
    userContent += `## Additional Context\n${additionalContext}\n`;
  }

  messages.push({ role: "user", content: userContent });

  return messages;
}

/**
 * Get the response_format config for a ScanForge prompt.
 */
export function getResponseFormat(promptId: ScanForgePromptId) {
  return PROMPT_REGISTRY[promptId].responseSchema;
}

// ─── Workflow Stage Definitions ─────────────────────────────────────────────

export const SCANFORGE_WORKFLOW_STAGES = [
  { name: "intake", actions: ["normalize_assets", "de_duplicate_targets", "classify_exposure"] },
  { name: "passive_enrichment", actions: ["dns_enrichment", "certificate_metadata", "cloud_provider_inference"] },
  { name: "fingerprinting", actions: ["banner_grab", "http_header_probe", "tls_matrix"] },
  { name: "detection", actions: ["run_safe_plugins", "attach_evidence"] },
  { name: "verification", actions: ["bounded_rechecks", "classify_state"] },
  { name: "scoring", actions: ["compute_cvss_context", "apply_hybrid_priority"] },
  { name: "reasoning", actions: ["triage_prompt", "attack_mapping_prompt", "fedramp_alignment_prompt"] },
  { name: "reporting", actions: ["report_writer_prompt", "executive_summary_prompt"] },
] as const;

/**
 * Get the prompts that should run for a given workflow stage.
 */
export function getPromptsForStage(stage: string): ScanForgePromptId[] {
  return Object.values(PROMPT_REGISTRY)
    .filter(p => p.stage === stage)
    .map(p => p.id);
}

// ─── Strict Passive Mode Policy ─────────────────────────────────────────────

export const STRICT_PASSIVE_MODE_POLICY = {
  allowed: [
    "DNS resolution and passive DNS lookups",
    "Certificate transparency review",
    "Public metadata and OSINT enrichment",
    "Third-party exposure intelligence from authorized providers",
    "Internal correlation against prior results",
  ],
  prohibited: [
    "Direct service probing",
    "Authentication attempts",
    "Payload-based validation",
    "Content retrieval beyond public metadata",
    "Rate-based discovery that touches the target directly",
  ],
  outputLabels: {
    collection_mode: "passive",
    direct_interaction: false,
  },
  analystNote: "Passive mode is valuable for exposure intelligence but is not a substitute for direct technical validation.",
};
