/**
 * LLM Evidence Guardrail
 *
 * Post-processing validation layer that sits between LLM specialist output
 * and evidence storage/reporting. Ensures all LLM-generated content that
 * enters evidence records or reports is grounded in actual tool output.
 *
 * Integration points:
 *   1. Report Writer — validates generated findings against raw scan data
 *   2. Vuln Verifier — validates verdict against actual evidence
 *   3. Attack Planner — validates attack paths against discovered assets
 *   4. Scan Analyst — validates analysis against raw tool output
 *   5. Pentest Report Pipeline — validates full report sections
 *
 * @module llm-evidence-guardrail
 */

import {
  checkHallucination,
  sanitizeEvidence,
  sha256,
  buildProvenance,
  createIntegrityEnvelope,
  recordCustodyEvent,
  type HallucinationCheckResult,
  type EvidenceSourceTool,
} from "./evidence-integrity-guardrails";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GuardrailContext {
  /** Which LLM specialist produced this output */
  specialist: string;
  /** Engagement ID for chain tracking */
  engagementId: string;
  /** Raw tool outputs that the LLM was given as input */
  toolOutputs: Record<string, string>;
  /** Known assets from the engagement */
  knownAssets?: Array<{ hostname: string; ip: string; ports?: number[] }>;
  /** Known CVEs from scanning */
  knownCves?: string[];
  /** Known services from enumeration */
  knownServices?: Array<{ port: number; service: string; version?: string }>;
  /** Strictness level */
  strictness?: "strict" | "moderate" | "lenient";
  /** Collector host (scan server) */
  collectorHost?: string;
  /** Source IP of the scanner */
  sourceIp?: string;
  /** Destination IP of the target */
  destinationIp?: string;
}

export interface GuardrailResult {
  /** Whether the content passed all guardrails */
  passed: boolean;
  /** The content (possibly sanitized) */
  content: string;
  /** Whether the content was modified by sanitization */
  wasSanitized: boolean;
  /** Hallucination check details */
  hallucinationCheck: HallucinationCheckResult;
  /** Content hash for integrity tracking */
  contentHash: string;
  /** Integrity envelope ID (if created) */
  envelopeId: string | null;
  /** Warnings that don't block but should be logged */
  warnings: string[];
  /** Errors that caused the guardrail to fail */
  errors: string[];
  /** Recommendation */
  recommendation: "accept" | "review" | "reject" | "quarantine";
}

// ─── Guardrail Functions ────────────────────────────────────────────────────

/**
 * Validate LLM-generated report finding against ground truth.
 *
 * Checks:
 *   - CVEs mentioned are from actual scan results
 *   - IPs/hostnames match engagement scope
 *   - Ports match enumeration data
 *   - Exploit claims are backed by tool output
 *   - CVSS scores are within valid range
 *   - Evidence data matches raw scanner output
 */
export function validateReportFinding(
  finding: {
    title: string;
    severity: string;
    cvss_score: number;
    affected_asset: string;
    description: string;
    evidence: Array<{ type: string; description: string; data: string }>;
    impact: string;
    reproduction_steps: string[];
    remediation: { short_term: string; long_term: string; effort: string };
    references: string[];
    mitre_mapping: Array<{ technique_id: string; technique_name: string; tactic: string }>;
  },
  context: GuardrailContext,
): GuardrailResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Serialize the finding for hallucination checking
  const findingText = [
    finding.title,
    finding.description,
    finding.impact,
    finding.affected_asset,
    ...finding.evidence.map(e => `${e.description}: ${e.data}`),
    ...finding.reproduction_steps,
    finding.remediation.short_term,
    finding.remediation.long_term,
    ...finding.references,
  ].join("\n");

  // 1. CVSS validation
  if (finding.cvss_score < 0 || finding.cvss_score > 10) {
    errors.push(`Invalid CVSS score: ${finding.cvss_score}. Must be 0.0-10.0`);
  }

  // 2. Severity-CVSS consistency check
  const severityRanges: Record<string, [number, number]> = {
    Critical: [9.0, 10.0],
    High: [7.0, 8.9],
    Medium: [4.0, 6.9],
    Low: [0.1, 3.9],
    Informational: [0.0, 0.0],
  };
  const expectedRange = severityRanges[finding.severity];
  if (expectedRange) {
    if (finding.cvss_score < expectedRange[0] || finding.cvss_score > expectedRange[1]) {
      warnings.push(
        `Severity "${finding.severity}" inconsistent with CVSS ${finding.cvss_score}. ` +
        `Expected range: ${expectedRange[0]}-${expectedRange[1]}`
      );
    }
  }

  // 3. MITRE ATT&CK technique ID format validation
  for (const mapping of finding.mitre_mapping) {
    if (!/^T\d{4}(\.\d{3})?$/.test(mapping.technique_id)) {
      warnings.push(`Invalid ATT&CK technique ID format: ${mapping.technique_id}`);
    }
  }

  // 4. Evidence data cross-reference
  for (const evidence of finding.evidence) {
    if (evidence.data && evidence.data.length > 50) {
      // Check if evidence data appears in any tool output
      const foundInToolOutput = Object.values(context.toolOutputs).some(output => {
        // Check for substantial substring overlap (not just single words)
        const dataChunks = evidence.data.match(/.{20,}/g) || [];
        return dataChunks.some(chunk => output.includes(chunk));
      });

      if (!foundInToolOutput && evidence.type !== "configuration") {
        warnings.push(
          `Evidence data for "${evidence.description}" not found in any tool output. ` +
          `May be LLM-generated rather than captured from actual scan.`
        );
      }
    }
  }

  // 5. Full hallucination check
  const hallucinationCheck = checkHallucination({
    llmContent: findingText,
    groundTruth: context.toolOutputs,
    knownAssets: context.knownAssets,
    knownCves: context.knownCves,
    knownServices: context.knownServices,
    strictness: context.strictness || "moderate",
  });

  warnings.push(...hallucinationCheck.warnings);

  // 6. Sanitize if needed
  let content = findingText;
  let wasSanitized = false;
  if (hallucinationCheck.recommendation === "review" || hallucinationCheck.recommendation === "reject") {
    const sanitized = sanitizeEvidence(findingText, hallucinationCheck);
    if (sanitized.annotations.length > 0) {
      wasSanitized = true;
      content = sanitized.sanitized;
      warnings.push(...sanitized.annotations);
    }
  }

  const contentHash = sha256(content);
  const passed = errors.length === 0 && hallucinationCheck.recommendation !== "quarantine" && hallucinationCheck.recommendation !== "reject";

  return {
    passed,
    content,
    wasSanitized,
    hallucinationCheck,
    contentHash,
    envelopeId: null,
    warnings,
    errors,
    recommendation: hallucinationCheck.recommendation,
  };
}

/**
 * Validate LLM vulnerability verification output.
 * Ensures the verdict is consistent with the evidence provided.
 */
export function validateVulnVerification(
  verification: {
    finding_summary: string;
    affected_asset: string;
    evidence_review: Array<{ tag: string; detail: string }>;
    false_positive_likelihood: string;
    exploitability: { rating: string; prerequisites: string[]; known_exploits: boolean; rationale: string };
    business_impact: { severity: string; rationale: string };
    analyst_verdict: string;
    confidence: string;
  },
  context: GuardrailContext,
): GuardrailResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Serialize for hallucination check
  const verificationText = [
    verification.finding_summary,
    verification.affected_asset,
    ...verification.evidence_review.map(e => `[${e.tag}] ${e.detail}`),
    verification.exploitability.rationale,
    verification.business_impact.rationale,
    verification.analyst_verdict,
  ].join("\n");

  // 1. Evidence tag validation — ensure OBSERVED claims match tool output
  for (const review of verification.evidence_review) {
    if (review.tag === "OBSERVED") {
      // OBSERVED claims MUST be traceable to tool output
      const foundInOutput = Object.values(context.toolOutputs).some(output =>
        review.detail.split(" ").filter(w => w.length > 4).some(word => output.toLowerCase().includes(word.toLowerCase()))
      );
      if (!foundInOutput) {
        warnings.push(`[OBSERVED] claim not traceable to tool output: "${review.detail.slice(0, 100)}"`);
      }
    }
  }

  // 2. Verdict consistency checks
  const validVerdicts = [
    "True Positive", "Likely True Positive", "Inconclusive",
    "Likely False Positive", "False Positive",
  ];
  if (!validVerdicts.includes(verification.analyst_verdict)) {
    errors.push(`Invalid analyst verdict: "${verification.analyst_verdict}"`);
  }

  // 3. Severity validation
  const validSeverities = ["Critical", "High", "Medium", "Low", "Informational"];
  if (!validSeverities.includes(verification.business_impact.severity)) {
    errors.push(`Invalid severity: "${verification.business_impact.severity}"`);
  }

  // 4. Exploitability-verdict consistency
  if (verification.exploitability.rating === "Confirmed" && verification.analyst_verdict === "False Positive") {
    errors.push("Contradictory: exploitability is 'Confirmed' but verdict is 'False Positive'");
  }
  if (verification.exploitability.rating === "Unlikely" && verification.analyst_verdict === "True Positive") {
    warnings.push("Inconsistency: exploitability is 'Unlikely' but verdict is 'True Positive'");
  }

  // 5. Hallucination check on the full text
  const hallucinationCheck = checkHallucination({
    llmContent: verificationText,
    groundTruth: context.toolOutputs,
    knownAssets: context.knownAssets,
    knownCves: context.knownCves,
    strictness: context.strictness || "moderate",
  });

  warnings.push(...hallucinationCheck.warnings);

  let content = verificationText;
  let wasSanitized = false;
  if (hallucinationCheck.recommendation !== "accept") {
    const sanitized = sanitizeEvidence(verificationText, hallucinationCheck);
    if (sanitized.annotations.length > 0) {
      wasSanitized = true;
      content = sanitized.sanitized;
    }
  }

  const contentHash = sha256(content);
  const passed = errors.length === 0 && hallucinationCheck.recommendation !== "quarantine";

  return {
    passed,
    content,
    wasSanitized,
    hallucinationCheck,
    contentHash,
    envelopeId: null,
    warnings,
    errors,
    recommendation: hallucinationCheck.recommendation,
  };
}

/**
 * Validate LLM-generated attack plan against discovered assets.
 * Ensures attack paths only reference assets and services that were actually found.
 */
export function validateAttackPlan(
  plan: {
    attack_objective: string;
    initial_access_options: Array<{ vector: string; target: string; feasibility: string; evidence_tag: string; rationale: string }>;
    attack_chain: Array<{ stage: string; technique: string; mitre_id: string; target: string; description: string }>;
  },
  context: GuardrailContext,
): GuardrailResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Serialize
  const planText = [
    plan.attack_objective,
    ...plan.initial_access_options.map(o => `[${o.evidence_tag}] ${o.vector} → ${o.target}: ${o.rationale}`),
    ...plan.attack_chain.map(c => `${c.stage}: ${c.technique} (${c.mitre_id}) → ${c.target}`),
  ].join("\n");

  // 1. Validate evidence tags
  for (const option of plan.initial_access_options) {
    if (!["OBSERVED", "INFERRED", "HYPOTHESIS"].includes(option.evidence_tag)) {
      errors.push(`Invalid evidence tag: "${option.evidence_tag}". Must be OBSERVED, INFERRED, or HYPOTHESIS.`);
    }

    // OBSERVED options must have tool output backing
    if (option.evidence_tag === "OBSERVED") {
      const hasEvidence = Object.values(context.toolOutputs).some(output =>
        output.toLowerCase().includes(option.target.toLowerCase()) ||
        output.toLowerCase().includes(option.vector.toLowerCase().split(" ")[0])
      );
      if (!hasEvidence) {
        warnings.push(`Attack option tagged [OBSERVED] but no supporting tool output: "${option.vector}" on ${option.target}`);
      }
    }
  }

  // 2. MITRE ATT&CK ID validation
  for (const step of plan.attack_chain) {
    if (!/^T\d{4}(\.\d{3})?$/.test(step.mitre_id)) {
      warnings.push(`Invalid ATT&CK technique ID: ${step.mitre_id} in attack chain step "${step.stage}"`);
    }
  }

  // 3. Hallucination check
  const hallucinationCheck = checkHallucination({
    llmContent: planText,
    groundTruth: context.toolOutputs,
    knownAssets: context.knownAssets,
    knownCves: context.knownCves,
    strictness: context.strictness || "moderate",
  });

  warnings.push(...hallucinationCheck.warnings);

  const contentHash = sha256(planText);
  const passed = errors.length === 0 && hallucinationCheck.recommendation !== "quarantine";

  return {
    passed,
    content: planText,
    wasSanitized: false,
    hallucinationCheck,
    contentHash,
    envelopeId: null,
    warnings,
    errors,
    recommendation: hallucinationCheck.recommendation,
  };
}

/**
 * Generic guardrail for any LLM-generated text that will become evidence.
 * Use this when the specific specialist guardrail doesn't apply.
 */
export function validateLLMEvidence(
  content: string,
  context: GuardrailContext,
): GuardrailResult {
  const hallucinationCheck = checkHallucination({
    llmContent: content,
    groundTruth: context.toolOutputs,
    knownAssets: context.knownAssets,
    knownCves: context.knownCves,
    knownServices: context.knownServices,
    strictness: context.strictness || "moderate",
  });

  let finalContent = content;
  let wasSanitized = false;
  if (hallucinationCheck.recommendation !== "accept") {
    const sanitized = sanitizeEvidence(content, hallucinationCheck);
    if (sanitized.annotations.length > 0) {
      wasSanitized = true;
      finalContent = sanitized.sanitized;
    }
  }

  const contentHash = sha256(finalContent);

  return {
    passed: hallucinationCheck.recommendation !== "quarantine" && hallucinationCheck.recommendation !== "reject",
    content: finalContent,
    wasSanitized,
    hallucinationCheck,
    contentHash,
    envelopeId: null,
    warnings: hallucinationCheck.warnings,
    errors: hallucinationCheck.recommendation === "quarantine"
      ? ["Critical hallucination detected — evidence quarantined"]
      : hallucinationCheck.recommendation === "reject"
        ? ["Too many ungrounded claims — evidence rejected"]
        : [],
    recommendation: hallucinationCheck.recommendation,
  };
}

// ─── Guardrail Wrapper for LLM Calls ───────────────────────────────────────

/**
 * Wrap an LLM specialist call with post-processing guardrails.
 * Creates an integrity envelope and validates the output.
 *
 * Usage:
 *   const result = await withGuardrail(
 *     () => writeReportFinding(input),
 *     { specialist: "report-writer", engagementId: "123", toolOutputs: { nmap: "..." } },
 *     (output) => validateReportFinding(output, context),
 *   );
 */
export async function withGuardrail<T>(
  llmCall: () => Promise<T>,
  context: GuardrailContext,
  validator: (output: T) => GuardrailResult,
): Promise<{ output: T; guardrail: GuardrailResult }> {
  // Execute the LLM call
  const output = await llmCall();

  // Run the guardrail validation
  const guardrail = validator(output);

  // Create integrity envelope for tracking
  const serialized = JSON.stringify(output);
  const provenance = buildProvenance({
    tool: "llm_analysis",
    command: `specialist:${context.specialist}`,
    collectorHost: context.collectorHost || "ac3-platform",
    rawOutput: serialized,
    targetHost: context.knownAssets?.[0]?.hostname || "unknown",
    sourceIp: context.sourceIp || "127.0.0.1",
    destinationIp: context.destinationIp || "unknown",
  });

  const evidenceId = `llm_${context.specialist}_${sha256(serialized).slice(0, 12)}`;
  const envelope = createIntegrityEnvelope({
    evidenceId,
    engagementId: context.engagementId,
    content: serialized,
    provenance,
    performedBy: `AC3 ${context.specialist}`,
  });

  // Record validation result
  if (guardrail.passed) {
    recordCustodyEvent(envelope, "validated", "AC3 Guardrail", `Passed: score=${guardrail.hallucinationCheck.score.toFixed(2)}, recommendation=${guardrail.recommendation}`);
  } else if (guardrail.recommendation === "quarantine") {
    recordCustodyEvent(envelope, "quarantined", "AC3 Guardrail", `Quarantined: ${guardrail.errors.join("; ")}`);
  }

  guardrail.envelopeId = evidenceId;

  // Log guardrail result
  const logPrefix = `[Guardrail:${context.specialist}]`;
  if (!guardrail.passed) {
    console.warn(`${logPrefix} FAILED: ${guardrail.errors.join("; ")}`);
  } else if (guardrail.wasSanitized) {
    console.log(`${logPrefix} PASSED with sanitization: ${guardrail.warnings.length} warnings`);
  } else if (guardrail.warnings.length > 0) {
    console.log(`${logPrefix} PASSED with ${guardrail.warnings.length} warnings`);
  }

  return { output, guardrail };
}

// ─── Report Section Guardrail ───────────────────────────────────────────────

/**
 * Validate an entire report section (e.g., executive summary, findings narrative).
 * Used by the pentest report pipeline before including LLM-generated sections.
 */
export function validateReportSection(
  sectionContent: string,
  sectionName: string,
  context: GuardrailContext,
): {
  valid: boolean;
  sanitizedContent: string;
  hallucinationScore: number;
  warnings: string[];
  errors: string[];
} {
  const result = validateLLMEvidence(sectionContent, context);

  return {
    valid: result.passed,
    sanitizedContent: result.content,
    hallucinationScore: result.hallucinationCheck.score,
    warnings: result.warnings,
    errors: result.errors,
  };
}
