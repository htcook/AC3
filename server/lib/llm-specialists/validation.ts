/**
 * LLM Specialist Output Validation
 * 
 * Every specialist output passes through validation before being accepted.
 * Validation enforces evidence grounding, confidence calibration, and
 * prevents training-data leakage.
 */

import type {
  ValidationResult,
  EvidenceReference,
  StructuredEvidencePackage,
  AttributionSpecialistOutput,
  AttributionClaim,
  ConfidenceBand,
} from "./types";
import { renderEvidencePackage } from "./evidence-package";

// ─── Training Data Leakage Indicators ─────────────────────────────
const TRAINING_DATA_INDICATORS = [
  "as of my training",
  "as of my knowledge cutoff",
  "i know that",
  "based on my knowledge",
  "i recall that",
  "from what i know",
  "it is well known",
  "according to my training",
  "in my training data",
  "i have learned that",
  "wikipedia states",
  "according to wikipedia",
];

// ─── Confidence Bounds by Evidence Weight ─────────────────────────
const MAX_CONFIDENCE_BY_WEIGHT: Record<string, number> = {
  "strong_multiple": 100,    // Multiple strong sources converging
  "strong_single": 80,       // Single strong source
  "moderate_multiple": 75,   // Multiple moderate sources
  "moderate_single": 60,     // Single moderate source
  "weak_multiple": 50,       // Multiple weak sources
  "weak_single": 35,         // Single weak source
  "none": 15,                // No direct evidence
};

// ─── Core Validation ──────────────────────────────────────────────

/**
 * Validate that all evidence references in the output actually exist
 * in the input evidence package.
 */
export function validateEvidenceGrounding(
  evidenceRefs: EvidenceReference[],
  pkg: StructuredEvidencePackage
): { passed: boolean; failures: string[] } {
  const failures: string[] = [];
  const renderedPackage = renderEvidencePackage(pkg).toLowerCase();

  for (const ref of evidenceRefs) {
    // Check that the source path maps to a real field in the package
    const sourceParts = ref.source.split(".");
    let current: any = pkg;
    let sourceValid = true;

    for (const part of sourceParts) {
      // Map common source paths to package fields
      const mapped = mapSourceToField(part);
      if (current && typeof current === "object" && mapped in current) {
        current = current[mapped];
      } else if (current && typeof current === "object" && part in current) {
        current = current[part];
      } else {
        sourceValid = false;
        break;
      }
    }

    if (!sourceValid) {
      // Fallback: check if the detail text appears anywhere in the rendered package
      if (ref.detail && renderedPackage.includes(ref.detail.toLowerCase())) {
        // Detail found in package — source path is just poorly formatted
        continue;
      }
      failures.push(
        `Evidence reference "${ref.source}" does not map to a field in the evidence package`
      );
    }

    // Check that the detail text appears in the package
    if (ref.detail) {
      const detailLower = ref.detail.toLowerCase().trim();
      if (detailLower.length > 0 && !renderedPackage.includes(detailLower)) {
        failures.push(
          `Evidence detail "${ref.detail}" from source "${ref.source}" not found verbatim in evidence package`
        );
      }
    }
  }

  return { passed: failures.length === 0, failures };
}

/**
 * Check for training data leakage in reasoning text.
 */
export function checkTrainingDataLeakage(text: string): { passed: boolean; failures: string[] } {
  const failures: string[] = [];
  const lower = text.toLowerCase();

  for (const indicator of TRAINING_DATA_INDICATORS) {
    if (lower.includes(indicator)) {
      failures.push(`Training data leakage detected: "${indicator}" found in output`);
    }
  }

  return { passed: failures.length === 0, failures };
}

/**
 * Validate that confidence scores are within bounds supported by evidence.
 */
export function validateConfidenceBounds(
  claims: AttributionClaim[]
): { passed: boolean; failures: string[] } {
  const failures: string[] = [];

  for (const claim of claims) {
    const evidenceProfile = categorizeEvidenceProfile(claim.supportingEvidence);
    const maxAllowed = MAX_CONFIDENCE_BY_WEIGHT[evidenceProfile] ?? 100;

    if (claim.confidenceScore > maxAllowed) {
      failures.push(
        `Claim for "${claim.attributedTo.organization}" has confidence ${claim.confidenceScore} ` +
        `but evidence profile "${evidenceProfile}" caps at ${maxAllowed}`
      );
    }

    // Validate confidence band matches score
    const expectedBand = scoreToBand(claim.confidenceScore);
    if (claim.confidence !== expectedBand) {
      failures.push(
        `Claim confidence band "${claim.confidence}" doesn't match score ${claim.confidenceScore} ` +
        `(expected "${expectedBand}")`
      );
    }
  }

  return { passed: failures.length === 0, failures };
}

/**
 * Full validation pipeline for attribution specialist output.
 */
export function validateAttributionOutput(
  output: AttributionSpecialistOutput,
  pkg: StructuredEvidencePackage
): ValidationResult {
  const allFailures: string[] = [];

  // 1. Evidence grounding check
  const allEvidence = output.claims.flatMap(c => c.supportingEvidence);
  const grounding = validateEvidenceGrounding(allEvidence, pkg);
  if (!grounding.passed) allFailures.push(...grounding.failures);

  // 2. Training data leakage check
  const allReasoning = output.claims.map(c => c.reasoning).join(" ");
  const leakage = checkTrainingDataLeakage(allReasoning);
  if (!leakage.passed) allFailures.push(...leakage.failures);

  // 3. Confidence bounds check
  const bounds = validateConfidenceBounds(output.claims);
  if (!bounds.passed) allFailures.push(...bounds.failures);

  // 4. Structural checks
  if (output.primaryClaim && !output.claims.includes(output.primaryClaim)) {
    allFailures.push("primaryClaim is not one of the claims array entries");
  }

  if (output.evidenceSufficiency === "insufficient" && output.claims.length > 0) {
    allFailures.push("evidenceSufficiency is 'insufficient' but claims array is non-empty");
  }

  return {
    passed: allFailures.length === 0,
    groundingChecks: {
      allEvidenceReferencesExistInInput: grounding.passed,
      noTrainingDataCitations: leakage.passed,
      confidenceWithinEvidenceBounds: bounds.passed,
    },
    failures: allFailures,
  };
}

/**
 * Generic validation for any specialist output with evidence references.
 */
export function validateGenericSpecialistOutput(
  evidenceRefs: EvidenceReference[],
  reasoning: string,
  pkg: StructuredEvidencePackage
): ValidationResult {
  const allFailures: string[] = [];

  const grounding = validateEvidenceGrounding(evidenceRefs, pkg);
  if (!grounding.passed) allFailures.push(...grounding.failures);

  const leakage = checkTrainingDataLeakage(reasoning);
  if (!leakage.passed) allFailures.push(...leakage.failures);

  return {
    passed: allFailures.length === 0,
    groundingChecks: {
      allEvidenceReferencesExistInInput: grounding.passed,
      noTrainingDataCitations: leakage.passed,
      confidenceWithinEvidenceBounds: true, // generic check doesn't enforce bounds
    },
    failures: allFailures,
  };
}

// ─── Bounded Delta Enforcement ────────────────────────────────────

const MAX_DELTA = 20;

/**
 * Clamp a delta value to the allowed range.
 */
export function clampDelta(delta: number): number {
  return Math.max(-MAX_DELTA, Math.min(MAX_DELTA, delta));
}

/**
 * Apply a bounded delta to a baseline score.
 * Result is clamped to [0, 100].
 */
export function applyBoundedDelta(baseline: number, delta: number): number {
  const clamped = clampDelta(delta);
  return Math.max(0, Math.min(100, baseline + clamped));
}

/**
 * Validate that LLM adjustments stay within bounded delta range.
 */
export function validateBoundedDelta(
  baselineScore: number,
  llmScore: number
): { passed: boolean; delta: number; clamped: number } {
  const delta = llmScore - baselineScore;
  const clamped = clampDelta(delta);
  return {
    passed: Math.abs(delta) <= MAX_DELTA,
    delta,
    clamped,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────

function mapSourceToField(part: string): string {
  const mapping: Record<string, string> = {
    "subject_o": "subjectO",
    "subject_cn": "subjectCN",
    "issuer_o": "issuerO",
    "issuer_cn": "issuerCN",
    "registrant": "registrant",
    "registrant_org": "registrantOrg",
    "as_holder": "asHolder",
    "sec_edgar": "secEdgarMatch",
    "company_name": "companyName",
  };
  return mapping[part] || part;
}

function categorizeEvidenceProfile(evidence: EvidenceReference[]): string {
  if (evidence.length === 0) return "none";

  const strongCount = evidence.filter(e => e.weight === "strong").length;
  const moderateCount = evidence.filter(e => e.weight === "moderate").length;
  const weakCount = evidence.filter(e => e.weight === "weak").length;

  if (strongCount >= 2) return "strong_multiple";
  if (strongCount === 1) return "strong_single";
  if (moderateCount >= 2) return "moderate_multiple";
  if (moderateCount === 1) return "moderate_single";
  if (weakCount >= 2) return "weak_multiple";
  if (weakCount === 1) return "weak_single";
  return "none";
}

export function scoreToBand(score: number): ConfidenceBand {
  if (score >= 75) return "high";
  if (score >= 40) return "medium";
  return "low";
}
