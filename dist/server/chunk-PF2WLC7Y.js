import {
  renderEvidencePackage
} from "./chunk-HAF2NEAB.js";

// server/lib/llm-specialists/validation.ts
var TRAINING_DATA_INDICATORS = [
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
  "according to wikipedia"
];
var MAX_CONFIDENCE_BY_WEIGHT = {
  "strong_multiple": 100,
  // Multiple strong sources converging
  "strong_single": 80,
  // Single strong source
  "moderate_multiple": 75,
  // Multiple moderate sources
  "moderate_single": 60,
  // Single moderate source
  "weak_multiple": 50,
  // Multiple weak sources
  "weak_single": 35,
  // Single weak source
  "none": 15
  // No direct evidence
};
function validateEvidenceGrounding(evidenceRefs, pkg) {
  const failures = [];
  const renderedPackage = renderEvidencePackage(pkg).toLowerCase();
  for (const ref of evidenceRefs) {
    const sourceParts = ref.source.split(".");
    let current = pkg;
    let sourceValid = true;
    for (const part of sourceParts) {
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
      if (ref.detail && renderedPackage.includes(ref.detail.toLowerCase())) {
        continue;
      }
      failures.push(
        `Evidence reference "${ref.source}" does not map to a field in the evidence package`
      );
    }
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
function checkTrainingDataLeakage(text) {
  const failures = [];
  const lower = text.toLowerCase();
  for (const indicator of TRAINING_DATA_INDICATORS) {
    if (lower.includes(indicator)) {
      failures.push(`Training data leakage detected: "${indicator}" found in output`);
    }
  }
  return { passed: failures.length === 0, failures };
}
function validateConfidenceBounds(claims) {
  const failures = [];
  for (const claim of claims) {
    const evidenceProfile = categorizeEvidenceProfile(claim.supportingEvidence);
    const maxAllowed = MAX_CONFIDENCE_BY_WEIGHT[evidenceProfile] ?? 100;
    if (claim.confidenceScore > maxAllowed) {
      failures.push(
        `Claim for "${claim.attributedTo.organization}" has confidence ${claim.confidenceScore} but evidence profile "${evidenceProfile}" caps at ${maxAllowed}`
      );
    }
    const expectedBand = scoreToBand(claim.confidenceScore);
    if (claim.confidence !== expectedBand) {
      failures.push(
        `Claim confidence band "${claim.confidence}" doesn't match score ${claim.confidenceScore} (expected "${expectedBand}")`
      );
    }
  }
  return { passed: failures.length === 0, failures };
}
function validateAttributionOutput(output, pkg) {
  const allFailures = [];
  const allEvidence = output.claims.flatMap((c) => c.supportingEvidence);
  const grounding = validateEvidenceGrounding(allEvidence, pkg);
  if (!grounding.passed) allFailures.push(...grounding.failures);
  const allReasoning = output.claims.map((c) => c.reasoning).join(" ");
  const leakage = checkTrainingDataLeakage(allReasoning);
  if (!leakage.passed) allFailures.push(...leakage.failures);
  const bounds = validateConfidenceBounds(output.claims);
  if (!bounds.passed) allFailures.push(...bounds.failures);
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
      confidenceWithinEvidenceBounds: bounds.passed
    },
    failures: allFailures
  };
}
function validateGenericSpecialistOutput(evidenceRefs, reasoning, pkg) {
  const allFailures = [];
  const grounding = validateEvidenceGrounding(evidenceRefs, pkg);
  if (!grounding.passed) allFailures.push(...grounding.failures);
  const leakage = checkTrainingDataLeakage(reasoning);
  if (!leakage.passed) allFailures.push(...leakage.failures);
  return {
    passed: allFailures.length === 0,
    groundingChecks: {
      allEvidenceReferencesExistInInput: grounding.passed,
      noTrainingDataCitations: leakage.passed,
      confidenceWithinEvidenceBounds: true
      // generic check doesn't enforce bounds
    },
    failures: allFailures
  };
}
var MAX_DELTA = 20;
function clampDelta(delta) {
  return Math.max(-MAX_DELTA, Math.min(MAX_DELTA, delta));
}
function applyBoundedDelta(baseline, delta) {
  const clamped = clampDelta(delta);
  return Math.max(0, Math.min(100, baseline + clamped));
}
function mapSourceToField(part) {
  const mapping = {
    "subject_o": "subjectO",
    "subject_cn": "subjectCN",
    "issuer_o": "issuerO",
    "issuer_cn": "issuerCN",
    "registrant": "registrant",
    "registrant_org": "registrantOrg",
    "as_holder": "asHolder",
    "sec_edgar": "secEdgarMatch",
    "company_name": "companyName"
  };
  return mapping[part] || part;
}
function categorizeEvidenceProfile(evidence) {
  if (evidence.length === 0) return "none";
  const strongCount = evidence.filter((e) => e.weight === "strong").length;
  const moderateCount = evidence.filter((e) => e.weight === "moderate").length;
  const weakCount = evidence.filter((e) => e.weight === "weak").length;
  if (strongCount >= 2) return "strong_multiple";
  if (strongCount === 1) return "strong_single";
  if (moderateCount >= 2) return "moderate_multiple";
  if (moderateCount === 1) return "moderate_single";
  if (weakCount >= 2) return "weak_multiple";
  if (weakCount === 1) return "weak_single";
  return "none";
}
function scoreToBand(score) {
  if (score >= 75) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export {
  validateAttributionOutput,
  validateGenericSpecialistOutput,
  applyBoundedDelta,
  scoreToBand
};
