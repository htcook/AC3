/**
 * Asset Attribution Specialist — Main Invocation Logic
 * 
 * Given structured discovery evidence about a digital asset, produces
 * attribution claims about which organization owns the asset, with
 * per-claim confidence and supporting evidence references.
 * 
 * Architecture: deterministic baseline → LLM augmentation → validation → output
 */

import type {
  AttributionSpecialistInput,
  AttributionSpecialistOutput,
  AttributionClaim,
  ValidationResult,
  SpecialistInvocationMetadata,
  SpecialistMode,
  LLMInvokeFunction,
} from "../types";
import { computeDeterministicAttribution } from "./deterministic-baseline";
import { ATTRIBUTION_SPECIALIST_SYSTEM_PROMPT, SPECIALIST_VERSION, PROMPT_VERSION, MODEL_VERSION } from "./prompts";
import { validateAttributionOutput, applyBoundedDelta, scoreToBand } from "../validation";
import { renderEvidencePackage, hashPackage } from "../evidence-package";
import { createHash } from "crypto";
import { parseLLMJson } from "../../../../shared/llm-json-parser";

// ─── Invocation ID Generator ──────────────────────────────────────

function generateInvocationId(): string {
  return `attr-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;
}

// ─── Deterministic-Only Output Builder ────────────────────────────

function buildDeterministicOnlyOutput(
  input: AttributionSpecialistInput,
  deterministicClaims: AttributionClaim[],
  validationOrError: Partial<ValidationResult> & { failures: string[] }
): AttributionSpecialistOutput {
  // Select primary claim (highest confidence)
  const primaryClaim = deterministicClaims.length > 0
    ? deterministicClaims.reduce((a, b) => a.confidenceScore > b.confidenceScore ? a : b)
    : undefined;

  // Determine evidence sufficiency
  let evidenceSufficiency: "sufficient" | "partial" | "insufficient";
  if (deterministicClaims.length === 0) {
    evidenceSufficiency = "insufficient";
  } else if (primaryClaim && primaryClaim.confidence === "high") {
    evidenceSufficiency = "sufficient";
  } else {
    evidenceSufficiency = "partial";
  }

  return {
    asset: {
      id: input.evidencePackage.assetId,
      identifier: input.evidencePackage.assetIdentifier,
    },
    claims: deterministicClaims,
    primaryClaim,
    evidenceSufficiency,
    insufficiencyReason: deterministicClaims.length === 0
      ? "No deterministic attribution rules matched the evidence package."
      : undefined,
    validationResult: {
      passed: false,
      groundingChecks: {
        allEvidenceReferencesExistInInput: true,
        noTrainingDataCitations: true,
        confidenceWithinEvidenceBounds: true,
      },
      failures: validationOrError.failures,
      fallbackApplied: true,
    },
    metadata: {} as SpecialistInvocationMetadata, // filled by caller
  };
}

// ─── LLM Response Parser ──────────────────────────────────────────

function parseAndStructure(rawResponse: any, input: AttributionSpecialistInput): AttributionSpecialistOutput {
  let content: string;

  if (rawResponse?.choices?.[0]?.message?.content) {
    content = rawResponse.choices[0].message.content;
  } else if (typeof rawResponse === "string") {
    content = rawResponse;
  } else {
    throw new Error("Unexpected LLM response format");
  }

  // Strip markdown code fences if present
  // Code fence stripping now handled by parseLLMJson

  const parsed = parseLLMJson(content, { fallback: {} }).data;

  // Normalize the output structure
  const output: AttributionSpecialistOutput = {
    asset: parsed.asset || {
      id: input.evidencePackage.assetId,
      identifier: input.evidencePackage.assetIdentifier,
    },
    claims: (parsed.claims || []).map((c: any) => ({
      attributedTo: c.attributedTo || { organization: "Unknown" },
      claimType: c.claimType || "unknown",
      confidence: c.confidence || scoreToBand(c.confidenceScore || 0),
      confidenceScore: c.confidenceScore || 0,
      supportingEvidence: c.supportingEvidence || [],
      contradictingEvidence: c.contradictingEvidence || undefined,
      alternativeAttributions: c.alternativeAttributions || undefined,
      reasoning: c.reasoning || "",
    })),
    primaryClaim: undefined, // set below
    evidenceSufficiency: parsed.evidenceSufficiency || "partial",
    insufficiencyReason: parsed.insufficiencyReason || undefined,
    validationResult: {} as ValidationResult, // set by caller
    metadata: {} as SpecialistInvocationMetadata, // set by caller
  };

  // Set primary claim
  if (parsed.primaryClaim) {
    // Find matching claim in the array
    output.primaryClaim = output.claims.find(
      (c: AttributionClaim) => c.attributedTo.organization === parsed.primaryClaim?.attributedTo?.organization
    ) || output.claims[0];
  } else if (output.claims.length > 0) {
    output.primaryClaim = output.claims.reduce(
      (a: AttributionClaim, b: AttributionClaim) => a.confidenceScore > b.confidenceScore ? a : b
    );
  }

  return output;
}

// ─── Apply Bounded Deltas to LLM Output ───────────────────────────

function applyBoundedDeltas(
  llmClaims: AttributionClaim[],
  baselineClaims: AttributionClaim[]
): AttributionClaim[] {
  return llmClaims.map(llmClaim => {
    // Find matching baseline claim
    const baselineClaim = baselineClaims.find(
      bc => bc.attributedTo.organization.toLowerCase() === llmClaim.attributedTo.organization.toLowerCase()
    );

    if (baselineClaim) {
      // Enforce bounded delta: LLM can adjust ±15 points from baseline
      const delta = llmClaim.confidenceScore - baselineClaim.confidenceScore;
      const clampedScore = applyBoundedDelta(baselineClaim.confidenceScore, Math.max(-15, Math.min(15, delta)));

      return {
        ...llmClaim,
        confidenceScore: clampedScore,
        confidence: scoreToBand(clampedScore),
      };
    }

    // New claim from LLM (not in baseline) — keep as-is but cap at 70
    return {
      ...llmClaim,
      confidenceScore: Math.min(llmClaim.confidenceScore, 70),
      confidence: scoreToBand(Math.min(llmClaim.confidenceScore, 70)),
    };
  });
}

// ─── Main Specialist Invocation ───────────────────────────────────

/**
 * Invoke the Asset Attribution Specialist.
 * 
 * Flow:
 * 1. Compute deterministic baseline from evidence package
 * 2. If LLM available, invoke with baseline + evidence package
 * 3. Validate LLM output (grounding, leakage, bounds)
 * 4. If validation fails, fall back to deterministic-only
 * 5. Record metadata and return
 */
export async function invokeAttributionSpecialist(
  input: AttributionSpecialistInput,
  llmInvoke?: LLMInvokeFunction
): Promise<AttributionSpecialistOutput> {
  const startTime = Date.now();
  const invocationId = generateInvocationId();

  // Step 1: Generate deterministic baseline
  const deterministicClaims = computeDeterministicAttribution(input.evidencePackage);

  let mode: SpecialistMode;
  let output: AttributionSpecialistOutput;
  let fallbackApplied = false;

  if (!llmInvoke || input.configurationHints?.preferDeterministic) {
    // Deterministic-only mode
    mode = "deterministic_only";
    output = buildDeterministicOnlyOutput(input, deterministicClaims, { failures: [] });
    output.validationResult.passed = true;
    output.validationResult.fallbackApplied = false;
  } else {
    // Full LLM mode
    mode = "full_llm";

    try {
      // Build the prompt input
      const promptInput = renderEvidencePackage(input.evidencePackage) +
        "\n\n# DETERMINISTIC BASELINE\n\n" +
        "The following claims are derived from rule-based analysis. " +
        "You may augment, refine, or add to these claims based on the " +
        "evidence package, but you may not contradict the underlying " +
        "evidence weights.\n\n" +
        JSON.stringify(deterministicClaims, null, 2);

      // Add engagement context if available (marked as "do not cite")
      let fullPrompt = promptInput;
      if (input.engagementContext) {
        fullPrompt += "\n\n# ENGAGEMENT CONTEXT (background only — do not cite as evidence)\n\n" +
          JSON.stringify(input.engagementContext, null, 2);
      }

      // Invoke LLM
      const rawResponse = await llmInvoke([
        { role: "system", content: ATTRIBUTION_SPECIALIST_SYSTEM_PROMPT },
        { role: "user", content: fullPrompt },
      ]);

      // Parse and structure
      output = parseAndStructure(rawResponse, input);

      // Apply bounded deltas
      output.claims = applyBoundedDeltas(output.claims, deterministicClaims);

      // Re-select primary claim after delta adjustment
      if (output.claims.length > 0) {
        output.primaryClaim = output.claims.reduce(
          (a, b) => a.confidenceScore > b.confidenceScore ? a : b
        );
      }

      // Validate
      const validation = validateAttributionOutput(output, input.evidencePackage);

      if (!validation.passed) {
        // Fallback to deterministic-only with degraded confidence
        mode = "confidence_degraded";
        output = buildDeterministicOnlyOutput(input, deterministicClaims, validation);
        fallbackApplied = true;
      } else {
        output.validationResult = validation;
      }

    } catch (error: any) {
      // LLM unavailable, timeout, or parse failure
      mode = "deterministic_only";
      output = buildDeterministicOnlyOutput(input, deterministicClaims, {
        failures: [`LLM invocation failed: ${error.message}`],
      });
      fallbackApplied = true;
    }
  }

  // Add invocation metadata
  output.metadata = {
    invocationId,
    specialistName: "asset-attribution",
    specialistVersion: SPECIALIST_VERSION,
    promptVersion: PROMPT_VERSION,
    modelVersion: MODEL_VERSION,
    durationMs: Date.now() - startTime,
    fallbackApplied,
    mode,
    inputPackageHash: hashPackage(input.evidencePackage),
    timestamp: new Date().toISOString(),
  };

  return output;
}
