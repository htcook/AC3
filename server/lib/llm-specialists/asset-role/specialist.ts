/**
 * Asset Role Specialist
 * 
 * Determines the operational role of a discovered asset:
 * exposure (customer_facing/internal/partner), environment (prod/staging/dev),
 * and criticality (primary/backup/auxiliary).
 * 
 * Architecture: deterministic baseline → LLM augmentation → validation → output
 */

import type {
  RoleSpecialistInput,
  RoleSpecialistOutput,
  RoleInference,
  StructuredEvidencePackage,
  EvidenceReference,
  ValidationResult,
  SpecialistMode,
  LLMInvokeFunction,
  AssetExposure,
  AssetEnvironment,
  AssetCriticality,
} from "../types";
import { validateGenericSpecialistOutput, applyBoundedDelta, scoreToBand } from "../validation";
import { renderEvidencePackage, hashPackage } from "../evidence-package";
import { createHash } from "crypto";
import { parseLLMJson } from "../../../../shared/llm-json-parser";

export const SPECIALIST_VERSION = "1.0.0";
export const PROMPT_VERSION = "1.0.0";

// ─── Deterministic Baseline ───────────────────────────────────────

const DEV_INDICATORS = [
  "dev.", "staging.", "stage.", "test.", "qa.", "uat.", "sandbox.",
  "demo.", "preview.", "beta.", "alpha.", "canary.", "preprod.",
  "pre-prod.", "development.", "testing.",
];

const INTERNAL_INDICATORS = [
  "internal.", "intranet.", "corp.", "vpn.", "admin.", "mgmt.",
  "management.", "ops.", "monitor.", "grafana.", "kibana.",
  "jenkins.", "gitlab.", "jira.", "confluence.", "wiki.",
];

const CUSTOMER_FACING_INDICATORS = [
  "www.", "app.", "api.", "portal.", "login.", "auth.",
  "shop.", "store.", "checkout.", "pay.", "cdn.",
  "mail.", "webmail.", "outlook.",
];

const BACKUP_INDICATORS = [
  "backup.", "bak.", "dr.", "failover.", "secondary.",
  "replica.", "mirror.", "standby.", "cold.",
];

export function computeRoleBaseline(pkg: StructuredEvidencePackage): RoleInference {
  const identifier = pkg.assetIdentifier.toLowerCase();
  const evidence: EvidenceReference[] = [];

  // Determine exposure
  let exposure: AssetExposure = "unknown";
  let exposureScore = 30;

  if (INTERNAL_INDICATORS.some(ind => identifier.includes(ind))) {
    exposure = "internal";
    exposureScore = 65;
    evidence.push({
      source: "asset_identifier",
      evidenceType: "naming_convention",
      weight: "moderate",
      detail: identifier,
    });
  } else if (CUSTOMER_FACING_INDICATORS.some(ind => identifier.includes(ind))) {
    exposure = "customer_facing";
    exposureScore = 65;
    evidence.push({
      source: "asset_identifier",
      evidenceType: "naming_convention",
      weight: "moderate",
      detail: identifier,
    });
  }

  // HTTP title/technologies can indicate exposure
  if (pkg.http?.title) {
    const title = pkg.http.title.toLowerCase();
    if (title.includes("admin") || title.includes("dashboard") || title.includes("management")) {
      if (exposure === "unknown") {
        exposure = "internal";
        exposureScore = 55;
      }
      evidence.push({
        source: "http.title",
        evidenceType: "content_analysis",
        weight: "moderate",
        detail: pkg.http.title,
      });
    }
  }

  // Determine environment
  let environment: AssetEnvironment = "unknown";
  let envScore = 30;

  if (DEV_INDICATORS.some(ind => identifier.includes(ind))) {
    environment = identifier.includes("staging") || identifier.includes("stage") || identifier.includes("preprod")
      ? "staging"
      : identifier.includes("test") || identifier.includes("qa") || identifier.includes("uat")
        ? "testing"
        : "development";
    envScore = 70;
    evidence.push({
      source: "asset_identifier",
      evidenceType: "naming_convention",
      weight: "strong",
      detail: identifier,
    });
  } else if (
    exposure === "customer_facing" ||
    (pkg.certificate && !pkg.certificate.isSelfSigned && !pkg.certificate.isExpired)
  ) {
    environment = "production";
    envScore = 55;
    if (pkg.certificate && !pkg.certificate.isSelfSigned) {
      evidence.push({
        source: "certificate",
        evidenceType: "certificate_validity",
        weight: "moderate",
        detail: `Valid CA-signed certificate (${pkg.certificate.issuerO || "unknown issuer"})`,
      });
    }
  }

  // Self-signed cert is a strong dev/staging signal
  if (pkg.certificate?.isSelfSigned) {
    if (environment === "unknown") {
      environment = "development";
      envScore = 60;
    }
    evidence.push({
      source: "certificate",
      evidenceType: "certificate_analysis",
      weight: "moderate",
      detail: "Self-signed certificate",
    });
  }

  // Determine criticality
  let criticality: AssetCriticality = "unknown";
  let critScore = 30;

  if (BACKUP_INDICATORS.some(ind => identifier.includes(ind))) {
    criticality = "backup";
    critScore = 60;
    evidence.push({
      source: "asset_identifier",
      evidenceType: "naming_convention",
      weight: "moderate",
      detail: identifier,
    });
  } else if (environment === "production" && exposure === "customer_facing") {
    criticality = "primary";
    critScore = 55;
  } else if (environment === "development" || environment === "testing") {
    criticality = "auxiliary";
    critScore = 50;
  }

  const overallScore = Math.round((exposureScore + envScore + critScore) / 3);

  return {
    exposure,
    environment,
    criticality,
    confidenceScore: overallScore,
    supportingEvidence: evidence,
    reasoning: `Deterministic role inference: ${exposure} exposure, ${environment} environment, ${criticality} criticality.`,
  };
}

// ─── System Prompt ────────────────────────────────────────────────

const ROLE_SPECIALIST_SYSTEM_PROMPT = `You are the Asset Role Specialist for the AC3 platform. Your role is to analyze structured discovery evidence and determine the operational role of a digital asset.

You determine three dimensions:
1. EXPOSURE: customer_facing | internal | partner | unknown
2. ENVIRONMENT: production | staging | development | testing | unknown
3. CRITICALITY: primary | backup | auxiliary | unknown

# GROUNDING REQUIREMENTS
- Every inference must cite evidence from the input package
- Do not use external knowledge about the organization
- If evidence is insufficient, return "unknown" for that dimension rather than guessing

# OUTPUT FORMAT (JSON only)
{
  "role": {
    "exposure": string,
    "environment": string,
    "criticality": string,
    "confidenceScore": number,
    "supportingEvidence": [{ "source": string, "evidenceType": string, "weight": string, "detail": string }],
    "reasoning": string
  },
  "alternativeRoles": [...] | null
}

Return ONLY the JSON object.`;

// ─── Main Specialist Invocation ───────────────────────────────────

export async function invokeRoleSpecialist(
  input: RoleSpecialistInput,
  llmInvoke?: LLMInvokeFunction
): Promise<RoleSpecialistOutput> {
  const startTime = Date.now();
  const invocationId = `role-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;

  const baselineRole = computeRoleBaseline(input.evidencePackage);

  let mode: SpecialistMode;
  let role: RoleInference;
  let fallbackApplied = false;
  let validationResult: ValidationResult;

  if (!llmInvoke) {
    mode = "deterministic_only";
    role = baselineRole;
    validationResult = {
      passed: true,
      groundingChecks: {
        allEvidenceReferencesExistInInput: true,
        noTrainingDataCitations: true,
        confidenceWithinEvidenceBounds: true,
      },
      failures: [],
      fallbackApplied: false,
    };
  } else {
    mode = "full_llm";
    try {
      const promptInput = renderEvidencePackage(input.evidencePackage) +
        "\n\n# DETERMINISTIC BASELINE\n\n" +
        JSON.stringify(baselineRole, null, 2);

      const rawResponse = await llmInvoke([
        { role: "system", content: ROLE_SPECIALIST_SYSTEM_PROMPT },
        { role: "user", content: promptInput },
      ]);

      const content = rawResponse?.choices?.[0]?.message?.content || "";
      const parsed = parseLLMJson(content, { fallback: {} }).data;

      role = {
        ...parsed.role,
        confidenceScore: applyBoundedDelta(baselineRole.confidenceScore, (parsed.role?.confidenceScore || 0) - baselineRole.confidenceScore),
      };

      validationResult = validateGenericSpecialistOutput(
        role.supportingEvidence || [],
        role.reasoning || "",
        input.evidencePackage
      );

      if (!validationResult.passed) {
        mode = "confidence_degraded";
        role = baselineRole;
        fallbackApplied = true;
      }
    } catch {
      mode = "deterministic_only";
      role = baselineRole;
      fallbackApplied = true;
      validationResult = {
        passed: false,
        groundingChecks: {
          allEvidenceReferencesExistInInput: true,
          noTrainingDataCitations: true,
          confidenceWithinEvidenceBounds: true,
        },
        failures: ["LLM invocation failed"],
        fallbackApplied: true,
      };
    }
  }

  return {
    asset: { id: input.evidencePackage.assetId, identifier: input.evidencePackage.assetIdentifier },
    role,
    validationResult: validationResult!,
    metadata: {
      invocationId,
      specialistName: "asset-role",
      specialistVersion: SPECIALIST_VERSION,
      promptVersion: PROMPT_VERSION,
      modelVersion: "gpt-4o",
      durationMs: Date.now() - startTime,
      fallbackApplied,
      mode,
      inputPackageHash: hashPackage(input.evidencePackage),
      timestamp: new Date().toISOString(),
    },
  };
}
