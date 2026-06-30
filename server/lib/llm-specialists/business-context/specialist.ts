/**
 * Business Context Specialist
 * 
 * Determines the business context of a discovered asset:
 * business unit attribution, function, revenue path,
 * regulatory exposure, and dependency edges.
 */

import type {
  BusinessContextSpecialistInput,
  BusinessContextSpecialistOutput,
  BusinessUnitAttribution,
  RegulatoryExposure,
  DependencyEdge,
  StructuredEvidencePackage,
  EvidenceReference,
  ValidationResult,
  SpecialistMode,
  LLMInvokeFunction,
  ConfidenceBand,
} from "../types";
import { validateGenericSpecialistOutput, applyBoundedDelta } from "../validation";
import { renderEvidencePackage, hashPackage } from "../evidence-package";
import { createHash } from "crypto";
import { parseLLMJson } from "../../../../shared/llm-json-parser";

export const SPECIALIST_VERSION = "1.0.0";
export const PROMPT_VERSION = "1.0.0";

// ─── Regulatory Framework Detection ──────────────────────────────

interface RegFrameworkRule {
  framework: string;
  indicators: string[];
  sectorMatch?: string[];
}

const REGULATORY_RULES: RegFrameworkRule[] = [
  {
    framework: "PCI-DSS",
    indicators: ["payment", "checkout", "pay.", "card", "stripe", "paypal", "braintree", "square"],
    sectorMatch: ["retail", "financial_services"],
  },
  {
    framework: "HIPAA",
    indicators: ["health", "patient", "medical", "ehr", "epic", "cerner", "pharmacy", "hipaa"],
    sectorMatch: ["healthcare"],
  },
  {
    framework: "SOX",
    indicators: [],
    sectorMatch: ["financial_services"],
  },
  {
    framework: "GDPR",
    indicators: ["eu.", ".eu", "gdpr", "privacy", "consent", "cookie"],
  },
  {
    framework: "FISMA",
    indicators: [".gov", ".mil", "fedramp", "fisma"],
    sectorMatch: ["government", "defense"],
  },
  {
    framework: "CMMC",
    indicators: ["cui", "cmmc", "dfars", "itar"],
    sectorMatch: ["defense"],
  },
];

// ─── Deterministic Baseline ───────────────────────────────────────

export function computeBusinessContextBaseline(
  pkg: StructuredEvidencePackage,
  customerIndustry?: string
): {
  regulatoryExposure: RegulatoryExposure[];
  dependencies: DependencyEdge[];
  function?: string;
  revenuePath?: "direct" | "supporting" | "internal" | "unknown";
} {
  const identifier = pkg.assetIdentifier.toLowerCase();
  const regulatoryExposure: RegulatoryExposure[] = [];
  const dependencies: DependencyEdge[] = [];

  // Detect regulatory frameworks
  for (const rule of REGULATORY_RULES) {
    const indicatorMatch = rule.indicators.some(ind => identifier.includes(ind));
    const sectorMatch = customerIndustry && rule.sectorMatch?.some(s =>
      customerIndustry.toLowerCase().includes(s.replace("_", " "))
    );

    if (indicatorMatch) {
      regulatoryExposure.push({
        framework: rule.framework,
        applicability: "probable",
        reasoning: `Asset identifier contains indicator matching ${rule.framework} scope.`,
      });
    } else if (sectorMatch) {
      regulatoryExposure.push({
        framework: rule.framework,
        applicability: "possible",
        reasoning: `Customer industry "${customerIndustry}" commonly falls under ${rule.framework} scope.`,
      });
    }
  }

  // Detect dependencies from DNS/HTTP
  if (pkg.dns?.cnameChain?.length) {
    const lastCname = pkg.dns.cnameChain[pkg.dns.cnameChain.length - 1];
    if (lastCname !== pkg.assetIdentifier) {
      dependencies.push({
        dependsOn: lastCname,
        relationship: "proxies",
        confidence: "medium",
      });
    }
  }

  if (pkg.http?.redirectChain?.length) {
    const finalRedirect = pkg.http.redirectChain[pkg.http.redirectChain.length - 1];
    if (finalRedirect && !finalRedirect.includes(pkg.assetIdentifier)) {
      dependencies.push({
        dependsOn: finalRedirect,
        relationship: "proxies",
        confidence: "medium",
      });
    }
  }

  // Infer function from naming
  let assetFunction: string | undefined;
  if (identifier.includes("api.") || identifier.includes("/api")) assetFunction = "API Gateway";
  else if (identifier.includes("mail.") || identifier.includes("smtp.")) assetFunction = "Email Service";
  else if (identifier.includes("vpn.")) assetFunction = "VPN Gateway";
  else if (identifier.includes("auth.") || identifier.includes("login.") || identifier.includes("sso.")) assetFunction = "Authentication";
  else if (identifier.includes("cdn.") || identifier.includes("static.")) assetFunction = "Content Delivery";
  else if (identifier.includes("db.") || identifier.includes("database.")) assetFunction = "Database";
  else if (identifier.includes("monitor.") || identifier.includes("grafana.")) assetFunction = "Monitoring";

  // Infer revenue path
  let revenuePath: "direct" | "supporting" | "internal" | "unknown" = "unknown";
  if (identifier.includes("shop.") || identifier.includes("store.") || identifier.includes("checkout.") || identifier.includes("pay.")) {
    revenuePath = "direct";
  } else if (identifier.includes("api.") || identifier.includes("cdn.")) {
    revenuePath = "supporting";
  } else if (identifier.includes("internal.") || identifier.includes("corp.") || identifier.includes("vpn.")) {
    revenuePath = "internal";
  }

  return { regulatoryExposure, dependencies, function: assetFunction, revenuePath };
}

// ─── System Prompt ────────────────────────────────────────────────

const BUSINESS_CONTEXT_SYSTEM_PROMPT = `You are the Business Context Specialist for the AC3 platform. Analyze structured discovery evidence and determine the business context of a digital asset.

Determine:
1. Business unit attribution (if identifiable)
2. Asset function (API, email, auth, CDN, etc.)
3. Revenue path (direct/supporting/internal/unknown)
4. Regulatory exposure (PCI-DSS, HIPAA, SOX, GDPR, FISMA, CMMC, etc.)
5. Dependencies (what other assets/services this depends on)

# GROUNDING REQUIREMENTS
- Every inference must cite evidence from the input package
- Do not use external knowledge about the organization
- If evidence is insufficient, omit the field rather than guessing

# OUTPUT FORMAT (JSON only)
{
  "businessUnit": { "unit": string, "confidence": string, "supportingEvidence": [...] } | null,
  "function": string | null,
  "revenuePath": "direct" | "supporting" | "internal" | "unknown",
  "regulatoryExposure": [{ "framework": string, "applicability": string, "reasoning": string }],
  "dependencies": [{ "dependsOn": string, "relationship": string, "confidence": string }]
}

Return ONLY the JSON object.`;

// ─── Main Invocation ──────────────────────────────────────────────

export async function invokeBusinessContextSpecialist(
  input: BusinessContextSpecialistInput,
  llmInvoke?: LLMInvokeFunction
): Promise<BusinessContextSpecialistOutput> {
  const startTime = Date.now();
  const invocationId = `bizctx-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;

  const baseline = computeBusinessContextBaseline(input.evidencePackage, input.customerIndustry);

  let mode: SpecialistMode;
  let result = { ...baseline };
  let businessUnit: BusinessUnitAttribution | undefined;
  let fallbackApplied = false;
  let validationResult: ValidationResult;

  if (!llmInvoke) {
    mode = "deterministic_only";
    validationResult = {
      passed: true,
      groundingChecks: { allEvidenceReferencesExistInInput: true, noTrainingDataCitations: true, confidenceWithinEvidenceBounds: true },
      failures: [],
    };
  } else {
    mode = "full_llm";
    try {
      const promptInput = renderEvidencePackage(input.evidencePackage) +
        "\n\n# DETERMINISTIC BASELINE\n\n" + JSON.stringify(baseline, null, 2) +
        (input.customerIndustry ? `\n\nCustomer Industry: ${input.customerIndustry}` : "") +
        (input.customerSize ? `\nCustomer Size: ${input.customerSize}` : "");

      const rawResponse = await llmInvoke([
        { role: "system", content: BUSINESS_CONTEXT_SYSTEM_PROMPT },
        { role: "user", content: promptInput },
      ]);

      const content = rawResponse?.choices?.[0]?.message?.content || "";
      const parsed = parseLLMJson(content, { fallback: {} }).data;

      businessUnit = parsed.businessUnit || undefined;
      result.function = parsed.function || baseline.function;
      result.revenuePath = parsed.revenuePath || baseline.revenuePath;
      result.regulatoryExposure = parsed.regulatoryExposure || baseline.regulatoryExposure;
      result.dependencies = parsed.dependencies || baseline.dependencies;

      const allEvidence: EvidenceReference[] = businessUnit?.supportingEvidence || [];
      validationResult = validateGenericSpecialistOutput(
        allEvidence,
        JSON.stringify(parsed),
        input.evidencePackage
      );

      if (!validationResult.passed) {
        mode = "confidence_degraded";
        businessUnit = undefined;
        result = { ...baseline };
        fallbackApplied = true;
      }
    } catch {
      mode = "deterministic_only";
      fallbackApplied = true;
      validationResult = {
        passed: false,
        groundingChecks: { allEvidenceReferencesExistInInput: true, noTrainingDataCitations: true, confidenceWithinEvidenceBounds: true },
        failures: ["LLM invocation failed"],
        fallbackApplied: true,
      };
    }
  }

  return {
    asset: { id: input.evidencePackage.assetId, identifier: input.evidencePackage.assetIdentifier },
    businessUnit,
    function: result.function,
    revenuePath: result.revenuePath,
    regulatoryExposure: result.regulatoryExposure,
    dependencies: result.dependencies,
    validationResult: validationResult!,
    metadata: {
      invocationId,
      specialistName: "business-context",
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
