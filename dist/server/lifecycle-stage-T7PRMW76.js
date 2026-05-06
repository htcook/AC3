import {
  applyBoundedDelta,
  validateGenericSpecialistOutput
} from "./chunk-PF2WLC7Y.js";
import {
  hashPackage,
  renderEvidencePackage
} from "./chunk-HAF2NEAB.js";
import {
  init_llm_json_parser,
  parseLLMJson
} from "./chunk-UQ7CH3JX.js";
import "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/lifecycle-stage/specialist.ts
init_llm_json_parser();
import { createHash } from "crypto";
var SPECIALIST_VERSION = "1.0.0";
var PROMPT_VERSION = "1.0.0";
function computeLifecycleBaseline(pkg) {
  const signals = [];
  const now = /* @__PURE__ */ new Date();
  if (pkg.certificate) {
    if (pkg.certificate.isExpired) {
      signals.push({
        signal: "Certificate expired",
        direction: "declining",
        weight: "strong",
        detail: `Certificate valid to ${pkg.certificate.validTo}`
      });
    } else if (pkg.certificate.validTo) {
      const expiry = new Date(pkg.certificate.validTo);
      const daysUntilExpiry = (expiry.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24);
      if (daysUntilExpiry < 30) {
        signals.push({
          signal: "Certificate expiring soon",
          direction: "declining",
          weight: "moderate",
          detail: `Certificate expires in ${Math.round(daysUntilExpiry)} days`
        });
      } else if (daysUntilExpiry > 365) {
        signals.push({
          signal: "Certificate recently renewed",
          direction: "active",
          weight: "moderate",
          detail: `Certificate valid for ${Math.round(daysUntilExpiry)} more days`
        });
      }
    }
    if (pkg.certificate.isSelfSigned) {
      signals.push({
        signal: "Self-signed certificate",
        direction: "declining",
        weight: "weak",
        detail: "Self-signed certificate may indicate abandoned or unmaintained asset"
      });
    }
  }
  if (pkg.whois?.updatedDate) {
    const updated = new Date(pkg.whois.updatedDate);
    const daysSinceUpdate = (now.getTime() - updated.getTime()) / (1e3 * 60 * 60 * 24);
    if (daysSinceUpdate > 730) {
      signals.push({
        signal: "WHOIS not updated in 2+ years",
        direction: "declining",
        weight: "moderate",
        detail: `Last WHOIS update: ${pkg.whois.updatedDate}`
      });
    } else if (daysSinceUpdate < 180) {
      signals.push({
        signal: "WHOIS recently updated",
        direction: "active",
        weight: "moderate",
        detail: `Last WHOIS update: ${pkg.whois.updatedDate}`
      });
    }
  }
  if (pkg.whois?.expirationDate) {
    const expiry = new Date(pkg.whois.expirationDate);
    if (expiry < now) {
      signals.push({
        signal: "Domain registration expired",
        direction: "abandoned",
        weight: "strong",
        detail: `Domain expired: ${pkg.whois.expirationDate}`
      });
    }
  }
  if (pkg.http) {
    if (pkg.http.statusCode && pkg.http.statusCode >= 400) {
      signals.push({
        signal: `HTTP ${pkg.http.statusCode} response`,
        direction: pkg.http.statusCode >= 500 ? "declining" : "declining",
        weight: "moderate",
        detail: `Server returned HTTP ${pkg.http.statusCode}`
      });
    }
    if (pkg.http.responseTimeMs && pkg.http.responseTimeMs > 1e4) {
      signals.push({
        signal: "Very slow HTTP response",
        direction: "declining",
        weight: "weak",
        detail: `Response time: ${pkg.http.responseTimeMs}ms`
      });
    }
    if (pkg.http.technologies?.length) {
      signals.push({
        signal: "Active technology stack detected",
        direction: "active",
        weight: "moderate",
        detail: `Technologies: ${pkg.http.technologies.join(", ")}`
      });
    }
  }
  if (pkg.lastSeen) {
    const lastSeen = new Date(pkg.lastSeen);
    const daysSinceLastSeen = (now.getTime() - lastSeen.getTime()) / (1e3 * 60 * 60 * 24);
    if (daysSinceLastSeen > 365) {
      signals.push({
        signal: "Not observed in 1+ year",
        direction: "abandoned",
        weight: "strong",
        detail: `Last seen: ${pkg.lastSeen}`
      });
    }
  }
  const activeSignals = signals.filter((s) => s.direction === "active");
  const decliningSignals = signals.filter((s) => s.direction === "declining");
  const abandonedSignals = signals.filter((s) => s.direction === "abandoned");
  const weightValue = (w) => w === "strong" ? 3 : w === "moderate" ? 2 : 1;
  const activeScore = activeSignals.reduce((sum, s) => sum + weightValue(s.weight), 0);
  const decliningScore = decliningSignals.reduce((sum, s) => sum + weightValue(s.weight), 0);
  const abandonedScore = abandonedSignals.reduce((sum, s) => sum + weightValue(s.weight), 0);
  let stage;
  let confidenceScore;
  if (abandonedScore >= 3) {
    stage = "abandoned";
    confidenceScore = Math.min(75, 40 + abandonedScore * 10);
  } else if (decliningScore > activeScore && decliningScore >= 3) {
    stage = "declining";
    confidenceScore = Math.min(70, 35 + decliningScore * 8);
  } else if (activeScore > decliningScore) {
    stage = "active";
    confidenceScore = Math.min(75, 40 + activeScore * 10);
  } else if (signals.length === 0) {
    stage = "unknown";
    confidenceScore = 15;
  } else {
    stage = "unknown";
    confidenceScore = 25;
  }
  return { stage, confidenceScore, signals };
}
var LIFECYCLE_SPECIALIST_SYSTEM_PROMPT = `You are the Lifecycle Stage Specialist for the AC3 platform. Analyze structured discovery evidence and determine the lifecycle stage of a digital asset.

Lifecycle stages: active | declining | abandoned | unknown

Use temporal signals: certificate validity, DNS freshness, WHOIS updates, HTTP responsiveness, observation recency.

# GROUNDING REQUIREMENTS
- Every inference must cite evidence from the input package
- Do not use external knowledge
- If evidence is insufficient, return "unknown"

# OUTPUT FORMAT (JSON only)
{
  "stage": string,
  "confidenceScore": number,
  "signals": [{ "signal": string, "direction": string, "weight": string, "detail": string }],
  "estimatedAge": string | null,
  "lastActivityIndicator": string | null
}

Return ONLY the JSON object.`;
async function invokeLifecycleSpecialist(input, llmInvoke) {
  const startTime = Date.now();
  const invocationId = `lifecycle-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;
  const baseline = computeLifecycleBaseline(input.evidencePackage);
  let mode;
  let stage = baseline.stage;
  let confidenceScore = baseline.confidenceScore;
  let signals = baseline.signals;
  let estimatedAge;
  let lastActivityIndicator;
  let fallbackApplied = false;
  let validationResult;
  if (!llmInvoke) {
    mode = "deterministic_only";
    validationResult = {
      passed: true,
      groundingChecks: { allEvidenceReferencesExistInInput: true, noTrainingDataCitations: true, confidenceWithinEvidenceBounds: true },
      failures: []
    };
  } else {
    mode = "full_llm";
    try {
      const promptInput = renderEvidencePackage(input.evidencePackage) + "\n\n# DETERMINISTIC BASELINE\n\n" + JSON.stringify(baseline, null, 2);
      const rawResponse = await llmInvoke([
        { role: "system", content: LIFECYCLE_SPECIALIST_SYSTEM_PROMPT },
        { role: "user", content: promptInput }
      ]);
      const content = rawResponse?.choices?.[0]?.message?.content || "";
      const parsed = parseLLMJson(content, { fallback: {} }).data;
      confidenceScore = applyBoundedDelta(baseline.confidenceScore, (parsed.confidenceScore || 0) - baseline.confidenceScore);
      stage = parsed.stage || baseline.stage;
      signals = parsed.signals || baseline.signals;
      estimatedAge = parsed.estimatedAge;
      lastActivityIndicator = parsed.lastActivityIndicator;
      const allEvidence = (signals || []).map((s) => ({
        source: "lifecycle_signal",
        evidenceType: s.signal,
        weight: s.weight,
        detail: s.detail
      }));
      validationResult = validateGenericSpecialistOutput(
        allEvidence,
        signals.map((s) => s.detail).join(" "),
        input.evidencePackage
      );
      if (!validationResult.passed) {
        mode = "confidence_degraded";
        stage = baseline.stage;
        confidenceScore = baseline.confidenceScore;
        signals = baseline.signals;
        fallbackApplied = true;
      }
    } catch {
      mode = "deterministic_only";
      fallbackApplied = true;
      validationResult = {
        passed: false,
        groundingChecks: { allEvidenceReferencesExistInInput: true, noTrainingDataCitations: true, confidenceWithinEvidenceBounds: true },
        failures: ["LLM invocation failed"],
        fallbackApplied: true
      };
    }
  }
  return {
    asset: { id: input.evidencePackage.assetId, identifier: input.evidencePackage.assetIdentifier },
    stage,
    confidenceScore,
    signals,
    estimatedAge,
    lastActivityIndicator,
    validationResult,
    metadata: {
      invocationId,
      specialistName: "lifecycle-stage",
      specialistVersion: SPECIALIST_VERSION,
      promptVersion: PROMPT_VERSION,
      modelVersion: "gpt-4o",
      durationMs: Date.now() - startTime,
      fallbackApplied,
      mode,
      inputPackageHash: hashPackage(input.evidencePackage),
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  };
}
export {
  computeLifecycleBaseline,
  invokeLifecycleSpecialist
};
