import {
  applyBoundedDelta,
  scoreToBand,
  validateAttributionOutput
} from "./chunk-PF2WLC7Y.js";
import {
  hashPackage,
  isCDNProvider,
  isGenericCertificateIssuer,
  isHostingProvider,
  isPrivacyProxy,
  renderEvidencePackage
} from "./chunk-HAF2NEAB.js";
import {
  init_llm_json_parser,
  parseLLMJson
} from "./chunk-UQ7CH3JX.js";
import "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/asset-attribution/deterministic-baseline.ts
function normalizeForComparison(name) {
  return name.toLowerCase().replace(/[,.\-_'"]/g, " ").replace(/\b(inc|llc|ltd|corp|co|na|n\.a\.|plc|gmbh|ag|sa|the)\b/gi, "").replace(/\s+/g, " ").trim();
}
function detectConvergence(claims) {
  if (claims.length < 2) {
    return { allClaimsAgreeOnOrganization: false, sourceCount: claims.length };
  }
  const normalized = claims.map((c) => normalizeForComparison(c.attributedTo.organization));
  const unique = [...new Set(normalized)];
  return {
    allClaimsAgreeOnOrganization: unique.length === 1,
    normalizedOrg: unique.length === 1 ? unique[0] : void 0,
    sourceCount: claims.length
  };
}
function computeDeterministicAttribution(pkg) {
  const claims = [];
  if (pkg.certificate?.subjectO) {
    const subjectO = pkg.certificate.subjectO;
    if (!isGenericCertificateIssuer(subjectO)) {
      claims.push({
        attributedTo: { organization: subjectO },
        claimType: "primary_owner",
        confidence: "medium",
        confidenceScore: 55,
        supportingEvidence: [{
          source: "certificate.subject_o",
          evidenceType: "direct_identity",
          weight: "strong",
          detail: subjectO
        }],
        reasoning: "Certificate Subject O field provides direct identity attribution."
      });
    }
  }
  if (pkg.whois?.registrantOrg && !isPrivacyProxy(pkg.whois.registrantOrg)) {
    const registrantOrg = pkg.whois.registrantOrg;
    claims.push({
      attributedTo: { organization: registrantOrg },
      claimType: "primary_owner",
      confidence: "medium",
      confidenceScore: 50,
      supportingEvidence: [{
        source: "whois.registrant_org",
        evidenceType: "direct_identity",
        weight: "strong",
        detail: registrantOrg
      }],
      reasoning: "WHOIS registrant organization provides direct identity attribution."
    });
  } else if (pkg.whois?.registrant && !isPrivacyProxy(pkg.whois.registrant)) {
    const registrant = pkg.whois.registrant;
    claims.push({
      attributedTo: { organization: registrant },
      claimType: "primary_owner",
      confidence: "low",
      confidenceScore: 35,
      supportingEvidence: [{
        source: "whois.registrant",
        evidenceType: "direct_identity",
        weight: "moderate",
        detail: registrant
      }],
      reasoning: "WHOIS registrant name (individual, not org) provides partial identity attribution."
    });
  }
  if (pkg.bgp?.asHolder) {
    const asHolder = pkg.bgp.asHolder;
    if (isCDNProvider(asHolder) || isHostingProvider(asHolder)) {
      claims.push({
        attributedTo: { organization: asHolder },
        claimType: "third_party_hosted",
        confidence: "medium",
        confidenceScore: 60,
        supportingEvidence: [{
          source: "bgp.as_holder",
          evidenceType: "infrastructure_identity",
          weight: "moderate",
          detail: asHolder
        }],
        reasoning: `BGP AS holder "${asHolder}" is a known hosting/CDN provider, indicating third-party hosting.`
      });
    } else {
      claims.push({
        attributedTo: { organization: asHolder },
        claimType: "primary_owner",
        confidence: "medium",
        confidenceScore: 45,
        supportingEvidence: [{
          source: "bgp.as_holder",
          evidenceType: "network_identity",
          weight: "moderate",
          detail: asHolder
        }],
        reasoning: "BGP AS holder provides network-level identity attribution."
      });
    }
  }
  if (pkg.businessIntel?.secEdgarMatch) {
    const sec = pkg.businessIntel.secEdgarMatch;
    claims.push({
      attributedTo: {
        organization: sec.companyName,
        organizationType: "public_company"
      },
      claimType: "primary_owner",
      confidence: "medium",
      confidenceScore: 50,
      supportingEvidence: [{
        source: "businessIntel.secEdgarMatch",
        evidenceType: "corroborating_business",
        weight: "moderate",
        detail: `${sec.companyName} (CIK: ${sec.cik})`
      }],
      reasoning: "SEC EDGAR filing match provides corroborating business identity."
    });
  }
  const convergence = detectConvergence(claims);
  if (convergence.allClaimsAgreeOnOrganization && claims.length >= 2) {
    const strongest = claims.reduce(
      (a, b) => a.confidenceScore > b.confidenceScore ? a : b
    );
    const allEvidence = [];
    for (const claim of claims) {
      if (claim !== strongest) {
        allEvidence.push(...claim.supportingEvidence);
      }
    }
    strongest.supportingEvidence.push(...allEvidence);
    strongest.confidence = "high";
    strongest.confidenceScore = Math.min(
      80 + (claims.length - 2) * 5,
      // +5 per additional converging source
      95
    );
    strongest.reasoning += ` Multi-source convergence detected across ${claims.length} independent sources.`;
  }
  if (claims.length === 0) {
    const obscurationSignals = [];
    if (pkg.whois?.privacyProtected) {
      obscurationSignals.push("WHOIS privacy protection enabled");
    }
    if (!pkg.certificate?.subjectO || isGenericCertificateIssuer(pkg.certificate?.subjectO || "")) {
      obscurationSignals.push("Generic or missing certificate Subject O");
    }
    if (!pkg.bgp?.asHolder) {
      obscurationSignals.push("No BGP AS holder information");
    }
    if (obscurationSignals.length >= 2) {
      claims.push({
        attributedTo: { organization: "Unknown (intentionally obscured)" },
        claimType: "unknown",
        confidence: "low",
        confidenceScore: 10,
        supportingEvidence: obscurationSignals.map((signal, i) => ({
          source: `negative_evidence.signal_${i}`,
          evidenceType: "absence_of_evidence",
          weight: "weak",
          detail: signal
        })),
        reasoning: `Asset ownership appears intentionally obscured. ${obscurationSignals.length} standard attribution sources are missing or masked: ${obscurationSignals.join("; ")}.`
      });
    }
  }
  const primaryOwnerClaims = claims.filter((c) => c.claimType === "primary_owner");
  const hostedClaims = claims.filter((c) => c.claimType === "third_party_hosted");
  if (primaryOwnerClaims.length > 0 && hostedClaims.length > 0) {
    for (const claim of primaryOwnerClaims) {
      claim.reasoning += " Note: asset is hosted on third-party infrastructure \u2014 this claim covers service/brand ownership.";
    }
    for (const claim of hostedClaims) {
      claim.reasoning += " Note: this claim covers infrastructure ownership only.";
    }
  }
  return claims;
}

// server/lib/llm-specialists/asset-attribution/prompts.ts
var SPECIALIST_VERSION = "1.0.0";
var PROMPT_VERSION = "1.0.0";
var MODEL_VERSION = "gpt-4o";
var ATTRIBUTION_SPECIALIST_SYSTEM_PROMPT = `You are the Asset Attribution Specialist for the AC3 platform. Your role is to analyze structured discovery evidence and produce grounded attribution claims about who owns digital assets.

Your analysis reflects the discipline of a senior security practitioner with 25 years of experience in penetration testing, security assessment, and offensive security operations. You prioritize verifiable evidence over plausible inference. You explicitly flag uncertainty rather than producing confident-sounding speculation. When evidence is insufficient to support attribution, you say so rather than making claims.

# YOUR INPUT

You will receive a structured EVIDENCE PACKAGE containing:

1. The asset under analysis (identifier, IPs, observation history)
2. Direct identity evidence (certificate, DNS, network attribution)
3. Corroborating business evidence (SEC filings, public references)
4. Negative evidence (what was checked but not found)
5. Cross-reference checks (convergence patterns across sources)
6. Engagement context (background only \u2014 explicitly marked "do not cite")

You will also receive a DETERMINISTIC BASELINE \u2014 rule-based claims derived from the evidence. You may augment, refine, or add to these claims based on the evidence package, but you may not contradict the underlying evidence weights.

# YOUR OUTPUT

Produce a JSON object matching this schema:

{
  "asset": { "id": string, "identifier": string },
  "claims": [
    {
      "attributedTo": {
        "organization": string,
        "legalEntity": string | null,
        "parentOrganization": string | null,
        "organizationType": "public_company" | "private_company" | "subsidiary" | "government" | "nonprofit" | "unknown" | null
      },
      "claimType": "primary_owner" | "subsidiary" | "third_party_hosted" | "vendor_managed" | "partner_integration" | "unknown",
      "confidence": "high" | "medium" | "low",
      "confidenceScore": number,
      "supportingEvidence": [
        {
          "source": string,
          "evidenceType": string,
          "weight": "strong" | "moderate" | "weak",
          "detail": string
        }
      ],
      "contradictingEvidence": [...] | null,
      "alternativeAttributions": [...] | null,
      "reasoning": string
    }
  ],
  "primaryClaim": <one of the claims, or null>,
  "evidenceSufficiency": "sufficient" | "partial" | "insufficient",
  "insufficiencyReason": string | null
}

# GROUNDING REQUIREMENTS (CRITICAL)

1. Every claim must cite supporting evidence from the input package. Claims without supporting evidence must not be made.

2. Every supportingEvidence reference must contain text that appears verbatim in the input package. Do not paraphrase. The detail field must be a direct quote from the package.

3. Do not use external knowledge about the organization. Even if you recognize the organization name from training data, your claims must be derived from evidence in the package, not from prior knowledge.

4. Engagement context is provided as background to inform reasoning, not as evidence. You may use it to understand what the package is about, but you may not cite it as supporting evidence.

5. If evidence is insufficient to support attribution at any confidence level, return evidenceSufficiency: "insufficient" with claims: [] and explain what additional evidence would be needed.

# CONFIDENCE CALIBRATION

HIGH CONFIDENCE (75-100):
- Multiple independent sources converge on the same attribution
- No contradicting evidence
- Direct identity evidence (certificate Subject O, RDAP registrant) matches business evidence (SEC filings, public references)
- Cross-reference check explicitly states convergence

MEDIUM CONFIDENCE (40-74):
- Some sources support attribution but coverage is incomplete
- Minor inconsistencies that don't fundamentally contradict the claim
- Direct identity evidence is partial (e.g., domain registered to org but certificate uses generic issuer)
- Inference required to bridge gaps in evidence

LOW CONFIDENCE (10-39):
- Single-source attribution
- Significant gaps in expected evidence
- Some contradicting evidence present
- Heavy inference required

INSUFFICIENT (below 10):
- Evidence does not support any specific attribution
- Sources contradict each other without resolution
- Asset appears intentionally obscured

When in doubt between two confidence tiers, choose the lower one. Speculative attribution at high confidence causes more harm than honest attribution at low confidence.

# BOUNDED DELTA RULES

You receive a deterministic baseline with pre-computed claims. Your adjustments are bounded:
- You MAY add new claims that the rules didn't generate
- You MAY adjust confidence scores within +/- 15 points of the baseline
- You MAY add contradicting evidence and surface alternatives
- You MAY NOT lower confidence below the deterministic baseline if the underlying evidence still supports it
- You MAY NOT push confidence above what the evidence weight supports

# HANDLING SPECIFIC PATTERNS

MULTI-TENANT ASSETS: If the asset appears to be a customer-facing service hosted on third-party infrastructure (SaaS provider, cloud hosting), produce two claims: one for service ownership and one for infrastructure ownership.

HOSTED-BUT-BRANDED: If a customer's domain points to vendor infrastructure, the customer owns the service brand and the vendor owns the infrastructure. Both are valid claims; produce both.

INTENTIONALLY OBSCURED: If standard attribution sources are missing (privacy WHOIS, generic certificates, no public references), this itself is signal. Note it explicitly, set confidence accordingly, and consider whether obscuration suggests a specific organization type.

CONTRADICTING EVIDENCE: When sources contradict, do not pick the strongest source and hide the rest. Surface the contradiction in contradictingEvidence and lower confidence accordingly.

NEGATIVE EVIDENCE: The package may include "what was checked but not found" sections. Use these to rule out alternative attributions. "No third-party hosting indicators found" is meaningful evidence against a hosted attribution claim.

# CALIBRATION EXAMPLES

EXAMPLE 1: HIGH CONFIDENCE PRIMARY OWNER
Input: Certificate Subject O: "Acme Bank, N.A.", RDAP registrant: "Acme Bank, National Association", BGP AS holder: "Acme Bank, N.A.", SEC EDGAR match with convergence.
Expected: confidenceScore 90+, confidence "high", claimType "primary_owner"

EXAMPLE 2: MEDIUM CONFIDENCE WITH PARTIAL EVIDENCE
Input: Certificate uses Let's Encrypt (generic), RDAP registrant: "Example Corp", no BGP match, no SEC match.
Expected: confidenceScore 45-55, confidence "medium", single-source attribution noted.

EXAMPLE 3: INSUFFICIENT EVIDENCE
Input: Privacy-protected WHOIS, generic certificate, CDN-hosted (Cloudflare AS), no business intel.
Expected: evidenceSufficiency "insufficient", claims: [], explanation of what additional evidence would help.

Return ONLY the JSON object. No markdown, no explanation outside the JSON.`;

// server/lib/llm-specialists/asset-attribution/specialist.ts
init_llm_json_parser();
import { createHash } from "crypto";
function generateInvocationId() {
  return `attr-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;
}
function buildDeterministicOnlyOutput(input, deterministicClaims, validationOrError) {
  const primaryClaim = deterministicClaims.length > 0 ? deterministicClaims.reduce((a, b) => a.confidenceScore > b.confidenceScore ? a : b) : void 0;
  let evidenceSufficiency;
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
      identifier: input.evidencePackage.assetIdentifier
    },
    claims: deterministicClaims,
    primaryClaim,
    evidenceSufficiency,
    insufficiencyReason: deterministicClaims.length === 0 ? "No deterministic attribution rules matched the evidence package." : void 0,
    validationResult: {
      passed: false,
      groundingChecks: {
        allEvidenceReferencesExistInInput: true,
        noTrainingDataCitations: true,
        confidenceWithinEvidenceBounds: true
      },
      failures: validationOrError.failures,
      fallbackApplied: true
    },
    metadata: {}
    // filled by caller
  };
}
function parseAndStructure(rawResponse, input) {
  let content;
  if (rawResponse?.choices?.[0]?.message?.content) {
    content = rawResponse.choices[0].message.content;
  } else if (typeof rawResponse === "string") {
    content = rawResponse;
  } else {
    throw new Error("Unexpected LLM response format");
  }
  const parsed = parseLLMJson(content, { fallback: {} }).data;
  const output = {
    asset: parsed.asset || {
      id: input.evidencePackage.assetId,
      identifier: input.evidencePackage.assetIdentifier
    },
    claims: (parsed.claims || []).map((c) => ({
      attributedTo: c.attributedTo || { organization: "Unknown" },
      claimType: c.claimType || "unknown",
      confidence: c.confidence || scoreToBand(c.confidenceScore || 0),
      confidenceScore: c.confidenceScore || 0,
      supportingEvidence: c.supportingEvidence || [],
      contradictingEvidence: c.contradictingEvidence || void 0,
      alternativeAttributions: c.alternativeAttributions || void 0,
      reasoning: c.reasoning || ""
    })),
    primaryClaim: void 0,
    // set below
    evidenceSufficiency: parsed.evidenceSufficiency || "partial",
    insufficiencyReason: parsed.insufficiencyReason || void 0,
    validationResult: {},
    // set by caller
    metadata: {}
    // set by caller
  };
  if (parsed.primaryClaim) {
    output.primaryClaim = output.claims.find(
      (c) => c.attributedTo.organization === parsed.primaryClaim?.attributedTo?.organization
    ) || output.claims[0];
  } else if (output.claims.length > 0) {
    output.primaryClaim = output.claims.reduce(
      (a, b) => a.confidenceScore > b.confidenceScore ? a : b
    );
  }
  return output;
}
function applyBoundedDeltas(llmClaims, baselineClaims) {
  return llmClaims.map((llmClaim) => {
    const baselineClaim = baselineClaims.find(
      (bc) => bc.attributedTo.organization.toLowerCase() === llmClaim.attributedTo.organization.toLowerCase()
    );
    if (baselineClaim) {
      const delta = llmClaim.confidenceScore - baselineClaim.confidenceScore;
      const clampedScore = applyBoundedDelta(baselineClaim.confidenceScore, Math.max(-15, Math.min(15, delta)));
      return {
        ...llmClaim,
        confidenceScore: clampedScore,
        confidence: scoreToBand(clampedScore)
      };
    }
    return {
      ...llmClaim,
      confidenceScore: Math.min(llmClaim.confidenceScore, 70),
      confidence: scoreToBand(Math.min(llmClaim.confidenceScore, 70))
    };
  });
}
async function invokeAttributionSpecialist(input, llmInvoke) {
  const startTime = Date.now();
  const invocationId = generateInvocationId();
  const deterministicClaims = computeDeterministicAttribution(input.evidencePackage);
  let mode;
  let output;
  let fallbackApplied = false;
  if (!llmInvoke || input.configurationHints?.preferDeterministic) {
    mode = "deterministic_only";
    output = buildDeterministicOnlyOutput(input, deterministicClaims, { failures: [] });
    output.validationResult.passed = true;
    output.validationResult.fallbackApplied = false;
  } else {
    mode = "full_llm";
    try {
      const promptInput = renderEvidencePackage(input.evidencePackage) + "\n\n# DETERMINISTIC BASELINE\n\nThe following claims are derived from rule-based analysis. You may augment, refine, or add to these claims based on the evidence package, but you may not contradict the underlying evidence weights.\n\n" + JSON.stringify(deterministicClaims, null, 2);
      let fullPrompt = promptInput;
      if (input.engagementContext) {
        fullPrompt += "\n\n# ENGAGEMENT CONTEXT (background only \u2014 do not cite as evidence)\n\n" + JSON.stringify(input.engagementContext, null, 2);
      }
      const rawResponse = await llmInvoke([
        { role: "system", content: ATTRIBUTION_SPECIALIST_SYSTEM_PROMPT },
        { role: "user", content: fullPrompt }
      ]);
      output = parseAndStructure(rawResponse, input);
      output.claims = applyBoundedDeltas(output.claims, deterministicClaims);
      if (output.claims.length > 0) {
        output.primaryClaim = output.claims.reduce(
          (a, b) => a.confidenceScore > b.confidenceScore ? a : b
        );
      }
      const validation = validateAttributionOutput(output, input.evidencePackage);
      if (!validation.passed) {
        mode = "confidence_degraded";
        output = buildDeterministicOnlyOutput(input, deterministicClaims, validation);
        fallbackApplied = true;
      } else {
        output.validationResult = validation;
      }
    } catch (error) {
      mode = "deterministic_only";
      output = buildDeterministicOnlyOutput(input, deterministicClaims, {
        failures: [`LLM invocation failed: ${error.message}`]
      });
      fallbackApplied = true;
    }
  }
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
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
  return output;
}

// server/lib/llm-specialists/asset-attribution/scoring-integration.ts
var SECTOR_PRESETS = {
  financial_services: {
    criticality: 90,
    accessibility: 60,
    recuperability: 40,
    vulnerability: 65,
    effect: 85,
    recognizability: 80
  },
  healthcare: {
    criticality: 85,
    accessibility: 55,
    recuperability: 35,
    vulnerability: 70,
    effect: 90,
    recognizability: 75
  },
  government: {
    criticality: 95,
    accessibility: 40,
    recuperability: 30,
    vulnerability: 50,
    effect: 95,
    recognizability: 90
  },
  technology: {
    criticality: 70,
    accessibility: 75,
    recuperability: 55,
    vulnerability: 60,
    effect: 65,
    recognizability: 70
  },
  retail: {
    criticality: 60,
    accessibility: 80,
    recuperability: 60,
    vulnerability: 65,
    effect: 55,
    recognizability: 65
  },
  energy: {
    criticality: 95,
    accessibility: 35,
    recuperability: 25,
    vulnerability: 45,
    effect: 90,
    recognizability: 85
  },
  defense: {
    criticality: 100,
    accessibility: 25,
    recuperability: 20,
    vulnerability: 35,
    effect: 100,
    recognizability: 95
  },
  generic: {
    criticality: 50,
    accessibility: 50,
    recuperability: 50,
    vulnerability: 50,
    effect: 50,
    recognizability: 50
  }
};
function applyAttributionToAssetRecord(attribution) {
  const primary = attribution.primaryClaim;
  if (!primary) {
    return {
      attributionConfidenceMultiplier: 0.3,
      attributionStatus: "insufficient",
      attributedOrganization: null,
      attributionEvidenceCount: 0
    };
  }
  let multiplier;
  switch (primary.confidence) {
    case "high":
      multiplier = 1;
      break;
    case "medium":
      multiplier = 0.85;
      break;
    case "low":
      multiplier = 0.3;
      break;
    default:
      multiplier = 0.3;
  }
  return {
    attributionConfidenceMultiplier: multiplier,
    attributionStatus: attribution.evidenceSufficiency === "sufficient" ? "attributed" : "partial",
    attributedOrganization: primary.attributedTo.organization,
    attributionLegalEntity: primary.attributedTo.legalEntity,
    attributionParent: primary.attributedTo.parentOrganization,
    attributionClaimType: primary.claimType,
    attributionEvidenceCount: primary.supportingEvidence.length
  };
}
function inferSectorFromAttribution(attribution, customerIndustry) {
  if (customerIndustry) {
    const lower = customerIndustry.toLowerCase();
    for (const sector of Object.keys(SECTOR_PRESETS)) {
      if (lower.includes(sector.replace("_", " "))) return sector;
    }
    if (lower.includes("bank") || lower.includes("finance") || lower.includes("insurance")) return "financial_services";
    if (lower.includes("health") || lower.includes("medical") || lower.includes("pharma")) return "healthcare";
    if (lower.includes("gov") || lower.includes("federal") || lower.includes("state")) return "government";
    if (lower.includes("tech") || lower.includes("software") || lower.includes("saas")) return "technology";
    if (lower.includes("retail") || lower.includes("ecommerce") || lower.includes("commerce")) return "retail";
    if (lower.includes("energy") || lower.includes("utility") || lower.includes("oil")) return "energy";
    if (lower.includes("defense") || lower.includes("military") || lower.includes("dod")) return "defense";
  }
  const primary = attribution.primaryClaim;
  if (primary?.attributedTo.organizationType === "government") return "government";
  return "generic";
}
function applyAttributionWeightedSectorPreset(attribution, carverBaseline, customerIndustry) {
  const detectedSector = inferSectorFromAttribution(attribution, customerIndustry);
  const sectorPreset = SECTOR_PRESETS[detectedSector] || SECTOR_PRESETS.generic;
  const genericBaseline = SECTOR_PRESETS.generic;
  const scoringOutput = applyAttributionToAssetRecord(attribution);
  const weight = scoringOutput.attributionConfidenceMultiplier;
  return {
    criticality: weighted(sectorPreset.criticality, genericBaseline.criticality, weight),
    accessibility: weighted(sectorPreset.accessibility, genericBaseline.accessibility, weight),
    recuperability: weighted(sectorPreset.recuperability, genericBaseline.recuperability, weight),
    vulnerability: weighted(sectorPreset.vulnerability, genericBaseline.vulnerability, weight),
    effect: weighted(sectorPreset.effect, genericBaseline.effect, weight),
    recognizability: weighted(sectorPreset.recognizability, genericBaseline.recognizability, weight)
  };
}
function weighted(specific, generic, weight) {
  return Math.round(specific * weight + generic * (1 - weight));
}
function getSectorPresets() {
  return { ...SECTOR_PRESETS };
}
export {
  ATTRIBUTION_SPECIALIST_SYSTEM_PROMPT,
  PROMPT_VERSION,
  SPECIALIST_VERSION,
  applyAttributionToAssetRecord,
  applyAttributionWeightedSectorPreset,
  computeDeterministicAttribution,
  getSectorPresets,
  inferSectorFromAttribution,
  invokeAttributionSpecialist
};
