/**
 * Threat Relevance Specialist
 * 
 * Assesses the threat relevance of a discovered asset:
 * per-actor-type relevance, sector exposure patterns,
 * active campaign correlations, and overall threat score.
 */

import type {
  ThreatRelevanceSpecialistInput,
  ThreatRelevanceSpecialistOutput,
  ThreatActorRelevance,
  SectorExposurePattern,
  ActiveCampaignCorrelation,
  StructuredEvidencePackage,
  EvidenceReference,
  ValidationResult,
  SpecialistMode,
  LLMInvokeFunction,
} from "../types";
import { validateGenericSpecialistOutput, applyBoundedDelta } from "../validation";
import { renderEvidencePackage, hashPackage } from "../evidence-package";
import { createHash } from "crypto";

export const SPECIALIST_VERSION = "1.0.0";
export const PROMPT_VERSION = "1.0.0";

// ─── Threat Actor Type Profiles ───────────────────────────────────

interface ThreatProfile {
  actorType: string;
  targetIndicators: string[];
  attackPatterns: string[];
  sectorPreference?: string[];
}

const THREAT_PROFILES: ThreatProfile[] = [
  {
    actorType: "nation_state_apt",
    targetIndicators: [".gov", ".mil", "defense", "energy", "critical"],
    attackPatterns: ["supply_chain", "zero_day", "spear_phishing", "watering_hole"],
    sectorPreference: ["government", "defense", "energy", "financial_services"],
  },
  {
    actorType: "ransomware_group",
    targetIndicators: ["vpn.", "rdp.", "citrix.", "exchange.", "owa."],
    attackPatterns: ["initial_access_broker", "credential_stuffing", "exploit_public_facing"],
    sectorPreference: ["healthcare", "financial_services", "retail"],
  },
  {
    actorType: "financially_motivated",
    targetIndicators: ["pay.", "checkout.", "shop.", "bank.", "finance."],
    attackPatterns: ["web_skimming", "credential_theft", "business_email_compromise"],
    sectorPreference: ["financial_services", "retail"],
  },
  {
    actorType: "hacktivist",
    targetIndicators: [".gov", "news.", "media.", "press."],
    attackPatterns: ["ddos", "defacement", "data_leak"],
  },
  {
    actorType: "insider_threat",
    targetIndicators: ["internal.", "corp.", "hr.", "payroll.", "admin."],
    attackPatterns: ["privilege_escalation", "data_exfiltration", "unauthorized_access"],
  },
];

// ─── Deterministic Baseline ───────────────────────────────────────

export function computeThreatRelevanceBaseline(
  pkg: StructuredEvidencePackage,
  customerIndustry?: string
): {
  actorRelevance: ThreatActorRelevance[];
  sectorExposure: SectorExposurePattern[];
  overallThreatScore: number;
} {
  const identifier = pkg.assetIdentifier.toLowerCase();
  const actorRelevance: ThreatActorRelevance[] = [];

  for (const profile of THREAT_PROFILES) {
    const matchingIndicators = profile.targetIndicators.filter(ind => identifier.includes(ind));
    const sectorMatch = customerIndustry && profile.sectorPreference?.some(s =>
      customerIndustry.toLowerCase().includes(s.replace("_", " "))
    );

    let relevanceScore = 0;
    const evidence: EvidenceReference[] = [];

    if (matchingIndicators.length > 0) {
      relevanceScore += 20 + matchingIndicators.length * 10;
      evidence.push({
        source: "asset_identifier",
        evidenceType: "target_indicator_match",
        weight: "moderate",
        detail: `Identifier matches: ${matchingIndicators.join(", ")}`,
      });
    }

    if (sectorMatch) {
      relevanceScore += 25;
      evidence.push({
        source: "engagement_context",
        evidenceType: "sector_alignment",
        weight: "moderate",
        detail: `Customer industry "${customerIndustry}" aligns with ${profile.actorType} targeting preferences`,
      });
    }

    // Technology-based signals
    if (pkg.http?.technologies) {
      const techs = pkg.http.technologies.map(t => t.toLowerCase());
      if (profile.actorType === "ransomware_group") {
        const vulnTechs = techs.filter(t =>
          ["exchange", "citrix", "pulse", "fortinet", "sonicwall", "f5"].some(v => t.includes(v))
        );
        if (vulnTechs.length > 0) {
          relevanceScore += 30;
          evidence.push({
            source: "http.technologies",
            evidenceType: "vulnerable_technology",
            weight: "strong",
            detail: `Technologies commonly targeted by ransomware: ${vulnTechs.join(", ")}`,
          });
        }
      }
    }

    // Exposure-based signals
    if (pkg.http?.statusCode === 200 && profile.actorType === "ransomware_group") {
      relevanceScore += 5; // publicly accessible = higher ransomware risk
    }

    if (relevanceScore > 0) {
      actorRelevance.push({
        actorType: profile.actorType,
        relevanceScore: Math.min(relevanceScore, 95),
        attackPatterns: profile.attackPatterns,
        reasoning: `Deterministic relevance assessment based on ${evidence.length} signals.`,
        supportingEvidence: evidence,
      });
    }
  }

  // Sector exposure
  const sectorExposure: SectorExposurePattern[] = [];
  if (customerIndustry) {
    const lower = customerIndustry.toLowerCase();
    if (lower.includes("health")) {
      sectorExposure.push({ sector: "healthcare", exposureLevel: "high", reasoning: "Healthcare sector faces elevated threat from ransomware and nation-state actors." });
    }
    if (lower.includes("financ") || lower.includes("bank")) {
      sectorExposure.push({ sector: "financial_services", exposureLevel: "high", reasoning: "Financial services sector faces elevated threat from financially motivated actors and nation-state espionage." });
    }
    if (lower.includes("gov") || lower.includes("defense")) {
      sectorExposure.push({ sector: "government", exposureLevel: "high", reasoning: "Government/defense sector faces elevated threat from nation-state APTs." });
    }
  }

  // Overall threat score
  const overallThreatScore = actorRelevance.length > 0
    ? Math.min(95, Math.round(actorRelevance.reduce((sum, a) => sum + a.relevanceScore, 0) / actorRelevance.length + sectorExposure.length * 10))
    : 15;

  return { actorRelevance, sectorExposure, overallThreatScore };
}

// ─── System Prompt ────────────────────────────────────────────────

const THREAT_RELEVANCE_SYSTEM_PROMPT = `You are the Threat Relevance Specialist for the AC3 platform. Analyze structured discovery evidence and assess the threat relevance of a digital asset.

Assess:
1. Per-actor-type relevance (nation_state_apt, ransomware_group, financially_motivated, hacktivist, insider_threat)
2. Sector exposure patterns
3. Active campaign correlations (if any indicators match known campaigns)
4. Overall threat score (0-100)

# GROUNDING REQUIREMENTS
- Every inference must cite evidence from the input package
- Do not use external knowledge about specific threat campaigns unless indicators are present in the evidence
- If evidence is insufficient, assign low relevance scores rather than guessing

# OUTPUT FORMAT (JSON only)
{
  "actorRelevance": [{ "actorType": string, "relevanceScore": number, "attackPatterns": string[], "reasoning": string, "supportingEvidence": [...] }],
  "sectorExposure": [{ "sector": string, "exposureLevel": string, "knownCampaigns": string[] | null, "reasoning": string }],
  "activeCampaigns": [{ "campaignName": string, "correlationStrength": string, "matchingIndicators": string[] }],
  "overallThreatScore": number
}

Return ONLY the JSON object.`;

// ─── Main Invocation ──────────────────────────────────────────────

export async function invokeThreatRelevanceSpecialist(
  input: ThreatRelevanceSpecialistInput,
  llmInvoke?: LLMInvokeFunction
): Promise<ThreatRelevanceSpecialistOutput> {
  const startTime = Date.now();
  const invocationId = `threat-${Date.now()}-${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 8)}`;

  const baseline = computeThreatRelevanceBaseline(input.evidencePackage, input.customerIndustry);

  let mode: SpecialistMode;
  let actorRelevance = baseline.actorRelevance;
  let sectorExposure = baseline.sectorExposure;
  let activeCampaigns: ActiveCampaignCorrelation[] = [];
  let overallThreatScore = baseline.overallThreatScore;
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
        (input.customerIndustry ? `\n\nCustomer Industry: ${input.customerIndustry}` : "");

      const rawResponse = await llmInvoke([
        { role: "system", content: THREAT_RELEVANCE_SYSTEM_PROMPT },
        { role: "user", content: promptInput },
      ]);

      const content = rawResponse?.choices?.[0]?.message?.content || "";
      const parsed = JSON.parse(content.replace(/^```json?\s*\n?/i, "").replace(/\n?```\s*$/i, "").trim());

      // Apply bounded deltas to threat scores
      actorRelevance = (parsed.actorRelevance || baseline.actorRelevance).map((ar: ThreatActorRelevance) => {
        const baselineAr = baseline.actorRelevance.find(b => b.actorType === ar.actorType);
        if (baselineAr) {
          return {
            ...ar,
            relevanceScore: applyBoundedDelta(baselineAr.relevanceScore, ar.relevanceScore - baselineAr.relevanceScore),
          };
        }
        return { ...ar, relevanceScore: Math.min(ar.relevanceScore, 70) };
      });

      sectorExposure = parsed.sectorExposure || baseline.sectorExposure;
      activeCampaigns = parsed.activeCampaigns || [];
      overallThreatScore = applyBoundedDelta(baseline.overallThreatScore, (parsed.overallThreatScore || 0) - baseline.overallThreatScore);

      const allEvidence = actorRelevance.flatMap((ar: ThreatActorRelevance) => ar.supportingEvidence || []);
      validationResult = validateGenericSpecialistOutput(
        allEvidence,
        actorRelevance.map((ar: ThreatActorRelevance) => ar.reasoning).join(" "),
        input.evidencePackage
      );

      if (!validationResult.passed) {
        mode = "confidence_degraded";
        actorRelevance = baseline.actorRelevance;
        sectorExposure = baseline.sectorExposure;
        activeCampaigns = [];
        overallThreatScore = baseline.overallThreatScore;
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
    actorRelevance,
    sectorExposure,
    activeCampaigns,
    overallThreatScore,
    validationResult: validationResult!,
    metadata: {
      invocationId,
      specialistName: "threat-relevance",
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
