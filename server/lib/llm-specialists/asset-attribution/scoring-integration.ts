/**
 * Asset Attribution Specialist — Scoring Engine Integration
 * 
 * Maps attribution output to the scoring pipeline's asset confidence
 * multiplier and sector preset weighting.
 */

import type {
  AttributionSpecialistOutput,
  AttributionScoringOutput,
  CarverScores,
} from "../types";

// ─── Sector Presets ───────────────────────────────────────────────
// CARVER+Shock baseline weights by sector (0-100 scale per dimension)

const SECTOR_PRESETS: Record<string, CarverScores> = {
  financial_services: {
    criticality: 90, accessibility: 60, recuperability: 40,
    vulnerability: 65, effect: 85, recognizability: 80,
  },
  healthcare: {
    criticality: 85, accessibility: 55, recuperability: 35,
    vulnerability: 70, effect: 90, recognizability: 75,
  },
  government: {
    criticality: 95, accessibility: 40, recuperability: 30,
    vulnerability: 50, effect: 95, recognizability: 90,
  },
  technology: {
    criticality: 70, accessibility: 75, recuperability: 55,
    vulnerability: 60, effect: 65, recognizability: 70,
  },
  retail: {
    criticality: 60, accessibility: 80, recuperability: 60,
    vulnerability: 65, effect: 55, recognizability: 65,
  },
  energy: {
    criticality: 95, accessibility: 35, recuperability: 25,
    vulnerability: 45, effect: 90, recognizability: 85,
  },
  defense: {
    criticality: 100, accessibility: 25, recuperability: 20,
    vulnerability: 35, effect: 100, recognizability: 95,
  },
  generic: {
    criticality: 50, accessibility: 50, recuperability: 50,
    vulnerability: 50, effect: 50, recognizability: 50,
  },
};

// ─── Asset Confidence Multiplier ──────────────────────────────────

/**
 * Apply attribution output to produce scoring-ready asset metadata.
 */
export function applyAttributionToAssetRecord(
  attribution: AttributionSpecialistOutput
): AttributionScoringOutput {
  const primary = attribution.primaryClaim;

  if (!primary) {
    return {
      attributionConfidenceMultiplier: 0.3,
      attributionStatus: "insufficient",
      attributedOrganization: null,
      attributionEvidenceCount: 0,
    };
  }

  let multiplier: number;
  switch (primary.confidence) {
    case "high":   multiplier = 1.0;  break;
    case "medium": multiplier = 0.85; break;
    case "low":    multiplier = 0.3;  break;
    default:       multiplier = 0.3;
  }

  return {
    attributionConfidenceMultiplier: multiplier,
    attributionStatus: attribution.evidenceSufficiency === "sufficient" ? "attributed" : "partial",
    attributedOrganization: primary.attributedTo.organization,
    attributionLegalEntity: primary.attributedTo.legalEntity,
    attributionParent: primary.attributedTo.parentOrganization,
    attributionClaimType: primary.claimType,
    attributionEvidenceCount: primary.supportingEvidence.length,
  };
}

// ─── Sector Preset Weighting ──────────────────────────────────────

/**
 * Infer sector from attribution output.
 * Uses SEC EDGAR SIC codes, industry fields, or organization type.
 */
export function inferSectorFromAttribution(
  attribution: AttributionSpecialistOutput,
  customerIndustry?: string
): string {
  // Prefer explicit customer industry if provided
  if (customerIndustry) {
    const lower = customerIndustry.toLowerCase();
    for (const sector of Object.keys(SECTOR_PRESETS)) {
      if (lower.includes(sector.replace("_", " "))) return sector;
    }
    // Common aliases
    if (lower.includes("bank") || lower.includes("finance") || lower.includes("insurance")) return "financial_services";
    if (lower.includes("health") || lower.includes("medical") || lower.includes("pharma")) return "healthcare";
    if (lower.includes("gov") || lower.includes("federal") || lower.includes("state")) return "government";
    if (lower.includes("tech") || lower.includes("software") || lower.includes("saas")) return "technology";
    if (lower.includes("retail") || lower.includes("ecommerce") || lower.includes("commerce")) return "retail";
    if (lower.includes("energy") || lower.includes("utility") || lower.includes("oil")) return "energy";
    if (lower.includes("defense") || lower.includes("military") || lower.includes("dod")) return "defense";
  }

  // Try to infer from attribution claims
  const primary = attribution.primaryClaim;
  if (primary?.attributedTo.organizationType === "government") return "government";

  return "generic";
}

/**
 * Apply attribution-weighted sector preset to CARVER scores.
 * When attribution confidence is high, the full sector preset applies.
 * When confidence is lower, the preset is blended with a generic baseline.
 */
export function applyAttributionWeightedSectorPreset(
  attribution: AttributionSpecialistOutput,
  carverBaseline: CarverScores,
  customerIndustry?: string
): CarverScores {
  const detectedSector = inferSectorFromAttribution(attribution, customerIndustry);
  const sectorPreset = SECTOR_PRESETS[detectedSector] || SECTOR_PRESETS.generic;
  const genericBaseline = SECTOR_PRESETS.generic;

  // Weight between sector-specific and generic based on attribution confidence
  const scoringOutput = applyAttributionToAssetRecord(attribution);
  const weight = scoringOutput.attributionConfidenceMultiplier;

  return {
    criticality: weighted(sectorPreset.criticality, genericBaseline.criticality, weight),
    accessibility: weighted(sectorPreset.accessibility, genericBaseline.accessibility, weight),
    recuperability: weighted(sectorPreset.recuperability, genericBaseline.recuperability, weight),
    vulnerability: weighted(sectorPreset.vulnerability, genericBaseline.vulnerability, weight),
    effect: weighted(sectorPreset.effect, genericBaseline.effect, weight),
    recognizability: weighted(sectorPreset.recognizability, genericBaseline.recognizability, weight),
  };
}

function weighted(specific: number, generic: number, weight: number): number {
  return Math.round(specific * weight + generic * (1 - weight));
}

/**
 * Get available sector presets for UI display.
 */
export function getSectorPresets(): Record<string, CarverScores> {
  return { ...SECTOR_PRESETS };
}
