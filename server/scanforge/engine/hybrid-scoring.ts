/**
 * ScanForge Hybrid Scoring Engine
 *
 * Combines classical technical severity (CVSS) with actual exposure context,
 * mission relevance, and attack path value — following the CARVER+SHOCK model.
 *
 * Formula:
 *   hybrid_priority_score =
 *     ((technical_severity × exposure_modifier) +
 *      (technical_severity × attack_path_modifier × 0.5) +
 *      (mission_impact_score × 0.8))
 *   Normalized to 0–100 for UI display.
 *
 * Inputs:
 *   - CVSS base score
 *   - KEV presence (CISA Known Exploited Vulnerabilities)
 *   - EPSS probability (Exploit Prediction Scoring System)
 *   - Exposure (external/internal/segmented/unknown)
 *   - Asset criticality & business role
 *   - Exploit path value (initial access, privesc, lateral movement, etc.)
 *   - Compensating controls confidence
 *   - Data sensitivity / operational criticality
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type ExposureLevel = "external" | "internal" | "segmented" | "unknown";
export type FindingState = "verified" | "probable" | "suspected" | "informational" | "not_affected";
export type SeverityBand = "critical" | "high" | "medium" | "low" | "informational";

export interface HybridScoringInput {
  /** CVSS v3.x base score (0–10) */
  cvssBase: number | null;
  /** Is this CVE in CISA KEV catalog? */
  kevListed: boolean;
  /** EPSS probability (0–1) */
  epss: number;
  /** Asset exposure level */
  exposure: ExposureLevel;
  /** Asset criticality (0–10 scale) */
  assetCriticality: number;
  /** Business role description for mission impact inference */
  businessRole: string;
  /** Attack path categories this finding enables */
  attackPathCategories: AttackPathCategory[];
  /** Compensating controls confidence (0–1, higher = more mitigated) */
  compensatingControlsConfidence: number;
  /** Data sensitivity level (0–10) */
  dataSensitivity: number;
  /** Operational criticality (0–10) */
  operationalCriticality: number;
  /** Finding verification state */
  state: FindingState;
  /** Optional: pre-computed exploitability confidence (0–1) */
  exploitabilityConfidence?: number;
}

export type AttackPathCategory =
  | "initial_access"
  | "privilege_escalation"
  | "credential_access"
  | "lateral_movement"
  | "data_exfiltration"
  | "persistence"
  | "defense_evasion"
  | "command_and_control"
  | "impact"
  | "collection"
  | "execution"
  | "discovery"
  | "resource_development";

export interface HybridScoringResult {
  /** Normalized priority score (0–100) */
  hybridPriorityScore: number;
  /** Severity band derived from hybrid score */
  severityBand: SeverityBand;
  /** Technical severity component (0–10) */
  technicalSeverity: number;
  /** Exposure modifier applied */
  exposureModifier: number;
  /** Mission impact score (0–10) */
  missionImpactScore: number;
  /** Attack path modifier applied */
  attackPathModifier: number;
  /** Exploitability confidence (0–1) */
  exploitabilityConfidence: number;
  /** Attack path value description */
  attackPathValue: string;
  /** Human-readable rationale */
  rationale: string;
  /** Component breakdown for transparency */
  breakdown: {
    baseComponent: number;
    exposureComponent: number;
    attackPathComponent: number;
    missionComponent: number;
    stateAdjustment: number;
    controlsMitigation: number;
  };
}

// ─── Constants ──────────────────────────────────────────────────────────────

const EXPOSURE_MODIFIERS: Record<ExposureLevel, number> = {
  external: 1.4,
  internal: 1.1,
  segmented: 0.9,
  unknown: 1.0,
};

/** EPSS probability bands and their severity boost */
const EPSS_BANDS: Array<{ threshold: number; boost: number }> = [
  { threshold: 0.7, boost: 1.0 },   // Very high exploit probability
  { threshold: 0.4, boost: 0.75 },   // High
  { threshold: 0.2, boost: 0.5 },    // Moderate
  { threshold: 0.05, boost: 0.25 },  // Low-moderate
  { threshold: 0, boost: 0 },        // Minimal
];

/** Attack path category weights */
const ATTACK_PATH_WEIGHTS: Record<AttackPathCategory, number> = {
  initial_access: 1.3,
  privilege_escalation: 1.25,
  credential_access: 1.2,
  lateral_movement: 1.2,
  data_exfiltration: 1.15,
  persistence: 1.1,
  defense_evasion: 1.1,
  command_and_control: 1.05,
  impact: 1.3,
  collection: 1.0,
  execution: 1.15,
  discovery: 0.9,
  resource_development: 0.85,
};

/** State confidence multipliers */
const STATE_MULTIPLIERS: Record<FindingState, number> = {
  verified: 1.0,
  probable: 0.85,
  suspected: 0.6,
  informational: 0.3,
  not_affected: 0.0,
};

/** Business role keywords that indicate high mission impact */
const HIGH_MISSION_IMPACT_KEYWORDS = [
  "identity", "auth", "authentication", "sso", "iam",
  "admin", "management", "control plane",
  "payment", "billing", "financial", "pci",
  "customer data", "pii", "phi", "hipaa",
  "production", "prod", "primary",
  "backup", "recovery", "disaster",
  "ci/cd", "pipeline", "deployment",
  "database", "data warehouse", "analytics",
  "api gateway", "load balancer", "dns",
  "certificate", "key management", "vault",
  "monitoring", "logging", "siem",
];

// ─── Core Scoring Functions ─────────────────────────────────────────────────

/**
 * Compute the technical severity score (0–10).
 * Starts from CVSS base, adjusted by KEV and EPSS.
 */
export function computeTechnicalSeverity(input: Pick<HybridScoringInput, "cvssBase" | "kevListed" | "epss">): number {
  let score = input.cvssBase ?? 5.0; // Default to medium if no CVSS

  // KEV boost: +0.5 if listed in CISA KEV
  if (input.kevListed) {
    score += 0.5;
  }

  // EPSS boost: graduated based on probability bands
  for (const band of EPSS_BANDS) {
    if (input.epss >= band.threshold) {
      score += band.boost;
      break;
    }
  }

  return Math.min(10, Math.max(0, score));
}

/**
 * Compute the exposure modifier (0.7–1.4).
 */
export function computeExposureModifier(exposure: ExposureLevel): number {
  return EXPOSURE_MODIFIERS[exposure] ?? 1.0;
}

/**
 * Compute the mission impact score (0–10).
 * Considers asset criticality, data sensitivity, operational criticality,
 * and business role keywords.
 */
export function computeMissionImpact(input: Pick<HybridScoringInput, "assetCriticality" | "businessRole" | "dataSensitivity" | "operationalCriticality">): number {
  // Base from asset criticality
  let score = input.assetCriticality;

  // Boost from data sensitivity
  score = (score + input.dataSensitivity * 0.3 + input.operationalCriticality * 0.3);

  // Business role keyword matching
  const roleLower = input.businessRole.toLowerCase();
  const keywordMatches = HIGH_MISSION_IMPACT_KEYWORDS.filter(kw => roleLower.includes(kw));
  if (keywordMatches.length > 0) {
    score += Math.min(2.0, keywordMatches.length * 0.4);
  }

  return Math.min(10, Math.max(0, score));
}

/**
 * Compute the attack path modifier (0.8–1.3).
 * Takes the highest-weighted attack path category.
 */
export function computeAttackPathModifier(categories: AttackPathCategory[]): { modifier: number; description: string } {
  if (categories.length === 0) {
    return { modifier: 1.0, description: "No specific attack path identified" };
  }

  let maxWeight = 0.8;
  let primaryCategory = "";

  for (const cat of categories) {
    const weight = ATTACK_PATH_WEIGHTS[cat] ?? 1.0;
    if (weight > maxWeight) {
      maxWeight = weight;
      primaryCategory = cat;
    }
  }

  // Additional boost for multi-path findings
  if (categories.length >= 3) {
    maxWeight = Math.min(1.3, maxWeight + 0.1);
  }

  const description = categories.map(c => c.replace(/_/g, " ")).join(", ");
  return { modifier: maxWeight, description };
}

/**
 * Compute exploitability confidence (0–1).
 */
export function computeExploitabilityConfidence(input: Pick<HybridScoringInput, "state" | "kevListed" | "epss" | "exploitabilityConfidence">): number {
  if (input.exploitabilityConfidence !== undefined) {
    return input.exploitabilityConfidence;
  }

  let confidence = 0.5; // baseline

  // State-based
  if (input.state === "verified") confidence += 0.3;
  else if (input.state === "probable") confidence += 0.15;
  else if (input.state === "suspected") confidence -= 0.1;

  // KEV = known exploited
  if (input.kevListed) confidence += 0.15;

  // EPSS
  if (input.epss > 0.5) confidence += 0.1;
  else if (input.epss > 0.2) confidence += 0.05;

  return Math.min(1.0, Math.max(0, confidence));
}

// ─── Main Scoring Function ──────────────────────────────────────────────────

/**
 * Compute the full hybrid priority score for a ScanForge finding.
 *
 * Returns a normalized 0–100 score with full breakdown and rationale.
 */
export function computeHybridScore(input: HybridScoringInput): HybridScoringResult {
  // 1. Technical Severity (0–10)
  const technicalSeverity = computeTechnicalSeverity(input);

  // 2. Exposure Modifier (0.7–1.4)
  const exposureModifier = computeExposureModifier(input.exposure);

  // 3. Mission Impact (0–10)
  const missionImpactScore = computeMissionImpact(input);

  // 4. Attack Path Modifier (0.8–1.3)
  const { modifier: attackPathModifier, description: attackPathValue } = computeAttackPathModifier(input.attackPathCategories);

  // 5. Exploitability Confidence
  const exploitabilityConfidence = computeExploitabilityConfidence(input);

  // 6. State adjustment
  const stateMultiplier = STATE_MULTIPLIERS[input.state] ?? 1.0;

  // 7. Compensating controls mitigation
  const controlsMitigation = 1.0 - (input.compensatingControlsConfidence * 0.3);

  // ─── Formula ───
  const exposureComponent = technicalSeverity * exposureModifier;
  const attackPathComponent = technicalSeverity * attackPathModifier * 0.5;
  const missionComponent = missionImpactScore * 0.8;

  const rawScore = (exposureComponent + attackPathComponent + missionComponent) * stateMultiplier * controlsMitigation;

  // Normalize to 0–100
  // Theoretical max: (10 * 1.4) + (10 * 1.3 * 0.5) + (10 * 0.8) = 14 + 6.5 + 8 = 28.5
  const maxTheoretical = 28.5;
  const hybridPriorityScore = Math.min(100, Math.max(0, Math.round((rawScore / maxTheoretical) * 100 * 10) / 10));

  // Derive severity band
  const severityBand = deriveSeverityBand(hybridPriorityScore);

  // Build rationale
  const rationale = buildRationale(input, {
    technicalSeverity,
    exposureModifier,
    missionImpactScore,
    attackPathModifier,
    exploitabilityConfidence,
    hybridPriorityScore,
    severityBand,
  });

  return {
    hybridPriorityScore,
    severityBand,
    technicalSeverity,
    exposureModifier,
    missionImpactScore,
    attackPathModifier,
    exploitabilityConfidence,
    attackPathValue,
    rationale,
    breakdown: {
      baseComponent: Math.round(technicalSeverity * 10) / 10,
      exposureComponent: Math.round(exposureComponent * 10) / 10,
      attackPathComponent: Math.round(attackPathComponent * 10) / 10,
      missionComponent: Math.round(missionComponent * 10) / 10,
      stateAdjustment: stateMultiplier,
      controlsMitigation: Math.round(controlsMitigation * 100) / 100,
    },
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function deriveSeverityBand(score: number): SeverityBand {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

function buildRationale(
  input: HybridScoringInput,
  computed: {
    technicalSeverity: number;
    exposureModifier: number;
    missionImpactScore: number;
    attackPathModifier: number;
    exploitabilityConfidence: number;
    hybridPriorityScore: number;
    severityBand: SeverityBand;
  },
): string {
  const parts: string[] = [];

  parts.push(`Technical severity: ${computed.technicalSeverity.toFixed(1)}/10`);

  if (input.cvssBase !== null) {
    parts.push(`CVSS base: ${input.cvssBase}`);
  }
  if (input.kevListed) {
    parts.push("CISA KEV listed (+0.5 boost)");
  }
  if (input.epss > 0.05) {
    parts.push(`EPSS: ${(input.epss * 100).toFixed(1)}%`);
  }

  parts.push(`Exposure: ${input.exposure} (×${computed.exposureModifier})`);
  parts.push(`Mission impact: ${computed.missionImpactScore.toFixed(1)}/10`);

  if (input.attackPathCategories.length > 0) {
    parts.push(`Attack path: ${input.attackPathCategories.join(", ")} (×${computed.attackPathModifier})`);
  }

  if (input.compensatingControlsConfidence > 0) {
    parts.push(`Compensating controls: ${(input.compensatingControlsConfidence * 100).toFixed(0)}% confidence`);
  }

  parts.push(`State: ${input.state} (×${STATE_MULTIPLIERS[input.state]})`);
  parts.push(`Hybrid priority: ${computed.hybridPriorityScore}/100 → ${computed.severityBand.toUpperCase()}`);

  return parts.join(". ");
}

// ─── Batch Scoring ──────────────────────────────────────────────────────────

/**
 * Score multiple findings and return sorted by priority (highest first).
 */
export function batchScore(findings: Array<{ id: string; input: HybridScoringInput }>): Array<{ id: string; result: HybridScoringResult }> {
  return findings
    .map(f => ({ id: f.id, result: computeHybridScore(f.input) }))
    .sort((a, b) => b.result.hybridPriorityScore - a.result.hybridPriorityScore);
}

/**
 * Quick severity band from CVSS only (fallback when full context unavailable).
 */
export function quickSeverityFromCvss(cvss: number | null): SeverityBand {
  if (cvss === null) return "medium";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss >= 0.1) return "low";
  return "informational";
}
