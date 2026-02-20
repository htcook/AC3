/**
 * CARVER+Shock / CVSS v4.0 Hybrid Adaptive Scoring Engine
 * ─────────────────────────────────────────────────────────
 * Production-grade scoring module that translates military CARVER+Shock
 * targeting methodology (US Army FM 34-36) to digital asset criticality
 * assessment, combined with CVSS v4.0 vulnerability scoring and
 * LLM-based asset classification.
 *
 * Key capabilities:
 *   - CARVER factors mapped to digital asset context per FM 34-36 Appendix D
 *   - Shock factors adapted from FDA CARVER+Shock primer for cyber impact
 *   - CVSS v4.0 full metric parsing (Base/Threat/Environmental/Supplemental)
 *   - CVSS v4.0 → CARVER factor feed-through for automated enrichment
 *   - FIPS 199 security categorization integration
 *   - LLM-based asset classification with device → platform → mission inference
 *   - Dynamic re-scoring as new intelligence emerges during discovery/enumeration
 *   - Profile-aware: adjustable factor weights per engagement objective
 *   - Criticality tier system aligned to RTO (Tier 1-5)
 *   - Audit trail: every scoring decision is logged with reasoning
 *
 * Patent-pending: CARVER+Shock/CVSS Hybrid Risk Scoring Pipeline
 * Created by Harrison Cook
 */

import { invokeLLM } from "../_core/llm";

// ═══════════════════════════════════════════════════════════════════════
// §1 — CORE TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface CarverScores {
  /** How critical is the asset to mission success? (FM 34-36: Target Value) */
  criticality: number;
  /** How accessible is the asset to an attacker? (FM 34-36: Can the element reach the target?) */
  accessibility: number;
  /** How long to restore the asset after attack? (FM 34-36: Time to replace/repair/bypass) */
  recuperability: number;
  /** How vulnerable is the asset to known attacks? (FM 34-36: Does the element have means?) */
  vulnerability: number;
  /** What is the broader effect of a successful attack? (FM 34-36: Military/political/economic impact) */
  effect: number;
  /** How easily can the asset be identified/fingerprinted? (FM 34-36: Degree of recognition) */
  recognizability: number;
}

export interface ShockScores {
  /** How wide is the blast radius? (FDA: health/psychological/economic scope) */
  scope: number;
  /** How difficult is incident response? (FDA: handling complexity) */
  handling: number;
  /** How much does it disrupt operations? (FDA: operational disruption) */
  operationalImpact: number;
  /** Does failure cascade to other systems? (FDA: collateral national economic impact) */
  cascadingEffects: number;
  /** How much specialized knowledge is needed to exploit? */
  knowledge: number;
}

export interface CarverWeights {
  criticality: number;
  accessibility: number;
  recuperability: number;
  vulnerability: number;
  effect: number;
  recognizability: number;
}

export interface ShockWeights {
  scope: number;
  handling: number;
  operationalImpact: number;
  cascadingEffects: number;
  knowledge: number;
}

export interface ScoringProfile {
  carverWeights: CarverWeights;
  shockWeights: ShockWeights;
  carverWeight: number;
  shockWeight: number;
  cvssWeight: number;
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
}

export interface ScoringInput {
  carver: CarverScores;
  shock: ShockScores;
  cvssEstimate: number;
  exposure: number;
  confidence: number;
  confirmedVulnScore?: number;
  portLikelihoodBoost?: number;
  missionMultiplier?: number;
  businessImpactLevel?: "mission_critical" | "business_essential" | "operational" | "administrative";
  /** CVSS v4.0 vector string for automated CARVER enrichment */
  cvssV4Vector?: string;
  /** FIPS 199 security categorization */
  fips199?: Fips199Category;
  /** Criticality tier (1-5) */
  criticalityTier?: CriticalityTier;
}

export interface ScoringResult {
  carverComposite: number;
  shockComposite: number;
  missionImpactScore: number;
  impactScore: number;
  likelihoodScore: number;
  hybridRiskScore: number;
  riskBand: "critical" | "high" | "medium" | "low";
  factorContributions: {
    factor: string;
    category: "CARVER" | "Shock";
    rawScore: number;
    weight: number;
    weightedScore: number;
  }[];
  /** CVSS v4.0 parsed metrics (if vector provided) */
  cvssV4Parsed?: CvssV4Parsed;
  /** CVSS v4.0 → CARVER feed-through adjustments applied */
  cvssCarverAdjustments?: Partial<CarverScores>;
  /** FIPS 199 category used */
  fips199Applied?: Fips199Category;
  /** Criticality tier applied */
  criticalityTierApplied?: CriticalityTier;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — CVSS v4.0 TYPES & PARSER
// ═══════════════════════════════════════════════════════════════════════

/**
 * CVSS v4.0 metric values per FIRST.org specification.
 * Four metric groups: Base, Threat, Environmental, Supplemental.
 */
export interface CvssV4Metrics {
  // Base — Exploitability
  AV: "N" | "A" | "L" | "P";       // Attack Vector
  AC: "L" | "H";                    // Attack Complexity
  AT: "N" | "P";                    // Attack Requirements (new in v4.0)
  PR: "N" | "L" | "H";             // Privileges Required
  UI: "N" | "P" | "A";             // User Interaction (expanded in v4.0)
  // Base — Vulnerable System Impact
  VC: "N" | "L" | "H";             // Confidentiality
  VI: "N" | "L" | "H";             // Integrity
  VA: "N" | "L" | "H";             // Availability
  // Base — Subsequent System Impact
  SC: "N" | "L" | "H";             // Subsequent Confidentiality
  SI: "N" | "L" | "H";             // Subsequent Integrity
  SA: "N" | "L" | "H";             // Subsequent Availability
  // Threat
  E?: "X" | "A" | "P" | "U";      // Exploit Maturity
  // Environmental — Requirements
  CR?: "X" | "H" | "M" | "L";     // Confidentiality Requirement
  IR?: "X" | "H" | "M" | "L";     // Integrity Requirement
  AR?: "X" | "H" | "M" | "L";     // Availability Requirement
  // Environmental — Modified Base (optional overrides)
  MAV?: "X" | "N" | "A" | "L" | "P";
  MAC?: "X" | "L" | "H";
  MAT?: "X" | "N" | "P";
  MPR?: "X" | "N" | "L" | "H";
  MUI?: "X" | "N" | "P" | "A";
  MVC?: "X" | "N" | "L" | "H";
  MVI?: "X" | "N" | "L" | "H";
  MVA?: "X" | "N" | "L" | "H";
  MSC?: "X" | "N" | "L" | "H";
  MSI?: "X" | "N" | "L" | "H" | "S";  // S = Safety
  MSA?: "X" | "N" | "L" | "H" | "S";
  // Supplemental
  S?: "X" | "N" | "P";             // Safety
  AU?: "X" | "N" | "Y";            // Automatable
  U?: "X" | "Red" | "Amber" | "Green" | "Clear";  // Provider Urgency
  R?: "X" | "A" | "U" | "I";       // Recovery
  V?: "X" | "D" | "C";             // Value Density
  RE?: "X" | "L" | "M" | "H";     // Vulnerability Response Effort
}

export interface CvssV4Parsed {
  metrics: CvssV4Metrics;
  /** Nomenclature: CVSS-B, CVSS-BT, CVSS-BE, or CVSS-BTE */
  nomenclature: "CVSS-B" | "CVSS-BT" | "CVSS-BE" | "CVSS-BTE";
  /** Estimated base score (0-10) */
  estimatedScore: number;
  /** Human-readable severity */
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  /** Whether threat metrics are present */
  hasThreat: boolean;
  /** Whether environmental metrics are present */
  hasEnvironmental: boolean;
  /** Whether supplemental metrics are present */
  hasSupplemental: boolean;
}

/**
 * Parse a CVSS v4.0 vector string into structured metrics.
 * Format: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
 */
export function parseCvssV4Vector(vector: string): CvssV4Parsed | null {
  if (!vector || !vector.startsWith("CVSS:4.0/")) return null;

  const parts = vector.replace("CVSS:4.0/", "").split("/");
  const metrics: any = {};

  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }

  // Validate required base metrics
  const requiredBase = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
  for (const key of requiredBase) {
    if (!metrics[key]) return null;
  }

  const hasThreat = !!metrics.E && metrics.E !== "X";
  const hasEnvironmental = !!(
    (metrics.CR && metrics.CR !== "X") ||
    (metrics.IR && metrics.IR !== "X") ||
    (metrics.AR && metrics.AR !== "X") ||
    metrics.MAV || metrics.MAC || metrics.MAT || metrics.MPR || metrics.MUI ||
    metrics.MVC || metrics.MVI || metrics.MVA || metrics.MSC || metrics.MSI || metrics.MSA
  );
  const hasSupplemental = !!(
    (metrics.S && metrics.S !== "X") ||
    (metrics.AU && metrics.AU !== "X") ||
    (metrics.U && metrics.U !== "X") ||
    (metrics.R && metrics.R !== "X") ||
    (metrics.V && metrics.V !== "X") ||
    (metrics.RE && metrics.RE !== "X")
  );

  let nomenclature: CvssV4Parsed["nomenclature"] = "CVSS-B";
  if (hasThreat && hasEnvironmental) nomenclature = "CVSS-BTE";
  else if (hasThreat) nomenclature = "CVSS-BT";
  else if (hasEnvironmental) nomenclature = "CVSS-BE";

  const estimatedScore = estimateCvssV4Score(metrics as CvssV4Metrics);
  const severity = cvssScoreToSeverity(estimatedScore);

  return {
    metrics: metrics as CvssV4Metrics,
    nomenclature,
    estimatedScore,
    severity,
    hasThreat,
    hasEnvironmental,
    hasSupplemental,
  };
}

/**
 * Estimate a CVSS v4.0 base score from metrics.
 * This is a simplified estimation — the full CVSS v4.0 scoring algorithm
 * uses a lookup table approach. We approximate using weighted factors.
 */
function estimateCvssV4Score(m: CvssV4Metrics): number {
  // Exploitability sub-score components
  const avWeight: Record<string, number> = { N: 1.0, A: 0.75, L: 0.55, P: 0.2 };
  const acWeight: Record<string, number> = { L: 1.0, H: 0.44 };
  const atWeight: Record<string, number> = { N: 1.0, P: 0.6 };
  const prWeight: Record<string, number> = { N: 1.0, L: 0.68, H: 0.27 };
  const uiWeight: Record<string, number> = { N: 1.0, P: 0.62, A: 0.38 };

  const exploitability =
    (avWeight[m.AV] ?? 0.5) *
    (acWeight[m.AC] ?? 0.5) *
    (atWeight[m.AT] ?? 0.5) *
    (prWeight[m.PR] ?? 0.5) *
    (uiWeight[m.UI] ?? 0.5);

  // Impact sub-score components
  const impactWeight: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
  const vulnImpact = 1 - (
    (1 - (impactWeight[m.VC] ?? 0)) *
    (1 - (impactWeight[m.VI] ?? 0)) *
    (1 - (impactWeight[m.VA] ?? 0))
  );
  const subImpact = 1 - (
    (1 - (impactWeight[m.SC] ?? 0)) *
    (1 - (impactWeight[m.SI] ?? 0)) *
    (1 - (impactWeight[m.SA] ?? 0))
  );

  const totalImpact = Math.min(1, vulnImpact + subImpact * 0.5);

  if (totalImpact <= 0) return 0;

  let score = Math.min(10, 10 * (0.6 * totalImpact + 0.4 * exploitability));

  // Threat adjustment
  if (m.E && m.E !== "X") {
    const threatMult: Record<string, number> = { A: 1.0, P: 0.94, U: 0.91 };
    score *= (threatMult[m.E] ?? 1.0);
  }

  // Environmental requirement adjustments
  if (m.CR && m.CR !== "X") {
    const reqMult: Record<string, number> = { H: 1.1, M: 1.0, L: 0.9 };
    score *= (reqMult[m.CR] ?? 1.0);
  }

  return Math.round(clamp(score, 0, 10) * 10) / 10;
}

function cvssScoreToSeverity(score: number): CvssV4Parsed["severity"] {
  if (score === 0) return "None";
  if (score <= 3.9) return "Low";
  if (score <= 6.9) return "Medium";
  if (score <= 8.9) return "High";
  return "Critical";
}

/**
 * Generate a CVSS v4.0 vector string from metrics.
 */
export function buildCvssV4Vector(metrics: Partial<CvssV4Metrics>): string {
  const parts = ["CVSS:4.0"];
  const order = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    "E", "CR", "IR", "AR",
    "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
    "S", "AU", "U", "R", "V", "RE",
  ];
  for (const key of order) {
    const val = (metrics as any)[key];
    if (val && val !== "X") parts.push(`${key}:${val}`);
  }
  return parts.join("/");
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — CVSS v4.0 → CARVER FEED-THROUGH
// ═══════════════════════════════════════════════════════════════════════

/**
 * Map CVSS v4.0 metrics to CARVER factor adjustments.
 * This is the bridge between technical vulnerability scoring and
 * organizational mission impact assessment.
 *
 * Mapping rationale:
 *   AV (Attack Vector)     → Accessibility (network reach = physical access analog)
 *   AC + AT (Complexity)   → Vulnerability (ease of exploitation)
 *   E (Exploit Maturity)   → Vulnerability + Recognizability
 *   PR + UI (Requirements) → Accessibility (barriers to entry)
 *   VC/VI/VA (Impact)      → Effect (direct damage)
 *   SC/SI/SA (Subsequent)  → Shock.cascadingEffects
 *   CR/IR/AR (Env Reqs)    → Criticality (organizational importance)
 *   R (Recovery)           → Recuperability
 *   S (Safety)             → Shock.operationalImpact
 *   AU (Automatable)       → Recognizability + Accessibility
 *   V (Value Density)      → Shock.scope
 */
export function cvssV4ToCarverAdjustments(parsed: CvssV4Parsed): {
  carverAdjustments: Partial<CarverScores>;
  shockAdjustments: Partial<ShockScores>;
} {
  const m = parsed.metrics;
  const carver: Partial<CarverScores> = {};
  const shock: Partial<ShockScores> = {};

  // AV → Accessibility
  const avMap: Record<string, number> = { N: 9, A: 7, L: 4, P: 2 };
  carver.accessibility = avMap[m.AV] ?? 5;

  // AC + AT → Vulnerability (ease of exploitation)
  const acBase: Record<string, number> = { L: 8, H: 4 };
  const atMod: Record<string, number> = { N: 1.0, P: 0.7 };
  carver.vulnerability = Math.round(
    (acBase[m.AC] ?? 5) * (atMod[m.AT] ?? 0.85)
  );

  // PR + UI → Accessibility modifier
  const prMod: Record<string, number> = { N: 0, L: -1, H: -3 };
  const uiMod: Record<string, number> = { N: 0, P: -1, A: -2 };
  carver.accessibility = clamp(
    carver.accessibility + (prMod[m.PR] ?? 0) + (uiMod[m.UI] ?? 0),
    1, 10
  );

  // VC/VI/VA → Effect (direct damage to vulnerable system)
  const impMap: Record<string, number> = { N: 0, L: 3, H: 8 };
  const vulnEffect = Math.max(
    impMap[m.VC] ?? 0,
    impMap[m.VI] ?? 0,
    impMap[m.VA] ?? 0
  );
  carver.effect = clamp(vulnEffect, 1, 10);

  // SC/SI/SA → Shock.cascadingEffects (damage to subsequent systems)
  const subEffect = Math.max(
    impMap[m.SC] ?? 0,
    impMap[m.SI] ?? 0,
    impMap[m.SA] ?? 0
  );
  if (subEffect > 0) {
    shock.cascadingEffects = clamp(subEffect + 1, 1, 10);
    shock.scope = clamp(Math.round(subEffect * 0.8), 1, 10);
  }

  // E (Exploit Maturity) → Vulnerability boost + Recognizability
  if (m.E && m.E !== "X") {
    const eMod: Record<string, number> = { A: 2, P: 1, U: 0 };
    carver.vulnerability = clamp(
      (carver.vulnerability ?? 5) + (eMod[m.E] ?? 0),
      1, 10
    );
    // Actively exploited = highly recognizable to attackers
    if (m.E === "A") carver.recognizability = 8;
    else if (m.E === "P") carver.recognizability = 6;
  }

  // Environmental Requirements → Criticality
  if (m.CR || m.IR || m.AR) {
    const reqMap: Record<string, number> = { H: 9, M: 6, L: 3 };
    const maxReq = Math.max(
      reqMap[m.CR ?? "X"] ?? 0,
      reqMap[m.IR ?? "X"] ?? 0,
      reqMap[m.AR ?? "X"] ?? 0
    );
    if (maxReq > 0) carver.criticality = maxReq;
  }

  // Supplemental: Recovery → Recuperability
  if (m.R && m.R !== "X") {
    const recMap: Record<string, number> = { I: 10, U: 7, A: 3 };
    carver.recuperability = recMap[m.R] ?? 5;
  }

  // Supplemental: Safety → Shock.operationalImpact
  if (m.S === "P") {
    shock.operationalImpact = 9;
  }

  // Supplemental: Automatable → Accessibility + Recognizability boost
  if (m.AU === "Y") {
    carver.accessibility = clamp((carver.accessibility ?? 5) + 1, 1, 10);
    carver.recognizability = clamp((carver.recognizability ?? 5) + 1, 1, 10);
  }

  // Supplemental: Value Density → Shock.scope
  if (m.V === "C") {
    shock.scope = clamp((shock.scope ?? 5) + 2, 1, 10);
  }

  return { carverAdjustments: carver, shockAdjustments: shock };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — FIPS 199 SECURITY CATEGORIZATION
// ═══════════════════════════════════════════════════════════════════════

export interface Fips199Category {
  confidentiality: "low" | "moderate" | "high";
  integrity: "low" | "moderate" | "high";
  availability: "low" | "moderate" | "high";
}

/**
 * Map FIPS 199 security categories to CARVER+Shock adjustments.
 * FIPS 199 defines the security categorization for federal information systems,
 * but the concept applies broadly to any organization's asset classification.
 */
export function fips199ToCarverAdjustments(category: Fips199Category): {
  carverAdjustments: Partial<CarverScores>;
  shockAdjustments: Partial<ShockScores>;
  missionMultiplier: number;
} {
  const levelMap: Record<string, number> = { low: 2, moderate: 5, high: 9 };

  const confScore = levelMap[category.confidentiality] ?? 5;
  const intScore = levelMap[category.integrity] ?? 5;
  const availScore = levelMap[category.availability] ?? 5;

  const maxLevel = Math.max(confScore, intScore, availScore);

  const carver: Partial<CarverScores> = {
    criticality: maxLevel,
    effect: Math.round((confScore + intScore) / 2),
    recuperability: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 3,
  };

  const shock: Partial<ShockScores> = {
    scope: confScore >= 7 ? 8 : confScore >= 4 ? 5 : 2,
    operationalImpact: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 2,
    handling: intScore >= 7 ? 7 : intScore >= 4 ? 5 : 3,
  };

  // Mission multiplier based on highest categorization
  let missionMultiplier = 1.0;
  if (maxLevel >= 9) missionMultiplier = 1.8;
  else if (maxLevel >= 5) missionMultiplier = 1.3;
  else missionMultiplier = 0.9;

  return { carverAdjustments: carver, shockAdjustments: shock, missionMultiplier };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — CRITICALITY TIER SYSTEM
// ═══════════════════════════════════════════════════════════════════════

export type CriticalityTier = 1 | 2 | 3 | 4 | 5;

/**
 * Criticality tiers aligned to Recovery Time Objectives (RTO).
 * Based on NIST SP 800-34 and BIA best practices.
 */
export const CRITICALITY_TIERS: Record<CriticalityTier, {
  name: string;
  rto: string;
  description: string;
  missionMultiplier: number;
  carverFloor: Partial<CarverScores>;
  shockFloor: Partial<ShockScores>;
}> = {
  1: {
    name: "Mission Critical",
    rto: "< 1 hour",
    description: "Immediate operational impact. Loss causes complete mission failure. No acceptable workaround exists.",
    missionMultiplier: 2.0,
    carverFloor: { criticality: 9, effect: 8, recuperability: 9 },
    shockFloor: { operationalImpact: 9, cascadingEffects: 8, scope: 8 },
  },
  2: {
    name: "Business Critical",
    rto: "1–24 hours",
    description: "Significant impact within hours. Core business functions degraded. Manual workarounds possible but costly.",
    missionMultiplier: 1.6,
    carverFloor: { criticality: 7, effect: 7, recuperability: 7 },
    shockFloor: { operationalImpact: 7, cascadingEffects: 6, scope: 6 },
  },
  3: {
    name: "Business Important",
    rto: "1–7 days",
    description: "Moderate impact within days. Supporting functions affected. Workarounds available.",
    missionMultiplier: 1.3,
    carverFloor: { criticality: 5, effect: 5, recuperability: 5 },
    shockFloor: { operationalImpact: 5, cascadingEffects: 4, scope: 4 },
  },
  4: {
    name: "Administrative",
    rto: "> 7 days",
    description: "Minimal operational impact. Administrative or convenience functions. Extended outage tolerable.",
    missionMultiplier: 0.9,
    carverFloor: { criticality: 3, effect: 3 },
    shockFloor: { operationalImpact: 3 },
  },
  5: {
    name: "Non-Essential",
    rto: "N/A",
    description: "No operational impact. Test environments, deprecated systems, or non-production assets.",
    missionMultiplier: 0.6,
    carverFloor: { criticality: 1, effect: 1 },
    shockFloor: { operationalImpact: 1 },
  },
};

/**
 * Apply criticality tier floors to CARVER+Shock scores.
 */
export function applyCriticalityTierFloors(
  carver: CarverScores,
  shock: ShockScores,
  tier: CriticalityTier
): { carver: CarverScores; shock: ShockScores; missionMultiplier: number } {
  const tierDef = CRITICALITY_TIERS[tier];
  const adjustedCarver = { ...carver };
  const adjustedShock = { ...shock };

  for (const [key, val] of Object.entries(tierDef.carverFloor)) {
    const k = key as keyof CarverScores;
    adjustedCarver[k] = Math.max(adjustedCarver[k], val as number);
  }
  for (const [key, val] of Object.entries(tierDef.shockFloor)) {
    const k = key as keyof ShockScores;
    adjustedShock[k] = Math.max(adjustedShock[k], val as number);
  }

  return { carver: adjustedCarver, shock: adjustedShock, missionMultiplier: tierDef.missionMultiplier };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — FM 34-36 DIGITAL ASSET TRANSLATION TABLES
// ═══════════════════════════════════════════════════════════════════════

/**
 * FM 34-36 Appendix D CARVER factor scoring translated to digital assets.
 * Each factor retains the 1-10 scale from the original military methodology
 * but criteria are adapted for cyber operations targeting.
 */
export const CARVER_DIGITAL_TRANSLATION = {
  criticality: {
    name: "Criticality (Mission Value)",
    fm34_36: "How important is the target to the overall system/mission?",
    digital: "How critical is this digital asset to the organization's essential missions and supporting functions?",
    scale: [
      { range: [9, 10], military: "Immediate halt in output/production/service", digital: "Domain controller, primary DB, payment gateway — immediate halt to all dependent services" },
      { range: [7, 8], military: "Halt within 1 day, or 66% curtailment", digital: "Email server, VPN concentrator, ERP — major business disruption within hours" },
      { range: [5, 6], military: "Halt within 1 week, or 33% curtailment", digital: "CI/CD pipeline, monitoring stack, secondary DNS — degraded operations within days" },
      { range: [3, 4], military: "Halt within 10 days, or 10% curtailment", digital: "Development server, staging environment, internal wiki — minor productivity loss" },
      { range: [1, 2], military: "No significant effect on output", digital: "Test environment, deprecated system, static marketing page — no operational impact" },
    ],
    subFactors: ["Time to impact", "Percentage of function curtailment", "Availability of surrogates", "Position in dependency chain"],
  },
  accessibility: {
    name: "Accessibility (Attack Surface)",
    fm34_36: "Can the operational element reach the target?",
    digital: "How reachable is the asset from an attacker's perspective, considering network position and authentication barriers?",
    scale: [
      { range: [9, 10], military: "Easily accessible, standoff weapons can be employed", digital: "Internet-facing, no auth required, known service with public exploits" },
      { range: [7, 8], military: "Inside perimeter fence but outdoors", digital: "Internet-facing with basic auth, or DMZ with known attack surface" },
      { range: [5, 6], military: "Inside building, ground floor", digital: "DMZ with WAF/IDS, requires credential theft or social engineering" },
      { range: [3, 4], military: "Inside building, 2nd floor/basement", digital: "Internal network, segmented VLAN, requires lateral movement" },
      { range: [1, 2], military: "Not accessible or extreme difficulty", digital: "Air-gapped, hardware security module, or zero-trust microsegmented" },
    ],
    subFactors: ["Network exposure", "Authentication barriers", "Firewall/WAF protection", "Physical access requirements"],
  },
  recuperability: {
    name: "Recuperability (Recovery Difficulty)",
    fm34_36: "How long to replace, repair, or bypass?",
    digital: "How long to restore the asset to full operational capability after compromise or destruction?",
    scale: [
      { range: [9, 10], military: "Replacement/repair requires 1 month+", digital: "Custom-built system, no backups, no documentation — months to rebuild" },
      { range: [7, 8], military: "Replacement/repair requires 1 week to 1 month", digital: "Complex system, weekly backups, specialized knowledge required" },
      { range: [5, 6], military: "Replacement/repair requires 72 hours to 1 week", digital: "Standard system, daily backups, documented recovery procedures" },
      { range: [3, 4], military: "Replacement/repair requires 24 to 72 hours", digital: "Redundant system, hot standby, automated failover with manual intervention" },
      { range: [1, 2], military: "Same day replacement/repair", digital: "Auto-scaling, instant failover, immutable infrastructure, containerized" },
    ],
    subFactors: ["Backup frequency", "Recovery documentation", "Redundancy level", "Specialized knowledge required"],
  },
  vulnerability: {
    name: "Vulnerability (Exploitability)",
    fm34_36: "Does the operational element have means to attack?",
    digital: "Does the attacker have viable means to exploit this asset, considering known CVEs, misconfigurations, and available tooling?",
    scale: [
      { range: [9, 10], military: "Vulnerable to small arms or charges ≤5 lbs", digital: "Known RCE with public exploit, actively exploited in the wild (KEV)" },
      { range: [7, 8], military: "Vulnerable to light antiarmor or 5-10 lb charges", digital: "Known vulnerability with proof-of-concept, exploit kit available" },
      { range: [5, 6], military: "Vulnerable to medium antiarmor or 10-30 lb charges", digital: "Known vulnerability, complex exploit chain required" },
      { range: [3, 4], military: "Vulnerable to heavy antiarmor or 30-50 lb charges", digital: "Theoretical vulnerability, no public exploit, requires custom tooling" },
      { range: [1, 2], military: "Invulnerable to all but extreme measures", digital: "No known vulnerabilities, hardened configuration, defense in depth" },
    ],
    subFactors: ["CVE count and severity", "Exploit availability", "Patch status", "Configuration hardening"],
  },
  effect: {
    name: "Effect (Organizational Impact)",
    fm34_36: "Military, political, economic, psychological, sociological impacts",
    digital: "What are the broader organizational impacts of successful compromise — financial, regulatory, reputational, operational?",
    scale: [
      { range: [9, 10], military: "Overwhelmingly positive effects for attacker", digital: "Data breach + regulatory fines + reputational damage + operational shutdown" },
      { range: [7, 8], military: "Moderately positive effects for attacker", digital: "Service disruption + financial loss + customer impact" },
      { range: [5, 6], military: "No significant effects; neutral", digital: "Limited operational impact, contained to single business unit" },
      { range: [3, 4], military: "Moderately negative effects for attacker", digital: "Minimal impact, quickly contained, no data exposure" },
      { range: [1, 2], military: "Overwhelmingly negative effects for attacker", digital: "No meaningful impact, honeypot/deception, attacker exposure risk" },
    ],
    subFactors: ["Financial impact", "Regulatory consequences", "Reputational damage", "Operational disruption"],
  },
  recognizability: {
    name: "Recognizability (Discoverability)",
    fm34_36: "Degree to which target can be identified",
    digital: "How easily can an attacker identify, fingerprint, and target this specific asset?",
    scale: [
      { range: [9, 10], military: "Clearly recognizable under all conditions from distance", digital: "Banner grabbing reveals exact version, indexed by search engines, public documentation" },
      { range: [7, 8], military: "Easily recognizable at small-arms range", digital: "Service type identifiable, version guessable from behavior patterns" },
      { range: [5, 6], military: "Difficult in bad weather, might be confused", digital: "Service type identifiable but version hidden, generic error pages" },
      { range: [3, 4], military: "Difficult even at close range, easily confused", digital: "Behind CDN/WAF, minimal fingerprint, custom headers stripped" },
      { range: [1, 2], military: "Cannot be recognized except by experts", digital: "Completely obscured, no signatures, deception/honeypot deployed" },
    ],
    subFactors: ["Banner exposure", "Search engine indexing", "DNS/certificate transparency", "Error page information leakage"],
  },
} as const;

/**
 * FM 34-36 Shock factor translated to digital assets.
 * Adapted from FDA CARVER+Shock primer for cyber operations.
 */
export const SHOCK_DIGITAL_TRANSLATION = {
  scope: {
    name: "Scope (Blast Radius)",
    original: "Health, psychological, and collateral economic impacts — scope of affected population",
    digital: "How many users, customers, or systems are affected by compromise of this asset?",
    scale: [
      { range: [9, 10], digital: "All customers/users affected, global service outage, supply chain cascade" },
      { range: [7, 8], digital: "Major customer segment affected, regional outage, partner impact" },
      { range: [5, 6], digital: "Department-level impact, subset of users affected" },
      { range: [3, 4], digital: "Team-level impact, limited user base affected" },
      { range: [1, 2], digital: "Single user or system affected, no external impact" },
    ],
  },
  handling: {
    name: "Handling (Response Complexity)",
    original: "Difficulty of incident response and containment",
    digital: "How complex is the incident response, forensics, and remediation process?",
    scale: [
      { range: [9, 10], digital: "Requires external forensics, legal counsel, regulatory notification, board-level response" },
      { range: [7, 8], digital: "Cross-team IR, evidence preservation, customer notification required" },
      { range: [5, 6], digital: "Standard IR playbook, contained within security team" },
      { range: [3, 4], digital: "Simple remediation, automated response available" },
      { range: [1, 2], digital: "Self-healing, auto-rollback, no manual intervention needed" },
    ],
  },
  operationalImpact: {
    name: "Operational Impact (Business Disruption)",
    original: "Disruption to normal operations and essential services",
    digital: "How severely does compromise disrupt day-to-day business operations and revenue generation?",
    scale: [
      { range: [9, 10], digital: "Complete business halt, revenue stops, SLA violations, contractual penalties" },
      { range: [7, 8], digital: "Major business disruption, significant revenue impact, degraded SLAs" },
      { range: [5, 6], digital: "Moderate disruption, some revenue impact, workarounds available" },
      { range: [3, 4], digital: "Minor disruption, negligible revenue impact, easy workarounds" },
      { range: [1, 2], digital: "No operational disruption, business continues normally" },
    ],
  },
  cascadingEffects: {
    name: "Cascading Effects (Dependency Chain)",
    original: "Collateral national economic impact and downstream effects",
    digital: "Does compromise of this asset enable attacks on dependent systems, partners, or supply chain?",
    scale: [
      { range: [9, 10], digital: "Compromise enables full domain takeover, supply chain poisoning, island-hopping to partners" },
      { range: [7, 8], digital: "Compromise of auth/SSO cascades to all downstream applications" },
      { range: [5, 6], digital: "Compromise affects 2-3 dependent systems or services" },
      { range: [3, 4], digital: "Limited cascade, 1 dependent system affected" },
      { range: [1, 2], digital: "Isolated system, no downstream dependencies" },
    ],
  },
  knowledge: {
    name: "Knowledge (Exploitation Expertise)",
    original: "Specialized knowledge required for attack",
    digital: "What level of specialized knowledge or tooling does an attacker need to exploit this asset?",
    scale: [
      { range: [9, 10], digital: "Script kiddie level — automated tools, public exploits, no expertise needed" },
      { range: [7, 8], digital: "Intermediate — requires understanding of the technology stack" },
      { range: [5, 6], digital: "Advanced — requires custom tooling or exploit development" },
      { range: [3, 4], digital: "Expert — requires deep domain knowledge and specialized equipment" },
      { range: [1, 2], digital: "Nation-state level — requires zero-day research and significant resources" },
    ],
  },
} as const;

// ═══════════════════════════════════════════════════════════════════════
// §7 — ASSET CLASSIFICATION TAXONOMY
// ═══════════════════════════════════════════════════════════════════════

export const ASSET_DEVICE_TYPES = [
  "network_infrastructure",
  "server",
  "endpoint",
  "security_appliance",
  "storage",
  "cloud_service",
  "iot_ot",
  "unknown",
] as const;

export const ASSET_PLATFORM_TYPES = [
  "identity_access",
  "business_critical",
  "communication",
  "development",
  "data_store",
  "web_application",
  "monitoring",
  "content_delivery",
  "unknown",
] as const;

export const MISSION_FUNCTIONS = [
  "command_control",
  "revenue_generation",
  "customer_data",
  "intellectual_property",
  "operational_continuity",
  "compliance",
  "external_communication",
  "authentication",
  "data_processing",
  "supply_chain",
] as const;

export const ESSENTIAL_SERVICES = [
  "email", "sso", "vpn", "dns", "dhcp", "active_directory",
  "payment_processing", "customer_portal", "api_gateway",
  "database", "file_storage", "backup", "monitoring",
  "ci_cd", "source_control", "container_orchestration",
  "erp", "crm", "hrm", "voip", "video_conferencing",
  "web_server", "load_balancer", "firewall", "waf",
  "siem", "edr", "dlp", "encryption_key_management",
] as const;

export const BUSINESS_IMPACT_LEVELS = [
  "mission_critical",
  "business_essential",
  "operational",
  "administrative",
] as const;

export interface AssetClassification {
  deviceType: typeof ASSET_DEVICE_TYPES[number];
  platformType: typeof ASSET_PLATFORM_TYPES[number];
  missionFunction: typeof MISSION_FUNCTIONS[number];
  essentialService: string;
  assetPurpose: string;
  businessImpactLevel: typeof BUSINESS_IMPACT_LEVELS[number];
  /** FIPS 199 security categorization inferred by LLM */
  fips199Category?: Fips199Category;
  /** Criticality tier (1-5) inferred by LLM */
  criticalityTier?: CriticalityTier;
  missionDependencies: {
    upstreamAssets: string[];
    downstreamAssets: string[];
    sharedServices: string[];
  };
  carverAdjustments: Partial<CarverScores>;
  shockAdjustments: Partial<ShockScores>;
  classificationConfidence: number;
  reasoning: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — MISSION FUNCTION BASELINES
// ═══════════════════════════════════════════════════════════════════════

export const MISSION_FUNCTION_BASELINES: Record<string, {
  carver: Partial<CarverScores>;
  shock: Partial<ShockScores>;
  missionMultiplier: number;
  description: string;
}> = {
  command_control: {
    carver: { criticality: 9, effect: 8, recuperability: 7 },
    shock: { operationalImpact: 9, cascadingEffects: 8, scope: 7 },
    missionMultiplier: 1.8,
    description: "C2 assets are the nerve center — compromise enables adversary control of the entire operational environment",
  },
  revenue_generation: {
    carver: { criticality: 8, effect: 8, recognizability: 7 },
    shock: { operationalImpact: 8, scope: 7, handling: 6 },
    missionMultiplier: 1.6,
    description: "Revenue assets directly impact financial viability — downtime or breach has immediate P&L consequences",
  },
  customer_data: {
    carver: { criticality: 8, effect: 7, recuperability: 8 },
    shock: { scope: 9, handling: 8, operationalImpact: 7 },
    missionMultiplier: 1.7,
    description: "Customer data assets carry regulatory and reputational risk — breach triggers mandatory disclosure and potential class action",
  },
  intellectual_property: {
    carver: { criticality: 7, effect: 9, recuperability: 9 },
    shock: { cascadingEffects: 8, scope: 6, knowledge: 7 },
    missionMultiplier: 1.5,
    description: "IP assets represent irreplaceable competitive advantage — exfiltration causes permanent strategic damage",
  },
  operational_continuity: {
    carver: { criticality: 7, effect: 7, recuperability: 6 },
    shock: { operationalImpact: 8, cascadingEffects: 7, handling: 6 },
    missionMultiplier: 1.4,
    description: "Operational assets keep the lights on — disruption cascades through dependent business processes",
  },
  compliance: {
    carver: { criticality: 6, effect: 7, recognizability: 5 },
    shock: { scope: 7, handling: 7, operationalImpact: 5 },
    missionMultiplier: 1.3,
    description: "Compliance assets carry regulatory risk — failure triggers audit findings, fines, and potential license revocation",
  },
  external_communication: {
    carver: { criticality: 6, accessibility: 8, recognizability: 8 },
    shock: { scope: 6, handling: 5, operationalImpact: 5 },
    missionMultiplier: 1.2,
    description: "External-facing communication assets are highly accessible and recognizable — prime targets for impersonation and phishing",
  },
  authentication: {
    carver: { criticality: 9, accessibility: 7, effect: 9, recuperability: 8 },
    shock: { cascadingEffects: 9, operationalImpact: 8, scope: 8 },
    missionMultiplier: 1.9,
    description: "Authentication is the master key — compromise grants adversary access to all downstream systems and data",
  },
  data_processing: {
    carver: { criticality: 6, effect: 6, vulnerability: 5 },
    shock: { operationalImpact: 6, cascadingEffects: 5, handling: 5 },
    missionMultiplier: 1.2,
    description: "Data processing assets transform raw data into actionable intelligence — disruption delays decision-making",
  },
  supply_chain: {
    carver: { criticality: 7, accessibility: 6, vulnerability: 7 },
    shock: { cascadingEffects: 8, scope: 7, handling: 7 },
    missionMultiplier: 1.5,
    description: "Supply chain assets bridge trust boundaries — compromise enables island-hopping attacks to partners and vendors",
  },
};

export const ESSENTIAL_SERVICE_BASELINES: Record<string, {
  carver: Partial<CarverScores>;
  shock: Partial<ShockScores>;
}> = {
  sso: { carver: { criticality: 9, effect: 9, recuperability: 8 }, shock: { cascadingEffects: 9, scope: 8 } },
  active_directory: { carver: { criticality: 9, effect: 9, recuperability: 9 }, shock: { cascadingEffects: 9, scope: 9, operationalImpact: 9 } },
  payment_processing: { carver: { criticality: 8, effect: 8, recognizability: 7 }, shock: { scope: 8, handling: 8 } },
  email: { carver: { criticality: 7, accessibility: 8, recognizability: 8 }, shock: { scope: 7, operationalImpact: 7 } },
  vpn: { carver: { criticality: 7, accessibility: 9, vulnerability: 7 }, shock: { cascadingEffects: 7, operationalImpact: 7 } },
  dns: { carver: { criticality: 8, effect: 8, recuperability: 6 }, shock: { cascadingEffects: 8, scope: 8 } },
  database: { carver: { criticality: 8, effect: 7, recuperability: 7 }, shock: { scope: 7, handling: 7 } },
  api_gateway: { carver: { criticality: 7, accessibility: 8, recognizability: 7 }, shock: { cascadingEffects: 7, scope: 6 } },
  firewall: { carver: { criticality: 8, effect: 8, vulnerability: 5 }, shock: { cascadingEffects: 8, scope: 7 } },
  backup: { carver: { criticality: 7, recuperability: 9, recognizability: 3 }, shock: { handling: 8, operationalImpact: 6 } },
  siem: { carver: { criticality: 6, effect: 5, recognizability: 4 }, shock: { handling: 7, knowledge: 7 } },
  encryption_key_management: { carver: { criticality: 9, effect: 9, recuperability: 10 }, shock: { cascadingEffects: 9, scope: 8, handling: 9 } },
  ci_cd: { carver: { criticality: 7, vulnerability: 7, effect: 7 }, shock: { cascadingEffects: 7, knowledge: 6 } },
  source_control: { carver: { criticality: 7, effect: 8, recuperability: 7 }, shock: { scope: 6, knowledge: 7 } },
  customer_portal: { carver: { criticality: 7, accessibility: 9, recognizability: 8 }, shock: { scope: 7, handling: 6 } },
  erp: { carver: { criticality: 8, effect: 8, recuperability: 7 }, shock: { operationalImpact: 9, cascadingEffects: 7, scope: 7 } },
  load_balancer: { carver: { criticality: 7, effect: 7, recognizability: 5 }, shock: { cascadingEffects: 7, operationalImpact: 6 } },
  waf: { carver: { criticality: 6, effect: 6, vulnerability: 4 }, shock: { scope: 5, handling: 5 } },
};

// ═══════════════════════════════════════════════════════════════════════
// §9 — DEFAULT & PRESET PROFILES
// ═══════════════════════════════════════════════════════════════════════

export const DEFAULT_PROFILE: ScoringProfile = {
  carverWeights: {
    criticality: 2.0,
    accessibility: 1.5,
    recuperability: 1.0,
    vulnerability: 1.5,
    effect: 1.5,
    recognizability: 0.5,
  },
  shockWeights: {
    scope: 1.5,
    handling: 1.0,
    operationalImpact: 2.0,
    cascadingEffects: 1.5,
    knowledge: 1.0,
  },
  carverWeight: 0.4,
  shockWeight: 0.3,
  cvssWeight: 0.3,
  criticalThreshold: 85,
  highThreshold: 65,
  mediumThreshold: 40,
};

export const PRESET_PROFILES: Record<string, { name: string; description: string; profile: ScoringProfile }> = {
  critical_infrastructure: {
    name: "Critical Infrastructure",
    description: "Emphasizes Shock factors (cascading effects, operational impact) for SCADA/ICS/OT environments. Designed for assessments of power grids, water treatment, and transportation systems.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 2.5, accessibility: 1.0, recuperability: 2.0, vulnerability: 1.5, effect: 2.0, recognizability: 0.5 },
      shockWeights: { scope: 2.5, handling: 1.5, operationalImpact: 3.0, cascadingEffects: 2.5, knowledge: 1.0 },
      carverWeight: 0.3,
      shockWeight: 0.5,
      cvssWeight: 0.2,
    },
  },
  financial_services: {
    name: "Financial Services",
    description: "Prioritizes accessibility and data exposure for banking, payment processing, and financial infrastructure. Aligns with PCI-DSS and SOX requirements.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 2.0, accessibility: 2.5, recuperability: 1.5, vulnerability: 2.0, effect: 1.5, recognizability: 1.0 },
      shockWeights: { scope: 2.0, handling: 1.5, operationalImpact: 1.5, cascadingEffects: 1.0, knowledge: 0.5 },
      carverWeight: 0.45,
      shockWeight: 0.2,
      cvssWeight: 0.35,
    },
  },
  healthcare: {
    name: "Healthcare / HIPAA",
    description: "Emphasizes recuperability and operational impact for patient care systems. Aligns with HIPAA security requirements and patient safety priorities.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 2.0, accessibility: 1.5, recuperability: 2.5, vulnerability: 1.5, effect: 2.0, recognizability: 0.5 },
      shockWeights: { scope: 1.5, handling: 2.0, operationalImpact: 2.5, cascadingEffects: 2.0, knowledge: 1.0 },
      carverWeight: 0.35,
      shockWeight: 0.4,
      cvssWeight: 0.25,
    },
  },
  government_dod: {
    name: "Government / DoD",
    description: "Balanced CARVER emphasis for military and government assessments. Aligns with NIST 800-53, CMMC, and traditional CARVER targeting methodology.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 2.5, accessibility: 2.0, recuperability: 1.5, vulnerability: 1.5, effect: 2.0, recognizability: 1.0 },
      shockWeights: { scope: 1.5, handling: 1.0, operationalImpact: 1.5, cascadingEffects: 1.5, knowledge: 1.5 },
      carverWeight: 0.5,
      shockWeight: 0.25,
      cvssWeight: 0.25,
    },
  },
  red_team_offensive: {
    name: "Red Team / Offensive",
    description: "Maximizes accessibility and vulnerability weights to prioritize the easiest attack paths. Designed for penetration testing and adversary emulation engagements.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 1.5, accessibility: 3.0, recuperability: 0.5, vulnerability: 2.5, effect: 1.0, recognizability: 1.5 },
      shockWeights: { scope: 1.0, handling: 0.5, operationalImpact: 1.0, cascadingEffects: 0.5, knowledge: 1.5 },
      carverWeight: 0.5,
      shockWeight: 0.15,
      cvssWeight: 0.35,
    },
  },
  mssp_managed: {
    name: "MSSP / Managed Services",
    description: "Balanced profile for managed security service providers managing multiple client environments. Emphasizes scope and cascading effects across client boundaries.",
    profile: {
      ...DEFAULT_PROFILE,
      carverWeights: { criticality: 2.0, accessibility: 2.0, recuperability: 1.5, vulnerability: 1.5, effect: 1.5, recognizability: 1.0 },
      shockWeights: { scope: 2.5, handling: 1.5, operationalImpact: 1.5, cascadingEffects: 2.0, knowledge: 1.0 },
      carverWeight: 0.35,
      shockWeight: 0.35,
      cvssWeight: 0.3,
    },
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §10 — CORE SCORING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

export function computeCarverComposite(scores: CarverScores, weights: CarverWeights): number {
  let sum = 0, totalWeight = 0;
  const entries: [keyof CarverScores, number][] = [
    ["criticality", weights.criticality],
    ["accessibility", weights.accessibility],
    ["recuperability", weights.recuperability],
    ["vulnerability", weights.vulnerability],
    ["effect", weights.effect],
    ["recognizability", weights.recognizability],
  ];
  for (const [key, w] of entries) {
    sum += clamp(scores[key], 0, 10) * w;
    totalWeight += w;
  }
  return totalWeight > 0 ? sum / totalWeight : 0;
}

export function computeShockComposite(scores: ShockScores, weights: ShockWeights): number {
  let sum = 0, totalWeight = 0;
  const entries: [keyof ShockScores, number][] = [
    ["scope", weights.scope],
    ["handling", weights.handling],
    ["operationalImpact", weights.operationalImpact],
    ["cascadingEffects", weights.cascadingEffects],
    ["knowledge", weights.knowledge],
  ];
  for (const [key, w] of entries) {
    sum += clamp(scores[key], 0, 10) * w;
    totalWeight += w;
  }
  return totalWeight > 0 ? sum / totalWeight : 0;
}

export function computeMissionImpact(
  carverComposite: number,
  shockComposite: number,
  profile: ScoringProfile,
  missionMultiplier: number = 1.0
): number {
  const carverNorm = profile.carverWeight / (profile.carverWeight + profile.shockWeight);
  const shockNorm = profile.shockWeight / (profile.carverWeight + profile.shockWeight);
  const baseMissionImpact = (carverComposite * carverNorm) + (shockComposite * shockNorm);
  return clamp(baseMissionImpact * missionMultiplier, 0, 10);
}

export function applyMissionBaselines(
  carver: CarverScores,
  shock: ShockScores,
  missionFunction: string,
  essentialService?: string
): { carver: CarverScores; shock: ShockScores; missionMultiplier: number } {
  const missionBaseline = MISSION_FUNCTION_BASELINES[missionFunction];
  const serviceBaseline = essentialService ? ESSENTIAL_SERVICE_BASELINES[essentialService] : undefined;

  let adjustedCarver = { ...carver };
  let adjustedShock = { ...shock };
  let missionMultiplier = 1.0;

  if (missionBaseline) {
    missionMultiplier = missionBaseline.missionMultiplier;
    for (const [key, val] of Object.entries(missionBaseline.carver)) {
      const k = key as keyof CarverScores;
      adjustedCarver[k] = Math.max(adjustedCarver[k], val as number);
    }
    for (const [key, val] of Object.entries(missionBaseline.shock)) {
      const k = key as keyof ShockScores;
      adjustedShock[k] = Math.max(adjustedShock[k], val as number);
    }
  }

  if (serviceBaseline) {
    for (const [key, val] of Object.entries(serviceBaseline.carver)) {
      const k = key as keyof CarverScores;
      adjustedCarver[k] = Math.max(adjustedCarver[k], val as number);
    }
    for (const [key, val] of Object.entries(serviceBaseline.shock)) {
      const k = key as keyof ShockScores;
      adjustedShock[k] = Math.max(adjustedShock[k], val as number);
    }
  }

  return { carver: adjustedCarver, shock: adjustedShock, missionMultiplier };
}

export function businessImpactToMultiplier(level: string): number {
  switch (level) {
    case "mission_critical": return 1.8;
    case "business_essential": return 1.4;
    case "operational": return 1.1;
    case "administrative": return 0.8;
    default: return 1.0;
  }
}

/**
 * Compute the full hybrid risk score using the Impact × Likelihood model.
 *
 * Now enhanced with:
 *   - CVSS v4.0 vector parsing and CARVER feed-through
 *   - FIPS 199 security categorization integration
 *   - Criticality tier floor enforcement
 *
 * IMPACT (0-1): Derived from CARVER+Shock mission impact with mission function weighting.
 * LIKELIHOOD (0-1): Driven by confirmed vulnerability evidence, exposure, and port risk.
 * RISK = sqrt(Impact × Likelihood) × 100
 */
export function computeHybridRisk(input: ScoringInput, profile: ScoringProfile): ScoringResult {
  let missionMult = input.missionMultiplier ?? 1.0;
  if (!input.missionMultiplier && input.businessImpactLevel) {
    missionMult = businessImpactToMultiplier(input.businessImpactLevel);
  }

  let carver = { ...input.carver };
  let shock = { ...input.shock };
  let cvssV4Parsed: CvssV4Parsed | undefined;
  let cvssCarverAdjustments: Partial<CarverScores> | undefined;
  let fips199Applied: Fips199Category | undefined;
  let criticalityTierApplied: CriticalityTier | undefined;

  // ── CVSS v4.0 Feed-Through ──
  if (input.cvssV4Vector) {
    cvssV4Parsed = parseCvssV4Vector(input.cvssV4Vector) ?? undefined;
    if (cvssV4Parsed) {
      const { carverAdjustments, shockAdjustments } = cvssV4ToCarverAdjustments(cvssV4Parsed);
      cvssCarverAdjustments = carverAdjustments;
      // Apply as floors (never lower existing scores)
      for (const [key, val] of Object.entries(carverAdjustments)) {
        const k = key as keyof CarverScores;
        carver[k] = Math.max(carver[k], val as number);
      }
      for (const [key, val] of Object.entries(shockAdjustments)) {
        const k = key as keyof ShockScores;
        shock[k] = Math.max(shock[k], val as number);
      }
    }
  }

  // ── FIPS 199 Integration ──
  if (input.fips199) {
    fips199Applied = input.fips199;
    const fipsResult = fips199ToCarverAdjustments(input.fips199);
    for (const [key, val] of Object.entries(fipsResult.carverAdjustments)) {
      const k = key as keyof CarverScores;
      carver[k] = Math.max(carver[k], val as number);
    }
    for (const [key, val] of Object.entries(fipsResult.shockAdjustments)) {
      const k = key as keyof ShockScores;
      shock[k] = Math.max(shock[k], val as number);
    }
    missionMult = Math.max(missionMult, fipsResult.missionMultiplier);
  }

  // ── Criticality Tier Floors ──
  if (input.criticalityTier) {
    criticalityTierApplied = input.criticalityTier;
    const tierResult = applyCriticalityTierFloors(carver, shock, input.criticalityTier);
    carver = tierResult.carver;
    shock = tierResult.shock;
    missionMult = Math.max(missionMult, tierResult.missionMultiplier);
  }

  // ── Core Computation ──
  const carverComposite = computeCarverComposite(carver, profile.carverWeights);
  const shockComposite = computeShockComposite(shock, profile.shockWeights);
  const missionImpact = computeMissionImpact(carverComposite, shockComposite, profile, missionMult);

  const impact = clamp(missionImpact / 10, 0, 1);

  // Likelihood computation
  let likelihoodBase: number;
  if (input.confirmedVulnScore !== undefined && input.confirmedVulnScore > 0) {
    const vulnNorm = clamp(input.confirmedVulnScore / 100, 0, 1);
    likelihoodBase = vulnNorm;
    likelihoodBase += (input.exposure - 0.5) * 0.2;
    likelihoodBase += (clamp(carver.recognizability / 10, 0, 1) - 0.5) * 0.1;
  } else if (input.confirmedVulnScore === 0) {
    likelihoodBase = clamp((input.exposure * 0.1) + (clamp(carver.recognizability / 10, 0, 1) * 0.05), 0, 0.15);
  } else {
    // "Innocent until proven guilty" — no confirmed vulnerability data available.
    // CVSS estimates (LLM or v4.0 vector) are advisory only and do NOT inflate the score.
    // Assets stay GREEN until corroborated evidence (confirmed/probable findings) arrives.
    // Use the same low-baseline formula as confirmedVulnScore === 0.
    likelihoodBase = clamp((input.exposure * 0.1) + (clamp(carver.recognizability / 10, 0, 1) * 0.05), 0, 0.15);
  }
  likelihoodBase = clamp(likelihoodBase, 0, 1);

  if (input.portLikelihoodBoost && input.portLikelihoodBoost > 0) {
    likelihoodBase = clamp(likelihoodBase + input.portLikelihoodBoost, 0, 1);
  }

  const confidenceDampening = 0.55 + (input.confidence * 0.45);
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);

  const hybridRiskScore = Math.round(Math.sqrt(impact * likelihood) * 100);

  let riskBand: "critical" | "high" | "medium" | "low";
  if (hybridRiskScore >= profile.criticalThreshold) riskBand = "critical";
  else if (hybridRiskScore >= profile.highThreshold) riskBand = "high";
  else if (hybridRiskScore >= profile.mediumThreshold) riskBand = "medium";
  else riskBand = "low";

  const factorContributions = [
    ...Object.entries(profile.carverWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "CARVER" as const,
      rawScore: (carver as any)[key] as number,
      weight,
      weightedScore: ((carver as any)[key] as number) * weight,
    })),
    ...Object.entries(profile.shockWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "Shock" as const,
      rawScore: (shock as any)[key] as number,
      weight,
      weightedScore: ((shock as any)[key] as number) * weight,
    })),
  ];

  return {
    carverComposite: Math.round(carverComposite * 100) / 100,
    shockComposite: Math.round(shockComposite * 100) / 100,
    missionImpactScore: Math.round(missionImpact * 100) / 100,
    impactScore: Math.round(impact * 100),
    likelihoodScore: Math.round(likelihood * 100),
    hybridRiskScore,
    riskBand,
    factorContributions,
    cvssV4Parsed,
    cvssCarverAdjustments,
    fips199Applied,
    criticalityTierApplied,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §11 — LLM ASSET CLASSIFICATION (Enhanced)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Enhanced LLM asset classification with:
 *   - Device type → Platform type → Mission function inference chain
 *   - FIPS 199 security categorization
 *   - Criticality tier assignment (1-5)
 *   - CARVER+Shock factor suggestions based on classification
 */
export async function classifyAssets(
  assets: Array<{
    assetId: string;
    hostname: string;
    assetType: string;
    assetClasses?: string[];
    tags?: string[];
    technologies?: any[];
    description?: string;
    url?: string;
  }>,
  orgContext: {
    name: string;
    sector: string;
    criticalFunctions: string[];
    complianceFlags: string[];
  }
): Promise<Map<string, AssetClassification>> {
  if (assets.length === 0) return new Map();

  const prompt = `You are an IT asset classification specialist trained on NIST SP 800-60, FIPS 199, and organizational mission function mapping. Classify each discovered asset using a three-step inference chain:

STEP 1: Identify DEVICE TYPE from hostname, services, and technology fingerprints
STEP 2: Infer PLATFORM TYPE from device type and detected technologies
STEP 3: Map to MISSION FUNCTION based on platform type and organizational context

ORGANIZATION CONTEXT:
- Name: ${orgContext.name}
- Sector: ${orgContext.sector}
- Critical Functions: ${orgContext.criticalFunctions.join(", ")}
- Compliance Requirements: ${orgContext.complianceFlags.join(", ") || "none specified"}

CLASSIFICATION TAXONOMY:

Device Types: ${ASSET_DEVICE_TYPES.filter(t => t !== "unknown").join(", ")}
Platform Types: ${ASSET_PLATFORM_TYPES.filter(t => t !== "unknown").join(", ")}
Mission Functions: ${MISSION_FUNCTIONS.join(", ")}
Essential Services: ${ESSENTIAL_SERVICES.join(", ")}
Business Impact Levels: ${BUSINESS_IMPACT_LEVELS.join(", ")}

FIPS 199 Security Categories (for each of Confidentiality, Integrity, Availability):
- high: Loss would have severe/catastrophic adverse effect
- moderate: Loss would have serious adverse effect
- low: Loss would have limited adverse effect

Criticality Tiers:
- 1 (Mission Critical): < 1 hour RTO, immediate operational impact
- 2 (Business Critical): 1-24 hour RTO, significant impact within hours
- 3 (Business Important): 1-7 day RTO, moderate impact within days
- 4 (Administrative): > 7 day RTO, minimal impact
- 5 (Non-Essential): No operational impact

ASSETS TO CLASSIFY (${assets.length}):
${JSON.stringify(assets.map(a => ({
  id: a.assetId,
  hostname: a.hostname,
  type: a.assetType,
  classes: a.assetClasses,
  tags: a.tags,
  tech: a.technologies?.slice(0, 5),
  desc: a.description?.slice(0, 200),
  url: a.url,
})), null, 2)}

For EACH asset, return:
1. deviceType, platformType, missionFunction, essentialService
2. assetPurpose: 1-2 sentence description of what this asset does for the organization
3. businessImpactLevel: mission_critical | business_essential | operational | administrative
4. fips199Category: { confidentiality: "low"|"moderate"|"high", integrity: "low"|"moderate"|"high", availability: "low"|"moderate"|"high" }
5. criticalityTier: 1-5 based on RTO analysis
6. missionDependencies: { upstreamAssets: [], downstreamAssets: [], sharedServices: [] }
7. carverAdjustments: Specific CARVER factor scores (0-10) based on your classification
8. shockAdjustments: Specific Shock factor scores (0-10) based on your classification
9. classificationConfidence: 0-1
10. reasoning: Brief explanation including your inference chain (device → platform → mission)

CALIBRATION RULES:
- Only 5-10% of assets should be mission_critical / Tier 1
- Consider the organization's sector when assessing impact
- CDNs, static sites, and marketing pages are almost always administrative / Tier 4-5
- Domain controllers, SSO, and payment gateways are almost always Tier 1
- APIs and databases are typically Tier 2 unless storing critical data

Return JSON: { "classifications": [ { "assetId": "...", ... } ] }`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are an IT asset classification specialist. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) return new Map();
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);

    let parsed: any;
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) parsed = JSON.parse(match[1]);
      else return new Map();
    }

    const result = new Map<string, AssetClassification>();
    for (const c of (parsed.classifications || [])) {
      result.set(c.assetId, {
        deviceType: c.deviceType || "unknown",
        platformType: c.platformType || "unknown",
        missionFunction: c.missionFunction || "operational_continuity",
        essentialService: c.essentialService || "unknown",
        assetPurpose: c.assetPurpose || "",
        businessImpactLevel: c.businessImpactLevel || "operational",
        fips199Category: c.fips199Category || undefined,
        criticalityTier: c.criticalityTier ? clamp(c.criticalityTier, 1, 5) as CriticalityTier : undefined,
        missionDependencies: c.missionDependencies || { upstreamAssets: [], downstreamAssets: [], sharedServices: [] },
        carverAdjustments: c.carverAdjustments || {},
        shockAdjustments: c.shockAdjustments || {},
        classificationConfidence: clamp(c.classificationConfidence || 0.5, 0, 1),
        reasoning: c.reasoning || "",
      });
    }
    return result;
  } catch (err: any) {
    console.error(`[ScoringEngine] Asset classification failed: ${err.message}`);
    return new Map();
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §12 — DYNAMIC RE-SCORING
// ═══════════════════════════════════════════════════════════════════════

export type RescoringTrigger =
  | "new_cve_discovered"
  | "new_port_service"
  | "vuln_scan_complete"
  | "network_position_change"
  | "bug_bounty_correlation"
  | "threat_actor_ttp_match"
  | "llm_reclassification"
  | "manual_override"
  | "profile_change"
  | "initial_scan"
  | "cvss_v4_vector_added"
  | "fips199_categorized"
  | "criticality_tier_assigned"
  | "kev_match"
  | "darkweb_exposure";

export interface RescoringEvent {
  trigger: RescoringTrigger;
  assetId: string;
  previousScore: number;
  newScore: number;
  previousBand: string;
  newBand: string;
  delta: number;
  changeDescription: string;
  factorChanges: Array<{
    factor: string;
    previousValue: number;
    newValue: number;
    reason: string;
  }>;
  timestamp: number;
}

/**
 * Discovery phase triggers and their CARVER/Shock adjustments.
 * These define how new intelligence gathered during discovery
 * automatically adjusts scoring factors.
 */
export const DISCOVERY_PHASE_TRIGGERS: Record<string, {
  description: string;
  carverAdjustments: (data: any) => Partial<CarverScores>;
  shockAdjustments: (data: any) => Partial<ShockScores>;
  likelihoodBoost: (data: any) => number;
}> = {
  new_cve_discovered: {
    description: "New CVE discovered during vulnerability scanning",
    carverAdjustments: (data: { cvssScore?: number; exploitAvailable?: boolean; kevListed?: boolean }) => ({
      vulnerability: data.kevListed ? 10 : data.exploitAvailable ? 8 : Math.min(10, Math.round((data.cvssScore ?? 5) * 1.2)),
    }),
    shockAdjustments: () => ({}),
    likelihoodBoost: (data: { cvssScore?: number; exploitAvailable?: boolean }) =>
      data.exploitAvailable ? 0.25 : (data.cvssScore ?? 5) > 7 ? 0.15 : 0.05,
  },
  new_port_service: {
    description: "New port/service discovered during enumeration",
    carverAdjustments: (data: { isHighRiskPort?: boolean; serviceVersion?: string }) => ({
      accessibility: data.isHighRiskPort ? 8 : 6,
      recognizability: data.serviceVersion ? 7 : 5,
    }),
    shockAdjustments: () => ({}),
    likelihoodBoost: (data: { isHighRiskPort?: boolean }) => data.isHighRiskPort ? 0.1 : 0.03,
  },
  kev_match: {
    description: "Asset vulnerability matches CISA Known Exploited Vulnerabilities catalog",
    carverAdjustments: () => ({
      vulnerability: 10,
      recognizability: 8,
    }),
    shockAdjustments: () => ({
      scope: 7,
      handling: 7,
    }),
    likelihoodBoost: () => 0.3,
  },
  darkweb_exposure: {
    description: "Asset credentials or data found on dark web marketplaces",
    carverAdjustments: (data: { dataType?: string }) => ({
      accessibility: 9,
      vulnerability: 8,
      recognizability: 9,
    }),
    shockAdjustments: (data: { dataType?: string }) => ({
      scope: data.dataType === "credentials" ? 8 : 6,
      handling: 8,
    }),
    likelihoodBoost: () => 0.25,
  },
  threat_actor_ttp_match: {
    description: "Asset matches known threat actor TTP targeting patterns",
    carverAdjustments: (data: { sophistication?: string }) => ({
      vulnerability: data.sophistication === "apt" ? 7 : 5,
    }),
    shockAdjustments: (data: { sophistication?: string }) => ({
      knowledge: data.sophistication === "apt" ? 3 : 6,
    }),
    likelihoodBoost: (data: { sophistication?: string }) => data.sophistication === "apt" ? 0.2 : 0.1,
  },
};

/**
 * Apply a discovery phase trigger to generate CARVER/Shock adjustments.
 */
export function applyDiscoveryTrigger(
  triggerType: string,
  triggerData: any,
  currentCarver: CarverScores,
  currentShock: ShockScores
): { carver: CarverScores; shock: ShockScores; likelihoodBoost: number } {
  const trigger = DISCOVERY_PHASE_TRIGGERS[triggerType];
  if (!trigger) return { carver: currentCarver, shock: currentShock, likelihoodBoost: 0 };

  const carverAdj = trigger.carverAdjustments(triggerData);
  const shockAdj = trigger.shockAdjustments(triggerData);
  const likelihoodBoost = trigger.likelihoodBoost(triggerData);

  const adjustedCarver = { ...currentCarver };
  const adjustedShock = { ...currentShock };

  // Apply as floors (never lower)
  for (const [key, val] of Object.entries(carverAdj)) {
    const k = key as keyof CarverScores;
    adjustedCarver[k] = Math.max(adjustedCarver[k], val as number);
  }
  for (const [key, val] of Object.entries(shockAdj)) {
    const k = key as keyof ShockScores;
    adjustedShock[k] = Math.max(adjustedShock[k], val as number);
  }

  return { carver: adjustedCarver, shock: adjustedShock, likelihoodBoost };
}

export function generateRescoringEvent(
  trigger: RescoringTrigger,
  assetId: string,
  previousResult: ScoringResult,
  newResult: ScoringResult,
  changeDescription: string,
  factorChanges: RescoringEvent["factorChanges"]
): RescoringEvent {
  return {
    trigger,
    assetId,
    previousScore: previousResult.hybridRiskScore,
    newScore: newResult.hybridRiskScore,
    previousBand: previousResult.riskBand,
    newBand: newResult.riskBand,
    delta: newResult.hybridRiskScore - previousResult.hybridRiskScore,
    changeDescription,
    factorChanges,
    timestamp: Date.now(),
  };
}

export function isSignificantChange(event: RescoringEvent): boolean {
  if (event.previousBand !== event.newBand) return true;
  if (Math.abs(event.delta) >= 15) return true;
  if (event.newBand === "critical" && event.previousBand !== "critical") return true;
  return false;
}

// ═══════════════════════════════════════════════════════════════════════
// §13 — UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

export function dbProfileToScoringProfile(row: any): ScoringProfile {
  return {
    carverWeights: {
      criticality: row.wCriticality ?? 2.0,
      accessibility: row.wAccessibility ?? 1.5,
      recuperability: row.wRecuperability ?? 1.0,
      vulnerability: row.wVulnerability ?? 1.5,
      effect: row.wEffect ?? 1.5,
      recognizability: row.wRecognizability ?? 0.5,
    },
    shockWeights: {
      scope: row.wScope ?? 1.5,
      handling: row.wHandling ?? 1.0,
      operationalImpact: row.wOperationalImpact ?? 2.0,
      cascadingEffects: row.wCascadingEffects ?? 1.5,
      knowledge: row.wKnowledge ?? 1.0,
    },
    carverWeight: row.carverWeight ?? 0.4,
    shockWeight: row.shockWeight ?? 0.3,
    cvssWeight: row.cvssWeight ?? 0.3,
    criticalThreshold: row.criticalThreshold ?? 85,
    highThreshold: row.highThreshold ?? 65,
    mediumThreshold: row.mediumThreshold ?? 40,
  };
}

export function riskScoreToHeatColor(score: number): string {
  const clamped = clamp(score, 0, 100);
  const hue = Math.round(120 * (1 - clamped / 100));
  const saturation = 70 + Math.round(30 * (clamped / 100));
  const lightness = 50 - Math.round(10 * (clamped / 100));
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}

export function generateHeatMapData(
  assets: Array<{
    assetId: string;
    hostname: string;
    hybridRiskScore: number;
    riskBand: string;
    missionFunction?: string;
    businessImpactLevel?: string;
    carverScores?: CarverScores;
    shockScores?: ShockScores;
  }>
): Array<{
  assetId: string;
  hostname: string;
  score: number;
  band: string;
  color: string;
  missionFunction: string;
  businessImpactLevel: string;
  intensity: number;
}> {
  return assets.map(a => ({
    assetId: a.assetId,
    hostname: a.hostname,
    score: a.hybridRiskScore,
    band: a.riskBand,
    color: riskScoreToHeatColor(a.hybridRiskScore),
    missionFunction: a.missionFunction || "unknown",
    businessImpactLevel: a.businessImpactLevel || "operational",
    intensity: clamp(a.hybridRiskScore / 100, 0, 1),
  }));
}
