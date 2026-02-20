/**
 * CARVER+Shock / CVSS Hybrid Adaptive Scoring Engine
 * ───────────────────────────────────────────────────
 * Production-grade scoring module that translates military CARVER+Shock
 * targeting methodology to digital asset criticality assessment, combined
 * with CVSS vulnerability scoring and LLM-based asset classification.
 *
 * Key capabilities:
 *   - CARVER factors mapped to digital asset context with mission-essential function weighting
 *   - Shock factors adapted for cyber impact (regulatory, reputational, operational)
 *   - LLM-based asset classification infers mission function, essential service, and business impact
 *   - Dynamic re-scoring as new intelligence emerges during discovery/enumeration
 *   - Profile-aware: adjustable factor weights per engagement objective
 *   - Audit trail: every scoring decision is logged with reasoning
 *
 * Patent-pending: CARVER+Shock/CVSS Hybrid Risk Scoring Pipeline
 * Created by Harrison Cook
 */

import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────

export interface CarverScores {
  criticality: number;    // 0-10: How critical is the asset to mission success?
  accessibility: number;  // 0-10: How accessible is the asset to an attacker?
  recuperability: number; // 0-10: How long to restore the asset after attack?
  vulnerability: number;  // 0-10: How vulnerable is the asset to known attacks?
  effect: number;         // 0-10: What is the effect of a successful attack?
  recognizability: number;// 0-10: How easily can the asset be identified?
}

export interface ShockScores {
  scope: number;             // 0-10: How wide is the blast radius?
  handling: number;          // 0-10: How difficult is incident response?
  operationalImpact: number; // 0-10: How much does it disrupt operations?
  cascadingEffects: number;  // 0-10: Does failure cascade to other systems?
  knowledge: number;         // 0-10: How much specialized knowledge is needed?
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
  /** How much CARVER contributes to the final composite (0-1) */
  carverWeight: number;
  /** How much Shock contributes to the final composite (0-1) */
  shockWeight: number;
  /** How much CVSS contributes to the final composite (0-1) */
  cvssWeight: number;
  /** Risk band thresholds */
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
}

export interface ScoringInput {
  carver: CarverScores;
  shock: ShockScores;
  cvssEstimate: number; // 0-10
  exposure: number;     // 0-1 (how exposed is the asset to the internet)
  confidence: number;   // 0-1 (confidence in the assessment)
  confirmedVulnScore?: number; // 0-100 from vuln enrichment
  portLikelihoodBoost?: number; // 0-0.3 from port risk analysis
  /** Mission function multiplier — boosts impact for mission-critical assets */
  missionMultiplier?: number; // 0.5-2.0 (default 1.0)
  /** Business impact level from LLM classification */
  businessImpactLevel?: "mission_critical" | "business_essential" | "operational" | "administrative";
}

export interface ScoringResult {
  /** Weighted CARVER composite (0-10) */
  carverComposite: number;
  /** Weighted Shock composite (0-10) */
  shockComposite: number;
  /** Mission impact score (0-10) — blended CARVER + Shock */
  missionImpactScore: number;
  /** Impact dimension (0-100) — normalized mission impact */
  impactScore: number;
  /** Likelihood dimension (0-100) — driven by confirmed vulns + exposure */
  likelihoodScore: number;
  /** Final hybrid risk score (0-100) */
  hybridRiskScore: number;
  /** Risk band label */
  riskBand: "critical" | "high" | "medium" | "low";
  /** Individual factor contributions for radar chart visualization */
  factorContributions: {
    factor: string;
    category: "CARVER" | "Shock";
    rawScore: number;
    weight: number;
    weightedScore: number;
  }[];
}

// ─── Asset Classification Types ─────────────────────────────────────────

/** IT asset classification taxonomy for LLM inference */
export const ASSET_DEVICE_TYPES = [
  "network_infrastructure", // Routers, switches, firewalls, load balancers, WAFs
  "server",                 // Web servers, app servers, database servers, file servers, mail servers
  "endpoint",               // Workstations, laptops, mobile devices, IoT
  "security_appliance",     // IDS/IPS, SIEM, DLP, NAC
  "storage",                // SAN, NAS, backup systems, cloud storage
  "cloud_service",          // SaaS, PaaS, IaaS instances
  "iot_ot",                 // Industrial control systems, SCADA, IoT sensors
  "unknown",
] as const;

export const ASSET_PLATFORM_TYPES = [
  "identity_access",        // Active Directory, LDAP, SSO, MFA providers
  "business_critical",      // ERP, CRM, HRM, financial systems, payment gateways
  "communication",          // Email, VoIP, messaging, video conferencing
  "development",            // CI/CD, source control, container orchestration
  "data_store",             // Databases, data warehouses, data lakes, caches
  "web_application",        // Customer-facing web apps, portals, APIs
  "monitoring",             // APM, logging, metrics, alerting
  "content_delivery",       // CDN, static hosting, media streaming
  "unknown",
] as const;

export const MISSION_FUNCTIONS = [
  "command_control",        // Assets enabling organizational decision-making
  "revenue_generation",     // Assets directly involved in generating revenue
  "customer_data",          // Assets storing or processing customer information
  "intellectual_property",  // Assets containing proprietary information
  "operational_continuity", // Assets required for day-to-day operations
  "compliance",             // Assets required for regulatory compliance
  "external_communication", // Assets enabling external stakeholder communication
  "authentication",         // Identity and access management
  "data_processing",        // Data transformation, analytics, reporting
  "supply_chain",           // Vendor/partner integration systems
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
  "mission_critical",    // Loss causes >75% business function disruption
  "business_essential",  // Loss causes 40-75% disruption
  "operational",         // Loss causes 10-40% disruption
  "administrative",      // Loss causes <10% disruption
] as const;

export interface AssetClassification {
  deviceType: typeof ASSET_DEVICE_TYPES[number];
  platformType: typeof ASSET_PLATFORM_TYPES[number];
  missionFunction: typeof MISSION_FUNCTIONS[number];
  essentialService: string;
  assetPurpose: string;
  businessImpactLevel: typeof BUSINESS_IMPACT_LEVELS[number];
  missionDependencies: {
    upstreamAssets: string[];
    downstreamAssets: string[];
    sharedServices: string[];
  };
  /** CARVER factor adjustments based on classification */
  carverAdjustments: Partial<CarverScores>;
  /** Shock factor adjustments based on classification */
  shockAdjustments: Partial<ShockScores>;
  /** Confidence in this classification (0-1) */
  classificationConfidence: number;
  /** Reasoning for the classification */
  reasoning: string;
}

// ─── Mission Function → CARVER/Shock Baseline Mappings ──────────────────

/**
 * Baseline CARVER+Shock score adjustments based on mission function.
 * These represent the "floor" scores for assets in each category —
 * the LLM and discovery data can only increase these, not decrease.
 *
 * This is the key innovation: military CARVER targeting methodology
 * translated to digital asset criticality through organizational
 * mission function mapping.
 */
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

/**
 * Essential service → baseline CARVER adjustments.
 * These provide granular scoring based on the specific service type.
 */
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

// ─── Default Profile ────────────────────────────────────────────────────

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

// ─── Preset Profiles ───────────────────────────────────────────────────

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
};

// ─── Core Scoring Functions ─────────────────────────────────────────────

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

/**
 * Compute the weighted CARVER composite score.
 * Each factor is weighted according to the engagement profile.
 */
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

/**
 * Compute the weighted Shock composite score.
 * Shock measures the broader organizational and societal impact.
 */
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

/**
 * Compute mission impact from CARVER and Shock composites using meta-weights.
 * Applies mission function multiplier for assets classified as mission-critical.
 */
export function computeMissionImpact(
  carverComposite: number,
  shockComposite: number,
  profile: ScoringProfile,
  missionMultiplier: number = 1.0
): number {
  const carverNorm = profile.carverWeight / (profile.carverWeight + profile.shockWeight);
  const shockNorm = profile.shockWeight / (profile.carverWeight + profile.shockWeight);
  const baseMissionImpact = (carverComposite * carverNorm) + (shockComposite * shockNorm);
  // Apply mission function multiplier — caps at 10
  return clamp(baseMissionImpact * missionMultiplier, 0, 10);
}

/**
 * Apply mission function baselines to CARVER and Shock scores.
 * Baselines act as floors — they raise scores but never lower them.
 * This ensures that an SSO system is never scored lower than its
 * mission-critical baseline, regardless of what the LLM initially estimated.
 */
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

  // Apply mission function baselines (floors)
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

  // Apply essential service baselines (additional floors)
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

/**
 * Business impact level → mission multiplier mapping.
 * Used when LLM classification provides a business impact level.
 */
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
 * Compute the full hybrid risk score using the Impact x Likelihood model.
 *
 * IMPACT (0-1): Derived from CARVER+Shock mission impact with mission function weighting.
 * LIKELIHOOD (0-1): Driven by confirmed vulnerability evidence, exposure, and port risk.
 * RISK = sqrt(Impact x Likelihood) x 100
 *
 * The geometric mean ensures both dimensions must be elevated for high risk:
 *   - Critical asset with no confirmed vulns → score ~30 (low)
 *   - Low-importance asset with confirmed CVEs → score ~52 (medium)
 *   - Critical asset with confirmed CVEs → score ~90 (critical)
 */
export function computeHybridRisk(input: ScoringInput, profile: ScoringProfile): ScoringResult {
  // Determine mission multiplier from business impact level or explicit multiplier
  let missionMult = input.missionMultiplier ?? 1.0;
  if (!input.missionMultiplier && input.businessImpactLevel) {
    missionMult = businessImpactToMultiplier(input.businessImpactLevel);
  }

  const carverComposite = computeCarverComposite(input.carver, profile.carverWeights);
  const shockComposite = computeShockComposite(input.shock, profile.shockWeights);
  const missionImpact = computeMissionImpact(carverComposite, shockComposite, profile, missionMult);

  // Impact: normalized mission impact (0-1)
  const impact = clamp(missionImpact / 10, 0, 1);

  // Likelihood: driven by confirmed vulnerability evidence
  let likelihoodBase: number;
  if (input.confirmedVulnScore !== undefined && input.confirmedVulnScore > 0) {
    const vulnNorm = clamp(input.confirmedVulnScore / 100, 0, 1);
    likelihoodBase = vulnNorm;
    likelihoodBase += (input.exposure - 0.5) * 0.2;
    likelihoodBase += (clamp(input.carver.recognizability / 10, 0, 1) - 0.5) * 0.1;
  } else if (input.confirmedVulnScore === 0) {
    // No confirmed vulns — baseline from exposure only
    likelihoodBase = clamp((input.exposure * 0.1) + (clamp(input.carver.recognizability / 10, 0, 1) * 0.05), 0, 0.15);
  } else {
    // Pre-enrichment: use CVSS estimate as placeholder
    const cvssNorm = clamp(input.cvssEstimate / 10, 0, 1);
    likelihoodBase = cvssNorm;
    likelihoodBase += (input.exposure - 0.5) * 0.2;
    likelihoodBase += (clamp(input.carver.recognizability / 10, 0, 1) - 0.5) * 0.1;
  }
  likelihoodBase = clamp(likelihoodBase, 0, 1);

  // Port exposure boost
  if (input.portLikelihoodBoost && input.portLikelihoodBoost > 0) {
    likelihoodBase = clamp(likelihoodBase + input.portLikelihoodBoost, 0, 1);
  }

  // Confidence dampening: low-confidence assessments reduce likelihood
  const confidenceDampening = 0.55 + (input.confidence * 0.45);
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);

  // Hybrid risk = geometric mean of Impact and Likelihood
  const hybridRiskScore = Math.round(Math.sqrt(impact * likelihood) * 100);

  // Risk band
  let riskBand: "critical" | "high" | "medium" | "low";
  if (hybridRiskScore >= profile.criticalThreshold) riskBand = "critical";
  else if (hybridRiskScore >= profile.highThreshold) riskBand = "high";
  else if (hybridRiskScore >= profile.mediumThreshold) riskBand = "medium";
  else riskBand = "low";

  // Factor contributions for visualization
  const factorContributions = [
    ...Object.entries(profile.carverWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "CARVER" as const,
      rawScore: (input.carver as any)[key] as number,
      weight,
      weightedScore: ((input.carver as any)[key] as number) * weight,
    })),
    ...Object.entries(profile.shockWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "Shock" as const,
      rawScore: (input.shock as any)[key] as number,
      weight,
      weightedScore: ((input.shock as any)[key] as number) * weight,
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
  };
}

// ─── LLM Asset Classification ──────────────────────────────────────────

/**
 * Use LLM to classify discovered assets by mission function, essential service,
 * business impact level, and inter-asset dependencies.
 *
 * The LLM is trained on IT asset classification taxonomies including:
 * - Device types (network infrastructure, servers, endpoints, security appliances, storage, cloud, IoT/OT)
 * - Platform types (identity/access, business critical, communication, development, data stores)
 * - Mission functions (C2, revenue, customer data, IP, ops continuity, compliance, auth)
 * - Essential services (SSO, AD, payment, email, VPN, DNS, DB, API gateway, etc.)
 *
 * Returns classification with CARVER/Shock adjustments and reasoning.
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

  const prompt = `You are an IT asset classification specialist. Classify each discovered asset based on its role in the organization's mission.

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

For EACH asset, determine:
1. deviceType: The physical/virtual device category
2. platformType: The application/platform category
3. missionFunction: Which organizational mission this asset supports (pick the PRIMARY one)
4. essentialService: The specific service this asset provides (from the list, or a custom short name)
5. assetPurpose: A 1-2 sentence description of what this asset does for the organization
6. businessImpactLevel: How severe would loss of this asset be?
   - mission_critical: Loss causes >75% business function disruption (e.g., AD, primary DB, payment gateway)
   - business_essential: Loss causes 40-75% disruption (e.g., email, VPN, CRM)
   - operational: Loss causes 10-40% disruption (e.g., monitoring, CI/CD, dev tools)
   - administrative: Loss causes <10% disruption (e.g., static sites, CDN, test environments)
7. missionDependencies: What other assets/services does this depend on or feed into?
8. carverAdjustments: Specific CARVER factor adjustments (0-10) based on your classification. Only include factors you want to adjust.
9. shockAdjustments: Specific Shock factor adjustments (0-10) based on your classification. Only include factors you want to adjust.
10. classificationConfidence: 0-1 confidence in your classification
11. reasoning: Brief explanation of why you classified it this way

CALIBRATION RULES:
- Only 5-10% of assets should be mission_critical. Most should be operational or administrative.
- Consider the organization's sector when assessing impact (healthcare → patient data is mission_critical)
- CDNs, static sites, and marketing pages are almost always administrative
- APIs and SSO are typically business_essential or higher
- Databases are business_essential unless they store critical customer/financial data

Return JSON: { "classifications": [ { "assetId": "...", "deviceType": "...", ... } ] }`;

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
      // Try to extract JSON from markdown code blocks
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

// ─── Dynamic Re-scoring ────────────────────────────────────────────────

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
  | "initial_scan";

export interface RescoringEvent {
  trigger: RescoringTrigger;
  assetId: string;
  previousScore: number;
  newScore: number;
  previousBand: string;
  newBand: string;
  delta: number;
  /** What changed that triggered the re-score */
  changeDescription: string;
  /** Factor-level changes */
  factorChanges: Array<{
    factor: string;
    previousValue: number;
    newValue: number;
    reason: string;
  }>;
  timestamp: number;
}

/**
 * Compute score delta and generate a re-scoring event.
 * This is called whenever new intelligence triggers a re-evaluation.
 */
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

/**
 * Determine if a re-scoring event is significant enough to warrant notification.
 * Significant events: band change, score delta > 15, or critical threshold crossed.
 */
export function isSignificantChange(event: RescoringEvent): boolean {
  if (event.previousBand !== event.newBand) return true;
  if (Math.abs(event.delta) >= 15) return true;
  if (event.newBand === "critical" && event.previousBand !== "critical") return true;
  return false;
}

// ─── Utility Functions ──────────────────────────────────────────────────

/**
 * Convert a DB scoring profile row to a ScoringProfile object.
 */
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

/**
 * Generate a heat map color for a given risk score (0-100).
 * Returns an HSL color string: green (low) → yellow (medium) → red (critical).
 */
export function riskScoreToHeatColor(score: number): string {
  const clamped = clamp(score, 0, 100);
  // Map 0-100 to hue 120 (green) → 0 (red)
  const hue = Math.round(120 * (1 - clamped / 100));
  const saturation = 70 + Math.round(30 * (clamped / 100)); // More saturated at higher risk
  const lightness = 50 - Math.round(10 * (clamped / 100)); // Darker at higher risk
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}

/**
 * Generate heat map data for attack path visualization overlay.
 * Groups assets by risk band and provides color-coded coordinates.
 */
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
  /** Normalized intensity for heat map rendering (0-1) */
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
