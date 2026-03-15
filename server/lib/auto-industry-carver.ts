/**
 * Auto-Industry CARVER Module (v1 + v2)
 * ──────────────────────────────────────
 * Integrates the AC3 Auto Industry + CARVER Hybrid Module packages:
 *
 * v1: Industry detection, CARVER+SHOCK presets, regulatory overlays,
 *     hybrid fusion formula, auto-BIA asset priority
 * v2: NAICS auto-mapping with multi-stage inference, threat actor likelihood,
 *     FedRAMP Moderate/High profiles, explainable risk cards,
 *     Cyber C2 operation prioritization tiers + ability set library
 *
 * Integration points:
 *   1) Industry/Sector inference → sector tag + confidence
 *   2) NAICS inference → primary_naics + candidates
 *   3) CARVER+SHOCK preset + regulatory overlays (FedRAMP/CMMC/NERC)
 *   4) Hybrid score fusion (CARVER + CVSS/EPSS/KEV optional)
 *   5) Explainable risk card emission for UI + reporting
 *   6) Caldera tier selection + ability-set recommendations
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — SECTOR & NAICS TYPES
// ═══════════════════════════════════════════════════════════════════════

export type CarverSector =
  | "banking_financial_services"
  | "healthcare_providers"
  | "pharmaceuticals_biotech"
  | "defense_aerospace"
  | "electric_gas_utilities"
  | "federal_government"
  | "saas_tech";

export type RegulatoryFramework =
  | "GLBA" | "SOX" | "FFIEC"
  | "CMMC" | "ITAR" | "DFARS"
  | "NERC_CIP"
  | "HIPAA" | "HITECH"
  | "FISMA" | "FedRAMP"
  | "GxP" | "FDA";

export type PriorityTier = "P0" | "P1" | "P2" | "P3";

export type ThreatCategory =
  | "ransomware_ecrime"
  | "financial_fraud_bec"
  | "apt_state_espionage"
  | "apt_state_disruption"
  | "ddos_extortion"
  | "insider_threat"
  | "supply_chain"
  | "data_extortion"
  | "credential_stuffing"
  | "abuse_of_apis"
  | "ot_intrusion"
  | "hacktivism";

export interface NaicsCandidate {
  code: string;
  label: string;
  score: number;
}

export interface NaicsInferenceResult {
  primaryNaics: string;
  primaryLabel: string;
  candidates: NaicsCandidate[];
  confidence: number;
  confidenceBand: "high" | "medium" | "low" | "insufficient";
  evidence: {
    tlds: string[];
    keywords: string[];
    assetSignals: string[];
    sources: string[];
  };
}

export interface SectorInferenceResult {
  sector: CarverSector;
  confidence: number;
  regulatoryProfile: RegulatoryFramework[];
  naics: NaicsInferenceResult;
}

export interface CarverShockPreset {
  criticality: number;
  accessibility: number;
  recuperability: number;
  vulnerability: number;
  effect: number;
  recognizability: number;
  shock: number;
}

export interface RegulatoryOverlay {
  criticality?: number;
  accessibility?: number;
  recuperability?: number;
  vulnerability?: number;
  effect?: number;
  recognizability?: number;
  shock?: number;
}

export interface RiskCardDriver {
  driver: string;
  evidence: string[];
  impact: "increase" | "decrease";
}

export interface CalderaPriority {
  operationTier: string;
  operationProfile: string;
  objectives: string[];
  recommendedAdversaries: string[];
  recommendedAbilitySets: string[];
  notes: string[];
}

export interface ExplainableRiskCard {
  assetId: string;
  assetLabel: string;
  sector: CarverSector;
  naics: string;
  regulatoryProfile: RegulatoryFramework[];
  scores: {
    carverShock: number;
    cvss: { base: number; exploitability: number };
    hybrid: number;
    priorityTier: PriorityTier;
  };
  topDrivers: RiskCardDriver[];
  threatLikelihood: Partial<Record<ThreatCategory, number>>;
  recommendedActions: string[];
  calderaPriority: CalderaPriority;
  confidence: number;
}

export interface FedRampProfile {
  label: string;
  overlayAdjustments: RegulatoryOverlay;
  notes: string[];
  riskTierThresholds: { P0: number; P1: number; P2: number };
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — INDUSTRY DETECTION RULES (from v1 industry_detection.yaml)
// ═══════════════════════════════════════════════════════════════════════

export const INDUSTRY_DETECTION_RULES: Record<string, {
  tlds?: string[];
  keywords: string[];
  assetSignals: string[];
  regulatory: RegulatoryFramework[];
}> = {
  banking: {
    tlds: [".bank"],
    keywords: ["bank", "fdic", "credit union", "ach", "swift"],
    assetSignals: ["swift", "ach", "payment gateway"],
    regulatory: ["GLBA", "SOX", "FFIEC"],
  },
  defense: {
    tlds: [".mil"],
    keywords: ["defense", "aerospace", "missile", "itar", "dfars"],
    assetSignals: ["itar", "dfars", "dod contractor"],
    regulatory: ["CMMC", "ITAR", "DFARS"],
  },
  energy: {
    keywords: ["utility", "grid", "pipeline", "nerc", "scada"],
    assetSignals: ["modbus", "dnp3", "ics"],
    regulatory: ["NERC_CIP"],
  },
  healthcare: {
    keywords: ["hospital", "clinic", "patient", "hipaa"],
    assetSignals: ["epic", "cerner"],
    regulatory: ["HIPAA", "HITECH"],
  },
  government: {
    tlds: [".gov"],
    keywords: ["department", "agency", "public service"],
    assetSignals: ["piv", "hspd-12", "fisma"],
    regulatory: ["FISMA", "FedRAMP"],
  },
  saas: {
    keywords: ["cloud", "platform", "saas", "api"],
    assetSignals: [],
    regulatory: [],
  },
};

// Map legacy sector names to CarverSector
const LEGACY_TO_SECTOR: Record<string, CarverSector> = {
  banking: "banking_financial_services",
  defense: "defense_aerospace",
  energy: "electric_gas_utilities",
  healthcare: "healthcare_providers",
  government: "federal_government",
  saas: "saas_tech",
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — NAICS AUTO-MAPPING (from v2 naics_auto_mapping.yaml)
// ═══════════════════════════════════════════════════════════════════════

export interface NaicsSectorMapping {
  naicsCodes: Array<{ code: string; label: string }>;
  signals: {
    keywords: string[];
    tlds?: string[];
    assetSignals: string[];
  };
}

export const NAICS_AUTO_MAPPING: Record<CarverSector, NaicsSectorMapping> = {
  banking_financial_services: {
    naicsCodes: [
      { code: "522110", label: "Commercial Banking" },
      { code: "522120", label: "Savings Institutions" },
      { code: "522130", label: "Credit Unions" },
      { code: "522190", label: "Other Depository Credit Intermediation" },
      { code: "523110", label: "Investment Banking and Securities Dealing" },
      { code: "523930", label: "Investment Advice" },
    ],
    signals: {
      keywords: ["bank", "credit union", "fdic", "routing number", "wealth management", "brokerage", "securities"],
      tlds: [".bank"],
      assetSignals: ["swift", "ach", "payment gateway", "online banking", "wire transfer"],
    },
  },
  healthcare_providers: {
    naicsCodes: [
      { code: "622110", label: "General Medical and Surgical Hospitals" },
      { code: "621111", label: "Offices of Physicians" },
      { code: "621512", label: "Diagnostic Imaging Centers" },
      { code: "621610", label: "Home Health Care Services" },
    ],
    signals: {
      keywords: ["hospital", "clinic", "patient", "physician", "ehr", "hipaa", "radiology", "lab results"],
      assetSignals: ["epic", "cerner", "patient portal", "hl7", "fhir"],
    },
  },
  pharmaceuticals_biotech: {
    naicsCodes: [
      { code: "325412", label: "Pharmaceutical Preparation Manufacturing" },
      { code: "541714", label: "R&D in Biotechnology" },
    ],
    signals: {
      keywords: ["clinical trial", "biotech", "pharmaceutical", "fda", "drug", "vaccine", "gxp", "gmp"],
      assetSignals: ["ctms", "lims", "gxp", "trial portal"],
    },
  },
  defense_aerospace: {
    naicsCodes: [
      { code: "336414", label: "Guided Missile and Space Vehicle Manufacturing" },
      { code: "336411", label: "Aircraft Manufacturing" },
      { code: "541330", label: "Engineering Services (defense)" },
      { code: "541715", label: "R&D in Physical/Engineering Sciences" },
    ],
    signals: {
      keywords: ["defense", "aerospace", "mission systems", "itar", "dfars", "dod", "cmmc"],
      tlds: [".mil"],
      assetSignals: ["itar", "dfars", "dod contractor", "controlled unclassified information", "cui"],
    },
  },
  electric_gas_utilities: {
    naicsCodes: [
      { code: "221122", label: "Electric Power Distribution" },
      { code: "221121", label: "Electric Bulk Power Transmission and Control" },
      { code: "221210", label: "Natural Gas Distribution" },
      { code: "486210", label: "Pipeline Transportation of Natural Gas" },
    ],
    signals: {
      keywords: ["utility", "grid", "substation", "transmission", "distribution", "pipeline", "nerc", "cip"],
      assetSignals: ["scada", "ics", "modbus", "dnp3", "historians"],
    },
  },
  federal_government: {
    naicsCodes: [
      { code: "921190", label: "Other General Government Support" },
      { code: "928110", label: "National Security" },
    ],
    signals: {
      tlds: [".gov"],
      keywords: ["department", "agency", "bureau", "commission", "office of", "public service"],
      assetSignals: ["piv", "hspd-12", "fisma", "fedramp"],
    },
  },
  saas_tech: {
    naicsCodes: [
      { code: "518210", label: "Data Processing, Hosting, and Related Services" },
      { code: "541512", label: "Computer Systems Design Services" },
      { code: "541511", label: "Custom Computer Programming Services" },
      { code: "511210", label: "Software Publishers" },
    ],
    signals: {
      keywords: ["saas", "cloud", "platform", "api", "developer", "integrations", "status page"],
      assetSignals: ["sso", "oidc", "saml", "admin portal", "api gateway"],
    },
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §4 — NAICS SCORING MODEL (from v2 naics_scoring_model.json)
// ═══════════════════════════════════════════════════════════════════════

export const NAICS_SCORING_WEIGHTS = {
  tldHeuristics: 0.25,
  keywordContentMatch: 0.40,
  assetSignalMatch: 0.30,
  registryCorrelation: 0.05,
} as const;

export const NAICS_CONFIDENCE_BANDS = {
  high: 0.78,
  medium: 0.55,
  low: 0.35,
} as const;

// ═══════════════════════════════════════════════════════════════════════
// §5 — CARVER+SHOCK PRESETS (from v1 carver_presets.json)
// ═══════════════════════════════════════════════════════════════════════

export const CARVER_SHOCK_PRESETS: Record<CarverSector, CarverShockPreset> = {
  banking_financial_services: {
    criticality: 9, accessibility: 7, recuperability: 5,
    vulnerability: 6, effect: 9, recognizability: 8, shock: 8,
  },
  healthcare_providers: {
    criticality: 8, accessibility: 7, recuperability: 6,
    vulnerability: 7, effect: 8, recognizability: 7, shock: 8,
  },
  pharmaceuticals_biotech: {
    criticality: 8, accessibility: 5, recuperability: 4,
    vulnerability: 6, effect: 8, recognizability: 6, shock: 7,
  },
  defense_aerospace: {
    criticality: 9, accessibility: 6, recuperability: 3,
    vulnerability: 6, effect: 9, recognizability: 8, shock: 9,
  },
  electric_gas_utilities: {
    criticality: 10, accessibility: 5, recuperability: 2,
    vulnerability: 5, effect: 10, recognizability: 7, shock: 9,
  },
  federal_government: {
    criticality: 9, accessibility: 5, recuperability: 4,
    vulnerability: 5, effect: 9, recognizability: 7, shock: 8,
  },
  saas_tech: {
    criticality: 7, accessibility: 8, recuperability: 6,
    vulnerability: 7, effect: 7, recognizability: 8, shock: 7,
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §6 — REGULATORY OVERLAYS (from v1 regulatory_overlays.json)
// ═══════════════════════════════════════════════════════════════════════

export const REGULATORY_OVERLAYS: Record<string, RegulatoryOverlay> = {
  fedramp: { shock: 1, effect: 1, criticality: 1 },
  cmmc: { criticality: 1, shock: 1, recuperability: -1 },
  nerc_cip: { criticality: 2, effect: 2, recuperability: -1 },
  glba: { criticality: 1, effect: 1 },
  hipaa: { criticality: 1, vulnerability: 1 },
  fisma: { criticality: 1, effect: 1, shock: 1 },
  itar: { criticality: 2, shock: 1, recognizability: 1 },
  dfars: { criticality: 1, shock: 1 },
  sox: { effect: 1 },
  ffiec: { criticality: 1, vulnerability: 1 },
  hitech: { vulnerability: 1, effect: 1 },
  gxp: { criticality: 1, recuperability: -1 },
  fda: { criticality: 1, effect: 1 },
};

// ═══════════════════════════════════════════════════════════════════════
// §7 — AUTO-BIA ASSET PRIORITY (from v1 auto_bia_asset_priority.json)
// ═══════════════════════════════════════════════════════════════════════

export const AUTO_BIA_ASSET_PRIORITY: Record<CarverSector, string[]> = {
  banking_financial_services: ["SWIFT", "Core Banking System", "Online Banking Portal", "Email"],
  healthcare_providers: ["EHR System", "Patient Data Store", "Billing Systems", "Email"],
  pharmaceuticals_biotech: ["CTMS", "LIMS", "GxP Systems", "R&D Data Store", "Email"],
  defense_aerospace: ["Classified Network", "Engineering Systems", "Program Data", "Email"],
  electric_gas_utilities: ["OT Control Systems", "SCADA", "Grid Operations", "Corporate IT"],
  federal_government: ["Mission Systems", "Classified Network", "PIV Infrastructure", "Email"],
  saas_tech: ["Production API", "Customer Data Store", "CI/CD Pipeline", "Admin Portal"],
};

// ═══════════════════════════════════════════════════════════════════════
// §8 — THREAT ACTOR LIKELIHOOD (from v2 threat_actor_likelihood.json)
// ═══════════════════════════════════════════════════════════════════════

export const THREAT_ACTOR_LIKELIHOOD: Record<CarverSector, Partial<Record<ThreatCategory, number>>> = {
  banking_financial_services: {
    ransomware_ecrime: 0.85, financial_fraud_bec: 0.90,
    apt_state_espionage: 0.60, ddos_extortion: 0.55, insider_threat: 0.45,
  },
  healthcare_providers: {
    ransomware_ecrime: 0.90, data_extortion: 0.80,
    apt_state_espionage: 0.40, insider_threat: 0.50, ddos_extortion: 0.35,
  },
  pharmaceuticals_biotech: {
    apt_state_espionage: 0.85, ransomware_ecrime: 0.55,
    insider_threat: 0.55, supply_chain: 0.50,
  },
  defense_aerospace: {
    apt_state_espionage: 0.95, insider_threat: 0.60,
    supply_chain: 0.65, ransomware_ecrime: 0.45,
  },
  electric_gas_utilities: {
    apt_state_disruption: 0.80, ransomware_ecrime: 0.65,
    ot_intrusion: 0.75, ddos_extortion: 0.40,
  },
  federal_government: {
    apt_state_espionage: 0.90, apt_state_disruption: 0.55,
    hacktivism: 0.45, insider_threat: 0.45,
  },
  saas_tech: {
    credential_stuffing: 0.70, supply_chain: 0.65,
    ransomware_ecrime: 0.55, apt_state_espionage: 0.50, abuse_of_apis: 0.60,
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §9 — FEDRAMP PROFILES (from v2 fedramp_moderate_high_profiles.json)
// ═══════════════════════════════════════════════════════════════════════

export const FEDRAMP_PROFILES: Record<"moderate" | "high", FedRampProfile> = {
  moderate: {
    label: "FedRAMP Moderate",
    overlayAdjustments: { criticality: 1, effect: 1, shock: 1 },
    notes: [
      "Use Moderate impact assumptions unless FIPS 199 indicates High for any objective.",
      "Prioritize auth, logging, vulnerability mgmt, incident reporting, crypto at rest/in transit.",
    ],
    riskTierThresholds: { P0: 12.0, P1: 9.0, P2: 6.0 },
  },
  high: {
    label: "FedRAMP High",
    overlayAdjustments: { criticality: 2, effect: 2, shock: 2 },
    notes: [
      "High-impact systems raise mission effect and shock; treat key auth and admin planes as crown jewels.",
      "Tighten prioritization thresholds and accelerate remediation SLAs.",
    ],
    riskTierThresholds: { P0: 11.0, P1: 8.0, P2: 5.0 },
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §10 — CALDERA OPERATION PRIORITIZATION (from v2)
// ═══════════════════════════════════════════════════════════════════════

export interface CalderaOpTier {
  name: string;
  whenPriorityTier: PriorityTier[];
  whenRegulatory?: string[];
  operationProfile: string;
  objectives: string[];
  notes: string[];
}

export const CALDERA_OP_TIERS: CalderaOpTier[] = [
  {
    name: "Tier-0",
    whenPriorityTier: ["P0"],
    whenRegulatory: ["FedRAMP", "CMMC", "NERC_CIP"],
    operationProfile: "High-Impact Rapid Validation",
    objectives: ["Initial Access", "Privilege Escalation", "Lateral Movement", "Collection", "Exfiltration"],
    notes: ["Run in scoped windows; validate detections and compensating controls; produce executive risk narrative."],
  },
  {
    name: "Tier-1",
    whenPriorityTier: ["P0", "P1"],
    operationProfile: "Threat-Informed Campaign",
    objectives: ["Credential Access", "Discovery", "Defense Evasion", "Collection"],
    notes: ["Select adversary set based on sector-weighted likelihood model."],
  },
  {
    name: "Tier-2",
    whenPriorityTier: ["P2"],
    operationProfile: "Control Validation & Hygiene",
    objectives: ["Discovery", "Persistence (light)", "Command and Control (simulation)"],
    notes: ["Use atomic and low-risk abilities; focus on gaps in logging, IAM, patching, segmentation."],
  },
  {
    name: "Tier-3",
    whenPriorityTier: ["P3"],
    operationProfile: "Continuous Monitoring Checks",
    objectives: ["Discovery (passive)", "Surface Reduction"],
    notes: ["Low cadence checks; prioritize backlog items and security debt."],
  },
];

export interface AbilitySetRule {
  name: string;
  matchSignals: string[];
  abilities: string[];
}

export const ABILITY_SET_LIBRARY: AbilitySetRule[] = [
  {
    name: "auth_surface",
    matchSignals: ["login", "sso", "idp", "oauth", "saml"],
    abilities: ["Valid Accounts", "Credential Dumping (sim)", "Token Impersonation (sim)"],
  },
  {
    name: "internet_exposed_admin",
    matchSignals: ["admin", "manage", "console"],
    abilities: ["Web Session Cookie (sim)", "Discovery", "Privilege Escalation (sim)"],
  },
  {
    name: "data_store_sensitive",
    matchSignals: ["db", "sql", "mongo", "vault", "s3", "blob"],
    abilities: ["Collection", "Archive Collected Data (sim)", "Exfiltration Over C2 Channel (sim)"],
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §11 — NAICS INFERENCE ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Multi-stage NAICS inference using TLD heuristics (25%), keyword content
 * match (40%), asset signal match (30%), and optional registry correlation (5%).
 */
export function inferNaics(input: {
  domain?: string;
  hostname?: string;
  keywords?: string[];
  assetSignals?: string[];
  pageContent?: string;
}): NaicsInferenceResult {
  const results: Array<{ sector: CarverSector; score: number; evidence: NaicsInferenceResult["evidence"] }> = [];

  for (const [sector, mapping] of Object.entries(NAICS_AUTO_MAPPING) as Array<[CarverSector, NaicsSectorMapping]>) {
    let tldScore = 0;
    let keywordScore = 0;
    let assetScore = 0;
    const evidence: NaicsInferenceResult["evidence"] = { tlds: [], keywords: [], assetSignals: [], sources: [] };

    // Stage 1: TLD heuristics (weight 0.25)
    if (input.domain && mapping.signals.tlds) {
      for (const tld of mapping.signals.tlds) {
        if (input.domain.toLowerCase().endsWith(tld)) {
          tldScore = 1.0;
          evidence.tlds.push(tld);
        }
      }
    }

    // Stage 2: Keyword content match (weight 0.40)
    const allText = [
      input.domain || "",
      input.hostname || "",
      ...(input.keywords || []),
      input.pageContent || "",
    ].join(" ").toLowerCase();

    let keywordHits = 0;
    for (const kw of mapping.signals.keywords) {
      if (allText.includes(kw.toLowerCase())) {
        keywordHits++;
        evidence.keywords.push(kw);
      }
    }
    if (mapping.signals.keywords.length > 0) {
      keywordScore = Math.min(1.0, keywordHits / Math.max(2, mapping.signals.keywords.length * 0.4));
    }

    // Stage 3: Asset signal match (weight 0.30)
    const inputSignals = (input.assetSignals || []).map(s => s.toLowerCase());
    let signalHits = 0;
    for (const sig of mapping.signals.assetSignals) {
      if (inputSignals.some(is => is.includes(sig.toLowerCase()) || sig.toLowerCase().includes(is))) {
        signalHits++;
        evidence.assetSignals.push(sig);
      }
    }
    if (mapping.signals.assetSignals.length > 0) {
      assetScore = Math.min(1.0, signalHits / Math.max(1, mapping.signals.assetSignals.length * 0.3));
    }

    // Composite score
    const composite =
      tldScore * NAICS_SCORING_WEIGHTS.tldHeuristics +
      keywordScore * NAICS_SCORING_WEIGHTS.keywordContentMatch +
      assetScore * NAICS_SCORING_WEIGHTS.assetSignalMatch;

    if (composite > 0) {
      results.push({ sector, score: composite, evidence });
    }
  }

  // Sort by score descending
  results.sort((a, b) => b.score - a.score);

  if (results.length === 0) {
    return {
      primaryNaics: "",
      primaryLabel: "Unknown",
      candidates: [],
      confidence: 0,
      confidenceBand: "insufficient",
      evidence: { tlds: [], keywords: [], assetSignals: [], sources: [] },
    };
  }

  const best = results[0];
  const primaryMapping = NAICS_AUTO_MAPPING[best.sector];
  const primaryNaics = primaryMapping.naicsCodes[0];

  const confidenceBand = best.score >= NAICS_CONFIDENCE_BANDS.high ? "high"
    : best.score >= NAICS_CONFIDENCE_BANDS.medium ? "medium"
    : best.score >= NAICS_CONFIDENCE_BANDS.low ? "low"
    : "insufficient";

  const candidates: NaicsCandidate[] = results.slice(0, 5).flatMap(r => {
    const m = NAICS_AUTO_MAPPING[r.sector];
    return m.naicsCodes.map(nc => ({
      code: nc.code,
      label: nc.label,
      score: Math.round(r.score * 100) / 100,
    }));
  });

  return {
    primaryNaics: primaryNaics.code,
    primaryLabel: primaryNaics.label,
    candidates,
    confidence: Math.round(best.score * 100) / 100,
    confidenceBand,
    evidence: best.evidence,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §12 — SECTOR INFERENCE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Infer sector from domain, keywords, and asset signals.
 * Returns sector tag, confidence, regulatory profile, and NAICS inference.
 */
export function inferSector(input: {
  domain?: string;
  hostname?: string;
  keywords?: string[];
  assetSignals?: string[];
  pageContent?: string;
}): SectorInferenceResult {
  const naics = inferNaics(input);

  if (naics.confidence > 0 && naics.primaryNaics) {
    // Find which sector owns this NAICS code
    for (const [sector, mapping] of Object.entries(NAICS_AUTO_MAPPING) as Array<[CarverSector, NaicsSectorMapping]>) {
      if (mapping.naicsCodes.some(nc => nc.code === naics.primaryNaics)) {
        // Determine regulatory profile from sector
        const regulatory = getSectorRegulatory(sector);
        return { sector, confidence: naics.confidence, regulatoryProfile: regulatory, naics };
      }
    }
  }

  // Fallback to legacy detection
  const allText = [
    input.domain || "",
    input.hostname || "",
    ...(input.keywords || []),
    input.pageContent || "",
  ].join(" ").toLowerCase();

  let bestSector: CarverSector = "saas_tech";
  let bestScore = 0;

  for (const [legacy, rules] of Object.entries(INDUSTRY_DETECTION_RULES)) {
    let score = 0;
    if (rules.tlds && input.domain) {
      for (const tld of rules.tlds) {
        if (input.domain.toLowerCase().endsWith(tld)) score += 3;
      }
    }
    for (const kw of rules.keywords) {
      if (allText.includes(kw.toLowerCase())) score += 1;
    }
    for (const sig of rules.assetSignals) {
      const inputSigs = (input.assetSignals || []).map(s => s.toLowerCase());
      if (inputSigs.some(is => is.includes(sig.toLowerCase()))) score += 2;
    }
    if (score > bestScore) {
      bestScore = score;
      bestSector = LEGACY_TO_SECTOR[legacy] || "saas_tech";
    }
  }

  const confidence = Math.min(1.0, bestScore / 8);
  const regulatory = getSectorRegulatory(bestSector);

  return { sector: bestSector, confidence, regulatoryProfile: regulatory, naics };
}

function getSectorRegulatory(sector: CarverSector): RegulatoryFramework[] {
  const map: Record<CarverSector, RegulatoryFramework[]> = {
    banking_financial_services: ["GLBA", "SOX", "FFIEC"],
    healthcare_providers: ["HIPAA", "HITECH"],
    pharmaceuticals_biotech: ["GxP", "FDA", "HIPAA"],
    defense_aerospace: ["CMMC", "ITAR", "DFARS"],
    electric_gas_utilities: ["NERC_CIP"],
    federal_government: ["FISMA", "FedRAMP"],
    saas_tech: [],
  };
  return map[sector] || [];
}

// ═══════════════════════════════════════════════════════════════════════
// §13 — CARVER PRESET + REGULATORY OVERLAY APPLICATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Get the CARVER+SHOCK preset for a sector, with regulatory overlays applied.
 */
export function getAdjustedCarverPreset(
  sector: CarverSector,
  regulatory: RegulatoryFramework[],
  fedRampLevel?: "moderate" | "high",
): CarverShockPreset {
  const base = { ...CARVER_SHOCK_PRESETS[sector] };

  // Apply regulatory overlays
  for (const reg of regulatory) {
    const overlay = REGULATORY_OVERLAYS[reg.toLowerCase().replace(/_/g, "_")];
    if (overlay) {
      if (overlay.criticality) base.criticality = clamp(base.criticality + overlay.criticality, 1, 10);
      if (overlay.accessibility) base.accessibility = clamp(base.accessibility + overlay.accessibility, 1, 10);
      if (overlay.recuperability) base.recuperability = clamp(base.recuperability + overlay.recuperability, 1, 10);
      if (overlay.vulnerability) base.vulnerability = clamp(base.vulnerability + overlay.vulnerability, 1, 10);
      if (overlay.effect) base.effect = clamp(base.effect + overlay.effect, 1, 10);
      if (overlay.recognizability) base.recognizability = clamp(base.recognizability + overlay.recognizability, 1, 10);
      if (overlay.shock) base.shock = clamp(base.shock + overlay.shock, 1, 10);
    }
  }

  // Apply FedRAMP-specific overlay if specified
  if (fedRampLevel) {
    const profile = FEDRAMP_PROFILES[fedRampLevel];
    const adj = profile.overlayAdjustments;
    if (adj.criticality) base.criticality = clamp(base.criticality + adj.criticality, 1, 10);
    if (adj.effect) base.effect = clamp(base.effect + adj.effect, 1, 10);
    if (adj.shock) base.shock = clamp(base.shock + adj.shock, 1, 10);
    if (adj.accessibility) base.accessibility = clamp(base.accessibility + adj.accessibility, 1, 10);
    if (adj.recuperability) base.recuperability = clamp(base.recuperability + adj.recuperability, 1, 10);
    if (adj.vulnerability) base.vulnerability = clamp(base.vulnerability + adj.vulnerability, 1, 10);
    if (adj.recognizability) base.recognizability = clamp(base.recognizability + adj.recognizability, 1, 10);
  }

  return base;
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

// ═══════════════════════════════════════════════════════════════════════
// §14 — HYBRID FUSION FORMULA (from v1 hybrid_fusion.py)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Hybrid score = (CARVER_composite * sector_multiplier) + (CVSS_base * 0.6) + (CVSS_exploitability * 0.4)
 * CARVER_composite = average of all 7 CARVER+SHOCK dimensions
 */
export function computeCarverComposite(preset: CarverShockPreset): number {
  const sum = preset.criticality + preset.accessibility + preset.recuperability +
    preset.vulnerability + preset.effect + preset.recognizability + preset.shock;
  return Math.round((sum / 7) * 100) / 100;
}

export function computeHybridFusionScore(input: {
  carverPreset: CarverShockPreset;
  sectorMultiplier?: number;
  cvssBase?: number;
  cvssExploitability?: number;
  epssScore?: number;
  isKev?: boolean;
}): { hybrid: number; carverComposite: number; priorityTier: PriorityTier } {
  const carverComposite = computeCarverComposite(input.carverPreset);
  const sectorMult = input.sectorMultiplier ?? 1.0;
  const cvssBase = input.cvssBase ?? 0;
  const cvssExploit = input.cvssExploitability ?? 0;

  let hybrid = (carverComposite * sectorMult) + (cvssBase * 0.6) + (cvssExploit * 0.4);

  // EPSS boost: if probability of exploitation is high, bump score
  if (input.epssScore && input.epssScore > 0.5) {
    hybrid += input.epssScore * 1.5;
  }

  // KEV boost: known exploited vulnerabilities get automatic P0 consideration
  if (input.isKev) {
    hybrid += 2.0;
  }

  hybrid = Math.round(hybrid * 100) / 100;

  return {
    hybrid,
    carverComposite,
    priorityTier: priorityTierFromScore(hybrid),
  };
}

export function priorityTierFromScore(hybrid: number, thresholds?: { P0: number; P1: number; P2: number }): PriorityTier {
  const t = thresholds || { P0: 12.0, P1: 9.0, P2: 6.0 };
  if (hybrid >= t.P0) return "P0";
  if (hybrid >= t.P1) return "P1";
  if (hybrid >= t.P2) return "P2";
  return "P3";
}

// ═══════════════════════════════════════════════════════════════════════
// §15 — CALDERA OPERATION PRIORITIZATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Determine the Cyber C2 operation tier and recommended ability sets
 * based on priority tier, regulatory profile, and asset signals.
 */
export function getCalderaOperationPriority(input: {
  priorityTier: PriorityTier;
  regulatory: RegulatoryFramework[];
  sector: CarverSector;
  assetSignals?: string[];
}): CalderaPriority {
  // Find the best matching tier
  let matchedTier = CALDERA_OP_TIERS[CALDERA_OP_TIERS.length - 1]; // default to lowest

  for (const tier of CALDERA_OP_TIERS) {
    if (!tier.whenPriorityTier.includes(input.priorityTier)) continue;

    // If tier requires specific regulatory, check for match
    if (tier.whenRegulatory) {
      const hasReg = tier.whenRegulatory.some(r =>
        input.regulatory.some(ir => ir.toLowerCase() === r.toLowerCase())
      );
      if (hasReg) {
        matchedTier = tier;
        break; // Tier-0 with regulatory match is highest priority
      }
    } else {
      matchedTier = tier;
      break;
    }
  }

  // Determine recommended ability sets from asset signals
  const signals = (input.assetSignals || []).map(s => s.toLowerCase());
  const abilitySets: string[] = [];
  for (const rule of ABILITY_SET_LIBRARY) {
    if (rule.matchSignals.some(ms => signals.some(s => s.includes(ms)))) {
      abilitySets.push(...rule.abilities);
    }
  }

  // Sector-specific adversary recommendations
  const threatLikelihood = THREAT_ACTOR_LIKELIHOOD[input.sector] || {};
  const topThreats = Object.entries(threatLikelihood)
    .sort(([, a], [, b]) => (b || 0) - (a || 0))
    .slice(0, 3)
    .map(([cat]) => formatThreatCategory(cat));

  return {
    operationTier: matchedTier.name,
    operationProfile: matchedTier.operationProfile,
    objectives: matchedTier.objectives,
    recommendedAdversaries: topThreats,
    recommendedAbilitySets: [...new Set(abilitySets)],
    notes: matchedTier.notes,
  };
}

function formatThreatCategory(cat: string): string {
  return cat.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

// ═══════════════════════════════════════════════════════════════════════
// §16 — EXPLAINABLE RISK CARD BUILDER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a full explainable risk card for an asset, combining all scoring
 * dimensions with human-readable drivers and recommended actions.
 */
export function buildExplainableRiskCard(input: {
  assetId: string;
  assetLabel: string;
  domain?: string;
  hostname?: string;
  keywords?: string[];
  assetSignals?: string[];
  pageContent?: string;
  cvssBase?: number;
  cvssExploitability?: number;
  epssScore?: number;
  isKev?: boolean;
  fedRampLevel?: "moderate" | "high";
  overrideSector?: CarverSector;
}): ExplainableRiskCard {
  // Step 1: Infer sector
  const sectorResult = input.overrideSector
    ? {
        sector: input.overrideSector,
        confidence: 1.0,
        regulatoryProfile: getSectorRegulatory(input.overrideSector),
        naics: inferNaics(input),
      }
    : inferSector(input);

  // Step 2: Get adjusted CARVER preset
  const carverPreset = getAdjustedCarverPreset(
    sectorResult.sector,
    sectorResult.regulatoryProfile,
    input.fedRampLevel,
  );

  // Step 3: Compute hybrid fusion score
  const sectorMultiplier = computeSectorMultiplier(sectorResult.sector);
  const thresholds = input.fedRampLevel
    ? FEDRAMP_PROFILES[input.fedRampLevel].riskTierThresholds
    : undefined;

  const fusion = computeHybridFusionScore({
    carverPreset,
    sectorMultiplier,
    cvssBase: input.cvssBase,
    cvssExploitability: input.cvssExploitability,
    epssScore: input.epssScore,
    isKev: input.isKev,
  });

  const priorityTier = thresholds
    ? priorityTierFromScore(fusion.hybrid, thresholds)
    : fusion.priorityTier;

  // Step 4: Build drivers
  const drivers = buildDrivers(sectorResult, carverPreset, input, fusion);

  // Step 5: Get threat likelihood
  const threatLikelihood = THREAT_ACTOR_LIKELIHOOD[sectorResult.sector] || {};

  // Step 6: Generate recommended actions
  const actions = generateRecommendedActions(sectorResult.sector, priorityTier, input.assetSignals || []);

  // Step 7: Get Cyber C2 operation priority
  const calderaPriority = getCalderaOperationPriority({
    priorityTier,
    regulatory: sectorResult.regulatoryProfile,
    sector: sectorResult.sector,
    assetSignals: input.assetSignals,
  });

  return {
    assetId: input.assetId,
    assetLabel: input.assetLabel,
    sector: sectorResult.sector,
    naics: sectorResult.naics.primaryNaics,
    regulatoryProfile: sectorResult.regulatoryProfile,
    scores: {
      carverShock: fusion.carverComposite,
      cvss: { base: input.cvssBase || 0, exploitability: input.cvssExploitability || 0 },
      hybrid: fusion.hybrid,
      priorityTier,
    },
    topDrivers: drivers.slice(0, 5),
    threatLikelihood,
    recommendedActions: actions.slice(0, 8),
    calderaPriority,
    confidence: sectorResult.confidence,
  };
}

function computeSectorMultiplier(sector: CarverSector): number {
  const multipliers: Record<CarverSector, number> = {
    defense_aerospace: 1.3,
    electric_gas_utilities: 1.25,
    federal_government: 1.2,
    banking_financial_services: 1.15,
    healthcare_providers: 1.1,
    pharmaceuticals_biotech: 1.1,
    saas_tech: 1.0,
  };
  return multipliers[sector] || 1.0;
}

function buildDrivers(
  sectorResult: SectorInferenceResult,
  carverPreset: CarverShockPreset,
  input: { assetSignals?: string[]; isKev?: boolean; cvssBase?: number; fedRampLevel?: "moderate" | "high" },
  fusion: { carverComposite: number; hybrid: number },
): RiskCardDriver[] {
  const drivers: RiskCardDriver[] = [];

  // Sector baseline driver
  drivers.push({
    driver: `${formatSectorName(sectorResult.sector)} sector baseline`,
    evidence: [
      `Criticality ${carverPreset.criticality}/10, Effect ${carverPreset.effect}/10, Shock ${carverPreset.shock}/10`,
      `CARVER+SHOCK composite: ${fusion.carverComposite}`,
    ],
    impact: "increase",
  });

  // Regulatory overlay driver
  if (sectorResult.regulatoryProfile.length > 0) {
    drivers.push({
      driver: "Regulatory compliance overlay",
      evidence: sectorResult.regulatoryProfile.map(r => `${r} controls applied`),
      impact: "increase",
    });
  }

  // FedRAMP driver
  if (input.fedRampLevel) {
    drivers.push({
      driver: `FedRAMP ${input.fedRampLevel.charAt(0).toUpperCase() + input.fedRampLevel.slice(1)} alignment`,
      evidence: FEDRAMP_PROFILES[input.fedRampLevel].notes,
      impact: "increase",
    });
  }

  // KEV driver
  if (input.isKev) {
    drivers.push({
      driver: "CISA Known Exploited Vulnerability",
      evidence: ["Asset has active KEV entry — exploitation confirmed in the wild"],
      impact: "increase",
    });
  }

  // CVSS driver
  if (input.cvssBase && input.cvssBase >= 7.0) {
    drivers.push({
      driver: "High CVSS base score",
      evidence: [`CVSS base ${input.cvssBase}/10 indicates significant technical severity`],
      impact: "increase",
    });
  }

  // Asset signal drivers
  const signals = input.assetSignals || [];
  const authSignals = signals.filter(s => ["login", "sso", "idp", "oauth", "saml"].some(a => s.toLowerCase().includes(a)));
  if (authSignals.length > 0) {
    drivers.push({
      driver: "Exposed authentication surface",
      evidence: authSignals.map(s => `Detected: ${s}`),
      impact: "increase",
    });
  }

  return drivers;
}

function formatSectorName(sector: CarverSector): string {
  return sector.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

function generateRecommendedActions(
  sector: CarverSector,
  tier: PriorityTier,
  signals: string[],
): string[] {
  const actions: string[] = [];

  // Universal actions by tier
  if (tier === "P0" || tier === "P1") {
    actions.push("Enforce phishing-resistant MFA for privileged and remote access");
    actions.push("Conduct immediate vulnerability assessment and patch critical findings");
  }
  if (tier === "P0") {
    actions.push("Initiate incident response readiness check and tabletop exercise");
    actions.push("Validate compensating controls and detection coverage");
  }

  // Sector-specific actions
  const sectorActions: Record<CarverSector, string[]> = {
    banking_financial_services: [
      "Review SWIFT/ACH transaction monitoring rules",
      "Validate WAF rules and rate-limit auth endpoints",
      "Audit privileged access to core banking systems",
    ],
    healthcare_providers: [
      "Verify HIPAA access controls on EHR/patient data",
      "Review medical device network segmentation",
      "Audit HL7/FHIR API access controls",
    ],
    pharmaceuticals_biotech: [
      "Review GxP system access controls and audit trails",
      "Validate clinical trial data integrity controls",
      "Audit R&D network segmentation",
    ],
    defense_aerospace: [
      "Validate CUI handling procedures and markings",
      "Review CMMC control implementation status",
      "Audit classified network boundary protections",
    ],
    electric_gas_utilities: [
      "Review OT/IT network segmentation boundaries",
      "Validate NERC CIP compliance controls",
      "Audit SCADA/ICS access control lists",
    ],
    federal_government: [
      "Validate PIV/CAC authentication enforcement",
      "Review FedRAMP continuous monitoring status",
      "Audit FISMA control implementation",
    ],
    saas_tech: [
      "Review API rate limiting and authentication",
      "Validate CI/CD pipeline security controls",
      "Audit customer data isolation mechanisms",
    ],
  };

  actions.push(...(sectorActions[sector] || []));

  // Signal-specific actions
  const sigLower = signals.map(s => s.toLowerCase());
  if (sigLower.some(s => s.includes("login") || s.includes("sso"))) {
    actions.push("Harden IdP configuration and monitor auth anomalies");
  }
  if (sigLower.some(s => s.includes("admin") || s.includes("console"))) {
    actions.push("Restrict admin panel access to VPN/zero-trust network");
  }

  return [...new Set(actions)];
}

// ═══════════════════════════════════════════════════════════════════════
// §17 — BATCH PROCESSING & UTILITIES
// ═══════════════════════════════════════════════════════════════════════

/**
 * Batch process multiple assets through the full CARVER scoring pipeline.
 */
export function batchBuildRiskCards(assets: Array<{
  assetId: string;
  assetLabel: string;
  domain?: string;
  hostname?: string;
  keywords?: string[];
  assetSignals?: string[];
  cvssBase?: number;
  cvssExploitability?: number;
  epssScore?: number;
  isKev?: boolean;
  fedRampLevel?: "moderate" | "high";
  overrideSector?: CarverSector;
}>): ExplainableRiskCard[] {
  return assets.map(a => buildExplainableRiskCard(a));
}

/**
 * Get all available sectors with their CARVER presets and metadata.
 */
export function getAllSectorProfiles(): Array<{
  sector: CarverSector;
  label: string;
  preset: CarverShockPreset;
  regulatory: RegulatoryFramework[];
  threatLikelihood: Partial<Record<ThreatCategory, number>>;
  biaPriority: string[];
  naicsCodes: Array<{ code: string; label: string }>;
}> {
  return (Object.keys(CARVER_SHOCK_PRESETS) as CarverSector[]).map(sector => ({
    sector,
    label: formatSectorName(sector),
    preset: CARVER_SHOCK_PRESETS[sector],
    regulatory: getSectorRegulatory(sector),
    threatLikelihood: THREAT_ACTOR_LIKELIHOOD[sector] || {},
    biaPriority: AUTO_BIA_ASSET_PRIORITY[sector] || [],
    naicsCodes: NAICS_AUTO_MAPPING[sector]?.naicsCodes || [],
  }));
}

/**
 * Get the BIA asset priority list for a sector.
 */
export function getBiaAssetPriority(sector: CarverSector): string[] {
  return AUTO_BIA_ASSET_PRIORITY[sector] || [];
}

/**
 * Get threat actor likelihood for a sector, sorted by probability.
 */
export function getSectorThreatLikelihood(sector: CarverSector): Array<{
  category: ThreatCategory;
  label: string;
  probability: number;
}> {
  const likelihood = THREAT_ACTOR_LIKELIHOOD[sector] || {};
  return Object.entries(likelihood)
    .sort(([, a], [, b]) => (b || 0) - (a || 0))
    .map(([cat, prob]) => ({
      category: cat as ThreatCategory,
      label: formatThreatCategory(cat),
      probability: prob || 0,
    }));
}
