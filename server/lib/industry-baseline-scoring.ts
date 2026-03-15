/**
 * Industry Baseline Scoring Module
 * ─────────────────────────────────
 * Integrates industry-specific asset tier baselines, risk modifiers,
 * auto-BIA inference, and enhanced hybrid scoring formula from the
 * AC3_Industry_Asset_Baseline_Package and AC3_Hybrid_CARVER_SHOCK_Package.
 *
 * Key capabilities:
 *   - 6 industry vertical profiles with Tier 1/2/3 asset classifications
 *   - Industry-specific risk amplification multipliers (safety, regulatory, systemic)
 *   - Auto-BIA inference from asset signals (MX, SSO, payment, admin, DB, git)
 *   - Enhanced hybrid formula: (CARVER/70 * 0.5 + CVSS/10 * 0.3 + BIA * 0.2) * TierWeight
 *   - SHOCK multiplier guidance (Low→Extreme)
 *   - Asset-to-tier auto-classification based on hostname/service patterns
 *
 *   - FIPS 199 security categorization (C/I/A) with industry-specific defaults
 *   - FIPS 199 → CARVER feed-through for automatic score floor adjustments
 *   - Combined BIA + FIPS 199 weighting in the enhanced hybrid formula
 *
 * Data sources:
 *   - AC3_Industry_Asset_Baseline_Package v1.0
 *   - AC3_Hybrid_CARVER_SHOCK_Package v1.0
 *   - NIST FIPS PUB 199 (Standards for Security Categorization)
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — INDUSTRY TYPES & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

export type IndustryVertical =
  | "Corporate_Enterprise"
  | "Industrial_OT_Manufacturing"
  | "Government_Federal_State"
  | "Healthcare"
  | "Financial_Services"
  | "Energy_Utilities";

export type AssetTier = "Tier_1_Strategic" | "Tier_2_Operational" | "Tier_3_Tactical";

export interface IndustryAssetBaseline {
  industry: IndustryVertical;
  tiers: Record<AssetTier, string[]>;
}

export interface IndustryRiskModifiers {
  [key: string]: number;
}

export interface AutoBiaRule {
  assetSignal: string;
  inferredAsset: string;
  defaultBiaMultiplier: number;
}

export interface TierWeights {
  Tier_1_Strategic: number;
  Tier_2_Operational: number;
  Tier_3_Tactical: number;
}

export interface ShockMultiplierLevel {
  level: "Low" | "Moderate" | "High" | "Extreme";
  multiplier: number;
}

export interface HybridScoringFormula {
  carverWeight: number;
  cvssWeight: number;
  biaWeight: number;
}

export type Fips199Level = "low" | "moderate" | "high";

/**
 * FIPS 199 CIA triad for a single information state.
 * Each of the three information lifecycle states (Access, Storage, Transit)
 * has its own Confidentiality / Integrity / Availability rating.
 */
export interface Fips199CiaRating {
  confidentiality: Fips199Level;
  integrity: Fips199Level;
  availability: Fips199Level;
}

/**
 * Full FIPS 199 Security Categorization across all three information states.
 * SC = {(confidentiality, impact), (integrity, impact), (availability, impact)}
 * applied to each lifecycle phase per NIST SP 800-60 / FIPS PUB 199.
 */
export interface Fips199Category {
  /** Data in use — actively being processed or accessed */
  access: Fips199CiaRating;
  /** Data at rest — stored in databases, file systems, backups */
  storage: Fips199CiaRating;
  /** Data in motion — network transfers, API calls, replication */
  transit: Fips199CiaRating;
}

/**
 * Aggregated high-watermark result after evaluating all three states.
 * The overall level for each CIA dimension is the highest across Access/Storage/Transit.
 */
export interface Fips199HighWatermark {
  confidentiality: Fips199Level;
  integrity: Fips199Level;
  availability: Fips199Level;
  overallLevel: Fips199Level;
}

export interface Fips199Adjustments {
  /** The three-state categorization that was evaluated */
  states: Fips199Category;
  /** Aggregated high-watermark across all states */
  highWatermark: Fips199HighWatermark;
  /** CARVER factor floor adjustments derived from FIPS 199 */
  carverFloors: {
    criticality: number;
    effect: number;
    recuperability: number;
  };
  /** Shock factor floor adjustments */
  shockFloors: {
    scope: number;
    operationalImpact: number;
    handling: number;
  };
  /** Mission multiplier boost from FIPS 199 categorization */
  missionMultiplier: number;
  /** Per-state impact summaries (useful for UI display) */
  stateImpacts: {
    access: Fips199Level;
    storage: Fips199Level;
    transit: Fips199Level;
  };
}

export interface IndustryEnhancedScore {
  /** Base hybrid score before industry modifiers */
  baseHybridScore: number;
  /** Industry-adjusted final score */
  industryAdjustedScore: number;
  /** Asset tier determined */
  assetTier: AssetTier;
  /** Tier weight applied */
  tierWeight: number;
  /** Industry identified */
  industry: IndustryVertical;
  /** Industry risk modifiers applied */
  modifiersApplied: Record<string, number>;
  /** Combined modifier multiplier */
  combinedModifier: number;
  /** Auto-BIA inference result (if applicable) */
  biaInference?: {
    signal: string;
    inferredAsset: string;
    biaMultiplier: number;
  };
  /** FIPS 199 categorization applied (if provided) */
  fips199?: {
    category: Fips199Category;
    adjustments: Fips199Adjustments;
  };
  /** SHOCK level determined */
  shockLevel: ShockMultiplierLevel;
  /** Breakdown of formula components */
  formulaBreakdown: {
    carverComponent: number;
    cvssComponent: number;
    biaComponent: number;
    fips199Component: number;
    tierMultiplier: number;
    shockMultiplier: number;
    industryMultiplier: number;
    fips199Multiplier: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — INDUSTRY ASSET BASELINES (from industry_asset_baselines.yaml)
// ═══════════════════════════════════════════════════════════════════════

export const INDUSTRY_ASSET_BASELINES: Record<IndustryVertical, Record<AssetTier, string[]>> = {
  Corporate_Enterprise: {
    Tier_1_Strategic: [
      "Identity Provider / SSO",
      "Email Infrastructure",
      "Cloud Control Plane",
      "Core Business Databases",
      "DNS Infrastructure",
      "Customer-Facing Applications",
      "Executive Endpoints",
    ],
    Tier_2_Operational: [
      "Secrets Management",
      "CI/CD Pipeline",
      "Backup Systems",
      "Internal API Gateways",
      "SIEM / SOC Stack",
    ],
    Tier_3_Tactical: [
      "Standard Workstations",
      "Dev/Test Environments",
      "Collaboration Tools",
    ],
  },
  Industrial_OT_Manufacturing: {
    Tier_1_Strategic: [
      "Industrial Control Systems (ICS)",
      "SCADA Control Servers",
      "Safety Instrumented Systems (SIS)",
      "OT Network Core Switches",
      "Plant Historian Databases",
    ],
    Tier_2_Operational: [
      "Engineering Workstations",
      "PLC Controllers",
      "Remote Maintenance Gateways",
      "Industrial IoT Gateways",
    ],
    Tier_3_Tactical: [
      "Corporate IT Network",
      "Inventory Systems",
      "Internal Documentation Portals",
    ],
  },
  Government_Federal_State: {
    Tier_1_Strategic: [
      "Identity Federation Systems",
      "Classified Network Gateways",
      "Mission Systems",
      "Law Enforcement Databases",
      "Citizen Data Repositories",
      "Email Infrastructure",
    ],
    Tier_2_Operational: [
      "Case Management Systems",
      "Interagency Data Exchange APIs",
      "SOC / SIEM Stack",
      "Cloud Hosting Subscriptions",
    ],
    Tier_3_Tactical: [
      "Public Web Portals",
      "General Employee Workstations",
      "Training Environments",
    ],
  },
  Healthcare: {
    Tier_1_Strategic: [
      "Electronic Health Record (EHR) Systems",
      "Clinical Data Repositories",
      "Identity & Access Management",
      "Medical Device Control Systems",
      "Pharmacy Systems",
    ],
    Tier_2_Operational: [
      "Scheduling Systems",
      "Billing Platforms",
      "Backup Infrastructure",
      "Telehealth Platforms",
    ],
    Tier_3_Tactical: [
      "Staff Workstations",
      "HR Systems",
      "Public Website",
    ],
  },
  Financial_Services: {
    Tier_1_Strategic: [
      "Core Banking Systems",
      "Payment Processing Systems",
      "Trading Platforms",
      "Customer Financial Databases",
      "Fraud Detection Systems",
      "Identity Infrastructure",
    ],
    Tier_2_Operational: [
      "Mobile Banking APIs",
      "SWIFT Interfaces",
      "Backup Systems",
      "Security Monitoring Stack",
    ],
    Tier_3_Tactical: [
      "Corporate Email",
      "Internal HR Platforms",
      "Marketing Systems",
    ],
  },
  Energy_Utilities: {
    Tier_1_Strategic: [
      "Grid Control Systems",
      "SCADA Master Stations",
      "Generation Control Systems",
      "Substation Automation Systems",
    ],
    Tier_2_Operational: [
      "Engineering Access Terminals",
      "Metering Data Systems",
      "Remote Field Gateways",
    ],
    Tier_3_Tactical: [
      "Corporate IT Infrastructure",
      "Billing Systems",
      "Public Web Services",
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — INDUSTRY RISK MODIFIERS (from industry_risk_modifiers.json)
// ═══════════════════════════════════════════════════════════════════════

export const INDUSTRY_RISK_MODIFIERS: Record<IndustryVertical, IndustryRiskModifiers> = {
  Corporate_Enterprise: {
    regulatory_multiplier: 1.1,
    reputation_multiplier: 1.2,
  },
  Industrial_OT_Manufacturing: {
    safety_multiplier: 1.5,
    operational_disruption_multiplier: 1.4,
  },
  Government_Federal_State: {
    national_security_multiplier: 1.6,
    public_trust_multiplier: 1.5,
  },
  Healthcare: {
    patient_safety_multiplier: 1.6,
    hipaa_regulatory_multiplier: 1.5,
  },
  Financial_Services: {
    systemic_financial_risk_multiplier: 1.6,
    regulatory_multiplier: 1.5,
  },
  Energy_Utilities: {
    critical_infrastructure_multiplier: 1.7,
    public_safety_multiplier: 1.6,
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §4 — TIER WEIGHTS (from asset_criticality_baseline.yaml)
// ═══════════════════════════════════════════════════════════════════════

export const TIER_WEIGHTS: TierWeights = {
  Tier_1_Strategic: 1.5,
  Tier_2_Operational: 1.2,
  Tier_3_Tactical: 1.0,
};

// ═══════════════════════════════════════════════════════════════════════
// §5 — HYBRID SCORING FORMULA (from hybrid_scoring_engine.json)
// ═══════════════════════════════════════════════════════════════════════

export const HYBRID_FORMULA: HybridScoringFormula = {
  carverWeight: 0.5,
  cvssWeight: 0.3,
  biaWeight: 0.2,
};

export const CARVER_DIMENSIONS = [
  "Criticality",
  "Accessibility",
  "Recuperability",
  "Vulnerability",
  "Effect",
  "Recognizability",
  "Shock",
] as const;

export const SHOCK_MULTIPLIER_GUIDANCE: ShockMultiplierLevel[] = [
  { level: "Low", multiplier: 1.0 },
  { level: "Moderate", multiplier: 1.1 },
  { level: "High", multiplier: 1.25 },
  { level: "Extreme", multiplier: 1.5 },
];

// ═══════════════════════════════════════════════════════════════════════
// §5b — FIPS 199 SECURITY CATEGORIZATION DEFAULTS & COMPUTATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * FIPS 199 level numeric mapping for score computation.
 * Low = 2, Moderate = 5, High = 9 (aligned with CARVER 1-10 scale).
 */
export const FIPS_199_LEVEL_MAP: Record<Fips199Level, number> = {
  low: 2,
  moderate: 5,
  high: 9,
};

/**
 * Industry-specific FIPS 199 defaults per asset tier.
 * These represent the expected baseline categorization for each information
 * state (Access/Storage/Transit) based on industry regulations and norms.
 *
 * Rationale:
 *   - Healthcare Tier 1: High C/I/A for storage (ePHI at rest), High C for transit (HIPAA)
 *   - Financial Tier 1: High across all states (PCI-DSS, SOX, GLBA)
 *   - Government Tier 1: High C for access/transit (FISMA), Moderate+ for storage
 *   - Energy Tier 1: High A across all states (grid reliability), High I for SCADA
 *   - OT/Manufacturing Tier 1: High A/I for access (safety-critical), Moderate C
 *   - Corporate Tier 1: Moderate-High depending on data sensitivity
 */
export const FIPS_199_INDUSTRY_DEFAULTS: Record<IndustryVertical, Record<AssetTier, Fips199Category>> = {
  Corporate_Enterprise: {
    Tier_1_Strategic: {
      access:  { confidentiality: "high",     integrity: "high",     availability: "high" },
      storage: { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "high",     integrity: "high",     availability: "moderate" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
      storage: { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "moderate", integrity: "moderate", availability: "low" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "low",      integrity: "low",      availability: "low" },
      storage: { confidentiality: "low",      integrity: "low",      availability: "low" },
      transit: { confidentiality: "low",      integrity: "low",      availability: "low" },
    },
  },
  Industrial_OT_Manufacturing: {
    Tier_1_Strategic: {
      access:  { confidentiality: "moderate", integrity: "high",     availability: "high" },
      storage: { confidentiality: "moderate", integrity: "high",     availability: "high" },
      transit: { confidentiality: "moderate", integrity: "high",     availability: "high" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "low",      integrity: "high",     availability: "high" },
      storage: { confidentiality: "low",      integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "low",      integrity: "high",     availability: "moderate" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "low",      integrity: "moderate", availability: "moderate" },
      storage: { confidentiality: "low",      integrity: "low",      availability: "low" },
      transit: { confidentiality: "low",      integrity: "moderate", availability: "low" },
    },
  },
  Government_Federal_State: {
    Tier_1_Strategic: {
      access:  { confidentiality: "high",     integrity: "high",     availability: "high" },
      storage: { confidentiality: "high",     integrity: "high",     availability: "moderate" },
      transit: { confidentiality: "high",     integrity: "high",     availability: "high" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
      storage: { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "moderate", integrity: "low",      availability: "low" },
      storage: { confidentiality: "low",      integrity: "low",      availability: "low" },
      transit: { confidentiality: "moderate", integrity: "low",      availability: "low" },
    },
  },
  Healthcare: {
    Tier_1_Strategic: {
      access:  { confidentiality: "high",     integrity: "high",     availability: "high" },
      storage: { confidentiality: "high",     integrity: "high",     availability: "high" },
      transit: { confidentiality: "high",     integrity: "high",     availability: "moderate" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
      storage: { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "high",     integrity: "moderate", availability: "low" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "moderate", integrity: "low",      availability: "low" },
      storage: { confidentiality: "moderate", integrity: "low",      availability: "low" },
      transit: { confidentiality: "moderate", integrity: "low",      availability: "low" },
    },
  },
  Financial_Services: {
    Tier_1_Strategic: {
      access:  { confidentiality: "high",     integrity: "high",     availability: "high" },
      storage: { confidentiality: "high",     integrity: "high",     availability: "high" },
      transit: { confidentiality: "high",     integrity: "high",     availability: "high" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "high",     integrity: "high",     availability: "moderate" },
      storage: { confidentiality: "high",     integrity: "moderate", availability: "moderate" },
      transit: { confidentiality: "high",     integrity: "high",     availability: "moderate" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "moderate", integrity: "moderate", availability: "low" },
      storage: { confidentiality: "moderate", integrity: "low",      availability: "low" },
      transit: { confidentiality: "moderate", integrity: "moderate", availability: "low" },
    },
  },
  Energy_Utilities: {
    Tier_1_Strategic: {
      access:  { confidentiality: "moderate", integrity: "high",     availability: "high" },
      storage: { confidentiality: "moderate", integrity: "high",     availability: "high" },
      transit: { confidentiality: "moderate", integrity: "high",     availability: "high" },
    },
    Tier_2_Operational: {
      access:  { confidentiality: "low",      integrity: "high",     availability: "high" },
      storage: { confidentiality: "low",      integrity: "moderate", availability: "high" },
      transit: { confidentiality: "low",      integrity: "high",     availability: "moderate" },
    },
    Tier_3_Tactical: {
      access:  { confidentiality: "low",      integrity: "moderate", availability: "moderate" },
      storage: { confidentiality: "low",      integrity: "low",      availability: "moderate" },
      transit: { confidentiality: "low",      integrity: "moderate", availability: "low" },
    },
  },
};

/**
 * Compute the FIPS 199 high-watermark across all three information states.
 * Per FIPS PUB 199: "The generalization of the security category is:
 *   SC = {(confidentiality, impact), (integrity, impact), (availability, impact)}"
 * We take the maximum impact level for each CIA dimension across Access/Storage/Transit.
 */
export function computeFips199HighWatermark(category: Fips199Category): Fips199HighWatermark {
  const levelOrder: Record<Fips199Level, number> = { low: 0, moderate: 1, high: 2 };
  const levelFromNum = (n: number): Fips199Level => n >= 2 ? "high" : n >= 1 ? "moderate" : "low";

  const maxC = Math.max(
    levelOrder[category.access.confidentiality],
    levelOrder[category.storage.confidentiality],
    levelOrder[category.transit.confidentiality]
  );
  const maxI = Math.max(
    levelOrder[category.access.integrity],
    levelOrder[category.storage.integrity],
    levelOrder[category.transit.integrity]
  );
  const maxA = Math.max(
    levelOrder[category.access.availability],
    levelOrder[category.storage.availability],
    levelOrder[category.transit.availability]
  );

  const conf = levelFromNum(maxC);
  const integ = levelFromNum(maxI);
  const avail = levelFromNum(maxA);
  const overall = levelFromNum(Math.max(maxC, maxI, maxA));

  return { confidentiality: conf, integrity: integ, availability: avail, overallLevel: overall };
}

/**
 * Compute the per-state impact level (highest of C/I/A within that state).
 */
function stateImpactLevel(state: Fips199CiaRating): Fips199Level {
  const levelOrder: Record<Fips199Level, number> = { low: 0, moderate: 1, high: 2 };
  const max = Math.max(
    levelOrder[state.confidentiality],
    levelOrder[state.integrity],
    levelOrder[state.availability]
  );
  return max >= 2 ? "high" : max >= 1 ? "moderate" : "low";
}

/**
 * Compute FIPS 199 adjustments from a full three-state categorization.
 * Maps the high-watermark CIA levels to CARVER/SHOCK floor values and
 * a mission multiplier that feeds into the hybrid scoring formula.
 */
export function computeFips199Adjustments(category: Fips199Category): Fips199Adjustments {
  const hw = computeFips199HighWatermark(category);

  const confScore = FIPS_199_LEVEL_MAP[hw.confidentiality];
  const intScore = FIPS_199_LEVEL_MAP[hw.integrity];
  const availScore = FIPS_199_LEVEL_MAP[hw.availability];
  const maxScore = Math.max(confScore, intScore, availScore);

  // CARVER floor adjustments: FIPS 199 sets minimum values
  const carverFloors = {
    criticality: maxScore,
    effect: Math.round((confScore + intScore) / 2),
    recuperability: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 3,
  };

  // SHOCK floor adjustments
  const shockFloors = {
    scope: confScore >= 7 ? 8 : confScore >= 4 ? 5 : 2,
    operationalImpact: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 2,
    handling: intScore >= 7 ? 7 : intScore >= 4 ? 5 : 3,
  };

  // Mission multiplier based on highest categorization
  let missionMultiplier = 1.0;
  if (maxScore >= 9) missionMultiplier = 1.8;
  else if (maxScore >= 5) missionMultiplier = 1.3;
  else missionMultiplier = 0.9;

  return {
    states: category,
    highWatermark: hw,
    carverFloors,
    shockFloors,
    missionMultiplier,
    stateImpacts: {
      access: stateImpactLevel(category.access),
      storage: stateImpactLevel(category.storage),
      transit: stateImpactLevel(category.transit),
    },
  };
}

/**
 * Get the FIPS 199 industry default for a given industry + tier combination.
 */
export function getFips199IndustryDefault(
  industry: IndustryVertical,
  tier: AssetTier
): Fips199Category {
  return FIPS_199_INDUSTRY_DEFAULTS[industry]?.[tier] ?? {
    access:  { confidentiality: "low", integrity: "low", availability: "low" },
    storage: { confidentiality: "low", integrity: "low", availability: "low" },
    transit: { confidentiality: "low", integrity: "low", availability: "low" },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — AUTO-BIA INFERENCE (from auto_bia_inference.yaml)
// ═══════════════════════════════════════════════════════════════════════

export const AUTO_BIA_RULES: AutoBiaRule[] = [
  { assetSignal: "MX Record", inferredAsset: "Email Infrastructure", defaultBiaMultiplier: 1.4 },
  { assetSignal: "SSO Endpoint", inferredAsset: "Identity Provider / SSO", defaultBiaMultiplier: 1.5 },
  { assetSignal: "Payment Page", inferredAsset: "Customer-Facing Applications", defaultBiaMultiplier: 1.45 },
  { assetSignal: "Admin Panel", inferredAsset: "Cloud Control Plane", defaultBiaMultiplier: 1.5 },
  { assetSignal: "Database Port Exposure", inferredAsset: "Core Business Databases", defaultBiaMultiplier: 1.5 },
  { assetSignal: "Git Repository", inferredAsset: "CI/CD Pipeline", defaultBiaMultiplier: 1.35 },
];

// Extended signal patterns for automatic detection from scan data
const SIGNAL_PATTERNS: Array<{ pattern: RegExp; signal: string }> = [
  { pattern: /\bmx\b|mail\.|smtp\.|exchange\.|postfix/i, signal: "MX Record" },
  { pattern: /\bsso\b|okta|auth0|saml|adfs|login\.|identity/i, signal: "SSO Endpoint" },
  { pattern: /payment|checkout|stripe|paypal|billing\..*pay/i, signal: "Payment Page" },
  { pattern: /admin|cpanel|webmin|dashboard\..*admin|manage\./i, signal: "Admin Panel" },
  { pattern: /\b(3306|5432|1433|27017|6379|5984)\b|mysql|postgres|mssql|mongo|redis/i, signal: "Database Port Exposure" },
  { pattern: /git(lab|hub|ea)|bitbucket|jenkins|ci\.|cd\.|pipeline|drone|argo/i, signal: "Git Repository" },
  // Additional patterns for broader coverage
  { pattern: /\bdns\b|ns1\.|ns2\.|named|bind/i, signal: "DNS Infrastructure" },
  { pattern: /\bvpn\b|wireguard|openvpn|ipsec/i, signal: "VPN Gateway" },
  { pattern: /backup|veeam|commvault|rubrik|cohesity/i, signal: "Backup Systems" },
  { pattern: /scada|plc|hmi|modbus|dnp3|ics/i, signal: "SCADA/ICS" },
  { pattern: /ehr|epic|cerner|meditech|allscripts/i, signal: "EHR System" },
  { pattern: /swift|core.?banking|trading|bloomberg/i, signal: "Financial Core" },
];

// ═══════════════════════════════════════════════════════════════════════
// §7 — ASSET TIER CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Classify an asset into a tier based on its characteristics and the
 * customer's industry vertical. Uses fuzzy matching against the
 * industry-specific tier definitions.
 */
export function classifyAssetTier(
  assetInfo: {
    hostname?: string;
    assetType?: string;
    services?: string[];
    technologies?: string[];
    description?: string;
    tags?: string[];
  },
  industry: IndustryVertical
): { tier: AssetTier; matchedAssetType: string; confidence: number } {
  const baselines = INDUSTRY_ASSET_BASELINES[industry];
  if (!baselines) {
    return { tier: "Tier_3_Tactical", matchedAssetType: "Unknown", confidence: 0.3 };
  }

  // Build a searchable string from all asset attributes
  const searchText = [
    assetInfo.hostname || "",
    assetInfo.assetType || "",
    ...(assetInfo.services || []),
    ...(assetInfo.technologies || []),
    assetInfo.description || "",
    ...(assetInfo.tags || []),
  ].join(" ").toLowerCase();

  // Check each tier from highest to lowest priority
  const tiers: AssetTier[] = ["Tier_1_Strategic", "Tier_2_Operational", "Tier_3_Tactical"];

  for (const tier of tiers) {
    for (const assetType of baselines[tier]) {
      // Generate keywords from the asset type name
      const keywords = assetType.toLowerCase()
        .replace(/[()\/]/g, " ")
        .split(/\s+/)
        .filter(w => w.length > 2 && !["and", "the", "for"].includes(w));

      // Count matching keywords
      const matchCount = keywords.filter(kw => searchText.includes(kw)).length;
      const matchRatio = keywords.length > 0 ? matchCount / keywords.length : 0;

      if (matchRatio >= 0.5) {
        const confidence = Math.min(0.95, 0.5 + matchRatio * 0.4);
        return { tier, matchedAssetType: assetType, confidence };
      }
    }
  }

  // Default to Tier 3 if no match found
  return { tier: "Tier_3_Tactical", matchedAssetType: "Unclassified", confidence: 0.3 };
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — AUTO-BIA INFERENCE ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Infer business impact from asset signals detected during scanning.
 * Uses pattern matching against hostname, services, and technologies
 * to identify asset signals and map them to BIA multipliers.
 */
export function inferBiaFromSignals(
  assetInfo: {
    hostname?: string;
    services?: string[];
    technologies?: string[];
    ports?: number[];
    description?: string;
  }
): { signal: string; inferredAsset: string; biaMultiplier: number } | null {
  const searchText = [
    assetInfo.hostname || "",
    ...(assetInfo.services || []),
    ...(assetInfo.technologies || []),
    ...(assetInfo.ports || []).map(String),
    assetInfo.description || "",
  ].join(" ");

  // Check signal patterns
  for (const { pattern, signal } of SIGNAL_PATTERNS) {
    if (pattern.test(searchText)) {
      const rule = AUTO_BIA_RULES.find(r => r.assetSignal === signal);
      if (rule) {
        return {
          signal: rule.assetSignal,
          inferredAsset: rule.inferredAsset,
          biaMultiplier: rule.defaultBiaMultiplier,
        };
      }
    }
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — SHOCK LEVEL DETERMINATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Determine SHOCK multiplier level based on the shock composite score.
 * Maps the 0-10 shock score to Low/Moderate/High/Extreme levels.
 */
export function determineShockLevel(shockComposite: number): ShockMultiplierLevel {
  if (shockComposite >= 8.0) return SHOCK_MULTIPLIER_GUIDANCE[3]; // Extreme
  if (shockComposite >= 6.0) return SHOCK_MULTIPLIER_GUIDANCE[2]; // High
  if (shockComposite >= 3.5) return SHOCK_MULTIPLIER_GUIDANCE[1]; // Moderate
  return SHOCK_MULTIPLIER_GUIDANCE[0]; // Low
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — INDUSTRY MODIFIER COMPUTATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute the combined industry risk modifier for a given industry.
 * Takes the geometric mean of all applicable modifiers to avoid
 * over-amplification while still reflecting compound risk.
 */
export function computeIndustryModifier(industry: IndustryVertical): {
  modifiers: Record<string, number>;
  combined: number;
} {
  const modifiers = INDUSTRY_RISK_MODIFIERS[industry];
  if (!modifiers || Object.keys(modifiers).length === 0) {
    return { modifiers: {}, combined: 1.0 };
  }

  const values = Object.values(modifiers);
  // Geometric mean to avoid over-amplification
  const product = values.reduce((acc, v) => acc * v, 1);
  const combined = Math.pow(product, 1 / values.length);

  return { modifiers, combined: Math.round(combined * 1000) / 1000 };
}

// ═══════════════════════════════════════════════════════════════════════
// §11 — ENHANCED HYBRID SCORING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute the industry-enhanced hybrid risk score using the formula:
 *
 *   score = ((CARVER_total / 70) * 0.5 + (CVSS / 10) * 0.3 + BIA * 0.2)
 *           * TierWeight * ShockMultiplier * IndustryModifier * Fips199Multiplier
 *
 * This extends the base Hybrid Risk scoring with:
 *   - Industry-specific asset tier classification
 *   - Industry risk amplification modifiers
 *   - Auto-BIA inference from scan signals
 *   - SHOCK level-based multipliers
 *   - FIPS 199 three-state security categorization (Access/Storage/Transit)
 *
 * When FIPS 199 is provided (or auto-populated from industry defaults),
 * the high-watermark mission multiplier is applied as an additional
 * scaling factor. This ensures that assets handling high-impact
 * information types across any lifecycle state receive appropriate
 * risk amplification.
 *
 * The result is normalized to a 0-100 scale.
 */
export function computeIndustryEnhancedScore(input: {
  /** Raw CARVER total (sum of 7 dimensions, 0-70) */
  carverTotal: number;
  /** CVSS score (0-10) */
  cvssScore: number;
  /** Shock composite score (0-10) */
  shockComposite: number;
  /** Customer industry vertical */
  industry: IndustryVertical;
  /** Asset information for tier classification and BIA inference */
  assetInfo: {
    hostname?: string;
    assetType?: string;
    services?: string[];
    technologies?: string[];
    ports?: number[];
    description?: string;
    tags?: string[];
  };
  /** Override BIA multiplier (if from interview data rather than auto-inference) */
  biaMultiplierOverride?: number;
  /** Override asset tier (if manually classified) */
  tierOverride?: AssetTier;
  /** FIPS 199 three-state categorization (Access/Storage/Transit). If omitted, uses industry defaults. */
  fips199?: Fips199Category;
  /** Set to true to skip auto-populating FIPS 199 from industry defaults */
  skipFips199Defaults?: boolean;
}): IndustryEnhancedScore {
  // Step 1: Classify asset tier
  const tierResult = input.tierOverride
    ? { tier: input.tierOverride, matchedAssetType: "Manual Override", confidence: 1.0 }
    : classifyAssetTier(input.assetInfo, input.industry);
  const tierWeight = TIER_WEIGHTS[tierResult.tier];

  // Step 2: Auto-BIA inference
  const biaInference = inferBiaFromSignals(input.assetInfo);
  const biaMultiplier = input.biaMultiplierOverride
    ?? biaInference?.biaMultiplier
    ?? getDefaultBiaForTier(tierResult.tier);

  // Step 3: Determine SHOCK level
  const shockLevel = determineShockLevel(input.shockComposite);

  // Step 4: Compute industry modifier
  const industryMod = computeIndustryModifier(input.industry);

  // Step 5: Resolve FIPS 199 categorization
  const fips199Category = input.fips199
    ?? (input.skipFips199Defaults ? undefined : getFips199IndustryDefault(input.industry, tierResult.tier));
  const fips199Result = fips199Category ? computeFips199Adjustments(fips199Category) : undefined;
  // FIPS 199 multiplier: use the mission multiplier from FIPS 199 adjustments
  // This ranges from 0.9 (low) to 1.8 (high), normalized to a gentler range
  const fips199Multiplier = fips199Result ? fips199Result.missionMultiplier : 1.0;

  // Step 6: Apply enhanced hybrid formula
  const carverNorm = clamp(input.carverTotal / 70, 0, 1);
  const cvssNorm = clamp(input.cvssScore / 10, 0, 1);
  // BIA multiplier is already a multiplier (1.0-1.5 range), normalize to 0-1 scale
  const biaNorm = clamp((biaMultiplier - 1.0) * 2, 0, 1);

  const carverComponent = carverNorm * HYBRID_FORMULA.carverWeight;
  const cvssComponent = cvssNorm * HYBRID_FORMULA.cvssWeight;
  const biaComponent = biaNorm * HYBRID_FORMULA.biaWeight;

  // FIPS 199 contributes as a multiplier on the overall score, not as an additive component
  // This reflects that FIPS 199 categorization amplifies the risk of high-impact info types
  const baseScore = (carverComponent + cvssComponent + biaComponent);
  const adjustedScore = baseScore * tierWeight * shockLevel.multiplier * industryMod.combined * fips199Multiplier;

  // Normalize to 0-100 scale
  const finalScore = Math.round(clamp(adjustedScore * 100, 0, 100));
  const baseHybridScore = Math.round(clamp(baseScore * 100, 0, 100));

  return {
    baseHybridScore,
    industryAdjustedScore: finalScore,
    assetTier: tierResult.tier,
    tierWeight,
    industry: input.industry,
    modifiersApplied: industryMod.modifiers,
    combinedModifier: industryMod.combined,
    biaInference: biaInference ? {
      signal: biaInference.signal,
      inferredAsset: biaInference.inferredAsset,
      biaMultiplier: biaInference.biaMultiplier,
    } : undefined,
    fips199: fips199Result ? {
      category: fips199Category!,
      adjustments: fips199Result,
    } : undefined,
    shockLevel,
    formulaBreakdown: {
      carverComponent: Math.round(carverComponent * 1000) / 1000,
      cvssComponent: Math.round(cvssComponent * 1000) / 1000,
      biaComponent: Math.round(biaComponent * 1000) / 1000,
      fips199Component: Math.round((fips199Multiplier - 1.0) * 1000) / 1000,
      tierMultiplier: tierWeight,
      shockMultiplier: shockLevel.multiplier,
      industryMultiplier: industryMod.combined,
      fips199Multiplier: Math.round(fips199Multiplier * 1000) / 1000,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §12 — BATCH SCORING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Score multiple assets with industry context in a single batch.
 * Returns sorted results (highest risk first) with summary statistics.
 */
export function batchIndustryScore(
  assets: Array<{
    assetId: string;
    carverTotal: number;
    cvssScore: number;
    shockComposite: number;
    assetInfo: {
      hostname?: string;
      assetType?: string;
      services?: string[];
      technologies?: string[];
      ports?: number[];
      description?: string;
      tags?: string[];
    };
    biaMultiplierOverride?: number;
    tierOverride?: AssetTier;
  }>,
  industry: IndustryVertical
): {
  scores: Array<{ assetId: string; score: IndustryEnhancedScore }>;
  summary: {
    totalAssets: number;
    tierDistribution: Record<AssetTier, number>;
    averageScore: number;
    maxScore: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
} {
  const scores = assets.map(asset => ({
    assetId: asset.assetId,
    score: computeIndustryEnhancedScore({
      carverTotal: asset.carverTotal,
      cvssScore: asset.cvssScore,
      shockComposite: asset.shockComposite,
      industry,
      assetInfo: asset.assetInfo,
      biaMultiplierOverride: asset.biaMultiplierOverride,
      tierOverride: asset.tierOverride,
    }),
  }));

  // Sort by industry-adjusted score descending
  scores.sort((a, b) => b.score.industryAdjustedScore - a.score.industryAdjustedScore);

  // Compute summary
  const tierDist: Record<AssetTier, number> = {
    Tier_1_Strategic: 0,
    Tier_2_Operational: 0,
    Tier_3_Tactical: 0,
  };

  let totalScore = 0;
  let maxScore = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const { score } of scores) {
    tierDist[score.assetTier]++;
    totalScore += score.industryAdjustedScore;
    maxScore = Math.max(maxScore, score.industryAdjustedScore);

    if (score.industryAdjustedScore >= 80) criticalCount++;
    else if (score.industryAdjustedScore >= 60) highCount++;
    else if (score.industryAdjustedScore >= 35) mediumCount++;
    else lowCount++;
  }

  return {
    scores,
    summary: {
      totalAssets: assets.length,
      tierDistribution: tierDist,
      averageScore: scores.length > 0 ? Math.round(totalScore / scores.length) : 0,
      maxScore,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §13 — UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function getDefaultBiaForTier(tier: AssetTier): number {
  switch (tier) {
    case "Tier_1_Strategic": return 1.4;
    case "Tier_2_Operational": return 1.2;
    case "Tier_3_Tactical": return 1.0;
    default: return 1.0;
  }
}

/**
 * Get all supported industry verticals with their display names.
 */
export function getIndustryVerticals(): Array<{ id: IndustryVertical; label: string; assetCount: number }> {
  return [
    { id: "Corporate_Enterprise", label: "Corporate / Enterprise", assetCount: countAssets("Corporate_Enterprise") },
    { id: "Industrial_OT_Manufacturing", label: "Industrial / OT / Manufacturing", assetCount: countAssets("Industrial_OT_Manufacturing") },
    { id: "Government_Federal_State", label: "Government (Federal / State)", assetCount: countAssets("Government_Federal_State") },
    { id: "Healthcare", label: "Healthcare", assetCount: countAssets("Healthcare") },
    { id: "Financial_Services", label: "Financial Services", assetCount: countAssets("Financial_Services") },
    { id: "Energy_Utilities", label: "Energy / Utilities", assetCount: countAssets("Energy_Utilities") },
  ];
}

function countAssets(industry: IndustryVertical): number {
  const baselines = INDUSTRY_ASSET_BASELINES[industry];
  return Object.values(baselines).reduce((sum, arr) => sum + arr.length, 0);
}

/**
 * Get the tier breakdown for a specific industry.
 */
export function getIndustryTierBreakdown(industry: IndustryVertical): {
  tier: AssetTier;
  weight: number;
  assets: string[];
}[] {
  const baselines = INDUSTRY_ASSET_BASELINES[industry];
  if (!baselines) return [];

  return [
    { tier: "Tier_1_Strategic", weight: TIER_WEIGHTS.Tier_1_Strategic, assets: baselines.Tier_1_Strategic },
    { tier: "Tier_2_Operational", weight: TIER_WEIGHTS.Tier_2_Operational, assets: baselines.Tier_2_Operational },
    { tier: "Tier_3_Tactical", weight: TIER_WEIGHTS.Tier_3_Tactical, assets: baselines.Tier_3_Tactical },
  ];
}

/**
 * Detect asset signals from scan data and return all matching BIA inferences.
 */
export function detectAllSignals(
  assetInfo: {
    hostname?: string;
    services?: string[];
    technologies?: string[];
    ports?: number[];
    description?: string;
  }
): AutoBiaRule[] {
  const searchText = [
    assetInfo.hostname || "",
    ...(assetInfo.services || []),
    ...(assetInfo.technologies || []),
    ...(assetInfo.ports || []).map(String),
    assetInfo.description || "",
  ].join(" ");

  const matched: AutoBiaRule[] = [];
  const seenSignals = new Set<string>();

  for (const { pattern, signal } of SIGNAL_PATTERNS) {
    if (pattern.test(searchText) && !seenSignals.has(signal)) {
      const rule = AUTO_BIA_RULES.find(r => r.assetSignal === signal);
      if (rule) {
        matched.push(rule);
        seenSignals.add(signal);
      }
    }
  }

  return matched;
}
