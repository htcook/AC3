/**
 * Hybrid Risk Scoring Hardening Layer
 * ─────────────────────────────────────
 * Production hardening for the scoring engine:
 * - Input validation and sanitization for all scoring inputs
 * - NaN/undefined/null protection across all numeric fields
 * - Division-by-zero guards
 * - Deterministic fallback scoring when LLM classification fails
 * - Scoring audit trail for debugging and compliance
 * - Edge-case handling for extreme values
 */

import type {
  CarverScores,
  ShockScores,
  ScoringInput,
  ScoringProfile,
  ScoringResult,
  CarverWeights,
  ShockWeights,
  CriticalityTier,
  Fips199Category,
  AssetClassification,
} from "./scoring-engine";
import {
  computeHybridRisk,
  computeCarverComposite,
  computeShockComposite,
} from "./scoring-engine";

// ─── Input Sanitization ──────────────────────────────────────────────

/** Safely convert any value to a number within a range, defaulting if NaN/undefined/null */
function safeNum(val: any, defaultVal: number, min: number, max: number): number {
  if (val === undefined || val === null) return defaultVal;
  const n = Number(val);
  if (isNaN(n) || !isFinite(n)) return defaultVal;
  return Math.max(min, Math.min(max, n));
}

/** Sanitize CARVER scores — ensure all 6 factors are valid numbers 0-10 */
export function sanitizeCarverScores(scores: any): CarverScores {
  if (!scores || typeof scores !== "object") {
    return DEFAULT_CARVER_SCORES;
  }
  return {
    criticality: safeNum(scores.criticality, 3, 0, 10),
    accessibility: safeNum(scores.accessibility, 3, 0, 10),
    recuperability: safeNum(scores.recuperability, 5, 0, 10),
    vulnerability: safeNum(scores.vulnerability, 3, 0, 10),
    effect: safeNum(scores.effect, 3, 0, 10),
    recognizability: safeNum(scores.recognizability, 5, 0, 10),
  };
}

/** Sanitize Shock scores — ensure all 5 factors are valid numbers 0-10 */
export function sanitizeShockScores(scores: any): ShockScores {
  if (!scores || typeof scores !== "object") {
    return DEFAULT_SHOCK_SCORES;
  }
  return {
    scope: safeNum(scores.scope, 3, 0, 10),
    handling: safeNum(scores.handling, 5, 0, 10),
    operationalImpact: safeNum(scores.operationalImpact, 3, 0, 10),
    cascadingEffects: safeNum(scores.cascadingEffects, 2, 0, 10),
    knowledge: safeNum(scores.knowledge, 5, 0, 10),
  };
}

/** Sanitize the full ScoringInput — protect every numeric field */
export function sanitizeScoringInput(input: any): ScoringInput {
  return {
    carver: sanitizeCarverScores(input?.carver),
    shock: sanitizeShockScores(input?.shock),
    cvssEstimate: safeNum(input?.cvssEstimate, 0, 0, 10),
    exposure: safeNum(input?.exposure, 0.5, 0, 1),
    confidence: safeNum(input?.confidence, 0.5, 0, 1),
    confirmedVulnScore: input?.confirmedVulnScore !== undefined
      ? safeNum(input.confirmedVulnScore, 0, 0, 100)
      : undefined,
    portLikelihoodBoost: input?.portLikelihoodBoost !== undefined
      ? safeNum(input.portLikelihoodBoost, 0, 0, 1)
      : undefined,
    missionMultiplier: input?.missionMultiplier !== undefined
      ? safeNum(input.missionMultiplier, 1.0, 0.1, 5.0)
      : undefined,
    businessImpactLevel: validateBusinessImpactLevel(input?.businessImpactLevel),
    cvssV4Vector: typeof input?.cvssV4Vector === "string" ? input.cvssV4Vector : undefined,
    fips199: validateFips199(input?.fips199),
    criticalityTier: validateCriticalityTier(input?.criticalityTier),
  };
}

/** Sanitize ScoringProfile — protect weights from zero/NaN */
export function sanitizeScoringProfile(profile: any): ScoringProfile {
  const defaultProfile = DEFAULT_SCORING_PROFILE;
  if (!profile || typeof profile !== "object") return defaultProfile;

  return {
    carverWeights: sanitizeWeights(profile.carverWeights, defaultProfile.carverWeights, "carver") as CarverWeights,
    shockWeights: sanitizeWeights(profile.shockWeights, defaultProfile.shockWeights, "shock") as ShockWeights,
    carverWeight: safeNum(profile.carverWeight, 0.6, 0.01, 1),
    shockWeight: safeNum(profile.shockWeight, 0.4, 0.01, 1),
    cvssWeight: safeNum(profile.cvssWeight, 0.3, 0.01, 1),
    criticalThreshold: safeNum(profile.criticalThreshold, 80, 1, 100),
    highThreshold: safeNum(profile.highThreshold, 60, 1, 100),
    mediumThreshold: safeNum(profile.mediumThreshold, 35, 1, 100),
  };
}

function sanitizeWeights(weights: any, defaults: any, type: "carver" | "shock"): CarverWeights | ShockWeights {
  if (!weights || typeof weights !== "object") return defaults;
  
  if (type === "carver") {
    return {
      criticality: safeNum(weights.criticality, defaults.criticality, 0.01, 10),
      accessibility: safeNum(weights.accessibility, defaults.accessibility, 0.01, 10),
      recuperability: safeNum(weights.recuperability, defaults.recuperability, 0.01, 10),
      vulnerability: safeNum(weights.vulnerability, defaults.vulnerability, 0.01, 10),
      effect: safeNum(weights.effect, defaults.effect, 0.01, 10),
      recognizability: safeNum(weights.recognizability, defaults.recognizability, 0.01, 10),
    } as CarverWeights;
  } else {
    return {
      scope: safeNum(weights.scope, defaults.scope, 0.01, 10),
      handling: safeNum(weights.handling, defaults.handling, 0.01, 10),
      operationalImpact: safeNum(weights.operationalImpact, defaults.operationalImpact, 0.01, 10),
      cascadingEffects: safeNum(weights.cascadingEffects, defaults.cascadingEffects, 0.01, 10),
      knowledge: safeNum(weights.knowledge, defaults.knowledge, 0.01, 10),
    } as ShockWeights;
  }
}

function validateBusinessImpactLevel(val: any): ScoringInput["businessImpactLevel"] {
  const valid = ["mission_critical", "business_essential", "operational", "administrative"];
  return valid.includes(val) ? val : undefined;
}

function validateFips199(val: any): Fips199Category | undefined {
  if (!val || typeof val !== "object") return undefined;
  const levels = ["low", "moderate", "high"];
  if (!levels.includes(val.confidentiality) || !levels.includes(val.integrity) || !levels.includes(val.availability)) {
    return undefined;
  }
  return val as Fips199Category;
}

function validateCriticalityTier(val: any): CriticalityTier | undefined {
  const n = Number(val);
  if (isNaN(n) || n < 1 || n > 5) return undefined;
  return Math.round(n) as CriticalityTier;
}


// ─── Default Values ──────────────────────────────────────────────────

export const DEFAULT_CARVER_SCORES: CarverScores = {
  criticality: 3,
  accessibility: 3,
  recuperability: 5,
  vulnerability: 3,
  effect: 3,
  recognizability: 5,
};

export const DEFAULT_SHOCK_SCORES: ShockScores = {
  scope: 3,
  handling: 5,
  operationalImpact: 3,
  cascadingEffects: 2,
  knowledge: 5,
};

export const DEFAULT_SCORING_PROFILE: ScoringProfile = {
  carverWeights: {
    criticality: 2.0,
    accessibility: 1.5,
    recuperability: 1.0,
    vulnerability: 2.0,
    effect: 1.5,
    recognizability: 1.0,
  },
  shockWeights: {
    scope: 1.5,
    handling: 1.0,
    operationalImpact: 2.0,
    cascadingEffects: 1.5,
    knowledge: 1.0,
  },
  carverWeight: 0.6,
  shockWeight: 0.4,
  cvssWeight: 0.3,
  criticalThreshold: 80,
  highThreshold: 60,
  mediumThreshold: 35,
};


// ─── Hardened Scoring Function ───────────────────────────────────────

export interface HardenedScoringResult extends ScoringResult {
  /** Whether fallback scoring was used */
  usedFallback: boolean;
  /** Validation warnings (non-fatal issues that were auto-corrected) */
  validationWarnings: string[];
  /** Audit trail of sanitization actions */
  sanitizationLog: string[];
}

/**
 * Hardened version of computeHybridRisk that:
 * 1. Validates and sanitizes all inputs
 * 2. Catches NaN/undefined/null at every stage
 * 3. Falls back to deterministic scoring if the main computation fails
 * 4. Returns an audit trail of all corrections made
 */
export function computeHybridRiskHardened(
  rawInput: any,
  rawProfile: any
): HardenedScoringResult {
  const warnings: string[] = [];
  const sanitizationLog: string[] = [];

  // Step 1: Sanitize inputs
  const input = sanitizeScoringInput(rawInput);
  const profile = sanitizeScoringProfile(rawProfile);

  // Log any corrections
  if (rawInput?.carver) {
    for (const key of Object.keys(DEFAULT_CARVER_SCORES)) {
      const orig = rawInput.carver[key];
      const sanitized = (input.carver as any)[key];
      if (orig !== undefined && orig !== sanitized) {
        sanitizationLog.push(`CARVER.${key}: ${orig} → ${sanitized} (corrected)`);
      }
    }
  } else {
    sanitizationLog.push("CARVER scores: missing, using defaults");
  }

  if (rawInput?.shock) {
    for (const key of Object.keys(DEFAULT_SHOCK_SCORES)) {
      const orig = rawInput.shock[key];
      const sanitized = (input.shock as any)[key];
      if (orig !== undefined && orig !== sanitized) {
        sanitizationLog.push(`Shock.${key}: ${orig} → ${sanitized} (corrected)`);
      }
    }
  } else {
    sanitizationLog.push("Shock scores: missing, using defaults");
  }

  // Step 2: Division-by-zero guard on profile weights
  if (profile.carverWeight + profile.shockWeight === 0) {
    warnings.push("carverWeight + shockWeight = 0, resetting to defaults");
    profile.carverWeight = 0.6;
    profile.shockWeight = 0.4;
  }

  // Step 3: Try the main scoring computation
  try {
    const result = computeHybridRisk(input, profile);

    // Step 4: Validate output — check for NaN in result
    if (isNaN(result.hybridRiskScore) || !isFinite(result.hybridRiskScore)) {
      warnings.push("hybridRiskScore was NaN/Infinity, falling back to deterministic scoring");
      return {
        ...computeFallbackScore(input, profile),
        usedFallback: true,
        validationWarnings: warnings,
        sanitizationLog,
      };
    }

    return {
      ...result,
      usedFallback: false,
      validationWarnings: warnings,
      sanitizationLog,
    };
  } catch (err: any) {
    // Step 5: Fallback scoring
    warnings.push(`Main scoring failed: ${err.message}, using fallback`);
    return {
      ...computeFallbackScore(input, profile),
      usedFallback: true,
      validationWarnings: warnings,
      sanitizationLog,
    };
  }
}


// ─── Deterministic Fallback Scoring ──────────────────────────────────

/**
 * Pure deterministic scoring that doesn't depend on any external calls.
 * Used when the main scoring pipeline fails or produces invalid results.
 */
function computeFallbackScore(input: ScoringInput, profile: ScoringProfile): ScoringResult {
  // Simple weighted average — no LLM, no external data
  const carverComposite = computeCarverComposite(input.carver, profile.carverWeights);
  const shockComposite = computeShockComposite(input.shock, profile.shockWeights);

  const carverNorm = profile.carverWeight / (profile.carverWeight + profile.shockWeight);
  const shockNorm = profile.shockWeight / (profile.carverWeight + profile.shockWeight);
  const missionImpact = Math.max(0, Math.min(10,
    (carverComposite * carverNorm + shockComposite * shockNorm) * (input.missionMultiplier ?? 1.0)
  ));

  const impact = Math.max(0, Math.min(1, missionImpact / 10));
  const likelihood = Math.max(0, Math.min(1,
    (input.confirmedVulnScore !== undefined ? input.confirmedVulnScore / 100 : 0.1) *
    (0.55 + input.confidence * 0.45)
  ));

  const hybridRiskScore = Math.round(Math.sqrt(impact * likelihood) * 100);

  let riskBand: "critical" | "high" | "medium" | "low";
  if (hybridRiskScore >= profile.criticalThreshold) riskBand = "critical";
  else if (hybridRiskScore >= profile.highThreshold) riskBand = "high";
  else if (hybridRiskScore >= profile.mediumThreshold) riskBand = "medium";
  else riskBand = "low";

  return {
    carverComposite: Math.round(carverComposite * 100) / 100,
    shockComposite: Math.round(shockComposite * 100) / 100,
    missionImpactScore: Math.round(missionImpact * 100) / 100,
    impactScore: Math.round(impact * 100),
    likelihoodScore: Math.round(likelihood * 100),
    hybridRiskScore,
    riskBand,
    factorContributions: [
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
    ],
  };
}


// ─── Deterministic Fallback Classification ───────────────────────────

/**
 * Deterministic asset classification fallback when LLM is unavailable.
 * Uses hostname pattern matching and technology fingerprints to infer classification.
 */
export function classifyAssetDeterministic(asset: {
  hostname: string;
  assetType: string;
  technologies?: any[];
  tags?: string[];
}): Partial<AssetClassification> {
  const h = (asset.hostname || "").toLowerCase();
  const techs = (asset.technologies || []).map((t: any) => (typeof t === "string" ? t : t?.name || "").toLowerCase());
  const allSignals = [h, ...techs, ...(asset.tags || []).map(t => t.toLowerCase())];

  // Pattern-based device type inference
  let deviceType: string = "unknown";
  let platformType: string = "unknown";
  let missionFunction: string = "operational_continuity";
  let businessImpactLevel: "mission_critical" | "business_essential" | "operational" | "administrative" = "operational";
  let criticalityTier: CriticalityTier = 4;

  // Web servers
  if (allSignals.some(s => /nginx|apache|iis|httpd|caddy|traefik/.test(s))) {
    deviceType = "web_server";
    platformType = "web_application";
  }

  // Databases
  if (allSignals.some(s => /mysql|postgres|mongodb|redis|elastic|mariadb|mssql|oracle/.test(s))) {
    deviceType = "database_server";
    platformType = "data_store";
    missionFunction = "data_management";
    businessImpactLevel = "business_essential";
    criticalityTier = 2;
  }

  // Authentication / SSO
  if (allSignals.some(s => /auth|sso|login|ldap|keycloak|okta|adfs|saml|oauth/.test(s))) {
    deviceType = "identity_provider";
    platformType = "authentication";
    missionFunction = "identity_management";
    businessImpactLevel = "mission_critical";
    criticalityTier = 1;
  }

  // Email
  if (allSignals.some(s => /mail|smtp|imap|pop3|exchange|postfix/.test(s))) {
    deviceType = "mail_server";
    platformType = "email";
    missionFunction = "communications";
    businessImpactLevel = "business_essential";
    criticalityTier = 2;
  }

  // DNS
  if (allSignals.some(s => /dns|bind|named|ns1|ns2/.test(s))) {
    deviceType = "dns_server";
    platformType = "infrastructure";
    missionFunction = "network_infrastructure";
    businessImpactLevel = "mission_critical";
    criticalityTier = 1;
  }

  // CDN / Static — check with word boundaries to avoid matching 'cd' in CI/CD
  if (allSignals.some(s => /\bcdn\b|cloudfront|akamai|fastly|\bstatic\b/.test(s))) {
    deviceType = "cdn_node";
    platformType = "content_delivery";
    missionFunction = "operational_continuity";
    businessImpactLevel = "administrative";
    criticalityTier = 4;
  }

  // API Gateway
  if (allSignals.some(s => /api|gateway|graphql|rest/.test(s))) {
    deviceType = "api_gateway";
    platformType = "api_service";
    missionFunction = "service_delivery";
    businessImpactLevel = "business_essential";
    criticalityTier = 2;
  }

  // Payment
  if (allSignals.some(s => /pay|stripe|braintree|checkout|billing/.test(s))) {
    deviceType = "payment_processor";
    platformType = "financial_service";
    missionFunction = "financial_operations";
    businessImpactLevel = "mission_critical";
    criticalityTier = 1;
  }

  // CI/CD — use word boundaries to avoid false positives
  if (allSignals.some(s => /jenkins|gitlab-ci|github-actions|\bci\b|\bcd\b|deploy|\bbuild\b/.test(s))) {
    deviceType = "ci_cd_server";
    platformType = "development_tools";
    missionFunction = "development_operations";
    businessImpactLevel = "operational";
    criticalityTier = 3;
  }

  // VPN / Firewall
  if (allSignals.some(s => /vpn|firewall|fortinet|palo|checkpoint|wireguard/.test(s))) {
    deviceType = "network_appliance";
    platformType = "network_security";
    missionFunction = "network_infrastructure";
    businessImpactLevel = "mission_critical";
    criticalityTier = 1;
  }

  return {
    deviceType: deviceType as AssetClassification["deviceType"],
    platformType: platformType as AssetClassification["platformType"],
    missionFunction: missionFunction as AssetClassification["missionFunction"],
    businessImpactLevel,
    criticalityTier,
    classificationConfidence: 0.4, // Lower confidence for deterministic classification
    reasoning: `Deterministic fallback: hostname="${asset.hostname}", type="${asset.assetType}", tech=[${techs.slice(0, 3).join(",")}]`,
  };
}


// ─── Scoring Validation Report ───────────────────────────────────────

export interface ScoringValidationReport {
  totalAssets: number;
  scoredAssets: number;
  fallbackAssets: number;
  nanDetected: number;
  correctedInputs: number;
  riskDistribution: Record<string, number>;
  warnings: string[];
}

export function generateScoringValidationReport(
  results: Array<{ assetId: string; result: HardenedScoringResult }>
): ScoringValidationReport {
  const report: ScoringValidationReport = {
    totalAssets: results.length,
    scoredAssets: results.filter(r => r.result.hybridRiskScore > 0).length,
    fallbackAssets: results.filter(r => r.result.usedFallback).length,
    nanDetected: results.filter(r => r.result.validationWarnings.some(w => w.includes("NaN"))).length,
    correctedInputs: results.filter(r => r.result.sanitizationLog.length > 0).length,
    riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
    warnings: [],
  };

  for (const r of results) {
    report.riskDistribution[r.result.riskBand]++;
  }

  // Check for suspicious distributions
  const total = results.length;
  if (total > 5) {
    const criticalPct = (report.riskDistribution.critical / total) * 100;
    if (criticalPct > 30) {
      report.warnings.push(`${criticalPct.toFixed(0)}% of assets scored critical — possible over-inflation`);
    }
    if (criticalPct === 0 && report.riskDistribution.high === 0) {
      report.warnings.push("No critical or high-risk assets — possible under-scoring");
    }
    if (report.fallbackAssets > total * 0.5) {
      report.warnings.push(`${report.fallbackAssets}/${total} assets used fallback scoring — LLM classification may be failing`);
    }
  }

  return report;
}
