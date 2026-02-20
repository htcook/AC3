/**
 * Temporal Decay Scoring
 * 
 * Adjusts vulnerability severity scores based on time-sensitive factors:
 * - Age of the finding (older unpatched = higher urgency)
 * - Time since CVE publication (exploit maturity increases over time)
 * - Time since last validation (stale validations lose confidence)
 * - KEV listing recency (recently added to KEV = active exploitation)
 * - Patch availability window (patch available but not applied = negligence)
 * 
 * Produces a temporal multiplier (0.5x - 2.0x) applied to base severity.
 * 
 * @module temporal-decay
 */

// ─── Types ─────────────────────────────────────────────────────────

export interface TemporalFactors {
  cvePublishedDate: number | null;      // Unix ms when CVE was published
  findingFirstSeen: number;              // Unix ms when finding was first detected
  lastValidated: number | null;          // Unix ms of last validation run
  patchAvailableDate: number | null;     // Unix ms when vendor patch was released
  kevAddedDate: number | null;           // Unix ms when added to CISA KEV
  exploitPublicDate: number | null;      // Unix ms when public exploit appeared
  baseSeverity: "critical" | "high" | "medium" | "low";
  baseScore: number;                     // CVSS base score (0-10)
}

export interface TemporalScore {
  baseScore: number;
  temporalMultiplier: number;            // 0.5 - 2.0
  adjustedScore: number;                 // baseScore * multiplier, capped at 10
  adjustedSeverity: "critical" | "high" | "medium" | "low";
  factors: TemporalFactorBreakdown[];
  urgencyLevel: "immediate" | "urgent" | "elevated" | "standard" | "deferred";
  rationale: string;
  decayWarnings: string[];
}

export interface TemporalFactorBreakdown {
  name: string;
  weight: number;          // How much this factor contributes
  multiplier: number;      // Individual factor multiplier
  description: string;
}

export interface TemporalConfig {
  // Weights for each factor (must sum to ~1.0)
  exploitMaturityWeight: number;
  patchNegligenceWeight: number;
  kevUrgencyWeight: number;
  validationStalenessWeight: number;
  findingAgeWeight: number;
  
  // Thresholds
  validationStalenessDays: number;       // After this many days, validation confidence drops
  patchNegligenceGraceDays: number;      // Grace period before "negligence" penalty
  kevUrgencyBoostDays: number;           // KEV items within this window get max boost
  maxMultiplier: number;
  minMultiplier: number;
}

export const DEFAULT_TEMPORAL_CONFIG: TemporalConfig = {
  exploitMaturityWeight: 0.25,
  patchNegligenceWeight: 0.25,
  kevUrgencyWeight: 0.20,
  validationStalenessWeight: 0.15,
  findingAgeWeight: 0.15,
  
  validationStalenessDays: 30,
  patchNegligenceGraceDays: 14,
  kevUrgencyBoostDays: 30,
  maxMultiplier: 2.0,
  minMultiplier: 0.5,
};

// ─── Core Scoring Functions ────────────────────────────────────────

/**
 * Calculate the temporal score for a finding.
 */
export function calculateTemporalScore(
  factors: TemporalFactors,
  config: TemporalConfig = DEFAULT_TEMPORAL_CONFIG,
  now: number = Date.now()
): TemporalScore {
  const breakdown: TemporalFactorBreakdown[] = [];
  const warnings: string[] = [];
  
  // 1. Exploit Maturity Factor
  const exploitMaturity = calculateExploitMaturity(factors, now);
  breakdown.push({
    name: "Exploit Maturity",
    weight: config.exploitMaturityWeight,
    multiplier: exploitMaturity.multiplier,
    description: exploitMaturity.description,
  });
  
  // 2. Patch Negligence Factor
  const patchNegligence = calculatePatchNegligence(factors, config, now);
  breakdown.push({
    name: "Patch Negligence",
    weight: config.patchNegligenceWeight,
    multiplier: patchNegligence.multiplier,
    description: patchNegligence.description,
  });
  if (patchNegligence.warning) warnings.push(patchNegligence.warning);
  
  // 3. KEV Urgency Factor
  const kevUrgency = calculateKevUrgency(factors, config, now);
  breakdown.push({
    name: "KEV Urgency",
    weight: config.kevUrgencyWeight,
    multiplier: kevUrgency.multiplier,
    description: kevUrgency.description,
  });
  if (kevUrgency.warning) warnings.push(kevUrgency.warning);
  
  // 4. Validation Staleness Factor
  const validationStaleness = calculateValidationStaleness(factors, config, now);
  breakdown.push({
    name: "Validation Staleness",
    weight: config.validationStalenessWeight,
    multiplier: validationStaleness.multiplier,
    description: validationStaleness.description,
  });
  if (validationStaleness.warning) warnings.push(validationStaleness.warning);
  
  // 5. Finding Age Factor
  const findingAge = calculateFindingAge(factors, now);
  breakdown.push({
    name: "Finding Age",
    weight: config.findingAgeWeight,
    multiplier: findingAge.multiplier,
    description: findingAge.description,
  });
  
  // Calculate weighted multiplier
  let weightedMultiplier = 0;
  for (const factor of breakdown) {
    weightedMultiplier += factor.weight * factor.multiplier;
  }
  
  // Clamp to configured range
  const temporalMultiplier = Math.max(
    config.minMultiplier,
    Math.min(config.maxMultiplier, weightedMultiplier)
  );
  
  // Round to 2 decimal places
  const roundedMultiplier = Math.round(temporalMultiplier * 100) / 100;
  
  // Calculate adjusted score
  const adjustedScore = Math.min(10, Math.round(factors.baseScore * roundedMultiplier * 10) / 10);
  const adjustedSeverity = scoreToSeverity(adjustedScore);
  
  // Determine urgency level
  const urgencyLevel = determineUrgency(adjustedScore, warnings.length, factors.kevAddedDate !== null);
  
  // Build rationale
  const rationale = buildRationale(factors, roundedMultiplier, adjustedScore, adjustedSeverity, breakdown);
  
  return {
    baseScore: factors.baseScore,
    temporalMultiplier: roundedMultiplier,
    adjustedScore,
    adjustedSeverity,
    factors: breakdown,
    urgencyLevel,
    rationale,
    decayWarnings: warnings,
  };
}

/**
 * Batch calculate temporal scores for multiple findings.
 */
export function batchTemporalScores(
  findings: Array<{ id: string; factors: TemporalFactors }>,
  config: TemporalConfig = DEFAULT_TEMPORAL_CONFIG
): Map<string, TemporalScore> {
  const results = new Map<string, TemporalScore>();
  const now = Date.now();
  
  for (const finding of findings) {
    results.set(finding.id, calculateTemporalScore(finding.factors, config, now));
  }
  
  return results;
}

// ─── Individual Factor Calculations ────────────────────────────────

function calculateExploitMaturity(
  factors: TemporalFactors,
  now: number
): { multiplier: number; description: string } {
  if (!factors.exploitPublicDate && !factors.cvePublishedDate) {
    return { multiplier: 1.0, description: "No exploit maturity data available." };
  }
  
  // If public exploit exists, maturity increases over time (more refined exploits)
  if (factors.exploitPublicDate) {
    const daysSinceExploit = (now - factors.exploitPublicDate) / (24 * 60 * 60 * 1000);
    
    if (daysSinceExploit < 7) {
      return { multiplier: 1.5, description: `Public exploit released ${Math.round(daysSinceExploit)} days ago. Zero-day window — maximum urgency.` };
    } else if (daysSinceExploit < 30) {
      return { multiplier: 1.3, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Active exploitation likely.` };
    } else if (daysSinceExploit < 90) {
      return { multiplier: 1.15, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Exploit is mature and widely available.` };
    } else {
      return { multiplier: 1.05, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Well-known exploit.` };
    }
  }
  
  // CVE published but no known public exploit
  if (factors.cvePublishedDate) {
    const daysSinceCve = (now - factors.cvePublishedDate) / (24 * 60 * 60 * 1000);
    if (daysSinceCve < 30) {
      return { multiplier: 1.1, description: `CVE published ${Math.round(daysSinceCve)} days ago. Exploit development likely in progress.` };
    }
    return { multiplier: 1.0, description: `CVE published ${Math.round(daysSinceCve)} days ago. No public exploit known.` };
  }
  
  return { multiplier: 1.0, description: "No exploit maturity data." };
}

function calculatePatchNegligence(
  factors: TemporalFactors,
  config: TemporalConfig,
  now: number
): { multiplier: number; description: string; warning: string | null } {
  if (!factors.patchAvailableDate) {
    return { multiplier: 1.0, description: "No patch availability data.", warning: null };
  }
  
  const daysSincePatch = (now - factors.patchAvailableDate) / (24 * 60 * 60 * 1000);
  
  if (daysSincePatch < config.patchNegligenceGraceDays) {
    return {
      multiplier: 0.9,
      description: `Patch available for ${Math.round(daysSincePatch)} days (within ${config.patchNegligenceGraceDays}-day grace period).`,
      warning: null,
    };
  } else if (daysSincePatch < 30) {
    return {
      multiplier: 1.1,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Grace period exceeded.`,
      warning: `Patch has been available for ${Math.round(daysSincePatch)} days but not applied.`,
    };
  } else if (daysSincePatch < 90) {
    return {
      multiplier: 1.3,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Significant negligence.`,
      warning: `OVERDUE: Patch available for ${Math.round(daysSincePatch)} days. Immediate patching recommended.`,
    };
  } else {
    return {
      multiplier: 1.5,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Critical negligence.`,
      warning: `CRITICAL NEGLIGENCE: Patch available for ${Math.round(daysSincePatch)} days. This represents a compliance risk.`,
    };
  }
}

function calculateKevUrgency(
  factors: TemporalFactors,
  config: TemporalConfig,
  now: number
): { multiplier: number; description: string; warning: string | null } {
  if (!factors.kevAddedDate) {
    return { multiplier: 1.0, description: "Not listed in CISA KEV catalog.", warning: null };
  }
  
  const daysSinceKev = (now - factors.kevAddedDate) / (24 * 60 * 60 * 1000);
  
  if (daysSinceKev < config.kevUrgencyBoostDays) {
    return {
      multiplier: 1.5,
      description: `Added to CISA KEV ${Math.round(daysSinceKev)} days ago. Active exploitation confirmed.`,
      warning: `CISA KEV ALERT: This vulnerability is under active exploitation (added ${Math.round(daysSinceKev)} days ago).`,
    };
  } else if (daysSinceKev < 90) {
    return {
      multiplier: 1.3,
      description: `Listed in CISA KEV for ${Math.round(daysSinceKev)} days. Known exploited vulnerability.`,
      warning: `Listed in CISA KEV catalog. Federal agencies required to remediate.`,
    };
  } else {
    return {
      multiplier: 1.15,
      description: `Listed in CISA KEV for ${Math.round(daysSinceKev)} days.`,
      warning: null,
    };
  }
}

function calculateValidationStaleness(
  factors: TemporalFactors,
  config: TemporalConfig,
  now: number
): { multiplier: number; description: string; warning: string | null } {
  if (!factors.lastValidated) {
    return {
      multiplier: 0.8,
      description: "Finding has never been validated. Confidence reduced.",
      warning: "This finding has not been validated. Consider running validation to confirm exploitability.",
    };
  }
  
  const daysSinceValidation = (now - factors.lastValidated) / (24 * 60 * 60 * 1000);
  
  if (daysSinceValidation < config.validationStalenessDays) {
    return {
      multiplier: 1.1,
      description: `Validated ${Math.round(daysSinceValidation)} days ago. Recent validation boosts confidence.`,
      warning: null,
    };
  } else if (daysSinceValidation < 90) {
    return {
      multiplier: 0.9,
      description: `Last validated ${Math.round(daysSinceValidation)} days ago. Validation becoming stale.`,
      warning: `Validation is ${Math.round(daysSinceValidation)} days old. Re-validation recommended.`,
    };
  } else {
    return {
      multiplier: 0.7,
      description: `Last validated ${Math.round(daysSinceValidation)} days ago. Validation is stale.`,
      warning: `Validation is ${Math.round(daysSinceValidation)} days old. Re-validation required for accurate assessment.`,
    };
  }
}

function calculateFindingAge(
  factors: TemporalFactors,
  now: number
): { multiplier: number; description: string } {
  const daysSinceFirstSeen = (now - factors.findingFirstSeen) / (24 * 60 * 60 * 1000);
  
  if (daysSinceFirstSeen < 7) {
    return { multiplier: 1.2, description: `New finding (${Math.round(daysSinceFirstSeen)} days old). Prioritize for triage.` };
  } else if (daysSinceFirstSeen < 30) {
    return { multiplier: 1.1, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old.` };
  } else if (daysSinceFirstSeen < 90) {
    return { multiplier: 1.0, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old. Standard priority.` };
  } else {
    return { multiplier: 1.15, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old. Long-standing unresolved vulnerability.` };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────

function scoreToSeverity(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function determineUrgency(
  score: number,
  warningCount: number,
  isKev: boolean
): TemporalScore["urgencyLevel"] {
  if (score >= 9.0 && isKev) return "immediate";
  if (score >= 9.0 || (score >= 7.0 && isKev)) return "urgent";
  if (score >= 7.0 || warningCount >= 2) return "elevated";
  if (score >= 4.0) return "standard";
  return "deferred";
}

function buildRationale(
  factors: TemporalFactors,
  multiplier: number,
  adjustedScore: number,
  adjustedSeverity: string,
  breakdown: TemporalFactorBreakdown[]
): string {
  const direction = multiplier > 1.05 ? "increased" : multiplier < 0.95 ? "decreased" : "unchanged";
  const topFactor = [...breakdown].sort((a, b) => Math.abs(b.multiplier - 1) - Math.abs(a.multiplier - 1))[0];
  
  return `Base score ${factors.baseScore} ${direction} to ${adjustedScore} (${adjustedSeverity}) with temporal multiplier ${multiplier}x. Primary driver: ${topFactor.name} (${topFactor.multiplier}x). ${breakdown.map(f => `${f.name}: ${f.multiplier}x`).join(", ")}.`;
}
