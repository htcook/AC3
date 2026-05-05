import "./chunk-KFQGP6VL.js";

// server/lib/temporal-decay.ts
var DEFAULT_TEMPORAL_CONFIG = {
  exploitMaturityWeight: 0.25,
  patchNegligenceWeight: 0.25,
  kevUrgencyWeight: 0.2,
  validationStalenessWeight: 0.15,
  findingAgeWeight: 0.15,
  validationStalenessDays: 30,
  patchNegligenceGraceDays: 14,
  kevUrgencyBoostDays: 30,
  maxMultiplier: 2,
  minMultiplier: 0.5
};
function calculateTemporalScore(factors, config = DEFAULT_TEMPORAL_CONFIG, now = Date.now()) {
  const breakdown = [];
  const warnings = [];
  const exploitMaturity = calculateExploitMaturity(factors, now);
  breakdown.push({
    name: "Exploit Maturity",
    weight: config.exploitMaturityWeight,
    multiplier: exploitMaturity.multiplier,
    description: exploitMaturity.description
  });
  const patchNegligence = calculatePatchNegligence(factors, config, now);
  breakdown.push({
    name: "Patch Negligence",
    weight: config.patchNegligenceWeight,
    multiplier: patchNegligence.multiplier,
    description: patchNegligence.description
  });
  if (patchNegligence.warning) warnings.push(patchNegligence.warning);
  const kevUrgency = calculateKevUrgency(factors, config, now);
  breakdown.push({
    name: "KEV Urgency",
    weight: config.kevUrgencyWeight,
    multiplier: kevUrgency.multiplier,
    description: kevUrgency.description
  });
  if (kevUrgency.warning) warnings.push(kevUrgency.warning);
  const validationStaleness = calculateValidationStaleness(factors, config, now);
  breakdown.push({
    name: "Validation Staleness",
    weight: config.validationStalenessWeight,
    multiplier: validationStaleness.multiplier,
    description: validationStaleness.description
  });
  if (validationStaleness.warning) warnings.push(validationStaleness.warning);
  const findingAge = calculateFindingAge(factors, now);
  breakdown.push({
    name: "Finding Age",
    weight: config.findingAgeWeight,
    multiplier: findingAge.multiplier,
    description: findingAge.description
  });
  let weightedMultiplier = 0;
  for (const factor of breakdown) {
    weightedMultiplier += factor.weight * factor.multiplier;
  }
  const temporalMultiplier = Math.max(
    config.minMultiplier,
    Math.min(config.maxMultiplier, weightedMultiplier)
  );
  const roundedMultiplier = Math.round(temporalMultiplier * 100) / 100;
  const adjustedScore = Math.min(10, Math.round(factors.baseScore * roundedMultiplier * 10) / 10);
  const adjustedSeverity = scoreToSeverity(adjustedScore);
  const urgencyLevel = determineUrgency(adjustedScore, warnings.length, factors.kevAddedDate !== null);
  const rationale = buildRationale(factors, roundedMultiplier, adjustedScore, adjustedSeverity, breakdown);
  return {
    baseScore: factors.baseScore,
    temporalMultiplier: roundedMultiplier,
    adjustedScore,
    adjustedSeverity,
    factors: breakdown,
    urgencyLevel,
    rationale,
    decayWarnings: warnings
  };
}
function batchTemporalScores(findings, config = DEFAULT_TEMPORAL_CONFIG) {
  const results = /* @__PURE__ */ new Map();
  const now = Date.now();
  for (const finding of findings) {
    results.set(finding.id, calculateTemporalScore(finding.factors, config, now));
  }
  return results;
}
function calculateExploitMaturity(factors, now) {
  if (!factors.exploitPublicDate && !factors.cvePublishedDate) {
    return { multiplier: 1, description: "No exploit maturity data available." };
  }
  if (factors.exploitPublicDate) {
    const daysSinceExploit = (now - factors.exploitPublicDate) / (24 * 60 * 60 * 1e3);
    if (daysSinceExploit < 7) {
      return { multiplier: 1.5, description: `Public exploit released ${Math.round(daysSinceExploit)} days ago. Zero-day window \u2014 maximum urgency.` };
    } else if (daysSinceExploit < 30) {
      return { multiplier: 1.3, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Active exploitation likely.` };
    } else if (daysSinceExploit < 90) {
      return { multiplier: 1.15, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Exploit is mature and widely available.` };
    } else {
      return { multiplier: 1.05, description: `Public exploit available for ${Math.round(daysSinceExploit)} days. Well-known exploit.` };
    }
  }
  if (factors.cvePublishedDate) {
    const daysSinceCve = (now - factors.cvePublishedDate) / (24 * 60 * 60 * 1e3);
    if (daysSinceCve < 30) {
      return { multiplier: 1.1, description: `CVE published ${Math.round(daysSinceCve)} days ago. Exploit development likely in progress.` };
    }
    return { multiplier: 1, description: `CVE published ${Math.round(daysSinceCve)} days ago. No public exploit known.` };
  }
  return { multiplier: 1, description: "No exploit maturity data." };
}
function calculatePatchNegligence(factors, config, now) {
  if (!factors.patchAvailableDate) {
    return { multiplier: 1, description: "No patch availability data.", warning: null };
  }
  const daysSincePatch = (now - factors.patchAvailableDate) / (24 * 60 * 60 * 1e3);
  if (daysSincePatch < config.patchNegligenceGraceDays) {
    return {
      multiplier: 0.9,
      description: `Patch available for ${Math.round(daysSincePatch)} days (within ${config.patchNegligenceGraceDays}-day grace period).`,
      warning: null
    };
  } else if (daysSincePatch < 30) {
    return {
      multiplier: 1.1,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Grace period exceeded.`,
      warning: `Patch has been available for ${Math.round(daysSincePatch)} days but not applied.`
    };
  } else if (daysSincePatch < 90) {
    return {
      multiplier: 1.3,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Significant negligence.`,
      warning: `OVERDUE: Patch available for ${Math.round(daysSincePatch)} days. Immediate patching recommended.`
    };
  } else {
    return {
      multiplier: 1.5,
      description: `Patch available for ${Math.round(daysSincePatch)} days. Critical negligence.`,
      warning: `CRITICAL NEGLIGENCE: Patch available for ${Math.round(daysSincePatch)} days. This represents a compliance risk.`
    };
  }
}
function calculateKevUrgency(factors, config, now) {
  if (!factors.kevAddedDate) {
    return { multiplier: 1, description: "Not listed in CISA KEV catalog.", warning: null };
  }
  const daysSinceKev = (now - factors.kevAddedDate) / (24 * 60 * 60 * 1e3);
  if (daysSinceKev < config.kevUrgencyBoostDays) {
    return {
      multiplier: 1.5,
      description: `Added to CISA KEV ${Math.round(daysSinceKev)} days ago. Active exploitation confirmed.`,
      warning: `CISA KEV ALERT: This vulnerability is under active exploitation (added ${Math.round(daysSinceKev)} days ago).`
    };
  } else if (daysSinceKev < 90) {
    return {
      multiplier: 1.3,
      description: `Listed in CISA KEV for ${Math.round(daysSinceKev)} days. Known exploited vulnerability.`,
      warning: `Listed in CISA KEV catalog. Federal agencies required to remediate.`
    };
  } else {
    return {
      multiplier: 1.15,
      description: `Listed in CISA KEV for ${Math.round(daysSinceKev)} days.`,
      warning: null
    };
  }
}
function calculateValidationStaleness(factors, config, now) {
  if (!factors.lastValidated) {
    return {
      multiplier: 0.8,
      description: "Finding has never been validated. Confidence reduced.",
      warning: "This finding has not been validated. Consider running validation to confirm exploitability."
    };
  }
  const daysSinceValidation = (now - factors.lastValidated) / (24 * 60 * 60 * 1e3);
  if (daysSinceValidation < config.validationStalenessDays) {
    return {
      multiplier: 1.1,
      description: `Validated ${Math.round(daysSinceValidation)} days ago. Recent validation boosts confidence.`,
      warning: null
    };
  } else if (daysSinceValidation < 90) {
    return {
      multiplier: 0.9,
      description: `Last validated ${Math.round(daysSinceValidation)} days ago. Validation becoming stale.`,
      warning: `Validation is ${Math.round(daysSinceValidation)} days old. Re-validation recommended.`
    };
  } else {
    return {
      multiplier: 0.7,
      description: `Last validated ${Math.round(daysSinceValidation)} days ago. Validation is stale.`,
      warning: `Validation is ${Math.round(daysSinceValidation)} days old. Re-validation required for accurate assessment.`
    };
  }
}
function calculateFindingAge(factors, now) {
  const daysSinceFirstSeen = (now - factors.findingFirstSeen) / (24 * 60 * 60 * 1e3);
  if (daysSinceFirstSeen < 7) {
    return { multiplier: 1.2, description: `New finding (${Math.round(daysSinceFirstSeen)} days old). Prioritize for triage.` };
  } else if (daysSinceFirstSeen < 30) {
    return { multiplier: 1.1, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old.` };
  } else if (daysSinceFirstSeen < 90) {
    return { multiplier: 1, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old. Standard priority.` };
  } else {
    return { multiplier: 1.15, description: `Finding is ${Math.round(daysSinceFirstSeen)} days old. Long-standing unresolved vulnerability.` };
  }
}
function scoreToSeverity(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}
function determineUrgency(score, warningCount, isKev) {
  if (score >= 9 && isKev) return "immediate";
  if (score >= 9 || score >= 7 && isKev) return "urgent";
  if (score >= 7 || warningCount >= 2) return "elevated";
  if (score >= 4) return "standard";
  return "deferred";
}
function buildRationale(factors, multiplier, adjustedScore, adjustedSeverity, breakdown) {
  const direction = multiplier > 1.05 ? "increased" : multiplier < 0.95 ? "decreased" : "unchanged";
  const topFactor = [...breakdown].sort((a, b) => Math.abs(b.multiplier - 1) - Math.abs(a.multiplier - 1))[0];
  return `Base score ${factors.baseScore} ${direction} to ${adjustedScore} (${adjustedSeverity}) with temporal multiplier ${multiplier}x. Primary driver: ${topFactor.name} (${topFactor.multiplier}x). ${breakdown.map((f) => `${f.name}: ${f.multiplier}x`).join(", ")}.`;
}
export {
  DEFAULT_TEMPORAL_CONFIG,
  batchTemporalScores,
  calculateTemporalScore
};
