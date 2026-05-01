/**
 * ICD 203 Analytical Confidence Framework
 * 
 * Implements the Intelligence Community Directive 203 standard for analytical
 * confidence in intelligence products. Provides:
 * 
 * 1. Confidence Levels (High/Moderate/Low) with IC-standard definitions
 * 2. Source Reliability Tracking with category-based baseline reliability
 * 3. Named Assumptions Framework for explicit analytical dependency tracking
 * 4. Confidence Computation Engine that aggregates sources into overall confidence
 * 
 * This framework is foundational — it integrates with hybrid scoring, findings,
 * report pipeline, and all analytical products across the platform.
 * 
 * Reference: ICD 203 — Analytic Standards (ODNI, 2015)
 */

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE LEVELS
// ─────────────────────────────────────────────────────────────────────────────

export type ConfidenceLevel = 'high' | 'moderate' | 'low';

export interface ConfidenceLevelDefinition {
  level: ConfidenceLevel;
  numericRange: [number, number]; // 0.0 - 1.0
  definition: string;
  characteristics: string[];
  exampleInAC3: string;
}

/**
 * IC-standard confidence level definitions.
 * These are calibration anchors that prevent confidence inflation.
 */
export const CONFIDENCE_DEFINITIONS: Record<ConfidenceLevel, ConfidenceLevelDefinition> = {
  high: {
    level: 'high',
    numericRange: [0.80, 1.0],
    definition: 'Analysis based on high-quality information from multiple independent sources, with corroborating evidence and sound logical inference. Alternative explanations have been considered and found less compelling.',
    characteristics: [
      'Multiple independent sources corroborate the assessment',
      'Evidence is directly observed or confirmed through testing',
      'Inference chain is short and well-supported',
      'Alternative explanations have been evaluated and rejected',
      'Assumptions are minimal and well-validated'
    ],
    exampleInAC3: 'Nuclei template confirmed vulnerability with version match and successful exploitation proof'
  },
  moderate: {
    level: 'moderate',
    numericRange: [0.50, 0.79],
    definition: 'Credibly sourced information that is plausible and logically consistent but not corroborated to the level of high confidence. Relies on fewer independent sources or involves inference chains with identifiable assumptions.',
    characteristics: [
      'Information is credibly sourced but not fully corroborated',
      'Inference chain involves identifiable assumptions',
      'Some alternative explanations remain plausible',
      'Evidence is indirect or partially confirmed',
      'Analysis depends on assumptions that are reasonable but unverified'
    ],
    exampleInAC3: 'CVE matched to confirmed software version but exploitation not verified; attack chain plausible based on architecture analysis'
  },
  low: {
    level: 'low',
    numericRange: [0.0, 0.49],
    definition: 'Information whose credibility or plausibility is questionable, or analysis based on fragmentary evidence with significant inference gaps. Alternative explanations remain viable and the analytical judgment may change with additional information.',
    characteristics: [
      'Single source or unverified information',
      'Significant inference gaps in the analytical chain',
      'Multiple alternative explanations remain viable',
      'Evidence is fragmentary or circumstantial',
      'Analysis depends on assumptions that are unverified or uncertain'
    ],
    exampleInAC3: 'CVE associated by vendor name only without version confirmation; potential vulnerability based on technology fingerprint alone'
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// SOURCE RELIABILITY
// ─────────────────────────────────────────────────────────────────────────────

export type SourceCategory =
  | 'confirmed_scanner'      // Direct scanner finding with template/signature match
  | 'version_corroborated'   // CVE matched to confirmed software version
  | 'exploitation_verified'  // Finding verified through actual exploitation
  | 'llm_inference'          // LLM-augmented analytical inference
  | 'osint_feed'             // Open source intelligence feed data
  | 'threat_intel_platform'  // Curated threat intelligence (SpicyTIP, etc.)
  | 'vendor_only_match'      // CVE associated by vendor name without version
  | 'operator_observation'   // Manual testing notes, professional judgment
  | 'customer_provided'      // Asset inventories, business context from customer
  | 'historical_engagement'  // Data from previous engagements with same target
  | 'certificate_analysis'   // Certificate transparency, cert chain analysis
  | 'dns_enumeration'        // DNS record analysis and enumeration
  | 'passive_fingerprint'    // Passive technology fingerprinting (headers, responses)
  | 'active_probe'           // Active probing/testing results
  | 'community_signature'    // Community-contributed signatures (JARM, etc.)
  | 'behavioral_analysis'    // Behavioral pattern analysis (timing, responses)
  | 'correlation_engine';    // Cross-source correlation inference

export interface SourceReliabilityProfile {
  category: SourceCategory;
  baselineReliability: number; // 0.0 - 1.0
  label: string;
  description: string;
  corroborationWeight: number; // How much this source contributes to corroboration
}

/**
 * Source reliability profiles with baseline assessments.
 * Baseline reliability represents the typical accuracy of this source category
 * when used in isolation. Corroboration weight represents how much independent
 * confirmation this source provides when combined with other sources.
 */
export const SOURCE_RELIABILITY_PROFILES: Record<SourceCategory, SourceReliabilityProfile> = {
  confirmed_scanner: {
    category: 'confirmed_scanner',
    baselineReliability: 0.92,
    label: 'Confirmed Scanner Finding',
    description: 'Direct scanner finding with template/signature match against known vulnerability pattern',
    corroborationWeight: 0.9
  },
  version_corroborated: {
    category: 'version_corroborated',
    baselineReliability: 0.85,
    label: 'Version-Corroborated CVE',
    description: 'CVE matched to confirmed software version through banner/header/fingerprint analysis',
    corroborationWeight: 0.85
  },
  exploitation_verified: {
    category: 'exploitation_verified',
    baselineReliability: 0.98,
    label: 'Exploitation Verified',
    description: 'Finding verified through actual exploitation attempt with confirmed impact',
    corroborationWeight: 0.95
  },
  llm_inference: {
    category: 'llm_inference',
    baselineReliability: 0.65,
    label: 'LLM-Augmented Inference',
    description: 'Analytical inference produced by LLM specialist with evidence context',
    corroborationWeight: 0.5
  },
  osint_feed: {
    category: 'osint_feed',
    baselineReliability: 0.70,
    label: 'OSINT Feed',
    description: 'Open source intelligence from curated feeds (abuse.ch, URLScan, etc.)',
    corroborationWeight: 0.6
  },
  threat_intel_platform: {
    category: 'threat_intel_platform',
    baselineReliability: 0.80,
    label: 'Threat Intelligence Platform',
    description: 'Curated threat intelligence from platforms (SpicyTIP, NVD, CISA KEV)',
    corroborationWeight: 0.75
  },
  vendor_only_match: {
    category: 'vendor_only_match',
    baselineReliability: 0.35,
    label: 'Vendor-Only CVE Match',
    description: 'CVE associated by vendor name without specific version confirmation',
    corroborationWeight: 0.3
  },
  operator_observation: {
    category: 'operator_observation',
    baselineReliability: 0.75,
    label: 'Operator Observation',
    description: 'Manual testing notes and professional judgment from qualified operator',
    corroborationWeight: 0.7
  },
  customer_provided: {
    category: 'customer_provided',
    baselineReliability: 0.60,
    label: 'Customer-Provided Data',
    description: 'Asset inventories, business context, and compliance scope from customer',
    corroborationWeight: 0.5
  },
  historical_engagement: {
    category: 'historical_engagement',
    baselineReliability: 0.72,
    label: 'Historical Engagement Data',
    description: 'Data from previous engagements with same target (may be stale)',
    corroborationWeight: 0.6
  },
  certificate_analysis: {
    category: 'certificate_analysis',
    baselineReliability: 0.88,
    label: 'Certificate Analysis',
    description: 'Certificate transparency logs, cert chain analysis, issuer identification',
    corroborationWeight: 0.8
  },
  dns_enumeration: {
    category: 'dns_enumeration',
    baselineReliability: 0.90,
    label: 'DNS Enumeration',
    description: 'DNS record analysis including A, AAAA, MX, TXT, CNAME, NS records',
    corroborationWeight: 0.85
  },
  passive_fingerprint: {
    category: 'passive_fingerprint',
    baselineReliability: 0.72,
    label: 'Passive Fingerprint',
    description: 'Technology identification from response headers, HTML content, behavior',
    corroborationWeight: 0.6
  },
  active_probe: {
    category: 'active_probe',
    baselineReliability: 0.88,
    label: 'Active Probe',
    description: 'Results from active probing/testing (port scan, service enumeration)',
    corroborationWeight: 0.8
  },
  community_signature: {
    category: 'community_signature',
    baselineReliability: 0.68,
    label: 'Community Signature',
    description: 'Community-contributed signatures and fingerprints (JARM, Shodan tags)',
    corroborationWeight: 0.55
  },
  behavioral_analysis: {
    category: 'behavioral_analysis',
    baselineReliability: 0.60,
    label: 'Behavioral Analysis',
    description: 'Behavioral pattern analysis based on timing, response characteristics',
    corroborationWeight: 0.5
  },
  correlation_engine: {
    category: 'correlation_engine',
    baselineReliability: 0.70,
    label: 'Correlation Engine',
    description: 'Cross-source correlation inference combining multiple data points',
    corroborationWeight: 0.65
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// NAMED ASSUMPTIONS
// ─────────────────────────────────────────────────────────────────────────────

export type AssumptionCategory =
  | 'environmental'    // Target environment continues to operate as observed
  | 'temporal'         // Time-sensitive conditions still hold
  | 'capability'       // Adversary/defender capability assumptions
  | 'business_context' // Customer-provided business context is accurate
  | 'technical'        // Technical conditions or configurations assumed
  | 'scope'            // Scope boundaries and their implications
  | 'operational';     // Operational conditions during assessment

export interface NamedAssumption {
  id: string;
  category: AssumptionCategory;
  statement: string;
  impact: 'critical' | 'significant' | 'minor'; // Impact if assumption is wrong
  validationStatus: 'validated' | 'reasonable' | 'unverified' | 'stale';
  validatedBy?: string; // Source that validated the assumption
  validatedAt?: number; // Timestamp of validation
  expiresAt?: number;   // When the assumption should be re-validated
  dependentClaims: string[]; // IDs of claims that depend on this assumption
}

export interface AssumptionSet {
  assumptions: NamedAssumption[];
  lastReviewed: number;
  reviewedBy?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANALYTICAL CLAIM (Core unit of analysis)
// ─────────────────────────────────────────────────────────────────────────────

export interface AnalyticalSource {
  id: string;
  category: SourceCategory;
  description: string;
  reliability: number; // Override of baseline if context-specific
  timestamp: number;
  rawEvidence?: string; // Reference to underlying evidence
  toolOrigin?: string;  // Which tool produced this (nuclei, zap, httpx, etc.)
}

export interface AnalyticalClaim {
  id: string;
  statement: string;
  confidence: ConfidenceLevel;
  confidenceScore: number; // 0.0 - 1.0 numeric score
  sources: AnalyticalSource[];
  assumptions: string[]; // IDs of named assumptions this claim depends on
  alternativeExplanations?: string[]; // Considered and rejected alternatives
  inferenceChainLength: number; // How many logical steps from evidence to claim
  corroborationCount: number; // Number of independent sources
  computedAt: number;
  computedBy: 'engine' | 'operator' | 'llm'; // Who/what produced the confidence assessment
  overriddenBy?: string; // If operator overrode the computed confidence
  overrideReason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE COMPUTATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

export interface ConfidenceComputationInput {
  sources: AnalyticalSource[];
  assumptions: NamedAssumption[];
  inferenceChainLength: number;
  alternativeExplanationsConsidered: number;
  alternativeExplanationsRejected: number;
}

export interface ConfidenceComputationResult {
  level: ConfidenceLevel;
  score: number;
  breakdown: {
    sourceReliabilityScore: number;
    corroborationBonus: number;
    inferenceChainPenalty: number;
    assumptionPenalty: number;
    alternativeExplanationBonus: number;
  };
  rationale: string;
}

/**
 * Compute analytical confidence from sources, assumptions, and inference characteristics.
 * 
 * The computation follows IC methodology:
 * 1. Base score from weighted source reliability
 * 2. Corroboration bonus for independent source agreement
 * 3. Inference chain penalty for longer logical chains
 * 4. Assumption penalty for unverified/critical assumptions
 * 5. Alternative explanation bonus for considered-and-rejected alternatives
 */
export function computeConfidence(input: ConfidenceComputationInput): ConfidenceComputationResult {
  const { sources, assumptions, inferenceChainLength, alternativeExplanationsConsidered, alternativeExplanationsRejected } = input;

  if (sources.length === 0) {
    return {
      level: 'low',
      score: 0.1,
      breakdown: {
        sourceReliabilityScore: 0,
        corroborationBonus: 0,
        inferenceChainPenalty: 0,
        assumptionPenalty: 0,
        alternativeExplanationBonus: 0
      },
      rationale: 'No sources provided; confidence cannot be assessed.'
    };
  }

  // Step 1: Weighted source reliability (highest source weighted most, diminishing returns)
  const sortedSources = [...sources].sort((a, b) => b.reliability - a.reliability);
  let sourceReliabilityScore = 0;
  let totalWeight = 0;
  for (let i = 0; i < sortedSources.length; i++) {
    const weight = 1 / (i + 1); // Diminishing weight: 1, 0.5, 0.33, 0.25...
    sourceReliabilityScore += sortedSources[i].reliability * weight;
    totalWeight += weight;
  }
  sourceReliabilityScore = sourceReliabilityScore / totalWeight;

  // Step 2: Corroboration bonus (independent sources agreeing)
  const independentSourceCount = countIndependentSources(sources);
  const corroborationBonus = Math.min(0.15, (independentSourceCount - 1) * 0.05);

  // Step 3: Inference chain penalty (longer chains = more uncertainty)
  const inferenceChainPenalty = Math.min(0.25, (inferenceChainLength - 1) * 0.05);

  // Step 4: Assumption penalty (unverified or critical assumptions reduce confidence)
  let assumptionPenalty = 0;
  for (const assumption of assumptions) {
    if (assumption.validationStatus === 'unverified' && assumption.impact === 'critical') {
      assumptionPenalty += 0.12;
    } else if (assumption.validationStatus === 'unverified' && assumption.impact === 'significant') {
      assumptionPenalty += 0.07;
    } else if (assumption.validationStatus === 'stale') {
      assumptionPenalty += 0.05;
    } else if (assumption.validationStatus === 'unverified' && assumption.impact === 'minor') {
      assumptionPenalty += 0.03;
    }
  }
  assumptionPenalty = Math.min(0.35, assumptionPenalty);

  // Step 5: Alternative explanation bonus (considering and rejecting alternatives shows rigor)
  const alternativeExplanationBonus = alternativeExplanationsConsidered > 0
    ? Math.min(0.10, (alternativeExplanationsRejected / alternativeExplanationsConsidered) * 0.10)
    : 0;

  // Compute final score
  const rawScore = sourceReliabilityScore + corroborationBonus - inferenceChainPenalty - assumptionPenalty + alternativeExplanationBonus;
  const score = Math.max(0.05, Math.min(1.0, rawScore));

  // Determine level from score
  const level = scoreToLevel(score);

  // Generate rationale
  const rationale = generateRationale(level, sources, independentSourceCount, inferenceChainLength, assumptions, alternativeExplanationsConsidered);

  return {
    level,
    score,
    breakdown: {
      sourceReliabilityScore,
      corroborationBonus,
      inferenceChainPenalty,
      assumptionPenalty,
      alternativeExplanationBonus
    },
    rationale
  };
}

/**
 * Convert numeric score to confidence level.
 */
export function scoreToLevel(score: number): ConfidenceLevel {
  if (score >= 0.80) return 'high';
  if (score >= 0.50) return 'moderate';
  return 'low';
}

/**
 * Convert confidence level to numeric midpoint for comparisons.
 */
export function levelToScore(level: ConfidenceLevel): number {
  switch (level) {
    case 'high': return 0.90;
    case 'moderate': return 0.65;
    case 'low': return 0.30;
  }
}

/**
 * Count independent source categories (sources from different categories count as independent).
 */
function countIndependentSources(sources: AnalyticalSource[]): number {
  const categories = new Set(sources.map(s => s.category));
  return categories.size;
}

/**
 * Generate human-readable rationale for the confidence assessment.
 */
function generateRationale(
  level: ConfidenceLevel,
  sources: AnalyticalSource[],
  independentSourceCount: number,
  inferenceChainLength: number,
  assumptions: NamedAssumption[],
  alternativesConsidered: number
): string {
  const parts: string[] = [];

  // Source description
  if (sources.length === 1) {
    const profile = SOURCE_RELIABILITY_PROFILES[sources[0].category];
    parts.push(`Based on a single source (${profile.label}).`);
  } else {
    parts.push(`Based on ${sources.length} sources from ${independentSourceCount} independent categories.`);
  }

  // Corroboration
  if (independentSourceCount >= 3) {
    parts.push('Multiple independent sources corroborate this assessment.');
  } else if (independentSourceCount === 2) {
    parts.push('Two independent source categories provide partial corroboration.');
  }

  // Inference chain
  if (inferenceChainLength > 3) {
    parts.push(`Inference chain involves ${inferenceChainLength} logical steps, introducing cumulative uncertainty.`);
  } else if (inferenceChainLength > 1) {
    parts.push(`Inference chain involves ${inferenceChainLength} logical steps.`);
  }

  // Assumptions
  const unverifiedCritical = assumptions.filter(a => a.validationStatus === 'unverified' && a.impact === 'critical');
  if (unverifiedCritical.length > 0) {
    parts.push(`${unverifiedCritical.length} critical assumption(s) remain unverified, which constrains confidence.`);
  }

  // Alternatives
  if (alternativesConsidered > 0) {
    parts.push(`${alternativesConsidered} alternative explanation(s) were considered.`);
  }

  return parts.join(' ');
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING CONFIDENCE ASSESSMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Assess confidence for a vulnerability finding based on its evidence chain.
 * Maps directly to the existing DI corroboration tiers but with full IC methodology.
 */
export interface FindingConfidenceInput {
  // Evidence characteristics
  hasVersionMatch: boolean;
  hasExploitVerification: boolean;
  hasScannerConfirmation: boolean;
  hasManualVerification: boolean;
  hasMultipleToolCorroboration: boolean;
  // Context
  cveAssociationMethod: 'version_confirmed' | 'vendor_only' | 'technology_inferred' | 'exploit_verified';
  evidenceAge: number; // Days since evidence was collected
  targetAccessLevel: 'direct' | 'indirect' | 'inferred';
  // Assumptions
  assumesCurrentConfiguration: boolean;
  assumesNoMitigation: boolean;
  assumesNetworkAccessibility: boolean;
}

/**
 * Quick confidence assessment for a vulnerability finding.
 * Produces a confidence level and rationale without requiring full source/assumption objects.
 */
export function assessFindingConfidence(input: FindingConfidenceInput): {
  level: ConfidenceLevel;
  score: number;
  rationale: string;
  tier: 'confirmed' | 'probable' | 'potential'; // Maps to existing DI tiers
} {
  let score = 0.30; // Base score

  // Evidence quality boosters
  if (input.hasExploitVerification) score += 0.40;
  else if (input.hasScannerConfirmation) score += 0.30;
  else if (input.hasVersionMatch) score += 0.20;

  if (input.hasManualVerification) score += 0.15;
  if (input.hasMultipleToolCorroboration) score += 0.10;

  // CVE association method
  switch (input.cveAssociationMethod) {
    case 'exploit_verified': score += 0.10; break;
    case 'version_confirmed': score += 0.05; break;
    case 'vendor_only': score -= 0.15; break;
    case 'technology_inferred': score -= 0.20; break;
  }

  // Evidence staleness penalty
  if (input.evidenceAge > 90) score -= 0.10;
  else if (input.evidenceAge > 30) score -= 0.05;

  // Access level
  if (input.targetAccessLevel === 'inferred') score -= 0.10;
  else if (input.targetAccessLevel === 'indirect') score -= 0.05;

  // Assumption penalties
  if (input.assumesCurrentConfiguration) score -= 0.03;
  if (input.assumesNoMitigation) score -= 0.05;
  if (input.assumesNetworkAccessibility) score -= 0.03;

  // Clamp
  score = Math.max(0.05, Math.min(1.0, score));

  const level = scoreToLevel(score);

  // Map to existing DI tiers for backward compatibility
  let tier: 'confirmed' | 'probable' | 'potential';
  if (score >= 0.75) tier = 'confirmed';
  else if (score >= 0.50) tier = 'probable';
  else tier = 'potential';

  // Generate rationale
  const rationaleparts: string[] = [];
  if (input.hasExploitVerification) rationaleparts.push('Exploitation verified.');
  else if (input.hasScannerConfirmation) rationaleparts.push('Scanner confirmation with signature match.');
  else if (input.hasVersionMatch) rationaleparts.push('Version match confirmed.');
  else rationaleparts.push('Association based on vendor/technology inference only.');

  if (input.hasMultipleToolCorroboration) rationaleparts.push('Multiple tools corroborate.');
  if (input.cveAssociationMethod === 'vendor_only') rationaleparts.push('CVE associated by vendor name only — version unconfirmed.');
  if (input.evidenceAge > 30) rationaleparts.push(`Evidence is ${input.evidenceAge} days old.`);
  if (input.assumesNoMitigation) rationaleparts.push('Assumes no compensating controls in place.');

  return {
    level,
    score,
    rationale: rationaleparts.join(' '),
    tier
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK CHAIN CONFIDENCE
// ─────────────────────────────────────────────────────────────────────────────

export interface AttackChainStep {
  stepNumber: number;
  technique: string;
  confidence: ConfidenceLevel;
  confidenceScore: number;
  sources: AnalyticalSource[];
  assumptions: string[];
}

/**
 * Compute overall confidence for an attack chain.
 * Chain confidence is bounded by the weakest link — the lowest-confidence step
 * in the chain constrains the overall assessment.
 */
export function computeAttackChainConfidence(steps: AttackChainStep[]): {
  overallLevel: ConfidenceLevel;
  overallScore: number;
  weakestLink: number; // Step number of the weakest link
  rationale: string;
} {
  if (steps.length === 0) {
    return { overallLevel: 'low', overallScore: 0.1, weakestLink: 0, rationale: 'No steps in chain.' };
  }

  // Find weakest link
  let weakestStep = steps[0];
  for (const step of steps) {
    if (step.confidenceScore < weakestStep.confidenceScore) {
      weakestStep = step;
    }
  }

  // Chain confidence is weakest link minus a small penalty for chain length
  const chainLengthPenalty = Math.min(0.15, (steps.length - 1) * 0.03);
  const overallScore = Math.max(0.05, weakestStep.confidenceScore - chainLengthPenalty);
  const overallLevel = scoreToLevel(overallScore);

  const rationale = `Chain confidence bounded by Step ${weakestStep.stepNumber} (${weakestStep.technique}, ${weakestStep.confidence} confidence). Chain length of ${steps.length} steps introduces ${(chainLengthPenalty * 100).toFixed(0)}% cumulative uncertainty.`;

  return {
    overallLevel,
    overallScore,
    weakestLink: weakestStep.stepNumber,
    rationale
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE METADATA FOR REPORTS
// ─────────────────────────────────────────────────────────────────────────────

export interface ReportConfidenceMetadata {
  overallAssessmentConfidence: ConfidenceLevel;
  findingConfidenceDistribution: {
    high: number;
    moderate: number;
    low: number;
  };
  keyAssumptions: NamedAssumption[];
  coverageGaps: string[]; // Placeholder for Q2 Intelligence Gaps feature
  analyticalLimitations: string[];
  sourceProfile: {
    category: SourceCategory;
    count: number;
    averageReliability: number;
  }[];
  confidenceStatement: string; // IC-style confidence statement for the report
}

/**
 * Generate confidence metadata for an entire report.
 * Produces the IC-style confidence statement and distribution summary.
 */
export function generateReportConfidenceMetadata(
  findings: Array<{ confidence: ConfidenceLevel; score: number }>,
  assumptions: NamedAssumption[],
  sources: AnalyticalSource[],
  analyticalLimitations: string[]
): ReportConfidenceMetadata {
  // Distribution
  const distribution = { high: 0, moderate: 0, low: 0 };
  for (const f of findings) {
    distribution[f.confidence]++;
  }

  // Overall assessment confidence (weighted by finding count)
  const totalFindings = findings.length;
  let weightedScore = 0;
  for (const f of findings) {
    weightedScore += f.score;
  }
  const avgScore = totalFindings > 0 ? weightedScore / totalFindings : 0.5;
  const overallConfidence = scoreToLevel(avgScore);

  // Source profile
  const sourceMap = new Map<SourceCategory, { count: number; totalReliability: number }>();
  for (const s of sources) {
    const existing = sourceMap.get(s.category) || { count: 0, totalReliability: 0 };
    existing.count++;
    existing.totalReliability += s.reliability;
    sourceMap.set(s.category, existing);
  }
  const sourceProfile = Array.from(sourceMap.entries()).map(([category, data]) => ({
    category,
    count: data.count,
    averageReliability: data.totalReliability / data.count
  })).sort((a, b) => b.count - a.count);

  // Key assumptions (critical and significant only)
  const keyAssumptions = assumptions.filter(a => a.impact === 'critical' || a.impact === 'significant');

  // Generate confidence statement
  const confidenceStatement = generateConfidenceStatement(overallConfidence, distribution, totalFindings, keyAssumptions, analyticalLimitations);

  return {
    overallAssessmentConfidence: overallConfidence,
    findingConfidenceDistribution: distribution,
    keyAssumptions,
    coverageGaps: [], // Populated in Q2
    analyticalLimitations,
    sourceProfile,
    confidenceStatement
  };
}

/**
 * Generate IC-style confidence statement for a report.
 */
function generateConfidenceStatement(
  overall: ConfidenceLevel,
  distribution: { high: number; moderate: number; low: number },
  total: number,
  keyAssumptions: NamedAssumption[],
  limitations: string[]
): string {
  const parts: string[] = [];

  // Overall confidence
  parts.push(`We assess with ${overall} confidence that the findings in this report accurately characterize the target's security posture within the scope of assessment.`);

  // Distribution context
  const highPct = total > 0 ? Math.round((distribution.high / total) * 100) : 0;
  const modPct = total > 0 ? Math.round((distribution.moderate / total) * 100) : 0;
  const lowPct = total > 0 ? Math.round((distribution.low / total) * 100) : 0;
  parts.push(`Of ${total} findings, ${highPct}% are assessed at high confidence, ${modPct}% at moderate confidence, and ${lowPct}% at low confidence.`);

  // Key assumptions
  if (keyAssumptions.length > 0) {
    const criticalCount = keyAssumptions.filter(a => a.impact === 'critical').length;
    if (criticalCount > 0) {
      parts.push(`This assessment depends on ${criticalCount} critical assumption(s) that, if invalidated, could materially change the analytical conclusions.`);
    }
  }

  // Limitations
  if (limitations.length > 0) {
    parts.push(`Analytical limitations include: ${limitations.slice(0, 3).join('; ')}.`);
  }

  return parts.join(' ');
}

// ─────────────────────────────────────────────────────────────────────────────
// EXISTING EVIDENCE MULTIPLIER BRIDGE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Bridge function: converts existing evidence multiplier (1.0/0.85/0.3) to
 * the new confidence framework. This allows gradual migration without breaking
 * existing scoring.
 */
export function evidenceMultiplierToConfidence(multiplier: number): {
  level: ConfidenceLevel;
  score: number;
  sourceCategory: SourceCategory;
} {
  if (multiplier >= 0.95) {
    return { level: 'high', score: 0.92, sourceCategory: 'exploitation_verified' };
  } else if (multiplier >= 0.80) {
    return { level: 'high', score: 0.85, sourceCategory: 'version_corroborated' };
  } else if (multiplier >= 0.60) {
    return { level: 'moderate', score: 0.65, sourceCategory: 'passive_fingerprint' };
  } else if (multiplier >= 0.40) {
    return { level: 'low', score: 0.40, sourceCategory: 'vendor_only_match' };
  } else {
    return { level: 'low', score: 0.25, sourceCategory: 'vendor_only_match' };
  }
}

/**
 * Bridge function: converts existing DI corroboration tier to confidence level.
 */
export function corroborationTierToConfidence(tier: 'confirmed' | 'probable' | 'potential'): {
  level: ConfidenceLevel;
  score: number;
} {
  switch (tier) {
    case 'confirmed': return { level: 'high', score: 0.88 };
    case 'probable': return { level: 'moderate', score: 0.65 };
    case 'potential': return { level: 'low', score: 0.35 };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OPERATOR OVERRIDE
// ─────────────────────────────────────────────────────────────────────────────

export interface ConfidenceOverride {
  originalLevel: ConfidenceLevel;
  originalScore: number;
  overrideLevel: ConfidenceLevel;
  overrideScore: number;
  reason: string;
  overriddenBy: string; // Operator ID
  overriddenAt: number;
}

/**
 * Apply operator override to a confidence assessment.
 * Operators can override computed confidence with explicit justification.
 * The override is tracked for audit purposes.
 */
export function applyConfidenceOverride(
  original: { level: ConfidenceLevel; score: number },
  newLevel: ConfidenceLevel,
  reason: string,
  operatorId: string
): ConfidenceOverride {
  return {
    originalLevel: original.level,
    originalScore: original.score,
    overrideLevel: newLevel,
    overrideScore: levelToScore(newLevel),
    reason,
    overriddenBy: operatorId,
    overriddenAt: Date.now()
  };
}
