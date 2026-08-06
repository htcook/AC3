/**
 * Confidence Enrichment Integration
 * 
 * Bridges the ICD 203 Analytical Confidence Framework into the DI pipeline,
 * hybrid scoring engine, and report pipeline. This module enriches existing
 * findings with full confidence metadata without modifying the core DI engine.
 * 
 * Integration points:
 * 1. PostureFinding → AnalyticalClaim (finding-level confidence)
 * 2. AssetAnalysis → Confidence metadata for hybrid scoring
 * 3. Report Pipeline → ReportConfidenceMetadata for analytical products
 */

import {
  type ConfidenceLevel,
  type AnalyticalSource,
  type AnalyticalClaim,
  type NamedAssumption,
  type FindingConfidenceInput,
  type ReportConfidenceMetadata,
  type SourceCategory,
  type AttackChainStep,
  assessFindingConfidence,
  computeConfidence,
  computeAttackChainConfidence,
  generateReportConfidenceMetadata,
  evidenceMultiplierToConfidence,
  corroborationTierToConfidence,
  scoreToLevel,
  SOURCE_RELIABILITY_PROFILES,
  CONFIDENCE_DEFINITIONS
} from './analytical-confidence';

// ─────────────────────────────────────────────────────────────────────────────
// FINDING ENRICHMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enriched finding with full ICD 203 confidence metadata.
 * Extends the existing PostureFinding with analytical confidence data.
 */
export interface EnrichedFindingConfidence {
  findingId: string;
  // ICD 203 Confidence Assessment
  confidenceLevel: ConfidenceLevel;
  confidenceScore: number;
  // Source Attribution
  sources: AnalyticalSource[];
  // Rationale
  rationale: string;
  // Backward-compatible tier mapping
  tier: 'confirmed' | 'probable' | 'potential';
  // Named assumptions this finding depends on
  assumptions: string[];
}

/**
 * Minimal PostureFinding interface for enrichment (avoids importing the full DI module).
 */
interface FindingForEnrichment {
  id: string;
  confidence: number; // 0-1
  corroborationTier: 'confirmed' | 'probable' | 'potential';
  evidenceBasis?: 'confirmed_cve' | 'kev_match' | 'vuln_feed' | 'llm_inference' | 'technology_match';
  cveIds?: string[];
  kevListed?: boolean;
  exploitAvailable?: boolean;
  cvssScore?: number;
  detectedVersion?: string;
  versionMatchConfirmed?: boolean;
  evidenceChain?: string[];
  severity: number;
}

/**
 * Enrich a single finding with ICD 203 confidence metadata.
 * Maps existing evidence fields to the analytical confidence framework.
 */
export function enrichFindingConfidence(finding: FindingForEnrichment): EnrichedFindingConfidence {
  // Map evidence basis to source categories
  const sources = deriveSources(finding);

  // Build confidence input from finding characteristics
  const input: FindingConfidenceInput = {
    hasVersionMatch: !!finding.versionMatchConfirmed,
    hasExploitVerification: !!finding.exploitAvailable,
    hasScannerConfirmation: finding.evidenceBasis === 'confirmed_cve' || finding.evidenceBasis === 'kev_match',
    hasManualVerification: false, // Would need operator flag
    hasMultipleToolCorroboration: (finding.evidenceChain?.length || 0) > 2,
    cveAssociationMethod: deriveCveMethod(finding),
    evidenceAge: 0, // Current scan — fresh evidence
    targetAccessLevel: 'direct',
    assumesCurrentConfiguration: true,
    assumesNoMitigation: true,
    assumesNetworkAccessibility: true
  };

  const assessment = assessFindingConfidence(input);

  // Build assumptions list
  const assumptions: string[] = [];
  if (input.assumesCurrentConfiguration) {
    assumptions.push('Target configuration unchanged since assessment');
  }
  if (input.assumesNoMitigation) {
    assumptions.push('No compensating controls mitigate this vulnerability');
  }
  if (!finding.versionMatchConfirmed && finding.cveIds && finding.cveIds.length > 0) {
    assumptions.push('CVE applicability assumed without confirmed version match');
  }

  return {
    findingId: finding.id,
    confidenceLevel: assessment.level,
    confidenceScore: assessment.score,
    sources,
    rationale: assessment.rationale,
    tier: assessment.tier,
    assumptions
  };
}

/**
 * Batch-enrich all findings from a DI scan.
 */
export function enrichAllFindings(findings: FindingForEnrichment[]): EnrichedFindingConfidence[] {
  return findings.map(f => enrichFindingConfidence(f));
}

/**
 * Derive analytical sources from a finding's evidence fields.
 */
function deriveSources(finding: FindingForEnrichment): AnalyticalSource[] {
  const sources: AnalyticalSource[] = [];
  const now = Date.now();

  switch (finding.evidenceBasis) {
    case 'confirmed_cve':
      sources.push({
        id: `src-${finding.id}-cve`,
        category: 'confirmed_scanner',
        description: `CVE confirmed via scanner with template match`,
        reliability: SOURCE_RELIABILITY_PROFILES.confirmed_scanner.baselineReliability,
        timestamp: now,
        toolOrigin: 'nuclei'
      });
      break;
    case 'kev_match':
      sources.push({
        id: `src-${finding.id}-kev`,
        category: 'threat_intel_platform',
        description: `CISA KEV listing confirms active exploitation`,
        reliability: SOURCE_RELIABILITY_PROFILES.threat_intel_platform.baselineReliability,
        timestamp: now,
        toolOrigin: 'cisa-kev'
      });
      break;
    case 'vuln_feed':
      sources.push({
        id: `src-${finding.id}-feed`,
        category: 'osint_feed',
        description: `Vulnerability feed match (NVD/vendor advisory)`,
        reliability: SOURCE_RELIABILITY_PROFILES.osint_feed.baselineReliability,
        timestamp: now,
        toolOrigin: 'nvd'
      });
      break;
    case 'llm_inference':
      sources.push({
        id: `src-${finding.id}-llm`,
        category: 'llm_inference',
        description: `LLM-inferred vulnerability based on technology fingerprint`,
        reliability: SOURCE_RELIABILITY_PROFILES.llm_inference.baselineReliability,
        timestamp: now,
        toolOrigin: 'llm-analyst'
      });
      break;
    case 'technology_match':
      sources.push({
        id: `src-${finding.id}-tech`,
        category: 'passive_fingerprint',
        description: `Technology fingerprint match suggests vulnerability`,
        reliability: SOURCE_RELIABILITY_PROFILES.passive_fingerprint.baselineReliability,
        timestamp: now,
        toolOrigin: 'httpx'
      });
      break;
    default:
      sources.push({
        id: `src-${finding.id}-unknown`,
        category: 'correlation_engine',
        description: `Finding derived from correlation analysis`,
        reliability: SOURCE_RELIABILITY_PROFILES.correlation_engine.baselineReliability,
        timestamp: now
      });
  }

  // Add version corroboration if present
  if (finding.versionMatchConfirmed) {
    sources.push({
      id: `src-${finding.id}-version`,
      category: 'version_corroborated',
      description: `Version ${finding.detectedVersion} confirmed within affected range`,
      reliability: SOURCE_RELIABILITY_PROFILES.version_corroborated.baselineReliability,
      timestamp: now,
      toolOrigin: 'version-detection'
    });
  }

  // Add KEV corroboration if listed
  if (finding.kevListed) {
    sources.push({
      id: `src-${finding.id}-kev-corr`,
      category: 'threat_intel_platform',
      description: `Listed on CISA Known Exploited Vulnerabilities catalog`,
      reliability: 0.95, // KEV listing is very high reliability
      timestamp: now,
      toolOrigin: 'cisa-kev'
    });
  }

  // Add exploit availability corroboration
  if (finding.exploitAvailable) {
    sources.push({
      id: `src-${finding.id}-exploit`,
      category: 'exploitation_verified',
      description: `Public exploit available and verified`,
      reliability: SOURCE_RELIABILITY_PROFILES.exploitation_verified.baselineReliability,
      timestamp: now,
      toolOrigin: 'exploit-db'
    });
  }

  return sources;
}

/**
 * Derive CVE association method from finding evidence.
 */
function deriveCveMethod(finding: FindingForEnrichment): FindingConfidenceInput['cveAssociationMethod'] {
  if (finding.exploitAvailable) return 'exploit_verified';
  if (finding.versionMatchConfirmed) return 'version_confirmed';
  if (finding.evidenceBasis === 'technology_match' || finding.evidenceBasis === 'llm_inference') return 'technology_inferred';
  return 'vendor_only';
}

// ─────────────────────────────────────────────────────────────────────────────
// REPORT CONFIDENCE INTEGRATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate full report confidence metadata from enriched findings.
 * Produces the IC-style confidence statement for the report header.
 */
export function generateConfidenceForReport(
  enrichedFindings: EnrichedFindingConfidence[],
  engagementContext: {
    type: string;
    hasAuthenticatedScanning: boolean;
    hasManualVerification: boolean;
    scopeCompleteness: number; // 0-1, how much of scope was assessed
    engagementDurationDays: number;
  }
): ReportConfidenceMetadata {
  // Collect all sources across findings
  const allSources: AnalyticalSource[] = [];
  for (const f of enrichedFindings) {
    allSources.push(...f.sources);
  }

  // Build engagement-level assumptions
  const assumptions: NamedAssumption[] = [];

  assumptions.push({
    id: 'assume-config-current',
    category: 'environmental',
    statement: 'Target systems continue to operate in the configuration observed during assessment.',
    impact: 'significant',
    validationStatus: 'reasonable',
    dependentClaims: enrichedFindings.map(f => f.findingId)
  });

  if (!engagementContext.hasAuthenticatedScanning) {
    assumptions.push({
      id: 'assume-no-auth-scan',
      category: 'scope',
      statement: 'Assessment was performed without authenticated access; internal vulnerabilities may exist that were not observable.',
      impact: 'critical',
      validationStatus: 'validated',
      validatedBy: 'engagement-scope',
      dependentClaims: enrichedFindings.map(f => f.findingId)
    });
  }

  if (engagementContext.scopeCompleteness < 0.8) {
    assumptions.push({
      id: 'assume-partial-scope',
      category: 'scope',
      statement: `Only ${Math.round(engagementContext.scopeCompleteness * 100)}% of in-scope assets were assessed to standard depth.`,
      impact: 'significant',
      validationStatus: 'validated',
      validatedBy: 'engagement-metrics',
      dependentClaims: []
    });
  }

  assumptions.push({
    id: 'assume-no-mitigation',
    category: 'technical',
    statement: 'Vulnerability assessments assume no compensating controls (WAF, IPS, network segmentation) mitigate identified risks unless explicitly observed.',
    impact: 'significant',
    validationStatus: 'reasonable',
    dependentClaims: enrichedFindings.filter(f => f.assumptions.includes('No compensating controls mitigate this vulnerability')).map(f => f.findingId)
  });

  // Build analytical limitations
  const limitations: string[] = [];
  if (!engagementContext.hasAuthenticatedScanning) {
    limitations.push('Assessment limited to unauthenticated external perspective');
  }
  if (!engagementContext.hasManualVerification) {
    limitations.push('Findings have not been manually verified by an operator');
  }
  if (engagementContext.scopeCompleteness < 1.0) {
    limitations.push(`${Math.round((1 - engagementContext.scopeCompleteness) * 100)}% of scope was not assessed to standard depth`);
  }
  if (engagementContext.engagementDurationDays < 3) {
    limitations.push('Abbreviated engagement window may have limited discovery depth');
  }

  // Generate report metadata
  const findingsForMetadata = enrichedFindings.map(f => ({
    confidence: f.confidenceLevel,
    score: f.confidenceScore
  }));

  return generateReportConfidenceMetadata(
    findingsForMetadata,
    assumptions,
    allSources,
    limitations
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK CHAIN CONFIDENCE ENRICHMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enrich an attack chain with confidence metadata.
 * Each step in the chain gets a confidence assessment, and the overall chain
 * confidence is bounded by the weakest link.
 */
export function enrichAttackChainConfidence(
  steps: Array<{
    stepNumber: number;
    technique: string;
    evidenceBasis: string;
    hasConfirmedVuln: boolean;
    hasVersionMatch: boolean;
  }>
): {
  overallLevel: ConfidenceLevel;
  overallScore: number;
  weakestLink: number;
  rationale: string;
  steps: AttackChainStep[];
} {
  const enrichedSteps: AttackChainStep[] = steps.map(step => {
    // Determine source category from evidence basis
    let sourceCategory: SourceCategory = 'llm_inference';
    let reliability = 0.65;

    if (step.hasConfirmedVuln) {
      sourceCategory = 'confirmed_scanner';
      reliability = 0.92;
    } else if (step.hasVersionMatch) {
      sourceCategory = 'version_corroborated';
      reliability = 0.85;
    }

    const source: AnalyticalSource = {
      id: `chain-step-${step.stepNumber}`,
      category: sourceCategory,
      description: `Evidence for ${step.technique}`,
      reliability,
      timestamp: Date.now()
    };

    // Compute step confidence
    const result = computeConfidence({
      sources: [source],
      assumptions: [],
      inferenceChainLength: 1,
      alternativeExplanationsConsidered: 0,
      alternativeExplanationsRejected: 0
    });

    return {
      stepNumber: step.stepNumber,
      technique: step.technique,
      confidence: result.level,
      confidenceScore: result.score,
      sources: [source],
      assumptions: []
    };
  });

  const chainResult = computeAttackChainConfidence(enrichedSteps);

  return {
    ...chainResult,
    steps: enrichedSteps
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// HYBRID SCORING BRIDGE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convert existing hybrid scoring confidence (0-1 numeric) to ICD 203 level.
 * This is the bridge that allows gradual migration without breaking existing scoring.
 */
export function hybridConfidenceToICD203(confidence: number): {
  level: ConfidenceLevel;
  definition: string;
} {
  const level = scoreToLevel(confidence);
  return {
    level,
    definition: CONFIDENCE_DEFINITIONS[level].definition
  };
}

/**
 * Compute the confidence dampening factor for hybrid scoring using ICD 203 methodology.
 * Replaces the existing linear dampening with a more nuanced approach.
 */
export function computeICD203Dampening(
  confidenceLevel: ConfidenceLevel,
  sourceCount: number,
  hasCorroboration: boolean
): number {
  // Base dampening by confidence level
  let dampening: number;
  switch (confidenceLevel) {
    case 'high': dampening = 0.95; break;
    case 'moderate': dampening = 0.70; break;
    case 'low': dampening = 0.40; break;
  }

  // Corroboration bonus (up to 5% boost)
  if (hasCorroboration && sourceCount >= 2) {
    dampening = Math.min(1.0, dampening + 0.05);
  }

  return dampening;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE DISPLAY HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Format confidence for display in reports and UI.
 */
export function formatConfidenceForDisplay(level: ConfidenceLevel, score: number): {
  label: string;
  badge: string;
  color: string;
  description: string;
} {
  switch (level) {
    case 'high':
      return {
        label: 'High Confidence',
        badge: 'HIGH',
        color: '#10b981', // emerald-500
        description: CONFIDENCE_DEFINITIONS.high.definition
      };
    case 'moderate':
      return {
        label: 'Moderate Confidence',
        badge: 'MOD',
        color: '#f59e0b', // amber-500
        description: CONFIDENCE_DEFINITIONS.moderate.definition
      };
    case 'low':
      return {
        label: 'Low Confidence',
        badge: 'LOW',
        color: '#ef4444', // red-500
        description: CONFIDENCE_DEFINITIONS.low.definition
      };
  }
}

/**
 * Generate the confidence section for a report (markdown format).
 */
export function generateConfidenceReportSection(metadata: ReportConfidenceMetadata): string {
  const lines: string[] = [];

  lines.push('## Analytical Confidence Assessment');
  lines.push('');
  lines.push(metadata.confidenceStatement);
  lines.push('');

  // Distribution table
  lines.push('### Finding Confidence Distribution');
  lines.push('');
  lines.push('| Confidence Level | Count | Definition |');
  lines.push('|---|---|---|');
  lines.push(`| **High** | ${metadata.findingConfidenceDistribution.high} | ${CONFIDENCE_DEFINITIONS.high.definition.slice(0, 80)}... |`);
  lines.push(`| **Moderate** | ${metadata.findingConfidenceDistribution.moderate} | ${CONFIDENCE_DEFINITIONS.moderate.definition.slice(0, 80)}... |`);
  lines.push(`| **Low** | ${metadata.findingConfidenceDistribution.low} | ${CONFIDENCE_DEFINITIONS.low.definition.slice(0, 80)}... |`);
  lines.push('');

  // Key assumptions
  if (metadata.keyAssumptions.length > 0) {
    lines.push('### Key Analytical Assumptions');
    lines.push('');
    lines.push('The following assumptions underpin this assessment. If any assumption is invalidated, the affected findings should be re-evaluated:');
    lines.push('');
    for (const assumption of metadata.keyAssumptions) {
      const impactBadge = assumption.impact === 'critical' ? '**[CRITICAL]**' : '**[SIGNIFICANT]**';
      lines.push(`- ${impactBadge} ${assumption.statement}`);
    }
    lines.push('');
  }

  // Analytical limitations
  if (metadata.analyticalLimitations.length > 0) {
    lines.push('### Analytical Limitations');
    lines.push('');
    for (const limitation of metadata.analyticalLimitations) {
      lines.push(`- ${limitation}`);
    }
    lines.push('');
  }

  // Source profile
  if (metadata.sourceProfile.length > 0) {
    lines.push('### Source Profile');
    lines.push('');
    lines.push('| Source Category | Count | Avg. Reliability |');
    lines.push('|---|---|---|');
    for (const sp of metadata.sourceProfile.slice(0, 8)) {
      const profile = SOURCE_RELIABILITY_PROFILES[sp.category];
      lines.push(`| ${profile?.label || sp.category} | ${sp.count} | ${(sp.averageReliability * 100).toFixed(0)}% |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
