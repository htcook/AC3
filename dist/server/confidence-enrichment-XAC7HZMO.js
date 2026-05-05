import "./chunk-KFQGP6VL.js";

// server/lib/analytical-confidence.ts
var CONFIDENCE_DEFINITIONS = {
  high: {
    level: "high",
    numericRange: [0.8, 1],
    definition: "Analysis based on high-quality information from multiple independent sources, with corroborating evidence and sound logical inference. Alternative explanations have been considered and found less compelling.",
    characteristics: [
      "Multiple independent sources corroborate the assessment",
      "Evidence is directly observed or confirmed through testing",
      "Inference chain is short and well-supported",
      "Alternative explanations have been evaluated and rejected",
      "Assumptions are minimal and well-validated"
    ],
    exampleInAC3: "Nuclei template confirmed vulnerability with version match and successful exploitation proof"
  },
  moderate: {
    level: "moderate",
    numericRange: [0.5, 0.79],
    definition: "Credibly sourced information that is plausible and logically consistent but not corroborated to the level of high confidence. Relies on fewer independent sources or involves inference chains with identifiable assumptions.",
    characteristics: [
      "Information is credibly sourced but not fully corroborated",
      "Inference chain involves identifiable assumptions",
      "Some alternative explanations remain plausible",
      "Evidence is indirect or partially confirmed",
      "Analysis depends on assumptions that are reasonable but unverified"
    ],
    exampleInAC3: "CVE matched to confirmed software version but exploitation not verified; attack chain plausible based on architecture analysis"
  },
  low: {
    level: "low",
    numericRange: [0, 0.49],
    definition: "Information whose credibility or plausibility is questionable, or analysis based on fragmentary evidence with significant inference gaps. Alternative explanations remain viable and the analytical judgment may change with additional information.",
    characteristics: [
      "Single source or unverified information",
      "Significant inference gaps in the analytical chain",
      "Multiple alternative explanations remain viable",
      "Evidence is fragmentary or circumstantial",
      "Analysis depends on assumptions that are unverified or uncertain"
    ],
    exampleInAC3: "CVE associated by vendor name only without version confirmation; potential vulnerability based on technology fingerprint alone"
  }
};
var SOURCE_RELIABILITY_PROFILES = {
  confirmed_scanner: {
    category: "confirmed_scanner",
    baselineReliability: 0.92,
    label: "Confirmed Scanner Finding",
    description: "Direct scanner finding with template/signature match against known vulnerability pattern",
    corroborationWeight: 0.9
  },
  version_corroborated: {
    category: "version_corroborated",
    baselineReliability: 0.85,
    label: "Version-Corroborated CVE",
    description: "CVE matched to confirmed software version through banner/header/fingerprint analysis",
    corroborationWeight: 0.85
  },
  exploitation_verified: {
    category: "exploitation_verified",
    baselineReliability: 0.98,
    label: "Exploitation Verified",
    description: "Finding verified through actual exploitation attempt with confirmed impact",
    corroborationWeight: 0.95
  },
  llm_inference: {
    category: "llm_inference",
    baselineReliability: 0.65,
    label: "LLM-Augmented Inference",
    description: "Analytical inference produced by LLM specialist with evidence context",
    corroborationWeight: 0.5
  },
  osint_feed: {
    category: "osint_feed",
    baselineReliability: 0.7,
    label: "OSINT Feed",
    description: "Open source intelligence from curated feeds (abuse.ch, URLScan, etc.)",
    corroborationWeight: 0.6
  },
  threat_intel_platform: {
    category: "threat_intel_platform",
    baselineReliability: 0.8,
    label: "Threat Intelligence Platform",
    description: "Curated threat intelligence from platforms (SpicyTIP, NVD, CISA KEV)",
    corroborationWeight: 0.75
  },
  vendor_only_match: {
    category: "vendor_only_match",
    baselineReliability: 0.35,
    label: "Vendor-Only CVE Match",
    description: "CVE associated by vendor name without specific version confirmation",
    corroborationWeight: 0.3
  },
  operator_observation: {
    category: "operator_observation",
    baselineReliability: 0.75,
    label: "Operator Observation",
    description: "Manual testing notes and professional judgment from qualified operator",
    corroborationWeight: 0.7
  },
  customer_provided: {
    category: "customer_provided",
    baselineReliability: 0.6,
    label: "Customer-Provided Data",
    description: "Asset inventories, business context, and compliance scope from customer",
    corroborationWeight: 0.5
  },
  historical_engagement: {
    category: "historical_engagement",
    baselineReliability: 0.72,
    label: "Historical Engagement Data",
    description: "Data from previous engagements with same target (may be stale)",
    corroborationWeight: 0.6
  },
  certificate_analysis: {
    category: "certificate_analysis",
    baselineReliability: 0.88,
    label: "Certificate Analysis",
    description: "Certificate transparency logs, cert chain analysis, issuer identification",
    corroborationWeight: 0.8
  },
  dns_enumeration: {
    category: "dns_enumeration",
    baselineReliability: 0.9,
    label: "DNS Enumeration",
    description: "DNS record analysis including A, AAAA, MX, TXT, CNAME, NS records",
    corroborationWeight: 0.85
  },
  passive_fingerprint: {
    category: "passive_fingerprint",
    baselineReliability: 0.72,
    label: "Passive Fingerprint",
    description: "Technology identification from response headers, HTML content, behavior",
    corroborationWeight: 0.6
  },
  active_probe: {
    category: "active_probe",
    baselineReliability: 0.88,
    label: "Active Probe",
    description: "Results from active probing/testing (port scan, service enumeration)",
    corroborationWeight: 0.8
  },
  community_signature: {
    category: "community_signature",
    baselineReliability: 0.68,
    label: "Community Signature",
    description: "Community-contributed signatures and fingerprints (JARM, Shodan tags)",
    corroborationWeight: 0.55
  },
  behavioral_analysis: {
    category: "behavioral_analysis",
    baselineReliability: 0.6,
    label: "Behavioral Analysis",
    description: "Behavioral pattern analysis based on timing, response characteristics",
    corroborationWeight: 0.5
  },
  correlation_engine: {
    category: "correlation_engine",
    baselineReliability: 0.7,
    label: "Correlation Engine",
    description: "Cross-source correlation inference combining multiple data points",
    corroborationWeight: 0.65
  }
};
function computeConfidence(input) {
  const { sources, assumptions, inferenceChainLength, alternativeExplanationsConsidered, alternativeExplanationsRejected } = input;
  if (sources.length === 0) {
    return {
      level: "low",
      score: 0.1,
      breakdown: {
        sourceReliabilityScore: 0,
        corroborationBonus: 0,
        inferenceChainPenalty: 0,
        assumptionPenalty: 0,
        alternativeExplanationBonus: 0
      },
      rationale: "No sources provided; confidence cannot be assessed."
    };
  }
  const sortedSources = [...sources].sort((a, b) => b.reliability - a.reliability);
  let sourceReliabilityScore = 0;
  let totalWeight = 0;
  for (let i = 0; i < sortedSources.length; i++) {
    const weight = 1 / (i + 1);
    sourceReliabilityScore += sortedSources[i].reliability * weight;
    totalWeight += weight;
  }
  sourceReliabilityScore = sourceReliabilityScore / totalWeight;
  const independentSourceCount = countIndependentSources(sources);
  const corroborationBonus = Math.min(0.15, (independentSourceCount - 1) * 0.05);
  const inferenceChainPenalty = Math.min(0.25, (inferenceChainLength - 1) * 0.05);
  let assumptionPenalty = 0;
  for (const assumption of assumptions) {
    if (assumption.validationStatus === "unverified" && assumption.impact === "critical") {
      assumptionPenalty += 0.12;
    } else if (assumption.validationStatus === "unverified" && assumption.impact === "significant") {
      assumptionPenalty += 0.07;
    } else if (assumption.validationStatus === "stale") {
      assumptionPenalty += 0.05;
    } else if (assumption.validationStatus === "unverified" && assumption.impact === "minor") {
      assumptionPenalty += 0.03;
    }
  }
  assumptionPenalty = Math.min(0.35, assumptionPenalty);
  const alternativeExplanationBonus = alternativeExplanationsConsidered > 0 ? Math.min(0.1, alternativeExplanationsRejected / alternativeExplanationsConsidered * 0.1) : 0;
  const rawScore = sourceReliabilityScore + corroborationBonus - inferenceChainPenalty - assumptionPenalty + alternativeExplanationBonus;
  const score = Math.max(0.05, Math.min(1, rawScore));
  const level = scoreToLevel(score);
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
function scoreToLevel(score) {
  if (score >= 0.8) return "high";
  if (score >= 0.5) return "moderate";
  return "low";
}
function countIndependentSources(sources) {
  const categories = new Set(sources.map((s) => s.category));
  return categories.size;
}
function generateRationale(level, sources, independentSourceCount, inferenceChainLength, assumptions, alternativesConsidered) {
  const parts = [];
  if (sources.length === 1) {
    const profile = SOURCE_RELIABILITY_PROFILES[sources[0].category];
    parts.push(`Based on a single source (${profile.label}).`);
  } else {
    parts.push(`Based on ${sources.length} sources from ${independentSourceCount} independent categories.`);
  }
  if (independentSourceCount >= 3) {
    parts.push("Multiple independent sources corroborate this assessment.");
  } else if (independentSourceCount === 2) {
    parts.push("Two independent source categories provide partial corroboration.");
  }
  if (inferenceChainLength > 3) {
    parts.push(`Inference chain involves ${inferenceChainLength} logical steps, introducing cumulative uncertainty.`);
  } else if (inferenceChainLength > 1) {
    parts.push(`Inference chain involves ${inferenceChainLength} logical steps.`);
  }
  const unverifiedCritical = assumptions.filter((a) => a.validationStatus === "unverified" && a.impact === "critical");
  if (unverifiedCritical.length > 0) {
    parts.push(`${unverifiedCritical.length} critical assumption(s) remain unverified, which constrains confidence.`);
  }
  if (alternativesConsidered > 0) {
    parts.push(`${alternativesConsidered} alternative explanation(s) were considered.`);
  }
  return parts.join(" ");
}
function assessFindingConfidence(input) {
  let score = 0.3;
  if (input.hasExploitVerification) score += 0.4;
  else if (input.hasScannerConfirmation) score += 0.3;
  else if (input.hasVersionMatch) score += 0.2;
  if (input.hasManualVerification) score += 0.15;
  if (input.hasMultipleToolCorroboration) score += 0.1;
  switch (input.cveAssociationMethod) {
    case "exploit_verified":
      score += 0.1;
      break;
    case "version_confirmed":
      score += 0.05;
      break;
    case "vendor_only":
      score -= 0.15;
      break;
    case "technology_inferred":
      score -= 0.2;
      break;
  }
  if (input.evidenceAge > 90) score -= 0.1;
  else if (input.evidenceAge > 30) score -= 0.05;
  if (input.targetAccessLevel === "inferred") score -= 0.1;
  else if (input.targetAccessLevel === "indirect") score -= 0.05;
  if (input.assumesCurrentConfiguration) score -= 0.03;
  if (input.assumesNoMitigation) score -= 0.05;
  if (input.assumesNetworkAccessibility) score -= 0.03;
  score = Math.max(0.05, Math.min(1, score));
  const level = scoreToLevel(score);
  let tier;
  if (score >= 0.75) tier = "confirmed";
  else if (score >= 0.5) tier = "probable";
  else tier = "potential";
  const rationaleparts = [];
  if (input.hasExploitVerification) rationaleparts.push("Exploitation verified.");
  else if (input.hasScannerConfirmation) rationaleparts.push("Scanner confirmation with signature match.");
  else if (input.hasVersionMatch) rationaleparts.push("Version match confirmed.");
  else rationaleparts.push("Association based on vendor/technology inference only.");
  if (input.hasMultipleToolCorroboration) rationaleparts.push("Multiple tools corroborate.");
  if (input.cveAssociationMethod === "vendor_only") rationaleparts.push("CVE associated by vendor name only \u2014 version unconfirmed.");
  if (input.evidenceAge > 30) rationaleparts.push(`Evidence is ${input.evidenceAge} days old.`);
  if (input.assumesNoMitigation) rationaleparts.push("Assumes no compensating controls in place.");
  return {
    level,
    score,
    rationale: rationaleparts.join(" "),
    tier
  };
}
function computeAttackChainConfidence(steps) {
  if (steps.length === 0) {
    return { overallLevel: "low", overallScore: 0.1, weakestLink: 0, rationale: "No steps in chain." };
  }
  let weakestStep = steps[0];
  for (const step of steps) {
    if (step.confidenceScore < weakestStep.confidenceScore) {
      weakestStep = step;
    }
  }
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
function generateReportConfidenceMetadata(findings, assumptions, sources, analyticalLimitations) {
  const distribution = { high: 0, moderate: 0, low: 0 };
  for (const f of findings) {
    distribution[f.confidence]++;
  }
  const totalFindings = findings.length;
  let weightedScore = 0;
  for (const f of findings) {
    weightedScore += f.score;
  }
  const avgScore = totalFindings > 0 ? weightedScore / totalFindings : 0.5;
  const overallConfidence = scoreToLevel(avgScore);
  const sourceMap = /* @__PURE__ */ new Map();
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
  const keyAssumptions = assumptions.filter((a) => a.impact === "critical" || a.impact === "significant");
  const confidenceStatement = generateConfidenceStatement(overallConfidence, distribution, totalFindings, keyAssumptions, analyticalLimitations);
  return {
    overallAssessmentConfidence: overallConfidence,
    findingConfidenceDistribution: distribution,
    keyAssumptions,
    coverageGaps: [],
    // Populated in Q2
    analyticalLimitations,
    sourceProfile,
    confidenceStatement
  };
}
function generateConfidenceStatement(overall, distribution, total, keyAssumptions, limitations) {
  const parts = [];
  parts.push(`We assess with ${overall} confidence that the findings in this report accurately characterize the target's security posture within the scope of assessment.`);
  const highPct = total > 0 ? Math.round(distribution.high / total * 100) : 0;
  const modPct = total > 0 ? Math.round(distribution.moderate / total * 100) : 0;
  const lowPct = total > 0 ? Math.round(distribution.low / total * 100) : 0;
  parts.push(`Of ${total} findings, ${highPct}% are assessed at high confidence, ${modPct}% at moderate confidence, and ${lowPct}% at low confidence.`);
  if (keyAssumptions.length > 0) {
    const criticalCount = keyAssumptions.filter((a) => a.impact === "critical").length;
    if (criticalCount > 0) {
      parts.push(`This assessment depends on ${criticalCount} critical assumption(s) that, if invalidated, could materially change the analytical conclusions.`);
    }
  }
  if (limitations.length > 0) {
    parts.push(`Analytical limitations include: ${limitations.slice(0, 3).join("; ")}.`);
  }
  return parts.join(" ");
}

// server/lib/confidence-enrichment.ts
function enrichFindingConfidence(finding) {
  const sources = deriveSources(finding);
  const input = {
    hasVersionMatch: !!finding.versionMatchConfirmed,
    hasExploitVerification: !!finding.exploitAvailable,
    hasScannerConfirmation: finding.evidenceBasis === "confirmed_cve" || finding.evidenceBasis === "kev_match",
    hasManualVerification: false,
    // Would need operator flag
    hasMultipleToolCorroboration: (finding.evidenceChain?.length || 0) > 2,
    cveAssociationMethod: deriveCveMethod(finding),
    evidenceAge: 0,
    // Current scan — fresh evidence
    targetAccessLevel: "direct",
    assumesCurrentConfiguration: true,
    assumesNoMitigation: true,
    assumesNetworkAccessibility: true
  };
  const assessment = assessFindingConfidence(input);
  const assumptions = [];
  if (input.assumesCurrentConfiguration) {
    assumptions.push("Target configuration unchanged since assessment");
  }
  if (input.assumesNoMitigation) {
    assumptions.push("No compensating controls mitigate this vulnerability");
  }
  if (!finding.versionMatchConfirmed && finding.cveIds && finding.cveIds.length > 0) {
    assumptions.push("CVE applicability assumed without confirmed version match");
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
function enrichAllFindings(findings) {
  return findings.map((f) => enrichFindingConfidence(f));
}
function deriveSources(finding) {
  const sources = [];
  const now = Date.now();
  switch (finding.evidenceBasis) {
    case "confirmed_cve":
      sources.push({
        id: `src-${finding.id}-cve`,
        category: "confirmed_scanner",
        description: `CVE confirmed via scanner with template match`,
        reliability: SOURCE_RELIABILITY_PROFILES.confirmed_scanner.baselineReliability,
        timestamp: now,
        toolOrigin: "nuclei"
      });
      break;
    case "kev_match":
      sources.push({
        id: `src-${finding.id}-kev`,
        category: "threat_intel_platform",
        description: `CISA KEV listing confirms active exploitation`,
        reliability: SOURCE_RELIABILITY_PROFILES.threat_intel_platform.baselineReliability,
        timestamp: now,
        toolOrigin: "cisa-kev"
      });
      break;
    case "vuln_feed":
      sources.push({
        id: `src-${finding.id}-feed`,
        category: "osint_feed",
        description: `Vulnerability feed match (NVD/vendor advisory)`,
        reliability: SOURCE_RELIABILITY_PROFILES.osint_feed.baselineReliability,
        timestamp: now,
        toolOrigin: "nvd"
      });
      break;
    case "llm_inference":
      sources.push({
        id: `src-${finding.id}-llm`,
        category: "llm_inference",
        description: `LLM-inferred vulnerability based on technology fingerprint`,
        reliability: SOURCE_RELIABILITY_PROFILES.llm_inference.baselineReliability,
        timestamp: now,
        toolOrigin: "llm-analyst"
      });
      break;
    case "technology_match":
      sources.push({
        id: `src-${finding.id}-tech`,
        category: "passive_fingerprint",
        description: `Technology fingerprint match suggests vulnerability`,
        reliability: SOURCE_RELIABILITY_PROFILES.passive_fingerprint.baselineReliability,
        timestamp: now,
        toolOrigin: "httpx"
      });
      break;
    default:
      sources.push({
        id: `src-${finding.id}-unknown`,
        category: "correlation_engine",
        description: `Finding derived from correlation analysis`,
        reliability: SOURCE_RELIABILITY_PROFILES.correlation_engine.baselineReliability,
        timestamp: now
      });
  }
  if (finding.versionMatchConfirmed) {
    sources.push({
      id: `src-${finding.id}-version`,
      category: "version_corroborated",
      description: `Version ${finding.detectedVersion} confirmed within affected range`,
      reliability: SOURCE_RELIABILITY_PROFILES.version_corroborated.baselineReliability,
      timestamp: now,
      toolOrigin: "version-detection"
    });
  }
  if (finding.kevListed) {
    sources.push({
      id: `src-${finding.id}-kev-corr`,
      category: "threat_intel_platform",
      description: `Listed on CISA Known Exploited Vulnerabilities catalog`,
      reliability: 0.95,
      // KEV listing is very high reliability
      timestamp: now,
      toolOrigin: "cisa-kev"
    });
  }
  if (finding.exploitAvailable) {
    sources.push({
      id: `src-${finding.id}-exploit`,
      category: "exploitation_verified",
      description: `Public exploit available and verified`,
      reliability: SOURCE_RELIABILITY_PROFILES.exploitation_verified.baselineReliability,
      timestamp: now,
      toolOrigin: "exploit-db"
    });
  }
  return sources;
}
function deriveCveMethod(finding) {
  if (finding.exploitAvailable) return "exploit_verified";
  if (finding.versionMatchConfirmed) return "version_confirmed";
  if (finding.evidenceBasis === "technology_match" || finding.evidenceBasis === "llm_inference") return "technology_inferred";
  return "vendor_only";
}
function generateConfidenceForReport(enrichedFindings, engagementContext) {
  const allSources = [];
  for (const f of enrichedFindings) {
    allSources.push(...f.sources);
  }
  const assumptions = [];
  assumptions.push({
    id: "assume-config-current",
    category: "environmental",
    statement: "Target systems continue to operate in the configuration observed during assessment.",
    impact: "significant",
    validationStatus: "reasonable",
    dependentClaims: enrichedFindings.map((f) => f.findingId)
  });
  if (!engagementContext.hasAuthenticatedScanning) {
    assumptions.push({
      id: "assume-no-auth-scan",
      category: "scope",
      statement: "Assessment was performed without authenticated access; internal vulnerabilities may exist that were not observable.",
      impact: "critical",
      validationStatus: "validated",
      validatedBy: "engagement-scope",
      dependentClaims: enrichedFindings.map((f) => f.findingId)
    });
  }
  if (engagementContext.scopeCompleteness < 0.8) {
    assumptions.push({
      id: "assume-partial-scope",
      category: "scope",
      statement: `Only ${Math.round(engagementContext.scopeCompleteness * 100)}% of in-scope assets were assessed to standard depth.`,
      impact: "significant",
      validationStatus: "validated",
      validatedBy: "engagement-metrics",
      dependentClaims: []
    });
  }
  assumptions.push({
    id: "assume-no-mitigation",
    category: "technical",
    statement: "Vulnerability assessments assume no compensating controls (WAF, IPS, network segmentation) mitigate identified risks unless explicitly observed.",
    impact: "significant",
    validationStatus: "reasonable",
    dependentClaims: enrichedFindings.filter((f) => f.assumptions.includes("No compensating controls mitigate this vulnerability")).map((f) => f.findingId)
  });
  const limitations = [];
  if (!engagementContext.hasAuthenticatedScanning) {
    limitations.push("Assessment limited to unauthenticated external perspective");
  }
  if (!engagementContext.hasManualVerification) {
    limitations.push("Findings have not been manually verified by an operator");
  }
  if (engagementContext.scopeCompleteness < 1) {
    limitations.push(`${Math.round((1 - engagementContext.scopeCompleteness) * 100)}% of scope was not assessed to standard depth`);
  }
  if (engagementContext.engagementDurationDays < 3) {
    limitations.push("Abbreviated engagement window may have limited discovery depth");
  }
  const findingsForMetadata = enrichedFindings.map((f) => ({
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
function enrichAttackChainConfidence(steps) {
  const enrichedSteps = steps.map((step) => {
    let sourceCategory = "llm_inference";
    let reliability = 0.65;
    if (step.hasConfirmedVuln) {
      sourceCategory = "confirmed_scanner";
      reliability = 0.92;
    } else if (step.hasVersionMatch) {
      sourceCategory = "version_corroborated";
      reliability = 0.85;
    }
    const source = {
      id: `chain-step-${step.stepNumber}`,
      category: sourceCategory,
      description: `Evidence for ${step.technique}`,
      reliability,
      timestamp: Date.now()
    };
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
function hybridConfidenceToICD203(confidence) {
  const level = scoreToLevel(confidence);
  return {
    level,
    definition: CONFIDENCE_DEFINITIONS[level].definition
  };
}
function computeICD203Dampening(confidenceLevel, sourceCount, hasCorroboration) {
  let dampening;
  switch (confidenceLevel) {
    case "high":
      dampening = 0.95;
      break;
    case "moderate":
      dampening = 0.7;
      break;
    case "low":
      dampening = 0.4;
      break;
  }
  if (hasCorroboration && sourceCount >= 2) {
    dampening = Math.min(1, dampening + 0.05);
  }
  return dampening;
}
function formatConfidenceForDisplay(level, score) {
  switch (level) {
    case "high":
      return {
        label: "High Confidence",
        badge: "HIGH",
        color: "#10b981",
        // emerald-500
        description: CONFIDENCE_DEFINITIONS.high.definition
      };
    case "moderate":
      return {
        label: "Moderate Confidence",
        badge: "MOD",
        color: "#f59e0b",
        // amber-500
        description: CONFIDENCE_DEFINITIONS.moderate.definition
      };
    case "low":
      return {
        label: "Low Confidence",
        badge: "LOW",
        color: "#ef4444",
        // red-500
        description: CONFIDENCE_DEFINITIONS.low.definition
      };
  }
}
function generateConfidenceReportSection(metadata) {
  const lines = [];
  lines.push("## Analytical Confidence Assessment");
  lines.push("");
  lines.push(metadata.confidenceStatement);
  lines.push("");
  lines.push("### Finding Confidence Distribution");
  lines.push("");
  lines.push("| Confidence Level | Count | Definition |");
  lines.push("|---|---|---|");
  lines.push(`| **High** | ${metadata.findingConfidenceDistribution.high} | ${CONFIDENCE_DEFINITIONS.high.definition.slice(0, 80)}... |`);
  lines.push(`| **Moderate** | ${metadata.findingConfidenceDistribution.moderate} | ${CONFIDENCE_DEFINITIONS.moderate.definition.slice(0, 80)}... |`);
  lines.push(`| **Low** | ${metadata.findingConfidenceDistribution.low} | ${CONFIDENCE_DEFINITIONS.low.definition.slice(0, 80)}... |`);
  lines.push("");
  if (metadata.keyAssumptions.length > 0) {
    lines.push("### Key Analytical Assumptions");
    lines.push("");
    lines.push("The following assumptions underpin this assessment. If any assumption is invalidated, the affected findings should be re-evaluated:");
    lines.push("");
    for (const assumption of metadata.keyAssumptions) {
      const impactBadge = assumption.impact === "critical" ? "**[CRITICAL]**" : "**[SIGNIFICANT]**";
      lines.push(`- ${impactBadge} ${assumption.statement}`);
    }
    lines.push("");
  }
  if (metadata.analyticalLimitations.length > 0) {
    lines.push("### Analytical Limitations");
    lines.push("");
    for (const limitation of metadata.analyticalLimitations) {
      lines.push(`- ${limitation}`);
    }
    lines.push("");
  }
  if (metadata.sourceProfile.length > 0) {
    lines.push("### Source Profile");
    lines.push("");
    lines.push("| Source Category | Count | Avg. Reliability |");
    lines.push("|---|---|---|");
    for (const sp of metadata.sourceProfile.slice(0, 8)) {
      const profile = SOURCE_RELIABILITY_PROFILES[sp.category];
      lines.push(`| ${profile?.label || sp.category} | ${sp.count} | ${(sp.averageReliability * 100).toFixed(0)}% |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
export {
  computeICD203Dampening,
  enrichAllFindings,
  enrichAttackChainConfidence,
  enrichFindingConfidence,
  formatConfidenceForDisplay,
  generateConfidenceForReport,
  generateConfidenceReportSection,
  hybridConfidenceToICD203
};
