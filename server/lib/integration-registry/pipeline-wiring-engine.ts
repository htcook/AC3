/**
 * Pipeline Wiring Engine — Auto-Connect Approved Integrations to Pipeline Stages
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * After a customer approves an integration proposal, this engine:
 *   1. Generates a PipelineWiringConfig based on the integration's capabilities
 *   2. Determines execution order and dependencies within each stage
 *   3. Sets up output mapping to normalize data into AC3's internal format
 *   4. Configures deduplication against overlapping sources
 *   5. Wires the integration into the engagement orchestrator
 * 
 * The engine uses heuristics + the integration's metadata to make smart
 * wiring decisions, but the customer can always override.
 */

import type {
  IntegrationDefinition,
  IntegrationCategory,
  PipelineStage,
  PipelineWiringConfig,
  PipelineCondition,
  OutputMapping,
  IntegrationValueAssessment,
} from "./types";
import { BUILTIN_CATALOG, CATALOG_BY_ID, type CatalogEntry } from "./builtin-catalog";

// ═══════════════════════════════════════════════════════════════════════
// §1 — WIRING HEURISTICS
// ═══════════════════════════════════════════════════════════════════════

/** Default priority by category (lower = runs first in stage) */
const CATEGORY_PRIORITY: Record<IntegrationCategory, number> = {
  osint: 10,
  threat_intel: 15,
  credential: 20,
  scanner: 30,
  pentest_tool: 40,
  exploit_db: 25,
  phishing: 35,
  c2: 45,
  siem_soar: 50,
  cloud: 35,
  custom: 60,
};

/** Default max duration by category (ms) */
const CATEGORY_TIMEOUT: Record<IntegrationCategory, number> = {
  osint: 30_000,        // 30s — most OSINT APIs are fast
  threat_intel: 30_000,
  credential: 20_000,
  scanner: 600_000,     // 10min — scanners take time
  pentest_tool: 900_000, // 15min — exploitation can be slow
  exploit_db: 30_000,
  phishing: 120_000,    // 2min — campaign setup
  c2: 300_000,          // 5min — C2 operations
  siem_soar: 60_000,    // 1min — alert pull
  cloud: 120_000,       // 2min — cloud API calls
  custom: 60_000,       // 1min default
};

/** Default failure policy by category */
const CATEGORY_FAILURE_POLICY: Record<IntegrationCategory, "continue" | "warn" | "abort"> = {
  osint: "continue",       // OSINT failure shouldn't block pipeline
  threat_intel: "continue",
  credential: "continue",
  scanner: "warn",         // Scanner failure is notable
  pentest_tool: "warn",    // Exploit failure is notable
  exploit_db: "continue",
  phishing: "warn",
  c2: "warn",
  siem_soar: "continue",
  cloud: "continue",
  custom: "continue",
};

// ═══════════════════════════════════════════════════════════════════════
// §2 — OUTPUT MAPPING TEMPLATES
// ═══════════════════════════════════════════════════════════════════════

/** Standard output mapping templates by data type */
function getOutputMapping(category: IntegrationCategory, dataTypes: string[]): OutputMapping {
  // OSINT → asset observations
  if (category === "osint" || category === "credential") {
    return {
      targetType: "asset_observation",
      fieldMappings: {
        "hostname": "hostname",
        "ip": "ip",
        "port": "port",
        "service": "service",
        "version": "version",
        "subdomain": "subdomain",
        "technology": "technology",
        "certificate": "certificate",
      },
      severityMapping: {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
      },
      confidenceMapping: {
        "certain": 95,
        "firm": 80,
        "tentative": 50,
        "unknown": 30,
      },
    };
  }

  // Scanners → vulnerabilities
  if (category === "scanner") {
    return {
      targetType: "vulnerability",
      fieldMappings: {
        "title": "title",
        "severity": "severity",
        "cve": "cve",
        "cwe": "cwe",
        "cvss": "cvss",
        "description": "description",
        "remediation": "remediation",
        "evidence": "evidence",
        "url": "url",
        "host": "hostname",
      },
      severityMapping: {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
      },
    };
  }

  // Exploit tools → exploit results
  if (category === "pentest_tool" || category === "c2") {
    return {
      targetType: "exploit_result",
      fieldMappings: {
        "target": "hostname",
        "module": "module",
        "success": "success",
        "session": "session",
        "output": "output",
        "technique": "mitre_technique",
      },
    };
  }

  // Threat intel → threat intel
  if (category === "threat_intel") {
    return {
      targetType: "threat_intel",
      fieldMappings: {
        "indicator": "indicator",
        "type": "indicator_type",
        "source": "source",
        "confidence": "confidence",
        "tags": "tags",
        "malware_family": "malware_family",
        "threat_actor": "threat_actor",
      },
    };
  }

  // Default → asset observation
  return {
    targetType: "asset_observation",
    fieldMappings: {},
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — CONDITION GENERATION
// ═══════════════════════════════════════════════════════════════════════

/** Generate pipeline conditions based on integration capabilities */
function generateConditions(
  category: IntegrationCategory,
  stages: PipelineStage[],
  requiresActiveProbing: boolean,
): PipelineCondition[] {
  const conditions: PipelineCondition[] = [];

  // Active probing requires RoE approval
  if (requiresActiveProbing) {
    conditions.push({
      type: "if_roe_allows",
      params: { requiredPermission: "active_scanning" },
      description: "Only run if Rules of Engagement permit active scanning",
    });
  }

  // Exploitation stage requires prior vuln detection
  if (stages.includes("exploitation")) {
    conditions.push({
      type: "if_previous_found",
      params: { previousStage: "vuln_detection", minFindings: 1 },
      description: "Only run exploitation if vulnerabilities were detected",
    });
  }

  // Post-exploit requires successful exploitation
  if (stages.includes("post_exploit")) {
    conditions.push({
      type: "if_previous_found",
      params: { previousStage: "exploitation", minFindings: 1 },
      description: "Only run post-exploitation if exploitation was successful",
    });
  }

  // Social engineering requires RoE
  if (stages.includes("social_engineering")) {
    conditions.push({
      type: "if_roe_allows",
      params: { requiredPermission: "social_engineering" },
      description: "Only run if Rules of Engagement permit social engineering",
    });
  }

  // If no specific conditions, always run
  if (conditions.length === 0) {
    conditions.push({
      type: "always",
      params: {},
      description: "Run in every engagement that includes this stage",
    });
  }

  return conditions;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — DEDUPLICATION ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

/** Find overlapping integrations for deduplication */
function findDeduplicationTargets(
  integrationId: string,
  category: IntegrationCategory,
  dataTypes: string[],
  stages: PipelineStage[],
  existingIntegrations: Array<{ id: string; category: IntegrationCategory; dataTypes: string[]; stages: PipelineStage[] }>,
): string[] {
  const targets: string[] = [];

  for (const existing of existingIntegrations) {
    if (existing.id === integrationId) continue;

    // Same category + overlapping stages + overlapping data types = dedup target
    const stageOverlap = stages.filter(s => existing.stages.includes(s));
    const dataOverlap = dataTypes.filter(d => existing.dataTypes.includes(d));

    if (stageOverlap.length > 0 && dataOverlap.length > 0) {
      targets.push(existing.id);
    }
  }

  return targets;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — MAIN WIRING ENGINE
// ═══════════════════════════════════════════════════════════════════════

export interface WiringProposal {
  /** The generated wiring configuration */
  config: PipelineWiringConfig;
  /** Human-readable explanation of wiring decisions */
  explanation: string;
  /** Warnings about the wiring */
  warnings: string[];
  /** Suggested optimizations */
  optimizations: string[];
}

/**
 * Generate a pipeline wiring configuration for an approved integration.
 * This is called after customer approval — the config can still be
 * modified by the customer before final activation.
 */
export function generateWiringConfig(
  integration: {
    id: string;
    category: IntegrationCategory;
    pipelineStages: PipelineStage[];
    dataTypes: string[];
    requiresActiveProbing: boolean;
    valueAssessment?: IntegrationValueAssessment;
  },
  existingIntegrations?: Array<{ id: string; category: IntegrationCategory; dataTypes: string[]; stages: PipelineStage[] }>,
): WiringProposal {
  const warnings: string[] = [];
  const optimizations: string[] = [];
  const explanations: string[] = [];

  const { id, category, pipelineStages, dataTypes, requiresActiveProbing, valueAssessment } = integration;

  // 1. Determine priority
  let priority = CATEGORY_PRIORITY[category] ?? 50;
  // Boost priority for high-value integrations
  if (valueAssessment && valueAssessment.overallScore > 80) {
    priority = Math.max(1, priority - 5);
    explanations.push(`Priority boosted (${priority}) due to high value score (${valueAssessment.overallScore})`);
  }

  // 2. Determine parallelism
  // OSINT and threat intel can run in parallel; scanners and exploit tools should be sequential
  const parallel = ["osint", "threat_intel", "credential", "cloud"].includes(category);
  explanations.push(parallel
    ? `Runs in parallel with other ${category} integrations for speed`
    : `Runs sequentially to avoid target overload`
  );

  // 3. Generate conditions
  const conditions = generateConditions(category, pipelineStages, requiresActiveProbing);
  if (requiresActiveProbing) {
    explanations.push("Requires RoE approval before active probing");
  }

  // 4. Generate output mapping
  const outputMapping = getOutputMapping(category, dataTypes);
  explanations.push(`Output mapped to AC3 ${outputMapping.targetType} format`);

  // 5. Find deduplication targets
  const existingForDedup = existingIntegrations || BUILTIN_CATALOG.map(e => ({
    id: e.id,
    category: e.category,
    dataTypes: e.dataTypes,
    stages: e.pipelineStages,
  }));
  const deduplicateWith = findDeduplicationTargets(id, category, dataTypes, pipelineStages, existingForDedup);
  if (deduplicateWith.length > 0) {
    explanations.push(`Deduplicates against: ${deduplicateWith.join(", ")}`);
    if (deduplicateWith.length > 5) {
      warnings.push(`High overlap with ${deduplicateWith.length} existing integrations — consider if this source adds unique value`);
    }
  }

  // 6. Determine dependencies
  const dependsOn: string[] = [];
  // Scanners depend on recon completing first
  if (category === "scanner" && pipelineStages.includes("vuln_detection")) {
    // No hard dependency — the orchestrator handles phase ordering
  }
  // Exploit tools may depend on scanner results
  if (category === "pentest_tool" && pipelineStages.includes("exploitation")) {
    // No hard dependency — conditions handle this
  }

  // 7. Determine timeout
  const maxDurationMs = CATEGORY_TIMEOUT[category] ?? 60_000;

  // 8. Determine failure policy
  const failurePolicy = CATEGORY_FAILURE_POLICY[category] ?? "continue";

  // 9. Generate optimizations
  if (parallel && pipelineStages.length > 1) {
    optimizations.push("Consider splitting into separate connectors per stage for finer-grained control");
  }
  if (valueAssessment && valueAssessment.overlapPercent > 50) {
    optimizations.push(`Consider disabling overlapping sources (${valueAssessment.overlapSources.join(", ")}) to reduce API costs`);
  }

  const config: PipelineWiringConfig = {
    stages: pipelineStages,
    priority,
    parallel,
    dependsOn,
    conditions,
    outputMapping,
    deduplicateWith,
    maxDurationMs,
    failurePolicy,
  };

  return {
    config,
    explanation: explanations.join(". "),
    warnings,
    optimizations,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — PIPELINE COVERAGE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

export interface PipelineCoverageReport {
  /** Coverage per stage */
  stages: Record<PipelineStage, {
    integrationCount: number;
    integrations: string[];
    coverageLevel: "none" | "minimal" | "adequate" | "strong" | "excellent";
    gaps: string[];
    recommendations: string[];
  }>;
  /** Overall pipeline health score (0-100) */
  overallScore: number;
  /** Top recommendations */
  topRecommendations: string[];
}

/**
 * Analyze pipeline coverage and identify gaps.
 * This helps customers understand where they need more integrations.
 */
export function analyzePipelineCoverage(
  activeIntegrations: Array<{ id: string; category: IntegrationCategory; stages: PipelineStage[]; dataTypes: string[] }>,
): PipelineCoverageReport {
  const allStages: PipelineStage[] = [
    "recon", "passive_discovery", "enumeration", "vuln_detection",
    "social_engineering", "exploitation", "post_exploit", "reporting",
    "monitoring", "enrichment",
  ];

  const stages: Record<string, any> = {};
  let totalScore = 0;
  const topRecommendations: string[] = [];

  for (const stage of allStages) {
    const stageIntegrations = activeIntegrations.filter(i => i.stages.includes(stage));
    const count = stageIntegrations.length;

    let coverageLevel: "none" | "minimal" | "adequate" | "strong" | "excellent";
    let stageScore: number;
    if (count === 0) { coverageLevel = "none"; stageScore = 0; }
    else if (count <= 2) { coverageLevel = "minimal"; stageScore = 25; }
    else if (count <= 5) { coverageLevel = "adequate"; stageScore = 50; }
    else if (count <= 10) { coverageLevel = "strong"; stageScore = 75; }
    else { coverageLevel = "excellent"; stageScore = 100; }

    const gaps: string[] = [];
    const recommendations: string[] = [];

    // Stage-specific gap analysis
    if (stage === "recon" && count < 3) {
      gaps.push("Limited passive reconnaissance sources");
      recommendations.push("Add more OSINT sources (Shodan, Censys, SecurityTrails) for comprehensive recon");
    }
    if (stage === "vuln_detection" && count < 2) {
      gaps.push("Limited vulnerability scanning coverage");
      recommendations.push("Add DAST scanners (ZAP, Burp Suite) and template scanners (Nuclei) for better coverage");
    }
    if (stage === "monitoring" && count === 0) {
      gaps.push("No SIEM/SOAR integration — cannot correlate detections during engagements");
      recommendations.push("Connect a SIEM (Wazuh, Elastic) to enable evasion scorecard and detection correlation");
    }
    if (stage === "enrichment" && count < 2) {
      gaps.push("Limited threat intelligence enrichment");
      recommendations.push("Add threat intel feeds (AlienVault OTX, ThreatFox) for better context");
    }

    totalScore += stageScore;
    stages[stage] = {
      integrationCount: count,
      integrations: stageIntegrations.map(i => i.id),
      coverageLevel,
      gaps,
      recommendations,
    };

    if (gaps.length > 0) {
      topRecommendations.push(...recommendations);
    }
  }

  return {
    stages: stages as Record<PipelineStage, any>,
    overallScore: Math.round(totalScore / allStages.length),
    topRecommendations: topRecommendations.slice(0, 5),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — INTEGRATION VALUE COMPARISON
// ═══════════════════════════════════════════════════════════════════════

export interface ValueComparisonResult {
  /** The new integration being evaluated */
  newIntegration: { id: string; name: string };
  /** Existing integrations it overlaps with */
  overlaps: Array<{
    existingId: string;
    existingName: string;
    overlapPercent: number;
    sharedDataTypes: string[];
    uniqueToNew: string[];
    uniqueToExisting: string[];
  }>;
  /** Net new data types this integration provides */
  netNewDataTypes: string[];
  /** Net new pipeline stages this integration covers */
  netNewStages: PipelineStage[];
  /** Recommendation */
  recommendation: "strongly_recommended" | "recommended" | "optional" | "redundant";
  /** Explanation */
  explanation: string;
}

/**
 * Compare a new integration against existing ones to determine incremental value.
 */
export function compareIntegrationValue(
  newIntegration: { id: string; name: string; category: IntegrationCategory; dataTypes: string[]; stages: PipelineStage[] },
  existingIntegrations: Array<{ id: string; name: string; category: IntegrationCategory; dataTypes: string[]; stages: PipelineStage[] }>,
): ValueComparisonResult {
  const overlaps: ValueComparisonResult["overlaps"] = [];
  const allExistingDataTypes = new Set<string>();
  const allExistingStages = new Set<PipelineStage>();

  for (const existing of existingIntegrations) {
    for (const dt of existing.dataTypes) allExistingDataTypes.add(dt);
    for (const s of existing.stages) allExistingStages.add(s);

    const sharedDataTypes = newIntegration.dataTypes.filter(d => existing.dataTypes.includes(d));
    if (sharedDataTypes.length > 0) {
      const uniqueToNew = newIntegration.dataTypes.filter(d => !existing.dataTypes.includes(d));
      const uniqueToExisting = existing.dataTypes.filter(d => !newIntegration.dataTypes.includes(d));
      const overlapPercent = Math.round((sharedDataTypes.length / Math.max(newIntegration.dataTypes.length, 1)) * 100);

      overlaps.push({
        existingId: existing.id,
        existingName: existing.name,
        overlapPercent,
        sharedDataTypes,
        uniqueToNew,
        uniqueToExisting,
      });
    }
  }

  const netNewDataTypes = newIntegration.dataTypes.filter(d => !allExistingDataTypes.has(d));
  const netNewStages = newIntegration.stages.filter(s => !allExistingStages.has(s));

  // Determine recommendation
  let recommendation: ValueComparisonResult["recommendation"];
  let explanation: string;

  if (netNewStages.length > 0) {
    recommendation = "strongly_recommended";
    explanation = `Covers ${netNewStages.length} pipeline stage(s) not yet covered: ${netNewStages.join(", ")}`;
  } else if (netNewDataTypes.length > 0) {
    recommendation = "recommended";
    explanation = `Provides ${netNewDataTypes.length} new data type(s): ${netNewDataTypes.join(", ")}`;
  } else if (overlaps.every(o => o.overlapPercent < 50)) {
    recommendation = "optional";
    explanation = "Provides some unique data but mostly overlaps with existing sources";
  } else {
    recommendation = "redundant";
    explanation = "Highly overlaps with existing integrations — consider if the additional cost is justified";
  }

  return {
    newIntegration: { id: newIntegration.id, name: newIntegration.name },
    overlaps,
    netNewDataTypes,
    netNewStages,
    recommendation,
    explanation,
  };
}
