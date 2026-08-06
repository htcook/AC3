/**
 * Evasion Scorecard — Tier 3 of the Evasion Architecture
 * ───────────────────────────────────────────────────────
 * Connects the SIEM Rule Mutation Engine (Tier 1) and the Payload
 * Transformation Pipeline (Tier 2) into a unified scorecard that
 * shows both "what was detected" and "what would survive evasion."
 *
 * Produces:
 *   - Campaign Stealth Score (0-100)
 *   - Per-rule robustness ratings
 *   - Detection gap matrix (technique × EDR)
 *   - Purple team loop recommendations
 *   - Hardened rule suggestions
 */

import type {
  MutationTestResult,
  SigmaRulePattern,
  MutationVariant,
} from "./siem-mutation-engine";
import type {
  TransformPipeline,
  EvasionProfile,
} from "./payload-transform-pipeline";
import { EVASION_TECHNIQUES } from "./payload-transform-pipeline";

// ═══════════════════════════════════════════════════════════════════════
// §1 — CORE TYPES
// ═══════════════════════════════════════════════════════════════════════

export type DetectionStatus = "detected" | "evaded" | "partial" | "untested";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

/** A single technique's detection result across the purple team loop */
export interface TechniqueDetectionResult {
  /** ATT&CK technique ID */
  techniqueId: string;
  /** ATT&CK technique name */
  techniqueName: string;
  /** ATT&CK tactic */
  tactic: string;
  /** Was it detected by the SIEM/EDR? */
  detectionStatus: DetectionStatus;
  /** Which Sigma rules detected it */
  detectingRules: string[];
  /** How many mutation variants evaded detection */
  mutationEvasionRate: number;
  /** Which evasion techniques would bypass detection */
  applicableEvasions: string[];
  /** Risk level if this technique goes undetected */
  riskIfUndetected: RiskLevel;
  /** Recommended hardened rule (if evadable) */
  hardenedRuleSnippet?: string;
}

/** The complete evasion scorecard for a campaign */
export interface EvasionScorecard {
  /** Unique scorecard ID */
  id: string;
  /** Campaign or scan identifier */
  campaignId: string;
  /** When the scorecard was generated */
  generatedAt: number;
  /** Overall campaign stealth score (0-100) */
  campaignStealthScore: number;
  /** Stealth score band */
  stealthBand: "exposed" | "detectable" | "stealthy" | "ghost";
  /** Detection coverage percentage (how many techniques are detected) */
  detectionCoverage: number;
  /** Evasion success rate (how many detections can be bypassed) */
  evasionSuccessRate: number;
  /** Per-technique detection results */
  techniqueResults: TechniqueDetectionResult[];
  /** Detection gap matrix — techniques that are NOT detected */
  detectionGaps: DetectionGap[];
  /** Per-rule robustness ratings */
  ruleRobustness: RuleRobustnessRating[];
  /** Purple team loop recommendations */
  purpleTeamActions: PurpleTeamAction[];
  /** Summary statistics */
  summary: ScorecardSummary;
  /** Pipeline profile used (if any) */
  evasionProfile?: EvasionProfile;
  /** Pipeline stealth rating (if pipeline was applied) */
  pipelineStealthRating?: number;
}

export interface DetectionGap {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  riskLevel: RiskLevel;
  reason: string;
  recommendation: string;
  /** Sigma rule that SHOULD detect this but doesn't exist */
  suggestedRuleTitle: string;
}

export interface RuleRobustnessRating {
  ruleId: string;
  ruleTitle: string;
  /** 0-100 robustness score */
  robustnessScore: number;
  /** How many mutation variants the rule catches */
  variantsCaught: number;
  /** How many mutation variants evade the rule */
  variantsEvaded: number;
  /** Total variants tested */
  totalVariants: number;
  /** Weakest mutation categories */
  weakestCategories: string[];
  /** Whether the rule needs hardening */
  needsHardening: boolean;
  /** Hardening suggestions */
  hardeningSuggestions: string[];
}

export interface PurpleTeamAction {
  /** Priority order */
  priority: number;
  /** Action type */
  type: "create_rule" | "harden_rule" | "add_telemetry" | "tune_edr" | "test_evasion";
  /** Human-readable description */
  description: string;
  /** Which technique(s) this addresses */
  techniques: string[];
  /** Estimated effort */
  effort: "low" | "medium" | "high";
  /** Expected detection improvement (percentage points) */
  expectedImprovement: number;
}

export interface ScorecardSummary {
  totalTechniques: number;
  detected: number;
  evaded: number;
  partial: number;
  untested: number;
  totalRules: number;
  robustRules: number;
  fragileRules: number;
  criticalGaps: number;
  highGaps: number;
  mediumGaps: number;
  lowGaps: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — ATT&CK TECHNIQUE CATALOG (for scorecard context)
// ═══════════════════════════════════════════════════════════════════════

interface AttackTechniqueInfo {
  id: string;
  name: string;
  tactic: string;
  riskIfUndetected: RiskLevel;
  commonSigmaRules: string[];
}

const ATTACK_TECHNIQUE_CATALOG: AttackTechniqueInfo[] = [
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", riskIfUndetected: "critical", commonSigmaRules: ["proc_creation_win_powershell_suspicious_cmd", "powershell_script_block_logging"] },
  { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution", riskIfUndetected: "high", commonSigmaRules: ["proc_creation_win_cmd_suspicious"] },
  { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence", riskIfUndetected: "high", commonSigmaRules: ["proc_creation_win_schtasks_creation"] },
  { id: "T1547.001", name: "Registry Run Keys", tactic: "Persistence", riskIfUndetected: "high", commonSigmaRules: ["registry_set_run_key"] },
  { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion", riskIfUndetected: "critical", commonSigmaRules: ["sysmon_process_hollowing"] },
  { id: "T1055.004", name: "APC Queue Injection", tactic: "Defense Evasion", riskIfUndetected: "critical", commonSigmaRules: ["sysmon_apc_injection"] },
  { id: "T1027", name: "Obfuscated Files", tactic: "Defense Evasion", riskIfUndetected: "medium", commonSigmaRules: ["proc_creation_win_obfuscation"] },
  { id: "T1027.009", name: "Embedded Payloads", tactic: "Defense Evasion", riskIfUndetected: "high", commonSigmaRules: [] },
  { id: "T1106", name: "Native API", tactic: "Execution", riskIfUndetected: "high", commonSigmaRules: ["sysmon_direct_syscall"] },
  { id: "T1562.001", name: "Disable Security Tools", tactic: "Defense Evasion", riskIfUndetected: "critical", commonSigmaRules: ["proc_creation_win_disable_defender", "sysmon_amsi_bypass"] },
  { id: "T1562.006", name: "Indicator Blocking (ETW)", tactic: "Defense Evasion", riskIfUndetected: "critical", commonSigmaRules: ["sysmon_etw_tamper"] },
  { id: "T1553.002", name: "Code Signing", tactic: "Defense Evasion", riskIfUndetected: "medium", commonSigmaRules: [] },
  { id: "T1574.002", name: "DLL Side-Loading", tactic: "Persistence", riskIfUndetected: "high", commonSigmaRules: ["sysmon_dll_sideload"] },
  { id: "T1003.001", name: "LSASS Memory Dump", tactic: "Credential Access", riskIfUndetected: "critical", commonSigmaRules: ["proc_access_win_lsass_dump", "sysmon_lsass_access"] },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement", riskIfUndetected: "high", commonSigmaRules: ["net_connection_win_smb_lateral"] },
  { id: "T1071.001", name: "Web Protocols C2", tactic: "Command and Control", riskIfUndetected: "high", commonSigmaRules: ["proxy_c2_beacon"] },
  { id: "T1048", name: "Exfiltration Over C2", tactic: "Exfiltration", riskIfUndetected: "critical", commonSigmaRules: ["proxy_large_upload"] },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access", riskIfUndetected: "critical", commonSigmaRules: ["win_security_login_anomaly"] },
  { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", riskIfUndetected: "high", commonSigmaRules: ["proc_creation_win_office_spawn"] },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", riskIfUndetected: "critical", commonSigmaRules: ["sysmon_ransomware_behavior"] },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — SCORECARD GENERATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a complete evasion scorecard from mutation test results,
 * a list of campaign techniques, and an optional payload pipeline.
 */
export function generateEvasionScorecard(input: {
  campaignId: string;
  /** ATT&CK technique IDs used in the campaign */
  campaignTechniques: string[];
  /** Sigma rule mutation test results (from Tier 1) */
  mutationResults?: MutationTestResult[];
  /** Command mutation results (from Tier 1) */
  commandMutationResults?: MutationTestResult[];
  /** Pipeline configuration (from Tier 2) */
  pipeline?: TransformPipeline;
  /** Known detected techniques (from SIEM correlation) */
  detectedTechniques?: string[];
  /** Known evaded techniques (from SIEM correlation) */
  evadedTechniques?: string[];
}): EvasionScorecard {
  const {
    campaignId,
    campaignTechniques,
    mutationResults = [],
    commandMutationResults = [],
    pipeline,
    detectedTechniques = [],
    evadedTechniques = [],
  } = input;

  // Build per-technique results
  const techniqueResults = buildTechniqueResults(
    campaignTechniques,
    mutationResults,
    commandMutationResults,
    pipeline,
    detectedTechniques,
    evadedTechniques
  );

  // Build rule robustness ratings
  const ruleRobustness = buildRuleRobustness(mutationResults);

  // Build detection gaps
  const detectionGaps = buildDetectionGaps(techniqueResults);

  // Build purple team actions
  const purpleTeamActions = buildPurpleTeamActions(
    techniqueResults,
    ruleRobustness,
    detectionGaps
  );

  // Compute summary
  const summary = computeSummary(techniqueResults, ruleRobustness, detectionGaps);

  // Compute campaign stealth score
  const campaignStealthScore = computeCampaignStealthScore(
    techniqueResults,
    ruleRobustness,
    pipeline
  );

  const stealthBand = getStealthBand(campaignStealthScore);

  // Detection coverage
  const detectionCoverage =
    techniqueResults.length > 0
      ? Math.round(
          ((summary.detected + summary.partial) / techniqueResults.length) * 100
        )
      : 0;

  // Evasion success rate
  const evasionSuccessRate =
    summary.detected + summary.partial > 0
      ? Math.round(
          (summary.evaded / (summary.detected + summary.partial + summary.evaded)) * 100
        )
      : 0;

  return {
    id: `scorecard-${campaignId}-${Date.now()}`,
    campaignId,
    generatedAt: Date.now(),
    campaignStealthScore,
    stealthBand,
    detectionCoverage,
    evasionSuccessRate,
    techniqueResults,
    detectionGaps,
    ruleRobustness,
    purpleTeamActions,
    summary,
    evasionProfile: pipeline?.profile,
    pipelineStealthRating: pipeline?.stealthRating,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — TECHNIQUE RESULT BUILDER
// ═══════════════════════════════════════════════════════════════════════

function buildTechniqueResults(
  campaignTechniques: string[],
  mutationResults: MutationTestResult[],
  commandMutationResults: MutationTestResult[],
  pipeline: TransformPipeline | undefined,
  detectedTechniques: string[],
  evadedTechniques: string[]
): TechniqueDetectionResult[] {
  const results: TechniqueDetectionResult[] = [];

  for (const techId of campaignTechniques) {
    const catalogEntry = ATTACK_TECHNIQUE_CATALOG.find((t) => t.id === techId);
    const techniqueName = catalogEntry?.name || techId;
    const tactic = catalogEntry?.tactic || "Unknown";
    const riskIfUndetected = catalogEntry?.riskIfUndetected || "medium";

    // Determine detection status
    let detectionStatus: DetectionStatus = "untested";
    if (detectedTechniques.includes(techId)) {
      detectionStatus = "detected";
    } else if (evadedTechniques.includes(techId)) {
      detectionStatus = "evaded";
    }

    // Find relevant mutation results for this technique
    // Use detectionPattern as a proxy — if the pattern mentions the technique ID
    const relevantMutations = mutationResults.filter(
      (mr) =>
        mr.detectionPattern.includes(techId) ||
        mr.originalCommand.toLowerCase().includes(techniqueName.toLowerCase())
    );

    // Calculate mutation evasion rate
    let mutationEvasionRate = 0;
    const detectingRules: string[] = [];

    if (relevantMutations.length > 0) {
      let totalVariants = 0;
      let evadedVariants = 0;

      for (const mr of relevantMutations) {
        detectingRules.push(mr.detectionPattern.slice(0, 60));
        for (const v of mr.variants) {
          totalVariants++;
          if (!v.detected) evadedVariants++;
        }
      }

      mutationEvasionRate =
        totalVariants > 0
          ? Math.round((evadedVariants / totalVariants) * 100)
          : 0;

      // If mutation testing shows high evasion, upgrade status
      if (mutationEvasionRate > 70 && detectionStatus === "detected") {
        detectionStatus = "partial";
      }
    }

    // Check command mutation results too
    for (const cmr of commandMutationResults) {
      if (cmr.variants.some((v: MutationVariant) => !v.detected)) {
        // If any command variant evades, note it
        if (detectionStatus === "detected") {
          detectionStatus = "partial";
        }
      }
    }

    // Find applicable evasion techniques from the pipeline
    const applicableEvasions: string[] = [];
    if (pipeline) {
      for (const step of pipeline.steps) {
        for (const evasionId of step.evasionTechniques) {
          const evasionTech = EVASION_TECHNIQUES.find(
            (et) => et.id === evasionId
          );
          if (evasionTech) {
            applicableEvasions.push(evasionTech.name);
          }
        }
      }
    }

    results.push({
      techniqueId: techId,
      techniqueName,
      tactic,
      detectionStatus,
      detectingRules,
      mutationEvasionRate,
      applicableEvasions: Array.from(new Set(applicableEvasions)),
      riskIfUndetected,
    });
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — RULE ROBUSTNESS BUILDER
// ═══════════════════════════════════════════════════════════════════════

function buildRuleRobustness(
  mutationResults: MutationTestResult[]
): RuleRobustnessRating[] {
  return mutationResults.map((mr) => {
    const totalVariants = mr.totalVariants;
    const variantsEvaded = mr.evadedCount;
    const variantsCaught = mr.detectedCount;
    const robustnessScore = mr.robustnessScore;

    const weakestCategories = mr.weakestCategories;
    const needsHardening = robustnessScore < 70;
    const hardeningSuggestions = [...mr.hardeningTips];

    return {
      ruleId: mr.detectionPattern.slice(0, 60),
      ruleTitle: mr.detectionPattern.slice(0, 80),
      robustnessScore,
      variantsCaught,
      variantsEvaded,
      totalVariants,
      weakestCategories,
      needsHardening,
      hardeningSuggestions,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — DETECTION GAP BUILDER
// ═══════════════════════════════════════════════════════════════════════

function buildDetectionGaps(
  techniqueResults: TechniqueDetectionResult[]
): DetectionGap[] {
  const gaps: DetectionGap[] = [];

  for (const tr of techniqueResults) {
    if (tr.detectionStatus === "evaded" || tr.detectionStatus === "untested") {
      const catalogEntry = ATTACK_TECHNIQUE_CATALOG.find(
        (t) => t.id === tr.techniqueId
      );

      let reason: string;
      let recommendation: string;
      let suggestedRuleTitle: string;

      if (tr.detectionStatus === "untested") {
        reason = "No Sigma rule exists for this technique in the current rule set.";
        recommendation = `Create a Sigma rule targeting ${tr.techniqueName} (${tr.techniqueId}). Monitor for characteristic process creation, API calls, or network patterns.`;
        suggestedRuleTitle = `Detect ${tr.techniqueName} Activity`;
      } else {
        reason =
          tr.detectingRules.length > 0
            ? `Existing rules (${tr.detectingRules.join(", ")}) were bypassed by evasion techniques.`
            : "Technique was executed without triggering any detection rules.";
        recommendation = `Harden existing rules or create behavioral detection for ${tr.techniqueName}. Consider process relationship monitoring and API call sequence detection.`;
        suggestedRuleTitle = `Hardened Detection for ${tr.techniqueName}`;
      }

      gaps.push({
        techniqueId: tr.techniqueId,
        techniqueName: tr.techniqueName,
        tactic: tr.tactic,
        riskLevel: tr.riskIfUndetected,
        reason,
        recommendation,
        suggestedRuleTitle,
      });
    }

    // Also flag partial detections as gaps
    if (tr.detectionStatus === "partial" && tr.mutationEvasionRate > 50) {
      gaps.push({
        techniqueId: tr.techniqueId,
        techniqueName: tr.techniqueName,
        tactic: tr.tactic,
        riskLevel: tr.riskIfUndetected === "critical" ? "critical" : "high",
        reason: `Detection rules exist but ${tr.mutationEvasionRate}% of mutation variants evade them.`,
        recommendation: `Harden rules: ${tr.detectingRules.join(", ")}. Add case-insensitive matching, path normalization, and behavioral correlation.`,
        suggestedRuleTitle: `Hardened ${tr.techniqueName} Detection`,
      });
    }
  }

  // Sort by risk level
  const riskOrder: Record<RiskLevel, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  gaps.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  return gaps;
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — PURPLE TEAM ACTION BUILDER
// ═══════════════════════════════════════════════════════════════════════

function buildPurpleTeamActions(
  techniqueResults: TechniqueDetectionResult[],
  ruleRobustness: RuleRobustnessRating[],
  detectionGaps: DetectionGap[]
): PurpleTeamAction[] {
  const actions: PurpleTeamAction[] = [];
  let priority = 1;

  // 1. Critical gaps need new rules
  const criticalGaps = detectionGaps.filter((g) => g.riskLevel === "critical");
  if (criticalGaps.length > 0) {
    actions.push({
      priority: priority++,
      type: "create_rule",
      description: `Create detection rules for ${criticalGaps.length} critical undetected technique(s): ${criticalGaps.map((g) => g.techniqueName).join(", ")}`,
      techniques: criticalGaps.map((g) => g.techniqueId),
      effort: criticalGaps.length > 3 ? "high" : "medium",
      expectedImprovement: Math.min(30, criticalGaps.length * 8),
    });
  }

  // 2. Fragile rules need hardening
  const fragileRules = ruleRobustness.filter((r) => r.needsHardening);
  if (fragileRules.length > 0) {
    actions.push({
      priority: priority++,
      type: "harden_rule",
      description: `Harden ${fragileRules.length} fragile detection rule(s) with robustness scores below 70%: ${fragileRules.map((r) => r.ruleTitle).join(", ")}`,
      techniques: [],
      effort: fragileRules.length > 5 ? "high" : "medium",
      expectedImprovement: Math.min(25, fragileRules.length * 5),
    });
  }

  // 3. High gaps need rules
  const highGaps = detectionGaps.filter((g) => g.riskLevel === "high");
  if (highGaps.length > 0) {
    actions.push({
      priority: priority++,
      type: "create_rule",
      description: `Create detection rules for ${highGaps.length} high-risk undetected technique(s): ${highGaps.map((g) => g.techniqueName).join(", ")}`,
      techniques: highGaps.map((g) => g.techniqueId),
      effort: highGaps.length > 3 ? "high" : "medium",
      expectedImprovement: Math.min(20, highGaps.length * 5),
    });
  }

  // 4. Add telemetry for untested techniques
  const untestedTechniques = techniqueResults.filter(
    (t) => t.detectionStatus === "untested"
  );
  if (untestedTechniques.length > 0) {
    actions.push({
      priority: priority++,
      type: "add_telemetry",
      description: `Enable telemetry collection for ${untestedTechniques.length} untested technique(s) to establish detection baseline.`,
      techniques: untestedTechniques.map((t) => t.techniqueId),
      effort: "medium",
      expectedImprovement: 10,
    });
  }

  // 5. Tune EDR for partial detections
  const partialDetections = techniqueResults.filter(
    (t) => t.detectionStatus === "partial"
  );
  if (partialDetections.length > 0) {
    actions.push({
      priority: priority++,
      type: "tune_edr",
      description: `Tune EDR policies for ${partialDetections.length} partially-detected technique(s) to improve catch rate.`,
      techniques: partialDetections.map((t) => t.techniqueId),
      effort: "low",
      expectedImprovement: Math.min(15, partialDetections.length * 3),
    });
  }

  // 6. Test evasion on detected techniques
  const detectedTechniques = techniqueResults.filter(
    (t) => t.detectionStatus === "detected" && t.mutationEvasionRate === 0
  );
  if (detectedTechniques.length > 0) {
    actions.push({
      priority: priority++,
      type: "test_evasion",
      description: `Run mutation testing against ${detectedTechniques.length} detected technique(s) to verify rule robustness.`,
      techniques: detectedTechniques.map((t) => t.techniqueId),
      effort: "low",
      expectedImprovement: 5,
    });
  }

  return actions;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — SCORING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function computeSummary(
  techniqueResults: TechniqueDetectionResult[],
  ruleRobustness: RuleRobustnessRating[],
  detectionGaps: DetectionGap[]
): ScorecardSummary {
  return {
    totalTechniques: techniqueResults.length,
    detected: techniqueResults.filter((t) => t.detectionStatus === "detected").length,
    evaded: techniqueResults.filter((t) => t.detectionStatus === "evaded").length,
    partial: techniqueResults.filter((t) => t.detectionStatus === "partial").length,
    untested: techniqueResults.filter((t) => t.detectionStatus === "untested").length,
    totalRules: ruleRobustness.length,
    robustRules: ruleRobustness.filter((r) => !r.needsHardening).length,
    fragileRules: ruleRobustness.filter((r) => r.needsHardening).length,
    criticalGaps: detectionGaps.filter((g) => g.riskLevel === "critical").length,
    highGaps: detectionGaps.filter((g) => g.riskLevel === "high").length,
    mediumGaps: detectionGaps.filter((g) => g.riskLevel === "medium").length,
    lowGaps: detectionGaps.filter((g) => g.riskLevel === "low").length,
  };
}

function computeCampaignStealthScore(
  techniqueResults: TechniqueDetectionResult[],
  ruleRobustness: RuleRobustnessRating[],
  pipeline?: TransformPipeline
): number {
  if (techniqueResults.length === 0) return 50;

  // Factor 1: Detection evasion rate (40% weight)
  const evadedOrUntested = techniqueResults.filter(
    (t) => t.detectionStatus === "evaded" || t.detectionStatus === "untested"
  ).length;
  const partialCount = techniqueResults.filter(
    (t) => t.detectionStatus === "partial"
  ).length;
  const evasionFactor =
    ((evadedOrUntested + partialCount * 0.5) / techniqueResults.length) * 100;

  // Factor 2: Rule fragility (25% weight)
  const avgRobustness =
    ruleRobustness.length > 0
      ? ruleRobustness.reduce((sum, r) => sum + r.robustnessScore, 0) /
        ruleRobustness.length
      : 50;
  const fragilityFactor = 100 - avgRobustness;

  // Factor 3: Mutation evasion rate across techniques (20% weight)
  const avgMutationEvasion =
    techniqueResults.length > 0
      ? techniqueResults.reduce((sum, t) => sum + t.mutationEvasionRate, 0) /
        techniqueResults.length
      : 0;

  // Factor 4: Pipeline stealth (15% weight)
  const pipelineFactor = pipeline?.stealthRating || 0;

  const score = Math.round(
    evasionFactor * 0.4 +
      fragilityFactor * 0.25 +
      avgMutationEvasion * 0.2 +
      pipelineFactor * 0.15
  );

  return Math.max(0, Math.min(100, score));
}

function getStealthBand(
  score: number
): "exposed" | "detectable" | "stealthy" | "ghost" {
  if (score >= 80) return "ghost";
  if (score >= 60) return "stealthy";
  if (score >= 35) return "detectable";
  return "exposed";
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — PURPLE TEAM LOOP ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * The 4-step purple team automation cycle:
 *   Execute → Detect → Evade → Improve
 *
 * This function generates the full cycle plan for a given set of techniques.
 */
export interface PurpleTeamCycle {
  /** Cycle identifier */
  cycleId: string;
  /** Techniques being tested */
  techniques: string[];
  /** Step 1: Execute — what to run */
  executePhase: {
    description: string;
    calderaAbilities: string[];
    evasionProfile: EvasionProfile;
  };
  /** Step 2: Detect — what to check */
  detectPhase: {
    description: string;
    sigmaRulesToCheck: string[];
    siemQueries: string[];
    expectedAlerts: number;
  };
  /** Step 3: Evade — what mutations to test */
  evadePhase: {
    description: string;
    mutationCategories: string[];
    pipelineProfile: EvasionProfile;
    expectedEvasionRate: number;
  };
  /** Step 4: Improve — what to fix */
  improvePhase: {
    description: string;
    rulesToHarden: string[];
    newRulesToCreate: string[];
    edrTuning: string[];
  };
}

export function generatePurpleTeamCycle(
  techniques: string[],
  currentScorecard?: EvasionScorecard
): PurpleTeamCycle {
  const cycleId = `ptc-${Date.now()}`;

  // Step 1: Execute
  const executePhase = {
    description: `Execute ${techniques.length} ATT&CK technique(s) via Caldera with baseline (no evasion) profile to establish detection baseline.`,
    calderaAbilities: techniques,
    evasionProfile: "none" as EvasionProfile,
  };

  // Step 2: Detect
  const relevantRules: string[] = [];
  for (const techId of techniques) {
    const catalog = ATTACK_TECHNIQUE_CATALOG.find((t) => t.id === techId);
    if (catalog) {
      relevantRules.push(...catalog.commonSigmaRules);
    }
  }

  const detectPhase = {
    description: `Query SIEM for alerts matching ${techniques.length} technique(s). Check ${relevantRules.length} Sigma rule(s) for detection hits.`,
    sigmaRulesToCheck: Array.from(new Set(relevantRules)),
    siemQueries: techniques.map(
      (t) => `event.category:process AND mitre.technique.id:${t}`
    ),
    expectedAlerts: techniques.length,
  };

  // Step 3: Evade
  const evadePhase = {
    description: `Re-execute with mutation variants and escalating evasion profiles (low → medium → high) to test detection robustness.`,
    mutationCategories: [
      "case_mutation",
      "path_mutation",
      "encoding_mutation",
      "argument_mutation",
      "env_var_substitution",
      "separator_mutation",
      "alias_substitution",
    ],
    pipelineProfile: "medium" as EvasionProfile,
    expectedEvasionRate: 40,
  };

  // Step 4: Improve
  const rulesToHarden: string[] = [];
  const newRulesToCreate: string[] = [];
  const edrTuning: string[] = [];

  if (currentScorecard) {
    for (const rr of currentScorecard.ruleRobustness) {
      if (rr.needsHardening) {
        rulesToHarden.push(rr.ruleTitle);
      }
    }
    for (const gap of currentScorecard.detectionGaps) {
      newRulesToCreate.push(gap.suggestedRuleTitle);
    }
    for (const tr of currentScorecard.techniqueResults) {
      if (tr.detectionStatus === "partial") {
        edrTuning.push(
          `Tune EDR policy for ${tr.techniqueName} (${tr.techniqueId})`
        );
      }
    }
  }

  const improvePhase = {
    description: `Apply ${rulesToHarden.length + newRulesToCreate.length} rule improvements and ${edrTuning.length} EDR tuning changes based on evasion results.`,
    rulesToHarden,
    newRulesToCreate,
    edrTuning,
  };

  return {
    cycleId,
    techniques,
    executePhase,
    detectPhase,
    evadePhase,
    improvePhase,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — EXPORTS
// ═══════════════════════════════════════════════════════════════════════

export { ATTACK_TECHNIQUE_CATALOG };
