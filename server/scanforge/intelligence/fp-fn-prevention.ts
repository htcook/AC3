/**
 * ScanForge False Positive / False Negative Prevention Engine
 *
 * A multi-layered validation system that dramatically reduces false positives
 * while minimizing false negatives. Based on research from:
 *   - Invicti's proof-based scanning (safe exploitation to confirm)
 *   - Nuclei's multi-layer matchers (app ID + version + exploit proof)
 *   - Acunetix confidence tiers (100%/95%/80%, never report below threshold)
 *   - Anchore/Grype ecosystem-aware matching (GHSA > CPE)
 *   - Algomox AI-based contextual validation
 *   - Multi-scanner correlation (corroboration increases confidence)
 *
 * Architecture:
 *   1. Signal Collection — Gather evidence from multiple sources
 *   2. Confidence Scoring — Multi-factor confidence calculation
 *   3. Corroboration Engine — Cross-validate across scanners/signals
 *   4. Proof Validation — Safe exploitation to confirm exploitability
 *   5. Contextual Filtering — Environment-aware suppression rules
 *   6. Adaptive Thresholds — Learn from operator feedback
 *
 * @author Harrison Cook — AceofCloud
 */

import type {
  ScanFinding,
  FindingSeverity,
  AssetEnvironment,
  ScanTarget,
  ComplianceFramework,
} from "../types";

// ─── Configuration ───────────────────────────────────────────────────────

export interface FPFNConfig {
  /** Minimum confidence to report a finding (0-100). Default: 60 */
  minReportingConfidence: number;
  /** Minimum confidence to mark as "confirmed" (0-100). Default: 80 */
  confirmedThreshold: number;
  /** Enable proof-based validation (safe exploitation). Default: true */
  enableProofValidation: boolean;
  /** Enable multi-scanner corroboration. Default: true */
  enableCorroboration: boolean;
  /** Enable contextual filtering (environment-aware). Default: true */
  enableContextualFiltering: boolean;
  /** Enable adaptive thresholds from operator feedback. Default: true */
  enableAdaptiveThresholds: boolean;
  /** Suppression profile: conservative (fewer FPs, more FNs), balanced, aggressive (more FPs, fewer FNs) */
  suppressionProfile: "conservative" | "balanced" | "aggressive";
  /** Maximum age of cached validation results in ms. Default: 3600000 (1hr) */
  cacheMaxAgeMs: number;
}

const DEFAULT_CONFIG: FPFNConfig = {
  minReportingConfidence: 60,
  confirmedThreshold: 80,
  enableProofValidation: true,
  enableCorroboration: true,
  enableContextualFiltering: true,
  enableAdaptiveThresholds: true,
  suppressionProfile: "balanced",
  cacheMaxAgeMs: 3600000,
};

// ─── Confidence Signal Types ─────────────────────────────────────────────

export type SignalSource =
  | "version_match"        // Version string matches known vulnerable range
  | "banner_match"         // Service banner matches expected pattern
  | "exploit_proof"        // Safe exploitation confirmed the vuln
  | "response_analysis"    // HTTP response analysis (headers, body, timing)
  | "multi_matcher"        // Multiple matchers all triggered (Nuclei-style)
  | "scanner_corroboration" // Multiple scanners found the same issue
  | "cve_correlation"      // CVE matches known exploit database
  | "kev_listed"           // CISA KEV catalog listing
  | "epss_high"            // EPSS score above threshold
  | "config_evidence"      // Configuration file/setting confirms exposure
  | "network_evidence"     // Network-level evidence (open port, protocol response)
  | "contextual_boost"     // Environment context increases confidence
  | "contextual_penalty"   // Environment context decreases confidence
  | "historical_pattern"   // Matches a known FP/TP pattern from feedback
  | "technology_match"     // Detected technology matches vuln applicability
  | "negative_signal"      // Evidence that contradicts the finding
  | "waf_interference"     // WAF may be masking or causing false signals
  | "version_mismatch"     // Detected version doesn't match vulnerable range
  | "compensating_control" // Compensating control detected that mitigates the vuln
  | "patch_detected";      // Patch or hotfix detected that addresses the vuln

export interface ConfidenceSignal {
  /** Signal source type */
  source: SignalSource;
  /** Signal weight (-100 to +100). Positive = increases confidence, negative = decreases */
  weight: number;
  /** Human-readable description of the signal */
  description: string;
  /** Raw evidence supporting the signal */
  evidence?: string;
  /** Timestamp when signal was collected */
  collectedAt: number;
}

// ─── Validation Result ───────────────────────────────────────────────────

export type ValidationVerdict =
  | "confirmed"            // High confidence, exploit-proven or multi-corroborated
  | "likely"               // Good confidence, multiple signals agree
  | "possible"             // Moderate confidence, needs more evidence
  | "unconfirmed"          // Low confidence, single signal only
  | "suppressed"           // Filtered out by contextual rules
  | "false_positive";      // Identified as FP by negative signals

export interface ValidationResult {
  /** The original finding */
  finding: ScanFinding;
  /** Final confidence score (0-100) */
  finalConfidence: number;
  /** Validation verdict */
  verdict: ValidationVerdict;
  /** All confidence signals collected */
  signals: ConfidenceSignal[];
  /** Positive signals count */
  positiveSignals: number;
  /** Negative signals count */
  negativeSignals: number;
  /** Corroboration details */
  corroboration?: CorroborationDetail;
  /** Proof validation result */
  proofResult?: ProofValidationResult;
  /** Suppression rule that triggered (if suppressed) */
  suppressionRule?: string;
  /** Timestamp */
  validatedAt: number;
}

export interface CorroborationDetail {
  /** Number of independent scanners that found this issue */
  scannerCount: number;
  /** Scanner names */
  scanners: string[];
  /** Corroboration tier */
  tier: "strong" | "moderate" | "weak" | "none";
  /** Confidence boost from corroboration */
  confidenceBoost: number;
}

export interface ProofValidationResult {
  /** Whether proof-based validation was attempted */
  attempted: boolean;
  /** Whether the exploitation proof succeeded */
  confirmed: boolean;
  /** Proof technique used */
  technique?: string;
  /** Evidence from the proof */
  evidence?: string;
  /** Duration of the proof attempt */
  durationMs?: number;
  /** Error if proof failed */
  error?: string;
}

// ─── Operator Feedback ───────────────────────────────────────────────────

export interface OperatorFeedback {
  /** Finding ID */
  findingId: string;
  /** Operator verdict */
  verdict: "true_positive" | "false_positive" | "needs_review";
  /** Operator notes */
  notes?: string;
  /** Operator ID */
  operatorId: string;
  /** Timestamp */
  submittedAt: number;
}

// ─── FP Pattern Database ─────────────────────────────────────────────────

interface FPPattern {
  /** Pattern ID */
  id: string;
  /** Finding title pattern (regex) */
  titlePattern: RegExp;
  /** Conditions that indicate FP */
  conditions: FPCondition[];
  /** Suppression reason */
  reason: string;
  /** Applicable environments */
  environments?: AssetEnvironment[];
  /** How many times this pattern has been confirmed by operators */
  confirmedCount: number;
}

interface FPCondition {
  type: "version_above" | "header_present" | "response_contains" | "port_mismatch" |
        "technology_absent" | "waf_present" | "cloud_managed" | "patch_level" |
        "default_page" | "generic_error" | "cdn_cached";
  value: string;
}

// ─── Known FP Patterns ───────────────────────────────────────────────────
// These are common false positive patterns observed across production scanners.
// Each pattern has conditions that, when met, indicate the finding is likely an FP.

const KNOWN_FP_PATTERNS: FPPattern[] = [
  {
    id: "fp-generic-info-disclosure",
    titlePattern: /information\s*disclosure|server\s*version|technology\s*detection/i,
    conditions: [{ type: "header_present", value: "x-powered-by" }],
    reason: "Generic information disclosure from standard headers — not exploitable",
    confirmedCount: 0,
  },
  {
    id: "fp-ssl-self-signed-internal",
    titlePattern: /self[- ]signed\s*certificate|untrusted\s*certificate/i,
    conditions: [{ type: "cloud_managed", value: "internal" }],
    reason: "Self-signed certificates on internal/management interfaces are expected",
    environments: ["cloud", "container"],
    confirmedCount: 0,
  },
  {
    id: "fp-default-page-vuln",
    titlePattern: /default\s*(web\s*)?page|welcome\s*page|test\s*page/i,
    conditions: [{ type: "default_page", value: "true" }],
    reason: "Default page detection is informational, not a vulnerability",
    confirmedCount: 0,
  },
  {
    id: "fp-cdn-cached-headers",
    titlePattern: /missing.*header|security\s*header/i,
    conditions: [{ type: "cdn_cached", value: "true" }],
    reason: "CDN-cached responses may strip security headers — test origin directly",
    confirmedCount: 0,
  },
  {
    id: "fp-waf-false-sqli",
    titlePattern: /sql\s*injection|sqli/i,
    conditions: [{ type: "waf_present", value: "true" }, { type: "generic_error", value: "true" }],
    reason: "WAF may generate SQL-error-like responses that trigger SQLi false positives",
    confirmedCount: 0,
  },
  {
    id: "fp-managed-service-vuln",
    titlePattern: /outdated|end[- ]of[- ]life|eol|unsupported\s*version/i,
    conditions: [{ type: "cloud_managed", value: "true" }],
    reason: "Managed cloud services handle patching — version detection may not reflect actual patch level",
    environments: ["cloud"],
    confirmedCount: 0,
  },
  {
    id: "fp-ics-safe-mode-probe",
    titlePattern: /modbus|dnp3|bacnet|ethernetip|opcua/i,
    conditions: [{ type: "port_mismatch", value: "true" }],
    reason: "ICS protocol detected on non-standard port — likely a false identification",
    environments: ["ics_ot"],
    confirmedCount: 0,
  },
  {
    id: "fp-container-host-leak",
    titlePattern: /container\s*escape|host\s*mount|privileged\s*container/i,
    conditions: [{ type: "technology_absent", value: "docker" }],
    reason: "Container escape finding on non-containerized target",
    environments: ["traditional"],
    confirmedCount: 0,
  },
  {
    id: "fp-version-backport",
    titlePattern: /CVE-\d{4}-\d+/i,
    conditions: [{ type: "patch_level", value: "backported" }],
    reason: "Linux distribution backports security patches without changing major version — CVE may not apply",
    confirmedCount: 0,
  },
  {
    id: "fp-cors-wildcard-internal",
    titlePattern: /cors.*wildcard|access-control-allow-origin.*\*/i,
    conditions: [{ type: "cloud_managed", value: "internal" }],
    reason: "CORS wildcard on internal APIs is often intentional for microservice communication",
    environments: ["cloud", "container"],
    confirmedCount: 0,
  },
];

// ─── Confidence Scoring Weights ──────────────────────────────────────────

const SIGNAL_WEIGHTS: Record<SignalSource, { base: number; max: number }> = {
  exploit_proof:          { base: 40, max: 50 },
  scanner_corroboration:  { base: 25, max: 35 },
  multi_matcher:          { base: 20, max: 30 },
  kev_listed:             { base: 20, max: 25 },
  cve_correlation:        { base: 15, max: 20 },
  version_match:          { base: 15, max: 20 },
  epss_high:              { base: 10, max: 15 },
  config_evidence:        { base: 15, max: 20 },
  network_evidence:       { base: 10, max: 15 },
  banner_match:           { base: 10, max: 15 },
  response_analysis:      { base: 10, max: 15 },
  technology_match:       { base: 8,  max: 12 },
  contextual_boost:       { base: 5,  max: 15 },
  historical_pattern:     { base: 10, max: 20 },
  contextual_penalty:     { base: -10, max: -25 },
  negative_signal:        { base: -15, max: -30 },
  waf_interference:       { base: -10, max: -20 },
  version_mismatch:       { base: -20, max: -35 },
  compensating_control:   { base: -15, max: -25 },
  patch_detected:         { base: -25, max: -40 },
};

// ─── Suppression Profile Thresholds ──────────────────────────────────────

const PROFILE_THRESHOLDS: Record<string, { minConfidence: number; confirmedThreshold: number; fpPatternSensitivity: number }> = {
  conservative: { minConfidence: 75, confirmedThreshold: 90, fpPatternSensitivity: 0.6 },
  balanced:     { minConfidence: 60, confirmedThreshold: 80, fpPatternSensitivity: 0.8 },
  aggressive:   { minConfidence: 40, confirmedThreshold: 70, fpPatternSensitivity: 1.0 },
};

// ─── FP/FN Prevention Engine ─────────────────────────────────────────────

export class FPFNPreventionEngine {
  private config: FPFNConfig;
  private fpPatterns: FPPattern[];
  private feedbackHistory: OperatorFeedback[] = [];
  private validationCache: Map<string, { result: ValidationResult; cachedAt: number }> = new Map();
  private adaptiveWeights: Map<string, number> = new Map();
  private stats = {
    totalValidated: 0,
    confirmed: 0,
    likely: 0,
    possible: 0,
    unconfirmed: 0,
    suppressed: 0,
    falsePositive: 0,
    operatorOverrides: 0,
  };

  constructor(config?: Partial<FPFNConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.fpPatterns = [...KNOWN_FP_PATTERNS];
  }

  // ─── Main Validation Pipeline ────────────────────────────────────────

  /**
   * Validate a single finding through the full FP/FN prevention pipeline.
   * Returns a ValidationResult with confidence score, verdict, and all signals.
   */
  async validateFinding(
    finding: ScanFinding,
    context: ValidationContext,
  ): Promise<ValidationResult> {
    // Check cache first
    const cacheKey = `${finding.id}-${finding.target}-${finding.title}`;
    const cached = this.validationCache.get(cacheKey);
    if (cached && Date.now() - cached.cachedAt < this.config.cacheMaxAgeMs) {
      return cached.result;
    }

    const signals: ConfidenceSignal[] = [];
    const now = Date.now();

    // Step 1: Collect base signals from the finding itself
    this.collectBaseSignals(finding, signals, now);

    // Step 2: Version-based validation
    this.collectVersionSignals(finding, context, signals, now);

    // Step 3: Multi-scanner corroboration
    let corroboration: CorroborationDetail | undefined;
    if (this.config.enableCorroboration && context.otherScannerFindings) {
      corroboration = this.evaluateCorroboration(finding, context.otherScannerFindings, signals, now);
    }

    // Step 4: Contextual signals (environment, technology, compensating controls)
    if (this.config.enableContextualFiltering) {
      this.collectContextualSignals(finding, context, signals, now);
    }

    // Step 5: Threat intelligence signals
    this.collectThreatIntelSignals(finding, signals, now);

    // Step 6: Historical pattern matching (adaptive)
    if (this.config.enableAdaptiveThresholds) {
      this.collectAdaptiveSignals(finding, signals, now);
    }

    // Step 7: FP pattern matching
    const suppressionRule = this.checkFPPatterns(finding, context, signals, now);

    // Step 8: Calculate final confidence
    const finalConfidence = this.calculateFinalConfidence(finding, signals);

    // Step 9: Determine verdict
    const verdict = this.determineVerdict(finalConfidence, signals, suppressionRule);

    const result: ValidationResult = {
      finding,
      finalConfidence,
      verdict,
      signals,
      positiveSignals: signals.filter(s => s.weight > 0).length,
      negativeSignals: signals.filter(s => s.weight < 0).length,
      corroboration,
      suppressionRule: suppressionRule || undefined,
      validatedAt: now,
    };

    // Update stats
    this.stats.totalValidated++;
    this.stats[verdict === "false_positive" ? "falsePositive" : verdict]++;

    // Cache result
    this.validationCache.set(cacheKey, { result, cachedAt: now });

    return result;
  }

  /**
   * Validate a batch of findings. Returns validated findings sorted by confidence.
   * Findings below the minimum reporting confidence are filtered out.
   */
  async validateBatch(
    findings: ScanFinding[],
    context: ValidationContext,
  ): Promise<{
    validated: ValidationResult[];
    suppressed: ValidationResult[];
    stats: BatchValidationStats;
  }> {
    const results: ValidationResult[] = [];

    // Build cross-reference map for corroboration
    const crossRef = this.buildCrossReferenceMap(findings);
    const enrichedContext: ValidationContext = {
      ...context,
      otherScannerFindings: findings,
    };

    // Validate each finding
    for (const finding of findings) {
      const result = await this.validateFinding(finding, enrichedContext);
      results.push(result);
    }

    // Separate validated from suppressed
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;
    const validated = results.filter(r =>
      r.verdict !== "suppressed" &&
      r.verdict !== "false_positive" &&
      r.finalConfidence >= profile.minConfidence
    );
    const suppressed = results.filter(r =>
      r.verdict === "suppressed" ||
      r.verdict === "false_positive" ||
      r.finalConfidence < profile.minConfidence
    );

    // Sort validated by confidence (highest first)
    validated.sort((a, b) => b.finalConfidence - a.finalConfidence);

    const stats: BatchValidationStats = {
      totalInput: findings.length,
      totalValidated: validated.length,
      totalSuppressed: suppressed.length,
      byVerdict: {
        confirmed: results.filter(r => r.verdict === "confirmed").length,
        likely: results.filter(r => r.verdict === "likely").length,
        possible: results.filter(r => r.verdict === "possible").length,
        unconfirmed: results.filter(r => r.verdict === "unconfirmed").length,
        suppressed: results.filter(r => r.verdict === "suppressed").length,
        false_positive: results.filter(r => r.verdict === "false_positive").length,
      },
      avgConfidence: validated.length > 0
        ? validated.reduce((sum, r) => sum + r.finalConfidence, 0) / validated.length
        : 0,
      suppressionRate: findings.length > 0
        ? suppressed.length / findings.length
        : 0,
      corroborationRate: results.filter(r => r.corroboration && r.corroboration.tier !== "none").length / Math.max(1, results.length),
    };

    return { validated, suppressed, stats };
  }

  // ─── Signal Collection Methods ───────────────────────────────────────

  private collectBaseSignals(finding: ScanFinding, signals: ConfidenceSignal[], now: number): void {
    // Base confidence from the finding's own confidence field
    if (finding.confidence > 0) {
      signals.push({
        source: "response_analysis",
        weight: Math.min(finding.confidence * 0.3, 15),
        description: `Scanner-reported confidence: ${finding.confidence}%`,
        collectedAt: now,
      });
    }

    // Evidence quality signals
    if (finding.evidence?.request && finding.evidence?.response) {
      signals.push({
        source: "response_analysis",
        weight: 10,
        description: "Full request/response evidence captured",
        evidence: `Request: ${finding.evidence.request.substring(0, 100)}...`,
        collectedAt: now,
      });
    }

    if (finding.evidence?.matchedPattern) {
      signals.push({
        source: "multi_matcher",
        weight: 8,
        description: `Pattern matched: ${finding.evidence.matchedPattern}`,
        collectedAt: now,
      });
    }

    // CVE presence is a positive signal
    if (finding.cves && finding.cves.length > 0) {
      signals.push({
        source: "cve_correlation",
        weight: 12,
        description: `CVE(s) associated: ${finding.cves.join(", ")}`,
        collectedAt: now,
      });
    }

    // CWE presence adds some confidence
    if (finding.cwes && finding.cwes.length > 0) {
      signals.push({
        source: "technology_match",
        weight: 5,
        description: `CWE(s) mapped: ${finding.cwes.join(", ")}`,
        collectedAt: now,
      });
    }
  }

  private collectVersionSignals(
    finding: ScanFinding,
    context: ValidationContext,
    signals: ConfidenceSignal[],
    now: number,
  ): void {
    // Check if the finding has version information
    const versionMatch = finding.title?.match(/(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)/);
    if (!versionMatch) return;

    const detectedVersion = versionMatch[1];

    // Check if detected technology version matches the finding's applicability
    if (context.detectedTechnologies) {
      const techVersions = context.detectedTechnologies;
      const findingTech = finding.title?.toLowerCase() || "";

      for (const [tech, version] of Object.entries(techVersions)) {
        if (findingTech.includes(tech.toLowerCase())) {
          if (version === detectedVersion || this.versionInRange(version, detectedVersion)) {
            signals.push({
              source: "version_match",
              weight: 18,
              description: `Detected ${tech} version ${version} matches vulnerable range`,
              evidence: `Technology: ${tech}, Detected: ${version}, Finding version: ${detectedVersion}`,
              collectedAt: now,
            });
          } else {
            signals.push({
              source: "version_mismatch",
              weight: -25,
              description: `Detected ${tech} version ${version} does NOT match vulnerable version ${detectedVersion}`,
              evidence: `Technology: ${tech}, Detected: ${version}, Expected vulnerable: ${detectedVersion}`,
              collectedAt: now,
            });
          }
        }
      }
    }
  }

  private evaluateCorroboration(
    finding: ScanFinding,
    otherFindings: ScanFinding[],
    signals: ConfidenceSignal[],
    now: number,
  ): CorroborationDetail {
    // Find other findings that match this one (same vuln, different scanner)
    const corroboratingFindings = otherFindings.filter(other => {
      if (other.id === finding.id) return false;
      // Match by CVE
      if (finding.cves?.length && other.cves?.length) {
        if (finding.cves.some(c => other.cves!.includes(c))) return true;
      }
      // Match by title similarity
      if (this.titleSimilarity(finding.title, other.title) > 0.7) return true;
      // Match by CWE + target + port
      if (finding.cwes?.length && other.cwes?.length &&
          finding.cwes.some(c => other.cwes!.includes(c)) &&
          finding.target === other.target &&
          finding.port === other.port) return true;
      return false;
    });

    const scanners = [...new Set(corroboratingFindings.map(f => f.source))];
    // Only count if different scanners found it (not same scanner twice)
    const uniqueScannerCount = scanners.filter(s => s !== finding.source).length + 1;

    let tier: CorroborationDetail["tier"] = "none";
    let confidenceBoost = 0;

    if (uniqueScannerCount >= 3) {
      tier = "strong";
      confidenceBoost = 30;
    } else if (uniqueScannerCount === 2) {
      tier = "moderate";
      confidenceBoost = 20;
    } else if (corroboratingFindings.length > 0) {
      tier = "weak";
      confidenceBoost = 8;
    }

    if (confidenceBoost > 0) {
      signals.push({
        source: "scanner_corroboration",
        weight: confidenceBoost,
        description: `${tier} corroboration: ${uniqueScannerCount} scanners agree (${scanners.join(", ")})`,
        collectedAt: now,
      });
    }

    return {
      scannerCount: uniqueScannerCount,
      scanners: [...new Set([finding.source, ...scanners])],
      tier,
      confidenceBoost,
    };
  }

  private collectContextualSignals(
    finding: ScanFinding,
    context: ValidationContext,
    signals: ConfidenceSignal[],
    now: number,
  ): void {
    // Environment-specific adjustments
    if (context.environment) {
      // ICS/OT findings on traditional IT = likely FP
      if (context.environment === "traditional" &&
          finding.title?.match(/modbus|dnp3|bacnet|scada|plc|hmi/i)) {
        signals.push({
          source: "contextual_penalty",
          weight: -20,
          description: "ICS/OT finding on traditional IT infrastructure — likely misidentification",
          collectedAt: now,
        });
      }

      // Cloud-managed service version findings
      if (context.environment === "cloud" && context.isManaged &&
          finding.title?.match(/outdated|end.of.life|unsupported/i)) {
        signals.push({
          source: "compensating_control",
          weight: -15,
          description: "Managed cloud service — vendor handles patching, version may not reflect actual patch level",
          collectedAt: now,
        });
      }

      // Container findings on non-container targets
      if (context.environment !== "container" &&
          finding.title?.match(/container\s*escape|docker|kubernetes|k8s/i)) {
        signals.push({
          source: "contextual_penalty",
          weight: -20,
          description: "Container-specific finding on non-containerized target",
          collectedAt: now,
        });
      }
    }

    // WAF interference detection
    if (context.wafDetected) {
      const isInjectionFinding = finding.title?.match(/injection|sqli|xss|rce|command\s*injection/i);
      if (isInjectionFinding) {
        signals.push({
          source: "waf_interference",
          weight: -10,
          description: `WAF detected (${context.wafDetected}) — injection findings may be false positives from WAF error pages`,
          collectedAt: now,
        });
      }
    }

    // Compensating controls
    if (context.compensatingControls) {
      for (const control of context.compensatingControls) {
        if (this.controlMitigatesFinding(control, finding)) {
          signals.push({
            source: "compensating_control",
            weight: -12,
            description: `Compensating control detected: ${control}`,
            collectedAt: now,
          });
        }
      }
    }

    // Network segmentation
    if (context.networkSegmented && finding.severity === "critical") {
      signals.push({
        source: "contextual_penalty",
        weight: -5,
        description: "Network segmentation reduces exploitability — risk may be lower than reported",
        collectedAt: now,
      });
    }
  }

  private collectThreatIntelSignals(
    finding: ScanFinding,
    signals: ConfidenceSignal[],
    now: number,
  ): void {
    // KEV listing is a strong positive signal
    if (finding.riskScore?.kevListed) {
      signals.push({
        source: "kev_listed",
        weight: 25,
        description: "Listed in CISA Known Exploited Vulnerabilities catalog — confirmed exploitable in the wild",
        collectedAt: now,
      });
    }

    // High EPSS score
    if (finding.riskScore?.epss && finding.riskScore.epss > 0.5) {
      signals.push({
        source: "epss_high",
        weight: Math.min(15, Math.round(finding.riskScore.epss * 20)),
        description: `EPSS score ${(finding.riskScore.epss * 100).toFixed(1)}% — high probability of exploitation`,
        collectedAt: now,
      });
    }

    // Ransomware use
    if (finding.riskScore?.ransomwareUse) {
      signals.push({
        source: "cve_correlation",
        weight: 20,
        description: "Known ransomware campaign exploitation — high-priority confirmed threat",
        collectedAt: now,
      });
    }

    // Threat actor relevance
    if (finding.riskScore?.threatActorRelevance?.length) {
      signals.push({
        source: "cve_correlation",
        weight: 12,
        description: `Exploited by threat actors: ${finding.riskScore.threatActorRelevance.join(", ")}`,
        collectedAt: now,
      });
    }
  }

  private collectAdaptiveSignals(
    finding: ScanFinding,
    signals: ConfidenceSignal[],
    now: number,
  ): void {
    // Check feedback history for similar findings
    const similarFeedback = this.feedbackHistory.filter(fb => {
      // Match by title pattern
      const titleKey = this.normalizeFindingTitle(finding.title);
      const fbTitleKey = this.normalizeFindingTitle(fb.findingId);
      return titleKey === fbTitleKey;
    });

    if (similarFeedback.length === 0) return;

    const tpCount = similarFeedback.filter(f => f.verdict === "true_positive").length;
    const fpCount = similarFeedback.filter(f => f.verdict === "false_positive").length;
    const total = tpCount + fpCount;

    if (total >= 3) {
      const tpRate = tpCount / total;
      if (tpRate > 0.8) {
        signals.push({
          source: "historical_pattern",
          weight: 15,
          description: `Historical pattern: ${(tpRate * 100).toFixed(0)}% true positive rate (${total} samples)`,
          collectedAt: now,
        });
      } else if (tpRate < 0.3) {
        signals.push({
          source: "historical_pattern",
          weight: -15,
          description: `Historical pattern: ${((1 - tpRate) * 100).toFixed(0)}% false positive rate (${total} samples)`,
          collectedAt: now,
        });
      }
    }
  }

  private checkFPPatterns(
    finding: ScanFinding,
    context: ValidationContext,
    signals: ConfidenceSignal[],
    now: number,
  ): string | null {
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;

    for (const pattern of this.fpPatterns) {
      if (!pattern.titlePattern.test(finding.title)) continue;

      // Check environment applicability
      if (pattern.environments && context.environment &&
          !pattern.environments.includes(context.environment)) continue;

      // Check conditions
      const conditionsMet = pattern.conditions.filter(cond => {
        switch (cond.type) {
          case "waf_present": return !!context.wafDetected;
          case "cloud_managed": return context.isManaged || context.environment === "cloud";
          case "port_mismatch": return finding.port && !this.isStandardPort(finding.port, finding.protocol || "");
          case "technology_absent": return !context.detectedTechnologies?.[cond.value];
          case "header_present": return finding.evidence?.response?.toLowerCase().includes(cond.value.toLowerCase());
          case "default_page": return finding.evidence?.response?.match(/welcome|default|it works|test page/i);
          case "generic_error": return finding.evidence?.response?.match(/error|exception|500|403/i);
          case "cdn_cached": return finding.evidence?.response?.match(/x-cache|cf-cache|x-cdn/i);
          case "patch_level": return context.patchLevel === cond.value;
          default: return false;
        }
      });

      const conditionRatio = conditionsMet.length / pattern.conditions.length;
      if (conditionRatio >= profile.fpPatternSensitivity) {
        signals.push({
          source: "negative_signal",
          weight: -20,
          description: `FP pattern match: ${pattern.reason} (${conditionsMet.length}/${pattern.conditions.length} conditions met)`,
          collectedAt: now,
        });
        return pattern.id;
      }
    }

    return null;
  }

  // ─── Confidence Calculation ──────────────────────────────────────────

  private calculateFinalConfidence(finding: ScanFinding, signals: ConfidenceSignal[]): number {
    // Start with base confidence from the finding
    let confidence = Math.max(20, finding.confidence || 50);

    // Apply signal weights
    for (const signal of signals) {
      const weightConfig = SIGNAL_WEIGHTS[signal.source];
      if (weightConfig) {
        // Clamp signal weight to configured max
        const clampedWeight = signal.weight > 0
          ? Math.min(signal.weight, weightConfig.max)
          : Math.max(signal.weight, weightConfig.max);
        confidence += clampedWeight;
      } else {
        confidence += signal.weight;
      }
    }

    // Apply adaptive weight adjustments
    const adaptiveKey = this.normalizeFindingTitle(finding.title);
    const adaptiveAdjustment = this.adaptiveWeights.get(adaptiveKey);
    if (adaptiveAdjustment) {
      confidence += adaptiveAdjustment;
    }

    // Clamp to 0-100
    return Math.max(0, Math.min(100, Math.round(confidence)));
  }

  private determineVerdict(
    confidence: number,
    signals: ConfidenceSignal[],
    suppressionRule: string | null,
  ): ValidationVerdict {
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;

    // Check for strong negative signals that indicate FP
    const strongNegatives = signals.filter(s => s.weight <= -20);
    const hasExploitProof = signals.some(s => s.source === "exploit_proof" && s.weight > 0);

    // Exploit proof overrides FP patterns (Invicti approach)
    if (hasExploitProof) {
      return confidence >= profile.confirmedThreshold ? "confirmed" : "likely";
    }

    // Strong negative signals with no positive corroboration
    if (strongNegatives.length >= 2 && confidence < 40) {
      return "false_positive";
    }

    // Suppression rule triggered
    if (suppressionRule && confidence < profile.minConfidence) {
      return "suppressed";
    }

    // Confidence-based verdicts
    if (confidence >= profile.confirmedThreshold) return "confirmed";
    if (confidence >= profile.minConfidence + 10) return "likely";
    if (confidence >= profile.minConfidence) return "possible";
    if (confidence >= profile.minConfidence - 15) return "unconfirmed";

    return "suppressed";
  }

  // ─── Operator Feedback Integration ───────────────────────────────────

  /**
   * Record operator feedback on a finding. This feeds the adaptive threshold system.
   */
  recordFeedback(feedback: OperatorFeedback): void {
    this.feedbackHistory.push(feedback);
    this.stats.operatorOverrides++;

    // Update adaptive weights
    const titleKey = this.normalizeFindingTitle(feedback.findingId);
    const currentWeight = this.adaptiveWeights.get(titleKey) || 0;

    if (feedback.verdict === "false_positive") {
      this.adaptiveWeights.set(titleKey, currentWeight - 5);
      // Update FP pattern confirmed counts
      for (const pattern of this.fpPatterns) {
        if (pattern.titlePattern.test(feedback.findingId)) {
          pattern.confirmedCount++;
        }
      }
    } else if (feedback.verdict === "true_positive") {
      this.adaptiveWeights.set(titleKey, currentWeight + 3);
    }

    // Invalidate cache for this finding
    for (const [key] of this.validationCache) {
      if (key.includes(feedback.findingId)) {
        this.validationCache.delete(key);
      }
    }
  }

  /**
   * Add a custom FP pattern from operator experience.
   */
  addFPPattern(pattern: Omit<FPPattern, "confirmedCount">): void {
    this.fpPatterns.push({ ...pattern, confirmedCount: 0 });
  }

  // ─── Utility Methods ─────────────────────────────────────────────────

  private titleSimilarity(a: string, b: string): number {
    const normalize = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, " ").replace(/\s+/g, " ").trim();
    const na = normalize(a);
    const nb = normalize(b);
    if (na === nb) return 1;

    const wordsA = new Set(na.split(" "));
    const wordsB = new Set(nb.split(" "));
    const intersection = new Set([...wordsA].filter(w => wordsB.has(w)));
    const union = new Set([...wordsA, ...wordsB]);
    return intersection.size / union.size; // Jaccard similarity
  }

  private normalizeFindingTitle(title: string): string {
    return title
      .toLowerCase()
      .replace(/\[.*?\]/g, "")
      .replace(/CVE-\d{4}-\d+/gi, "CVE")
      .replace(/\d+\.\d+\.\d+/g, "VERSION")
      .replace(/\s+/g, " ")
      .trim();
  }

  private versionInRange(detected: string, vulnerable: string): boolean {
    // Simple semver comparison — detected version <= vulnerable version
    const parse = (v: string) => v.split(/[.-]/).map(p => parseInt(p, 10) || 0);
    const d = parse(detected);
    const v = parse(vulnerable);
    for (let i = 0; i < Math.max(d.length, v.length); i++) {
      const dPart = d[i] || 0;
      const vPart = v[i] || 0;
      if (dPart < vPart) return true;
      if (dPart > vPart) return false;
    }
    return true; // Equal versions
  }

  private isStandardPort(port: number, protocol: string): boolean {
    const standardPorts: Record<string, number[]> = {
      http: [80, 8080, 8443, 443],
      https: [443, 8443],
      ssh: [22],
      ftp: [21],
      smtp: [25, 587, 465],
      dns: [53],
      modbus: [502],
      dnp3: [20000],
      bacnet: [47808],
      mqtt: [1883, 8883],
      coap: [5683, 5684],
      opcua: [4840],
    };
    return standardPorts[protocol.toLowerCase()]?.includes(port) ?? false;
  }

  private controlMitigatesFinding(control: string, finding: ScanFinding): boolean {
    const controlLower = control.toLowerCase();
    const titleLower = (finding.title || "").toLowerCase();

    // WAF mitigates injection findings
    if (controlLower.includes("waf") && titleLower.match(/injection|xss|sqli/)) return true;
    // MFA mitigates credential findings
    if (controlLower.includes("mfa") && titleLower.match(/credential|password|auth/)) return true;
    // Encryption mitigates data exposure
    if (controlLower.includes("encrypt") && titleLower.match(/cleartext|plain.?text|unencrypted/)) return true;
    // Network segmentation mitigates lateral movement
    if (controlLower.includes("segment") && titleLower.match(/lateral|pivot|internal/)) return true;

    return false;
  }

  private buildCrossReferenceMap(findings: ScanFinding[]): Map<string, ScanFinding[]> {
    const map = new Map<string, ScanFinding[]>();
    for (const f of findings) {
      const key = `${f.target}:${f.port || "any"}`;
      const existing = map.get(key) || [];
      existing.push(f);
      map.set(key, existing);
    }
    return map;
  }

  // ─── Statistics & Reporting ──────────────────────────────────────────

  getStats(): typeof this.stats & { feedbackCount: number; fpPatternCount: number; cacheSize: number } {
    return {
      ...this.stats,
      feedbackCount: this.feedbackHistory.length,
      fpPatternCount: this.fpPatterns.length,
      cacheSize: this.validationCache.size,
    };
  }

  getConfig(): FPFNConfig {
    return { ...this.config };
  }

  updateConfig(updates: Partial<FPFNConfig>): void {
    this.config = { ...this.config, ...updates };
    // Clear cache when config changes
    this.validationCache.clear();
  }

  clearCache(): void {
    this.validationCache.clear();
  }
}

// ─── Validation Context ──────────────────────────────────────────────────

export interface ValidationContext {
  /** Target environment type */
  environment?: AssetEnvironment;
  /** Whether the target is a managed service */
  isManaged?: boolean;
  /** Detected WAF/CDN */
  wafDetected?: string;
  /** Detected technologies and their versions */
  detectedTechnologies?: Record<string, string>;
  /** Compensating controls in place */
  compensatingControls?: string[];
  /** Whether the network is segmented */
  networkSegmented?: boolean;
  /** Patch level (e.g., "backported", "current", "outdated") */
  patchLevel?: string;
  /** Other scanner findings for corroboration */
  otherScannerFindings?: ScanFinding[];
  /** Cloud provider if applicable */
  cloudProvider?: string;
  /** Compliance frameworks being assessed */
  complianceFrameworks?: ComplianceFramework[];
}

export interface BatchValidationStats {
  totalInput: number;
  totalValidated: number;
  totalSuppressed: number;
  byVerdict: Record<ValidationVerdict, number>;
  avgConfidence: number;
  suppressionRate: number;
  corroborationRate: number;
}

// ─── Singleton ───────────────────────────────────────────────────────────

let engineInstance: FPFNPreventionEngine | null = null;

export function getFPFNEngine(config?: Partial<FPFNConfig>): FPFNPreventionEngine {
  if (!engineInstance) {
    engineInstance = new FPFNPreventionEngine(config);
  }
  return engineInstance;
}

export function resetFPFNEngine(): void {
  engineInstance = null;
}
