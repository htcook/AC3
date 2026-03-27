/**
 * ScanForge Finding Deduplication, Normalization & FN Coverage Gap Detection
 *
 * Three integrated subsystems:
 *
 * 1. **Deduplication Engine** — Fingerprint-based matching that identifies
 *    duplicate findings across multiple scanners, templates, and scan runs.
 *    Uses a multi-factor fingerprint (target + port + CVE/CWE + title hash)
 *    to merge duplicates while preserving the highest-confidence evidence.
 *
 * 2. **Normalization Layer** — Unifies finding severity, CVE/CWE mappings,
 *    MITRE ATT&CK technique IDs, and compliance references into a canonical
 *    form. Resolves severity disagreements between scanners using a
 *    confidence-weighted voting system.
 *
 * 3. **FN Coverage Gap Detector** — Compares the set of templates/scanners
 *    executed against the expected coverage matrix for the target's asset
 *    environment, protocol profile, and compliance requirements. Identifies
 *    missing checks and recommends additional scans to close gaps.
 *
 * @author Harrison Cook — AceofCloud
 */

import type {
  ScanFinding,
  FindingSeverity,
  ScanTemplate,
  ScannerResult,
  AssetEnvironment,
  AssetClassification,
  ComplianceFramework,
  ComplianceMapping,
  ScanConfig,
  ScanTarget,
} from "../types";

// ─── Deduplication Types ──────────────────────────────────────────────────

export interface FindingFingerprint {
  /** Computed fingerprint hash */
  hash: string;
  /** Components used to generate the fingerprint */
  components: {
    target: string;
    port?: number;
    protocol?: string;
    cves: string[];
    cwes: string[];
    titleNormalized: string;
    templateId?: string;
  };
}

export interface DedupResult {
  /** Deduplicated findings (merged) */
  findings: ScanFinding[];
  /** Number of duplicates removed */
  duplicatesRemoved: number;
  /** Merge log — which findings were merged into which */
  mergeLog: MergeEntry[];
  /** Total findings before dedup */
  totalBefore: number;
  /** Total findings after dedup */
  totalAfter: number;
}

export interface MergeEntry {
  /** The surviving (canonical) finding ID */
  canonicalId: string;
  /** IDs of findings merged into the canonical */
  mergedIds: string[];
  /** Reason for merge */
  reason: "exact_fingerprint" | "cve_overlap" | "cwe_overlap" | "title_similarity" | "fuzzy_title" | "template_overlap";
  /** Confidence delta from merge (positive = confidence increased) */
  confidenceDelta: number;
}

// ─── Normalization Types ──────────────────────────────────────────────────

export interface NormalizationResult {
  /** Normalized findings */
  findings: ScanFinding[];
  /** Number of severity adjustments made */
  severityAdjustments: number;
  /** Number of CVE/CWE enrichments added */
  referenceEnrichments: number;
  /** Number of compliance mappings added */
  complianceMappingsAdded: number;
  /** Normalization log */
  log: NormalizationLogEntry[];
}

export interface NormalizationLogEntry {
  findingId: string;
  field: string;
  oldValue: string;
  newValue: string;
  reason: string;
}

// ─── Coverage Gap Types ───────────────────────────────────────────────────

export interface CoverageGap {
  /** Gap identifier */
  id: string;
  /** Category of the gap */
  category: CoverageCategory;
  /** Human-readable description */
  description: string;
  /** Severity of the gap (how critical is the missing coverage) */
  severity: "critical" | "high" | "medium" | "low";
  /** What should be run to close the gap */
  recommendation: string;
  /** Template IDs that would close this gap */
  recommendedTemplateIds: string[];
  /** Scanner protocols that would close this gap */
  recommendedProtocols: string[];
  /** Compliance controls that are uncovered */
  uncoveredControls: string[];
  /** Estimated FN risk (0-100) — likelihood of missing a real vuln */
  fnRiskScore: number;
}

export type CoverageCategory =
  | "protocol_gap"        // Target protocol not scanned
  | "template_gap"        // Known template not executed
  | "compliance_gap"      // Required compliance control not tested
  | "environment_gap"     // Environment-specific checks missing
  | "severity_gap"        // Missing checks for a severity tier
  | "attack_surface_gap"  // Exposed service not scanned
  | "dns_gap"             // DNS security checks missing (SP 800-81r3)
  | "auth_gap"            // Authentication testing missing
  | "crypto_gap";         // Cryptographic checks missing

export interface CoverageReport {
  /** Target analyzed */
  target: string;
  /** Overall coverage percentage (0-100) */
  coveragePercent: number;
  /** Gaps identified */
  gaps: CoverageGap[];
  /** Templates executed */
  templatesExecuted: string[];
  /** Templates available but not executed */
  templatesSkipped: string[];
  /** Protocols scanned */
  protocolsScanned: string[];
  /** Protocols available but not scanned */
  protocolsSkipped: string[];
  /** Compliance frameworks covered */
  complianceCovered: ComplianceFramework[];
  /** Compliance controls tested vs total */
  complianceStats: Record<string, { tested: number; total: number; percent: number }>;
  /** FN risk assessment */
  fnRiskAssessment: {
    overallRisk: "low" | "medium" | "high" | "critical";
    riskScore: number;
    topGaps: CoverageGap[];
  };
}

// ─── Severity Mapping ─────────────────────────────────────────────────────

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

// ─── Deduplication Engine ─────────────────────────────────────────────────

export class DeduplicationEngine {
  /**
   * Compute a deterministic fingerprint for a finding.
   * Two findings with the same fingerprint are considered duplicates.
   */
  computeFingerprint(finding: ScanFinding): FindingFingerprint {
    const titleNormalized = this.normalizeTitle(finding.title);
    const cves = [...(finding.cves || [])].sort();
    const cwes = [...(finding.cwes || [])].sort();

    // Build composite key
    const parts = [
      finding.target.toLowerCase(),
      finding.port?.toString() || "*",
      finding.protocol || "*",
      cves.join(",") || titleNormalized,
      cwes.join(","),
    ];

    const hash = this.hashString(parts.join("|"));

    return {
      hash,
      components: {
        target: finding.target,
        port: finding.port,
        protocol: finding.protocol,
        cves,
        cwes,
        titleNormalized,
        templateId: finding.source,
      },
    };
  }

  /**
   * Deduplicate a set of findings. Merges duplicates by keeping the
   * highest-confidence version and combining evidence from all sources.
   */
  deduplicate(findings: ScanFinding[]): DedupResult {
    const mergeLog: MergeEntry[] = [];
    const fingerprints = new Map<string, ScanFinding[]>();

    // Phase 1: Group by exact fingerprint
    for (const finding of findings) {
      const fp = this.computeFingerprint(finding);
      const group = fingerprints.get(fp.hash) || [];
      group.push(finding);
      fingerprints.set(fp.hash, group);
    }

    // Phase 2: Within non-exact groups, check CVE overlap
    const mergedFindings: ScanFinding[] = [];

    for (const [hash, group] of fingerprints) {
      if (group.length === 1) {
        mergedFindings.push(group[0]);
        continue;
      }

      // Merge the group
      const canonical = this.mergeGroup(group);
      mergedFindings.push(canonical.finding);
      mergeLog.push(canonical.entry);
    }

    // Phase 3: Cross-group CVE overlap detection
    const cveDeduped = this.deduplicateByCVEOverlap(mergedFindings, mergeLog);

    // Phase 4: Cross-group CWE overlap detection (catches ZAP vs Nuclei duplicates)
    const cweDeduped = this.deduplicateByCWEOverlap(cveDeduped, mergeLog);

    // Phase 5: Fuzzy title matching across sources (catches renamed/rephrased findings)
    const fuzzyDeduped = this.deduplicateByFuzzyTitle(cweDeduped, mergeLog);

    return {
      findings: fuzzyDeduped,
      duplicatesRemoved: findings.length - fuzzyDeduped.length,
      mergeLog,
      totalBefore: findings.length,
      totalAfter: fuzzyDeduped.length,
    };
  }

  /**
   * Merge a group of duplicate findings into a single canonical finding.
   * Strategy: Keep highest confidence, combine evidence, union references.
   */
  private mergeGroup(group: ScanFinding[]): { finding: ScanFinding; entry: MergeEntry } {
    // Sort by confidence descending — highest confidence becomes canonical
    const sorted = [...group].sort((a, b) => b.confidence - a.confidence);
    const canonical = { ...sorted[0] };
    const mergedIds = sorted.slice(1).map((f) => f.id);

    // Combine CVEs from all findings
    const allCves = new Set<string>();
    const allCwes = new Set<string>();
    const allTechniques = new Set<string>();
    const allReferences = new Set<string>();

    for (const finding of sorted) {
      finding.cves?.forEach((c) => allCves.add(c));
      finding.cwes?.forEach((c) => allCwes.add(c));
      finding.techniqueIds?.forEach((t) => allTechniques.add(t));
      finding.references?.forEach((r) => allReferences.add(r));
    }

    canonical.cves = [...allCves];
    canonical.cwes = [...allCwes];
    canonical.techniqueIds = [...allTechniques];
    canonical.references = [...allReferences];

    // Boost confidence from corroboration (multiple scanners found the same thing)
    const originalConfidence = canonical.confidence;
    const corroborationBoost = Math.min(15, (group.length - 1) * 5);
    canonical.confidence = Math.min(100, canonical.confidence + corroborationBoost);

    // Combine compliance mappings
    const complianceMap = new Map<string, ComplianceMapping>();
    for (const finding of sorted) {
      finding.compliance?.forEach((c) => {
        const key = `${c.framework}:${c.controlId}`;
        if (!complianceMap.has(key) || c.confidence > (complianceMap.get(key)?.confidence || 0)) {
          complianceMap.set(key, c);
        }
      });
    }
    canonical.compliance = [...complianceMap.values()];

    // Use the best evidence (longest response, most detail)
    const bestEvidence = sorted.reduce((best, f) => {
      const bestLen = (best.evidence.response?.length || 0) + (best.evidence.request?.length || 0);
      const fLen = (f.evidence.response?.length || 0) + (f.evidence.request?.length || 0);
      return fLen > bestLen ? f : best;
    }, sorted[0]);
    canonical.evidence = bestEvidence.evidence;

    // Use highest risk score
    const bestRisk = sorted.reduce((best, f) => {
      if (!f.riskScore) return best;
      if (!best || (f.riskScore.composite > (best.composite || 0))) return f.riskScore;
      return best;
    }, canonical.riskScore);
    if (bestRisk) canonical.riskScore = bestRisk;

    // Use the most severe severity
    const highestSeverity = sorted.reduce((best, f) => {
      return SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best;
    }, sorted[0].severity);
    canonical.severity = highestSeverity;

    return {
      finding: canonical,
      entry: {
        canonicalId: canonical.id,
        mergedIds,
        reason: "exact_fingerprint",
        confidenceDelta: canonical.confidence - originalConfidence,
      },
    };
  }

  /**
   * Second-pass deduplication: find findings across different fingerprint
   * groups that share CVEs (different scanners may report the same CVE
   * with slightly different titles/ports).
   */
  private deduplicateByCVEOverlap(findings: ScanFinding[], mergeLog: MergeEntry[]): ScanFinding[] {
    const cveIndex = new Map<string, number[]>();

    // Build CVE → finding index
    for (let i = 0; i < findings.length; i++) {
      for (const cve of findings[i].cves || []) {
        const indices = cveIndex.get(cve) || [];
        indices.push(i);
        cveIndex.set(cve, indices);
      }
    }

    // Find groups that share CVEs on the same target
    const toMerge = new Map<number, Set<number>>();

    for (const [_cve, indices] of cveIndex) {
      if (indices.length < 2) continue;

      // Only merge if same target
      const byTarget = new Map<string, number[]>();
      for (const idx of indices) {
        const target = findings[idx].target;
        const group = byTarget.get(target) || [];
        group.push(idx);
        byTarget.set(target, group);
      }

      for (const [_target, targetIndices] of byTarget) {
        if (targetIndices.length < 2) continue;
        const canonical = targetIndices[0];
        for (let i = 1; i < targetIndices.length; i++) {
          const mergeSet = toMerge.get(canonical) || new Set();
          mergeSet.add(targetIndices[i]);
          toMerge.set(canonical, mergeSet);
        }
      }
    }

    if (toMerge.size === 0) return findings;

    // Perform merges
    const removed = new Set<number>();
    const result = [...findings];

    for (const [canonicalIdx, mergeIndices] of toMerge) {
      if (removed.has(canonicalIdx)) continue;

      for (const mergeIdx of mergeIndices) {
        if (removed.has(mergeIdx)) continue;

        const merged = this.mergeGroup([result[canonicalIdx], result[mergeIdx]]);
        result[canonicalIdx] = merged.finding;
        merged.entry.reason = "cve_overlap";
        mergeLog.push(merged.entry);
        removed.add(mergeIdx);
      }
    }

    return result.filter((_, i) => !removed.has(i));
  }

  /**
   * Phase 4: CWE-based cross-source deduplication.
   * ZAP findings often have CWE IDs but no CVEs, while Nuclei findings have CVEs but not CWEs.
   * This phase catches duplicates where different scanners report the same weakness (CWE)
   * on the same target but with different titles.
   */
  private deduplicateByCWEOverlap(findings: ScanFinding[], mergeLog: MergeEntry[]): ScanFinding[] {
    const cweIndex = new Map<string, number[]>();

    // Build CWE → finding index (only for findings with CWEs)
    for (let i = 0; i < findings.length; i++) {
      for (const cwe of findings[i].cwes || []) {
        const indices = cweIndex.get(cwe) || [];
        indices.push(i);
        cweIndex.set(cwe, indices);
      }
    }

    // Find groups that share CWEs on the same target
    const toMerge = new Map<number, Set<number>>();

    for (const [_cwe, indices] of cweIndex) {
      if (indices.length < 2) continue;

      // Only merge if same target AND from different sources
      const byTarget = new Map<string, number[]>();
      for (const idx of indices) {
        const target = findings[idx].target;
        const group = byTarget.get(target) || [];
        group.push(idx);
        byTarget.set(target, group);
      }

      for (const [_target, targetIndices] of byTarget) {
        if (targetIndices.length < 2) continue;

        // Only merge if findings come from different sources
        const sources = new Set(targetIndices.map(idx => findings[idx].source));
        if (sources.size < 2) continue;

        const canonical = targetIndices[0];
        for (let i = 1; i < targetIndices.length; i++) {
          // Don't merge if already marked for merge
          const mergeSet = toMerge.get(canonical) || new Set();
          mergeSet.add(targetIndices[i]);
          toMerge.set(canonical, mergeSet);
        }
      }
    }

    if (toMerge.size === 0) return findings;

    // Perform merges
    const removed = new Set<number>();
    const result = [...findings];

    for (const [canonicalIdx, mergeIndices] of toMerge) {
      if (removed.has(canonicalIdx)) continue;

      for (const mergeIdx of mergeIndices) {
        if (removed.has(mergeIdx)) continue;

        const merged = this.mergeGroup([result[canonicalIdx], result[mergeIdx]]);
        result[canonicalIdx] = merged.finding;
        merged.entry.reason = "cwe_overlap";
        mergeLog.push(merged.entry);
        removed.add(mergeIdx);
      }
    }

    return result.filter((_, i) => !removed.has(i));
  }

  /**
   * Phase 5: Fuzzy title matching across different sources.
   * Catches cases where ZAP reports "Content Security Policy (CSP) Header Not Set"
   * and Nuclei reports "Missing CSP Header" — same vulnerability, different wording.
   * Uses source-prefix stripping + keyword extraction + Jaccard similarity.
   */
  private deduplicateByFuzzyTitle(findings: ScanFinding[], mergeLog: MergeEntry[]): ScanFinding[] {
    const SIMILARITY_THRESHOLD = 0.55; // Jaccard similarity threshold

    // Strip scanner prefixes and normalize titles for comparison
    const normalizedTitles = findings.map(f => this.stripSourcePrefix(this.normalizeTitle(f.title)));
    const titleKeywords = normalizedTitles.map(t => new Set(t.split(/\s+/).filter(w => w.length > 2)));

    const toMerge = new Map<number, Set<number>>();

    for (let i = 0; i < findings.length; i++) {
      for (let j = i + 1; j < findings.length; j++) {
        // Only fuzzy-match across different sources on the same target
        if (findings[i].target !== findings[j].target) continue;
        if (findings[i].source === findings[j].source) continue;

        // Compute Jaccard similarity of keyword sets
        const setA = titleKeywords[i];
        const setB = titleKeywords[j];
        if (setA.size === 0 || setB.size === 0) continue;

        let intersection = 0;
        for (const word of setA) {
          if (setB.has(word)) intersection++;
        }
        const union = setA.size + setB.size - intersection;
        const similarity = intersection / union;

        if (similarity >= SIMILARITY_THRESHOLD) {
          const mergeSet = toMerge.get(i) || new Set();
          mergeSet.add(j);
          toMerge.set(i, mergeSet);
        }
      }
    }

    if (toMerge.size === 0) return findings;

    // Perform merges
    const removed = new Set<number>();
    const result = [...findings];

    for (const [canonicalIdx, mergeIndices] of toMerge) {
      if (removed.has(canonicalIdx)) continue;

      for (const mergeIdx of mergeIndices) {
        if (removed.has(mergeIdx)) continue;

        const merged = this.mergeGroup([result[canonicalIdx], result[mergeIdx]]);
        result[canonicalIdx] = merged.finding;
        merged.entry.reason = "fuzzy_title";
        mergeLog.push(merged.entry);
        removed.add(mergeIdx);
      }
    }

    return result.filter((_, i) => !removed.has(i));
  }

  /**
   * Strip scanner source prefixes from titles for cross-source comparison.
   * Handles [ZAP], [zap], [nuclei], [Nuclei], [nikto], [nmap], [scanforge], etc.
   */
  private stripSourcePrefix(title: string): string {
    return title.replace(/^\[?\w+\]?\s*/i, "").trim();
  }

  /**
   * Normalize a finding title for comparison.
   * Strips version numbers, normalizes whitespace, lowercases.
   */
  private normalizeTitle(title: string): string {
    return title
      .toLowerCase()
      .replace(/\s+/g, " ")
      .replace(/v?\d+\.\d+(\.\d+)*/g, "VERSION")
      .replace(/[^\w\s]/g, "")
      .trim();
  }

  /**
   * Simple string hash (djb2 algorithm).
   */
  private hashString(str: string): string {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xffffffff;
    }
    return hash.toString(16).padStart(8, "0");
  }
}

// ─── Normalization Layer ──────────────────────────────────────────────────

export class NormalizationEngine {
  /**
   * Normalize a set of findings to a canonical form.
   * Unifies severity, CVE/CWE mappings, and compliance references.
   */
  normalize(findings: ScanFinding[]): NormalizationResult {
    const log: NormalizationLogEntry[] = [];
    let severityAdjustments = 0;
    let referenceEnrichments = 0;
    let complianceMappingsAdded = 0;

    const normalized = findings.map((finding) => {
      const f = { ...finding };

      // 1. Normalize severity using CVE-based lookup
      const adjustedSeverity = this.normalizeSeverity(f);
      if (adjustedSeverity !== f.severity) {
        log.push({
          findingId: f.id,
          field: "severity",
          oldValue: f.severity,
          newValue: adjustedSeverity,
          reason: "CVE-based severity normalization",
        });
        f.severity = adjustedSeverity;
        severityAdjustments++;
      }

      // 2. Normalize and deduplicate CVE/CWE references
      const enriched = this.enrichReferences(f);
      if (enriched.added > 0) {
        referenceEnrichments += enriched.added;
        f.cves = enriched.cves;
        f.cwes = enriched.cwes;
      }

      // 3. Add missing compliance mappings based on CWE → control mapping
      const complianceAdded = this.enrichComplianceMappings(f);
      if (complianceAdded > 0) {
        complianceMappingsAdded += complianceAdded;
      }

      // 4. Normalize target format
      f.target = this.normalizeTarget(f.target);

      // 5. Ensure consistent timestamp format
      if (!f.foundAt) f.foundAt = Date.now();

      return f;
    });

    return {
      findings: normalized,
      severityAdjustments,
      referenceEnrichments,
      complianceMappingsAdded,
      log,
    };
  }

  /**
   * Normalize severity based on CVE data and confidence-weighted voting.
   * If multiple scanners disagree on severity, use the confidence-weighted
   * consensus.
   */
  private normalizeSeverity(finding: ScanFinding): FindingSeverity {
    // If the finding has a CVSS score in riskScore, use that as ground truth
    if (finding.riskScore?.cvss !== undefined) {
      const cvss = finding.riskScore.cvss;
      if (cvss >= 9.0) return "critical";
      if (cvss >= 7.0) return "high";
      if (cvss >= 4.0) return "medium";
      if (cvss >= 0.1) return "low";
      return "info";
    }

    // If KEV-listed, minimum severity is high
    if (finding.riskScore?.kevListed && SEVERITY_RANK[finding.severity] < SEVERITY_RANK["high"]) {
      return "high";
    }

    // If ransomware-associated, minimum severity is high
    if (finding.riskScore?.ransomwareUse && SEVERITY_RANK[finding.severity] < SEVERITY_RANK["high"]) {
      return "high";
    }

    return finding.severity;
  }

  /**
   * Enrich CVE/CWE references by cross-referencing known mappings.
   */
  private enrichReferences(finding: ScanFinding): { cves: string[]; cwes: string[]; added: number } {
    const cves = new Set(finding.cves || []);
    const cwes = new Set(finding.cwes || []);
    let added = 0;

    // CWE enrichment from common vulnerability patterns in titles
    const titleLower = finding.title.toLowerCase();
    const descLower = finding.description.toLowerCase();
    const combined = `${titleLower} ${descLower}`;

    const CWE_PATTERNS: [RegExp, string][] = [
      [/sql\s*inject/i, "CWE-89"],
      [/cross.?site\s*script|xss/i, "CWE-79"],
      [/command\s*inject|os\s*command/i, "CWE-78"],
      [/path\s*travers|directory\s*travers|\.\.\//i, "CWE-22"],
      [/open\s*redirect/i, "CWE-601"],
      [/ssrf|server.?side\s*request/i, "CWE-918"],
      [/xxe|xml\s*external/i, "CWE-611"],
      [/csrf|cross.?site\s*request\s*forg/i, "CWE-352"],
      [/insecure\s*deseri/i, "CWE-502"],
      [/broken\s*auth|authentication\s*bypass/i, "CWE-287"],
      [/sensitive\s*data\s*expos|information\s*disclos/i, "CWE-200"],
      [/missing\s*hsts|strict.?transport/i, "CWE-16"],
      [/weak\s*cipher|ssl|tls.*1\.[01]/i, "CWE-326"],
      [/zone\s*transfer|axfr/i, "CWE-200"],
      [/dnssec/i, "CWE-295"],
      [/subdomain\s*takeover|dangling\s*cname/i, "CWE-672"],
      [/dns\s*tunnel/i, "CWE-200"],
      [/default\s*cred|default\s*password/i, "CWE-798"],
      [/buffer\s*overflow/i, "CWE-120"],
      [/race\s*condition/i, "CWE-362"],
      [/privilege\s*escalat/i, "CWE-269"],
      [/hardcoded\s*(password|secret|key|credential)/i, "CWE-798"],
      [/unencrypted|cleartext|plaintext/i, "CWE-319"],
    ];

    for (const [pattern, cwe] of CWE_PATTERNS) {
      if (pattern.test(combined) && !cwes.has(cwe)) {
        cwes.add(cwe);
        added++;
      }
    }

    return { cves: [...cves], cwes: [...cwes], added };
  }

  /**
   * Enrich compliance mappings based on CWE → NIST 800-53 control mapping.
   */
  private enrichComplianceMappings(finding: ScanFinding): number {
    if (!finding.cwes || finding.cwes.length === 0) return 0;

    const existing = new Set(
      (finding.compliance || []).map((c) => `${c.framework}:${c.controlId}`)
    );

    const CWE_TO_NIST: Record<string, { controlId: string; controlTitle: string }[]> = {
      "CWE-89": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-79": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-78": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-22": [{ controlId: "AC-6", controlTitle: "Least Privilege" }],
      "CWE-200": [{ controlId: "SC-28", controlTitle: "Protection of Information at Rest" }],
      "CWE-287": [{ controlId: "IA-2", controlTitle: "Identification and Authentication" }],
      "CWE-295": [{ controlId: "SC-20", controlTitle: "Secure Name/Address Resolution Service" }],
      "CWE-319": [{ controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" }],
      "CWE-326": [{ controlId: "SC-13", controlTitle: "Cryptographic Protection" }],
      "CWE-352": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-502": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-601": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-611": [{ controlId: "SI-10", controlTitle: "Information Input Validation" }],
      "CWE-672": [{ controlId: "SC-20", controlTitle: "Secure Name/Address Resolution Service" }],
      "CWE-798": [{ controlId: "IA-5", controlTitle: "Authenticator Management" }],
      "CWE-918": [{ controlId: "SC-7", controlTitle: "Boundary Protection" }],
      "CWE-16": [{ controlId: "CM-6", controlTitle: "Configuration Settings" }],
    };

    let added = 0;
    const compliance = [...(finding.compliance || [])];

    for (const cwe of finding.cwes) {
      const controls = CWE_TO_NIST[cwe];
      if (!controls) continue;

      for (const control of controls) {
        const key = `nist_800_53:${control.controlId}`;
        if (existing.has(key)) continue;

        compliance.push({
          framework: "nist_800_53" as ComplianceFramework,
          controlId: control.controlId,
          controlTitle: control.controlTitle,
          status: "non_compliant",
          confidence: 70,
        });
        existing.add(key);
        added++;
      }
    }

    finding.compliance = compliance;
    return added;
  }

  /**
   * Normalize target format (strip trailing slashes, lowercase hostname).
   */
  private normalizeTarget(target: string): string {
    try {
      const url = new URL(target.startsWith("http") ? target : `https://${target}`);
      return `${url.protocol}//${url.hostname.toLowerCase()}${url.port ? `:${url.port}` : ""}${url.pathname.replace(/\/+$/, "") || "/"}`;
    } catch {
      return target.toLowerCase().replace(/\/+$/, "");
    }
  }
}

// ─── FN Coverage Gap Detector ─────────────────────────────────────────────

/**
 * Expected coverage matrix — defines what should be tested for each
 * asset environment and protocol profile.
 */
interface CoverageExpectation {
  /** Required protocols to scan for this environment */
  requiredProtocols: string[];
  /** Required template tag categories */
  requiredTemplateTags: string[];
  /** Required compliance controls */
  requiredControls: { framework: string; controlIds: string[] }[];
  /** Minimum number of templates per protocol */
  minTemplatesPerProtocol: number;
}

const ENVIRONMENT_COVERAGE: Record<string, CoverageExpectation> = {
  traditional: {
    requiredProtocols: ["http", "https", "ssh", "dns", "smtp", "ftp"],
    requiredTemplateTags: [
      "owasp-top10", "exposure", "credentials", "misconfig", "cve",
      "dns", "dnssec", "zone-transfer",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: [
          "AC-6", "AU-2", "CM-6", "IA-2", "IA-5", "SC-7", "SC-8",
          "SC-13", "SC-20", "SC-21", "SC-22", "SI-4", "SI-10",
        ],
      },
    ],
    minTemplatesPerProtocol: 3,
  },
  cloud: {
    requiredProtocols: ["http", "https", "dns", "cloud_metadata", "cloud_storage"],
    requiredTemplateTags: [
      "owasp-top10", "cloud", "imds", "s3", "storage", "iam",
      "dns", "dnssec",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: [
          "AC-2", "AC-6", "CM-6", "IA-2", "SC-7", "SC-8",
          "SC-13", "SC-20", "SC-21", "SC-22",
        ],
      },
    ],
    minTemplatesPerProtocol: 2,
  },
  iot: {
    requiredProtocols: ["http", "mqtt", "coap", "upnp", "dns"],
    requiredTemplateTags: [
      "iot", "mqtt", "coap", "upnp", "default-credentials", "firmware",
      "dns",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: ["AC-6", "IA-2", "IA-5", "SC-8", "SC-20", "SI-4"],
      },
    ],
    minTemplatesPerProtocol: 2,
  },
  ics: {
    requiredProtocols: ["modbus", "dnp3", "bacnet", "ethernet_ip", "opc_ua", "dns"],
    requiredTemplateTags: [
      "ics", "scada", "modbus", "dnp3", "bacnet", "safety",
      "dns",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: ["AC-6", "IA-2", "SC-7", "SC-8", "SC-20", "SI-4"],
      },
    ],
    minTemplatesPerProtocol: 1,
  },
  container: {
    requiredProtocols: ["http", "https", "docker_api", "k8s_api", "dns"],
    requiredTemplateTags: [
      "container", "docker", "kubernetes", "registry", "rbac",
      "dns",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: ["AC-2", "AC-6", "CM-6", "IA-2", "SC-7", "SC-8", "SC-20"],
      },
    ],
    minTemplatesPerProtocol: 2,
  },
  hybrid: {
    requiredProtocols: ["http", "https", "dns", "ssh", "cloud_metadata"],
    requiredTemplateTags: [
      "owasp-top10", "cloud", "exposure", "dns", "dnssec",
    ],
    requiredControls: [
      {
        framework: "nist_800_53",
        controlIds: [
          "AC-6", "CM-6", "IA-2", "SC-7", "SC-8",
          "SC-13", "SC-20", "SC-21", "SC-22",
        ],
      },
    ],
    minTemplatesPerProtocol: 2,
  },
};

/** DNS-specific coverage requirements per NIST SP 800-81r3 */
const DNS_COVERAGE_REQUIREMENTS = {
  templateTags: [
    "zone-transfer", "dangling-record", "dnssec", "encrypted-dns",
    "dns-tunneling", "lame-delegation", "typosquat", "dns-info-leakage",
    "recursive-authoritative", "soa-config",
  ],
  controls: [
    { controlId: "SC-20", controlTitle: "Secure Name/Address Resolution Service (Authoritative Source)" },
    { controlId: "SC-21", controlTitle: "Secure Name/Address Resolution Service (Recursive or Caching Resolver)" },
    { controlId: "SC-22", controlTitle: "Architecture and Provisioning for Name/Address Resolution Service" },
    { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
    { controlId: "SC-7", controlTitle: "Boundary Protection" },
    { controlId: "SI-4", controlTitle: "System Monitoring" },
  ],
};

export class CoverageGapDetector {
  /**
   * Analyze coverage gaps for a completed scan.
   *
   * @param target - The scan target
   * @param config - The scan configuration used
   * @param scannersRun - Results from scanners that were executed
   * @param templatesExecuted - IDs of templates that were executed
   * @param allTemplates - All available templates in the engine
   * @param classification - Asset classification from context engine (if available)
   */
  analyze(
    target: ScanTarget,
    config: ScanConfig,
    scannersRun: ScannerResult[],
    templatesExecuted: string[],
    allTemplates: ScanTemplate[],
    classification?: AssetClassification
  ): CoverageReport {
    const gaps: CoverageGap[] = [];
    const environment = classification?.environment || "traditional";
    const expectations = ENVIRONMENT_COVERAGE[environment] || ENVIRONMENT_COVERAGE.traditional;

    const protocolsScanned = new Set(scannersRun.filter((s) => s.status === "completed").map((s) => s.scanner));
    const templateIdsExecuted = new Set(templatesExecuted);
    const templateTagsExecuted = new Set<string>();

    // Build tag index from executed templates
    for (const tmpl of allTemplates) {
      if (templateIdsExecuted.has(tmpl.id)) {
        tmpl.tags.forEach((t) => templateTagsExecuted.add(t));
      }
    }

    // 1. Protocol gap detection
    const protocolGaps = this.detectProtocolGaps(
      expectations.requiredProtocols,
      protocolsScanned,
      environment
    );
    gaps.push(...protocolGaps);

    // 2. Template tag coverage gaps
    const templateGaps = this.detectTemplateGaps(
      expectations.requiredTemplateTags,
      templateTagsExecuted,
      allTemplates,
      templateIdsExecuted,
      environment
    );
    gaps.push(...templateGaps);

    // 3. Compliance control coverage gaps
    const complianceGaps = this.detectComplianceGaps(
      expectations.requiredControls,
      allTemplates,
      templateIdsExecuted
    );
    gaps.push(...complianceGaps);

    // 4. DNS-specific coverage gaps (NIST SP 800-81r3)
    const dnsGaps = this.detectDNSCoverageGaps(
      templateTagsExecuted,
      allTemplates,
      templateIdsExecuted
    );
    gaps.push(...dnsGaps);

    // 5. Attack surface gaps (services detected but not scanned)
    const surfaceGaps = this.detectAttackSurfaceGaps(target, scannersRun);
    gaps.push(...surfaceGaps);

    // Calculate overall coverage
    const totalExpected =
      expectations.requiredProtocols.length +
      expectations.requiredTemplateTags.length +
      DNS_COVERAGE_REQUIREMENTS.templateTags.length;
    const totalCovered =
      totalExpected - protocolGaps.length - templateGaps.length - dnsGaps.length;
    const coveragePercent = Math.round((totalCovered / Math.max(totalExpected, 1)) * 100);

    // Compliance stats
    const complianceStats: Record<string, { tested: number; total: number; percent: number }> = {};
    for (const req of expectations.requiredControls) {
      const tested = req.controlIds.filter((id) => {
        return allTemplates.some(
          (t) =>
            templateIdsExecuted.has(t.id) &&
            t.complianceMapping?.some((c) => c.controlId === id)
        );
      }).length;
      complianceStats[req.framework] = {
        tested,
        total: req.controlIds.length,
        percent: Math.round((tested / req.controlIds.length) * 100),
      };
    }

    // FN risk assessment
    const fnRiskScore = this.calculateFNRiskScore(gaps);
    const fnRiskLevel: "low" | "medium" | "high" | "critical" =
      fnRiskScore >= 80 ? "critical" :
      fnRiskScore >= 60 ? "high" :
      fnRiskScore >= 40 ? "medium" : "low";

    const protocolsSkipped = expectations.requiredProtocols.filter(
      (p) => !protocolsScanned.has(p)
    );
    const templatesSkipped = allTemplates
      .filter((t) => !templateIdsExecuted.has(t.id))
      .map((t) => t.id);

    return {
      target: target.host,
      coveragePercent,
      gaps,
      templatesExecuted: [...templateIdsExecuted],
      templatesSkipped,
      protocolsScanned: [...protocolsScanned],
      protocolsSkipped,
      complianceCovered: Object.keys(complianceStats) as ComplianceFramework[],
      complianceStats,
      fnRiskAssessment: {
        overallRisk: fnRiskLevel,
        riskScore: fnRiskScore,
        topGaps: gaps
          .sort((a, b) => b.fnRiskScore - a.fnRiskScore)
          .slice(0, 5),
      },
    };
  }

  private detectProtocolGaps(
    required: string[],
    scanned: Set<string>,
    environment: string
  ): CoverageGap[] {
    return required
      .filter((p) => !scanned.has(p))
      .map((protocol) => ({
        id: `protocol-gap-${protocol}`,
        category: "protocol_gap" as CoverageCategory,
        description: `Protocol "${protocol}" was not scanned but is required for ${environment} environment assessment`,
        severity: this.protocolSeverity(protocol) as "critical" | "high" | "medium" | "low",
        recommendation: `Run protocol scanner for ${protocol} to ensure complete coverage`,
        recommendedTemplateIds: [],
        recommendedProtocols: [protocol],
        uncoveredControls: [],
        fnRiskScore: this.protocolFNRisk(protocol),
      }));
  }

  private detectTemplateGaps(
    requiredTags: string[],
    executedTags: Set<string>,
    allTemplates: ScanTemplate[],
    executedIds: Set<string>,
    environment: string
  ): CoverageGap[] {
    return requiredTags
      .filter((tag) => !executedTags.has(tag))
      .map((tag) => {
        const matchingTemplates = allTemplates
          .filter((t) => t.tags.includes(tag) && !executedIds.has(t.id))
          .map((t) => t.id);

        return {
          id: `template-gap-${tag}`,
          category: "template_gap" as CoverageCategory,
          description: `No templates with tag "${tag}" were executed — this category is required for ${environment} assessment`,
          severity: this.tagSeverity(tag) as "critical" | "high" | "medium" | "low",
          recommendation: `Execute templates tagged "${tag}" to close this coverage gap`,
          recommendedTemplateIds: matchingTemplates.slice(0, 5),
          recommendedProtocols: [],
          uncoveredControls: [],
          fnRiskScore: this.tagFNRisk(tag),
        };
      });
  }

  private detectComplianceGaps(
    requiredControls: { framework: string; controlIds: string[] }[],
    allTemplates: ScanTemplate[],
    executedIds: Set<string>
  ): CoverageGap[] {
    const gaps: CoverageGap[] = [];

    for (const req of requiredControls) {
      for (const controlId of req.controlIds) {
        // Check if any executed template covers this control
        const covered = allTemplates.some(
          (t) =>
            executedIds.has(t.id) &&
            t.complianceMapping?.some((c) => c.controlId === controlId)
        );

        if (!covered) {
          const matchingTemplates = allTemplates
            .filter(
              (t) =>
                !executedIds.has(t.id) &&
                t.complianceMapping?.some((c) => c.controlId === controlId)
            )
            .map((t) => t.id);

          gaps.push({
            id: `compliance-gap-${req.framework}-${controlId}`,
            category: "compliance_gap",
            description: `Compliance control ${controlId} (${req.framework}) has no test coverage from executed templates`,
            severity: "medium",
            recommendation: `Execute templates that map to ${controlId} to ensure compliance coverage`,
            recommendedTemplateIds: matchingTemplates.slice(0, 3),
            recommendedProtocols: [],
            uncoveredControls: [controlId],
            fnRiskScore: 50,
          });
        }
      }
    }

    return gaps;
  }

  private detectDNSCoverageGaps(
    executedTags: Set<string>,
    allTemplates: ScanTemplate[],
    executedIds: Set<string>
  ): CoverageGap[] {
    const gaps: CoverageGap[] = [];

    for (const tag of DNS_COVERAGE_REQUIREMENTS.templateTags) {
      if (executedTags.has(tag)) continue;

      const matchingTemplates = allTemplates
        .filter((t) => t.tags.includes(tag) && !executedIds.has(t.id))
        .map((t) => t.id);

      gaps.push({
        id: `dns-gap-${tag}`,
        category: "dns_gap",
        description: `DNS security check "${tag}" was not executed — required per NIST SP 800-81r3 guidance`,
        severity: this.dnsTagSeverity(tag) as "critical" | "high" | "medium" | "low",
        recommendation: `Execute DNS security templates for "${tag}" per NIST SP 800-81r3`,
        recommendedTemplateIds: matchingTemplates,
        recommendedProtocols: ["dns"],
        uncoveredControls: this.dnsTagToControls(tag),
        fnRiskScore: this.dnsTagFNRisk(tag),
      });
    }

    return gaps;
  }

  private detectAttackSurfaceGaps(
    target: ScanTarget,
    scannersRun: ScannerResult[]
  ): CoverageGap[] {
    const gaps: CoverageGap[] = [];
    const scannedPorts = new Set(
      scannersRun.filter((s) => s.status === "completed").map((s) => s.scanner)
    );

    // Check if common high-value ports were detected but not scanned
    const HIGH_VALUE_SERVICES: { port: number; service: string; protocol: string }[] = [
      { port: 22, service: "SSH", protocol: "ssh" },
      { port: 53, service: "DNS", protocol: "dns" },
      { port: 80, service: "HTTP", protocol: "http" },
      { port: 443, service: "HTTPS", protocol: "https" },
      { port: 445, service: "SMB", protocol: "smb" },
      { port: 1883, service: "MQTT", protocol: "mqtt" },
      { port: 3306, service: "MySQL", protocol: "mysql" },
      { port: 5432, service: "PostgreSQL", protocol: "postgresql" },
      { port: 6379, service: "Redis", protocol: "redis" },
      { port: 8080, service: "HTTP Proxy", protocol: "http" },
      { port: 8443, service: "HTTPS Alt", protocol: "https" },
      { port: 27017, service: "MongoDB", protocol: "mongodb" },
    ];

    // If target has specific ports, check if they were scanned
    if (target.ports && target.ports.length > 0) {
      for (const port of target.ports) {
        const service = HIGH_VALUE_SERVICES.find((s) => s.port === port);
        if (service && !scannedPorts.has(service.protocol)) {
          gaps.push({
            id: `surface-gap-${service.service.toLowerCase()}-${port}`,
            category: "attack_surface_gap",
            description: `Port ${port} (${service.service}) is in scope but no ${service.protocol} scanner was executed`,
            severity: "medium",
            recommendation: `Run ${service.protocol} protocol scanner against port ${port}`,
            recommendedTemplateIds: [],
            recommendedProtocols: [service.protocol],
            uncoveredControls: [],
            fnRiskScore: 45,
          });
        }
      }
    }

    return gaps;
  }

  private calculateFNRiskScore(gaps: CoverageGap[]): number {
    if (gaps.length === 0) return 0;

    // Weighted average of gap FN risk scores, with severity multiplier
    const severityWeight: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const gap of gaps) {
      const weight = severityWeight[gap.severity] || 1;
      weightedSum += gap.fnRiskScore * weight;
      totalWeight += weight;
    }

    return Math.min(100, Math.round(weightedSum / totalWeight));
  }

  private protocolSeverity(protocol: string): string {
    const HIGH = ["http", "https", "dns", "ssh"];
    const MEDIUM = ["smtp", "ftp", "cloud_metadata", "docker_api", "k8s_api"];
    if (HIGH.includes(protocol)) return "high";
    if (MEDIUM.includes(protocol)) return "medium";
    return "low";
  }

  private protocolFNRisk(protocol: string): number {
    const risks: Record<string, number> = {
      http: 80, https: 80, dns: 75, ssh: 60, smtp: 50,
      cloud_metadata: 70, docker_api: 65, k8s_api: 65,
      modbus: 55, mqtt: 50, ftp: 40,
    };
    return risks[protocol] || 30;
  }

  private tagSeverity(tag: string): string {
    const HIGH = ["owasp-top10", "credentials", "cve", "exposure"];
    const MEDIUM = ["misconfig", "cloud", "dns", "dnssec"];
    if (HIGH.includes(tag)) return "high";
    if (MEDIUM.includes(tag)) return "medium";
    return "low";
  }

  private tagFNRisk(tag: string): number {
    const risks: Record<string, number> = {
      "owasp-top10": 85, credentials: 80, cve: 75, exposure: 70,
      misconfig: 60, cloud: 65, dns: 70, dnssec: 60,
      iot: 55, ics: 60, container: 55,
    };
    return risks[tag] || 40;
  }

  private dnsTagSeverity(tag: string): string {
    const HIGH = ["zone-transfer", "dangling-record", "lame-delegation", "dns-tunneling"];
    const MEDIUM = ["dnssec", "encrypted-dns", "typosquat", "recursive-authoritative"];
    if (HIGH.includes(tag)) return "high";
    if (MEDIUM.includes(tag)) return "medium";
    return "low";
  }

  private dnsTagFNRisk(tag: string): number {
    const risks: Record<string, number> = {
      "zone-transfer": 75, "dangling-record": 80, dnssec: 65,
      "encrypted-dns": 55, "dns-tunneling": 70, "lame-delegation": 75,
      typosquat: 60, "dns-info-leakage": 40,
      "recursive-authoritative": 50, "soa-config": 35,
    };
    return risks[tag] || 40;
  }

  private dnsTagToControls(tag: string): string[] {
    const mapping: Record<string, string[]> = {
      "zone-transfer": ["SC-20", "SC-22"],
      "dangling-record": ["SC-20"],
      dnssec: ["SC-20", "SC-21"],
      "encrypted-dns": ["SC-8", "SC-21"],
      "dns-tunneling": ["SC-7", "SI-4"],
      "lame-delegation": ["SC-20", "SC-22"],
      typosquat: ["SC-20"],
      "dns-info-leakage": ["SC-20"],
      "recursive-authoritative": ["SC-22"],
      "soa-config": ["SC-20"],
    };
    return mapping[tag] || [];
  }
}

// ─── Singleton Accessors ──────────────────────────────────────────────────

let dedupEngine: DeduplicationEngine | null = null;
let normEngine: NormalizationEngine | null = null;
let coverageDetector: CoverageGapDetector | null = null;

export function getDeduplicationEngine(): DeduplicationEngine {
  if (!dedupEngine) dedupEngine = new DeduplicationEngine();
  return dedupEngine;
}

export function getNormalizationEngine(): NormalizationEngine {
  if (!normEngine) normEngine = new NormalizationEngine();
  return normEngine;
}

export function getCoverageGapDetector(): CoverageGapDetector {
  if (!coverageDetector) coverageDetector = new CoverageGapDetector();
  return coverageDetector;
}
