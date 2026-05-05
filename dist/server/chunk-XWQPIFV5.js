import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/scanforge/intelligence/dedup-coverage.ts
function getDeduplicationEngine() {
  if (!dedupEngine) dedupEngine = new DeduplicationEngine();
  return dedupEngine;
}
function getNormalizationEngine() {
  if (!normEngine) normEngine = new NormalizationEngine();
  return normEngine;
}
function getCoverageGapDetector() {
  if (!coverageDetector) coverageDetector = new CoverageGapDetector();
  return coverageDetector;
}
var SEVERITY_RANK, DeduplicationEngine, NormalizationEngine, ENVIRONMENT_COVERAGE, DNS_COVERAGE_REQUIREMENTS, CoverageGapDetector, dedupEngine, normEngine, coverageDetector;
var init_dedup_coverage = __esm({
  "server/scanforge/intelligence/dedup-coverage.ts"() {
    "use strict";
    SEVERITY_RANK = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };
    DeduplicationEngine = class {
      /**
       * Compute a deterministic fingerprint for a finding.
       * Two findings with the same fingerprint are considered duplicates.
       */
      computeFingerprint(finding) {
        const titleNormalized = this.normalizeTitle(finding.title);
        const cves = [...finding.cves || []].sort();
        const cwes = [...finding.cwes || []].sort();
        const parts = [
          finding.target.toLowerCase(),
          finding.port?.toString() || "*",
          finding.protocol || "*",
          cves.join(",") || titleNormalized,
          cwes.join(",")
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
            templateId: finding.source
          }
        };
      }
      /**
       * Deduplicate a set of findings. Merges duplicates by keeping the
       * highest-confidence version and combining evidence from all sources.
       */
      deduplicate(findings) {
        const mergeLog = [];
        const fingerprints = /* @__PURE__ */ new Map();
        for (const finding of findings) {
          const fp = this.computeFingerprint(finding);
          const group = fingerprints.get(fp.hash) || [];
          group.push(finding);
          fingerprints.set(fp.hash, group);
        }
        const mergedFindings = [];
        for (const [hash, group] of fingerprints) {
          if (group.length === 1) {
            mergedFindings.push(group[0]);
            continue;
          }
          const canonical = this.mergeGroup(group);
          mergedFindings.push(canonical.finding);
          mergeLog.push(canonical.entry);
        }
        const cveDeduped = this.deduplicateByCVEOverlap(mergedFindings, mergeLog);
        const cweDeduped = this.deduplicateByCWEOverlap(cveDeduped, mergeLog);
        const fuzzyDeduped = this.deduplicateByFuzzyTitle(cweDeduped, mergeLog);
        return {
          findings: fuzzyDeduped,
          duplicatesRemoved: findings.length - fuzzyDeduped.length,
          mergeLog,
          totalBefore: findings.length,
          totalAfter: fuzzyDeduped.length
        };
      }
      /**
       * Merge a group of duplicate findings into a single canonical finding.
       * Strategy: Keep highest confidence, combine evidence, union references.
       */
      mergeGroup(group) {
        const sorted = [...group].sort((a, b) => b.confidence - a.confidence);
        const canonical = { ...sorted[0] };
        const mergedIds = sorted.slice(1).map((f) => f.id);
        const allCves = /* @__PURE__ */ new Set();
        const allCwes = /* @__PURE__ */ new Set();
        const allTechniques = /* @__PURE__ */ new Set();
        const allReferences = /* @__PURE__ */ new Set();
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
        const originalConfidence = canonical.confidence;
        const corroborationBoost = Math.min(15, (group.length - 1) * 5);
        canonical.confidence = Math.min(100, canonical.confidence + corroborationBoost);
        const complianceMap = /* @__PURE__ */ new Map();
        for (const finding of sorted) {
          finding.compliance?.forEach((c) => {
            const key = `${c.framework}:${c.controlId}`;
            if (!complianceMap.has(key) || c.confidence > (complianceMap.get(key)?.confidence || 0)) {
              complianceMap.set(key, c);
            }
          });
        }
        canonical.compliance = [...complianceMap.values()];
        const bestEvidence = sorted.reduce((best, f) => {
          const bestLen = (best.evidence.response?.length || 0) + (best.evidence.request?.length || 0);
          const fLen = (f.evidence.response?.length || 0) + (f.evidence.request?.length || 0);
          return fLen > bestLen ? f : best;
        }, sorted[0]);
        canonical.evidence = bestEvidence.evidence;
        const bestRisk = sorted.reduce((best, f) => {
          if (!f.riskScore) return best;
          if (!best || f.riskScore.composite > (best.composite || 0)) return f.riskScore;
          return best;
        }, canonical.riskScore);
        if (bestRisk) canonical.riskScore = bestRisk;
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
            confidenceDelta: canonical.confidence - originalConfidence
          }
        };
      }
      /**
       * Second-pass deduplication: find findings across different fingerprint
       * groups that share CVEs (different scanners may report the same CVE
       * with slightly different titles/ports).
       */
      deduplicateByCVEOverlap(findings, mergeLog) {
        const cveIndex = /* @__PURE__ */ new Map();
        for (let i = 0; i < findings.length; i++) {
          for (const cve of findings[i].cves || []) {
            const indices = cveIndex.get(cve) || [];
            indices.push(i);
            cveIndex.set(cve, indices);
          }
        }
        const toMerge = /* @__PURE__ */ new Map();
        for (const [_cve, indices] of cveIndex) {
          if (indices.length < 2) continue;
          const byTarget = /* @__PURE__ */ new Map();
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
              const mergeSet = toMerge.get(canonical) || /* @__PURE__ */ new Set();
              mergeSet.add(targetIndices[i]);
              toMerge.set(canonical, mergeSet);
            }
          }
        }
        if (toMerge.size === 0) return findings;
        const removed = /* @__PURE__ */ new Set();
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
      deduplicateByCWEOverlap(findings, mergeLog) {
        const cweIndex = /* @__PURE__ */ new Map();
        for (let i = 0; i < findings.length; i++) {
          for (const cwe of findings[i].cwes || []) {
            const indices = cweIndex.get(cwe) || [];
            indices.push(i);
            cweIndex.set(cwe, indices);
          }
        }
        const toMerge = /* @__PURE__ */ new Map();
        for (const [_cwe, indices] of cweIndex) {
          if (indices.length < 2) continue;
          const byTarget = /* @__PURE__ */ new Map();
          for (const idx of indices) {
            const target = findings[idx].target;
            const group = byTarget.get(target) || [];
            group.push(idx);
            byTarget.set(target, group);
          }
          for (const [_target, targetIndices] of byTarget) {
            if (targetIndices.length < 2) continue;
            const sources = new Set(targetIndices.map((idx) => findings[idx].source));
            if (sources.size < 2) continue;
            const canonical = targetIndices[0];
            for (let i = 1; i < targetIndices.length; i++) {
              const mergeSet = toMerge.get(canonical) || /* @__PURE__ */ new Set();
              mergeSet.add(targetIndices[i]);
              toMerge.set(canonical, mergeSet);
            }
          }
        }
        if (toMerge.size === 0) return findings;
        const removed = /* @__PURE__ */ new Set();
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
      deduplicateByFuzzyTitle(findings, mergeLog) {
        const SIMILARITY_THRESHOLD = 0.55;
        const normalizedTitles = findings.map((f) => this.stripSourcePrefix(this.normalizeTitle(f.title)));
        const titleKeywords = normalizedTitles.map((t) => new Set(t.split(/\s+/).filter((w) => w.length > 2)));
        const toMerge = /* @__PURE__ */ new Map();
        for (let i = 0; i < findings.length; i++) {
          for (let j = i + 1; j < findings.length; j++) {
            if (findings[i].target !== findings[j].target) continue;
            if (findings[i].source === findings[j].source) continue;
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
              const mergeSet = toMerge.get(i) || /* @__PURE__ */ new Set();
              mergeSet.add(j);
              toMerge.set(i, mergeSet);
            }
          }
        }
        if (toMerge.size === 0) return findings;
        const removed = /* @__PURE__ */ new Set();
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
       * Handles [ZAP], [zap], [nuclei], [Nuclei], [nikto], [scanforge-discovery], [scanforge], etc.
       */
      stripSourcePrefix(title) {
        return title.replace(/^\[?\w+\]?\s*/i, "").trim();
      }
      /**
       * Normalize a finding title for comparison.
       * Strips version numbers, normalizes whitespace, lowercases.
       */
      normalizeTitle(title) {
        return title.toLowerCase().replace(/\s+/g, " ").replace(/v?\d+\.\d+(\.\d+)*/g, "VERSION").replace(/[^\w\s]/g, "").trim();
      }
      /**
       * Simple string hash (djb2 algorithm).
       */
      hashString(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
          hash = (hash << 5) + hash + str.charCodeAt(i) & 4294967295;
        }
        return hash.toString(16).padStart(8, "0");
      }
    };
    NormalizationEngine = class {
      /**
       * Normalize a set of findings to a canonical form.
       * Unifies severity, CVE/CWE mappings, and compliance references.
       */
      normalize(findings) {
        const log = [];
        let severityAdjustments = 0;
        let referenceEnrichments = 0;
        let complianceMappingsAdded = 0;
        const normalized = findings.map((finding) => {
          const f = { ...finding };
          const adjustedSeverity = this.normalizeSeverity(f);
          if (adjustedSeverity !== f.severity) {
            log.push({
              findingId: f.id,
              field: "severity",
              oldValue: f.severity,
              newValue: adjustedSeverity,
              reason: "CVE-based severity normalization"
            });
            f.severity = adjustedSeverity;
            severityAdjustments++;
          }
          const enriched = this.enrichReferences(f);
          if (enriched.added > 0) {
            referenceEnrichments += enriched.added;
            f.cves = enriched.cves;
            f.cwes = enriched.cwes;
          }
          const complianceAdded = this.enrichComplianceMappings(f);
          if (complianceAdded > 0) {
            complianceMappingsAdded += complianceAdded;
          }
          f.target = this.normalizeTarget(f.target);
          if (!f.foundAt) f.foundAt = Date.now();
          return f;
        });
        return {
          findings: normalized,
          severityAdjustments,
          referenceEnrichments,
          complianceMappingsAdded,
          log
        };
      }
      /**
       * Normalize severity based on CVE data and confidence-weighted voting.
       * If multiple scanners disagree on severity, use the confidence-weighted
       * consensus.
       */
      normalizeSeverity(finding) {
        if (finding.riskScore?.cvss !== void 0) {
          const cvss = finding.riskScore.cvss;
          if (cvss >= 9) return "critical";
          if (cvss >= 7) return "high";
          if (cvss >= 4) return "medium";
          if (cvss >= 0.1) return "low";
          return "info";
        }
        if (finding.riskScore?.kevListed && SEVERITY_RANK[finding.severity] < SEVERITY_RANK["high"]) {
          return "high";
        }
        if (finding.riskScore?.ransomwareUse && SEVERITY_RANK[finding.severity] < SEVERITY_RANK["high"]) {
          return "high";
        }
        return finding.severity;
      }
      /**
       * Enrich CVE/CWE references by cross-referencing known mappings.
       */
      enrichReferences(finding) {
        const cves = new Set(finding.cves || []);
        const cwes = new Set(finding.cwes || []);
        let added = 0;
        const titleLower = finding.title.toLowerCase();
        const descLower = finding.description.toLowerCase();
        const combined = `${titleLower} ${descLower}`;
        const CWE_PATTERNS = [
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
          [/unencrypted|cleartext|plaintext/i, "CWE-319"]
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
      enrichComplianceMappings(finding) {
        if (!finding.cwes || finding.cwes.length === 0) return 0;
        const existing = new Set(
          (finding.compliance || []).map((c) => `${c.framework}:${c.controlId}`)
        );
        const CWE_TO_NIST = {
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
          "CWE-16": [{ controlId: "CM-6", controlTitle: "Configuration Settings" }]
        };
        let added = 0;
        const compliance = [...finding.compliance || []];
        for (const cwe of finding.cwes) {
          const controls = CWE_TO_NIST[cwe];
          if (!controls) continue;
          for (const control of controls) {
            const key = `nist_800_53:${control.controlId}`;
            if (existing.has(key)) continue;
            compliance.push({
              framework: "nist_800_53",
              controlId: control.controlId,
              controlTitle: control.controlTitle,
              status: "non_compliant",
              confidence: 70
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
      normalizeTarget(target) {
        try {
          const url = new URL(target.startsWith("http") ? target : `https://${target}`);
          return `${url.protocol}//${url.hostname.toLowerCase()}${url.port ? `:${url.port}` : ""}${url.pathname.replace(/\/+$/, "") || "/"}`;
        } catch {
          return target.toLowerCase().replace(/\/+$/, "");
        }
      }
    };
    ENVIRONMENT_COVERAGE = {
      traditional: {
        requiredProtocols: ["http", "https", "ssh", "dns", "smtp", "ftp"],
        requiredTemplateTags: [
          "owasp-top10",
          "exposure",
          "credentials",
          "misconfig",
          "cve",
          "dns",
          "dnssec",
          "zone-transfer"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: [
              "AC-6",
              "AU-2",
              "CM-6",
              "IA-2",
              "IA-5",
              "SC-7",
              "SC-8",
              "SC-13",
              "SC-20",
              "SC-21",
              "SC-22",
              "SI-4",
              "SI-10"
            ]
          }
        ],
        minTemplatesPerProtocol: 3
      },
      cloud: {
        requiredProtocols: ["http", "https", "dns", "cloud_metadata", "cloud_storage"],
        requiredTemplateTags: [
          "owasp-top10",
          "cloud",
          "imds",
          "s3",
          "storage",
          "iam",
          "dns",
          "dnssec"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: [
              "AC-2",
              "AC-6",
              "CM-6",
              "IA-2",
              "SC-7",
              "SC-8",
              "SC-13",
              "SC-20",
              "SC-21",
              "SC-22"
            ]
          }
        ],
        minTemplatesPerProtocol: 2
      },
      iot: {
        requiredProtocols: ["http", "mqtt", "coap", "upnp", "dns"],
        requiredTemplateTags: [
          "iot",
          "mqtt",
          "coap",
          "upnp",
          "default-credentials",
          "firmware",
          "dns"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: ["AC-6", "IA-2", "IA-5", "SC-8", "SC-20", "SI-4"]
          }
        ],
        minTemplatesPerProtocol: 2
      },
      ics: {
        requiredProtocols: ["modbus", "dnp3", "bacnet", "ethernet_ip", "opc_ua", "dns"],
        requiredTemplateTags: [
          "ics",
          "scada",
          "modbus",
          "dnp3",
          "bacnet",
          "safety",
          "dns"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: ["AC-6", "IA-2", "SC-7", "SC-8", "SC-20", "SI-4"]
          }
        ],
        minTemplatesPerProtocol: 1
      },
      container: {
        requiredProtocols: ["http", "https", "docker_api", "k8s_api", "dns"],
        requiredTemplateTags: [
          "container",
          "docker",
          "kubernetes",
          "registry",
          "rbac",
          "dns"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: ["AC-2", "AC-6", "CM-6", "IA-2", "SC-7", "SC-8", "SC-20"]
          }
        ],
        minTemplatesPerProtocol: 2
      },
      hybrid: {
        requiredProtocols: ["http", "https", "dns", "ssh", "cloud_metadata"],
        requiredTemplateTags: [
          "owasp-top10",
          "cloud",
          "exposure",
          "dns",
          "dnssec"
        ],
        requiredControls: [
          {
            framework: "nist_800_53",
            controlIds: [
              "AC-6",
              "CM-6",
              "IA-2",
              "SC-7",
              "SC-8",
              "SC-13",
              "SC-20",
              "SC-21",
              "SC-22"
            ]
          }
        ],
        minTemplatesPerProtocol: 2
      }
    };
    DNS_COVERAGE_REQUIREMENTS = {
      templateTags: [
        "zone-transfer",
        "dangling-record",
        "dnssec",
        "encrypted-dns",
        "dns-tunneling",
        "lame-delegation",
        "typosquat",
        "dns-info-leakage",
        "recursive-authoritative",
        "soa-config"
      ],
      controls: [
        { controlId: "SC-20", controlTitle: "Secure Name/Address Resolution Service (Authoritative Source)" },
        { controlId: "SC-21", controlTitle: "Secure Name/Address Resolution Service (Recursive or Caching Resolver)" },
        { controlId: "SC-22", controlTitle: "Architecture and Provisioning for Name/Address Resolution Service" },
        { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
        { controlId: "SC-7", controlTitle: "Boundary Protection" },
        { controlId: "SI-4", controlTitle: "System Monitoring" }
      ]
    };
    CoverageGapDetector = class {
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
      analyze(target, config, scannersRun, templatesExecuted, allTemplates, classification) {
        const gaps = [];
        const environment = classification?.environment || "traditional";
        const expectations = ENVIRONMENT_COVERAGE[environment] || ENVIRONMENT_COVERAGE.traditional;
        const protocolsScanned = new Set(scannersRun.filter((s) => s.status === "completed").map((s) => s.scanner));
        const templateIdsExecuted = new Set(templatesExecuted);
        const templateTagsExecuted = /* @__PURE__ */ new Set();
        for (const tmpl of allTemplates) {
          if (templateIdsExecuted.has(tmpl.id)) {
            tmpl.tags.forEach((t) => templateTagsExecuted.add(t));
          }
        }
        const protocolGaps = this.detectProtocolGaps(
          expectations.requiredProtocols,
          protocolsScanned,
          environment
        );
        gaps.push(...protocolGaps);
        const templateGaps = this.detectTemplateGaps(
          expectations.requiredTemplateTags,
          templateTagsExecuted,
          allTemplates,
          templateIdsExecuted,
          environment
        );
        gaps.push(...templateGaps);
        const complianceGaps = this.detectComplianceGaps(
          expectations.requiredControls,
          allTemplates,
          templateIdsExecuted
        );
        gaps.push(...complianceGaps);
        const dnsGaps = this.detectDNSCoverageGaps(
          templateTagsExecuted,
          allTemplates,
          templateIdsExecuted
        );
        gaps.push(...dnsGaps);
        const surfaceGaps = this.detectAttackSurfaceGaps(target, scannersRun);
        gaps.push(...surfaceGaps);
        const totalExpected = expectations.requiredProtocols.length + expectations.requiredTemplateTags.length + DNS_COVERAGE_REQUIREMENTS.templateTags.length;
        const totalCovered = totalExpected - protocolGaps.length - templateGaps.length - dnsGaps.length;
        const coveragePercent = Math.round(totalCovered / Math.max(totalExpected, 1) * 100);
        const complianceStats = {};
        for (const req of expectations.requiredControls) {
          const tested = req.controlIds.filter((id) => {
            return allTemplates.some(
              (t) => templateIdsExecuted.has(t.id) && t.complianceMapping?.some((c) => c.controlId === id)
            );
          }).length;
          complianceStats[req.framework] = {
            tested,
            total: req.controlIds.length,
            percent: Math.round(tested / req.controlIds.length * 100)
          };
        }
        const fnRiskScore = this.calculateFNRiskScore(gaps);
        const fnRiskLevel = fnRiskScore >= 80 ? "critical" : fnRiskScore >= 60 ? "high" : fnRiskScore >= 40 ? "medium" : "low";
        const protocolsSkipped = expectations.requiredProtocols.filter(
          (p) => !protocolsScanned.has(p)
        );
        const templatesSkipped = allTemplates.filter((t) => !templateIdsExecuted.has(t.id)).map((t) => t.id);
        return {
          target: target.host,
          coveragePercent,
          gaps,
          templatesExecuted: [...templateIdsExecuted],
          templatesSkipped,
          protocolsScanned: [...protocolsScanned],
          protocolsSkipped,
          complianceCovered: Object.keys(complianceStats),
          complianceStats,
          fnRiskAssessment: {
            overallRisk: fnRiskLevel,
            riskScore: fnRiskScore,
            topGaps: gaps.sort((a, b) => b.fnRiskScore - a.fnRiskScore).slice(0, 5)
          }
        };
      }
      detectProtocolGaps(required, scanned, environment) {
        return required.filter((p) => !scanned.has(p)).map((protocol) => ({
          id: `protocol-gap-${protocol}`,
          category: "protocol_gap",
          description: `Protocol "${protocol}" was not scanned but is required for ${environment} environment assessment`,
          severity: this.protocolSeverity(protocol),
          recommendation: `Run protocol scanner for ${protocol} to ensure complete coverage`,
          recommendedTemplateIds: [],
          recommendedProtocols: [protocol],
          uncoveredControls: [],
          fnRiskScore: this.protocolFNRisk(protocol)
        }));
      }
      detectTemplateGaps(requiredTags, executedTags, allTemplates, executedIds, environment) {
        return requiredTags.filter((tag) => !executedTags.has(tag)).map((tag) => {
          const matchingTemplates = allTemplates.filter((t) => t.tags.includes(tag) && !executedIds.has(t.id)).map((t) => t.id);
          return {
            id: `template-gap-${tag}`,
            category: "template_gap",
            description: `No templates with tag "${tag}" were executed \u2014 this category is required for ${environment} assessment`,
            severity: this.tagSeverity(tag),
            recommendation: `Execute templates tagged "${tag}" to close this coverage gap`,
            recommendedTemplateIds: matchingTemplates.slice(0, 5),
            recommendedProtocols: [],
            uncoveredControls: [],
            fnRiskScore: this.tagFNRisk(tag)
          };
        });
      }
      detectComplianceGaps(requiredControls, allTemplates, executedIds) {
        const gaps = [];
        for (const req of requiredControls) {
          for (const controlId of req.controlIds) {
            const covered = allTemplates.some(
              (t) => executedIds.has(t.id) && t.complianceMapping?.some((c) => c.controlId === controlId)
            );
            if (!covered) {
              const matchingTemplates = allTemplates.filter(
                (t) => !executedIds.has(t.id) && t.complianceMapping?.some((c) => c.controlId === controlId)
              ).map((t) => t.id);
              gaps.push({
                id: `compliance-gap-${req.framework}-${controlId}`,
                category: "compliance_gap",
                description: `Compliance control ${controlId} (${req.framework}) has no test coverage from executed templates`,
                severity: "medium",
                recommendation: `Execute templates that map to ${controlId} to ensure compliance coverage`,
                recommendedTemplateIds: matchingTemplates.slice(0, 3),
                recommendedProtocols: [],
                uncoveredControls: [controlId],
                fnRiskScore: 50
              });
            }
          }
        }
        return gaps;
      }
      detectDNSCoverageGaps(executedTags, allTemplates, executedIds) {
        const gaps = [];
        for (const tag of DNS_COVERAGE_REQUIREMENTS.templateTags) {
          if (executedTags.has(tag)) continue;
          const matchingTemplates = allTemplates.filter((t) => t.tags.includes(tag) && !executedIds.has(t.id)).map((t) => t.id);
          gaps.push({
            id: `dns-gap-${tag}`,
            category: "dns_gap",
            description: `DNS security check "${tag}" was not executed \u2014 required per NIST SP 800-81r3 guidance`,
            severity: this.dnsTagSeverity(tag),
            recommendation: `Execute DNS security templates for "${tag}" per NIST SP 800-81r3`,
            recommendedTemplateIds: matchingTemplates,
            recommendedProtocols: ["dns"],
            uncoveredControls: this.dnsTagToControls(tag),
            fnRiskScore: this.dnsTagFNRisk(tag)
          });
        }
        return gaps;
      }
      detectAttackSurfaceGaps(target, scannersRun) {
        const gaps = [];
        const scannedPorts = new Set(
          scannersRun.filter((s) => s.status === "completed").map((s) => s.scanner)
        );
        const HIGH_VALUE_SERVICES = [
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
          { port: 27017, service: "MongoDB", protocol: "mongodb" }
        ];
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
                fnRiskScore: 45
              });
            }
          }
        }
        return gaps;
      }
      calculateFNRiskScore(gaps) {
        if (gaps.length === 0) return 0;
        const severityWeight = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1
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
      protocolSeverity(protocol) {
        const HIGH = ["http", "https", "dns", "ssh"];
        const MEDIUM = ["smtp", "ftp", "cloud_metadata", "docker_api", "k8s_api"];
        if (HIGH.includes(protocol)) return "high";
        if (MEDIUM.includes(protocol)) return "medium";
        return "low";
      }
      protocolFNRisk(protocol) {
        const risks = {
          http: 80,
          https: 80,
          dns: 75,
          ssh: 60,
          smtp: 50,
          cloud_metadata: 70,
          docker_api: 65,
          k8s_api: 65,
          modbus: 55,
          mqtt: 50,
          ftp: 40
        };
        return risks[protocol] || 30;
      }
      tagSeverity(tag) {
        const HIGH = ["owasp-top10", "credentials", "cve", "exposure"];
        const MEDIUM = ["misconfig", "cloud", "dns", "dnssec"];
        if (HIGH.includes(tag)) return "high";
        if (MEDIUM.includes(tag)) return "medium";
        return "low";
      }
      tagFNRisk(tag) {
        const risks = {
          "owasp-top10": 85,
          credentials: 80,
          cve: 75,
          exposure: 70,
          misconfig: 60,
          cloud: 65,
          dns: 70,
          dnssec: 60,
          iot: 55,
          ics: 60,
          container: 55
        };
        return risks[tag] || 40;
      }
      dnsTagSeverity(tag) {
        const HIGH = ["zone-transfer", "dangling-record", "lame-delegation", "dns-tunneling"];
        const MEDIUM = ["dnssec", "encrypted-dns", "typosquat", "recursive-authoritative"];
        if (HIGH.includes(tag)) return "high";
        if (MEDIUM.includes(tag)) return "medium";
        return "low";
      }
      dnsTagFNRisk(tag) {
        const risks = {
          "zone-transfer": 75,
          "dangling-record": 80,
          dnssec: 65,
          "encrypted-dns": 55,
          "dns-tunneling": 70,
          "lame-delegation": 75,
          typosquat: 60,
          "dns-info-leakage": 40,
          "recursive-authoritative": 50,
          "soa-config": 35
        };
        return risks[tag] || 40;
      }
      dnsTagToControls(tag) {
        const mapping = {
          "zone-transfer": ["SC-20", "SC-22"],
          "dangling-record": ["SC-20"],
          dnssec: ["SC-20", "SC-21"],
          "encrypted-dns": ["SC-8", "SC-21"],
          "dns-tunneling": ["SC-7", "SI-4"],
          "lame-delegation": ["SC-20", "SC-22"],
          typosquat: ["SC-20"],
          "dns-info-leakage": ["SC-20"],
          "recursive-authoritative": ["SC-22"],
          "soa-config": ["SC-20"]
        };
        return mapping[tag] || [];
      }
    };
    dedupEngine = null;
    normEngine = null;
    coverageDetector = null;
  }
});

export {
  DeduplicationEngine,
  NormalizationEngine,
  CoverageGapDetector,
  getDeduplicationEngine,
  getNormalizationEngine,
  getCoverageGapDetector,
  init_dedup_coverage
};
