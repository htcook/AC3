/**
 * Dedup/Coverage Bridge — Adapts the engagement orchestrator's finding format
 * to ScanForge's dedup/normalization/coverage engines.
 *
 * The orchestrator stores findings as simple { id, severity, title, cve } objects
 * on each asset. ScanForge's engines expect the richer ScanFinding type. This bridge
 * converts between the two formats and runs the dedup/normalization/coverage pipeline
 * at the end of the vuln detection phase.
 *
 * Integration points:
 *   1. After vuln detection completes → dedup + normalize all asset.vulns
 *   2. After dedup → coverage gap analysis per asset
 *   3. Results stored on EngagementOpsState.dedupStats + coverageReport
 *
 * @author Harrison Cook — AceofCloud
 */

import type { ScanFinding, FindingSeverity, ScanTarget, ScanConfig, ScannerResult, ScanTemplate, AssetClassification, AssetEnvironment } from "../scanforge/types";
import {
  getDeduplicationEngine,
  getNormalizationEngine,
  getCoverageGapDetector,
} from "../scanforge/intelligence/dedup-coverage";
import type { DedupResult, NormalizationResult, CoverageReport, CoverageGap } from "../scanforge/intelligence/dedup-coverage";
import {
  enrichFinding as enrichWithNistMitre,
  generateNistGapSummary,
  getImpactedNistFamilies,
  type FindingEnrichment,
  type NistControl,
  type MitreTechnique,
  type CweEntry,
} from "./nist-mitre-cwe-mapper";
import { resolveCvesToCwes } from "./nvd-cve-lookup";

// ─── Types for Orchestrator Integration ──────────────────────────────────

/** Simple vuln shape from the engagement orchestrator */
export interface OrchestratorVuln {
  id: string;
  severity: string;
  title: string;
  cve?: string;
  corroborationTier?: string;
  evidenceDetail?: string;
  detectedVersion?: string;
  affectedVersions?: string;
  /** Evidence preserved from ALL scanners that reported this vuln */
  scannerEvidence?: Array<{
    scanner: string;
    title: string;
    evidenceDetail?: string;
    rawEvidence?: string;
    corroborationTier: string;
    detectedVersion?: string;
    timestamp: number;
  }>;
  [key: string]: any;
}

/** Simple port shape from the engagement orchestrator */
export interface OrchestratorPort {
  port: number;
  service: string;
  version?: string;
}

/** Asset shape from the engagement orchestrator */
export interface OrchestratorAsset {
  hostname: string;
  ip?: string;
  type: string;
  ports: OrchestratorPort[];
  vulns: OrchestratorVuln[];
  pendingVulns?: OrchestratorVuln[];
  zapFindings?: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  toolResults?: Array<{
    tool: string;
    command: string;
    exitCode: number;
    durationMs: number;
    timedOut: boolean;
    findingCount: number;
    findings: Array<{ severity: string; title: string; cve?: string }>;
    outputPreview: string;
    executedAt: number;
    phase: string;
  }>;
  status: string;
  wafDetected?: string;
}

/** Dedup stats returned to the UI */
export interface DedupStats {
  totalFindingsBeforeDedup: number;
  totalFindingsAfterDedup: number;
  duplicatesRemoved: number;
  duplicatesByAsset: Record<string, number>;
  mergeLog: Array<{
    canonicalTitle: string;
    mergedCount: number;
    sources: string[];
  }>;
  normalizedSeverityChanges: number;
  processedAt: number;
  /** NIST/MITRE/CWE enrichment summary across all deduplicated findings */
  complianceEnrichment?: ComplianceEnrichmentSummary;
}

/** Compliance enrichment summary for all findings */
export interface ComplianceEnrichmentSummary {
  /** Total unique NIST 800-53 controls impacted */
  totalNistControlsImpacted: number;
  /** NIST control families impacted, sorted by control count */
  impactedNistFamilies: Array<{ familyCode: string; familyName: string; controlCount: number }>;
  /** Total unique MITRE ATT&CK techniques identified */
  totalMitreTechniques: number;
  /** MITRE techniques grouped by tactic */
  mitreTechniquesByTactic: Record<string, Array<{ techniqueId: string; techniqueName: string }>>;
  /** Total unique CWEs identified */
  totalCwes: number;
  /** CWEs grouped by category */
  cwesByCategory: Record<string, CweEntry[]>;
  /** NIST gap summary at moderate baseline */
  nistGapSummary: {
    totalControlsImpacted: number;
    criticalGaps: NistControl[];
    coverageScore: number;
    byFamily: Array<{ familyCode: string; familyName: string; controls: string[]; highestPriority: string }>;
  };
  /** Per-finding enrichment details (finding ID → enrichment) */
  findingEnrichments: Record<string, FindingEnrichment>;
}

/** Coverage report returned to the UI */
export interface EngagementCoverageReport {
  overallScore: number; // 0-100
  assetReports: Array<{
    hostname: string;
    score: number;
    gaps: Array<{
      category: string;
      description: string;
      severity: string;
      recommendation: string;
      missingChecks: string[];
      /** NIST controls related to this gap */
      relatedNistControls?: string[];
      /** MITRE techniques related to this gap */
      relatedMitreTechniques?: string[];
    }>;
    totalGaps: number;
    criticalGaps: number;
  }>;
  totalGaps: number;
  criticalGaps: number;
  recommendations: string[];
  processedAt: number;
}

// ─── Format Adapters ─────────────────────────────────────────────────────

/**
 * Convert an orchestrator vuln to a ScanForge ScanFinding.
 * Extracts scanner source from the title prefix (e.g., "[nuclei]", "[ZAP]", "[SQLMap]").
 *
 * ScanFinding expects:
 *   - target: string (hostname)
 *   - source: string (template/scanner ID)
 *   - foundAt: number (timestamp)
 *   - evidence: FindingEvidence (object with data, matchedPattern, etc.)
 */
function vulnToScanFinding(vuln: OrchestratorVuln, asset: OrchestratorAsset): ScanFinding {
  // Extract scanner source from title prefix
  const sourceMatch = vuln.title.match(/^\[([^\]]+)\]/);
  const scanner = sourceMatch ? sourceMatch[1].toLowerCase() : "unknown";
  const cleanTitle = sourceMatch ? vuln.title.slice(sourceMatch[0].length).trim() : vuln.title;

  // Map severity string to FindingSeverity
  const severityMap: Record<string, FindingSeverity> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "info",
  };
  const severity = severityMap[vuln.severity?.toLowerCase()] || "info";

  // Extract CWE from title if present
  const cweMatch = vuln.title.match(/CWE-(\d+)/i);
  const cwes = cweMatch ? [`CWE-${cweMatch[1]}`] : [];

  return {
    id: vuln.id,
    source: `orchestrator-${scanner}`,
    title: cleanTitle || vuln.title,
    description: vuln.evidenceDetail || `Finding from ${scanner}: ${cleanTitle || vuln.title}`,
    severity,
    confidence: vuln.corroborationTier === "confirmed" ? 95 : vuln.corroborationTier === "corroborated" ? 80 : 60,
    target: asset.hostname,
    port: 0,
    protocol: "tcp",
    evidence: {
      data: { raw: vuln.evidenceDetail || vuln.title },
      matchedPattern: vuln.title,
    },
    cves: vuln.cve ? [vuln.cve] : [],
    cwes,
    references: [],
    remediation: "",
    foundAt: Date.now(),
  } as ScanFinding;
}

/**
 * Convert ZAP findings to ScanForge ScanFindings.
 */
function zapFindingToScanFinding(zap: { alert: string; risk: string; url: string; cweId?: number }, asset: OrchestratorAsset): ScanFinding {
  const severityMap: Record<string, FindingSeverity> = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
  };

  return {
    id: `zap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    source: "orchestrator-zap",
    title: zap.alert,
    description: `ZAP finding: ${zap.alert} at ${zap.url}`,
    severity: severityMap[zap.risk] || "info",
    confidence: 85,
    target: asset.hostname,
    port: 0,
    protocol: "tcp",
    evidence: {
      data: { alert: zap.alert, risk: zap.risk, url: zap.url },
    },
    cves: [],
    cwes: zap.cweId ? [`CWE-${zap.cweId}`] : [],
    references: [],
    remediation: "",
    foundAt: Date.now(),
  } as ScanFinding;
}

/**
 * Convert a deduplicated ScanFinding back to the orchestrator vuln format.
 * Preserves merged scanner evidence when available.
 */
function scanFindingToVuln(finding: ScanFinding, mergedFindings?: ScanFinding[]): OrchestratorVuln {
  // Reconstruct the scanner prefix from source field
  const sourceStr = (finding as any).source || "unknown";
  const scanner = sourceStr.replace(/^orchestrator-/, "") || "unknown";
  const title = `[${scanner}] ${finding.title}`;
  // Extract CWE from the finding's cwes array (e.g., ["CWE-693"] → "CWE-693")
  const cwe = finding.cwes?.[0] || undefined;
  // Extract description from the finding for richer exploit context
  const description = finding.description || undefined;
  // Extract evidence text if available
  const evidence = finding.evidence?.data ? JSON.stringify(finding.evidence.data) : undefined;

  // Build scannerEvidence array from all merged findings
  const scannerEvidence: Array<{ scanner: string; title: string; evidenceDetail?: string; rawEvidence?: string; corroborationTier: string; timestamp: number }> = [];

  // Add canonical finding's evidence
  scannerEvidence.push({
    scanner,
    title: finding.title,
    evidenceDetail: finding.evidence?.data?.raw as string || finding.description || undefined,
    rawEvidence: evidence || undefined,
    corroborationTier: finding.confidence >= 90 ? "confirmed" : finding.confidence >= 70 ? "corroborated" : "tentative",
    timestamp: finding.foundAt || Date.now(),
  });

  // Add evidence from all merged (duplicate) findings
  if (mergedFindings && mergedFindings.length > 0) {
    for (const mf of mergedFindings) {
      const mfSource = ((mf as any).source || "unknown").replace(/^orchestrator-/, "") || "unknown";
      scannerEvidence.push({
        scanner: mfSource,
        title: mf.title,
        evidenceDetail: mf.evidence?.data?.raw as string || mf.description || undefined,
        rawEvidence: mf.evidence?.data ? JSON.stringify(mf.evidence.data) : undefined,
        corroborationTier: mf.confidence >= 90 ? "confirmed" : mf.confidence >= 70 ? "corroborated" : "tentative",
        timestamp: mf.foundAt || Date.now(),
      });
    }
  }

  // Determine corroboration tier based on scanner count
  let corroborationTier: string;
  if (finding.confidence >= 90 || scannerEvidence.length >= 3) {
    corroborationTier = "confirmed";
  } else if (finding.confidence >= 70 || scannerEvidence.length >= 2) {
    corroborationTier = "corroborated";
  } else {
    corroborationTier = "tentative";
  }

  // Build combined evidenceDetail from all scanners
  const combinedEvidenceDetail = scannerEvidence
    .filter(e => e.evidenceDetail)
    .map(e => `[${e.scanner}] ${e.evidenceDetail}`)
    .join(' | ');

  return {
    id: finding.id,
    severity: finding.severity,
    title,
    cve: finding.cves?.[0],
    cwe,
    description,
    evidence,
    source: scanner,
    corroborationTier,
    evidenceDetail: combinedEvidenceDetail || finding.evidence?.data?.raw as string || finding.description,
    scannerEvidence,
  };
}

/**
 * Infer asset environment from the orchestrator asset's type, ports, and tool results.
 */
function inferAssetEnvironment(asset: OrchestratorAsset): AssetEnvironment {
  const services = asset.ports.map(p => p.service?.toLowerCase() || "");
  const toolNames = (asset.toolResults || []).map(t => t.tool?.toLowerCase() || "");
  const allText = [
    ...services,
    ...toolNames,
    ...asset.vulns.map(v => v.title.toLowerCase()),
    asset.hostname.toLowerCase(),
  ].join(" ");

  // Cloud indicators
  if (
    allText.includes("aws") || allText.includes("azure") || allText.includes("gcp") ||
    allText.includes("cloud") || allText.includes("s3") || allText.includes("lambda") ||
    asset.hostname.includes("amazonaws.com") || asset.hostname.includes("azure") ||
    asset.hostname.includes("cloudfront") || asset.hostname.includes("appspot")
  ) {
    return "cloud";
  }

  // IoT indicators
  if (
    allText.includes("mqtt") || allText.includes("coap") || allText.includes("upnp") ||
    allText.includes("zigbee") || allText.includes("ble") || allText.includes("iot") ||
    services.includes("mqtt") || services.includes("coap")
  ) {
    return "iot";
  }

  // ICS/OT indicators
  if (
    allText.includes("modbus") || allText.includes("dnp3") || allText.includes("bacnet") ||
    allText.includes("scada") || allText.includes("plc") || allText.includes("ics") ||
    allText.includes("opc") || allText.includes("ethernetip") ||
    services.includes("modbus") || services.includes("dnp3") || services.includes("bacnet")
  ) {
    return "ics_ot";
  }

  // Container indicators
  if (
    allText.includes("docker") || allText.includes("kubernetes") || allText.includes("k8s") ||
    allText.includes("container") || allText.includes("etcd") || allText.includes("kubelet") ||
    services.includes("docker") || services.includes("etcd")
  ) {
    return "container";
  }

  return "traditional";
}

// ─── False Positive Reduction & Server-Wide Consolidation ────────────────

/**
 * Server-wide findings that should be reported ONCE per host, not per-URL.
 * These are configuration-level issues that apply to the entire server.
 */
const SERVER_WIDE_ALERTS = new Set([
  'Content Security Policy (CSP) Header Not Set',
  'Missing Anti-clickjacking Header',
  'X-Content-Type-Options Header Missing',
  'Server Leaks Version Information via "Server" HTTP Response Header Field',
  'Strict-Transport-Security Header Not Set',
  'X-Frame-Options Header Not Set',
  'HTTP Only Site',
  'Cookie No HttpOnly Flag',
  'Cookie without SameSite Attribute',
  'Permissions Policy Header Not Set',
  'Cross-Domain Misconfiguration',
]);

/**
 * ZAP alerts that are known false positives when triggered on specific patterns.
 * Each entry defines the alert name and a condition under which it's a false positive.
 */
interface FPRule {
  alert: string;
  condition: (finding: { alert: string; risk: string; url: string; cweId?: number }) => boolean;
  reclassifyTo: 'info' | 'false_positive';
  reason: string;
}

const FALSE_POSITIVE_RULES: FPRule[] = [
  {
    // Apache mod_dir trailing-slash redirects misclassified as External Redirect
    alert: 'External Redirect',
    condition: (f) => {
      // If URL is a directory path (no extension, no query) it's likely a slash redirect
      try {
        const url = new URL(f.url, 'http://placeholder');
        const path = url.pathname;
        // Directory paths: no file extension in the last segment
        const lastSegment = path.split('/').filter(Boolean).pop() || '';
        return !lastSegment.includes('.') && !url.search;
      } catch { return false; }
    },
    reclassifyTo: 'info',
    reason: 'Apache mod_dir trailing-slash redirect (not exploitable open redirect)',
  },
  {
    // Path Traversal on non-injectable headers (Origin, Referer)
    alert: 'Path Traversal',
    condition: (f) => {
      // ZAP reports path traversal on Origin/Referer headers which don't affect file system
      // We detect this by checking if the URL is a login page and the param context suggests header injection
      return true; // All ZAP path traversal findings need manual verification - downgrade to tentative
    },
    reclassifyTo: 'info',
    reason: 'ZAP path traversal on HTTP headers (Origin/Referer) - not confirmed file system access',
  },
];

/**
 * Training lab applications where findings are "expected" rather than "discovered".
 * Findings on these are still reported but with adjusted confidence/tier.
 */
const TRAINING_LAB_APPS = [
  'dvwa', 'damn vulnerable', 'juiceshop', 'juice-shop', 'bwapp',
  'altoro', 'hackazon', 'testphp', 'webgoat', 'mutillidae',
  'bodgeit', 'gruyere', 'brokencrystals', 'broken-crystals',
];

/**
 * Pre-process ZAP findings before dedup:
 * 1. Collapse server-wide findings to 1 per alert type per host
 * 2. Apply false positive rules (reclassify or filter)
 * 3. Adjust confidence for training lab targets
 *
 * This runs BEFORE the ScanForge dedup engine to reduce noise at the source.
 */
export function preProcessZapFindings(
  asset: OrchestratorAsset,
  isTrainingLab: boolean = false,
): { processedZapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>; fpStats: { collapsed: number; reclassified: number; total: number } } {
  const zapFindings = asset.zapFindings || [];
  const stats = { collapsed: 0, reclassified: 0, total: zapFindings.length };

  if (zapFindings.length === 0) return { processedZapFindings: [], fpStats: stats };

  const processed: Array<{ alert: string; risk: string; url: string; cweId?: number }> = [];
  const seenServerWide = new Set<string>();

  for (const finding of zapFindings) {
    // 1. Server-wide consolidation: keep only first instance per alert type
    if (SERVER_WIDE_ALERTS.has(finding.alert)) {
      if (seenServerWide.has(finding.alert)) {
        stats.collapsed++;
        continue; // Skip duplicate server-wide finding
      }
      seenServerWide.add(finding.alert);
    }

    // 2. Apply false positive rules
    let reclassified = false;
    for (const rule of FALSE_POSITIVE_RULES) {
      if (finding.alert === rule.alert && rule.condition(finding)) {
        if (rule.reclassifyTo === 'false_positive') {
          stats.reclassified++;
          reclassified = true;
          break; // Drop entirely
        } else if (rule.reclassifyTo === 'info') {
          // Downgrade to info severity
          processed.push({ ...finding, risk: 'info' });
          stats.reclassified++;
          reclassified = true;
          break;
        }
      }
    }
    if (reclassified) continue;

    // 3. Keep the finding as-is
    processed.push(finding);
  }

  return { processedZapFindings: processed, fpStats: stats };
}

/**
 * Pre-process asset.vulns to collapse server-wide findings and apply FP rules.
 * Similar to preProcessZapFindings but operates on the vulns array.
 */
export function preProcessVulns(
  asset: OrchestratorAsset,
  isTrainingLab: boolean = false,
): { processedVulns: OrchestratorVuln[]; fpStats: { collapsed: number; reclassified: number; total: number } } {
  const vulns = asset.vulns || [];
  const stats = { collapsed: 0, reclassified: 0, total: vulns.length };

  if (vulns.length === 0) return { processedVulns: [], fpStats: stats };

  const processed: OrchestratorVuln[] = [];
  const seenServerWide = new Set<string>();

  for (const vuln of vulns) {
    // Extract alert name from title (strip [source] prefix)
    const alertName = vuln.title.replace(/^\[[^\]]+\]\s*/, '');

    // 1. Server-wide consolidation
    if (SERVER_WIDE_ALERTS.has(alertName)) {
      if (seenServerWide.has(alertName)) {
        stats.collapsed++;
        continue;
      }
      seenServerWide.add(alertName);
    }

    // 2. Apply FP rules based on title matching
    let reclassified = false;

    // External Redirect on directory paths
    if (alertName === 'External Redirect' && vuln.evidenceDetail) {
      const urlMatch = vuln.evidenceDetail.match(/https?:\/\/[^\s]+/);
      if (urlMatch) {
        try {
          const url = new URL(urlMatch[0]);
          const lastSegment = url.pathname.split('/').filter(Boolean).pop() || '';
          if (!lastSegment.includes('.') && !url.search) {
            // Directory path redirect — downgrade to info
            processed.push({ ...vuln, severity: 'info', corroborationTier: 'tentative' });
            stats.reclassified++;
            reclassified = true;
          }
        } catch {}
      }
    }

    // Path Traversal on Origin/Referer headers
    if (!reclassified && alertName === 'Path Traversal' && vuln.evidenceDetail) {
      const paramMatch = vuln.evidenceDetail.match(/Param:\s*(\w+)/i);
      if (paramMatch) {
        const param = paramMatch[1].toLowerCase();
        if (['origin', 'referer', 'host', 'x-forwarded-for', 'x-forwarded-host'].includes(param)) {
          // Header-based path traversal — not exploitable for file access
          processed.push({ ...vuln, severity: 'info', corroborationTier: 'tentative' });
          stats.reclassified++;
          reclassified = true;
        }
      }
    }

    // 3. Training lab context adjustment
    if (!reclassified && isTrainingLab) {
      // Mark findings on known training labs as "expected" rather than "discovered"
      processed.push({
        ...vuln,
        corroborationTier: vuln.corroborationTier === 'confirmed' ? 'corroborated' : vuln.corroborationTier,
        // Add training lab context flag
        ...(!(vuln as any).trainingLabExpected && { trainingLabExpected: true }),
      } as any);
      reclassified = true;
    }

    if (!reclassified) {
      processed.push(vuln);
    }
  }

  return { processedVulns: processed, fpStats: stats };
}

/**
 * Detect if an asset is a known training lab application.
 */
export function isTrainingLabAsset(asset: OrchestratorAsset): boolean {
  const hostLower = asset.hostname.toLowerCase();
  const vulnText = asset.vulns.map(v => v.title + ' ' + (v.evidenceDetail || '')).join(' ').toLowerCase();
  const zapText = (asset.zapFindings || []).map(z => z.url).join(' ').toLowerCase();
  const allText = `${hostLower} ${vulnText} ${zapText}`;

  return TRAINING_LAB_APPS.some(lab => allText.includes(lab));
}

// ─── Main Integration Functions ──────────────────────────────────────────

/**
 * Run deduplication and normalization across all assets in the engagement.
 *
 * This is called at the end of the vuln detection phase, before exploitation begins.
 * It:
 *   1. Pre-processes findings (server-wide consolidation, FP reduction, context-awareness)
 *   2. Collects all vulns + ZAP findings from all assets
 *   3. Converts them to ScanFinding format
 *   4. Runs dedup engine per asset
 *   5. Runs normalization on the deduplicated set
 *   6. Writes back the deduplicated vulns to each asset
 *   7. Returns stats for the UI
 */
export async function runEngagementDedup(assets: OrchestratorAsset[]): Promise<DedupStats> {
  const dedup = getDeduplicationEngine();
  const normalizer = getNormalizationEngine();

  let totalBefore = 0;
  let totalAfter = 0;
  let totalDuplicates = 0;
  let totalSeverityChanges = 0;
  const duplicatesByAsset: Record<string, number> = {};
  const allMergeLog: DedupStats["mergeLog"] = [];

  // ── Pre-processing: FP reduction, server-wide consolidation, context-awareness ──
  let totalFpCollapsed = 0;
  let totalFpReclassified = 0;

  for (const asset of assets) {
    const isLab = isTrainingLabAsset(asset);

    // Pre-process vulns (collapse server-wide, reclassify FPs)
    const { processedVulns, fpStats: vulnFpStats } = preProcessVulns(asset, isLab);
    asset.vulns = processedVulns;
    totalFpCollapsed += vulnFpStats.collapsed;
    totalFpReclassified += vulnFpStats.reclassified;

    // Pre-process ZAP findings (collapse server-wide, reclassify FPs)
    const { processedZapFindings, fpStats: zapFpStats } = preProcessZapFindings(asset, isLab);
    asset.zapFindings = processedZapFindings;
    totalFpCollapsed += zapFpStats.collapsed;
    totalFpReclassified += zapFpStats.reclassified;
  }

  console.log(`[DedupBridge] FP pre-processing: ${totalFpCollapsed} server-wide duplicates collapsed, ${totalFpReclassified} findings reclassified`);

  for (const asset of assets) {
    // Collect all findings for this asset
    const allFindings: ScanFinding[] = [];

    // Convert vulns
    for (const vuln of asset.vulns) {
      allFindings.push(vulnToScanFinding(vuln, asset));
    }

    // Convert ZAP findings (already pre-processed)
    if (asset.zapFindings) {
      for (const zap of asset.zapFindings) {
        allFindings.push(zapFindingToScanFinding(zap, asset));
      }
    }

    // NOTE: toolResults.findings are SKIPPED here — they are already present in asset.vulns
    // (the orchestrator pushes findings to both toolResults AND asset.vulns during scanning).
    // Including them here caused double-counting: the dedup engine would create new ScanFinding
    // objects with port=0 and slightly different metadata, preventing proper deduplication.

    totalBefore += allFindings.length;

    if (allFindings.length === 0) continue;

    // Run dedup
    const dedupResult = dedup.deduplicate(allFindings);
    const dupsRemoved = dedupResult.duplicatesRemoved;
    duplicatesByAsset[asset.hostname] = dupsRemoved;
    totalDuplicates += dupsRemoved;

    // Run normalization on deduplicated findings
    const normResult = normalizer.normalize(dedupResult.findings);
    totalSeverityChanges += normResult.log.filter(e => e.field === "severity").length;

    // Build a map of canonical ID → merged findings for evidence preservation
    const mergedFindingsMap = new Map<string, ScanFinding[]>();
    for (const entry of dedupResult.mergeLog) {
      const mergedFindings = entry.mergedIds
        .map(id => allFindings.find(af => af.id === id))
        .filter(Boolean) as ScanFinding[];
      mergedFindingsMap.set(entry.canonicalId, mergedFindings);
    }

    // Write back deduplicated vulns to the asset, preserving ALL scanner evidence
    const dedupedVulns = normResult.findings.map(f => {
      const merged = mergedFindingsMap.get(f.id);
      return scanFindingToVuln(f, merged);
    });
    asset.vulns = dedupedVulns;
    // Clear zapFindings — they are now merged into the deduplicated vulns array.
    // Without this, the UI double-counts them (vulns.length + zapFindings.length).
    asset.zapFindings = [];
    totalAfter += dedupedVulns.length;

    // Build merge log for UI
    for (const entry of dedupResult.mergeLog) {
      // MergeEntry has canonicalId and mergedIds, not canonical/duplicates objects
      // We need to find the canonical finding from the deduplicated results
      const canonicalFinding = dedupResult.findings.find(f => f.id === entry.canonicalId);
      const canonicalTitle = canonicalFinding?.title || entry.canonicalId;

      allMergeLog.push({
        canonicalTitle,
        mergedCount: entry.mergedIds.length + 1,
        sources: [entry.canonicalId, ...entry.mergedIds]
          .map(id => {
            const f = allFindings.find(af => af.id === id);
            return (f as any)?.source?.replace(/^orchestrator-/, "") || "unknown";
          })
          .filter((v, i, a) => a.indexOf(v) === i), // unique sources
      });
    }
  }

  // ── NVD CVE-to-CWE Resolution ──
  // Collect all CVE IDs from findings that lack CWE data
  const cveIdsToResolve: string[] = [];
  const vulnCveMap: Array<{ vulnId: string; cve: string }> = [];

  for (const asset of assets) {
    for (const vuln of asset.vulns) {
      if (vuln.cve) {
        const cweMatch = vuln.title.match(/CWE-(\d+)/gi);
        if (!cweMatch || cweMatch.length === 0) {
          cveIdsToResolve.push(vuln.cve);
          vulnCveMap.push({ vulnId: vuln.id, cve: vuln.cve });
        }
      }
    }
  }

  // Resolve CVEs to CWEs via NVD API (with caching + rate limiting)
  let cveToCweMap = new Map<string, string[]>();
  if (cveIdsToResolve.length > 0) {
    try {
      cveToCweMap = await resolveCvesToCwes(cveIdsToResolve);
    } catch (err) {
      // Graceful degradation — continue without NVD data
      console.warn("[DedupBridge] NVD CVE-to-CWE resolution failed:", err);
    }
  }

  // ── NIST/MITRE/CWE Enrichment ──
  // Enrich all deduplicated findings with compliance mappings
  const allDedupedFindings: Array<{ id: string; cwes?: string[]; techniqueIds?: string[]; severity?: string; title?: string; category?: string }> = [];
  const findingEnrichments: Record<string, FindingEnrichment> = {};

  for (const asset of assets) {
    for (const vuln of asset.vulns) {
      // Extract CWEs from the vuln title
      const cweMatch = vuln.title.match(/CWE-(\d+)/gi);
      const cwes = cweMatch ? cweMatch.map(m => m.toUpperCase()) : [];

      // Merge in NVD-resolved CWEs for findings that have CVEs but no CWEs
      if (vuln.cve && cwes.length === 0) {
        const nvdCwes = cveToCweMap.get(vuln.cve.toUpperCase());
        if (nvdCwes) {
          cwes.push(...nvdCwes);
        }
      }

      const findingInput = {
        cwes,
        techniqueIds: [],
        severity: vuln.severity,
        title: vuln.title,
        category: undefined,
      };

      allDedupedFindings.push({ id: vuln.id, ...findingInput });

      // Enrich each finding
      const enrichment = enrichWithNistMitre(findingInput);
      findingEnrichments[vuln.id] = enrichment;
    }
  }

  // Build compliance enrichment summary
  const nistGapSummary = generateNistGapSummary(allDedupedFindings);
  const impactedFamilies = getImpactedNistFamilies(allDedupedFindings);

  // Aggregate MITRE techniques by tactic
  const mitreTechniquesByTactic: Record<string, Array<{ techniqueId: string; techniqueName: string }>> = {};
  const allMitreSet = new Map<string, MitreTechnique>();
  const allCweSet = new Map<string, CweEntry>();

  for (const enrichment of Object.values(findingEnrichments)) {
    for (const tech of enrichment.mitreTechniques) {
      allMitreSet.set(tech.techniqueId, tech);
      if (!mitreTechniquesByTactic[tech.tactic]) {
        mitreTechniquesByTactic[tech.tactic] = [];
      }
      if (!mitreTechniquesByTactic[tech.tactic].some(t => t.techniqueId === tech.techniqueId)) {
        mitreTechniquesByTactic[tech.tactic].push({ techniqueId: tech.techniqueId, techniqueName: tech.techniqueName });
      }
    }
    for (const cwe of enrichment.cwes) {
      allCweSet.set(cwe.cweId, cwe);
    }
  }

  // Group CWEs by category
  const cwesByCategory: Record<string, CweEntry[]> = {};
  for (const cwe of allCweSet.values()) {
    if (!cwesByCategory[cwe.category]) {
      cwesByCategory[cwe.category] = [];
    }
    cwesByCategory[cwe.category].push(cwe);
  }

  const complianceEnrichment: ComplianceEnrichmentSummary = {
    totalNistControlsImpacted: nistGapSummary.totalControlsImpacted,
    impactedNistFamilies: impactedFamilies,
    totalMitreTechniques: allMitreSet.size,
    mitreTechniquesByTactic,
    totalCwes: allCweSet.size,
    cwesByCategory,
    nistGapSummary,
    findingEnrichments,
  };

  return {
    totalFindingsBeforeDedup: totalBefore,
    totalFindingsAfterDedup: totalAfter,
    duplicatesRemoved: totalDuplicates,
    duplicatesByAsset,
    mergeLog: allMergeLog,
    normalizedSeverityChanges: totalSeverityChanges,
    processedAt: Date.now(),
    complianceEnrichment,
  };
}

/**
 * Run coverage gap analysis across all assets in the engagement.
 *
 * This is called after dedup, before exploitation begins.
 * It analyzes each asset's port/service profile against the expected
 * coverage matrix for its environment type.
 */
export function runEngagementCoverageAnalysis(assets: OrchestratorAsset[]): EngagementCoverageReport {
  const detector = getCoverageGapDetector();
  const assetReports: EngagementCoverageReport["assetReports"] = [];
  let totalGaps = 0;
  let criticalGaps = 0;
  const allRecommendations: string[] = [];

  for (const asset of assets) {
    // Build ScanTarget from orchestrator asset
    // ScanTarget expects: value (string), type, ports, services
    const target: ScanTarget = {
      value: asset.hostname,
      type: asset.hostname.match(/^\d+\.\d+\.\d+\.\d+$/) ? "ip" : "domain",
      ports: asset.ports.map(p => p.port),
      services: Object.fromEntries(asset.ports.map(p => [p.port, p.service])),
    };

    // Build minimal ScanConfig
    const config: ScanConfig = {
      maxConcurrency: 5,
      timeoutSeconds: 300,
    };

    // ── Tool-to-Protocol Mapping ──────────────────────────────────────────
    // The coverage detector expects protocol names (http, https, ssh, dns, etc.)
    // but the orchestrator records tool names (naabu, nuclei, httpx, etc.).
    // Map tool execution to the protocols they cover.
    const TOOL_TO_PROTOCOLS: Record<string, string[]> = {
      httpx: ["http", "https"],
      nuclei: ["http", "https"],
      naabu: [],  // port scanner — protocols inferred from discovered services
      masscan: [],
      rustscan: [],
      nerva: ["http", "https", "ssh", "dns", "smtp", "ftp"],
      zap: ["http", "https"],
      nikto: ["http", "https"],
      sqlmap: ["http", "https"],
      hydra: ["ssh", "ftp", "http", "https"],
      dig: ["dns"],
      dnsrecon: ["dns"],
      subfinder: ["dns"],
      amass: ["dns"],
      curl: ["http", "https"],
      wpscan: ["http", "https"],
      gobuster: ["http", "https"],
      dirb: ["http", "https"],
      ffuf: ["http", "https"],
      testssl: ["https"],
      sslscan: ["https"],
      msfconsole: ["http", "https", "ssh", "ftp", "smtp"],
    };

    // ── Tool-to-Tag Mapping ───────────────────────────────────────────────
    // Map tool execution to the template tags they satisfy.
    const TOOL_TO_TAGS: Record<string, string[]> = {
      nuclei: ["cve", "exposure", "misconfig", "owasp-top10"],
      zap: ["owasp-top10", "exposure", "misconfig"],
      nikto: ["exposure", "misconfig"],
      httpx: ["exposure"],
      hydra: ["credentials"],
      sqlmap: ["owasp-top10"],
      wpscan: ["cve", "exposure", "credentials"],
      dig: ["dns", "zone-transfer"],
      dnsrecon: ["dns", "dnssec", "zone-transfer"],
      naabu: ["exposure"],
      nerva: ["exposure"],
      testssl: ["misconfig"],
      sslscan: ["misconfig"],
      gobuster: ["exposure"],
      dirb: ["exposure"],
      ffuf: ["exposure"],
      msfconsole: ["cve", "owasp-top10"],
    };

    // Build protocol set from tool execution + discovered services
    const protocolsFromTools = new Set<string>();
    const tagsFromTools = new Set<string>();
    const completedTools = (asset.toolResults || []).filter(tr => tr.exitCode === 0 && !tr.timedOut);
    for (const tr of completedTools) {
      const toolName = tr.tool.toLowerCase();
      const protocols = TOOL_TO_PROTOCOLS[toolName];
      if (protocols) protocols.forEach(p => protocolsFromTools.add(p));
      const tags = TOOL_TO_TAGS[toolName];
      if (tags) tags.forEach(t => tagsFromTools.add(t));
    }
    // Also infer protocols from discovered port services
    for (const p of asset.ports) {
      const svc = (p.service || "").toLowerCase();
      if (svc === "http" || svc === "https" || svc === "ssh" || svc === "dns" ||
          svc === "smtp" || svc === "ftp" || svc === "smb" || svc === "mysql" ||
          svc === "postgresql" || svc === "redis" || svc === "mongodb") {
        protocolsFromTools.add(svc);
      }
    }

    // Build ScannerResult array using protocol names for the coverage detector
    const scannersRun: ScannerResult[] = [];
    // Add one entry per inferred protocol (the detector checks protocolsScanned.has("http") etc.)
    for (const proto of protocolsFromTools) {
      scannersRun.push({
        scanner: proto,
        status: "completed" as ScannerResult["status"],
        durationMs: 0,
        findingCount: 0,
      });
    }
    // Also add original tool entries for tool-level tracking
    for (const tr of (asset.toolResults || [])) {
      scannersRun.push({
        scanner: tr.tool,
        status: (tr.timedOut ? "timeout" : tr.exitCode === 0 ? "completed" : "failed") as ScannerResult["status"],
        durationMs: tr.durationMs,
        findingCount: tr.findingCount,
        error: tr.exitCode !== 0 && !tr.timedOut ? `Exit code ${tr.exitCode}` : undefined,
      });
    }

    // Get templates executed — include both tool names AND inferred tags
    const templatesExecuted = [
      ...(asset.toolResults || []).map(tr => tr.tool),
      ...Array.from(tagsFromTools),
    ];

    // Infer asset classification
    const environment = inferAssetEnvironment(asset);
    const classification: AssetClassification = {
      environment,
      assetType: asset.type as any || "server",
      protocols: [...protocolsFromTools],
      technologies: [],
      complianceScope: [],
    };

    // Build synthetic ScanTemplate objects from inferred tags so the coverage
    // detector's tag-matching loop can find them. Each inferred tag becomes a
    // synthetic template whose id matches an entry in templatesExecuted.
    const syntheticTemplates: ScanTemplate[] = Array.from(tagsFromTools).map(tag => ({
      id: tag,
      name: `Inferred: ${tag}`,
      description: `Synthetic template for coverage tracking — inferred from tool execution`,
      author: "bridge",
      severity: "info" as any,
      tags: [tag],
      protocol: "http",
      matchers: [],
    }));

    // Run coverage analysis
    const report = detector.analyze(
      target,
      config,
      scannersRun,
      templatesExecuted,
      syntheticTemplates, // synthetic templates so tag matching works
      classification
    );

    // Map CoverageGap to the UI format
    // CoverageGap has: recommendedTemplateIds, recommendedProtocols (not missingChecks)
    // Enrich each gap with related NIST controls and MITRE techniques
    const assetGaps = report.gaps.map(g => {
      // Use the gap category/description to infer related NIST/MITRE mappings
      const gapEnrichment = enrichWithNistMitre({
        title: `${g.category}: ${g.description}`,
        category: g.category,
        severity: g.severity,
      });

      return {
        category: g.category,
        description: g.description,
        severity: g.severity,
        recommendation: g.recommendation,
        missingChecks: [
          ...g.recommendedTemplateIds,
          ...g.recommendedProtocols,
        ],
        relatedNistControls: gapEnrichment.nistControls.map(c => c.controlId),
        relatedMitreTechniques: gapEnrichment.mitreTechniques.map(t => t.techniqueId),
      };
    });

    const assetCritical = assetGaps.filter(g => g.severity === "critical" || g.severity === "high").length;

    assetReports.push({
      hostname: asset.hostname,
      score: report.coveragePercent, // CoverageReport uses coveragePercent, not score
      gaps: assetGaps,
      totalGaps: assetGaps.length,
      criticalGaps: assetCritical,
    });

    totalGaps += assetGaps.length;
    criticalGaps += assetCritical;

    // Collect unique recommendations
    for (const g of assetGaps) {
      if (g.recommendation && !allRecommendations.includes(g.recommendation)) {
        allRecommendations.push(g.recommendation);
      }
    }
  }

  // Calculate overall score (weighted average by asset vuln count)
  const totalScore = assetReports.length > 0
    ? Math.round(assetReports.reduce((sum, r) => sum + r.score, 0) / assetReports.length)
    : 100;

  return {
    overallScore: totalScore,
    assetReports,
    totalGaps,
    criticalGaps,
    recommendations: allRecommendations.slice(0, 20), // Top 20 recommendations
    processedAt: Date.now(),
  };
}
