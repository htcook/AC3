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
 */
function scanFindingToVuln(finding: ScanFinding): OrchestratorVuln {
  // Reconstruct the scanner prefix from source field
  const sourceStr = (finding as any).source || "unknown";
  const scanner = sourceStr.replace(/^orchestrator-/, "") || "unknown";
  const title = `[${scanner}] ${finding.title}`;

  return {
    id: finding.id,
    severity: finding.severity,
    title,
    cve: finding.cves?.[0],
    corroborationTier: finding.confidence >= 90 ? "confirmed" : finding.confidence >= 70 ? "corroborated" : "tentative",
    evidenceDetail: finding.evidence?.data?.raw as string || finding.description,
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

// ─── Main Integration Functions ──────────────────────────────────────────

/**
 * Run deduplication and normalization across all assets in the engagement.
 *
 * This is called at the end of the vuln detection phase, before exploitation begins.
 * It:
 *   1. Collects all vulns + ZAP findings from all assets
 *   2. Converts them to ScanFinding format
 *   3. Runs dedup engine per asset
 *   4. Runs normalization on the deduplicated set
 *   5. Writes back the deduplicated vulns to each asset
 *   6. Returns stats for the UI
 */
export function runEngagementDedup(assets: OrchestratorAsset[]): DedupStats {
  const dedup = getDeduplicationEngine();
  const normalizer = getNormalizationEngine();

  let totalBefore = 0;
  let totalAfter = 0;
  let totalDuplicates = 0;
  let totalSeverityChanges = 0;
  const duplicatesByAsset: Record<string, number> = {};
  const allMergeLog: DedupStats["mergeLog"] = [];

  for (const asset of assets) {
    // Collect all findings for this asset
    const allFindings: ScanFinding[] = [];

    // Convert vulns
    for (const vuln of asset.vulns) {
      allFindings.push(vulnToScanFinding(vuln, asset));
    }

    // Convert ZAP findings
    if (asset.zapFindings) {
      for (const zap of asset.zapFindings) {
        allFindings.push(zapFindingToScanFinding(zap, asset));
      }
    }

    // Convert tool result findings
    if (asset.toolResults) {
      for (const tr of asset.toolResults) {
        if (tr.findings) {
          for (const f of tr.findings) {
            allFindings.push({
              id: `tr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              source: `orchestrator-${tr.tool}`,
              title: f.title,
              description: `Finding from ${tr.tool}: ${f.title}`,
              severity: (f.severity as FindingSeverity) || "info",
              confidence: 70,
              target: asset.hostname,
              port: 0,
              protocol: "tcp",
              evidence: {
                data: { raw: tr.outputPreview?.slice(0, 500) || f.title },
              },
              cves: f.cve ? [f.cve] : [],
              cwes: [],
              references: [],
              remediation: "",
              foundAt: tr.executedAt || Date.now(),
            } as ScanFinding);
          }
        }
      }
    }

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

    // Write back deduplicated vulns to the asset
    const dedupedVulns = normResult.findings.map(scanFindingToVuln);
    asset.vulns = dedupedVulns;
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

  return {
    totalFindingsBeforeDedup: totalBefore,
    totalFindingsAfterDedup: totalAfter,
    duplicatesRemoved: totalDuplicates,
    duplicatesByAsset,
    mergeLog: allMergeLog,
    normalizedSeverityChanges: totalSeverityChanges,
    processedAt: Date.now(),
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

    // Build ScannerResult array from tool results
    const scannersRun: ScannerResult[] = (asset.toolResults || []).map(tr => ({
      scanner: tr.tool,
      status: (tr.timedOut ? "timeout" : tr.exitCode === 0 ? "completed" : "failed") as ScannerResult["status"],
      durationMs: tr.durationMs,
      findingCount: tr.findingCount,
      error: tr.exitCode !== 0 && !tr.timedOut ? `Exit code ${tr.exitCode}` : undefined,
    }));

    // Get templates executed (from tool names)
    const templatesExecuted = (asset.toolResults || []).map(tr => tr.tool);

    // Infer asset classification
    const environment = inferAssetEnvironment(asset);
    const classification: AssetClassification = {
      environment,
      assetType: asset.type as any || "server",
      protocols: asset.ports.map(p => p.service).filter(Boolean),
      technologies: [],
      complianceScope: [],
    };

    // Run coverage analysis
    const report = detector.analyze(
      target,
      config,
      scannersRun,
      templatesExecuted,
      [], // all templates — empty means detector uses its built-in expectations
      classification
    );

    // Map CoverageGap to the UI format
    // CoverageGap has: recommendedTemplateIds, recommendedProtocols (not missingChecks)
    const assetGaps = report.gaps.map(g => ({
      category: g.category,
      description: g.description,
      severity: g.severity,
      recommendation: g.recommendation,
      missingChecks: [
        ...g.recommendedTemplateIds,
        ...g.recommendedProtocols,
      ],
    }));

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
