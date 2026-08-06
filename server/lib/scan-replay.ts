/**
 * Scan Replay Module — P3 Gap Remediation
 * 
 * Enables operators to replay previous scan configurations against targets
 * to track remediation progress, verify fixes, and compare results over time.
 * 
 * Features:
 * - Snapshot scan configurations (ZAP, ScanForge, Nuclei profiles)
 * - Replay a saved config against the same or different target
 * - Diff engine to compare scan results across runs
 * - Remediation verification workflow
 * - Scheduled replay for continuous validation
 */

import crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScanEngine = "zap" | "scanforge-discovery" | "nuclei" | "caldera" | "custom";
export type ReplayStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type DiffSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanProfile {
  id: string;
  name: string;
  engine: ScanEngine;
  config: Record<string, any>;
  target: string;
  createdBy: string;
  createdAt: string;
  tags: string[];
}

export interface ScanResult {
  profileId: string;
  runId: string;
  engine: ScanEngine;
  target: string;
  startedAt: string;
  completedAt?: string;
  status: ReplayStatus;
  findingsCount: number;
  findings: ScanFinding[];
  rawOutput?: string;
  hashSha256: string;
}

export interface ScanFinding {
  id: string;
  title: string;
  severity: DiffSeverity;
  category: string;
  description: string;
  evidence: string;
  location: string;         // URL, host:port, or file path
  cweId?: string;
  cveId?: string;
  confidence: "high" | "medium" | "low";
  remediation?: string;
}

export interface ScanDiff {
  profileId: string;
  baselineRunId: string;
  comparisonRunId: string;
  generatedAt: string;
  summary: DiffSummary;
  newFindings: ScanFinding[];
  resolvedFindings: ScanFinding[];
  persistentFindings: ScanFinding[];
  regressions: ScanFinding[];    // Previously resolved, now reappeared
}

export interface DiffSummary {
  baselineTotal: number;
  comparisonTotal: number;
  newCount: number;
  resolvedCount: number;
  persistentCount: number;
  regressionCount: number;
  remediationRate: number;       // Percentage of resolved findings
  severityDelta: Record<DiffSeverity, { baseline: number; comparison: number; delta: number }>;
}

// ─── Scan Profile Builder ───────────────────────────────────────────────────

/**
 * Build a ZAP scan profile from common parameters.
 */
export function buildZapProfile(params: {
  name: string;
  target: string;
  scanType: "baseline" | "full" | "api" | "ajax";
  authConfig?: { loginUrl: string; username: string; password: string; usernameField: string; passwordField: string };
  excludeUrls?: string[];
  alertThreshold?: "low" | "medium" | "high";
  createdBy: string;
}): ScanProfile {
  return {
    id: `zap-${crypto.randomBytes(8).toString("hex")}`,
    name: params.name,
    engine: "zap",
    config: {
      scanType: params.scanType,
      target: params.target,
      authConfig: params.authConfig || null,
      excludeUrls: params.excludeUrls || [],
      alertThreshold: params.alertThreshold || "medium",
      maxDuration: params.scanType === "full" ? 3600 : 1800,
      ajaxSpider: params.scanType === "ajax",
      passiveScan: true,
      activeScan: params.scanType !== "baseline",
    },
    target: params.target,
    createdBy: params.createdBy,
    createdAt: new Date().toISOString(),
    tags: ["zap", params.scanType],
  };
}

/**
 * Build an ScanForge scan profile.
 */
export function buildScanForgeProfile(params: {
  name: string;
  target: string;
  scanType: "quick" | "full" | "stealth" | "vuln" | "service";
  ports?: string;
  scripts?: string[];
  timing?: number;   // 0-5
  createdBy: string;
}): ScanProfile {
  const portSpec = params.ports || (params.scanType === "quick" ? "--top-ports 1000" : "-p-");
  const timingFlag = params.timing !== undefined ? `-T${params.timing}` : (params.scanType === "stealth" ? "-T2" : "-T4");

  const flagMap: Record<string, string[]> = {
    quick: ["-sV", "-sC", portSpec, timingFlag],
    full: ["-sV", "-sC", "-O", "--traceroute", portSpec, timingFlag],
    stealth: ["-sS", "-Pn", portSpec, timingFlag, "--data-length", "24"],
    vuln: ["-sV", "--script=vuln", portSpec, timingFlag],
    service: ["-sV", "-sC", "--version-all", portSpec, timingFlag],
  };

  return {
    id: `discovery-${crypto.randomBytes(8).toString("hex")}`,
    name: params.name,
    engine: "scanforge-discovery",
    config: {
      scanType: params.scanType,
      target: params.target,
      flags: flagMap[params.scanType] || flagMap.quick,
      scripts: params.scripts || [],
      outputFormat: "xml",
    },
    target: params.target,
    createdBy: params.createdBy,
    createdAt: new Date().toISOString(),
    tags: ["scanforge-discovery", params.scanType],
  };
}

/**
 * Build a Nuclei scan profile.
 */
export function buildNucleiProfile(params: {
  name: string;
  target: string;
  templates?: string[];
  severity?: DiffSeverity[];
  tags?: string[];
  rateLimit?: number;
  createdBy: string;
}): ScanProfile {
  return {
    id: `nuclei-${crypto.randomBytes(8).toString("hex")}`,
    name: params.name,
    engine: "nuclei",
    config: {
      target: params.target,
      templates: params.templates || [],
      severity: params.severity || ["critical", "high", "medium"],
      tags: params.tags || [],
      rateLimit: params.rateLimit || 150,
      bulkSize: 25,
      concurrency: 10,
      timeout: 10,
      retries: 1,
    },
    target: params.target,
    createdBy: params.createdBy,
    createdAt: new Date().toISOString(),
    tags: ["nuclei", ...(params.tags || [])],
  };
}

// ─── Diff Engine ────────────────────────────────────────────────────────────

/**
 * Generate a finding fingerprint for comparison.
 * Uses title + severity + location + category to identify "same" finding.
 */
export function fingerprintFinding(finding: ScanFinding): string {
  const raw = `${finding.title}|${finding.severity}|${finding.location}|${finding.category}|${finding.cweId || ""}`;
  return crypto.createHash("sha256").update(raw).digest("hex").substring(0, 16);
}

/**
 * Compare two scan results and produce a diff report.
 */
export function diffScanResults(baseline: ScanResult, comparison: ScanResult): ScanDiff {
  const baselineFingerprints = new Map<string, ScanFinding>();
  for (const f of baseline.findings) {
    baselineFingerprints.set(fingerprintFinding(f), f);
  }

  const comparisonFingerprints = new Map<string, ScanFinding>();
  for (const f of comparison.findings) {
    comparisonFingerprints.set(fingerprintFinding(f), f);
  }

  const newFindings: ScanFinding[] = [];
  const resolvedFindings: ScanFinding[] = [];
  const persistentFindings: ScanFinding[] = [];

  // Find new and persistent findings
  for (const [fp, finding] of comparisonFingerprints) {
    if (baselineFingerprints.has(fp)) {
      persistentFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }

  // Find resolved findings
  for (const [fp, finding] of baselineFingerprints) {
    if (!comparisonFingerprints.has(fp)) {
      resolvedFindings.push(finding);
    }
  }

  // Build severity delta
  const severities: DiffSeverity[] = ["critical", "high", "medium", "low", "info"];
  const severityDelta: Record<DiffSeverity, { baseline: number; comparison: number; delta: number }> = {} as any;
  for (const sev of severities) {
    const bCount = baseline.findings.filter(f => f.severity === sev).length;
    const cCount = comparison.findings.filter(f => f.severity === sev).length;
    severityDelta[sev] = { baseline: bCount, comparison: cCount, delta: cCount - bCount };
  }

  const remediationRate = baseline.findings.length > 0
    ? Math.round((resolvedFindings.length / baseline.findings.length) * 100)
    : 0;

  return {
    profileId: baseline.profileId,
    baselineRunId: baseline.runId,
    comparisonRunId: comparison.runId,
    generatedAt: new Date().toISOString(),
    summary: {
      baselineTotal: baseline.findingsCount,
      comparisonTotal: comparison.findingsCount,
      newCount: newFindings.length,
      resolvedCount: resolvedFindings.length,
      persistentCount: persistentFindings.length,
      regressionCount: 0,  // Would need historical data to detect
      remediationRate,
      severityDelta,
    },
    newFindings,
    resolvedFindings,
    persistentFindings,
    regressions: [],
  };
}

/**
 * Generate a human-readable diff summary.
 */
export function formatDiffSummary(diff: ScanDiff): string {
  const s = diff.summary;
  const lines: string[] = [
    `## Scan Replay Diff Report`,
    `Generated: ${diff.generatedAt}`,
    ``,
    `### Summary`,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Baseline Findings | ${s.baselineTotal} |`,
    `| Current Findings | ${s.comparisonTotal} |`,
    `| New Findings | ${s.newCount} |`,
    `| Resolved | ${s.resolvedCount} |`,
    `| Persistent | ${s.persistentCount} |`,
    `| Regressions | ${s.regressionCount} |`,
    `| **Remediation Rate** | **${s.remediationRate}%** |`,
    ``,
    `### Severity Delta`,
    `| Severity | Baseline | Current | Change |`,
    `|----------|----------|---------|--------|`,
  ];

  for (const [sev, data] of Object.entries(s.severityDelta)) {
    const arrow = data.delta > 0 ? "↑" : data.delta < 0 ? "↓" : "→";
    lines.push(`| ${sev} | ${data.baseline} | ${data.comparison} | ${arrow} ${Math.abs(data.delta)} |`);
  }

  if (diff.newFindings.length > 0) {
    lines.push(``, `### New Findings (${diff.newFindings.length})`);
    for (const f of diff.newFindings.slice(0, 10)) {
      lines.push(`- **[${f.severity.toUpperCase()}]** ${f.title} at \`${f.location}\``);
    }
  }

  if (diff.resolvedFindings.length > 0) {
    lines.push(``, `### Resolved Findings (${diff.resolvedFindings.length})`);
    for (const f of diff.resolvedFindings.slice(0, 10)) {
      lines.push(`- ~~[${f.severity.toUpperCase()}] ${f.title} at \`${f.location}\`~~`);
    }
  }

  return lines.join("\n");
}

/**
 * Calculate a remediation score based on diff results.
 * Returns 0-100 where 100 means all baseline findings are resolved.
 */
export function calculateRemediationScore(diff: ScanDiff): {
  score: number;
  grade: string;
  assessment: string;
} {
  const s = diff.summary;
  const score = s.remediationRate;

  let grade: string;
  let assessment: string;

  if (score >= 90) {
    grade = "A";
    assessment = "Excellent remediation progress. Nearly all findings from the baseline scan have been resolved.";
  } else if (score >= 75) {
    grade = "B";
    assessment = "Good remediation progress. Most findings have been addressed, but some remain.";
  } else if (score >= 50) {
    grade = "C";
    assessment = "Moderate remediation progress. About half of the findings have been resolved.";
  } else if (score >= 25) {
    grade = "D";
    assessment = "Limited remediation progress. Most findings from the baseline scan persist.";
  } else {
    grade = "F";
    assessment = "Minimal remediation progress. Very few findings have been resolved since the baseline.";
  }

  // Penalize for new findings
  if (s.newCount > 0) {
    assessment += ` Warning: ${s.newCount} new finding(s) discovered that were not in the baseline.`;
  }

  // Penalize for regressions
  if (s.regressionCount > 0) {
    assessment += ` Alert: ${s.regressionCount} previously resolved finding(s) have regressed.`;
  }

  return { score, grade, assessment };
}
