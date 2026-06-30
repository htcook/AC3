/**
 * Delta Comparison Engine — Detect Changes Between Scans
 *
 * Compares two sets of passive recon observations to produce a structured
 * diff showing what's new, what's gone, and what changed. This enables:
 *
 * - "What changed since last scan?" reporting
 * - Attack surface drift detection
 * - Regression monitoring (did a vuln come back?)
 * - Trend analysis over time
 *
 * Comparison is done at the observation level using assetId for matching,
 * with semantic grouping by category for the summary.
 */

import type { AssetObservation } from "./types";

// ─── Delta Types ───────────────────────────────────────────────────

export type DeltaStatus = "new" | "removed" | "changed" | "unchanged";

export interface ObservationDelta {
  /** The observation (current version for new/changed, previous for removed) */
  observation: AssetObservation;
  /** What happened to this observation */
  status: DeltaStatus;
  /** For "changed" status: what fields changed */
  changes?: FieldChange[];
  /** Risk implication of this change */
  riskImplication: "increased" | "decreased" | "neutral";
  /** Human-readable summary of the change */
  summary: string;
}

export interface FieldChange {
  field: string;
  previousValue: unknown;
  currentValue: unknown;
}

export interface DeltaCategorySummary {
  category: string;
  newCount: number;
  removedCount: number;
  changedCount: number;
  unchangedCount: number;
  riskDelta: "increased" | "decreased" | "neutral";
}

export interface DeltaReport {
  /** When the previous scan was run */
  previousScanDate: Date | null;
  /** When the current scan was run */
  currentScanDate: Date;
  /** Total observations in previous scan */
  previousTotal: number;
  /** Total observations in current scan */
  currentTotal: number;
  /** All individual observation deltas */
  deltas: ObservationDelta[];
  /** Summary by category */
  categorySummary: DeltaCategorySummary[];
  /** Overall risk trend */
  overallRiskTrend: "increasing" | "decreasing" | "stable";
  /** Key highlights for the executive summary */
  highlights: string[];
  /** Statistics */
  stats: {
    newObservations: number;
    removedObservations: number;
    changedObservations: number;
    unchangedObservations: number;
    newCriticalFindings: number;
    resolvedCriticalFindings: number;
    newSubdomains: number;
    removedSubdomains: number;
    newOpenPorts: number;
    closedPorts: number;
    newCredentialLeaks: number;
  };
}

// ─── Comparison Logic ──────────────────────────────────────────────

/**
 * Generate an asset ID for matching observations across scans.
 * Uses a combination of type + name + source for stable matching.
 */
function getMatchKey(obs: AssetObservation): string {
  const type = obs.assetType || "unknown";
  const name = (obs.name || "").toLowerCase().trim();
  const ip = obs.ip || "";
  // For port-based observations, include port in the key
  const portTag = obs.tags.find(t => t.startsWith("port:"));
  const port = portTag ? portTag.split(":")[1] : "";
  return `${type}|${name}|${ip}|${port}`;
}

/**
 * Compare two observations and return field-level changes.
 */
function diffObservations(prev: AssetObservation, curr: AssetObservation): FieldChange[] {
  const changes: FieldChange[] = [];

  // Compare risk score
  if (prev.riskScore !== curr.riskScore) {
    changes.push({ field: "riskScore", previousValue: prev.riskScore, currentValue: curr.riskScore });
  }

  // Compare tags (set difference)
  const prevTags = new Set(prev.tags);
  const currTags = new Set(curr.tags);
  const newTags = curr.tags.filter(t => !prevTags.has(t));
  const removedTags = prev.tags.filter(t => !currTags.has(t));
  if (newTags.length > 0 || removedTags.length > 0) {
    changes.push({ field: "tags", previousValue: prev.tags, currentValue: curr.tags });
  }

  // Compare key evidence fields
  const prevEvidence = prev.evidence || {};
  const currEvidence = curr.evidence || {};
  const evidenceKeys = new Set([...Object.keys(prevEvidence), ...Object.keys(currEvidence)]);
  for (const key of evidenceKeys) {
    const pv = JSON.stringify(prevEvidence[key]);
    const cv = JSON.stringify(currEvidence[key]);
    if (pv !== cv) {
      changes.push({ field: `evidence.${key}`, previousValue: prevEvidence[key], currentValue: currEvidence[key] });
    }
  }

  return changes;
}

/**
 * Determine the risk implication of a delta.
 */
function assessRiskImplication(delta: ObservationDelta): "increased" | "decreased" | "neutral" {
  const obs = delta.observation;
  const tags = obs.tags.join(" ").toLowerCase();

  if (delta.status === "new") {
    // New critical/high findings increase risk
    if (obs.riskScore && obs.riskScore >= 7) return "increased";
    if (tags.includes("critical") || tags.includes("high")) return "increased";
    if (tags.includes("breach") || tags.includes("credential") || tags.includes("vulnerability")) return "increased";
    if (obs.assetType === "subdomain" || obs.assetType === "open_port") return "increased";
    return "neutral";
  }

  if (delta.status === "removed") {
    // Removed critical findings decrease risk
    if (obs.riskScore && obs.riskScore >= 7) return "decreased";
    if (tags.includes("critical") || tags.includes("high")) return "decreased";
    if (tags.includes("breach") || tags.includes("vulnerability")) return "decreased";
    return "neutral";
  }

  if (delta.status === "changed" && delta.changes) {
    const riskChange = delta.changes.find(c => c.field === "riskScore");
    if (riskChange) {
      const prev = (riskChange.previousValue as number) || 0;
      const curr = (riskChange.currentValue as number) || 0;
      return curr > prev ? "increased" : curr < prev ? "decreased" : "neutral";
    }
  }

  return "neutral";
}

/**
 * Generate a human-readable summary for a delta.
 */
function summarizeDelta(delta: ObservationDelta): string {
  const obs = delta.observation;
  const name = obs.name || obs.ip || "unknown asset";

  switch (delta.status) {
    case "new":
      return `New ${obs.assetType || "observation"} discovered: ${name}`;
    case "removed":
      return `${obs.assetType || "Observation"} no longer detected: ${name}`;
    case "changed": {
      const changeFields = delta.changes?.map(c => c.field).join(", ") || "unknown fields";
      return `${obs.assetType || "Observation"} changed (${changeFields}): ${name}`;
    }
    case "unchanged":
      return `${obs.assetType || "Observation"} unchanged: ${name}`;
  }
}

// ─── Main Comparison Function ──────────────────────────────────────

/**
 * Compare two sets of recon observations and produce a structured delta report.
 *
 * @param previousObservations - Observations from the previous scan (empty array for first scan)
 * @param currentObservations - Observations from the current scan
 * @param previousScanDate - When the previous scan was run (null for first scan)
 */
export function compareReconResults(
  previousObservations: AssetObservation[],
  currentObservations: AssetObservation[],
  previousScanDate: Date | null = null,
): DeltaReport {
  const currentScanDate = new Date();

  // Build lookup maps by match key
  const prevMap = new Map<string, AssetObservation>();
  for (const obs of previousObservations) {
    const key = getMatchKey(obs);
    prevMap.set(key, obs);
  }

  const currMap = new Map<string, AssetObservation>();
  for (const obs of currentObservations) {
    const key = getMatchKey(obs);
    currMap.set(key, obs);
  }

  const deltas: ObservationDelta[] = [];

  // Find new and changed observations
  for (const [key, currObs] of currMap) {
    const prevObs = prevMap.get(key);

    if (!prevObs) {
      // New observation
      const delta: ObservationDelta = {
        observation: currObs,
        status: "new",
        riskImplication: "neutral",
        summary: "",
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    } else {
      // Existing — check for changes
      const changes = diffObservations(prevObs, currObs);
      const status: DeltaStatus = changes.length > 0 ? "changed" : "unchanged";
      const delta: ObservationDelta = {
        observation: currObs,
        status,
        changes: changes.length > 0 ? changes : undefined,
        riskImplication: "neutral",
        summary: "",
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    }
  }

  // Find removed observations
  for (const [key, prevObs] of prevMap) {
    if (!currMap.has(key)) {
      const delta: ObservationDelta = {
        observation: prevObs,
        status: "removed",
        riskImplication: "neutral",
        summary: "",
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    }
  }

  // Build category summary
  const categoryMap = new Map<string, DeltaCategorySummary>();
  for (const delta of deltas) {
    const category = delta.observation.assetType || "other";
    if (!categoryMap.has(category)) {
      categoryMap.set(category, {
        category,
        newCount: 0,
        removedCount: 0,
        changedCount: 0,
        unchangedCount: 0,
        riskDelta: "neutral",
      });
    }
    const summary = categoryMap.get(category)!;
    switch (delta.status) {
      case "new": summary.newCount++; break;
      case "removed": summary.removedCount++; break;
      case "changed": summary.changedCount++; break;
      case "unchanged": summary.unchangedCount++; break;
    }
  }

  // Determine risk delta per category
  for (const [, summary] of categoryMap) {
    if (summary.newCount > summary.removedCount) {
      summary.riskDelta = "increased";
    } else if (summary.removedCount > summary.newCount) {
      summary.riskDelta = "decreased";
    }
  }

  // Compute stats
  const stats = {
    newObservations: deltas.filter(d => d.status === "new").length,
    removedObservations: deltas.filter(d => d.status === "removed").length,
    changedObservations: deltas.filter(d => d.status === "changed").length,
    unchangedObservations: deltas.filter(d => d.status === "unchanged").length,
    newCriticalFindings: deltas.filter(d => d.status === "new" && d.riskImplication === "increased" &&
      (d.observation.riskScore || 0) >= 8).length,
    resolvedCriticalFindings: deltas.filter(d => d.status === "removed" && d.riskImplication === "decreased" &&
      (d.observation.riskScore || 0) >= 8).length,
    newSubdomains: deltas.filter(d => d.status === "new" && d.observation.assetType === "subdomain").length,
    removedSubdomains: deltas.filter(d => d.status === "removed" && d.observation.assetType === "subdomain").length,
    newOpenPorts: deltas.filter(d => d.status === "new" && d.observation.tags.some(t => t.startsWith("port:"))).length,
    closedPorts: deltas.filter(d => d.status === "removed" && d.observation.tags.some(t => t.startsWith("port:"))).length,
    newCredentialLeaks: deltas.filter(d => d.status === "new" &&
      d.observation.tags.some(t => t.includes("breach") || t.includes("credential"))).length,
  };

  // Determine overall risk trend
  const riskIncreased = deltas.filter(d => d.riskImplication === "increased").length;
  const riskDecreased = deltas.filter(d => d.riskImplication === "decreased").length;
  const overallRiskTrend: DeltaReport["overallRiskTrend"] =
    riskIncreased > riskDecreased * 1.5 ? "increasing" :
    riskDecreased > riskIncreased * 1.5 ? "decreasing" : "stable";

  // Generate highlights
  const highlights: string[] = [];
  if (previousObservations.length === 0) {
    highlights.push("Initial scan — no previous baseline for comparison.");
  } else {
    if (stats.newObservations > 0) {
      highlights.push(`${stats.newObservations} new observations discovered since last scan.`);
    }
    if (stats.removedObservations > 0) {
      highlights.push(`${stats.removedObservations} observations no longer detected.`);
    }
    if (stats.newCriticalFindings > 0) {
      highlights.push(`${stats.newCriticalFindings} new critical findings require immediate attention.`);
    }
    if (stats.resolvedCriticalFindings > 0) {
      highlights.push(`${stats.resolvedCriticalFindings} critical findings appear to be resolved.`);
    }
    if (stats.newSubdomains > 0) {
      highlights.push(`${stats.newSubdomains} new subdomains discovered — attack surface expanded.`);
    }
    if (stats.newOpenPorts > 0) {
      highlights.push(`${stats.newOpenPorts} new open ports detected.`);
    }
    if (stats.closedPorts > 0) {
      highlights.push(`${stats.closedPorts} previously open ports are now closed.`);
    }
    if (stats.newCredentialLeaks > 0) {
      highlights.push(`${stats.newCredentialLeaks} new credential leaks found in breach databases.`);
    }
    if (stats.changedObservations > 0) {
      highlights.push(`${stats.changedObservations} existing observations have changed attributes.`);
    }
  }

  return {
    previousScanDate,
    currentScanDate,
    previousTotal: previousObservations.length,
    currentTotal: currentObservations.length,
    deltas,
    categorySummary: Array.from(categoryMap.values()).sort((a, b) =>
      (b.newCount + b.removedCount + b.changedCount) - (a.newCount + a.removedCount + a.changedCount)
    ),
    overallRiskTrend,
    highlights,
    stats,
  };
}

/**
 * Format a delta report as markdown for inclusion in reports or UI display.
 */
export function formatDeltaReportMarkdown(report: DeltaReport): string {
  const lines: string[] = [];

  lines.push("## Attack Surface Delta Report");
  lines.push("");

  if (report.previousScanDate) {
    lines.push(`**Previous scan:** ${report.previousScanDate.toISOString()}`);
  }
  lines.push(`**Current scan:** ${report.currentScanDate.toISOString()}`);
  lines.push(`**Risk trend:** ${report.overallRiskTrend}`);
  lines.push("");

  // Highlights
  if (report.highlights.length > 0) {
    lines.push("### Key Changes");
    for (const h of report.highlights) {
      lines.push(`- ${h}`);
    }
    lines.push("");
  }

  // Summary table
  lines.push("### Change Summary by Category");
  lines.push("");
  lines.push("| Category | New | Removed | Changed | Unchanged | Risk |");
  lines.push("|----------|-----|---------|---------|-----------|------|");
  for (const cat of report.categorySummary) {
    const riskIcon = cat.riskDelta === "increased" ? "\u2191" : cat.riskDelta === "decreased" ? "\u2193" : "\u2192";
    lines.push(`| ${cat.category} | ${cat.newCount} | ${cat.removedCount} | ${cat.changedCount} | ${cat.unchangedCount} | ${riskIcon} |`);
  }
  lines.push("");

  // New critical findings
  const criticals = report.deltas.filter(d => d.status === "new" && d.riskImplication === "increased");
  if (criticals.length > 0) {
    lines.push("### New High-Risk Findings");
    lines.push("");
    for (const d of criticals.slice(0, 20)) {
      lines.push(`- **${d.observation.assetType}**: ${d.summary}`);
    }
    if (criticals.length > 20) {
      lines.push(`- ... and ${criticals.length - 20} more`);
    }
    lines.push("");
  }

  // Resolved findings
  const resolved = report.deltas.filter(d => d.status === "removed" && d.riskImplication === "decreased");
  if (resolved.length > 0) {
    lines.push("### Resolved Findings");
    lines.push("");
    for (const d of resolved.slice(0, 10)) {
      lines.push(`- ${d.summary}`);
    }
    if (resolved.length > 10) {
      lines.push(`- ... and ${resolved.length - 10} more`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
