import "./chunk-KFQGP6VL.js";

// server/lib/passive/delta-comparison.ts
function getMatchKey(obs) {
  const type = obs.assetType || "unknown";
  const name = (obs.name || "").toLowerCase().trim();
  const ip = obs.ip || "";
  const portTag = obs.tags.find((t) => t.startsWith("port:"));
  const port = portTag ? portTag.split(":")[1] : "";
  return `${type}|${name}|${ip}|${port}`;
}
function diffObservations(prev, curr) {
  const changes = [];
  if (prev.riskScore !== curr.riskScore) {
    changes.push({ field: "riskScore", previousValue: prev.riskScore, currentValue: curr.riskScore });
  }
  const prevTags = new Set(prev.tags);
  const currTags = new Set(curr.tags);
  const newTags = curr.tags.filter((t) => !prevTags.has(t));
  const removedTags = prev.tags.filter((t) => !currTags.has(t));
  if (newTags.length > 0 || removedTags.length > 0) {
    changes.push({ field: "tags", previousValue: prev.tags, currentValue: curr.tags });
  }
  const prevEvidence = prev.evidence || {};
  const currEvidence = curr.evidence || {};
  const evidenceKeys = /* @__PURE__ */ new Set([...Object.keys(prevEvidence), ...Object.keys(currEvidence)]);
  for (const key of evidenceKeys) {
    const pv = JSON.stringify(prevEvidence[key]);
    const cv = JSON.stringify(currEvidence[key]);
    if (pv !== cv) {
      changes.push({ field: `evidence.${key}`, previousValue: prevEvidence[key], currentValue: currEvidence[key] });
    }
  }
  return changes;
}
function assessRiskImplication(delta) {
  const obs = delta.observation;
  const tags = obs.tags.join(" ").toLowerCase();
  if (delta.status === "new") {
    if (obs.riskScore && obs.riskScore >= 7) return "increased";
    if (tags.includes("critical") || tags.includes("high")) return "increased";
    if (tags.includes("breach") || tags.includes("credential") || tags.includes("vulnerability")) return "increased";
    if (obs.assetType === "subdomain" || obs.assetType === "open_port") return "increased";
    return "neutral";
  }
  if (delta.status === "removed") {
    if (obs.riskScore && obs.riskScore >= 7) return "decreased";
    if (tags.includes("critical") || tags.includes("high")) return "decreased";
    if (tags.includes("breach") || tags.includes("vulnerability")) return "decreased";
    return "neutral";
  }
  if (delta.status === "changed" && delta.changes) {
    const riskChange = delta.changes.find((c) => c.field === "riskScore");
    if (riskChange) {
      const prev = riskChange.previousValue || 0;
      const curr = riskChange.currentValue || 0;
      return curr > prev ? "increased" : curr < prev ? "decreased" : "neutral";
    }
  }
  return "neutral";
}
function summarizeDelta(delta) {
  const obs = delta.observation;
  const name = obs.name || obs.ip || "unknown asset";
  switch (delta.status) {
    case "new":
      return `New ${obs.assetType || "observation"} discovered: ${name}`;
    case "removed":
      return `${obs.assetType || "Observation"} no longer detected: ${name}`;
    case "changed": {
      const changeFields = delta.changes?.map((c) => c.field).join(", ") || "unknown fields";
      return `${obs.assetType || "Observation"} changed (${changeFields}): ${name}`;
    }
    case "unchanged":
      return `${obs.assetType || "Observation"} unchanged: ${name}`;
  }
}
function compareReconResults(previousObservations, currentObservations, previousScanDate = null) {
  const currentScanDate = /* @__PURE__ */ new Date();
  const prevMap = /* @__PURE__ */ new Map();
  for (const obs of previousObservations) {
    const key = getMatchKey(obs);
    prevMap.set(key, obs);
  }
  const currMap = /* @__PURE__ */ new Map();
  for (const obs of currentObservations) {
    const key = getMatchKey(obs);
    currMap.set(key, obs);
  }
  const deltas = [];
  for (const [key, currObs] of currMap) {
    const prevObs = prevMap.get(key);
    if (!prevObs) {
      const delta = {
        observation: currObs,
        status: "new",
        riskImplication: "neutral",
        summary: ""
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    } else {
      const changes = diffObservations(prevObs, currObs);
      const status = changes.length > 0 ? "changed" : "unchanged";
      const delta = {
        observation: currObs,
        status,
        changes: changes.length > 0 ? changes : void 0,
        riskImplication: "neutral",
        summary: ""
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    }
  }
  for (const [key, prevObs] of prevMap) {
    if (!currMap.has(key)) {
      const delta = {
        observation: prevObs,
        status: "removed",
        riskImplication: "neutral",
        summary: ""
      };
      delta.riskImplication = assessRiskImplication(delta);
      delta.summary = summarizeDelta(delta);
      deltas.push(delta);
    }
  }
  const categoryMap = /* @__PURE__ */ new Map();
  for (const delta of deltas) {
    const category = delta.observation.assetType || "other";
    if (!categoryMap.has(category)) {
      categoryMap.set(category, {
        category,
        newCount: 0,
        removedCount: 0,
        changedCount: 0,
        unchangedCount: 0,
        riskDelta: "neutral"
      });
    }
    const summary = categoryMap.get(category);
    switch (delta.status) {
      case "new":
        summary.newCount++;
        break;
      case "removed":
        summary.removedCount++;
        break;
      case "changed":
        summary.changedCount++;
        break;
      case "unchanged":
        summary.unchangedCount++;
        break;
    }
  }
  for (const [, summary] of categoryMap) {
    if (summary.newCount > summary.removedCount) {
      summary.riskDelta = "increased";
    } else if (summary.removedCount > summary.newCount) {
      summary.riskDelta = "decreased";
    }
  }
  const stats = {
    newObservations: deltas.filter((d) => d.status === "new").length,
    removedObservations: deltas.filter((d) => d.status === "removed").length,
    changedObservations: deltas.filter((d) => d.status === "changed").length,
    unchangedObservations: deltas.filter((d) => d.status === "unchanged").length,
    newCriticalFindings: deltas.filter((d) => d.status === "new" && d.riskImplication === "increased" && (d.observation.riskScore || 0) >= 8).length,
    resolvedCriticalFindings: deltas.filter((d) => d.status === "removed" && d.riskImplication === "decreased" && (d.observation.riskScore || 0) >= 8).length,
    newSubdomains: deltas.filter((d) => d.status === "new" && d.observation.assetType === "subdomain").length,
    removedSubdomains: deltas.filter((d) => d.status === "removed" && d.observation.assetType === "subdomain").length,
    newOpenPorts: deltas.filter((d) => d.status === "new" && d.observation.tags.some((t) => t.startsWith("port:"))).length,
    closedPorts: deltas.filter((d) => d.status === "removed" && d.observation.tags.some((t) => t.startsWith("port:"))).length,
    newCredentialLeaks: deltas.filter((d) => d.status === "new" && d.observation.tags.some((t) => t.includes("breach") || t.includes("credential"))).length
  };
  const riskIncreased = deltas.filter((d) => d.riskImplication === "increased").length;
  const riskDecreased = deltas.filter((d) => d.riskImplication === "decreased").length;
  const overallRiskTrend = riskIncreased > riskDecreased * 1.5 ? "increasing" : riskDecreased > riskIncreased * 1.5 ? "decreasing" : "stable";
  const highlights = [];
  if (previousObservations.length === 0) {
    highlights.push("Initial scan \u2014 no previous baseline for comparison.");
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
      highlights.push(`${stats.newSubdomains} new subdomains discovered \u2014 attack surface expanded.`);
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
    categorySummary: Array.from(categoryMap.values()).sort(
      (a, b) => b.newCount + b.removedCount + b.changedCount - (a.newCount + a.removedCount + a.changedCount)
    ),
    overallRiskTrend,
    highlights,
    stats
  };
}
function formatDeltaReportMarkdown(report) {
  const lines = [];
  lines.push("## Attack Surface Delta Report");
  lines.push("");
  if (report.previousScanDate) {
    lines.push(`**Previous scan:** ${report.previousScanDate.toISOString()}`);
  }
  lines.push(`**Current scan:** ${report.currentScanDate.toISOString()}`);
  lines.push(`**Risk trend:** ${report.overallRiskTrend}`);
  lines.push("");
  if (report.highlights.length > 0) {
    lines.push("### Key Changes");
    for (const h of report.highlights) {
      lines.push(`- ${h}`);
    }
    lines.push("");
  }
  lines.push("### Change Summary by Category");
  lines.push("");
  lines.push("| Category | New | Removed | Changed | Unchanged | Risk |");
  lines.push("|----------|-----|---------|---------|-----------|------|");
  for (const cat of report.categorySummary) {
    const riskIcon = cat.riskDelta === "increased" ? "\u2191" : cat.riskDelta === "decreased" ? "\u2193" : "\u2192";
    lines.push(`| ${cat.category} | ${cat.newCount} | ${cat.removedCount} | ${cat.changedCount} | ${cat.unchangedCount} | ${riskIcon} |`);
  }
  lines.push("");
  const criticals = report.deltas.filter((d) => d.status === "new" && d.riskImplication === "increased");
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
  const resolved = report.deltas.filter((d) => d.status === "removed" && d.riskImplication === "decreased");
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
export {
  compareReconResults,
  formatDeltaReportMarkdown
};
