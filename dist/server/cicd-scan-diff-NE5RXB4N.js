import "./chunk-KFQGP6VL.js";

// server/lib/cicd-scan-diff.ts
function fingerprintFinding(f) {
  const title = (f.title || "").toLowerCase().trim();
  const url = normalizeUrl(f.url || "");
  return `${title}||${url}`;
}
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return `${u.hostname}${u.pathname.replace(/\/$/, "")}`;
  } catch {
    return url.toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}
var SEVERITY_SCORE = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};
function severityScore(s) {
  return SEVERITY_SCORE[s?.toLowerCase()] ?? 0;
}
function compareRuns(runA, runB) {
  const mapA = /* @__PURE__ */ new Map();
  const mapB = /* @__PURE__ */ new Map();
  for (const f of runA.findings) {
    const fp = fingerprintFinding(f);
    if (!mapA.has(fp)) mapA.set(fp, f);
  }
  for (const f of runB.findings) {
    const fp = fingerprintFinding(f);
    if (!mapB.has(fp)) mapB.set(fp, f);
  }
  const newFindings = [];
  const fixedFindings = [];
  const unchangedFindings = [];
  const changedSeverity = [];
  for (const [fp, findingB] of mapB) {
    const findingA = mapA.get(fp);
    if (!findingA) {
      newFindings.push(findingB);
    } else if (findingA.severity?.toLowerCase() !== findingB.severity?.toLowerCase()) {
      changedSeverity.push({
        finding: findingB,
        oldSeverity: findingA.severity,
        newSeverity: findingB.severity
      });
    } else {
      unchangedFindings.push(findingB);
    }
  }
  for (const [fp, findingA] of mapA) {
    if (!mapB.has(fp)) {
      fixedFindings.push(findingA);
    }
  }
  const countBySeverity = (findings) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      const s = f.severity?.toLowerCase();
      if (s in counts) counts[s]++;
    }
    return counts;
  };
  const countsA = countBySeverity(runA.findings);
  const countsB = countBySeverity(runB.findings);
  const riskDelta = newFindings.reduce((sum, f) => sum + severityScore(f.severity), 0) - fixedFindings.reduce((sum, f) => sum + severityScore(f.severity), 0);
  return {
    runA: { id: runA.id, status: runA.status, branch: runA.branch, completedAt: runA.completedAt },
    runB: { id: runB.id, status: runB.status, branch: runB.branch, completedAt: runB.completedAt },
    newFindings,
    fixedFindings,
    unchangedFindings,
    changedSeverity,
    summary: {
      totalA: runA.findings.length,
      totalB: runB.findings.length,
      newCount: newFindings.length,
      fixedCount: fixedFindings.length,
      unchangedCount: unchangedFindings.length,
      changedCount: changedSeverity.length,
      riskDelta,
      severityDelta: {
        critical: countsB.critical - countsA.critical,
        high: countsB.high - countsA.high,
        medium: countsB.medium - countsA.medium,
        low: countsB.low - countsA.low
      }
    }
  };
}
export {
  compareRuns,
  fingerprintFinding
};
