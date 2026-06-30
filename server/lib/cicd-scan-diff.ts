/**
 * CI/CD Scan Comparison Diff Engine
 * 
 * Compares findings between two CI/CD runs to identify:
 * - New findings (in run B but not in run A)
 * - Fixed findings (in run A but not in run B)
 * - Unchanged findings (in both runs)
 * - Changed severity findings (same finding, different severity)
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DiffFinding {
  title: string;
  severity: string;
  url?: string;
  scanner?: string;
  cvss?: number;
  cweId?: string;
  description?: string;
}

export interface DiffResult {
  runA: { id: number; status: string; branch?: string; completedAt?: string };
  runB: { id: number; status: string; branch?: string; completedAt?: string };
  newFindings: DiffFinding[];
  fixedFindings: DiffFinding[];
  unchangedFindings: DiffFinding[];
  changedSeverity: Array<{
    finding: DiffFinding;
    oldSeverity: string;
    newSeverity: string;
  }>;
  summary: {
    totalA: number;
    totalB: number;
    newCount: number;
    fixedCount: number;
    unchangedCount: number;
    changedCount: number;
    riskDelta: number; // positive = worse, negative = better
    severityDelta: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

// ─── Fingerprinting ──────────────────────────────────────────────────────────

/**
 * Generate a stable fingerprint for a finding to enable comparison.
 * Uses title + URL (normalized) as the primary key.
 */
export function fingerprintFinding(f: DiffFinding): string {
  const title = (f.title || "").toLowerCase().trim();
  const url = normalizeUrl(f.url || "");
  return `${title}||${url}`;
}

/**
 * Normalize a URL for comparison (strip protocol, trailing slash, query params)
 */
function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}${u.pathname.replace(/\/$/, "")}`;
  } catch {
    return url.toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

// ─── Severity Scoring ────────────────────────────────────────────────────────

const SEVERITY_SCORE: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function severityScore(s: string): number {
  return SEVERITY_SCORE[s?.toLowerCase()] ?? 0;
}

// ─── Diff Engine ─────────────────────────────────────────────────────────────

/**
 * Compare findings between two runs and produce a structured diff
 */
export function compareRuns(
  runA: { id: number; status: string; branch?: string; completedAt?: string; findings: DiffFinding[] },
  runB: { id: number; status: string; branch?: string; completedAt?: string; findings: DiffFinding[] }
): DiffResult {
  // Build fingerprint maps
  const mapA = new Map<string, DiffFinding>();
  const mapB = new Map<string, DiffFinding>();

  for (const f of runA.findings) {
    const fp = fingerprintFinding(f);
    if (!mapA.has(fp)) mapA.set(fp, f);
  }

  for (const f of runB.findings) {
    const fp = fingerprintFinding(f);
    if (!mapB.has(fp)) mapB.set(fp, f);
  }

  const newFindings: DiffFinding[] = [];
  const fixedFindings: DiffFinding[] = [];
  const unchangedFindings: DiffFinding[] = [];
  const changedSeverity: DiffResult["changedSeverity"] = [];

  // Find new and unchanged/changed findings
  for (const [fp, findingB] of mapB) {
    const findingA = mapA.get(fp);
    if (!findingA) {
      newFindings.push(findingB);
    } else if (findingA.severity?.toLowerCase() !== findingB.severity?.toLowerCase()) {
      changedSeverity.push({
        finding: findingB,
        oldSeverity: findingA.severity,
        newSeverity: findingB.severity,
      });
    } else {
      unchangedFindings.push(findingB);
    }
  }

  // Find fixed findings (in A but not in B)
  for (const [fp, findingA] of mapA) {
    if (!mapB.has(fp)) {
      fixedFindings.push(findingA);
    }
  }

  // Calculate severity deltas
  const countBySeverity = (findings: DiffFinding[]) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      const s = f.severity?.toLowerCase() as keyof typeof counts;
      if (s in counts) counts[s]++;
    }
    return counts;
  };

  const countsA = countBySeverity(runA.findings);
  const countsB = countBySeverity(runB.findings);

  // Risk delta: sum of severity scores for new findings minus fixed findings
  const riskDelta =
    newFindings.reduce((sum, f) => sum + severityScore(f.severity), 0) -
    fixedFindings.reduce((sum, f) => sum + severityScore(f.severity), 0);

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
        low: countsB.low - countsA.low,
      },
    },
  };
}
