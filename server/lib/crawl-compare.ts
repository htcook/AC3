/**
 * Crawl Comparison / Diff Service
 *
 * Compares two crawl results for the same domain to highlight changes:
 * - New/removed security headers
 * - Header grade changes (regressions or improvements)
 * - New/removed technologies
 * - New/removed exposed paths
 * - New/removed/changed security findings
 * - Cookie security changes
 * - TLS certificate changes
 * - New/removed forms
 * - Link count changes
 */

export type ChangeType = "added" | "removed" | "changed" | "unchanged";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface DiffItem<T = string> {
  type: ChangeType;
  label: string;
  oldValue?: T;
  newValue?: T;
  severity?: Severity;
  detail?: string;
}

export interface HeaderDiff {
  present: DiffItem<string>[];
  missing: DiffItem<string>[];
  misconfigured: DiffItem<string>[];
  gradeChange: { old: string; new: string; direction: "improved" | "regressed" | "unchanged" };
}

export interface TechnologyDiff {
  added: { name: string; version?: string; category: string }[];
  removed: { name: string; version?: string; category: string }[];
  versionChanged: { name: string; oldVersion?: string; newVersion?: string; category: string }[];
  unchanged: { name: string; version?: string; category: string }[];
}

export interface FindingDiff {
  added: { severity: Severity; title: string; category: string; description: string }[];
  removed: { severity: Severity; title: string; category: string; description: string }[];
  unchanged: { severity: Severity; title: string; category: string }[];
  severityChanges: { title: string; oldSeverity: Severity; newSeverity: Severity; direction: "escalated" | "deescalated" }[];
}

export interface ExposedPathDiff {
  added: { path: string; type: string; severity: Severity; description: string }[];
  removed: { path: string; type: string; severity: Severity }[];
  unchanged: { path: string; type: string; severity: Severity }[];
}

export interface CookieDiff {
  added: { name: string; issues: string[] }[];
  removed: { name: string }[];
  changed: { name: string; changes: string[] }[];
  unchanged: { name: string }[];
}

export interface CrawlComparisonResult {
  domain: string;
  oldCrawlDate: string;
  newCrawlDate: string;
  oldJobId?: string;
  newJobId?: string;
  // Summary
  overallChange: "improved" | "regressed" | "mixed" | "unchanged";
  changeScore: number; // -100 to +100 (negative = regressed, positive = improved)
  totalChanges: number;
  // Detailed diffs
  headerDiff: HeaderDiff;
  technologyDiff: TechnologyDiff;
  findingDiff: FindingDiff;
  exposedPathDiff: ExposedPathDiff;
  cookieDiff: CookieDiff;
  // Metrics
  responseTimeDelta: { old: number; new: number; changeMs: number; changePct: number };
  contentSizeDelta: { old: number; new: number; changeBytes: number; changePct: number };
  linkCountDelta: { oldInternal: number; newInternal: number; oldExternal: number; newExternal: number };
  formCountDelta: { old: number; new: number };
  tlsChanged: boolean;
  tlsChanges: string[];
}

// ─── Grade Comparison ─────────────────────────────────────────────────────

const GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"];

function compareGrades(oldGrade: string, newGrade: string): "improved" | "regressed" | "unchanged" {
  const oldIdx = GRADE_ORDER.indexOf(oldGrade);
  const newIdx = GRADE_ORDER.indexOf(newGrade);
  if (newIdx > oldIdx) return "improved";
  if (newIdx < oldIdx) return "regressed";
  return "unchanged";
}

// ─── Header Diff ──────────────────────────────────────────────────────────

function diffHeaders(
  oldHeaders: any,
  newHeaders: any,
  oldGrade: string,
  newGrade: string,
): HeaderDiff {
  const result: HeaderDiff = {
    present: [],
    missing: [],
    misconfigured: [],
    gradeChange: { old: oldGrade, new: newGrade, direction: compareGrades(oldGrade, newGrade) },
  };

  // Compare present headers
  const oldPresent = new Map((oldHeaders?.present || []).map((h: any) => [h.name, h]));
  const newPresent = new Map((newHeaders?.present || []).map((h: any) => [h.name, h]));

  for (const [name, hdr] of newPresent) {
    if (!oldPresent.has(name)) {
      result.present.push({ type: "added", label: name, newValue: (hdr as any).value, detail: "Newly added security header" });
    } else {
      const oldHdr = oldPresent.get(name) as any;
      if (oldHdr.value !== (hdr as any).value) {
        result.present.push({ type: "changed", label: name, oldValue: oldHdr.value, newValue: (hdr as any).value });
      }
    }
  }
  for (const [name] of oldPresent) {
    if (!newPresent.has(name)) {
      result.present.push({ type: "removed", label: name, detail: "Security header removed" });
    }
  }

  // Compare missing headers
  const oldMissing = new Set((oldHeaders?.missing || []).map((h: any) => h.name));
  const newMissing = new Set((newHeaders?.missing || []).map((h: any) => h.name));

  for (const name of newMissing) {
    if (!oldMissing.has(name)) {
      const hdr = (newHeaders?.missing || []).find((h: any) => h.name === name);
      result.missing.push({ type: "added", label: name, severity: hdr?.severity, detail: "Newly missing header (regression)" });
    }
  }
  for (const name of oldMissing) {
    if (!newMissing.has(name)) {
      result.missing.push({ type: "removed", label: name, detail: "Previously missing header now present (improvement)" });
    }
  }

  return result;
}

// ─── Technology Diff ──────────────────────────────────────────────────────

function diffTechnologies(oldTech: any[], newTech: any[]): TechnologyDiff {
  const result: TechnologyDiff = { added: [], removed: [], versionChanged: [], unchanged: [] };

  const oldMap = new Map((oldTech || []).map((t: any) => [t.name, t]));
  const newMap = new Map((newTech || []).map((t: any) => [t.name, t]));

  for (const [name, tech] of newMap) {
    if (!oldMap.has(name)) {
      result.added.push({ name, version: (tech as any).version, category: (tech as any).category });
    } else {
      const oldT = oldMap.get(name) as any;
      if (oldT.version !== (tech as any).version && ((tech as any).version || oldT.version)) {
        result.versionChanged.push({
          name,
          oldVersion: oldT.version,
          newVersion: (tech as any).version,
          category: (tech as any).category,
        });
      } else {
        result.unchanged.push({ name, version: (tech as any).version, category: (tech as any).category });
      }
    }
  }
  for (const [name, tech] of oldMap) {
    if (!newMap.has(name)) {
      result.removed.push({ name, version: (tech as any).version, category: (tech as any).category });
    }
  }

  return result;
}

// ─── Finding Diff ─────────────────────────────────────────────────────────

function diffFindings(oldFindings: any[], newFindings: any[]): FindingDiff {
  const result: FindingDiff = { added: [], removed: [], unchanged: [], severityChanges: [] };

  const oldMap = new Map((oldFindings || []).map((f: any) => [f.title, f]));
  const newMap = new Map((newFindings || []).map((f: any) => [f.title, f]));

  for (const [title, finding] of newMap) {
    if (!oldMap.has(title)) {
      result.added.push({
        severity: (finding as any).severity,
        title,
        category: (finding as any).category,
        description: (finding as any).description,
      });
    } else {
      const oldF = oldMap.get(title) as any;
      if (oldF.severity !== (finding as any).severity) {
        const sevOrder: Severity[] = ["info", "low", "medium", "high", "critical"];
        const oldIdx = sevOrder.indexOf(oldF.severity);
        const newIdx = sevOrder.indexOf((finding as any).severity);
        result.severityChanges.push({
          title,
          oldSeverity: oldF.severity,
          newSeverity: (finding as any).severity,
          direction: newIdx > oldIdx ? "escalated" : "deescalated",
        });
      } else {
        result.unchanged.push({ severity: (finding as any).severity, title, category: (finding as any).category });
      }
    }
  }
  for (const [title, finding] of oldMap) {
    if (!newMap.has(title)) {
      result.removed.push({
        severity: (finding as any).severity,
        title,
        category: (finding as any).category,
        description: (finding as any).description || "",
      });
    }
  }

  return result;
}

// ─── Exposed Path Diff ────────────────────────────────────────────────────

function diffExposedPaths(oldPaths: any[], newPaths: any[]): ExposedPathDiff {
  const result: ExposedPathDiff = { added: [], removed: [], unchanged: [] };

  const oldSet = new Map((oldPaths || []).map((p: any) => [p.path, p]));
  const newSet = new Map((newPaths || []).map((p: any) => [p.path, p]));

  for (const [path, p] of newSet) {
    if (!oldSet.has(path)) {
      result.added.push({ path, type: (p as any).type, severity: (p as any).severity, description: (p as any).description });
    } else {
      result.unchanged.push({ path, type: (p as any).type, severity: (p as any).severity });
    }
  }
  for (const [path, p] of oldSet) {
    if (!newSet.has(path)) {
      result.removed.push({ path, type: (p as any).type, severity: (p as any).severity });
    }
  }

  return result;
}

// ─── Cookie Diff ──────────────────────────────────────────────────────────

function diffCookies(oldCookies: any[], newCookies: any[]): CookieDiff {
  const result: CookieDiff = { added: [], removed: [], changed: [], unchanged: [] };

  const oldMap = new Map((oldCookies || []).map((c: any) => [c.name, c]));
  const newMap = new Map((newCookies || []).map((c: any) => [c.name, c]));

  for (const [name, cookie] of newMap) {
    if (!oldMap.has(name)) {
      result.added.push({ name, issues: (cookie as any).issues || [] });
    } else {
      const oldC = oldMap.get(name) as any;
      const changes: string[] = [];
      if (oldC.secure !== (cookie as any).secure) changes.push(`Secure: ${oldC.secure} → ${(cookie as any).secure}`);
      if (oldC.httpOnly !== (cookie as any).httpOnly) changes.push(`HttpOnly: ${oldC.httpOnly} → ${(cookie as any).httpOnly}`);
      if (oldC.sameSite !== (cookie as any).sameSite) changes.push(`SameSite: ${oldC.sameSite} → ${(cookie as any).sameSite}`);
      if (changes.length > 0) {
        result.changed.push({ name, changes });
      } else {
        result.unchanged.push({ name });
      }
    }
  }
  for (const [name] of oldMap) {
    if (!newMap.has(name)) {
      result.removed.push({ name });
    }
  }

  return result;
}

// ─── TLS Diff ─────────────────────────────────────────────────────────────

function diffTls(oldTls: any, newTls: any): { changed: boolean; changes: string[] } {
  if (!oldTls && !newTls) return { changed: false, changes: [] };
  if (!oldTls && newTls) return { changed: true, changes: ["TLS certificate added"] };
  if (oldTls && !newTls) return { changed: true, changes: ["TLS certificate removed"] };

  const changes: string[] = [];
  if (oldTls.issuer !== newTls.issuer) changes.push(`Issuer changed: ${oldTls.issuer} → ${newTls.issuer}`);
  if (oldTls.subject !== newTls.subject) changes.push(`Subject changed: ${oldTls.subject} → ${newTls.subject}`);
  if (oldTls.validTo !== newTls.validTo) changes.push(`Expiry changed: ${oldTls.validTo} → ${newTls.validTo}`);
  if (oldTls.protocol !== newTls.protocol) changes.push(`Protocol changed: ${oldTls.protocol} → ${newTls.protocol}`);
  if (oldTls.cipher !== newTls.cipher) changes.push(`Cipher changed: ${oldTls.cipher} → ${newTls.cipher}`);

  return { changed: changes.length > 0, changes };
}

// ─── Main Comparison Function ─────────────────────────────────────────────

export function compareCrawlResults(
  oldResult: any,
  newResult: any,
  domain: string,
): CrawlComparisonResult {
  const headerDiff = diffHeaders(
    oldResult.securityHeaders,
    newResult.securityHeaders,
    oldResult.securityHeaderGrade || "N/A",
    newResult.securityHeaderGrade || "N/A",
  );

  const technologyDiff = diffTechnologies(
    oldResult.detectedTechnologies || [],
    newResult.detectedTechnologies || [],
  );

  const findingDiff = diffFindings(
    oldResult.findings || [],
    newResult.findings || [],
  );

  const exposedPathDiff = diffExposedPaths(
    oldResult.exposedPaths || [],
    newResult.exposedPaths || [],
  );

  const cookieDiff = diffCookies(
    oldResult.cookies || [],
    newResult.cookies || [],
  );

  const tlsDiff = diffTls(oldResult.tlsInfo, newResult.tlsInfo);

  // Calculate change score (-100 to +100)
  let changeScore = 0;
  // Header grade improvement/regression
  if (headerDiff.gradeChange.direction === "improved") changeScore += 20;
  if (headerDiff.gradeChange.direction === "regressed") changeScore -= 20;
  // Finding changes
  changeScore -= findingDiff.added.filter(f => f.severity === "critical").length * 15;
  changeScore -= findingDiff.added.filter(f => f.severity === "high").length * 10;
  changeScore -= findingDiff.added.filter(f => f.severity === "medium").length * 5;
  changeScore += findingDiff.removed.filter(f => f.severity === "critical").length * 15;
  changeScore += findingDiff.removed.filter(f => f.severity === "high").length * 10;
  changeScore += findingDiff.removed.filter(f => f.severity === "medium").length * 5;
  // Exposed paths
  changeScore -= exposedPathDiff.added.filter(p => p.severity === "critical" || p.severity === "high").length * 10;
  changeScore += exposedPathDiff.removed.filter(p => p.severity === "critical" || p.severity === "high").length * 10;
  // Clamp
  changeScore = Math.max(-100, Math.min(100, changeScore));

  const totalChanges =
    headerDiff.present.filter(h => h.type !== "unchanged").length +
    headerDiff.missing.length +
    technologyDiff.added.length + technologyDiff.removed.length + technologyDiff.versionChanged.length +
    findingDiff.added.length + findingDiff.removed.length + findingDiff.severityChanges.length +
    exposedPathDiff.added.length + exposedPathDiff.removed.length +
    cookieDiff.added.length + cookieDiff.removed.length + cookieDiff.changed.length +
    (tlsDiff.changed ? 1 : 0);

  let overallChange: CrawlComparisonResult["overallChange"] = "unchanged";
  if (totalChanges === 0) overallChange = "unchanged";
  else if (changeScore > 10) overallChange = "improved";
  else if (changeScore < -10) overallChange = "regressed";
  else overallChange = "mixed";

  const oldResponseTime = oldResult.responseTimeMs || 0;
  const newResponseTime = newResult.responseTimeMs || 0;
  const oldSize = oldResult.contentLength || 0;
  const newSize = newResult.contentLength || 0;

  return {
    domain,
    oldCrawlDate: oldResult.createdAt ? new Date(oldResult.createdAt).toISOString() : new Date(oldResult.startedAt || 0).toISOString(),
    newCrawlDate: newResult.createdAt ? new Date(newResult.createdAt).toISOString() : new Date(newResult.startedAt || 0).toISOString(),
    oldJobId: oldResult.jobId,
    newJobId: newResult.jobId,
    overallChange,
    changeScore,
    totalChanges,
    headerDiff,
    technologyDiff,
    findingDiff,
    exposedPathDiff,
    cookieDiff,
    responseTimeDelta: {
      old: oldResponseTime,
      new: newResponseTime,
      changeMs: newResponseTime - oldResponseTime,
      changePct: oldResponseTime > 0 ? Math.round(((newResponseTime - oldResponseTime) / oldResponseTime) * 100) : 0,
    },
    contentSizeDelta: {
      old: oldSize,
      new: newSize,
      changeBytes: newSize - oldSize,
      changePct: oldSize > 0 ? Math.round(((newSize - oldSize) / oldSize) * 100) : 0,
    },
    linkCountDelta: {
      oldInternal: (oldResult.internalLinks || []).length,
      newInternal: (newResult.internalLinks || []).length,
      oldExternal: (oldResult.externalLinks || []).length,
      newExternal: (newResult.externalLinks || []).length,
    },
    formCountDelta: {
      old: (oldResult.forms || []).length,
      new: (newResult.forms || []).length,
    },
    tlsChanged: tlsDiff.changed,
    tlsChanges: tlsDiff.changes,
  };
}

/**
 * Compare two crawl results by their database IDs.
 * Returns the full comparison result.
 */
export async function compareCrawlResultsById(
  oldResultId: number,
  newResultId: number,
): Promise<CrawlComparisonResult> {
  const { getDbRequired } = await import("../db");
  const { webCrawlResults } = await import("../../drizzle/schema");
  const { eq } = await import("drizzle-orm");

  const db = await getDbRequired();

  const [oldResult] = await db.select().from(webCrawlResults).where(eq(webCrawlResults.id, oldResultId)).limit(1);
  if (!oldResult) throw new Error(`Old crawl result ${oldResultId} not found`);

  const [newResult] = await db.select().from(webCrawlResults).where(eq(webCrawlResults.id, newResultId)).limit(1);
  if (!newResult) throw new Error(`New crawl result ${newResultId} not found`);

  const domain = newResult.domain || oldResult.domain || "unknown";
  return compareCrawlResults(oldResult, newResult, domain);
}

/**
 * Get all crawl results for a domain, grouped by URL, for comparison selection.
 */
export async function getCrawlHistoryForDomain(domain: string): Promise<{
  domain: string;
  urls: { url: string; crawls: { id: number; crawledAt: string; grade: string; findingCount: number }[] }[];
}> {
  const { getDb } = await import("../db");
  const { webCrawlResults } = await import("../../drizzle/schema");
  const { eq, desc } = await import("drizzle-orm");

  const db = await getDb();
  if (!db) return { domain, urls: [] };

  const results = await db.select({
    id: webCrawlResults.id,
    targetUrl: webCrawlResults.targetUrl,
    domain: webCrawlResults.domain,
    securityHeaderGrade: webCrawlResults.securityHeaderGrade,
    totalFindings: webCrawlResults.totalFindings,
    createdAt: webCrawlResults.createdAt,
  })
    .from(webCrawlResults)
    .where(eq(webCrawlResults.domain, domain))
    .orderBy(desc(webCrawlResults.createdAt));

  // Group by URL
  const urlMap = new Map<string, { id: number; crawledAt: string; grade: string; findingCount: number }[]>();
  for (const r of results) {
    const url = r.targetUrl || "unknown";
    if (!urlMap.has(url)) urlMap.set(url, []);
    urlMap.get(url)!.push({
      id: r.id,
      crawledAt: r.createdAt ? new Date(r.createdAt).toISOString() : "unknown",
      grade: r.securityHeaderGrade || "N/A",
      findingCount: r.totalFindings || 0,
    });
  }

  return {
    domain,
    urls: [...urlMap.entries()].map(([url, crawls]) => ({ url, crawls })),
  };
}
