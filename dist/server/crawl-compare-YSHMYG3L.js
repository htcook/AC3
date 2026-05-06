import "./chunk-KFQGP6VL.js";

// server/lib/crawl-compare.ts
var GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"];
function compareGrades(oldGrade, newGrade) {
  const oldIdx = GRADE_ORDER.indexOf(oldGrade);
  const newIdx = GRADE_ORDER.indexOf(newGrade);
  if (newIdx > oldIdx) return "improved";
  if (newIdx < oldIdx) return "regressed";
  return "unchanged";
}
function diffHeaders(oldHeaders, newHeaders, oldGrade, newGrade) {
  const result = {
    present: [],
    missing: [],
    misconfigured: [],
    gradeChange: { old: oldGrade, new: newGrade, direction: compareGrades(oldGrade, newGrade) }
  };
  const oldPresent = new Map((oldHeaders?.present || []).map((h) => [h.name, h]));
  const newPresent = new Map((newHeaders?.present || []).map((h) => [h.name, h]));
  for (const [name, hdr] of newPresent) {
    const nameStr = name;
    if (!oldPresent.has(nameStr)) {
      result.present.push({ type: "added", label: nameStr, newValue: hdr.value, detail: "Newly added security header" });
    } else {
      const oldHdr = oldPresent.get(nameStr);
      if (oldHdr.value !== hdr.value) {
        result.present.push({ type: "changed", label: nameStr, oldValue: oldHdr.value, newValue: hdr.value });
      }
    }
  }
  for (const [name] of oldPresent) {
    const nameStr = name;
    if (!newPresent.has(nameStr)) {
      result.present.push({ type: "removed", label: nameStr, detail: "Security header removed" });
    }
  }
  const oldMissing = new Set((oldHeaders?.missing || []).map((h) => h.name));
  const newMissing = new Set((newHeaders?.missing || []).map((h) => h.name));
  for (const name of newMissing) {
    const nameStr = name;
    if (!oldMissing.has(nameStr)) {
      const hdr = (newHeaders?.missing || []).find((h) => h.name === nameStr);
      result.missing.push({ type: "added", label: nameStr, severity: hdr?.severity, detail: "Newly missing header (regression)" });
    }
  }
  for (const name of oldMissing) {
    const nameStr = name;
    if (!newMissing.has(nameStr)) {
      result.missing.push({ type: "removed", label: nameStr, detail: "Previously missing header now present (improvement)" });
    }
  }
  return result;
}
function diffTechnologies(oldTech, newTech) {
  const result = { added: [], removed: [], versionChanged: [], unchanged: [] };
  const oldMap = new Map((oldTech || []).map((t) => [t.name, t]));
  const newMap = new Map((newTech || []).map((t) => [t.name, t]));
  for (const [name, tech] of newMap) {
    if (!oldMap.has(name)) {
      result.added.push({ name, version: tech.version, category: tech.category });
    } else {
      const oldT = oldMap.get(name);
      if (oldT.version !== tech.version && (tech.version || oldT.version)) {
        result.versionChanged.push({
          name,
          oldVersion: oldT.version,
          newVersion: tech.version,
          category: tech.category
        });
      } else {
        result.unchanged.push({ name, version: tech.version, category: tech.category });
      }
    }
  }
  for (const [name, tech] of oldMap) {
    if (!newMap.has(name)) {
      result.removed.push({ name, version: tech.version, category: tech.category });
    }
  }
  return result;
}
function diffFindings(oldFindings, newFindings) {
  const result = { added: [], removed: [], unchanged: [], severityChanges: [] };
  const oldMap = new Map((oldFindings || []).map((f) => [f.title, f]));
  const newMap = new Map((newFindings || []).map((f) => [f.title, f]));
  for (const [title, finding] of newMap) {
    if (!oldMap.has(title)) {
      result.added.push({
        severity: finding.severity,
        title,
        category: finding.category,
        description: finding.description
      });
    } else {
      const oldF = oldMap.get(title);
      if (oldF.severity !== finding.severity) {
        const sevOrder = ["info", "low", "medium", "high", "critical"];
        const oldIdx = sevOrder.indexOf(oldF.severity);
        const newIdx = sevOrder.indexOf(finding.severity);
        result.severityChanges.push({
          title,
          oldSeverity: oldF.severity,
          newSeverity: finding.severity,
          direction: newIdx > oldIdx ? "escalated" : "deescalated"
        });
      } else {
        result.unchanged.push({ severity: finding.severity, title, category: finding.category });
      }
    }
  }
  for (const [title, finding] of oldMap) {
    if (!newMap.has(title)) {
      result.removed.push({
        severity: finding.severity,
        title,
        category: finding.category,
        description: finding.description || ""
      });
    }
  }
  return result;
}
function diffExposedPaths(oldPaths, newPaths) {
  const result = { added: [], removed: [], unchanged: [] };
  const oldSet = new Map((oldPaths || []).map((p) => [p.path, p]));
  const newSet = new Map((newPaths || []).map((p) => [p.path, p]));
  for (const [path, p] of newSet) {
    if (!oldSet.has(path)) {
      result.added.push({ path, type: p.type, severity: p.severity, description: p.description });
    } else {
      result.unchanged.push({ path, type: p.type, severity: p.severity });
    }
  }
  for (const [path, p] of oldSet) {
    if (!newSet.has(path)) {
      result.removed.push({ path, type: p.type, severity: p.severity });
    }
  }
  return result;
}
function diffCookies(oldCookies, newCookies) {
  const result = { added: [], removed: [], changed: [], unchanged: [] };
  const oldMap = new Map((oldCookies || []).map((c) => [c.name, c]));
  const newMap = new Map((newCookies || []).map((c) => [c.name, c]));
  for (const [name, cookie] of newMap) {
    if (!oldMap.has(name)) {
      result.added.push({ name, issues: cookie.issues || [] });
    } else {
      const oldC = oldMap.get(name);
      const changes = [];
      if (oldC.secure !== cookie.secure) changes.push(`Secure: ${oldC.secure} \u2192 ${cookie.secure}`);
      if (oldC.httpOnly !== cookie.httpOnly) changes.push(`HttpOnly: ${oldC.httpOnly} \u2192 ${cookie.httpOnly}`);
      if (oldC.sameSite !== cookie.sameSite) changes.push(`SameSite: ${oldC.sameSite} \u2192 ${cookie.sameSite}`);
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
function diffTls(oldTls, newTls) {
  if (!oldTls && !newTls) return { changed: false, changes: [] };
  if (!oldTls && newTls) return { changed: true, changes: ["TLS certificate added"] };
  if (oldTls && !newTls) return { changed: true, changes: ["TLS certificate removed"] };
  const changes = [];
  if (oldTls.issuer !== newTls.issuer) changes.push(`Issuer changed: ${oldTls.issuer} \u2192 ${newTls.issuer}`);
  if (oldTls.subject !== newTls.subject) changes.push(`Subject changed: ${oldTls.subject} \u2192 ${newTls.subject}`);
  if (oldTls.validTo !== newTls.validTo) changes.push(`Expiry changed: ${oldTls.validTo} \u2192 ${newTls.validTo}`);
  if (oldTls.protocol !== newTls.protocol) changes.push(`Protocol changed: ${oldTls.protocol} \u2192 ${newTls.protocol}`);
  if (oldTls.cipher !== newTls.cipher) changes.push(`Cipher changed: ${oldTls.cipher} \u2192 ${newTls.cipher}`);
  return { changed: changes.length > 0, changes };
}
function compareCrawlResults(oldResult, newResult, domain) {
  const headerDiff = diffHeaders(
    oldResult.securityHeaders,
    newResult.securityHeaders,
    oldResult.securityHeaderGrade || "N/A",
    newResult.securityHeaderGrade || "N/A"
  );
  const technologyDiff = diffTechnologies(
    oldResult.detectedTechnologies || [],
    newResult.detectedTechnologies || []
  );
  const findingDiff = diffFindings(
    oldResult.findings || [],
    newResult.findings || []
  );
  const exposedPathDiff = diffExposedPaths(
    oldResult.exposedPaths || [],
    newResult.exposedPaths || []
  );
  const cookieDiff = diffCookies(
    oldResult.cookies || [],
    newResult.cookies || []
  );
  const tlsDiff = diffTls(oldResult.tlsInfo, newResult.tlsInfo);
  let changeScore = 0;
  if (headerDiff.gradeChange.direction === "improved") changeScore += 20;
  if (headerDiff.gradeChange.direction === "regressed") changeScore -= 20;
  changeScore -= findingDiff.added.filter((f) => f.severity === "critical").length * 15;
  changeScore -= findingDiff.added.filter((f) => f.severity === "high").length * 10;
  changeScore -= findingDiff.added.filter((f) => f.severity === "medium").length * 5;
  changeScore += findingDiff.removed.filter((f) => f.severity === "critical").length * 15;
  changeScore += findingDiff.removed.filter((f) => f.severity === "high").length * 10;
  changeScore += findingDiff.removed.filter((f) => f.severity === "medium").length * 5;
  changeScore -= exposedPathDiff.added.filter((p) => p.severity === "critical" || p.severity === "high").length * 10;
  changeScore += exposedPathDiff.removed.filter((p) => p.severity === "critical" || p.severity === "high").length * 10;
  changeScore = Math.max(-100, Math.min(100, changeScore));
  const totalChanges = headerDiff.present.filter((h) => h.type !== "unchanged").length + headerDiff.missing.length + technologyDiff.added.length + technologyDiff.removed.length + technologyDiff.versionChanged.length + findingDiff.added.length + findingDiff.removed.length + findingDiff.severityChanges.length + exposedPathDiff.added.length + exposedPathDiff.removed.length + cookieDiff.added.length + cookieDiff.removed.length + cookieDiff.changed.length + (tlsDiff.changed ? 1 : 0);
  let overallChange = "unchanged";
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
      changePct: oldResponseTime > 0 ? Math.round((newResponseTime - oldResponseTime) / oldResponseTime * 100) : 0
    },
    contentSizeDelta: {
      old: oldSize,
      new: newSize,
      changeBytes: newSize - oldSize,
      changePct: oldSize > 0 ? Math.round((newSize - oldSize) / oldSize * 100) : 0
    },
    linkCountDelta: {
      oldInternal: (oldResult.internalLinks || []).length,
      newInternal: (newResult.internalLinks || []).length,
      oldExternal: (oldResult.externalLinks || []).length,
      newExternal: (newResult.externalLinks || []).length
    },
    formCountDelta: {
      old: (oldResult.forms || []).length,
      new: (newResult.forms || []).length
    },
    tlsChanged: tlsDiff.changed,
    tlsChanges: tlsDiff.changes
  };
}
async function compareCrawlResultsById(oldResultId, newResultId) {
  const { getDbRequired } = await import("./db-F33RXQPM.js");
  const { webCrawlResults } = await import("./schema-OF2ORZ4R.js");
  const { eq } = await import("drizzle-orm");
  const db = await getDbRequired();
  const [oldResult] = await db.select().from(webCrawlResults).where(eq(webCrawlResults.id, oldResultId)).limit(1);
  if (!oldResult) throw new Error(`Old crawl result ${oldResultId} not found`);
  const [newResult] = await db.select().from(webCrawlResults).where(eq(webCrawlResults.id, newResultId)).limit(1);
  if (!newResult) throw new Error(`New crawl result ${newResultId} not found`);
  const domain = newResult.domain || oldResult.domain || "unknown";
  return compareCrawlResults(oldResult, newResult, domain);
}
async function getCrawlHistoryForDomain(domain) {
  const { getDb } = await import("./db-F33RXQPM.js");
  const { webCrawlResults } = await import("./schema-OF2ORZ4R.js");
  const { eq, desc } = await import("drizzle-orm");
  const db = await getDb();
  if (!db) return { domain, urls: [] };
  const results = await db.select({
    id: webCrawlResults.id,
    targetUrl: webCrawlResults.targetUrl,
    domain: webCrawlResults.domain,
    securityHeaderGrade: webCrawlResults.securityHeaderGrade,
    totalFindings: webCrawlResults.totalFindings,
    createdAt: webCrawlResults.createdAt
  }).from(webCrawlResults).where(eq(webCrawlResults.domain, domain)).orderBy(desc(webCrawlResults.createdAt));
  const urlMap = /* @__PURE__ */ new Map();
  for (const r of results) {
    const url = r.targetUrl || "unknown";
    if (!urlMap.has(url)) urlMap.set(url, []);
    urlMap.get(url).push({
      id: r.id,
      crawledAt: r.createdAt ? new Date(r.createdAt).toISOString() : "unknown",
      grade: r.securityHeaderGrade || "N/A",
      findingCount: r.totalFindings || 0
    });
  }
  return {
    domain,
    urls: [...urlMap.entries()].map(([url, crawls]) => ({ url, crawls }))
  };
}
export {
  compareCrawlResults,
  compareCrawlResultsById,
  getCrawlHistoryForDomain
};
