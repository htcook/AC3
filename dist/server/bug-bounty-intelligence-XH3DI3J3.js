import {
  getH1CredentialsForUser,
  init_credential_service
} from "./chunk-SHILJMMJ.js";
import "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/bug-bounty-intelligence.ts
function setActiveUser(userId) {
  _activeUserId = userId;
}
function getActiveUser() {
  return _activeUserId;
}
async function resolveH1Credentials() {
  const creds = await getH1CredentialsForUser(_activeUserId);
  if (creds) {
    return { username: creds.username, apiKey: creds.apiKey };
  }
  return null;
}
async function h1ApiFetch(path) {
  if (h1CircuitOpen) {
    throw new Error("HackerOne API circuit open \u2014 skipping (previous auth failure)");
  }
  const creds = await resolveH1Credentials();
  const headers = {
    Accept: "application/json"
  };
  if (creds) {
    headers.Authorization = "Basic " + Buffer.from(`${creds.username}:${creds.apiKey}`).toString("base64");
  }
  const res = await fetch(`${H1_BASE}${path}`, {
    headers,
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      h1CircuitOpen = true;
      console.warn(`[BugBountyIntel] HackerOne ${res.status} \u2014 circuit opened, no further calls this session`);
    }
    throw new Error(`HackerOne API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}
async function fetchHacktivity(query, pages = 3) {
  const items = [];
  for (let page = 1; page <= pages; page++) {
    try {
      const data = await h1ApiFetch(
        `/hacktivity?queryString=${encodeURIComponent(query)}&page[number]=${page}&page[size]=100`
      );
      if (!data?.data?.length) break;
      items.push(...data.data);
    } catch (err) {
      console.error(`[BugBountyIntel] Hacktivity fetch page ${page} failed:`, err);
      break;
    }
  }
  return items;
}
function severityToNumber(s) {
  return SEVERITY_ORDER[s?.toLowerCase()] ?? 0;
}
function avgSeverityLabel(items) {
  if (items.length === 0) return "none";
  const avg = items.reduce((sum, i) => sum + severityToNumber(i.attributes.severity_rating), 0) / items.length;
  if (avg >= 3.5) return "critical";
  if (avg >= 2.5) return "high";
  if (avg >= 1.5) return "medium";
  if (avg >= 0.5) return "low";
  return "none";
}
function classifyCWE(cwe) {
  return CWE_CATEGORIES[cwe] || { category: "Other", mitigationFocus: "Security review and hardening" };
}
async function enrichDomainIntel(domain, userId) {
  if (userId !== void 0) setActiveUser(userId);
  const domainBase = domain.replace(/^www\./, "").split(".").slice(-2).join(".");
  const items = await fetchHacktivity(`team:${domainBase}`, 5);
  let allItems = items;
  if (items.length === 0) {
    const broadItems = await fetchHacktivity(`disclosed:true`, 2);
    allItems = broadItems.filter((i) => {
      const prog = i.relationships?.program?.data?.attributes;
      return prog?.handle?.includes(domainBase.split(".")[0]) || prog?.name?.toLowerCase().includes(domainBase.split(".")[0]);
    });
  }
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const cweCounts = /* @__PURE__ */ new Map();
  let totalBounties = 0;
  let bountyCount = 0;
  for (const item of allItems) {
    const sev = item.attributes.severity_rating?.toLowerCase();
    if (sev && sev in severityCounts) {
      severityCounts[sev]++;
    }
    if (item.attributes.cwe) {
      cweCounts.set(item.attributes.cwe, (cweCounts.get(item.attributes.cwe) || 0) + 1);
    }
    if (item.attributes.total_awarded_amount > 0) {
      totalBounties += item.attributes.total_awarded_amount;
      bountyCount++;
    }
  }
  const program = allItems[0]?.relationships?.program?.data?.attributes;
  const topCWEs = Array.from(cweCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([cwe, count]) => ({ cwe, count }));
  const topVulns = allItems.sort((a, b) => severityToNumber(b.attributes.severity_rating) - severityToNumber(a.attributes.severity_rating)).slice(0, 20).map((i) => ({
    title: i.attributes.title,
    severity: i.attributes.severity_rating,
    cwe: i.attributes.cwe,
    cveIds: i.attributes.cve_ids || [],
    awardedAmount: i.attributes.total_awarded_amount || 0,
    disclosedAt: i.attributes.disclosed_at,
    url: i.attributes.url
  }));
  const lastDisclosed = allItems.filter((i) => i.attributes.disclosed_at).sort((a, b) => new Date(b.attributes.disclosed_at).getTime() - new Date(a.attributes.disclosed_at).getTime())[0];
  return {
    domain,
    hasBugBountyProgram: allItems.length > 0,
    programName: program?.name || null,
    programHandle: program?.handle || null,
    programUrl: program?.url || null,
    disclosedVulnerabilities: {
      total: allItems.length,
      ...severityCounts
    },
    topCWEs,
    topVulnerabilities: topVulns,
    totalBountiesPaid: totalBounties,
    avgBountyAmount: bountyCount > 0 ? Math.round(totalBounties / bountyCount) : 0,
    lastDisclosedAt: lastDisclosed?.attributes.disclosed_at || null
  };
}
async function enrichThreatIntelligence(timeRangeDays = 90, userId) {
  if (userId !== void 0) setActiveUser(userId);
  const fromDate = new Date(Date.now() - timeRangeDays * 864e5);
  const fromStr = fromDate.toISOString().split("T")[0].replace(/-/g, "-");
  const toStr = (/* @__PURE__ */ new Date()).toISOString().split("T")[0].replace(/-/g, "-");
  const criticalItems = await fetchHacktivity(`severity_rating:critical AND disclosed_at:>=${fromStr}`, 3);
  const highItems = await fetchHacktivity(`severity_rating:high AND disclosed_at:>=${fromStr}`, 3);
  const mediumItems = await fetchHacktivity(`severity_rating:medium AND disclosed_at:>=${fromStr}`, 2);
  const lowItems = await fetchHacktivity(`severity_rating:low AND disclosed_at:>=${fromStr}`, 1);
  const allItems = [...criticalItems, ...highItems, ...mediumItems, ...lowItems];
  const total = allItems.length;
  const cweCounts = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    if (item.attributes.cwe) {
      cweCounts.set(item.attributes.cwe, (cweCounts.get(item.attributes.cwe) || 0) + 1);
    }
  }
  const cweDistribution = Array.from(cweCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([cwe, count]) => ({ cwe, count, percentage: total > 0 ? Math.round(count / total * 100) : 0 }));
  const sevCounts = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const sev = item.attributes.severity_rating || "none";
    sevCounts.set(sev, (sevCounts.get(sev) || 0) + 1);
  }
  const severityDistribution = Array.from(sevCounts.entries()).sort((a, b) => severityToNumber(b[0]) - severityToNumber(a[0])).map(([severity, count]) => ({ severity, count, percentage: total > 0 ? Math.round(count / total * 100) : 0 }));
  const thirtyDaysAgo = Date.now() - 30 * 864e5;
  const recentCwe = /* @__PURE__ */ new Map();
  const olderCwe = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const cwe = item.attributes.cwe;
    if (!cwe) continue;
    const disclosedAt = item.attributes.disclosed_at ? new Date(item.attributes.disclosed_at).getTime() : 0;
    if (disclosedAt >= thirtyDaysAgo) {
      recentCwe.set(cwe, (recentCwe.get(cwe) || 0) + 1);
    } else {
      olderCwe.set(cwe, (olderCwe.get(cwe) || 0) + 1);
    }
  }
  const trendingWeaknesses = Array.from(recentCwe.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([cwe, recentCount]) => {
    const olderCount = olderCwe.get(cwe) || 0;
    const trend = recentCount > olderCount * 1.3 ? "rising" : recentCount < olderCount * 0.7 ? "declining" : "stable";
    return { cwe, recentCount, trend };
  });
  const patternMap = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const cwe = item.attributes.cwe || "Unknown";
    const { category } = classifyCWE(cwe);
    if (!patternMap.has(category)) {
      patternMap.set(category, { items: [], totalBounty: 0 });
    }
    const entry = patternMap.get(category);
    entry.items.push(item);
    entry.totalBounty += item.attributes.total_awarded_amount || 0;
  }
  const exploitPatterns = Array.from(patternMap.entries()).sort((a, b) => b[1].items.length - a[1].items.length).slice(0, 10).map(([pattern, { items: patItems, totalBounty }]) => ({
    pattern,
    description: `${patItems.length} disclosed findings in the ${pattern} category`,
    frequency: patItems.length,
    avgBounty: patItems.length > 0 ? Math.round(totalBounty / patItems.length) : 0,
    exampleReports: patItems.sort((a, b) => severityToNumber(b.attributes.severity_rating) - severityToNumber(a.attributes.severity_rating)).slice(0, 3).map((i) => ({ title: i.attributes.title, url: i.attributes.url, severity: i.attributes.severity_rating }))
  }));
  return {
    cweDistribution,
    severityDistribution,
    trendingWeaknesses,
    exploitPatterns,
    totalReportsAnalyzed: total,
    timeRange: { from: fromStr, to: toStr }
  };
}
async function enrichAttackVectors(userId) {
  if (userId !== void 0) setActiveUser(userId);
  const criticalItems = await fetchHacktivity("severity_rating:critical AND disclosed:true", 5);
  const highItems = await fetchHacktivity("severity_rating:high AND disclosed:true", 5);
  const allItems = [...criticalItems, ...highItems];
  const assetMap = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const cwe = item.attributes.cwe || "Unknown";
    const { category } = classifyCWE(cwe);
    if (!assetMap.has(category)) assetMap.set(category, []);
    assetMap.get(category).push(item);
  }
  const assetTypeBreakdown = Array.from(assetMap.entries()).sort((a, b) => b[1].length - a[1].length).map(([assetType, items]) => {
    const cwes = /* @__PURE__ */ new Map();
    let totalBounty = 0;
    for (const i of items) {
      if (i.attributes.cwe) cwes.set(i.attributes.cwe, (cwes.get(i.attributes.cwe) || 0) + 1);
      totalBounty += i.attributes.total_awarded_amount || 0;
    }
    return {
      assetType,
      findingsCount: items.length,
      avgSeverity: items.reduce((s, i) => s + severityToNumber(i.attributes.severity_rating), 0) / items.length,
      topWeaknesses: Array.from(cwes.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c]) => c),
      avgBounty: items.length > 0 ? Math.round(totalBounty / items.length) : 0
    };
  });
  const cweVectors = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const cwe = item.attributes.cwe;
    if (!cwe) continue;
    if (!cweVectors.has(cwe)) cweVectors.set(cwe, { items: [], totalBounty: 0 });
    const entry = cweVectors.get(cwe);
    entry.items.push(item);
    entry.totalBounty += item.attributes.total_awarded_amount || 0;
  }
  const bountyValidatedVectors = Array.from(cweVectors.entries()).sort((a, b) => b[1].items.length - a[1].items.length).slice(0, 15).map(([cwe, { items, totalBounty }]) => {
    const severities = items.map((i) => i.attributes.severity_rating).filter(Boolean);
    const sorted = severities.sort((a, b) => severityToNumber(a) - severityToNumber(b));
    return {
      vector: classifyCWE(cwe).category,
      cwe,
      validationCount: items.length,
      avgBountyPaid: items.length > 0 ? Math.round(totalBounty / items.length) : 0,
      severityRange: { min: sorted[0] || "none", max: sorted[sorted.length - 1] || "none" },
      realWorldExamples: items.length
    };
  });
  const programMap = /* @__PURE__ */ new Map();
  for (const item of allItems) {
    const prog = item.relationships?.program?.data?.attributes;
    if (!prog?.handle) continue;
    if (!programMap.has(prog.handle)) {
      programMap.set(prog.handle, { name: prog.name, handle: prog.handle, items: [], totalPaid: 0 });
    }
    const entry = programMap.get(prog.handle);
    entry.items.push(item);
    entry.totalPaid += item.attributes.total_awarded_amount || 0;
  }
  const highValueTargets = Array.from(programMap.values()).sort((a, b) => b.totalPaid - a.totalPaid).slice(0, 10).map((p) => {
    const cwes = /* @__PURE__ */ new Map();
    let critCount = 0;
    for (const i of p.items) {
      if (i.attributes.severity_rating === "critical") critCount++;
      if (i.attributes.cwe) cwes.set(i.attributes.cwe, (cwes.get(i.attributes.cwe) || 0) + 1);
    }
    return {
      programName: p.name,
      handle: p.handle,
      totalPaid: p.totalPaid,
      criticalFindings: critCount,
      topWeaknesses: Array.from(cwes.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c]) => c)
    };
  });
  return { assetTypeBreakdown, bountyValidatedVectors, highValueTargets };
}
async function enrichOpSec(userId) {
  if (userId !== void 0) setActiveUser(userId);
  const items = await fetchHacktivity("severity_rating:critical OR severity_rating:high", 5);
  const categoryMap = /* @__PURE__ */ new Map();
  for (const item of items) {
    const cwe = item.attributes.cwe;
    if (!cwe) continue;
    const { category, mitigationFocus } = classifyCWE(cwe);
    if (!categoryMap.has(category)) {
      categoryMap.set(category, { cwes: /* @__PURE__ */ new Set(), items: [] });
    }
    const entry = categoryMap.get(category);
    entry.cwes.add(cwe);
    entry.items.push(item);
  }
  const weaknessCategories = Array.from(categoryMap.entries()).sort((a, b) => b[1].items.length - a[1].items.length).map(([category, { cwes, items: catItems }]) => {
    const avgSev = avgSeverityLabel(catItems);
    const priority = catItems.length > 50 ? "critical" : catItems.length > 20 ? "high" : catItems.length > 5 ? "medium" : "low";
    const firstCwe = Array.from(cwes)[0];
    return {
      category,
      cweIds: Array.from(cwes),
      frequency: catItems.length,
      avgSeverity: avgSev,
      defensivePriority: priority,
      mitigationFocus: classifyCWE(firstCwe).mitigationFocus
    };
  });
  const misconfigTypes = [
    { cwes: ["Information Disclosure", "Improper Access Control"], type: "Exposed Sensitive Data", recommendation: "Implement proper access controls and data classification" },
    { cwes: ["Server-Side Request Forgery (SSRF)"], type: "SSRF via Internal Services", recommendation: "Implement URL allowlisting and network segmentation" },
    { cwes: ["Open Redirect"], type: "Unvalidated Redirects", recommendation: "Validate all redirect URLs against an allowlist" },
    { cwes: ["Cross-site Scripting (XSS)"], type: "Missing Content Security Policy", recommendation: "Deploy strict CSP headers and sanitize all user input" },
    { cwes: ["SQL Injection", "Command Injection"], type: "Injection Vulnerabilities", recommendation: "Use parameterized queries and input validation" },
    { cwes: ["Authentication Bypass"], type: "Weak Authentication Controls", recommendation: "Enforce MFA and implement robust session management" }
  ];
  const commonMisconfigurations = misconfigTypes.map((mc) => {
    const matchingItems = items.filter((i) => mc.cwes.includes(i.attributes.cwe));
    return {
      type: mc.type,
      frequency: matchingItems.length,
      impactLevel: matchingItems.length > 10 ? "Critical" : matchingItems.length > 3 ? "High" : "Medium",
      recommendation: mc.recommendation
    };
  }).filter((mc) => mc.frequency > 0).sort((a, b) => b.frequency - a.frequency);
  const defensiveGaps = weaknessCategories.filter((wc) => wc.defensivePriority === "critical" || wc.defensivePriority === "high").map((wc) => ({
    gap: `${wc.category} weaknesses \u2014 ${wc.frequency} disclosed findings`,
    exploitFrequency: wc.frequency,
    relatedCWEs: wc.cweIds.slice(0, 5),
    priorityScore: wc.frequency * (wc.defensivePriority === "critical" ? 4 : 3)
  })).sort((a, b) => b.priorityScore - a.priorityScore);
  return { weaknessCategories, commonMisconfigurations, defensiveGaps };
}
async function generateFullIntelligenceReport(domain, userId) {
  if (userId !== void 0) setActiveUser(userId);
  const [domainIntel, threatEnrichment, attackVectors, opSec] = await Promise.all([
    domain ? enrichDomainIntel(domain, userId) : Promise.resolve(null),
    enrichThreatIntelligence(90, userId),
    enrichAttackVectors(userId),
    enrichOpSec(userId)
  ]);
  return {
    generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    domainIntel,
    threatEnrichment,
    attackVectors,
    opSec
  };
}
var _activeUserId, H1_BASE, h1CircuitOpen, SEVERITY_ORDER, CWE_CATEGORIES;
var init_bug_bounty_intelligence = __esm({
  "server/lib/bug-bounty-intelligence.ts"() {
    init_credential_service();
    _activeUserId = null;
    H1_BASE = "https://api.hackerone.com/v1/hackers";
    h1CircuitOpen = false;
    SEVERITY_ORDER = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      none: 0
    };
    CWE_CATEGORIES = {
      "Cross-site Scripting (XSS)": { category: "Injection", mitigationFocus: "Input validation, CSP headers, output encoding" },
      "SQL Injection": { category: "Injection", mitigationFocus: "Parameterized queries, ORM usage, WAF rules" },
      "Server-Side Request Forgery (SSRF)": { category: "Server-Side", mitigationFocus: "URL allowlisting, network segmentation, egress filtering" },
      "Improper Access Control": { category: "Access Control", mitigationFocus: "RBAC enforcement, authorization middleware, least privilege" },
      "Information Disclosure": { category: "Data Exposure", mitigationFocus: "Error handling, data classification, response filtering" },
      "Privilege Escalation": { category: "Access Control", mitigationFocus: "Role validation, privilege boundaries, audit logging" },
      "Cross-Site Request Forgery (CSRF)": { category: "Session", mitigationFocus: "CSRF tokens, SameSite cookies, origin validation" },
      "Insecure Direct Object Reference (IDOR)": { category: "Access Control", mitigationFocus: "Object-level authorization, UUID references, access checks" },
      "Remote Code Execution": { category: "Code Execution", mitigationFocus: "Input sanitization, sandboxing, dependency auditing" },
      "Open Redirect": { category: "Redirect", mitigationFocus: "URL validation, allowlisting, relative paths only" },
      "Authentication Bypass": { category: "Authentication", mitigationFocus: "Multi-factor auth, session management, token validation" },
      "Business Logic Errors": { category: "Logic", mitigationFocus: "Workflow validation, state machine enforcement, integration testing" },
      "Denial of Service": { category: "Availability", mitigationFocus: "Rate limiting, resource quotas, circuit breakers" },
      "Path Traversal": { category: "File System", mitigationFocus: "Path canonicalization, chroot, input validation" },
      "Cryptographic Issues": { category: "Cryptography", mitigationFocus: "Modern algorithms, key management, TLS configuration" },
      "Uncontrolled Resource Consumption": { category: "Availability", mitigationFocus: "Rate limiting, resource quotas, timeout enforcement" },
      "Race Condition": { category: "Concurrency", mitigationFocus: "Mutex locks, atomic operations, idempotency tokens" },
      "XML External Entities (XXE)": { category: "Injection", mitigationFocus: "Disable DTD processing, input validation, XML parser hardening" },
      "Deserialization of Untrusted Data": { category: "Code Execution", mitigationFocus: "Type checking, allowlisted classes, integrity verification" },
      "Command Injection": { category: "Injection", mitigationFocus: "Input sanitization, parameterized commands, least privilege" }
    };
  }
});
init_bug_bounty_intelligence();
export {
  enrichAttackVectors,
  enrichDomainIntel,
  enrichOpSec,
  enrichThreatIntelligence,
  generateFullIntelligenceReport,
  getActiveUser,
  setActiveUser
};
