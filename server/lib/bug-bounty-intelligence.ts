/**
 * Bug Bounty Intelligence Service
 * 
 * Enriches Domain Intel, Threat Enrichment, Attack Vectors, and OpSec modules
 * with real vulnerability data from HackerOne's disclosed reports (hacktivity).
 * 
 * Cross-module enrichment:
 * - Domain Intel: disclosed vulns per domain, program scope awareness
 * - Threat Enrichment: CWE trends, severity distribution, real exploit patterns
 * - Attack Vectors: bounty-validated attack surfaces by asset type
 * - OpSec: weakness categories from disclosed reports, defensive priorities
 */

import { ENV } from "../_core/env";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface H1HacktivityItem {
  id: number;
  type: string;
  attributes: {
    title: string;
    substate: string;
    url: string;
    disclosed_at: string | null;
    cve_ids: string[];
    cwe: string;
    severity_rating: string;
    votes: number;
    total_awarded_amount: number;
    submitted_at: string;
    disclosed: boolean;
    latest_disclosable_activity_at: string | null;
  };
  relationships: {
    reporter?: { data: { type: string; attributes: { name: string; username: string } } };
    program?: { data: { type: string; attributes: { handle: string; name: string; currency: string; url: string } } };
    report_generated_content?: { data: { type: string; attributes: { hacktivity_summary: string } } };
  };
}

export interface DomainIntelEnrichment {
  domain: string;
  hasBugBountyProgram: boolean;
  programName: string | null;
  programHandle: string | null;
  programUrl: string | null;
  disclosedVulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  topCWEs: Array<{ cwe: string; count: number }>;
  topVulnerabilities: Array<{
    title: string;
    severity: string;
    cwe: string;
    cveIds: string[];
    awardedAmount: number;
    disclosedAt: string | null;
    url: string;
  }>;
  totalBountiesPaid: number;
  avgBountyAmount: number;
  lastDisclosedAt: string | null;
}

export interface ThreatEnrichment {
  cweDistribution: Array<{ cwe: string; count: number; percentage: number }>;
  severityDistribution: Array<{ severity: string; count: number; percentage: number }>;
  trendingWeaknesses: Array<{ cwe: string; recentCount: number; trend: "rising" | "stable" | "declining" }>;
  exploitPatterns: Array<{
    pattern: string;
    description: string;
    frequency: number;
    avgBounty: number;
    exampleReports: Array<{ title: string; url: string; severity: string }>;
  }>;
  totalReportsAnalyzed: number;
  timeRange: { from: string; to: string };
}

export interface AttackVectorEnrichment {
  assetTypeBreakdown: Array<{
    assetType: string;
    findingsCount: number;
    avgSeverity: number;
    topWeaknesses: string[];
    avgBounty: number;
  }>;
  bountyValidatedVectors: Array<{
    vector: string;
    cwe: string;
    validationCount: number;
    avgBountyPaid: number;
    severityRange: { min: string; max: string };
    realWorldExamples: number;
  }>;
  highValueTargets: Array<{
    programName: string;
    handle: string;
    totalPaid: number;
    criticalFindings: number;
    topWeaknesses: string[];
  }>;
}

export interface OpSecEnrichment {
  weaknessCategories: Array<{
    category: string;
    cweIds: string[];
    frequency: number;
    avgSeverity: string;
    defensivePriority: "critical" | "high" | "medium" | "low";
    mitigationFocus: string;
  }>;
  commonMisconfigurations: Array<{
    type: string;
    frequency: number;
    impactLevel: string;
    recommendation: string;
  }>;
  defensiveGaps: Array<{
    gap: string;
    exploitFrequency: number;
    relatedCWEs: string[];
    priorityScore: number;
  }>;
}

// ─── HackerOne API Client ────────────────────────────────────────────────────

const H1_BASE = "https://api.hackerone.com/v1/hackers";

async function h1ApiFetch(path: string): Promise<any> {
  const apiKey = ENV.HACKERONE_API_KEY;
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (apiKey) {
    // HackerOne uses Basic auth: username:token
    // The API key format may be just the token; use it as both username and token
    headers.Authorization = "Basic " + Buffer.from(`${apiKey}:${apiKey}`).toString("base64");
  }
  const res = await fetch(`${H1_BASE}${path}`, {
    headers,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    throw new Error(`HackerOne API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

async function fetchHacktivity(query: string, pages: number = 3): Promise<H1HacktivityItem[]> {
  const items: H1HacktivityItem[] = [];
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

// ─── Severity Helpers ────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

function severityToNumber(s: string): number {
  return SEVERITY_ORDER[s?.toLowerCase()] ?? 0;
}

function avgSeverityLabel(items: H1HacktivityItem[]): string {
  if (items.length === 0) return "none";
  const avg = items.reduce((sum, i) => sum + severityToNumber(i.attributes.severity_rating), 0) / items.length;
  if (avg >= 3.5) return "critical";
  if (avg >= 2.5) return "high";
  if (avg >= 1.5) return "medium";
  if (avg >= 0.5) return "low";
  return "none";
}

// ─── CWE Classification ─────────────────────────────────────────────────────

const CWE_CATEGORIES: Record<string, { category: string; mitigationFocus: string }> = {
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
  "Command Injection": { category: "Injection", mitigationFocus: "Input sanitization, parameterized commands, least privilege" },
};

function classifyCWE(cwe: string): { category: string; mitigationFocus: string } {
  return CWE_CATEGORIES[cwe] || { category: "Other", mitigationFocus: "Security review and hardening" };
}

// ─── Domain Intel Enrichment ─────────────────────────────────────────────────

export async function enrichDomainIntel(domain: string): Promise<DomainIntelEnrichment> {
  // Search hacktivity for the domain's program
  const domainBase = domain.replace(/^www\./, "").split(".").slice(-2).join(".");
  const items = await fetchHacktivity(`team:${domainBase}`, 5);

  // Also try broader search
  let allItems = items;
  if (items.length === 0) {
    const broadItems = await fetchHacktivity(`disclosed:true`, 2);
    allItems = broadItems.filter((i) => {
      const prog = i.relationships?.program?.data?.attributes;
      return prog?.handle?.includes(domainBase.split(".")[0]) || prog?.name?.toLowerCase().includes(domainBase.split(".")[0]);
    });
  }

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const cweCounts = new Map<string, number>();
  let totalBounties = 0;
  let bountyCount = 0;

  for (const item of allItems) {
    const sev = item.attributes.severity_rating?.toLowerCase();
    if (sev && sev in severityCounts) {
      severityCounts[sev as keyof typeof severityCounts]++;
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
  const topCWEs = Array.from(cweCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([cwe, count]) => ({ cwe, count }));

  const topVulns = allItems
    .sort((a, b) => severityToNumber(b.attributes.severity_rating) - severityToNumber(a.attributes.severity_rating))
    .slice(0, 20)
    .map((i) => ({
      title: i.attributes.title,
      severity: i.attributes.severity_rating,
      cwe: i.attributes.cwe,
      cveIds: i.attributes.cve_ids || [],
      awardedAmount: i.attributes.total_awarded_amount || 0,
      disclosedAt: i.attributes.disclosed_at,
      url: i.attributes.url,
    }));

  const lastDisclosed = allItems
    .filter((i) => i.attributes.disclosed_at)
    .sort((a, b) => new Date(b.attributes.disclosed_at!).getTime() - new Date(a.attributes.disclosed_at!).getTime())[0];

  return {
    domain,
    hasBugBountyProgram: allItems.length > 0,
    programName: program?.name || null,
    programHandle: program?.handle || null,
    programUrl: program?.url || null,
    disclosedVulnerabilities: {
      total: allItems.length,
      ...severityCounts,
    },
    topCWEs,
    topVulnerabilities: topVulns,
    totalBountiesPaid: totalBounties,
    avgBountyAmount: bountyCount > 0 ? Math.round(totalBounties / bountyCount) : 0,
    lastDisclosedAt: lastDisclosed?.attributes.disclosed_at || null,
  };
}

// ─── Threat Enrichment ───────────────────────────────────────────────────────

export async function enrichThreatIntelligence(
  timeRangeDays: number = 90
): Promise<ThreatEnrichment> {
  const fromDate = new Date(Date.now() - timeRangeDays * 86400000);
  const fromStr = fromDate.toISOString().split("T")[0].replace(/-/g, "-");
  const toStr = new Date().toISOString().split("T")[0].replace(/-/g, "-");

  // Fetch recent disclosed reports across all severity levels
  const criticalItems = await fetchHacktivity(`severity_rating:critical AND disclosed_at:>=${fromStr}`, 3);
  const highItems = await fetchHacktivity(`severity_rating:high AND disclosed_at:>=${fromStr}`, 3);
  const mediumItems = await fetchHacktivity(`severity_rating:medium AND disclosed_at:>=${fromStr}`, 2);
  const lowItems = await fetchHacktivity(`severity_rating:low AND disclosed_at:>=${fromStr}`, 1);

  const allItems = [...criticalItems, ...highItems, ...mediumItems, ...lowItems];
  const total = allItems.length;

  // CWE distribution
  const cweCounts = new Map<string, number>();
  for (const item of allItems) {
    if (item.attributes.cwe) {
      cweCounts.set(item.attributes.cwe, (cweCounts.get(item.attributes.cwe) || 0) + 1);
    }
  }
  const cweDistribution = Array.from(cweCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([cwe, count]) => ({ cwe, count, percentage: total > 0 ? Math.round((count / total) * 100) : 0 }));

  // Severity distribution
  const sevCounts = new Map<string, number>();
  for (const item of allItems) {
    const sev = item.attributes.severity_rating || "none";
    sevCounts.set(sev, (sevCounts.get(sev) || 0) + 1);
  }
  const severityDistribution = Array.from(sevCounts.entries())
    .sort((a, b) => severityToNumber(b[0]) - severityToNumber(a[0]))
    .map(([severity, count]) => ({ severity, count, percentage: total > 0 ? Math.round((count / total) * 100) : 0 }));

  // Trending weaknesses (compare recent 30 days vs older)
  const thirtyDaysAgo = Date.now() - 30 * 86400000;
  const recentCwe = new Map<string, number>();
  const olderCwe = new Map<string, number>();
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
  const trendingWeaknesses = Array.from(recentCwe.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([cwe, recentCount]) => {
      const olderCount = olderCwe.get(cwe) || 0;
      const trend: "rising" | "stable" | "declining" =
        recentCount > olderCount * 1.3 ? "rising" : recentCount < olderCount * 0.7 ? "declining" : "stable";
      return { cwe, recentCount, trend };
    });

  // Exploit patterns — group by CWE category
  const patternMap = new Map<string, { items: H1HacktivityItem[]; totalBounty: number }>();
  for (const item of allItems) {
    const cwe = item.attributes.cwe || "Unknown";
    const { category } = classifyCWE(cwe);
    if (!patternMap.has(category)) {
      patternMap.set(category, { items: [], totalBounty: 0 });
    }
    const entry = patternMap.get(category)!;
    entry.items.push(item);
    entry.totalBounty += item.attributes.total_awarded_amount || 0;
  }
  const exploitPatterns = Array.from(patternMap.entries())
    .sort((a, b) => b[1].items.length - a[1].items.length)
    .slice(0, 10)
    .map(([pattern, { items: patItems, totalBounty }]) => ({
      pattern,
      description: `${patItems.length} disclosed findings in the ${pattern} category`,
      frequency: patItems.length,
      avgBounty: patItems.length > 0 ? Math.round(totalBounty / patItems.length) : 0,
      exampleReports: patItems
        .sort((a, b) => severityToNumber(b.attributes.severity_rating) - severityToNumber(a.attributes.severity_rating))
        .slice(0, 3)
        .map((i) => ({ title: i.attributes.title, url: i.attributes.url, severity: i.attributes.severity_rating })),
    }));

  return {
    cweDistribution,
    severityDistribution,
    trendingWeaknesses,
    exploitPatterns,
    totalReportsAnalyzed: total,
    timeRange: { from: fromStr, to: toStr },
  };
}

// ─── Attack Vector Enrichment ────────────────────────────────────────────────

export async function enrichAttackVectors(): Promise<AttackVectorEnrichment> {
  // Fetch high-value disclosed reports
  const criticalItems = await fetchHacktivity("severity_rating:critical AND disclosed:true", 5);
  const highItems = await fetchHacktivity("severity_rating:high AND disclosed:true", 5);
  const allItems = [...criticalItems, ...highItems];

  // Asset type breakdown (group by CWE category as proxy for asset type)
  const assetMap = new Map<string, H1HacktivityItem[]>();
  for (const item of allItems) {
    const cwe = item.attributes.cwe || "Unknown";
    const { category } = classifyCWE(cwe);
    if (!assetMap.has(category)) assetMap.set(category, []);
    assetMap.get(category)!.push(item);
  }

  const assetTypeBreakdown = Array.from(assetMap.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .map(([assetType, items]) => {
      const cwes = new Map<string, number>();
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
        avgBounty: items.length > 0 ? Math.round(totalBounty / items.length) : 0,
      };
    });

  // Bounty-validated vectors
  const cweVectors = new Map<string, { items: H1HacktivityItem[]; totalBounty: number }>();
  for (const item of allItems) {
    const cwe = item.attributes.cwe;
    if (!cwe) continue;
    if (!cweVectors.has(cwe)) cweVectors.set(cwe, { items: [], totalBounty: 0 });
    const entry = cweVectors.get(cwe)!;
    entry.items.push(item);
    entry.totalBounty += item.attributes.total_awarded_amount || 0;
  }

  const bountyValidatedVectors = Array.from(cweVectors.entries())
    .sort((a, b) => b[1].items.length - a[1].items.length)
    .slice(0, 15)
    .map(([cwe, { items, totalBounty }]) => {
      const severities = items.map((i) => i.attributes.severity_rating).filter(Boolean);
      const sorted = severities.sort((a, b) => severityToNumber(a) - severityToNumber(b));
      return {
        vector: classifyCWE(cwe).category,
        cwe,
        validationCount: items.length,
        avgBountyPaid: items.length > 0 ? Math.round(totalBounty / items.length) : 0,
        severityRange: { min: sorted[0] || "none", max: sorted[sorted.length - 1] || "none" },
        realWorldExamples: items.length,
      };
    });

  // High-value targets (programs with most critical findings)
  const programMap = new Map<string, { name: string; handle: string; items: H1HacktivityItem[]; totalPaid: number }>();
  for (const item of allItems) {
    const prog = item.relationships?.program?.data?.attributes;
    if (!prog?.handle) continue;
    if (!programMap.has(prog.handle)) {
      programMap.set(prog.handle, { name: prog.name, handle: prog.handle, items: [], totalPaid: 0 });
    }
    const entry = programMap.get(prog.handle)!;
    entry.items.push(item);
    entry.totalPaid += item.attributes.total_awarded_amount || 0;
  }

  const highValueTargets = Array.from(programMap.values())
    .sort((a, b) => b.totalPaid - a.totalPaid)
    .slice(0, 10)
    .map((p) => {
      const cwes = new Map<string, number>();
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
        topWeaknesses: Array.from(cwes.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c]) => c),
      };
    });

  return { assetTypeBreakdown, bountyValidatedVectors, highValueTargets };
}

// ─── OpSec Enrichment ────────────────────────────────────────────────────────

export async function enrichOpSec(): Promise<OpSecEnrichment> {
  // Fetch recent critical and high findings for defensive analysis
  const items = await fetchHacktivity("severity_rating:critical OR severity_rating:high", 5);

  // Weakness categories
  const categoryMap = new Map<string, { cwes: Set<string>; items: H1HacktivityItem[] }>();
  for (const item of items) {
    const cwe = item.attributes.cwe;
    if (!cwe) continue;
    const { category, mitigationFocus } = classifyCWE(cwe);
    if (!categoryMap.has(category)) {
      categoryMap.set(category, { cwes: new Set(), items: [] });
    }
    const entry = categoryMap.get(category)!;
    entry.cwes.add(cwe);
    entry.items.push(item);
  }

  const weaknessCategories = Array.from(categoryMap.entries())
    .sort((a, b) => b[1].items.length - a[1].items.length)
    .map(([category, { cwes, items: catItems }]) => {
      const avgSev = avgSeverityLabel(catItems);
      const priority: "critical" | "high" | "medium" | "low" =
        catItems.length > 50 ? "critical" : catItems.length > 20 ? "high" : catItems.length > 5 ? "medium" : "low";
      const firstCwe = Array.from(cwes)[0];
      return {
        category,
        cweIds: Array.from(cwes),
        frequency: catItems.length,
        avgSeverity: avgSev,
        defensivePriority: priority,
        mitigationFocus: classifyCWE(firstCwe).mitigationFocus,
      };
    });

  // Common misconfigurations (derived from CWE patterns)
  const misconfigTypes = [
    { cwes: ["Information Disclosure", "Improper Access Control"], type: "Exposed Sensitive Data", recommendation: "Implement proper access controls and data classification" },
    { cwes: ["Server-Side Request Forgery (SSRF)"], type: "SSRF via Internal Services", recommendation: "Implement URL allowlisting and network segmentation" },
    { cwes: ["Open Redirect"], type: "Unvalidated Redirects", recommendation: "Validate all redirect URLs against an allowlist" },
    { cwes: ["Cross-site Scripting (XSS)"], type: "Missing Content Security Policy", recommendation: "Deploy strict CSP headers and sanitize all user input" },
    { cwes: ["SQL Injection", "Command Injection"], type: "Injection Vulnerabilities", recommendation: "Use parameterized queries and input validation" },
    { cwes: ["Authentication Bypass"], type: "Weak Authentication Controls", recommendation: "Enforce MFA and implement robust session management" },
  ];

  const commonMisconfigurations = misconfigTypes
    .map((mc) => {
      const matchingItems = items.filter((i) => mc.cwes.includes(i.attributes.cwe));
      return {
        type: mc.type,
        frequency: matchingItems.length,
        impactLevel: matchingItems.length > 10 ? "Critical" : matchingItems.length > 3 ? "High" : "Medium",
        recommendation: mc.recommendation,
      };
    })
    .filter((mc) => mc.frequency > 0)
    .sort((a, b) => b.frequency - a.frequency);

  // Defensive gaps
  const defensiveGaps = weaknessCategories
    .filter((wc) => wc.defensivePriority === "critical" || wc.defensivePriority === "high")
    .map((wc) => ({
      gap: `${wc.category} weaknesses — ${wc.frequency} disclosed findings`,
      exploitFrequency: wc.frequency,
      relatedCWEs: wc.cweIds.slice(0, 5),
      priorityScore: wc.frequency * (wc.defensivePriority === "critical" ? 4 : 3),
    }))
    .sort((a, b) => b.priorityScore - a.priorityScore);

  return { weaknessCategories, commonMisconfigurations, defensiveGaps };
}

// ─── Unified Enrichment ──────────────────────────────────────────────────────

export interface BugBountyIntelligenceReport {
  generatedAt: string;
  domainIntel: DomainIntelEnrichment | null;
  threatEnrichment: ThreatEnrichment;
  attackVectors: AttackVectorEnrichment;
  opSec: OpSecEnrichment;
}

export async function generateFullIntelligenceReport(
  domain?: string
): Promise<BugBountyIntelligenceReport> {
  const [domainIntel, threatEnrichment, attackVectors, opSec] = await Promise.all([
    domain ? enrichDomainIntel(domain) : Promise.resolve(null),
    enrichThreatIntelligence(90),
    enrichAttackVectors(),
    enrichOpSec(),
  ]);

  return {
    generatedAt: new Date().toISOString(),
    domainIntel,
    threatEnrichment,
    attackVectors,
    opSec,
  };
}
