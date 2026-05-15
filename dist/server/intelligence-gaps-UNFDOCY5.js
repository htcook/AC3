import {
  getDb,
  init_db
} from "./chunk-YEW6KKPA.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  intelligenceGaps
} from "./chunk-EMIPCWBF.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/intelligence-gaps.ts
import { eq, and, desc, count } from "drizzle-orm";
async function createGap(gap) {
  const db = await getDb();
  const result = await db.insert(intelligenceGaps).values({
    engagementId: gap.engagementId ?? null,
    scanId: gap.scanId ?? null,
    customerId: gap.customerId ?? null,
    category: gap.category,
    subcategory: gap.subcategory ?? null,
    title: gap.title,
    description: gap.description ?? null,
    reason: gap.reason,
    riskImplication: gap.riskImplication ?? null,
    potentialImpact: gap.potentialImpact ?? GAP_CATEGORY_META[gap.category]?.defaultImpact ?? "unknown",
    recommendation: gap.recommendation ?? null,
    estimatedEffort: gap.estimatedEffort ?? null,
    status: gap.status ?? "open",
    detectedBy: gap.detectedBy ?? "system",
    confidence: gap.confidence ?? null,
    affectedAssets: gap.affectedAssets ?? null,
    affectedScope: gap.affectedScope ?? null,
    relatedFindings: gap.relatedFindings ?? null,
    tags: gap.tags ?? null
  });
  return result[0]?.insertId ?? 0;
}
async function createGapsBatch(gaps) {
  const ids = [];
  for (const gap of gaps) {
    const id = await createGap(gap);
    ids.push(id);
  }
  return ids;
}
async function listGaps(opts) {
  const conditions = [];
  if (opts.engagementId) conditions.push(eq(intelligenceGaps.engagementId, opts.engagementId));
  if (opts.scanId) conditions.push(eq(intelligenceGaps.scanId, opts.scanId));
  if (opts.customerId) conditions.push(eq(intelligenceGaps.customerId, opts.customerId));
  if (opts.status) conditions.push(eq(intelligenceGaps.status, opts.status));
  if (opts.category) conditions.push(eq(intelligenceGaps.category, opts.category));
  const db = await getDb();
  const query = db.select().from(intelligenceGaps).where(conditions.length > 0 ? and(...conditions) : void 0).orderBy(desc(intelligenceGaps.createdAt)).limit(opts.limit ?? 100).offset(opts.offset ?? 0);
  return query;
}
async function getGapSummary(opts) {
  const conditions = [];
  if (opts.engagementId) conditions.push(eq(intelligenceGaps.engagementId, opts.engagementId));
  if (opts.scanId) conditions.push(eq(intelligenceGaps.scanId, opts.scanId));
  if (opts.customerId) conditions.push(eq(intelligenceGaps.customerId, opts.customerId));
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const db = await getDb();
  const rows = await db.select({
    category: intelligenceGaps.category,
    status: intelligenceGaps.status,
    potentialImpact: intelligenceGaps.potentialImpact,
    cnt: count()
  }).from(intelligenceGaps).where(whereClause).groupBy(intelligenceGaps.category, intelligenceGaps.status, intelligenceGaps.potentialImpact);
  const byCategory = {};
  const byStatus = {};
  const byImpact = {};
  let total = 0;
  let openCount = 0;
  let resolvedCount = 0;
  for (const row of rows) {
    const c = Number(row.cnt);
    total += c;
    byCategory[row.category] = (byCategory[row.category] || 0) + c;
    byStatus[row.status] = (byStatus[row.status] || 0) + c;
    byImpact[row.potentialImpact || "unknown"] = (byImpact[row.potentialImpact || "unknown"] || 0) + c;
    if (row.status === "open" || row.status === "acknowledged") openCount += c;
    if (row.status === "resolved" || row.status === "mitigated") resolvedCount += c;
  }
  return { total, byCategory, byStatus, byImpact, openCount, resolvedCount };
}
async function resolveGap(gapId, resolvedBy, resolutionNote, status = "resolved") {
  const db = await getDb();
  await db.update(intelligenceGaps).set({
    status,
    resolvedBy,
    resolutionNote,
    resolvedAt: (/* @__PURE__ */ new Date()).toISOString().replace("T", " ").replace("Z", "")
  }).where(eq(intelligenceGaps.id, gapId));
}
async function updateGapStatus(gapId, status) {
  const db = await getDb();
  await db.update(intelligenceGaps).set({ status }).where(eq(intelligenceGaps.id, gapId));
}
function detectGaps(ctx) {
  const gaps = [];
  const base = {
    engagementId: ctx.engagementId,
    scanId: ctx.scanId,
    customerId: ctx.customerId,
    detectedBy: "system"
  };
  if (ctx.outOfScope && ctx.outOfScope.length > 0) {
    for (const excluded of ctx.outOfScope) {
      gaps.push({
        ...base,
        category: "scope_exclusion",
        title: `Excluded from scope: ${excluded}`,
        reason: "Asset or vector was explicitly listed in out-of-scope section of the Rules of Engagement",
        riskImplication: "Vulnerabilities in this area remain unknown and unassessed",
        potentialImpact: "medium",
        recommendation: "Consider including in future assessment scope if risk tolerance allows",
        affectedAssets: [excluded],
        tags: ["auto-detected", "scope"]
      });
    }
  }
  if (ctx.scanDurationMs && ctx.maxDurationMs && ctx.scanDurationMs >= ctx.maxDurationMs * 0.95) {
    gaps.push({
      ...base,
      category: "time_constraint",
      title: "Assessment window nearly exhausted or exceeded",
      reason: `Scan duration (${Math.round(ctx.scanDurationMs / 6e4)}m) approached or exceeded the maximum allowed window (${Math.round(ctx.maxDurationMs / 6e4)}m)`,
      riskImplication: "Some assets or attack vectors may not have been fully assessed due to time pressure",
      potentialImpact: "high",
      recommendation: "Extend assessment window or prioritize critical assets in future engagements",
      tags: ["auto-detected", "time"]
    });
  }
  if (ctx.authFailures && ctx.authFailures.length > 0) {
    for (const failure of ctx.authFailures) {
      gaps.push({
        ...base,
        category: "access_denied",
        title: `Authentication failed: ${failure.service} on ${failure.asset}`,
        reason: failure.reason || "Authentication credentials were rejected or not provided",
        riskImplication: `Authenticated vulnerability assessment of ${failure.service} was not possible \u2014 unauthenticated-only results may miss significant findings`,
        potentialImpact: "high",
        recommendation: `Provide valid credentials for ${failure.service} on ${failure.asset} to enable authenticated scanning`,
        affectedAssets: [failure.asset],
        tags: ["auto-detected", "auth"]
      });
    }
  }
  if (ctx.errorsEncountered && ctx.errorsEncountered.length > 0) {
    const byTool = /* @__PURE__ */ new Map();
    for (const err of ctx.errorsEncountered) {
      if (!byTool.has(err.tool)) byTool.set(err.tool, []);
      byTool.get(err.tool).push({ error: err.error, asset: err.asset });
    }
    for (const [tool, errors] of byTool) {
      const assets = errors.map((e) => e.asset).filter(Boolean);
      gaps.push({
        ...base,
        category: "tool_limitation",
        subcategory: tool,
        title: `${tool} encountered ${errors.length} error(s) during assessment`,
        reason: errors.map((e) => e.error).slice(0, 3).join("; "),
        riskImplication: `Findings from ${tool} may be incomplete for ${assets.length > 0 ? assets.join(", ") : "some targets"}`,
        potentialImpact: "high",
        recommendation: `Investigate ${tool} errors and re-run assessment for affected targets`,
        affectedAssets: assets.length > 0 ? assets : void 0,
        tags: ["auto-detected", "tool-error"]
      });
    }
  }
  if (ctx.scopeDomains && ctx.assetsDiscovered) {
    const discoveredSet = new Set(ctx.assetsDiscovered.map((a) => a.toLowerCase()));
    const missing = ctx.scopeDomains.filter(
      (d) => !discoveredSet.has(d.toLowerCase()) && !ctx.outOfScope?.includes(d)
    );
    if (missing.length > 0) {
      gaps.push({
        ...base,
        category: "data_unavailable",
        title: `${missing.length} scope domain(s) returned no scan data`,
        reason: "DNS resolution failed, host unreachable, or no services detected on these domains",
        riskImplication: "These domains may host vulnerable services that were not assessed",
        potentialImpact: "medium",
        recommendation: "Verify DNS records and network reachability for these domains",
        affectedAssets: missing,
        tags: ["auto-detected", "unreachable"]
      });
    }
  }
  const commonGaps = detectCommonAssessmentGaps(ctx);
  gaps.push(...commonGaps);
  return gaps;
}
function detectCommonAssessmentGaps(ctx) {
  const gaps = [];
  const base = {
    engagementId: ctx.engagementId,
    scanId: ctx.scanId,
    customerId: ctx.customerId,
    detectedBy: "system"
  };
  const toolsUsed = new Set((ctx.toolsUsed || []).map((t) => t.toLowerCase()));
  if (!toolsUsed.has("nuclei") && !toolsUsed.has("zap") && !toolsUsed.has("burp")) {
    gaps.push({
      ...base,
      category: "tool_limitation",
      subcategory: "web_app_scanning",
      title: "No dedicated web application scanner was used",
      reason: "Neither Nuclei, ZAP, nor Burp Suite was included in the tool chain",
      riskImplication: "Web application vulnerabilities (XSS, SQLi, SSRF, etc.) may not have been detected",
      potentialImpact: "high",
      recommendation: "Include a web application scanner in future assessments",
      tags: ["auto-detected", "coverage-gap"]
    });
  }
  if (!toolsUsed.has("bloodhound") && !toolsUsed.has("sharphound") && !toolsUsed.has("ad_enumeration")) {
    const hasADIndicators = ctx.servicesDetected?.some(
      (s) => s.toLowerCase().includes("ldap") || s.toLowerCase().includes("kerberos") || s.toLowerCase().includes("smb")
    );
    if (hasADIndicators) {
      gaps.push({
        ...base,
        category: "expertise_gap",
        subcategory: "active_directory",
        title: "Active Directory attack path analysis not performed",
        reason: "AD services detected but no AD-specific enumeration tools were used",
        riskImplication: "Privilege escalation paths, Kerberoasting targets, and delegation misconfigurations may exist undetected",
        potentialImpact: "critical",
        recommendation: "Run BloodHound/SharpHound collection and analyze attack paths",
        tags: ["auto-detected", "coverage-gap", "ad"]
      });
    }
  }
  const hasCloudIndicators = ctx.servicesDetected?.some(
    (s) => s.toLowerCase().includes("aws") || s.toLowerCase().includes("azure") || s.toLowerCase().includes("gcp") || s.toLowerCase().includes("s3")
  );
  if (hasCloudIndicators && !toolsUsed.has("prowler") && !toolsUsed.has("scoutsuite") && !toolsUsed.has("cloudsploit")) {
    gaps.push({
      ...base,
      category: "tool_limitation",
      subcategory: "cloud_security",
      title: "Cloud security posture assessment not performed",
      reason: "Cloud services detected but no cloud-specific security tools were used",
      riskImplication: "Cloud misconfigurations (public S3 buckets, overly permissive IAM, etc.) may exist undetected",
      potentialImpact: "high",
      recommendation: "Include cloud security posture management (CSPM) tools in future assessments",
      tags: ["auto-detected", "coverage-gap", "cloud"]
    });
  }
  return gaps;
}
function formatGapsForReport(gaps) {
  const byCategory = /* @__PURE__ */ new Map();
  let totalOpen = 0;
  let totalResolved = 0;
  for (const gap of gaps) {
    if (!byCategory.has(gap.category)) byCategory.set(gap.category, []);
    byCategory.get(gap.category).push(gap);
    if (gap.status === "open" || gap.status === "acknowledged") totalOpen++;
    if (gap.status === "resolved" || gap.status === "mitigated") totalResolved++;
  }
  const sections = Array.from(byCategory.entries()).map(([category, categoryGaps]) => ({
    category,
    categoryLabel: GAP_CATEGORY_META[category]?.label || category,
    gaps: categoryGaps.map((g) => ({
      title: g.title,
      reason: g.reason || "",
      impact: g.potentialImpact || "unknown",
      recommendation: g.recommendation || "No specific recommendation",
      assets: g.affectedAssets || []
    }))
  }));
  const summary = gaps.length === 0 ? "No intelligence gaps were identified during this assessment." : `${gaps.length} intelligence gap(s) were identified: ${totalOpen} open, ${totalResolved} resolved. Categories: ${sections.map((s) => `${s.categoryLabel} (${s.gaps.length})`).join(", ")}.`;
  return { summary, sections, totalOpen, totalResolved };
}
var GAP_CATEGORY_META;
var init_intelligence_gaps = __esm({
  "server/lib/intelligence-gaps.ts"() {
    init_db();
    init_schema();
    GAP_CATEGORY_META = {
      scope_exclusion: {
        label: "Scope Exclusion",
        description: "Asset or attack vector was explicitly excluded from the Rules of Engagement",
        defaultImpact: "medium",
        icon: "\u{1F6AB}"
      },
      tool_limitation: {
        label: "Tool Limitation",
        description: "Scanner or tool was unable to assess the target due to technical constraints",
        defaultImpact: "high",
        icon: "\u{1F527}"
      },
      time_constraint: {
        label: "Time Constraint",
        description: "Assessment window expired before this area could be fully evaluated",
        defaultImpact: "high",
        icon: "\u23F1"
      },
      access_denied: {
        label: "Access Denied",
        description: "Target refused connection, authentication failed, or access was blocked",
        defaultImpact: "high",
        icon: "\u{1F512}"
      },
      data_unavailable: {
        label: "Data Unavailable",
        description: "Required intelligence source was offline, empty, or returned no results",
        defaultImpact: "medium",
        icon: "\u{1F4ED}"
      },
      expertise_gap: {
        label: "Expertise Gap",
        description: "Assessment requires specialist knowledge or tooling not currently available",
        defaultImpact: "medium",
        icon: "\u{1F393}"
      },
      environmental_constraint: {
        label: "Environmental Constraint",
        description: "Network, infrastructure, or environmental limitation prevented assessment",
        defaultImpact: "medium",
        icon: "\u{1F310}"
      }
    };
  }
});
init_intelligence_gaps();
export {
  GAP_CATEGORY_META,
  createGap,
  createGapsBatch,
  detectGaps,
  formatGapsForReport,
  getGapSummary,
  listGaps,
  resolveGap,
  updateGapStatus
};
