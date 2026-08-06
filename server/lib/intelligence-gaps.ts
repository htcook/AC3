/**
 * Intelligence Gaps Module
 * 
 * Tracks what was NOT assessed during an engagement/DI scan and why.
 * Implements first-class gap tracking with explicit "what wasn't assessed and why"
 * following ICD 203 analytical standards for intelligence completeness.
 * 
 * Gap Categories:
 *   scope_exclusion     - Asset/vector explicitly excluded from ROE
 *   tool_limitation     - Scanner/tool couldn't assess (e.g., no auth creds, WAF blocked)
 *   time_constraint     - Assessment window expired before completion
 *   access_denied       - Target refused connection or auth failed
 *   data_unavailable    - Required intelligence source offline or empty
 *   expertise_gap       - Assessment requires specialist knowledge not available
 *   environmental_constraint - Network/infra limitation prevented assessment
 */

import { getDb } from "../db";
import { intelligenceGaps } from "../../drizzle/schema";
import { eq, and, desc, sql, inArray, isNull, isNotNull, count } from "drizzle-orm";

// ── Types ──────────────────────────────────────────────────────────────────

export type GapCategory =
  | "scope_exclusion"
  | "tool_limitation"
  | "time_constraint"
  | "access_denied"
  | "data_unavailable"
  | "expertise_gap"
  | "environmental_constraint";

export type GapStatus = "open" | "acknowledged" | "mitigated" | "resolved" | "accepted";

export type PotentialImpact = "critical" | "high" | "medium" | "low" | "unknown";

export interface IntelligenceGap {
  id?: number;
  engagementId?: number;
  scanId?: number;
  customerId?: string;
  category: GapCategory;
  subcategory?: string;
  title: string;
  description?: string;
  reason: string;
  riskImplication?: string;
  potentialImpact?: PotentialImpact;
  recommendation?: string;
  estimatedEffort?: string;
  status?: GapStatus;
  detectedBy?: string;
  confidence?: number;
  affectedAssets?: string[];
  affectedScope?: string[];
  relatedFindings?: string[];
  tags?: string[];
}

export interface GapDetectionContext {
  engagementId?: number;
  scanId?: number;
  customerId?: string;
  scopeDomains?: string[];
  scopeAssets?: string[];
  outOfScope?: string[];
  toolsUsed?: string[];
  scanDurationMs?: number;
  maxDurationMs?: number;
  findingsCount?: number;
  assetsScanned?: string[];
  assetsDiscovered?: string[];
  portsScanned?: number[];
  servicesDetected?: string[];
  errorsEncountered?: Array<{ tool: string; error: string; asset?: string }>;
  authFailures?: Array<{ asset: string; service: string; reason: string }>;
}

// ── Gap Category Metadata ──────────────────────────────────────────────────

export const GAP_CATEGORY_META: Record<GapCategory, {
  label: string;
  description: string;
  defaultImpact: PotentialImpact;
  icon: string;
}> = {
  scope_exclusion: {
    label: "Scope Exclusion",
    description: "Asset or attack vector was explicitly excluded from the Rules of Engagement",
    defaultImpact: "medium",
    icon: "🚫",
  },
  tool_limitation: {
    label: "Tool Limitation",
    description: "Scanner or tool was unable to assess the target due to technical constraints",
    defaultImpact: "high",
    icon: "🔧",
  },
  time_constraint: {
    label: "Time Constraint",
    description: "Assessment window expired before this area could be fully evaluated",
    defaultImpact: "high",
    icon: "⏱",
  },
  access_denied: {
    label: "Access Denied",
    description: "Target refused connection, authentication failed, or access was blocked",
    defaultImpact: "high",
    icon: "🔒",
  },
  data_unavailable: {
    label: "Data Unavailable",
    description: "Required intelligence source was offline, empty, or returned no results",
    defaultImpact: "medium",
    icon: "📭",
  },
  expertise_gap: {
    label: "Expertise Gap",
    description: "Assessment requires specialist knowledge or tooling not currently available",
    defaultImpact: "medium",
    icon: "🎓",
  },
  environmental_constraint: {
    label: "Environmental Constraint",
    description: "Network, infrastructure, or environmental limitation prevented assessment",
    defaultImpact: "medium",
    icon: "🌐",
  },
};

// ── Core Functions ─────────────────────────────────────────────────────────

/**
 * Create a new intelligence gap record
 */
export async function createGap(gap: IntelligenceGap): Promise<number> {
  const db = await getDb();
  const result = await db!.insert(intelligenceGaps).values({
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
    tags: gap.tags ?? null,
  });
  return (result as any)[0]?.insertId ?? 0;
}

/**
 * Create multiple gaps in a batch
 */
export async function createGapsBatch(gaps: IntelligenceGap[]): Promise<number[]> {
  const ids: number[] = [];
  for (const gap of gaps) {
    const id = await createGap(gap);
    ids.push(id);
  }
  return ids;
}

/**
 * List gaps for an engagement or scan
 */
export async function listGaps(opts: {
  engagementId?: number;
  scanId?: number;
  customerId?: string;
  status?: GapStatus;
  category?: GapCategory;
  limit?: number;
  offset?: number;
}): Promise<Array<typeof intelligenceGaps.$inferSelect>> {
  const conditions = [];
  if (opts.engagementId) conditions.push(eq(intelligenceGaps.engagementId, opts.engagementId));
  if (opts.scanId) conditions.push(eq(intelligenceGaps.scanId, opts.scanId));
  if (opts.customerId) conditions.push(eq(intelligenceGaps.customerId, opts.customerId));
  if (opts.status) conditions.push(eq(intelligenceGaps.status, opts.status));
  if (opts.category) conditions.push(eq(intelligenceGaps.category, opts.category));

  const db = await getDb();
  const query = db!
    .select()
    .from(intelligenceGaps)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(intelligenceGaps.createdAt))
    .limit(opts.limit ?? 100)
    .offset(opts.offset ?? 0);

  return query;
}

/**
 * Get gap summary statistics
 */
export async function getGapSummary(opts: {
  engagementId?: number;
  scanId?: number;
  customerId?: string;
}): Promise<{
  total: number;
  byCategory: Record<string, number>;
  byStatus: Record<string, number>;
  byImpact: Record<string, number>;
  openCount: number;
  resolvedCount: number;
}> {
  const conditions = [];
  if (opts.engagementId) conditions.push(eq(intelligenceGaps.engagementId, opts.engagementId));
  if (opts.scanId) conditions.push(eq(intelligenceGaps.scanId, opts.scanId));
  if (opts.customerId) conditions.push(eq(intelligenceGaps.customerId, opts.customerId));

  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

  const db = await getDb();
  const rows = await db!
    .select({
      category: intelligenceGaps.category,
      status: intelligenceGaps.status,
      potentialImpact: intelligenceGaps.potentialImpact,
      cnt: count(),
    })
    .from(intelligenceGaps)
    .where(whereClause)
    .groupBy(intelligenceGaps.category, intelligenceGaps.status, intelligenceGaps.potentialImpact);

  const byCategory: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  const byImpact: Record<string, number> = {};
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

/**
 * Resolve a gap
 */
export async function resolveGap(
  gapId: number,
  resolvedBy: number,
  resolutionNote: string,
  status: "resolved" | "mitigated" | "accepted" = "resolved"
): Promise<void> {
  const db = await getDb();
  await db!
    .update(intelligenceGaps)
    .set({
      status,
      resolvedBy,
      resolutionNote,
      resolvedAt: new Date().toISOString().replace("T", " ").replace("Z", ""),
    })
    .where(eq(intelligenceGaps.id, gapId));
}

/**
 * Update a gap's status
 */
export async function updateGapStatus(gapId: number, status: GapStatus): Promise<void> {
  const db = await getDb();
  await db!
    .update(intelligenceGaps)
    .set({ status })
    .where(eq(intelligenceGaps.id, gapId));
}

// ── Automated Gap Detection ────────────────────────────────────────────────

/**
 * Automatically detect intelligence gaps from engagement/scan context.
 * This analyzes what was scoped vs. what was actually assessed to identify gaps.
 */
export function detectGaps(ctx: GapDetectionContext): IntelligenceGap[] {
  const gaps: IntelligenceGap[] = [];
  const base = {
    engagementId: ctx.engagementId,
    scanId: ctx.scanId,
    customerId: ctx.customerId,
    detectedBy: "system" as const,
  };

  // 1. Scope exclusion gaps — assets in scope but explicitly excluded
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
        tags: ["auto-detected", "scope"],
      });
    }
  }

  // 2. Time constraint gaps — scan took too long
  if (ctx.scanDurationMs && ctx.maxDurationMs && ctx.scanDurationMs >= ctx.maxDurationMs * 0.95) {
    gaps.push({
      ...base,
      category: "time_constraint",
      title: "Assessment window nearly exhausted or exceeded",
      reason: `Scan duration (${Math.round(ctx.scanDurationMs / 60000)}m) approached or exceeded the maximum allowed window (${Math.round(ctx.maxDurationMs / 60000)}m)`,
      riskImplication: "Some assets or attack vectors may not have been fully assessed due to time pressure",
      potentialImpact: "high",
      recommendation: "Extend assessment window or prioritize critical assets in future engagements",
      tags: ["auto-detected", "time"],
    });
  }

  // 3. Access denied gaps — auth failures
  if (ctx.authFailures && ctx.authFailures.length > 0) {
    for (const failure of ctx.authFailures) {
      gaps.push({
        ...base,
        category: "access_denied",
        title: `Authentication failed: ${failure.service} on ${failure.asset}`,
        reason: failure.reason || "Authentication credentials were rejected or not provided",
        riskImplication: `Authenticated vulnerability assessment of ${failure.service} was not possible — unauthenticated-only results may miss significant findings`,
        potentialImpact: "high",
        recommendation: `Provide valid credentials for ${failure.service} on ${failure.asset} to enable authenticated scanning`,
        affectedAssets: [failure.asset],
        tags: ["auto-detected", "auth"],
      });
    }
  }

  // 4. Tool error gaps — scanner errors
  if (ctx.errorsEncountered && ctx.errorsEncountered.length > 0) {
    // Group errors by tool
    const byTool = new Map<string, Array<{ error: string; asset?: string }>>();
    for (const err of ctx.errorsEncountered) {
      if (!byTool.has(err.tool)) byTool.set(err.tool, []);
      byTool.get(err.tool)!.push({ error: err.error, asset: err.asset });
    }

    for (const [tool, errors] of byTool) {
      const assets = errors.map((e) => e.asset).filter(Boolean) as string[];
      gaps.push({
        ...base,
        category: "tool_limitation",
        subcategory: tool,
        title: `${tool} encountered ${errors.length} error(s) during assessment`,
        reason: errors.map((e) => e.error).slice(0, 3).join("; "),
        riskImplication: `Findings from ${tool} may be incomplete for ${assets.length > 0 ? assets.join(", ") : "some targets"}`,
        potentialImpact: "high",
        recommendation: `Investigate ${tool} errors and re-run assessment for affected targets`,
        affectedAssets: assets.length > 0 ? assets : undefined,
        tags: ["auto-detected", "tool-error"],
      });
    }
  }

  // 5. Undiscovered assets gap — scope domains that weren't found in scan
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
        tags: ["auto-detected", "unreachable"],
      });
    }
  }

  // 6. Common assessment gaps — things most scans miss
  const commonGaps = detectCommonAssessmentGaps(ctx);
  gaps.push(...commonGaps);

  return gaps;
}

/**
 * Detect common assessment gaps that most automated scans miss
 */
function detectCommonAssessmentGaps(ctx: GapDetectionContext): IntelligenceGap[] {
  const gaps: IntelligenceGap[] = [];
  const base = {
    engagementId: ctx.engagementId,
    scanId: ctx.scanId,
    customerId: ctx.customerId,
    detectedBy: "system" as const,
  };

  const toolsUsed = new Set((ctx.toolsUsed || []).map((t) => t.toLowerCase()));

  // Check for missing assessment categories
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
      tags: ["auto-detected", "coverage-gap"],
    });
  }

  if (!toolsUsed.has("bloodhound") && !toolsUsed.has("sharphound") && !toolsUsed.has("ad_enumeration")) {
    // Only flag if there are Windows/AD indicators
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
        tags: ["auto-detected", "coverage-gap", "ad"],
      });
    }
  }

  // Check for cloud-specific gaps
  const hasCloudIndicators = ctx.servicesDetected?.some(
    (s) =>
      s.toLowerCase().includes("aws") ||
      s.toLowerCase().includes("azure") ||
      s.toLowerCase().includes("gcp") ||
      s.toLowerCase().includes("s3")
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
      tags: ["auto-detected", "coverage-gap", "cloud"],
    });
  }

  return gaps;
}

/**
 * Format gaps for report output
 */
export function formatGapsForReport(gaps: Array<typeof intelligenceGaps.$inferSelect>): {
  summary: string;
  sections: Array<{
    category: string;
    categoryLabel: string;
    gaps: Array<{
      title: string;
      reason: string;
      impact: string;
      recommendation: string;
      assets: string[];
    }>;
  }>;
  totalOpen: number;
  totalResolved: number;
} {
  const byCategory = new Map<string, Array<typeof intelligenceGaps.$inferSelect>>();
  let totalOpen = 0;
  let totalResolved = 0;

  for (const gap of gaps) {
    if (!byCategory.has(gap.category)) byCategory.set(gap.category, []);
    byCategory.get(gap.category)!.push(gap);
    if (gap.status === "open" || gap.status === "acknowledged") totalOpen++;
    if (gap.status === "resolved" || gap.status === "mitigated") totalResolved++;
  }

  const sections = Array.from(byCategory.entries()).map(([category, categoryGaps]) => ({
    category,
    categoryLabel: GAP_CATEGORY_META[category as GapCategory]?.label || category,
    gaps: categoryGaps.map((g) => ({
      title: g.title,
      reason: g.reason || "",
      impact: g.potentialImpact || "unknown",
      recommendation: g.recommendation || "No specific recommendation",
      assets: (g.affectedAssets as string[]) || [],
    })),
  }));

  const summary =
    gaps.length === 0
      ? "No intelligence gaps were identified during this assessment."
      : `${gaps.length} intelligence gap(s) were identified: ${totalOpen} open, ${totalResolved} resolved. ` +
        `Categories: ${sections.map((s) => `${s.categoryLabel} (${s.gaps.length})`).join(", ")}.`;

  return { summary, sections, totalOpen, totalResolved };
}
