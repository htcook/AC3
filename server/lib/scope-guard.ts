/**
 * Centralized ROE Scope Guard
 *
 * Validates that every active-scan target (IP, CIDR, domain, URL) falls
 * within the engagement's ROE-defined scope before any tool touches it.
 *
 * Data sources (checked in order, merged):
 *   1. engagement.roeScope          — quick JSON blob on the engagement row
 *   2. roeDocuments.*               — full NIST 800-115 §4 scope fields
 *
 * Enforcement layers:
 *   - IP / CIDR membership (in-scope ranges, out-of-scope ranges)
 *   - Domain / subdomain matching (with wildcard + includeSubdomains)
 *   - Application URL matching
 *   - Testing-window enforcement (day-of-week + hour range + timezone)
 *   - ROE permission flags (DoS, social engineering, pivoting, etc.)
 *   - Audit logging of every BLOCKED attempt
 *
 * Author: Harrison Cook — AceofCloud
 */
import { TRPCError } from "@trpc/server";
import * as net from "net";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ScopeCheckResult {
  allowed: boolean;
  reason: string;
  /** Which scope rule matched (for audit) */
  matchedRule?: string;
  /** The normalised target that was checked */
  normalisedTarget: string;
}

export interface ScopeTarget {
  /** IP address, CIDR, domain, hostname, or URL */
  value: string;
  /** Optional port (used for application-URL matching) */
  port?: number;
  /** Hint so the guard can pick the right matching strategy */
  type?: "ip" | "cidr" | "domain" | "url";
}

/** Mirrors the ROE document scope fields from drizzle/schema.ts */
export interface ROEScopeData {
  // From engagement.roeScope (quick JSON)
  inScopeIpRanges?: Array<{ cidr: string; description?: string; vlan?: string; location?: string }>;
  outOfScopeIpRanges?: Array<{ cidr: string; description?: string }>;
  inScopeDomains?: Array<{ domain: string; includeSubdomains?: boolean; description?: string }>;
  outOfScopeDomains?: Array<{ domain: string; includeSubdomains?: boolean; description?: string }>;
  inScopeAssets?: Array<{ name: string; ipAddress?: string; hostname?: string; type?: string }>;
  outOfScopeAssets?: Array<{ name: string; ipAddress?: string; hostname?: string; type?: string }>;
  inScopeApplications?: Array<{ name: string; url?: string; type?: string }>;
  // Testing-window fields (from roeDocuments)
  testingWindowStart?: string | null;  // "HH:mm" or "HH:MM"
  testingWindowEnd?: string | null;
  testingDays?: string[] | null;       // ["monday","tuesday",...]
  testTimezone?: string | null;
  testScheduleStart?: Date | string | null;
  testScheduleEnd?: Date | string | null;
  // Permission flags
  dosTestingAllowed?: boolean;
  socialEngineeringAllowed?: boolean;
  pivotingAllowed?: boolean;
  exfiltrationAllowed?: boolean;
  persistenceAllowed?: boolean;
  fileModificationAllowed?: boolean;
  fileInstallationAllowed?: boolean;
  physicalTestingAllowed?: boolean;
  wirelessTestingAllowed?: boolean;
}

export type PermissionFlag =
  | "dos"
  | "social_engineering"
  | "pivoting"
  | "exfiltration"
  | "persistence"
  | "file_modification"
  | "file_installation"
  | "physical"
  | "wireless";

// ─── IP / CIDR Utilities ────────────────────────────────────────────────────

/** Parse an IPv4 address to a 32-bit number */
function ipv4ToLong(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** Check if an IPv4 address falls inside a CIDR block */
function ipInCidr(ip: string, cidr: string): boolean {
  // Handle single IP (no slash)
  if (!cidr.includes("/")) {
    return ip === cidr;
  }
  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);
  if (prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const ipLong = ipv4ToLong(ip);
  const netLong = ipv4ToLong(network);
  return (ipLong & mask) === (netLong & mask);
}

/** Check if one CIDR fully contains another CIDR */
function cidrContainsCidr(outer: string, inner: string): boolean {
  const [outerNet, outerPrefixStr] = outer.includes("/") ? outer.split("/") : [outer, "32"];
  const [innerNet, innerPrefixStr] = inner.includes("/") ? inner.split("/") : [inner, "32"];
  const outerPrefix = parseInt(outerPrefixStr, 10);
  const innerPrefix = parseInt(innerPrefixStr, 10);
  // Inner prefix must be >= outer prefix (smaller or equal network)
  if (innerPrefix < outerPrefix) return false;
  const mask = outerPrefix === 0 ? 0 : (~0 << (32 - outerPrefix)) >>> 0;
  return (ipv4ToLong(innerNet) & mask) === (ipv4ToLong(outerNet) & mask);
}

/** Normalise a target string and detect its type */
function classifyTarget(target: ScopeTarget): { type: "ip" | "cidr" | "domain" | "url"; value: string } {
  if (target.type) return { type: target.type, value: target.value.trim() };

  const val = target.value.trim();

  // URL?
  if (/^https?:\/\//i.test(val)) {
    return { type: "url", value: val };
  }
  // CIDR?
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(val)) {
    return { type: "cidr", value: val };
  }
  // IPv4?
  if (net.isIPv4(val)) {
    return { type: "ip", value: val };
  }
  // IPv6?
  if (net.isIPv6(val)) {
    return { type: "ip", value: val };
  }
  // Default: treat as domain
  return { type: "domain", value: val.toLowerCase() };
}

/** Extract hostname from a URL */
function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    // Fallback: strip protocol and path
    return url.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase();
  }
}

// ─── Domain Matching ────────────────────────────────────────────────────────

/** Check if a target domain matches a scope domain entry */
function domainMatches(
  targetDomain: string,
  scopeDomain: string,
  includeSubdomains: boolean
): boolean {
  const target = targetDomain.toLowerCase().replace(/\.$/, "");
  const scope = scopeDomain.toLowerCase().replace(/\.$/, "");

  // Exact match
  if (target === scope) return true;

  // Subdomain match
  if (includeSubdomains && target.endsWith(`.${scope}`)) return true;

  return false;
}

// ─── Core Scope Checker ─────────────────────────────────────────────────────

/**
 * Check whether a single target is within the ROE scope.
 *
 * Logic:
 *   1. If target matches any out-of-scope rule → BLOCKED (explicit exclusion wins)
 *   2. If target matches any in-scope rule → ALLOWED
 *   3. If no rules match at all → BLOCKED (default-deny)
 */
export function checkTargetScope(
  target: ScopeTarget,
  scope: ROEScopeData
): ScopeCheckResult {
  const classified = classifyTarget(target);
  const normalisedTarget = classified.value;

  // ── Step 0: If scope has zero in-scope rules, block everything ──
  const hasAnyInScopeRules =
    (scope.inScopeIpRanges && scope.inScopeIpRanges.length > 0) ||
    (scope.inScopeDomains && scope.inScopeDomains.length > 0) ||
    (scope.inScopeAssets && scope.inScopeAssets.length > 0) ||
    (scope.inScopeApplications && scope.inScopeApplications.length > 0);

  if (!hasAnyInScopeRules) {
    return {
      allowed: false,
      reason: "No in-scope rules defined in ROE. Cannot validate target. Define scope before running active tools.",
      normalisedTarget,
    };
  }

  // ── Step 1: Check OUT-OF-SCOPE (explicit exclusion wins) ──

  // Out-of-scope IP ranges
  if (scope.outOfScopeIpRanges) {
    for (const range of scope.outOfScopeIpRanges) {
      if (classified.type === "ip" && ipInCidr(normalisedTarget, range.cidr)) {
        return {
          allowed: false,
          reason: `Target IP ${normalisedTarget} is explicitly OUT OF SCOPE (matches exclusion ${range.cidr}${range.description ? `: ${range.description}` : ""})`,
          matchedRule: `out_of_scope_ip:${range.cidr}`,
          normalisedTarget,
        };
      }
      if (classified.type === "cidr" && cidrContainsCidr(range.cidr, normalisedTarget)) {
        return {
          allowed: false,
          reason: `Target CIDR ${normalisedTarget} overlaps with OUT OF SCOPE range ${range.cidr}`,
          matchedRule: `out_of_scope_ip:${range.cidr}`,
          normalisedTarget,
        };
      }
    }
  }

  // Out-of-scope domains
  if (scope.outOfScopeDomains) {
    const targetDomain =
      classified.type === "url" ? hostnameFromUrl(normalisedTarget) :
      classified.type === "domain" ? normalisedTarget : null;

    if (targetDomain) {
      for (const d of scope.outOfScopeDomains) {
        if (domainMatches(targetDomain, d.domain, d.includeSubdomains !== false)) {
          return {
            allowed: false,
            reason: `Target domain "${targetDomain}" is explicitly OUT OF SCOPE (matches exclusion ${d.domain})`,
            matchedRule: `out_of_scope_domain:${d.domain}`,
            normalisedTarget,
          };
        }
      }
    }
  }

  // Out-of-scope assets (by IP or hostname)
  if (scope.outOfScopeAssets) {
    for (const asset of scope.outOfScopeAssets) {
      if (asset.ipAddress && classified.type === "ip" && normalisedTarget === asset.ipAddress) {
        return {
          allowed: false,
          reason: `Target IP ${normalisedTarget} matches OUT OF SCOPE asset "${asset.name}"`,
          matchedRule: `out_of_scope_asset:${asset.name}`,
          normalisedTarget,
        };
      }
      if (asset.hostname) {
        const targetDomain =
          classified.type === "url" ? hostnameFromUrl(normalisedTarget) :
          classified.type === "domain" ? normalisedTarget : null;
        if (targetDomain && targetDomain === asset.hostname.toLowerCase()) {
          return {
            allowed: false,
            reason: `Target "${targetDomain}" matches OUT OF SCOPE asset "${asset.name}"`,
            matchedRule: `out_of_scope_asset:${asset.name}`,
            normalisedTarget,
          };
        }
      }
    }
  }

  // ── Step 2: Check IN-SCOPE ──
  let inScope = false;
  let matchedRule = "";

  // In-scope IP ranges
  if (scope.inScopeIpRanges && (classified.type === "ip" || classified.type === "cidr")) {
    for (const range of scope.inScopeIpRanges) {
      if (classified.type === "ip" && ipInCidr(normalisedTarget, range.cidr)) {
        inScope = true;
        matchedRule = `in_scope_ip:${range.cidr}`;
        break;
      }
      if (classified.type === "cidr" && cidrContainsCidr(range.cidr, normalisedTarget)) {
        inScope = true;
        matchedRule = `in_scope_ip:${range.cidr}`;
        break;
      }
    }
  }

  // In-scope domains
  if (!inScope && scope.inScopeDomains) {
    const targetDomain =
      classified.type === "url" ? hostnameFromUrl(normalisedTarget) :
      classified.type === "domain" ? normalisedTarget : null;

    if (targetDomain) {
      for (const d of scope.inScopeDomains) {
        if (domainMatches(targetDomain, d.domain, d.includeSubdomains !== false)) {
          inScope = true;
          matchedRule = `in_scope_domain:${d.domain}`;
          break;
        }
      }
    }
  }

  // In-scope assets (by IP or hostname)
  if (!inScope && scope.inScopeAssets) {
    for (const asset of scope.inScopeAssets) {
      if (asset.ipAddress && classified.type === "ip" && normalisedTarget === asset.ipAddress) {
        inScope = true;
        matchedRule = `in_scope_asset:${asset.name}`;
        break;
      }
      if (asset.hostname) {
        const targetDomain =
          classified.type === "url" ? hostnameFromUrl(normalisedTarget) :
          classified.type === "domain" ? normalisedTarget : null;
        if (targetDomain && targetDomain === asset.hostname.toLowerCase()) {
          inScope = true;
          matchedRule = `in_scope_asset:${asset.name}`;
          break;
        }
      }
    }
  }

  // In-scope applications (URL matching)
  if (!inScope && scope.inScopeApplications && classified.type === "url") {
    for (const app of scope.inScopeApplications) {
      if (app.url) {
        const appHost = hostnameFromUrl(app.url);
        const targetHost = hostnameFromUrl(normalisedTarget);
        if (targetHost === appHost) {
          inScope = true;
          matchedRule = `in_scope_app:${app.name}`;
          break;
        }
      }
    }
  }

  // ── Step 3: Default-deny ──
  if (!inScope) {
    return {
      allowed: false,
      reason: `Target "${normalisedTarget}" does not match any in-scope rule. Default-deny policy blocks all unrecognised targets.`,
      normalisedTarget,
    };
  }

  return {
    allowed: true,
    reason: `Target "${normalisedTarget}" is within ROE scope`,
    matchedRule,
    normalisedTarget,
  };
}

// ─── Testing Window Enforcement ─────────────────────────────────────────────

/**
 * Check whether the current time falls within the ROE testing window.
 */
export function checkTestingWindow(scope: ROEScopeData): ScopeCheckResult {
  const now = new Date();

  // Check overall schedule dates
  if (scope.testScheduleStart) {
    const start = new Date(scope.testScheduleStart);
    if (now < start) {
      return {
        allowed: false,
        reason: `Testing has not started yet. Scheduled start: ${start.toISOString()}`,
        normalisedTarget: "time_window",
      };
    }
  }
  if (scope.testScheduleEnd) {
    const end = new Date(scope.testScheduleEnd);
    if (now > end) {
      return {
        allowed: false,
        reason: `Testing period has ended. Scheduled end: ${end.toISOString()}`,
        normalisedTarget: "time_window",
      };
    }
  }

  // Check day-of-week
  if (scope.testingDays && scope.testingDays.length > 0) {
    const dayNames = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
    // Get current day in the testing timezone
    let currentDay: string;
    try {
      const tz = scope.testTimezone || "UTC";
      const formatter = new Intl.DateTimeFormat("en-US", { weekday: "long", timeZone: tz });
      currentDay = formatter.format(now).toLowerCase();
    } catch {
      currentDay = dayNames[now.getUTCDay()];
    }

    const allowedDays = scope.testingDays.map(d => d.toLowerCase());
    if (!allowedDays.includes(currentDay)) {
      return {
        allowed: false,
        reason: `Testing is not allowed on ${currentDay}. Allowed days: ${allowedDays.join(", ")}`,
        normalisedTarget: "time_window",
      };
    }
  }

  // Check time-of-day window
  if (scope.testingWindowStart && scope.testingWindowEnd) {
    let currentHour: number;
    let currentMinute: number;
    try {
      const tz = scope.testTimezone || "UTC";
      const hourFmt = new Intl.DateTimeFormat("en-US", { hour: "numeric", hour12: false, timeZone: tz });
      const minFmt = new Intl.DateTimeFormat("en-US", { minute: "numeric", timeZone: tz });
      currentHour = parseInt(hourFmt.format(now), 10);
      currentMinute = parseInt(minFmt.format(now), 10);
    } catch {
      currentHour = now.getUTCHours();
      currentMinute = now.getUTCMinutes();
    }

    const [startH, startM] = scope.testingWindowStart.split(":").map(Number);
    const [endH, endM] = scope.testingWindowEnd.split(":").map(Number);
    const currentMinutes = currentHour * 60 + currentMinute;
    const startMinutes = startH * 60 + startM;
    const endMinutes = endH * 60 + endM;

    let withinWindow: boolean;
    if (startMinutes <= endMinutes) {
      // Normal window (e.g., 09:00 - 17:00)
      withinWindow = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } else {
      // Overnight window (e.g., 22:00 - 06:00)
      withinWindow = currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }

    if (!withinWindow) {
      return {
        allowed: false,
        reason: `Current time is outside the testing window (${scope.testingWindowStart} - ${scope.testingWindowEnd} ${scope.testTimezone || "UTC"})`,
        normalisedTarget: "time_window",
      };
    }
  }

  return {
    allowed: true,
    reason: "Within testing window",
    normalisedTarget: "time_window",
  };
}

// ─── Permission Flag Check ──────────────────────────────────────────────────

/**
 * Check whether a specific ROE permission flag is enabled.
 */
export function checkPermission(
  scope: ROEScopeData,
  flag: PermissionFlag
): ScopeCheckResult {
  const flagMap: Record<PermissionFlag, { field: keyof ROEScopeData; label: string }> = {
    dos: { field: "dosTestingAllowed", label: "Denial of Service testing" },
    social_engineering: { field: "socialEngineeringAllowed", label: "Social engineering" },
    pivoting: { field: "pivotingAllowed", label: "Pivoting / lateral movement" },
    exfiltration: { field: "exfiltrationAllowed", label: "Data exfiltration" },
    persistence: { field: "persistenceAllowed", label: "Persistence mechanisms" },
    file_modification: { field: "fileModificationAllowed", label: "File modification on target" },
    file_installation: { field: "fileInstallationAllowed", label: "Software installation on target" },
    physical: { field: "physicalTestingAllowed", label: "Physical security testing" },
    wireless: { field: "wirelessTestingAllowed", label: "Wireless network testing" },
  };

  const mapping = flagMap[flag];
  const allowed = scope[mapping.field] === true;

  return {
    allowed,
    reason: allowed
      ? `${mapping.label} is permitted by ROE`
      : `${mapping.label} is NOT permitted by ROE. This operation requires explicit authorisation in the Rules of Engagement.`,
    matchedRule: `permission:${flag}`,
    normalisedTarget: `permission_check:${flag}`,
  };
}

// ─── Scope Data Loader ──────────────────────────────────────────────────────

/**
 * Load and merge scope data from both engagement.roeScope and roeDocuments.
 * The roeDocuments fields take precedence where both exist.
 */
export async function loadEngagementScope(engagementId: number): Promise<ROEScopeData | null> {
  try {
    const { getDb } = await import("../db");
    const { engagements, roeDocuments } = await import("../../drizzle/schema");
    const { eq, desc } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return null;

    // Get engagement with roeScope + target fields
    const [eng] = await db
      .select({
        roeScope: engagements.roeScope,
        roeDocumentId: engagements.roeDocumentId,
        roeStatus: engagements.roeStatus,
        roeExpiryDate: engagements.roeExpiryDate,
        targetDomain: engagements.targetDomain,
        targetIpRange: engagements.targetIpRange,
      })
      .from(engagements)
      .where(eq(engagements.id, engagementId))
      .limit(1);

    if (!eng) return null;

    // Start with engagement.roeScope
    const scope: ROEScopeData = (eng.roeScope as ROEScopeData) || {};

    // Merge engagement-level targetDomain and targetIpRange as baseline scope
    // These are always enforced even if the RoE document hasn't been fully completed
    if (eng.targetDomain) {
      const domains = eng.targetDomain.split(/[,;\s]+/).map((d: string) => d.trim()).filter(Boolean);
      if (!scope.inScopeDomains) scope.inScopeDomains = [];
      for (const domain of domains) {
        const alreadyExists = scope.inScopeDomains.some(d => d.domain.toLowerCase() === domain.toLowerCase());
        if (!alreadyExists) {
          scope.inScopeDomains.push({ domain, includeSubdomains: true, description: 'From engagement builder' });
        }
      }
    }
    if (eng.targetIpRange) {
      const ranges = eng.targetIpRange.split(/[,;\s]+/).map((r: string) => r.trim()).filter(Boolean);
      if (!scope.inScopeIpRanges) scope.inScopeIpRanges = [];
      for (const range of ranges) {
        const cidr = range.includes('/') ? range : `${range}/32`;
        const alreadyExists = scope.inScopeIpRanges.some(r => r.cidr === cidr);
        if (!alreadyExists) {
          scope.inScopeIpRanges.push({ cidr, description: 'From engagement builder' });
        }
      }
    }

    // Try to load the linked ROE document for richer scope data
    let roeDoc: any = null;
    if (eng.roeDocumentId) {
      const [doc] = await db
        .select()
        .from(roeDocuments)
        .where(eq(roeDocuments.id, eng.roeDocumentId))
        .limit(1);
      roeDoc = doc;
    } else {
      // Fallback: get the latest active/approved ROE document for this engagement
      const docs = await db
        .select()
        .from(roeDocuments)
        .where(eq(roeDocuments.engagementId, engagementId))
        .orderBy(desc(roeDocuments.updatedAt))
        .limit(1);
      roeDoc = docs[0] || null;
    }

    if (roeDoc) {
      // Merge ROE document fields (document takes precedence)
      if (roeDoc.inScopeIpRanges) scope.inScopeIpRanges = roeDoc.inScopeIpRanges as any;
      if (roeDoc.outOfScopeIpRanges) scope.outOfScopeIpRanges = roeDoc.outOfScopeIpRanges as any;
      if (roeDoc.inScopeDomains) scope.inScopeDomains = roeDoc.inScopeDomains as any;
      if (roeDoc.outOfScopeDomains) scope.outOfScopeDomains = roeDoc.outOfScopeDomains as any;
      if (roeDoc.inScopeAssets) scope.inScopeAssets = roeDoc.inScopeAssets as any;
      if (roeDoc.outOfScopeAssets) scope.outOfScopeAssets = roeDoc.outOfScopeAssets as any;
      if (roeDoc.inScopeApplications) scope.inScopeApplications = roeDoc.inScopeApplications as any;

      // Testing window
      scope.testingWindowStart = roeDoc.testingWindowStart;
      scope.testingWindowEnd = roeDoc.testingWindowEnd;
      scope.testingDays = roeDoc.testingDays as string[] | null;
      scope.testTimezone = roeDoc.testTimezone;
      scope.testScheduleStart = roeDoc.testScheduleStart;
      scope.testScheduleEnd = roeDoc.testScheduleEnd;

      // Permission flags
      scope.dosTestingAllowed = roeDoc.dosTestingAllowed ?? false;
      scope.socialEngineeringAllowed = roeDoc.socialEngineeringAllowed ?? false;
      scope.pivotingAllowed = roeDoc.pivotingAllowed ?? true;
      scope.exfiltrationAllowed = roeDoc.exfiltrationAllowed ?? false;
      scope.persistenceAllowed = roeDoc.persistenceAllowed ?? false;
      scope.fileModificationAllowed = roeDoc.fileModificationAllowed ?? false;
      scope.fileInstallationAllowed = roeDoc.fileInstallationAllowed ?? false;
      scope.physicalTestingAllowed = roeDoc.physicalTestingAllowed ?? false;
      scope.wirelessTestingAllowed = roeDoc.wirelessTestingAllowed ?? false;
    }

    return scope;
  } catch (err: any) {
    console.error("[ScopeGuard] Failed to load engagement scope:", err.message);
    return null;
  }
}

// ─── High-Level Enforcement ─────────────────────────────────────────────────

export interface EnforceScopeOptions {
  engagementId: number;
  targets: ScopeTarget[];
  /** The tool or module requesting access */
  tool: string;
  /** Operator info for audit logging */
  operatorId: string;
  operatorName?: string;
  /** Permission flags required for this operation */
  requiredPermissions?: PermissionFlag[];
  /** Skip testing-window check (for passive-only operations) */
  skipTimeWindow?: boolean;
}

export interface EnforceScopeResult {
  allAllowed: boolean;
  results: Array<ScopeTarget & ScopeCheckResult>;
  blockedTargets: string[];
  timeWindowResult?: ScopeCheckResult;
  permissionResults?: Array<{ flag: PermissionFlag } & ScopeCheckResult>;
}

/**
 * Full enforcement: loads scope, checks every target, checks time window,
 * checks permissions, logs violations, and throws on any failure.
 *
 * Call this before EVERY active tool dispatch.
 */
export async function enforceScope(opts: EnforceScopeOptions): Promise<EnforceScopeResult> {
  const scope = await loadEngagementScope(opts.engagementId);

  if (!scope) {
    // Log and block — no scope data means we cannot validate
    await logScopeViolation({
      engagementId: opts.engagementId,
      operatorId: opts.operatorId,
      operatorName: opts.operatorName,
      tool: opts.tool,
      target: opts.targets.map(t => t.value).join(", "),
      reason: "No ROE scope data found for engagement",
    });
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[SCOPE GUARD] No ROE scope data found for engagement #${opts.engagementId}. Cannot proceed with active operations.`,
    });
  }

  const result: EnforceScopeResult = {
    allAllowed: true,
    results: [],
    blockedTargets: [],
  };

  // ── Check testing window ──
  if (!opts.skipTimeWindow) {
    const twResult = checkTestingWindow(scope);
    result.timeWindowResult = twResult;
    if (!twResult.allowed) {
      result.allAllowed = false;
      await logScopeViolation({
        engagementId: opts.engagementId,
        operatorId: opts.operatorId,
        operatorName: opts.operatorName,
        tool: opts.tool,
        target: opts.targets.map(t => t.value).join(", "),
        reason: twResult.reason,
      });
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: `[SCOPE GUARD] ${twResult.reason}`,
      });
    }
  }

  // ── Check permission flags ──
  if (opts.requiredPermissions && opts.requiredPermissions.length > 0) {
    result.permissionResults = [];
    for (const flag of opts.requiredPermissions) {
      const permResult = checkPermission(scope, flag);
      result.permissionResults.push({ flag, ...permResult });
      if (!permResult.allowed) {
        result.allAllowed = false;
        await logScopeViolation({
          engagementId: opts.engagementId,
          operatorId: opts.operatorId,
          operatorName: opts.operatorName,
          tool: opts.tool,
          target: `permission:${flag}`,
          reason: permResult.reason,
        });
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: `[SCOPE GUARD] ${permResult.reason}`,
        });
      }
    }
  }

  // ── Check each target ──
  for (const target of opts.targets) {
    const checkResult = checkTargetScope(target, scope);
    result.results.push({ ...target, ...checkResult });

    if (!checkResult.allowed) {
      result.allAllowed = false;
      result.blockedTargets.push(target.value);

      await logScopeViolation({
        engagementId: opts.engagementId,
        operatorId: opts.operatorId,
        operatorName: opts.operatorName,
        tool: opts.tool,
        target: target.value,
        reason: checkResult.reason,
      });
    }
  }

  // If any target was blocked, throw
  if (!result.allAllowed) {
    const blockedSummary = result.blockedTargets.join(", ");
    const reasons = result.results
      .filter(r => !r.allowed)
      .map(r => `  - ${r.value}: ${r.reason}`)
      .join("\n");

    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[SCOPE GUARD] ${result.blockedTargets.length} target(s) blocked — outside ROE scope:\n${reasons}`,
    });
  }

  return result;
}

/**
 * Non-throwing variant: returns the result without throwing.
 * Use this when you want to filter targets rather than block the entire operation.
 */
export async function checkScope(opts: EnforceScopeOptions): Promise<EnforceScopeResult> {
  const scope = await loadEngagementScope(opts.engagementId);

  if (!scope) {
    return {
      allAllowed: false,
      results: opts.targets.map(t => ({
        ...t,
        allowed: false,
        reason: "No ROE scope data found",
        normalisedTarget: t.value,
      })),
      blockedTargets: opts.targets.map(t => t.value),
    };
  }

  const result: EnforceScopeResult = {
    allAllowed: true,
    results: [],
    blockedTargets: [],
  };

  // Check time window
  if (!opts.skipTimeWindow) {
    const twResult = checkTestingWindow(scope);
    result.timeWindowResult = twResult;
    if (!twResult.allowed) {
      result.allAllowed = false;
    }
  }

  // Check permissions
  if (opts.requiredPermissions) {
    result.permissionResults = [];
    for (const flag of opts.requiredPermissions) {
      const permResult = checkPermission(scope, flag);
      result.permissionResults.push({ flag, ...permResult });
      if (!permResult.allowed) result.allAllowed = false;
    }
  }

  // Check targets
  for (const target of opts.targets) {
    const checkResult = checkTargetScope(target, scope);
    result.results.push({ ...target, ...checkResult });
    if (!checkResult.allowed) {
      result.allAllowed = false;
      result.blockedTargets.push(target.value);
    }
  }

  return result;
}

/**
 * Filter a list of targets, returning only those within scope.
 * Logs blocked targets to audit but does not throw.
 */
export async function filterInScopeTargets(
  engagementId: number,
  targets: ScopeTarget[],
  tool: string,
  operatorId: string,
  operatorName?: string,
): Promise<{ inScope: ScopeTarget[]; outOfScope: Array<ScopeTarget & { reason: string }> }> {
  const scope = await loadEngagementScope(engagementId);

  if (!scope) {
    return {
      inScope: [],
      outOfScope: targets.map(t => ({ ...t, reason: "No ROE scope data found" })),
    };
  }

  const inScope: ScopeTarget[] = [];
  const outOfScope: Array<ScopeTarget & { reason: string }> = [];

  for (const target of targets) {
    const result = checkTargetScope(target, scope);
    if (result.allowed) {
      inScope.push(target);
    } else {
      outOfScope.push({ ...target, reason: result.reason });
      await logScopeViolation({
        engagementId,
        operatorId,
        operatorName,
        tool,
        target: target.value,
        reason: result.reason,
      });
    }
  }

  return { inScope, outOfScope };
}

// ─── Audit Logging ──────────────────────────────────────────────────────────

interface ScopeViolationEntry {
  engagementId: number;
  operatorId: string;
  operatorName?: string;
  tool: string;
  target: string;
  reason: string;
}

/**
 * Log a scope violation to the offensive audit log.
 */
async function logScopeViolation(entry: ScopeViolationEntry): Promise<void> {
  try {
    const { logOffensiveAction } = await import("./roe-guard");
    await logOffensiveAction({
      engagementId: entry.engagementId,
      operatorId: entry.operatorId,
      operatorName: entry.operatorName ?? null,
      actionType: "active_probe",
      riskTier: "red",
      target: entry.target,
      moduleOrTool: entry.tool,
      roeStatus: "signed",
      actionDetail: {
        scopeViolation: true,
        reason: entry.reason,
        blockedAt: new Date().toISOString(),
      },
      resultStatus: "blocked",
      resultDetail: `[SCOPE GUARD BLOCKED] ${entry.reason}`,
    });
  } catch (err: any) {
    console.error("[ScopeGuard] Failed to log scope violation:", err.message);
  }
}

// ─── Convenience: Quick single-target check ─────────────────────────────────

/**
 * Quick check for a single target. Throws if out of scope.
 */
export async function enforceSingleTarget(
  engagementId: number,
  target: string,
  tool: string,
  operatorId: string,
  operatorName?: string,
  requiredPermissions?: PermissionFlag[],
): Promise<void> {
  await enforceScope({
    engagementId,
    targets: [{ value: target }],
    tool,
    operatorId,
    operatorName,
    requiredPermissions,
  });
}
