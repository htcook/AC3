import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scope-guard.ts
import { TRPCError } from "@trpc/server";
import * as net from "net";
function ipv4ToLong(ip) {
  const parts = ip.split(".").map(Number);
  return (parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) >>> 0;
}
function ipInCidr(ip, cidr) {
  if (!cidr.includes("/")) {
    return ip === cidr;
  }
  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);
  if (prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : ~0 << 32 - prefix >>> 0;
  const ipLong = ipv4ToLong(ip);
  const netLong = ipv4ToLong(network);
  return (ipLong & mask) === (netLong & mask);
}
function cidrContainsCidr(outer, inner) {
  const [outerNet, outerPrefixStr] = outer.includes("/") ? outer.split("/") : [outer, "32"];
  const [innerNet, innerPrefixStr] = inner.includes("/") ? inner.split("/") : [inner, "32"];
  const outerPrefix = parseInt(outerPrefixStr, 10);
  const innerPrefix = parseInt(innerPrefixStr, 10);
  if (innerPrefix < outerPrefix) return false;
  const mask = outerPrefix === 0 ? 0 : ~0 << 32 - outerPrefix >>> 0;
  return (ipv4ToLong(innerNet) & mask) === (ipv4ToLong(outerNet) & mask);
}
function classifyTarget(target) {
  if (target.type) return { type: target.type, value: target.value.trim() };
  const val = target.value.trim();
  if (/^https?:\/\//i.test(val)) {
    return { type: "url", value: val };
  }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(val)) {
    return { type: "cidr", value: val };
  }
  if (net.isIPv4(val)) {
    return { type: "ip", value: val };
  }
  if (net.isIPv6(val)) {
    return { type: "ip", value: val };
  }
  return { type: "domain", value: val.toLowerCase() };
}
function hostnameFromUrl(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase();
  }
}
function domainMatches(targetDomain, scopeDomain, includeSubdomains) {
  const target = targetDomain.toLowerCase().replace(/\.$/, "");
  const scope = scopeDomain.toLowerCase().replace(/\.$/, "");
  if (target === scope) return true;
  if (includeSubdomains && target.endsWith(`.${scope}`)) return true;
  return false;
}
function checkTargetScope(target, scope) {
  const classified = classifyTarget(target);
  const normalisedTarget = classified.value;
  const hasAnyInScopeRules = scope.inScopeIpRanges && scope.inScopeIpRanges.length > 0 || scope.inScopeDomains && scope.inScopeDomains.length > 0 || scope.inScopeAssets && scope.inScopeAssets.length > 0 || scope.inScopeApplications && scope.inScopeApplications.length > 0;
  if (!hasAnyInScopeRules) {
    return {
      allowed: false,
      reason: "No in-scope rules defined in ROE. Cannot validate target. Define scope before running active tools.",
      normalisedTarget
    };
  }
  if (scope.outOfScopeIpRanges) {
    for (const range of scope.outOfScopeIpRanges) {
      if (classified.type === "ip" && ipInCidr(normalisedTarget, range.cidr)) {
        return {
          allowed: false,
          reason: `Target IP ${normalisedTarget} is explicitly OUT OF SCOPE (matches exclusion ${range.cidr}${range.description ? `: ${range.description}` : ""})`,
          matchedRule: `out_of_scope_ip:${range.cidr}`,
          normalisedTarget
        };
      }
      if (classified.type === "cidr" && cidrContainsCidr(range.cidr, normalisedTarget)) {
        return {
          allowed: false,
          reason: `Target CIDR ${normalisedTarget} overlaps with OUT OF SCOPE range ${range.cidr}`,
          matchedRule: `out_of_scope_ip:${range.cidr}`,
          normalisedTarget
        };
      }
    }
  }
  if (scope.outOfScopeDomains) {
    const targetDomain = classified.type === "url" ? hostnameFromUrl(normalisedTarget) : classified.type === "domain" ? normalisedTarget : null;
    if (targetDomain) {
      for (const d of scope.outOfScopeDomains) {
        if (domainMatches(targetDomain, d.domain, d.includeSubdomains !== false)) {
          return {
            allowed: false,
            reason: `Target domain "${targetDomain}" is explicitly OUT OF SCOPE (matches exclusion ${d.domain})`,
            matchedRule: `out_of_scope_domain:${d.domain}`,
            normalisedTarget
          };
        }
      }
    }
  }
  if (scope.outOfScopeAssets) {
    for (const asset of scope.outOfScopeAssets) {
      if (asset.ipAddress && classified.type === "ip" && normalisedTarget === asset.ipAddress) {
        return {
          allowed: false,
          reason: `Target IP ${normalisedTarget} matches OUT OF SCOPE asset "${asset.name}"`,
          matchedRule: `out_of_scope_asset:${asset.name}`,
          normalisedTarget
        };
      }
      if (asset.hostname) {
        const targetDomain = classified.type === "url" ? hostnameFromUrl(normalisedTarget) : classified.type === "domain" ? normalisedTarget : null;
        if (targetDomain && targetDomain === asset.hostname.toLowerCase()) {
          return {
            allowed: false,
            reason: `Target "${targetDomain}" matches OUT OF SCOPE asset "${asset.name}"`,
            matchedRule: `out_of_scope_asset:${asset.name}`,
            normalisedTarget
          };
        }
      }
    }
  }
  let inScope = false;
  let matchedRule = "";
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
  if (!inScope && scope.inScopeDomains) {
    const targetDomain = classified.type === "url" ? hostnameFromUrl(normalisedTarget) : classified.type === "domain" ? normalisedTarget : null;
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
  if (!inScope && scope.inScopeAssets) {
    for (const asset of scope.inScopeAssets) {
      if (asset.ipAddress && classified.type === "ip" && normalisedTarget === asset.ipAddress) {
        inScope = true;
        matchedRule = `in_scope_asset:${asset.name}`;
        break;
      }
      if (asset.hostname) {
        const targetDomain = classified.type === "url" ? hostnameFromUrl(normalisedTarget) : classified.type === "domain" ? normalisedTarget : null;
        if (targetDomain && targetDomain === asset.hostname.toLowerCase()) {
          inScope = true;
          matchedRule = `in_scope_asset:${asset.name}`;
          break;
        }
      }
    }
  }
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
  if (!inScope) {
    return {
      allowed: false,
      reason: `Target "${normalisedTarget}" does not match any in-scope rule. Default-deny policy blocks all unrecognised targets.`,
      normalisedTarget
    };
  }
  return {
    allowed: true,
    reason: `Target "${normalisedTarget}" is within ROE scope`,
    matchedRule,
    normalisedTarget
  };
}
function checkTestingWindow(scope) {
  const now = /* @__PURE__ */ new Date();
  if (scope.testScheduleStart) {
    const start = new Date(scope.testScheduleStart);
    if (now < start) {
      return {
        allowed: false,
        reason: `Testing has not started yet. Scheduled start: ${start.toISOString()}`,
        normalisedTarget: "time_window"
      };
    }
  }
  if (scope.testScheduleEnd) {
    const end = new Date(scope.testScheduleEnd);
    if (now > end) {
      return {
        allowed: false,
        reason: `Testing period has ended. Scheduled end: ${end.toISOString()}`,
        normalisedTarget: "time_window"
      };
    }
  }
  if (scope.testingDays && scope.testingDays.length > 0) {
    const dayNames = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
    let currentDay;
    try {
      const tz = scope.testTimezone || "UTC";
      const formatter = new Intl.DateTimeFormat("en-US", { weekday: "long", timeZone: tz });
      currentDay = formatter.format(now).toLowerCase();
    } catch {
      currentDay = dayNames[now.getUTCDay()];
    }
    const allowedDays = scope.testingDays.map((d) => d.toLowerCase());
    if (!allowedDays.includes(currentDay)) {
      return {
        allowed: false,
        reason: `Testing is not allowed on ${currentDay}. Allowed days: ${allowedDays.join(", ")}`,
        normalisedTarget: "time_window"
      };
    }
  }
  if (scope.testingWindowStart && scope.testingWindowEnd) {
    let currentHour;
    let currentMinute;
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
    let withinWindow;
    if (startMinutes <= endMinutes) {
      withinWindow = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } else {
      withinWindow = currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }
    if (!withinWindow) {
      return {
        allowed: false,
        reason: `Current time is outside the testing window (${scope.testingWindowStart} - ${scope.testingWindowEnd} ${scope.testTimezone || "UTC"})`,
        normalisedTarget: "time_window"
      };
    }
  }
  return {
    allowed: true,
    reason: "Within testing window",
    normalisedTarget: "time_window"
  };
}
function checkPermission(scope, flag) {
  const flagMap = {
    dos: { field: "dosTestingAllowed", label: "Denial of Service testing" },
    social_engineering: { field: "socialEngineeringAllowed", label: "Social engineering" },
    pivoting: { field: "pivotingAllowed", label: "Pivoting / lateral movement" },
    exfiltration: { field: "exfiltrationAllowed", label: "Data exfiltration" },
    persistence: { field: "persistenceAllowed", label: "Persistence mechanisms" },
    file_modification: { field: "fileModificationAllowed", label: "File modification on target" },
    file_installation: { field: "fileInstallationAllowed", label: "Software installation on target" },
    physical: { field: "physicalTestingAllowed", label: "Physical security testing" },
    wireless: { field: "wirelessTestingAllowed", label: "Wireless network testing" }
  };
  const mapping = flagMap[flag];
  const allowed = scope[mapping.field] === true;
  return {
    allowed,
    reason: allowed ? `${mapping.label} is permitted by ROE` : `${mapping.label} is NOT permitted by ROE. This operation requires explicit authorisation in the Rules of Engagement.`,
    matchedRule: `permission:${flag}`,
    normalisedTarget: `permission_check:${flag}`
  };
}
async function loadEngagementScope(engagementId) {
  try {
    const { getDb } = await import("./db-PHFZ5GDL.js");
    const { engagements, roeDocuments } = await import("./schema-XOTPZHKC.js");
    const { eq, desc } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return null;
    const [eng] = await db.select({
      roeScope: engagements.roeScope,
      roeDocumentId: engagements.roeDocumentId,
      roeStatus: engagements.roeStatus,
      roeExpiryDate: engagements.roeExpiryDate,
      targetDomain: engagements.targetDomain,
      targetIpRange: engagements.targetIpRange
    }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);
    if (!eng) return null;
    const scope = eng.roeScope || {};
    if (eng.targetDomain) {
      const domains = eng.targetDomain.split(/[,;\s]+/).map((d) => d.trim()).filter(Boolean);
      if (!scope.inScopeDomains) scope.inScopeDomains = [];
      for (const domain of domains) {
        const alreadyExists = scope.inScopeDomains.some((d) => d.domain.toLowerCase() === domain.toLowerCase());
        if (!alreadyExists) {
          scope.inScopeDomains.push({ domain, includeSubdomains: true, description: "From engagement builder" });
        }
      }
    }
    if (eng.targetIpRange) {
      const ranges = eng.targetIpRange.split(/[,;\s]+/).map((r) => r.trim()).filter(Boolean);
      if (!scope.inScopeIpRanges) scope.inScopeIpRanges = [];
      for (const range of ranges) {
        const cidr = range.includes("/") ? range : `${range}/32`;
        const alreadyExists = scope.inScopeIpRanges.some((r) => r.cidr === cidr);
        if (!alreadyExists) {
          scope.inScopeIpRanges.push({ cidr, description: "From engagement builder" });
        }
      }
    }
    let roeDoc = null;
    if (eng.roeDocumentId) {
      const [doc] = await db.select().from(roeDocuments).where(eq(roeDocuments.id, eng.roeDocumentId)).limit(1);
      roeDoc = doc;
    } else {
      const docs = await db.select().from(roeDocuments).where(eq(roeDocuments.engagementId, engagementId)).orderBy(desc(roeDocuments.updatedAt)).limit(1);
      roeDoc = docs[0] || null;
    }
    if (roeDoc) {
      if (roeDoc.inScopeIpRanges) scope.inScopeIpRanges = roeDoc.inScopeIpRanges;
      if (roeDoc.outOfScopeIpRanges) scope.outOfScopeIpRanges = roeDoc.outOfScopeIpRanges;
      if (roeDoc.inScopeDomains) scope.inScopeDomains = roeDoc.inScopeDomains;
      if (roeDoc.outOfScopeDomains) scope.outOfScopeDomains = roeDoc.outOfScopeDomains;
      if (roeDoc.inScopeAssets) scope.inScopeAssets = roeDoc.inScopeAssets;
      if (roeDoc.outOfScopeAssets) scope.outOfScopeAssets = roeDoc.outOfScopeAssets;
      if (roeDoc.inScopeApplications) scope.inScopeApplications = roeDoc.inScopeApplications;
      scope.testingWindowStart = roeDoc.testingWindowStart;
      scope.testingWindowEnd = roeDoc.testingWindowEnd;
      scope.testingDays = roeDoc.testingDays;
      scope.testTimezone = roeDoc.testTimezone;
      scope.testScheduleStart = roeDoc.testScheduleStart;
      scope.testScheduleEnd = roeDoc.testScheduleEnd;
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
  } catch (err) {
    console.error("[ScopeGuard] Failed to load engagement scope:", err.message);
    return null;
  }
}
async function enforceScope(opts) {
  const scope = await loadEngagementScope(opts.engagementId);
  if (!scope) {
    await logScopeViolation({
      engagementId: opts.engagementId,
      operatorId: opts.operatorId,
      operatorName: opts.operatorName,
      tool: opts.tool,
      target: opts.targets.map((t) => t.value).join(", "),
      reason: "No ROE scope data found for engagement"
    });
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[SCOPE GUARD] No ROE scope data found for engagement #${opts.engagementId}. Cannot proceed with active operations.`
    });
  }
  const result = {
    allAllowed: true,
    results: [],
    blockedTargets: []
  };
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
        target: opts.targets.map((t) => t.value).join(", "),
        reason: twResult.reason
      });
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: `[SCOPE GUARD] ${twResult.reason}`
      });
    }
  }
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
          reason: permResult.reason
        });
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: `[SCOPE GUARD] ${permResult.reason}`
        });
      }
    }
  }
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
        reason: checkResult.reason
      });
    }
  }
  if (!result.allAllowed) {
    const blockedSummary = result.blockedTargets.join(", ");
    const reasons = result.results.filter((r) => !r.allowed).map((r) => `  - ${r.value}: ${r.reason}`).join("\n");
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `[SCOPE GUARD] ${result.blockedTargets.length} target(s) blocked \u2014 outside ROE scope:
${reasons}`
    });
  }
  return result;
}
async function checkScope(opts) {
  const scope = await loadEngagementScope(opts.engagementId);
  if (!scope) {
    return {
      allAllowed: false,
      results: opts.targets.map((t) => ({
        ...t,
        allowed: false,
        reason: "No ROE scope data found",
        normalisedTarget: t.value
      })),
      blockedTargets: opts.targets.map((t) => t.value)
    };
  }
  const result = {
    allAllowed: true,
    results: [],
    blockedTargets: []
  };
  if (!opts.skipTimeWindow) {
    const twResult = checkTestingWindow(scope);
    result.timeWindowResult = twResult;
    if (!twResult.allowed) {
      result.allAllowed = false;
    }
  }
  if (opts.requiredPermissions) {
    result.permissionResults = [];
    for (const flag of opts.requiredPermissions) {
      const permResult = checkPermission(scope, flag);
      result.permissionResults.push({ flag, ...permResult });
      if (!permResult.allowed) result.allAllowed = false;
    }
  }
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
async function filterInScopeTargets(engagementId, targets, tool, operatorId, operatorName) {
  const scope = await loadEngagementScope(engagementId);
  if (!scope) {
    return {
      inScope: [],
      outOfScope: targets.map((t) => ({ ...t, reason: "No ROE scope data found" }))
    };
  }
  const inScope = [];
  const outOfScope = [];
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
        reason: result.reason
      });
    }
  }
  return { inScope, outOfScope };
}
async function logScopeViolation(entry) {
  try {
    const { logOffensiveAction } = await import("./roe-guard-X5TNP6RX.js");
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
        blockedAt: (/* @__PURE__ */ new Date()).toISOString()
      },
      resultStatus: "blocked",
      resultDetail: `[SCOPE GUARD BLOCKED] ${entry.reason}`
    });
  } catch (err) {
    console.error("[ScopeGuard] Failed to log scope violation:", err.message);
  }
}
async function enforceSingleTarget(engagementId, target, tool, operatorId, operatorName, requiredPermissions) {
  await enforceScope({
    engagementId,
    targets: [{ value: target }],
    tool,
    operatorId,
    operatorName,
    requiredPermissions
  });
}
var init_scope_guard = __esm({
  "server/lib/scope-guard.ts"() {
  }
});

export {
  checkTargetScope,
  checkTestingWindow,
  checkPermission,
  loadEngagementScope,
  enforceScope,
  checkScope,
  filterInScopeTargets,
  enforceSingleTarget,
  init_scope_guard
};
