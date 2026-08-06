/**
 * Fingerprint Diff Engine
 *
 * Compares current fingerprint results against previous scan snapshots to detect
 * service changes between scans. This enables:
 *   - Version upgrade/downgrade detection (e.g., Apache 2.4.49 → 2.4.51)
 *   - New service detection (port appeared that wasn't there before)
 *   - Removed service detection (port disappeared)
 *   - Security posture changes (headers added/removed, TLS changes)
 *   - CVE delta (new CVEs introduced, old CVEs resolved by upgrade)
 *
 * Uses the fingerprintCache table to store historical snapshots keyed by
 * engagement + host + port, and produces a structured diff report.
 *
 * @module fingerprint-diff
 */

import type { FingerprintResult } from "./service-fingerprinter";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ChangeType =
  | "new_service"
  | "removed_service"
  | "version_upgrade"
  | "version_downgrade"
  | "product_change"
  | "security_improvement"
  | "security_degradation"
  | "tls_change"
  | "new_cves"
  | "resolved_cves"
  | "banner_change"
  | "os_change"
  | "confidence_change";

export type ChangeSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface FingerprintChange {
  /** Type of change detected */
  changeType: ChangeType;
  /** Severity of the change */
  severity: ChangeSeverity;
  /** Human-readable description */
  description: string;
  /** Host affected */
  host: string;
  /** Port affected */
  port: number;
  /** Protocol */
  protocol: string;
  /** Previous value (if applicable) */
  previousValue: string | null;
  /** Current value (if applicable) */
  currentValue: string | null;
  /** Operational impact assessment */
  impact: string;
  /** Recommended action */
  recommendation: string;
}

export interface FingerprintDiffReport {
  /** Engagement ID */
  engagementId: number;
  /** When the current scan was performed */
  currentScanTime: number;
  /** When the previous scan was performed */
  previousScanTime: number | null;
  /** Time elapsed between scans (ms) */
  timeDelta: number | null;
  /** Total changes detected */
  totalChanges: number;
  /** Changes by severity */
  changeBySeverity: Record<ChangeSeverity, number>;
  /** Changes by type */
  changeByType: Record<string, number>;
  /** All individual changes */
  changes: FingerprintChange[];
  /** Services in current scan */
  currentServiceCount: number;
  /** Services in previous scan */
  previousServiceCount: number;
  /** New services discovered */
  newServices: Array<{ host: string; port: number; product: string | null }>;
  /** Services no longer present */
  removedServices: Array<{ host: string; port: number; product: string | null }>;
  /** Services with version changes */
  versionChanges: Array<{
    host: string;
    port: number;
    product: string | null;
    oldVersion: string;
    newVersion: string;
    direction: "upgrade" | "downgrade";
  }>;
  /** CVE delta */
  cveDelta: {
    newCves: string[];
    resolvedCves: string[];
    persistentCves: string[];
  };
  /** Overall security posture change */
  postureChange: "improved" | "degraded" | "unchanged" | "mixed";
  /** Risk score delta */
  riskScoreDelta: number;
}

export interface CachedFingerprint {
  host: string;
  port: number;
  protocol: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
  os: string | null;
  securityFlags: Record<string, boolean> | null;
  riskIndicators: any[];
  potentialCves: string[];
  confidence: number;
  fingerprintedAt: number;
  engagementId: string | null;
}

// ─── Version Comparison ─────────────────────────────────────────────────────

/**
 * Compare two version strings semantically.
 * Returns: 1 if a > b, -1 if a < b, 0 if equal.
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.replace(/^v/i, "").split(/[.\-_]/).map(p => {
    const n = parseInt(p, 10);
    return isNaN(n) ? p : n;
  });
  const partsB = b.replace(/^v/i, "").split(/[.\-_]/).map(p => {
    const n = parseInt(p, 10);
    return isNaN(n) ? p : n;
  });

  const maxLen = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < maxLen; i++) {
    const pa = partsA[i] ?? 0;
    const pb = partsB[i] ?? 0;

    if (typeof pa === "number" && typeof pb === "number") {
      if (pa > pb) return 1;
      if (pa < pb) return -1;
    } else {
      const sa = String(pa);
      const sb = String(pb);
      if (sa > sb) return 1;
      if (sa < sb) return -1;
    }
  }
  return 0;
}

// ─── Security Flag Diff ─────────────────────────────────────────────────────

/**
 * Compare security flags between two fingerprints and generate changes.
 */
function diffSecurityFlags(
  host: string,
  port: number,
  protocol: string,
  oldFlags: Record<string, boolean> | null,
  newFlags: Record<string, boolean> | null,
): FingerprintChange[] {
  const changes: FingerprintChange[] = [];
  if (!oldFlags && !newFlags) return changes;

  const old = oldFlags || {};
  const curr = newFlags || {};

  // Security-positive flags (true = good)
  const positiveFlags = [
    "hasHsts", "hasContentSecurityPolicy", "hasXFrameOptions",
    "hasXContentTypeOptions", "hasReferrerPolicy", "hasPermissionsPolicy",
    "tlsValid", "http2Support",
  ];

  // Security-negative flags (true = bad)
  const negativeFlags = [
    "serverHeaderExposed", "poweredByExposed", "directoryListingEnabled",
    "defaultPageDetected", "debugModeEnabled", "corsWildcard",
    "tlsExpiringSoon", "tlsSelfSigned", "tlsWeakCipher",
  ];

  for (const flag of positiveFlags) {
    if (!old[flag] && curr[flag]) {
      changes.push({
        changeType: "security_improvement",
        severity: "info",
        description: `Security header/feature enabled: ${flag}`,
        host, port, protocol,
        previousValue: "disabled",
        currentValue: "enabled",
        impact: "Improved security posture",
        recommendation: "No action needed — positive change",
      });
    } else if (old[flag] && !curr[flag]) {
      changes.push({
        changeType: "security_degradation",
        severity: "medium",
        description: `Security header/feature removed: ${flag}`,
        host, port, protocol,
        previousValue: "enabled",
        currentValue: "disabled",
        impact: "Reduced security posture — potential misconfiguration after update",
        recommendation: `Re-enable ${flag} to maintain security baseline`,
      });
    }
  }

  for (const flag of negativeFlags) {
    if (!old[flag] && curr[flag]) {
      changes.push({
        changeType: "security_degradation",
        severity: flag.includes("tls") ? "high" : "medium",
        description: `Security weakness introduced: ${flag}`,
        host, port, protocol,
        previousValue: "not present",
        currentValue: "detected",
        impact: "New attack surface or information disclosure",
        recommendation: `Address ${flag} to restore previous security baseline`,
      });
    } else if (old[flag] && !curr[flag]) {
      changes.push({
        changeType: "security_improvement",
        severity: "info",
        description: `Security weakness resolved: ${flag}`,
        host, port, protocol,
        previousValue: "detected",
        currentValue: "not present",
        impact: "Reduced attack surface",
        recommendation: "No action needed — positive change",
      });
    }
  }

  return changes;
}

// ─── Core Diff Engine ───────────────────────────────────────────────────────

/**
 * Compare current fingerprint results against cached previous results.
 *
 * @param currentResults - Fingerprint results from the current scan
 * @param previousResults - Cached fingerprint results from the previous scan
 * @param engagementId - Engagement ID for context
 * @returns Structured diff report
 */
export function diffFingerprints(
  currentResults: FingerprintResult[],
  previousResults: CachedFingerprint[],
  engagementId: number,
): FingerprintDiffReport {
  const changes: FingerprintChange[] = [];
  const now = Date.now();

  // Build lookup maps keyed by host:port
  const currentMap = new Map<string, FingerprintResult>();
  for (const fp of currentResults) {
    if (!fp.error) {
      currentMap.set(`${fp.host}:${fp.port}`, fp);
    }
  }

  const previousMap = new Map<string, CachedFingerprint>();
  let earliestPrevScan = Infinity;
  for (const cached of previousResults) {
    previousMap.set(`${cached.host}:${cached.port}`, cached);
    if (cached.fingerprintedAt < earliestPrevScan) {
      earliestPrevScan = cached.fingerprintedAt;
    }
  }

  const previousScanTime = earliestPrevScan === Infinity ? null : earliestPrevScan;

  // Track new and removed services
  const newServices: FingerprintDiffReport["newServices"] = [];
  const removedServices: FingerprintDiffReport["removedServices"] = [];
  const versionChanges: FingerprintDiffReport["versionChanges"] = [];

  // All CVEs across scans for delta calculation
  const currentCves = new Set<string>();
  const previousCves = new Set<string>();

  for (const fp of currentResults) {
    if (!fp.error && fp.potentialCves) {
      for (const cve of fp.potentialCves) currentCves.add(cve);
    }
  }
  for (const cached of previousResults) {
    if (cached.potentialCves) {
      for (const cve of cached.potentialCves) previousCves.add(cve);
    }
  }

  // ── Detect new services ──
  for (const [key, fp] of currentMap) {
    if (!previousMap.has(key)) {
      newServices.push({ host: fp.host, port: fp.port, product: fp.product });
      changes.push({
        changeType: "new_service",
        severity: "medium",
        description: `New service discovered: ${fp.product || "unknown"}${fp.version ? "/" + fp.version : ""} on port ${fp.port}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: null,
        currentValue: `${fp.product || "unknown"}${fp.version ? "/" + fp.version : ""}`,
        impact: "New attack surface — service was not present in previous scan",
        recommendation: "Verify this service is authorized and within scope. Run targeted vulnerability assessment.",
      });
    }
  }

  // ── Detect removed services ──
  for (const [key, cached] of previousMap) {
    if (!currentMap.has(key)) {
      removedServices.push({ host: cached.host, port: cached.port, product: cached.product });
      changes.push({
        changeType: "removed_service",
        severity: "info",
        description: `Service no longer detected: ${cached.product || "unknown"} on port ${cached.port}`,
        host: cached.host,
        port: cached.port,
        protocol: cached.protocol || "unknown",
        previousValue: `${cached.product || "unknown"}${cached.version ? "/" + cached.version : ""}`,
        currentValue: null,
        impact: "Service may have been decommissioned, firewalled, or moved",
        recommendation: "Confirm service removal was intentional. Check if it moved to a different port.",
      });
    }
  }

  // ── Detect changes on existing services ──
  for (const [key, fp] of currentMap) {
    const cached = previousMap.get(key);
    if (!cached) continue; // Already handled as new_service

    // Version change
    if (fp.version && cached.version && fp.version !== cached.version) {
      const cmp = compareVersions(fp.version, cached.version);
      const direction = cmp > 0 ? "upgrade" : cmp < 0 ? "downgrade" : null;

      if (direction) {
        versionChanges.push({
          host: fp.host,
          port: fp.port,
          product: fp.product,
          oldVersion: cached.version,
          newVersion: fp.version,
          direction,
        });

        changes.push({
          changeType: direction === "upgrade" ? "version_upgrade" : "version_downgrade",
          severity: direction === "downgrade" ? "high" : "low",
          description: `${fp.product || "Service"} ${direction}: ${cached.version} → ${fp.version}`,
          host: fp.host,
          port: fp.port,
          protocol: fp.protocol,
          previousValue: cached.version,
          currentValue: fp.version,
          impact: direction === "upgrade"
            ? "Version upgrade may resolve known CVEs but could introduce new ones"
            : "Version downgrade may reintroduce previously patched vulnerabilities",
          recommendation: direction === "upgrade"
            ? "Re-assess CVEs for the new version. Verify upgrade didn't break security configurations."
            : "URGENT: Investigate why service was downgraded. Check for reintroduced CVEs.",
        });
      }
    }

    // Product change (e.g., Apache → Nginx)
    if (fp.product && cached.product && fp.product.toLowerCase() !== cached.product.toLowerCase()) {
      changes.push({
        changeType: "product_change",
        severity: "medium",
        description: `Service changed from ${cached.product} to ${fp.product} on port ${fp.port}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: cached.product,
        currentValue: fp.product,
        impact: "Different software stack — entire vulnerability profile has changed",
        recommendation: "Run full vulnerability assessment for the new product. Previous findings may no longer apply.",
      });
    }

    // OS change
    if (fp.os && cached.os && fp.os !== cached.os) {
      changes.push({
        changeType: "os_change",
        severity: "medium",
        description: `OS fingerprint changed: ${cached.os} → ${fp.os}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: cached.os,
        currentValue: fp.os,
        impact: "OS change may indicate migration, VM rebuild, or container replacement",
        recommendation: "Verify OS-level vulnerabilities for the new platform.",
      });
    }

    // Banner change (without product/version change — indicates config change)
    if (fp.banner && cached.banner && fp.banner !== cached.banner &&
        fp.product === cached.product && fp.version === cached.version) {
      changes.push({
        changeType: "banner_change",
        severity: "low",
        description: `Service banner changed on port ${fp.port}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: cached.banner?.slice(0, 100) || null,
        currentValue: fp.banner?.slice(0, 100) || null,
        impact: "Configuration change detected — may affect information disclosure",
        recommendation: "Review banner for sensitive information exposure.",
      });
    }

    // Security flags diff
    const secFlags = diffSecurityFlags(
      fp.host, fp.port, fp.protocol,
      cached.securityFlags,
      fp.securityFlags,
    );
    changes.push(...secFlags);

    // Confidence change
    if (cached.confidence > 0 && fp.confidence > 0) {
      const confDelta = fp.confidence - cached.confidence;
      if (Math.abs(confDelta) >= 20) {
        changes.push({
          changeType: "confidence_change",
          severity: "info",
          description: `Fingerprint confidence ${confDelta > 0 ? "increased" : "decreased"}: ${cached.confidence}% → ${fp.confidence}%`,
          host: fp.host,
          port: fp.port,
          protocol: fp.protocol,
          previousValue: `${cached.confidence}%`,
          currentValue: `${fp.confidence}%`,
          impact: confDelta > 0
            ? "Better identification — more reliable vulnerability matching"
            : "Reduced identification confidence — service may be obfuscating",
          recommendation: confDelta < 0
            ? "Service may have added fingerprint evasion. Consider active probing."
            : "No action needed.",
        });
      }
    }
  }

  // ── CVE Delta ──
  const newCves = Array.from(currentCves).filter(c => !previousCves.has(c));
  const resolvedCves = Array.from(previousCves).filter(c => !currentCves.has(c));
  const persistentCves = Array.from(currentCves).filter(c => previousCves.has(c));

  if (newCves.length > 0) {
    changes.push({
      changeType: "new_cves",
      severity: newCves.length > 5 ? "high" : "medium",
      description: `${newCves.length} new CVE(s) detected: ${newCves.slice(0, 5).join(", ")}${newCves.length > 5 ? ` (+${newCves.length - 5} more)` : ""}`,
      host: "*",
      port: 0,
      protocol: "*",
      previousValue: null,
      currentValue: newCves.join(", "),
      impact: "New vulnerabilities discovered — may require immediate remediation",
      recommendation: "Prioritize CVEs with known exploits or CISA KEV listings for immediate attention.",
    });
  }

  if (resolvedCves.length > 0) {
    changes.push({
      changeType: "resolved_cves",
      severity: "info",
      description: `${resolvedCves.length} CVE(s) no longer detected: ${resolvedCves.slice(0, 5).join(", ")}${resolvedCves.length > 5 ? ` (+${resolvedCves.length - 5} more)` : ""}`,
      host: "*",
      port: 0,
      protocol: "*",
      previousValue: resolvedCves.join(", "),
      currentValue: null,
      impact: "Previously detected vulnerabilities appear to be patched or mitigated",
      recommendation: "Verify remediation through targeted re-testing of specific CVEs.",
    });
  }

  // ── Calculate posture change ──
  const improvements = changes.filter(c => c.changeType === "security_improvement" || c.changeType === "resolved_cves" || c.changeType === "version_upgrade").length;
  const degradations = changes.filter(c => c.changeType === "security_degradation" || c.changeType === "new_cves" || c.changeType === "version_downgrade").length;

  let postureChange: FingerprintDiffReport["postureChange"] = "unchanged";
  if (improvements > 0 && degradations === 0) postureChange = "improved";
  else if (degradations > 0 && improvements === 0) postureChange = "degraded";
  else if (improvements > 0 && degradations > 0) postureChange = "mixed";

  // Risk score delta (positive = worse, negative = better)
  const riskScoreDelta =
    (newCves.length * 5) - (resolvedCves.length * 5) +
    (degradations * 3) - (improvements * 3) +
    (newServices.length * 2) - (removedServices.length * 1);

  // ── Severity counts ──
  const changeBySeverity: Record<ChangeSeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  const changeByType: Record<string, number> = {};
  for (const c of changes) {
    changeBySeverity[c.severity]++;
    changeByType[c.changeType] = (changeByType[c.changeType] || 0) + 1;
  }

  return {
    engagementId,
    currentScanTime: now,
    previousScanTime,
    timeDelta: previousScanTime ? now - previousScanTime : null,
    totalChanges: changes.length,
    changeBySeverity,
    changeByType,
    changes,
    currentServiceCount: currentMap.size,
    previousServiceCount: previousMap.size,
    newServices,
    removedServices,
    versionChanges,
    cveDelta: { newCves, resolvedCves, persistentCves },
    postureChange,
    riskScoreDelta,
  };
}

// ─── Snapshot Management ────────────────────────────────────────────────────

/**
 * Convert current fingerprint results to cacheable format for storage.
 */
export function fingerprintsToCacheEntries(
  results: FingerprintResult[],
  engagementId: string,
): CachedFingerprint[] {
  return results
    .filter(fp => !fp.error)
    .map(fp => ({
      host: fp.host,
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      version: fp.version,
      banner: fp.banner,
      os: fp.os,
      securityFlags: fp.securityFlags,
      riskIndicators: fp.riskIndicators || [],
      potentialCves: fp.potentialCves || [],
      confidence: fp.confidence,
      fingerprintedAt: Date.now(),
      engagementId,
    }));
}

/**
 * Build a human-readable summary of the diff report for display in the UI.
 */
export function buildDiffSummaryText(report: FingerprintDiffReport): string {
  if (report.totalChanges === 0) {
    return "No changes detected since previous scan.";
  }

  const lines: string[] = [];

  // Header
  const timeDeltaStr = report.timeDelta
    ? `${Math.round(report.timeDelta / 3600000)}h ${Math.round((report.timeDelta % 3600000) / 60000)}m`
    : "unknown";
  lines.push(`## Fingerprint Diff Report`);
  lines.push(`**${report.totalChanges} changes** detected over ${timeDeltaStr}`);
  lines.push(`Posture: **${report.postureChange.toUpperCase()}** | Risk Delta: ${report.riskScoreDelta > 0 ? "+" : ""}${report.riskScoreDelta}`);
  lines.push("");

  // Severity breakdown
  if (report.changeBySeverity.critical > 0 || report.changeBySeverity.high > 0) {
    lines.push(`### ⚠ Attention Required`);
    if (report.changeBySeverity.critical > 0) lines.push(`- **${report.changeBySeverity.critical} CRITICAL** changes`);
    if (report.changeBySeverity.high > 0) lines.push(`- **${report.changeBySeverity.high} HIGH** changes`);
    lines.push("");
  }

  // New services
  if (report.newServices.length > 0) {
    lines.push(`### New Services (+${report.newServices.length})`);
    for (const svc of report.newServices) {
      lines.push(`- **${svc.host}:${svc.port}** — ${svc.product || "unknown"}`);
    }
    lines.push("");
  }

  // Removed services
  if (report.removedServices.length > 0) {
    lines.push(`### Removed Services (-${report.removedServices.length})`);
    for (const svc of report.removedServices) {
      lines.push(`- ~~${svc.host}:${svc.port}~~ — ${svc.product || "unknown"}`);
    }
    lines.push("");
  }

  // Version changes
  if (report.versionChanges.length > 0) {
    lines.push(`### Version Changes`);
    for (const vc of report.versionChanges) {
      const arrow = vc.direction === "upgrade" ? "⬆" : "⬇";
      lines.push(`- ${arrow} **${vc.product || "Service"}** on ${vc.host}:${vc.port}: ${vc.oldVersion} → ${vc.newVersion}`);
    }
    lines.push("");
  }

  // CVE delta
  if (report.cveDelta.newCves.length > 0 || report.cveDelta.resolvedCves.length > 0) {
    lines.push(`### CVE Delta`);
    if (report.cveDelta.newCves.length > 0) {
      lines.push(`- **+${report.cveDelta.newCves.length} new**: ${report.cveDelta.newCves.slice(0, 8).join(", ")}${report.cveDelta.newCves.length > 8 ? "..." : ""}`);
    }
    if (report.cveDelta.resolvedCves.length > 0) {
      lines.push(`- **-${report.cveDelta.resolvedCves.length} resolved**: ${report.cveDelta.resolvedCves.slice(0, 8).join(", ")}${report.cveDelta.resolvedCves.length > 8 ? "..." : ""}`);
    }
    if (report.cveDelta.persistentCves.length > 0) {
      lines.push(`- **${report.cveDelta.persistentCves.length} persistent** (unpatched)`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
