import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/fingerprint-diff.ts
function compareVersions(a, b) {
  const partsA = a.replace(/^v/i, "").split(/[.\-_]/).map((p) => {
    const n = parseInt(p, 10);
    return isNaN(n) ? p : n;
  });
  const partsB = b.replace(/^v/i, "").split(/[.\-_]/).map((p) => {
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
function diffSecurityFlags(host, port, protocol, oldFlags, newFlags) {
  const changes = [];
  if (!oldFlags && !newFlags) return changes;
  const old = oldFlags || {};
  const curr = newFlags || {};
  const positiveFlags = [
    "hasHsts",
    "hasContentSecurityPolicy",
    "hasXFrameOptions",
    "hasXContentTypeOptions",
    "hasReferrerPolicy",
    "hasPermissionsPolicy",
    "tlsValid",
    "http2Support"
  ];
  const negativeFlags = [
    "serverHeaderExposed",
    "poweredByExposed",
    "directoryListingEnabled",
    "defaultPageDetected",
    "debugModeEnabled",
    "corsWildcard",
    "tlsExpiringSoon",
    "tlsSelfSigned",
    "tlsWeakCipher"
  ];
  for (const flag of positiveFlags) {
    if (!old[flag] && curr[flag]) {
      changes.push({
        changeType: "security_improvement",
        severity: "info",
        description: `Security header/feature enabled: ${flag}`,
        host,
        port,
        protocol,
        previousValue: "disabled",
        currentValue: "enabled",
        impact: "Improved security posture",
        recommendation: "No action needed \u2014 positive change"
      });
    } else if (old[flag] && !curr[flag]) {
      changes.push({
        changeType: "security_degradation",
        severity: "medium",
        description: `Security header/feature removed: ${flag}`,
        host,
        port,
        protocol,
        previousValue: "enabled",
        currentValue: "disabled",
        impact: "Reduced security posture \u2014 potential misconfiguration after update",
        recommendation: `Re-enable ${flag} to maintain security baseline`
      });
    }
  }
  for (const flag of negativeFlags) {
    if (!old[flag] && curr[flag]) {
      changes.push({
        changeType: "security_degradation",
        severity: flag.includes("tls") ? "high" : "medium",
        description: `Security weakness introduced: ${flag}`,
        host,
        port,
        protocol,
        previousValue: "not present",
        currentValue: "detected",
        impact: "New attack surface or information disclosure",
        recommendation: `Address ${flag} to restore previous security baseline`
      });
    } else if (old[flag] && !curr[flag]) {
      changes.push({
        changeType: "security_improvement",
        severity: "info",
        description: `Security weakness resolved: ${flag}`,
        host,
        port,
        protocol,
        previousValue: "detected",
        currentValue: "not present",
        impact: "Reduced attack surface",
        recommendation: "No action needed \u2014 positive change"
      });
    }
  }
  return changes;
}
function diffFingerprints(currentResults, previousResults, engagementId) {
  const changes = [];
  const now = Date.now();
  const currentMap = /* @__PURE__ */ new Map();
  for (const fp of currentResults) {
    if (!fp.error) {
      currentMap.set(`${fp.host}:${fp.port}`, fp);
    }
  }
  const previousMap = /* @__PURE__ */ new Map();
  let earliestPrevScan = Infinity;
  for (const cached of previousResults) {
    previousMap.set(`${cached.host}:${cached.port}`, cached);
    if (cached.fingerprintedAt < earliestPrevScan) {
      earliestPrevScan = cached.fingerprintedAt;
    }
  }
  const previousScanTime = earliestPrevScan === Infinity ? null : earliestPrevScan;
  const newServices = [];
  const removedServices = [];
  const versionChanges = [];
  const currentCves = /* @__PURE__ */ new Set();
  const previousCves = /* @__PURE__ */ new Set();
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
        impact: "New attack surface \u2014 service was not present in previous scan",
        recommendation: "Verify this service is authorized and within scope. Run targeted vulnerability assessment."
      });
    }
  }
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
        recommendation: "Confirm service removal was intentional. Check if it moved to a different port."
      });
    }
  }
  for (const [key, fp] of currentMap) {
    const cached = previousMap.get(key);
    if (!cached) continue;
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
          direction
        });
        changes.push({
          changeType: direction === "upgrade" ? "version_upgrade" : "version_downgrade",
          severity: direction === "downgrade" ? "high" : "low",
          description: `${fp.product || "Service"} ${direction}: ${cached.version} \u2192 ${fp.version}`,
          host: fp.host,
          port: fp.port,
          protocol: fp.protocol,
          previousValue: cached.version,
          currentValue: fp.version,
          impact: direction === "upgrade" ? "Version upgrade may resolve known CVEs but could introduce new ones" : "Version downgrade may reintroduce previously patched vulnerabilities",
          recommendation: direction === "upgrade" ? "Re-assess CVEs for the new version. Verify upgrade didn't break security configurations." : "URGENT: Investigate why service was downgraded. Check for reintroduced CVEs."
        });
      }
    }
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
        impact: "Different software stack \u2014 entire vulnerability profile has changed",
        recommendation: "Run full vulnerability assessment for the new product. Previous findings may no longer apply."
      });
    }
    if (fp.os && cached.os && fp.os !== cached.os) {
      changes.push({
        changeType: "os_change",
        severity: "medium",
        description: `OS fingerprint changed: ${cached.os} \u2192 ${fp.os}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: cached.os,
        currentValue: fp.os,
        impact: "OS change may indicate migration, VM rebuild, or container replacement",
        recommendation: "Verify OS-level vulnerabilities for the new platform."
      });
    }
    if (fp.banner && cached.banner && fp.banner !== cached.banner && fp.product === cached.product && fp.version === cached.version) {
      changes.push({
        changeType: "banner_change",
        severity: "low",
        description: `Service banner changed on port ${fp.port}`,
        host: fp.host,
        port: fp.port,
        protocol: fp.protocol,
        previousValue: cached.banner?.slice(0, 100) || null,
        currentValue: fp.banner?.slice(0, 100) || null,
        impact: "Configuration change detected \u2014 may affect information disclosure",
        recommendation: "Review banner for sensitive information exposure."
      });
    }
    const secFlags = diffSecurityFlags(
      fp.host,
      fp.port,
      fp.protocol,
      cached.securityFlags,
      fp.securityFlags
    );
    changes.push(...secFlags);
    if (cached.confidence > 0 && fp.confidence > 0) {
      const confDelta = fp.confidence - cached.confidence;
      if (Math.abs(confDelta) >= 20) {
        changes.push({
          changeType: "confidence_change",
          severity: "info",
          description: `Fingerprint confidence ${confDelta > 0 ? "increased" : "decreased"}: ${cached.confidence}% \u2192 ${fp.confidence}%`,
          host: fp.host,
          port: fp.port,
          protocol: fp.protocol,
          previousValue: `${cached.confidence}%`,
          currentValue: `${fp.confidence}%`,
          impact: confDelta > 0 ? "Better identification \u2014 more reliable vulnerability matching" : "Reduced identification confidence \u2014 service may be obfuscating",
          recommendation: confDelta < 0 ? "Service may have added fingerprint evasion. Consider active probing." : "No action needed."
        });
      }
    }
  }
  const newCves = Array.from(currentCves).filter((c) => !previousCves.has(c));
  const resolvedCves = Array.from(previousCves).filter((c) => !currentCves.has(c));
  const persistentCves = Array.from(currentCves).filter((c) => previousCves.has(c));
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
      impact: "New vulnerabilities discovered \u2014 may require immediate remediation",
      recommendation: "Prioritize CVEs with known exploits or CISA KEV listings for immediate attention."
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
      recommendation: "Verify remediation through targeted re-testing of specific CVEs."
    });
  }
  const improvements = changes.filter((c) => c.changeType === "security_improvement" || c.changeType === "resolved_cves" || c.changeType === "version_upgrade").length;
  const degradations = changes.filter((c) => c.changeType === "security_degradation" || c.changeType === "new_cves" || c.changeType === "version_downgrade").length;
  let postureChange = "unchanged";
  if (improvements > 0 && degradations === 0) postureChange = "improved";
  else if (degradations > 0 && improvements === 0) postureChange = "degraded";
  else if (improvements > 0 && degradations > 0) postureChange = "mixed";
  const riskScoreDelta = newCves.length * 5 - resolvedCves.length * 5 + degradations * 3 - improvements * 3 + newServices.length * 2 - removedServices.length * 1;
  const changeBySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  const changeByType = {};
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
    riskScoreDelta
  };
}
function fingerprintsToCacheEntries(results, engagementId) {
  return results.filter((fp) => !fp.error).map((fp) => ({
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
    engagementId
  }));
}
function buildDiffSummaryText(report) {
  if (report.totalChanges === 0) {
    return "No changes detected since previous scan.";
  }
  const lines = [];
  const timeDeltaStr = report.timeDelta ? `${Math.round(report.timeDelta / 36e5)}h ${Math.round(report.timeDelta % 36e5 / 6e4)}m` : "unknown";
  lines.push(`## Fingerprint Diff Report`);
  lines.push(`**${report.totalChanges} changes** detected over ${timeDeltaStr}`);
  lines.push(`Posture: **${report.postureChange.toUpperCase()}** | Risk Delta: ${report.riskScoreDelta > 0 ? "+" : ""}${report.riskScoreDelta}`);
  lines.push("");
  if (report.changeBySeverity.critical > 0 || report.changeBySeverity.high > 0) {
    lines.push(`### \u26A0 Attention Required`);
    if (report.changeBySeverity.critical > 0) lines.push(`- **${report.changeBySeverity.critical} CRITICAL** changes`);
    if (report.changeBySeverity.high > 0) lines.push(`- **${report.changeBySeverity.high} HIGH** changes`);
    lines.push("");
  }
  if (report.newServices.length > 0) {
    lines.push(`### New Services (+${report.newServices.length})`);
    for (const svc of report.newServices) {
      lines.push(`- **${svc.host}:${svc.port}** \u2014 ${svc.product || "unknown"}`);
    }
    lines.push("");
  }
  if (report.removedServices.length > 0) {
    lines.push(`### Removed Services (-${report.removedServices.length})`);
    for (const svc of report.removedServices) {
      lines.push(`- ~~${svc.host}:${svc.port}~~ \u2014 ${svc.product || "unknown"}`);
    }
    lines.push("");
  }
  if (report.versionChanges.length > 0) {
    lines.push(`### Version Changes`);
    for (const vc of report.versionChanges) {
      const arrow = vc.direction === "upgrade" ? "\u2B06" : "\u2B07";
      lines.push(`- ${arrow} **${vc.product || "Service"}** on ${vc.host}:${vc.port}: ${vc.oldVersion} \u2192 ${vc.newVersion}`);
    }
    lines.push("");
  }
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
var init_fingerprint_diff = __esm({
  "server/lib/fingerprint-diff.ts"() {
  }
});

export {
  diffFingerprints,
  fingerprintsToCacheEntries,
  buildDiffSummaryText,
  init_fingerprint_diff
};
