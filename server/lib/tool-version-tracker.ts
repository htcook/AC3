/**
 * Tool Version Tracker & License Compliance Checker
 *
 * Tracks tool versions, checks for updates, monitors deprecation,
 * and ensures license compliance for all security tools in the pipeline.
 */

export interface ToolVersionInfo {
  name: string;
  currentVersion: string;
  latestKnownVersion: string;
  releaseDate: string;
  /** GitHub repo or official URL */
  source: string;
  license: string;
  licenseCategory: "open_source" | "commercial" | "freemium" | "restricted";
  /** Whether this tool is actively maintained */
  maintained: boolean;
  /** Whether this tool has known CVEs */
  hasKnownCVEs: boolean;
  /** Deprecation status */
  deprecated: boolean;
  deprecationReason?: string;
  /** Recommended replacement if deprecated */
  replacement?: string;
  /** Last checked timestamp */
  lastChecked: number;
}

export interface LicenseComplianceResult {
  tool: string;
  license: string;
  compliant: boolean;
  issues: string[];
  recommendations: string[];
}

export interface VersionCheckResult {
  tool: string;
  currentVersion: string;
  latestVersion: string;
  isOutdated: boolean;
  versionsBehind: number;
  securityUpdate: boolean;
  updateUrgency: "critical" | "recommended" | "optional" | "current";
}

// ─── Known Tool Versions Database ───────────────────────────────────────────

export const TOOL_VERSION_DB: Record<string, ToolVersionInfo> = {
  gobuster: {
    name: "Gobuster",
    currentVersion: "3.6.0",
    latestKnownVersion: "3.6.0",
    releaseDate: "2024-01-15",
    source: "https://github.com/OJ/gobuster",
    license: "Apache-2.0",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  ffuf: {
    name: "ffuf",
    currentVersion: "2.1.0",
    latestKnownVersion: "2.1.0",
    releaseDate: "2024-02-20",
    source: "https://github.com/ffuf/ffuf",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  nuclei: {
    name: "Nuclei",
    currentVersion: "3.2.0",
    latestKnownVersion: "3.3.5",
    releaseDate: "2024-11-01",
    source: "https://github.com/projectdiscovery/nuclei",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  nikto: {
    name: "Nikto",
    currentVersion: "2.5.0",
    latestKnownVersion: "2.5.0",
    releaseDate: "2023-08-10",
    source: "https://github.com/sullo/nikto",
    license: "GPL-2.0",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  sqlmap: {
    name: "SQLMap",
    currentVersion: "1.8.0",
    latestKnownVersion: "1.8.4",
    releaseDate: "2024-10-15",
    source: "https://github.com/sqlmapproject/sqlmap",
    license: "GPL-2.0",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  hydra: {
    name: "THC-Hydra",
    currentVersion: "9.5",
    latestKnownVersion: "9.5",
    releaseDate: "2023-06-01",
    source: "https://github.com/vanhauser-thc/thc-hydra",
    license: "AGPL-3.0",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  nmap: {
    name: "Nmap",
    currentVersion: "7.94",
    latestKnownVersion: "7.95",
    releaseDate: "2024-04-23",
    source: "https://nmap.org",
    license: "NPSL",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  katana: {
    name: "Katana",
    currentVersion: "1.0.5",
    latestKnownVersion: "1.1.0",
    releaseDate: "2024-09-01",
    source: "https://github.com/projectdiscovery/katana",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  dalfox: {
    name: "Dalfox",
    currentVersion: "2.9.3",
    latestKnownVersion: "2.9.3",
    releaseDate: "2024-07-15",
    source: "https://github.com/hahwul/dalfox",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  interactsh: {
    name: "Interactsh",
    currentVersion: "1.2.0",
    latestKnownVersion: "1.2.0",
    releaseDate: "2024-06-01",
    source: "https://github.com/projectdiscovery/interactsh",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  ssrfmap: {
    name: "SSRFmap",
    currentVersion: "1.0",
    latestKnownVersion: "1.0",
    releaseDate: "2023-03-01",
    source: "https://github.com/swisskyrepo/SSRFmap",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  subjack: {
    name: "Subjack",
    currentVersion: "1.0",
    latestKnownVersion: "1.0",
    releaseDate: "2022-01-01",
    source: "https://github.com/haccer/subjack",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: false,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  wfuzz: {
    name: "Wfuzz",
    currentVersion: "3.1.0",
    latestKnownVersion: "3.1.0",
    releaseDate: "2022-05-01",
    source: "https://github.com/xmendez/wfuzz",
    license: "GPL-2.0",
    licenseCategory: "open_source",
    maintained: false,
    hasKnownCVEs: false,
    deprecated: true,
    deprecationReason: "Largely superseded by ffuf for most use cases",
    replacement: "ffuf",
    lastChecked: Date.now(),
  },
  enum4linux: {
    name: "enum4linux",
    currentVersion: "0.9.1",
    latestKnownVersion: "0.9.1",
    releaseDate: "2021-01-01",
    source: "https://github.com/CiscoCXSecurity/enum4linux",
    license: "GPL-2.0",
    licenseCategory: "open_source",
    maintained: false,
    hasKnownCVEs: false,
    deprecated: true,
    deprecationReason: "Python3 rewrite (enum4linux-ng) is the recommended replacement",
    replacement: "enum4linux-ng",
    lastChecked: Date.now(),
  },
  alterx: {
    name: "AlterX",
    currentVersion: "0.0.4",
    latestKnownVersion: "0.0.4",
    releaseDate: "2024-03-01",
    source: "https://github.com/projectdiscovery/alterx",
    license: "MIT",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
  puredns: {
    name: "PureDNS",
    currentVersion: "2.1.1",
    latestKnownVersion: "2.1.1",
    releaseDate: "2024-05-01",
    source: "https://github.com/d3mondev/puredns",
    license: "GPL-3.0",
    licenseCategory: "open_source",
    maintained: true,
    hasKnownCVEs: false,
    deprecated: false,
    lastChecked: Date.now(),
  },
};

// ─── Version Checking ───────────────────────────────────────────────────────

/**
 * Check version status for a specific tool
 */
export function checkToolVersion(toolName: string): VersionCheckResult | undefined {
  const info = TOOL_VERSION_DB[toolName.toLowerCase()];
  if (!info) return undefined;

  const current = parseVersion(info.currentVersion);
  const latest = parseVersion(info.latestKnownVersion);

  const isOutdated = compareVersions(current, latest) < 0;
  const versionsBehind = isOutdated ? estimateVersionsBehind(current, latest) : 0;

  let updateUrgency: VersionCheckResult["updateUrgency"] = "current";
  if (info.hasKnownCVEs) updateUrgency = "critical";
  else if (versionsBehind >= 3) updateUrgency = "recommended";
  else if (isOutdated) updateUrgency = "optional";

  return {
    tool: info.name,
    currentVersion: info.currentVersion,
    latestVersion: info.latestKnownVersion,
    isOutdated,
    versionsBehind,
    securityUpdate: info.hasKnownCVEs,
    updateUrgency,
  };
}

/**
 * Check all tools and return a summary
 */
export function checkAllToolVersions(): {
  results: VersionCheckResult[];
  outdatedCount: number;
  criticalCount: number;
  deprecatedTools: string[];
  unmaintainedTools: string[];
} {
  const results: VersionCheckResult[] = [];
  const deprecatedTools: string[] = [];
  const unmaintainedTools: string[] = [];

  for (const [key, info] of Object.entries(TOOL_VERSION_DB)) {
    const result = checkToolVersion(key);
    if (result) results.push(result);

    if (info.deprecated) deprecatedTools.push(info.name);
    if (!info.maintained && !info.deprecated) unmaintainedTools.push(info.name);
  }

  return {
    results,
    outdatedCount: results.filter((r) => r.isOutdated).length,
    criticalCount: results.filter((r) => r.updateUrgency === "critical").length,
    deprecatedTools,
    unmaintainedTools,
  };
}

// ─── License Compliance ─────────────────────────────────────────────────────

const GPL_LICENSES = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"];
const PERMISSIVE_LICENSES = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"];

/**
 * Check license compliance for a tool
 */
export function checkLicenseCompliance(
  toolName: string,
  usage: "internal" | "commercial" | "saas" | "distribution"
): LicenseComplianceResult | undefined {
  const info = TOOL_VERSION_DB[toolName.toLowerCase()];
  if (!info) return undefined;

  const issues: string[] = [];
  const recommendations: string[] = [];
  let compliant = true;

  // GPL compliance
  if (GPL_LICENSES.includes(info.license)) {
    if (usage === "distribution") {
      issues.push(`${info.license} requires source code disclosure when distributing`);
      recommendations.push("Ensure source code is available if distributing binaries");
      compliant = false;
    }
    if (info.license === "AGPL-3.0" && usage === "saas") {
      issues.push("AGPL-3.0 requires source code disclosure for SaaS usage");
      recommendations.push("Provide source code access or use an alternative tool");
      compliant = false;
    }
    if (usage === "commercial") {
      recommendations.push(`${info.license} is compatible with commercial use but requires attribution and source disclosure`);
    }
  }

  // Permissive license — generally compliant
  if (PERMISSIVE_LICENSES.includes(info.license)) {
    if (usage === "distribution" || usage === "commercial") {
      recommendations.push(`${info.license} requires attribution in documentation`);
    }
  }

  // Special cases
  if (info.license === "NPSL") {
    if (usage === "commercial" || usage === "distribution") {
      issues.push("Nmap Public Source License has specific commercial use restrictions");
      recommendations.push("Review NPSL terms for commercial use or consider Nmap OEM licensing");
    }
  }

  // Deprecated tool warning
  if (info.deprecated) {
    recommendations.push(`Tool is deprecated. Consider migrating to ${info.replacement || "an alternative"}`);
  }

  // Unmaintained tool warning
  if (!info.maintained) {
    recommendations.push("Tool is no longer actively maintained — security patches may not be available");
  }

  return {
    tool: info.name,
    license: info.license,
    compliant,
    issues,
    recommendations,
  };
}

/**
 * Check license compliance for all tools
 */
export function checkAllLicenseCompliance(
  usage: "internal" | "commercial" | "saas" | "distribution"
): {
  results: LicenseComplianceResult[];
  compliantCount: number;
  nonCompliantCount: number;
  totalIssues: number;
} {
  const results: LicenseComplianceResult[] = [];

  for (const key of Object.keys(TOOL_VERSION_DB)) {
    const result = checkLicenseCompliance(key, usage);
    if (result) results.push(result);
  }

  return {
    results,
    compliantCount: results.filter((r) => r.compliant).length,
    nonCompliantCount: results.filter((r) => !r.compliant).length,
    totalIssues: results.reduce((sum, r) => sum + r.issues.length, 0),
  };
}

/**
 * Get deprecation warnings for tools currently in use
 */
export function getDeprecationWarnings(toolsInUse: string[]): Array<{
  tool: string;
  reason: string;
  replacement: string | undefined;
  urgency: "high" | "medium" | "low";
}> {
  const warnings: Array<{
    tool: string;
    reason: string;
    replacement: string | undefined;
    urgency: "high" | "medium" | "low";
  }> = [];

  for (const toolName of toolsInUse) {
    const info = TOOL_VERSION_DB[toolName.toLowerCase()];
    if (!info) continue;

    if (info.deprecated) {
      warnings.push({
        tool: info.name,
        reason: info.deprecationReason || "Tool is deprecated",
        replacement: info.replacement,
        urgency: info.hasKnownCVEs ? "high" : "medium",
      });
    } else if (!info.maintained) {
      warnings.push({
        tool: info.name,
        reason: "Tool is no longer actively maintained",
        replacement: info.replacement,
        urgency: "low",
      });
    }
  }

  return warnings;
}

// ─── Version Parsing Helpers ────────────────────────────────────────────────

function parseVersion(version: string): number[] {
  return version.split(".").map((n) => parseInt(n, 10) || 0);
}

function compareVersions(a: number[], b: number[]): number {
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    const av = a[i] || 0;
    const bv = b[i] || 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

function estimateVersionsBehind(current: number[], latest: number[]): number {
  // Simple estimate based on major.minor difference
  const majorDiff = (latest[0] || 0) - (current[0] || 0);
  const minorDiff = (latest[1] || 0) - (current[1] || 0);
  const patchDiff = (latest[2] || 0) - (current[2] || 0);

  if (majorDiff > 0) return majorDiff * 10 + minorDiff;
  if (minorDiff > 0) return minorDiff;
  return patchDiff;
}
