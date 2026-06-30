/**
 * Technology Stack Grouping Module
 * 
 * Groups assets by shared technology stack fingerprint so the report can say
 * "200 assets running Apache 2.4.x share these 15 vulnerabilities" instead
 * of listing each asset individually. This dramatically reduces report noise
 * for large-scale scans (PBS: 584 assets, many sharing identical stacks).
 * 
 * The grouping uses a normalized fingerprint of (sorted tech names + versions)
 * to cluster assets. Each group gets:
 * - A human-readable stack label (e.g., "Apache 2.4.51 + nginx 1.18.0 + jQuery 3.6.0")
 * - Shared CVE profile (CVEs common to ALL assets in the group)
 * - Group-level risk statistics
 * - Most Widespread Vulnerabilities ranking
 */

import type { AssetAnalysis, PostureFinding } from "../domainIntel";

// ─── Types ──────────────────────────────────────────────────────────────

export interface TechStackGroup {
  /** Unique fingerprint hash for this stack combination */
  fingerprint: string;
  /** Human-readable label for the stack (e.g., "Apache 2.4.51 + nginx 1.18.0") */
  stackLabel: string;
  /** Individual technologies in this stack with versions */
  technologies: Array<{ name: string; version: string | null }>;
  /** Hostnames of all assets sharing this stack */
  assetHostnames: string[];
  /** Number of assets in this group */
  assetCount: number;
  /** CVEs shared by ALL assets in this group */
  sharedCves: SharedCveEntry[];
  /** Total unique CVEs across all assets in this group */
  totalUniqueCves: number;
  /** Average hybrid risk score across group members */
  avgRiskScore: number;
  /** Max hybrid risk score in the group */
  maxRiskScore: number;
  /** Risk band for the group (based on avg) */
  riskBand: string;
  /** Primary asset tier (most common tier in the group) */
  primaryTier: string;
}

export interface SharedCveEntry {
  cveId: string;
  title: string;
  severity: number;
  cvssScore: number | null;
  kevListed: boolean;
  corroborationTier: string;
  affectedAssetCount: number;
  exploitAvailable: boolean;
}

export interface WidespreadVulnerability {
  cveId: string;
  title: string;
  severity: number;
  cvssScore: number | null;
  kevListed: boolean;
  exploitAvailable: boolean;
  affectedAssetCount: number;
  affectedPercentage: number; // 0-100
  stackGroups: string[]; // fingerprints of affected stack groups
  corroborationTier: string; // highest confidence tier across instances
}

export interface TechStackGroupingResult {
  /** All stack groups, sorted by asset count descending */
  groups: TechStackGroup[];
  /** Top 20 most widespread vulnerabilities across all assets */
  mostWidespreadVulns: WidespreadVulnerability[];
  /** Summary statistics */
  summary: {
    totalGroups: number;
    totalAssets: number;
    largestGroupSize: number;
    largestGroupLabel: string;
    averageGroupSize: number;
    /** Percentage of assets that share a stack with at least one other asset */
    stackOverlapPercentage: number;
    /** Number of unique technology stacks discovered */
    uniqueStacks: number;
  };
}

// ─── Core Logic ─────────────────────────────────────────────────────────

/**
 * Generate a normalized fingerprint for an asset's technology stack.
 * Sorts technologies alphabetically and includes versions where known.
 * Technologies are lowercased for consistency.
 */
function generateStackFingerprint(
  technologies: string[],
  technologyVersions: Record<string, string> | undefined
): string {
  if (!technologies || technologies.length === 0) return "__no_tech__";
  
  const normalized = technologies
    .map(t => t.trim())
    .filter(Boolean)
    .map(t => {
      const version = technologyVersions?.[t] || null;
      // Normalize: lowercase name, include major.minor version only
      const normName = t.toLowerCase();
      const normVersion = version ? normalizeMajorMinor(version) : "unknown";
      return `${normName}@${normVersion}`;
    })
    .sort()
    .join("|");
  
  return normalized || "__no_tech__";
}

/**
 * Normalize version to major.minor for grouping purposes.
 * "2.4.51" → "2.4", "1.18.0" → "1.18", "3.6.0" → "3.6"
 * This groups assets with patch-level differences together.
 */
function normalizeMajorMinor(version: string): string {
  const match = version.match(/^(\d+\.\d+)/);
  return match ? match[1] : version;
}

/**
 * Create a human-readable stack label from technologies.
 * Shows top 4 technologies with versions, then "+N more" if needed.
 */
function createStackLabel(
  technologies: Array<{ name: string; version: string | null }>
): string {
  const sorted = [...technologies].sort((a, b) => a.name.localeCompare(b.name));
  const shown = sorted.slice(0, 4);
  const label = shown.map(t => t.version ? `${t.name} ${t.version}` : t.name).join(" + ");
  if (sorted.length > 4) {
    return `${label} +${sorted.length - 4} more`;
  }
  return label;
}

/**
 * Determine risk band from score.
 */
function riskBand(score: number): string {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

/**
 * Main entry point: group assets by technology stack and compute shared vulnerability profiles.
 */
export function computeTechStackGrouping(
  analyses: AssetAnalysis[]
): TechStackGroupingResult {
  if (!analyses || analyses.length === 0) {
    return {
      groups: [],
      mostWidespreadVulns: [],
      summary: {
        totalGroups: 0,
        totalAssets: 0,
        largestGroupSize: 0,
        largestGroupLabel: "N/A",
        averageGroupSize: 0,
        stackOverlapPercentage: 0,
        uniqueStacks: 0,
      },
    };
  }

  // ── Step 1: Group assets by stack fingerprint ──
  const groupMap = new Map<string, {
    fingerprint: string;
    technologies: Array<{ name: string; version: string | null }>;
    assets: AssetAnalysis[];
  }>();

  for (const a of analyses) {
    const techs = a.asset.technologies || [];
    const versions = (a.asset.technologyVersions || {}) as Record<string, string>;
    const fp = generateStackFingerprint(techs, versions);

    if (!groupMap.has(fp)) {
      groupMap.set(fp, {
        fingerprint: fp,
        technologies: techs.map(t => ({
          name: t,
          version: versions[t] || null,
        })),
        assets: [],
      });
    }
    groupMap.get(fp)!.assets.push(a);
  }

  // ── Step 2: Build CVE index across all assets ──
  const cveToAssets = new Map<string, {
    cveId: string;
    title: string;
    severity: number;
    cvssScore: number | null;
    kevListed: boolean;
    exploitAvailable: boolean;
    corroborationTier: string;
    assetHostnames: Set<string>;
    stackFingerprints: Set<string>;
  }>();

  for (const a of analyses) {
    const fp = generateStackFingerprint(
      a.asset.technologies || [],
      (a.asset.technologyVersions || {}) as Record<string, string>
    );
    for (const f of a.postureFindings) {
      if (f.cveIds) {
        for (const cve of f.cveIds) {
          if (!cveToAssets.has(cve)) {
            cveToAssets.set(cve, {
              cveId: cve,
              title: f.title || cve,
              severity: f.severity,
              cvssScore: f.cvssScore ?? null,
              kevListed: !!(f as any).kevListed,
              exploitAvailable: !!(f as any).exploitAvailable,
              corroborationTier: f.corroborationTier || "potential",
              assetHostnames: new Set(),
              stackFingerprints: new Set(),
            });
          }
          const entry = cveToAssets.get(cve)!;
          entry.assetHostnames.add(a.asset.hostname);
          entry.stackFingerprints.add(fp);
          // Upgrade corroboration tier if higher confidence found
          if (f.corroborationTier === "confirmed") entry.corroborationTier = "confirmed";
          else if (f.corroborationTier === "probable" && entry.corroborationTier !== "confirmed") entry.corroborationTier = "probable";
          // Upgrade severity/CVSS if higher found
          if (f.severity > entry.severity) entry.severity = f.severity;
          if (f.cvssScore && (!entry.cvssScore || f.cvssScore > entry.cvssScore)) entry.cvssScore = f.cvssScore;
          if ((f as any).kevListed) entry.kevListed = true;
          if ((f as any).exploitAvailable) entry.exploitAvailable = true;
        }
      }
    }
  }

  // ── Step 3: Build TechStackGroup objects ──
  const groups: TechStackGroup[] = [];
  for (const [fp, group] of groupMap) {
    const assetHostnames = group.assets.map(a => a.asset.hostname);
    const assetSet = new Set(assetHostnames);

    // Find CVEs shared by ALL assets in this group
    const sharedCves: SharedCveEntry[] = [];
    const groupUniqueCves = new Set<string>();

    for (const [cve, cveData] of cveToAssets) {
      // Check if this CVE affects any asset in this group
      const affectedInGroup = [...cveData.assetHostnames].filter(h => assetSet.has(h));
      if (affectedInGroup.length > 0) {
        groupUniqueCves.add(cve);
        // "Shared" = affects ALL assets in the group
        if (affectedInGroup.length === group.assets.length && group.assets.length > 1) {
          sharedCves.push({
            cveId: cve,
            title: cveData.title,
            severity: cveData.severity,
            cvssScore: cveData.cvssScore,
            kevListed: cveData.kevListed,
            corroborationTier: cveData.corroborationTier,
            affectedAssetCount: affectedInGroup.length,
            exploitAvailable: cveData.exploitAvailable,
          });
        }
      }
    }

    // Sort shared CVEs by severity desc, then CVSS desc
    sharedCves.sort((a, b) => (b.severity - a.severity) || ((b.cvssScore || 0) - (a.cvssScore || 0)));

    // Risk stats
    const riskScores = group.assets.map(a => a.hybridRiskScore || 0);
    const avgRisk = riskScores.length > 0
      ? Math.round(riskScores.reduce((s, v) => s + v, 0) / riskScores.length)
      : 0;
    const maxRisk = riskScores.length > 0 ? Math.max(...riskScores) : 0;

    // Most common tier
    const tierCounts = new Map<string, number>();
    for (const a of group.assets) {
      const tier = a.suggestedTier || "unknown";
      tierCounts.set(tier, (tierCounts.get(tier) || 0) + 1);
    }
    const primaryTier = [...tierCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";

    groups.push({
      fingerprint: fp,
      stackLabel: createStackLabel(group.technologies),
      technologies: group.technologies,
      assetHostnames,
      assetCount: group.assets.length,
      sharedCves: sharedCves.slice(0, 20), // Top 20 shared CVEs
      totalUniqueCves: groupUniqueCves.size,
      avgRiskScore: avgRisk,
      maxRiskScore: maxRisk,
      riskBand: riskBand(avgRisk),
      primaryTier,
    });
  }

  // Sort groups by asset count descending
  groups.sort((a, b) => b.assetCount - a.assetCount);

  // ── Step 4: Build Most Widespread Vulnerabilities ──
  const totalAssets = analyses.length;
  const mostWidespreadVulns: WidespreadVulnerability[] = Array.from(cveToAssets.values())
    .filter(c => c.assetHostnames.size > 1) // Only CVEs affecting 2+ assets
    .sort((a, b) => b.assetHostnames.size - a.assetHostnames.size)
    .slice(0, 20)
    .map(c => ({
      cveId: c.cveId,
      title: c.title,
      severity: c.severity,
      cvssScore: c.cvssScore,
      kevListed: c.kevListed,
      exploitAvailable: c.exploitAvailable,
      affectedAssetCount: c.assetHostnames.size,
      affectedPercentage: Math.round((c.assetHostnames.size / totalAssets) * 100),
      stackGroups: [...c.stackFingerprints],
      corroborationTier: c.corroborationTier,
    }));

  // ── Step 5: Summary statistics ──
  const multiAssetGroups = groups.filter(g => g.assetCount > 1);
  const assetsInMultiGroups = multiAssetGroups.reduce((s, g) => s + g.assetCount, 0);
  const largestGroup = groups[0];

  return {
    groups,
    mostWidespreadVulns,
    summary: {
      totalGroups: groups.length,
      totalAssets,
      largestGroupSize: largestGroup?.assetCount || 0,
      largestGroupLabel: largestGroup?.stackLabel || "N/A",
      averageGroupSize: groups.length > 0
        ? Math.round((totalAssets / groups.length) * 10) / 10
        : 0,
      stackOverlapPercentage: totalAssets > 0
        ? Math.round((assetsInMultiGroups / totalAssets) * 100)
        : 0,
      uniqueStacks: groups.length,
    },
  };
}
