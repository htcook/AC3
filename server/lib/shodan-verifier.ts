/**
 * Shodan Verification Service
 *
 * Post-discovery enrichment that uses Shodan passive recon observations to:
 * 1. Enrich discovered assets with real version data from Shodan banners
 * 2. Confirm or deny KEV/CVE matches by cross-referencing Shodan's own vuln detection
 * 3. Upgrade posture findings from "probable" to "confirmed" when Shodan banner data
 *    provides version evidence that matches a known vulnerable range
 *
 * This runs AFTER passive recon (Stage 0.5) and BEFORE/DURING KEV enrichment (Stage 3.5).
 * It bridges the gap between "this domain runs nginx" (potential) and
 * "this domain runs nginx/1.18.0 which has CVE-2021-23017" (confirmed).
 */

import type { AssetObservation } from "./passive/types";
import type { DiscoveredAssetRaw, AssetAnalysis, PostureFinding, CorroborationTier } from "../domainIntel";

// ─── Types ──────────────────────────────────────────────────────────────

export interface ShodanVersionEvidence {
  ip: string;
  port: number;
  product: string;
  version: string;
  cpe: string[];
  vulns: string[];        // CVE IDs from Shodan's own vuln detection
  bannerSnippet: string;
  hostname?: string;
  os?: string;
  transport?: string;
}

export interface ShodanEnrichmentResult {
  /** Number of assets enriched with Shodan version data */
  assetsEnriched: number;
  /** Number of new technology versions added from Shodan */
  versionsAdded: number;
  /** Number of Shodan-confirmed CVEs (from Shodan's own vuln database) */
  shodanConfirmedCves: number;
  /** All version evidence extracted from Shodan observations */
  versionEvidence: ShodanVersionEvidence[];
  /** Summary log */
  summary: string;
}

export interface ShodanVulnVerification {
  cveId: string;
  /** Whether Shodan independently detected this CVE on the target */
  shodanConfirmed: boolean;
  /** The IP:port where Shodan detected the vuln */
  detectedOn?: string;
  /** Product and version from Shodan banner */
  product?: string;
  version?: string;
  /** CPE strings from Shodan */
  cpe?: string[];
}

// ─── Product Name Normalization ─────────────────────────────────────────

/**
 * Normalize product names for cross-referencing between Shodan observations
 * and discovered asset technologies. Shodan uses its own naming conventions
 * (e.g., "Apache httpd" vs "Apache"), so we need fuzzy matching.
 */
const PRODUCT_ALIASES: Record<string, string[]> = {
  "nginx": ["nginx"],
  "apache": ["apache httpd", "apache http server", "apache", "httpd"],
  "iis": ["microsoft-iis", "iis", "microsoft iis"],
  "openssh": ["openssh", "ssh"],
  "openssl": ["openssl"],
  "php": ["php"],
  "mysql": ["mysql", "mariadb"],
  "postgresql": ["postgresql", "postgres"],
  "redis": ["redis"],
  "mongodb": ["mongodb", "mongo"],
  "elasticsearch": ["elasticsearch", "elastic"],
  "tomcat": ["apache-coyote", "tomcat", "apache tomcat"],
  "wordpress": ["wordpress"],
  "drupal": ["drupal"],
  "exchange": ["microsoft exchange", "exchange", "microsoft-httpapi"],
  "citrix": ["citrix", "netscaler"],
  "f5 big-ip": ["big-ip", "bigip"],
  "fortinet": ["fortigate", "fortios", "fortinet"],
  "palo alto": ["panos", "palo alto"],
  "sonicwall": ["sonicwall", "sonicos"],
  "vmware": ["vmware", "vcenter", "esxi"],
  "jenkins": ["jenkins"],
  "gitlab": ["gitlab"],
  "confluence": ["confluence"],
  "jira": ["jira"],
  "varnish": ["varnish"],
  "haproxy": ["haproxy"],
  "lighttpd": ["lighttpd"],
  "caddy": ["caddy"],
  "express": ["express"],
  "gunicorn": ["gunicorn"],
  "envoy": ["envoy"],
  "cloudflare": ["cloudflare"],
  "akamai": ["akamai"],
  "litespeed": ["litespeed"],
  "zimbra": ["zimbra"],
  "roundcube": ["roundcube"],
  "pulse secure": ["pulse secure", "pulse connect secure"],
  "ivanti": ["ivanti", "pulse secure"],
  "solarwinds": ["solarwinds", "orion"],
  "barracuda": ["barracuda"],
  "moveit": ["moveit", "progress moveit"],
  "connectwise": ["connectwise", "screenconnect"],
};

/**
 * Find the canonical technology name that matches a Shodan product string
 */
function matchShodanProductToTech(shodanProduct: string): string | null {
  const lower = shodanProduct.toLowerCase().trim();
  if (!lower) return null;

  for (const [canonical, aliases] of Object.entries(PRODUCT_ALIASES)) {
    for (const alias of aliases) {
      if (lower === alias || lower.includes(alias) || alias.includes(lower)) {
        return canonical;
      }
    }
  }

  // Fallback: return the product name as-is if it's meaningful
  if (lower.length >= 3 && !["unknown", "n/a", "none"].includes(lower)) {
    return shodanProduct;
  }

  return null;
}

/**
 * Check if a technology name from an asset matches a Shodan product
 */
function techMatchesShodanProduct(assetTech: string, shodanProduct: string): boolean {
  const techLower = assetTech.toLowerCase().trim();
  const prodLower = shodanProduct.toLowerCase().trim();

  // Direct match
  if (techLower === prodLower) return true;
  if (techLower.includes(prodLower) || prodLower.includes(techLower)) return true;

  // Check aliases
  for (const [canonical, aliases] of Object.entries(PRODUCT_ALIASES)) {
    const techIsAlias = aliases.some(a => techLower.includes(a) || a.includes(techLower)) || techLower.includes(canonical);
    const prodIsAlias = aliases.some(a => prodLower.includes(a) || a.includes(prodLower)) || prodLower.includes(canonical);
    if (techIsAlias && prodIsAlias) return true;
  }

  return false;
}

// ─── Shodan Observation Extraction ──────────────────────────────────────

/**
 * Extract version evidence from Shodan passive recon observations.
 * Parses the evidence/tags fields to pull out product, version, CPE, and CVE data.
 */
export function extractShodanVersionEvidence(
  observations: AssetObservation[]
): ShodanVersionEvidence[] {
  const evidence: ShodanVersionEvidence[] = [];
  const seen = new Set<string>(); // Dedupe by ip:port:product

  for (const obs of observations) {
    if (obs.source !== "shodan") continue;
    if (obs.assetType !== "ip") continue;

    const ev = obs.evidence || {};
    const ip = obs.ip || ev.ip || "";
    const port = ev.port || 0;
    const product = ev.product || "";
    const version = ev.version || "";
    const cpe: string[] = ev.cpe || [];
    const vulns: string[] = ev.vulns || ev.host_vulns || [];
    const banner = ev.banner_snippet || "";
    const hostname = obs.name || ev.hostnames?.[0] || "";
    const os = ev.os || "";
    const transport = ev.transport || "tcp";

    // Skip entries without useful product/version data
    if (!product && !version && cpe.length === 0 && vulns.length === 0) continue;

    const key = `${ip}:${port}:${product}`;
    if (seen.has(key)) continue;
    seen.add(key);

    evidence.push({
      ip,
      port,
      product,
      version,
      cpe,
      vulns,
      bannerSnippet: banner,
      hostname: hostname || undefined,
      os: os || undefined,
      transport: transport || undefined,
    });
  }

  return evidence;
}

// ─── Asset Enrichment ───────────────────────────────────────────────────

/**
 * Enrich discovered assets with Shodan version data.
 * Maps Shodan observations back to discovered assets by hostname/IP matching,
 * then populates technologyVersions with real version data from Shodan banners.
 *
 * This should run AFTER passive recon and DNS/banner verification,
 * but BEFORE KEV/CVE enrichment so that the version data is available
 * for confirmation matching.
 */
export function enrichAssetsWithShodanData(
  assets: DiscoveredAssetRaw[],
  shodanObservations: AssetObservation[]
): ShodanEnrichmentResult {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  let assetsEnriched = 0;
  let versionsAdded = 0;
  let shodanConfirmedCves = 0;

  for (const asset of assets) {
    const hostname = asset.hostname.toLowerCase();
    const assetIPs = asset.dnsRecords?.A || [];

    // Find Shodan evidence that matches this asset by hostname or IP
    const matchingEvidence = versionEvidence.filter(ev => {
      // Match by hostname
      if (ev.hostname && (
        ev.hostname.toLowerCase() === hostname ||
        ev.hostname.toLowerCase().endsWith(`.${hostname}`) ||
        hostname.endsWith(`.${ev.hostname.toLowerCase()}`)
      )) return true;

      // Match by IP (if asset has resolved IPs from DNS verification)
      if (ev.ip && assetIPs.includes(ev.ip)) return true;

      return false;
    });

    if (matchingEvidence.length === 0) continue;

    let enriched = false;
    const existingVersions = { ...(asset.technologyVersions || {}) };
    const existingTechs = new Set((asset.technologies || []).map(t => t.toLowerCase()));

    for (const ev of matchingEvidence) {
      // 1. Add version data from Shodan product/version fields
      if (ev.product && ev.version) {
        const canonicalName = matchShodanProductToTech(ev.product);
        if (canonicalName) {
          // Check if we already have this technology
          const existingKey = Object.keys(existingVersions).find(
            k => k.toLowerCase() === canonicalName.toLowerCase() ||
                 techMatchesShodanProduct(k, ev.product)
          );

          if (existingKey) {
            // Only upgrade if we don't already have a version, or Shodan's is more specific
            if (!existingVersions[existingKey] || existingVersions[existingKey] === "null") {
              existingVersions[existingKey] = ev.version;
              versionsAdded++;
              enriched = true;
            }
          } else {
            // Add new technology + version
            existingVersions[canonicalName] = ev.version;
            if (!existingTechs.has(canonicalName.toLowerCase())) {
              asset.technologies = [...(asset.technologies || []), canonicalName];
              existingTechs.add(canonicalName.toLowerCase());
            }
            versionsAdded++;
            enriched = true;
          }
        }
      }

      // 2. Extract versions from CPE strings (cpe:2.3:a:vendor:product:version:...)
      for (const cpeStr of ev.cpe) {
        const parts = cpeStr.split(":");
        if (parts.length >= 6) {
          const cpeProduct = parts[4] || "";
          const cpeVersion = parts[5] || "";
          if (cpeProduct && cpeVersion && cpeVersion !== "*" && cpeVersion !== "-") {
            const canonicalName = matchShodanProductToTech(cpeProduct);
            if (canonicalName) {
              const existingKey = Object.keys(existingVersions).find(
                k => k.toLowerCase() === canonicalName.toLowerCase() ||
                     techMatchesShodanProduct(k, cpeProduct)
              );
              if (!existingKey || !existingVersions[existingKey] || existingVersions[existingKey] === "null") {
                const key = existingKey || canonicalName;
                existingVersions[key] = cpeVersion;
                if (!existingTechs.has(canonicalName.toLowerCase())) {
                  asset.technologies = [...(asset.technologies || []), canonicalName];
                  existingTechs.add(canonicalName.toLowerCase());
                }
                versionsAdded++;
                enriched = true;
              }
            }
          }
        }
      }

      // 3. Count Shodan-confirmed CVEs
      shodanConfirmedCves += ev.vulns.length;
    }

    if (enriched) {
      asset.technologyVersions = existingVersions;
      // Upgrade discovery evidence
      const shodanProducts = matchingEvidence
        .filter(e => e.product)
        .map(e => `${e.product}${e.version ? "/" + e.version : ""} (${e.ip}:${e.port})`)
        .slice(0, 5)
        .join(", ");
      asset.discoveryEvidence = `${asset.discoveryEvidence || ""} | Shodan banner enrichment: ${shodanProducts}`.trim();
      assetsEnriched++;
    }
  }

  const summary = `Shodan enrichment: ${assetsEnriched} assets enriched, ${versionsAdded} versions added, ${shodanConfirmedCves} Shodan-confirmed CVEs across ${versionEvidence.length} service banners`;

  return {
    assetsEnriched,
    versionsAdded,
    shodanConfirmedCves,
    versionEvidence,
    summary,
  };
}

// ─── KEV/CVE Verification ───────────────────────────────────────────────

/**
 * Verify KEV and CVE matches using Shodan's own vulnerability detection.
 * 
 * For each posture finding with a CVE ID, check if Shodan independently
 * detected that CVE on any of the asset's IPs. If yes, upgrade the finding
 * from "probable" to "confirmed" with Shodan as the verification source.
 *
 * This runs AFTER KEV/vuln feed enrichment (Stage 3.5/3.6) to upgrade
 * findings that were marked as "probable" (product-family match without version).
 */
export function verifyCvesWithShodanData(
  analyses: AssetAnalysis[],
  shodanObservations: AssetObservation[]
): {
  upgraded: number;
  verified: ShodanVulnVerification[];
  summary: string;
} {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  const verifications: ShodanVulnVerification[] = [];
  let upgraded = 0;

  // Build a map of CVE -> Shodan evidence for quick lookup
  const cveShodanMap = new Map<string, ShodanVersionEvidence[]>();
  for (const ev of versionEvidence) {
    for (const cve of ev.vulns) {
      const existing = cveShodanMap.get(cve) || [];
      existing.push(ev);
      cveShodanMap.set(cve, existing);
    }
  }

  // Build a map of IP -> Shodan evidence for version lookups
  const ipShodanMap = new Map<string, ShodanVersionEvidence[]>();
  for (const ev of versionEvidence) {
    if (ev.ip) {
      const existing = ipShodanMap.get(ev.ip) || [];
      existing.push(ev);
      ipShodanMap.set(ev.ip, existing);
    }
  }

  for (const analysis of analyses) {
    const hostname = analysis.asset.hostname.toLowerCase();
    const assetIPs: string[] = analysis.asset.dnsRecords?.A || [];

    // Find all Shodan evidence for this asset
    const assetShodanEvidence: ShodanVersionEvidence[] = [];
    for (const ev of versionEvidence) {
      if (ev.hostname && (
        ev.hostname.toLowerCase() === hostname ||
        ev.hostname.toLowerCase().endsWith(`.${hostname}`) ||
        hostname.endsWith(`.${ev.hostname.toLowerCase()}`)
      )) {
        assetShodanEvidence.push(ev);
        continue;
      }
      if (ev.ip && assetIPs.includes(ev.ip)) {
        assetShodanEvidence.push(ev);
      }
    }

    // Check each posture finding for Shodan verification
    for (const finding of analysis.postureFindings) {
      if (!finding.cveIds || finding.cveIds.length === 0) continue;

      for (const cveId of finding.cveIds) {
        // Method 1: Shodan directly detected this CVE on a matching host
        const shodanCveEvidence = cveShodanMap.get(cveId);
        if (shodanCveEvidence) {
          // Check if any of the Shodan CVE detections are on this asset's IPs/hostnames
          const matchingCveEvidence = shodanCveEvidence.find(ev => {
            if (ev.hostname && (
              ev.hostname.toLowerCase() === hostname ||
              ev.hostname.toLowerCase().endsWith(`.${hostname}`) ||
              hostname.endsWith(`.${ev.hostname.toLowerCase()}`)
            )) return true;
            if (ev.ip && assetIPs.includes(ev.ip)) return true;
            return false;
          });

          if (matchingCveEvidence) {
            verifications.push({
              cveId,
              shodanConfirmed: true,
              detectedOn: `${matchingCveEvidence.ip}:${matchingCveEvidence.port}`,
              product: matchingCveEvidence.product,
              version: matchingCveEvidence.version,
              cpe: matchingCveEvidence.cpe,
            });

            // Upgrade finding if it was "probable" or "potential"
            if (finding.corroborationTier !== "confirmed") {
              finding.corroborationTier = "confirmed" as CorroborationTier;
              finding.versionMatchConfirmed = true;
              finding.detectedVersion = matchingCveEvidence.version || finding.detectedVersion;
              // Uncap severity now that it's confirmed
              if (finding.severity < 7 && finding.cvssScore && finding.cvssScore >= 7) {
                finding.severity = Math.round(finding.cvssScore);
              }
              // Boost confidence
              finding.confidence = Math.max(finding.confidence, 0.95);
              // Update evidence chain
              finding.evidenceChain = [
                ...(finding.evidenceChain || []),
                `SHODAN VERIFICATION: ${cveId} independently detected by Shodan on ${matchingCveEvidence.ip}:${matchingCveEvidence.port} (${matchingCveEvidence.product}${matchingCveEvidence.version ? "/" + matchingCveEvidence.version : ""})`,
                `Corroboration upgraded from probable → CONFIRMED via Shodan banner analysis`,
              ];
              finding.evidenceDetail = `CONFIRMED (Shodan-verified): ${finding.evidenceDetail || ""} Shodan independently detected ${cveId} on ${matchingCveEvidence.ip}:${matchingCveEvidence.port}.`;
              finding.evidenceBasis = "confirmed_cve";
              upgraded++;
            }
            continue; // CVE verified, move to next
          }
        }

        // Method 2: Shodan has version data for the same product on this asset
        // Even if Shodan didn't flag the specific CVE, if we have a version match
        // from Shodan banners, we can upgrade the finding
        if (finding.corroborationTier === "probable" && !finding.versionMatchConfirmed) {
          for (const ev of assetShodanEvidence) {
            if (!ev.product || !ev.version) continue;

            // Check if the Shodan product matches the finding's technology
            const findingTitle = (finding.title || "").toLowerCase();
            const findingTech = finding.cveIds?.join(" ").toLowerCase() || "";

            if (techMatchesShodanProduct(findingTitle, ev.product) ||
                (finding.assetHostname && ev.hostname &&
                 ev.hostname.toLowerCase().includes(finding.assetHostname.toLowerCase()))) {
              // We have a version from Shodan for this product on this asset
              // This provides version evidence even if Shodan didn't flag the specific CVE
              if (!finding.detectedVersion) {
                finding.detectedVersion = ev.version;
                finding.versionMatchConfirmed = true;
                finding.corroborationTier = "confirmed" as CorroborationTier;
                // Uncap severity
                if (finding.severity < 7 && finding.cvssScore && finding.cvssScore >= 7) {
                  finding.severity = Math.round(finding.cvssScore);
                }
                finding.confidence = Math.max(finding.confidence, 0.85);
                finding.evidenceChain = [
                  ...(finding.evidenceChain || []),
                  `SHODAN VERSION EVIDENCE: ${ev.product}/${ev.version} detected on ${ev.ip}:${ev.port} via Shodan banner`,
                  `Version evidence allows corroboration upgrade from probable → CONFIRMED`,
                ];
                finding.evidenceDetail = `CONFIRMED (Shodan version): ${finding.evidenceDetail || ""} Shodan detected ${ev.product}/${ev.version} on ${ev.ip}:${ev.port}.`;

                verifications.push({
                  cveId,
                  shodanConfirmed: true,
                  detectedOn: `${ev.ip}:${ev.port}`,
                  product: ev.product,
                  version: ev.version,
                  cpe: ev.cpe,
                });
                upgraded++;
                break;
              }
            }
          }
        }
      }
    }
  }

  const summary = `Shodan CVE verification: ${upgraded} findings upgraded to confirmed, ${verifications.filter(v => v.shodanConfirmed).length} CVEs verified across ${analyses.length} assets`;

  return { upgraded, verified: verifications, summary };
}

// ─── Shodan-Sourced Posture Findings ────────────────────────────────────

/**
 * Create posture findings directly from Shodan's own CVE detection.
 * These are HIGH-confidence findings because Shodan detected the CVE
 * through its own banner analysis, independent of our KEV/vuln feed matching.
 *
 * These findings are always "confirmed" tier because Shodan's detection
 * is based on actual banner/version data from internet-wide scans.
 */
export function createShodanPostureFindings(
  analyses: AssetAnalysis[],
  shodanObservations: AssetObservation[]
): {
  findingsAdded: number;
  summary: string;
} {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  let findingsAdded = 0;

  for (const analysis of analyses) {
    const hostname = analysis.asset.hostname.toLowerCase();
    const assetIPs: string[] = analysis.asset.dnsRecords?.A || [];

    // Find Shodan evidence for this asset
    const matchingEvidence = versionEvidence.filter(ev => {
      if (ev.hostname && (
        ev.hostname.toLowerCase() === hostname ||
        ev.hostname.toLowerCase().endsWith(`.${hostname}`) ||
        hostname.endsWith(`.${ev.hostname.toLowerCase()}`)
      )) return true;
      if (ev.ip && assetIPs.includes(ev.ip)) return true;
      return false;
    });

    for (const ev of matchingEvidence) {
      // Only process entries with Shodan-detected CVEs
      if (ev.vulns.length === 0) continue;

      for (const cveId of ev.vulns) {
        // Skip if we already have a finding for this CVE on this asset
        if (analysis.postureFindings.some(f => f.cveIds?.includes(cveId))) continue;

        const finding: PostureFinding = {
          id: `shodan-${cveId}-${analysis.asset.assetId}`,
          assetRef: analysis.asset.assetId,
          assetHostname: analysis.asset.hostname,
          category: "Shodan Detected CVE",
          title: `${cveId}: Detected by Shodan on ${ev.product || "service"}${ev.version ? " " + ev.version : ""} (${ev.ip}:${ev.port})`,
          severity: 8, // High default — Shodan-detected CVEs are real
          likelihood: 8,
          confidence: 0.95, // Very high — Shodan's own detection
          recommendedControls: [
            `Investigate ${cveId} on ${ev.ip}:${ev.port}`,
            `Verify ${ev.product || "service"} version and apply patches`,
            `Check Shodan for additional details: https://www.shodan.io/host/${ev.ip}`,
          ],
          cveIds: [cveId],
          kevListed: false, // Will be updated by KEV enrichment if applicable
          exploitAvailable: true, // Shodan-detected implies exploitability
          affectedAssets: [analysis.asset.hostname],
          evidenceBasis: "confirmed_cve",
          evidenceDetail: `CONFIRMED (Shodan detection): Shodan's internet-wide scan detected ${cveId} on ${ev.ip}:${ev.port} running ${ev.product || "unknown"}${ev.version ? "/" + ev.version : ""}. Banner: "${ev.bannerSnippet.substring(0, 100)}..."`,
          corroborationTier: "confirmed" as CorroborationTier,
          detectedVersion: ev.version || undefined,
          versionMatchConfirmed: true,
          evidenceChain: [
            `Shodan internet-wide scan detected ${ev.product || "service"} on ${ev.ip}:${ev.port}/${ev.transport || "tcp"}`,
            ev.version ? `Version ${ev.version} identified from service banner` : "Version not available in banner",
            ev.cpe.length > 0 ? `CPE: ${ev.cpe.join(", ")}` : "No CPE data",
            `${cveId} flagged by Shodan's vulnerability detection engine`,
            `Corroboration: CONFIRMED — independent detection by Shodan (not inferred)`,
          ],
        };

        analysis.postureFindings.push(finding);
        findingsAdded++;
      }
    }
  }

  const summary = `Shodan posture findings: ${findingsAdded} new confirmed CVE findings added from Shodan's own detection`;
  return { findingsAdded, summary };
}

// ─── Exports ────────────────────────────────────────────────────────────

export {
  matchShodanProductToTech,
  techMatchesShodanProduct,
  PRODUCT_ALIASES,
};
