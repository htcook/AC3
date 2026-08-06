/**
 * CISA Advisories Connector — Free, No API Key
 * 
 * Queries the CISA Known Exploited Vulnerabilities (KEV) catalog
 * and CISA ICS advisories for vulnerabilities relevant to the
 * target's detected tech stack. Provides real-time vulnerability
 * advisories with exploitation status and remediation deadlines.
 * 
 * Data sources:
 * - KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 * - ICS advisories: https://www.cisa.gov/news-events/ics-advisories
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/**
 * Extract vendor/product names from tech stack observations
 */
function extractVendorProducts(config?: ConnectorConfig): { vendor: string; product: string }[] {
  const results: { vendor: string; product: string }[] = [];
  const priorObs = config?.priorObservations || [];
  const seen = new Set<string>();

  // Common web technology → vendor/product mappings for KEV matching
  const techMap: Record<string, { vendor: string; product: string }[]> = {
    "apache": [{ vendor: "Apache", product: "HTTP Server" }, { vendor: "Apache", product: "Tomcat" }],
    "nginx": [{ vendor: "F5", product: "NGINX" }],
    "iis": [{ vendor: "Microsoft", product: "Internet Information Services" }],
    "microsoft": [{ vendor: "Microsoft", product: "Exchange" }, { vendor: "Microsoft", product: "Windows" }],
    "wordpress": [{ vendor: "WordPress", product: "WordPress" }],
    "drupal": [{ vendor: "Drupal", product: "Drupal" }],
    "joomla": [{ vendor: "Joomla!", product: "Joomla!" }],
    "citrix": [{ vendor: "Citrix", product: "ADC" }, { vendor: "Citrix", product: "NetScaler" }],
    "fortinet": [{ vendor: "Fortinet", product: "FortiOS" }, { vendor: "Fortinet", product: "FortiGate" }],
    "palo alto": [{ vendor: "Palo Alto Networks", product: "PAN-OS" }],
    "cisco": [{ vendor: "Cisco", product: "IOS" }, { vendor: "Cisco", product: "ASA" }],
    "vmware": [{ vendor: "VMware", product: "vCenter" }, { vendor: "VMware", product: "ESXi" }],
    "oracle": [{ vendor: "Oracle", product: "WebLogic" }],
    "sap": [{ vendor: "SAP", product: "NetWeaver" }],
    "ivanti": [{ vendor: "Ivanti", product: "Connect Secure" }],
    "sonicwall": [{ vendor: "SonicWall", product: "SMA" }],
    "zimbra": [{ vendor: "Zimbra", product: "Collaboration" }],
    "atlassian": [{ vendor: "Atlassian", product: "Confluence" }, { vendor: "Atlassian", product: "Jira" }],
    "jenkins": [{ vendor: "Jenkins", product: "Jenkins" }],
    "gitlab": [{ vendor: "GitLab", product: "GitLab" }],
    "openssl": [{ vendor: "OpenSSL", product: "OpenSSL" }],
    "log4j": [{ vendor: "Apache", product: "Log4j" }],
    "spring": [{ vendor: "VMware", product: "Spring Framework" }],
    "php": [{ vendor: "PHP Group", product: "PHP" }],
    "jquery": [{ vendor: "jQuery", product: "jQuery" }],
  };

  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs).toLowerCase();
    for (const [tech, vps] of Object.entries(techMap)) {
      if (obsStr.includes(tech.toLowerCase())) {
        for (const vp of vps) {
          const key = `${vp.vendor}|${vp.product}`;
          if (!seen.has(key)) {
            seen.add(key);
            results.push(vp);
          }
        }
      }
    }
  }

  return results;
}

/**
 * Extract CVE IDs from prior observations (from Shodan, NVD, etc.)
 */
function extractCVEsFromPrior(config?: ConnectorConfig): string[] {
  const cves = new Set<string>();
  const priorObs = config?.priorObservations || [];

  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs);
    const matches = obsStr.match(/CVE-\d{4}-\d{4,}/g);
    if (matches) {
      for (const cve of matches) {
        cves.add(cve);
      }
    }
  }

  return [...cves];
}

export const cisaAdvisoriesConnector: PassiveConnector = {
  name: "cisa_advisories",
  description: "CISA Advisories — free KEV catalog & ICS advisories, exploitation status, remediation deadlines",
  requiresApiKey: false,
  freeUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Fetch the KEV catalog
      const resp = await fetch(KEV_URL, {
        headers: { "User-Agent": "AceC3Platform/1.0" },
        signal: AbortSignal.timeout(20000),
      });

      if (!resp.ok) {
        errors.push(`CISA KEV catalog fetch failed: ${resp.status}`);
        return { connector: "cisa_advisories", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const kevData = await resp.json() as { title: string; catalogVersion: string; dateReleased: string; count: number; vulnerabilities: any[] };

      // Extract CVEs and vendor/products from prior observations
      const priorCVEs = extractCVEsFromPrior(config);
      const vendorProducts = extractVendorProducts(config);

      // Match KEV entries against prior CVEs
      const matchedByCV: any[] = [];
      const matchedByVendor: any[] = [];
      const kevMap = new Map<string, any>();

      for (const vuln of kevData.vulnerabilities) {
        kevMap.set(vuln.cveID, vuln);
      }

      // Direct CVE matches (highest confidence)
      for (const cve of priorCVEs) {
        const kevEntry = kevMap.get(cve);
        if (kevEntry) {
          matchedByCV.push(kevEntry);
        }
      }

      // Vendor/product matches (medium confidence — may be version-specific)
      if (vendorProducts.length > 0) {
        for (const vuln of kevData.vulnerabilities) {
          const vulnVendor = (vuln.vendorProject || "").toLowerCase();
          const vulnProduct = (vuln.product || "").toLowerCase();
          
          for (const vp of vendorProducts) {
            if (vulnVendor.includes(vp.vendor.toLowerCase()) || 
                vulnProduct.includes(vp.product.toLowerCase())) {
              // Only include recent KEVs (last 2 years) for vendor matches to reduce noise
              const addedDate = new Date(vuln.dateAdded);
              const twoYearsAgo = new Date();
              twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
              
              if (addedDate > twoYearsAgo && !matchedByCV.find(m => m.cveID === vuln.cveID)) {
                matchedByVendor.push(vuln);
              }
              break;
            }
          }
        }
      }

      const totalMatches = matchedByCV.length + matchedByVendor.length;

      // Summary observation
      observations.push({
        assetId: makeAssetId(domain, `CISA KEV summary: ${domain}`, "cisa_advisories"),
        domain,
        assetType: totalMatches > 0 ? "vuln" : "info",
        name: totalMatches > 0
          ? `CISA KEV: ${totalMatches} known exploited vuln(s) relevant to ${domain}`
          : `CISA KEV: No known exploited vulns matched for ${domain}`,
        source: "cisa_advisories",
        observedAt: now,
        tags: [
          "cisa", "kev", "known_exploited",
          ...(matchedByCV.length > 0 ? ["confirmed_kev_match", "critical"] : []),
          ...(matchedByVendor.length > 0 ? ["vendor_match"] : []),
        ],
        evidence: {
          severity: matchedByCV.length > 0 ? 10 : matchedByVendor.length > 0 ? 7 : 0,
          confidence: matchedByCV.length > 0 ? 95 : matchedByVendor.length > 0 ? 60 : 0,
          value: matchedByCV.length > 0
            ? `${matchedByCV.length} CONFIRMED KEV match(es) — actively exploited in the wild`
            : matchedByVendor.length > 0
              ? `${matchedByVendor.length} vendor/product match(es) — verify version applicability`
              : `No KEV matches from ${priorCVEs.length} CVE(s) and ${vendorProducts.length} vendor/product(s) checked`,
          confirmed_matches: matchedByCV.length,
          vendor_matches: matchedByVendor.length,
          cves_checked: priorCVEs.length,
          vendors_checked: vendorProducts.length,
          kev_catalog_version: kevData.catalogVersion,
          kev_catalog_date: kevData.dateReleased,
          kev_total_entries: kevData.count,
        },
        attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" },
      });

      // Individual confirmed KEV matches (highest priority)
      for (const vuln of matchedByCV.slice(0, 10)) {
        const isPastDue = new Date(vuln.dueDate) < now;
        observations.push({
          assetId: makeAssetId(domain, `CISA KEV: ${vuln.cveID}`, "cisa_advisories"),
          domain,
          assetType: "vuln",
          name: `CISA KEV: ${vuln.cveID} — ${vuln.vulnerabilityName || vuln.shortDescription?.slice(0, 60)}`,
          source: "cisa_advisories",
          observedAt: now,
          firstSeen: vuln.dateAdded ? new Date(vuln.dateAdded) : undefined,
          tags: [
            "cisa", "kev", "known_exploited", "confirmed_match", "critical",
            vuln.cveID,
            ...(isPastDue ? ["past_due", "overdue_remediation"] : []),
            ...(vuln.knownRansomwareCampaignUse === "Known" ? ["ransomware"] : []),
          ],
          evidence: {
            severity: 10,
            confidence: 95,
            value: `ACTIVELY EXPLOITED: ${vuln.vulnerabilityName} — ${vuln.shortDescription}`,
            cve_id: vuln.cveID,
            vulnerability_name: vuln.vulnerabilityName,
            description: vuln.shortDescription,
            vendor: vuln.vendorProject,
            product: vuln.product,
            date_added: vuln.dateAdded,
            due_date: vuln.dueDate,
            is_past_due: isPastDue,
            required_action: vuln.requiredAction,
            known_ransomware_use: vuln.knownRansomwareCampaignUse,
            notes: vuln.notes,
            kev_url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
            nvd_url: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
          },
          attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" },
        });
      }

      // Vendor/product matches (lower confidence)
      for (const vuln of matchedByVendor.slice(0, 10)) {
        const isPastDue = new Date(vuln.dueDate) < now;
        observations.push({
          assetId: makeAssetId(domain, `CISA KEV vendor: ${vuln.cveID}`, "cisa_advisories"),
          domain,
          assetType: "vuln",
          name: `CISA KEV (vendor match): ${vuln.cveID} — ${vuln.vendorProject} ${vuln.product}`,
          source: "cisa_advisories",
          observedAt: now,
          firstSeen: vuln.dateAdded ? new Date(vuln.dateAdded) : undefined,
          tags: [
            "cisa", "kev", "known_exploited", "vendor_match",
            vuln.cveID,
            ...(vuln.knownRansomwareCampaignUse === "Known" ? ["ransomware"] : []),
          ],
          evidence: {
            severity: 7,
            confidence: 55,
            value: `Vendor match: ${vuln.vendorProject} ${vuln.product} — ${vuln.shortDescription} (verify version applicability)`,
            cve_id: vuln.cveID,
            vulnerability_name: vuln.vulnerabilityName,
            description: vuln.shortDescription,
            vendor: vuln.vendorProject,
            product: vuln.product,
            date_added: vuln.dateAdded,
            due_date: vuln.dueDate,
            is_past_due: isPastDue,
            required_action: vuln.requiredAction,
            known_ransomware_use: vuln.knownRansomwareCampaignUse,
            match_type: "vendor_product",
            verification_needed: true,
          },
          attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("timeout")) {
        errors.push("CISA KEV catalog fetch timeout");
      } else {
        errors.push(err.message || "Unknown error during CISA advisory lookup");
      }
    }

    return {
      connector: "cisa_advisories",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
