/**
 * OSV.dev Connector — Free, No API Key
 * 
 * Queries the Open Source Vulnerabilities database for supply chain
 * vulnerabilities in packages detected on the target's tech stack
 * (npm, PyPI, Go, Maven, etc.). Complements NVD by covering
 * ecosystem-specific advisories that NVD often lags on.
 * 
 * API docs: https://osv.dev/docs/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const API_URL = "https://api.osv.dev/v1";

async function osvQuery(body: Record<string, any>): Promise<any> {
  const resp = await fetch(`${API_URL}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) return null;
  return resp.json();
}

async function osvQueryBatch(queries: Record<string, any>[]): Promise<any> {
  const resp = await fetch(`${API_URL}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(20000),
  });
  if (!resp.ok) return null;
  return resp.json();
}

/**
 * Extract package names from tech stack observations collected by other connectors.
 * Looks for common frameworks/libraries in the config's prior observations.
 */
function extractPackagesFromTechStack(config?: ConnectorConfig): { name: string; ecosystem: string }[] {
  const packages: { name: string; ecosystem: string }[] = [];
  const priorObs = config?.priorObservations || [];

  // Common web technology → package mappings
  const techToPackage: Record<string, { name: string; ecosystem: string }[]> = {
    "wordpress": [{ name: "wordpress", ecosystem: "Packagist" }],
    "jquery": [{ name: "jquery", ecosystem: "npm" }],
    "react": [{ name: "react", ecosystem: "npm" }],
    "angular": [{ name: "@angular/core", ecosystem: "npm" }],
    "vue": [{ name: "vue", ecosystem: "npm" }],
    "next.js": [{ name: "next", ecosystem: "npm" }],
    "express": [{ name: "express", ecosystem: "npm" }],
    "django": [{ name: "Django", ecosystem: "PyPI" }],
    "flask": [{ name: "Flask", ecosystem: "PyPI" }],
    "rails": [{ name: "rails", ecosystem: "RubyGems" }],
    "spring": [{ name: "org.springframework:spring-core", ecosystem: "Maven" }],
    "laravel": [{ name: "laravel/framework", ecosystem: "Packagist" }],
    "drupal": [{ name: "drupal/core", ecosystem: "Packagist" }],
    "joomla": [{ name: "joomla/joomla-cms", ecosystem: "Packagist" }],
    "nginx": [{ name: "nginx", ecosystem: "Linux" }],
    "apache": [{ name: "apache2", ecosystem: "Linux" }],
    "openssl": [{ name: "openssl", ecosystem: "Linux" }],
    "bootstrap": [{ name: "bootstrap", ecosystem: "npm" }],
    "lodash": [{ name: "lodash", ecosystem: "npm" }],
    "moment": [{ name: "moment", ecosystem: "npm" }],
    "axios": [{ name: "axios", ecosystem: "npm" }],
  };

  // Scan prior observations for tech stack indicators
  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs).toLowerCase();
    for (const [tech, pkgs] of Object.entries(techToPackage)) {
      if (obsStr.includes(tech.toLowerCase())) {
        for (const pkg of pkgs) {
          if (!packages.find(p => p.name === pkg.name && p.ecosystem === pkg.ecosystem)) {
            packages.push(pkg);
          }
        }
      }
    }
  }

  return packages;
}

export const osvDevConnector: PassiveConnector = {
  name: "osv_dev",
  description: "OSV.dev — free open source vulnerability database, supply chain vulns for npm/PyPI/Go/Maven/RubyGems",
  requiresApiKey: false,
  freeUrl: "https://osv.dev",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Extract packages from tech stack detected by other connectors
      const packages = extractPackagesFromTechStack(config);

      if (packages.length === 0) {
        // No tech stack detected — try common packages as a baseline
        observations.push({
          assetId: makeAssetId(domain, `OSV.dev: no tech stack for ${domain}`, "osv_dev"),
          domain,
          assetType: "info",
          name: `OSV.dev: No detected tech stack packages to query for ${domain}`,
          source: "osv_dev",
          observedAt: now,
          tags: ["osv_dev", "supply_chain", "no_tech_stack"],
          evidence: {
            severity: 0,
            status: "no_packages",
            value: "No technology packages detected from prior recon — run BuiltWith/Wappalyzer first for best results",
          },
          attribution: { provider: "OSV.dev", url: "https://osv.dev", method: "api" },
        });
        return { connector: "osv_dev", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Batch query OSV for all detected packages
      const queries = packages.map(pkg => ({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
      }));

      const batchResult = await osvQueryBatch(queries);
      
      let totalVulns = 0;
      const criticalVulns: any[] = [];
      const highVulns: any[] = [];
      const allVulns: { pkg: { name: string; ecosystem: string }; vulns: any[] }[] = [];

      if (batchResult?.results) {
        for (let i = 0; i < batchResult.results.length; i++) {
          const result = batchResult.results[i];
          const pkg = packages[i];
          
          if (result.vulns && result.vulns.length > 0) {
            totalVulns += result.vulns.length;
            allVulns.push({ pkg, vulns: result.vulns });

            for (const vuln of result.vulns) {
              const severity = vuln.database_specific?.severity || 
                vuln.severity?.[0]?.score || "unknown";
              const cvss = typeof severity === "number" ? severity :
                vuln.severity?.[0]?.score || 0;
              
              if (cvss >= 9.0 || severity === "CRITICAL") {
                criticalVulns.push({ ...vuln, _pkg: pkg });
              } else if (cvss >= 7.0 || severity === "HIGH") {
                highVulns.push({ ...vuln, _pkg: pkg });
              }
            }
          }
        }
      }

      // Summary observation
      observations.push({
        assetId: makeAssetId(domain, `OSV.dev summary: ${domain}`, "osv_dev"),
        domain,
        assetType: totalVulns > 0 ? "vuln" : "info",
        name: totalVulns > 0
          ? `OSV.dev: ${totalVulns} supply chain vuln(s) across ${allVulns.length} package(s)`
          : `OSV.dev: No known supply chain vulns in ${packages.length} detected package(s)`,
        source: "osv_dev",
        observedAt: now,
        tags: [
          "osv_dev", "supply_chain",
          ...(totalVulns > 0 ? ["vulnerable"] : ["clean"]),
          ...(criticalVulns.length > 0 ? ["critical_supply_chain"] : []),
        ],
        evidence: {
          severity: criticalVulns.length > 0 ? 9 : highVulns.length > 0 ? 7 : totalVulns > 0 ? 5 : 0,
          confidence: 90,
          value: `${totalVulns} vuln(s) in ${packages.length} package(s) — ${criticalVulns.length} critical, ${highVulns.length} high`,
          total_vulns: totalVulns,
          critical_count: criticalVulns.length,
          high_count: highVulns.length,
          packages_scanned: packages.length,
          packages_vulnerable: allVulns.length,
          packages_checked: packages.map(p => `${p.ecosystem}/${p.name}`),
        },
        attribution: { provider: "OSV.dev", url: "https://osv.dev", method: "api" },
      });

      // Individual critical/high vulnerability observations (limit to 15)
      const topVulns = [...criticalVulns, ...highVulns].slice(0, 15);
      for (const vuln of topVulns) {
        const vulnId = vuln.id || vuln.aliases?.[0] || "unknown";
        const pkg = vuln._pkg;
        const cvss = vuln.severity?.[0]?.score || 0;
        const summary = vuln.summary || vuln.details?.slice(0, 200) || "No description";

        observations.push({
          assetId: makeAssetId(domain, `OSV ${vulnId}: ${pkg.name}`, "osv_dev"),
          domain,
          assetType: "vuln",
          name: `OSV ${vulnId}: ${pkg.ecosystem}/${pkg.name} — ${summary.slice(0, 80)}`,
          source: "osv_dev",
          observedAt: now,
          firstSeen: vuln.published ? new Date(vuln.published) : undefined,
          lastSeen: vuln.modified ? new Date(vuln.modified) : undefined,
          tags: [
            "osv_dev", "supply_chain", "vulnerability",
            pkg.ecosystem.toLowerCase(),
            cvss >= 9 ? "critical" : cvss >= 7 ? "high" : "medium",
            ...(vuln.aliases || []).filter((a: string) => a.startsWith("CVE-")),
          ],
          evidence: {
            severity: cvss >= 9 ? 10 : cvss >= 7 ? 8 : 6,
            confidence: 95,
            value: `${vulnId} in ${pkg.ecosystem}/${pkg.name} — CVSS: ${cvss || 'N/A'} — ${summary}`,
            vuln_id: vulnId,
            aliases: vuln.aliases || [],
            package_name: pkg.name,
            package_ecosystem: pkg.ecosystem,
            cvss_score: cvss,
            summary,
            published: vuln.published,
            modified: vuln.modified,
            affected_versions: vuln.affected?.map((a: any) => a.ranges)?.flat() || [],
            references: vuln.references?.map((r: any) => r.url)?.slice(0, 5) || [],
            osv_url: `https://osv.dev/vulnerability/${vulnId}`,
          },
          attribution: { provider: "OSV.dev", url: `https://osv.dev/vulnerability/${vulnId}`, method: "api" },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("timeout")) {
        errors.push("OSV.dev API timeout");
      } else {
        errors.push(err.message || "Unknown error during OSV.dev lookup");
      }
    }

    return {
      connector: "osv_dev",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
