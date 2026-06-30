/**
 * GitHub Security Advisories (GHSA) Connector — Free, API Key Optional
 * 
 * Queries the GitHub Advisory Database for known vulnerabilities
 * in packages/technologies detected on the target domain.
 * Complements NVD/CVE with faster disclosure and ecosystem-specific data.
 * 
 * API docs: https://docs.github.com/en/rest/security-advisories/global-advisories
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const GHSA_API = "https://api.github.com/advisories";

// Common web technology packages to check against GHSA
const TECH_TO_ECOSYSTEM: Record<string, { ecosystem: string; packages: string[] }> = {
  "wordpress": { ecosystem: "composer", packages: ["wordpress/wordpress"] },
  "drupal": { ecosystem: "composer", packages: ["drupal/core", "drupal/drupal"] },
  "laravel": { ecosystem: "composer", packages: ["laravel/framework"] },
  "django": { ecosystem: "pip", packages: ["django"] },
  "flask": { ecosystem: "pip", packages: ["flask"] },
  "express": { ecosystem: "npm", packages: ["express"] },
  "next.js": { ecosystem: "npm", packages: ["next"] },
  "react": { ecosystem: "npm", packages: ["react", "react-dom"] },
  "angular": { ecosystem: "npm", packages: ["@angular/core"] },
  "vue": { ecosystem: "npm", packages: ["vue"] },
  "jquery": { ecosystem: "npm", packages: ["jquery"] },
  "apache": { ecosystem: "maven", packages: ["org.apache.httpd:httpd"] },
  "nginx": { ecosystem: "other", packages: ["nginx"] },
  "openssl": { ecosystem: "other", packages: ["openssl"] },
  "php": { ecosystem: "composer", packages: ["php"] },
  "ruby on rails": { ecosystem: "rubygems", packages: ["rails", "actionpack"] },
  "spring": { ecosystem: "maven", packages: ["org.springframework:spring-core"] },
  "tomcat": { ecosystem: "maven", packages: ["org.apache.tomcat:tomcat"] },
};

export const githubAdvisoriesConnector: PassiveConnector = {
  name: "github_advisories",
  description: "GitHub Security Advisories (GHSA) — vulnerability database for open-source packages",
  requiresApiKey: false,
  freeUrl: "https://github.com/advisories",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Build headers — use GitHub PAT if available for higher rate limits
      const headers: Record<string, string> = {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AC3-SecurityScanner/1.0",
      };
      const ghToken = config?.env?.GITHUB_PAT || config?.env?.GITHUB_CLASSIC_TOKEN;
      if (ghToken) {
        headers.Authorization = `Bearer ${ghToken}`;
      }

      // Detect technologies from prior scan context if available
      const detectedTechs: string[] = [];
      if (config?.context?.technologies) {
        for (const tech of config.context.technologies) {
          const normalized = tech.toLowerCase();
          for (const [key] of Object.entries(TECH_TO_ECOSYSTEM)) {
            if (normalized.includes(key)) {
              detectedTechs.push(key);
            }
          }
        }
      }

      // If no technologies detected, search by domain keyword
      const searchTerms = detectedTechs.length > 0 ? detectedTechs : [domain.split(".")[0]];
      const seenGhsaIds = new Set<string>();

      for (const term of searchTerms.slice(0, 5)) {
        try {
          const techMapping = TECH_TO_ECOSYSTEM[term];
          let url: string;

          if (techMapping) {
            // Search by ecosystem and package
            const pkg = techMapping.packages[0];
            url = `${GHSA_API}?affects=${encodeURIComponent(pkg)}&severity=critical,high&per_page=10&sort=updated&direction=desc`;
          } else {
            // Keyword search
            url = `${GHSA_API}?type=reviewed&severity=critical,high&per_page=10&sort=updated&direction=desc`;
          }

          const resp = await rateLimitedFetch("github_advisories", url, {
            headers,
            signal: AbortSignal.timeout(12000),
          });

          if (resp.status === 403 || resp.status === 429) {
            rateLimited = true;
            errors.push(`GitHub API rate limited (${resp.status})`);
            break;
          }

          if (!resp.ok) continue;

          const advisories = await resp.json() as any[];
          if (!Array.isArray(advisories)) continue;

          for (const adv of advisories) {
            if (seenGhsaIds.has(adv.ghsa_id)) continue;
            seenGhsaIds.add(adv.ghsa_id);

            const cveId = adv.cve_id || null;
            const severity = adv.severity || "unknown";
            const severityScore = severity === "critical" ? 10 :
                                  severity === "high" ? 8 :
                                  severity === "medium" ? 5 : 3;

            const affectedPackages = (adv.vulnerabilities || [])
              .map((v: any) => `${v.package?.ecosystem}/${v.package?.name}@${v.vulnerable_version_range || "?"}`)
              .slice(0, 5);

            const name = `GHSA: ${adv.ghsa_id} — ${(adv.summary || "").slice(0, 80)}`;

            observations.push({
              assetId: makeAssetId(domain, adv.ghsa_id, "github_advisories"),
              domain,
              assetType: "vulnerability",
              name,
              source: "github_advisories",
              observedAt: now,
              firstSeen: adv.published_at ? new Date(adv.published_at) : undefined,
              lastSeen: adv.updated_at ? new Date(adv.updated_at) : undefined,
              tags: ["github_advisories", "ghsa", severity, ...(cveId ? [cveId] : []), term],
              evidence: {
                severity: severityScore,
                confidence: techMapping ? 75 : 40, // Higher confidence if tech was detected
                value: `${severity.toUpperCase()} — ${adv.summary || "No summary"}`,
                ghsa_id: adv.ghsa_id,
                cve_id: cveId,
                severity_level: severity,
                cvss_score: adv.cvss?.score,
                cvss_vector: adv.cvss?.vector_string,
                summary: adv.summary,
                description: (adv.description || "").slice(0, 500),
                affected_packages: affectedPackages,
                published_at: adv.published_at,
                updated_at: adv.updated_at,
                withdrawn_at: adv.withdrawn_at,
                html_url: adv.html_url,
                detected_technology: term,
                cwes: (adv.cwes || []).map((c: any) => c.cwe_id),
              },
              attribution: {
                provider: "GitHub Advisory Database",
                url: "https://github.com/advisories",
                method: "api",
              },
            });
          }
        } catch (err: any) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(`GHSA lookup for "${term}": ${err.message}`);
        }
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during GitHub Advisories lookup");
    }

    return {
      connector: "github_advisories",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
