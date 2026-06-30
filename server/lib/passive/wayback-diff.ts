/**
 * Wayback Content Diff Analysis Connector
 * 
 * Compares historical Wayback Machine snapshots to detect:
 * - Removed admin panels
 * - Leaked credentials or API keys
 * - Exposed configuration files
 * - Removed sensitive endpoints
 * 
 * Method: Query Wayback CDX API for historical URLs → identify sensitive patterns
 * Data Source: Internet Archive Wayback Machine CDX API (free)
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

/** Patterns that indicate sensitive/interesting historical content */
const SENSITIVE_PATTERNS = [
  { pattern: /\/(admin|administrator|wp-admin|phpmyadmin|cpanel|webmin|manager)/i, category: "admin_panel", severity: "medium" },
  { pattern: /\/(\.env|\.git|\.svn|\.htaccess|\.htpasswd|web\.config|\.DS_Store)/i, category: "config_exposure", severity: "high" },
  { pattern: /\/(backup|dump|export|sql|database|db)\.(zip|tar|gz|sql|bak|old)/i, category: "backup_file", severity: "high" },
  { pattern: /\/(api[-_]?key|secret|token|password|credential|auth)/i, category: "credential_exposure", severity: "critical" },
  { pattern: /\/(swagger|api-docs|openapi|graphql|graphiql|playground)/i, category: "api_documentation", severity: "medium" },
  { pattern: /\/(debug|trace|test|staging|dev|internal)/i, category: "debug_endpoint", severity: "medium" },
  { pattern: /\/(phpinfo|server-status|server-info|status|health)/i, category: "server_info", severity: "medium" },
  { pattern: /\/(\.well-known|robots\.txt|sitemap\.xml|crossdomain\.xml)/i, category: "metadata", severity: "info" },
  { pattern: /\/(upload|uploads|files|documents|attachments|media)/i, category: "file_upload", severity: "low" },
  { pattern: /\/(jenkins|gitlab|jira|confluence|bamboo|sonarqube|grafana|kibana)/i, category: "devops_tool", severity: "medium" },
  { pattern: /\/(wp-content|wp-includes|wp-json)/i, category: "wordpress", severity: "info" },
  { pattern: /\/(cgi-bin|fcgi|wsgi)/i, category: "cgi_endpoint", severity: "low" },
  { pattern: /\.(bak|old|orig|copy|tmp|temp|swp|save)$/i, category: "backup_extension", severity: "medium" },
  { pattern: /\.(log|logs|error_log|access_log)$/i, category: "log_file", severity: "high" },
  { pattern: /\.(conf|config|cfg|ini|properties|yaml|yml|toml)$/i, category: "config_file", severity: "high" },
];

export const waybackDiffConnector: PassiveConnector = {
  name: "wayback_diff",
  description: "Wayback content diff analysis — discovers removed admin panels, leaked credentials, and exposed configs from historical snapshots",
  requiresApiKey: false,
  freeUrl: "https://web.archive.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 200;

    try {
      // Query Wayback CDX API for all archived URLs
      const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=5000`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let rows: string[][];
      try {
        const res = await fetch(cdxUrl, { signal: controller.signal });
        if (!res.ok) throw new Error(`Wayback CDX returned ${res.status}`);
        rows = await res.json();
      } finally {
        clearTimeout(timer);
      }

      if (!Array.isArray(rows) || rows.length < 2) {
        return { connector: "wayback_diff", domain, observations, errors: ["No Wayback data found"], durationMs: Date.now() - start, rateLimited: false };
      }

      // Skip header row
      const dataRows = rows.slice(1);
      const seen = new Set<string>();
      const now = new Date();
      const categoryCounts: Record<string, number> = {};

      for (const row of dataRows) {
        if (observations.length >= maxResults) break;
        const [originalUrl, timestamp, statusCode, mimeType] = row;
        if (!originalUrl) continue;

        // Check against sensitive patterns
        for (const { pattern, category, severity } of SENSITIVE_PATTERNS) {
          if (pattern.test(originalUrl)) {
            const urlKey = `${category}:${originalUrl}`;
            if (seen.has(urlKey)) continue;
            seen.add(urlKey);

            categoryCounts[category] = (categoryCounts[category] || 0) + 1;

            const archiveUrl = `https://web.archive.org/web/${timestamp}/${originalUrl}`;

            observations.push({
              assetId: makeAssetId(domain, urlKey, "wayback_diff"),
              domain,
              assetType: "url",
              name: originalUrl,
              source: "wayback_diff",
              observedAt: now,
              firstSeen: timestamp ? new Date(
                parseInt(timestamp.slice(0, 4)),
                parseInt(timestamp.slice(4, 6)) - 1,
                parseInt(timestamp.slice(6, 8))
              ) : undefined,
              tags: ["wayback", "historical", category, `severity_${severity}`],
              evidence: {
                originalUrl,
                archiveTimestamp: timestamp,
                statusCode,
                mimeType,
                archiveUrl,
                category,
                severity,
              },
              attribution: {
                provider: "Internet Archive Wayback Machine",
                url: archiveUrl,
                method: `Historical content analysis — found ${category} pattern in archived URL from ${timestamp}`,
                verifyUrl: archiveUrl,
              },
            });
            break; // Only match first pattern per URL
          }
        }
      }

      // Add summary observation
      if (Object.keys(categoryCounts).length > 0) {
        observations.push({
          assetId: makeAssetId(domain, "wayback_summary", "wayback_diff"),
          domain,
          assetType: "infrastructure",
          name: `wayback_analysis:${domain}`,
          source: "wayback_diff",
          observedAt: now,
          tags: ["wayback", "summary"],
          evidence: {
            totalArchived: dataRows.length,
            sensitiveFindings: observations.length,
            categoryCounts,
          },
          attribution: {
            provider: "Internet Archive Wayback Machine",
            url: `https://web.archive.org/web/*/${domain}`,
            method: `Analyzed ${dataRows.length} archived URLs for ${domain} — found ${observations.length} sensitive patterns across ${Object.keys(categoryCounts).length} categories`,
            verifyUrl: `https://web.archive.org/web/*/${domain}`,
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("429")) {
        return { connector: "wayback_diff", domain, observations, errors: ["Wayback CDX rate limited"], durationMs: Date.now() - start, rateLimited: true };
      }
      errors.push(`Wayback diff error: ${err.message}`);
    }

    return { connector: "wayback_diff", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
