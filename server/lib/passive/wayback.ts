/**
 * Wayback Machine CDX — Web Archive Connector
 * 
 * Queries the Internet Archive's CDX index for all historically archived URLs
 * under *.domain/*. Reveals historical attack surface — forgotten admin panels,
 * old API endpoints, deprecated staging environments.
 * 
 * Method: Queries Wayback CDX API with domain wildcard
 * Data Source: Internet Archive's web crawl dataset (billions of archived pages)
 * Attribution: Each observation links to the archived page for verification
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

function extractSubdomain(urlStr: string, domain: string): string | null {
  try {
    // CDX returns URLs without protocol sometimes
    const normalized = urlStr.startsWith("http") ? urlStr : `https://${urlStr}`;
    const parsed = new URL(normalized);
    const host = parsed.hostname.toLowerCase();
    if (host.endsWith(`.${domain}`) || host === domain) {
      return host;
    }
  } catch {
    // Parse failures are expected for malformed archived URLs
  }
  return null;
}

export const waybackConnector: PassiveConnector = {
  name: "wayback",
  description: "Internet Archive CDX search — discovers historical URLs and subdomains from the Wayback Machine's web crawl archive",
  requiresApiKey: false,
  freeUrl: "https://web.archive.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 45000; // Wayback can be slow
    const maxResults = config?.maxResults ?? 2000;

    try {
      const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=${maxResults}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let rows: any[];
      try {
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok) throw new Error(`Wayback CDX returned ${res.status}`);
        rows = await res.json();
      } finally {
        clearTimeout(timer);
      }

      // First row is header: ["original", "timestamp", "statuscode", "mimetype"]
      if (rows.length <= 1) {
        return { connector: "wayback", domain, observations: [], errors: [], durationMs: Date.now() - start, rateLimited: false };
      }

      const now = new Date();
      const seenSubdomains = new Set<string>();
      const seenUrls = new Set<string>();

      for (let i = 1; i < rows.length; i++) {
        const [original, timestamp, statusCode, mimeType] = rows[i];
        if (!original) continue;

        const subdomain = extractSubdomain(original, domain);
        if (!subdomain) continue;

        // Parse Wayback timestamp (YYYYMMDDHHmmss)
        let archivedAt: Date | undefined;
        if (timestamp && timestamp.length >= 8) {
          const y = timestamp.slice(0, 4);
          const m = timestamp.slice(4, 6);
          const d = timestamp.slice(6, 8);
          const h = timestamp.slice(8, 10) || "00";
          const mi = timestamp.slice(10, 12) || "00";
          const s = timestamp.slice(12, 14) || "00";
          archivedAt = new Date(`${y}-${m}-${d}T${h}:${mi}:${s}Z`);
        }

        // Create subdomain observation (deduplicated)
        if (!seenSubdomains.has(subdomain)) {
          seenSubdomains.add(subdomain);
          observations.push({
            assetId: makeAssetId(domain, subdomain, "wayback_sub"),
            domain,
            assetType: "subdomain",
            name: subdomain,
            source: "wayback",
            observedAt: now,
            firstSeen: archivedAt,
            tags: ["historical", "web_archive"],
            evidence: {
              first_archived: timestamp,
              sample_url: original,
            },
            attribution: {
              provider: "Wayback Machine (Internet Archive)",
              url: `https://web.archive.org/web/*/${subdomain}`,
              method: `Wayback Machine CDX index search — found historical web crawl records for ${subdomain} in the Internet Archive`,
              verifyUrl: `https://web.archive.org/web/*/${subdomain}`,
            },
          });
        }

        // Create URL observation (deduplicated, limited)
        const urlKey = original.toLowerCase();
        if (!seenUrls.has(urlKey) && seenUrls.size < 500) {
          seenUrls.add(urlKey);
          observations.push({
            assetId: makeAssetId(domain, urlKey, "wayback_url"),
            domain,
            assetType: "url",
            name: original,
            source: "wayback",
            observedAt: now,
            firstSeen: archivedAt,
            tags: [
              "historical",
              `status:${statusCode}`,
              `mime:${mimeType}`,
              ...(original.match(/admin|console|mgmt|login|auth/i) ? ["admin_path"] : []),
              ...(original.match(/api|graphql|swagger/i) ? ["api_path"] : []),
              ...(original.match(/dev|test|stage|staging|qa/i) ? ["staging_path"] : []),
            ],
            evidence: {
              original_url: original,
              archived_timestamp: timestamp,
              status_code: statusCode,
              mime_type: mimeType,
              wayback_url: `https://web.archive.org/web/${timestamp}/${original}`,
            },
            attribution: {
              provider: "Wayback Machine (Internet Archive)",
              url: `https://web.archive.org/web/${timestamp}/${original}`,
              method: `Historical URL discovered in Wayback Machine CDX index — page was archived on ${timestamp} with HTTP ${statusCode}`,
              verifyUrl: `https://web.archive.org/web/${timestamp}/${original}`,
            },
          });
        }
      }
    } catch (err: any) {
      if (err.name === "AbortError") {
        errors.push("Wayback CDX request timed out (archive may be slow)");
      } else {
        errors.push(`Wayback error: ${err.message}`);
      }
    }

    return {
      connector: "wayback",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
