/**
 * CommonCrawl Index Connector — Free, No API Key
 * 
 * Searches the CommonCrawl index for historical web pages
 * of the target domain. Useful for discovering:
 * - Historical pages and content changes
 * - Exposed directories, admin panels, API docs
 * - Old subdomains and URL patterns
 * 
 * API docs: https://index.commoncrawl.org/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const CC_INDEX = 'https://index.commoncrawl.org/CC-MAIN-2024-51-index';

export const commoncrawlConnector: PassiveConnector = {
  name: "commoncrawl",
  description: 'CommonCrawl — free historical web crawl data, exposed pages, URL patterns',
  requiresApiKey: false,
  freeUrl: "https://commoncrawl.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const now = new Date();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    let rateLimited = false;

    try {
      const resp = await fetch(
        `${CC_INDEX}?url=*.${domain}&output=json&limit=200`,
        {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
          signal: config?.timeout ? AbortSignal.timeout(config.timeout) : AbortSignal.timeout(20000),
        }
      );

      if (resp.status === 429) {
        rateLimited = true;
      }

      if (resp.ok) {
        const text = await resp.text();
        const records = text
          .split('\n')
          .filter(line => line.trim())
          .map(line => {
            try { return JSON.parse(line); } catch { return null; }
          })
          .filter(Boolean);

        if (records.length > 0) {
          const urls = new Set<string>();
          const subdomains = new Set<string>();
          const statusCodes = new Map<number, number>();
          const mimeTypes = new Map<string, number>();
          const interestingPaths: string[] = [];

          for (const r of records) {
            if (r.url) urls.add(r.url);

            try {
              const u = new URL(r.url.startsWith('http') ? r.url : `https://${r.url}`);
              if (u.hostname.endsWith(domain)) {
                subdomains.add(u.hostname);
              }

              const path = u.pathname.toLowerCase();
              if (
                path.includes('/admin') || path.includes('/api/') ||
                path.includes('/swagger') || path.includes('/graphql') ||
                path.includes('/.env') || path.includes('/config') ||
                path.includes('/backup') || path.includes('/debug') ||
                path.includes('/phpmyadmin') || path.includes('/wp-admin') ||
                path.includes('/.git') || path.includes('/server-status') ||
                path.includes('/actuator') || path.includes('/console')
              ) {
                interestingPaths.push(r.url);
              }
            } catch { /* skip malformed URLs */ }

            const status = parseInt(r.status) || 0;
            if (status > 0) statusCodes.set(status, (statusCodes.get(status) || 0) + 1);

            if (r.mime) mimeTypes.set(r.mime, (mimeTypes.get(r.mime) || 0) + 1);
          }

          const intelName = `CommonCrawl data for ${domain}`;
          observations.push({
            assetId: makeAssetId(domain, intelName, "commoncrawl"),
            domain: domain,
            assetType: 'breach',
            name: intelName,
            source: "commoncrawl",
            observedAt: now,
            tags: ['commoncrawl', 'historical', 'web_archive'],
            evidence: {
              value: `${urls.size} unique URLs, ${subdomains.size} subdomains found in web crawl archive`,
              severity: 0,
              confidence: 70,
              totalUrls: urls.size,
              totalSubdomains: subdomains.size,
              subdomains: Array.from(subdomains).slice(0, 50),
              statusCodes: Object.fromEntries(statusCodes),
              mimeTypes: Object.fromEntries(mimeTypes),
              sampleUrls: Array.from(urls).slice(0, 30),
            },
            attribution: {
              provider: "CommonCrawl",
              url: "https://commoncrawl.org",
              method: "api",
            },
          });

          if (subdomains.size > 1) {
            for (const sub of Array.from(subdomains).slice(0, 30)) {
              if (sub !== domain && sub !== `www.${domain}`) {
                observations.push({
                  assetId: makeAssetId(domain, sub, "commoncrawl"),
                  domain: domain,
                  assetType: 'subdomain',
                  name: sub,
                  source: "commoncrawl",
                  observedAt: now,
                  tags: ['commoncrawl', 'subdomain', 'historical'],
                  evidence: {
                    value: `Subdomain discovered via CommonCrawl archive`,
                    severity: 0,
                    confidence: 60,
                  },
                  attribution: {
                    provider: "CommonCrawl",
                    url: "https://commoncrawl.org",
                    method: "api",
                  },
                });
              }
            }
          }

          if (interestingPaths.length > 0) {
            const pathName = `Potentially sensitive paths found for ${domain}`;
            observations.push({
              assetId: makeAssetId(domain, pathName, "commoncrawl"),
              domain: domain,
              assetType: 'breach',
              name: pathName,
              source: "commoncrawl",
              observedAt: now,
              tags: ['commoncrawl', 'sensitive_path', 'exposure'],
              evidence: {
                value: `${interestingPaths.length} interesting path(s) in crawl archive (admin panels, APIs, configs)`,
                severity: 4,
                confidence: 50,
                note: 'Historical data — paths may no longer be accessible',
                paths: [...new Set(interestingPaths)].slice(0, 20),
              },
              attribution: {
                provider: "CommonCrawl",
                url: "https://commoncrawl.org",
                method: "api",
              },
            });
          }
        }
      } else if (!rateLimited) {
        errors.push(`Failed to fetch data from CommonCrawl: ${resp.status} ${resp.statusText}`);
      }
    } catch (err: any) {
      if (err.name === 'AbortError') {
        errors.push("CommonCrawl lookup timed out");
      } else {
        errors.push(`CommonCrawl lookup error: ${err.message}`);
      }
    }

    return {
      connector: 'commoncrawl',
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
