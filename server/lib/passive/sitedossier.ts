/**
 * Sitedossier — Free Subdomain Enumeration Connector
 * 
 * Queries Sitedossier for subdomains of a given domain.
 * Sitedossier maintains a web crawl database with domain/subdomain information.
 * 
 * Method: GET http://www.sitedossier.com/parentdomain/{domain} (HTML scraping)
 * Data Source: Web crawl database
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const sitedossierConnector: PassiveConnector = {
  name: "sitedossier",
  description: "Sitedossier subdomain enumeration — discovers subdomains from web crawl database",
  requiresApiKey: false,
  freeUrl: "http://www.sitedossier.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const url = `http://www.sitedossier.com/parentdomain/${encodeURIComponent(domain)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let html: string;
      try {
        const res = await fetch(url, {
          signal: controller.signal,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" },
        });
        if (!res.ok) throw new Error(`Sitedossier returned ${res.status}`);
        html = await res.text();
      } finally {
        clearTimeout(timer);
      }

      // Parse subdomains from anchor tags pointing to /site/ paths
      // Pattern: <a href="/site/subdomain.example.com">subdomain.example.com</a>
      const linkRegex = /href="\/site\/([^"]+)"/gi;
      const seen = new Set<string>();
      const now = new Date();
      let match: RegExpExecArray | null;

      while ((match = linkRegex.exec(html)) !== null) {
        const name = match[1].trim().toLowerCase();
        if (!name || name.startsWith("*.") || seen.has(name)) continue;
        if (!name.endsWith(`.${domain}`) && name !== domain) continue;
        seen.add(name);
        if (seen.size > maxResults) break;

        observations.push({
          assetId: makeAssetId(domain, name, "sitedossier"),
          domain,
          assetType: "subdomain",
          name,
          source: "sitedossier",
          observedAt: now,
          tags: ["subdomain_enum", "web_crawl"],
          evidence: { rawMatch: match[0] },
          attribution: {
            provider: "Sitedossier",
            url: `http://www.sitedossier.com/parentdomain/${domain}`,
            method: `Sitedossier subdomain enumeration — scraped web crawl database for subdomains of ${domain}`,
            verifyUrl: `http://www.sitedossier.com/parentdomain/${domain}`,
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("429")) {
        return { connector: "sitedossier", domain, observations, errors: ["Sitedossier rate limited"], durationMs: Date.now() - start, rateLimited: true };
      }
      errors.push(`Sitedossier error: ${err.message}`);
    }

    return { connector: "sitedossier", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
