/**
 * RapidDNS — Free Subdomain Enumeration Connector
 * 
 * Queries the RapidDNS API for subdomains of a given domain.
 * RapidDNS maintains a large database of DNS records collected from zone files and active scanning.
 * 
 * Method: GET https://rapiddns.io/subdomain/{domain}?full=1#result (HTML scraping)
 * Data Source: DNS zone files + active DNS scanning
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const rapiddnsConnector: PassiveConnector = {
  name: "rapiddns",
  description: "RapidDNS subdomain enumeration — discovers subdomains from DNS zone files and active scanning database",
  requiresApiKey: false,
  freeUrl: "https://rapiddns.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let html: string;
      try {
        const res = await fetch(url, {
          signal: controller.signal,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" },
        });
        if (!res.ok) throw new Error(`RapidDNS returned ${res.status}`);
        html = await res.text();
      } finally {
        clearTimeout(timer);
      }

      // Parse HTML table rows — RapidDNS returns subdomains in <td> elements
      // Pattern: <td>subdomain.example.com</td><td>A</td><td>1.2.3.4</td>
      const rowRegex = /<td>([^<]+)<\/td>\s*<td>([^<]*)<\/td>\s*<td>([^<]*)<\/td>/g;
      const seen = new Set<string>();
      const now = new Date();
      let match: RegExpExecArray | null;

      while ((match = rowRegex.exec(html)) !== null) {
        const name = match[1].trim().toLowerCase();
        const recordType = match[2].trim();
        const value = match[3].trim();

        if (!name || name.startsWith("*.") || seen.has(name)) continue;
        if (!name.endsWith(`.${domain}`) && name !== domain) continue;
        seen.add(name);
        if (seen.size > maxResults) break;

        const ip = recordType === "A" || recordType === "AAAA" ? value : undefined;

        observations.push({
          assetId: makeAssetId(domain, name, "rapiddns"),
          domain,
          assetType: "subdomain",
          name,
          ip,
          source: "rapiddns",
          observedAt: now,
          tags: ["subdomain_enum", "dns_zone"],
          evidence: { recordType, value, rawMatch: match[0] },
          attribution: {
            provider: "RapidDNS",
            url: `https://rapiddns.io/subdomain/${domain}`,
            method: `RapidDNS subdomain enumeration — scraped DNS record database for subdomains of ${domain}`,
            verifyUrl: `https://rapiddns.io/subdomain/${domain}?full=1`,
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("429")) {
        return { connector: "rapiddns", domain, observations, errors: ["RapidDNS rate limited"], durationMs: Date.now() - start, rateLimited: true };
      }
      errors.push(`RapidDNS error: ${err.message}`);
    }

    return { connector: "rapiddns", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
