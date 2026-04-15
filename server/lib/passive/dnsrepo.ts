/**
 * DNSRepo — Free Subdomain Enumeration Connector
 * 
 * Queries the DNSRepo API for subdomains of a given domain.
 * DNSRepo maintains a large database of DNS records from zone files.
 * 
 * Method: GET https://dnsrepo.noc.org/?domain={domain} (HTML scraping)
 * Data Source: DNS zone file aggregation
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const dnsrepoConnector: PassiveConnector = {
  name: "dnsrepo",
  description: "DNSRepo subdomain enumeration — discovers subdomains from DNS zone file database",
  requiresApiKey: false,
  freeUrl: "https://dnsrepo.noc.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const url = `https://dnsrepo.noc.org/?domain=${encodeURIComponent(domain)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let html: string;
      try {
        const res = await fetch(url, {
          signal: controller.signal,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" },
        });
        if (!res.ok) throw new Error(`DNSRepo returned ${res.status}`);
        html = await res.text();
      } finally {
        clearTimeout(timer);
      }

      // Parse subdomains from the HTML response
      // DNSRepo lists subdomains in table rows or anchor tags
      const subdomainRegex = new RegExp(`([a-zA-Z0-9][-a-zA-Z0-9]*\\.)*${domain.replace(/\./g, '\\.')}`, 'gi');
      const seen = new Set<string>();
      const now = new Date();
      let match: RegExpExecArray | null;

      while ((match = subdomainRegex.exec(html)) !== null) {
        const name = match[0].trim().toLowerCase();
        if (!name || name.startsWith("*.") || seen.has(name)) continue;
        if (!name.endsWith(`.${domain}`) && name !== domain) continue;
        // Skip if it looks like a CSS class or HTML attribute
        if (name.includes("_") || name.length > 253) continue;
        seen.add(name);
        if (seen.size > maxResults) break;

        observations.push({
          assetId: makeAssetId(domain, name, "dnsrepo"),
          domain,
          assetType: "subdomain",
          name,
          source: "dnsrepo",
          observedAt: now,
          tags: ["subdomain_enum", "dns_zone"],
          evidence: { rawMatch: match[0] },
          attribution: {
            provider: "DNSRepo (noc.org)",
            url: `https://dnsrepo.noc.org/?domain=${domain}`,
            method: `DNSRepo subdomain enumeration — scraped DNS zone file database for subdomains of ${domain}`,
            verifyUrl: `https://dnsrepo.noc.org/?domain=${domain}`,
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("429")) {
        return { connector: "dnsrepo", domain, observations, errors: ["DNSRepo rate limited"], durationMs: Date.now() - start, rateLimited: true };
      }
      errors.push(`DNSRepo error: ${err.message}`);
    }

    return { connector: "dnsrepo", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
