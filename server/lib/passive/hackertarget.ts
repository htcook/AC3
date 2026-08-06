/**
 * HackerTarget — Free Subdomain & Host Search Connector
 * 
 * Queries the HackerTarget API for hosts associated with a domain.
 * Returns subdomain/IP pairs from their host search database.
 * 
 * Method: GET https://api.hackertarget.com/hostsearch/?q={domain}
 * Data Source: HackerTarget host database (DNS + web crawling)
 * Free: Yes, no API key required (limited to 100 queries/day without key)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const hackertargetConnector: PassiveConnector = {
  name: "hackertarget",
  description: "HackerTarget host search — discovers subdomains and associated IPs from HackerTarget database",
  requiresApiKey: false,
  freeUrl: "https://hackertarget.com/ip-tools/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let text: string;
      try {
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok) throw new Error(`HackerTarget returned ${res.status}`);
        text = await res.text();
      } finally {
        clearTimeout(timer);
      }

      // Check for error/rate limit responses
      if (text.includes("error") || text.includes("API count exceeded")) {
        const isRateLimited = text.includes("API count exceeded");
        return {
          connector: "hackertarget", domain, observations,
          errors: [isRateLimited ? "HackerTarget daily API limit exceeded" : `HackerTarget error: ${text.slice(0, 200)}`],
          durationMs: Date.now() - start, rateLimited: isRateLimited,
        };
      }

      const seen = new Set<string>();
      const now = new Date();
      const lines = text.split("\n").filter(Boolean);

      for (const line of lines) {
        const parts = line.split(",");
        if (parts.length < 2) continue;
        const name = parts[0].trim().toLowerCase();
        const ip = parts[1].trim();

        if (!name || name.startsWith("*.") || seen.has(name)) continue;
        if (!name.endsWith(`.${domain}`) && name !== domain) continue;
        seen.add(name);
        if (seen.size > maxResults) break;

        observations.push({
          assetId: makeAssetId(domain, name, "hackertarget"),
          domain,
          assetType: "subdomain",
          name,
          ip: ip || undefined,
          source: "hackertarget",
          observedAt: now,
          tags: ["subdomain_enum", "host_search"],
          evidence: { rawLine: line, resolvedIp: ip },
          attribution: {
            provider: "HackerTarget",
            url: `https://api.hackertarget.com/hostsearch/?q=${domain}`,
            method: `HackerTarget host search — queried hostsearch API for hosts under ${domain}`,
            verifyUrl: `https://api.hackertarget.com/hostsearch/?q=${domain}`,
          },
        });
      }
    } catch (err: any) {
      errors.push(`HackerTarget error: ${err.message}`);
    }

    return { connector: "hackertarget", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
