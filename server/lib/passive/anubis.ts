/**
 * Anubis — Free Subdomain Enumeration Connector
 * 
 * Queries the Anubis API (jldc.me) for subdomains of a given domain.
 * Anubis aggregates data from certificate transparency logs and DNS records.
 * 
 * Method: GET https://jldc.me/anubis/subdomains/{domain}
 * Data Source: Certificate transparency + DNS aggregation
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const anubisConnector: PassiveConnector = {
  name: "anubis",
  description: "Anubis subdomain enumeration — discovers subdomains via jldc.me aggregation of CT logs and DNS data",
  requiresApiKey: false,
  freeUrl: "https://jldc.me/anubis/subdomains",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      
      let subdomains: string[];
      try {
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok) throw new Error(`Anubis returned ${res.status}`);
        subdomains = await res.json();
      } finally {
        clearTimeout(timer);
      }

      if (!Array.isArray(subdomains)) {
        errors.push("Anubis returned non-array response");
        return { connector: "anubis", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const seen = new Set<string>();
      const now = new Date();

      for (const sub of subdomains) {
        const name = sub.trim().toLowerCase();
        if (!name || name.startsWith("*.") || seen.has(name)) continue;
        if (!name.endsWith(`.${domain}`) && name !== domain) continue;
        seen.add(name);
        if (seen.size > maxResults) break;

        observations.push({
          assetId: makeAssetId(domain, name, "anubis"),
          domain,
          assetType: "subdomain",
          name,
          source: "anubis",
          observedAt: now,
          tags: ["subdomain_enum", "ct_aggregation"],
          evidence: { rawSubdomain: sub },
          attribution: {
            provider: "Anubis (jldc.me)",
            url: `https://jldc.me/anubis/subdomains/${domain}`,
            method: `Anubis subdomain enumeration — queried jldc.me API for subdomains of ${domain}`,
            verifyUrl: `https://jldc.me/anubis/subdomains/${domain}`,
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("429")) {
        return { connector: "anubis", domain, observations, errors: ["Anubis rate limited"], durationMs: Date.now() - start, rateLimited: true };
      }
      errors.push(`Anubis error: ${err.message}`);
    }

    return { connector: "anubis", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
