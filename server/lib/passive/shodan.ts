/**
 * Shodan — Internet-Wide Scan Database Connector
 * 
 * Queries Shodan's pre-scanned database for hosts matching the target domain.
 * Returns open ports, service banners, organization info, and ASN data.
 * 
 * Method: Queries Shodan Search API with hostname filter
 * Data Source: Shodan's continuous internet-wide port scanning dataset
 * Attribution: Each observation links to the Shodan host page for verification
 * Requires: SHODAN_API_KEY (free tier: 100 queries/month)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const shodanConnector: PassiveConnector = {
  name: "shodan",
  description: "Internet-wide scan database — discovers open ports, services, and banners from Shodan's pre-scanned dataset",
  requiresApiKey: true,
  freeUrl: "https://www.shodan.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;

    if (!apiKey) {
      return {
        connector: "shodan",
        domain,
        observations: [],
        errors: ["SHODAN_API_KEY not configured — skipping Shodan connector"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      const query = `hostname:.${domain}`;
      const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent(query)}&minify=true`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: any;
      try {
        const res = await fetch(url, { signal: controller.signal });
        if (res.status === 401) {
          return { connector: "shodan", domain, observations: [], errors: ["Shodan API key is invalid"], durationMs: Date.now() - start, rateLimited: false };
        }
        if (res.status === 429) {
          return { connector: "shodan", domain, observations: [], errors: ["Shodan rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
        }
        if (!res.ok) throw new Error(`Shodan returned ${res.status}`);
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const now = new Date();
      const matches = data.matches || [];

      for (const match of matches) {
        const ip = match.ip_str;
        const port = match.port;
        const hostnames: string[] = match.hostnames || [];
        const product = match.product || "";
        const version = match.version || "";
        const org = match.org || "";
        const asn = match.asn ? parseInt(match.asn.replace("AS", ""), 10) : undefined;
        const transport = match.transport || "tcp";

        // Create observation for the IP + port
        const name = hostnames.length > 0 ? hostnames[0] : ip;
        const tags = [
          `port:${port}`,
          `transport:${transport}`,
          ...(product ? [`product:${product}`] : []),
          ...(org ? [`org:${org}`] : []),
        ];

        observations.push({
          assetId: makeAssetId(domain, `${ip}:${port}`, "shodan"),
          domain,
          assetType: "ip",
          name,
          ip,
          asn: isNaN(asn as number) ? undefined : asn,
          source: "shodan",
          observedAt: now,
          lastSeen: match.timestamp ? new Date(match.timestamp) : undefined,
          tags,
          evidence: {
            port,
            transport,
            product,
            version,
            org,
            asn: match.asn,
            isp: match.isp,
            os: match.os,
            banner_snippet: (match.data || "").substring(0, 300),
            hostnames,
          },
          attribution: {
            provider: "Shodan (Internet-Wide Scan Database)",
            url: `https://www.shodan.io/host/${ip}`,
            method: `Shodan pre-scanned database query — searched for hosts with hostname matching *.${domain}. Port ${port}/${transport} found open with ${product || "unknown"} service.`,
            verifyUrl: `https://www.shodan.io/host/${ip}`,
          },
        });

        // Also create subdomain observations for each hostname
        for (const hn of hostnames) {
          if (hn.endsWith(`.${domain}`) || hn === domain) {
            observations.push({
              assetId: makeAssetId(domain, hn, "shodan_hostname"),
              domain,
              assetType: "subdomain",
              name: hn,
              ip,
              source: "shodan",
              observedAt: now,
              tags: ["shodan_resolved", `port:${port}`],
              evidence: { resolved_ip: ip, port, product, version },
              attribution: {
                provider: "Shodan (Internet-Wide Scan Database)",
                url: `https://www.shodan.io/host/${ip}`,
                method: `Hostname discovered via Shodan reverse DNS — ${hn} resolves to ${ip} with port ${port} open`,
                verifyUrl: `https://www.shodan.io/host/${ip}`,
              },
            });
          }
        }
      }
    } catch (err: any) {
      errors.push(`Shodan error: ${err.message}`);
    }

    return {
      connector: "shodan",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
