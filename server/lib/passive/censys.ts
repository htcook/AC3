/**
 * Censys — Internet-Wide Scan Database Connector
 * 
 * Queries Censys Search 2.0 API for hosts matching the target domain.
 * Returns IP addresses, open ports, services, and certificate data.
 * 
 * Method: Queries Censys Hosts Search API with services.tls.certificates.leaf.names filter
 * Data Source: Censys continuous internet-wide scanning (IPv4 + IPv6)
 * Attribution: Each observation links to the Censys host page for verification
 * Requires: CENSYS_API_ID + CENSYS_API_SECRET (free tier: 250 queries/month)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const censysConnector: PassiveConnector = {
  name: "censys",
  description: "Internet-wide scan database — discovers hosts, open ports, and certificates from Censys continuous scanning",
  requiresApiKey: true,
  freeUrl: "https://search.censys.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiId = config?.apiId;
    const apiSecret = config?.apiSecret;

    if (!apiId || !apiSecret) {
      return { connector: "censys", domain, observations: [], errors: ["CENSYS_API_ID/SECRET not configured — skipping Censys connector"], durationMs: Date.now() - start, rateLimited: false };
    }

    try {
      const authHeader = "Basic " + Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
      const body = JSON.stringify({
        q: `services.tls.certificates.leaf.names: ${domain}`,
        per_page: 100,
      });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: any;
      try {
        const res = await fetch("https://search.censys.io/api/v2/hosts/search", {
          method: "POST",
          headers: { Authorization: authHeader, "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        });
        if (res.status === 401) return { connector: "censys", domain, observations: [], errors: ["Censys API credentials invalid"], durationMs: Date.now() - start, rateLimited: false };
        if (res.status === 429) return { connector: "censys", domain, observations: [], errors: ["Censys rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
        if (!res.ok) throw new Error(`Censys returned ${res.status}`);
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const now = new Date();
      const hits = data?.result?.hits || [];

      for (const hit of hits) {
        const ip = hit.ip;
        const services = hit.services || [];
        const asn = hit.autonomous_system?.asn;
        const asnOrg = hit.autonomous_system?.name;

        for (const svc of services) {
          const port = svc.port;
          const transport = svc.transport_protocol || "TCP";
          const serviceName = svc.service_name || "unknown";

          observations.push({
            assetId: makeAssetId(domain, `${ip}:${port}`, "censys"),
            domain,
            assetType: "ip",
            name: ip,
            ip,
            asn,
            source: "censys",
            observedAt: now,
            lastSeen: hit.last_updated_at ? new Date(hit.last_updated_at) : undefined,
            tags: [`port:${port}`, `transport:${transport}`, `service:${serviceName}`, ...(asnOrg ? [`org:${asnOrg}`] : [])],
            evidence: {
              port,
              transport,
              service_name: serviceName,
              asn,
              asn_org: asnOrg,
              location: hit.location,
              operating_system: hit.operating_system,
            },
            attribution: {
              provider: "Censys (Internet-Wide Scan Database)",
              url: `https://search.censys.io/hosts/${ip}`,
              method: `Censys Hosts Search API — found ${ip}:${port} with ${serviceName} service via TLS certificate matching for ${domain}`,
              verifyUrl: `https://search.censys.io/hosts/${ip}`,
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`Censys error: ${err.message}`);
    }

    return { connector: "censys", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
