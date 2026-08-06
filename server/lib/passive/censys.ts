/**
 * Censys — Internet-Wide Scan Database Connector
 * 
 * Queries Censys Platform API v3 for hosts matching the target domain.
 * Returns IP addresses, open ports, services, and certificate data.
 * 
 * Method: Queries Censys Global Data Search API with host.dns.names filter
 * Data Source: Censys continuous internet-wide scanning (IPv4 + IPv6)
 * Attribution: Each observation links to the Censys host page for verification
 * Requires: CENSYS_API_SECRET (Personal Access Token) + optional CENSYS_API_ID (Organization ID)
 * 
 * Updated Feb 2026: Migrated from deprecated search.censys.io Basic Auth to
 * new api.platform.censys.io v3 Bearer PAT authentication.
 * 
 * API Reference: https://docs.censys.com/reference/v3-globaldata-search-query
 * - Search: POST /v3/global/search/query  { query, page_size, page_token }
 * - Host:   GET  /v3/global/asset/host/{ip}
 * - Response: result.hits[].host_v1.resource.{ip, services, dns, autonomous_system}
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const PLATFORM_BASE = "https://api.platform.censys.io";

export const censysConnector: PassiveConnector = {
  name: "censys",
  description: "Internet-wide scan database — discovers hosts, open ports, and certificates from Censys continuous scanning",
  requiresApiKey: true,
  freeUrl: "https://platform.censys.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiId = config?.apiId;       // Organization ID (optional, for enterprise-tier)
    const apiSecret = config?.apiSecret; // Personal Access Token (PAT)

    if (!apiSecret) {
      return { connector: "censys", domain, observations: [], errors: ["CENSYS_API_SECRET (PAT) not configured — skipping Censys connector"], durationMs: Date.now() - start, rateLimited: false };
    }

    try {
      // Build headers for the Platform API v3
      const headers: Record<string, string> = {
        Authorization: `Bearer ${apiSecret}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      };
      // Include Organization ID if available for enterprise-tier access
      if (apiId) {
        headers["X-Organization-ID"] = apiId;
      }

      // Platform API v3 uses CenQL query syntax
      // host.dns.names matches domains observed in DNS records
      // MUST quote the domain value — unquoted hyphens cause CenQL parse errors (422)
      const body = JSON.stringify({
        query: `host.dns.names: "${domain}"`,
        page_size: 100,
      });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: any;
      try {
        // Platform API v3 search endpoint
        const res = await fetch(`${PLATFORM_BASE}/v3/global/search/query`, {
          method: "POST",
          headers,
          body,
          signal: controller.signal,
        });
        if (res.status === 401 || res.status === 403) {
          const errBody = await res.text().catch(() => "");
          return { connector: "censys", domain, observations: [], errors: [`Censys API credentials invalid (${res.status}): ${errBody.substring(0, 100)}`], durationMs: Date.now() - start, rateLimited: false };
        }
        if (res.status === 429) return { connector: "censys", domain, observations: [], errors: ["Censys rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
        if (res.status === 422) {
          const errBody = await res.json().catch(() => ({}));
          return { connector: "censys", domain, observations: [], errors: [`Censys query error: ${JSON.stringify(errBody.errors || errBody).substring(0, 200)}`], durationMs: Date.now() - start, rateLimited: false };
        }
        if (!res.ok) throw new Error(`Censys returned ${res.status}`);
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const now = new Date();
      // v3 response: result.hits[].host_v1.resource
      const hits = data?.result?.hits || [];

      for (const hit of hits) {
        // v3 wraps host data under host_v1.resource
        const hostData = hit.host_v1?.resource || hit;
        const ip = hostData.ip;
        if (!ip) continue;

        const services = hostData.services || [];
        const asn = hostData.autonomous_system?.asn;
        const asnOrg = hostData.autonomous_system?.name || hostData.autonomous_system?.description;
        const location = hostData.location;

        // If no services found, still record the IP as an observation
        if (services.length === 0) {
          observations.push({
            assetId: makeAssetId(domain, ip, "censys"),
            domain,
            assetType: "ip",
            name: ip,
            ip,
            asn,
            source: "censys",
            observedAt: now,
            tags: [...(asnOrg ? [`org:${asnOrg}`] : [])],
            evidence: {
              asn,
              asn_org: asnOrg,
              location,
              service_count: hostData.service_count,
            },
            attribution: {
              provider: "Censys (Internet-Wide Scan Database)",
              url: `https://platform.censys.io/hosts/${ip}`,
              method: `Censys Platform API v3 — found ${ip} via DNS name matching for ${domain}`,
              verifyUrl: `https://platform.censys.io/hosts/${ip}`,
            },
          });
          continue;
        }

        for (const svc of services) {
          const port = svc.port;
          const transport = svc.transport_protocol || "TCP";
          const serviceName = svc.protocol || svc.service_name || "unknown";

          // Extract certificate info if available (v3 uses svc.cert.parsed)
          const certNames: string[] = [];
          if (svc.cert?.parsed) {
            const parsed = svc.cert.parsed;
            const subjectCN = parsed.subject?.common_name;
            if (subjectCN) certNames.push(...(Array.isArray(subjectCN) ? subjectCN : [subjectCN]));
            const sans = parsed.extensions?.subject_alt_name?.dns_names;
            if (sans) certNames.push(...sans);
          }

          observations.push({
            assetId: makeAssetId(domain, `${ip}:${port}`, "censys"),
            domain,
            assetType: "ip",
            name: ip,
            ip,
            asn,
            source: "censys",
            observedAt: now,
            tags: [
              `port:${port}`,
              `transport:${transport}`,
              `service:${serviceName}`,
              ...(asnOrg ? [`org:${asnOrg}`] : []),
              ...(certNames.length > 0 ? [`cert_names:${certNames.slice(0, 5).join(",")}`] : []),
            ],
            evidence: {
              port,
              transport,
              service_name: serviceName,
              asn,
              asn_org: asnOrg,
              location,
              operating_system: hostData.operating_system,
              software: svc.software,
              cert_names: certNames.length > 0 ? certNames : undefined,
              banner_hash: svc.banner_hash_sha256,
            },
            attribution: {
              provider: "Censys (Internet-Wide Scan Database)",
              url: `https://platform.censys.io/hosts/${ip}`,
              method: `Censys Platform API v3 — found ${ip}:${port} with ${serviceName} service via DNS name matching for ${domain}`,
              verifyUrl: `https://platform.censys.io/hosts/${ip}`,
            },
          });
        }
      }

      // Fetch additional page if there's a next_page_token and we have room
      if (data?.result?.next_page_token && observations.length < 500) {
        try {
          const page2Body = JSON.stringify({
            query: `host.dns.names: "${domain}"`,
            page_size: 100,
            page_token: data.result.next_page_token,
          });
          const controller2 = new AbortController();
          const timer2 = setTimeout(() => controller2.abort(), timeout);
          try {
            const res2 = await fetch(`${PLATFORM_BASE}/v3/global/search/query`, {
              method: "POST",
              headers,
              body: page2Body,
              signal: controller2.signal,
            });
            if (res2.ok) {
              const data2 = await res2.json();
              const hits2 = data2?.result?.hits || [];
              for (const hit of hits2) {
                const hostData = hit.host_v1?.resource || hit;
                const ip = hostData.ip;
                if (!ip) continue;
                const services = hostData.services || [];
                const asn = hostData.autonomous_system?.asn;
                const asnOrg = hostData.autonomous_system?.name || hostData.autonomous_system?.description;

                if (services.length === 0) {
                  observations.push({
                    assetId: makeAssetId(domain, ip, "censys"),
                    domain, assetType: "ip", name: ip, ip, asn, source: "censys",
                    observedAt: now, tags: [...(asnOrg ? [`org:${asnOrg}`] : [])],
                    evidence: { asn, asn_org: asnOrg },
                    attribution: { provider: "Censys (Internet-Wide Scan Database)", url: `https://platform.censys.io/hosts/${ip}`, method: `Censys Platform API v3 — page 2`, verifyUrl: `https://platform.censys.io/hosts/${ip}` },
                  });
                  continue;
                }

                for (const svc of services) {
                  observations.push({
                    assetId: makeAssetId(domain, `${ip}:${svc.port}`, "censys"),
                    domain, assetType: "ip", name: ip, ip, asn, source: "censys",
                    observedAt: now,
                    tags: [`port:${svc.port}`, `transport:${svc.transport_protocol || "TCP"}`, `service:${svc.protocol || "unknown"}`, ...(asnOrg ? [`org:${asnOrg}`] : [])],
                    evidence: { port: svc.port, transport: svc.transport_protocol, service_name: svc.protocol, asn, asn_org: asnOrg },
                    attribution: { provider: "Censys (Internet-Wide Scan Database)", url: `https://platform.censys.io/hosts/${ip}`, method: `Censys Platform API v3 — page 2`, verifyUrl: `https://platform.censys.io/hosts/${ip}` },
                  });
                }
              }
            }
          } finally {
            clearTimeout(timer2);
          }
        } catch {
          // Page 2 is best-effort, don't fail the whole connector
        }
      }
    } catch (err: any) {
      errors.push(`Censys error: ${err.message}`);
    }

    return { connector: "censys", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
