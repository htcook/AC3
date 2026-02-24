/**
 * Netlas.io — Internet Intelligence Connector
 *
 * Queries the Netlas API for internet-wide scanning data:
 * - Host search (open ports, services, banners)
 * - DNS search (historical DNS records)
 * - WHOIS data
 * - Certificate search
 *
 * Method: REST API with X-API-Key header
 * Data Source: Netlas.io's internet-wide scanning platform
 * Free tier: 50 queries/day
 * Paid tier: Higher limits, bulk access
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const netlasConnector: PassiveConnector = {
  name: "netlas",
  description: "Netlas.io — internet-wide host scanning, DNS history, certificate search, and WHOIS",
  requiresApiKey: true,
  freeUrl: "https://netlas.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "netlas", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    const headers = { "X-API-Key": apiKey, "Content-Type": "application/json" };

    try {
      // 1. Host search — find all hosts for this domain
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch(
          `https://app.netlas.io/api/responses/?q=domain:${encodeURIComponent(domain)}&indices=&fields=*&source_type=include&start=0&count=50`,
          { headers, signal: controller.signal }
        );
        clearTimeout(timer);

        if (res.status === 429) {
          rateLimited = true;
          errors.push("Rate limited");
        } else if (res.ok) {
          const data = await res.json();
          const now = new Date();

          if (data.items && Array.isArray(data.items)) {
            for (const item of data.items) {
              const d = item.data || {};
              const ip = d.ip || d.host;
              const port = d.port;
              const hostname = d.domain || d.hostname || domain;

              if (!ip) continue;

              observations.push({
                assetId: makeAssetId(domain, `host-${ip}-${port}`, "netlas"),
                domain,
                assetType: "ip",
                name: hostname,
                ip,
                source: "netlas",
                observedAt: now,
                tags: [
                  "host-scan",
                  d.protocol || "unknown",
                  ...(d.tag || []),
                  port ? `port:${port}` : "",
                ].filter(Boolean),
                evidence: {
                  port,
                  protocol: d.protocol,
                  banner: (d.http?.title || d.banner || "").slice(0, 500),
                  server: d.http?.server,
                  statusCode: d.http?.status_code,
                  contentType: d.http?.content_type,
                  jarm: d.jarm,
                  geo: d.geo ? {
                    country: d.geo.country,
                    city: d.geo.city,
                    asn: d.geo.asn,
                    asnOrg: d.geo.as_org,
                  } : undefined,
                  tls: d.certificate ? {
                    subject: d.certificate.subject?.common_name,
                    issuer: d.certificate.issuer?.common_name,
                    notBefore: d.certificate.validity?.start,
                    notAfter: d.certificate.validity?.end,
                    sans: d.certificate.subject_alt_name?.dns_names?.slice(0, 20),
                  } : undefined,
                  technologies: d.tag,
                },
                attribution: {
                  provider: "Netlas.io",
                  url: `https://app.netlas.io/responses/?q=host:${ip}`,
                  method: "Netlas host scan",
                },
              });
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("Netlas host search timed out");
      }

      // 2. DNS search — historical DNS records
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller2 = new AbortController();
        const timer2 = setTimeout(() => controller2.abort(), timeout);
        try {
          const res = await fetch(
            `https://app.netlas.io/api/dns/?q=domain:${encodeURIComponent(domain)}&fields=*&source_type=include&start=0&count=50`,
            { headers, signal: controller2.signal }
          );
          clearTimeout(timer2);

          if (res.status === 429) {
            rateLimited = true;
          } else if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.items && Array.isArray(data.items)) {
              for (const item of data.items) {
                const d = item.data || {};
                const name = d.domain || d.name;
                if (!name) continue;

                // Extract A/AAAA records
                const aRecords = d.a || [];
                for (const ip of aRecords) {
                  observations.push({
                    assetId: makeAssetId(domain, `dns-a-${name}-${ip}`, "netlas"),
                    domain,
                    assetType: "ip",
                    name,
                    ip,
                    source: "netlas",
                    observedAt: now,
                    lastSeen: d.last_updated ? new Date(d.last_updated) : undefined,
                    tags: ["dns", "a-record", "netlas-dns"],
                    evidence: { type: "A", value: ip, domain: name },
                    attribution: {
                      provider: "Netlas.io",
                      url: `https://app.netlas.io/dns/?q=domain:${name}`,
                      method: "Netlas DNS record lookup",
                    },
                  });
                }

                // Extract CNAME records
                const cnameRecords = d.cname || [];
                for (const cname of cnameRecords) {
                  observations.push({
                    assetId: makeAssetId(domain, `dns-cname-${name}-${cname}`, "netlas"),
                    domain,
                    assetType: "cname",
                    name,
                    source: "netlas",
                    observedAt: now,
                    tags: ["dns", "cname", "netlas-dns"],
                    evidence: { type: "CNAME", value: cname, domain: name },
                    attribution: {
                      provider: "Netlas.io",
                      url: `https://app.netlas.io/dns/?q=domain:${name}`,
                      method: "Netlas DNS CNAME lookup",
                    },
                  });
                }
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`Netlas DNS search: ${err.message}`);
        }
      }

      // 3. Certificate search
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller3 = new AbortController();
        const timer3 = setTimeout(() => controller3.abort(), timeout);
        try {
          const res = await fetch(
            `https://app.netlas.io/api/certs/?q=domain:${encodeURIComponent(domain)}&fields=*&source_type=include&start=0&count=30`,
            { headers, signal: controller3.signal }
          );
          clearTimeout(timer3);

          if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.items && Array.isArray(data.items)) {
              for (const item of data.items) {
                const cert = item.data || {};
                const cn = cert.subject?.common_name || cert.parsed?.subject?.common_name;
                if (!cn) continue;

                observations.push({
                  assetId: makeAssetId(domain, `cert-${cn}-${cert.serial_number || ""}`, "netlas"),
                  domain,
                  assetType: "certificate",
                  name: cn,
                  source: "netlas",
                  observedAt: now,
                  tags: ["certificate", "tls", "netlas-cert"],
                  evidence: {
                    serialNumber: cert.serial_number,
                    issuer: cert.issuer?.common_name,
                    notBefore: cert.validity?.start,
                    notAfter: cert.validity?.end,
                    sans: cert.subject_alt_name?.dns_names?.slice(0, 20),
                    signatureAlgorithm: cert.signature_algorithm,
                  },
                  attribution: {
                    provider: "Netlas.io",
                    url: `https://app.netlas.io/certs/?q=domain:${domain}`,
                    method: "Netlas certificate search",
                  },
                });
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`Netlas cert search: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`Netlas error: ${err.message}`);
    }

    return {
      connector: "netlas",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
