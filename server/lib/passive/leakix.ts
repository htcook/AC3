/**
 * LeakIX — Exposed Services & Data Leak Connector
 *
 * Queries the LeakIX API for exposed services and data leaks:
 * - Open databases, misconfigured services
 * - Leaked credentials and sensitive data
 * - Service banners and version detection
 *
 * Method: REST API v2 with api-key header
 * Data Source: LeakIX's internet-wide scanning and leak aggregation
 * Free tier: 10 req/min, limited results
 * Paid tier: Full access, bulk queries
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const leakixConnector: PassiveConnector = {
  name: "leakix",
  description: "LeakIX — exposed services, data leaks, misconfigured databases, and credential exposure",
  requiresApiKey: true,
  freeUrl: "https://leakix.net",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "leakix", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // 1. Search for services on this domain
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch(`https://leakix.net/search?scope=service&q=hostname:${encodeURIComponent(domain)}`, {
          headers: {
            "api-key": apiKey,
            "Accept": "application/json",
          },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (res.status === 429) {
          rateLimited = true;
          errors.push("Rate limited");
        } else if (res.ok) {
          const results = await res.json();
          const now = new Date();

          if (Array.isArray(results)) {
            for (const svc of results.slice(0, 100)) {
              const ip = svc.ip || svc.host;
              const port = svc.port;
              const protocol = svc.protocol || "tcp";
              const hostname = svc.hostname || domain;

              observations.push({
                assetId: makeAssetId(domain, `svc-${ip}-${port}`, "leakix"),
                domain,
                assetType: "ip",
                name: hostname,
                ip,
                source: "leakix",
                observedAt: now,
                firstSeen: svc.time ? new Date(svc.time) : undefined,
                tags: [
                  "exposed-service",
                  protocol,
                  ...(svc.tags || []),
                  svc.leak?.severity ? `severity:${svc.leak.severity}` : "",
                  svc.summary ? "has-banner" : "",
                ].filter(Boolean),
                evidence: {
                  port,
                  protocol,
                  transport: svc.transport,
                  summary: (svc.summary || "").slice(0, 500),
                  software: svc.software?.name,
                  softwareVersion: svc.software?.version,
                  ssl: svc.ssl ? {
                    version: svc.ssl.version,
                    cipher: svc.ssl.cipher,
                    subject: svc.ssl.certificate?.cn,
                    issuer: svc.ssl.certificate?.issuer_cn,
                    notAfter: svc.ssl.certificate?.not_after,
                  } : undefined,
                  geoip: svc.geoip ? {
                    country: svc.geoip.country_name,
                    city: svc.geoip.city_name,
                    asn: svc.geoip.as_number,
                    org: svc.geoip.as_name,
                  } : undefined,
                  leak: svc.leak ? {
                    type: svc.leak.type,
                    severity: svc.leak.severity,
                    dataset: svc.leak.dataset?.name,
                    rows: svc.leak.dataset?.rows,
                    size: svc.leak.dataset?.size,
                  } : undefined,
                },
                attribution: {
                  provider: "LeakIX",
                  url: `https://leakix.net/host/${ip}`,
                  method: "LeakIX exposed service scan",
                },
              });
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("LeakIX request timed out");
      }

      // 2. Search for leaks on this domain
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 1000));
        const controller2 = new AbortController();
        const timer2 = setTimeout(() => controller2.abort(), timeout);
        try {
          const res = await fetch(`https://leakix.net/search?scope=leak&q=hostname:${encodeURIComponent(domain)}`, {
            headers: {
              "api-key": apiKey,
              "Accept": "application/json",
            },
            signal: controller2.signal,
          });
          clearTimeout(timer2);

          if (res.status === 429) {
            rateLimited = true;
          } else if (res.ok) {
            const leaks = await res.json();
            const now = new Date();

            if (Array.isArray(leaks)) {
              for (const leak of leaks.slice(0, 50)) {
                observations.push({
                  assetId: makeAssetId(domain, `leak-${leak.ip}-${leak.port}-${leak.time}`, "leakix"),
                  domain,
                  assetType: "ip",
                  name: leak.hostname || domain,
                  ip: leak.ip,
                  source: "leakix",
                  observedAt: now,
                  firstSeen: leak.time ? new Date(leak.time) : undefined,
                  tags: ["data-leak", "exposed-data", ...(leak.tags || [])],
                  evidence: {
                    port: leak.port,
                    leakType: leak.leak?.type,
                    severity: leak.leak?.severity,
                    datasetName: leak.leak?.dataset?.name,
                    rows: leak.leak?.dataset?.rows,
                    collections: leak.leak?.dataset?.collections,
                    summary: (leak.summary || "").slice(0, 500),
                  },
                  attribution: {
                    provider: "LeakIX",
                    url: `https://leakix.net/host/${leak.ip}`,
                    method: "LeakIX data leak detection",
                  },
                });
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`LeakIX leak search: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`LeakIX error: ${err.message}`);
    }

    return {
      connector: "leakix",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
