/**
 * ip-api.com Connector — Free, No API Key
 * 
 * Provides IP geolocation, ASN, ISP, and organization data.
 * Free for non-commercial use, 45 requests/minute.
 * 
 * API docs: https://ip-api.com/docs/api:json
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const ipApiConnector: PassiveConnector = {
  name: "ip_api",
  description: "ip-api.com — free IP geolocation, ASN, ISP, and organization data",
  requiresApiKey: false,
  freeUrl: "https://ip-api.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const now = new Date();
    const source = "ip_api";
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    let rateLimited = false;

    try {
      const resp = await fetch(
        `http://ip-api.com/json/${domain}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
        { signal: config?.signal ?? AbortSignal.timeout(8000) }
      );

      if (resp.status === 429) {
        rateLimited = true;
        errors.push("Rate limit exceeded for ip-api.com");
      } else if (!resp.ok) {
        errors.push(`Failed to fetch data from ip-api.com: ${resp.status} ${resp.statusText}`);
      } else {
        const data = await resp.json();
        if (data.status !== "success") {
          errors.push(`ip-api.com returned an error for ${domain}: ${data.message}`);
        } else {
          // Main IP Geolocation Observation
          observations.push({
            assetId: makeAssetId(domain, data.query, source),
            domain: domain,
            assetType: "ip",
            name: data.query,
            ip: data.query,
            source: source,
            observedAt: now,
            tags: ["geolocation", "isp", "asn"],
            evidence: {
              country: data.country,
              countryCode: data.countryCode,
              region: data.regionName,
              city: data.city,
              zip: data.zip,
              lat: data.lat,
              lon: data.lon,
              timezone: data.timezone,
              isp: data.isp,
              org: data.org,
              as: data.as,
              asname: data.asname,
              reverse: data.reverse,
            },
            attribution: {
              provider: "ip-api.com",
              url: `https://ip-api.com/#${data.query}`,
              method: "api",
            },
          });

          // Breach observation for hosting provider
          if (data.hosting) {
            observations.push({
              assetId: makeAssetId(domain, `${data.query}-hosting`, source),
              domain: domain,
              assetType: "breach",
              name: `${data.query} is a hosting provider IP`,
              ip: data.query,
              source: source,
              observedAt: now,
              tags: ["hosting_provider", "infrastructure-misuse"],
              evidence: {
                confidence: 80,
                provider: data.org,
                description: `IP belongs to hosting provider: ${data.org}`,
              },
              attribution: {
                provider: "ip-api.com",
                url: `https://ip-api.com/#${data.query}`,
                method: "api",
              },
            });
          }

          // Breach observation for proxy/VPN
          if (data.proxy) {
            observations.push({
              assetId: makeAssetId(domain, `${data.query}-proxy`, source),
              domain: domain,
              assetType: "breach",
              name: `${data.query} detected as proxy/VPN`,
              ip: data.query,
              source: source,
              observedAt: now,
              tags: ["proxy_vpn", "anonymizer"],
              evidence: {
                confidence: 70,
                description: "IP is identified as a proxy or VPN endpoint",
              },
              attribution: {
                provider: "ip-api.com",
                url: `https://ip-api.com/#${data.query}`,
                method: "api",
              },
            });
          }

          // Breach observation for mobile network
          if (data.mobile) {
            observations.push({
              assetId: makeAssetId(domain, `${data.query}-mobile`, source),
              domain: domain,
              assetType: "breach",
              name: `${data.query} is a mobile network IP`,
              ip: data.query,
              source: source,
              observedAt: now,
              tags: ["mobile_network"],
              evidence: {
                confidence: 60,
                provider: data.isp,
                description: `IP belongs to a mobile network provider: ${data.isp}`,
              },
              attribution: {
                provider: "ip-api.com",
                url: `https://ip-api.com/#${data.query}`,
                method: "api",
              },
            });
          }
        }
      }
    } catch (err: any) {
      if (err.name === "AbortError") {
        errors.push("Request to ip-api.com timed out");
      } else {
        errors.push(`An unexpected error occurred: ${err.message}`);
      }
    }

    return {
      connector: source,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
