/**
 * FullHunt — Attack Surface Discovery Connector
 *
 * Queries the FullHunt API for external attack surface intelligence:
 * - Subdomain enumeration with technology detection
 * - Exposed services and ports
 * - DNS records and hosting information
 *
 * Method: REST API v1 with X-API-KEY header
 * Data Source: FullHunt's internet-wide scanning and ASM platform
 * Free tier: 100 queries/month
 * Paid tier: Higher limits, real-time monitoring
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const fullhuntConnector: PassiveConnector = {
  name: "fullhunt",
  description: "FullHunt — external attack surface discovery, subdomain enumeration, exposed services",
  requiresApiKey: true,
  freeUrl: "https://fullhunt.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "fullhunt", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // 1. Domain details
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch(`https://fullhunt.io/api/v1/domain/${domain}/details`, {
          headers: { "X-API-KEY": apiKey },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (res.status === 429) {
          rateLimited = true;
          errors.push("Rate limited");
        } else if (res.ok) {
          const data = await res.json();
          const now = new Date();

          if (data.domain) {
            observations.push({
              assetId: makeAssetId(domain, `domain-${domain}`, "fullhunt"),
              domain,
              assetType: "subdomain",
              name: domain,
              source: "fullhunt",
              observedAt: now,
              tags: ["domain-overview", "attack-surface"],
              evidence: {
                hostCount: data.host_count,
                dnsCount: data.dns_count,
                ipCount: data.ip_count,
                isRegistered: data.is_registered,
                status: data.status,
              },
              attribution: {
                provider: "FullHunt",
                url: `https://fullhunt.io/search?query=domain:${domain}`,
                method: "FullHunt domain overview",
              },
            });
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("FullHunt domain details timed out");
      }

      // 2. Subdomain enumeration
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller2 = new AbortController();
        const timer2 = setTimeout(() => controller2.abort(), timeout);
        try {
          const res = await fetch(`https://fullhunt.io/api/v1/domain/${domain}/subdomains`, {
            headers: { "X-API-KEY": apiKey },
            signal: controller2.signal,
          });
          clearTimeout(timer2);

          if (res.status === 429) {
            rateLimited = true;
          } else if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.hosts && Array.isArray(data.hosts)) {
              for (const host of data.hosts.slice(0, 200)) {
                const hostname = typeof host === "string" ? host : host.host;
                if (!hostname) continue;

                observations.push({
                  assetId: makeAssetId(domain, hostname, "fullhunt"),
                  domain,
                  assetType: "subdomain",
                  name: hostname,
                  ip: typeof host === "object" ? host.ip : undefined,
                  source: "fullhunt",
                  observedAt: now,
                  tags: [
                    "subdomain",
                    "fullhunt-enum",
                    ...(typeof host === "object" && host.is_live ? ["live"] : []),
                    ...(typeof host === "object" && host.has_ipv6 ? ["ipv6"] : []),
                  ],
                  evidence: typeof host === "object" ? {
                    ip: host.ip,
                    isLive: host.is_live,
                    cdn: host.cdn,
                    cloud: host.cloud?.provider,
                    hasIpv6: host.has_ipv6,
                    tags: host.tags,
                    technologies: host.technologies,
                    ports: host.ports,
                    statusCode: host.status_code,
                  } : {},
                  attribution: {
                    provider: "FullHunt",
                    url: `https://fullhunt.io/search?query=host:${hostname}`,
                    method: "FullHunt subdomain enumeration",
                  },
                });
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`FullHunt subdomains: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`FullHunt error: ${err.message}`);
    }

    return {
      connector: "fullhunt",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
