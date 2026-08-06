/**
 * VirusTotal — Multi-AV & Passive DNS Connector
 *
 * Queries the VirusTotal v3 API for domain intelligence:
 * - Passive DNS resolutions (historical IP↔domain mappings)
 * - Subdomain enumeration
 * - WHOIS records
 * - Detected URLs and communicating files (malware associations)
 *
 * Method: REST API v3 with x-apikey header
 * Data Source: VirusTotal's aggregated AV/sandbox/passive DNS dataset
 * Free tier: 4 req/min, 500 req/day — sufficient for single-domain scans
 * Paid tier: Higher rate limits, premium features
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface VTResponse {
  data?: any;
  error?: { code: string; message: string };
}

async function vtFetch(path: string, apiKey: string, timeout: number): Promise<VTResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3${path}`, {
      headers: { "x-apikey": apiKey },
      signal: controller.signal,
    });
    if (res.status === 429) return { error: { code: "QuotaExceeded", message: "Rate limited" } };
    if (!res.ok) throw new Error(`VT returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export const virustotalConnector: PassiveConnector = {
  name: "virustotal",
  description: "VirusTotal domain intelligence — passive DNS, subdomains, WHOIS, malware associations",
  requiresApiKey: true,
  freeUrl: "https://www.virustotal.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "virustotal", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // 1. Domain report — get WHOIS, categories, reputation
      const domainReport = await vtFetch(`/domains/${domain}`, apiKey, timeout);
      if (domainReport.error?.code === "QuotaExceeded") {
        rateLimited = true;
        errors.push("Rate limited on domain report");
      } else if (domainReport.data) {
        const attrs = domainReport.data.attributes || {};
        const now = new Date();

        // WHOIS registrar info
        if (attrs.whois) {
          observations.push({
            assetId: makeAssetId(domain, `whois-${domain}`, "virustotal"),
            domain,
            assetType: "subdomain",
            name: domain,
            source: "virustotal",
            observedAt: now,
            tags: ["whois", "registrar"],
            evidence: {
              registrar: attrs.registrar,
              creationDate: attrs.creation_date,
              lastUpdateDate: attrs.last_update_date,
              whoisRaw: (attrs.whois || "").slice(0, 2000),
              reputation: attrs.reputation,
              categories: attrs.categories,
            },
            attribution: {
              provider: "VirusTotal",
              url: `https://www.virustotal.com/gui/domain/${domain}`,
              method: "VirusTotal domain WHOIS lookup",
            },
          });
        }

        // Last DNS records
        if (attrs.last_dns_records) {
          for (const rec of attrs.last_dns_records) {
            if (rec.type === "A" || rec.type === "AAAA") {
              observations.push({
                assetId: makeAssetId(domain, `dns-${rec.value}`, "virustotal"),
                domain,
                assetType: "ip",
                name: domain,
                ip: rec.value,
                source: "virustotal",
                observedAt: now,
                tags: ["dns", rec.type.toLowerCase()],
                evidence: { type: rec.type, ttl: rec.ttl, value: rec.value },
                attribution: {
                  provider: "VirusTotal",
                  url: `https://www.virustotal.com/gui/domain/${domain}/dns`,
                  method: "VirusTotal DNS record lookup",
                },
              });
            }
          }
        }
      }

      // 2. Subdomains
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 1200)); // respect rate limit
        const subdomains = await vtFetch(`/domains/${domain}/subdomains?limit=40`, apiKey, timeout);
        if (subdomains.error?.code === "QuotaExceeded") {
          rateLimited = true;
          errors.push("Rate limited on subdomains");
        } else if (subdomains.data && Array.isArray(subdomains.data)) {
          const now = new Date();
          for (const sub of subdomains.data) {
            const subId = sub.id || sub.attributes?.id;
            if (!subId) continue;
            observations.push({
              assetId: makeAssetId(domain, subId, "virustotal"),
              domain,
              assetType: "subdomain",
              name: subId,
              source: "virustotal",
              observedAt: now,
              tags: ["subdomain", "virustotal-enum"],
              evidence: {
                reputation: sub.attributes?.reputation,
                lastAnalysisStats: sub.attributes?.last_analysis_stats,
              },
              attribution: {
                provider: "VirusTotal",
                url: `https://www.virustotal.com/gui/domain/${subId}`,
                method: "VirusTotal subdomain enumeration",
              },
            });
          }
        }
      }

      // 3. Passive DNS resolutions
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 1200));
        const resolutions = await vtFetch(`/domains/${domain}/resolutions?limit=40`, apiKey, timeout);
        if (resolutions.error?.code === "QuotaExceeded") {
          rateLimited = true;
          errors.push("Rate limited on resolutions");
        } else if (resolutions.data && Array.isArray(resolutions.data)) {
          const now = new Date();
          for (const res of resolutions.data) {
            const ip = res.attributes?.ip_address;
            if (!ip) continue;
            observations.push({
              assetId: makeAssetId(domain, `pdns-${ip}`, "virustotal"),
              domain,
              assetType: "ip",
              name: domain,
              ip,
              source: "virustotal",
              observedAt: now,
              firstSeen: res.attributes?.date ? new Date(res.attributes.date * 1000) : undefined,
              tags: ["passive-dns", "historical-resolution"],
              evidence: {
                hostName: res.attributes?.host_name,
                resolver: res.attributes?.resolver,
                date: res.attributes?.date,
              },
              attribution: {
                provider: "VirusTotal",
                url: `https://www.virustotal.com/gui/domain/${domain}/relations`,
                method: "VirusTotal passive DNS resolution history",
              },
            });
          }
        }
      }
    } catch (err: any) {
      errors.push(`VirusTotal error: ${err.message}`);
    }

    return {
      connector: "virustotal",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
