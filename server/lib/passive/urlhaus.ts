/**
 * URLhaus (abuse.ch) Connector — Free, No API Key
 * 
 * Searches the URLhaus database for malicious URLs associated
 * with the target domain (malware distribution, phishing lures,
 * exploit kit landing pages).
 * 
 * API docs: https://urlhaus-api.abuse.ch/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const API_URL = "https://urlhaus-api.abuse.ch/v1/";

async function urlhausPost(endpoint: string, body: Record<string, string>): Promise<any> {
  const resp = await fetch(`${API_URL}${endpoint}/`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) return null;
  return resp.json();
}

export const urlhausConnector: PassiveConnector = {
  name: "urlhaus",
  description: "URLhaus (abuse.ch) — free malicious URL database, malware distribution, phishing lures, exploit kits",
  requiresApiKey: false,
  freeUrl: "https://urlhaus.abuse.ch",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Query URLhaus for the host/domain
      const hostResult = await urlhausPost("host", { host: domain });

      if (hostResult?.query_status === "no_results") {
        // Clean — domain not found in URLhaus
        observations.push({
          assetId: makeAssetId(domain, `URLhaus clean: ${domain}`, "urlhaus"),
          domain,
          assetType: "info",
          name: `URLhaus: No malicious URLs found for ${domain}`,
          source: "urlhaus",
          observedAt: now,
          tags: ["urlhaus", "abuse_ch", "clean", "malware_distribution"],
          evidence: {
            severity: 0,
            status: "clean",
            value: `No malicious URLs associated with ${domain} in URLhaus database`,
          },
          attribution: { provider: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch", method: "api" },
        });
      } else if (hostResult?.urls && Array.isArray(hostResult.urls)) {
        const urlCount = hostResult.urls.length;
        const onlineUrls = hostResult.urls.filter((u: any) => u.url_status === "online");
        const offlineUrls = hostResult.urls.filter((u: any) => u.url_status === "offline");

        // Summary observation
        observations.push({
          assetId: makeAssetId(domain, `URLhaus summary: ${domain}`, "urlhaus"),
          domain,
          assetType: "breach",
          name: `URLhaus: ${urlCount} malicious URL(s) found for ${domain}`,
          source: "urlhaus",
          observedAt: now,
          tags: [
            "urlhaus", "abuse_ch", "malware_distribution",
            ...(onlineUrls.length > 0 ? ["active_threat", "critical"] : []),
          ],
          evidence: {
            severity: onlineUrls.length > 0 ? 9 : 6,
            confidence: 90,
            value: `${urlCount} malicious URL(s): ${onlineUrls.length} online, ${offlineUrls.length} offline`,
            total_urls: urlCount,
            online_count: onlineUrls.length,
            offline_count: offlineUrls.length,
            blacklists: hostResult.blacklists || {},
            url_count: hostResult.urls_online || urlCount,
          },
          attribution: { provider: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch", method: "api" },
        });

        // Individual URL observations (limit to 20 most recent)
        for (const url of hostResult.urls.slice(0, 20)) {
          const isOnline = url.url_status === "online";
          const name = `URLhaus URL: ${url.url || 'unknown'}`;
          observations.push({
            assetId: makeAssetId(domain, name, "urlhaus"),
            domain,
            assetType: "breach",
            name,
            source: "urlhaus",
            observedAt: now,
            firstSeen: url.date_added ? new Date(url.date_added) : undefined,
            tags: [
              "urlhaus", "abuse_ch", "malicious_url",
              url.threat || "malware",
              url.url_status || "unknown",
              ...(isOnline ? ["active_threat"] : []),
            ],
            evidence: {
              severity: isOnline ? 9 : 5,
              confidence: 85,
              value: `${url.threat || 'malware'} — ${url.url_status || 'unknown'} (${url.tags?.join(', ') || 'no tags'})`,
              url: url.url,
              url_status: url.url_status,
              threat: url.threat,
              date_added: url.date_added,
              urlhaus_reference: url.urlhaus_reference,
              tags: url.tags || [],
            },
            attribution: { provider: "URLhaus (abuse.ch)", url: url.urlhaus_reference || "https://urlhaus.abuse.ch", method: "api" },
          });
        }
      }
    } catch (err: any) {
      if (err.message?.includes("timeout")) {
        errors.push("URLhaus API timeout");
      } else {
        errors.push(err.message || "Unknown error during URLhaus lookup");
      }
    }

    return {
      connector: "urlhaus",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
