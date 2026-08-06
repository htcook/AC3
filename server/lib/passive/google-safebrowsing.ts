/**
 * Google SafeBrowsing Connector — Free (requires API key from Google Cloud Console)
 *
 * Checks the target domain and common URL patterns against Google's
 * constantly updated lists of unsafe web resources:
 *   - MALWARE
 *   - SOCIAL_ENGINEERING (phishing)
 *   - UNWANTED_SOFTWARE
 *   - POTENTIALLY_HARMFUL_APPLICATION
 *
 * API docs: https://developers.google.com/safe-browsing/v4/lookup-api
 * Free tier: 10,000 requests/day
 */

import { createHash } from "crypto";
import type {
  AssetObservation,
  ConnectorConfig,
  ConnectorResult,
  PassiveConnector,
} from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256")
    .update(`${domain}|${name}|${source}`)
    .digest("hex")
    .slice(0, 20);
}

const API_URL =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

const PLATFORM_TYPES = ["ANY_PLATFORM"];
const THREAT_ENTRY_TYPES = ["URL"];

function buildCheckUrls(domain: string): string[] {
  return [
    `http://${domain}/`,
    `https://${domain}/`,
    `http://www.${domain}/`,
    `https://www.${domain}/`,
  ];
}

const SEVERITY_MAP: Record<string, number> = {
  MALWARE: 9,
  SOCIAL_ENGINEERING: 8,
  UNWANTED_SOFTWARE: 6,
  POTENTIALLY_HARMFUL_APPLICATION: 7,
};

export const googleSafeBrowsingConnector: PassiveConnector = {
  name: "google-safebrowsing",
  description:
    "Google SafeBrowsing — malware, phishing, unwanted software detection (free, requires Google API key)",
  requiresApiKey: true,
  freeUrl: "https://transparencyreport.google.com/safe-browsing/search",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const start = Date.now();
    let rateLimited = false;
    const now = new Date();

    if (!config?.apiKey) {
      return {
        connector: "google-safebrowsing",
        domain,
        observations: [],
        errors: ["No Google SafeBrowsing API key provided — skipping"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      const urls = buildCheckUrls(domain);
      const body = {
        client: {
          clientId: "ace-c3-caldera",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: PLATFORM_TYPES,
          threatEntryTypes: THREAT_ENTRY_TYPES,
          threatEntries: urls.map((url) => ({ url })),
        },
      };

      const resp = await fetch(`${API_URL}?key=${config.apiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: config?.signal || AbortSignal.timeout(15000),
      });

      if (resp.status === 429) {
        rateLimited = true;
      } else if (!resp.ok) {
        const errText = await resp.text().catch(() => "");
        errors.push(
          `SafeBrowsing API error ${resp.status}: ${errText.substring(0, 200)}`
        );
      } else {
        const data = await resp.json();

        if (data.matches && data.matches.length > 0) {
          for (const match of data.matches) {
            const threatType = match.threatType || "UNKNOWN";
            const matchUrl = match.threat?.url || domain;
            const name = `SafeBrowsing: ${threatType} — ${matchUrl}`;
            const severity = SEVERITY_MAP[threatType] || 6;

            observations.push({
              assetId: makeAssetId(
                domain,
                `gsb-${threatType}-${matchUrl}`,
                "google-safebrowsing"
              ),
              domain,
              assetType: "url",
              name,
              source: "google-safebrowsing",
              observedAt: now,
              tags: [
                "google-safebrowsing",
                threatType.toLowerCase().replace(/_/g, "-"),
                "malicious",
              ],
              evidence: {
                severity,
                confidence: 95, // Google SafeBrowsing has very high confidence
                value: `Google SafeBrowsing flagged ${matchUrl} as ${threatType}`,
                threatType,
                platformType: match.platformType,
                threatEntryType: match.threatEntryType,
                url: matchUrl,
                cacheDuration: match.cacheDuration,
              },
              attribution: {
                provider: "Google SafeBrowsing",
                url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                  matchUrl
                )}`,
                method:
                  "SafeBrowsing Lookup API v4 — threatMatches.find",
                verifyUrl: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                  domain
                )}`,
              },
            });
          }
        } else {
          // No threats found — record a clean observation for completeness
          observations.push({
            assetId: makeAssetId(
              domain,
              "gsb-clean",
              "google-safebrowsing"
            ),
            domain,
            assetType: "subdomain",
            name: `SafeBrowsing: ${domain} — No threats detected`,
            source: "google-safebrowsing",
            observedAt: now,
            tags: ["google-safebrowsing", "clean"],
            evidence: {
              severity: 0,
              confidence: 95,
              value: `Google SafeBrowsing reports no threats for ${domain}`,
              checkedUrls: urls,
              result: "clean",
            },
            attribution: {
              provider: "Google SafeBrowsing",
              url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                domain
              )}`,
              method: "SafeBrowsing Lookup API v4 — threatMatches.find",
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`SafeBrowsing: ${err.message}`);
    }

    return {
      connector: "google-safebrowsing",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
