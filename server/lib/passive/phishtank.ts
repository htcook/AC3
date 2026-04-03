/**
 * PhishTank Connector — Free (API key optional, improves rate limits)
 *
 * Checks the target domain against PhishTank's community-verified
 * phishing URL database. PhishTank is one of the largest open
 * phishing intelligence sources, maintained by Cisco/OpenDNS.
 *
 * Two approaches:
 *   1. check_url API — check specific URLs (requires API key for higher limits)
 *   2. Online database download — hourly dump of all verified phishing URLs
 *      (we use approach 1 for real-time checks)
 *
 * API docs: https://phishtank.net/api_info.php
 * Rate limits: Without API key — very limited; with key — reasonable
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

const CHECK_URL_API = "https://checkurl.phishtank.com/checkurl/";

async function checkPhishTankUrl(
  url: string,
  apiKey?: string,
  signal?: AbortSignal
): Promise<any> {
  const params = new URLSearchParams({
    url,
    format: "json",
  });
  if (apiKey) {
    params.set("app_key", apiKey);
  }

  const resp = await fetch(CHECK_URL_API, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    signal: signal || AbortSignal.timeout(15000),
  });

  if (resp.status === 429 || resp.status === 509) return { _rateLimited: true };
  if (!resp.ok) return null;
  return resp.json();
}

export const phishtankConnector: PassiveConnector = {
  name: "phishtank",
  description:
    "PhishTank — community-verified phishing URL database (free, API key optional)",
  requiresApiKey: false,
  freeUrl: "https://phishtank.net",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const start = Date.now();
    let rateLimited = false;
    const now = new Date();
    const apiKey = config?.apiKey;
    const sig = config?.signal;

    // Check common URL patterns for the domain
    const urlsToCheck = [
      `http://${domain}/`,
      `https://${domain}/`,
      `http://www.${domain}/`,
      `https://www.${domain}/`,
    ];

    for (const url of urlsToCheck) {
      if (rateLimited) break;

      try {
        const result = await checkPhishTankUrl(url, apiKey, sig);

        if (result?._rateLimited) {
          rateLimited = true;
          break;
        }

        if (result?.results) {
          const r = result.results;
          if (r.in_database) {
            const verified = r.verified === "yes" || r.verified === true;
            const verifiedAt = r.verified_at;
            const phishId = r.phish_id;
            const phishDetailUrl = r.phish_detail_page;

            const name = `PhishTank: ${url} — ${
              verified ? "VERIFIED PHISH" : "Reported (unverified)"
            }`;

            observations.push({
              assetId: makeAssetId(
                domain,
                `phishtank-${phishId || url}`,
                "phishtank"
              ),
              domain,
              assetType: "url",
              name,
              source: "phishtank",
              observedAt: now,
              firstSeen: verifiedAt ? new Date(verifiedAt) : undefined,
              tags: [
                "phishtank",
                "phishing",
                verified ? "verified-phish" : "reported-phish",
                "social-engineering",
              ],
              evidence: {
                severity: verified ? 9 : 6,
                confidence: verified ? 90 : 50,
                value: `${
                  verified ? "VERIFIED" : "Reported"
                } phishing URL in PhishTank database: ${url}`,
                phishId,
                url,
                inDatabase: true,
                verified,
                verifiedAt,
                valid: r.valid,
              },
              attribution: {
                provider: "PhishTank",
                url:
                  phishDetailUrl ||
                  `https://phishtank.net/phish_detail.php?phish_id=${phishId}`,
                method: "PhishTank checkurl API — community-verified phishing database",
                verifyUrl:
                  phishDetailUrl ||
                  `https://phishtank.net/phish_detail.php?phish_id=${phishId}`,
              },
            });
          }
        }
      } catch (err: any) {
        // Don't error on individual URL checks — just note it
        if (err.message?.includes("timeout")) {
          errors.push(`PhishTank timeout checking ${url}`);
        }
        // Silently skip other errors for individual URL checks
      }
    }

    // If no phishing found and no errors, add a clean observation
    if (observations.length === 0 && !rateLimited && errors.length === 0) {
      observations.push({
        assetId: makeAssetId(domain, "phishtank-clean", "phishtank"),
        domain,
        assetType: "subdomain",
        name: `PhishTank: ${domain} — No phishing URLs found`,
        source: "phishtank",
        observedAt: now,
        tags: ["phishtank", "clean"],
        evidence: {
          severity: 0,
          confidence: 70,
          value: `No phishing URLs found for ${domain} in PhishTank database`,
          checkedUrls: urlsToCheck,
          result: "clean",
        },
        attribution: {
          provider: "PhishTank",
          url: `https://phishtank.net`,
          method: "PhishTank checkurl API",
        },
      });
    }

    return {
      connector: "phishtank",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
