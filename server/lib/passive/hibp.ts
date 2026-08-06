/**
 * Have I Been Pwned (HIBP) — Breach & Paste Connector
 *
 * Queries the HIBP v3 API for domain-level breach exposure:
 * - All breaches affecting email addresses on the target domain
 * - Paste exposure for discovered email addresses
 *
 * Method: REST API v3 with hibp-api-key header
 * Data Source: Troy Hunt's HIBP database (12B+ breached accounts)
 * Paid: $3.50/month for API access (required since 2019)
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

async function hibpFetch(path: string, apiKey: string, timeout: number): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3${path}`, {
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": "AceStrike-DomainIntel",
      },
      signal: controller.signal,
    });
    if (res.status === 404) return null; // no breaches found
    if (res.status === 429) throw new Error("RATE_LIMITED");
    if (!res.ok) throw new Error(`HIBP returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export const hibpConnector: PassiveConnector = {
  name: "hibp",
  description: "Have I Been Pwned — domain breach exposure, compromised credentials, and paste monitoring",
  requiresApiKey: true,
  freeUrl: "https://haveibeenpwned.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "hibp", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // 1. Domain search — get all breaches affecting this domain
      const breaches = await hibpFetch(`/breaches?domain=${encodeURIComponent(domain)}`, apiKey, timeout);
      if (breaches && Array.isArray(breaches)) {
        const now = new Date();
        for (const breach of breaches) {
          observations.push({
            assetId: makeAssetId(domain, `breach-${breach.Name}`, "hibp"),
            domain,
            assetType: "breach",
            name: breach.Name,
            source: "hibp",
            observedAt: now,
            firstSeen: breach.BreachDate ? new Date(breach.BreachDate) : undefined,
            tags: [
              "breach",
              ...(breach.DataClasses || []).map((dc: string) => dc.toLowerCase().replace(/\s+/g, "-")),
              breach.IsVerified ? "verified" : "unverified",
              breach.IsSensitive ? "sensitive" : "public",
            ],
            evidence: {
              title: breach.Title,
              breachDate: breach.BreachDate,
              addedDate: breach.AddedDate,
              modifiedDate: breach.ModifiedDate,
              pwnCount: breach.PwnCount,
              description: (breach.Description || "").slice(0, 500),
              dataClasses: breach.DataClasses,
              isVerified: breach.IsVerified,
              isFabricated: breach.IsFabricated,
              isSensitive: breach.IsSensitive,
              isRetired: breach.IsRetired,
              isSpamList: breach.IsSpamList,
              isMalware: breach.IsMalware,
              logoPath: breach.LogoPath,
            },
            attribution: {
              provider: "Have I Been Pwned",
              url: `https://haveibeenpwned.com/PwnedWebsites#${breach.Name}`,
              method: "HIBP domain breach search",
              verifyUrl: `https://haveibeenpwned.com/DomainSearch/${domain}`,
            },
          });
        }
      }

      // 2. Get all breached email addresses for the domain (paid feature)
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 1600)); // HIBP rate limit: 1 req/1.5s
        try {
          const domainSearch = await hibpFetch(`/breacheddomain/${encodeURIComponent(domain)}`, apiKey, timeout);
          if (domainSearch && typeof domainSearch === "object") {
            const now = new Date();
            const aliases = Object.keys(domainSearch);
            for (const alias of aliases.slice(0, 100)) { // cap at 100 emails
              const email = `${alias}@${domain}`;
              const breachNames: string[] = domainSearch[alias] || [];
              observations.push({
                assetId: makeAssetId(domain, `email-breach-${alias}`, "hibp"),
                domain,
                assetType: "breach",
                name: email,
                source: "hibp",
                observedAt: now,
                tags: ["email-breach", "credential-exposure", ...breachNames.slice(0, 5).map(b => `breach:${b}`)],
                evidence: {
                  email,
                  breachCount: breachNames.length,
                  breaches: breachNames,
                },
                attribution: {
                  provider: "Have I Been Pwned",
                  url: `https://haveibeenpwned.com/account/${email}`,
                  method: "HIBP breached domain email search",
                },
              });
            }
          }
        } catch (err: any) {
          if (err.message === "RATE_LIMITED") {
            rateLimited = true;
            errors.push("Rate limited on domain email search");
          } else {
            errors.push(`Domain email search: ${err.message}`);
          }
        }
      }
    } catch (err: any) {
      if (err.message === "RATE_LIMITED") {
        rateLimited = true;
        errors.push("HIBP rate limited");
      } else {
        errors.push(`HIBP error: ${err.message}`);
      }
    }

    return {
      connector: "hibp",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
