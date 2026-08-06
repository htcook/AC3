/**
 * Hunter.io — Email Discovery & Verification Connector
 *
 * Queries the Hunter.io API for email intelligence:
 * - Domain email pattern detection
 * - Email address discovery (first/last name + domain)
 * - Email verification
 * - Organization info and social links
 *
 * Method: REST API v2 with api_key parameter
 * Data Source: Hunter.io's email crawling and verification platform
 * Free tier: 25 searches/month, 50 verifications/month
 * Paid tier: From $49/month (500 searches)
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const hunterConnector: PassiveConnector = {
  name: "hunter",
  description: "Hunter.io — email address discovery, email pattern detection, and organization intelligence",
  requiresApiKey: true,
  freeUrl: "https://hunter.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "hunter", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch(
          `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${apiKey}&limit=100`,
          { signal: controller.signal }
        );
        clearTimeout(timer);

        if (res.status === 429) {
          rateLimited = true;
          errors.push("Rate limited");
        } else if (res.ok) {
          const data = await res.json();
          const now = new Date();

          if (data.data) {
            const d = data.data;

            // Organization overview
            observations.push({
              assetId: makeAssetId(domain, `org-${domain}`, "hunter"),
              domain,
              assetType: "subdomain",
              name: domain,
              source: "hunter",
              observedAt: now,
              tags: ["organization", "email-pattern", "hunter-domain"],
              evidence: {
                organization: d.organization,
                emailPattern: d.pattern,
                emailCount: d.emails?.length || 0,
                totalResults: d.total || 0,
                disposable: d.disposable,
                webmail: d.webmail,
                acceptAll: d.accept_all,
                description: d.description,
                industry: d.industry,
                twitter: d.twitter,
                facebook: d.facebook,
                linkedin: d.linkedin,
                instagram: d.instagram,
                youtube: d.youtube,
                technologies: d.technologies,
                country: d.country,
                state: d.state,
                city: d.city,
                headcount: d.headcount,
              },
              attribution: {
                provider: "Hunter.io",
                url: `https://hunter.io/try/search/${domain}`,
                method: "Hunter.io domain search",
              },
            });

            // Individual email addresses
            if (d.emails && Array.isArray(d.emails)) {
              for (const email of d.emails) {
                observations.push({
                  assetId: makeAssetId(domain, `email-${email.value}`, "hunter"),
                  domain,
                  assetType: "breach", // reuse breach type for email-related findings
                  name: email.value,
                  source: "hunter",
                  observedAt: now,
                  firstSeen: email.first_seen ? new Date(email.first_seen) : undefined,
                  lastSeen: email.last_seen ? new Date(email.last_seen) : undefined,
                  tags: [
                    "email-address",
                    "discovered-email",
                    email.type || "unknown-type",
                    `confidence:${email.confidence}`,
                    email.department || "",
                    email.seniority || "",
                  ].filter(Boolean),
                  evidence: {
                    email: email.value,
                    type: email.type,
                    confidence: email.confidence,
                    firstName: email.first_name,
                    lastName: email.last_name,
                    position: email.position,
                    department: email.department,
                    seniority: email.seniority,
                    twitter: email.twitter,
                    linkedin: email.linkedin_url,
                    phoneNumber: email.phone_number,
                    sources: (email.sources || []).slice(0, 5).map((s: any) => ({
                      domain: s.domain,
                      uri: s.uri,
                      extractedOn: s.extracted_on,
                    })),
                  },
                  attribution: {
                    provider: "Hunter.io",
                    url: `https://hunter.io/try/search/${domain}`,
                    method: "Hunter.io email discovery",
                  },
                });
              }
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("Hunter.io request timed out");
      }
    } catch (err: any) {
      errors.push(`Hunter.io error: ${err.message}`);
    }

    return {
      connector: "hunter",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
