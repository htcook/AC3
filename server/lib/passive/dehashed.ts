/**
 * Dehashed — Breach Intelligence & Domain Mapping Connector
 * 
 * Queries the Dehashed v2 API for breach records matching the target domain.
 * Extracts subdomains from email addresses, discovers credential exposures,
 * maps IP addresses, and identifies breach database sources.
 * 
 * Method: POST to Dehashed Search API v2 with domain query
 * Data Source: 15B+ breach records aggregated from public and private data wells
 * Attribution: Each observation references the Dehashed breach database source
 * Requires: DEHASHED_API_KEY (credit-based, limited-use token)
 * 
 * Intelligence produced:
 * - Subdomain discovery from email domains in breach records
 * - Credential exposure signals (leaked passwords/hashes)
 * - Email pattern enumeration for the target domain
 * - IP address associations from breach metadata
 * - Breach database attribution (which breaches exposed the domain)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface DehashedEntry {
  id?: string;
  email?: string;
  ip_address?: string;
  username?: string;
  password?: string;
  hashed_password?: string;
  name?: string;
  phone?: string;
  address?: string;
  vin?: string;
  database_name?: string;
  domain?: string;
}

interface DehashedResponse {
  balance?: number;
  entries?: DehashedEntry[];
  total?: number;
  took?: string;
}

const DEHASHED_SEARCH_URL = "https://api.dehashed.com/v2/search";

export const dehashedConnector: PassiveConnector = {
  name: "dehashed",
  description: "Breach intelligence & domain mapping — discovers subdomains, credential exposures, email patterns, and IP associations from 15B+ breach records",
  requiresApiKey: true,
  freeUrl: "https://dehashed.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    const maxResults = config?.maxResults ?? 10000;

    if (!apiKey) {
      return {
        connector: "dehashed",
        domain,
        observations: [],
        errors: ["DEHASHED_API_KEY not configured — skipping Dehashed connector"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    let rateLimited = false;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: DehashedResponse;
      try {
        const res = await fetch(DEHASHED_SEARCH_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "DeHashed-Api-Key": apiKey,
          },
          body: JSON.stringify({
            query: `domain:${domain}`,
            page: 1,
            size: Math.min(maxResults, 10000),
            wildcard: false,
            regex: false,
            de_dupe: true,
          }),
          signal: controller.signal,
        });

        if (res.status === 401 || res.status === 403) {
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: ["Dehashed API key is invalid or expired"],
            durationMs: Date.now() - start,
            rateLimited: false,
          };
        }
        if (res.status === 429) {
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: ["Dehashed rate limit exceeded — insufficient API credits"],
            durationMs: Date.now() - start,
            rateLimited: true,
          };
        }
        if (!res.ok) {
          throw new Error(`Dehashed returned ${res.status}: ${await res.text().catch(() => "unknown")}`);
        }
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const entries = data.entries || [];
      const now = new Date();

      // Track unique values for deduplication
      const seenSubdomains = new Set<string>();
      const seenIPs = new Set<string>();
      const seenBreaches = new Set<string>();
      const breachEmailCounts = new Map<string, number>();
      const breachCredCounts = new Map<string, number>();

      // First pass: aggregate breach statistics
      for (const entry of entries) {
        const dbName = entry.database_name || "unknown";
        breachEmailCounts.set(dbName, (breachEmailCounts.get(dbName) || 0) + 1);
        if (entry.password || entry.hashed_password) {
          breachCredCounts.set(dbName, (breachCredCounts.get(dbName) || 0) + 1);
        }
      }

      // Second pass: extract observations
      for (const entry of entries) {
        // ─── Subdomain discovery from email addresses ───────────
        if (entry.email) {
          const emailDomain = entry.email.split("@")[1]?.toLowerCase();
          if (emailDomain && (emailDomain === domain || emailDomain.endsWith(`.${domain}`))) {
            if (!seenSubdomains.has(emailDomain) && emailDomain !== domain) {
              seenSubdomains.add(emailDomain);
              observations.push({
                assetId: makeAssetId(domain, emailDomain, "dehashed_subdomain"),
                domain,
                assetType: "subdomain",
                name: emailDomain,
                source: "dehashed",
                observedAt: now,
                tags: ["breach_derived", "email_domain", `breach:${entry.database_name || "unknown"}`],
                evidence: {
                  discovery_method: "email_domain_extraction",
                  sample_email_pattern: entry.email.replace(/^[^@]+/, "***"),
                  database_name: entry.database_name,
                },
                attribution: {
                  provider: "Dehashed (Breach Intelligence)",
                  url: "https://dehashed.com",
                  method: `Subdomain discovered via email domain extraction from breach records — ${emailDomain} found in ${entry.database_name || "unknown"} breach database`,
                  verifyUrl: "https://dehashed.com",
                },
              });
            }
          }
        }

        // ─── IP address mapping from breach records ─────────────
        if (entry.ip_address && !seenIPs.has(entry.ip_address)) {
          seenIPs.add(entry.ip_address);
          observations.push({
            assetId: makeAssetId(domain, entry.ip_address, "dehashed_ip"),
            domain,
            assetType: "ip",
            name: entry.ip_address,
            ip: entry.ip_address,
            source: "dehashed",
            observedAt: now,
            tags: ["breach_derived", "ip_association", `breach:${entry.database_name || "unknown"}`],
            evidence: {
              discovery_method: "breach_ip_association",
              database_name: entry.database_name,
              associated_email: entry.email ? entry.email.replace(/^[^@]+/, "***@") + entry.email.split("@")[1] : undefined,
            },
            attribution: {
              provider: "Dehashed (Breach Intelligence)",
              url: "https://dehashed.com",
              method: `IP address associated with ${domain} discovered in breach records from ${entry.database_name || "unknown"} database`,
              verifyUrl: "https://dehashed.com",
            },
          });
        }

        // ─── Breach database observations ───────────────────────
        const dbName = entry.database_name || "unknown";
        if (!seenBreaches.has(dbName) && dbName !== "unknown") {
          seenBreaches.add(dbName);
          const emailCount = breachEmailCounts.get(dbName) || 0;
          const credCount = breachCredCounts.get(dbName) || 0;

          observations.push({
            assetId: makeAssetId(domain, `breach:${dbName}`, "dehashed_breach"),
            domain,
            assetType: "breach",
            name: dbName,
            source: "dehashed",
            observedAt: now,
            tags: [
              "breach_database",
              ...(credCount > 0 ? ["credentials_exposed"] : []),
              `records:${emailCount}`,
            ],
            evidence: {
              database_name: dbName,
              total_records: emailCount,
              credentials_exposed: credCount,
              has_passwords: credCount > 0,
              has_hashed_passwords: entries.some(e => e.database_name === dbName && !!e.hashed_password),
            },
            attribution: {
              provider: "Dehashed (Breach Intelligence)",
              url: "https://dehashed.com",
              method: `Breach database "${dbName}" contains ${emailCount} records associated with ${domain} (${credCount} with exposed credentials)`,
              verifyUrl: "https://dehashed.com",
            },
          });
        }
      }

      // ─── Summary observation for the domain ───────────────────
      if (entries.length > 0) {
        const totalCreds = Array.from(breachCredCounts.values()).reduce((a, b) => a + b, 0);
        observations.push({
          assetId: makeAssetId(domain, "breach_summary", "dehashed"),
          domain,
          assetType: "breach",
          name: `${domain} breach summary`,
          source: "dehashed",
          observedAt: now,
          tags: [
            "breach_summary",
            `total_records:${data.total || entries.length}`,
            `total_breaches:${seenBreaches.size}`,
            ...(totalCreds > 0 ? ["credentials_at_risk"] : []),
          ],
          evidence: {
            total_records: data.total || entries.length,
            unique_breaches: seenBreaches.size,
            unique_subdomains_found: seenSubdomains.size,
            unique_ips_found: seenIPs.size,
            credentials_exposed: totalCreds,
            breach_databases: Array.from(seenBreaches),
            api_balance: data.balance,
          },
          attribution: {
            provider: "Dehashed (Breach Intelligence)",
            url: "https://dehashed.com",
            method: `Domain-wide breach analysis — ${data.total || entries.length} total records across ${seenBreaches.size} breach databases, ${seenSubdomains.size} subdomains discovered, ${totalCreds} credentials exposed`,
            verifyUrl: "https://dehashed.com",
          },
        });
      }

    } catch (err: any) {
      if (err.name === "AbortError") {
        errors.push("Dehashed request timed out");
      } else {
        errors.push(`Dehashed error: ${err.message}`);
      }
    }

    return {
      connector: "dehashed",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
