/**
 * Dehashed — Breach Intelligence & Domain Mapping Connector (v4 API)
 * 
 * Queries the Dehashed v2/v4 API for breach records matching the target domain.
 * Extracts subdomains from email addresses, discovers credential exposures,
 * maps IP addresses, and identifies breach database sources.
 * 
 * Auth: Dehashed-Api-Key header (v4 format — old Basic Auth is deprecated)
 * Method: POST https://api.dehashed.com/v2/search
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

/** v4 API returns arrays for most fields */
interface DehashedEntryV4 {
  id?: string;
  email?: string[];
  ip_address?: string[];
  username?: string[];
  password?: string[];
  hashed_password?: string[];
  name?: string[];
  phone?: string[];
  address?: string[];
  company?: string[];
  url?: string[];
  social?: string[];
  cryptocurrency_address?: string[];
  database_name?: string;
  raw_record?: { le_only?: boolean; unstructured?: boolean };
  dob?: string[];
  license_plate?: string[];
  domain?: string[];
}

interface DehashedResponseV4 {
  balance?: number;
  entries?: DehashedEntryV4[] | null;
  total?: number;
  took?: string;
  error?: string;
}

const DEHASHED_SEARCH_URL = "https://api.dehashed.com/v2/search";

/** Helper to get first string from a v4 array field */
function first(arr?: string[]): string | undefined {
  return arr && arr.length > 0 ? arr[0] : undefined;
}

/** Helper to check if any element in array is non-empty */
function hasValue(arr?: string[]): boolean {
  return !!arr && arr.some(v => v && v.trim().length > 0);
}

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

      const size = Math.min(maxResults, 10000);

      let data: DehashedResponseV4;
      try {
        const res = await fetch(DEHASHED_SEARCH_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Dehashed-Api-Key": apiKey,
          },
          body: JSON.stringify({
            query: `domain:${domain}`,
            page: 1,
            size,
            de_dupe: true,
          }),
          signal: controller.signal,
        });

        if (res.status === 401 || res.status === 403) {
          const body = await res.text().catch(() => "");
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: [`Dehashed API credentials invalid (${res.status}): ${body} — check DEHASHED_API_KEY. The old v1 Basic Auth API is deprecated; use the v4 API key from app.dehashed.com/documentation/api`],
            durationMs: Date.now() - start,
            rateLimited: false,
          };
        }
        if (res.status === 429) {
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: ["Dehashed rate limit exceeded — max 10 requests/second"],
            durationMs: Date.now() - start,
            rateLimited: true,
          };
        }
        if (res.status === 402) {
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: ["Dehashed API credits exhausted — purchase more at dehashed.com"],
            durationMs: Date.now() - start,
            rateLimited: false,
          };
        }
        if (res.status === 400) {
          const body = await res.text().catch(() => "");
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: [`Dehashed bad request (400): ${body}`],
            durationMs: Date.now() - start,
            rateLimited: false,
          };
        }
        if (!res.ok) {
          throw new Error(`Dehashed returned ${res.status}: ${await res.text().catch(() => "unknown")}`);
        }
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      // Check for API-level errors in response body
      if (data.error) {
        return {
          connector: "dehashed",
          domain,
          observations: [],
          errors: [`Dehashed API error: ${data.error}`],
          durationMs: Date.now() - start,
          rateLimited: false,
        };
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
        const hasPassword = hasValue(entry.password);
        const hasHash = hasValue(entry.hashed_password);
        if (hasPassword || hasHash) {
          breachCredCounts.set(dbName, (breachCredCounts.get(dbName) || 0) + 1);
        }
      }

      // Second pass: extract observations
      for (const entry of entries) {
        // ─── Subdomain discovery from email addresses ───────────
        const emails = entry.email || [];
        for (const email of emails) {
          if (!email) continue;
          const emailDomain = email.split("@")[1]?.toLowerCase();
          if (emailDomain && (emailDomain === domain || emailDomain.endsWith(`.${domain}`))) {
            if (!seenSubdomains.has(emailDomain) && emailDomain !== domain.toLowerCase()) {
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
                  sample_email_pattern: email.replace(/^[^@]+/, "***"),
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
        const ips = entry.ip_address || [];
        for (const rawIp of ips) {
          if (!rawIp) continue;
          const ip = rawIp.trim();
          if (ip.length > 0 && !seenIPs.has(ip)) {
            seenIPs.add(ip);
            observations.push({
              assetId: makeAssetId(domain, ip, "dehashed_ip"),
              domain,
              assetType: "ip",
              name: ip,
              ip,
              source: "dehashed",
              observedAt: now,
              tags: ["breach_derived", "ip_association", `breach:${entry.database_name || "unknown"}`],
              evidence: {
                discovery_method: "breach_ip_association",
                database_name: entry.database_name,
                associated_email: first(entry.email)
                  ? first(entry.email)!.replace(/^[^@]+/, "***@") + (first(entry.email)!.split("@")[1] || "")
                  : undefined,
              },
              attribution: {
                provider: "Dehashed (Breach Intelligence)",
                url: "https://dehashed.com",
                method: `IP address associated with ${domain} discovered in breach records from ${entry.database_name || "unknown"} database`,
                verifyUrl: "https://dehashed.com",
              },
            });
          }
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
              has_hashed_passwords: entries.some(e =>
                e.database_name === dbName && hasValue(e.hashed_password)
              ),
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
