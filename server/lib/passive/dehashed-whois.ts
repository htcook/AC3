/**
 * Dehashed WHOIS & Subdomain Scan Connector
 *
 * Uses the Dehashed V2 WHOIS API to enrich DI scans with:
 * - Domain WHOIS registration data (registrar, dates, nameservers, status)
 * - Reverse WHOIS (discover related domains by registrant org/email)
 * - Subdomain discovery via Dehashed's WHOIS subdomain scan
 *
 * Auth: Dehashed-Api-Key header
 * Endpoints:
 *   POST https://api.dehashed.com/v2/whois/search  (search_type: whois | reverse-whois | subdomain-scan)
 *   GET  https://api.dehashed.com/v2/whois/credits
 *
 * Credit costs:
 *   - WHOIS lookup: 1 credit
 *   - Reverse WHOIS: varies
 *   - WHOIS history: 25 credits (SKIPPED — too expensive for passive DI)
 *   - Subdomain scan: 1 credit
 *
 * Requires: DEHASHED_API_KEY
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const WHOIS_URL = "https://api.dehashed.com/v2/whois/search";
const WHOIS_CREDITS_URL = "https://api.dehashed.com/v2/whois/credits";

interface WhoisResponse {
  domain_name?: string;
  registrar?: string;
  registrar_url?: string;
  creation_date?: string;
  updated_date?: string;
  expiration_date?: string;
  name_servers?: string[];
  status?: string[];
  registrant_name?: string;
  registrant_organization?: string;
  registrant_email?: string;
  registrant_country?: string;
  registrant_state?: string;
  admin_email?: string;
  tech_email?: string;
  dnssec?: string;
  error?: string;
  // Reverse WHOIS returns domains array
  domains?: string[];
  total?: number;
  // Subdomain scan returns subdomains
  subdomains?: string[];
}

async function dehashedWhoisRequest(
  apiKey: string,
  body: Record<string, unknown>,
  timeout: number,
): Promise<{ data: WhoisResponse | null; error: string | null; status: number }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(WHOIS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": apiKey,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (res.status === 401) return { data: null, error: "Dehashed WHOIS: invalid API key", status: 401 };
    if (res.status === 403) return { data: null, error: "Dehashed WHOIS: insufficient credits", status: 403 };
    if (res.status === 429) return { data: null, error: "Dehashed WHOIS: rate limited", status: 429 };
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { data: null, error: `Dehashed WHOIS returned ${res.status}: ${body}`, status: res.status };
    }

    const data = await res.json();
    return { data, error: null, status: res.status };
  } catch (err: any) {
    if (err.name === "AbortError") return { data: null, error: "Dehashed WHOIS request timed out", status: 0 };
    return { data: null, error: `Dehashed WHOIS error: ${err.message}`, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}

export const dehashedWhoisConnector: PassiveConnector = {
  name: "dehashed_whois",
  description: "WHOIS registration data, reverse WHOIS domain discovery, and subdomain scanning via Dehashed V2 API",
  requiresApiKey: true,
  freeUrl: "https://dehashed.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;

    if (!apiKey) {
      return {
        connector: "dehashed_whois",
        domain,
        observations: [],
        errors: ["DEHASHED_API_KEY not configured — skipping Dehashed WHOIS connector"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    const now = new Date();
    let rateLimited = false;

    // ─── 1. Domain WHOIS Lookup (1 credit) ──────────────────────────────
    const whoisResult = await dehashedWhoisRequest(apiKey, {
      search_type: "whois",
      domain,
    }, timeout);

    if (whoisResult.status === 429) rateLimited = true;

    if (whoisResult.data && !whoisResult.error) {
      const w = whoisResult.data;

      // Calculate domain age and expiry proximity
      const creationDate = w.creation_date ? new Date(w.creation_date) : null;
      const expirationDate = w.expiration_date ? new Date(w.expiration_date) : null;
      const updatedDate = w.updated_date ? new Date(w.updated_date) : null;
      const domainAgeYears = creationDate ? Math.round((now.getTime() - creationDate.getTime()) / (365.25 * 24 * 60 * 60 * 1000) * 10) / 10 : null;
      const daysUntilExpiry = expirationDate ? Math.round((expirationDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)) : null;

      // Risk signals from WHOIS data
      const riskSignals: string[] = [];
      if (domainAgeYears !== null && domainAgeYears < 1) riskSignals.push("recently_registered");
      if (daysUntilExpiry !== null && daysUntilExpiry < 30) riskSignals.push("expiring_soon");
      if (daysUntilExpiry !== null && daysUntilExpiry < 0) riskSignals.push("expired");
      if (w.dnssec === "unsigned") riskSignals.push("dnssec_unsigned");
      if (w.registrant_email && w.registrant_email.includes("privacy")) riskSignals.push("privacy_protected");
      if (w.registrant_organization && /proxy|privacy|protect|guard|domains by/i.test(w.registrant_organization)) {
        riskSignals.push("whois_privacy_service");
      }

      observations.push({
        assetId: makeAssetId(domain, "whois", "dehashed_whois"),
        domain,
        assetType: "domain",
        name: domain,
        source: "dehashed_whois",
        observedAt: now,
        tags: [
          "whois_registration",
          "domain_intelligence",
          ...riskSignals,
        ],
        evidence: {
          registrar: w.registrar,
          registrar_url: w.registrar_url,
          creation_date: w.creation_date,
          updated_date: w.updated_date,
          expiration_date: w.expiration_date,
          domain_age_years: domainAgeYears,
          days_until_expiry: daysUntilExpiry,
          name_servers: w.name_servers,
          status: w.status,
          registrant_organization: w.registrant_organization,
          registrant_country: w.registrant_country,
          registrant_state: w.registrant_state,
          registrant_email: w.registrant_email ? w.registrant_email.replace(/^[^@]+/, "***") : undefined,
          admin_email: w.admin_email ? w.admin_email.replace(/^[^@]+/, "***") : undefined,
          dnssec: w.dnssec,
          risk_signals: riskSignals,
        },
        attribution: {
          provider: "Dehashed (WHOIS)",
          url: "https://dehashed.com",
          method: `WHOIS registration lookup for ${domain} — registered ${w.creation_date || "unknown"}, expires ${w.expiration_date || "unknown"}, registrar: ${w.registrar || "unknown"}`,
          verifyUrl: `https://who.is/whois/${domain}`,
        },
      });

      // Extract nameserver observations
      if (w.name_servers && w.name_servers.length > 0) {
        const nsProvider = detectNsProvider(w.name_servers);
        observations.push({
          assetId: makeAssetId(domain, "nameservers", "dehashed_whois"),
          domain,
          assetType: "infrastructure",
          name: `${domain} nameservers`,
          source: "dehashed_whois",
          observedAt: now,
          tags: ["nameserver", "dns_infrastructure", ...(nsProvider ? [`ns_provider:${nsProvider}`] : [])],
          evidence: {
            nameservers: w.name_servers,
            provider: nsProvider,
            count: w.name_servers.length,
          },
          attribution: {
            provider: "Dehashed (WHOIS)",
            url: "https://dehashed.com",
            method: `Nameserver enumeration from WHOIS for ${domain}`,
          },
        });
      }
    } else if (whoisResult.error) {
      errors.push(whoisResult.error);
    }

    // ─── 2. Subdomain Scan (1 credit) ───────────────────────────────────
    if (!rateLimited) {
      const subResult = await dehashedWhoisRequest(apiKey, {
        search_type: "subdomain-scan",
        domain,
      }, timeout);

      if (subResult.status === 429) rateLimited = true;

      if (subResult.data && !subResult.error) {
        const subs = subResult.data.subdomains || [];
        const seenSubs = new Set<string>();

        for (const sub of subs) {
          if (!sub || seenSubs.has(sub.toLowerCase())) continue;
          const subLower = sub.toLowerCase();
          seenSubs.add(subLower);

          // Skip the apex domain itself
          if (subLower === domain.toLowerCase()) continue;

          observations.push({
            assetId: makeAssetId(domain, subLower, "dehashed_whois_sub"),
            domain,
            assetType: "subdomain",
            name: subLower,
            source: "dehashed_whois",
            observedAt: now,
            tags: ["whois_derived", "subdomain_scan"],
            evidence: {
              discovery_method: "dehashed_whois_subdomain_scan",
              subdomain: subLower,
            },
            attribution: {
              provider: "Dehashed (WHOIS Subdomain Scan)",
              url: "https://dehashed.com",
              method: `Subdomain discovered via Dehashed WHOIS subdomain scan for ${domain}`,
            },
          });
        }

        if (subs.length > 0) {
          observations.push({
            assetId: makeAssetId(domain, "subdomain_scan_summary", "dehashed_whois"),
            domain,
            assetType: "domain",
            name: `${domain} subdomain scan`,
            source: "dehashed_whois",
            observedAt: now,
            tags: ["subdomain_scan_summary", "whois_derived"],
            evidence: {
              total_subdomains: seenSubs.size,
              subdomains: Array.from(seenSubs).slice(0, 50), // Cap at 50 for evidence
              truncated: seenSubs.size > 50,
            },
            attribution: {
              provider: "Dehashed (WHOIS Subdomain Scan)",
              url: "https://dehashed.com",
              method: `Discovered ${seenSubs.size} subdomains for ${domain} via WHOIS subdomain scan`,
            },
          });
        }
      } else if (subResult.error) {
        errors.push(subResult.error);
      }
    }

    // ─── 3. Reverse WHOIS — discover related domains ────────────────────
    // Only run if we got registrant org from the WHOIS lookup
    if (!rateLimited && whoisResult.data?.registrant_organization) {
      const orgName = whoisResult.data.registrant_organization;
      // Skip if it's a privacy service
      if (!/proxy|privacy|protect|guard|domains by/i.test(orgName)) {
        const reverseResult = await dehashedWhoisRequest(apiKey, {
          search_type: "reverse-whois",
          include: [orgName],
          exclude: [],
          reverse_type: "current",
        }, timeout);

        if (reverseResult.status === 429) rateLimited = true;

        if (reverseResult.data && !reverseResult.error) {
          const relatedDomains = reverseResult.data.domains || [];
          const filteredDomains = relatedDomains.filter(
            (d: string) => d && d.toLowerCase() !== domain.toLowerCase()
          );

          if (filteredDomains.length > 0) {
            observations.push({
              assetId: makeAssetId(domain, "reverse_whois", "dehashed_whois"),
              domain,
              assetType: "domain",
              name: `${domain} related domains`,
              source: "dehashed_whois",
              observedAt: now,
              tags: [
                "reverse_whois",
                "related_domains",
                "attack_surface_expansion",
                `related_count:${filteredDomains.length}`,
              ],
              evidence: {
                registrant_organization: orgName,
                related_domains: filteredDomains.slice(0, 100),
                total_related: filteredDomains.length,
                truncated: filteredDomains.length > 100,
                discovery_method: "reverse_whois_by_organization",
              },
              attribution: {
                provider: "Dehashed (Reverse WHOIS)",
                url: "https://dehashed.com",
                method: `Reverse WHOIS by organization "${orgName}" discovered ${filteredDomains.length} related domains`,
              },
            });

            // Emit individual related domain observations (top 20 for DI report)
            for (const relDomain of filteredDomains.slice(0, 20)) {
              observations.push({
                assetId: makeAssetId(domain, relDomain, "dehashed_reverse_whois"),
                domain,
                assetType: "domain",
                name: relDomain,
                source: "dehashed_whois",
                observedAt: now,
                tags: ["related_domain", "same_registrant", "attack_surface"],
                evidence: {
                  parent_domain: domain,
                  registrant_organization: orgName,
                  relationship: "same_registrant_organization",
                },
                attribution: {
                  provider: "Dehashed (Reverse WHOIS)",
                  url: "https://dehashed.com",
                  method: `Related domain ${relDomain} shares registrant organization "${orgName}" with ${domain}`,
                },
              });
            }
          }
        } else if (reverseResult.error) {
          errors.push(reverseResult.error);
        }
      }
    }

    return {
      connector: "dehashed_whois",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};

// ─── Nameserver Provider Detection ──────────────────────────────────────────

function detectNsProvider(nameservers: string[]): string | null {
  const nsStr = nameservers.join(" ").toLowerCase();
  const providers: [string, string[]][] = [
    ["cloudflare", ["cloudflare"]],
    ["aws_route53", ["awsdns"]],
    ["google_cloud_dns", ["googledomains", "google.com"]],
    ["azure_dns", ["azure-dns"]],
    ["godaddy", ["domaincontrol"]],
    ["namecheap", ["registrar-servers"]],
    ["digitalocean", ["digitalocean"]],
    ["dnsimple", ["dnsimple"]],
    ["dnsmadeeasy", ["dnsmadeeasy"]],
    ["ns1", ["nsone.net"]],
    ["ultradns", ["ultradns"]],
    ["akamai", ["akam.net"]],
    ["verisign", ["verisign"]],
    ["ovh", ["ovh.net"]],
    ["hetzner", ["hetzner"]],
  ];

  for (const [provider, patterns] of providers) {
    if (patterns.some(p => nsStr.includes(p))) return provider;
  }
  return null;
}
