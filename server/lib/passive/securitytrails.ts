/**
 * SecurityTrails — DNS & Domain Intelligence Connector
 * 
 * Queries SecurityTrails API for comprehensive DNS data: subdomains,
 * historical DNS records, associated domains, and WHOIS data.
 * 
 * Method: Queries SecurityTrails Subdomains API + Domain Details API
 * Data Source: SecurityTrails proprietary DNS crawl dataset (3+ billion DNS records)
 * Attribution: Each observation links to the SecurityTrails domain page for verification
 * Requires: SECURITYTRAILS_API_KEY (free tier: 50 queries/month)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

async function fetchST(path: string, apiKey: string, timeout: number): Promise<any> {
  const url = `https://api.securitytrails.com/v1/${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { APIKEY: apiKey, Accept: "application/json" },
      signal: controller.signal,
    });
    if (res.status === 401) throw new Error("SecurityTrails API key invalid");
    if (res.status === 429) throw new Error("RATE_LIMITED");
    if (!res.ok) throw new Error(`SecurityTrails returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export const securitytrailsConnector: PassiveConnector = {
  name: "securitytrails",
  description: "DNS & domain intelligence — discovers subdomains, DNS records, and associated domains from SecurityTrails' 3B+ record dataset",
  requiresApiKey: true,
  freeUrl: "https://securitytrails.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;

    if (!apiKey) {
      return { connector: "securitytrails", domain, observations: [], errors: ["SECURITYTRAILS_API_KEY not configured — skipping SecurityTrails connector"], durationMs: Date.now() - start, rateLimited: false };
    }

    const now = new Date();
    let rateLimited = false;

    // 1. Fetch subdomains
    try {
      const subData = await fetchST(`domain/${domain}/subdomains?children_only=false`, apiKey, timeout);
      const subdomains: string[] = subData?.subdomains || [];

      for (const sub of subdomains) {
        const fqdn = `${sub}.${domain}`.toLowerCase();
        observations.push({
          assetId: makeAssetId(domain, fqdn, "securitytrails_sub"),
          domain,
          assetType: "subdomain",
          name: fqdn,
          source: "securitytrails",
          observedAt: now,
          tags: ["dns_intelligence", "securitytrails"],
          evidence: { subdomain: sub, endpoint: "subdomains" },
          attribution: {
            provider: "SecurityTrails (DNS Intelligence)",
            url: `https://securitytrails.com/domain/${domain}/dns`,
            method: `SecurityTrails Subdomains API — enumerated subdomains for ${domain} from SecurityTrails' DNS crawl dataset`,
            verifyUrl: `https://securitytrails.com/domain/${domain}/dns`,
          },
        });
      }
    } catch (err: any) {
      if (err.message === "RATE_LIMITED") { rateLimited = true; errors.push("SecurityTrails rate limit exceeded on subdomains endpoint"); }
      else errors.push(`SecurityTrails subdomains error: ${err.message}`);
    }

    // 2. Fetch domain details (DNS records)
    try {
      const details = await fetchST(`domain/${domain}`, apiKey, timeout);
      const currentDns = details?.current_dns || {};

      // A records
      for (const record of (currentDns.a?.values || [])) {
        const ip = record.ip;
        if (ip) {
          observations.push({
            assetId: makeAssetId(domain, `${domain}|A|${ip}`, "securitytrails_a"),
            domain,
            assetType: "ip",
            name: `${domain} → ${ip}`,
            ip,
            source: "securitytrails",
            observedAt: now,
            tags: ["dns_a_record", "current_dns"],
            evidence: { record_type: "A", ip, first_seen: currentDns.a?.first_seen },
            attribution: {
              provider: "SecurityTrails (DNS Intelligence)",
              url: `https://securitytrails.com/domain/${domain}/dns`,
              method: `SecurityTrails Domain Details API — current A record for ${domain} points to ${ip}`,
              verifyUrl: `https://securitytrails.com/domain/${domain}/dns`,
            },
          });
        }
      }

      // MX records
      for (const record of (currentDns.mx?.values || [])) {
        const mx = record.hostname || record.host;
        if (mx) {
          observations.push({
            assetId: makeAssetId(domain, `${domain}|MX|${mx}`, "securitytrails_mx"),
            domain,
            assetType: "mx",
            name: mx,
            source: "securitytrails",
            observedAt: now,
            tags: ["dns_mx_record", "mail_server"],
            evidence: { record_type: "MX", hostname: mx, priority: record.priority },
            attribution: {
              provider: "SecurityTrails (DNS Intelligence)",
              url: `https://securitytrails.com/domain/${domain}/dns`,
              method: `SecurityTrails Domain Details API — MX record for ${domain} points to ${mx}`,
              verifyUrl: `https://securitytrails.com/domain/${domain}/dns`,
            },
          });
        }
      }

      // NS records
      for (const record of (currentDns.ns?.values || [])) {
        const ns = record.nameserver || record.host;
        if (ns) {
          observations.push({
            assetId: makeAssetId(domain, `${domain}|NS|${ns}`, "securitytrails_ns"),
            domain,
            assetType: "ns",
            name: ns,
            source: "securitytrails",
            observedAt: now,
            tags: ["dns_ns_record", "nameserver"],
            evidence: { record_type: "NS", nameserver: ns },
            attribution: {
              provider: "SecurityTrails (DNS Intelligence)",
              url: `https://securitytrails.com/domain/${domain}/dns`,
              method: `SecurityTrails Domain Details API — NS record for ${domain} delegated to ${ns}`,
              verifyUrl: `https://securitytrails.com/domain/${domain}/dns`,
            },
          });
        }
      }

      // TXT records
      for (const record of (currentDns.txt?.values || [])) {
        const txt = record.value;
        if (txt) {
          observations.push({
            assetId: makeAssetId(domain, `${domain}|TXT|${txt.slice(0, 50)}`, "securitytrails_txt"),
            domain,
            assetType: "txt",
            name: txt.length > 80 ? txt.slice(0, 80) + "..." : txt,
            source: "securitytrails",
            observedAt: now,
            tags: [
              "dns_txt_record",
              ...(txt.includes("v=spf") ? ["spf"] : []),
              ...(txt.includes("v=DMARC") ? ["dmarc"] : []),
              ...(txt.includes("google-site-verification") ? ["google_verified"] : []),
              ...(txt.includes("MS=") ? ["microsoft_verified"] : []),
            ],
            evidence: { record_type: "TXT", value: txt },
            attribution: {
              provider: "SecurityTrails (DNS Intelligence)",
              url: `https://securitytrails.com/domain/${domain}/dns`,
              method: `SecurityTrails Domain Details API — TXT record for ${domain}`,
              verifyUrl: `https://securitytrails.com/domain/${domain}/dns`,
            },
          });
        }
      }
    } catch (err: any) {
      if (err.message === "RATE_LIMITED") { rateLimited = true; errors.push("SecurityTrails rate limit exceeded on domain details endpoint"); }
      else errors.push(`SecurityTrails domain details error: ${err.message}`);
    }

    return { connector: "securitytrails", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
  },
};
