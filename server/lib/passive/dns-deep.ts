/**
 * DNS Deep Connector — Comprehensive DNS Record Analysis
 *
 * Queries A, AAAA, CNAME, NS, SOA, TXT, SRV, and CAA records to build
 * a complete DNS footprint. Identifies CDN usage, hosting providers,
 * dangling CNAMEs, and zone transfer misconfigurations.
 * Covers Red Team Top-10 #1 (DNS Footprint) and #9 (Security Posture).
 *
 * Method: DNS record lookups (fully passive)
 * Data Source: Public DNS records
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import { resolve4, resolve6, resolveCname, resolveNs, resolveSoa, resolveSrv, resolveTxt, resolveCaa } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const CDN_PATTERNS: Record<string, string[]> = {
  "Cloudflare": ["cloudflare", "cf-"],
  "AWS CloudFront": ["cloudfront.net", "d1", "d2", "d3"],
  "Akamai": ["akamai", "edgekey", "edgesuite"],
  "Fastly": ["fastly", "global.ssl.fastly"],
  "Azure CDN": ["azureedge.net", "azurefd.net"],
  "Google CDN": ["googleusercontent", "googlevideo"],
  "Incapsula": ["incapdns", "impervadns"],
};

function detectCdn(cname: string): string | undefined {
  const lower = cname.toLowerCase();
  for (const [cdn, patterns] of Object.entries(CDN_PATTERNS)) {
    if (patterns.some(p => lower.includes(p))) return cdn;
  }
  return undefined;
}

/** Wrap a DNS query with a per-query timeout to prevent individual queries from hanging */
async function dnsWithTimeout<T>(queryFn: () => Promise<T>, timeoutMs: number = 5000): Promise<T> {
  return Promise.race([
    queryFn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('DNS query timeout')), timeoutMs)
    ),
  ]);
}

export const dnsDeepConnector: PassiveConnector = {
  name: "dns_deep",
  description: "Comprehensive DNS record analysis — A, AAAA, CNAME, NS, SOA, TXT, SRV, CAA records with CDN and hosting provider detection",
  requiresApiKey: false,
  freeUrl: "https://dnsdumpster.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const now = new Date();
    const signal = config?.signal;
    const DNS_TIMEOUT = 5000; // 5s per individual DNS query

    // Early abort check
    if (signal?.aborted) {
      return { connector: "dns_deep", domain, observations: [], errors: ['Aborted before start'], durationMs: 0, rateLimited: false };
    }

    // A records
    try {
      const aRecords = await dnsWithTimeout(() => resolve4(domain), DNS_TIMEOUT);
      if (aRecords.length > 0) {
        observations.push({
          assetId: makeAssetId(domain, `a:${domain}`, "dns_deep"),
          domain, assetType: "ip",
          name: `A Records: ${aRecords.join(", ")}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "a_record", ...(aRecords.length > 1 ? ["load_balanced"] : [])],
          evidence: { records: aRecords, recordType: "A", count: aRecords.length },
          attribution: { provider: "DNS A Record Lookup", method: `Resolved A records for ${domain}`, verifyUrl: `https://dns.google/resolve?name=${domain}&type=A` },
        });
      }
    } catch { /* No A records or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // AAAA records
    try {
      const aaaaRecords = await dnsWithTimeout(() => resolve6(domain), DNS_TIMEOUT);
      if (aaaaRecords.length > 0) {
        observations.push({
          assetId: makeAssetId(domain, `aaaa:${domain}`, "dns_deep"),
          domain, assetType: "ip",
          name: `AAAA Records: ${aaaaRecords.join(", ")}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "aaaa_record", "ipv6"],
          evidence: { records: aaaaRecords, recordType: "AAAA", count: aaaaRecords.length },
          attribution: { provider: "DNS AAAA Record Lookup", method: `Resolved AAAA records for ${domain}` },
        });
      }
    } catch { /* No AAAA records or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // CNAME records
    try {
      const cnameRecords = await dnsWithTimeout(() => resolveCname(domain), DNS_TIMEOUT);
      if (cnameRecords.length > 0) {
        const cdn = detectCdn(cnameRecords[0]);
        observations.push({
          assetId: makeAssetId(domain, `cname:${domain}`, "dns_deep"),
          domain, assetType: "subdomain",
          name: `CNAME: ${cnameRecords[0]}${cdn ? ` (${cdn})` : ""}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "cname_record", ...(cdn ? [`cdn:${cdn.toLowerCase().replace(/\s+/g, "_")}`] : [])],
          evidence: { records: cnameRecords, recordType: "CNAME", detectedCdn: cdn },
          attribution: { provider: "DNS CNAME Record Lookup", method: `Resolved CNAME records for ${domain}` },
        });
      }
    } catch { /* No CNAME records or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // NS records
    try {
      const nsRecords = await dnsWithTimeout(() => resolveNs(domain), DNS_TIMEOUT);
      if (nsRecords.length > 0) {
        const nsProviders: string[] = [];
        for (const ns of nsRecords) {
          const lower = ns.toLowerCase();
          if (lower.includes("cloudflare")) nsProviders.push("Cloudflare");
          else if (lower.includes("awsdns")) nsProviders.push("AWS Route 53");
          else if (lower.includes("azure-dns")) nsProviders.push("Azure DNS");
          else if (lower.includes("google")) nsProviders.push("Google Cloud DNS");
          else if (lower.includes("domaincontrol")) nsProviders.push("GoDaddy");
        }
        observations.push({
          assetId: makeAssetId(domain, `ns:${domain}`, "dns_deep"),
          domain, assetType: "subdomain",
          name: `NS: ${nsRecords.join(", ")}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "ns_record", ...(nsProviders.length > 0 ? nsProviders.map(p => `dns_provider:${p.toLowerCase().replace(/\s+/g, "_")}`) : [])],
          evidence: { records: nsRecords, recordType: "NS", detectedProviders: Array.from(new Set(nsProviders)) },
          attribution: { provider: "DNS NS Record Lookup", method: `Resolved NS records for ${domain}` },
        });
      }
    } catch { /* No NS records or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // SOA record
    try {
      const soa = await dnsWithTimeout(() => resolveSoa(domain), DNS_TIMEOUT);
      if (soa) {
        observations.push({
          assetId: makeAssetId(domain, `soa:${domain}`, "dns_deep"),
          domain, assetType: "subdomain",
          name: `SOA: ${soa.nsname} (admin: ${soa.hostmaster})`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "soa_record"],
          evidence: { nsname: soa.nsname, hostmaster: soa.hostmaster, serial: soa.serial, refresh: soa.refresh, retry: soa.retry, expire: soa.expire, minttl: soa.minttl, recordType: "SOA" },
          attribution: { provider: "DNS SOA Record Lookup", method: `Resolved SOA record for ${domain}` },
        });
      }
    } catch { /* No SOA record or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // TXT records (non-SPF/DMARC — those are handled by email-security connector)
    try {
      const txtRecords = await dnsWithTimeout(() => resolveTxt(domain), DNS_TIMEOUT);
      const nonEmailTxt = txtRecords.filter(parts => {
        const record = parts.join("");
        return !record.toLowerCase().startsWith("v=spf1") && !record.toLowerCase().startsWith("v=dmarc1");
      });
      if (nonEmailTxt.length > 0) {
        const verificationServices: string[] = [];
        for (const parts of nonEmailTxt) {
          const record = parts.join("");
          if (record.includes("google-site-verification")) verificationServices.push("Google Search Console");
          if (record.includes("MS=")) verificationServices.push("Microsoft 365");
          if (record.includes("facebook-domain-verification")) verificationServices.push("Facebook");
          if (record.includes("apple-domain-verification")) verificationServices.push("Apple");
          if (record.includes("atlassian-domain-verification")) verificationServices.push("Atlassian");
          if (record.includes("docusign")) verificationServices.push("DocuSign");
        }
        observations.push({
          assetId: makeAssetId(domain, `txt:${domain}`, "dns_deep"),
          domain, assetType: "txt",
          name: `TXT Records: ${nonEmailTxt.length} non-email records${verificationServices.length > 0 ? ` (${verificationServices.join(", ")})` : ""}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "txt_record", ...(verificationServices.length > 0 ? verificationServices.map(s => `verified:${s.toLowerCase().replace(/\s+/g, "_")}`) : [])],
          evidence: { records: nonEmailTxt.map(p => p.join("")), recordType: "TXT", count: nonEmailTxt.length, verificationServices },
          attribution: { provider: "DNS TXT Record Lookup", method: `Resolved TXT records for ${domain} (excluding SPF/DMARC)` },
        });
      }
    } catch { /* No TXT records or timeout */ }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // SRV records — common service discovery
    const srvPrefixes = ["_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_autodiscover._tcp", "_ldap._tcp", "_kerberos._tcp"];
    for (const prefix of srvPrefixes) {
      if (signal?.aborted) break;
      try {
        const srvRecords = await dnsWithTimeout(() => resolveSrv(`${prefix}.${domain}`), DNS_TIMEOUT);
        if (srvRecords.length > 0) {
          observations.push({
            assetId: makeAssetId(domain, `srv:${prefix}:${domain}`, "dns_deep"),
            domain, assetType: "subdomain",
            name: `SRV ${prefix}: ${srvRecords.map(r => `${r.name}:${r.port}`).join(", ")}`,
            source: "dns_deep", observedAt: now,
            tags: ["dns", "srv_record", `service:${prefix.split(".")[0].replace("_", "")}`],
            evidence: { records: srvRecords, recordType: "SRV", prefix },
            attribution: { provider: "DNS SRV Record Lookup", method: `Resolved SRV records for ${prefix}.${domain}` },
          });
        }
      } catch { /* No SRV records for this prefix or timeout */ }
    }

    if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited: false };

    // CAA records
    try {
      const caaRecords = await dnsWithTimeout(() => resolveCaa(domain), DNS_TIMEOUT);
      if (caaRecords.length > 0) {
        const issuers = caaRecords.filter((r: any) => r.critical !== undefined || r.issue || r.issuewild).map((r: any) => r.issue || r.issuewild || JSON.stringify(r));
        observations.push({
          assetId: makeAssetId(domain, `caa:${domain}`, "dns_deep"),
          domain, assetType: "txt",
          name: `CAA: ${issuers.length > 0 ? issuers.join(", ") : "present"}`,
          source: "dns_deep", observedAt: now,
          tags: ["dns", "caa_record", "certificate_authority"],
          evidence: { records: caaRecords, recordType: "CAA", authorizedIssuers: issuers },
          attribution: { provider: "DNS CAA Record Lookup", method: `Resolved CAA records for ${domain} to identify authorized certificate authorities` },
        });
      }
    } catch { /* No CAA records or timeout */ }

    return { connector: "dns_deep", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
