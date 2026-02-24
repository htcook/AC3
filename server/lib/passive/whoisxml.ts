/**
 * WhoisXML API — WHOIS, DNS, & Reverse Lookup Connector
 *
 * Queries WhoisXML API for comprehensive domain intelligence:
 * - Full WHOIS records with historical data
 * - Reverse WHOIS (find all domains by registrant)
 * - DNS lookup with all record types
 * - Subdomain enumeration
 *
 * Method: REST API with apiKey parameter
 * Data Source: WhoisXML's proprietary WHOIS/DNS database (13B+ records)
 * Paid: From $19/month (500 queries) — free trial available
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

async function wxFetch(url: string, timeout: number): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`WhoisXML returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export const whoisxmlConnector: PassiveConnector = {
  name: "whoisxml",
  description: "WhoisXML API — comprehensive WHOIS records, reverse WHOIS, DNS lookup, subdomain enumeration",
  requiresApiKey: true,
  freeUrl: "https://www.whoisxmlapi.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "whoisxml", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // 1. WHOIS lookup
      const whois = await wxFetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
        timeout
      );
      if (whois?.WhoisRecord) {
        const rec = whois.WhoisRecord;
        const now = new Date();
        observations.push({
          assetId: makeAssetId(domain, `whois-${domain}`, "whoisxml"),
          domain,
          assetType: "subdomain",
          name: domain,
          source: "whoisxml",
          observedAt: now,
          firstSeen: rec.createdDate ? new Date(rec.createdDate) : undefined,
          tags: ["whois", "registrar", "domain-registration"],
          evidence: {
            registrarName: rec.registrarName,
            registrarIANAID: rec.registrarIANAID,
            createdDate: rec.createdDate,
            updatedDate: rec.updatedDate,
            expiresDate: rec.expiresDate,
            status: rec.status,
            nameServers: rec.nameServers?.hostNames,
            registrant: rec.registrant ? {
              organization: rec.registrant.organization,
              state: rec.registrant.state,
              country: rec.registrant.country,
              countryCode: rec.registrant.countryCode,
            } : undefined,
            technicalContact: rec.technicalContact ? {
              organization: rec.technicalContact.organization,
              country: rec.technicalContact.country,
            } : undefined,
            domainAge: rec.estimatedDomainAge,
            contactEmail: rec.contactEmail,
          },
          attribution: {
            provider: "WhoisXML API",
            url: `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}`,
            method: "WhoisXML WHOIS record lookup",
          },
        });
      }

      // 2. Subdomain enumeration
      const subdomains = await wxFetch(
        `https://subdomains.whoisxmlapi.com/api/v1?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
        timeout
      );
      if (subdomains?.result?.records) {
        const now = new Date();
        for (const rec of subdomains.result.records.slice(0, 200)) {
          const sub = rec.domain || rec.value;
          if (!sub) continue;
          observations.push({
            assetId: makeAssetId(domain, sub, "whoisxml"),
            domain,
            assetType: "subdomain",
            name: sub,
            source: "whoisxml",
            observedAt: now,
            firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : undefined,
            lastSeen: rec.lastSeen ? new Date(rec.lastSeen) : undefined,
            tags: ["subdomain", "whoisxml-enum"],
            evidence: { firstSeen: rec.firstSeen, lastSeen: rec.lastSeen },
            attribution: {
              provider: "WhoisXML API",
              url: `https://subdomains.whoisxmlapi.com/api/v1?domainName=${domain}`,
              method: "WhoisXML subdomain enumeration",
            },
          });
        }
      }

      // 3. DNS lookup (all record types)
      const dns = await wxFetch(
        `https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=${apiKey}&domainName=${domain}&type=_all&outputFormat=JSON`,
        timeout
      );
      if (dns?.DNSData?.dnsRecords) {
        const now = new Date();
        for (const rec of dns.DNSData.dnsRecords) {
          const recType = rec.dnsType || rec.type;
          const value = rec.address || rec.target || rec.strings?.join("; ") || rec.name;
          if (!value) continue;

          let assetType: "ip" | "mx" | "ns" | "txt" | "cname" | "subdomain" = "subdomain";
          if (recType === "A" || recType === "AAAA") assetType = "ip";
          else if (recType === "MX") assetType = "mx";
          else if (recType === "NS") assetType = "ns";
          else if (recType === "TXT") assetType = "txt";
          else if (recType === "CNAME") assetType = "cname";

          observations.push({
            assetId: makeAssetId(domain, `dns-${recType}-${value}`, "whoisxml"),
            domain,
            assetType,
            name: rec.name || domain,
            ip: (recType === "A" || recType === "AAAA") ? value : undefined,
            source: "whoisxml",
            observedAt: now,
            tags: ["dns", recType.toLowerCase()],
            evidence: { type: recType, value, ttl: rec.ttl, priority: rec.priority },
            attribution: {
              provider: "WhoisXML API",
              url: `https://dns-lookup-api.whoisxmlapi.com`,
              method: `WhoisXML DNS ${recType} record lookup`,
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`WhoisXML error: ${err.message}`);
    }

    return {
      connector: "whoisxml",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
