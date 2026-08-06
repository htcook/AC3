/**
 * PassiveTotal (RiskIQ) — Passive DNS & Threat Intelligence Connector
 *
 * Queries the PassiveTotal API for passive DNS and threat data:
 * - Passive DNS resolution history
 * - WHOIS records
 * - SSL certificate history
 * - Host attribute pairs (trackers, components)
 * - Malware and OSINT associations
 *
 * Method: REST API v2 with HTTP Basic Auth (email + API key)
 * Data Source: RiskIQ/Microsoft's internet intelligence platform
 * Free tier: 15 queries/day (community edition)
 * Paid tier: Enterprise access via RiskIQ
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const passivetotalConnector: PassiveConnector = {
  name: "passivetotal",
  description: "PassiveTotal — passive DNS history, SSL certificate history, host attributes, and threat associations",
  requiresApiKey: true,
  freeUrl: "https://community.riskiq.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "passivetotal", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    // API key format: email:apikey
    const [email, key] = apiKey.includes(":") ? apiKey.split(":", 2) : ["", apiKey];
    if (!email || !key) {
      return { connector: "passivetotal", domain, observations: [], errors: ["API key must be in format email:apikey"], durationMs: 0, rateLimited: false };
    }

    const authHeader = "Basic " + Buffer.from(`${email}:${key}`).toString("base64");
    const headers = { "Authorization": authHeader, "Content-Type": "application/json" };

    try {
      // 1. Passive DNS resolutions
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch("https://api.passivetotal.org/v2/dns/passive", {
          method: "POST",
          headers,
          body: JSON.stringify({ query: domain }),
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (res.status === 429) {
          rateLimited = true;
          errors.push("Rate limited");
        } else if (res.ok) {
          const data = await res.json();
          const now = new Date();

          if (data.results && Array.isArray(data.results)) {
            for (const rec of data.results.slice(0, 100)) {
              const resolveValue = rec.resolve;
              const resolveType = rec.recordType || "A";
              if (!resolveValue) continue;

              const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(resolveValue);

              observations.push({
                assetId: makeAssetId(domain, `pdns-${resolveType}-${resolveValue}`, "passivetotal"),
                domain,
                assetType: isIP ? "ip" : "subdomain",
                name: rec.query || domain,
                ip: isIP ? resolveValue : undefined,
                source: "passivetotal",
                observedAt: now,
                firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : undefined,
                lastSeen: rec.lastSeen ? new Date(rec.lastSeen) : undefined,
                tags: [
                  "passive-dns",
                  resolveType.toLowerCase(),
                  "historical-resolution",
                  rec.collected ? "collected" : "",
                ].filter(Boolean),
                evidence: {
                  resolveValue,
                  recordType: resolveType,
                  firstSeen: rec.firstSeen,
                  lastSeen: rec.lastSeen,
                  collected: rec.collected,
                  source: rec.source?.join(", "),
                },
                attribution: {
                  provider: "PassiveTotal",
                  url: `https://community.riskiq.com/search/${domain}/resolutions`,
                  method: "PassiveTotal passive DNS lookup",
                },
              });
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("PassiveTotal DNS timed out");
      }

      // 2. WHOIS lookup
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller2 = new AbortController();
        const timer2 = setTimeout(() => controller2.abort(), timeout);
        try {
          const res = await fetch("https://api.passivetotal.org/v2/whois", {
            method: "POST",
            headers,
            body: JSON.stringify({ query: domain }),
            signal: controller2.signal,
          });
          clearTimeout(timer2);

          if (res.status === 429) {
            rateLimited = true;
          } else if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.domain) {
              observations.push({
                assetId: makeAssetId(domain, `whois-${domain}`, "passivetotal"),
                domain,
                assetType: "subdomain",
                name: domain,
                source: "passivetotal",
                observedAt: now,
                firstSeen: data.registered ? new Date(data.registered) : undefined,
                tags: ["whois", "registrar", "passivetotal-whois"],
                evidence: {
                  registrar: data.registrar,
                  organization: data.organization,
                  registered: data.registered,
                  expiresAt: data.expiresAt,
                  lastLoadedAt: data.lastLoadedAt,
                  nameServers: data.nameServers,
                  registrant: data.registrant,
                  admin: data.admin,
                  tech: data.tech,
                  contactEmail: data.contactEmail,
                  whoisServer: data.whoisServer,
                },
                attribution: {
                  provider: "PassiveTotal",
                  url: `https://community.riskiq.com/search/${domain}/whois`,
                  method: "PassiveTotal WHOIS lookup",
                },
              });
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`PassiveTotal WHOIS: ${err.message}`);
        }
      }

      // 3. SSL certificate history
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller3 = new AbortController();
        const timer3 = setTimeout(() => controller3.abort(), timeout);
        try {
          const res = await fetch("https://api.passivetotal.org/v2/ssl-certificate/search", {
            method: "POST",
            headers,
            body: JSON.stringify({ query: domain, field: "subjectCommonName" }),
            signal: controller3.signal,
          });
          clearTimeout(timer3);

          if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.results && Array.isArray(data.results)) {
              for (const cert of data.results.slice(0, 30)) {
                observations.push({
                  assetId: makeAssetId(domain, `ssl-${cert.sha1 || cert.serialNumber || ""}`, "passivetotal"),
                  domain,
                  assetType: "certificate",
                  name: cert.subjectCommonName || domain,
                  source: "passivetotal",
                  observedAt: now,
                  firstSeen: cert.notBefore ? new Date(cert.notBefore) : undefined,
                  tags: [
                    "ssl-certificate",
                    "certificate-history",
                    cert.expired ? "expired" : "valid",
                    cert.selfSigned ? "self-signed" : "",
                  ].filter(Boolean),
                  evidence: {
                    sha1: cert.sha1,
                    serialNumber: cert.serialNumber,
                    issuerCommonName: cert.issuerCommonName,
                    issuerOrganization: cert.issuerOrganizationName,
                    subjectCommonName: cert.subjectCommonName,
                    subjectOrganization: cert.subjectOrganizationName,
                    notBefore: cert.notBefore,
                    notAfter: cert.notAfter,
                    subjectAlternativeNames: cert.subjectAlternativeNames?.slice(0, 20),
                    sslVersion: cert.sslVersion,
                    selfSigned: cert.selfSigned,
                    expired: cert.expired,
                  },
                  attribution: {
                    provider: "PassiveTotal",
                    url: `https://community.riskiq.com/search/${domain}/certificates`,
                    method: "PassiveTotal SSL certificate history",
                  },
                });
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`PassiveTotal SSL: ${err.message}`);
        }
      }

      // 4. Host attributes (trackers, components)
      if (!rateLimited) {
        await new Promise(r => setTimeout(r, 500));
        const controller4 = new AbortController();
        const timer4 = setTimeout(() => controller4.abort(), timeout);
        try {
          const res = await fetch("https://api.passivetotal.org/v2/host-attributes/components", {
            method: "POST",
            headers,
            body: JSON.stringify({ query: domain }),
            signal: controller4.signal,
          });
          clearTimeout(timer4);

          if (res.ok) {
            const data = await res.json();
            const now = new Date();

            if (data.results && Array.isArray(data.results)) {
              for (const comp of data.results.slice(0, 50)) {
                observations.push({
                  assetId: makeAssetId(domain, `comp-${comp.category}-${comp.label}`, "passivetotal"),
                  domain,
                  assetType: "url",
                  name: comp.hostname || domain,
                  source: "passivetotal",
                  observedAt: now,
                  firstSeen: comp.firstSeen ? new Date(comp.firstSeen) : undefined,
                  lastSeen: comp.lastSeen ? new Date(comp.lastSeen) : undefined,
                  tags: ["host-component", "technology-detection", comp.category?.toLowerCase() || ""],
                  evidence: {
                    category: comp.category,
                    label: comp.label,
                    hostname: comp.hostname,
                    firstSeen: comp.firstSeen,
                    lastSeen: comp.lastSeen,
                  },
                  attribution: {
                    provider: "PassiveTotal",
                    url: `https://community.riskiq.com/search/${domain}/components`,
                    method: "PassiveTotal host component detection",
                  },
                });
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`PassiveTotal components: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`PassiveTotal error: ${err.message}`);
    }

    return {
      connector: "passivetotal",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
