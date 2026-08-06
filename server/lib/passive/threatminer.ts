/**
 * ThreatMiner Connector — Free, No API Key
 * 
 * Aggregates threat intelligence around domains and IPs:
 * - WHOIS records, passive DNS, subdomains
 * - Related malware samples and APT reports
 * - URI patterns and SSL certificates
 * 
 * API docs: https://www.threatminer.org/api.php
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const BASE = 'https://api.threatminer.org/v2';
const PROVIDER = "ThreatMiner";

async function tmFetch(endpoint: string): Promise<any> {
  const resp = await fetch(`${BASE}${endpoint}`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
    signal: AbortSignal.timeout(12000),
  });
  if (resp.status === 429) {
    // Rate limited
    throw new Error("RATE_LIMITED");
  }
  if (!resp.ok) {
    throw new Error(`ThreatMiner API returned status ${resp.status}`);
  }
  const data = await resp.json();
  if (data.status_code !== '200') {
    return null;
  }
  return data.results;
}

export const threatminerConnector: PassiveConnector = {
  name: "threatminer",
  description: 'ThreatMiner — free threat intelligence (passive DNS, subdomains, malware, APT reports)',
  requiresApiKey: false,
  freeUrl: "https://www.threatminer.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const start = Date.now();
    const now = new Date();
    let rateLimited = false;

    const endpoints = [
      { rt: 1, name: "WHOIS" },
      { rt: 2, name: "Passive DNS" },
      { rt: 4, name: "Malware Samples" },
      { rt: 5, name: "Subdomains" },
      { rt: 6, name: "URIs" },
      { rt: 7, name: "APT Reports" },
    ];

    const promises = endpoints.map(ep => tmFetch(`/domain.php?q=${domain}&rt=${ep.rt}`));
    const results = await Promise.allSettled(promises);

    results.forEach((result, index) => {
      const endpointName = endpoints[index].name;

      if (result.status === 'rejected') {
        if (result.reason?.message === "RATE_LIMITED") {
          rateLimited = true;
        }
        errors.push(`Failed to fetch ${endpointName}: ${result.reason?.message || "Unknown error"}`);
        return;
      }

      const data = result.value;
      if (!data || data.length === 0) {
        return;
      }

      try {
        switch (endpoints[index].rt) {
          case 1: // WHOIS
            observations.push({
              assetId: makeAssetId(domain, `WHOIS for ${domain}`, "threatminer"),
              domain,
              assetType: "breach",
              name: `WHOIS data for ${domain}`,
              source: "threatminer",
              observedAt: now,
              tags: ['threatminer', 'whois'],
              evidence: { 
                severity: 0, 
                confidence: 70,
                whois: data[0],
              },
              attribution: {
                provider: PROVIDER,
                url: `https://www.threatminer.org/whois.php?q=${domain}`,
                method: "api",
              },
            });
            break;

          case 2: // Passive DNS
            observations.push({
              assetId: makeAssetId(domain, `Passive DNS for ${domain}`, "threatminer"),
              domain,
              assetType: "breach",
              name: `Passive DNS for ${domain}`,
              source: "threatminer",
              observedAt: now,
              tags: ['threatminer', 'passive_dns'],
              evidence: {
                severity: 0,
                confidence: 75,
                records: data.slice(0, 50),
                total: data.length,
              },
              attribution: {
                provider: PROVIDER,
                url: `https://www.threatminer.org/passive-dns.php?q=${domain}`,
                method: "api",
              },
            });
            break;

          case 4: // Related malware samples
            observations.push({
              assetId: makeAssetId(domain, `Malware samples for ${domain}`, "threatminer"),
              domain,
              assetType: "breach",
              name: `Malware samples associated with ${domain}`,
              source: "threatminer",
              observedAt: now,
              tags: ['threatminer', 'malware', 'threat_intel'],
              evidence: {
                severity: 7,
                confidence: 65,
                samples: data.slice(0, 20),
                total: data.length,
              },
              attribution: {
                provider: PROVIDER,
                url: `https://www.threatminer.org/malware.php?q=${domain}`,
                method: "api",
              },
            });
            break;

          case 5: // Subdomains
            for (const sub of data.slice(0, 30)) {
              observations.push({
                assetId: makeAssetId(domain, sub, "threatminer"),
                domain,
                assetType: "subdomain",
                name: sub,
                source: "threatminer",
                observedAt: now,
                tags: ['threatminer', 'subdomain'],
                evidence: {
                  severity: 0,
                  confidence: 70,
                },
                attribution: {
                  provider: PROVIDER,
                  url: `https://www.threatminer.org/host.php?q=${domain}`,
                  method: "api",
                },
              });
            }
            break;

          case 6: // URIs
            observations.push({
              assetId: makeAssetId(domain, `URI patterns for ${domain}`, "threatminer"),
              domain,
              assetType: "breach",
              name: `URI patterns for ${domain}`,
              source: "threatminer",
              observedAt: now,
              tags: ['threatminer', 'uri_pattern'],
              evidence: {
                severity: 3,
                confidence: 60,
                uris: data.slice(0, 30),
                total: data.length,
              },
              attribution: {
                provider: PROVIDER,
                url: `https://www.threatminer.org/uri.php?q=${domain}`,
                method: "api",
              },
            });
            break;

          case 7: // APT reports
            observations.push({
              assetId: makeAssetId(domain, `APT reports for ${domain}`, "threatminer"),
              domain,
              assetType: "breach",
              name: `APT reports mentioning ${domain}`,
              source: "threatminer",
              observedAt: now,
              tags: ['threatminer', 'apt_report', 'threat_intel'],
              evidence: {
                severity: 8,
                confidence: 75,
                reports: data.slice(0, 10),
                total: data.length,
              },
              attribution: {
                provider: PROVIDER,
                url: `https://www.threatminer.org/report.php?q=${domain}`,
                method: "api",
              },
            });
            break;
        }
      } catch (e: any) {
        errors.push(`Failed to process ${endpointName}: ${e.message}`);
      }
    });

    return {
      connector: 'threatminer',
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
