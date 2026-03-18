/**
 * CIRCL Passive DNS Connector — Free, No API Key
 * 
 * Provides historical DNS resolution records:
 * - Past IP addresses for a domain
 * - DNS record changes over time
 * - Infrastructure migration patterns
 * 
 * API docs: https://www.circl.lu/services/passive-dns/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const circlPdnsConnector: PassiveConnector = {
  name: 'circl_pdns',
  description: 'CIRCL Passive DNS — free historical DNS resolution records and infrastructure changes',
  requiresApiKey: false,
  freeUrl: "https://www.circl.lu/services/passive-dns/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      const resp = await fetch(`https://www.circl.lu/pdns/query/${encodeURIComponent(domain)}`, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)',
        },
        signal: AbortSignal.timeout(config?.timeout || 15000),
      });

      if (resp.status === 429) {
        rateLimited = true;
        errors.push("Rate limited by CIRCL Passive DNS API");
      } else if (resp.ok) {
        const text = await resp.text();
        const records = text
          .split('\n')
          .filter(line => line.trim())
          .map(line => {
            try { return JSON.parse(line); } catch { return null; }
          })
          .filter(Boolean);

        if (records.length > 0) {
          const uniqueIps = new Set<string>(records.filter(r => r.rrtype === 'A' || r.rrtype === 'AAAA').map(r => r.rdata));

          for (const ip of uniqueIps) {
            observations.push({
              assetId: makeAssetId(domain, ip, 'circl_pdns'),
              domain,
              assetType: 'ip',
              name: ip,
              source: 'circl_pdns',
              observedAt: now,
              tags: ['circl_pdns', 'passive_dns'],
              evidence: {},
              attribution: {
                provider: 'CIRCL',
                url: 'https://www.circl.lu/services/passive-dns/',
                method: 'api',
              },
            });
          }

          const cnames = records.filter(r => r.rrtype === 'CNAME');
          for (const cname of cnames) {
            observations.push({
              assetId: makeAssetId(domain, cname.rdata, 'circl_pdns'),
              domain,
              assetType: 'cname',
              name: cname.rdata,
              source: 'circl_pdns',
              observedAt: now,
              firstSeen: cname.time_first ? new Date(cname.time_first * 1000) : undefined,
              lastSeen: cname.time_last ? new Date(cname.time_last * 1000) : undefined,
              tags: ['circl_pdns', 'passive_dns'],
              evidence: {
                count: cname.count,
              },
              attribution: {
                provider: 'CIRCL',
                url: 'https://www.circl.lu/services/passive-dns/',
                method: 'api',
              },
            });
          }

          const mxRecords = records.filter(r => r.rrtype === 'MX');
          for (const mx of mxRecords) {
            observations.push({
              assetId: makeAssetId(domain, mx.rdata, 'circl_pdns'),
              domain,
              assetType: 'mx',
              name: mx.rdata,
              source: 'circl_pdns',
              observedAt: now,
              firstSeen: mx.time_first ? new Date(mx.time_first * 1000) : undefined,
              lastSeen: mx.time_last ? new Date(mx.time_last * 1000) : undefined,
              tags: ['circl_pdns', 'passive_dns'],
              evidence: {
                count: mx.count,
              },
              attribution: {
                provider: 'CIRCL',
                url: 'https://www.circl.lu/services/passive-dns/',
                method: 'api',
              },
            });
          }
        }
      } else {
        errors.push(`CIRCL Passive DNS API returned status ${resp.status}`);
      }
    } catch (err: any) {
      errors.push(err.name === 'TimeoutError' ? 'CIRCL Passive DNS API request timed out' : err.message);
    }

    return {
      connector: 'circl_pdns',
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
