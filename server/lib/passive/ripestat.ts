/**
 * RIPEstat — Regional Internet Registry Data Connector
 * 
 * Queries RIPEstat Data API for network intelligence: announced prefixes,
 * ASN information, and routing data for IPs associated with the domain.
 * 
 * Method: DNS resolution → RIPEstat prefix/ASN lookup for each resolved IP
 * Data Source: RIPE NCC routing data, BGP announcements, RIR databases
 * Attribution: Each observation links to the RIPEstat widget for verification
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import { resolve4 } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const ripestatConnector: PassiveConnector = {
  name: "ripestat",
  description: "Regional Internet Registry data — discovers ASN, announced prefixes, and routing information for domain IPs via RIPE NCC",
  requiresApiKey: false,
  freeUrl: "https://stat.ripe.net",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 20000;

    try {
      // First resolve the domain to IPs
      let ips: string[] = [];
      try {
        ips = await resolve4(domain);
      } catch {
        errors.push(`Could not resolve ${domain} to IP addresses`);
        return { connector: "ripestat", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const now = new Date();

      for (const ip of ips.slice(0, 5)) { // Limit to 5 IPs
        try {
          // Get prefix overview
          const prefixUrl = `https://stat.ripe.net/data/prefix-overview/data.json?resource=${ip}&sourceapp=caldera-dashboard`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);

          let prefixData: any;
          try {
            const res = await fetch(prefixUrl, { signal: controller.signal });
            if (!res.ok) throw new Error(`RIPEstat returned ${res.status}`);
            prefixData = await res.json();
          } finally {
            clearTimeout(timer);
          }

          const asns = prefixData?.data?.asns || [];
          const prefix = prefixData?.data?.resource || "";
          const block = prefixData?.data?.block || {};

          for (const asnInfo of asns) {
            const asn = asnInfo.asn;
            const holder = asnInfo.holder || "";

            observations.push({
              assetId: makeAssetId(domain, `${ip}|asn:${asn}`, "ripestat"),
              domain,
              assetType: "asn",
              name: `AS${asn} (${holder})`,
              ip,
              asn,
              source: "ripestat",
              observedAt: now,
              tags: [
                `asn:${asn}`,
                `prefix:${prefix}`,
                ...(holder ? [`holder:${holder}`] : []),
              ],
              evidence: {
                ip,
                asn,
                holder,
                prefix,
                block_name: block.name,
                block_desc: block.desc,
                is_less_specific: prefixData?.data?.is_less_specific,
              },
              attribution: {
                provider: "RIPEstat (RIPE NCC Data API)",
                url: `https://stat.ripe.net/widget/prefix-overview#w.resource=${ip}`,
                method: `RIPEstat prefix overview — resolved ${domain} to ${ip}, found AS${asn} (${holder}) announcing prefix ${prefix}`,
                verifyUrl: `https://stat.ripe.net/widget/prefix-overview#w.resource=${ip}`,
              },
            });
          }

          // Get network info
          const networkUrl = `https://stat.ripe.net/data/network-info/data.json?resource=${ip}&sourceapp=caldera-dashboard`;
          const controller2 = new AbortController();
          const timer2 = setTimeout(() => controller2.abort(), timeout);

          try {
            const res2 = await fetch(networkUrl, { signal: controller2.signal });
            if (res2.ok) {
              const netData = await res2.json();
              const netPrefix = netData?.data?.prefix || "";
              const netAsns = netData?.data?.asns || [];

              if (netPrefix) {
                observations.push({
                  assetId: makeAssetId(domain, `${ip}|net:${netPrefix}`, "ripestat_net"),
                  domain,
                  assetType: "ip",
                  name: `${ip} (${netPrefix})`,
                  ip,
                  source: "ripestat",
                  observedAt: now,
                  tags: [`prefix:${netPrefix}`, "network_info"],
                  evidence: { ip, prefix: netPrefix, asns: netAsns },
                  attribution: {
                    provider: "RIPEstat (RIPE NCC Data API)",
                    url: `https://stat.ripe.net/widget/network-info#w.resource=${ip}`,
                    method: `RIPEstat network info — ${ip} belongs to prefix ${netPrefix}`,
                    verifyUrl: `https://stat.ripe.net/widget/network-info#w.resource=${ip}`,
                  },
                });
              }
            }
          } finally {
            clearTimeout(timer2);
          }
        } catch (err: any) {
          errors.push(`RIPEstat error for ${ip}: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`RIPEstat error: ${err.message}`);
    }

    return { connector: "ripestat", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
