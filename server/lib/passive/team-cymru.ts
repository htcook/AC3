/**
 * Team Cymru Connector — Free, No API Key
 * 
 * Performs authoritative IP-to-ASN mapping via DNS queries to
 * Team Cymru's IP-to-ASN mapping service. Provides BGP origin,
 * ASN, network name, country, and allocation date — the gold
 * standard for IP attribution.
 * 
 * Service docs: https://www.team-cymru.com/ip-asn-mapping
 * DNS method: reverse IP octets + .origin.asn.cymru.com TXT
 */
import { createHash } from "crypto";
import { resolve as dnsResolve } from "dns";
import { promisify } from "util";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

const resolveTxt = promisify(dnsResolve) as unknown as (hostname: string, rrtype: "TXT") => Promise<string[][]>;

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

/** Wrap a DNS query with a per-query timeout */
async function dnsWithTimeout<T>(queryFn: () => Promise<T>, timeoutMs: number = 5000): Promise<T> {
  return Promise.race([
    queryFn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('DNS query timeout')), timeoutMs)
    ),
  ]);
}

/**
 * Resolve domain to IP addresses using DNS
 */
async function resolveToIPs(domain: string): Promise<string[]> {
  const resolveA = promisify(dnsResolve) as unknown as (hostname: string, rrtype: "A") => Promise<string[]>;
  try {
    const ips = await dnsWithTimeout(() => resolveA(domain, "A"), 5000);
    return ips || [];
  } catch {
    return [];
  }
}

/**
 * Query Team Cymru DNS for IP-to-ASN mapping
 */
async function queryOriginASN(ip: string): Promise<{ asn: string; cidr: string; cc: string; registry: string; allocated: string } | null> {
  try {
    const reversed = ip.split(".").reverse().join(".");
    const hostname = `${reversed}.origin.asn.cymru.com`;
    const records = await dnsWithTimeout(() => resolveTxt(hostname, "TXT"), 5000);
    
    if (records && records.length > 0) {
      const txt = records[0].join("").trim();
      const parts = txt.split("|").map((s: string) => s.trim());
      return {
        asn: parts[0] || "",
        cidr: parts[1] || "",
        cc: parts[2] || "",
        registry: parts[3] || "",
        allocated: parts[4] || "",
      };
    }
  } catch {
    // DNS query failed or timeout
  }
  return null;
}

/**
 * Query Team Cymru for ASN details (name, country)
 */
async function queryASNDetails(asn: string): Promise<{ name: string; cc: string; registry: string; allocated: string } | null> {
  try {
    const asnNum = asn.replace(/^AS/i, "").trim();
    const hostname = `AS${asnNum}.asn.cymru.com`;
    const records = await dnsWithTimeout(() => resolveTxt(hostname, "TXT"), 5000);
    
    if (records && records.length > 0) {
      const txt = records[0].join("").trim();
      const parts = txt.split("|").map((s: string) => s.trim());
      return {
        cc: parts[1] || "",
        registry: parts[2] || "",
        allocated: parts[3] || "",
        name: parts[4] || "",
      };
    }
  } catch {
    // DNS query failed or timeout
  }
  return null;
}

export const teamCymruConnector: PassiveConnector = {
  name: "team_cymru",
  description: "Team Cymru — authoritative IP-to-ASN mapping via DNS, BGP origin, network attribution",
  requiresApiKey: false,
  freeUrl: "https://www.team-cymru.com/ip-asn-mapping",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();
    const signal = config?.signal;

    // Early abort check
    if (signal?.aborted) {
      return { connector: "team_cymru", domain, observations: [], errors: ['Aborted before start'], durationMs: 0, rateLimited: false };
    }

    try {
      // Resolve domain to IPs
      const ips = await resolveToIPs(domain);

      if (ips.length === 0) {
        observations.push({
          assetId: makeAssetId(domain, `Team Cymru: no IPs for ${domain}`, "team_cymru"),
          domain,
          assetType: "info",
          name: `Team Cymru: Could not resolve ${domain} to IP addresses`,
          source: "team_cymru",
          observedAt: now,
          tags: ["team_cymru", "asn_mapping", "dns_failure"],
          evidence: {
            severity: 0,
            status: "no_ips",
            value: `DNS resolution failed for ${domain} — cannot perform IP-to-ASN mapping`,
          },
          attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com", method: "dns" },
        });
        return { connector: "team_cymru", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Query each IP for ASN mapping (limit to 10 IPs)
      const seenASNs = new Set<string>();
      const asnDetails: Map<string, { name: string; cc: string; registry: string; allocated: string }> = new Map();

      for (const ip of ips.slice(0, 10)) {
        if (signal?.aborted) {
          errors.push('Aborted mid-execution');
          break;
        }

        const origin = await queryOriginASN(ip);
        if (!origin) continue;

        // Get ASN details if we haven't seen this ASN yet
        const asnNum = origin.asn.split(" ")[0]; // Handle multi-origin ASNs
        if (asnNum && !seenASNs.has(asnNum)) {
          seenASNs.add(asnNum);
          if (!signal?.aborted) {
            const details = await queryASNDetails(asnNum);
            if (details) {
              asnDetails.set(asnNum, details);
            }
          }
        }

        const asnName = asnDetails.get(asnNum)?.name || "unknown";
        const name = `Team Cymru: ${ip} → AS${asnNum} (${asnName})`;

        observations.push({
          assetId: makeAssetId(domain, name, "team_cymru"),
          domain,
          assetType: "info",
          name,
          source: "team_cymru",
          observedAt: now,
          tags: [
            "team_cymru", "asn_mapping", "bgp_origin", "ip_attribution",
            `asn:${asnNum}`,
            `cc:${origin.cc}`,
            `registry:${origin.registry}`,
          ],
          evidence: {
            severity: 1,
            confidence: 95,
            value: `${ip} → AS${asnNum} (${asnName}) | ${origin.cidr} | ${origin.cc} | ${origin.registry} | Allocated: ${origin.allocated}`,
            ip,
            asn: asnNum,
            asn_name: asnName,
            cidr: origin.cidr,
            country_code: origin.cc,
            registry: origin.registry,
            allocated: origin.allocated,
          },
          attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com/ip-asn-mapping", method: "dns" },
        });
      }

      // Summary observation with all unique ASNs
      if (seenASNs.size > 0 && !signal?.aborted) {
        const asnSummary = [...seenASNs].map(asn => {
          const details = asnDetails.get(asn);
          return `AS${asn} (${details?.name || 'unknown'}, ${details?.cc || '??'})`;
        }).join("; ");

        observations.push({
          assetId: makeAssetId(domain, `Team Cymru summary: ${domain}`, "team_cymru"),
          domain,
          assetType: "info",
          name: `Team Cymru: ${domain} hosted across ${seenASNs.size} ASN(s)`,
          source: "team_cymru",
          observedAt: now,
          tags: ["team_cymru", "asn_mapping", "summary", "network_topology"],
          evidence: {
            severity: 1,
            confidence: 95,
            value: `${ips.length} IP(s) across ${seenASNs.size} ASN(s): ${asnSummary}`,
            total_ips: ips.length,
            unique_asns: seenASNs.size,
            asn_list: [...seenASNs].map(asn => ({
              asn,
              name: asnDetails.get(asn)?.name || "unknown",
              cc: asnDetails.get(asn)?.cc || "unknown",
              registry: asnDetails.get(asn)?.registry || "unknown",
            })),
          },
          attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com/ip-asn-mapping", method: "dns" },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("timeout")) {
        errors.push("Team Cymru DNS timeout");
      } else {
        errors.push(err.message || "Unknown error during Team Cymru lookup");
      }
    }

    return {
      connector: "team_cymru",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
