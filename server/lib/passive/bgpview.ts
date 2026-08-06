/**
 * BGPView Connector — Free, No API Key
 * 
 * Maps network infrastructure: ASN ownership, IP prefixes,
 * upstream providers, peer relationships.
 * Uses parallel fetches for speed.
 * 
 * API docs: https://bgpview.docs.apiary.io/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const BASE = 'https://api.bgpview.io';

async function bgpFetch(path: string): Promise<any> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
    signal: AbortSignal.timeout(10000),
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.status === 'ok' ? data.data : null;
}

async function resolveDomain(domain: string): Promise<string[]> {
    try {
        const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
            headers: { 'accept': 'application/dns-json' },
        });
        if (!resp.ok) return [];
        const data = await resp.json();
        return data.Answer?.map((a: any) => a.data) || [];
    } catch {
        return [];
    }
}

export const bgpviewConnector: PassiveConnector = {
  name: "bgpview",
  description: 'BGPView — free ASN lookup, IP prefix ownership, network peers, upstream providers',
  requiresApiKey: false,
  freeUrl: "https://bgpview.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const now = new Date();
    const source = "bgpview";
    let rateLimited = false;

    try {
      // Step 1: Resolve domain to IP
      const ips = await resolveDomain(domain);
      if (ips.length === 0) {
        return { connector: source, domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Step 2: Parallel IP prefix lookups for all resolved IPs
      const prefixResults = await Promise.allSettled(
        ips.slice(0, 3).map(ip => bgpFetch(`/ip/${ip}`))
      );

      const seenAsns = new Set<number>();

      for (let i = 0; i < prefixResults.length; i++) {
        const result = prefixResults[i];
        if (result.status !== 'fulfilled' || !result.value) continue;
        const data = result.value;
        const ip = ips[i];

        if (data.prefixes && data.prefixes.length > 0) {
          for (const pfx of data.prefixes) {
            const name = `IP prefix ${pfx.prefix} for ${ip}`;
            observations.push({
              assetId: makeAssetId(domain, name, source),
              domain,
              assetType: 'ip',
              name,
              ip,
              asn: pfx.asn?.asn,
              source,
              observedAt: now,
              tags: ['bgpview', 'ip_prefix', 'network'],
              evidence: {
                severity: 0,
                confidence: 85,
                prefix: pfx.prefix,
                asn_name: pfx.asn?.name,
                asn_description: pfx.asn?.description,
                country: pfx.asn?.country_code,
              },
              attribution: {
                provider: 'BGPView',
                url: `https://bgpview.io/ip/${ip}`,
                method: 'api',
              },
            });
            if (pfx.asn?.asn) seenAsns.add(pfx.asn.asn);
          }
        }
      }

      // Step 3: Parallel ASN detail lookups (peers + upstreams)
      const asnArray = Array.from(seenAsns).slice(0, 3);
      const [asnDetails, asnPeers, asnUpstreams] = await Promise.all([
        Promise.allSettled(asnArray.map(asn => bgpFetch(`/asn/${asn}`))),
        Promise.allSettled(asnArray.map(asn => bgpFetch(`/asn/${asn}/peers`))),
        Promise.allSettled(asnArray.map(asn => bgpFetch(`/asn/${asn}/upstreams`))),
      ]);

      for (let i = 0; i < asnArray.length; i++) {
        const asn = asnArray[i];

        // ASN details
        const detail = asnDetails[i];
        if (detail.status === 'fulfilled' && detail.value) {
          const d = detail.value;
          const name = `AS${asn} — ${d.name || 'Unknown'}`;
          observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'asn',
            name,
            asn,
            source,
            observedAt: now,
            tags: ['bgpview', 'asn_detail', 'network'],
            evidence: {
                severity: 0,
                confidence: 90,
                description: d.description_full || d.description_short,
                country: d.country_code,
                website: d.website,
                email_contacts: d.email_contacts,
                abuse_contacts: d.abuse_contacts,
                owner_address: d.owner_address,
                rir: d.rir_allocation?.rir_name,
                date_allocated: d.rir_allocation?.date_allocated,
            },
            attribution: {
                provider: 'BGPView',
                url: `https://bgpview.io/asn/${asn}`,
                method: 'api',
            },
          });
        }

        // Peers
        const peers = asnPeers[i];
        if (peers.status === 'fulfilled' && peers.value) {
          const peerList = [...(peers.value.ipv4_peers || []), ...(peers.value.ipv6_peers || [])];
          if (peerList.length > 0) {
            const name = `AS${asn} network peers`;
            observations.push({
              assetId: makeAssetId(domain, name, source),
              domain,
              assetType: 'breach',
              name,
              source,
              observedAt: now,
              tags: ['bgpview', 'network_peers'],
              evidence: {
                severity: 0,
                confidence: 80,
                asn,
                peer_count: peerList.length,
                peers: peerList.slice(0, 20).map((p: any) => ({ asn: p.asn, name: p.name, description: p.description, country: p.country_code })),
              },
              attribution: {
                provider: 'BGPView',
                url: `https://bgpview.io/asn/${asn}/peers`,
                method: 'api',
              },
            });
          }
        }

        // Upstreams
        const ups = asnUpstreams[i];
        if (ups.status === 'fulfilled' && ups.value) {
          const upList = [...(ups.value.ipv4_upstreams || []), ...(ups.value.ipv6_upstreams || [])];
          if (upList.length > 0) {
            const name = `AS${asn} upstream providers`;
            observations.push({
              assetId: makeAssetId(domain, name, source),
              domain,
              assetType: 'breach',
              name,
              source,
              observedAt: now,
              tags: ['bgpview', 'upstream_providers'],
              evidence: {
                severity: 0,
                confidence: 80,
                asn,
                upstream_count: upList.length,
                upstreams: upList.slice(0, 10).map((u: any) => ({ asn: u.asn, name: u.name, description: u.description, country: u.country_code })),
              },
              attribution: {
                provider: 'BGPView',
                url: `https://bgpview.io/asn/${asn}/upstreams`,
                method: 'api',
              },
            });
          }
        }
      }

      // Step 4: Parallel prefix listing for each ASN
      const prefixLists = await Promise.allSettled(
        asnArray.map(asn => bgpFetch(`/asn/${asn}/prefixes`))
      );

      for (let i = 0; i < asnArray.length; i++) {
        const result = prefixLists[i];
        if (result.status !== 'fulfilled' || !result.value) continue;
        const allPrefixes = [...(result.value.ipv4_prefixes || []), ...(result.value.ipv6_prefixes || [])];
        if (allPrefixes.length > 0) {
            const name = `AS${asnArray[i]} IP prefix inventory`;
            observations.push({
                assetId: makeAssetId(domain, name, source),
                domain,
                assetType: 'breach',
                name,
                source,
                observedAt: now,
                tags: ['bgpview', 'prefix_inventory', 'attack_surface'],
                evidence: {
                    severity: 0,
                    confidence: 85,
                    asn: asnArray[i],
                    total_prefixes: allPrefixes.length,
                    prefixes: allPrefixes.slice(0, 30).map((p: any) => ({ prefix: p.prefix, name: p.name, description: p.description, country: p.country_code })),
                },
                attribution: {
                    provider: 'BGPView',
                    url: `https://bgpview.io/asn/${asnArray[i]}/prefixes`,
                    method: 'api',
                },
            });
        }
      }

    } catch (err: any) {
      errors.push(err.message || 'Unknown BGPView error');
    }

    return {
      connector: source,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
