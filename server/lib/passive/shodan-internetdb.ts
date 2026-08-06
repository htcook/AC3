/**
 * Shodan InternetDB — Free Fast-Path IP Enrichment
 * 
 * Queries the Shodan InternetDB API (internetdb.shodan.io/{ip}) for every
 * resolved IP address. This is a free, rate-limit-free API that provides:
 *   - Open ports
 *   - CVEs (vulnerability IDs)
 *   - CPEs (Common Platform Enumeration strings)
 *   - Hostnames
 *   - Tags (e.g., "cloud", "vpn", "self-signed")
 * 
 * This connector runs as a pre-enrichment step before the full Shodan API,
 * providing instant vulnerability data without consuming API credits.
 * 
 * Method: DNS resolution → InternetDB lookup for each resolved IP
 * Data Source: Shodan's pre-computed internet-wide scan database
 * Attribution: Each observation links to shodan.io/host/{ip}
 * Free: Yes, no API key required, no rate limits
 */

import { createHash } from "crypto";
import { resolve4 } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface InternetDBResponse {
  cpes: string[];
  hostnames: string[];
  ip: string;
  ports: number[];
  tags: string[];
  vulns: string[];
}

async function queryInternetDB(ip: string, timeout: number): Promise<InternetDBResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" },
    });
    if (res.status === 404) return null; // IP not in database
    if (!res.ok) throw new Error(`InternetDB returned ${res.status}`);
    return await res.json() as InternetDBResponse;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Classify a CVE severity based on its ID pattern (rough heuristic).
 * In production, this would be enriched from NVD/CVEDB, but for tagging
 * purposes we use the InternetDB data as-is.
 */
function cveToTags(cveId: string): string[] {
  return [`cve:${cveId}`, "shodan_internetdb_vuln"];
}

export const shodanInternetDBConnector: PassiveConnector = {
  name: "shodan_internetdb",
  description: "Shodan InternetDB — free, instant IP enrichment with open ports, CVEs, CPEs, hostnames, and tags (no API key required)",
  requiresApiKey: false,
  freeUrl: "https://internetdb.shodan.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;

    try {
      // Resolve domain to IPs
      let ips: string[] = [];
      try {
        ips = await resolve4(domain);
      } catch {
        errors.push(`Could not resolve ${domain} to IP addresses`);
        return { connector: "shodan_internetdb", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const now = new Date();

      // Query InternetDB for each IP (limit to 20 IPs)
      const results = await Promise.allSettled(
        ips.slice(0, 20).map(ip => queryInternetDB(ip, timeout))
      );

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        const ip = ips[i];

        if (result.status === "rejected") {
          errors.push(`InternetDB error for ${ip}: ${result.reason?.message || result.reason}`);
          continue;
        }

        const data = result.value;
        if (!data) continue; // IP not in database

        // Create main IP observation with all InternetDB data
        observations.push({
          assetId: makeAssetId(domain, `${ip}|internetdb`, "shodan_internetdb"),
          domain,
          assetType: "ip",
          name: `${ip} (InternetDB)`,
          ip,
          source: "shodan_internetdb",
          observedAt: now,
          tags: [
            ...data.tags.map(t => `idb_tag:${t}`),
            ...data.ports.map(p => `port:${p}`),
            ...data.cpes.map(c => `cpe:${c}`),
            ...data.vulns.flatMap(v => cveToTags(v)),
            `open_ports:${data.ports.length}`,
            `vuln_count:${data.vulns.length}`,
            `cpe_count:${data.cpes.length}`,
          ],
          evidence: {
            ip: data.ip,
            ports: data.ports,
            cpes: data.cpes,
            vulns: data.vulns,
            hostnames: data.hostnames,
            tags: data.tags,
            port_count: data.ports.length,
            vuln_count: data.vulns.length,
            cpe_count: data.cpes.length,
          },
          attribution: {
            provider: "Shodan InternetDB (Free API)",
            url: `https://internetdb.shodan.io/${ip}`,
            method: `Shodan InternetDB lookup — queried pre-computed scan data for ${ip}, found ${data.ports.length} open ports, ${data.vulns.length} CVEs, ${data.cpes.length} CPEs`,
            verifyUrl: `https://www.shodan.io/host/${ip}`,
          },
        });

        // Create individual CVE observations for each vulnerability
        for (const vuln of data.vulns) {
          observations.push({
            assetId: makeAssetId(domain, `${ip}|${vuln}|internetdb`, "shodan_internetdb_vuln"),
            domain,
            assetType: "ip",
            name: `${vuln} on ${ip}`,
            ip,
            source: "shodan_internetdb",
            observedAt: now,
            tags: [
              `cve:${vuln}`,
              "shodan_internetdb_vuln",
              "pre_enrichment",
              ...data.cpes.map(c => `cpe:${c}`),
            ],
            evidence: {
              cve_id: vuln,
              ip: data.ip,
              ports: data.ports,
              cpes: data.cpes,
              source_api: "internetdb.shodan.io",
              verification_type: "shodan_precomputed",
            },
            attribution: {
              provider: "Shodan InternetDB (Free API)",
              url: `https://internetdb.shodan.io/${ip}`,
              method: `Shodan InternetDB — ${vuln} detected on ${ip} via pre-computed internet-wide scan data`,
              verifyUrl: `https://www.shodan.io/host/${ip}`,
            },
          });
        }

        // Create hostname observations from InternetDB
        for (const hostname of data.hostnames) {
          if (hostname.endsWith(domain) || hostname === domain) {
            observations.push({
              assetId: makeAssetId(domain, `${hostname}|internetdb_host`, "shodan_internetdb"),
              domain,
              assetType: "subdomain",
              name: hostname,
              ip,
              source: "shodan_internetdb",
              observedAt: now,
              tags: ["internetdb_hostname", `ip:${ip}`],
              evidence: {
                hostname,
                ip: data.ip,
                discovered_via: "shodan_internetdb",
              },
              attribution: {
                provider: "Shodan InternetDB (Free API)",
                url: `https://internetdb.shodan.io/${ip}`,
                method: `Shodan InternetDB — hostname ${hostname} associated with ${ip}`,
                verifyUrl: `https://www.shodan.io/host/${ip}`,
              },
            });
          }
        }
      }
    } catch (err: any) {
      errors.push(`InternetDB error: ${err.message}`);
    }

    return {
      connector: "shodan_internetdb",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
