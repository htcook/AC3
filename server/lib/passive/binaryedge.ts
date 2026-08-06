/**
 * BinaryEdge — Independent Internet-Wide Scanning Connector
 * 
 * Queries the BinaryEdge API for host data including:
 *   - Service banners and versions (3,500+ ports scanned)
 *   - CVE matches from CPE analysis
 *   - JARM TLS fingerprints
 *   - SSH key data
 *   - Torrent activity
 *   - Module-specific data (web, ssl, ssh, dns, etc.)
 * 
 * BinaryEdge provides an independent scanning dataset from Shodan,
 * enabling multi-source corroboration of vulnerability findings.
 * 
 * Method: DNS resolution → BinaryEdge host query for each resolved IP
 * Data Source: BinaryEdge internet-wide scanning platform
 * Attribution: Each observation links to app.binaryedge.io
 * Requires: API key ($40/mo for 250 queries/month)
 */

import { createHash } from "crypto";
import { resolve4 } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface BinaryEdgeEvent {
  results: Array<{
    origin: { ip: string; port: number; type: string; ts: string; module?: string };
    result: {
      data: {
        service?: { name?: string; banner?: string; product?: string; version?: string; cpe?: string[] };
        cert?: { issuer?: Record<string, string>; subject?: Record<string, string>; not_before?: string; not_after?: string; fingerprint?: string };
        jarm?: string;
        ssh?: { banner?: string; hassh?: string; algorithms?: Record<string, string[]> };
        state?: { state?: string };
      };
    };
  }>;
}

interface BinaryEdgeHostResponse {
  total: number;
  query: string;
  events: BinaryEdgeEvent[];
  ports?: number[];
}

async function queryBinaryEdge(ip: string, apiKey: string, timeout: number): Promise<BinaryEdgeHostResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.binaryedge.io/v2/query/ip/${ip}`, {
      signal: controller.signal,
      headers: {
        "X-Key": apiKey,
        "Accept": "application/json",
      },
    });
    if (res.status === 404) return null;
    if (res.status === 429) throw new Error("Rate limited by BinaryEdge API");
    if (res.status === 403) throw new Error("Invalid or expired BinaryEdge API key");
    if (!res.ok) throw new Error(`BinaryEdge returned ${res.status}`);
    return await res.json() as BinaryEdgeHostResponse;
  } finally {
    clearTimeout(timer);
  }
}

async function queryBinaryEdgeCVE(ip: string, apiKey: string, timeout: number): Promise<any | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.binaryedge.io/v2/query/cve/ip/${ip}`, {
      signal: controller.signal,
      headers: {
        "X-Key": apiKey,
        "Accept": "application/json",
      },
    });
    if (res.status === 404) return null;
    if (res.status === 429) return null; // Don't fail on rate limit for CVE endpoint
    if (!res.ok) return null;
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export const binaryedgeConnector: PassiveConnector = {
  name: "binaryedge",
  description: "BinaryEdge — independent internet-wide scanning with 3,500+ port coverage, JARM fingerprints, CVE detection, and SSH key analysis",
  requiresApiKey: true,
  freeUrl: "https://app.binaryedge.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 20000;
    const apiKey = config?.apiKey;

    if (!apiKey) {
      return {
        connector: "binaryedge",
        domain,
        observations: [],
        errors: ["BinaryEdge API key not configured — skipping"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      // Resolve domain to IPs
      let ips: string[] = [];
      try {
        ips = await resolve4(domain);
      } catch {
        errors.push(`Could not resolve ${domain} to IP addresses`);
        return { connector: "binaryedge", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const now = new Date();

      // Query BinaryEdge for each IP (limit to 10 to conserve API credits)
      for (const ip of ips.slice(0, 10)) {
        try {
          const [hostData, cveData] = await Promise.allSettled([
            queryBinaryEdge(ip, apiKey, timeout),
            queryBinaryEdgeCVE(ip, apiKey, timeout),
          ]);

          // Process host data
          if (hostData.status === "fulfilled" && hostData.value) {
            const data = hostData.value;
            const allPorts: number[] = [];
            const allCpes: string[] = [];
            const allProducts: string[] = [];
            const jarmFingerprints: string[] = [];
            const sshData: any[] = [];

            for (const event of data.events || []) {
              for (const result of event.results || []) {
                const port = result.origin?.port;
                if (port) allPorts.push(port);

                const service = result.result?.data?.service;
                if (service) {
                  if (service.cpe) allCpes.push(...service.cpe);
                  if (service.product) allProducts.push(`${service.product}${service.version ? ` ${service.version}` : ""}`);
                }

                const jarm = result.result?.data?.jarm;
                if (jarm && jarm !== "00000000000000000000000000000000000000000000") {
                  jarmFingerprints.push(jarm);
                }

                const ssh = result.result?.data?.ssh;
                if (ssh) {
                  sshData.push({
                    banner: ssh.banner,
                    hassh: ssh.hassh,
                    algorithms: ssh.algorithms,
                  });
                }

                // TLS certificate observations
                const cert = result.result?.data?.cert;
                if (cert) {
                  observations.push({
                    assetId: makeAssetId(domain, `${ip}:${port}|cert|binaryedge`, "binaryedge"),
                    domain,
                    assetType: "certificate",
                    name: `TLS cert on ${ip}:${port}`,
                    ip,
                    source: "binaryedge",
                    observedAt: now,
                    tags: [
                      `port:${port}`,
                      "tls_certificate",
                      "binaryedge",
                      ...(cert.fingerprint ? [`fingerprint:${cert.fingerprint}`] : []),
                    ],
                    evidence: {
                      port,
                      issuer: cert.issuer,
                      subject: cert.subject,
                      not_before: cert.not_before,
                      not_after: cert.not_after,
                      fingerprint: cert.fingerprint,
                    },
                    attribution: {
                      provider: "BinaryEdge",
                      url: `https://app.binaryedge.io/services/query?query=ip:${ip}&page=1`,
                      method: `BinaryEdge — TLS certificate on ${ip}:${port}`,
                      verifyUrl: `https://app.binaryedge.io/services/query?query=ip:${ip}`,
                    },
                  });
                }
              }
            }

            // Deduplicate
            const uniquePorts = Array.from(new Set(allPorts)).sort((a, b) => a - b);
            const uniqueCpes = Array.from(new Set(allCpes));
            const uniqueProducts = Array.from(new Set(allProducts));

            // Main IP observation with all BinaryEdge data
            observations.push({
              assetId: makeAssetId(domain, `${ip}|binaryedge_host`, "binaryedge"),
              domain,
              assetType: "ip",
              name: `${ip} (BinaryEdge)`,
              ip,
              source: "binaryedge",
              observedAt: now,
              tags: [
                ...uniquePorts.map(p => `port:${p}`),
                ...uniqueCpes.map(c => `cpe:${c}`),
                ...uniqueProducts.map(p => `product:${p}`),
                ...jarmFingerprints.map(j => `jarm:${j}`),
                `open_ports:${uniquePorts.length}`,
                `cpe_count:${uniqueCpes.length}`,
                "binaryedge",
              ],
              evidence: {
                ip,
                ports: uniquePorts,
                cpes: uniqueCpes,
                products: uniqueProducts,
                jarm_fingerprints: jarmFingerprints,
                ssh_data: sshData.length > 0 ? sshData : undefined,
                total_events: data.total,
                port_count: uniquePorts.length,
                cpe_count: uniqueCpes.length,
              },
              attribution: {
                provider: "BinaryEdge",
                url: `https://app.binaryedge.io/services/query?query=ip:${ip}`,
                method: `BinaryEdge host query — found ${uniquePorts.length} open ports, ${uniqueCpes.length} CPEs, ${uniqueProducts.length} products on ${ip}`,
                verifyUrl: `https://app.binaryedge.io/services/query?query=ip:${ip}`,
              },
            });
          } else if (hostData.status === "rejected") {
            errors.push(`BinaryEdge host error for ${ip}: ${hostData.reason?.message || hostData.reason}`);
          }

          // Process CVE data
          if (cveData.status === "fulfilled" && cveData.value) {
            const vulns = cveData.value;
            const cveList: Array<{ cve: string; cvss?: number; cpes?: string[] }> = [];

            // BinaryEdge CVE response structure varies; handle both formats
            if (Array.isArray(vulns.events)) {
              for (const event of vulns.events) {
                const cves = event.cves || event.results || [];
                for (const cveEntry of cves) {
                  const cveId = typeof cveEntry === "string" ? cveEntry : cveEntry.cve || cveEntry.id;
                  if (cveId && cveId.startsWith("CVE-")) {
                    cveList.push({
                      cve: cveId,
                      cvss: typeof cveEntry === "object" ? cveEntry.cvss : undefined,
                      cpes: typeof cveEntry === "object" ? cveEntry.cpes : undefined,
                    });
                  }
                }
              }
            } else if (Array.isArray(vulns.cves)) {
              for (const cveEntry of vulns.cves) {
                const cveId = typeof cveEntry === "string" ? cveEntry : cveEntry.cve || cveEntry.id;
                if (cveId && cveId.startsWith("CVE-")) {
                  cveList.push({
                    cve: cveId,
                    cvss: typeof cveEntry === "object" ? cveEntry.cvss : undefined,
                  });
                }
              }
            }

            // Create individual CVE observations
            for (const { cve, cvss, cpes } of cveList.slice(0, 100)) { // Limit to 100 CVEs
              observations.push({
                assetId: makeAssetId(domain, `${ip}|${cve}|binaryedge`, "binaryedge_vuln"),
                domain,
                assetType: "ip",
                name: `${cve} on ${ip} (BinaryEdge)`,
                ip,
                source: "binaryedge",
                observedAt: now,
                tags: [
                  `cve:${cve}`,
                  "binaryedge_vuln",
                  "independent_validation",
                  ...(cvss !== undefined ? [`cvss:${cvss}`] : []),
                  ...(cpes || []).map((c: string) => `cpe:${c}`),
                ],
                evidence: {
                  cve_id: cve,
                  ip,
                  cvss,
                  cpes,
                  source_api: "api.binaryedge.io",
                  verification_type: "binaryedge_cve_scan",
                },
                attribution: {
                  provider: "BinaryEdge",
                  url: `https://app.binaryedge.io/services/query?query=ip:${ip}`,
                  method: `BinaryEdge CVE scan — ${cve} detected on ${ip} via independent internet-wide scanning`,
                  verifyUrl: `https://app.binaryedge.io/services/query?query=ip:${ip}`,
                },
              });
            }
          }
        } catch (err: any) {
          if (err.message.includes("Rate limited")) {
            errors.push(`BinaryEdge rate limited — remaining IPs skipped`);
            break;
          }
          errors.push(`BinaryEdge error for ${ip}: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`BinaryEdge error: ${err.message}`);
    }

    return {
      connector: "binaryedge",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: errors.some(e => e.includes("Rate limited")),
    };
  },
};
