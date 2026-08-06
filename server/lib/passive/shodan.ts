/**
 * Shodan — Internet-Wide Scan Database Connector (Enhanced)
 *
 * Three-stage collection:
 * 1. DNS Domain API — discovers subdomains + DNS records
 * 2. Host Search API — finds all hosts matching *.domain with open ports/services/banners
 * 3. Host Detail API — for each unique IP, fetches full banner data including CVE/vuln info
 *
 * The connector extracts:
 * - Subdomains from DNS records and reverse DNS
 * - Open ports, transport protocols, service products + versions
 * - OS detection, organization, ASN, ISP
 * - Banner snippets for version fingerprinting
 * - Known CVEs/vulns associated with detected services (from Shodan's vuln database)
 * - SSL/TLS certificate details
 *
 * Requires: SHODAN_API_KEY
 */

import { createHash } from "crypto";
import type {
  AssetObservation,
  ConnectorConfig,
  ConnectorResult,
  PassiveConnector,
} from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256")
    .update(`${domain}|${name}|${source}`)
    .digest("hex")
    .slice(0, 20);
}

/** Rate-limited fetch with retry on 429 */
async function shodanFetch(url: string, timeout: number, retries = 1, externalSignal?: AbortSignal): Promise<any> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (externalSignal?.aborted) throw new Error('Aborted by external signal');
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    externalSignal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (res.status === 429 && attempt < retries) {
        // Wait 1.5s and retry
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      if (res.status === 401) throw Object.assign(new Error("Shodan API key is invalid"), { status: 401 });
      if (res.status === 429) throw Object.assign(new Error("Shodan rate limit exceeded"), { status: 429 });
      if (res.status === 404) return null; // No data for this query
      if (!res.ok) throw new Error(`Shodan returned ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', onAbort);
    }
  }
}

/** Small delay to respect Shodan rate limits */
function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

export const shodanConnector: PassiveConnector = {
  name: "shodan",
  description:
    "Internet-wide scan database — discovers subdomains, open ports, services, banners, CVEs, and SSL certs from Shodan",
  requiresApiKey: true,
  freeUrl: "https://www.shodan.io",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    const externalSignal = config?.signal;

    if (!apiKey) {
      return {
        connector: "shodan",
        domain,
        observations: [],
        errors: ["SHODAN_API_KEY not configured — skipping Shodan connector"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    const now = new Date();
    const seenSubdomains = new Set<string>();
    const seenIPs = new Set<string>();
    let rateLimited = false;

    // ── Stage 1: DNS Domain API ─────────────────────────────────
    try {
      const dnsData = await shodanFetch(
        `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiKey)}`,
        timeout, 1, externalSignal
      );

      if (dnsData && dnsData.subdomains) {
        for (const sub of dnsData.subdomains) {
          const fqdn = `${sub}.${domain}`;
          if (seenSubdomains.has(fqdn)) continue;
          seenSubdomains.add(fqdn);

          observations.push({
            assetId: makeAssetId(domain, fqdn, "shodan_dns"),
            domain,
            assetType: "subdomain",
            name: fqdn,
            source: "shodan",
            observedAt: now,
            tags: ["shodan_dns_discovery"],
            evidence: { discovery_method: "shodan_dns_domain_api" },
            attribution: {
              provider: "Shodan (DNS Domain API)",
              url: `https://www.shodan.io/domain/${domain}`,
              method: `Subdomain discovered via Shodan DNS Domain API for ${domain}`,
              verifyUrl: `https://www.shodan.io/domain/${domain}`,
            },
          });
        }

        // Extract A/AAAA records for IP observations
        if (dnsData.data) {
          for (const record of dnsData.data) {
            if ((record.type === "A" || record.type === "AAAA") && record.value) {
              const fqdn = record.subdomain
                ? `${record.subdomain}.${domain}`
                : domain;
              if (!seenSubdomains.has(fqdn)) {
                seenSubdomains.add(fqdn);
              }
              if (record.value && !seenIPs.has(record.value)) {
                seenIPs.add(record.value);
              }
            }
          }
        }
      }
    } catch (err: any) {
      if (err.status === 429) rateLimited = true;
      errors.push(`Shodan DNS domain: ${err.message}`);
    }

    // ── Stage 2: Host Search API ────────────────────────────────
    if (externalSignal?.aborted) {
      return { connector: "shodan", domain, observations, errors: [...errors, "Aborted before stage 2"], durationMs: Date.now() - start, rateLimited };
    }
    try {
      await delay(300); // Small delay between API calls
      const query = `hostname:.${domain}`;
      const searchData = await shodanFetch(
        `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent(query)}&minify=false`,
        timeout, 1, externalSignal
      );

      if (searchData && searchData.matches) {
        for (const match of searchData.matches) {
          const ip = match.ip_str;
          const port = match.port;
          const hostnames: string[] = match.hostnames || [];
          const product = match.product || "";
          const version = match.version || "";
          const org = match.org || "";
          const asn = match.asn
            ? parseInt(match.asn.replace("AS", ""), 10)
            : undefined;
          const transport = match.transport || "tcp";
          const os = match.os || "";
          const cpe = match.cpe || match.cpe23 || [];

          // Extract SSL info
          const ssl = match.ssl || {};
          const sslCert = ssl.cert || {};
          const sslSubject = sslCert.subject || {};
          const sslIssuer = sslCert.issuer || {};
          const sslExpires = sslCert.expires;

          // Extract vulns from match
          const vulns: string[] = match.vulns ? Object.keys(match.vulns) : [];

          // Build rich tags
          const tags = [
            `port:${port}`,
            `transport:${transport}`,
            ...(product ? [`product:${product}`] : []),
            ...(version ? [`version:${version}`] : []),
            ...(os ? [`os:${os}`] : []),
            ...(org ? [`org:${org}`] : []),
            ...vulns.map((v) => `cve:${v}`),
            ...(cpe.length > 0 ? cpe.map((c: string) => `cpe:${c}`) : []),
          ];

          const name = hostnames.length > 0 ? hostnames[0] : ip;
          seenIPs.add(ip);

          observations.push({
            assetId: makeAssetId(domain, `${ip}:${port}`, "shodan"),
            domain,
            assetType: "ip",
            name,
            ip,
            asn: isNaN(asn as number) ? undefined : asn,
            source: "shodan",
            observedAt: now,
            lastSeen: match.timestamp
              ? new Date(match.timestamp)
              : undefined,
            tags,
            evidence: {
              port,
              transport,
              product,
              version,
              org,
              asn: match.asn,
              isp: match.isp,
              os,
              cpe,
              vulns,
              banner_snippet: (match.data || "").substring(0, 500),
              hostnames,
              ssl_subject: sslSubject.CN || undefined,
              ssl_issuer: sslIssuer.O || undefined,
              ssl_expires: sslExpires || undefined,
              http_title: match.http?.title || undefined,
              http_server: match.http?.server || undefined,
              http_status: match.http?.status || undefined,
            },
            attribution: {
              provider: "Shodan (Internet-Wide Scan Database)",
              url: `https://www.shodan.io/host/${ip}`,
              method: `Shodan host search — port ${port}/${transport} open with ${product || "unknown"}${version ? " " + version : ""} service. ${vulns.length > 0 ? `Known CVEs: ${vulns.join(", ")}` : "No known CVEs."}`,
              verifyUrl: `https://www.shodan.io/host/${ip}`,
            },
          });

          // Create subdomain observations for each hostname
          for (const hn of hostnames) {
            if (
              (hn.endsWith(`.${domain}`) || hn === domain) &&
              !seenSubdomains.has(hn)
            ) {
              seenSubdomains.add(hn);
              observations.push({
                assetId: makeAssetId(domain, hn, "shodan_hostname"),
                domain,
                assetType: "subdomain",
                name: hn,
                ip,
                source: "shodan",
                observedAt: now,
                tags: [
                  "shodan_resolved",
                  `port:${port}`,
                  ...(product ? [`product:${product}`] : []),
                  ...(version ? [`version:${version}`] : []),
                ],
                evidence: {
                  resolved_ip: ip,
                  port,
                  product,
                  version,
                  os,
                  vulns,
                },
                attribution: {
                  provider: "Shodan (Internet-Wide Scan Database)",
                  url: `https://www.shodan.io/host/${ip}`,
                  method: `Hostname discovered via Shodan reverse DNS — ${hn} resolves to ${ip} with port ${port} open`,
                  verifyUrl: `https://www.shodan.io/host/${ip}`,
                },
              });
            }
          }
        }
      }
    } catch (err: any) {
      if (err.status === 429) rateLimited = true;
      errors.push(`Shodan host search: ${err.message}`);
    }

    // ── Stage 3: Host Detail API (top IPs for deep banner/vuln data) ──
    // Query up to 5 unique IPs for full host details including all ports and CVEs
    const ipsToQuery = Array.from(seenIPs).slice(0, 5);
    for (const ip of ipsToQuery) {
      if (externalSignal?.aborted) break;
      try {
        await delay(300);
        const hostData = await shodanFetch(
          `https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(apiKey)}`,
          timeout, 1, externalSignal
        );

        if (!hostData) continue;

        // Extract all vulns from the host
        const hostVulns: string[] = hostData.vulns || [];
        const allPorts: number[] = hostData.ports || [];
        const hostOs = hostData.os || "";

        // Create a comprehensive host-level observation
        const hostHostnames = hostData.hostnames || [];
        const primaryName = hostHostnames.find((h: string) =>
          h.endsWith(`.${domain}`) || h === domain
        ) || ip;

        // Process each service/banner on this host
        if (hostData.data && Array.isArray(hostData.data)) {
          for (const svc of hostData.data) {
            const port = svc.port;
            const product = svc.product || "";
            const version = svc.version || "";
            const transport = svc.transport || "tcp";
            const cpe = svc.cpe || svc.cpe23 || [];
            const svcVulns: string[] = svc.vulns
              ? Object.keys(svc.vulns)
              : [];

            // Only create if we don't already have this IP:port from search
            const existingId = makeAssetId(domain, `${ip}:${port}`, "shodan");
            const alreadyExists = observations.some(
              (o) => o.assetId === existingId
            );

            if (!alreadyExists) {
              observations.push({
                assetId: makeAssetId(domain, `${ip}:${port}`, "shodan_detail"),
                domain,
                assetType: "ip",
                name: primaryName,
                ip,
                source: "shodan",
                observedAt: now,
                lastSeen: svc.timestamp
                  ? new Date(svc.timestamp)
                  : undefined,
                tags: [
                  `port:${port}`,
                  `transport:${transport}`,
                  ...(product ? [`product:${product}`] : []),
                  ...(version ? [`version:${version}`] : []),
                  ...(hostOs ? [`os:${hostOs}`] : []),
                  ...svcVulns.map((v) => `cve:${v}`),
                  ...cpe.map((c: string) => `cpe:${c}`),
                  "shodan_host_detail",
                ],
                evidence: {
                  port,
                  transport,
                  product,
                  version,
                  os: hostOs,
                  cpe,
                  vulns: svcVulns,
                  host_vulns: hostVulns,
                  all_ports: allPorts,
                  banner_snippet: (svc.data || "").substring(0, 500),
                  http_title: svc.http?.title || undefined,
                  http_server: svc.http?.server || undefined,
                },
                attribution: {
                  provider: "Shodan (Host Detail API)",
                  url: `https://www.shodan.io/host/${ip}`,
                  method: `Shodan host detail query — ${ip} port ${port}/${transport}: ${product || "unknown"}${version ? " " + version : ""}. ${svcVulns.length > 0 ? `CVEs: ${svcVulns.join(", ")}` : ""}`,
                  verifyUrl: `https://www.shodan.io/host/${ip}`,
                },
              });
            } else {
              // Update existing observation with deeper data from host detail
              const existing = observations.find(
                (o) => o.assetId === existingId
              );
              if (existing && existing.evidence) {
                // Merge vulns from host detail into existing observation
                const existingVulns: string[] =
                  (existing.evidence as any).vulns || [];
                const mergedVulns = Array.from(
                  new Set([...existingVulns, ...svcVulns])
                );
                (existing.evidence as any).vulns = mergedVulns;
                (existing.evidence as any).host_vulns = hostVulns;
                (existing.evidence as any).all_ports = allPorts;
                // Update CPE if richer
                if (cpe.length > 0) {
                  (existing.evidence as any).cpe = cpe;
                }
                // Add CVE tags
                for (const v of svcVulns) {
                  if (!existing.tags?.includes(`cve:${v}`)) {
                    existing.tags?.push(`cve:${v}`);
                  }
                }
              }
            }
          }
        }

        // Add host-level vuln summary observation if there are vulns
        if (hostVulns.length > 0) {
          observations.push({
            assetId: makeAssetId(domain, `${ip}:vulns`, "shodan_vulns"),
            domain,
            assetType: "ip",
            name: primaryName,
            ip,
            source: "shodan",
            observedAt: now,
            tags: [
              "shodan_vuln_summary",
              ...hostVulns.map((v) => `cve:${v}`),
              ...allPorts.map((p) => `port:${p}`),
            ],
            evidence: {
              vulns: hostVulns,
              vuln_count: hostVulns.length,
              all_ports: allPorts,
              os: hostOs,
              hostnames: hostHostnames,
              verification_source: "shodan_host_detail",
              verified: true,
            },
            attribution: {
              provider: "Shodan (Vulnerability Detection)",
              url: `https://www.shodan.io/host/${ip}`,
              method: `Shodan detected ${hostVulns.length} known CVEs on ${ip} via banner analysis: ${hostVulns.slice(0, 5).join(", ")}${hostVulns.length > 5 ? ` (+${hostVulns.length - 5} more)` : ""}`,
              verifyUrl: `https://www.shodan.io/host/${ip}`,
            },
          });
        }
      } catch (err: any) {
        if (err.status === 429) {
          rateLimited = true;
          break; // Stop querying more IPs if rate limited
        }
        errors.push(`Shodan host detail ${ip}: ${err.message}`);
      }
    }

    return {
      connector: "shodan",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
