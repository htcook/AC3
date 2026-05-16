import {
  domainHealthConnector,
  init_domain_health
} from "./chunk-B5ZZBP3X.js";
import {
  filterConnectors,
  getScanModeDescription,
  init_passive_guard
} from "./chunk-NBT7IJMY.js";
import {
  corroborateFindings,
  init_corroboration_engine
} from "./chunk-WY62SLRF.js";
import {
  containerDiscoveryConnector,
  init_container_discovery
} from "./chunk-VCQC5R24.js";
import {
  classifyError,
  init_api_resilience,
  recordFailure,
  recordSuccess,
  shouldAllowRequest,
  trackCall
} from "./chunk-YWKNEYVH.js";
import {
  getDb,
  init_db
} from "./chunk-CKIMRR6W.js";
import {
  credentialExposures,
  init_schema,
  threatActorIocs,
  threatActors,
  threatGroupEvents,
  undergroundIntelEvents
} from "./chunk-Q4QB2XQC.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/passive/crtsh.ts
import { createHash } from "crypto";
function makeAssetId(domain, name, source) {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function fetchCrtsh(domain, timeout) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
var crtshConnector;
var init_crtsh = __esm({
  "server/lib/passive/crtsh.ts"() {
    "use strict";
    crtshConnector = {
      name: "crtsh",
      description: "Certificate Transparency log search via crt.sh \u2014 discovers subdomains from issued SSL/TLS certificates",
      requiresApiKey: false,
      freeUrl: "https://crt.sh",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const raw = await fetchCrtsh(domain, timeout);
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          for (const entry of raw) {
            const nameValue = entry.name_value || "";
            const names = nameValue.split("\n").map((n) => n.trim().toLowerCase()).filter(Boolean);
            for (const name of names) {
              if (name.startsWith("*.") || seen.has(name)) continue;
              if (!name.endsWith(`.${domain}`) && name !== domain) continue;
              seen.add(name);
              if (seen.size > maxResults) break;
              const notBefore = entry.not_before ? new Date(entry.not_before) : void 0;
              const notAfter = entry.not_after ? new Date(entry.not_after) : void 0;
              observations.push({
                assetId: makeAssetId(domain, name, "crtsh"),
                domain,
                assetType: "subdomain",
                name,
                source: "crtsh",
                observedAt: now,
                firstSeen: notBefore,
                lastSeen: notAfter,
                tags: ["ct_log", "certificate"],
                evidence: {
                  issuer_name: entry.issuer_name,
                  serial_number: entry.serial_number,
                  not_before: entry.not_before,
                  not_after: entry.not_after,
                  entry_timestamp: entry.entry_timestamp,
                  crt_sh_id: entry.id
                },
                attribution: {
                  provider: "crt.sh (Certificate Transparency)",
                  url: `https://crt.sh/?id=${entry.id}`,
                  method: "Certificate Transparency log search \u2014 queried crt.sh for all SSL/TLS certificates issued for *.${domain}",
                  verifyUrl: `https://crt.sh/?q=%25.${domain}`
                }
              });
            }
            if (seen.size > maxResults) break;
          }
        } catch (err) {
          errors.push(`crt.sh error: ${err.message}`);
        }
        return {
          connector: "crtsh",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/shodan.ts
import { createHash as createHash2 } from "crypto";
function makeAssetId2(domain, name, source) {
  return createHash2("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function shodanFetch(url, timeout, retries = 1, externalSignal) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (externalSignal?.aborted) throw new Error("Aborted by external signal");
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    externalSignal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (res.status === 429 && attempt < retries) {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      if (res.status === 401) throw Object.assign(new Error("Shodan API key is invalid"), { status: 401 });
      if (res.status === 429) throw Object.assign(new Error("Shodan rate limit exceeded"), { status: 429 });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`Shodan returned ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onAbort);
    }
  }
}
function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
var shodanConnector;
var init_shodan = __esm({
  "server/lib/passive/shodan.ts"() {
    "use strict";
    shodanConnector = {
      name: "shodan",
      description: "Internet-wide scan database \u2014 discovers subdomains, open ports, services, banners, CVEs, and SSL certs from Shodan",
      requiresApiKey: true,
      freeUrl: "https://www.shodan.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        const externalSignal = config?.signal;
        if (!apiKey) {
          return {
            connector: "shodan",
            domain,
            observations: [],
            errors: ["SHODAN_API_KEY not configured \u2014 skipping Shodan connector"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        const now = /* @__PURE__ */ new Date();
        const seenSubdomains = /* @__PURE__ */ new Set();
        const seenIPs = /* @__PURE__ */ new Set();
        let rateLimited = false;
        try {
          const dnsData = await shodanFetch(
            `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiKey)}`,
            timeout,
            1,
            externalSignal
          );
          if (dnsData && dnsData.subdomains) {
            for (const sub of dnsData.subdomains) {
              const fqdn = `${sub}.${domain}`;
              if (seenSubdomains.has(fqdn)) continue;
              seenSubdomains.add(fqdn);
              observations.push({
                assetId: makeAssetId2(domain, fqdn, "shodan_dns"),
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
                  verifyUrl: `https://www.shodan.io/domain/${domain}`
                }
              });
            }
            if (dnsData.data) {
              for (const record of dnsData.data) {
                if ((record.type === "A" || record.type === "AAAA") && record.value) {
                  const fqdn = record.subdomain ? `${record.subdomain}.${domain}` : domain;
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
        } catch (err) {
          if (err.status === 429) rateLimited = true;
          errors.push(`Shodan DNS domain: ${err.message}`);
        }
        if (externalSignal?.aborted) {
          return { connector: "shodan", domain, observations, errors: [...errors, "Aborted before stage 2"], durationMs: Date.now() - start, rateLimited };
        }
        try {
          await delay(300);
          const query = `hostname:.${domain}`;
          const searchData = await shodanFetch(
            `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent(query)}&minify=false`,
            timeout,
            1,
            externalSignal
          );
          if (searchData && searchData.matches) {
            for (const match of searchData.matches) {
              const ip = match.ip_str;
              const port = match.port;
              const hostnames = match.hostnames || [];
              const product = match.product || "";
              const version = match.version || "";
              const org = match.org || "";
              const asn = match.asn ? parseInt(match.asn.replace("AS", ""), 10) : void 0;
              const transport = match.transport || "tcp";
              const os = match.os || "";
              const cpe = match.cpe || match.cpe23 || [];
              const ssl = match.ssl || {};
              const sslCert = ssl.cert || {};
              const sslSubject = sslCert.subject || {};
              const sslIssuer = sslCert.issuer || {};
              const sslExpires = sslCert.expires;
              const vulns = match.vulns ? Object.keys(match.vulns) : [];
              const tags = [
                `port:${port}`,
                `transport:${transport}`,
                ...product ? [`product:${product}`] : [],
                ...version ? [`version:${version}`] : [],
                ...os ? [`os:${os}`] : [],
                ...org ? [`org:${org}`] : [],
                ...vulns.map((v) => `cve:${v}`),
                ...cpe.length > 0 ? cpe.map((c) => `cpe:${c}`) : []
              ];
              const name = hostnames.length > 0 ? hostnames[0] : ip;
              seenIPs.add(ip);
              observations.push({
                assetId: makeAssetId2(domain, `${ip}:${port}`, "shodan"),
                domain,
                assetType: "ip",
                name,
                ip,
                asn: isNaN(asn) ? void 0 : asn,
                source: "shodan",
                observedAt: now,
                lastSeen: match.timestamp ? new Date(match.timestamp) : void 0,
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
                  ssl_subject: sslSubject.CN || void 0,
                  ssl_issuer: sslIssuer.O || void 0,
                  ssl_expires: sslExpires || void 0,
                  http_title: match.http?.title || void 0,
                  http_server: match.http?.server || void 0,
                  http_status: match.http?.status || void 0
                },
                attribution: {
                  provider: "Shodan (Internet-Wide Scan Database)",
                  url: `https://www.shodan.io/host/${ip}`,
                  method: `Shodan host search \u2014 port ${port}/${transport} open with ${product || "unknown"}${version ? " " + version : ""} service. ${vulns.length > 0 ? `Known CVEs: ${vulns.join(", ")}` : "No known CVEs."}`,
                  verifyUrl: `https://www.shodan.io/host/${ip}`
                }
              });
              for (const hn of hostnames) {
                if ((hn.endsWith(`.${domain}`) || hn === domain) && !seenSubdomains.has(hn)) {
                  seenSubdomains.add(hn);
                  observations.push({
                    assetId: makeAssetId2(domain, hn, "shodan_hostname"),
                    domain,
                    assetType: "subdomain",
                    name: hn,
                    ip,
                    source: "shodan",
                    observedAt: now,
                    tags: [
                      "shodan_resolved",
                      `port:${port}`,
                      ...product ? [`product:${product}`] : [],
                      ...version ? [`version:${version}`] : []
                    ],
                    evidence: {
                      resolved_ip: ip,
                      port,
                      product,
                      version,
                      os,
                      vulns
                    },
                    attribution: {
                      provider: "Shodan (Internet-Wide Scan Database)",
                      url: `https://www.shodan.io/host/${ip}`,
                      method: `Hostname discovered via Shodan reverse DNS \u2014 ${hn} resolves to ${ip} with port ${port} open`,
                      verifyUrl: `https://www.shodan.io/host/${ip}`
                    }
                  });
                }
              }
            }
          }
        } catch (err) {
          if (err.status === 429) rateLimited = true;
          errors.push(`Shodan host search: ${err.message}`);
        }
        const ipsToQuery = Array.from(seenIPs).slice(0, 5);
        for (const ip of ipsToQuery) {
          if (externalSignal?.aborted) break;
          try {
            await delay(300);
            const hostData = await shodanFetch(
              `https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(apiKey)}`,
              timeout,
              1,
              externalSignal
            );
            if (!hostData) continue;
            const hostVulns = hostData.vulns || [];
            const allPorts = hostData.ports || [];
            const hostOs = hostData.os || "";
            const hostHostnames = hostData.hostnames || [];
            const primaryName = hostHostnames.find(
              (h) => h.endsWith(`.${domain}`) || h === domain
            ) || ip;
            if (hostData.data && Array.isArray(hostData.data)) {
              for (const svc of hostData.data) {
                const port = svc.port;
                const product = svc.product || "";
                const version = svc.version || "";
                const transport = svc.transport || "tcp";
                const cpe = svc.cpe || svc.cpe23 || [];
                const svcVulns = svc.vulns ? Object.keys(svc.vulns) : [];
                const existingId = makeAssetId2(domain, `${ip}:${port}`, "shodan");
                const alreadyExists = observations.some(
                  (o) => o.assetId === existingId
                );
                if (!alreadyExists) {
                  observations.push({
                    assetId: makeAssetId2(domain, `${ip}:${port}`, "shodan_detail"),
                    domain,
                    assetType: "ip",
                    name: primaryName,
                    ip,
                    source: "shodan",
                    observedAt: now,
                    lastSeen: svc.timestamp ? new Date(svc.timestamp) : void 0,
                    tags: [
                      `port:${port}`,
                      `transport:${transport}`,
                      ...product ? [`product:${product}`] : [],
                      ...version ? [`version:${version}`] : [],
                      ...hostOs ? [`os:${hostOs}`] : [],
                      ...svcVulns.map((v) => `cve:${v}`),
                      ...cpe.map((c) => `cpe:${c}`),
                      "shodan_host_detail"
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
                      http_title: svc.http?.title || void 0,
                      http_server: svc.http?.server || void 0
                    },
                    attribution: {
                      provider: "Shodan (Host Detail API)",
                      url: `https://www.shodan.io/host/${ip}`,
                      method: `Shodan host detail query \u2014 ${ip} port ${port}/${transport}: ${product || "unknown"}${version ? " " + version : ""}. ${svcVulns.length > 0 ? `CVEs: ${svcVulns.join(", ")}` : ""}`,
                      verifyUrl: `https://www.shodan.io/host/${ip}`
                    }
                  });
                } else {
                  const existing = observations.find(
                    (o) => o.assetId === existingId
                  );
                  if (existing && existing.evidence) {
                    const existingVulns = existing.evidence.vulns || [];
                    const mergedVulns = Array.from(
                      /* @__PURE__ */ new Set([...existingVulns, ...svcVulns])
                    );
                    existing.evidence.vulns = mergedVulns;
                    existing.evidence.host_vulns = hostVulns;
                    existing.evidence.all_ports = allPorts;
                    if (cpe.length > 0) {
                      existing.evidence.cpe = cpe;
                    }
                    for (const v of svcVulns) {
                      if (!existing.tags?.includes(`cve:${v}`)) {
                        existing.tags?.push(`cve:${v}`);
                      }
                    }
                  }
                }
              }
            }
            if (hostVulns.length > 0) {
              observations.push({
                assetId: makeAssetId2(domain, `${ip}:vulns`, "shodan_vulns"),
                domain,
                assetType: "ip",
                name: primaryName,
                ip,
                source: "shodan",
                observedAt: now,
                tags: [
                  "shodan_vuln_summary",
                  ...hostVulns.map((v) => `cve:${v}`),
                  ...allPorts.map((p) => `port:${p}`)
                ],
                evidence: {
                  vulns: hostVulns,
                  vuln_count: hostVulns.length,
                  all_ports: allPorts,
                  os: hostOs,
                  hostnames: hostHostnames,
                  verification_source: "shodan_host_detail",
                  verified: true
                },
                attribution: {
                  provider: "Shodan (Vulnerability Detection)",
                  url: `https://www.shodan.io/host/${ip}`,
                  method: `Shodan detected ${hostVulns.length} known CVEs on ${ip} via banner analysis: ${hostVulns.slice(0, 5).join(", ")}${hostVulns.length > 5 ? ` (+${hostVulns.length - 5} more)` : ""}`,
                  verifyUrl: `https://www.shodan.io/host/${ip}`
                }
              });
            }
          } catch (err) {
            if (err.status === 429) {
              rateLimited = true;
              break;
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
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/wayback.ts
import { createHash as createHash3 } from "crypto";
function makeAssetId3(domain, name, source) {
  return createHash3("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function extractSubdomain(urlStr, domain) {
  try {
    const normalized = urlStr.startsWith("http") ? urlStr : `https://${urlStr}`;
    const parsed = new URL(normalized);
    const host = parsed.hostname.toLowerCase();
    if (host.endsWith(`.${domain}`) || host === domain) {
      return host;
    }
  } catch {
  }
  return null;
}
var waybackConnector;
var init_wayback = __esm({
  "server/lib/passive/wayback.ts"() {
    "use strict";
    waybackConnector = {
      name: "wayback",
      description: "Internet Archive CDX search \u2014 discovers historical URLs and subdomains from the Wayback Machine's web crawl archive",
      requiresApiKey: false,
      freeUrl: "https://web.archive.org",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 45e3;
        const maxResults = config?.maxResults ?? 2e3;
        try {
          const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=${maxResults}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let rows;
          try {
            const res = await fetch(url, { signal: controller.signal });
            if (!res.ok) throw new Error(`Wayback CDX returned ${res.status}`);
            rows = await res.json();
          } finally {
            clearTimeout(timer);
          }
          if (rows.length <= 1) {
            return { connector: "wayback", domain, observations: [], errors: [], durationMs: Date.now() - start, rateLimited: false };
          }
          const now = /* @__PURE__ */ new Date();
          const seenSubdomains = /* @__PURE__ */ new Set();
          const seenUrls = /* @__PURE__ */ new Set();
          for (let i = 1; i < rows.length; i++) {
            const [original, timestamp, statusCode, mimeType] = rows[i];
            if (!original) continue;
            const subdomain = extractSubdomain(original, domain);
            if (!subdomain) continue;
            let archivedAt;
            if (timestamp && timestamp.length >= 8) {
              const y = timestamp.slice(0, 4);
              const m = timestamp.slice(4, 6);
              const d = timestamp.slice(6, 8);
              const h = timestamp.slice(8, 10) || "00";
              const mi = timestamp.slice(10, 12) || "00";
              const s = timestamp.slice(12, 14) || "00";
              archivedAt = /* @__PURE__ */ new Date(`${y}-${m}-${d}T${h}:${mi}:${s}Z`);
            }
            if (!seenSubdomains.has(subdomain)) {
              seenSubdomains.add(subdomain);
              observations.push({
                assetId: makeAssetId3(domain, subdomain, "wayback_sub"),
                domain,
                assetType: "subdomain",
                name: subdomain,
                source: "wayback",
                observedAt: now,
                firstSeen: archivedAt,
                tags: ["historical", "web_archive"],
                evidence: {
                  first_archived: timestamp,
                  sample_url: original
                },
                attribution: {
                  provider: "Wayback Machine (Internet Archive)",
                  url: `https://web.archive.org/web/*/${subdomain}`,
                  method: `Wayback Machine CDX index search \u2014 found historical web crawl records for ${subdomain} in the Internet Archive`,
                  verifyUrl: `https://web.archive.org/web/*/${subdomain}`
                }
              });
            }
            const urlKey = original.toLowerCase();
            if (!seenUrls.has(urlKey) && seenUrls.size < 500) {
              seenUrls.add(urlKey);
              observations.push({
                assetId: makeAssetId3(domain, urlKey, "wayback_url"),
                domain,
                assetType: "url",
                name: original,
                source: "wayback",
                observedAt: now,
                firstSeen: archivedAt,
                tags: [
                  "historical",
                  `status:${statusCode}`,
                  `mime:${mimeType}`,
                  ...original.match(/admin|console|mgmt|login|auth/i) ? ["admin_path"] : [],
                  ...original.match(/api|graphql|swagger/i) ? ["api_path"] : [],
                  ...original.match(/dev|test|stage|staging|qa/i) ? ["staging_path"] : []
                ],
                evidence: {
                  original_url: original,
                  archived_timestamp: timestamp,
                  status_code: statusCode,
                  mime_type: mimeType,
                  wayback_url: `https://web.archive.org/web/${timestamp}/${original}`
                },
                attribution: {
                  provider: "Wayback Machine (Internet Archive)",
                  url: `https://web.archive.org/web/${timestamp}/${original}`,
                  method: `Historical URL discovered in Wayback Machine CDX index \u2014 page was archived on ${timestamp} with HTTP ${statusCode}`,
                  verifyUrl: `https://web.archive.org/web/${timestamp}/${original}`
                }
              });
            }
          }
        } catch (err) {
          if (err.name === "AbortError") {
            errors.push("Wayback CDX request timed out (archive may be slow)");
          } else {
            errors.push(`Wayback error: ${err.message}`);
          }
        }
        return {
          connector: "wayback",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/censys.ts
import { createHash as createHash4 } from "crypto";
function makeAssetId4(domain, name, source) {
  return createHash4("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var PLATFORM_BASE, censysConnector;
var init_censys = __esm({
  "server/lib/passive/censys.ts"() {
    "use strict";
    PLATFORM_BASE = "https://api.platform.censys.io";
    censysConnector = {
      name: "censys",
      description: "Internet-wide scan database \u2014 discovers hosts, open ports, and certificates from Censys continuous scanning",
      requiresApiKey: true,
      freeUrl: "https://platform.censys.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiId = config?.apiId;
        const apiSecret = config?.apiSecret;
        if (!apiSecret) {
          return { connector: "censys", domain, observations: [], errors: ["CENSYS_API_SECRET (PAT) not configured \u2014 skipping Censys connector"], durationMs: Date.now() - start, rateLimited: false };
        }
        try {
          const headers = {
            Authorization: `Bearer ${apiSecret}`,
            "Content-Type": "application/json",
            Accept: "application/json"
          };
          if (apiId) {
            headers["X-Organization-ID"] = apiId;
          }
          const body = JSON.stringify({
            query: `host.dns.names: "${domain}"`,
            page_size: 100
          });
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let data;
          try {
            const res = await fetch(`${PLATFORM_BASE}/v3/global/search/query`, {
              method: "POST",
              headers,
              body,
              signal: controller.signal
            });
            if (res.status === 401 || res.status === 403) {
              const errBody = await res.text().catch(() => "");
              return { connector: "censys", domain, observations: [], errors: [`Censys API credentials invalid (${res.status}): ${errBody.substring(0, 100)}`], durationMs: Date.now() - start, rateLimited: false };
            }
            if (res.status === 429) return { connector: "censys", domain, observations: [], errors: ["Censys rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
            if (res.status === 422) {
              const errBody = await res.json().catch(() => ({}));
              return { connector: "censys", domain, observations: [], errors: [`Censys query error: ${JSON.stringify(errBody.errors || errBody).substring(0, 200)}`], durationMs: Date.now() - start, rateLimited: false };
            }
            if (!res.ok) throw new Error(`Censys returned ${res.status}`);
            data = await res.json();
          } finally {
            clearTimeout(timer);
          }
          const now = /* @__PURE__ */ new Date();
          const hits = data?.result?.hits || [];
          for (const hit of hits) {
            const hostData = hit.host_v1?.resource || hit;
            const ip = hostData.ip;
            if (!ip) continue;
            const services = hostData.services || [];
            const asn = hostData.autonomous_system?.asn;
            const asnOrg = hostData.autonomous_system?.name || hostData.autonomous_system?.description;
            const location = hostData.location;
            if (services.length === 0) {
              observations.push({
                assetId: makeAssetId4(domain, ip, "censys"),
                domain,
                assetType: "ip",
                name: ip,
                ip,
                asn,
                source: "censys",
                observedAt: now,
                tags: [...asnOrg ? [`org:${asnOrg}`] : []],
                evidence: {
                  asn,
                  asn_org: asnOrg,
                  location,
                  service_count: hostData.service_count
                },
                attribution: {
                  provider: "Censys (Internet-Wide Scan Database)",
                  url: `https://platform.censys.io/hosts/${ip}`,
                  method: `Censys Platform API v3 \u2014 found ${ip} via DNS name matching for ${domain}`,
                  verifyUrl: `https://platform.censys.io/hosts/${ip}`
                }
              });
              continue;
            }
            for (const svc of services) {
              const port = svc.port;
              const transport = svc.transport_protocol || "TCP";
              const serviceName = svc.protocol || svc.service_name || "unknown";
              const certNames = [];
              if (svc.cert?.parsed) {
                const parsed = svc.cert.parsed;
                const subjectCN = parsed.subject?.common_name;
                if (subjectCN) certNames.push(...Array.isArray(subjectCN) ? subjectCN : [subjectCN]);
                const sans = parsed.extensions?.subject_alt_name?.dns_names;
                if (sans) certNames.push(...sans);
              }
              observations.push({
                assetId: makeAssetId4(domain, `${ip}:${port}`, "censys"),
                domain,
                assetType: "ip",
                name: ip,
                ip,
                asn,
                source: "censys",
                observedAt: now,
                tags: [
                  `port:${port}`,
                  `transport:${transport}`,
                  `service:${serviceName}`,
                  ...asnOrg ? [`org:${asnOrg}`] : [],
                  ...certNames.length > 0 ? [`cert_names:${certNames.slice(0, 5).join(",")}`] : []
                ],
                evidence: {
                  port,
                  transport,
                  service_name: serviceName,
                  asn,
                  asn_org: asnOrg,
                  location,
                  operating_system: hostData.operating_system,
                  software: svc.software,
                  cert_names: certNames.length > 0 ? certNames : void 0,
                  banner_hash: svc.banner_hash_sha256
                },
                attribution: {
                  provider: "Censys (Internet-Wide Scan Database)",
                  url: `https://platform.censys.io/hosts/${ip}`,
                  method: `Censys Platform API v3 \u2014 found ${ip}:${port} with ${serviceName} service via DNS name matching for ${domain}`,
                  verifyUrl: `https://platform.censys.io/hosts/${ip}`
                }
              });
            }
          }
          if (data?.result?.next_page_token && observations.length < 500) {
            try {
              const page2Body = JSON.stringify({
                query: `host.dns.names: "${domain}"`,
                page_size: 100,
                page_token: data.result.next_page_token
              });
              const controller2 = new AbortController();
              const timer2 = setTimeout(() => controller2.abort(), timeout);
              try {
                const res2 = await fetch(`${PLATFORM_BASE}/v3/global/search/query`, {
                  method: "POST",
                  headers,
                  body: page2Body,
                  signal: controller2.signal
                });
                if (res2.ok) {
                  const data2 = await res2.json();
                  const hits2 = data2?.result?.hits || [];
                  for (const hit of hits2) {
                    const hostData = hit.host_v1?.resource || hit;
                    const ip = hostData.ip;
                    if (!ip) continue;
                    const services = hostData.services || [];
                    const asn = hostData.autonomous_system?.asn;
                    const asnOrg = hostData.autonomous_system?.name || hostData.autonomous_system?.description;
                    if (services.length === 0) {
                      observations.push({
                        assetId: makeAssetId4(domain, ip, "censys"),
                        domain,
                        assetType: "ip",
                        name: ip,
                        ip,
                        asn,
                        source: "censys",
                        observedAt: now,
                        tags: [...asnOrg ? [`org:${asnOrg}`] : []],
                        evidence: { asn, asn_org: asnOrg },
                        attribution: { provider: "Censys (Internet-Wide Scan Database)", url: `https://platform.censys.io/hosts/${ip}`, method: `Censys Platform API v3 \u2014 page 2`, verifyUrl: `https://platform.censys.io/hosts/${ip}` }
                      });
                      continue;
                    }
                    for (const svc of services) {
                      observations.push({
                        assetId: makeAssetId4(domain, `${ip}:${svc.port}`, "censys"),
                        domain,
                        assetType: "ip",
                        name: ip,
                        ip,
                        asn,
                        source: "censys",
                        observedAt: now,
                        tags: [`port:${svc.port}`, `transport:${svc.transport_protocol || "TCP"}`, `service:${svc.protocol || "unknown"}`, ...asnOrg ? [`org:${asnOrg}`] : []],
                        evidence: { port: svc.port, transport: svc.transport_protocol, service_name: svc.protocol, asn, asn_org: asnOrg },
                        attribution: { provider: "Censys (Internet-Wide Scan Database)", url: `https://platform.censys.io/hosts/${ip}`, method: `Censys Platform API v3 \u2014 page 2`, verifyUrl: `https://platform.censys.io/hosts/${ip}` }
                      });
                    }
                  }
                }
              } finally {
                clearTimeout(timer2);
              }
            } catch {
            }
          }
        } catch (err) {
          errors.push(`Censys error: ${err.message}`);
        }
        return { connector: "censys", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/urlscan.ts
import { createHash as createHash5 } from "crypto";
function makeAssetId5(domain, name, source) {
  return createHash5("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var urlscanConnector;
var init_urlscan = __esm({
  "server/lib/passive/urlscan.ts"() {
    "use strict";
    urlscanConnector = {
      name: "urlscan",
      description: "Website intelligence search \u2014 discovers page metadata, technologies, and IPs from urlscan.io community scans",
      requiresApiKey: false,
      freeUrl: "https://urlscan.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        try {
          const headers = { "Content-Type": "application/json" };
          if (apiKey) headers["API-Key"] = apiKey;
          const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let data;
          try {
            const res = await fetch(url, { headers, signal: controller.signal });
            if (res.status === 429) return { connector: "urlscan", domain, observations: [], errors: ["urlscan.io rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
            if (!res.ok) throw new Error(`urlscan.io returned ${res.status}`);
            data = await res.json();
          } finally {
            clearTimeout(timer);
          }
          const now = /* @__PURE__ */ new Date();
          const results = data?.results || [];
          const seenPages = /* @__PURE__ */ new Set();
          for (const result of results) {
            const page = result.page || {};
            const task = result.task || {};
            const pageUrl = page.url || task.url || "";
            const pageDomain = page.domain || "";
            const ip = page.ip || "";
            const server = page.server || "";
            const asn = page.asn ? parseInt(page.asn.replace("AS", ""), 10) : void 0;
            if (!pageDomain.endsWith(`.${domain}`) && pageDomain !== domain) continue;
            const pageKey = `${pageDomain}|${pageUrl}`;
            if (seenPages.has(pageKey)) continue;
            seenPages.add(pageKey);
            observations.push({
              assetId: makeAssetId5(domain, pageKey, "urlscan"),
              domain,
              assetType: "url",
              name: pageUrl,
              ip: ip || void 0,
              asn: isNaN(asn) ? void 0 : asn,
              source: "urlscan",
              observedAt: now,
              firstSeen: task.time ? new Date(task.time) : void 0,
              tags: [
                ...server ? [`server:${server}`] : [],
                ...page.tlsIssuer ? ["tls_enabled"] : [],
                `status:${page.status || "unknown"}`
              ],
              evidence: {
                page_url: pageUrl,
                page_domain: pageDomain,
                ip,
                server,
                tls_issuer: page.tlsIssuer,
                asn_name: page.asnname,
                status: page.status,
                scan_id: result._id,
                screenshot: result.screenshot
              },
              attribution: {
                provider: "urlscan.io (Website Intelligence)",
                url: `https://urlscan.io/result/${result._id}/`,
                method: `urlscan.io community scan database \u2014 found previously scanned page at ${pageUrl} with server ${server || "unknown"}`,
                verifyUrl: `https://urlscan.io/result/${result._id}/`
              }
            });
            if (pageDomain !== domain) {
              observations.push({
                assetId: makeAssetId5(domain, pageDomain, "urlscan_sub"),
                domain,
                assetType: "subdomain",
                name: pageDomain,
                ip: ip || void 0,
                source: "urlscan",
                observedAt: now,
                tags: ["urlscan_discovered"],
                evidence: { resolved_ip: ip, server, scan_id: result._id },
                attribution: {
                  provider: "urlscan.io (Website Intelligence)",
                  url: `https://urlscan.io/result/${result._id}/`,
                  method: `Subdomain discovered via urlscan.io community scans \u2014 ${pageDomain} was scanned and found resolving to ${ip}`,
                  verifyUrl: `https://urlscan.io/search/#domain:${pageDomain}`
                }
              });
            }
          }
        } catch (err) {
          errors.push(`urlscan.io error: ${err.message}`);
        }
        return { connector: "urlscan", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/rdap.ts
import { createHash as createHash6 } from "crypto";
function makeAssetId6(domain, name, source) {
  return createHash6("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var rdapConnector;
var init_rdap = __esm({
  "server/lib/passive/rdap.ts"() {
    "use strict";
    rdapConnector = {
      name: "rdap",
      description: "Domain registration data via RDAP \u2014 discovers registrar, nameservers, registration dates, and domain status",
      requiresApiKey: false,
      freeUrl: "https://rdap.org",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        try {
          const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let data;
          try {
            const res = await fetch(url, { signal: controller.signal, headers: { Accept: "application/rdap+json" } });
            if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
            data = await res.json();
          } finally {
            clearTimeout(timer);
          }
          const now = /* @__PURE__ */ new Date();
          const events = {};
          for (const evt of data.events || []) {
            if (evt.eventAction && evt.eventDate) {
              events[evt.eventAction] = evt.eventDate;
            }
          }
          const nameservers = [];
          for (const ns of data.nameservers || []) {
            const nsName = ns.ldhName || ns.unicodeName;
            if (nsName) {
              nameservers.push(nsName.toLowerCase());
              observations.push({
                assetId: makeAssetId6(domain, nsName, "rdap_ns"),
                domain,
                assetType: "ns",
                name: nsName.toLowerCase(),
                source: "rdap",
                observedAt: now,
                tags: ["nameserver", "rdap"],
                evidence: { nameserver: nsName, ip_addresses: ns.ipAddresses },
                attribution: {
                  provider: "RDAP (Registration Data Access Protocol)",
                  url: `https://rdap.org/domain/${domain}`,
                  method: `RDAP query for ${domain} \u2014 nameserver ${nsName} listed in authoritative registration data`,
                  verifyUrl: `https://rdap.org/domain/${domain}`
                }
              });
            }
          }
          let registrar = "";
          for (const entity of data.entities || []) {
            if ((entity.roles || []).includes("registrar")) {
              registrar = entity.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || entity.handle || "";
            }
          }
          observations.push({
            assetId: makeAssetId6(domain, domain, "rdap"),
            domain,
            assetType: "subdomain",
            name: domain,
            source: "rdap",
            observedAt: now,
            firstSeen: events.registration ? new Date(events.registration) : void 0,
            lastSeen: events.last_changed ? new Date(events.last_changed) : void 0,
            tags: [
              "registration_data",
              ...data.status || [],
              ...registrar ? [`registrar:${registrar}`] : []
            ],
            evidence: {
              handle: data.handle,
              ldhName: data.ldhName,
              status: data.status,
              registrar,
              nameservers,
              events,
              secureDNS: data.secureDNS
            },
            attribution: {
              provider: "RDAP (Registration Data Access Protocol)",
              url: `https://rdap.org/domain/${domain}`,
              method: `RDAP domain lookup \u2014 queried authoritative registrar for ${domain} registration data including registrar, nameservers, and status`,
              verifyUrl: `https://rdap.org/domain/${domain}`
            }
          });
        } catch (err) {
          errors.push(`RDAP error: ${err.message}`);
        }
        return { connector: "rdap", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/ripestat.ts
import { createHash as createHash7 } from "crypto";
import { resolve4 } from "dns/promises";
function makeAssetId7(domain, name, source) {
  return createHash7("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var ripestatConnector;
var init_ripestat = __esm({
  "server/lib/passive/ripestat.ts"() {
    "use strict";
    ripestatConnector = {
      name: "ripestat",
      description: "Regional Internet Registry data \u2014 discovers ASN, announced prefixes, and routing information for domain IPs via RIPE NCC",
      requiresApiKey: false,
      freeUrl: "https://stat.ripe.net",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 2e4;
        try {
          let ips = [];
          try {
            ips = await resolve4(domain);
          } catch {
            errors.push(`Could not resolve ${domain} to IP addresses`);
            return { connector: "ripestat", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const now = /* @__PURE__ */ new Date();
          for (const ip of ips.slice(0, 5)) {
            try {
              const prefixUrl = `https://stat.ripe.net/data/prefix-overview/data.json?resource=${ip}&sourceapp=caldera-dashboard`;
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), timeout);
              let prefixData;
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
                  assetId: makeAssetId7(domain, `${ip}|asn:${asn}`, "ripestat"),
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
                    ...holder ? [`holder:${holder}`] : []
                  ],
                  evidence: {
                    ip,
                    asn,
                    holder,
                    prefix,
                    block_name: block.name,
                    block_desc: block.desc,
                    is_less_specific: prefixData?.data?.is_less_specific
                  },
                  attribution: {
                    provider: "RIPEstat (RIPE NCC Data API)",
                    url: `https://stat.ripe.net/widget/prefix-overview#w.resource=${ip}`,
                    method: `RIPEstat prefix overview \u2014 resolved ${domain} to ${ip}, found AS${asn} (${holder}) announcing prefix ${prefix}`,
                    verifyUrl: `https://stat.ripe.net/widget/prefix-overview#w.resource=${ip}`
                  }
                });
              }
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
                      assetId: makeAssetId7(domain, `${ip}|net:${netPrefix}`, "ripestat_net"),
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
                        method: `RIPEstat network info \u2014 ${ip} belongs to prefix ${netPrefix}`,
                        verifyUrl: `https://stat.ripe.net/widget/network-info#w.resource=${ip}`
                      }
                    });
                  }
                }
              } finally {
                clearTimeout(timer2);
              }
            } catch (err) {
              errors.push(`RIPEstat error for ${ip}: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`RIPEstat error: ${err.message}`);
        }
        return { connector: "ripestat", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/securitytrails.ts
import { createHash as createHash8 } from "crypto";
function makeAssetId8(domain, name, source) {
  return createHash8("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function fetchST(path, apiKey, timeout) {
  const url = `https://api.securitytrails.com/v1/${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { APIKEY: apiKey, Accept: "application/json" },
      signal: controller.signal
    });
    if (res.status === 401) throw new Error("SecurityTrails API key invalid");
    if (res.status === 429) throw new Error("RATE_LIMITED");
    if (!res.ok) throw new Error(`SecurityTrails returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
var securitytrailsConnector;
var init_securitytrails = __esm({
  "server/lib/passive/securitytrails.ts"() {
    "use strict";
    securitytrailsConnector = {
      name: "securitytrails",
      description: "DNS & domain intelligence \u2014 discovers subdomains, DNS records, and associated domains from SecurityTrails' 3B+ record dataset",
      requiresApiKey: true,
      freeUrl: "https://securitytrails.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        if (!apiKey) {
          return { connector: "securitytrails", domain, observations: [], errors: ["SECURITYTRAILS_API_KEY not configured \u2014 skipping SecurityTrails connector"], durationMs: Date.now() - start, rateLimited: false };
        }
        const now = /* @__PURE__ */ new Date();
        let rateLimited = false;
        try {
          const subData = await fetchST(`domain/${domain}/subdomains?children_only=false`, apiKey, timeout);
          const subdomains = subData?.subdomains || [];
          for (const sub of subdomains) {
            const fqdn = `${sub}.${domain}`.toLowerCase();
            observations.push({
              assetId: makeAssetId8(domain, fqdn, "securitytrails_sub"),
              domain,
              assetType: "subdomain",
              name: fqdn,
              source: "securitytrails",
              observedAt: now,
              tags: ["dns_intelligence", "securitytrails"],
              evidence: { subdomain: sub, endpoint: "subdomains" },
              attribution: {
                provider: "SecurityTrails (DNS Intelligence)",
                url: `https://securitytrails.com/domain/${domain}/dns`,
                method: `SecurityTrails Subdomains API \u2014 enumerated subdomains for ${domain} from SecurityTrails' DNS crawl dataset`,
                verifyUrl: `https://securitytrails.com/domain/${domain}/dns`
              }
            });
          }
        } catch (err) {
          if (err.message === "RATE_LIMITED") {
            rateLimited = true;
            errors.push("SecurityTrails rate limit exceeded on subdomains endpoint");
          } else errors.push(`SecurityTrails subdomains error: ${err.message}`);
        }
        try {
          const details = await fetchST(`domain/${domain}`, apiKey, timeout);
          const currentDns = details?.current_dns || {};
          for (const record of currentDns.a?.values || []) {
            const ip = record.ip;
            if (ip) {
              observations.push({
                assetId: makeAssetId8(domain, `${domain}|A|${ip}`, "securitytrails_a"),
                domain,
                assetType: "ip",
                name: `${domain} \u2192 ${ip}`,
                ip,
                source: "securitytrails",
                observedAt: now,
                tags: ["dns_a_record", "current_dns"],
                evidence: { record_type: "A", ip, first_seen: currentDns.a?.first_seen },
                attribution: {
                  provider: "SecurityTrails (DNS Intelligence)",
                  url: `https://securitytrails.com/domain/${domain}/dns`,
                  method: `SecurityTrails Domain Details API \u2014 current A record for ${domain} points to ${ip}`,
                  verifyUrl: `https://securitytrails.com/domain/${domain}/dns`
                }
              });
            }
          }
          for (const record of currentDns.mx?.values || []) {
            const mx = record.hostname || record.host;
            if (mx) {
              observations.push({
                assetId: makeAssetId8(domain, `${domain}|MX|${mx}`, "securitytrails_mx"),
                domain,
                assetType: "mx",
                name: mx,
                source: "securitytrails",
                observedAt: now,
                tags: ["dns_mx_record", "mail_server"],
                evidence: { record_type: "MX", hostname: mx, priority: record.priority },
                attribution: {
                  provider: "SecurityTrails (DNS Intelligence)",
                  url: `https://securitytrails.com/domain/${domain}/dns`,
                  method: `SecurityTrails Domain Details API \u2014 MX record for ${domain} points to ${mx}`,
                  verifyUrl: `https://securitytrails.com/domain/${domain}/dns`
                }
              });
            }
          }
          for (const record of currentDns.ns?.values || []) {
            const ns = record.nameserver || record.host;
            if (ns) {
              observations.push({
                assetId: makeAssetId8(domain, `${domain}|NS|${ns}`, "securitytrails_ns"),
                domain,
                assetType: "ns",
                name: ns,
                source: "securitytrails",
                observedAt: now,
                tags: ["dns_ns_record", "nameserver"],
                evidence: { record_type: "NS", nameserver: ns },
                attribution: {
                  provider: "SecurityTrails (DNS Intelligence)",
                  url: `https://securitytrails.com/domain/${domain}/dns`,
                  method: `SecurityTrails Domain Details API \u2014 NS record for ${domain} delegated to ${ns}`,
                  verifyUrl: `https://securitytrails.com/domain/${domain}/dns`
                }
              });
            }
          }
          for (const record of currentDns.txt?.values || []) {
            const txt = record.value;
            if (txt) {
              observations.push({
                assetId: makeAssetId8(domain, `${domain}|TXT|${txt.slice(0, 50)}`, "securitytrails_txt"),
                domain,
                assetType: "txt",
                name: txt.length > 80 ? txt.slice(0, 80) + "..." : txt,
                source: "securitytrails",
                observedAt: now,
                tags: [
                  "dns_txt_record",
                  ...txt.includes("v=spf") ? ["spf"] : [],
                  ...txt.includes("v=DMARC") ? ["dmarc"] : [],
                  ...txt.includes("google-site-verification") ? ["google_verified"] : [],
                  ...txt.includes("MS=") ? ["microsoft_verified"] : []
                ],
                evidence: { record_type: "TXT", value: txt },
                attribution: {
                  provider: "SecurityTrails (DNS Intelligence)",
                  url: `https://securitytrails.com/domain/${domain}/dns`,
                  method: `SecurityTrails Domain Details API \u2014 TXT record for ${domain}`,
                  verifyUrl: `https://securitytrails.com/domain/${domain}/dns`
                }
              });
            }
          }
        } catch (err) {
          if (err.message === "RATE_LIMITED") {
            rateLimited = true;
            errors.push("SecurityTrails rate limit exceeded on domain details endpoint");
          } else errors.push(`SecurityTrails domain details error: ${err.message}`);
        }
        return { connector: "securitytrails", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }
    };
  }
});

// server/lib/passive/dehashed.ts
import { createHash as createHash9 } from "crypto";
function makeAssetId9(domain, name, source) {
  return createHash9("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function first(arr) {
  return arr && arr.length > 0 ? arr[0] : void 0;
}
function hasValue(arr) {
  return !!arr && arr.some((v) => v && v.trim().length > 0);
}
function classifyCredentialSourceDehashed(targetDomain, breachName, email) {
  const baseDomain = targetDomain.replace(/^www\./, "").toLowerCase();
  const orgName = baseDomain.split(".")[0];
  const breachLower = (breachName || "").toLowerCase();
  if (breachLower.includes(baseDomain)) {
    return {
      type: "first_party",
      confidence: 90,
      reasoning: `Breach "${breachName}" directly references target domain ${baseDomain} \u2014 this was a breach of the target's own systems`
    };
  }
  if (orgName.length > 3 && breachLower.includes(orgName)) {
    const idx = breachLower.indexOf(orgName);
    const before = idx > 0 ? breachLower[idx - 1] : " ";
    const after = idx + orgName.length < breachLower.length ? breachLower[idx + orgName.length] : " ";
    if (/[\s\-_.,]/.test(before) && /[\s\-_.,]/.test(after)) {
      return {
        type: "first_party",
        confidence: 75,
        reasoning: `Breach "${breachName}" matches organization name "${orgName}" \u2014 likely a breach of the target's own systems`
      };
    }
  }
  const thirdPartyServices = [
    "linkedin",
    "facebook",
    "adobe",
    "dropbox",
    "myspace",
    "tumblr",
    "canva",
    "zynga",
    "dubsmash",
    "myfitnesspal",
    "chegg",
    "animoto",
    "evite",
    "coffeemeetsbagel",
    "500px",
    "sharelatex",
    "verifications.io",
    "collection #",
    "antipublic",
    "exploit.in",
    "combolist",
    "naz.api",
    "telegram",
    "discord",
    "twitter",
    "snapchat",
    "instagram",
    "tiktok",
    "spotify",
    "netflix",
    "hulu",
    "lastfm",
    "last.fm",
    "dailymotion",
    "bitly",
    "imgur",
    "patreon",
    "kickstarter",
    "wattpad",
    "mathway",
    "livejournal",
    "habbo",
    "neopets",
    "gaia online",
    "xsplit",
    "deezer",
    "appen",
    "gravatar",
    "pixlr",
    "123rf",
    "stockx",
    "wyzant",
    "poshmark",
    "minted",
    "shein",
    "slickdeals",
    "marriott",
    "equifax",
    "experian",
    "t-mobile",
    "att",
    "verizon",
    "yahoo",
    "hotmail",
    "gmail",
    "outlook",
    "aol"
  ];
  for (const svc of thirdPartyServices) {
    if (breachLower.includes(svc)) {
      return {
        type: "third_party",
        confidence: 95,
        reasoning: `Breach "${breachName}" is a known third-party service (${svc}) \u2014 employee used their ${baseDomain} email on this external service`
      };
    }
  }
  const comboIndicators = ["combo", "collection", "compilation", "aggregated", "antipublic", "exploit.in", "naz.api", "stealer log", "stealer_log"];
  for (const indicator of comboIndicators) {
    if (breachLower.includes(indicator)) {
      return {
        type: "third_party",
        confidence: 85,
        reasoning: `Breach "${breachName}" is an aggregated credential dump \u2014 credentials harvested from multiple third-party sources`
      };
    }
  }
  return {
    type: "unknown",
    confidence: 40,
    reasoning: `Unable to determine if "${breachName}" is a direct breach of ${baseDomain} or a third-party service \u2014 manual review recommended`
  };
}
var DEHASHED_SEARCH_URL, dehashedConnector;
var init_dehashed = __esm({
  "server/lib/passive/dehashed.ts"() {
    "use strict";
    DEHASHED_SEARCH_URL = "https://api.dehashed.com/v2/search";
    dehashedConnector = {
      name: "dehashed",
      description: "Breach intelligence & domain mapping \u2014 discovers subdomains, credential exposures, email patterns, and IP associations from 15B+ breach records",
      requiresApiKey: true,
      freeUrl: "https://dehashed.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        const maxResults = config?.maxResults ?? 1e4;
        if (!apiKey) {
          return {
            connector: "dehashed",
            domain,
            observations: [],
            errors: ["DEHASHED_API_KEY not configured \u2014 skipping Dehashed connector"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        let rateLimited = false;
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          const size = Math.min(maxResults, 1e4);
          let data;
          try {
            const res = await fetch(DEHASHED_SEARCH_URL, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Dehashed-Api-Key": apiKey
              },
              body: JSON.stringify({
                query: `domain:${domain}`,
                page: 1,
                size,
                de_dupe: true
              }),
              signal: controller.signal
            });
            if (res.status === 401 || res.status === 403) {
              const body = await res.text().catch(() => "");
              return {
                connector: "dehashed",
                domain,
                observations: [],
                errors: [`Dehashed API credentials invalid (${res.status}): ${body} \u2014 check DEHASHED_API_KEY. The old v1 Basic Auth API is deprecated; use the v4 API key from app.dehashed.com/documentation/api`],
                durationMs: Date.now() - start,
                rateLimited: false
              };
            }
            if (res.status === 429) {
              return {
                connector: "dehashed",
                domain,
                observations: [],
                errors: ["Dehashed rate limit exceeded \u2014 max 10 requests/second"],
                durationMs: Date.now() - start,
                rateLimited: true
              };
            }
            if (res.status === 402) {
              return {
                connector: "dehashed",
                domain,
                observations: [],
                errors: ["Dehashed API credits exhausted \u2014 purchase more at dehashed.com"],
                durationMs: Date.now() - start,
                rateLimited: false
              };
            }
            if (res.status === 400) {
              const body = await res.text().catch(() => "");
              return {
                connector: "dehashed",
                domain,
                observations: [],
                errors: [`Dehashed bad request (400): ${body}`],
                durationMs: Date.now() - start,
                rateLimited: false
              };
            }
            if (!res.ok) {
              throw new Error(`Dehashed returned ${res.status}: ${await res.text().catch(() => "unknown")}`);
            }
            data = await res.json();
          } finally {
            clearTimeout(timer);
          }
          if (data.error) {
            return {
              connector: "dehashed",
              domain,
              observations: [],
              errors: [`Dehashed API error: ${data.error}`],
              durationMs: Date.now() - start,
              rateLimited: false
            };
          }
          const entries = data.entries || [];
          const now = /* @__PURE__ */ new Date();
          const seenSubdomains = /* @__PURE__ */ new Set();
          const seenIPs = /* @__PURE__ */ new Set();
          const seenBreaches = /* @__PURE__ */ new Set();
          const seenCredentials = /* @__PURE__ */ new Set();
          const breachEmailCounts = /* @__PURE__ */ new Map();
          const breachCredCounts = /* @__PURE__ */ new Map();
          for (const entry of entries) {
            const dbName = entry.database_name || "unknown";
            breachEmailCounts.set(dbName, (breachEmailCounts.get(dbName) || 0) + 1);
            const hasPassword = hasValue(entry.password);
            const hasHash = hasValue(entry.hashed_password);
            if (hasPassword || hasHash) {
              breachCredCounts.set(dbName, (breachCredCounts.get(dbName) || 0) + 1);
            }
          }
          for (const entry of entries) {
            const emails = entry.email || [];
            for (const email of emails) {
              if (!email) continue;
              const emailDomain = email.split("@")[1]?.toLowerCase();
              if (emailDomain && (emailDomain === domain || emailDomain.endsWith(`.${domain}`))) {
                if (!seenSubdomains.has(emailDomain) && emailDomain !== domain.toLowerCase()) {
                  seenSubdomains.add(emailDomain);
                  observations.push({
                    assetId: makeAssetId9(domain, emailDomain, "dehashed_subdomain"),
                    domain,
                    assetType: "subdomain",
                    name: emailDomain,
                    source: "dehashed",
                    observedAt: now,
                    tags: ["breach_derived", "email_domain", `breach:${entry.database_name || "unknown"}`],
                    evidence: {
                      discovery_method: "email_domain_extraction",
                      sample_email_pattern: email.replace(/^[^@]+/, "***"),
                      database_name: entry.database_name
                    },
                    attribution: {
                      provider: "Dehashed (Breach Intelligence)",
                      url: "https://dehashed.com",
                      method: `Subdomain discovered via email domain extraction from breach records \u2014 ${emailDomain} found in ${entry.database_name || "unknown"} breach database`,
                      verifyUrl: "https://dehashed.com"
                    }
                  });
                }
              }
            }
            const ips = entry.ip_address || [];
            for (const rawIp of ips) {
              if (!rawIp) continue;
              const ip = rawIp.trim();
              if (ip.length > 0 && !seenIPs.has(ip)) {
                seenIPs.add(ip);
                observations.push({
                  assetId: makeAssetId9(domain, ip, "dehashed_ip"),
                  domain,
                  assetType: "ip",
                  name: ip,
                  ip,
                  source: "dehashed",
                  observedAt: now,
                  tags: ["breach_derived", "ip_association", `breach:${entry.database_name || "unknown"}`],
                  evidence: {
                    discovery_method: "breach_ip_association",
                    database_name: entry.database_name,
                    associated_email: first(entry.email) ? first(entry.email).replace(/^[^@]+/, "***@") + (first(entry.email).split("@")[1] || "") : void 0
                  },
                  attribution: {
                    provider: "Dehashed (Breach Intelligence)",
                    url: "https://dehashed.com",
                    method: `IP address associated with ${domain} discovered in breach records from ${entry.database_name || "unknown"} database`,
                    verifyUrl: "https://dehashed.com"
                  }
                });
              }
            }
            const entryEmails = entry.email || [];
            for (const email of entryEmails) {
              if (!email) continue;
              const emailLower = email.toLowerCase();
              const emailDomain = emailLower.split("@")[1];
              if (!emailDomain || !(emailDomain === domain || emailDomain.endsWith(`.${domain}`))) continue;
              const hasPlaintext = hasValue(entry.password);
              const hasHash = hasValue(entry.hashed_password);
              const hasUsername = hasValue(entry.username);
              const dbNameForCred = entry.database_name || "unknown";
              const credKey = `${emailLower}|${dbNameForCred}`;
              if (!seenCredentials.has(credKey)) {
                seenCredentials.add(credKey);
                const credType = hasPlaintext ? "plaintext_password" : hasHash ? "hashed_password" : "email_only";
                const severity = hasPlaintext ? "critical" : hasHash ? "high" : "medium";
                const credSource = classifyCredentialSourceDehashed(domain, dbNameForCred, emailLower);
                observations.push({
                  assetId: makeAssetId9(domain, `cred:${credKey}`, "dehashed_credential"),
                  domain,
                  assetType: "credential",
                  name: emailLower,
                  source: "dehashed",
                  observedAt: now,
                  tags: [
                    "leaked_credential",
                    `credential_type:${credType}`,
                    `severity:${severity}`,
                    `breach:${dbNameForCred}`,
                    `breach_source:${credSource.type}`,
                    ...credSource.type === "first_party" ? ["first_party_breach"] : [],
                    ...credSource.type === "third_party" ? ["third_party_breach", "credential_reuse"] : [],
                    ...hasPlaintext ? ["plaintext_exposed"] : [],
                    ...hasHash ? ["hash_exposed"] : [],
                    ...hasUsername ? ["username_exposed"] : []
                  ],
                  evidence: {
                    email: emailLower,
                    username: hasUsername ? first(entry.username) : void 0,
                    credential_type: credType,
                    severity,
                    has_plaintext_password: hasPlaintext,
                    has_hashed_password: hasHash,
                    password_preview: hasPlaintext && first(entry.password) ? first(entry.password).charAt(0) + "*".repeat(Math.min(first(entry.password).length - 1, 8)) : void 0,
                    hash_type_hint: hasHash && first(entry.hashed_password) ? first(entry.hashed_password).startsWith("$2") ? "bcrypt" : first(entry.hashed_password).startsWith("$6$") ? "sha512crypt" : first(entry.hashed_password).startsWith("$5$") ? "sha256crypt" : first(entry.hashed_password).startsWith("$1$") ? "md5crypt" : first(entry.hashed_password).length === 32 ? "md5" : first(entry.hashed_password).length === 40 ? "sha1" : first(entry.hashed_password).length === 64 ? "sha256" : "unknown" : void 0,
                    database_name: dbNameForCred,
                    associated_name: hasValue(entry.name) ? first(entry.name) : void 0,
                    associated_phone: hasValue(entry.phone) ? "[REDACTED]" : void 0,
                    associated_ip: hasValue(entry.ip_address) ? first(entry.ip_address) : void 0,
                    // Credential source classification
                    credential_source: credSource.type,
                    credential_source_confidence: credSource.confidence,
                    credential_source_reasoning: credSource.reasoning
                  },
                  attribution: {
                    provider: "Dehashed (Breach Intelligence)",
                    url: "https://dehashed.com",
                    method: `Leaked ${credType.replace(/_/g, " ")} for ${emailLower} found in "${dbNameForCred}" breach database`,
                    verifyUrl: "https://dehashed.com"
                  }
                });
              }
            }
            const dbName = entry.database_name || "unknown";
            if (!seenBreaches.has(dbName) && dbName !== "unknown") {
              seenBreaches.add(dbName);
              const emailCount = breachEmailCounts.get(dbName) || 0;
              const credCount = breachCredCounts.get(dbName) || 0;
              observations.push({
                assetId: makeAssetId9(domain, `breach:${dbName}`, "dehashed_breach"),
                domain,
                assetType: "breach",
                name: dbName,
                source: "dehashed",
                observedAt: now,
                tags: [
                  "breach_database",
                  ...credCount > 0 ? ["credentials_exposed"] : [],
                  `records:${emailCount}`
                ],
                evidence: {
                  database_name: dbName,
                  total_records: emailCount,
                  credentials_exposed: credCount,
                  has_passwords: credCount > 0,
                  has_hashed_passwords: entries.some(
                    (e) => e.database_name === dbName && hasValue(e.hashed_password)
                  )
                },
                attribution: {
                  provider: "Dehashed (Breach Intelligence)",
                  url: "https://dehashed.com",
                  method: `Breach database "${dbName}" contains ${emailCount} records associated with ${domain} (${credCount} with exposed credentials)`,
                  verifyUrl: "https://dehashed.com"
                }
              });
            }
          }
          if (entries.length > 0) {
            const totalCreds = Array.from(breachCredCounts.values()).reduce((a, b) => a + b, 0);
            observations.push({
              assetId: makeAssetId9(domain, "breach_summary", "dehashed"),
              domain,
              assetType: "breach",
              name: `${domain} breach summary`,
              source: "dehashed",
              observedAt: now,
              tags: [
                "breach_summary",
                `total_records:${data.total || entries.length}`,
                `total_breaches:${seenBreaches.size}`,
                ...totalCreds > 0 ? ["credentials_at_risk"] : []
              ],
              evidence: {
                total_records: data.total || entries.length,
                unique_breaches: seenBreaches.size,
                unique_subdomains_found: seenSubdomains.size,
                unique_ips_found: seenIPs.size,
                unique_leaked_accounts: seenCredentials.size,
                credentials_exposed: totalCreds,
                breach_databases: Array.from(seenBreaches),
                api_balance: data.balance
              },
              attribution: {
                provider: "Dehashed (Breach Intelligence)",
                url: "https://dehashed.com",
                method: `Domain-wide breach analysis \u2014 ${data.total || entries.length} total records across ${seenBreaches.size} breach databases, ${seenSubdomains.size} subdomains discovered, ${totalCreds} credentials exposed`,
                verifyUrl: "https://dehashed.com"
              }
            });
          }
        } catch (err) {
          if (err.name === "AbortError") {
            errors.push("Dehashed request timed out");
          } else {
            errors.push(`Dehashed error: ${err.message}`);
          }
        }
        return {
          connector: "dehashed",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/shodan-internetdb.ts
import { createHash as createHash10 } from "crypto";
import { resolve4 as resolve42 } from "dns/promises";
function makeAssetId10(domain, name, source) {
  return createHash10("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function queryInternetDB(ip, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`InternetDB returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
function cveToTags(cveId) {
  return [`cve:${cveId}`, "shodan_internetdb_vuln"];
}
var shodanInternetDBConnector;
var init_shodan_internetdb = __esm({
  "server/lib/passive/shodan-internetdb.ts"() {
    "use strict";
    shodanInternetDBConnector = {
      name: "shodan_internetdb",
      description: "Shodan InternetDB \u2014 free, instant IP enrichment with open ports, CVEs, CPEs, hostnames, and tags (no API key required)",
      requiresApiKey: false,
      freeUrl: "https://internetdb.shodan.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        try {
          let ips = [];
          try {
            ips = await resolve42(domain);
          } catch {
            errors.push(`Could not resolve ${domain} to IP addresses`);
            return { connector: "shodan_internetdb", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const now = /* @__PURE__ */ new Date();
          const results = await Promise.allSettled(
            ips.slice(0, 20).map((ip) => queryInternetDB(ip, timeout))
          );
          for (let i = 0; i < results.length; i++) {
            const result = results[i];
            const ip = ips[i];
            if (result.status === "rejected") {
              errors.push(`InternetDB error for ${ip}: ${result.reason?.message || result.reason}`);
              continue;
            }
            const data = result.value;
            if (!data) continue;
            observations.push({
              assetId: makeAssetId10(domain, `${ip}|internetdb`, "shodan_internetdb"),
              domain,
              assetType: "ip",
              name: `${ip} (InternetDB)`,
              ip,
              source: "shodan_internetdb",
              observedAt: now,
              tags: [
                ...data.tags.map((t) => `idb_tag:${t}`),
                ...data.ports.map((p) => `port:${p}`),
                ...data.cpes.map((c) => `cpe:${c}`),
                ...data.vulns.flatMap((v) => cveToTags(v)),
                `open_ports:${data.ports.length}`,
                `vuln_count:${data.vulns.length}`,
                `cpe_count:${data.cpes.length}`
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
                cpe_count: data.cpes.length
              },
              attribution: {
                provider: "Shodan InternetDB (Free API)",
                url: `https://internetdb.shodan.io/${ip}`,
                method: `Shodan InternetDB lookup \u2014 queried pre-computed scan data for ${ip}, found ${data.ports.length} open ports, ${data.vulns.length} CVEs, ${data.cpes.length} CPEs`,
                verifyUrl: `https://www.shodan.io/host/${ip}`
              }
            });
            for (const vuln of data.vulns) {
              observations.push({
                assetId: makeAssetId10(domain, `${ip}|${vuln}|internetdb`, "shodan_internetdb_vuln"),
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
                  ...data.cpes.map((c) => `cpe:${c}`)
                ],
                evidence: {
                  cve_id: vuln,
                  ip: data.ip,
                  ports: data.ports,
                  cpes: data.cpes,
                  source_api: "internetdb.shodan.io",
                  verification_type: "shodan_precomputed"
                },
                attribution: {
                  provider: "Shodan InternetDB (Free API)",
                  url: `https://internetdb.shodan.io/${ip}`,
                  method: `Shodan InternetDB \u2014 ${vuln} detected on ${ip} via pre-computed internet-wide scan data`,
                  verifyUrl: `https://www.shodan.io/host/${ip}`
                }
              });
            }
            for (const hostname of data.hostnames) {
              if (hostname.endsWith(domain) || hostname === domain) {
                observations.push({
                  assetId: makeAssetId10(domain, `${hostname}|internetdb_host`, "shodan_internetdb"),
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
                    discovered_via: "shodan_internetdb"
                  },
                  attribution: {
                    provider: "Shodan InternetDB (Free API)",
                    url: `https://internetdb.shodan.io/${ip}`,
                    method: `Shodan InternetDB \u2014 hostname ${hostname} associated with ${ip}`,
                    verifyUrl: `https://www.shodan.io/host/${ip}`
                  }
                });
              }
            }
          }
        } catch (err) {
          errors.push(`InternetDB error: ${err.message}`);
        }
        return {
          connector: "shodan_internetdb",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/coalition-control.ts
import { createHash as createHash11 } from "crypto";
function makeAssetId11(domain, name, source) {
  return createHash11("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function getAuthToken(email, password) {
  if (cachedToken && Date.now() < cachedToken.expiresAt - 5 * 60 * 1e3) {
    return cachedToken.token;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const response = await fetch(`${CONTROL_BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: email, password }),
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) return null;
    const data = await response.json();
    const token = data.access_token || data.token;
    if (!token) return null;
    cachedToken = { token, expiresAt: Date.now() + 60 * 60 * 1e3 };
    return token;
  } catch {
    return null;
  }
}
async function authedFetch(path, token) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const response = await fetch(`${CONTROL_BASE_URL}${path}`, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/json"
      },
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}
var CONTROL_BASE_URL, REQUEST_TIMEOUT_MS, cachedToken, coalitionControlConnector;
var init_coalition_control = __esm({
  "server/lib/passive/coalition-control.ts"() {
    "use strict";
    CONTROL_BASE_URL = "https://api.control.coalitioninc.com";
    REQUEST_TIMEOUT_MS = 15e3;
    cachedToken = null;
    coalitionControlConnector = {
      name: "coalition_control",
      description: "Coalition Control ASM \u2014 Attack surface monitoring powered by BinaryEdge scanning engine. Provides security findings, data leaks, and asset discovery.",
      requiresApiKey: true,
      freeUrl: "https://www.coalitioninc.com/control",
      async collect(domain, config) {
        const start = Date.now();
        const observations = [];
        const errors = [];
        const now = (/* @__PURE__ */ new Date()).toISOString();
        const email = process.env.COALITION_CONTROL_EMAIL;
        const password = process.env.COALITION_CONTROL_PASSWORD;
        if (!email || !password) {
          errors.push("Coalition Control credentials not configured \u2014 register free at https://www.coalitioninc.com/control");
          return {
            connector: "coalition_control",
            domain,
            observations,
            errors,
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        const token = await getAuthToken(email, password);
        if (!token) {
          errors.push("Coalition Control authentication failed \u2014 check email/password");
          return {
            connector: "coalition_control",
            domain,
            observations,
            errors,
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          const meData = await authedFetch("/asm/me", token);
          if (!meData || !meData.entity_id) {
            errors.push("Coalition Control: could not retrieve entity ID");
            return { connector: "coalition_control", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const entityId = meData.entity_id;
          const findingsData = await authedFetch(`/asm/entity/${entityId}/findings`, token);
          if (findingsData && Array.isArray(findingsData.findings || findingsData)) {
            const findings = findingsData.findings || findingsData;
            for (const finding of findings) {
              const findingDomain = finding.domain || finding.asset || "";
              if (!findingDomain.includes(domain) && !domain.includes(findingDomain)) continue;
              observations.push({
                assetId: makeAssetId11(domain, `${finding.id || finding.title}|coalition_finding`, "coalition_control"),
                domain,
                assetType: "finding",
                name: `[Coalition] ${finding.title || finding.name || "Security Finding"}`,
                source: "coalition_control",
                observedAt: finding.created_at || now,
                tags: [
                  "coalition_control",
                  "security_finding",
                  finding.severity ? `severity:${finding.severity}` : "severity:unknown",
                  finding.category ? `category:${finding.category}` : "",
                  finding.cve_id ? `cve:${finding.cve_id}` : ""
                ].filter(Boolean),
                evidence: {
                  title: finding.title || finding.name,
                  severity: finding.severity,
                  category: finding.category,
                  description: finding.description,
                  cve_id: finding.cve_id,
                  remediation: finding.remediation,
                  asset: finding.asset || finding.domain,
                  port: finding.port,
                  service: finding.service,
                  first_seen: finding.first_seen || finding.created_at,
                  last_seen: finding.last_seen || finding.updated_at
                },
                attribution: {
                  provider: "Coalition Control",
                  url: "https://app.control.coalitioninc.com",
                  method: `Coalition Control ASM finding \u2014 ${finding.title || "security issue"} detected via BinaryEdge scanning engine`,
                  verifyUrl: "https://app.control.coalitioninc.com"
                }
              });
            }
          }
          const assetsData = await authedFetch(`/asm/entity/${entityId}/assets/impacted`, token);
          if (assetsData && Array.isArray(assetsData.assets || assetsData)) {
            const assets = assetsData.assets || assetsData;
            for (const asset of assets) {
              const assetDomain = asset.domain || asset.hostname || "";
              if (!assetDomain.includes(domain) && !domain.includes(assetDomain)) continue;
              observations.push({
                assetId: makeAssetId11(domain, `${asset.ip || asset.hostname}|coalition_asset`, "coalition_control"),
                domain,
                assetType: "ip",
                name: `[Coalition] Impacted asset: ${asset.hostname || asset.ip}`,
                ip: asset.ip,
                source: "coalition_control",
                observedAt: now,
                tags: [
                  "coalition_control",
                  "impacted_asset",
                  asset.ip ? `ip:${asset.ip}` : "",
                  ...(asset.open_ports || []).map((p) => `port:${p}`),
                  `risk_score:${asset.risk_score || "unknown"}`
                ].filter(Boolean),
                evidence: {
                  ip: asset.ip,
                  hostname: asset.hostname,
                  open_ports: asset.open_ports,
                  risk_score: asset.risk_score,
                  findings_count: asset.findings_count,
                  services: asset.services
                },
                attribution: {
                  provider: "Coalition Control",
                  url: "https://app.control.coalitioninc.com",
                  method: `Coalition Control ASM \u2014 impacted asset ${asset.hostname || asset.ip} with ${asset.findings_count || 0} findings`,
                  verifyUrl: "https://app.control.coalitioninc.com"
                }
              });
            }
          }
          const leaksData = await authedFetch(`/asm/entity/${entityId}/dataleaks`, token);
          if (leaksData && Array.isArray(leaksData.dataleaks || leaksData)) {
            const leaks = leaksData.dataleaks || leaksData;
            for (const leak of leaks) {
              observations.push({
                assetId: makeAssetId11(domain, `${leak.id || leak.source}|coalition_leak`, "coalition_control"),
                domain,
                assetType: "data_leak",
                name: `[Coalition] Data leak: ${leak.source || leak.title || "Unknown source"}`,
                source: "coalition_control",
                observedAt: leak.discovered_at || now,
                tags: [
                  "coalition_control",
                  "data_leak",
                  "credential_exposure",
                  leak.source ? `leak_source:${leak.source}` : "",
                  leak.severity ? `severity:${leak.severity}` : ""
                ].filter(Boolean),
                evidence: {
                  source: leak.source,
                  title: leak.title,
                  description: leak.description,
                  severity: leak.severity,
                  discovered_at: leak.discovered_at,
                  affected_emails: leak.affected_emails,
                  data_types: leak.data_types
                },
                attribution: {
                  provider: "Coalition Control",
                  url: "https://app.control.coalitioninc.com",
                  method: `Coalition Control data leak detection \u2014 ${leak.source || "breach"} affecting ${domain}`,
                  verifyUrl: "https://app.control.coalitioninc.com"
                }
              });
            }
          }
        } catch (err) {
          errors.push(`Coalition Control error: ${err.message}`);
        }
        return {
          connector: "coalition_control",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/greynoise.ts
import { createHash as createHash12 } from "crypto";
import { resolve4 as resolve43 } from "dns/promises";
function makeAssetId12(domain, name, source) {
  return createHash12("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function queryCommunityAPI(ip, apiKey, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      signal: controller.signal,
      headers: {
        "key": apiKey,
        "Accept": "application/json"
      }
    });
    if (res.status === 404) return null;
    if (res.status === 429) throw new Error("Rate limited by GreyNoise API");
    if (res.status === 401) throw new Error("Invalid GreyNoise API key");
    if (!res.ok) throw new Error(`GreyNoise returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
async function queryContextAPI(ip, apiKey, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      signal: controller.signal,
      headers: {
        "key": apiKey,
        "Accept": "application/json"
      }
    });
    if (res.ok) {
      const controller2 = new AbortController();
      const timer2 = setTimeout(() => controller2.abort(), timeout);
      try {
        const contextRes = await fetch(`https://api.greynoise.io/v2/noise/context/${ip}`, {
          signal: controller2.signal,
          headers: {
            "key": apiKey,
            "Accept": "application/json"
          }
        });
        if (contextRes.ok) {
          return await contextRes.json();
        }
      } finally {
        clearTimeout(timer2);
      }
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}
var greynoiseConnector;
var init_greynoise = __esm({
  "server/lib/passive/greynoise.ts"() {
    "use strict";
    greynoiseConnector = {
      name: "greynoise",
      description: "GreyNoise \u2014 internet background noise analysis providing threat pressure context, active attack detection, and IP classification (benign/malicious/unknown)",
      requiresApiKey: true,
      freeUrl: "https://viz.greynoise.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        const apiKey = config?.apiKey;
        if (!apiKey) {
          return {
            connector: "greynoise",
            domain,
            observations: [],
            errors: ["GreyNoise API key not configured \u2014 skipping"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          let ips = [];
          try {
            ips = await resolve43(domain);
          } catch {
            errors.push(`Could not resolve ${domain} to IP addresses`);
            return { connector: "greynoise", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const now = /* @__PURE__ */ new Date();
          for (const ip of ips.slice(0, 15)) {
            try {
              let contextData = null;
              let communityData = null;
              try {
                contextData = await queryContextAPI(ip, apiKey, timeout);
              } catch {
              }
              if (!contextData) {
                try {
                  communityData = await queryCommunityAPI(ip, apiKey, timeout);
                } catch (err) {
                  if (err.message.includes("Rate limited")) {
                    errors.push("GreyNoise rate limited \u2014 remaining IPs skipped");
                    break;
                  }
                  throw err;
                }
              }
              if (contextData && contextData.seen) {
                const threatTags = [
                  `classification:${contextData.classification}`,
                  "greynoise",
                  "threat_context"
                ];
                if (contextData.classification === "malicious") {
                  threatTags.push("UNDER_ACTIVE_ATTACK", "greynoise_malicious");
                }
                if (contextData.vpn) threatTags.push("vpn_detected");
                if (contextData.bot) threatTags.push("bot_detected");
                if (contextData.metadata?.tor) threatTags.push("tor_exit_node");
                if (contextData.spoofable) threatTags.push("spoofable_ip");
                if (contextData.actor) threatTags.push(`actor:${contextData.actor}`);
                for (const tag of contextData.tags || []) {
                  threatTags.push(`gn_tag:${tag}`);
                }
                for (const cve of contextData.cve || []) {
                  threatTags.push(`cve:${cve}`, "actively_exploited");
                }
                observations.push({
                  assetId: makeAssetId12(domain, `${ip}|greynoise_context`, "greynoise"),
                  domain,
                  assetType: "ip",
                  name: `${ip} (GreyNoise: ${contextData.classification})`,
                  ip,
                  source: "greynoise",
                  observedAt: now,
                  firstSeen: contextData.first_seen ? new Date(contextData.first_seen) : void 0,
                  lastSeen: contextData.last_seen ? new Date(contextData.last_seen) : void 0,
                  tags: threatTags,
                  evidence: {
                    ip: contextData.ip,
                    classification: contextData.classification,
                    actor: contextData.actor || null,
                    tags: contextData.tags,
                    cves_exploited: contextData.cve,
                    vpn: contextData.vpn,
                    vpn_service: contextData.vpn_service || null,
                    bot: contextData.bot,
                    spoofable: contextData.spoofable,
                    metadata: contextData.metadata,
                    scan_ports: contextData.raw_data?.scan?.map((s) => s.port) || [],
                    web_paths: contextData.raw_data?.web?.paths || [],
                    ja3_fingerprints: contextData.raw_data?.ja3?.map((j) => j.fingerprint) || [],
                    first_seen: contextData.first_seen,
                    last_seen: contextData.last_seen,
                    threat_pressure: contextData.classification === "malicious" ? "high" : contextData.classification === "unknown" ? "medium" : "low"
                  },
                  attribution: {
                    provider: "GreyNoise (Enterprise)",
                    url: `https://viz.greynoise.io/ip/${ip}`,
                    method: `GreyNoise context \u2014 ${ip} classified as ${contextData.classification}${contextData.actor ? ` (actor: ${contextData.actor})` : ""}${contextData.cve?.length ? `, ${contextData.cve.length} CVEs actively exploited` : ""}`,
                    verifyUrl: `https://viz.greynoise.io/ip/${ip}`
                  }
                });
                for (const cve of contextData.cve || []) {
                  observations.push({
                    assetId: makeAssetId12(domain, `${ip}|${cve}|greynoise_exploit`, "greynoise"),
                    domain,
                    assetType: "ip",
                    name: `${cve} actively exploited against ${ip}`,
                    ip,
                    source: "greynoise",
                    observedAt: now,
                    tags: [
                      `cve:${cve}`,
                      "actively_exploited",
                      "greynoise_threat_intel",
                      "UNDER_ACTIVE_ATTACK"
                    ],
                    evidence: {
                      cve_id: cve,
                      ip,
                      classification: contextData.classification,
                      actor: contextData.actor || null,
                      source_api: "api.greynoise.io",
                      verification_type: "greynoise_active_exploitation",
                      threat_pressure: "critical"
                    },
                    attribution: {
                      provider: "GreyNoise (Enterprise)",
                      url: `https://viz.greynoise.io/ip/${ip}`,
                      method: `GreyNoise \u2014 ${cve} is being actively exploited against ${ip} based on GreyNoise sensor network data`,
                      verifyUrl: `https://viz.greynoise.io/ip/${ip}`
                    }
                  });
                }
              } else if (communityData) {
                const threatTags = [
                  `classification:${communityData.classification}`,
                  "greynoise",
                  "community_api"
                ];
                if (communityData.noise) threatTags.push("internet_noise", "mass_scanning");
                if (communityData.riot) threatTags.push("riot_known_benign");
                if (communityData.classification === "malicious") {
                  threatTags.push("UNDER_ACTIVE_ATTACK", "greynoise_malicious");
                }
                observations.push({
                  assetId: makeAssetId12(domain, `${ip}|greynoise_community`, "greynoise"),
                  domain,
                  assetType: "ip",
                  name: `${ip} (GreyNoise: ${communityData.classification})`,
                  ip,
                  source: "greynoise",
                  observedAt: now,
                  lastSeen: communityData.last_seen ? new Date(communityData.last_seen) : void 0,
                  tags: threatTags,
                  evidence: {
                    ip: communityData.ip,
                    classification: communityData.classification,
                    noise: communityData.noise,
                    riot: communityData.riot,
                    name: communityData.name,
                    last_seen: communityData.last_seen,
                    threat_pressure: communityData.classification === "malicious" ? "high" : communityData.noise ? "medium" : "low"
                  },
                  attribution: {
                    provider: "GreyNoise (Community)",
                    url: communityData.link || `https://viz.greynoise.io/ip/${ip}`,
                    method: `GreyNoise community \u2014 ${ip} classified as ${communityData.classification}${communityData.noise ? " (seen mass-scanning)" : ""}${communityData.riot ? " (known benign service)" : ""}`,
                    verifyUrl: `https://viz.greynoise.io/ip/${ip}`
                  }
                });
              }
            } catch (err) {
              if (err.message.includes("Rate limited")) {
                errors.push("GreyNoise rate limited \u2014 remaining IPs skipped");
                break;
              }
              errors.push(`GreyNoise error for ${ip}: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`GreyNoise error: ${err.message}`);
        }
        return {
          connector: "greynoise",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: errors.some((e) => e.includes("Rate limited"))
        };
      }
    };
  }
});

// server/lib/passive/email-security.ts
import { createHash as createHash13 } from "crypto";
import { resolveMx, resolveTxt } from "dns/promises";
function makeAssetId13(domain, name, source) {
  return createHash13("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function dnsWithTimeout(queryFn, timeoutMs = 5e3) {
  return Promise.race([
    queryFn(),
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("DNS query timeout")), timeoutMs)
    )
  ]);
}
async function queryDns(domain, _timeout, signal) {
  const DNS_TIMEOUT = 5e3;
  const result = {
    spf: { found: false, issues: [] },
    dmarc: { found: false, issues: [] },
    dkim: { selectorsChecked: [], found: [], issues: [] },
    mx: { records: [], issues: [] }
  };
  try {
    if (signal?.aborted) throw new Error("Aborted");
    const txtRecords = await dnsWithTimeout(() => resolveTxt(domain), DNS_TIMEOUT);
    for (const parts of txtRecords) {
      const record = parts.join("");
      if (record.toLowerCase().startsWith("v=spf1")) {
        result.spf.found = true;
        result.spf.record = record;
        if (record.includes("-all")) result.spf.policy = "hard_fail";
        else if (record.includes("~all")) result.spf.policy = "soft_fail";
        else if (record.includes("?all")) result.spf.policy = "neutral";
        else if (record.includes("+all")) {
          result.spf.policy = "pass_all";
          result.spf.issues.push("SPF uses +all which allows any sender \u2014 effectively no protection");
        }
        const includeCount = (record.match(/include:/g) || []).length;
        if (includeCount > 10) {
          result.spf.issues.push(`SPF has ${includeCount} includes \u2014 may exceed DNS lookup limit (10)`);
        }
      }
    }
  } catch {
  }
  if (!result.spf.found) {
    result.spf.issues.push("No SPF record found \u2014 email spoofing is trivial");
  }
  try {
    if (signal?.aborted) throw new Error("Aborted");
    const dmarcRecords = await dnsWithTimeout(() => resolveTxt(`_dmarc.${domain}`), DNS_TIMEOUT);
    for (const parts of dmarcRecords) {
      const record = parts.join("");
      if (record.toLowerCase().startsWith("v=dmarc1")) {
        result.dmarc.found = true;
        result.dmarc.record = record;
        const pMatch = record.match(/;\s*p=(\w+)/i);
        if (pMatch) result.dmarc.policy = pMatch[1].toLowerCase();
        const pctMatch = record.match(/;\s*pct=(\d+)/i);
        if (pctMatch) result.dmarc.pct = parseInt(pctMatch[1], 10);
        const ruaMatch = record.match(/;\s*rua=([^;]+)/i);
        if (ruaMatch) result.dmarc.rua = ruaMatch[1].trim();
        if (result.dmarc.policy === "none") {
          result.dmarc.issues.push("DMARC policy is 'none' \u2014 spoofed emails are not blocked");
        }
        if (result.dmarc.pct !== void 0 && result.dmarc.pct < 100) {
          result.dmarc.issues.push(`DMARC only applies to ${result.dmarc.pct}% of messages`);
        }
      }
    }
  } catch {
  }
  if (!result.dmarc.found) {
    result.dmarc.issues.push("No DMARC record found \u2014 email spoofing protection is absent");
  }
  const commonSelectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2"];
  result.dkim.selectorsChecked = commonSelectors;
  for (const sel of commonSelectors) {
    if (signal?.aborted) break;
    try {
      const dkimRecords = await dnsWithTimeout(() => resolveTxt(`${sel}._domainkey.${domain}`), DNS_TIMEOUT);
      for (const parts of dkimRecords) {
        const record = parts.join("");
        if (record.includes("v=DKIM1") || record.includes("p=")) {
          result.dkim.found.push(sel);
          break;
        }
      }
    } catch {
    }
  }
  if (result.dkim.found.length === 0) {
    result.dkim.issues.push("No DKIM selectors found among common selectors \u2014 email authentication may be weak");
  }
  try {
    if (signal?.aborted) throw new Error("Aborted");
    const mxRecords = await dnsWithTimeout(() => resolveMx(domain), DNS_TIMEOUT);
    result.mx.records = mxRecords.map((r) => ({ exchange: r.exchange, priority: r.priority }));
    if (mxRecords.length === 0) {
      result.mx.issues.push("No MX records found \u2014 domain may not receive email");
    }
  } catch {
    result.mx.issues.push("MX lookup failed \u2014 domain may not receive email");
  }
  return result;
}
var emailSecurityConnector;
var init_email_security = __esm({
  "server/lib/passive/email-security.ts"() {
    "use strict";
    emailSecurityConnector = {
      name: "email_security",
      description: "Email security posture analysis \u2014 DMARC, SPF, DKIM, and MX record assessment for phishing susceptibility",
      requiresApiKey: false,
      freeUrl: "https://mxtoolbox.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        const signal = config?.signal;
        const now = /* @__PURE__ */ new Date();
        if (signal?.aborted) {
          return { connector: "email_security", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          const result = await queryDns(domain, timeout, signal);
          observations.push({
            assetId: makeAssetId13(domain, `spf:${domain}`, "email_security"),
            domain,
            assetType: "txt",
            name: `SPF: ${result.spf.found ? result.spf.policy || "present" : "MISSING"}`,
            source: "email_security",
            observedAt: now,
            tags: ["email_security", "spf", ...result.spf.found ? ["spf_present"] : ["spf_missing", "phishing_risk"], ...result.spf.policy === "pass_all" ? ["spf_permissive", "critical_misconfiguration"] : []],
            evidence: { record: result.spf.record, policy: result.spf.policy, issues: result.spf.issues },
            attribution: { provider: "DNS TXT Record Lookup", method: "Queried DNS TXT records for SPF (v=spf1) policy on " + domain, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${domain}&run=toolpage` }
          });
          observations.push({
            assetId: makeAssetId13(domain, `dmarc:${domain}`, "email_security"),
            domain,
            assetType: "txt",
            name: `DMARC: ${result.dmarc.found ? result.dmarc.policy || "present" : "MISSING"}`,
            source: "email_security",
            observedAt: now,
            tags: ["email_security", "dmarc", ...result.dmarc.found ? ["dmarc_present"] : ["dmarc_missing", "phishing_risk"], ...result.dmarc.policy === "none" ? ["dmarc_monitor_only"] : []],
            evidence: { record: result.dmarc.record, policy: result.dmarc.policy, pct: result.dmarc.pct, rua: result.dmarc.rua, issues: result.dmarc.issues },
            attribution: { provider: "DNS TXT Record Lookup", method: `Queried DNS TXT records for DMARC (v=DMARC1) policy at _dmarc.${domain}`, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a${domain}&run=toolpage` }
          });
          observations.push({
            assetId: makeAssetId13(domain, `dkim:${domain}`, "email_security"),
            domain,
            assetType: "txt",
            name: result.dkim.found.length > 0 ? `DKIM: selectors found (${result.dkim.found.join(", ")})` : "DKIM: no common selectors found",
            source: "email_security",
            observedAt: now,
            tags: ["email_security", "dkim", ...result.dkim.found.length > 0 ? ["dkim_present"] : ["dkim_missing"]],
            evidence: { selectorsFound: result.dkim.found, selectorsChecked: result.dkim.selectorsChecked, issues: result.dkim.issues },
            attribution: { provider: "DNS TXT Record Lookup", method: `Checked ${result.dkim.selectorsChecked.length} common DKIM selectors at <selector>._domainkey.${domain}` }
          });
          if (result.mx.records.length > 0) {
            const providers = [];
            for (const mx of result.mx.records) {
              const ex = mx.exchange.toLowerCase();
              if (ex.includes("google") || ex.includes("gmail")) providers.push("Google Workspace");
              else if (ex.includes("outlook") || ex.includes("microsoft")) providers.push("Microsoft 365");
              else if (ex.includes("protonmail")) providers.push("ProtonMail");
              else if (ex.includes("mimecast")) providers.push("Mimecast");
              else if (ex.includes("pphosted") || ex.includes("proofpoint")) providers.push("Proofpoint");
            }
            observations.push({
              assetId: makeAssetId13(domain, `mx:${domain}`, "email_security"),
              domain,
              assetType: "mx",
              name: result.mx.records.map((r) => r.exchange).join(", "),
              source: "email_security",
              observedAt: now,
              tags: ["email_security", "mx", ...providers.length > 0 ? providers.map((p) => `provider:${p.toLowerCase().replace(/\s+/g, "_")}`) : []],
              evidence: { records: result.mx.records, detectedProviders: Array.from(new Set(providers)) },
              attribution: { provider: "DNS MX Record Lookup", method: `Queried DNS MX records for ${domain} to identify email infrastructure`, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domain}&run=toolpage` }
            });
          }
        } catch (err) {
          errors.push(`Email security check error: ${err.message}`);
        }
        return { connector: "email_security", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/http-security.ts
import { createHash as createHash14 } from "crypto";
function makeAssetId14(domain, name, source) {
  return createHash14("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var SECURITY_HEADERS, WAF_SIGNATURES, httpSecurityConnector;
var init_http_security = __esm({
  "server/lib/passive/http-security.ts"() {
    "use strict";
    SECURITY_HEADERS = [
      { name: "strict-transport-security", label: "HSTS", critical: true },
      { name: "content-security-policy", label: "CSP", critical: true },
      { name: "x-content-type-options", label: "X-Content-Type-Options", critical: false },
      { name: "x-frame-options", label: "X-Frame-Options", critical: false },
      { name: "x-xss-protection", label: "X-XSS-Protection", critical: false },
      { name: "referrer-policy", label: "Referrer-Policy", critical: false },
      { name: "permissions-policy", label: "Permissions-Policy", critical: false },
      { name: "cross-origin-opener-policy", label: "COOP", critical: false },
      { name: "cross-origin-resource-policy", label: "CORP", critical: false },
      { name: "cross-origin-embedder-policy", label: "COEP", critical: false }
    ];
    WAF_SIGNATURES = {
      "Cloudflare": (h) => !!(h["cf-ray"] || h["cf-cache-status"] || (h["server"] || "").toLowerCase().includes("cloudflare")),
      "AWS CloudFront": (h) => !!(h["x-amz-cf-id"] || h["x-amz-cf-pop"] || (h["via"] || "").includes("cloudfront")),
      "Akamai": (h) => !!(h["x-akamai-transformed"] || (h["server"] || "").toLowerCase().includes("akamai")),
      "Fastly": (h) => !!(h["x-fastly-request-id"] || h["fastly-debug-digest"]),
      "Sucuri": (h) => !!(h["x-sucuri-id"] || (h["server"] || "").toLowerCase().includes("sucuri")),
      "Imperva/Incapsula": (h) => !!(h["x-iinfo"] || h["x-cdn"] === "Imperva"),
      "F5 BIG-IP": (h) => !!(h["x-wa-info"] || (h["server"] || "").toLowerCase().includes("big-ip")),
      "ModSecurity": (h) => !!(h["server"] || "").toLowerCase().includes("mod_security"),
      "Azure Front Door": (h) => !!(h["x-azure-ref"] || h["x-fd-healthprobe"])
    };
    httpSecurityConnector = {
      name: "http_security",
      description: "HTTP security headers and WAF detection \u2014 identifies defensive posture, missing security headers, and technology fingerprints",
      requiresApiKey: false,
      freeUrl: "https://securityheaders.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        const now = /* @__PURE__ */ new Date();
        try {
          const url = `https://${domain}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let res;
          try {
            res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow", headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" } });
          } finally {
            clearTimeout(timer);
          }
          const headers = {};
          res.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
          });
          const securityHeaders = SECURITY_HEADERS.map((sh) => {
            const value = headers[sh.name];
            return { name: sh.label, present: !!value, value, rating: value ? "good" : sh.critical ? "missing" : "warning", detail: value ? `${sh.label} is set: ${value.substring(0, 100)}` : `${sh.label} header is missing${sh.critical ? " (critical)" : ""}` };
          });
          const missingCritical = securityHeaders.filter((h) => h.rating === "missing");
          const present = securityHeaders.filter((h) => h.present);
          observations.push({
            assetId: makeAssetId14(domain, `http_headers:${domain}`, "http_security"),
            domain,
            assetType: "url",
            name: `Security Headers: ${present.length}/${SECURITY_HEADERS.length} present${missingCritical.length > 0 ? ` (${missingCritical.length} critical missing)` : ""}`,
            source: "http_security",
            observedAt: now,
            tags: ["http_security", "security_headers", ...missingCritical.length > 0 ? ["missing_critical_headers"] : []],
            evidence: { statusCode: res.status, url: res.url || url, securityHeaders, presentCount: present.length, totalChecked: SECURITY_HEADERS.length, missingCritical: missingCritical.map((h) => h.name) },
            attribution: { provider: "HTTP HEAD Request", method: `Sent HTTP HEAD request to https://${domain} and analyzed ${SECURITY_HEADERS.length} security headers`, verifyUrl: `https://securityheaders.com/?q=${domain}&followRedirects=on` }
          });
          let wafDetected;
          for (const [wafName, detector] of Object.entries(WAF_SIGNATURES)) {
            if (detector(headers)) {
              wafDetected = wafName;
              break;
            }
          }
          observations.push({
            assetId: makeAssetId14(domain, `waf:${domain}`, "http_security"),
            domain,
            assetType: "url",
            name: wafDetected ? `WAF Detected: ${wafDetected}` : "WAF: Not detected",
            source: "http_security",
            observedAt: now,
            tags: ["http_security", ...wafDetected ? ["waf_detected", `waf:${wafDetected.toLowerCase().replace(/[^a-z0-9]/g, "_")}`] : ["no_waf_detected"]],
            evidence: { wafName: wafDetected, detectionMethod: "HTTP response header fingerprinting" },
            attribution: { provider: "HTTP Header WAF Fingerprinting", method: wafDetected ? `Detected ${wafDetected} WAF from HTTP response headers on ${domain}` : `Checked ${Object.keys(WAF_SIGNATURES).length} WAF signatures against HTTP response headers from ${domain}` }
          });
          const techFingerprints = [];
          if (headers["x-powered-by"]) techFingerprints.push(`X-Powered-By: ${headers["x-powered-by"]}`);
          if (headers["x-aspnet-version"]) techFingerprints.push(`ASP.NET: ${headers["x-aspnet-version"]}`);
          const serverBanner = headers["server"];
          if (serverBanner) {
            const sl = serverBanner.toLowerCase();
            if (sl.includes("nginx")) techFingerprints.push(`nginx: ${serverBanner}`);
            else if (sl.includes("apache")) techFingerprints.push(`Apache: ${serverBanner}`);
            else if (sl.includes("iis")) techFingerprints.push(`IIS: ${serverBanner}`);
          }
          if (techFingerprints.length > 0 || serverBanner) {
            observations.push({
              assetId: makeAssetId14(domain, `tech:${domain}`, "http_security"),
              domain,
              assetType: "url",
              name: `Tech: ${techFingerprints.slice(0, 3).join(", ") || serverBanner || "unknown"}`,
              source: "http_security",
              observedAt: now,
              tags: ["http_security", "tech_fingerprint", ...serverBanner ? [`server:${serverBanner.split("/")[0].toLowerCase()}`] : []],
              evidence: { serverBanner, techFingerprints, poweredBy: headers["x-powered-by"] },
              attribution: { provider: "HTTP Header Technology Fingerprinting", method: `Extracted technology fingerprints from HTTP response headers on ${domain}` }
            });
          }
        } catch (err) {
          errors.push(`HTTP security check error: ${err.message}`);
        }
        return { connector: "http_security", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/cloud-assets.ts
import { createHash as createHash15 } from "crypto";
function makeAssetId15(domain, name, source) {
  return createHash15("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function generateCandidates(domain) {
  const parts = domain.split(".");
  const orgName = parts[0];
  const orgNameClean = orgName.replace(/[^a-z0-9]/gi, "");
  const suffixes = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-production", "-assets", "-static", "-media", "-uploads", "-data", "-logs", "-public", "-private", "-internal", "-docs", "-files", "-cdn", "-images", "-web", "-api", "-config"];
  const candidates = [];
  for (const suffix of suffixes) {
    candidates.push(`${orgNameClean}${suffix}`);
    if (orgName !== orgNameClean) candidates.push(`${orgName}${suffix}`);
  }
  const domainClean = domain.replace(/\./g, "-");
  candidates.push(domainClean, `${domainClean}-backup`, `${domainClean}-assets`);
  return Array.from(new Set(candidates.map((c) => c.toLowerCase())));
}
async function probeBucket(candidate, provider, timeout, externalSignal) {
  const url = provider === "aws" ? `https://${candidate}.s3.amazonaws.com/` : provider === "azure" ? `https://${candidate}.blob.core.windows.net/` : `https://storage.googleapis.com/${candidate}/`;
  const controller = new AbortController();
  if (externalSignal?.aborted) return { provider, bucketName: candidate, url, status: "error" };
  const onAbort = () => controller.abort();
  externalSignal?.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow" });
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onAbort);
    if (res.status === 200) return { provider, bucketName: candidate, url, status: "public", statusCode: 200 };
    if (res.status === 403) return { provider, bucketName: candidate, url, status: "exists_private", statusCode: 403 };
    return { provider, bucketName: candidate, url, status: res.status === 404 ? "not_found" : "error", statusCode: res.status };
  } catch {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onAbort);
    return { provider, bucketName: candidate, url, status: "error" };
  }
}
var cloudAssetsConnector;
var init_cloud_assets = __esm({
  "server/lib/passive/cloud-assets.ts"() {
    "use strict";
    cloudAssetsConnector = {
      name: "cloud_assets",
      description: "Cloud storage enumeration \u2014 probes S3, Azure Blob, and GCP Storage for publicly accessible or misconfigured buckets",
      requiresApiKey: false,
      freeUrl: "https://buckets.grayhatwarfare.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = Math.min(config?.timeout ?? 3e3, 3e3);
        const now = /* @__PURE__ */ new Date();
        try {
          const candidates = generateCandidates(domain);
          const providers = ["aws", "azure", "gcp"];
          const allProbes = [];
          for (const candidate of candidates.slice(0, 8)) {
            for (const provider of providers) allProbes.push({ candidate, provider });
          }
          const results = [];
          const externalSignal = config?.signal;
          for (let i = 0; i < allProbes.length; i += 10) {
            if (externalSignal?.aborted) break;
            const batch = allProbes.slice(i, i + 10);
            const batchResults = await Promise.allSettled(batch.map((p) => probeBucket(p.candidate, p.provider, timeout, externalSignal)));
            for (const r of batchResults) {
              if (r.status === "fulfilled") results.push(r.value);
            }
          }
          const found = results.filter((r) => r.status === "public" || r.status === "exists_private");
          for (const bucket of found) {
            const isPublic = bucket.status === "public";
            const providerLabel = bucket.provider === "aws" ? "AWS S3" : bucket.provider === "azure" ? "Azure Blob" : "Google Cloud Storage";
            observations.push({
              assetId: makeAssetId15(domain, `cloud:${bucket.provider}:${bucket.bucketName}`, "cloud_assets"),
              domain,
              assetType: "url",
              name: `${providerLabel}: ${bucket.bucketName} (${isPublic ? "PUBLIC" : "private"})`,
              source: "cloud_assets",
              observedAt: now,
              tags: ["cloud_asset", `provider:${bucket.provider}`, isPublic ? "public_bucket" : "private_bucket", ...isPublic ? ["critical_misconfiguration", "data_exposure_risk"] : []],
              evidence: { bucketName: bucket.bucketName, provider: bucket.provider, url: bucket.url, status: bucket.status, statusCode: bucket.statusCode },
              attribution: { provider: `${providerLabel} Bucket Probe`, url: bucket.url, method: `Probed ${providerLabel} endpoint for bucket named '${bucket.bucketName}' derived from domain ${domain}`, verifyUrl: bucket.url }
            });
          }
          const publicCount = found.filter((r) => r.status === "public").length;
          const privateCount = found.filter((r) => r.status === "exists_private").length;
          observations.push({
            assetId: makeAssetId15(domain, `cloud_summary:${domain}`, "cloud_assets"),
            domain,
            assetType: "url",
            name: `Cloud Storage: ${found.length} buckets found (${publicCount} public, ${privateCount} private) from ${results.length} probes`,
            source: "cloud_assets",
            observedAt: now,
            tags: ["cloud_asset", "cloud_summary", ...publicCount > 0 ? ["public_buckets_found", "critical_misconfiguration"] : []],
            evidence: { totalProbed: results.length, totalFound: found.length, publicCount, privateCount, candidatesChecked: candidates.slice(0, 20), providersChecked: providers },
            attribution: { provider: "Cloud Storage Enumeration", method: `Probed ${results.length} cloud storage endpoints (S3, Azure Blob, GCP) using ${candidates.slice(0, 20).length} naming patterns derived from ${domain}` }
          });
        } catch (err) {
          errors.push(`Cloud asset discovery error: ${err.message}`);
        }
        return { connector: "cloud_assets", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/dns-deep.ts
import { createHash as createHash16 } from "crypto";
import { resolve4 as resolve44, resolve6, resolveCname, resolveNs, resolveSoa, resolveSrv, resolveTxt as resolveTxt2, resolveCaa } from "dns/promises";
function makeAssetId16(domain, name, source) {
  return createHash16("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function detectCdn(cname) {
  const lower = cname.toLowerCase();
  for (const [cdn, patterns] of Object.entries(CDN_PATTERNS)) {
    if (patterns.some((p) => lower.includes(p))) return cdn;
  }
  return void 0;
}
async function dnsWithTimeout2(queryFn, timeoutMs = 5e3) {
  return Promise.race([
    queryFn(),
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("DNS query timeout")), timeoutMs)
    )
  ]);
}
var CDN_PATTERNS, dnsDeepConnector;
var init_dns_deep = __esm({
  "server/lib/passive/dns-deep.ts"() {
    "use strict";
    CDN_PATTERNS = {
      "Cloudflare": ["cloudflare", "cf-"],
      "AWS CloudFront": ["cloudfront.net", "d1", "d2", "d3"],
      "Akamai": ["akamai", "edgekey", "edgesuite"],
      "Fastly": ["fastly", "global.ssl.fastly"],
      "Azure CDN": ["azureedge.net", "azurefd.net"],
      "Google CDN": ["googleusercontent", "googlevideo"],
      "Incapsula": ["incapdns", "impervadns"]
    };
    dnsDeepConnector = {
      name: "dns_deep",
      description: "Comprehensive DNS record analysis \u2014 A, AAAA, CNAME, NS, SOA, TXT, SRV, CAA records with CDN and hosting provider detection",
      requiresApiKey: false,
      freeUrl: "https://dnsdumpster.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const now = /* @__PURE__ */ new Date();
        const signal = config?.signal;
        const DNS_TIMEOUT = 5e3;
        if (signal?.aborted) {
          return { connector: "dns_deep", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          const aRecords = await dnsWithTimeout2(() => resolve44(domain), DNS_TIMEOUT);
          if (aRecords.length > 0) {
            observations.push({
              assetId: makeAssetId16(domain, `a:${domain}`, "dns_deep"),
              domain,
              assetType: "ip",
              name: `A Records: ${aRecords.join(", ")}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "a_record", ...aRecords.length > 1 ? ["load_balanced"] : []],
              evidence: { records: aRecords, recordType: "A", count: aRecords.length },
              attribution: { provider: "DNS A Record Lookup", method: `Resolved A records for ${domain}`, verifyUrl: `https://dns.google/resolve?name=${domain}&type=A` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const aaaaRecords = await dnsWithTimeout2(() => resolve6(domain), DNS_TIMEOUT);
          if (aaaaRecords.length > 0) {
            observations.push({
              assetId: makeAssetId16(domain, `aaaa:${domain}`, "dns_deep"),
              domain,
              assetType: "ip",
              name: `AAAA Records: ${aaaaRecords.join(", ")}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "aaaa_record", "ipv6"],
              evidence: { records: aaaaRecords, recordType: "AAAA", count: aaaaRecords.length },
              attribution: { provider: "DNS AAAA Record Lookup", method: `Resolved AAAA records for ${domain}` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const cnameRecords = await dnsWithTimeout2(() => resolveCname(domain), DNS_TIMEOUT);
          if (cnameRecords.length > 0) {
            const cdn = detectCdn(cnameRecords[0]);
            observations.push({
              assetId: makeAssetId16(domain, `cname:${domain}`, "dns_deep"),
              domain,
              assetType: "subdomain",
              name: `CNAME: ${cnameRecords[0]}${cdn ? ` (${cdn})` : ""}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "cname_record", ...cdn ? [`cdn:${cdn.toLowerCase().replace(/\s+/g, "_")}`] : []],
              evidence: { records: cnameRecords, recordType: "CNAME", detectedCdn: cdn },
              attribution: { provider: "DNS CNAME Record Lookup", method: `Resolved CNAME records for ${domain}` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const nsRecords = await dnsWithTimeout2(() => resolveNs(domain), DNS_TIMEOUT);
          if (nsRecords.length > 0) {
            const nsProviders = [];
            for (const ns of nsRecords) {
              const lower = ns.toLowerCase();
              if (lower.includes("cloudflare")) nsProviders.push("Cloudflare");
              else if (lower.includes("awsdns")) nsProviders.push("AWS Route 53");
              else if (lower.includes("azure-dns")) nsProviders.push("Azure DNS");
              else if (lower.includes("google")) nsProviders.push("Google Cloud DNS");
              else if (lower.includes("domaincontrol")) nsProviders.push("GoDaddy");
            }
            observations.push({
              assetId: makeAssetId16(domain, `ns:${domain}`, "dns_deep"),
              domain,
              assetType: "subdomain",
              name: `NS: ${nsRecords.join(", ")}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "ns_record", ...nsProviders.length > 0 ? nsProviders.map((p) => `dns_provider:${p.toLowerCase().replace(/\s+/g, "_")}`) : []],
              evidence: { records: nsRecords, recordType: "NS", detectedProviders: Array.from(new Set(nsProviders)) },
              attribution: { provider: "DNS NS Record Lookup", method: `Resolved NS records for ${domain}` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const soa = await dnsWithTimeout2(() => resolveSoa(domain), DNS_TIMEOUT);
          if (soa) {
            observations.push({
              assetId: makeAssetId16(domain, `soa:${domain}`, "dns_deep"),
              domain,
              assetType: "subdomain",
              name: `SOA: ${soa.nsname} (admin: ${soa.hostmaster})`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "soa_record"],
              evidence: { nsname: soa.nsname, hostmaster: soa.hostmaster, serial: soa.serial, refresh: soa.refresh, retry: soa.retry, expire: soa.expire, minttl: soa.minttl, recordType: "SOA" },
              attribution: { provider: "DNS SOA Record Lookup", method: `Resolved SOA record for ${domain}` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const txtRecords = await dnsWithTimeout2(() => resolveTxt2(domain), DNS_TIMEOUT);
          const nonEmailTxt = txtRecords.filter((parts) => {
            const record = parts.join("");
            return !record.toLowerCase().startsWith("v=spf1") && !record.toLowerCase().startsWith("v=dmarc1");
          });
          if (nonEmailTxt.length > 0) {
            const verificationServices = [];
            for (const parts of nonEmailTxt) {
              const record = parts.join("");
              if (record.includes("google-site-verification")) verificationServices.push("Google Search Console");
              if (record.includes("MS=")) verificationServices.push("Microsoft 365");
              if (record.includes("facebook-domain-verification")) verificationServices.push("Facebook");
              if (record.includes("apple-domain-verification")) verificationServices.push("Apple");
              if (record.includes("atlassian-domain-verification")) verificationServices.push("Atlassian");
              if (record.includes("docusign")) verificationServices.push("DocuSign");
            }
            observations.push({
              assetId: makeAssetId16(domain, `txt:${domain}`, "dns_deep"),
              domain,
              assetType: "txt",
              name: `TXT Records: ${nonEmailTxt.length} non-email records${verificationServices.length > 0 ? ` (${verificationServices.join(", ")})` : ""}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "txt_record", ...verificationServices.length > 0 ? verificationServices.map((s) => `verified:${s.toLowerCase().replace(/\s+/g, "_")}`) : []],
              evidence: { records: nonEmailTxt.map((p) => p.join("")), recordType: "TXT", count: nonEmailTxt.length, verificationServices },
              attribution: { provider: "DNS TXT Record Lookup", method: `Resolved TXT records for ${domain} (excluding SPF/DMARC)` }
            });
          }
        } catch {
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        const srvPrefixes = ["_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_autodiscover._tcp", "_ldap._tcp", "_kerberos._tcp"];
        for (const prefix of srvPrefixes) {
          if (signal?.aborted) break;
          try {
            const srvRecords = await dnsWithTimeout2(() => resolveSrv(`${prefix}.${domain}`), DNS_TIMEOUT);
            if (srvRecords.length > 0) {
              observations.push({
                assetId: makeAssetId16(domain, `srv:${prefix}:${domain}`, "dns_deep"),
                domain,
                assetType: "subdomain",
                name: `SRV ${prefix}: ${srvRecords.map((r) => `${r.name}:${r.port}`).join(", ")}`,
                source: "dns_deep",
                observedAt: now,
                tags: ["dns", "srv_record", `service:${prefix.split(".")[0].replace("_", "")}`],
                evidence: { records: srvRecords, recordType: "SRV", prefix },
                attribution: { provider: "DNS SRV Record Lookup", method: `Resolved SRV records for ${prefix}.${domain}` }
              });
            }
          } catch {
          }
        }
        if (signal?.aborted) return { connector: "dns_deep", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited: false };
        try {
          const caaRecords = await dnsWithTimeout2(() => resolveCaa(domain), DNS_TIMEOUT);
          if (caaRecords.length > 0) {
            const issuers = caaRecords.filter((r) => r.critical !== void 0 || r.issue || r.issuewild).map((r) => r.issue || r.issuewild || JSON.stringify(r));
            observations.push({
              assetId: makeAssetId16(domain, `caa:${domain}`, "dns_deep"),
              domain,
              assetType: "txt",
              name: `CAA: ${issuers.length > 0 ? issuers.join(", ") : "present"}`,
              source: "dns_deep",
              observedAt: now,
              tags: ["dns", "caa_record", "certificate_authority"],
              evidence: { records: caaRecords, recordType: "CAA", authorizedIssuers: issuers },
              attribution: { provider: "DNS CAA Record Lookup", method: `Resolved CAA records for ${domain} to identify authorized certificate authorities` }
            });
          }
        } catch {
        }
        return { connector: "dns_deep", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/github-leaks.ts
import { createHash as createHash17 } from "crypto";
function makeAssetId17(domain, name, source) {
  return createHash17("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function getLeaksToken(primary) {
  if (_leaksTokenPool.tokens.length === 0) {
    _leaksTokenPool.tokens = [...new Set([primary, process.env.GITHUB_PAT, process.env.GITHUB_CLASSIC_TOKEN].filter((t) => !!t && t.length > 5))];
  }
  const now = Date.now();
  for (let i = 0; i < _leaksTokenPool.tokens.length; i++) {
    const idx = (_leaksTokenPool.idx + i) % _leaksTokenPool.tokens.length;
    const t = _leaksTokenPool.tokens[idx];
    const rlUntil = _leaksTokenPool.rl.get(t);
    if (!rlUntil || now > rlUntil) {
      _leaksTokenPool.idx = idx;
      return t;
    }
  }
  return primary || _leaksTokenPool.tokens[0];
}
function markLeaksTokenRL(token, resetEpoch) {
  _leaksTokenPool.rl.set(token, resetEpoch ? resetEpoch * 1e3 : Date.now() + 6e4);
  _leaksTokenPool.idx = (_leaksTokenPool.idx + 1) % Math.max(_leaksTokenPool.tokens.length, 1);
}
async function searchGitHubCode(query, token, timeout = 1e4) {
  const activeToken = getLeaksToken(token);
  const headers = {
    Accept: "application/vnd.github.text-match+json",
    "User-Agent": "Caldera-Dashboard-OSINT/1.0"
  };
  if (activeToken) headers["Authorization"] = `Bearer ${activeToken}`;
  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30&sort=indexed&order=desc`;
  try {
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(timeout) });
    if (response.status === 403 || response.status === 429) {
      const resetHeader = response.headers.get("X-RateLimit-Reset");
      if (activeToken) markLeaksTokenRL(activeToken, resetHeader ? +resetHeader : void 0);
      const fallback = getLeaksToken(token);
      if (fallback && fallback !== activeToken) {
        const h2 = { ...headers, Authorization: `Bearer ${fallback}` };
        const res2 = await fetch(url, { headers: h2, signal: AbortSignal.timeout(timeout) });
        if (res2.ok) return await res2.json();
        if (res2.status === 403 || res2.status === 429) markLeaksTokenRL(fallback);
      }
      const resetTime = resetHeader ? new Date(parseInt(resetHeader) * 1e3).toISOString() : "unknown";
      throw new Error(`GitHub rate limit exceeded (all tokens). Resets at ${resetTime}`);
    }
    if (response.status === 422) {
      return { total_count: 0, incomplete_results: false, items: [] };
    }
    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }
    return await response.json();
  } catch (err) {
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      throw new Error(`GitHub search timed out after ${timeout}ms`);
    }
    throw err;
  }
}
function buildObservation(domain, pattern, item, now) {
  const repoFullName = item.repository.full_name;
  const filePath = item.path;
  const textSnippet = item.text_matches?.[0]?.fragment?.slice(0, 200) || "";
  return {
    assetId: makeAssetId17(domain, `github:${repoFullName}:${filePath}`, "github_leaks"),
    domain,
    assetType: "url",
    name: `[${pattern.name}] ${repoFullName}/${filePath}`,
    source: "github_leaks",
    observedAt: now,
    lastSeen: item.repository.updated_at ? new Date(item.repository.updated_at) : now,
    tags: [
      "github",
      ...pattern.tags,
      `severity:${pattern.severity}`,
      item.repository.fork ? "forked_repo" : "original_repo",
      ...item.repository.stargazers_count > 100 ? ["popular_repo"] : []
    ],
    evidence: {
      patternId: pattern.id,
      patternName: pattern.name,
      severity: pattern.severity,
      repository: repoFullName,
      repoUrl: item.repository.html_url,
      repoDescription: item.repository.description,
      repoStars: item.repository.stargazers_count,
      repoOwner: item.repository.owner.login,
      repoOwnerType: item.repository.owner.type,
      filePath,
      fileUrl: item.html_url,
      textSnippet,
      isFork: item.repository.fork,
      lastUpdated: item.repository.updated_at
    },
    attribution: {
      provider: "GitHub Code Search API",
      method: `Searched GitHub public code for "${pattern.name}" patterns referencing ${domain}`,
      url: item.html_url,
      verifyUrl: item.html_url
    }
  };
}
var LEAK_PATTERNS, _leaksTokenPool, githubLeaksConnector;
var init_github_leaks = __esm({
  "server/lib/passive/github-leaks.ts"() {
    "use strict";
    LEAK_PATTERNS = [
      // ── Credential Leaks ──────────────────────────────────────────────
      {
        id: "env_files",
        name: "Environment Files (.env)",
        description: "Exposed .env files with API keys, database credentials, and secrets",
        queryTemplate: "{{domain}} filename:.env",
        severity: "critical",
        tags: ["code_leak", "env_file", "credential", "config_leak"]
      },
      {
        id: "api_keys",
        name: "API Keys & Tokens",
        description: "Hardcoded API keys, access tokens, and secret keys in source code",
        queryTemplate: "{{domain}} API_KEY OR api_key OR apikey OR secret_key OR access_token",
        severity: "critical",
        tags: ["code_leak", "api_key_leak", "credential"]
      },
      {
        id: "passwords",
        name: "Hardcoded Passwords",
        description: "Passwords embedded in configuration files or source code",
        queryTemplate: "{{domain}} password OR passwd OR pwd NOT example NOT test",
        severity: "critical",
        tags: ["code_leak", "credential", "password"]
      },
      // ── Configuration Leaks ───────────────────────────────────────────
      {
        id: "config_files",
        name: "Configuration Files",
        description: "Exposed config files (YAML, JSON, XML) with internal settings",
        queryTemplate: "{{domain}} filename:config.yml OR filename:config.json OR filename:settings.py",
        severity: "high",
        tags: ["code_leak", "config_leak"]
      },
      {
        id: "docker_compose",
        name: "Docker Compose / Infrastructure",
        description: "Docker Compose files revealing service architecture and internal ports",
        queryTemplate: "{{domain}} filename:docker-compose.yml OR filename:Dockerfile",
        severity: "high",
        tags: ["code_leak", "config_leak", "infrastructure"]
      },
      {
        id: "terraform",
        name: "Terraform / IaC Files",
        description: "Infrastructure-as-Code files exposing cloud architecture",
        queryTemplate: "{{domain}} filename:.tf OR filename:terraform.tfvars",
        severity: "high",
        tags: ["code_leak", "config_leak", "infrastructure", "cloud"]
      },
      // ── Network & Architecture ────────────────────────────────────────
      {
        id: "internal_ips",
        name: "Internal IP Addresses",
        description: "References to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x)",
        queryTemplate: '{{domain}} "10." OR "172.16" OR "192.168" filename:.conf OR filename:.cfg',
        severity: "medium",
        tags: ["code_leak", "internal_ip", "network"]
      },
      {
        id: "database_strings",
        name: "Database Connection Strings",
        description: "Exposed database URIs with host, port, and credential information",
        queryTemplate: '{{domain}} "mongodb://" OR "mysql://" OR "postgresql://" OR "redis://"',
        severity: "critical",
        tags: ["code_leak", "credential", "database"]
      },
      // ── SSH & Certificates ────────────────────────────────────────────
      {
        id: "ssh_keys",
        name: "SSH Private Keys",
        description: "Exposed SSH private keys that could grant server access",
        queryTemplate: '{{domain}} "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"',
        severity: "critical",
        tags: ["code_leak", "credential", "ssh_key"]
      },
      {
        id: "ssl_certs",
        name: "SSL/TLS Certificates & Keys",
        description: "Exposed SSL certificates and private keys",
        queryTemplate: '{{domain}} "BEGIN CERTIFICATE" filename:.pem OR filename:.key',
        severity: "high",
        tags: ["code_leak", "credential", "certificate"]
      },
      // ── CI/CD & Deployment ────────────────────────────────────────────
      {
        id: "ci_cd",
        name: "CI/CD Pipeline Configs",
        description: "GitHub Actions, Jenkins, GitLab CI configs with deployment secrets",
        queryTemplate: "{{domain}} filename:.github/workflows OR filename:Jenkinsfile OR filename:.gitlab-ci.yml",
        severity: "medium",
        tags: ["code_leak", "config_leak", "ci_cd"]
      },
      {
        id: "aws_credentials",
        name: "AWS Credentials",
        description: "AWS access key IDs and secret access keys",
        queryTemplate: "{{domain}} AKIA OR aws_access_key_id OR aws_secret_access_key",
        severity: "critical",
        tags: ["code_leak", "credential", "cloud", "aws"]
      }
    ];
    _leaksTokenPool = { tokens: [], idx: 0, rl: /* @__PURE__ */ new Map() };
    githubLeaksConnector = {
      name: "github_leaks",
      description: "GitHub code leak scanner \u2014 searches public repositories for exposed credentials, configuration files, API keys, and infrastructure details (Red Team Priority #10)",
      requiresApiKey: false,
      // Works without token, but rate-limited
      freeUrl: "https://github.com/search",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 1e4;
        const token = config?.apiKey;
        const now = /* @__PURE__ */ new Date();
        const maxResults = config?.maxResults ?? 30;
        const patternsToSearch = LEAK_PATTERNS.slice(0, 8);
        const seenRepoFiles = /* @__PURE__ */ new Set();
        for (const pattern of patternsToSearch) {
          const query = pattern.queryTemplate.replace("{{domain}}", domain);
          try {
            if (patternsToSearch.indexOf(pattern) > 0) {
              await new Promise((r) => setTimeout(r, 2200));
            }
            const result = await searchGitHubCode(query, token, timeout);
            if (!result) continue;
            for (const item of result.items) {
              const key = `${item.repository.full_name}:${item.path}`;
              if (seenRepoFiles.has(key)) continue;
              seenRepoFiles.add(key);
              if (item.repository.owner.login.toLowerCase() === domain.split(".")[0].toLowerCase()) {
                continue;
              }
              observations.push(buildObservation(domain, pattern, item, now));
              if (observations.length >= maxResults) break;
            }
            if (observations.length >= maxResults) break;
          } catch (err) {
            errors.push(`[${pattern.id}] ${err.message}`);
            if (err.message.includes("rate limit")) break;
          }
        }
        return {
          connector: "github_leaks",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: errors.some((e) => e.includes("rate limit"))
        };
      }
    };
  }
});

// server/lib/passive/github-recon.ts
import { createHash as createHash18 } from "crypto";
function makeAssetId18(domain, name, source) {
  return createHash18("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function getAvailableToken(primaryToken) {
  if (_tokenPool.tokens.length === 0) {
    const candidates = [
      primaryToken,
      process.env.GITHUB_PAT,
      process.env.GITHUB_CLASSIC_TOKEN
    ].filter((t) => !!t && t.length > 5);
    _tokenPool.tokens = [...new Set(candidates)];
  }
  const now = Date.now();
  for (let i = 0; i < _tokenPool.tokens.length; i++) {
    const idx = (_tokenPool.currentIdx + i) % _tokenPool.tokens.length;
    const t = _tokenPool.tokens[idx];
    const rlUntil = _tokenPool.rateLimited.get(t);
    if (!rlUntil || now > rlUntil) {
      _tokenPool.currentIdx = idx;
      return t;
    }
  }
  return primaryToken || _tokenPool.tokens[0];
}
function markTokenRateLimited(token, resetEpoch) {
  const resetMs = resetEpoch ? resetEpoch * 1e3 : Date.now() + 6e4;
  _tokenPool.rateLimited.set(token, resetMs);
  _tokenPool.currentIdx = (_tokenPool.currentIdx + 1) % Math.max(_tokenPool.tokens.length, 1);
}
async function githubFetch(url, token, timeout = 1e4) {
  const activeToken = getAvailableToken(token);
  const headers = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "AceStrike-OSINT/2.0"
  };
  if (activeToken) headers["Authorization"] = `Bearer ${activeToken}`;
  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(timeout)
    });
    if (res.status === 403 || res.status === 429) {
      const reset = res.headers.get("X-RateLimit-Reset");
      if (activeToken) markTokenRateLimited(activeToken, reset ? +reset : void 0);
      const fallback = getAvailableToken(token);
      if (fallback && fallback !== activeToken) {
        const h2 = { ...headers, Authorization: `Bearer ${fallback}` };
        const res2 = await fetch(url, { headers: h2, signal: AbortSignal.timeout(timeout) });
        if (res2.ok) return await res2.json();
        if (res2.status === 403 || res2.status === 429) {
          markTokenRateLimited(fallback, res2.headers.get("X-RateLimit-Reset") ? +res2.headers.get("X-RateLimit-Reset") : void 0);
        }
      }
      throw new Error(`Rate limited (all tokens exhausted). Resets: ${reset ? new Date(+reset * 1e3).toISOString() : "unknown"}`);
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub ${res.status}: ${res.statusText}`);
    return await res.json();
  } catch (err) {
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      throw new Error(`GitHub API timeout after ${timeout}ms`);
    }
    throw err;
  }
}
async function searchGitHubCode2(query, token, timeout = 1e4) {
  const activeToken = getAvailableToken(token);
  const headers = {
    Accept: "application/vnd.github.text-match+json",
    "User-Agent": "AceStrike-OSINT/2.0"
  };
  if (activeToken) headers["Authorization"] = `Bearer ${activeToken}`;
  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30&sort=indexed&order=desc`;
  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeout) });
    if (res.status === 403 || res.status === 429) {
      if (activeToken) markTokenRateLimited(activeToken);
      const fallback = getAvailableToken(token);
      if (fallback && fallback !== activeToken) {
        const h2 = { ...headers, Authorization: `Bearer ${fallback}` };
        const res2 = await fetch(url, { headers: h2, signal: AbortSignal.timeout(timeout) });
        if (res2.ok) return await res2.json();
        if (res2.status === 403 || res2.status === 429) markTokenRateLimited(fallback);
      }
      throw new Error("GitHub rate limit exceeded (all tokens exhausted)");
    }
    if (res.status === 422) return { total_count: 0, incomplete_results: false, items: [] };
    if (!res.ok) throw new Error(`GitHub ${res.status}`);
    return await res.json();
  } catch (err) {
    if (err.name === "TimeoutError" || err.name === "AbortError") return null;
    throw err;
  }
}
function deriveOrgCandidates(domain, orgName) {
  const parts = domain.split(".");
  const base = parts[0];
  const candidates = /* @__PURE__ */ new Set();
  candidates.add(base);
  candidates.add(base.replace(/[^a-z0-9]/gi, ""));
  candidates.add(base.replace(/[^a-z0-9]/gi, "-"));
  candidates.add(`${base}-inc`);
  candidates.add(`${base}-io`);
  candidates.add(`${base}hq`);
  candidates.add(`${base}-team`);
  candidates.add(`${base}-dev`);
  candidates.add(`${base}-labs`);
  candidates.add(`${base}-oss`);
  candidates.add(`${base}-engineering`);
  candidates.add(`${base}-security`);
  candidates.add(`${base}-infra`);
  if (orgName) {
    const clean = orgName.toLowerCase().replace(/[^a-z0-9]/gi, "");
    const dashed = orgName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/gi, "");
    candidates.add(clean);
    candidates.add(dashed);
    candidates.add(`${clean}hq`);
    candidates.add(`${clean}-inc`);
  }
  return Array.from(candidates).filter((c) => c.length >= 2);
}
async function discoverOrgs(domain, token, orgName, timeout = 8e3) {
  const candidates = deriveOrgCandidates(domain, orgName);
  const orgs = [];
  for (const candidate of candidates.slice(0, 15)) {
    try {
      const org = await githubFetch(
        `https://api.github.com/orgs/${encodeURIComponent(candidate)}`,
        token,
        timeout
      );
      if (org) {
        orgs.push(org);
        break;
      }
    } catch {
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (orgs.length === 0) {
    try {
      const searchResult = await githubFetch(
        `https://api.github.com/search/users?q=${encodeURIComponent(domain)}+type:org&per_page=5`,
        token,
        timeout
      );
      if (searchResult?.items) {
        for (const item of searchResult.items.slice(0, 3)) {
          const fullOrg = await githubFetch(
            `https://api.github.com/orgs/${item.login}`,
            token,
            timeout
          );
          if (fullOrg) orgs.push(fullOrg);
        }
      }
    } catch {
    }
  }
  return { orgs, candidates };
}
async function enumerateOrgRepos(orgLogin, token, maxPages = 3, timeout = 8e3) {
  const repos = [];
  for (let page = 1; page <= maxPages; page++) {
    const pageRepos = await githubFetch(
      `https://api.github.com/orgs/${encodeURIComponent(orgLogin)}/repos?per_page=100&page=${page}&sort=updated&direction=desc`,
      token,
      timeout
    );
    if (!pageRepos || pageRepos.length === 0) break;
    repos.push(...pageRepos);
    if (pageRepos.length < 100) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  return repos;
}
async function getOrgMembers(orgLogin, token, timeout = 8e3) {
  const members = await githubFetch(
    `https://api.github.com/orgs/${encodeURIComponent(orgLogin)}/members?per_page=100`,
    token,
    timeout
  );
  if (!members) return [];
  const detailed = [];
  for (const m of members.slice(0, 10)) {
    try {
      const user = await githubFetch(
        `https://api.github.com/users/${m.login}`,
        token,
        timeout
      );
      if (user) detailed.push(user);
      await new Promise((r) => setTimeout(r, 200));
    } catch {
    }
  }
  return detailed;
}
async function analyzeWorkflows(repoFullName, token, timeout = 8e3) {
  const result = {
    workflows: [],
    secretsReferenced: [],
    runnersUsed: [],
    thirdPartyActions: []
  };
  try {
    const wfResponse = await githubFetch(
      `https://api.github.com/repos/${repoFullName}/actions/workflows?per_page=30`,
      token,
      timeout
    );
    if (wfResponse?.workflows) {
      result.workflows = wfResponse.workflows;
    }
  } catch {
  }
  try {
    const searchResult = await searchGitHubCode2(
      `repo:${repoFullName} path:.github/workflows`,
      token,
      timeout
    );
    if (searchResult?.items) {
      for (const item of searchResult.items) {
        const fragment = item.text_matches?.[0]?.fragment || "";
        const secretMatches = fragment.match(/\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}/g);
        if (secretMatches) {
          result.secretsReferenced.push(
            ...secretMatches.map((m) => m.replace(/\$\{\{\s*secrets\.|\s*\}\}/g, ""))
          );
        }
        const runnerMatches = fragment.match(/runs-on:\s*([^\n]+)/g);
        if (runnerMatches) {
          result.runnersUsed.push(...runnerMatches.map((m) => m.replace("runs-on:", "").trim()));
        }
        const actionMatches = fragment.match(/uses:\s*([^\n@]+)/g);
        if (actionMatches) {
          result.thirdPartyActions.push(
            ...actionMatches.map((m) => m.replace("uses:", "").trim()).filter((a) => !a.startsWith("actions/") && !a.startsWith("./"))
          );
        }
      }
    }
  } catch {
  }
  result.secretsReferenced = [...new Set(result.secretsReferenced)];
  result.runnersUsed = [...new Set(result.runnersUsed)];
  result.thirdPartyActions = [...new Set(result.thirdPartyActions)];
  return result;
}
async function analyzeDependencies(repoFullName, token, timeout = 8e3) {
  const results = [];
  const depFiles = [
    { file: "package.json", manager: "npm" },
    { file: "requirements.txt", manager: "pip" },
    { file: "Gemfile", manager: "bundler" },
    { file: "go.mod", manager: "go" },
    { file: "pom.xml", manager: "maven" },
    { file: "build.gradle", manager: "gradle" },
    { file: "Cargo.toml", manager: "cargo" },
    { file: "composer.json", manager: "composer" }
  ];
  for (const { file, manager } of depFiles) {
    try {
      const content = await githubFetch(
        `https://api.github.com/repos/${repoFullName}/contents/${file}`,
        token,
        timeout
      );
      if (content?.content) {
        const decoded = Buffer.from(content.content, "base64").toString("utf-8");
        const deps = [];
        if (manager === "npm") {
          try {
            const pkg = JSON.parse(decoded);
            deps.push(...Object.keys(pkg.dependencies || {}));
            deps.push(...Object.keys(pkg.devDependencies || {}));
          } catch {
          }
        } else if (manager === "pip") {
          deps.push(...decoded.split("\n").filter((l) => l.trim() && !l.startsWith("#")).map((l) => l.split("==")[0].split(">=")[0].trim()));
        } else {
          deps.push(`[${manager} manifest detected]`);
        }
        if (deps.length > 0) {
          results.push({ packageManager: manager, dependencies: deps.slice(0, 50) });
        }
      }
    } catch {
    }
  }
  return results;
}
function scanForSecrets(text) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(text)) !== null) {
      const redacted = match[0].length > 12 ? match[0].slice(0, 6) + "..." + match[0].slice(-4) : match[0].slice(0, 4) + "...";
      findings.push({ pattern, match: redacted });
    }
  }
  return findings;
}
function buildOrgObservation(domain, org, now) {
  return {
    assetId: makeAssetId18(domain, `github_org:${org.login}`, "github_recon"),
    domain,
    assetType: "url",
    name: `GitHub Org: ${org.login} (${org.public_repos} public repos)`,
    source: "github_recon",
    observedAt: now,
    tags: ["github", "organization", "code_repository", `repos:${org.public_repos}`],
    evidence: {
      orgLogin: org.login,
      orgUrl: org.html_url,
      publicRepos: org.public_repos,
      description: org.description,
      blog: org.blog,
      email: org.email,
      location: org.location,
      createdAt: org.created_at
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Discovered GitHub organization '${org.login}' linked to ${domain}`,
      url: org.html_url,
      verifyUrl: org.html_url
    }
  };
}
function buildRepoObservation(domain, repo, now) {
  const riskTags = ["github", "repository"];
  if (repo.fork) riskTags.push("forked_repo");
  if (repo.archived) riskTags.push("archived_repo");
  if (repo.has_wiki) riskTags.push("wiki_enabled");
  if (repo.has_pages) riskTags.push("github_pages");
  if (repo.stargazers_count > 100) riskTags.push("popular_repo");
  if (repo.language) riskTags.push(`lang:${repo.language.toLowerCase()}`);
  if (repo.topics?.length) riskTags.push(...repo.topics.slice(0, 5).map((t) => `topic:${t}`));
  return {
    assetId: makeAssetId18(domain, `github_repo:${repo.full_name}`, "github_recon"),
    domain,
    assetType: "url",
    name: `Repo: ${repo.full_name} (${repo.language || "unknown"}, \u2605${repo.stargazers_count})`,
    source: "github_recon",
    observedAt: now,
    lastSeen: new Date(repo.pushed_at),
    tags: riskTags,
    evidence: {
      repoName: repo.name,
      fullName: repo.full_name,
      repoUrl: repo.html_url,
      description: repo.description,
      language: repo.language,
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      openIssues: repo.open_issues_count,
      isFork: repo.fork,
      isArchived: repo.archived,
      hasWiki: repo.has_wiki,
      hasPages: repo.has_pages,
      topics: repo.topics,
      defaultBranch: repo.default_branch,
      sizeKb: repo.size,
      createdAt: repo.created_at,
      lastPushed: repo.pushed_at,
      owner: repo.owner.login,
      ownerType: repo.owner.type
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Enumerated public repository '${repo.full_name}' from organization`,
      url: repo.html_url,
      verifyUrl: repo.html_url
    }
  };
}
function buildContributorObservation(domain, user, orgLogin, now) {
  return {
    assetId: makeAssetId18(domain, `github_user:${user.login}`, "github_recon"),
    domain,
    assetType: "url",
    name: `Contributor: ${user.name || user.login} (${user.public_repos} repos, ${user.followers} followers)`,
    source: "github_recon",
    observedAt: now,
    tags: ["github", "contributor", "developer", `org:${orgLogin}`],
    evidence: {
      login: user.login,
      name: user.name,
      profileUrl: user.html_url,
      company: user.company,
      blog: user.blog,
      location: user.location,
      email: user.email,
      bio: user.bio,
      publicRepos: user.public_repos,
      publicGists: user.public_gists,
      followers: user.followers,
      createdAt: user.created_at,
      organization: orgLogin
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Mapped contributor '${user.login}' from organization '${orgLogin}'`,
      url: user.html_url,
      verifyUrl: user.html_url
    }
  };
}
function buildDorkObservation(domain, dork, item, secretFindings, now) {
  const tags = [
    "github",
    "code_leak",
    `category:${dork.category}`,
    `severity:${dork.severity}`,
    item.repository.fork ? "forked_repo" : "original_repo"
  ];
  if (secretFindings.length > 0) {
    tags.push("secrets_detected", ...secretFindings.map((f) => `secret:${f.pattern.id}`));
  }
  return {
    assetId: makeAssetId18(domain, `github_dork:${dork.id}:${item.repository.full_name}:${item.path}`, "github_recon"),
    domain,
    assetType: "url",
    name: `[${dork.name}] ${item.repository.full_name}/${item.path}`,
    source: "github_recon",
    observedAt: now,
    lastSeen: item.repository.updated_at ? new Date(item.repository.updated_at) : now,
    tags,
    evidence: {
      dorkId: dork.id,
      dorkName: dork.name,
      dorkCategory: dork.category,
      severity: dork.severity,
      repository: item.repository.full_name,
      repoUrl: item.repository.html_url,
      filePath: item.path,
      fileUrl: item.html_url,
      repoOwner: item.repository.owner.login,
      repoOwnerType: item.repository.owner.type,
      isFork: item.repository.fork,
      textSnippet: item.text_matches?.[0]?.fragment?.slice(0, 300) || "",
      secretsFound: secretFindings.map((f) => ({
        type: f.pattern.name,
        severity: f.pattern.severity,
        redactedMatch: f.match
      })),
      secretCount: secretFindings.length
    },
    attribution: {
      provider: "GitHub Code Search API",
      method: `GitHub dork '${dork.name}' found match in ${item.repository.full_name}`,
      url: item.html_url,
      verifyUrl: item.html_url
    }
  };
}
function buildWorkflowObservation(domain, repoFullName, analysis, now) {
  const tags = ["github", "ci_cd", "github_actions"];
  if (analysis.thirdPartyActions.length > 5) tags.push("supply_chain_risk");
  if (analysis.secretsReferenced.length > 0) tags.push("secrets_in_workflows");
  return {
    assetId: makeAssetId18(domain, `github_cicd:${repoFullName}`, "github_recon"),
    domain,
    assetType: "url",
    name: `CI/CD: ${repoFullName} (${analysis.workflows.length} workflows, ${analysis.secretsReferenced.length} secrets refs)`,
    source: "github_recon",
    observedAt: now,
    tags,
    evidence: {
      repository: repoFullName,
      workflowCount: analysis.workflows.length,
      workflows: analysis.workflows.map((w) => ({ name: w.name, path: w.path, state: w.state })),
      secretsReferenced: analysis.secretsReferenced,
      runnersUsed: analysis.runnersUsed,
      thirdPartyActions: analysis.thirdPartyActions,
      supplyChainRisk: analysis.thirdPartyActions.length > 5 ? "elevated" : "normal"
    },
    attribution: {
      provider: "GitHub REST API + Code Search",
      method: `Analyzed CI/CD workflows in ${repoFullName}`,
      url: `https://github.com/${repoFullName}/actions`,
      verifyUrl: `https://github.com/${repoFullName}/actions`
    }
  };
}
var SECRET_PATTERNS, GITHUB_DORKS, _tokenPool, githubReconConnector;
var init_github_recon = __esm({
  "server/lib/passive/github-recon.ts"() {
    "use strict";
    SECRET_PATTERNS = [
      // AWS
      { id: "aws_access_key", name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g, severity: "critical", description: "AWS IAM access key identifier" },
      { id: "aws_secret_key", name: "AWS Secret Access Key", regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g, severity: "critical", description: "AWS IAM secret access key" },
      // Azure
      { id: "azure_storage_key", name: "Azure Storage Account Key", regex: /(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?/g, severity: "critical", description: "Azure Storage account access key" },
      { id: "azure_client_secret", name: "Azure AD Client Secret", regex: /(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,})['"]?/g, severity: "critical", description: "Azure Active Directory application secret" },
      // GCP
      { id: "gcp_service_account", name: "GCP Service Account Key", regex: /"type"\s*:\s*"service_account"/g, severity: "critical", description: "Google Cloud Platform service account JSON key" },
      { id: "gcp_api_key", name: "GCP API Key", regex: /AIza[0-9A-Za-z_-]{35}/g, severity: "high", description: "Google Cloud Platform API key" },
      // GitHub
      { id: "github_pat", name: "GitHub Personal Access Token", regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: "critical", description: "GitHub personal access or secret token" },
      { id: "github_oauth", name: "GitHub OAuth Token", regex: /gho_[A-Za-z0-9_]{36,}/g, severity: "critical", description: "GitHub OAuth access token" },
      // Stripe
      { id: "stripe_secret", name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical", description: "Stripe live secret API key" },
      { id: "stripe_publishable", name: "Stripe Publishable Key", regex: /pk_live_[0-9a-zA-Z]{24,}/g, severity: "medium", description: "Stripe live publishable key" },
      // Slack
      { id: "slack_token", name: "Slack Token", regex: /xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g, severity: "high", description: "Slack bot, user, or workspace token" },
      { id: "slack_webhook", name: "Slack Webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/g, severity: "high", description: "Slack incoming webhook URL" },
      // Database
      { id: "db_connection_string", name: "Database Connection String", regex: /(?:mongodb|mysql|postgresql|postgres|redis|mssql):\/\/[^\s'"]{10,}/g, severity: "critical", description: "Database connection URI with potential credentials" },
      // JWT
      { id: "jwt_secret", name: "JWT Secret", regex: /(?:JWT_SECRET|jwt_secret|JWT_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{16,})['"]?/g, severity: "high", description: "JSON Web Token signing secret" },
      // Private Keys
      { id: "rsa_private_key", name: "RSA Private Key", regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: "critical", description: "RSA private key (PEM format)" },
      { id: "ssh_private_key", name: "SSH Private Key", regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical", description: "OpenSSH private key" },
      // SendGrid / Mailgun / Twilio
      { id: "sendgrid_key", name: "SendGrid API Key", regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: "high", description: "SendGrid API key" },
      { id: "twilio_sid", name: "Twilio Account SID", regex: /AC[a-f0-9]{32}/g, severity: "high", description: "Twilio account SID" },
      // Generic
      { id: "generic_api_key", name: "Generic API Key Pattern", regex: /(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?/g, severity: "medium", description: "Generic API key assignment" },
      { id: "generic_secret", name: "Generic Secret Pattern", regex: /(?:secret|SECRET|password|PASSWORD|passwd|PASSWD)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/g, severity: "medium", description: "Generic secret or password assignment" }
    ];
    GITHUB_DORKS = [
      // ── Credentials ──────────────────────────────────────────────────
      { id: "env_production", name: "Production .env Files", category: "credentials", queryTemplate: "{{domain}} filename:.env.production", severity: "critical", description: "Production environment configuration with live credentials" },
      { id: "env_local", name: "Local .env Files", category: "credentials", queryTemplate: "{{domain}} filename:.env.local", severity: "high", description: "Local environment files that may contain development credentials" },
      { id: "htpasswd", name: "Apache .htpasswd", category: "credentials", queryTemplate: "{{domain}} filename:.htpasswd", severity: "critical", description: "Apache HTTP authentication password files" },
      { id: "netrc", name: ".netrc Credentials", category: "credentials", queryTemplate: "{{domain}} filename:.netrc", severity: "critical", description: "Machine login credentials for FTP/HTTP" },
      { id: "npmrc_auth", name: "NPM Auth Tokens", category: "credentials", queryTemplate: "{{domain}} filename:.npmrc _authToken", severity: "critical", description: "NPM registry authentication tokens" },
      { id: "pypirc", name: "PyPI Credentials", category: "credentials", queryTemplate: "{{domain}} filename:.pypirc", severity: "high", description: "Python Package Index upload credentials" },
      { id: "aws_credentials", name: "AWS Credentials File", category: "credentials", queryTemplate: "{{domain}} filename:credentials aws_access_key_id", severity: "critical", description: "AWS CLI credential files with access keys" },
      { id: "kubeconfig", name: "Kubernetes Config", category: "credentials", queryTemplate: "{{domain}} filename:kubeconfig OR filename:.kube/config", severity: "critical", description: "Kubernetes cluster configuration with auth tokens" },
      // ── Infrastructure ───────────────────────────────────────────────
      { id: "terraform_state", name: "Terraform State Files", category: "infrastructure", queryTemplate: "{{domain}} filename:terraform.tfstate", severity: "critical", description: "Terraform state files containing infrastructure secrets and resource IDs" },
      { id: "ansible_vault", name: "Ansible Vault Files", category: "infrastructure", queryTemplate: "{{domain}} filename:vault.yml OR filename:vault.yaml ansible_vault", severity: "high", description: "Ansible vault encrypted secrets files" },
      { id: "docker_env", name: "Docker Environment Files", category: "infrastructure", queryTemplate: "{{domain}} filename:docker-compose.yml environment", severity: "high", description: "Docker Compose files with environment variable definitions" },
      { id: "k8s_secrets", name: "Kubernetes Secrets", category: "infrastructure", queryTemplate: "{{domain}} kind: Secret filename:.yaml OR filename:.yml", severity: "critical", description: "Kubernetes Secret manifests with base64-encoded credentials" },
      { id: "helm_values", name: "Helm Values Files", category: "infrastructure", queryTemplate: "{{domain}} filename:values.yaml password OR secret OR token", severity: "high", description: "Helm chart values files with sensitive configuration" },
      // ── CI/CD ────────────────────────────────────────────────────────
      { id: "github_actions_secrets", name: "GitHub Actions Secrets Refs", category: "ci_cd", queryTemplate: "{{domain}} filename:.github/workflows secrets.", severity: "medium", description: "GitHub Actions workflows referencing repository secrets" },
      { id: "circleci_config", name: "CircleCI Configuration", category: "ci_cd", queryTemplate: "{{domain}} filename:.circleci/config.yml", severity: "medium", description: "CircleCI pipeline configuration files" },
      { id: "travis_config", name: "Travis CI Configuration", category: "ci_cd", queryTemplate: "{{domain}} filename:.travis.yml", severity: "medium", description: "Travis CI configuration with potential encrypted secrets" },
      { id: "jenkins_credentials", name: "Jenkins Credentials", category: "ci_cd", queryTemplate: "{{domain}} filename:Jenkinsfile credentials OR withCredentials", severity: "high", description: "Jenkins pipeline files referencing credential stores" },
      // ── Cloud ────────────────────────────────────────────────────────
      { id: "s3_bucket_refs", name: "S3 Bucket References", category: "cloud", queryTemplate: "{{domain}} s3.amazonaws.com OR s3:// bucket", severity: "medium", description: "References to S3 buckets in code" },
      { id: "gcs_bucket_refs", name: "GCS Bucket References", category: "cloud", queryTemplate: "{{domain}} storage.googleapis.com OR gs://", severity: "medium", description: "References to Google Cloud Storage buckets" },
      { id: "azure_blob_refs", name: "Azure Blob References", category: "cloud", queryTemplate: "{{domain}} blob.core.windows.net", severity: "medium", description: "References to Azure Blob Storage containers" },
      // ── Network ──────────────────────────────────────────────────────
      { id: "vpn_configs", name: "VPN Configuration Files", category: "network", queryTemplate: "{{domain}} filename:.ovpn OR filename:vpn.conf", severity: "high", description: "OpenVPN or VPN configuration files with connection details" },
      { id: "ssh_config", name: "SSH Configuration", category: "network", queryTemplate: "{{domain}} filename:ssh_config OR filename:sshd_config", severity: "high", description: "SSH client/server configuration files" },
      { id: "hosts_file", name: "Internal Hosts Mapping", category: "network", queryTemplate: "{{domain}} filename:hosts 10. OR 172. OR 192.168.", severity: "medium", description: "Hosts files revealing internal network topology" },
      // ── Sensitive Files ──────────────────────────────────────────────
      { id: "sql_dumps", name: "SQL Database Dumps", category: "sensitive_files", queryTemplate: "{{domain}} filename:.sql INSERT INTO OR CREATE TABLE", severity: "critical", description: "SQL database dump files with potential PII or credentials" },
      { id: "backup_files", name: "Backup Archives", category: "sensitive_files", queryTemplate: "{{domain}} filename:.bak OR filename:.backup OR filename:.old", severity: "medium", description: "Backup files that may contain sensitive data" },
      { id: "log_files", name: "Application Log Files", category: "sensitive_files", queryTemplate: "{{domain}} filename:.log password OR token OR error", severity: "medium", description: "Log files with potential credential leaks or error details" },
      { id: "swagger_docs", name: "API Documentation (Swagger/OpenAPI)", category: "sensitive_files", queryTemplate: "{{domain}} filename:swagger.json OR filename:openapi.yaml", severity: "low", description: "API documentation revealing endpoint structure" },
      { id: "postman_collection", name: "Postman Collections", category: "sensitive_files", queryTemplate: "{{domain}} filename:.postman_collection.json", severity: "high", description: "Postman API collections with potential auth tokens and endpoints" }
    ];
    _tokenPool = {
      tokens: [],
      currentIdx: 0,
      rateLimited: /* @__PURE__ */ new Map()
    };
    githubReconConnector = {
      name: "github_recon",
      description: "Enhanced GitHub reconnaissance \u2014 org discovery, repo enumeration, contributor mapping, CI/CD workflow analysis, secret scanning, and 30+ GitHub dork patterns (T1593.003, T1591.004, T1589.001)",
      requiresApiKey: false,
      freeUrl: "https://github.com/search",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 1e4;
        const token = config?.apiKey;
        const now = /* @__PURE__ */ new Date();
        const GLOBAL_TIMEOUT = 9e4;
        try {
          const { orgs } = await discoverOrgs(domain, token, void 0, timeout);
          for (const org of orgs) {
            observations.push(buildOrgObservation(domain, org, now));
          }
          if (orgs.length > 0 && Date.now() - start < GLOBAL_TIMEOUT) {
            const primaryOrg = orgs[0];
            const repos = await enumerateOrgRepos(primaryOrg.login, token, 2, timeout);
            const sortedRepos = repos.sort((a, b) => new Date(b.pushed_at).getTime() - new Date(a.pushed_at).getTime()).slice(0, 20);
            for (const repo of sortedRepos) {
              observations.push(buildRepoObservation(domain, repo, now));
            }
            if (Date.now() - start < GLOBAL_TIMEOUT) {
              try {
                const members = await getOrgMembers(primaryOrg.login, token, timeout);
                for (const member of members.slice(0, 10)) {
                  observations.push(buildContributorObservation(domain, member, primaryOrg.login, now));
                }
              } catch (err) {
                errors.push(`Contributor mapping: ${err.message}`);
              }
            }
            if (Date.now() - start < GLOBAL_TIMEOUT) {
              const activeRepos = sortedRepos.filter((r) => !r.archived && !r.fork).slice(0, 5);
              for (const repo of activeRepos) {
                if (Date.now() - start >= GLOBAL_TIMEOUT) break;
                try {
                  const wfAnalysis = await analyzeWorkflows(repo.full_name, token, timeout);
                  if (wfAnalysis.workflows.length > 0) {
                    observations.push(buildWorkflowObservation(domain, repo.full_name, wfAnalysis, now));
                  }
                  await new Promise((r) => setTimeout(r, 500));
                } catch (err) {
                  errors.push(`CI/CD analysis [${repo.name}]: ${err.message}`);
                }
              }
            }
            if (Date.now() - start < GLOBAL_TIMEOUT) {
              for (const repo of sortedRepos.filter((r) => !r.fork).slice(0, 3)) {
                if (Date.now() - start >= GLOBAL_TIMEOUT) break;
                try {
                  const deps = await analyzeDependencies(repo.full_name, token, timeout);
                  if (deps.length > 0) {
                    observations.push({
                      assetId: makeAssetId18(domain, `github_deps:${repo.full_name}`, "github_recon"),
                      domain,
                      assetType: "url",
                      name: `Dependencies: ${repo.full_name} (${deps.map((d) => `${d.packageManager}: ${d.dependencies.length}`).join(", ")})`,
                      source: "github_recon",
                      observedAt: now,
                      tags: ["github", "dependencies", "supply_chain", ...deps.map((d) => `pkg:${d.packageManager}`)],
                      evidence: {
                        repository: repo.full_name,
                        dependencyManifests: deps,
                        totalDependencies: deps.reduce((sum, d) => sum + d.dependencies.length, 0)
                      },
                      attribution: {
                        provider: "GitHub REST API",
                        method: `Analyzed dependency manifests in ${repo.full_name}`,
                        url: repo.html_url,
                        verifyUrl: repo.html_url
                      }
                    });
                  }
                  await new Promise((r) => setTimeout(r, 300));
                } catch {
                }
              }
            }
          }
          if (Date.now() - start < GLOBAL_TIMEOUT) {
            const priorityDorks = GITHUB_DORKS.filter((d) => d.severity === "critical" || d.severity === "high").slice(0, 12);
            const seenFiles = /* @__PURE__ */ new Set();
            for (const dork of priorityDorks) {
              if (Date.now() - start >= GLOBAL_TIMEOUT) break;
              const query = dork.queryTemplate.replace("{{domain}}", domain);
              try {
                await new Promise((r) => setTimeout(r, 2200));
                const result = await searchGitHubCode2(query, token, timeout);
                if (!result) continue;
                for (const item of result.items.slice(0, 5)) {
                  const key = `${item.repository.full_name}:${item.path}`;
                  if (seenFiles.has(key)) continue;
                  seenFiles.add(key);
                  const fragment = item.text_matches?.[0]?.fragment || "";
                  const secretFindings = scanForSecrets(fragment);
                  observations.push(buildDorkObservation(domain, dork, item, secretFindings, now));
                }
              } catch (err) {
                errors.push(`[dork:${dork.id}] ${err.message}`);
                if (err.message.includes("rate limit")) break;
              }
            }
          }
          const orgCount = observations.filter((o) => o.tags.includes("organization")).length;
          const repoCount = observations.filter((o) => o.tags.includes("repository")).length;
          const contributorCount = observations.filter((o) => o.tags.includes("contributor")).length;
          const dorkFindings = observations.filter((o) => o.tags.includes("code_leak")).length;
          const cicdFindings = observations.filter((o) => o.tags.includes("ci_cd")).length;
          const secretsDetected = observations.filter((o) => o.tags.includes("secrets_detected")).length;
          observations.push({
            assetId: makeAssetId18(domain, `github_recon_summary:${domain}`, "github_recon"),
            domain,
            assetType: "url",
            name: `GitHub Recon Summary: ${orgCount} orgs, ${repoCount} repos, ${contributorCount} contributors, ${dorkFindings} code leaks, ${cicdFindings} CI/CD, ${secretsDetected} secrets`,
            source: "github_recon",
            observedAt: now,
            tags: [
              "github",
              "recon_summary",
              ...secretsDetected > 0 ? ["secrets_exposed"] : [],
              ...dorkFindings > 5 ? ["high_exposure"] : []
            ],
            evidence: {
              organizationsFound: orgCount,
              repositoriesEnumerated: repoCount,
              contributorsMapped: contributorCount,
              codeLeakFindings: dorkFindings,
              cicdAnalyzed: cicdFindings,
              secretsDetected,
              scanDurationMs: Date.now() - start
            },
            attribution: {
              provider: "GitHub REST API + Code Search",
              method: `Comprehensive GitHub reconnaissance for ${domain}`
            }
          });
        } catch (err) {
          errors.push(`GitHub recon top-level error: ${err.message}`);
        }
        return {
          connector: "github_recon",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: errors.some((e) => e.includes("rate limit"))
        };
      }
    };
  }
});

// server/lib/passive/cloud-bucket-recon.ts
import { createHash as createHash19 } from "crypto";
function makeAssetId19(domain, name, source) {
  return createHash19("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function generateBucketCandidates(domain, orgName, industry) {
  const parts = domain.split(".");
  const base = parts[0];
  const baseClean = base.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const baseDashed = base.replace(/[^a-z0-9]/gi, "-").toLowerCase();
  const domainDashed = domain.replace(/\./g, "-").toLowerCase();
  const domainUnderscore = domain.replace(/\./g, "_").toLowerCase();
  const roots = /* @__PURE__ */ new Set();
  roots.add(baseClean);
  if (baseDashed !== baseClean) roots.add(baseDashed);
  roots.add(domainDashed);
  roots.add(domainUnderscore);
  if (base.includes("-") || base.includes("_")) {
    const acronym = base.split(/[-_]/).map((p) => p[0]).join("").toLowerCase();
    if (acronym.length >= 2) roots.add(acronym);
  }
  if (orgName) {
    const orgClean = orgName.toLowerCase().replace(/[^a-z0-9]/gi, "");
    const orgDashed = orgName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/gi, "");
    roots.add(orgClean);
    if (orgDashed !== orgClean) roots.add(orgDashed);
    const orgWords = orgName.split(/\s+/);
    if (orgWords.length >= 2) {
      const orgAcronym = orgWords.map((w) => w[0]).join("").toLowerCase();
      if (orgAcronym.length >= 2) roots.add(orgAcronym);
    }
  }
  if (industry) {
    const indClean = industry.toLowerCase().replace(/[^a-z0-9]/gi, "");
    roots.add(`${baseClean}-${indClean}`);
  }
  const candidates = /* @__PURE__ */ new Set();
  for (const root of roots) {
    for (const suffix of INDUSTRY_SUFFIXES) {
      const candidate = `${root}${suffix}`;
      if (candidate.length >= 3 && candidate.length <= 63) {
        candidates.add(candidate);
      }
    }
  }
  return Array.from(candidates);
}
async function probeBucket2(candidate, endpoint, region, timeout) {
  const url = endpoint.buildUrl(candidate, region);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(timeout),
      redirect: "follow",
      headers: { "User-Agent": "AceStrike-CloudRecon/2.0" }
    });
    const body = res.status === 200 ? await res.text().catch(() => "") : "";
    const status = endpoint.parseStatus(res.status, body);
    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      if (["server", "x-amz-request-id", "x-goog-generation", "x-ms-request-id"].includes(k.toLowerCase())) {
        headers[k] = v;
      }
    }
    return {
      provider: endpoint.provider,
      providerLabel: endpoint.label,
      bucketName: candidate,
      url,
      status,
      statusCode: res.status,
      region,
      responseHeaders: Object.keys(headers).length > 0 ? headers : void 0,
      responseBody: body.slice(0, 5e3)
      // Limit body size
    };
  } catch {
    return {
      provider: endpoint.provider,
      providerLabel: endpoint.label,
      bucketName: candidate,
      url,
      status: "error",
      statusCode: 0,
      region
    };
  }
}
function analyzePermissions(probe) {
  const result = {
    canList: false,
    canRead: false,
    canWrite: false,
    aclPublic: false,
    sampleFiles: [],
    sensitiveFiles: []
  };
  if (probe.status === "public_list" || probe.status === "public_read") {
    result.canList = probe.status === "public_list";
    result.canRead = true;
    if (probe.responseBody) {
      const keyMatches = probe.responseBody.match(/<Key>([^<]+)<\/Key>/g);
      if (keyMatches) {
        const files = keyMatches.map((m) => m.replace(/<\/?Key>/g, ""));
        result.fileCount = files.length;
        result.sampleFiles = files.slice(0, 20);
        for (const file of files) {
          for (const pattern of SENSITIVE_FILE_PATTERNS) {
            if (pattern.test(file)) {
              result.sensitiveFiles.push(file);
              break;
            }
          }
        }
      }
      const blobMatches = probe.responseBody.match(/<Name>([^<]+)<\/Name>/g);
      if (blobMatches && !keyMatches) {
        const files = blobMatches.map((m) => m.replace(/<\/?Name>/g, ""));
        result.fileCount = files.length;
        result.sampleFiles = files.slice(0, 20);
        for (const file of files) {
          for (const pattern of SENSITIVE_FILE_PATTERNS) {
            if (pattern.test(file)) {
              result.sensitiveFiles.push(file);
              break;
            }
          }
        }
      }
      const sizeMatches = probe.responseBody.match(/<Size>(\d+)<\/Size>/g);
      if (sizeMatches) {
        const totalBytes = sizeMatches.reduce((sum, m) => {
          const size = parseInt(m.replace(/<\/?Size>/g, ""), 10);
          return sum + (isNaN(size) ? 0 : size);
        }, 0);
        if (totalBytes > 1e9) result.totalSizeEstimate = `${(totalBytes / 1e9).toFixed(1)} GB`;
        else if (totalBytes > 1e6) result.totalSizeEstimate = `${(totalBytes / 1e6).toFixed(1)} MB`;
        else result.totalSizeEstimate = `${(totalBytes / 1e3).toFixed(1)} KB`;
      }
    }
  }
  return result;
}
function buildBucketObservation(domain, probe, permissions, now) {
  const isPublic = probe.status === "public_list" || probe.status === "public_read" || probe.status === "public_read_write";
  const hasSensitiveFiles = permissions.sensitiveFiles.length > 0;
  const tags = [
    "cloud_asset",
    `provider:${probe.provider}`,
    isPublic ? "public_bucket" : "private_bucket"
  ];
  if (isPublic) {
    tags.push("critical_misconfiguration", "data_exposure_risk");
    if (permissions.canList) tags.push("public_listing");
    if (permissions.canWrite) tags.push("public_write", "critical_write_access");
    if (hasSensitiveFiles) tags.push("sensitive_files_exposed", "credential_exposure_risk");
  }
  let severity = "low";
  if (isPublic && hasSensitiveFiles) severity = "critical";
  else if (isPublic && permissions.canWrite) severity = "critical";
  else if (isPublic && permissions.canList) severity = "high";
  else if (isPublic) severity = "high";
  else if (probe.status === "exists_private") severity = "low";
  return {
    assetId: makeAssetId19(domain, `cloud_bucket:${probe.provider}:${probe.bucketName}`, "cloud_bucket_recon"),
    domain,
    assetType: "url",
    name: `${probe.providerLabel}: ${probe.bucketName} (${isPublic ? "PUBLIC" : "private"}${hasSensitiveFiles ? " \u2014 SENSITIVE FILES" : ""})`,
    source: "cloud_bucket_recon",
    observedAt: now,
    tags,
    evidence: {
      bucketName: probe.bucketName,
      provider: probe.provider,
      providerLabel: probe.providerLabel,
      url: probe.url,
      status: probe.status,
      statusCode: probe.statusCode,
      region: probe.region,
      severity,
      permissions: {
        canList: permissions.canList,
        canRead: permissions.canRead,
        canWrite: permissions.canWrite,
        aclPublic: permissions.aclPublic
      },
      fileCount: permissions.fileCount,
      sampleFiles: permissions.sampleFiles.slice(0, 10),
      sensitiveFiles: permissions.sensitiveFiles.slice(0, 20),
      totalSizeEstimate: permissions.totalSizeEstimate,
      responseHeaders: probe.responseHeaders
    },
    attribution: {
      provider: `${probe.providerLabel} Bucket Probe`,
      url: probe.url,
      method: `Probed ${probe.providerLabel} endpoint for bucket '${probe.bucketName}' derived from ${domain}`,
      verifyUrl: probe.url
    }
  };
}
var PROVIDERS, INDUSTRY_SUFFIXES, SENSITIVE_FILE_PATTERNS, cloudBucketReconConnector;
var init_cloud_bucket_recon = __esm({
  "server/lib/passive/cloud-bucket-recon.ts"() {
    "use strict";
    PROVIDERS = [
      {
        provider: "aws",
        label: "AWS S3",
        buildUrl: (bucket, region) => region ? `https://${bucket}.s3.${region}.amazonaws.com/` : `https://${bucket}.s3.amazonaws.com/`,
        parseStatus: (status, body) => {
          if (status === 200) return "public_list";
          if (status === 403) return "exists_private";
          if (status === 301) return "redirect";
          if (status === 404) return "not_found";
          return "error";
        },
        regions: ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
      },
      {
        provider: "azure",
        label: "Azure Blob Storage",
        buildUrl: (bucket) => `https://${bucket}.blob.core.windows.net/?comp=list&restype=container`,
        parseStatus: (status) => {
          if (status === 200) return "public_list";
          if (status === 403 || status === 409) return "exists_private";
          if (status === 404) return "not_found";
          return "error";
        }
      },
      {
        provider: "gcp",
        label: "Google Cloud Storage",
        buildUrl: (bucket) => `https://storage.googleapis.com/${bucket}/`,
        parseStatus: (status) => {
          if (status === 200) return "public_list";
          if (status === 403) return "exists_private";
          if (status === 404) return "not_found";
          return "error";
        }
      },
      {
        provider: "digitalocean",
        label: "DigitalOcean Spaces",
        buildUrl: (bucket, region) => `https://${bucket}.${region || "nyc3"}.digitaloceanspaces.com/`,
        parseStatus: (status) => {
          if (status === 200) return "public_list";
          if (status === 403) return "exists_private";
          if (status === 404) return "not_found";
          return "error";
        },
        regions: ["nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1"]
      },
      {
        provider: "alibaba",
        label: "Alibaba Cloud OSS",
        buildUrl: (bucket, region) => `https://${bucket}.oss-${region || "us-east-1"}.aliyuncs.com/`,
        parseStatus: (status) => {
          if (status === 200) return "public_list";
          if (status === 403) return "exists_private";
          if (status === 404) return "not_found";
          return "error";
        },
        regions: ["us-east-1", "cn-hangzhou", "ap-southeast-1", "eu-central-1"]
      }
    ];
    INDUSTRY_SUFFIXES = [
      // Common
      "",
      "-backup",
      "-backups",
      "-bak",
      "-dev",
      "-development",
      "-staging",
      "-stg",
      "-prod",
      "-production",
      "-prd",
      "-assets",
      "-static",
      "-media",
      "-uploads",
      "-data",
      "-logs",
      "-public",
      "-private",
      "-internal",
      "-docs",
      "-files",
      "-cdn",
      "-images",
      "-web",
      "-api",
      "-config",
      "-configs",
      // DevOps / Infrastructure
      "-terraform",
      "-tf-state",
      "-tfstate",
      "-ansible",
      "-deploy",
      "-deployments",
      "-artifacts",
      "-builds",
      "-releases",
      "-packages",
      "-docker",
      "-containers",
      "-k8s",
      "-kubernetes",
      "-helm",
      "-charts",
      // Data / Analytics
      "-datalake",
      "-data-lake",
      "-warehouse",
      "-analytics",
      "-reports",
      "-exports",
      "-imports",
      "-etl",
      "-pipeline",
      "-raw",
      "-processed",
      "-archive",
      "-archives",
      // Security / Compliance
      "-security",
      "-audit",
      "-compliance",
      "-scans",
      "-vulnerabilities",
      "-certs",
      "-certificates",
      "-keys",
      "-secrets",
      // Application
      "-app",
      "-application",
      "-frontend",
      "-backend",
      "-mobile",
      "-desktop",
      "-emails",
      "-notifications",
      "-temp",
      "-tmp",
      "-cache",
      "-test",
      "-testing",
      "-qa",
      "-uat",
      "-sandbox",
      // Database
      "-db-backup",
      "-db-backups",
      "-database",
      "-mysql-backup",
      "-pg-backup",
      "-mongo-backup",
      "-redis-backup",
      "-snapshots"
    ];
    SENSITIVE_FILE_PATTERNS = [
      /\.env$/i,
      /\.pem$/i,
      /\.key$/i,
      /\.p12$/i,
      /\.pfx$/i,
      /\.sql$/i,
      /\.bak$/i,
      /\.backup$/i,
      /\.dump$/i,
      /password/i,
      /credential/i,
      /secret/i,
      /\.htpasswd$/i,
      /\.git\//i,
      /\.ssh\//i,
      /id_rsa/i,
      /\.csv$/i,
      /\.xlsx?$/i,
      /terraform\.tfstate/i,
      /\.tfvars$/i,
      /kubeconfig/i,
      /docker-compose/i,
      /\.npmrc$/i,
      /\.pypirc$/i,
      /\.netrc$/i,
      /\.pgpass$/i,
      /\.my\.cnf$/i
    ];
    cloudBucketReconConnector = {
      name: "cloud_bucket_recon",
      description: "Enhanced cloud storage enumeration \u2014 probes AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces, and Alibaba OSS with intelligent wordlists, permission depth analysis, and sensitive file detection (T1530, T1619)",
      requiresApiKey: false,
      freeUrl: "https://buckets.grayhatwarfare.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 4e3;
        const now = /* @__PURE__ */ new Date();
        const GLOBAL_TIMEOUT = 3e4;
        const CONCURRENCY = 15;
        try {
          const candidates = generateBucketCandidates(domain);
          const priorityCandidates = candidates.slice(0, 40);
          const probeList = [];
          for (const candidate of priorityCandidates) {
            for (const endpoint of PROVIDERS) {
              if (endpoint.regions) {
                for (const region of endpoint.regions.slice(0, 2)) {
                  probeList.push({ candidate, endpoint, region });
                }
              } else {
                probeList.push({ candidate, endpoint });
              }
            }
          }
          const results = [];
          let aborted = false;
          for (let i = 0; i < probeList.length && !aborted; i += CONCURRENCY) {
            if (Date.now() - start >= GLOBAL_TIMEOUT) {
              aborted = true;
              break;
            }
            const batch = probeList.slice(i, i + CONCURRENCY);
            const batchResults = await Promise.allSettled(
              batch.map((p) => probeBucket2(p.candidate, p.endpoint, p.region, timeout))
            );
            for (const r of batchResults) {
              if (r.status === "fulfilled" && r.value.status !== "error" && r.value.status !== "not_found") {
                results.push(r.value);
              }
            }
          }
          const found = results.filter(
            (r) => r.status === "public_list" || r.status === "public_read" || r.status === "public_read_write" || r.status === "exists_private" || r.status === "redirect"
          );
          const seen = /* @__PURE__ */ new Set();
          const uniqueFound = [];
          for (const bucket of found) {
            const key = `${bucket.provider}:${bucket.bucketName}`;
            if (!seen.has(key)) {
              seen.add(key);
              uniqueFound.push(bucket);
            }
          }
          for (const bucket of uniqueFound) {
            const permissions = analyzePermissions(bucket);
            observations.push(buildBucketObservation(domain, bucket, permissions, now));
          }
          const publicBuckets = uniqueFound.filter(
            (r) => r.status === "public_list" || r.status === "public_read" || r.status === "public_read_write"
          );
          const privateBuckets = uniqueFound.filter((r) => r.status === "exists_private");
          const redirectBuckets = uniqueFound.filter((r) => r.status === "redirect");
          const sensitiveFileCount = observations.reduce(
            (sum, o) => sum + (o.evidence?.sensitiveFiles?.length || 0),
            0
          );
          const byProvider = {};
          for (const b of uniqueFound) {
            byProvider[b.providerLabel] = (byProvider[b.providerLabel] || 0) + 1;
          }
          let riskLevel = "none";
          if (sensitiveFileCount > 0 || publicBuckets.some((b) => b.status === "public_read_write")) {
            riskLevel = "critical";
          } else if (publicBuckets.length > 0) {
            riskLevel = "high";
          } else if (privateBuckets.length > 0) {
            riskLevel = "medium";
          } else if (redirectBuckets.length > 0) {
            riskLevel = "low";
          }
          observations.push({
            assetId: makeAssetId19(domain, `cloud_bucket_summary:${domain}`, "cloud_bucket_recon"),
            domain,
            assetType: "url",
            name: `Cloud Bucket Recon: ${uniqueFound.length} found (${publicBuckets.length} public, ${privateBuckets.length} private) across ${PROVIDERS.length} providers`,
            source: "cloud_bucket_recon",
            observedAt: now,
            tags: [
              "cloud_asset",
              "recon_summary",
              ...publicBuckets.length > 0 ? ["public_buckets_found", "critical_misconfiguration"] : [],
              ...sensitiveFileCount > 0 ? ["sensitive_files_exposed"] : []
            ],
            evidence: {
              totalProbed: probeList.length,
              totalCandidates: priorityCandidates.length,
              totalFound: uniqueFound.length,
              publicCount: publicBuckets.length,
              privateCount: privateBuckets.length,
              redirectCount: redirectBuckets.length,
              sensitiveFileCount,
              byProvider,
              providersChecked: PROVIDERS.map((p) => p.label),
              riskLevel,
              scanAborted: aborted,
              scanDurationMs: Date.now() - start
            },
            attribution: {
              provider: "Cloud Bucket Enumeration v2",
              method: `Probed ${probeList.length} cloud storage endpoints across ${PROVIDERS.length} providers (S3, Azure, GCP, DO Spaces, Alibaba OSS) using ${priorityCandidates.length} naming patterns derived from ${domain}`
            }
          });
        } catch (err) {
          errors.push(`Cloud bucket recon error: ${err.message}`);
        }
        return {
          connector: "cloud_bucket_recon",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/virustotal.ts
import { createHash as createHash20 } from "crypto";
function makeAssetId20(domain, name, source) {
  return createHash20("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function vtFetch(path, apiKey, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3${path}`, {
      headers: { "x-apikey": apiKey },
      signal: controller.signal
    });
    if (res.status === 429) return { error: { code: "QuotaExceeded", message: "Rate limited" } };
    if (!res.ok) throw new Error(`VT returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
var virustotalConnector;
var init_virustotal = __esm({
  "server/lib/passive/virustotal.ts"() {
    "use strict";
    virustotalConnector = {
      name: "virustotal",
      description: "VirusTotal domain intelligence \u2014 passive DNS, subdomains, WHOIS, malware associations",
      requiresApiKey: true,
      freeUrl: "https://www.virustotal.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "virustotal", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const domainReport = await vtFetch(`/domains/${domain}`, apiKey, timeout);
          if (domainReport.error?.code === "QuotaExceeded") {
            rateLimited = true;
            errors.push("Rate limited on domain report");
          } else if (domainReport.data) {
            const attrs = domainReport.data.attributes || {};
            const now = /* @__PURE__ */ new Date();
            if (attrs.whois) {
              observations.push({
                assetId: makeAssetId20(domain, `whois-${domain}`, "virustotal"),
                domain,
                assetType: "subdomain",
                name: domain,
                source: "virustotal",
                observedAt: now,
                tags: ["whois", "registrar"],
                evidence: {
                  registrar: attrs.registrar,
                  creationDate: attrs.creation_date,
                  lastUpdateDate: attrs.last_update_date,
                  whoisRaw: (attrs.whois || "").slice(0, 2e3),
                  reputation: attrs.reputation,
                  categories: attrs.categories
                },
                attribution: {
                  provider: "VirusTotal",
                  url: `https://www.virustotal.com/gui/domain/${domain}`,
                  method: "VirusTotal domain WHOIS lookup"
                }
              });
            }
            if (attrs.last_dns_records) {
              for (const rec of attrs.last_dns_records) {
                if (rec.type === "A" || rec.type === "AAAA") {
                  observations.push({
                    assetId: makeAssetId20(domain, `dns-${rec.value}`, "virustotal"),
                    domain,
                    assetType: "ip",
                    name: domain,
                    ip: rec.value,
                    source: "virustotal",
                    observedAt: now,
                    tags: ["dns", rec.type.toLowerCase()],
                    evidence: { type: rec.type, ttl: rec.ttl, value: rec.value },
                    attribution: {
                      provider: "VirusTotal",
                      url: `https://www.virustotal.com/gui/domain/${domain}/dns`,
                      method: "VirusTotal DNS record lookup"
                    }
                  });
                }
              }
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 1200));
            const subdomains = await vtFetch(`/domains/${domain}/subdomains?limit=40`, apiKey, timeout);
            if (subdomains.error?.code === "QuotaExceeded") {
              rateLimited = true;
              errors.push("Rate limited on subdomains");
            } else if (subdomains.data && Array.isArray(subdomains.data)) {
              const now = /* @__PURE__ */ new Date();
              for (const sub of subdomains.data) {
                const subId = sub.id || sub.attributes?.id;
                if (!subId) continue;
                observations.push({
                  assetId: makeAssetId20(domain, subId, "virustotal"),
                  domain,
                  assetType: "subdomain",
                  name: subId,
                  source: "virustotal",
                  observedAt: now,
                  tags: ["subdomain", "virustotal-enum"],
                  evidence: {
                    reputation: sub.attributes?.reputation,
                    lastAnalysisStats: sub.attributes?.last_analysis_stats
                  },
                  attribution: {
                    provider: "VirusTotal",
                    url: `https://www.virustotal.com/gui/domain/${subId}`,
                    method: "VirusTotal subdomain enumeration"
                  }
                });
              }
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 1200));
            const resolutions = await vtFetch(`/domains/${domain}/resolutions?limit=40`, apiKey, timeout);
            if (resolutions.error?.code === "QuotaExceeded") {
              rateLimited = true;
              errors.push("Rate limited on resolutions");
            } else if (resolutions.data && Array.isArray(resolutions.data)) {
              const now = /* @__PURE__ */ new Date();
              for (const res of resolutions.data) {
                const ip = res.attributes?.ip_address;
                if (!ip) continue;
                observations.push({
                  assetId: makeAssetId20(domain, `pdns-${ip}`, "virustotal"),
                  domain,
                  assetType: "ip",
                  name: domain,
                  ip,
                  source: "virustotal",
                  observedAt: now,
                  firstSeen: res.attributes?.date ? new Date(res.attributes.date * 1e3) : void 0,
                  tags: ["passive-dns", "historical-resolution"],
                  evidence: {
                    hostName: res.attributes?.host_name,
                    resolver: res.attributes?.resolver,
                    date: res.attributes?.date
                  },
                  attribution: {
                    provider: "VirusTotal",
                    url: `https://www.virustotal.com/gui/domain/${domain}/relations`,
                    method: "VirusTotal passive DNS resolution history"
                  }
                });
              }
            }
          }
        } catch (err) {
          errors.push(`VirusTotal error: ${err.message}`);
        }
        return {
          connector: "virustotal",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/hibp.ts
import { createHash as createHash21 } from "crypto";
function makeAssetId21(domain, name, source) {
  return createHash21("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function hibpFetch(path, apiKey, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3${path}`, {
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": "AceStrike-DomainIntel"
      },
      signal: controller.signal
    });
    if (res.status === 404) return null;
    if (res.status === 429) throw new Error("RATE_LIMITED");
    if (!res.ok) throw new Error(`HIBP returned ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
var hibpConnector;
var init_hibp = __esm({
  "server/lib/passive/hibp.ts"() {
    "use strict";
    hibpConnector = {
      name: "hibp",
      description: "Have I Been Pwned \u2014 domain breach exposure, compromised credentials, and paste monitoring",
      requiresApiKey: true,
      freeUrl: "https://haveibeenpwned.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "hibp", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const breaches = await hibpFetch(`/breaches?domain=${encodeURIComponent(domain)}`, apiKey, timeout);
          if (breaches && Array.isArray(breaches)) {
            const now = /* @__PURE__ */ new Date();
            for (const breach of breaches) {
              observations.push({
                assetId: makeAssetId21(domain, `breach-${breach.Name}`, "hibp"),
                domain,
                assetType: "breach",
                name: breach.Name,
                source: "hibp",
                observedAt: now,
                firstSeen: breach.BreachDate ? new Date(breach.BreachDate) : void 0,
                tags: [
                  "breach",
                  ...(breach.DataClasses || []).map((dc) => dc.toLowerCase().replace(/\s+/g, "-")),
                  breach.IsVerified ? "verified" : "unverified",
                  breach.IsSensitive ? "sensitive" : "public"
                ],
                evidence: {
                  title: breach.Title,
                  breachDate: breach.BreachDate,
                  addedDate: breach.AddedDate,
                  modifiedDate: breach.ModifiedDate,
                  pwnCount: breach.PwnCount,
                  description: (breach.Description || "").slice(0, 500),
                  dataClasses: breach.DataClasses,
                  isVerified: breach.IsVerified,
                  isFabricated: breach.IsFabricated,
                  isSensitive: breach.IsSensitive,
                  isRetired: breach.IsRetired,
                  isSpamList: breach.IsSpamList,
                  isMalware: breach.IsMalware,
                  logoPath: breach.LogoPath
                },
                attribution: {
                  provider: "Have I Been Pwned",
                  url: `https://haveibeenpwned.com/PwnedWebsites#${breach.Name}`,
                  method: "HIBP domain breach search",
                  verifyUrl: `https://haveibeenpwned.com/DomainSearch/${domain}`
                }
              });
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 1600));
            try {
              const domainSearch = await hibpFetch(`/breacheddomain/${encodeURIComponent(domain)}`, apiKey, timeout);
              if (domainSearch && typeof domainSearch === "object") {
                const now = /* @__PURE__ */ new Date();
                const aliases = Object.keys(domainSearch);
                for (const alias of aliases.slice(0, 100)) {
                  const email = `${alias}@${domain}`;
                  const breachNames = domainSearch[alias] || [];
                  observations.push({
                    assetId: makeAssetId21(domain, `email-breach-${alias}`, "hibp"),
                    domain,
                    assetType: "breach",
                    name: email,
                    source: "hibp",
                    observedAt: now,
                    tags: ["email-breach", "credential-exposure", ...breachNames.slice(0, 5).map((b) => `breach:${b}`)],
                    evidence: {
                      email,
                      breachCount: breachNames.length,
                      breaches: breachNames
                    },
                    attribution: {
                      provider: "Have I Been Pwned",
                      url: `https://haveibeenpwned.com/account/${email}`,
                      method: "HIBP breached domain email search"
                    }
                  });
                }
              }
            } catch (err) {
              if (err.message === "RATE_LIMITED") {
                rateLimited = true;
                errors.push("Rate limited on domain email search");
              } else {
                errors.push(`Domain email search: ${err.message}`);
              }
            }
          }
        } catch (err) {
          if (err.message === "RATE_LIMITED") {
            rateLimited = true;
            errors.push("HIBP rate limited");
          } else {
            errors.push(`HIBP error: ${err.message}`);
          }
        }
        return {
          connector: "hibp",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/whoisxml.ts
import { createHash as createHash22 } from "crypto";
function makeAssetId22(domain, name, source) {
  return createHash22("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function wxFetch(url, timeout) {
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
var whoisxmlConnector;
var init_whoisxml = __esm({
  "server/lib/passive/whoisxml.ts"() {
    "use strict";
    whoisxmlConnector = {
      name: "whoisxml",
      description: "WhoisXML API \u2014 comprehensive WHOIS records, reverse WHOIS, DNS lookup, subdomain enumeration",
      requiresApiKey: true,
      freeUrl: "https://www.whoisxmlapi.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "whoisxml", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const whois = await wxFetch(
            `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
            timeout
          );
          if (whois?.WhoisRecord) {
            const rec = whois.WhoisRecord;
            const now = /* @__PURE__ */ new Date();
            observations.push({
              assetId: makeAssetId22(domain, `whois-${domain}`, "whoisxml"),
              domain,
              assetType: "subdomain",
              name: domain,
              source: "whoisxml",
              observedAt: now,
              firstSeen: rec.createdDate ? new Date(rec.createdDate) : void 0,
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
                  countryCode: rec.registrant.countryCode
                } : void 0,
                technicalContact: rec.technicalContact ? {
                  organization: rec.technicalContact.organization,
                  country: rec.technicalContact.country
                } : void 0,
                domainAge: rec.estimatedDomainAge,
                contactEmail: rec.contactEmail
              },
              attribution: {
                provider: "WhoisXML API",
                url: `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}`,
                method: "WhoisXML WHOIS record lookup"
              }
            });
          }
          const subdomains = await wxFetch(
            `https://subdomains.whoisxmlapi.com/api/v1?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
            timeout
          );
          if (subdomains?.result?.records) {
            const now = /* @__PURE__ */ new Date();
            for (const rec of subdomains.result.records.slice(0, 200)) {
              const sub = rec.domain || rec.value;
              if (!sub) continue;
              observations.push({
                assetId: makeAssetId22(domain, sub, "whoisxml"),
                domain,
                assetType: "subdomain",
                name: sub,
                source: "whoisxml",
                observedAt: now,
                firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : void 0,
                lastSeen: rec.lastSeen ? new Date(rec.lastSeen) : void 0,
                tags: ["subdomain", "whoisxml-enum"],
                evidence: { firstSeen: rec.firstSeen, lastSeen: rec.lastSeen },
                attribution: {
                  provider: "WhoisXML API",
                  url: `https://subdomains.whoisxmlapi.com/api/v1?domainName=${domain}`,
                  method: "WhoisXML subdomain enumeration"
                }
              });
            }
          }
          const dns = await wxFetch(
            `https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=${apiKey}&domainName=${domain}&type=_all&outputFormat=JSON`,
            timeout
          );
          if (dns?.DNSData?.dnsRecords) {
            const now = /* @__PURE__ */ new Date();
            for (const rec of dns.DNSData.dnsRecords) {
              const recType = rec.dnsType || rec.type;
              const value = rec.address || rec.target || rec.strings?.join("; ") || rec.name;
              if (!value) continue;
              let assetType = "subdomain";
              if (recType === "A" || recType === "AAAA") assetType = "ip";
              else if (recType === "MX") assetType = "mx";
              else if (recType === "NS") assetType = "ns";
              else if (recType === "TXT") assetType = "txt";
              else if (recType === "CNAME") assetType = "cname";
              observations.push({
                assetId: makeAssetId22(domain, `dns-${recType}-${value}`, "whoisxml"),
                domain,
                assetType,
                name: rec.name || domain,
                ip: recType === "A" || recType === "AAAA" ? value : void 0,
                source: "whoisxml",
                observedAt: now,
                tags: ["dns", recType.toLowerCase()],
                evidence: { type: recType, value, ttl: rec.ttl, priority: rec.priority },
                attribution: {
                  provider: "WhoisXML API",
                  url: `https://dns-lookup-api.whoisxmlapi.com`,
                  method: `WhoisXML DNS ${recType} record lookup`
                }
              });
            }
          }
        } catch (err) {
          errors.push(`WhoisXML error: ${err.message}`);
        }
        return {
          connector: "whoisxml",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/leakix.ts
import { createHash as createHash23 } from "crypto";
function makeAssetId23(domain, name, source) {
  return createHash23("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var leakixConnector;
var init_leakix = __esm({
  "server/lib/passive/leakix.ts"() {
    "use strict";
    leakixConnector = {
      name: "leakix",
      description: "LeakIX \u2014 exposed services, data leaks, misconfigured databases, and credential exposure",
      requiresApiKey: true,
      freeUrl: "https://leakix.net",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "leakix", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(`https://leakix.net/search?scope=service&q=hostname:${encodeURIComponent(domain)}`, {
              headers: {
                "api-key": apiKey,
                "Accept": "application/json"
              },
              signal: controller.signal
            });
            clearTimeout(timer);
            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
            } else if (res.ok) {
              const results = await res.json();
              const now = /* @__PURE__ */ new Date();
              if (Array.isArray(results)) {
                for (const svc of results.slice(0, 100)) {
                  const ip = svc.ip || svc.host;
                  const port = svc.port;
                  const protocol = svc.protocol || "tcp";
                  const hostname = svc.hostname || domain;
                  observations.push({
                    assetId: makeAssetId23(domain, `svc-${ip}-${port}`, "leakix"),
                    domain,
                    assetType: "ip",
                    name: hostname,
                    ip,
                    source: "leakix",
                    observedAt: now,
                    firstSeen: svc.time ? new Date(svc.time) : void 0,
                    tags: [
                      "exposed-service",
                      protocol,
                      ...svc.tags || [],
                      svc.leak?.severity ? `severity:${svc.leak.severity}` : "",
                      svc.summary ? "has-banner" : ""
                    ].filter(Boolean),
                    evidence: {
                      port,
                      protocol,
                      transport: svc.transport,
                      summary: (svc.summary || "").slice(0, 500),
                      software: svc.software?.name,
                      softwareVersion: svc.software?.version,
                      ssl: svc.ssl ? {
                        version: svc.ssl.version,
                        cipher: svc.ssl.cipher,
                        subject: svc.ssl.certificate?.cn,
                        issuer: svc.ssl.certificate?.issuer_cn,
                        notAfter: svc.ssl.certificate?.not_after
                      } : void 0,
                      geoip: svc.geoip ? {
                        country: svc.geoip.country_name,
                        city: svc.geoip.city_name,
                        asn: svc.geoip.as_number,
                        org: svc.geoip.as_name
                      } : void 0,
                      leak: svc.leak ? {
                        type: svc.leak.type,
                        severity: svc.leak.severity,
                        dataset: svc.leak.dataset?.name,
                        rows: svc.leak.dataset?.rows,
                        size: svc.leak.dataset?.size
                      } : void 0
                    },
                    attribution: {
                      provider: "LeakIX",
                      url: `https://leakix.net/host/${ip}`,
                      method: "LeakIX exposed service scan"
                    }
                  });
                }
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("LeakIX request timed out");
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 1e3));
            const controller2 = new AbortController();
            const timer2 = setTimeout(() => controller2.abort(), timeout);
            try {
              const res = await fetch(`https://leakix.net/search?scope=leak&q=hostname:${encodeURIComponent(domain)}`, {
                headers: {
                  "api-key": apiKey,
                  "Accept": "application/json"
                },
                signal: controller2.signal
              });
              clearTimeout(timer2);
              if (res.status === 429) {
                rateLimited = true;
              } else if (res.ok) {
                const leaks = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (Array.isArray(leaks)) {
                  for (const leak of leaks.slice(0, 50)) {
                    observations.push({
                      assetId: makeAssetId23(domain, `leak-${leak.ip}-${leak.port}-${leak.time}`, "leakix"),
                      domain,
                      assetType: "ip",
                      name: leak.hostname || domain,
                      ip: leak.ip,
                      source: "leakix",
                      observedAt: now,
                      firstSeen: leak.time ? new Date(leak.time) : void 0,
                      tags: ["data-leak", "exposed-data", ...leak.tags || []],
                      evidence: {
                        port: leak.port,
                        leakType: leak.leak?.type,
                        severity: leak.leak?.severity,
                        datasetName: leak.leak?.dataset?.name,
                        rows: leak.leak?.dataset?.rows,
                        collections: leak.leak?.dataset?.collections,
                        summary: (leak.summary || "").slice(0, 500)
                      },
                      attribution: {
                        provider: "LeakIX",
                        url: `https://leakix.net/host/${leak.ip}`,
                        method: "LeakIX data leak detection"
                      }
                    });
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`LeakIX leak search: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`LeakIX error: ${err.message}`);
        }
        return {
          connector: "leakix",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/fullhunt.ts
import { createHash as createHash24 } from "crypto";
function makeAssetId24(domain, name, source) {
  return createHash24("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var fullhuntConnector;
var init_fullhunt = __esm({
  "server/lib/passive/fullhunt.ts"() {
    "use strict";
    fullhuntConnector = {
      name: "fullhunt",
      description: "FullHunt \u2014 external attack surface discovery, subdomain enumeration, exposed services",
      requiresApiKey: true,
      freeUrl: "https://fullhunt.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "fullhunt", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(`https://fullhunt.io/api/v1/domain/${domain}/details`, {
              headers: { "X-API-KEY": apiKey },
              signal: controller.signal
            });
            clearTimeout(timer);
            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
            } else if (res.ok) {
              const data = await res.json();
              const now = /* @__PURE__ */ new Date();
              if (data.domain) {
                observations.push({
                  assetId: makeAssetId24(domain, `domain-${domain}`, "fullhunt"),
                  domain,
                  assetType: "subdomain",
                  name: domain,
                  source: "fullhunt",
                  observedAt: now,
                  tags: ["domain-overview", "attack-surface"],
                  evidence: {
                    hostCount: data.host_count,
                    dnsCount: data.dns_count,
                    ipCount: data.ip_count,
                    isRegistered: data.is_registered,
                    status: data.status
                  },
                  attribution: {
                    provider: "FullHunt",
                    url: `https://fullhunt.io/search?query=domain:${domain}`,
                    method: "FullHunt domain overview"
                  }
                });
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("FullHunt domain details timed out");
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller2 = new AbortController();
            const timer2 = setTimeout(() => controller2.abort(), timeout);
            try {
              const res = await fetch(`https://fullhunt.io/api/v1/domain/${domain}/subdomains`, {
                headers: { "X-API-KEY": apiKey },
                signal: controller2.signal
              });
              clearTimeout(timer2);
              if (res.status === 429) {
                rateLimited = true;
              } else if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.hosts && Array.isArray(data.hosts)) {
                  for (const host of data.hosts.slice(0, 200)) {
                    const hostname = typeof host === "string" ? host : host.host;
                    if (!hostname) continue;
                    observations.push({
                      assetId: makeAssetId24(domain, hostname, "fullhunt"),
                      domain,
                      assetType: "subdomain",
                      name: hostname,
                      ip: typeof host === "object" ? host.ip : void 0,
                      source: "fullhunt",
                      observedAt: now,
                      tags: [
                        "subdomain",
                        "fullhunt-enum",
                        ...typeof host === "object" && host.is_live ? ["live"] : [],
                        ...typeof host === "object" && host.has_ipv6 ? ["ipv6"] : []
                      ],
                      evidence: typeof host === "object" ? {
                        ip: host.ip,
                        isLive: host.is_live,
                        cdn: host.cdn,
                        cloud: host.cloud?.provider,
                        hasIpv6: host.has_ipv6,
                        tags: host.tags,
                        technologies: host.technologies,
                        ports: host.ports,
                        statusCode: host.status_code
                      } : {},
                      attribution: {
                        provider: "FullHunt",
                        url: `https://fullhunt.io/search?query=host:${hostname}`,
                        method: "FullHunt subdomain enumeration"
                      }
                    });
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`FullHunt subdomains: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`FullHunt error: ${err.message}`);
        }
        return {
          connector: "fullhunt",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/netlas.ts
import { createHash as createHash25 } from "crypto";
function makeAssetId25(domain, name, source) {
  return createHash25("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var netlasConnector;
var init_netlas = __esm({
  "server/lib/passive/netlas.ts"() {
    "use strict";
    netlasConnector = {
      name: "netlas",
      description: "Netlas.io \u2014 internet-wide host scanning, DNS history, certificate search, and WHOIS",
      requiresApiKey: true,
      freeUrl: "https://netlas.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "netlas", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        const headers = { "X-API-Key": apiKey, "Content-Type": "application/json" };
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(
              `https://app.netlas.io/api/responses/?q=domain:${encodeURIComponent(domain)}&indices=&fields=*&source_type=include&start=0&count=50`,
              { headers, signal: controller.signal }
            );
            clearTimeout(timer);
            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
            } else if (res.ok) {
              const data = await res.json();
              const now = /* @__PURE__ */ new Date();
              if (data.items && Array.isArray(data.items)) {
                for (const item of data.items) {
                  const d = item.data || {};
                  const ip = d.ip || d.host;
                  const port = d.port;
                  const hostname = d.domain || d.hostname || domain;
                  if (!ip) continue;
                  observations.push({
                    assetId: makeAssetId25(domain, `host-${ip}-${port}`, "netlas"),
                    domain,
                    assetType: "ip",
                    name: hostname,
                    ip,
                    source: "netlas",
                    observedAt: now,
                    tags: [
                      "host-scan",
                      d.protocol || "unknown",
                      ...d.tag || [],
                      port ? `port:${port}` : ""
                    ].filter(Boolean),
                    evidence: {
                      port,
                      protocol: d.protocol,
                      banner: (d.http?.title || d.banner || "").slice(0, 500),
                      server: d.http?.server,
                      statusCode: d.http?.status_code,
                      contentType: d.http?.content_type,
                      jarm: d.jarm,
                      geo: d.geo ? {
                        country: d.geo.country,
                        city: d.geo.city,
                        asn: d.geo.asn,
                        asnOrg: d.geo.as_org
                      } : void 0,
                      tls: d.certificate ? {
                        subject: d.certificate.subject?.common_name,
                        issuer: d.certificate.issuer?.common_name,
                        notBefore: d.certificate.validity?.start,
                        notAfter: d.certificate.validity?.end,
                        sans: d.certificate.subject_alt_name?.dns_names?.slice(0, 20)
                      } : void 0,
                      technologies: d.tag
                    },
                    attribution: {
                      provider: "Netlas.io",
                      url: `https://app.netlas.io/responses/?q=host:${ip}`,
                      method: "Netlas host scan"
                    }
                  });
                }
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("Netlas host search timed out");
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller2 = new AbortController();
            const timer2 = setTimeout(() => controller2.abort(), timeout);
            try {
              const res = await fetch(
                `https://app.netlas.io/api/dns/?q=domain:${encodeURIComponent(domain)}&fields=*&source_type=include&start=0&count=50`,
                { headers, signal: controller2.signal }
              );
              clearTimeout(timer2);
              if (res.status === 429) {
                rateLimited = true;
              } else if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.items && Array.isArray(data.items)) {
                  for (const item of data.items) {
                    const d = item.data || {};
                    const name = d.domain || d.name;
                    if (!name) continue;
                    const aRecords = d.a || [];
                    for (const ip of aRecords) {
                      observations.push({
                        assetId: makeAssetId25(domain, `dns-a-${name}-${ip}`, "netlas"),
                        domain,
                        assetType: "ip",
                        name,
                        ip,
                        source: "netlas",
                        observedAt: now,
                        lastSeen: d.last_updated ? new Date(d.last_updated) : void 0,
                        tags: ["dns", "a-record", "netlas-dns"],
                        evidence: { type: "A", value: ip, domain: name },
                        attribution: {
                          provider: "Netlas.io",
                          url: `https://app.netlas.io/dns/?q=domain:${name}`,
                          method: "Netlas DNS record lookup"
                        }
                      });
                    }
                    const cnameRecords = d.cname || [];
                    for (const cname of cnameRecords) {
                      observations.push({
                        assetId: makeAssetId25(domain, `dns-cname-${name}-${cname}`, "netlas"),
                        domain,
                        assetType: "cname",
                        name,
                        source: "netlas",
                        observedAt: now,
                        tags: ["dns", "cname", "netlas-dns"],
                        evidence: { type: "CNAME", value: cname, domain: name },
                        attribution: {
                          provider: "Netlas.io",
                          url: `https://app.netlas.io/dns/?q=domain:${name}`,
                          method: "Netlas DNS CNAME lookup"
                        }
                      });
                    }
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`Netlas DNS search: ${err.message}`);
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller3 = new AbortController();
            const timer3 = setTimeout(() => controller3.abort(), timeout);
            try {
              const res = await fetch(
                `https://app.netlas.io/api/certs/?q=domain:${encodeURIComponent(domain)}&fields=*&source_type=include&start=0&count=30`,
                { headers, signal: controller3.signal }
              );
              clearTimeout(timer3);
              if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.items && Array.isArray(data.items)) {
                  for (const item of data.items) {
                    const cert = item.data || {};
                    const cn = cert.subject?.common_name || cert.parsed?.subject?.common_name;
                    if (!cn) continue;
                    observations.push({
                      assetId: makeAssetId25(domain, `cert-${cn}-${cert.serial_number || ""}`, "netlas"),
                      domain,
                      assetType: "certificate",
                      name: cn,
                      source: "netlas",
                      observedAt: now,
                      tags: ["certificate", "tls", "netlas-cert"],
                      evidence: {
                        serialNumber: cert.serial_number,
                        issuer: cert.issuer?.common_name,
                        notBefore: cert.validity?.start,
                        notAfter: cert.validity?.end,
                        sans: cert.subject_alt_name?.dns_names?.slice(0, 20),
                        signatureAlgorithm: cert.signature_algorithm
                      },
                      attribution: {
                        provider: "Netlas.io",
                        url: `https://app.netlas.io/certs/?q=domain:${domain}`,
                        method: "Netlas certificate search"
                      }
                    });
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`Netlas cert search: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`Netlas error: ${err.message}`);
        }
        return {
          connector: "netlas",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/hunter.ts
import { createHash as createHash26 } from "crypto";
function makeAssetId26(domain, name, source) {
  return createHash26("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var hunterConnector;
var init_hunter = __esm({
  "server/lib/passive/hunter.ts"() {
    "use strict";
    hunterConnector = {
      name: "hunter",
      description: "Hunter.io \u2014 email address discovery, email pattern detection, and organization intelligence",
      requiresApiKey: true,
      freeUrl: "https://hunter.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "hunter", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(
              `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${apiKey}&limit=100`,
              { signal: controller.signal }
            );
            clearTimeout(timer);
            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
            } else if (res.ok) {
              const data = await res.json();
              const now = /* @__PURE__ */ new Date();
              if (data.data) {
                const d = data.data;
                observations.push({
                  assetId: makeAssetId26(domain, `org-${domain}`, "hunter"),
                  domain,
                  assetType: "subdomain",
                  name: domain,
                  source: "hunter",
                  observedAt: now,
                  tags: ["organization", "email-pattern", "hunter-domain"],
                  evidence: {
                    organization: d.organization,
                    emailPattern: d.pattern,
                    emailCount: d.emails?.length || 0,
                    totalResults: d.total || 0,
                    disposable: d.disposable,
                    webmail: d.webmail,
                    acceptAll: d.accept_all,
                    description: d.description,
                    industry: d.industry,
                    twitter: d.twitter,
                    facebook: d.facebook,
                    linkedin: d.linkedin,
                    instagram: d.instagram,
                    youtube: d.youtube,
                    technologies: d.technologies,
                    country: d.country,
                    state: d.state,
                    city: d.city,
                    headcount: d.headcount
                  },
                  attribution: {
                    provider: "Hunter.io",
                    url: `https://hunter.io/try/search/${domain}`,
                    method: "Hunter.io domain search"
                  }
                });
                if (d.emails && Array.isArray(d.emails)) {
                  for (const email of d.emails) {
                    observations.push({
                      assetId: makeAssetId26(domain, `email-${email.value}`, "hunter"),
                      domain,
                      assetType: "breach",
                      // reuse breach type for email-related findings
                      name: email.value,
                      source: "hunter",
                      observedAt: now,
                      firstSeen: email.first_seen ? new Date(email.first_seen) : void 0,
                      lastSeen: email.last_seen ? new Date(email.last_seen) : void 0,
                      tags: [
                        "email-address",
                        "discovered-email",
                        email.type || "unknown-type",
                        `confidence:${email.confidence}`,
                        email.department || "",
                        email.seniority || ""
                      ].filter(Boolean),
                      evidence: {
                        email: email.value,
                        type: email.type,
                        confidence: email.confidence,
                        firstName: email.first_name,
                        lastName: email.last_name,
                        position: email.position,
                        department: email.department,
                        seniority: email.seniority,
                        twitter: email.twitter,
                        linkedin: email.linkedin_url,
                        phoneNumber: email.phone_number,
                        sources: (email.sources || []).slice(0, 5).map((s) => ({
                          domain: s.domain,
                          uri: s.uri,
                          extractedOn: s.extracted_on
                        }))
                      },
                      attribution: {
                        provider: "Hunter.io",
                        url: `https://hunter.io/try/search/${domain}`,
                        method: "Hunter.io email discovery"
                      }
                    });
                  }
                }
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("Hunter.io request timed out");
          }
        } catch (err) {
          errors.push(`Hunter.io error: ${err.message}`);
        }
        return {
          connector: "hunter",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/social-media.ts
import { createHash as createHash27 } from "crypto";
function makeAssetId27(domain, name, source) {
  return createHash27("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function extractOrgName(domain) {
  const base = domain.replace(/\.(com|org|net|io|co|dev|app|xyz|info|biz|us|uk|ca|au|de|fr|jp|cn)(\.[a-z]{2})?$/i, "");
  const names = [base];
  if (base.includes("-")) names.push(base.replace(/-/g, ""));
  if (base.includes(".")) names.push(base.replace(/\./g, ""));
  return Array.from(new Set(names));
}
var socialMediaConnector;
var init_social_media = __esm({
  "server/lib/passive/social-media.ts"() {
    "use strict";
    socialMediaConnector = {
      name: "social-media",
      description: "Social media OSINT \u2014 organization presence detection on GitHub, discovers public repos and org metadata",
      requiresApiKey: false,
      freeUrl: "https://github.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = Math.min(config?.timeout ?? 1e4, 1e4);
        let rateLimited = false;
        const externalSignal = config?.signal;
        const orgNames = extractOrgName(domain);
        try {
          for (const orgName of orgNames) {
            if (externalSignal?.aborted) break;
            try {
              const controller = new AbortController();
              if (externalSignal) externalSignal.addEventListener("abort", () => controller.abort(), { once: true });
              const timer = setTimeout(() => controller.abort(), timeout);
              const res = await fetch(`https://api.github.com/orgs/${encodeURIComponent(orgName)}`, {
                headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" },
                signal: controller.signal
              });
              clearTimeout(timer);
              if (res.status === 403 || res.status === 429) {
                rateLimited = true;
              } else if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                observations.push({
                  assetId: makeAssetId27(domain, `github-org-${orgName}`, "social-media"),
                  domain,
                  assetType: "subdomain",
                  name: `github.com/${orgName}`,
                  source: "social-media",
                  observedAt: now,
                  firstSeen: data.created_at ? new Date(data.created_at) : void 0,
                  tags: ["social-media", "github", "organization", "code-exposure"],
                  evidence: {
                    platform: "GitHub",
                    profileType: "organization",
                    login: data.login,
                    name: data.name,
                    description: data.description,
                    blog: data.blog,
                    location: data.location,
                    email: data.email,
                    publicRepos: data.public_repos,
                    publicGists: data.public_gists,
                    followers: data.followers,
                    following: data.following,
                    createdAt: data.created_at,
                    updatedAt: data.updated_at,
                    twitterUsername: data.twitter_username,
                    isVerified: data.is_verified,
                    hasOrganizationProjects: data.has_organization_projects,
                    hasRepositoryProjects: data.has_repository_projects
                  },
                  attribution: {
                    provider: "GitHub API",
                    url: `https://github.com/${orgName}`,
                    method: "GitHub organization profile lookup",
                    verifyUrl: `https://github.com/${orgName}`
                  }
                });
                if (data.public_repos > 0) {
                  await new Promise((r) => setTimeout(r, 500));
                  try {
                    const repoRes = await fetch(
                      `https://api.github.com/orgs/${encodeURIComponent(orgName)}/repos?sort=updated&per_page=10`,
                      {
                        headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" }
                      }
                    );
                    if (repoRes.ok) {
                      const repos = await repoRes.json();
                      for (const repo of repos) {
                        observations.push({
                          assetId: makeAssetId27(domain, `github-repo-${repo.full_name}`, "social-media"),
                          domain,
                          assetType: "url",
                          name: repo.full_name,
                          source: "social-media",
                          observedAt: now,
                          tags: [
                            "github-repo",
                            "code-exposure",
                            repo.language?.toLowerCase() || "unknown-lang",
                            repo.fork ? "fork" : "original",
                            repo.archived ? "archived" : "active"
                          ].filter(Boolean),
                          evidence: {
                            platform: "GitHub",
                            repoName: repo.name,
                            fullName: repo.full_name,
                            description: repo.description,
                            language: repo.language,
                            stars: repo.stargazers_count,
                            forks: repo.forks_count,
                            watchers: repo.watchers_count,
                            openIssues: repo.open_issues_count,
                            isPrivate: repo.private,
                            isFork: repo.fork,
                            isArchived: repo.archived,
                            defaultBranch: repo.default_branch,
                            createdAt: repo.created_at,
                            updatedAt: repo.updated_at,
                            pushedAt: repo.pushed_at,
                            topics: repo.topics,
                            homepage: repo.homepage,
                            hasWiki: repo.has_wiki,
                            hasPages: repo.has_pages,
                            license: repo.license?.spdx_id
                          },
                          attribution: {
                            provider: "GitHub API",
                            url: `https://github.com/${repo.full_name}`,
                            method: "GitHub organization repository enumeration"
                          }
                        });
                      }
                    }
                  } catch {
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`GitHub org check (${orgName}): ${err.message}`);
            }
            if (externalSignal?.aborted) break;
            if (observations.filter((o) => o.tags.includes("github")).length === 0) {
              try {
                const controller = new AbortController();
                if (externalSignal) externalSignal.addEventListener("abort", () => controller.abort(), { once: true });
                const timer = setTimeout(() => controller.abort(), timeout);
                const res = await fetch(`https://api.github.com/users/${encodeURIComponent(orgName)}`, {
                  headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" },
                  signal: controller.signal
                });
                clearTimeout(timer);
                if (res.ok) {
                  const data = await res.json();
                  const now = /* @__PURE__ */ new Date();
                  observations.push({
                    assetId: makeAssetId27(domain, `github-user-${orgName}`, "social-media"),
                    domain,
                    assetType: "subdomain",
                    name: `github.com/${orgName}`,
                    source: "social-media",
                    observedAt: now,
                    tags: ["social-media", "github", "user-profile", "code-exposure"],
                    evidence: {
                      platform: "GitHub",
                      profileType: "user",
                      login: data.login,
                      name: data.name,
                      bio: data.bio,
                      blog: data.blog,
                      company: data.company,
                      location: data.location,
                      email: data.email,
                      publicRepos: data.public_repos,
                      followers: data.followers,
                      twitterUsername: data.twitter_username
                    },
                    attribution: {
                      provider: "GitHub API",
                      url: `https://github.com/${orgName}`,
                      method: "GitHub user profile lookup"
                    }
                  });
                }
              } catch {
              }
            }
          }
        } catch (err) {
          errors.push(`Social media OSINT error: ${err.message}`);
        }
        return {
          connector: "social-media",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/abuseipdb.ts
import { createHash as createHash28 } from "crypto";
function makeAssetId28(domain, name, source) {
  return createHash28("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var abuseipdbConnector;
var init_abuseipdb = __esm({
  "server/lib/passive/abuseipdb.ts"() {
    "use strict";
    abuseipdbConnector = {
      name: "abuseipdb",
      description: "AbuseIPDB \u2014 IP abuse confidence scoring, report history, and threat categorization",
      requiresApiKey: true,
      freeUrl: "https://www.abuseipdb.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "abuseipdb", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
              signal: controller.signal
            });
            clearTimeout(timer);
            const ips = [];
            if (dnsRes.ok) {
              const dnsData = await dnsRes.json();
              if (dnsData.Answer) {
                for (const ans of dnsData.Answer) {
                  if (ans.type === 1 && ans.data) ips.push(ans.data);
                }
              }
            }
            for (const ip of ips.slice(0, 10)) {
              await new Promise((r) => setTimeout(r, 300));
              const controller2 = new AbortController();
              const timer2 = setTimeout(() => controller2.abort(), timeout);
              try {
                const res = await fetch(
                  `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
                  {
                    headers: { "Key": apiKey, "Accept": "application/json" },
                    signal: controller2.signal
                  }
                );
                clearTimeout(timer2);
                if (res.status === 429) {
                  rateLimited = true;
                  errors.push("Rate limited");
                  break;
                } else if (res.ok) {
                  const data = await res.json();
                  const now = /* @__PURE__ */ new Date();
                  if (data.data) {
                    const d = data.data;
                    const severity = d.abuseConfidenceScore > 75 ? "critical" : d.abuseConfidenceScore > 50 ? "high" : d.abuseConfidenceScore > 25 ? "medium" : "low";
                    observations.push({
                      assetId: makeAssetId28(domain, `abuse-${ip}`, "abuseipdb"),
                      domain,
                      assetType: "ip",
                      name: domain,
                      ip,
                      source: "abuseipdb",
                      observedAt: now,
                      lastSeen: d.lastReportedAt ? new Date(d.lastReportedAt) : void 0,
                      tags: [
                        "ip-reputation",
                        "abuse-check",
                        `severity:${severity}`,
                        `confidence:${d.abuseConfidenceScore}`,
                        d.isWhitelisted ? "whitelisted" : "",
                        d.isTor ? "tor-exit" : "",
                        d.totalReports > 0 ? "reported" : "clean",
                        ...(d.reports || []).slice(0, 5).map((r) => {
                          const categories = {
                            1: "dns-compromise",
                            2: "dns-poisoning",
                            3: "fraud-orders",
                            4: "ddos",
                            5: "ftp-brute",
                            6: "ping-of-death",
                            7: "phishing",
                            8: "fraud-voip",
                            9: "open-proxy",
                            10: "web-spam",
                            11: "email-spam",
                            14: "port-scan",
                            15: "hacking",
                            16: "sql-injection",
                            17: "spoofing",
                            18: "brute-force",
                            19: "bad-web-bot",
                            20: "exploited-host",
                            21: "web-app-attack",
                            22: "ssh",
                            23: "iot-targeted"
                          };
                          return (r.categories || []).map((c) => categories[c] || `cat:${c}`);
                        }).flat()
                      ].filter(Boolean),
                      evidence: {
                        abuseConfidenceScore: d.abuseConfidenceScore,
                        countryCode: d.countryCode,
                        countryName: d.countryName,
                        usageType: d.usageType,
                        isp: d.isp,
                        domain: d.domain,
                        hostnames: d.hostnames,
                        totalReports: d.totalReports,
                        numDistinctUsers: d.numDistinctUsers,
                        lastReportedAt: d.lastReportedAt,
                        isWhitelisted: d.isWhitelisted,
                        isTor: d.isTor,
                        isPublic: d.isPublic,
                        recentReports: (d.reports || []).slice(0, 5).map((r) => ({
                          reportedAt: r.reportedAt,
                          comment: (r.comment || "").slice(0, 200),
                          categories: r.categories,
                          reporterId: r.reporterId,
                          reporterCountryCode: r.reporterCountryCode
                        }))
                      },
                      attribution: {
                        provider: "AbuseIPDB",
                        url: `https://www.abuseipdb.com/check/${ip}`,
                        method: "AbuseIPDB IP abuse check",
                        verifyUrl: `https://www.abuseipdb.com/check/${ip}`
                      }
                    });
                  }
                }
              } catch (err) {
                if (err.name !== "AbortError") errors.push(`AbuseIPDB check ${ip}: ${err.message}`);
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("DNS resolution timed out");
          }
        } catch (err) {
          errors.push(`AbuseIPDB error: ${err.message}`);
        }
        return {
          connector: "abuseipdb",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/passivetotal.ts
import { createHash as createHash29 } from "crypto";
function makeAssetId29(domain, name, source) {
  return createHash29("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var passivetotalConnector;
var init_passivetotal = __esm({
  "server/lib/passive/passivetotal.ts"() {
    "use strict";
    passivetotalConnector = {
      name: "passivetotal",
      description: "PassiveTotal \u2014 passive DNS history, SSL certificate history, host attributes, and threat associations",
      requiresApiKey: true,
      freeUrl: "https://community.riskiq.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        let rateLimited = false;
        if (!apiKey) {
          return { connector: "passivetotal", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
        }
        const [email, key] = apiKey.includes(":") ? apiKey.split(":", 2) : ["", apiKey];
        if (!email || !key) {
          return { connector: "passivetotal", domain, observations: [], errors: ["API key must be in format email:apikey"], durationMs: 0, rateLimited: false };
        }
        const authHeader = "Basic " + Buffer.from(`${email}:${key}`).toString("base64");
        const headers = { "Authorization": authHeader, "Content-Type": "application/json" };
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch("https://api.passivetotal.org/v2/dns/passive", {
              method: "POST",
              headers,
              body: JSON.stringify({ query: domain }),
              signal: controller.signal
            });
            clearTimeout(timer);
            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
            } else if (res.ok) {
              const data = await res.json();
              const now = /* @__PURE__ */ new Date();
              if (data.results && Array.isArray(data.results)) {
                for (const rec of data.results.slice(0, 100)) {
                  const resolveValue = rec.resolve;
                  const resolveType = rec.recordType || "A";
                  if (!resolveValue) continue;
                  const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(resolveValue);
                  observations.push({
                    assetId: makeAssetId29(domain, `pdns-${resolveType}-${resolveValue}`, "passivetotal"),
                    domain,
                    assetType: isIP ? "ip" : "subdomain",
                    name: rec.query || domain,
                    ip: isIP ? resolveValue : void 0,
                    source: "passivetotal",
                    observedAt: now,
                    firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : void 0,
                    lastSeen: rec.lastSeen ? new Date(rec.lastSeen) : void 0,
                    tags: [
                      "passive-dns",
                      resolveType.toLowerCase(),
                      "historical-resolution",
                      rec.collected ? "collected" : ""
                    ].filter(Boolean),
                    evidence: {
                      resolveValue,
                      recordType: resolveType,
                      firstSeen: rec.firstSeen,
                      lastSeen: rec.lastSeen,
                      collected: rec.collected,
                      source: rec.source?.join(", ")
                    },
                    attribution: {
                      provider: "PassiveTotal",
                      url: `https://community.riskiq.com/search/${domain}/resolutions`,
                      method: "PassiveTotal passive DNS lookup"
                    }
                  });
                }
              }
            }
          } catch (err) {
            if (err.name !== "AbortError") throw err;
            errors.push("PassiveTotal DNS timed out");
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller2 = new AbortController();
            const timer2 = setTimeout(() => controller2.abort(), timeout);
            try {
              const res = await fetch("https://api.passivetotal.org/v2/whois", {
                method: "POST",
                headers,
                body: JSON.stringify({ query: domain }),
                signal: controller2.signal
              });
              clearTimeout(timer2);
              if (res.status === 429) {
                rateLimited = true;
              } else if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.domain) {
                  observations.push({
                    assetId: makeAssetId29(domain, `whois-${domain}`, "passivetotal"),
                    domain,
                    assetType: "subdomain",
                    name: domain,
                    source: "passivetotal",
                    observedAt: now,
                    firstSeen: data.registered ? new Date(data.registered) : void 0,
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
                      whoisServer: data.whoisServer
                    },
                    attribution: {
                      provider: "PassiveTotal",
                      url: `https://community.riskiq.com/search/${domain}/whois`,
                      method: "PassiveTotal WHOIS lookup"
                    }
                  });
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`PassiveTotal WHOIS: ${err.message}`);
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller3 = new AbortController();
            const timer3 = setTimeout(() => controller3.abort(), timeout);
            try {
              const res = await fetch("https://api.passivetotal.org/v2/ssl-certificate/search", {
                method: "POST",
                headers,
                body: JSON.stringify({ query: domain, field: "subjectCommonName" }),
                signal: controller3.signal
              });
              clearTimeout(timer3);
              if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.results && Array.isArray(data.results)) {
                  for (const cert of data.results.slice(0, 30)) {
                    observations.push({
                      assetId: makeAssetId29(domain, `ssl-${cert.sha1 || cert.serialNumber || ""}`, "passivetotal"),
                      domain,
                      assetType: "certificate",
                      name: cert.subjectCommonName || domain,
                      source: "passivetotal",
                      observedAt: now,
                      firstSeen: cert.notBefore ? new Date(cert.notBefore) : void 0,
                      tags: [
                        "ssl-certificate",
                        "certificate-history",
                        cert.expired ? "expired" : "valid",
                        cert.selfSigned ? "self-signed" : ""
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
                        expired: cert.expired
                      },
                      attribution: {
                        provider: "PassiveTotal",
                        url: `https://community.riskiq.com/search/${domain}/certificates`,
                        method: "PassiveTotal SSL certificate history"
                      }
                    });
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`PassiveTotal SSL: ${err.message}`);
            }
          }
          if (!rateLimited) {
            await new Promise((r) => setTimeout(r, 500));
            const controller4 = new AbortController();
            const timer4 = setTimeout(() => controller4.abort(), timeout);
            try {
              const res = await fetch("https://api.passivetotal.org/v2/host-attributes/components", {
                method: "POST",
                headers,
                body: JSON.stringify({ query: domain }),
                signal: controller4.signal
              });
              clearTimeout(timer4);
              if (res.ok) {
                const data = await res.json();
                const now = /* @__PURE__ */ new Date();
                if (data.results && Array.isArray(data.results)) {
                  for (const comp of data.results.slice(0, 50)) {
                    observations.push({
                      assetId: makeAssetId29(domain, `comp-${comp.category}-${comp.label}`, "passivetotal"),
                      domain,
                      assetType: "url",
                      name: comp.hostname || domain,
                      source: "passivetotal",
                      observedAt: now,
                      firstSeen: comp.firstSeen ? new Date(comp.firstSeen) : void 0,
                      lastSeen: comp.lastSeen ? new Date(comp.lastSeen) : void 0,
                      tags: ["host-component", "technology-detection", comp.category?.toLowerCase() || ""],
                      evidence: {
                        category: comp.category,
                        label: comp.label,
                        hostname: comp.hostname,
                        firstSeen: comp.firstSeen,
                        lastSeen: comp.lastSeen
                      },
                      attribution: {
                        provider: "PassiveTotal",
                        url: `https://community.riskiq.com/search/${domain}/components`,
                        method: "PassiveTotal host component detection"
                      }
                    });
                  }
                }
              }
            } catch (err) {
              if (err.name !== "AbortError") errors.push(`PassiveTotal components: ${err.message}`);
            }
          }
        } catch (err) {
          errors.push(`PassiveTotal error: ${err.message}`);
        }
        return {
          connector: "passivetotal",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/intelx-search.ts
import { createHash as createHash30 } from "crypto";
function makeAssetId30(domain, name, source) {
  return createHash30("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var INTELX_BASE, intelxSearchConnector;
var init_intelx_search = __esm({
  "server/lib/passive/intelx-search.ts"() {
    "use strict";
    INTELX_BASE = "https://2.intelx.io";
    intelxSearchConnector = {
      name: "intelx_search",
      description: "Searches darkweb, paste sites, leaked databases, and stealer logs for domain mentions",
      requiresApiKey: true,
      freeUrl: "https://intelx.io",
      async collect(domain, config) {
        const start = Date.now();
        const now = /* @__PURE__ */ new Date();
        const observations = [];
        const errors = [];
        let rateLimited = false;
        const apiKey = config?.apiKey;
        if (!apiKey) {
          errors.push("No IntelX API key configured");
          return {
            connector: this.name,
            domain,
            observations,
            errors,
            durationMs: Date.now() - start,
            rateLimited
          };
        }
        try {
          const searchResp = await fetch(`${INTELX_BASE}/intelligent/search`, {
            method: "POST",
            headers: {
              "x-key": apiKey,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              term: domain,
              buckets: ["pastes", "leaks", "darknet", "dumpster"],
              lookuplevel: 0,
              maxresults: 100,
              timeout: 10,
              datefrom: "",
              dateto: "",
              sort: 2,
              // sort by date descending
              media: 0
              // all media types
            }),
            signal: config?.signal
          });
          if (searchResp.status === 402) {
            rateLimited = true;
            errors.push("IntelX API rate limit exceeded or payment required");
          } else if (!searchResp.ok) {
            throw new Error(`IntelX search failed with status: ${searchResp.status}`);
          }
          const searchData = await searchResp.json();
          const searchId = searchData.id;
          let results = [];
          for (let attempt = 0; attempt < 5; attempt++) {
            await new Promise((r) => setTimeout(r, 3e3));
            if (config?.signal?.aborted) throw new Error("Operation aborted");
            const resultResp = await fetch(
              `${INTELX_BASE}/intelligent/search/result?id=${searchId}&limit=100&offset=0`,
              { headers: { "x-key": apiKey }, signal: config?.signal }
            );
            if (resultResp.ok) {
              const resultData = await resultResp.json();
              if (resultData.records?.length > 0) {
                results = resultData.records;
              }
              if (resultData.status === 0 || resultData.status === 2) break;
            }
          }
          const stealerLogEntries = [];
          const pasteEntries = [];
          const leakEntries = [];
          const darknetEntries = [];
          for (const record of results) {
            const bucket = record.bucket?.toLowerCase() || "unknown";
            if (bucket === "darknet") darknetEntries.push(record);
            else if (bucket === "leaks") leakEntries.push(record);
            else if (bucket === "pastes") pasteEntries.push(record);
            if (record.name?.match(/stealer|redline|raccoon|vidar|aurora|lumma|stealc|meta_stealer/i)) {
              stealerLogEntries.push(record);
            }
          }
          const attribution = { provider: "Intelligence X", url: `https://intelx.io/results?s=${searchId}`, method: "api" };
          for (const entry of darknetEntries.slice(0, 10)) {
            const name = entry.name || `Darknet mention: ${domain}`;
            observations.push({
              assetId: makeAssetId30(domain, name, this.name),
              domain,
              assetType: "breach",
              name,
              source: this.name,
              observedAt: now,
              firstSeen: entry.date ? new Date(entry.date) : void 0,
              tags: ["darkweb", "darknet_mention", "intelx"],
              evidence: {
                severity: 8,
                confidence: 80,
                description: `Darknet mention found on ${entry.date || "unknown date"} in ${entry.bucket}`,
                date: entry.date,
                media_type: entry.typeh,
                storage_id: entry.storageid,
                system_id: entry.systemid
              },
              attribution
            });
          }
          for (const entry of stealerLogEntries.slice(0, 10)) {
            const name = `Stealer log: ${entry.name || domain}`;
            observations.push({
              assetId: makeAssetId30(domain, name, this.name),
              domain,
              assetType: "breach",
              name,
              source: this.name,
              observedAt: now,
              firstSeen: entry.date ? new Date(entry.date) : void 0,
              tags: ["darkweb", "stealer_log", "credential_leak", "intelx"],
              evidence: {
                severity: 9,
                confidence: 85,
                description: `Stealer log containing ${domain} credentials found`,
                stealer_name: entry.name,
                date: entry.date,
                storage_id: entry.storageid
              },
              attribution
            });
          }
          for (const entry of pasteEntries.slice(0, 5)) {
            const name = `Paste: ${entry.name || domain}`;
            observations.push({
              assetId: makeAssetId30(domain, name, this.name),
              domain,
              assetType: "breach",
              name,
              source: this.name,
              observedAt: now,
              firstSeen: entry.date ? new Date(entry.date) : void 0,
              tags: ["paste_site", "intelx"],
              evidence: {
                severity: 5,
                confidence: 70,
                description: `Domain mentioned in paste site on ${entry.date || "unknown date"}`,
                date: entry.date,
                storage_id: entry.storageid
              },
              attribution
            });
          }
          for (const entry of leakEntries.slice(0, 5)) {
            const name = `Leak DB: ${entry.name || domain}`;
            observations.push({
              assetId: makeAssetId30(domain, name, this.name),
              domain,
              assetType: "breach",
              name,
              source: this.name,
              observedAt: now,
              firstSeen: entry.date ? new Date(entry.date) : void 0,
              tags: ["data_leak", "breach_database", "intelx"],
              evidence: {
                severity: 8,
                confidence: 80,
                description: `Domain found in leaked database: ${entry.name}`,
                leak_name: entry.name,
                date: entry.date,
                storage_id: entry.storageid
              },
              attribution
            });
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during IntelX search");
        }
        return {
          connector: this.name,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/hudson-rock.ts
import { createHash as createHash31 } from "crypto";
function makeAssetId31(domain, name, source) {
  return createHash31("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var HUDSON_ROCK_BASE, hudsonRockConnector;
var init_hudson_rock = __esm({
  "server/lib/passive/hudson-rock.ts"() {
    "use strict";
    HUDSON_ROCK_BASE = "https://cavalier.hudsonrock.com/api/json/v2";
    hudsonRockConnector = {
      name: "hudson_rock",
      description: "Queries stealer log intelligence for compromised employee credentials and third-party exposures",
      requiresApiKey: true,
      freeUrl: "https://cavalier.hudsonrock.com",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const signal = config?.signal;
        if (signal?.aborted) {
          return { connector: "hudson_rock", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        const apiKey = config?.apiKey;
        if (!apiKey) {
          return {
            connector: "hudson_rock",
            domain,
            observations: [],
            errors: ["No Hudson Rock API key configured"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          const fetchTimeout = Math.min(config?.timeout ?? 15e3, 2e4);
          const responses = await Promise.allSettled([
            fetch(`${HUDSON_ROCK_BASE}/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`, {
              headers: { "api-key": apiKey, "Accept": "application/json" },
              signal: signal || AbortSignal.timeout(fetchTimeout)
            }),
            fetch(`${HUDSON_ROCK_BASE}/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}&type=thirdparty`, {
              headers: { "api-key": apiKey, "Accept": "application/json" },
              signal: signal || AbortSignal.timeout(fetchTimeout)
            })
          ]);
          const [employeeResp, thirdPartyResp] = responses;
          let employees = [];
          if (employeeResp.status === "fulfilled" && employeeResp.value.ok) {
            const empData = await employeeResp.value.json();
            employees = Array.isArray(empData) ? empData : empData?.stealers || empData?.data || [];
          } else if (employeeResp.status === "fulfilled") {
            if (employeeResp.value.status === 429) rateLimited = true;
            errors.push(`Hudson Rock employee API returned status ${employeeResp.value.status}`);
          } else {
            errors.push(`Hudson Rock employee API fetch failed: ${employeeResp.reason}`);
          }
          if (signal?.aborted) {
            return { connector: "hudson_rock", domain, observations, errors: ["Aborted mid-execution"], durationMs: Date.now() - start, rateLimited };
          }
          let thirdParty = [];
          if (thirdPartyResp.status === "fulfilled" && thirdPartyResp.value.ok) {
            const tpData = await thirdPartyResp.value.json();
            thirdParty = Array.isArray(tpData) ? tpData : tpData?.stealers || tpData?.data || [];
          } else if (thirdPartyResp.status === "fulfilled") {
            if (thirdPartyResp.value.status === 429) rateLimited = true;
            errors.push(`Hudson Rock third-party API returned status ${thirdPartyResp.value.status}`);
          } else {
            errors.push(`Hudson Rock third-party API fetch failed: ${thirdPartyResp.reason}`);
          }
          const totalCompromised = employees.length + thirdParty.length;
          if (totalCompromised > 0) {
            const stealerTypes = /* @__PURE__ */ new Set();
            [...employees, ...thirdParty].forEach((e) => {
              if (e.stealer_type) stealerTypes.add(e.stealer_type);
            });
            observations.push({
              assetId: makeAssetId31(domain, `stealer-summary`, "hudson_rock"),
              domain,
              assetType: "breach",
              name: `Hudson Rock: ${totalCompromised} stealer log entries for ${domain}`,
              source: "hudson_rock",
              observedAt: now,
              tags: ["darkweb", "stealer_log", "hudson_rock", "breach_summary"],
              evidence: {
                total_compromised: totalCompromised,
                compromised_employees: employees.length,
                third_party_exposures: thirdParty.length,
                stealer_types: Array.from(stealerTypes),
                credentials_with_passwords: [...employees, ...thirdParty].filter((e) => e.password).length,
                severity: totalCompromised > 50 ? 10 : totalCompromised > 20 ? 9 : totalCompromised > 5 ? 7 : 5,
                confidence: 90
              },
              attribution: {
                provider: "Hudson Rock",
                url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
                method: "api"
              }
            });
          }
          for (const emp of employees.slice(0, 15)) {
            observations.push({
              assetId: makeAssetId31(domain, emp.email, "hudson_rock"),
              domain,
              assetType: "breach",
              name: `Compromised employee: ${emp.email}`,
              source: "hudson_rock",
              observedAt: now,
              firstSeen: emp.date_compromised ? new Date(emp.date_compromised) : void 0,
              tags: ["stealer_log", "compromised_employee", "credential_leak", "hudson_rock"],
              evidence: {
                email: emp.email,
                has_password: !!emp.password,
                login_url: emp.login_url,
                computer_name: emp.computer_name,
                operating_system: emp.operating_system,
                stealer_type: emp.stealer_type,
                ip: emp.ip,
                antiviruses: emp.antiviruses,
                severity: emp.password ? 9 : 7,
                confidence: 90
              },
              attribution: {
                provider: "Hudson Rock",
                url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
                method: "api"
              }
            });
          }
          for (const tp of thirdParty.slice(0, 10)) {
            observations.push({
              assetId: makeAssetId31(domain, tp.email, "hudson_rock"),
              domain,
              assetType: "breach",
              name: `Third-party exposure: ${tp.email}`,
              source: "hudson_rock",
              observedAt: now,
              firstSeen: tp.date_compromised ? new Date(tp.date_compromised) : void 0,
              tags: ["stealer_log", "third_party_exposure", "credential_leak", "hudson_rock"],
              evidence: {
                email: tp.email,
                has_password: !!tp.password,
                login_url: tp.url,
                stealer_type: tp.stealer_type,
                severity: tp.password ? 8 : 6,
                confidence: 85
              },
              attribution: {
                provider: "Hudson Rock",
                url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
                method: "api"
              }
            });
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during Hudson Rock query");
        }
        return {
          connector: "hudson_rock",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/leakcheck.ts
import { createHash as createHash32 } from "crypto";
function makeAssetId32(domain, name, source) {
  return createHash32("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var LEAKCHECK_BASE, leakcheckConnector;
var init_leakcheck = __esm({
  "server/lib/passive/leakcheck.ts"() {
    "use strict";
    LEAKCHECK_BASE = "https://leakcheck.io/api/v2";
    leakcheckConnector = {
      name: "leakcheck",
      description: "Searches leaked credential databases for domain-associated accounts and passwords",
      requiresApiKey: true,
      freeUrl: "https://leakcheck.io",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const apiKey = config?.apiKey;
        if (!apiKey) {
          return {
            connector: "leakcheck",
            domain,
            observations: [],
            errors: ["No LeakCheck API key configured"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          const resp = await fetch(
            `${LEAKCHECK_BASE}/query/${encodeURIComponent(domain)}?type=domain&limit=100`,
            {
              headers: {
                "X-API-Key": apiKey,
                "Accept": "application/json"
              },
              signal: config?.signal
            }
          );
          if (resp.status === 429) {
            rateLimited = true;
            errors.push("LeakCheck API rate limit exceeded");
          } else if (!resp.ok) {
            if (resp.status === 404) {
              return {
                connector: "leakcheck",
                domain,
                observations: [],
                errors,
                durationMs: Date.now() - start,
                rateLimited
              };
            }
            throw new Error(`LeakCheck API error: ${resp.status}`);
          }
          const data = await resp.json();
          const results = data.result || [];
          const totalFound = data.found || results.length;
          const breachSources = /* @__PURE__ */ new Map();
          let credentialsWithPasswords = 0;
          let credentialsWithHashes = 0;
          const uniqueEmails = /* @__PURE__ */ new Set();
          for (const entry of results) {
            if (entry.email) uniqueEmails.add(entry.email.toLowerCase());
            if (entry.password) credentialsWithPasswords++;
            if (entry.hash) credentialsWithHashes++;
            for (const src of entry.sources || []) {
              const existing = breachSources.get(src.name);
              if (existing) {
                existing.count++;
              } else {
                breachSources.set(src.name, { count: 1, date: src.date });
              }
            }
          }
          if (totalFound > 0) {
            const name = `LeakCheck: ${totalFound} leaked credentials for ${domain}`;
            observations.push({
              assetId: makeAssetId32(domain, name, "leakcheck"),
              domain,
              assetType: "breach",
              name,
              source: "leakcheck",
              observedAt: now,
              tags: ["darkweb", "credential_leak", "leakcheck", "breach_summary"],
              evidence: {
                value: `Found ${totalFound} leaked accounts across ${breachSources.size} breach sources. ${credentialsWithPasswords} have plaintext passwords.`,
                severity: credentialsWithPasswords > 20 ? 10 : credentialsWithPasswords > 5 ? 8 : totalFound > 10 ? 7 : 5,
                confidence: 90,
                total_leaked: totalFound,
                unique_emails: uniqueEmails.size,
                credentials_with_passwords: credentialsWithPasswords,
                credentials_with_hashes: credentialsWithHashes,
                breach_sources: Object.fromEntries(breachSources)
              },
              attribution: {
                provider: "LeakCheck",
                url: "https://leakcheck.io",
                method: "api"
              }
            });
          }
          for (const [sourceName, info] of breachSources) {
            const name = `Breach: ${sourceName}`;
            observations.push({
              assetId: makeAssetId32(domain, name, "leakcheck"),
              domain,
              assetType: "breach",
              name,
              source: "leakcheck",
              observedAt: now,
              tags: ["breach_source", "credential_leak", "leakcheck"],
              evidence: {
                value: `${info.count} ${domain} accounts found in ${sourceName} breach${info.date ? ` (${info.date})` : ""}`,
                severity: info.count > 10 ? 8 : 6,
                confidence: 85,
                breach_name: sourceName,
                breach_date: info.date,
                affected_count: info.count
              },
              attribution: {
                provider: "LeakCheck",
                url: "https://leakcheck.io",
                method: "api"
              }
            });
          }
          for (const entry of results.slice(0, 20)) {
            const identifier = entry.email || entry.username || "unknown";
            const name = `Leaked credential: ${identifier}`;
            observations.push({
              assetId: makeAssetId32(domain, name, "leakcheck"),
              domain,
              assetType: "breach",
              name,
              source: "leakcheck",
              observedAt: now,
              tags: ["credential_leak", "leaked_account", "leakcheck"],
              evidence: {
                value: `Credential found in ${entry.sources?.map((s) => s.name).join(", ") || "unknown breach"}`,
                severity: entry.password ? 9 : entry.hash ? 7 : 5,
                confidence: 88,
                email: entry.email,
                username: entry.username,
                has_password: !!entry.password,
                has_hash: !!entry.hash,
                sources: entry.sources?.map((s) => s.name),
                last_breach: entry.last_breach,
                exposed_fields: entry.fields
              },
              attribution: {
                provider: "LeakCheck",
                url: "https://leakcheck.io",
                method: "api"
              }
            });
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during LeakCheck query");
        }
        return {
          connector: "leakcheck",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/company-intel.ts
import { createHash as createHash33 } from "crypto";
function makeAssetId33(domain, name, source) {
  return createHash33("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function scrapeCompanyWebsite(domain) {
  try {
    const resp = await fetch(`https://${domain}`, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
      signal: AbortSignal.timeout(5e3)
    });
    if (!resp.ok) return { html: "", text: "" };
    const html = await resp.text();
    const text = html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    return { html, text: text.slice(0, 1e4) };
  } catch {
    return { html: "", text: "" };
  }
}
async function scrapeAboutPage(domain) {
  const aboutPaths = ["/about", "/about-us", "/company", "/about.html"];
  for (const path of aboutPaths) {
    try {
      const resp = await fetch(`https://${domain}${path}`, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
        signal: AbortSignal.timeout(4e3)
      });
      if (resp.ok) {
        const html = await resp.text();
        const text = html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
        return { html, text: text.slice(0, 8e3), found: true };
      }
    } catch {
    }
  }
  return { html: "", text: "", found: false };
}
function extractSocialLinks(html1, html2) {
  const combined = html1 + html2;
  const links = {};
  const patterns = [
    ["linkedin", /https?:\/\/(www\.)?linkedin\.com\/company\/[^\s\"'<>]+/i],
    ["twitter", /https?:\/\/(www\.)?(twitter|x)\.com\/[^\s\"'<>]+/i],
    ["facebook", /https?:\/\/(www\.)?facebook\.com\/[^\s\"'<>]+/i],
    ["github", /https?:\/\/(www\.)?github\.com\/[^\s\"'<>]+/i],
    ["crunchbase", /https?:\/\/(www\.)?crunchbase\.com\/organization\/[^\s\"'<>]+/i]
  ];
  for (const [name, pattern] of patterns) {
    const match = combined.match(pattern);
    if (match) links[name] = match[0];
  }
  return links;
}
function detectPublicCompany(html1, html2) {
  const combined = (html1 + html2).toLowerCase();
  const indicators = [];
  if (combined.includes("investor") || combined.includes("shareholders")) indicators.push("investor_relations");
  if (combined.includes("sec filing") || combined.includes("10-k") || combined.includes("10-q")) indicators.push("sec_filings");
  if (combined.match(/nasdaq|nyse|stock\s*price/)) indicators.push("stock_exchange");
  if (combined.match(/annual\s*report/)) indicators.push("annual_report");
  if (combined.match(/earnings\s*call/)) indicators.push("earnings_call");
  return indicators;
}
function extractMetaTags(html) {
  const meta = {};
  const patterns = [
    ["og_title", /<meta\s+property="og:title"\s+content="([^\"]+)"/i],
    ["og_description", /<meta\s+property="og:description"\s+content="([^\"]+)"/i],
    ["og_site_name", /<meta\s+property="og:site_name"\s+content="([^\"]+)"/i],
    ["description", /<meta\s+name="description"\s+content="([^\"]+)"/i],
    ["keywords", /<meta\s+name="keywords"\s+content="([^\"]+)"/i],
    ["author", /<meta\s+name="author"\s+content="([^\"]+)"/i],
    ["title", /<title>([^<]+)<\/title>/i]
  ];
  for (const [key, pattern] of patterns) {
    const match = html.match(pattern);
    if (match) meta[key] = match[1].trim();
  }
  const jsonLdMatch = html.match(/<script\s+type="application\/ld\+json">([\s\S]*?)<\/script>/i);
  if (jsonLdMatch) {
    try {
      const ld = JSON.parse(jsonLdMatch[1]);
      if (ld["@type"] === "Organization" || ld["@type"] === "Corporation") {
        if (ld.name) meta["ld_name"] = ld.name;
        if (ld.description) meta["ld_description"] = ld.description;
        if (ld.numberOfEmployees?.value) meta["ld_employees"] = String(ld.numberOfEmployees.value);
        if (ld.foundingDate) meta["ld_founded"] = ld.foundingDate;
        if (ld.address?.addressLocality) meta["ld_city"] = ld.address.addressLocality;
        if (ld.address?.addressCountry) meta["ld_country"] = ld.address.addressCountry;
      }
    } catch {
    }
  }
  return meta;
}
async function detectRegulatoryHints(domain, html) {
  const hints = [];
  const lowerHtml = html.toLowerCase();
  if (lowerHtml.match(/hipaa|health\s*insurance\s*portability/)) hints.push("HIPAA");
  if (lowerHtml.match(/gdpr|general\s*data\s*protection/)) hints.push("GDPR");
  if (lowerHtml.match(/ccpa|california\s*consumer\s*privacy/)) hints.push("CCPA");
  if (lowerHtml.match(/pci[\s-]*dss|payment\s*card\s*industry/)) hints.push("PCI-DSS");
  if (lowerHtml.match(/sox|sarbanes[\s-]*oxley/)) hints.push("SOX");
  if (lowerHtml.match(/fedramp/i)) hints.push("FedRAMP");
  if (lowerHtml.match(/cmmc|cybersecurity\s*maturity/)) hints.push("CMMC");
  if (lowerHtml.match(/nerc[\s-]*cip/)) hints.push("NERC-CIP");
  if (lowerHtml.match(/ferpa|family\s*educational/)) hints.push("FERPA");
  if (lowerHtml.match(/glba|gramm[\s-]*leach/)) hints.push("GLBA");
  if (lowerHtml.match(/nist\s*800/)) hints.push("NIST-800-53");
  if (lowerHtml.match(/iso\s*27001/)) hints.push("ISO-27001");
  if (lowerHtml.match(/soc\s*2|soc2/)) hints.push("SOC-2");
  if (lowerHtml.match(/hitrust/)) hints.push("HITRUST");
  if (lowerHtml.match(/itar|international\s*traffic\s*in\s*arms/)) hints.push("ITAR");
  if (lowerHtml.match(/coppa|children.*online.*privacy/)) hints.push("COPPA");
  if (lowerHtml.match(/certified|certification|compliant|compliance/)) {
    try {
      const privacyResp = await fetch(`https://${domain}/privacy`, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
        signal: AbortSignal.timeout(4e3)
      });
      if (privacyResp.ok) {
        const privacyHtml = (await privacyResp.text()).toLowerCase();
        if (privacyHtml.match(/hipaa/) && !hints.includes("HIPAA")) hints.push("HIPAA");
        if (privacyHtml.match(/gdpr/) && !hints.includes("GDPR")) hints.push("GDPR");
        if (privacyHtml.match(/ccpa/) && !hints.includes("CCPA")) hints.push("CCPA");
        if (privacyHtml.match(/pci/) && !hints.includes("PCI-DSS")) hints.push("PCI-DSS");
        if (privacyHtml.match(/coppa/) && !hints.includes("COPPA")) hints.push("COPPA");
        if (privacyHtml.match(/ferpa/) && !hints.includes("FERPA")) hints.push("FERPA");
        if (privacyHtml.match(/glba/) && !hints.includes("GLBA")) hints.push("GLBA");
      }
    } catch {
    }
  }
  return hints;
}
var companyIntelConnector;
var init_company_intel = __esm({
  "server/lib/passive/company-intel.ts"() {
    "use strict";
    companyIntelConnector = {
      name: "company_intel",
      description: "Gathers firmographic data (industry, size, products, tech stack) from target domain for BIA enrichment",
      requiresApiKey: false,
      freeUrl: "https://www.google.com",
      async collect(domain, config) {
        const start = Date.now();
        const GLOBAL_TIMEOUT = 2e4;
        const observations = [];
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const source = "company_intel";
        const isTimedOut = () => Date.now() - start > GLOBAL_TIMEOUT;
        try {
          const websiteData = await scrapeCompanyWebsite(domain);
          const aboutData = isTimedOut() ? { html: "", text: "", found: false } : await scrapeAboutPage(domain);
          const socialLinks = extractSocialLinks(websiteData.html || "", aboutData.html || "");
          const publicIndicators = detectPublicCompany(websiteData.html || "", aboutData.html || "");
          const combinedText = [
            websiteData.text || "",
            aboutData.text || ""
          ].join("\n").slice(0, 8e3);
          if (combinedText.length > 100) {
            const name = `Company website data for ${domain}`;
            observations.push({
              assetId: makeAssetId33(domain, name, source),
              domain,
              assetType: "breach",
              name,
              source,
              observedAt: now,
              tags: ["company_intel", "website_scrape"],
              evidence: {
                source: "website_scrape",
                text_length: combinedText.length,
                has_about_page: aboutData.found,
                social_links: socialLinks,
                public_company_indicators: publicIndicators,
                raw_text: combinedText,
                severity: 0,
                confidence: 70
              },
              attribution: {
                provider: "Company Intel Connector",
                method: "scrape",
                url: `https://${domain}`
              }
            });
          }
          const metaData = extractMetaTags(websiteData.html || "");
          if (Object.keys(metaData).length > 0) {
            const name = `Structured metadata for ${domain}`;
            observations.push({
              assetId: makeAssetId33(domain, name, source),
              domain,
              assetType: "breach",
              name,
              source,
              observedAt: now,
              tags: ["company_intel", "metadata"],
              evidence: {
                source: "meta_tags",
                ...metaData,
                severity: 0,
                confidence: 75
              },
              attribution: {
                provider: "Company Intel Connector",
                method: "scrape",
                url: `https://${domain}`
              }
            });
          }
          const regulatoryHints = await detectRegulatoryHints(domain, websiteData.html || "");
          if (regulatoryHints.length > 0) {
            const name = `Regulatory hints for ${domain}`;
            observations.push({
              assetId: makeAssetId33(domain, name, source),
              domain,
              assetType: "breach",
              name,
              source,
              observedAt: now,
              tags: ["company_intel", "regulatory_hint"],
              evidence: {
                source: "website_analysis",
                hints: regulatoryHints,
                severity: 0,
                confidence: 60
              },
              attribution: {
                provider: "Company Intel Connector",
                method: "scrape",
                url: `https://${domain}`
              }
            });
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during company intel collection");
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/threatminer.ts
import { createHash as createHash34 } from "crypto";
function makeAssetId34(domain, name, source) {
  return createHash34("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function tmFetch(endpoint) {
  const resp = await fetch(`${BASE}${endpoint}`, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
    signal: AbortSignal.timeout(12e3)
  });
  if (resp.status === 429) {
    throw new Error("RATE_LIMITED");
  }
  if (!resp.ok) {
    throw new Error(`ThreatMiner API returned status ${resp.status}`);
  }
  const data = await resp.json();
  if (data.status_code !== "200") {
    return null;
  }
  return data.results;
}
var BASE, PROVIDER, threatminerConnector;
var init_threatminer = __esm({
  "server/lib/passive/threatminer.ts"() {
    "use strict";
    BASE = "https://api.threatminer.org/v2";
    PROVIDER = "ThreatMiner";
    threatminerConnector = {
      name: "threatminer",
      description: "ThreatMiner \u2014 free threat intelligence (passive DNS, subdomains, malware, APT reports)",
      requiresApiKey: false,
      freeUrl: "https://www.threatminer.org",
      async collect(domain, config) {
        const observations = [];
        const errors = [];
        const start = Date.now();
        const now = /* @__PURE__ */ new Date();
        let rateLimited = false;
        const endpoints = [
          { rt: 1, name: "WHOIS" },
          { rt: 2, name: "Passive DNS" },
          { rt: 4, name: "Malware Samples" },
          { rt: 5, name: "Subdomains" },
          { rt: 6, name: "URIs" },
          { rt: 7, name: "APT Reports" }
        ];
        const promises = endpoints.map((ep) => tmFetch(`/domain.php?q=${domain}&rt=${ep.rt}`));
        const results = await Promise.allSettled(promises);
        results.forEach((result, index) => {
          const endpointName = endpoints[index].name;
          if (result.status === "rejected") {
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
              case 1:
                observations.push({
                  assetId: makeAssetId34(domain, `WHOIS for ${domain}`, "threatminer"),
                  domain,
                  assetType: "breach",
                  name: `WHOIS data for ${domain}`,
                  source: "threatminer",
                  observedAt: now,
                  tags: ["threatminer", "whois"],
                  evidence: {
                    severity: 0,
                    confidence: 70,
                    whois: data[0]
                  },
                  attribution: {
                    provider: PROVIDER,
                    url: `https://www.threatminer.org/whois.php?q=${domain}`,
                    method: "api"
                  }
                });
                break;
              case 2:
                observations.push({
                  assetId: makeAssetId34(domain, `Passive DNS for ${domain}`, "threatminer"),
                  domain,
                  assetType: "breach",
                  name: `Passive DNS for ${domain}`,
                  source: "threatminer",
                  observedAt: now,
                  tags: ["threatminer", "passive_dns"],
                  evidence: {
                    severity: 0,
                    confidence: 75,
                    records: data.slice(0, 50),
                    total: data.length
                  },
                  attribution: {
                    provider: PROVIDER,
                    url: `https://www.threatminer.org/passive-dns.php?q=${domain}`,
                    method: "api"
                  }
                });
                break;
              case 4:
                observations.push({
                  assetId: makeAssetId34(domain, `Malware samples for ${domain}`, "threatminer"),
                  domain,
                  assetType: "breach",
                  name: `Malware samples associated with ${domain}`,
                  source: "threatminer",
                  observedAt: now,
                  tags: ["threatminer", "malware", "threat_intel"],
                  evidence: {
                    severity: 7,
                    confidence: 65,
                    samples: data.slice(0, 20),
                    total: data.length
                  },
                  attribution: {
                    provider: PROVIDER,
                    url: `https://www.threatminer.org/malware.php?q=${domain}`,
                    method: "api"
                  }
                });
                break;
              case 5:
                for (const sub of data.slice(0, 30)) {
                  observations.push({
                    assetId: makeAssetId34(domain, sub, "threatminer"),
                    domain,
                    assetType: "subdomain",
                    name: sub,
                    source: "threatminer",
                    observedAt: now,
                    tags: ["threatminer", "subdomain"],
                    evidence: {
                      severity: 0,
                      confidence: 70
                    },
                    attribution: {
                      provider: PROVIDER,
                      url: `https://www.threatminer.org/host.php?q=${domain}`,
                      method: "api"
                    }
                  });
                }
                break;
              case 6:
                observations.push({
                  assetId: makeAssetId34(domain, `URI patterns for ${domain}`, "threatminer"),
                  domain,
                  assetType: "breach",
                  name: `URI patterns for ${domain}`,
                  source: "threatminer",
                  observedAt: now,
                  tags: ["threatminer", "uri_pattern"],
                  evidence: {
                    severity: 3,
                    confidence: 60,
                    uris: data.slice(0, 30),
                    total: data.length
                  },
                  attribution: {
                    provider: PROVIDER,
                    url: `https://www.threatminer.org/uri.php?q=${domain}`,
                    method: "api"
                  }
                });
                break;
              case 7:
                observations.push({
                  assetId: makeAssetId34(domain, `APT reports for ${domain}`, "threatminer"),
                  domain,
                  assetType: "breach",
                  name: `APT reports mentioning ${domain}`,
                  source: "threatminer",
                  observedAt: now,
                  tags: ["threatminer", "apt_report", "threat_intel"],
                  evidence: {
                    severity: 8,
                    confidence: 75,
                    reports: data.slice(0, 10),
                    total: data.length
                  },
                  attribution: {
                    provider: PROVIDER,
                    url: `https://www.threatminer.org/report.php?q=${domain}`,
                    method: "api"
                  }
                });
                break;
            }
          } catch (e) {
            errors.push(`Failed to process ${endpointName}: ${e.message}`);
          }
        });
        return {
          connector: "threatminer",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/ip-api.ts
import { createHash as createHash35 } from "crypto";
function makeAssetId35(domain, name, source) {
  return createHash35("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var ipApiConnector;
var init_ip_api = __esm({
  "server/lib/passive/ip-api.ts"() {
    "use strict";
    ipApiConnector = {
      name: "ip_api",
      description: "ip-api.com \u2014 free IP geolocation, ASN, ISP, and organization data",
      requiresApiKey: false,
      freeUrl: "https://ip-api.com",
      async collect(domain, config) {
        const start = Date.now();
        const now = /* @__PURE__ */ new Date();
        const source = "ip_api";
        const observations = [];
        const errors = [];
        let rateLimited = false;
        try {
          const resp = await fetch(
            `http://ip-api.com/json/${domain}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
            { signal: config?.signal ?? AbortSignal.timeout(8e3) }
          );
          if (resp.status === 429) {
            rateLimited = true;
            errors.push("Rate limit exceeded for ip-api.com");
          } else if (!resp.ok) {
            errors.push(`Failed to fetch data from ip-api.com: ${resp.status} ${resp.statusText}`);
          } else {
            const data = await resp.json();
            if (data.status !== "success") {
              errors.push(`ip-api.com returned an error for ${domain}: ${data.message}`);
            } else {
              observations.push({
                assetId: makeAssetId35(domain, data.query, source),
                domain,
                assetType: "ip",
                name: data.query,
                ip: data.query,
                source,
                observedAt: now,
                tags: ["geolocation", "isp", "asn"],
                evidence: {
                  country: data.country,
                  countryCode: data.countryCode,
                  region: data.regionName,
                  city: data.city,
                  zip: data.zip,
                  lat: data.lat,
                  lon: data.lon,
                  timezone: data.timezone,
                  isp: data.isp,
                  org: data.org,
                  as: data.as,
                  asname: data.asname,
                  reverse: data.reverse
                },
                attribution: {
                  provider: "ip-api.com",
                  url: `https://ip-api.com/#${data.query}`,
                  method: "api"
                }
              });
              if (data.hosting) {
                observations.push({
                  assetId: makeAssetId35(domain, `${data.query}-hosting`, source),
                  domain,
                  assetType: "breach",
                  name: `${data.query} is a hosting provider IP`,
                  ip: data.query,
                  source,
                  observedAt: now,
                  tags: ["hosting_provider", "infrastructure-misuse"],
                  evidence: {
                    confidence: 80,
                    provider: data.org,
                    description: `IP belongs to hosting provider: ${data.org}`
                  },
                  attribution: {
                    provider: "ip-api.com",
                    url: `https://ip-api.com/#${data.query}`,
                    method: "api"
                  }
                });
              }
              if (data.proxy) {
                observations.push({
                  assetId: makeAssetId35(domain, `${data.query}-proxy`, source),
                  domain,
                  assetType: "breach",
                  name: `${data.query} detected as proxy/VPN`,
                  ip: data.query,
                  source,
                  observedAt: now,
                  tags: ["proxy_vpn", "anonymizer"],
                  evidence: {
                    confidence: 70,
                    description: "IP is identified as a proxy or VPN endpoint"
                  },
                  attribution: {
                    provider: "ip-api.com",
                    url: `https://ip-api.com/#${data.query}`,
                    method: "api"
                  }
                });
              }
              if (data.mobile) {
                observations.push({
                  assetId: makeAssetId35(domain, `${data.query}-mobile`, source),
                  domain,
                  assetType: "breach",
                  name: `${data.query} is a mobile network IP`,
                  ip: data.query,
                  source,
                  observedAt: now,
                  tags: ["mobile_network"],
                  evidence: {
                    confidence: 60,
                    provider: data.isp,
                    description: `IP belongs to a mobile network provider: ${data.isp}`
                  },
                  attribution: {
                    provider: "ip-api.com",
                    url: `https://ip-api.com/#${data.query}`,
                    method: "api"
                  }
                });
              }
            }
          }
        } catch (err) {
          if (err.name === "AbortError") {
            errors.push("Request to ip-api.com timed out");
          } else {
            errors.push(`An unexpected error occurred: ${err.message}`);
          }
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/bgpview.ts
import { createHash as createHash36 } from "crypto";
function makeAssetId36(domain, name, source) {
  return createHash36("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function bgpFetch(path) {
  const resp = await fetch(`${BASE2}${path}`, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
    signal: AbortSignal.timeout(1e4)
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.status === "ok" ? data.data : null;
}
async function resolveDomain(domain) {
  try {
    const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
      headers: { "accept": "application/dns-json" }
    });
    if (!resp.ok) return [];
    const data = await resp.json();
    return data.Answer?.map((a) => a.data) || [];
  } catch {
    return [];
  }
}
var BASE2, bgpviewConnector;
var init_bgpview = __esm({
  "server/lib/passive/bgpview.ts"() {
    "use strict";
    BASE2 = "https://api.bgpview.io";
    bgpviewConnector = {
      name: "bgpview",
      description: "BGPView \u2014 free ASN lookup, IP prefix ownership, network peers, upstream providers",
      requiresApiKey: false,
      freeUrl: "https://bgpview.io",
      async collect(domain, config) {
        const start = Date.now();
        const observations = [];
        const errors = [];
        const now = /* @__PURE__ */ new Date();
        const source = "bgpview";
        let rateLimited = false;
        try {
          const ips = await resolveDomain(domain);
          if (ips.length === 0) {
            return { connector: source, domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const prefixResults = await Promise.allSettled(
            ips.slice(0, 3).map((ip) => bgpFetch(`/ip/${ip}`))
          );
          const seenAsns = /* @__PURE__ */ new Set();
          for (let i = 0; i < prefixResults.length; i++) {
            const result = prefixResults[i];
            if (result.status !== "fulfilled" || !result.value) continue;
            const data = result.value;
            const ip = ips[i];
            if (data.prefixes && data.prefixes.length > 0) {
              for (const pfx of data.prefixes) {
                const name = `IP prefix ${pfx.prefix} for ${ip}`;
                observations.push({
                  assetId: makeAssetId36(domain, name, source),
                  domain,
                  assetType: "ip",
                  name,
                  ip,
                  asn: pfx.asn?.asn,
                  source,
                  observedAt: now,
                  tags: ["bgpview", "ip_prefix", "network"],
                  evidence: {
                    severity: 0,
                    confidence: 85,
                    prefix: pfx.prefix,
                    asn_name: pfx.asn?.name,
                    asn_description: pfx.asn?.description,
                    country: pfx.asn?.country_code
                  },
                  attribution: {
                    provider: "BGPView",
                    url: `https://bgpview.io/ip/${ip}`,
                    method: "api"
                  }
                });
                if (pfx.asn?.asn) seenAsns.add(pfx.asn.asn);
              }
            }
          }
          const asnArray = Array.from(seenAsns).slice(0, 3);
          const [asnDetails, asnPeers, asnUpstreams] = await Promise.all([
            Promise.allSettled(asnArray.map((asn) => bgpFetch(`/asn/${asn}`))),
            Promise.allSettled(asnArray.map((asn) => bgpFetch(`/asn/${asn}/peers`))),
            Promise.allSettled(asnArray.map((asn) => bgpFetch(`/asn/${asn}/upstreams`)))
          ]);
          for (let i = 0; i < asnArray.length; i++) {
            const asn = asnArray[i];
            const detail = asnDetails[i];
            if (detail.status === "fulfilled" && detail.value) {
              const d = detail.value;
              const name = `AS${asn} \u2014 ${d.name || "Unknown"}`;
              observations.push({
                assetId: makeAssetId36(domain, name, source),
                domain,
                assetType: "asn",
                name,
                asn,
                source,
                observedAt: now,
                tags: ["bgpview", "asn_detail", "network"],
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
                  date_allocated: d.rir_allocation?.date_allocated
                },
                attribution: {
                  provider: "BGPView",
                  url: `https://bgpview.io/asn/${asn}`,
                  method: "api"
                }
              });
            }
            const peers = asnPeers[i];
            if (peers.status === "fulfilled" && peers.value) {
              const peerList = [...peers.value.ipv4_peers || [], ...peers.value.ipv6_peers || []];
              if (peerList.length > 0) {
                const name = `AS${asn} network peers`;
                observations.push({
                  assetId: makeAssetId36(domain, name, source),
                  domain,
                  assetType: "breach",
                  name,
                  source,
                  observedAt: now,
                  tags: ["bgpview", "network_peers"],
                  evidence: {
                    severity: 0,
                    confidence: 80,
                    asn,
                    peer_count: peerList.length,
                    peers: peerList.slice(0, 20).map((p) => ({ asn: p.asn, name: p.name, description: p.description, country: p.country_code }))
                  },
                  attribution: {
                    provider: "BGPView",
                    url: `https://bgpview.io/asn/${asn}/peers`,
                    method: "api"
                  }
                });
              }
            }
            const ups = asnUpstreams[i];
            if (ups.status === "fulfilled" && ups.value) {
              const upList = [...ups.value.ipv4_upstreams || [], ...ups.value.ipv6_upstreams || []];
              if (upList.length > 0) {
                const name = `AS${asn} upstream providers`;
                observations.push({
                  assetId: makeAssetId36(domain, name, source),
                  domain,
                  assetType: "breach",
                  name,
                  source,
                  observedAt: now,
                  tags: ["bgpview", "upstream_providers"],
                  evidence: {
                    severity: 0,
                    confidence: 80,
                    asn,
                    upstream_count: upList.length,
                    upstreams: upList.slice(0, 10).map((u) => ({ asn: u.asn, name: u.name, description: u.description, country: u.country_code }))
                  },
                  attribution: {
                    provider: "BGPView",
                    url: `https://bgpview.io/asn/${asn}/upstreams`,
                    method: "api"
                  }
                });
              }
            }
          }
          const prefixLists = await Promise.allSettled(
            asnArray.map((asn) => bgpFetch(`/asn/${asn}/prefixes`))
          );
          for (let i = 0; i < asnArray.length; i++) {
            const result = prefixLists[i];
            if (result.status !== "fulfilled" || !result.value) continue;
            const allPrefixes = [...result.value.ipv4_prefixes || [], ...result.value.ipv6_prefixes || []];
            if (allPrefixes.length > 0) {
              const name = `AS${asnArray[i]} IP prefix inventory`;
              observations.push({
                assetId: makeAssetId36(domain, name, source),
                domain,
                assetType: "breach",
                name,
                source,
                observedAt: now,
                tags: ["bgpview", "prefix_inventory", "attack_surface"],
                evidence: {
                  severity: 0,
                  confidence: 85,
                  asn: asnArray[i],
                  total_prefixes: allPrefixes.length,
                  prefixes: allPrefixes.slice(0, 30).map((p) => ({ prefix: p.prefix, name: p.name, description: p.description, country: p.country_code }))
                },
                attribution: {
                  provider: "BGPView",
                  url: `https://bgpview.io/asn/${asnArray[i]}/prefixes`,
                  method: "api"
                }
              });
            }
          }
        } catch (err) {
          errors.push(err.message || "Unknown BGPView error");
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/ransomware-live.ts
import { createHash as createHash37 } from "crypto";
function makeAssetId37(domain, name, source) {
  return createHash37("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function fetchVictimsByDomain(domain, config) {
  const url = `${BASE3}/victims/search/${encodeURIComponent(domain)}`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
    signal: config?.signal || AbortSignal.timeout(config?.timeout || 15e3)
  });
  if (resp.status === 429) {
  }
  if (!resp.ok) {
    throw new Error(`Ransomware.live API returned ${resp.status} for ${url}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data : [];
}
async function fetchRecentVictims(config) {
  const url = `${BASE3}/victims/recent`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
    signal: config?.signal || AbortSignal.timeout(config?.timeout || 15e3)
  });
  if (resp.status === 429) {
  }
  if (!resp.ok) {
    throw new Error(`Ransomware.live API returned ${resp.status} for ${url}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data.slice(0, 200) : [];
}
var BASE3, ransomwareLiveConnector;
var init_ransomware_live = __esm({
  "server/lib/passive/ransomware-live.ts"() {
    "use strict";
    BASE3 = "https://api.ransomware.live/v2";
    ransomwareLiveConnector = {
      name: "ransomware_live",
      description: "Ransomware.live \u2014 free ransomware victim tracking, checks if target was a ransomware victim",
      requiresApiKey: false,
      freeUrl: "https://ransomware.live",
      async collect(domain, config) {
        const start = Date.now();
        const observations = [];
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const source = "ransomware_live";
        try {
          const [victimsResult, recentResult] = await Promise.allSettled([
            fetchVictimsByDomain(domain, config),
            fetchRecentVictims(config)
          ]);
          if (victimsResult.status === "rejected") {
            errors.push(`Failed to fetch victims by domain: ${victimsResult.reason}`);
          }
          if (recentResult.status === "rejected") {
            errors.push(`Failed to fetch recent victims: ${recentResult.reason}`);
          }
          if (victimsResult.status === "fulfilled" && victimsResult.value.length > 0) {
            for (const victim of victimsResult.value) {
              const name = `Ransomware victim: ${victim.victim || domain}`;
              observations.push({
                assetId: makeAssetId37(domain, name, source),
                domain,
                assetType: "breach",
                name,
                source,
                observedAt: now,
                tags: ["ransomware_live", "ransomware_victim", "darkweb", "critical_threat"],
                evidence: {
                  severity: 9,
                  confidence: 85,
                  value: `Listed by ${victim.group_name || "unknown group"} on ${victim.discovered || "unknown date"}`,
                  victim_name: victim.victim,
                  group_name: victim.group_name,
                  discovered: victim.discovered,
                  published: victim.published,
                  country: victim.country,
                  activity: victim.activity,
                  website: victim.website,
                  description: victim.description
                },
                attribution: {
                  provider: "Ransomware.live",
                  url: "https://ransomware.live",
                  method: "api"
                }
              });
            }
          }
          if (recentResult.status === "fulfilled" && recentResult.value.length > 0) {
            const baseDomain = domain.replace(/^www\./, "").split(".")[0].toLowerCase();
            const fuzzyMatches = recentResult.value.filter((v) => {
              const victimLower = (v.victim || "").toLowerCase();
              const websiteLower = (v.website || "").toLowerCase();
              return websiteLower.includes(domain) || victimLower.includes(baseDomain) || websiteLower.includes(baseDomain);
            });
            for (const match of fuzzyMatches) {
              const alreadyFound = observations.some(
                (o) => o.evidence?.victim_name === match.victim && o.evidence?.group_name === match.group_name
              );
              if (alreadyFound) continue;
              const name = `Possible ransomware victim match: ${match.victim}`;
              observations.push({
                assetId: makeAssetId37(domain, name, source),
                domain,
                assetType: "breach",
                name,
                source,
                observedAt: now,
                tags: ["ransomware_live", "ransomware_victim", "fuzzy_match", "darkweb"],
                evidence: {
                  severity: 8,
                  confidence: 60,
                  value: `Fuzzy match \u2014 listed by ${match.group_name || "unknown"} on ${match.discovered || "unknown date"}`,
                  match_type: "fuzzy",
                  victim_name: match.victim,
                  group_name: match.group_name,
                  discovered: match.discovered,
                  country: match.country,
                  website: match.website
                },
                attribution: {
                  provider: "Ransomware.live",
                  url: "https://ransomware.live",
                  method: "api"
                }
              });
            }
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during collection");
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/threatfox.ts
import { createHash as createHash38 } from "crypto";
function makeAssetId38(domain, name, source) {
  return createHash38("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function threatFoxPost(body) {
  const resp = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15e3)
  });
  if (!resp.ok) return null;
  return resp.json();
}
var API_URL, threatfoxConnector;
var init_threatfox = __esm({
  "server/lib/passive/threatfox.ts"() {
    "use strict";
    API_URL = "https://threatfox-api.abuse.ch/api/v1/";
    threatfoxConnector = {
      name: "threatfox",
      description: "ThreatFox (abuse.ch) \u2014 free IOC database, malware C2, phishing, botnet indicators",
      requiresApiKey: false,
      freeUrl: "https://threatfox.abuse.ch",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const results = await threatFoxPost({ query: "search_ioc", search_term: domain });
          if (results?.query_status === "ok" && results.data) {
            for (const ioc of results.data.slice(0, 25)) {
              const name = `ThreatFox IOC: ${ioc.ioc_value || domain}`;
              observations.push({
                assetId: makeAssetId38(domain, name, "threatfox"),
                domain,
                assetType: "breach",
                name,
                source: "threatfox",
                observedAt: now,
                firstSeen: ioc.first_seen_utc ? new Date(ioc.first_seen_utc) : void 0,
                lastSeen: ioc.last_seen_utc ? new Date(ioc.last_seen_utc) : void 0,
                tags: ["threatfox", "ioc", ioc.threat_type || "malware", "abuse_ch"],
                evidence: {
                  severity: ioc.threat_type === "botnet_cc" ? 9 : ioc.threat_type === "payload_delivery" ? 8 : ioc.threat_type === "payload" ? 7 : 6,
                  confidence: ioc.confidence_level || 70,
                  value: `${ioc.threat_type || "unknown"} \u2014 ${ioc.malware || "unknown malware"} (${ioc.malware_alias || ""})`,
                  ioc_id: ioc.id,
                  ioc_value: ioc.ioc_value,
                  ioc_type: ioc.ioc_type,
                  threat_type: ioc.threat_type,
                  threat_type_desc: ioc.threat_type_desc,
                  malware: ioc.malware,
                  malware_alias: ioc.malware_alias,
                  malware_printable: ioc.malware_printable,
                  confidence_level: ioc.confidence_level,
                  reporter: ioc.reporter,
                  reference: ioc.reference
                },
                attribution: {
                  provider: "ThreatFox",
                  url: "https://threatfox.abuse.ch/api/",
                  method: "api"
                }
              });
            }
          }
        } catch (err) {
          errors.push(err.message || "Unknown error during ThreatFox lookup");
        }
        return {
          connector: "threatfox",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/builtwith.ts
import { createHash as createHash39 } from "crypto";
function makeAssetId39(domain, name, source) {
  return createHash39("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function detectFromHeaders(domain) {
  const tech = {};
  try {
    const resp = await fetch(`https://${domain}`, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(1e4),
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" }
    });
    const server = resp.headers.get("server");
    if (server) tech.server = [server];
    const powered = resp.headers.get("x-powered-by");
    if (powered) tech.framework = [powered];
    const cdn = [];
    if (resp.headers.get("cf-ray")) cdn.push("Cloudflare");
    if (resp.headers.get("x-amz-cf-id") || resp.headers.get("x-amz-cf-pop")) cdn.push("AWS CloudFront");
    if (resp.headers.get("x-akamai-transformed")) cdn.push("Akamai");
    if (resp.headers.get("x-fastly-request-id")) cdn.push("Fastly");
    if (resp.headers.get("x-sucuri-id")) cdn.push("Sucuri WAF");
    if (resp.headers.get("x-cdn") === "Incapsula") cdn.push("Imperva/Incapsula");
    if (resp.headers.get("x-vercel-id")) cdn.push("Vercel");
    if (resp.headers.get("x-netlify-request-id")) cdn.push("Netlify");
    if (cdn.length > 0) tech.cdn = cdn;
    const security = [];
    if (resp.headers.get("strict-transport-security")) security.push("HSTS");
    if (resp.headers.get("content-security-policy")) security.push("CSP");
    if (resp.headers.get("x-frame-options")) security.push("X-Frame-Options");
    if (resp.headers.get("x-content-type-options")) security.push("X-Content-Type-Options");
    if (resp.headers.get("x-xss-protection")) security.push("X-XSS-Protection");
    if (resp.headers.get("permissions-policy")) security.push("Permissions-Policy");
    if (security.length > 0) tech.security = security;
  } catch {
  }
  return tech;
}
async function detectFromHtml(domain) {
  const tech = {};
  try {
    const resp = await fetch(`https://${domain}`, {
      redirect: "follow",
      signal: AbortSignal.timeout(12e3),
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }
    });
    if (!resp.ok) return tech;
    const html = await resp.text();
    const lower = html.toLowerCase();
    const cms = [];
    if (lower.includes("wp-content") || lower.includes("wp-includes")) cms.push("WordPress");
    if (lower.includes("drupal") || lower.includes("/sites/default/")) cms.push("Drupal");
    if (lower.includes("joomla") || lower.includes("/media/jui/")) cms.push("Joomla");
    if (lower.includes("shopify") || lower.includes("cdn.shopify.com")) cms.push("Shopify");
    if (lower.includes("squarespace")) cms.push("Squarespace");
    if (lower.includes("wix.com")) cms.push("Wix");
    if (lower.includes("hubspot")) cms.push("HubSpot");
    if (lower.includes("webflow")) cms.push("Webflow");
    if (lower.includes("ghost") && lower.includes("ghost-")) cms.push("Ghost");
    if (cms.length > 0) tech.cms = cms;
    const framework = [];
    if (lower.includes("__next") || lower.includes("_next/")) framework.push("Next.js");
    if (lower.includes("__nuxt") || lower.includes("/_nuxt/")) framework.push("Nuxt.js");
    if (lower.includes("ng-") || lower.includes("angular")) framework.push("Angular");
    if (lower.includes("react") || lower.includes("__react")) framework.push("React");
    if (lower.includes("vue") && lower.includes("data-v-")) framework.push("Vue.js");
    if (lower.includes("laravel")) framework.push("Laravel");
    if (lower.includes("django") || lower.includes("csrfmiddlewaretoken")) framework.push("Django");
    if (lower.includes("rails") || lower.includes("csrf-token")) framework.push("Ruby on Rails");
    if (lower.includes("asp.net") || lower.includes("__viewstate")) framework.push("ASP.NET");
    if (framework.length > 0) tech.framework = framework;
    const analytics = [];
    if (lower.includes("google-analytics") || lower.includes("gtag") || lower.includes("ga.js")) analytics.push("Google Analytics");
    if (lower.includes("googletagmanager")) analytics.push("Google Tag Manager");
    if (lower.includes("hotjar")) analytics.push("Hotjar");
    if (lower.includes("mixpanel")) analytics.push("Mixpanel");
    if (lower.includes("segment.com") || lower.includes("analytics.js")) analytics.push("Segment");
    if (lower.includes("facebook") && lower.includes("pixel")) analytics.push("Facebook Pixel");
    if (lower.includes("clarity.ms")) analytics.push("Microsoft Clarity");
    if (lower.includes("heap") && lower.includes("heap-")) analytics.push("Heap");
    if (analytics.length > 0) tech.analytics = analytics;
    const js = [];
    if (lower.includes("jquery")) js.push("jQuery");
    if (lower.includes("bootstrap")) js.push("Bootstrap");
    if (lower.includes("tailwind")) js.push("Tailwind CSS");
    if (lower.includes("lodash")) js.push("Lodash");
    if (lower.includes("moment.js") || lower.includes("moment.min")) js.push("Moment.js");
    if (lower.includes("recaptcha")) js.push("reCAPTCHA");
    if (lower.includes("stripe.js") || lower.includes("stripe.com/v3")) js.push("Stripe");
    if (js.length > 0) tech.javascript = js;
    const email = [];
    if (lower.includes("mailchimp")) email.push("Mailchimp");
    if (lower.includes("sendgrid")) email.push("SendGrid");
    if (lower.includes("intercom")) email.push("Intercom");
    if (lower.includes("zendesk")) email.push("Zendesk");
    if (lower.includes("drift")) email.push("Drift");
    if (lower.includes("crisp")) email.push("Crisp");
    if (email.length > 0) tech.email = email;
  } catch {
  }
  return tech;
}
var builtwithConnector;
var init_builtwith = __esm({
  "server/lib/passive/builtwith.ts"() {
    "use strict";
    builtwithConnector = {
      name: "builtwith",
      description: "BuiltWith \u2014 tech stack detection (CMS, frameworks, analytics, CDN, hosting)",
      requiresApiKey: false,
      freeUrl: "https://builtwith.com",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const source = "builtwith";
        const [headerResult, metaResult] = await Promise.allSettled([
          detectFromHeaders(domain),
          detectFromHtml(domain)
        ]);
        const techStack = {
          server: [],
          cms: [],
          framework: [],
          analytics: [],
          cdn: [],
          security: [],
          email: [],
          hosting: [],
          javascript: [],
          other: []
        };
        if (headerResult.status === "fulfilled") {
          for (const [cat, items] of Object.entries(headerResult.value)) {
            if (techStack[cat]) techStack[cat].push(...items);
            else techStack[cat] = items;
          }
        }
        if (metaResult.status === "fulfilled") {
          for (const [cat, items] of Object.entries(metaResult.value)) {
            if (techStack[cat]) techStack[cat].push(...items);
            else techStack[cat] = items;
          }
        }
        for (const cat of Object.keys(techStack)) {
          techStack[cat] = [...new Set(techStack[cat])];
        }
        const totalTech = Object.values(techStack).flat().length;
        if (totalTech > 0) {
          const name = `Tech stack for ${domain}`;
          observations.push({
            assetId: makeAssetId39(domain, name, source),
            domain,
            assetType: "breach",
            name,
            source,
            observedAt: now,
            tags: ["builtwith", "tech_stack", "fingerprint"],
            evidence: {
              source: "builtwith_passive",
              techStack,
              totalTechnologies: totalTech,
              value: `${totalTech} technologies detected across ${Object.keys(techStack).filter((k) => techStack[k].length > 0).length} categories`,
              severity: 0,
              confidence: 65
            },
            attribution: {
              provider: "BuiltWith",
              url: "https://builtwith.com",
              method: "passive"
            }
          });
          if (techStack.server.length > 0) {
            const name2 = `Web server: ${techStack.server.join(", ")}`;
            observations.push({
              assetId: makeAssetId39(domain, name2, source),
              domain,
              assetType: "breach",
              name: name2,
              source,
              observedAt: now,
              tags: ["builtwith", "web_server", "fingerprint"],
              evidence: {
                source: "builtwith_passive",
                servers: techStack.server,
                value: `Server technology identified for ${domain}`,
                severity: 1,
                confidence: 75
              },
              attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive"
              }
            });
          }
          if (techStack.cms.length > 0) {
            const name2 = `CMS: ${techStack.cms.join(", ")}`;
            observations.push({
              assetId: makeAssetId39(domain, name2, source),
              domain,
              assetType: "breach",
              name: name2,
              source,
              observedAt: now,
              tags: ["builtwith", "cms", "fingerprint"],
              evidence: {
                source: "builtwith_passive",
                cms: techStack.cms,
                value: `Content management system detected \u2014 check for known CVEs`,
                severity: 2,
                confidence: 70
              },
              attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive"
              }
            });
          }
          if (techStack.security.length > 0) {
            const name2 = `Security tools: ${techStack.security.join(", ")}`;
            observations.push({
              assetId: makeAssetId39(domain, name2, source),
              domain,
              assetType: "breach",
              name: name2,
              source,
              observedAt: now,
              tags: ["builtwith", "security_tools", "defense"],
              evidence: {
                source: "builtwith_passive",
                security: techStack.security,
                value: `Security measures detected on ${domain}`,
                severity: 0,
                confidence: 65
              },
              attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive"
              }
            });
          }
          if (techStack.cdn.length > 0) {
            const name2 = `CDN/WAF: ${techStack.cdn.join(", ")}`;
            observations.push({
              assetId: makeAssetId39(domain, name2, source),
              domain,
              assetType: "breach",
              name: name2,
              source,
              observedAt: now,
              tags: ["builtwith", "cdn", "waf"],
              evidence: {
                source: "builtwith_passive",
                cdn: techStack.cdn,
                value: `CDN or WAF detected \u2014 may affect scanning approach`,
                severity: 0,
                confidence: 70
              },
              attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive"
              }
            });
          }
        }
        return {
          connector: "builtwith",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/circl-pdns.ts
import { createHash as createHash40 } from "crypto";
function makeAssetId40(domain, name, source) {
  return createHash40("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var circlPdnsConnector;
var init_circl_pdns = __esm({
  "server/lib/passive/circl-pdns.ts"() {
    "use strict";
    circlPdnsConnector = {
      name: "circl_pdns",
      description: "CIRCL Passive DNS \u2014 free historical DNS resolution records and infrastructure changes",
      requiresApiKey: false,
      freeUrl: "https://www.circl.lu/services/passive-dns/",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const resp = await fetch(`https://www.circl.lu/pdns/query/${encodeURIComponent(domain)}`, {
            headers: {
              "Accept": "application/json",
              "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"
            },
            signal: AbortSignal.timeout(config?.timeout || 15e3)
          });
          if (resp.status === 429) {
            rateLimited = true;
            errors.push("Rate limited by CIRCL Passive DNS API");
          } else if (resp.ok) {
            const text = await resp.text();
            const records = text.split("\n").filter((line) => line.trim()).map((line) => {
              try {
                return JSON.parse(line);
              } catch {
                return null;
              }
            }).filter(Boolean);
            if (records.length > 0) {
              const uniqueIps = new Set(records.filter((r) => r.rrtype === "A" || r.rrtype === "AAAA").map((r) => r.rdata));
              for (const ip of uniqueIps) {
                observations.push({
                  assetId: makeAssetId40(domain, ip, "circl_pdns"),
                  domain,
                  assetType: "ip",
                  name: ip,
                  source: "circl_pdns",
                  observedAt: now,
                  tags: ["circl_pdns", "passive_dns"],
                  evidence: {},
                  attribution: {
                    provider: "CIRCL",
                    url: "https://www.circl.lu/services/passive-dns/",
                    method: "api"
                  }
                });
              }
              const cnames = records.filter((r) => r.rrtype === "CNAME");
              for (const cname of cnames) {
                observations.push({
                  assetId: makeAssetId40(domain, cname.rdata, "circl_pdns"),
                  domain,
                  assetType: "cname",
                  name: cname.rdata,
                  source: "circl_pdns",
                  observedAt: now,
                  firstSeen: cname.time_first ? new Date(cname.time_first * 1e3) : void 0,
                  lastSeen: cname.time_last ? new Date(cname.time_last * 1e3) : void 0,
                  tags: ["circl_pdns", "passive_dns"],
                  evidence: {
                    count: cname.count
                  },
                  attribution: {
                    provider: "CIRCL",
                    url: "https://www.circl.lu/services/passive-dns/",
                    method: "api"
                  }
                });
              }
              const mxRecords = records.filter((r) => r.rrtype === "MX");
              for (const mx of mxRecords) {
                observations.push({
                  assetId: makeAssetId40(domain, mx.rdata, "circl_pdns"),
                  domain,
                  assetType: "mx",
                  name: mx.rdata,
                  source: "circl_pdns",
                  observedAt: now,
                  firstSeen: mx.time_first ? new Date(mx.time_first * 1e3) : void 0,
                  lastSeen: mx.time_last ? new Date(mx.time_last * 1e3) : void 0,
                  tags: ["circl_pdns", "passive_dns"],
                  evidence: {
                    count: mx.count
                  },
                  attribution: {
                    provider: "CIRCL",
                    url: "https://www.circl.lu/services/passive-dns/",
                    method: "api"
                  }
                });
              }
            }
          } else {
            errors.push(`CIRCL Passive DNS API returned status ${resp.status}`);
          }
        } catch (err) {
          errors.push(err.name === "TimeoutError" ? "CIRCL Passive DNS API request timed out" : err.message);
        }
        return {
          connector: "circl_pdns",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/commoncrawl.ts
import { createHash as createHash41 } from "crypto";
function makeAssetId41(domain, name, source) {
  return createHash41("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var CC_INDEX, commoncrawlConnector;
var init_commoncrawl = __esm({
  "server/lib/passive/commoncrawl.ts"() {
    "use strict";
    CC_INDEX = "https://index.commoncrawl.org/CC-MAIN-2024-51-index";
    commoncrawlConnector = {
      name: "commoncrawl",
      description: "CommonCrawl \u2014 free historical web crawl data, exposed pages, URL patterns",
      requiresApiKey: false,
      freeUrl: "https://commoncrawl.org",
      async collect(domain, config) {
        const start = Date.now();
        const now = /* @__PURE__ */ new Date();
        const observations = [];
        const errors = [];
        let rateLimited = false;
        try {
          const resp = await fetch(
            `${CC_INDEX}?url=*.${domain}&output=json&limit=200`,
            {
              headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
              signal: config?.timeout ? AbortSignal.timeout(config.timeout) : AbortSignal.timeout(2e4)
            }
          );
          if (resp.status === 429) {
            rateLimited = true;
          }
          if (resp.ok) {
            const text = await resp.text();
            const records = text.split("\n").filter((line) => line.trim()).map((line) => {
              try {
                return JSON.parse(line);
              } catch {
                return null;
              }
            }).filter(Boolean);
            if (records.length > 0) {
              const urls = /* @__PURE__ */ new Set();
              const subdomains = /* @__PURE__ */ new Set();
              const statusCodes = /* @__PURE__ */ new Map();
              const mimeTypes = /* @__PURE__ */ new Map();
              const interestingPaths = [];
              for (const r of records) {
                if (r.url) urls.add(r.url);
                try {
                  const u = new URL(r.url.startsWith("http") ? r.url : `https://${r.url}`);
                  if (u.hostname.endsWith(domain)) {
                    subdomains.add(u.hostname);
                  }
                  const path = u.pathname.toLowerCase();
                  if (path.includes("/admin") || path.includes("/api/") || path.includes("/swagger") || path.includes("/graphql") || path.includes("/.env") || path.includes("/config") || path.includes("/backup") || path.includes("/debug") || path.includes("/phpmyadmin") || path.includes("/wp-admin") || path.includes("/.git") || path.includes("/server-status") || path.includes("/actuator") || path.includes("/console")) {
                    interestingPaths.push(r.url);
                  }
                } catch {
                }
                const status = parseInt(r.status) || 0;
                if (status > 0) statusCodes.set(status, (statusCodes.get(status) || 0) + 1);
                if (r.mime) mimeTypes.set(r.mime, (mimeTypes.get(r.mime) || 0) + 1);
              }
              const intelName = `CommonCrawl data for ${domain}`;
              observations.push({
                assetId: makeAssetId41(domain, intelName, "commoncrawl"),
                domain,
                assetType: "breach",
                name: intelName,
                source: "commoncrawl",
                observedAt: now,
                tags: ["commoncrawl", "historical", "web_archive"],
                evidence: {
                  value: `${urls.size} unique URLs, ${subdomains.size} subdomains found in web crawl archive`,
                  severity: 0,
                  confidence: 70,
                  totalUrls: urls.size,
                  totalSubdomains: subdomains.size,
                  subdomains: Array.from(subdomains).slice(0, 50),
                  statusCodes: Object.fromEntries(statusCodes),
                  mimeTypes: Object.fromEntries(mimeTypes),
                  sampleUrls: Array.from(urls).slice(0, 30)
                },
                attribution: {
                  provider: "CommonCrawl",
                  url: "https://commoncrawl.org",
                  method: "api"
                }
              });
              if (subdomains.size > 1) {
                for (const sub of Array.from(subdomains).slice(0, 30)) {
                  if (sub !== domain && sub !== `www.${domain}`) {
                    observations.push({
                      assetId: makeAssetId41(domain, sub, "commoncrawl"),
                      domain,
                      assetType: "subdomain",
                      name: sub,
                      source: "commoncrawl",
                      observedAt: now,
                      tags: ["commoncrawl", "subdomain", "historical"],
                      evidence: {
                        value: `Subdomain discovered via CommonCrawl archive`,
                        severity: 0,
                        confidence: 60
                      },
                      attribution: {
                        provider: "CommonCrawl",
                        url: "https://commoncrawl.org",
                        method: "api"
                      }
                    });
                  }
                }
              }
              if (interestingPaths.length > 0) {
                const pathName = `Potentially sensitive paths found for ${domain}`;
                observations.push({
                  assetId: makeAssetId41(domain, pathName, "commoncrawl"),
                  domain,
                  assetType: "breach",
                  name: pathName,
                  source: "commoncrawl",
                  observedAt: now,
                  tags: ["commoncrawl", "sensitive_path", "exposure"],
                  evidence: {
                    value: `${interestingPaths.length} interesting path(s) in crawl archive (admin panels, APIs, configs)`,
                    severity: 4,
                    confidence: 50,
                    note: "Historical data \u2014 paths may no longer be accessible",
                    paths: [...new Set(interestingPaths)].slice(0, 20)
                  },
                  attribution: {
                    provider: "CommonCrawl",
                    url: "https://commoncrawl.org",
                    method: "api"
                  }
                });
              }
            }
          } else if (!rateLimited) {
            errors.push(`Failed to fetch data from CommonCrawl: ${resp.status} ${resp.statusText}`);
          }
        } catch (err) {
          if (err.name === "AbortError") {
            errors.push("CommonCrawl lookup timed out");
          } else {
            errors.push(`CommonCrawl lookup error: ${err.message}`);
          }
        }
        return {
          connector: "commoncrawl",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/reverse-whois.ts
import { createHash as createHash42 } from "crypto";
function makeAssetId42(domain, name, source) {
  return createHash42("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function discoverViaCrtSh(domain, errors) {
  const domains = [];
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
      signal: AbortSignal.timeout(2e4)
    });
    if (!resp.ok) {
      errors.push(`crt.sh request failed with status ${resp.status}`);
      return domains;
    }
    const certs = await resp.json();
    const seen = /* @__PURE__ */ new Set();
    for (const cert of certs) {
      const names = (cert.name_value || "").split("\n");
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "");
        if (clean && clean.includes(".") && !seen.has(clean)) {
          seen.add(clean);
          domains.push(clean);
        }
      }
      if (cert.common_name) {
        const cn = cert.common_name.trim().toLowerCase().replace(/^\*\./, "");
        if (cn && cn.includes(".") && !seen.has(cn)) {
          seen.add(cn);
          domains.push(cn);
        }
      }
    }
  } catch (e) {
    errors.push(`crt.sh discovery failed: ${e.message}`);
  }
  return domains;
}
async function discoverViaSPF(domain, errors) {
  const domains = [];
  try {
    const txtUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`;
    const txtResp = await fetch(txtUrl, { signal: AbortSignal.timeout(8e3) });
    if (txtResp.ok) {
      const data = await txtResp.json();
      if (data.Answer) {
        for (const answer of data.Answer) {
          const txt = (answer.data || "").replace(/\"/g, "");
          const includeMatches = txt.match(/include:([^\s]+)/g);
          if (includeMatches) {
            for (const match of includeMatches) {
              const d = match.replace("include:", "").trim();
              if (d.includes(".") && !d.startsWith("_")) domains.push(d);
            }
          }
          const redirectMatch = txt.match(/redirect=([^\s]+)/);
          if (redirectMatch) domains.push(redirectMatch[1].trim());
        }
      }
    }
    const mxUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`;
    const mxResp = await fetch(mxUrl, { signal: AbortSignal.timeout(8e3) });
    if (mxResp.ok) {
      const mxData = await mxResp.json();
      if (mxData.Answer) {
        for (const answer of mxData.Answer) {
          const mx = (answer.data || "").replace(/^\d+\s+/, "").replace(/\.$/, "").trim();
          if (mx && mx.includes(".")) {
            const parts = mx.split(".");
            if (parts.length >= 2) {
              const baseMx = parts.slice(-2).join(".");
              if (baseMx !== domain) domains.push(baseMx);
            }
          }
        }
      }
    }
    const nsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`;
    const nsResp = await fetch(nsUrl, { signal: AbortSignal.timeout(8e3) });
    if (nsResp.ok) {
      const nsData = await nsResp.json();
      if (nsData.Answer) {
        for (const answer of nsData.Answer) {
          const ns = (answer.data || "").replace(/\.$/, "").trim();
          if (ns && ns.includes(".")) {
            const parts = ns.split(".");
            if (parts.length >= 2) {
              const baseNs = parts.slice(-2).join(".");
              if (baseNs !== domain) domains.push(baseNs);
            }
          }
        }
      }
    }
  } catch (e) {
    errors.push(`DNS discovery (SPF/MX/NS) failed: ${e.message}`);
  }
  return domains;
}
async function discoverViaSecurityTrails(domain, apiKey, errors) {
  const domains = [];
  try {
    const whoisUrl = `https://api.securitytrails.com/v1/domain/${domain}/whois`;
    const whoisResp = await fetch(whoisUrl, {
      headers: { APIKEY: apiKey, "Content-Type": "application/json" },
      signal: AbortSignal.timeout(1e4)
    });
    if (!whoisResp.ok) {
      errors.push(`SecurityTrails WHOIS fetch failed with status ${whoisResp.status}`);
      return domains;
    }
    const whoisData = await whoisResp.json();
    const registrantOrg = whoisData?.result?.registrant_org;
    const registrantEmail = whoisData?.result?.registrant_email;
    const reverseWhois = async (filter) => {
      try {
        const revResp = await fetch("https://api.securitytrails.com/v1/domains/list", {
          method: "POST",
          headers: { APIKEY: apiKey, "Content-Type": "application/json" },
          body: JSON.stringify({ filter }),
          signal: AbortSignal.timeout(15e3)
        });
        if (revResp.ok) {
          const revData = await revResp.json();
          if (revData.records) {
            for (const r of revData.records) {
              if (r.hostname) domains.push(r.hostname);
            }
          }
        } else {
          errors.push(`SecurityTrails reverse WHOIS failed with status ${revResp.status}`);
        }
      } catch (e) {
        errors.push(`SecurityTrails reverse WHOIS request failed: ${e.message}`);
      }
    };
    if (registrantOrg) await reverseWhois({ whois_organization: registrantOrg });
    if (registrantEmail && !registrantEmail.includes("privacy") && !registrantEmail.includes("proxy")) {
      await reverseWhois({ whois_email: registrantEmail });
    }
    const assocUrl = `https://api.securitytrails.com/v1/domain/${domain}/associated`;
    const assocResp = await fetch(assocUrl, {
      headers: { APIKEY: apiKey },
      signal: AbortSignal.timeout(1e4)
    });
    if (assocResp.ok) {
      const assocData = await assocResp.json();
      if (assocData.records) {
        for (const r of assocData.records) {
          if (r.hostname) domains.push(r.hostname);
        }
      }
    } else {
      errors.push(`SecurityTrails associated domains fetch failed with status ${assocResp.status}`);
    }
  } catch (e) {
    errors.push(`SecurityTrails discovery failed: ${e.message}`);
  }
  return domains;
}
var reverseWhoisConnector;
var init_reverse_whois = __esm({
  "server/lib/passive/reverse-whois.ts"() {
    "use strict";
    reverseWhoisConnector = {
      name: "reverse_whois",
      description: "Reverse WHOIS \u2014 discover all domains owned by the target organization",
      requiresApiKey: false,
      freeUrl: "https://crt.sh",
      async collect(domain, config) {
        const start = Date.now();
        const observations = [];
        const errors = [];
        const rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const source = "reverse_whois";
        const allRelatedDomains = /* @__PURE__ */ new Set();
        const [crtResult, spfResult, stResult] = await Promise.allSettled([
          discoverViaCrtSh(domain, errors),
          discoverViaSPF(domain, errors),
          config?.apiKey ? discoverViaSecurityTrails(domain, config.apiKey, errors) : Promise.resolve([])
        ]);
        if (crtResult.status === "fulfilled") {
          for (const d of crtResult.value) allRelatedDomains.add(d);
        }
        if (spfResult.status === "fulfilled") {
          for (const d of spfResult.value) allRelatedDomains.add(d);
        }
        if (stResult.status === "fulfilled") {
          for (const d of stResult.value) allRelatedDomains.add(d);
        }
        allRelatedDomains.delete(domain);
        allRelatedDomains.delete(`www.${domain}`);
        const subdomains = /* @__PURE__ */ new Set();
        const relatedDomains = /* @__PURE__ */ new Set();
        for (const d of allRelatedDomains) {
          if (d.endsWith(`.${domain}`)) {
            subdomains.add(d);
          } else {
            relatedDomains.add(d);
          }
        }
        if (subdomains.size > 0) {
          const name = `${subdomains.size} subdomains discovered for ${domain}`;
          observations.push({
            assetId: makeAssetId42(domain, name, source),
            domain,
            assetType: "breach",
            name,
            source,
            observedAt: now,
            tags: ["reverse_whois", "subdomain_discovery", "attack_surface"],
            evidence: {
              description: `Certificate transparency and DNS analysis revealed ${subdomains.size} subdomain(s)`,
              source: "reverse_whois_composite",
              subdomains: Array.from(subdomains).sort().slice(0, 100),
              total: subdomains.size,
              severity: 0,
              confidence: 80
            },
            attribution: {
              provider: "Multiple (crt.sh, DNS)",
              method: "Passive Discovery"
            }
          });
          for (const sub of Array.from(subdomains).slice(0, 40)) {
            observations.push({
              assetId: makeAssetId42(domain, sub, source),
              domain,
              assetType: "subdomain",
              name: sub,
              source,
              observedAt: now,
              tags: ["reverse_whois", "subdomain"],
              evidence: {
                description: "Subdomain discovered via certificate/DNS analysis",
                source: "reverse_whois_composite",
                severity: 0,
                confidence: 75
              },
              attribution: {
                provider: "Multiple (crt.sh, DNS)",
                method: "Passive Discovery"
              }
            });
          }
        }
        if (relatedDomains.size > 0) {
          const name = `${relatedDomains.size} related domain(s) owned by same org`;
          observations.push({
            assetId: makeAssetId42(domain, name, source),
            domain,
            assetType: "breach",
            name,
            source,
            observedAt: now,
            tags: ["reverse_whois", "related_domains", "org_portfolio", "attack_surface"],
            evidence: {
              description: `Reverse WHOIS/cert analysis found ${relatedDomains.size} domain(s) likely owned by the same organization`,
              source: "reverse_whois_composite",
              relatedDomains: Array.from(relatedDomains).sort().slice(0, 50),
              total: relatedDomains.size,
              severity: 1,
              confidence: 60
            },
            attribution: {
              provider: "Multiple (SecurityTrails, crt.sh, DNS)",
              method: "Passive Discovery"
            }
          });
          for (const rd of Array.from(relatedDomains).slice(0, 20)) {
            observations.push({
              assetId: makeAssetId42(domain, rd, source),
              domain,
              assetType: "subdomain",
              // Using subdomain as it represents a discoverable host
              name: rd,
              source,
              observedAt: now,
              tags: ["reverse_whois", "related_domain", "org_portfolio"],
              evidence: {
                description: "Related domain \u2014 likely owned by same organization",
                source: "reverse_whois_composite",
                severity: 1,
                confidence: 55
              },
              attribution: {
                provider: "Multiple (SecurityTrails, crt.sh, DNS)",
                method: "Passive Discovery"
              }
            });
          }
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/typosquat.ts
import { createHash as createHash43 } from "crypto";
function makeAssetId43(domain, name, source) {
  return createHash43("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function generateTyposquats(domain) {
  const parts = domain.split(".");
  if (parts.length < 2) return [];
  const name = parts.slice(0, -1).join(".");
  const tld = parts[parts.length - 1];
  const candidates = /* @__PURE__ */ new Set();
  for (let i = 0; i < name.length; i++) {
    if (name[i] === ".") continue;
    const variant = name.slice(0, i) + name.slice(i + 1);
    if (variant.length > 0) candidates.add(`${variant}.${tld}`);
  }
  for (let i = 0; i < name.length - 1; i++) {
    if (name[i] === "." || name[i + 1] === ".") continue;
    const arr = name.split("");
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    candidates.add(`${arr.join("")}.${tld}`);
  }
  for (let i = 0; i < name.length; i++) {
    if (name[i] === "." || name[i] === "-") continue;
    const variant = name.slice(0, i) + name[i] + name.slice(i);
    candidates.add(`${variant}.${tld}`);
  }
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    const neighbors = QWERTY_NEIGHBORS[ch];
    if (!neighbors) continue;
    for (const n of neighbors.slice(0, 2)) {
      const variant = name.slice(0, i) + n + name.slice(i + 1);
      candidates.add(`${variant}.${tld}`);
    }
  }
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    const glyphs = HOMOGLYPHS[ch];
    if (!glyphs) continue;
    for (const g of glyphs.slice(0, 2)) {
      const variant = name.slice(0, i) + g + name.slice(i + 1);
      candidates.add(`${variant}.${tld}`);
    }
  }
  for (const altTld of COMMON_TLDS) {
    if (altTld !== tld) {
      candidates.add(`${name}.${altTld}`);
    }
  }
  for (let i = 1; i < name.length; i++) {
    if (name[i] === "." || name[i] === "-" || name[i - 1] === "-") continue;
    const variant = name.slice(0, i) + "-" + name.slice(i);
    candidates.add(`${variant}.${tld}`);
  }
  const prefixes = ["www", "login", "secure", "mail", "portal", "account", "auth"];
  for (const prefix of prefixes) {
    candidates.add(`${prefix}-${name}.${tld}`);
    candidates.add(`${prefix}${name}.${tld}`);
  }
  const vowels = ["a", "e", "i", "o", "u"];
  for (let i = 0; i <= name.length && candidates.size < 500; i++) {
    if (i > 0 && (name[i - 1] === "." || name[i - 1] === "-")) continue;
    for (const v of vowels) {
      const variant = name.slice(0, i) + v + name.slice(i);
      candidates.add(`${variant}.${tld}`);
      if (candidates.size >= 500) break;
    }
  }
  candidates.delete(domain);
  candidates.delete(`.${tld}`);
  return Array.from(candidates).slice(0, 300);
}
async function checkDomainRegistered(domain) {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
      signal: AbortSignal.timeout(3e3)
    });
    if (!resp.ok) return { registered: false };
    const data = await resp.json();
    if (data.Answer && data.Answer.length > 0) {
      return { registered: true, ip: data.Answer[0].data };
    }
    return { registered: false };
  } catch {
    return { registered: false };
  }
}
async function batchCheckDomains(domains, concurrency = 20) {
  const results = /* @__PURE__ */ new Map();
  const queue = [...domains];
  async function worker() {
    while (queue.length > 0) {
      const domain = queue.shift();
      const result = await checkDomainRegistered(domain);
      results.set(domain, result);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, () => worker());
  await Promise.allSettled(workers);
  return results;
}
var HOMOGLYPHS, COMMON_TLDS, QWERTY_NEIGHBORS, typosquatConnector;
var init_typosquat = __esm({
  "server/lib/passive/typosquat.ts"() {
    "use strict";
    HOMOGLYPHS = {
      a: ["\xE0", "\xE1", "\xE2", "\xE3", "\xE4", "\xE5", "\u0251", "\u0430"],
      // last is Cyrillic а
      c: ["\xE7", "\u0107", "\u0441"],
      // last is Cyrillic с
      d: ["\u0257", "\u0111"],
      e: ["\xE8", "\xE9", "\xEA", "\xEB", "\u0113", "\u0435"],
      // last is Cyrillic е
      g: ["\u011F", "\u0121"],
      h: ["\u04BB"],
      // Cyrillic
      i: ["\xEC", "\xED", "\xEE", "\xEF", "\u0131", "\u0456"],
      // last is Cyrillic і
      k: ["\u03BA", "\u043A"],
      // Greek kappa, Cyrillic к
      l: ["\u013A", "\u013C", "\u2113", "1"],
      m: ["\u043C"],
      n: ["\xF1", "\u0144", "\u014B"],
      o: ["\xF2", "\xF3", "\xF4", "\xF5", "\xF6", "\xF8", "\u043E", "0"],
      // Cyrillic о, zero
      p: ["\u0440"],
      // Cyrillic р
      r: ["\u0155", "\u0159"],
      s: ["\u015B", "\u015F", "\u0219", "\u0455"],
      // last is Cyrillic ѕ
      t: ["\u0163", "\u021B"],
      u: ["\xF9", "\xFA", "\xFB", "\xFC", "\u016B"],
      w: ["\u1E83", "\u1E81", "\u0175"],
      x: ["\u0445"],
      // Cyrillic х
      y: ["\xFD", "\xFF", "\u0443"],
      // last is Cyrillic у
      z: ["\u017A", "\u017C", "\u017E"]
    };
    COMMON_TLDS = ["com", "net", "org", "io", "co", "info", "biz", "us", "xyz", "app", "dev", "tech", "online", "site", "cloud"];
    QWERTY_NEIGHBORS = {
      q: ["w", "a"],
      w: ["q", "e", "s", "a"],
      e: ["w", "r", "d", "s"],
      r: ["e", "t", "f", "d"],
      t: ["r", "y", "g", "f"],
      y: ["t", "u", "h", "g"],
      u: ["y", "i", "j", "h"],
      i: ["u", "o", "k", "j"],
      o: ["i", "p", "l", "k"],
      p: ["o", "l"],
      a: ["q", "w", "s", "z"],
      s: ["a", "w", "e", "d", "z", "x"],
      d: ["s", "e", "r", "f", "x", "c"],
      f: ["d", "r", "t", "g", "c", "v"],
      g: ["f", "t", "y", "h", "v", "b"],
      h: ["g", "y", "u", "j", "b", "n"],
      j: ["h", "u", "i", "k", "n", "m"],
      k: ["j", "i", "o", "l", "m"],
      l: ["k", "o", "p"],
      z: ["a", "s", "x"],
      x: ["z", "s", "d", "c"],
      c: ["x", "d", "f", "v"],
      v: ["c", "f", "g", "b"],
      b: ["v", "g", "h", "n"],
      n: ["b", "h", "j", "m"],
      m: ["n", "j", "k"]
    };
    typosquatConnector = {
      name: "typosquat",
      description: "Typosquat Domain Generator \u2014 identifies registered lookalike domains for phishing assessment",
      requiresApiKey: false,
      freeUrl: "https://dns.google",
      async collect(domain, config) {
        const observations = [];
        const errors = [];
        const start = Date.now();
        const now = /* @__PURE__ */ new Date();
        let rateLimited = false;
        try {
          const candidates = generateTyposquats(domain);
          const dnsResults = await batchCheckDomains(candidates, 15);
          const registeredDomains = [];
          for (const [candidate, result] of dnsResults) {
            if (!result.registered) continue;
            let technique = "unknown";
            const namePart = candidate.split(".").slice(0, -1).join(".");
            const origName = domain.split(".").slice(0, -1).join(".");
            const origTld = domain.split(".").pop();
            const candTld = candidate.split(".").pop();
            if (candTld !== origTld) technique = "wrong-tld";
            else if (namePart.includes("-") && !origName.includes("-")) technique = "hyphenation";
            else if (namePart.length < origName.length) technique = "char-omission";
            else if (namePart.length > origName.length) technique = "char-insertion";
            else technique = "char-substitution";
            registeredDomains.push({ domain: candidate, ip: result.ip, technique });
            observations.push({
              assetId: makeAssetId43(domain, `typosquat:${candidate}`, "typosquat"),
              domain,
              assetType: "subdomain",
              name: `Typosquat: ${candidate}`,
              source: "typosquat",
              observedAt: now,
              tags: ["typosquat", "phishing", technique],
              evidence: {
                typosquatDomain: candidate,
                resolvedIp: result.ip,
                technique,
                originalDomain: domain,
                severity: 7,
                confidence: 90,
                description: `Registered lookalike domain: ${candidate} (${technique}) resolves to ${result.ip}`
              },
              attribution: {
                provider: "Typosquat Generator",
                url: "https://dns.google",
                method: `DNS resolution check via Google DNS \u2014 ${technique} variant`
              }
            });
          }
          if (registeredDomains.length > 0) {
            const byTechnique = {};
            for (const d of registeredDomains) {
              byTechnique[d.technique] = (byTechnique[d.technique] || 0) + 1;
            }
            observations.push({
              assetId: makeAssetId43(domain, "typosquat-summary", "typosquat"),
              domain,
              assetType: "breach",
              name: `Typosquat Summary: ${registeredDomains.length} lookalike domains found`,
              source: "typosquat",
              observedAt: now,
              tags: ["typosquat", "phishing", "summary"],
              evidence: {
                totalCandidatesGenerated: candidates.length,
                registeredCount: registeredDomains.length,
                byTechnique,
                registeredDomains: registeredDomains.slice(0, 50),
                severity: registeredDomains.length > 10 ? 8 : registeredDomains.length > 3 ? 6 : 4,
                confidence: 95,
                description: `Found ${registeredDomains.length} registered typosquat domains out of ${candidates.length} candidates`
              },
              attribution: {
                provider: "Typosquat Generator",
                url: "https://dns.google",
                method: `Generated ${candidates.length} candidates, ${registeredDomains.length} registered`
              }
            });
          }
        } catch (err) {
          errors.push(`Typosquat generator error: ${err.message}`);
        }
        return {
          connector: "typosquat",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/alienvault-otx.ts
import { createHash as createHash44 } from "crypto";
function makeAssetId44(domain, name, source) {
  return createHash44("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function otxFetch(path, apiKey, signal) {
  const headers = {
    Accept: "application/json"
  };
  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }
  const resp = await fetch(`${BASE_URL}${path}`, {
    headers,
    signal: signal || AbortSignal.timeout(2e4)
  });
  if (resp.status === 429) return { _rateLimited: true };
  if (!resp.ok) return null;
  return resp.json();
}
var BASE_URL, alienvaultOtxConnector;
var init_alienvault_otx = __esm({
  "server/lib/passive/alienvault-otx.ts"() {
    "use strict";
    BASE_URL = "https://otx.alienvault.com/api/v1";
    alienvaultOtxConnector = {
      name: "alienvault-otx",
      description: "AlienVault OTX \u2014 free threat intelligence exchange, pulse associations, passive DNS, malware hashes",
      requiresApiKey: false,
      freeUrl: "https://otx.alienvault.com",
      async collect(domain, config) {
        const observations = [];
        const errors = [];
        const start = Date.now();
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const apiKey = config?.apiKey;
        const sig = config?.signal;
        try {
          const general = await otxFetch(
            `/indicator/domain/${domain}/general`,
            apiKey,
            sig
          );
          if (general?._rateLimited) {
            rateLimited = true;
          } else if (general) {
            const pulses = general.pulse_info?.pulses || [];
            for (const pulse of pulses.slice(0, 15)) {
              const name = `OTX Pulse: ${pulse.name || "Unknown"}`;
              observations.push({
                assetId: makeAssetId44(domain, `pulse-${pulse.id}`, "alienvault-otx"),
                domain,
                assetType: "breach",
                name,
                source: "alienvault-otx",
                observedAt: now,
                firstSeen: pulse.created ? new Date(pulse.created) : void 0,
                lastSeen: pulse.modified ? new Date(pulse.modified) : void 0,
                tags: [
                  "alienvault-otx",
                  "threat-intel",
                  "pulse",
                  ...(pulse.tags || []).slice(0, 5),
                  ...pulse.adversary ? [`adversary:${pulse.adversary}`] : []
                ],
                evidence: {
                  severity: pulse.adversary ? 8 : pulse.TLP === "red" ? 9 : pulse.TLP === "amber" ? 7 : 5,
                  confidence: 75,
                  value: `Threat report "${pulse.name}" ${pulse.adversary ? `(adversary: ${pulse.adversary})` : ""} \u2014 ${pulse.description?.substring(0, 200) || "No description"}`,
                  pulseId: pulse.id,
                  pulseName: pulse.name,
                  adversary: pulse.adversary || null,
                  tlp: pulse.TLP || "white",
                  tags: pulse.tags || [],
                  indicatorCount: pulse.indicator_count || 0,
                  references: (pulse.references || []).slice(0, 5),
                  attackIds: (pulse.attack_ids || []).slice(0, 10),
                  malwareFamilies: (pulse.malware_families || []).slice(0, 5)
                },
                attribution: {
                  provider: "AlienVault OTX",
                  url: `https://otx.alienvault.com/pulse/${pulse.id}`,
                  method: "OTX DirectConnect API \u2014 domain general indicator lookup",
                  verifyUrl: `https://otx.alienvault.com/indicator/domain/${domain}`
                }
              });
            }
            if (general.validation?.length > 0) {
              for (const v of general.validation.slice(0, 5)) {
                const name = `OTX Validation: ${v.source || "unknown"} \u2014 ${v.message || ""}`;
                observations.push({
                  assetId: makeAssetId44(
                    domain,
                    `validation-${v.source}`,
                    "alienvault-otx"
                  ),
                  domain,
                  assetType: "subdomain",
                  name,
                  source: "alienvault-otx",
                  observedAt: now,
                  tags: ["alienvault-otx", "validation", v.source || "unknown"],
                  evidence: {
                    severity: 4,
                    confidence: 60,
                    value: v.message || "Validation entry",
                    validationSource: v.source,
                    validationName: v.name
                  },
                  attribution: {
                    provider: "AlienVault OTX",
                    url: `https://otx.alienvault.com/indicator/domain/${domain}`,
                    method: "OTX validation data"
                  }
                });
              }
            }
          }
        } catch (err) {
          errors.push(`OTX general: ${err.message}`);
        }
        try {
          const pdns = await otxFetch(
            `/indicator/domain/${domain}/passive_dns`,
            apiKey,
            sig
          );
          if (pdns?._rateLimited) {
            rateLimited = true;
          } else if (pdns?.passive_dns) {
            for (const record of pdns.passive_dns.slice(0, 30)) {
              const hostname = record.hostname || domain;
              const ip = record.address || "";
              const name = `${hostname} \u2192 ${ip} (${record.record_type || "A"})`;
              observations.push({
                assetId: makeAssetId44(
                  domain,
                  `pdns-${hostname}-${ip}`,
                  "alienvault-otx"
                ),
                domain,
                assetType: record.record_type === "CNAME" ? "cname" : "ip",
                name,
                ip: ip || void 0,
                source: "alienvault-otx",
                observedAt: now,
                firstSeen: record.first ? new Date(record.first) : void 0,
                lastSeen: record.last ? new Date(record.last) : void 0,
                tags: [
                  "alienvault-otx",
                  "passive-dns",
                  record.record_type || "A"
                ],
                evidence: {
                  severity: 2,
                  confidence: 70,
                  value: `Passive DNS: ${hostname} \u2192 ${ip} (${record.record_type || "A"})`,
                  hostname,
                  address: ip,
                  recordType: record.record_type,
                  asn: record.asn,
                  flag: record.flag
                },
                attribution: {
                  provider: "AlienVault OTX",
                  url: `https://otx.alienvault.com/indicator/domain/${domain}`,
                  method: "OTX passive DNS resolution history"
                }
              });
            }
          }
        } catch (err) {
          errors.push(`OTX passive_dns: ${err.message}`);
        }
        try {
          const malware = await otxFetch(
            `/indicator/domain/${domain}/malware`,
            apiKey,
            sig
          );
          if (malware?._rateLimited) {
            rateLimited = true;
          } else if (malware?.data) {
            for (const sample of malware.data.slice(0, 10)) {
              const hash = sample.hash || "unknown";
              const name = `OTX Malware: ${hash.substring(0, 16)}...`;
              observations.push({
                assetId: makeAssetId44(
                  domain,
                  `malware-${hash}`,
                  "alienvault-otx"
                ),
                domain,
                assetType: "breach",
                name,
                source: "alienvault-otx",
                observedAt: now,
                firstSeen: sample.datetime_int ? new Date(sample.datetime_int * 1e3) : void 0,
                tags: ["alienvault-otx", "malware", "ioc"],
                evidence: {
                  severity: 8,
                  confidence: 70,
                  value: `Malware sample associated with ${domain}: ${hash}`,
                  hash,
                  detections: sample.detections
                },
                attribution: {
                  provider: "AlienVault OTX",
                  url: `https://otx.alienvault.com/indicator/file/${hash}`,
                  method: "OTX domain malware association lookup"
                }
              });
            }
          }
        } catch (err) {
          errors.push(`OTX malware: ${err.message}`);
        }
        try {
          const urls = await otxFetch(
            `/indicator/domain/${domain}/url_list?limit=20`,
            apiKey,
            sig
          );
          if (urls?._rateLimited) {
            rateLimited = true;
          } else if (urls?.url_list) {
            for (const entry of urls.url_list.slice(0, 15)) {
              const url = entry.url || "";
              if (!url) continue;
              const name = `OTX URL: ${url.substring(0, 80)}`;
              observations.push({
                assetId: makeAssetId44(domain, `url-${url}`, "alienvault-otx"),
                domain,
                assetType: "url",
                name,
                source: "alienvault-otx",
                observedAt: now,
                firstSeen: entry.date ? new Date(entry.date) : void 0,
                tags: [
                  "alienvault-otx",
                  "url",
                  ...entry.result?.safebrowsing ? ["google-safebrowsing-flagged"] : []
                ],
                evidence: {
                  severity: entry.result?.safebrowsing ? 7 : 3,
                  confidence: 65,
                  value: url,
                  httpcode: entry.httpcode,
                  gsb: entry.result?.safebrowsing || null,
                  urlworker: entry.result?.urlworker || null
                },
                attribution: {
                  provider: "AlienVault OTX",
                  url: `https://otx.alienvault.com/indicator/domain/${domain}`,
                  method: "OTX URL list for domain"
                }
              });
            }
          }
        } catch (err) {
          errors.push(`OTX url_list: ${err.message}`);
        }
        return {
          connector: "alienvault-otx",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/google-safebrowsing.ts
import { createHash as createHash45 } from "crypto";
function makeAssetId45(domain, name, source) {
  return createHash45("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function buildCheckUrls(domain) {
  return [
    `http://${domain}/`,
    `https://${domain}/`,
    `http://www.${domain}/`,
    `https://www.${domain}/`
  ];
}
var API_URL2, THREAT_TYPES, PLATFORM_TYPES, THREAT_ENTRY_TYPES, SEVERITY_MAP, googleSafeBrowsingConnector;
var init_google_safebrowsing = __esm({
  "server/lib/passive/google-safebrowsing.ts"() {
    "use strict";
    API_URL2 = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
    THREAT_TYPES = [
      "MALWARE",
      "SOCIAL_ENGINEERING",
      "UNWANTED_SOFTWARE",
      "POTENTIALLY_HARMFUL_APPLICATION"
    ];
    PLATFORM_TYPES = ["ANY_PLATFORM"];
    THREAT_ENTRY_TYPES = ["URL"];
    SEVERITY_MAP = {
      MALWARE: 9,
      SOCIAL_ENGINEERING: 8,
      UNWANTED_SOFTWARE: 6,
      POTENTIALLY_HARMFUL_APPLICATION: 7
    };
    googleSafeBrowsingConnector = {
      name: "google-safebrowsing",
      description: "Google SafeBrowsing \u2014 malware, phishing, unwanted software detection (free, requires Google API key)",
      requiresApiKey: true,
      freeUrl: "https://transparencyreport.google.com/safe-browsing/search",
      async collect(domain, config) {
        const observations = [];
        const errors = [];
        const start = Date.now();
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        if (!config?.apiKey) {
          return {
            connector: "google-safebrowsing",
            domain,
            observations: [],
            errors: ["No Google SafeBrowsing API key provided \u2014 skipping"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          const urls = buildCheckUrls(domain);
          const body = {
            client: {
              clientId: "ace-c3-caldera",
              clientVersion: "1.0.0"
            },
            threatInfo: {
              threatTypes: THREAT_TYPES,
              platformTypes: PLATFORM_TYPES,
              threatEntryTypes: THREAT_ENTRY_TYPES,
              threatEntries: urls.map((url) => ({ url }))
            }
          };
          const resp = await fetch(`${API_URL2}?key=${config.apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: config?.signal || AbortSignal.timeout(15e3)
          });
          if (resp.status === 429) {
            rateLimited = true;
          } else if (!resp.ok) {
            const errText = await resp.text().catch(() => "");
            errors.push(
              `SafeBrowsing API error ${resp.status}: ${errText.substring(0, 200)}`
            );
          } else {
            const data = await resp.json();
            if (data.matches && data.matches.length > 0) {
              for (const match of data.matches) {
                const threatType = match.threatType || "UNKNOWN";
                const matchUrl = match.threat?.url || domain;
                const name = `SafeBrowsing: ${threatType} \u2014 ${matchUrl}`;
                const severity = SEVERITY_MAP[threatType] || 6;
                observations.push({
                  assetId: makeAssetId45(
                    domain,
                    `gsb-${threatType}-${matchUrl}`,
                    "google-safebrowsing"
                  ),
                  domain,
                  assetType: "url",
                  name,
                  source: "google-safebrowsing",
                  observedAt: now,
                  tags: [
                    "google-safebrowsing",
                    threatType.toLowerCase().replace(/_/g, "-"),
                    "malicious"
                  ],
                  evidence: {
                    severity,
                    confidence: 95,
                    // Google SafeBrowsing has very high confidence
                    value: `Google SafeBrowsing flagged ${matchUrl} as ${threatType}`,
                    threatType,
                    platformType: match.platformType,
                    threatEntryType: match.threatEntryType,
                    url: matchUrl,
                    cacheDuration: match.cacheDuration
                  },
                  attribution: {
                    provider: "Google SafeBrowsing",
                    url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                      matchUrl
                    )}`,
                    method: "SafeBrowsing Lookup API v4 \u2014 threatMatches.find",
                    verifyUrl: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                      domain
                    )}`
                  }
                });
              }
            } else {
              observations.push({
                assetId: makeAssetId45(
                  domain,
                  "gsb-clean",
                  "google-safebrowsing"
                ),
                domain,
                assetType: "subdomain",
                name: `SafeBrowsing: ${domain} \u2014 No threats detected`,
                source: "google-safebrowsing",
                observedAt: now,
                tags: ["google-safebrowsing", "clean"],
                evidence: {
                  severity: 0,
                  confidence: 95,
                  value: `Google SafeBrowsing reports no threats for ${domain}`,
                  checkedUrls: urls,
                  result: "clean"
                },
                attribution: {
                  provider: "Google SafeBrowsing",
                  url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                    domain
                  )}`,
                  method: "SafeBrowsing Lookup API v4 \u2014 threatMatches.find"
                }
              });
            }
          }
        } catch (err) {
          errors.push(`SafeBrowsing: ${err.message}`);
        }
        return {
          connector: "google-safebrowsing",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/phishtank.ts
import { createHash as createHash46 } from "crypto";
function makeAssetId46(domain, name, source) {
  return createHash46("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function checkPhishTankUrl(url, apiKey, signal) {
  const params = new URLSearchParams({
    url,
    format: "json"
  });
  if (apiKey) {
    params.set("app_key", apiKey);
  }
  const resp = await fetch(CHECK_URL_API, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    signal: signal || AbortSignal.timeout(15e3)
  });
  if (resp.status === 429 || resp.status === 509) return { _rateLimited: true };
  if (!resp.ok) return null;
  return resp.json();
}
var CHECK_URL_API, phishtankConnector;
var init_phishtank = __esm({
  "server/lib/passive/phishtank.ts"() {
    "use strict";
    CHECK_URL_API = "https://checkurl.phishtank.com/checkurl/";
    phishtankConnector = {
      name: "phishtank",
      description: "PhishTank \u2014 community-verified phishing URL database (free, API key optional)",
      requiresApiKey: false,
      freeUrl: "https://phishtank.net",
      async collect(domain, config) {
        const observations = [];
        const errors = [];
        const start = Date.now();
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const apiKey = config?.apiKey;
        const sig = config?.signal;
        const urlsToCheck = [
          `http://${domain}/`,
          `https://${domain}/`,
          `http://www.${domain}/`,
          `https://www.${domain}/`
        ];
        for (const url of urlsToCheck) {
          if (rateLimited) break;
          try {
            const result = await checkPhishTankUrl(url, apiKey, sig);
            if (result?._rateLimited) {
              rateLimited = true;
              break;
            }
            if (result?.results) {
              const r = result.results;
              if (r.in_database) {
                const verified = r.verified === "yes" || r.verified === true;
                const verifiedAt = r.verified_at;
                const phishId = r.phish_id;
                const phishDetailUrl = r.phish_detail_page;
                const name = `PhishTank: ${url} \u2014 ${verified ? "VERIFIED PHISH" : "Reported (unverified)"}`;
                observations.push({
                  assetId: makeAssetId46(
                    domain,
                    `phishtank-${phishId || url}`,
                    "phishtank"
                  ),
                  domain,
                  assetType: "url",
                  name,
                  source: "phishtank",
                  observedAt: now,
                  firstSeen: verifiedAt ? new Date(verifiedAt) : void 0,
                  tags: [
                    "phishtank",
                    "phishing",
                    verified ? "verified-phish" : "reported-phish",
                    "social-engineering"
                  ],
                  evidence: {
                    severity: verified ? 9 : 6,
                    confidence: verified ? 90 : 50,
                    value: `${verified ? "VERIFIED" : "Reported"} phishing URL in PhishTank database: ${url}`,
                    phishId,
                    url,
                    inDatabase: true,
                    verified,
                    verifiedAt,
                    valid: r.valid
                  },
                  attribution: {
                    provider: "PhishTank",
                    url: phishDetailUrl || `https://phishtank.net/phish_detail.php?phish_id=${phishId}`,
                    method: "PhishTank checkurl API \u2014 community-verified phishing database",
                    verifyUrl: phishDetailUrl || `https://phishtank.net/phish_detail.php?phish_id=${phishId}`
                  }
                });
              }
            }
          } catch (err) {
            if (err.message?.includes("timeout")) {
              errors.push(`PhishTank timeout checking ${url}`);
            }
          }
        }
        if (observations.length === 0 && !rateLimited && errors.length === 0) {
          observations.push({
            assetId: makeAssetId46(domain, "phishtank-clean", "phishtank"),
            domain,
            assetType: "infrastructure",
            name: `PhishTank: ${domain} \u2014 No phishing URLs found`,
            source: "phishtank",
            observedAt: now,
            tags: ["phishtank", "clean"],
            evidence: {
              severity: 0,
              confidence: 70,
              value: `No phishing URLs found for ${domain} in PhishTank database`,
              checkedUrls: urlsToCheck,
              result: "clean"
            },
            attribution: {
              provider: "PhishTank",
              url: `https://phishtank.net`,
              method: "PhishTank checkurl API"
            }
          });
        }
        return {
          connector: "phishtank",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/darkweb-crossref.ts
import { createHash as createHash47 } from "crypto";
import { sql, like, or, eq } from "drizzle-orm";
function makeAssetId47(domain, name, source) {
  return createHash47("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function classifyCredentialSource(targetDomain, breachName, breachDomain, description) {
  const baseDomain = targetDomain.replace(/^www\./, "").toLowerCase();
  const orgName = baseDomain.split(".")[0];
  const breachLower = (breachName || "").toLowerCase();
  const descLower = (description || "").toLowerCase();
  const breachDomainLower = (breachDomain || "").toLowerCase();
  if (breachDomainLower.includes(baseDomain) || breachLower.includes(baseDomain)) {
    return {
      type: "first_party",
      confidence: 90,
      reasoning: `Breach "${breachName}" directly references target domain ${baseDomain}`
    };
  }
  if (orgName.length > 3 && breachLower.includes(orgName)) {
    const idx = breachLower.indexOf(orgName);
    const before = idx > 0 ? breachLower[idx - 1] : " ";
    const after = idx + orgName.length < breachLower.length ? breachLower[idx + orgName.length] : " ";
    if (/[\s\-_.,]/.test(before) && /[\s\-_.,]/.test(after)) {
      return {
        type: "first_party",
        confidence: 75,
        reasoning: `Breach "${breachName}" matches organization name "${orgName}" \u2014 likely a breach of the target's own systems`
      };
    }
  }
  const thirdPartyServices = [
    "linkedin",
    "facebook",
    "adobe",
    "dropbox",
    "myspace",
    "tumblr",
    "canva",
    "zynga",
    "dubsmash",
    "myfitnesspal",
    "chegg",
    "animoto",
    "evite",
    "coffeemeetsbagel",
    "500px",
    "sharelatex",
    "verifications.io",
    "collection #",
    "antipublic",
    "exploit.in",
    "combolist",
    "naz.api",
    "telegram",
    "discord",
    "twitter",
    "snapchat",
    "instagram",
    "tiktok",
    "spotify",
    "netflix",
    "hulu",
    "lastfm",
    "last.fm",
    "dailymotion",
    "bitly",
    "imgur",
    "patreon",
    "kickstarter",
    "wattpad",
    "mathway",
    "livejournal",
    "habbo",
    "neopets",
    "gaia online",
    "xsplit",
    "deezer",
    "appen",
    "gravatar",
    "pixlr",
    "123rf",
    "stockx",
    "wyzant",
    "poshmark",
    "minted",
    "shein",
    "slickdeals",
    "marriott",
    "equifax",
    "experian",
    "t-mobile",
    "att",
    "verizon",
    "yahoo",
    "hotmail",
    "gmail",
    "outlook",
    "aol"
  ];
  for (const svc of thirdPartyServices) {
    if (breachLower.includes(svc)) {
      return {
        type: "third_party",
        confidence: 95,
        reasoning: `Breach "${breachName}" is a known third-party service (${svc}) \u2014 employee credential reuse, not a breach of ${baseDomain}`
      };
    }
  }
  const comboIndicators = ["combo", "collection", "compilation", "aggregated", "antipublic", "exploit.in", "naz.api", "stealer log"];
  for (const indicator of comboIndicators) {
    if (breachLower.includes(indicator) || descLower.includes(indicator)) {
      return {
        type: "third_party",
        confidence: 85,
        reasoning: `Breach "${breachName}" appears to be an aggregated credential dump \u2014 credentials likely harvested from multiple third-party breaches`
      };
    }
  }
  if (breachDomainLower && !breachDomainLower.includes(baseDomain) && !breachDomainLower.includes(orgName)) {
    return {
      type: "third_party",
      confidence: 80,
      reasoning: `Breach "${breachName}" originated from ${breachDomain}, not from ${baseDomain} \u2014 employee credential reuse`
    };
  }
  return {
    type: "unknown",
    confidence: 40,
    reasoning: `Unable to determine if "${breachName}" is a direct breach of ${baseDomain} or a third-party service \u2014 manual review recommended`
  };
}
var darkwebCrossrefConnector;
var init_darkweb_crossref = __esm({
  "server/lib/passive/darkweb-crossref.ts"() {
    "use strict";
    init_db();
    init_schema();
    darkwebCrossrefConnector = {
      name: "darkweb_crossref",
      description: "Cross-references target domain against local underground intel database \u2014 ransomware listings, data leaks, credential breaches, IAB access sales, threat group attribution",
      requiresApiKey: false,
      freeUrl: void 0,
      async collect(domain, config) {
        const start = Date.now();
        const observations = [];
        const errors = [];
        const now = /* @__PURE__ */ new Date();
        const source = "darkweb_crossref";
        const signal = config?.signal;
        if (signal?.aborted) {
          return { connector: source, domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          const db = await getDb();
          if (!db) {
            errors.push("Database not available for darkweb cross-reference");
            return { connector: source, domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const baseDomain = domain.replace(/^www\./, "");
          const orgName = baseDomain.split(".")[0];
          const uieResults = await db.select({
            id: undergroundIntelEvents.id,
            category: undergroundIntelEvents.uieCategory,
            source: undergroundIntelEvents.uieSource,
            title: undergroundIntelEvents.uieTitle,
            description: undergroundIntelEvents.uieDescription,
            severity: undergroundIntelEvents.uieSeverity,
            actorName: undergroundIntelEvents.uieActorName,
            actorAliases: undergroundIntelEvents.uieActorAliases,
            victimName: undergroundIntelEvents.uieVictimName,
            victimSector: undergroundIntelEvents.uieVictimSector,
            victimCountry: undergroundIntelEvents.uieVictimCountry,
            eventDate: undergroundIntelEvents.uieEventDate,
            ingestedAt: undergroundIntelEvents.uieIngestedAt,
            tags: undergroundIntelEvents.uieTags,
            mitreTechniques: undergroundIntelEvents.uieMitreTechniques
          }).from(undergroundIntelEvents).where(
            or(
              like(undergroundIntelEvents.uieVictimName, `%${baseDomain}%`),
              like(undergroundIntelEvents.uieVictimName, `%${orgName}%`),
              like(undergroundIntelEvents.uieTitle, `%${baseDomain}%`),
              like(undergroundIntelEvents.uieDescription, `%${baseDomain}%`),
              like(undergroundIntelEvents.uieIocValue, `%${baseDomain}%`)
            )
          ).limit(100);
          if (signal?.aborted) {
            return { connector: source, domain, observations, errors: ["Aborted after stage 1"], durationMs: Date.now() - start, rateLimited: false };
          }
          const ceResults = await db.select({
            id: credentialExposures.id,
            source: credentialExposures.ceSource,
            breachName: credentialExposures.ceBreachName,
            breachDate: credentialExposures.ceBreachDate,
            breachDomain: credentialExposures.ceDomain,
            emailCount: credentialExposures.ceEmailCount,
            totalRecords: credentialExposures.ceTotalRecords,
            dataClasses: credentialExposures.ceDataClasses,
            actorName: credentialExposures.ceActorName,
            severity: credentialExposures.ceSeverity,
            isVerified: credentialExposures.ceIsVerified,
            isSpamList: credentialExposures.ceIsSpamList,
            description: credentialExposures.ceDescription
          }).from(credentialExposures).where(
            or(
              like(credentialExposures.ceDomain, `%${baseDomain}%`),
              like(credentialExposures.ceBreachName, `%${orgName}%`)
            )
          ).limit(100);
          if (signal?.aborted) {
            return { connector: source, domain, observations, errors: ["Aborted after stage 2"], durationMs: Date.now() - start, rateLimited: false };
          }
          const actorNames = Array.from(new Set(
            uieResults.map((e) => e.actorName).filter(Boolean)
          ));
          const threatGroupProfiles = [];
          if (actorNames.length > 0) {
            const actorRows = await db.select({
              actorId: threatActors.actorId,
              name: threatActors.name,
              aliases: threatActors.aliases,
              actorType: threatActors.actorType,
              origin: threatActors.origin,
              description: threatActors.description,
              motivation: threatActors.motivation,
              threatLevel: threatActors.threatLevel,
              sophistication: threatActors.sophistication,
              targetSectors: threatActors.targetSectors,
              targetRegions: threatActors.targetRegions,
              techniques: threatActors.techniques,
              tools: threatActors.tools,
              malware: threatActors.malware,
              firstSeen: threatActors.firstSeen,
              lastActive: threatActors.lastActive
            }).from(threatActors).where(
              or(
                ...actorNames.map((name) => like(threatActors.name, `%${name}%`)),
                ...actorNames.flatMap((name) => {
                  return [like(sql`CAST(${threatActors.aliases} AS CHAR)`, `%${name}%`)];
                })
              )
            ).limit(20);
            for (const actor of actorRows) {
              const events = await db.select({
                eventType: threatGroupEvents.eventType,
                title: threatGroupEvents.tgeTitle,
                description: threatGroupEvents.tgeDescription,
                severity: threatGroupEvents.tgeSeverity,
                victimName: threatGroupEvents.tgeVictimName,
                victimSector: threatGroupEvents.tgeVictimSector,
                victimCountry: threatGroupEvents.tgeVictimCountry,
                mitreTechniques: threatGroupEvents.tgeMitreTechniques,
                eventDate: threatGroupEvents.eventDate,
                source: threatGroupEvents.tgeSource
              }).from(threatGroupEvents).where(eq(threatGroupEvents.tgeActorId, actor.actorId)).limit(50);
              const iocs = await db.select({
                iocType: threatActorIocs.iocType,
                value: threatActorIocs.value,
                description: threatActorIocs.description,
                confidence: threatActorIocs.iocConfidence,
                firstSeen: threatActorIocs.iocFirstSeen,
                lastSeen: threatActorIocs.iocLastSeen
              }).from(threatActorIocs).where(eq(threatActorIocs.actorId, actor.actorId)).limit(30);
              const domainRelatedEvents = events.filter((e) => {
                const text = `${e.victimName || ""} ${e.title || ""} ${e.description || ""}`.toLowerCase();
                return text.includes(baseDomain) || text.includes(orgName);
              });
              const domainRelatedIocs = iocs.filter((i) => {
                const val = (i.value || "").toLowerCase();
                return val.includes(baseDomain);
              });
              threatGroupProfiles.push({
                actorId: actor.actorId,
                name: actor.name,
                aliases: Array.isArray(actor.aliases) ? actor.aliases : [],
                actorType: actor.actorType,
                origin: actor.origin,
                description: actor.description,
                motivation: actor.motivation,
                threatLevel: actor.threatLevel,
                sophistication: actor.sophistication,
                targetSectors: actor.targetSectors,
                targetRegions: actor.targetRegions,
                techniques: actor.techniques,
                tools: actor.tools,
                malware: actor.malware,
                firstSeen: actor.firstSeen,
                lastActive: actor.lastActive,
                attributedEvents: domainRelatedEvents.length > 0 ? domainRelatedEvents : events.slice(0, 10),
                relevantIocs: domainRelatedIocs.length > 0 ? domainRelatedIocs : iocs.slice(0, 10)
              });
            }
          }
          const ransomwareListings = uieResults.filter((e) => e.category === "ransomware");
          const dataLeaks = uieResults.filter((e) => e.category === "data_leak" || e.category === "credential");
          const iabListings = uieResults.filter((e) => e.category === "iab");
          const otherMentions = uieResults.filter((e) => !["ransomware", "data_leak", "credential", "iab"].includes(e.category));
          for (const listing of ransomwareListings) {
            observations.push({
              assetId: makeAssetId47(domain, `ransomware:${listing.id}`, source),
              domain,
              assetType: "breach",
              name: `Ransomware listing: ${listing.title}`,
              source,
              observedAt: now,
              firstSeen: listing.eventDate ? new Date(listing.eventDate) : void 0,
              tags: ["darkweb", "ransomware_listing", "critical_threat", "underground_intel"],
              evidence: {
                severity: 10,
                confidence: listing.victimName?.toLowerCase().includes(baseDomain) ? 90 : 65,
                category: "ransomware",
                actor_name: listing.actorName,
                actor_aliases: listing.actorAliases,
                victim_name: listing.victimName,
                victim_sector: listing.victimSector,
                victim_country: listing.victimCountry,
                event_date: listing.eventDate,
                ingested_at: listing.ingestedAt,
                source_feed: listing.source,
                title: listing.title,
                description: listing.description?.substring(0, 500),
                mitre_techniques: listing.mitreTechniques,
                match_type: listing.victimName?.toLowerCase().includes(baseDomain) ? "direct_domain" : "fuzzy_org_name"
              },
              attribution: {
                provider: `Underground Intel (${listing.source})`,
                url: "https://ransomware.live",
                method: "local_db_crossref"
              }
            });
          }
          for (const leak of dataLeaks.slice(0, 15)) {
            observations.push({
              assetId: makeAssetId47(domain, `leak:${leak.id}`, source),
              domain,
              assetType: "breach",
              name: `Data leak mention: ${leak.title}`,
              source,
              observedAt: now,
              firstSeen: leak.eventDate ? new Date(leak.eventDate) : void 0,
              tags: ["darkweb", "data_leak", "underground_intel"],
              evidence: {
                severity: 8,
                confidence: 75,
                category: leak.category,
                actor_name: leak.actorName,
                event_date: leak.eventDate,
                source_feed: leak.source,
                title: leak.title,
                description: leak.description?.substring(0, 500),
                mitre_techniques: leak.mitreTechniques
              },
              attribution: {
                provider: `Underground Intel (${leak.source})`,
                url: "",
                method: "local_db_crossref"
              }
            });
          }
          for (const iab of iabListings) {
            observations.push({
              assetId: makeAssetId47(domain, `iab:${iab.id}`, source),
              domain,
              assetType: "breach",
              name: `IAB access listing: ${iab.title}`,
              source,
              observedAt: now,
              firstSeen: iab.eventDate ? new Date(iab.eventDate) : void 0,
              tags: ["darkweb", "iab_listing", "critical_threat", "access_sale", "underground_intel"],
              evidence: {
                severity: 10,
                confidence: 70,
                category: "iab",
                actor_name: iab.actorName,
                event_date: iab.eventDate,
                source_feed: iab.source,
                title: iab.title,
                description: iab.description?.substring(0, 500),
                mitre_techniques: iab.mitreTechniques
              },
              attribution: {
                provider: `Underground Intel (${iab.source})`,
                url: "",
                method: "local_db_crossref"
              }
            });
          }
          let firstPartyBreachCount = 0;
          let thirdPartyBreachCount = 0;
          let unknownBreachCount = 0;
          for (const breach of ceResults.slice(0, 30)) {
            if (breach.isSpamList === 1) continue;
            const classification = classifyCredentialSource(
              domain,
              breach.breachName,
              breach.breachDomain,
              breach.description
            );
            if (classification.type === "first_party") firstPartyBreachCount++;
            else if (classification.type === "third_party") thirdPartyBreachCount++;
            else unknownBreachCount++;
            const baseSeverity = breach.severity === "critical" ? 9 : breach.severity === "high" ? 7 : 5;
            const adjustedSeverity = classification.type === "first_party" ? Math.min(baseSeverity + 2, 10) : classification.type === "third_party" ? Math.max(baseSeverity - 1, 3) : baseSeverity;
            observations.push({
              assetId: makeAssetId47(domain, `cebreach:${breach.id}`, source),
              domain,
              assetType: "credential",
              name: `${classification.type === "first_party" ? "\u{1F534} 1st-Party" : classification.type === "third_party" ? "3rd-Party" : "Unclassified"} Breach: ${breach.breachName}`,
              source,
              observedAt: now,
              firstSeen: breach.breachDate ? new Date(breach.breachDate) : void 0,
              tags: [
                "credential_breach",
                "breach_database",
                "underground_intel",
                `breach_source:${classification.type}`,
                ...classification.type === "first_party" ? ["first_party_breach", "critical_threat"] : [],
                ...classification.type === "third_party" ? ["third_party_breach", "credential_reuse"] : []
              ],
              evidence: {
                severity: adjustedSeverity,
                confidence: Math.max(breach.isVerified ? 90 : 70, classification.confidence),
                breach_name: breach.breachName,
                breach_date: breach.breachDate,
                breach_domain: breach.breachDomain,
                email_count: breach.emailCount,
                total_records: breach.totalRecords,
                data_classes: breach.dataClasses,
                actor_name: breach.actorName,
                is_verified: !!breach.isVerified,
                source_feed: breach.source,
                description: breach.description?.substring(0, 300),
                // Credential source classification
                credential_source: classification.type,
                credential_source_confidence: classification.confidence,
                credential_source_reasoning: classification.reasoning
              },
              attribution: {
                provider: `Credential Intel (${breach.source})`,
                url: "",
                method: "local_db_crossref"
              }
            });
          }
          for (const mention of otherMentions.slice(0, 10)) {
            observations.push({
              assetId: makeAssetId47(domain, `uie:${mention.id}`, source),
              domain,
              assetType: "breach",
              name: `Underground mention: ${mention.title}`,
              source,
              observedAt: now,
              firstSeen: mention.eventDate ? new Date(mention.eventDate) : void 0,
              tags: ["darkweb", `category:${mention.category}`, "underground_intel"],
              evidence: {
                severity: mention.severity === "critical" ? 9 : mention.severity === "high" ? 7 : 5,
                confidence: 65,
                category: mention.category,
                actor_name: mention.actorName,
                event_date: mention.eventDate,
                source_feed: mention.source,
                title: mention.title,
                description: mention.description?.substring(0, 500),
                mitre_techniques: mention.mitreTechniques
              },
              attribution: {
                provider: `Underground Intel (${mention.source})`,
                url: "",
                method: "local_db_crossref"
              }
            });
          }
          for (const profile of threatGroupProfiles) {
            observations.push({
              assetId: makeAssetId47(domain, `threat_group:${profile.actorId}`, source),
              domain,
              assetType: "breach",
              name: `Threat group attributed: ${profile.name}`,
              source,
              observedAt: now,
              tags: [
                "threat_group",
                "attribution",
                `actor_type:${profile.actorType}`,
                ...profile.threatLevel === "critical" ? ["critical_threat"] : [],
                "underground_intel"
              ],
              evidence: {
                severity: profile.threatLevel === "critical" ? 10 : profile.threatLevel === "high" ? 8 : profile.threatLevel === "medium" ? 6 : 4,
                confidence: 75,
                // Group profile
                actor_id: profile.actorId,
                actor_name: profile.name,
                actor_aliases: profile.aliases,
                actor_type: profile.actorType,
                origin: profile.origin,
                motivation: profile.motivation,
                threat_level: profile.threatLevel,
                sophistication: profile.sophistication,
                first_seen: profile.firstSeen,
                last_active: profile.lastActive,
                description: profile.description?.substring(0, 500),
                // Targeting profile
                target_sectors: profile.targetSectors,
                target_regions: profile.targetRegions,
                // TTPs
                techniques: profile.techniques,
                tools: profile.tools,
                malware: profile.malware,
                // Attribution evidence
                attributed_events_count: profile.attributedEvents.length,
                attributed_events: profile.attributedEvents.slice(0, 10).map((e) => ({
                  type: e.eventType,
                  title: e.title,
                  severity: e.severity,
                  victim: e.victimName,
                  sector: e.victimSector,
                  country: e.victimCountry,
                  date: e.eventDate,
                  mitre: e.mitreTechniques
                })),
                relevant_iocs_count: profile.relevantIocs.length,
                relevant_iocs: profile.relevantIocs.slice(0, 10).map((i) => ({
                  type: i.iocType,
                  value: i.value.substring(0, 200),
                  confidence: i.confidence,
                  first_seen: i.firstSeen,
                  last_seen: i.lastSeen
                }))
              },
              attribution: {
                provider: "Threat Actor Intelligence Database",
                url: "",
                method: "local_db_crossref"
              }
            });
            const domainEvents = profile.attributedEvents.filter((e) => {
              const text = `${e.victimName || ""} ${e.title || ""}`.toLowerCase();
              return text.includes(baseDomain) || text.includes(orgName);
            });
            for (const event of domainEvents.slice(0, 5)) {
              observations.push({
                assetId: makeAssetId47(domain, `tge:${profile.actorId}:${event.title}`, source),
                domain,
                assetType: "breach",
                name: `${profile.name} incident: ${event.title}`,
                source,
                observedAt: now,
                firstSeen: event.eventDate ? new Date(event.eventDate) : void 0,
                tags: [
                  "threat_group_event",
                  `event_type:${event.eventType}`,
                  "attribution",
                  "underground_intel"
                ],
                evidence: {
                  severity: event.severity === "critical" ? 10 : event.severity === "high" ? 8 : 6,
                  confidence: 85,
                  actor_name: profile.name,
                  actor_type: profile.actorType,
                  event_type: event.eventType,
                  title: event.title,
                  description: event.description?.substring(0, 500),
                  victim_name: event.victimName,
                  victim_sector: event.victimSector,
                  victim_country: event.victimCountry,
                  event_date: event.eventDate,
                  mitre_techniques: event.mitreTechniques,
                  source: event.source
                },
                attribution: {
                  provider: `Threat Group Events (${profile.name})`,
                  url: "",
                  method: "local_db_crossref"
                }
              });
            }
          }
          const totalMentions = uieResults.length + ceResults.length;
          const activeBreaches = ceResults.filter((c) => c.isSpamList !== 1);
          if (totalMentions > 0 || threatGroupProfiles.length > 0) {
            observations.push({
              assetId: makeAssetId47(domain, "darkweb_summary", source),
              domain,
              assetType: "breach",
              name: `Dark web intelligence summary for ${domain}`,
              source,
              observedAt: now,
              tags: ["darkweb", "summary", "underground_intel"],
              evidence: {
                total_mentions: totalMentions,
                ransomware_listings: ransomwareListings.length,
                data_leak_mentions: dataLeaks.length,
                iab_listings: iabListings.length,
                credential_breaches: activeBreaches.length,
                first_party_breaches: firstPartyBreachCount,
                third_party_breaches: thirdPartyBreachCount,
                unclassified_breaches: unknownBreachCount,
                other_mentions: otherMentions.length,
                threat_groups_attributed: threatGroupProfiles.length,
                threat_group_names: threatGroupProfiles.map((p) => p.name),
                threat_group_types: Array.from(new Set(threatGroupProfiles.map((p) => p.actorType))),
                unique_actors: Array.from(new Set([
                  ...ransomwareListings.map((r) => r.actorName),
                  ...iabListings.map((r) => r.actorName),
                  ...dataLeaks.map((r) => r.actorName)
                ].filter(Boolean))),
                severity: ransomwareListings.length > 0 || iabListings.length > 0 ? 10 : threatGroupProfiles.some((p) => p.threatLevel === "critical") ? 9 : dataLeaks.length > 0 ? 8 : firstPartyBreachCount > 0 ? 7 : activeBreaches.length > 0 ? 6 : 4,
                confidence: 80
              },
              attribution: {
                provider: "Local Underground Intel Database",
                url: "",
                method: "local_db_crossref"
              }
            });
          }
        } catch (err) {
          errors.push(`Darkweb cross-reference error: ${err.message}`);
        }
        return {
          connector: source,
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

// server/lib/passive/dehashed-whois.ts
import { createHash as createHash48 } from "crypto";
function makeAssetId48(domain, name, source) {
  return createHash48("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function dehashedWhoisRequest(apiKey, body, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(WHOIS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": apiKey
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (res.status === 401) return { data: null, error: "Dehashed WHOIS: invalid API key", status: 401 };
    if (res.status === 403) return { data: null, error: "Dehashed WHOIS: insufficient credits", status: 403 };
    if (res.status === 429) return { data: null, error: "Dehashed WHOIS: rate limited", status: 429 };
    if (!res.ok) {
      const body2 = await res.text().catch(() => "");
      return { data: null, error: `Dehashed WHOIS returned ${res.status}: ${body2}`, status: res.status };
    }
    const data = await res.json();
    return { data, error: null, status: res.status };
  } catch (err) {
    if (err.name === "AbortError") return { data: null, error: "Dehashed WHOIS request timed out", status: 0 };
    return { data: null, error: `Dehashed WHOIS error: ${err.message}`, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}
function detectNsProvider(nameservers) {
  const nsStr = nameservers.join(" ").toLowerCase();
  const providers = [
    ["cloudflare", ["cloudflare"]],
    ["aws_route53", ["awsdns"]],
    ["google_cloud_dns", ["googledomains", "google.com"]],
    ["azure_dns", ["azure-dns"]],
    ["godaddy", ["domaincontrol"]],
    ["namecheap", ["registrar-servers"]],
    ["digitalocean", ["digitalocean"]],
    ["dnsimple", ["dnsimple"]],
    ["dnsmadeeasy", ["dnsmadeeasy"]],
    ["ns1", ["nsone.net"]],
    ["ultradns", ["ultradns"]],
    ["akamai", ["akam.net"]],
    ["verisign", ["verisign"]],
    ["ovh", ["ovh.net"]],
    ["hetzner", ["hetzner"]]
  ];
  for (const [provider, patterns] of providers) {
    if (patterns.some((p) => nsStr.includes(p))) return provider;
  }
  return null;
}
var WHOIS_URL, dehashedWhoisConnector;
var init_dehashed_whois = __esm({
  "server/lib/passive/dehashed-whois.ts"() {
    "use strict";
    WHOIS_URL = "https://api.dehashed.com/v2/whois/search";
    dehashedWhoisConnector = {
      name: "dehashed_whois",
      description: "WHOIS registration data, reverse WHOIS domain discovery, and subdomain scanning via Dehashed V2 API",
      requiresApiKey: true,
      freeUrl: "https://dehashed.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const apiKey = config?.apiKey;
        if (!apiKey) {
          return {
            connector: "dehashed_whois",
            domain,
            observations: [],
            errors: ["DEHASHED_API_KEY not configured \u2014 skipping Dehashed WHOIS connector"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        const now = /* @__PURE__ */ new Date();
        let rateLimited = false;
        const whoisResult = await dehashedWhoisRequest(apiKey, {
          search_type: "whois",
          domain
        }, timeout);
        if (whoisResult.status === 429) rateLimited = true;
        if (whoisResult.data && !whoisResult.error) {
          const w = whoisResult.data;
          const creationDate = w.creation_date ? new Date(w.creation_date) : null;
          const expirationDate = w.expiration_date ? new Date(w.expiration_date) : null;
          const updatedDate = w.updated_date ? new Date(w.updated_date) : null;
          const domainAgeYears = creationDate ? Math.round((now.getTime() - creationDate.getTime()) / (365.25 * 24 * 60 * 60 * 1e3) * 10) / 10 : null;
          const daysUntilExpiry = expirationDate ? Math.round((expirationDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1e3)) : null;
          const riskSignals = [];
          if (domainAgeYears !== null && domainAgeYears < 1) riskSignals.push("recently_registered");
          if (daysUntilExpiry !== null && daysUntilExpiry < 30) riskSignals.push("expiring_soon");
          if (daysUntilExpiry !== null && daysUntilExpiry < 0) riskSignals.push("expired");
          if (w.dnssec === "unsigned") riskSignals.push("dnssec_unsigned");
          if (w.registrant_email && w.registrant_email.includes("privacy")) riskSignals.push("privacy_protected");
          if (w.registrant_organization && /proxy|privacy|protect|guard|domains by/i.test(w.registrant_organization)) {
            riskSignals.push("whois_privacy_service");
          }
          observations.push({
            assetId: makeAssetId48(domain, "whois", "dehashed_whois"),
            domain,
            assetType: "domain",
            name: domain,
            source: "dehashed_whois",
            observedAt: now,
            tags: [
              "whois_registration",
              "domain_intelligence",
              ...riskSignals
            ],
            evidence: {
              registrar: w.registrar,
              registrar_url: w.registrar_url,
              creation_date: w.creation_date,
              updated_date: w.updated_date,
              expiration_date: w.expiration_date,
              domain_age_years: domainAgeYears,
              days_until_expiry: daysUntilExpiry,
              name_servers: w.name_servers,
              status: w.status,
              registrant_organization: w.registrant_organization,
              registrant_country: w.registrant_country,
              registrant_state: w.registrant_state,
              registrant_email: w.registrant_email ? w.registrant_email.replace(/^[^@]+/, "***") : void 0,
              admin_email: w.admin_email ? w.admin_email.replace(/^[^@]+/, "***") : void 0,
              dnssec: w.dnssec,
              risk_signals: riskSignals
            },
            attribution: {
              provider: "Dehashed (WHOIS)",
              url: "https://dehashed.com",
              method: `WHOIS registration lookup for ${domain} \u2014 registered ${w.creation_date || "unknown"}, expires ${w.expiration_date || "unknown"}, registrar: ${w.registrar || "unknown"}`,
              verifyUrl: `https://who.is/whois/${domain}`
            }
          });
          if (w.name_servers && w.name_servers.length > 0) {
            const nsProvider = detectNsProvider(w.name_servers);
            observations.push({
              assetId: makeAssetId48(domain, "nameservers", "dehashed_whois"),
              domain,
              assetType: "infrastructure",
              name: `${domain} nameservers`,
              source: "dehashed_whois",
              observedAt: now,
              tags: ["nameserver", "dns_infrastructure", ...nsProvider ? [`ns_provider:${nsProvider}`] : []],
              evidence: {
                nameservers: w.name_servers,
                provider: nsProvider,
                count: w.name_servers.length
              },
              attribution: {
                provider: "Dehashed (WHOIS)",
                url: "https://dehashed.com",
                method: `Nameserver enumeration from WHOIS for ${domain}`
              }
            });
          }
        } else if (whoisResult.error) {
          errors.push(whoisResult.error);
        }
        if (!rateLimited) {
          const subResult = await dehashedWhoisRequest(apiKey, {
            search_type: "subdomain-scan",
            domain
          }, timeout);
          if (subResult.status === 429) rateLimited = true;
          if (subResult.data && !subResult.error) {
            const subs = subResult.data.subdomains || [];
            const seenSubs = /* @__PURE__ */ new Set();
            for (const sub of subs) {
              if (!sub || seenSubs.has(sub.toLowerCase())) continue;
              const subLower = sub.toLowerCase();
              seenSubs.add(subLower);
              if (subLower === domain.toLowerCase()) continue;
              observations.push({
                assetId: makeAssetId48(domain, subLower, "dehashed_whois_sub"),
                domain,
                assetType: "subdomain",
                name: subLower,
                source: "dehashed_whois",
                observedAt: now,
                tags: ["whois_derived", "subdomain_scan"],
                evidence: {
                  discovery_method: "dehashed_whois_subdomain_scan",
                  subdomain: subLower
                },
                attribution: {
                  provider: "Dehashed (WHOIS Subdomain Scan)",
                  url: "https://dehashed.com",
                  method: `Subdomain discovered via Dehashed WHOIS subdomain scan for ${domain}`
                }
              });
            }
            if (subs.length > 0) {
              observations.push({
                assetId: makeAssetId48(domain, "subdomain_scan_summary", "dehashed_whois"),
                domain,
                assetType: "domain",
                name: `${domain} subdomain scan`,
                source: "dehashed_whois",
                observedAt: now,
                tags: ["subdomain_scan_summary", "whois_derived"],
                evidence: {
                  total_subdomains: seenSubs.size,
                  subdomains: Array.from(seenSubs).slice(0, 50),
                  // Cap at 50 for evidence
                  truncated: seenSubs.size > 50
                },
                attribution: {
                  provider: "Dehashed (WHOIS Subdomain Scan)",
                  url: "https://dehashed.com",
                  method: `Discovered ${seenSubs.size} subdomains for ${domain} via WHOIS subdomain scan`
                }
              });
            }
          } else if (subResult.error) {
            errors.push(subResult.error);
          }
        }
        if (!rateLimited && whoisResult.data?.registrant_organization) {
          const orgName = whoisResult.data.registrant_organization;
          if (!/proxy|privacy|protect|guard|domains by/i.test(orgName)) {
            const reverseResult = await dehashedWhoisRequest(apiKey, {
              search_type: "reverse-whois",
              include: [orgName],
              exclude: [],
              reverse_type: "current"
            }, timeout);
            if (reverseResult.status === 429) rateLimited = true;
            if (reverseResult.data && !reverseResult.error) {
              const relatedDomains = reverseResult.data.domains || [];
              const filteredDomains = relatedDomains.filter(
                (d) => d && d.toLowerCase() !== domain.toLowerCase()
              );
              if (filteredDomains.length > 0) {
                observations.push({
                  assetId: makeAssetId48(domain, "reverse_whois", "dehashed_whois"),
                  domain,
                  assetType: "domain",
                  name: `${domain} related domains`,
                  source: "dehashed_whois",
                  observedAt: now,
                  tags: [
                    "reverse_whois",
                    "related_domains",
                    "attack_surface_expansion",
                    `related_count:${filteredDomains.length}`
                  ],
                  evidence: {
                    registrant_organization: orgName,
                    related_domains: filteredDomains.slice(0, 100),
                    total_related: filteredDomains.length,
                    truncated: filteredDomains.length > 100,
                    discovery_method: "reverse_whois_by_organization"
                  },
                  attribution: {
                    provider: "Dehashed (Reverse WHOIS)",
                    url: "https://dehashed.com",
                    method: `Reverse WHOIS by organization "${orgName}" discovered ${filteredDomains.length} related domains`
                  }
                });
                for (const relDomain of filteredDomains.slice(0, 20)) {
                  observations.push({
                    assetId: makeAssetId48(domain, relDomain, "dehashed_reverse_whois"),
                    domain,
                    assetType: "domain",
                    name: relDomain,
                    source: "dehashed_whois",
                    observedAt: now,
                    tags: ["related_domain", "same_registrant", "attack_surface"],
                    evidence: {
                      parent_domain: domain,
                      registrant_organization: orgName,
                      relationship: "same_registrant_organization"
                    },
                    attribution: {
                      provider: "Dehashed (Reverse WHOIS)",
                      url: "https://dehashed.com",
                      method: `Related domain ${relDomain} shares registrant organization "${orgName}" with ${domain}`
                    }
                  });
                }
              }
            } else if (reverseResult.error) {
              errors.push(reverseResult.error);
            }
          }
        }
        return {
          connector: "dehashed_whois",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/anubis.ts
import { createHash as createHash49 } from "crypto";
function makeAssetId49(domain, name, source) {
  return createHash49("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var anubisConnector;
var init_anubis = __esm({
  "server/lib/passive/anubis.ts"() {
    "use strict";
    anubisConnector = {
      name: "anubis",
      description: "Anubis subdomain enumeration \u2014 discovers subdomains via jldc.me aggregation of CT logs and DNS data",
      requiresApiKey: false,
      freeUrl: "https://jldc.me/anubis/subdomains",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let subdomains;
          try {
            const res = await fetch(url, { signal: controller.signal });
            if (!res.ok) throw new Error(`Anubis returned ${res.status}`);
            subdomains = await res.json();
          } finally {
            clearTimeout(timer);
          }
          if (!Array.isArray(subdomains)) {
            errors.push("Anubis returned non-array response");
            return { connector: "anubis", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
          }
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          for (const sub of subdomains) {
            const name = sub.trim().toLowerCase();
            if (!name || name.startsWith("*.") || seen.has(name)) continue;
            if (!name.endsWith(`.${domain}`) && name !== domain) continue;
            seen.add(name);
            if (seen.size > maxResults) break;
            observations.push({
              assetId: makeAssetId49(domain, name, "anubis"),
              domain,
              assetType: "subdomain",
              name,
              source: "anubis",
              observedAt: now,
              tags: ["subdomain_enum", "ct_aggregation"],
              evidence: { rawSubdomain: sub },
              attribution: {
                provider: "Anubis (jldc.me)",
                url: `https://jldc.me/anubis/subdomains/${domain}`,
                method: `Anubis subdomain enumeration \u2014 queried jldc.me API for subdomains of ${domain}`,
                verifyUrl: `https://jldc.me/anubis/subdomains/${domain}`
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("429")) {
            return { connector: "anubis", domain, observations, errors: ["Anubis rate limited"], durationMs: Date.now() - start, rateLimited: true };
          }
          errors.push(`Anubis error: ${err.message}`);
        }
        return { connector: "anubis", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/hackertarget.ts
import { createHash as createHash50 } from "crypto";
function makeAssetId50(domain, name, source) {
  return createHash50("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var hackertargetConnector;
var init_hackertarget = __esm({
  "server/lib/passive/hackertarget.ts"() {
    "use strict";
    hackertargetConnector = {
      name: "hackertarget",
      description: "HackerTarget host search \u2014 discovers subdomains and associated IPs from HackerTarget database",
      requiresApiKey: false,
      freeUrl: "https://hackertarget.com/ip-tools/",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let text;
          try {
            const res = await fetch(url, { signal: controller.signal });
            if (!res.ok) throw new Error(`HackerTarget returned ${res.status}`);
            text = await res.text();
          } finally {
            clearTimeout(timer);
          }
          if (text.includes("error") || text.includes("API count exceeded")) {
            const isRateLimited = text.includes("API count exceeded");
            return {
              connector: "hackertarget",
              domain,
              observations,
              errors: [isRateLimited ? "HackerTarget daily API limit exceeded" : `HackerTarget error: ${text.slice(0, 200)}`],
              durationMs: Date.now() - start,
              rateLimited: isRateLimited
            };
          }
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          const lines = text.split("\n").filter(Boolean);
          for (const line of lines) {
            const parts = line.split(",");
            if (parts.length < 2) continue;
            const name = parts[0].trim().toLowerCase();
            const ip = parts[1].trim();
            if (!name || name.startsWith("*.") || seen.has(name)) continue;
            if (!name.endsWith(`.${domain}`) && name !== domain) continue;
            seen.add(name);
            if (seen.size > maxResults) break;
            observations.push({
              assetId: makeAssetId50(domain, name, "hackertarget"),
              domain,
              assetType: "subdomain",
              name,
              ip: ip || void 0,
              source: "hackertarget",
              observedAt: now,
              tags: ["subdomain_enum", "host_search"],
              evidence: { rawLine: line, resolvedIp: ip },
              attribution: {
                provider: "HackerTarget",
                url: `https://api.hackertarget.com/hostsearch/?q=${domain}`,
                method: `HackerTarget host search \u2014 queried hostsearch API for hosts under ${domain}`,
                verifyUrl: `https://api.hackertarget.com/hostsearch/?q=${domain}`
              }
            });
          }
        } catch (err) {
          errors.push(`HackerTarget error: ${err.message}`);
        }
        return { connector: "hackertarget", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/rapiddns.ts
import { createHash as createHash51 } from "crypto";
function makeAssetId51(domain, name, source) {
  return createHash51("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var rapiddnsConnector;
var init_rapiddns = __esm({
  "server/lib/passive/rapiddns.ts"() {
    "use strict";
    rapiddnsConnector = {
      name: "rapiddns",
      description: "RapidDNS subdomain enumeration \u2014 discovers subdomains from DNS zone files and active scanning database",
      requiresApiKey: false,
      freeUrl: "https://rapiddns.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let html;
          try {
            const res = await fetch(url, {
              signal: controller.signal,
              headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" }
            });
            if (!res.ok) throw new Error(`RapidDNS returned ${res.status}`);
            html = await res.text();
          } finally {
            clearTimeout(timer);
          }
          const rowRegex = /<td>([^<]+)<\/td>\s*<td>([^<]*)<\/td>\s*<td>([^<]*)<\/td>/g;
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          let match;
          while ((match = rowRegex.exec(html)) !== null) {
            const name = match[1].trim().toLowerCase();
            const recordType = match[2].trim();
            const value = match[3].trim();
            if (!name || name.startsWith("*.") || seen.has(name)) continue;
            if (!name.endsWith(`.${domain}`) && name !== domain) continue;
            seen.add(name);
            if (seen.size > maxResults) break;
            const ip = recordType === "A" || recordType === "AAAA" ? value : void 0;
            observations.push({
              assetId: makeAssetId51(domain, name, "rapiddns"),
              domain,
              assetType: "subdomain",
              name,
              ip,
              source: "rapiddns",
              observedAt: now,
              tags: ["subdomain_enum", "dns_zone"],
              evidence: { recordType, value, rawMatch: match[0] },
              attribution: {
                provider: "RapidDNS",
                url: `https://rapiddns.io/subdomain/${domain}`,
                method: `RapidDNS subdomain enumeration \u2014 scraped DNS record database for subdomains of ${domain}`,
                verifyUrl: `https://rapiddns.io/subdomain/${domain}?full=1`
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("429")) {
            return { connector: "rapiddns", domain, observations, errors: ["RapidDNS rate limited"], durationMs: Date.now() - start, rateLimited: true };
          }
          errors.push(`RapidDNS error: ${err.message}`);
        }
        return { connector: "rapiddns", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/dnsrepo.ts
import { createHash as createHash52 } from "crypto";
function makeAssetId52(domain, name, source) {
  return createHash52("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var dnsrepoConnector;
var init_dnsrepo = __esm({
  "server/lib/passive/dnsrepo.ts"() {
    "use strict";
    dnsrepoConnector = {
      name: "dnsrepo",
      description: "DNSRepo subdomain enumeration \u2014 discovers subdomains from DNS zone file database",
      requiresApiKey: false,
      freeUrl: "https://dnsrepo.noc.org",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const url = `https://dnsrepo.noc.org/?domain=${encodeURIComponent(domain)}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let html;
          try {
            const res = await fetch(url, {
              signal: controller.signal,
              headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" }
            });
            if (!res.ok) throw new Error(`DNSRepo returned ${res.status}`);
            html = await res.text();
          } finally {
            clearTimeout(timer);
          }
          const subdomainRegex = new RegExp(`([a-zA-Z0-9][-a-zA-Z0-9]*\\.)*${domain.replace(/\./g, "\\.")}`, "gi");
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          let match;
          while ((match = subdomainRegex.exec(html)) !== null) {
            const name = match[0].trim().toLowerCase();
            if (!name || name.startsWith("*.") || seen.has(name)) continue;
            if (!name.endsWith(`.${domain}`) && name !== domain) continue;
            if (name.includes("_") || name.length > 253) continue;
            seen.add(name);
            if (seen.size > maxResults) break;
            observations.push({
              assetId: makeAssetId52(domain, name, "dnsrepo"),
              domain,
              assetType: "subdomain",
              name,
              source: "dnsrepo",
              observedAt: now,
              tags: ["subdomain_enum", "dns_zone"],
              evidence: { rawMatch: match[0] },
              attribution: {
                provider: "DNSRepo (noc.org)",
                url: `https://dnsrepo.noc.org/?domain=${domain}`,
                method: `DNSRepo subdomain enumeration \u2014 scraped DNS zone file database for subdomains of ${domain}`,
                verifyUrl: `https://dnsrepo.noc.org/?domain=${domain}`
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("429")) {
            return { connector: "dnsrepo", domain, observations, errors: ["DNSRepo rate limited"], durationMs: Date.now() - start, rateLimited: true };
          }
          errors.push(`DNSRepo error: ${err.message}`);
        }
        return { connector: "dnsrepo", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/sitedossier.ts
import { createHash as createHash53 } from "crypto";
function makeAssetId53(domain, name, source) {
  return createHash53("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var sitedossierConnector;
var init_sitedossier = __esm({
  "server/lib/passive/sitedossier.ts"() {
    "use strict";
    sitedossierConnector = {
      name: "sitedossier",
      description: "Sitedossier subdomain enumeration \u2014 discovers subdomains from web crawl database",
      requiresApiKey: false,
      freeUrl: "http://www.sitedossier.com",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 500;
        try {
          const url = `http://www.sitedossier.com/parentdomain/${encodeURIComponent(domain)}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let html;
          try {
            const res = await fetch(url, {
              signal: controller.signal,
              headers: { "User-Agent": "Mozilla/5.0 (compatible; AceC3/1.0)" }
            });
            if (!res.ok) throw new Error(`Sitedossier returned ${res.status}`);
            html = await res.text();
          } finally {
            clearTimeout(timer);
          }
          const linkRegex = /href="\/site\/([^"]+)"/gi;
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          let match;
          while ((match = linkRegex.exec(html)) !== null) {
            const name = match[1].trim().toLowerCase();
            if (!name || name.startsWith("*.") || seen.has(name)) continue;
            if (!name.endsWith(`.${domain}`) && name !== domain) continue;
            seen.add(name);
            if (seen.size > maxResults) break;
            observations.push({
              assetId: makeAssetId53(domain, name, "sitedossier"),
              domain,
              assetType: "subdomain",
              name,
              source: "sitedossier",
              observedAt: now,
              tags: ["subdomain_enum", "web_crawl"],
              evidence: { rawMatch: match[0] },
              attribution: {
                provider: "Sitedossier",
                url: `http://www.sitedossier.com/parentdomain/${domain}`,
                method: `Sitedossier subdomain enumeration \u2014 scraped web crawl database for subdomains of ${domain}`,
                verifyUrl: `http://www.sitedossier.com/parentdomain/${domain}`
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("429")) {
            return { connector: "sitedossier", domain, observations, errors: ["Sitedossier rate limited"], durationMs: Date.now() - start, rateLimited: true };
          }
          errors.push(`Sitedossier error: ${err.message}`);
        }
        return { connector: "sitedossier", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/favicon-hash.ts
import { createHash as createHash54 } from "crypto";
function makeAssetId54(domain, name, source) {
  return createHash54("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function murmurHash3_32(key, seed = 0) {
  const c1 = 3432918353;
  const c2 = 461845907;
  const len = key.length;
  let h1 = seed;
  const roundedEnd = len & ~3;
  for (let i = 0; i < roundedEnd; i += 4) {
    let k12 = key[i] & 255 | (key[i + 1] & 255) << 8 | (key[i + 2] & 255) << 16 | (key[i + 3] & 255) << 24;
    k12 = Math.imul(k12, c1);
    k12 = k12 << 15 | k12 >>> 17;
    k12 = Math.imul(k12, c2);
    h1 ^= k12;
    h1 = h1 << 13 | h1 >>> 19;
    h1 = Math.imul(h1, 5) + 3864292196;
  }
  let k1 = 0;
  const remaining = len & 3;
  if (remaining >= 3) k1 ^= (key[roundedEnd + 2] & 255) << 16;
  if (remaining >= 2) k1 ^= (key[roundedEnd + 1] & 255) << 8;
  if (remaining >= 1) {
    k1 ^= key[roundedEnd] & 255;
    k1 = Math.imul(k1, c1);
    k1 = k1 << 15 | k1 >>> 17;
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }
  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 2246822507);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 3266489909);
  h1 ^= h1 >>> 16;
  return h1 | 0;
}
function computeFaviconHash(faviconBytes) {
  const b64 = faviconBytes.toString("base64");
  const b64WithNewlines = b64.replace(/(.{76})/g, "$1\n") + "\n";
  return murmurHash3_32(Buffer.from(b64WithNewlines));
}
var faviconHashConnector;
var init_favicon_hash = __esm({
  "server/lib/passive/favicon-hash.ts"() {
    "use strict";
    faviconHashConnector = {
      name: "favicon_hash",
      description: "Favicon hash infrastructure discovery \u2014 computes favicon MMH3 hash to find related infrastructure via Shodan",
      requiresApiKey: false,
      freeUrl: "https://internetdb.shodan.io",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 15e3;
        try {
          const faviconUrls = [
            `https://${domain}/favicon.ico`,
            `http://${domain}/favicon.ico`
          ];
          let faviconBytes = null;
          let faviconUrl = "";
          for (const url of faviconUrls) {
            try {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), timeout);
              try {
                const res = await fetch(url, { signal: controller.signal, redirect: "follow" });
                if (res.ok) {
                  const arrayBuf = await res.arrayBuffer();
                  faviconBytes = Buffer.from(arrayBuf);
                  faviconUrl = url;
                  break;
                }
              } finally {
                clearTimeout(timer);
              }
            } catch {
              continue;
            }
          }
          if (!faviconBytes || faviconBytes.length < 10) {
            return { connector: "favicon_hash", domain, observations, errors: ["No favicon found"], durationMs: Date.now() - start, rateLimited: false };
          }
          const hash = computeFaviconHash(faviconBytes);
          const now = /* @__PURE__ */ new Date();
          observations.push({
            assetId: makeAssetId54(domain, `favicon:${hash}`, "favicon_hash"),
            domain,
            assetType: "infrastructure",
            name: `favicon:${hash}`,
            source: "favicon_hash",
            observedAt: now,
            tags: ["favicon", "infrastructure_discovery", "mmh3"],
            evidence: {
              faviconHash: hash,
              faviconUrl,
              faviconSize: faviconBytes.length,
              shodanQuery: `http.favicon.hash:${hash}`,
              sha256: createHash54("sha256").update(faviconBytes).digest("hex")
            },
            attribution: {
              provider: "Favicon Hash (local computation + Shodan query)",
              url: faviconUrl,
              method: `Computed MurmurHash3 of ${domain} favicon \u2014 use Shodan query http.favicon.hash:${hash} to find related infrastructure`,
              verifyUrl: `https://www.shodan.io/search?query=http.favicon.hash%3A${hash}`
            }
          });
        } catch (err) {
          errors.push(`Favicon hash error: ${err.message}`);
        }
        return { connector: "favicon_hash", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/jarm-fingerprint.ts
import { createHash as createHash55 } from "crypto";
import { connect } from "tls";
function makeAssetId55(domain, name, source) {
  return createHash55("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function tlsFingerprint(host, port, timeout, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Aborted before TLS connect"));
      return;
    }
    const PER_PORT_TIMEOUT = Math.min(timeout, 8e3);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("TLS connection timeout"));
    }, PER_PORT_TIMEOUT);
    const onAbort = () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error("Aborted by external signal"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    const socket = connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: PER_PORT_TIMEOUT
    }, () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      const protocol = socket.getProtocol() || "unknown";
      const cipher = socket.getCipher()?.name || "unknown";
      const cert = socket.getPeerCertificate();
      const result = {
        protocol,
        cipher,
        authorized: socket.authorized,
        issuer: typeof cert.issuer === "object" ? cert.issuer?.O || JSON.stringify(cert.issuer) : String(cert.issuer || ""),
        subject: typeof cert.subject === "object" ? cert.subject?.CN || JSON.stringify(cert.subject) : String(cert.subject || ""),
        validFrom: cert.valid_from || "",
        validTo: cert.valid_to || "",
        fingerprint256: cert.fingerprint256 || "",
        serialNumber: cert.serialNumber || "",
        sigAlgorithm: cert.sigAlgorithm || ""
      };
      socket.destroy();
      resolve(result);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(err);
    });
    socket.on("timeout", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
      reject(new Error("Socket timeout"));
    });
  });
}
var jarmFingerprintConnector;
var init_jarm_fingerprint = __esm({
  "server/lib/passive/jarm-fingerprint.ts"() {
    "use strict";
    jarmFingerprintConnector = {
      name: "jarm_fingerprint",
      description: "JARM TLS fingerprinting \u2014 identifies server TLS implementation to detect C2 frameworks, CDN infrastructure, and server software",
      requiresApiKey: false,
      freeUrl: "https://github.com/salesforce/jarm",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 1e4;
        const signal = config?.signal;
        if (signal?.aborted) {
          return { connector: "jarm_fingerprint", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          const ports = [443, 8443, 8080];
          const now = /* @__PURE__ */ new Date();
          for (const port of ports) {
            if (signal?.aborted) {
              errors.push(`Aborted after scanning ${observations.length} port(s)`);
              break;
            }
            try {
              const fp = await tlsFingerprint(domain, port, timeout, signal);
              const fpString = `${fp.protocol}|${fp.cipher}|${fp.issuer}|${fp.sigAlgorithm}`;
              const fpHash = createHash55("sha256").update(fpString).digest("hex").slice(0, 32);
              observations.push({
                assetId: makeAssetId55(domain, `tls:${port}:${fpHash}`, "jarm_fingerprint"),
                domain,
                assetType: "infrastructure",
                name: `${domain}:${port}`,
                source: "jarm_fingerprint",
                observedAt: now,
                tags: ["tls_fingerprint", "infrastructure_discovery", port === 443 ? "https" : `port_${port}`],
                evidence: {
                  port,
                  protocol: fp.protocol,
                  cipher: fp.cipher,
                  authorized: fp.authorized,
                  issuer: fp.issuer,
                  subject: fp.subject,
                  validFrom: fp.validFrom,
                  validTo: fp.validTo,
                  fingerprint256: fp.fingerprint256,
                  serialNumber: fp.serialNumber,
                  compositeHash: fpHash
                },
                attribution: {
                  provider: "JARM TLS Fingerprint (local probe)",
                  url: `https://${domain}:${port}`,
                  method: `TLS fingerprinting on ${domain}:${port} \u2014 protocol: ${fp.protocol}, cipher: ${fp.cipher}, issuer: ${fp.issuer}`
                }
              });
            } catch {
              continue;
            }
          }
          if (observations.length === 0 && !signal?.aborted) {
            errors.push(`No TLS services found on ${domain} (tried ports 443, 8443, 8080)`);
          }
        } catch (err) {
          errors.push(`JARM fingerprint error: ${err.message}`);
        }
        return { connector: "jarm_fingerprint", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/dns-zone-transfer.ts
import { createHash as createHash56 } from "crypto";
import { resolveNs as resolveNs2, resolve4 as resolve45 } from "dns/promises";
function makeAssetId56(domain, name, source) {
  return createHash56("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function dnsWithTimeout3(queryFn, timeoutMs = 5e3) {
  return Promise.race([
    queryFn(),
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("DNS query timeout")), timeoutMs)
    )
  ]);
}
async function attemptAxfr(nameserver, domain, timeout, signal) {
  const net = await import("net");
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Aborted before AXFR connect"));
      return;
    }
    const PER_NS_TIMEOUT = Math.min(timeout, 8e3);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("AXFR timeout"));
    }, PER_NS_TIMEOUT);
    const onAbort = () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error("Aborted by external signal"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    const socket = new net.Socket();
    const subdomains = [];
    const domainParts = domain.split(".");
    let qnameLen = 0;
    for (const part of domainParts) qnameLen += 1 + part.length;
    qnameLen += 1;
    const queryLen = 12 + qnameLen + 4;
    const packet = Buffer.alloc(2 + queryLen);
    packet.writeUInt16BE(queryLen, 0);
    packet.writeUInt16BE(4660, 2);
    packet.writeUInt16BE(0, 4);
    packet.writeUInt16BE(1, 6);
    packet.writeUInt16BE(0, 8);
    packet.writeUInt16BE(0, 10);
    packet.writeUInt16BE(0, 12);
    let offset = 14;
    for (const part of domainParts) {
      packet.writeUInt8(part.length, offset++);
      packet.write(part, offset, "ascii");
      offset += part.length;
    }
    packet.writeUInt8(0, offset++);
    packet.writeUInt16BE(252, offset);
    offset += 2;
    packet.writeUInt16BE(1, offset);
    let responseBuffer = Buffer.alloc(0);
    socket.connect(53, nameserver, () => {
      socket.write(packet);
    });
    socket.on("data", (data) => {
      responseBuffer = Buffer.concat([responseBuffer, data]);
      const responseStr = responseBuffer.toString("ascii");
      const domainPattern = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*\\.${domain.replace(/\./g, "\\.")}`, "gi");
      let match;
      while ((match = domainPattern.exec(responseStr)) !== null) {
        const found = match[0].toLowerCase();
        if (!subdomains.includes(found)) {
          subdomains.push(found);
        }
      }
    });
    socket.on("end", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(subdomains);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(err);
    });
    socket.on("timeout", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
      reject(new Error("Socket timeout"));
    });
  });
}
var dnsZoneTransferConnector;
var init_dns_zone_transfer = __esm({
  "server/lib/passive/dns-zone-transfer.ts"() {
    "use strict";
    dnsZoneTransferConnector = {
      name: "dns_zone_transfer",
      description: "DNS zone transfer (AXFR) attempt \u2014 discovers all DNS records from misconfigured nameservers",
      requiresApiKey: false,
      freeUrl: "https://en.wikipedia.org/wiki/DNS_zone_transfer",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 1e4;
        const maxResults = config?.maxResults ?? 500;
        const signal = config?.signal;
        if (signal?.aborted) {
          return { connector: "dns_zone_transfer", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          let nameservers;
          try {
            nameservers = await dnsWithTimeout3(() => resolveNs2(domain), 5e3);
          } catch {
            return { connector: "dns_zone_transfer", domain, observations, errors: ["Could not resolve NS records"], durationMs: Date.now() - start, rateLimited: false };
          }
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          let transferSucceeded = false;
          for (const ns of nameservers.slice(0, 4)) {
            if (signal?.aborted) {
              errors.push("Aborted mid-execution");
              break;
            }
            try {
              let nsIps;
              try {
                nsIps = await dnsWithTimeout3(() => resolve45(ns), 5e3);
              } catch {
                continue;
              }
              for (const nsIp of nsIps.slice(0, 2)) {
                if (signal?.aborted) break;
                try {
                  const subdomains = await attemptAxfr(nsIp, domain, timeout, signal);
                  if (subdomains.length > 0) {
                    transferSucceeded = true;
                    observations.push({
                      assetId: makeAssetId56(domain, `axfr:${ns}`, "dns_zone_transfer"),
                      domain,
                      assetType: "infrastructure",
                      name: `axfr:${ns}`,
                      source: "dns_zone_transfer",
                      observedAt: now,
                      tags: ["zone_transfer", "misconfiguration", "critical"],
                      evidence: {
                        nameserver: ns,
                        nameserverIp: nsIp,
                        subdomainsFound: subdomains.length,
                        vulnerability: "DNS zone transfer allowed \u2014 entire zone file is publicly accessible"
                      },
                      attribution: {
                        provider: "DNS Zone Transfer (AXFR)",
                        method: `Successful AXFR zone transfer from ${ns} (${nsIp}) \u2014 ${subdomains.length} records exposed`
                      }
                    });
                    for (const sub of subdomains) {
                      if (seen.has(sub) || seen.size > maxResults) continue;
                      seen.add(sub);
                      observations.push({
                        assetId: makeAssetId56(domain, sub, "dns_zone_transfer"),
                        domain,
                        assetType: "subdomain",
                        name: sub,
                        source: "dns_zone_transfer",
                        observedAt: now,
                        tags: ["zone_transfer", "subdomain_enum"],
                        evidence: { nameserver: ns, discoveryMethod: "AXFR" },
                        attribution: {
                          provider: "DNS Zone Transfer (AXFR)",
                          method: `Discovered via zone transfer from ${ns}`
                        }
                      });
                    }
                  }
                } catch {
                  continue;
                }
              }
            } catch {
              continue;
            }
          }
          if (!transferSucceeded && !signal?.aborted) {
            observations.push({
              assetId: makeAssetId56(domain, "axfr:blocked", "dns_zone_transfer"),
              domain,
              assetType: "infrastructure",
              name: `axfr:${domain}`,
              source: "dns_zone_transfer",
              observedAt: /* @__PURE__ */ new Date(),
              tags: ["zone_transfer", "secure"],
              evidence: {
                nameservers,
                result: "Zone transfer properly blocked on all nameservers"
              },
              attribution: {
                provider: "DNS Zone Transfer (AXFR)",
                method: `Attempted AXFR against ${nameservers.length} nameservers \u2014 all properly blocked`
              }
            });
          }
        } catch (err) {
          errors.push(`DNS zone transfer error: ${err.message}`);
        }
        return { connector: "dns_zone_transfer", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/wayback-diff.ts
import { createHash as createHash57 } from "crypto";
function makeAssetId57(domain, name, source) {
  return createHash57("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var SENSITIVE_PATTERNS, waybackDiffConnector;
var init_wayback_diff = __esm({
  "server/lib/passive/wayback-diff.ts"() {
    "use strict";
    SENSITIVE_PATTERNS = [
      { pattern: /\/(admin|administrator|wp-admin|phpmyadmin|cpanel|webmin|manager)/i, category: "admin_panel", severity: "medium" },
      { pattern: /\/(\.env|\.git|\.svn|\.htaccess|\.htpasswd|web\.config|\.DS_Store)/i, category: "config_exposure", severity: "high" },
      { pattern: /\/(backup|dump|export|sql|database|db)\.(zip|tar|gz|sql|bak|old)/i, category: "backup_file", severity: "high" },
      { pattern: /\/(api[-_]?key|secret|token|password|credential|auth)/i, category: "credential_exposure", severity: "critical" },
      { pattern: /\/(swagger|api-docs|openapi|graphql|graphiql|playground)/i, category: "api_documentation", severity: "medium" },
      { pattern: /\/(debug|trace|test|staging|dev|internal)/i, category: "debug_endpoint", severity: "medium" },
      { pattern: /\/(phpinfo|server-status|server-info|status|health)/i, category: "server_info", severity: "medium" },
      { pattern: /\/(\.well-known|robots\.txt|sitemap\.xml|crossdomain\.xml)/i, category: "metadata", severity: "info" },
      { pattern: /\/(upload|uploads|files|documents|attachments|media)/i, category: "file_upload", severity: "low" },
      { pattern: /\/(jenkins|gitlab|jira|confluence|bamboo|sonarqube|grafana|kibana)/i, category: "devops_tool", severity: "medium" },
      { pattern: /\/(wp-content|wp-includes|wp-json)/i, category: "wordpress", severity: "info" },
      { pattern: /\/(cgi-bin|fcgi|wsgi)/i, category: "cgi_endpoint", severity: "low" },
      { pattern: /\.(bak|old|orig|copy|tmp|temp|swp|save)$/i, category: "backup_extension", severity: "medium" },
      { pattern: /\.(log|logs|error_log|access_log)$/i, category: "log_file", severity: "high" },
      { pattern: /\.(conf|config|cfg|ini|properties|yaml|yml|toml)$/i, category: "config_file", severity: "high" }
    ];
    waybackDiffConnector = {
      name: "wayback_diff",
      description: "Wayback content diff analysis \u2014 discovers removed admin panels, leaked credentials, and exposed configs from historical snapshots",
      requiresApiKey: false,
      freeUrl: "https://web.archive.org",
      async collect(domain, config) {
        const start = Date.now();
        const errors = [];
        const observations = [];
        const timeout = config?.timeout ?? 3e4;
        const maxResults = config?.maxResults ?? 200;
        try {
          const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=5000`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          let rows;
          try {
            const res = await fetch(cdxUrl, { signal: controller.signal });
            if (!res.ok) throw new Error(`Wayback CDX returned ${res.status}`);
            rows = await res.json();
          } finally {
            clearTimeout(timer);
          }
          if (!Array.isArray(rows) || rows.length < 2) {
            return { connector: "wayback_diff", domain, observations, errors: ["No Wayback data found"], durationMs: Date.now() - start, rateLimited: false };
          }
          const dataRows = rows.slice(1);
          const seen = /* @__PURE__ */ new Set();
          const now = /* @__PURE__ */ new Date();
          const categoryCounts = {};
          for (const row of dataRows) {
            if (observations.length >= maxResults) break;
            const [originalUrl, timestamp, statusCode, mimeType] = row;
            if (!originalUrl) continue;
            for (const { pattern, category, severity } of SENSITIVE_PATTERNS) {
              if (pattern.test(originalUrl)) {
                const urlKey = `${category}:${originalUrl}`;
                if (seen.has(urlKey)) continue;
                seen.add(urlKey);
                categoryCounts[category] = (categoryCounts[category] || 0) + 1;
                const archiveUrl = `https://web.archive.org/web/${timestamp}/${originalUrl}`;
                observations.push({
                  assetId: makeAssetId57(domain, urlKey, "wayback_diff"),
                  domain,
                  assetType: "url",
                  name: originalUrl,
                  source: "wayback_diff",
                  observedAt: now,
                  firstSeen: timestamp ? new Date(
                    parseInt(timestamp.slice(0, 4)),
                    parseInt(timestamp.slice(4, 6)) - 1,
                    parseInt(timestamp.slice(6, 8))
                  ) : void 0,
                  tags: ["wayback", "historical", category, `severity_${severity}`],
                  evidence: {
                    originalUrl,
                    archiveTimestamp: timestamp,
                    statusCode,
                    mimeType,
                    archiveUrl,
                    category,
                    severity
                  },
                  attribution: {
                    provider: "Internet Archive Wayback Machine",
                    url: archiveUrl,
                    method: `Historical content analysis \u2014 found ${category} pattern in archived URL from ${timestamp}`,
                    verifyUrl: archiveUrl
                  }
                });
                break;
              }
            }
          }
          if (Object.keys(categoryCounts).length > 0) {
            observations.push({
              assetId: makeAssetId57(domain, "wayback_summary", "wayback_diff"),
              domain,
              assetType: "infrastructure",
              name: `wayback_analysis:${domain}`,
              source: "wayback_diff",
              observedAt: now,
              tags: ["wayback", "summary"],
              evidence: {
                totalArchived: dataRows.length,
                sensitiveFindings: observations.length,
                categoryCounts
              },
              attribution: {
                provider: "Internet Archive Wayback Machine",
                url: `https://web.archive.org/web/*/${domain}`,
                method: `Analyzed ${dataRows.length} archived URLs for ${domain} \u2014 found ${observations.length} sensitive patterns across ${Object.keys(categoryCounts).length} categories`,
                verifyUrl: `https://web.archive.org/web/*/${domain}`
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("429")) {
            return { connector: "wayback_diff", domain, observations, errors: ["Wayback CDX rate limited"], durationMs: Date.now() - start, rateLimited: true };
          }
          errors.push(`Wayback diff error: ${err.message}`);
        }
        return { connector: "wayback_diff", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
    };
  }
});

// server/lib/passive/urlhaus.ts
import { createHash as createHash58 } from "crypto";
function makeAssetId58(domain, name, source) {
  return createHash58("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function urlhausPost(endpoint, body) {
  const resp = await fetch(`${API_URL3}${endpoint}/`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
    signal: AbortSignal.timeout(15e3)
  });
  if (!resp.ok) return null;
  return resp.json();
}
var API_URL3, urlhausConnector;
var init_urlhaus = __esm({
  "server/lib/passive/urlhaus.ts"() {
    "use strict";
    API_URL3 = "https://urlhaus-api.abuse.ch/v1/";
    urlhausConnector = {
      name: "urlhaus",
      description: "URLhaus (abuse.ch) \u2014 free malicious URL database, malware distribution, phishing lures, exploit kits",
      requiresApiKey: false,
      freeUrl: "https://urlhaus.abuse.ch",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const hostResult = await urlhausPost("host", { host: domain });
          if (hostResult?.query_status === "no_results") {
            observations.push({
              assetId: makeAssetId58(domain, `URLhaus clean: ${domain}`, "urlhaus"),
              domain,
              assetType: "info",
              name: `URLhaus: No malicious URLs found for ${domain}`,
              source: "urlhaus",
              observedAt: now,
              tags: ["urlhaus", "abuse_ch", "clean", "malware_distribution"],
              evidence: {
                severity: 0,
                status: "clean",
                value: `No malicious URLs associated with ${domain} in URLhaus database`
              },
              attribution: { provider: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch", method: "api" }
            });
          } else if (hostResult?.urls && Array.isArray(hostResult.urls)) {
            const urlCount = hostResult.urls.length;
            const onlineUrls = hostResult.urls.filter((u) => u.url_status === "online");
            const offlineUrls = hostResult.urls.filter((u) => u.url_status === "offline");
            observations.push({
              assetId: makeAssetId58(domain, `URLhaus summary: ${domain}`, "urlhaus"),
              domain,
              assetType: "breach",
              name: `URLhaus: ${urlCount} malicious URL(s) found for ${domain}`,
              source: "urlhaus",
              observedAt: now,
              tags: [
                "urlhaus",
                "abuse_ch",
                "malware_distribution",
                ...onlineUrls.length > 0 ? ["active_threat", "critical"] : []
              ],
              evidence: {
                severity: onlineUrls.length > 0 ? 9 : 6,
                confidence: 90,
                value: `${urlCount} malicious URL(s): ${onlineUrls.length} online, ${offlineUrls.length} offline`,
                total_urls: urlCount,
                online_count: onlineUrls.length,
                offline_count: offlineUrls.length,
                blacklists: hostResult.blacklists || {},
                url_count: hostResult.urls_online || urlCount
              },
              attribution: { provider: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch", method: "api" }
            });
            for (const url of hostResult.urls.slice(0, 20)) {
              const isOnline = url.url_status === "online";
              const name = `URLhaus URL: ${url.url || "unknown"}`;
              observations.push({
                assetId: makeAssetId58(domain, name, "urlhaus"),
                domain,
                assetType: "breach",
                name,
                source: "urlhaus",
                observedAt: now,
                firstSeen: url.date_added ? new Date(url.date_added) : void 0,
                tags: [
                  "urlhaus",
                  "abuse_ch",
                  "malicious_url",
                  url.threat || "malware",
                  url.url_status || "unknown",
                  ...isOnline ? ["active_threat"] : []
                ],
                evidence: {
                  severity: isOnline ? 9 : 5,
                  confidence: 85,
                  value: `${url.threat || "malware"} \u2014 ${url.url_status || "unknown"} (${url.tags?.join(", ") || "no tags"})`,
                  url: url.url,
                  url_status: url.url_status,
                  threat: url.threat,
                  date_added: url.date_added,
                  urlhaus_reference: url.urlhaus_reference,
                  tags: url.tags || []
                },
                attribution: { provider: "URLhaus (abuse.ch)", url: url.urlhaus_reference || "https://urlhaus.abuse.ch", method: "api" }
              });
            }
          }
        } catch (err) {
          if (err.message?.includes("timeout")) {
            errors.push("URLhaus API timeout");
          } else {
            errors.push(err.message || "Unknown error during URLhaus lookup");
          }
        }
        return {
          connector: "urlhaus",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/malwarebazaar.ts
import { createHash as createHash59 } from "crypto";
function makeAssetId59(domain, name, source) {
  return createHash59("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function bazaarPost(body) {
  const resp = await fetch(API_URL4, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
    signal: AbortSignal.timeout(15e3)
  });
  if (!resp.ok) return null;
  return resp.json();
}
var API_URL4, malwarebazaarConnector;
var init_malwarebazaar = __esm({
  "server/lib/passive/malwarebazaar.ts"() {
    "use strict";
    API_URL4 = "https://mb-api.abuse.ch/api/v1/";
    malwarebazaarConnector = {
      name: "malwarebazaar",
      description: "MalwareBazaar (abuse.ch) \u2014 free malware sample database, C2 callbacks, payload delivery, dropper infrastructure",
      requiresApiKey: false,
      freeUrl: "https://bazaar.abuse.ch",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const tagResult = await bazaarPost({ query: "get_taginfo", tag: domain.replace(/\./g, "_") });
          const domainTagResult = await bazaarPost({ query: "get_taginfo", tag: domain });
          const allSamples = [];
          const seenHashes = /* @__PURE__ */ new Set();
          for (const result of [tagResult, domainTagResult]) {
            if (result?.query_status === "ok" && result.data) {
              for (const sample of result.data) {
                if (!seenHashes.has(sample.sha256_hash)) {
                  seenHashes.add(sample.sha256_hash);
                  allSamples.push(sample);
                }
              }
            }
          }
          if (domain.split(".").length >= 2) {
            try {
              const sigResult = await bazaarPost({ query: "get_siginfo", signature: domain.split(".")[0] });
              if (sigResult?.query_status === "ok" && sigResult.data) {
                for (const sample of sigResult.data.slice(0, 10)) {
                  if (!seenHashes.has(sample.sha256_hash)) {
                    const sampleStr = JSON.stringify(sample).toLowerCase();
                    if (sampleStr.includes(domain.toLowerCase())) {
                      seenHashes.add(sample.sha256_hash);
                      allSamples.push(sample);
                    }
                  }
                }
              }
            } catch {
            }
          }
          if (allSamples.length === 0) {
            observations.push({
              assetId: makeAssetId59(domain, `MalwareBazaar clean: ${domain}`, "malwarebazaar"),
              domain,
              assetType: "info",
              name: `MalwareBazaar: No malware samples found for ${domain}`,
              source: "malwarebazaar",
              observedAt: now,
              tags: ["malwarebazaar", "abuse_ch", "clean", "malware_samples"],
              evidence: {
                severity: 0,
                status: "clean",
                value: `No malware samples associated with ${domain} in MalwareBazaar database`
              },
              attribution: { provider: "MalwareBazaar (abuse.ch)", url: "https://bazaar.abuse.ch", method: "api" }
            });
          } else {
            const families = [...new Set(allSamples.map((s) => s.signature || "unknown").filter(Boolean))];
            const fileTypes = [...new Set(allSamples.map((s) => s.file_type || "unknown"))];
            observations.push({
              assetId: makeAssetId59(domain, `MalwareBazaar summary: ${domain}`, "malwarebazaar"),
              domain,
              assetType: "breach",
              name: `MalwareBazaar: ${allSamples.length} malware sample(s) associated with ${domain}`,
              source: "malwarebazaar",
              observedAt: now,
              tags: [
                "malwarebazaar",
                "abuse_ch",
                "malware_samples",
                "critical_threat",
                ...families.slice(0, 5).map((f) => `malware_family:${f}`)
              ],
              evidence: {
                severity: 9,
                confidence: 85,
                value: `${allSamples.length} malware sample(s) \u2014 families: ${families.join(", ") || "unknown"}`,
                total_samples: allSamples.length,
                malware_families: families,
                file_types: fileTypes
              },
              attribution: { provider: "MalwareBazaar (abuse.ch)", url: "https://bazaar.abuse.ch", method: "api" }
            });
            for (const sample of allSamples.slice(0, 15)) {
              const name = `MalwareBazaar: ${sample.signature || "unknown"} (${sample.sha256_hash?.slice(0, 12)}...)`;
              observations.push({
                assetId: makeAssetId59(domain, name, "malwarebazaar"),
                domain,
                assetType: "breach",
                name,
                source: "malwarebazaar",
                observedAt: now,
                firstSeen: sample.first_seen ? new Date(sample.first_seen) : void 0,
                lastSeen: sample.last_seen ? new Date(sample.last_seen) : void 0,
                tags: [
                  "malwarebazaar",
                  "abuse_ch",
                  "malware_sample",
                  sample.signature || "unknown_family",
                  sample.file_type || "unknown_type",
                  ...sample.tags || []
                ],
                evidence: {
                  severity: 8,
                  confidence: sample.intelligence?.clamav ? 90 : 75,
                  value: `${sample.signature || "unknown"} \u2014 ${sample.file_type || "unknown"} (${sample.file_size || "?"} bytes)`,
                  sha256: sample.sha256_hash,
                  sha1: sample.sha1_hash,
                  md5: sample.md5_hash,
                  file_type: sample.file_type,
                  file_type_mime: sample.file_type_mime,
                  file_size: sample.file_size,
                  signature: sample.signature,
                  first_seen: sample.first_seen,
                  last_seen: sample.last_seen,
                  reporter: sample.reporter,
                  delivery_method: sample.delivery_method,
                  intelligence: sample.intelligence || {},
                  bazaar_reference: `https://bazaar.abuse.ch/sample/${sample.sha256_hash}/`
                },
                attribution: {
                  provider: "MalwareBazaar (abuse.ch)",
                  url: `https://bazaar.abuse.ch/sample/${sample.sha256_hash}/`,
                  method: "api"
                }
              });
            }
          }
        } catch (err) {
          if (err.message?.includes("timeout")) {
            errors.push("MalwareBazaar API timeout");
          } else {
            errors.push(err.message || "Unknown error during MalwareBazaar lookup");
          }
        }
        return {
          connector: "malwarebazaar",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/sec-edgar.ts
import { createHash as createHash60 } from "crypto";
function makeAssetId60(domain, name, source) {
  return createHash60("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function edgarFetch(url) {
  const resp = await fetch(url, {
    headers: {
      "User-Agent": USER_AGENT,
      "Accept": "application/json"
    },
    signal: AbortSignal.timeout(15e3)
  });
  if (!resp.ok) return null;
  return resp.json();
}
async function searchCompany(query) {
  const url = `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(query)}%22&dateRange=custom&startdt=2023-01-01&forms=10-K,10-Q,8-K&from=0&size=5`;
  return edgarFetch(url);
}
async function getSubmissions(cik) {
  const paddedCik = cik.padStart(10, "0");
  return edgarFetch(`${SUBMISSIONS_BASE}/CIK${paddedCik}.json`);
}
function domainToCompanyName(domain) {
  return domain.split(".")[0].replace(/-/g, " ");
}
var SUBMISSIONS_BASE, USER_AGENT, secEdgarConnector;
var init_sec_edgar = __esm({
  "server/lib/passive/sec-edgar.ts"() {
    "use strict";
    SUBMISSIONS_BASE = "https://data.sec.gov/submissions";
    USER_AGENT = "AceC3Platform/1.0 (security-research@acec3.com)";
    secEdgarConnector = {
      name: "sec_edgar",
      description: "SEC EDGAR \u2014 free US public company filings (10-K, 10-Q, 8-K) for BIA financial impact context",
      requiresApiKey: false,
      freeUrl: "https://www.sec.gov/cgi-bin/browse-edgar",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const companyName = domainToCompanyName(domain);
          let searchResult = await searchCompany(domain);
          if (!searchResult?.hits?.hits?.length && companyName.length > 2) {
            searchResult = await searchCompany(companyName);
          }
          if (!searchResult?.hits?.hits?.length) {
            observations.push({
              assetId: makeAssetId60(domain, `SEC EDGAR: no filings for ${domain}`, "sec_edgar"),
              domain,
              assetType: "info",
              name: `SEC EDGAR: No public filings found for ${domain}`,
              source: "sec_edgar",
              observedAt: now,
              tags: ["sec_edgar", "bia_context", "financial", "no_results"],
              evidence: {
                severity: 0,
                status: "not_found",
                value: `No SEC filings found \u2014 organization may be private, non-US, or not publicly traded`
              },
              attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" }
            });
            return { connector: "sec_edgar", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const topHit = searchResult.hits.hits[0]._source || searchResult.hits.hits[0];
          const cik = topHit.entity_id || topHit.ciks?.[0];
          const entityName = topHit.entity_name || topHit.display_names?.[0] || companyName;
          let submissions = null;
          if (cik) {
            try {
              submissions = await getSubmissions(String(cik));
            } catch {
            }
          }
          const recentFilings = searchResult.hits.hits.slice(0, 5);
          const filingTypes = recentFilings.map((h) => (h._source || h).form_type || (h._source || h).forms).filter(Boolean);
          observations.push({
            assetId: makeAssetId60(domain, `SEC EDGAR company: ${entityName}`, "sec_edgar"),
            domain,
            assetType: "info",
            name: `SEC EDGAR: ${entityName} (CIK ${cik || "unknown"})`,
            source: "sec_edgar",
            observedAt: now,
            tags: ["sec_edgar", "bia_context", "financial", "public_company", "company_profile"],
            evidence: {
              severity: 2,
              confidence: cik ? 85 : 60,
              value: `Public company: ${entityName} \u2014 recent filings: ${filingTypes.join(", ") || "various"}`,
              entity_name: entityName,
              cik: cik || null,
              is_public_company: true,
              recent_filing_types: filingTypes,
              total_filings: searchResult.hits.total?.value || recentFilings.length,
              edgar_url: cik ? `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${cik}&type=10-K&dateb=&owner=include&count=10` : null
            },
            attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" }
          });
          if (submissions) {
            const companyInfo = {
              name: submissions.name,
              sic: submissions.sic,
              sicDescription: submissions.sicDescription,
              stateOfIncorporation: submissions.stateOfIncorporation,
              fiscalYearEnd: submissions.fiscalYearEnd,
              exchanges: submissions.exchanges || [],
              tickers: submissions.tickers || [],
              category: submissions.category,
              entityType: submissions.entityType,
              phone: submissions.phone,
              addresses: submissions.addresses
            };
            observations.push({
              assetId: makeAssetId60(domain, `SEC EDGAR profile: ${entityName}`, "sec_edgar"),
              domain,
              assetType: "info",
              name: `SEC EDGAR Profile: ${companyInfo.name || entityName} \u2014 ${companyInfo.sicDescription || "unknown sector"}`,
              source: "sec_edgar",
              observedAt: now,
              tags: [
                "sec_edgar",
                "bia_context",
                "financial",
                "company_profile",
                ...companyInfo.tickers?.length ? [`ticker:${companyInfo.tickers[0]}`] : [],
                ...companyInfo.sic ? [`sic:${companyInfo.sic}`] : []
              ],
              evidence: {
                severity: 2,
                confidence: 90,
                value: `${companyInfo.name || entityName} \u2014 SIC: ${companyInfo.sicDescription || "unknown"} | Ticker: ${companyInfo.tickers?.join(", ") || "N/A"} | Exchange: ${companyInfo.exchanges?.join(", ") || "N/A"}`,
                company_name: companyInfo.name,
                sic_code: companyInfo.sic,
                sic_description: companyInfo.sicDescription,
                state_of_incorporation: companyInfo.stateOfIncorporation,
                fiscal_year_end: companyInfo.fiscalYearEnd,
                exchanges: companyInfo.exchanges,
                tickers: companyInfo.tickers,
                entity_type: companyInfo.entityType,
                category: companyInfo.category
              },
              attribution: { provider: "SEC EDGAR", url: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${cik}`, method: "api" }
            });
            const recentFilingsData = submissions.filings?.recent;
            if (recentFilingsData?.form) {
              const tenKIndices = [];
              for (let i = 0; i < recentFilingsData.form.length && tenKIndices.length < 3; i++) {
                if (recentFilingsData.form[i] === "10-K") {
                  tenKIndices.push(i);
                }
              }
              for (const idx of tenKIndices) {
                const filingDate = recentFilingsData.filingDate?.[idx];
                const accessionNumber = recentFilingsData.accessionNumber?.[idx];
                const primaryDoc = recentFilingsData.primaryDocument?.[idx];
                observations.push({
                  assetId: makeAssetId60(domain, `SEC 10-K: ${entityName} ${filingDate}`, "sec_edgar"),
                  domain,
                  assetType: "info",
                  name: `SEC 10-K Filing: ${entityName} (${filingDate || "unknown date"})`,
                  source: "sec_edgar",
                  observedAt: now,
                  firstSeen: filingDate ? new Date(filingDate) : void 0,
                  tags: ["sec_edgar", "bia_context", "financial", "10-K", "annual_report"],
                  evidence: {
                    severity: 2,
                    confidence: 95,
                    value: `Annual report (10-K) filed ${filingDate || "unknown"} \u2014 contains revenue, risk factors, business segments`,
                    filing_type: "10-K",
                    filing_date: filingDate,
                    accession_number: accessionNumber,
                    primary_document: primaryDoc,
                    filing_url: accessionNumber ? `https://www.sec.gov/Archives/edgar/data/${cik}/${accessionNumber.replace(/-/g, "")}/${primaryDoc}` : null,
                    bia_relevance: "Contains revenue data, business segment descriptions, risk factors, and operational dependencies for BIA financial impact calculation"
                  },
                  attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" }
                });
              }
            }
          }
        } catch (err) {
          if (err.message?.includes("429") || err.message?.includes("rate")) {
            rateLimited = true;
            errors.push("SEC EDGAR rate limited (10 req/sec limit)");
          } else if (err.message?.includes("timeout")) {
            errors.push("SEC EDGAR API timeout");
          } else {
            errors.push(err.message || "Unknown error during SEC EDGAR lookup");
          }
        }
        return {
          connector: "sec_edgar",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/osv-dev.ts
import { createHash as createHash61 } from "crypto";
function makeAssetId61(domain, name, source) {
  return createHash61("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function osvQueryBatch(queries) {
  const resp = await fetch(`${API_URL5}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(2e4)
  });
  if (!resp.ok) return null;
  return resp.json();
}
function extractPackagesFromTechStack(config) {
  const packages = [];
  const priorObs = config?.priorObservations || [];
  const techToPackage = {
    "wordpress": [{ name: "wordpress", ecosystem: "Packagist" }],
    "jquery": [{ name: "jquery", ecosystem: "npm" }],
    "react": [{ name: "react", ecosystem: "npm" }],
    "angular": [{ name: "@angular/core", ecosystem: "npm" }],
    "vue": [{ name: "vue", ecosystem: "npm" }],
    "next.js": [{ name: "next", ecosystem: "npm" }],
    "express": [{ name: "express", ecosystem: "npm" }],
    "django": [{ name: "Django", ecosystem: "PyPI" }],
    "flask": [{ name: "Flask", ecosystem: "PyPI" }],
    "rails": [{ name: "rails", ecosystem: "RubyGems" }],
    "spring": [{ name: "org.springframework:spring-core", ecosystem: "Maven" }],
    "laravel": [{ name: "laravel/framework", ecosystem: "Packagist" }],
    "drupal": [{ name: "drupal/core", ecosystem: "Packagist" }],
    "joomla": [{ name: "joomla/joomla-cms", ecosystem: "Packagist" }],
    "nginx": [{ name: "nginx", ecosystem: "Linux" }],
    "apache": [{ name: "apache2", ecosystem: "Linux" }],
    "openssl": [{ name: "openssl", ecosystem: "Linux" }],
    "bootstrap": [{ name: "bootstrap", ecosystem: "npm" }],
    "lodash": [{ name: "lodash", ecosystem: "npm" }],
    "moment": [{ name: "moment", ecosystem: "npm" }],
    "axios": [{ name: "axios", ecosystem: "npm" }]
  };
  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs).toLowerCase();
    for (const [tech, pkgs] of Object.entries(techToPackage)) {
      if (obsStr.includes(tech.toLowerCase())) {
        for (const pkg of pkgs) {
          if (!packages.find((p) => p.name === pkg.name && p.ecosystem === pkg.ecosystem)) {
            packages.push(pkg);
          }
        }
      }
    }
  }
  return packages;
}
var API_URL5, osvDevConnector;
var init_osv_dev = __esm({
  "server/lib/passive/osv-dev.ts"() {
    "use strict";
    API_URL5 = "https://api.osv.dev/v1";
    osvDevConnector = {
      name: "osv_dev",
      description: "OSV.dev \u2014 free open source vulnerability database, supply chain vulns for npm/PyPI/Go/Maven/RubyGems",
      requiresApiKey: false,
      freeUrl: "https://osv.dev",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const packages = extractPackagesFromTechStack(config);
          if (packages.length === 0) {
            observations.push({
              assetId: makeAssetId61(domain, `OSV.dev: no tech stack for ${domain}`, "osv_dev"),
              domain,
              assetType: "info",
              name: `OSV.dev: No detected tech stack packages to query for ${domain}`,
              source: "osv_dev",
              observedAt: now,
              tags: ["osv_dev", "supply_chain", "no_tech_stack"],
              evidence: {
                severity: 0,
                status: "no_packages",
                value: "No technology packages detected from prior recon \u2014 run BuiltWith/Wappalyzer first for best results"
              },
              attribution: { provider: "OSV.dev", url: "https://osv.dev", method: "api" }
            });
            return { connector: "osv_dev", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const queries = packages.map((pkg) => ({
            package: { name: pkg.name, ecosystem: pkg.ecosystem }
          }));
          const batchResult = await osvQueryBatch(queries);
          let totalVulns = 0;
          const criticalVulns = [];
          const highVulns = [];
          const allVulns = [];
          if (batchResult?.results) {
            for (let i = 0; i < batchResult.results.length; i++) {
              const result = batchResult.results[i];
              const pkg = packages[i];
              if (result.vulns && result.vulns.length > 0) {
                totalVulns += result.vulns.length;
                allVulns.push({ pkg, vulns: result.vulns });
                for (const vuln of result.vulns) {
                  const severity = vuln.database_specific?.severity || vuln.severity?.[0]?.score || "unknown";
                  const cvss = typeof severity === "number" ? severity : vuln.severity?.[0]?.score || 0;
                  if (cvss >= 9 || severity === "CRITICAL") {
                    criticalVulns.push({ ...vuln, _pkg: pkg });
                  } else if (cvss >= 7 || severity === "HIGH") {
                    highVulns.push({ ...vuln, _pkg: pkg });
                  }
                }
              }
            }
          }
          observations.push({
            assetId: makeAssetId61(domain, `OSV.dev summary: ${domain}`, "osv_dev"),
            domain,
            assetType: totalVulns > 0 ? "vuln" : "info",
            name: totalVulns > 0 ? `OSV.dev: ${totalVulns} supply chain vuln(s) across ${allVulns.length} package(s)` : `OSV.dev: No known supply chain vulns in ${packages.length} detected package(s)`,
            source: "osv_dev",
            observedAt: now,
            tags: [
              "osv_dev",
              "supply_chain",
              ...totalVulns > 0 ? ["vulnerable"] : ["clean"],
              ...criticalVulns.length > 0 ? ["critical_supply_chain"] : []
            ],
            evidence: {
              severity: criticalVulns.length > 0 ? 9 : highVulns.length > 0 ? 7 : totalVulns > 0 ? 5 : 0,
              confidence: 90,
              value: `${totalVulns} vuln(s) in ${packages.length} package(s) \u2014 ${criticalVulns.length} critical, ${highVulns.length} high`,
              total_vulns: totalVulns,
              critical_count: criticalVulns.length,
              high_count: highVulns.length,
              packages_scanned: packages.length,
              packages_vulnerable: allVulns.length,
              packages_checked: packages.map((p) => `${p.ecosystem}/${p.name}`)
            },
            attribution: { provider: "OSV.dev", url: "https://osv.dev", method: "api" }
          });
          const topVulns = [...criticalVulns, ...highVulns].slice(0, 15);
          for (const vuln of topVulns) {
            const vulnId = vuln.id || vuln.aliases?.[0] || "unknown";
            const pkg = vuln._pkg;
            const cvss = vuln.severity?.[0]?.score || 0;
            const summary = vuln.summary || vuln.details?.slice(0, 200) || "No description";
            observations.push({
              assetId: makeAssetId61(domain, `OSV ${vulnId}: ${pkg.name}`, "osv_dev"),
              domain,
              assetType: "vuln",
              name: `OSV ${vulnId}: ${pkg.ecosystem}/${pkg.name} \u2014 ${summary.slice(0, 80)}`,
              source: "osv_dev",
              observedAt: now,
              firstSeen: vuln.published ? new Date(vuln.published) : void 0,
              lastSeen: vuln.modified ? new Date(vuln.modified) : void 0,
              tags: [
                "osv_dev",
                "supply_chain",
                "vulnerability",
                pkg.ecosystem.toLowerCase(),
                cvss >= 9 ? "critical" : cvss >= 7 ? "high" : "medium",
                ...(vuln.aliases || []).filter((a) => a.startsWith("CVE-"))
              ],
              evidence: {
                severity: cvss >= 9 ? 10 : cvss >= 7 ? 8 : 6,
                confidence: 95,
                value: `${vulnId} in ${pkg.ecosystem}/${pkg.name} \u2014 CVSS: ${cvss || "N/A"} \u2014 ${summary}`,
                vuln_id: vulnId,
                aliases: vuln.aliases || [],
                package_name: pkg.name,
                package_ecosystem: pkg.ecosystem,
                cvss_score: cvss,
                summary,
                published: vuln.published,
                modified: vuln.modified,
                affected_versions: vuln.affected?.map((a) => a.ranges)?.flat() || [],
                references: vuln.references?.map((r) => r.url)?.slice(0, 5) || [],
                osv_url: `https://osv.dev/vulnerability/${vulnId}`
              },
              attribution: { provider: "OSV.dev", url: `https://osv.dev/vulnerability/${vulnId}`, method: "api" }
            });
          }
        } catch (err) {
          if (err.message?.includes("timeout")) {
            errors.push("OSV.dev API timeout");
          } else {
            errors.push(err.message || "Unknown error during OSV.dev lookup");
          }
        }
        return {
          connector: "osv_dev",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/team-cymru.ts
import { createHash as createHash62 } from "crypto";
import { resolve as dnsResolve } from "dns";
import { promisify } from "util";
function makeAssetId62(domain, name, source) {
  return createHash62("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function dnsWithTimeout4(queryFn, timeoutMs = 5e3) {
  return Promise.race([
    queryFn(),
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("DNS query timeout")), timeoutMs)
    )
  ]);
}
async function resolveToIPs(domain) {
  const resolveA = promisify(dnsResolve);
  try {
    const ips = await dnsWithTimeout4(() => resolveA(domain, "A"), 5e3);
    return ips || [];
  } catch {
    return [];
  }
}
async function queryOriginASN(ip) {
  try {
    const reversed = ip.split(".").reverse().join(".");
    const hostname = `${reversed}.origin.asn.cymru.com`;
    const records = await dnsWithTimeout4(() => resolveTxt3(hostname, "TXT"), 5e3);
    if (records && records.length > 0) {
      const txt = records[0].join("").trim();
      const parts = txt.split("|").map((s) => s.trim());
      return {
        asn: parts[0] || "",
        cidr: parts[1] || "",
        cc: parts[2] || "",
        registry: parts[3] || "",
        allocated: parts[4] || ""
      };
    }
  } catch {
  }
  return null;
}
async function queryASNDetails(asn) {
  try {
    const asnNum = asn.replace(/^AS/i, "").trim();
    const hostname = `AS${asnNum}.asn.cymru.com`;
    const records = await dnsWithTimeout4(() => resolveTxt3(hostname, "TXT"), 5e3);
    if (records && records.length > 0) {
      const txt = records[0].join("").trim();
      const parts = txt.split("|").map((s) => s.trim());
      return {
        cc: parts[1] || "",
        registry: parts[2] || "",
        allocated: parts[3] || "",
        name: parts[4] || ""
      };
    }
  } catch {
  }
  return null;
}
var resolveTxt3, teamCymruConnector;
var init_team_cymru = __esm({
  "server/lib/passive/team-cymru.ts"() {
    "use strict";
    resolveTxt3 = promisify(dnsResolve);
    teamCymruConnector = {
      name: "team_cymru",
      description: "Team Cymru \u2014 authoritative IP-to-ASN mapping via DNS, BGP origin, network attribution",
      requiresApiKey: false,
      freeUrl: "https://www.team-cymru.com/ip-asn-mapping",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const signal = config?.signal;
        if (signal?.aborted) {
          return { connector: "team_cymru", domain, observations: [], errors: ["Aborted before start"], durationMs: 0, rateLimited: false };
        }
        try {
          const ips = await resolveToIPs(domain);
          if (ips.length === 0) {
            observations.push({
              assetId: makeAssetId62(domain, `Team Cymru: no IPs for ${domain}`, "team_cymru"),
              domain,
              assetType: "info",
              name: `Team Cymru: Could not resolve ${domain} to IP addresses`,
              source: "team_cymru",
              observedAt: now,
              tags: ["team_cymru", "asn_mapping", "dns_failure"],
              evidence: {
                severity: 0,
                status: "no_ips",
                value: `DNS resolution failed for ${domain} \u2014 cannot perform IP-to-ASN mapping`
              },
              attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com", method: "dns" }
            });
            return { connector: "team_cymru", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const seenASNs = /* @__PURE__ */ new Set();
          const asnDetails = /* @__PURE__ */ new Map();
          for (const ip of ips.slice(0, 10)) {
            if (signal?.aborted) {
              errors.push("Aborted mid-execution");
              break;
            }
            const origin = await queryOriginASN(ip);
            if (!origin) continue;
            const asnNum = origin.asn.split(" ")[0];
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
            const name = `Team Cymru: ${ip} \u2192 AS${asnNum} (${asnName})`;
            observations.push({
              assetId: makeAssetId62(domain, name, "team_cymru"),
              domain,
              assetType: "info",
              name,
              source: "team_cymru",
              observedAt: now,
              tags: [
                "team_cymru",
                "asn_mapping",
                "bgp_origin",
                "ip_attribution",
                `asn:${asnNum}`,
                `cc:${origin.cc}`,
                `registry:${origin.registry}`
              ],
              evidence: {
                severity: 1,
                confidence: 95,
                value: `${ip} \u2192 AS${asnNum} (${asnName}) | ${origin.cidr} | ${origin.cc} | ${origin.registry} | Allocated: ${origin.allocated}`,
                ip,
                asn: asnNum,
                asn_name: asnName,
                cidr: origin.cidr,
                country_code: origin.cc,
                registry: origin.registry,
                allocated: origin.allocated
              },
              attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com/ip-asn-mapping", method: "dns" }
            });
          }
          if (seenASNs.size > 0 && !signal?.aborted) {
            const asnSummary = [...seenASNs].map((asn) => {
              const details = asnDetails.get(asn);
              return `AS${asn} (${details?.name || "unknown"}, ${details?.cc || "??"})`;
            }).join("; ");
            observations.push({
              assetId: makeAssetId62(domain, `Team Cymru summary: ${domain}`, "team_cymru"),
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
                asn_list: [...seenASNs].map((asn) => ({
                  asn,
                  name: asnDetails.get(asn)?.name || "unknown",
                  cc: asnDetails.get(asn)?.cc || "unknown",
                  registry: asnDetails.get(asn)?.registry || "unknown"
                }))
              },
              attribution: { provider: "Team Cymru", url: "https://www.team-cymru.com/ip-asn-mapping", method: "dns" }
            });
          }
        } catch (err) {
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
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/cisa-advisories.ts
import { createHash as createHash63 } from "crypto";
function makeAssetId63(domain, name, source) {
  return createHash63("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
function extractVendorProducts(config) {
  const results = [];
  const priorObs = config?.priorObservations || [];
  const seen = /* @__PURE__ */ new Set();
  const techMap = {
    "apache": [{ vendor: "Apache", product: "HTTP Server" }, { vendor: "Apache", product: "Tomcat" }],
    "nginx": [{ vendor: "F5", product: "NGINX" }],
    "iis": [{ vendor: "Microsoft", product: "Internet Information Services" }],
    "microsoft": [{ vendor: "Microsoft", product: "Exchange" }, { vendor: "Microsoft", product: "Windows" }],
    "wordpress": [{ vendor: "WordPress", product: "WordPress" }],
    "drupal": [{ vendor: "Drupal", product: "Drupal" }],
    "joomla": [{ vendor: "Joomla!", product: "Joomla!" }],
    "citrix": [{ vendor: "Citrix", product: "ADC" }, { vendor: "Citrix", product: "NetScaler" }],
    "fortinet": [{ vendor: "Fortinet", product: "FortiOS" }, { vendor: "Fortinet", product: "FortiGate" }],
    "palo alto": [{ vendor: "Palo Alto Networks", product: "PAN-OS" }],
    "cisco": [{ vendor: "Cisco", product: "IOS" }, { vendor: "Cisco", product: "ASA" }],
    "vmware": [{ vendor: "VMware", product: "vCenter" }, { vendor: "VMware", product: "ESXi" }],
    "oracle": [{ vendor: "Oracle", product: "WebLogic" }],
    "sap": [{ vendor: "SAP", product: "NetWeaver" }],
    "ivanti": [{ vendor: "Ivanti", product: "Connect Secure" }],
    "sonicwall": [{ vendor: "SonicWall", product: "SMA" }],
    "zimbra": [{ vendor: "Zimbra", product: "Collaboration" }],
    "atlassian": [{ vendor: "Atlassian", product: "Confluence" }, { vendor: "Atlassian", product: "Jira" }],
    "jenkins": [{ vendor: "Jenkins", product: "Jenkins" }],
    "gitlab": [{ vendor: "GitLab", product: "GitLab" }],
    "openssl": [{ vendor: "OpenSSL", product: "OpenSSL" }],
    "log4j": [{ vendor: "Apache", product: "Log4j" }],
    "spring": [{ vendor: "VMware", product: "Spring Framework" }],
    "php": [{ vendor: "PHP Group", product: "PHP" }],
    "jquery": [{ vendor: "jQuery", product: "jQuery" }]
  };
  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs).toLowerCase();
    for (const [tech, vps] of Object.entries(techMap)) {
      if (obsStr.includes(tech.toLowerCase())) {
        for (const vp of vps) {
          const key = `${vp.vendor}|${vp.product}`;
          if (!seen.has(key)) {
            seen.add(key);
            results.push(vp);
          }
        }
      }
    }
  }
  return results;
}
function extractCVEsFromPrior(config) {
  const cves = /* @__PURE__ */ new Set();
  const priorObs = config?.priorObservations || [];
  for (const obs of priorObs) {
    const obsStr = JSON.stringify(obs);
    const matches = obsStr.match(/CVE-\d{4}-\d{4,}/g);
    if (matches) {
      for (const cve of matches) {
        cves.add(cve);
      }
    }
  }
  return [...cves];
}
var KEV_URL, cisaAdvisoriesConnector;
var init_cisa_advisories = __esm({
  "server/lib/passive/cisa-advisories.ts"() {
    "use strict";
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    cisaAdvisoriesConnector = {
      name: "cisa_advisories",
      description: "CISA Advisories \u2014 free KEV catalog & ICS advisories, exploitation status, remediation deadlines",
      requiresApiKey: false,
      freeUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const resp = await fetch(KEV_URL, {
            headers: { "User-Agent": "AceC3Platform/1.0" },
            signal: AbortSignal.timeout(2e4)
          });
          if (!resp.ok) {
            errors.push(`CISA KEV catalog fetch failed: ${resp.status}`);
            return { connector: "cisa_advisories", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const kevData = await resp.json();
          const priorCVEs = extractCVEsFromPrior(config);
          const vendorProducts = extractVendorProducts(config);
          const matchedByCV = [];
          const matchedByVendor = [];
          const kevMap = /* @__PURE__ */ new Map();
          for (const vuln of kevData.vulnerabilities) {
            kevMap.set(vuln.cveID, vuln);
          }
          for (const cve of priorCVEs) {
            const kevEntry = kevMap.get(cve);
            if (kevEntry) {
              matchedByCV.push(kevEntry);
            }
          }
          if (vendorProducts.length > 0) {
            for (const vuln of kevData.vulnerabilities) {
              const vulnVendor = (vuln.vendorProject || "").toLowerCase();
              const vulnProduct = (vuln.product || "").toLowerCase();
              for (const vp of vendorProducts) {
                if (vulnVendor.includes(vp.vendor.toLowerCase()) || vulnProduct.includes(vp.product.toLowerCase())) {
                  const addedDate = new Date(vuln.dateAdded);
                  const twoYearsAgo = /* @__PURE__ */ new Date();
                  twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
                  if (addedDate > twoYearsAgo && !matchedByCV.find((m) => m.cveID === vuln.cveID)) {
                    matchedByVendor.push(vuln);
                  }
                  break;
                }
              }
            }
          }
          const totalMatches = matchedByCV.length + matchedByVendor.length;
          observations.push({
            assetId: makeAssetId63(domain, `CISA KEV summary: ${domain}`, "cisa_advisories"),
            domain,
            assetType: totalMatches > 0 ? "vuln" : "info",
            name: totalMatches > 0 ? `CISA KEV: ${totalMatches} known exploited vuln(s) relevant to ${domain}` : `CISA KEV: No known exploited vulns matched for ${domain}`,
            source: "cisa_advisories",
            observedAt: now,
            tags: [
              "cisa",
              "kev",
              "known_exploited",
              ...matchedByCV.length > 0 ? ["confirmed_kev_match", "critical"] : [],
              ...matchedByVendor.length > 0 ? ["vendor_match"] : []
            ],
            evidence: {
              severity: matchedByCV.length > 0 ? 10 : matchedByVendor.length > 0 ? 7 : 0,
              confidence: matchedByCV.length > 0 ? 95 : matchedByVendor.length > 0 ? 60 : 0,
              value: matchedByCV.length > 0 ? `${matchedByCV.length} CONFIRMED KEV match(es) \u2014 actively exploited in the wild` : matchedByVendor.length > 0 ? `${matchedByVendor.length} vendor/product match(es) \u2014 verify version applicability` : `No KEV matches from ${priorCVEs.length} CVE(s) and ${vendorProducts.length} vendor/product(s) checked`,
              confirmed_matches: matchedByCV.length,
              vendor_matches: matchedByVendor.length,
              cves_checked: priorCVEs.length,
              vendors_checked: vendorProducts.length,
              kev_catalog_version: kevData.catalogVersion,
              kev_catalog_date: kevData.dateReleased,
              kev_total_entries: kevData.count
            },
            attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" }
          });
          for (const vuln of matchedByCV.slice(0, 10)) {
            const isPastDue = new Date(vuln.dueDate) < now;
            observations.push({
              assetId: makeAssetId63(domain, `CISA KEV: ${vuln.cveID}`, "cisa_advisories"),
              domain,
              assetType: "vuln",
              name: `CISA KEV: ${vuln.cveID} \u2014 ${vuln.vulnerabilityName || vuln.shortDescription?.slice(0, 60)}`,
              source: "cisa_advisories",
              observedAt: now,
              firstSeen: vuln.dateAdded ? new Date(vuln.dateAdded) : void 0,
              tags: [
                "cisa",
                "kev",
                "known_exploited",
                "confirmed_match",
                "critical",
                vuln.cveID,
                ...isPastDue ? ["past_due", "overdue_remediation"] : [],
                ...vuln.knownRansomwareCampaignUse === "Known" ? ["ransomware"] : []
              ],
              evidence: {
                severity: 10,
                confidence: 95,
                value: `ACTIVELY EXPLOITED: ${vuln.vulnerabilityName} \u2014 ${vuln.shortDescription}`,
                cve_id: vuln.cveID,
                vulnerability_name: vuln.vulnerabilityName,
                description: vuln.shortDescription,
                vendor: vuln.vendorProject,
                product: vuln.product,
                date_added: vuln.dateAdded,
                due_date: vuln.dueDate,
                is_past_due: isPastDue,
                required_action: vuln.requiredAction,
                known_ransomware_use: vuln.knownRansomwareCampaignUse,
                notes: vuln.notes,
                kev_url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
                nvd_url: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`
              },
              attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" }
            });
          }
          for (const vuln of matchedByVendor.slice(0, 10)) {
            const isPastDue = new Date(vuln.dueDate) < now;
            observations.push({
              assetId: makeAssetId63(domain, `CISA KEV vendor: ${vuln.cveID}`, "cisa_advisories"),
              domain,
              assetType: "vuln",
              name: `CISA KEV (vendor match): ${vuln.cveID} \u2014 ${vuln.vendorProject} ${vuln.product}`,
              source: "cisa_advisories",
              observedAt: now,
              firstSeen: vuln.dateAdded ? new Date(vuln.dateAdded) : void 0,
              tags: [
                "cisa",
                "kev",
                "known_exploited",
                "vendor_match",
                vuln.cveID,
                ...vuln.knownRansomwareCampaignUse === "Known" ? ["ransomware"] : []
              ],
              evidence: {
                severity: 7,
                confidence: 55,
                value: `Vendor match: ${vuln.vendorProject} ${vuln.product} \u2014 ${vuln.shortDescription} (verify version applicability)`,
                cve_id: vuln.cveID,
                vulnerability_name: vuln.vulnerabilityName,
                description: vuln.shortDescription,
                vendor: vuln.vendorProject,
                product: vuln.product,
                date_added: vuln.dateAdded,
                due_date: vuln.dueDate,
                is_past_due: isPastDue,
                required_action: vuln.requiredAction,
                known_ransomware_use: vuln.knownRansomwareCampaignUse,
                match_type: "vendor_product",
                verification_needed: true
              },
              attribution: { provider: "CISA", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", method: "api" }
            });
          }
        } catch (err) {
          if (err.message?.includes("timeout")) {
            errors.push("CISA KEV catalog fetch timeout");
          } else {
            errors.push(err.message || "Unknown error during CISA advisory lookup");
          }
        }
        return {
          connector: "cisa_advisories",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/rate-limiter.ts
async function rateLimitedFetch(connector, url, init, options) {
  const acquired = await osintRateLimiter.waitAndAcquire(connector, options?.maxWaitMs ?? 3e4);
  if (!acquired) {
    throw new Error(`Rate limit exceeded for ${connector} \u2014 could not acquire token within timeout`);
  }
  const resp = await fetch(url, init);
  if (resp.status === 429) {
    osintRateLimiter.report429(connector);
    throw new Error(`429 Too Many Requests from ${connector} \u2014 backoff activated`);
  }
  return resp;
}
var CONNECTOR_RATE_LIMITS, GLOBAL_RATE_LIMIT, TokenBucket, OsintRateLimiter, osintRateLimiter;
var init_rate_limiter = __esm({
  "server/lib/passive/rate-limiter.ts"() {
    "use strict";
    CONNECTOR_RATE_LIMITS = {
      // === Free APIs (conservative limits) ===
      urlhaus: { maxRequests: 10, windowMs: 6e4 },
      // abuse.ch: undocumented, be conservative
      malwarebazaar: { maxRequests: 10, windowMs: 6e4 },
      // abuse.ch: undocumented, be conservative
      threatfox: { maxRequests: 10, windowMs: 6e4 },
      // abuse.ch: undocumented, be conservative
      cisa_advisories: { maxRequests: 5, windowMs: 6e4 },
      // Static JSON, rarely changes — cache-friendly
      osv_dev: { maxRequests: 20, windowMs: 6e4 },
      // Google-backed, generous but undocumented
      team_cymru: { maxRequests: 30, windowMs: 6e4 },
      // DNS-based, generous but respect fair use
      sec_edgar: { maxRequests: 10, windowMs: 6e4 },
      // SEC: 10 req/sec documented, we go slower
      crtsh: { maxRequests: 5, windowMs: 6e4 },
      // crt.sh: shared resource, be gentle
      phishtank: { maxRequests: 10, windowMs: 6e4 },
      // PhishTank: undocumented
      alienvault_otx: { maxRequests: 20, windowMs: 6e4 },
      // OTX: documented 10k/day ≈ 7/min
      ransomware_live: { maxRequests: 5, windowMs: 6e4 },
      // Small project, be gentle
      hackertarget: { maxRequests: 5, windowMs: 6e4 },
      // Free tier: 100/day
      rapiddns: { maxRequests: 5, windowMs: 6e4 },
      // Web scraping, be gentle
      bgpview: { maxRequests: 10, windowMs: 6e4 },
      // Undocumented
      ip_api: { maxRequests: 45, windowMs: 6e4 },
      // Documented: 45/min
      anubis: { maxRequests: 10, windowMs: 6e4 },
      // Undocumented
      dnsrepo: { maxRequests: 5, windowMs: 6e4 },
      // Undocumented
      sitedossier: { maxRequests: 5, windowMs: 6e4 },
      // Web scraping, be gentle
      commoncrawl: { maxRequests: 5, windowMs: 6e4 },
      // Shared resource
      threatminer: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 10/min
      circl_pdns: { maxRequests: 10, windowMs: 6e4 },
      // Undocumented
      // === API Key Required (respect documented limits) ===
      shodan: { maxRequests: 1, windowMs: 1e3 },
      // Documented: 1 req/sec
      shodan_internetdb: { maxRequests: 30, windowMs: 6e4 },
      // Free, no auth, generous
      censys: { maxRequests: 5, windowMs: 6e4 },
      // Documented: 120/5min = 24/min, we go slower
      virustotal: { maxRequests: 4, windowMs: 6e4 },
      // Free: 4/min, Premium: 500/min
      securitytrails: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 50/day free
      urlscan: { maxRequests: 5, windowMs: 6e4 },
      // Documented: varies by plan
      abuseipdb: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 1000/day ≈ 0.7/min
      greynoise: { maxRequests: 10, windowMs: 6e4 },
      // Community: 500/day
      dehashed: { maxRequests: 5, windowMs: 6e4 },
      // Commercial API
      dehashed_whois: { maxRequests: 5, windowMs: 6e4 },
      // Commercial API
      hunter: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 500/month free
      whoisxml: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 500/month free
      passivetotal: { maxRequests: 10, windowMs: 6e4 },
      // Commercial API
      fullhunt: { maxRequests: 5, windowMs: 6e4 },
      // Free tier limited
      netlas: { maxRequests: 5, windowMs: 6e4 },
      // Free tier limited
      intelx_search: { maxRequests: 3, windowMs: 6e4 },
      // Free: 3/day
      leakix: { maxRequests: 5, windowMs: 6e4 },
      // Free tier limited
      coalition_control: { maxRequests: 10, windowMs: 6e4 },
      // Commercial API
      google_safebrowsing: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 10k/day
      // === DNS-based (no API, but respect DNS infrastructure) ===
      dns_deep: { maxRequests: 30, windowMs: 6e4 },
      // Direct DNS queries
      email_security: { maxRequests: 20, windowMs: 6e4 },
      // Direct DNS queries
      dns_zone_transfer: { maxRequests: 5, windowMs: 6e4 },
      // AXFR — be very conservative
      domain_health: { maxRequests: 10, windowMs: 6e4 },
      // DNSBL lookups
      // === Web scraping (conservative) ===
      builtwith: { maxRequests: 3, windowMs: 6e4 },
      // Web scraping
      github_leaks: { maxRequests: 10, windowMs: 6e4 },
      // GitHub API: 30/min unauthenticated
      github_recon: { maxRequests: 10, windowMs: 6e4 },
      // GitHub API
      social_media: { maxRequests: 5, windowMs: 6e4 },
      // Web scraping
      company_intel: { maxRequests: 3, windowMs: 6e4 },
      // Web scraping + LLM
      wayback: { maxRequests: 5, windowMs: 6e4 },
      // Wayback CDX API
      wayback_diff: { maxRequests: 3, windowMs: 6e4 },
      // Wayback content fetch
      http_security: { maxRequests: 10, windowMs: 6e4 },
      // Direct HTTP requests
      reverse_whois: { maxRequests: 5, windowMs: 6e4 },
      // crt.sh based
      favicon_hash: { maxRequests: 5, windowMs: 6e4 },
      // HTTP + Shodan
      jarm_fingerprint: { maxRequests: 5, windowMs: 6e4 },
      // Direct TLS probing
      typosquat: { maxRequests: 10, windowMs: 6e4 },
      // DNS resolution
      cloud_assets: { maxRequests: 10, windowMs: 6e4 },
      // DNS/HTTP probing
      cloud_bucket_recon: { maxRequests: 5, windowMs: 6e4 },
      // HTTP probing
      container_discovery: { maxRequests: 5, windowMs: 6e4 },
      // HTTP probing
      // === Credential sources ===
      hibp: { maxRequests: 10, windowMs: 6e4 },
      // Documented: 10/min
      hudson_rock: { maxRequests: 5, windowMs: 6e4 },
      // Free API
      leakcheck: { maxRequests: 5, windowMs: 6e4 },
      // Commercial API
      darkweb_crossref: { maxRequests: 20, windowMs: 6e4 }
      // Local DB, generous
    };
    GLOBAL_RATE_LIMIT = {
      maxRequests: 100,
      windowMs: 6e4,
      burstAllowance: 20
    };
    TokenBucket = class {
      constructor(config) {
        this.config = config;
        this.state = {
          tokens: config.maxRequests + (config.burstAllowance ?? Math.floor(config.maxRequests * 0.2)),
          lastRefill: Date.now(),
          backoffUntil: 0,
          backoffLevel: 0,
          totalRequests: 0,
          totalThrottled: 0,
          total429s: 0
        };
      }
      refill() {
        const now = Date.now();
        const elapsed = now - this.state.lastRefill;
        const maxTokens = this.config.maxRequests + (this.config.burstAllowance ?? Math.floor(this.config.maxRequests * 0.2));
        const tokensToAdd = Math.floor(elapsed / this.config.windowMs * this.config.maxRequests);
        if (tokensToAdd > 0) {
          this.state.tokens = Math.min(maxTokens, this.state.tokens + tokensToAdd);
          this.state.lastRefill = now;
        }
      }
      /**
       * Try to consume a token. Returns true if allowed, false if throttled.
       */
      tryConsume() {
        const now = Date.now();
        if (now < this.state.backoffUntil) {
          this.state.totalThrottled++;
          return false;
        }
        this.refill();
        if (this.state.tokens >= 1) {
          this.state.tokens -= 1;
          this.state.totalRequests++;
          if (this.state.backoffLevel > 0) {
            this.state.backoffLevel = Math.max(0, this.state.backoffLevel - 1);
          }
          return true;
        }
        this.state.totalThrottled++;
        return false;
      }
      /**
       * Report a 429 response to trigger exponential backoff
       */
      report429() {
        this.state.total429s++;
        this.state.backoffLevel++;
        const multiplier = this.config.backoffMultiplier ?? 2;
        const maxBackoff = this.config.maxBackoffMs ?? 6e4;
        const backoffMs = Math.min(maxBackoff, 1e3 * Math.pow(multiplier, this.state.backoffLevel));
        this.state.backoffUntil = Date.now() + backoffMs;
      }
      /**
       * Get time until next available token (ms), 0 if available now
       */
      getWaitTime() {
        const now = Date.now();
        if (now < this.state.backoffUntil) {
          return this.state.backoffUntil - now;
        }
        this.refill();
        if (this.state.tokens >= 1) return 0;
        return Math.ceil(this.config.windowMs / this.config.maxRequests);
      }
      getStats() {
        this.refill();
        return {
          totalRequests: this.state.totalRequests,
          totalThrottled: this.state.totalThrottled,
          total429s: this.state.total429s,
          tokensRemaining: Math.floor(this.state.tokens),
          backoffLevel: this.state.backoffLevel
        };
      }
    };
    OsintRateLimiter = class {
      constructor() {
        this.buckets = /* @__PURE__ */ new Map();
        this.globalBucket = new TokenBucket(GLOBAL_RATE_LIMIT);
      }
      getBucket(connector) {
        if (!this.buckets.has(connector)) {
          const config = CONNECTOR_RATE_LIMITS[connector] || { maxRequests: 10, windowMs: 6e4 };
          this.buckets.set(connector, new TokenBucket(config));
        }
        return this.buckets.get(connector);
      }
      /**
       * Check if a request is allowed for the given connector.
       * Checks both per-connector and global limits.
       */
      tryAcquire(connector) {
        const bucket = this.getBucket(connector);
        if (!bucket.tryConsume()) return false;
        if (!this.globalBucket.tryConsume()) return false;
        return true;
      }
      /**
       * Wait until a request is allowed, then return.
       * Use this for queue-based scheduling.
       */
      async waitAndAcquire(connector, maxWaitMs = 3e4) {
        const deadline = Date.now() + maxWaitMs;
        while (Date.now() < deadline) {
          if (this.tryAcquire(connector)) return true;
          const bucket = this.getBucket(connector);
          const waitTime = Math.min(bucket.getWaitTime(), this.globalBucket.getWaitTime(), 1e3);
          await new Promise((resolve) => setTimeout(resolve, Math.max(100, waitTime)));
        }
        return false;
      }
      /**
       * Report a 429 response for a connector
       */
      report429(connector) {
        this.getBucket(connector).report429();
      }
      /**
       * Get rate limit status for all active connectors
       */
      getStatus() {
        const status = {};
        status["__global__"] = this.globalBucket.getStats();
        for (const [name, bucket] of this.buckets) {
          status[name] = bucket.getStats();
        }
        return status;
      }
      /**
       * Get rate limit status for a specific connector
       */
      getConnectorStatus(connector) {
        const bucket = this.buckets.get(connector);
        return bucket?.getStats() ?? null;
      }
      /**
       * Reset all rate limit state (useful for testing)
       */
      reset() {
        this.buckets.clear();
        this.globalBucket = new TokenBucket(GLOBAL_RATE_LIMIT);
      }
    };
    osintRateLimiter = new OsintRateLimiter();
  }
});

// server/lib/passive/feodo-tracker.ts
import { createHash as createHash64 } from "crypto";
function makeAssetId64(domain, name, source) {
  return createHash64("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var RECENT_C2_URL, feodoTrackerConnector;
var init_feodo_tracker = __esm({
  "server/lib/passive/feodo-tracker.ts"() {
    "use strict";
    init_rate_limiter();
    RECENT_C2_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";
    feodoTrackerConnector = {
      name: "feodo_tracker",
      description: "Feodo Tracker (abuse.ch) \u2014 botnet C2 infrastructure tracking (Dridex, Emotet, TrickBot, QakBot)",
      requiresApiKey: false,
      freeUrl: "https://feodotracker.abuse.ch",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const dnsRes = await rateLimitedFetch("feodo_tracker", `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
            signal: AbortSignal.timeout(8e3)
          });
          const dnsData = await dnsRes.json();
          const domainIps = /* @__PURE__ */ new Set();
          if (dnsData?.Answer) {
            for (const ans of dnsData.Answer) {
              if (ans.type === 1 && ans.data) domainIps.add(ans.data);
            }
          }
          const resp = await rateLimitedFetch("feodo_tracker", RECENT_C2_URL, {
            signal: AbortSignal.timeout(15e3)
          });
          if (!resp.ok) {
            errors.push(`Feodo Tracker returned ${resp.status}`);
            return { connector: "feodo_tracker", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const c2List = await resp.json();
          if (!Array.isArray(c2List)) {
            errors.push("Unexpected Feodo Tracker response format");
            return { connector: "feodo_tracker", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const matches = [];
          for (const entry of c2List) {
            if (domainIps.has(entry.ip_address)) {
              matches.push(entry);
            }
          }
          for (const entry of c2List) {
            if (entry.hostname && (entry.hostname === domain || entry.hostname.endsWith(`.${domain}`))) {
              if (!matches.find((m) => m.ip_address === entry.ip_address)) {
                matches.push(entry);
              }
            }
          }
          for (const match of matches.slice(0, 20)) {
            const malwareFamily = match.malware || "unknown";
            const name = `Feodo C2: ${match.ip_address} (${malwareFamily})`;
            observations.push({
              assetId: makeAssetId64(domain, name, "feodo_tracker"),
              domain,
              assetType: "breach",
              name,
              source: "feodo_tracker",
              observedAt: now,
              firstSeen: match.first_seen ? new Date(match.first_seen) : void 0,
              lastSeen: match.last_seen ? new Date(match.last_seen) : void 0,
              tags: ["feodo_tracker", "c2", "botnet", malwareFamily.toLowerCase(), "abuse_ch"],
              evidence: {
                severity: 10,
                // C2 infrastructure is always critical
                confidence: 95,
                value: `Active botnet C2 infrastructure detected \u2014 ${malwareFamily} at ${match.ip_address}:${match.port || "unknown"}`,
                ip_address: match.ip_address,
                port: match.port,
                malware: malwareFamily,
                status: match.status || "unknown",
                as_number: match.as_number,
                as_name: match.as_name,
                country: match.country,
                first_seen: match.first_seen,
                last_seen: match.last_seen
              },
              attribution: {
                provider: "Feodo Tracker (abuse.ch)",
                url: "https://feodotracker.abuse.ch/",
                method: "blocklist"
              }
            });
          }
          if (matches.length === 0 && domainIps.size > 0) {
            const domainSubnets = /* @__PURE__ */ new Set();
            for (const ip of domainIps) {
              domainSubnets.add(ip.split(".").slice(0, 3).join("."));
            }
            let nearbyC2Count = 0;
            for (const entry of c2List) {
              const subnet = entry.ip_address?.split(".")?.slice(0, 3)?.join(".");
              if (subnet && domainSubnets.has(subnet)) nearbyC2Count++;
            }
            if (nearbyC2Count > 0) {
              const name = `Feodo Proximity: ${nearbyC2Count} C2 IPs in same /24 subnet`;
              observations.push({
                assetId: makeAssetId64(domain, name, "feodo_tracker"),
                domain,
                assetType: "network",
                name,
                source: "feodo_tracker",
                observedAt: now,
                tags: ["feodo_tracker", "c2_proximity", "network_risk", "abuse_ch"],
                evidence: {
                  severity: 4,
                  confidence: 60,
                  value: `${nearbyC2Count} known botnet C2 IPs found in the same /24 subnet as ${domain} \u2014 potential neighborhood risk`,
                  nearby_c2_count: nearbyC2Count,
                  domain_ips: Array.from(domainIps)
                },
                attribution: {
                  provider: "Feodo Tracker (abuse.ch)",
                  url: "https://feodotracker.abuse.ch/",
                  method: "blocklist"
                }
              });
            }
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during Feodo Tracker lookup");
        }
        return {
          connector: "feodo_tracker",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/sslbl.ts
import { createHash as createHash65 } from "crypto";
function makeAssetId65(domain, name, source) {
  return createHash65("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var SSLBL_RECENT_URL, sslblConnector;
var init_sslbl = __esm({
  "server/lib/passive/sslbl.ts"() {
    "use strict";
    init_rate_limiter();
    SSLBL_RECENT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json";
    sslblConnector = {
      name: "sslbl",
      description: "SSLBL (abuse.ch) \u2014 SSL certificate blacklist for botnet C2 and malware distribution",
      requiresApiKey: false,
      freeUrl: "https://sslbl.abuse.ch",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const dnsRes = await rateLimitedFetch("sslbl", `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
            signal: AbortSignal.timeout(8e3)
          });
          const dnsData = await dnsRes.json();
          const domainIps = /* @__PURE__ */ new Set();
          if (dnsData?.Answer) {
            for (const ans of dnsData.Answer) {
              if (ans.type === 1 && ans.data) domainIps.add(ans.data);
            }
          }
          const resp = await rateLimitedFetch("sslbl", SSLBL_RECENT_URL, {
            signal: AbortSignal.timeout(15e3)
          });
          if (!resp.ok) {
            errors.push(`SSLBL returned ${resp.status}`);
            return { connector: "sslbl", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const text = await resp.text();
          let sslData;
          try {
            sslData = JSON.parse(text);
          } catch {
            const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
            sslData = lines.map((line) => {
              const parts = line.split(",");
              return {
                listing_date: parts[0]?.trim(),
                sha1: parts[1]?.trim(),
                listing_reason: parts[2]?.trim()
              };
            });
          }
          if (!Array.isArray(sslData)) {
            errors.push("Unexpected SSLBL response format");
            return { connector: "sslbl", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const matches = [];
          for (const entry of sslData) {
            if (entry.dst_ip && domainIps.has(entry.dst_ip)) {
              matches.push(entry);
            }
            if (entry.subject_cn && (entry.subject_cn === domain || entry.subject_cn === `*.${domain}` || entry.subject_cn.endsWith(`.${domain}`))) {
              if (!matches.find((m) => m.sha1 === entry.sha1)) {
                matches.push(entry);
              }
            }
          }
          for (const match of matches.slice(0, 15)) {
            const reason = match.listing_reason || match.malware || "unknown";
            const name = `SSLBL: Blacklisted cert ${match.sha1?.slice(0, 12) || "unknown"} (${reason})`;
            observations.push({
              assetId: makeAssetId65(domain, name, "sslbl"),
              domain,
              assetType: "certificate",
              name,
              source: "sslbl",
              observedAt: now,
              firstSeen: match.listing_date ? new Date(match.listing_date) : void 0,
              tags: ["sslbl", "ssl_blacklist", "malicious_cert", reason.toLowerCase().replace(/\s+/g, "_"), "abuse_ch"],
              evidence: {
                severity: 9,
                confidence: 90,
                value: `SSL certificate blacklisted for ${reason} \u2014 SHA1: ${match.sha1 || "unknown"}`,
                sha1: match.sha1,
                subject_cn: match.subject_cn,
                issuer_cn: match.issuer_cn,
                serial_number: match.serial_number,
                listing_reason: reason,
                listing_date: match.listing_date,
                dst_ip: match.dst_ip,
                dst_port: match.dst_port
              },
              attribution: {
                provider: "SSLBL (abuse.ch)",
                url: "https://sslbl.abuse.ch/",
                method: "blacklist"
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during SSLBL lookup");
        }
        return {
          connector: "sslbl",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/github-advisories.ts
import { createHash as createHash66 } from "crypto";
function makeAssetId66(domain, name, source) {
  return createHash66("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var GHSA_API, TECH_TO_ECOSYSTEM, githubAdvisoriesConnector;
var init_github_advisories = __esm({
  "server/lib/passive/github-advisories.ts"() {
    "use strict";
    init_rate_limiter();
    GHSA_API = "https://api.github.com/advisories";
    TECH_TO_ECOSYSTEM = {
      "wordpress": { ecosystem: "composer", packages: ["wordpress/wordpress"] },
      "drupal": { ecosystem: "composer", packages: ["drupal/core", "drupal/drupal"] },
      "laravel": { ecosystem: "composer", packages: ["laravel/framework"] },
      "django": { ecosystem: "pip", packages: ["django"] },
      "flask": { ecosystem: "pip", packages: ["flask"] },
      "express": { ecosystem: "npm", packages: ["express"] },
      "next.js": { ecosystem: "npm", packages: ["next"] },
      "react": { ecosystem: "npm", packages: ["react", "react-dom"] },
      "angular": { ecosystem: "npm", packages: ["@angular/core"] },
      "vue": { ecosystem: "npm", packages: ["vue"] },
      "jquery": { ecosystem: "npm", packages: ["jquery"] },
      "apache": { ecosystem: "maven", packages: ["org.apache.httpd:httpd"] },
      "nginx": { ecosystem: "other", packages: ["nginx"] },
      "openssl": { ecosystem: "other", packages: ["openssl"] },
      "php": { ecosystem: "composer", packages: ["php"] },
      "ruby on rails": { ecosystem: "rubygems", packages: ["rails", "actionpack"] },
      "spring": { ecosystem: "maven", packages: ["org.springframework:spring-core"] },
      "tomcat": { ecosystem: "maven", packages: ["org.apache.tomcat:tomcat"] }
    };
    githubAdvisoriesConnector = {
      name: "github_advisories",
      description: "GitHub Security Advisories (GHSA) \u2014 vulnerability database for open-source packages",
      requiresApiKey: false,
      freeUrl: "https://github.com/advisories",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const headers = {
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AC3-SecurityScanner/1.0"
          };
          const ghToken = config?.env?.GITHUB_PAT || config?.env?.GITHUB_CLASSIC_TOKEN;
          if (ghToken) {
            headers.Authorization = `Bearer ${ghToken}`;
          }
          const detectedTechs = [];
          if (config?.context?.technologies) {
            for (const tech of config.context.technologies) {
              const normalized = tech.toLowerCase();
              for (const [key] of Object.entries(TECH_TO_ECOSYSTEM)) {
                if (normalized.includes(key)) {
                  detectedTechs.push(key);
                }
              }
            }
          }
          const searchTerms = detectedTechs.length > 0 ? detectedTechs : [domain.split(".")[0]];
          const seenGhsaIds = /* @__PURE__ */ new Set();
          for (const term of searchTerms.slice(0, 5)) {
            try {
              const techMapping = TECH_TO_ECOSYSTEM[term];
              let url;
              if (techMapping) {
                const pkg = techMapping.packages[0];
                url = `${GHSA_API}?affects=${encodeURIComponent(pkg)}&severity=critical,high&per_page=10&sort=updated&direction=desc`;
              } else {
                url = `${GHSA_API}?type=reviewed&severity=critical,high&per_page=10&sort=updated&direction=desc`;
              }
              const resp = await rateLimitedFetch("github_advisories", url, {
                headers,
                signal: AbortSignal.timeout(12e3)
              });
              if (resp.status === 403 || resp.status === 429) {
                rateLimited = true;
                errors.push(`GitHub API rate limited (${resp.status})`);
                break;
              }
              if (!resp.ok) continue;
              const advisories = await resp.json();
              if (!Array.isArray(advisories)) continue;
              for (const adv of advisories) {
                if (seenGhsaIds.has(adv.ghsa_id)) continue;
                seenGhsaIds.add(adv.ghsa_id);
                const cveId = adv.cve_id || null;
                const severity = adv.severity || "unknown";
                const severityScore = severity === "critical" ? 10 : severity === "high" ? 8 : severity === "medium" ? 5 : 3;
                const affectedPackages = (adv.vulnerabilities || []).map((v) => `${v.package?.ecosystem}/${v.package?.name}@${v.vulnerable_version_range || "?"}`).slice(0, 5);
                const name = `GHSA: ${adv.ghsa_id} \u2014 ${(adv.summary || "").slice(0, 80)}`;
                observations.push({
                  assetId: makeAssetId66(domain, adv.ghsa_id, "github_advisories"),
                  domain,
                  assetType: "vulnerability",
                  name,
                  source: "github_advisories",
                  observedAt: now,
                  firstSeen: adv.published_at ? new Date(adv.published_at) : void 0,
                  lastSeen: adv.updated_at ? new Date(adv.updated_at) : void 0,
                  tags: ["github_advisories", "ghsa", severity, ...cveId ? [cveId] : [], term],
                  evidence: {
                    severity: severityScore,
                    confidence: techMapping ? 75 : 40,
                    // Higher confidence if tech was detected
                    value: `${severity.toUpperCase()} \u2014 ${adv.summary || "No summary"}`,
                    ghsa_id: adv.ghsa_id,
                    cve_id: cveId,
                    severity_level: severity,
                    cvss_score: adv.cvss?.score,
                    cvss_vector: adv.cvss?.vector_string,
                    summary: adv.summary,
                    description: (adv.description || "").slice(0, 500),
                    affected_packages: affectedPackages,
                    published_at: adv.published_at,
                    updated_at: adv.updated_at,
                    withdrawn_at: adv.withdrawn_at,
                    html_url: adv.html_url,
                    detected_technology: term,
                    cwes: (adv.cwes || []).map((c) => c.cwe_id)
                  },
                  attribution: {
                    provider: "GitHub Advisory Database",
                    url: "https://github.com/advisories",
                    method: "api"
                  }
                });
              }
            } catch (err) {
              if (err.message?.includes("Rate limit")) rateLimited = true;
              errors.push(`GHSA lookup for "${term}": ${err.message}`);
            }
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during GitHub Advisories lookup");
        }
        return {
          connector: "github_advisories",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/certspotter.ts
import { createHash as createHash67 } from "crypto";
function makeAssetId67(domain, name, source) {
  return createHash67("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var CERTSPOTTER_API, certspotterConnector;
var init_certspotter = __esm({
  "server/lib/passive/certspotter.ts"() {
    "use strict";
    init_rate_limiter();
    CERTSPOTTER_API = "https://api.certspotter.com/v1/issuances";
    certspotterConnector = {
      name: "certspotter",
      description: "Certspotter (SSLMate) \u2014 Certificate Transparency log monitoring for subdomain discovery and cert anomalies",
      requiresApiKey: false,
      freeUrl: "https://sslmate.com/certspotter/",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const params = new URLSearchParams({
            domain,
            include_subdomains: "true",
            expand: "dns_names,issuer",
            match_wildcards: "true"
          });
          const resp = await rateLimitedFetch("certspotter", `${CERTSPOTTER_API}?${params}`, {
            headers: {
              "User-Agent": "AC3-SecurityScanner/1.0"
            },
            signal: AbortSignal.timeout(15e3)
          });
          if (resp.status === 429) {
            rateLimited = true;
            errors.push("Certspotter rate limited \u2014 free tier allows 100 queries/hour");
            return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          if (!resp.ok) {
            errors.push(`Certspotter returned ${resp.status}`);
            return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const issuances = await resp.json();
          if (!Array.isArray(issuances)) {
            errors.push("Unexpected Certspotter response format");
            return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const discoveredSubdomains = /* @__PURE__ */ new Set();
          const issuerStats = {};
          const wildcardCerts = [];
          let recentIssuances = 0;
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3);
          for (const cert of issuances) {
            const dnsNames = cert.dns_names || [];
            const issuerOrg = cert.issuer?.organization || cert.issuer?.common_name || "unknown";
            issuerStats[issuerOrg] = (issuerStats[issuerOrg] || 0) + 1;
            const notBefore = cert.not_before ? new Date(cert.not_before) : null;
            if (notBefore && notBefore > thirtyDaysAgo) recentIssuances++;
            for (const name of dnsNames) {
              if (name.startsWith("*.")) {
                wildcardCerts.push({ name, issuer: issuerOrg, notBefore: cert.not_before });
              }
              if (name.endsWith(`.${domain}`) || name === domain) {
                discoveredSubdomains.add(name.replace(/^\*\./, ""));
              }
            }
          }
          if (discoveredSubdomains.size > 0) {
            const subdomainList = Array.from(discoveredSubdomains).sort();
            const name = `CT Log Subdomains: ${discoveredSubdomains.size} discovered for ${domain}`;
            observations.push({
              assetId: makeAssetId67(domain, name, "certspotter"),
              domain,
              assetType: "subdomain",
              name,
              source: "certspotter",
              observedAt: now,
              tags: ["certspotter", "ct_logs", "subdomain_discovery", "certificate_transparency"],
              evidence: {
                severity: 3,
                confidence: 95,
                value: `${discoveredSubdomains.size} unique subdomains found in Certificate Transparency logs`,
                subdomain_count: discoveredSubdomains.size,
                subdomains: subdomainList.slice(0, 50),
                total_certificates: issuances.length
              },
              attribution: {
                provider: "Certspotter (SSLMate)",
                url: "https://sslmate.com/certspotter/",
                method: "api"
              }
            });
          }
          if (wildcardCerts.length > 0) {
            const name = `Wildcard Certs: ${wildcardCerts.length} wildcard certificates for ${domain}`;
            observations.push({
              assetId: makeAssetId67(domain, name, "certspotter"),
              domain,
              assetType: "certificate",
              name,
              source: "certspotter",
              observedAt: now,
              tags: ["certspotter", "wildcard_cert", "certificate_transparency"],
              evidence: {
                severity: 4,
                confidence: 90,
                value: `${wildcardCerts.length} wildcard certificates detected \u2014 potential for subdomain takeover or misuse`,
                wildcard_count: wildcardCerts.length,
                wildcards: wildcardCerts.slice(0, 10).map((w) => ({
                  name: w.name,
                  issuer: w.issuer,
                  issued: w.notBefore
                }))
              },
              attribution: {
                provider: "Certspotter (SSLMate)",
                url: "https://sslmate.com/certspotter/",
                method: "api"
              }
            });
          }
          if (recentIssuances > 5) {
            const name = `High Cert Velocity: ${recentIssuances} certs issued in last 30 days`;
            observations.push({
              assetId: makeAssetId67(domain, name, "certspotter"),
              domain,
              assetType: "certificate",
              name,
              source: "certspotter",
              observedAt: now,
              tags: ["certspotter", "cert_velocity", "anomaly", "certificate_transparency"],
              evidence: {
                severity: recentIssuances > 20 ? 7 : 5,
                confidence: 70,
                value: `${recentIssuances} certificates issued in the last 30 days \u2014 unusually high issuance rate may indicate automated provisioning or abuse`,
                recent_issuances: recentIssuances,
                total_issuances: issuances.length
              },
              attribution: {
                provider: "Certspotter (SSLMate)",
                url: "https://sslmate.com/certspotter/",
                method: "api"
              }
            });
          }
          const issuerCount = Object.keys(issuerStats).length;
          if (issuerCount > 3) {
            const name = `Multi-CA: ${issuerCount} different certificate authorities for ${domain}`;
            const sortedIssuers = Object.entries(issuerStats).sort(([, a], [, b]) => b - a).slice(0, 10);
            observations.push({
              assetId: makeAssetId67(domain, name, "certspotter"),
              domain,
              assetType: "certificate",
              name,
              source: "certspotter",
              observedAt: now,
              tags: ["certspotter", "multi_ca", "certificate_transparency"],
              evidence: {
                severity: 3,
                confidence: 80,
                value: `${issuerCount} different CAs have issued certificates for ${domain} \u2014 may indicate decentralized PKI management`,
                issuer_count: issuerCount,
                issuers: sortedIssuers.map(([issuer, count]) => ({ issuer, count }))
              },
              attribution: {
                provider: "Certspotter (SSLMate)",
                url: "https://sslmate.com/certspotter/",
                method: "api"
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during Certspotter lookup");
        }
        return {
          connector: "certspotter",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/companies-house.ts
import { createHash as createHash68 } from "crypto";
function makeAssetId68(domain, name, source) {
  return createHash68("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var CH_API, companiesHouseConnector;
var init_companies_house = __esm({
  "server/lib/passive/companies-house.ts"() {
    "use strict";
    init_rate_limiter();
    CH_API = "https://api.company-information.service.gov.uk";
    companiesHouseConnector = {
      name: "companies_house",
      description: "Companies House (UK) \u2014 corporate registry for BIA context (officers, filings, company status)",
      requiresApiKey: true,
      freeUrl: "https://find-and-update.company-information.service.gov.uk/",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        const apiKey = config?.env?.COMPANIES_HOUSE_API_KEY;
        if (!apiKey) {
          return {
            connector: "companies_house",
            domain,
            observations,
            errors: ["No COMPANIES_HOUSE_API_KEY configured \u2014 skipping"],
            durationMs: Date.now() - start,
            rateLimited: false
          };
        }
        try {
          const companySearch = domain.replace(/\.(com|co\.uk|org|net|io|uk|ltd|plc)$/i, "").replace(/[.-]/g, " ");
          const searchResp = await rateLimitedFetch("companies_house", `${CH_API}/search/companies?q=${encodeURIComponent(companySearch)}&items_per_page=5`, {
            headers: {
              Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`
            },
            signal: AbortSignal.timeout(12e3)
          });
          if (searchResp.status === 429) {
            rateLimited = true;
            errors.push("Companies House rate limited");
            return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          if (!searchResp.ok) {
            errors.push(`Companies House search returned ${searchResp.status}`);
            return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const searchData = await searchResp.json();
          const companies = searchData?.items || [];
          if (companies.length === 0) {
            return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const company = companies[0];
          const companyNumber = company.company_number;
          let profile = null;
          try {
            const profileResp = await rateLimitedFetch("companies_house", `${CH_API}/company/${companyNumber}`, {
              headers: {
                Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`
              },
              signal: AbortSignal.timeout(1e4)
            });
            if (profileResp.ok) profile = await profileResp.json();
          } catch (e) {
            errors.push(`Profile fetch: ${e.message}`);
          }
          let officers = [];
          try {
            const officersResp = await rateLimitedFetch("companies_house", `${CH_API}/company/${companyNumber}/officers?items_per_page=10`, {
              headers: {
                Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`
              },
              signal: AbortSignal.timeout(1e4)
            });
            if (officersResp.ok) {
              const data = await officersResp.json();
              officers = data?.items || [];
            }
          } catch (e) {
            errors.push(`Officers fetch: ${e.message}`);
          }
          if (profile) {
            const name = `Companies House: ${profile.company_name || company.title}`;
            const isActive = profile.company_status === "active";
            observations.push({
              assetId: makeAssetId68(domain, name, "companies_house"),
              domain,
              assetType: "organization",
              name,
              source: "companies_house",
              observedAt: now,
              firstSeen: profile.date_of_creation ? new Date(profile.date_of_creation) : void 0,
              tags: ["companies_house", "uk_registry", "corporate_intel", isActive ? "active" : "inactive"],
              evidence: {
                severity: isActive ? 1 : 5,
                confidence: 85,
                value: `${profile.company_name} \u2014 ${profile.company_status} (${profile.type || "unknown type"})`,
                company_name: profile.company_name,
                company_number: companyNumber,
                company_status: profile.company_status,
                company_type: profile.type,
                date_of_creation: profile.date_of_creation,
                jurisdiction: profile.jurisdiction,
                registered_office: profile.registered_office_address ? {
                  address_line_1: profile.registered_office_address.address_line_1,
                  locality: profile.registered_office_address.locality,
                  postal_code: profile.registered_office_address.postal_code,
                  country: profile.registered_office_address.country
                } : null,
                sic_codes: profile.sic_codes,
                has_charges: profile.has_charges,
                has_insolvency_history: profile.has_insolvency_history,
                accounts_overdue: profile.accounts?.overdue,
                last_accounts_date: profile.accounts?.last_accounts?.made_up_to,
                confirmation_statement_overdue: profile.confirmation_statement?.overdue
              },
              attribution: {
                provider: "Companies House (UK)",
                url: "https://find-and-update.company-information.service.gov.uk/",
                method: "api"
              }
            });
          }
          if (officers.length > 0) {
            const activeOfficers = officers.filter((o) => !o.resigned_on);
            const name = `CH Officers: ${activeOfficers.length} active directors for ${company.title || domain}`;
            observations.push({
              assetId: makeAssetId68(domain, name, "companies_house"),
              domain,
              assetType: "organization",
              name,
              source: "companies_house",
              observedAt: now,
              tags: ["companies_house", "officers", "corporate_intel"],
              evidence: {
                severity: 2,
                confidence: 90,
                value: `${activeOfficers.length} active officers, ${officers.length - activeOfficers.length} resigned`,
                active_officers: activeOfficers.slice(0, 10).map((o) => ({
                  name: o.name,
                  role: o.officer_role,
                  appointed_on: o.appointed_on,
                  nationality: o.nationality,
                  country_of_residence: o.country_of_residence
                })),
                total_officers: officers.length,
                active_count: activeOfficers.length
              },
              attribution: {
                provider: "Companies House (UK)",
                url: "https://find-and-update.company-information.service.gov.uk/",
                method: "api"
              }
            });
          }
          if (profile?.has_insolvency_history || profile?.accounts?.overdue || profile?.confirmation_statement?.overdue) {
            const risks = [];
            if (profile.has_insolvency_history) risks.push("insolvency history");
            if (profile.accounts?.overdue) risks.push("accounts overdue");
            if (profile.confirmation_statement?.overdue) risks.push("confirmation statement overdue");
            const name = `CH Risk: ${risks.join(", ")} for ${company.title || domain}`;
            observations.push({
              assetId: makeAssetId68(domain, name, "companies_house"),
              domain,
              assetType: "organization",
              name,
              source: "companies_house",
              observedAt: now,
              tags: ["companies_house", "corporate_risk", ...risks.map((r) => r.replace(/\s+/g, "_"))],
              evidence: {
                severity: 6,
                confidence: 95,
                value: `Corporate risk indicators: ${risks.join(", ")}`,
                risk_indicators: risks,
                has_insolvency_history: profile.has_insolvency_history,
                accounts_overdue: profile.accounts?.overdue,
                confirmation_overdue: profile.confirmation_statement?.overdue
              },
              attribution: {
                provider: "Companies House (UK)",
                url: "https://find-and-update.company-information.service.gov.uk/",
                method: "api"
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during Companies House lookup");
        }
        return {
          connector: "companies_house",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/opencorporates.ts
import { createHash as createHash69 } from "crypto";
function makeAssetId69(domain, name, source) {
  return createHash69("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var OC_API, opencorporatesConnector;
var init_opencorporates = __esm({
  "server/lib/passive/opencorporates.ts"() {
    "use strict";
    init_rate_limiter();
    OC_API = "https://api.opencorporates.com/v0.4";
    opencorporatesConnector = {
      name: "opencorporates",
      description: "OpenCorporates \u2014 global corporate registry for BIA context (140M+ companies across 140 jurisdictions)",
      requiresApiKey: false,
      freeUrl: "https://opencorporates.com/",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const companySearch = domain.replace(/\.(com|co\.uk|org|net|io|uk|ltd|plc|inc|llc|gmbh|ag|sa|bv)$/i, "").replace(/[.-]/g, " ");
          const apiKey = config?.env?.OPENCORPORATES_API_KEY;
          const params = new URLSearchParams({
            q: companySearch,
            per_page: "5",
            order: "score"
          });
          if (apiKey) params.set("api_token", apiKey);
          const resp = await rateLimitedFetch("opencorporates", `${OC_API}/companies/search?${params}`, {
            headers: { "User-Agent": "AC3-SecurityScanner/1.0" },
            signal: AbortSignal.timeout(15e3)
          });
          if (resp.status === 429) {
            rateLimited = true;
            errors.push("OpenCorporates rate limited \u2014 consider adding API key");
            return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          if (resp.status === 403) {
            errors.push("OpenCorporates API access denied \u2014 may need API key for this query");
            return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          if (!resp.ok) {
            errors.push(`OpenCorporates returned ${resp.status}`);
            return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          const data = await resp.json();
          const companies = data?.results?.companies || [];
          if (companies.length === 0) {
            return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
          }
          for (const item of companies.slice(0, 3)) {
            const company = item.company;
            if (!company) continue;
            const isActive = company.current_status?.toLowerCase().includes("active") || company.current_status?.toLowerCase().includes("good standing");
            const name = `OpenCorporates: ${company.name} (${company.jurisdiction_code?.toUpperCase() || "?"})`;
            observations.push({
              assetId: makeAssetId69(domain, company.company_number || name, "opencorporates"),
              domain,
              assetType: "organization",
              name,
              source: "opencorporates",
              observedAt: now,
              firstSeen: company.incorporation_date ? new Date(company.incorporation_date) : void 0,
              tags: [
                "opencorporates",
                "corporate_intel",
                company.jurisdiction_code || "unknown_jurisdiction",
                isActive ? "active" : "inactive"
              ],
              evidence: {
                severity: isActive ? 1 : 4,
                confidence: company.score ? Math.min(company.score * 10, 90) : 50,
                value: `${company.name} \u2014 ${company.current_status || "unknown status"} in ${company.jurisdiction_code?.toUpperCase() || "?"}`,
                company_name: company.name,
                company_number: company.company_number,
                jurisdiction: company.jurisdiction_code,
                incorporation_date: company.incorporation_date,
                dissolution_date: company.dissolution_date,
                company_type: company.company_type,
                current_status: company.current_status,
                registry_url: company.registry_url,
                opencorporates_url: company.opencorporates_url,
                registered_address: company.registered_address_in_full,
                branch: company.branch,
                branch_status: company.branch_status,
                inactive: company.inactive,
                agent_name: company.agent_name,
                agent_address: company.agent_address,
                previous_names: (company.previous_names || []).slice(0, 5).map((pn) => ({
                  name: pn.company_name,
                  start_date: pn.con_date
                }))
              },
              attribution: {
                provider: "OpenCorporates",
                url: "https://opencorporates.com/",
                method: "api"
              }
            });
          }
          const jurisdictions = new Set(companies.map((c) => c.company?.jurisdiction_code).filter(Boolean));
          if (jurisdictions.size > 1) {
            const name = `Multi-Jurisdiction: ${companySearch} found in ${jurisdictions.size} jurisdictions`;
            observations.push({
              assetId: makeAssetId69(domain, name, "opencorporates"),
              domain,
              assetType: "organization",
              name,
              source: "opencorporates",
              observedAt: now,
              tags: ["opencorporates", "multi_jurisdiction", "corporate_intel"],
              evidence: {
                severity: 2,
                confidence: 70,
                value: `Company entities found in ${jurisdictions.size} jurisdictions: ${Array.from(jurisdictions).join(", ")}`,
                jurisdiction_count: jurisdictions.size,
                jurisdictions: Array.from(jurisdictions)
              },
              attribution: {
                provider: "OpenCorporates",
                url: "https://opencorporates.com/",
                method: "api"
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during OpenCorporates lookup");
        }
        return {
          connector: "opencorporates",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/hc3.ts
import { createHash as createHash70 } from "crypto";
function makeAssetId70(domain, name, source) {
  return createHash70("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
var HC3_PRODUCTS_URL, HEALTHCARE_KEYWORDS, HC3_THREAT_GROUPS, hc3Connector;
var init_hc3 = __esm({
  "server/lib/passive/hc3.ts"() {
    "use strict";
    init_rate_limiter();
    HC3_PRODUCTS_URL = "https://www.hhs.gov/about/agencies/asa/ocio/hc3/products/index.html";
    HEALTHCARE_KEYWORDS = [
      "healthcare",
      "hospital",
      "medical",
      "hipaa",
      "phi",
      "ehr",
      "emr",
      "health system",
      "clinic",
      "pharmaceutical",
      "biotech",
      "life sciences",
      "patient data",
      "medical device",
      "telehealth",
      "health insurance",
      "medicare",
      "medicaid",
      "hhs",
      "fda",
      "cms"
    ];
    HC3_THREAT_GROUPS = [
      { name: "Royal/BlackSuit", aliases: ["Royal", "BlackSuit", "Zeon"], targets: "healthcare", severity: 9 },
      { name: "ALPHV/BlackCat", aliases: ["ALPHV", "BlackCat", "Noberus"], targets: "healthcare", severity: 9 },
      { name: "Clop/Cl0p", aliases: ["Clop", "Cl0p", "TA505"], targets: "healthcare", severity: 9 },
      { name: "LockBit", aliases: ["LockBit", "LockBit 3.0", "LockBit Black"], targets: "healthcare", severity: 9 },
      { name: "Rhysida", aliases: ["Rhysida"], targets: "healthcare", severity: 8 },
      { name: "Scattered Spider", aliases: ["Scattered Spider", "UNC3944", "0ktapus"], targets: "healthcare", severity: 8 },
      { name: "Lazarus Group", aliases: ["Lazarus", "HIDDEN COBRA", "APT38"], targets: "healthcare", severity: 9 },
      { name: "Volt Typhoon", aliases: ["Volt Typhoon", "BRONZE SILHOUETTE"], targets: "critical_infrastructure", severity: 10 },
      { name: "Qilin", aliases: ["Qilin", "Agenda"], targets: "healthcare", severity: 8 },
      { name: "INC Ransom", aliases: ["INC Ransom", "INC"], targets: "healthcare", severity: 7 }
    ];
    hc3Connector = {
      name: "hc3",
      description: "HC3 (HHS Health Sector Cybersecurity) \u2014 healthcare sector threat intelligence, HIPAA-relevant alerts",
      requiresApiKey: false,
      freeUrl: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
      async collect(domain, config) {
        const observations = [];
        const start = Date.now();
        const errors = [];
        let rateLimited = false;
        const now = /* @__PURE__ */ new Date();
        try {
          const isHealthcare = config?.context?.sector?.toLowerCase().includes("health") || config?.context?.complianceFlags?.some((f) => f.toLowerCase().includes("hipaa")) || HEALTHCARE_KEYWORDS.some((kw) => domain.toLowerCase().includes(kw));
          const relevantThreats = [];
          const knownActors = config?.context?.threatActorMatches || [];
          for (const group of HC3_THREAT_GROUPS) {
            const matched = group.aliases.some(
              (alias) => knownActors.some(
                (actor) => actor.name?.toLowerCase().includes(alias.toLowerCase()) || actor.aliases?.some((a) => a.toLowerCase().includes(alias.toLowerCase()))
              )
            );
            if (matched) relevantThreats.push(group);
          }
          let recentAlerts = [];
          try {
            const resp = await rateLimitedFetch("hc3", HC3_PRODUCTS_URL, {
              headers: { "User-Agent": "AC3-SecurityScanner/1.0" },
              signal: AbortSignal.timeout(15e3)
            });
            if (resp.ok) {
              const html = await resp.text();
              const alertRegex = /<a[^>]*href="([^"]*)"[^>]*>([^<]+)<\/a>/gi;
              let match;
              while ((match = alertRegex.exec(html)) !== null && recentAlerts.length < 20) {
                const [, url, title] = match;
                if (title.length > 10 && (title.includes("Alert") || title.includes("Briefing") || title.includes("Analyst Note") || title.includes("Threat") || title.includes("Ransomware") || title.includes("Vulnerability"))) {
                  recentAlerts.push({
                    title: title.trim(),
                    url: url.startsWith("http") ? url : `https://www.hhs.gov${url}`,
                    type: title.includes("Alert") ? "alert" : title.includes("Briefing") ? "briefing" : title.includes("Analyst Note") ? "analyst_note" : "advisory"
                  });
                }
              }
            }
          } catch (err) {
            errors.push(`HC3 products fetch: ${err.message}`);
          }
          if (isHealthcare || relevantThreats.length > 0) {
            const name = `HC3 Sector Intel: ${relevantThreats.length > 0 ? `${relevantThreats.length} active threat groups targeting healthcare` : "Healthcare sector threat landscape"}`;
            observations.push({
              assetId: makeAssetId70(domain, name, "hc3"),
              domain,
              assetType: "threat_intel",
              name,
              source: "hc3",
              observedAt: now,
              tags: ["hc3", "healthcare", "sector_intel", "hipaa", ...isHealthcare ? ["target_is_healthcare"] : []],
              evidence: {
                severity: relevantThreats.length > 0 ? 9 : isHealthcare ? 6 : 3,
                confidence: relevantThreats.length > 0 ? 85 : 60,
                value: relevantThreats.length > 0 ? `${relevantThreats.length} known healthcare-targeting threat groups matched: ${relevantThreats.map((t) => t.name).join(", ")}` : `Healthcare sector threat landscape \u2014 HC3 tracks ${HC3_THREAT_GROUPS.length} active groups targeting the health sector`,
                is_healthcare_target: isHealthcare,
                matched_threat_groups: relevantThreats.map((t) => ({
                  name: t.name,
                  aliases: t.aliases,
                  severity: t.severity
                })),
                total_tracked_groups: HC3_THREAT_GROUPS.length,
                tracked_groups: HC3_THREAT_GROUPS.map((g) => g.name)
              },
              attribution: {
                provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
                url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
                method: "threat_intel"
              }
            });
          }
          if (recentAlerts.length > 0) {
            const name = `HC3 Alerts: ${recentAlerts.length} recent healthcare security advisories`;
            observations.push({
              assetId: makeAssetId70(domain, name, "hc3"),
              domain,
              assetType: "threat_intel",
              name,
              source: "hc3",
              observedAt: now,
              tags: ["hc3", "healthcare_alerts", "sector_advisories"],
              evidence: {
                severity: 4,
                confidence: 80,
                value: `${recentAlerts.length} recent HC3 advisories \u2014 latest: ${recentAlerts[0]?.title || "N/A"}`,
                alert_count: recentAlerts.length,
                alerts: recentAlerts.slice(0, 10).map((a) => ({
                  title: a.title,
                  type: a.type,
                  url: a.url
                }))
              },
              attribution: {
                provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
                url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
                method: "web_scrape"
              }
            });
          }
          if (isHealthcare) {
            const name = `HC3 HIPAA Context: ${domain} identified as healthcare entity`;
            observations.push({
              assetId: makeAssetId70(domain, name, "hc3"),
              domain,
              assetType: "compliance",
              name,
              source: "hc3",
              observedAt: now,
              tags: ["hc3", "hipaa", "compliance", "healthcare"],
              evidence: {
                severity: 5,
                confidence: 70,
                value: "Target identified as healthcare entity \u2014 HIPAA Security Rule and Breach Notification Rule apply. HC3 recommends enhanced monitoring for ransomware, credential theft, and supply chain attacks.",
                compliance_frameworks: ["HIPAA Security Rule", "HIPAA Breach Notification Rule", "HITECH Act"],
                recommended_controls: [
                  "Multi-factor authentication for all remote access",
                  "Network segmentation for medical devices and EHR systems",
                  "Encrypted backup with offline/immutable copies",
                  "Incident response plan with HHS OCR notification procedures",
                  "Regular vulnerability scanning of internet-facing assets",
                  "Phishing-resistant authentication (FIDO2/WebAuthn)"
                ]
              },
              attribution: {
                provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
                url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
                method: "knowledge_base"
              }
            });
          }
        } catch (err) {
          if (err.message?.includes("Rate limit")) rateLimited = true;
          errors.push(err.message || "Unknown error during HC3 lookup");
        }
        return {
          connector: "hc3",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited
        };
      }
    };
  }
});

// server/lib/passive/wildcard-detection.ts
import { resolve4 as resolve46 } from "dns/promises";
import { randomBytes } from "crypto";
function randomLabel() {
  return `wc-probe-${randomBytes(8).toString("hex")}`;
}
async function detectWildcardDns(domain, timeout = 5e3) {
  const start = Date.now();
  const probes = [randomLabel(), randomLabel(), randomLabel()];
  const resolvedSets = [];
  for (const label of probes) {
    const hostname = `${label}.${domain}`;
    try {
      const ips = await Promise.race([
        resolve46(hostname),
        new Promise((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), timeout))
      ]);
      resolvedSets.push(ips.sort());
    } catch {
      resolvedSets.push([]);
    }
  }
  const resolvedCount = resolvedSets.filter((s) => s.length > 0).length;
  const isWildcard = resolvedCount >= 2;
  const wildcardIps = [...new Set(resolvedSets.flat())];
  return {
    domain,
    isWildcard,
    wildcardIps,
    probeHostname: `${probes[0]}.${domain}`,
    durationMs: Date.now() - start
  };
}
function tagWildcardObservations(observations, wildcardResult) {
  if (!wildcardResult.isWildcard || wildcardResult.wildcardIps.length === 0) {
    return observations;
  }
  const wildcardIpSet = new Set(wildcardResult.wildcardIps);
  return observations.map((obs) => {
    if (obs.ip && wildcardIpSet.has(obs.ip)) {
      return {
        ...obs,
        tags: [...obs.tags, "wildcard_candidate"],
        evidence: {
          ...obs.evidence,
          wildcardDetected: true,
          wildcardIps: wildcardResult.wildcardIps
        }
      };
    }
    return obs;
  });
}
function createWildcardSignal(domain, wildcardResult) {
  return {
    signalType: "wildcard_dns",
    severity: "info",
    confidence: wildcardResult.wildcardIps.length > 0 ? 0.95 : 0.7,
    rationale: `Domain ${domain} has wildcard DNS configured \u2014 all non-existent subdomains resolve to ${wildcardResult.wildcardIps.join(", ")}. Subdomain enumeration results may contain false positives.`,
    evidenceRefs: [wildcardResult.probeHostname]
  };
}
var init_wildcard_detection = __esm({
  "server/lib/passive/wildcard-detection.ts"() {
    "use strict";
  }
});

// server/lib/nist-control-mapper.ts
function getNistControlsForSignal(signalType) {
  const controlIds = SIGNAL_TO_NIST[signalType] || [];
  return controlIds.map((id) => NIST_CONTROLS[id]).filter((c) => c !== void 0);
}
function getFedrampTimeline(severity) {
  return FEDRAMP_TIMELINES[severity.toLowerCase()] || FEDRAMP_TIMELINES.info;
}
function calculateFedrampDeadline(findingDate, severity) {
  const timeline = getFedrampTimeline(severity);
  const deadline = new Date(findingDate);
  deadline.setDate(deadline.getDate() + timeline.remediationDays);
  return deadline;
}
var NIST_CONTROLS, SIGNAL_TO_NIST, FEDRAMP_TIMELINES;
var init_nist_control_mapper = __esm({
  "server/lib/nist-control-mapper.ts"() {
    "use strict";
    NIST_CONTROLS = {
      "AC-2": {
        controlId: "AC-2",
        controlName: "Account Management",
        family: "Access Control",
        familyCode: "AC",
        fedrampBaseline: "low",
        description: "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
      },
      "AC-3": {
        controlId: "AC-3",
        controlName: "Access Enforcement",
        family: "Access Control",
        familyCode: "AC",
        fedrampBaseline: "low",
        description: "Enforce approved authorizations for logical access to information and system resources."
      },
      "AC-4": {
        controlId: "AC-4",
        controlName: "Information Flow Enforcement",
        family: "Access Control",
        familyCode: "AC",
        fedrampBaseline: "moderate",
        description: "Enforce approved authorizations for controlling the flow of information within the system and between systems."
      },
      "AC-17": {
        controlId: "AC-17",
        controlName: "Remote Access",
        family: "Access Control",
        familyCode: "AC",
        fedrampBaseline: "low",
        description: "Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed."
      },
      "AU-6": {
        controlId: "AU-6",
        controlName: "Audit Record Review, Analysis, and Reporting",
        family: "Audit and Accountability",
        familyCode: "AU",
        fedrampBaseline: "low",
        description: "Review and analyze system audit records for indications of inappropriate or unusual activity."
      },
      "CA-8": {
        controlId: "CA-8",
        controlName: "Penetration Testing",
        family: "Assessment, Authorization, and Monitoring",
        familyCode: "CA",
        fedrampBaseline: "moderate",
        description: "Conduct penetration testing on the system or system components."
      },
      "CM-6": {
        controlId: "CM-6",
        controlName: "Configuration Settings",
        family: "Configuration Management",
        familyCode: "CM",
        fedrampBaseline: "low",
        description: "Establish and document configuration settings for components employed within the system."
      },
      "CM-7": {
        controlId: "CM-7",
        controlName: "Least Functionality",
        family: "Configuration Management",
        familyCode: "CM",
        fedrampBaseline: "low",
        description: "Configure the system to provide only mission-essential capabilities."
      },
      "CM-8": {
        controlId: "CM-8",
        controlName: "System Component Inventory",
        family: "Configuration Management",
        familyCode: "CM",
        fedrampBaseline: "low",
        description: "Develop and document an inventory of system components."
      },
      "IA-2": {
        controlId: "IA-2",
        controlName: "Identification and Authentication (Organizational Users)",
        family: "Identification and Authentication",
        familyCode: "IA",
        fedrampBaseline: "low",
        description: "Uniquely identify and authenticate organizational users."
      },
      "IA-5": {
        controlId: "IA-5",
        controlName: "Authenticator Management",
        family: "Identification and Authentication",
        familyCode: "IA",
        fedrampBaseline: "low",
        description: "Manage system authenticators by verifying identity, initial content, establishing administrative procedures, and protecting authenticators."
      },
      "IR-4": {
        controlId: "IR-4",
        controlName: "Incident Handling",
        family: "Incident Response",
        familyCode: "IR",
        fedrampBaseline: "low",
        description: "Implement an incident handling capability for incidents that includes preparation, detection and analysis, containment, eradication, and recovery."
      },
      "IR-6": {
        controlId: "IR-6",
        controlName: "Incident Reporting",
        family: "Incident Response",
        familyCode: "IR",
        fedrampBaseline: "low",
        description: "Require personnel to report suspected incidents to the organizational incident response capability."
      },
      "RA-5": {
        controlId: "RA-5",
        controlName: "Vulnerability Monitoring and Scanning",
        family: "Risk Assessment",
        familyCode: "RA",
        fedrampBaseline: "low",
        description: "Monitor and scan for vulnerabilities in the system and hosted applications."
      },
      "SA-11": {
        controlId: "SA-11",
        controlName: "Developer Testing and Evaluation",
        family: "System and Services Acquisition",
        familyCode: "SA",
        fedrampBaseline: "moderate",
        description: "Require the developer to create and implement a security and privacy assessment plan."
      },
      "SA-12": {
        controlId: "SA-12",
        controlName: "Supply Chain Risk Management",
        family: "System and Services Acquisition",
        familyCode: "SA",
        fedrampBaseline: "moderate",
        description: "Protect against supply chain threats by employing security safeguards."
      },
      "SC-5": {
        controlId: "SC-5",
        controlName: "Denial-of-Service Protection",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "low",
        description: "Protect against or limit the effects of denial-of-service attacks."
      },
      "SC-7": {
        controlId: "SC-7",
        controlName: "Boundary Protection",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "low",
        description: "Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces."
      },
      "SC-8": {
        controlId: "SC-8",
        controlName: "Transmission Confidentiality and Integrity",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "moderate",
        description: "Protect the confidentiality and integrity of transmitted information."
      },
      "SC-12": {
        controlId: "SC-12",
        controlName: "Cryptographic Key Establishment and Management",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "low",
        description: "Establish and manage cryptographic keys when cryptography is employed within the system."
      },
      "SC-13": {
        controlId: "SC-13",
        controlName: "Cryptographic Protection",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "low",
        description: "Implement FIPS-validated or NSA-approved cryptography."
      },
      "SC-17": {
        controlId: "SC-17",
        controlName: "Public Key Infrastructure Certificates",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "moderate",
        description: "Issue public key certificates under an appropriate certificate policy or obtain public key certificates from an approved service provider."
      },
      "SC-28": {
        controlId: "SC-28",
        controlName: "Protection of Information at Rest",
        family: "System and Communications Protection",
        familyCode: "SC",
        fedrampBaseline: "moderate",
        description: "Protect the confidentiality and integrity of information at rest."
      },
      "SI-2": {
        controlId: "SI-2",
        controlName: "Flaw Remediation",
        family: "System and Information Integrity",
        familyCode: "SI",
        fedrampBaseline: "low",
        description: "Identify, report, and correct system flaws."
      },
      "SI-3": {
        controlId: "SI-3",
        controlName: "Malicious Code Protection",
        family: "System and Information Integrity",
        familyCode: "SI",
        fedrampBaseline: "low",
        description: "Implement malicious code protection mechanisms at system entry and exit points."
      },
      "SI-4": {
        controlId: "SI-4",
        controlName: "System Monitoring",
        family: "System and Information Integrity",
        familyCode: "SI",
        fedrampBaseline: "low",
        description: "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections."
      },
      "SI-5": {
        controlId: "SI-5",
        controlName: "Security Alerts, Advisories, and Directives",
        family: "System and Information Integrity",
        familyCode: "SI",
        fedrampBaseline: "low",
        description: "Receive system security alerts, advisories, and directives from external organizations on an ongoing basis."
      },
      "SI-10": {
        controlId: "SI-10",
        controlName: "Information Input Validation",
        family: "System and Information Integrity",
        familyCode: "SI",
        fedrampBaseline: "moderate",
        description: "Check the validity of information inputs."
      }
    };
    SIGNAL_TO_NIST = {
      // Access control & authentication
      "admin_panel_exposed": ["AC-3", "AC-17", "CM-7"],
      "open_remote_access": ["AC-17", "SC-7"],
      "credential_exposure": ["IA-5", "IR-6"],
      "high_volume_breach": ["IA-5", "IR-4", "IR-6"],
      "api_key_leak": ["IA-5", "SC-28"],
      "sensitive_data_url": ["IA-5", "SC-28"],
      // Configuration & inventory
      "open_db_port": ["SC-7", "CM-7"],
      "staging_env_exposed": ["CM-8", "CM-7"],
      "shadow_it_service": ["CM-8", "CM-7"],
      "cloud_storage_exposed": ["SC-28", "AC-3"],
      // Certificates & encryption
      "expired_cert": ["SC-17", "SC-12"],
      "cert_anomaly": ["SC-17", "SC-13"],
      "missing_spf": ["SC-8", "SI-4"],
      "missing_dmarc": ["SC-8", "SI-4"],
      // Vulnerability management
      "known_vuln_software": ["SI-2", "RA-5"],
      "binaryedge_cve": ["SI-2", "RA-5"],
      "internetdb_cve": ["SI-2", "RA-5"],
      "greynoise_cve_exploit": ["SI-2", "RA-5", "SI-5"],
      // Threat detection
      "greynoise_malicious": ["SI-4", "IR-4"],
      "greynoise_noise": ["SI-4"],
      // Subdomain & DNS
      "subdomain_takeover": ["CM-8", "SC-7"],
      "breach_subdomain": ["CM-8"],
      // Historical
      "historical_admin_path": ["CM-8", "AC-3"],
      "api_endpoint_exposed": ["AC-3", "SC-7"]
    };
    FEDRAMP_TIMELINES = {
      critical: { severity: "critical", remediationDays: 30, label: "30 days (Critical)" },
      high: { severity: "high", remediationDays: 30, label: "30 days (High)" },
      medium: { severity: "medium", remediationDays: 90, label: "90 days (Moderate)" },
      low: { severity: "low", remediationDays: 180, label: "180 days (Low)" },
      info: { severity: "info", remediationDays: 365, label: "365 days (Informational)" }
    };
  }
});

// server/lib/passive/signal-classifier.ts
import { createHash as createHash71 } from "crypto";
function makeSignalId(assetId, ruleId) {
  return createHash71("sha256").update(`${assetId}|${ruleId}`).digest("hex").slice(0, 20);
}
function classifySignals(observations) {
  const signals = [];
  const seen = /* @__PURE__ */ new Set();
  for (const obs of observations) {
    for (const rule of SIGNAL_RULES) {
      try {
        if (rule.match(obs)) {
          const signalId = makeSignalId(obs.assetId, rule.id);
          if (seen.has(signalId)) continue;
          seen.add(signalId);
          const signal = {
            signalId,
            assetId: obs.assetId,
            signalType: rule.id,
            severity: rule.severity,
            confidence: rule.confidence,
            observedAt: obs.observedAt,
            rationale: rule.rationale(obs),
            evidenceRefs: [obs.assetId]
          };
          try {
            const nistControls = getNistControlsForSignal(rule.id);
            if (nistControls.length > 0) {
              signal.nistControls = nistControls.map((c) => ({
                controlId: c.controlId,
                controlName: c.controlName,
                family: c.family
              }));
            }
            const deadline = calculateFedrampDeadline(obs.observedAt, rule.severity);
            signal.fedrampDeadline = deadline.toISOString();
          } catch {
          }
          if (rule.credentialEvidence) {
            try {
              signal.credentialEvidence = rule.credentialEvidence(obs);
            } catch {
            }
          }
          signals.push(signal);
        }
      } catch {
      }
    }
  }
  return signals;
}
function getSignalRuleDescriptions() {
  return SIGNAL_RULES.map((r) => ({ id: r.id, name: r.name, severity: r.severity }));
}
var SIGNAL_RULES;
var init_signal_classifier = __esm({
  "server/lib/passive/signal-classifier.ts"() {
    "use strict";
    init_nist_control_mapper();
    SIGNAL_RULES = [
      // ─── Exposed Admin Interfaces ──────────────────────────────────
      {
        id: "admin_panel_exposed",
        name: "Exposed Admin/Management Interface",
        severity: "high",
        confidence: 0.85,
        match: (obs) => {
          const name = (obs.name || "").toLowerCase();
          const tags = obs.tags.join(" ");
          return /admin|console|mgmt|management|cpanel|phpmyadmin|webmin|cockpit/i.test(name) || tags.includes("admin_path");
        },
        rationale: (obs) => `Admin/management interface detected at ${obs.name}. These interfaces are high-value targets for attackers and should not be publicly accessible.`
      },
      // ─── Open Database Ports ───────────────────────────────────────
      {
        id: "open_db_port",
        name: "Open Database/Cache Port",
        severity: "critical",
        confidence: 0.9,
        match: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          if (!portTag) return false;
          const port = parseInt(portTag.split(":")[1], 10);
          return [3306, 5432, 27017, 6379, 9200, 11211, 5984, 8529].includes(port);
        },
        rationale: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          const portMap = {
            "3306": "MySQL",
            "5432": "PostgreSQL",
            "27017": "MongoDB",
            "6379": "Redis",
            "9200": "Elasticsearch",
            "11211": "Memcached",
            "5984": "CouchDB",
            "8529": "ArangoDB"
          };
          const port = portTag.split(":")[1];
          return `Open ${portMap[port] || "database"} port (${port}) detected on ${obs.ip || obs.name}. Database ports should never be directly exposed to the internet.`;
        }
      },
      // ─── Expired TLS Certificates ──────────────────────────────────
      {
        id: "expired_cert",
        name: "Expired TLS Certificate",
        severity: "medium",
        confidence: 0.95,
        match: (obs) => {
          const notAfter = obs.evidence?.not_after;
          if (!notAfter) return false;
          return new Date(notAfter) < /* @__PURE__ */ new Date();
        },
        rationale: (obs) => `TLS certificate for ${obs.name} expired on ${obs.evidence.not_after}. Expired certificates cause browser warnings and may indicate abandoned infrastructure.`
      },
      // ─── Staging/Dev Environments ──────────────────────────────────
      {
        id: "staging_env_exposed",
        name: "Exposed Staging/Development Environment",
        severity: "high",
        confidence: 0.75,
        match: (obs) => {
          const name = (obs.name || "").toLowerCase();
          return /^(dev|test|staging|stage|qa|uat|sandbox|demo|beta|preview)\./i.test(name) || obs.tags.includes("staging_path");
        },
        rationale: (obs) => `Staging/development environment detected at ${obs.name}. These environments often have weaker security controls and may contain sensitive test data.`
      },
      // ─── API Endpoints ─────────────────────────────────────────────
      {
        id: "api_endpoint_exposed",
        name: "Exposed API Endpoint",
        severity: "medium",
        confidence: 0.7,
        match: (obs) => {
          const name = (obs.name || "").toLowerCase();
          return /api\.|graphql|swagger|openapi|\/api\/|\/v[0-9]+\//i.test(name) || obs.tags.includes("api_path");
        },
        rationale: (obs) => `API endpoint detected at ${obs.name}. Exposed API endpoints should be reviewed for proper authentication and rate limiting.`
      },
      // ─── Sensitive Data in URLs ────────────────────────────────────
      {
        id: "sensitive_data_url",
        name: "Potential Sensitive Data in URL",
        severity: "high",
        confidence: 0.6,
        match: (obs) => {
          if (obs.assetType !== "url") return false;
          const name = (obs.name || "").toLowerCase();
          return /[?&](api_key|apikey|token|secret|password|passwd|auth|access_token|private_key)=/i.test(name);
        },
        rationale: (obs) => `URL contains potential sensitive data (API key, token, or credential) in query parameters: ${obs.name?.substring(0, 100)}...`
      },
      // ─── Missing SPF Record ────────────────────────────────────────
      {
        id: "missing_spf",
        name: "Missing or Weak SPF Record",
        severity: "low",
        confidence: 0.8,
        match: (obs) => {
          if (obs.assetType !== "txt") return false;
          const txt = (obs.evidence?.value || "").toLowerCase();
          return txt.includes("v=spf") && (txt.includes("+all") || txt.includes("?all"));
        },
        rationale: (obs) => `Weak SPF record detected for ${obs.domain}: ${obs.evidence?.value}. A permissive SPF policy (+all or ?all) allows anyone to send email on behalf of the domain.`
      },
      // ─── Known Vulnerable Software ─────────────────────────────────
      {
        id: "known_vuln_software",
        name: "Potentially Vulnerable Software Version",
        severity: "high",
        confidence: 0.65,
        match: (obs) => {
          const product = (obs.evidence?.product || "").toLowerCase();
          const version = obs.evidence?.version || "";
          if (!product || !version) return false;
          const vulnPatterns = [
            [/apache/i, /^[12]\.[0-3]\./],
            [/nginx/i, /^1\.[0-9]\./],
            [/openssh/i, /^[1-6]\./],
            [/php/i, /^[5-7]\.[0-2]\./],
            [/iis/i, /^[5-7]\./]
          ];
          return vulnPatterns.some(([prodRe, verRe]) => prodRe.test(product) && verRe.test(version));
        },
        rationale: (obs) => `Potentially vulnerable software detected: ${obs.evidence.product} ${obs.evidence.version} on ${obs.ip || obs.name}. Older versions may have known CVEs.`
      },
      // ─── Historical Admin Paths ────────────────────────────────────
      {
        id: "historical_admin_path",
        name: "Historical Admin Path in Web Archive",
        severity: "medium",
        confidence: 0.55,
        match: (obs) => {
          return obs.source === "wayback" && obs.tags.includes("admin_path");
        },
        rationale: (obs) => `Historical admin path found in Wayback Machine archive: ${obs.name}. Even if no longer active, this reveals the application's admin URL pattern.`
      },
      // ─── Credential Exposure (Breach Data) ────────────────────────
      {
        id: "credential_exposure",
        name: "Credentials Exposed in Data Breach",
        severity: "critical",
        confidence: 0.95,
        match: (obs) => {
          return obs.source === "dehashed" && obs.assetType === "breach" && obs.tags.includes("credentials_exposed");
        },
        rationale: (obs) => {
          const creds = obs.evidence?.credentials_exposed || 0;
          const dbName = obs.evidence?.database_name || obs.name;
          return `${creds} credentials (passwords/hashes) for ${obs.domain} exposed in the "${dbName}" data breach. Exposed credentials enable password spraying and credential stuffing attacks.`;
        },
        credentialEvidence: (obs) => {
          const ev = obs.evidence || {};
          return {
            breachName: ev.database_name || obs.name || void 0,
            breachDate: ev.breach_date || void 0,
            totalRecords: ev.credentials_exposed || ev.total_records || void 0,
            emails: ev.sample_emails?.slice(0, 10) || (ev.email ? [ev.email] : void 0),
            usernames: ev.sample_usernames?.slice(0, 10) || (ev.username ? [ev.username] : void 0),
            hashTypes: ev.hash_types || (ev.hash_type ? [ev.hash_type] : void 0),
            hasPlaintextPasswords: ev.has_plaintext === true || ev.password_count > 0 || void 0,
            sources: ["dehashed"],
            domain: obs.domain
          };
        }
      },
      // ─── High-Volume Breach Exposure ──────────────────────────────
      {
        id: "high_volume_breach",
        name: "High-Volume Breach Exposure",
        severity: "high",
        confidence: 0.9,
        match: (obs) => {
          return obs.source === "dehashed" && obs.assetType === "breach" && obs.tags.includes("breach_summary") && (obs.evidence?.total_records || 0) > 100;
        },
        rationale: (obs) => {
          const total = obs.evidence?.total_records || 0;
          const breaches = obs.evidence?.unique_breaches || 0;
          return `${total} breach records found across ${breaches} data breaches for ${obs.domain}. High-volume exposure significantly increases the risk of credential stuffing and account takeover attacks.`;
        },
        credentialEvidence: (obs) => {
          const ev = obs.evidence || {};
          return {
            totalRecords: ev.total_records || void 0,
            uniqueBreaches: ev.unique_breaches || void 0,
            emails: ev.sample_emails?.slice(0, 10) || void 0,
            usernames: ev.sample_usernames?.slice(0, 10) || void 0,
            hashTypes: ev.hash_types || void 0,
            hasPlaintextPasswords: ev.has_plaintext === true || ev.password_count > 0 || void 0,
            breachName: ev.top_breaches?.join(", ") || ev.database_name || void 0,
            sources: ["dehashed"],
            domain: obs.domain
          };
        }
      },
      // ─── Breach-Derived Subdomain Discovery ───────────────────────
      {
        id: "breach_subdomain",
        name: "Subdomain Discovered via Breach Data",
        severity: "info",
        confidence: 0.8,
        match: (obs) => {
          return obs.source === "dehashed" && obs.assetType === "subdomain" && obs.tags.includes("breach_derived");
        },
        rationale: (obs) => `Subdomain ${obs.name} discovered through email addresses found in breach records. This subdomain may host services with compromised user accounts.`
      },
      // ─── GreyNoise: Active Attack Detection ────────────────────────
      {
        id: "greynoise_malicious",
        name: "IP Under Active Attack (GreyNoise)",
        severity: "critical",
        confidence: 0.95,
        match: (obs) => {
          return obs.source === "greynoise" && obs.tags.includes("UNDER_ACTIVE_ATTACK");
        },
        rationale: (obs) => {
          const actor = obs.evidence?.actor || "unknown";
          const cves = obs.evidence?.cves_exploited || [];
          const cveStr = cves.length > 0 ? ` CVEs being exploited: ${cves.join(", ")}.` : "";
          return `GreyNoise classifies ${obs.ip || obs.name} as MALICIOUS \u2014 this IP is being actively targeted by threat actors${actor !== "unknown" ? ` (actor: ${actor})` : ""}.${cveStr} Immediate investigation recommended.`;
        }
      },
      // ─── GreyNoise: Mass Scanning Target ──────────────────────────
      {
        id: "greynoise_noise",
        name: "IP Targeted by Mass Scanning (GreyNoise)",
        severity: "medium",
        confidence: 0.85,
        match: (obs) => {
          return obs.source === "greynoise" && obs.tags.includes("internet_noise") && !obs.tags.includes("UNDER_ACTIVE_ATTACK");
        },
        rationale: (obs) => `GreyNoise detects mass-scanning activity targeting ${obs.ip || obs.name}. While this is common internet background noise, it indicates the IP is visible to automated scanners.`
      },
      // ─── GreyNoise: Active CVE Exploitation ───────────────────────
      {
        id: "greynoise_cve_exploit",
        name: "CVE Actively Exploited Against IP (GreyNoise)",
        severity: "critical",
        confidence: 0.95,
        match: (obs) => {
          return obs.source === "greynoise" && obs.tags.includes("actively_exploited") && obs.tags.some((t) => t.startsWith("cve:"));
        },
        rationale: (obs) => {
          const cve = obs.tags.find((t) => t.startsWith("cve:"))?.split(":")[1] || "unknown";
          return `GreyNoise sensor network confirms ${cve} is being actively exploited against ${obs.ip || obs.name}. This is ground-truth exploitation data from passive traffic analysis.`;
        }
      },
      // ─── BinaryEdge: CVE Detected ─────────────────────────────────
      {
        id: "binaryedge_cve",
        name: "CVE Detected by BinaryEdge",
        severity: "high",
        confidence: 0.85,
        match: (obs) => {
          return obs.source === "binaryedge" && obs.tags.includes("binaryedge_cve") && obs.tags.some((t) => t.startsWith("cve:"));
        },
        rationale: (obs) => {
          const cve = obs.tags.find((t) => t.startsWith("cve:"))?.split(":")[1] || "unknown";
          return `BinaryEdge independently confirms ${cve} on ${obs.ip || obs.name}. Cross-validated with Shodan data for higher confidence.`;
        }
      },
      // ─── BinaryEdge: Exposed Service ──────────────────────────────
      {
        id: "binaryedge_exposed_service",
        name: "Exposed Service (BinaryEdge Independent Validation)",
        severity: "medium",
        confidence: 0.8,
        match: (obs) => {
          return obs.source === "binaryedge" && obs.assetType === "ip" && obs.tags.includes("binaryedge_host") && (obs.evidence?.open_ports?.length || 0) > 5;
        },
        rationale: (obs) => {
          const ports = obs.evidence?.open_ports || [];
          return `BinaryEdge detects ${ports.length} open ports on ${obs.ip || obs.name}: ${ports.slice(0, 10).join(", ")}${ports.length > 10 ? "..." : ""}. Large attack surface independently confirmed.`;
        }
      },
      // ─── Shodan InternetDB: Fast CVE Match ────────────────────────
      {
        id: "internetdb_cve",
        name: "CVE Detected by Shodan InternetDB (Free)",
        severity: "high",
        confidence: 0.8,
        match: (obs) => {
          return obs.source === "shodan_internetdb" && obs.tags.includes("internetdb_cve") && obs.tags.some((t) => t.startsWith("cve:"));
        },
        rationale: (obs) => {
          const cve = obs.tags.find((t) => t.startsWith("cve:"))?.split(":")[1] || "unknown";
          return `Shodan InternetDB (free fast-path) detects ${cve} on ${obs.ip || obs.name}. This is pre-computed data from Shodan's internet-wide scanning.`;
        }
      },
      // ─── Dangling CNAME / Subdomain Takeover ──────────────────────
      {
        id: "subdomain_takeover",
        name: "Potential Subdomain Takeover (Dangling CNAME)",
        severity: "critical",
        confidence: 0.8,
        match: (obs) => {
          if (obs.assetType !== "cname" && obs.assetType !== "subdomain") return false;
          const name = (obs.name || "").toLowerCase();
          const cname = (obs.evidence?.cname || obs.evidence?.value || "").toLowerCase();
          const takeoverTargets = [
            /\.s3\.amazonaws\.com$/,
            /\.s3-website[.-].*\.amazonaws\.com$/,
            /\.cloudfront\.net$/,
            /\.herokuapp\.com$/,
            /\.herokudns\.com$/,
            /\.azurewebsites\.net$/,
            /\.blob\.core\.windows\.net$/,
            /\.cloudapp\.azure\.com$/,
            /\.trafficmanager\.net$/,
            /\.ghost\.io$/,
            /\.myshopify\.com$/,
            /\.surge\.sh$/,
            /\.bitbucket\.io$/,
            /\.pantheonsite\.io$/,
            /\.zendesk\.com$/,
            /\.github\.io$/,
            /\.gitlab\.io$/,
            /\.netlify\.app$/,
            /\.fly\.dev$/,
            /\.vercel\.app$/,
            /\.render\.com$/,
            /\.unbouncepages\.com$/,
            /\.wordpress\.com$/,
            /\.wpengine\.com$/,
            /\.fastly\.net$/
          ];
          const hasTakeoverTarget = takeoverTargets.some((re) => re.test(cname));
          const hasNxdomain = obs.tags.some((t) => t.includes("nxdomain") || t.includes("dangling") || t.includes("unresolved"));
          return hasTakeoverTarget || hasNxdomain;
        },
        rationale: (obs) => {
          const cname = obs.evidence?.cname || obs.evidence?.value || "unknown";
          return `Potential subdomain takeover: ${obs.name} has a CNAME pointing to ${cname}, which may be unclaimed. An attacker could register this resource and serve malicious content under your domain.`;
        }
      },
      // ─── Cloud Storage Exposure ───────────────────────────────────
      {
        id: "cloud_storage_exposed",
        name: "Publicly Accessible Cloud Storage",
        severity: "critical",
        confidence: 0.85,
        match: (obs) => {
          const name = (obs.name || "").toLowerCase();
          const tags = obs.tags.join(" ").toLowerCase();
          const evidence = obs.evidence || {};
          const isCloudStorage = /s3\.amazonaws|blob\.core\.windows|storage\.googleapis|storage\.cloud\.google/i.test(name) || tags.includes("s3_bucket") || tags.includes("azure_blob") || tags.includes("gcp_bucket") || tags.includes("cloud_storage") || tags.includes("public_bucket");
          const isPublic = tags.includes("public") || tags.includes("open_bucket") || evidence.public === true || evidence.publicAccess === true || evidence.acl === "public-read" || evidence.acl === "public-read-write" || evidence.listable === true;
          return isCloudStorage && isPublic;
        },
        rationale: (obs) => {
          const provider = /s3|amazonaws/i.test(obs.name || "") ? "AWS S3" : /blob\.core\.windows/i.test(obs.name || "") ? "Azure Blob" : /storage\.google/i.test(obs.name || "") ? "Google Cloud Storage" : "cloud storage";
          return `Publicly accessible ${provider} bucket detected: ${obs.name}. Public cloud storage can expose sensitive data, backups, credentials, and internal documents.`;
        }
      },
      // ─── API Key Leakage ──────────────────────────────────────────
      {
        id: "api_key_leak",
        name: "API Key or Secret Leaked in Public Source",
        severity: "critical",
        confidence: 0.75,
        match: (obs) => {
          const tags = obs.tags.join(" ").toLowerCase();
          const evidence = obs.evidence || {};
          const hasLeakTag = tags.includes("api_key_leak") || tags.includes("secret_leak") || tags.includes("credential_leak") || tags.includes("hardcoded_secret") || tags.includes("exposed_key") || tags.includes("token_leak");
          const hasKeyPattern = evidence.secret_type && /api.key|token|secret|password|credential/i.test(evidence.secret_type);
          return hasLeakTag || hasKeyPattern;
        },
        rationale: (obs) => {
          const secretType = obs.evidence?.secret_type || "API key/secret";
          const location = obs.evidence?.file_path || obs.evidence?.url || obs.name;
          return `${secretType} leaked in public source: ${location}. Exposed API keys and secrets can grant unauthorized access to internal systems, cloud resources, and third-party services.`;
        }
      },
      // ─── Certificate Transparency Anomalies ───────────────────────
      {
        id: "cert_anomaly",
        name: "Certificate Transparency Anomaly",
        severity: "high",
        confidence: 0.7,
        match: (obs) => {
          if (obs.assetType !== "certificate") return false;
          const evidence = obs.evidence || {};
          const issuer = (evidence.issuer || "").toLowerCase();
          const subject = (evidence.subject || evidence.commonName || "").toLowerCase();
          const isSelfSigned = issuer === subject || evidence.selfSigned === true;
          const isWildcard = subject.startsWith("*.");
          const suspiciousIssuer = /let.*encrypt/i.test(issuer) === false && /digicert|comodo|sectigo|globalsign|entrust|godaddy|amazon|google|microsoft|cloudflare/i.test(issuer) === false && issuer.length > 0;
          const notBefore = evidence.not_before ? new Date(evidence.not_before).getTime() : 0;
          const notAfter = evidence.not_after ? new Date(evidence.not_after).getTime() : 0;
          const validityDays = notAfter && notBefore ? (notAfter - notBefore) / (1e3 * 60 * 60 * 24) : 0;
          const unusualValidity = validityDays > 0 && (validityDays < 30 || validityDays > 825);
          return isSelfSigned || isWildcard && suspiciousIssuer || unusualValidity;
        },
        rationale: (obs) => {
          const evidence = obs.evidence || {};
          const issuer = evidence.issuer || "unknown";
          const subject = evidence.subject || evidence.commonName || obs.name;
          if (evidence.selfSigned) {
            return `Self-signed certificate detected for ${subject}. Self-signed certificates on production systems indicate misconfiguration or potential MITM setup.`;
          }
          return `Certificate anomaly detected for ${subject} (issuer: ${issuer}). Unexpected certificate characteristics may indicate domain hijacking, MITM, or misconfiguration.`;
        }
      },
      // ─── Shadow IT / Unauthorized Services ────────────────────────
      {
        id: "shadow_it_service",
        name: "Potential Shadow IT / Unauthorized Service",
        severity: "medium",
        confidence: 0.65,
        match: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          if (!portTag) return false;
          const port = parseInt(portTag.split(":")[1], 10);
          const shadowPorts = [
            8080,
            8443,
            8888,
            9090,
            9443,
            3e3,
            4e3,
            5e3,
            7e3,
            7443,
            8e3,
            8001,
            8008,
            8081,
            8082,
            8083,
            8084,
            8085,
            8181,
            8282,
            8383,
            8484,
            8585,
            8686,
            8787,
            8880,
            8881,
            8882,
            8883,
            8884,
            9e3,
            9001,
            9002,
            9003,
            9080,
            9443,
            1e4,
            10443
          ];
          const standardPorts = [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 27017, 6379, 9200, 3389, 5900, 5901];
          return shadowPorts.includes(port) || port > 1024 && port < 65535 && !standardPorts.includes(port) && obs.evidence?.product;
        },
        rationale: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          const port = portTag.split(":")[1];
          const product = obs.evidence?.product || "unknown service";
          return `Potential shadow IT service detected: ${product} on port ${port} at ${obs.ip || obs.name}. Non-standard ports often host unauthorized, unpatched, or forgotten services that bypass normal security controls.`;
        }
      },
      // ─── Missing DMARC Record ─────────────────────────────────────
      {
        id: "missing_dmarc",
        name: "Missing or Weak DMARC Record",
        severity: "medium",
        confidence: 0.85,
        match: (obs) => {
          if (obs.source !== "email-security") return false;
          const tags = obs.tags.join(" ").toLowerCase();
          return tags.includes("no_dmarc") || tags.includes("dmarc_none") || obs.evidence?.dmarc_policy === "none" || obs.evidence?.hasDmarc === false;
        },
        rationale: (obs) => `Missing or weak DMARC policy for ${obs.domain || obs.name}. Without DMARC enforcement (quarantine/reject), attackers can spoof emails from this domain for phishing campaigns.`
      },
      // ─── Open Remote Access Ports ──────────────────────────────────
      {
        id: "open_remote_access",
        name: "Open Remote Access Port",
        severity: "high",
        confidence: 0.85,
        match: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          if (!portTag) return false;
          const port = parseInt(portTag.split(":")[1], 10);
          return [22, 23, 3389, 5900, 5901].includes(port);
        },
        rationale: (obs) => {
          const portTag = obs.tags.find((t) => t.startsWith("port:"));
          const portMap = {
            "22": "SSH",
            "23": "Telnet",
            "3389": "RDP",
            "5900": "VNC",
            "5901": "VNC"
          };
          const port = portTag.split(":")[1];
          return `Open ${portMap[port] || "remote access"} port (${port}) detected on ${obs.ip || obs.name}. Remote access services should be restricted via VPN or IP allowlisting.`;
        }
      }
    ];
  }
});

// server/lib/redteam-discovery-coverage.ts
function computeDiscoveryCoverage(connectorResults, allObservations) {
  const connectorData = /* @__PURE__ */ new Map();
  for (const cr of connectorResults) {
    const data = { count: cr.observations.length, tags: /* @__PURE__ */ new Set(), assetTypes: /* @__PURE__ */ new Set() };
    for (const obs of cr.observations) {
      for (const tag of obs.tags) data.tags.add(tag);
      if (obs.assetType) data.assetTypes.add(obs.assetType);
    }
    connectorData.set(cr.connector, data);
  }
  const globalTags = /* @__PURE__ */ new Set();
  const globalAssetTypes = /* @__PURE__ */ new Set();
  for (const obs of allObservations) {
    for (const tag of obs.tags) globalTags.add(tag);
    if (obs.assetType) globalAssetTypes.add(obs.assetType);
  }
  const priorities = [];
  let weightedCoveredSum = 0;
  let totalWeight = 0;
  const structuralGaps = [];
  const actionableGaps = [];
  for (const priority of RED_TEAM_PRIORITIES) {
    const hasConnectors = priority.connectors.length > 0;
    totalWeight += priority.weight;
    let observationCount = 0;
    const contributingConnectors = [];
    for (const connName of priority.connectors) {
      const data = connectorData.get(connName);
      if (data && data.count > 0) {
        const tagOverlap = priority.coverageTags.some((t) => data.tags.has(t)) || priority.coverageTags.some((t) => data.assetTypes.has(t));
        if (tagOverlap || data.count > 0) {
          observationCount += data.count;
          contributingConnectors.push(connName);
        }
      }
    }
    if (observationCount === 0) {
      let globalMatchCount = 0;
      for (const obs of allObservations) {
        const hasTagMatch = priority.coverageTags.some((t) => obs.tags.includes(t));
        const hasTypeMatch = priority.coverageTags.some((t) => obs.assetType === t);
        if (hasTagMatch || hasTypeMatch) globalMatchCount++;
      }
      if (globalMatchCount > 0) {
        observationCount = globalMatchCount;
        contributingConnectors.push("cross-source");
      }
    }
    const covered = observationCount >= priority.minObservations;
    const quality = observationCount >= priority.minObservations * 2 ? "full" : observationCount >= priority.minObservations ? "partial" : "none";
    if (covered) {
      weightedCoveredSum += priority.weight * (quality === "full" ? 1 : 0.7);
    } else if (!hasConnectors) {
      structuralGaps.push(priority.name);
    } else {
      actionableGaps.push(priority.name);
    }
    priorities.push({
      id: priority.id,
      name: priority.name,
      shortName: priority.shortName,
      weight: priority.weight,
      covered,
      observationCount,
      contributingConnectors,
      quality,
      hasConnectors,
      attackTechniques: priority.attackTechniques
    });
  }
  const prioritiesCovered = priorities.filter((p) => p.covered).length;
  const coverageScore = totalWeight > 0 ? Math.round(weightedCoveredSum / totalWeight * 100) : 0;
  const coverageBand = coverageScore >= 80 ? "comprehensive" : coverageScore >= 60 ? "good" : coverageScore >= 40 ? "partial" : "limited";
  const assessment = generateAssessment(coverageScore, coverageBand, prioritiesCovered, structuralGaps, actionableGaps);
  return {
    coverageScore,
    prioritiesCovered,
    totalPriorities: RED_TEAM_PRIORITIES.length,
    priorities,
    structuralGaps,
    actionableGaps,
    coverageBand,
    assessment
  };
}
function generateAssessment(score, band, covered, structuralGaps, actionableGaps) {
  const parts = [];
  parts.push(`Discovery coverage: ${score}% (${band}) \u2014 ${covered}/10 red team priorities covered.`);
  if (structuralGaps.length > 0) {
    parts.push(`Structural gaps (no connectors available): ${structuralGaps.join(", ")}.`);
  }
  if (actionableGaps.length > 0) {
    parts.push(`Actionable gaps (connectors available but no data found): ${actionableGaps.join(", ")}.`);
  }
  if (score >= 80) {
    parts.push("This scan provides comprehensive recon coverage aligned with standard red team methodology.");
  } else if (score >= 60) {
    parts.push("Good coverage of core discovery areas. Consider adding missing connectors to close remaining gaps.");
  } else if (score >= 40) {
    parts.push("Partial coverage \u2014 several critical discovery areas are missing. Prioritize adding connectors for the highest-weight gaps.");
  } else {
    parts.push("Limited coverage \u2014 most red team discovery priorities are not covered. This scan provides an incomplete picture of the attack surface.");
  }
  return parts.join(" ");
}
var RED_TEAM_PRIORITIES;
var init_redteam_discovery_coverage = __esm({
  "server/lib/redteam-discovery-coverage.ts"() {
    "use strict";
    RED_TEAM_PRIORITIES = [
      {
        id: 1,
        name: "Domains, Subdomains & DNS Footprint",
        shortName: "DNS Footprint",
        description: "Map the entire external perimeter \u2014 subdomains, dev/staging environments, wildcard certs, forgotten assets.",
        weight: 1,
        connectors: ["crtsh", "securitytrails", "dns-deep", "rdap"],
        coverageTags: ["subdomain", "certificate", "dns", "domain", "cname", "ns_record", "soa_record", "wildcard"],
        minObservations: 3,
        attackTechniques: ["T1590.002", "T1596.003"]
      },
      {
        id: 2,
        name: "IP Ranges, Netblocks & Hosting Providers",
        shortName: "IP/Netblocks",
        description: "Define what can be legally scanned, reveal cloud vs on-prem boundaries, expose misrouted or legacy ranges.",
        weight: 0.95,
        connectors: ["ripestat", "rdap", "censys", "shodan"],
        coverageTags: ["ip", "netblock", "asn", "hosting", "whois", "bgp"],
        minObservations: 2,
        attackTechniques: ["T1590.004", "T1590.005"]
      },
      {
        id: 3,
        name: "Live Hosts, Open Ports & Services",
        shortName: "Port Enumeration",
        description: "Identify internet-facing assets, banner versions, and low-hanging services (RDP, SSH, web servers).",
        weight: 0.9,
        connectors: ["shodan", "shodan-internetdb", "censys", "binaryedge", "zap_passive", "nuclei_info"],
        coverageTags: ["port", "service", "banner", "open_port", "service_banner"],
        minObservations: 2,
        attackTechniques: ["T1046", "T1595.001"]
      },
      {
        id: 4,
        name: "Web Applications, APIs & Tech Stack",
        shortName: "Web/API Stack",
        description: "Reveal frameworks/versions with known CVEs, login portals, API keys in JS, misconfigured buckets.",
        weight: 0.85,
        connectors: ["urlscan", "wayback", "http-security", "zap_passive", "zap_active", "nuclei_info"],
        coverageTags: ["technology", "web_app", "framework", "api", "tech_stack", "waf", "security_header", "csp"],
        minObservations: 2,
        attackTechniques: ["T1592.004", "T1595.002"]
      },
      {
        id: 5,
        name: "Employee Emails, Names & Roles",
        shortName: "People Intel",
        description: "Essential for targeted phishing/spear-phishing \u2014 people are the #1 vector in 80%+ of successful initial accesses.",
        weight: 0.8,
        connectors: ["dehashed", "hunter"],
        coverageTags: ["email", "employee", "contact", "breach_email", "breach_summary", "email_pattern", "email_format"],
        minObservations: 1,
        attackTechniques: ["T1589.002", "T1589.003"]
      },
      {
        id: 6,
        name: "Key Personnel OSINT",
        shortName: "Personnel OSINT",
        description: "Build credible pretexts for vishing or social engineering. High-signal targets: execs, IT admins, helpdesk.",
        weight: 0.7,
        connectors: ["social-media", "hunter", "dehashed"],
        coverageTags: ["executive", "admin", "personnel", "social_media", "linkedin", "twitter", "employee_name", "job_title"],
        minObservations: 1,
        attackTechniques: ["T1593", "T1593.001"]
      },
      {
        id: 7,
        name: "Leaked/Breached Credentials",
        shortName: "Credential Leaks",
        description: "Password reuse or exposed API keys often grant immediate footholds without zero-days.",
        weight: 0.85,
        connectors: ["dehashed"],
        coverageTags: ["breach", "credential", "password", "breach_database", "breach_summary", "api_key_leak"],
        minObservations: 1,
        attackTechniques: ["T1589.001", "T1552.001"]
      },
      {
        id: 8,
        name: "Cloud Assets & Misconfigurations",
        shortName: "Cloud Misconfig",
        description: "Cloud sprawl is a top real-world breach vector \u2014 public buckets, open RDS instances, exposed storage.",
        weight: 0.8,
        connectors: ["cloud-assets", "nuclei_vuln"],
        coverageTags: ["cloud", "s3_bucket", "azure_blob", "gcp_bucket", "cloud_storage", "cloud_asset"],
        minObservations: 1,
        attackTechniques: ["T1530", "T1580"]
      },
      {
        id: 9,
        name: "Security Tooling & Defensive Posture",
        shortName: "Defensive Posture",
        description: "WAF fingerprints, EDR/AV banners, SIEM clues, email security (DMARC/SPF) \u2014 what to evade from day one.",
        weight: 0.75,
        connectors: ["email-security", "http-security", "zap_active", "nuclei_info", "atomic_red_team"],
        coverageTags: ["waf", "dmarc", "spf", "dkim", "security_header", "edr", "av", "siem", "hsts", "csp", "email_security", "detection_gap"],
        minObservations: 2,
        attackTechniques: ["T1518.001", "T1590.006"]
      },
      {
        id: 10,
        name: "Code Repositories & Configuration Leaks",
        shortName: "Code/Config Leaks",
        description: "GitHub, Pastebin, Confluence \u2014 hardcoded creds, internal IPs, architecture diagrams, .env files.",
        weight: 0.65,
        connectors: ["github_leaks", "nuclei_vuln"],
        coverageTags: ["github", "pastebin", "code_leak", "config_leak", "env_file", "api_key_leak", "credential"],
        minObservations: 1,
        attackTechniques: ["T1593.003", "T1596.004"]
      }
    ];
  }
});

// server/lib/passive/index.ts
function isLabDomain(domain) {
  return LAB_DOMAIN_PATTERNS.some((pattern) => pattern.test(domain));
}
async function runPassiveRecon(domain, config) {
  const start = Date.now();
  const { scanMode, apiKeys = {}, timeout = 15e3, maxConcurrent = 10 } = config;
  const labMode = isLabDomain(domain);
  if (labMode) {
    console.log(`[PassiveRecon] Lab domain detected: ${domain} \u2014 fast-track mode (${LAB_FAST_TRACK_CONNECTORS.size} connectors only)`);
  }
  const { allowed: modeAllowed, blocked } = filterConnectors(ALL_CONNECTORS, scanMode);
  const allowed = labMode ? modeAllowed.filter((c) => LAB_FAST_TRACK_CONNECTORS.has(c.name)) : modeAllowed;
  if (labMode) {
    const skippedCount = modeAllowed.length - allowed.length;
    console.log(`[PassiveRecon] Lab fast-track: Running ${allowed.length} connectors, skipped ${skippedCount} external API connectors`);
  }
  const scanModeDescription = getScanModeDescription(scanMode);
  const connectorConfigs = /* @__PURE__ */ new Map();
  for (const connector of allowed) {
    const cfg = { timeout };
    switch (connector.name) {
      case "shodan":
        cfg.apiKey = apiKeys.shodan;
        break;
      case "censys":
        cfg.apiId = apiKeys.censys_id;
        cfg.apiSecret = apiKeys.censys_secret;
        break;
      case "urlscan":
        cfg.apiKey = apiKeys.urlscan;
        break;
      case "securitytrails":
        cfg.apiKey = apiKeys.securitytrails;
        break;
      case "dehashed":
        cfg.apiKey = apiKeys.dehashed;
        break;
      case "dehashed_whois":
        cfg.apiKey = apiKeys.dehashed;
        break;
      case "binaryedge":
        cfg.apiKey = apiKeys.binaryedge;
        break;
      case "greynoise":
        cfg.apiKey = apiKeys.greynoise;
        break;
      case "virustotal":
        cfg.apiKey = apiKeys.virustotal;
        break;
      case "hibp":
        cfg.apiKey = apiKeys.hibp;
        break;
      case "whoisxml":
        cfg.apiKey = apiKeys.whoisxml;
        break;
      case "leakix":
        cfg.apiKey = apiKeys.leakix;
        break;
      case "fullhunt":
        cfg.apiKey = apiKeys.fullhunt;
        break;
      case "netlas":
        cfg.apiKey = apiKeys.netlas;
        break;
      case "hunter":
        cfg.apiKey = apiKeys.hunter;
        break;
      case "abuseipdb":
        cfg.apiKey = apiKeys.abuseipdb;
        break;
      case "passivetotal":
        cfg.apiKey = apiKeys.passivetotal;
        break;
      case "github_recon":
        cfg.apiKey = apiKeys.github;
        break;
      case "github_leaks":
        cfg.apiKey = apiKeys.github;
        break;
      case "intelx_search":
        cfg.apiKey = apiKeys.intelx;
        break;
      case "hudson_rock":
        cfg.apiKey = apiKeys.hudson_rock;
        break;
      case "leakcheck":
        cfg.apiKey = apiKeys.leakcheck;
        break;
    }
    connectorConfigs.set(connector.name, cfg);
  }
  const cbConfig = {
    failureThreshold: 3,
    // Open circuit after 3 consecutive failures
    resetTimeoutMs: 12e4,
    // 2 minute cooldown before half-open probe
    halfOpenMaxAttempts: 1
    // 1 probe attempt in half-open state
  };
  const CONNECTORS_REQUIRING_API_KEY = {
    shodan: "apiKey",
    censys: "apiId",
    urlscan: "apiKey",
    securitytrails: "apiKey",
    dehashed: "apiKey",
    dehashed_whois: "apiKey",
    binaryedge: "apiKey",
    greynoise: "apiKey",
    virustotal: "apiKey",
    hibp: "apiKey",
    whoisxml: "apiKey",
    leakix: "apiKey",
    fullhunt: "apiKey",
    netlas: "apiKey",
    hunter: "apiKey",
    abuseipdb: "apiKey",
    passivetotal: "apiKey",
    github_recon: "apiKey",
    github_leaks: "apiKey",
    intelx_search: "apiKey",
    hudson_rock: "apiKey",
    leakcheck: "apiKey"
  };
  const readyConnectors = [];
  const skippedNoKey = [];
  for (const connector of allowed) {
    const requiredField = CONNECTORS_REQUIRING_API_KEY[connector.name];
    if (requiredField) {
      const cfg = connectorConfigs.get(connector.name);
      const hasKey = cfg && (cfg.apiKey || cfg.apiId);
      if (!hasKey) {
        skippedNoKey.push({
          connector: connector.name,
          domain,
          observations: [],
          errors: [`Skipped: No API key configured`],
          durationMs: 0,
          rateLimited: false
        });
        continue;
      }
    }
    readyConnectors.push(connector);
  }
  if (skippedNoKey.length > 0) {
    console.log(`[PassiveRecon] Skipped ${skippedNoKey.length} connectors with no API key: ${skippedNoKey.map((s) => s.connector).join(", ")}`);
  }
  const BACKGROUND_CONNECTORS = /* @__PURE__ */ new Set(["github_leaks", "github_recon"]);
  const mainConnectors = readyConnectors.filter((c) => !BACKGROUND_CONNECTORS.has(c.name));
  const backgroundConnectors = readyConnectors.filter((c) => BACKGROUND_CONNECTORS.has(c.name));
  if (backgroundConnectors.length > 0) {
    console.log(`[PassiveRecon] Background queue: ${backgroundConnectors.map((c) => c.name).join(", ")} (will run after main connectors)`);
  }
  const connectorResults = [...skippedNoKey];
  const { onConnectorProgress } = config;
  const HARD_CONNECTOR_TIMEOUT = 3e4;
  const GLOBAL_RECON_TIMEOUT = 5 * 60 * 1e3;
  const reconStart = Date.now();
  let activeCount = 0;
  let connectorIndex = 0;
  const pendingResults = [];
  function makeTimeoutResult(serviceName) {
    return {
      connector: serviceName,
      domain,
      observations: [],
      errors: [`Hard timeout: ${serviceName} exceeded ${HARD_CONNECTOR_TIMEOUT / 1e3}s \u2014 abandoned`],
      durationMs: HARD_CONNECTOR_TIMEOUT,
      rateLimited: false
    };
  }
  async function runSingleConnector(connector) {
    const serviceName = connector.name;
    if (Date.now() - reconStart >= GLOBAL_RECON_TIMEOUT) {
      return { connector: serviceName, domain, observations: [], errors: ["Global recon timeout reached"], durationMs: 0, rateLimited: false };
    }
    const cbCheck = shouldAllowRequest(serviceName, cbConfig);
    if (!cbCheck.allowed) {
      console.log(`[PassiveRecon] Circuit OPEN for ${serviceName} \u2014 skipping (${cbCheck.reason})`);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: "skipped", error: cbCheck.reason });
      return { connector: serviceName, domain, observations: [], errors: [`Circuit breaker open: ${cbCheck.reason}`], durationMs: 0, rateLimited: false };
    }
    await onConnectorProgress?.({ connector: serviceName, status: "started" });
    const connStart = Date.now();
    const abortCtrl = new AbortController();
    const cfgWithAbort = {
      ...connectorConfigs.get(serviceName),
      signal: abortCtrl.signal,
      timeout: Math.min(timeout, HARD_CONNECTOR_TIMEOUT)
    };
    const timeoutPromise = new Promise((resolve) => {
      setTimeout(() => {
        abortCtrl.abort("Hard timeout");
        resolve(makeTimeoutResult(serviceName));
      }, HARD_CONNECTOR_TIMEOUT);
    });
    const connectorPromise = (async () => {
      try {
        const result2 = await connector.collect(domain, cfgWithAbort);
        return result2;
      } catch (err) {
        return {
          connector: serviceName,
          domain,
          observations: [],
          errors: [`Connector error: ${err.message}`],
          durationMs: Date.now() - connStart,
          rateLimited: false
        };
      }
    })();
    const result = await Promise.race([connectorPromise, timeoutPromise]);
    const connDuration = Date.now() - connStart;
    const hasAuthError = result.errors.some((e) => e.includes("401") || e.includes("Unauthorized") || e.includes("invalid") || e.includes("not configured") || e.includes("skipping"));
    const hasRateLimit = result.rateLimited;
    const isTimeout = result.errors.some((e) => e.includes("Hard timeout"));
    if (isTimeout) {
      console.log(`[PassiveRecon] ${serviceName} HARD TIMEOUT after ${(connDuration / 1e3).toFixed(1)}s \u2014 abandoned`);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: "failed", error: `Hard timeout (${HARD_CONNECTOR_TIMEOUT / 1e3}s)`, durationMs: connDuration });
    } else if (hasAuthError) {
      const classified = classifyError(new Error(result.errors[0]), serviceName);
      recordFailure(serviceName, classified, cbConfig);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: "skipped", error: result.errors[0], durationMs: connDuration });
    } else if (hasRateLimit) {
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: "failed", error: "Rate limited", observations: result.observations.length, durationMs: connDuration });
    } else if (result.errors.length > 0 && result.observations.length === 0) {
      const classified = classifyError(new Error(result.errors[0]), serviceName);
      recordFailure(serviceName, classified, cbConfig);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: "failed", error: result.errors[0], observations: 0, durationMs: connDuration });
    } else {
      recordSuccess(serviceName);
      trackCall(serviceName, true);
      await onConnectorProgress?.({ connector: serviceName, status: "completed", observations: result.observations.length, durationMs: connDuration });
    }
    return result;
  }
  const allConnectorPromises = mainConnectors.map((connector) => {
    return new Promise(async (resolve) => {
      while (activeCount >= maxConcurrent) {
        await new Promise((r) => setTimeout(r, 100));
      }
      if (Date.now() - reconStart >= GLOBAL_RECON_TIMEOUT) {
        connectorResults.push({
          connector: connector.name,
          domain,
          observations: [],
          errors: ["Global recon timeout reached \u2014 skipped"],
          durationMs: 0,
          rateLimited: false
        });
        resolve();
        return;
      }
      activeCount++;
      try {
        const result = await runSingleConnector(connector);
        connectorResults.push(result);
      } catch (err) {
        connectorResults.push({
          connector: connector.name,
          domain,
          observations: [],
          errors: [`Unexpected error: ${err.message}`],
          durationMs: 0,
          rateLimited: false
        });
      } finally {
        activeCount--;
        resolve();
      }
    });
  });
  await Promise.all(allConnectorPromises);
  if (backgroundConnectors.length > 0 && Date.now() - reconStart < GLOBAL_RECON_TIMEOUT) {
    const bgTimeout = Math.min(45e3, GLOBAL_RECON_TIMEOUT - (Date.now() - reconStart));
    console.log(`[PassiveRecon] Starting background connectors (${bgTimeout / 1e3}s budget remaining)`);
    const bgPromises = backgroundConnectors.map(async (connector) => {
      try {
        const result = await runSingleConnector(connector);
        connectorResults.push(result);
      } catch (err) {
        connectorResults.push({
          connector: connector.name,
          domain,
          observations: [],
          errors: [`Background connector error: ${err.message}`],
          durationMs: 0,
          rateLimited: false
        });
      }
    });
    const bgTimeoutPromise = new Promise((resolve) => setTimeout(resolve, bgTimeout));
    await Promise.race([Promise.all(bgPromises), bgTimeoutPromise]);
    console.log(`[PassiveRecon] Background connectors finished or timed out`);
  } else if (backgroundConnectors.length > 0) {
    for (const c of backgroundConnectors) {
      connectorResults.push({
        connector: c.name,
        domain,
        observations: [],
        errors: ["Skipped: global timeout reached before background queue"],
        durationMs: 0,
        rateLimited: false
      });
    }
  }
  for (const b of blocked) {
    connectorResults.push({
      connector: b.name,
      domain,
      observations: [],
      errors: [`Skipped: ${b.reason}`],
      durationMs: 0,
      rateLimited: false
    });
  }
  const seenAssets = /* @__PURE__ */ new Set();
  let allObservations = [];
  for (const result of connectorResults) {
    for (const obs of result.observations) {
      if (!seenAssets.has(obs.assetId)) {
        seenAssets.add(obs.assetId);
        allObservations.push(obs);
      }
    }
  }
  let wildcardResult = null;
  try {
    wildcardResult = await detectWildcardDns(domain, 5e3);
    if (wildcardResult.isWildcard) {
      console.log(`[PassiveRecon] \u26A0\uFE0F Wildcard DNS detected for ${domain} \u2014 IPs: ${wildcardResult.wildcardIps.join(", ")}`);
      allObservations = tagWildcardObservations(allObservations, wildcardResult);
    }
  } catch (err) {
    console.log(`[PassiveRecon] Wildcard detection failed for ${domain}: ${err.message}`);
  }
  const riskSignals = classifySignals(allObservations);
  const signalRules = getSignalRuleDescriptions();
  const corroboration = corroborateFindings(connectorResults, riskSignals);
  const corroboratedSignals = corroboration.adjustedSignals;
  const byAssetType = {};
  const bySource = {};
  for (const obs of allObservations) {
    byAssetType[obs.assetType] = (byAssetType[obs.assetType] || 0) + 1;
    bySource[obs.source] = (bySource[obs.source] || 0) + 1;
  }
  const bySeverity = {};
  for (const sig of corroboratedSignals) {
    bySeverity[sig.severity] = (bySeverity[sig.severity] || 0) + 1;
  }
  const connectorStats = connectorResults.map((r) => ({
    name: r.connector,
    observations: r.observations.length,
    errors: r.errors.length,
    durationMs: r.durationMs,
    rateLimited: r.rateLimited,
    skipped: blocked.some((b) => b.name === r.connector),
    skipReason: blocked.find((b) => b.name === r.connector)?.reason
  }));
  const discoveryCoverage = computeDiscoveryCoverage(connectorResults, allObservations);
  console.log(`[PassiveRecon] Red team discovery coverage: ${discoveryCoverage.coverageScore}% (${discoveryCoverage.prioritiesCovered}/10 priorities)`);
  if (wildcardResult?.isWildcard) {
    const wcSignal = createWildcardSignal(domain, wildcardResult);
    corroboratedSignals.push(wcSignal);
  }
  return {
    domain,
    scanMode,
    scanModeDescription,
    connectorResults,
    allObservations,
    riskSignals: corroboratedSignals,
    signalRules,
    corroboration,
    discoveryCoverage,
    wildcardDetection: wildcardResult ? {
      isWildcard: wildcardResult.isWildcard,
      wildcardIps: wildcardResult.wildcardIps,
      durationMs: wildcardResult.durationMs
    } : null,
    summary: {
      totalObservations: allObservations.length,
      totalSignals: corroboratedSignals.length,
      connectorStats,
      byAssetType,
      bySeverity,
      bySource,
      corroborationRate: corroboration.stats.corroborationRate
    },
    durationMs: Date.now() - start
  };
}
var ALL_CONNECTORS, LAB_DOMAIN_PATTERNS, LAB_FAST_TRACK_CONNECTORS;
var init_passive = __esm({
  "server/lib/passive/index.ts"() {
    init_api_resilience();
    init_crtsh();
    init_shodan();
    init_wayback();
    init_censys();
    init_urlscan();
    init_rdap();
    init_ripestat();
    init_securitytrails();
    init_dehashed();
    init_shodan_internetdb();
    init_coalition_control();
    init_greynoise();
    init_email_security();
    init_http_security();
    init_cloud_assets();
    init_container_discovery();
    init_dns_deep();
    init_github_leaks();
    init_github_recon();
    init_cloud_bucket_recon();
    init_virustotal();
    init_hibp();
    init_whoisxml();
    init_leakix();
    init_fullhunt();
    init_netlas();
    init_hunter();
    init_social_media();
    init_abuseipdb();
    init_passivetotal();
    init_intelx_search();
    init_hudson_rock();
    init_leakcheck();
    init_company_intel();
    init_threatminer();
    init_ip_api();
    init_bgpview();
    init_ransomware_live();
    init_threatfox();
    init_builtwith();
    init_circl_pdns();
    init_commoncrawl();
    init_reverse_whois();
    init_typosquat();
    init_domain_health();
    init_alienvault_otx();
    init_google_safebrowsing();
    init_phishtank();
    init_darkweb_crossref();
    init_dehashed_whois();
    init_anubis();
    init_hackertarget();
    init_rapiddns();
    init_dnsrepo();
    init_sitedossier();
    init_favicon_hash();
    init_jarm_fingerprint();
    init_dns_zone_transfer();
    init_wayback_diff();
    init_urlhaus();
    init_malwarebazaar();
    init_sec_edgar();
    init_osv_dev();
    init_team_cymru();
    init_cisa_advisories();
    init_feodo_tracker();
    init_sslbl();
    init_github_advisories();
    init_certspotter();
    init_companies_house();
    init_opencorporates();
    init_hc3();
    init_wildcard_detection();
    init_passive_guard();
    init_signal_classifier();
    init_corroboration_engine();
    init_redteam_discovery_coverage();
    init_passive_guard();
    init_signal_classifier();
    ALL_CONNECTORS = [
      shodanInternetDBConnector,
      // Free fast-path — runs first for instant CVE/port data
      crtshConnector,
      shodanConnector,
      waybackConnector,
      censysConnector,
      urlscanConnector,
      rdapConnector,
      ripestatConnector,
      securitytrailsConnector,
      dehashedConnector,
      coalitionControlConnector,
      // Coalition Control ASM — replaces BinaryEdge (shut down March 2025)
      // binaryedgeConnector,     // DEPRECATED: BinaryEdge API shut down March 31, 2025 — replaced by Coalition Control
      greynoiseConnector,
      // Threat pressure context
      emailSecurityConnector,
      // Email security posture (DMARC/SPF/DKIM)
      httpSecurityConnector,
      // HTTP security headers & WAF detection
      cloudAssetsConnector,
      // Cloud storage enumeration (S3/Azure/GCP)
      containerDiscoveryConnector,
      // Container infrastructure discovery (Docker/K8s/registries)
      dnsDeepConnector,
      // Comprehensive DNS record analysis
      githubLeaksConnector,
      // GitHub code leak scanner (Priority #10)
      // --- New OSINT sources (SpiderFoot-class expansion) ---
      virustotalConnector,
      // VirusTotal — file/URL/domain reputation & malware analysis
      hibpConnector,
      // Have I Been Pwned — breach exposure & credential leaks
      whoisxmlConnector,
      // WhoisXML — WHOIS records, DNS, subdomain enum
      leakixConnector,
      // LeakIX — exposed services & data leaks
      fullhuntConnector,
      // FullHunt — attack surface discovery
      netlasConnector,
      // Netlas.io — internet-wide host scanning & DNS history
      hunterConnector,
      // Hunter.io — email discovery & org intelligence
      socialMediaConnector,
      // Social media — GitHub org/user presence & code exposure
      abuseipdbConnector,
      // AbuseIPDB — IP abuse reputation scoring
      passivetotalConnector,
      // PassiveTotal — passive DNS, SSL history, host attributes
      // --- Enhanced Recon Modules ---
      githubReconConnector,
      // Enhanced GitHub recon — org discovery, repo enum, CI/CD, secrets, dorks
      cloudBucketReconConnector,
      // Enhanced cloud bucket recon — 5 providers, permission depth, sensitive files
      // --- OSINT Pipeline Expansion (Gap Analysis v2) ---
      intelxSearchConnector,
      // Intelligence X — darkweb/paste/leak search (requires API key)
      hudsonRockConnector,
      // Hudson Rock — stealer log exposure (requires API key)
      leakcheckConnector,
      // LeakCheck — credential leak search (requires API key)
      companyIntelConnector,
      // Company Intelligence — firmographic data via web scraping + LLM
      threatminerConnector,
      // ThreatMiner — free threat intel (passive DNS, malware, APT reports)
      ipApiConnector,
      // ip-api.com — free IP geolocation, ASN, org info
      bgpviewConnector,
      // BGPView — free ASN lookup, network topology, IP prefixes
      ransomwareLiveConnector,
      // Ransomware.live — free ransomware victim tracking
      threatfoxConnector,
      // ThreatFox (abuse.ch) — free IOC database
      builtwithConnector,
      // BuiltWith — free tech stack detection
      circlPdnsConnector,
      // CIRCL Passive DNS — free historical DNS resolution
      commoncrawlConnector,
      // CommonCrawl — free historical web data for company context
      reverseWhoisConnector,
      // Reverse WHOIS — free related domain discovery via crt.sh
      typosquatConnector,
      // Typosquat Generator — free lookalike domain detection for phishing
      // --- Domain Health (MXToolbox-equivalent) ---
      domainHealthConnector,
      // Domain Health — DNSBL blacklist, SMTP test, PTR, DNS health, IP block, TCP connectivity
      // --- Threat Intel Expansion (Gap Analysis P0) ---
      alienvaultOtxConnector,
      // AlienVault OTX — free threat intel exchange, pulses, passive DNS, malware
      googleSafeBrowsingConnector,
      // Google SafeBrowsing — malware, phishing, unwanted software detection
      phishtankConnector,
      // PhishTank — community-verified phishing URL database
      // --- Dark Web Cross-Reference (Local DB) ---
      darkwebCrossrefConnector,
      // Cross-references domain against local underground intel DB (ransomware, IAB, data leaks)
      // --- Dehashed WHOIS & Subdomain Scan ---
      dehashedWhoisConnector,
      // Dehashed WHOIS — registration data, reverse WHOIS, subdomain scan
      // --- Free Subdomain Enumeration Sources (Audit R2) ---
      anubisConnector,
      // Anubis — free subdomain enum via jldc.me (CT + DNS aggregation)
      hackertargetConnector,
      // HackerTarget — free host search (100 queries/day)
      rapiddnsConnector,
      // RapidDNS — free subdomain enum from DNS zone files
      dnsrepoConnector,
      // DNSRepo — free subdomain enum from DNS zone file database
      sitedossierConnector,
      // Sitedossier — free subdomain enum from web crawl database
      // --- Infrastructure Discovery (Audit R10, R11) ---
      faviconHashConnector,
      // Favicon Hash — MMH3 hash for Shodan infrastructure discovery
      jarmFingerprintConnector,
      // JARM — TLS fingerprinting to detect C2, CDN, server software
      // --- DNS Security (Audit R13) ---
      dnsZoneTransferConnector,
      // DNS Zone Transfer — AXFR attempt against nameservers
      // --- Historical Analysis (Audit R14) ---
      waybackDiffConnector,
      // Wayback Diff — historical content analysis for removed admin panels, leaked creds
      // --- Tier 1 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
      urlhausConnector,
      // URLhaus (abuse.ch) — free malicious URL database
      malwarebazaarConnector,
      // MalwareBazaar (abuse.ch) — free malware sample database
      secEdgarConnector,
      // SEC EDGAR — free US public company filings for BIA context
      osvDevConnector,
      // OSV.dev — free open source vulnerability database (supply chain)
      teamCymruConnector,
      // Team Cymru — authoritative IP-to-ASN mapping via DNS
      cisaAdvisoriesConnector,
      // CISA Advisories — KEV catalog & ICS advisories
      // --- Tier 2 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
      feodoTrackerConnector,
      // Feodo Tracker (abuse.ch) — botnet C2 infrastructure tracking
      sslblConnector,
      // SSLBL (abuse.ch) — SSL certificate blacklist for C2/malware
      githubAdvisoriesConnector,
      // GitHub Security Advisories — GHSA vulnerability database
      certspotterConnector,
      // Certspotter (SSLMate) — CT log monitoring & subdomain discovery
      companiesHouseConnector,
      // Companies House (UK) — corporate registry for BIA context
      opencorporatesConnector,
      // OpenCorporates — global corporate registry (140M+ companies)
      hc3Connector
      // HC3 (HHS) — healthcare sector cybersecurity threat intel
    ];
    LAB_DOMAIN_PATTERNS = [
      /\.lab\.aceofcloud\.io$/i,
      /\.lab\.aceofcloud\.com$/i,
      /\.training\.aceofcloud\./i,
      /\.test\.aceofcloud\./i,
      /\.ctf\.aceofcloud\./i,
      /^(dvwa|juiceshop|bwapp|mutillidae|webgoat|altoro|dvbank|hackazon|bodgeit|railsgoat)/i
    ];
    LAB_FAST_TRACK_CONNECTORS = /* @__PURE__ */ new Set([
      "crtsh",
      // Certificate transparency — works for any domain with a cert
      "dns_deep",
      // DNS records — works for any resolvable domain
      "http_security",
      // HTTP headers — works for any reachable web server
      "email_security",
      // DMARC/SPF/DKIM — works via DNS
      "rdap",
      // RDAP/WHOIS — fast fail for lab domains, minimal cost
      "shodan_internetdb",
      // Free Shodan InternetDB — fast, no API key needed
      "ip_api",
      // Free IP geolocation — works for any IP
      "wayback",
      // Wayback Machine — fast fail for lab domains
      "container_discovery",
      // Docker/K8s discovery — works for lab infra
      "domain_health",
      // Domain health — DNSBL, SMTP, PTR, DNS health (no API key needed)
      // --- Audit R2: Free subdomain sources ---
      "anubis",
      // Anubis — free subdomain enum (no API key)
      "hackertarget",
      // HackerTarget — free host search (no API key)
      "rapiddns",
      // RapidDNS — free subdomain enum (no API key)
      "dnsrepo",
      // DNSRepo — free subdomain enum (no API key)
      "sitedossier",
      // Sitedossier — free subdomain enum (no API key)
      // --- Audit R10, R11, R13, R14 ---
      "favicon_hash",
      // Favicon hash — local computation (no API key)
      "jarm_fingerprint",
      // JARM — direct TLS probe (no API key)
      "dns_zone_transfer",
      // DNS zone transfer — direct DNS query (no API key)
      "wayback_diff"
      // Wayback diff — free Wayback CDX API (no API key)
    ]);
  }
});

export {
  getSignalRuleDescriptions,
  ALL_CONNECTORS,
  isLabDomain,
  runPassiveRecon,
  init_passive
};
