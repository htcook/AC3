/**
 * Active DNS & Banner Verification Module
 * 
 * Resolves hostnames via DNS and parses HTTP response headers to:
 * 1. Verify that inferred assets actually exist (DNS resolution)
 * 2. Extract real technology versions from Server/X-Powered-By headers
 * 3. Upgrade asset discoveryMethod from "inferred" to "dns_verified" or "header_detected"
 * 4. Populate technologyVersions with real version data for corroboration
 */

import dns from "dns/promises";
import type { DiscoveredAssetRaw } from "../domainIntel";

// ─── Types ───────────────────────────────────────────────────────────

export interface DnsVerificationResult {
  hostname: string;
  resolved: boolean;
  aRecords?: string[];
  aaaaRecords?: string[];
  cnameRecords?: string[];
  mxRecords?: Array<{ priority: number; exchange: string }>;
  txtRecords?: string[];
  nsRecords?: string[];
  error?: string;
}

export interface BannerVerificationResult {
  hostname: string;
  reachable: boolean;
  statusCode?: number;
  serverHeader?: string;
  poweredByHeader?: string;
  xGeneratorHeader?: string;
  contentTypeHeader?: string;
  setCookieHeaders?: string[];
  allHeaders?: Record<string, string>;
  detectedTechnologies: Array<{ name: string; version?: string; source: string }>;
  error?: string;
}

export interface VerificationResult {
  dns: DnsVerificationResult;
  banner?: BannerVerificationResult;
}

// ─── Version Extraction Patterns ─────────────────────────────────────

interface TechPattern {
  name: string;
  patterns: RegExp[];
}

const TECH_PATTERNS: TechPattern[] = [
  { name: "nginx", patterns: [/nginx\/([\d.]+)/i, /nginx/i] },
  { name: "Apache", patterns: [/Apache\/([\d.]+)/i, /Apache/i] },
  { name: "IIS", patterns: [/Microsoft-IIS\/([\d.]+)/i, /IIS/i] },
  { name: "OpenSSL", patterns: [/OpenSSL\/([\d.]+[a-z]?)/i] },
  { name: "PHP", patterns: [/PHP\/([\d.]+)/i] },
  { name: "Express", patterns: [/Express/i] },
  { name: "ASP.NET", patterns: [/ASP\.NET/i, /X-AspNet-Version:\s*([\d.]+)/i] },
  { name: "Cloudflare", patterns: [/cloudflare/i] },
  { name: "Amazon S3", patterns: [/AmazonS3/i] },
  { name: "Varnish", patterns: [/Varnish/i, /varnish\/([\d.]+)/i] },
  { name: "LiteSpeed", patterns: [/LiteSpeed/i, /LiteSpeed\/([\d.]+)/i] },
  { name: "Tomcat", patterns: [/Apache-Coyote\/([\d.]+)/i, /Tomcat/i] },
  { name: "Caddy", patterns: [/Caddy/i] },
  { name: "gunicorn", patterns: [/gunicorn\/([\d.]+)/i, /gunicorn/i] },
  { name: "Envoy", patterns: [/envoy/i] },
  { name: "HAProxy", patterns: [/HAProxy/i] },
  { name: "WordPress", patterns: [/WordPress\/([\d.]+)/i, /wp-/i] },
  { name: "Drupal", patterns: [/Drupal/i, /X-Drupal-Cache/i] },
  { name: "Django", patterns: [/WSGIServer/i, /django/i] },
  { name: "Rails", patterns: [/Phusion Passenger/i, /X-Powered-By:\s*Phusion/i] },
  { name: "Next.js", patterns: [/Next\.js/i, /x-nextjs/i] },
  { name: "Vercel", patterns: [/Vercel/i] },
  { name: "Netlify", patterns: [/Netlify/i] },
  { name: "Microsoft Exchange", patterns: [/Microsoft-HTTPAPI\/([\d.]+)/i, /X-OWA-Version:\s*([\d.]+)/i, /X-FEServer/i] },
  { name: "Citrix", patterns: [/Citrix/i, /NetScaler/i] },
  { name: "F5 BIG-IP", patterns: [/BIG-IP/i, /BigIP/i, /Set-Cookie:.*BIGipServer/i, /Server:.*\bF5\b/i] },
  { name: "Palo Alto", patterns: [/PanOS/i, /Palo Alto/i] },
  { name: "Fortinet", patterns: [/FortiGate/i, /Fortinet/i, /FortiOS/i] },
  { name: "SonicWall", patterns: [/SonicWALL/i, /SonicOS/i] },
];

/**
 * Extract technology names and versions from HTTP headers
 */
export function extractTechnologiesFromHeaders(
  headers: Record<string, string>
): Array<{ name: string; version?: string; source: string }> {
  const results: Array<{ name: string; version?: string; source: string }> = [];
  const seen = new Set<string>();

  // Combine all header values for pattern matching
  const headerString = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");

  // Also check specific headers individually
  const serverHeader = headers["server"] || headers["Server"] || "";
  const poweredBy = headers["x-powered-by"] || headers["X-Powered-By"] || "";
  const generator = headers["x-generator"] || headers["X-Generator"] || "";
  const setCookie = headers["set-cookie"] || headers["Set-Cookie"] || "";

  const allHeaderText = [headerString, serverHeader, poweredBy, generator, setCookie].join("\n");

  for (const tech of TECH_PATTERNS) {
    if (seen.has(tech.name)) continue;

    for (const pattern of tech.patterns) {
      const match = allHeaderText.match(pattern);
      if (match) {
        seen.add(tech.name);
        const version = match[1] || undefined;
        const source = serverHeader && pattern.test(serverHeader)
          ? "Server header"
          : poweredBy && pattern.test(poweredBy)
            ? "X-Powered-By header"
            : setCookie && pattern.test(setCookie)
              ? "Set-Cookie header"
              : "HTTP response headers";
        results.push({ name: tech.name, version, source });
        break;
      }
    }
  }

  return results;
}

// ─── DNS Resolution ──────────────────────────────────────────────────

/**
 * Resolve DNS records for a hostname with timeout
 */
export async function verifyDns(hostname: string, timeoutMs = 5000): Promise<DnsVerificationResult> {
  const result: DnsVerificationResult = { hostname, resolved: false };

  try {
    const resolver = new dns.Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);

    // Race against timeout
    const withTimeout = <T>(promise: Promise<T>, fallback: T): Promise<T> =>
      Promise.race([
        promise,
        new Promise<T>((resolve) => setTimeout(() => resolve(fallback), timeoutMs)),
      ]);

    // Resolve A records (primary check)
    try {
      const aRecords = await withTimeout(resolver.resolve4(hostname), []);
      if (aRecords.length > 0) {
        result.resolved = true;
        result.aRecords = aRecords;
      }
    } catch { /* no A records */ }

    // Resolve AAAA records
    try {
      const aaaaRecords = await withTimeout(resolver.resolve6(hostname), []);
      if (aaaaRecords.length > 0) {
        result.resolved = true;
        result.aaaaRecords = aaaaRecords;
      }
    } catch { /* no AAAA records */ }

    // Resolve CNAME records
    try {
      const cnameRecords = await withTimeout(resolver.resolveCname(hostname), []);
      if (cnameRecords.length > 0) {
        result.resolved = true;
        result.cnameRecords = cnameRecords;
      }
    } catch { /* no CNAME records */ }

    // Resolve MX records (useful for mail servers)
    try {
      const mxRecords = await withTimeout(resolver.resolveMx(hostname), []);
      if (mxRecords.length > 0) {
        result.resolved = true;
        result.mxRecords = mxRecords;
      }
    } catch { /* no MX records */ }

    // Resolve TXT records (SPF, DMARC, etc.)
    try {
      const txtRecords = await withTimeout(resolver.resolveTxt(hostname), []);
      if (txtRecords.length > 0) {
        result.txtRecords = txtRecords.map(r => r.join(""));
      }
    } catch { /* no TXT records */ }

    // Resolve NS records
    try {
      const nsRecords = await withTimeout(resolver.resolveNs(hostname), []);
      if (nsRecords.length > 0) {
        result.nsRecords = nsRecords;
      }
    } catch { /* no NS records */ }

  } catch (err: any) {
    result.error = err.message || "DNS resolution failed";
  }

  return result;
}

// ─── HTTP Banner Grabbing ────────────────────────────────────────────

/**
 * Fetch HTTP headers from a hostname to detect technologies and versions
 */
export async function verifyBanner(hostname: string, timeoutMs = 8000): Promise<BannerVerificationResult> {
  const result: BannerVerificationResult = {
    hostname,
    reachable: false,
    detectedTechnologies: [],
  };

  // Try HTTPS first, then HTTP
  const urls = [
    `https://${hostname}`,
    `http://${hostname}`,
  ];

  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(url, {
        method: "HEAD",
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; AceC3-Scanner/1.0; +https://aceofcloud.com)",
        },
      });

      clearTimeout(timer);

      result.reachable = true;
      result.statusCode = response.status;

      // Extract all headers into a flat object
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      result.allHeaders = headers;

      // Extract specific headers
      result.serverHeader = headers["server"] || undefined;
      result.poweredByHeader = headers["x-powered-by"] || undefined;
      result.xGeneratorHeader = headers["x-generator"] || undefined;
      result.contentTypeHeader = headers["content-type"] || undefined;

      // Extract technologies from headers
      result.detectedTechnologies = extractTechnologiesFromHeaders(headers);

      // If HEAD fails with 405, try GET with a small body
      if (response.status === 405) {
        try {
          const getController = new AbortController();
          const getTimer = setTimeout(() => getController.abort(), timeoutMs);
          const getResponse = await fetch(url, {
            method: "GET",
            signal: getController.signal,
            redirect: "follow",
            headers: {
              "User-Agent": "Mozilla/5.0 (compatible; AceC3-Scanner/1.0; +https://aceofcloud.com)",
            },
          });
          clearTimeout(getTimer);

          const getHeaders: Record<string, string> = {};
          getResponse.headers.forEach((value, key) => {
            getHeaders[key.toLowerCase()] = value;
          });

          // Merge any additional tech detections
          const additionalTechs = extractTechnologiesFromHeaders(getHeaders);
          for (const tech of additionalTechs) {
            if (!result.detectedTechnologies.some(t => t.name === tech.name)) {
              result.detectedTechnologies.push(tech);
            }
          }

          // Consume body to prevent memory leaks
          await getResponse.text().catch(() => {});
        } catch { /* GET fallback failed */ }
      }

      break; // Success — don't try HTTP if HTTPS worked
    } catch (err: any) {
      result.error = err.message || "HTTP request failed";
      // Continue to try next URL (HTTP after HTTPS)
    }
  }

  return result;
}

// ─── Combined Verification ───────────────────────────────────────────

/**
 * Run DNS + banner verification on a single asset and return enriched asset data
 */
export async function verifyAsset(asset: DiscoveredAssetRaw): Promise<{
  asset: DiscoveredAssetRaw;
  verification: VerificationResult;
}> {
  const hostname = asset.hostname;

  // Step 1: DNS verification
  const dnsResult = await verifyDns(hostname);

  // Step 2: Banner verification (only if DNS resolved or it's a root domain)
  let bannerResult: BannerVerificationResult | undefined;
  if (dnsResult.resolved) {
    bannerResult = await verifyBanner(hostname);
  }

  // Step 3: Enrich the asset based on verification results
  const enrichedAsset = { ...asset };

  if (dnsResult.resolved) {
    // Upgrade discovery method
    enrichedAsset.discoveryMethod = bannerResult?.reachable ? "header_detected" : "dns_verified";

    // Update DNS records
    enrichedAsset.dnsRecords = {
      ...(enrichedAsset.dnsRecords || {}),
      A: dnsResult.aRecords || [],
      AAAA: dnsResult.aaaaRecords || [],
      CNAME: dnsResult.cnameRecords || [],
      MX: dnsResult.mxRecords?.map(r => `${r.priority} ${r.exchange}`) || [],
      TXT: dnsResult.txtRecords || [],
      NS: dnsResult.nsRecords || [],
    };
    enrichedAsset.dnsStatus = "verified";

    // Build evidence string
    const evidenceParts: string[] = [];
    if (dnsResult.aRecords?.length) evidenceParts.push(`A records: ${dnsResult.aRecords.join(", ")}`);
    if (dnsResult.cnameRecords?.length) evidenceParts.push(`CNAME: ${dnsResult.cnameRecords.join(", ")}`);
    if (dnsResult.mxRecords?.length) evidenceParts.push(`MX: ${dnsResult.mxRecords.map(r => r.exchange).join(", ")}`);
    enrichedAsset.discoveryEvidence = `DNS verified: ${evidenceParts.join("; ") || "resolved successfully"}`;

    // Merge banner-detected technologies
    if (bannerResult?.reachable && bannerResult.detectedTechnologies.length > 0) {
      const existingTechs = new Set((enrichedAsset.technologies || []).map(t => t.toLowerCase()));
      const existingVersions = { ...(enrichedAsset.technologyVersions || {}) };

      for (const tech of bannerResult.detectedTechnologies) {
        // Add technology if not already present
        if (!existingTechs.has(tech.name.toLowerCase())) {
          enrichedAsset.technologies = [...(enrichedAsset.technologies || []), tech.name];
          existingTechs.add(tech.name.toLowerCase());
        }

        // Add or upgrade version info
        if (tech.version) {
          // Find existing key (case-insensitive)
          const existingKey = Object.keys(existingVersions).find(
            k => k.toLowerCase() === tech.name.toLowerCase()
          );
          if (existingKey) {
            existingVersions[existingKey] = tech.version;
          } else {
            existingVersions[tech.name] = tech.version;
          }
        }
      }

      enrichedAsset.technologyVersions = existingVersions;
      enrichedAsset.headers = bannerResult.serverHeader || enrichedAsset.headers;

      // Upgrade evidence
      const techDetails = bannerResult.detectedTechnologies
        .map(t => t.version ? `${t.name}/${t.version} (${t.source})` : `${t.name} (${t.source})`)
        .join(", ");
      enrichedAsset.discoveryEvidence = `DNS verified + HTTP banner: ${techDetails}. ${enrichedAsset.discoveryEvidence}`;
      enrichedAsset.discoveryMethod = "header_detected";
    }
  } else {
    // DNS did not resolve — asset remains inferred
    enrichedAsset.dnsStatus = "unresolved";
    enrichedAsset.discoveryEvidence = `DNS unresolved: ${hostname} did not resolve. ${enrichedAsset.discoveryEvidence || "Inferred from OSINT patterns."}`;
  }

  return {
    asset: enrichedAsset,
    verification: { dns: dnsResult, banner: bannerResult },
  };
}

/**
 * Verify all assets in parallel with concurrency limit
 */
export async function verifyAllAssets(
  assets: DiscoveredAssetRaw[],
  concurrency = 5,
  onProgress?: (completed: number, total: number) => void
): Promise<{
  assets: DiscoveredAssetRaw[];
  summary: {
    total: number;
    dnsVerified: number;
    bannerDetected: number;
    unresolved: number;
    technologiesFound: number;
    versionsFound: number;
  };
}> {
  const results: DiscoveredAssetRaw[] = [];
  let dnsVerified = 0;
  let bannerDetected = 0;
  let unresolved = 0;
  let technologiesFound = 0;
  let versionsFound = 0;

  // Process in batches for concurrency control
  for (let i = 0; i < assets.length; i += concurrency) {
    const batch = assets.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(asset => verifyAsset(asset))
    );

    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        const { asset } = result.value;
        results.push(asset);

        if (asset.discoveryMethod === "header_detected") {
          bannerDetected++;
        } else if (asset.discoveryMethod === "dns_verified") {
          dnsVerified++;
        } else {
          unresolved++;
        }

        const versions = asset.technologyVersions || {};
        const versionCount = Object.values(versions).filter(v => v && v !== "null").length;
        technologiesFound += (asset.technologies || []).length;
        versionsFound += versionCount;
      } else {
        // On failure, keep original asset
        const originalAsset = batch[batchResults.indexOf(result)];
        if (originalAsset) {
          results.push(originalAsset);
          unresolved++;
        }
      }
    }

    onProgress?.(Math.min(i + concurrency, assets.length), assets.length);
  }

  return {
    assets: results,
    summary: {
      total: assets.length,
      dnsVerified,
      bannerDetected,
      unresolved,
      technologiesFound,
      versionsFound,
    },
  };
}
