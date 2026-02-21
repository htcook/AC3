/**
 * HTTP Security Headers Connector — Security Header & WAF Detection
 *
 * Performs a lightweight HEAD request to detect security headers, WAF
 * fingerprints, and server technology banners. Covers Red Team Top-10
 * #4 (Tech Stack) and #9 (Defensive Posture).
 *
 * Method: HTTP HEAD request to the target domain (minimal footprint)
 * Data Source: HTTP response headers
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const SECURITY_HEADERS = [
  { name: "strict-transport-security", label: "HSTS", critical: true },
  { name: "content-security-policy", label: "CSP", critical: true },
  { name: "x-content-type-options", label: "X-Content-Type-Options", critical: false },
  { name: "x-frame-options", label: "X-Frame-Options", critical: false },
  { name: "x-xss-protection", label: "X-XSS-Protection", critical: false },
  { name: "referrer-policy", label: "Referrer-Policy", critical: false },
  { name: "permissions-policy", label: "Permissions-Policy", critical: false },
  { name: "cross-origin-opener-policy", label: "COOP", critical: false },
  { name: "cross-origin-resource-policy", label: "CORP", critical: false },
  { name: "cross-origin-embedder-policy", label: "COEP", critical: false },
];

const WAF_SIGNATURES: Record<string, (headers: Record<string, string>) => boolean> = {
  "Cloudflare": (h) => !!(h["cf-ray"] || h["cf-cache-status"] || (h["server"] || "").toLowerCase().includes("cloudflare")),
  "AWS CloudFront": (h) => !!(h["x-amz-cf-id"] || h["x-amz-cf-pop"] || (h["via"] || "").includes("cloudfront")),
  "Akamai": (h) => !!(h["x-akamai-transformed"] || (h["server"] || "").toLowerCase().includes("akamai")),
  "Fastly": (h) => !!(h["x-fastly-request-id"] || h["fastly-debug-digest"]),
  "Sucuri": (h) => !!(h["x-sucuri-id"] || (h["server"] || "").toLowerCase().includes("sucuri")),
  "Imperva/Incapsula": (h) => !!(h["x-iinfo"] || h["x-cdn"] === "Imperva"),
  "F5 BIG-IP": (h) => !!(h["x-wa-info"] || (h["server"] || "").toLowerCase().includes("big-ip")),
  "ModSecurity": (h) => !!(h["server"] || "").toLowerCase().includes("mod_security"),
  "Azure Front Door": (h) => !!(h["x-azure-ref"] || h["x-fd-healthprobe"]),
};

export const httpSecurityConnector: PassiveConnector = {
  name: "http_security",
  description: "HTTP security headers and WAF detection — identifies defensive posture, missing security headers, and technology fingerprints",
  requiresApiKey: false,
  freeUrl: "https://securityheaders.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;
    const now = new Date();

    try {
      const url = `https://${domain}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let res: Response;
      try {
        res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow", headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" } });
      } finally {
        clearTimeout(timer);
      }

      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

      // Check security headers
      const securityHeaders = SECURITY_HEADERS.map(sh => {
        const value = headers[sh.name];
        return { name: sh.label, present: !!value, value, rating: value ? "good" as const : (sh.critical ? "missing" as const : "warning" as const), detail: value ? `${sh.label} is set: ${value.substring(0, 100)}` : `${sh.label} header is missing${sh.critical ? " (critical)" : ""}` };
      });

      const missingCritical = securityHeaders.filter(h => h.rating === "missing");
      const present = securityHeaders.filter(h => h.present);

      observations.push({
        assetId: makeAssetId(domain, `http_headers:${domain}`, "http_security"),
        domain, assetType: "url",
        name: `Security Headers: ${present.length}/${SECURITY_HEADERS.length} present${missingCritical.length > 0 ? ` (${missingCritical.length} critical missing)` : ""}`,
        source: "http_security", observedAt: now,
        tags: ["http_security", "security_headers", ...(missingCritical.length > 0 ? ["missing_critical_headers"] : [])],
        evidence: { statusCode: res.status, url: res.url || url, securityHeaders, presentCount: present.length, totalChecked: SECURITY_HEADERS.length, missingCritical: missingCritical.map(h => h.name) },
        attribution: { provider: "HTTP HEAD Request", method: `Sent HTTP HEAD request to https://${domain} and analyzed ${SECURITY_HEADERS.length} security headers`, verifyUrl: `https://securityheaders.com/?q=${domain}&followRedirects=on` },
      });

      // WAF detection
      let wafDetected: string | undefined;
      for (const [wafName, detector] of Object.entries(WAF_SIGNATURES)) {
        if (detector(headers)) { wafDetected = wafName; break; }
      }

      observations.push({
        assetId: makeAssetId(domain, `waf:${domain}`, "http_security"),
        domain, assetType: "url",
        name: wafDetected ? `WAF Detected: ${wafDetected}` : "WAF: Not detected",
        source: "http_security", observedAt: now,
        tags: ["http_security", ...(wafDetected ? ["waf_detected", `waf:${wafDetected.toLowerCase().replace(/[^a-z0-9]/g, "_")}`] : ["no_waf_detected"])],
        evidence: { wafName: wafDetected, detectionMethod: "HTTP response header fingerprinting" },
        attribution: { provider: "HTTP Header WAF Fingerprinting", method: wafDetected ? `Detected ${wafDetected} WAF from HTTP response headers on ${domain}` : `Checked ${Object.keys(WAF_SIGNATURES).length} WAF signatures against HTTP response headers from ${domain}` },
      });

      // Tech fingerprints
      const techFingerprints: string[] = [];
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
          assetId: makeAssetId(domain, `tech:${domain}`, "http_security"),
          domain, assetType: "url",
          name: `Tech: ${techFingerprints.slice(0, 3).join(", ") || serverBanner || "unknown"}`,
          source: "http_security", observedAt: now,
          tags: ["http_security", "tech_fingerprint", ...(serverBanner ? [`server:${serverBanner.split("/")[0].toLowerCase()}`] : [])],
          evidence: { serverBanner, techFingerprints, poweredBy: headers["x-powered-by"] },
          attribution: { provider: "HTTP Header Technology Fingerprinting", method: `Extracted technology fingerprints from HTTP response headers on ${domain}` },
        });
      }
    } catch (err: any) {
      errors.push(`HTTP security check error: ${err.message}`);
    }

    return { connector: "http_security", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
