/**
 * urlscan.io — Website Scanner & Intelligence Connector
 * 
 * Searches urlscan.io's public scan database for previously scanned pages
 * matching the target domain. Returns page metadata, technologies, IPs, and screenshots.
 * 
 * Method: Queries urlscan.io Search API with domain filter
 * Data Source: urlscan.io community scan database (user-submitted URL scans)
 * Attribution: Each observation links to the urlscan.io result page for verification
 * Requires: URLSCAN_API_KEY (optional — free tier works without key, limited to 100/day)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const urlscanConnector: PassiveConnector = {
  name: "urlscan",
  description: "Website intelligence search — discovers page metadata, technologies, and IPs from urlscan.io community scans",
  requiresApiKey: false,
  freeUrl: "https://urlscan.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (apiKey) headers["API-Key"] = apiKey;

      const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: any;
      try {
        const res = await fetch(url, { headers, signal: controller.signal });
        if (res.status === 429) return { connector: "urlscan", domain, observations: [], errors: ["urlscan.io rate limit exceeded"], durationMs: Date.now() - start, rateLimited: true };
        if (!res.ok) throw new Error(`urlscan.io returned ${res.status}`);
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const now = new Date();
      const results = data?.results || [];
      const seenPages = new Set<string>();

      for (const result of results) {
        const page = result.page || {};
        const task = result.task || {};
        const pageUrl = page.url || task.url || "";
        const pageDomain = page.domain || "";
        const ip = page.ip || "";
        const server = page.server || "";
        const asn = page.asn ? parseInt(page.asn.replace("AS", ""), 10) : undefined;

        if (!pageDomain.endsWith(`.${domain}`) && pageDomain !== domain) continue;

        const pageKey = `${pageDomain}|${pageUrl}`;
        if (seenPages.has(pageKey)) continue;
        seenPages.add(pageKey);

        observations.push({
          assetId: makeAssetId(domain, pageKey, "urlscan"),
          domain,
          assetType: "url",
          name: pageUrl,
          ip: ip || undefined,
          asn: isNaN(asn as number) ? undefined : asn,
          source: "urlscan",
          observedAt: now,
          firstSeen: task.time ? new Date(task.time) : undefined,
          tags: [
            ...(server ? [`server:${server}`] : []),
            ...(page.tlsIssuer ? ["tls_enabled"] : []),
            `status:${page.status || "unknown"}`,
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
            screenshot: result.screenshot,
          },
          attribution: {
            provider: "urlscan.io (Website Intelligence)",
            url: `https://urlscan.io/result/${result._id}/`,
            method: `urlscan.io community scan database — found previously scanned page at ${pageUrl} with server ${server || "unknown"}`,
            verifyUrl: `https://urlscan.io/result/${result._id}/`,
          },
        });

        // Also create subdomain observation
        if (pageDomain !== domain) {
          observations.push({
            assetId: makeAssetId(domain, pageDomain, "urlscan_sub"),
            domain,
            assetType: "subdomain",
            name: pageDomain,
            ip: ip || undefined,
            source: "urlscan",
            observedAt: now,
            tags: ["urlscan_discovered"],
            evidence: { resolved_ip: ip, server, scan_id: result._id },
            attribution: {
              provider: "urlscan.io (Website Intelligence)",
              url: `https://urlscan.io/result/${result._id}/`,
              method: `Subdomain discovered via urlscan.io community scans — ${pageDomain} was scanned and found resolving to ${ip}`,
              verifyUrl: `https://urlscan.io/search/#domain:${pageDomain}`,
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`urlscan.io error: ${err.message}`);
    }

    return { connector: "urlscan", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
