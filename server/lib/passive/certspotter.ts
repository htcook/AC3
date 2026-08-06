/**
 * Certspotter (SSLMate) Connector — Free Tier, No API Key Required
 * 
 * Monitors Certificate Transparency logs for certificates issued
 * for the target domain. Detects subdomain discovery, wildcard certs,
 * unauthorized issuance, and certificate lifecycle anomalies.
 * 
 * API docs: https://sslmate.com/help/reference/ct_search_api_v1
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const CERTSPOTTER_API = "https://api.certspotter.com/v1/issuances";

export const certspotterConnector: PassiveConnector = {
  name: "certspotter",
  description: "Certspotter (SSLMate) — Certificate Transparency log monitoring for subdomain discovery and cert anomalies",
  requiresApiKey: false,
  freeUrl: "https://sslmate.com/certspotter/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      const params = new URLSearchParams({
        domain: domain,
        include_subdomains: "true",
        expand: "dns_names,issuer",
        match_wildcards: "true",
      });

      const resp = await rateLimitedFetch("certspotter", `${CERTSPOTTER_API}?${params}`, {
        headers: {
          "User-Agent": "AC3-SecurityScanner/1.0",
        },
        signal: AbortSignal.timeout(15000),
      });

      if (resp.status === 429) {
        rateLimited = true;
        errors.push("Certspotter rate limited — free tier allows 100 queries/hour");
        return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      if (!resp.ok) {
        errors.push(`Certspotter returned ${resp.status}`);
        return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const issuances = await resp.json() as any[];
      if (!Array.isArray(issuances)) {
        errors.push("Unexpected Certspotter response format");
        return { connector: "certspotter", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Track unique subdomains discovered via CT logs
      const discoveredSubdomains = new Set<string>();
      const issuerStats: Record<string, number> = {};
      const wildcardCerts: any[] = [];
      let recentIssuances = 0;
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

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
          // Extract subdomain
          if (name.endsWith(`.${domain}`) || name === domain) {
            discoveredSubdomains.add(name.replace(/^\*\./, ""));
          }
        }
      }

      // Observation 1: Subdomain discovery via CT logs
      if (discoveredSubdomains.size > 0) {
        const subdomainList = Array.from(discoveredSubdomains).sort();
        const name = `CT Log Subdomains: ${discoveredSubdomains.size} discovered for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, "certspotter"),
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
            total_certificates: issuances.length,
          },
          attribution: {
            provider: "Certspotter (SSLMate)",
            url: "https://sslmate.com/certspotter/",
            method: "api",
          },
        });
      }

      // Observation 2: Wildcard certificates (potential attack surface)
      if (wildcardCerts.length > 0) {
        const name = `Wildcard Certs: ${wildcardCerts.length} wildcard certificates for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, "certspotter"),
          domain,
          assetType: "certificate",
          name,
          source: "certspotter",
          observedAt: now,
          tags: ["certspotter", "wildcard_cert", "certificate_transparency"],
          evidence: {
            severity: 4,
            confidence: 90,
            value: `${wildcardCerts.length} wildcard certificates detected — potential for subdomain takeover or misuse`,
            wildcard_count: wildcardCerts.length,
            wildcards: wildcardCerts.slice(0, 10).map(w => ({
              name: w.name,
              issuer: w.issuer,
              issued: w.notBefore,
            })),
          },
          attribution: {
            provider: "Certspotter (SSLMate)",
            url: "https://sslmate.com/certspotter/",
            method: "api",
          },
        });
      }

      // Observation 3: Certificate issuance velocity (high recent issuance = suspicious)
      if (recentIssuances > 5) {
        const name = `High Cert Velocity: ${recentIssuances} certs issued in last 30 days`;
        observations.push({
          assetId: makeAssetId(domain, name, "certspotter"),
          domain,
          assetType: "certificate",
          name,
          source: "certspotter",
          observedAt: now,
          tags: ["certspotter", "cert_velocity", "anomaly", "certificate_transparency"],
          evidence: {
            severity: recentIssuances > 20 ? 7 : 5,
            confidence: 70,
            value: `${recentIssuances} certificates issued in the last 30 days — unusually high issuance rate may indicate automated provisioning or abuse`,
            recent_issuances: recentIssuances,
            total_issuances: issuances.length,
          },
          attribution: {
            provider: "Certspotter (SSLMate)",
            url: "https://sslmate.com/certspotter/",
            method: "api",
          },
        });
      }

      // Observation 4: Issuer diversity (multiple CAs = complex PKI or potential issues)
      const issuerCount = Object.keys(issuerStats).length;
      if (issuerCount > 3) {
        const name = `Multi-CA: ${issuerCount} different certificate authorities for ${domain}`;
        const sortedIssuers = Object.entries(issuerStats)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 10);

        observations.push({
          assetId: makeAssetId(domain, name, "certspotter"),
          domain,
          assetType: "certificate",
          name,
          source: "certspotter",
          observedAt: now,
          tags: ["certspotter", "multi_ca", "certificate_transparency"],
          evidence: {
            severity: 3,
            confidence: 80,
            value: `${issuerCount} different CAs have issued certificates for ${domain} — may indicate decentralized PKI management`,
            issuer_count: issuerCount,
            issuers: sortedIssuers.map(([issuer, count]) => ({ issuer, count })),
          },
          attribution: {
            provider: "Certspotter (SSLMate)",
            url: "https://sslmate.com/certspotter/",
            method: "api",
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during Certspotter lookup");
    }

    return {
      connector: "certspotter",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
