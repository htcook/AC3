/**
 * AbuseIPDB — IP Reputation & Abuse Reporting Connector
 *
 * Queries the AbuseIPDB API for IP abuse intelligence:
 * - IP abuse confidence scores
 * - Report history and categories
 * - CIDR block checks
 *
 * Method: REST API v2 with Key header
 * Data Source: AbuseIPDB crowdsourced abuse database
 * Free tier: 1000 checks/day
 * Paid tier: Higher limits, bulk operations
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const abuseipdbConnector: PassiveConnector = {
  name: "abuseipdb",
  description: "AbuseIPDB — IP abuse confidence scoring, report history, and threat categorization",
  requiresApiKey: true,
  freeUrl: "https://www.abuseipdb.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const apiKey = config?.apiKey;
    let rateLimited = false;

    if (!apiKey) {
      return { connector: "abuseipdb", domain, observations: [], errors: ["No API key provided"], durationMs: 0, rateLimited: false };
    }

    try {
      // First resolve the domain to IPs, then check each IP
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        // Use DNS resolution to get IPs for the domain
        const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
          signal: controller.signal,
        });
        clearTimeout(timer);

        const ips: string[] = [];
        if (dnsRes.ok) {
          const dnsData = await dnsRes.json();
          if (dnsData.Answer) {
            for (const ans of dnsData.Answer) {
              if (ans.type === 1 && ans.data) ips.push(ans.data); // A records
            }
          }
        }

        // Check each resolved IP against AbuseIPDB
        for (const ip of ips.slice(0, 10)) {
          await new Promise(r => setTimeout(r, 300)); // Rate limit spacing
          const controller2 = new AbortController();
          const timer2 = setTimeout(() => controller2.abort(), timeout);
          try {
            const res = await fetch(
              `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
              {
                headers: { "Key": apiKey, "Accept": "application/json" },
                signal: controller2.signal,
              }
            );
            clearTimeout(timer2);

            if (res.status === 429) {
              rateLimited = true;
              errors.push("Rate limited");
              break;
            } else if (res.ok) {
              const data = await res.json();
              const now = new Date();

              if (data.data) {
                const d = data.data;
                const severity = d.abuseConfidenceScore > 75 ? "critical"
                  : d.abuseConfidenceScore > 50 ? "high"
                  : d.abuseConfidenceScore > 25 ? "medium" : "low";

                observations.push({
                  assetId: makeAssetId(domain, `abuse-${ip}`, "abuseipdb"),
                  domain,
                  assetType: "ip",
                  name: domain,
                  ip,
                  source: "abuseipdb",
                  observedAt: now,
                  lastSeen: d.lastReportedAt ? new Date(d.lastReportedAt) : undefined,
                  tags: [
                    "ip-reputation",
                    "abuse-check",
                    `severity:${severity}`,
                    `confidence:${d.abuseConfidenceScore}`,
                    d.isWhitelisted ? "whitelisted" : "",
                    d.isTor ? "tor-exit" : "",
                    d.totalReports > 0 ? "reported" : "clean",
                    ...(d.reports || []).slice(0, 5).map((r: any) => {
                      const categories: Record<number, string> = {
                        1: "dns-compromise", 2: "dns-poisoning", 3: "fraud-orders",
                        4: "ddos", 5: "ftp-brute", 6: "ping-of-death",
                        7: "phishing", 8: "fraud-voip", 9: "open-proxy",
                        10: "web-spam", 11: "email-spam", 14: "port-scan",
                        15: "hacking", 16: "sql-injection", 17: "spoofing",
                        18: "brute-force", 19: "bad-web-bot", 20: "exploited-host",
                        21: "web-app-attack", 22: "ssh", 23: "iot-targeted",
                      };
                      return (r.categories || []).map((c: number) => categories[c] || `cat:${c}`);
                    }).flat(),
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
                    recentReports: (d.reports || []).slice(0, 5).map((r: any) => ({
                      reportedAt: r.reportedAt,
                      comment: (r.comment || "").slice(0, 200),
                      categories: r.categories,
                      reporterId: r.reporterId,
                      reporterCountryCode: r.reporterCountryCode,
                    })),
                  },
                  attribution: {
                    provider: "AbuseIPDB",
                    url: `https://www.abuseipdb.com/check/${ip}`,
                    method: "AbuseIPDB IP abuse check",
                    verifyUrl: `https://www.abuseipdb.com/check/${ip}`,
                  },
                });
              }
            }
          } catch (err: any) {
            if (err.name !== "AbortError") errors.push(`AbuseIPDB check ${ip}: ${err.message}`);
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") throw err;
        errors.push("DNS resolution timed out");
      }
    } catch (err: any) {
      errors.push(`AbuseIPDB error: ${err.message}`);
    }

    return {
      connector: "abuseipdb",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
