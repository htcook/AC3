/**
 * Feodo Tracker (abuse.ch) Connector — Free, No API Key
 * 
 * Tracks botnet C2 infrastructure (Dridex, Emotet, TrickBot, QakBot, BazarLoader).
 * Checks if any IPs associated with the target domain appear in the Feodo blocklist.
 * 
 * Data source: https://feodotracker.abuse.ch/
 * API docs: https://feodotracker.abuse.ch/blocklist/
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const RECENT_C2_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";

export const feodoTrackerConnector: PassiveConnector = {
  name: "feodo_tracker",
  description: "Feodo Tracker (abuse.ch) — botnet C2 infrastructure tracking (Dridex, Emotet, TrickBot, QakBot)",
  requiresApiKey: false,
  freeUrl: "https://feodotracker.abuse.ch",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Step 1: Resolve domain IPs via DNS-over-HTTPS
      const dnsRes = await rateLimitedFetch("feodo_tracker", `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
        signal: AbortSignal.timeout(8000),
      });
      const dnsData = await dnsRes.json() as any;
      const domainIps = new Set<string>();
      if (dnsData?.Answer) {
        for (const ans of dnsData.Answer) {
          if (ans.type === 1 && ans.data) domainIps.add(ans.data);
        }
      }

      // Step 2: Fetch Feodo recommended blocklist (recent C2 IPs)
      const resp = await rateLimitedFetch("feodo_tracker", RECENT_C2_URL, {
        signal: AbortSignal.timeout(15000),
      });

      if (!resp.ok) {
        errors.push(`Feodo Tracker returned ${resp.status}`);
        return { connector: "feodo_tracker", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const c2List = await resp.json() as any[];

      if (!Array.isArray(c2List)) {
        errors.push("Unexpected Feodo Tracker response format");
        return { connector: "feodo_tracker", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Step 3: Check if any domain IPs match C2 infrastructure
      const matches: any[] = [];
      for (const entry of c2List) {
        if (domainIps.has(entry.ip_address)) {
          matches.push(entry);
        }
      }

      // Step 4: Also check if domain appears in any C2 hostname fields
      for (const entry of c2List) {
        if (entry.hostname && (
          entry.hostname === domain ||
          entry.hostname.endsWith(`.${domain}`)
        )) {
          if (!matches.find(m => m.ip_address === entry.ip_address)) {
            matches.push(entry);
          }
        }
      }

      // Step 5: Generate observations for matches
      for (const match of matches.slice(0, 20)) {
        const malwareFamily = match.malware || "unknown";
        const name = `Feodo C2: ${match.ip_address} (${malwareFamily})`;
        
        observations.push({
          assetId: makeAssetId(domain, name, "feodo_tracker"),
          domain,
          assetType: "breach",
          name,
          source: "feodo_tracker",
          observedAt: now,
          firstSeen: match.first_seen ? new Date(match.first_seen) : undefined,
          lastSeen: match.last_seen ? new Date(match.last_seen) : undefined,
          tags: ["feodo_tracker", "c2", "botnet", malwareFamily.toLowerCase(), "abuse_ch"],
          evidence: {
            severity: 10, // C2 infrastructure is always critical
            confidence: 95,
            value: `Active botnet C2 infrastructure detected — ${malwareFamily} at ${match.ip_address}:${match.port || "unknown"}`,
            ip_address: match.ip_address,
            port: match.port,
            malware: malwareFamily,
            status: match.status || "unknown",
            as_number: match.as_number,
            as_name: match.as_name,
            country: match.country,
            first_seen: match.first_seen,
            last_seen: match.last_seen,
          },
          attribution: {
            provider: "Feodo Tracker (abuse.ch)",
            url: "https://feodotracker.abuse.ch/",
            method: "blocklist",
          },
        });
      }

      // Step 6: Even if no direct matches, check for related ASN overlap
      if (matches.length === 0 && domainIps.size > 0) {
        // Count C2s in same /24 subnet as a proximity signal
        const domainSubnets = new Set<string>();
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
            assetId: makeAssetId(domain, name, "feodo_tracker"),
            domain,
            assetType: "network",
            name,
            source: "feodo_tracker",
            observedAt: now,
            tags: ["feodo_tracker", "c2_proximity", "network_risk", "abuse_ch"],
            evidence: {
              severity: 4,
              confidence: 60,
              value: `${nearbyC2Count} known botnet C2 IPs found in the same /24 subnet as ${domain} — potential neighborhood risk`,
              nearby_c2_count: nearbyC2Count,
              domain_ips: Array.from(domainIps),
            },
            attribution: {
              provider: "Feodo Tracker (abuse.ch)",
              url: "https://feodotracker.abuse.ch/",
              method: "blocklist",
            },
          });
        }
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during Feodo Tracker lookup");
    }

    return {
      connector: "feodo_tracker",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
