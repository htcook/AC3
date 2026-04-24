/**
 * SSLBL (abuse.ch SSL Blacklist) Connector — Free, No API Key
 * 
 * Identifies SSL certificates associated with botnet C2 servers,
 * malware distribution, and other malicious activity.
 * 
 * Data source: https://sslbl.abuse.ch/
 * API docs: https://sslbl.abuse.ch/blacklist/
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const SSLBL_RECENT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json";

export const sslblConnector: PassiveConnector = {
  name: "sslbl",
  description: "SSLBL (abuse.ch) — SSL certificate blacklist for botnet C2 and malware distribution",
  requiresApiKey: false,
  freeUrl: "https://sslbl.abuse.ch",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Step 1: Resolve domain IPs via DNS-over-HTTPS
      const dnsRes = await rateLimitedFetch("sslbl", `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
        signal: AbortSignal.timeout(8000),
      });
      const dnsData = await dnsRes.json() as any;
      const domainIps = new Set<string>();
      if (dnsData?.Answer) {
        for (const ans of dnsData.Answer) {
          if (ans.type === 1 && ans.data) domainIps.add(ans.data);
        }
      }

      // Step 2: Fetch SSLBL blacklist
      const resp = await rateLimitedFetch("sslbl", SSLBL_RECENT_URL, {
        signal: AbortSignal.timeout(15000),
      });

      if (!resp.ok) {
        errors.push(`SSLBL returned ${resp.status}`);
        return { connector: "sslbl", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const text = await resp.text();
      let sslData: any[];
      try {
        sslData = JSON.parse(text);
      } catch {
        // SSLBL may return CSV format — parse it
        const lines = text.split("\n").filter(l => l.trim() && !l.startsWith("#"));
        sslData = lines.map(line => {
          const parts = line.split(",");
          return {
            listing_date: parts[0]?.trim(),
            sha1: parts[1]?.trim(),
            listing_reason: parts[2]?.trim(),
          };
        });
      }

      if (!Array.isArray(sslData)) {
        errors.push("Unexpected SSLBL response format");
        return { connector: "sslbl", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Step 3: Check for IP matches in SSLBL entries
      const matches: any[] = [];
      for (const entry of sslData) {
        // Check if the entry's dst_ip matches any domain IP
        if (entry.dst_ip && domainIps.has(entry.dst_ip)) {
          matches.push(entry);
        }
        // Check if the entry's subject CN matches the domain
        if (entry.subject_cn && (
          entry.subject_cn === domain ||
          entry.subject_cn === `*.${domain}` ||
          entry.subject_cn.endsWith(`.${domain}`)
        )) {
          if (!matches.find(m => m.sha1 === entry.sha1)) {
            matches.push(entry);
          }
        }
      }

      // Step 4: Generate observations for matches
      for (const match of matches.slice(0, 15)) {
        const reason = match.listing_reason || match.malware || "unknown";
        const name = `SSLBL: Blacklisted cert ${match.sha1?.slice(0, 12) || "unknown"} (${reason})`;

        observations.push({
          assetId: makeAssetId(domain, name, "sslbl"),
          domain,
          assetType: "certificate",
          name,
          source: "sslbl",
          observedAt: now,
          firstSeen: match.listing_date ? new Date(match.listing_date) : undefined,
          tags: ["sslbl", "ssl_blacklist", "malicious_cert", reason.toLowerCase().replace(/\s+/g, "_"), "abuse_ch"],
          evidence: {
            severity: 9,
            confidence: 90,
            value: `SSL certificate blacklisted for ${reason} — SHA1: ${match.sha1 || "unknown"}`,
            sha1: match.sha1,
            subject_cn: match.subject_cn,
            issuer_cn: match.issuer_cn,
            serial_number: match.serial_number,
            listing_reason: reason,
            listing_date: match.listing_date,
            dst_ip: match.dst_ip,
            dst_port: match.dst_port,
          },
          attribution: {
            provider: "SSLBL (abuse.ch)",
            url: "https://sslbl.abuse.ch/",
            method: "blacklist",
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during SSLBL lookup");
    }

    return {
      connector: "sslbl",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
