/**
 * GreyNoise — Internet Background Noise & Threat Context Connector
 * 
 * Queries the GreyNoise API for IP classification data:
 *   - Classification: benign, malicious, or unknown
 *   - Noise status: whether the IP is seen mass-scanning the internet
 *   - RIOT status: whether the IP belongs to a known benign service
 *   - Actor information: who is scanning (if known)
 *   - Tags: specific scan/attack behaviors observed
 *   - CVEs: vulnerabilities being actively exploited against the IP
 *   - Metadata: OS, ports, organization, ASN, city, country
 * 
 * GreyNoise provides unique "threat pressure" context that no other
 * scanner offers — it tells you not just what's exposed, but whether
 * attackers are actively probing those exposures.
 * 
 * Community API: Free, 50 queries/day, basic classification
 * Enterprise API: Paid, full context with tags, CVEs, metadata
 * 
 * Method: DNS resolution → GreyNoise IP lookup for each resolved IP
 * Data Source: GreyNoise sensor network (passive traffic analysis)
 * Attribution: Each observation links to viz.greynoise.io
 */

import { createHash } from "crypto";
import { resolve4 } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// GreyNoise Community API response
interface GreyNoiseCommunityResponse {
  ip: string;
  noise: boolean;
  riot: boolean;
  classification: "benign" | "malicious" | "unknown";
  name: string;
  link: string;
  last_seen: string;
  message: string;
}

// GreyNoise Enterprise (full context) response
interface GreyNoiseContextResponse {
  ip: string;
  seen: boolean;
  classification: "benign" | "malicious" | "unknown";
  first_seen: string;
  last_seen: string;
  actor: string;
  tags: string[];
  cve: string[];
  spoofable: boolean;
  vpn: boolean;
  vpn_service: string;
  bot: boolean;
  metadata: {
    asn: string;
    city: string;
    country: string;
    country_code: string;
    organization: string;
    category: string;
    os: string;
    rdns: string;
    tor: boolean;
    sensor_count?: number;
    sensor_hits?: number;
  };
  raw_data: {
    scan: Array<{ port: number; protocol: string }>;
    web: { paths: string[]; useragents: string[] };
    ja3: Array<{ fingerprint: string; port: number }>;
    hassh: Array<{ fingerprint: string; port: number }>;
  };
}

async function queryCommunityAPI(ip: string, apiKey: string, timeout: number): Promise<GreyNoiseCommunityResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      signal: controller.signal,
      headers: {
        "key": apiKey,
        "Accept": "application/json",
      },
    });
    if (res.status === 404) return null;
    if (res.status === 429) throw new Error("Rate limited by GreyNoise API");
    if (res.status === 401) throw new Error("Invalid GreyNoise API key");
    if (!res.ok) throw new Error(`GreyNoise returned ${res.status}`);
    return await res.json() as GreyNoiseCommunityResponse;
  } finally {
    clearTimeout(timer);
  }
}

async function queryContextAPI(ip: string, apiKey: string, timeout: number): Promise<GreyNoiseContextResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      signal: controller.signal,
      headers: {
        "key": apiKey,
        "Accept": "application/json",
      },
    });
    // If community API works, try the full context endpoint
    if (res.ok) {
      // Try enterprise endpoint
      const controller2 = new AbortController();
      const timer2 = setTimeout(() => controller2.abort(), timeout);
      try {
        const contextRes = await fetch(`https://api.greynoise.io/v2/noise/context/${ip}`, {
          signal: controller2.signal,
          headers: {
            "key": apiKey,
            "Accept": "application/json",
          },
        });
        if (contextRes.ok) {
          return await contextRes.json() as GreyNoiseContextResponse;
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

export const greynoiseConnector: PassiveConnector = {
  name: "greynoise",
  description: "GreyNoise — internet background noise analysis providing threat pressure context, active attack detection, and IP classification (benign/malicious/unknown)",
  requiresApiKey: true,
  freeUrl: "https://viz.greynoise.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;
    const apiKey = config?.apiKey;

    if (!apiKey) {
      return {
        connector: "greynoise",
        domain,
        observations: [],
        errors: ["GreyNoise API key not configured — skipping"],
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
        return { connector: "greynoise", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const now = new Date();

      // Query GreyNoise for each IP (limit to 15 IPs to conserve API credits)
      for (const ip of ips.slice(0, 15)) {
        try {
          // Try enterprise context API first, fall back to community
          let contextData: GreyNoiseContextResponse | null = null;
          let communityData: GreyNoiseCommunityResponse | null = null;

          try {
            contextData = await queryContextAPI(ip, apiKey, timeout);
          } catch {
            // Enterprise API not available, fall back to community
          }

          if (!contextData) {
            try {
              communityData = await queryCommunityAPI(ip, apiKey, timeout);
            } catch (err: any) {
              if (err.message.includes("Rate limited")) {
                errors.push("GreyNoise rate limited — remaining IPs skipped");
                break;
              }
              throw err;
            }
          }

          if (contextData && contextData.seen) {
            // Full context available (enterprise)
            const threatTags: string[] = [
              `classification:${contextData.classification}`,
              "greynoise",
              "threat_context",
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
              assetId: makeAssetId(domain, `${ip}|greynoise_context`, "greynoise"),
              domain,
              assetType: "ip",
              name: `${ip} (GreyNoise: ${contextData.classification})`,
              ip,
              source: "greynoise",
              observedAt: now,
              firstSeen: contextData.first_seen ? new Date(contextData.first_seen) : undefined,
              lastSeen: contextData.last_seen ? new Date(contextData.last_seen) : undefined,
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
                scan_ports: contextData.raw_data?.scan?.map(s => s.port) || [],
                web_paths: contextData.raw_data?.web?.paths || [],
                ja3_fingerprints: contextData.raw_data?.ja3?.map(j => j.fingerprint) || [],
                first_seen: contextData.first_seen,
                last_seen: contextData.last_seen,
                threat_pressure: contextData.classification === "malicious" ? "high" : contextData.classification === "unknown" ? "medium" : "low",
              },
              attribution: {
                provider: "GreyNoise (Enterprise)",
                url: `https://viz.greynoise.io/ip/${ip}`,
                method: `GreyNoise context — ${ip} classified as ${contextData.classification}${contextData.actor ? ` (actor: ${contextData.actor})` : ""}${contextData.cve?.length ? `, ${contextData.cve.length} CVEs actively exploited` : ""}`,
                verifyUrl: `https://viz.greynoise.io/ip/${ip}`,
              },
            });

            // Create individual CVE observations for actively exploited vulns
            for (const cve of contextData.cve || []) {
              observations.push({
                assetId: makeAssetId(domain, `${ip}|${cve}|greynoise_exploit`, "greynoise"),
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
                  "UNDER_ACTIVE_ATTACK",
                ],
                evidence: {
                  cve_id: cve,
                  ip,
                  classification: contextData.classification,
                  actor: contextData.actor || null,
                  source_api: "api.greynoise.io",
                  verification_type: "greynoise_active_exploitation",
                  threat_pressure: "critical",
                },
                attribution: {
                  provider: "GreyNoise (Enterprise)",
                  url: `https://viz.greynoise.io/ip/${ip}`,
                  method: `GreyNoise — ${cve} is being actively exploited against ${ip} based on GreyNoise sensor network data`,
                  verifyUrl: `https://viz.greynoise.io/ip/${ip}`,
                },
              });
            }
          } else if (communityData) {
            // Community API data
            const threatTags: string[] = [
              `classification:${communityData.classification}`,
              "greynoise",
              "community_api",
            ];

            if (communityData.noise) threatTags.push("internet_noise", "mass_scanning");
            if (communityData.riot) threatTags.push("riot_known_benign");
            if (communityData.classification === "malicious") {
              threatTags.push("UNDER_ACTIVE_ATTACK", "greynoise_malicious");
            }

            observations.push({
              assetId: makeAssetId(domain, `${ip}|greynoise_community`, "greynoise"),
              domain,
              assetType: "ip",
              name: `${ip} (GreyNoise: ${communityData.classification})`,
              ip,
              source: "greynoise",
              observedAt: now,
              lastSeen: communityData.last_seen ? new Date(communityData.last_seen) : undefined,
              tags: threatTags,
              evidence: {
                ip: communityData.ip,
                classification: communityData.classification,
                noise: communityData.noise,
                riot: communityData.riot,
                name: communityData.name,
                last_seen: communityData.last_seen,
                threat_pressure: communityData.classification === "malicious" ? "high"
                  : communityData.noise ? "medium" : "low",
              },
              attribution: {
                provider: "GreyNoise (Community)",
                url: communityData.link || `https://viz.greynoise.io/ip/${ip}`,
                method: `GreyNoise community — ${ip} classified as ${communityData.classification}${communityData.noise ? " (seen mass-scanning)" : ""}${communityData.riot ? " (known benign service)" : ""}`,
                verifyUrl: `https://viz.greynoise.io/ip/${ip}`,
              },
            });
          }
          // If neither returned data, the IP is not in GreyNoise — which is actually good (no threat pressure)
        } catch (err: any) {
          if (err.message.includes("Rate limited")) {
            errors.push("GreyNoise rate limited — remaining IPs skipped");
            break;
          }
          errors.push(`GreyNoise error for ${ip}: ${err.message}`);
        }
      }
    } catch (err: any) {
      errors.push(`GreyNoise error: ${err.message}`);
    }

    return {
      connector: "greynoise",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: errors.some(e => e.includes("Rate limited")),
    };
  },
};
