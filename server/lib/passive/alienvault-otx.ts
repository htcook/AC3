/**
 * AlienVault OTX Connector — Free (API key optional, improves rate limits)
 *
 * Queries the OTX DirectConnect API v1 for domain/hostname indicators:
 *   - General info + pulse (threat report) associations
 *   - Passive DNS records
 *   - Malware file hashes associated with the domain
 *   - URL list (known URLs crawled/reported)
 *
 * API docs: https://otx.alienvault.com/assets/static/external_api.html
 * No API key required for general indicator lookups.
 * An API key (free registration) improves rate limits and unlocks NIDS data.
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

const BASE_URL = "https://otx.alienvault.com/api/v1";

async function otxFetch(
  path: string,
  apiKey?: string,
  signal?: AbortSignal
): Promise<any> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }
  const resp = await fetch(`${BASE_URL}${path}`, {
    headers,
    signal: signal || AbortSignal.timeout(20000),
  });
  if (resp.status === 429) return { _rateLimited: true };
  if (!resp.ok) return null;
  return resp.json();
}

export const alienvaultOtxConnector: PassiveConnector = {
  name: "alienvault-otx",
  description:
    "AlienVault OTX — free threat intelligence exchange, pulse associations, passive DNS, malware hashes",
  requiresApiKey: false,
  freeUrl: "https://otx.alienvault.com",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const start = Date.now();
    let rateLimited = false;
    const now = new Date();
    const apiKey = config?.apiKey;
    const sig = config?.signal;

    // ── 1. General indicator info + pulse associations ──────────────
    try {
      const general = await otxFetch(
        `/indicator/domain/${domain}/general`,
        apiKey,
        sig
      );
      if (general?._rateLimited) {
        rateLimited = true;
      } else if (general) {
        // Extract pulse (threat report) associations
        const pulses = general.pulse_info?.pulses || [];
        for (const pulse of pulses.slice(0, 15)) {
          const name = `OTX Pulse: ${pulse.name || "Unknown"}`;
          observations.push({
            assetId: makeAssetId(domain, `pulse-${pulse.id}`, "alienvault-otx"),
            domain,
            assetType: "breach",
            name,
            source: "alienvault-otx",
            observedAt: now,
            firstSeen: pulse.created ? new Date(pulse.created) : undefined,
            lastSeen: pulse.modified ? new Date(pulse.modified) : undefined,
            tags: [
              "alienvault-otx",
              "threat-intel",
              "pulse",
              ...(pulse.tags || []).slice(0, 5),
              ...(pulse.adversary ? [`adversary:${pulse.adversary}`] : []),
            ],
            evidence: {
              severity:
                pulse.adversary
                  ? 8
                  : pulse.TLP === "red"
                  ? 9
                  : pulse.TLP === "amber"
                  ? 7
                  : 5,
              confidence: 75,
              value: `Threat report "${pulse.name}" ${
                pulse.adversary ? `(adversary: ${pulse.adversary})` : ""
              } — ${pulse.description?.substring(0, 200) || "No description"}`,
              pulseId: pulse.id,
              pulseName: pulse.name,
              adversary: pulse.adversary || null,
              tlp: pulse.TLP || "white",
              tags: pulse.tags || [],
              indicatorCount: pulse.indicator_count || 0,
              references: (pulse.references || []).slice(0, 5),
              attackIds: (pulse.attack_ids || []).slice(0, 10),
              malwareFamilies: (pulse.malware_families || []).slice(0, 5),
            },
            attribution: {
              provider: "AlienVault OTX",
              url: `https://otx.alienvault.com/pulse/${pulse.id}`,
              method: "OTX DirectConnect API — domain general indicator lookup",
              verifyUrl: `https://otx.alienvault.com/indicator/domain/${domain}`,
            },
          });
        }

        // Overall reputation / validation info
        if (general.validation?.length > 0) {
          for (const v of general.validation.slice(0, 5)) {
            const name = `OTX Validation: ${v.source || "unknown"} — ${
              v.message || ""
            }`;
            observations.push({
              assetId: makeAssetId(
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
                validationName: v.name,
              },
              attribution: {
                provider: "AlienVault OTX",
                url: `https://otx.alienvault.com/indicator/domain/${domain}`,
                method: "OTX validation data",
              },
            });
          }
        }
      }
    } catch (err: any) {
      errors.push(`OTX general: ${err.message}`);
    }

    // ── 2. Passive DNS ──────────────────────────────────────────────
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
          const name = `${hostname} → ${ip} (${record.record_type || "A"})`;
          observations.push({
            assetId: makeAssetId(
              domain,
              `pdns-${hostname}-${ip}`,
              "alienvault-otx"
            ),
            domain,
            assetType: record.record_type === "CNAME" ? "cname" : "ip",
            name,
            ip: ip || undefined,
            source: "alienvault-otx",
            observedAt: now,
            firstSeen: record.first ? new Date(record.first) : undefined,
            lastSeen: record.last ? new Date(record.last) : undefined,
            tags: [
              "alienvault-otx",
              "passive-dns",
              record.record_type || "A",
            ],
            evidence: {
              severity: 2,
              confidence: 70,
              value: `Passive DNS: ${hostname} → ${ip} (${
                record.record_type || "A"
              })`,
              hostname,
              address: ip,
              recordType: record.record_type,
              asn: record.asn,
              flag: record.flag,
            },
            attribution: {
              provider: "AlienVault OTX",
              url: `https://otx.alienvault.com/indicator/domain/${domain}`,
              method: "OTX passive DNS resolution history",
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`OTX passive_dns: ${err.message}`);
    }

    // ── 3. Malware associated with domain ───────────────────────────
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
            assetId: makeAssetId(
              domain,
              `malware-${hash}`,
              "alienvault-otx"
            ),
            domain,
            assetType: "breach",
            name,
            source: "alienvault-otx",
            observedAt: now,
            firstSeen: sample.datetime_int
              ? new Date(sample.datetime_int * 1000)
              : undefined,
            tags: ["alienvault-otx", "malware", "ioc"],
            evidence: {
              severity: 8,
              confidence: 70,
              value: `Malware sample associated with ${domain}: ${hash}`,
              hash,
              detections: sample.detections,
            },
            attribution: {
              provider: "AlienVault OTX",
              url: `https://otx.alienvault.com/indicator/file/${hash}`,
              method: "OTX domain malware association lookup",
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`OTX malware: ${err.message}`);
    }

    // ── 4. URL list (known URLs) ────────────────────────────────────
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
            assetId: makeAssetId(domain, `url-${url}`, "alienvault-otx"),
            domain,
            assetType: "url",
            name,
            source: "alienvault-otx",
            observedAt: now,
            firstSeen: entry.date ? new Date(entry.date) : undefined,
            tags: [
              "alienvault-otx",
              "url",
              ...(entry.result?.safebrowsing
                ? ["google-safebrowsing-flagged"]
                : []),
            ],
            evidence: {
              severity: entry.result?.safebrowsing ? 7 : 3,
              confidence: 65,
              value: url,
              httpcode: entry.httpcode,
              gsb: entry.result?.safebrowsing || null,
              urlworker: entry.result?.urlworker || null,
            },
            attribution: {
              provider: "AlienVault OTX",
              url: `https://otx.alienvault.com/indicator/domain/${domain}`,
              method: "OTX URL list for domain",
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(`OTX url_list: ${err.message}`);
    }

    return {
      connector: "alienvault-otx",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
