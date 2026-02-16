/**
 * crt.sh — Certificate Transparency Log Connector
 * 
 * Queries the crt.sh database for SSL/TLS certificates issued for *.domain.
 * Extracts subdomain names from certificate Subject Alternative Names (SANs).
 * 
 * Method: Queries crt.sh JSON API for certificates matching %.domain
 * Data Source: Certificate Transparency logs (Google, DigiCert, Let's Encrypt, etc.)
 * Attribution: Each observation links to the crt.sh certificate entry for verification
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

async function fetchCrtsh(domain: string, timeout: number): Promise<any[]> {
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

export const crtshConnector: PassiveConnector = {
  name: "crtsh",
  description: "Certificate Transparency log search via crt.sh — discovers subdomains from issued SSL/TLS certificates",
  requiresApiKey: false,
  freeUrl: "https://crt.sh",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 30000;
    const maxResults = config?.maxResults ?? 500;

    try {
      const raw = await fetchCrtsh(domain, timeout);
      
      // Deduplicate by common_name / name_value
      const seen = new Set<string>();
      const now = new Date();

      for (const entry of raw) {
        const nameValue: string = entry.name_value || "";
        // name_value can contain multiple names separated by newlines
        const names = nameValue.split("\n").map((n: string) => n.trim().toLowerCase()).filter(Boolean);

        for (const name of names) {
          // Skip wildcards and already-seen names
          if (name.startsWith("*.") || seen.has(name)) continue;
          if (!name.endsWith(`.${domain}`) && name !== domain) continue;
          seen.add(name);

          if (seen.size > maxResults) break;

          const notBefore = entry.not_before ? new Date(entry.not_before) : undefined;
          const notAfter = entry.not_after ? new Date(entry.not_after) : undefined;

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
              crt_sh_id: entry.id,
            },
            attribution: {
              provider: "crt.sh (Certificate Transparency)",
              url: `https://crt.sh/?id=${entry.id}`,
              method: "Certificate Transparency log search — queried crt.sh for all SSL/TLS certificates issued for *.${domain}",
              verifyUrl: `https://crt.sh/?q=%25.${domain}`,
            },
          });
        }
        if (seen.size > maxResults) break;
      }
    } catch (err: any) {
      errors.push(`crt.sh error: ${err.message}`);
    }

    return {
      connector: "crtsh",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
