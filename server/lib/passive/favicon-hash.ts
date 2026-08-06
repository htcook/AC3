/**
 * Favicon Hash — Infrastructure Discovery Connector
 * 
 * Calculates the MurmurHash3 of each target's favicon and queries Shodan InternetDB
 * for matching hosts. This reveals shadow IT, dev/staging environments, and
 * infrastructure sharing patterns.
 * 
 * Method: Fetch favicon → compute MMH3 hash → query Shodan for matching hosts
 * Data Source: Target favicon + Shodan InternetDB (free)
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

/**
 * MurmurHash3 (32-bit) — matches Shodan's favicon hash algorithm.
 * Shodan uses the base64-encoded favicon content as input to MMH3.
 */
function murmurHash3_32(key: Buffer, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = key.length;
  let h1 = seed;
  const roundedEnd = len & ~3; // round down to 4 byte block

  for (let i = 0; i < roundedEnd; i += 4) {
    let k1 = (key[i] & 0xff) | ((key[i + 1] & 0xff) << 8) | ((key[i + 2] & 0xff) << 16) | ((key[i + 3] & 0xff) << 24);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = Math.imul(h1, 5) + 0xe6546b64;
  }

  let k1 = 0;
  const remaining = len & 3;
  if (remaining >= 3) k1 ^= (key[roundedEnd + 2] & 0xff) << 16;
  if (remaining >= 2) k1 ^= (key[roundedEnd + 1] & 0xff) << 8;
  if (remaining >= 1) {
    k1 ^= key[roundedEnd] & 0xff;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0; // Convert to signed 32-bit int (matches Shodan)
}

/**
 * Compute Shodan-compatible favicon hash from raw favicon bytes.
 * Shodan hashes the base64-encoded favicon content.
 */
export function computeFaviconHash(faviconBytes: Buffer): number {
  const b64 = faviconBytes.toString("base64");
  // Shodan adds newlines every 76 chars in the base64 encoding
  const b64WithNewlines = b64.replace(/(.{76})/g, "$1\n") + "\n";
  return murmurHash3_32(Buffer.from(b64WithNewlines));
}

export const faviconHashConnector: PassiveConnector = {
  name: "favicon_hash",
  description: "Favicon hash infrastructure discovery — computes favicon MMH3 hash to find related infrastructure via Shodan",
  requiresApiKey: false,
  freeUrl: "https://internetdb.shodan.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;

    try {
      // Step 1: Fetch favicon
      const faviconUrls = [
        `https://${domain}/favicon.ico`,
        `http://${domain}/favicon.ico`,
      ];

      let faviconBytes: Buffer | null = null;
      let faviconUrl = "";

      for (const url of faviconUrls) {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(url, { signal: controller.signal, redirect: "follow" });
            if (res.ok) {
              const arrayBuf = await res.arrayBuffer();
              faviconBytes = Buffer.from(arrayBuf);
              faviconUrl = url;
              break;
            }
          } finally {
            clearTimeout(timer);
          }
        } catch {
          continue;
        }
      }

      if (!faviconBytes || faviconBytes.length < 10) {
        return { connector: "favicon_hash", domain, observations, errors: ["No favicon found"], durationMs: Date.now() - start, rateLimited: false };
      }

      // Step 2: Compute hash
      const hash = computeFaviconHash(faviconBytes);
      const now = new Date();

      observations.push({
        assetId: makeAssetId(domain, `favicon:${hash}`, "favicon_hash"),
        domain,
        assetType: "infrastructure",
        name: `favicon:${hash}`,
        source: "favicon_hash",
        observedAt: now,
        tags: ["favicon", "infrastructure_discovery", "mmh3"],
        evidence: {
          faviconHash: hash,
          faviconUrl,
          faviconSize: faviconBytes.length,
          shodanQuery: `http.favicon.hash:${hash}`,
          sha256: createHash("sha256").update(faviconBytes).digest("hex"),
        },
        attribution: {
          provider: "Favicon Hash (local computation + Shodan query)",
          url: faviconUrl,
          method: `Computed MurmurHash3 of ${domain} favicon — use Shodan query http.favicon.hash:${hash} to find related infrastructure`,
          verifyUrl: `https://www.shodan.io/search?query=http.favicon.hash%3A${hash}`,
        },
      });

    } catch (err: any) {
      errors.push(`Favicon hash error: ${err.message}`);
    }

    return { connector: "favicon_hash", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
