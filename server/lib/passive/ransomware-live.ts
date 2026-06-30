/**
 * Ransomware.live Connector — Free, No API Key
 * 
 * Checks if the target organization appears in ransomware
 * group victim lists. Critical for BIA — a prior ransomware
 * incident dramatically changes the risk profile.
 * 
 * API docs: https://www.ransomware.live/api
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const BASE = 'https://api.ransomware.live/v2';

export const ransomwareLiveConnector: PassiveConnector = {
  name: 'ransomware_live',
  description: 'Ransomware.live — free ransomware victim tracking, checks if target was a ransomware victim',
  requiresApiKey: false,
  freeUrl: "https://ransomware.live",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();
    const source = "ransomware_live";

    try {
      const [victimsResult, recentResult] = await Promise.allSettled([
        fetchVictimsByDomain(domain, config),
        fetchRecentVictims(config),
      ]);

      if (victimsResult.status === 'rejected') {
        errors.push(`Failed to fetch victims by domain: ${victimsResult.reason}`);
      }
      if (recentResult.status === 'rejected') {
        errors.push(`Failed to fetch recent victims: ${recentResult.reason}`);
      }

      // Direct domain match
      if (victimsResult.status === 'fulfilled' && victimsResult.value.length > 0) {
        for (const victim of victimsResult.value) {
          const name = `Ransomware victim: ${victim.victim || domain}`;
          observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['ransomware_live', 'ransomware_victim', 'darkweb', 'critical_threat'],
            evidence: {
              severity: 9,
              confidence: 85,
              value: `Listed by ${victim.group_name || 'unknown group'} on ${victim.discovered || 'unknown date'}`,
              victim_name: victim.victim,
              group_name: victim.group_name,
              discovered: victim.discovered,
              published: victim.published,
              country: victim.country,
              activity: victim.activity,
              website: victim.website,
              description: victim.description,
            },
            attribution: {
              provider: "Ransomware.live",
              url: "https://ransomware.live",
              method: "api",
            },
          });
        }
      }

      // Also check recent victims for fuzzy domain/company name match
      if (recentResult.status === 'fulfilled' && recentResult.value.length > 0) {
        const baseDomain = domain.replace(/^www\./, '').split('.')[0].toLowerCase();
        const fuzzyMatches = recentResult.value.filter((v: any) => {
          const victimLower = (v.victim || '').toLowerCase();
          const websiteLower = (v.website || '').toLowerCase();
          return (
            websiteLower.includes(domain) ||
            victimLower.includes(baseDomain) ||
            websiteLower.includes(baseDomain)
          );
        });

        for (const match of fuzzyMatches) {
          const alreadyFound = observations.some(
            o => o.evidence?.victim_name === match.victim && o.evidence?.group_name === match.group_name
          );
          if (alreadyFound) continue;

          const name = `Possible ransomware victim match: ${match.victim}`;
          observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['ransomware_live', 'ransomware_victim', 'fuzzy_match', 'darkweb'],
            evidence: {
              severity: 8,
              confidence: 60,
              value: `Fuzzy match — listed by ${match.group_name || 'unknown'} on ${match.discovered || 'unknown date'}`,
              match_type: 'fuzzy',
              victim_name: match.victim,
              group_name: match.group_name,
              discovered: match.discovered,
              country: match.country,
              website: match.website,
            },
            attribution: {
              provider: "Ransomware.live",
              url: "https://ransomware.live",
              method: "api",
            },
          });
        }
      }
    } catch (err: any) {
      errors.push(err.message || 'Unknown error during collection');
    }

    return {
      connector: source,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};

async function fetchVictimsByDomain(domain: string, config?: ConnectorConfig): Promise<any[]> {
  const url = `${BASE}/victims/search/${encodeURIComponent(domain)}`;
  const resp = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
    signal: config?.signal || AbortSignal.timeout(config?.timeout || 15000),
  });
  if (resp.status === 429) {
    // Rate limited, but we can't tell the caller from here easily
  }
  if (!resp.ok) {
    throw new Error(`Ransomware.live API returned ${resp.status} for ${url}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data : [];
}

async function fetchRecentVictims(config?: ConnectorConfig): Promise<any[]> {
  const url = `${BASE}/victims/recent`;
  const resp = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
    signal: config?.signal || AbortSignal.timeout(config?.timeout || 15000),
  });
  if (resp.status === 429) {
    // Rate limited
  }
  if (!resp.ok) {
    throw new Error(`Ransomware.live API returned ${resp.status} for ${url}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data.slice(0, 200) : [];
}
