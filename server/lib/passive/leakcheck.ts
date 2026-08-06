/**
 * LeakCheck Credential Leak Connector
 * 
 * Queries LeakCheck API for leaked credentials associated with
 * a target domain. Returns breach sources, credential counts,
 * and individual leaked accounts.
 * API: https://leakcheck.io/api
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const LEAKCHECK_BASE = 'https://leakcheck.io/api/v2';

interface LeakCheckResult {
  email?: string;
  username?: string;
  password?: string;
  hash?: string;
  sources: { name: string; date?: string; breach_id?: number }[];
  last_breach?: string;
  fields?: string[];
}

export const leakcheckConnector: PassiveConnector = {
  name: "leakcheck",
  description: 'Searches leaked credential databases for domain-associated accounts and passwords',
  requiresApiKey: true,
  freeUrl: "https://leakcheck.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    const apiKey = config?.apiKey;
    if (!apiKey) {
      return {
        connector: 'leakcheck',
        domain,
        observations: [],
        errors: ['No LeakCheck API key configured'],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      const resp = await fetch(
        `${LEAKCHECK_BASE}/query/${encodeURIComponent(domain)}?type=domain&limit=100`,
        {
          headers: {
            'X-API-Key': apiKey,
            'Accept': 'application/json',
          },
          signal: config?.signal,
        }
      );

      if (resp.status === 429) {
        rateLimited = true;
        errors.push("LeakCheck API rate limit exceeded");
      } else if (!resp.ok) {
        if (resp.status === 404) {
          // No results found — not an error
          return {
            connector: 'leakcheck',
            domain,
            observations: [],
            errors,
            durationMs: Date.now() - start,
            rateLimited,
          };
        }
        throw new Error(`LeakCheck API error: ${resp.status}`);
      }

      const data = await resp.json() as { found: number; result: LeakCheckResult[] };
      const results = data.result || [];
      const totalFound = data.found || results.length;

      // Aggregate breach sources
      const breachSources = new Map<string, { count: number; date?: string }>();
      let credentialsWithPasswords = 0;
      let credentialsWithHashes = 0;
      const uniqueEmails = new Set<string>();

      for (const entry of results) {
        if (entry.email) uniqueEmails.add(entry.email.toLowerCase());
        if (entry.password) credentialsWithPasswords++;
        if (entry.hash) credentialsWithHashes++;

        for (const src of entry.sources || []) {
          const existing = breachSources.get(src.name);
          if (existing) {
            existing.count++;
          } else {
            breachSources.set(src.name, { count: 1, date: src.date });
          }
        }
      }

      // Summary observation
      if (totalFound > 0) {
        const name = `LeakCheck: ${totalFound} leaked credentials for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, "leakcheck"),
          domain,
          assetType: 'breach',
          name,
          source: "leakcheck",
          observedAt: now,
          tags: ['darkweb', 'credential_leak', 'leakcheck', 'breach_summary'],
          evidence: {
            value: `Found ${totalFound} leaked accounts across ${breachSources.size} breach sources. ${credentialsWithPasswords} have plaintext passwords.`,
            severity: credentialsWithPasswords > 20 ? 10 : credentialsWithPasswords > 5 ? 8 : totalFound > 10 ? 7 : 5,
            confidence: 90,
            total_leaked: totalFound,
            unique_emails: uniqueEmails.size,
            credentials_with_passwords: credentialsWithPasswords,
            credentials_with_hashes: credentialsWithHashes,
            breach_sources: Object.fromEntries(breachSources),
          },
          attribution: {
            provider: "LeakCheck",
            url: "https://leakcheck.io",
            method: "api",
          },
        });
      }

      // Per-breach source observations
      for (const [sourceName, info] of breachSources) {
        const name = `Breach: ${sourceName}`;
        observations.push({
          assetId: makeAssetId(domain, name, "leakcheck"),
          domain,
          assetType: 'breach',
          name,
          source: "leakcheck",
          observedAt: now,
          tags: ['breach_source', 'credential_leak', 'leakcheck'],
          evidence: {
            value: `${info.count} ${domain} accounts found in ${sourceName} breach${info.date ? ` (${info.date})` : ''}`,
            severity: info.count > 10 ? 8 : 6,
            confidence: 85,
            breach_name: sourceName,
            breach_date: info.date,
            affected_count: info.count,
          },
          attribution: {
            provider: "LeakCheck",
            url: "https://leakcheck.io",
            method: "api",
          },
        });
      }

      // Individual credential observations (top 20)
      for (const entry of results.slice(0, 20)) {
        const identifier = entry.email || entry.username || 'unknown';
        const name = `Leaked credential: ${identifier}`;
        observations.push({
          assetId: makeAssetId(domain, name, "leakcheck"),
          domain,
          assetType: 'breach',
          name,
          source: "leakcheck",
          observedAt: now,
          tags: ['credential_leak', 'leaked_account', 'leakcheck'],
          evidence: {
            value: `Credential found in ${entry.sources?.map(s => s.name).join(', ') || 'unknown breach'}`,
            severity: entry.password ? 9 : entry.hash ? 7 : 5,
            confidence: 88,
            email: entry.email,
            username: entry.username,
            has_password: !!entry.password,
            has_hash: !!entry.hash,
            sources: entry.sources?.map(s => s.name),
            last_breach: entry.last_breach,
            exposed_fields: entry.fields,
          },
          attribution: {
            provider: "LeakCheck",
            url: "https://leakcheck.io",
            method: "api",
          },
        });
      }

    } catch (err: any) {
      errors.push(err.message || 'Unknown error during LeakCheck query');
    }

    return {
      connector: 'leakcheck',
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
