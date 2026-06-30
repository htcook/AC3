/**
 * Hudson Rock Stealer Log Connector
 * 
 * Queries Hudson Rock's Cavalier API for stealer log data
 * associated with a target domain — compromised employees,
 * third-party credentials, and machine infections.
 * API: https://cavalier.hudsonrock.com/docs
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const HUDSON_ROCK_BASE = 'https://cavalier.hudsonrock.com/api/json/v2';

interface HudsonRockEmployee {
  email: string;
  login_url?: string;
  password?: string;
  ip?: string;
  computer_name?: string;
  operating_system?: string;
  malware_path?: string;
  date_compromised?: string;
  antiviruses?: string[];
  stealer_type?: string;
}

interface HudsonRockThirdParty {
  email: string;
  url?: string;
  password?: string;
  date_compromised?: string;
  stealer_type?: string;
}

export const hudsonRockConnector: PassiveConnector = {
  name: "hudson_rock",
  description: 'Queries stealer log intelligence for compromised employee credentials and third-party exposures',
  requiresApiKey: true,
  freeUrl: "https://cavalier.hudsonrock.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();
    const signal = config?.signal;

    // Early abort check
    if (signal?.aborted) {
      return { connector: 'hudson_rock', domain, observations: [], errors: ['Aborted before start'], durationMs: 0, rateLimited: false };
    }

    const apiKey = config?.apiKey;
    if (!apiKey) {
      return {
        connector: 'hudson_rock',
        domain,
        observations: [],
        errors: ['No Hudson Rock API key configured'],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      const fetchTimeout = Math.min(config?.timeout ?? 15000, 20000);
      
      const responses = await Promise.allSettled([
        fetch(`${HUDSON_ROCK_BASE}/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`, {
          headers: { 'api-key': apiKey, 'Accept': 'application/json' },
          signal: signal || AbortSignal.timeout(fetchTimeout),
        }),
        fetch(`${HUDSON_ROCK_BASE}/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}&type=thirdparty`, {
          headers: { 'api-key': apiKey, 'Accept': 'application/json' },
          signal: signal || AbortSignal.timeout(fetchTimeout),
        }),
      ]);

      const [employeeResp, thirdPartyResp] = responses;

      let employees: HudsonRockEmployee[] = [];
      if (employeeResp.status === 'fulfilled' && employeeResp.value.ok) {
        const empData = await employeeResp.value.json();
        employees = Array.isArray(empData) ? empData : (empData?.stealers || empData?.data || []);
      } else if (employeeResp.status === 'fulfilled') {
        if (employeeResp.value.status === 429) rateLimited = true;
        errors.push(`Hudson Rock employee API returned status ${employeeResp.value.status}`);
      } else {
        errors.push(`Hudson Rock employee API fetch failed: ${employeeResp.reason}`);
      }

      // Check abort between API calls
      if (signal?.aborted) {
        return { connector: 'hudson_rock', domain, observations, errors: ['Aborted mid-execution'], durationMs: Date.now() - start, rateLimited };
      }

      let thirdParty: HudsonRockThirdParty[] = [];
      if (thirdPartyResp.status === 'fulfilled' && thirdPartyResp.value.ok) {
        const tpData = await thirdPartyResp.value.json();
        thirdParty = Array.isArray(tpData) ? tpData : (tpData?.stealers || tpData?.data || []);
      } else if (thirdPartyResp.status === 'fulfilled') {
        if (thirdPartyResp.value.status === 429) rateLimited = true;
        errors.push(`Hudson Rock third-party API returned status ${thirdPartyResp.value.status}`);
      } else {
        errors.push(`Hudson Rock third-party API fetch failed: ${thirdPartyResp.reason}`);
      }

      const totalCompromised = employees.length + thirdParty.length;

      if (totalCompromised > 0) {
        const stealerTypes = new Set<string>();
        [...employees, ...thirdParty].forEach(e => {
          if (e.stealer_type) stealerTypes.add(e.stealer_type);
        });

        observations.push({
          assetId: makeAssetId(domain, `stealer-summary`, 'hudson_rock'),
          domain,
          assetType: 'breach',
          name: `Hudson Rock: ${totalCompromised} stealer log entries for ${domain}`,
          source: 'hudson_rock',
          observedAt: now,
          tags: ['darkweb', 'stealer_log', 'hudson_rock', 'breach_summary'],
          evidence: {
            total_compromised: totalCompromised,
            compromised_employees: employees.length,
            third_party_exposures: thirdParty.length,
            stealer_types: Array.from(stealerTypes),
            credentials_with_passwords: [...employees, ...thirdParty].filter(e => e.password).length,
            severity: totalCompromised > 50 ? 10 : totalCompromised > 20 ? 9 : totalCompromised > 5 ? 7 : 5,
            confidence: 90,
          },
          attribution: {
            provider: 'Hudson Rock',
            url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
            method: 'api',
          },
        });
      }

      for (const emp of employees.slice(0, 15)) {
        observations.push({
          assetId: makeAssetId(domain, emp.email, 'hudson_rock'),
          domain,
          assetType: 'breach',
          name: `Compromised employee: ${emp.email}`,
          source: 'hudson_rock',
          observedAt: now,
          firstSeen: emp.date_compromised ? new Date(emp.date_compromised) : undefined,
          tags: ['stealer_log', 'compromised_employee', 'credential_leak', 'hudson_rock'],
          evidence: {
            email: emp.email,
            has_password: !!emp.password,
            login_url: emp.login_url,
            computer_name: emp.computer_name,
            operating_system: emp.operating_system,
            stealer_type: emp.stealer_type,
            ip: emp.ip,
            antiviruses: emp.antiviruses,
            severity: emp.password ? 9 : 7,
            confidence: 90,
          },
          attribution: {
            provider: 'Hudson Rock',
            url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
            method: 'api',
          },
        });
      }

      for (const tp of thirdParty.slice(0, 10)) {
        observations.push({
          assetId: makeAssetId(domain, tp.email, 'hudson_rock'),
          domain,
          assetType: 'breach',
          name: `Third-party exposure: ${tp.email}`,
          source: 'hudson_rock',
          observedAt: now,
          firstSeen: tp.date_compromised ? new Date(tp.date_compromised) : undefined,
          tags: ['stealer_log', 'third_party_exposure', 'credential_leak', 'hudson_rock'],
          evidence: {
            email: tp.email,
            has_password: !!tp.password,
            login_url: tp.url,
            stealer_type: tp.stealer_type,
            severity: tp.password ? 8 : 6,
            confidence: 85,
          },
          attribution: {
            provider: 'Hudson Rock',
            url: `https://cavalier.hudsonrock.com/search?domain=${domain}`,
            method: 'api',
          },
        });
      }

    } catch (err: any) {
      errors.push(err.message || 'Unknown error during Hudson Rock query');
    }

    return {
      connector: 'hudson_rock',
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
