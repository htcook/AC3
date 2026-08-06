/**
 * ThreatFox (abuse.ch) Connector — Free, No API Key
 * 
 * Searches the ThreatFox IOC database for indicators
 * associated with the target domain (malware C2, phishing,
 * botnet infrastructure).
 * 
 * API docs: https://threatfox.abuse.ch/api/
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const API_URL = 'https://threatfox-api.abuse.ch/api/v1/';

async function threatFoxPost(body: Record<string, any>): Promise<any> {
  const resp = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) return null;
  return resp.json();
}

export const threatfoxConnector: PassiveConnector = {
  name: "threatfox",
  description: 'ThreatFox (abuse.ch) — free IOC database, malware C2, phishing, botnet indicators',
  requiresApiKey: false,
  freeUrl: "https://threatfox.abuse.ch",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      const results = await threatFoxPost({ query: 'search_ioc', search_term: domain });

      if (results?.query_status === 'ok' && results.data) {
        for (const ioc of results.data.slice(0, 25)) {
          const name = `ThreatFox IOC: ${ioc.ioc_value || domain}`;
          observations.push({
            assetId: makeAssetId(domain, name, "threatfox"),
            domain: domain,
            assetType: 'breach',
            name,
            source: "threatfox",
            observedAt: now,
            firstSeen: ioc.first_seen_utc ? new Date(ioc.first_seen_utc) : undefined,
            lastSeen: ioc.last_seen_utc ? new Date(ioc.last_seen_utc) : undefined,
            tags: ['threatfox', 'ioc', ioc.threat_type || 'malware', 'abuse_ch'],
            evidence: {
              severity: ioc.threat_type === 'botnet_cc' ? 9 :
                        ioc.threat_type === 'payload_delivery' ? 8 :
                        ioc.threat_type === 'payload' ? 7 : 6,
              confidence: ioc.confidence_level || 70,
              value: `${ioc.threat_type || 'unknown'} — ${ioc.malware || 'unknown malware'} (${ioc.malware_alias || ''})`,
              ioc_id: ioc.id,
              ioc_value: ioc.ioc_value,
              ioc_type: ioc.ioc_type,
              threat_type: ioc.threat_type,
              threat_type_desc: ioc.threat_type_desc,
              malware: ioc.malware,
              malware_alias: ioc.malware_alias,
              malware_printable: ioc.malware_printable,
              confidence_level: ioc.confidence_level,
              reporter: ioc.reporter,
              reference: ioc.reference,
            },
            attribution: {
                provider: "ThreatFox",
                url: "https://threatfox.abuse.ch/api/",
                method: "api"
            }
          });
        }
      }
    } catch (err: any) {
      errors.push(err.message || 'Unknown error during ThreatFox lookup');
    }

    return {
      connector: 'threatfox',
      domain,
      observations,
      errors, 
      durationMs: Date.now() - start, 
      rateLimited,
    };
  },
};
