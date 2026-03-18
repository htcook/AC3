/**
 * Connector Adapter — Wraps new-style connectors into the existing PassiveConnector interface
 * 
 * New connectors use a simplified interface with run() and Observation[].
 * This adapter converts them to the standard PassiveConnector interface
 * with collect() and AssetObservation[] so they integrate seamlessly
 * with the existing pipeline (circuit breaker, corroboration, signal classifier).
 */
import { createHash } from "crypto";
import type { AssetObservation, AssetType, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

/** Simplified observation type used by new connectors */
export interface SimpleObservation {
  type: string;           // 'intelligence' | 'infrastructure' | 'vulnerability' | 'asset' | 'error'
  name: string;
  value: string;
  severity: number;       // 0-10
  confidence: number;     // 0-100
  assetType: string;      // 'domain' | 'subdomain' | 'ip' | 'breach' | etc.
  tags: string[];
  evidence: Record<string, any>;
}

/** Simplified connector result used by new connectors */
export interface SimpleConnectorResult {
  connector: string;
  domain: string;
  observations: SimpleObservation[];
  metadata: Record<string, any>;
}

/** New-style connector interface */
export interface SimpleConnector {
  id: string;
  name: string;
  description: string;
  category: string;
  requiresApiKey: boolean;
  rateLimit?: { requestsPerMinute: number };
  run(domain: string, config?: any, apiKeys?: Record<string, string>): Promise<SimpleConnectorResult>;
}

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

function mapAssetType(raw: string): AssetType {
  const map: Record<string, AssetType> = {
    domain: "subdomain",
    subdomain: "subdomain",
    ip: "ip",
    breach: "breach",
    certificate: "certificate",
    url: "url",
    asn: "asn",
    mx: "mx",
    ns: "ns",
    txt: "txt",
    cname: "cname",
  };
  return map[raw] || "subdomain";
}

/**
 * Adapt a new-style SimpleConnector into the standard PassiveConnector interface.
 * 
 * @param connector - The new-style connector to wrap
 * @param apiKeyField - Which field in ConnectorConfig to read the API key from (default: 'apiKey')
 * @param freeUrl - URL for manual verification
 */
export function adaptConnector(
  connector: SimpleConnector,
  freeUrl: string,
  apiKeyField: 'apiKey' | 'apiId' | 'apiSecret' = 'apiKey',
): PassiveConnector {
  return {
    name: connector.id,
    description: connector.description,
    requiresApiKey: connector.requiresApiKey,
    freeUrl,

    async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
      const start = Date.now();
      const errors: string[] = [];
      const observations: AssetObservation[] = [];
      let rateLimited = false;

      try {
        const apiKey = config?.[apiKeyField];
        if (connector.requiresApiKey && !apiKey) {
          return {
            connector: connector.id,
            domain,
            observations: [],
            errors: [`${connector.name} API key not configured — skipping`],
            durationMs: Date.now() - start,
            rateLimited: false,
          };
        }

        // Build apiKeys map for connectors that need multiple keys
        const apiKeys: Record<string, string> = {};
        if (config?.apiKey) apiKeys[connector.id] = config.apiKey;
        if (config?.apiId) apiKeys[`${connector.id}_id`] = config.apiId;
        if (config?.apiSecret) apiKeys[`${connector.id}_secret`] = config.apiSecret;

        const result = await connector.run(domain, config, apiKeys);
        const now = new Date();

        // Convert SimpleObservation[] to AssetObservation[]
        for (const obs of result.observations) {
          if (obs.type === 'error') {
            errors.push(obs.value);
            continue;
          }

          observations.push({
            assetId: makeAssetId(domain, obs.name, connector.id),
            domain,
            assetType: mapAssetType(obs.assetType),
            name: obs.name,
            source: connector.id,
            observedAt: now,
            tags: obs.tags,
            evidence: {
              ...obs.evidence,
              severity: obs.severity,
              confidence: obs.confidence,
              description: obs.value,
            },
            attribution: {
              provider: connector.name,
              url: freeUrl,
              method: `${connector.description} — ${obs.value}`,
            },
          });
        }
      } catch (err: any) {
        if (err.message?.includes('429') || err.message?.includes('rate limit')) {
          rateLimited = true;
        }
        errors.push(`${connector.name} error: ${err.message}`);
      }

      return {
        connector: connector.id,
        domain,
        observations,
        errors,
        durationMs: Date.now() - start,
        rateLimited,
      };
    },
  };
}
