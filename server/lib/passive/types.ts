/**
 * Passive ASM Connector Types
 * 
 * Shared types for all passive reconnaissance connectors.
 * Based on the passive_asm_mega_bundle schema definitions.
 */

// ─── Asset Observation ──────────────────────────────────────────────

export type AssetType = 
  | "subdomain" | "ip" | "certificate" | "url" 
  | "asn" | "mx" | "ns" | "txt" | "cname"
  | "breach";

export interface AssetObservation {
  assetId: string;
  domain: string;
  assetType: AssetType;
  name?: string;           // hostname or label
  ip?: string;
  asn?: number;
  source: string;          // connector name that produced this
  observedAt: Date;
  firstSeen?: Date;
  lastSeen?: Date;
  tags: string[];
  evidence: Record<string, any>;  // raw provider fields
  attribution: {
    provider: string;
    url?: string;
    method: string;        // human-readable description of how this was found
    verifyUrl?: string;    // URL where user can independently verify
  };
}

// ─── Risk Signal ────────────────────────────────────────────────────

export type SignalSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface RiskSignal {
  signalId: string;
  assetId: string;
  signalType: string;
  severity: SignalSeverity;
  confidence: number;      // 0-1
  observedAt: Date;
  rationale: string;
  evidenceRefs: string[];
}

// ─── Hybrid Risk Score ──────────────────────────────────────────────

export interface HybridRiskScore {
  assetId: string;
  hybridScore: number;     // 0-10
  severity: "none" | "low" | "medium" | "high" | "critical";
  carver: Record<string, number>;
  cvss: { vector?: string; score?: number };
  explanation: string;
  inputs: Record<string, any>;
}

// ─── Connector Interface ────────────────────────────────────────────

export interface ConnectorResult {
  connector: string;
  domain: string;
  observations: AssetObservation[];
  errors: string[];
  durationMs: number;
  rateLimited: boolean;
}

export interface ConnectorConfig {
  apiKey?: string;
  apiId?: string;
  apiSecret?: string;
  timeout?: number;        // ms, default 30000
  maxResults?: number;
  signal?: AbortSignal;     // External abort signal for hard timeout enforcement
}

export interface PassiveConnector {
  name: string;
  description: string;
  requiresApiKey: boolean;
  freeUrl: string;         // URL for manual verification
  collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult>;
}

// ─── Passive Policy ─────────────────────────────────────────────────

export type ScanMode = "strict_passive" | "standard" | "active";

export interface PassivePolicyConfig {
  scanMode: ScanMode;
  allowDnsResolution: boolean;
  allowWellKnownFetch: boolean;
  allowedNetlocs: Set<string>;
}

// ─── Collection Summary ─────────────────────────────────────────────

export interface CollectionSummary {
  totalObservations: number;
  totalUniqueAssets: number;
  connectorResults: ConnectorResult[];
  signals: RiskSignal[];
  scanMode: ScanMode;
  startedAt: Date;
  completedAt: Date;
  durationMs: number;
}
