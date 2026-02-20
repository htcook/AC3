/**
 * Cross-Source Corroboration Engine
 * 
 * Assigns confidence multipliers to observations based on how many
 * independent sources confirm the same finding. Observations confirmed
 * by multiple connectors receive higher confidence scores, reducing
 * false positives from stale or inaccurate single-source data.
 * 
 * Confidence multiplier tiers:
 *   1 source  → 0.6x  (unverified — single-source only)
 *   2 sources → 0.85x (corroborated — two independent sources)
 *   3+ sources → 1.0x  (high confidence — multi-source confirmed)
 * 
 * @module corroboration-engine
 */

import type { AssetObservation, ConnectorResult, RiskSignal } from "./types";

// ─── Configuration ─────────────────────────────────────────────────

export interface CorroborationConfig {
  /** Confidence multiplier for findings from a single source */
  singleSourceMultiplier: number;
  /** Confidence multiplier for findings corroborated by 2 sources */
  dualSourceMultiplier: number;
  /** Confidence multiplier for findings confirmed by 3+ sources */
  multiSourceMultiplier: number;
  /** Whether to add corroboration metadata to observations */
  annotateObservations: boolean;
}

export const DEFAULT_CORROBORATION_CONFIG: CorroborationConfig = {
  singleSourceMultiplier: 0.6,
  dualSourceMultiplier: 0.85,
  multiSourceMultiplier: 1.0,
  annotateObservations: true,
};

// ─── Corroboration Result Types ────────────────────────────────────

export interface CorroborationResult {
  /** Total observations processed */
  totalObservations: number;
  /** Number of unique findings (grouped by fingerprint) */
  uniqueFindings: number;
  /** Observations with corroboration metadata applied */
  corroboratedObservations: CorroboratedObservation[];
  /** Risk signals with adjusted confidence */
  adjustedSignals: RiskSignal[];
  /** Summary statistics */
  stats: CorroborationStats;
}

export interface CorroboratedObservation extends AssetObservation {
  corroboration: {
    /** Number of independent sources confirming this finding */
    sourceCount: number;
    /** Names of all sources that confirmed this finding */
    confirmingSources: string[];
    /** The confidence multiplier applied */
    confidenceMultiplier: number;
    /** Corroboration tier: 'unverified' | 'corroborated' | 'high-confidence' */
    tier: "unverified" | "corroborated" | "high-confidence";
    /** The fingerprint used for grouping */
    fingerprint: string;
  };
}

export interface CorroborationStats {
  /** Observations with only 1 source (unverified) */
  unverifiedCount: number;
  /** Observations with 2 sources (corroborated) */
  corroboratedCount: number;
  /** Observations with 3+ sources (high-confidence) */
  highConfidenceCount: number;
  /** Percentage of observations that are corroborated or better */
  corroborationRate: number;
  /** Average source count per finding */
  averageSourceCount: number;
  /** Source-pair agreement matrix: which sources agree most often */
  sourceAgreement: Record<string, Record<string, number>>;
}

// ─── Fingerprinting ────────────────────────────────────────────────

/**
 * Generate a fingerprint for an observation that groups equivalent
 * findings from different sources. Two observations with the same
 * fingerprint are considered to be reporting the same fact.
 * 
 * Fingerprint strategy by asset type:
 *   subdomain → normalized hostname
 *   ip        → IP address + port (if available)
 *   certificate → subject CN or serial
 *   url       → normalized URL path
 *   breach    → breach source + email/domain
 *   asn/mx/ns/txt/cname → type + value
 */
export function generateFingerprint(obs: AssetObservation): string {
  const type = obs.assetType;
  
  switch (type) {
    case "subdomain": {
      const host = (obs.name || obs.assetId).toLowerCase().replace(/\.$/, "");
      return `sub:${host}`;
    }
    case "ip": {
      const ip = obs.ip || obs.name || obs.assetId;
      const port = obs.evidence?.port || obs.evidence?.ports?.[0] || "";
      return port ? `ip:${ip}:${port}` : `ip:${ip}`;
    }
    case "certificate": {
      const cn = obs.evidence?.subject_cn || obs.evidence?.common_name || obs.name || "";
      const serial = obs.evidence?.serial || "";
      return serial ? `cert:${serial}` : `cert:${cn.toLowerCase()}`;
    }
    case "url": {
      const url = (obs.name || obs.evidence?.url || obs.assetId).toLowerCase();
      // Normalize URL: remove trailing slash, protocol
      const normalized = url.replace(/^https?:\/\//, "").replace(/\/$/, "");
      return `url:${normalized}`;
    }
    case "breach": {
      const source = obs.evidence?.breach_source || obs.evidence?.database_name || "";
      const target = obs.evidence?.email || obs.domain;
      return `breach:${source.toLowerCase()}:${target.toLowerCase()}`;
    }
    case "mx":
    case "ns":
    case "cname":
    case "txt": {
      const value = (obs.name || obs.evidence?.value || obs.assetId).toLowerCase();
      return `${type}:${value}`;
    }
    case "asn": {
      const asnNum = obs.asn || obs.evidence?.asn || obs.assetId;
      return `asn:${asnNum}`;
    }
    default:
      return `${type}:${obs.assetId}`;
  }
}

// ─── Core Engine ───────────────────────────────────────────────────

/**
 * Run cross-source corroboration on a set of connector results.
 * Groups observations by fingerprint, counts independent sources,
 * and applies confidence multipliers.
 */
export function corroborateFindings(
  connectorResults: ConnectorResult[],
  riskSignals: RiskSignal[],
  config: CorroborationConfig = DEFAULT_CORROBORATION_CONFIG
): CorroborationResult {
  // Step 1: Group all observations by fingerprint
  const fingerprintMap = new Map<string, { sources: Set<string>; observations: AssetObservation[] }>();
  
  for (const result of connectorResults) {
    for (const obs of result.observations) {
      const fp = generateFingerprint(obs);
      
      if (!fingerprintMap.has(fp)) {
        fingerprintMap.set(fp, { sources: new Set(), observations: [] });
      }
      
      const group = fingerprintMap.get(fp)!;
      group.sources.add(obs.source);
      group.observations.push(obs);
    }
  }
  
  // Step 2: Apply corroboration metadata to observations
  const corroboratedObservations: CorroboratedObservation[] = [];
  const sourceAgreement: Record<string, Record<string, number>> = {};
  let unverifiedCount = 0;
  let corroboratedCount = 0;
  let highConfidenceCount = 0;
  let totalSourceCount = 0;
  
  for (const fp of Array.from(fingerprintMap.keys())) {
    const group = fingerprintMap.get(fp)!;
    const sourceCount = group.sources.size;
    const confirmingSources = Array.from(group.sources).sort();
    totalSourceCount += sourceCount;
    
    // Determine tier and multiplier
    let tier: "unverified" | "corroborated" | "high-confidence";
    let confidenceMultiplier: number;
    
    if (sourceCount >= 3) {
      tier = "high-confidence";
      confidenceMultiplier = config.multiSourceMultiplier;
      highConfidenceCount += group.observations.length;
    } else if (sourceCount === 2) {
      tier = "corroborated";
      confidenceMultiplier = config.dualSourceMultiplier;
      corroboratedCount += group.observations.length;
    } else {
      tier = "unverified";
      confidenceMultiplier = config.singleSourceMultiplier;
      unverifiedCount += group.observations.length;
    }
    
    // Track source-pair agreement
    if (sourceCount >= 2) {
      for (let i = 0; i < confirmingSources.length; i++) {
        for (let j = i + 1; j < confirmingSources.length; j++) {
          const a = confirmingSources[i];
          const b = confirmingSources[j];
          if (!sourceAgreement[a]) sourceAgreement[a] = {};
          if (!sourceAgreement[b]) sourceAgreement[b] = {};
          sourceAgreement[a][b] = (sourceAgreement[a][b] || 0) + 1;
          sourceAgreement[b][a] = (sourceAgreement[b][a] || 0) + 1;
        }
      }
    }
    
    // Annotate each observation in the group
    for (const obs of group.observations) {
      const corroborated: CorroboratedObservation = {
        ...obs,
        corroboration: {
          sourceCount,
          confirmingSources,
          confidenceMultiplier,
          tier,
          fingerprint: fp,
        },
      };
      corroboratedObservations.push(corroborated);
    }
  }
  
  // Step 3: Adjust risk signal confidence based on corroboration
  const assetCorroboration = new Map<string, { multiplier: number; tier: string }>();
  for (const obs of corroboratedObservations) {
    const existing = assetCorroboration.get(obs.assetId);
    // Use the highest corroboration level for each asset
    if (!existing || obs.corroboration.confidenceMultiplier > existing.multiplier) {
      assetCorroboration.set(obs.assetId, {
        multiplier: obs.corroboration.confidenceMultiplier,
        tier: obs.corroboration.tier,
      });
    }
  }
  
  const adjustedSignals = riskSignals.map(signal => {
    const corr = assetCorroboration.get(signal.assetId);
    if (!corr) return signal;
    
    return {
      ...signal,
      confidence: Math.min(1, signal.confidence * corr.multiplier),
      evidenceRefs: [
        ...signal.evidenceRefs,
        `corroboration:${corr.tier}`,
      ],
    };
  });
  
  // Step 4: Build stats
  const totalObs = corroboratedObservations.length;
  const corroborationRate = totalObs > 0
    ? ((corroboratedCount + highConfidenceCount) / totalObs) * 100
    : 0;
  const averageSourceCount = fingerprintMap.size > 0
    ? totalSourceCount / fingerprintMap.size
    : 0;
  
  return {
    totalObservations: totalObs,
    uniqueFindings: fingerprintMap.size,
    corroboratedObservations,
    adjustedSignals,
    stats: {
      unverifiedCount,
      corroboratedCount,
      highConfidenceCount,
      corroborationRate: Math.round(corroborationRate * 10) / 10,
      averageSourceCount: Math.round(averageSourceCount * 100) / 100,
      sourceAgreement,
    },
  };
}

/**
 * Deduplicate observations using corroboration-aware logic.
 * Instead of simple first-seen dedup, picks the observation with
 * the richest evidence from the highest-quality source.
 */
export function deduplicateWithCorroboration(
  corroboratedObservations: CorroboratedObservation[]
): CorroboratedObservation[] {
  const byFingerprint = new Map<string, CorroboratedObservation[]>();
  
  for (const obs of corroboratedObservations) {
    const fp = obs.corroboration.fingerprint;
    if (!byFingerprint.has(fp)) {
      byFingerprint.set(fp, []);
    }
    byFingerprint.get(fp)!.push(obs);
  }
  
  const deduplicated: CorroboratedObservation[] = [];
  
  for (const fp of Array.from(byFingerprint.keys())) {
    const group = byFingerprint.get(fp)!;
    // Pick the observation with the most evidence fields
    const best = group.reduce((a: CorroboratedObservation, b: CorroboratedObservation) => {
      const aEvidence = Object.keys(a.evidence).length;
      const bEvidence = Object.keys(b.evidence).length;
      if (bEvidence > aEvidence) return b;
      // Tie-break: prefer more recent observation
      if (bEvidence === aEvidence && b.observedAt > a.observedAt) return b;
      return a;
    });
    
    // Merge corroboration data from all observations in the group
    const allSources = new Set<string>();
    for (const obs of group) {
      for (const src of obs.corroboration.confirmingSources) {
        allSources.add(src);
      }
    }
    
    deduplicated.push({
      ...best,
      corroboration: {
        ...best.corroboration,
        confirmingSources: Array.from(allSources).sort(),
        sourceCount: allSources.size,
      },
    });
  }
  
  return deduplicated;
}

// ─── Source Reliability Weights ─────────────────────────────────────

/**
 * Source reliability weights based on data freshness and accuracy.
 * Higher weights indicate more reliable/fresh data sources.
 */
export const SOURCE_RELIABILITY: Record<string, number> = {
  "shodan": 0.9,           // Active scanning, fresh data
  "shodan-internetdb": 0.85, // Cached but frequently updated
  "censys": 0.9,           // Active scanning, fresh data
  "binaryedge": 0.85,      // Active scanning
  "crtsh": 0.95,           // Certificate transparency — authoritative
  "securitytrails": 0.8,   // DNS history — good but can be stale
  "urlscan": 0.75,         // Community submissions — variable freshness
  "rdap": 0.95,            // Registry data — authoritative
  "ripestat": 0.9,         // RIR data — authoritative
  "dehashed": 0.7,         // Breach data — variable age
  "greynoise": 0.85,       // Active threat intel — fresh
  "wayback": 0.5,          // Historical archives — often stale
};

/**
 * Get the reliability weight for a source.
 * Returns 0.5 for unknown sources.
 */
export function getSourceReliability(source: string): number {
  return SOURCE_RELIABILITY[source] ?? 0.5;
}
