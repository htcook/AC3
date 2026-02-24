/**
 * Passive ASM Orchestrator — Runs all connectors in parallel
 * 
 * This is the main entry point for the passive reconnaissance stage.
 * It coordinates all connectors, applies the scan mode policy,
 * deduplicates observations, and runs the signal classifier.
 */

import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector, RiskSignal, ScanMode } from "./types";
import { crtshConnector } from "./crtsh";
import { shodanConnector } from "./shodan";
import { waybackConnector } from "./wayback";
import { censysConnector } from "./censys";
import { urlscanConnector } from "./urlscan";
import { rdapConnector } from "./rdap";
import { ripestatConnector } from "./ripestat";
import { securitytrailsConnector } from "./securitytrails";
import { dehashedConnector } from "./dehashed";
import { shodanInternetDBConnector } from "./shodan-internetdb";
import { binaryedgeConnector } from "./binaryedge";
import { greynoiseConnector } from "./greynoise";
import { emailSecurityConnector } from "./email-security";
import { httpSecurityConnector } from "./http-security";
import { cloudAssetsConnector } from "./cloud-assets";
import { dnsDeepConnector } from "./dns-deep";
import { githubLeaksConnector } from "./github-leaks";
import { virustotalConnector } from "./virustotal";
import { hibpConnector } from "./hibp";
import { whoisxmlConnector } from "./whoisxml";
import { leakixConnector } from "./leakix";
import { fullhuntConnector } from "./fullhunt";
import { netlasConnector } from "./netlas";
import { hunterConnector } from "./hunter";
import { socialMediaConnector } from "./social-media";
import { abuseipdbConnector } from "./abuseipdb";
import { passivetotalConnector } from "./passivetotal";
import { filterConnectors, getScanModeDescription } from "./passive-guard";
import { classifySignals, getSignalRuleDescriptions } from "./signal-classifier";
import { corroborateFindings, deduplicateWithCorroboration, type CorroborationResult, type CorroborationConfig, DEFAULT_CORROBORATION_CONFIG, type CorroboratedObservation } from "./corroboration-engine";
import { computeDiscoveryCoverage, type DiscoveryCoverageReport } from "../redteam-discovery-coverage";

// All available connectors
export const ALL_CONNECTORS: PassiveConnector[] = [
  shodanInternetDBConnector,  // Free fast-path — runs first for instant CVE/port data
  crtshConnector,
  shodanConnector,
  waybackConnector,
  censysConnector,
  urlscanConnector,
  rdapConnector,
  ripestatConnector,
  securitytrailsConnector,
  dehashedConnector,
  binaryedgeConnector,        // Independent validation source
  greynoiseConnector,         // Threat pressure context
  emailSecurityConnector,     // Email security posture (DMARC/SPF/DKIM)
  httpSecurityConnector,      // HTTP security headers & WAF detection
  cloudAssetsConnector,       // Cloud storage enumeration (S3/Azure/GCP)
  dnsDeepConnector,           // Comprehensive DNS record analysis
  githubLeaksConnector,       // GitHub code leak scanner (Priority #10)
  // --- New OSINT sources (SpiderFoot-class expansion) ---
  virustotalConnector,         // VirusTotal — file/URL/domain reputation & malware analysis
  hibpConnector,               // Have I Been Pwned — breach exposure & credential leaks
  whoisxmlConnector,           // WhoisXML — WHOIS records, DNS, subdomain enum
  leakixConnector,             // LeakIX — exposed services & data leaks
  fullhuntConnector,           // FullHunt — attack surface discovery
  netlasConnector,             // Netlas.io — internet-wide host scanning & DNS history
  hunterConnector,             // Hunter.io — email discovery & org intelligence
  socialMediaConnector,        // Social media — GitHub org/user presence & code exposure
  abuseipdbConnector,          // AbuseIPDB — IP abuse reputation scoring
  passivetotalConnector,       // PassiveTotal — passive DNS, SSL history, host attributes
];

export interface PassiveReconConfig {
  scanMode: ScanMode;
  apiKeys?: {
    shodan?: string;
    censys_id?: string;
    censys_secret?: string;
    urlscan?: string;
    securitytrails?: string;
    dehashed?: string;
    binaryedge?: string;
    greynoise?: string;
    virustotal?: string;
    hibp?: string;
    whoisxml?: string;
    leakix?: string;
    fullhunt?: string;
    netlas?: string;
    hunter?: string;
    abuseipdb?: string;
    passivetotal?: string;
  };
  timeout?: number;
  maxConcurrent?: number;
}

export interface PassiveReconResult {
  domain: string;
  scanMode: ScanMode;
  scanModeDescription: ReturnType<typeof getScanModeDescription>;
  connectorResults: ConnectorResult[];
  allObservations: AssetObservation[];
  riskSignals: RiskSignal[];
  signalRules: ReturnType<typeof getSignalRuleDescriptions>;
  corroboration?: CorroborationResult;
  discoveryCoverage?: DiscoveryCoverageReport;
  summary: {
    totalObservations: number;
    totalSignals: number;
    connectorStats: { name: string; observations: number; errors: number; durationMs: number; rateLimited: boolean; skipped: boolean; skipReason?: string }[];
    byAssetType: Record<string, number>;
    bySeverity: Record<string, number>;
    bySource: Record<string, number>;
    corroborationRate?: number;
  };
  durationMs: number;
}


/**
 * Run passive reconnaissance against a domain
 */
export async function runPassiveRecon(
  domain: string,
  config: PassiveReconConfig
): Promise<PassiveReconResult> {
  const start = Date.now();
  const { scanMode, apiKeys = {}, timeout = 30000, maxConcurrent = 5 } = config;

  // Apply scan mode policy
  const { allowed, blocked } = filterConnectors(ALL_CONNECTORS, scanMode);
  const scanModeDescription = getScanModeDescription(scanMode);

  // Build connector configs
  const connectorConfigs: Map<string, ConnectorConfig> = new Map();
  for (const connector of allowed) {
    const cfg: ConnectorConfig = { timeout };
    switch (connector.name) {
      case "shodan": cfg.apiKey = apiKeys.shodan; break;
      case "censys": cfg.apiId = apiKeys.censys_id; cfg.apiSecret = apiKeys.censys_secret; break;
      case "urlscan": cfg.apiKey = apiKeys.urlscan; break;
      case "securitytrails": cfg.apiKey = apiKeys.securitytrails; break;
      case "dehashed": cfg.apiKey = apiKeys.dehashed; break;
      case "binaryedge": cfg.apiKey = apiKeys.binaryedge; break;
      case "greynoise": cfg.apiKey = apiKeys.greynoise; break;
      case "virustotal": cfg.apiKey = apiKeys.virustotal; break;
      case "hibp": cfg.apiKey = apiKeys.hibp; break;
      case "whoisxml": cfg.apiKey = apiKeys.whoisxml; break;
      case "leakix": cfg.apiKey = apiKeys.leakix; break;
      case "fullhunt": cfg.apiKey = apiKeys.fullhunt; break;
      case "netlas": cfg.apiKey = apiKeys.netlas; break;
      case "hunter": cfg.apiKey = apiKeys.hunter; break;
      case "abuseipdb": cfg.apiKey = apiKeys.abuseipdb; break;
      case "passivetotal": cfg.apiKey = apiKeys.passivetotal; break;
    }
    connectorConfigs.set(connector.name, cfg);
  }

  // Run connectors in parallel with concurrency limit
  const connectorResults: ConnectorResult[] = [];
  const batches: PassiveConnector[][] = [];
  for (let i = 0; i < allowed.length; i += maxConcurrent) {
    batches.push(allowed.slice(i, i + maxConcurrent));
  }

  for (const batch of batches) {
    const results = await Promise.allSettled(
      batch.map(async (connector) => {
        try {
          return await connector.collect(domain, connectorConfigs.get(connector.name));
        } catch (err: any) {
          return {
            connector: connector.name,
            domain,
            observations: [],
            errors: [`Unhandled error: ${err.message}`],
            durationMs: 0,
            rateLimited: false,
          } satisfies ConnectorResult;
        }
      })
    );

    for (const result of results) {
      if (result.status === "fulfilled") {
        connectorResults.push(result.value);
      } else {
        connectorResults.push({
          connector: "unknown",
          domain,
          observations: [],
          errors: [`Promise rejected: ${result.reason}`],
          durationMs: 0,
          rateLimited: false,
        });
      }
    }
  }

  // Add blocked connectors as skipped
  for (const b of blocked) {
    connectorResults.push({
      connector: b.name,
      domain,
      observations: [],
      errors: [`Skipped: ${b.reason}`],
      durationMs: 0,
      rateLimited: false,
    });
  }

  // Deduplicate observations by assetId
  const seenAssets = new Set<string>();
  const allObservations: AssetObservation[] = [];
  for (const result of connectorResults) {
    for (const obs of result.observations) {
      if (!seenAssets.has(obs.assetId)) {
        seenAssets.add(obs.assetId);
        allObservations.push(obs);
      }
    }
  }

  // Run signal classifier
  const riskSignals = classifySignals(allObservations);
  const signalRules = getSignalRuleDescriptions();

  // Run cross-source corroboration engine
  const corroboration = corroborateFindings(connectorResults, riskSignals);
  const corroboratedSignals = corroboration.adjustedSignals;

  // Build summary
  const byAssetType: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  for (const obs of allObservations) {
    byAssetType[obs.assetType] = (byAssetType[obs.assetType] || 0) + 1;
    bySource[obs.source] = (bySource[obs.source] || 0) + 1;
  }

  const bySeverity: Record<string, number> = {};
  for (const sig of corroboratedSignals) {
    bySeverity[sig.severity] = (bySeverity[sig.severity] || 0) + 1;
  }

  const connectorStats = connectorResults.map(r => ({
    name: r.connector,
    observations: r.observations.length,
    errors: r.errors.length,
    durationMs: r.durationMs,
    rateLimited: r.rateLimited,
    skipped: blocked.some(b => b.name === r.connector),
    skipReason: blocked.find(b => b.name === r.connector)?.reason,
  }));

  // Compute red team discovery coverage
  const discoveryCoverage = computeDiscoveryCoverage(connectorResults, allObservations);
  console.log(`[PassiveRecon] Red team discovery coverage: ${discoveryCoverage.coverageScore}% (${discoveryCoverage.prioritiesCovered}/10 priorities)`);

  return {
    domain,
    scanMode,
    scanModeDescription,
    connectorResults,
    allObservations,
    riskSignals: corroboratedSignals,
    signalRules,
    corroboration,
    discoveryCoverage,
    summary: {
      totalObservations: allObservations.length,
      totalSignals: corroboratedSignals.length,
      connectorStats,
      byAssetType,
      bySeverity,
      bySource,
      corroborationRate: corroboration.stats.corroborationRate,
    },
    durationMs: Date.now() - start,
  };
}

// Re-export types and utilities
export type { AssetObservation, ConnectorResult, RiskSignal, ScanMode, PassiveConnector } from "./types";
export { getScanModeDescription } from "./passive-guard";
export { getSignalRuleDescriptions } from "./signal-classifier";
