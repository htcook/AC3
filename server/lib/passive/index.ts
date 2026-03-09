/**
 * Passive ASM Orchestrator — Runs all connectors in parallel
 * 
 * This is the main entry point for the passive reconnaissance stage.
 * It coordinates all connectors, applies the scan mode policy,
 * deduplicates observations, and runs the signal classifier.
 */

import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector, RiskSignal, ScanMode } from "./types";
import { shouldAllowRequest, recordSuccess, recordFailure, classifyError, trackCall, type CircuitBreakerConfig } from "../api-resilience";
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
import { coalitionControlConnector } from "./coalition-control";
import { greynoiseConnector } from "./greynoise";
import { emailSecurityConnector } from "./email-security";
import { httpSecurityConnector } from "./http-security";
import { cloudAssetsConnector } from "./cloud-assets";
import { containerDiscoveryConnector } from "./container-discovery";
import { dnsDeepConnector } from "./dns-deep";
import { githubLeaksConnector } from "./github-leaks";
import { githubReconConnector } from "./github-recon";
import { cloudBucketReconConnector } from "./cloud-bucket-recon";
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
  coalitionControlConnector,   // Coalition Control ASM — replaces BinaryEdge (shut down March 2025)
  // binaryedgeConnector,     // DEPRECATED: BinaryEdge API shut down March 31, 2025 — replaced by Coalition Control
  greynoiseConnector,         // Threat pressure context
  emailSecurityConnector,     // Email security posture (DMARC/SPF/DKIM)
  httpSecurityConnector,      // HTTP security headers & WAF detection
  cloudAssetsConnector,       // Cloud storage enumeration (S3/Azure/GCP)
  containerDiscoveryConnector, // Container infrastructure discovery (Docker/K8s/registries)
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
  // --- Enhanced Recon Modules ---
  githubReconConnector,          // Enhanced GitHub recon — org discovery, repo enum, CI/CD, secrets, dorks
  cloudBucketReconConnector,     // Enhanced cloud bucket recon — 5 providers, permission depth, sensitive files
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
    github?: string;
  };
  timeout?: number;
  maxConcurrent?: number;
  /** Optional callback fired when each connector starts/completes */
  onConnectorProgress?: (event: { connector: string; status: 'started' | 'completed' | 'failed' | 'skipped'; observations?: number; durationMs?: number; error?: string }) => void | Promise<void>;
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
  const { scanMode, apiKeys = {}, timeout = 15000, maxConcurrent = 10 } = config;

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
      case "github_recon": cfg.apiKey = apiKeys.github; break;
      case "github_leaks": cfg.apiKey = apiKeys.github; break;
    }
    connectorConfigs.set(connector.name, cfg);
  }

  // ── Circuit Breaker Configuration ──────────────────────────────────
  // Each connector is wrapped with a circuit breaker that prevents
  // hammering APIs that are down, rate-limited, or misconfigured.
  const cbConfig: CircuitBreakerConfig = {
    failureThreshold: 3,      // Open circuit after 3 consecutive failures
    resetTimeoutMs: 120_000,  // 2 minute cooldown before half-open probe
    halfOpenMaxAttempts: 1,   // 1 probe attempt in half-open state
  };

  // ── Pre-filter: skip connectors that require API keys when no key is configured ──
  // This avoids wasting batch slots on connectors that will immediately fail with "No API key"
  const CONNECTORS_REQUIRING_API_KEY: Record<string, string> = {
    shodan: 'apiKey', censys: 'apiId', urlscan: 'apiKey', securitytrails: 'apiKey',
    dehashed: 'apiKey', binaryedge: 'apiKey', greynoise: 'apiKey', virustotal: 'apiKey',
    hibp: 'apiKey', whoisxml: 'apiKey', leakix: 'apiKey', fullhunt: 'apiKey',
    netlas: 'apiKey', hunter: 'apiKey', abuseipdb: 'apiKey', passivetotal: 'apiKey',
    github_recon: 'apiKey', github_leaks: 'apiKey',
  };
  const readyConnectors: PassiveConnector[] = [];
  const skippedNoKey: ConnectorResult[] = [];
  for (const connector of allowed) {
    const requiredField = CONNECTORS_REQUIRING_API_KEY[connector.name];
    if (requiredField) {
      const cfg = connectorConfigs.get(connector.name);
      const hasKey = cfg && ((cfg as any).apiKey || (cfg as any).apiId);
      if (!hasKey) {
        skippedNoKey.push({
          connector: connector.name, domain, observations: [],
          errors: [`Skipped: No API key configured`], durationMs: 0, rateLimited: false,
        });
        continue;
      }
    }
    readyConnectors.push(connector);
  }
  if (skippedNoKey.length > 0) {
    console.log(`[PassiveRecon] Skipped ${skippedNoKey.length} connectors with no API key: ${skippedNoKey.map(s => s.connector).join(', ')}`);
  }

  // Run connectors in parallel with concurrency limit + circuit breaker
  const connectorResults: ConnectorResult[] = [...skippedNoKey];
  const batches: PassiveConnector[][] = [];
  for (let i = 0; i < readyConnectors.length; i += maxConcurrent) {
    batches.push(readyConnectors.slice(i, i + maxConcurrent));
  }

  const { onConnectorProgress } = config;

  const GLOBAL_RECON_TIMEOUT = 5 * 60 * 1000; // 5 min max for all connectors combined
  const reconStart = Date.now();
  for (const batch of batches) {
    if (Date.now() - reconStart >= GLOBAL_RECON_TIMEOUT) {
      console.log(`[PassiveRecon] Global recon timeout (${GLOBAL_RECON_TIMEOUT / 1000}s) reached — proceeding with ${connectorResults.length} results`);
      break;
    }
    const results = await Promise.allSettled(
      batch.map(async (connector) => {
        const serviceName = connector.name;

        // ── Circuit Breaker Gate ──────────────────────────────────────────
        const cbCheck = shouldAllowRequest(serviceName, cbConfig);
        if (!cbCheck.allowed) {
          console.log(`[PassiveRecon] Circuit OPEN for ${serviceName} — skipping (${cbCheck.reason})`);
          trackCall(serviceName, false);
          await onConnectorProgress?.({ connector: serviceName, status: 'skipped', error: cbCheck.reason });
          return {
            connector: serviceName,
            domain,
            observations: [],
            errors: [`Circuit breaker open: ${cbCheck.reason}`],
            durationMs: 0,
            rateLimited: false,
          } satisfies ConnectorResult;
        }

        try {
          await onConnectorProgress?.({ connector: serviceName, status: 'started' });
          const connStart = Date.now();
          const HARD_CONNECTOR_TIMEOUT = 30_000; // 30s hard cap per connector
          const result = await Promise.race([
            connector.collect(domain, connectorConfigs.get(serviceName)),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error(`Hard timeout: ${serviceName} exceeded ${HARD_CONNECTOR_TIMEOUT / 1000}s`)), HARD_CONNECTOR_TIMEOUT)
            ),
          ]);

          // Track success/failure based on result errors
          const hasAuthError = result.errors.some(e => e.includes("401") || e.includes("Unauthorized") || e.includes("invalid") || e.includes("not configured") || e.includes("skipping"));
          const hasRateLimit = result.rateLimited;
          const connDuration = Date.now() - connStart;

          if (hasAuthError) {
            // Auth/config failures — report as skipped, open circuit to avoid wasting quota
            const classified = classifyError(new Error(result.errors[0]), serviceName);
            recordFailure(serviceName, classified, cbConfig);
            trackCall(serviceName, false);
            await onConnectorProgress?.({ connector: serviceName, status: 'skipped', error: result.errors[0], durationMs: connDuration });
          } else if (hasRateLimit) {
            // Rate limits are transient — report as failed with rate limit info
            trackCall(serviceName, false);
            await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: 'Rate limited', observations: result.observations.length, durationMs: connDuration });
          } else if (result.errors.length > 0 && result.observations.length === 0) {
            // Complete failure with no data — report as failed
            const classified = classifyError(new Error(result.errors[0]), serviceName);
            recordFailure(serviceName, classified, cbConfig);
            trackCall(serviceName, false);
            await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: result.errors[0], observations: 0, durationMs: connDuration });
          } else {
            // Success (even partial — some errors but also some observations)
            recordSuccess(serviceName);
            trackCall(serviceName, true);
            await onConnectorProgress?.({ connector: serviceName, status: 'completed', observations: result.observations.length, durationMs: connDuration });
          };
          return result;
        } catch (err: any) {
          const classified = classifyError(err, serviceName);
          recordFailure(serviceName, classified, cbConfig);
          trackCall(serviceName, false);
          console.error(`[PassiveRecon] ${serviceName} failed (${classified.category}): ${classified.message}`);
          await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: err.message });
          return {
            connector: serviceName,
            domain,
            observations: [],
            errors: [`[${classified.category}] ${err.message}`],
            durationMs: 0,
            rateLimited: classified.category === "rate_limited",
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
