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
import { intelxSearchConnector } from "./intelx-search";
import { hudsonRockConnector } from "./hudson-rock";
import { leakcheckConnector } from "./leakcheck";
import { companyIntelConnector } from "./company-intel";
import { threatminerConnector } from "./threatminer";
import { ipApiConnector } from "./ip-api";
import { bgpviewConnector } from "./bgpview";
import { ransomwareLiveConnector } from "./ransomware-live";
import { threatfoxConnector } from "./threatfox";
import { builtwithConnector } from "./builtwith";
import { circlPdnsConnector } from "./circl-pdns";
import { commoncrawlConnector } from "./commoncrawl";
import { reverseWhoisConnector } from "./reverse-whois";
import { typosquatConnector } from "./typosquat";
import { domainHealthConnector } from "./domain-health";
import { alienvaultOtxConnector } from "./alienvault-otx";
import { googleSafeBrowsingConnector } from "./google-safebrowsing";
import { phishtankConnector } from "./phishtank";
import { darkwebCrossrefConnector } from "./darkweb-crossref";
import { dehashedWhoisConnector } from "./dehashed-whois";
import { anubisConnector } from "./anubis";
import { hackertargetConnector } from "./hackertarget";
import { rapiddnsConnector } from "./rapiddns";
import { dnsrepoConnector } from "./dnsrepo";
import { sitedossierConnector } from "./sitedossier";
import { faviconHashConnector } from "./favicon-hash";
import { jarmFingerprintConnector } from "./jarm-fingerprint";
import { dnsZoneTransferConnector } from "./dns-zone-transfer";
import { waybackDiffConnector } from "./wayback-diff";
import { urlhausConnector } from "./urlhaus";
import { malwarebazaarConnector } from "./malwarebazaar";
import { secEdgarConnector } from "./sec-edgar";
import { osvDevConnector } from "./osv-dev";
import { teamCymruConnector } from "./team-cymru";
import { cisaAdvisoriesConnector } from "./cisa-advisories";
import { feodoTrackerConnector } from "./feodo-tracker";
import { sslblConnector } from "./sslbl";
import { githubAdvisoriesConnector } from "./github-advisories";
import { certspotterConnector } from "./certspotter";
import { companiesHouseConnector } from "./companies-house";
import { opencorporatesConnector } from "./opencorporates";
import { hc3Connector } from "./hc3";
import { detectWildcardDns, tagWildcardObservations, createWildcardSignal } from "./wildcard-detection";
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
  // --- OSINT Pipeline Expansion (Gap Analysis v2) ---
  intelxSearchConnector,           // Intelligence X — darkweb/paste/leak search (requires API key)
  hudsonRockConnector,             // Hudson Rock — stealer log exposure (requires API key)
  leakcheckConnector,              // LeakCheck — credential leak search (requires API key)
  companyIntelConnector,           // Company Intelligence — firmographic data via web scraping + LLM
  threatminerConnector,            // ThreatMiner — free threat intel (passive DNS, malware, APT reports)
  ipApiConnector,                  // ip-api.com — free IP geolocation, ASN, org info
  bgpviewConnector,                // BGPView — free ASN lookup, network topology, IP prefixes
  ransomwareLiveConnector,         // Ransomware.live — free ransomware victim tracking
  threatfoxConnector,              // ThreatFox (abuse.ch) — free IOC database
  builtwithConnector,              // BuiltWith — free tech stack detection
  circlPdnsConnector,              // CIRCL Passive DNS — free historical DNS resolution
  commoncrawlConnector,            // CommonCrawl — free historical web data for company context
  reverseWhoisConnector,           // Reverse WHOIS — free related domain discovery via crt.sh
  typosquatConnector,                // Typosquat Generator — free lookalike domain detection for phishing
  // --- Domain Health (MXToolbox-equivalent) ---
  domainHealthConnector,               // Domain Health — DNSBL blacklist, SMTP test, PTR, DNS health, IP block, TCP connectivity
  // --- Threat Intel Expansion (Gap Analysis P0) ---
  alienvaultOtxConnector,              // AlienVault OTX — free threat intel exchange, pulses, passive DNS, malware
  googleSafeBrowsingConnector,         // Google SafeBrowsing — malware, phishing, unwanted software detection
  phishtankConnector,                  // PhishTank — community-verified phishing URL database
  // --- Dark Web Cross-Reference (Local DB) ---
  darkwebCrossrefConnector,              // Cross-references domain against local underground intel DB (ransomware, IAB, data leaks)
  // --- Dehashed WHOIS & Subdomain Scan ---
  dehashedWhoisConnector,                  // Dehashed WHOIS — registration data, reverse WHOIS, subdomain scan
  // --- Free Subdomain Enumeration Sources (Audit R2) ---
  anubisConnector,                         // Anubis — free subdomain enum via jldc.me (CT + DNS aggregation)
  hackertargetConnector,                   // HackerTarget — free host search (100 queries/day)
  rapiddnsConnector,                       // RapidDNS — free subdomain enum from DNS zone files
  dnsrepoConnector,                        // DNSRepo — free subdomain enum from DNS zone file database
  sitedossierConnector,                    // Sitedossier — free subdomain enum from web crawl database
  // --- Infrastructure Discovery (Audit R10, R11) ---
  faviconHashConnector,                    // Favicon Hash — MMH3 hash for Shodan infrastructure discovery
  jarmFingerprintConnector,                // JARM — TLS fingerprinting to detect C2, CDN, server software
  // --- DNS Security (Audit R13) ---
  dnsZoneTransferConnector,                // DNS Zone Transfer — AXFR attempt against nameservers
  // --- Historical Analysis (Audit R14) ---
  waybackDiffConnector,                    // Wayback Diff — historical content analysis for removed admin panels, leaked creds
  // --- Tier 1 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
  urlhausConnector,                          // URLhaus (abuse.ch) — free malicious URL database
  malwarebazaarConnector,                    // MalwareBazaar (abuse.ch) — free malware sample database
  secEdgarConnector,                         // SEC EDGAR — free US public company filings for BIA context
  osvDevConnector,                           // OSV.dev — free open source vulnerability database (supply chain)
  teamCymruConnector,                        // Team Cymru — authoritative IP-to-ASN mapping via DNS
  cisaAdvisoriesConnector,                   // CISA Advisories — KEV catalog & ICS advisories
  // --- Tier 2 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
  feodoTrackerConnector,                       // Feodo Tracker (abuse.ch) — botnet C2 infrastructure tracking
  sslblConnector,                              // SSLBL (abuse.ch) — SSL certificate blacklist for C2/malware
  githubAdvisoriesConnector,                   // GitHub Security Advisories — GHSA vulnerability database
  certspotterConnector,                        // Certspotter (SSLMate) — CT log monitoring & subdomain discovery
  companiesHouseConnector,                     // Companies House (UK) — corporate registry for BIA context
  opencorporatesConnector,                     // OpenCorporates — global corporate registry (140M+ companies)
  hc3Connector,                                // HC3 (HHS) — healthcare sector cybersecurity threat intel
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
    intelx?: string;
    hudson_rock?: string;
    leakcheck?: string;
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


// ─── Training Lab Detection ─────────────────────────────────────────
// Lab/training domains won't have WHOIS, Shodan, SecurityTrails, or breach
// data. Running 40+ connectors against them wastes 2-5 minutes per domain.
// Fast-track mode runs only free/local connectors that actually return data.

const LAB_DOMAIN_PATTERNS = [
  /\.lab\.aceofcloud\.io$/i,
  /\.lab\.aceofcloud\.com$/i,
  /\.training\.aceofcloud\./i,
  /\.test\.aceofcloud\./i,
  /\.ctf\.aceofcloud\./i,
  /^(dvwa|juiceshop|bwapp|mutillidae|webgoat|altoro|dvbank|hackazon|bodgeit|railsgoat)/i,
];

/** Connectors that work against lab/internal domains (no external API needed or free) */
const LAB_FAST_TRACK_CONNECTORS = new Set([
  'crtsh',           // Certificate transparency — works for any domain with a cert
  'dns_deep',        // DNS records — works for any resolvable domain
  'http_security',   // HTTP headers — works for any reachable web server
  'email_security',  // DMARC/SPF/DKIM — works via DNS
  'rdap',            // RDAP/WHOIS — fast fail for lab domains, minimal cost
  'shodan_internetdb', // Free Shodan InternetDB — fast, no API key needed
  'ip_api',          // Free IP geolocation — works for any IP
  'wayback',         // Wayback Machine — fast fail for lab domains
  'container_discovery', // Docker/K8s discovery — works for lab infra
  'domain_health',     // Domain health — DNSBL, SMTP, PTR, DNS health (no API key needed)
  // --- Audit R2: Free subdomain sources ---
  'anubis',            // Anubis — free subdomain enum (no API key)
  'hackertarget',      // HackerTarget — free host search (no API key)
  'rapiddns',          // RapidDNS — free subdomain enum (no API key)
  'dnsrepo',           // DNSRepo — free subdomain enum (no API key)
  'sitedossier',       // Sitedossier — free subdomain enum (no API key)
  // --- Audit R10, R11, R13, R14 ---
  'favicon_hash',      // Favicon hash — local computation (no API key)
  'jarm_fingerprint',  // JARM — direct TLS probe (no API key)
  'dns_zone_transfer', // DNS zone transfer — direct DNS query (no API key)
  'wayback_diff',      // Wayback diff — free Wayback CDX API (no API key)
]);

export function isLabDomain(domain: string): boolean {
  return LAB_DOMAIN_PATTERNS.some(pattern => pattern.test(domain));
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

  // ── Lab Domain Fast-Track ──────────────────────────────────────────
  const labMode = isLabDomain(domain);
  if (labMode) {
    console.log(`[PassiveRecon] Lab domain detected: ${domain} — fast-track mode (${LAB_FAST_TRACK_CONNECTORS.size} connectors only)`);
  }

  // Apply scan mode policy
  const { allowed: modeAllowed, blocked } = filterConnectors(ALL_CONNECTORS, scanMode);
  // Further filter for lab domains
  const allowed = labMode
    ? modeAllowed.filter(c => LAB_FAST_TRACK_CONNECTORS.has(c.name))
    : modeAllowed;
  if (labMode) {
    const skippedCount = modeAllowed.length - allowed.length;
    console.log(`[PassiveRecon] Lab fast-track: Running ${allowed.length} connectors, skipped ${skippedCount} external API connectors`);
  }
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
      case "dehashed_whois": cfg.apiKey = apiKeys.dehashed; break;
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
      case "intelx_search": cfg.apiKey = apiKeys.intelx; break;
      case "hudson_rock": cfg.apiKey = apiKeys.hudson_rock; break;
      case "leakcheck": cfg.apiKey = apiKeys.leakcheck; break;
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
    dehashed: 'apiKey', dehashed_whois: 'apiKey', binaryedge: 'apiKey', greynoise: 'apiKey', virustotal: 'apiKey',
    hibp: 'apiKey', whoisxml: 'apiKey', leakix: 'apiKey', fullhunt: 'apiKey',
    netlas: 'apiKey', hunter: 'apiKey', abuseipdb: 'apiKey', passivetotal: 'apiKey',
    github_recon: 'apiKey', github_leaks: 'apiKey',
    intelx_search: 'apiKey', hudson_rock: 'apiKey', leakcheck: 'apiKey',
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

  // ── Tier 1 Optimization #3.3: Separate GitHub connectors into background queue ──
  // GitHub connectors (github_leaks, github_recon) consistently hit the 30s
  // hard timeout. Moving them out of the main pool frees up 2 concurrency
  // slots and lets the main pipeline complete ~30s faster.
  const BACKGROUND_CONNECTORS = new Set(['github_leaks', 'github_recon']);
  const mainConnectors = readyConnectors.filter(c => !BACKGROUND_CONNECTORS.has(c.name));
  const backgroundConnectors = readyConnectors.filter(c => BACKGROUND_CONNECTORS.has(c.name));
  if (backgroundConnectors.length > 0) {
    console.log(`[PassiveRecon] Background queue: ${backgroundConnectors.map(c => c.name).join(', ')} (will run after main connectors)`);
  }

  // ── Run connectors with semaphore + Promise.race hard timeout ──────────
  // Key design: each connector is wrapped in Promise.race against a timeout
  // promise. Even if the connector's .collect() blocks the event loop and
  // never checks the abort signal, Promise.race resolves after the timeout
  // and we move on. The straggler promise is abandoned (fire-and-forget).
  const connectorResults: ConnectorResult[] = [...skippedNoKey];
  const { onConnectorProgress } = config;
  const HARD_CONNECTOR_TIMEOUT = 30_000; // 30s hard cap per connector
  const GLOBAL_RECON_TIMEOUT = 5 * 60 * 1000; // 5 min max for all connectors combined
  const reconStart = Date.now();

  // Semaphore-based concurrency: process all connectors through a pool
  let activeCount = 0;
  let connectorIndex = 0;
  const pendingResults: Promise<void>[] = [];

  function makeTimeoutResult(serviceName: string): ConnectorResult {
    return {
      connector: serviceName,
      domain,
      observations: [],
      errors: [`Hard timeout: ${serviceName} exceeded ${HARD_CONNECTOR_TIMEOUT / 1000}s — abandoned`],
      durationMs: HARD_CONNECTOR_TIMEOUT,
      rateLimited: false,
    };
  }

  async function runSingleConnector(connector: PassiveConnector): Promise<ConnectorResult> {
    const serviceName = connector.name;

    // Check global timeout
    if (Date.now() - reconStart >= GLOBAL_RECON_TIMEOUT) {
      return { connector: serviceName, domain, observations: [], errors: ['Global recon timeout reached'], durationMs: 0, rateLimited: false };
    }

    // Circuit breaker gate
    const cbCheck = shouldAllowRequest(serviceName, cbConfig);
    if (!cbCheck.allowed) {
      console.log(`[PassiveRecon] Circuit OPEN for ${serviceName} — skipping (${cbCheck.reason})`);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: 'skipped', error: cbCheck.reason });
      return { connector: serviceName, domain, observations: [], errors: [`Circuit breaker open: ${cbCheck.reason}`], durationMs: 0, rateLimited: false };
    }

    await onConnectorProgress?.({ connector: serviceName, status: 'started' });
    const connStart = Date.now();

    // Create abort controller for this connector
    const abortCtrl = new AbortController();
    const cfgWithAbort: ConnectorConfig = {
      ...connectorConfigs.get(serviceName),
      signal: abortCtrl.signal,
      timeout: Math.min(timeout, HARD_CONNECTOR_TIMEOUT),
    };

    // Promise.race: connector vs hard timeout
    // The timeout promise resolves (not rejects) with a timeout result
    const timeoutPromise = new Promise<ConnectorResult>((resolve) => {
      setTimeout(() => {
        abortCtrl.abort('Hard timeout');
        resolve(makeTimeoutResult(serviceName));
      }, HARD_CONNECTOR_TIMEOUT);
    });

    const connectorPromise = (async (): Promise<ConnectorResult> => {
      try {
        const result = await connector.collect(domain, cfgWithAbort);
        return result;
      } catch (err: any) {
        return {
          connector: serviceName,
          domain,
          observations: [],
          errors: [`Connector error: ${err.message}`],
          durationMs: Date.now() - connStart,
          rateLimited: false,
        };
      }
    })();

    const result = await Promise.race([connectorPromise, timeoutPromise]);
    const connDuration = Date.now() - connStart;

    // Track success/failure
    const hasAuthError = result.errors.some(e => e.includes('401') || e.includes('Unauthorized') || e.includes('invalid') || e.includes('not configured') || e.includes('skipping'));
    const hasRateLimit = result.rateLimited;
    const isTimeout = result.errors.some(e => e.includes('Hard timeout'));

    if (isTimeout) {
      console.log(`[PassiveRecon] ${serviceName} HARD TIMEOUT after ${(connDuration / 1000).toFixed(1)}s — abandoned`);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: `Hard timeout (${HARD_CONNECTOR_TIMEOUT / 1000}s)`, durationMs: connDuration });
    } else if (hasAuthError) {
      const classified = classifyError(new Error(result.errors[0]), serviceName);
      recordFailure(serviceName, classified, cbConfig);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: 'skipped', error: result.errors[0], durationMs: connDuration });
    } else if (hasRateLimit) {
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: 'Rate limited', observations: result.observations.length, durationMs: connDuration });
    } else if (result.errors.length > 0 && result.observations.length === 0) {
      const classified = classifyError(new Error(result.errors[0]), serviceName);
      recordFailure(serviceName, classified, cbConfig);
      trackCall(serviceName, false);
      await onConnectorProgress?.({ connector: serviceName, status: 'failed', error: result.errors[0], observations: 0, durationMs: connDuration });
    } else {
      recordSuccess(serviceName);
      trackCall(serviceName, true);
      await onConnectorProgress?.({ connector: serviceName, status: 'completed', observations: result.observations.length, durationMs: connDuration });
    }

    return result;
  }

  // Process main connectors through a concurrency-limited pool
  // (GitHub connectors run in background after main pool completes)
  const allConnectorPromises = mainConnectors.map((connector) => {
    return new Promise<void>(async (resolve) => {
      // Wait for a slot in the pool
      while (activeCount >= maxConcurrent) {
        await new Promise(r => setTimeout(r, 100)); // Poll every 100ms for a free slot
      }
      // Check global timeout before starting
      if (Date.now() - reconStart >= GLOBAL_RECON_TIMEOUT) {
        connectorResults.push({
          connector: connector.name, domain, observations: [],
          errors: ['Global recon timeout reached — skipped'], durationMs: 0, rateLimited: false,
        });
        resolve();
        return;
      }
      activeCount++;
      try {
        const result = await runSingleConnector(connector);
        connectorResults.push(result);
      } catch (err: any) {
        connectorResults.push({
          connector: connector.name, domain, observations: [],
          errors: [`Unexpected error: ${err.message}`], durationMs: 0, rateLimited: false,
        });
      } finally {
        activeCount--;
        resolve();
      }
    });
  });

  await Promise.all(allConnectorPromises);

  // ── Background queue: run GitHub connectors with lower priority ──
  // These run after main connectors complete, with a generous timeout.
  // Results are merged into the main results before signal classification.
  if (backgroundConnectors.length > 0 && (Date.now() - reconStart) < GLOBAL_RECON_TIMEOUT) {
    const bgTimeout = Math.min(45_000, GLOBAL_RECON_TIMEOUT - (Date.now() - reconStart));
    console.log(`[PassiveRecon] Starting background connectors (${bgTimeout / 1000}s budget remaining)`);
    const bgPromises = backgroundConnectors.map(async (connector) => {
      try {
        const result = await runSingleConnector(connector);
        connectorResults.push(result);
      } catch (err: any) {
        connectorResults.push({
          connector: connector.name, domain, observations: [],
          errors: [`Background connector error: ${err.message}`], durationMs: 0, rateLimited: false,
        });
      }
    });
    // Race background connectors against remaining budget
    const bgTimeoutPromise = new Promise<void>((resolve) => setTimeout(resolve, bgTimeout));
    await Promise.race([Promise.all(bgPromises), bgTimeoutPromise]);
    console.log(`[PassiveRecon] Background connectors finished or timed out`);
  } else if (backgroundConnectors.length > 0) {
    // Global timeout already reached, skip background connectors
    for (const c of backgroundConnectors) {
      connectorResults.push({
        connector: c.name, domain, observations: [],
        errors: ['Skipped: global timeout reached before background queue'], durationMs: 0, rateLimited: false,
      });
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
  let allObservations: AssetObservation[] = [];
  for (const result of connectorResults) {
    for (const obs of result.observations) {
      if (!seenAssets.has(obs.assetId)) {
        seenAssets.add(obs.assetId);
        allObservations.push(obs);
      }
    }
  }

  // ── Wildcard DNS Detection (Audit R3) ──────────────────────────────
  // Before accepting subdomain results, check for wildcard DNS.
  // If detected, tag observations that resolve to wildcard IPs.
  let wildcardResult: Awaited<ReturnType<typeof detectWildcardDns>> | null = null;
  try {
    wildcardResult = await detectWildcardDns(domain, 5000);
    if (wildcardResult.isWildcard) {
      console.log(`[PassiveRecon] ⚠️ Wildcard DNS detected for ${domain} — IPs: ${wildcardResult.wildcardIps.join(", ")}`);
      allObservations = tagWildcardObservations(allObservations, wildcardResult);
    }
  } catch (err: any) {
    console.log(`[PassiveRecon] Wildcard detection failed for ${domain}: ${err.message}`);
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

  // Add wildcard DNS signal if detected
  if (wildcardResult?.isWildcard) {
    const wcSignal = createWildcardSignal(domain, wildcardResult);
    corroboratedSignals.push(wcSignal as any);
  }

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
    wildcardDetection: wildcardResult ? {
      isWildcard: wildcardResult.isWildcard,
      wildcardIps: wildcardResult.wildcardIps,
      durationMs: wildcardResult.durationMs,
    } : null,
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
// Pipeline optimization v2 - Mon Mar  9 01:37:44 EDT 2026
