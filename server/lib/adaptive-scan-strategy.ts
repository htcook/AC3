/**
 * adaptive-scan-strategy.ts
 * 
 * Uses graduation scores and historical connector performance to dynamically
 * tune the DI scan pipeline for future scans on the same or similar targets.
 * 
 * Decisions made:
 *  1. Connector ranking — prioritize connectors that historically yield the most
 *     observations for this domain/sector, deprioritize those that fail or timeout.
 *  2. Scan depth — adjust maxConcurrent, timeout, and scan mode based on
 *     recon_analyst graduation scores (higher score → deeper, more aggressive).
 *  3. Evasion strategy — select evasion presets based on evasion_optimizer scores
 *     and WAF detection history.
 *  4. Focus areas — route more resources to asset categories where cloud_assessor
 *     or supply_chain_analyst scores indicate gaps.
 */

import type { GraduationResult } from './post-pipeline-graduation';

// ─── Types ───────────────────────────────────────────────────────────

export interface ConnectorPerformance {
  connector: string;
  domain: string;
  observations: number;
  durationMs: number;
  status: 'completed' | 'failed' | 'skipped' | 'timeout';
  scanId: number;
  timestamp: number;
}

export interface DomainScanHistory {
  domain: string;
  scanCount: number;
  lastScanAt: number;
  avgGraduationScores: GraduationResult['scores'] | null;
  connectorPerformance: ConnectorPerformance[];
  wafDetectedCount: number;
  wafBypassedCount: number;
  avgScanDurationMs: number;
  sector?: string;
}

export interface AdaptiveScanStrategy {
  /** Connectors sorted by predicted value (highest first) */
  connectorRanking: ConnectorRank[];
  /** Recommended scan depth parameters */
  scanDepth: ScanDepthConfig;
  /** Evasion preset selection */
  evasionPreset: EvasionPreset;
  /** Focus area recommendations */
  focusAreas: FocusArea[];
  /** Human-readable rationale for each decision */
  rationale: string[];
  /** Confidence level (0-1) based on data availability */
  confidence: number;
  /** Source data used for decisions */
  basedOn: {
    scanCount: number;
    graduationDataAvailable: boolean;
    connectorHistoryCount: number;
  };
}

export interface ConnectorRank {
  connector: string;
  /** Predicted value score 0-100 */
  score: number;
  /** Whether to include in the scan */
  include: boolean;
  /** Reason for ranking */
  reason: string;
  /** Historical avg observations for this domain */
  avgObservations: number;
  /** Historical avg duration */
  avgDurationMs: number;
  /** Historical failure rate (0-1) */
  failureRate: number;
}

export interface ScanDepthConfig {
  /** Recommended scan mode */
  scanMode: 'strict_passive' | 'standard' | 'active';
  /** Recommended max concurrent connectors */
  maxConcurrent: number;
  /** Recommended per-connector timeout (ms) */
  connectorTimeout: number;
  /** Whether to enable recursive discovery */
  enableRecursiveDiscovery: boolean;
  /** Max depth for recursive discovery */
  recursiveDepth: number;
  /** Whether to run background connectors (GitHub etc.) */
  enableBackgroundConnectors: boolean;
}

export interface EvasionPreset {
  name: 'none' | 'cautious' | 'standard' | 'aggressive';
  /** Request delay between connector calls (ms) */
  requestDelayMs: number;
  /** Whether to randomize connector order */
  randomizeOrder: boolean;
  /** Whether to use rotating user agents */
  rotateUserAgents: boolean;
  /** Reason for selection */
  reason: string;
}

export interface FocusArea {
  area: string;
  priority: 'high' | 'medium' | 'low';
  reason: string;
  /** Connectors that serve this focus area */
  relevantConnectors: string[];
}

// ─── Connector Category Map ──────────────────────────────────────────

const CONNECTOR_CATEGORIES: Record<string, string[]> = {
  recon_core: ['crtsh', 'shodan_internetdb', 'shodan', 'censys', 'securitytrails', 'dns_deep', 'rdap', 'ripestat'],
  vuln_intel: ['shodan', 'censys', 'virustotal', 'google_safebrowsing', 'phishtank'],
  cloud_assets: ['cloud_assets', 'cloud_bucket_recon', 'container_discovery'],
  supply_chain: ['github_leaks', 'github_recon', 'builtwith', 'commoncrawl'],
  threat_intel: ['greynoise', 'alienvault_otx', 'threatfox', 'threatminer', 'abuseipdb', 'darkweb_crossref'],
  credential_exposure: ['dehashed', 'dehashed_whois', 'hibp', 'leakix', 'leakcheck', 'hudson_rock', 'intelx_search'],
  email_security: ['email_security', 'domain_health'],
  web_security: ['http_security', 'urlscan', 'wayback'],
  company_intel: ['company_intel', 'hunter', 'social_media', 'whoisxml', 'reverse_whois'],
  network_intel: ['bgpview', 'ip_api', 'netlas', 'fullhunt', 'passivetotal', 'circlpdns'],
};

/** Invert the map: connector → categories */
const CONNECTOR_TO_CATEGORIES: Record<string, string[]> = {};
for (const [cat, connectors] of Object.entries(CONNECTOR_CATEGORIES)) {
  for (const c of connectors) {
    if (!CONNECTOR_TO_CATEGORIES[c]) CONNECTOR_TO_CATEGORIES[c] = [];
    CONNECTOR_TO_CATEGORIES[c].push(cat);
  }
}

// ─── In-Memory Store ─────────────────────────────────────────────────
// Graduation scores and connector performance are stored in memory and
// also persisted to the database (see phase 4). This in-memory store
// provides fast lookups during strategy computation.

const graduationStore = new Map<string, { scores: GraduationResult['scores']; timestamp: number }[]>();
const connectorPerfStore = new Map<string, ConnectorPerformance[]>();

/**
 * Record graduation scores for a domain.
 */
export function recordGraduationScores(domain: string, scores: GraduationResult['scores']): void {
  const key = domain.toLowerCase();
  if (!graduationStore.has(key)) graduationStore.set(key, []);
  graduationStore.get(key)!.push({ scores, timestamp: Date.now() });
  // Keep last 20 entries per domain
  const entries = graduationStore.get(key)!;
  if (entries.length > 20) graduationStore.set(key, entries.slice(-20));
}

/**
 * Record connector performance for a domain.
 */
export function recordConnectorPerformance(perf: ConnectorPerformance): void {
  const key = perf.domain.toLowerCase();
  if (!connectorPerfStore.has(key)) connectorPerfStore.set(key, []);
  connectorPerfStore.get(key)!.push(perf);
  // Keep last 500 entries per domain
  const entries = connectorPerfStore.get(key)!;
  if (entries.length > 500) connectorPerfStore.set(key, entries.slice(-500));
}

/**
 * Bulk record connector performance from a scan's connector results.
 */
export function recordConnectorResults(
  domain: string,
  scanId: number,
  connectorResults: Array<{ connector: string; observations: any[]; errors: string[]; durationMs: number; rateLimited: boolean }>
): void {
  for (const cr of connectorResults) {
    const status: ConnectorPerformance['status'] =
      cr.errors.some(e => e.includes('Hard timeout')) ? 'timeout' :
      cr.errors.some(e => e.includes('Skipped')) ? 'skipped' :
      cr.errors.length > 0 && cr.observations.length === 0 ? 'failed' :
      'completed';
    recordConnectorPerformance({
      connector: cr.connector,
      domain,
      observations: cr.observations.length,
      durationMs: cr.durationMs,
      status,
      scanId,
      timestamp: Date.now(),
    });
  }
}

/**
 * Get domain scan history from in-memory stores.
 */
export function getDomainHistory(domain: string): DomainScanHistory | null {
  const key = domain.toLowerCase();
  const gradEntries = graduationStore.get(key);
  const perfEntries = connectorPerfStore.get(key);

  if (!gradEntries?.length && !perfEntries?.length) return null;

  // Compute average graduation scores
  let avgScores: GraduationResult['scores'] | null = null;
  if (gradEntries?.length) {
    const sum: Record<string, number> = {};
    for (const entry of gradEntries) {
      for (const [model, score] of Object.entries(entry.scores)) {
        sum[model] = (sum[model] || 0) + score;
      }
    }
    avgScores = {} as any;
    for (const [model, total] of Object.entries(sum)) {
      (avgScores as any)[model] = Math.round(total / gradEntries.length);
    }
  }

  // Unique scan IDs
  const scanIds = new Set(perfEntries?.map(p => p.scanId) || []);

  return {
    domain: key,
    scanCount: Math.max(scanIds.size, gradEntries?.length || 0),
    lastScanAt: Math.max(
      gradEntries?.length ? gradEntries[gradEntries.length - 1].timestamp : 0,
      perfEntries?.length ? perfEntries[perfEntries.length - 1].timestamp : 0,
    ),
    avgGraduationScores: avgScores,
    connectorPerformance: perfEntries || [],
    wafDetectedCount: 0, // Will be enriched from graduation data
    wafBypassedCount: 0,
    avgScanDurationMs: perfEntries?.length
      ? perfEntries.reduce((s, p) => s + p.durationMs, 0) / perfEntries.length
      : 0,
  };
}

// ─── Strategy Computation ────────────────────────────────────────────

/**
 * Compute an adaptive scan strategy for a domain based on graduation
 * scores and historical connector performance.
 */
export function computeAdaptiveStrategy(
  domain: string,
  options?: {
    /** Override: force a specific scan mode */
    forceScanMode?: 'strict_passive' | 'standard' | 'active';
    /** Override: force specific connectors to include */
    forceInclude?: string[];
    /** Override: force specific connectors to exclude */
    forceExclude?: string[];
    /** Sector hint for cross-domain learning */
    sector?: string;
  }
): AdaptiveScanStrategy {
  const history = getDomainHistory(domain);
  const rationale: string[] = [];
  const confidence = history ? Math.min(1, history.scanCount / 5) : 0;

  // ── 1. Connector Ranking ───────────────────────────────────────────
  const connectorRanking = computeConnectorRanking(domain, history, options, rationale);

  // ── 2. Scan Depth ──────────────────────────────────────────────────
  const scanDepth = computeScanDepth(history, options, rationale);

  // ── 3. Evasion Preset ──────────────────────────────────────────────
  const evasionPreset = computeEvasionPreset(history, rationale);

  // ── 4. Focus Areas ─────────────────────────────────────────────────
  const focusAreas = computeFocusAreas(history, rationale);

  return {
    connectorRanking,
    scanDepth,
    evasionPreset,
    focusAreas,
    rationale,
    confidence,
    basedOn: {
      scanCount: history?.scanCount || 0,
      graduationDataAvailable: !!history?.avgGraduationScores,
      connectorHistoryCount: history?.connectorPerformance.length || 0,
    },
  };
}

function computeConnectorRanking(
  domain: string,
  history: DomainScanHistory | null,
  options: { forceInclude?: string[]; forceExclude?: string[] } | undefined,
  rationale: string[]
): ConnectorRank[] {
  const key = domain.toLowerCase();
  const perfEntries = connectorPerfStore.get(key) || [];

  // Group performance by connector
  const byConnector = new Map<string, ConnectorPerformance[]>();
  for (const p of perfEntries) {
    if (!byConnector.has(p.connector)) byConnector.set(p.connector, []);
    byConnector.get(p.connector)!.push(p);
  }

  // All known connectors (from categories + history)
  const allConnectors = new Set<string>();
  for (const connectors of Object.values(CONNECTOR_CATEGORIES)) {
    for (const c of connectors) allConnectors.add(c);
  }
  for (const c of byConnector.keys()) allConnectors.add(c);

  const rankings: ConnectorRank[] = [];

  for (const connector of allConnectors) {
    const entries = byConnector.get(connector) || [];
    const avgObs = entries.length > 0
      ? entries.reduce((s, e) => s + e.observations, 0) / entries.length
      : -1; // Unknown
    const avgDur = entries.length > 0
      ? entries.reduce((s, e) => s + e.durationMs, 0) / entries.length
      : -1;
    const failCount = entries.filter(e => e.status === 'failed' || e.status === 'timeout').length;
    const failureRate = entries.length > 0 ? failCount / entries.length : 0;

    // Score computation:
    // - Base: 50 (unknown connectors get a neutral score)
    // - +0-30 for observation yield (more observations = higher score)
    // - -0-30 for failure rate (higher failure = lower score)
    // - +0-10 for speed (faster = bonus)
    // - +0-10 for focus area alignment (if graduation scores indicate gaps)
    let score = 50;
    let reason = 'No history — using default priority';

    if (entries.length > 0) {
      // Observation yield bonus (0-30)
      const obsBonus = Math.min(30, avgObs * 3);
      score += obsBonus;

      // Failure penalty (0-30)
      const failPenalty = failureRate * 30;
      score -= failPenalty;

      // Speed bonus (0-10): connectors under 5s get full bonus
      if (avgDur > 0) {
        const speedBonus = Math.max(0, 10 - (avgDur / 5000) * 10);
        score += speedBonus;
      }

      reason = `Avg ${avgObs.toFixed(1)} obs, ${(failureRate * 100).toFixed(0)}% fail rate, ${(avgDur / 1000).toFixed(1)}s avg`;
    }

    // Focus area alignment bonus from graduation scores
    if (history?.avgGraduationScores) {
      const categories = CONNECTOR_TO_CATEGORIES[connector] || [];
      const gs = history.avgGraduationScores;

      // If cloud_assessor is low and this connector serves cloud_assets, boost it
      if (categories.includes('cloud_assets') && gs.cloud_assessor < 40) {
        score += 10;
        reason += ' | Boosted: low cloud_assessor score';
      }
      // If supply_chain_analyst is low and this serves supply_chain, boost it
      if (categories.includes('supply_chain') && gs.supply_chain_analyst < 40) {
        score += 10;
        reason += ' | Boosted: low supply_chain score';
      }
      // If recon_analyst is high, boost core recon connectors for deeper coverage
      if (categories.includes('recon_core') && gs.recon_analyst > 70) {
        score += 5;
        reason += ' | Boosted: strong recon baseline';
      }
    }

    // Clamp score
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Determine inclusion
    let include = score >= 20;
    if (options?.forceInclude?.includes(connector)) { include = true; reason += ' | Force-included'; }
    if (options?.forceExclude?.includes(connector)) { include = false; reason += ' | Force-excluded'; }

    // Connectors with >80% failure rate over 3+ runs are excluded
    if (failureRate > 0.8 && entries.length >= 3 && !options?.forceInclude?.includes(connector)) {
      include = false;
      reason += ' | Auto-excluded: persistent failures';
    }

    rankings.push({
      connector,
      score,
      include,
      reason,
      avgObservations: avgObs >= 0 ? Math.round(avgObs * 10) / 10 : 0,
      avgDurationMs: avgDur >= 0 ? Math.round(avgDur) : 0,
      failureRate: Math.round(failureRate * 100) / 100,
    });
  }

  // Sort by score descending
  rankings.sort((a, b) => b.score - a.score);

  const includedCount = rankings.filter(r => r.include).length;
  const excludedCount = rankings.filter(r => !r.include).length;
  rationale.push(`Connector ranking: ${includedCount} included, ${excludedCount} excluded based on ${perfEntries.length} historical data points`);

  return rankings;
}

function computeScanDepth(
  history: DomainScanHistory | null,
  options: { forceScanMode?: 'strict_passive' | 'standard' | 'active' } | undefined,
  rationale: string[]
): ScanDepthConfig {
  const defaults: ScanDepthConfig = {
    scanMode: 'standard',
    maxConcurrent: 5,
    connectorTimeout: 15000,
    enableRecursiveDiscovery: false,
    recursiveDepth: 2,
    enableBackgroundConnectors: true,
  };

  if (options?.forceScanMode) {
    defaults.scanMode = options.forceScanMode;
    rationale.push(`Scan mode forced to: ${options.forceScanMode}`);
    return defaults;
  }

  if (!history?.avgGraduationScores) {
    rationale.push('Scan depth: using defaults (no graduation history)');
    return defaults;
  }

  const gs = history.avgGraduationScores;

  // Recon analyst score drives depth decisions
  if (gs.recon_analyst >= 70) {
    // Strong recon performance → go deeper
    defaults.maxConcurrent = 8;
    defaults.connectorTimeout = 20000;
    defaults.enableRecursiveDiscovery = true;
    defaults.recursiveDepth = 3;
    rationale.push(`Scan depth: DEEP — recon_analyst score ${gs.recon_analyst} indicates strong baseline, increasing depth for diminishing-return coverage`);
  } else if (gs.recon_analyst >= 40) {
    // Moderate → standard with slight boost
    defaults.maxConcurrent = 6;
    defaults.connectorTimeout = 15000;
    defaults.enableRecursiveDiscovery = true;
    defaults.recursiveDepth = 2;
    rationale.push(`Scan depth: STANDARD+ — recon_analyst score ${gs.recon_analyst}, enabling recursive discovery`);
  } else {
    // Low recon score → focus on breadth, not depth
    defaults.maxConcurrent = 10;
    defaults.connectorTimeout = 12000;
    defaults.enableRecursiveDiscovery = false;
    rationale.push(`Scan depth: BROAD — recon_analyst score ${gs.recon_analyst} is low, maximizing connector breadth over depth`);
  }

  // Cognitive core score influences scan mode
  if (gs.cognitive_core >= 80 && history.scanCount >= 3) {
    defaults.scanMode = 'active';
    rationale.push(`Scan mode: ACTIVE — cognitive_core score ${gs.cognitive_core} with ${history.scanCount} prior scans justifies active probing`);
  }

  // If average scan duration is very long, reduce concurrency to avoid overload
  if (history.avgScanDurationMs > 180000) {
    defaults.maxConcurrent = Math.max(3, defaults.maxConcurrent - 2);
    rationale.push(`Concurrency reduced: avg scan duration ${(history.avgScanDurationMs / 1000).toFixed(0)}s exceeds 3min threshold`);
  }

  return defaults;
}

function computeEvasionPreset(
  history: DomainScanHistory | null,
  rationale: string[]
): EvasionPreset {
  const defaultPreset: EvasionPreset = {
    name: 'standard',
    requestDelayMs: 0,
    randomizeOrder: false,
    rotateUserAgents: false,
    reason: 'No evasion history — using standard preset',
  };

  if (!history?.avgGraduationScores) {
    rationale.push('Evasion: standard preset (no history)');
    return defaultPreset;
  }

  const evasionScore = history.avgGraduationScores.evasion_optimizer;
  const wafRate = history.scanCount > 0
    ? history.wafDetectedCount / history.scanCount
    : 0;

  if (evasionScore >= 80) {
    // High evasion score → WAF handling is working well, stay aggressive
    rationale.push(`Evasion: NONE — evasion_optimizer score ${evasionScore} indicates clean scanning`);
    return {
      name: 'none',
      requestDelayMs: 0,
      randomizeOrder: false,
      rotateUserAgents: false,
      reason: `Evasion score ${evasionScore}: no WAF issues detected`,
    };
  }

  if (evasionScore >= 50 || wafRate > 0.3) {
    // Moderate evasion or frequent WAF → be cautious
    rationale.push(`Evasion: CAUTIOUS — evasion_optimizer score ${evasionScore}, WAF rate ${(wafRate * 100).toFixed(0)}%`);
    return {
      name: 'cautious',
      requestDelayMs: 500,
      randomizeOrder: true,
      rotateUserAgents: true,
      reason: `Evasion score ${evasionScore}, WAF detected in ${(wafRate * 100).toFixed(0)}% of scans`,
    };
  }

  if (evasionScore < 50) {
    // Low evasion score → target has strong defenses, go aggressive evasion
    rationale.push(`Evasion: AGGRESSIVE — evasion_optimizer score ${evasionScore} indicates strong target defenses`);
    return {
      name: 'aggressive',
      requestDelayMs: 1000,
      randomizeOrder: true,
      rotateUserAgents: true,
      reason: `Evasion score ${evasionScore}: target has strong WAF/defenses, maximizing evasion`,
    };
  }

  return defaultPreset;
}

function computeFocusAreas(
  history: DomainScanHistory | null,
  rationale: string[]
): FocusArea[] {
  const areas: FocusArea[] = [];

  if (!history?.avgGraduationScores) {
    rationale.push('Focus areas: none (no graduation history)');
    return areas;
  }

  const gs = history.avgGraduationScores;

  // Cloud assessment gap
  if (gs.cloud_assessor < 30) {
    areas.push({
      area: 'Cloud & Container Assets',
      priority: 'high',
      reason: `cloud_assessor score ${gs.cloud_assessor} — cloud infrastructure may be under-discovered`,
      relevantConnectors: CONNECTOR_CATEGORIES.cloud_assets || [],
    });
  } else if (gs.cloud_assessor < 60) {
    areas.push({
      area: 'Cloud & Container Assets',
      priority: 'medium',
      reason: `cloud_assessor score ${gs.cloud_assessor} — moderate cloud coverage, room for improvement`,
      relevantConnectors: CONNECTOR_CATEGORIES.cloud_assets || [],
    });
  }

  // Supply chain gap
  if (gs.supply_chain_analyst < 30) {
    areas.push({
      area: 'Supply Chain & Code Exposure',
      priority: 'high',
      reason: `supply_chain_analyst score ${gs.supply_chain_analyst} — code repos and dependencies under-analyzed`,
      relevantConnectors: CONNECTOR_CATEGORIES.supply_chain || [],
    });
  } else if (gs.supply_chain_analyst < 60) {
    areas.push({
      area: 'Supply Chain & Code Exposure',
      priority: 'medium',
      reason: `supply_chain_analyst score ${gs.supply_chain_analyst} — partial supply chain coverage`,
      relevantConnectors: CONNECTOR_CATEGORIES.supply_chain || [],
    });
  }

  // Exploit/vuln identification gap
  if (gs.exploit_selector < 40) {
    areas.push({
      area: 'Vulnerability Identification',
      priority: 'high',
      reason: `exploit_selector score ${gs.exploit_selector} — vuln detection needs improvement`,
      relevantConnectors: CONNECTOR_CATEGORIES.vuln_intel || [],
    });
  }

  // Credential exposure gap (inferred from recon + exploit scores)
  if (gs.recon_analyst > 60 && gs.exploit_selector < 50) {
    areas.push({
      area: 'Credential & Data Exposure',
      priority: 'medium',
      reason: 'Good recon but low exploit identification — credential exposure may be under-checked',
      relevantConnectors: CONNECTOR_CATEGORIES.credential_exposure || [],
    });
  }

  // Evasion gap
  if (gs.evasion_optimizer < 50) {
    areas.push({
      area: 'WAF/Defense Evasion',
      priority: 'medium',
      reason: `evasion_optimizer score ${gs.evasion_optimizer} — target defenses are blocking scans`,
      relevantConnectors: ['http_security'],
    });
  }

  if (areas.length > 0) {
    rationale.push(`Focus areas: ${areas.length} identified — ${areas.map(a => `${a.area} (${a.priority})`).join(', ')}`);
  } else {
    rationale.push('Focus areas: none — all graduation scores are healthy');
  }

  return areas;
}

// ─── Strategy Application Helpers ────────────────────────────────────

/**
 * Apply an adaptive strategy to filter and reorder a connector list.
 * Returns the connectors in recommended execution order.
 */
export function applyConnectorStrategy(
  allConnectors: Array<{ name: string; [key: string]: any }>,
  strategy: AdaptiveScanStrategy
): Array<{ name: string; [key: string]: any }> {
  const rankMap = new Map(strategy.connectorRanking.map(r => [r.connector, r]));

  // Filter out excluded connectors
  const included = allConnectors.filter(c => {
    const rank = rankMap.get(c.name);
    return !rank || rank.include; // If no ranking data, include by default
  });

  // Sort by ranking score (highest first)
  included.sort((a, b) => {
    const scoreA = rankMap.get(a.name)?.score ?? 50;
    const scoreB = rankMap.get(b.name)?.score ?? 50;
    return scoreB - scoreA;
  });

  return included;
}

/**
 * Get a human-readable strategy summary for logging.
 */
export function formatStrategySummary(strategy: AdaptiveScanStrategy): string {
  const lines: string[] = [
    `[AdaptiveStrategy] Confidence: ${(strategy.confidence * 100).toFixed(0)}% (${strategy.basedOn.scanCount} prior scans)`,
    `  Scan depth: mode=${strategy.scanDepth.scanMode}, concurrent=${strategy.scanDepth.maxConcurrent}, timeout=${strategy.scanDepth.connectorTimeout}ms`,
    `  Evasion: ${strategy.evasionPreset.name} — ${strategy.evasionPreset.reason}`,
    `  Connectors: ${strategy.connectorRanking.filter(r => r.include).length} included, ${strategy.connectorRanking.filter(r => !r.include).length} excluded`,
  ];
  if (strategy.focusAreas.length > 0) {
    lines.push(`  Focus areas: ${strategy.focusAreas.map(a => `${a.area} (${a.priority})`).join(', ')}`);
  }
  for (const r of strategy.rationale) {
    lines.push(`  → ${r}`);
  }
  return lines.join('\n');
}

/**
 * Reset in-memory stores (for testing).
 */
export function _resetStores(): void {
  graduationStore.clear();
  connectorPerfStore.clear();
}
