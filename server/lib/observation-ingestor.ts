/**
 * SSIL Observation Ingestor
 *
 * Central service that wires the observation normalizer into live scan flows.
 * Call ingestXxxResults() after each scanner completes to:
 *   1. Normalize raw results → NormalizedObservation[]
 *   2. Derive signals from observations
 *   3. Generate risk cards from signals
 *   4. Persist everything to the database
 *   5. Emit events for real-time streaming
 *
 * Author: Harrison Cook — AceofCloud
 */

import {
  adaptScanForgeResults,
  adaptNucleiResults,
  adaptZgrab2Results,
  adaptWebCrawlerResults,
  adaptDomainIntelResults,
  adaptVulnScanResults,
  deriveSignals,
  generateRiskCards,
  observationToInsert,
  type ScanForgeRawResult,
  type NucleiRawResult,
  type Zgrab2RawResult,
  type WebCrawlerRawResult,
  type DomainIntelRawResult,
  type VulnScanRawResult,
  type NormalizedObservation,
  type AdapterResult,
} from "./observation-normalizer";
import type { InsertScanObservation, InsertScanSignal, InsertScanRiskCard } from "../../drizzle/schema";

// ─── Event System for Real-Time Streaming ──────────────────────────────────

export type IngestionEventType = "observations" | "signals" | "risk_cards" | "error";

export interface IngestionEvent {
  type: IngestionEventType;
  timestamp: number;
  scanner: string;
  count: number;
  data: any[];
}

type IngestionListener = (event: IngestionEvent) => void;

const listeners = new Set<IngestionListener>();
const recentEvents: IngestionEvent[] = [];
const MAX_RECENT_EVENTS = 200;

export function onIngestionEvent(listener: IngestionListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getRecentEvents(since?: number, limit = 50): IngestionEvent[] {
  const filtered = since
    ? recentEvents.filter((e) => e.timestamp > since)
    : recentEvents;
  return filtered.slice(-limit);
}

function emit(event: IngestionEvent): void {
  recentEvents.push(event);
  if (recentEvents.length > MAX_RECENT_EVENTS) {
    recentEvents.splice(0, recentEvents.length - MAX_RECENT_EVENTS);
  }
  for (const listener of listeners) {
    try {
      listener(event);
    } catch (err) {
      console.error("[ObservationIngestor] Listener error:", err);
    }
  }
}

// ─── Ingestion Stats ───────────────────────────────────────────────────────

interface IngestionStats {
  totalObservations: number;
  totalSignals: number;
  totalRiskCards: number;
  totalErrors: number;
  lastIngestionAt: number | null;
  byScanner: Record<string, { observations: number; signals: number; riskCards: number; errors: number; lastAt: number }>;
}

const stats: IngestionStats = {
  totalObservations: 0,
  totalSignals: 0,
  totalRiskCards: 0,
  totalErrors: 0,
  lastIngestionAt: null,
  byScanner: {},
};

export function getIngestionStats(): IngestionStats {
  return { ...stats };
}

function updateStats(scanner: string, observations: number, signals: number, riskCards: number, errors: number): void {
  stats.totalObservations += observations;
  stats.totalSignals += signals;
  stats.totalRiskCards += riskCards;
  stats.totalErrors += errors;
  stats.lastIngestionAt = Date.now();
  if (!stats.byScanner[scanner]) {
    stats.byScanner[scanner] = { observations: 0, signals: 0, riskCards: 0, errors: 0, lastAt: 0 };
  }
  stats.byScanner[scanner].observations += observations;
  stats.byScanner[scanner].signals += signals;
  stats.byScanner[scanner].riskCards += riskCards;
  stats.byScanner[scanner].errors += errors;
  stats.byScanner[scanner].lastAt = Date.now();
}

// ─── Database Persistence ──────────────────────────────────────────────────

async function persistObservations(observations: InsertScanObservation[]): Promise<number> {
  if (observations.length === 0) return 0;
  try {
    const { getDb } = await import("../db");
    const { scanObservations } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) {
      console.warn("[ObservationIngestor] Database unavailable, skipping observation persistence");
      return 0;
    }
    // Insert in batches of 50 to avoid query size limits
    let inserted = 0;
    for (let i = 0; i < observations.length; i += 50) {
      const batch = observations.slice(i, i + 50);
      try {
        await db.insert(scanObservations).values(batch);
        inserted += batch.length;
      } catch (err: any) {
        // Handle duplicate key errors gracefully (idempotent ingestion)
        if (err.code === "ER_DUP_ENTRY") {
          console.warn(`[ObservationIngestor] ${batch.length} duplicate observations skipped`);
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err: any) {
    console.error("[ObservationIngestor] Failed to persist observations:", err.message);
    return 0;
  }
}

async function persistSignals(signals: InsertScanSignal[]): Promise<number> {
  if (signals.length === 0) return 0;
  try {
    const { getDb } = await import("../db");
    const { scanSignals } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) return 0;
    let inserted = 0;
    for (let i = 0; i < signals.length; i += 50) {
      const batch = signals.slice(i, i + 50);
      try {
        await db.insert(scanSignals).values(batch);
        inserted += batch.length;
      } catch (err: any) {
        if (err.code === "ER_DUP_ENTRY") {
          console.warn(`[ObservationIngestor] ${batch.length} duplicate signals skipped`);
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err: any) {
    console.error("[ObservationIngestor] Failed to persist signals:", err.message);
    return 0;
  }
}

async function persistRiskCards(cards: InsertScanRiskCard[]): Promise<number> {
  if (cards.length === 0) return 0;
  try {
    const { getDb } = await import("../db");
    const { scanRiskCards } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) return 0;
    let inserted = 0;
    for (const card of cards) {
      try {
        await db.insert(scanRiskCards).values(card);
        inserted++;
      } catch (err: any) {
        if (err.code === "ER_DUP_ENTRY") {
          // Update existing risk card with new score
          const { eq } = await import("drizzle-orm");
          await db.update(scanRiskCards)
            .set({
              finalScore: card.finalScore,
              componentCvss: card.componentCvss,
              componentCarver: card.componentCarver,
              componentBia: card.componentBia,
              confidenceWeight: card.confidenceWeight,
              summary: card.summary,
              whyItMatters: card.whyItMatters,
              evidence: card.evidence,
              recommendations: card.recommendations,
              signalIds: card.signalIds ?? null,
              updatedAt: Date.now(),
            } as any)
            .where(eq(scanRiskCards.riskId, card.riskId));
          inserted++;
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err: any) {
    console.error("[ObservationIngestor] Failed to persist risk cards:", err.message);
    return 0;
  }
}

// ─── Core Ingestion Pipeline ───────────────────────────────────────────────

async function runIngestionPipeline(
  scannerName: string,
  adapterResult: AdapterResult
): Promise<{ observations: number; signals: number; riskCards: number; errors: string[] }> {
  const errors: string[] = [...adapterResult.metrics.errors];

  // 1. Convert to DB insert format
  const obsInserts = adapterResult.observations.map(observationToInsert);

  // 2. Persist observations
  const obsCount = await persistObservations(obsInserts);

  // 3. Emit observation events
  if (obsCount > 0) {
    emit({
      type: "observations",
      timestamp: Date.now(),
      scanner: scannerName,
      count: obsCount,
      data: adapterResult.observations.map((o) => ({
        observationId: o.observationId,
        assetHost: o.asset.host,
        assetPort: o.asset.port,
        observationType: o.observationType,
        severity: o.severity,
        summary: o.evidence.summary,
      })),
    });
  }

  // 4. Derive signals
  const signals = deriveSignals(adapterResult.observations);
  const sigCount = await persistSignals(signals);

  if (sigCount > 0) {
    emit({
      type: "signals",
      timestamp: Date.now(),
      scanner: scannerName,
      count: sigCount,
      data: signals.map((s) => ({
        signalId: s.signalId,
        assetId: s.assetId,
        signalType: s.signalType,
        category: s.category,
        confidence: s.confidence,
      })),
    });
  }

  // 5. Generate risk cards
  const riskCards = generateRiskCards(signals);
  const cardCount = await persistRiskCards(riskCards);

  if (cardCount > 0) {
    emit({
      type: "risk_cards",
      timestamp: Date.now(),
      scanner: scannerName,
      count: cardCount,
      data: riskCards.map((c) => ({
        riskId: c.riskId,
        assetId: c.assetId,
        finalScore: c.finalScore,
        summary: c.summary,
      })),
    });
  }

  // 6. Update stats
  updateStats(scannerName, obsCount, sigCount, cardCount, errors.length);

  console.log(
    `[ObservationIngestor] ${scannerName}: ${obsCount} observations, ${sigCount} signals, ${cardCount} risk cards ingested` +
    (errors.length > 0 ? ` (${errors.length} errors)` : "")
  );

  return { observations: obsCount, signals: sigCount, riskCards: cardCount, errors };
}

// ─── Scanner-Specific Ingestion Functions ──────────────────────────────────

export async function ingestScanForgeResults(rawResults: ScanForgeRawResult[]) {
  const adapterResult = adaptScanForgeResults(rawResults);
  return runIngestionPipeline("scanforge-discovery", adapterResult);
}

export async function ingestNucleiResults(rawResults: NucleiRawResult[]) {
  const adapterResult = adaptNucleiResults(rawResults);
  return runIngestionPipeline("nuclei", adapterResult);
}

export async function ingestZgrab2Results(rawResults: Zgrab2RawResult[]) {
  const adapterResult = adaptZgrab2Results(rawResults);
  return runIngestionPipeline("zgrab2", adapterResult);
}

export async function ingestWebCrawlerResults(rawResults: WebCrawlerRawResult[]) {
  const adapterResult = adaptWebCrawlerResults(rawResults);
  return runIngestionPipeline("web_crawler", adapterResult);
}

export async function ingestDomainIntelResults(rawResults: DomainIntelRawResult[]) {
  const adapterResult = adaptDomainIntelResults(rawResults);
  return runIngestionPipeline("domain_intel", adapterResult);
}

export async function ingestVulnScanResults(rawResults: VulnScanRawResult[]) {
  const adapterResult = adaptVulnScanResults(rawResults);
  return runIngestionPipeline("vuln_scanner", adapterResult);
}

/**
 * Ingest raw observations directly (for custom/generic scanners).
 * Observations must already be in NormalizedObservation format.
 */
export async function ingestRawObservations(
  scannerName: string,
  observations: NormalizedObservation[]
) {
  const adapterResult: AdapterResult = {
    observations,
    metrics: {
      durationMs: 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: [],
    },
  };
  return runIngestionPipeline(scannerName, adapterResult);
}

/**
 * Convert domain intel pipeline results into observation-normalizer format
 * and ingest them. This bridges the existing domainIntel.ts pipeline output
 * to the SSIL observation system.
 */
export async function ingestDomainIntelPipelineResults(pipelineResult: any) {
  const rawResults: DomainIntelRawResult[] = [];

  // Convert analyzed assets to domain intel raw results
  if (pipelineResult.assets && Array.isArray(pipelineResult.assets)) {
    for (const analysis of pipelineResult.assets) {
      const asset = analysis.asset || analysis;
      rawResults.push({
        domain: asset.hostname || pipelineResult.orgProfile?.primaryDomain || "unknown",
        dnsRecords: asset.dnsRecords || {},
        subdomains: asset.subdomains || [],
        whois: asset.whois || {},
        scanRunId: `pipeline-${Date.now().toString(36)}`,
      });
    }
  }

  if (rawResults.length > 0) {
    return ingestDomainIntelResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}

/**
 * Convert vuln scan import findings to observation-normalizer format
 * and ingest them. Bridges the existing vulnScanFindings table data.
 */
export async function ingestVulnScanImportFindings(findings: any[]) {
  const rawResults: VulnScanRawResult[] = findings.map((f) => ({
    host: f.hostIp || f.hostName || "unknown",
    port: f.port || undefined,
    protocol: f.protocol || undefined,
    title: f.title,
    description: f.description || undefined,
    severity: f.severity || "info",
    cvss: f.cvssScore || undefined,
    cve: f.cveId || undefined,
    confidence: f.corroborationScore ? f.corroborationScore / 100 : undefined,
    tags: f.exploitAvailable ? ["exploit_available"] : undefined,
    remediation: f.solution || undefined,
    scanRunId: `import-${f.importId || "unknown"}`,
  }));

  if (rawResults.length > 0) {
    return ingestVulnScanResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}

/**
 * Convert web crawler page results to observation-normalizer format
 * and ingest them.
 */
export async function ingestWebCrawlerPageResults(pages: any[]) {
  const rawResults: WebCrawlerRawResult[] = pages.map((page) => ({
    url: page.url || page.targetUrl || "",
    securityHeaders: page.securityHeaders
      ? {
          grade: page.securityHeaderGrade || undefined,
          present: page.securityHeaders?.present || [],
          missing: page.securityHeaders?.missing || [],
        }
      : undefined,
    exposedPaths: page.exposedPaths || undefined,
    technologies: page.detectedTechnologies || undefined,
    tls: page.tlsInfo || undefined,
    scanRunId: page.jobId || undefined,
  }));

  if (rawResults.length > 0) {
    return ingestWebCrawlerResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}

/**
 * Convert unified pipeline findings to observation-normalizer format.
 * Bridges the unified-pipeline.ts submitFindings flow.
 */
export async function ingestUnifiedPipelineFindings(
  tool: string,
  findings: any[]
) {
  // Map tool names to scanner adapters
  const toolToScanner: Record<string, string> = {
    zap_passive: "web_crawler",
    zap_active: "vuln_scanner",
    nuclei_info: "nuclei",
    nuclei_vuln: "nuclei",
    nuclei_critical: "nuclei",
    passive_osint: "domain_intel",
  };

  const scannerName = toolToScanner[tool] || "generic";

  // Convert pipeline findings to the appropriate raw format
  if (scannerName === "nuclei") {
    const rawResults: NucleiRawResult[] = findings.map((f) => ({
      templateId: f.templateId || f.id || "unknown",
      name: f.title || f.name,
      severity: f.severity || "info",
      host: f.host || f.target,
      matchedAt: f.matchedAt || f.url,
      cve: f.cveId,
      cvss: f.cvss,
      tags: f.tags,
    }));
    return ingestNucleiResults(rawResults);
  }

  if (scannerName === "vuln_scanner") {
    const rawResults: VulnScanRawResult[] = findings.map((f) => ({
      host: f.host || f.target || "unknown",
      port: f.port,
      title: f.title || f.name || "Unknown",
      severity: f.severity || "info",
      cvss: f.cvss,
      cve: f.cveId,
      confidence: f.confidence ? f.confidence / 100 : undefined,
    }));
    return ingestVulnScanResults(rawResults);
  }

  if (scannerName === "domain_intel") {
    const rawResults: DomainIntelRawResult[] = findings.map((f) => ({
      domain: f.host || f.target || "unknown",
      dnsRecords: f.evidence?.dns || {},
      subdomains: f.evidence?.subdomains || [],
    }));
    return ingestDomainIntelResults(rawResults);
  }

  // Generic: convert to vuln scanner format as fallback
  const rawResults: VulnScanRawResult[] = findings.map((f) => ({
    host: f.host || f.target || "unknown",
    port: f.port,
    title: f.title || f.name || "Unknown Finding",
    severity: f.severity || "info",
    cvss: f.cvss,
    cve: f.cveId,
  }));
  return ingestVulnScanResults(rawResults);
}

// ─── ProjectDiscovery Tool Ingestion ────────────────────────────────────────

/**
 * Ingest subfinder results into the SSIL observation pipeline.
 * Converts subdomain entries into dns-type observations.
 */
export async function ingestSubfinderResults(subfinderResult: any) {
  const observations: NormalizedObservation[] = [];

  for (const entry of subfinderResult.subdomains || []) {
    observations.push({
      observationId: `subfinder-${entry.subdomain}-${Date.now().toString(36)}`,
      asset: {
        assetId: `host:${entry.subdomain}`,
        host: entry.subdomain,
        port: 0,
        protocol: "dns",
        tags: ["subdomain", `source:${entry.source}`],
      },
      scanner: {
        name: "subfinder",
        version: "2.6.x",
        adapter: "subfinder",
        mode: "passive",
      },
      observationType: "dns",
      severity: "info",
      confidence: entry.alive ? 0.95 : 0.7,
      timestamp: new Date(entry.firstSeen || Date.now()).toISOString(),
      evidence: {
        summary: `Subdomain discovered: ${entry.subdomain} via ${entry.source}`,
        artifacts: [
          {
            type: "subdomain",
            subdomain: entry.subdomain,
            source: entry.source,
            ip: entry.ip,
            alive: entry.alive,
            cname: entry.cname,
          },
        ],
      },
      metadata: {
        scanRunId: `subfinder-${subfinderResult.domain}-${Date.now().toString(36)}`,
        notes: `Part of ${subfinderResult.domain} enumeration`,
      },
    });
  }

  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }

  const adapterResult: AdapterResult = {
    observations,
    metrics: {
      durationMs: subfinderResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: [],
    },
  };

  return runIngestionPipeline("subfinder", adapterResult);
}

/**
 * Ingest httpx results into the SSIL observation pipeline.
 * Converts HTTP probe entries into http_headers and tls observations.
 */
export async function ingestHttpxResults(httpxResult: any) {
  const observations: NormalizedObservation[] = [];

  for (const entry of httpxResult.targets || []) {
    // HTTP headers / web server observation
    observations.push({
      observationId: `httpx-http-${entry.host}-${entry.port}-${Date.now().toString(36)}`,
      asset: {
        assetId: `host:${entry.host}:${entry.port}`,
        host: entry.host,
        port: entry.port,
        protocol: entry.scheme === "https" ? "https" : "http",
        tags: [
          ...(entry.technologies || []).map((t: string) => `tech:${t.toLowerCase()}`),
          ...(entry.cdn ? [`cdn:${entry.cdn.toLowerCase()}`] : []),
        ],
      },
      scanner: {
        name: "httpx",
        version: "1.6.x",
        adapter: "httpx",
        mode: "active-low",
      },
      observationType: "http_headers",
      severity: entry.statusCode >= 500 ? "medium" : "info",
      confidence: entry.alive ? 0.95 : 0.5,
      timestamp: new Date(entry.timestamp || Date.now()).toISOString(),
      evidence: {
        summary: `HTTP probe: ${entry.url} → ${entry.statusCode} (${entry.webServer || "unknown"})`,
        artifacts: [
          {
            type: "http_probe",
            url: entry.url,
            statusCode: entry.statusCode,
            contentLength: entry.contentLength,
            title: entry.title,
            webServer: entry.webServer,
            technologies: entry.technologies,
            responseTime: entry.responseTime,
            method: entry.method,
            finalUrl: entry.finalUrl,
            bodyHash: entry.bodyHash,
            headerHash: entry.headerHash,
            faviconHash: entry.faviconHash,
            jarmHash: entry.jarmHash,
            cdn: entry.cdn,
            ip: entry.ip,
          },
        ],
      },
      metadata: {
        scanRunId: `httpx-${Date.now().toString(36)}`,
      },
    });

    // TLS observation if HTTPS
    if (entry.scheme === "https" && entry.tlsVersion) {
      observations.push({
        observationId: `httpx-tls-${entry.host}-${entry.port}-${Date.now().toString(36)}`,
        asset: {
          assetId: `host:${entry.host}:${entry.port}`,
          host: entry.host,
          port: entry.port,
          protocol: "tls",
        },
        scanner: {
          name: "httpx",
          version: "1.6.x",
          adapter: "httpx",
          mode: "active-low",
        },
        observationType: "tls",
        severity: entry.tlsVersion === "tls1.0" || entry.tlsVersion === "tls1.1" ? "high" : "info",
        confidence: 0.95,
        timestamp: new Date(entry.timestamp || Date.now()).toISOString(),
        evidence: {
          summary: `TLS ${entry.tlsVersion} with ${entry.tlsCipher || "unknown cipher"}`,
          artifacts: [
            {
              type: "tls_probe",
              tlsVersion: entry.tlsVersion,
              tlsCipher: entry.tlsCipher,
              certIssuer: entry.certIssuer,
              certSubject: entry.certSubject,
              certExpiry: entry.certExpiry,
              jarmHash: entry.jarmHash,
            },
          ],
        },
        metadata: {
          scanRunId: `httpx-${Date.now().toString(36)}`,
        },
      });
    }
  }

  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }

  const adapterResult: AdapterResult = {
    observations,
    metrics: {
      durationMs: httpxResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: [],
    },
  };

  return runIngestionPipeline("httpx", adapterResult);
}

/**
 * Ingest naabu results into the SSIL observation pipeline.
 * Converts port scan entries into service_banner observations.
 */
export async function ingestNaabuResults(naabuResult: any) {
  const observations: NormalizedObservation[] = [];

  for (const host of naabuResult.targets || []) {
    for (const port of host.ports || []) {
      observations.push({
        observationId: `naabu-${host.host}-${port.port}-${Date.now().toString(36)}`,
        asset: {
          assetId: `host:${host.host}:${port.port}`,
          host: host.host,
          port: port.port,
          protocol: port.protocol || "tcp",
          tags: [
            `state:${port.state}`,
            ...(port.service ? [`service:${port.service}`] : []),
            ...(port.tls ? ["tls:true"] : []),
          ],
        },
        scanner: {
          name: "naabu",
          version: "2.3.x",
          adapter: "naabu",
          mode: "active-low",
        },
        observationType: "service_banner",
        severity: "info",
        confidence: port.state === "open" ? 0.95 : 0.6,
        timestamp: new Date(port.timestamp || Date.now()).toISOString(),
        evidence: {
          summary: `Port ${port.port}/${port.protocol} ${port.state}${port.service ? ` (${port.service})` : ""}${port.version ? ` ${port.version}` : ""}`,
          artifacts: [
            {
              type: "port_scan",
              port: port.port,
              protocol: port.protocol,
              state: port.state,
              service: port.service,
              version: port.version,
              banner: port.banner,
              tls: port.tls,
              hostIp: host.ip,
              hostOs: host.os,
            },
          ],
        },
        metadata: {
          scanRunId: `naabu-${Date.now().toString(36)}`,
        },
      });
    }
  }

  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }

  const adapterResult: AdapterResult = {
    observations,
    metrics: {
      durationMs: naabuResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: [],
    },
  };

  return runIngestionPipeline("naabu", adapterResult);
}
