import {
  adaptDomainIntelResults,
  adaptNucleiResults,
  adaptScanForgeResults,
  adaptVulnScanResults,
  adaptWebCrawlerResults,
  adaptZgrab2Results,
  deriveSignals,
  generateRiskCards,
  init_observation_normalizer,
  observationToInsert
} from "./chunk-BCMODKPD.js";
import "./chunk-5BWO4Y3K.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/observation-ingestor.ts
function onIngestionEvent(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
function getRecentEvents(since, limit = 50) {
  const filtered = since ? recentEvents.filter((e) => e.timestamp > since) : recentEvents;
  return filtered.slice(-limit);
}
function emit(event) {
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
function getIngestionStats() {
  return { ...stats };
}
function updateStats(scanner, observations, signals, riskCards, errors) {
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
async function persistObservations(observations) {
  if (observations.length === 0) return 0;
  try {
    const { getDb } = await import("./db-PHFZ5GDL.js");
    const { scanObservations } = await import("./schema-XOTPZHKC.js");
    const db = await getDb();
    if (!db) {
      console.warn("[ObservationIngestor] Database unavailable, skipping observation persistence");
      return 0;
    }
    let inserted = 0;
    for (let i = 0; i < observations.length; i += 50) {
      const batch = observations.slice(i, i + 50);
      try {
        await db.insert(scanObservations).values(batch);
        inserted += batch.length;
      } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
          console.warn(`[ObservationIngestor] ${batch.length} duplicate observations skipped`);
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err) {
    console.error("[ObservationIngestor] Failed to persist observations:", err.message);
    return 0;
  }
}
async function persistSignals(signals) {
  if (signals.length === 0) return 0;
  try {
    const { getDb } = await import("./db-PHFZ5GDL.js");
    const { scanSignals } = await import("./schema-XOTPZHKC.js");
    const db = await getDb();
    if (!db) return 0;
    let inserted = 0;
    for (let i = 0; i < signals.length; i += 50) {
      const batch = signals.slice(i, i + 50);
      try {
        await db.insert(scanSignals).values(batch);
        inserted += batch.length;
      } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
          console.warn(`[ObservationIngestor] ${batch.length} duplicate signals skipped`);
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err) {
    console.error("[ObservationIngestor] Failed to persist signals:", err.message);
    return 0;
  }
}
async function persistRiskCards(cards) {
  if (cards.length === 0) return 0;
  try {
    const { getDb } = await import("./db-PHFZ5GDL.js");
    const { scanRiskCards } = await import("./schema-XOTPZHKC.js");
    const db = await getDb();
    if (!db) return 0;
    let inserted = 0;
    for (const card of cards) {
      try {
        await db.insert(scanRiskCards).values(card);
        inserted++;
      } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
          const { eq } = await import("drizzle-orm");
          await db.update(scanRiskCards).set({
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
            updatedAt: Date.now()
          }).where(eq(scanRiskCards.riskId, card.riskId));
          inserted++;
        } else {
          throw err;
        }
      }
    }
    return inserted;
  } catch (err) {
    console.error("[ObservationIngestor] Failed to persist risk cards:", err.message);
    return 0;
  }
}
async function runIngestionPipeline(scannerName, adapterResult) {
  const errors = [...adapterResult.metrics.errors];
  const obsInserts = adapterResult.observations.map(observationToInsert);
  const obsCount = await persistObservations(obsInserts);
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
        summary: o.evidence.summary
      }))
    });
  }
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
        confidence: s.confidence
      }))
    });
  }
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
        summary: c.summary
      }))
    });
  }
  updateStats(scannerName, obsCount, sigCount, cardCount, errors.length);
  console.log(
    `[ObservationIngestor] ${scannerName}: ${obsCount} observations, ${sigCount} signals, ${cardCount} risk cards ingested` + (errors.length > 0 ? ` (${errors.length} errors)` : "")
  );
  return { observations: obsCount, signals: sigCount, riskCards: cardCount, errors };
}
async function ingestScanForgeResults(rawResults) {
  const adapterResult = adaptScanForgeResults(rawResults);
  return runIngestionPipeline("scanforge-discovery", adapterResult);
}
async function ingestNucleiResults(rawResults) {
  const adapterResult = adaptNucleiResults(rawResults);
  return runIngestionPipeline("nuclei", adapterResult);
}
async function ingestZgrab2Results(rawResults) {
  const adapterResult = adaptZgrab2Results(rawResults);
  return runIngestionPipeline("zgrab2", adapterResult);
}
async function ingestWebCrawlerResults(rawResults) {
  const adapterResult = adaptWebCrawlerResults(rawResults);
  return runIngestionPipeline("web_crawler", adapterResult);
}
async function ingestDomainIntelResults(rawResults) {
  const adapterResult = adaptDomainIntelResults(rawResults);
  return runIngestionPipeline("domain_intel", adapterResult);
}
async function ingestVulnScanResults(rawResults) {
  const adapterResult = adaptVulnScanResults(rawResults);
  return runIngestionPipeline("vuln_scanner", adapterResult);
}
async function ingestRawObservations(scannerName, observations) {
  const adapterResult = {
    observations,
    metrics: {
      durationMs: 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: []
    }
  };
  return runIngestionPipeline(scannerName, adapterResult);
}
async function ingestDomainIntelPipelineResults(pipelineResult) {
  const rawResults = [];
  if (pipelineResult.assets && Array.isArray(pipelineResult.assets)) {
    for (const analysis of pipelineResult.assets) {
      const asset = analysis.asset || analysis;
      rawResults.push({
        domain: asset.hostname || pipelineResult.orgProfile?.primaryDomain || "unknown",
        dnsRecords: asset.dnsRecords || {},
        subdomains: asset.subdomains || [],
        whois: asset.whois || {},
        scanRunId: `pipeline-${Date.now().toString(36)}`
      });
    }
  }
  if (rawResults.length > 0) {
    return ingestDomainIntelResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}
async function ingestVulnScanImportFindings(findings) {
  const rawResults = findings.map((f) => ({
    host: f.hostIp || f.hostName || "unknown",
    port: f.port || void 0,
    protocol: f.protocol || void 0,
    title: f.title,
    description: f.description || void 0,
    severity: f.severity || "info",
    cvss: f.cvssScore || void 0,
    cve: f.cveId || void 0,
    confidence: f.corroborationScore ? f.corroborationScore / 100 : void 0,
    tags: f.exploitAvailable ? ["exploit_available"] : void 0,
    remediation: f.solution || void 0,
    scanRunId: `import-${f.importId || "unknown"}`
  }));
  if (rawResults.length > 0) {
    return ingestVulnScanResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}
async function ingestWebCrawlerPageResults(pages) {
  const rawResults = pages.map((page) => ({
    url: page.url || page.targetUrl || "",
    securityHeaders: page.securityHeaders ? {
      grade: page.securityHeaderGrade || void 0,
      present: page.securityHeaders?.present || [],
      missing: page.securityHeaders?.missing || []
    } : void 0,
    exposedPaths: page.exposedPaths || void 0,
    technologies: page.detectedTechnologies || void 0,
    tls: page.tlsInfo || void 0,
    scanRunId: page.jobId || void 0
  }));
  if (rawResults.length > 0) {
    return ingestWebCrawlerResults(rawResults);
  }
  return { observations: 0, signals: 0, riskCards: 0, errors: [] };
}
async function ingestUnifiedPipelineFindings(tool, findings) {
  const toolToScanner = {
    zap_passive: "web_crawler",
    zap_active: "vuln_scanner",
    nuclei_info: "nuclei",
    nuclei_vuln: "nuclei",
    nuclei_critical: "nuclei",
    passive_osint: "domain_intel"
  };
  const scannerName = toolToScanner[tool] || "generic";
  if (scannerName === "nuclei") {
    const rawResults2 = findings.map((f) => ({
      templateId: f.templateId || f.id || "unknown",
      name: f.title || f.name,
      severity: f.severity || "info",
      host: f.host || f.target,
      matchedAt: f.matchedAt || f.url,
      cve: f.cveId,
      cvss: f.cvss,
      tags: f.tags
    }));
    return ingestNucleiResults(rawResults2);
  }
  if (scannerName === "vuln_scanner") {
    const rawResults2 = findings.map((f) => ({
      host: f.host || f.target || "unknown",
      port: f.port,
      title: f.title || f.name || "Unknown",
      severity: f.severity || "info",
      cvss: f.cvss,
      cve: f.cveId,
      confidence: f.confidence ? f.confidence / 100 : void 0
    }));
    return ingestVulnScanResults(rawResults2);
  }
  if (scannerName === "domain_intel") {
    const rawResults2 = findings.map((f) => ({
      domain: f.host || f.target || "unknown",
      dnsRecords: f.evidence?.dns || {},
      subdomains: f.evidence?.subdomains || []
    }));
    return ingestDomainIntelResults(rawResults2);
  }
  const rawResults = findings.map((f) => ({
    host: f.host || f.target || "unknown",
    port: f.port,
    title: f.title || f.name || "Unknown Finding",
    severity: f.severity || "info",
    cvss: f.cvss,
    cve: f.cveId
  }));
  return ingestVulnScanResults(rawResults);
}
async function ingestSubfinderResults(subfinderResult) {
  const observations = [];
  for (const entry of subfinderResult.subdomains || []) {
    observations.push({
      observationId: `subfinder-${entry.subdomain}-${Date.now().toString(36)}`,
      asset: {
        assetId: `host:${entry.subdomain}`,
        host: entry.subdomain,
        port: 0,
        protocol: "dns",
        tags: ["subdomain", `source:${entry.source}`]
      },
      scanner: {
        name: "subfinder",
        version: "2.6.x",
        adapter: "subfinder",
        mode: "passive"
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
            cname: entry.cname
          }
        ]
      },
      metadata: {
        scanRunId: `subfinder-${subfinderResult.domain}-${Date.now().toString(36)}`,
        notes: `Part of ${subfinderResult.domain} enumeration`
      }
    });
  }
  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }
  const adapterResult = {
    observations,
    metrics: {
      durationMs: subfinderResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: []
    }
  };
  return runIngestionPipeline("subfinder", adapterResult);
}
async function ingestHttpxResults(httpxResult) {
  const observations = [];
  for (const entry of httpxResult.targets || []) {
    observations.push({
      observationId: `httpx-http-${entry.host}-${entry.port}-${Date.now().toString(36)}`,
      asset: {
        assetId: `host:${entry.host}:${entry.port}`,
        host: entry.host,
        port: entry.port,
        protocol: entry.scheme === "https" ? "https" : "http",
        tags: [
          ...(entry.technologies || []).map((t) => `tech:${t.toLowerCase()}`),
          ...entry.cdn ? [`cdn:${entry.cdn.toLowerCase()}`] : []
        ]
      },
      scanner: {
        name: "httpx",
        version: "1.6.x",
        adapter: "httpx",
        mode: "active-low"
      },
      observationType: "http_headers",
      severity: entry.statusCode >= 500 ? "medium" : "info",
      confidence: entry.alive ? 0.95 : 0.5,
      timestamp: new Date(entry.timestamp || Date.now()).toISOString(),
      evidence: {
        summary: `HTTP probe: ${entry.url} \u2192 ${entry.statusCode} (${entry.webServer || "unknown"})`,
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
            ip: entry.ip
          }
        ]
      },
      metadata: {
        scanRunId: `httpx-${Date.now().toString(36)}`
      }
    });
    if (entry.scheme === "https" && entry.tlsVersion) {
      observations.push({
        observationId: `httpx-tls-${entry.host}-${entry.port}-${Date.now().toString(36)}`,
        asset: {
          assetId: `host:${entry.host}:${entry.port}`,
          host: entry.host,
          port: entry.port,
          protocol: "tls"
        },
        scanner: {
          name: "httpx",
          version: "1.6.x",
          adapter: "httpx",
          mode: "active-low"
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
              jarmHash: entry.jarmHash
            }
          ]
        },
        metadata: {
          scanRunId: `httpx-${Date.now().toString(36)}`
        }
      });
    }
  }
  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }
  const adapterResult = {
    observations,
    metrics: {
      durationMs: httpxResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: []
    }
  };
  return runIngestionPipeline("httpx", adapterResult);
}
async function ingestNaabuResults(naabuResult) {
  const observations = [];
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
            ...port.service ? [`service:${port.service}`] : [],
            ...port.tls ? ["tls:true"] : []
          ]
        },
        scanner: {
          name: "naabu",
          version: "2.3.x",
          adapter: "naabu",
          mode: "active-low"
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
              hostOs: host.os
            }
          ]
        },
        metadata: {
          scanRunId: `naabu-${Date.now().toString(36)}`
        }
      });
    }
  }
  if (observations.length === 0) {
    return { observations: 0, signals: 0, riskCards: 0, errors: [] };
  }
  const adapterResult = {
    observations,
    metrics: {
      durationMs: naabuResult.stats?.duration || 0,
      requestsMade: observations.length,
      observationsEmitted: observations.length,
      errors: []
    }
  };
  return runIngestionPipeline("naabu", adapterResult);
}
var listeners, recentEvents, MAX_RECENT_EVENTS, stats;
var init_observation_ingestor = __esm({
  "server/lib/observation-ingestor.ts"() {
    init_observation_normalizer();
    listeners = /* @__PURE__ */ new Set();
    recentEvents = [];
    MAX_RECENT_EVENTS = 200;
    stats = {
      totalObservations: 0,
      totalSignals: 0,
      totalRiskCards: 0,
      totalErrors: 0,
      lastIngestionAt: null,
      byScanner: {}
    };
  }
});
init_observation_ingestor();
export {
  getIngestionStats,
  getRecentEvents,
  ingestDomainIntelPipelineResults,
  ingestDomainIntelResults,
  ingestHttpxResults,
  ingestNaabuResults,
  ingestNucleiResults,
  ingestRawObservations,
  ingestScanForgeResults,
  ingestSubfinderResults,
  ingestUnifiedPipelineFindings,
  ingestVulnScanImportFindings,
  ingestVulnScanResults,
  ingestWebCrawlerPageResults,
  ingestWebCrawlerResults,
  ingestZgrab2Results,
  onIngestionEvent
};
