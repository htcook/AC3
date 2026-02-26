/**
 * SSIL Observation Normalizer
 *
 * Transforms raw scanner output from multiple tools (Nmap, Nuclei, ZGrab2,
 * ZAP, Web Crawler, Domain Intel, Protocol Scanner) into the unified
 * scan_observation schema defined by SSIL.
 *
 * Each scanner has a dedicated adapter that maps tool-specific fields into
 * the normalized observation format. Observations are then stored in the
 * scan_observations table for cross-scanner correlation.
 *
 * Implements the adapter contract from docs/ssil/adapters/adapter-contract.yaml
 *
 * Author: Harrison Cook — AceofCloud
 */

import * as crypto from "crypto";
import type { InsertScanObservation, InsertScanSignal, InsertScanRiskCard } from "../../drizzle/schema";
import { getScanPolicyEngine } from "./scan-policy-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ObservationType =
  | "service_banner"
  | "tls"
  | "http_headers"
  | "dns"
  | "vulnerability_finding"
  | "misconfiguration"
  | "exposure_surface"
  | "cloud_fingerprint";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type SignalType = "vulnerability" | "exposure" | "weak_signal" | "intel" | "hygiene" | "misconfiguration";

export interface NormalizedObservation {
  observationId: string;
  asset: {
    assetId: string;
    host: string;
    port: number;
    protocol?: string;
    tags?: string[];
  };
  scanner: {
    name: string;
    version?: string;
    adapter: string;
    mode?: "passive" | "active-low" | "active-standard" | "active-aggressive";
  };
  observationType: ObservationType;
  severity: Severity;
  confidence: number;
  timestamp: string;
  evidence: {
    summary: string;
    templateId?: string;
    cve?: string;
    cvss?: number;
    requestFingerprint?: string;
    responseFingerprint?: string;
    artifacts?: Record<string, unknown>[];
  };
  metadata?: {
    scanRunId?: string;
    policyProfile?: string;
    rateLimitBucket?: string;
    notes?: string;
  };
}

export interface AdapterMetrics {
  durationMs: number;
  requestsMade: number;
  observationsEmitted: number;
  errors: string[];
}

export interface AdapterResult {
  observations: NormalizedObservation[];
  metrics: AdapterMetrics;
}

// ─── Observation ID Generation ──────────────────────────────────────────────

/**
 * Generates a stable observation ID by hashing key fields.
 * This ensures the same finding produces the same ID across runs.
 */
export function generateObservationId(
  scannerName: string,
  host: string,
  port: number,
  observationType: string,
  evidenceKey: string
): string {
  const input = `${scannerName}:${host}:${port}:${observationType}:${evidenceKey}`;
  return `obs-${crypto.createHash("sha256").update(input).digest("hex").substring(0, 24)}`;
}

export function generateSignalId(
  assetId: string,
  category: string,
  signalType: string
): string {
  const input = `${assetId}:${category}:${signalType}:${Date.now()}`;
  return `sig-${crypto.createHash("sha256").update(input).digest("hex").substring(0, 24)}`;
}

export function generateRiskId(assetId: string): string {
  const input = `${assetId}:risk:${Date.now()}`;
  return `risk-${crypto.createHash("sha256").update(input).digest("hex").substring(0, 24)}`;
}

// ─── Evidence Fingerprinting ────────────────────────────────────────────────

export function fingerprintData(data: string | Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex").substring(0, 64);
}

export function redactSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
  const engine = getScanPolicyEngine();
  return engine.redactHeaders(headers);
}

// ─── Scanner Adapters ───────────────────────────────────────────────────────

/**
 * Nmap XML → Normalized Observations
 *
 * Converts Nmap scan results (typically stored in our discovery_results or
 * protocol_findings tables) into SSIL observations.
 */
export function adaptNmapResults(rawResults: NmapRawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      for (const port of result.ports || []) {
        const obs: NormalizedObservation = {
          observationId: generateObservationId("nmap", result.host, port.port, "service_banner", port.service || "unknown"),
          asset: {
            assetId: `nmap-${result.host}`,
            host: result.host,
            port: port.port,
            protocol: port.protocol || "tcp",
            tags: result.tags || [],
          },
          scanner: {
            name: "nmap",
            version: result.nmapVersion || "7.94",
            adapter: "nmap-orchestrated",
            mode: "active-low",
          },
          observationType: "service_banner",
          severity: classifyPortSeverity(port.port, port.service),
          confidence: port.serviceConfidence || 0.8,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `Port ${port.port}/${port.protocol || "tcp"} open — ${port.service || "unknown"} ${port.version || ""}`.trim(),
            responseFingerprint: port.banner ? fingerprintData(port.banner) : undefined,
            artifacts: port.scripts ? port.scripts.map((s: any) => ({ scriptId: s.id, output: s.output?.substring(0, 500) })) : undefined,
          },
          metadata: {
            scanRunId: result.scanRunId,
            policyProfile: result.policyProfile,
          },
        };
        observations.push(obs);
      }
    } catch (err: any) {
      errors.push(`Nmap adapter error for ${result.host}: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/**
 * Nuclei JSON → Normalized Observations
 *
 * Converts Nuclei template match results into SSIL observations.
 * Maps template severity, CVE references, and matched-at URLs.
 */
export function adaptNucleiResults(rawResults: NucleiRawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      const host = extractHost(result.host || result.matchedAt || "");
      const port = extractPort(result.host || result.matchedAt || "", result.port);

      const obs: NormalizedObservation = {
        observationId: generateObservationId("nuclei", host, port, mapNucleiType(result.templateId), result.templateId),
        asset: {
          assetId: `nuclei-${host}`,
          host,
          port,
          protocol: result.protocol || "https",
          tags: result.tags || [],
        },
        scanner: {
          name: "nuclei",
          version: result.nucleiVersion || "3.x",
          adapter: "nuclei-wrapper",
          mode: mapNucleiMode(result.tags),
        },
        observationType: mapNucleiType(result.templateId),
        severity: mapNucleiSeverity(result.severity),
        confidence: mapNucleiConfidence(result.severity, result.matcherStatus),
        timestamp: result.timestamp || new Date().toISOString(),
        evidence: {
          summary: result.name || result.templateId || "Nuclei finding",
          templateId: result.templateId,
          cve: result.cve,
          cvss: result.cvss,
          requestFingerprint: result.curlCommand ? fingerprintData(result.curlCommand) : undefined,
          responseFingerprint: result.response ? fingerprintData(result.response) : undefined,
        },
        metadata: {
          scanRunId: result.scanRunId,
          policyProfile: result.policyProfile,
          notes: result.description,
        },
      };
      observations.push(obs);
    } catch (err: any) {
      errors.push(`Nuclei adapter error: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/**
 * ZGrab2 → Normalized Observations
 *
 * Converts ZGrab2 protocol scan results (TLS, HTTP, SSH, SMTP banners)
 * into SSIL observations.
 */
export function adaptZgrab2Results(rawResults: Zgrab2RawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      // TLS observation
      if (result.tls) {
        observations.push({
          observationId: generateObservationId("zgrab2", result.host, result.port || 443, "tls", result.tls.certSubject || ""),
          asset: {
            assetId: `zgrab2-${result.host}`,
            host: result.host,
            port: result.port || 443,
            protocol: "https",
          },
          scanner: {
            name: "zgrab2",
            version: result.zgrab2Version || "0.1.x",
            adapter: "zgrab2-wrapper",
            mode: "passive",
          },
          observationType: "tls",
          severity: classifyTlsSeverity(result.tls),
          confidence: 0.95,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `TLS: ${result.tls.version || "unknown"}, Subject: ${result.tls.certSubject || "N/A"}, Issuer: ${result.tls.certIssuer || "N/A"}, Expires: ${result.tls.notAfter || "N/A"}`,
            responseFingerprint: result.tls.certFingerprint || fingerprintData(JSON.stringify(result.tls)),
            artifacts: [
              { certSubject: result.tls.certSubject, certIssuer: result.tls.certIssuer, notAfter: result.tls.notAfter, version: result.tls.version, cipherSuites: result.tls.cipherSuites },
            ],
          },
          metadata: { scanRunId: result.scanRunId, policyProfile: result.policyProfile },
        });
      }

      // HTTP headers observation
      if (result.http) {
        observations.push({
          observationId: generateObservationId("zgrab2", result.host, result.port || 80, "http_headers", result.http.server || ""),
          asset: {
            assetId: `zgrab2-${result.host}`,
            host: result.host,
            port: result.port || 80,
            protocol: "http",
          },
          scanner: {
            name: "zgrab2",
            version: result.zgrab2Version || "0.1.x",
            adapter: "zgrab2-wrapper",
            mode: "passive",
          },
          observationType: "http_headers",
          severity: classifyHeaderSeverity(result.http.headers),
          confidence: 0.90,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `HTTP Server: ${result.http.server || "unknown"}, Status: ${result.http.statusCode || "N/A"}`,
            responseFingerprint: fingerprintData(JSON.stringify(result.http.headers || {})),
            artifacts: [{ headers: redactSensitiveHeaders(result.http.headers || {}), statusCode: result.http.statusCode }],
          },
          metadata: { scanRunId: result.scanRunId, policyProfile: result.policyProfile },
        });
      }

      // Banner observation
      if (result.banner) {
        observations.push({
          observationId: generateObservationId("zgrab2", result.host, result.port || 0, "service_banner", result.banner.substring(0, 50)),
          asset: {
            assetId: `zgrab2-${result.host}`,
            host: result.host,
            port: result.port || 0,
            protocol: result.protocol || "tcp",
          },
          scanner: {
            name: "zgrab2",
            version: result.zgrab2Version || "0.1.x",
            adapter: "zgrab2-wrapper",
            mode: "passive",
          },
          observationType: "service_banner",
          severity: "info",
          confidence: 0.85,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `Banner: ${result.banner.substring(0, 200)}`,
            responseFingerprint: fingerprintData(result.banner),
          },
          metadata: { scanRunId: result.scanRunId, policyProfile: result.policyProfile },
        });
      }
    } catch (err: any) {
      errors.push(`ZGrab2 adapter error for ${result.host}: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/**
 * Web Crawler → Normalized Observations
 *
 * Converts web crawler results (security headers, technologies, exposed paths,
 * cookies, TLS info) into SSIL observations.
 */
export function adaptWebCrawlerResults(rawResults: WebCrawlerRawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      const host = extractHost(result.url);
      const port = extractPort(result.url);

      // Security headers observation
      if (result.securityHeaders) {
        observations.push({
          observationId: generateObservationId("web_crawler", host, port, "http_headers", JSON.stringify(result.securityHeaders.grade || "")),
          asset: {
            assetId: `crawler-${host}`,
            host,
            port,
            protocol: "https",
            tags: ["web_asset"],
          },
          scanner: { name: "web_crawler", adapter: "ace-crawler", mode: "passive" },
          observationType: "http_headers",
          severity: mapHeaderGradeSeverity(result.securityHeaders.grade),
          confidence: 0.90,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `Security headers grade: ${result.securityHeaders.grade || "N/A"}. Missing: ${(result.securityHeaders.missing || []).join(", ") || "none"}`,
            responseFingerprint: fingerprintData(JSON.stringify(result.securityHeaders)),
            artifacts: [{ grade: result.securityHeaders.grade, present: result.securityHeaders.present, missing: result.securityHeaders.missing }],
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }

      // Exposed paths observation
      if (result.exposedPaths && result.exposedPaths.length > 0) {
        observations.push({
          observationId: generateObservationId("web_crawler", host, port, "exposure_surface", result.exposedPaths.join(",")),
          asset: {
            assetId: `crawler-${host}`,
            host,
            port,
            protocol: "https",
            tags: ["web_asset", "exposed_paths"],
          },
          scanner: { name: "web_crawler", adapter: "ace-crawler", mode: "passive" },
          observationType: "exposure_surface",
          severity: result.exposedPaths.some((p: string) => p.includes(".env") || p.includes(".git")) ? "high" : "medium",
          confidence: 0.85,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `Exposed paths detected: ${result.exposedPaths.join(", ")}`,
            artifacts: result.exposedPaths.map((p: string) => ({ path: p, status: "accessible" })),
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }

      // Technology fingerprinting observation
      if (result.technologies && result.technologies.length > 0) {
        observations.push({
          observationId: generateObservationId("web_crawler", host, port, "cloud_fingerprint", result.technologies.join(",")),
          asset: {
            assetId: `crawler-${host}`,
            host,
            port,
            protocol: "https",
            tags: ["web_asset"],
          },
          scanner: { name: "web_crawler", adapter: "ace-crawler", mode: "passive" },
          observationType: "cloud_fingerprint",
          severity: "info",
          confidence: 0.80,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `Technologies detected: ${result.technologies.join(", ")}`,
            artifacts: result.technologies.map((t: string) => ({ technology: t })),
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }

      // TLS observation from crawler
      if (result.tls) {
        observations.push({
          observationId: generateObservationId("web_crawler", host, port, "tls", result.tls.subject || ""),
          asset: {
            assetId: `crawler-${host}`,
            host,
            port,
            protocol: "https",
          },
          scanner: { name: "web_crawler", adapter: "ace-crawler", mode: "passive" },
          observationType: "tls",
          severity: result.tls.daysUntilExpiry && result.tls.daysUntilExpiry < 30 ? "medium" : "info",
          confidence: 0.90,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `TLS cert: ${result.tls.subject || "N/A"}, Issuer: ${result.tls.issuer || "N/A"}, Expires in ${result.tls.daysUntilExpiry || "?"} days`,
            artifacts: [{ subject: result.tls.subject, issuer: result.tls.issuer, daysUntilExpiry: result.tls.daysUntilExpiry }],
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }
    } catch (err: any) {
      errors.push(`Web crawler adapter error for ${result.url}: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/**
 * Domain Intel → Normalized Observations
 *
 * Converts domain intelligence scan results (DNS records, WHOIS, subdomains)
 * into SSIL observations.
 */
export function adaptDomainIntelResults(rawResults: DomainIntelRawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      // DNS observation
      if (result.dnsRecords) {
        observations.push({
          observationId: generateObservationId("domain_intel", result.domain, 53, "dns", JSON.stringify(result.dnsRecords).substring(0, 50)),
          asset: {
            assetId: `domain-${result.domain}`,
            host: result.domain,
            port: 53,
            protocol: "dns",
            tags: ["domain_asset"],
          },
          scanner: { name: "domain_intel", adapter: "ace-domain-intel", mode: "passive" },
          observationType: "dns",
          severity: "info",
          confidence: 0.95,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `DNS records for ${result.domain}: ${Object.keys(result.dnsRecords).join(", ")} record types found`,
            artifacts: Object.entries(result.dnsRecords).map(([type, records]) => ({ recordType: type, count: Array.isArray(records) ? records.length : 1 })),
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }

      // Subdomain observations
      if (result.subdomains && result.subdomains.length > 0) {
        observations.push({
          observationId: generateObservationId("domain_intel", result.domain, 0, "exposure_surface", `subdomains-${result.subdomains.length}`),
          asset: {
            assetId: `domain-${result.domain}`,
            host: result.domain,
            port: 0,
            protocol: "dns",
            tags: ["domain_asset", "subdomain_enum"],
          },
          scanner: { name: "domain_intel", adapter: "ace-domain-intel", mode: "passive" },
          observationType: "exposure_surface",
          severity: result.subdomains.length > 20 ? "medium" : "info",
          confidence: 0.85,
          timestamp: new Date().toISOString(),
          evidence: {
            summary: `${result.subdomains.length} subdomains discovered for ${result.domain}`,
            artifacts: result.subdomains.slice(0, 50).map((s: string) => ({ subdomain: s })),
          },
          metadata: { scanRunId: result.scanRunId },
        });
      }
    } catch (err: any) {
      errors.push(`Domain intel adapter error for ${result.domain}: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/**
 * Vulnerability Scanner → Normalized Observations
 *
 * Converts vulnerability scan findings (from vuln_scan_findings table)
 * into SSIL observations.
 */
export function adaptVulnScanResults(rawResults: VulnScanRawResult[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const result of rawResults) {
    try {
      const obs: NormalizedObservation = {
        observationId: generateObservationId("vuln_scanner", result.host, result.port || 0, "vulnerability_finding", result.cve || result.title),
        asset: {
          assetId: `vuln-${result.host}`,
          host: result.host,
          port: result.port || 0,
          protocol: result.protocol || "tcp",
          tags: result.tags || [],
        },
        scanner: {
          name: "vuln_scanner",
          version: result.scannerVersion || "1.0",
          adapter: "ace-vuln-scanner",
          mode: "active-low",
        },
        observationType: "vulnerability_finding",
        severity: mapVulnSeverity(result.severity, result.cvss),
        confidence: result.confidence || 0.75,
        timestamp: result.timestamp || new Date().toISOString(),
        evidence: {
          summary: result.title || result.description?.substring(0, 500) || "Vulnerability finding",
          cve: result.cve,
          cvss: result.cvss,
          requestFingerprint: result.requestHash,
          responseFingerprint: result.responseHash,
          artifacts: result.references ? result.references.map((r: string) => ({ reference: r })) : undefined,
        },
        metadata: {
          scanRunId: result.scanRunId,
          notes: result.remediation,
        },
      };
      observations.push(obs);
    } catch (err: any) {
      errors.push(`Vuln scanner adapter error: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: rawResults.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

// ─── Signal Derivation ──────────────────────────────────────────────────────

/**
 * Derives intelligence signals from a set of observations.
 * Groups observations by asset and category, then produces signals
 * with aggregated confidence and severity.
 */
export function deriveSignals(observations: NormalizedObservation[]): InsertScanSignal[] {
  const signals: InsertScanSignal[] = [];
  const assetGroups = new Map<string, NormalizedObservation[]>();

  // Group by asset
  for (const obs of observations) {
    const key = obs.asset.assetId;
    if (!assetGroups.has(key)) assetGroups.set(key, []);
    assetGroups.get(key)!.push(obs);
  }

  for (const [assetId, assetObs] of Array.from(assetGroups.entries())) {
    // TLS hygiene signal
    const tlsObs = assetObs.filter((o) => o.observationType === "tls");
    if (tlsObs.length > 0) {
      const worstSeverity = getWorstSeverity(tlsObs.map((o) => o.severity));
      signals.push({
        signalId: generateSignalId(assetId, "tls_hygiene", "hygiene"),
        assetId,
        signalType: "hygiene",
        category: "tls_hygiene",
        severity: worstSeverity,
        confidence: averageConfidence(tlsObs),
        rationale: `${tlsObs.length} TLS observation(s) analyzed. ${tlsObs.map((o) => o.evidence.summary).join("; ")}`,
        sourceObservations: tlsObs.map((o) => o.observationId),
        enrichmentCvss: null,
        enrichmentCve: null,
        enrichmentReferences: null,
        createdAt: Date.now(),
      });
    }

    // Auth surface signal
    const headerObs = assetObs.filter((o) => o.observationType === "http_headers");
    const exposureObs = assetObs.filter((o) => o.observationType === "exposure_surface");
    if (headerObs.length > 0 || exposureObs.length > 0) {
      const allObs = [...headerObs, ...exposureObs];
      const worstSeverity = getWorstSeverity(allObs.map((o) => o.severity));
      signals.push({
        signalId: generateSignalId(assetId, "auth_surface", "exposure"),
        assetId,
        signalType: "exposure",
        category: "auth_surface",
        severity: worstSeverity,
        confidence: averageConfidence(allObs),
        rationale: `${allObs.length} exposure/header observation(s). ${allObs.map((o) => o.evidence.summary).join("; ")}`,
        sourceObservations: allObs.map((o) => o.observationId),
        enrichmentCvss: null,
        enrichmentCve: null,
        enrichmentReferences: null,
        createdAt: Date.now(),
      });
    }

    // Vulnerability signal
    const vulnObs = assetObs.filter((o) => o.observationType === "vulnerability_finding");
    if (vulnObs.length > 0) {
      const maxCvss = Math.max(...vulnObs.map((o) => o.evidence.cvss || 0));
      const cves = vulnObs.map((o) => o.evidence.cve).filter(Boolean) as string[];
      signals.push({
        signalId: generateSignalId(assetId, "cve", "vulnerability"),
        assetId,
        signalType: "vulnerability",
        category: "cve",
        severity: getWorstSeverity(vulnObs.map((o) => o.severity)),
        confidence: averageConfidence(vulnObs),
        rationale: `${vulnObs.length} vulnerability finding(s). CVEs: ${cves.join(", ") || "none"}. Max CVSS: ${maxCvss}`,
        sourceObservations: vulnObs.map((o) => o.observationId),
        enrichmentCvss: maxCvss > 0 ? maxCvss : null,
        enrichmentCve: cves[0] || null,
        enrichmentReferences: cves.length > 0 ? cves : null,
        createdAt: Date.now(),
      });
    }

    // DNS takeover signal
    const dnsObs = assetObs.filter((o) => o.observationType === "dns");
    if (dnsObs.length > 0) {
      signals.push({
        signalId: generateSignalId(assetId, "dns_takeover", "weak_signal"),
        assetId,
        signalType: "weak_signal",
        category: "dns_takeover",
        severity: "low",
        confidence: averageConfidence(dnsObs) * 0.6, // Lower confidence for DNS takeover signals
        rationale: `${dnsObs.length} DNS observation(s) analyzed for potential takeover indicators.`,
        sourceObservations: dnsObs.map((o) => o.observationId),
        enrichmentCvss: null,
        enrichmentCve: null,
        enrichmentReferences: null,
        createdAt: Date.now(),
      });
    }

    // Misconfiguration signal
    const misconfigObs = assetObs.filter((o) => o.observationType === "misconfiguration");
    if (misconfigObs.length > 0) {
      signals.push({
        signalId: generateSignalId(assetId, "misconfiguration", "misconfiguration"),
        assetId,
        signalType: "misconfiguration",
        category: "misconfiguration",
        severity: getWorstSeverity(misconfigObs.map((o) => o.severity)),
        confidence: averageConfidence(misconfigObs),
        rationale: `${misconfigObs.length} misconfiguration(s) detected. ${misconfigObs.map((o) => o.evidence.summary).join("; ")}`,
        sourceObservations: misconfigObs.map((o) => o.observationId),
        enrichmentCvss: null,
        enrichmentCve: null,
        enrichmentReferences: null,
        createdAt: Date.now(),
      });
    }
  }

  return signals;
}

// ─── Risk Card Generation ───────────────────────────────────────────────────

/**
 * Generates SSIL risk cards from signals using the hybrid scoring formula:
 * final_score = (cvss * 0.40 + carver * 0.40 + bia * 0.20) * confidence
 */
export function generateRiskCards(
  signals: InsertScanSignal[],
  carverOverrides?: Record<string, number>,
  biaOverrides?: Record<string, number>
): InsertScanRiskCard[] {
  const cards: InsertScanRiskCard[] = [];
  const assetSignals = new Map<string, InsertScanSignal[]>();

  for (const signal of signals) {
    if (!assetSignals.has(signal.assetId)) assetSignals.set(signal.assetId, []);
    assetSignals.get(signal.assetId)!.push(signal);
  }

  const CARVER_DEFAULTS: Record<string, number> = {
    auth_surface: 7.0,
    tls_hygiene: 3.8,
    dns_takeover: 6.5,
    cve: 7.5,
    misconfiguration: 5.0,
  };

  const BIA_DEFAULT = 5.0;
  const WEIGHTS = { cvss: 0.40, carver: 0.40, bia: 0.20 };
  const CONFIDENCE_FLOOR = 0.30;

  for (const [assetId, assetSigs] of Array.from(assetSignals.entries())) {
    // Aggregate scores
    const maxCvss = Math.max(...assetSigs.map((s) => s.enrichmentCvss || 0), 0);
    const categories = assetSigs.map((s) => s.category);
    const avgCarver = categories.reduce((sum, cat) => sum + (carverOverrides?.[cat] || CARVER_DEFAULTS[cat] || 5.0), 0) / categories.length;
    const bia = biaOverrides?.[assetId] || BIA_DEFAULT;
    const avgConfidence = Math.max(
      CONFIDENCE_FLOOR,
      assetSigs.reduce((sum, s) => sum + s.confidence, 0) / assetSigs.length
    );

    const rawScore = maxCvss * WEIGHTS.cvss + avgCarver * WEIGHTS.carver + bia * WEIGHTS.bia;
    const finalScore = Math.min(10, Math.max(0, rawScore * avgConfidence));

    const worstSeverity = getWorstSeverity(assetSigs.map((s) => s.severity as Severity));
    const recommendations = generateRecommendations(assetSigs);

    cards.push({
      riskId: generateRiskId(assetId),
      assetId,
      finalScore: Math.round(finalScore * 100) / 100,
      componentCvss: Math.round(maxCvss * 100) / 100,
      componentCarver: Math.round(avgCarver * 100) / 100,
      componentBia: Math.round(bia * 100) / 100,
      confidenceWeight: Math.round(avgConfidence * 100) / 100,
      summary: `Asset ${assetId} has ${assetSigs.length} signal(s) with worst severity ${worstSeverity}. Hybrid risk score: ${finalScore.toFixed(2)}/10.`,
      whyItMatters: `This score combines CVSS (${maxCvss.toFixed(1)}), CARVER+SHOCK (${avgCarver.toFixed(1)}), and BIA (${bia.toFixed(1)}) weighted by confidence (${avgConfidence.toFixed(2)}).`,
      evidence: assetSigs.flatMap((s) => s.sourceObservations as string[]),
      recommendations,
      createdAt: Date.now(),
    });
  }

  return cards;
}

// ─── Conversion to DB Insert Format ─────────────────────────────────────────

export function observationToInsert(obs: NormalizedObservation): InsertScanObservation {
  return {
    observationId: obs.observationId,
    assetId: obs.asset.assetId,
    assetHost: obs.asset.host,
    assetPort: obs.asset.port,
    assetProtocol: obs.asset.protocol || null,
    assetTags: obs.asset.tags || null,
    scannerName: obs.scanner.name,
    scannerVersion: obs.scanner.version || null,
    scannerAdapter: obs.scanner.adapter,
    scannerMode: obs.scanner.mode || "passive",
    observationType: obs.observationType,
    severity: obs.severity,
    confidence: obs.confidence,
    evidenceSummary: obs.evidence.summary,
    evidenceTemplateId: obs.evidence.templateId || null,
    evidenceCve: obs.evidence.cve || null,
    evidenceCvss: obs.evidence.cvss || null,
    evidenceRequestFingerprint: obs.evidence.requestFingerprint || null,
    evidenceResponseFingerprint: obs.evidence.responseFingerprint || null,
    evidenceArtifacts: obs.evidence.artifacts || null,
    scanRunId: obs.metadata?.scanRunId || null,
    policyProfile: obs.metadata?.policyProfile || null,
    rateLimitBucket: obs.metadata?.rateLimitBucket || null,
    notes: obs.metadata?.notes || null,
    rawDataHash: null,
    observedAt: new Date(obs.timestamp).getTime(),
    ingestedAt: Date.now(),
  };
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function classifyPortSeverity(port: number, service?: string): Severity {
  const highRiskPorts = [21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017];
  const mediumRiskPorts = [22, 25, 110, 143, 389, 636, 8080, 8443, 9200];
  if (highRiskPorts.includes(port)) return "high";
  if (mediumRiskPorts.includes(port)) return "medium";
  if (service && ["telnet", "ftp", "rsh", "rlogin"].includes(service.toLowerCase())) return "high";
  return "info";
}

function classifyTlsSeverity(tls: any): Severity {
  if (!tls) return "info";
  if (tls.version && ["SSLv2", "SSLv3", "TLSv1.0"].includes(tls.version)) return "high";
  if (tls.version === "TLSv1.1") return "medium";
  if (tls.notAfter) {
    const expiry = new Date(tls.notAfter);
    const daysLeft = (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
    if (daysLeft < 0) return "critical";
    if (daysLeft < 30) return "high";
    if (daysLeft < 90) return "medium";
  }
  return "info";
}

function classifyHeaderSeverity(headers?: Record<string, string>): Severity {
  if (!headers) return "medium";
  const securityHeaders = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"];
  const missing = securityHeaders.filter((h) => !Object.keys(headers).some((k) => k.toLowerCase() === h));
  if (missing.length >= 3) return "high";
  if (missing.length >= 2) return "medium";
  if (missing.length >= 1) return "low";
  return "info";
}

function mapHeaderGradeSeverity(grade?: string): Severity {
  if (!grade) return "medium";
  if (grade === "A+" || grade === "A") return "info";
  if (grade === "B") return "low";
  if (grade === "C" || grade === "D") return "medium";
  return "high";
}

function mapNucleiType(templateId?: string): ObservationType {
  if (!templateId) return "vulnerability_finding";
  if (templateId.includes("misconfig")) return "misconfiguration";
  if (templateId.includes("tls") || templateId.includes("ssl")) return "tls";
  if (templateId.includes("header")) return "http_headers";
  if (templateId.includes("dns")) return "dns";
  if (templateId.includes("exposure") || templateId.includes("panel")) return "exposure_surface";
  if (templateId.includes("cloud")) return "cloud_fingerprint";
  return "vulnerability_finding";
}

function mapNucleiSeverity(severity?: string): Severity {
  const map: Record<string, Severity> = { info: "info", low: "low", medium: "medium", high: "high", critical: "critical" };
  return map[severity?.toLowerCase() || "info"] || "info";
}

function mapNucleiConfidence(severity?: string, matcherStatus?: boolean): number {
  const base = matcherStatus !== false ? 0.85 : 0.60;
  const severityBoost: Record<string, number> = { critical: 0.10, high: 0.05, medium: 0, low: -0.05, info: -0.10 };
  return Math.min(1, Math.max(0, base + (severityBoost[severity?.toLowerCase() || "info"] || 0)));
}

function mapNucleiMode(tags?: string[]): "passive" | "active-low" | "active-standard" | "active-aggressive" {
  if (!tags) return "passive";
  const activeTags = ["rce", "sqli", "ssrf", "cmdi", "deserialization", "bruteforce"];
  if (tags.some((t) => activeTags.includes(t))) return "active-aggressive";
  if (tags.some((t) => ["misconfig", "headers", "tls", "exposures"].includes(t))) return "passive";
  return "active-low";
}

function mapVulnSeverity(severity?: string, cvss?: number): Severity {
  if (cvss !== undefined) {
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    if (cvss >= 0.1) return "low";
    return "info";
  }
  return mapNucleiSeverity(severity);
}

function extractHost(url: string): string {
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`);
    return u.hostname;
  } catch {
    return url.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  }
}

function extractPort(url: string, fallback?: number): number {
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`);
    if (u.port) return parseInt(u.port, 10);
    return u.protocol === "https:" ? 443 : 80;
  } catch {
    return fallback || 443;
  }
}

function getWorstSeverity(severities: Severity[]): Severity {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  let worst = 0;
  for (const s of severities) {
    const idx = order.indexOf(s);
    if (idx > worst) worst = idx;
  }
  return order[worst];
}

function averageConfidence(obs: NormalizedObservation[]): number {
  if (obs.length === 0) return 0;
  return obs.reduce((sum, o) => sum + o.confidence, 0) / obs.length;
}

function generateRecommendations(signals: InsertScanSignal[]): string[] {
  const recs: string[] = [];
  for (const signal of signals) {
    switch (signal.category) {
      case "tls_hygiene":
        recs.push("Review and update TLS configuration to enforce TLS 1.2+ with strong cipher suites");
        recs.push("Ensure certificates are valid and not approaching expiry");
        break;
      case "auth_surface":
        recs.push("Review exposed authentication surfaces and ensure MFA is enforced");
        recs.push("Audit security headers (HSTS, CSP, X-Frame-Options) on all web endpoints");
        break;
      case "cve":
        recs.push("Prioritize patching for identified CVEs based on CVSS score and exploitability");
        recs.push("Implement compensating controls (WAF rules, network segmentation) for unpatched vulnerabilities");
        break;
      case "dns_takeover":
        recs.push("Audit DNS records for dangling CNAMEs pointing to decommissioned services");
        recs.push("Implement DNS monitoring for unauthorized record changes");
        break;
      case "misconfiguration":
        recs.push("Review and harden service configurations against CIS benchmarks");
        recs.push("Implement configuration drift detection and automated remediation");
        break;
    }
  }
  return Array.from(new Set(recs)); // Deduplicate
}

// ─── Raw Result Types ───────────────────────────────────────────────────────

export interface NmapRawResult {
  host: string;
  ports: Array<{
    port: number;
    protocol?: string;
    state?: string;
    service?: string;
    version?: string;
    banner?: string;
    serviceConfidence?: number;
    scripts?: Array<{ id: string; output: string }>;
  }>;
  tags?: string[];
  nmapVersion?: string;
  scanRunId?: string;
  policyProfile?: string;
}

export interface NucleiRawResult {
  templateId: string;
  name?: string;
  description?: string;
  severity?: string;
  host?: string;
  matchedAt?: string;
  port?: number;
  protocol?: string;
  tags?: string[];
  cve?: string;
  cvss?: number;
  curlCommand?: string;
  response?: string;
  matcherStatus?: boolean;
  timestamp?: string;
  nucleiVersion?: string;
  scanRunId?: string;
  policyProfile?: string;
}

export interface Zgrab2RawResult {
  host: string;
  port?: number;
  protocol?: string;
  tls?: {
    version?: string;
    certSubject?: string;
    certIssuer?: string;
    notAfter?: string;
    certFingerprint?: string;
    cipherSuites?: string[];
  };
  http?: {
    server?: string;
    statusCode?: number;
    headers?: Record<string, string>;
  };
  banner?: string;
  zgrab2Version?: string;
  scanRunId?: string;
  policyProfile?: string;
}

export interface WebCrawlerRawResult {
  url: string;
  securityHeaders?: {
    grade?: string;
    present?: string[];
    missing?: string[];
  };
  exposedPaths?: string[];
  technologies?: string[];
  tls?: {
    subject?: string;
    issuer?: string;
    daysUntilExpiry?: number;
  };
  scanRunId?: string;
}

export interface DomainIntelRawResult {
  domain: string;
  dnsRecords?: Record<string, unknown>;
  subdomains?: string[];
  whois?: Record<string, unknown>;
  scanRunId?: string;
}

export interface VulnScanRawResult {
  host: string;
  port?: number;
  protocol?: string;
  title: string;
  description?: string;
  severity?: string;
  cvss?: number;
  cve?: string;
  confidence?: number;
  tags?: string[];
  references?: string[];
  requestHash?: string;
  responseHash?: string;
  remediation?: string;
  scannerVersion?: string;
  timestamp?: string;
  scanRunId?: string;
}
