/**
 * Re-export module for domain intel pipeline
 * The actual implementation lives in server/domainIntel.ts
 * This module provides a simplified interface for the rerunFullPipeline endpoint
 */
import type { PassiveReconResult } from '../domainIntel';

export interface DomainIntelResult {
  dns?: { aRecords?: string[] };
  technologies?: string[];
  riskSignals?: Array<{ severity: string; type: string; rationale: string }>;
  services?: Array<{ port: number; protocol: string; service: string; product?: string; version?: string }>;
  subdomains?: string[];
  certificates?: Array<{ subject: string; issuer?: string }>;
  allObservations?: any[];
  summary?: { totalObservations: number; totalSignals: number; connectorStats: any[] };
}

/**
 * Run domain intel pipeline for a single domain.
 * Returns a simplified passive recon result suitable for asset enrichment.
 */
export async function runDomainIntelPipeline(domain: string): Promise<DomainIntelResult> {
  const { runPassiveRecon } = await import('./passive/index');
  const { ENV } = await import('../_core/env');

  const passiveRecon = await runPassiveRecon(domain, {
    scanMode: 'standard',
    apiKeys: {
      shodan: ENV.SHODAN_API_KEY || undefined,
      censys_id: ENV.CENSYS_API_ID || undefined,
      censys_secret: ENV.CENSYS_API_SECRET || undefined,
      urlscan: ENV.URLSCAN_API_KEY || undefined,
      securitytrails: ENV.SECURITYTRAILS_API_KEY || undefined,
      dehashed: ENV.DEHASHED_API_KEY || undefined,
      abuseipdb: ENV.ABUSEIPDB_API_KEY || undefined,
      github: ENV.GITHUB_PAT || undefined,
    },
    timeout: 30000,
    maxConcurrent: 5,
  });

  // Extract technologies from observations
  const technologies: string[] = [];
  const services: DomainIntelResult['services'] = [];
  const subdomains: string[] = [];
  const certificates: DomainIntelResult['certificates'] = [];
  const aRecords: string[] = [];

  for (const obs of passiveRecon.allObservations) {
    // IPs
    if (obs.ip && !aRecords.includes(obs.ip)) aRecords.push(obs.ip);

    // Subdomains
    if (obs.assetType === 'subdomain' && obs.name && !subdomains.includes(obs.name)) {
      subdomains.push(obs.name);
    }

    // Services from Shodan/Censys
    const ev = obs.evidence || {};
    if (ev.port) {
      services.push({
        port: Number(ev.port),
        protocol: ev.transport || 'tcp',
        service: ev.service || ev.product || 'unknown',
        product: ev.product,
        version: ev.version,
      });
    }

    // Technologies
    if (ev.product && !technologies.includes(ev.product)) technologies.push(ev.product);
    if (ev.technologies && Array.isArray(ev.technologies)) {
      for (const t of ev.technologies) {
        if (typeof t === 'string' && !technologies.includes(t)) technologies.push(t);
      }
    }

    // Certificates
    if (obs.assetType === 'certificate' && obs.name) {
      certificates.push({ subject: obs.name, issuer: obs.evidence?.issuer });
    }
  }

  return {
    dns: { aRecords },
    technologies,
    riskSignals: passiveRecon.riskSignals?.map((r: any) => ({
      severity: r.severity || 'info',
      type: r.signalType || r.type || 'unknown',
      rationale: r.rationale || r.description || r.title || '',
    })) || [],
    services,
    subdomains,
    certificates,
    allObservations: passiveRecon.allObservations,
    summary: passiveRecon.summary,
  };
}
