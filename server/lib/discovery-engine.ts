/**
 * Discovery Engine — Unified Reconnaissance Orchestrator
 *
 * Integrates external scanning tools and intelligence feeds for comprehensive
 * discovery, enumeration, and fingerprinting with LLM-powered analysis.
 *
 * Tool integrations (based on Grok research analysis):
 * - Shodan: Passive host discovery, open ports, service banners, CVE detection
 * - Censys: TLS certificate analysis, host enumeration, service identification
 * - SecurityTrails: DNS history, subdomain enumeration, WHOIS intelligence
 * - Nuclei: Template-based vulnerability scanning (via API/CLI bridge)
 * - LLM Analysis: Natural language scan orchestration, result interpretation
 *
 * Cross-module enrichment (two-way):
 * - Domain Intel → Discovery Engine: target domains, org profiles
 * - Discovery Engine → Domain Intel: enriched assets, verified findings
 * - Bug Bounty Intel → Discovery Engine: known vuln patterns, program scope
 * - Discovery Engine → Bug Bounty Intel: new attack surface for bounty matching
 * - Threat Enrichment → Discovery Engine: IOCs, threat actor TTPs
 * - Discovery Engine → Threat Enrichment: exposed services matching threat patterns
 * - OpSec → Discovery Engine: defensive posture gaps
 * - Discovery Engine → OpSec: infrastructure exposure findings
 */

import { ENV } from "../_core/env";
import { discoverOrgDomains, type OrgDiscoveryResult } from "./org-domain-discovery";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DiscoveryTarget {
  domain?: string;
  ip?: string;
  cidr?: string;
  asn?: string;
}

export interface DiscoveryConfig {
  targets: DiscoveryTarget[];
  scanDepth: "quick" | "standard" | "deep";
  enabledSources: DiscoverySources;
  scanMode: "passive" | "active" | "hybrid";
  enrichmentModules: EnrichmentModule[];
  maxConcurrency: number;
  timeoutMs: number;
}

export interface DiscoverySources {
  shodan: boolean;
  censys: boolean;
  securityTrails: boolean;
  nuclei: boolean;
  crtsh: boolean;
  wayback: boolean;
  dnsEnum: boolean;
  whois: boolean;
}

export type EnrichmentModule =
  | "domain_intel"
  | "bug_bounty"
  | "threat_enrichment"
  | "opsec"
  | "attack_vectors"
  | "evasion_engine";

export interface DiscoveredHost {
  ip: string;
  hostnames: string[];
  ports: PortInfo[];
  os: string | null;
  location: GeoLocation | null;
  organization: string | null;
  asn: number | null;
  isp: string | null;
  lastSeen: string;
  source: string;
  tags: string[];
  vulns: string[];
  confidence: number;
}

export interface PortInfo {
  port: number;
  protocol: "tcp" | "udp";
  service: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
  cpe: string[];
  vulns: string[];
  transport: string | null;
  timestamp: string | null;
}

export interface GeoLocation {
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
}

export interface DNSRecord {
  type: string;
  value: string;
  ttl: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface SubdomainResult {
  subdomain: string;
  source: string;
  ips: string[];
  firstSeen: string | null;
  isActive: boolean;
}

export interface TLSCertificate {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  sans: string[];
  isExpired: boolean;
  isWildcard: boolean;
}

export interface NucleiFinding {
  templateId: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  type: string;
  host: string;
  matchedAt: string;
  description: string;
  reference: string[];
  tags: string[];
  cveId: string | null;
  cweId: string | null;
  cvssScore: number | null;
  remediation: string | null;
}

export interface DiscoveryResult {
  id: string;
  startedAt: string;
  completedAt: string | null;
  status: "running" | "completed" | "failed" | "partial";
  targets: DiscoveryTarget[];
  config: DiscoveryConfig;
  hosts: DiscoveredHost[];
  subdomains: SubdomainResult[];
  dnsRecords: DNSRecord[];
  certificates: TLSCertificate[];
  nucleiFindings: NucleiFinding[];
  sourceStats: SourceStats[];
  summary: DiscoverySummary;
  enrichmentResults: EnrichmentResult[];
  llmAnalysis: LLMAnalysis | null;
  orgDiscovery: OrgDiscoveryResult | null;
}

export interface SourceStats {
  source: string;
  hostsFound: number;
  portsFound: number;
  subdomainsFound: number;
  vulnsFound: number;
  responseTimeMs: number;
  status: "success" | "failed" | "skipped" | "partial";
  error: string | null;
}

export interface DiscoverySummary {
  totalHosts: number;
  totalPorts: number;
  totalSubdomains: number;
  totalVulnerabilities: number;
  totalCertificates: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  uniqueServices: string[];
  uniqueProducts: string[];
  exposedPorts: number[];
  riskScore: number;
  riskBand: "critical" | "high" | "medium" | "low" | "minimal";
}

export interface EnrichmentResult {
  module: EnrichmentModule;
  status: "success" | "failed" | "skipped";
  findingsCount: number;
  data: Record<string, any>;
  correlations: Correlation[];
}

export interface Correlation {
  sourceModule: string;
  targetModule: string;
  correlationType: "confirms" | "extends" | "contradicts" | "new_finding";
  description: string;
  confidence: number;
  relatedEntities: string[];
}

export interface LLMAnalysis {
  executiveSummary: string;
  keyFindings: string[];
  riskAssessment: string;
  attackSurfaceAnalysis: string;
  recommendations: string[];
  threatActorRelevance: string[];
  nextSteps: string[];
}

// ─── API Clients ─────────────────────────────────────────────────────────────

// Shodan API Client
async function shodanFetch(path: string, params: Record<string, string> = {}): Promise<any> {
  const apiKey = ENV.SHODAN_API_KEY;
  if (!apiKey) throw new Error("Shodan API key not configured");
  const qs = new URLSearchParams({ ...params, key: apiKey }).toString();
  const res = await fetch(`https://api.shodan.io${path}?${qs}`, {
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Shodan ${res.status}: ${text}`);
  }
  return res.json();
}

export async function shodanHostLookup(ip: string): Promise<DiscoveredHost | null> {
  try {
    const data = await shodanFetch(`/shodan/host/${ip}`);
    return {
      ip: data.ip_str || ip,
      hostnames: data.hostnames || [],
      ports: (data.data || []).map((svc: any) => ({
        port: svc.port,
        protocol: svc.transport || "tcp",
        service: svc._shodan?.module || null,
        product: svc.product || null,
        version: svc.version || null,
        banner: (svc.data || "").substring(0, 500),
        cpe: svc.cpe || [],
        vulns: Object.keys(svc.vulns || {}),
        transport: svc.transport || null,
        timestamp: svc.timestamp || null,
      })),
      os: data.os || null,
      location: {
        country: data.country_name || null,
        city: data.city || null,
        latitude: data.latitude || null,
        longitude: data.longitude || null,
      },
      organization: data.org || null,
      asn: data.asn ? parseInt(String(data.asn).replace("AS", "")) : null,
      isp: data.isp || null,
      lastSeen: data.last_update || new Date().toISOString(),
      source: "shodan",
      tags: data.tags || [],
      vulns: data.vulns || [],
      confidence: 90,
    };
  } catch (err: any) {
    console.error(`[DiscoveryEngine] Shodan host lookup failed for ${ip}:`, err.message);
    return null;
  }
}

export async function shodanDomainSearch(domain: string): Promise<DiscoveredHost[]> {
  try {
    const data = await shodanFetch("/shodan/host/search", { query: `hostname:${domain}` });
    return (data.matches || []).map((match: any) => ({
      ip: match.ip_str,
      hostnames: match.hostnames || [],
      ports: [{
        port: match.port,
        protocol: match.transport || "tcp",
        service: match._shodan?.module || null,
        product: match.product || null,
        version: match.version || null,
        banner: (match.data || "").substring(0, 500),
        cpe: match.cpe || [],
        vulns: Object.keys(match.vulns || {}),
        transport: match.transport || null,
        timestamp: match.timestamp || null,
      }],
      os: match.os || null,
      location: {
        country: match.location?.country_name || null,
        city: match.location?.city || null,
        latitude: match.location?.latitude || null,
        longitude: match.location?.longitude || null,
      },
      organization: match.org || null,
      asn: match.asn ? parseInt(String(match.asn).replace("AS", "")) : null,
      isp: match.isp || null,
      lastSeen: match.timestamp || new Date().toISOString(),
      source: "shodan",
      tags: [],
      vulns: Object.keys(match.vulns || {}),
      confidence: 85,
    }));
  } catch (err: any) {
    console.error(`[DiscoveryEngine] Shodan domain search failed for ${domain}:`, err.message);
    return [];
  }
}

export async function shodanDNSLookup(domain: string): Promise<SubdomainResult[]> {
  try {
    const data = await shodanFetch(`/dns/domain/${domain}`);
    const subdomains: SubdomainResult[] = [];
    for (const record of data.data || []) {
      if (record.type === "A" || record.type === "AAAA") {
        const fqdn = record.subdomain ? `${record.subdomain}.${domain}` : domain;
        const existing = subdomains.find(s => s.subdomain === fqdn);
        if (existing) {
          if (!existing.ips.includes(record.value)) existing.ips.push(record.value);
        } else {
          subdomains.push({
            subdomain: fqdn,
            source: "shodan_dns",
            ips: [record.value],
            firstSeen: null,
            isActive: true,
          });
        }
      }
    }
    return subdomains;
  } catch (err: any) {
    console.error(`[DiscoveryEngine] Shodan DNS lookup failed for ${domain}:`, err.message);
    return [];
  }
}

// Censys API Client
async function censysFetch(path: string, body?: any): Promise<any> {
  const apiId = ENV.CENSYS_API_ID;
  const apiSecret = ENV.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) throw new Error("Censys API credentials not configured");
  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
  const res = await fetch(`https://search.censys.io/api/v2${path}`, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Censys ${res.status}: ${text}`);
  }
  return res.json();
}

export async function censysHostSearch(query: string): Promise<DiscoveredHost[]> {
  try {
    const data = await censysFetch("/hosts/search", { q: query, per_page: 50 });
    return (data.result?.hits || []).map((hit: any) => ({
      ip: hit.ip,
      hostnames: hit.dns?.names || [],
      ports: (hit.services || []).map((svc: any) => ({
        port: svc.port,
        protocol: svc.transport_protocol || "tcp",
        service: svc.service_name || null,
        product: svc.software?.[0]?.product || null,
        version: svc.software?.[0]?.version || null,
        banner: svc.banner || null,
        cpe: svc.software?.map((s: any) => s.uniform_resource_identifier).filter(Boolean) || [],
        vulns: [],
        transport: svc.transport_protocol || null,
        timestamp: svc.observed_at || null,
      })),
      os: hit.operating_system?.product || null,
      location: {
        country: hit.location?.country || null,
        city: hit.location?.city || null,
        latitude: hit.location?.coordinates?.latitude || null,
        longitude: hit.location?.coordinates?.longitude || null,
      },
      organization: hit.autonomous_system?.name || null,
      asn: hit.autonomous_system?.asn || null,
      isp: null,
      lastSeen: hit.last_updated_at || new Date().toISOString(),
      source: "censys",
      tags: hit.labels || [],
      vulns: [],
      confidence: 85,
    }));
  } catch (err: any) {
    console.error(`[DiscoveryEngine] Censys host search failed:`, err.message);
    return [];
  }
}

export async function censysCertSearch(domain: string): Promise<TLSCertificate[]> {
  try {
    const data = await censysFetch("/certificates/search", { q: `names: ${domain}`, per_page: 50 });
    return (data.result?.hits || []).map((cert: any) => {
      const parsed = cert.parsed || {};
      const notAfter = parsed.validity_period?.not_after || "";
      return {
        subject: parsed.subject_dn || "",
        issuer: parsed.issuer_dn || "",
        validFrom: parsed.validity_period?.not_before || "",
        validTo: notAfter,
        serialNumber: parsed.serial_number || "",
        fingerprint: cert.fingerprint_sha256 || "",
        sans: parsed.names || [],
        isExpired: notAfter ? new Date(notAfter) < new Date() : false,
        isWildcard: (parsed.names || []).some((n: string) => n.startsWith("*.")),
      };
    });
  } catch (err: any) {
    console.error(`[DiscoveryEngine] Censys cert search failed for ${domain}:`, err.message);
    return [];
  }
}

// SecurityTrails API Client
async function securityTrailsFetch(path: string): Promise<any> {
  const apiKey = ENV.SECURITYTRAILS_API_KEY;
  if (!apiKey) throw new Error("SecurityTrails API key not configured");
  const res = await fetch(`https://api.securitytrails.com/v1${path}`, {
    headers: {
      APIKEY: apiKey,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`SecurityTrails ${res.status}: ${text}`);
  }
  return res.json();
}

export async function securityTrailsSubdomains(domain: string): Promise<SubdomainResult[]> {
  try {
    const data = await securityTrailsFetch(`/domain/${domain}/subdomains`);
    return (data.subdomains || []).map((sub: string) => ({
      subdomain: `${sub}.${domain}`,
      source: "securitytrails",
      ips: [],
      firstSeen: null,
      isActive: true,
    }));
  } catch (err: any) {
    console.error(`[DiscoveryEngine] SecurityTrails subdomain enum failed for ${domain}:`, err.message);
    return [];
  }
}

export async function securityTrailsDNSHistory(domain: string): Promise<DNSRecord[]> {
  try {
    const data = await securityTrailsFetch(`/history/${domain}/dns/a`);
    const records: DNSRecord[] = [];
    for (const record of data.records || []) {
      for (const value of record.values || []) {
        records.push({
          type: "A",
          value: value.ip || value.value || "",
          ttl: null,
          firstSeen: record.first_seen || null,
          lastSeen: record.last_seen || null,
        });
      }
    }
    return records;
  } catch (err: any) {
    console.error(`[DiscoveryEngine] SecurityTrails DNS history failed for ${domain}:`, err.message);
    return [];
  }
}

export async function securityTrailsDomainInfo(domain: string): Promise<Record<string, any>> {
  try {
    return await securityTrailsFetch(`/domain/${domain}`);
  } catch (err: any) {
    console.error(`[DiscoveryEngine] SecurityTrails domain info failed for ${domain}:`, err.message);
    return {};
  }
}

export async function securityTrailsWHOIS(domain: string): Promise<Record<string, any>> {
  try {
    return await securityTrailsFetch(`/domain/${domain}/whois`);
  } catch (err: any) {
    console.error(`[DiscoveryEngine] SecurityTrails WHOIS failed for ${domain}:`, err.message);
    return {};
  }
}

// ─── Discovery Pipeline ──────────────────────────────────────────────────────

function generateDiscoveryId(): string {
  return `disc_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

function defaultConfig(targets: DiscoveryTarget[]): DiscoveryConfig {
  return {
    targets,
    scanDepth: "standard",
    enabledSources: {
      shodan: !!ENV.SHODAN_API_KEY,
      censys: !!(ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET),
      securityTrails: !!ENV.SECURITYTRAILS_API_KEY,
      nuclei: false, // Requires CLI bridge
      crtsh: true,
      wayback: true,
      dnsEnum: true,
      whois: true,
    },
    scanMode: "passive",
    enrichmentModules: ["domain_intel", "bug_bounty", "threat_enrichment", "opsec"],
    maxConcurrency: 3,
    timeoutMs: 120000,
  };
}

// crt.sh integration (free, no API key)
async function crtshSubdomains(domain: string): Promise<SubdomainResult[]> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(15000) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    const seen = new Set<string>();
    const results: SubdomainResult[] = [];
    for (const entry of data) {
      const names = (entry.name_value || "").split("\n").map((n: string) => n.trim().toLowerCase());
      for (const name of names) {
        if (name && name.endsWith(`.${domain}`) && !seen.has(name) && !name.startsWith("*.")) {
          seen.add(name);
          results.push({
            subdomain: name,
            source: "crtsh",
            ips: [],
            firstSeen: entry.not_before || null,
            isActive: true,
          });
        }
      }
    }
    return results;
  } catch (err: any) {
    console.error(`[DiscoveryEngine] crt.sh lookup failed for ${domain}:`, err.message);
    return [];
  }
}

// Merge hosts from multiple sources, deduplicating by IP
function mergeHosts(allHosts: DiscoveredHost[]): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();
  for (const host of allHosts) {
    const existing = hostMap.get(host.ip);
    if (!existing) {
      hostMap.set(host.ip, { ...host });
      continue;
    }
    // Merge hostnames
    for (const h of host.hostnames) {
      if (!existing.hostnames.includes(h)) existing.hostnames.push(h);
    }
    // Merge ports
    for (const port of host.ports) {
      const existingPort = existing.ports.find(p => p.port === port.port && p.protocol === port.protocol);
      if (!existingPort) {
        existing.ports.push(port);
      } else if (port.version && !existingPort.version) {
        existingPort.version = port.version;
        existingPort.product = port.product || existingPort.product;
        existingPort.banner = port.banner || existingPort.banner;
      }
    }
    // Merge vulns
    for (const v of host.vulns) {
      if (!existing.vulns.includes(v)) existing.vulns.push(v);
    }
    // Merge tags
    for (const t of host.tags) {
      if (!existing.tags.includes(t)) existing.tags.push(t);
    }
    // Update source
    if (!existing.source.includes(host.source)) {
      existing.source += `,${host.source}`;
    }
    // Higher confidence wins
    existing.confidence = Math.max(existing.confidence, host.confidence);
  }
  return Array.from(hostMap.values());
}

// Merge subdomains from multiple sources
function mergeSubdomains(allSubs: SubdomainResult[]): SubdomainResult[] {
  const subMap = new Map<string, SubdomainResult>();
  for (const sub of allSubs) {
    const existing = subMap.get(sub.subdomain);
    if (!existing) {
      subMap.set(sub.subdomain, { ...sub });
      continue;
    }
    for (const ip of sub.ips) {
      if (!existing.ips.includes(ip)) existing.ips.push(ip);
    }
    if (!existing.source.includes(sub.source)) {
      existing.source += `,${sub.source}`;
    }
  }
  return Array.from(subMap.values());
}

// Calculate risk score from findings
function calculateRiskScore(hosts: DiscoveredHost[], nucleiFindings: NucleiFinding[]): { score: number; band: DiscoverySummary["riskBand"] } {
  let score = 0;
  // Vuln-based scoring
  const allVulns = hosts.flatMap(h => h.vulns);
  score += allVulns.length * 5;
  // Port-based scoring (high-risk ports)
  const highRiskPorts = [21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];
  for (const host of hosts) {
    for (const port of host.ports) {
      if (highRiskPorts.includes(port.port)) score += 3;
    }
  }
  // Nuclei finding scoring
  for (const finding of nucleiFindings) {
    switch (finding.severity) {
      case "critical": score += 25; break;
      case "high": score += 15; break;
      case "medium": score += 8; break;
      case "low": score += 3; break;
      default: score += 1;
    }
  }
  // Normalize to 0-100
  score = Math.min(100, Math.round(score));
  const band: DiscoverySummary["riskBand"] =
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "minimal";
  return { score, band };
}

// Build summary from discovery results
function buildSummary(hosts: DiscoveredHost[], subdomains: SubdomainResult[], certs: TLSCertificate[], nucleiFindings: NucleiFinding[]): DiscoverySummary {
  const allPorts = hosts.flatMap(h => h.ports);
  const services = new Set<string>();
  const products = new Set<string>();
  const exposedPorts = new Set<number>();
  for (const port of allPorts) {
    if (port.service) services.add(port.service);
    if (port.product) products.add(port.product);
    exposedPorts.add(port.port);
  }
  const { score, band } = calculateRiskScore(hosts, nucleiFindings);
  return {
    totalHosts: hosts.length,
    totalPorts: allPorts.length,
    totalSubdomains: subdomains.length,
    totalVulnerabilities: hosts.reduce((sum, h) => sum + h.vulns.length, 0) + nucleiFindings.length,
    totalCertificates: certs.length,
    criticalFindings: nucleiFindings.filter(f => f.severity === "critical").length,
    highFindings: nucleiFindings.filter(f => f.severity === "high").length,
    mediumFindings: nucleiFindings.filter(f => f.severity === "medium").length,
    lowFindings: nucleiFindings.filter(f => f.severity === "low").length,
    infoFindings: nucleiFindings.filter(f => f.severity === "info").length,
    uniqueServices: Array.from(services),
    uniqueProducts: Array.from(products),
    exposedPorts: Array.from(exposedPorts).sort((a, b) => a - b),
    riskScore: score,
    riskBand: band,
  };
}

// ─── Cross-Module Enrichment ─────────────────────────────────────────────────

async function enrichFromBugBounty(hosts: DiscoveredHost[], domain: string): Promise<EnrichmentResult> {
  try {
    const { enrichDomainIntel } = await import("./bug-bounty-intelligence");
    const bbData = await enrichDomainIntel(domain);
    const correlations: Correlation[] = [];
    if (bbData.hasBugBountyProgram) {
      correlations.push({
        sourceModule: "bug_bounty",
        targetModule: "discovery_engine",
        correlationType: "extends",
        description: `Active bug bounty program found: ${bbData.programName}. ${bbData.disclosedVulnerabilities.total} disclosed vulnerabilities.`,
        confidence: 90,
        relatedEntities: [domain],
      });
    }
    if (bbData.topCWEs.length > 0) {
      correlations.push({
        sourceModule: "bug_bounty",
        targetModule: "discovery_engine",
        correlationType: "extends",
        description: `Top CWEs from bounty reports: ${bbData.topCWEs.slice(0, 5).map(c => c.cwe).join(", ")}`,
        confidence: 80,
        relatedEntities: bbData.topCWEs.map(c => c.cwe),
      });
    }
    return {
      module: "bug_bounty",
      status: "success",
      findingsCount: bbData.disclosedVulnerabilities.total,
      data: bbData,
      correlations,
    };
  } catch (err: any) {
    return { module: "bug_bounty", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}

async function enrichFromThreatIntel(hosts: DiscoveredHost[]): Promise<EnrichmentResult> {
  try {
    const { enrichThreatIntelligence } = await import("./bug-bounty-intelligence");
    const threatData = await enrichThreatIntelligence(30);
    const correlations: Correlation[] = [];
    // Cross-reference discovered services with trending weaknesses
    const discoveredServices = new Set(hosts.flatMap(h => h.ports.map(p => p.product).filter(Boolean)));
    for (const trend of threatData.trendingWeaknesses || []) {
      if (trend.trend === "rising") {
        correlations.push({
          sourceModule: "threat_enrichment",
          targetModule: "discovery_engine",
          correlationType: "extends",
          description: `Rising weakness trend: ${trend.cwe} (${trend.recentCount} recent reports)`,
          confidence: 70,
          relatedEntities: [trend.cwe],
        });
      }
    }
    return {
      module: "threat_enrichment",
      status: "success",
      findingsCount: threatData.exploitPatterns?.length || 0,
      data: threatData,
      correlations,
    };
  } catch (err: any) {
    return { module: "threat_enrichment", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}

async function enrichFromOpSec(hosts: DiscoveredHost[]): Promise<EnrichmentResult> {
  try {
    const { enrichOpSec } = await import("./bug-bounty-intelligence");
    const opsecData = await enrichOpSec();
    const correlations: Correlation[] = [];
    // Map discovered ports to defensive gaps
    const exposedHighRisk = hosts.filter(h => h.ports.some(p => [22, 3389, 445, 5900].includes(p.port)));
    if (exposedHighRisk.length > 0) {
      correlations.push({
        sourceModule: "discovery_engine",
        targetModule: "opsec",
        correlationType: "new_finding",
        description: `${exposedHighRisk.length} hosts expose high-risk remote access ports (SSH, RDP, SMB, VNC)`,
        confidence: 95,
        relatedEntities: exposedHighRisk.map(h => h.ip),
      });
    }
    return {
      module: "opsec",
      status: "success",
      findingsCount: opsecData.weaknessCategories?.length || 0,
      data: opsecData,
      correlations,
    };
  } catch (err: any) {
    return { module: "opsec", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}

// ─── LLM Analysis ────────────────────────────────────────────────────────────

export async function analyzeScanWithLLM(result: DiscoveryResult): Promise<LLMAnalysis> {
  try {
    const { invokeLLM } = await import("../_core/llm");
    const prompt = `You are a senior red team operator analyzing reconnaissance results. Analyze the following discovery scan data and provide a structured security assessment.

Target: ${result.targets.map(t => t.domain || t.ip || t.cidr).join(", ")}
Hosts Discovered: ${result.summary.totalHosts}
Open Ports: ${result.summary.totalPorts}
Subdomains: ${result.summary.totalSubdomains}
Vulnerabilities: ${result.summary.totalVulnerabilities}
Risk Score: ${result.summary.riskScore}/100 (${result.summary.riskBand})

Services Found: ${result.summary.uniqueServices.join(", ")}
Products Found: ${result.summary.uniqueProducts.join(", ")}
Exposed Ports: ${result.summary.exposedPorts.join(", ")}

Top Hosts (by port count):
${result.hosts.slice(0, 10).map(h => `- ${h.ip} (${h.hostnames.join(", ")}): ${h.ports.length} ports, ${h.vulns.length} vulns, OS: ${h.os || "unknown"}`).join("\n")}

Critical/High Findings:
${result.nucleiFindings.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 10).map(f => `- [${f.severity.toUpperCase()}] ${f.name}: ${f.description}`).join("\n") || "None from Nuclei templates"}

Cross-Module Correlations:
${result.enrichmentResults.flatMap(e => e.correlations).slice(0, 10).map(c => `- [${c.correlationType}] ${c.description}`).join("\n") || "None"}

Provide your analysis as JSON with these fields: executiveSummary, keyFindings (array), riskAssessment, attackSurfaceAnalysis, recommendations (array), threatActorRelevance (array), nextSteps (array).`;

    const response = await invokeLLM({
      _caller: "discovery-engine.analyzeScanWithLLM",
      messages: [
        { role: "system", content: "You are a senior penetration tester and red team operator. Provide actionable security analysis. Return valid JSON only." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "discovery_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              keyFindings: { type: "array", items: { type: "string" } },
              riskAssessment: { type: "string" },
              attackSurfaceAnalysis: { type: "string" },
              recommendations: { type: "array", items: { type: "string" } },
              threatActorRelevance: { type: "array", items: { type: "string" } },
              nextSteps: { type: "array", items: { type: "string" } },
            },
            required: ["executiveSummary", "keyFindings", "riskAssessment", "attackSurfaceAnalysis", "recommendations", "threatActorRelevance", "nextSteps"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices[0].message.content;
    return JSON.parse(typeof content === "string" ? content : "{}");
  } catch (err: any) {
    console.error("[DiscoveryEngine] LLM analysis failed:", err.message);
    return {
      executiveSummary: "LLM analysis unavailable — review raw findings manually.",
      keyFindings: [],
      riskAssessment: "Unable to generate automated risk assessment.",
      attackSurfaceAnalysis: "Manual review required.",
      recommendations: ["Review discovered hosts and ports manually", "Cross-reference with known vulnerability databases"],
      threatActorRelevance: [],
      nextSteps: ["Run deeper scans on high-value targets", "Validate critical findings"],
    };
  }
}

// ─── Main Discovery Pipeline ─────────────────────────────────────────────────

export async function runDiscoveryPipeline(
  targets: DiscoveryTarget[],
  config?: Partial<DiscoveryConfig>,
  onProgress?: (stage: string, detail: string) => void,
): Promise<DiscoveryResult> {
  const fullConfig = { ...defaultConfig(targets), ...config };
  const discoveryId = generateDiscoveryId();
  const startedAt = new Date().toISOString();
  const sourceStats: SourceStats[] = [];
  let allHosts: DiscoveredHost[] = [];
  let allSubdomains: SubdomainResult[] = [];
  let allDnsRecords: DNSRecord[] = [];
  let allCerts: TLSCertificate[] = [];
  const nucleiFindings: NucleiFinding[] = [];

  onProgress?.("initializing", `Discovery scan ${discoveryId} starting for ${targets.length} target(s)`);

  // Extract domains and IPs from targets
  let domains = targets.filter(t => t.domain).map(t => t.domain!);
  const ips = targets.filter(t => t.ip).map(t => t.ip!);

  // ─── Phase 0: Org-Wide Domain Discovery ───────────────────────────
  let orgDiscoveryResult: OrgDiscoveryResult | null = null;
  if (domains.length > 0) {
    onProgress?.("org_discovery", "Discovering all domains owned by the target organization");
    try {
      // Get org name from WHOIS of the primary (seed) domain
      const seedDomain = domains[0];
      let orgName = "";
      let orgEmail: string | null = null;

      if (fullConfig.enabledSources.securityTrails) {
        try {
          const whoisData = await securityTrailsWHOIS(seedDomain);
          orgName = whoisData?.registrant?.organization
            || whoisData?.registrant?.name
            || whoisData?.contacts?.registrant?.organization
            || whoisData?.contacts?.registrant?.name
            || "";
          orgEmail = whoisData?.registrant?.email
            || whoisData?.contacts?.registrant?.email
            || null;
          onProgress?.("org_discovery", `Identified org: "${orgName}" (${orgEmail || "no email"}) from WHOIS`);
        } catch (err: any) {
          onProgress?.("org_discovery", `WHOIS org extraction failed: ${err.message}`);
        }
      }

      if (orgName) {
        orgDiscoveryResult = await discoverOrgDomains(
          seedDomain,
          orgName,
          orgEmail,
          {
            minConfidenceThreshold: 60,
            maxCandidates: 150,
            enableWebVerification: false,
            enableSpfPivoting: true,
            lookupTimeoutMs: 15000,
          },
          (detail) => onProgress?.("org_discovery", detail),
        );

        // Add verified domains to the scan targets
        const newDomains = orgDiscoveryResult.verifiedDomains
          .filter(d => !domains.includes(d.domain))
          .map(d => d.domain);

        if (newDomains.length > 0) {
          domains = [...domains, ...newDomains];
          onProgress?.("org_discovery", `Added ${newDomains.length} verified org domains to scan scope: ${newDomains.join(", ")}`);
        }

        // Add org discovery stats
        sourceStats.push({
          source: "org_discovery",
          hostsFound: 0,
          portsFound: 0,
          subdomainsFound: 0,
          vulnsFound: 0,
          responseTimeMs: orgDiscoveryResult.durationMs,
          status: orgDiscoveryResult.verifiedDomains.length > 0 ? "success" : "partial",
          error: null,
        });
      } else {
        onProgress?.("org_discovery", "Skipped: could not determine org name from WHOIS");
        sourceStats.push({
          source: "org_discovery",
          hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0,
          responseTimeMs: 0, status: "skipped", error: "No org name available from WHOIS",
        });
      }
    } catch (err: any) {
      onProgress?.("org_discovery", `Org discovery failed (non-fatal): ${err.message}`);
      sourceStats.push({
        source: "org_discovery",
        hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0,
        responseTimeMs: 0, status: "failed", error: err.message,
      });
    }
  }

  // ─── Phase 1: Subdomain Enumeration ────────────────────────────────
  onProgress?.("subdomain_enum", "Enumerating subdomains from multiple sources");

  for (const domain of domains) {
    // crt.sh (always available)
    if (fullConfig.enabledSources.crtsh) {
      const start = Date.now();
      try {
        const subs = await crtshSubdomains(domain);
        allSubdomains.push(...subs);
        sourceStats.push({ source: "crtsh", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "crtsh", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }

    // SecurityTrails subdomains
    if (fullConfig.enabledSources.securityTrails) {
      const start = Date.now();
      try {
        const subs = await securityTrailsSubdomains(domain);
        allSubdomains.push(...subs);
        const dnsHistory = await securityTrailsDNSHistory(domain);
        allDnsRecords.push(...dnsHistory);
        sourceStats.push({ source: "securitytrails", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "securitytrails", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }

    // Shodan DNS
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const subs = await shodanDNSLookup(domain);
        allSubdomains.push(...subs);
        sourceStats.push({ source: "shodan_dns", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "shodan_dns", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }

  allSubdomains = mergeSubdomains(allSubdomains);
  onProgress?.("subdomain_enum", `Found ${allSubdomains.length} unique subdomains`);

  // ─── Phase 2: Host Discovery & Port Scanning ──────────────────────
  onProgress?.("host_discovery", "Discovering hosts and scanning ports");

  for (const domain of domains) {
    // Shodan host search
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const hosts = await shodanDomainSearch(domain);
        allHosts.push(...hosts);
        const totalPorts = hosts.reduce((s, h) => s + h.ports.length, 0);
        const totalVulns = hosts.reduce((s, h) => s + h.vulns.length, 0);
        sourceStats.push({ source: "shodan", hostsFound: hosts.length, portsFound: totalPorts, subdomainsFound: 0, vulnsFound: totalVulns, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "shodan", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }

    // Censys host search
    if (fullConfig.enabledSources.censys) {
      const start = Date.now();
      try {
        const hosts = await censysHostSearch(domain);
        allHosts.push(...hosts);
        const certs = await censysCertSearch(domain);
        allCerts.push(...certs);
        sourceStats.push({ source: "censys", hostsFound: hosts.length, portsFound: hosts.reduce((s, h) => s + h.ports.length, 0), subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "censys", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }

  // Direct IP lookups
  for (const ip of ips) {
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const host = await shodanHostLookup(ip);
        if (host) allHosts.push(host);
        sourceStats.push({ source: "shodan_ip", hostsFound: host ? 1 : 0, portsFound: host?.ports.length || 0, subdomainsFound: 0, vulnsFound: host?.vulns.length || 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err: any) {
        sourceStats.push({ source: "shodan_ip", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }

  allHosts = mergeHosts(allHosts);
  onProgress?.("host_discovery", `Found ${allHosts.length} unique hosts with ${allHosts.reduce((s, h) => s + h.ports.length, 0)} ports`);

  // ─── Phase 3: Cross-Module Enrichment ─────────────────────────────
  onProgress?.("enrichment", "Running cross-module enrichment");
  const enrichmentResults: EnrichmentResult[] = [];

  if (fullConfig.enrichmentModules.includes("bug_bounty") && domains.length > 0) {
    const bbResult = await enrichFromBugBounty(allHosts, domains[0]);
    enrichmentResults.push(bbResult);
  }

  if (fullConfig.enrichmentModules.includes("threat_enrichment")) {
    const threatResult = await enrichFromThreatIntel(allHosts);
    enrichmentResults.push(threatResult);
  }

  if (fullConfig.enrichmentModules.includes("opsec")) {
    const opsecResult = await enrichFromOpSec(allHosts);
    enrichmentResults.push(opsecResult);
  }

  onProgress?.("enrichment", `Completed ${enrichmentResults.filter(e => e.status === "success").length}/${enrichmentResults.length} enrichment modules`);

  // ─── Phase 4: Build Summary ───────────────────────────────────────
  const summary = buildSummary(allHosts, allSubdomains, allCerts, nucleiFindings);

  const result: DiscoveryResult = {
    id: discoveryId,
    startedAt,
    completedAt: new Date().toISOString(),
    status: "completed",
    targets,
    config: fullConfig,
    hosts: allHosts,
    subdomains: allSubdomains,
    dnsRecords: allDnsRecords,
    certificates: allCerts,
    nucleiFindings,
    sourceStats,
    summary,
    enrichmentResults,
    llmAnalysis: null,
    orgDiscovery: orgDiscoveryResult,
  };

  // ─── Phase 5: LLM Analysis (if hosts found) ──────────────────────
  if (allHosts.length > 0 || allSubdomains.length > 0) {
    onProgress?.("llm_analysis", "Running LLM-powered analysis");
    result.llmAnalysis = await analyzeScanWithLLM(result);
  }

  // ─── Phase 6: Auto-generate CARVER Risk Cards ──────────────────
  try {
    onProgress?.("carver_scoring", "Generating CARVER risk cards for discovered assets");
    const { buildExplainableRiskCard } = await import("./auto-industry-carver");
    const { createCarverRiskCardsBatch } = await import("../db");

    const riskCardRecords: any[] = [];
    const batchId = `discovery-${discoveryId}`;

    // Generate risk card for each target domain
    for (const domain of domains) {
      try {
        // Collect asset signals from discovered subdomains and services
        const domainSubs = allSubdomains.filter(s => s.subdomain.endsWith(domain));
        const assetSignals: string[] = [];
        for (const sub of domainSubs) {
          if (sub.subdomain.includes("mail") || sub.subdomain.includes("mx")) assetSignals.push("MX Record");
          if (sub.subdomain.includes("sso") || sub.subdomain.includes("auth") || sub.subdomain.includes("login")) assetSignals.push("SSO");
          if (sub.subdomain.includes("vpn")) assetSignals.push("VPN Gateway");
          if (sub.subdomain.includes("api")) assetSignals.push("API Gateway");
          if (sub.subdomain.includes("db") || sub.subdomain.includes("sql")) assetSignals.push("Database");
          if (sub.subdomain.includes("git") || sub.subdomain.includes("ci") || sub.subdomain.includes("jenkins")) assetSignals.push("CI/CD");
        }

        // Collect service keywords from hosts
        const domainHosts = allHosts.filter(h => h.hostnames?.some(hn => hn.endsWith(domain)));
        const keywords: string[] = [];
        for (const host of domainHosts) {
          for (const port of (host.ports || [])) {
            if (port.service) keywords.push(port.service);
            if (port.product) keywords.push(port.product);
          }
        }

        const riskCard = buildExplainableRiskCard({
          assetId: domain,
          assetLabel: `${domain} (Discovery Scan)`,
          domain,
          keywords: [...new Set(keywords)],
          assetSignals: [...new Set(assetSignals)],
        });

        riskCardRecords.push({
          domain,
          scanTitle: `${domain} — Discovery Scan`,
          inferredSector: riskCard.sector,
          sectorConfidence: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : riskCard.confidence >= 0.35 ? "low" : "insufficient",
          naicsCode: riskCard.naics || null,
          naicsLabel: null,
          industry: null,
          regulatoryTags: riskCard.regulatoryProfile || [],
          country: "US",
          carverScores: { criticality: riskCard.scores?.carverShock || 0 },
          shockScores: null,
          hybridScore: riskCard.scores?.hybrid || 0,
          priorityTier: riskCard.scores?.priorityTier || "P3",
          confidenceBand: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : "low",
          topDrivers: riskCard.topDrivers || [],
          recommendedActions: riskCard.recommendedActions || [],
          calderaOps: riskCard.calderaPriority || null,
          threatLikelihood: riskCard.threatLikelihood || null,
          fullRiskCard: riskCard,
          source: "discovery_engine" as const,
          batchId,
        });
      } catch (_) {
        // Skip individual domain failures
      }
    }

    if (riskCardRecords.length > 0) {
      await createCarverRiskCardsBatch(riskCardRecords as any);
      onProgress?.("carver_scoring", `Generated ${riskCardRecords.length} CARVER risk cards`);
    }
  } catch (carverErr) {
    // Non-fatal: don't block discovery pipeline if CARVER scoring fails
    onProgress?.("carver_scoring", `CARVER scoring skipped: ${(carverErr as Error).message}`);
  }

  onProgress?.("completed", `Discovery scan complete: ${summary.totalHosts} hosts, ${summary.totalSubdomains} subdomains, risk=${summary.riskScore}`);
  return result;
}

// ─── Available Sources Check ─────────────────────────────────────────────────

export function getAvailableSources(): { source: string; available: boolean; reason: string }[] {
  return [
    { source: "shodan", available: !!ENV.SHODAN_API_KEY, reason: ENV.SHODAN_API_KEY ? "API key configured" : "SHODAN_API_KEY not set" },
    { source: "censys", available: !!(ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET), reason: (ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET) ? "API credentials configured" : "CENSYS_API_ID/SECRET not set" },
    { source: "securityTrails", available: !!ENV.SECURITYTRAILS_API_KEY, reason: ENV.SECURITYTRAILS_API_KEY ? "API key configured" : "SECURITYTRAILS_API_KEY not set" },
    { source: "crtsh", available: true, reason: "Free service, no API key required" },
    { source: "wayback", available: true, reason: "Free service, no API key required" },
    { source: "dnsEnum", available: true, reason: "Built-in DNS enumeration" },
    { source: "whois", available: true, reason: "Built-in WHOIS lookup" },
    { source: "nuclei", available: false, reason: "Requires CLI bridge (not yet configured)" },
  ];
}
