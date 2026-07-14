/**
 * Finding Deduplication & Quality Service
 * 
 * Addresses the 5 key issues identified in the Celerium Pen Test 2026 analysis:
 * 1. IP-based hostname deduplication (same server, different DNS names)
 * 2. Re-scan deduplication (prevent doubling on re-run)
 * 3. Multi-tool finding consolidation (nuclei + ZAP + scanforge → 1 finding)
 * 4. ZAP noise filtering (User Agent Fuzzer, duplicate CSP entries)
 * 5. Exploit matching severity gate (no exploit rules for info-level findings)
 * 
 * Integrated into the engagement-orchestrator pipeline before final vuln counting.
 */

import * as dns from 'dns';
import { promisify } from 'util';

const dnsResolve4 = promisify(dns.resolve4);

// ─── Types ─────────────────────────────────────────────────────────────────

export interface AssetFindings {
  hostname: string;
  ip?: string;
  vulns: VulnFinding[];
  zapFindings: ZapFinding[];
  nucleiFindings?: NucleiFinding[];
  ports: PortInfo[];
  exploitAttempts: any[];
}

export interface VulnFinding {
  title: string;
  severity: string;
  cwe?: string;
  owasp?: string;
  endpoint?: string;
  source?: string;
  rawEvidence?: string;
  evidence?: string;
  corroborationTier?: string;
  scannerEvidence?: Array<{ scanner: string; title: string }>;
  scannerCount?: number;
  [key: string]: any;
}

export interface ZapFinding {
  alert: string;
  risk: string;
  confidence?: string;
  url?: string;
  cweId?: string | number;
  description?: string;
  solution?: string;
  [key: string]: any;
}

export interface NucleiFinding {
  title: string;
  severity: string;
  templateId?: string;
  host?: string;
  matchedAt?: string;
  [key: string]: any;
}

export interface PortInfo {
  port: number;
  service?: string;
  version?: string;
  [key: string]: any;
}

export interface DeduplicationResult {
  assets: AssetFindings[];
  stats: {
    originalAssetCount: number;
    deduplicatedAssetCount: number;
    originalVulnCount: number;
    deduplicatedVulnCount: number;
    ipGroupsMerged: number;
    zapNoiseFiltered: number;
    multiToolMerged: number;
    rescanDuplicatesRemoved: number;
    crossHostConsolidated: number;
  };
  log: string[];
  /** Distinct vulnerability types after cross-host consolidation */
  distinctVulnTypes?: Array<{ title: string; severity: string; affectedHosts: string[]; count: number }>;
}

// ─── ZAP Noise Patterns ────────────────────────────────────────────────────

/**
 * ZAP findings that are informational noise and should be collapsed or filtered.
 * These generate multiple entries per host without providing actionable vuln data.
 */
const ZAP_NOISE_PATTERNS: RegExp[] = [
  /user\s*agent\s*fuzzer/i,
  /information\s*disclosure.*suspicious\s*comments/i,
  /timestamp\s*disclosure/i,
  /x-content-type-options\s*header\s*missing/i,  // Only if reported multiple times per host
  /re-examine\s*cache/i,
  /modern\s*web\s*application/i,
  /non-storable\s*content/i,
  /storable\s*but\s*non-cacheable/i,
];

/**
 * ZAP findings that should be collapsed to 1 per host (keep highest confidence).
 * These are legitimate observations but get duplicated per-URL.
 */
const ZAP_COLLAPSE_PATTERNS: RegExp[] = [
  /user\s*agent\s*fuzzer/i,
  /csp:?\s*x-content-security-policy/i,
  /csp:?\s*x-webkit-csp/i,
  /obsolete\s*content\s*security\s*policy/i,
  /csp:?\s*failure\s*to\s*define/i,
  /http\s*only\s*site/i,
  /server\s*leaks\s*version/i,
  /x-frame-options\s*header/i,
  /strict-transport-security/i,
];

// ─── Severity Helpers ──────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  informational: 1,
};

function getSeverityRank(severity: string): number {
  return SEVERITY_RANK[severity?.toLowerCase()] || 0;
}

const CONFIDENCE_RANK: Record<string, number> = {
  confirmed: 4,
  high: 3,
  medium: 2,
  low: 1,
  potential: 0,
};

function getConfidenceRank(confidence: string): number {
  return CONFIDENCE_RANK[confidence?.toLowerCase()] || 0;
}

// ─── Fix 1: IP-Based Hostname Deduplication ────────────────────────────────

/**
 * Resolves hostnames to IPs and merges assets that share the same IP address.
 * Findings from duplicate hostnames are consolidated into a single asset entry,
 * with all affected hostnames listed.
 */
export async function deduplicateByIp(assets: AssetFindings[]): Promise<{
  mergedAssets: AssetFindings[];
  ipGroups: Map<string, string[]>;
  mergeCount: number;
}> {
  // Step 1: Resolve all hostnames to IPs
  const hostnameToIp = new Map<string, string>();
  
  for (const asset of assets) {
    if (asset.ip) {
      hostnameToIp.set(asset.hostname, asset.ip);
    } else {
      try {
        const ips = await dnsResolve4(asset.hostname);
        if (ips.length > 0) {
          hostnameToIp.set(asset.hostname, ips[0]);
          asset.ip = ips[0];
        }
      } catch {
        // DNS resolution failed — treat as unique
        hostnameToIp.set(asset.hostname, `unresolved-${asset.hostname}`);
      }
    }
  }

  // Step 2: Group assets by IP
  const ipGroups = new Map<string, AssetFindings[]>();
  for (const asset of assets) {
    const ip = hostnameToIp.get(asset.hostname) || asset.hostname;
    const group = ipGroups.get(ip) || [];
    group.push(asset);
    ipGroups.set(ip, group);
  }

  // Step 3: Merge assets within each IP group
  const mergedAssets: AssetFindings[] = [];
  let mergeCount = 0;
  const ipHostnameMap = new Map<string, string[]>();

  for (const [ip, group] of ipGroups) {
    ipHostnameMap.set(ip, group.map(a => a.hostname));
    
    if (group.length === 1) {
      mergedAssets.push(group[0]);
      continue;
    }

    // Multiple hostnames → same IP: merge findings
    mergeCount += group.length - 1;
    const primary = group[0]; // Use first hostname as primary
    const allHostnames = group.map(a => a.hostname);

    // Merge vulns (deduplicate by title+severity)
    const vulnMap = new Map<string, VulnFinding>();
    for (const asset of group) {
      for (const vuln of asset.vulns) {
        const key = `${vuln.title.toLowerCase()}|${vuln.severity?.toLowerCase()}|${vuln.endpoint || ''}`;
        const existing = vulnMap.get(key);
        if (!existing) {
          vulnMap.set(key, { ...vuln, affectedHostnames: allHostnames } as any);
        } else {
          // Merge: upgrade severity if higher, combine evidence
          if (getSeverityRank(vuln.severity) > getSeverityRank(existing.severity)) {
            existing.severity = vuln.severity;
          }
          if (vuln.rawEvidence && !existing.rawEvidence) {
            existing.rawEvidence = vuln.rawEvidence;
          }
          if (vuln.corroborationTier === 'confirmed' && existing.corroborationTier !== 'confirmed') {
            existing.corroborationTier = 'confirmed';
          }
        }
      }
    }

    // Merge ZAP findings (deduplicate by alert+risk)
    const zapMap = new Map<string, ZapFinding>();
    for (const asset of group) {
      for (const zap of asset.zapFindings) {
        const key = `${zap.alert.toLowerCase()}|${zap.risk?.toLowerCase()}`;
        const existing = zapMap.get(key);
        if (!existing) {
          zapMap.set(key, { ...zap, affectedHostnames: allHostnames } as any);
        } else {
          // Keep higher confidence
          if (getConfidenceRank(zap.confidence || '') > getConfidenceRank(existing.confidence || '')) {
            existing.confidence = zap.confidence;
          }
        }
      }
    }

    // Merge ports (union)
    const portSet = new Set<number>();
    const mergedPorts: PortInfo[] = [];
    for (const asset of group) {
      for (const port of asset.ports) {
        if (!portSet.has(port.port)) {
          portSet.add(port.port);
          mergedPorts.push(port);
        }
      }
    }

    // Merge nuclei findings
    const nucleiMap = new Map<string, NucleiFinding>();
    for (const asset of group) {
      for (const nf of (asset.nucleiFindings || [])) {
        const key = `${nf.title?.toLowerCase()}|${nf.templateId || ''}`;
        if (!nucleiMap.has(key)) {
          nucleiMap.set(key, { ...nf, affectedHostnames: allHostnames } as any);
        }
      }
    }

    mergedAssets.push({
      hostname: primary.hostname,
      ip,
      vulns: [...vulnMap.values()],
      zapFindings: [...zapMap.values()],
      nucleiFindings: [...nucleiMap.values()],
      ports: mergedPorts,
      exploitAttempts: group.flatMap(a => a.exploitAttempts),
      // Preserve metadata about the merge
      ...(({ mergedFrom: allHostnames }) as any),
    });
  }

  return { mergedAssets, ipGroups: ipHostnameMap, mergeCount };
}

// ─── Fix 2: Re-Scan Deduplication ─────────────────────────────────────────

/**
 * Compares new scan findings against existing findings and removes duplicates.
 * Used when "Quick Re-Scan" or "Re-Run Full Pipeline" is triggered.
 */
export function deduplicateOnRescan(
  existingVulns: VulnFinding[],
  newVulns: VulnFinding[]
): { unique: VulnFinding[]; duplicates: number } {
  const existingKeys = new Set(
    existingVulns.map(v => generateFindingKey(v))
  );

  const unique: VulnFinding[] = [];
  let duplicates = 0;

  for (const vuln of newVulns) {
    const key = generateFindingKey(vuln);
    if (existingKeys.has(key)) {
      duplicates++;
    } else {
      unique.push(vuln);
      existingKeys.add(key); // Prevent intra-batch duplicates too
    }
  }

  return { unique, duplicates };
}

export function deduplicateZapOnRescan(
  existingZap: ZapFinding[],
  newZap: ZapFinding[]
): { unique: ZapFinding[]; duplicates: number } {
  const existingKeys = new Set(
    existingZap.map(z => `${z.alert.toLowerCase()}|${z.risk?.toLowerCase()}|${z.url || ''}`)
  );

  const unique: ZapFinding[] = [];
  let duplicates = 0;

  for (const zap of newZap) {
    const key = `${zap.alert.toLowerCase()}|${zap.risk?.toLowerCase()}|${zap.url || ''}`;
    if (existingKeys.has(key)) {
      duplicates++;
    } else {
      unique.push(zap);
      existingKeys.add(key);
    }
  }

  return { unique, duplicates };
}

function generateFindingKey(vuln: VulnFinding): string {
  const title = vuln.title.toLowerCase()
    .replace(/\[zap\]\s*/g, '')
    .replace(/\[nuclei\]\s*/g, '')
    .replace(/\[scanforge\]\s*/g, '')
    .trim();
  const severity = vuln.severity?.toLowerCase() || 'info';
  const endpoint = vuln.endpoint?.toLowerCase() || '';
  return `${title}|${severity}|${endpoint}`;
}

// ─── Fix 3: Multi-Tool Finding Consolidation ──────────────────────────────

/**
 * Consolidates findings reported by multiple tools into single entries.
 * E.g., "Missing Security Headers" from nuclei + ZAP + scanforge → 1 finding with 3 evidence sources.
 */
export function consolidateMultiToolFindings(
  vulns: VulnFinding[],
  zapFindings: ZapFinding[]
): { consolidated: VulnFinding[]; mergedCount: number } {
  // Normalize all findings into a common format for comparison
  const consolidationMap = new Map<string, VulnFinding>();
  let mergedCount = 0;

  // Process vulns first (they have richer metadata)
  for (const vuln of vulns) {
    const normKey = normalizeFindingTitle(vuln.title);
    const existing = consolidationMap.get(normKey);
    if (!existing) {
      consolidationMap.set(normKey, {
        ...vuln,
        scannerEvidence: vuln.scannerEvidence || [{ scanner: extractScanner(vuln.title, vuln.source), title: vuln.title }],
        scannerCount: 1,
      });
    } else {
      mergedCount++;
      // Merge: keep highest severity
      if (getSeverityRank(vuln.severity) > getSeverityRank(existing.severity)) {
        existing.severity = vuln.severity;
      }
      // Add scanner evidence
      const scanner = extractScanner(vuln.title, vuln.source);
      const evidence = existing.scannerEvidence || [];
      if (!evidence.some(e => e.scanner === scanner)) {
        evidence.push({ scanner, title: vuln.title });
      }
      existing.scannerEvidence = evidence;
      existing.scannerCount = evidence.length;
      // Merge raw evidence
      if (vuln.rawEvidence && !existing.rawEvidence) {
        existing.rawEvidence = vuln.rawEvidence;
      }
      // Upgrade corroboration
      if (vuln.corroborationTier === 'confirmed') {
        existing.corroborationTier = 'confirmed';
      }
    }
  }

  // Now check ZAP findings against existing consolidated vulns
  for (const zap of zapFindings) {
    const normKey = normalizeFindingTitle(zap.alert);
    const existing = consolidationMap.get(normKey);
    if (existing) {
      mergedCount++;
      // ZAP finding matches an existing vuln — add as evidence
      const evidence = existing.scannerEvidence || [];
      if (!evidence.some(e => e.scanner === 'zap')) {
        evidence.push({ scanner: 'zap', title: zap.alert });
      }
      existing.scannerEvidence = evidence;
      existing.scannerCount = evidence.length;
      if (zap.confidence === 'High' || zap.confidence === 'Confirmed') {
        existing.corroborationTier = 'confirmed';
      }
    }
    // If no match, ZAP finding stays in zapFindings array (not duplicated into vulns)
  }

  return { consolidated: [...consolidationMap.values()], mergedCount };
}

/**
 * Normalizes finding titles for comparison across tools.
 * Strips tool prefixes, normalizes case, and maps common synonyms.
 */
function normalizeFindingTitle(title: string): string {
  let normalized = title.toLowerCase()
    .replace(/^\[(zap|nuclei|scanforge|nmap|nikto|httpx)\]\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();

  // Map common synonyms
  const synonyms: [RegExp, string][] = [
    [/missing.*x-frame-options/i, 'missing-x-frame-options'],
    [/x-frame-options.*missing/i, 'missing-x-frame-options'],
    [/clickjacking.*x-frame/i, 'missing-x-frame-options'],
    [/missing.*x-content-type-options/i, 'missing-x-content-type-options'],
    [/x-content-type-options.*missing/i, 'missing-x-content-type-options'],
    [/missing.*strict-transport/i, 'missing-hsts'],
    [/hsts.*missing/i, 'missing-hsts'],
    [/strict-transport-security.*not.*set/i, 'missing-hsts'],
    [/content-security-policy.*missing/i, 'missing-csp'],
    [/missing.*content-security-policy/i, 'missing-csp'],
    [/csp.*not.*implemented/i, 'missing-csp'],
    [/server.*version.*disclosure/i, 'server-version-disclosure'],
    [/server.*leaks.*version/i, 'server-version-disclosure'],
    [/server.*header.*information/i, 'server-version-disclosure'],
    [/http.*only.*site/i, 'http-only-no-https'],
    [/missing.*https/i, 'http-only-no-https'],
    [/ssl.*not.*enforced/i, 'http-only-no-https'],
  ];

  for (const [pattern, replacement] of synonyms) {
    if (pattern.test(normalized)) {
      return replacement;
    }
  }

  return normalized;
}

function extractScanner(title: string, source?: string): string {
  if (source) return source.toLowerCase();
  const match = title.match(/^\[(zap|nuclei|scanforge|nmap|nikto|httpx|hydra)\]/i);
  if (match) return match[1].toLowerCase();
  return 'unknown';
}

// ─── Fix 4: ZAP Noise Filter ──────────────────────────────────────────────

/**
 * Filters ZAP findings to remove noise and collapse duplicates per host.
 * - Removes "User Agent Fuzzer" spam (keep max 1 per host)
 * - Collapses duplicate CSP findings
 * - Removes CONFIRMED+POTENTIAL duplicates (keeps CONFIRMED)
 */
export function filterZapNoise(zapFindings: ZapFinding[]): {
  filtered: ZapFinding[];
  removedCount: number;
} {
  const seen = new Map<string, ZapFinding>();
  let removedCount = 0;

  for (const zap of zapFindings) {
    // Check if this is a noise pattern that should be collapsed
    const shouldCollapse = ZAP_COLLAPSE_PATTERNS.some(p => p.test(zap.alert));

    if (shouldCollapse) {
      // Only keep one instance per alert type (highest confidence)
      const collapseKey = zap.alert.toLowerCase().replace(/\s+/g, ' ').trim();
      const existing = seen.get(collapseKey);
      if (!existing) {
        seen.set(collapseKey, zap);
      } else {
        // Keep the one with higher confidence
        if (getConfidenceRank(zap.confidence || '') > getConfidenceRank(existing.confidence || '')) {
          seen.set(collapseKey, zap);
        }
        removedCount++;
      }
      continue;
    }

    // Check if this is pure noise that should be removed entirely
    const isNoise = ZAP_NOISE_PATTERNS.some(p => p.test(zap.alert));
    if (isNoise && zap.risk?.toLowerCase() === 'informational') {
      removedCount++;
      continue;
    }

    // Deduplicate CONFIRMED vs POTENTIAL for same alert
    const dedupeKey = `${zap.alert.toLowerCase()}|${zap.risk?.toLowerCase()}`;
    const existingDedup = seen.get(dedupeKey);
    if (!existingDedup) {
      seen.set(dedupeKey, zap);
    } else {
      // Keep CONFIRMED over POTENTIAL
      if (getConfidenceRank(zap.confidence || '') > getConfidenceRank(existingDedup.confidence || '')) {
        seen.set(dedupeKey, zap);
      }
      removedCount++;
    }
  }

  return { filtered: [...seen.values()], removedCount };
}

// ─── Fix 5: Exploit Matching Severity Gate ─────────────────────────────────

/**
 * Determines whether a finding should be eligible for exploit rule matching.
 * Info-level findings (CSP observations, User Agent Fuzzer, etc.) should NOT
 * be matched to SQL Injection/XSS/Command Injection exploit rules.
 */
export function isExploitMatchEligible(vuln: { title: string; severity: string; cve?: string }): boolean {
  const severity = vuln.severity?.toLowerCase() || 'info';
  
  // Info-level findings are never exploit-matchable unless they have a CVE
  if (severity === 'info' || severity === 'informational') {
    // Exception: if it has a real CVE, it might still be exploitable
    if (vuln.cve && /^CVE-\d{4}-\d+$/i.test(vuln.cve)) {
      return true;
    }
    return false;
  }

  // Low-severity findings need additional validation
  if (severity === 'low') {
    const titleLower = vuln.title.toLowerCase();
    // These low-sev findings are purely informational and not exploitable
    const nonExploitable = [
      /server.*leaks.*version/i,
      /information.*disclosure/i,
      /cookie.*without.*secure/i,
      /cookie.*without.*httponly/i,
      /x-content-type-options/i,
      /csp.*header/i,
      /content-security-policy/i,
    ];
    if (nonExploitable.some(p => p.test(titleLower))) {
      return false;
    }
  }

  return true;
}

/**
 * Filters the ZAP rules that should be applied based on the actual finding type.
 * Prevents blanket "SQL Injection, XSS, Command Injection, Path Traversal" 
 * from being applied to every [zap] finding regardless of what it actually is.
 */
export function getRelevantZapRules(vuln: { title: string; severity: string }): string[] {
  if (!isExploitMatchEligible(vuln)) return [];

  const titleLower = vuln.title.toLowerCase();
  const rules: string[] = [];

  // Only apply specific rules that are relevant to the finding type
  if (titleLower.includes('sql') || titleLower.includes('database')) {
    rules.push('SQL Injection');
  }
  if (titleLower.includes('xss') || titleLower.includes('cross-site scripting') || titleLower.includes('script injection')) {
    rules.push('XSS (Reflected)', 'XSS (Persistent)');
  }
  if (titleLower.includes('command') || titleLower.includes('rce') || titleLower.includes('remote code')) {
    rules.push('Command Injection');
  }
  if (titleLower.includes('path traversal') || titleLower.includes('lfi') || titleLower.includes('directory traversal') || titleLower.includes('file inclusion')) {
    rules.push('Path Traversal');
  }
  if (titleLower.includes('auth') || titleLower.includes('login') || titleLower.includes('credential') || titleLower.includes('brute')) {
    rules.push('Authentication Bypass', 'Forced Browse: Default Credentials');
  }
  if (titleLower.includes('ssrf') || titleLower.includes('server-side request')) {
    rules.push('Server Side Request Forgery');
  }
  if (titleLower.includes('redirect') || titleLower.includes('open redirect')) {
    rules.push('Open Redirect');
  }

  return [...new Set(rules)];
}

// ─── Fix 6: Cross-Host Title-Based Consolidation ─────────────────────────────

/**
 * Consolidates the same finding type across ALL hosts (regardless of IP).
 * After IP-based dedup handles same-IP hosts, this pass handles the case where
 * the same vulnerability type (e.g., "Missing HSTS Header") appears on hosts
 * at different IPs (e.g., 18.209.149.165 and 40.39.3.58).
 *
 * This does NOT remove findings from individual assets (they still appear per-host
 * in detailed views). Instead, it produces a consolidated summary of distinct
 * vulnerability types with affected host lists for executive reporting.
 */
export function consolidateCrossHost(assets: AssetFindings[]): {
  distinctTypes: Array<{ title: string; severity: string; affectedHosts: string[]; count: number }>;
  consolidatedCount: number;
  totalInstances: number;
} {
  const typeMap = new Map<string, { title: string; severity: string; affectedHosts: Set<string>; count: number }>();

  for (const asset of assets) {
    const hostname = asset.hostname;

    for (const vuln of asset.vulns) {
      const normKey = normalizeFindingTitle(vuln.title);
      const existing = typeMap.get(normKey);
      if (!existing) {
        typeMap.set(normKey, { title: vuln.title, severity: vuln.severity, affectedHosts: new Set([hostname]), count: 1 });
      } else {
        existing.affectedHosts.add(hostname);
        existing.count++;
        if (getSeverityRank(vuln.severity) > getSeverityRank(existing.severity)) existing.severity = vuln.severity;
      }
    }

    for (const zap of asset.zapFindings) {
      const normKey = normalizeFindingTitle(zap.alert);
      const existing = typeMap.get(normKey);
      if (!existing) {
        typeMap.set(normKey, { title: zap.alert, severity: zap.risk || 'info', affectedHosts: new Set([hostname]), count: 1 });
      } else {
        existing.affectedHosts.add(hostname);
        existing.count++;
        if (getSeverityRank(zap.risk || 'info') > getSeverityRank(existing.severity)) existing.severity = zap.risk || 'info';
      }
    }

    if (asset.nucleiFindings) {
      for (const nf of asset.nucleiFindings) {
        const normKey = normalizeFindingTitle(nf.title);
        const existing = typeMap.get(normKey);
        if (!existing) {
          typeMap.set(normKey, { title: nf.title, severity: nf.severity, affectedHosts: new Set([hostname]), count: 1 });
        } else {
          existing.affectedHosts.add(hostname);
          existing.count++;
          if (getSeverityRank(nf.severity) > getSeverityRank(existing.severity)) existing.severity = nf.severity;
        }
      }
    }
  }

  const totalInstances = [...typeMap.values()].reduce((sum, t) => sum + t.count, 0);
  const distinctTypes = [...typeMap.values()]
    .map(t => ({ title: t.title, severity: t.severity, affectedHosts: [...t.affectedHosts], count: t.count }))
    .sort((a, b) => getSeverityRank(b.severity) - getSeverityRank(a.severity));

  return { distinctTypes, consolidatedCount: distinctTypes.length, totalInstances };
}

// ─── Master Pipeline ───────────────────────────────────────────────────────────────────────

/**
 * Runs the complete deduplication pipeline on engagement assets.
 * Call this before final vuln counting and report generation.
 */
export async function runDeduplicationPipeline(
  assets: AssetFindings[],
  options: {
    enableIpDedup?: boolean;
    enableZapFilter?: boolean;
    enableMultiToolConsolidation?: boolean;
    enableRescanDedup?: boolean;
    existingFindings?: VulnFinding[];
    existingZapFindings?: ZapFinding[];
  } = {}
): Promise<DeduplicationResult> {
  const {
    enableIpDedup = true,
    enableZapFilter = true,
    enableMultiToolConsolidation = true,
    enableRescanDedup = false,
    existingFindings = [],
    existingZapFindings = [],
  } = options;

  const log: string[] = [];
  const stats = {
    originalAssetCount: assets.length,
    deduplicatedAssetCount: 0,
    originalVulnCount: assets.reduce((sum, a) => sum + a.vulns.length + a.zapFindings.length, 0),
    deduplicatedVulnCount: 0,
    ipGroupsMerged: 0,
    zapNoiseFiltered: 0,
    multiToolMerged: 0,
    rescanDuplicatesRemoved: 0,
    crossHostConsolidated: 0,
  };

  let processedAssets = [...assets];

  // Step 1: IP-based deduplication
  if (enableIpDedup) {
    const { mergedAssets, ipGroups, mergeCount } = await deduplicateByIp(processedAssets);
    processedAssets = mergedAssets;
    stats.ipGroupsMerged = mergeCount;
    if (mergeCount > 0) {
      const groupDetails = [...ipGroups.entries()]
        .filter(([_, hosts]) => hosts.length > 1)
        .map(([ip, hosts]) => `${ip}: ${hosts.join(', ')}`)
        .join('; ');
      log.push(`[IP Dedup] Merged ${mergeCount} duplicate hostname(s) sharing the same IP: ${groupDetails}`);
    }
  }

  // Step 2: ZAP noise filtering (per asset)
  if (enableZapFilter) {
    let totalZapRemoved = 0;
    for (const asset of processedAssets) {
      const { filtered, removedCount } = filterZapNoise(asset.zapFindings);
      asset.zapFindings = filtered;
      totalZapRemoved += removedCount;
    }
    stats.zapNoiseFiltered = totalZapRemoved;
    if (totalZapRemoved > 0) {
      log.push(`[ZAP Filter] Removed ${totalZapRemoved} noise/duplicate ZAP finding(s) (User Agent Fuzzer, duplicate CSP, CONFIRMED/POTENTIAL overlap)`);
    }
  }

  // Step 3: Multi-tool consolidation (per asset)
  if (enableMultiToolConsolidation) {
    let totalMerged = 0;
    for (const asset of processedAssets) {
      const { consolidated, mergedCount } = consolidateMultiToolFindings(asset.vulns, asset.zapFindings);
      asset.vulns = consolidated;
      totalMerged += mergedCount;
    }
    stats.multiToolMerged = totalMerged;
    if (totalMerged > 0) {
      log.push(`[Multi-Tool] Consolidated ${totalMerged} finding(s) reported by multiple scanners into single entries with combined evidence`);
    }
  }

  // Step 4: Re-scan deduplication
  if (enableRescanDedup && (existingFindings.length > 0 || existingZapFindings.length > 0)) {
    let totalRescanDupes = 0;
    for (const asset of processedAssets) {
      if (existingFindings.length > 0) {
        const { unique, duplicates } = deduplicateOnRescan(existingFindings, asset.vulns);
        asset.vulns = unique;
        totalRescanDupes += duplicates;
      }
      if (existingZapFindings.length > 0) {
        const { unique, duplicates } = deduplicateZapOnRescan(existingZapFindings, asset.zapFindings);
        asset.zapFindings = unique;
        totalRescanDupes += duplicates;
      }
    }
    stats.rescanDuplicatesRemoved = totalRescanDupes;
    if (totalRescanDupes > 0) {
      log.push(`[Re-Scan Dedup] Removed ${totalRescanDupes} finding(s) already present from previous scan run`);
    }
  }

  // Step 5: Cross-host title-based consolidation (for reporting)
  const crossHostResult = consolidateCrossHost(processedAssets);
  stats.crossHostConsolidated = crossHostResult.totalInstances - crossHostResult.consolidatedCount;
  if (crossHostResult.consolidatedCount > 0) {
    log.push(`[Cross-Host] ${crossHostResult.totalInstances} per-endpoint instances consolidated into ${crossHostResult.consolidatedCount} distinct vulnerability types across all hosts`);
  }

  // Calculate final stats
  stats.deduplicatedAssetCount = processedAssets.length;
  stats.deduplicatedVulnCount = processedAssets.reduce((sum, a) => sum + a.vulns.length + a.zapFindings.length, 0);

  const totalReduction = stats.originalVulnCount - stats.deduplicatedVulnCount;
  if (totalReduction > 0) {
    log.push(`[Summary] Total finding reduction: ${stats.originalVulnCount} → ${stats.deduplicatedVulnCount} (${totalReduction} removed, ${Math.round((totalReduction / stats.originalVulnCount) * 100)}% reduction)`);
  }
  log.push(`[Distinct Types] ${crossHostResult.consolidatedCount} unique vulnerability types identified for executive reporting`);

  return { assets: processedAssets, stats, log, distinctVulnTypes: crossHostResult.distinctTypes };
}
