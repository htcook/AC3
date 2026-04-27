/**
 * Finding Normalization Layer
 * 
 * Converts multi-scanner output (Nuclei, ZAP, Burp, OpenVAS, Trivy, Nikto)
 * into a unified NormalizedFinding format with dedup fingerprinting,
 * exploitability metadata, and verification status tracking.
 * 
 * This is the core of the Vulnerability Assessment architecture.
 */

import crypto from 'crypto';

// ─── Verification Status ───────────────────────────────────────────────────────

export type VerificationStatus =
  | 'unverified'              // Scanner reported, not validated (0.3 confidence multiplier)
  | 'configuration_verified'  // Version/config confirmed present (0.85 multiplier)
  | 'behavior_verified'       // Behavioral test confirmed vuln exists without exploitation
  | 'exploit_safe'            // Safe exploitation confirmed impact (0.95 multiplier)
  | 'exploit_full'            // Full exploitation confirmed (1.0 multiplier)
  | 'verification_failed'     // Attempted verification, finding not confirmed
  | 'verification_blocked';   // Cannot verify (firewall, WAF, scope restriction)

export const VERIFICATION_CONFIDENCE_MULTIPLIER: Record<VerificationStatus, number> = {
  unverified: 0.3,
  configuration_verified: 0.85,
  behavior_verified: 0.9,
  exploit_safe: 0.95,
  exploit_full: 1.0,
  verification_failed: 0.0,
  verification_blocked: 0.2,
};

// ─── Scanner Source Types ──────────────────────────────────────────────────────

export type ScannerSource =
  | 'nuclei' | 'zap' | 'burp' | 'openvas' | 'trivy'
  | 'nikto' | 'nmap' | 'sqlmap' | 'commix' | 'xsstrike'
  | 'manual' | 'llm_synthesis';

export interface SourceProvenance {
  scanner: ScannerSource;
  scannerVersion?: string;
  templateId?: string;         // e.g., nuclei template ID
  pluginId?: string;           // e.g., Burp plugin ID, OpenVAS NVT OID
  scanConfig?: string;         // e.g., "full", "light", "compliance"
  scanTimestamp: number;       // UTC ms
  rawOutput?: string;          // truncated raw scanner output (max 4KB)
}

// ─── Exploitability Metadata ───────────────────────────────────────────────────

export interface ExploitabilityMetadata {
  epssScore?: number;          // EPSS probability (0-1)
  epssPercentile?: number;     // EPSS percentile (0-100)
  isKev: boolean;              // CISA Known Exploited Vulnerabilities
  kevDateAdded?: string;       // ISO date when added to KEV
  kevDueDate?: string;         // ISO date for remediation deadline
  hasMetasploitModule: boolean;
  metasploitModuleName?: string;
  hasNucleiTemplate: boolean;
  nucleiTemplateId?: string;
  hasPublicExploit: boolean;
  exploitDbId?: string;
  attackComplexity: 'low' | 'high' | 'unknown';
  privilegesRequired: 'none' | 'low' | 'high' | 'unknown';
  userInteraction: 'none' | 'required' | 'unknown';
}

// ─── Affected Asset ────────────────────────────────────────────────────────────

export interface AffectedAsset {
  hostname: string;
  ip?: string;
  port?: number;
  protocol?: string;           // http, https, ssh, etc.
  service?: string;            // nginx, apache, openssh, etc.
  serviceVersion?: string;
  path?: string;               // URL path where vuln was found
  parameter?: string;          // Specific parameter (for injection vulns)
  component?: string;          // Software component (for dependency vulns)
  componentVersion?: string;
}

// ─── Evidence Chain ────────────────────────────────────────────────────────────

export interface EvidenceItem {
  type: 'request' | 'response' | 'screenshot' | 'log' | 'config' | 'proof_of_concept' | 'reproduction_steps';
  title: string;
  content: string;             // Text content or URL to stored evidence
  timestamp: number;
  capturedBy: ScannerSource | 'operator';
}

// ─── NormalizedFinding ─────────────────────────────────────────────────────────

export interface NormalizedFinding {
  // Identity
  findingId: string;           // Unique ID for this finding instance
  fingerprint: string;         // Dedup hash (vuln identity + affected asset)
  
  // Source provenance
  sources: SourceProvenance[]; // Multiple scanners may confirm same finding
  firstSeen: number;           // UTC ms - earliest detection
  lastSeen: number;            // UTC ms - most recent detection
  
  // Vulnerability identity
  cveIds: string[];            // CVE-YYYY-NNNNN
  cweIds: string[];            // CWE-NNN
  vulnClass: string;           // e.g., "SQL Injection", "XSS", "RCE"
  title: string;               // Human-readable finding title
  description: string;         // Detailed description
  
  // Affected asset
  affectedAsset: AffectedAsset;
  
  // Severity
  cvssVector?: string;         // CVSS 3.1 vector string
  cvssBaseScore?: number;      // 0-10
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  
  // Detection confidence
  detectionMethod: 'version_match' | 'config_check' | 'behavior_test' | 'exploit_confirmed' | 'heuristic';
  detectionConfidence: number; // 0-1
  
  // Verification
  verificationStatus: VerificationStatus;
  verificationHistory: Array<{
    status: VerificationStatus;
    timestamp: number;
    method: string;
    evidence?: string;
  }>;
  
  // Exploitability
  exploitability: ExploitabilityMetadata;
  
  // Evidence chain
  evidence: EvidenceItem[];
  
  // Compliance mapping (populated by framework mapper)
  complianceMappings?: Array<{
    framework: string;
    controlId: string;
    controlTitle: string;
    gapType: 'direct_violation' | 'contributing_weakness' | 'indicator';
  }>;
  
  // Remediation
  remediation?: {
    summary: string;
    steps: string[];
    references: string[];
    estimatedEffort: 'trivial' | 'low' | 'medium' | 'high' | 'complex';
    priority: number;          // 1-5 (1 = fix immediately)
  };
  
  // Corroboration
  corroborationCount: number;  // How many independent sources confirmed
  corroborationTier: 'confirmed' | 'probable' | 'potential';
}

// ─── Dedup Fingerprint Generation ──────────────────────────────────────────────

/**
 * Generate a dedup fingerprint for a finding.
 * Two findings with the same fingerprint represent the same vulnerability
 * on the same asset, even if detected by different scanners.
 */
export function generateFingerprint(params: {
  cveIds?: string[];
  cweIds?: string[];
  vulnClass: string;
  hostname: string;
  port?: number;
  path?: string;
  parameter?: string;
  component?: string;
}): string {
  const parts = [
    // Vulnerability identity
    ...(params.cveIds?.sort() || []),
    ...(params.cweIds?.sort() || []),
    params.vulnClass.toLowerCase().replace(/\s+/g, '_'),
    // Asset identity
    params.hostname.toLowerCase(),
    params.port?.toString() || '',
    params.path?.toLowerCase() || '',
    params.parameter?.toLowerCase() || '',
    params.component?.toLowerCase() || '',
  ].filter(Boolean);
  
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
}

// ─── Severity Inference ────────────────────────────────────────────────────────

export function inferSeverity(cvssScore?: number, scannerSeverity?: string): NormalizedFinding['severity'] {
  if (cvssScore !== undefined) {
    if (cvssScore >= 9.0) return 'critical';
    if (cvssScore >= 7.0) return 'high';
    if (cvssScore >= 4.0) return 'medium';
    if (cvssScore >= 0.1) return 'low';
    return 'info';
  }
  
  if (scannerSeverity) {
    const s = scannerSeverity.toLowerCase();
    if (s === 'critical' || s === 'crit') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'moderate') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
  }
  
  return 'info';
}

// ─── Corroboration Tier ────────────────────────────────────────────────────────

export function inferCorroborationTier(
  sourceCount: number,
  detectionMethod: NormalizedFinding['detectionMethod'],
  verificationStatus: VerificationStatus
): NormalizedFinding['corroborationTier'] {
  // Exploit-confirmed or behavior-verified = always confirmed
  if (verificationStatus === 'exploit_full' || verificationStatus === 'exploit_safe' || verificationStatus === 'behavior_verified') {
    return 'confirmed';
  }
  // Multiple independent sources = confirmed
  if (sourceCount >= 2) return 'confirmed';
  // Config check or version match with single source
  if (detectionMethod === 'config_check' || detectionMethod === 'version_match') {
    return verificationStatus === 'configuration_verified' ? 'confirmed' : 'probable';
  }
  // Heuristic with single source = potential
  if (detectionMethod === 'heuristic') return 'potential';
  // Default
  return 'probable';
}

// ─── Scanner Normalizers ───────────────────────────────────────────────────────

/**
 * Normalize a Nuclei finding into NormalizedFinding format
 */
export function normalizeNucleiFinding(raw: {
  templateId: string;
  info: {
    name: string;
    description?: string;
    severity: string;
    classification?: {
      cve?: string[];
      cwe?: string[];
      cvss_metrics?: string;
      cvss_score?: number;
    };
    tags?: string[];
    reference?: string[];
  };
  host: string;
  matched_at?: string;
  extracted_results?: string[];
  curl_command?: string;
  timestamp?: string;
  matcher_name?: string;
}): NormalizedFinding {
  const now = Date.now();
  const hostname = extractHostname(raw.host);
  const port = extractPort(raw.host);
  const path = extractPath(raw.matched_at || raw.host);
  const cveIds = raw.info.classification?.cve?.filter(Boolean) || [];
  const cweIds = raw.info.classification?.cwe?.map(c => typeof c === 'number' ? `CWE-${c}` : c).filter(Boolean) || [];
  const vulnClass = inferVulnClass(raw.info.name, raw.info.tags || [], cweIds);
  
  const fingerprint = generateFingerprint({
    cveIds, cweIds, vulnClass, hostname, port, path,
  });
  
  const severity = inferSeverity(raw.info.classification?.cvss_score, raw.info.severity);
  
  const evidence: EvidenceItem[] = [];
  if (raw.extracted_results?.length) {
    evidence.push({
      type: 'proof_of_concept',
      title: 'Nuclei Extracted Results',
      content: raw.extracted_results.join('\n'),
      timestamp: now,
      capturedBy: 'nuclei',
    });
  }
  if (raw.curl_command) {
    evidence.push({
      type: 'request',
      title: 'Reproduction cURL Command',
      content: raw.curl_command,
      timestamp: now,
      capturedBy: 'nuclei',
    });
  }
  
  return {
    findingId: crypto.randomUUID(),
    fingerprint,
    sources: [{
      scanner: 'nuclei',
      templateId: raw.templateId,
      scanTimestamp: now,
      rawOutput: JSON.stringify(raw).slice(0, 4000),
    }],
    firstSeen: now,
    lastSeen: now,
    cveIds,
    cweIds,
    vulnClass,
    title: raw.info.name,
    description: raw.info.description || `Nuclei detected: ${raw.info.name}`,
    affectedAsset: {
      hostname,
      port,
      protocol: port === 443 ? 'https' : 'http',
      path,
    },
    cvssVector: raw.info.classification?.cvss_metrics,
    cvssBaseScore: raw.info.classification?.cvss_score,
    severity,
    detectionMethod: inferDetectionMethod(raw.info.tags || [], raw.extracted_results),
    detectionConfidence: severity === 'info' ? 0.5 : 0.7,
    verificationStatus: 'unverified',
    verificationHistory: [{
      status: 'unverified',
      timestamp: now,
      method: `Nuclei template: ${raw.templateId}`,
    }],
    exploitability: {
      isKev: false,
      hasMetasploitModule: false,
      hasNucleiTemplate: true,
      nucleiTemplateId: raw.templateId,
      hasPublicExploit: (raw.info.tags || []).some(t => t === 'exploit' || t === 'rce'),
      attackComplexity: 'unknown',
      privilegesRequired: 'unknown',
      userInteraction: 'unknown',
    },
    evidence,
    corroborationCount: 1,
    corroborationTier: 'probable',
  };
}

/**
 * Normalize a ZAP finding into NormalizedFinding format
 */
export function normalizeZapFinding(raw: {
  alert: string;
  risk: string;
  confidence: string;
  url: string;
  param?: string;
  attack?: string;
  evidence?: string;
  description?: string;
  solution?: string;
  reference?: string;
  cweId?: number;
  wascId?: number;
  pluginId?: string;
  other?: string;
}): NormalizedFinding {
  const now = Date.now();
  const hostname = extractHostname(raw.url);
  const port = extractPort(raw.url);
  const path = extractPath(raw.url);
  const cweIds = raw.cweId ? [`CWE-${raw.cweId}`] : [];
  const vulnClass = inferVulnClass(raw.alert, [], cweIds);
  
  const fingerprint = generateFingerprint({
    cweIds, vulnClass, hostname, port, path, parameter: raw.param,
  });
  
  const severity = inferSeverity(undefined, raw.risk);
  
  const evidence: EvidenceItem[] = [];
  if (raw.attack) {
    evidence.push({
      type: 'proof_of_concept',
      title: 'ZAP Attack Payload',
      content: raw.attack,
      timestamp: now,
      capturedBy: 'zap',
    });
  }
  if (raw.evidence) {
    evidence.push({
      type: 'response',
      title: 'ZAP Evidence',
      content: raw.evidence,
      timestamp: now,
      capturedBy: 'zap',
    });
  }
  
  return {
    findingId: crypto.randomUUID(),
    fingerprint,
    sources: [{
      scanner: 'zap',
      pluginId: raw.pluginId,
      scanTimestamp: now,
      rawOutput: JSON.stringify(raw).slice(0, 4000),
    }],
    firstSeen: now,
    lastSeen: now,
    cveIds: [],
    cweIds,
    vulnClass,
    title: raw.alert,
    description: raw.description || `ZAP detected: ${raw.alert}`,
    affectedAsset: {
      hostname,
      port,
      protocol: port === 443 ? 'https' : 'http',
      path,
      parameter: raw.param,
    },
    severity,
    detectionMethod: raw.attack ? 'behavior_test' : 'heuristic',
    detectionConfidence: mapZapConfidence(raw.confidence),
    verificationStatus: 'unverified',
    verificationHistory: [{
      status: 'unverified',
      timestamp: now,
      method: `ZAP plugin: ${raw.pluginId || 'unknown'}`,
    }],
    exploitability: {
      isKev: false,
      hasMetasploitModule: false,
      hasNucleiTemplate: false,
      hasPublicExploit: false,
      attackComplexity: raw.attack ? 'low' : 'unknown',
      privilegesRequired: 'unknown',
      userInteraction: 'unknown',
    },
    evidence,
    remediation: raw.solution ? {
      summary: raw.solution,
      steps: [raw.solution],
      references: raw.reference ? raw.reference.split('\n').filter(Boolean) : [],
      estimatedEffort: 'medium',
      priority: severity === 'critical' ? 1 : severity === 'high' ? 2 : severity === 'medium' ? 3 : 4,
    } : undefined,
    corroborationCount: 1,
    corroborationTier: raw.confidence === 'High' ? 'probable' : 'potential',
  };
}

/**
 * Normalize a Burp finding into NormalizedFinding format
 */
export function normalizeBurpFinding(raw: {
  name: string;
  severity: string;
  confidence: string;
  host: string;
  path?: string;
  issueType?: number;
  issueBackground?: string;
  remediationBackground?: string;
  issueDetail?: string;
  remediationDetail?: string;
  requestResponse?: Array<{
    request?: string;
    response?: string;
  }>;
  vulnerabilityClassifications?: string[];
}): NormalizedFinding {
  const now = Date.now();
  const hostname = extractHostname(raw.host);
  const port = extractPort(raw.host);
  const cweIds = extractCweFromClassifications(raw.vulnerabilityClassifications || []);
  const vulnClass = inferVulnClass(raw.name, [], cweIds);
  
  const fingerprint = generateFingerprint({
    cweIds, vulnClass, hostname, port, path: raw.path,
  });
  
  const severity = inferSeverity(undefined, raw.severity);
  
  const evidence: EvidenceItem[] = [];
  if (raw.requestResponse?.length) {
    for (const rr of raw.requestResponse.slice(0, 3)) {
      if (rr.request) {
        evidence.push({
          type: 'request',
          title: 'Burp Request',
          content: rr.request.slice(0, 2000),
          timestamp: now,
          capturedBy: 'burp',
        });
      }
      if (rr.response) {
        evidence.push({
          type: 'response',
          title: 'Burp Response',
          content: rr.response.slice(0, 2000),
          timestamp: now,
          capturedBy: 'burp',
        });
      }
    }
  }
  if (raw.issueDetail) {
    evidence.push({
      type: 'log',
      title: 'Burp Issue Detail',
      content: raw.issueDetail,
      timestamp: now,
      capturedBy: 'burp',
    });
  }
  
  return {
    findingId: crypto.randomUUID(),
    fingerprint,
    sources: [{
      scanner: 'burp',
      pluginId: raw.issueType?.toString(),
      scanTimestamp: now,
      rawOutput: JSON.stringify(raw).slice(0, 4000),
    }],
    firstSeen: now,
    lastSeen: now,
    cveIds: [],
    cweIds,
    vulnClass,
    title: raw.name,
    description: raw.issueBackground || `Burp detected: ${raw.name}`,
    affectedAsset: {
      hostname,
      port,
      protocol: port === 443 ? 'https' : 'http',
      path: raw.path,
    },
    severity,
    detectionMethod: raw.confidence === 'Certain' ? 'behavior_test' : 'heuristic',
    detectionConfidence: mapBurpConfidence(raw.confidence),
    verificationStatus: 'unverified',
    verificationHistory: [{
      status: 'unverified',
      timestamp: now,
      method: `Burp issue type: ${raw.issueType || 'unknown'}`,
    }],
    exploitability: {
      isKev: false,
      hasMetasploitModule: false,
      hasNucleiTemplate: false,
      hasPublicExploit: false,
      attackComplexity: 'unknown',
      privilegesRequired: 'unknown',
      userInteraction: 'unknown',
    },
    evidence,
    remediation: raw.remediationBackground ? {
      summary: raw.remediationBackground,
      steps: raw.remediationDetail ? [raw.remediationDetail] : [raw.remediationBackground],
      references: [],
      estimatedEffort: 'medium',
      priority: severity === 'critical' ? 1 : severity === 'high' ? 2 : severity === 'medium' ? 3 : 4,
    } : undefined,
    corroborationCount: 1,
    corroborationTier: raw.confidence === 'Certain' ? 'confirmed' : raw.confidence === 'Firm' ? 'probable' : 'potential',
  };
}

/**
 * Normalize a Trivy finding (container/dependency scan) into NormalizedFinding format
 */
export function normalizeTrivyFinding(raw: {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  References?: string[];
  CVSS?: Record<string, { V3Score?: number; V3Vector?: string }>;
  CweIDs?: string[];
  PrimaryURL?: string;
  Target?: string;           // Container image or filesystem path
}): NormalizedFinding {
  const now = Date.now();
  const cveIds = raw.VulnerabilityID.startsWith('CVE-') ? [raw.VulnerabilityID] : [];
  const cweIds = raw.CweIDs || [];
  const vulnClass = inferVulnClassFromCwe(cweIds) || 'Vulnerable Dependency';
  
  // Extract CVSS from any source
  const cvssEntry = raw.CVSS ? Object.values(raw.CVSS)[0] : undefined;
  const cvssScore = cvssEntry?.V3Score;
  const cvssVector = cvssEntry?.V3Vector;
  
  const hostname = raw.Target || 'container';
  
  const fingerprint = generateFingerprint({
    cveIds, cweIds, vulnClass, hostname,
    component: raw.PkgName,
  });
  
  const severity = inferSeverity(cvssScore, raw.Severity);
  
  return {
    findingId: crypto.randomUUID(),
    fingerprint,
    sources: [{
      scanner: 'trivy',
      scanTimestamp: now,
      rawOutput: JSON.stringify(raw).slice(0, 4000),
    }],
    firstSeen: now,
    lastSeen: now,
    cveIds,
    cweIds,
    vulnClass,
    title: raw.Title || `${raw.VulnerabilityID} in ${raw.PkgName}`,
    description: raw.Description || `Vulnerable package ${raw.PkgName} ${raw.InstalledVersion}`,
    affectedAsset: {
      hostname,
      component: raw.PkgName,
      componentVersion: raw.InstalledVersion,
    },
    cvssVector,
    cvssBaseScore: cvssScore,
    severity,
    detectionMethod: 'version_match',
    detectionConfidence: 0.9, // Version match is high confidence
    verificationStatus: 'configuration_verified',
    verificationHistory: [{
      status: 'configuration_verified',
      timestamp: now,
      method: `Version match: ${raw.PkgName}@${raw.InstalledVersion}`,
    }],
    exploitability: {
      isKev: false,
      hasMetasploitModule: false,
      hasNucleiTemplate: false,
      hasPublicExploit: false,
      attackComplexity: 'unknown',
      privilegesRequired: 'unknown',
      userInteraction: 'unknown',
    },
    evidence: [{
      type: 'config',
      title: 'Package Version',
      content: `Package: ${raw.PkgName}\nInstalled: ${raw.InstalledVersion}\nFixed: ${raw.FixedVersion || 'N/A'}\nTarget: ${raw.Target || 'N/A'}`,
      timestamp: now,
      capturedBy: 'trivy',
    }],
    remediation: raw.FixedVersion ? {
      summary: `Update ${raw.PkgName} from ${raw.InstalledVersion} to ${raw.FixedVersion}`,
      steps: [`Update package ${raw.PkgName} to version ${raw.FixedVersion} or later`],
      references: raw.References || [],
      estimatedEffort: 'low',
      priority: severity === 'critical' ? 1 : severity === 'high' ? 2 : 3,
    } : undefined,
    corroborationCount: 1,
    corroborationTier: 'confirmed', // Version match = confirmed
  };
}

// ─── Finding Deduplication & Merging ───────────────────────────────────────────

/**
 * Merge multiple findings with the same fingerprint into a single corroborated finding.
 * Preserves all source provenance and evidence, picks highest severity/confidence.
 */
export function mergeFindings(findings: NormalizedFinding[]): NormalizedFinding {
  if (findings.length === 0) throw new Error('Cannot merge empty findings array');
  if (findings.length === 1) return findings[0];
  
  // Sort by detection confidence descending
  const sorted = [...findings].sort((a, b) => b.detectionConfidence - a.detectionConfidence);
  const primary = sorted[0];
  
  // Merge all sources
  const allSources: SourceProvenance[] = [];
  const allEvidence: EvidenceItem[] = [];
  const allCveIds = new Set<string>();
  const allCweIds = new Set<string>();
  let earliestSeen = primary.firstSeen;
  let latestSeen = primary.lastSeen;
  
  for (const f of findings) {
    allSources.push(...f.sources);
    allEvidence.push(...f.evidence);
    f.cveIds.forEach(c => allCveIds.add(c));
    f.cweIds.forEach(c => allCweIds.add(c));
    if (f.firstSeen < earliestSeen) earliestSeen = f.firstSeen;
    if (f.lastSeen > latestSeen) latestSeen = f.lastSeen;
  }
  
  // Pick highest severity
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const highestSeverity = findings.reduce((best, f) =>
    (severityOrder[f.severity] || 0) > (severityOrder[best.severity] || 0) ? f : best
  );
  
  // Pick best CVSS
  const bestCvss = findings.reduce((best, f) =>
    (f.cvssBaseScore || 0) > (best.cvssBaseScore || 0) ? f : best
  );
  
  // Unique scanner count for corroboration
  const uniqueScanners = new Set(allSources.map(s => s.scanner));
  const corroborationTier = inferCorroborationTier(
    uniqueScanners.size,
    primary.detectionMethod,
    primary.verificationStatus
  );
  
  return {
    ...primary,
    sources: allSources,
    firstSeen: earliestSeen,
    lastSeen: latestSeen,
    cveIds: Array.from(allCveIds),
    cweIds: Array.from(allCweIds),
    severity: highestSeverity.severity,
    cvssBaseScore: bestCvss.cvssBaseScore,
    cvssVector: bestCvss.cvssVector,
    evidence: allEvidence,
    corroborationCount: uniqueScanners.size,
    corroborationTier,
    // Boost confidence when multiple scanners agree
    detectionConfidence: Math.min(1.0, primary.detectionConfidence + (uniqueScanners.size - 1) * 0.15),
  };
}

/**
 * Deduplicate and merge a list of findings by fingerprint.
 * Returns one NormalizedFinding per unique vulnerability instance.
 */
export function deduplicateFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  const byFingerprint = new Map<string, NormalizedFinding[]>();
  
  for (const f of findings) {
    const existing = byFingerprint.get(f.fingerprint) || [];
    existing.push(f);
    byFingerprint.set(f.fingerprint, existing);
  }
  
  return Array.from(byFingerprint.values()).map(group => mergeFindings(group));
}

// ─── Batch Normalization ───────────────────────────────────────────────────────

export interface BatchNormalizationResult {
  findings: NormalizedFinding[];
  stats: {
    totalRaw: number;
    totalNormalized: number;
    totalDeduplicated: number;
    byScannerRaw: Record<string, number>;
    bySeverity: Record<string, number>;
    byCorroboration: Record<string, number>;
    byVerification: Record<string, number>;
  };
}

/**
 * Normalize and deduplicate findings from multiple scanners in a single batch.
 */
export function batchNormalize(params: {
  nucleiFindings?: Parameters<typeof normalizeNucleiFinding>[0][];
  zapFindings?: Parameters<typeof normalizeZapFinding>[0][];
  burpFindings?: Parameters<typeof normalizeBurpFinding>[0][];
  trivyFindings?: Parameters<typeof normalizeTrivyFinding>[0][];
}): BatchNormalizationResult {
  const allNormalized: NormalizedFinding[] = [];
  const byScannerRaw: Record<string, number> = {};
  
  // Normalize each scanner's findings
  if (params.nucleiFindings?.length) {
    byScannerRaw.nuclei = params.nucleiFindings.length;
    for (const raw of params.nucleiFindings) {
      try {
        allNormalized.push(normalizeNucleiFinding(raw));
      } catch { /* skip malformed */ }
    }
  }
  
  if (params.zapFindings?.length) {
    byScannerRaw.zap = params.zapFindings.length;
    for (const raw of params.zapFindings) {
      try {
        allNormalized.push(normalizeZapFinding(raw));
      } catch { /* skip malformed */ }
    }
  }
  
  if (params.burpFindings?.length) {
    byScannerRaw.burp = params.burpFindings.length;
    for (const raw of params.burpFindings) {
      try {
        allNormalized.push(normalizeBurpFinding(raw));
      } catch { /* skip malformed */ }
    }
  }
  
  if (params.trivyFindings?.length) {
    byScannerRaw.trivy = params.trivyFindings.length;
    for (const raw of params.trivyFindings) {
      try {
        allNormalized.push(normalizeTrivyFinding(raw));
      } catch { /* skip malformed */ }
    }
  }
  
  const totalRaw = Object.values(byScannerRaw).reduce((a, b) => a + b, 0);
  const totalNormalized = allNormalized.length;
  
  // Deduplicate
  const deduplicated = deduplicateFindings(allNormalized);
  
  // Compute stats
  const bySeverity: Record<string, number> = {};
  const byCorroboration: Record<string, number> = {};
  const byVerification: Record<string, number> = {};
  
  for (const f of deduplicated) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCorroboration[f.corroborationTier] = (byCorroboration[f.corroborationTier] || 0) + 1;
    byVerification[f.verificationStatus] = (byVerification[f.verificationStatus] || 0) + 1;
  }
  
  return {
    findings: deduplicated,
    stats: {
      totalRaw,
      totalNormalized,
      totalDeduplicated: deduplicated.length,
      byScannerRaw,
      bySeverity,
      byCorroboration,
      byVerification,
    },
  };
}

// ─── Utility Functions ─────────────────────────────────────────────────────────

function extractHostname(urlOrHost: string): string {
  try {
    if (urlOrHost.includes('://')) {
      const u = new URL(urlOrHost);
      return u.hostname;
    }
    // Handle host:port format
    return urlOrHost.split(':')[0];
  } catch {
    return urlOrHost;
  }
}

function extractPort(urlOrHost: string): number | undefined {
  try {
    if (urlOrHost.includes('://')) {
      const u = new URL(urlOrHost);
      if (u.port) return parseInt(u.port, 10);
      return u.protocol === 'https:' ? 443 : 80;
    }
    const parts = urlOrHost.split(':');
    if (parts.length > 1) {
      const p = parseInt(parts[parts.length - 1], 10);
      if (!isNaN(p)) return p;
    }
  } catch { /* ignore */ }
  return undefined;
}

function extractPath(url: string): string | undefined {
  try {
    if (url.includes('://')) {
      const u = new URL(url);
      return u.pathname !== '/' ? u.pathname : undefined;
    }
  } catch { /* ignore */ }
  return undefined;
}

const VULN_CLASS_PATTERNS: Array<[RegExp, string]> = [
  [/sql.?inject/i, 'SQL Injection'],
  [/xss|cross.?site.?script/i, 'Cross-Site Scripting'],
  [/rce|remote.?code.?exec|command.?inject/i, 'Remote Code Execution'],
  [/ssrf|server.?side.?request/i, 'Server-Side Request Forgery'],
  [/lfi|local.?file.?inclu/i, 'Local File Inclusion'],
  [/rfi|remote.?file.?inclu/i, 'Remote File Inclusion'],
  [/path.?travers|directory.?travers/i, 'Path Traversal'],
  [/xxe|xml.?external/i, 'XML External Entity'],
  [/csrf|cross.?site.?request.?forg/i, 'Cross-Site Request Forgery'],
  [/open.?redirect/i, 'Open Redirect'],
  [/idor|insecure.?direct.?object/i, 'Insecure Direct Object Reference'],
  [/auth.?bypass|broken.?auth/i, 'Authentication Bypass'],
  [/priv.?escal/i, 'Privilege Escalation'],
  [/info.?disclos|info.?leak/i, 'Information Disclosure'],
  [/misconfig/i, 'Security Misconfiguration'],
  [/default.?cred|default.?pass/i, 'Default Credentials'],
  [/weak.?cipher|weak.?ssl|weak.?tls/i, 'Weak Cryptography'],
  [/denial.?of.?service|dos\b/i, 'Denial of Service'],
  [/deseri/i, 'Insecure Deserialization'],
  [/ssti|template.?inject/i, 'Server-Side Template Injection'],
  [/crlf.?inject/i, 'CRLF Injection'],
  [/header.?inject/i, 'HTTP Header Injection'],
  [/cors/i, 'CORS Misconfiguration'],
  [/upload/i, 'Unrestricted File Upload'],
  [/exposed|disclosure|leak/i, 'Information Disclosure'],
];

const CWE_TO_VULN_CLASS: Record<string, string> = {
  'CWE-89': 'SQL Injection',
  'CWE-79': 'Cross-Site Scripting',
  'CWE-78': 'Remote Code Execution',
  'CWE-77': 'Remote Code Execution',
  'CWE-94': 'Remote Code Execution',
  'CWE-918': 'Server-Side Request Forgery',
  'CWE-22': 'Path Traversal',
  'CWE-611': 'XML External Entity',
  'CWE-352': 'Cross-Site Request Forgery',
  'CWE-601': 'Open Redirect',
  'CWE-639': 'Insecure Direct Object Reference',
  'CWE-287': 'Authentication Bypass',
  'CWE-269': 'Privilege Escalation',
  'CWE-200': 'Information Disclosure',
  'CWE-502': 'Insecure Deserialization',
  'CWE-434': 'Unrestricted File Upload',
  'CWE-98': 'Remote File Inclusion',
  'CWE-1321': 'Prototype Pollution',
  'CWE-400': 'Denial of Service',
  'CWE-306': 'Authentication Bypass',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-327': 'Weak Cryptography',
  'CWE-798': 'Default Credentials',
  'CWE-532': 'Information Disclosure',
};

function inferVulnClass(name: string, tags: string[], cweIds: string[]): string {
  // Try CWE mapping first
  for (const cwe of cweIds) {
    if (CWE_TO_VULN_CLASS[cwe]) return CWE_TO_VULN_CLASS[cwe];
  }
  
  // Try name pattern matching
  for (const [pattern, cls] of VULN_CLASS_PATTERNS) {
    if (pattern.test(name)) return cls;
  }
  
  // Try tags
  for (const tag of tags) {
    for (const [pattern, cls] of VULN_CLASS_PATTERNS) {
      if (pattern.test(tag)) return cls;
    }
  }
  
  return 'Unclassified';
}

function inferVulnClassFromCwe(cweIds: string[]): string | undefined {
  for (const cwe of cweIds) {
    if (CWE_TO_VULN_CLASS[cwe]) return CWE_TO_VULN_CLASS[cwe];
  }
  return undefined;
}

function inferDetectionMethod(
  tags: string[],
  extractedResults?: string[]
): NormalizedFinding['detectionMethod'] {
  if (extractedResults?.length) return 'behavior_test';
  if (tags.includes('exploit') || tags.includes('rce')) return 'exploit_confirmed';
  if (tags.includes('config') || tags.includes('misconfiguration')) return 'config_check';
  if (tags.includes('cve') || tags.includes('version')) return 'version_match';
  return 'heuristic';
}

function mapZapConfidence(confidence: string): number {
  switch (confidence) {
    case 'High': return 0.85;
    case 'Medium': return 0.6;
    case 'Low': return 0.35;
    default: return 0.5;
  }
}

function mapBurpConfidence(confidence: string): number {
  switch (confidence) {
    case 'Certain': return 0.95;
    case 'Firm': return 0.75;
    case 'Tentative': return 0.4;
    default: return 0.5;
  }
}

function extractCweFromClassifications(classifications: string[]): string[] {
  const cwes: string[] = [];
  for (const c of classifications) {
    const match = c.match(/CWE-(\d+)/);
    if (match) cwes.push(`CWE-${match[1]}`);
  }
  return cwes;
}
