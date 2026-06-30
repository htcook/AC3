/**
 * Shared Engagement Orchestrator Types
 *
 * Canonical type definitions for the engagement pipeline. All modules
 * (orchestrator, extracted phases, helpers) import types from HERE
 * to avoid circular dependencies.
 *
 * Previously these lived in engagement-orchestrator.ts, creating a
 * circular import when extracted phase modules imported types back
 * from the orchestrator.
 */

// ─── Phase & Status Types ─────────────────────────────────────────────────────

export type OpsPhase =
  | "idle"
  | "recon"                  // Phase 1: Domain Recon (passive OSINT)
  | "passive_discovery"       // Phase 2: Passive Discovery & Enumeration (pre-RoE)
  | "scoping"                 // Phase 3: Scoping & RoE Review
  | "test_plan"               // Phase 4: Test Plan Generation (NIST 800-115 aligned)
  | "test_plan_approval"      // Phase 4b: Customer Test Plan Approval Gate
  | "enumeration"             // Phase 5: Active Discovery & Enumeration (ScanForge, httpx)
  | "vuln_detection"          // Phase 6: Vulnerability Scanning
  | "social_engineering"      // Phase 6b: Social Engineering / Phishing (ROE-gated)
  | "exploitation"            // Phase 7: Penetration Testing / Exploitation
  | "post_exploit"            // Phase 8: Post-Exploitation (Red Team only)
  | "reporting"               // Phase 9: Reporting
  | "completed"
  | "paused"
  | "error";

export type ApprovalStatus = "pending" | "approved" | "denied";

// ─── Core Interfaces ──────────────────────────────────────────────────────────

export interface ApprovalGate {
  id: string;
  phase: OpsPhase;
  riskTier: "yellow" | "orange" | "red";
  title: string;
  description: string;
  target: string;
  module?: string;
  detail: Record<string, any>;
  status: ApprovalStatus;
  createdAt: number;
  resolvedAt?: number;
  resolvedBy?: string;
  /** When true, this gate requires two independent approvers before resolving */
  dualApprovalRequired?: boolean;
  /** Tracks approver IDs for dual-approval gates; gate resolves when length >= requiredApprovals */
  approvers?: string[];
  /** Number of approvals required (1 for normal, 2 for dual-approval) */
  requiredApprovals?: number;
}

export interface OpsLogEntry {
  id: string;
  timestamp: number;
  phase: OpsPhase;
  type: "info" | "scan_start" | "scan_result" | "finding" | "exploit_attempt" |
        "exploit_success" | "exploit_fail" | "approval_request" | "approval_response" |
        "c2_deploy" | "pivot" | "evidence" | "error" | "llm_decision" | "zap_scan" |
        "waf_detected" | "phase_complete" | "tool_match" | "tool_exec" | "warning";
  title: string;
  detail: string;
  data?: Record<string, any>;
  riskTier?: "yellow" | "orange" | "red";
}

/** Structured passive recon data per asset — feeds into LLM scan plan generation */
export interface AssetPassiveRecon {
  subdomains: string[];
  ipAddresses: string[];
  services: Array<{ port: number; protocol: string; service: string; product?: string; version?: string; source: string }>;
  technologies: string[];
  certificates: Array<{ subject: string; issuer?: string; validFrom?: string; validTo?: string }>;
  riskSignals: Array<{ severity: string; type: string; rationale: string }>;
  wafDetected?: string;
  cloudProvider?: string;
  historicalUrls: string[];
  emailSecurity?: { spf: boolean; dkim: boolean; dmarc: boolean; dmarcPolicy?: string };
  breachExposure?: { count: number; sources: string[] };
  dnsRecords?: Record<string, string[]>;
  rawObservationCount: number;
  sources: string[];
}

export interface AssetStatus {
  hostname: string;
  ip?: string;
  type: "web_app" | "server" | "network_device" | "database" | "api" | "unknown";
  ports: Array<{ port: number; service: string; version?: string }>;
  vulns: Array<{
    id: string; severity: string; title: string; cve?: string; description?: string; cvss?: number; cwe?: string; evidence?: string; source?: string;
    /** Evidence quality tier */
    corroborationTier?: 'confirmed' | 'corroborated' | 'unverified';
    /** Human-readable evidence summary */
    evidenceDetail?: string;
    /** Raw tool output or HTTP request/response that proves the vulnerability exists */
    rawEvidence?: string;
  }>;
  /** Passive recon findings deferred until vuln_detection phase — NOT counted as confirmed vulns */
  pendingVulns: Array<{ id: string; severity: string; title: string; cve?: string; corroborationTier?: string; evidenceDetail?: string; detectedVersion?: string; affectedVersions?: string }>;
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{
    module: string;
    success: boolean;
    sessionId?: string;
    cve?: string;
    service?: string;
    port?: number;
    target?: string;
    confidence?: number;
    reasoning?: string;
    selectedExploit?: { modulePath?: string; payload?: string; options?: Record<string, any> };
    timestamp?: number;
    durationMs?: number;
    errorDetail?: string;
    exploitOutput?: string;
    shellType?: string;
    httpEvidence?: {
      request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string };
      response?: { statusCode?: number; headers?: Record<string, string>; body?: string };
    };
    attackPayload?: string;
    technique?: string;
  }>;
  status: "pending" | "scanning" | "enumerated" | "vulns_found" | "exploiting" | "compromised" | "no_vulns" | "discovered";
  wafDetected?: string;
  passiveRecon?: AssetPassiveRecon;
  /** Confirmed working credentials from credential testing */
  confirmedCredentials: Array<{
    username: string;
    password: string;
    service: string;
    port: number;
    protocol: string;
    accessLevel?: string;
    source: string;
    responseSnippet?: string;
    confirmedAt: number;
  }>;
  /** Per-tool execution results stored on the asset */
  toolResults: Array<{
    tool: string;
    command: string;
    exitCode: number;
    durationMs: number;
    timedOut: boolean;
    findingCount: number;
    findings: Array<{
      severity: string; title: string; cve?: string; description?: string; cvss?: number; cwe?: string;
      evidence?: {
        request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string };
        response?: { statusCode?: number; headers?: Record<string, string>; body?: string };
        attackPayload?: string;
        vulnerableParam?: string;
        matchedPattern?: string;
        proofText?: string;
      };
    }>;
    outputPreview: string;
    rawOutput?: string;
    executedAt: number;
    phase: string;
    fingerprints?: {
      webServer?: string;
      technologies?: string[];
      frameworks?: string[];
      operatingSystem?: string;
      serviceVersions?: Array<{ port: number; service: string; product?: string; version?: string; banner?: string }>;
      httpHeaders?: Record<string, string>;
      tlsInfo?: { subjectCN?: string; issuerOrg?: string; notAfter?: string; protocol?: string; cipherSuite?: string };
      cookies?: string[];
      poweredBy?: string;
    };
  }>;
}

export interface AssetScanPlan {
  hostname: string;
  ip?: string;
  assetType: string;
  discoveryFlags: string;
  discoveryRationale: string;
  httpxFlags: string;
  activeTools: Array<{
    tool: string;
    command: string;
    rationale: string;
    priority: number;
  }>;
  riskNotes: string;
  evasionTechniques: string[];
}

export interface ScanPlan {
  generatedAt: number;
  overallStrategy: string;
  discoveryStrategy: string;
  discoveryEvasionProfile: {
    timing: string;
    fragmentation: boolean;
    decoys: boolean;
    randomizeHosts: boolean;
    dataLengthPadding: boolean;
    sourcePortSpoofing: boolean;
    rationale: string;
  };
  assetPlans: AssetScanPlan[];
  estimatedDuration: string;
  riskAssessment: string;
}

/** Manual finding submitted by a pentester */
export interface ManualFinding {
  id: string;
  asset: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss?: number;
  cve?: string;
  cwe?: string;
  description: string;
  stepsToReproduce?: string;
  impact?: string;
  remediation?: string;
  evidence: ManualEvidence[];
  category: string;
  tags: string[];
  submittedBy: string;
  submittedAt: number;
  updatedAt: number;
  status: 'draft' | 'submitted' | 'verified' | 'rejected';
  notes?: string;
}

/** Evidence attachment for a manual finding */
export interface ManualEvidence {
  id: string;
  type: 'screenshot' | 'terminal_output' | 'http_request_response' | 'exploit_code' | 'tool_output' | 'notes' | 'pcap' | 'video' | 'document';
  name: string;
  mimeType: string;
  url?: string;
  fileKey?: string;
  textContent?: string;
  sizeBytes?: number;
  uploadedAt: number;
  caption?: string;
}

// ─── RoE Scope Guard ──────────────────────────────────────────────────────────

export interface RoeScopeGuard {
  authorizedDomains: string[];
  authorizedIps: string[];
  roeStatus: string;
}

// ─── Main State Interface ─────────────────────────────────────────────────────

export interface EngagementOpsState {
  engagementId: number;
  engagementType: "pentest" | "red_team" | "purple_team" | "phishing" | "tabletop";
  phase: OpsPhase;
  progress: number;
  trainingLabMode?: boolean;
  isRunning: boolean;
  isPaused: boolean;
  startedAt?: number;
  completedAt?: number;
  assets: AssetStatus[];
  log: OpsLogEntry[];
  approvalGates: ApprovalGate[];
  llmPlan?: string;
  scanPlan?: ScanPlan;
  currentAction?: string;
  error?: string;
  currentDomain?: string;
  currentDomainStartedAt?: number;
  skippedDomains?: Set<string>;
  passiveReconResults?: Record<string, any>;
  scanProfile?: 'quick' | 'standard' | 'deep' | 'stealth';
  /** ═══ RoE SCOPE GUARD ═══ Hard-enforced authorized target list from engagement RoE */
  roeScopeGuard?: RoeScopeGuard;
  engagementContext?: any;
  dastConfig?: {
    enabled: boolean;
    crawlDepth: number;
    crawlScope: 'strict' | 'subdomain' | 'domain';
    templateCategories: string[];
    timeout: number;
    maxRequests: number;
    rateLimit: number;
    headless: boolean;
    customHeaders?: Record<string, string>;
  };
  exhaustiveExploit?: boolean;
  testPlan?: {
    id: string;
    generatedAt: number;
    status: 'draft' | 'pending_approval' | 'approved' | 'rejected';
    approvedAt?: number;
    approvedBy?: string;
    sections: Array<{ title: string; content: string }>;
    attackVectors: string[];
    dnsAssessment?: any;
    estimatedDuration?: string;
    toolsPlanned?: string[];
  };
  passiveDiscovery?: {
    completedAt?: number;
    subdomains: string[];
    dnsRecords: Record<string, any[]>;
    certificates: any[];
    technologies: string[];
    cloudProviders: string[];
    wafDetected?: string;
    emailAddresses: string[];
    breachExposure: any[];
  };
  dedupStats?: {
    totalFindingsBeforeDedup: number;
    totalFindingsAfterDedup: number;
    duplicatesRemoved: number;
    duplicatesByAsset: Record<string, number>;
    mergeLog: Array<{
      canonicalTitle: string;
      mergedCount: number;
      sources: string[];
    }>;
    normalizedSeverityChanges: number;
    processedAt: number;
  };
  coverageReport?: {
    overallScore: number;
    assetReports: Array<{
      hostname: string;
      score: number;
      gaps: Array<{
        category: string;
        description: string;
        severity: string;
        recommendation: string;
        missingChecks: string[];
      }>;
      totalGaps: number;
      criticalGaps: number;
    }>;
    totalGaps: number;
    criticalGaps: number;
    recommendations: string[];
    processedAt: number;
  };
  targetProfiles?: Record<string, any>;
  manualFindings?: ManualFinding[];
  completedScans?: {
    nucleiCompleted: Set<string>;
    zapCompleted: Set<string>;
    hydraCompleted: Set<string>;
    exploitCompleted: Set<string>;
    katanaCompleted: Set<string>;
    feroxbusterCompleted: Set<string>;
    ffufCompleted: Set<string>;
    testsslCompleted: Set<string>;
    paramDiscoveryCompleted: Set<string>;
    wafw00fCompleted: Set<string>;
    burpCompleted: Set<string>;
    lastCheckpointAt: number;
  };
  bbRoeConfig?: any;
  stats: {
    hostsScanned: number;
    portsFound: number;
    vulnsFound: number;
    exploitsAttempted: number;
    exploitsSucceeded: number;
    sessionsOpened: number;
    zapScansRun: number;
    wafDetections: number;
  };
}

// ─── Utility Functions (pure, no side effects) ────────────────────────────────

/**
 * Check if a hostname/IP is within the RoE scope guard.
 * Pure function — no state mutation, safe to call from any module.
 */
export function isInRoeScope(state: Pick<EngagementOpsState, 'roeScopeGuard'>, hostname: string, ip?: string): boolean {
  const guard = state.roeScopeGuard;
  if (!guard) return true; // No guard = legacy behavior (all assets in scope)
  const normalizedHost = hostname.toLowerCase().trim();
  const normalizedIp = (ip || "").trim();

  // Strip port from hostname for matching (e.g., "159.223.152.190:8443" → "159.223.152.190")
  const hostWithoutPort = normalizedHost.includes(":") ? normalizedHost.split(":")[0] : normalizedHost;

  // Check exact domain match (with and without port)
  if (guard.authorizedDomains.some(d => {
    const nd = d.toLowerCase().trim();
    return nd === normalizedHost || nd === hostWithoutPort;
  })) return true;

  // Check exact IP match (also try stripping port from hostname as IP)
  if (normalizedIp && guard.authorizedIps.some(i => i.trim() === normalizedIp)) return true;

  // If hostname looks like an IP (possibly with port), check against authorizedIps
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostWithoutPort)) {
    if (guard.authorizedIps.some(i => i.trim() === hostWithoutPort)) return true;
  }

  return false;
}

/**
 * Format target display: always show IP alongside hostname when available.
 * Pure function — safe to call from any module.
 */
export function fmtTarget(asset: { hostname: string; ip?: string } | null, fallbackTarget?: string): string {
  if (!asset) return fallbackTarget || 'unknown';
  if (asset.ip && asset.ip !== asset.hostname) return `${asset.hostname} (${asset.ip})`;
  return asset.hostname;
}
