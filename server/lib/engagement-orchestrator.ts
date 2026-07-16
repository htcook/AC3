/**
 * Engagement Orchestrator — LLM-driven autonomous pentest/red team execution engine
 *
 * One-click execution: operator presses "Execute" and the LLM orchestrates the entire
 * engagement pipeline autonomously, pausing only for operator approval on high-risk actions.
 *
 * Phases:
 *   1. Domain Recon (passive OSINT, domain intel)
 *   2. Passive Discovery & Enumeration (DNS, certs, tech fingerprinting — pre-RoE)
 *   3. Scoping & RoE Review (scope validation, RoE checklist)
 *   4. Test Plan Generation (NIST 800-115 aligned, LLM-powered)
 *   4b. Test Plan Approval Gate (customer review)
 *   5. Active Discovery & Enumeration (ScanForge multi-tool discovery)
 *   6. Vulnerability Scanning (nuclei + ZAP for web apps, WAF-aware)
 *   7. Penetration Testing / Exploitation (Metasploit modules, exploitation bridge)
 *   8a. Pentest: per-asset unauthorized access demo → evidence → report
 *   8b. Red Team: C2 agent deploy → Caldera callback → pivot → objectives
 *
 * All actions are gated by RoE scope enforcement and logged to offensive_audit_log.
 */

import { invokeLLM } from "../_core/llm";
import { SCANFORGE_DEDICATED_IP, SCAN_API_KEY } from "./scan-service-url";
import { throttledLLMCall } from "./llm-throttle";
import { buildGobusterCommand, getScanProfile } from "./scan-profiles";
import {
  executePassiveDiscovery,
  executeScopingReview,
  executeTestPlanGeneration,
  executeTestPlanApproval,
  getPipelinePhaseOrder,
} from "./pipeline-phases";
// ═══ LAZY KNOWLEDGE BASE IMPORTS (memory optimization) ═══
// All 17 knowledge modules are loaded on-demand via knowledge-lazy.ts
// to reduce boot-time heap from ~230MB to ~150MB.
import {
  getScanforgeScanPlanContext, getScanforgeVulnCorrelationContext, getScanforgeHuntContext,
  getChainsByVulnDescriptions, formatChainsForPrompt,
  inferAssetContext, formatOntologyForPrompt,
  getBugBountyContext, getTriageSystemPrompt, getTrainingExamplesForPrompt,
  getTriageCorpusContext,
  buildCloudSecurityContext, buildGeneralCloudContext, detectCloudProviders,
  getOwaspScanPlanContext, getOwaspVulnCorrelationContext, getOwaspAssetClassificationContext,
  getThreatGroupScanContext, getThreatGroupVulnContext, getSectorThreatContext, getGroupsByCVE,
  buildOffensiveTechniquesContext, getFirewallEvasionContext, getFileUploadBypassContext,
  getLOTLContext, getShodanReconContext, getSubdomainEnumContext,
  buildZAPKnowledgeContext, getZAPAlertCatalogContext, getTechScanPolicyContext,
  getZAPAuthContext, getZAPReasoningPrompt, getVulnPayloadContext,
  buildToolRecommendationContext, buildAttackPlannerToolContext,
  buildMethodologyContext, buildPhaseToolContext, buildVulnTestingContext, buildScanPlanningContext,
  buildMissedVulnContext, buildMissedVulnAttackContext,
  buildThreatActorLearningContext, buildThreatActorVulnContext,
  scoreEngagementThreatAttribution, clearThreatLearningCache,
  buildSourceSecretsContext, buildCompactSourceSecretsContext,
  lazyFetchKevCatalog, lazyMatchCvesAgainstKev, lazyCalculateKevRiskBoost,
  clearKnowledgeCache,
  buildBurpKnowledgeContext, getBurpScanConfigContext, getBurpAttackProfileContext,
  getBurpCollaboratorContext, getCrossToolCorrelationContext, getBurpReasoningPrompt,
} from "./knowledge-lazy";
// Re-export KEV functions with original names for compatibility
const fetchKevCatalog = lazyFetchKevCatalog;

/**
 * Yield the event loop to prevent starvation during long-running pipeline phases.
 * Call this between CPU-intensive operations to keep the server responsive.
 */
const breathe = (): Promise<void> => new Promise(resolve => setImmediate(resolve));
const matchCvesAgainstKev = lazyMatchCvesAgainstKev;
const calculateKevRiskBoost = lazyCalculateKevRiskBoost;
type KevMatch = any; // Type-only import not needed at runtime
type BugBountyPhase = any; // Type-only import not needed at runtime
import {
  emitExploitFired, emitExploitResult, emitAgentDeployed,
  emitReconComplete, emitSystemNotification, emitSystemAlert,
  eventHub,
} from "./ws-event-hub";
import { onShellObtained } from "./post-exploit-auto-trigger";
import { captureDecision, captureExploitOutcome, updateDecisionOutcome } from "./engagement-training-bridge";
import { lookupCVEProduct, ensureKEVLoaded } from "./cisa-kev-product-map";
import { emitLLMDecision, emitLLMDelegation, emitLLMEngagementProgress } from "./ws-event-hub";
import {
  acquireScanSlot,
  releaseAllForEngagement,
  getScanConcurrencyMetrics,
} from "./scan-concurrency";
import {
  executeToolViaQueue,
  executeRawCommandViaQueue,
  executeToolBatchViaQueue,
  getBridgeStatus,
} from "./job-queue-bridge";
import { retryWithBackoff, isRetryableError } from "./api-resilience";
import { getOwaspTracker, resetOwaspTracker } from "./owasp-coverage-tracker";
import { getSafetyEngine, clearSafetyEngine, type SafetyLevel } from "./safety-engine";
import { validateEngagementTargets, isSourceCodeTarget } from "../../shared/domain-safety-whitelist";
import { captureCalderaEvidence, type CalderaEvidenceSnapshot } from "./caldera-evidence-collector";
import {
  evidenceGate,
  createIntegrityEnvelope,
  buildProvenance,
  recordCustodyEvent,
  sha256 as integrityHash,
  flushChainToDb,
  createAnchor as createIntegrityAnchor,
  type EvidenceSourceTool,
} from "./evidence-integrity-guardrails";
import { validateLLMEvidence, type GuardrailContext } from "./llm-evidence-guardrail";
import { SERVER_INSTANCE_ID } from "./server-instance";
import { capLLMContext as _capLLMContext } from "./memory-manager";
import { enrichPortServices } from "./service-resolver";
import { registerHeartbeatUpdater } from "./do-scan-api";
import { executeScanForgePhase, runPostEngagementAnalysis, type ScanForgeFinding, type ScanForgeResult, type ScanForgeCredential } from "../scanforge/engine/engagement-integration";
import {
  accumulateOutcome as accumulateLearningOutcome,
  classifyVulnClass,
  prioritizeVulns,
  shouldRetry as shouldLearningRetry,
  getLearningStats,
  getPersistedLearningStats,
  hydrateFromDb as hydrateLearningEngine,
  type ExploitOutcome as LearningExploitOutcome,
  classifyVulnClass,
} from "./exploit-learning-engine";

// Cache server instance ID at module level for sync access in getHealthStatus
const _serverInstanceId = SERVER_INSTANCE_ID;

// ─── Types ──────────────────────────────────────────────────────────────────

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
  | "degraded"              // Tool failure rate >50% — engagement results unreliable
  | "paused"
  | "error";

export type ApprovalStatus = "pending" | "approved" | "denied";

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
  /** When true, this gate requires client confirmation — timeout extended to 72h and auto-approval disabled */
  clientConfirmation?: boolean;
  /** When true, timeout is disabled entirely — gate waits indefinitely for manual resolution */
  timeoutDisabled?: boolean;
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
  vulns: Array<{ id: string; severity: string; title: string; cve?: string; description?: string; cvss?: number; cwe?: string; evidence?: string; source?: string;
    /** Evidence quality tier: 'confirmed' = tool output/HTTP capture attached, 'corroborated' = multiple sources agree, 'unverified' = no raw evidence */
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
    /** Evidence fields for exploit attempts */
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
    /** Raw exploit output (stdout/stderr from the exploit execution) */
    exploitOutput?: string;
    /** Type of shell obtained (reverse_shell, bind_shell, web_shell, none) */
    shellType?: string;
    /** HTTP request/response evidence for web-based exploits */
    httpEvidence?: {
      request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string };
      response?: { statusCode?: number; headers?: Record<string, string>; body?: string };
    };
    /** The actual payload/command sent during exploitation */
    attackPayload?: string;
    /** What technique was used (e.g., SQLi, RCE, LFI) */
    technique?: string;
  }>;
  status: "pending" | "scanning" | "enumerated" | "vulns_found" | "exploiting" | "compromised" | "no_vulns" | "discovered";
  wafDetected?: string;
  passiveRecon?: AssetPassiveRecon;
  /** Confirmed working credentials from credential testing (Hydra, HTTP form, etc.) */
  confirmedCredentials: Array<{
    username: string;
    password: string;
    service: string;
    port: number;
    protocol: string;
    accessLevel?: string;
    source: string; // e.g. "hydra", "http_form", "oem_default"
    responseSnippet?: string;
    confirmedAt: number;
  }>;
  /** Per-tool execution results stored on the asset for display and LLM context */
  toolResults: Array<{
    tool: string;
    command: string;
    exitCode: number;
    durationMs: number;
    timedOut: boolean;
    findingCount: number;
    findings: Array<{
      severity: string; title: string; cve?: string; description?: string; cvss?: number; cwe?: string;
      /** Structured evidence captured from tool output */
      evidence?: {
        /** HTTP request that triggered the finding */
        request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string };
        /** HTTP response proving the vulnerability */
        response?: { statusCode?: number; headers?: Record<string, string>; body?: string };
        /** The attack payload or input that was used */
        attackPayload?: string;
        /** The vulnerable parameter name */
        vulnerableParam?: string;
        /** Matched pattern or signature from the scanner */
        matchedPattern?: string;
        /** Raw proof text from scanner output */
        proofText?: string;
      };
    }>;
    outputPreview: string; // first 2KB of stdout
    /** Full raw stdout (up to 50KB) for evidence extraction */
    rawOutput?: string;
    executedAt: number;
    phase: string;
    /** Structured fingerprints extracted from this tool's output */
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

/** Format target display: always show IP alongside hostname when available */
function fmtTarget(asset: { hostname: string; ip?: string } | null, fallbackTarget?: string): string {
  if (!asset) return fallbackTarget || 'unknown';
  if (asset.ip && asset.ip !== asset.hostname) return `${asset.hostname} (${asset.ip})`;
  return asset.hostname;
}

/**
 * Resolve the effective scan target for an asset.
 *
 * When a target is behind a reverse proxy / virtual host (e.g., nginx on the scan server),
 * HTTP-based tools MUST use the hostname so the Host header triggers correct routing.
 * Using the raw IP would hit the default nginx server block (wrong app or 404).
 *
 * Detection: if asset.ip matches a known infrastructure IP (scan server, ScanForge droplet)
 * AND the asset has a hostname, prefer hostname for HTTP tools.
 *
 * For non-HTTP tools (raw TCP, nmap discovery), use `getEffectiveTarget(asset, 'discovery')`
 * which still prefers IP for direct connection.
 */
export const KNOWN_INFRA_IPS = new Set([
  process.env.SCAN_SERVER_HOST || '',
  process.env.SCANFORGE_HOST || '',
  SCANFORGE_DEDICATED_IP,
].filter(Boolean));

export function getEffectiveTarget(
  asset: { hostname: string; ip?: string },
  mode: 'http' | 'discovery' | 'metadata' = 'http'
): string {
  // If no IP resolved, hostname is all we have
  if (!asset.ip) return asset.hostname;
  // If no hostname (IP-only target), use IP
  if (!asset.hostname || asset.hostname === asset.ip) return asset.ip;
  // For HTTP tools: prefer hostname when target is behind a virtual host on infra
  if (mode === 'http' && KNOWN_INFRA_IPS.has(asset.ip)) {
    return asset.hostname;
  }
  // For discovery (nmap, ScanForge port scans): IP is fine, no Host header needed
  if (mode === 'discovery') {
    return asset.ip;
  }
  // For metadata/logging: prefer hostname for readability
  if (mode === 'metadata') {
    return asset.hostname;
  }
  // Default: prefer hostname for safety (HTTP tools are the most common case)
  return asset.hostname;
}

export interface AssetScanPlan {
  hostname: string;
  ip?: string;
  assetType: string;
  /** Phase A: discovery discovery flags — broad port sweep + service fingerprinting with evasion */
  discoveryFlags: string;
  discoveryRationale: string;
  /** httpx flags for HTTP probing on discovered web ports */
  httpxFlags: string;
  /** Phase B: targeted discovery flags — deeper scan based on discovery results */
  discoveryFlags: string;
  discoveryRationale: string;
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
  /** Phase A: global discovery scan strategy with evasion */
  discoveryStrategy: string;
  discoveryEvasionProfile: {
    timing: string; // T0-T5
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
/** Manual finding submitted by a pentester — first-class evidence for report generation */
export interface ManualFinding {
  id: string;
  /** Which asset this finding relates to (hostname or IP) */
  asset: string;
  /** Finding title */
  title: string;
  /** Severity: critical, high, medium, low, info */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS score if applicable */
  cvss?: number;
  /** CVE identifier if applicable */
  cve?: string;
  /** CWE identifier if applicable */
  cwe?: string;
  /** Detailed description of the finding */
  description: string;
  /** Steps to reproduce the vulnerability */
  stepsToReproduce?: string;
  /** Impact assessment */
  impact?: string;
  /** Remediation recommendation */
  remediation?: string;
  /** Evidence attachments — screenshots, terminal output, tool logs, etc. */
  evidence: ManualEvidence[];
  /** Category: web, network, infrastructure, social_engineering, physical, wireless, cloud, mobile, api */
  category: string;
  /** Tags for filtering and grouping */
  tags: string[];
  /** Who submitted this finding */
  submittedBy: string;
  /** When this finding was submitted */
  submittedAt: number;
  /** When this finding was last updated */
  updatedAt: number;
  /** Status: draft, submitted, verified, rejected */
  status: 'draft' | 'submitted' | 'verified' | 'rejected';
  /** Operator notes / narrative context */
  notes?: string;
}

/** Evidence attachment for a manual finding */
export interface ManualEvidence {
  id: string;
  /** Type of evidence */
  type: 'screenshot' | 'terminal_output' | 'http_request_response' | 'exploit_code' | 'tool_output' | 'notes' | 'pcap' | 'video' | 'document';
  /** Display name */
  name: string;
  /** MIME type */
  mimeType: string;
  /** S3 URL for file-based evidence */
  url?: string;
  /** S3 key for file-based evidence */
  fileKey?: string;
  /** Inline text content for terminal output, HTTP req/res, exploit code, notes */
  textContent?: string;
  /** File size in bytes */
  sizeBytes?: number;
  /** When this evidence was uploaded */
  uploadedAt: number;
  /** Caption or description of this evidence */
  caption?: string;
}

export interface EngagementOpsState {
  engagementId: number;
  engagementType: "pentest" | "red_team" | "purple_team" | "phishing" | "tabletop";
  phase: OpsPhase;
  progress: number; // 0-100
  /** When true, auto-approve all gates and enable aggressive scanning (training lab mode) */
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
  /** Currently scanning domain name — used for elapsed timer and skip button */
  currentDomain?: string;
  /** Timestamp when current domain scan started — used for per-domain elapsed timer */
  currentDomainStartedAt?: number;
  /** Set of domains the operator has requested to skip */
  skippedDomains?: Set<string>;
  /** Raw passive recon results keyed by domain — full pipeline output for LLM consumption */
  passiveReconResults?: Record<string, any>;
  /** Selected scan profile for this engagement */
  scanProfile?: 'quick' | 'standard' | 'deep' | 'stealth';
  /** ═══ RoE SCOPE GUARD ═══ Hard-enforced authorized target list from engagement RoE */
  roeScopeGuard?: {
    authorizedDomains: string[];  // exact domains from targetDomain
    authorizedIps: string[];      // exact IPs/CIDRs from targetIpRange
    roeStatus: string;            // signed, pending, etc.
  };
  /** LLM engagement context — built once at pipeline start, shared across all specialist calls */
  engagementContext?: any;
  /** DAST scanning configuration */
  dastConfig?: {
    enabled: boolean;
    crawlDepth: number;       // 1-5, how deep to crawl from root URL
    crawlScope: 'strict' | 'subdomain' | 'domain'; // strict=same path, subdomain=*.target, domain=all subdomains
    templateCategories: string[]; // e.g. ['sqli', 'xss', 'lfi', 'rfi', 'ssrf', 'rce', 'auth-bypass']
    timeout: number;          // per-target timeout in seconds
    maxRequests: number;      // max HTTP requests per target
    rateLimit: number;        // requests per second
    headless: boolean;        // use headless browser for JS-rendered pages
    customHeaders?: Record<string, string>; // custom headers for authenticated scanning
  };
  /** When true, attempt every exploit opportunity across all assets — do not stop at first success */
  exhaustiveExploit?: boolean;
  /** Generated test plan (NIST 800-115 aligned) */
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
  /** Passive discovery results (pre-RoE) */
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
  /** Deduplication stats from the dedup/coverage bridge — populated after vuln detection */
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
  /** Coverage gap report from the dedup/coverage bridge — populated after vuln detection */
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
  /** Context-aware target profiles — built from httpx/ScanForge data for WAF/CDN/topology awareness */
  targetProfiles?: Record<string, import('./context-aware-scanner').TargetProfile>;
  /** Manual findings submitted by pentesters — first-class evidence alongside automated findings */
  manualFindings?: ManualFinding[];
  /** Phase checkpoint tracking — tracks completed scan targets so resume skips them */
  completedScans?: {
    /** Nuclei scan URLs that completed (success or graceful failure) */
    nucleiCompleted: Set<string>;
    /** ZAP scan URLs that completed */
    zapCompleted: Set<string>;
    /** Hydra targets that completed */
    hydraCompleted: Set<string>;
    /** Exploit targets that completed */
    exploitCompleted: Set<string>;
    /** Katana JS crawl targets that completed */
    katanaCompleted: Set<string>;
    /** Feroxbuster content discovery targets that completed */
    feroxbusterCompleted: Set<string>;
    /** ffuf fuzzing targets that completed (vhost + param) */
    ffufCompleted: Set<string>;
    /** testssl.sh TLS scan targets that completed */
    testsslCompleted: Set<string>;
    /** Arjun/ParamSpider parameter discovery targets that completed */
    paramDiscoveryCompleted: Set<string>;
    /** wafw00f WAF detection targets that completed */
    wafw00fCompleted: Set<string>;
    /** Burp scan targets that completed */
    burpCompleted: Set<string>;
    /** Timestamp of last checkpoint */
    lastCheckpointAt: number;
  };
  /** Bug Bounty RoE enforcement config — loaded from program-specific rules at engagement start */
  bbRoeConfig?: import('./bb-roe-enforcement').BugBountyProgramRoE;
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

// ─── In-Memory State Store ──────────────────────────────────────────────────

const opsStates = new Map<number, EngagementOpsState>();

// ═══ CONCURRENT ENGAGEMENT CAPACITY ═══
// Maximum number of engagements that can run simultaneously.
// Each active engagement consumes ~15-30MB of heap for state, logs, and LLM contexts.
// With 1536MB heap, 10 concurrent engagements is the safe ceiling.
export const MAX_CONCURRENT_ENGAGEMENTS = 10;
const approvalResolvers = new Map<string, (approved: boolean) => void>();

let idCounter = 0;
function genId(): string {
  return `ops-${Date.now()}-${++idCounter}`;
}

/**
 * Deduplicated vuln push — prevents duplicate vulnerabilities on the same asset.
 * Deduplicates by matching on (title + cve). When a duplicate is found, MERGES
 * evidence from the new scanner into the existing record (preserving all scanner evidence).
 * Returns true if the vuln was added (new), false if it was merged into an existing record.
 */
export function pushVulnDeduped(
  asset: AssetStatus,
  vuln: { id: string; severity: string; title: string; cve?: string; [key: string]: any },
): boolean {
  const existingVuln = asset.vulns.find((existing: any) => {
    // Match on CVE if both have one
    if (vuln.cve && existing.cve && vuln.cve === existing.cve) return true;
    // Match on normalized title (strip [scanner] prefix for comparison)
    const normExisting = (existing.title || '').replace(/^\[[^\]]+\]\s*/, '').toLowerCase().trim();
    const normNew = (vuln.title || '').replace(/^\[[^\]]+\]\s*/, '').toLowerCase().trim();
    if (normExisting && normNew && normExisting === normNew) return true;
    return false;
  });

  if (existingVuln) {
    // ── MERGE evidence from new scanner into existing record ──
    mergeVulnEvidence(existingVuln as any, vuln);
    return false;
  }

  // Auto-classify vulnClass if not already set
  if (!vuln.vulnClass || vuln.vulnClass === 'unknown') {
    vuln.vulnClass = classifyVulnClass(vuln.title, vuln.description);
  }
  // Initialize scannerEvidence array with the first scanner's data
  if (!vuln.scannerEvidence) {
    vuln.scannerEvidence = [buildScannerEvidenceEntry(vuln)];
  }
  asset.vulns.push(vuln as any);
  return true;
}

/**
 * Extract scanner name from a vuln title prefix like "[nuclei]" or "[ZAP Active]".
 */
function extractScannerFromTitle(title: string): string {
  const match = (title || '').match(/^\[([^\]]+)\]/);
  return match ? match[1].toLowerCase() : (title || '').includes('ZAP') ? 'zap' : 'unknown';
}

/**
 * Build a scanner evidence entry from a vuln record.
 */
function buildScannerEvidenceEntry(vuln: { title?: string; source?: string; evidenceDetail?: string; rawEvidence?: string; corroborationTier?: string; detectedVersion?: string; [key: string]: any }): ScannerEvidenceEntry {
  return {
    scanner: vuln.source || extractScannerFromTitle(vuln.title || ''),
    title: vuln.title || '',
    evidenceDetail: vuln.evidenceDetail || undefined,
    rawEvidence: vuln.rawEvidence || undefined,
    corroborationTier: vuln.corroborationTier || 'unverified',
    detectedVersion: vuln.detectedVersion || undefined,
    timestamp: Date.now(),
  };
}

/**
 * Merge evidence from a new vuln report into an existing vuln record.
 * Preserves ALL scanner evidence while keeping the canonical record enriched.
 */
function mergeVulnEvidence(
  existing: { severity: string; evidenceDetail?: string; rawEvidence?: string; corroborationTier?: string; scannerEvidence?: ScannerEvidenceEntry[]; source?: string; cve?: string; cwe?: string; description?: string; detectedVersion?: string; [key: string]: any },
  incoming: { severity: string; title?: string; evidenceDetail?: string; rawEvidence?: string; corroborationTier?: string; source?: string; cve?: string; cwe?: string; description?: string; detectedVersion?: string; [key: string]: any },
): void {
  // Initialize scannerEvidence array if not present
  if (!existing.scannerEvidence) {
    existing.scannerEvidence = [buildScannerEvidenceEntry(existing)];
  }

  // Add the new scanner's evidence
  const newEntry = buildScannerEvidenceEntry(incoming);
  // Avoid adding duplicate entries from the same scanner with the same evidence
  const alreadyHas = existing.scannerEvidence.some(
    (e) => e.scanner === newEntry.scanner && e.evidenceDetail === newEntry.evidenceDetail
  );
  if (!alreadyHas) {
    existing.scannerEvidence.push(newEntry);
  }

  // Upgrade severity if the new report has a higher severity
  const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  if ((SEVERITY_RANK[incoming.severity?.toLowerCase()] || 0) > (SEVERITY_RANK[existing.severity?.toLowerCase()] || 0)) {
    existing.severity = incoming.severity;
  }

  // Upgrade corroboration tier: multiple scanners = corroborated at minimum
  const TIER_RANK: Record<string, number> = { confirmed: 3, corroborated: 2, unverified: 1 };
  if (existing.scannerEvidence.length >= 2 && (TIER_RANK[existing.corroborationTier || 'unverified'] || 0) < 2) {
    existing.corroborationTier = 'corroborated';
  }
  if ((TIER_RANK[incoming.corroborationTier || 'unverified'] || 0) > (TIER_RANK[existing.corroborationTier || 'unverified'] || 0)) {
    existing.corroborationTier = incoming.corroborationTier;
  }

  // Merge CVE/CWE if the existing record lacks them
  if (!existing.cve && incoming.cve) existing.cve = incoming.cve;
  if (!existing.cwe && incoming.cwe) existing.cwe = incoming.cwe;

  // Merge description (keep longest)
  if (incoming.description && (!existing.description || incoming.description.length > existing.description.length)) {
    existing.description = incoming.description;
  }

  // Merge detected version
  if (!existing.detectedVersion && incoming.detectedVersion) {
    existing.detectedVersion = incoming.detectedVersion;
  }

  // Build combined evidenceDetail from all scanners
  existing.evidenceDetail = existing.scannerEvidence
    .filter(e => e.evidenceDetail)
    .map(e => `[${e.scanner}] ${e.evidenceDetail}`)
    .join(' | ');
}

/** Scanner evidence entry — preserved per-scanner when deduplicating vulns */
export interface ScannerEvidenceEntry {
  scanner: string;
  title: string;
  evidenceDetail?: string;
  rawEvidence?: string;
  corroborationTier: string;
  detectedVersion?: string;
  timestamp: number;
}

/**
 * Merge evidence from a new pending vuln report into an existing pending vuln.
 * Same logic as mergeVulnEvidence but for the simpler pendingVulns shape.
 */
function mergePendingVulnEvidence(
  existing: { severity: string; title?: string; evidenceDetail?: string; corroborationTier?: string; detectedVersion?: string; scannerEvidence?: ScannerEvidenceEntry[]; [key: string]: any },
  incoming: { severity: string; title?: string; evidenceDetail?: string; corroborationTier?: string; detectedVersion?: string; source?: string; [key: string]: any },
): void {
  // Initialize scannerEvidence array if not present
  if (!existing.scannerEvidence) {
    existing.scannerEvidence = [buildScannerEvidenceEntry(existing as any)];
  }

  // Add the new scanner's evidence
  const newEntry = buildScannerEvidenceEntry(incoming as any);
  const alreadyHas = existing.scannerEvidence.some(
    (e) => e.scanner === newEntry.scanner && e.evidenceDetail === newEntry.evidenceDetail
  );
  if (!alreadyHas) {
    existing.scannerEvidence.push(newEntry);
  }

  // Upgrade severity
  const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  if ((SEVERITY_RANK[incoming.severity?.toLowerCase()] || 0) > (SEVERITY_RANK[existing.severity?.toLowerCase()] || 0)) {
    existing.severity = incoming.severity;
  }

  // Upgrade corroboration tier
  const TIER_RANK: Record<string, number> = { confirmed: 3, corroborated: 2, unverified: 1 };
  if (existing.scannerEvidence.length >= 2 && (TIER_RANK[existing.corroborationTier || 'unverified'] || 0) < 2) {
    existing.corroborationTier = 'corroborated';
  }
  if ((TIER_RANK[incoming.corroborationTier || 'unverified'] || 0) > (TIER_RANK[existing.corroborationTier || 'unverified'] || 0)) {
    existing.corroborationTier = incoming.corroborationTier;
  }

  // Merge detected version
  if (!existing.detectedVersion && incoming.detectedVersion) {
    existing.detectedVersion = incoming.detectedVersion;
  }

  // Build combined evidenceDetail from all scanners
  existing.evidenceDetail = existing.scannerEvidence
    .filter(e => e.evidenceDetail)
    .map(e => `[${e.scanner}] ${e.evidenceDetail}`)
    .join(' | ');
}

export function getOpsState(engagementId: number): EngagementOpsState | null {
  return opsStates.get(engagementId) || null;
}

/**
 * Fully clear the in-memory ops state for an engagement.
 * Also removes the DB snapshot so recovery won't restore stale data.
 */
export async function clearOpsState(engagementId: number): Promise<void> {
  opsStates.delete(engagementId);
  const timer = persistTimers.get(engagementId);
  if (timer) { clearTimeout(timer); persistTimers.delete(engagementId); }
  try {
    const { deleteOpsSnapshot } = await import('../db');
    await deleteOpsSnapshot(engagementId);
  } catch (e: any) {
    console.error(`[OpsState] Failed to delete DB snapshot for #${engagementId}:`, e.message);
  }
}

/**
 * Normalize an ops state recovered from DB snapshot.
 * Ensures all required fields exist and rehydrates non-JSON-safe types (e.g., Set).
 * Prevents runtime crashes when snapshots were created before new fields were added.
 */
export function normalizeOpsState(state: any): EngagementOpsState {
  // Ensure required arrays
  if (!Array.isArray(state.assets)) state.assets = [];
  if (!Array.isArray(state.log)) state.log = [];
  if (!Array.isArray(state.approvalGates)) state.approvalGates = [];

  // Ensure stats object with all required fields
  const defaultStats = {
    hostsScanned: 0, portsFound: 0, vulnsFound: 0,
    exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
    zapScansRun: 0, wafDetections: 0,
  };
  state.stats = { ...defaultStats, ...(state.stats || {}) };

  // Rehydrate skippedDomains from JSON (array/object/null → Set)
  if (state.skippedDomains && !(state.skippedDomains instanceof Set)) {
    try {
      const arr = Array.isArray(state.skippedDomains)
        ? state.skippedDomains
        : Object.values(state.skippedDomains);
      state.skippedDomains = new Set(arr);
    } catch {
      state.skippedDomains = new Set();
    }
  } else if (!state.skippedDomains) {
    state.skippedDomains = new Set();
  }

  // Rehydrate completedScans from JSON (arrays → Sets)
  const defaultCompletedScans = {
    nucleiCompleted: new Set<string>(),
    zapCompleted: new Set<string>(),
    hydraCompleted: new Set<string>(),
    exploitCompleted: new Set<string>(),
    katanaCompleted: new Set<string>(),
    feroxbusterCompleted: new Set<string>(),
    ffufCompleted: new Set<string>(),
    testsslCompleted: new Set<string>(),
    paramDiscoveryCompleted: new Set<string>(),
    wafw00fCompleted: new Set<string>(),
    burpCompleted: new Set<string>(),
    lastCheckpointAt: Date.now(),
  };
  if (state.completedScans) {
    for (const key of [
      'nucleiCompleted', 'zapCompleted', 'hydraCompleted', 'exploitCompleted',
      'katanaCompleted', 'feroxbusterCompleted', 'ffufCompleted',
      'testsslCompleted', 'paramDiscoveryCompleted', 'wafw00fCompleted', 'burpCompleted',
    ] as const) {
      const val = (state.completedScans as any)[key];
      if (val && !(val instanceof Set)) {
        try {
          const arr = Array.isArray(val) ? val : Object.values(val);
          (state.completedScans as any)[key] = new Set(arr);
        } catch {
          (state.completedScans as any)[key] = new Set();
        }
      } else if (!val) {
        (state.completedScans as any)[key] = new Set();
      }
    }
    if (typeof state.completedScans.lastCheckpointAt !== 'number') {
      state.completedScans.lastCheckpointAt = Date.now();
    }
  } else {
    state.completedScans = defaultCompletedScans;
  }

  // Ensure boolean fields
  if (typeof state.isRunning !== 'boolean') state.isRunning = false;
  if (typeof state.isPaused !== 'boolean') state.isPaused = false;
  // Preserve trainingLabMode across snapshot round-trips (must stay boolean, not truthy string)
  if (state.trainingLabMode !== undefined && typeof state.trainingLabMode !== 'boolean') {
    state.trainingLabMode = Boolean(state.trainingLabMode);
  }

  // Ensure phase
  if (!state.phase) state.phase = 'idle';

  // Ensure progress
  if (typeof state.progress !== 'number') state.progress = 0;

  // Ensure roeScopeGuard sub-arrays
  if (state.roeScopeGuard) {
    if (!Array.isArray(state.roeScopeGuard.authorizedDomains)) state.roeScopeGuard.authorizedDomains = [];
    if (!Array.isArray(state.roeScopeGuard.authorizedIps)) state.roeScopeGuard.authorizedIps = [];
  }

  // Ensure each asset has required arrays
  for (const asset of state.assets) {
    if (!Array.isArray(asset.vulns)) asset.vulns = [];
    if (!Array.isArray(asset.pendingVulns)) asset.pendingVulns = [];
    if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    if (!Array.isArray(asset.ports)) asset.ports = [];
    if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
    if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
    if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
    // Normalize toolResult sub-fields (findings can become non-iterable after JSON round-trip)
    for (const tr of asset.toolResults) {
      if (tr.findings && !Array.isArray(tr.findings)) {
        try {
          tr.findings = Array.isArray(tr.findings) ? tr.findings : Object.values(tr.findings);
        } catch {
          tr.findings = [];
        }
      } else if (!tr.findings) {
        tr.findings = [];
      }
    }
  }

  // Recalculate portsFound from actual asset port arrays to fix stale stat after snapshot recovery
  const actualPortCount = state.assets.reduce((sum: number, a: any) => sum + (a.ports?.length || 0), 0);
  if (actualPortCount > 0 && state.stats.portsFound === 0) {
    state.stats.portsFound = actualPortCount;
  }

  return state as EngagementOpsState;
}

/**
 * Get ops state with auto-recovery from DB if in-memory state is missing.
 * Use this from API endpoints; the sync version above is for internal pipeline use.
 */
export async function getOpsStateWithRecovery(engagementId: number): Promise<EngagementOpsState | null> {
  const memState = opsStates.get(engagementId);
  if (memState) return normalizeOpsState(memState);

  // Try to recover from DB snapshot
  try {
    const { loadOpsSnapshot } = await import('../db');
    const snapshot = await loadOpsSnapshot(engagementId);
    if (snapshot) {
      const normalized = normalizeOpsState(snapshot);
      console.log(`[OpsState] Recovered state for engagement #${engagementId} from DB snapshot (${normalized.assets?.length || 0} assets, normalized)`);
      opsStates.set(engagementId, normalized);
      return normalized;
    }
  } catch (e: any) {
    console.error(`[OpsState] Failed to recover from DB:`, e.message);
  }
  return null;
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * RoE SCOPE GUARD — Hard enforcement of Rules of Engagement target scope
 * ═══════════════════════════════════════════════════════════════════════════
 * Every target MUST pass this check before any active scanning (ScanForge discovery, nuclei,
 * ZAP, etc.). Passive OSINT can discover assets outside scope, but they are
 * tagged as "out_of_scope" and NEVER actively probed.
 */
export function isInRoeScope(state: EngagementOpsState, hostname: string, ip?: string): boolean {
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
  // Strip CIDR notation from authorizedIps for matching (e.g., "10.0.0.1/32" → "10.0.0.1")
  if (normalizedIp && guard.authorizedIps.some(i => i.trim().replace(/\/\d+$/, '') === normalizedIp)) return true;

  // If hostname looks like an IP (possibly with port), check against authorizedIps
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostWithoutPort)) {
    if (guard.authorizedIps.some(i => i.trim().replace(/\/\d+$/, '') === hostWithoutPort)) return true;
  }

  // Check if hostname is a subdomain of an authorized domain (e.g., sub.target.com matches target.com)
  // DISABLED by default — only exact matches are in scope unless RoE explicitly allows subdomain discovery
  return false;
}

export function initOpsState(engagementId: number, engagementType: string): EngagementOpsState {
  const state: EngagementOpsState = {
    engagementId,
    engagementType: engagementType as any || "pentest",
    phase: "idle",
    progress: 0,
    isRunning: false,
    isPaused: false,
    assets: [],
    log: [],
    approvalGates: [],
    skippedDomains: new Set(),
    completedScans: {
      nucleiCompleted: new Set(),
      zapCompleted: new Set(),
      hydraCompleted: new Set(),
      exploitCompleted: new Set(),
      katanaCompleted: new Set(),
      feroxbusterCompleted: new Set(),
      ffufCompleted: new Set(),
      testsslCompleted: new Set(),
      paramDiscoveryCompleted: new Set(),
      wafw00fCompleted: new Set(),
      burpCompleted: new Set(),
      lastCheckpointAt: Date.now(),
    },
    exhaustiveExploit: true, // Default: attempt every exploit opportunity, don't stop at first success
    stats: {
      hostsScanned: 0, portsFound: 0, vulnsFound: 0,
      exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
      zapScansRun: 0, wafDetections: 0,
    },
  };
  opsStates.set(engagementId, state);
  // Persist initial state to DB
  persistOpsStateDebounced(engagementId);
  return state;
}

// ─── State Persistence ──────────────────────────────────────────────────────
// Debounced persistence to avoid hammering the DB on every log entry
const persistTimers = new Map<number, NodeJS.Timeout>();

// Periodic forced persistence timers — one per active engagement
// These ensure state is saved every 60s even if the debounced persist hasn't fired
const periodicPersistTimers = new Map<number, NodeJS.Timeout>();

export function persistOpsStateDebounced(engagementId: number, delayMs = 2000) {
  const existing = persistTimers.get(engagementId);
  if (existing) clearTimeout(existing);
  persistTimers.set(engagementId, setTimeout(async () => {
    persistTimers.delete(engagementId);
    const state = opsStates.get(engagementId);
    if (!state) return;
    try {
      const { saveOpsSnapshot } = await import('../db');
      await saveOpsSnapshot(engagementId, state);
    } catch (e: any) {
      console.error(`[OpsState] Failed to persist state for #${engagementId}:`, e.message);
    }
  }, delayMs));
}

/** Force-persist state immediately (use before critical transitions) */
export async function persistOpsStateNow(engagementId: number): Promise<void> {
  const existing = persistTimers.get(engagementId);
  if (existing) clearTimeout(existing);
  persistTimers.delete(engagementId);
  const state = opsStates.get(engagementId);
  if (!state) return;
  try {
    const { saveOpsSnapshot } = await import('../db');
    await saveOpsSnapshot(engagementId, state);
  } catch (e: any) {
    console.error(`[OpsState] Failed to force-persist state for #${engagementId}:`, e.message);
  }
}

// ─── Graceful Shutdown ─────────────────────────────────────────────────────

/** Per-engagement abort controllers — used to cancel in-flight operations on shutdown */
const engagementAbortControllers = new Map<number, AbortController>();

/** Get or create an AbortController for an engagement */
export function getEngagementAbortSignal(engagementId: number): AbortSignal {
  let controller = engagementAbortControllers.get(engagementId);
  if (!controller) {
    controller = new AbortController();
    engagementAbortControllers.set(engagementId, controller);
  }
  return controller.signal;
}

/** Abort a specific engagement's in-flight operations */
export function abortEngagement(engagementId: number): void {
  const controller = engagementAbortControllers.get(engagementId);
  if (controller) {
    controller.abort();
    engagementAbortControllers.delete(engagementId);
  }
  // Release any held scan concurrency slots for this engagement
  releaseAllForEngagement(engagementId);
}

// ─── Memory Watchdog ──────────────────────────────────────────────────────────

let memoryWatchdogInterval: NodeJS.Timeout | null = null;

/** Start a memory watchdog that logs warnings and triggers emergency trimming */
export function startMemoryWatchdog() {
  if (memoryWatchdogInterval) return;
  memoryWatchdogInterval = setInterval(async () => {
    const mem = process.memoryUsage();
    const heapMB = mem.heapUsed / 1024 / 1024;
    const rssMB = mem.rss / 1024 / 1024;
    // Auto-detect heap limit from V8 stats (respects --max-old-space-size)
    if (!(global as any).__heapLimitMB) {
      try {
        const v8 = await import('v8');
        const stats = v8.getHeapStatistics();
        (global as any).__heapLimitMB = Math.round(stats.heap_size_limit / 1024 / 1024);
      } catch {
        (global as any).__heapLimitMB = 768;
      }
    }
    const heapLimitMB = (global as any).__heapLimitMB;
    const HEAP_WARNING_MB = heapLimitMB * 0.6;   // ~460MB
    const HEAP_CRITICAL_MB = heapLimitMB * 0.75;  // ~576MB
    const RSS_EMERGENCY_MB = heapLimitMB * 1.3;   // ~1000MB

    const needsAction = heapMB > HEAP_WARNING_MB || rssMB > RSS_EMERGENCY_MB;
    if (needsAction) {
      const level = rssMB > RSS_EMERGENCY_MB ? 'EMERGENCY' : heapMB > HEAP_CRITICAL_MB ? 'CRITICAL' : 'WARNING';
      console.warn(`[MemoryWatchdog] ${level}: ${heapMB.toFixed(0)}MB heap, ${rssMB.toFixed(0)}MB RSS, ${opsStates.size} active states`);

      const isEmergency = rssMB > RSS_EMERGENCY_MB || heapMB > HEAP_CRITICAL_MB;

      for (const [engId, state] of opsStates.entries()) {
        // Evict completed/error engagement states: immediately at CRITICAL+, 60s at WARNING
        const evictAge = isEmergency ? 0 : 60_000;
        if ((state.phase === 'completed' || state.phase === 'error')) {
          const age = state.completedAt ? Date.now() - state.completedAt : Infinity;
          if (age > evictAge) {
            opsStates.delete(engId);
            console.warn(`[MemoryWatchdog] Evicted ${state.phase} engagement #${engId} from memory (age=${Math.round(age/1000)}s)`);
            continue;
          }
        }
        // Also evict idle states that have been sitting for > 5 minutes
        if (!state.isRunning && state.phase === 'idle') {
          opsStates.delete(engId);
          console.warn(`[MemoryWatchdog] Evicted idle engagement #${engId} from memory`);
          continue;
        }

        // Use memory-manager for aggressive eviction at CRITICAL/EMERGENCY level
        if (isEmergency) {
          try {
            const { emergencyEviction, logMemoryProfile } = await import('./memory-manager');
            // Persist to DB first so we don't lose data
            try {
              const { saveOpsSnapshot } = await import('../db');
              await saveOpsSnapshot(engId, state);
            } catch { /* best effort */ }
            const result = emergencyEviction(state);
            console.warn(`[MemoryWatchdog] Emergency eviction for #${engId}: freed ~${(result.freedEstimateBytes / 1024).toFixed(0)}KB, actions: ${result.actions.join(', ')}`);
          } catch (e: any) {
            console.error(`[MemoryWatchdog] Emergency eviction failed for #${engId}:`, e.message);
          }
        } else {
          // WARNING level: moderate trimming
          const maxLogsPerEng = Math.max(20, Math.floor(60 / Math.max(1, opsStates.size)));
          if (state.log.length > maxLogsPerEng) {
            state.log = state.log.slice(-maxLogsPerEng);
          }
          // Trim toolResult outputs
          for (const asset of state.assets) {
            for (const tr of (asset.toolResults || [])) {
              if (tr.outputPreview && tr.outputPreview.length > 256) {
                tr.outputPreview = tr.outputPreview.slice(0, 256) + '...[trimmed]';
              }
              if (tr.findings && tr.findings.length > 10) {
                tr.findings = tr.findings.slice(0, 10);
              }
            }
          }
          // Clear passiveReconResults at WARNING level too
          if ((state as any).passiveReconResults) {
            delete (state as any).passiveReconResults;
          }
          // Clear temporary analysis objects
          for (const key of ['vulnAnalysisSuppressed', 'fpSuppressionStats', 'scanFeedbackLoop', 'cloudDetection']) {
            if ((state as any)[key]) delete (state as any)[key];
          }
        }
      }
      // Clear knowledge module cache at emergency level to free ~80MB
      if (isEmergency) {
        const cleared = clearKnowledgeCache();
        if (cleared > 0) console.warn(`[MemoryWatchdog] Cleared ${cleared} knowledge module caches`);
      }
      // Trigger GC if available (requires --expose-gc flag in NODE_OPTIONS)
      if (global.gc) {
        global.gc();
      }
    }
  }, 10_000); // Check every 10_000ms — Manus container can OOM fast
}

/** Stop the memory watchdog */
export function stopMemoryWatchdog() {
  if (memoryWatchdogInterval) {
    clearInterval(memoryWatchdogInterval);
    memoryWatchdogInterval = null;
  }
}

/** Get health status for the /health endpoint */
export function getHealthStatus() {
  const mem = process.memoryUsage();
  const activeEngagements: Array<{
    id: number;
    phase: string;
    progress: number;
    assets: number;
    logs: number;
  }> = [];
  for (const [engId, state] of opsStates.entries()) {
    activeEngagements.push({
      id: engId,
      phase: state.phase,
      progress: state.progress,
      assets: state.assets.length,
      logs: state.log.length,
    });
  }
  return {
    status: 'ok' as const,
    timestamp: Date.now(),
    uptime: process.uptime(),
    pid: process.pid,
    nodeVersion: process.version,
    serverInstanceId: _serverInstanceId,
    memory: {
      heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
      rssMB: Math.round(mem.rss / 1024 / 1024),
      externalMB: Math.round(mem.external / 1024 / 1024),
      arrayBuffersMB: Math.round((mem.arrayBuffers || 0) / 1024 / 1024),
    },
    memoryWatchdog: {
      running: memoryWatchdogInterval !== null,
      heapLimitMB: (global as any).__heapLimitMB || 768,
      heapWarningThresholdMB: Math.round(((global as any).__heapLimitMB || 768) * 0.6),
      heapCriticalThresholdMB: Math.round(((global as any).__heapLimitMB || 768) * 0.75),
      rssEmergencyThresholdMB: Math.round(((global as any).__heapLimitMB || 768) * 1.3),
    },
    scanConcurrency: getScanConcurrencyMetrics(),
    engagements: {
      activeCount: opsStates.size,
      details: activeEngagements,
    },
  };
}

/**
 * Flush ALL pending debounced state to DB immediately.
 * Call this during graceful shutdown (SIGTERM/SIGINT) to prevent data loss.
 * Returns the number of states flushed.
 */
export async function flushAllPendingState(): Promise<number> {
  // Cancel all debounce timers
  for (const [engId, timer] of persistTimers.entries()) {
    clearTimeout(timer);
    persistTimers.delete(engId);
  }

  // Cancel all periodic persistence timers
  for (const [engId, timer] of periodicPersistTimers.entries()) {
    clearInterval(timer);
    periodicPersistTimers.delete(engId);
  }

  // Force-persist all active states
  const activeEngagements = Array.from(opsStates.entries());
  if (activeEngagements.length === 0) return 0;

  console.log(`[GracefulShutdown] Flushing ${activeEngagements.length} active engagement state(s) to DB...`);
  let flushed = 0;

  try {
    const { saveOpsSnapshot } = await import('../db');
    await Promise.allSettled(
      activeEngagements.map(async ([engId, state]) => {
        try {
          await saveOpsSnapshot(engId, state);
          flushed++;
          console.log(`[GracefulShutdown] Flushed state for engagement #${engId} (phase=${state.phase}, progress=${state.progress}%)`);
        } catch (e: any) {
          console.error(`[GracefulShutdown] Failed to flush state for #${engId}: ${e.message}`);
        }
      })
    );
  } catch (e: any) {
    console.error(`[GracefulShutdown] DB import failed during flush: ${e.message}`);
  }

  // Abort all in-flight engagement operations
  for (const [engId, controller] of engagementAbortControllers.entries()) {
    controller.abort();
    engagementAbortControllers.delete(engId);
  }

  // Release all claim locks so other servers can pick up the engagements
  try {
    const { releaseAllClaims } = await import('./engagement-claim-lock');
    await releaseAllClaims();
  } catch (e: any) {
    console.error(`[GracefulShutdown] Failed to release claim locks: ${e.message}`);
  }

  console.log(`[GracefulShutdown] Flushed ${flushed}/${activeEngagements.length} engagement states`);
  return flushed;
}

// ─── Broadcast helpers ──────────────────────────────────────────────────────

export function broadcastOpsUpdate(engagementId: number, data: Record<string, any>) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:progress_update",
      timestamp: Date.now(),
      engagementId,
      data,
    });
  } catch (e: any) {
    console.error(`[broadcastOpsUpdate] WebSocket broadcast failed for #${engagementId}:`, e.message);
  }
}

/**
 * Emit a recon:finding event for the Ops Viewer live stream.
 * The useOpsViewerLiveStream hook converts these into graph nodes/edges in real-time.
 */
export function broadcastReconFinding(engagementId: number, finding: {
  target?: string; host?: string; ip?: string; domain?: string;
  port?: number; service?: string; protocol?: string;
  vulnerability?: string; cve?: string; templateId?: string; finding?: string;
  severity?: string; subdomain?: string;
  technology?: string; waf?: string; cdn?: string;
  tool?: string;
}) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "recon:finding",
      timestamp: Date.now(),
      engagementId,
      data: finding,
    });
  } catch (e: any) {
    // Non-critical — live stream is best-effort
  }
}

/**
 * Emit a credential:found event for the Ops Viewer live stream.
 */
export function broadcastCredentialFound(engagementId: number, cred: {
  target?: string; host?: string; username?: string; credential?: string; tool?: string;
}) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "credential:found",
      timestamp: Date.now(),
      engagementId,
      data: cred,
    });
  } catch (e: any) { /* best-effort */ }
}

/**
 * Emit an exploit:fired event for the Ops Viewer live stream.
 */
export function broadcastExploitFired(engagementId: number, exploit: {
  target?: string; targetIp?: string; module?: string; exploit?: string;
}) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "exploit:fired",
      timestamp: Date.now(),
      engagementId,
      data: exploit,
    });
  } catch (e: any) { /* best-effort */ }
}

/**
 * Emit an exploit:result event for the Ops Viewer live stream.
 */
export function broadcastExploitResult(engagementId: number, result: {
  target?: string; targetIp?: string; module?: string; success?: boolean;
}) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "exploit:result",
      timestamp: Date.now(),
      engagementId,
      data: result,
    });
  } catch (e: any) { /* best-effort */ }
}

export function addLog(state: EngagementOpsState, entry: Omit<OpsLogEntry, "id" | "timestamp">) {
  // Deduplicate consecutive identical log entries (same title + detail)
  // This prevents ZAP progress spam and other polling loops from flooding the feed
  if (state.log.length > 0) {
    const last = state.log[state.log.length - 1];
    if (last.title === entry.title && last.detail === (entry as any).detail) {
      // Update timestamp on existing entry instead of adding a duplicate
      last.timestamp = Date.now();
      // Still broadcast so the UI sees the updated timestamp
      broadcastOpsUpdate(state.engagementId, { type: "log", entry: last });
      return;
    }
  }
  const logEntry: OpsLogEntry = { id: genId(), timestamp: Date.now(), ...entry };
  state.log.push(logEntry);
  // Memory-aware log trimming: calibrated for Manus container (~384MB max-old-space)
  const heapMB = process.memoryUsage().heapUsed / 1024 / 1024;
  const maxLogs = heapMB > 200 ? 30 : heapMB > 150 ? 50 : heapMB > 100 ? 80 : 150;
  if (state.log.length > maxLogs) state.log = state.log.slice(-maxLogs);
  // Under memory pressure, aggressively trim toolResults outputPreview
  if (heapMB > 120) {
    const outputCap = heapMB > 200 ? 128 : heapMB > 150 ? 256 : 512;
    for (const asset of state.assets) {
      for (const tr of (asset.toolResults || [])) {
        if (tr.outputPreview && tr.outputPreview.length > outputCap) {
          tr.outputPreview = tr.outputPreview.slice(0, outputCap) + '...[trimmed]';
        }
      }
    }
  }
  // Trigger GC periodically when heap is high (every ~50 log entries)
  if (heapMB > 180 && state.log.length % 50 === 0 && global.gc) {
    global.gc();
  }
  broadcastOpsUpdate(state.engagementId, { type: "log", entry: logEntry });
  // Trigger debounced persistence on every log entry
  persistOpsStateDebounced(state.engagementId);

  // ── Auto-persist LLM decisions to llm_decision_log ──
  if (entry.type === 'llm_decision') {
    captureDecision({
      engagementId: state.engagementId,
      phase: entry.phase,
      caller: `engagement-orchestrator.${entry.phase}`,
      decision: entry.title,
      reasoning: entry.detail || '',
      actions: entry.data ? [{ type: 'llm_analysis', params: entry.data }] : [],
      contextSummary: entry.detail?.slice(0, 2000),
      knowledgeModules: [
        'owasp_testing',
        ...(entry.phase === 'vuln_detection' || entry.phase === 'exploitation' ? ['burp_pentesting', 'zap_pentesting', 'cross_tool_intelligence'] : []),
        ...(entry.phase === 'enumeration' ? ['recon_methodology'] : []),
      ],
    }).catch(() => {}); // fire-and-forget

    // Emit WebSocket event for real-time monitor
    emitLLMDecision({
      engagementId: state.engagementId,
      agent: `engagement-orchestrator.${entry.phase}`,
      decisionType: 'analysis',
      action: entry.title,
      confidence: typeof entry.data?.confidence === 'number' ? entry.data.confidence : 0.7,
      stealthScore: entry.data?.stealthScore,
      reasoning: entry.detail?.slice(0, 500) || '',
    });
  }

  // ── Auto-persist timeline events to engagement_timeline_events ──
  const persistableTypes = ['phase_complete', 'scan_result', 'finding', 'exploit_attempt',
    'exploit_success', 'exploit_fail', 'c2_deploy', 'pivot', 'evidence', 'llm_decision',
    'zap_scan', 'waf_detected', 'warning'];
  if (persistableTypes.includes(entry.type)) {
    persistTimelineEvent(state.engagementId, logEntry).catch(() => {});
  }

  // ── Emit engagement progress for phase completions ──
  if (entry.type === 'phase_complete') {
    emitLLMEngagementProgress({
      engagementId: state.engagementId,
      engagementName: `Engagement #${state.engagementId}`,
      target: state.assets?.[0]?.hostname || 'unknown',
      phase: entry.phase,
      progress: entry.phase === 'completed' ? 100 : 50,
      findingsCount: state.stats?.vulnsFound || 0,
      activeAgents: [],
      llmCallsTotal: 0,
    });
  }

  return logEntry;
}

// Map ops log types to timeline event types
const OPS_TO_TIMELINE_TYPE: Record<string, string> = {
  phase_complete: 'phase_completed',
  scan_result: 'scan_completed',
  finding: 'finding_discovered',
  exploit_attempt: 'exploit_attempted',
  exploit_success: 'exploit_succeeded',
  exploit_fail: 'exploit_attempted',
  c2_deploy: 'shell_obtained',
  pivot: 'pivot_established',
  evidence: 'data_collected',
  llm_decision: 'tool_executed',
  zap_scan: 'scan_completed',
  waf_detected: 'opsec_alert',
  warning: 'opsec_alert',
};

const OPS_TO_SEVERITY: Record<string, string> = {
  phase_complete: 'info',
  scan_result: 'info',
  finding: 'medium',
  exploit_attempt: 'high',
  exploit_success: 'critical',
  exploit_fail: 'medium',
  c2_deploy: 'critical',
  pivot: 'critical',
  evidence: 'high',
  llm_decision: 'info',
  zap_scan: 'low',
  waf_detected: 'high',
  warning: 'medium',
};

async function persistTimelineEvent(engagementId: number, logEntry: OpsLogEntry) {
  try {
    const { getDb } = await import('../db');
    const { engagementTimelineEvents } = await import('../../drizzle/schema');
    const db = await getDb();
    const eventType = OPS_TO_TIMELINE_TYPE[logEntry.type] || 'note_added';
    const severity = OPS_TO_SEVERITY[logEntry.type] || 'info';
    await db.insert(engagementTimelineEvents).values({
      engagementId,
      phase: logEntry.phase || 'unknown',
      eventType: eventType as any,
      severity: severity as any,
      title: logEntry.title.slice(0, 512),
      description: logEntry.detail?.slice(0, 2000),
      metadata: logEntry.data || null,
      sourceModule: 'engagement-orchestrator',
      timestamp: logEntry.timestamp,
    });
  } catch (err: any) {
    console.error(`[TimelinePersist] Failed to persist timeline event:`, err.message);
  }
}

// ─── Scan Result Persistence ───────────────────────────────────────────────

export async function persistScanResult(opts: {
  engagementId: number;
  tool: string;
  target: string;
  command: string;
  stdout: string;
  stderr?: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  findings: any[];
  phase: string;
  operatorId?: number;
}) {
  try {
    const { insertScanResult, saveEngagementFindings } = await import("../db");
    const severitySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of opts.findings) {
      const sev = (f.severity || "info").toLowerCase();
      if (sev in severitySummary) severitySummary[sev as keyof typeof severitySummary]++;
    }
    const scanResult = await insertScanResult({
      engagementId: opts.engagementId,
      tool: opts.tool,
      target: opts.target,
      command: opts.command,
      rawOutput: opts.stdout.slice(0, 100_000), // cap at 100KB (reduced from 1MB to prevent OOM)
      rawStderr: (opts.stderr || "").slice(0, 50_000),
      exitCode: opts.exitCode,
      durationMs: opts.durationMs,
      timedOut: opts.timedOut,
      findings: opts.findings,
      findingCount: opts.findings.length,
      severitySummary,
      phase: opts.phase,
      operatorId: opts.operatorId,
    });

    // ── Real-time Finding Promotion ──────────────────────────────────────
    // Promote scan findings to engagement_findings immediately (not just at completion).
    // This ensures findings are visible in the DB and UI as soon as they're discovered.
    if (opts.findings.length > 0) {
      try {
        const resultId = scanResult?.id;
        const findingsToPromote = opts.findings
          .filter((f: any) => f.title || f.name || f.alert || f.template_id)
          .map((f: any) => {
            const sev = (f.severity || f.risk || 'info').toLowerCase();
            const mappedSev = sev === 'moderate' ? 'medium' : (['critical','high','medium','low','info'].includes(sev) ? sev : 'info');
            return {
              engagementId: opts.engagementId,
              resultId,
              title: (f.title || f.name || f.alert || f.template_id || 'Untitled').slice(0, 500),
              severity: mappedSev as 'critical' | 'high' | 'medium' | 'low' | 'info',
              cve: f.cve || f.cve_id || undefined,
              cwe: f.cwe || undefined,
              description: (f.description || f.desc || f.info || '').slice(0, 65000) || undefined,
              endpoint: f.endpoint || f.url || f.matched_at || undefined,
              hostname: f.hostname || f.host || opts.target?.replace(/https?:\/\//, '').split(':')[0] || undefined,
              port: f.port || undefined,
              source: f.source || opts.tool,
              tool: opts.tool,
              corroborationTier: (f.corroborationTier || f.corroboration_tier || 'unverified') as 'confirmed' | 'corroborated' | 'unverified',
              rawEvidence: (f.rawEvidence || f.raw_evidence || f.evidence || f.curl_command || '').slice(0, 65000) || undefined,
              exploitAttempted: !!f.exploit_attempted,
              exploitSucceeded: !!f.exploit_succeeded,
              owaspCategory: f.owasp_category || f.owaspCategory || undefined,
              mitreTechnique: f.mitre_technique || f.mitreTechnique || undefined,
            };
          });
        if (findingsToPromote.length > 0) {
          const promoted = await saveEngagementFindings(findingsToPromote);
          if (promoted > 0) {
            console.log(`[FindingPromotion] Real-time: promoted ${promoted} findings from ${opts.tool} scan on ${opts.target} to engagement_findings`);
          }
        }
      } catch (promoteErr: any) {
        // Non-fatal: findings still exist in scan_results and ops state
        console.error(`[FindingPromotion] Failed to promote ${opts.tool} findings:`, promoteErr.message);
      }
    }
  } catch (e: any) {
    console.error(`[persistScanResult] Failed to save ${opts.tool} result for ${opts.target}:`, e.message);
  }
}

// ─── Approval Gate System ───────────────────────────────────────────────────

/**
 * Auto-approval policy for signed RoE engagements.
 * When RoE is signed, yellow and orange risk actions are auto-approved
 * to prevent the pipeline from blocking indefinitely on each credential test.
 * Red risk actions (destructive exploits, C2 deployment) always require manual approval.
 */
function shouldAutoApprove(state: EngagementOpsState, riskTier: string, gate?: Omit<ApprovalGate, "id" | "status" | "createdAt">): boolean {
  // ── PAUSE OVERRIDE ──
  // If the engagement is explicitly paused by an operator, NEVER auto-approve anything.
  // The operator paused for a reason (e.g., waiting for client confirmation).
  if (state.isPaused && !state.isRunning) return false;

  // ── CLIENT CONFIRMATION GATES ──
  // Gates marked as clientConfirmation NEVER auto-approve — they require explicit
  // client sign-off regardless of training lab mode, precedent, or RoE status.
  if (gate?.clientConfirmation) return false;

  // Training lab mode: auto-approve ALL gates including red tier (exploitation)
  // Training labs are authorized targets where we want the full pipeline to run unattended
  if (state.trainingLabMode === true) return true;

  // ── RED TIER NEVER AUTO-APPROVES (except training lab) ──
  // Exploit execution, C2 deployment, and destructive actions always require manual approval.
  // This check is placed BEFORE precedent to prevent any cascading into red tier.
  if (riskTier === 'red') return false;

  // ── Precedent-based auto-approval (yellow/orange only) ──
  // If the operator has already manually approved a gate at the same risk tier
  // (or higher) in this engagement, auto-approve subsequent gates at that tier.
  // This means: approve one credential test → all credential tests auto-approved.
  // IMPORTANT: Precedent only cascades WITHIN the same tier or from higher to lower.
  // It NEVER escalates (approving yellow does NOT cascade to orange or red).
  const TIER_ORDER: Record<string, number> = { yellow: 0, orange: 1, red: 2 };
  const currentTierIdx = TIER_ORDER[riskTier] ?? -1;
  const hasManualPrecedent = state.approvalGates.some(g =>
    g.status === 'approved' &&
    g.resolvedBy &&
    !g.resolvedBy.startsWith('auto-') && // Must be a real manual approval, not auto-timeout/auto-roe
    (TIER_ORDER[g.riskTier] ?? -1) >= currentTierIdx
  );
  if (hasManualPrecedent) return true;

  // Only auto-approve if RoE is signed (treat 'none'/unset as signed since operator started the engagement)
  const roeStatus = state.roeScopeGuard?.roeStatus;
  if (roeStatus && roeStatus !== 'signed' && roeStatus !== 'none') return false;

  // Yellow and orange tiers are auto-approved for signed RoE
  // This covers: credential testing, enumeration, vulnerability scanning
  return true;
}

export async function requestApproval(
  state: EngagementOpsState,
  gate: Omit<ApprovalGate, "id" | "status" | "createdAt">
): Promise<boolean> {
  // ── Auto-Approval (RoE / Precedent) ──
  // Skip the blocking approval gate when auto-approve conditions are met:
  // 1. Training lab mode (all tiers)
  // 2. Operator already approved a gate at this tier or higher (precedent)
  // 3. Signed RoE for yellow/orange tiers
  if (shouldAutoApprove(state, gate.riskTier, gate)) {
    // Determine the reason for auto-approval for audit trail
    const isTrainingLab = state.trainingLabMode === true;
    const hasPrecedent = !isTrainingLab && state.approvalGates.some(g =>
      g.status === 'approved' && g.resolvedBy && !g.resolvedBy.startsWith('auto-') &&
      ({ yellow: 0, orange: 1, red: 2 }[g.riskTier] ?? -1) >= ({ yellow: 0, orange: 1, red: 2 }[gate.riskTier] ?? -1)
    );
    const autoReason = isTrainingLab ? 'training-lab' : hasPrecedent ? 'operator-precedent' : 'signed-roe';
    const autoLabel = isTrainingLab ? 'Training Lab' : hasPrecedent ? 'Operator Precedent' : 'Signed RoE';

    const approval: ApprovalGate = {
      id: genId(),
      status: "approved",
      createdAt: Date.now(),
      resolvedAt: Date.now(),
      resolvedBy: `auto-approval:${autoReason}`,
      ...gate,
    };
    state.approvalGates.push(approval);

    addLog(state, {
      phase: gate.phase,
      type: "approval_response",
      title: `✅ Auto-Approved (${autoLabel}): ${gate.title}`,
      detail: `${gate.description} — Auto-approved via ${autoLabel.toLowerCase()} (risk tier: ${gate.riskTier}).`,
      data: gate.detail,
      riskTier: gate.riskTier,
    });

    broadcastOpsUpdate(state.engagementId, {
      type: "approval_resolved",
      gateId: approval.id,
      approved: true,
    });

    return true;
  }

  // ── Dual-Approval Check ──
  // When the safety profile requires dual approval (full_exploitation tier),
  // red-tier gates need 2 independent approvers before resolving.
  const safetyEng = getSafetyEngine(state.engagementId);
  const isDualApproval = safetyEng.getProfile().dualApprovalRequired === true && gate.riskTier === 'red';
  const requiredApprovals = isDualApproval ? 2 : 1;

  // ── Manual Approval Gate ──
  const approval: ApprovalGate = {
    id: genId(),
    status: "pending",
    createdAt: Date.now(),
    ...gate,
    dualApprovalRequired: isDualApproval,
    approvers: [],
    requiredApprovals,
  };
  state.approvalGates.push(approval);
  state.isPaused = true;
  state.currentAction = isDualApproval
    ? `⏸ Awaiting dual approval (0/${requiredApprovals}): ${gate.title}`
    : `⏸ Awaiting approval: ${gate.title}`;

  addLog(state, {
    phase: gate.phase,
    type: "approval_request",
    title: isDualApproval
      ? `🔐 Dual Approval Required (0/${requiredApprovals}): ${gate.title}`
      : `🔒 Approval Required: ${gate.title}`,
    detail: isDualApproval
      ? `${gate.description}\n\n⚠️ DUAL-APPROVAL: This red-tier action requires ${requiredApprovals} independent approvers. Each approver must be a distinct operator.`
      : gate.description,
    data: { ...gate.detail, dualApprovalRequired: isDualApproval, requiredApprovals },
    riskTier: gate.riskTier,
  });

  broadcastOpsUpdate(state.engagementId, {
    type: "approval_required",
    gate: approval,
  });

  // Wait for operator response with tier-appropriate timeout:
  // - Red tier / client confirmation / timeoutDisabled: 72 hours (client sign-off may take days)
  // - Yellow/orange: 30 minutes (routine operational gates)
  const isExtendedTimeout = gate.riskTier === 'red' || gate.clientConfirmation || gate.timeoutDisabled;
  const timeoutMs = isExtendedTimeout ? 72 * 60 * 60 * 1000 : 30 * 60 * 1000; // 72h or 30min
  const timeoutLabel = isExtendedTimeout ? '72 hours' : '30 minutes';

  return new Promise<boolean>((resolve) => {
    const timeoutId = setTimeout(() => {
      // On timeout: auto-approve yellow/orange, deny red/clientConfirmation
      const autoDecision = !isExtendedTimeout; // Only auto-approve routine (yellow/orange) gates
      approval.status = autoDecision ? "approved" : "denied";
      approval.resolvedAt = Date.now();
      approval.resolvedBy = `auto-timeout:${autoDecision ? 'approved' : 'denied'}`;
      state.isPaused = false;
      approvalResolvers.delete(approval.id);

      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: autoDecision ? `✅ Auto-Approved (Timeout): ${gate.title}` : `❌ Auto-Denied (Timeout): ${gate.title}`,
        detail: `No operator response after ${timeoutLabel}. ${autoDecision ? 'Auto-approved' : 'Auto-denied'} based on risk tier (${gate.riskTier}).`,
        riskTier: gate.riskTier,
      });

      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: approval.id,
        approved: autoDecision,
      });

      resolve(autoDecision);
    }, timeoutMs);

    approvalResolvers.set(approval.id, (approved) => {
      clearTimeout(timeoutId);
      approval.status = approved ? "approved" : "denied";
      approval.resolvedAt = Date.now();
      state.isPaused = false;

      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: approved ? `✅ Approved: ${gate.title}` : `❌ Denied: ${gate.title}`,
        detail: approved ? "Operator approved the action" : "Operator denied the action",
        riskTier: gate.riskTier,
      });

      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: approval.id,
        approved,
      });

      resolve(approved);
    });
  });
}

/**
 * Rehydrate a stale approval gate by recreating its resolver.
 * When the server restarts or the timeout fires, the in-memory resolver is lost.
 * This function finds the pending gate, creates a new resolver that will:
 * 1. Update the gate status (approved/denied)
 * 2. Unpause the engagement
 * 3. Trigger a resume of the engagement from the phase where it was paused
 *
 * Returns true if the gate was successfully rehydrated, false otherwise.
 */
export function rehydrateApprovalGate(gateId: string): boolean {
  // Don't rehydrate if there's already an active resolver
  if (approvalResolvers.has(gateId)) return true;

  // Find the pending gate across all engagement states
  let matchedGate: ApprovalGate | undefined;
  let matchedState: EngagementOpsState | undefined;
  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find(g => g.id === gateId && g.status === 'pending');
    if (gate) {
      matchedGate = gate;
      matchedState = state;
      break;
    }
  }

  if (!matchedGate || !matchedState) return false;

  const engagementId = matchedState.engagementId;
  const gatePhase = matchedGate.phase;

  // Create a new resolver that handles the approval and triggers engagement resume
  approvalResolvers.set(gateId, (approved: boolean) => {
    if (!matchedGate || !matchedState) return;

    matchedGate.status = approved ? 'approved' : 'denied';
    matchedGate.resolvedAt = Date.now();
    matchedState.isPaused = false;

    addLog(matchedState, {
      phase: gatePhase,
      type: 'approval_response',
      title: approved
        ? `✅ Approved (Rehydrated): ${matchedGate.title}`
        : `❌ Denied (Rehydrated): ${matchedGate.title}`,
      detail: approved
        ? `Operator approved the action after gate rehydration. The engagement will resume from the ${gatePhase} phase.`
        : `Operator denied the action after gate rehydration.`,
      riskTier: matchedGate.riskTier,
    });

    broadcastOpsUpdate(engagementId, {
      type: 'approval_resolved',
      gateId: matchedGate.id,
      approved,
    });

    // Persist the updated state
    persistOpsStateDebounced(engagementId);

    // If approved, trigger a resume of the engagement from the gate's phase
    // This re-enters the pipeline at the point where it was paused
    if (approved && !matchedState.isRunning) {
      // Determine the best phase to resume from
      const validPipelinePhases = new Set(['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit']);
      const resumePhase = validPipelinePhases.has(gatePhase) ? gatePhase : 'recon';

      addLog(matchedState, {
        phase: resumePhase as any,
        type: 'info',
        title: `🔄 Resuming engagement after gate approval`,
        detail: `Engagement resuming from ${resumePhase} phase after stale gate was approved by operator.`,
      });

      // Fire off the execution with resume flag (async, non-blocking)
      executeEngagement(engagementId, { id: 'system', name: 'system-rehydrate' }, {
        startPhase: resumePhase as any,
        resume: true,
      }).catch((err: any) => {
        console.error(`[RehydrateGate] Failed to resume engagement #${engagementId}:`, err.message);
      });
    }
  });

  addLog(matchedState, {
    phase: gatePhase,
    type: 'info',
    title: `🔄 Gate Rehydrated: ${matchedGate.title}`,
    detail: `Approval gate was rehydrated after becoming stale (server restart or timeout). Operator can now approve or deny.`,
    riskTier: matchedGate.riskTier,
  });

  console.log(`[RehydrateGate] Successfully rehydrated gate ${gateId} for engagement #${engagementId} (phase: ${gatePhase})`);
  return true;
}

export function resolveApproval(gateId: string, approved: boolean, resolvedBy?: string): boolean | 'partial' {
  let resolver = approvalResolvers.get(gateId);

  // ── Stale Gate Rehydration ──
  // If no resolver exists (server restarted or timeout cleared it), attempt to
  // rehydrate the gate so the operator can still approve/deny it.
  if (!resolver) {
    const rehydrated = rehydrateApprovalGate(gateId);
    if (!rehydrated) return false;
    resolver = approvalResolvers.get(gateId);
    if (!resolver) return false;
  }

  // Find the gate across all engagement states
  let matchedGate: ApprovalGate | undefined;
  let matchedState: EngagementOpsState | undefined;
  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find(g => g.id === gateId);
    if (gate) {
      matchedGate = gate;
      matchedState = state;
      break;
    }
  }

  // ── Denial always resolves immediately (any single operator can deny) ──
  if (!approved) {
    if (matchedGate) {
      matchedGate.resolvedBy = resolvedBy;
    }
    resolver(false);
    approvalResolvers.delete(gateId);
    return true;
  }

  // ── Dual-Approval Enforcement ──
  if (matchedGate?.dualApprovalRequired && (matchedGate.requiredApprovals || 2) > 1) {
    const approvers = matchedGate.approvers || [];
    const approverId = resolvedBy || 'unknown';

    // Reject duplicate approver — same person cannot approve twice
    if (approvers.includes(approverId)) {
      if (matchedState) {
        addLog(matchedState, {
          phase: matchedGate.phase,
          type: 'warning',
          title: `⚠️ Duplicate Approver Rejected: ${matchedGate.title}`,
          detail: `Operator '${approverId}' already approved this gate. Dual-approval requires ${matchedGate.requiredApprovals} distinct approvers.`,
          riskTier: matchedGate.riskTier,
        });
      }
      return 'partial'; // Signal that the approval was recorded but gate not yet resolved
    }

    approvers.push(approverId);
    matchedGate.approvers = approvers;

    if (approvers.length < (matchedGate.requiredApprovals || 2)) {
      // Not enough approvers yet — log progress and keep gate open
      if (matchedState) {
        matchedState.currentAction = `⏸ Awaiting dual approval (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`;
        addLog(matchedState, {
          phase: matchedGate.phase,
          type: 'approval_response',
          title: `🔐 Partial Approval (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`,
          detail: `Operator '${approverId}' approved. Waiting for ${(matchedGate.requiredApprovals || 2) - approvers.length} more independent approver(s).`,
          riskTier: matchedGate.riskTier,
        });
        broadcastOpsUpdate(matchedState.engagementId, {
          type: 'approval_partial',
          gateId: matchedGate.id,
          approvers: [...approvers],
          requiredApprovals: matchedGate.requiredApprovals,
        });
      }
      return 'partial';
    }

    // All required approvers present — resolve the gate
    matchedGate.resolvedBy = approvers.join(',');
    if (matchedState) {
      addLog(matchedState, {
        phase: matchedGate.phase,
        type: 'approval_response',
        title: `✅ Dual Approval Complete (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`,
        detail: `All ${matchedGate.requiredApprovals} independent approvers confirmed: [${approvers.join(', ')}]. Gate resolved.`,
        riskTier: matchedGate.riskTier,
      });
    }
    resolver(true);
    approvalResolvers.delete(gateId);
    return true;
  }

  // ── Standard single-approval resolution ──
  if (matchedGate) {
    matchedGate.resolvedBy = resolvedBy;
  }
  resolver(true);
  approvalResolvers.delete(gateId);
  return true;
}

/**
 * Dismiss a stale/orphaned approval gate that has no active resolver.
 * This happens when the server restarts while an approval gate was pending —
 * the in-memory resolver is lost but the gate still shows as "pending" in the UI.
 * Marks the gate as denied with a clear audit trail.
 */
export function dismissStaleApproval(gateId: string, resolvedBy?: string): boolean {
  // If there's an active resolver, this isn't stale — use resolveApproval instead
  if (approvalResolvers.has(gateId)) return false;

  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find(g => g.id === gateId && g.status === 'pending');
    if (gate) {
      gate.status = 'denied';
      gate.resolvedAt = Date.now();
      gate.resolvedBy = resolvedBy || 'dismissed:stale-gate';

      // Unpause the engagement if it was paused for this gate
      const hasOtherPending = state.approvalGates.some(g => g.id !== gateId && g.status === 'pending');
      if (!hasOtherPending) {
        state.isPaused = false;
      }

      addLog(state, {
        phase: gate.phase,
        type: 'approval_response',
        title: `🗑️ Dismissed (Stale): ${gate.title}`,
        detail: `Approval gate dismissed — the server restarted while this gate was pending, so the action context was lost. The engagement pipeline will continue without this action.`,
        riskTier: gate.riskTier,
      });

      broadcastOpsUpdate(state.engagementId, {
        type: 'approval_resolved',
        gateId: gate.id,
        approved: false,
      });

      return true;
    }
  }
  return false;
}

/**
 * Dismiss ALL stale pending approval gates for an engagement.
 * Useful after server restart to clear all orphaned gates at once.
 */
export function dismissAllStaleApprovals(engagementId: number, resolvedBy?: string): number {
  const state = opsStates.get(engagementId);
  if (!state) return 0;

  let dismissed = 0;
  const staleGates = state.approvalGates.filter(
    g => g.status === 'pending' && !approvalResolvers.has(g.id)
  );

  for (const gate of staleGates) {
    gate.status = 'denied';
    gate.resolvedAt = Date.now();
    gate.resolvedBy = resolvedBy || 'dismissed:stale-gate-bulk';

    addLog(state, {
      phase: gate.phase,
      type: 'approval_response',
      title: `🗑️ Dismissed (Stale): ${gate.title}`,
      detail: `Stale approval gate auto-dismissed after server restart.`,
      riskTier: gate.riskTier,
    });

    broadcastOpsUpdate(state.engagementId, {
      type: 'approval_resolved',
      gateId: gate.id,
      approved: false,
    });

    dismissed++;
  }

  if (dismissed > 0) {
    state.isPaused = false;
  }

  return dismissed;
}

/**
 * Get the full detail of an approval gate by ID (for plan history persistence).
 * Returns the gate object with its detail, title, etc. or null if not found.
 */
export function getApprovalGateDetail(gateId: string): (typeof opsStates extends Map<any, infer S> ? S extends { approvalGates: (infer G)[] } ? G & { _engagementId?: number } : any : any) | null {
  for (const [engId, state] of opsStates) {
    const gate = state.approvalGates.find(g => g.id === gateId);
    if (gate) {
      // Attach engagement ID for convenience
      (gate as any)._engagementId = engId;
      return gate as any;
    }
  }
  return null;
}

// ─── Audit Logging ──────────────────────────────────────────────────────────

export async function auditLog(params: {
  engagementId: number;
  operatorId: string;
  operatorName?: string;
  actionType: string;
  riskTier: "yellow" | "orange" | "red";
  target: string;
  targetPort?: number;
  moduleOrTool?: string;
  roeStatus?: string;
  actionDetail?: Record<string, any>;
  resultStatus: string;
  resultDetail?: string;
  ipAddress?: string;
}) {
  try {
    const { getDb } = await import("../db");
    const { offensiveAuditLog } = await import("../../drizzle/schema");
    const db = await getDb();
    if (db) {
      await db.insert(offensiveAuditLog).values({
        engagementId: params.engagementId,
        operatorId: params.operatorId,
        operatorName: params.operatorName,
        actionType: params.actionType as any,
        riskTier: params.riskTier,
        target: params.target,
        targetPort: params.targetPort,
        moduleOrTool: params.moduleOrTool,
        roeStatus: params.roeStatus || "in_scope",
        actionDetail: params.actionDetail,
        resultStatus: params.resultStatus as any,
        resultDetail: params.resultDetail,
        ipAddress: params.ipAddress,
      });
    }
  } catch (e) {
    console.warn("[OpsAudit] Failed to write audit log:", e);
  }
}

// ─── LLM Scan Plan Generator ──────────────────────────────────────────────

export async function generateScanPlan(engagementId: number): Promise<ScanPlan> {
  const state = opsStates.get(engagementId);
  if (!state) throw new Error('No ops state found for engagement');
  if (state.assets.length === 0) throw new Error('No assets discovered yet — run passive scan first');

  addLog(state, {
    phase: state.phase,
    type: 'info',
    title: '🧠 LLM Scan Plan Analysis Starting',
    detail: `Analyzing ${state.assets.length} discovered assets to determine optimal ScanForge discovery settings and active scan tools...`,
  });
  broadcastOpsUpdate(engagementId, { type: 'phase_change', phase: 'scan_planning' });

  const assetSummaries = state.assets.map(a => {
    const info: Record<string, any> = {
      hostname: a.hostname,
      ip: a.ip || 'unknown',
      type: a.type,
      status: a.status,
      knownPorts: a.ports.map(p => `${p.port}/${p.service}${p.version ? ` (${p.version})` : ''}`),
      existingVulns: a.vulns.length,
      wafDetected: a.wafDetected || 'none',
    };
    // Enrich with passive recon data if available
    if (a.passiveRecon) {
      const pr = a.passiveRecon;
      if (pr.services.length > 0) {
        info.passiveServices = pr.services.map(s => 
          `${s.port}/${s.protocol} ${s.service}${s.product ? ` (${s.product}${s.version ? ' ' + s.version : ''})` : ''} [source: ${s.source}]`
        );
      }
      if (pr.technologies.length > 0) info.technologies = pr.technologies;
      if (pr.subdomains.length > 0) info.discoveredSubdomains = pr.subdomains.slice(0, 20);
      if (pr.ipAddresses.length > 0) info.resolvedIPs = pr.ipAddresses;
      if (pr.certificates.length > 0) info.certificates = pr.certificates.slice(0, 5).map(c => 
        `${c.subject}${c.issuer ? ` (issued by: ${c.issuer})` : ''}${c.validTo ? ` expires: ${c.validTo}` : ''}`
      );
      if (pr.riskSignals.length > 0) info.passiveRiskSignals = pr.riskSignals.map(s => 
        `[${s.severity}] ${s.type}: ${s.rationale}`
      );
      if (pr.wafDetected) info.wafDetected = pr.wafDetected;
      if (pr.cloudProvider) info.cloudProvider = pr.cloudProvider;
      if (pr.historicalUrls.length > 0) info.historicalUrlCount = pr.historicalUrls.length;
      if (pr.dnsRecords && Object.keys(pr.dnsRecords).length > 0) info.dnsRecords = pr.dnsRecords;
      if (pr.emailSecurity) info.emailSecurity = pr.emailSecurity;
      if (pr.breachExposure) info.breachExposure = pr.breachExposure;
      info.passiveReconSources = pr.sources;
      info.totalPassiveObservations = pr.rawObservationCount;
    }
    // Include any previous tool results
    if (a.toolResults && a.toolResults.length > 0) {
      info.previousToolResults = a.toolResults.map(tr => ({
        tool: tr.tool,
        findingCount: tr.findingCount,
        findings: tr.findings.slice(0, 5).map(f => `[${f.severity}] ${f.title}`),
        phase: tr.phase,
      }));
    }
    return info;
  });

  // Include domain-level passive recon summary for additional context
  const domainReconSummary = state.passiveReconResults ? Object.entries(state.passiveReconResults).map(([domain, data]: [string, any]) => ({
    domain,
    totalAssets: data.totalAssets,
    totalFindings: data.totalFindings,
    overallRiskScore: data.overallRiskScore,
    executiveSummary: data.executiveSummary?.slice(0, 500),
    emailSecurity: data.emailSecurity,
    wafAssessment: data.wafAssessment ? {
      detected: data.wafAssessment.detected,
      vendor: data.wafAssessment.vendor,
      bypassDifficulty: data.wafAssessment.bypassDifficulty,
    } : undefined,
    oemCredentials: (data.oemCredentials || []).slice(0, 10).map((c: any) => ({
      vendor: c.vendor, product: c.product, protocol: c.protocol, port: c.port,
    })),
    connectorStats: (data.connectorStats || []).filter((c: any) => c.observations > 0).map((c: any) => `${c.name}: ${c.observations} obs`),
  })) : [];

  // Compact tool reference — name:purpose only to minimize token count
  const toolRef = [
    'ScanForge Discovery (Masscan/Naabu/RustScan): port scan/service detection',
    'nuclei: vuln scanner (-u URL -severity critical,high,medium -nc -duc -ni -jsonl)',
    'nikto: web server scanner (-h URL)',
    'gobuster: dir brute-forcer (supports -x extensions, -r follow redirects, --random-agent, -b exclude status codes, -m HTTP method, -c cookies for auth scanning)',
    'httpx: HTTP probe (echo URL | httpx -json -tech-detect -status-code -title -follow-redirects)',
    'hydra: credential brute-forcer',
    'enum4linux: SMB/NetBIOS enum',
    'smbclient: SMB share lister',
    'ldapsearch: LDAP enum',
    'dig: DNS queries/zone transfers',
    'onesixtyone: SNMP scanner',
    'subfinder: subdomain discovery (broad scope only)',
    'cloud_enum: multi-cloud resource enum (-k keyword)',
    's3scanner: S3 bucket ACL check (echo bucket | s3scanner scan --json)',
    'trufflehog: secret scanner for buckets',
    'aws: S3 CLI (aws s3 ls s3://bucket --no-sign-request)',
    'gobuster: directory/file brute-force (gobuster dir -u URL -w /opt/SecLists/Discovery/Web-Content/common.txt -t 10 -q --no-error -x php,html,js,txt -r --random-agent)',
    'sqlmap: SQLi exploitation (only confirmed targets)',
    'testssl: TLS/SSL vuln scanner',
    'whatweb: tech fingerprinter',
    'wpscan: WordPress scanner (only when WP detected)',
    'amass: attack surface mapping (amass enum -d domain -passive)',
  ].join('\n');

  // ─── Build tiered prompt for scan plan generation ───────────────────────
  // Tier 1 (essential): asset summaries + domain recon + engagement type
  // Tier 2 (enrichment): knowledge context blocks (ontology, bug bounty, etc.)
  // Strategy: try full prompt first, fallback to Tier 1 only if 403 error

  const systemPrompt = `You are a penetration tester planning active scanning for a ${state.engagementType} engagement after passive OSINT.

PHASE A — Discovery: ScanForge discovery --top-ports 1000 -T3 then httpx on web ports. discoveryFlags = scan type/evasion only (no -p, --top-ports, -T). Cloud/WAF targets: use '-Pn -sV -sC' only, no evasion flags.
PHASE B — Targeted tools per asset based on recon: Web→nuclei,nikto,gobuster,whatweb,testssl; WP→wpscan; SQLi→sqlmap; Cloud→cloud_enum,s3scanner; SMB→enum4linux; LDAP→ldapsearch; DNS→dig; SNMP→onesixtyone; Login→hydra.

GOBUSTER GUIDANCE:
- When a login page is detected, recommend authenticated Gobuster scanning with discovered session cookies (-c flag)
- When a specific tech stack is identified (PHP, ASP.NET, Java), recommend extension enumeration matching that stack (-x php,phtml or -x asp,aspx,ashx or -x jsp,do,action)
- When WAF is detected, recommend status code filtering (-b 403) and reduced thread count (-t 10)
- For API targets, recommend HTTP method enumeration (-m GET,POST,PUT,DELETE)
- Always use --random-agent to avoid WAF fingerprinting of scanner User-Agents

Tools:
${toolRef}

Return valid JSON per the response_format schema.`;

  // Build compact user content — summarize assets as text, not JSON
  const assetLines = assetSummaries.map((a: any) => {
    const parts = [`${a.hostname}${a.ip ? ' ('+a.ip+')' : ''} [${a.type}]`];
    if (a.wafDetected && a.wafDetected !== 'none') parts.push(`WAF:${a.wafDetected}`);
    if (a.cloudProvider) parts.push(`Cloud:${a.cloudProvider}`);
    if (a.ports?.length) parts.push(`Ports:${a.ports.map((p:any) => typeof p === 'object' ? `${p.port}/${p.service||''}` : p).join(',')}`);
    if (a.technologies?.length) parts.push(`Tech:${a.technologies.slice(0,5).join(',')}`);
    if (a.riskSignals?.length) parts.push(`Risks:${a.riskSignals.length}`);
    if (a.toolResults?.length) {
      const tools = a.toolResults.map((t:any) => `${t.tool}(${t.findingCount})`).join(',');
      parts.push(`Scanned:${tools}`);
    }
    return parts.join(' | ');
  }).join('\n');

  const domainLines = domainReconSummary.map((d: any) => {
    const parts = [`${d.domain}: risk=${d.overallRiskScore||'?'}, findings=${d.totalFindings||0}`];
    if (d.wafAssessment?.detected) parts.push(`WAF:${d.wafAssessment.vendor}`);
    if (d.emailSecurity) parts.push(`Email:${JSON.stringify(d.emailSecurity).substring(0,80)}`);
    return parts.join(' | ');
  }).join('\n');

  const tier1Content = `Assets (${state.assets.length}, ${state.engagementType}):\n${assetLines}\n${domainLines ? '\nDomain Intel:\n' + domainLines + '\n' : ''}\nGenerate two-phase scan plan. Phase A: ScanForge discovery --top-ports 1000. Phase B: tools per asset.`;

  // Build Tier 2 enrichment context
  const detectedTech = state.assets.flatMap(a => [
    ...(a.type !== 'unknown' ? [a.type] : []),
    ...a.ports.map((p: any) => p.service).filter(Boolean),
  ]);
  const uniqueTech = [...new Set(detectedTech)];
  const allObs = state.assets.flatMap(a => [
    ...(a.passiveRecon?.technologies || []),
    ...(a.passiveRecon?.riskSignals?.map(r => r.rationale) || []),
    a.passiveRecon?.cloudProvider || '',
  ]).filter(Boolean);

  let enrichmentCtx = '';
  try {
    const ontologyCtx = uniqueTech.length > 0 ? formatOntologyForPrompt(uniqueTech) : '';
    const bbCtx = getTrainingExamplesForPrompt(2);
    const corpusCtx = getTriageCorpusContext(undefined, 2);
    const cloudCtx = allObs.length > 0 ? buildCloudSecurityContext(allObs) : buildGeneralCloudContext();
    const discoveryCtx = getScanforgeScanPlanContext({
      detectedTech: uniqueTech,
      cloudProvider: state.assets.find(a => a.passiveRecon?.cloudProvider)?.passiveRecon?.cloudProvider,
      hasFirewall: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
      hasIDS: state.engagementType === 'red_team',
      stealthRequired: state.engagementType === 'red_team',
    });
    const owaspCtx = getOwaspScanPlanContext(uniqueTech);
    const threatGroupCtx = getThreatGroupScanContext({ technologies: uniqueTech });
    // Build offensive techniques context based on engagement phase
    const offensiveTechCtx = buildOffensiveTechniquesContext({
      phase: 'enumeration',
      hasFirewall: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
      hasWAF: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
      hasFileUpload: uniqueTech.some(t => /upload|file|cms|wordpress|drupal|joomla/i.test(t)),
      includeShodan: true,
    });
    // Build ZAP pentesting knowledge for enumeration (tech-specific scan policies)
    const zapKnowledgeCtx = buildZAPKnowledgeContext({
      phase: 'enumeration',
      technology: uniqueTech[0],
    });
    // Build offensive tools context for the current phase
    const toolsCtx = buildToolRecommendationContext({
      phase: 'enumeration',
      hasWebApp: uniqueTech.some(t => /http|web|html|php|asp|jsp|node|react|angular|vue/i.test(t)),
      hasAPI: uniqueTech.some(t => /api|rest|graphql|json|soap/i.test(t)),
      detectedTech: uniqueTech,
    });
    // Bug bounty methodology context — provides attack methodology and workflow
    const targetPreset = state.assets?.[0]?.hostname?.includes('bwapp') ? 'bwapp'
      : state.assets?.[0]?.hostname?.includes('mutillidae') ? 'mutillidae'
      : state.assets?.[0]?.hostname?.includes('crapi') ? 'crapi'
      : state.assets?.[0]?.hostname?.includes('dvwa') ? 'dvwa'
      : state.assets?.[0]?.hostname?.includes('juice') ? 'juice-shop'
      : state.assets?.[0]?.hostname?.includes('webgoat') ? 'webgoat'
      : state.assets?.[0]?.hostname?.includes('vampi') ? 'vampi'
      : state.assets?.[0]?.hostname?.includes('dvga') ? 'dvga'
      : state.assets?.[0]?.hostname?.includes('brokencrystals') ? 'broken-crystals'
      : undefined;
    const methodologyCtx = buildMethodologyContext(targetPreset);
    const phaseToolCtx = buildPhaseToolContext('enumeration');
    // Build ZAP source code & secrets analysis context
    const sourceSecretsCtx = buildSourceSecretsContext({
      phase: 'enumeration',
      includeSecretPatterns: true,
      includeSourceDisclosure: true,
      includeJSAnalysis: false,
      includeBrowserStorage: false,
      technology: uniqueTech[0],
    });
    // Fetch live threat actor learning data from DO learning engine
    let threatActorLearningCtx = '';
    try {
      threatActorLearningCtx = await buildThreatActorLearningContext();
    } catch (e) {
      console.warn('[ScanPlan] Failed to build threat actor learning context:', e);
    }
    // Injection tools knowledge (Commix, tplmap advanced guides)
    let injectionToolsCtx = '';
    try {
      const { buildInjectionToolContext } = await import('./knowledge/injection-tools-knowledge');
      injectionToolsCtx = buildInjectionToolContext();
    } catch (e) {
      console.warn('[ScanPlan] Failed to build injection tools context:', e);
    }
    // WAF-adaptive tool guidance — maps WAF vendor to specific tool flags
    let wafAdaptiveCtx = '';
    try {
      const detectedWAFs = state.assets
        .filter(a => a.wafDetected && a.wafDetected !== 'none')
        .map(a => ({ host: a.hostname, waf: a.wafDetected }));
      if (detectedWAFs.length > 0) {
        const wafSections: string[] = ['## WAF-Adaptive Tool Configuration\n'];
        for (const { host, waf } of detectedWAFs) {
          const wafLower = (waf || '').toLowerCase();
          wafSections.push(`### ${host} — ${waf} WAF Detected`);
          wafSections.push('**General evasion:**');
          wafSections.push('- Add random delays: `--delay 2 --random-agent`');
          wafSections.push('- Use encoding: URL-encode payloads, double-encode for strict WAFs');
          wafSections.push('- Fragment requests: use chunked transfer encoding');
          if (/cloudflare/i.test(wafLower)) {
            wafSections.push('**Cloudflare-specific:**');
            wafSections.push('- SQLMap: `--tamper=between,randomcase,space2comment --random-agent --delay=3`');
            wafSections.push('- Nuclei: `-rl 5 -c 2 -H "Cache-Control: no-transform"` (rate limit to 5 req/s)');
            wafSections.push('- Commix: `--tamper=base64encode --delay=2 --random-agent`');
            wafSections.push('- XSS: Use DOM-based vectors, avoid `<script>` tags, use event handlers');
            wafSections.push('- Bypass: Try origin IP via DNS history, check for direct IP access');
          } else if (/akamai/i.test(wafLower)) {
            wafSections.push('**Akamai-specific:**');
            wafSections.push('- SQLMap: `--tamper=charencode,between --random-agent --delay=5`');
            wafSections.push('- Nuclei: `-rl 3 -c 1` (very aggressive rate limiting)');
            wafSections.push('- Use HTTP/2 where possible, Akamai blocks HTTP/1.0');
            wafSections.push('- Avoid common scanner User-Agents (nikto, sqlmap default)');
          } else if (/aws|shield|waf/i.test(wafLower)) {
            wafSections.push('**AWS WAF-specific:**');
            wafSections.push('- SQLMap: `--tamper=space2comment,randomcase --random-agent`');
            wafSections.push('- Use case variation and comment injection for SQL bypass');
            wafSections.push('- Check for WAF rule groups: SQLi, XSS, LFI are separate rule sets');
          } else if (/imperva|incapsula/i.test(wafLower)) {
            wafSections.push('**Imperva-specific:**');
            wafSections.push('- SQLMap: `--tamper=apostrophemask,equaltolike --delay=3`');
            wafSections.push('- Rotate User-Agents per request');
            wafSections.push('- Use HPP (HTTP Parameter Pollution) for bypass');
          } else if (/f5|big.?ip/i.test(wafLower)) {
            wafSections.push('**F5 BIG-IP-specific:**');
            wafSections.push('- SQLMap: `--tamper=space2mssqlblank,charencode`');
            wafSections.push('- Check for ASM vs Advanced WAF (different bypass techniques)');
          } else {
            wafSections.push('**Generic WAF bypass:**');
            wafSections.push('- Try all tamper scripts: `--tamper=apostrophemask,between,randomcase`');
            wafSections.push('- Use alternative encoding (Unicode, hex, double-URL)');
            wafSections.push('- Test with different HTTP methods (GET vs POST vs PUT)');
          }
          wafSections.push('');
        }
        wafAdaptiveCtx = wafSections.join('\n');
      }
    } catch (e) {
      console.warn('[ScanPlan] Failed to build WAF adaptive context:', e);
    }
    // Tool availability tracking — use comprehensive inventory + failed-tool exclusion
    let toolAvailabilityCtx = '';
    try {
      // Get comprehensive tool inventory from scan server
      const { getToolInventory, getInventoryForLLM } = await import('./scan-server-inventory');
      const inventory = await getToolInventory();
      if (inventory.serverReachable) {
        toolAvailabilityCtx = '## Scan Server Tool Inventory\n' + getInventoryForLLM(inventory);
      }
      // Also append tools that failed in previous phases (runtime failures)
      const failedTools = new Set<string>();
      for (const asset of state.assets) {
        for (const tr of (asset.toolResults || [])) {
          if (tr.outputPreview && /command not found|not installed|No such file|ENOENT/i.test(tr.outputPreview)) {
            failedTools.add(tr.tool);
          }
        }
      }
      if (failedTools.size > 0) {
        toolAvailabilityCtx += `\n\n## Runtime Tool Failures\n**The following tools FAILED during this engagement — do NOT recommend them:**\n${[...failedTools].map(t => `- ${t} (runtime failure)`).join('\n')}\n\nUse alternative tools instead.`;
      }
    } catch (e) {
      console.warn('[ScanPlan] Failed to build tool availability context:', e);
    }
    // Banking domain knowledge injection
    let bankingCtx = '';
    try {
      const inferredSector = state.engagementContext?.inferredSector || '';
      if (inferredSector === 'banking_financial_services' || state.assets.some(a => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname))) {
        const { buildBankingDomainContext } = await import('./llm-specialists/banking-domain-knowledge');
        bankingCtx = buildBankingDomainContext({ phase: 'enumeration', includeRegulatory: true, includeTechStack: true });
        console.log('[ScanPlan] Banking domain knowledge injected');
      }
    } catch (e) {
      console.warn('[ScanPlan] Failed to build banking context:', e);
    }
    // Use capLLMContext to prevent multi-MB prompt accumulation (memory optimization)
    const { capLLMContext } = await import('./memory-manager');
    // Assemble all context blocks for the scan planning decision
    const _scanPlanContextBlocks: Array<{ label: string; content: string }> = [
      { label: 'banking', content: bankingCtx || '' },
      { label: 'ontology', content: ontologyCtx ? '## Asset Architecture Context\n' + ontologyCtx : '' },
      { label: 'bugbounty', content: bbCtx ? '## Bug Bounty Methodology\n' + bbCtx : '' },
      { label: 'triage', content: corpusCtx ? '## Triage Examples\n' + corpusCtx : '' },
      { label: 'cloud', content: cloudCtx || '' },
      { label: 'scanforge-discovery', content: discoveryCtx || '' },
      { label: 'owasp', content: owaspCtx || '' },
      { label: 'threatGroup', content: threatGroupCtx || '' },
      { label: 'threatActor', content: threatActorLearningCtx || '' },
      { label: 'offensive', content: offensiveTechCtx || '' },
      { label: 'zap', content: zapKnowledgeCtx || '' },
      { label: 'burp', content: buildBurpKnowledgeContext({ phase: 'enumeration', technology: uniqueTech[0], includeAttackProfiles: true, includeCrossToolCorrelation: true }) },
      { label: 'secrets', content: sourceSecretsCtx || '' },
      { label: 'tools', content: toolsCtx || '' },
      { label: 'methodology', content: methodologyCtx ? '## Attack Methodology Knowledge\n' + methodologyCtx : '' },
      { label: 'phaseTool', content: phaseToolCtx ? '## Phase Tool Recommendations\n' + phaseToolCtx : '' },
      { label: 'injectionTools', content: injectionToolsCtx || '' },
      { label: 'wafAdaptive', content: wafAdaptiveCtx || '' },
      { label: 'toolAvailability', content: toolAvailabilityCtx || '' },
      { label: 'missedVuln', content: buildMissedVulnContext({ targetPreset: targetPreset || undefined }) },
      // Context-aware target profiles (WAF/CDN/topology) — if profiling ran before scan plan generation
      { label: 'targetProfiles', content: (() => {
        if (!state.targetProfiles || Object.keys(state.targetProfiles).length === 0) return '';
        try {
          const { buildTargetProfileContext } = require('./context-aware-scanner');
          const profileCtxParts: string[] = [];
          for (const [host, profile] of Object.entries(state.targetProfiles)) {
            profileCtxParts.push(buildTargetProfileContext(profile));
          }
          return '## Context-Aware Target Profiles\n' + profileCtxParts.join('\n---\n');
        } catch { return ''; }
      })() },
    ];
    enrichmentCtx = capLLMContext(_scanPlanContextBlocks);
    // ── Context Engine Tracker: record which knowledge sources contributed to this scan planning decision ──
    try {
      const { buildContributionFromBlocks } = require('./context-engine-tracker');
      buildContributionFromBlocks(
        state.engagementId,
        state.assets.map((a: any) => a.hostname).join(', '),
        'scan_planning',
        _scanPlanContextBlocks,
        enrichmentCtx,
        'scan_planned',
      );
    } catch (e) { console.warn('[ContextTracker] Failed to record scan planning contribution:', e); }
  } catch (e) {
    console.warn('[ScanPlan] Failed to build enrichment context:', e);
  }

  const fullUserContent = enrichmentCtx
    ? tier1Content + '\n\n' + enrichmentCtx
    : tier1Content;

  const scanPlanResponseFormat = {
    type: 'json_schema' as const,
    json_schema: {
      name: 'scan_plan',
      strict: true,
      schema: {
        type: 'object',
        properties: {
          overallStrategy: { type: 'string' },
          discoveryStrategy: { type: 'string' },
          discoveryEvasionProfile: {
            type: 'object',
            properties: {
              timing: { type: 'string' },
              fragmentation: { type: 'boolean' },
              decoys: { type: 'boolean' },
              randomizeHosts: { type: 'boolean' },
              dataLengthPadding: { type: 'boolean' },
              sourcePortSpoofing: { type: 'boolean' },
              rationale: { type: 'string' }
            },
            required: ['timing', 'fragmentation', 'decoys', 'randomizeHosts', 'dataLengthPadding', 'sourcePortSpoofing', 'rationale'],
            additionalProperties: false
          },
          estimatedDuration: { type: 'string' },
          riskAssessment: { type: 'string' },
          assetPlans: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                hostname: { type: 'string' },
                ip: { type: 'string' },
                assetType: { type: 'string' },
                discoveryFlags: { type: 'string' },
                discoveryRationale: { type: 'string' },
                httpxFlags: { type: 'string', description: 'httpx flags for HTTP probing on discovered web ports' },
                activeTools: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      tool: { type: 'string' },
                      command: { type: 'string' },
                      rationale: { type: 'string' },
                      priority: { type: 'number' }
                    },
                    required: ['tool', 'command', 'rationale', 'priority'],
                    additionalProperties: false
                  }
                },
                riskNotes: { type: 'string' },
                evasionTechniques: { type: 'array', items: { type: 'string' } }
              },
              required: ['hostname', 'ip', 'assetType', 'discoveryFlags', 'discoveryRationale', 'httpxFlags', 'discoveryFlags', 'discoveryRationale', 'activeTools', 'riskNotes', 'evasionTechniques'],
              additionalProperties: false
            }
          }
        },
        required: ['overallStrategy', 'discoveryStrategy', 'discoveryEvasionProfile', 'estimatedDuration', 'riskAssessment', 'assetPlans'],
        additionalProperties: false
      }
    }
  };

  // ─── Dual-path: try specialist planAttack first, fallback to direct invokeLLM ───
  let response: any;
  let usedPath = 'specialist';
  try {
    console.log(`[ScanPlan] Using Attack Planner specialist...`);
    console.log(`[ScanPlan] passiveReconSummary size: ${fullUserContent.length} chars (~${Math.ceil(fullUserContent.length / 4)} tokens)`);
    const { planAttack } = await import('./llm-specialists/attack-planner');
    const attackPlan = await planAttack({
      passiveReconSummary: fullUserContent,
      engagement: {
        engagementType: state.engagementType,
        clientName: state.assets[0]?.hostname,
        targetCount: state.assets.length,
      },
      assets: state.assets.map(a => ({
        hostname: a.hostname,
        ip: a.ip,
        type: a.type,
        status: a.status,
        ports: a.ports.map(p => ({ port: p.port, service: p.service, version: p.version })),
        technologies: a.passiveRecon?.technologies,
        wafDetected: a.wafDetected,
        cloudProvider: a.passiveRecon?.cloudProvider,
        riskSignals: a.passiveRecon?.riskSignals?.map(r => ({ severity: r.severity, rationale: r.rationale })),
      })),
      engagementId: state.engagementId,
    });

    // Map specialist output to the existing ScanPlan response format
    const mappedContent = JSON.stringify({
      overallStrategy: attackPlan.attack_objective + ' — ' + attackPlan.estimated_impact,
      discoveryStrategy: 'Full port discovery with evasion techniques',
      discoveryEvasionProfile: {
        timing: 'T2', fragmentation: true, decoys: true,
        randomizeHosts: true, dataLengthPadding: true, sourcePortSpoofing: false,
        rationale: `Attack confidence: ${attackPlan.confidence}. Detection risks: ${attackPlan.detection_opportunities.join('; ')}`,
      },
      estimatedDuration: 'Varies by target count',
      riskAssessment: attackPlan.estimated_impact,
      assetPlans: attackPlan.scan_plan.discovery_targets.map(nt => {
        const webScans = attackPlan.scan_plan.web_scan_targets.filter(w => w.target === nt.target);
        const nucleiScans = attackPlan.scan_plan.nuclei_targets.filter(n => n.target === nt.target);
        return {
          hostname: nt.target,
          ip: state.assets.find(a => a.hostname === nt.target)?.ip || nt.target,
          assetType: state.assets.find(a => a.hostname === nt.target)?.type || 'unknown',
          discoveryFlags: nt.flags || '--rate 1000 --top-ports 1000',
          discoveryRationale: nt.rationale || 'Default discovery with evasion',
          httpxFlags: '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent',
          activeTools: [
            ...nucleiScans.map(n => {
              // Always include base vuln tags alongside LLM-selected templates
              const baseTags = ['cve', 'misconfig', 'exposed-panels', 'default-logins', 'sqli', 'xss', 'rce', 'ssrf', 'lfi', 'ssti', 'traversal', 'injection'];
              const allTags = [...new Set([...(n.templates || '').split(',').map((t: string) => t.trim()), ...baseTags])].filter(Boolean).join(',');
              return { tool: 'nuclei', command: `nuclei -u ${n.target} -severity critical,high,medium -tags ${allTags} -nc -duc -ni -jsonl`, rationale: n.rationale, priority: 1 };
            }),
            ...webScans.map(w => ({ tool: w.tool, command: w.config, rationale: w.rationale, priority: 2 })),
          ],
          riskNotes: attackPlan.detection_opportunities.join('; '),
          evasionTechniques: ['fragmentation', 'decoys', 'timing-T2'],
        };
      }),
    });
    response = { choices: [{ message: { content: mappedContent } }] };

    // Log the attack chain from the specialist
    if (attackPlan.attack_chain.length > 0) {
      addLog(state, {
        phase: state.phase, type: 'llm_decision',
        title: '⚔️ Attack Chain Identified',
        detail: attackPlan.attack_chain.map(ac => `${ac.stage}: ${ac.technique} (${ac.mitre_id}) → ${ac.target}`).join('\n'),
        data: { attackChain: attackPlan.attack_chain, initialAccess: attackPlan.initial_access_options },
      });
      broadcastOpsUpdate(engagementId, { type: 'log_update' });
    }
  } catch (specialistErr: any) {
    console.warn(`[ScanPlan] Specialist failed: ${specialistErr.message}. Falling back to direct LLM...`);
    addLog(state, {
      phase: state.phase, type: 'warning',
      title: 'Attack Planner Specialist Failed — Falling Back',
      detail: `${specialistErr.message?.substring(0, 150)}. Using direct LLM call...`,
    });
    broadcastOpsUpdate(engagementId, { type: 'log_update' });
    usedPath = 'direct-llm';
    try {
      // Budget-aware fallback: cap total prompt to ~40K chars (~10K tokens)
      const FALLBACK_MAX_CHARS = 40_000;
      const fallbackSystemLen = systemPrompt.length;
      const fallbackUserBudget = Math.max(FALLBACK_MAX_CHARS - fallbackSystemLen - 2000, 4000);
      const fallbackUserContent = tier1Content.length > fallbackUserBudget
        ? tier1Content.slice(0, fallbackUserBudget) + '\n[...truncated to fit token budget]'
        : tier1Content;
      console.log(`[ScanPlan Fallback] System: ${fallbackSystemLen} chars, User: ${fallbackUserContent.length} chars, Total: ${fallbackSystemLen + fallbackUserContent.length}`);
      response = await throttledLLMCall({
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: fallbackUserContent },
          ],
          _caller: 'engagement-orchestrator.generateScanPlan.fallback',
          _engagementId: state.engagementId,
          response_format: scanPlanResponseFormat,
        });
    } catch (fallbackErr: any) {
      addLog(state, {
        phase: state.phase, type: 'error',
        title: 'LLM Scan Plan Failed',
        detail: `Both specialist and direct LLM failed after retries. Error: ${fallbackErr.message?.substring(0, 200)}`,
      });
      broadcastOpsUpdate(engagementId, { type: 'log_update' });
      throw fallbackErr;
    }
  }
  console.log(`[ScanPlan] Succeeded with ${usedPath} path`);

  let parsed: any;
  try {
    const content = response.choices?.[0]?.message?.content || '{}';
    parsed = JSON.parse(content);
  } catch {
    addLog(state, { phase: state.phase, type: 'error', title: 'Scan Plan Parse Error', detail: 'LLM returned invalid JSON for scan plan' });
    throw new Error('Failed to parse LLM scan plan response');
  }

  const scanPlan: ScanPlan = {
    generatedAt: Date.now(),
    overallStrategy: parsed.overallStrategy || 'Two-phase active scanning with evasion',
    discoveryStrategy: parsed.discoveryStrategy || 'Full port discovery with evasion techniques',
    discoveryEvasionProfile: {
      timing: parsed.discoveryEvasionProfile?.timing || 'T2',
      fragmentation: parsed.discoveryEvasionProfile?.fragmentation ?? true,
      decoys: parsed.discoveryEvasionProfile?.decoys ?? true,
      randomizeHosts: parsed.discoveryEvasionProfile?.randomizeHosts ?? true,
      dataLengthPadding: parsed.discoveryEvasionProfile?.dataLengthPadding ?? true,
      sourcePortSpoofing: parsed.discoveryEvasionProfile?.sourcePortSpoofing ?? false,
      rationale: parsed.discoveryEvasionProfile?.rationale || 'Default evasion profile for safe discovery',
    },
    estimatedDuration: parsed.estimatedDuration || 'Unknown',
    riskAssessment: parsed.riskAssessment || 'Standard risk',
    assetPlans: (parsed.assetPlans || []).map((ap: any) => ({
      hostname: ap.hostname,
      ip: ap.ip,
      assetType: ap.assetType,
      discoveryFlags: ap.discoveryFlags || '-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64',
      discoveryRationale: ap.discoveryRationale || 'Default discovery scan with evasion and --top-ports 1000',
      httpxFlags: ap.httpxFlags || '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent',
      activeTools: (ap.activeTools || []).map((t: any) => ({
        tool: t.tool,
        command: t.command,
        rationale: t.rationale,
        priority: t.priority || 2,
      })),
      riskNotes: ap.riskNotes,
      evasionTechniques: ap.evasionTechniques || [],
    })),
  };

  state.scanPlan = scanPlan;

  // ═══ CRITICAL: Force-persist scanPlan immediately ═══
  // The scanPlan must survive server restarts. Without this, a restart between
  // plan generation and the next phaseCheckpoint loses the ZAP/Nuclei configs,
  // causing ZAP scans to be silently skipped on recovery.
  await persistOpsStateNow(engagementId);

  // Log the scan plan to the live feed
  const ep = scanPlan.discoveryEvasionProfile;
  const evasionFlags = [
    ep.fragmentation ? 'fragmentation' : null,
    ep.decoys ? 'decoys' : null,
    ep.randomizeHosts ? 'host-randomization' : null,
    ep.dataLengthPadding ? 'data-padding' : null,
    ep.sourcePortSpoofing ? 'source-port-spoofing' : null,
  ].filter(Boolean).join(', ');

  addLog(state, {
    phase: state.phase,
    type: 'llm_decision',
    title: '📋 Two-Phase Scan Plan Generated',
    detail: `Strategy: ${scanPlan.overallStrategy}\n\n🔍 Phase A — Discovery: ${scanPlan.discoveryStrategy}\nEvasion: ${evasionFlags} (timing: ${ep.timing})\nRationale: ${ep.rationale}\n\n🎯 Phase B — Targeted tools per asset\nEstimated duration: ${scanPlan.estimatedDuration}\nAssets planned: ${scanPlan.assetPlans.length}`,
    data: { scanPlan },
  });

  for (const ap of scanPlan.assetPlans) {
    addLog(state, {
      phase: state.phase,
      type: 'tool_match',
      title: `🎯 ${ap.hostname}${ap.ip && ap.ip !== ap.hostname ? ` (${ap.ip})` : ''}`,
      detail: `Phase A discovery: ${ap.discoveryFlags}\n  Rationale: ${ap.discoveryRationale}\nPhase B targeted: ${ap.discoveryFlags}\n  Rationale: ${ap.discoveryRationale}\nTools: ${ap.activeTools.map(t => t.tool).join(', ')}\nEvasion: ${ap.evasionTechniques.join(', ')}\nRisk: ${ap.riskNotes}`,
      data: { assetPlan: ap },
    });
  }

  broadcastOpsUpdate(engagementId, { type: 'scan_plan', scanPlan });

  return scanPlan;
}

// ─── LLM Decision Engine ───────────────────────────────────────────────────

export async function llmDecide(context: {
  phase: OpsPhase;
  engagementType: string;
  engagementId?: number;
  assets: AssetStatus[];
  recentLog: OpsLogEntry[];
  question: string;
}): Promise<{ decision: string; reasoning: string; actions: Array<{ type: string; params: Record<string, any> }> }> {
  // Compact asset summary for ops decisions
  const assetSummary = context.assets.map(a =>
    `${a.hostname}${a.ip ? '('+a.ip+')' : ''} [${a.type}] ${a.status} ports:${a.ports.length} vulns:${a.vulns.length} zap:${a.zapFindings.length}${a.wafDetected ? ' WAF:'+a.wafDetected : ''}`
  ).join('\n');
  const recentActivity = context.recentLog.slice(-10).map(l => `[${l.type}] ${l.title}`).join('\n');

  // ─── Try Ops Decider specialist first ───
  // Skip ops-decider for exploitation/post-exploit phases — it only returns scan-type actions,
  // not exploit_attempt actions. The direct LLM fallback handles exploitation properly.
  const skipSpecialist = ['exploitation', 'post_exploit'].includes(context.phase);
  if (skipSpecialist) {
    console.log(`[OpsLLM] Skipping ops-decider specialist for ${context.phase} phase — using direct LLM for exploit action generation`);
  }
  if (!skipSpecialist) try {
    const { decideNextOp } = await import('./llm-specialists/ops-decider');
    const opsResult = await decideNextOp({
      currentPhase: context.phase,
      recentActivity,
      assetSummary,
      availableTools: ['nmap', 'naabu', 'masscan', 'scanforge-discovery', 'nuclei', 'zap', 'nikto', 'gobuster', 'testssl', 'hydra', 'sqlmap', 'feroxbuster', 'ffuf', 'whatweb', 'wpscan', 'sslscan', 'arjun'],
      engagement: {
        engagementType: context.engagementType,
        clientName: context.assets[0]?.hostname,
        targetCount: context.assets.length,
      },
      engagementId: context.engagementId,
    });

    // Map specialist output to legacy format
    const toolToActionType: Record<string, string> = {
      discovery: 'discovery_scan', nuclei: 'nuclei_scan', zap: 'zap_scan',
      nikto: 'nuclei_scan', gobuster: 'nuclei_scan',
      testssl: 'nuclei_scan', hydra: 'exploit_attempt', sqlmap: 'exploit_attempt',
      // Port scanning & service discovery tools
      nmap: 'discovery_scan', naabu: 'discovery_scan', masscan: 'discovery_scan',
      'scanforge-discovery': 'discovery_scan',
      // Web fuzzing & content discovery tools
      feroxbuster: 'nuclei_scan', ffuf: 'nuclei_scan', whatweb: 'discovery_scan',
      wpscan: 'nuclei_scan', sslscan: 'nuclei_scan', arjun: 'nuclei_scan',
    };
    const actionType = toolToActionType[opsResult.recommended_action.tool] || 'discovery_scan';
    const actions: Array<{ type: string; params: Record<string, any> }> = [{
      type: actionType,
      params: {
        target: opsResult.recommended_action.target,
        targets: [opsResult.recommended_action.target],
        tool: opsResult.recommended_action.tool,
        profile: 'standard',
      },
    }];

    // Add alternative actions
    for (const alt of opsResult.alternative_actions.slice(0, 2)) {
      actions.push({ type: 'discovery_scan', params: { reason: alt.action } });
    }

    return {
      decision: opsResult.recommended_action.action,
      reasoning: `[${opsResult.confidence}] ${opsResult.current_assessment}\nGaps: ${opsResult.coverage_gaps.join(', ')}\nRationale: ${opsResult.recommended_action.rationale}${opsResult.should_escalate ? '\n⚠️ ESCALATION RECOMMENDED' : ''}`,
      actions,
    };
  } catch (specialistErr: any) {
    console.warn(`[OpsLLM] Specialist failed: ${specialistErr.message}. Falling back to direct LLM...`);
  }

  // ─── Fallback: direct invokeLLM ───
  // Cap the question size to prevent oversized prompts (memory optimization)
  if (context.question.length > 15_000) {
    console.warn(`[OpsLLM] Question too large (${context.question.length} chars), truncating to 15K`);
    context.question = context.question.slice(0, 15_000) + '\n[...context truncated for memory]';
  }
  // Build phase-specific instructions for the LLM
  const exploitPhaseInstructions = ['exploitation', 'post_exploit'].includes(context.phase)
    ? `\n\nIMPORTANT: You are in the ${context.phase} phase. You MUST return actions with type "exploit_attempt" for each vulnerability you want to exploit.
Each exploit_attempt action MUST include params: {target: "hostname", port: number, cve: "CVE-XXXX-XXXXX", service: "service_name", module: "exploit_module_or_technique"}
Prioritize critical and high severity vulnerabilities. Generate one exploit_attempt action per target/CVE combination.
Do NOT return scan-type actions (discovery_scan, nuclei_scan) during exploitation — only exploit_attempt, c2_deploy, or complete.`
    : '';

   // Inject banking domain knowledge if applicable
  let bankingOpsCtx = '';
  try {
    if (context.assets?.some((a: any) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || a.ip || ''))) {
      const { getBankingContextCompact, buildBankingDomainContext } = await import('./llm-specialists/banking-domain-knowledge');
      bankingOpsCtx = ['exploitation', 'post_exploit'].includes(context.phase)
        ? '\n\n' + buildBankingDomainContext({ phase: context.phase, includeRegulatory: false, includeTechStack: false, includeAttackScenarios: true })
        : '\n\n' + getBankingContextCompact();
    }
  } catch (e) { /* non-fatal */ }
  const systemPrompt = `Pentest AI for ${context.engagementType} engagement. Phase: ${context.phase}.
Assets:\n${assetSummary}\n\nRecent:\n${recentActivity}\n\nReturn JSON: {"decision":"str","reasoning":"str","actions":[{"type":"discovery_scan|nuclei_scan|zap_scan|exploit_attempt|c2_deploy|recon|skip|complete|wait","params":{...}}]}
Action params: discovery_scan={targets,profile:quick|standard|deep|stealth|service|vuln} nuclei_scan={targets,severity,tags?} zap_scan={targetUrl,scanType:full|active|spider_only,wafAware} exploit_attempt={target,port,cve,service,module?} c2_deploy={target,platform,method} recon={domain} complete={reason}
Rules: pentest=test each asset systematically; red_team=find weakest entry,exploit,C2,pivot; WAF-aware scanning; correlate findings across tools; flag high-risk actions; stay in scope.${exploitPhaseInstructions}${bankingOpsCtx}`;

  try {
    const response = await throttledLLMCall({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: context.question },
        ],
        _caller: 'engagement-orchestrator.opsDecision',
        _engagementId: context.engagementId,
        response_format: {
          type: "json_object" as const,
        },
      });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    return JSON.parse(content);
  } catch (e: any) {
    console.warn("[OpsLLM] Decision failed after retries:", e.message);
    return {
      decision: "LLM decision failed, falling back to sequential scan",
      reasoning: e.message,
      actions: [{ type: "skip", params: { reason: "LLM unavailable" } }],
    };
  }
}

// ─── Phase Executors ────────────────────────────────────────────────────────

async function executeRecon(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "recon";
  state.currentAction = "Running passive reconnaissance...";
  addLog(state, { phase: "recon", type: "info", title: "🔍 Phase 1: Domain Recon", detail: "Starting passive OSINT and domain intelligence gathering" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "recon" });

   const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean).map(ip => ip.replace(/\/\d+$/, ''));

  // ═══ INITIALIZE RoE SCOPE GUARD ═══
  // Hard-lock the authorized targets from the engagement's RoE before any scanning begins
  state.roeScopeGuard = {
    authorizedDomains: [...domains],
    authorizedIps: [...ipRanges],
    roeStatus: (!engagement.roeStatus || engagement.roeStatus === "none") ? "signed" : (engagement.roeStatus || engagement.roe_status || "signed"),
  };
  addLog(state, {
    phase: "recon", type: "info",
    title: "🛡️ RoE Scope Guard Activated",
    detail: `Authorized targets: ${domains.join(", ")}${ipRanges.length ? " | IPs: " + ipRanges.join(", ") : ""}\nOnly these targets will be actively scanned. Discovered assets outside scope will be tagged but NOT probed.`,
  });

  // ═══ BUG BOUNTY RoE ENFORCEMENT ═══
  // For bug_bounty engagements, load program-specific RoE config and enforce at scan-time
  if ((state.engagementType as string) === 'bug_bounty' || engagement.engagementType === 'bug_bounty') {
    try {
      const { getProgramRoE, generateOperatorBriefing, enforceScanAction } = await import('./bb-roe-enforcement');
      // Extract program handle from engagement's roeScope or name
      const roeScope = engagement.roeScope || engagement.roe_scope;
      const parsedScope = typeof roeScope === 'string' ? JSON.parse(roeScope) : roeScope;
      const programHandle = parsedScope?.programHandle || parsedScope?.platform_handle || engagement.name?.toLowerCase().replace(/[^a-z0-9]/g, '_').split('_')[0] || '';
      const programRoE = getProgramRoE(programHandle);
      if (programRoE) {
        state.bbRoeConfig = programRoE;
        // Add excluded targets from program RoE to the scope guard
        const excludedTargets = programRoE.testingRestrictions.excludedTargets;
        if (excludedTargets.length > 0) {
          addLog(state, {
            phase: 'recon', type: 'info',
            title: `🚫 BB RoE: ${excludedTargets.length} Excluded Targets`,
            detail: `Program "${programHandle}" excludes:\n${excludedTargets.map(t => `  • ${t}`).join('\n')}\nThese will be blocked from all active scanning.`,
          });
        }
        // Log operator briefing
        const briefing = generateOperatorBriefing(programHandle);
        if (briefing) {
          addLog(state, {
            phase: 'recon', type: 'info',
            title: `🎯 BB Program RoE Loaded: ${programHandle.toUpperCase()}`,
            detail: [
              `Platform: ${briefing.platform} | Policy: ${briefing.policyUrl}`,
              '',
              '--- CRITICAL RULES ---',
              ...briefing.criticalRules,
              '',
              '--- IDENTIFICATION SETUP ---',
              ...briefing.identificationSetup,
              '',
              '--- EXCLUDED TARGETS ---',
              ...briefing.excludedTargets.map(t => `  • ${t}`),
              '',
              '--- DO NOT SUBMIT ---',
              ...briefing.doNotSubmit,
              '',
              '--- CLEANUP REQUIRED ---',
              ...briefing.cleanupActions,
            ].join('\n'),
          });
        }
        // Apply custom headers to DAST config
        if (Object.keys(programRoE.identification.customHeaders).length > 0) {
          if (!state.dastConfig) {
            state.dastConfig = { enabled: true, crawlDepth: 3, crawlScope: 'subdomain', templateCategories: [], timeout: 300, maxRequests: 5000, rateLimit: programRoE.testingRestrictions.rateLimiting?.maxRequestsPerSecond || 10, headless: true };
          }
          state.dastConfig.customHeaders = { ...(state.dastConfig.customHeaders || {}), ...programRoE.identification.customHeaders };
          // Replace empty header values with operator username
          const opUsername = (operatorCtx as any).h1Username || operatorCtx.name || 'ac3-operator';
          for (const [key, val] of Object.entries(state.dastConfig.customHeaders)) {
            if (val === '') state.dastConfig.customHeaders[key] = opUsername;
          }
          addLog(state, {
            phase: 'recon', type: 'info',
            title: '🆔 BB Custom Headers Configured',
            detail: `Injecting identification headers into all scan requests:\n${Object.entries(state.dastConfig.customHeaders).map(([k, v]) => `  ${k}: ${v}`).join('\n')}`,
          });
        }
        // Apply rate limiting from program RoE
        if (programRoE.testingRestrictions.rateLimiting && state.dastConfig) {
          state.dastConfig.rateLimit = programRoE.testingRestrictions.rateLimiting.maxRequestsPerSecond || state.dastConfig.rateLimit;
          addLog(state, {
            phase: 'recon', type: 'info',
            title: '⏱️ BB Rate Limiting Applied',
            detail: `Max ${state.dastConfig.rateLimit} req/s per program RoE requirements`,
          });
        }
      } else {
        addLog(state, {
          phase: 'recon', type: 'info',
          title: '⚠️ BB Program RoE: No Config Found',
          detail: `No program-specific RoE config found for "${programHandle}". Engagement will proceed with general H1 Core Ineligible filtering only. Consider importing the program's policy page.`,
        });
      }
    } catch (e: any) {
      console.error('[BBRoE] Failed to load program RoE:', e.message);
      addLog(state, { phase: 'recon', type: 'info', title: '⚠️ BB RoE Load Warning', detail: `Non-fatal: ${e.message}` });
    }
  }

  // Initialize assets from scope
  for (const domain of domains) {
    if (!state.assets.find(a => a.hostname === domain)) {
      const sourceCheck = isSourceCodeTarget(domain);
      if (sourceCheck.isSourceCode) {
        // Source code repository — mark as source_code type, not a scannable domain
        state.assets.push({
          hostname: domain,
          type: "source_code",
          ports: [],
          vulns: [],
          pendingVulns: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
          toolResults: [],
          status: "pending",
          sourceCodeUrl: sourceCheck.repoUrl,
        } as any);
        addLog(state, {
          phase: "recon", type: "info",
          title: "\uD83D\uDCE6 Source Code Asset Detected",
          detail: `${domain} is a source code repository. This asset requires download and local build before testing. Use the Build & Deploy panel in RoE & Scope to provision the test environment.`,
        });
      } else {
        state.assets.push({
          hostname: domain,
          type: "unknown",
          ports: [],
          vulns: [],
          pendingVulns: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
          toolResults: [],
          status: "pending",
        });
      }
    }
  }
  for (const rawIp of ipRanges) {
    const ip = rawIp.replace(/\/\d+$/, '');  // Strip CIDR notation (e.g., /32, /24)
    if (!state.assets.find(a => a.hostname === ip || a.ip === ip)) {
      state.assets.push({
        hostname: ip,
        ip,
        type: "unknown",
        ports: [],
        vulns: [],
        pendingVulns: [],
        zapFindings: [],
        exploitAttempts: [],
        confirmedCredentials: [],
        toolResults: [],
        status: "pending",
      });
    }
  }

  // Run domain intel scan for each domain
  for (const domain of domains) {
    try {
      // Lab domain detection — fast-track mode skips external API connectors
      const { isLabDomain } = await import("./passive/index");
      const isLab = isLabDomain(domain);
      const modeLabel = isLab ? 'Lab fast-track OSINT (local connectors only)' : 'Running passive OSINT scan';
      addLog(state, { phase: "recon", type: "scan_start", title: `Domain Intel: ${domain}`, detail: modeLabel });
      if (isLab) {
        addLog(state, { phase: "recon", type: "info", title: `Lab Domain Detected`, detail: `${domain} matched training lab pattern — skipping external API connectors (Shodan, SecurityTrails, Censys, etc.) to avoid timeouts` });
      }

      const { runDomainIntelPipeline } = await import("../domainIntel");
      const result = await runDomainIntelPipeline({
        customerName: engagement.customerName || "Auto",
        primaryDomain: domain,
        additionalDomains: [],
        sector: "technology",
        clientType: "enterprise",
        criticalFunctions: [],
        complianceFlags: [],
      });

      // Extract discovered assets — RoE SCOPE GUARD enforced
      const discoveredAssets = (result as any).assets || [];
      const passiveReconData = (result as any).passiveRecon;
      let outOfScopeCount = 0;

      // Helper: build AssetPassiveRecon from pipeline result observations
      function buildPassiveRecon(assetAnalysis: any, reconData: any): AssetPassiveRecon {
        const observations = reconData?.allObservations || [];
        const riskSignals = reconData?.riskSignals || [];
        const assetObs = observations.filter((o: any) => o.domain === domain || o.name === assetAnalysis?.asset?.hostname);
        const services: AssetPassiveRecon['services'] = [];
        const ipAddresses: string[] = [];
        const subdomains: string[] = [];
        const technologies: string[] = [...(assetAnalysis?.asset?.technologies || [])];
        const certificates: AssetPassiveRecon['certificates'] = [];
        const historicalUrls: string[] = [];
        const sources: string[] = [];

        for (const obs of assetObs) {
          if (obs.source && !sources.includes(obs.source)) sources.push(obs.source);
          if (obs.ip && !ipAddresses.includes(obs.ip)) ipAddresses.push(obs.ip);
          if (obs.name && obs.name !== domain && !subdomains.includes(obs.name)) subdomains.push(obs.name);
          // Extract services from evidence (Shodan, Censys)
          const ev = obs.evidence || {};
          if (ev.port) {
            services.push({
              port: Number(ev.port),
              protocol: ev.transport || 'tcp',
              service: ev.service || ev.product || 'unknown',
              product: ev.product,
              version: ev.version,
              source: obs.source,
            });
          }
          if (ev.ports && Array.isArray(ev.ports)) {
            for (const p of ev.ports) {
              services.push({
                port: typeof p === 'number' ? p : Number(p.port || p),
                protocol: p.transport || 'tcp',
                service: p.service || 'unknown',
                product: p.product,
                version: p.version,
                source: obs.source,
              });
            }
          }
          if (ev.technologies && Array.isArray(ev.technologies)) {
            for (const t of ev.technologies) {
              if (typeof t === 'string' && !technologies.includes(t)) technologies.push(t);
            }
          }
          if (ev.ssl?.cert) {
            certificates.push({
              subject: ev.ssl.cert.subject || ev.ssl.cert.cn || '',
              issuer: ev.ssl.cert.issuer,
              validFrom: ev.ssl.cert.notBefore,
              validTo: ev.ssl.cert.notAfter,
            });
          }
        }

        return {
          subdomains,
          ipAddresses,
          services,
          technologies,
          certificates,
          riskSignals: riskSignals.map((r: any) => ({
            severity: r.severity || 'info',
            type: r.signalType || r.type || 'unknown',
            rationale: r.rationale || r.description || r.title || '',
          })),
          wafDetected: undefined,
          cloudProvider: undefined,
          historicalUrls,
          rawObservationCount: assetObs.length,
          sources,
        };
      }

      // Helper: convert PostureFindings to vulns (matching AssetStatus.vulns type)
      function postureToVulns(findings: any[]): Array<{ id: string; severity: string; title: string; cve?: string; corroborationTier?: string; evidenceDetail?: string; detectedVersion?: string; affectedVersions?: string; __nucleiHint?: any }> {
        return (findings || []).map((f: any, idx: number) => {
          // Determine corroboration tier based on evidence quality
          const hasVersion = !!f.detectedVersion && f.detectedVersion !== 'unknown';
          const hasConfirmedVersion = hasVersion && f.versionConfidence === 'confirmed';
          const tier = hasConfirmedVersion ? 'confirmed' : hasVersion ? 'probable' : 'potential';
          const evidenceSource = f.source || 'passive recon';

          // ── Nuclei Fast-Path Hint: resolve template for DI-discovered CVEs ──
          // When a DI finding has CVE IDs, attempt to resolve a Nuclei template
          // so the exploitation phase can skip LLM generation and run Nuclei directly.
          let nucleiHint: any = undefined;
          const primaryCve = f.cveIds?.[0];
          if (primaryCve || f.category) {
            try {
              // Dynamic import to avoid circular deps — resolveNucleiTemplate is sync-capable
              // after initial cache load, so we build the hint inline
              const { KNOWN_NUCLEI_CVES, NUCLEI_VULN_CLASS_TAGS } = require('../lib/exploit-selection-intelligence');
              const VULN_CLASS_ALIASES: Record<string, string> = {
                'command_injection': 'cmdi', 'os_command_injection': 'cmdi',
                'path_traversal': 'lfi', 'directory_traversal': 'lfi',
                'local_file_inclusion': 'lfi', 'remote_file_inclusion': 'rfi',
                'server_side_request_forgery': 'ssrf', 'cross_site_scripting': 'xss',
                'sql_injection': 'sqli', 'server_side_template_injection': 'ssti',
                'xml_external_entity': 'xxe', 'insecure_deserialization': 'deserialization',
                'unrestricted_file_upload': 'file_upload', 'fileupload': 'file_upload',
                'authentication_bypass': 'auth_bypass', 'auth-bypass': 'auth_bypass',
              };

              // Try CVE-based template first
              if (primaryCve && KNOWN_NUCLEI_CVES) {
                const templatePath = KNOWN_NUCLEI_CVES[primaryCve];
                if (templatePath) {
                  nucleiHint = {
                    templatePath,
                    tags: [],
                    source: 'di_pipeline_static_map',
                    confidence: 95,
                    cveId: primaryCve,
                  };
                }
              }

              // Fall back to vuln class tags if no CVE template found
              if (!nucleiHint && f.category && NUCLEI_VULN_CLASS_TAGS) {
                const rawClass = f.category.toLowerCase().replace(/[\s-]+/g, '_');
                const normalizedClass = VULN_CLASS_ALIASES[rawClass] || rawClass;
                const tags = NUCLEI_VULN_CLASS_TAGS[normalizedClass];
                if (tags && tags.length > 0) {
                  nucleiHint = {
                    templatePath: null,
                    tags: [...tags],
                    source: 'di_pipeline_vuln_class',
                    confidence: 70,
                    cveId: primaryCve || undefined,
                  };
                }
              }

              // Fall back to generic CVE tag if we have a CVE but no specific template
              if (!nucleiHint && primaryCve) {
                nucleiHint = {
                  templatePath: null,
                  tags: ['cve'],
                  source: 'di_pipeline_generic_cve',
                  confidence: 50,
                  cveId: primaryCve,
                };
              }
            } catch (e) {
              // Non-critical — if template resolution fails, exploit phase still works via normal pipeline
            }
          }

          // Build rich evidence detail from DI scan finding data instead of generic placeholder
          const richEvidenceParts: string[] = [];
          // Use the original DI scan evidenceDetail if available (contains version-specific match info)
          if (f.evidenceDetail) {
            richEvidenceParts.push(f.evidenceDetail);
          } else {
            richEvidenceParts.push(`Detected via ${evidenceSource}${hasVersion ? ` (version ${f.detectedVersion})` : ''}`);
          }
          // Include NVD description for CVE context
          if (f.nvdDescription) {
            richEvidenceParts.push(`NVD: ${f.nvdDescription}`);
          }
          // Include affected version range for version-based findings
          if (f.affectedVersions && f.detectedVersion) {
            richEvidenceParts.push(`Affected versions: ${f.affectedVersions}. Detected: ${f.detectedVersion}`);
          }
          // Include evidence basis for traceability
          if (f.evidenceBasis) {
            const basisLabels: Record<string, string> = {
              confirmed_cve: 'Confirmed CVE match',
              kev_match: 'CISA KEV catalog match',
              vuln_feed: 'Vulnerability feed match',
              llm_inference: 'LLM-inferred risk',
              technology_match: 'Technology fingerprint match',
            };
            richEvidenceParts.push(`Basis: ${basisLabels[f.evidenceBasis] || f.evidenceBasis}`);
          }

          const vuln: any = {
            id: f.cveIds?.[0] || `passive-${domain}-${idx}`,
            severity: f.severity >= 8 ? 'critical' : f.severity >= 6 ? 'high' : f.severity >= 4 ? 'medium' : 'low',
            title: f.title || f.category || 'Unknown finding',
            cve: f.cveIds?.[0],
            corroborationTier: tier,
            evidenceDetail: richEvidenceParts.join(' | '),
            detectedVersion: f.detectedVersion || null,
            affectedVersions: f.affectedVersions || null,
            // Preserve the full evidence chain from DI scan for report consumption
            evidenceChain: f.evidenceChain || [],
            // Preserve raw evidence fields for report pipeline
            rawEvidence: f.evidenceChain ? f.evidenceChain.join('\n') : undefined,
            description: f.nvdDescription || f.evidenceDetail || undefined,
            source: f.source || evidenceSource,
            tool: f.source || 'domain-intel',
            kevListed: f.kevListed || false,
            exploitAvailable: f.exploitAvailable || false,
            cvssScore: f.cvssScore,
          };

          // Attach Nuclei fast-path hint if resolved
          if (nucleiHint) {
            vuln.__nucleiHint = nucleiHint;
          }

          return vuln;
        });
      }

      for (const asset of discoveredAssets) {
        const assetHostname = asset.asset?.hostname || asset.hostname || asset.domain || asset.ip;
        if (!assetHostname) continue;
        const existing = state.assets.find(a => a.hostname === assetHostname);
        const passiveRecon = buildPassiveRecon(asset, passiveReconData);
        const passiveVulns = postureToVulns(asset.postureFindings);

        if (existing) {
          existing.ip = asset.asset?.ip || asset.ip || existing.ip;
          existing.type = asset.asset?.assetType === "web_application" ? "web_app" : existing.type;
          // CRITICAL FIX: Populate passiveRecon data from domain intel pipeline
          existing.passiveRecon = passiveRecon;
          // Add ports from passive recon (Shodan/Censys service discovery)
          for (const svc of passiveRecon.services) {
            if (!existing.ports.some((p) => p.port === svc.port)) {
              existing.ports.push({
                port: svc.port,
                service: svc.service || 'unknown',
                version: svc.version || '',
              });
            }
          }
          // Resolve any remaining "unknown" service labels
          enrichPortServices(existing.ports, passiveRecon.services || []);
          // Defer passive vulns to pendingVulns — they will be promoted to vulns at vuln_detection phase start
          // When duplicates exist, MERGE evidence from all scanners into the existing record
          for (const v of passiveVulns) {
            const existingPV = existing.pendingVulns.find((pv: any) => {
              if (v.cve && pv.cve && v.cve === pv.cve) return true;
              const normExisting = (pv.title || '').replace(/^\[[^\]]+\]\s*/, '').toLowerCase().trim();
              const normNew = (v.title || '').replace(/^\[[^\]]+\]\s*/, '').toLowerCase().trim();
              if (normExisting && normNew && normExisting === normNew) return true;
              return false;
            });
            if (existingPV) {
              // Merge evidence from new scanner into existing pending vuln
              mergePendingVulnEvidence(existingPV as any, v as any);
            } else {
              // New vuln — initialize scannerEvidence array
              if (!(v as any).scannerEvidence) {
                (v as any).scannerEvidence = [buildScannerEvidenceEntry(v as any)];
              }
              existing.pendingVulns.push(v as any);
            }
          }
          existing.status = 'discovered';
          // Update port stats only — vulns are deferred
          state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
        } else if (isInRoeScope(state, assetHostname, asset.asset?.ip || asset.ip)) {
          // Asset is in RoE scope — add for active scanning
          state.assets.push({
            hostname: assetHostname,
            ip: asset.asset?.ip || asset.ip,
            type: asset.asset?.assetType === "web_application" ? "web_app" : "unknown",
            ports: (() => {
              const ports = passiveRecon.services.map(svc => ({
                port: svc.port,
                service: svc.service || 'unknown',
                version: svc.version || '',
              }));
              enrichPortServices(ports, passiveRecon.services || []);
              return ports;
            })(),
            vulns: [],
            pendingVulns: passiveVulns,
            zapFindings: [],
            exploitAttempts: [],
            confirmedCredentials: [],
            toolResults: [],
            status: "discovered",
            passiveRecon,
          });
          state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
        } else {
          // Asset discovered but OUT OF RoE SCOPE — log but do NOT add for active scanning
          outOfScopeCount++;
          addLog(state, {
            phase: "recon", type: "warning",
            title: `⚠️ Out-of-Scope Asset: ${assetHostname}`,
            detail: `Discovered ${assetHostname}${asset.ip ? ` (${asset.ip})` : ''} via passive recon but it is NOT in the RoE authorized target list. Skipping active scanning.`,
          });
        }
      }

      // Store raw passive recon results for LLM context
      if (passiveReconData) {
        if (!state.passiveReconResults) state.passiveReconResults = {};
        state.passiveReconResults[domain] = {
          totalObservations: passiveReconData.allObservations?.length || 0,
          riskSignals: passiveReconData.riskSignals?.length || 0,
          connectorStats: passiveReconData.summary?.connectorStats || [],
        };
      }

      if (outOfScopeCount > 0) {
        addLog(state, {
          phase: "recon", type: "info",
          title: `🛡️ Scope Guard: ${outOfScopeCount} out-of-scope assets filtered`,
          detail: `${outOfScopeCount} assets discovered via passive recon were excluded from active scanning per RoE.`,
        });
      }

      const findingsCount = (result as any).totalFindings || 0;
      const portsFound = state.stats.portsFound;
      const pendingVulnCount = state.assets.reduce((sum, a) => sum + (a.pendingVulns?.length || 0), 0);
      addLog(state, {
        phase: "recon",
        type: "scan_result",
        title: `Recon Complete: ${domain}`,
        detail: `Discovered ${discoveredAssets.length} assets, ${findingsCount} findings, ${portsFound} ports, ${pendingVulnCount} risk signals deferred to scanning phase`,
        data: { domain, assets: discoveredAssets.length, findings: findingsCount, ports: portsFound, pendingVulns: pendingVulnCount },
      });

      emitReconComplete({ scanId: 0, domain, findings: findingsCount });

      // ─── Specialist: Scan Analyst for passive recon findings ───
      try {
        const domainAssets = state.assets.filter(a => a.hostname === domain || a.hostname.endsWith('.' + domain));
        if (domainAssets.length > 0) {
          const { analyzeScan } = await import('./llm-specialists/scan-analyst');
          const scanData = domainAssets.map(a => ({
            hostname: a.hostname,
            ip: a.ip,
            type: a.type,
            ports: a.ports,
            technologies: a.passiveRecon?.technologies,
            cloudProvider: a.passiveRecon?.cloudProvider,
            riskSignals: a.passiveRecon?.riskSignals?.map(r => ({ severity: r.severity, rationale: r.rationale })),
          }));
          const analysis = await analyzeScan({
            hostname: domain,
            scanData: JSON.stringify(scanData, null, 2),
            engagement: {
              engagementType: state.engagementType,
              clientName: domain,
              targetCount: state.assets.length,
            },
            engagementId: state.engagementId,
          });
          addLog(state, {
            phase: 'recon', type: 'llm_decision',
            title: `📊 Scan Analysis: ${domain}`,
            detail: `Risk: ${analysis.risk_rating || 'unknown'} (${analysis.confidence || 'low'})\n${analysis.executive_summary || 'No summary'}\n\nKey findings:\n${(analysis.findings || []).slice(0, 5).map((f: any) => `• [${f.severity}] ${f.title} — ${f.evidence_tag || ''}`).join('\n')}\n\nRecommendations:\n${(analysis.recommendations || []).slice(0, 3).map((r: any) => `• [${r.priority}] ${r.action}`).join('\n')}`,
            data: { scanAnalysis: analysis },
          });
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        }
      } catch (saErr: any) {
        console.warn(`[ScanAnalyst] Failed for ${domain}:`, saErr.message);
      }

      // ─── Specialist: Hybrid Scorer for context-aware risk scoring ───
      try {
        const domainAssets = state.assets.filter(a => a.hostname === domain || a.hostname.endsWith('.' + domain));
        if (domainAssets.length > 0) {
          const { scoreFullHybrid, buildEngagementContext } = await import('./llm-specialists/hybrid-scorer');
          // Score each asset individually using the correct FullHybridScoreInput interface
          for (const asset of domainAssets) {
            // Update heartbeat so stall detector knows we're alive during long LLM scoring
            if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now();
            try {
              const riskSignals = (asset.passiveRecon?.riskSignals || []).map((r: any) => ({
                severity: r.severity || 'medium',
                rationale: r.rationale || 'Risk signal detected',
                source: r.source || 'passive_recon',
              }));
              const hybridResult = await scoreFullHybrid({
                assetId: asset.hostname,
                assetLabel: asset.hostname,
                domain: domain,
                hostname: asset.hostname,
                keywords: (asset.passiveRecon as any)?.keywords || [],
                ports: (asset.ports || []).map((p: any) => ({
                  port: p.port,
                  service: p.service,
                  version: p.version,
                  state: p.state || 'open',
                })),
                technologies: (asset.passiveRecon as any)?.technologies || [],
                wafDetected: (asset.passiveRecon as any)?.wafDetected,
                cloudProvider: (asset.passiveRecon as any)?.cloudProvider,
                certificates: (asset.passiveRecon as any)?.certificates || [],
                dnsRecords: (asset.passiveRecon as any)?.dnsRecords || [],
                httpHeaders: (asset.passiveRecon as any)?.httpHeaders || {},
                riskSignals,
                engagementContext: state.engagementContext || buildEngagementContext({
                  engagementType: state.engagementType || 'pentest',
                  targetCount: state.assets?.length || 1,
                  domains: [domain],
                }),
              });
              // Store the hybrid score on the asset for downstream use
              (asset as any).hybridScore = hybridResult.finalScore;
              (asset as any).hybridTier = hybridResult.finalTier;
              const adjustmentSummary = Object.entries(hybridResult.llmEnhanced.adjustments || {})
                .filter(([_, v]: [string, any]) => v.delta !== 0)
                .map(([k, v]: [string, any]) => `${k}: ${v.delta > 0 ? '+' : ''}${v.delta} (${v.justification})`)
                .slice(0, 5);
              addLog(state, {
                phase: 'recon', type: 'llm_decision',
              title: `🎯 Hybrid Risk Score: ${asset.hostname}`,
              detail: `Score: ${hybridResult.finalScore}/10 (${hybridResult.finalTier})\nBaseline: ${hybridResult.baseline.scores.hybrid}/10 (${hybridResult.baseline.scores.priorityTier})\nConfidence: ${hybridResult.llmEnhanced.confidence}\n\nRisk Narrative: ${hybridResult.llmEnhanced.overallRiskNarrative}\n\n${adjustmentSummary.length > 0 ? 'LLM Adjustments:\n' + adjustmentSummary.map(a => '• ' + a).join('\n') : 'No LLM adjustments applied'}`,
              data: { hybridScoring: hybridResult },
            });
            broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
            } catch (assetHsErr: any) {
              console.warn(`[HybridScorer] Failed for asset ${asset.hostname}:`, assetHsErr.message);
            }
          }
        }
      } catch (hsErr: any) {
        console.warn(`[HybridScorer] Failed for ${domain}:`, hsErr.message);
      }
    } catch (e: any) {
      addLog(state, { phase: "recon", type: "error", title: `Recon Failed: ${domain}`, detail: e.message });
    }
  }

  state.progress = 15;
  addLog(state, { phase: "recon", type: "phase_complete", title: "\u2705 Phase 1 Complete", detail: `${state.assets.length} assets in scope` });

  // ═══ EMIT recon:finding EVENTS FOR LIVE GRAPH UPDATES ═══
  // Broadcast each discovered asset so the Ops Viewer live stream can render them in real-time
  for (const asset of state.assets) {
    // Host node
    broadcastReconFinding(state.engagementId, {
      target: asset.hostname || asset.ip,
      host: asset.hostname,
      ip: asset.ip,
      tool: "passive_recon",
    });
    // Ports
    for (const p of (asset.ports || [])) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        port: typeof p.port === "number" ? p.port : parseInt(String(p.port)) || undefined,
        service: p.service || undefined,
        protocol: "tcp",
        tool: "passive_recon",
      });
    }
    // Vulns from passive recon
    for (const v of (asset.vulns || [])) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        vulnerability: v.title || v.id,
        cve: v.cve,
        severity: v.severity || "info",
        tool: "passive_recon",
      });
    }
    // Subdomains
    if (asset.passiveRecon?.subdomains) {
      for (const sub of asset.passiveRecon.subdomains) {
        broadcastReconFinding(state.engagementId, {
          target: asset.hostname || asset.ip,
          subdomain: typeof sub === "string" ? sub : sub.hostname,
          tool: "passive_recon",
        });
      }
    }
    // Technologies / WAF / CDN
    if (asset.passiveRecon?.technologies) {
      for (const tech of asset.passiveRecon.technologies) {
        broadcastReconFinding(state.engagementId, {
          target: asset.hostname || asset.ip,
          technology: typeof tech === "string" ? tech : tech.name,
          tool: "passive_recon",
        });
      }
    }
  }
}

// ─── Tool Output Parser ────────────────────────────────────────────────────

// ─── Tool Output Parsing (extracted to tool-output-parsers.ts) ────────────────
import { parseToolOutput, type ParsedFinding } from "./tool-output-parsers";
// Re-export for backward compatibility with any external consumers
export type { ParsedFinding } from "./tool-output-parsers";


async function executeEnumeration(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  const { executeEnumeration: runEnumerationPhase } = await import('./engagement-phase-enumeration');
  return runEnumerationPhase(state, engagement, operatorCtx);
}
export async function executeVulnDetection(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "vuln_detection";
  state.currentAction = "Running vulnerability detection...";
  const scanServerHost = process.env.SCAN_SERVER_HOST || '';
  addLog(state, { phase: "vuln_detection", type: "info", title: "🛡️ Phase 6: Vulnerability Scanning", detail: "Running nuclei scans and ZAP web app scans" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "vuln_detection" });

  // ── Shared context for all Phase 6 sub-modules ──
  const phase6Ctx: any = {
    state,
    engagement,
    operatorCtx,
    scanServerHost,
    // Core helpers
    addLog,
    broadcastOpsUpdate,
    broadcastReconFinding,
    pushVulnDeduped,
    persistOpsStateDebounced,
    persistScanResult,
    executeToolViaQueue,
    acquireScanSlot,
    getScanConcurrencyMetrics,
    genId,
    breathe,
    invokeLLM,
    throttledLLMCall,
    // Scope & targeting
    isInRoeScope,
    getEffectiveTarget,
    fmtTarget,
    // Approval & decisions
    requestApproval,
    llmDecide,
    captureDecision,
    scoreEngagementThreatAttribution,
    // Tool output parsing
    parseToolOutput,
    // Abort & ScanForge
    getEngagementAbortSignal,
    executeScanForgePhase,
  };

  // ── Phase 6a: Vulnerability Preparation (delegated to vuln-detection/vuln-prep.ts) ──
  const { executeVulnPrep } = await import('./vuln-detection/vuln-prep');
  // vuln-prep uses ctx.helpers.* pattern (legacy interface)
  const vulnPrepCtx = {
    state,
    engagement,
    operatorCtx,
    scanServerHost,
    helpers: {
      addLog,
      broadcastOpsUpdate,
      pushVulnDeduped,
      persistOpsStateDebounced,
      persistScanResult,
      executeToolViaQueue,
      acquireScanSlot,
      getScanConcurrencyMetrics,
      genId,
      breathe,
      invokeLLM,
      throttledLLMCall,
    },
  };
  const vulnPrepResult = await executeVulnPrep(vulnPrepCtx);
  const burpAppLogin = vulnPrepResult.burpAppLogin;
  const initialPipelineResult = vulnPrepResult.initialPipelineResult;

  // Attach prep results to shared context for sub-modules that need them
  phase6Ctx.burpAppLogin = burpAppLogin;
  phase6Ctx.initialPipelineResult = initialPipelineResult;

  // ── Phase 6b: Nuclei Scanning (delegated to vuln-detection/nuclei-scanner.ts) ──
  const { executeNucleiScanning } = await import('./vuln-detection/nuclei-scanner');
  const nucleiResult = await executeNucleiScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Nuclei Complete", detail: `${nucleiResult.findingsCount} findings, ${nucleiResult.errorsCount} errors` });

  // ── Phase 6c: ZAP Web Application Scanning (delegated to vuln-detection/zap-scanner.ts) ──
  const { executeZapScanning } = await import('./vuln-detection/zap-scanner');
  const zapResult = await executeZapScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "ZAP Complete", detail: `${zapResult.findingsCount} findings across ${zapResult.webAppsScanned} targets` });

  // ── Phase 6d: Injection Scanning — SQLMap, XSStrike, Commix, tplmap (delegated to vuln-detection/injection-scanner.ts) ──
  const { executeInjectionScanning } = await import('./vuln-detection/injection-scanner');
  const injectionResult = await executeInjectionScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Injection Scanning Complete", detail: `${injectionResult.totalFindings} findings` });

  // ── Phase 6e: Credential Testing — Hydra (delegated to vuln-detection/credential-tester.ts) ──
  const { executeCredentialTesting } = await import('./vuln-detection/credential-tester');
  const credResult = await executeCredentialTesting(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Credential Testing Complete", detail: `${credResult.credentialsConfirmed} credentials confirmed` });

  // ── Phase 6e.1: Authenticated ZAP Re-Scan (if Hydra found credentials) ──
  if (credResult.credentialsConfirmed > 0) {
    try {
      const assetsWithCreds = state.assets.filter((a: any) =>
        a.confirmedCredentials && a.confirmedCredentials.length > 0 &&
        a.confirmedCredentials.some((c: any) =>
          ['http', 'https', 'web_admin', 'http-form', 'http-get', 'http-post'].includes(c.service) ||
          c.protocol === 'http' || c.protocol === 'https'
        )
      );

      if (assetsWithCreds.length > 0) {
        addLog(state, {
          phase: "vuln_detection", type: "info",
          title: `🔐 Authenticated ZAP Re-Scan: ${assetsWithCreds.length} target(s)`,
          detail: `Hydra found web credentials — re-running ZAP with authenticated sessions to discover vulns behind login pages`,
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

        const { executeZapScanning } = await import('./vuln-detection/zap-scanner');
        // Mark this as an authenticated re-scan pass
        const authRescanCtx = { ...phase6Ctx, authenticatedRescan: true, rescanAssets: assetsWithCreds };
        await executeZapScanning(authRescanCtx);

        addLog(state, {
          phase: "vuln_detection", type: "info",
          title: `🔐 Authenticated Re-Scan Complete`,
          detail: `${state.stats.zapScansRun} total ZAP scans (includes authenticated pass)`,
        });
      }
    } catch (authRescanErr: any) {
      console.warn(`[Phase6e.1] Authenticated ZAP re-scan failed:`, authRescanErr.message);
      addLog(state, {
        phase: "vuln_detection", type: "warning",
        title: `Authenticated Re-Scan Skipped`,
        detail: `Error: ${authRescanErr.message?.slice(0, 200)}`,
      });
    }
  }

  // ── Phase 6f: Vuln Correlation — LLM analysis, specialists, dedup, coverage gaps (delegated to vuln-detection/vuln-correlation.ts) ──
  const { executeVulnCorrelation } = await import('./vuln-detection/vuln-correlation');
  const correlationResult = await executeVulnCorrelation(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Vuln Correlation Complete", detail: `${correlationResult.deduplicatedCount} unique findings after dedup` });

  // ── Phase 6 Summary ──
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "✅ Phase 6 Complete", detail: `${state.stats.vulnsFound} vulns found (post-dedup), ${state.stats.zapScansRun} ZAP scans, ${state.stats.wafDetections} WAFs detected` });
  broadcastOpsUpdate(state.engagementId, {
    type: "phase_complete",
    title: "✅ Phase 6 Complete",
    detail: `${state.stats.vulnsFound} vulns found (post-dedup), ${state.stats.zapScansRun} ZAP scans, ${state.stats.wafDetections} WAFs detected`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

async function executeExploitation(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  const { executeExploitation: runExploitPhase } = await import('./engagement-phase-exploitation');
  return runExploitPhase(state, engagement, operatorCtx);
}

async function executePostExploit(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  const { executePostExploit: runPostExploitPhase } = await import('./engagement-phase-post-exploit');
  return runPostExploitPhase(state, engagement, operatorCtx);
}

// ─── Main Execution Pipeline ────────────────────────────────────────────────

export async function executeEngagement(
  engagementId: number,
  operatorCtx: { id: string; name?: string },
  options?: {
    startPhase?: 'recon' | 'passive_discovery' | 'scoping' | 'test_plan' | 'enumeration' | 'vuln_detection' | 'social_engineering' | 'exploitation' | 'post_exploit';
    resume?: boolean; // If true, resume from last saved phase instead of startPhase
    scanProfile?: 'quick' | 'standard' | 'deep' | 'stealth';
  }
): Promise<void> {
  let startPhase = options?.startPhase || 'recon';

  // ═══ CAPACITY CHECK ═══
  // Count actively running engagements (exclude completed/error/idle)
  const runningCount = [...opsStates.values()].filter(s => s.isRunning && s.phase !== 'completed' && s.phase !== 'error').length;
  if (runningCount >= MAX_CONCURRENT_ENGAGEMENTS) {
    const errState = opsStates.get(engagementId) || initOpsState(engagementId, 'pentest');
    addLog(errState, {
      phase: 'idle', type: 'error',
      title: `⛔ Capacity Limit Reached (${MAX_CONCURRENT_ENGAGEMENTS} concurrent)`,
      detail: `Cannot start engagement — ${runningCount} engagements are already running. Wait for one to complete or stop an active engagement.`,
    });
    errState.phase = 'error';
    errState.error = `Capacity limit: ${runningCount}/${MAX_CONCURRENT_ENGAGEMENTS} concurrent engagements`;
    return;
  }

  // ═══ CLAIM LOCK ═══
  // Acquire ownership so no other server instance can run this engagement simultaneously
  try {
    const { claimEngagement } = await import('./engagement-claim-lock');
    // User-initiated actions force-claim to override stale claims from dead servers
    const claim = await claimEngagement(engagementId, { force: true });
    if (!claim.claimed) {
      const errState = opsStates.get(engagementId) || initOpsState(engagementId, 'pentest');
      addLog(errState, {
        phase: 'idle', type: 'error',
        title: `⛔ Engagement Owned by Another Server`,
        detail: `Cannot start: another server instance (${claim.currentOwner}) owns this engagement. ${claim.reason}`,
      });
      errState.phase = 'error';
      errState.error = `Claim denied: owned by ${claim.currentOwner}`;
      return;
    }
  } catch (e: any) {
    console.warn(`[ExecuteEngagement] Claim lock check failed (proceeding): ${e.message}`);
  }

  let state = opsStates.get(engagementId);

  // ═══ DURABLE STATE RESUME ═══
  // If resume=true, try to recover from DB snapshot and continue from last phase
  if (options?.resume && !state) {
    try {
      const recovered = await getOpsStateWithRecovery(engagementId);
      if (recovered && recovered.phase !== 'completed' && recovered.phase !== 'error' && recovered.phase !== 'idle') {
        state = recovered;
        // Use explicit startPhase from options if provided (caller already computed next phase)
        // Otherwise advance to the next phase after the recovered one
        const phaseOrder: OpsPhase[] = ['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit'];
        if (options?.startPhase) {
          startPhase = options.startPhase;
        } else {
          // ═══ RESUME FROM SAME PHASE (not next) ═══
          // Previously this advanced to the NEXT phase, which caused ZAP/Burp scans
          // to be skipped if the server crashed during vuln_detection.
          // Now we resume from the SAME phase — the completedScans tracking
          // (nucleiCompleted, zapCompleted, hydraCompleted, etc.) ensures that
          // already-finished work within the phase is skipped automatically.
          startPhase = recovered.phase as any;
        }
        const recoveredPhaseLabel = recovered.phase.replace(/_/g, ' ');
        const startPhaseLabel = (startPhase as string).replace(/_/g, ' ');
        addLog(state, {
          phase: state.phase, type: 'info',
          title: '🔄 Resumed from Checkpoint',
          detail: `State recovered from DB snapshot.\n` +
            `Last completed phase: ${recoveredPhaseLabel}\n` +
            `Continuing from: ${startPhaseLabel}\n` +
            `Preserved: ${state.assets.length} assets, ${state.stats.vulnsFound} vulns, ${state.stats.portsFound} ports, ${state.log.length} log entries`,
        });
        console.log(`[OpsState] Resuming engagement #${engagementId}: ${recoveredPhaseLabel} → ${startPhaseLabel} (${state.assets.length} assets, ${state.stats.vulnsFound} vulns)`);
      }
    } catch (e: any) {
      console.error(`[OpsState] Resume failed for #${engagementId}:`, e.message);
    }
  }

  if (!state) {
    state = initOpsState(engagementId, "pentest");
  }

  // Fetch engagement details
  let engagement: any;
  try {
    const db = await import("../db");
    engagement = await db.getEngagementById(engagementId);
    if (!engagement) throw new Error("Engagement not found");
    state.engagementType = engagement.engagementType || "pentest";
  } catch (e: any) {
    state.error = e.message;
    state.phase = "error";
    return;
  }
  // Re-detect trainingLabMode if it was lost during state recovery (e.g., server restart)
  if (state.trainingLabMode === undefined) {
    const domain = engagement.targetDomain || '';
    if (domain.includes('aceofcloud.io') || domain.includes('aceofcloud.com') || (engagement as any).labName) {
      state.trainingLabMode = true;
      console.log(`[ExecuteEngagement] Training lab mode re-detected for #${engagementId} (domain: ${domain})`);
    }
  }
  // Debug: log engagement fields for restart resilience diagnosis
  console.log(`[ExecuteEngagement] #${engagementId} loaded from DB: roeStatus=${JSON.stringify(engagement.roeStatus)}, trainingLabMode=${state.trainingLabMode}, startPhase=${startPhase}, resume=${options?.resume}`);
  // Check RoE status.
  // A digitally signed RoE is preferred but NOT required: operators may run an
  // engagement that was manually assigned or verbally approved by the customer,
  // or that has a customer-provided RoE / approved Test Plan uploaded. Only a
  // clearly invalid status (e.g. 'expired') blocks active operations.
  if (engagement.roeStatus !== "signed" && engagement.roeStatus !== "pending" && engagement.roeStatus !== "none" && engagement.roeStatus && !state.trainingLabMode) {
    addLog(state, {
      phase: "idle",
      type: "error",
      title: "⚠️ RoE Not Valid",
      detail: `Rules of Engagement status is "${engagement.roeStatus}". Resolve the RoE (sign, or set to a valid status) before active operations. Only passive recon is allowed.`,
    });
  } else if (!state.trainingLabMode && engagement.roeStatus !== "signed") {
    // Launching without a digitally signed RoE — record an explicit operator
    // attestation so there is an audit trail for the manual/verbal-approval and
    // customer-provided-document cases.
    const attestor = operatorCtx.name || operatorCtx.id || (engagement.createdBy != null ? `user#${engagement.createdBy}` : "operator");
    addLog(state, {
      phase: "idle",
      type: "info",
      title: "📝 Launching without a digitally signed RoE",
      detail: `RoE status: "${engagement.roeStatus || "none"}". Proceeding under operator-attested manual/verbal customer authorization (attestor: ${attestor}). A digitally signed RoE or approved Test Plan is preferred — upload it to the engagement when available.`,
    });
    console.warn(`[Orchestrator] Engagement #${engagementId} launched without a signed RoE (status=${engagement.roeStatus || "none"}); recorded operator attestation by ${attestor}.`);
  }

  state.isRunning = true;
  if (!state.startedAt) state.startedAt = Date.now();
  state.phase = startPhase;
  if (options?.scanProfile) state.scanProfile = options.scanProfile;

  // ═══ DOMAIN SAFETY WHITELIST ENFORCEMENT ═══
  // Validate all targets against the approved domain whitelist.
  // Non-whitelisted domains are forcibly capped at passive_only unless
  // the admin has set active_scan_override on the engagement.
  const domainValidation = validateEngagementTargets(engagement.targetDomain, engagement.targetIpRange);
  let domainWhitelistOverride = false;
  if (!domainValidation.allWhitelisted && !state.trainingLabMode) {
    // Check for admin override
    try {
      const mysql = await import('mysql2/promise');
      const tmpConn = await mysql.createConnection(process.env.DATABASE_URL!);
      const [rows] = await tmpConn.query('SELECT active_scan_override FROM engagements WHERE id = ?', [engagementId]);
      domainWhitelistOverride = !!(rows as any)?.[0]?.active_scan_override;
      await tmpConn.end();
    } catch {}
    if (!domainWhitelistOverride) {
      addLog(state, {
        phase: state.phase, type: 'info',
        title: '🛡️ Domain Whitelist: Non-Approved Targets Detected',
        detail: `${domainValidation.nonWhitelistedCount} target(s) are NOT on the approved test lab whitelist: ${domainValidation.nonWhitelistedTargets.join(', ')}. ` +
          `Safety level will be capped at passive_only. Active scanning, exploitation, and C2 are BLOCKED. ` +
          `An admin can enable "Active Scan Override" on this engagement to authorize active testing.`,
      });
      console.warn(`[Orchestrator] Domain whitelist enforcement: capping engagement #${engagementId} to passive_only (non-whitelisted: ${domainValidation.nonWhitelistedTargets.join(', ')})`);
    } else {
      addLog(state, {
        phase: state.phase, type: 'info',
        title: '⚠️ Domain Whitelist: Admin Override Active',
        detail: `${domainValidation.nonWhitelistedCount} target(s) are not on the whitelist (${domainValidation.nonWhitelistedTargets.join(', ')}), ` +
          `but an admin has enabled Active Scan Override. Full pipeline authorized per admin authorization.`,
      });
    }
  } else if (domainValidation.allWhitelisted) {
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '✅ Domain Whitelist: All Targets Approved',
      detail: `All ${domainValidation.totalTargets} target(s) are on the approved test lab whitelist. Full pipeline access authorized.`,
    });
  }

  // ═══ SAFETY ENGINE INITIALIZATION ═══
  // Initialize or retrieve the safety engine for this engagement.
  // The safety level is derived from the engagement's scanMode:
  //   strict_passive → passive_only, standard → standard, active → full_exploitation
  const scanModeToSafety: Record<string, SafetyLevel> = {
    strict_passive: "passive_only",
    passive: "passive_only",
    standard: "standard",
    active: "full_exploitation",
    aggressive: "full_exploitation",
  };
  let engagementSafetyLevel: SafetyLevel = scanModeToSafety[engagement.scanMode || "standard"] || "standard";

  // ═══ AUTO-ESCALATION: RoE-approved Pentest/Red Team engagements always get full pipeline access ═══
  // When the RoE is signed and the engagement type is pentest or red_team,
  // automatically escalate to full_exploitation so the entire pipeline
  // (recon → enum → vuln detection → exploitation → C2 → lateral movement → exfiltration)
  // runs without safety blocks. The RoE approval IS the authorization.
  const roeSigned = engagement.roeStatus === 'signed';
  const offensiveType = ['pentest', 'red_team', 'purple_team'].includes(engagement.engagementType);
  if (roeSigned && offensiveType && engagementSafetyLevel !== 'full_exploitation') {
    const originalLevel = engagementSafetyLevel;
    engagementSafetyLevel = 'full_exploitation';
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '🔓 Safety Auto-Escalated: RoE Approved',
      detail: `Engagement type '${engagement.engagementType}' with signed RoE — safety level escalated from '${originalLevel}' to 'full_exploitation'. Full scan-to-exploit-to-C2 pipeline authorized.`,
    });
  }

  // ═══ TRAINING LAB AUTO-ESCALATION ═══
  // Training lab engagements always get full_exploitation since they target intentionally vulnerable apps
  if (state.trainingLabMode && engagementSafetyLevel !== 'full_exploitation') {
    const originalLevel = engagementSafetyLevel;
    engagementSafetyLevel = 'full_exploitation';
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '🔓 Safety Auto-Escalated: Training Lab',
      detail: `Training lab mode detected — safety level escalated from '${originalLevel}' to 'full_exploitation'. Full pipeline authorized for intentionally vulnerable target.`,
    });
  }

  // ═══ DOMAIN WHITELIST SAFETY CAP (FINAL ENFORCEMENT) ═══
  // This runs AFTER all auto-escalation logic. If targets are not whitelisted
  // and there's no admin override, forcibly cap to passive_only regardless of
  // RoE status, engagement type, or scan mode. This is the ultimate guardrail.
  if (!domainValidation.allWhitelisted && !state.trainingLabMode && !domainWhitelistOverride) {
    if (engagementSafetyLevel !== 'passive_only') {
      const cappedFrom = engagementSafetyLevel;
      engagementSafetyLevel = 'passive_only';
      addLog(state, {
        phase: state.phase, type: 'info',
        title: '🛑 Safety Level Capped: Non-Whitelisted Targets',
        detail: `Safety level forcibly capped from '${cappedFrom}' to 'passive_only' because ${domainValidation.nonWhitelistedCount} target(s) ` +
          `(${domainValidation.nonWhitelistedTargets.join(', ')}) are not on the approved whitelist. ` +
          `Enable "Active Scan Override" on this engagement to remove this restriction.`,
      });
    }
  }

  const safetyEngine = getSafetyEngine(engagementId, engagementSafetyLevel);
  addLog(state, {
    phase: state.phase, type: "info",
    title: `🛡️ Safety Engine Active — Level: ${safetyEngine.getProfile().label}`,
    detail: `Safety level '${engagementSafetyLevel}' ${roeSigned && offensiveType ? '(auto-escalated from RoE-approved ' + engagement.engagementType + ')' : 'initialized from scan mode \'' + (engagement.scanMode || 'standard') + '\''}.\n` +
      `Credential testing: ${safetyEngine.getProfile().allowCredentialTesting ? '✅' : '❌'}\n` +
      `Exploitation: ${safetyEngine.getProfile().allowExploitation ? '✅' : '❌'}\n` +
      `C2 deployment: ${safetyEngine.getProfile().allowC2Deployment ? '✅' : '❌'}\n` +
      `Max blast radius: ${engagementSafetyLevel === 'passive_only' ? 5 : engagementSafetyLevel === 'low_impact' ? 30 : engagementSafetyLevel === 'standard' ? 60 : 100}`,
  });
  broadcastOpsUpdate(engagementId, { type: "safety_init", level: engagementSafetyLevel });

  // ═══ DUAL-APPROVAL ENFORCEMENT LOG ═══
  if (safetyEngine.getProfile().dualApprovalRequired) {
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '🔐 Dual-Approval Enforcement Active',
      detail: `Safety profile '${safetyEngine.getProfile().label}' requires two independent approvers for red-tier gates. ` +
        `Each exploit/C2/post-exploit approval must be confirmed by two distinct operators before execution proceeds.`,
    });
  }

  // ═══ STATS RECALCULATION ═══
  // Ensure stats reflect actual asset data (fixes vulnsFound=0 after reset/resume)
  if (state.assets.length > 0) {
    state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + (a.vulns || []).length, 0);
    state.stats.portsFound = state.assets.reduce((sum, a) => sum + (a.ports || []).length, 0);
    state.stats.assetsDiscovered = state.assets.length;
  }

  // ═══ ENGAGEMENT CONTEXT (shared across all LLM specialist calls) ═══
  try {
    const { buildEngagementContext } = await import('./llm-specialists/hybrid-scorer');
    state.engagementContext = buildEngagementContext({
      engagementType: state.engagementType,
      clientName: engagement.clientName || engagement.name || 'Unknown',
      industry: engagement.sector || engagement.industry || undefined,
      scope: engagement.scope || state.assets.map(a => a.hostname).join(', '),
      targetCount: state.assets.length || 1,
      domains: state.assets.map(a => a.hostname),
      rulesOfEngagement: engagement.roeStatus === 'signed'
        ? (engagement.roeNotes || 'Signed RoE on file')
        : undefined,
    });
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '🧠 Context Engine Initialized',
      detail: `Sector: ${state.engagementContext.inferredSector || 'auto-detect'} | Type: ${state.engagementType} | Compliance: ${state.engagementContext.complianceFrameworks?.join(', ') || 'none'} | RoE: ${engagement.roeStatus}`,
    });
  } catch (e: any) {
    console.error('[OpsState] Context engine init failed:', e.message);
    // Non-fatal — specialists will work without context
  }

  // ═══ OWASP COVERAGE TRACKING ═══
  // Reset tracker at engagement start, register asset tech as discovered
  const owaspTracker = resetOwaspTracker();

  // ═══ PER-USER CREDENTIAL CONTEXT ═══
  // Set the active user for per-user HackerOne API credential resolution.
  // This ensures bug bounty intelligence calls use the operator's own API keys.
  try {
    const { setActiveUser } = await import('./bug-bounty-intelligence');
    setActiveUser(operatorCtx.id);
    console.log(`[CredentialCtx] Set active user to ${operatorCtx.id} (${operatorCtx.name || 'unknown'}) for engagement #${engagementId}`);
  } catch (e: any) {
    console.warn('[CredentialCtx] Failed to set active user:', e.message);
  }

  emitSystemNotification({
    title: options?.resume ? "Engagement Resumed" : "Engagement Execution Started",
    message: `Autonomous ${state.engagementType} execution ${options?.resume ? 'resumed' : 'started'} for engagement #${engagementId} (from ${startPhase})`,
    severity: "info",
  });

  // Helper: checkpoint state to DB after each phase completes
  async function phaseCheckpoint(completedPhase: string) {
    // ═══ POST-PHASE VULN CLASSIFICATION ═══
    // Ensure all vulns have a vulnClass assigned (catches any that bypassed pushVulnDeduped)
    let classifiedCount = 0;
    for (const asset of state.assets) {
      for (const vuln of (asset.vulns || [])) {
        if (!vuln.vulnClass || vuln.vulnClass === 'unknown') {
          const newClass = classifyVulnClass(vuln.title || '', vuln.description);
          if (newClass !== 'unknown') {
            vuln.vulnClass = newClass;
            classifiedCount++;
          }
        }
      }
    }
    if (classifiedCount > 0) {
      console.log(`[VulnClassify] Eng#${engagementId} phase=${completedPhase}: classified ${classifiedCount} vulns`);
    }
    await persistOpsStateNow(engagementId);
    console.log(`[OpsState] Phase checkpoint saved: ${completedPhase} for engagement #${engagementId}`);
    // ═══ POST-PHASE MEMORY CLEANUP ═══
    // State is now safely in DB. Strip heavy data from memory to prevent OOM.
    try {
      const { postPhaseCleanup, logMemoryProfile } = await import('./memory-manager');
      logMemoryProfile(engagementId, state, `pre-cleanup-${completedPhase}`);
      const cleanup = postPhaseCleanup(state, completedPhase);
      logMemoryProfile(engagementId, state, `post-cleanup-${completedPhase}`);
      console.log(`[MemCleanup] Eng#${engagementId} phase=${completedPhase}: freed ~${(cleanup.freedEstimateBytes / 1024).toFixed(0)}KB, actions: ${cleanup.actions.join(', ')}`);
    } catch (e: any) {
      console.error(`[MemCleanup] Failed for #${engagementId}:`, e.message);
    }
    // ═══ REAL-TIME OWASP COVERAGE UPDATE ═══
    try {
      // Re-populate tracker from current state after each phase
      const phaseTracker = resetOwaspTracker();
      for (const asset of state.assets) {
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) phaseTracker.registerAssetTech(asset.hostname, tech);
        for (const tr of asset.toolResults) {
          phaseTracker.addToolRun({ tool: tr.tool, target: asset.hostname, command: tr.command, exitCode: tr.exitCode });
          for (const f of tr.findings) {
            phaseTracker.addFinding({ title: f.title, severity: f.severity, tool: tr.tool, target: asset.hostname });
          }
        }
        for (const v of asset.vulns) {
          phaseTracker.addFinding({ title: v.title, severity: v.severity, tool: 'nuclei', target: asset.hostname });
        }
        for (const z of asset.zapFindings) {
          phaseTracker.addFinding({ title: z.alert, severity: z.risk, tool: 'zap', target: asset.hostname });
        }
      }
      const liveCoverage = phaseTracker.getEngagementCoverage(String(engagementId));
      const grade = liveCoverage.overallScore >= 90 ? 'A' : liveCoverage.overallScore >= 80 ? 'B' : liveCoverage.overallScore >= 70 ? 'C' : liveCoverage.overallScore >= 60 ? 'D' : 'F';
      // Flatten per-asset categories into a single list (deduplicate by category ID, pick worst status)
      const categoryMap = new Map<string, { id: string; name: string; status: string; score: number; findingsCount: number }>();
      for (const asset of liveCoverage.assets || []) {
        for (const cat of asset.categories || []) {
          const existing = categoryMap.get(cat.categoryId);
          const catScore = cat.status === 'tested' ? 100 : cat.status === 'partial' ? 50 : cat.status === 'not_applicable' ? -1 : 0;
          if (!existing || catScore < existing.score) {
            categoryMap.set(cat.categoryId, {
              id: cat.categoryId,
              name: cat.categoryName || cat.categoryId,
              status: cat.status,
              score: catScore,
              findingsCount: cat.findingsCount || 0,
            });
          }
        }
      }
      broadcastOpsUpdate(engagementId, {
        type: 'owasp_coverage_update',
        phase: completedPhase,
        owaspCoverage: {
          overallScore: liveCoverage.overallScore,
          grade,
          totalTested: liveCoverage.totalTested,
          totalPartial: liveCoverage.totalPartial,
          totalGaps: liveCoverage.totalGaps,
          criticalGaps: liveCoverage.criticalGaps.length,
          categories: [...categoryMap.values()],
        },
      });
    } catch (e: any) {
      console.error(`[OWASP Coverage] Real-time update failed after ${completedPhase}:`, e.message);
    }
  }

  // ═══ PHASE ACTIVITY HEARTBEAT ═══
  // Detect stalls: if no new log entries for 5 minutes, emit a heartbeat warning.
  // If no activity for 10 minutes, log a stall warning.
  // After 2 consecutive stall warnings (20 min total), abort the stuck phase via AbortController
  // so the pipeline can advance to the next phase instead of hanging indefinitely.
  let lastActivityAt = Date.now();
  const STALL_WARNING_MS = 5 * 60_000;
  // Phase-aware stall threshold: scan-heavy phases (enumeration, vuln_detection, exploitation)
  // need longer timeouts because tools like Nikto/Nuclei run 5+ min each sequentially.
  const SCAN_HEAVY_PHASES = new Set(['enumeration', 'vuln_detection', 'exploitation', 'targeted_enum', 'discovery']);
  const STALL_FORCE_MS_DEFAULT = 10 * 60_000;
  const STALL_FORCE_MS_SCAN = 20 * 60_000; // 20 min for scan-heavy phases
  const MAX_STALL_COUNT = 2; // After 2 stall detections, force-abort
  let consecutiveStalls = 0;
  let lastStallPhase = '';
  const heartbeatInterval = setInterval(() => {
    if (!state.isRunning || state.phase === 'completed' || state.phase === 'error') {
      clearInterval(heartbeatInterval);
      return;
    }
    // ── Skip stall detection when paused for approval ──
    // When the pipeline is legitimately waiting for human approval (dual-approval gates),
    // idle time is expected and should NOT count toward stall detection.
    if (state.isPaused && state.approvalGates?.some(g => g.status === 'pending')) {
      // Reset activity timer so stall counter doesn't accumulate while waiting for approval
      lastActivityAt = Date.now();
      if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now();
      consecutiveStalls = 0; // Clear any prior stall count from before the approval gate
      return;
    }
    // Read from shared heartbeat ref (updated by phase executors during long ops)
    const currentLastActivity = (state as any)._heartbeatRef?.lastActivityAt || lastActivityAt;
    const idleMs = Date.now() - currentLastActivity;
    const effectiveStallMs = SCAN_HEAVY_PHASES.has(state.phase) ? STALL_FORCE_MS_SCAN : STALL_FORCE_MS_DEFAULT;
    if (idleMs > effectiveStallMs) {
      // Track consecutive stalls in the same phase
      if (lastStallPhase === state.phase) {
        consecutiveStalls++;
      } else {
        consecutiveStalls = 1;
        lastStallPhase = state.phase;
      }

      if (consecutiveStalls >= MAX_STALL_COUNT) {
        // Force-abort: cancel in-flight operations for this engagement
        addLog(state, {
          phase: state.phase, type: 'error',
          title: `\u26A0\uFE0F Phase Force-Abort: ${state.phase}`,
          detail: `Phase stalled for ${Math.round(idleMs / 60_000)} minutes (${consecutiveStalls} consecutive stalls). ` +
            `Aborting stuck operations to allow pipeline to advance. This typically means an LLM call or external tool timed out.`,
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        // Abort in-flight operations — this will cause pending awaits to reject with AbortError
        abortEngagement(state.engagementId);
        // Create a fresh controller so subsequent phases can still run
        const freshController = new AbortController();
        engagementAbortControllers.set(state.engagementId, freshController);
        consecutiveStalls = 0;
        console.error(`[Heartbeat] FORCE-ABORT engagement #${engagementId} phase ${state.phase} after ${MAX_STALL_COUNT} stalls`);
      } else {
        addLog(state, {
          phase: state.phase, type: 'warning',
          title: `\u23F0 Phase Stall Detected: ${state.phase} (${consecutiveStalls}/${MAX_STALL_COUNT})`,
          detail: `No activity for ${Math.round(idleMs / 60_000)} minutes. Phase may be stuck on an LLM call or external tool. ` +
            `Will force-abort after ${MAX_STALL_COUNT - consecutiveStalls} more stall(s).`,
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
      }
      lastActivityAt = Date.now(); // Reset to avoid spamming
      if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now();
    } else if (idleMs > STALL_WARNING_MS) {
      console.warn(`[Heartbeat] Engagement #${engagementId} phase ${state.phase}: idle for ${Math.round(idleMs / 1000)}s`);
    }
  }, 60_000); // Check every minute

  // ═══ PERIODIC FORCED PERSISTENCE (P4) ═══
  // Force-persist state every 60s to minimize data loss on hard crashes (OOM/SIGKILL).
  // The debounced persistence (2s) handles normal saves, but on a hard kill the debounce
  // timer never fires. This guarantees max 60s of data loss instead of "since last phase checkpoint".
  const PERIODIC_PERSIST_INTERVAL_MS = 60_000;
  let lastPeriodicPersistAt = Date.now();
  // Clear any existing periodic timer for this engagement (e.g. from a previous run)
  const existingPeriodicTimer = periodicPersistTimers.get(engagementId);
  if (existingPeriodicTimer) clearInterval(existingPeriodicTimer);
  const periodicPersistInterval = setInterval(async () => {
    if (!state.isRunning || state.phase === 'completed' || state.phase === 'error') {
      clearInterval(periodicPersistInterval);
      periodicPersistTimers.delete(engagementId);
      return;
    }
    try {
      const { saveOpsSnapshot } = await import('../db');
      await saveOpsSnapshot(engagementId, state);
      const elapsed = Math.round((Date.now() - lastPeriodicPersistAt) / 1000);
      lastPeriodicPersistAt = Date.now();
      console.log(`[PeriodicPersist] Engagement #${engagementId}: state saved (phase=${state.phase}, progress=${state.progress}%, assets=${state.assets.length}, logs=${state.log.length}, interval=${elapsed}s)`);
    } catch (e: any) {
      console.error(`[PeriodicPersist] Failed for engagement #${engagementId}: ${e.message}`);
    }
  }, PERIODIC_PERSIST_INTERVAL_MS);
  periodicPersistTimers.set(engagementId, periodicPersistInterval);

  // Share lastActivityAt via state so phase executors can update it during long-running operations
  (state as any)._heartbeatRef = { lastActivityAt };

  // Wire heartbeat propagation: when do-scan-api completes a tool, update the stall detector
  registerHeartbeatUpdater((eid) => {
    if (eid === engagementId) {
      lastActivityAt = Date.now();
      if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now();
    }
  });

  try {
    // Phase 1: Domain Recon (skip if starting from a later phase)
    if (startPhase === 'recon') {
      const reconGate = safetyEngine.canEnterPhase('recon');
      if (!reconGate.allowed) {
        addLog(state, { phase: 'recon', type: 'warning', title: '🛡️ Safety: Recon Blocked', detail: reconGate.reason });
      } else {
        await executeRecon(state, engagement, operatorCtx);
        await breathe(); // yield event loop between phases
        // ─── Customer Integration Bridge: Recon ───
        try {
          const { executeCustomerIntegrationsForStage, mergeIntegrationResultsIntoObservations } = await import('./integration-registry/pipeline-bridge');
          const custReconResults = await executeCustomerIntegrationsForStage({
            engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'recon',
            targetIps: state.assets.flatMap(a => a.ips || []),
          });
          if (custReconResults.length > 0) {
            const successCount = custReconResults.filter(r => r.status === 'success').length;
            const totalRecords = custReconResults.reduce((s, r) => s + r.recordsReturned, 0);
            addLog(state, { phase: 'recon', type: 'info', title: '🔌 Customer Integrations (Recon)', detail: `${successCount}/${custReconResults.length} sources executed, ${totalRecords} records enriched` });
          }
        } catch (e: any) { addLog(state, { phase: 'recon', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
        await phaseCheckpoint('recon');
        if (!state.isRunning) return;
      }
    }

    // Phase 2: Passive Discovery & Enumeration (pre-RoE, no active scanning)
    if (['recon', 'passive_discovery'].includes(startPhase)) {
      try {
        await executePassiveDiscovery(state, engagement, addLog, broadcastOpsUpdate);
        await breathe(); // yield event loop between phases
        // ─── Customer Integration Bridge: Passive Discovery ───
        try {
          const { executeCustomerIntegrationsForStage } = await import('./integration-registry/pipeline-bridge');
          const custPassiveResults = await executeCustomerIntegrationsForStage({
            engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'passive_discovery',
            targetIps: state.assets.flatMap(a => a.ips || []),
          });
          if (custPassiveResults.length > 0) {
            const successCount = custPassiveResults.filter(r => r.status === 'success').length;
            const totalRecords = custPassiveResults.reduce((s, r) => s + r.recordsReturned, 0);
            addLog(state, { phase: 'passive_discovery', type: 'info', title: '🔌 Customer Integrations (Passive)', detail: `${successCount}/${custPassiveResults.length} sources executed, ${totalRecords} records enriched` });
          }
        } catch (e: any) { addLog(state, { phase: 'passive_discovery', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
        state.progress = 15;
        await phaseCheckpoint('passive_discovery');
        if (!state.isRunning) return;

        // ═══ HYPOTHESIS GENERATOR — Auto-generate vulnerability hypotheses from recon data ═══
        try {
          const { runHypothesisGeneration, formatHypothesisLogEntry, buildScanPriorityAdjustments } = await import('./hypothesis-orchestrator-hook');
          const hypothesisResult = await runHypothesisGeneration(state);
          if (hypothesisResult.generated) {
            const logEntry = formatHypothesisLogEntry(hypothesisResult);
            addLog(state, { phase: 'passive_discovery', type: 'info', title: logEntry.title, detail: logEntry.detail, data: { hypothesisResult } });
            broadcastOpsUpdate(engagementId, { type: 'hypothesis_generated', hypothesisCount: hypothesisResult.hypothesisCount, highConfidence: hypothesisResult.highConfidenceCount });
            // Store scan priority adjustments for scan plan generation
            const priorities = buildScanPriorityAdjustments(state);
            if (priorities.length > 0) {
              (state.metadata as any).hypothesisScanPriorities = priorities;
              addLog(state, { phase: 'passive_discovery', type: 'info', title: `🎯 Scan Priority Adjustments: ${priorities.length} endpoints prioritized`, detail: priorities.slice(0, 5).map(p => `• [${p.priority.toUpperCase()}] ${p.endpoint} — ${p.vulnClass}: ${p.reason}`).join('\n') });
            }
            console.log(`[HypothesisGen] Engagement #${engagementId}: ${hypothesisResult.hypothesisCount} hypotheses generated (${hypothesisResult.highConfidenceCount} high-confidence)`);
          }
        } catch (hypErr: any) {
          console.warn(`[HypothesisGen] Failed for #${engagementId}:`, hypErr.message);
          addLog(state, { phase: 'passive_discovery', type: 'warning', title: '⚠️ Hypothesis Generation Failed', detail: hypErr.message });
        }
      } catch (err: any) {
        addLog(state, { phase: 'passive_discovery', type: 'warning', title: 'Passive Discovery Error', detail: err.message });
      }
    }

    // Phase 3: Scoping & RoE Review
    if (['recon', 'passive_discovery', 'scoping'].includes(startPhase)) {
      try {
        await executeScopingReview(state, engagement, addLog, broadcastOpsUpdate);
        state.progress = 20;
        await phaseCheckpoint('scoping');
        if (!state.isRunning) return;
      } catch (err: any) {
        addLog(state, { phase: 'scoping', type: 'warning', title: 'Scoping Review Error', detail: err.message });
      }
    }

    // Phase 4: Test Plan Generation (NIST 800-115 aligned)
    if (['recon', 'passive_discovery', 'scoping', 'test_plan'].includes(startPhase)) {
      try {
        const testPlan = await executeTestPlanGeneration(state, engagement, addLog, broadcastOpsUpdate);
        state.progress = 25;
        await phaseCheckpoint('test_plan');
        if (!state.isRunning) return;

        // Phase 4b: Test Plan Approval Gate
        await executeTestPlanApproval(state, addLog, broadcastOpsUpdate);
        // Note: In production, the pipeline would pause here for customer approval.
        // For now, auto-approve if RoE is signed (operator trust model).
        if (engagement.roeStatus === 'signed') {
          state.testPlan!.status = 'approved';
          state.testPlan!.approvedAt = Date.now();
          addLog(state, {
            phase: 'test_plan_approval', type: 'info',
            title: '✅ Test Plan Auto-Approved',
            detail: 'RoE is signed — test plan auto-approved under operator trust model. In production, this would await explicit customer approval.',
          });
        }
        state.progress = 30;
        await phaseCheckpoint('test_plan_approval');
        if (!state.isRunning) return;
      } catch (err: any) {
        addLog(state, { phase: 'test_plan', type: 'warning', title: 'Test Plan Generation Error', detail: err.message });
      }
    }

    // Phase 5+: Require RoE for active scanning (training lab mode bypasses RoE)
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending" || engagement.roeStatus === "none" || !engagement.roeStatus || state.trainingLabMode === true) {
      // Phase 5: Active Discovery & Enumeration (ScanForge first — always)
      if (['recon', 'passive_discovery', 'scoping', 'test_plan', 'enumeration'].includes(startPhase)) {
        const enumGate = safetyEngine.canEnterPhase('enumeration');
        if (!enumGate.allowed) {
          addLog(state, { phase: 'enumeration', type: 'warning', title: '🛡️ Safety: Enumeration Blocked', detail: `${enumGate.reason}. Requires safety level '${enumGate.requiredLevel}' or higher.` });
        } else {
          // ═══ PRE-ENGAGEMENT SCAN SERVER HEALTH CHECK ═══
          // Validate SSH connectivity and tool availability before starting active phases.
          // This prevents wasted time and confusing 0-result phases when the scan server is unreachable.
          try {
            const { checkScanServerStatus } = await import('./scan-server-executor');
            const serverHealth = await checkScanServerStatus();
            if (!serverHealth.connected) {
              addLog(state, {
                phase: 'enumeration', type: 'warning',
                title: '⚠️ Scan Server Unreachable',
                detail: `Pre-engagement health check failed: ${serverHealth.error || 'SSH connection refused'}. ` +
                  `Active scanning phases (enumeration, vuln detection, exploitation) may produce 0 results. ` +
                  `Verify scan server is running and SSH credentials are correct.`,
              });
              broadcastOpsUpdate(engagementId, { type: 'log_update' });
            } else {
              const toolNames = Object.entries(serverHealth.tools || {})
                .filter(([, info]) => info.installed)
                .map(([name]) => name);
              const missingTools = ['nmap', 'nuclei', 'httpx', 'zap-cli'].filter(
                t => !toolNames.some(tn => tn.toLowerCase().includes(t))
              );
              addLog(state, {
                phase: 'enumeration', type: 'info',
                title: '✅ Scan Server Health Check Passed',
                detail: `SSH connected. Available tools: ${toolNames.slice(0, 10).join(', ')}${toolNames.length > 10 ? ` (+${toolNames.length - 10} more)` : ''}` +
                  (missingTools.length > 0 ? `\nMissing recommended tools: ${missingTools.join(', ')}` : '') +
                  (serverHealth.diskFree ? `\nDisk: ${serverHealth.diskFree}` : '') +
                  (serverHealth.memoryFree ? ` | Memory: ${serverHealth.memoryFree}` : ''),
              });
            }
          } catch (healthErr: any) {
            addLog(state, {
              phase: 'enumeration', type: 'warning',
              title: '⚠️ Scan Server Health Check Failed',
              detail: `Could not validate scan server: ${healthErr.message}. Proceeding with active phases — results may be limited.`,
            });
          }

          try {
            await executeEnumeration(state, engagement, operatorCtx);
          } catch (enumErr: any) {
            // Handle AbortError from force-abort gracefully — allow pipeline to continue
            if (enumErr?.name === 'AbortError' || enumErr?.message?.includes('abort') || enumErr?.message?.includes('Abort')) {
              addLog(state, { phase: 'enumeration', type: 'warning', title: '⚡ Enumeration Force-Aborted', detail: 'Phase was force-aborted due to stall. Continuing to next phase with partial results.' });
            } else {
              addLog(state, { phase: 'enumeration', type: 'error', title: '❌ Enumeration Error', detail: `${enumErr?.message || enumErr}`.slice(0, 500) });
            }
          }
          await breathe(); // yield event loop between phases
          // ─── Customer Integration Bridge: Enumeration ───
          try {
            const { executeCustomerIntegrationsForStage } = await import('./integration-registry/pipeline-bridge');
            const custEnumResults = await executeCustomerIntegrationsForStage({
              engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'enumeration',
              targetIps: state.assets.flatMap(a => a.ips || []),
              assets: state.assets.map(a => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType })),
            });
            if (custEnumResults.length > 0) {
              const successCount = custEnumResults.filter(r => r.status === 'success').length;
              const totalRecords = custEnumResults.reduce((s, r) => s + r.recordsReturned, 0);
              addLog(state, { phase: 'enumeration', type: 'info', title: '🔌 Customer Integrations (Enum)', detail: `${successCount}/${custEnumResults.length} sources executed, ${totalRecords} records enriched` });
            }
          } catch (e: any) { addLog(state, { phase: 'enumeration', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
          await phaseCheckpoint('enumeration');
          if (!state.isRunning) return;
        }
      }

      // Phase 6: Vulnerability Scanning (safety gated)
      if (['recon', 'passive_discovery', 'scoping', 'test_plan', 'enumeration', 'vuln_detection'].includes(startPhase)) {
        const vulnGate = safetyEngine.canEnterPhase('vuln_detection');
        if (!vulnGate.allowed) {
          addLog(state, { phase: 'vuln_detection', type: 'warning', title: '🛡️ Safety: Vuln Detection Blocked', detail: `${vulnGate.reason}. Requires safety level '${vulnGate.requiredLevel}' or higher.` });
        } else {
          try {
            await executeVulnDetection(state, engagement, operatorCtx);
          } catch (vulnErr: any) {
            if (vulnErr?.name === 'AbortError' || vulnErr?.message?.includes('abort') || vulnErr?.message?.includes('Abort')) {
              addLog(state, { phase: 'vuln_detection', type: 'warning', title: '⚡ Vuln Detection Force-Aborted', detail: 'Phase was force-aborted due to stall. Continuing to next phase with partial results.' });
            } else {
              addLog(state, { phase: 'vuln_detection', type: 'error', title: '❌ Vuln Detection Error', detail: `${vulnErr?.message || vulnErr}`.slice(0, 500) });
            }
          }
          await breathe(); // yield event loop between phases
          // ─── Customer Integration Bridge: Vuln Detection ───
          try {
            const { executeCustomerIntegrationsForStage } = await import('./integration-registry/pipeline-bridge');
            const custVulnResults = await executeCustomerIntegrationsForStage({
              engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'vuln_detection',
              targetIps: state.assets.flatMap(a => a.ips || []),
              assets: state.assets.map(a => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType })),
            });
            if (custVulnResults.length > 0) {
              const successCount = custVulnResults.filter(r => r.status === 'success').length;
              const totalRecords = custVulnResults.reduce((s, r) => s + r.recordsReturned, 0);
              addLog(state, { phase: 'vuln_detection', type: 'info', title: '🔌 Customer Integrations (Vuln)', detail: `${successCount}/${custVulnResults.length} sources executed, ${totalRecords} records enriched` });
            }
          } catch (e: any) { addLog(state, { phase: 'vuln_detection', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
          await phaseCheckpoint('vuln_detection');
          if (!state.isRunning) return;

        // Phase 3.4: Coalition ESS CVE Enrichment
        // Enrich all CVE findings with CESS scores, EPSS, exploit availability, CISA KEV flags
        if (state.stats.vulnsFound > 0) {
          try {
            const { batchEnrichCves, summarizeExploitIntelligence } = await import('./coalition-ess');
            const allCves = state.assets.flatMap(a => a.vulns.map(v => v.cve).filter((c): c is string => !!c && /^CVE-\d{4}-\d{4,}$/.test(c)));
            const uniqueCves = [...new Set(allCves)];
            if (uniqueCves.length > 0) {
              state.currentAction = `Enriching ${uniqueCves.length} CVEs with Coalition ESS intelligence...`;
              addLog(state, {
                phase: 'vuln_detection', type: 'info',
                title: '\uD83D\uDD0D Coalition ESS CVE Enrichment',
                detail: `Querying Coalition ESS API for ${uniqueCves.length} unique CVEs — CESS scores, EPSS, exploit availability, CISA KEV flags`,
              });
              broadcastOpsUpdate(state.engagementId, { type: 'action', action: 'ess_enrichment' });

              const essResult = await batchEnrichCves(uniqueCves);
              const intel = summarizeExploitIntelligence(essResult.enrichments);

              // Attach ESS enrichment to each vuln on each asset
              for (const asset of state.assets) {
                for (const vuln of asset.vulns) {
                  if (vuln.cve && essResult.enrichments.has(vuln.cve)) {
                    const ess = essResult.enrichments.get(vuln.cve)!;
                    (vuln as any).essEnrichment = {
                      cessScore: ess.cess.probabilityExploitUsage,
                      cvssBase: ess.cvss.baseScore,
                      cvssVector: ess.cvss.vectorString,
                      epssScore: ess.epss.score,
                      exploitdbCount: ess.exploits.exploitdb.numExploits,
                      metasploitCount: ess.exploits.metasploit.numExploits,
                      cisaKev: ess.visibility.cisaKev,
                      githubPocs: ess.social.github.numReposWithPocKeyword,
                      riskTier: ess.riskTier,
                      riskSummary: ess.riskSummary,
                    };
                    // Upgrade severity if ESS indicates higher risk
                    if (ess.riskTier === 'critical' && vuln.severity !== 'critical') {
                      vuln.severity = 'critical';
                    }
                  }
                }
              }

              // Store ESS summary in state for UI and LLM context
              (state as any).essIntelligence = {
                totalCvesEnriched: essResult.enrichments.size,
                cisaKevCount: intel.cisaKevCount,
                metasploitCount: intel.metasploitCount,
                exploitdbCount: intel.exploitdbCount,
                highCessCount: intel.highCessCount,
                criticalRiskCount: intel.criticalRiskCount,
                highRiskCount: intel.highRiskCount,
                topThreats: intel.topThreats.slice(0, 5),
                cacheHits: essResult.cacheHits,
                apiCalls: essResult.apiCalls,
                durationMs: essResult.durationMs,
                errors: essResult.errors.length,
              };

              const kevMsg = intel.cisaKevCount > 0 ? ` \u26A0\uFE0F ${intel.cisaKevCount} CISA KEV listed!` : '';
              const msfMsg = intel.metasploitCount > 0 ? ` ${intel.metasploitCount} with Metasploit modules.` : '';
              addLog(state, {
                phase: 'vuln_detection', type: intel.cisaKevCount > 0 ? 'warning' : 'info',
                title: '\u2705 ESS Enrichment Complete',
                detail: `Enriched ${essResult.enrichments.size}/${uniqueCves.length} CVEs in ${(essResult.durationMs / 1000).toFixed(1)}s. ` +
                  `${intel.criticalRiskCount} critical, ${intel.highRiskCount} high risk.${kevMsg}${msfMsg}`,
              });
              broadcastOpsUpdate(state.engagementId, { type: 'phase_complete', phase: 'ess_enrichment' });
            }
          } catch (err: any) {
            addLog(state, {
              phase: 'vuln_detection', type: 'warning',
              title: '\u26A0\uFE0F ESS Enrichment Failed',
              detail: `Coalition ESS enrichment error: ${err.message}. Continuing without enrichment.`,
            });
          }
        }

        // Phase 3.5: Specialized Vulnerability Analysis (Shannon-inspired)
        // Run dedicated analysis agents per vulnerability class for deeper insights
        if (state.stats.vulnsFound > 0) {
          try {
            state.currentAction = 'Running specialized vulnerability analysis agents...';
            addLog(state, {
              phase: 'vuln_detection', type: 'info',
              title: '🧠 Specialized Vuln Analysis',
              detail: `Dispatching ${state.stats.vulnsFound} findings to specialized analysis agents (injection, XSS, auth, config, crypto, etc.)`,
            });
            broadcastOpsUpdate(state.engagementId, { type: 'action', action: 'vuln_analysis_agents' });

             const { batchAnalyzeFindings, generateAnalysisSummary, classifyVulnerability } = await import('./vuln-analysis-agents');
            // Collect all findings from all assets, enriched with tool result context
            const allFindings = state.assets.flatMap(asset => {
              // Build a lookup of tool outputs for this asset so findings get context
              const toolOutputMap = new Map<string, string>();
              for (const tr of (asset.toolResults || [])) {
                if (tr.outputPreview && tr.findingCount > 0) {
                  const existing = toolOutputMap.get(tr.tool) || '';
                  toolOutputMap.set(tr.tool, (existing + '\n' + tr.outputPreview).slice(0, 1024));
                }
              }
              return asset.vulns.map((v, idx) => {
                // Try to find the tool that produced this finding from the title prefix
                const toolMatch = v.title?.match(/^\[(\w+)\]/)?.[1]?.toLowerCase();
                const toolOutput = toolMatch ? toolOutputMap.get(toolMatch) : undefined;
                return {
                  id: `${asset.hostname}-${idx}`,
                  title: v.title || v.id || 'Unknown',
                  severity: v.severity || 'medium',
                  description: v.description,
                  cve: v.cve,
                  asset: asset.hostname,
                  port: v.port || (asset.ports.length > 0 ? asset.ports[0].port : undefined),
                  service: v.service || (asset.ports.length > 0 ? asset.ports[0].service : undefined),
                  rawOutput: v.rawOutput || v.rawEvidence || toolOutput,
                  tool: v.tool || v.source || toolMatch,
                };
              });
            });

            // Build services map for context
            const servicesMap: Record<string, string[]> = {};
            for (const asset of state.assets) {
              servicesMap[asset.hostname] = asset.ports.map(p => `${p.port}/${p.service || 'unknown'}`);
            }

            // Run analysis (max 3 concurrent agents)
            const analysisResults = await batchAnalyzeFindings(allFindings, {
              maxConcurrency: 3,
              services: servicesMap,
            });

            // Apply FP suppression before storing
            const { applySuppressionRules } = await import('./knowledge/fp-suppression-rules');
            const suppressionProfile = (state as any).metadata?.fpSuppressionProfile || 'balanced';
            const { kept, suppressed, stats: suppressionStats } = applySuppressionRules(
              analysisResults,
              suppressionProfile
            );

            // Store both kept and suppressed for UI toggle
            (state as any).vulnAnalysis = kept;
            (state as any).vulnAnalysisSuppressed = suppressed;
            (state as any).fpSuppressionStats = suppressionStats;

            if (suppressionStats.suppressed > 0) {
              addLog(state, {
                phase: 'vuln_detection', type: 'info',
                title: `🔇 FP Suppression: ${suppressionStats.suppressed} findings filtered (${suppressionProfile} profile)`,
                detail: `Kept: ${suppressionStats.kept} | Suppressed: ${suppressionStats.suppressed} | Rules: ${Object.entries(suppressionStats.byRule).map(([r,c]) => `${r}:${c}`).join(', ')}`,
                data: { suppressionStats },
              });

              // ═══ FIX: Also remove suppressed findings from asset.vulns ═══
              // Previously, FP suppression only removed from vulnAnalysis but left
              // asset.vulns untouched, causing the UI stat to show inflated counts.
              const suppressedTitles = new Set(
                suppressed.map((s: any) => (s.finding?.title || '').toLowerCase().trim())
              );
              const suppressedCves = new Set(
                suppressed
                  .map((s: any) => s.finding?.cve || s.finding?.cves?.[0])
                  .filter(Boolean)
              );
              let assetVulnsRemoved = 0;
              for (const asset of state.assets) {
                const before = asset.vulns.length;
                asset.vulns = asset.vulns.filter((v: any) => {
                  const titleMatch = suppressedTitles.has((v.title || '').toLowerCase().trim());
                  const cveMatch = v.cve && suppressedCves.has(v.cve);
                  // Only suppress if severity is NOT critical/high (matching FP rule behavior)
                  const sev = (v.severity || '').toLowerCase();
                  if (sev === 'critical' || sev === 'high') return true;
                  return !titleMatch && !cveMatch;
                });
                assetVulnsRemoved += before - asset.vulns.length;
              }
              if (assetVulnsRemoved > 0) {
                state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
                addLog(state, {
                  phase: 'vuln_detection', type: 'info',
                  title: `🧹 Asset vulns cleaned: ${assetVulnsRemoved} FP findings removed from asset data`,
                  detail: `vulnsFound recalculated: ${state.stats.vulnsFound}`,
                });
              }
            }

            // Generate summary from kept findings (post-suppression)
            const summary = generateAnalysisSummary(kept);

            // Log the classification breakdown
            const classBreakdown = Object.entries(summary.byClass)
              .map(([cls, count]) => `${cls}: ${count}`)
              .join(', ');

            addLog(state, {
              phase: 'vuln_detection', type: 'phase_complete',
              title: `✅ Vuln Analysis Complete — ${analysisResults.length} findings analyzed`,
              detail: `Agent classes: ${classBreakdown}\nAvg risk score: ${summary.avgRiskScore}/10\nChainable: ${summary.chainableCount}\nTop risk: ${summary.topRisks[0]?.title || 'none'} (${summary.topRisks[0]?.riskScore || 0}/10)`,
              data: { summary },
            });

            // Log high-confidence, high-risk findings
            const criticalFindings = analysisResults
              .filter(r => r.analysis.riskScore >= 8 && r.analysis.confidence === 'high')
              .sort((a, b) => b.analysis.riskScore - a.analysis.riskScore);

            for (const cf of criticalFindings.slice(0, 5)) {
              addLog(state, {
                phase: 'vuln_detection', type: 'finding',
                title: `🚨 High-Risk: ${cf.finding.title} [${cf.agentClass}]`,
                detail: `Risk: ${cf.analysis.riskScore}/10 | ${cf.analysis.technicalAnalysis.substring(0, 200)}...\nPoC: ${cf.analysis.poc || 'N/A'}`,
                data: { analysis: cf },
              });
            }
          } catch (analysisErr: any) {
            console.error('[VulnAgents] Batch analysis failed:', analysisErr.message);
            addLog(state, {
              phase: 'vuln_detection', type: 'warning',
              title: '⚠️ Vuln Analysis Agents Failed',
              detail: `Specialized analysis could not complete: ${analysisErr.message}. Proceeding with raw findings.`,
            });
          }
        }
      }

      // Phase 3.7: LLM Scan Feedback Loop — adaptive re-scanning
      // The LLM analyzes all findings so far and requests targeted re-scans
      // to fill information gaps before attack planning.
      if (state.stats.vulnsFound > 0 || state.assets.some(a => (a as any).cloudProviders?.length > 0)) {
        try {
          state.currentAction = 'Running LLM scan feedback loop — adaptive re-scanning...';
          addLog(state, {
            phase: 'vuln_detection', type: 'info',
            title: '🔄 LLM Scan Feedback Loop',
            detail: 'LLM is analyzing all findings to identify information gaps and request targeted re-scans with optimal tool selection.',
          });
          broadcastOpsUpdate(state.engagementId, { type: 'action', action: 'llm_scan_feedback' });

          const { runFeedbackLoop, getFeedbackLoopSummary } = await import('./llm-scan-feedback');

          // Collect all findings into a flat array for the LLM
          const allFindingsForLLM = state.assets.flatMap(asset => [
            ...asset.vulns.map(v => ({
              type: 'vulnerability',
              title: v.title,
              severity: v.severity,
              cve: v.cve,
              target: asset.hostname,
              host: getEffectiveTarget(asset, 'http'),
              port: (v as any).port,
              service: (v as any).service,
              details: (v as any).description || v.title,
            })),
            ...asset.ports.map(p => ({
              type: 'service',
              title: `${p.service || 'unknown'} on port ${p.port}`,
              severity: 'info',
              target: asset.hostname,
              host: getEffectiveTarget(asset, 'http'),
              port: p.port,
              service: p.service,
              details: p.version ? `${p.service} ${p.version}` : p.service,
            })),
            ...(asset.zapFindings || []).map(z => ({
              type: 'web_vuln',
              title: z.alert || z.name,
              severity: z.risk || 'info',
              target: asset.hostname,
              host: getEffectiveTarget(asset, 'http'),
              details: z.url || '',
            })),
            // Include tool result summaries so the LLM can see what tools already ran
            // and their output previews for richer context
            ...(asset.toolResults || []).filter(tr => tr.findingCount > 0 || tr.outputPreview).map(tr => ({
              type: 'tool_result',
              title: `[${tr.tool}] ${tr.findingCount} findings (exit ${tr.exitCode}, ${tr.phase})`,
              severity: tr.findingCount > 0 ? 'info' : 'low',
              target: asset.hostname,
              host: getEffectiveTarget(asset, 'http'),
              details: tr.outputPreview ? tr.outputPreview.slice(0, 500) : `${tr.tool} ran with ${tr.findingCount} findings`,
              tool: tr.tool,
              phase: tr.phase,
            })),
          ]);

          // Add cloud findings
          const cloudDetection = (state as any).cloudDetection;
          if (cloudDetection?.findings) {
            for (const cf of cloudDetection.findings) {
              allFindingsForLLM.push({
                type: 'cloud_misconfiguration',
                title: cf.title,
                severity: cf.severity,
                target: cf.asset,
                host: cf.asset,
                details: `${cf.provider} ${cf.service}: ${cf.title}`,
              });
            }
          }

          const scope = {
            targets: state.assets.map(a => getEffectiveTarget(a, 'http')),
            engagementName: engagement?.name || `Engagement #${state.engagementId}`,
          };

          // P0-FIX: Training lab targets get more aggressive feedback loop settings
          const isFeedbackTrainingLab = state.trainingLabMode || ['brokencrystals', 'broken-crystals', 'dvwa', 'juiceshop', 'juice-shop', 'bwapp', 'altoro', 'hackazon', 'testphp', 'webgoat', 'mutillidae', 'bodgeit', 'gruyere'].some(lab => state.assets.some(a => a.hostname.toLowerCase().includes(lab)));
          const feedbackState = await runFeedbackLoop(allFindingsForLLM, scope, {
            maxIterations: isFeedbackTrainingLab ? 5 : 5,
            maxTotalScans: isFeedbackTrainingLab ? 20 : 12,
            maxScansPerIteration: isFeedbackTrainingLab ? 6 : 4,
            minIterations: isFeedbackTrainingLab ? 3 : 0,
            staleThreshold: isFeedbackTrainingLab ? 3 : 2,
            engagementId: state.engagementId,
            onProgress: (fbState) => {
              state.currentAction = `LLM feedback loop: iteration ${fbState.iteration + 1}, ${fbState.totalScansExecuted} scans executed`;
              broadcastOpsUpdate(state.engagementId, {
                type: 'action',
                action: 'llm_feedback_progress',
                data: { iteration: fbState.iteration, scans: fbState.totalScansExecuted },
              });
            },
          });

          // Ingest re-scan findings into asset vulns
          let newFindingsCount = 0;
          for (const h of feedbackState.history) {
            if (h.result.exitCode === 0 && h.result.stdout.length > 10) {
              const targetAsset = state.assets.find(
                a => a.hostname === h.request.target || a.ip === h.request.target
              );
              if (targetAsset) {
                const parsedFindings = parseToolOutput(h.request.tool, h.result.stdout, targetAsset);
                for (const pf of parsedFindings) {
                  if (pushVulnDeduped(targetAsset, {
                    id: `rescan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                    severity: pf.severity,
                    title: pf.title,
                    cve: pf.cve,
                    description: pf.description,
                    corroborationTier: 'confirmed',
                    evidenceDetail: `Confirmed by ${h.request.tool} re-scan`,
                    rawEvidence: pf.evidence ? JSON.stringify(pf.evidence).slice(0, 4000) : undefined,
                    source: h.request.tool,
                  })) {
                    state.stats.vulnsFound++;
                    newFindingsCount++;
                  }
                }
              }
              // Log each re-scan result
              addLog(state, {
                phase: 'vuln_detection', type: 'scan_result',
                title: `🔄 Re-scan: ${h.request.tool} → ${h.request.target}`,
                detail: `Rationale: ${h.request.rationale}\nExit: ${h.result.exitCode} | Duration: ${Math.round(h.result.durationMs / 1000)}s\nOutput preview: ${h.result.stdout.slice(0, 300)}`,
                data: { request: h.request, exitCode: h.result.exitCode },
              });
            }
          }

          const summary = getFeedbackLoopSummary(feedbackState);
          addLog(state, {
            phase: 'vuln_detection', type: 'phase_complete',
            title: `✅ LLM Feedback Loop Complete — ${feedbackState.totalScansExecuted} re-scans, ${newFindingsCount} new findings`,
            detail: `Iterations: ${feedbackState.iteration + 1} | Satisfied: ${feedbackState.satisfied}\n${feedbackState.finalAnalysis?.slice(0, 500) || ''}`,
            data: { feedbackState: { ...feedbackState, history: feedbackState.history.map(h => ({ tool: h.request.tool, target: h.request.target, exitCode: h.result.exitCode })) } },
          });

          // Store feedback loop state for attack chain designer
          (state as any).scanFeedbackLoop = feedbackState;
        } catch (feedbackErr: any) {
          console.error('[ScanFeedback] Feedback loop failed:', feedbackErr.message);
          addLog(state, {
            phase: 'vuln_detection', type: 'warning',
            title: '⚠️ LLM Feedback Loop Failed',
            detail: `Adaptive re-scanning could not complete: ${feedbackErr.message}. Proceeding with existing findings.`,
          });
        }
      }

      // Phase 3.8: LLM Attack Chain Design
      // Generate attack chains from all findings (including re-scan results)
      if (state.stats.vulnsFound > 0) {
        try {
          state.currentAction = 'Designing attack chains with LLM...';
          addLog(state, {
            phase: 'vuln_detection', type: 'info',
            title: '🧠 Attack Chain Design',
            detail: 'LLM is designing multi-stage attack chains from all vulnerability, cloud, and re-scan findings.',
          });
          broadcastOpsUpdate(state.engagementId, { type: 'action', action: 'attack_chain_design' });

          const { generateEngagementAttackChains } = await import('./cloud-attack-chain-designer');
          const attackChains = await generateEngagementAttackChains(
            state as any,
            engagement?.targetDescription || state.assets.map(a => a.hostname).join(', '),
          );

          (state as any).attackChains = attackChains;

          addLog(state, {
            phase: 'vuln_detection', type: 'phase_complete',
            title: `✅ Attack Chains Designed — ${attackChains.length} chains generated`,
            detail: attackChains.map((c, i) =>
              `Chain ${i + 1}: ${c.name} (risk: ${c.overallRisk}/10, feasibility: ${c.feasibility}/10, steps: ${c.totalSteps})`
            ).join('\n'),
            data: { chainCount: attackChains.length, chains: attackChains.map(c => ({ name: c.name, risk: c.overallRisk, feasibility: c.feasibility, steps: c.totalSteps })) },
          });
        } catch (chainErr: any) {
          console.error('[AttackChainDesigner] Chain design failed:', chainErr.message);
          addLog(state, {
            phase: 'vuln_detection', type: 'warning',
            title: '⚠️ Attack Chain Design Failed',
            detail: `LLM attack chain generation could not complete: ${chainErr.message}. Proceeding to exploitation with raw findings.`,
          });
        }
      }

      // ── Recalculate stats before exploitation decision ──
      state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
      state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);

      // ═══ SCANFORGE POST-SCAN COMPARISON ═══
      // Compare ScanForge findings with Nuclei/ZAP findings for accuracy tracking
      // scanforgeResult is stored on state by executeVulnDetection (was previously a scoping bug)
      const scanforgeResult = (state as any)._scanforgeResult as ScanForgeResult | null;
      if (scanforgeResult && scanforgeResult.stats.findingsTotal > 0) {
        try {
          const legacyFindings: Array<{ tool: string; title: string; target: string; severity: string; cve?: string }> = [];
          for (const asset of state.assets) {
            for (const v of asset.vulns) {
              if (!v.title.startsWith('[ScanForge]')) {
                legacyFindings.push({
                  tool: v.title.includes('ZAP') || v.title.includes('zap') ? 'zap' : 'nuclei',
                  title: v.title,
                  target: asset.hostname,
                  severity: v.severity,
                  cve: v.cve,
                });
              }
            }
          }
          await runPostEngagementAnalysis(
            String(state.engagementId),
            scanforgeResult,
            legacyFindings,
            (entry) => addLog(state, { ...entry, phase: entry.phase || 'vuln_detection', type: entry.type || 'info' }),
          );
        } catch (compErr: any) {
          console.warn('[ScanForge Comparison] Post-scan analysis failed:', compErr.message);
        }
      }

      // ═══ SCANNER-VERIFIED EXPLOIT PROMOTION (Nuclei + ZAP + Burp) ═══
      // Promote findings from Nuclei, ZAP, and Burp that already demonstrate exploitation
      // impact (data extraction, command execution, injection proof) to verified exploits.
      // These are counted as exploit successes and skipped during the exploitation phase.
      try {
        const { promoteAllScannerExploits } = await import('./nuclei-exploit-promotion');
        const promotionSummary = promoteAllScannerExploits(
          state.assets as any,
          state.stats,
          (entry) => addLog(state, entry as any),
        );

        if (promotionSummary.totalPromoted > 0) {
          const scannerBreakdown = Object.entries(promotionSummary.byScanner || {}).map(([k, v]) => `${k.toUpperCase()}: ${v}`).join(', ');
          addLog(state, {
            phase: 'vuln_detection', type: 'phase_complete',
            title: `⚡ Scanner Exploit Promotion: ${promotionSummary.totalPromoted} finding(s) promoted`,
            detail: `${promotionSummary.totalPromoted} scanner findings with demonstrated exploitation impact promoted to verified exploits.\n` +
              `By scanner: ${scannerBreakdown}\n` +
              `By category: ${Object.entries(promotionSummary.byCategory).map(([k, v]) => `${k}: ${v}`).join(', ')}\n` +
              `By confidence: ${Object.entries(promotionSummary.byConfidence).map(([k, v]) => `${k}: ${v}`).join(', ')}\n` +
              `Promoted: ${promotionSummary.promotedVulns.map(p => `${p.vulnTitle.slice(0, 50)} [${p.scanner}/${p.category}]`).join('; ')}`,
            data: { scannerPromotion: promotionSummary },
          });
        } else {
          addLog(state, {
            phase: 'vuln_detection', type: 'info',
            title: '⚡ Scanner Exploit Promotion: No findings qualified',
            detail: 'No Nuclei/ZAP/Burp findings met the promotion criteria for verified exploit status. All vulns will proceed to standard exploitation phase.',
          });
        }
      } catch (promoErr: any) {
        console.error('[ScannerPromotion] Promotion logic failed:', promoErr.message);
        addLog(state, {
          phase: 'vuln_detection', type: 'warning',
          title: '⚠️ Scanner Exploit Promotion Failed',
          detail: `Promotion logic encountered an error: ${promoErr.message}. Proceeding without promotions.`,
        });
      }

            // Phase 6b: Social Engineering / Phishing (ROE-gated, extracted module)
      {
        const { executeSocialEngineering } = await import('./engagement-phase-social-engineering');
        const socialEngResult = await executeSocialEngineering(
          state as any,
          engagement as any,
          {
            addLog: (entry) => addLog(state, entry),
            broadcastUpdate: (update) => broadcastOpsUpdate(state.engagementId, update),
          }
        );
        if (socialEngResult.phishingIntel) {
          (state as any).phishingIntel = socialEngResult.phishingIntel;
        }
        if (socialEngResult.executed) {
          await phaseCheckpoint('social_engineering');
          if (!state.isRunning) return;
        }
      }

            // Phase 7: Exploitation (safety gated)
      const exploitGate = safetyEngine.canEnterPhase('exploitation');
      if (!exploitGate.allowed) {
        addLog(state, { phase: 'exploitation', type: 'warning', title: '🛡️ Safety: Exploitation Blocked', detail: `${exploitGate.reason}. Requires safety level '${exploitGate.requiredLevel}' or higher. ${state.stats.vulnsFound} vulns found but exploitation is not permitted at current safety level.` });
      } else if (state.stats.vulnsFound > 0) {
        try {
          await executeExploitation(state, engagement, operatorCtx);
        } catch (exploitErr: any) {
          if (exploitErr?.name === 'AbortError' || exploitErr?.message?.includes('abort') || exploitErr?.message?.includes('Abort')) {
            addLog(state, { phase: 'exploitation', type: 'warning', title: '⚡ Exploitation Force-Aborted', detail: 'Phase was force-aborted due to stall. Continuing to next phase with partial results.' });
          } else {
            addLog(state, { phase: 'exploitation', type: 'error', title: '❌ Exploitation Error', detail: `${exploitErr?.message || exploitErr}`.slice(0, 500) });
          }
        }
        await breathe(); // yield event loop between phases
        // ─── Customer Integration Bridge: Exploitation ───
        try {
          const { executeCustomerIntegrationsForStage } = await import('./integration-registry/pipeline-bridge');
          const custExploitResults = await executeCustomerIntegrationsForStage({
            engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'exploitation',
            targetIps: state.assets.flatMap(a => a.ips || []),
            assets: state.assets.map(a => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType })),
          });
          if (custExploitResults.length > 0) {
            const successCount = custExploitResults.filter(r => r.status === 'success').length;
            addLog(state, { phase: 'exploitation', type: 'info', title: '🔌 Customer Integrations (Exploit)', detail: `${successCount}/${custExploitResults.length} sources executed` });
          }
        } catch (e: any) { addLog(state, { phase: 'exploitation', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
        await phaseCheckpoint('exploitation');
        if (!state.isRunning) return;
      } else {
        addLog(state, { phase: "exploitation", type: "info", title: "No Exploitable Vulns", detail: "No vulnerabilities found to exploit. Engagement complete." });
      }

      // Phase 8: Post-Exploit (safety gated)
      const postExploitGate = safetyEngine.canEnterPhase('post_exploit');
      if (!postExploitGate.allowed) {
        addLog(state, { phase: 'post_exploit', type: 'warning', title: '🛡️ Safety: Post-Exploit Blocked', detail: `${postExploitGate.reason}. Requires safety level '${postExploitGate.requiredLevel}' or higher.` });
      } else if (state.stats.exploitsSucceeded > 0) {
        await executePostExploit(state, engagement, operatorCtx);
        // ─── Customer Integration Bridge: Post-Exploit ───
        try {
          const { executeCustomerIntegrationsForStage } = await import('./integration-registry/pipeline-bridge');
          const custPostResults = await executeCustomerIntegrationsForStage({
            engagementId, targetDomain: state.assets[0]?.hostname || '', phase: 'post_exploit',
            targetIps: state.assets.flatMap(a => a.ips || []),
          });
          if (custPostResults.length > 0) {
            const successCount = custPostResults.filter(r => r.status === 'success').length;
            addLog(state, { phase: 'post_exploit', type: 'info', title: '🔌 Customer Integrations (Post-Exploit)', detail: `${successCount}/${custPostResults.length} sources executed` });
          }
        } catch (e: any) { addLog(state, { phase: 'post_exploit', type: 'warning', title: 'Customer Integration Warning', detail: e.message }); }
        await phaseCheckpoint('post_exploit');
      }
    } else {
      addLog(state, { phase: "enumeration", type: "error", title: "⛔ Active Phases Blocked", detail: "RoE must be signed to proceed past recon. Please have the team lead sign the RoE." });
    }

    // ═══ DEFERRED SCAN RETRY ═══
    // Retry any scans that failed due to infrastructure issues (ScanForge down, SSH failure)
    // before generating the final report, so we can collect remaining results.
    try {
      const { retryDeferredScans, getDeferredScans, clearDeferredScans } = await import('./job-queue-bridge');
      const deferred = getDeferredScans(engagementId);
      if (deferred.length > 0) {
        addLog(state, {
          phase: 'post_exploit', type: 'info',
          title: `🔄 Deferred Scan Retry: ${deferred.length} failed scans`,
          detail: `Retrying scans that failed due to infrastructure issues: ${deferred.map(d => d.config.tool).join(', ')}`,
        });
        const retryResults = await retryDeferredScans(engagementId, {
          engagementAbortSignal: engagementAbortSig,
          maxRetries: 2,
        });
        if (retryResults.length > 0) {
          addLog(state, {
            phase: 'post_exploit', type: 'info',
            title: `✅ Deferred Retry Success: ${retryResults.length}/${deferred.length} scans recovered`,
            detail: retryResults.map(r => `${r.tool}: exit=${r.result.exitCode}, stdout=${r.result.stdout?.length || 0}b`).join('\n'),
          });
          // Process recovered results — add findings to assets
          for (const { tool, result } of retryResults) {
            if (result.stdout && state.assets.length > 0) {
              const asset = state.assets[0]; // Primary asset
              const findings = parseToolOutput(tool, result.stdout, asset);
              for (const f of findings) {
                pushVulnDeduped(asset, {
                  id: genId(), severity: f.severity, title: f.title, cve: f.cve,
                  description: f.description, cvss: f.cvss, cwe: f.cwe,
                  corroborationTier: 'confirmed',
                  evidenceDetail: `Confirmed by ${tool} (deferred retry)`,
                  rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined,
                  source: tool,
                });
                state.stats.vulnsFound++;
              }
              asset.toolResults.push({
                tool, command: result.command || `${tool} (deferred)`,
                exitCode: result.exitCode, durationMs: result.durationMs || 0,
                timedOut: result.timedOut || false, findingCount: findings.length,
                findings: findings.map(f => ({ severity: f.severity, title: f.title })),
                outputPreview: result.stdout.slice(0, 512),
                executedAt: Date.now(), phase: 'deferred_retry',
              });
            }
          }
        } else {
          addLog(state, {
            phase: 'post_exploit', type: 'warning',
            title: `⚠️ Deferred Retry: 0/${deferred.length} scans recovered`,
            detail: `Infrastructure may still be unavailable. Failed tools: ${deferred.map(d => d.config.tool).join(', ')}`,
          });
        }
        clearDeferredScans(engagementId);
      }
    } catch (deferredErr: any) {
      console.error('[DeferredRetry] Failed:', deferredErr.message);
      addLog(state, { phase: 'post_exploit', type: 'error', title: 'Deferred Scan Retry Failed', detail: deferredErr.message });
    }

    // ═══ OWASP COVERAGE ANALYSIS ═══
    // Populate tracker from final state and generate coverage report
    try {
      for (const asset of state.assets) {
        // Register detected technologies
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) owaspTracker.registerAssetTech(asset.hostname, tech);
        // Register all tool runs and findings
        for (const tr of asset.toolResults) {
          owaspTracker.addToolRun({ tool: tr.tool, target: asset.hostname, command: tr.command, exitCode: tr.exitCode });
          for (const f of tr.findings) {
            owaspTracker.addFinding({ title: f.title, severity: f.severity, tool: tr.tool, target: asset.hostname });
          }
        }
        // Register vuln findings
        for (const v of asset.vulns) {
          owaspTracker.addFinding({ title: v.title, severity: v.severity, tool: 'nuclei', target: asset.hostname });
        }
        // Register ZAP findings
        for (const z of asset.zapFindings) {
          owaspTracker.addFinding({ title: z.alert, severity: z.risk, tool: 'zap', target: asset.hostname });
        }
      }
      const owaspCoverage = owaspTracker.getEngagementCoverage(String(engagementId));
      addLog(state, {
        phase: 'completed', type: 'info',
        title: `🛡️ OWASP Top 10:2025 Coverage: ${owaspCoverage.overallScore}%`,
        detail: `${owaspCoverage.totalTested} tested, ${owaspCoverage.totalPartial} partial, ${owaspCoverage.totalGaps} gaps, ${owaspCoverage.criticalGaps.length} critical gaps`,
        data: { owaspCoverage },
      });
    } catch (e: any) {
      console.error('[OWASP Coverage] Failed to generate coverage:', e.message);
    }

    // Complete
    clearInterval(heartbeatInterval); // Clean up heartbeat on completion
    clearInterval(periodicPersistInterval); // Clean up periodic persistence on completion

    // ═══ P0-3: TOOL FAILURE GATING ═══
    // If >50% of tools failed, mark engagement as DEGRADED instead of completed.
    // This prevents misleading "completed" status when scan infrastructure was broken.
    const allToolResults = state.assets.flatMap(a => a.toolResults || []);
    const totalToolRuns = allToolResults.length;
    const failedToolRuns = allToolResults.filter(tr =>
      tr.exitCode !== 0 || tr.timedOut || tr.durationMs < 100
    ).length;
    const toolFailureRate = totalToolRuns > 0 ? failedToolRuns / totalToolRuns : 0;
    const isDegraded = totalToolRuns >= 3 && toolFailureRate > 0.5; // Need at least 3 tool runs to judge

    // ═══ P0-4: X-SCAN-KEY VALIDATION ═══
    // Detect if the scan key is still the default placeholder "ADMIN123".
    // If so, all exploit attempts were likely blocked by scanner gateway auth.
    const scanKeyIsPlaceholder = SCAN_API_KEY === 'ADMIN123';
    const exploitBlockedByAuth = scanKeyIsPlaceholder && state.stats.exploitsAttempted > 0 && state.stats.exploitsSucceeded === 0;

    if (isDegraded) {
      state.phase = "degraded";
      addLog(state, {
        phase: 'degraded', type: 'error',
        title: '⚠️ ENGAGEMENT DEGRADED — Tool Failure Rate Exceeds 50%',
        detail: `${failedToolRuns}/${totalToolRuns} tool executions failed (${Math.round(toolFailureRate * 100)}%). ` +
          `Results are unreliable. Check scan server connectivity, tool installations, and resource limits. ` +
          `Report will include a DEGRADED banner.`,
        data: { toolFailureRate, failedToolRuns, totalToolRuns },
      });
    } else {
      state.phase = "completed";
    }

    if (exploitBlockedByAuth) {
      addLog(state, {
        phase: state.phase, type: 'error',
        title: '🔒 X-Scan-Key Still Using Default Placeholder (ADMIN123)',
        detail: `All ${state.stats.exploitsAttempted} exploit attempts likely blocked by scanner gateway authentication. ` +
          `The SCAN_API_KEY is still set to the default "ADMIN123" placeholder. ` +
          `Configure a real scan key in scan-service-url.ts or set SCAN_API_KEY env var.`,
        data: { scanKeyIsPlaceholder, exploitsAttempted: state.stats.exploitsAttempted, exploitsSucceeded: state.stats.exploitsSucceeded },
      });
    }

    state.progress = 100;
    state.isRunning = false;
    state.completedAt = Date.now();
    state.currentAction = undefined;
    // Store tool failure metrics for report pipeline consumption
    (state.stats as any).toolFailureRate = toolFailureRate;
    (state.stats as any).totalToolRuns = totalToolRuns;
    (state.stats as any).failedToolRuns = failedToolRuns;
    (state.stats as any).isDegraded = isDegraded;
    (state.stats as any).scanKeyIsPlaceholder = scanKeyIsPlaceholder;

    // ── Finding Deduplication Pipeline ──
    // Run IP-based dedup, ZAP noise filtering, and multi-tool consolidation
    // before counting vulns. This prevents inflated finding counts from:
    // 1. Multiple hostnames resolving to the same IP
    // 2. ZAP User Agent Fuzzer / CSP noise
    // 3. Same vuln reported by nuclei + ZAP + scanforge independently
    try {
      const { runDeduplicationPipeline } = await import('./finding-deduplication');
      const isRescan = !!(state as any).previousScanFindings;
      const dedupResult = await runDeduplicationPipeline(state.assets as any, {
        enableIpDedup: true,
        enableZapFilter: true,
        enableMultiToolConsolidation: true,
        enableRescanDedup: isRescan,
        existingFindings: isRescan ? (state as any).previousScanFindings : [],
        existingZapFindings: isRescan ? (state as any).previousZapFindings : [],
      });
      // Apply deduplicated assets back to state
      state.assets = dedupResult.assets as any;
      // Log deduplication results
      for (const logEntry of dedupResult.log) {
        addLog(state, { phase: 'completed', type: 'info', title: '🔍 Finding Deduplication', detail: logEntry });
      }
      if (dedupResult.stats.originalVulnCount !== dedupResult.stats.deduplicatedVulnCount) {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: `📉 Dedup Summary: ${dedupResult.stats.originalVulnCount} → ${dedupResult.stats.deduplicatedVulnCount} findings`,
          detail: `IP merges: ${dedupResult.stats.ipGroupsMerged}, ZAP noise: ${dedupResult.stats.zapNoiseFiltered}, Multi-tool: ${dedupResult.stats.multiToolMerged}, Re-scan dupes: ${dedupResult.stats.rescanDuplicatesRemoved}`,
        });
      }
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (dedupErr) {
      console.error('[Dedup] Finding deduplication pipeline error:', dedupErr);
      addLog(state, { phase: 'completed', type: 'warning', title: '⚠️ Deduplication Skipped', detail: `Pipeline error: ${(dedupErr as Error).message}` });
    }

    // ── Evidence-Gated Stats Recalculation ──
    // Classify each vuln's evidence status before counting.
    // A vuln is "evidence-backed" if it has:
    //   - corroborationTier === 'confirmed' (tool actively verified it), OR
    //   - rawEvidence or evidence field is non-empty (raw tool output attached), OR
    //   - source from an active scan tool (nuclei, zap, sqlmap, etc.)
    // Vulns without evidence are tagged 'unverified' and excluded from risk counts.
    const ACTIVE_SCAN_SOURCES = ['nuclei', 'zap', 'sqlmap', 'naabu', 'masscan', 'nerva', 'hydra', 'nikto', 'xss-scanner', 'metasploit', 'httpx', 'ffuf'];
    let totalVulns = 0;
    let verifiedVulns = 0;
    let unverifiedVulns = 0;
    for (const asset of state.assets) {
      for (const vuln of asset.vulns) {
        totalVulns++;
        const hasRawEvidence = !!(vuln.rawEvidence || vuln.evidence);
        const isConfirmed = vuln.corroborationTier === 'confirmed' || vuln.corroborationTier === 'corroborated';
        const isFromActiveScan = ACTIVE_SCAN_SOURCES.some(s => (vuln.source || '').toLowerCase().includes(s) || (vuln.title || '').toLowerCase().includes(`[${s}]`));
        if (hasRawEvidence || isConfirmed || isFromActiveScan) {
          if (!vuln.corroborationTier) vuln.corroborationTier = 'confirmed';
          verifiedVulns++;
        } else {
          vuln.corroborationTier = 'unverified';
          unverifiedVulns++;
        }
      }
    }
    // Also classify exploit attempts
    let verifiedExploits = 0;
    let unverifiedExploits = 0;
    for (const asset of state.assets) {
      for (const exploit of asset.exploitAttempts) {
        const hasExploitEvidence = !!(exploit.exploitOutput || exploit.httpEvidence || exploit.attackPayload);
        if (hasExploitEvidence) {
          verifiedExploits++;
        } else {
          unverifiedExploits++;
        }
      }
    }
    state.stats.vulnsFound = totalVulns;
    state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
    // Store evidence breakdown in stats for downstream use
    (state.stats as any).verifiedVulns = verifiedVulns;
    (state.stats as any).unverifiedVulns = unverifiedVulns;
    (state.stats as any).verifiedExploits = verifiedExploits;
    (state.stats as any).unverifiedExploits = unverifiedExploits;

    addLog(state, {
      phase: "completed",
      type: "phase_complete",
      title: "🏁 Engagement Execution Complete",
      detail: `${state.stats.hostsScanned} hosts, ${verifiedVulns} verified vulns (${unverifiedVulns} unverified — excluded from risk), ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits (${verifiedExploits} with evidence), ${state.stats.zapScansRun} ZAP scans`,
    });
    // ── Screenshot Evidence Capture ──
    try {
      const { selectFindingsForScreenshot, captureScreenshotBatch } = await import('./scanners/screenshot-capture');
      const allVulnsForScreenshot = state.assets.flatMap(a => {
        // Determine the base URL for this asset (for vulns without explicit endpoints)
        const assetBaseUrl = (() => {
          const host = a.hostname || a.ip;
          if (!host) return undefined;
          const httpPort = a.ports?.find((p: any) => p.service === 'http' || p.port === 80);
          const httpsPort = a.ports?.find((p: any) => p.service === 'https' || p.service === 'ssl/http' || p.port === 443);
          if (httpsPort) return `https://${host}${httpsPort.port !== 443 ? ':' + httpsPort.port : ''}`;
          if (httpPort) return `http://${host}${httpPort.port !== 80 ? ':' + httpPort.port : ''}`;
          // Default to https for web targets
          if (a.type === 'web_application' || a.type === 'subdomain') return `https://${host}`;
          return undefined;
        })();

        // Map vulns — use explicit endpoint/url, fall back to asset base URL
        const vulnEntries = (a.vulns || []).map((v: any) => ({
          id: v.id,
          title: v.title || v.name || 'Unknown',
          severity: v.severity || 'info',
          endpoint: v.endpoint || v.url || assetBaseUrl,
          url: v.endpoint || v.url || assetBaseUrl,
          source: v.source || v.tool,
          corroborationTier: v.corroborationTier,
        }));

        // Also include ZAP findings which always have URLs
        const zapEntries = (a.zapFindings || []).map((z: any) => ({
          id: `zap-${z.alert}-${z.url}`,
          title: z.alert || 'ZAP Finding',
          severity: z.risk || 'medium',
          endpoint: z.url,
          url: z.url,
          source: 'zap',
          corroborationTier: 'confirmed' as const,
        }));

        // Deduplicate: prefer vuln entries (which may already include ZAP vulns)
        const seenUrls = new Set(vulnEntries.filter(v => v.url).map(v => `${v.title}|${v.url}`));
        const uniqueZapEntries = zapEntries.filter(z => !seenUrls.has(`[ZAP] ${z.title}|${z.url}`));

        return [...vulnEntries, ...uniqueZapEntries];
      });
      const screenshotTargets = selectFindingsForScreenshot(allVulnsForScreenshot, 15);
      if (screenshotTargets.length > 0) {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: `\uD83D\uDCF8 Capturing ${screenshotTargets.length} evidence screenshots...`,
          detail: `Targeting ${screenshotTargets.filter(s => s.severity === 'critical' || s.severity === 'high').length} critical/high findings`,
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

        const screenshotRequests = screenshotTargets.map(t => ({
          url: t.url,
          engagementId,
          findingId: t.findingId,
          findingTitle: t.findingTitle,
          severity: t.severity,
        }));

        const screenshotResults = await captureScreenshotBatch(screenshotRequests, {
          maxConcurrency: 3,
          onProgress: (done, total) => {
            state.currentAction = `Capturing screenshots: ${done}/${total}`;
          },
        });

        let successCount = 0;
        let failCount = 0;
        for (const [key, result] of screenshotResults) {
          if (result.success) {
            successCount++;
            // Attach screenshot path to the corresponding vuln
            for (const asset of state.assets) {
              const vuln = (asset.vulns || []).find((v: any) =>
                (v.id === key || v.title === key || v.name === key)
              );
              if (vuln) {
                (vuln as any).screenshotPath = result.screenshotPath;
                (vuln as any).screenshotCapturedAt = result.capturedAt;
                (vuln as any).screenshotPageTitle = result.pageTitle;
                break;
              }
            }
          } else {
            failCount++;
          }
        }

        addLog(state, {
          phase: 'completed', type: successCount > 0 ? 'info' : 'warning',
          title: `\uD83D\uDCF8 Screenshots: ${successCount} captured, ${failCount} failed`,
          detail: `Evidence screenshots attached to ${successCount} findings`,
        });
      } else {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: '\uD83D\uDCF8 No web-accessible findings for screenshot capture',
          detail: 'Screenshots require HTTP-accessible vulnerability endpoints',
        });
      }
    } catch (ssErr: any) {
      console.warn('[ScreenshotCapture] Failed:', ssErr.message);
      addLog(state, {
        phase: 'completed', type: 'warning',
        title: '\u26A0\uFE0F Screenshot capture failed',
        detail: ssErr.message,
      });
    }

    // ── Attack Narrative Generation ──
    try {
      const { generateAttackNarratives, generateExecutiveSummary } = await import('./attack-narrative-generator');
      const narrativeInput = {
        engagementId: state.engagementId,
        engagementName: state.engagementName || `Engagement #${state.engagementId}`,
        targetProfile: state.targetProfiles ? {
          industry: state.identifiedOrg?.sector || state.engagementContext?.inferredSector || undefined,
          orgName: state.identifiedOrg?.orgName || undefined,
          orgSource: state.identifiedOrg?.source || undefined,
          waf: Object.values(state.targetProfiles as Record<string, any>)[0]?.waf?.vendor,
          cdn: Object.values(state.targetProfiles as Record<string, any>)[0]?.cdn?.provider,
          techStack: Object.values(state.targetProfiles as Record<string, any>)[0]?.fingerprint?.webServer
            ? [Object.values(state.targetProfiles as Record<string, any>)[0]?.fingerprint?.webServer]
            : [],
        } : undefined,
        assets: state.assets.map((a: any) => ({
          hostname: a.hostname || a.ip,
          ip: a.ip,
          ports: a.ports,
          vulns: (a.vulns || []).map((v: any) => ({
            id: v.id,
            title: v.title || v.name,
            severity: v.severity,
            description: v.description,
            tool: v.tool || v.source,
            cve: v.cve,
            endpoint: v.endpoint || v.url,
            rawEvidence: v.rawEvidence || v.evidence,
            corroborationTier: v.corroborationTier,
            screenshotPath: v.screenshotPath,
          })),
          exploitAttempts: a.exploitAttempts || [],
          toolResults: a.toolResults || [],
        })),
      };

      addLog(state, {
        phase: 'completed', type: 'info',
        title: '\uD83D\uDCDD Generating attack narratives...',
        detail: 'LLM analyzing findings to produce kill chain narratives',
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

      const narratives = await generateAttackNarratives(narrativeInput);

      if (narratives.length > 0) {
        // Store narratives on state for report generation
        (state as any).attackNarratives = narratives;

        // Generate executive summary
        const execSummary = await generateExecutiveSummary({
          ...narrativeInput,
          stats: {
            vulnsFound: state.stats.vulnsFound || 0,
            verifiedVulns: verifiedVulns,
            exploitsAttempted: state.stats.exploitsAttempted || 0,
            exploitsSucceeded: state.stats.exploitsSucceeded || 0,
            portsFound: state.stats.portsFound || 0,
          },
          narratives,
        });
        (state as any).executiveSummary = execSummary;

        addLog(state, {
          phase: 'completed', type: 'info',
          title: `\uD83D\uDCDD Generated ${narratives.length} attack narratives`,
          detail: [
            `Critical/High: ${narratives.filter(n => n.severity === 'critical' || n.severity === 'high').length}`,
            `Medium: ${narratives.filter(n => n.severity === 'medium').length}`,
            `MITRE techniques mapped: ${[...new Set(narratives.flatMap(n => n.mitreTechniques))].length}`,
          ].join(' | '),
        });
      } else {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: '\uD83D\uDCDD No findings eligible for narrative generation',
          detail: 'Attack narratives require confirmed findings with evidence',
        });
      }
    } catch (narrErr: any) {
      console.warn('[AttackNarrative] Generation failed:', narrErr.message);
      addLog(state, {
        phase: 'completed', type: 'warning',
        title: '\u26A0\uFE0F Attack narrative generation failed',
        detail: narrErr.message,
      });
    }

    // ── Evidence Chain Flush & Integrity Anchor ──
    try {
      const flushResult = await flushChainToDb(String(state.engagementId));
      const anchor = createIntegrityAnchor(String(state.engagementId));
      addLog(state, {
        phase: 'completed', type: 'evidence',
        title: `🔐 Evidence Chain Sealed`,
        detail: [
          `Flushed ${flushResult.flushed} evidence envelopes to DB`,
          anchor ? `Merkle root: ${anchor.merkleRoot.slice(0, 16)}...` : 'No anchor (empty chain)',
          anchor ? `Chain length: ${anchor.chainLength}` : '',
          flushResult.errors.length > 0 ? `Flush errors: ${flushResult.errors.length}` : '',
        ].filter(Boolean).join(' | '),
        data: {
          chainFlushed: flushResult.flushed,
          flushErrors: flushResult.errors,
          anchor: anchor ? {
            merkleRoot: anchor.merkleRoot,
            hmacSignature: anchor.hmacSignature,
            chainLength: anchor.chainLength,
            anchoredAt: anchor.anchoredAt,
          } : null,
        },
      });
    } catch (chainErr: any) {
      console.error('[EvidenceChain] Failed to flush/anchor:', chainErr.message);
    }
    // ── Accuracy Feedback Loop: auto-compare findings against ground truth ──
    try {
      const { runAccuracyComparison } = await import('./accuracy-feedback-loop');
      // Comprehensive training lab target detection map
      const TRAINING_LAB_PATTERNS: Array<[RegExp, string]> = [
        [/juice[-_]?shop/i, 'juice-shop'],
        [/dvwa/i, 'dvwa'],
        [/webgoat/i, 'webgoat'],
        [/vampi/i, 'vampi'],
        [/dvga/i, 'dvga'],
        [/hackazon/i, 'hackazon'],
        [/nodegoat/i, 'nodegoat'],
        [/crapi/i, 'crapi'],
        [/bwapp/i, 'bwapp'],
        [/mutillidae/i, 'mutillidae'],
        [/damn[-_]?vulnerable[-_]?web/i, 'dvwa'],
        [/bodgeit/i, 'bodgeit'],
        [/railsgoat/i, 'railsgoat'],
        [/gruyere/i, 'gruyere'],
        [/altoro[-_]?mutual/i, 'altoro-mutual'],
        [/tiredful[-_]?api/i, 'tiredful-api'],
        [/vulnerable[-_]?graphql/i, 'dvga'],
        [/damn[-_]?vulnerable[-_]?graphql/i, 'dvga'],
        [/owasp[-_]?benchmark/i, 'owasp-benchmark'],
        [/security[-_]?shepherd/i, 'security-shepherd'],
        [/wavsep/i, 'wavsep'],
        [/vulnhub/i, 'vulnhub'],
        [/metasploitable/i, 'metasploitable'],
        [/hackthebox/i, 'hackthebox'],
        [/pentesterlab/i, 'pentesterlab'],
        [/overthewire/i, 'overthewire'],
        [/picoctf/i, 'picoctf'],
      ];

      // Detect training lab from hostname, URL, or engagement target name
      const allHosts = state.assets.map(a => a.hostname || '').join(' ');
      const targetName = state.targetName || '';
      const searchStr = `${allHosts} ${targetName}`.toLowerCase();

      let targetPreset: string | null = null;
      for (const [pattern, preset] of TRAINING_LAB_PATTERNS) {
        if (pattern.test(searchStr)) {
          targetPreset = preset;
          break;
        }
      }

      // Also check if the engagement was launched from a training lab page
      if (!targetPreset && state.metadata?.trainingLabPreset) {
        targetPreset = state.metadata.trainingLabPreset;
      }

      if (targetPreset) {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: '📊 Accuracy Feedback Loop',
          detail: `Auto-comparing ${state.stats.vulnsFound} findings against ground truth for ${targetPreset}...`,
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

        // Collect all findings from all assets (vulns + ZAP findings + nuclei findings)
        // Collect all raw findings from all sources, preserving scanner evidence
        const rawFindings = state.assets.flatMap(a => [
          ...a.vulns.map(v => ({
            name: v.title,
            severity: v.severity,
            cwe: v.cwe || undefined,
            owasp: v.owasp || undefined,
            endpoint: v.endpoint || undefined,
            scannerEvidence: (v as any).scannerEvidence || [],
            scannerCount: ((v as any).scannerEvidence || []).length || 1,
          })),
          ...a.zapFindings.map(z => ({
            name: z.alert,
            severity: z.risk,
            cwe: z.cweId ? `CWE-${z.cweId}` : undefined,
            scannerEvidence: [{ scanner: 'zap', title: z.alert }],
            scannerCount: 1,
          })),
          ...(a.nucleiFindings || []).map((n: any) => ({
            name: n.templateId || n.name || n.info?.name || 'nuclei-finding',
            severity: n.info?.severity || n.severity || 'info',
            cwe: n.classification?.cweId?.[0] ? `CWE-${n.classification.cweId[0]}` : undefined,
            scannerEvidence: [{ scanner: 'nuclei', title: n.templateId || n.name || n.info?.name }],
            scannerCount: 1,
          })),
        ]);

        // Normalize finding names: strip tool prefixes, normalize whitespace
        const normalizeForScoring = (name: string) =>
          (name || '').replace(/^\[\w+(?:\s*\w+)*\]\s*/i, '').replace(/^\(\w+\)\s*/i, '').replace(/\s+/g, ' ').trim();

        // Deduplicate findings by normalized name (keep highest severity, merge scanner evidence)
        const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        const deduped = new Map<string, typeof rawFindings[0]>();
        for (const f of rawFindings) {
          const key = normalizeForScoring(f.name).toLowerCase();
          const existing = deduped.get(key);
          if (!existing) {
            deduped.set(key, { ...f, name: normalizeForScoring(f.name) });
          } else {
            // Merge: upgrade severity, combine scanner evidence
            if ((severityRank[f.severity?.toLowerCase() || 'info'] || 0) > (severityRank[existing.severity?.toLowerCase() || 'info'] || 0)) {
              existing.severity = f.severity;
            }
            // Merge scanner evidence arrays
            const existingEvidence = existing.scannerEvidence || [];
            const newEvidence = f.scannerEvidence || [];
            for (const ne of newEvidence) {
              if (!existingEvidence.some((ee: any) => ee.scanner === ne.scanner && ee.title === ne.title)) {
                existingEvidence.push(ne);
              }
            }
            existing.scannerEvidence = existingEvidence;
            existing.scannerCount = existingEvidence.length;
            // Merge CWE
            if (!existing.cwe && f.cwe) existing.cwe = f.cwe;
          }
        }
        const allFindings = [...deduped.values()];
        if (rawFindings.length !== allFindings.length) {
          const multiScannerCount = allFindings.filter(f => (f.scannerCount || 1) > 1).length;
          addLog(state, {
            phase: 'completed', type: 'info',
            title: `🔄 Finding Normalization: ${rawFindings.length} → ${allFindings.length} (${rawFindings.length - allFindings.length} duplicates merged)`,
            detail: `Stripped tool prefixes and deduplicated findings before accuracy scoring. ${multiScannerCount} findings confirmed by multiple scanners.`,
          });
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        }

        // Determine which knowledge modules were used during this engagement
        const modulesUsed = [
          'nuclei', 'zap', 'scanforge-discovery',
          ...(state.knowledgeModulesUsed || []),
          ...(state.metadata?.knowledgeModules || []),
        ];

        // ── Detect if bounty training knowledge was injected ──
        // Load engagement notes from DB since in-memory state may not carry them
        let engNotes: any = null;
        try {
          const { engagements: engTable } = await import('../../drizzle/schema');
          const { getDbRequired: getDbReq } = await import('../db');
          const { eq: eqOp } = await import('drizzle-orm');
          const dbForNotes = await getDbReq();
          const [engRow] = await dbForNotes.select({ notes: engTable.notes }).from(engTable).where(eqOp(engTable.id, engagementId)).limit(1);
          if (engRow?.notes) {
            engNotes = typeof engRow.notes === 'string' ? JSON.parse(engRow.notes) : engRow.notes;
          }
        } catch { /* fallback to state notes */ }
        if (!engNotes) {
          try {
            engNotes = typeof (state as any).notes === 'string' ? JSON.parse((state as any).notes) : (state as any).notes;
          } catch { /* no notes */ }
        }
        try {
          if (engNotes?.bountyKnowledgeInjected) {
            modulesUsed.push('bounty_training_knowledge');
            if (engNotes.bountyKnowledge?.topCwes?.length) {
              modulesUsed.push(`bounty_cwe_patterns_${engNotes.bountyKnowledge.topCwes.length}`);
            }
            if (engNotes.bountyKnowledge?.enrichedPatterns?.length) {
              modulesUsed.push(`bounty_enriched_categories_${engNotes.bountyKnowledge.enrichedPatterns.length}`);
            }
            if (engNotes.bountyKnowledge?.totalTrainingSamples) {
              modulesUsed.push(`bounty_training_samples_${engNotes.bountyKnowledge.totalTrainingSamples}`);
            }
          }
          if (engNotes?.dfirKnowledgeInjected) {
            modulesUsed.push('dfir_knowledge');
            modulesUsed.push(`dfir_reports_${engNotes.dfirReportsCount || 0}`);
          }
        } catch { /* notes not JSON or missing */ }

        // Also check if this engagement has training lab mode with bounty context
        if ((state as any).trainingLabMode) {
          modulesUsed.push('training_lab_mode');
        }
        if ((state as any).dfirKnowledgeContext?.length > 0) {
          modulesUsed.push('dfir_context_injected');
        }

        const uniqueModules = [...new Set(modulesUsed)];

        const compResult = await runAccuracyComparison({
          sessionId: `eng-${engagementId}-${Date.now()}`,
          engagementId: String(engagementId),
          targetPreset,
          targetUrl: state.assets[0]?.hostname || '',
          scanType: state.engagementType,
          findings: allFindings,
          knowledgeModulesUsed: uniqueModules,
          scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : undefined,
        });

        if (compResult) {
          const deltaStr = compResult.f1Delta != null
            ? ` (Δ${compResult.f1Delta >= 0 ? '+' : ''}${(compResult.f1Delta * 100).toFixed(1)}%)`
            : '';
          const trendEmoji = compResult.f1Delta != null
            ? (compResult.f1Delta > 0.02 ? '📈' : compResult.f1Delta < -0.02 ? '📉' : '➡️')
            : '';
          const bountyAttr = uniqueModules.includes('bounty_training_knowledge')
            ? ' | 🎯 Bounty Knowledge Active'
            : '';
          addLog(state, {
            phase: 'completed', type: 'info',
            title: `✅ Accuracy (DO): F1=${(compResult.f1Score * 100).toFixed(1)}%${deltaStr} ${trendEmoji}`,
            detail: `P=${(compResult.precision * 100).toFixed(1)}% R=${(compResult.recall * 100).toFixed(1)}% | ` +
              `TP=${compResult.truePositives} FP=${compResult.falsePositives} FN=${compResult.falseNegatives} | ` +
              `Missed: ${compResult.missedVulns.slice(0, 5).join(', ') || 'none'}${bountyAttr}`,
            data: { accuracyComparison: compResult, knowledgeModules: uniqueModules },
          });
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

          // Emit notification to the owner about accuracy results
          try {
            const { notifyOwner } = await import('../_core/notification');
            const f1Pct = (compResult.f1Score * 100).toFixed(1);
            const pPct = (compResult.precision * 100).toFixed(1);
            const rPct = (compResult.recall * 100).toFixed(1);
            const bountyNote = uniqueModules.includes('bounty_training_knowledge')
              ? `\nKnowledge Modules: Bug Bounty Training (${engNotes?.bountyKnowledge?.totalTrainingSamples || 0} samples, ${engNotes?.bountyKnowledge?.topCwes?.length || 0} CWE patterns)`
              : '';
            await notifyOwner({
              title: `Accuracy Report: ${targetPreset} — F1 ${f1Pct}%${deltaStr}`,
              content: `Engagement #${engagementId} completed on ${targetPreset}.\n` +
                `F1: ${f1Pct}% | Precision: ${pPct}% | Recall: ${rPct}%\n` +
                `TP: ${compResult.truePositives} | FP: ${compResult.falsePositives} | FN: ${compResult.falseNegatives}\n` +
                `Missed: ${compResult.missedVulns.slice(0, 5).join(', ') || 'none'}${bountyNote}\n` +
                `View details on the Knowledge Base → Accuracy Feedback tab.`,
            });
          } catch (notifErr: any) {
            console.warn('[AccuracyFeedback] Notification failed:', notifErr.message);
          }
        }

        // ── Local scoring with improved matching algorithm (dual mode) ──
        try {
          const { runLocalAccuracyComparison } = await import('./accuracy-feedback-loop');

          // Full local scoring
          const localFull = await runLocalAccuracyComparison({
            sessionId: `eng-${engagementId}-local-full-${Date.now()}`,
            engagementId: String(engagementId),
            targetPreset,
            targetUrl: state.assets[0]?.hostname || '',
            scanType: state.engagementType,
            findings: allFindings,
            knowledgeModulesUsed: uniqueModules,
            scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : undefined,
            autoDetectableOnly: false,
          });

          // AutoDetectable-only local scoring
          const localAuto = await runLocalAccuracyComparison({
            sessionId: `eng-${engagementId}-local-auto-${Date.now()}`,
            engagementId: String(engagementId),
            targetPreset,
            targetUrl: state.assets[0]?.hostname || '',
            scanType: state.engagementType,
            findings: allFindings,
            knowledgeModulesUsed: uniqueModules,
            scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : undefined,
            autoDetectableOnly: true,
          });

          if (localFull) {
            addLog(state, {
              phase: 'completed', type: 'info',
              title: `📊 Local Accuracy (Full): F1=${(localFull.f1Score * 100).toFixed(1)}%`,
              detail: `P=${(localFull.precision * 100).toFixed(1)}% R=${(localFull.recall * 100).toFixed(1)}% | ` +
                `TP=${localFull.truePositives} FP=${localFull.falsePositives} FN=${localFull.falseNegatives}`,
              data: { localAccuracyFull: localFull },
            });
          }
          if (localAuto) {
            addLog(state, {
              phase: 'completed', type: 'info',
              title: `🎯 Local Accuracy (Auto-Detectable): F1=${(localAuto.f1Score * 100).toFixed(1)}%`,
              detail: `P=${(localAuto.precision * 100).toFixed(1)}% R=${(localAuto.recall * 100).toFixed(1)}% | ` +
                `TP=${localAuto.truePositives} FP=${localAuto.falsePositives} FN=${localAuto.falseNegatives} | ` +
                `Missed: ${localAuto.missedVulns.slice(0, 5).join(', ') || 'none'}`,
              data: { localAccuracyAutoDetectable: localAuto },
            });
          }
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        } catch (localErr: any) {
          console.warn('[AccuracyFeedback] Local scoring failed:', localErr.message);
        }
      }
    } catch (accErr: any) {
      console.warn('[AccuracyFeedback] Auto-comparison failed:', accErr.message);
    }

    // ── Compliance Evidence Auto-Mapping ──
    try {
      const { mapEngagementToCompliance } = await import('./compliance-evidence-mapper');
      const mappingInput = {
        engagementId,
        assets: state.assets.map(a => ({
          hostname: a.hostname,
          ip: a.ip,
          vulns: a.vulns.map(v => ({
            title: v.title || v.name || 'Unknown',
            severity: v.severity || 'info',
            description: v.description,
            tool: v.tool || v.source || 'unknown',
            cve: v.cve,
            rawOutput: v.rawOutput || v.evidence,
          })),
          ports: a.ports.map(p => ({
            port: p.port,
            service: p.service,
            protocol: p.protocol,
          })),
          toolResults: (a.toolResults || []).map((tr: any) => ({
            tool: tr.tool,
            command: tr.command,
            exitCode: tr.exitCode,
            findingCount: tr.findingCount || 0,
            outputPreview: tr.output?.slice(0, 500),
            findings: (tr.findings || []).map((f: any) => ({
              title: f.title || f.name || 'finding',
              severity: f.severity || 'info',
            })),
          })),
          zapFindings: (a.zapFindings || []).map((z: any) => ({
            alert: z.alert || z.name || 'ZAP finding',
            risk: z.risk || z.severity || 'info',
            description: z.description,
            url: z.url,
            evidence: z.evidence,
          })),
        })),
      };

      const complianceResult = mapEngagementToCompliance(mappingInput);

      // Store compliance mapping in state metadata for UI access
      if (!state.metadata) state.metadata = {} as any;
      (state.metadata as any).complianceMapping = {
        totalEvidence: complianceResult.totalEvidenceItems,
        frameworksCovered: complianceResult.frameworksCovered,
        gapCount: complianceResult.gapCount,
        summaries: complianceResult.summaries.map(s => ({
          framework: s.framework,
          totalControls: s.totalControls,
          compliant: s.compliant,
          nonCompliant: s.nonCompliant,
          partial: s.partial,
          noEvidence: s.noEvidence,
          complianceScore: s.complianceScore,
        })),
        generatedAt: Date.now(),
      };

      // Log compliance summary
      const topFrameworks = complianceResult.summaries
        .sort((a, b) => b.complianceScore - a.complianceScore)
        .slice(0, 3)
        .map(s => `${s.framework}: ${s.complianceScore}%`)
        .join(', ');

      addLog(state, {
        phase: 'completed',
        type: 'info',
        title: `📋 Compliance Evidence: ${complianceResult.totalEvidenceItems} items across ${complianceResult.frameworksCovered.length} frameworks`,
        detail: `Scores: ${topFrameworks} | Gaps: ${complianceResult.gapCount} controls without evidence`,
        data: { complianceMapping: (state.metadata as any).complianceMapping },
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (compErr: any) {
      console.warn('[ComplianceMapper] Auto-mapping failed:', compErr.message);
      addLog(state, {
        phase: 'completed',
        type: 'warning',
        title: '⚠️ Compliance Mapping Failed',
        detail: compErr.message,
      });
    }

    } // end ROE-signed if block

    // ═══ AUTO-REPORT GENERATION (extracted to engagement-auto-report.ts) ═══
    try {
      const { generateAutoReport } = await import('./engagement-auto-report');
      const reportResult = await generateAutoReport(
        state as any,
        engagement as any,
        {
          addLog: (entry) => addLog(state, entry),
          broadcastUpdate: (update) => broadcastOpsUpdate(state.engagementId, update),
        }
      );
      if (reportResult.success && reportResult.reportId) {
        if (!state.metadata) state.metadata = {} as any;
        (state.metadata as any).autoReportId = reportResult.reportId;
        (state.metadata as any).autoReportFindings = reportResult.findingsCount;
      }
    } catch (reportErr: any) {
      console.error('[AutoReport] Auto-report generation failed:', reportErr.message);
      addLog(state, {
        phase: 'completed', type: 'warning',
        title: '⚠️ Auto-Report Generation Failed',
        detail: `${reportErr.message}. You can manually create a report from the Reports tab.`,
      });
    }

        // ═══ TEST PLAN ADHERENCE — Compare planned tests vs actual execution ═══
    try {
      addLog(state, {
        phase: 'completed', type: 'info',
        title: '📋 Test Plan Adherence: Analyzing execution against PTES/NIST standards...',
        detail: 'Comparing planned tests vs actual execution, identifying coverage gaps, generating recommendations',
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

      const { generateTestPlanAdherence } = await import('./engagement-report-handoff');

      // Convert state.testPlan (stored by pipeline-phases.ts) to TestPlanForHandoff format
      // Bug fix: was reading from state.metadata.testPlan which is never set — the test plan
      // is stored on state.testPlan by executeTestPlanGeneration()
      let testPlanForHandoff: any = null;
      const rawTestPlan = state.testPlan;
      if (rawTestPlan) {
        // Reconstruct the full attack vector objects from the stored test plan
        // state.testPlan.attackVectors is string[] (just names), but we also have
        // toolsPlanned[] and the engagement targets to build a proper handoff object
        const targets = state.assets.map((a: any) => a.hostname || a.ip).filter(Boolean);
        const toolsPlanned = rawTestPlan.toolsPlanned || [];
        // Map each section to a PTES phase based on title keywords
        const ptesPhaseMap: Record<string, string> = {
          'executive': 'Pre-engagement Interactions',
          'scope': 'Pre-engagement Interactions',
          'methodology': 'Intelligence Gathering',
          'intelligence': 'Intelligence Gathering',
          'recon': 'Intelligence Gathering',
          'threat': 'Threat Modeling',
          'attack': 'Exploitation',
          'vulnerability': 'Vulnerability Analysis',
          'exploit': 'Exploitation',
          'post': 'Post-Exploitation',
          'report': 'Reporting',
          'deliverable': 'Reporting',
          'dns': 'Intelligence Gathering',
          'tool': 'Vulnerability Analysis',
          'risk': 'Pre-engagement Interactions',
          'communication': 'Pre-engagement Interactions',
          'timeline': 'Pre-engagement Interactions',
        };
        const inferPtesPhase = (title: string): string => {
          const lower = title.toLowerCase();
          for (const [keyword, phase] of Object.entries(ptesPhaseMap)) {
            if (lower.includes(keyword)) return phase;
          }
          return 'Vulnerability Analysis';
        };
        // Build attack vectors from the stored names + toolsPlanned
        const attackVectorNames: string[] = rawTestPlan.attackVectors || [];
        const attackVectors = attackVectorNames.map((name: string, i: number) => ({
          id: `av-${i}`,
          name,
          tools: toolsPlanned.slice(0, 5), // Best-effort: associate top tools with each vector
          targets,
          ptesPhase: inferPtesPhase(name),
          estimatedHours: 2,
          priority: 'high',
        }));
        // Build tool matrix from toolsPlanned
        const toolMatrix = toolsPlanned.map((tool: string) => {
          const toolLower = tool.toLowerCase();
          let phase = 'Vulnerability Analysis';
          let purpose = 'Security scanning';
          if (/naabu|masscan|nerva|discovery|recon|subfinder|httpx|dig|dnsrecon/.test(toolLower)) { phase = 'Intelligence Gathering'; purpose = 'Reconnaissance and discovery'; }
          else if (/nuclei|zap|burp|nikto|testssl/.test(toolLower)) { phase = 'Vulnerability Analysis'; purpose = 'Vulnerability scanning'; }
          else if (/metasploit|sqlmap|commix|hydra|exploit/.test(toolLower)) { phase = 'Exploitation'; purpose = 'Exploitation and validation'; }
          return { tool, purpose, targets, phase };
        });
        testPlanForHandoff = {
          metadata: {
            planId: rawTestPlan.id || 'unknown',
            generatedAt: new Date(rawTestPlan.generatedAt || Date.now()).toISOString(),
            orgName: engagement.name || 'Unknown',
            targetDomain: engagement.targetDomain || '',
            planType: 'pentest',
          },
          sections: (rawTestPlan.sections || []).map((s: any) => ({
            id: s.id || s.title?.replace(/\s+/g, '-').toLowerCase() || 'section',
            title: s.title || 'Untitled',
            ptesPhase: inferPtesPhase(s.title || ''),
            nistSection: '§3',
            content: s.content || '',
          })),
          structuredData: {
            attackVectors,
            toolMatrix,
          },
        };
      }

      const adherence = await generateTestPlanAdherence(
        {
          engagementId: state.engagementId,
          engagementName: engagement.name,
          engagementType: state.engagementType,
          phase: state.phase,
          assets: state.assets,
          stats: state.stats,
          log: state.log,
          startedAt: state.startedAt,
          completedAt: state.completedAt,
          metadata: state.metadata as Record<string, any>,
        },
        testPlanForHandoff,
      );

      // Store adherence in state metadata for UI access
      if (!state.metadata) state.metadata = {} as any;
      (state.metadata as any).testPlanAdherence = {
        adherencePercentage: adherence.adherencePercentage,
        totalPlanned: adherence.totalPlannedTests,
        executed: adherence.executedTests,
        skipped: adherence.skippedTests,
        blocked: adherence.blockedTests,
        ptesPhases: adherence.ptesPhaseCompletion.map(p => ({
          phase: p.phase,
          status: p.status,
          findings: p.findings,
        })),
        coverageGaps: adherence.coverageGaps.length,
        recommendations: adherence.recommendations,
        generatedAt: adherence.generatedAt,
      };

      const completedPhases = adherence.ptesPhaseCompletion.filter(p => p.status === 'completed').length;
      const totalPhases = adherence.ptesPhaseCompletion.length;

      addLog(state, {
        phase: 'completed', type: 'phase_complete',
        title: `📋 Test Plan Adherence: ${adherence.adherencePercentage}% — ${completedPhases}/${totalPhases} PTES phases completed`,
        detail: `Executed: ${adherence.executedTests} | Skipped: ${adherence.skippedTests} | Gaps: ${adherence.coverageGaps.length} | Recommendations: ${adherence.recommendations.length}`,
        data: { testPlanAdherence: (state.metadata as any).testPlanAdherence },
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (adherenceErr: any) {
      console.warn('[TestPlanAdherence] Analysis failed:', adherenceErr.message);
      addLog(state, {
        phase: 'completed', type: 'warning',
        title: '⚠️ Test Plan Adherence Analysis Failed',
        detail: adherenceErr.message,
      });
    }

    // Final checkpoint
    await phaseCheckpoint('completed');

    // ═══ MARK ENGAGEMENT AS COMPLETED IN DB ═══
    // Update the engagements table to reflect completion and disable auto-resume
    try {
      const { updateEngagement } = await import('../db');
      await updateEngagement(engagementId, {
        status: 'completed' as any,
        endDate: new Date(state.completedAt || Date.now()).toISOString().replace('T', ' ').replace('Z', ''),
        autoResumeOnRestart: 0,
      });
      console.log(`[Engagement] Marked #${engagementId} as completed in DB`);
    } catch (statusErr: any) {
      console.error(`[Engagement] Failed to mark #${engagementId} as completed:`, statusErr.message);
    }

    // ═══ ENGAGEMENT RESULT PERSISTENCE ═══
    // Save structured results and findings to engagement_results / engagement_findings tables
    try {
      const { saveEngagementResult, saveEngagementFindings } = await import('../db');

      // Compute severity breakdown from assets
      const sevBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const asset of state.assets) {
        for (const v of (asset.vulns || [])) {
          const sev = (v.severity || 'medium').toLowerCase();
          if (sev === 'critical') sevBreakdown.critical++;
          else if (sev === 'high') sevBreakdown.high++;
          else if (sev === 'medium' || sev === 'moderate') sevBreakdown.medium++;
          else if (sev === 'low') sevBreakdown.low++;
          else sevBreakdown.info++;
        }
      }

      // Compute OWASP coverage from state
      const owaspData = (state as any).owaspCoverage || (state.metadata as any)?.owaspCoverage;
      const owaspCov = owaspData ? {
        score: owaspData.coveragePercentage || owaspData.score || 0,
        totalTested: owaspData.tested || owaspData.totalTested || 0,
        totalPartial: owaspData.partial || owaspData.totalPartial || 0,
        totalGaps: owaspData.gaps || owaspData.totalGaps || 0,
        criticalGaps: owaspData.criticalGaps || [],
      } : undefined;

      // Build summary JSON with attack narratives, test plan adherence, etc.
      const adherence = (state.metadata as any)?.testPlanAdherence;
      const summaryJson: Record<string, any> = {
        phases: state.log.filter(l => l.type === 'phase_complete').map(l => l.phase),
        logEntryCount: state.log.length,
        testPlanAdherence: adherence || null,
        autoReportId: (state.metadata as any)?.autoReportId || null,
        autoReportFindings: (state.metadata as any)?.autoReportFindings || 0,
        scanProfile: (state as any).scanProfile || 'standard',
        safetyLevel: (state as any).safetyLevel || 'standard',
      };

      const resultId = await saveEngagementResult({
        engagementId,
        operatorId: parseInt(String(operatorCtx.id), 10) || undefined,
        operatorName: operatorCtx.name,
        engagementType: state.engagementType,
        targetDomain: state.assets.map(a => a.hostname).join(', '),
        status: 'completed',
        startedAt: state.startedAt,
        completedAt: state.completedAt,
        durationMs: (state.completedAt || Date.now()) - (state.startedAt || Date.now()),
        stats: {
          hostsScanned: state.assets.length,
          portsFound: state.stats.portsFound,
          vulnsFound: state.stats.vulnsFound,
          verifiedVulns: (state.stats as any).verifiedVulns || 0,
          unverifiedVulns: (state.stats as any).unverifiedVulns || 0,
          exploitsAttempted: state.stats.exploitsAttempted,
          exploitsSucceeded: state.stats.exploitsSucceeded,
          sessionsOpened: state.stats.sessionsOpened,
          zapScansRun: state.stats.zapScansRun || 0,
        },
        severityBreakdown: sevBreakdown,
        owaspCoverage: owaspCov,
        autoReportId: (state.metadata as any)?.autoReportId,
        summaryJson,
      });

      // Persist individual findings — AFTER dedup, asset.vulns contains ALL findings
      // (including former ZAP findings that were merged during dedup-coverage-bridge).
      // No need to separately persist zapFindings as they are already in vulns.
      const findingsToSave: Array<any> = [];
      const dbDedupKeys = new Set<string>(); // Final dedup guard for DB persistence
      for (const asset of state.assets) {
        for (const v of (asset.vulns || [])) {
          // DB-level dedup key: title + hostname + port + CVE
          const dedupKey = `${(v.title || '').toLowerCase().trim()}::${asset.hostname}::${v.port || 0}::${v.cve || ''}`;
          if (dbDedupKeys.has(dedupKey)) continue;
          dbDedupKeys.add(dedupKey);

          const sev = (v.severity || 'medium').toLowerCase();
          const mappedSev = sev === 'moderate' ? 'medium' : (['critical','high','medium','low','info'].includes(sev) ? sev : 'medium');
          findingsToSave.push({
            engagementId,
            resultId,
            title: v.title || v.cve || 'Untitled',
            severity: mappedSev as any,
            cve: v.cve || undefined,
            cwe: v.cwe || undefined,
            description: v.description || undefined,
            endpoint: v.endpoint || v.url || undefined,
            hostname: asset.hostname,
            port: v.port || undefined,
            source: v.source || undefined,
            tool: v.tool || v.source || undefined,
            corroborationTier: v.corroborationTier || v.verified ? 'confirmed' : 'unverified',
            rawEvidence: v.rawEvidence || v.evidence || (() => {
              // Enrich from toolResults if no direct evidence
              const matchingTr = (asset.toolResults || []).find((tr: any) =>
                tr.findings?.some((f: any) => f.title === v.title)
              );
              if (matchingTr) {
                return JSON.stringify({
                  command: matchingTr.command,
                  output: matchingTr.outputPreview?.slice(0, 8000),
                  exitCode: matchingTr.exitCode,
                  executedAt: matchingTr.executedAt ? new Date(matchingTr.executedAt).toISOString() : null,
                }).slice(0, 16000);
              }
              return undefined;
            })(),
            exploitAttempted: (asset.exploitAttempts || []).some((e: any) => e.vulnTitle === v.title),
            exploitSucceeded: (asset.exploitAttempts || []).some((e: any) => e.vulnTitle === v.title && e.succeeded),
            exploitTechnique: (asset.exploitAttempts || []).find((e: any) => e.vulnTitle === v.title)?.technique,
            owaspCategory: v.owaspCategory || undefined,
            mitreTechnique: v.mitreTechnique || undefined,
          });
        }
        // NOTE: zapFindings are already merged into asset.vulns by dedup-coverage-bridge.
        // Any remaining zapFindings (from pre-dedup state) are intentionally NOT persisted
        // to avoid duplicates in the DB.
      }

      // Clear existing findings for this engagement before inserting clean set
      try {
        const { engagementFindings } = await import('../../drizzle/schema');
        const { eq } = await import('drizzle-orm');
        const { db: dbConn } = await import('../db');
        await dbConn.delete(engagementFindings).where(eq(engagementFindings.engagementId, engagementId));
      } catch (clearErr: any) {
        console.warn('[ResultPersistence] Could not clear old findings:', clearErr.message);
      }

      const savedCount = await saveEngagementFindings(findingsToSave);

      addLog(state, {
        phase: 'completed', type: 'info',
        title: `💾 Results Persisted: ${savedCount} findings saved to DB`,
        detail: `Result ID: ${resultId} | Findings: ${savedCount} (${sevBreakdown.critical}C/${sevBreakdown.high}H/${sevBreakdown.medium}M/${sevBreakdown.low}L/${sevBreakdown.info}I)${owaspCov ? ` | OWASP: ${owaspCov.score}%` : ''}`,
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (persistErr: any) {
      console.error('[ResultPersistence] Failed to save engagement results:', persistErr.message);
      addLog(state, {
        phase: 'completed', type: 'warning',
        title: '⚠️ Result Persistence Failed',
        detail: `${persistErr.message}. Results are still available in the ops state snapshot.`,
      });
    }

    // ═══ HOT PATH ANALYSIS — Analyze LLM call patterns from this engagement ═══
    try {
      const { getEngagementLlmTelemetryRaw } = await import('../db');
      const { analyzeHotPaths } = await import('./llm-hot-path-analyzer');
      const rawTelemetry = await getEngagementLlmTelemetryRaw(engagementId);

      if (rawTelemetry.length >= 10) {
        const hotPathAnalysis = analyzeHotPaths(rawTelemetry, { engagementId, topN: 10, minCallsForAnalysis: 3 });

        // Store analysis in state metadata for UI retrieval
        (state.metadata as any).hotPathAnalysis = {
          analyzedAt: hotPathAnalysis.analyzedAt,
          summary: hotPathAnalysis.summary,
          top5: hotPathAnalysis.hotPaths.slice(0, 5).map(hp => ({
            caller: hp.caller,
            calls: hp.totalCalls,
            pctOfTotal: hp.percentOfTotal.toFixed(1),
            cost: hp.estimatedCost.toFixed(4),
            graduation: hp.graduationRecommendation,
            graduationScore: hp.graduationScore.toFixed(2),
          })),
          redundancyClusters: hotPathAnalysis.redundancyClusters.length,
          recommendations: hotPathAnalysis.recommendations.slice(0, 5).map(r => ({
            priority: r.priority,
            category: r.category,
            caller: r.caller,
            title: r.title,
            callsReduced: r.estimatedImpact.callsReduced,
            costReduced: r.estimatedImpact.costReduced.toFixed(4),
          })),
          projectedSavings: hotPathAnalysis.projectedSavings,
        };

        // Log top 5 costliest call sites
        const top5Lines = hotPathAnalysis.hotPaths.slice(0, 5).map((hp, i) =>
          `${i + 1}. ${hp.caller}: ${hp.totalCalls} calls (${hp.percentOfTotal.toFixed(1)}%), $${hp.estimatedCost.toFixed(4)}, grad=${hp.graduationRecommendation}`
        );

        addLog(state, {
          phase: 'completed', type: 'info',
          title: `🔥 Hot Path Analysis: ${hotPathAnalysis.summary.totalCalls} calls, $${hotPathAnalysis.summary.totalCost.toFixed(4)} total cost`,
          detail: [
            `Top 5 costliest call sites (${hotPathAnalysis.summary.top5CallerPercent.toFixed(1)}% of all calls):`,
            ...top5Lines,
            '',
            `Redundancy clusters: ${hotPathAnalysis.redundancyClusters.length}`,
            `Optimization recommendations: ${hotPathAnalysis.recommendations.length}`,
            `Projected savings: ${hotPathAnalysis.projectedSavings.callReductionPercent.toFixed(1)}% calls, ${hotPathAnalysis.projectedSavings.costReductionPercent.toFixed(1)}% cost`,
          ].join('\n'),
          data: { hotPathAnalysis: (state.metadata as any).hotPathAnalysis },
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        console.log(`[HotPath] Engagement #${engagementId}: ${hotPathAnalysis.summary.totalCalls} calls analyzed, ${hotPathAnalysis.recommendations.length} optimization recommendations`);
      } else {
        console.log(`[HotPath] Engagement #${engagementId}: Only ${rawTelemetry.length} telemetry records — skipping analysis (need >= 10)`);
      }
    } catch (hotPathErr: any) {
      console.warn(`[HotPath] Failed to analyze hot paths for #${engagementId}:`, hotPathErr.message);
    }

    // ═══ NEGATIVE EXAMPLE FEEDBACK LOOP — Feed rejected findings into calibration ═══
    try {
      const { feedbackLoop } = await import('./negative-example-feedback-loop');
      const { confidenceCalibrationEngine } = await import('./bounty-confidence-calibration');
      const { crossTrainingBus } = await import('./cross-training-event-bus');

      // Collect rejected/false-positive findings from this engagement
      const rejectedFindings: Array<any> = [];
      for (const asset of state.assets) {
        for (const vuln of (asset.vulns || [])) {
          if (vuln.verified === false || vuln.corroborationTier === 'false_positive' || vuln.status === 'rejected') {
            rejectedFindings.push({
              id: `neg-${engagementId}-${vuln.cve || vuln.title || Math.random().toString(36).slice(2)}`,
              vulnClass: vuln.cwe || vuln.vulnClass || 'unknown',
              title: vuln.title || vuln.cve || 'Untitled',
              affectedEndpoint: vuln.endpoint || vuln.url || asset.hostname,
              technology: asset.passiveRecon?.technologies?.[0],
              severity: vuln.severity || 'medium',
              rejectionReason: vuln.corroborationTier === 'false_positive' ? 'false_positive' : 'not_reproducible',
              rejectionDetail: vuln.description || 'Unverified finding from automated scan',
              programHandle: state.bbRoeConfig?.programHandle,
              submittedAt: new Date(state.startedAt || Date.now()).toISOString(),
              rejectedAt: new Date().toISOString(),
              lessonsLearned: [`Unverified ${vuln.cwe || 'finding'} on ${asset.hostname} — needs manual validation`],
              tags: [state.engagementType, vuln.source || 'unknown'],
            });
          }
        }
      }

      if (rejectedFindings.length > 0) {
        const batchResult = feedbackLoop.processBatch(rejectedFindings, confidenceCalibrationEngine, crossTrainingBus);
        addLog(state, {
          phase: 'completed', type: 'info',
          title: `🔄 Negative Example Feedback: ${batchResult.processed} rejections processed`,
          detail: [
            `Calibration updates: ${batchResult.calibrationUpdates}`,
            `Event bus publications: ${batchResult.eventsPublished}`,
            batchResult.driftDetected ? `⚠️ Calibration drift detected: ${batchResult.driftReport?.direction} (${batchResult.driftReport?.severity})` : 'No calibration drift detected',
          ].join('\n'),
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        console.log(`[NegFeedback] Engagement #${engagementId}: ${batchResult.processed} rejections fed into calibration loop`);
      }
    } catch (negErr: any) {
      console.warn(`[NegFeedback] Failed for #${engagementId}:`, negErr.message);
    }

    // Free knowledge module memory after engagement completes
    const clearedMods = clearKnowledgeCache();
    if (clearedMods > 0) console.log(`[MemCleanup] Cleared ${clearedMods} knowledge module caches after completion`);

    emitSystemNotification({
      title: "Engagement Complete",
      message: `${state.engagementType} engagement #${engagementId} finished: ${state.stats.exploitsSucceeded} successful exploits`,
      severity: "info",
    });

    // ── Owner Push Notification ──
    try {
      const { notifyOwner } = await import('../_core/notification');
      const durationMs = (state.completedAt || Date.now()) - (state.startedAt || Date.now());
      const durationMin = Math.round(durationMs / 60_000);
      const phases = ['recon', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit'];
      const phasesCompleted = phases.filter(p => state.log.some(l => l.phase === p)).length;
      const critVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'critical').length, 0);
      const highVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'high').length, 0);
      await notifyOwner({
        title: `✅ Engagement #${engagementId} Complete — ${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits`,
        content: [
          `${state.engagementType.toUpperCase()} engagement #${engagementId} has completed.`,
          ``,
          `Duration: ${durationMin} minutes | Phases: ${phasesCompleted}/5`,
          `Assets: ${state.assets.length} | Ports: ${state.stats.portsFound}`,
          `Vulnerabilities: ${state.stats.vulnsFound} (${critVulns} critical, ${highVulns} high)`,
          `Exploits: ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} succeeded`,
          `Sessions: ${state.stats.sessionsOpened} | ZAP Scans: ${state.stats.zapScansRun || 0}`,
          `Log entries: ${state.log.length}`,
          ``,
          `View full results on the Engagement Ops page.`,
        ].join('\n'),
      });
    } catch (notifErr: any) {
      console.warn(`[Notification] Completion notification failed for #${engagementId}:`, notifErr.message);
    }

    // ═══ GRADUATION SYSTEM — Record engagement outcomes via shared post-pipeline-graduation module ═══
    try {
      const { runPostPipelineGraduation, extractEngagementMetrics } = await import('./post-pipeline-graduation');
      const engMetrics = extractEngagementMetrics(engagementId, state);
      const graduation = await runPostPipelineGraduation(engMetrics);

      addLog(state, {
        phase: 'completed', type: 'info',
        title: `🎓 Graduation: ${graduation.modelsScored} specialist models scored`,
        detail: `Recon: ${graduation.scores.recon_analyst}/100 | Exploit: ${graduation.scores.exploit_selector}/100 | Evasion: ${graduation.scores.evasion_optimizer}/100 | Cognitive: ${graduation.scores.cognitive_core}/100 | Cloud: ${graduation.scores.cloud_assessor}/100 | SupplyChain: ${graduation.scores.supply_chain_analyst}/100 | Training examples: ${graduation.trainingExamplesCollected}`,
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
      console.log(`[Graduation] 🎓 Engagement #${engagementId}: ${graduation.summary}`);
    } catch (gradErr: any) {
      console.warn(`[Graduation] Failed to record engagement outcomes for #${engagementId}:`, gradErr.message);
    }

    // ═══ INTELLIGENCE GAPS — Auto-detect gaps from engagement context ═══
    try {
      const { detectGaps, createGapsBatch } = await import('./intelligence-gaps');

      // Build gap detection context from engagement state
      const toolsUsedSet = new Set<string>();
      for (const asset of state.assets) {
        for (const tr of (asset.toolResults || [])) {
          toolsUsedSet.add(tr.tool);
        }
      }

      // Collect error entries from logs for tool failures
      const errorLogs = state.log.filter(l => l.type === 'error' || l.type === 'warning');
      const errorsEncountered = errorLogs
        .filter(l => l.title.match(/failed|error|timeout/i))
        .slice(0, 50)
        .map(l => ({
          tool: l.title.match(/^(\w+)/)?.[1] || 'unknown',
          error: l.detail || l.title,
          asset: undefined as string | undefined,
        }));

      // Collect auth failures from logs
      const authFailures = errorLogs
        .filter(l => l.title.match(/auth|credential|login|access denied/i))
        .slice(0, 20)
        .map(l => ({
          asset: l.detail?.match(/([\w.-]+\.\w{2,})/)?.[1] || 'unknown',
          service: l.title.match(/^(\w+)/)?.[1] || 'unknown',
          reason: l.detail || l.title,
        }));

      // Parse out-of-scope from RoE
      let outOfScope: string[] = [];
      try {
        const roeScope = engagement.roeScope as any;
        if (roeScope && typeof roeScope === 'object') {
          outOfScope = roeScope.outOfScope || roeScope.excludedTargets || [];
        }
        if (state.bbRoeConfig?.testingRestrictions?.excludedTargets) {
          outOfScope = [...outOfScope, ...state.bbRoeConfig.testingRestrictions.excludedTargets];
        }
      } catch { /* ignore RoE parse errors */ }

      const gapCtx = {
        engagementId,
        customerId: engagement.customerName || `eng-${engagementId}`,
        scopeDomains: (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean),
        scopeAssets: state.assets.map(a => a.hostname || a.ip || '').filter(Boolean),
        outOfScope,
        toolsUsed: [...toolsUsedSet],
        scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : undefined,
        maxDurationMs: undefined, // No hard limit tracked in state currently
        findingsCount: state.stats.vulnsFound || 0,
        assetsScanned: state.assets.filter(a => a.status !== 'discovered').map(a => a.hostname || a.ip || '').filter(Boolean),
        assetsDiscovered: state.assets.map(a => a.hostname || a.ip || '').filter(Boolean),
        portsScanned: state.assets.flatMap(a => a.ports.map(p => p.port)),
        servicesDetected: [...new Set(state.assets.flatMap(a => a.ports.map(p => p.service).filter(Boolean)))],
        errorsEncountered,
        authFailures,
      };

      const detectedGaps = detectGaps(gapCtx);
      if (detectedGaps.length > 0) {
        const gapIds = await createGapsBatch(detectedGaps);
        addLog(state, {
          phase: 'completed', type: 'info',
          title: `🔍 Intelligence Gaps: ${detectedGaps.length} gaps auto-detected`,
          detail: [
            ...detectedGaps.slice(0, 5).map(g => `• [${g.category}] ${g.title}`),
            detectedGaps.length > 5 ? `... and ${detectedGaps.length - 5} more` : '',
          ].filter(Boolean).join('\n'),
          data: { gapCount: detectedGaps.length, gapIds },
        });
        broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
      } else {
        addLog(state, {
          phase: 'completed', type: 'info',
          title: '🔍 Intelligence Gaps: No gaps detected',
          detail: 'All scope areas appear to have been assessed. Manual review recommended.',
        });
      }
      console.log(`[IntelGaps] Engagement #${engagementId}: ${detectedGaps.length} gaps auto-detected and persisted`);
    } catch (gapErr: any) {
      console.warn(`[IntelGaps] Failed to detect/persist gaps for #${engagementId}:`, gapErr.message);
    }

    // ═══ CUSTOMER INTELLIGENCE PROFILE — Auto-update from engagement results ═══
    try {
      const { updateProfileFromEngagement } = await import('./customer-intel-profile');

      // Build EngagementSnapshot from state
      const critCount = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'critical').length, 0);
      const highCount = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'high').length, 0);
      const medCount = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'medium').length, 0);
      const lowCount = state.assets.reduce((sum, a) => sum + a.vulns.filter(v => v.severity === 'low' || v.severity === 'info').length, 0);
      const totalServices = state.assets.reduce((sum, a) => sum + a.ports.filter(p => p.service && p.service !== 'unknown').length, 0);
      const totalPorts = state.assets.reduce((sum, a) => sum + a.ports.length, 0);

      // Collect technologies from assets
      const technologies = [...new Set(
        state.assets.flatMap(a => [
          ...(a.passiveRecon?.technologies || []),
          ...(a.ports || []).map(p => p.service).filter(Boolean),
          a.wafDetected ? `WAF: ${a.wafDetected}` : '',
        ].filter(Boolean))
      )];

      // Collect weakness categories from CWE/OWASP
      const weaknessCategories = [...new Set(
        state.assets.flatMap(a =>
          a.vulns.map(v => v.cwe || '').filter(Boolean)
        )
      )];

      const snapshot = {
        engagementId,
        date: new Date().toISOString(),
        customerId: engagement.customerName || `eng-${engagementId}`,
        customerName: engagement.customerName || engagement.name || `Engagement #${engagementId}`,
        findings: {
          total: state.stats.vulnsFound || 0,
          critical: critCount,
          high: highCount,
          medium: medCount,
          low: lowCount,
        },
        assets: {
          total: state.assets.length,
          hosts: state.assets.filter(a => a.hostname || a.ip).length,
          services: totalServices,
          exposedPorts: totalPorts,
        },
        technologies,
        weaknessCategories,
      };

      await updateProfileFromEngagement(snapshot);

      addLog(state, {
        phase: 'completed', type: 'info',
        title: `📊 Customer Intel Profile updated for "${snapshot.customerName}"`,
        detail: `Profile updated with ${snapshot.findings.total} findings across ${snapshot.assets.total} assets. Technologies: ${technologies.length}. Weakness categories: ${weaknessCategories.length}.`,
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
      console.log(`[CustomerIntel] Engagement #${engagementId}: Profile updated for "${snapshot.customerName}"`);
    } catch (cipErr: any) {
      console.warn(`[CustomerIntel] Failed to update profile for #${engagementId}:`, cipErr.message);
    }
  } catch (e: any) {
    clearInterval(heartbeatInterval); // Clean up heartbeat on error
    clearInterval(periodicPersistInterval); // Clean up periodic persistence on error
    state.phase = "error";
    state.isRunning = false;
    state.error = e.message;
    addLog(state, { phase: "error", type: "error", title: "Pipeline Error", detail: e.message });
    // Save error state so it can be inspected and potentially resumed
    await persistOpsStateNow(engagementId);
    // Update engagement DB record to reflect error state
    // Note: engagements table has no 'error' status enum, use 'paused' to indicate failure
    // and store error details in notes field
    try {
      const { updateEngagement } = await import('../db');
      const existingEng = await (await import('../db')).getEngagementById(engagementId);
      const existingNotes = existingEng?.notes || '';
      let parsedNotes: Record<string, any> = {};
      try { parsedNotes = existingNotes ? JSON.parse(existingNotes) : {}; } catch { parsedNotes = { originalNotes: existingNotes }; }
      const errorNote = JSON.stringify({
        ...parsedNotes,
        pipelineError: e.message?.slice(0, 2000),
        errorPhase: state.phase || 'unknown',
        errorAt: new Date().toISOString(),
      });
      await updateEngagement(engagementId, {
        status: 'paused' as any,
        notes: errorNote,
      });
      console.log(`[Engagement] Marked #${engagementId} as paused (error) in DB`);
    } catch (statusErr: any) {
      console.error(`[Engagement] Failed to mark #${engagementId} as error:`, statusErr.message);
    }
    // Free knowledge module memory on error too
    try { clearKnowledgeCache(); } catch { /* best effort */ }

    // ── Owner Push Notification (Error) ──
    try {
      const { notifyOwner } = await import('../_core/notification');
      const durationMs = Date.now() - (state.startedAt || Date.now());
      const durationMin = Math.round(durationMs / 60_000);
      await notifyOwner({
        title: `❌ Engagement #${engagementId} Failed — ${state.phase} phase error`,
        content: [
          `${state.engagementType.toUpperCase()} engagement #${engagementId} encountered an error.`,
          ``,
          `Error: ${e.message}`,
          `Last phase: ${state.log.length > 0 ? state.log[state.log.length - 1].phase : 'unknown'}`,
          `Duration: ${durationMin} minutes`,
          `Assets: ${state.assets.length} | Vulns: ${state.stats.vulnsFound}`,
          `Log entries: ${state.log.length}`,
          ``,
          `The engagement state has been saved. Use Resume to continue from the last checkpoint.`,
        ].join('\n'),
      });
    } catch (notifErr: any) {
      console.warn(`[Notification] Error notification failed for #${engagementId}:`, notifErr.message);
    }
  }
}

export function stopEngagement(engagementId: number): boolean {
  const state = opsStates.get(engagementId);
  if (!state) return false;
  state.isRunning = false;
  state.isPaused = false;
  state.currentAction = "Stopped by operator";
  addLog(state, { phase: state.phase, type: "info", title: "⏹ Execution Stopped", detail: "Operator stopped the engagement execution. Use 'Resume' to continue from this phase." });
  broadcastOpsUpdate(engagementId, { type: "stopped" });
  // Persist stopped state so it can be resumed later
  persistOpsStateNow(engagementId);
  return true;
}

/**
 * Resume a stopped or crashed engagement from its last saved phase.
 * Recovers state from DB if not in memory.
 */
export async function resumeEngagement(
  engagementId: number,
  operatorCtx: { id: string; name?: string }
): Promise<{ success: boolean; message: string; resumePhase?: string }> {
  // Try to get state from memory or DB
  let state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: "No saved state found for this engagement. Start a new execution instead." };
  }

  if (state.isRunning) {
    return { success: false, message: "Engagement is already running." };
  }

  if (state.phase === 'completed') {
    return { success: false, message: "Engagement already completed. Start a new execution to re-run." };
  }

  // Determine the best phase to resume from.
  // When state.phase is 'error'/'idle'/'paused', search backwards through logs
  // for the last VALID pipeline phase (not 'error', 'idle', 'paused', 'unknown', 'completed').
  const validPipelinePhases = new Set(['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit']);
  let resumePhase: string = 'recon';
  if (state.phase === 'error' || state.phase === 'idle' || state.phase === 'paused') {
    // Search backwards through log entries for the last valid pipeline phase
    for (let i = state.log.length - 1; i >= 0; i--) {
      const logPhase = state.log[i].phase;
      if (validPipelinePhases.has(logPhase)) {
        resumePhase = logPhase;
        break;
      }
    }
  } else if (validPipelinePhases.has(state.phase)) {
    resumePhase = state.phase;
  }

  // ── Claim Lock: acquire ownership before resuming (force=true for user-initiated) ──
  try {
    const { claimEngagement } = await import('./engagement-claim-lock');
    // User-initiated resumes force-claim to override stale claims from dead servers
    const claim = await claimEngagement(engagementId, { force: true });
    if (!claim.claimed) {
      return {
        success: false,
        message: `Cannot resume: another server instance (${claim.currentOwner}) owns this engagement. ${claim.reason}`,
      };
    }
  } catch (e: any) {
    console.warn(`[ResumeEngagement] Claim lock check failed (proceeding anyway): ${e.message}`);
  }

  // Reset error state
  state.error = undefined;
  state.isRunning = false; // Will be set to true by executeEngagement

  // ── Dismiss stale approval gates from previous run ──
  // After server restart, in-memory resolvers are lost so pending gates can never resolve.
  // Dismiss them before resuming to prevent the UI from showing orphaned gates.
  const staleCount = dismissAllStaleApprovals(engagementId, `auto-resume:${operatorCtx.id}`);
  if (staleCount > 0) {
    addLog(state, {
      phase: resumePhase as any,
      type: 'info',
      title: `🗑️ Dismissed ${staleCount} stale approval gate(s)`,
      detail: `Cleared orphaned approval gates from previous run before resuming.`,
    });
  }
  state.isPaused = false;

  // Fire off the execution with resume flag
  executeEngagement(engagementId, operatorCtx, {
    startPhase: resumePhase as any,
    resume: true,
  });

  return {
    success: true,
    message: `Resuming engagement from phase: ${resumePhase}. ${state.assets.length} assets, ${state.stats.vulnsFound} vulns recovered.`,
    resumePhase,
  };
}


// ─── Startup Recovery: Detect Interrupted Engagements ────────────────────────

/**
 * Scan the DB for engagements that were running when the server last shut down.
 * Loads their state into memory (marked as crashed/error) and notifies the owner.
 * Call this once during server startup (after DB is ready).
 */
export async function recoverInterruptedEngagements(): Promise<{
  recovered: number;
  engagements: Array<{ id: number; phase: string; assets: number }>;
}> {
  const result: { recovered: number; engagements: Array<{ id: number; phase: string; assets: number }> } = {
    recovered: 0,
    engagements: [],
  };

  try {
    const { getDbRequired } = await import('../db');
    const db = await getDbRequired();
    const { engagementOpsSnapshots } = await import('../../drizzle/schema');
    const { eq } = await import('drizzle-orm');

    // Find all snapshots that were marked as running (server crashed mid-execution)
    const interrupted = await db.select()
      .from(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.isRunning, 1));

    for (const row of interrupted) {
      const engId = row.engagementId;
      try {
        // MEMORY OPTIMIZATION: Don't load full state into memory at boot.
        // Just record that this engagement exists and can be resumed.
        // The full state will be loaded on-demand when the user clicks Resume.
        // Parse just enough metadata from the snapshot to show in the UI.
        let phase = 'unknown';
        let assetCount = 0;
        try {
          const snapshotData = typeof row.stateJson === 'string' ? JSON.parse(row.stateJson) : row.stateJson;
          phase = snapshotData?.phase || 'unknown';
          assetCount = snapshotData?.assets?.length || 0;
        } catch { /* use defaults */ }

        // Mark as error/stopped in DB so it won't be recovered again on next restart
        // The state stays in DB and can be loaded on-demand via getOpsStateWithRecovery()
        try {
          await db.update(engagementOpsSnapshots)
            .set({ isRunning: 0 })
            .where(eq(engagementOpsSnapshots.engagementId, engId));
        } catch { /* best effort */ }

        result.recovered++;
        result.engagements.push({ id: engId, phase, assets: assetCount });
        console.log(`[StartupRecovery] Recovered engagement #${engId}: phase=${phase}, assets=${assetCount} (state NOT loaded into memory — will load on Resume)`);
      } catch (e: any) {
        console.error(`[StartupRecovery] Failed to recover engagement #${engId}:`, e.message);
      }
    }

    // Notify owner if any engagements were interrupted
    if (result.recovered > 0) {
      try {
        const { notifyOwner } = await import('../_core/notification');
        const engList = result.engagements
          .map(e => `  • #${e.id}: last phase = ${e.phase}, ${e.assets} assets preserved`)
          .join('\n');
        await notifyOwner({
          title: `⚠️ ${result.recovered} Interrupted Engagement${result.recovered > 1 ? 's' : ''} Recovered`,
          content: [
            `The server restarted and ${result.recovered} engagement${result.recovered > 1 ? 's were' : ' was'} interrupted mid-execution.`,
            ``,
            `Recovered engagements:`,
            engList,
            ``,
            `All asset data and progress has been preserved. Use the Resume button on the Engagement Ops page to continue from the last checkpoint.`,
          ].join('\n'),
        });
      } catch (notifErr: any) {
        console.warn('[StartupRecovery] Notification failed:', notifErr.message);
      }
    }
  } catch (e: any) {
    console.error('[StartupRecovery] Recovery scan failed:', e.message);
  }

  return result;
}

// ─── Re-run From Phase ──────────────────────────────────────────────────────

/**
 * Re-run a completed (or errored) engagement starting from a specific phase.
 * Preserves all data from phases BEFORE the target phase, clears data from
 * the target phase onward, then executes the pipeline from that phase.
 */
export async function rerunFromPhase(
  engagementId: number,
  targetPhase: 'recon' | 'enumeration' | 'vuln_detection' | 'social_engineering' | 'exploitation' | 'post_exploit',
  operatorCtx: { id: string; name?: string }
): Promise<{ success: boolean; message: string }> {
  const PHASE_ORDER: Array<'recon' | 'enumeration' | 'vuln_detection' | 'social_engineering' | 'exploitation' | 'post_exploit'> = [
    'recon', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit',
  ];

  const targetIdx = PHASE_ORDER.indexOf(targetPhase);
  if (targetIdx < 0) {
    return { success: false, message: `Invalid phase: ${targetPhase}. Must be one of: ${PHASE_ORDER.join(', ')}` };
  }

  // Get state from memory or DB
  let state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: 'No saved state found for this engagement. Run it first before re-running from a specific phase.' };
  }

  if (state.isRunning) {
    return { success: false, message: 'Engagement is currently running. Stop it first before re-running.' };
  }

  // Determine which phases to keep (everything before targetPhase)
  const phasesToKeep = PHASE_ORDER.slice(0, targetIdx);
  const phasesToClear = PHASE_ORDER.slice(targetIdx);

  // ═══ CAPTURE PREVIOUS FINDINGS FOR DEDUP (parity with rerunFullPipeline) ═══
  // Before clearing any data, snapshot existing findings so the dedup pipeline
  // can compare new results against them and prevent duplicates.
  if (Array.isArray(state.assets) && state.assets.length > 0) {
    (state as any).previousScanFindings = state.assets.flatMap((a: any) => a.vulns || []);
    (state as any).previousZapFindings = state.assets.flatMap((a: any) => a.zapFindings || []);
  }

  // Clear logs from phases being re-run
  state.log = state.log.filter(l => phasesToKeep.includes(l.phase as any));

  // Clear asset data from phases being re-run
  if (targetIdx <= 1) {
    // Re-running from recon or enumeration: clear port data
    for (const asset of state.assets) {
      asset.ports = [];
      asset.toolResults = [];
    }
    state.stats.portsFound = 0;
  }
  if (targetIdx <= 2) {
    // Re-running from vuln_detection or earlier: clear vuln data
    for (const asset of state.assets) {
      asset.vulns = [];
      asset.zapFindings = [];
      asset.nucleiFindings = [];
    }
    state.stats.vulnsFound = 0;
    state.stats.zapScansRun = 0;
    // Reset completedScans tracking for vuln detection tools
    if (state.completedScans) {
      state.completedScans.nucleiCompleted = new Set();
      state.completedScans.zapCompleted = new Set();
    }
  }
  if (targetIdx <= 3) {
    // Re-running from exploitation or earlier: clear exploit data
    for (const asset of state.assets) {
      asset.exploitAttempts = [];
    }
    state.stats.exploitsAttempted = 0;
    state.stats.exploitsSucceeded = 0;
    state.stats.sessionsOpened = 0;
    if (state.completedScans) {
      state.completedScans.exploitCompleted = new Set();
    }
  }
  // Post-exploit: clear post-exploit specific data
  if (targetIdx <= 4) {
    state.completedAt = undefined;
  }

  // Reset state for re-execution
  state.error = undefined;
  state.isRunning = false;
  state.progress = Math.round((targetIdx / PHASE_ORDER.length) * 100);

  // ═══ CLEAR CORRESPONDING DB TABLES to prevent duplicate numbers ═══
  // Without this, partial re-runs would accumulate rows in the DB while
  // in-memory stats are reset — causing inflated counts on Results pages.
  try {
    const { getDb } = await import('../db');
    const { eq } = await import('drizzle-orm');
    const dbConn = await getDb();
    if (dbConn) {
      const cleared: Record<string, number> = {};
      if (targetIdx <= 2) {
        // Clearing vuln_detection or earlier: remove engagement findings & web app findings
        const { engagementFindings, webAppFindings, webAppScans } = await import('../../drizzle/schema');
        const r1 = await dbConn.delete(engagementFindings).where(eq(engagementFindings.engagementId, engagementId)).catch(() => [{ affectedRows: 0 }]);
        cleared.engagementFindings = (r1 as any)[0]?.affectedRows ?? 0;
        const r2 = await dbConn.delete(webAppFindings).where(eq(webAppFindings.engagementId, engagementId)).catch(() => [{ affectedRows: 0 }]);
        cleared.webAppFindings = (r2 as any)[0]?.affectedRows ?? 0;
        const r3 = await dbConn.delete(webAppScans).where(eq(webAppScans.engagementId, engagementId)).catch(() => [{ affectedRows: 0 }]);
        cleared.webAppScans = (r3 as any)[0]?.affectedRows ?? 0;
      }
      if (targetIdx <= 3) {
        // Clearing exploitation or earlier: remove exploit attempts & plan history
        const { exploitationAttempts, exploitPlanHistory } = await import('../../drizzle/schema');
        const r4 = await dbConn.delete(exploitationAttempts).where(eq(exploitationAttempts.engagementId, engagementId)).catch(() => [{ affectedRows: 0 }]);
        cleared.exploitationAttempts = (r4 as any)[0]?.affectedRows ?? 0;
        const r5 = await dbConn.delete(exploitPlanHistory).where(eq(exploitPlanHistory.engagementId, engagementId)).catch(() => [{ affectedRows: 0 }]);
        cleared.exploitPlanHistory = (r5 as any)[0]?.affectedRows ?? 0;
      }
      console.log(`[rerunFromPhase] DB tables cleared for engagement #${engagementId}:`, JSON.stringify(cleared));
    }
  } catch (dbErr: any) {
    console.error(`[rerunFromPhase] Failed to clear DB tables: ${dbErr.message}`);
  }

  // Add re-run log entry
  addLog(state, {
    phase: targetPhase,
    type: 'info',
    title: `🔄 Re-run from ${targetPhase.replace(/_/g, ' ')}`,
    detail: `Operator initiated re-run from ${targetPhase}. Preserved data from: ${phasesToKeep.join(', ') || 'none'}. Clearing: ${phasesToClear.join(', ')}.`,
  });

  // Save the cleaned state
  opsStates.set(engagementId, state);
  await persistOpsStateNow(engagementId);

  // Fire off the execution from the target phase
  executeEngagement(engagementId, operatorCtx, {
    startPhase: targetPhase,
    resume: false,
  });

  return {
    success: true,
    message: `Re-running engagement #${engagementId} from ${targetPhase}. Preserved ${phasesToKeep.length} prior phase(s), ${state.assets.length} assets, ${state.log.length} log entries.`,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// RE-SCAN WITH DEEPER PROFILE — Escalate Quick → Standard → Deep on a single asset
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Profile escalation order: quick → standard → deep
 * Allows operators to re-run content discovery (Gobuster) on a specific asset
 * with a more thorough profile without re-running the entire engagement.
 */
const PROFILE_ESCALATION_ORDER: Array<'quick' | 'standard' | 'deep' | 'stealth'> = [
  'quick', 'standard', 'deep',
];

export interface RescanEscalationResult {
  success: boolean;
  message: string;
  previousProfile?: string;
  newProfile?: string;
  assetHostname?: string;
  command?: string;
}

export async function rescanAssetWithDeeperProfile(
  engagementId: number,
  assetHostname: string,
  options?: {
    targetProfile?: 'quick' | 'standard' | 'deep';
    operatorId?: string;
    operatorName?: string;
  }
): Promise<RescanEscalationResult> {
  // Get state
  let state = getOpsState(engagementId);
  if (!state) state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: 'No engagement state found. Run the engagement first.' };
  }

  // Find the target asset
  const asset = state.assets.find(a =>
    a.hostname.toLowerCase() === assetHostname.toLowerCase() ||
    a.ip === assetHostname
  );
  if (!asset) {
    return {
      success: false,
      message: `Asset "${assetHostname}" not found in engagement #${engagementId}. Available: ${state.assets.map(a => a.hostname).join(', ')}`,
    };
  }

  // Determine current profile and escalation target
  const currentProfile = state.scanProfile || 'quick';
  const currentIdx = PROFILE_ESCALATION_ORDER.indexOf(currentProfile as any);
  let targetProfile = options?.targetProfile;

  if (!targetProfile) {
    // Auto-escalate to next level
    const nextIdx = Math.min(currentIdx + 1, PROFILE_ESCALATION_ORDER.length - 1);
    targetProfile = PROFILE_ESCALATION_ORDER[nextIdx];
    if (targetProfile === currentProfile) {
      return {
        success: false,
        message: `Asset "${assetHostname}" is already at the maximum profile level (${currentProfile}). Cannot escalate further.`,
        previousProfile: currentProfile,
      };
    }
  }

  // Validate the target profile is actually deeper
  const targetIdx = PROFILE_ESCALATION_ORDER.indexOf(targetProfile);
  if (targetIdx < 0) {
    return { success: false, message: `Invalid target profile: ${targetProfile}. Must be one of: ${PROFILE_ESCALATION_ORDER.join(', ')}` };
  }
  if (targetIdx <= currentIdx && !options?.targetProfile) {
    return {
      success: false,
      message: `Target profile "${targetProfile}" is not deeper than current "${currentProfile}".`,
      previousProfile: currentProfile,
    };
  }

  // Build the deeper Gobuster command
  const profile = getScanProfile(targetProfile);
  const httpPort = asset.ports.find(p => p.service === 'http' || p.service === 'https' || p.port === 80 || p.port === 443);
  const protocol = httpPort?.port === 443 || httpPort?.service === 'https' ? 'https' : 'http';
  const port = httpPort?.port || 80;
  const targetUrl = port === 80 || port === 443
    ? `${protocol}://${asset.hostname}`
    : `${protocol}://${asset.hostname}:${port}`;

  // Gather context
  const wafDetected = !!(asset.wafDetected && asset.wafDetected !== 'none');
  const detectedTech = asset.passiveRecon?.technologies || [];
  const isApiTarget = asset.type === 'api' ||
    asset.ports.some(p => /api|graphql|rest/i.test(p.service || '')) ||
    /\/api\/|\/v[0-9]+\//i.test(targetUrl);

  // Get auth cookie if available
  let authCookie = '';
  const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
    ['http', 'web', 'form', 'http-get', 'http-post-form'].includes(c.service)
  );
  if (webCreds.length > 0 && (webCreds[0] as any).sessionCookie) {
    authCookie = (webCreds[0] as any).sessionCookie;
  } else if ((asset as any).trainingLabCreds?.sessionCookie) {
    authCookie = (asset as any).trainingLabCreds.sessionCookie;
  }

  const command = buildGobusterCommand(profile, targetUrl, {
    wafDetected,
    authCookie: authCookie || undefined,
    detectedTech,
    isApiTarget,
  });

  // Log the escalation
  addLog(state, {
    phase: state.phase || 'enumeration',
    type: 'info',
    title: `⬆️ Profile Escalation: ${currentProfile} → ${targetProfile} for ${asset.hostname}`,
    detail: `Operator requested deeper content discovery scan. Previous profile: ${currentProfile}, new profile: ${targetProfile}.\nCommand: ${command}`,
    data: { previousProfile: currentProfile, newProfile: targetProfile, asset: asset.hostname, command },
  });

  // Execute the scan via scan server
  try {
    const { executeTool } = await import('./scan-server-executor');
    const scanResult = await executeTool({
      tool: 'gobuster',
      args: command.replace(/^gobuster\s+/, ''),
      timeout: profile.gobuster.timeout || 600,
    });

    // Parse results and merge into asset
    const newPaths: string[] = [];
    if (scanResult.stdout) {
      const lines = scanResult.stdout.split('\n');
      for (const line of lines) {
        // Match gobuster output: /path (Status: 200) [Size: 1234]
        const pathMatch = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
        if (pathMatch) {
          const [, path, status] = pathMatch;
          const statusCode = parseInt(status);
          if (statusCode >= 200 && statusCode < 400) {
            newPaths.push(path);
          }
        }
      }
    }

    // Merge new tool results
    if (!asset.toolResults) asset.toolResults = [];
    asset.toolResults.push({
      tool: 'gobuster',
      command,
      output: scanResult.stdout?.substring(0, 5000) || '',
      timestamp: Date.now(),
      profile: targetProfile,
      pathsFound: newPaths.length,
    } as any);

    addLog(state, {
      phase: state.phase || 'enumeration',
      type: newPaths.length > 0 ? 'finding' : 'info',
      title: `✅ Deeper Scan Complete: ${newPaths.length} new paths on ${asset.hostname}`,
      detail: `Profile "${targetProfile}" Gobuster scan completed. Found ${newPaths.length} accessible paths.${newPaths.length > 0 ? '\nNew paths: ' + newPaths.slice(0, 20).join(', ') + (newPaths.length > 20 ? ` (+${newPaths.length - 20} more)` : '') : ''}`,
      data: { paths: newPaths, profile: targetProfile, command },
    });

    // Update the engagement's scan profile to the new level
    state.scanProfile = targetProfile;
    broadcastOpsUpdate(engagementId, { type: 'log_update' });
    await persistOpsStateNow(engagementId);

    return {
      success: true,
      message: `Deeper scan completed: ${newPaths.length} paths found on ${asset.hostname} with "${targetProfile}" profile.`,
      previousProfile: currentProfile,
      newProfile: targetProfile,
      assetHostname: asset.hostname,
      command,
    };
  } catch (err: any) {
    addLog(state, {
      phase: state.phase || 'enumeration',
      type: 'error',
      title: `❌ Deeper Scan Failed: ${asset.hostname}`,
      detail: `Profile escalation scan failed: ${err.message}`,
    });
    broadcastOpsUpdate(engagementId, { type: 'log_update' });
    return {
      success: false,
      message: `Deeper scan failed: ${err.message}`,
      previousProfile: currentProfile,
      newProfile: targetProfile,
      assetHostname: asset.hostname,
    };
  }
}
// deploy trigger 20260708173121
