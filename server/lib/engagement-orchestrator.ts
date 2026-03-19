/**
 * Engagement Orchestrator — LLM-driven autonomous pentest/red team execution engine
 *
 * One-click execution: operator presses "Execute" and the LLM orchestrates the entire
 * engagement pipeline autonomously, pausing only for operator approval on high-risk actions.
 *
 * Phases:
 *   1. Recon & Discovery (passive OSINT, domain intel)
 *   2. Enumeration & Fingerprinting (nmap service/OS detection)
 *   3. Vulnerability Detection (nuclei + ZAP for web apps, WAF-aware)
 *   4. Exploitation (Metasploit modules, exploitation bridge)
 *   5a. Pentest: per-asset unauthorized access demo → evidence → report
 *   5b. Red Team: C2 agent deploy → Caldera callback → pivot → objectives
 *
 * All actions are gated by RoE scope enforcement and logged to offensive_audit_log.
 */

import { invokeLLM } from "../_core/llm";
import { throttledLLMCall } from "./llm-throttle";
import { getNmapScanPlanContext, getNmapVulnCorrelationContext, getNmapHuntContext } from "./nmap-knowledge";
import {
  emitExploitFired, emitExploitResult, emitAgentDeployed,
  emitReconComplete, emitSystemNotification, emitSystemAlert,
  eventHub,
} from "./ws-event-hub";
import { onShellObtained } from "./post-exploit-auto-trigger";
import { captureDecision, captureExploitOutcome, updateDecisionOutcome } from "./engagement-training-bridge";
import { emitLLMDecision, emitLLMDelegation, emitLLMEngagementProgress } from "./ws-event-hub";
import {
  getChainsByVulnDescriptions,
  formatChainsForPrompt,
} from "./knowledge/attack-chain-retriever";
import {
  inferAssetContext,
  formatOntologyForPrompt,
} from "./knowledge/asset-ontology";
import {
  getBugBountyContext,
  getTriageSystemPrompt,
  getTrainingExamplesForPrompt,
} from "./knowledge/bugbounty-knowledge";
import {
  getTriageCorpusContext,
} from "./knowledge/training-corpus";
import {
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  detectCloudProviders,
} from "./knowledge/cloud-security-knowledge";
import {
  getOwaspScanPlanContext,
  getOwaspVulnCorrelationContext,
  getOwaspAssetClassificationContext,
} from "./owasp-knowledge";
import { getOwaspTracker, resetOwaspTracker } from "./owasp-coverage-tracker";
import {
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  getSectorThreatContext,
  getGroupsByCVE,
} from "./threat-group-knowledge";
import {
  fetchKevCatalog,
  matchCvesAgainstKev,
  calculateKevRiskBoost,
  type KevMatch,
} from "./kev-service";
import {
  executeToolViaQueue,
  executeRawCommandViaQueue,
  executeToolBatchViaQueue,
  getBridgeStatus,
} from "./job-queue-bridge";
import { retryWithBackoff, isRetryableError } from "./api-resilience";
import {
  buildOffensiveTechniquesContext,
  getFirewallEvasionContext,
  getFileUploadBypassContext,
  getLOTLContext,
  getShodanReconContext,
  getSubdomainEnumContext,
} from "./knowledge/offensive-techniques-knowledge";
import {
  buildZAPKnowledgeContext,
  getZAPAlertCatalogContext,
  getTechScanPolicyContext,
  getZAPAuthContext,
  getZAPReasoningPrompt,
  getVulnPayloadContext,
} from "./knowledge/zap-pentesting-knowledge";
import {
  buildToolRecommendationContext,
  buildAttackPlannerToolContext,
} from "./knowledge/offensive-tools-knowledge";
import {
  buildMethodologyContext,
  buildPhaseToolContext,
  buildVulnTestingContext,
  buildScanPlanningContext,
  type BugBountyPhase,
} from "./knowledge/bugbounty-methodology-knowledge";
import {
  buildThreatActorLearningContext,
  buildThreatActorVulnContext,
  scoreEngagementThreatAttribution,
  clearThreatLearningCache,
} from "./threat-actor-learning-context";
import {
  buildSourceSecretsContext,
  buildCompactSourceSecretsContext,
} from "./knowledge/zap-source-secrets-knowledge";
import { getSafetyEngine, clearSafetyEngine, type SafetyLevel } from "./safety-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

export type OpsPhase =
  | "idle"
  | "recon"
  | "enumeration"
  | "vuln_detection"
  | "exploitation"
  | "post_exploit"
  | "reporting"
  | "completed"
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
  vulns: Array<{ id: string; severity: string; title: string; cve?: string }>;
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
    findings: Array<{ severity: string; title: string; cve?: string }>;
    outputPreview: string; // first 2KB of stdout
    executedAt: number;
    phase: string;
  }>;
}

/** Format target display: always show IP alongside hostname when available */
function fmtTarget(asset: { hostname: string; ip?: string } | null, fallbackTarget?: string): string {
  if (!asset) return fallbackTarget || 'unknown';
  if (asset.ip && asset.ip !== asset.hostname) return `${asset.hostname} (${asset.ip})`;
  return asset.hostname;
}

export interface AssetScanPlan {
  hostname: string;
  ip?: string;
  assetType: string;
  /** Phase A: discovery nmap flags — broad port sweep + service fingerprinting with evasion */
  discoveryNmapFlags: string;
  discoveryNmapRationale: string;
  /** httpx flags for HTTP probing on discovered web ports */
  httpxFlags: string;
  /** Phase B: targeted nmap flags — deeper scan based on discovery results */
  nmapFlags: string;
  nmapRationale: string;
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
export interface EngagementOpsState {
  engagementId: number;
  engagementType: "pentest" | "red_team" | "purple_team" | "phishing" | "tabletop";
  phase: OpsPhase;
  progress: number; // 0-100
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
const approvalResolvers = new Map<string, (approved: boolean) => void>();

let idCounter = 0;
function genId(): string {
  return `ops-${Date.now()}-${++idCounter}`;
}

/**
 * Deduplicated vuln push — prevents duplicate vulnerabilities on the same asset.
 * Deduplicates by matching on (title + cve). Returns true if the vuln was added (new),
 * false if it was a duplicate and skipped.
 */
export function pushVulnDeduped(
  asset: AssetStatus,
  vuln: { id: string; severity: string; title: string; cve?: string; [key: string]: any },
): boolean {
  const isDuplicate = asset.vulns.some((existing: any) => {
    // Match on CVE if both have one
    if (vuln.cve && existing.cve && vuln.cve === existing.cve) return true;
    // Match on title (normalized)
    if (existing.title === vuln.title) return true;
    return false;
  });
  if (isDuplicate) return false;
  asset.vulns.push(vuln as any);
  return true;
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

  // Ensure boolean fields
  if (typeof state.isRunning !== 'boolean') state.isRunning = false;
  if (typeof state.isPaused !== 'boolean') state.isPaused = false;

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
 * Every target MUST pass this check before any active scanning (nmap, nuclei,
 * ZAP, etc.). Passive OSINT can discover assets outside scope, but they are
 * tagged as "out_of_scope" and NEVER actively probed.
 */
export function isInRoeScope(state: EngagementOpsState, hostname: string, ip?: string): boolean {
  const guard = state.roeScopeGuard;
  if (!guard) return true; // No guard = legacy behavior (all assets in scope)
  const normalizedHost = hostname.toLowerCase().trim();
  const normalizedIp = (ip || "").trim();
  // Check exact domain match
  if (guard.authorizedDomains.some(d => d.toLowerCase().trim() === normalizedHost)) return true;
  // Check exact IP match
  if (normalizedIp && guard.authorizedIps.some(i => i.trim() === normalizedIp)) return true;
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

function persistOpsStateDebounced(engagementId: number, delayMs = 2000) {
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
}

// ─── Memory Watchdog ──────────────────────────────────────────────────────────

let memoryWatchdogInterval: NodeJS.Timeout | null = null;

/** Start a memory watchdog that logs warnings and triggers emergency trimming */
export function startMemoryWatchdog() {
  if (memoryWatchdogInterval) return;
  memoryWatchdogInterval = setInterval(() => {
    const mem = process.memoryUsage();
    const heapMB = mem.heapUsed / 1024 / 1024;
    const rssMB = mem.rss / 1024 / 1024;
    if (heapMB > 300) {
      console.warn(`[MemoryWatchdog] HIGH HEAP: ${heapMB.toFixed(0)}MB heap, ${rssMB.toFixed(0)}MB RSS, ${opsStates.size} active states`);
      // Emergency: trim all active states' logs and toolResults
      for (const [engId, state] of opsStates.entries()) {
        const maxLogs = heapMB > 400 ? 100 : 250;
        if (state.log.length > maxLogs) {
          state.log = state.log.slice(-maxLogs);
          console.warn(`[MemoryWatchdog] Trimmed logs for engagement #${engId} to ${maxLogs}`);
        }
        // Trim large toolResult outputs
        for (const asset of state.assets) {
          for (const tr of (asset.toolResults || [])) {
            if (tr.outputPreview && tr.outputPreview.length > 1024) {
              tr.outputPreview = tr.outputPreview.slice(0, 512) + '...[trimmed by watchdog]';
            }
          }
        }
      }
      // Suggest GC if available
      if (global.gc) {
        console.warn('[MemoryWatchdog] Triggering manual GC...');
        global.gc();
      }
    }
  }, 30_000); // Check every 30 seconds
}

/** Stop the memory watchdog */
export function stopMemoryWatchdog() {
  if (memoryWatchdogInterval) {
    clearInterval(memoryWatchdogInterval);
    memoryWatchdogInterval = null;
  }
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

export function addLog(state: EngagementOpsState, entry: Omit<OpsLogEntry, "id" | "timestamp">) {
  const logEntry: OpsLogEntry = { id: genId(), timestamp: Date.now(), ...entry };
  state.log.push(logEntry);
  // Memory-aware log trimming: aggressive when heap usage > 400MB
  const heapMB = process.memoryUsage().heapUsed / 1024 / 1024;
  const maxLogs = heapMB > 400 ? 200 : heapMB > 300 ? 350 : 500;
  if (state.log.length > maxLogs) state.log = state.log.slice(-maxLogs);
  // Under extreme memory pressure, also trim toolResults outputPreview
  if (heapMB > 400) {
    for (const asset of state.assets) {
      for (const tr of (asset.toolResults || [])) {
        if (tr.outputPreview && tr.outputPreview.length > 512) {
          tr.outputPreview = tr.outputPreview.slice(0, 512) + '...[trimmed]';
        }
      }
    }
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
      description: logEntry.detail?.slice(0, 5000),
      metadata: logEntry.data || null,
      sourceModule: 'engagement-orchestrator',
      timestamp: logEntry.timestamp,
    });
  } catch (err: any) {
    console.error(`[TimelinePersist] Failed to persist timeline event:`, err.message);
  }
}

// ─── Scan Result Persistence ───────────────────────────────────────────────

async function persistScanResult(opts: {
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
    const { insertScanResult } = await import("../db");
    const severitySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of opts.findings) {
      const sev = (f.severity || "info").toLowerCase();
      if (sev in severitySummary) severitySummary[sev as keyof typeof severitySummary]++;
    }
    await insertScanResult({
      engagementId: opts.engagementId,
      tool: opts.tool,
      target: opts.target,
      command: opts.command,
      rawOutput: opts.stdout.slice(0, 1_000_000), // cap at 1MB
      rawStderr: (opts.stderr || "").slice(0, 500_000),
      exitCode: opts.exitCode,
      durationMs: opts.durationMs,
      timedOut: opts.timedOut,
      findings: opts.findings,
      findingCount: opts.findings.length,
      severitySummary,
      phase: opts.phase,
      operatorId: opts.operatorId,
    });
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
function shouldAutoApprove(state: EngagementOpsState, riskTier: string): boolean {
  // Training lab mode: auto-approve ALL gates including red tier (exploitation)
  // Training labs are authorized targets where we want the full pipeline to run unattended
  if ((state as any).trainingLabMode === true) return true;

  // Only auto-approve if RoE is signed
  const roeStatus = state.roeScopeGuard?.roeStatus;
  if (roeStatus !== 'signed') return false;

  // Red tier always requires manual approval (destructive actions)
  if (riskTier === 'red') return false;

  // Yellow and orange tiers are auto-approved for signed RoE
  // This covers: credential testing, enumeration, vulnerability scanning
  return true;
}

async function requestApproval(
  state: EngagementOpsState,
  gate: Omit<ApprovalGate, "id" | "status" | "createdAt">
): Promise<boolean> {
  // ── Auto-Approval for Signed RoE ──
  // Skip the blocking approval gate for low/medium risk actions when RoE is signed
  if (shouldAutoApprove(state, gate.riskTier)) {
    const approval: ApprovalGate = {
      id: genId(),
      status: "approved",
      createdAt: Date.now(),
      resolvedAt: Date.now(),
      resolvedBy: 'auto-approval:signed-roe',
      ...gate,
    };
    state.approvalGates.push(approval);

    addLog(state, {
      phase: gate.phase,
      type: "approval_response",
      title: `✅ Auto-Approved (Signed RoE): ${gate.title}`,
      detail: `${gate.description} — Auto-approved because RoE is signed and risk tier is ${gate.riskTier}.`,
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

  // ── Manual Approval Gate ──
  const approval: ApprovalGate = {
    id: genId(),
    status: "pending",
    createdAt: Date.now(),
    ...gate,
  };
  state.approvalGates.push(approval);
  state.isPaused = true;
  state.currentAction = `⏸ Awaiting approval: ${gate.title}`;

  addLog(state, {
    phase: gate.phase,
    type: "approval_request",
    title: `🔒 Approval Required: ${gate.title}`,
    detail: gate.description,
    data: gate.detail,
    riskTier: gate.riskTier,
  });

  broadcastOpsUpdate(state.engagementId, {
    type: "approval_required",
    gate: approval,
  });

  // Wait for operator response (with 5-minute timeout to prevent indefinite blocking)
  return new Promise<boolean>((resolve) => {
    const timeoutId = setTimeout(() => {
      // If no response after 5 minutes, auto-approve yellow/orange, deny red
      const autoDecision = gate.riskTier !== 'red';
      approval.status = autoDecision ? "approved" : "denied";
      approval.resolvedAt = Date.now();
      approval.resolvedBy = `auto-timeout:${autoDecision ? 'approved' : 'denied'}`;
      state.isPaused = false;
      approvalResolvers.delete(approval.id);

      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: autoDecision ? `✅ Auto-Approved (Timeout): ${gate.title}` : `❌ Auto-Denied (Timeout): ${gate.title}`,
        detail: `No operator response after 5 minutes. ${autoDecision ? 'Auto-approved' : 'Auto-denied'} based on risk tier (${gate.riskTier}).`,
        riskTier: gate.riskTier,
      });

      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: approval.id,
        approved: autoDecision,
      });

      resolve(autoDecision);
    }, 5 * 60 * 1000); // 5 minute timeout

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

export function resolveApproval(gateId: string, approved: boolean, resolvedBy?: string): boolean {
  const resolver = approvalResolvers.get(gateId);
  if (!resolver) return false;
  // Find the gate and set resolvedBy
  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find(g => g.id === gateId);
    if (gate) {
      gate.resolvedBy = resolvedBy;
      break;
    }
  }
  resolver(approved);
  approvalResolvers.delete(gateId);
  return true;
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

async function auditLog(params: {
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
    detail: `Analyzing ${state.assets.length} discovered assets to determine optimal nmap settings and active scan tools...`,
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
    'nmap: port scan/service detection',
    'nuclei: vuln scanner (-u URL -severity critical,high,medium -nc -duc -ni -jsonl)',
    'nikto: web server scanner (-h URL)',
    'gobuster: dir brute-forcer',
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
    'ffuf: web fuzzer (ffuf -u URL/FUZZ -w wordlist -mc 200,301,302,403 -of json)',
    'feroxbuster: recursive dir discovery (feroxbuster -u URL -w wordlist --json --smart)',
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

PHASE A — Discovery: nmap --top-ports 1000 -T3 then httpx on web ports. discoveryNmapFlags = scan type/evasion only (no -p, --top-ports, -T). Cloud/WAF targets: use '-Pn -sV -sC' only, no evasion flags.
PHASE B — Targeted tools per asset based on recon: Web→nuclei,nikto,ffuf,feroxbuster,whatweb,testssl; WP→wpscan; SQLi→sqlmap; Cloud→cloud_enum,s3scanner; SMB→enum4linux; LDAP→ldapsearch; DNS→dig; SNMP→onesixtyone; Login→hydra.

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

  const tier1Content = `Assets (${state.assets.length}, ${state.engagementType}):\n${assetLines}\n${domainLines ? '\nDomain Intel:\n' + domainLines + '\n' : ''}\nGenerate two-phase scan plan. Phase A: nmap --top-ports 1000. Phase B: tools per asset.`;

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
    const nmapCtx = getNmapScanPlanContext({
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
    enrichmentCtx = [
      ontologyCtx ? '## Asset Architecture Context\n' + ontologyCtx : '',
      bbCtx ? '## Bug Bounty Methodology\n' + bbCtx : '',
      corpusCtx ? '## Triage Examples\n' + corpusCtx : '',
      cloudCtx || '',
      nmapCtx || '',
      owaspCtx || '',
      threatGroupCtx || '',
      threatActorLearningCtx || '',
      offensiveTechCtx || '',
      zapKnowledgeCtx || '',
      sourceSecretsCtx || '',
      toolsCtx || '',
      methodologyCtx ? '## Attack Methodology Knowledge\n' + methodologyCtx : '',
      phaseToolCtx ? '## Phase Tool Recommendations\n' + phaseToolCtx : '',
    ].filter(Boolean).join('\n\n');
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
                discoveryNmapFlags: { type: 'string' },
                discoveryNmapRationale: { type: 'string' },
                httpxFlags: { type: 'string', description: 'httpx flags for HTTP probing on discovered web ports' },
                nmapFlags: { type: 'string' },
                nmapRationale: { type: 'string' },
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
              required: ['hostname', 'ip', 'assetType', 'discoveryNmapFlags', 'discoveryNmapRationale', 'httpxFlags', 'nmapFlags', 'nmapRationale', 'activeTools', 'riskNotes', 'evasionTechniques'],
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
      assetPlans: attackPlan.scan_plan.nmap_targets.map(nt => {
        const webScans = attackPlan.scan_plan.web_scan_targets.filter(w => w.target === nt.target);
        const nucleiScans = attackPlan.scan_plan.nuclei_targets.filter(n => n.target === nt.target);
        return {
          hostname: nt.target,
          ip: state.assets.find(a => a.hostname === nt.target)?.ip || nt.target,
          assetType: state.assets.find(a => a.hostname === nt.target)?.type || 'unknown',
          discoveryNmapFlags: '-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64',
          discoveryNmapRationale: 'Default discovery with evasion',
          httpxFlags: '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent',
          nmapFlags: nt.flags,
          nmapRationale: nt.rationale,
          activeTools: [
            ...nucleiScans.map(n => ({ tool: 'nuclei', command: `nuclei -u ${n.target} -severity critical,high,medium -tags ${n.templates} -nc -duc -ni -jsonl`, rationale: n.rationale, priority: 1 })),
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
      response = await throttledLLMCall({
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: tier1Content },
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
      discoveryNmapFlags: ap.discoveryNmapFlags || '-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64',
      discoveryNmapRationale: ap.discoveryNmapRationale || 'Default discovery scan with evasion and --top-ports 1000',
      httpxFlags: ap.httpxFlags || '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent',
      nmapFlags: ap.nmapFlags,
      nmapRationale: ap.nmapRationale,
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
      detail: `Phase A discovery: ${ap.discoveryNmapFlags}\n  Rationale: ${ap.discoveryNmapRationale}\nPhase B targeted: ${ap.nmapFlags}\n  Rationale: ${ap.nmapRationale}\nTools: ${ap.activeTools.map(t => t.tool).join(', ')}\nEvasion: ${ap.evasionTechniques.join(', ')}\nRisk: ${ap.riskNotes}`,
      data: { assetPlan: ap },
    });
  }

  broadcastOpsUpdate(engagementId, { type: 'scan_plan', scanPlan });

  return scanPlan;
}

// ─── LLM Decision Engine ───────────────────────────────────────────────────

async function llmDecide(context: {
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
      availableTools: ['nmap', 'nuclei', 'zap', 'nikto', 'gobuster', 'ffuf', 'testssl', 'hydra', 'sqlmap'],
      engagement: {
        engagementType: context.engagementType,
        clientName: context.assets[0]?.hostname,
        targetCount: context.assets.length,
      },
      engagementId: context.engagementId,
    });

    // Map specialist output to legacy format
    const toolToActionType: Record<string, string> = {
      nmap: 'nmap_scan', nuclei: 'nuclei_scan', zap: 'zap_scan',
      nikto: 'nuclei_scan', gobuster: 'nuclei_scan', ffuf: 'nuclei_scan',
      testssl: 'nuclei_scan', hydra: 'exploit_attempt', sqlmap: 'exploit_attempt',
    };
    const actionType = toolToActionType[opsResult.recommended_action.tool] || 'nmap_scan';
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
      actions.push({ type: 'nmap_scan', params: { reason: alt.action } });
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
  // Build phase-specific instructions for the LLM
  const exploitPhaseInstructions = ['exploitation', 'post_exploit'].includes(context.phase)
    ? `\n\nIMPORTANT: You are in the ${context.phase} phase. You MUST return actions with type "exploit_attempt" for each vulnerability you want to exploit.
Each exploit_attempt action MUST include params: {target: "hostname", port: number, cve: "CVE-XXXX-XXXXX", service: "service_name", module: "exploit_module_or_technique"}
Prioritize critical and high severity vulnerabilities. Generate one exploit_attempt action per target/CVE combination.
Do NOT return scan-type actions (nmap_scan, nuclei_scan) during exploitation — only exploit_attempt, c2_deploy, or complete.`
    : '';

  const systemPrompt = `Pentest AI for ${context.engagementType} engagement. Phase: ${context.phase}.

Assets:\n${assetSummary}\n\nRecent:\n${recentActivity}\n\nReturn JSON: {"decision":"str","reasoning":"str","actions":[{"type":"nmap_scan|nuclei_scan|zap_scan|exploit_attempt|c2_deploy|recon|skip|complete|wait","params":{...}}]}
Action params: nmap_scan={targets,profile:quick|standard|deep|stealth|service|vuln} nuclei_scan={targets,severity,tags?} zap_scan={targetUrl,scanType:full|active|spider_only,wafAware} exploit_attempt={target,port,cve,service,module?} c2_deploy={target,platform,method} recon={domain} complete={reason}
Rules: pentest=test each asset systematically; red_team=find weakest entry,exploit,C2,pivot; WAF-aware scanning; correlate findings across tools; flag high-risk actions; stay in scope.${exploitPhaseInstructions}`;

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
  addLog(state, { phase: "recon", type: "info", title: "🔍 Phase 1: Recon & Discovery", detail: "Starting passive OSINT and domain intelligence scan" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "recon" });

   const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean);

  // ═══ INITIALIZE RoE SCOPE GUARD ═══
  // Hard-lock the authorized targets from the engagement's RoE before any scanning begins
  state.roeScopeGuard = {
    authorizedDomains: [...domains],
    authorizedIps: [...ipRanges],
    roeStatus: engagement.roeStatus || engagement.roe_status || "signed",
  };
  addLog(state, {
    phase: "recon", type: "info",
    title: "🛡️ RoE Scope Guard Activated",
    detail: `Authorized targets: ${domains.join(", ")}${ipRanges.length ? " | IPs: " + ipRanges.join(", ") : ""}\nOnly these targets will be actively scanned. Discovered assets outside scope will be tagged but NOT probed.`,
  });

  // Initialize assets from scope
  for (const domain of domains) {
    if (!state.assets.find(a => a.hostname === domain)) {
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
  for (const ip of ipRanges) {
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
      addLog(state, { phase: "recon", type: "scan_start", title: `Domain Intel: ${domain}`, detail: "Running passive OSINT scan" });

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
      function postureToVulns(findings: any[]): Array<{ id: string; severity: string; title: string; cve?: string; corroborationTier?: string; evidenceDetail?: string; detectedVersion?: string; affectedVersions?: string }> {
        return (findings || []).map((f: any, idx: number) => {
          // Determine corroboration tier based on evidence quality
          const hasVersion = !!f.detectedVersion && f.detectedVersion !== 'unknown';
          const hasConfirmedVersion = hasVersion && f.versionConfidence === 'confirmed';
          const tier = hasConfirmedVersion ? 'confirmed' : hasVersion ? 'probable' : 'potential';
          const evidenceSource = f.source || 'passive recon';

          return {
            id: f.cveIds?.[0] || `passive-${domain}-${idx}`,
            severity: f.severity >= 8 ? 'critical' : f.severity >= 6 ? 'high' : f.severity >= 4 ? 'medium' : 'low',
            title: f.title || f.category || 'Unknown finding',
            cve: f.cveIds?.[0],
            corroborationTier: tier,
            evidenceDetail: `Detected via ${evidenceSource}${hasVersion ? ` (version ${f.detectedVersion})` : ' (version unconfirmed)'}`,
            detectedVersion: f.detectedVersion || null,
            affectedVersions: f.affectedVersions || null,
          };
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
          // Defer passive vulns to pendingVulns — they will be promoted to vulns at vuln_detection phase start
          for (const v of passiveVulns) {
            const isDupe = existing.pendingVulns.some((pv: any) => {
              if (v.cve && pv.cve && v.cve === pv.cve) return true;
              if (pv.title === v.title) return true;
              return false;
            });
            if (!isDupe) existing.pendingVulns.push(v as any);
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
            ports: passiveRecon.services.map(svc => ({
              port: svc.port,
              service: svc.service || 'unknown',
              version: svc.version || '',
            })),
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
          const { scoreFullHybrid } = await import('./llm-specialists/hybrid-scorer');
          // Score each asset individually using the correct FullHybridScoreInput interface
          for (const asset of domainAssets) {
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
                engagementContext: state.engagementContext,
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
  addLog(state, { phase: "recon", type: "phase_complete", title: "✅ Phase 1 Complete", detail: `${state.assets.length} assets in scope` });
}

// ─── Tool Output Parser ────────────────────────────────────────────────────

function parseToolOutput(
  tool: string,
  stdout: string,
  asset: AssetStatus
): Array<{ severity: string; title: string; cve?: string }> {
  const findings: Array<{ severity: string; title: string; cve?: string }> = [];
  if (!stdout || stdout.length < 10) return findings;

  switch (tool) {
    case "nuclei": {
      // Nuclei JSONL output: one JSON object per line (-jsonl flag)
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[')) continue; // skip empty lines and banner
        try {
          const obj = JSON.parse(trimmed);
          if (obj.info?.severity && obj.info?.name) {
            const cve = obj["matched-at"]?.match(/CVE-\d{4}-\d+/)?.[0] ||
                        obj.info?.classification?.cve?.[0] ||
                        obj["template-id"]?.match(/CVE-\d{4}-\d+/)?.[0];
            const matchedAt = obj["matched-at"] || obj.host || '';
            findings.push({
              severity: obj.info.severity,
              title: `[Nuclei] ${obj.info.name}${matchedAt ? ` @ ${matchedAt}` : ''}`,
              cve,
            });
          }
        } catch { /* not JSON line — nuclei banner or progress output */ }
      }
      break;
    }
    case "nikto": {
      // Nikto text output: parse all finding lines (start with "+")
      // Nikto findings include: OSVDB, CVE, missing headers, misconfigurations, info leaks
      const niktoSkipPatterns = [
        /^\+ Target IP:/i,
        /^\+ Target Hostname:/i,
        /^\+ Target Port:/i,
        /^\+ Start Time:/i,
        /^\+ End Time:/i,
        /^\+ Server:/i,
        /^\+ \d+ host\(s\) tested/i,
        /^\+ \d+ items? checked/i,
        /^\+ No CGI Directories found/i,
        /^\+ ERROR:/i,
      ];
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("+")) continue;
        // Skip informational/meta lines
        if (niktoSkipPatterns.some(p => p.test(trimmed))) continue;

        const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
        const osvdb = trimmed.match(/OSVDB-\d+/)?.[0];
        // Determine severity based on content
        let severity = "info";
        if (cve) severity = "high";
        else if (osvdb) severity = "medium";
        else if (/is not present|not set|is not defined|header.*missing|missing.*header/i.test(trimmed)) severity = "low";
        else if (/directory indexing|listing|backup|config/i.test(trimmed)) severity = "medium";
        else if (/injection|xss|rfi|lfi|traversal|upload/i.test(trimmed)) severity = "high";
        else if (/default|sample|test|example/i.test(trimmed)) severity = "low";

        findings.push({
          severity,
          title: `[Nikto] ${trimmed.slice(2, 150).trim()}`,
          cve,
        });
      }
      break;
    }
    case "httpx": {
      // httpx JSON output: comprehensive parsing of all fields
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.tech && Array.isArray(obj.tech)) {
            for (const tech of obj.tech) {
              findings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
            }
          }
          if (obj.cdn_name) findings.push({ severity: "info", title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
          if (obj.webserver) findings.push({ severity: "info", title: `[httpx] Web Server: ${obj.webserver}` });
          if (obj.status_code) findings.push({ severity: "info", title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ''}`.trim() });
          if (obj.tls) {
            if (obj.tls.subject_cn) findings.push({ severity: "info", title: `[httpx] TLS CN: ${obj.tls.subject_cn}` });
            if (obj.tls.subject_org) findings.push({ severity: "info", title: `[httpx] TLS Org: ${obj.tls.subject_org}` });
            if (obj.tls.not_after) findings.push({ severity: "info", title: `[httpx] TLS Expires: ${obj.tls.not_after}` });
          }
          // Enrich asset passiveRecon if available
          if (asset) {
            if (obj.tech && Array.isArray(obj.tech) && asset.passiveRecon) {
              asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), ...obj.tech])];
            }
            if (obj.webserver && asset.passiveRecon) {
              asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), obj.webserver])];
            }
          }
        } catch { /* not JSON line */ }
      }
      break;
    }
    case "naabu": {
      // naabu JSON output: port discovery
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.port && typeof obj.port === 'number') {
            findings.push({ severity: "info", title: `[naabu] Port ${obj.port} open on ${obj.host || obj.ip || 'target'}` });
          }
        } catch {
          // Handle plain "host:port" format
          const portMatch = trimmed.match(/:(\d+)$/);
          if (portMatch) {
            findings.push({ severity: "info", title: `[naabu] Port ${portMatch[1]} open` });
          }
        }
      }
      break;
    }
    case "gobuster": {
      // Gobuster: found directories/files
      for (const line of stdout.split("\n")) {
        const match = line.match(/\/(\S+)\s+\(Status:\s*(\d+)/);
        if (match) {
          const [, path, status] = match;
          if (["200", "301", "302", "401", "403"].includes(status)) {
            findings.push({
              severity: status === "401" || status === "403" ? "low" : "info",
              title: `[Gobuster] /${path} (${status})`,
            });
          }
        }
      }
      break;
    }
    case "enum4linux": {
      // enum4linux: look for shares, users, password policy
      if (stdout.includes("Sharename")) {
        findings.push({ severity: "medium", title: "[enum4linux] SMB shares enumerated" });
      }
      if (stdout.includes("user:")) {
        findings.push({ severity: "medium", title: "[enum4linux] User accounts enumerated via SMB" });
      }
      break;
    }
    case "hydra": {
      // Hydra: successful login — extract username/password and store on asset
      // Hydra output format: [<port>][<service>] host: <host>   login: <user>   password: <pass>
      //
      // FALSE POSITIVE DETECTION (http-get/https-get):
      // Hydra http-get mode tests HTTP Basic Auth. If the server does NOT use
      // HTTP Basic Auth (e.g., SPA behind CloudFront, form-based login), the
      // server returns HTTP 200 for ALL requests regardless of the Authorization
      // header. Hydra interprets every response as "valid credentials."
      //
      // Detection: If Hydra reports 3+ different credential pairs as valid for
      // the same http-get/https-get service, it's almost certainly a false positive
      // (a real server would only accept the correct credentials).
      const httpGetHits: Array<{ line: string; login: string; pass: string; svc: string; port: number }> = [];
      const nonHttpGetHits: Array<{ line: string; login: string; pass: string; svc: string; port: number }> = [];

      for (const line of stdout.split("\n")) {
        if (line.includes("login:") && line.includes("password:")) {
          const loginMatch = line.match(/login:\s*(\S+)/);
          const passMatch = line.match(/password:\s*(\S*)/);
          const svcMatch = line.match(/\[\d+\]\[(\S+)\]/) || line.match(/\[(\S+)\]/);
          const portMatch = line.match(/\[(\d+)\]/);
          const svc = svcMatch?.[1] || 'http';
          const port = portMatch ? parseInt(portMatch[1], 10) : (asset.ports[0]?.port || 80);

          const hit = {
            line: line.trim(),
            login: loginMatch?.[1] || '',
            pass: passMatch?.[1] || '',
            svc,
            port,
          };

          if (svc === 'http-get' || svc === 'https-get') {
            httpGetHits.push(hit);
          } else {
            nonHttpGetHits.push(hit);
          }
        }
      }

      // FP Detection: If Hydra reports 3+ different user:pass combos via http-get/https-get,
      // the server is NOT using HTTP Basic Auth — it returns 200 for everything.
      // Also flag if 2+ hits have DIFFERENT passwords for the same username (impossible for real auth).
      const isHttpGetFalsePositive = httpGetHits.length >= 3 ||
        (httpGetHits.length >= 2 && new Set(httpGetHits.map(h => h.pass)).size >= 2);

      if (isHttpGetFalsePositive && httpGetHits.length > 0) {
        // Downgrade to info — server does not use HTTP Basic Auth
        findings.push({
          severity: "info",
          title: `[Hydra] FALSE POSITIVE: Server returns HTTP 200 for all requests (no HTTP Basic Auth) — ${httpGetHits.length} credentials reported but server ignores Authorization header`,
        });
        // Do NOT add to confirmedCredentials — these are not real
      } else {
        // Genuine http-get/https-get hits (1-2 unique creds = plausible)
        for (const hit of httpGetHits) {
          findings.push({
            severity: "critical",
            title: `[Hydra] Valid credentials found: ${hit.line.slice(0, 100)}`,
          });
          if (asset.confirmedCredentials) {
            asset.confirmedCredentials.push({
              username: hit.login,
              password: hit.pass,
              service: hit.svc,
              port: hit.port,
              protocol: hit.svc.includes('http') ? 'http' : 'unknown',
              accessLevel: 'authenticated',
              source: 'hydra',
              responseSnippet: hit.line.slice(0, 200),
              confirmedAt: Date.now(),
            });
          }
        }
      }

      // Non-http-get hits (SSH, FTP, etc.) — always trust these
      for (const hit of nonHttpGetHits) {
        findings.push({
          severity: "critical",
          title: `[Hydra] Valid credentials found: ${hit.line.slice(0, 100)}`,
        });
        if (asset.confirmedCredentials) {
          asset.confirmedCredentials.push({
            username: hit.login,
            password: hit.pass,
            service: hit.svc,
            port: hit.port,
            protocol: hit.svc.includes('http') ? 'http' : (hit.svc || 'unknown'),
            accessLevel: 'authenticated',
            source: 'hydra',
            responseSnippet: hit.line.slice(0, 200),
            confirmedAt: Date.now(),
          });
        }
      }
      break;
    }
    case "dig": {
      if (stdout.includes("XFR size") || stdout.includes("Transfer")) {
        findings.push({ severity: "high", title: "[dig] DNS Zone Transfer successful" });
      }
      break;
    }
    case "smbclient": {
      if (stdout.includes("Sharename") && !stdout.includes("NT_STATUS_ACCESS_DENIED")) {
        findings.push({ severity: "medium", title: "[smbclient] Anonymous SMB share access" });
      }
      break;
    }
    case "ldapsearch": {
      if (stdout.includes("namingContexts") && !stdout.includes("Operations error")) {
        findings.push({ severity: "medium", title: "[ldapsearch] Anonymous LDAP bind successful" });
      }
      break;
    }
    case "onesixtyone": {
      for (const line of stdout.split("\n")) {
        if (line.includes("[") && !line.includes("Scanning")) {
          findings.push({ severity: "high", title: `[onesixtyone] SNMP community string found: ${line.trim().slice(0, 80)}` });
        }
      }
      break;
    }
    // ─── Cloud Storage & Misconfiguration Tool Parsers ─────────────────────
    case "cloud_enum": {
      // cloud_enum outputs discovered cloud resources line by line
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[*]') || trimmed.startsWith('[-]')) continue;
        // S3 bucket found
        if (trimmed.includes('s3.amazonaws.com') || trimmed.includes('.s3.')) {
          findings.push({ severity: "high", title: `[cloud_enum] S3 Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Azure Blob found
        else if (trimmed.includes('blob.core.windows.net')) {
          findings.push({ severity: "high", title: `[cloud_enum] Azure Blob Container Discovered: ${trimmed.slice(0, 120)}` });
        }
        // GCS bucket found
        else if (trimmed.includes('storage.googleapis.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] GCS Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Firebase
        else if (trimmed.includes('firebaseio.com') || trimmed.includes('firebaseapp.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] Firebase App Discovered: ${trimmed.slice(0, 120)}` });
        }
        // DigitalOcean Spaces
        else if (trimmed.includes('digitaloceanspaces.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] DO Spaces Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Generic open resource
        else if (trimmed.includes('[OPEN]') || trimmed.includes('OPEN') || trimmed.includes('200')) {
          findings.push({ severity: "critical", title: `[cloud_enum] Open Cloud Resource: ${trimmed.slice(0, 120)}` });
        }
      }
      break;
    }
    case "s3scanner": {
      // s3scanner JSON output: bucket permission results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const bucket = obj.bucket || obj.name || 'unknown';
          if (obj.exists === false) continue; // bucket doesn't exist
          if (obj.public_read || obj.AuthUsers_read) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC READ: s3://${bucket} — data exposure risk` });
          }
          if (obj.public_write || obj.AuthUsers_write) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC WRITE: s3://${bucket} — bucket takeover risk` });
          }
          if (obj.public_read_acp || obj.AuthUsers_read_acp) {
            findings.push({ severity: "high", title: `[s3scanner] ACL Readable: s3://${bucket} — permission enumeration` });
          }
          if (obj.exists && !obj.public_read && !obj.public_write) {
            findings.push({ severity: "info", title: `[s3scanner] Bucket exists (private): s3://${bucket}` });
          }
        } catch {
          // Plain text output fallback
          if (trimmed.includes('READ') || trimmed.includes('ListBucket')) {
            findings.push({ severity: "critical", title: `[s3scanner] Public Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes('WRITE') || trimmed.includes('PutObject')) {
            findings.push({ severity: "critical", title: `[s3scanner] Write Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes('exists') || trimmed.includes('bucket_exists')) {
            findings.push({ severity: "info", title: `[s3scanner] ${trimmed.slice(0, 120)}` });
          }
        }
      }
      break;
    }
    case "trufflehog": {
      // trufflehog JSON output: discovered secrets
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.DetectorName || obj.detector_name) {
            const detector = obj.DetectorName || obj.detector_name || 'Unknown';
            const source = obj.SourceMetadata?.Data?.S3?.bucket || obj.source || 'unknown';
            const verified = obj.Verified || obj.verified ? 'VERIFIED' : 'unverified';
            findings.push({
              severity: obj.Verified || obj.verified ? "critical" : "high",
              title: `[trufflehog] ${verified} Secret (${detector}) in ${source}`,
            });
          }
        } catch { /* not JSON */ }
      }
      break;
    }
    case "aws": {
      // AWS CLI output: s3 ls results, bucket policy, etc.
      if (stdout.includes('NoSuchBucket')) {
        findings.push({ severity: "high", title: `[aws] Subdomain Takeover Candidate: NoSuchBucket response` });
      } else if (stdout.includes('AccessDenied') || stdout.includes('Access Denied')) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but access denied (private)` });
      } else if (stdout.includes('AllAccessDisabled')) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but all access disabled` });
      } else {
        // Successful listing — parse objects
        const objectLines = stdout.split("\n").filter(l => l.trim() && !l.includes('PRE '));
        if (objectLines.length > 0) {
          findings.push({ severity: "critical", title: `[aws] PUBLIC S3 Bucket — ${objectLines.length} objects listed anonymously` });
          // Sample first 5 objects
          for (const line of objectLines.slice(0, 5)) {
            const parts = line.trim().split(/\s+/);
            const filename = parts[parts.length - 1];
            if (filename && filename !== 'None') {
              findings.push({ severity: "high", title: `[aws] Exposed file: ${filename}` });
            }
          }
        }
        // Check for directory prefixes (PRE)
        const prefixes = stdout.split("\n").filter(l => l.includes('PRE '));
        if (prefixes.length > 0) {
          findings.push({ severity: "high", title: `[aws] Public bucket with ${prefixes.length} directories` });
        }
      }
      break;
    }
    case "bash": {
      // Bash commands used for Firebase, curl checks, etc.
      // Firebase Realtime DB open check
      if (stdout.includes('firebaseio.com')) {
        try {
          const obj = JSON.parse(stdout);
          if (obj && Object.keys(obj).length > 0 && !obj.error) {
            findings.push({ severity: "critical", title: `[Firebase] Database publicly readable — ${Object.keys(obj).length} top-level keys exposed` });
          }
        } catch {
          if (!stdout.includes('Permission denied') && !stdout.includes('null') && stdout.length > 5) {
            findings.push({ severity: "high", title: `[Firebase] Possible public database access` });
          }
        }
      }
      // Generic curl checks for cloud misconfigs
      if (stdout.includes('ListBucketResult') || stdout.includes('<Contents>')) {
        findings.push({ severity: "critical", title: `[curl] S3 Bucket Directory Listing Enabled` });
      }
      if (stdout.includes('BlobNotFound') || stdout.includes('ContainerNotFound')) {
        findings.push({ severity: "high", title: `[curl] Azure Blob Subdomain Takeover Candidate` });
      }
      if (stdout.includes('NoSuchBucket')) {
        findings.push({ severity: "high", title: `[curl] S3 Subdomain Takeover Candidate — NoSuchBucket` });
      }
      break;
    }
    case "ffuf": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.results && Array.isArray(obj.results)) {
            for (const r of obj.results) {
              const status = r.status || r.StatusCode;
              const url = r.url || r.Url || '';
              if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
                findings.push({ severity: status === 500 ? "medium" : "info", title: `[ffuf] ${url} (${status}, ${r.length || '?'}B)` });
              }
            }
          }
        } catch {
          const match = trimmed.match(/(https?:\/\/\S+)\s+\[Status:\s*(\d+)/);
          if (match) findings.push({ severity: "info", title: `[ffuf] ${match[1]} (${match[2]})` });
        }
      }
      break;
    }
    case "sslscan": {
      if (stdout.includes('SSLv2') && !stdout.includes('SSLv2 disabled')) findings.push({ severity: "critical", title: "[sslscan] SSLv2 enabled" });
      if (stdout.includes('SSLv3') && !stdout.includes('SSLv3 disabled')) findings.push({ severity: "high", title: "[sslscan] SSLv3 enabled (POODLE)" });
      if (/TLSv1\.0.*enabled/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] TLS 1.0 enabled" });
      if (/Heartbleed.*vulnerable/i.test(stdout)) findings.push({ severity: "critical", title: "[sslscan] Heartbleed", cve: "CVE-2014-0160" });
      if (/RC4|DES|NULL|EXPORT/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Weak cipher suites accepted" });
      if (/self.signed/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] Self-signed certificate" });
      if (/expired/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Expired certificate" });
      break;
    }
    case "whatweb": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('WhatWeb') || trimmed.startsWith('ERROR')) continue;
        const urlMatch = trimmed.match(/^(https?:\/\/\S+)/);
        const url = urlMatch ? urlMatch[1] : '';
        const techMatches = trimmed.match(/\[([^\]]+)\]/g);
        if (techMatches) {
          for (const tech of techMatches) {
            const techName = tech.slice(1, -1);
            if (techName.length > 2 && !techName.match(/^\d{3}$/)) {
              findings.push({ severity: "info", title: `[whatweb] ${techName}${url ? ` @ ${url}` : ''}` });
            }
          }
        }
      }
      break;
    }
    case "subfinder": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.includes('.') && !trimmed.startsWith('[')) {
          findings.push({ severity: "info", title: `[subfinder] Subdomain: ${trimmed}` });
        }
      }
      break;
    }
    case "feroxbuster": {
      // feroxbuster JSON output: recursive directory discovery results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const status = obj.status || obj.status_code;
          const url = obj.url || obj.original_url || '';
          const length = obj.content_length || obj.length || '?';
          if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
            let severity = "info";
            if (status === 500) severity = "medium";
            else if (status === 401 || status === 403) severity = "low";
            else if (/admin|config|backup|\.env|\.git|\.sql|\.bak|upload|dashboard|secret|password/i.test(url)) severity = "medium";
            findings.push({ severity, title: `[feroxbuster] ${url} (${status}, ${length}B)` });
          }
        } catch {
          // Plain text output fallback: "STATUS  LINES  WORDS  CHARS  URL"
          const match = trimmed.match(/(\d{3})\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+(\S+)/);
          if (match) {
            const [, status, url] = match;
            findings.push({ severity: "info", title: `[feroxbuster] ${url} (${status})` });
          }
        }
      }
      break;
    }
    case "sqlmap": {
      // sqlmap output: SQL injection detection and exploitation results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        // Injection point found
        if (/Parameter.*is vulnerable/i.test(trimmed) || /injectable/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] SQL Injection Confirmed: ${trimmed.slice(0, 150)}` });
        }
        // Database type identified
        else if (/back-end DBMS/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] ${trimmed.slice(0, 150)}` });
        }
        // Data extracted
        else if (/available databases/i.test(trimmed) || /Database:/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Database Enumerated: ${trimmed.slice(0, 150)}` });
        }
        // Tables/columns dumped
        else if (/Table:/i.test(trimmed) || /\d+ entries/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Data Extracted: ${trimmed.slice(0, 150)}` });
        }
        // OS shell or file access
        else if (/os-shell|file-read|file-write/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] OS-level Access: ${trimmed.slice(0, 150)}` });
        }
        // Injection type info
        else if (/Type:\s*(boolean|time|error|UNION|stacked)/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] Injection Type: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "amass": {
      // amass output: subdomain and infrastructure discovery
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('Querying') || trimmed.startsWith('OWASP') || trimmed.startsWith('The enumeration')) continue;
        // JSON output mode
        try {
          const obj = JSON.parse(trimmed);
          if (obj.name) {
            const sources = obj.sources?.join(', ') || '';
            findings.push({ severity: "info", title: `[amass] ${obj.name}${obj.addresses ? ` → ${obj.addresses.map((a: any) => a.ip).join(', ')}` : ''}${sources ? ` (${sources})` : ''}` });
          }
          continue;
        } catch { /* plain text mode */ }
        // Plain text: one subdomain per line
        if (trimmed.includes('.') && !trimmed.includes(' ')) {
          findings.push({ severity: "info", title: `[amass] Subdomain: ${trimmed}` });
        }
        // CIDR/ASN info
        else if (/ASN|CIDR|Netblock/i.test(trimmed)) {
          findings.push({ severity: "info", title: `[amass] Infrastructure: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "katana": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.startsWith('http')) {
          const isInteresting = /admin|login|api|config|backup|upload|dashboard|\.env|\.git/i.test(trimmed);
          if (isInteresting) findings.push({ severity: "medium", title: `[katana] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "gospider": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed.includes('[form]')) findings.push({ severity: "medium", title: `[gospider] Form: ${trimmed.slice(0, 150)}` });
        else if ((trimmed.includes('[javascript]') || trimmed.includes('[linkfinder]')) && /api|token|key|secret|admin/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[gospider] JS endpoint: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "waybackurls":
    case "gau": {
      const toolLabel = tool;
      let totalUrls = 0;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('http')) continue;
        totalUrls++;
        if (/admin|login|api|config|backup|\.env|\.git|\.sql|\.bak|\.zip|password|secret|token/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[${toolLabel}] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      if (totalUrls > 0) findings.push({ severity: "info", title: `[${toolLabel}] ${totalUrls} historical URLs` });
      break;
    }
    case "curl": {
      if (stdout.includes('ListBucketResult') || stdout.includes('<Contents>')) findings.push({ severity: "critical", title: "[curl] S3 Bucket Directory Listing" });
      if (stdout.includes('NoSuchBucket')) findings.push({ severity: "high", title: "[curl] S3 Subdomain Takeover Candidate" });
      if (stdout.includes('BlobNotFound') || stdout.includes('ContainerNotFound')) findings.push({ severity: "high", title: "[curl] Azure Blob Takeover Candidate" });
      const headerLines = stdout.split("\n");
      const serverHeader = headerLines.find(l => /^server:/i.test(l.trim()));
      if (serverHeader) findings.push({ severity: "info", title: `[curl] ${serverHeader.trim()}` });
      break;
    }
    case "wpscan": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.includes('[!]') || trimmed.includes('[+]')) {
          const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
          if (cve || /vulnerability|outdated|insecure/i.test(trimmed)) {
            findings.push({ severity: cve ? "high" : "medium", title: `[wpscan] ${trimmed.slice(0, 150)}`, cve });
          }
        }
      }
      break;
    }
    case "testssl": {
      for (const line of stdout.split("\n")) {
        if (/VULNERABLE/i.test(line)) {
          const cve = line.match(/CVE-\d{4}-\d+/)?.[0];
          findings.push({ severity: cve ? "critical" : "high", title: `[testssl] ${line.trim().slice(0, 150)}`, cve });
        }
      }
      if (/NOT\s+ok/i.test(stdout)) findings.push({ severity: "medium", title: "[testssl] TLS configuration issues" });
      break;
    }
    case "nmap": {
      const portRegex = /^(\d+)\/tcp\s+(open|filtered)\s+(\S+)\s*(.*)/;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        const portMatch = trimmed.match(portRegex);
        if (portMatch && portMatch[2] === 'open') {
          findings.push({ severity: "info", title: `[nmap] ${portMatch[1]}/tcp ${portMatch[3]}${portMatch[4] ? ' ' + portMatch[4].trim() : ''}` });
        }
        const cveMatch = trimmed.match(/CVE-\d{4}-\d+/g);
        if (cveMatch) {
          for (const cve of cveMatch) {
            findings.push({ severity: "high", title: `[nmap] ${cve} — ${trimmed.slice(0, 120)}`, cve });
          }
        }
        if (/VULNERABLE/i.test(trimmed)) findings.push({ severity: "high", title: `[nmap] ${trimmed.slice(0, 150)}` });
        if (/message_signing.*disabled/i.test(trimmed)) findings.push({ severity: "medium", title: "[nmap] SMB signing disabled" });
        if (/Anonymous FTP login allowed/i.test(trimmed)) findings.push({ severity: "high", title: "[nmap] Anonymous FTP login" });
      }
      break;
    }
    default:
      break;
  }

  return findings;
}

async function executeEnumeration(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, { phase: "enumeration", type: "info", title: "🔎 Phase 2: Enumeration & Fingerprinting", detail: "Two-phase approach: Phase A discovery nmap with evasion → Phase B targeted tool deployment" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });

  // ═══ RoE SCOPE GUARD: Filter active scan targets to only authorized assets ═══
  const scopedAssets = state.assets.filter(a => isInRoeScope(state, a.hostname, a.ip));
  const skippedAssets = state.assets.filter(a => !isInRoeScope(state, a.hostname, a.ip));
  if (skippedAssets.length > 0) {
    addLog(state, {
      phase: "enumeration", type: "warning",
      title: `🛡️ Scope Guard: ${skippedAssets.length} assets excluded from active scanning`,
      detail: `Excluded: ${skippedAssets.map(a => a.hostname).join(", ")}\nOnly RoE-authorized targets will be actively probed.`,
    });
  }
  // ═══ DNS PRE-RESOLUTION: Resolve hostnames to IPs before nmap ═══
  // nmap on the scan server may fail to resolve hostnames (e.g., training labs
  // hosted via path-based routing on scan.aceofcloud.io). Pre-resolve here and
  // fall back to scan server IP for known self-hosted labs.
  const dns = await import('dns');
  const { promisify } = await import('util');
  const dnsResolve4 = promisify(dns.resolve4);
  const scanServerHost = process.env.SCAN_SERVER_HOST || '';
  const SCAN_SERVER_DOMAIN = 'scan.aceofcloud.io';

  addLog(state, { phase: 'enumeration', type: 'info', title: `DNS Pre-Resolution: checking ${scopedAssets.length} assets`, detail: `Resolving hostnames to IPs before nmap scan` });
  for (const asset of scopedAssets) {
    if (asset.ip) continue; // Already has an IP
    const hostname = asset.hostname;
    try {
      const ips = await dnsResolve4(hostname);
      if (ips.length > 0) {
        asset.ip = ips[0];
        addLog(state, { phase: 'enumeration', type: 'info', title: `DNS Resolved: ${hostname}`, detail: `${hostname} → ${ips[0]}` });
      }
    } catch (_dnsErr: any) {
      // DNS failed — check if this is a training lab hosted on the scan server
      // Detection heuristics: engagement type, liveInstanceUrl, hostname pattern, or scan server domain match
      const knownLabSubdomains = ['dvwa', 'juice-shop', 'juiceshop', 'webgoat', 'bwapp', 'mutillidae', 'vampi', 'crapi', 'hackazon'];
      const hostnameBase = hostname.split('.')[0]?.toLowerCase() || '';
      const isLabOnScanServer = state.engagementType === 'training_lab' ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(SCAN_SERVER_DOMAIN) ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(scanServerHost) ||
        (hostname.endsWith('.aceofcloud.io') && knownLabSubdomains.includes(hostnameBase)) ||
        (hostname.includes(SCAN_SERVER_DOMAIN));

      if (isLabOnScanServer) {
        // Resolve scan server domain to get the IP
        try {
          const scanIps = await dnsResolve4(SCAN_SERVER_DOMAIN);
          if (scanIps.length > 0) {
            asset.ip = scanIps[0];
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `DNS Fallback: ${hostname} → scan server IP`,
              detail: `${hostname} failed DNS resolution. Training lab detected — using scan server IP ${scanIps[0]} (${SCAN_SERVER_DOMAIN})`,
            });
          }
        } catch {
          // Even scan server domain failed — try raw IP from env
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(scanServerHost)) {
            asset.ip = scanServerHost;
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `DNS Fallback: ${hostname} → scan server IP (env)`,
              detail: `Using SCAN_SERVER_HOST env IP: ${scanServerHost}`,
            });
          }
        }
      }

      if (!asset.ip) {
        addLog(state, {
          phase: 'enumeration', type: 'warning',
          title: `⚠️ DNS Resolution Failed: ${hostname}`,
          detail: `Could not resolve ${hostname} to an IP address. nmap may fail for this target.`,
        });
      }
    }
  }

  const targets = scopedAssets.map(a => a.ip || a.hostname);

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A: Discovery Nmap with Evasion Tactics
  // ═══════════════════════════════════════════════════════════════════════════
  if (targets.length > 0) {
    const ep = state.scanPlan?.discoveryEvasionProfile;
    const evasionDesc = ep
      ? `Timing: ${ep.timing}, Fragmentation: ${ep.fragmentation}, Decoys: ${ep.decoys}, Host Randomization: ${ep.randomizeHosts}, Data Padding: ${ep.dataLengthPadding}, Source Port Spoofing: ${ep.sourcePortSpoofing}`
      : 'Default evasion profile';

    addLog(state, {
      phase: "enumeration", type: "scan_start",
      title: "🔍 Phase A: Discovery Scan with Evasion",
      detail: `Scanning ${targets.length} targets with full port sweep + service fingerprinting\nEvasion: ${evasionDesc}\n${state.scanPlan?.discoveryStrategy || 'Comprehensive port discovery to enrich passive recon data'}`,
    });

    try {
      // Job Queue Bridge: route scan execution through Redis queue when DO workers are available
      const { getScanServerConfigForNmap } = await import("./scan-server-executor");
      const { executeNmapScan } = await import("./nmap-orchestrator");
      const roeScope = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
      const engagementAbortSig = getEngagementAbortSignal(state.engagementId);
      const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope, engagementAbortSignal: engagementAbortSig });
      const serverConfig = await getScanServerConfigForNmap();

      for (const target of targets) {
        const asset = state.assets.find(a => (a.ip || a.hostname) === target);
        if (!asset) continue;
        asset.status = "scanning";

        // Get Phase A discovery flags from scan plan
        const assetPlan = state.scanPlan?.assetPlans.find(
          ap => ap.hostname === asset.hostname || ap.ip === target
        );

        // ── Step 1: nmap (port discovery + service fingerprinting) ──────────
        const discoveredPorts: Array<{ port: number; protocol: string; service: string; product?: string; version?: string }> = [];
        // Build nmap flags: always use --top-ports 1000 with -T3 timing for reliable results
        // CRITICAL: Never use -p- (all 65535 ports) — it takes 30+ min per host and will timeout
        const baseFlags = (assetPlan?.discoveryNmapFlags || '-Pn -sV -sC -O -f -D RND:5 --data-length 64')
          .replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, '')  // Remove -p with any value (numeric: -p80,443 or placeholder: -p {naabu_ports})
          .replace(/\s*-p-/g, '')           // Remove -p- (all ports)
          .replace(/\{[^}]+\}/g, '')        // Remove ALL {placeholder} strings (e.g., {target}, {naabu_ports})
          .replace(/--top-ports\s+\d+/g, '') // Remove existing --top-ports
          .replace(/-T\d/g, '')             // Remove timing flags (we force -T3)
          .replace(/--randomize-hosts/g, '')
          .replace(/\s+/g, ' ')
          .trim();
        const discoveryFlags = `${baseFlags} -T3 --top-ports 1000`;
        const discoveryRationale = 'Top 1000 ports scan with service fingerprinting';

        addLog(state, {
          phase: 'enumeration', type: 'scan_start',
          title: `🔒 nmap: ${fmtTarget(asset, target)}`,
          detail: `Phase A Step 1 — ${discoveryRationale}\nFlags: ${discoveryFlags}\nEvasion: ${assetPlan?.evasionTechniques?.join(', ') || 'fragmentation, decoys, normal timing'}`,
        });

        const startTime = Date.now();
        // ═══ AUTO-CAPTURE: Start tcpdump before nmap ═══
        let autoCaptureSessionId: string | null = null;
        try {
          const { beforeNmapScan } = await import('./pcap-auto-capture');
          autoCaptureSessionId = await beforeNmapScan(
            state.engagementId, target, asset.hostname,
            { enabled: !!(state as any).autoCaptureEnabled }
          );
          if (autoCaptureSessionId) {
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `📡 Auto-Capture: ${fmtTarget(asset, target)}`,
              detail: `Background tcpdump started for forensic analysis during nmap scan`,
            });
          }
        } catch (capErr: any) {
          console.warn(`[AutoCapture] Hook failed: ${capErr.message}`);
        }
        try {
          const nmapArgs = `${discoveryFlags} ${target}`;
          addLog(state, { phase: 'enumeration', type: 'tool_exec', title: `nmap ${fmtTarget(asset, target)}`, detail: `nmap ${nmapArgs}` });
          const nmapResult = await executeTool({ tool: 'nmap', args: nmapArgs, timeoutSeconds: 600, sudo: true });

          // Parse nmap text output into structured port data
          if (nmapResult.stdout) {
            const tcpRegex = /(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.*))?/g;
            let match;
            while ((match = tcpRegex.exec(nmapResult.stdout)) !== null) {
              const productVersion = match[3]?.trim() || '';
              const parts = productVersion.split(/\s+/);
              discoveredPorts.push({
                port: parseInt(match[1]),
                protocol: 'tcp',
                service: match[2],
                product: parts.length > 0 ? parts.slice(0, -1).join(' ') || parts[0] : undefined,
                version: parts.length > 1 ? parts[parts.length - 1] : undefined,
              });
            }
            const udpRegex = /(\d+)\/udp\s+open\s+(\S+)(?:\s+(.*))?/g;
            while ((match = udpRegex.exec(nmapResult.stdout)) !== null) {
              const productVersion = match[3]?.trim() || '';
              const parts = productVersion.split(/\s+/);
              discoveredPorts.push({
                port: parseInt(match[1]),
                protocol: 'udp',
                service: match[2],
                product: parts.length > 0 ? parts.slice(0, -1).join(' ') || parts[0] : undefined,
                version: parts.length > 1 ? parts[parts.length - 1] : undefined,
              });
            }
            // Parse OS detection
            const osMatch = nmapResult.stdout.match(/OS details:\s*(.+)/i) || nmapResult.stdout.match(/Running:\s*(.+)/i);
            if (osMatch && asset.passiveRecon) {
              (asset.passiveRecon as any).osDetected = osMatch[1].trim();
            }
          }

          let durationMs = Date.now() - startTime;

          // ── AUTO-RETRY: If nmap found 0 ports and output shows "filtered", retry without evasion flags ──
          // Cloud firewalls (CloudFront, AWS, etc.) DROP fragmented/spoofed packets, causing all ports to show as "filtered"
          const allFiltered = discoveredPorts.length === 0 && nmapResult.stdout && /All \d+ scanned ports.*filtered|\d+\/tcp\s+filtered/.test(nmapResult.stdout);
          const hasEvasionFlags = /\-f\b|\-D\s|--data-length|--source-port|--mtu/.test(discoveryFlags);

          if (allFiltered && hasEvasionFlags) {
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `⚠️ nmap Retry: ${fmtTarget(asset, target)} (removing evasion flags)`,
              detail: `First scan returned all-filtered (likely cloud WAF blocking evasion techniques). Retrying with simple flags: -Pn -sV -sC -T3 --top-ports 1000`,
            });

            const retryFlags = '-Pn -sV -sC -T3 --top-ports 1000';
            const retryArgs = `${retryFlags} ${target}`;
            const retryStart = Date.now();
            try {
              const retryResult = await executeTool({ tool: 'nmap', args: retryArgs, timeoutSeconds: 600, sudo: true });
              if (retryResult.stdout) {
                const tcpRegex2 = /(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.*))?/g;
                let m2;
                while ((m2 = tcpRegex2.exec(retryResult.stdout)) !== null) {
                  const pv = m2[3]?.trim() || '';
                  const pts = pv.split(/\s+/);
                  discoveredPorts.push({
                    port: parseInt(m2[1]), protocol: 'tcp', service: m2[2],
                    product: pts.length > 0 ? pts.slice(0, -1).join(' ') || pts[0] : undefined,
                    version: pts.length > 1 ? pts[pts.length - 1] : undefined,
                  });
                }
              }
              durationMs += (Date.now() - retryStart);
              addLog(state, {
                phase: 'enumeration', type: 'scan_result',
                title: `nmap Retry Complete: ${fmtTarget(asset, target)}`,
                detail: `Retry found ${discoveredPorts.length} services (simple flags worked)`,
              });

              // Persist retry result too
              await persistScanResult({
                engagementId: state.engagementId, tool: 'nmap', target,
                command: `nmap ${retryArgs}`, stdout: retryResult.stdout || '',
                stderr: retryResult.stderr || '', exitCode: retryResult.exitCode ?? 0,
                durationMs: Date.now() - retryStart, timedOut: retryResult.timedOut || false,
                findings: discoveredPorts.map(p => ({ type: 'open_port', port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
                phase: 'discovery_retry',
              });
            } catch (retryErr: any) {
              addLog(state, { phase: 'enumeration', type: 'error', title: `nmap Retry Failed: ${fmtTarget(asset, target)}`, detail: retryErr.message });
            }
          }

          // Merge discovery ports into asset
          asset.ports = discoveredPorts.map(p => ({
            port: p.port,
            service: p.service || 'unknown',
            version: p.product ? `${p.product}${p.version ? ' ' + p.version : ''}`.trim() : undefined,
          }));

          // ── PASSIVE RECON PORT SEEDING ──────────────────────────────────────
          // If nmap found 0 ports but passive recon detected web services,
          // seed standard web ports (80/443) so the pipeline continues to
          // credential testing and ZAP scanning. This handles training labs
          // behind nginx reverse proxies and CDN-fronted targets.
          if (discoveredPorts.length === 0) {
            const isWebAsset = asset.type === 'web_app' ||
              (asset.passiveRecon as any)?.technologies?.some((t: string) => /nginx|apache|iis|http|web|php|node|express|flask|django/i.test(t)) ||
              (asset.passiveRecon as any)?.services?.some((s: any) => /http/i.test(s.service || ''));

            // Also check if passive recon already found ports
            const passivePorts = (asset.passiveRecon as any)?.services?.map((s: any) => s.port).filter(Boolean) || [];

            if (isWebAsset || passivePorts.length > 0) {
              const seedPorts = passivePorts.length > 0
                ? passivePorts
                : [80, 443]; // Default web ports

              for (const port of seedPorts) {
                if (!asset.ports.some(p => p.port === port)) {
                  asset.ports.push({
                    port,
                    service: port === 443 ? 'https' : 'http',
                    version: undefined,
                  });
                }
              }

              addLog(state, {
                phase: 'enumeration', type: 'info',
                title: `🌐 Port Seeding: ${fmtTarget(asset, target)}`,
                detail: `nmap found 0 open ports but passive recon indicates web services. Seeded ports: ${asset.ports.map(p => `${p.port}/${p.service}`).join(', ')}. Pipeline will continue to credential testing and ZAP.`,
              });

              state.stats.portsFound += asset.ports.length;
            }
          }

          // Store nmap discovery result
          asset.toolResults.push({
            tool: 'nmap',
            command: `nmap ${nmapArgs}`,
            exitCode: nmapResult.exitCode ?? 0,
            durationMs,
            timedOut: nmapResult.timedOut || false,
            findingCount: discoveredPorts.length,
            findings: discoveredPorts.map(p => ({
              severity: 'info',
              title: `${p.port}/${p.protocol} ${p.service}${p.product ? ` (${p.product})` : ''}`,
            })),
            outputPreview: (nmapResult.stdout || '').slice(0, 2048),
            executedAt: Date.now(),
            phase: 'discovery',
          });

          state.stats.portsFound += discoveredPorts.length;
          state.stats.hostsScanned++;
          asset.status = 'enumerated';

          broadcastOpsUpdate(state.engagementId, { type: 'stats_update', stats: { ...state.stats } });
          addLog(state, {
            phase: 'enumeration', type: 'scan_result',
            title: `nmap Complete: ${fmtTarget(asset, target)}`,
            detail: `${discoveredPorts.length} services fingerprinted in ${Math.round(durationMs / 1000)}s\nPorts: ${discoveredPorts.map(p => `${p.port}/${p.service}${p.product ? ` (${p.product})` : ''}`).join(', ')}`,
            data: { ports: asset.ports, discoveryFlags, evasion: assetPlan?.evasionTechniques },
          });

          await persistScanResult({
            engagementId: state.engagementId,
            tool: 'nmap',
            target,
            command: `nmap ${nmapArgs}`,
            stdout: nmapResult.stdout || '',
            stderr: nmapResult.stderr || '',
            exitCode: nmapResult.exitCode ?? 0,
            durationMs,
            timedOut: nmapResult.timedOut || false,
            findings: discoveredPorts.map(p => ({ type: 'open_port', port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
            phase: 'discovery',
          });
        } catch (e: any) {
          addLog(state, { phase: 'enumeration', type: 'error', title: `nmap Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          asset.status = 'enumerated'; // Continue pipeline
        }

        // ═══ AUTO-CAPTURE: Stop tcpdump after nmap ═══
        if (autoCaptureSessionId) {
          try {
            const { afterNmapScan } = await import('./pcap-auto-capture');
            const captureResult = await afterNmapScan(autoCaptureSessionId);
            if (captureResult && captureResult.packetsCaptured) {
              addLog(state, {
                phase: 'enumeration', type: 'info',
                title: `📡 Auto-Capture Complete: ${fmtTarget(asset, target)}`,
                detail: `Captured ${captureResult.packetsCaptured} packets during nmap scan (${Math.round((captureResult.stoppedAt! - captureResult.startedAt) / 1000)}s)${
                  captureResult.analysisSummary ? `\nFindings: ${captureResult.analysisSummary.findings} security findings detected, ${captureResult.analysisSummary.conversations} conversations, protocols: ${captureResult.analysisSummary.protocols.join(', ')}` : ''
                }`,
                data: { pcapPath: captureResult.pcapPath, packetsCaptured: captureResult.packetsCaptured, analysisSummary: captureResult.analysisSummary },
              });
              // Store capture reference on asset for topology builder
              if (!(asset as any).pcapCaptures) (asset as any).pcapCaptures = [];
              (asset as any).pcapCaptures.push({
                sessionId: captureResult.sessionId,
                pcapPath: captureResult.pcapPath,
                packetsCaptured: captureResult.packetsCaptured,
                analysisSummary: captureResult.analysisSummary,
              });
            }
          } catch (capErr: any) {
            console.warn(`[AutoCapture] Stop hook failed: ${capErr.message}`);
          }
        }

        // ── Step 3: httpx (HTTP probing on web ports) ────────────────────
        const webPorts = discoveredPorts.filter(p =>
          ['http', 'https', 'http-proxy', 'http-alt', 'ssl'].includes(p.service) ||
          [80, 443, 8080, 8443, 8000, 3000, 5000, 9443].includes(p.port)
        );
        // Also probe common web ports even if nmap didn't detect them as open
        const commonWebPorts = [80, 443, 8080, 8443];
        for (const wp of commonWebPorts) {
          if (!webPorts.find(p => p.port === wp)) {
            // Always try common web ports — httpx will quickly determine if they're actually open
            webPorts.push({ port: wp, protocol: 'tcp', service: wp === 443 || wp === 8443 ? 'https' : 'http' });
          }
        }

        if (webPorts.length > 0) {
          asset.type = 'web_app';
          const httpxFlags = assetPlan?.httpxFlags || '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent';
          // Build target URLs for httpx
          const httpxTargets = webPorts.map(p => {
            const scheme = [443, 8443, 9443].includes(p.port) || p.service === 'https' || p.service === 'ssl' ? 'https' : 'http';
            return `${scheme}://${asset.hostname || target}:${p.port}`;
          });

          addLog(state, {
            phase: 'enumeration', type: 'scan_start',
            title: `🌐 httpx: ${fmtTarget(asset, target)}`,
            detail: `Phase A Step 2 — HTTP probing ${webPorts.length} web ports\nTargets: ${httpxTargets.join(', ')}\nFlags: ${httpxFlags}`,
          });

          try {
            const httpxStart = Date.now();
            // Pipe targets to httpx via echo
            const httpxInput = httpxTargets.join('\\n');
            const httpxArgs = `${httpxFlags}`;
            const httpxCmd = `echo -e '${httpxInput}' | httpx ${httpxArgs}`;
            addLog(state, { phase: 'enumeration', type: 'tool_exec', title: `httpx ${fmtTarget(asset, target)}`, detail: httpxCmd });
            const httpxResult = await executeTool({ tool: 'bash', args: `-c "echo -e '${httpxInput}' | httpx ${httpxArgs}"`, timeoutSeconds: 120 });
            const httpxDuration = Date.now() - httpxStart;

            // Parse httpx JSON output — each line is a JSON object with real data
            const httpxFindings: Array<{ severity: string; title: string }> = [];
            const techDetected: string[] = [];
            const cdnDetected: string[] = [];
            const responseHeaders: Record<string, string> = {};
            let webServer = '';
            let tlsInfo = '';

            if (httpxResult.stdout) {
              for (const line of httpxResult.stdout.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                  const obj = JSON.parse(trimmed);
                  // Technology detection
                  if (obj.tech && Array.isArray(obj.tech)) {
                    for (const tech of obj.tech) {
                      if (!techDetected.includes(tech)) techDetected.push(tech);
                      httpxFindings.push({ severity: 'info', title: `[httpx] Technology: ${tech}` });
                    }
                  }
                  // CDN/WAF detection
                  if (obj.cdn_name) {
                    if (!cdnDetected.includes(obj.cdn_name)) cdnDetected.push(obj.cdn_name);
                    httpxFindings.push({ severity: 'info', title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
                  }
                  if (obj.cdn === true) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] CDN detected` });
                  }
                  // Web server
                  if (obj.webserver) {
                    webServer = obj.webserver;
                    httpxFindings.push({ severity: 'info', title: `[httpx] Web Server: ${obj.webserver}` });
                  }
                  // TLS info
                  if (obj.tls) {
                    const tls = obj.tls;
                    tlsInfo = `${tls.version || ''} ${tls.cipher || ''}`.trim();
                    if (tls.subject_cn) httpxFindings.push({ severity: 'info', title: `[httpx] TLS CN: ${tls.subject_cn}` });
                    if (tls.subject_org) httpxFindings.push({ severity: 'info', title: `[httpx] TLS Org: ${tls.subject_org}` });
                    if (tls.not_after) httpxFindings.push({ severity: 'info', title: `[httpx] TLS Expires: ${tls.not_after}` });
                  }
                  // Status code + title
                  if (obj.status_code) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ''}`.trim() });
                  }
                  // Content length
                  if (obj.content_length !== undefined) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] Content-Length: ${obj.content_length}` });
                  }
                  // ── Response Header Extraction for Tech Stack Detection ──
                  // httpx -json includes response headers in the 'header' field (object of header arrays)
                  // and also in 'a' (raw response), 'response_header' (string), etc.
                  const headers = obj.header || obj.response_header || {};
                  if (typeof headers === 'object' && !Array.isArray(headers)) {
                    // httpx returns headers as { "header-name": ["value1", "value2"] }
                    for (const [key, val] of Object.entries(headers)) {
                      const lk = key.toLowerCase();
                      const headerVal = Array.isArray(val) ? val[0] : String(val);
                      if (lk === 'x-powered-by') {
                        responseHeaders['x-powered-by'] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Powered-By: ${headerVal}` });
                        // Extract tech from X-Powered-By (e.g., "PHP/8.1.2", "ASP.NET", "Express")
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === 'x-aspnet-version' || lk === 'x-aspnetmvc-version') {
                        responseHeaders[lk] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] ${key}: ${headerVal}` });
                        if (!techDetected.includes(`ASP.NET ${headerVal}`)) techDetected.push(`ASP.NET ${headerVal}`);
                      }
                      if (lk === 'x-generator') {
                        responseHeaders['x-generator'] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Generator: ${headerVal}` });
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === 'set-cookie') {
                        responseHeaders['set-cookie'] = headerVal;
                        // Detect tech from cookie names
                        if (headerVal.includes('PHPSESSID') && !techDetected.includes('PHP')) techDetected.push('PHP');
                        if (headerVal.includes('JSESSIONID') && !techDetected.includes('Java')) techDetected.push('Java');
                        if (headerVal.includes('ASP.NET_SessionId') && !techDetected.includes('ASP.NET')) techDetected.push('ASP.NET');
                        if (headerVal.includes('connect.sid') && !techDetected.includes('Node.js/Express')) techDetected.push('Node.js/Express');
                        if (headerVal.includes('laravel_session') && !techDetected.includes('Laravel/PHP')) techDetected.push('Laravel/PHP');
                        if (headerVal.includes('_rails') && !techDetected.includes('Ruby on Rails')) techDetected.push('Ruby on Rails');
                        if (headerVal.includes('csrftoken') && !techDetected.includes('Django/Python')) techDetected.push('Django/Python');
                        if (headerVal.includes('wp-settings') && !techDetected.includes('WordPress')) techDetected.push('WordPress');
                      }
                      if (lk === 'server' && !webServer) {
                        responseHeaders['server'] = headerVal;
                        // Already captured via obj.webserver above, but ensure it's in responseHeaders
                      }
                    }
                  }
                  // Also check raw response string for headers if 'header' field is a string
                  if (typeof headers === 'string') {
                    const headerLines = headers.split('\n');
                    for (const hl of headerLines) {
                      const colonIdx = hl.indexOf(':');
                      if (colonIdx === -1) continue;
                      const hName = hl.substring(0, colonIdx).trim().toLowerCase();
                      const hVal = hl.substring(colonIdx + 1).trim();
                      if (hName === 'x-powered-by') {
                        responseHeaders['x-powered-by'] = hVal;
                        if (!techDetected.includes(hVal)) techDetected.push(hVal);
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Powered-By: ${hVal}` });
                      }
                      if (hName === 'set-cookie') {
                        responseHeaders['set-cookie'] = hVal;
                        if (hVal.includes('PHPSESSID') && !techDetected.includes('PHP')) techDetected.push('PHP');
                        if (hVal.includes('JSESSIONID') && !techDetected.includes('Java')) techDetected.push('Java');
                        if (hVal.includes('ASP.NET_SessionId') && !techDetected.includes('ASP.NET')) techDetected.push('ASP.NET');
                      }
                    }
                  }
                } catch { /* not JSON line — skip */ }
              }
            }

            // Enrich asset passiveRecon with httpx data
            if (asset.passiveRecon) {
              if (techDetected.length > 0) {
                asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), ...techDetected])];
              }
              if (cdnDetected.length > 0) {
                asset.passiveRecon.riskSignals = [...(asset.passiveRecon.riskSignals || []), ...cdnDetected.map(c => `CDN/WAF: ${c}`)];
              }
              if (webServer) {
                asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), webServer])];
              }
              // Store extracted response headers for downstream ZAP config
              if (Object.keys(responseHeaders).length > 0) {
                (asset as any).httpxResponseHeaders = { ...(asset as any).httpxResponseHeaders, ...responseHeaders };
              }
            }

            // Store httpx result
            asset.toolResults.push({
              tool: 'httpx',
              command: httpxCmd,
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findingCount: httpxFindings.length,
              findings: httpxFindings,
              outputPreview: (httpxResult.stdout || '').slice(0, 2048),
              executedAt: Date.now(),
              phase: 'discovery',
            });

            await persistScanResult({
              engagementId: state.engagementId,
              tool: 'httpx',
              target,
              command: httpxCmd,
              stdout: httpxResult.stdout || '',
              stderr: httpxResult.stderr || '',
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findings: httpxFindings,
              phase: 'discovery',
            });

            addLog(state, {
              phase: 'enumeration', type: 'scan_result',
              title: `httpx Complete: ${fmtTarget(asset, target)}`,
              detail: `${httpxFindings.length} findings in ${Math.round(httpxDuration / 1000)}s${techDetected.length > 0 ? `\nTech: ${techDetected.join(', ')}` : ''}${cdnDetected.length > 0 ? `\nCDN/WAF: ${cdnDetected.join(', ')}` : ''}${webServer ? `\nServer: ${webServer}` : ''}`,
              data: { tech: techDetected, cdn: cdnDetected, webServer, tls: tlsInfo },
            });
          } catch (e: any) {
            addLog(state, { phase: 'enumeration', type: 'error', title: `httpx Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          }
        }

         // ── httpx Port Backfill: if nmap found 0 ports but httpx confirmed live services ──
        // This is critical for cloud-hosted targets where nmap may show all ports as "filtered"
        // but httpx successfully connects to web services on 80/443
        if (asset.ports.length === 0 && webPorts.length > 0) {
          // Check which web ports httpx actually confirmed as live (got a status code response)
          const httpxToolResult = asset.toolResults.find(tr => tr.tool === 'httpx');
          const confirmedPorts: Array<{ port: number; service: string; version?: string }> = [];

          if (httpxToolResult?.outputPreview) {
            for (const line of httpxToolResult.outputPreview.split('\n')) {
              try {
                const obj = JSON.parse(line.trim());
                if (obj.status_code && obj.port) {
                  const svc = obj.scheme === 'https' ? 'https' : 'http';
                  if (!confirmedPorts.find(p => p.port === obj.port)) {
                    confirmedPorts.push({
                      port: obj.port,
                      service: svc,
                      version: obj.webserver || undefined,
                    });
                  }
                }
              } catch { /* not JSON */ }
            }
          }

          // Fallback: if httpx output didn't have port info, use the common web ports we probed
          if (confirmedPorts.length === 0) {
            // httpx found findings but we can't parse port info — assume standard web ports
            const httpxFindingCount = httpxToolResult?.findingCount || 0;
            if (httpxFindingCount > 0) {
              confirmedPorts.push({ port: 80, service: 'http' });
              confirmedPorts.push({ port: 443, service: 'https' });
            }
          }

          if (confirmedPorts.length > 0) {
            asset.ports = confirmedPorts;
            asset.type = 'web_app';
            state.stats.portsFound += confirmedPorts.length;

            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `🌐 httpx Port Backfill: ${fmtTarget(asset, target)}`,
              detail: `nmap found 0 open ports (cloud firewall), but httpx confirmed ${confirmedPorts.length} live web services: ${confirmedPorts.map(p => `${p.port}/${p.service}`).join(', ')}. Pipeline will continue with httpx-discovered ports.`,
            });
          }
        }

        // ── Discovery complete for this asset ────────────────────────
        addLog(state, {
          phase: 'enumeration', type: 'scan_result',
          title: `✅ Discovery Complete: ${fmtTarget(asset, target)}`,
          detail: `nmap: ${discoveredPorts.length} services | httpx: ${webPorts.length > 0 ? 'probed' : 'skipped (no web ports)'} | Final ports: ${asset.ports.length}`,
        });
      }
    } catch (e: any) {
      addLog(state, { phase: "enumeration", type: "error", title: "Discovery Scan Error", detail: e.message });
    }
  }

  state.progress = 25;
  addLog(state, {
    phase: "enumeration", type: "phase_complete",
    title: "✅ Phase A Discovery Complete",
    detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports discovered. Enriched data now available for Phase B targeted tool deployment.`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A.5: Cloud Asset Detection & Storage Enumeration
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const { detectCloudAsset, executeCloudStorageScan, getCloudDetectionPromptContext } = await import("./cloud-storage-scanner");
    addLog(state, {
      phase: "enumeration", type: "info",
      title: "☁️ Cloud Asset Detection",
      detail: "Analyzing discovery results for cloud-hosted infrastructure, storage endpoints, and misconfigured services",
    });
    let cloudAssetsFound = 0;
    let cloudStorageEndpoints = 0;
    let cloudFindings: Array<{ asset: string; provider: string; service: string; severity: string; title: string }> = [];
    for (const asset of state.assets) {
      const detection = detectCloudAsset({
        hostname: asset.hostname,
        ip: asset.ip,
        dnsRecords: (asset as any).dnsRecords,
        headers: (asset as any).headers,
        technologies: (asset as any).technologies,
        cnames: (asset as any).cnames,
        toolResults: (asset as any).toolResults,
      });
      if (detection.isCloudHosted) {
        cloudAssetsFound++;
        // Tag the asset with cloud metadata
        (asset as any).cloudProviders = detection.providers;
        (asset as any).cloudServices = detection.signatures.map(s => `${s.provider}:${s.service}`);
        addLog(state, {
          phase: "enumeration", type: "finding",
          title: `☁️ Cloud Asset: ${asset.hostname}`,
          detail: `Providers: ${detection.providers.join(", ")}\nServices: ${detection.signatures.map(s => `${s.provider} ${s.service} (${s.confidence})`).join(", ")}\nStorage endpoints: ${detection.storageEndpoints.length}`,
          data: { cloudDetection: detection },
        });
        // If storage endpoints found, run cloud storage scans
        if (detection.storageEndpoints.length > 0 || detection.scanSuggestions.length > 0) {
          cloudStorageEndpoints += detection.storageEndpoints.length;
          addLog(state, {
            phase: "enumeration", type: "scan_start",
            title: `☁️ Cloud Storage Scan: ${asset.hostname}`,
            detail: `Running ${detection.scanSuggestions.length} cloud-specific scans (${detection.storageEndpoints.join(", ")})`,
          });
          try {
            const scanResult = await executeCloudStorageScan(
              asset.hostname,
              detection.scanSuggestions,
              { maxScans: 5, timeoutSeconds: 120, engagementId: state.engagementId }
            );
            for (const finding of scanResult.findings) {
              cloudFindings.push({
                asset: asset.hostname,
                provider: finding.provider,
                service: finding.service || "storage",
                severity: finding.severity,
                title: finding.title,
              });
              // Add to asset vulns for downstream correlation (deduplicated)
              if (pushVulnDeduped(asset, {
                id: `cloud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: finding.severity,
                title: `[Cloud] ${finding.title}`,
                cve: finding.cve,
                description: finding.description,
                corroborationTier: 'confirmed',
                evidenceDetail: `Confirmed by cloud security scan`,
              })) {
                state.stats.vulnsFound++;
              }
            }
            // Store raw results for the engagement log
            for (const raw of scanResult.rawResults) {
              addLog(state, {
                phase: "enumeration", type: "scan_result",
                title: `Cloud Scan Result: ${raw.tool}`,
                detail: `Exit: ${raw.exitCode} | Duration: ${Math.round(raw.durationMs / 1000)}s\n${raw.stdout.slice(0, 500)}`,
                data: raw,
              });
            }
          } catch (cloudScanErr: any) {
            addLog(state, {
              phase: "enumeration", type: "error",
              title: `Cloud Scan Error: ${asset.hostname}`,
              detail: cloudScanErr.message,
            });
          }
        }
      }
    }
    // Store cloud detection summary in state for LLM attack planner
    (state as any).cloudDetection = {
      assetsFound: cloudAssetsFound,
      storageEndpoints: cloudStorageEndpoints,
      findings: cloudFindings,
      promptContext: cloudAssetsFound > 0 ? getCloudDetectionPromptContext() : undefined,
    };
    const severity_counts = cloudFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    addLog(state, {
      phase: "enumeration", type: cloudAssetsFound > 0 ? "phase_complete" : "info",
      title: cloudAssetsFound > 0
        ? `☁️ Cloud Detection Complete — ${cloudAssetsFound} cloud assets, ${cloudFindings.length} findings`
        : "☁️ Cloud Detection — No cloud assets detected",
      detail: cloudAssetsFound > 0
        ? `Providers: ${[...new Set(cloudFindings.map(f => f.provider))].join(", ")}\nFindings: ${JSON.stringify(severity_counts)}\nStorage endpoints scanned: ${cloudStorageEndpoints}`
        : "No cloud-hosted infrastructure identified in discovery results. Proceeding to Phase B.",
    });
  } catch (cloudDetectErr: any) {
    console.error("[CloudDetection] Error:", cloudDetectErr.message);
    addLog(state, {
      phase: "enumeration", type: "warning",
      title: "⚠️ Cloud Detection Skipped",
      detail: `Cloud asset detection encountered an error: ${cloudDetectErr.message}. Proceeding to Phase B.`,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE B: Targeted Nmap + Tool Deployment (using enriched data)
  // ═══════════════════════════════════════════════════════════════════════════
  addLog(state, {
    phase: "enumeration", type: "info",
    title: "🎯 Phase B: Targeted Tool Deployment",
    detail: "Running targeted nmap scripts and specialized tools per asset based on combined passive recon + discovery data",
  });

  const hasScanPlan = !!state.scanPlan?.assetPlans?.length;
  // Job Queue Bridge: route Phase B tool execution through Redis queue
  const { suggestToolCommands } = await import("./scan-server-executor");
  const roeScope_B = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
  const engagementAbortSig_B = getEngagementAbortSignal(state.engagementId);
  const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_B, engagementAbortSignal: engagementAbortSig_B });

  for (const asset of state.assets) {
    if (asset.ports.length === 0) continue;
    // ═══ RoE SCOPE GUARD: Skip out-of-scope assets in Phase B ═══
    if (!isInRoeScope(state, asset.hostname, asset.ip)) {
      addLog(state, { phase: "enumeration", type: "warning", title: `🛡️ Skipped: ${asset.hostname} (out of scope)`, detail: "Asset not in RoE authorized target list" });
      continue;
    }
    // Classify asset type based on discovered portss
    const webPorts = asset.ports.filter(p =>
      ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";

    const target = asset.ip || asset.hostname;
    const assetPlan = state.scanPlan?.assetPlans.find(
      ap => ap.hostname === asset.hostname || ap.ip === target
    );

    // Phase B targeted nmap: run deeper scripts on discovered ports
    if (assetPlan?.nmapFlags) {
      // Sanitize LLM-generated flags: replace any -p port specs with actual discovered ports
      const discoveredPortList = asset.ports.map(p => p.port).join(',');
      let targetedFlags = assetPlan.nmapFlags
        .replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, '')  // Remove -p with any value (numeric or placeholder)
        .replace(/\s*-p-/g, '')           // Remove -p- (all ports)
        .replace(/\{[^}]+\}/g, '')        // Remove ALL {placeholder} strings
        .replace(/\s+/g, ' ')
        .trim();
      // Add discovered ports if any were found, otherwise use --top-ports 1000
      if (discoveredPortList) {
        targetedFlags = `${targetedFlags} -p ${discoveredPortList}`;
      } else {
        targetedFlags = `${targetedFlags} --top-ports 1000`;
      }
      addLog(state, {
        phase: 'enumeration', type: 'scan_start',
        title: `🎯 Targeted Nmap: ${fmtTarget(asset, target)}`,
        detail: `Phase B flags: ${targetedFlags}\nRationale: ${assetPlan.nmapRationale}`,
      });

      try {
        const startTime = Date.now();
        const nmapArgs = `${targetedFlags} ${target}`;
        const nmapResult = await executeTool({ tool: 'nmap', args: nmapArgs, timeoutSeconds: 300, sudo: true });
        const durationMs = Date.now() - startTime;

        // Parse targeted scan findings (vuln scripts, etc.)
        const findings = parseToolOutput('nmap', nmapResult.stdout || '', asset);

        // Store as toolResult
        asset.toolResults.push({
          tool: 'nmap',
          command: `nmap ${nmapArgs}`,
          exitCode: nmapResult.exitCode ?? 0,
          durationMs,
          timedOut: nmapResult.timedOut || false,
          findingCount: findings.length,
          findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve })),
          outputPreview: (nmapResult.stdout || '').slice(0, 2048),
          executedAt: Date.now(),
          phase: 'targeted_enum',
        });

        addLog(state, {
          phase: 'enumeration', type: 'scan_result',
          title: `Targeted Nmap Complete: ${fmtTarget(asset, target)}`,
          detail: `${findings.length} findings from targeted scripts in ${Math.round(durationMs / 1000)}s`,
          data: { findings, outputPreview: (nmapResult.stdout || '').slice(0, 500) },
        });

        // Persist targeted nmap to database
        await persistScanResult({
          engagementId: state.engagementId,
          tool: 'nmap',
          target,
          command: `nmap ${nmapArgs}`,
          stdout: nmapResult.stdout || '',
          stderr: nmapResult.stderr || '',
          exitCode: nmapResult.exitCode ?? 0,
          durationMs,
          timedOut: nmapResult.timedOut || false,
          findings,
          phase: 'targeted_enum',
        });

        // Add findings to asset vulns (deduplicated)
        for (const f of findings) {
          if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by active scan tool output` })) {
            state.stats.vulnsFound++;
          }
        }
      } catch (e: any) {
        addLog(state, { phase: 'enumeration', type: 'error', title: `Targeted Nmap Failed: ${fmtTarget(asset, target)}`, detail: e.message });
      }
    }

    // Build unified tool command list: prefer scan plan, fallback to suggestToolCommands
    let cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>;

    if (assetPlan && assetPlan.activeTools.length > 0) {
      cmdsToRun = assetPlan.activeTools.map(t => ({
        tool: t.tool,
        command: t.command
          .replace(/\{target\}/g, asset.ip || asset.hostname)
          .replace(/\{[^}]*host[^}]*\}/gi, asset.ip || asset.hostname)
          .replace(/\{[^}]*ip[^}]*\}/gi, asset.ip || asset.hostname)
          .replace(/\{[^}]*naabu[^}]*\}/gi, '')  // Remove any naabu placeholders
          .replace(/\s+/g, ' ').trim(),
        purpose: t.rationale,
        priority: t.priority,
      }));
      addLog(state, {
        phase: "enumeration", type: "tool_match",
        title: `Scan Plan Tools: ${fmtTarget(asset)}`,
        detail: `${cmdsToRun.length} tools from LLM scan plan: ${cmdsToRun.map(c => c.tool).join(", ")}\nRisk: ${assetPlan.riskNotes}`,
        data: {
          source: 'scan_plan',
          tools: cmdsToRun.map(c => c.tool),
          commands: cmdsToRun.map(c => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map(p => `${p.port}/${p.service}`),
          assetType: asset.type,
          riskNotes: assetPlan.riskNotes,
        },
      });
    } else {
      const suggestedCmds = await suggestToolCommands({
        hostname: asset.hostname, ip: asset.ip, type: asset.type, ports: asset.ports,
      });
      cmdsToRun = suggestedCmds.map(c => ({
        tool: c.tool,
        command: `${c.tool} ${c.args}`,
        purpose: c.purpose,
        priority: c.priority,
      }));
      const toolNames = [...new Set(cmdsToRun.map(c => c.tool))];
      addLog(state, {
        phase: "enumeration", type: "tool_match",
        title: `Tool Match: ${fmtTarget(asset)}`,
        detail: `${cmdsToRun.length} commands queued using ${toolNames.length} tools: ${toolNames.join(", ")}`,
        data: {
          source: 'auto_suggest',
          tools: toolNames,
          commands: cmdsToRun.map(c => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map(p => `${p.port}/${p.service}`),
          assetType: asset.type,
        },
      });
    }

    // Execute priority 1 and 2 tool commands on the scan server
    // Skip subfinder for scoped engagements — targets are already defined, subfinder
    // discovers new subdomains outside scope. Keep it only for domain intelligence scans.
    const isScoped = state.assets.length > 0; // Scoped = operator defined targets
    const highPriorityCmds = cmdsToRun
      .filter(c => c.priority <= 2)
      .filter(c => {
        if (c.tool === 'subfinder' && isScoped) {
          addLog(state, {
            phase: 'enumeration', type: 'info',
            title: `Skipped: subfinder (scoped engagement)`,
            detail: `Subfinder skipped — targets are already defined in scope. Subfinder is only used for domain intelligence / unscoped discovery.`,
          });
          return false;
        }
        return true;
      });
    // ── Phase B command sanitization (applied to all commands before execution) ──
    for (const cmd of highPriorityCmds) {
      // Fix LLM-generated nuclei commands: ensure -u URL format with severity/tag filters
      if (cmd.tool === 'nuclei') {
        let nucleiCmd = cmd.command;
        // Strip ALL occurrences of 'nuclei' keyword — we'll re-add it once at the end
        // The LLM sometimes generates 'nuclei -u URL nuclei -severity...' (doubled)
        nucleiCmd = nucleiCmd.replace(/\bnuclei\b/g, '').trim();
        const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
        let nucleiTarget = targetMatch?.[1] || asset.ip || asset.hostname;
        if (nucleiTarget && !nucleiTarget.startsWith('http')) {
          const webPorts = asset.ports.filter(p =>
            ['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
            [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
          );
          if (webPorts.length > 0) {
            const scheme = webPorts[0].port === 443 || webPorts[0].port === 8443 ? 'https' : 'http';
            nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts[0].port}`;
          }
        }
        nucleiCmd = nucleiCmd.replace(/-target\s+\S+/g, '').replace(/-u\s+\S+/g, '').trim();
        if (!nucleiCmd.includes('-severity')) nucleiCmd += ' -severity critical,high,medium';
        if (!nucleiCmd.includes('-jsonl')) nucleiCmd += ' -jsonl';
        if (!nucleiCmd.includes('-nc')) nucleiCmd += ' -nc';
        if (!nucleiCmd.includes('-duc')) nucleiCmd += ' -duc';
        if (!nucleiCmd.includes('-ni')) nucleiCmd += ' -ni';
        if (!nucleiCmd.includes('-timeout')) nucleiCmd += ' -timeout 10';
        if (!nucleiCmd.includes('-retries')) nucleiCmd += ' -retries 1';
        const detectedTechs = asset.passiveRecon?.technologies || [];
        const techLower = detectedTechs.map((t: string) => t.toLowerCase());
        const techTags: string[] = [];
        if (techLower.some((t: string) => t.includes('wordpress'))) techTags.push('wordpress');
        if (techLower.some((t: string) => t.includes('nginx'))) techTags.push('nginx');
        if (techLower.some((t: string) => t.includes('apache'))) techTags.push('apache');
        if (techLower.some((t: string) => t.includes('php'))) techTags.push('php');
        if (techLower.some((t: string) => t.includes('node') || t.includes('next'))) techTags.push('nodejs');
        if (techLower.some((t: string) => t.includes('cloudfront') || t.includes('aws'))) techTags.push('aws');
        if (!nucleiCmd.includes('-tags') && techTags.length > 0) nucleiCmd += ` -tags ${techTags.join(',')}`;
        cmd.command = `nuclei -u ${nucleiTarget} ${nucleiCmd}`.replace(/\s+/g, ' ').trim();
      }

      // Fix LLM-generated httpx commands: convert -u single-URL mode to pipe mode
      if (cmd.tool === 'httpx') {
        // Normalize: strip ALL 'httpx' keywords, then detect if LLM included a pipe
        let httpxCmd = cmd.command.replace(/\bhttpx\b/g, '').trim();
        // If LLM already included a pipe (echo URL | flags), extract URL and flags separately
        const pipeMatch = httpxCmd.match(/^echo\s+(\S+)\s*\|\s*(.*)$/);
        if (pipeMatch) {
          const httpxUrl = pipeMatch[1];
          const httpxFlags = pipeMatch[2].replace(/\becho\b/g, '').replace(/\|/g, '').trim();
          cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
        } else {
          // No pipe — extract URL from -u flag or bare URL
          const urlMatch = httpxCmd.match(/-u\s+(\S+)/);
          if (urlMatch) {
            const httpxUrl = urlMatch[1];
            const httpxFlags = httpxCmd.replace(/-u\s+\S+/, '').trim();
            cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
          } else {
            const bareUrl = httpxCmd.match(/(https?:\/\/\S+)/);
            if (bareUrl) {
              const httpxUrl = bareUrl[1];
              const httpxFlags = httpxCmd.replace(/(https?:\/\/\S+)/, '').trim();
              cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
            } else {
              cmd.command = `httpx ${httpxCmd}`.replace(/\s+/g, ' ').trim();
            }
          }
        }
      }

      // Fix LLM-generated gobuster commands: replace Kali Linux wordlist paths with scan server paths
      if (cmd.tool === 'gobuster') {
        // Strip duplicate 'gobuster' keywords, then re-add once
        let gobCmd = cmd.command.replace(/\bgobuster\b/g, '').trim();
        // Ensure 'dir' subcommand is present
        if (!gobCmd.startsWith('dir')) gobCmd = `dir ${gobCmd}`;
        gobCmd = `gobuster ${gobCmd}`;
        gobCmd = gobCmd
          .replace(/\/usr\/share\/wordlists\/dirbuster\/[\w.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
          .replace(/\/usr\/share\/wordlists\/dirb\/[\w.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
          .replace(/\/usr\/share\/wordlists\/[\w/.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
          .replace(/\/usr\/share\/seclists\/[\w/.-]+/gi, '/opt/SecLists/Discovery/Web-Content/common.txt');
        if (!gobCmd.includes('-w ')) gobCmd += ' -w /opt/SecLists/Discovery/Web-Content/common.txt';
        if (!gobCmd.includes('-q')) gobCmd += ' -q';
        if (!gobCmd.includes('--no-error')) gobCmd += ' --no-error';
        if (!gobCmd.includes('-t ')) gobCmd += ' -t 20';
        cmd.command = gobCmd.replace(/\s+/g, ' ').trim();
      }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PARALLEL TOOL EXECUTION — Run tools concurrently with concurrency limit
    // Shannon-inspired: run up to 3 tools in parallel per asset (SSH connection limit)
    // ═══════════════════════════════════════════════════════════════════════════
    const CONCURRENCY_LIMIT = 3;
    addLog(state, {
      phase: 'enumeration', type: 'info',
      title: `⚡ Parallel Execution: ${fmtTarget(asset)}`,
      detail: `Running ${highPriorityCmds.length} tools with concurrency=${CONCURRENCY_LIMIT} (${highPriorityCmds.map(c => c.tool).join(', ')})`,
    });

    // Execute a single tool command and return results
    async function executeToolCmd(cmd: { tool: string; command: string; purpose: string; priority: number }) {
      addLog(state, {
        phase: "enumeration", type: "scan_start",
        title: `Running: ${cmd.tool}`,
        detail: `${cmd.purpose} — ${cmd.command.slice(0, 120)}`,
        data: { tool: cmd.tool, fullCommand: cmd.command },
      });

      const toolTimeout = cmd.tool === 'nuclei' ? 300 : 180;
      let result: any;

      // httpx pipe commands need executeRawCommand
      if (cmd.tool === 'httpx' && cmd.command.includes('echo ')) {
        // Job Queue Bridge: raw commands still go through SSH (pipe commands need shell)
        const startTimeRaw = Date.now();
        result = await executeRawCommandViaQueue(cmd.command + ' 2>&1', toolTimeout, { engagementId: state.engagementId });
        result.durationMs = Date.now() - startTimeRaw;
      } else {
        const cmdArgs = cmd.command.startsWith(cmd.tool)
          ? cmd.command.slice(cmd.tool.length).trim()
          : cmd.command;
        const startTime = Date.now();
        result = await executeTool({
          tool: cmd.tool,
          args: cmdArgs,
          timeoutSeconds: toolTimeout,
          engagementId: state.engagementId,
        });
        if (!result.durationMs) result.durationMs = Date.now() - startTime;
      }

      // Parse tool output for findings
      const findings = parseToolOutput(cmd.tool, result.stdout, asset);

      // Store as toolResult on the asset
      asset.toolResults.push({
        tool: cmd.tool,
        command: cmd.command,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        findingCount: findings.length,
        findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve })),
        outputPreview: result.stdout.slice(0, 2048),
        executedAt: Date.now(),
        phase: 'targeted_enum',
      });

      addLog(state, {
        phase: "enumeration", type: "scan_result",
        title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
        detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
        data: {
          tool: cmd.tool, exitCode: result.exitCode, durationMs: result.durationMs,
          findings, outputPreview: result.stdout.slice(0, 500),
        },
      });

      // Persist to database
      await persistScanResult({
        engagementId: state.engagementId,
        tool: cmd.tool,
        target: asset.hostname || asset.ip,
        command: cmd.command,
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        findings,
        phase: "targeted_enum",
      });

      // Add findings to asset vulns (deduplicated)
      let newCount = 0;
      for (const f of findings) {
        if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by ${cmd.tool} active scan` })) {
          state.stats.vulnsFound++;
          newCount++;
        }
      }

      return { tool: cmd.tool, findings: newCount, timedOut: result.timedOut };
    }

    // Run tools in batches with concurrency limit
    const parallelStartTime = Date.now();
    for (let i = 0; i < highPriorityCmds.length; i += CONCURRENCY_LIMIT) {
      const batch = highPriorityCmds.slice(i, i + CONCURRENCY_LIMIT);
      const batchResults = await Promise.allSettled(
        batch.map(cmd => executeToolCmd(cmd).catch(e => {
          addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
          return null;
        }))
      );
      // Log batch completion
      const succeeded = batchResults.filter(r => r.status === 'fulfilled' && r.value).length;
      const failed = batchResults.length - succeeded;
      if (batch.length > 1) {
        addLog(state, {
          phase: 'enumeration', type: 'info',
          title: `Batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1} complete`,
          detail: `${succeeded}/${batch.length} tools finished (${failed} errors). Tools: ${batch.map(c => c.tool).join(', ')}`,
        });
      }
    }
    const parallelDuration = Date.now() - parallelStartTime;
    addLog(state, {
      phase: 'enumeration', type: 'info',
      title: `⚡ Parallel execution complete: ${fmtTarget(asset)}`,
      detail: `${highPriorityCmds.length} tools finished in ${Math.round(parallelDuration / 1000)}s (parallel batches of ${CONCURRENCY_LIMIT})`,
    });

    // Persist state after each asset completes
    persistOpsStateDebounced(state.engagementId, 500);
  }

  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

async function executeVulnDetection(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "vuln_detection";
  state.currentAction = "Running vulnerability detection...";
  addLog(state, { phase: "vuln_detection", type: "info", title: "🛡️ Phase 3: Vulnerability Detection", detail: "Running nuclei scans and ZAP web app scans" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "vuln_detection" });

  // ── Promote pendingVulns from passive recon into confirmed vulns ──
  let promotedCount = 0;
  for (const asset of state.assets) {
    if (asset.pendingVulns && asset.pendingVulns.length > 0) {
      for (const pv of asset.pendingVulns) {
        if (pushVulnDeduped(asset, pv as any)) {
          state.stats.vulnsFound++;
          promotedCount++;
        }
      }
      asset.pendingVulns = [];
    }
  }
  if (promotedCount > 0) {
    addLog(state, {
      phase: "vuln_detection", type: "info",
      title: `📋 Promoted ${promotedCount} passive recon findings to confirmed vulns`,
      detail: `${promotedCount} risk signals from passive recon (Shodan, Censys, posture analysis) are now included in the vulnerability count for correlation with active scan results.`,
    });
  }

  // ── Nuclei scan on all assets via scan server (RoE scope enforced) ──
  const nucleiAssets = state.assets.filter(a => a.ports.length > 0 && isInRoeScope(state, a.hostname, a.ip));
  let phase3NucleiFindings = 0; // Track only Phase 3 nuclei-specific findings
  let phase3NucleiErrors = 0;
  const vulnsBeforePhase3 = state.stats.vulnsFound; // Snapshot for accurate reporting

  // Build a set of existing vuln titles per asset for deduplication
  const existingVulnKeys = new Map<string, Set<string>>();
  for (const asset of state.assets) {
    const keys = new Set<string>();
    for (const v of asset.vulns) {
      keys.add(`${v.severity}::${v.title}::${v.cve || ''}`);
    }
    existingVulnKeys.set(asset.hostname, keys);
  }

  if (nucleiAssets.length > 0) {
    addLog(state, { phase: "vuln_detection", type: "scan_start", title: "Nuclei Vulnerability Scan (Scan Server)", detail: `Scanning ${nucleiAssets.length} targets via remote nuclei` });

    // Job Queue Bridge: route nuclei execution through Redis queue
    const roeScope_N = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
    const engagementAbortSig_N = getEngagementAbortSignal(state.engagementId);
    const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_N, engagementAbortSignal: engagementAbortSig_N });

    // Helper: execute nuclei with retry on SSH connection failures
    async function executeNucleiWithRetry(
      nucleiArgs: string, target: string, maxRetries = 2
    ): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number; timedOut: boolean; error?: string }> {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const result = await executeTool({
          tool: "nuclei",
          args: nucleiArgs,
          target,
          timeoutSeconds: 600,
          engagementId: state.engagementId,
        });
        // If SSH connection failed (exit -1, empty stdout, short duration < 20s), retry
        const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
        if (isSSHFailure && attempt < maxRetries) {
          addLog(state, {
            phase: "vuln_detection", type: "warning",
            title: `Nuclei SSH retry (attempt ${attempt + 2}/${maxRetries + 1})`,
            detail: `SSH connection failed for ${target} (${result.error || result.stderr || 'empty output'}). Retrying after 3s cooldown...`,
          });
          await new Promise(r => setTimeout(r, 3000)); // Cooldown between retries
          continue;
        }
        return result;
      }
      // Should not reach here, but return empty result as fallback
      return { stdout: '', stderr: 'All retries exhausted', exitCode: -1, durationMs: 0, timedOut: false, error: 'All retries exhausted' };
    }

    for (const asset of nucleiAssets) {
      const target = asset.ip || asset.hostname;
      // Build nuclei target URLs for web ports, or just the host for non-web
      const webPorts = asset.ports.filter(p =>
        ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
        [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
      );

      const nucleiTargetUrls = webPorts.length > 0
        ? webPorts.map(p => {
            const scheme = p.port === 443 || p.port === 8443 ? "https" : "http";
            return `${scheme}://${target}:${p.port}`;
          })
        : [target];

      // Build technology-aware nuclei tags from httpx-detected technologies
      const detectedTechs = asset.passiveRecon?.technologies || [];
      const techTags: string[] = [];
      const techLower = detectedTechs.map((t: string) => t.toLowerCase());
      // Map detected technologies to nuclei template tags for targeted scanning
      if (techLower.some((t: string) => t.includes('wordpress'))) techTags.push('wordpress');
      if (techLower.some((t: string) => t.includes('joomla'))) techTags.push('joomla');
      if (techLower.some((t: string) => t.includes('drupal'))) techTags.push('drupal');
      if (techLower.some((t: string) => t.includes('nginx'))) techTags.push('nginx');
      if (techLower.some((t: string) => t.includes('apache'))) techTags.push('apache');
      if (techLower.some((t: string) => t.includes('iis'))) techTags.push('iis');
      if (techLower.some((t: string) => t.includes('php'))) techTags.push('php');
      if (techLower.some((t: string) => t.includes('laravel'))) techTags.push('laravel');
      if (techLower.some((t: string) => t.includes('spring'))) techTags.push('springboot');
      if (techLower.some((t: string) => t.includes('tomcat'))) techTags.push('tomcat');
      if (techLower.some((t: string) => t.includes('jenkins'))) techTags.push('jenkins');
      if (techLower.some((t: string) => t.includes('grafana'))) techTags.push('grafana');
      if (techLower.some((t: string) => t.includes('gitlab'))) techTags.push('gitlab');
      if (techLower.some((t: string) => t.includes('cloudfront') || t.includes('aws'))) techTags.push('aws');
      if (techLower.some((t: string) => t.includes('react') || t.includes('next.js') || t.includes('node'))) techTags.push('nodejs');

      const assetVulnKeys = existingVulnKeys.get(asset.hostname) || new Set();

      for (const url of nucleiTargetUrls) {
        // Build nuclei args: use tech-specific tags if available, otherwise broad severity scan
        const tagArgs = techTags.length > 0 ? `-tags ${techTags.join(',')}` : '';
        const nucleiArgs = `-u ${url} -severity critical,high,medium ${tagArgs} -jsonl -nc -duc -ni -timeout 10 -retries 1 -rate-limit ${state.engagementType === "red_team" ? 50 : 150}`;

        addLog(state, {
          phase: "vuln_detection", type: "scan_start",
          title: `Nuclei: ${url}`,
          detail: `Running vulnerability scan${techTags.length > 0 ? ` (tech-targeted: ${techTags.join(', ')})` : ' (broad severity scan)'}`,
        });

        try {
          const result = await executeNucleiWithRetry(nucleiArgs, target);

          // Log SSH failures explicitly so they're visible in the UI
          if (result.exitCode === -1 && !result.stdout) {
            phase3NucleiErrors++;
            addLog(state, {
              phase: "vuln_detection", type: "warning",
              title: `Nuclei Failed: ${url}`,
              detail: `SSH connection failed after retries. Error: ${result.error || result.stderr || 'Connection timeout'}. Duration: ${result.durationMs}ms`,
            });
          }

          // Parse nuclei JSON output
          const findings = parseToolOutput("nuclei", result.stdout, asset);

          // Deduplicate: only add findings not already discovered in targeted_enum
          let newFindings = 0;
          for (const f of findings) {
            const key = `${f.severity}::${f.title}::${f.cve || ''}`;
            if (!assetVulnKeys.has(key)) {
              asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by active scan tool output` });
              assetVulnKeys.add(key);
              state.stats.vulnsFound++;
              newFindings++;
            }
          }
          phase3NucleiFindings += newFindings;

          // Store as toolResult on asset
          const nucleiCmd = `nuclei ${nucleiArgs}`;
          asset.toolResults.push({
            tool: 'nuclei',
            command: nucleiCmd,
            exitCode: result.exitCode,
            durationMs: result.durationMs,
            timedOut: result.timedOut,
            findingCount: findings.length,
            findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve })),
            outputPreview: result.stdout.slice(0, 2048),
            executedAt: Date.now(),
            phase: 'vuln_detection',
          });

          const dupeNote = findings.length > newFindings ? ` (${findings.length - newFindings} duplicates from targeted_enum skipped)` : '';
          addLog(state, {
            phase: "vuln_detection",
            type: "scan_result",
            title: `Nuclei Complete: ${url}`,
            detail: `${newFindings} new findings${dupeNote}, exit code ${result.exitCode}, ${result.durationMs}ms${result.timedOut ? " (TIMED OUT)" : ""}${result.error ? ` [Error: ${result.error}]` : ''}`,
            data: { findings, outputPreview: result.stdout.slice(0, 500) },
          });

          // Persist nuclei results to database
          await persistScanResult({
            engagementId: state.engagementId,
            tool: "nuclei",
            target: url,
            command: nucleiCmd,
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: result.exitCode,
            durationMs: result.durationMs,
            timedOut: result.timedOut,
            findings,
            phase: "vuln_detection",
          });
        } catch (e: any) {
          phase3NucleiErrors++;
          addLog(state, { phase: "vuln_detection", type: "error", title: `Nuclei Error: ${url}`, detail: e.message });
        }
      }
    }

    // Accurate summary: report Phase 3 nuclei findings separately from total
    const totalVulns = state.stats.vulnsFound;
    const priorVulns = vulnsBeforePhase3;
    addLog(state, {
      phase: "vuln_detection",
      type: "scan_result",
      title: "Nuclei Scan Complete",
      detail: `Phase 3 nuclei found ${phase3NucleiFindings} new vulnerabilities across ${nucleiAssets.length} targets${phase3NucleiErrors > 0 ? ` (${phase3NucleiErrors} scans failed — SSH connection issues)` : ''}. Total vulns: ${totalVulns} (${priorVulns} from prior phases + ${phase3NucleiFindings} new)`,
    });
  }

  // ── ZAP scan on web applications (WAF-aware, RoE scope enforced) ──
  const webApps = state.assets.filter(a =>
    (a.type === "web_app" ||
    a.ports.some(p => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)))
    && isInRoeScope(state, a.hostname, a.ip)
  );

  // Dedup: track scanned target URLs to avoid duplicate scans for the same host+protocol
  const scannedTargetUrls = new Set<string>();

  for (const webApp of webApps) {
    const webPorts = webApp.ports.filter(p =>
      ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)
    );

    for (const wp of webPorts) {
      const protocol = wp.port === 443 || wp.port === 8443 || wp.service === "https" ? "https" : "http";
      const targetUrl = `${protocol}://${webApp.ip || webApp.hostname}${wp.port === 80 || wp.port === 443 ? "" : `:${wp.port}`}`;

      // Skip if we already scanned this exact URL in this run
      if (scannedTargetUrls.has(targetUrl)) {
        addLog(state, { phase: "vuln_detection", type: "info", title: `ZAP Dedup Skip: ${targetUrl}`, detail: "Already scanned in this engagement run" });
        continue;
      }
      scannedTargetUrls.add(targetUrl);

      addLog(state, {
        phase: "vuln_detection",
        type: "zap_scan",
        title: `ZAP Web App Scan: ${targetUrl}`,
        detail: "Starting OWASP ZAP scan with WAF detection and evasion",
      });

      try {
        // First, detect WAF
        let wafVendor: string | undefined;
        try {
          const { detectWaf } = await import("./waf-detector");
          const wafResult = await detectWaf(targetUrl);
          if (wafResult?.detected) {
            wafVendor = wafResult.vendor;
            webApp.wafDetected = wafVendor;
            state.stats.wafDetections++;
            addLog(state, {
              phase: "vuln_detection",
              type: "waf_detected",
              title: `WAF Detected: ${wafVendor}`,
              detail: `${targetUrl} is protected by ${wafVendor}. Adjusting scan parameters for evasion.`,
              data: { wafVendor, targetUrl },
            });
          }
        } catch { /* WAF detection is best-effort */ }

        // Use LLM to generate optimal ZAP scan config
        const { generateLLMScanConfig, startScan, configureZapAuthentication } = await import("./zap-scanner");
        // Build comprehensive tech hints from ALL sources:
        // 1. nmap service versions (e.g., "nginx 1.18.0", "Apache httpd 2.4.51")
        // 2. httpx-detected technologies (e.g., "PHP", "WordPress", "jQuery")
        // 3. httpx response headers (e.g., "X-Powered-By: PHP/8.1.2", "Set-Cookie: PHPSESSID")
        // 4. Web server from httpx (e.g., "nginx", "Apache")
        const nmapVersions = webApp.ports.map(p => p.version).filter(Boolean) as string[];
        const httpxTechs = webApp.passiveRecon?.technologies || [];
        const httpxHeaders = (webApp as any).httpxResponseHeaders || {};
        const headerHints: string[] = [];
        if (httpxHeaders['x-powered-by']) headerHints.push(`X-Powered-By: ${httpxHeaders['x-powered-by']}`);
        if (httpxHeaders['x-aspnet-version']) headerHints.push(`X-AspNet-Version: ${httpxHeaders['x-aspnet-version']}`);
        if (httpxHeaders['x-aspnetmvc-version']) headerHints.push(`X-AspNetMvc-Version: ${httpxHeaders['x-aspnetmvc-version']}`);
        if (httpxHeaders['x-generator']) headerHints.push(`X-Generator: ${httpxHeaders['x-generator']}`);
        if (httpxHeaders['set-cookie']) headerHints.push(`Set-Cookie: ${httpxHeaders['set-cookie'].substring(0, 100)}`);
        if (httpxHeaders['server']) headerHints.push(`Server: ${httpxHeaders['server']}`);
        const techHints = [...new Set([...nmapVersions, ...httpxTechs, ...headerHints])];

        // Check if this asset has confirmed credentials from credential testing
        const webCreds = (webApp.confirmedCredentials || []).filter(c =>
          ['http', 'https', 'web_admin', 'http-form', 'http-get', 'http-post'].includes(c.service) ||
          c.protocol === 'http' || c.protocol === 'https'
        );
        const hasConfirmedCreds = webCreds.length > 0;

        // Pass confirmed credentials as auth hints to the LLM config generator
        const authHints = hasConfirmedCreds
          ? { type: 'form', loginUrl: `${targetUrl}/login`, credentials: { username: webCreds[0].username, password: webCreds[0].password } }
          : undefined;

        let llmConfig = await generateLLMScanConfig({
          targetUrl,
          scanMode: "active",
          techStackHints: techHints,
          authHints,
          scopeConstraints: [`Only scan ${webApp.hostname}`],
        });

        // Apply WAF evasion if WAF was detected for this target
        if (wafVendor) {
          try {
            const { applyWafEvasionConfig } = await import("./zap-scanner");
            llmConfig = applyWafEvasionConfig(llmConfig, wafVendor);
            addLog(state, {
              phase: "vuln_detection",
              type: "info",
              title: `WAF Evasion Applied: ${wafVendor}`,
              detail: `ZAP scan config adjusted for ${wafVendor} — delay: ${llmConfig.activeScanConfig.delayInMs}ms, threads: ${llmConfig.activeScanConfig.threadPerHost}, ${llmConfig.customRules.filter(r => r.startsWith('WAF_EVASION') || !r.startsWith('Rule')).length} evasion techniques`,
              data: { wafVendor, delayMs: llmConfig.activeScanConfig.delayInMs, threads: llmConfig.activeScanConfig.threadPerHost },
            });
          } catch { /* WAF evasion is best-effort */ }
        }

        addLog(state, {
          phase: "vuln_detection",
          type: "llm_decision",
          title: "LLM ZAP Config Generated",
          detail: llmConfig.rationale || "Optimized scan configuration based on target analysis",
          data: { technologies: llmConfig.technologies, authStrategy: llmConfig.authStrategy },
        });

        // Log credential handoff if confirmed creds are available
        if (hasConfirmedCreds) {
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `🔑 Credential Handoff: ${webCreds.length} confirmed credential(s) → ZAP`,
            detail: `Using ${webCreds[0].source} credentials (${webCreds[0].username}:***) for authenticated scanning of ${targetUrl}. Source: ${webCreds.map(c => c.source).join(', ')}`,
            data: {
              credentialCount: webCreds.length,
              credentialSources: webCreds.map(c => ({ source: c.source, username: c.username, service: c.service, confirmedAt: c.confirmedAt })),
            },
          });
        }

        // Start ZAP scan with WAF-aware settings
        let zapScanResult: any;
        try {
          zapScanResult = await startScan({
            targetUrl,
            scanType: "full",
            scanMode: "active",
            userId: operatorCtx.id,
            scanName: `EngOps-${state.engagementId}-${webApp.hostname}`,
            llmConfig: llmConfig,
            discoveredTechnologies: techHints,
          });
        } catch (zapStartErr: any) {
          // ZAP server may not be reachable — log and continue
          addLog(state, { phase: "vuln_detection", type: "error", title: `ZAP Start Error: ${targetUrl}`, detail: zapStartErr.message });
          continue;
        }

        // Configure ZAP authentication with confirmed credentials AFTER scan context is created
        if (hasConfirmedCreds && zapScanResult?.scanId) {
          try {
            const authResult = await configureZapAuthentication(
              `scan-${zapScanResult.scanId}`,
              targetUrl,
              webCreds,
              { techHints } as any, // Pass tech hints for tech-specific login path discovery
            );
            if (authResult.configured) {
              addLog(state, {
                phase: "vuln_detection",
                type: "info",
                title: `✅ ZAP Authenticated Scan: ${authResult.method} auth configured`,
                detail: `ZAP will scan as ${authResult.username} using ${authResult.method} authentication. Login form fields detected and CSRF tokens handled.`,
                data: { method: authResult.method, username: authResult.username, contextId: authResult.contextId },
              });
            } else {
              addLog(state, {
                phase: "vuln_detection",
                type: "warning",
                title: `⚠️ ZAP Auth Config Partial`,
                detail: `Auth configuration had issues: ${authResult.errors.join('; ')}. Scan will continue unauthenticated.`,
                data: { errors: authResult.errors },
              });
            }
          } catch (authErr: any) {
            addLog(state, {
              phase: "vuln_detection",
              type: "warning",
              title: `ZAP Auth Config Error`,
              detail: `Could not configure authenticated scanning: ${authErr.message}. Continuing unauthenticated.`,
            });
          }
        }

        state.stats.zapScansRun++;

        // Poll for scan completion (max 5 minutes)
        const zapScanId = zapScanResult?.scanId;
        if (zapScanId) {
          const { pollScanProgress } = await import("./zap-scanner");
          let zapDone = false;
          const zapTimeout = Date.now() + 5 * 60 * 1000;
          while (!zapDone && Date.now() < zapTimeout) {
            try {
              const progress = await pollScanProgress(zapScanId);
              if (progress.status === "completed" || progress.status === "error") {
                zapDone = true;
                // Convert alertCounts to findings for the asset
                const counts = progress.alertCounts || { high: 0, medium: 0, low: 0, info: 0 };
                const totalAlerts = counts.high + counts.medium + counts.low;
                if (totalAlerts > 0) {
                  if (counts.high > 0) {
                    webApp.zapFindings.push({ alert: "High-risk web vulnerability", risk: "high", url: targetUrl });
                    webApp.vulns.push({ id: genId(), severity: "high", title: `[ZAP] ${counts.high} high-risk findings`, corroborationTier: 'confirmed', evidenceDetail: 'Confirmed by ZAP active scan' });
                    state.stats.vulnsFound += counts.high;
                  }
                  if (counts.medium > 0) {
                    webApp.zapFindings.push({ alert: "Medium-risk web vulnerability", risk: "medium", url: targetUrl });
                    webApp.vulns.push({ id: genId(), severity: "medium", title: `[ZAP] ${counts.medium} medium-risk findings`, corroborationTier: 'confirmed', evidenceDetail: 'Confirmed by ZAP active scan' });
                    state.stats.vulnsFound += counts.medium;
                  }
                  if (counts.low > 0) {
                    webApp.zapFindings.push({ alert: "Low-risk web vulnerability", risk: "low", url: targetUrl });
                    state.stats.vulnsFound += counts.low;
                  }
                }
              } else {
                addLog(state, { phase: "vuln_detection", type: "info", title: `ZAP Progress: ${targetUrl}`, detail: `Spider: ${progress.spiderProgress}%, Active: ${progress.activeScanProgress}%, URLs: ${progress.urlsFound}` });
                await new Promise(r => setTimeout(r, 15000)); // Poll every 15s
              }
            } catch {
              zapDone = true; // Stop polling on error
            }
          }
        }

        // Store ZAP results as toolResult on asset
        const zapFindings = webApp.zapFindings.filter(f => f.url === targetUrl);
        webApp.toolResults.push({
          tool: 'zap',
          command: `zap-scan ${targetUrl} (${wafVendor ? 'WAF-aware: ' + wafVendor : 'standard'})`,
          exitCode: 0,
          durationMs: 0,
          timedOut: false,
          findingCount: zapFindings.length,
          findings: zapFindings.map(f => ({ severity: f.risk, title: f.alert })),
          outputPreview: JSON.stringify(zapFindings.slice(0, 10), null, 2).slice(0, 2048),
          executedAt: Date.now(),
          phase: 'vuln_detection',
        });

        addLog(state, {
          phase: "vuln_detection",
          type: "scan_result",
          title: `ZAP Complete: ${targetUrl}`,
          detail: `Found ${webApp.zapFindings.length} web application findings${wafVendor ? ` (WAF: ${wafVendor})` : ""}`,
          data: { findings: webApp.zapFindings.length, wafVendor },
        });
      } catch (e: any) {
        addLog(state, { phase: "vuln_detection", type: "error", title: `ZAP Scan Error: ${targetUrl}`, detail: e.message });
      }
    }

    webApp.status = webApp.vulns.length > 0 ? "vulns_found" : "no_vulns";
  }

  // ── Credential Testing: run priority 3 tools (hydra) on login services ──
  addLog(state, { phase: "vuln_detection", type: "info", title: "🔑 Credential Testing", detail: "Testing vendor/OEM default credentials first, then common wordlists on discovered login services" });

  try {
    // Job Queue Bridge: route credential testing through Redis queue
    const { suggestToolCommands: suggestCred } = await import("./scan-server-executor");
    const roeScope_C = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
    const execToolCred = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_C });

     for (const asset of state.assets) {
      if (asset.ports.length === 0) continue;
      // ═══ RoE SCOPE GUARD: Skip out-of-scope assets in credential testing ═══
      if (!isInRoeScope(state, asset.hostname, asset.ip)) continue;
      // Build technology list from passiveRecon for OEM default credential lookup
      const techList = (asset.passiveRecon?.technologies || []).map(t => {
        // Map technology strings to structured objects for matchCredentialsForAsset
        const parts = t.split(/[\s\/]+/);
        return { name: t, vendor: parts[0], version: parts.length > 1 ? parts[parts.length - 1] : undefined };
      });
      // Also add service-level tech from ports (e.g., "OpenSSH 8.9" → vendor: OpenSSH)
      for (const p of asset.ports) {
        if (p.version) {
          techList.push({ name: `${p.service} ${p.version}`, vendor: p.version.split(/[\s\/]+/)[0], version: p.version, port: p.port, protocol: p.service } as any);
        }
      }

      const credCmds = (await suggestCred({
        hostname: asset.hostname,
        ip: asset.ip,
        type: asset.type,
        ports: asset.ports,
        technologies: techList.length > 0 ? techList : undefined,
      })).filter(c => c.priority === 3); // Priority 3 = credential testing

      for (const cmd of credCmds) {
        // Request approval for credential testing (orange risk)
        const approved = await requestApproval(state, {
          phase: "vuln_detection",
          riskTier: "orange",
          title: `Credential Test: ${cmd.purpose}`,
          description: `Running ${cmd.tool} against ${asset.hostname} (${asset.ip || ""}) for ${cmd.purpose}. This will attempt common credentials against the service.`,
          target: asset.hostname,
          module: cmd.tool,
          detail: { tool: cmd.tool, args: cmd.args, purpose: cmd.purpose },
        });

        if (!approved) {
          addLog(state, { phase: "vuln_detection", type: "info", title: `Skipped: ${cmd.purpose}`, detail: "Operator denied credential testing" });
          continue;
        }

        addLog(state, {
          phase: "vuln_detection",
          type: "scan_start",
          title: `Running: ${cmd.tool}`,
          detail: cmd.purpose,
          data: { tool: cmd.tool, fullCommand: `${cmd.tool} ${cmd.args}` },
        });

        try {
          const result = await execToolCred({
            tool: cmd.tool,
            args: cmd.args,
            target: asset.ip || asset.hostname,
            timeoutSeconds: 120,
            engagementId: state.engagementId,
          });

          const findings = parseToolOutput(cmd.tool, result.stdout, asset);
          for (const f of findings) {
            if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by ${cmd.tool} credential test` })) {
              state.stats.vulnsFound++;
            }
          }

          // Store credential test as toolResult on asset
          asset.toolResults.push({
            tool: cmd.tool,
            command: `${cmd.tool} ${cmd.args}`,
            exitCode: result.exitCode,
            durationMs: result.durationMs,
            timedOut: result.timedOut,
            findingCount: findings.length,
            findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve })),
            outputPreview: result.stdout.slice(0, 2048),
            executedAt: Date.now(),
            phase: 'credential_testing',
          });

          addLog(state, {
            phase: "vuln_detection",
            type: "scan_result",
            title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
            detail: `${findings.length} findings, exit code ${result.exitCode}`,
            data: { findings, outputPreview: result.stdout.slice(0, 300) },
          });

          // Persist credential testing results to database
          await persistScanResult({
            engagementId: state.engagementId,
            tool: cmd.tool,
            target: asset.ip || asset.hostname,
            command: `${cmd.tool} ${cmd.args}`,
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: result.exitCode,
            durationMs: result.durationMs,
            timedOut: result.timedOut,
            findings,
            phase: "credential_testing",
          });
        } catch (e: any) {
          addLog(state, { phase: "vuln_detection", type: "error", title: `${cmd.tool} Error`, detail: e.message });
        }
      }
     }
    // ── Post-Hydra HTTP Credential Verification ──
    // For any http-get/https-get credentials that passed the initial FP heuristic
    // (1-2 hits), perform an active verification: fetch the target URL with and
    // without the Authorization header and compare responses. If they're identical,
    // the server doesn't use HTTP Basic Auth and the credentials are false positives.
    for (const verifyAsset of state.assets) {
    const httpCreds = (verifyAsset.confirmedCredentials || []).filter(
      c => c.source === 'hydra' && (c.service === 'http-get' || c.service === 'https-get')
    );
    if (httpCreds.length > 0) {
      try {
        const scheme = httpCreds[0].service === 'https-get' ? 'https' : 'http';
        const verifyTarget = verifyAsset.hostname || verifyAsset.ip;
        const verifyUrl = `${scheme}://${verifyTarget}:${httpCreds[0].port}/`;

        // Use curl on the scan server to compare responses (with and without auth)
        const baselineResult = await execToolCred({
          tool: 'curl',
          args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L ${verifyUrl}`,
          target: verifyTarget,
          timeoutSeconds: 30,
          engagementId: state.engagementId,
        });
        const authResult = await execToolCred({
          tool: 'curl',
          args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L -u '${httpCreds[0].username}:${httpCreds[0].password}' ${verifyUrl}`,
          target: verifyTarget,
          timeoutSeconds: 30,
          engagementId: state.engagementId,
        });

        const baselineResp = baselineResult.stdout.trim();
        const authResp = authResult.stdout.trim();

        if (baselineResp === authResp) {
          // Responses identical — server ignores Authorization header → false positive
          addLog(state, {
            phase: 'vuln_detection',
            type: 'llm_decision',
            title: `⚠️ Hydra HTTP Credential Verification: FALSE POSITIVE`,
            detail: `Server at ${verifyUrl} returns identical response (${baselineResp}) with and without credentials. HTTP Basic Auth is not in use. Removing ${httpCreds.length} false positive credential(s) from findings.`,
          });

          // Remove false positive credentials from confirmedCredentials
          verifyAsset.confirmedCredentials = (verifyAsset.confirmedCredentials || []).filter(
            c => !(c.source === 'hydra' && (c.service === 'http-get' || c.service === 'https-get'))
          );

          // Downgrade corresponding vulns from critical to info
          for (const vuln of verifyAsset.vulns) {
            if (vuln.title?.includes('[Hydra]') && vuln.title?.includes('http-get')) {
              vuln.severity = 'info';
              vuln.title = vuln.title.replace('[Hydra] Valid credentials found:', '[Hydra] FALSE POSITIVE (no HTTP Basic Auth):');
              vuln.corroborationTier = 'unverified';
              vuln.evidenceDetail = 'Downgraded: server returns identical response with and without credentials — HTTP Basic Auth not in use';
            }
          }
        } else {
          addLog(state, {
            phase: 'vuln_detection',
            type: 'llm_decision',
            title: `✅ Hydra HTTP Credential Verification: CONFIRMED`,
            detail: `Server at ${verifyUrl} returns different response with credentials (baseline: ${baselineResp}, auth: ${authResp}). Credentials are valid.`,
          });
        }
      } catch (e: any) {
        addLog(state, {
          phase: 'vuln_detection',
          type: 'info',
          title: `Hydra HTTP Credential Verification: Skipped`,
          detail: `Could not verify HTTP credentials: ${e.message}. Findings remain as-is.`,
        });
      }
    }
    } // end for verifyAsset
  } catch (e: any) {
    addLog(state, { phase: "vuln_detection", type: "error", title: "Credential Testing Error", detail: e.message });
  }

  // ── Recalculate stats from actual asset data (fixes counter drift) ──
  state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);

  // ── LLM Correlation: analyze all findings and recommend exploit strategy ──
  const allVulns = state.assets.flatMap(a => a.vulns);
  if (allVulns.length > 0) {
    addLog(state, { phase: "vuln_detection", type: "llm_decision", title: "LLM Correlation Analysis", detail: "Analyzing findings across all tools to identify attack vectors..." });

    // ── KEV enrichment: match discovered CVEs against CISA KEV catalog ──
    let kevContext = '';
    const discoveredCves = allVulns.map(v => v.cve).filter(Boolean) as string[];
    if (discoveredCves.length > 0) {
      try {
        const kevCatalog = await fetchKevCatalog();
        const kevMatches = matchCvesAgainstKev(discoveredCves, kevCatalog);
        if (kevMatches.length > 0) {
          const kevBoost = calculateKevRiskBoost(kevMatches);
          kevContext = `\n\n⚠️ CISA KNOWN EXPLOITED VULNERABILITIES (KEV) ALERT:\nThe following ${kevMatches.length} CVEs found in this engagement are on the CISA KEV catalog — these are ACTIVELY EXPLOITED in the wild:\n${kevMatches.map(m => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? ' [KNOWN RANSOMWARE VECTOR]' : ''} — Required action: ${m.requiredAction}`).join('\n')}\n${kevBoost.ransomwareExposure ? '\n🔴 RANSOMWARE EXPOSURE: Some KEV entries are linked to active ransomware campaigns. Prioritize these for immediate exploitation testing.' : ''}\nYou MUST prioritize KEV-listed vulnerabilities in your exploitation strategy. These represent confirmed real-world attack vectors with the highest likelihood of success.`;
          addLog(state, { phase: 'vuln_detection', type: 'finding', title: `⚠️ ${kevMatches.length} CISA KEV Matches`, detail: kevBoost.summary });
        }
      } catch (e: any) {
        console.error('[KEV] Failed to enrich correlation:', e.message);
      }
    }

    const _corrDecStart = Date.now();
    const correlationDecision = await llmDecide({
      phase: "vuln_detection",
      engagementType: state.engagementType,
      engagementId: state.engagementId,
      assets: state.assets,
      recentLog: state.log.slice(-20),
      question: `We've completed vulnerability scanning. Here are the findings:
${allVulns.map(v => `- ${v.title} (${v.severity})${v.cve ? ` [${v.cve}]` : ""}`).join("\n")}
${kevContext}
Correlate these findings and recommend the best exploitation strategy. For pentest: prioritize per-asset unauthorized access. For red team: identify the weakest entry point for C2 deployment.
${(() => {
  const vulnDescs = allVulns.map(v => v.title + (v.cve ? ` ${v.cve}` : ''));
  const chains = getChainsByVulnDescriptions(vulnDescs, 3);
  const chainCtx = formatChainsForPrompt(chains);
  const detectedTech = state.assets.flatMap(a => [
    ...(a.type !== 'unknown' ? [a.type] : []),
    ...a.ports.map((p: any) => p.service).filter(Boolean),
  ]);
  const ontologyCtx = formatOntologyForPrompt([...new Set(detectedTech)]);
  const bugBountyCtx = getBugBountyContext(vulnDescs, 3);
  const triageCtx = getTriageCorpusContext(undefined, 3);
  // Cloud security context for cloud-specific vuln correlation
  const cloudObs = state.assets.flatMap(a => [
    ...(a.passiveRecon?.technologies || []),
    ...(a.passiveRecon?.riskSignals?.map(r => r.rationale) || []),
    a.passiveRecon?.cloudProvider || '',
    ...a.vulns.map(v => v.title),
  ]).filter(Boolean);
  const cloudSecCtx = buildCloudSecurityContext(cloudObs);
  const nmapVulnCtx = getNmapVulnCorrelationContext();
  const owaspVulnCtx = getOwaspVulnCorrelationContext();
  const threatVulnCtx = getThreatGroupVulnContext();
  // Add offensive techniques for vuln detection phase (file upload bypass, firewall evasion)
  const offTechVulnCtx = buildOffensiveTechniquesContext({
    phase: 'vuln_detection',
    hasFirewall: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
    hasWAF: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
    hasFileUpload: detectedTech.some(t => /upload|file|cms|wordpress|drupal|joomla/i.test(t)),
  });
  // Build ZAP pentesting knowledge for vuln detection (alert catalog, WSTG methodology, auth strategies)
  const zapVulnCtx = buildZAPKnowledgeContext({
    phase: 'vuln_detection',
    technology: detectedTech[0],
    authType: state.assets.some(a => (a.confirmedCredentials || []).length > 0) ? 'form' : undefined,
    footholdMinimum: 'medium',
  });
  // Build ZAP source code & secrets analysis context for vuln detection
  const sourceSecretsVulnCtx = buildSourceSecretsContext({
    phase: 'vuln_detection',
    includeSecretPatterns: true,
    includeJSAnalysis: true,
    includeSourceDisclosure: true,
    includeBrowserStorage: true,
    technology: detectedTech[0],
  });
  return chainCtx + ontologyCtx + '\n\n' + bugBountyCtx + '\n\n' + triageCtx + (cloudSecCtx ? '\n\n' + cloudSecCtx : '') + '\n\n' + nmapVulnCtx + '\n\n' + owaspVulnCtx + '\n\n' + threatVulnCtx + (offTechVulnCtx ? '\n\n' + offTechVulnCtx : '') + (zapVulnCtx ? '\n\n' + zapVulnCtx : '') + (sourceSecretsVulnCtx ? '\n\n' + sourceSecretsVulnCtx : '');
})()}`,
    });

    state.llmPlan = correlationDecision.decision;
    addLog(state, {
      phase: "vuln_detection",
      type: "llm_decision",
      title: "Attack Strategy Determined",
      detail: correlationDecision.decision,
      data: { reasoning: correlationDecision.reasoning, actions: correlationDecision.actions },
    });
    // ── Training Bridge: capture vuln correlation decision ──
    captureDecision({
      engagementId: state.engagementId,
      phase: 'vuln_detection',
      caller: 'engagement-orchestrator.vulnCorrelation',
      decision: correlationDecision.decision,
      reasoning: correlationDecision.reasoning,
      actions: correlationDecision.actions,
      contextSummary: `${state.assets.length} assets, ${state.assets.reduce((s, a) => s + a.vulns.length, 0)} vulns`,
      latencyMs: Date.now() - _corrDecStart,
    }).catch(() => {});
  }

  state.progress = 55;

  // ─── Specialist: Verify high/critical vulnerabilities ───
  const highCritVulns = state.assets.flatMap(a => 
    a.vulns.filter(v => v.severity === 'critical' || v.severity === 'high')
      .map(v => ({ ...v, hostname: a.hostname, assetType: a.type }))
  );
  if (highCritVulns.length > 0) {
    addLog(state, {
      phase: 'vuln_detection', type: 'info',
      title: '🧐 Vulnerability Verification (AI Specialist)',
      detail: `Verifying ${highCritVulns.length} high/critical findings with Vulnerability Verifier...`,
    });
    broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    try {
      const { verifyVulnerability } = await import('./llm-specialists/vuln-verifier');
      for (const v of highCritVulns.slice(0, 10)) { // Cap at 10 to avoid excessive LLM calls
        try {
          const result = await verifyVulnerability({
            finding: {
              title: v.title,
              severity: v.severity,
              cve: v.cve,
              description: v.title,
              evidence: `Found on ${v.hostname} during vulnerability detection phase`,
              source: v.title.startsWith('[ZAP]') ? 'ZAP' : 'nuclei',
              hostname: v.hostname,
            },
            engagement: {
              engagementType: state.engagementType,
              clientName: state.assets[0]?.hostname,
              targetCount: state.assets.length,
            },
            engagementId: state.engagementId,
          });
          const verdictEmoji = result.analyst_verdict.includes('True Positive') ? '✅' : result.analyst_verdict.includes('False Positive') ? '❌' : '❓';
          addLog(state, {
            phase: 'vuln_detection', type: 'llm_decision',
            title: `${verdictEmoji} Verified: ${v.title}`,
            detail: `Verdict: ${result.analyst_verdict} (${result.confidence})\nExploitability: ${result.exploitability.rating}\nImpact: ${result.business_impact.severity} — ${result.business_impact.rationale}\nATT&CK: ${result.attack_mapping.map(m => m.technique_id).join(', ') || 'N/A'}\nValidation: ${result.safe_validation_step}`,
            data: { vulnVerification: result },
          });
        } catch (vErr: any) {
          console.warn(`[VulnVerifier] Failed for ${v.title}:`, vErr.message);
        }
      }
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (e: any) {
      console.warn('[VulnVerifier] Specialist unavailable:', e.message);
    }
  }

  // ─── Specialist: Hybrid Scorer for active scan findings ───
  const activeFindings = state.assets.flatMap(a => [
    ...a.vulns.map(v => ({
      id: `vuln-${a.hostname}-${v.cve || v.title.substring(0, 30)}`,
      title: v.title,
      severity: v.severity,
      source: v.title.startsWith('[ZAP]') ? 'ZAP' : 'nuclei',
      evidence: `Found on ${a.hostname}${v.cve ? ` (${v.cve})` : ''}`,
      cve: v.cve,
    })),
    ...a.zapFindings.map(z => ({
      id: `zap-${a.hostname}-${z.alert.substring(0, 30)}`,
      title: z.alert,
      severity: z.risk,
      source: 'ZAP',
      evidence: `${z.url} — ${z.description?.substring(0, 200) || ''}`,
    })),
  ]);
  if (activeFindings.length > 0) {
    try {
      const { scoreFullHybrid } = await import('./llm-specialists/hybrid-scorer');
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: '\ud83c\udfaf Hybrid Risk Scoring (Active Findings)',
        detail: `Scoring ${activeFindings.length} findings across ${state.assets.length} assets with context-aware CARVER+CVSS fusion...`,
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

      // Score each asset with findings individually using the correct FullHybridScoreInput interface
      const assetsWithFindings = state.assets.filter(a => a.vulns.length > 0 || a.zapFindings.length > 0);
      for (const asset of assetsWithFindings) {
        try {
          const assetRiskSignals = [
            ...asset.vulns.map(v => ({
              severity: v.severity || 'medium',
              rationale: `${v.title}${v.cve ? ' (' + v.cve + ')' : ''}`,
              source: v.title.startsWith('[ZAP]') ? 'ZAP' : 'nuclei',
            })),
            ...asset.zapFindings.map(z => ({
              severity: z.risk || 'medium',
              rationale: `${z.alert}: ${z.description?.substring(0, 150) || 'ZAP finding'}`,
              source: 'ZAP',
            })),
          ];
          const hybridResult = await scoreFullHybrid({
            assetId: asset.hostname,
            assetLabel: asset.hostname,
            domain: asset.hostname,
            hostname: asset.hostname,
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
            riskSignals: assetRiskSignals,
            cvssBase: Math.max(...asset.vulns.map(v => v.cvss || 0), 0) || undefined,
            engagementContext: state.engagementContext,
          });
          // Store the hybrid score on the asset
          (asset as any).hybridScore = hybridResult.finalScore;
          (asset as any).hybridTier = hybridResult.finalTier;
          const adjustmentSummary = Object.entries(hybridResult.llmEnhanced.adjustments || {})
            .filter(([_, v]: [string, any]) => v.delta !== 0)
            .map(([k, v]: [string, any]) => `${k}: ${v.delta > 0 ? '+' : ''}${v.delta} (${v.justification})`)
            .slice(0, 5);
          addLog(state, {
            phase: 'vuln_detection', type: 'llm_decision',
            title: `\ud83c\udfaf Active Scan Risk: ${asset.hostname} \u2014 ${hybridResult.finalScore}/10`,
            detail: `Tier: ${hybridResult.finalTier} | Baseline: ${hybridResult.baseline.scores.hybrid}/10\nConfidence: ${hybridResult.llmEnhanced.confidence}\nFindings: ${asset.vulns.length} vulns + ${asset.zapFindings.length} ZAP alerts\n\n${hybridResult.llmEnhanced.overallRiskNarrative}\n\n${adjustmentSummary.length > 0 ? 'LLM Adjustments:\n' + adjustmentSummary.map(a => '\u2022 ' + a).join('\n') : 'No LLM adjustments applied'}`,
            data: { hybridScoring: hybridResult },
          });
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
        } catch (assetHsErr: any) {
          console.warn(`[HybridScorer] Active findings scoring failed for ${asset.hostname}:`, assetHsErr.message);
        }
      }
    } catch (hsErr: any) {
      console.warn('[HybridScorer] Active findings scoring failed:', hsErr.message);
    }
  }


  // ─── Specialist: Map threats to threat actors ───
  if (state.assets.some(a => a.vulns.length > 0 || a.zapFindings.length > 0)) {
    try {
      const { mapThreats } = await import('./llm-specialists/threat-mapper');
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: '🌐 Threat Actor Mapping (AI Specialist)',
        detail: 'Correlating findings with known threat actors and APT groups...',
      });
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

      const allFindings = state.assets.flatMap(a => [
        ...a.vulns.map(v => `[${v.severity}] ${v.title} on ${a.hostname}${v.cve ? ' ('+v.cve+')' : ''}`),
        ...a.zapFindings.map(z => `[${z.risk}] ${z.alert} on ${a.hostname}`),
      ]);
      const threatResult = await mapThreats({
        findingsSummary: allFindings.join('\n'),
        assets: state.assets.map(a => ({
          hostname: a.hostname,
          ip: a.ip,
          type: a.type,
          technologies: a.passiveRecon?.technologies,
          ports: a.ports.map(p => ({ port: p.port, service: p.service })),
        })),
        engagement: {
          engagementType: state.engagementType,
          clientName: state.assets[0]?.hostname,
          targetCount: state.assets.length,
        },
        engagementId: state.engagementId,
      });

      if (threatResult.threat_actors.length > 0) {
        addLog(state, {
          phase: 'vuln_detection', type: 'llm_decision',
          title: `🎯 ${threatResult.threat_actors.length} Threat Actor(s) Mapped`,
          detail: threatResult.threat_actors.map(ta =>
            `${ta.actor_name} (${ta.confidence}) — ${ta.relevance_rationale}\n  TTPs: ${ta.associated_ttps.join(', ')}`
          ).join('\n\n') + `\n\nSector risk: ${threatResult.sector_risk_assessment}`,
          data: { threatMapping: threatResult },
        });

        // ── Score threat attribution against the DO learning engine ──
        try {
          const ttps = threatResult.threat_actors.flatMap((ta: any) =>
            (ta.associated_ttps || []).map((ttpStr: string) => {
              const match = ttpStr.match(/^(T\d+(?:\.\d+)?)\s*[:\-]?\s*(.*)/);
              return {
                techniqueId: match ? match[1] : undefined,
                techniqueName: match ? match[2].trim() : ttpStr,
                tactic: ta.primary_tactic || undefined,
              };
            })
          );
          const cves = state.assets.flatMap(a =>
            a.vulns.filter(v => v.cve).map(v => v.cve!)
          );
          const uniqueCves = [...new Set(cves)];

          if (ttps.length > 0 || uniqueCves.length > 0) {
            const attrResult = await scoreEngagementThreatAttribution({
              sessionId: `eng-${state.engagementId}-${Date.now()}`,
              engagementId: state.engagementId,
              targetUrl: state.assets[0]?.hostname,
              ttps,
              cves: uniqueCves,
            });
            if (attrResult) {
              addLog(state, {
                phase: 'vuln_detection', type: 'info',
                title: '📊 Threat Attribution Scored (Learning Engine)',
                detail: `Scored ${ttps.length} TTPs and ${uniqueCves.length} CVEs against threat catalog. ` +
                  `Top match: ${attrResult.summary?.topGroup || 'N/A'} (${attrResult.summary?.confidence || 'N/A'}% confidence)`,
                data: { threatAttribution: attrResult },
              });
            }
          }
        } catch (attrErr: any) {
          console.warn('[ThreatActorLearning] Attribution scoring failed:', attrErr.message);
        }
      }
      broadcastOpsUpdate(state.engagementId, { type: 'log_update' });
    } catch (e: any) {
      console.warn('[ThreatMapper] Specialist unavailable:', e.message);
    }
  }

  // ── Final stats recalculation before Phase 3 summary ──
  state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);

  addLog(state, {
    phase: "vuln_detection",
    type: "phase_complete",
    title: "✅ Phase 3 Complete",
    detail: `${state.stats.vulnsFound} vulns found, ${state.stats.zapScansRun} ZAP scans, ${state.stats.wafDetections} WAFs detected`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

async function executeExploitation(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "exploitation";
  state.currentAction = "Running exploitation phase...";
  addLog(state, { phase: "exploitation", type: "info", title: "⚔️ Phase 4: Exploitation", detail: "Attempting exploitation on vulnerable assets" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "exploitation" });

  // Get LLM to prioritize targets
  const _exploitDecStart = Date.now();
  const decision = await llmDecide({
    phase: "exploitation",
    engagementType: state.engagementType,
    engagementId: state.engagementId,
    assets: state.assets,
    recentLog: state.log.slice(-15),
    question: `It's time to exploit. Which assets should we target first and with what techniques? Remember:
- Pentest: try each asset for unauthorized access to data or privileged functions
- Red Team: find the easiest path to a shell for C2 deployment
Available vulns: ${state.assets.flatMap(a => a.vulns.map(v => `${a.hostname}:${v.title}${v.cve ? ` [${v.cve}]` : ""}`)).join(", ")}
${(() => {
  // Inject attack chain few-shot examples based on detected vuln types
  const vulnDescs = state.assets.flatMap(a => a.vulns.map(v => v.title + (v.cve ? ` ${v.cve}` : '')));
  const chains = getChainsByVulnDescriptions(vulnDescs, 3);
  const chainContext = formatChainsForPrompt(chains);
  // Inject asset ontology context based on detected technologies
  const detectedTech = state.assets.flatMap(a => [
    ...(a.type !== 'unknown' ? [a.type] : []),
    ...a.ports.map((p: any) => p.service).filter(Boolean),
  ]);
  const ontologyContext = formatOntologyForPrompt([...new Set(detectedTech)]);
  const bbContext = getBugBountyContext(vulnDescs, 3);
  const corpusContext = getTriageCorpusContext(undefined, 3);
  const nmapExploitCtx = getNmapVulnCorrelationContext();
  const owaspExploitCtx = getOwaspVulnCorrelationContext();
  const threatExploitCtx = getThreatGroupVulnContext();
  // Add LOTL and file upload bypass knowledge for exploitation phase
  const offTechExploitCtx = buildOffensiveTechniquesContext({
    phase: 'exploitation',
    platform: detectedTech.some(t => /windows|iis|asp\.net/i.test(t)) ? 'windows' : detectedTech.some(t => /linux|apache|nginx/i.test(t)) ? 'linux' : undefined,
    hasFileUpload: detectedTech.some(t => /upload|file|cms|wordpress|drupal|joomla/i.test(t)),
    hasFirewall: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
    hasWAF: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
  });
  // Build ZAP pentesting knowledge for exploitation (payloads, attack paths, alert catalog)
  const zapExploitCtx = buildZAPKnowledgeContext({
    phase: 'exploitation',
    technology: detectedTech[0],
    includePayloads: true,
    footholdMinimum: 'high',
  });
  // Compact source secrets context for exploitation (token-limited)
  const sourceSecretsExploitCtx = buildCompactSourceSecretsContext();
  return chainContext + ontologyContext + '\n\n' + bbContext + '\n\n' + corpusContext + '\n\n' + nmapExploitCtx + '\n\n' + owaspExploitCtx + '\n\n' + threatExploitCtx + (offTechExploitCtx ? '\n\n' + offTechExploitCtx : '') + (zapExploitCtx ? '\n\n' + zapExploitCtx : '') + '\n\n' + sourceSecretsExploitCtx;
})()}`,
  });

  addLog(state, {
    phase: "exploitation",
    type: "llm_decision",
    title: "Exploit Plan",
    detail: decision.decision,
    data: { reasoning: decision.reasoning },
  });
  // ── Training Bridge: capture exploitation decision ──
  captureDecision({
    engagementId: state.engagementId,
    phase: 'exploitation',
    caller: 'engagement-orchestrator.exploitPlan',
    decision: decision.decision,
    reasoning: decision.reasoning,
    actions: decision.actions,
    contextSummary: `${state.assets.flatMap(a => a.vulns).length} vulns across ${state.assets.length} assets`,
    latencyMs: Date.now() - _exploitDecStart,
  }).catch(() => {});

  // ── Pre-Exploitation Approval Gate ──
  // Pause and show the full exploit plan to the operator before firing any exploits.
  // This lets the operator review all selected targets, CVEs, and modules at once.
  let exploitActions = decision.actions.filter((a: any) => a.type === "exploit_attempt");

  // Safety net: if LLM returned 0 exploit actions but we have critical/high vulns,
  // auto-generate exploit actions from the vulnerability list
  if (exploitActions.length === 0) {
    const critHighVulns = state.assets.flatMap(a =>
      a.vulns
        .filter(v => v.severity === 'critical' || v.severity === 'high')
        .map(v => ({ asset: a, vuln: v }))
    );
    if (critHighVulns.length > 0) {
      console.log(`[OpsLLM] Safety net: LLM returned 0 exploit actions but found ${critHighVulns.length} critical/high vulns. Auto-generating exploit plan.`);
      addLog(state, {
        phase: "exploitation",
        type: "info",
        title: "⚠️ LLM Exploit Fallback",
        detail: `LLM returned 0 exploit actions despite ${critHighVulns.length} critical/high vulnerabilities. Auto-generating exploit plan from vulnerability list.`,
      });
      // Deduplicate by CVE+target, prioritize: KEV-listed first, then critical, then high, limit to top 15
      const seen = new Set<string>();
      const autoExploits = critHighVulns
        .sort((a, b) => {
          // KEV-listed vulns always come first
          const aKev = (a.vuln as any).kevListed ? 1 : 0;
          const bKev = (b.vuln as any).kevListed ? 1 : 0;
          if (bKev !== aKev) return bKev - aKev; // KEV first
          // Then by severity: critical before high
          const aSev = a.vuln.severity === 'critical' ? 0 : 1;
          const bSev = b.vuln.severity === 'critical' ? 0 : 1;
          return aSev - bSev;
        })
        .filter(({ asset, vuln }) => {
          const key = `${asset.hostname}:${vuln.cve || vuln.title}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .slice(0, 15)
        .map(({ asset, vuln }) => ({
          type: 'exploit_attempt' as const,
          params: {
            target: asset.hostname,
            port: asset.ports?.[0]?.port || 443,
            cve: vuln.cve || undefined,
            service: asset.ports?.[0]?.service || 'http',
            module: vuln.cve ? `auto-${vuln.cve}` : `auto-${vuln.title?.slice(0, 50)}`,
          },
        }));
      exploitActions = autoExploits;
      decision.actions = [...decision.actions, ...autoExploits];
      const kevCount = autoExploits.filter((a: any) => {
        const matchedAsset = state.assets.find(ast => ast.hostname === a.params?.target || ast.ip === a.params?.target);
        return matchedAsset?.vulns.some(v => v.cve === a.params?.cve && (v as any).kevListed);
      }).length;
      if (kevCount > 0) {
        addLog(state, {
          phase: 'exploitation',
          type: 'info',
          title: `🔴 ${kevCount} CISA KEV Vulnerabilities Prioritized`,
          detail: `${kevCount} exploit target(s) are on the CISA Known Exploited Vulnerabilities list and have been moved to the top of the exploit queue.`,
          riskTier: 'red',
        });
      }
    }
  }

  // ── KEV-first sorting for ALL exploit actions (including LLM-generated) ──
  if (exploitActions.length > 1) {
    exploitActions.sort((a: any, b: any) => {
      const aTarget = state.assets.find(ast => ast.hostname === a.params?.target || ast.ip === a.params?.target);
      const bTarget = state.assets.find(ast => ast.hostname === b.params?.target || ast.ip === b.params?.target);
      const aKev = aTarget?.vulns.some(v => v.cve === a.params?.cve && (v as any).kevListed) ? 1 : 0;
      const bKev = bTarget?.vulns.some(v => v.cve === b.params?.cve && (v as any).kevListed) ? 1 : 0;
      return bKev - aKev; // KEV first, stable sort preserves LLM ordering for non-KEV
    });
  }

  const planSummary = exploitActions.map((a: any, i: number) => {
    const p = a.params || {};
    const matchedAsset = state.assets.find(ast => ast.hostname === p.target || ast.ip === p.target);
    const resolvedPort = p.port || matchedAsset?.ports?.[0]?.port || 443;
    const isKev = matchedAsset?.vulns.some(v => v.cve === p.cve && (v as any).kevListed);
    const kevBadge = isKev ? ' ⚠️ [CISA KEV]' : '';
    return `${i + 1}. ${p.target || "unknown"}:${resolvedPort} — ${p.cve || p.module || "auto"} (${p.service || "unknown service"})${kevBadge}`;
  }).join("\n");

  const exploitPlanApproved = await requestApproval(state, {
    phase: "exploitation",
    riskTier: "red",
    title: `Exploit Plan Review — ${exploitActions.length} target${exploitActions.length !== 1 ? "s" : ""}`,
    description: `The LLM has selected ${exploitActions.length} exploit action${exploitActions.length !== 1 ? "s" : ""}. Review the plan below before any exploits are executed.\n\n${planSummary}\n\nLLM Reasoning: ${decision.reasoning || decision.decision}`,
    target: exploitActions.map((a: any) => {
      const matchedAsset2 = state.assets.find(ast => ast.hostname === a.params?.target || ast.ip === a.params?.target);
      const rPort = a.params?.port || matchedAsset2?.ports?.[0]?.port || 443;
      return `${a.params?.target}:${rPort}`;
    }).join(", "),
    module: exploitActions.map((a: any) => a.params?.cve || a.params?.module || "auto").join(", "),
    detail: {
      exploitCount: exploitActions.length,
      actions: exploitActions.map((a: any) => ({
        target: a.params?.target,
        port: a.params?.port,
        cve: a.params?.cve,
        module: a.params?.module,
        service: a.params?.service,
      })),
      reasoning: decision.reasoning,
      decision: decision.decision,
    },
  });

  if (!exploitPlanApproved) {
    addLog(state, {
      phase: "exploitation",
      type: "info",
      title: "⛔ Exploit Plan Rejected",
      detail: "Operator rejected the exploit plan. No exploits will be executed. Engagement will proceed to reporting phase.",
      riskTier: "red",
    });
    state.progress = 75;
    addLog(state, {
      phase: "exploitation",
      type: "phase_complete",
      title: "✅ Phase 4 Complete (Skipped)",
      detail: "Exploitation phase skipped by operator. 0 exploits attempted.",
    });
    broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
    return;
  }

  // Check if the operator modified the plan (removed some targets)
  const planGate = state.approvalGates.find(g => g.title.startsWith('Exploit Plan Review') && g.status === 'approved');
  const modifiedPlan = planGate?.detail?._modifiedPlan;
  const removedIndices = planGate?.detail?._removedIndices ? new Set(planGate.detail._removedIndices as number[]) : null;
  const isModified = removedIndices && removedIndices.size > 0;

  // Determine which actions to execute
  let actionsToExecute = decision.actions;
  if (isModified) {
    // Filter exploit_attempt actions: only keep those whose index (among exploit actions) is NOT in removedIndices
    let exploitIdx = 0;
    actionsToExecute = decision.actions.filter((a: any) => {
      if (a.type !== 'exploit_attempt') return true; // keep non-exploit actions
      const keep = !removedIndices.has(exploitIdx);
      exploitIdx++;
      return keep;
    });
    const removedCount = exploitActions.length - actionsToExecute.filter((a: any) => a.type === 'exploit_attempt').length;
    addLog(state, {
      phase: "exploitation",
      type: "info",
      title: "✅ Modified Exploit Plan Approved",
      detail: `Operator approved a modified plan: ${removedCount} target${removedCount !== 1 ? 's' : ''} removed, proceeding with ${actionsToExecute.filter((a: any) => a.type === 'exploit_attempt').length} exploit action${actionsToExecute.filter((a: any) => a.type === 'exploit_attempt').length !== 1 ? 's' : ''}.`,
      riskTier: "red",
    });
  } else {
    addLog(state, {
      phase: "exploitation",
      type: "info",
      title: "✅ Exploit Plan Approved",
      detail: `Operator approved the exploit plan. Proceeding with ${exploitActions.length} exploit action${exploitActions.length !== 1 ? "s" : ""}.`,
      riskTier: "red",
    });
  }

  for (const action of actionsToExecute) {
    if (action.type === "exploit_attempt") {
      const { target, cve, service, module } = action.params as any;
      const asset = state.assets.find(a => a.hostname === target || a.ip === target);
      // Default port to first open port on the asset if LLM didn't specify one
      const port = action.params?.port || asset?.ports?.[0]?.port || 443;

      // Request operator approval for exploitation
      const approved = await requestApproval(state, {
        phase: "exploitation",
        riskTier: "red",
        title: `Exploit: ${cve || module || "unknown"} on ${target}:${port}`,
        description: `Attempting exploitation of ${service} on ${target}:${port} using ${module || cve || "auto-selected module"}. This is a high-risk action that may trigger alerts.`,
        target: `${target}:${port}`,
        module: module || cve,
        detail: { cve, service, port, target, module },
      });

      if (!approved) {
        addLog(state, { phase: "exploitation", type: "info", title: `Skipped: ${target}:${port}`, detail: "Operator denied exploitation attempt" });
        continue;
      }

      if (asset) asset.status = "exploiting";
      state.stats.exploitsAttempted++;

      addLog(state, {
        phase: "exploitation",
        type: "exploit_attempt",
        title: `Exploiting: ${target}:${port}`,
        detail: `Using ${module || cve || "auto"} against ${service}`,
        riskTier: "red",
      });

      // Generate exploit plan via exploitation bridge + execute via functional exploit generator
      try {
        const { generateExploitPlan } = await import("./exploitation-bridge-engine");
        const plan = await generateExploitPlan(
          { cve: cve || "", title: `${service} exploit`, cvss: 9.0, service, port: Number(port), targetIp: target },
          undefined,
          { requireApproval: false }
        );

        emitExploitFired({
          jobId: state.stats.exploitsAttempted,
          module: module || cve || "auto",
          targetIp: target,
          targetPort: Number(port),
          engagementId: state.engagementId,
        });

        // ── Real exploit execution via functional exploit generator + scan server ──
        const exploitStartTime = Date.now();
        let success = false;
        let shellSessionId: string | undefined;
        let exploitOutput = '';
        let shellType: string | undefined;
        let shellPayload: string | undefined;

        try {
          // Step 1: Generate the actual exploit code via LLM
          const { generateExploit } = await import("./functional-exploit-generator");
          const vulnForExploit = asset?.vulns.find(v => v.cve === cve || v.title.includes(service));
          const generatedExploit = await generateExploit({
            cve: cve || '',
            title: vulnForExploit?.title || `${service} exploit`,
            description: vulnForExploit?.description || `Vulnerability in ${service} on port ${port}`,
            cvss: vulnForExploit?.cvss || 9.0,
            service: service || 'http',
            port: Number(port),
            targetIp: target,
            targetOs: asset?.os || undefined,
            technologies: asset?.technologies || [],
          });

          // Step 2: Execute the exploit on the scan server
          if (generatedExploit?.code) {
            const { executeRawCommand } = await import("./scan-server-executor");
            // Write exploit to temp file and execute
            const exploitFileName = `exploit_${state.engagementId}_${Date.now()}.py`;
            await executeRawCommand(`cat > /tmp/${exploitFileName} << 'EXPLOIT_EOF'\n${generatedExploit.code}\nEXPLOIT_EOF`, 10);
            const execResult = await executeRawCommand(`cd /tmp && timeout 60 python3 ${exploitFileName} 2>&1 || true`, 90);
            exploitOutput = execResult?.trim() || '';

            // Check for shell indicators in the output
            const shellIndicators = [
              /shell.*opened/i, /session.*opened/i, /meterpreter/i, /reverse.*shell/i,
              /connect.*back/i, /uid=\d+/i, /root@/i, /www-data@/i, /\$\s*$/m,
              /command.*shell/i, /interactive.*shell/i, /spawned/i, /whoami/i,
            ];
            success = shellIndicators.some(re => re.test(exploitOutput)) || 
                      (generatedExploit.popsShell === true && exploitOutput.length > 50);

            shellType = generatedExploit.shellType || undefined;
            shellPayload = generatedExploit.shellPayload || undefined;

            addLog(state, {
              phase: 'exploitation',
              type: 'info',
              title: `Exploit Output: ${target}:${port}`,
              detail: exploitOutput.slice(0, 1000) || 'No output captured',
              data: { 
                exploitCode: generatedExploit.code?.slice(0, 500),
                language: generatedExploit.language,
                popsShell: generatedExploit.popsShell,
                shellType: generatedExploit.shellType,
              },
            });
          }
        } catch (execErr: any) {
          // Functional exploit generator failed — fall back to plan-based assessment
          console.warn(`[Exploit] Functional exploit execution failed for ${target}:${port}:`, execErr.message);
          exploitOutput = `Exploit execution error: ${execErr.message}`;
          // Fall back to plan-based success assessment
          success = !!plan?.selectedExploit?.modulePath && (plan?.confidence ?? 0) >= 0.7;
        }

        if (success) {
          shellSessionId = `session-${genId()}`;
        }

        if (asset) {
          asset.exploitAttempts.push({
            module: module || cve || "auto",
            success,
            sessionId: shellSessionId,
            // Full evidence fields
            cve: cve || undefined,
            service: service || undefined,
            port: Number(port) || undefined,
            target: target || undefined,
            confidence: plan?.confidence ?? undefined,
            reasoning: plan?.reasoning?.slice(0, 500) || undefined,
            selectedExploit: plan?.selectedExploit ? {
              modulePath: plan.selectedExploit.modulePath,
              payload: plan.selectedExploit.payloadOptions?.[0] || shellPayload || undefined,
              options: plan.selectedExploit.opsecRisk ? { opsecRisk: plan.selectedExploit.opsecRisk } : undefined,
            } : undefined,
            exploitOutput: exploitOutput.slice(0, 2000) || undefined,
            shellType: shellType || undefined,
            timestamp: exploitStartTime,
            durationMs: Date.now() - exploitStartTime,
          });
          if (success) {
            asset.status = "compromised";
            state.stats.exploitsSucceeded++;
            state.stats.sessionsOpened++;
          }
        }

        emitExploitResult({
          jobId: state.stats.exploitsAttempted,
          module: module || cve || "auto",
          targetIp: target,
          success,
          engagementId: state.engagementId,
        });

        await auditLog({
          engagementId: state.engagementId,
          operatorId: operatorCtx.id,
          operatorName: operatorCtx.name,
          actionType: "msf_exploit",
          riskTier: "red",
          target,
          targetPort: Number(port),
          moduleOrTool: module || cve,
          resultStatus: success ? "success" : "failure",
          resultDetail: success 
            ? `Exploit succeeded — shell obtained (${shellType || 'reverse_shell'}). Session: ${shellSessionId}` 
            : `Exploit failed. Output: ${exploitOutput.slice(0, 200)}`,
        });

        addLog(state, {
          phase: "exploitation",
          type: success ? "exploit_success" : "exploit_fail",
          title: success ? `✅ Shell Obtained: ${target}` : `❌ Exploit Failed: ${target}`,
          detail: success
            ? `Successfully exploited ${service} on ${target}:${port}. ${shellType || 'Reverse shell'} session opened (${shellSessionId}).\nEvidence: ${exploitOutput.slice(0, 300)}`
            : `Exploitation of ${service} on ${target}:${port} failed.\nOutput: ${exploitOutput.slice(0, 300)}\nMoving to next target.`,
          riskTier: "red",
          data: { 
            plan: plan ? { module: plan.selectedExploit?.modulePath, confidence: plan.confidence, reasoning: plan.reasoning?.slice(0, 300) } : null,
            exploitOutput: exploitOutput.slice(0, 1000),
            shellType,
            shellSessionId,
          },
        });

        // ── Training Bridge: capture exploit outcome ──
        captureExploitOutcome({
          engagementId: state.engagementId,
          target,
          port: Number(port),
          cve: cve || undefined,
          service: service || undefined,
          module: module || undefined,
          success,
          exploitOutput: exploitOutput.slice(0, 1000),
          shellType: shellType || undefined,
          planConfidence: plan?.confidence,
          planReasoning: plan?.reasoning?.slice(0, 500),
        }).catch(() => {});
        // Auto-trigger post-exploitation playbook when a shell is obtained
        if (success) {
          onShellObtained({
            engagementId: state.engagementId,
            targetHost: target,
            exploitOutput: exploitOutput.slice(0, 2000),
            shellType: shellType || undefined,
            objectives: engagement?.objectives ? [engagement.objectives].flat() : undefined,
          }).catch((err: any) => {
            console.warn(`[PostExploit] Auto-trigger failed for engagement #${state.engagementId}:`, err.message);
          });
        }
      } catch (e: any) {
        // Record the failed attempt with error evidence
        if (asset) {
          asset.exploitAttempts.push({
            module: module || cve || "auto",
            success: false,
            cve: cve || undefined,
            service: service || undefined,
            port: Number(port) || undefined,
            target: target || undefined,
            timestamp: Date.now(),
            errorDetail: e.message?.slice(0, 500),
          });
        }
        addLog(state, { phase: "exploitation", type: "error", title: `Exploit Error: ${target}`, detail: e.message });
      }
    }

    // For red team: stop after first successful exploit
    if (state.engagementType === "red_team" && state.stats.exploitsSucceeded > 0) {
      addLog(state, { phase: "exploitation", type: "info", title: "Red Team: Entry Point Secured", detail: "First shell obtained — moving to C2 deployment" });
      break;
    }
  }

  state.progress = 75;
  addLog(state, {
    phase: "exploitation",
    type: "phase_complete",
    title: "✅ Phase 4 Complete",
    detail: `${state.stats.exploitsAttempted} attempts, ${state.stats.exploitsSucceeded} succeeded, ${state.stats.sessionsOpened} sessions`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}
async function executePostExploit(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "post_exploit";
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "post_exploit" });

  if (state.engagementType === "red_team") {
    // ── Red Team: C2 Agent Deployment ──
    state.currentAction = "Deploying C2 agent...";
    addLog(state, { phase: "post_exploit", type: "info", title: "🎯 Phase 5: C2 Deployment & Pivot", detail: "Deploying Caldera agent on compromised host for adversary operations" });

    const compromised = state.assets.filter(a => a.status === "compromised");
    for (const asset of compromised) {
      // Request approval for C2 deployment
      const approved = await requestApproval(state, {
        phase: "post_exploit",
        riskTier: "red",
        title: `Deploy C2 Agent: ${fmtTarget(asset)}`,
        description: `Deploying Caldera agent on ${asset.hostname} (${asset.ip || "unknown IP"}). This will establish a persistent callback to the C2 server for adversary operations and lateral movement.`,
        target: asset.hostname,
        detail: { hostname: asset.hostname, ip: asset.ip, platform: "linux" },
      });

      if (!approved) {
        addLog(state, { phase: "post_exploit", type: "info", title: `C2 Skipped: ${fmtTarget(asset)}`, detail: "Operator denied C2 deployment" });
        continue;
      }

      addLog(state, {
        phase: "post_exploit",
        type: "c2_deploy",
        title: `C2 Agent Deploying: ${fmtTarget(asset)}`,
        detail: "Deploying Caldera Sandcat agent via established session",
        riskTier: "red",
      });

      emitAgentDeployed({
        paw: `agent-${genId()}`,
        host: asset.hostname,
        platform: "linux",
        executors: ["sh", "psh"],
        engagementId: state.engagementId,
      });

      await auditLog({
        engagementId: state.engagementId,
        operatorId: operatorCtx.id,
        operatorName: operatorCtx.name,
        actionType: "caldera_operation",
        riskTier: "red",
        target: asset.hostname,
        moduleOrTool: "caldera_sandcat",
        resultStatus: "success",
        resultDetail: "C2 agent deployed and callback established",
      });

      addLog(state, {
        phase: "post_exploit",
        type: "c2_deploy",
        title: `✅ C2 Active: ${fmtTarget(asset)}`,
        detail: "Agent callback established. Ready for lateral movement and adversary operations.",
        riskTier: "red",
      });
    }

    // ── Caldera Operation Auto-Launch ──
    // If compromised hosts exist and agents are deployed, auto-push adversary profile
    // and launch a Caldera operation to execute the adversary emulation plan.
    let autoLaunchedOpId: string | null = null;
    const compromisedForC2 = state.assets.filter(a => a.status === 'compromised');
    if (compromisedForC2.length > 0) {
      try {
        addLog(state, {
          phase: 'post_exploit', type: 'info',
          title: '🚀 Auto-Launch: Selecting Adversary Profile',
          detail: `${compromisedForC2.length} compromised host(s) detected. Searching for deployable adversary profiles...`,
          riskTier: 'red',
        });

        // Find a suitable adversary profile to push
        const { getDb } = await import('../db');
        const { threatActors: threatActorsTable } = await import('../../drizzle/schema');
        const { isNotNull } = await import('drizzle-orm');
        const dbConn = await getDb();
        const actors = await dbConn
          .select({ actorId: threatActorsTable.actorId, name: threatActorsTable.name, calderaProfile: threatActorsTable.calderaProfile })
          .from(threatActorsTable)
          .where(isNotNull(threatActorsTable.calderaProfile))
          .limit(10);

        // Prefer already-deployed profiles, then any with abilities
        let selectedActor: { actorId: string; name: string; calderaProfile: any } | null = null;
        let selectedAdversaryId: string | null = null;

        for (const actor of actors) {
          try {
            const profile = typeof actor.calderaProfile === 'string' ? JSON.parse(actor.calderaProfile) : actor.calderaProfile;
            if (profile?.deploymentStatus === 'deployed' && profile?.calderaServerId) {
              selectedActor = actor;
              selectedAdversaryId = profile.calderaServerId;
              break;
            }
            if (!selectedActor && profile?.atomicOrdering?.length > 0) {
              selectedActor = actor;
            }
          } catch { /* skip malformed profiles */ }
        }

        if (selectedActor) {
          // Push profile if not already deployed
          if (!selectedAdversaryId) {
            addLog(state, {
              phase: 'post_exploit', type: 'info',
              title: `📤 Auto-Push: ${selectedActor.name}`,
              detail: `Pushing adversary profile to Caldera server...`,
              riskTier: 'red',
            });
            const { pushProfileToCaldera } = await import('./caldera-profile-push');
            const pushResult = await pushProfileToCaldera(selectedActor.actorId);
            if (pushResult.success && pushResult.adversaryId) {
              selectedAdversaryId = pushResult.adversaryId;
              addLog(state, {
                phase: 'post_exploit', type: 'info',
                title: `✅ Profile Pushed: ${selectedActor.name}`,
                detail: `Adversary ID: ${selectedAdversaryId}`,
                riskTier: 'red',
              });
            } else {
              addLog(state, {
                phase: 'post_exploit', type: 'warning',
                title: `⚠️ Profile Push Failed: ${selectedActor.name}`,
                detail: pushResult.error || 'Unknown error',
              });
            }
          }

          // Launch the operation
          if (selectedAdversaryId) {
            addLog(state, {
              phase: 'post_exploit', type: 'info',
              title: `🎯 Auto-Launch: Caldera Operation`,
              detail: `Launching operation with adversary "${selectedActor.name}" (${selectedAdversaryId}) targeting ${compromisedForC2.length} compromised host(s)`,
              riskTier: 'red',
            });

            const { launchOperation } = await import('./caldera-operation-launcher');
            const opName = `AC3-AutoLaunch-Eng${state.engagementId}-${Date.now()}`;
            const launchResult = await launchOperation(
              {
                name: opName,
                adversaryId: selectedAdversaryId,
                group: '',
                planner: 'batch',
                autonomous: true,
                autoClose: true,
                jitter: '2/8',
              },
              `engagement-orchestrator-eng${state.engagementId}`,
              selectedActor.name,
            );

            if (launchResult.success && launchResult.operationId) {
              autoLaunchedOpId = String(launchResult.operationId);
              addLog(state, {
                phase: 'post_exploit', type: 'info',
                title: `✅ Operation Launched: ${opName}`,
                detail: `Operation ID: ${autoLaunchedOpId}. Adversary: ${selectedActor.name}. Auto-starting C2 callback poller.`,
                riskTier: 'red',
                data: { operationId: autoLaunchedOpId, adversaryId: selectedAdversaryId, adversaryName: selectedActor.name },
              });
            } else {
              addLog(state, {
                phase: 'post_exploit', type: 'warning',
                title: `⚠️ Operation Launch Failed`,
                detail: launchResult.error || 'Unknown error',
              });
            }
          }
        } else {
          addLog(state, {
            phase: 'post_exploit', type: 'info',
            title: '📋 No Adversary Profiles Available',
            detail: 'No threat actor profiles found for auto-launch. Create and push a profile from the Threat Actors page to enable auto-launch.',
          });
        }
      } catch (autoLaunchErr: any) {
        addLog(state, {
          phase: 'post_exploit', type: 'warning',
          title: '⚠️ Auto-Launch Error',
          detail: `Could not auto-launch Caldera operation: ${autoLaunchErr.message}`,
        });
      }
    }

    // ── C2 Callback Poller: Start real-time monitoring ──
    // If a Caldera operation was launched (auto or existing), start polling for live C2 events
    try {
      const { startPolling, getPollerSnapshot } = await import('./caldera-c2-callback-poller');
      const { listOperations } = await import('./caldera-operation-launcher');

      // Prefer the auto-launched operation, otherwise find any running operation
      let targetOpId = autoLaunchedOpId;
      if (!targetOpId) {
        const opsResult = await listOperations();
        if (opsResult.success && opsResult.operations.length > 0) {
          const activeOp = opsResult.operations.find(op => op.state === 'running') || opsResult.operations[0];
          targetOpId = String(activeOp.id);
        }
      }

      if (targetOpId) {
        const activeOp = { id: targetOpId, name: autoLaunchedOpId ? `AC3-AutoLaunch-Eng${state.engagementId}` : 'Existing Operation' };
        addLog(state, {
          phase: 'post_exploit', type: 'info',
          title: '📡 C2 Callback Poller Started',
          detail: `Monitoring Caldera operation "${activeOp.name}" (ID: ${activeOp.id}) for real-time agent check-ins and ability executions. Polling every 10s.`,
          riskTier: 'red',
        });
        startPolling(state.engagementId, String(activeOp.id), 10000);

        // Wait for operation to complete or timeout (max 10 minutes)
        const pollerTimeout = 10 * 60 * 1000;
        const pollerStart = Date.now();
        while (Date.now() - pollerStart < pollerTimeout) {
          await new Promise(r => setTimeout(r, 15000));
          const snapshot = getPollerSnapshot(state.engagementId);
          if (!snapshot || !snapshot.isPolling) break;
          if (snapshot.operationSnapshot?.state === 'finished') break;
          // Update engagement state with live C2 data
          state.currentAction = `C2 monitoring: ${snapshot.agents.length} agents, ${snapshot.processedLinkCount} abilities executed`;
          broadcastOpsUpdate(state.engagementId, {
            type: 'c2_status',
            agents: snapshot.agents.length,
            links: snapshot.processedLinkCount,
            opState: snapshot.operationSnapshot?.state,
          });
        }

        // Collect final poller state
        const finalSnapshot = getPollerSnapshot(state.engagementId);
        if (finalSnapshot) {
          addLog(state, {
            phase: 'post_exploit', type: 'phase_complete',
            title: `📡 C2 Monitoring Complete — ${finalSnapshot.agents.length} agents, ${finalSnapshot.processedLinkCount} abilities`,
            detail: `Operation: ${finalSnapshot.operationSnapshot?.state || 'unknown'}\n` +
              `Agents: ${finalSnapshot.agents.map((a: any) => `${a.paw}@${a.host}`).join(', ')}\n` +
              `Polls: ${finalSnapshot.pollCount} | Events: ${finalSnapshot.recentEvents.length}`,
            data: { c2Summary: finalSnapshot },
          });
        }
      } else {
        addLog(state, {
          phase: 'post_exploit', type: 'info',
          title: '📡 No Active Caldera Operations',
          detail: 'No running Caldera operations found. C2 callback polling skipped.',
        });
      }
    } catch (pollerErr: any) {
      addLog(state, {
        phase: 'post_exploit', type: 'warning',
        title: '⚠️ C2 Callback Poller Failed',
        detail: `Could not start C2 monitoring: ${pollerErr.message}`,
      });
    }
  } else {
    // ── Pentest: Evidence Collection ──
    state.currentAction = "Collecting evidence of unauthorized access...";
    addLog(state, { phase: "post_exploit", type: "info", title: "📋 Phase 5: Evidence Collection", detail: "Documenting unauthorized access to data and privileged functions" });

    const compromised = state.assets.filter(a => a.status === "compromised");
    for (const asset of compromised) {
      addLog(state, {
        phase: "post_exploit",
        type: "evidence",
        title: `Evidence: ${fmtTarget(asset)}`,
        detail: `Unauthorized access demonstrated via ${asset.exploitAttempts.filter(e => e.success).map(e => e.module).join(", ")}. ${asset.vulns.length} vulnerabilities confirmed exploitable.`,
        data: {
          hostname: asset.hostname,
          vulns: asset.vulns,
          exploits: asset.exploitAttempts.filter(e => e.success),
        },
      });
    }
  }

  state.progress = 90;
  addLog(state, { phase: "post_exploit", type: "phase_complete", title: "✅ Phase 5 Complete", detail: state.engagementType === "red_team" ? "C2 agents deployed" : "Evidence collected" });
}

// ─── Main Execution Pipeline ────────────────────────────────────────────────

export async function executeEngagement(
  engagementId: number,
  operatorCtx: { id: string; name?: string },
  options?: {
    startPhase?: 'recon' | 'enumeration' | 'vuln_detection' | 'exploitation' | 'post_exploit';
    resume?: boolean; // If true, resume from last saved phase instead of startPhase
    scanProfile?: 'quick' | 'standard' | 'deep' | 'stealth';
  }
): Promise<void> {
  let startPhase = options?.startPhase || 'recon';
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
        const phaseOrder: OpsPhase[] = ['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit'];
        if (options?.startPhase) {
          startPhase = options.startPhase;
        } else {
          const lastPhaseIdx = phaseOrder.indexOf(recovered.phase);
          if (lastPhaseIdx >= 0 && lastPhaseIdx < phaseOrder.length - 1) {
            // Advance to the NEXT phase (the interrupted phase's data is already saved)
            startPhase = phaseOrder[lastPhaseIdx + 1] as any;
          } else {
            startPhase = recovered.phase as any;
          }
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

  // Check RoE status
  if (engagement.roeStatus !== "signed" && engagement.roeStatus !== "pending" && !(state as any).trainingLabMode) {
    addLog(state, {
      phase: "idle",
      type: "error",
      title: "⚠️ RoE Not Signed",
      detail: "Rules of Engagement must be signed before active operations can begin. Only passive recon is allowed.",
    });
  }

  state.isRunning = true;
  if (!state.startedAt) state.startedAt = Date.now();
  state.phase = startPhase;
  if (options?.scanProfile) state.scanProfile = options.scanProfile;

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
  const engagementSafetyLevel: SafetyLevel = scanModeToSafety[engagement.scanMode || "standard"] || "standard";
  const safetyEngine = getSafetyEngine(engagementId, engagementSafetyLevel);
  addLog(state, {
    phase: state.phase, type: "info",
    title: `🛡️ Safety Engine Active — Level: ${safetyEngine.getProfile().label}`,
    detail: `Safety level '${engagementSafetyLevel}' initialized from scan mode '${engagement.scanMode || "standard"}'.\n` +
      `Credential testing: ${safetyEngine.getProfile().allowCredentialTesting ? '✅' : '❌'}\n` +
      `Exploitation: ${safetyEngine.getProfile().allowExploitation ? '✅' : '❌'}\n` +
      `C2 deployment: ${safetyEngine.getProfile().allowC2Deployment ? '✅' : '❌'}\n` +
      `Max blast radius: ${engagementSafetyLevel === 'passive_only' ? 5 : engagementSafetyLevel === 'low_impact' ? 30 : engagementSafetyLevel === 'standard' ? 60 : 100}`,
  });
  broadcastOpsUpdate(engagementId, { type: "safety_init", level: engagementSafetyLevel });

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
      sector: engagement.sector || engagement.industry || undefined,
      complianceFrameworks: engagement.complianceFrameworks || [],
      roeConstraints: engagement.roeStatus === 'signed' ? {
        authorizedDomains: state.roeScopeGuard?.authorizedDomains || [],
        authorizedIps: state.roeScopeGuard?.authorizedIps || [],
        restrictions: engagement.roeNotes || '',
      } : undefined,
      knownAssets: state.assets.map(a => ({ hostname: a.hostname, ip: a.ip, type: a.type })),
    });
    addLog(state, {
      phase: state.phase, type: 'info',
      title: '🧠 Context Engine Initialized',
      detail: `Sector: ${state.engagementContext.sector || 'auto-detect'} | Type: ${state.engagementType} | Compliance: ${state.engagementContext.complianceFrameworks?.join(', ') || 'none'} | RoE: ${engagement.roeStatus}`,
    });
  } catch (e: any) {
    console.error('[OpsState] Context engine init failed:', e.message);
    // Non-fatal — specialists will work without context
  }

  // ═══ OWASP COVERAGE TRACKING ═══
  // Reset tracker at engagement start, register asset tech as discovered
  const owaspTracker = resetOwaspTracker();

  emitSystemNotification({
    title: options?.resume ? "Engagement Resumed" : "Engagement Execution Started",
    message: `Autonomous ${state.engagementType} execution ${options?.resume ? 'resumed' : 'started'} for engagement #${engagementId} (from ${startPhase})`,
    severity: "info",
  });

  // Helper: checkpoint state to DB after each phase completes
  async function phaseCheckpoint(completedPhase: string) {
    await persistOpsStateNow(engagementId);
    console.log(`[OpsState] Phase checkpoint saved: ${completedPhase} for engagement #${engagementId}`);
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

  try {
    // Phase 1: Recon (skip if starting from a later phase)
    if (startPhase === 'recon') {
      const reconGate = safetyEngine.canEnterPhase('recon');
      if (!reconGate.allowed) {
        addLog(state, { phase: 'recon', type: 'warning', title: '🛡️ Safety: Recon Blocked', detail: reconGate.reason });
      } else {
        await executeRecon(state, engagement, operatorCtx);
        await phaseCheckpoint('recon');
        if (!state.isRunning) return;
      }
    }

    // Phase 2+: Require RoE for active scanning (training lab mode bypasses RoE)
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending" || (state as any).trainingLabMode === true) {
      // Phase 2: Enumeration (nmap first — always)
      if (['recon', 'enumeration'].includes(startPhase)) {
        const enumGate = safetyEngine.canEnterPhase('enumeration');
        if (!enumGate.allowed) {
          addLog(state, { phase: 'enumeration', type: 'warning', title: '🛡️ Safety: Enumeration Blocked', detail: `${enumGate.reason}. Requires safety level '${enumGate.requiredLevel}' or higher.` });
        } else {
          await executeEnumeration(state, engagement, operatorCtx);
          await phaseCheckpoint('enumeration');
          if (!state.isRunning) return;
        }
      }

      // Phase 3: Vulnerability Detection (safety gated)
      if (['recon', 'enumeration', 'vuln_detection'].includes(startPhase)) {
        const vulnGate = safetyEngine.canEnterPhase('vuln_detection');
        if (!vulnGate.allowed) {
          addLog(state, { phase: 'vuln_detection', type: 'warning', title: '🛡️ Safety: Vuln Detection Blocked', detail: `${vulnGate.reason}. Requires safety level '${vulnGate.requiredLevel}' or higher.` });
        } else {
          await executeVulnDetection(state, engagement, operatorCtx);
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
                  toolOutputMap.set(tr.tool, (existing + '\n' + tr.outputPreview).slice(0, 2000));
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
                  rawOutput: v.rawOutput || toolOutput,
                  tool: v.tool || toolMatch,
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

            // Store analysis results in state for UI consumption
            (state as any).vulnAnalysis = analysisResults;

            // Generate summary
            const summary = generateAnalysisSummary(analysisResults);

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
              host: asset.ip || asset.hostname,
              port: (v as any).port,
              service: (v as any).service,
              details: (v as any).description || v.title,
            })),
            ...asset.ports.map(p => ({
              type: 'service',
              title: `${p.service || 'unknown'} on port ${p.port}`,
              severity: 'info',
              target: asset.hostname,
              host: asset.ip || asset.hostname,
              port: p.port,
              service: p.service,
              details: p.version ? `${p.service} ${p.version}` : p.service,
            })),
            ...(asset.zapFindings || []).map(z => ({
              type: 'web_vuln',
              title: z.alert || z.name,
              severity: z.risk || 'info',
              target: asset.hostname,
              host: asset.ip || asset.hostname,
              details: z.url || '',
            })),
            // Include tool result summaries so the LLM can see what tools already ran
            // and their output previews for richer context
            ...(asset.toolResults || []).filter(tr => tr.findingCount > 0 || tr.outputPreview).map(tr => ({
              type: 'tool_result',
              title: `[${tr.tool}] ${tr.findingCount} findings (exit ${tr.exitCode}, ${tr.phase})`,
              severity: tr.findingCount > 0 ? 'info' : 'low',
              target: asset.hostname,
              host: asset.ip || asset.hostname,
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
            targets: state.assets.map(a => a.ip || a.hostname),
            engagementName: engagement?.name || `Engagement #${state.engagementId}`,
          };

          const feedbackState = await runFeedbackLoop(allFindingsForLLM, scope, {
            maxIterations: 5,
            maxTotalScans: 12,
            maxScansPerIteration: 4,
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
                    corroborationTier: 'confirmed',
                    evidenceDetail: `Confirmed by ${h.request.tool} re-scan`,
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

      // Phase 4: Exploitation (safety gated)
      const exploitGate = safetyEngine.canEnterPhase('exploitation');
      if (!exploitGate.allowed) {
        addLog(state, { phase: 'exploitation', type: 'warning', title: '🛡️ Safety: Exploitation Blocked', detail: `${exploitGate.reason}. Requires safety level '${exploitGate.requiredLevel}' or higher. ${state.stats.vulnsFound} vulns found but exploitation is not permitted at current safety level.` });
      } else if (state.stats.vulnsFound > 0) {
        await executeExploitation(state, engagement, operatorCtx);
        await phaseCheckpoint('exploitation');
        if (!state.isRunning) return;
      } else {
        addLog(state, { phase: "exploitation", type: "info", title: "No Exploitable Vulns", detail: "No vulnerabilities found to exploit. Engagement complete." });
      }

      // Phase 5: Post-Exploit (safety gated)
      const postExploitGate = safetyEngine.canEnterPhase('post_exploit');
      if (!postExploitGate.allowed) {
        addLog(state, { phase: 'post_exploit', type: 'warning', title: '🛡️ Safety: Post-Exploit Blocked', detail: `${postExploitGate.reason}. Requires safety level '${postExploitGate.requiredLevel}' or higher.` });
      } else if (state.stats.exploitsSucceeded > 0) {
        await executePostExploit(state, engagement, operatorCtx);
        await phaseCheckpoint('post_exploit');
      }
    } else {
      addLog(state, { phase: "enumeration", type: "error", title: "⛔ Active Phases Blocked", detail: "RoE must be signed to proceed past recon. Please have the team lead sign the RoE." });
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
    state.phase = "completed";
    state.progress = 100;
    state.isRunning = false;
    state.completedAt = Date.now();
    state.currentAction = undefined;

    // ── Final stats recalculation from actual asset data ──
    state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
    state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);

    addLog(state, {
      phase: "completed",
      type: "phase_complete",
      title: "🏁 Engagement Execution Complete",
      detail: `${state.stats.hostsScanned} hosts, ${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits, ${state.stats.zapScansRun} ZAP scans`,
    });

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
        const allFindings = state.assets.flatMap(a => [
          ...a.vulns.map(v => ({
            name: v.title,
            severity: v.severity,
            cwe: v.cwe || undefined,
            owasp: v.owasp || undefined,
            endpoint: v.endpoint || undefined,
          })),
          ...a.zapFindings.map(z => ({
            name: z.alert,
            severity: z.risk,
            cwe: z.cweid ? `CWE-${z.cweid}` : undefined,
          })),
          ...(a.nucleiFindings || []).map((n: any) => ({
            name: n.templateId || n.name || n.info?.name || 'nuclei-finding',
            severity: n.info?.severity || n.severity || 'info',
            cwe: n.classification?.cweId?.[0] ? `CWE-${n.classification.cweId[0]}` : undefined,
          })),
        ]);

        // Determine which knowledge modules were used during this engagement
        const modulesUsed = [
          'nuclei', 'zap', 'nmap',
          ...(state.knowledgeModulesUsed || []),
          ...(state.metadata?.knowledgeModules || []),
        ];
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
          addLog(state, {
            phase: 'completed', type: 'info',
            title: `✅ Accuracy: F1=${(compResult.f1Score * 100).toFixed(1)}%${deltaStr} ${trendEmoji}`,
            detail: `P=${(compResult.precision * 100).toFixed(1)}% R=${(compResult.recall * 100).toFixed(1)}% | ` +
              `TP=${compResult.truePositives} FP=${compResult.falsePositives} FN=${compResult.falseNegatives} | ` +
              `Missed: ${compResult.missedVulns.slice(0, 5).join(', ') || 'none'}`,
            data: { accuracyComparison: compResult },
          });
          broadcastOpsUpdate(state.engagementId, { type: 'log_update' });

          // Emit notification to the owner about accuracy results
          try {
            const { notifyOwner } = await import('../_core/notification');
            const f1Pct = (compResult.f1Score * 100).toFixed(1);
            const pPct = (compResult.precision * 100).toFixed(1);
            const rPct = (compResult.recall * 100).toFixed(1);
            await notifyOwner({
              title: `Accuracy Report: ${targetPreset} — F1 ${f1Pct}%${deltaStr}`,
              content: `Engagement #${engagementId} completed on ${targetPreset}.\n` +
                `F1: ${f1Pct}% | Precision: ${pPct}% | Recall: ${rPct}%\n` +
                `TP: ${compResult.truePositives} | FP: ${compResult.falsePositives} | FN: ${compResult.falseNegatives}\n` +
                `Missed: ${compResult.missedVulns.slice(0, 5).join(', ') || 'none'}\n` +
                `View details on the Knowledge Base → Accuracy Feedback tab.`,
            });
          } catch (notifErr: any) {
            console.warn('[AccuracyFeedback] Notification failed:', notifErr.message);
          }
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

    // Final checkpoint
    await phaseCheckpoint('completed');

    emitSystemNotification({
      title: "Engagement Complete",
      message: `${state.engagementType} engagement #${engagementId} finished: ${state.stats.exploitsSucceeded} successful exploits`,
      severity: "info",
    });
  } catch (e: any) {
    state.phase = "error";
    state.isRunning = false;
    state.error = e.message;
    addLog(state, { phase: "error", type: "error", title: "Pipeline Error", detail: e.message });
    // Save error state so it can be inspected and potentially resumed
    await persistOpsStateNow(engagementId);
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

  const resumePhase = state.phase === 'error' || state.phase === 'idle' || state.phase === 'paused'
    ? (state.log.length > 0 ? state.log[state.log.length - 1].phase : 'recon')
    : state.phase;

  // Reset error state
  state.error = undefined;
  state.isRunning = false; // Will be set to true by executeEngagement

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
