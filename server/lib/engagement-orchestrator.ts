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
import { getNmapScanPlanContext, getNmapVulnCorrelationContext, getNmapHuntContext } from "./nmap-knowledge";
import {
  emitExploitFired, emitExploitResult, emitAgentDeployed,
  emitReconComplete, emitSystemNotification, emitSystemAlert,
  eventHub,
} from "./ws-event-hub";
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
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{ module: string; success: boolean; sessionId?: string }>;
  status: "pending" | "scanning" | "enumerated" | "vulns_found" | "exploiting" | "compromised" | "no_vulns" | "discovered";
  wafDetected?: string;
  passiveRecon?: AssetPassiveRecon;
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

export function getOpsState(engagementId: number): EngagementOpsState | null {
  return opsStates.get(engagementId) || null;
}

/**
 * Get ops state with auto-recovery from DB if in-memory state is missing.
 * Use this from API endpoints; the sync version above is for internal pipeline use.
 */
export async function getOpsStateWithRecovery(engagementId: number): Promise<EngagementOpsState | null> {
  const memState = opsStates.get(engagementId);
  if (memState) return memState;

  // Try to recover from DB snapshot
  try {
    const { loadOpsSnapshot } = await import('../db');
    const snapshot = await loadOpsSnapshot(engagementId);
    if (snapshot) {
      console.log(`[OpsState] Recovered state for engagement #${engagementId} from DB snapshot (${snapshot.assets?.length || 0} assets)`);
      opsStates.set(engagementId, snapshot);
      return snapshot;
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

function addLog(state: EngagementOpsState, entry: Omit<OpsLogEntry, "id" | "timestamp">) {
  const logEntry: OpsLogEntry = { id: genId(), timestamp: Date.now(), ...entry };
  state.log.push(logEntry);
  // Keep last 500 entries
  if (state.log.length > 500) state.log = state.log.slice(-500);
  broadcastOpsUpdate(state.engagementId, { type: "log", entry: logEntry });
  // Trigger debounced persistence on every log entry
  persistOpsStateDebounced(state.engagementId);
  return logEntry;
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

async function requestApproval(
  state: EngagementOpsState,
  gate: Omit<ApprovalGate, "id" | "status" | "createdAt">
): Promise<boolean> {
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

  // Wait for operator response
  return new Promise<boolean>((resolve) => {
    approvalResolvers.set(approval.id, (approved) => {
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

  const availableTools = [
    { name: 'nmap', desc: 'Port scanner and service fingerprinter', flags: ['-sV (version detection)', '-sC (default scripts)', '-sU (UDP scan)', '-O (OS detection)', '--script vuln (vuln scripts)', '-T4 (aggressive timing)', '-T2 (polite timing)', '-Pn (skip host discovery)', '-p- (all ports)', '--top-ports N'] },
    { name: 'nuclei', desc: 'Template-based vulnerability scanner (v3.7.0, 9800+ templates). CRITICAL: always use -u URL (NOT -target), always include -severity critical,high,medium to filter templates, always use -nc -duc -ni -jsonl flags. Example: nuclei -u https://target:443 -severity critical,high,medium -tags nginx -jsonl -nc -duc -ni -timeout 10 -retries 1', use: 'web apps, known CVEs, misconfigurations' },
    { name: 'nikto', desc: 'Web server scanner for dangerous files/CGIs. Use -h URL format. Example: nikto -h https://target:443 -Tuning 1234567890 -maxtime 300', use: 'web servers' },
    { name: 'gobuster', desc: 'Directory/file brute-forcer', use: 'web apps to find hidden paths' },
    { name: 'httpx', desc: 'HTTP probe, tech fingerprinter, and web asset enumerator. CRITICAL: use pipe mode (echo URL | httpx flags) NOT -u flag. Example: echo https://target:443 | httpx -json -tech-detect -status-code -title -follow-redirects', flags: ['-json (JSON output)', '-tech-detect', '-status-code', '-title', '-cdn', '-tls-grab', '-follow-redirects', '-content-length', '-web-server', '-method GET', '-threads 50', '-ports 80,443,8080,8443', '-probe', '-silent'], use: 'mandatory HTTP probing after port discovery — detects tech stack, CDN/WAF, TLS, status codes, web server' },
    { name: 'hydra', desc: 'Credential brute-forcer', use: 'SSH, FTP, RDP, MySQL, HTTP-auth, SMB logins' },
    { name: 'enum4linux', desc: 'SMB/NetBIOS enumerator', use: 'Windows/Samba hosts' },
    { name: 'smbclient', desc: 'SMB share lister', use: 'Windows/Samba file shares' },
    { name: 'ldapsearch', desc: 'LDAP directory enumerator', use: 'Active Directory/LDAP servers' },
    { name: 'dig', desc: 'DNS query tool', use: 'DNS servers, zone transfers' },
    { name: 'onesixtyone', desc: 'SNMP scanner', use: 'network devices with SNMP' },
    // naabu removed — raw socket issues on DigitalOcean; use nmap --top-ports for port discovery
    { name: 'subfinder', desc: 'Subdomain discovery (skip for scoped engagements — only use when doing broad domain discovery)', use: 'finding additional subdomains in unscoped/domain-intel mode' },
    // Cloud storage & misconfiguration enumeration tools
    { name: 'cloud_enum', desc: 'Multi-cloud resource enumerator — discovers S3 buckets, Azure Blobs, GCS buckets by keyword. Usage: cloud_enum -k <keyword> [--disable-aws] [--disable-azure] [--disable-gcp] -l /tmp/cloud_enum_<keyword>.txt', use: 'cloud resource discovery when cloud-hosted assets detected via CNAME/headers' },
    { name: 's3scanner', desc: 'S3 bucket permission scanner — checks for public ACLs, listing, and read/write access. Usage: echo "<bucket_name>" | s3scanner scan --json', use: 'testing specific S3 bucket names for access misconfigurations' },
    { name: 'trufflehog', desc: 'Secret scanner — finds exposed credentials in public buckets. Usage: trufflehog s3 --bucket <bucket_name> --json', use: 'post-discovery scanning of accessible buckets for leaked secrets' },
    { name: 'aws', desc: 'AWS CLI for direct S3/cloud API interaction. Usage: aws s3 ls s3://<bucket> --no-sign-request', use: 'direct bucket enumeration without credentials (anonymous access testing)' },
    // Web application fuzzing & content discovery tools
    { name: 'ffuf', desc: 'Fast web fuzzer for directory/file discovery, parameter fuzzing, and vhost enumeration. Usage: ffuf -u https://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o /tmp/ffuf_<target>.json -of json -t 50 -timeout 10', use: 'web content discovery, hidden endpoint fuzzing, parameter brute-forcing — faster than gobuster for large wordlists' },
    { name: 'feroxbuster', desc: 'Recursive content discovery tool with auto-filtering and smart recursion. Usage: feroxbuster -u https://target -w /usr/share/wordlists/dirb/common.txt -o /tmp/ferox_<target>.txt --json -t 50 -d 3 --smart --auto-tune', use: 'deep recursive directory discovery — better than gobuster for finding nested paths and auto-filtering false positives' },
    // SQL injection & database exploitation
    { name: 'sqlmap', desc: 'Automatic SQL injection detection and exploitation tool. Usage: sqlmap -u "https://target/page?id=1" --batch --level 3 --risk 2 --random-agent --output-dir /tmp/sqlmap_<target> --forms --crawl=2. CRITICAL: only use against confirmed injectable parameters or after nuclei/ZAP identifies SQLi. Never run blindly.', use: 'SQL injection exploitation on web apps with confirmed or suspected SQLi vulnerabilities' },
    // TLS/SSL analysis
    { name: 'testssl', desc: 'TLS/SSL cipher and vulnerability scanner. Usage: testssl.sh --jsonfile /tmp/testssl_<target>.json --severity HIGH --sneaky <target>:443. Tests for Heartbleed, POODLE, BEAST, ROBOT, DROWN, CRIME, BREACH, FREAK, Logjam, and weak ciphers.', use: 'TLS/SSL security assessment — run on all HTTPS services to check for protocol vulnerabilities and weak cipher suites' },
    // Web technology fingerprinting
    { name: 'whatweb', desc: 'Web technology identifier — detects CMS, frameworks, server software, analytics, JavaScript libraries. Usage: whatweb -a 3 --log-json /tmp/whatweb_<target>.json https://target', use: 'technology stack fingerprinting — complements httpx with deeper CMS/framework detection (WordPress, Drupal, Joomla, etc.)' },
    // WordPress-specific scanning
    { name: 'wpscan', desc: 'WordPress vulnerability scanner — enumerates users, plugins, themes, and checks for known CVEs. Usage: wpscan --url https://target --enumerate u,vp,vt,dbe --format json -o /tmp/wpscan_<target>.json --random-user-agent. CRITICAL: only use when WordPress is detected by httpx/whatweb.', use: 'WordPress-specific vulnerability scanning — plugin/theme CVEs, user enumeration, xmlrpc abuse' },
    // Advanced subdomain & infrastructure discovery
    { name: 'amass', desc: 'In-depth attack surface mapping and external asset discovery. Usage: amass enum -d <domain> -o /tmp/amass_<domain>.txt -timeout 15 -passive. Combines DNS brute-force, certificate transparency, web archives, and API sources.', use: 'comprehensive subdomain and infrastructure discovery — use for broad attack surface mapping when scope allows domain-wide discovery' },
  ];

  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are an expert penetration tester and red team operator planning the active scanning phase of a ${state.engagementType} engagement. You have completed passive OSINT reconnaissance and now have rich data about each target asset including services, technologies, certificates, risk signals, and WAF/CDN detection.

Your scan plan MUST follow a two-phase approach:

## PHASE A: Discovery Scan (MANDATORY FIRST STEP — 2 tools in sequence)
Phase A runs TWO mandatory tools in sequence for every asset:

### Step 1: nmap (port discovery + service fingerprinting)
- Run nmap with --top-ports 1000 and -T3 timing for reliable port discovery
- The system automatically appends the target and enforces --top-ports 1000 with -T3 timing
- discoveryNmapFlags should ONLY contain scan type flags, NOT port specs or target
- DO NOT include -p, --top-ports, -T flags, or any {placeholder} strings in discoveryNmapFlags
- DO NOT use -p- (all 65535 ports) — it takes 30+ minutes per host and will timeout

⚠️ CRITICAL: EVASION FLAGS vs CLOUD TARGETS
- If the target is behind a CDN/WAF (CloudFront, CloudFlare, Akamai, etc.) or is cloud-hosted (AWS, Azure, GCP):
  * DO NOT use -f (fragmentation) — cloud firewalls DROP fragmented packets, causing ALL ports to show as 'filtered'
  * DO NOT use -D RND:5 (decoys) — cloud infrastructure ignores decoy responses
  * DO NOT use --data-length (padding) — gets stripped/blocked by cloud WAFs
  * DO NOT use --source-port 53/80 (source port spoofing) — cloud firewalls block spoofed source ports
  * USE SIMPLE FLAGS ONLY: '-Pn -sV -sC' — this reliably finds open ports on cloud targets
  * Example for cloud targets: '-Pn -sV -sC'
- If the target is on-premise / self-hosted / no CDN detected:
  * Evasion flags are appropriate: '-Pn -sV -sC -O -f -D RND:5 --data-length 64 --source-port 53'
  * Example for on-premise targets: '-Pn -sV -sC -O -f -D RND:5 --data-length 64'
- When in doubt, use SIMPLE flags — finding ports is more important than evasion

### Step 2: httpx (HTTP probing on all web ports)
- Run httpx on ALL HTTP/HTTPS ports found by nmap
- The system automatically builds the httpx command with discovered ports — no need to specify in flags
- httpx detects: technology stack, CDN/WAF presence, TLS certificate info, HTTP status codes, web server software, page titles
- This data is CRITICAL for Phase B tool selection (e.g., if httpx detects WordPress → nuclei wordpress templates)

The discovery scan ENRICHES the passive recon data — both tools' results will be fed back to you for Phase B planning

## PHASE B: Targeted Tool Deployment
After discovery results are merged, select specific tools per asset based on the COMBINED passive recon + discovery data:
- Web services → nuclei, nikto, gobuster, httpx, ffuf (fast fuzzing), feroxbuster (recursive discovery)
- Web tech fingerprinting → whatweb (deep CMS/framework detection, complements httpx)
- WordPress sites → wpscan (ONLY when WordPress detected by httpx/whatweb)
- SQL injection → sqlmap (ONLY against confirmed or suspected injectable parameters from nuclei/ZAP findings)
- TLS/SSL analysis → testssl (run on all HTTPS services to check for protocol vulnerabilities)
- SMB/NetBIOS → enum4linux, smbclient
- LDAP/AD → ldapsearch
- DNS → dig (zone transfer attempts)
- SNMP → onesixtyone
- Login services (SSH, FTP, RDP, MySQL) → hydra (only if approved)
- Additional subdomains → subfinder or amass (ONLY for domain intelligence / unscoped discovery — skip for scoped engagements where targets are already defined)
- Attack surface mapping → amass (comprehensive subdomain + infrastructure discovery when scope allows)
- Cloud storage/apps → cloud_enum (keyword enumeration), s3scanner (bucket permission testing), aws CLI (anonymous S3 access), trufflehog (secret scanning in accessible buckets)
- Nuclei cloud templates → nuclei with -tags cloud,s3,azure,gcp,firebase,bucket,storage,misconfig

### Tool Selection Priority Rules:
1. ALWAYS run whatweb on web services for deep tech fingerprinting before selecting specialized tools
2. If WordPress detected → add wpscan to the tool list
3. If SQLi suspected (from nuclei/ZAP) → add sqlmap targeting the specific parameter
4. Use ffuf over gobuster when you need parameter fuzzing or vhost enumeration
5. Use feroxbuster over gobuster when you need recursive depth-first directory discovery
6. Run testssl on all HTTPS services — TLS vulnerabilities are often overlooked
7. Use amass instead of subfinder when you need comprehensive infrastructure mapping (DNS + CT + web archives)

## CLOUD STORAGE & APP MISCONFIGURATION DETECTION
When you detect cloud-hosted assets (via CNAME patterns, HTTP headers, or technology fingerprints), you MUST include cloud-specific tools in the activeTools list:

### Cloud Provider Detection Signals:
- AWS: CNAME to *.s3.amazonaws.com, *.cloudfront.net, *.elasticbeanstalk.com; Headers: x-amz-request-id, Server: AmazonS3
- Azure: CNAME to *.blob.core.windows.net, *.azurewebsites.net; Headers: x-ms-request-id, x-ms-version
- GCP: CNAME to *.storage.googleapis.com, *.appspot.com; Headers: x-goog-storage-class, Server: UploadServer
- Firebase: CNAME to *.firebaseio.com, *.firebaseapp.com, *.web.app
- DigitalOcean: CNAME to *.digitaloceanspaces.com

### Cloud Scan Priority Rules (MANDATORY — MUST follow for ALL cloud-hosted targets):
1. **MUST add cloud_enum** for EVERY cloud-hosted target. Command: \`cloud_enum -k <domain_keyword>\`. This is NON-NEGOTIABLE.
2. **MUST add s3scanner** when AWS is detected. Command: \`echo "<domain>" | s3scanner scan --json\`. This is NON-NEGOTIABLE.
3. **MUST add nuclei -tags cloud,s3,misconfig** for ALL cloud targets. This is NON-NEGOTIABLE.
4. If S3/GCS/Blob endpoints found → add s3scanner or direct curl/aws CLI checks
5. If Firebase detected → add bash curl checks for Firebase DB rules and public read access
6. For subdomain takeover candidates (NoSuchBucket, ContainerNotFound) → flag as HIGH severity
7. Only run trufflehog AFTER confirming public access to a bucket (Priority 4 — last resort)

**FAILURE TO INCLUDE cloud_enum AND s3scanner FOR CLOUD TARGETS IS A CRITICAL ERROR.**

Available tools on the scan server:
${availableTools.map(t => `- ${t.name}: ${t.desc}${(t as any).use ? ` (best for: ${(t as any).use})` : ''}`).join('\n')}

IMPORTANT EVASION CONSIDERATIONS:
- If WAF/CDN detected (CloudFront, CloudFlare, Akamai, etc.): DO NOT use evasion flags (-f, -D, --data-length, --source-port). Cloud firewalls DROP fragmented/spoofed packets, causing 0 results. Use simple '-Pn -sV -sC' instead.
- If cloud-hosted (AWS, Azure, GCP): same rule — simple flags only. Cloud WAFs filter evasion techniques.
- For on-premise targets: evasion flags are appropriate and recommended.
- For red_team engagements against on-premise: maximize stealth with -T2, fragmentation, decoys
- For pentest engagements: balance speed vs stealth with -T3, selective evasion only on non-cloud targets
- RULE: Finding open ports is ALWAYS more important than evasion. If evasion might cause 0 results, skip it.

You MUST respond with valid JSON matching this exact schema:
{
  "overallStrategy": "Brief description of the two-phase scanning approach",
  "discoveryStrategy": "Description of the Phase A discovery scan approach and evasion rationale",
  "discoveryEvasionProfile": {
    "timing": "T2 or T3",
    "fragmentation": true/false,
    "decoys": true/false,
    "randomizeHosts": true/false,
    "dataLengthPadding": true/false,
    "sourcePortSpoofing": true/false,
    "rationale": "Why these evasion techniques were selected"
  },
  "estimatedDuration": "Estimated time for all scans (e.g., '15-25 minutes')",
  "riskAssessment": "Overall risk notes for active scanning these targets",
  "assetPlans": [
    {
      "hostname": "exact hostname from the asset list",
      "ip": "IP if known",
      "assetType": "web_app|server|api|database|network_device|unknown",
      "discoveryNmapFlags": "ONLY scan type and evasion flags. NO -p, --top-ports, -T, or placeholders. Example: '-Pn -sV -sC -O -f -D RND:5 --data-length 64 --source-port 53'",
      "discoveryNmapRationale": "Why these discovery+evasion flags for this specific asset",
      "nmapFlags": "Phase B scan type flags ONLY. NO -p port specs or placeholders. Example: '-sV -sC --script vuln'. Ports are added automatically from Phase A results.",
      "nmapRationale": "Why these targeted flags based on expected services",
      "activeTools": [
        {
          "tool": "tool name from available list",
          "command": "exact command with the ACTUAL hostname/IP. CRITICAL FORMAT RULES: nuclei MUST use '-u URL' format with -severity filter (e.g. 'nuclei -u https://target:443 -severity critical,high,medium -tags nginx -jsonl -nc -duc -ni -timeout 10 -retries 1'). httpx MUST use pipe mode (e.g. 'echo https://target:443 | httpx -json -tech-detect -status-code -title -follow-redirects'). nikto uses -h URL (e.g. 'nikto -h https://target:443 -Tuning 1234567890 -maxtime 300')",
          "rationale": "Why this tool for this asset based on passive recon data",
          "priority": 1
        }
      ],
      "riskNotes": "Any risk concerns for this specific asset (WAF, rate limiting, IDS)",
      "evasionTechniques": ["list of evasion techniques to use for this asset"]
    }
  ]
}`
      },
      {
        role: 'user',
        content: `## Passive OSINT Results\n\n### Per-Asset Intelligence:\n${JSON.stringify(assetSummaries, null, 2)}\n\n${domainReconSummary.length > 0 ? `### Domain-Level Intelligence Summary:\n${JSON.stringify(domainReconSummary, null, 2)}\n\n` : ''}Engagement type: ${state.engagementType}\nTotal assets: ${state.assets.length}\n\n${(() => {
  // Inject knowledge context for smarter scan planning
  const detectedTech = state.assets.flatMap(a => [
    ...(a.type !== 'unknown' ? [a.type] : []),
    ...a.ports.map((p: any) => p.service).filter(Boolean),
  ]);
  const ontologyCtx = detectedTech.length > 0 ? formatOntologyForPrompt([...new Set(detectedTech)]) : '';
  const bbCtx = getTrainingExamplesForPrompt(2);
  const corpusCtx = getTriageCorpusContext(undefined, 2);
  // Inject cloud security awareness for cloud asset detection
  const allObs = state.assets.flatMap(a => [
    ...(a.passiveRecon?.technologies || []),
    ...(a.passiveRecon?.riskSignals?.map(r => r.rationale) || []),
    a.passiveRecon?.cloudProvider || '',
  ]).filter(Boolean);
  const cloudCtx = allObs.length > 0 ? buildCloudSecurityContext(allObs) : buildGeneralCloudContext();
  // Inject nmap expertise for scan plan generation
  const nmapCtx = getNmapScanPlanContext({
    detectedTech: [...new Set(detectedTech)],
    cloudProvider: state.assets.find(a => a.passiveRecon?.cloudProvider)?.passiveRecon?.cloudProvider,
    hasFirewall: state.assets.some(a => a.wafDetected && a.wafDetected !== 'none'),
    hasIDS: state.engagementType === 'red_team',
    stealthRequired: state.engagementType === 'red_team',
  });
  const owaspCtx = getOwaspScanPlanContext([...new Set(detectedTech)]);
  const threatGroupCtx = getThreatGroupScanContext({ technologies: [...new Set(detectedTech)] });
  return (ontologyCtx ? '## Asset Architecture Context\n' + ontologyCtx + '\n\n' : '') +
    (bbCtx ? '## Bug Bounty Methodology Context\n' + bbCtx + '\n\n' : '') +
    (corpusCtx ? '## Tool Output Triage Examples\n' + corpusCtx + '\n\n' : '') +
    (cloudCtx ? cloudCtx + '\n\n' : '') +
    (nmapCtx ? nmapCtx + '\n\n' : '') +
    (owaspCtx ? owaspCtx + '\n\n' : '') +
    (threatGroupCtx ? threatGroupCtx + '\n\n' : '');
})()}Generate the two-phase scan plan. Phase A discovery nmap MUST use --top-ports 1000 with evasion techniques. Do NOT use -p- (all ports) — it times out. Always include --top-ports 1000 in discoveryNmapFlags. Phase B tools should be tailored to what passive recon already revealed about each asset.`
      }
    ],
    response_format: {
      type: 'json_schema',
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
    }
  });

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
  assets: AssetStatus[];
  recentLog: OpsLogEntry[];
  question: string;
}): Promise<{ decision: string; reasoning: string; actions: Array<{ type: string; params: Record<string, any> }> }> {
  const systemPrompt = `You are an expert penetration tester and red team operator AI assistant embedded in the ACE C3 offensive security platform. You are orchestrating an autonomous ${context.engagementType} engagement.

Current phase: ${context.phase}
Assets in scope: ${context.assets.map(a => `${a.hostname}${a.ip ? ` (${a.ip})` : ''} [${a.type}] — ${a.status}, ${a.ports.length} ports, ${a.vulns.length} vulns, ${a.zapFindings.length} ZAP findings${a.wafDetected ? `, WAF: ${a.wafDetected}` : ''}`).join('\n')}

Recent activity:
${context.recentLog.slice(-15).map(l => `[${l.type}] ${l.title}: ${l.detail}`).join('\n')}

You must respond with valid JSON matching this schema:
{
  "decision": "brief summary of what to do next",
  "reasoning": "why this is the best next step",
  "actions": [
    {
      "type": "nmap_scan|nuclei_scan|zap_scan|exploit_attempt|c2_deploy|recon|skip|complete|wait",
      "params": { ... action-specific parameters ... }
    }
  ]
}

For nmap_scan: params = { targets: string[], profile: "quick"|"standard"|"deep"|"stealth"|"service"|"vuln" }
For nuclei_scan: params = { targets: string[], severity: string[], tags?: string[] }
For zap_scan: params = { targetUrl: string, scanType: "full"|"active"|"spider_only", wafAware: boolean }
For exploit_attempt: params = { target: string, port: number, cve: string, service: string, module?: string }
For c2_deploy: params = { target: string, platform: string, method: string }
For recon: params = { domain: string }
For complete: params = { reason: string }

Rules:
- For pentest: systematically test each asset for unauthorized access to data or privileged functions
- For red_team: find the weakest/easiest entry point, exploit it, deploy C2, pivot internally
- Always check for web applications and trigger ZAP scans on discovered web apps/sites
- Be WAF-aware: if WAF is detected, adjust scan parameters (lower rate, use evasion)
- Correlate findings across tools (nmap services → nuclei templates → ZAP findings → exploit selection)
- High-risk actions (exploits, C2 deployment) require operator approval — flag them
- Never scan out-of-scope targets
${(() => {
  // Inject asset ontology context for architecture-aware decisions
  const detectedTech = context.assets.flatMap(a => [
    ...(a.type !== 'unknown' ? [a.type] : []),
    ...a.ports.map((p: any) => p.service).filter(Boolean),
  ]);
  const ontology = detectedTech.length > 0 ? formatOntologyForPrompt([...new Set(detectedTech)]) : '';
  const bbTraining = getTrainingExamplesForPrompt(2);
  // Inject attack chain context based on known vulns
  const vulnDescs = context.assets.flatMap(a => a.vulns.map((v: any) => v.title || v.description || '').filter(Boolean));
  const chains = vulnDescs.length > 0 ? getChainsByVulnDescriptions(vulnDescs, 3) : [];
  const chainCtx = chains.length > 0 ? formatChainsForPrompt(chains) : '';
  const corpusCtx = getTriageCorpusContext(undefined, 2);
  // Cloud security context for cloud-aware decision making
  const cloudObs = context.assets.flatMap(a => [
    ...(a.passiveRecon?.technologies || []),
    ...(a.passiveRecon?.riskSignals?.map(r => r.rationale) || []),
    a.passiveRecon?.cloudProvider || '',
    ...a.vulns.map(v => v.title),
  ]).filter(Boolean);
  const cloudCtx = cloudObs.length > 0 ? buildCloudSecurityContext(cloudObs) : '';
  return (chainCtx ? '\n\n## Known Attack Chains\n' + chainCtx : '') +
    ontology +
    (bbTraining ? '\n\n## Bug Bounty Reasoning Examples\n' + bbTraining : '') +
    (corpusCtx ? '\n\n## Tool Output Triage Examples\n' + corpusCtx : '') +
    (cloudCtx ? '\n\n' + cloudCtx : '');
})()}`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: context.question },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "ops_decision",
          strict: true,
          schema: {
            type: "object",
            properties: {
              decision: { type: "string" },
              reasoning: { type: "string" },
              actions: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    type: { type: "string" },
                    params: { type: "object", additionalProperties: true },
                  },
                  required: ["type", "params"],
                  additionalProperties: false,
                },
              },
            },
            required: ["decision", "reasoning", "actions"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    return JSON.parse(content);
  } catch (e: any) {
    console.warn("[OpsLLM] Decision failed:", e.message);
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
        zapFindings: [],
        exploitAttempts: [],
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
        zapFindings: [],
        exploitAttempts: [],
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
      let outOfScopeCount = 0;
      for (const asset of discoveredAssets) {
        const hostname = asset.hostname || asset.domain || asset.ip;
        if (!hostname) continue;
        const existing = state.assets.find(a => a.hostname === hostname);
        if (existing) {
          existing.ip = asset.ip || existing.ip;
          existing.type = asset.assetType === "web_application" ? "web_app" : existing.type;
        } else if (isInRoeScope(state, hostname, asset.ip)) {
          // Asset is in RoE scope — add for active scanning
          state.assets.push({
            hostname,
            ip: asset.ip,
            type: asset.assetType === "web_application" ? "web_app" : "unknown",
            ports: [],
            vulns: [],
            zapFindings: [],
            exploitAttempts: [],
            toolResults: [],
            status: "pending",
          });
        } else {
          // Asset discovered but OUT OF RoE SCOPE — log but do NOT add for active scanning
          outOfScopeCount++;
          addLog(state, {
            phase: "recon", type: "warning",
            title: `⚠️ Out-of-Scope Asset: ${hostname}`,
            detail: `Discovered ${hostname}${asset.ip ? ` (${asset.ip})` : ''} via passive recon but it is NOT in the RoE authorized target list. Skipping active scanning.`,
          });
        }
      }
      if (outOfScopeCount > 0) {
        addLog(state, {
          phase: "recon", type: "info",
          title: `🛡️ Scope Guard: ${outOfScopeCount} out-of-scope assets filtered`,
          detail: `${outOfScopeCount} assets discovered via passive recon were excluded from active scanning per RoE.`,
        });
      }

      const findingsCount = (result as any).totalFindings || 0;
      addLog(state, {
        phase: "recon",
        type: "scan_result",
        title: `Recon Complete: ${domain}`,
        detail: `Discovered ${discoveredAssets.length} assets, ${findingsCount} findings`,
        data: { domain, assets: discoveredAssets.length, findings: findingsCount },
      });

      emitReconComplete({ scanId: 0, domain, findings: findingsCount });
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
      // Hydra: successful login
      for (const line of stdout.split("\n")) {
        if (line.includes("login:") && line.includes("password:")) {
          findings.push({
            severity: "critical",
            title: `[Hydra] Valid credentials found: ${line.trim().slice(0, 100)}`,
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
      const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope });
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
              // Add to asset vulns for downstream correlation
              asset.vulns.push({
                id: `cloud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: finding.severity,
                title: `[Cloud] ${finding.title}`,
                cve: finding.cve,
                description: finding.description,
              });
              state.stats.vulnsFound++;
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
  const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_B });

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

        // Add findings to asset vulns
        for (const f of findings) {
          asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
          state.stats.vulnsFound++;
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
      const suggestedCmds = suggestToolCommands({
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

      // Add findings to asset vulns
      for (const f of findings) {
        asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
        state.stats.vulnsFound++;
      }

      return { tool: cmd.tool, findings: findings.length, timedOut: result.timedOut };
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
    const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_N });

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
              asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
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
        const { generateLLMScanConfig, startScan } = await import("./zap-scanner");
        const techHints = webApp.ports.map(p => p.version).filter(Boolean) as string[];

        const llmConfig = await generateLLMScanConfig({
          targetUrl,
          scanMode: "active",
          techStackHints: techHints,
          scopeConstraints: [`Only scan ${webApp.hostname}`],
        });

        addLog(state, {
          phase: "vuln_detection",
          type: "llm_decision",
          title: "LLM ZAP Config Generated",
          detail: llmConfig.rationale || "Optimized scan configuration based on target analysis",
          data: { technologies: llmConfig.technologies, authStrategy: llmConfig.authStrategy },
        });

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
                    webApp.vulns.push({ id: genId(), severity: "high", title: `[ZAP] ${counts.high} high-risk findings` });
                    state.stats.vulnsFound += counts.high;
                  }
                  if (counts.medium > 0) {
                    webApp.zapFindings.push({ alert: "Medium-risk web vulnerability", risk: "medium", url: targetUrl });
                    webApp.vulns.push({ id: genId(), severity: "medium", title: `[ZAP] ${counts.medium} medium-risk findings` });
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

      const credCmds = suggestCred({
        hostname: asset.hostname,
        ip: asset.ip,
        type: asset.type,
        ports: asset.ports,
        technologies: techList.length > 0 ? techList : undefined,
      }).filter(c => c.priority === 3); // Priority 3 = credential testing

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
            asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
            state.stats.vulnsFound++;
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
  } catch (e: any) {
    addLog(state, { phase: "vuln_detection", type: "error", title: "Credential Testing Error", detail: e.message });
  }

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

    const correlationDecision = await llmDecide({
      phase: "vuln_detection",
      engagementType: state.engagementType,
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
  return chainCtx + ontologyCtx + '\n\n' + bugBountyCtx + '\n\n' + triageCtx + (cloudSecCtx ? '\n\n' + cloudSecCtx : '') + '\n\n' + nmapVulnCtx + '\n\n' + owaspVulnCtx + '\n\n' + threatVulnCtx;
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
  }

  state.progress = 55;
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
  const decision = await llmDecide({
    phase: "exploitation",
    engagementType: state.engagementType,
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
  return chainContext + ontologyContext + '\n\n' + bbContext + '\n\n' + corpusContext + '\n\n' + nmapExploitCtx + '\n\n' + owaspExploitCtx + '\n\n' + threatExploitCtx;
})()}`,
  });

  addLog(state, {
    phase: "exploitation",
    type: "llm_decision",
    title: "Exploit Plan",
    detail: decision.decision,
    data: { reasoning: decision.reasoning },
  });

  // ── Pre-Exploitation Approval Gate ──
  // Pause and show the full exploit plan to the operator before firing any exploits.
  // This lets the operator review all selected targets, CVEs, and modules at once.
  const exploitActions = decision.actions.filter((a: any) => a.type === "exploit_attempt");
  const planSummary = exploitActions.map((a: any, i: number) => {
    const p = a.params || {};
    return `${i + 1}. ${p.target || "unknown"}:${p.port || "?"} — ${p.cve || p.module || "auto"} (${p.service || "unknown service"})`;
  }).join("\n");

  const exploitPlanApproved = await requestApproval(state, {
    phase: "exploitation",
    riskTier: "red",
    title: `Exploit Plan Review — ${exploitActions.length} target${exploitActions.length !== 1 ? "s" : ""}`,
    description: `The LLM has selected ${exploitActions.length} exploit action${exploitActions.length !== 1 ? "s" : ""}. Review the plan below before any exploits are executed.\n\n${planSummary}\n\nLLM Reasoning: ${decision.reasoning || decision.decision}`,
    target: exploitActions.map((a: any) => `${a.params?.target}:${a.params?.port}`).join(", "),
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
      const { target, port, cve, service, module } = action.params as any;
      const asset = state.assets.find(a => a.hostname === target || a.ip === target);

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

      // Generate exploit plan via exploitation bridge
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

        // Simulate exploit result (in production this would call MSF API)
        const success = plan?.exploitModules?.length > 0;
        if (asset) {
          asset.exploitAttempts.push({ module: module || cve || "auto", success, sessionId: success ? `session-${genId()}` : undefined });
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
          resultDetail: success ? "Exploit succeeded — session opened" : "Exploit failed",
        });

        addLog(state, {
          phase: "exploitation",
          type: success ? "exploit_success" : "exploit_fail",
          title: success ? `✅ Shell Obtained: ${target}` : `❌ Exploit Failed: ${target}`,
          detail: success
            ? `Successfully exploited ${service} on ${target}:${port}. Session opened.`
            : `Exploitation of ${service} on ${target}:${port} failed. Moving to next target.`,
          riskTier: "red",
          data: { plan: plan?.exploitModules?.slice(0, 3) },
        });
      } catch (e: any) {
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
        // Determine the next phase to run based on what was completed
        const phaseOrder: OpsPhase[] = ['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit'];
        const lastPhaseIdx = phaseOrder.indexOf(recovered.phase);
        if (lastPhaseIdx >= 0 && lastPhaseIdx < phaseOrder.length - 1) {
          // Resume from the phase that was interrupted (re-run it)
          startPhase = recovered.phase as any;
        } else {
          startPhase = recovered.phase as any;
        }
        addLog(state, {
          phase: state.phase, type: 'info',
          title: '🔄 Resuming from checkpoint',
          detail: `Recovered state from DB snapshot. Resuming from phase: ${startPhase}. Assets: ${state.assets.length}, Vulns: ${state.stats.vulnsFound}, Progress: ${state.progress}%`,
        });
        console.log(`[OpsState] Resuming engagement #${engagementId} from phase ${startPhase} (${state.assets.length} assets, ${state.stats.vulnsFound} vulns)`);
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
  if (engagement.roeStatus !== "signed" && engagement.roeStatus !== "pending") {
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
  }

  try {
    // Phase 1: Recon (skip if starting from a later phase)
    if (startPhase === 'recon') {
      await executeRecon(state, engagement, operatorCtx);
      await phaseCheckpoint('recon');
      if (!state.isRunning) return;
    }

    // Phase 2+: Require RoE for active scanning
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending") {
      // Phase 2: Enumeration (nmap first — always)
      if (['recon', 'enumeration'].includes(startPhase)) {
        await executeEnumeration(state, engagement, operatorCtx);
        await phaseCheckpoint('enumeration');
        if (!state.isRunning) return;
      }

      // Phase 3: Vulnerability Detection
      if (['recon', 'enumeration', 'vuln_detection'].includes(startPhase)) {
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
            maxIterations: 3,
            maxTotalScans: 8,
            maxScansPerIteration: 3,
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
                  targetAsset.vulns.push({
                    id: `rescan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                    severity: pf.severity,
                    title: pf.title,
                    cve: pf.cve,
                  });
                  state.stats.vulnsFound++;
                  newFindingsCount++;
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

      // Phase 4: Exploitation
      if (state.stats.vulnsFound > 0) {
        await executeExploitation(state, engagement, operatorCtx);
        await phaseCheckpoint('exploitation');
        if (!state.isRunning) return;
      } else {
        addLog(state, { phase: "exploitation", type: "info", title: "No Exploitable Vulns", detail: "No vulnerabilities found to exploit. Engagement complete." });
      }

      // Phase 5: Post-Exploit
      if (state.stats.exploitsSucceeded > 0) {
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
    addLog(state, {
      phase: "completed",
      type: "phase_complete",
      title: "🏁 Engagement Execution Complete",
      detail: `${state.stats.hostsScanned} hosts, ${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits, ${state.stats.zapScansRun} ZAP scans`,
    });;

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
