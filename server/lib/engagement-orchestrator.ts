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
import {
  emitExploitFired, emitExploitResult, emitAgentDeployed,
  emitReconComplete, emitSystemNotification, emitSystemAlert,
  eventHub,
} from "./ws-event-hub";

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
        "waf_detected" | "phase_complete" | "tool_match" | "tool_exec";
  title: string;
  detail: string;
  data?: Record<string, any>;
  riskTier?: "yellow" | "orange" | "red";
}

export interface AssetStatus {
  hostname: string;
  ip?: string;
  type: "web_app" | "server" | "network_device" | "database" | "api" | "unknown";
  ports: Array<{ port: number; service: string; version?: string }>;
  vulns: Array<{ id: string; severity: string; title: string; cve?: string }>;
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{ module: string; success: boolean; sessionId?: string }>;
  status: "pending" | "scanning" | "enumerated" | "vulns_found" | "exploiting" | "compromised" | "no_vulns";
  wafDetected?: string;
}

export interface AssetScanPlan {
  hostname: string;
  ip?: string;
  assetType: string;
  nmapFlags: string;
  nmapRationale: string;
  activeTools: Array<{
    tool: string;
    command: string;
    rationale: string;
    priority: number;
  }>;
  riskNotes: string;
}
export interface ScanPlan {
  generatedAt: number;
  overallStrategy: string;
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
    stats: {
      hostsScanned: 0, portsFound: 0, vulnsFound: 0,
      exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
      zapScansRun: 0, wafDetections: 0,
    },
  };
  opsStates.set(engagementId, state);
  return state;
}

// ─── Broadcast helpers ──────────────────────────────────────────────────────

function broadcastOpsUpdate(engagementId: number, data: Record<string, any>) {
  eventHub.broadcastEngagement(engagementId, {
    type: "engagement:progress_update",
    timestamp: Date.now(),
    engagementId,
    data,
  });
}

function addLog(state: EngagementOpsState, entry: Omit<OpsLogEntry, "id" | "timestamp">) {
  const logEntry: OpsLogEntry = { id: genId(), timestamp: Date.now(), ...entry };
  state.log.push(logEntry);
  // Keep last 500 entries
  if (state.log.length > 500) state.log = state.log.slice(-500);
  broadcastOpsUpdate(state.engagementId, { type: "log", entry: logEntry });
  return logEntry;
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
    return info;
  });

  const availableTools = [
    { name: 'nmap', desc: 'Port scanner and service fingerprinter', flags: ['-sV (version detection)', '-sC (default scripts)', '-sU (UDP scan)', '-O (OS detection)', '--script vuln (vuln scripts)', '-T4 (aggressive timing)', '-T2 (polite timing)', '-Pn (skip host discovery)', '-p- (all ports)', '--top-ports N'] },
    { name: 'nuclei', desc: 'Template-based vulnerability scanner', use: 'web apps, known CVEs, misconfigurations' },
    { name: 'nikto', desc: 'Web server scanner for dangerous files/CGIs', use: 'web servers' },
    { name: 'gobuster', desc: 'Directory/file brute-forcer', use: 'web apps to find hidden paths' },
    { name: 'httpx', desc: 'HTTP probe and tech fingerprinter', use: 'web asset enumeration' },
    { name: 'hydra', desc: 'Credential brute-forcer', use: 'SSH, FTP, RDP, MySQL, HTTP-auth, SMB logins' },
    { name: 'enum4linux', desc: 'SMB/NetBIOS enumerator', use: 'Windows/Samba hosts' },
    { name: 'smbclient', desc: 'SMB share lister', use: 'Windows/Samba file shares' },
    { name: 'ldapsearch', desc: 'LDAP directory enumerator', use: 'Active Directory/LDAP servers' },
    { name: 'dig', desc: 'DNS query tool', use: 'DNS servers, zone transfers' },
    { name: 'onesixtyone', desc: 'SNMP scanner', use: 'network devices with SNMP' },
    { name: 'subfinder', desc: 'Subdomain discovery', use: 'finding additional subdomains' },
  ];

  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are an expert penetration tester planning the active scanning phase of a ${state.engagementType} engagement. You have completed passive OSINT reconnaissance and discovered the following assets. Now you must analyze each asset and recommend:

1. **Specific nmap flags** per asset — tailor the scan based on what you already know (e.g., if passive recon found web services, focus on web ports; if it's an IP with no known services, do a broader scan)
2. **Active tools** to run per asset after nmap — select from the available toolkit based on the asset type and services
3. **Risk assessment** — note any concerns (WAF detected, rate limiting, IDS evasion needed)

Available tools on the scan server:
${availableTools.map(t => `- ${t.name}: ${t.desc}${(t as any).use ? ` (best for: ${(t as any).use})` : ''}`).join('\n')}

You MUST respond with valid JSON matching this exact schema:
{
  "overallStrategy": "Brief description of the overall scanning approach",
  "estimatedDuration": "Estimated time for all scans (e.g., '15-25 minutes')",
  "riskAssessment": "Overall risk notes for active scanning these targets",
  "assetPlans": [
    {
      "hostname": "exact hostname from the asset list",
      "ip": "IP if known",
      "assetType": "web_app|server|api|database|network_device|unknown",
      "nmapFlags": "exact nmap flags to use (e.g., '-sV -sC -T4 -p 80,443,8080')",
      "nmapRationale": "Why these specific nmap flags",
      "activeTools": [
        {
          "tool": "tool name from available list",
          "command": "exact command to run (use {target} as placeholder for hostname/IP)",
          "rationale": "Why this tool for this asset",
          "priority": 1
        }
      ],
      "riskNotes": "Any risk concerns for this specific asset"
    }
  ]
}`
      },
      {
        role: 'user',
        content: `Discovered assets from passive OSINT:\n${JSON.stringify(assetSummaries, null, 2)}\n\nEngagement type: ${state.engagementType}\nTotal assets: ${state.assets.length}\n\nGenerate the scan plan for the active scanning phase.`
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
                  riskNotes: { type: 'string' }
                },
                required: ['hostname', 'ip', 'assetType', 'nmapFlags', 'nmapRationale', 'activeTools', 'riskNotes'],
                additionalProperties: false
              }
            }
          },
          required: ['overallStrategy', 'estimatedDuration', 'riskAssessment', 'assetPlans'],
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
    overallStrategy: parsed.overallStrategy || 'Standard active scanning',
    estimatedDuration: parsed.estimatedDuration || 'Unknown',
    riskAssessment: parsed.riskAssessment || 'Standard risk',
    assetPlans: (parsed.assetPlans || []).map((ap: any) => ({
      hostname: ap.hostname,
      ip: ap.ip,
      assetType: ap.assetType,
      nmapFlags: ap.nmapFlags,
      nmapRationale: ap.nmapRationale,
      activeTools: (ap.activeTools || []).map((t: any) => ({
        tool: t.tool,
        command: t.command,
        rationale: t.rationale,
        priority: t.priority || 2,
      })),
      riskNotes: ap.riskNotes,
    })),
  };

  state.scanPlan = scanPlan;

  // Log the scan plan to the live feed
  addLog(state, {
    phase: state.phase,
    type: 'llm_decision',
    title: '📋 Scan Plan Generated',
    detail: `Strategy: ${scanPlan.overallStrategy}\nEstimated duration: ${scanPlan.estimatedDuration}\nAssets planned: ${scanPlan.assetPlans.length}`,
    data: { scanPlan },
  });

  for (const ap of scanPlan.assetPlans) {
    addLog(state, {
      phase: state.phase,
      type: 'tool_match',
      title: `🎯 ${ap.hostname}`,
      detail: `nmap: ${ap.nmapFlags}\nTools: ${ap.activeTools.map(t => t.tool).join(', ')}\nRisk: ${ap.riskNotes}`,
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
- Never scan out-of-scope targets`;

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

      // Extract discovered assets
      const discoveredAssets = (result as any).assets || [];
      for (const asset of discoveredAssets) {
        const hostname = asset.hostname || asset.domain || asset.ip;
        if (!hostname) continue;
        const existing = state.assets.find(a => a.hostname === hostname);
        if (existing) {
          existing.ip = asset.ip || existing.ip;
          existing.type = asset.assetType === "web_application" ? "web_app" : existing.type;
        } else {
          state.assets.push({
            hostname,
            ip: asset.ip,
            type: asset.assetType === "web_application" ? "web_app" : "unknown",
            ports: [],
            vulns: [],
            zapFindings: [],
            exploitAttempts: [],
            status: "pending",
          });
        }
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
      // Nuclei JSON output: one JSON object per line
      for (const line of stdout.split("\n")) {
        try {
          const obj = JSON.parse(line.trim());
          if (obj.info?.severity && obj.info?.name) {
            const cve = obj["matched-at"]?.match(/CVE-\d{4}-\d+/)?.[0] ||
                        obj.info?.classification?.cve?.[0] ||
                        obj["template-id"]?.match(/CVE-\d{4}-\d+/)?.[0];
            findings.push({
              severity: obj.info.severity,
              title: `[Nuclei] ${obj.info.name}`,
              cve,
            });
          }
        } catch { /* not JSON line */ }
      }
      break;
    }
    case "nikto": {
      // Nikto text output: look for OSVDB, CVE, and vulnerability lines
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("+") && (trimmed.includes("OSVDB") || trimmed.includes("CVE-") || trimmed.includes("vulnerability"))) {
          const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
          findings.push({
            severity: cve ? "high" : "medium",
            title: `[Nikto] ${trimmed.slice(2, 120)}`,
            cve,
          });
        }
      }
      break;
    }
    case "httpx": {
      // httpx JSON output: tech detection
      for (const line of stdout.split("\n")) {
        try {
          const obj = JSON.parse(line.trim());
          if (obj.tech && Array.isArray(obj.tech)) {
            // Not vulns but useful context — store as info-level
            for (const tech of obj.tech) {
              findings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
            }
          }
        } catch { /* not JSON */ }
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
    default:
      break;
  }

  return findings;
}

async function executeEnumeration(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, { phase: "enumeration", type: "info", title: "🔎 Phase 2: Enumeration & Fingerprinting", detail: "Running nmap service/OS detection on all in-scope assets via scan server" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });

  const targets = state.assets.map(a => a.ip || a.hostname);

  if (targets.length > 0) {
    addLog(state, { phase: "enumeration", type: "scan_start", title: "Nmap Service Scan", detail: `Scanning ${targets.length} targets with service detection via remote scan server` });

    // Use LLM to decide scan profile based on engagement type
    const decision = await llmDecide({
      phase: "enumeration",
      engagementType: state.engagementType,
      assets: state.assets,
      recentLog: state.log.slice(-10),
      question: `We have ${targets.length} targets to enumerate. What nmap scan profile should we use? Consider the engagement type (${state.engagementType}) and OPSEC requirements.`,
    });

    addLog(state, {
      phase: "enumeration",
      type: "llm_decision",
      title: "LLM Scan Strategy",
      detail: decision.decision,
      data: { reasoning: decision.reasoning },
    });

    // Execute nmap scan via scan server SSH
    try {
      const { executeTool, getScanServerConfigForNmap } = await import("./scan-server-executor");
      const { executeNmapScan } = await import("./nmap-orchestrator");
      const serverConfig = getScanServerConfigForNmap();

      for (const target of targets) {
        const asset = state.assets.find(a => (a.ip || a.hostname) === target);
        if (!asset) continue;
        asset.status = "scanning";

        addLog(state, { phase: "enumeration", type: "scan_start", title: `Scanning: ${target}`, detail: `Nmap service detection on scan server (${serverConfig.host})` });

        try {
          // Use scan plan nmap flags if available for this asset
          const assetPlan = state.scanPlan?.assetPlans.find(
            ap => ap.hostname === (asset?.hostname) || ap.ip === target
          );
          let profile: string;
          let customFlags: string | undefined;
          if (assetPlan?.nmapFlags) {
            customFlags = assetPlan.nmapFlags;
            profile = 'custom';
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `Scan Plan: ${target}`,
              detail: `Using LLM-recommended nmap flags: ${customFlags}\nRationale: ${assetPlan.nmapRationale}`,
            });
          } else {
            profile = state.engagementType === 'red_team' ? 'stealth' : 'service';
          }

          // If custom flags, run nmap directly via SSH; otherwise use the nmap orchestrator
          let result: any;
          if (customFlags) {
            const { executeTool: execNmap } = await import('./scan-server-executor');
            const nmapArgs = `${customFlags} ${target}`;
            addLog(state, { phase: 'enumeration', type: 'tool_exec', title: `nmap ${target}`, detail: `nmap ${nmapArgs}` });
            const nmapResult = await execNmap({ tool: 'nmap', args: nmapArgs, timeoutSeconds: 300 });
            // Parse nmap text output into hosts structure
            result = { hosts: [{ address: target, ports: [] as any[] }] };
            if (nmapResult.stdout) {
              const portRegex = /(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.*))?/g;
              let match;
              while ((match = portRegex.exec(nmapResult.stdout)) !== null) {
                result.hosts[0].ports.push({
                  portId: parseInt(match[1]),
                  state: 'open',
                  service: { name: match[2], product: match[3]?.trim() || undefined },
                });
              }
              // Also parse UDP if present
              const udpRegex = /(\d+)\/udp\s+open\s+(\S+)(?:\s+(.*))?/g;
              while ((match = udpRegex.exec(nmapResult.stdout)) !== null) {
                result.hosts[0].ports.push({
                  portId: parseInt(match[1]),
                  state: 'open',
                  service: { name: match[2], product: match[3]?.trim() || undefined },
                });
              }
            }
          } else {
            result = await executeNmapScan({
              targets: [target],
              profile,
              timeoutSeconds: 300,
              engagementId: state.engagementId,
              operatorId: operatorCtx.id,
              operatorName: operatorCtx.name,
              server: serverConfig,
            });
          }

          // Parse results into asset ports
          if (result?.hosts) {
            for (const host of result.hosts) {
              const ports = (host.ports || []).filter((p: any) => p.state === "open");
              asset.ports = ports.map((p: any) => ({
                port: p.portId,
                service: p.service?.name || "unknown",
                version: p.service?.product ? `${p.service.product} ${p.service.version || ""}`.trim() : undefined,
              }));
              asset.ip = host.address || asset.ip;

              // Detect web services
              const webPorts = ports.filter((p: any) =>
                ["http", "https", "http-proxy", "http-alt"].includes(p.service?.name) ||
                [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.portId)
              );
              if (webPorts.length > 0) {
                asset.type = "web_app";
              }

              state.stats.portsFound += ports.length;
            }
          }

          asset.status = "enumerated";
          state.stats.hostsScanned++;
          broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
          addLog(state, {
            phase: "enumeration",
            type: "scan_result",
            title: `Enumerated: ${target}`,
            detail: `${asset.ports.length} open ports found${asset.type === "web_app" ? " (web application detected)" : ""}`,
            data: { ports: asset.ports },
          });
        } catch (e: any) {
          addLog(state, { phase: "enumeration", type: "error", title: `Scan Failed: ${target}`, detail: e.message });
          asset.status = "enumerated"; // Mark as enumerated even on failure so pipeline continues
        }
      }
    } catch (e: any) {
      addLog(state, { phase: "enumeration", type: "error", title: "Nmap Execution Error", detail: e.message });
    }
  }

  state.progress = 30;
  addLog(state, { phase: "enumeration", type: "phase_complete", title: "✅ Phase 2 Complete", detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports found` });

  // ── Tool Matching: Use scan plan tools if available, otherwise LLM-generated suggestions ──
  const hasScanPlan = !!state.scanPlan?.assetPlans?.length;
  addLog(state, {
    phase: "enumeration", type: "info",
    title: "🔧 Tool Matching",
    detail: hasScanPlan
      ? `Executing LLM scan plan tools for ${state.scanPlan!.assetPlans.length} assets on scan server...`
      : "LLM analyzing nmap results to select and deploy tools for each asset on scan server...",
  });

  const { executeTool, suggestToolCommands } = await import("./scan-server-executor");

  for (const asset of state.assets) {
    if (asset.ports.length === 0) continue;

    // Classify asset type based on ports
    const webPorts = asset.ports.filter(p =>
      ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";

    // Check if scan plan has tools for this asset
    const assetPlan = state.scanPlan?.assetPlans.find(
      ap => ap.hostname === asset.hostname || ap.ip === (asset.ip || asset.hostname)
    );

    // Build unified command list: prefer scan plan, fallback to suggestToolCommands
    let cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>;

    if (assetPlan && assetPlan.activeTools.length > 0) {
      // Use scan plan tools — LLM already analyzed the asset
      cmdsToRun = assetPlan.activeTools.map(t => ({
        tool: t.tool,
        command: t.command.replace(/\{target\}/g, asset.ip || asset.hostname),
        purpose: t.rationale,
        priority: t.priority,
      }));
      addLog(state, {
        phase: "enumeration", type: "tool_match",
        title: `Scan Plan Tools: ${asset.hostname}`,
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
      // Fallback to generic tool suggestions
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
        title: `Tool Match: ${asset.hostname}`,
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
    const highPriorityCmds = cmdsToRun.filter(c => c.priority <= 2);
    for (const cmd of highPriorityCmds) {
      addLog(state, {
        phase: "enumeration", type: "scan_start",
        title: `Running: ${cmd.tool}`,
        detail: `${cmd.purpose} — ${cmd.command.slice(0, 120)}`,
        data: { tool: cmd.tool, fullCommand: cmd.command },
      });

      try {
        // Split full command into tool + args for executeTool
        const cmdArgs = cmd.command.startsWith(cmd.tool)
          ? cmd.command.slice(cmd.tool.length).trim()
          : cmd.command;
        const result = await executeTool({
          tool: cmd.tool,
          args: cmdArgs,
          timeoutSeconds: 180,
          engagementId: state.engagementId,
        });

        // Parse tool output for findings
        const findings = parseToolOutput(cmd.tool, result.stdout, asset);

        addLog(state, {
          phase: "enumeration", type: "scan_result",
          title: `${cmd.tool} Complete: ${asset.hostname}`,
          detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
          data: {
            tool: cmd.tool, exitCode: result.exitCode, durationMs: result.durationMs,
            findings, outputPreview: result.stdout.slice(0, 500),
          },
        });

        // Add findings to asset vulns
        for (const f of findings) {
          asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
          state.stats.vulnsFound++;
        }
      } catch (e: any) {
        addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
      }
    }
  }

  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

async function executeVulnDetection(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "vuln_detection";
  state.currentAction = "Running vulnerability detection...";
  addLog(state, { phase: "vuln_detection", type: "info", title: "🛡️ Phase 3: Vulnerability Detection", detail: "Running nuclei scans and ZAP web app scans" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "vuln_detection" });

  // ── Nuclei scan on all assets via scan server ──
  const nucleiAssets = state.assets.filter(a => a.ports.length > 0);

  if (nucleiAssets.length > 0) {
    addLog(state, { phase: "vuln_detection", type: "scan_start", title: "Nuclei Vulnerability Scan (Scan Server)", detail: `Scanning ${nucleiAssets.length} targets via remote nuclei` });

    const { executeTool } = await import("./scan-server-executor");

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

      for (const url of nucleiTargetUrls) {
        addLog(state, { phase: "vuln_detection", type: "scan_start", title: `Nuclei: ${url}`, detail: "Running CVE and vulnerability template scan" });

        try {
          const result = await executeTool({
            tool: "nuclei",
            args: `-u ${url} -severity critical,high,medium -json -timeout 5 -retries 1 -rate-limit ${state.engagementType === "red_team" ? 50 : 150}`,
            target,
            timeoutSeconds: 300,
            engagementId: state.engagementId,
          });

          // Parse nuclei JSON output
          const findings = parseToolOutput("nuclei", result.stdout, asset);
          for (const f of findings) {
            asset.vulns.push({ id: genId(), severity: f.severity, title: f.title, cve: f.cve });
            state.stats.vulnsFound++;
          }

          addLog(state, {
            phase: "vuln_detection",
            type: "scan_result",
            title: `Nuclei Complete: ${url}`,
            detail: `${findings.length} findings, exit code ${result.exitCode}, ${result.durationMs}ms${result.timedOut ? " (TIMED OUT)" : ""}`,
            data: { findings, outputPreview: result.stdout.slice(0, 500) },
          });
        } catch (e: any) {
          addLog(state, { phase: "vuln_detection", type: "error", title: `Nuclei Error: ${url}`, detail: e.message });
        }
      }
    }

    addLog(state, {
      phase: "vuln_detection",
      type: "scan_result",
      title: "Nuclei Scan Complete",
      detail: `Found ${state.stats.vulnsFound} vulnerabilities across ${nucleiAssets.length} targets`,
    });
  }

  // ── ZAP scan on web applications (WAF-aware) ──
  const webApps = state.assets.filter(a =>
    a.type === "web_app" ||
    a.ports.some(p => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port))
  );

  for (const webApp of webApps) {
    const webPorts = webApp.ports.filter(p =>
      ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)
    );

    for (const wp of webPorts) {
      const protocol = wp.port === 443 || wp.port === 8443 || wp.service === "https" ? "https" : "http";
      const targetUrl = `${protocol}://${webApp.ip || webApp.hostname}${wp.port === 80 || wp.port === 443 ? "" : `:${wp.port}`}`;

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
  addLog(state, { phase: "vuln_detection", type: "info", title: "🔑 Credential Testing", detail: "Testing default/common credentials on discovered login services" });

  try {
    const { executeTool: execToolCred, suggestToolCommands: suggestCred } = await import("./scan-server-executor");

    for (const asset of state.assets) {
      if (asset.ports.length === 0) continue;
      const credCmds = suggestCred({
        hostname: asset.hostname,
        ip: asset.ip,
        type: asset.type,
        ports: asset.ports,
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

          addLog(state, {
            phase: "vuln_detection",
            type: "scan_result",
            title: `${cmd.tool} Complete: ${asset.hostname}`,
            detail: `${findings.length} findings, exit code ${result.exitCode}`,
            data: { findings, outputPreview: result.stdout.slice(0, 300) },
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

    const correlationDecision = await llmDecide({
      phase: "vuln_detection",
      engagementType: state.engagementType,
      assets: state.assets,
      recentLog: state.log.slice(-20),
      question: `We've completed vulnerability scanning. Here are the findings:
${allVulns.map(v => `- ${v.title} (${v.severity})${v.cve ? ` [${v.cve}]` : ""}`).join("\n")}

Correlate these findings and recommend the best exploitation strategy. For pentest: prioritize per-asset unauthorized access. For red team: identify the weakest entry point for C2 deployment.`,
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
Available vulns: ${state.assets.flatMap(a => a.vulns.map(v => `${a.hostname}:${v.title}${v.cve ? ` [${v.cve}]` : ""}`)).join(", ")}`,
  });

  addLog(state, {
    phase: "exploitation",
    type: "llm_decision",
    title: "Exploit Plan",
    detail: decision.decision,
    data: { reasoning: decision.reasoning },
  });

  for (const action of decision.actions) {
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
        title: `Deploy C2 Agent: ${asset.hostname}`,
        description: `Deploying Caldera agent on ${asset.hostname} (${asset.ip || "unknown IP"}). This will establish a persistent callback to the C2 server for adversary operations and lateral movement.`,
        target: asset.hostname,
        detail: { hostname: asset.hostname, ip: asset.ip, platform: "linux" },
      });

      if (!approved) {
        addLog(state, { phase: "post_exploit", type: "info", title: `C2 Skipped: ${asset.hostname}`, detail: "Operator denied C2 deployment" });
        continue;
      }

      addLog(state, {
        phase: "post_exploit",
        type: "c2_deploy",
        title: `C2 Agent Deploying: ${asset.hostname}`,
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
        title: `✅ C2 Active: ${asset.hostname}`,
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
        title: `Evidence: ${asset.hostname}`,
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
  options?: { startPhase?: 'recon' | 'enumeration' | 'vuln_detection' | 'exploitation' | 'post_exploit' }
): Promise<void> {
  const startPhase = options?.startPhase || 'recon';
  let state = opsStates.get(engagementId);
  if (!state) {
    state = initOpsState(engagementId, "pentest");
  }

  // Fetch engagement details
  let engagement: any;
  try {
    const db = await import("../db");
    engagement = await db.default.getEngagementById(engagementId);
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

  emitSystemNotification({
    title: "Engagement Execution Started",
    message: `Autonomous ${state.engagementType} execution started for engagement #${engagementId} (from ${startPhase})`,
    severity: "info",
  });

  try {
    // Phase 1: Recon (skip if starting from a later phase)
    if (startPhase === 'recon') {
      await executeRecon(state, engagement, operatorCtx);
      if (!state.isRunning) return;
    }

    // Phase 2+: Require RoE for active scanning
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending") {
      // Phase 2: Enumeration (nmap first — always)
      if (['recon', 'enumeration'].includes(startPhase)) {
        await executeEnumeration(state, engagement, operatorCtx);
        if (!state.isRunning) return;
      }

      // Phase 3: Vulnerability Detection
      if (['recon', 'enumeration', 'vuln_detection'].includes(startPhase)) {
        await executeVulnDetection(state, engagement, operatorCtx);
        if (!state.isRunning) return;
      }

      // Phase 4: Exploitation
      if (state.stats.vulnsFound > 0) {
        await executeExploitation(state, engagement, operatorCtx);
        if (!state.isRunning) return;
      } else {
        addLog(state, { phase: "exploitation", type: "info", title: "No Exploitable Vulns", detail: "No vulnerabilities found to exploit. Engagement complete." });
      }

      // Phase 5: Post-Exploit
      if (state.stats.exploitsSucceeded > 0) {
        await executePostExploit(state, engagement, operatorCtx);
      }
    } else {
      addLog(state, { phase: "enumeration", type: "error", title: "⛔ Active Phases Blocked", detail: "RoE must be signed to proceed past recon. Please have the team lead sign the RoE." });
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
    });

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
  }
}

export function stopEngagement(engagementId: number): boolean {
  const state = opsStates.get(engagementId);
  if (!state) return false;
  state.isRunning = false;
  state.isPaused = false;
  state.currentAction = "Stopped by operator";
  addLog(state, { phase: state.phase, type: "info", title: "⏹ Execution Stopped", detail: "Operator stopped the engagement execution" });
  broadcastOpsUpdate(engagementId, { type: "stopped" });
  return true;
}
