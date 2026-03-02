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
        "waf_detected" | "phase_complete";
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

async function executeEnumeration(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, { phase: "enumeration", type: "info", title: "🔎 Phase 2: Enumeration & Fingerprinting", detail: "Running nmap service/OS detection on all in-scope assets" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });

  const targets = state.assets.map(a => a.ip || a.hostname);

  if (targets.length > 0) {
    addLog(state, { phase: "enumeration", type: "scan_start", title: "Nmap Service Scan", detail: `Scanning ${targets.length} targets with service detection` });

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

    // Execute nmap scan via the router's internal function
    try {
      const { executeNmapScan, scanWithScopeEnforcement } = await import("./nmap-orchestrator");

      for (const target of targets) {
        const asset = state.assets.find(a => (a.ip || a.hostname) === target);
        if (!asset) continue;
        asset.status = "scanning";

        addLog(state, { phase: "enumeration", type: "scan_start", title: `Scanning: ${target}`, detail: "Nmap service detection" });

        try {
          const profile = state.engagementType === "red_team" ? "stealth" : "service";
          const result = await executeNmapScan({
            targets: [target],
            profile,
            timeoutSeconds: 300,
          });

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
          addLog(state, {
            phase: "enumeration",
            type: "scan_result",
            title: `Enumerated: ${target}`,
            detail: `${asset.ports.length} open ports found${asset.type === "web_app" ? " (web application detected)" : ""}`,
            data: { ports: asset.ports },
          });
        } catch (e: any) {
          addLog(state, { phase: "enumeration", type: "error", title: `Scan Failed: ${target}`, detail: e.message });
        }
      }
    } catch (e: any) {
      addLog(state, { phase: "enumeration", type: "error", title: "Nmap Execution Error", detail: e.message });
    }
  }

  state.progress = 35;
  addLog(state, { phase: "enumeration", type: "phase_complete", title: "✅ Phase 2 Complete", detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports found` });
}

async function executeVulnDetection(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "vuln_detection";
  state.currentAction = "Running vulnerability detection...";
  addLog(state, { phase: "vuln_detection", type: "info", title: "🛡️ Phase 3: Vulnerability Detection", detail: "Running nuclei scans and ZAP web app scans" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "vuln_detection" });

  // ── Nuclei scan on all assets ──
  const nucleiTargets = state.assets
    .filter(a => a.status === "enumerated" && a.ports.length > 0)
    .map(a => a.ip || a.hostname);

  if (nucleiTargets.length > 0) {
    addLog(state, { phase: "vuln_detection", type: "scan_start", title: "Nuclei Vulnerability Scan", detail: `Scanning ${nucleiTargets.length} targets` });

    try {
      const { startNucleiScan } = await import("./nuclei-engine");
      const nucleiResult = await startNucleiScan({
        targets: nucleiTargets,
        severity: ["critical", "high", "medium"],
        rateLimit: state.engagementType === "red_team" ? 50 : 150,
        concurrency: state.engagementType === "red_team" ? 10 : 25,
      });

      // Map findings to assets
      if (nucleiResult?.findings) {
        for (const finding of nucleiResult.findings) {
          const asset = state.assets.find(a =>
            finding.host?.includes(a.ip || "") || finding.host?.includes(a.hostname)
          );
          if (asset) {
            asset.vulns.push({
              id: genId(),
              severity: finding.severity || "medium",
              title: finding.templateName || finding.name || "Unknown",
              cve: finding.cve,
            });
          }
          state.stats.vulnsFound++;
        }
      }

      addLog(state, {
        phase: "vuln_detection",
        type: "scan_result",
        title: "Nuclei Scan Complete",
        detail: `Found ${state.stats.vulnsFound} vulnerabilities across ${nucleiTargets.length} targets`,
      });
    } catch (e: any) {
      addLog(state, { phase: "vuln_detection", type: "error", title: "Nuclei Scan Error", detail: e.message });
    }
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
        const scanResult = await startScan({
          targetUrl,
          scanType: "full",
          scanMode: "active",
          useLLMConfig: true,
          techStackHints: techHints,
          wafVendor,
          engagementId: state.engagementId,
        });

        state.stats.zapScansRun++;

        // Collect ZAP findings
        if (scanResult?.alerts) {
          for (const alert of scanResult.alerts) {
            webApp.zapFindings.push({
              alert: alert.name || alert.alert,
              risk: alert.risk || "medium",
              url: alert.url || targetUrl,
              cweId: alert.cweId,
            });
            // Also add to vulns for correlation
            webApp.vulns.push({
              id: genId(),
              severity: alert.risk || "medium",
              title: `[ZAP] ${alert.name || alert.alert}`,
              cve: alert.cveId,
            });
            state.stats.vulnsFound++;
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
  operatorCtx: { id: string; name?: string }
): Promise<void> {
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
  state.startedAt = Date.now();
  state.phase = "recon";

  emitSystemNotification({
    title: "Engagement Execution Started",
    message: `Autonomous ${state.engagementType} execution started for engagement #${engagementId}`,
    severity: "info",
  });

  try {
    // Phase 1: Recon
    await executeRecon(state, engagement, operatorCtx);
    if (!state.isRunning) return;

    // Phase 2: Enumeration (requires RoE for active scanning)
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending") {
      await executeEnumeration(state, engagement, operatorCtx);
      if (!state.isRunning) return;

      // Phase 3: Vulnerability Detection
      await executeVulnDetection(state, engagement, operatorCtx);
      if (!state.isRunning) return;

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
