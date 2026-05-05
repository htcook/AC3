/**
 * Vulnerability Detection Phase (Phase 6) — Extracted Module
 *
 * This module decomposes the monolithic executeVulnDetection function (~3,950 lines)
 * into logical sub-modules for maintainability:
 *
 *   1. vuln-prep.ts       — Passive vuln promotion, taxonomy enrichment, tech detection, stack profile
 *   2. nuclei-scanner.ts  — Nuclei template scanning via scan server (RoE-scoped)
 *   3. zap-scanner.ts     — ZAP web application scanning (WAF-aware, RoE-scoped)
 *   4. injection-scanner.ts — SQLMap, XSStrike, Commix, tplmap injection testing
 *   5. credential-tester.ts — Hydra credential testing on login services
 *   6. vuln-correlation.ts — LLM correlation, specialist pipelines, dedup, coverage gap analysis
 *
 * Each sub-module receives a VulnDetectionContext that provides access to:
 *   - EngagementOpsState (the mutable state object)
 *   - Shared helpers (addLog, broadcastOpsUpdate, persistScanResult, etc.)
 *   - Engagement metadata
 *   - Operator context
 *
 * The orchestrator's executeVulnDetection function becomes a thin dispatcher
 * that calls each sub-module in sequence.
 */

import type { EngagementOpsState, OpsLogEntry } from "../../../shared/orchestrator-types";

// ─── Shared Context for Sub-Modules ──────────────────────────────────────────

/**
 * Context object passed to each Phase 6 sub-module.
 * Provides access to state, helpers, and engagement metadata without
 * requiring each sub-module to import the entire orchestrator.
 */
export interface VulnDetectionContext {
  /** Mutable engagement operations state */
  state: EngagementOpsState & { [key: string]: any };
  /** Engagement record from DB */
  engagement: any;
  /** Operator who triggered the engagement */
  operatorCtx: { id: string; name?: string };
  /** Scan server hostname */
  scanServerHost: string;

  // ─── Helper Functions (injected from orchestrator) ───────────────────────

  /** Add a log entry to the engagement state */
  addLog: (state: any, entry: Omit<OpsLogEntry, "id" | "timestamp"> & { [key: string]: any }) => void;
  /** Broadcast real-time update to connected clients */
  broadcastOpsUpdate: (engagementId: number, data: Record<string, any>) => void;
  /** Broadcast a recon finding to connected clients */
  broadcastReconFinding: (engagementId: number, finding: any) => void;
  /** Push a vulnerability finding with dedup check */
  pushVulnDeduped: (asset: any, vuln: any) => boolean;
  /** Debounced persistence of engagement state */
  persistOpsStateDebounced: (engagementId: number, delayMs?: number) => void;
  /** Persist scan result to database */
  persistScanResult: (opts: any) => Promise<void>;
  /** Execute a tool via the job queue bridge */
  executeToolViaQueue: (config: any, opts?: any) => Promise<any>;
  /** Acquire a concurrency slot for scanning */
  acquireScanSlot: (opts?: any) => Promise<any>;
  /** Get scan concurrency metrics */
  getScanConcurrencyMetrics: () => any;
  /** Generate a unique ID */
  genId: () => string;
  /** Yield to event loop (memory backpressure) */
  breathe: () => Promise<void>;
  /** Invoke LLM for decisions */
  invokeLLM: (opts: any) => Promise<any>;
  /** Throttled LLM call */
  throttledLLMCall: (opts: any) => Promise<any>;
  /** Parse tool output into findings */
  parseToolOutput: (tool: string, stdout: string, asset: any) => any[];
  /** Check if target is in RoE scope */
  isInRoeScope: (state: any, hostname: string, ip?: string) => boolean;
  /** Request operator approval for risky actions */
  requestApproval: (state: any, opts: any) => Promise<boolean>;
  /** Get effective target (IP or hostname based on context) */
  getEffectiveTarget: (asset: any, context: string) => string;
  /** Format target for display */
  fmtTarget: (asset: any) => string;
  /** LLM decision helper */
  llmDecide: (opts: any) => Promise<any>;
  /** Capture training decision */
  captureDecision: (opts: any) => Promise<void>;
  /** Score engagement threat attribution */
  scoreEngagementThreatAttribution: (opts: any) => Promise<any>;
  /** Get abort signal for an engagement (cancellation support) */
  getEngagementAbortSignal: (engagementId: number) => AbortSignal;
  /** Execute ScanForge phase (optional — only available when ScanForge is enabled) */
  executeScanForgePhase?: (...args: any[]) => Promise<any>;
  /** Burp Suite app login credentials (from vuln-prep) */
  burpAppLogin?: { username: string; password: string; loginUrl?: string };
  /** Initial ZAP→Burp pipeline result (from vuln-prep) */
  initialPipelineResult?: any;

  // ─── Legacy helpers pattern (used by vuln-prep.ts) ───────────────────────
  helpers?: {
    addLog: (state: any, entry: any) => void;
    broadcastOpsUpdate: (engagementId: number, data: any) => void;
    pushVulnDeduped: (asset: any, vuln: any) => boolean;
    persistOpsStateDebounced: (engagementId: number, delayMs?: number) => void;
    persistScanResult: (opts: any) => Promise<void>;
    executeToolViaQueue: (config: any, opts?: any) => Promise<any>;
    acquireScanSlot: (opts?: any) => Promise<any>;
    getScanConcurrencyMetrics: () => any;
    genId: () => string;
    breathe: () => Promise<void>;
    invokeLLM: (opts: any) => Promise<any>;
    throttledLLMCall: (opts: any) => Promise<any>;
  };

  /** Allow additional properties for forward compatibility */
  [key: string]: any;
}

// ─── Sub-Module Exports ──────────────────────────────────────────────────────

export { executeVulnPrep } from "./vuln-prep";
export { executeNucleiScanning } from "./nuclei-scanner";
export { executeZapScanning } from "./zap-scanner";
export { executeInjectionScanning } from "./injection-scanner";
export { executeCredentialTesting } from "./credential-tester";
export { executeVulnCorrelation } from "./vuln-correlation";
