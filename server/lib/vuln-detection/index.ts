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
 *   - Shared helpers (addLog, broadcastOpsUpdate, persistOpsStateDebounced, etc.)
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
  state: EngagementOpsState;
  /** Engagement record from DB */
  engagement: any;
  /** Operator who triggered the engagement */
  operatorCtx: { id: string; name?: string };
  /** Scan server hostname */
  scanServerHost: string;
  /** Helper functions from the orchestrator */
  helpers: VulnDetectionHelpers;
}

/**
 * Helper functions injected from the orchestrator.
 * These are defined in the orchestrator but needed by sub-modules.
 */
export interface VulnDetectionHelpers {
  addLog: (state: EngagementOpsState, entry: Omit<OpsLogEntry, "id" | "timestamp">) => void;
  broadcastOpsUpdate: (engagementId: number, data: Record<string, any>) => void;
  pushVulnDeduped: (asset: any, vuln: any) => boolean;
  persistOpsStateDebounced: (engagementId: number, delayMs?: number) => void;
  persistScanResult: (opts: {
    engagementId: number;
    tool: string;
    target: string;
    rawOutput: string;
    parsedFindings?: any[];
    scanType?: string;
  }) => Promise<void>;
  executeToolViaQueue: typeof import("../job-queue-bridge").executeToolViaQueue;
  acquireScanSlot: typeof import("../scan-concurrency").acquireScanSlot;
  getScanConcurrencyMetrics: typeof import("../scan-concurrency").getScanConcurrencyMetrics;
  genId: () => string;
  breathe: () => Promise<void>;
  invokeLLM: typeof import("../../_core/llm").invokeLLM;
  throttledLLMCall: typeof import("../llm-throttle").throttledLLMCall;
}

// ─── Sub-Module Exports ──────────────────────────────────────────────────────

export { executeVulnPrep } from "./vuln-prep";
export { executeNucleiScanning } from "./nuclei-scanner";
export { executeZapScanning } from "./zap-scanner";
export { executeInjectionScanning } from "./injection-scanner";
export { executeCredentialTesting } from "./credential-tester";
export { executeVulnCorrelation } from "./vuln-correlation";
