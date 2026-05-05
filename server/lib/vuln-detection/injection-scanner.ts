/**
 * Vulnerability Detection — Injection Scanners
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 5761-6345).
 *
 * Responsibilities:
 *   - SQLMap: SQL injection testing on discovered web app parameters
 *   - XSStrike: Cross-site scripting (XSS) testing
 *   - Commix: OS command injection testing
 *   - tplmap: Server-side template injection (SSTI) testing
 *   - Parse and normalize injection findings
 *   - Persist scan results to DB
 *
 * NOTE: This is a delegation stub. The actual implementation remains in the
 * orchestrator until the full extraction is complete.
 */

import type { VulnDetectionContext } from "./index";

export interface InjectionScanResult {
  /** Total SQL injection findings */
  sqlInjectionFindings: number;
  /** Total XSS findings */
  xssFindings: number;
  /** Total command injection findings */
  commandInjectionFindings: number;
  /** Total SSTI findings */
  sstiFindings: number;
  /** Number of endpoints tested */
  endpointsTested: number;
}

/**
 * Execute injection scanning (SQLMap, XSStrike, Commix, tplmap) on discovered web apps.
 *
 * This is currently a delegation stub — the actual implementation
 * remains inline in the orchestrator.
 *
 * @param ctx - Shared vulnerability detection context
 * @returns Injection scan results summary
 */
export async function executeInjectionScanning(ctx: VulnDetectionContext): Promise<InjectionScanResult> {
  throw new Error(
    "[InjectionScanner] This stub should not be called directly. " +
    "The orchestrator still executes injection scanning inline until full extraction is complete."
  );
}
