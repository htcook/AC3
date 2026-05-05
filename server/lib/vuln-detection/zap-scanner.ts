/**
 * Vulnerability Detection — ZAP Web Application Scanner
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 4771-5760).
 *
 * Responsibilities:
 *   - Execute ZAP active/passive scans on web applications
 *   - WAF detection and evasion strategy selection
 *   - RoE scope enforcement for all targets
 *   - Authenticated scanning with harvested/training lab credentials
 *   - Parse and normalize ZAP findings
 *   - Deferred ZAP → Burp re-feed after ZAP completes
 *   - Persist scan results to DB
 *
 * NOTE: This is a delegation stub. The actual implementation remains in the
 * orchestrator until the full extraction is complete.
 */

import type { VulnDetectionContext } from "./index";

export interface ZapScanResult {
  /** Total findings from ZAP scanning */
  findingsCount: number;
  /** Number of web apps scanned */
  webAppsScanned: number;
  /** Number of WAFs detected */
  wafDetections: number;
  /** Whether deferred ZAP→Burp re-feed was triggered */
  deferredRefeedTriggered: boolean;
}

/**
 * Execute ZAP scanning on all in-scope web applications.
 *
 * This is currently a delegation stub — the actual implementation
 * remains inline in the orchestrator.
 *
 * @param ctx - Shared vulnerability detection context
 * @param burpAppLogin - Optional Burp app login for cross-tool pipeline
 * @returns ZAP scan results summary
 */
export async function executeZapScanning(
  ctx: VulnDetectionContext,
  burpAppLogin?: { username: string; password: string; loginUrl?: string },
): Promise<ZapScanResult> {
  throw new Error(
    "[ZapScanner] This stub should not be called directly. " +
    "The orchestrator still executes ZAP scanning inline until full extraction is complete."
  );
}
