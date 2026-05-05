/**
 * Vulnerability Detection — Nuclei Scanner
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 4068-4770).
 *
 * Responsibilities:
 *   - Execute Nuclei template scans on all in-scope assets via scan server
 *   - RoE scope enforcement for all targets
 *   - Template selection based on technology fingerprints
 *   - ScanForge in-process template execution
 *   - Parse and normalize Nuclei findings
 *   - Persist scan results to DB
 *   - Track scan completion for recovery/resume
 *
 * NOTE: This is a delegation stub. The actual implementation remains in the
 * orchestrator until the full extraction is complete. This module defines the
 * interface and will be progressively filled in.
 */

import type { VulnDetectionContext } from "./index";

export interface NucleiScanResult {
  /** Total findings from Nuclei scanning */
  findingsCount: number;
  /** Number of assets scanned */
  assetsScanned: number;
  /** Number of templates executed */
  templatesExecuted: number;
  /** ScanForge in-process findings */
  scanForgeFindings: number;
}

/**
 * Execute Nuclei scanning on all in-scope assets.
 *
 * This is currently a delegation stub — the actual implementation
 * remains inline in the orchestrator. Once the full extraction is
 * validated, the code will be moved here.
 *
 * @param ctx - Shared vulnerability detection context
 * @returns Nuclei scan results summary
 */
export async function executeNucleiScanning(ctx: VulnDetectionContext): Promise<NucleiScanResult> {
  // STUB: This function will be populated when the orchestrator delegation is wired.
  // For now, the orchestrator continues to execute Nuclei scanning inline.
  throw new Error(
    "[NucleiScanner] This stub should not be called directly. " +
    "The orchestrator still executes Nuclei scanning inline until full extraction is complete."
  );
}
