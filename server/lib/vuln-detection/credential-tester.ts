/**
 * Vulnerability Detection — Credential Testing
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 6346-6642).
 *
 * Responsibilities:
 *   - Hydra credential testing on login services (SSH, FTP, HTTP-form, etc.)
 *   - Priority 3 tool execution (post-discovery, pre-exploitation)
 *   - Credential validation against discovered services
 *   - Persist confirmed credentials to asset state
 *
 * NOTE: This is a delegation stub. The actual implementation remains in the
 * orchestrator until the full extraction is complete.
 */

import type { VulnDetectionContext } from "./index";

export interface CredentialTestResult {
  /** Number of services tested */
  servicesTested: number;
  /** Number of credentials confirmed */
  credentialsConfirmed: number;
  /** Number of credential pairs attempted */
  attemptsTotal: number;
}

/**
 * Execute credential testing (Hydra) on discovered login services.
 *
 * This is currently a delegation stub — the actual implementation
 * remains inline in the orchestrator.
 *
 * @param ctx - Shared vulnerability detection context
 * @returns Credential test results summary
 */
export async function executeCredentialTesting(ctx: VulnDetectionContext): Promise<CredentialTestResult> {
  throw new Error(
    "[CredentialTester] This stub should not be called directly. " +
    "The orchestrator still executes credential testing inline until full extraction is complete."
  );
}
