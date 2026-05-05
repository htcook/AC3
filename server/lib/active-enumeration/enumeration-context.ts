/**
 * Shared context interface for Phase 5 (Active Enumeration) sub-modules.
 *
 * All sub-modules receive this context to avoid circular imports and
 * keep the dependency graph clean.
 */

import { type EngagementOpsState, isInRoeScope, fmtTarget } from "../../../shared/orchestrator-types";
import {
  addLog,
  broadcastOpsUpdate,
  broadcastReconFinding,
  getEffectiveTarget,
  getEngagementAbortSignal,
  pushVulnDeduped,
  persistScanResult,
  persistOpsStateDebounced,
  KNOWN_INFRA_IPS,
} from "../engagement-orchestrator";
import { parseToolOutput } from "../tool-output-parsers";
import { executeToolViaQueue, executeRawCommandViaQueue } from "../job-queue-bridge";
import { enrichPortServices } from "../service-resolver";
import { getScanProfile, buildGobusterCommand } from "../scan-profiles";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ToolResult {
  stdout: string;
  stderr?: string;
  exitCode: number;
  timedOut?: boolean;
  durationMs?: number;
}

export interface EnumerationContext {
  state: EngagementOpsState;
  scopedAssets: any[];
  engagementAbortSignal: AbortSignal | undefined;
}

// ─── Helper factory ─────────────────────────────────────────────────────────

/**
 * Build a reusable helpers object for sub-modules.
 * Avoids each sub-module needing to import 10+ functions individually.
 */
export function buildEnumerationHelpers(state: EngagementOpsState) {
  const roeScope = [
    ...(state.roeScopeGuard?.authorizedDomains || []),
    ...(state.roeScopeGuard?.authorizedIps || []),
  ];
  const engagementAbortSignal = getEngagementAbortSignal(state.engagementId);

  const executeTool = (config: any) =>
    executeToolViaQueue(config, {
      engagementId: state.engagementId,
      roeScope,
      engagementAbortSignal,
    });

  const executeRawCommand = (cmd: string, timeout: number, opts?: any) =>
    executeRawCommandViaQueue(cmd, timeout, {
      engagementId: state.engagementId,
      engagementAbortSignal,
      ...opts,
    });

  return {
    addLog: (entry: any) => addLog(state, entry),
    broadcastOpsUpdate: (data: any) => broadcastOpsUpdate(state.engagementId, data),
    broadcastReconFinding: (finding: any) => broadcastReconFinding(state.engagementId, finding),
    getEffectiveTarget,
    isInRoeScope: (hostname: string, ip?: string) => isInRoeScope(state, hostname, ip),
    fmtTarget,
    parseToolOutput,
    pushVulnDeduped,
    enrichPortServices,
    getScanProfile,
    buildGobusterCommand,
    executeTool,
    executeRawCommand,
    persistScanResult: (opts: any) => persistScanResult(opts),
    persistOpsStateDebounced: (delayMs?: number) => persistOpsStateDebounced(state.engagementId, delayMs),
    KNOWN_INFRA_IPS,
    engagementAbortSignal,
    genId: () => Math.random().toString(36).substring(2, 10),
  };
}

export type EnumerationHelpers = ReturnType<typeof buildEnumerationHelpers>;

// Re-export commonly needed items for sub-modules
export {
  type EngagementOpsState,
  isInRoeScope,
  fmtTarget,
  addLog,
  broadcastOpsUpdate,
  broadcastReconFinding,
  getEffectiveTarget,
  getEngagementAbortSignal,
  pushVulnDeduped,
  persistScanResult,
  persistOpsStateDebounced,
  KNOWN_INFRA_IPS,
  parseToolOutput,
  executeToolViaQueue,
  executeRawCommandViaQueue,
  enrichPortServices,
  getScanProfile,
  buildGobusterCommand,
};
