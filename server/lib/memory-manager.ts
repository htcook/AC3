/**
 * Memory Manager — Aggressive memory reduction for Manus container (512MB limit)
 *
 * Strategy:
 * 1. Post-phase cleanup: After each phase completes and state is persisted to DB,
 *    strip heavy data from in-memory state (toolResults outputPreview, passiveReconResults,
 *    scanFeedbackLoop, vulnAnalysis, attackChains, etc.)
 * 2. LLM context capping: Hard-cap the total size of knowledge base context strings
 *    to prevent multi-MB prompt accumulation
 * 3. Aggressive watchdog: More granular eviction at WARNING level, not just EMERGENCY
 * 4. State size tracking: Log the size of each engagement state for profiling
 */

// ─── Constants ─────────────────────────────────────────────────────────────

/** Maximum total characters for concatenated LLM knowledge base context */
export const MAX_LLM_CONTEXT_CHARS = 12_000; // ~3K tokens, was unlimited (often 50K+)

/** Maximum outputPreview length per toolResult after phase completion */
export const POST_PHASE_OUTPUT_PREVIEW_CAP = 64;

/** Maximum findings per toolResult after phase completion */
export const POST_PHASE_FINDINGS_CAP = 5;

/** Maximum log entries to keep in memory */
export const MAX_IN_MEMORY_LOGS = 40;

/** Maximum log detail string length */
export const MAX_LOG_DETAIL_LENGTH = 256;

/** Maximum zapFindings per asset in memory */
export const MAX_ZAP_FINDINGS_IN_MEMORY = 20;

/** Maximum vulns per asset in memory (full data is in DB) */
export const MAX_VULNS_IN_MEMORY = 50;

/** Maximum pendingVulns per asset */
export const MAX_PENDING_VULNS_IN_MEMORY = 20;

// ─── State Size Estimation ─────────────────────────────────────────────────

/**
 * Estimate the in-memory size of an engagement state in bytes.
 * Uses a fast heuristic (not JSON.stringify which would double memory).
 */
export function estimateStateSize(state: any): {
  totalBytes: number;
  breakdown: Record<string, number>;
} {
  const breakdown: Record<string, number> = {};

  // Assets
  let assetBytes = 0;
  for (const asset of (state.assets || [])) {
    // toolResults are the biggest offender
    for (const tr of (asset.toolResults || [])) {
      assetBytes += (tr.outputPreview?.length || 0) * 2; // UTF-16
      assetBytes += (tr.findings?.length || 0) * 200; // ~200 bytes per finding object
      assetBytes += 200; // base object overhead
    }
    // vulns
    assetBytes += (asset.vulns?.length || 0) * 300;
    // zapFindings
    assetBytes += (asset.zapFindings?.length || 0) * 200;
    // pendingVulns
    assetBytes += (asset.pendingVulns?.length || 0) * 250;
    // exploitAttempts
    assetBytes += (asset.exploitAttempts?.length || 0) * 500;
    // passiveRecon
    if (asset.passiveRecon) {
      assetBytes += JSON.stringify(asset.passiveRecon).length * 2;
    }
    // confirmedCredentials
    assetBytes += (asset.confirmedCredentials?.length || 0) * 200;
    assetBytes += 500; // base asset overhead
  }
  breakdown.assets = assetBytes;

  // Logs
  let logBytes = 0;
  for (const log of (state.log || [])) {
    logBytes += (log.detail?.length || 0) * 2;
    logBytes += (log.title?.length || 0) * 2;
    logBytes += log.data ? JSON.stringify(log.data).length * 2 : 0;
    logBytes += 200; // base log overhead
  }
  breakdown.logs = logBytes;

  // passiveReconResults (raw OSINT data)
  if (state.passiveReconResults) {
    try {
      breakdown.passiveReconResults = JSON.stringify(state.passiveReconResults).length * 2;
    } catch {
      breakdown.passiveReconResults = 50_000; // estimate
    }
  }

  // scanPlan
  if (state.scanPlan) {
    try {
      breakdown.scanPlan = JSON.stringify(state.scanPlan).length * 2;
    } catch {
      breakdown.scanPlan = 10_000;
    }
  }

  // vulnAnalysis, attackChains, scanFeedbackLoop, essIntelligence
  for (const key of ['vulnAnalysis', 'vulnAnalysisSuppressed', 'attackChains', 'scanFeedbackLoop', 'essIntelligence', 'cloudDetection', 'engagementContext']) {
    if (state[key]) {
      try {
        breakdown[key] = JSON.stringify(state[key]).length * 2;
      } catch {
        breakdown[key] = 20_000;
      }
    }
  }

  // llmPlan string
  if (state.llmPlan) {
    breakdown.llmPlan = state.llmPlan.length * 2;
  }

  const totalBytes = Object.values(breakdown).reduce((sum, v) => sum + v, 0);
  return { totalBytes, breakdown };
}

// ─── Post-Phase Cleanup ────────────────────────────────────────────────────

/**
 * Strip heavy data from in-memory state after a phase completes and state
 * has been persisted to DB. The full data remains in the DB snapshot.
 *
 * This is the PRIMARY memory reduction mechanism. After each phase:
 * - toolResults.outputPreview → truncated to 64 chars (was 1KB+)
 * - toolResults.findings → capped at 5 (was unlimited)
 * - passiveReconResults → deleted (only needed during recon)
 * - log.detail → truncated to 256 chars
 * - log.data → deleted (already persisted to timeline_events)
 * - Temporary analysis objects → deleted
 */
export function postPhaseCleanup(state: any, completedPhase: string): {
  freedEstimateBytes: number;
  actions: string[];
} {
  const actions: string[] = [];
  let freedEstimate = 0;

  // 1. Trim toolResults across all assets
  for (const asset of (state.assets || [])) {
    for (const tr of (asset.toolResults || [])) {
      // Truncate outputPreview
      if (tr.outputPreview && tr.outputPreview.length > POST_PHASE_OUTPUT_PREVIEW_CAP) {
        freedEstimate += (tr.outputPreview.length - POST_PHASE_OUTPUT_PREVIEW_CAP) * 2;
        tr.outputPreview = tr.outputPreview.slice(0, POST_PHASE_OUTPUT_PREVIEW_CAP) + '…';
      }
      // Cap findings array
      if (tr.findings && tr.findings.length > POST_PHASE_FINDINGS_CAP) {
        freedEstimate += (tr.findings.length - POST_PHASE_FINDINGS_CAP) * 200;
        tr.findings = tr.findings.slice(0, POST_PHASE_FINDINGS_CAP);
      }
    }
    actions.push(`toolResults trimmed for ${asset.hostname}`);

    // Cap zapFindings
    if (asset.zapFindings && asset.zapFindings.length > MAX_ZAP_FINDINGS_IN_MEMORY) {
      freedEstimate += (asset.zapFindings.length - MAX_ZAP_FINDINGS_IN_MEMORY) * 200;
      asset.zapFindings = asset.zapFindings.slice(0, MAX_ZAP_FINDINGS_IN_MEMORY);
    }

    // Cap pendingVulns
    if (asset.pendingVulns && asset.pendingVulns.length > MAX_PENDING_VULNS_IN_MEMORY) {
      freedEstimate += (asset.pendingVulns.length - MAX_PENDING_VULNS_IN_MEMORY) * 250;
      asset.pendingVulns = asset.pendingVulns.slice(0, MAX_PENDING_VULNS_IN_MEMORY);
    }
  }

  // 2. Clear passiveReconResults after recon phase (huge raw OSINT data)
  if (state.passiveReconResults && ['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit', 'completed'].includes(completedPhase)) {
    try {
      freedEstimate += JSON.stringify(state.passiveReconResults).length * 2;
    } catch { freedEstimate += 50_000; }
    delete state.passiveReconResults;
    actions.push('passiveReconResults cleared');
  }

  // 3. Clear temporary analysis objects after their phase
  const phaseCleanupMap: Record<string, string[]> = {
    vuln_detection: ['vulnAnalysis', 'vulnAnalysisSuppressed', 'fpSuppressionStats', 'scanFeedbackLoop'],
    exploitation: ['attackChains', 'essIntelligence'],
    post_exploit: ['cloudDetection'],
    completed: ['vulnAnalysis', 'vulnAnalysisSuppressed', 'fpSuppressionStats', 'scanFeedbackLoop', 'attackChains', 'essIntelligence', 'cloudDetection', 'engagementContext'],
  };

  const keysToClean = phaseCleanupMap[completedPhase] || [];
  for (const key of keysToClean) {
    if (state[key]) {
      try {
        freedEstimate += JSON.stringify(state[key]).length * 2;
      } catch { freedEstimate += 20_000; }
      delete state[key];
      actions.push(`${key} cleared`);
    }
  }

  // 4. Trim logs
  if (state.log && state.log.length > MAX_IN_MEMORY_LOGS) {
    const trimmed = state.log.length - MAX_IN_MEMORY_LOGS;
    freedEstimate += trimmed * 500; // ~500 bytes per log entry
    state.log = state.log.slice(-MAX_IN_MEMORY_LOGS);
    actions.push(`${trimmed} old logs trimmed`);
  }

  // 5. Truncate log detail strings and remove log data objects
  for (const log of (state.log || [])) {
    if (log.detail && log.detail.length > MAX_LOG_DETAIL_LENGTH) {
      freedEstimate += (log.detail.length - MAX_LOG_DETAIL_LENGTH) * 2;
      log.detail = log.detail.slice(0, MAX_LOG_DETAIL_LENGTH) + '…';
    }
    if (log.data) {
      try {
        freedEstimate += JSON.stringify(log.data).length * 2;
      } catch { freedEstimate += 1000; }
      delete log.data;
    }
  }

  // 6. Clear passiveRecon.historicalUrls (can be huge, already in DB)
  for (const asset of (state.assets || [])) {
    if (asset.passiveRecon?.historicalUrls?.length > 5) {
      freedEstimate += (asset.passiveRecon.historicalUrls.length - 5) * 100;
      asset.passiveRecon.historicalUrls = asset.passiveRecon.historicalUrls.slice(0, 5);
    }
    if (asset.passiveRecon?.subdomains?.length > 10) {
      freedEstimate += (asset.passiveRecon.subdomains.length - 10) * 50;
      asset.passiveRecon.subdomains = asset.passiveRecon.subdomains.slice(0, 10);
    }
  }

  // 7. Trigger GC if available
  if (global.gc) {
    global.gc();
    actions.push('GC triggered');
  }

  return { freedEstimateBytes: freedEstimate, actions };
}

// ─── LLM Context Capping ───────────────────────────────────────────────────

/**
 * Cap the total size of concatenated knowledge base context strings.
 * Each context string is proportionally truncated to fit within the budget.
 *
 * @param contexts Array of { label, content } pairs
 * @param maxChars Maximum total characters (default: MAX_LLM_CONTEXT_CHARS)
 * @returns Concatenated string within budget
 */
export function capLLMContext(
  contexts: Array<{ label: string; content: string }>,
  maxChars: number = MAX_LLM_CONTEXT_CHARS,
): string {
  // Filter out empty contexts
  const nonEmpty = contexts.filter(c => c.content && c.content.length > 0);
  if (nonEmpty.length === 0) return '';

  const totalChars = nonEmpty.reduce((sum, c) => sum + c.content.length, 0);

  // If within budget, return as-is
  if (totalChars <= maxChars) {
    return nonEmpty.map(c => c.content).join('\n\n');
  }

  // Proportionally allocate budget to each context
  // Give priority to shorter contexts (they're usually more targeted)
  const sorted = [...nonEmpty].sort((a, b) => a.content.length - b.content.length);
  let remainingBudget = maxChars;
  const allocations = new Map<string, number>();

  for (let i = 0; i < sorted.length; i++) {
    const remaining = sorted.length - i;
    const fairShare = Math.floor(remainingBudget / remaining);
    const allocation = Math.min(sorted[i].content.length, fairShare);
    allocations.set(sorted[i].label, allocation);
    remainingBudget -= allocation;
  }

  // Build result with truncation markers
  const parts: string[] = [];
  for (const ctx of nonEmpty) {
    const budget = allocations.get(ctx.label) || 0;
    if (budget <= 0) continue;
    if (ctx.content.length <= budget) {
      parts.push(ctx.content);
    } else {
      parts.push(ctx.content.slice(0, budget) + '\n[...truncated for memory]');
    }
  }

  return parts.join('\n\n');
}

// ─── Aggressive Watchdog Eviction ──────────────────────────────────────────

/**
 * Emergency memory eviction — called by the memory watchdog when heap is high.
 * More aggressive than the existing watchdog: strips ALL non-essential data.
 */
export function emergencyEviction(state: any): {
  freedEstimateBytes: number;
  actions: string[];
} {
  const actions: string[] = [];
  let freedEstimate = 0;

  // 1. Strip ALL toolResults outputPreview to empty string
  for (const asset of (state.assets || [])) {
    for (const tr of (asset.toolResults || [])) {
      if (tr.outputPreview) {
        freedEstimate += tr.outputPreview.length * 2;
        tr.outputPreview = '';
      }
      if (tr.findings && tr.findings.length > 0) {
        freedEstimate += tr.findings.length * 200;
        tr.findings = [];
      }
    }
    // Strip zapFindings to summary only
    if (asset.zapFindings && asset.zapFindings.length > 5) {
      freedEstimate += (asset.zapFindings.length - 5) * 200;
      asset.zapFindings = asset.zapFindings.slice(0, 5);
    }
    // Strip passiveRecon entirely (it's in DB)
    if (asset.passiveRecon) {
      try {
        freedEstimate += JSON.stringify(asset.passiveRecon).length * 2;
      } catch { freedEstimate += 5_000; }
      // Keep only essential fields
      asset.passiveRecon = {
        technologies: (asset.passiveRecon.technologies || []).slice(0, 5),
        cloudProvider: asset.passiveRecon.cloudProvider,
        wafDetected: asset.passiveRecon.wafDetected,
        rawObservationCount: asset.passiveRecon.rawObservationCount || 0,
        sources: [],
        subdomains: [],
        ipAddresses: [],
        services: [],
        certificates: [],
        riskSignals: [],
        historicalUrls: [],
      };
    }
    // Strip exploitAttempts detail
    for (const ea of (asset.exploitAttempts || [])) {
      if (ea.reasoning && ea.reasoning.length > 100) {
        freedEstimate += (ea.reasoning.length - 100) * 2;
        ea.reasoning = ea.reasoning.slice(0, 100) + '…';
      }
      if (ea.errorDetail && ea.errorDetail.length > 100) {
        freedEstimate += (ea.errorDetail.length - 100) * 2;
        ea.errorDetail = ea.errorDetail.slice(0, 100) + '…';
      }
    }
  }
  actions.push('all toolResults/passiveRecon stripped');

  // 2. Strip ALL temporary analysis objects
  for (const key of ['vulnAnalysis', 'vulnAnalysisSuppressed', 'fpSuppressionStats',
    'scanFeedbackLoop', 'attackChains', 'essIntelligence', 'cloudDetection',
    'engagementContext', 'passiveReconResults', 'metadata']) {
    if (state[key]) {
      try {
        freedEstimate += JSON.stringify(state[key]).length * 2;
      } catch { freedEstimate += 20_000; }
      delete state[key];
      actions.push(`${key} deleted`);
    }
  }

  // 3. Aggressive log trimming
  if (state.log && state.log.length > 15) {
    freedEstimate += (state.log.length - 15) * 500;
    state.log = state.log.slice(-15);
  }
  for (const log of (state.log || [])) {
    if (log.detail && log.detail.length > 100) {
      freedEstimate += (log.detail.length - 100) * 2;
      log.detail = log.detail.slice(0, 100) + '…';
    }
    if (log.data) {
      delete log.data;
      freedEstimate += 500;
    }
  }
  actions.push('logs aggressively trimmed');

  // 4. Strip scanPlan (already used, in DB)
  if (state.scanPlan) {
    try {
      freedEstimate += JSON.stringify(state.scanPlan).length * 2;
    } catch { freedEstimate += 10_000; }
    // Keep only the overall strategy string
    state.scanPlan = {
      overallStrategy: state.scanPlan.overallStrategy?.slice(0, 200) || '',
      assetPlans: [],
      generatedAt: state.scanPlan.generatedAt,
    };
    actions.push('scanPlan stripped');
  }

  // 5. Strip llmPlan
  if (state.llmPlan && state.llmPlan.length > 200) {
    freedEstimate += (state.llmPlan.length - 200) * 2;
    state.llmPlan = state.llmPlan.slice(0, 200) + '…';
    actions.push('llmPlan truncated');
  }

  // 6. GC
  if (global.gc) {
    global.gc();
    actions.push('GC triggered');
  }

  return { freedEstimateBytes: freedEstimate, actions };
}

// ─── Memory Profile Logging ────────────────────────────────────────────────

/**
 * Log memory profile for an engagement state.
 * Call this at phase transitions for profiling.
 */
export function logMemoryProfile(engagementId: number, state: any, phase: string): void {
  const mem = process.memoryUsage();
  const { totalBytes, breakdown } = estimateStateSize(state);

  // Sort breakdown by size descending
  const sorted = Object.entries(breakdown)
    .sort(([, a], [, b]) => b - a)
    .map(([k, v]) => `${k}=${(v / 1024).toFixed(0)}KB`)
    .join(', ');

  console.log(
    `[MemProfile] Eng#${engagementId} phase=${phase}: ` +
    `stateEst=${(totalBytes / 1024).toFixed(0)}KB, ` +
    `heap=${(mem.heapUsed / 1024 / 1024).toFixed(0)}MB, ` +
    `rss=${(mem.rss / 1024 / 1024).toFixed(0)}MB | ` +
    sorted
  );
}
