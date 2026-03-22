/**
 * Scan Concurrency Limiter — Global semaphore for throttling concurrent scans
 *
 * Prevents CPU thrashing when running 40+ assets across multiple engagements
 * by enforcing configurable per-tool and global concurrency caps.
 *
 * Architecture:
 *   - Global semaphore with per-tool slots (nuclei, zap, other)
 *   - FIFO queue with backpressure — excess scans wait, never dropped
 *   - Per-engagement fairness — no single engagement can monopolize all slots
 *   - Metrics tracking for observability (wait times, queue depth, utilization)
 */

export interface ScanConcurrencyConfig {
  /** Max concurrent nuclei scans across all engagements (default: 4) */
  maxConcurrentNuclei: number;
  /** Max concurrent ZAP scans across all engagements (default: 2) */
  maxConcurrentZap: number;
  /** Max total concurrent scans globally (default: 6) */
  maxConcurrentTotal: number;
  /** Max scans per engagement to ensure fairness (default: 3) */
  maxPerEngagement: number;
  /** Max time a scan can wait in queue before being rejected (ms, default: 300000 = 5min) */
  queueTimeoutMs: number;
}

interface QueueEntry {
  tool: string;
  engagementId: number;
  resolve: (release: () => void) => void;
  reject: (err: Error) => void;
  enqueuedAt: number;
}

interface ActiveScan {
  tool: string;
  engagementId: number;
  startedAt: number;
}

interface ConcurrencyMetrics {
  activeNuclei: number;
  activeZap: number;
  activeOther: number;
  activeTotal: number;
  queueDepth: number;
  totalAcquired: number;
  totalReleased: number;
  totalTimedOut: number;
  avgWaitMs: number;
  peakConcurrent: number;
  perEngagement: Record<number, number>;
}

const DEFAULT_CONFIG: ScanConcurrencyConfig = {
  maxConcurrentNuclei: 4,
  maxConcurrentZap: 2,
  maxConcurrentTotal: 6,
  maxPerEngagement: 3,
  queueTimeoutMs: 5 * 60 * 1000, // 5 minutes
};

let config: ScanConcurrencyConfig = { ...DEFAULT_CONFIG };
const activeScans: ActiveScan[] = [];
const waitQueue: QueueEntry[] = [];
let totalAcquired = 0;
let totalReleased = 0;
let totalTimedOut = 0;
let totalWaitMs = 0;
let peakConcurrent = 0;
let queueTimeoutChecker: ReturnType<typeof setInterval> | null = null;

/**
 * Update concurrency configuration at runtime.
 * Does NOT affect currently active scans — only future acquire() calls.
 */
export function configureScanConcurrency(newConfig: Partial<ScanConcurrencyConfig>): ScanConcurrencyConfig {
  config = { ...config, ...newConfig };
  console.log(`[ScanConcurrency] Config updated: nuclei=${config.maxConcurrentNuclei}, zap=${config.maxConcurrentZap}, total=${config.maxConcurrentTotal}, perEngagement=${config.maxPerEngagement}`);
  // Try to drain queue with new config
  drainQueue();
  return config;
}

/**
 * Get current concurrency configuration.
 */
export function getScanConcurrencyConfig(): ScanConcurrencyConfig {
  return { ...config };
}

/**
 * Acquire a scan slot. Returns a release function.
 * Blocks (via Promise) if all slots are full, with FIFO queue ordering.
 * Throws if queue timeout is exceeded.
 */
export function acquireScanSlot(tool: string, engagementId: number): Promise<() => void> {
  // Check if we can run immediately
  if (canAcquire(tool, engagementId)) {
    return Promise.resolve(doAcquire(tool, engagementId));
  }

  // Queue the request
  return new Promise<() => void>((resolve, reject) => {
    waitQueue.push({
      tool,
      engagementId,
      resolve,
      reject,
      enqueuedAt: Date.now(),
    });

    // Start timeout checker if not running
    if (!queueTimeoutChecker) {
      queueTimeoutChecker = setInterval(checkQueueTimeouts, 5000);
    }
  });
}

/**
 * Check if a scan slot is immediately available (non-blocking).
 */
export function isScanSlotAvailable(tool: string, engagementId: number): boolean {
  return canAcquire(tool, engagementId);
}

/**
 * Get current concurrency metrics for observability.
 */
export function getScanConcurrencyMetrics(): ConcurrencyMetrics {
  const perEngagement: Record<number, number> = {};
  for (const scan of activeScans) {
    perEngagement[scan.engagementId] = (perEngagement[scan.engagementId] || 0) + 1;
  }

  return {
    activeNuclei: activeScans.filter(s => s.tool === 'nuclei').length,
    activeZap: activeScans.filter(s => s.tool === 'zap').length,
    activeOther: activeScans.filter(s => s.tool !== 'nuclei' && s.tool !== 'zap').length,
    activeTotal: activeScans.length,
    queueDepth: waitQueue.length,
    totalAcquired,
    totalReleased,
    totalTimedOut,
    avgWaitMs: totalAcquired > 0 ? Math.round(totalWaitMs / totalAcquired) : 0,
    peakConcurrent,
    perEngagement,
  };
}

/**
 * Force-release all slots for a specific engagement (e.g., on abort/error).
 */
export function releaseAllForEngagement(engagementId: number): number {
  const toRemove = activeScans.filter(s => s.engagementId === engagementId);
  for (const scan of toRemove) {
    const idx = activeScans.indexOf(scan);
    if (idx >= 0) {
      activeScans.splice(idx, 1);
      totalReleased++;
    }
  }

  // Also remove queued entries for this engagement
  let queueRemoved = 0;
  for (let i = waitQueue.length - 1; i >= 0; i--) {
    if (waitQueue[i].engagementId === engagementId) {
      const entry = waitQueue.splice(i, 1)[0];
      entry.reject(new Error(`Engagement ${engagementId} aborted — scan slot released`));
      queueRemoved++;
    }
  }

  if (toRemove.length > 0 || queueRemoved > 0) {
    console.log(`[ScanConcurrency] Force-released ${toRemove.length} active + ${queueRemoved} queued slots for engagement ${engagementId}`);
    drainQueue();
  }

  return toRemove.length + queueRemoved;
}

/**
 * Reset all state (for testing).
 */
export function resetScanConcurrency(): void {
  activeScans.length = 0;
  waitQueue.length = 0;
  totalAcquired = 0;
  totalReleased = 0;
  totalTimedOut = 0;
  totalWaitMs = 0;
  peakConcurrent = 0;
  config = { ...DEFAULT_CONFIG };
  if (queueTimeoutChecker) {
    clearInterval(queueTimeoutChecker);
    queueTimeoutChecker = null;
  }
}

// ── Internal helpers ──

function canAcquire(tool: string, engagementId: number): boolean {
  // Check global total
  if (activeScans.length >= config.maxConcurrentTotal) return false;

  // Check per-tool limit
  const toolCount = activeScans.filter(s => s.tool === tool).length;
  if (tool === 'nuclei' && toolCount >= config.maxConcurrentNuclei) return false;
  if (tool === 'zap' && toolCount >= config.maxConcurrentZap) return false;

  // Check per-engagement fairness
  const engCount = activeScans.filter(s => s.engagementId === engagementId).length;
  if (engCount >= config.maxPerEngagement) return false;

  return true;
}

function doAcquire(tool: string, engagementId: number): () => void {
  const scan: ActiveScan = { tool, engagementId, startedAt: Date.now() };
  activeScans.push(scan);
  totalAcquired++;

  if (activeScans.length > peakConcurrent) {
    peakConcurrent = activeScans.length;
  }

  // Return release function
  return () => {
    const idx = activeScans.indexOf(scan);
    if (idx >= 0) {
      activeScans.splice(idx, 1);
      totalReleased++;
      drainQueue();
    }
  };
}

function drainQueue(): void {
  // Process queue entries in FIFO order
  let i = 0;
  while (i < waitQueue.length) {
    const entry = waitQueue[i];
    if (canAcquire(entry.tool, entry.engagementId)) {
      waitQueue.splice(i, 1);
      const waitTime = Date.now() - entry.enqueuedAt;
      totalWaitMs += waitTime;
      const release = doAcquire(entry.tool, entry.engagementId);
      entry.resolve(release);
      // Don't increment i — array shifted
    } else {
      i++;
    }
  }

  // Stop timeout checker if queue is empty
  if (waitQueue.length === 0 && queueTimeoutChecker) {
    clearInterval(queueTimeoutChecker);
    queueTimeoutChecker = null;
  }
}

function checkQueueTimeouts(): void {
  const now = Date.now();
  for (let i = waitQueue.length - 1; i >= 0; i--) {
    const entry = waitQueue[i];
    if (now - entry.enqueuedAt > config.queueTimeoutMs) {
      waitQueue.splice(i, 1);
      totalTimedOut++;
      entry.reject(new Error(
        `Scan queue timeout: ${entry.tool} for engagement ${entry.engagementId} waited ${Math.round((now - entry.enqueuedAt) / 1000)}s (limit: ${config.queueTimeoutMs / 1000}s). ` +
        `Active: ${activeScans.length}/${config.maxConcurrentTotal}, Queue: ${waitQueue.length}`
      ));
    }
  }

  if (waitQueue.length === 0 && queueTimeoutChecker) {
    clearInterval(queueTimeoutChecker);
    queueTimeoutChecker = null;
  }
}
