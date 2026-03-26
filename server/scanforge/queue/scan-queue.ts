/**
 * ScanForge Job Queue
 *
 * In-memory priority queue for scan jobs. Uses a sorted array with
 * priority-based ordering (critical > high > medium > low) and FIFO
 * within the same priority level.
 *
 * Supports concurrent job execution with configurable concurrency limits.
 * No external dependencies (Redis/BullMQ) — runs entirely in-process
 * on the DO droplet for simplicity and zero-config deployment.
 *
 * For future scaling, this can be swapped for BullMQ with Redis.
 */

import { EventEmitter } from "events";
import type {
  ScanRequest,
  ScanJob,
  ScanStatus,
  ScanFinding,
  ScannerResult,
  ScanEvent,
  ScanPhase,
  ScanPriority,
  ScanSummary,
} from "../types";

// ─── Priority Weights ──────────────────────────────────────────────────────

const PRIORITY_WEIGHT: Record<ScanPriority, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

// ─── Queue Configuration ───────────────────────────────────────────────────

export interface QueueConfig {
  /** Max concurrent scan jobs */
  maxConcurrency: number;
  /** Max queue depth before rejecting new jobs */
  maxQueueDepth: number;
  /** Job timeout in ms (default 30 min) */
  jobTimeoutMs: number;
  /** Stale job cleanup interval in ms */
  cleanupIntervalMs: number;
}

const DEFAULT_CONFIG: QueueConfig = {
  maxConcurrency: 3,
  maxQueueDepth: 50,
  jobTimeoutMs: 30 * 60 * 1000,  // 30 minutes
  cleanupIntervalMs: 60 * 1000,  // 1 minute
};

// ─── Queue Manager ─────────────────────────────────────────────────────────

export class ScanQueue extends EventEmitter {
  private queue: ScanJob[] = [];
  private running: Map<string, ScanJob> = new Map();
  private completed: Map<string, ScanJob> = new Map();
  private config: QueueConfig;
  private cleanupTimer: NodeJS.Timeout | null = null;
  private processorFn: ((job: ScanJob) => Promise<void>) | null = null;

  constructor(config: Partial<QueueConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.startCleanup();
  }

  // ─── Public API ────────────────────────────────────────────────────────

  /**
   * Register the scan processor function.
   * Called when a job is dequeued and ready to execute.
   */
  setProcessor(fn: (job: ScanJob) => Promise<void>): void {
    this.processorFn = fn;
  }

  /**
   * Enqueue a new scan request. Returns the created ScanJob.
   */
  enqueue(request: ScanRequest): ScanJob {
    if (this.queue.length >= this.config.maxQueueDepth) {
      throw new Error(`Queue full (${this.config.maxQueueDepth} jobs). Try again later.`);
    }

    const job: ScanJob = {
      request,
      status: "queued",
      progress: 0,
      findings: [],
      scannerResults: [],
    };

    // Insert in priority order
    const weight = PRIORITY_WEIGHT[request.priority] || 1;
    let inserted = false;
    for (let i = 0; i < this.queue.length; i++) {
      const existingWeight = PRIORITY_WEIGHT[this.queue[i].request.priority] || 1;
      if (weight > existingWeight) {
        this.queue.splice(i, 0, job);
        inserted = true;
        break;
      }
    }
    if (!inserted) {
      this.queue.push(job);
    }

    const position = this.queue.indexOf(job) + 1;
    this.emitEvent({
      type: "scan:queued",
      scanId: request.id,
      position,
    });

    console.log(`[ScanQueue] Enqueued scan ${request.id} (priority=${request.priority}, position=${position}, queue=${this.queue.length})`);

    // Try to process immediately
    this.processNext();

    return job;
  }

  /**
   * Cancel a scan by ID. Works for queued or running scans.
   */
  cancel(scanId: string): boolean {
    // Check queue
    const queueIdx = this.queue.findIndex(j => j.request.id === scanId);
    if (queueIdx >= 0) {
      const job = this.queue.splice(queueIdx, 1)[0];
      job.status = "cancelled";
      job.completedAt = Date.now();
      this.completed.set(scanId, job);
      this.emitEvent({ type: "scan:cancelled", scanId });
      console.log(`[ScanQueue] Cancelled queued scan ${scanId}`);
      return true;
    }

    // Check running
    const runningJob = this.running.get(scanId);
    if (runningJob) {
      runningJob.status = "cancelled";
      runningJob.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, runningJob);
      this.emitEvent({ type: "scan:cancelled", scanId });
      console.log(`[ScanQueue] Cancelled running scan ${scanId}`);
      this.processNext();
      return true;
    }

    return false;
  }

  /**
   * Pause a running scan.
   */
  pause(scanId: string): boolean {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "paused";
      this.running.delete(scanId);
      // Re-enqueue at front
      this.queue.unshift(job);
      console.log(`[ScanQueue] Paused scan ${scanId}`);
      return true;
    }
    return false;
  }

  /**
   * Resume a paused scan.
   */
  resume(scanId: string): boolean {
    const idx = this.queue.findIndex(j => j.request.id === scanId && j.status === "paused");
    if (idx >= 0) {
      this.queue[idx].status = "queued";
      this.processNext();
      return true;
    }
    return false;
  }

  /**
   * Get a scan job by ID (from any state).
   */
  getJob(scanId: string): ScanJob | null {
    const queued = this.queue.find(j => j.request.id === scanId);
    if (queued) return queued;
    const running = this.running.get(scanId);
    if (running) return running;
    return this.completed.get(scanId) || null;
  }

  /**
   * Get queue status.
   */
  getStatus(): {
    queued: number;
    running: number;
    completed: number;
    maxConcurrency: number;
  } {
    return {
      queued: this.queue.length,
      running: this.running.size,
      completed: this.completed.size,
      maxConcurrency: this.config.maxConcurrency,
    };
  }

  /**
   * Get all jobs (for dashboard).
   */
  getAllJobs(): ScanJob[] {
    return [
      ...this.queue,
      ...Array.from(this.running.values()),
      ...Array.from(this.completed.values()),
    ];
  }

  /**
   * Update job progress (called by the scan engine during execution).
   */
  updateProgress(scanId: string, progress: number, scanner?: string): void {
    const job = this.running.get(scanId);
    if (job) {
      job.progress = Math.min(100, Math.max(0, progress));
      if (scanner) job.currentScanner = scanner;
      this.emitEvent({
        type: "scan:progress",
        scanId,
        progress: job.progress,
        scanner: scanner || "unknown",
      });
    }
  }

  /**
   * Add a finding to a running job.
   */
  addFinding(scanId: string, finding: ScanFinding): void {
    const job = this.running.get(scanId);
    if (job) {
      job.findings.push(finding);
      this.emitEvent({ type: "scan:finding", scanId, finding });
    }
  }

  /**
   * Record a scanner result.
   */
  addScannerResult(scanId: string, result: ScannerResult): void {
    const job = this.running.get(scanId);
    if (job) {
      job.scannerResults.push(result);
      this.emitEvent({ type: "scan:scanner_complete", scanId, result });
    }
  }

  /**
   * Update scan phase.
   */
  setPhase(scanId: string, phase: ScanPhase): void {
    const job = this.running.get(scanId);
    if (job) {
      job.phase = phase;
      this.emitEvent({ type: "scan:phase_change", scanId, phase });
    }
  }

  /**
   * Mark a job as completed.
   */
  completeJob(scanId: string): void {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "completed";
      job.progress = 100;
      job.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, job);

      const summary = this.buildSummary(job);
      this.emitEvent({ type: "scan:completed", scanId, summary });
      console.log(`[ScanQueue] Scan ${scanId} completed: ${summary.totalFindings} findings in ${summary.durationMs}ms`);

      // Deliver callback if configured
      if (job.request.callbackUrl) {
        this.deliverCallback(job.request.callbackUrl, summary).catch(() => {});
      }

      this.processNext();
    }
  }

  /**
   * Mark a job as failed.
   */
  failJob(scanId: string, error: string): void {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "failed";
      job.error = error;
      job.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, job);
      this.emitEvent({ type: "scan:failed", scanId, error });
      console.error(`[ScanQueue] Scan ${scanId} failed: ${error}`);
      this.processNext();
    }
  }

  /**
   * Shutdown the queue gracefully.
   */
  shutdown(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    // Cancel all queued jobs
    for (const job of this.queue) {
      job.status = "cancelled";
      job.completedAt = Date.now();
    }
    this.queue = [];
    console.log("[ScanQueue] Shutdown complete");
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private processNext(): void {
    if (!this.processorFn) return;
    if (this.running.size >= this.config.maxConcurrency) return;

    const nextJob = this.queue.find(j => j.status === "queued");
    if (!nextJob) return;

    // Move from queue to running
    const idx = this.queue.indexOf(nextJob);
    this.queue.splice(idx, 1);
    nextJob.status = "running";
    nextJob.startedAt = Date.now();
    nextJob.phase = "recon";
    this.running.set(nextJob.request.id, nextJob);

    this.emitEvent({
      type: "scan:started",
      scanId: nextJob.request.id,
      phase: "recon",
    });

    console.log(`[ScanQueue] Starting scan ${nextJob.request.id} (running=${this.running.size}/${this.config.maxConcurrency})`);

    // Execute in background
    const processor = this.processorFn;
    const scanId = nextJob.request.id;
    const timeoutMs = this.config.jobTimeoutMs;

    // Set up timeout
    const timeout = setTimeout(() => {
      if (this.running.has(scanId)) {
        this.failJob(scanId, `Scan timed out after ${timeoutMs / 1000}s`);
      }
    }, timeoutMs);

    processor(nextJob)
      .then(() => {
        clearTimeout(timeout);
        if (this.running.has(scanId)) {
          this.completeJob(scanId);
        }
      })
      .catch((err) => {
        clearTimeout(timeout);
        if (this.running.has(scanId)) {
          this.failJob(scanId, err.message || "Unknown error");
        }
      });

    // Try to fill remaining concurrency slots
    if (this.running.size < this.config.maxConcurrency) {
      this.processNext();
    }
  }

  private buildSummary(job: ScanJob): ScanSummary {
    const bySeverity: Record<string, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of job.findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }

    return {
      scanId: job.request.id,
      totalFindings: job.findings.length,
      bySeverity: bySeverity as any,
      scannersRun: job.scannerResults.length,
      scannersCompleted: job.scannerResults.filter(r => r.status === "completed").length,
      scannersFailed: job.scannerResults.filter(r => r.status === "failed").length,
      durationMs: (job.completedAt || Date.now()) - (job.startedAt || Date.now()),
      topFindings: job.findings
        .sort((a, b) => (b.riskScore?.composite || 0) - (a.riskScore?.composite || 0))
        .slice(0, 10),
    };
  }

  private emitEvent(event: ScanEvent): void {
    this.emit("scan_event", event);
  }

  private async deliverCallback(url: string, summary: ScanSummary): Promise<void> {
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(summary),
        signal: AbortSignal.timeout(10000),
      });
    } catch (err: any) {
      console.warn(`[ScanQueue] Callback delivery failed: ${err.message}`);
    }
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const cutoff = Date.now() - 2 * 60 * 60 * 1000; // 2 hours
      for (const [id, job] of this.completed) {
        if (job.completedAt && job.completedAt < cutoff) {
          this.completed.delete(id);
        }
      }
    }, this.config.cleanupIntervalMs);
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _queue: ScanQueue | null = null;

export function getScanQueue(config?: Partial<QueueConfig>): ScanQueue {
  if (!_queue) {
    _queue = new ScanQueue(config);
  }
  return _queue;
}
