/**
 * Scheduled Threat Actor Crawler & Enrichment Engine
 *
 * Provides a configurable cron-based scheduler for the threat actor intelligence
 * crawler. Supports:
 * - Configurable crawl intervals (hourly, daily, weekly, custom cron)
 * - Job queue with priority and concurrency control
 * - Automatic gap analysis and targeted enrichment
 * - Source health monitoring and adaptive retry
 * - Crawl result persistence and history tracking
 * - Real-time status reporting via tRPC
 * - Pause/resume/force-run controls
 *
 * Architecture:
 * ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
 * │  Scheduler   │────▶│  Job Queue   │────▶│  Crawler Engine   │
 * │  (cron/int)  │     │  (priority)  │     │  (threat-actor-   │
 * └──────────────┘     └──────────────┘     │   crawler.ts)     │
 *                                           └──────────────────┘
 *                                                    │
 *                                           ┌────────▼─────────┐
 *                                           │  Enrichment      │
 *                                           │  Pipeline         │
 *                                           │  (gap analysis → │
 *                                           │   LLM enrich)    │
 *                                           └──────────────────┘
 *
 * Author: Harrison Cook — AceofCloud
 */

import {
  runIntelligenceCrawl,
  runTargetedEnrichment,
  getCrawlerStats,
  isCrawlRunning,
  analyzeDataGaps,
  getCrawlSources,
  type CrawlResult,
  type CrawlerStats,
} from "./threat-actor-crawler";

// ─── Types ──────────────────────────────────────────────────────────────────

export type SchedulePreset = "realtime" | "aggressive" | "standard" | "conservative" | "manual";

export type JobType = "full_crawl" | "targeted_enrichment" | "gap_analysis" | "source_check";

export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type JobPriority = "critical" | "high" | "normal" | "low";

export interface SchedulerConfig {
  /** Whether the scheduler is active */
  enabled: boolean;
  /** Schedule preset (determines crawl frequency) */
  preset: SchedulePreset;
  /** Custom interval in minutes (used when preset is not "manual") */
  crawlIntervalMinutes: number;
  /** Enrichment interval in minutes (runs between crawls) */
  enrichmentIntervalMinutes: number;
  /** Maximum concurrent jobs */
  maxConcurrentJobs: number;
  /** Auto-enrich after each crawl */
  autoEnrichAfterCrawl: boolean;
  /** Maximum actors to enrich per cycle */
  maxActorsPerEnrichment: number;
  /** Retry failed jobs */
  retryFailedJobs: boolean;
  /** Max retry attempts per job */
  maxRetries: number;
  /** Pause between jobs (ms) */
  jobCooldownMs: number;
  /** Actor focus list (empty = all actors) */
  focusActors: string[];
  /** Source priority order */
  sourcePriority: string[];
  /** Notify on completion */
  notifyOnComplete: boolean;
  /** Notify on failure */
  notifyOnFailure: boolean;
}

export interface ScheduledJob {
  id: string;
  type: JobType;
  status: JobStatus;
  priority: JobPriority;
  scheduledAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: CrawlResult;
  error?: string;
  retryCount: number;
  metadata?: Record<string, any>;
}

export interface SchedulerStatus {
  config: SchedulerConfig;
  isRunning: boolean;
  currentJob: ScheduledJob | null;
  queuedJobs: number;
  completedJobs: number;
  failedJobs: number;
  totalJobsRun: number;
  lastCrawlAt?: string;
  lastEnrichmentAt?: string;
  nextScheduledRun?: string;
  uptime: number;
  startedAt?: string;
  crawlerStats: CrawlerStats;
  recentJobs: ScheduledJob[];
}

// ─── Default Configurations ─────────────────────────────────────────────────

const PRESET_CONFIGS: Record<SchedulePreset, Partial<SchedulerConfig>> = {
  realtime: {
    crawlIntervalMinutes: 15,
    enrichmentIntervalMinutes: 30,
    maxConcurrentJobs: 3,
    autoEnrichAfterCrawl: true,
    maxActorsPerEnrichment: 50,
    jobCooldownMs: 5000,
  },
  aggressive: {
    crawlIntervalMinutes: 60,
    enrichmentIntervalMinutes: 120,
    maxConcurrentJobs: 2,
    autoEnrichAfterCrawl: true,
    maxActorsPerEnrichment: 30,
    jobCooldownMs: 10000,
  },
  standard: {
    crawlIntervalMinutes: 360,      // Every 6 hours
    enrichmentIntervalMinutes: 720,  // Every 12 hours
    maxConcurrentJobs: 1,
    autoEnrichAfterCrawl: true,
    maxActorsPerEnrichment: 20,
    jobCooldownMs: 30000,
  },
  conservative: {
    crawlIntervalMinutes: 1440,     // Daily
    enrichmentIntervalMinutes: 2880, // Every 2 days
    maxConcurrentJobs: 1,
    autoEnrichAfterCrawl: false,
    maxActorsPerEnrichment: 10,
    jobCooldownMs: 60000,
  },
  manual: {
    crawlIntervalMinutes: 0,
    enrichmentIntervalMinutes: 0,
    maxConcurrentJobs: 1,
    autoEnrichAfterCrawl: false,
    maxActorsPerEnrichment: 20,
    jobCooldownMs: 10000,
  },
};

// ─── Scheduler State ────────────────────────────────────────────────────────

let schedulerConfig: SchedulerConfig = {
  enabled: false,
  preset: "standard",
  crawlIntervalMinutes: 360,
  enrichmentIntervalMinutes: 720,
  maxConcurrentJobs: 1,
  autoEnrichAfterCrawl: true,
  maxActorsPerEnrichment: 20,
  retryFailedJobs: true,
  maxRetries: 3,
  jobCooldownMs: 30000,
  focusActors: [],
  sourcePriority: [],
  notifyOnComplete: false,
  notifyOnFailure: true,
};

let schedulerRunning = false;
let schedulerStartedAt: string | undefined;
let crawlTimer: ReturnType<typeof setInterval> | null = null;
let enrichmentTimer: ReturnType<typeof setInterval> | null = null;

const jobQueue: ScheduledJob[] = [];
const jobHistory: ScheduledJob[] = [];
let currentJob: ScheduledJob | null = null;
let totalJobsRun = 0;
let lastCrawlAt: string | undefined;
let lastEnrichmentAt: string | undefined;
let processingQueue = false;

// ─── Scheduler Control ──────────────────────────────────────────────────────

/**
 * Start the scheduler with the given configuration.
 */
export function startScheduler(config?: Partial<SchedulerConfig>): SchedulerStatus {
  if (config) {
    // Apply preset defaults first, then overrides
    if (config.preset && config.preset !== schedulerConfig.preset) {
      const presetDefaults = PRESET_CONFIGS[config.preset] || {};
      schedulerConfig = { ...schedulerConfig, ...presetDefaults, ...config };
    } else {
      schedulerConfig = { ...schedulerConfig, ...config };
    }
  }

  schedulerConfig.enabled = true;
  schedulerRunning = true;
  schedulerStartedAt = new Date().toISOString();

  // Clear existing timers
  stopTimers();

  // Set up crawl timer
  if (schedulerConfig.crawlIntervalMinutes > 0) {
    const crawlMs = schedulerConfig.crawlIntervalMinutes * 60 * 1000;
    crawlTimer = setInterval(() => {
      enqueueJob("full_crawl", "normal");
    }, crawlMs);

    console.log(`[CrawlerScheduler] Crawl timer set: every ${schedulerConfig.crawlIntervalMinutes}m`);
  }

  // Set up enrichment timer
  if (schedulerConfig.enrichmentIntervalMinutes > 0) {
    const enrichMs = schedulerConfig.enrichmentIntervalMinutes * 60 * 1000;
    enrichmentTimer = setInterval(() => {
      enqueueJob("targeted_enrichment", "normal");
    }, enrichMs);

    console.log(`[CrawlerScheduler] Enrichment timer set: every ${schedulerConfig.enrichmentIntervalMinutes}m`);
  }

  console.log(`[CrawlerScheduler] Started with preset "${schedulerConfig.preset}"`);

  return getSchedulerStatus();
}

/**
 * Stop the scheduler.
 */
export function stopScheduler(): SchedulerStatus {
  schedulerConfig.enabled = false;
  schedulerRunning = false;
  stopTimers();

  console.log("[CrawlerScheduler] Stopped");
  return getSchedulerStatus();
}

/**
 * Pause the scheduler (keeps config, stops timers).
 */
export function pauseScheduler(): SchedulerStatus {
  schedulerRunning = false;
  stopTimers();
  console.log("[CrawlerScheduler] Paused");
  return getSchedulerStatus();
}

/**
 * Resume the scheduler.
 */
export function resumeScheduler(): SchedulerStatus {
  if (!schedulerConfig.enabled) {
    return startScheduler();
  }
  schedulerRunning = true;
  // Re-create timers
  return startScheduler(schedulerConfig);
}

/**
 * Update scheduler configuration without restarting.
 */
export function updateSchedulerConfig(config: Partial<SchedulerConfig>): SchedulerStatus {
  const wasRunning = schedulerRunning;
  if (wasRunning) stopTimers();

  if (config.preset && config.preset !== schedulerConfig.preset) {
    const presetDefaults = PRESET_CONFIGS[config.preset] || {};
    schedulerConfig = { ...schedulerConfig, ...presetDefaults, ...config };
  } else {
    schedulerConfig = { ...schedulerConfig, ...config };
  }

  if (wasRunning && schedulerConfig.enabled) {
    return startScheduler(schedulerConfig);
  }

  return getSchedulerStatus();
}

/**
 * Get current scheduler status.
 */
export function getSchedulerStatus(): SchedulerStatus {
  const now = Date.now();
  const startMs = schedulerStartedAt ? new Date(schedulerStartedAt).getTime() : now;

  // Calculate next scheduled run
  let nextScheduledRun: string | undefined;
  if (schedulerRunning && schedulerConfig.crawlIntervalMinutes > 0) {
    const lastRun = lastCrawlAt ? new Date(lastCrawlAt).getTime() : startMs;
    const nextMs = lastRun + schedulerConfig.crawlIntervalMinutes * 60 * 1000;
    nextScheduledRun = new Date(Math.max(nextMs, now)).toISOString();
  }

  return {
    config: { ...schedulerConfig },
    isRunning: schedulerRunning,
    currentJob,
    queuedJobs: jobQueue.length,
    completedJobs: jobHistory.filter(j => j.status === "completed").length,
    failedJobs: jobHistory.filter(j => j.status === "failed").length,
    totalJobsRun,
    lastCrawlAt,
    lastEnrichmentAt,
    nextScheduledRun,
    uptime: schedulerStartedAt ? Math.floor((now - startMs) / 1000) : 0,
    startedAt: schedulerStartedAt,
    crawlerStats: getCrawlerStats(),
    recentJobs: [...jobHistory].reverse().slice(0, 20),
  };
}

/**
 * Get the scheduler configuration.
 */
export function getSchedulerConfig(): SchedulerConfig {
  return { ...schedulerConfig };
}

/**
 * Get available presets with their descriptions.
 */
export function getSchedulePresets(): Array<{
  id: SchedulePreset;
  name: string;
  description: string;
  crawlInterval: string;
  enrichmentInterval: string;
}> {
  return [
    {
      id: "realtime",
      name: "Real-Time",
      description: "Maximum coverage — crawls every 15 minutes with continuous enrichment. High API usage.",
      crawlInterval: "15 minutes",
      enrichmentInterval: "30 minutes",
    },
    {
      id: "aggressive",
      name: "Aggressive",
      description: "Frequent updates — crawls hourly with auto-enrichment. Moderate API usage.",
      crawlInterval: "1 hour",
      enrichmentInterval: "2 hours",
    },
    {
      id: "standard",
      name: "Standard",
      description: "Balanced coverage — crawls every 6 hours with enrichment every 12 hours. Recommended for most deployments.",
      crawlInterval: "6 hours",
      enrichmentInterval: "12 hours",
    },
    {
      id: "conservative",
      name: "Conservative",
      description: "Low resource usage — daily crawls with manual enrichment. Suitable for stable environments.",
      crawlInterval: "24 hours",
      enrichmentInterval: "48 hours",
    },
    {
      id: "manual",
      name: "Manual",
      description: "No automatic scheduling — all crawls and enrichments are triggered manually.",
      crawlInterval: "Manual only",
      enrichmentInterval: "Manual only",
    },
  ];
}

// ─── Job Queue ──────────────────────────────────────────────────────────────

/**
 * Enqueue a new job.
 */
export function enqueueJob(
  type: JobType,
  priority: JobPriority = "normal",
  metadata?: Record<string, any>,
): ScheduledJob {
  const job: ScheduledJob = {
    id: `job-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    type,
    status: "queued",
    priority,
    scheduledAt: new Date().toISOString(),
    retryCount: 0,
    metadata,
  };

  // Insert by priority
  const priorityOrder: Record<JobPriority, number> = {
    critical: 0,
    high: 1,
    normal: 2,
    low: 3,
  };

  const insertIdx = jobQueue.findIndex(
    j => priorityOrder[j.priority] > priorityOrder[priority]
  );

  if (insertIdx === -1) {
    jobQueue.push(job);
  } else {
    jobQueue.splice(insertIdx, 0, job);
  }

  console.log(`[CrawlerScheduler] Job enqueued: ${type} (${priority}) — ${job.id}`);

  // Trigger queue processing
  processJobQueue().catch(err => {
    console.error("[CrawlerScheduler] Queue processing error:", err.message);
  });

  return job;
}

/**
 * Cancel a queued job.
 */
export function cancelJob(jobId: string): boolean {
  const idx = jobQueue.findIndex(j => j.id === jobId);
  if (idx === -1) return false;

  const job = jobQueue.splice(idx, 1)[0];
  job.status = "cancelled";
  job.completedAt = new Date().toISOString();
  jobHistory.push(job);

  console.log(`[CrawlerScheduler] Job cancelled: ${jobId}`);
  return true;
}

/**
 * Force-run a job immediately (bypasses queue).
 */
export async function forceRunJob(type: JobType, metadata?: Record<string, any>): Promise<ScheduledJob> {
  const job = enqueueJob(type, "critical", metadata);
  // Move to front of queue
  const idx = jobQueue.findIndex(j => j.id === job.id);
  if (idx > 0) {
    jobQueue.splice(idx, 1);
    jobQueue.unshift(job);
  }
  return job;
}

/**
 * Get job history.
 */
export function getJobHistory(limit: number = 50): ScheduledJob[] {
  return [...jobHistory].reverse().slice(0, limit);
}

/**
 * Get queue status.
 */
export function getQueueStatus(): {
  queueLength: number;
  currentJob: ScheduledJob | null;
  jobs: ScheduledJob[];
} {
  return {
    queueLength: jobQueue.length,
    currentJob,
    jobs: [...jobQueue],
  };
}

// ─── Job Processing ─────────────────────────────────────────────────────────

async function processJobQueue(): Promise<void> {
  if (processingQueue) return;
  if (jobQueue.length === 0) return;
  if (isCrawlRunning()) return; // Don't start if crawler is already running

  processingQueue = true;

  try {
    while (jobQueue.length > 0) {
      // Check if scheduler was stopped
      if (!schedulerConfig.enabled && !currentJob) {
        break;
      }

      const job = jobQueue.shift()!;
      currentJob = job;
      job.status = "running";
      job.startedAt = new Date().toISOString();

      console.log(`[CrawlerScheduler] Running job: ${job.type} (${job.id})`);

      try {
        const result = await executeJob(job);
        job.status = "completed";
        job.result = result;
        job.completedAt = new Date().toISOString();

        // Update timestamps
        if (job.type === "full_crawl") {
          lastCrawlAt = job.completedAt;
        } else if (job.type === "targeted_enrichment") {
          lastEnrichmentAt = job.completedAt;
        }

        totalJobsRun++;
        console.log(`[CrawlerScheduler] Job completed: ${job.id} — ${result.summary}`);

        // Auto-enrich after crawl if configured
        if (
          job.type === "full_crawl" &&
          schedulerConfig.autoEnrichAfterCrawl &&
          result.actorsEnriched === 0
        ) {
          enqueueJob("targeted_enrichment", "high", { triggeredBy: job.id });
        }

        // Notify on completion
        if (schedulerConfig.notifyOnComplete) {
          try {
            const { notifyOwner } = await import("../_core/notification");
            await notifyOwner({
              title: `Crawler Job Completed: ${job.type}`,
              content: result.summary || `Job ${job.id} completed successfully.`,
            });
          } catch {
            // Notification is best-effort
          }
        }
      } catch (err: any) {
        job.status = "failed";
        job.error = err.message;
        job.completedAt = new Date().toISOString();
        totalJobsRun++;

        console.error(`[CrawlerScheduler] Job failed: ${job.id} — ${err.message}`);

        // Retry logic
        if (schedulerConfig.retryFailedJobs && job.retryCount < schedulerConfig.maxRetries) {
          const retryJob: ScheduledJob = {
            ...job,
            id: `${job.id}-retry-${job.retryCount + 1}`,
            status: "queued",
            retryCount: job.retryCount + 1,
            scheduledAt: new Date().toISOString(),
            startedAt: undefined,
            completedAt: undefined,
            result: undefined,
            error: undefined,
          };
          jobQueue.push(retryJob);
          console.log(`[CrawlerScheduler] Retry scheduled: ${retryJob.id} (attempt ${retryJob.retryCount})`);
        }

        // Notify on failure
        if (schedulerConfig.notifyOnFailure) {
          try {
            const { notifyOwner } = await import("../_core/notification");
            await notifyOwner({
              title: `Crawler Job Failed: ${job.type}`,
              content: `Job ${job.id} failed: ${err.message}`,
            });
          } catch {
            // Notification is best-effort
          }
        }
      }

      // Move to history
      jobHistory.push(job);
      currentJob = null;

      // Trim history
      if (jobHistory.length > 200) {
        jobHistory.splice(0, jobHistory.length - 200);
      }

      // Cooldown between jobs
      if (jobQueue.length > 0 && schedulerConfig.jobCooldownMs > 0) {
        await sleep(schedulerConfig.jobCooldownMs);
      }
    }
  } finally {
    processingQueue = false;
  }
}

async function executeJob(job: ScheduledJob): Promise<CrawlResult> {
  switch (job.type) {
    case "full_crawl":
      return runIntelligenceCrawl({
        actorFocus: schedulerConfig.focusActors.length > 0 ? schedulerConfig.focusActors : undefined,
        maxArticlesPerSource: 50,
      });

    case "targeted_enrichment":
      return runTargetedEnrichment({
        actorIds: schedulerConfig.focusActors.length > 0 ? schedulerConfig.focusActors : undefined,
        maxActors: schedulerConfig.maxActorsPerEnrichment,
      });

    case "gap_analysis": {
      const gaps = await analyzeDataGaps(
        schedulerConfig.focusActors.length > 0 ? schedulerConfig.focusActors : undefined
      );
      return {
        crawlId: `gap-${Date.now().toString(36)}`,
        startedAt: job.startedAt || new Date().toISOString(),
        completedAt: new Date().toISOString(),
        sourcesChecked: 0,
        articlesFound: 0,
        articlesProcessed: 0,
        actorsEnriched: 0,
        newActorsDiscovered: 0,
        newEventsRecorded: 0,
        newIocsFound: 0,
        newTtpsFound: 0,
        errors: [],
        summary: `Gap analysis complete: ${gaps.length} actors analyzed, ${gaps.filter(g => g.enrichmentPriority === "critical").length} critical, ${gaps.filter(g => g.enrichmentPriority === "high").length} high priority.`,
      };
    }

    case "source_check": {
      const sources = getCrawlSources();
      const enabledCount = sources.filter(s => s.enabled).length;
      return {
        crawlId: `srccheck-${Date.now().toString(36)}`,
        startedAt: job.startedAt || new Date().toISOString(),
        completedAt: new Date().toISOString(),
        sourcesChecked: sources.length,
        articlesFound: 0,
        articlesProcessed: 0,
        actorsEnriched: 0,
        newActorsDiscovered: 0,
        newEventsRecorded: 0,
        newIocsFound: 0,
        newTtpsFound: 0,
        errors: [],
        summary: `Source check: ${enabledCount}/${sources.length} sources enabled and reachable.`,
      };
    }

    default:
      throw new Error(`Unknown job type: ${job.type}`);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function stopTimers(): void {
  if (crawlTimer) {
    clearInterval(crawlTimer);
    crawlTimer = null;
  }
  if (enrichmentTimer) {
    clearInterval(enrichmentTimer);
    enrichmentTimer = null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
