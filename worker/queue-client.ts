/**
 * Queue Client — Enqueue jobs from the API server to the worker process.
 * 
 * Usage from tRPC procedures:
 *   import { enqueuePassiveScan, enqueueActiveScan } from '../../worker/queue-client';
 *   
 *   // In a mutation:
 *   await enqueuePassiveScan({ engagementId: 123, userId: '1', targets: [...] });
 * 
 * When REDIS_URL is not set, jobs execute inline (same-process fallback).
 */

import { QUEUE_NAMES } from './index';
import type { PassiveScanJob, ActiveScanJob, ThreatIntelJob, ReportGenJob, ValidationJob } from './index';

let _queues: Record<string, any> | null = null;

async function getQueues() {
  if (_queues) return _queues;

  const REDIS_URL = process.env.REDIS_URL;
  if (!REDIS_URL) {
    console.log('[QueueClient] No REDIS_URL — jobs will execute inline (single-process mode)');
    return null;
  }

  try {
    const { Queue } = await import('bullmq');
    const connection = { url: REDIS_URL };

    _queues = {
      [QUEUE_NAMES.PASSIVE_SCAN]: new Queue(QUEUE_NAMES.PASSIVE_SCAN, { connection }),
      [QUEUE_NAMES.ACTIVE_SCAN]: new Queue(QUEUE_NAMES.ACTIVE_SCAN, { connection }),
      [QUEUE_NAMES.THREAT_INTEL]: new Queue(QUEUE_NAMES.THREAT_INTEL, { connection }),
      [QUEUE_NAMES.REPORT_GEN]: new Queue(QUEUE_NAMES.REPORT_GEN, { connection }),
      [QUEUE_NAMES.VALIDATION]: new Queue(QUEUE_NAMES.VALIDATION, { connection }),
    };

    console.log('[QueueClient] Connected to Redis, job queues initialized');
    return _queues;
  } catch {
    console.warn('[QueueClient] BullMQ not available — falling back to inline execution');
    return null;
  }
}

/**
 * Check if worker mode is available (Redis + BullMQ configured)
 */
export async function isWorkerMode(): Promise<boolean> {
  const queues = await getQueues();
  return queues !== null;
}

/**
 * Enqueue a passive scan job. Returns job ID if queued, null if inline.
 */
export async function enqueuePassiveScan(data: PassiveScanJob): Promise<string | null> {
  const queues = await getQueues();
  if (!queues) return null; // Caller should fall back to inline execution

  const job = await queues[QUEUE_NAMES.PASSIVE_SCAN].add('passive-scan', data, {
    attempts: 2,
    backoff: { type: 'exponential', delay: 30_000 },
    removeOnComplete: { age: 86400 }, // Keep completed jobs for 24h
    removeOnFail: { age: 604800 },    // Keep failed jobs for 7 days
  });

  return job.id;
}

/**
 * Enqueue an active scan job.
 */
export async function enqueueActiveScan(data: ActiveScanJob): Promise<string | null> {
  const queues = await getQueues();
  if (!queues) return null;

  const job = await queues[QUEUE_NAMES.ACTIVE_SCAN].add('active-scan', data, {
    attempts: 1, // Active scans should not auto-retry (destructive)
    removeOnComplete: { age: 86400 },
    removeOnFail: { age: 604800 },
  });

  return job.id;
}

/**
 * Enqueue a threat intel feed ingestion job.
 */
export async function enqueueThreatIntelFeed(data: ThreatIntelJob): Promise<string | null> {
  const queues = await getQueues();
  if (!queues) return null;

  const job = await queues[QUEUE_NAMES.THREAT_INTEL].add('threat-intel', data, {
    attempts: 3,
    backoff: { type: 'exponential', delay: 60_000 },
    removeOnComplete: { age: 3600 },
    removeOnFail: { age: 86400 },
  });

  return job.id;
}

/**
 * Enqueue a report generation job.
 */
export async function enqueueReportGen(data: ReportGenJob): Promise<string | null> {
  const queues = await getQueues();
  if (!queues) return null;

  const job = await queues[QUEUE_NAMES.REPORT_GEN].add('report-gen', data, {
    attempts: 2,
    backoff: { type: 'fixed', delay: 10_000 },
    removeOnComplete: { age: 86400 },
    removeOnFail: { age: 86400 },
  });

  return job.id;
}
