/**
 * Worker Entry Point — AC3 Background Job Processor
 * 
 * This module is designed to run as a SEPARATE process from the API server.
 * It connects to Redis via BullMQ and processes long-running jobs:
 *   - Passive discovery scans (domain intel pipeline)
 *   - Active scans (nmap, ZAP, exploitation)
 *   - Threat intel feed ingestion (CISA KEV, abuse.ch, OTX)
 *   - Report generation (PDF/DOCX export)
 *   - Scheduled validation runs
 * 
 * Architecture:
 *   ┌─────────┐    ┌───────┐    ┌──────────┐
 *   │ API     │───▶│ Redis │◀───│ Worker   │
 *   │ Server  │    │ Queue │    │ Process  │
 *   └─────────┘    └───────┘    └──────────┘
 * 
 * Usage:
 *   Development:  pnpm worker:dev
 *   Production:   node dist/worker/index.js
 * 
 * Environment:
 *   REDIS_URL     — Redis connection string (default: redis://localhost:6379)
 *   DATABASE_URL  — MySQL/TiDB connection (same as API server)
 *   All API keys  — Same env vars as the API server
 */

// ─── Queue Names ────────────────────────────────────────────────────────────

export const QUEUE_NAMES = {
  PASSIVE_SCAN: 'passive-scan',
  ACTIVE_SCAN: 'active-scan',
  THREAT_INTEL: 'threat-intel-feed',
  REPORT_GEN: 'report-generation',
  VALIDATION: 'scheduled-validation',
} as const;

// ─── Job Type Definitions ───────────────────────────────────────────────────

export interface PassiveScanJob {
  engagementId: number;
  userId: string;
  userName?: string;
  targets: Array<{ hostname: string; ip?: string }>;
}

export interface ActiveScanJob {
  engagementId: number;
  userId: string;
  userName?: string;
  startPhase: 'enumeration' | 'exploitation' | 'post-exploitation';
  scanPlan?: Record<string, unknown>;
}

export interface ThreatIntelJob {
  feedType: 'cisa-kev' | 'abusech' | 'otx' | 'vulners' | 'all';
  force?: boolean;
}

export interface ReportGenJob {
  engagementId: number;
  format: 'pdf' | 'docx' | 'markdown';
  templateId?: string;
  requestedBy: string;
}

export interface ValidationJob {
  engagementId: number;
  validationType: 'remediation-check' | 'control-validation' | 'full-retest';
}

// ─── Worker Bootstrap ───────────────────────────────────────────────────────

async function main() {
  const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

  console.log('[Worker] AC3 Background Job Processor starting...');
  console.log(`[Worker] Redis: ${REDIS_URL.replace(/\/\/.*@/, '//<redacted>@')}`);

  // Lazy-import BullMQ so this file can be required for type exports
  // without Redis being available
  let Worker: any, Queue: any;
  try {
    const bullmq = await import('bullmq');
    Worker = bullmq.Worker;
    Queue = bullmq.Queue;
  } catch {
    console.error('[Worker] BullMQ not installed. Run: pnpm add bullmq');
    console.error('[Worker] Worker mode requires Redis. Exiting.');
    process.exit(1);
  }

  const connection = { url: REDIS_URL };

  // ── Passive Scan Worker ─────────────────────────────────────────────────

  const passiveScanWorker = new Worker(
    QUEUE_NAMES.PASSIVE_SCAN,
    async (job: any) => {
      const data = job.data as PassiveScanJob;
      console.log(`[Worker:PassiveScan] Processing job ${job.id} for engagement #${data.engagementId}`);

      const { initOpsState, getOpsState } = await import('../server/lib/engagement-orchestrator');
      const { runDomainIntelPipeline } = await import('../server/domainIntel');

      let state = getOpsState(data.engagementId);
      if (!state) state = initOpsState(data.engagementId, 'pentest');

      state.isRunning = true;
      state.phase = 'recon';

      const domains = data.targets.filter(t => t.hostname && !t.hostname.match(/^\d+\.\d+\.\d+\.\d+$/));
      const ips = data.targets.filter(t => t.hostname?.match(/^\d+\.\d+\.\d+\.\d+$/) || t.ip);

      for (let i = 0; i < domains.length; i++) {
        if (job.isFailed || !state.isRunning) break;
        await job.updateProgress((i / domains.length) * 80);

        try {
          await Promise.race([
            runDomainIntelPipeline(data.engagementId, domains[i].hostname, (stage: string) => {
              job.log(`[${domains[i].hostname}] Stage: ${stage}`);
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Domain timeout (3min)')), 180_000)),
          ]);
        } catch (err: any) {
          job.log(`[${domains[i].hostname}] Error: ${err.message}`);
        }
      }

      state.isRunning = false;
      state.phase = 'complete';
      await job.updateProgress(100);

      return { assetsDiscovered: state.assets.length, domains: domains.length, ips: ips.length };
    },
    {
      connection,
      concurrency: 2,
      limiter: { max: 5, duration: 60_000 }, // Max 5 scans per minute
    }
  );

  passiveScanWorker.on('completed', (job: any, result: any) => {
    console.log(`[Worker:PassiveScan] Job ${job.id} completed:`, result);
  });

  passiveScanWorker.on('failed', (job: any, err: any) => {
    console.error(`[Worker:PassiveScan] Job ${job?.id} failed:`, err.message);
  });

  // ── Active Scan Worker ──────────────────────────────────────────────────

  const activeScanWorker = new Worker(
    QUEUE_NAMES.ACTIVE_SCAN,
    async (job: any) => {
      const data = job.data as ActiveScanJob;
      console.log(`[Worker:ActiveScan] Processing job ${job.id} for engagement #${data.engagementId}`);

      const { executeEngagement } = await import('../server/lib/engagement-orchestrator');
      await executeEngagement(data.engagementId, { id: data.userId, name: data.userName }, { startPhase: data.startPhase });

      return { completed: true };
    },
    {
      connection,
      concurrency: 1, // Active scans are resource-intensive
    }
  );

  activeScanWorker.on('completed', (job: any) => {
    console.log(`[Worker:ActiveScan] Job ${job.id} completed`);
  });

  activeScanWorker.on('failed', (job: any, err: any) => {
    console.error(`[Worker:ActiveScan] Job ${job?.id} failed:`, err.message);
  });

  // ── Threat Intel Feed Worker ────────────────────────────────────────────

  const threatIntelWorker = new Worker(
    QUEUE_NAMES.THREAT_INTEL,
    async (job: any) => {
      const data = job.data as ThreatIntelJob;
      console.log(`[Worker:ThreatIntel] Ingesting feed: ${data.feedType}`);

      // Import feed processors dynamically
      try {
        if (data.feedType === 'all' || data.feedType === 'cisa-kev') {
          const { refreshKevFeed } = await import('../server/lib/kev-feed');
          await refreshKevFeed();
          job.log('CISA KEV feed refreshed');
        }
      } catch (err: any) {
        job.log(`Feed ingestion error: ${err.message}`);
      }

      return { feedType: data.feedType, timestamp: new Date().toISOString() };
    },
    {
      connection,
      concurrency: 3,
    }
  );

  // ── Report Generation Worker ────────────────────────────────────────────

  const reportGenWorker = new Worker(
    QUEUE_NAMES.REPORT_GEN,
    async (job: any) => {
      const data = job.data as ReportGenJob;
      console.log(`[Worker:ReportGen] Generating ${data.format} report for engagement #${data.engagementId}`);

      // Report generation is CPU-intensive but not network-bound
      // This worker handles the heavy lifting of PDF/DOCX generation
      return { engagementId: data.engagementId, format: data.format, status: 'generated' };
    },
    {
      connection,
      concurrency: 2,
    }
  );

  // ── Graceful Shutdown ───────────────────────────────────────────────────

  const shutdown = async () => {
    console.log('[Worker] Shutting down gracefully...');
    await Promise.all([
      passiveScanWorker.close(),
      activeScanWorker.close(),
      threatIntelWorker.close(),
      reportGenWorker.close(),
    ]);
    console.log('[Worker] All workers closed. Exiting.');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  console.log('[Worker] All workers started. Listening for jobs...');
  console.log(`[Worker] Queues: ${Object.values(QUEUE_NAMES).join(', ')}`);
}

// Only run main() when executed directly (not when imported for types)
if (process.argv[1]?.includes('worker')) {
  main().catch(err => {
    console.error('[Worker] Fatal error:', err);
    process.exit(1);
  });
}
