/**
 * Job Queue Router — Redis-backed job dispatch management
 *
 * Provides endpoints for monitoring and managing the job queue,
 * worker health, and dispatching scan/recon/feed jobs.
 */
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { getDb } from "../db";
import { eq, desc, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const jobQueueRouter = router({
  /** Get queue statistics */
  stats: protectedProcedure.query(async () => {
    const { getQueueStats, getWorkers } = await import("../lib/job-queue");
    const stats = getQueueStats();
    const workers = getWorkers();

    return {
      ...stats,
      workerDetails: workers.map((w) => ({
        id: w.id,
        host: w.host,
        region: w.region,
        types: w.type,
        healthy: w.healthy,
        activeJobs: w.activeJobs,
        maxJobs: w.maxJobs,
        fipsCompliant: w.fipsCompliant,
        vpcOnly: w.vpcOnly,
        lastHeartbeat: w.lastHeartbeat,
      })),
    };
  }),

  /** Get job status by ID */
  getJob: protectedProcedure
    .input(z.object({ jobId: z.string() }))
    .query(async ({ input }) => {
      const { getJobStatus } = await import("../lib/job-queue");
      return getJobStatus(input.jobId);
    }),

  /** Cancel a job */
  cancelJob: protectedProcedure
    .input(z.object({ jobId: z.string() }))
    .mutation(async ({ input }) => {
      const { cancelJob } = await import("../lib/job-queue");
      const cancelled = cancelJob(input.jobId);
      if (!cancelled) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Job not found or already completed" });
      }
      return { success: true, jobId: input.jobId };
    }),

  /** Dispatch a scan job */
  dispatchScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string()).min(1),
      tool: z.string(),
      args: z.string().default(""),
      roeScope: z.array(z.string()),
      timeoutSeconds: z.number().default(300),
      sudo: z.boolean().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      const { dispatchScanJob } = await import("../lib/job-queue");
      const result = await dispatchScanJob({
        ...input,
        operatorId: ctx.user?.name || ctx.user?.openId,
      });
      return result;
    }),

  /** Dispatch a recon job */
  dispatchRecon: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string()).min(1),
      connectors: z.array(z.string()),
      depth: z.enum(["shallow", "standard", "deep"]).default("standard"),
      roeScope: z.array(z.string()),
    }))
    .mutation(async ({ input, ctx }) => {
      const { dispatchReconJob } = await import("../lib/job-queue");
      const result = await dispatchReconJob({
        ...input,
        operatorId: ctx.user?.name || ctx.user?.openId,
      });
      return result;
    }),

  /** Get job history from database */
  history: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
      jobType: z.enum(["scan", "recon", "feed", "c2", "all"]).default("all"),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { items: [], total: 0 };

      const filters = input || { limit: 50, offset: 0, jobType: "all" };
      const conditions = filters.jobType !== "all"
        ? eq(schema.jobQueueEntries.jobType, filters.jobType)
        : undefined;

      const [items, countResult] = await Promise.all([
        db.select()
          .from(schema.jobQueueEntries)
          .where(conditions)
          .orderBy(desc(schema.jobQueueEntries.createdAt))
          .limit(filters.limit)
          .offset(filters.offset),
        db.select({ count: sql<number>`count(*)` })
          .from(schema.jobQueueEntries)
          .where(conditions),
      ]);

      return { items, total: countResult[0]?.count || 0 };
    }),

  /** Get FIPS DO infrastructure status */
  infraStatus: protectedProcedure.query(async () => {
    const { getInfrastructureSummary } = await import("../lib/fips-do-infrastructure");
    return getInfrastructureSummary();
  }),

  /** Run FIPS compliance check */
  complianceCheck: protectedProcedure.mutation(async () => {
    const { runComplianceCheck } = await import("../lib/fips-do-infrastructure");
    return runComplianceCheck();
  }),

  /** Get FIPS audit log */
  auditLog: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(500).default(100) }).optional())
    .query(async ({ input }) => {
      const { getAuditLog } = await import("../lib/fips-do-infrastructure");
      return getAuditLog(input?.limit || 100);
    }),

  /** Get key rotation schedules */
  keyRotation: protectedProcedure.query(async () => {
    const { getKeyRotationSchedules, getOverdueRotations } = await import("../lib/fips-do-infrastructure");
    return {
      schedules: getKeyRotationSchedules(),
      overdue: getOverdueRotations(),
    };
  }),

  /** Get ops state recovery info */
  opsStateHistory: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getSnapshotHistory } = await import("../lib/ops-state-persistence");
      return getSnapshotHistory(input.engagementId);
    }),
});
