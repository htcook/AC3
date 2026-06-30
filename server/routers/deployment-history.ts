/**
 * Deployment History Router
 *
 * tRPC procedures for recording, listing, and managing monitoring stack deployments.
 * Tracks deployment configs, status, and provides config diff comparisons.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  createDeployment,
  listDeployments,
  getDeploymentById,
  updateDeploymentStatus,
  getDeploymentStats,
} from "../db";
import { randomUUID } from "crypto";

const configSnapshotSchema = z.object({
  ecsClusterName: z.string(),
  ecsServiceName: z.string(),
  cpuThreshold: z.number().min(1).max(100),
  memoryThreshold: z.number().min(1).max(100),
  alb5xxThreshold: z.number().min(0),
  alb4xxThreshold: z.number().min(0),
  responseTimeThreshold: z.number().min(0),
  slackWebhookUrl: z.string().optional().default(""),
  alertEmail: z.string().optional().default(""),
});

export const deploymentHistoryRouter = router({
  /** Record a new deployment */
  record: protectedProcedure
    .input(z.object({
      environment: z.enum(["dev", "staging", "prod"]),
      region: z.string().min(1),
      stackName: z.string().min(1),
      stackVersion: z.string().optional(),
      configSnapshot: configSnapshotSchema,
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const deploymentId = `deploy-${randomUUID().slice(0, 8)}`;
      const id = await createDeployment({
        deploymentId,
        userId: ctx.user.id,
        environment: input.environment,
        region: input.region,
        stackName: input.stackName,
        stackVersion: input.stackVersion ?? null,
        status: "pending",
        configSnapshot: input.configSnapshot,
        resourceCount: 17,
        notes: input.notes ?? null,
      });
      return { id, deploymentId };
    }),

  /** List all deployments with optional environment filter */
  list: protectedProcedure
    .input(z.object({
      environment: z.enum(["dev", "staging", "prod"]).optional(),
      limit: z.number().min(1).max(200).optional(),
    }).optional())
    .query(async ({ input }) => {
      return listDeployments({
        environment: input?.environment,
        limit: input?.limit,
      });
    }),

  /** Get a single deployment by ID */
  get: protectedProcedure
    .input(z.object({ deploymentId: z.string() }))
    .query(async ({ input }) => {
      return getDeploymentById(input.deploymentId);
    }),

  /** Update deployment status */
  updateStatus: protectedProcedure
    .input(z.object({
      deploymentId: z.string(),
      status: z.enum(["pending", "in_progress", "success", "failed", "rolled_back"]),
      errorMessage: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      await updateDeploymentStatus(input.deploymentId, input.status, input.errorMessage);
      return { success: true };
    }),

  /** Get deployment statistics */
  stats: protectedProcedure
    .query(async () => {
      return getDeploymentStats();
    }),

  /** Compare two deployment configs */
  compareConfigs: protectedProcedure
    .input(z.object({
      deploymentIdA: z.string(),
      deploymentIdB: z.string(),
    }))
    .query(async ({ input }) => {
      const [a, b] = await Promise.all([
        getDeploymentById(input.deploymentIdA),
        getDeploymentById(input.deploymentIdB),
      ]);
      if (!a || !b) return { error: "One or both deployments not found", diffs: [] };

      const configA = a.configSnapshot as Record<string, any>;
      const configB = b.configSnapshot as Record<string, any>;
      const allKeys = new Set([...Object.keys(configA), ...Object.keys(configB)]);
      const diffs: { field: string; valueA: any; valueB: any; changed: boolean }[] = [];

      for (const key of allKeys) {
        diffs.push({
          field: key,
          valueA: configA[key] ?? null,
          valueB: configB[key] ?? null,
          changed: JSON.stringify(configA[key]) !== JSON.stringify(configB[key]),
        });
      }

      return {
        deploymentA: { id: a.deploymentId, environment: a.environment, createdAt: a.createdAt },
        deploymentB: { id: b.deploymentId, environment: b.environment, createdAt: b.createdAt },
        diffs,
        changedCount: diffs.filter(d => d.changed).length,
      };
    }),
});
