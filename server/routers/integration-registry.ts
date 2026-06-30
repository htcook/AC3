/**
 * Integration Registry Router — tRPC API for the Integration Management System
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Exposes the full integration registry to the frontend:
 *   - Browse catalog (built-in + customer-added)
 *   - Discover & classify new APIs (LLM-powered)
 *   - Review & approve proposals (human-in-the-loop)
 *   - Manage lifecycle (activate, pause, remove)
 *   - Pipeline coverage analysis
 *   - API health monitoring with periodic checks
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  getAllIntegrations,
  getIntegration,
  getIntegrationsByCategory,
  getIntegrationsByStage,
  getCustomerIntegrations,
  getIntegrationsByStatus,
  getCategorySummary,
  discoverNewSource,
  submitCustomerReview,
  activateIntegration,
  pauseIntegration,
  removeIntegration,
  getPipelineCoverageReport,
  getHealthSummary,
  BUILTIN_CATALOG,
  CATEGORY_METADATA,
  PIPELINE_STAGE_METADATA,
} from "../lib/integration-registry";
import type {
  IntegrationCategory,
  IntegrationStatus,
  PipelineStage,
} from "../lib/integration-registry";

// ═══════════════════════════════════════════════════════════════════════
// Zod schemas
// ═══════════════════════════════════════════════════════════════════════

const categoryEnum = z.enum([
  "osint", "exploit_db", "threat_intel", "scanner", "pentest_tool",
  "phishing", "c2", "siem_soar", "cloud", "credential", "custom",
]);

const stageEnum = z.enum([
  "recon", "passive_discovery", "enumeration", "vuln_detection",
  "social_engineering", "exploitation", "post_exploit", "reporting",
  "monitoring", "enrichment",
]);

const statusEnum = z.enum([
  "proposed", "review", "approved", "active", "paused", "rejected", "error", "deprecated",
]);

// ═══════════════════════════════════════════════════════════════════════
// Router
// ═══════════════════════════════════════════════════════════════════════

export const integrationRegistryRouter = router({
  // ─── Catalog Browsing ─────────────────────────────────────────────

  /** Get all integrations (built-in + customer) */
  getAll: protectedProcedure.query(async () => {
    return getAllIntegrations();
  }),

  /** Get a single integration by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      return (await getIntegration(input.id)) ?? null;
    }),

  /** Get integrations by category */
  getByCategory: protectedProcedure
    .input(z.object({ category: categoryEnum }))
    .query(async ({ input }) => {
      return getIntegrationsByCategory(input.category as IntegrationCategory);
    }),

  /** Get integrations by pipeline stage */
  getByStage: protectedProcedure
    .input(z.object({ stage: stageEnum }))
    .query(async ({ input }) => {
      return getIntegrationsByStage(input.stage as PipelineStage);
    }),

  /** Get customer-added integrations only */
  getCustomer: protectedProcedure.query(async () => {
    return getCustomerIntegrations();
  }),

  /** Get integrations by status */
  getByStatus: protectedProcedure
    .input(z.object({ status: statusEnum }))
    .query(async ({ input }) => {
      return getIntegrationsByStatus(input.status as IntegrationStatus);
    }),

  /** Get category summary with counts */
  getCategorySummary: protectedProcedure.query(async () => {
    return getCategorySummary();
  }),

  /** Get category metadata */
  getCategoryMetadata: protectedProcedure.query(() => {
    return CATEGORY_METADATA;
  }),

  /** Get pipeline stage metadata */
  getStageMetadata: protectedProcedure.query(() => {
    return PIPELINE_STAGE_METADATA;
  }),

  /** Get built-in catalog only */
  getBuiltIn: protectedProcedure.query(() => {
    return BUILTIN_CATALOG;
  }),

  // ─── Discovery & Classification ───────────────────────────────────

  /** Discover and classify a new API source */
  discover: protectedProcedure
    .input(z.object({
      baseUrl: z.string().url(),
      apiKey: z.string().optional(),
      apiKeyHeader: z.string().optional(),
      docsUrl: z.string().url().optional(),
      customerDescription: z.string().optional(),
      customerName: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return discoverNewSource(input);
    }),

  // ─── Customer Review & Approval ───────────────────────────────────

  /** Submit a customer review for a discovered integration */
  submitReview: protectedProcedure
    .input(z.object({
      discoveryId: z.string(),
      approved: z.boolean(),
      correctedCategory: categoryEnum.optional(),
      correctedPipelineStages: z.array(stageEnum).optional(),
      correctedDataTypes: z.array(z.string()).optional(),
      notes: z.string().optional(),
      priority: z.number().min(1).max(5).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      return submitCustomerReview(input.discoveryId, {
        approved: input.approved,
        correctedCategory: input.correctedCategory as IntegrationCategory | undefined,
        correctedPipelineStages: input.correctedPipelineStages as PipelineStage[] | undefined,
        correctedDataTypes: input.correctedDataTypes,
        notes: input.notes,
        priority: input.priority,
        reviewedBy: ctx.user.id,
        reviewedAt: Date.now(),
      });
    }),

  // ─── Lifecycle Management ─────────────────────────────────────────

  /** Activate an approved integration */
  activate: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      return activateIntegration(input.id);
    }),

  /** Pause an active integration */
  pause: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      return pauseIntegration(input.id);
    }),

  /** Remove a customer integration */
  remove: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      return removeIntegration(input.id);
    }),

  // ─── Pipeline Coverage & Health ───────────────────────────────────

  /** Get pipeline coverage report */
  getCoverage: protectedProcedure.query(async () => {
    return getPipelineCoverageReport();
  }),

  /** Get integration health summary */
  getHealth: protectedProcedure.query(async () => {
    return getHealthSummary();
  }),

  // ─── Health Monitoring ────────────────────────────────────────────

  /** Get health check history for a specific integration */
  getHealthHistory: protectedProcedure
    .input(z.object({
      integrationId: z.string(),
      hoursBack: z.number().min(1).max(168).default(24),
    }))
    .query(async ({ input }) => {
      const { getHealthCheckHistory } = await import("../db");
      return getHealthCheckHistory(input.integrationId, input.hoursBack);
    }),

  /** Get latest health status for all customer integrations */
  getHealthDashboard: protectedProcedure.query(async () => {
    const { getLatestHealthCheckPerIntegration, getAllCustomerIntegrations } = await import("../db");
    const [healthChecks, integrations] = await Promise.all([
      getLatestHealthCheckPerIntegration(),
      getAllCustomerIntegrations(),
    ]);

    const healthMap = new Map(healthChecks.map(h => [h.integrationId, h]));

    return integrations.map(integ => ({
      integrationId: integ.integrationId,
      displayName: integ.displayName,
      category: integ.category,
      status: integ.status,
      lastHealthCheck: healthMap.get(integ.integrationId) || null,
      lastHealthStatus: integ.lastHealthStatus,
      totalCalls: integ.totalCalls,
      totalErrors: integ.totalErrors,
      avgLatencyMs: integ.avgLatencyMs,
    }));
  }),

  /** Trigger an immediate health check for a specific integration */
  triggerHealthCheck: protectedProcedure
    .input(z.object({ integrationId: z.string() }))
    .mutation(async ({ input }) => {
      const { runHealthCheckForIntegration } = await import("../lib/integration-registry/health-monitor");
      return runHealthCheckForIntegration(input.integrationId);
    }),

  /** Get execution logs for an integration */
  getExecutionLogs: protectedProcedure
    .input(z.object({
      integrationId: z.string(),
      limit: z.number().min(1).max(200).default(50),
    }))
    .query(async ({ input }) => {
      const { getExecutionLogsByIntegration } = await import("../db");
      return getExecutionLogsByIntegration(input.integrationId, input.limit);
    }),

  // ─── Test Mode ────────────────────────────────────────────────────

  /** Run a test probe against a new API (without full classification) */
  testProbe: protectedProcedure
    .input(z.object({
      baseUrl: z.string().url(),
      apiKey: z.string().optional(),
      apiKeyHeader: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { probeApi } = await import("../lib/integration-registry/auto-discovery-engine");
      return probeApi(input);
    }),
});
