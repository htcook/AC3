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
  getAll: protectedProcedure.query(() => {
    return getAllIntegrations();
  }),

  /** Get a single integration by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      return getIntegration(input.id) ?? null;
    }),

  /** Get integrations by category */
  getByCategory: protectedProcedure
    .input(z.object({ category: categoryEnum }))
    .query(({ input }) => {
      return getIntegrationsByCategory(input.category as IntegrationCategory);
    }),

  /** Get integrations by pipeline stage */
  getByStage: protectedProcedure
    .input(z.object({ stage: stageEnum }))
    .query(({ input }) => {
      return getIntegrationsByStage(input.stage as PipelineStage);
    }),

  /** Get customer-added integrations only */
  getCustomer: protectedProcedure.query(() => {
    return getCustomerIntegrations();
  }),

  /** Get integrations by status */
  getByStatus: protectedProcedure
    .input(z.object({ status: statusEnum }))
    .query(({ input }) => {
      return getIntegrationsByStatus(input.status as IntegrationStatus);
    }),

  /** Get category summary with counts */
  getCategorySummary: protectedProcedure.query(() => {
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
    .mutation(({ input, ctx }) => {
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
    .mutation(({ input }) => {
      return activateIntegration(input.id);
    }),

  /** Pause an active integration */
  pause: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      return pauseIntegration(input.id);
    }),

  /** Remove a customer integration */
  remove: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      return removeIntegration(input.id);
    }),

  // ─── Pipeline Coverage & Health ───────────────────────────────────

  /** Get pipeline coverage report */
  getCoverage: protectedProcedure.query(() => {
    return getPipelineCoverageReport();
  }),

  /** Get integration health summary */
  getHealth: protectedProcedure.query(() => {
    return getHealthSummary();
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
      // Import probeApi directly for lightweight testing
      const { probeApi } = await import("../lib/integration-registry/auto-discovery-engine");
      return probeApi(input);
    }),
});
