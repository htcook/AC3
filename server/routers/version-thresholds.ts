/**
 * Version Thresholds Router — tRPC API for auto-refresh version thresholds
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Manages the dynamic version threshold system that keeps
 * KNOWN_MIN_SAFE_VERSIONS current by pulling data from NVD CVE API
 * and learning from DI scan detectedTechnologies.
 *
 * Endpoints:
 *   - getAll: List all thresholds (merged static + dynamic)
 *   - getStats: Get refresh stats and health info
 *   - refresh: Trigger manual NVD refresh (all or specific techs)
 *   - set: Manually set a threshold
 *   - delete: Delete a dynamic threshold (reverts to static fallback)
 *   - learnFromScan: Feed DI scan tech data to the learning engine
 *
 * @author Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getAllThresholds,
  getThresholdStats,
  refreshFromNvd,
  learnFromDiScan,
  setManualThreshold,
  deleteThreshold,
  getMinSafeVersion,
  getNvdApiKeyStatus,
} from "../lib/version-threshold-service";

export const versionThresholdsRouter = router({
  /**
   * Get all version thresholds (merged: dynamic DB + static fallback).
   */
  getAll: protectedProcedure.query(async () => {
    return getAllThresholds();
  }),

  /**
   * Get threshold stats: counts by source, refresh history, stale count.
   */
  getStats: protectedProcedure.query(async () => {
    return getThresholdStats();
  }),

  /**
   * Get NVD API key configuration status.
   * Shows whether an API key is configured and the resulting rate limits.
   */
  nvdApiKeyStatus: protectedProcedure.query(() => {
    return getNvdApiKeyStatus();
  }),

  /**
   * Get the minimum safe version for a specific technology.
   */
  getForTech: protectedProcedure
    .input(z.object({ technology: z.string() }))
    .query(async ({ input }) => {
      const minSafe = getMinSafeVersion(input.technology);
      return { technology: input.technology, minSafeVersion: minSafe };
    }),

  /**
   * Trigger a manual NVD refresh for all or specific technologies.
   */
  refresh: protectedProcedure
    .input(
      z.object({
        technologies: z.array(z.string()).optional(),
      }).optional()
    )
    .mutation(async ({ input }) => {
      const result = await refreshFromNvd(input?.technologies);
      return result;
    }),

  /**
   * Manually set a version threshold.
   */
  set: protectedProcedure
    .input(
      z.object({
        technology: z.string().min(1),
        minSafeVersion: z.string().min(1),
        notes: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const threshold = setManualThreshold(
        input.technology,
        input.minSafeVersion,
        input.notes,
      );
      return threshold;
    }),

  /**
   * Delete a dynamic threshold (reverts to static fallback).
   */
  delete: protectedProcedure
    .input(z.object({ technology: z.string() }))
    .mutation(async ({ input }) => {
      const deleted = deleteThreshold(input.technology);
      return { deleted, technology: input.technology };
    }),

  /**
   * Feed DI scan detected technologies to the learning engine.
   * Called automatically after each DI scan completes.
   */
  learnFromScan: protectedProcedure
    .input(
      z.object({
        technologies: z.array(
          z.object({
            name: z.string(),
            version: z.string().optional(),
            category: z.string().optional(),
          })
        ),
      })
    )
    .mutation(async ({ input }) => {
      const result = learnFromDiScan(input.technologies);
      return result;
    }),
});
