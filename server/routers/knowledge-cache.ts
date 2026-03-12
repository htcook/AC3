/**
 * Knowledge Cache Diagnostics Router
 *
 * Admin-only endpoints for monitoring and managing the knowledge data cache.
 * The knowledge loader fetches large JSON datasets from the DO scan server
 * and caches them in memory with a 6-hour TTL (stale-while-revalidate).
 *
 * Endpoints:
 *   - stats: Returns cache entry ages, refresh status, and hit/miss info
 *   - invalidate: Force-clears one or all cached entries so the next access re-fetches
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getKnowledgeCacheStats,
  invalidateKnowledgeCache,
} from "../lib/knowledge/knowledge-loader";

// Admin guard
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  }
  return next({ ctx });
});

export const knowledgeCacheRouter = router({
  /**
   * Get cache diagnostics — returns per-file age, refresh status.
   */
  stats: adminProcedure.query(() => {
    const entries = getKnowledgeCacheStats();
    const CACHE_TTL_MINUTES = 360; // 6 hours
    return {
      ttlMinutes: CACHE_TTL_MINUTES,
      entries: entries.map((e) => ({
        ...e,
        stale: e.ageMinutes >= CACHE_TTL_MINUTES,
        expiresInMinutes: Math.max(0, CACHE_TTL_MINUTES - e.ageMinutes),
      })),
      totalCached: entries.length,
      staleCount: entries.filter((e) => e.ageMinutes >= CACHE_TTL_MINUTES).length,
      refreshingCount: entries.filter((e) => e.refreshing).length,
    };
  }),

  /**
   * Force-invalidate cached knowledge data.
   * Pass a filename to invalidate a single entry, or omit to clear all.
   */
  invalidate: adminProcedure
    .input(
      z.object({
        filename: z.string().optional(),
      })
    )
    .mutation(({ input }) => {
      invalidateKnowledgeCache(input.filename);
      return {
        success: true,
        invalidated: input.filename || "all",
        message: input.filename
          ? `Cache entry "${input.filename}" invalidated. Next access will re-fetch from DO.`
          : "All cache entries invalidated. Next access will re-fetch from DO.",
      };
    }),
});
