/**
 * Customer Intelligence Profile Router
 * 
 * tRPC procedures for managing customer intelligence profiles —
 * cumulative cross-engagement data models that track posture trends,
 * recurring weaknesses, technology changes, and strategic recommendations.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getOrCreateProfile,
  getProfile,
  listProfiles,
  updateProfileFromEngagement,
  incrementDIScanCount,
} from "../lib/customer-intel-profile";

export const customerIntelProfileRouter = router({
  /**
   * Get a customer intelligence profile by customer ID.
   * Creates one if it doesn't exist.
   */
  getProfile: protectedProcedure
    .input(z.object({
      customerId: z.string().min(1),
      customerName: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const profile = await getProfile(input.customerId);
      if (profile) return { profile };

      // Auto-create if name provided
      if (input.customerName) {
        const created = await getOrCreateProfile(input.customerId, input.customerName);
        return { profile: created };
      }

      return { profile: null };
    }),

  /**
   * List all customer profiles (paginated)
   */
  listProfiles: protectedProcedure
    .input(z.object({
      limit: z.number().int().min(1).max(100).optional(),
      offset: z.number().int().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      const profiles = await listProfiles({
        limit: input?.limit ?? 50,
        offset: input?.offset ?? 0,
      });
      return { profiles };
    }),

  /**
   * Update a customer profile from an engagement snapshot.
   * Called when an engagement completes or when manually triggered.
   */
  updateFromEngagement: protectedProcedure
    .input(z.object({
      engagementId: z.number().int(),
      date: z.string(),
      customerId: z.string().min(1),
      customerName: z.string().min(1),
      findings: z.object({
        total: z.number().int(),
        critical: z.number().int(),
        high: z.number().int(),
        medium: z.number().int(),
        low: z.number().int(),
      }),
      assets: z.object({
        total: z.number().int(),
        hosts: z.number().int(),
        services: z.number().int(),
        exposedPorts: z.number().int(),
      }),
      technologies: z.array(z.string()).optional(),
      weaknessCategories: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      await updateProfileFromEngagement(input);
      const updated = await getProfile(input.customerId);
      return { profile: updated };
    }),

  /**
   * Increment DI scan count for a customer
   */
  incrementDIScan: protectedProcedure
    .input(z.object({
      customerId: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      await incrementDIScanCount(input.customerId);
      return { success: true };
    }),

  /**
   * Get posture trend data for charting
   */
  getPostureTrend: protectedProcedure
    .input(z.object({
      customerId: z.string().min(1),
    }))
    .query(async ({ input }) => {
      const profile = await getProfile(input.customerId);
      if (!profile) return { trend: [], grade: null, score: null };

      return {
        trend: (profile.postureTrendData as any[]) || [],
        grade: profile.postureGrade,
        score: profile.overallPostureScore,
      };
    }),

  /**
   * Get recurring weaknesses for a customer
   */
  getRecurringWeaknesses: protectedProcedure
    .input(z.object({
      customerId: z.string().min(1),
    }))
    .query(async ({ input }) => {
      const profile = await getProfile(input.customerId);
      if (!profile) return { weaknesses: [] };
      return {
        weaknesses: (profile.recurringWeaknesses as any[]) || [],
      };
    }),

  /**
   * Get strategic recommendations for a customer
   */
  getRecommendations: protectedProcedure
    .input(z.object({
      customerId: z.string().min(1),
    }))
    .query(async ({ input }) => {
      const profile = await getProfile(input.customerId);
      if (!profile) return { recommendations: [] };
      return {
        recommendations: (profile.strategicRecommendations as any[]) || [],
      };
    }),
});
