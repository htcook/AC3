/**
 * SpicyThreatIntel Darkweb Bridge Router
 *
 * Exposes SpicyThreatIntel API data through tRPC procedures for the
 * Darkweb Intelligence dashboard and enrichment workflows.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  checkBridgeHealth,
  getRansomwareVictimStats,
  getThreatFoxIOCs,
  getActivityRatings,
  getGlobalThreatActors,
  getCISAKEV,
  getRecentVictimEvents,
  getOTXPulses,
  getMalwareBazaarEntries,
  getAdaptiveKeywords,
  getEscalationAlerts,
  corroborateAssets,
  syncDarkwebIntelligence,
  isBridgeConfigured,
} from "../lib/spicy-tip-bridge";

export const darkwebBridgeRouter = router({
  /**
   * Health check — is the SpicyThreatIntel bridge configured and reachable?
   */
  health: protectedProcedure.query(async () => {
    return checkBridgeHealth();
  }),

  /**
   * Get bridge configuration status (without secrets).
   */
  status: protectedProcedure.query(async () => {
    return {
      configured: isBridgeConfigured(),
      timestamp: new Date().toISOString(),
    };
  }),

  /**
   * Ransomware victim statistics by group.
   */
  ransomwareVictimStats: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getRansomwareVictimStats(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * ThreatFox IOCs for corroboration enrichment.
   */
  threatFoxIOCs: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(500).optional(),
        type: z.enum(["ip", "domain", "url", "hash", "email"]).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const data = await getThreatFoxIOCs({ limit: input?.limit, type: input?.type });
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Activity ratings for ransomware groups.
   */
  activityRatings: protectedProcedure.query(async () => {
    const data = await getActivityRatings();
    return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
  }),

  /**
   * Global threat actors from SpicyThreatIntel.
   */
  globalThreatActors: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(500).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getGlobalThreatActors(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * CISA Known Exploited Vulnerabilities.
   */
  cisaKEV: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getCISAKEV(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Recent ransomware victim events.
   */
  recentVictimEvents: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getRecentVictimEvents(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * OTX threat intelligence pulses.
   */
  otxPulses: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getOTXPulses(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Malware Bazaar entries.
   */
  malwareBazaar: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).optional() }).optional())
    .query(async ({ input }) => {
      const data = await getMalwareBazaarEntries(input?.limit);
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Adaptive keywords for darkweb monitoring.
   */
  adaptiveKeywords: protectedProcedure.query(async () => {
    const data = await getAdaptiveKeywords();
    return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
  }),

  /**
   * Escalation alerts from darkweb monitoring.
   */
  escalationAlerts: protectedProcedure
    .input(
      z.object({
        severity: z.enum(["critical", "high", "medium", "low"]).optional(),
        limit: z.number().min(1).max(100).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const data = await getEscalationAlerts({
        severity: input?.severity,
        limit: input?.limit,
      });
      return { data: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Corroborate discovered assets against ThreatFox IOCs.
   * Used during OSINT scanning to elevate corroboration tiers.
   */
  corroborateAssets: protectedProcedure
    .input(
      z.object({
        assets: z.array(
          z.object({
            value: z.string(),
            type: z.enum(["ip", "domain", "url", "hash", "email"]),
          })
        ),
      })
    )
    .mutation(async ({ input }) => {
      const data = await corroborateAssets(input.assets);
      return { matches: data || [], source: "spicy_tip", fetchedAt: new Date().toISOString() };
    }),

  /**
   * Full darkweb intelligence sync — pulls all data types from SpicyThreatIntel.
   */
  syncAll: protectedProcedure.mutation(async () => {
    const result = await syncDarkwebIntelligence();
    return result || {
      actorsImported: 0,
      iocsImported: 0,
      eventsImported: 0,
      ratingsUpdated: 0,
      errors: ["Sync failed — bridge may not be configured"],
    };
  }),
});
