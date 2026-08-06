/**
 * SOCRadar Router — Dark Web Monitoring, Brand Protection & Threat Feeds
 *
 * Provides tRPC procedures for the SOCRadar connector integration:
 *   - Connection health check
 *   - Incident listing/management
 *   - Dark web mention monitoring
 *   - Brand protection alerts
 *   - IOC enrichment (IP, domain, hash)
 *   - Threat feed access
 *   - Summary statistics
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { SOCRadarConnector } from "../lib/socradar-connector";

// ─── Helper: Get connector instance from env ─────────────────────────────
function getConnector(): SOCRadarConnector | null {
  const apiKey = process.env.SOCRADAR_API_KEY;
  const companyId = process.env.SOCRADAR_COMPANY_ID;
  if (!apiKey || !companyId) return null;
  return new SOCRadarConnector({
    apiKey,
    companyId,
    baseUrl: process.env.SOCRADAR_BASE_URL || undefined,
  });
}

// ─── Router ──────────────────────────────────────────────────────────────

export const socradarRouter = router({
  /**
   * Health check — verifies SOCRadar API connectivity
   */
  health: protectedProcedure.query(async () => {
    const connector = getConnector();
    if (!connector) {
      return {
        configured: false,
        connected: false,
        message: "SOCRadar API key or Company ID not configured",
        companyName: null,
      };
    }
    const result = await connector.verify();
    return {
      configured: true,
      connected: result.valid,
      message: result.message,
      companyName: result.companyName || null,
    };
  }),

  /**
   * Get incidents with optional filters
   */
  incidents: protectedProcedure
    .input(
      z.object({
        severity: z.array(z.string()).optional(),
        mainType: z.string().optional(),
        subType: z.string().optional(),
        resolved: z.boolean().optional(),
        limit: z.number().min(1).max(100).optional().default(50),
        offset: z.number().min(0).optional().default(0),
      }).optional(),
    )
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { incidents: [], total: 0, configured: false };
      const result = await connector.getIncidents(input || undefined);
      return { ...result, configured: true };
    }),

  /**
   * Mark incident as false positive
   */
  markFP: protectedProcedure
    .input(z.object({ incidentId: z.number(), comments: z.string().optional() }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { success: false, message: "Not configured" };
      const success = await connector.markIncidentFP(input.incidentId, input.comments);
      return { success, message: success ? "Marked as false positive" : "Failed to mark as FP" };
    }),

  /**
   * Mark incident as resolved
   */
  markResolved: protectedProcedure
    .input(z.object({ incidentId: z.number(), comments: z.string().optional() }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { success: false, message: "Not configured" };
      const success = await connector.markIncidentResolved(input.incidentId, input.comments);
      return { success, message: success ? "Incident resolved" : "Failed to resolve" };
    }),

  /**
   * Dark web mentions
   */
  darkWebMentions: protectedProcedure
    .input(
      z.object({
        category: z.string().optional(),
        severity: z.string().optional(),
        limit: z.number().min(1).max(100).optional().default(25),
      }).optional(),
    )
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { mentions: [], configured: false };
      const mentions = await connector.getDarkWebMentions(input || undefined);
      return { mentions, configured: true };
    }),

  /**
   * Brand protection alerts
   */
  brandAlerts: protectedProcedure
    .input(
      z.object({
        type: z.string().optional(),
        status: z.string().optional(),
        limit: z.number().min(1).max(100).optional().default(25),
      }).optional(),
    )
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { alerts: [], configured: false };
      const alerts = await connector.getBrandAlerts(input || undefined);
      return { alerts, configured: true };
    }),

  /**
   * Request takedown for a brand alert
   */
  requestTakedown: protectedProcedure
    .input(z.object({ alertId: z.number() }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { success: false, message: "Not configured" };
      const success = await connector.requestTakedown(input.alertId);
      return { success, message: success ? "Takedown requested" : "Failed to request takedown" };
    }),

  /**
   * IOC enrichment — IP address
   */
  enrichIP: protectedProcedure
    .input(z.object({ ip: z.string() }))
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { result: null, configured: false };
      const result = await connector.enrichIP(input.ip);
      return { result, configured: true };
    }),

  /**
   * IOC enrichment — Domain
   */
  enrichDomain: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { result: null, configured: false };
      const result = await connector.enrichDomain(input.domain);
      return { result, configured: true };
    }),

  /**
   * IOC enrichment — File hash
   */
  enrichHash: protectedProcedure
    .input(z.object({ hash: z.string() }))
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { result: null, configured: false };
      const result = await connector.enrichHash(input.hash);
      return { result, configured: true };
    }),

  /**
   * Threat feeds listing
   */
  threatFeeds: protectedProcedure
    .input(
      z.object({
        type: z.string().optional(),
        limit: z.number().min(1).max(50).optional().default(20),
      }).optional(),
    )
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { feeds: [], configured: false };
      const feeds = await connector.getThreatFeeds(input || undefined);
      return { feeds, configured: true };
    }),

  /**
   * Get indicators from a specific feed
   */
  feedIndicators: protectedProcedure
    .input(z.object({ feedId: z.string(), limit: z.number().min(1).max(500).optional().default(100) }))
    .query(async ({ input }) => {
      const connector = getConnector();
      if (!connector) return { indicators: [], configured: false };
      const indicators = await connector.getFeedIndicators(input.feedId, input.limit);
      return { indicators, configured: true };
    }),

  /**
   * Summary statistics
   */
  stats: protectedProcedure.query(async () => {
    const connector = getConnector();
    if (!connector) {
      return {
        configured: false,
        stats: null,
      };
    }
    const stats = await connector.getStats();
    return { configured: true, stats };
  }),
});
