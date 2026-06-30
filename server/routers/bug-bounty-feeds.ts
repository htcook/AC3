/**
 * Bug Bounty Live Feed Router
 * 
 * tRPC procedures for HackerOne/Bugcrowd live feed data:
 * - Program listing with search/filter
 * - Disclosed report feed
 * - Scope change detection
 * - Feed health status
 * - Aggregated feed events
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getBugBountyFeedAggregator } from "../lib/bug-bounty-feeds";

export const bugBountyFeedsRouter = router({
  // Get feed configuration status
  getFeedStatus: protectedProcedure.query(async () => {
    const aggregator = getBugBountyFeedAggregator();
    return {
      isConfigured: aggregator.isConfigured,
      configuredPlatforms: aggregator.configuredPlatforms,
      state: aggregator.getFeedState(),
    };
  }),

  // List programs from configured platforms
  getPrograms: protectedProcedure
    .input(z.object({
      platform: z.enum(["hackerone", "bugcrowd"]).optional(),
      page: z.number().min(1).default(1),
      search: z.string().optional(),
      onlyBounties: z.boolean().default(false),
    }))
    .query(async ({ input }) => {
      const aggregator = getBugBountyFeedAggregator();

      if (!aggregator.isConfigured) {
        return {
          programs: [],
          total: 0,
          error: "No bug bounty platform API keys configured. Add HACKERONE_API_USERNAME + HACKERONE_API_KEY or BUGCROWD_API_TOKEN.",
        };
      }

      const { programs, total } = await aggregator.fetchPrograms(input.platform, input.page);

      let filtered = programs;
      if (input.search) {
        const q = input.search.toLowerCase();
        filtered = filtered.filter(p =>
          p.name.toLowerCase().includes(q) ||
          p.handle.toLowerCase().includes(q)
        );
      }
      if (input.onlyBounties) {
        filtered = filtered.filter(p => p.offersBounties);
      }

      return { programs: filtered, total };
    }),

  // Get disclosed reports feed
  getDisclosedReports: protectedProcedure
    .input(z.object({
      platform: z.enum(["hackerone", "bugcrowd"]).optional(),
      page: z.number().min(1).default(1),
      severityFilter: z.enum(["all", "critical", "high", "medium", "low"]).default("all"),
    }))
    .query(async ({ input }) => {
      const aggregator = getBugBountyFeedAggregator();

      if (!aggregator.isConfigured) {
        return { reports: [], error: "Feed not configured" };
      }

      let reports = await aggregator.fetchDisclosedReports(input.platform, input.page);

      if (input.severityFilter !== "all") {
        reports = reports.filter(r => r.severity === input.severityFilter);
      }

      return { reports };
    }),

  // Get aggregated feed events (unified timeline)
  getFeedEvents: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      typeFilter: z.enum(["all", "new_program", "scope_change", "payout", "disclosure", "program_update"]).default("all"),
    }))
    .query(async ({ input }) => {
      const aggregator = getBugBountyFeedAggregator();

      if (!aggregator.isConfigured) {
        return { events: [], error: "Feed not configured" };
      }

      let events = await aggregator.generateFeedEvents(input.limit);

      if (input.typeFilter !== "all") {
        events = events.filter(e => e.type === input.typeFilter);
      }

      return { events };
    }),

  // Detect scope changes for a specific program
  checkScopeChanges: protectedProcedure
    .input(z.object({
      programHandle: z.string(),
      platform: z.enum(["hackerone", "bugcrowd"]),
    }))
    .mutation(async ({ input }) => {
      const aggregator = getBugBountyFeedAggregator();

      if (!aggregator.isConfigured) {
        return { changes: [], error: "Feed not configured" };
      }

      const changes = await aggregator.detectScopeChanges(input.programHandle, input.platform);
      return { changes };
    }),

  // Get program details with scope
  getProgramDetails: protectedProcedure
    .input(z.object({
      handle: z.string(),
      platform: z.enum(["hackerone", "bugcrowd"]),
    }))
    .query(async ({ input }) => {
      const aggregator = getBugBountyFeedAggregator();

      if (!aggregator.isConfigured) {
        return { program: null, error: "Feed not configured" };
      }

      // Try to get from cache first
      const cached = aggregator.getCachedPrograms().find(
        p => p.handle === input.handle && p.platform === input.platform
      );

      return { program: cached || null };
    }),

  // Get feed analytics summary
  getFeedAnalytics: protectedProcedure.query(async () => {
    const aggregator = getBugBountyFeedAggregator();
    const state = aggregator.getFeedState();
    const events = aggregator.getCachedFeed();

    // Compute analytics from cached data
    const platformBreakdown = {
      hackerone: events.filter(e => e.platform === "hackerone").length,
      bugcrowd: events.filter(e => e.platform === "bugcrowd").length,
      intigriti: events.filter(e => e.platform === "intigriti").length,
    };

    const severityBreakdown = {
      critical: events.filter(e => e.severity === "critical").length,
      high: events.filter(e => e.severity === "high").length,
      medium: events.filter(e => e.severity === "medium").length,
      low: events.filter(e => e.severity === "low").length,
    };

    const totalPayouts = events
      .filter(e => e.amount)
      .reduce((sum, e) => sum + (e.amount || 0), 0);

    return {
      state,
      platformBreakdown,
      severityBreakdown,
      totalPayouts,
      eventCount: events.length,
    };
  }),
});
