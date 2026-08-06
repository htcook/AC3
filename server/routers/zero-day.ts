/**
 * zero-day.ts — tRPC router for zero-day feed, CVE search, and scan match queries
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import * as db from "../db";

export const zeroDayRouter = router({
  // ─── Feed Management ─────────────────────────────────────────────────────────

  /** Get feed status and statistics */
  getFeedStatus: protectedProcedure.query(async () => {
    const { getZeroDayFeed } = await import("../lib/zero-day-feed");
    const feed = getZeroDayFeed();
    const stats = feed.getStats();
    const matchStats = await db.getZeroDayMatchStats();
    return {
      ...stats,
      matchStats,
    };
  }),

  /** Force refresh the zero-day feed from Google Sheets */
  refreshFeed: protectedProcedure.mutation(async () => {
    const { getZeroDayFeed } = await import("../lib/zero-day-feed");
    const feed = getZeroDayFeed();
    await feed.refresh();
    const stats = feed.getStats();
    return {
      success: true,
      ...stats,
    };
  }),

  /** Get all zero-day entries with optional filters */
  getEntries: protectedProcedure
    .input(
      z.object({
        year: z.number().optional(),
        vendor: z.string().optional(),
        product: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().min(1).max(500).default(100),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const { getZeroDayFeed } = await import("../lib/zero-day-feed");
      const feed = getZeroDayFeed();
      await feed.ensureLoaded();
      let entries = feed.getAllEntries();

      // Apply filters
      if (input.year) {
        entries = entries.filter((e) => e.year === input.year);
      }
      if (input.vendor) {
        const vendorLower = input.vendor.toLowerCase();
        entries = entries.filter((e) =>
          e.vendor.toLowerCase().includes(vendorLower)
        );
      }
      if (input.product) {
        const productLower = input.product.toLowerCase();
        entries = entries.filter((e) =>
          e.product.toLowerCase().includes(productLower)
        );
      }
      if (input.search) {
        const searchLower = input.search.toLowerCase();
        entries = entries.filter(
          (e) =>
            e.cve.toLowerCase().includes(searchLower) ||
            e.vendor.toLowerCase().includes(searchLower) ||
            e.product.toLowerCase().includes(searchLower) ||
            e.description.toLowerCase().includes(searchLower) ||
            e.type.toLowerCase().includes(searchLower)
        );
      }

      const total = entries.length;
      const paged = entries.slice(input.offset, input.offset + input.limit);

      // Get unique vendors and years for filter dropdowns
      const allEntries = feed.getAllEntries();
      const vendors = [
        ...new Set(allEntries.map((e) => e.vendor).filter(Boolean)),
      ].sort();
      const years = [
        ...new Set(allEntries.map((e) => e.year).filter(Boolean)),
      ].sort((a, b) => (b || 0) - (a || 0));

      return {
        entries: paged,
        total,
        vendors,
        years,
      };
    }),

  // ─── CVE / Asset Search ───────────────────────────────────────────────────────

  /** Search for a specific CVE in the zero-day database */
  searchCVE: protectedProcedure
    .input(
      z.object({
        cve: z.string().min(1),
      })
    )
    .query(async ({ input }) => {
      const { getZeroDayFeed } = await import("../lib/zero-day-feed");
      const feed = getZeroDayFeed();
      await feed.ensureLoaded();

      const cveUpper = input.cve.toUpperCase().trim();
      const entries = feed.getAllEntries();

      // Exact match
      const exact = entries.filter((e) => e.cve === cveUpper);

      // Partial match (e.g., searching "2024" finds all 2024 CVEs)
      const partial = exact.length === 0
        ? entries.filter((e) => e.cve.includes(cveUpper)).slice(0, 20)
        : [];

      return {
        exactMatches: exact,
        partialMatches: partial,
        isKnownZeroDay: exact.length > 0,
      };
    }),

  /** Manual asset check — cross-reference user-provided assets against zero-day DB */
  manualAssetCheck: protectedProcedure
    .input(
      z.object({
        assets: z.array(
          z.object({
            identifier: z.string(),
            cves: z.array(z.string()).optional(),
            vendors: z.array(z.string()).optional(),
            products: z.array(z.string()).optional(),
            versions: z.array(z.string()).optional(),
          })
        ),
      })
    )
    .mutation(async ({ input }) => {
      const { crossReferenceAssets } = await import("../lib/zero-day-feed");
      const result = await crossReferenceAssets(input.assets);
      return result;
    }),

  /** Quick search — search by vendor/product/CVE text */
  quickSearch: protectedProcedure
    .input(
      z.object({
        query: z.string().min(1),
      })
    )
    .query(async ({ input }) => {
      const { getZeroDayFeed } = await import("../lib/zero-day-feed");
      const feed = getZeroDayFeed();
      await feed.ensureLoaded();

      const q = input.query.toLowerCase().trim();
      const entries = feed.getAllEntries();

      // Check if it looks like a CVE
      const isCVE = /^cve-?\d{4}/i.test(q);

      let results;
      if (isCVE) {
        const cveUpper = q.toUpperCase().replace(/^CVE(\d)/, "CVE-$1");
        results = entries.filter((e) => e.cve.includes(cveUpper));
      } else {
        results = entries.filter(
          (e) =>
            e.vendor.toLowerCase().includes(q) ||
            e.product.toLowerCase().includes(q) ||
            e.description.toLowerCase().includes(q) ||
            e.type.toLowerCase().includes(q) ||
            (e.reportedBy && e.reportedBy.toLowerCase().includes(q))
        );
      }

      return {
        results: results.slice(0, 50),
        totalMatches: results.length,
        query: input.query,
      };
    }),

  // ─── Scan Match Queries ───────────────────────────────────────────────────────

  /** Get zero-day matches for a specific scan */
  getMatchesByScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      return db.getZeroDayMatchesByScan(input.scanId);
    }),

  /** Get zero-day matches for a specific domain */
  getMatchesByDomain: protectedProcedure
    .input(
      z.object({
        domain: z.string(),
        limit: z.number().min(1).max(200).default(50),
      })
    )
    .query(async ({ input }) => {
      return db.getZeroDayMatchesByDomain(input.domain, input.limit);
    }),

  /** Get zero-day matches for a specific engagement */
  getMatchesByEngagement: protectedProcedure
    .input(z.object({ engagementId: z.string() }))
    .query(async ({ input }) => {
      return db.getZeroDayMatchesByEngagement(input.engagementId);
    }),

  /** Get recent undismissed zero-day matches across all scans */
  getRecentMatches: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(500).default(100) }))
    .query(async ({ input }) => {
      return db.getRecentZeroDayMatches(input.limit);
    }),

  /** Dismiss a zero-day match (false positive) */
  dismissMatch: protectedProcedure
    .input(z.object({ matchId: z.number() }))
    .mutation(async ({ input }) => {
      await db.dismissZeroDayMatch(input.matchId);
      return { success: true };
    }),

  /** Get zero-day match statistics */
  getMatchStats: protectedProcedure.query(async () => {
    return db.getZeroDayMatchStats();
  }),

  // ─── Vendor / Product Analytics ───────────────────────────────────────────────

  /** Get zero-day counts by vendor (for charts) */
  getVendorBreakdown: protectedProcedure.query(async () => {
    const { getZeroDayFeed } = await import("../lib/zero-day-feed");
    const feed = getZeroDayFeed();
    await feed.ensureLoaded();
    const entries = feed.getAllEntries();

    const vendorCounts = new Map<string, number>();
    for (const e of entries) {
      const vendor = e.vendor || "Unknown";
      vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);
    }

    return Array.from(vendorCounts.entries())
      .map(([vendor, count]) => ({ vendor, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 30);
  }),

  /** Get zero-day counts by year (for charts) */
  getYearBreakdown: protectedProcedure.query(async () => {
    const { getZeroDayFeed } = await import("../lib/zero-day-feed");
    const feed = getZeroDayFeed();
    await feed.ensureLoaded();
    const entries = feed.getAllEntries();

    const yearCounts = new Map<number, number>();
    for (const e of entries) {
      if (e.year) {
        yearCounts.set(e.year, (yearCounts.get(e.year) || 0) + 1);
      }
    }

    return Array.from(yearCounts.entries())
      .map(([year, count]) => ({ year, count }))
      .sort((a, b) => a.year - b.year);
  }),

  /** Get zero-day counts by vulnerability type (for charts) */
  getTypeBreakdown: protectedProcedure.query(async () => {
    const { getZeroDayFeed } = await import("../lib/zero-day-feed");
    const feed = getZeroDayFeed();
    await feed.ensureLoaded();
    const entries = feed.getAllEntries();

    const typeCounts = new Map<string, number>();
    for (const e of entries) {
      const type = e.type || "Unknown";
      typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    }

    return Array.from(typeCounts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
  }),
});
