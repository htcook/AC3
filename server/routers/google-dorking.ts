/**
 * Google Dorking Router — OSINT Reconnaissance via Google Custom Search
 *
 * Provides tRPC procedures for:
 *   - Connection health check
 *   - Dork template listing by category
 *   - Single dork execution
 *   - Custom query execution
 *   - Full domain scan with selected categories
 *   - Category metadata
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { GoogleDorkingConnector, DORK_TEMPLATES, type DorkCategory } from "../lib/google-dorking-connector";

// ─── Helper: Get connector instance from env ─────────────────────────────
function getConnector(): GoogleDorkingConnector | null {
  const apiKey = process.env.GOOGLE_CSE_API_KEY;
  const searchEngineId = process.env.GOOGLE_CSE_ID;
  if (!apiKey || !searchEngineId) return null;
  return new GoogleDorkingConnector(apiKey, searchEngineId);
}

// ─── Router ──────────────────────────────────────────────────────────────

export const googleDorkingRouter = router({
  /**
   * Health check — verifies Google CSE API connectivity
   */
  health: protectedProcedure.query(async () => {
    const connector = getConnector();
    if (!connector) {
      return {
        configured: false,
        connected: false,
        message: "Google Custom Search API not configured. Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID.",
        templateCount: DORK_TEMPLATES.length,
      };
    }

    try {
      // Test with a minimal query
      await connector.search("test", 1, 1);
      return {
        configured: true,
        connected: true,
        message: "Google Custom Search API connected successfully.",
        templateCount: DORK_TEMPLATES.length,
      };
    } catch (err: any) {
      return {
        configured: true,
        connected: false,
        message: `Connection failed: ${err.message}`,
        templateCount: DORK_TEMPLATES.length,
      };
    }
  }),

  /**
   * Get available dork categories with metadata
   */
  categories: protectedProcedure.query(async () => {
    const connector = new GoogleDorkingConnector("", ""); // No API key needed for metadata
    return connector.getCategories();
  }),

  /**
   * Get dork templates, optionally filtered by category
   */
  templates: protectedProcedure
    .input(z.object({ category: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const connector = new GoogleDorkingConnector("", "");
      return connector.getTemplates(input?.category as DorkCategory | undefined);
    }),

  /**
   * Execute a single dork template against a target domain
   */
  executeDork: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      domain: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) {
        return { configured: false, result: null, error: "Google CSE not configured." };
      }

      const template = DORK_TEMPLATES.find((t) => t.id === input.templateId);
      if (!template) {
        return { configured: true, result: null, error: `Template "${input.templateId}" not found.` };
      }

      try {
        const result = await connector.executeDork(template, input.domain);
        return { configured: true, result, error: null };
      } catch (err: any) {
        return { configured: true, result: null, error: err.message };
      }
    }),

  /**
   * Execute a custom dork query (user-defined)
   */
  executeCustom: protectedProcedure
    .input(z.object({
      query: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) {
        return { configured: false, results: [], totalResults: 0, error: "Google CSE not configured." };
      }

      try {
        const { results, totalResults, searchTime } = await connector.executeCustomDork(input.query);
        return { configured: true, results, totalResults, searchTime, error: null };
      } catch (err: any) {
        return { configured: true, results: [], totalResults: 0, searchTime: 0, error: err.message };
      }
    }),

  /**
   * Run a full scan against a domain with selected categories
   * This executes multiple dork queries sequentially with rate limiting
   */
  runScan: protectedProcedure
    .input(z.object({
      domain: z.string().min(1),
      categories: z.array(z.string()).optional(),
      delayMs: z.number().min(500).max(5000).optional(),
    }))
    .mutation(async ({ input }) => {
      const connector = getConnector();
      if (!connector) {
        return { configured: false, summary: null, error: "Google CSE not configured." };
      }

      try {
        const summary = await connector.runScan(
          input.domain,
          input.categories as DorkCategory[] | undefined,
          input.delayMs || 1200,
        );
        return { configured: true, summary, error: null };
      } catch (err: any) {
        return { configured: true, summary: null, error: err.message };
      }
    }),

  /**
   * Preview the query that would be generated for a template + domain
   */
  previewQuery: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      domain: z.string().min(1),
    }))
    .query(({ input }) => {
      const template = DORK_TEMPLATES.find((t) => t.id === input.templateId);
      if (!template) return { query: null, error: "Template not found" };
      return {
        query: template.query.replace(/\{\{domain\}\}/g, input.domain),
        template,
        error: null,
      };
    }),
});
