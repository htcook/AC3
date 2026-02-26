/**
 * Web Crawler Router
 *
 * tRPC endpoints for the lightweight web crawler/scanner:
 * - Quick scan a single URL
 * - Full domain crawl
 * - List crawl jobs and results
 * - Get crawl result details
 * - Crawl assets from a domain intel scan
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const webCrawlerRouter = router({
  // ─── Quick Scan (single URL) ──────────────────────────────────────────
  quickScan: protectedProcedure
    .input(z.object({
      url: z.string().url(),
    }))
    .mutation(async ({ input }) => {
      const { quickScan } = await import("../lib/web-crawler");
      const result = await quickScan(input.url);
      if (!result) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to crawl URL" });
      return result;
    }),

  // ─── Full Domain Crawl ────────────────────────────────────────────────
  crawlDomain: protectedProcedure
    .input(z.object({
      domain: z.string(),
      seedUrls: z.array(z.string()).default([]),
      maxDepth: z.number().min(0).max(5).default(2),
      maxPages: z.number().min(1).max(200).default(50),
      timeoutMs: z.number().min(5000).max(60000).default(15000),
      respectRobotsTxt: z.boolean().default(true),
      // Optional link to domain intel scan
      scanId: z.number().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { crawlDomain } = await import("../lib/web-crawler");
      const { getDb } = await import("../db");
      const { webCrawlJobs, webCrawlResults } = await import("../../drizzle/schema");

      const result = await crawlDomain(input.domain, input.seedUrls, {
        maxDepth: input.maxDepth,
        maxPages: input.maxPages,
        timeoutMs: input.timeoutMs,
        respectRobotsTxt: input.respectRobotsTxt,
      });

      // Persist to database
      const db = await getDb();
      if (db) {
        try {
          // Save crawl job
          await db.insert(webCrawlJobs).values({
            jobId: result.jobId,
            scanId: input.scanId || null,
            engagementId: input.engagementId || null,
            targetDomain: input.domain,
            seedUrls: input.seedUrls,
            maxDepth: input.maxDepth,
            maxPages: input.maxPages,
            timeoutMs: input.timeoutMs,
            respectRobotsTxt: input.respectRobotsTxt,
            status: "completed",
            totalUrlsQueued: result.totalUrlsCrawled + result.totalUrlsFailed,
            totalUrlsCrawled: result.totalUrlsCrawled,
            totalUrlsFailed: result.totalUrlsFailed,
            totalFindings: result.totalFindings,
            findingSummary: result.findingSummary,
            technologiesSummary: result.technologiesSummary,
            securityGrade: result.securityGrade,
            startedBy: ctx.user?.name || ctx.user?.openId || "system",
            startedAt: result.startedAt,
            completedAt: result.completedAt,
          });

          // Save individual page results
          for (const page of result.pages) {
            await db.insert(webCrawlResults).values({
              scanId: input.scanId || null,
              engagementId: input.engagementId || null,
              targetUrl: page.url,
              finalUrl: page.finalUrl,
              domain: input.domain,
              status: "completed",
              httpStatus: page.httpStatus,
              responseTimeMs: page.responseTimeMs,
              contentType: page.contentType,
              contentLength: page.contentLength,
              depth: page.depth,
              securityHeaders: page.securityHeaders,
              securityHeaderGrade: page.securityHeaderGrade,
              detectedTechnologies: page.detectedTechnologies,
              serverHeader: page.serverHeader,
              poweredBy: page.poweredBy,
              pageTitle: page.pageTitle,
              metaDescription: page.metaDescription,
              internalLinks: page.internalLinks,
              externalLinks: page.externalLinks,
              resourceUrls: page.resourceUrls,
              forms: page.forms,
              exposedPaths: page.exposedPaths,
              robotsTxt: page.robotsTxt,
              securityTxt: page.securityTxt,
              sitemapUrls: page.sitemapUrls,
              cookies: page.cookies,
              tlsInfo: page.tlsInfo,
              findings: page.findings,
              findingCounts: page.findingCounts,
              totalFindings: page.findings.length,
              rawHeaders: page.rawHeaders,
              crawlConfig: {
                maxDepth: input.maxDepth,
                maxPages: input.maxPages,
                timeoutMs: input.timeoutMs,
                respectRobotsTxt: input.respectRobotsTxt,
              },
              crawledBy: ctx.user?.name || ctx.user?.openId || "system",
              startedAt: result.startedAt,
              completedAt: result.completedAt,
            });
          }
        } catch (err: any) {
          console.error("[WebCrawler] Failed to persist crawl results:", err.message);
        }
      }

      return result;
    }),

  // ─── Crawl Assets from Domain Intel Scan ──────────────────────────────
  crawlScanAssets: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      maxDepth: z.number().min(0).max(3).default(1),
      maxPagesPerAsset: z.number().min(1).max(20).default(5),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDbRequired } = await import("../db");
      const { domainIntelScans, discoveredAssets } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { quickScan } = await import("../lib/web-crawler");
      const { webCrawlResults } = await import("../../drizzle/schema");

      const db = await getDbRequired();

      // Get scan
      const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      // Get discovered assets with URLs
      const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
      const crawlableAssets = assets.filter((a) => a.url || a.hostname);

      const results: { assetId: number; hostname: string; result: Awaited<ReturnType<typeof quickScan>> }[] = [];

      // Crawl each asset (limited concurrency)
      for (let i = 0; i < crawlableAssets.length; i += 3) {
        const batch = crawlableAssets.slice(i, i + 3);
        const batchResults = await Promise.all(
          batch.map(async (asset) => {
            const url = asset.url || `https://${asset.hostname}`;
            const result = await quickScan(url);
            return { assetId: asset.id, hostname: asset.hostname, result };
          }),
        );

        for (const br of batchResults) {
          results.push(br);
          if (br.result) {
            try {
              await db.insert(webCrawlResults).values({
                scanId: input.scanId,
                assetId: br.assetId,
                targetUrl: br.result.url,
                finalUrl: br.result.finalUrl,
                domain: br.hostname,
                status: "completed",
                httpStatus: br.result.httpStatus,
                responseTimeMs: br.result.responseTimeMs,
                contentType: br.result.contentType,
                contentLength: br.result.contentLength,
                depth: 0,
                securityHeaders: br.result.securityHeaders,
                securityHeaderGrade: br.result.securityHeaderGrade,
                detectedTechnologies: br.result.detectedTechnologies,
                serverHeader: br.result.serverHeader,
                poweredBy: br.result.poweredBy,
                pageTitle: br.result.pageTitle,
                metaDescription: br.result.metaDescription,
                internalLinks: br.result.internalLinks,
                externalLinks: br.result.externalLinks,
                resourceUrls: br.result.resourceUrls,
                forms: br.result.forms,
                exposedPaths: br.result.exposedPaths,
                robotsTxt: br.result.robotsTxt,
                securityTxt: br.result.securityTxt,
                sitemapUrls: br.result.sitemapUrls,
                cookies: br.result.cookies,
                tlsInfo: br.result.tlsInfo,
                findings: br.result.findings,
                findingCounts: br.result.findingCounts,
                totalFindings: br.result.findings.length,
                rawHeaders: br.result.rawHeaders,
                crawledBy: ctx.user?.name || ctx.user?.openId || "system",
                startedAt: Date.now(),
                completedAt: Date.now(),
              });
            } catch (err: any) {
              console.error(`[WebCrawler] Failed to persist result for ${br.hostname}:`, err.message);
            }
          }
        }
      }

      return {
        scanId: input.scanId,
        totalAssets: crawlableAssets.length,
        totalCrawled: results.filter((r) => r.result).length,
        totalFailed: results.filter((r) => !r.result).length,
        results: results.map((r) => ({
          assetId: r.assetId,
          hostname: r.hostname,
          httpStatus: r.result?.httpStatus || null,
          securityGrade: r.result?.securityHeaderGrade || null,
          totalFindings: r.result?.findings.length || 0,
          technologies: r.result?.detectedTechnologies.map((t) => t.name) || [],
        })),
      };
    }),

  // ─── List Crawl Jobs ──────────────────────────────────────────────────
  listJobs: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(20),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { webCrawlJobs } = await import("../../drizzle/schema");
      const { desc, sql } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) return { jobs: [], total: 0 };

      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` }).from(webCrawlJobs);
      const jobs = await db.select().from(webCrawlJobs)
        .orderBy(desc(webCrawlJobs.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      return { jobs, total: countResult?.count || 0 };
    }),

  // ─── List Crawl Results ───────────────────────────────────────────────
  listResults: protectedProcedure
    .input(z.object({
      scanId: z.number().optional(),
      domain: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { webCrawlResults } = await import("../../drizzle/schema");
      const { desc, eq, sql, and } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) return { results: [], total: 0 };

      const conditions = [];
      if (input.scanId) conditions.push(eq(webCrawlResults.scanId, input.scanId));
      if (input.domain) conditions.push(eq(webCrawlResults.domain, input.domain));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` }).from(webCrawlResults).where(where);
      const results = await db.select().from(webCrawlResults)
        .where(where)
        .orderBy(desc(webCrawlResults.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      return { results, total: countResult?.count || 0 };
    }),

  // ─── Get Single Crawl Result ──────────────────────────────────────────
  getResult: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDbRequired } = await import("../db");
      const { webCrawlResults } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDbRequired();
      const [result] = await db.select().from(webCrawlResults).where(eq(webCrawlResults.id, input.id)).limit(1);
      if (!result) throw new TRPCError({ code: "NOT_FOUND", message: "Crawl result not found" });
      return result;
    }),
});
