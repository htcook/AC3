/**
 * Auto-Crawl Trigger
 *
 * Automatically crawls discovered web assets after a domain intel scan completes.
 * Runs as a fire-and-forget background task so it doesn't block the scan pipeline.
 *
 * Extracts HTTP/HTTPS URLs from discovered assets and feeds them through the
 * lightweight web crawler to surface security headers, technologies, exposed
 * paths, and other attack-surface metadata.
 */

import type { CrawlPageResult } from "./web-crawler";
import { computeCrawlCarverAdjustment, aggregateCrawlAdjustments, type CrawlCarverAdjustment } from "./crawl-carver-integration";

export interface AutoCrawlSummary {
  scanId: number;
  domain: string;
  totalAssets: number;
  totalCrawled: number;
  totalFailed: number;
  totalFindings: number;
  worstGrade: string;
  startedAt: number;
  completedAt: number;
  carverAdjustment: CrawlCarverAdjustment | null;
  results: {
    assetId: number;
    hostname: string;
    url: string;
    httpStatus: number | null;
    securityGrade: string | null;
    findingCount: number;
    technologies: string[];
    carverAdjustment: CrawlCarverAdjustment | null;
  }[];
}

/**
 * Trigger auto-crawl for all web-accessible assets discovered in a domain intel scan.
 * This is designed to be called via setImmediate() after scan completion.
 */
export async function triggerAutoCrawl(scanId: number, domain: string): Promise<AutoCrawlSummary | null> {
  const startedAt = Date.now();
  console.log(`[AutoCrawl] Starting auto-crawl for scan ${scanId} (${domain})`);

  try {
    const { getDb } = await import("../db");
    const { discoveredAssets, webCrawlResults, webCrawlJobs, domainIntelScans } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");
    const { quickScan } = await import("./web-crawler");

    const db = await getDb();
    if (!db) {
      console.error("[AutoCrawl] Database not available");
      return null;
    }

    // Get all discovered assets for this scan
    const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));

    // Filter to web-accessible assets (those with URLs or hostnames that suggest web services)
    const webAssets = assets.filter((a) => {
      // Has an explicit URL
      if (a.url && (a.url.startsWith("http://") || a.url.startsWith("https://"))) return true;
      // Has a hostname that likely serves web content
      if (a.hostname) {
        const assetType = (a.assetType || "").toLowerCase();
        // Include web apps, APIs, CDNs, and general web-facing assets
        if (["web_application", "api_endpoint", "cdn", "web_server", "load_balancer"].includes(assetType)) return true;
        // Include anything with web-related tags
        const tags = (a.tags as string[]) || [];
        if (tags.some(t => ["web", "http", "https", "api", "cdn"].includes(t.toLowerCase()))) return true;
        // Default: try to crawl any hostname (the crawler handles failures gracefully)
        return true;
      }
      return false;
    });

    if (webAssets.length === 0) {
      console.log(`[AutoCrawl] No web-accessible assets found for scan ${scanId}`);
      return null;
    }

    console.log(`[AutoCrawl] Found ${webAssets.length} crawlable assets out of ${assets.length} total for scan ${scanId}`);

    // Limit to 30 assets to avoid excessive crawling
    const assetsToScan = webAssets.slice(0, 30);
    const results: AutoCrawlSummary["results"] = [];
    let totalFindings = 0;
    const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
    let worstGradeIdx = gradeOrder.length - 1;
    const allCarverAdjustments: CrawlCarverAdjustment[] = [];

    // Create a crawl job record
    const jobId = `auto_crawl_${scanId}_${Date.now()}`;
    try {
      await db.insert(webCrawlJobs).values({
        jobId,
        scanId,
        targetDomain: domain,
        seedUrls: assetsToScan.map(a => a.url || `https://${a.hostname}`),
        maxDepth: 0,
        maxPages: assetsToScan.length,
        timeoutMs: 15000,
        respectRobotsTxt: true,
        status: "running",
        totalUrlsQueued: assetsToScan.length,
        totalUrlsCrawled: 0,
        totalUrlsFailed: 0,
        totalFindings: 0,
        findingSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        technologiesSummary: [],
        securityGrade: "N/A",
        startedBy: "auto-crawl",
        startedAt: startedAt,
        completedAt: null,
      });
    } catch (err: any) {
      console.error(`[AutoCrawl] Failed to create job record: ${err.message}`);
    }

    // Crawl in batches of 3 (limited concurrency)
    for (let i = 0; i < assetsToScan.length; i += 3) {
      const batch = assetsToScan.slice(i, i + 3);
      const batchResults = await Promise.all(
        batch.map(async (asset) => {
          const url = asset.url || `https://${asset.hostname}`;
          try {
            const result = await quickScan(url);
            return { asset, url, result };
          } catch (err: any) {
            console.error(`[AutoCrawl] Failed to crawl ${url}: ${err.message}`);
            return { asset, url, result: null };
          }
        }),
      );

      for (const { asset, url, result } of batchResults) {
        // Compute CARVER+Shock adjustment from crawl findings
        let assetCarverAdj: CrawlCarverAdjustment | null = null;
        if (result) {
          try {
            assetCarverAdj = computeCrawlCarverAdjustment(result, asset.hostname);
            allCarverAdjustments.push(assetCarverAdj);
          } catch (err: any) {
            console.error(`[AutoCrawl] CARVER scoring failed for ${asset.hostname}: ${err.message}`);
          }
        }

        const summary = {
          assetId: asset.id,
          hostname: asset.hostname,
          url,
          httpStatus: result?.httpStatus || null,
          securityGrade: result?.securityHeaderGrade || null,
          findingCount: result?.findings.length || 0,
          technologies: result?.detectedTechnologies.map(t => t.name) || [],
          carverAdjustment: assetCarverAdj,
        };
        results.push(summary);

        if (result) {
          totalFindings += result.findings.length;
          const gradeIdx = gradeOrder.indexOf(result.securityHeaderGrade);
          if (gradeIdx >= 0 && gradeIdx < worstGradeIdx) worstGradeIdx = gradeIdx;

          // Persist crawl result to DB
          try {
            await db.insert(webCrawlResults).values({
              scanId,
              assetId: asset.id,
              targetUrl: url,
              finalUrl: result.finalUrl,
              domain: asset.hostname,
              status: "completed",
              httpStatus: result.httpStatus,
              responseTimeMs: result.responseTimeMs,
              contentType: result.contentType,
              contentLength: result.contentLength,
              depth: 0,
              securityHeaders: result.securityHeaders,
              securityHeaderGrade: result.securityHeaderGrade,
              detectedTechnologies: result.detectedTechnologies,
              serverHeader: result.serverHeader,
              poweredBy: result.poweredBy,
              pageTitle: result.pageTitle,
              metaDescription: result.metaDescription,
              internalLinks: result.internalLinks,
              externalLinks: result.externalLinks,
              resourceUrls: result.resourceUrls,
              forms: result.forms,
              exposedPaths: result.exposedPaths,
              robotsTxt: result.robotsTxt,
              securityTxt: result.securityTxt,
              sitemapUrls: result.sitemapUrls,
              cookies: result.cookies,
              tlsInfo: result.tlsInfo,
              findings: result.findings,
              findingCounts: result.findingCounts,
              totalFindings: result.findings.length,
              rawHeaders: result.rawHeaders,
              crawledBy: "auto-crawl",
              startedAt,
              completedAt: Date.now(),
            });
          } catch (err: any) {
            console.error(`[AutoCrawl] Failed to persist result for ${asset.hostname}: ${err.message}`);
          }
        }
      }
    }

    const completedAt = Date.now();
    const totalCrawled = results.filter(r => r.httpStatus !== null).length;
    const totalFailed = results.filter(r => r.httpStatus === null).length;

    // Update crawl job record
    try {
      const { eq: eqOp } = await import("drizzle-orm");
      await db.update(webCrawlJobs)
        .set({
          status: "completed",
          totalUrlsCrawled: totalCrawled,
          totalUrlsFailed: totalFailed,
          totalFindings,
          findingSummary: results.reduce(
            (acc, r) => acc,
            { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          ),
          securityGrade: gradeOrder[worstGradeIdx] || "F",
          completedAt,
        })
        .where(eqOp(webCrawlJobs.jobId, jobId));
    } catch (err: any) {
      console.error(`[AutoCrawl] Failed to update job record: ${err.message}`);
    }

    // Aggregate CARVER adjustments across all crawled assets
    const aggregatedCarver = aggregateCrawlAdjustments(allCarverAdjustments);

    // Update the domain intel scan with auto-crawl summary + CARVER adjustments
    try {
      const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
      if (scan) {
        const existingOutput = (scan.pipelineOutput as any) || {};
        await db.update(domainIntelScans)
          .set({
            pipelineOutput: {
              ...existingOutput,
              autoCrawlSummary: {
                totalAssets: assetsToScan.length,
                totalCrawled,
                totalFailed,
                totalFindings,
                worstGrade: gradeOrder[worstGradeIdx] || "F",
                completedAt: new Date(completedAt).toISOString(),
              },
              crawlCarverAdjustment: aggregatedCarver ? {
                carver: aggregatedCarver.carver,
                shock: aggregatedCarver.shock,
                likelihoodBoost: aggregatedCarver.likelihoodBoost,
                contextAdjustment: aggregatedCarver.contextAdjustment,
                overallWebVulnScore: aggregatedCarver.breakdown.overallWebVulnScore,
                assessmentConfidence: aggregatedCarver.breakdown.assessmentConfidence,
                postureFindings: aggregatedCarver.postureFindings,
              } : null,
            },
          })
          .where(eq(domainIntelScans.id, scanId));
      }
    } catch (err: any) {
      console.error(`[AutoCrawl] Failed to update scan with auto-crawl summary: ${err.message}`);
    }

    const summary: AutoCrawlSummary = {
      scanId,
      domain,
      totalAssets: assetsToScan.length,
      totalCrawled,
      totalFailed,
      totalFindings,
      worstGrade: gradeOrder[worstGradeIdx] || "F",
      startedAt,
      completedAt,
      carverAdjustment: aggregatedCarver,
      results,
    };

    const carverSummary = aggregatedCarver
      ? `, webVulnScore=${aggregatedCarver.breakdown.overallWebVulnScore}, postureFindings=${aggregatedCarver.postureFindings.length}`
      : ", no CARVER adjustments";
    console.log(`[AutoCrawl] Completed for scan ${scanId}: ${totalCrawled}/${assetsToScan.length} assets crawled, ${totalFindings} findings, grade=${summary.worstGrade}${carverSummary} in ${completedAt - startedAt}ms`);
    return summary;
  } catch (err: any) {
    console.error(`[AutoCrawl] Fatal error for scan ${scanId}: ${err.message}`);
    return null;
  }
}
