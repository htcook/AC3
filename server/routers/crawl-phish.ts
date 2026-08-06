import * as db from "../db";
/**
 * Crawl-to-Phish Router
 *
 * tRPC endpoints for generating phishing templates from web crawl results.
 * All endpoints are RoE-gated: they require an active engagement context.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const crawlPhishRouter = router({
  /**
   * Generate phishing templates from a scan's web crawl results.
   * Extracts login forms, branding, and vendor dependencies to create
   * GoPhish-ready templates.
   */
  generateFromScan: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { domainIntelScans, webCrawlResults } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { generatePhishingFromCrawl } = await import("../lib/crawl-phish-generator");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      // Get the scan
      const [scan] = await db.select().from(domainIntelScans)
        .where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      // Get crawl results for this scan
      const crawlRows = await db.select().from(webCrawlResults)
        .where(eq(webCrawlResults.scanId, input.scanId));

      if (crawlRows.length === 0) {
        return {
          success: false,
          message: "No web crawl results found for this scan. Run a web crawl first.",
          templates: [],
          vendors: [],
          loginForms: [],
        };
      }

      // Map DB rows to the format expected by the generator
      const crawlData = crawlRows.map(r => ({
        id: r.id,
        targetUrl: r.targetUrl,
        domain: r.domain,
        pageTitle: r.pageTitle,
        metaDescription: r.metaDescription,
        forms: (r.forms as any[]) || [],
        externalLinks: (r.externalLinks as string[]) || [],
        resourceUrls: (r.resourceUrls as string[]) || [],
        rawHeaders: (r.rawHeaders as Record<string, string>) || {},
        detectedTechnologies: (r.detectedTechnologies as any[]) || [],
      }));

      const result = await generatePhishingFromCrawl({
        scanId: input.scanId,
        domain: scan.domain,
        crawlResults: crawlData,
      });

      return {
        success: true,
        message: `Generated ${result.generatedTemplates.length} phishing templates from ${crawlRows.length} crawled pages`,
        templates: result.generatedTemplates,
        vendors: result.detectedVendors,
        loginForms: result.loginForms,
        branding: result.branding,
        supplyChainRisks: result.supplyChainRisks,
      };
    }),

  /**
   * Detect vendors from a scan's crawl results without generating templates.
   * Useful for the Supply Chain Risk tab.
   */
  detectVendors: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { webCrawlResults } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { detectVendors, extractBranding } = await import("../lib/crawl-phish-generator");

      const db = await getDb();
      if (!db) return { vendors: [], branding: null };

      const crawlRows = await db.select().from(webCrawlResults)
        .where(eq(webCrawlResults.scanId, input.scanId));

      if (crawlRows.length === 0) return { vendors: [], branding: null };

      // Aggregate vendors across all crawl results
      const allVendors = new Map<string, any>();
      let branding = null;

      for (const row of crawlRows) {
        if (!branding) {
          branding = extractBranding({
            domain: row.domain,
            pageTitle: row.pageTitle,
            metaDescription: row.metaDescription,
            resourceUrls: (row.resourceUrls as string[]) || [],
            rawHeaders: (row.rawHeaders as Record<string, string>) || {},
            detectedTechnologies: (row.detectedTechnologies as any[]) || [],
            externalLinks: (row.externalLinks as string[]) || [],
          });
        }

        const vendors = detectVendors({
          externalLinks: (row.externalLinks as string[]) || [],
          resourceUrls: (row.resourceUrls as string[]) || [],
          rawHeaders: (row.rawHeaders as Record<string, string>) || {},
          detectedTechnologies: (row.detectedTechnologies as any[]) || [],
        });

        for (const v of vendors) {
          const existing = allVendors.get(v.vendor);
          if (!existing || v.confidence > existing.confidence) {
            allVendors.set(v.vendor, v);
          }
        }
      }

      return {
        vendors: Array.from(allVendors.values()).sort((a: any, b: any) => b.confidence - a.confidence),
        branding,
      };
    }),

  /**
   * Get web crawl summary for a scan (for the Web Crawl tab in results).
   */
  getCrawlSummary: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { webCrawlResults } = await import("../../drizzle/schema");
      const { eq, desc } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) return { results: [], summary: null };

      const results = await db.select().from(webCrawlResults)
        .where(eq(webCrawlResults.scanId, input.scanId))
        .orderBy(desc(webCrawlResults.totalFindings));

      if (results.length === 0) return { results: [], summary: null };

      // Aggregate summary
      let totalFindings = 0;
      let totalForms = 0;
      let totalLoginForms = 0;
      let totalExternalLinks = 0;
      let totalCookies = 0;
      let totalExposedPaths = 0;
      const allTechnologies = new Set<string>();
      const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
      let worstGradeIdx = gradeOrder.length - 1;

      for (const r of results) {
        totalFindings += r.totalFindings || 0;
        const forms = (r.forms as any[]) || [];
        totalForms += forms.length;
        totalLoginForms += forms.filter((f: any) => f.hasPasswordField).length;
        totalExternalLinks += ((r.externalLinks as string[]) || []).length;
        totalCookies += ((r.cookies as any[]) || []).length;
        totalExposedPaths += ((r.exposedPaths as any[]) || []).length;
        for (const tech of ((r.detectedTechnologies as any[]) || [])) {
          allTechnologies.add(tech.name);
        }
        const gradeIdx = gradeOrder.indexOf(r.securityHeaderGrade || "F");
        if (gradeIdx >= 0 && gradeIdx < worstGradeIdx) worstGradeIdx = gradeIdx;
      }

      return {
        results: results.map(r => ({
          id: r.id,
          targetUrl: r.targetUrl,
          domain: r.domain,
          httpStatus: r.httpStatus,
          responseTimeMs: r.responseTimeMs,
          securityHeaderGrade: r.securityHeaderGrade,
          totalFindings: r.totalFindings,
          pageTitle: r.pageTitle,
          serverHeader: r.serverHeader,
          poweredBy: r.poweredBy,
          securityHeaders: r.securityHeaders,
          detectedTechnologies: r.detectedTechnologies,
          forms: r.forms,
          externalLinks: r.externalLinks,
          cookies: r.cookies,
          exposedPaths: r.exposedPaths,
          findings: r.findings,
          findingCounts: r.findingCounts,
          robotsTxt: r.robotsTxt,
          securityTxt: r.securityTxt,
          tlsInfo: r.tlsInfo,
          createdAt: r.createdAt,
        })),
        summary: {
          totalPages: results.length,
          totalFindings,
          totalForms,
          totalLoginForms,
          totalExternalLinks,
          totalCookies,
          totalExposedPaths,
          uniqueTechnologies: allTechnologies.size,
          technologies: Array.from(allTechnologies),
          worstGrade: gradeOrder[worstGradeIdx] || "F",
        },
      };
    }),

  /**
   * Deploy a generated template to GoPhish.
   * Requires active engagement with valid RoE.
   */
  deployToGophish: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      template: z.object({
        name: z.string(),
        subject: z.string(),
        emailHtml: z.string(),
        landingPageHtml: z.string(),
      }),
    }))
    .mutation(async ({ input }) => {
      // Verify engagement exists and has active RoE
      const { getDb } = await import("../db");
      const { engagements } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      const [engagement] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId)).limit(1);
      if (!engagement) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
      if (engagement.status !== "active" && engagement.status !== "planning") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Engagement must be active to deploy phishing templates" });
      }

      // Check for signed RoE on the engagement
      if (engagement.roeStatus !== "signed") {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "Cannot deploy phishing templates without signed Rules of Engagement. Please get RoE approval first.",
        });
      }

      // Deploy email template to GoPhish
      const { ENV } = await import("../_core/env");
      const baseUrl = ENV.gophishBaseUrl;
      const apiKey = ENV.gophishApiKey;
      if (!baseUrl || !apiKey) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "GoPhish not configured" });
      }

      // FIPS 140-3: Use FIPS HTTPS agent for GoPhish self-signed certs
      const { createFIPSHttpsAgent } = await import('../lib/fips-tls');
      const gophishAgent = baseUrl.startsWith('https://') ? createFIPSHttpsAgent({ rejectUnauthorized: false }) : undefined;
      const fetchOpts = (body: any): RequestInit & { agent?: any } => ({
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
        // @ts-ignore - Node.js specific option
        ...(gophishAgent ? { agent: gophishAgent } : {}),
      });

      // Create email template
      const templateRes = await fetch(`${baseUrl}/api/templates/`, fetchOpts({
        name: input.template.name,
        subject: input.template.subject,
        html: input.template.emailHtml,
      }));

      // Create landing page
      const pageRes = await fetch(`${baseUrl}/api/pages/`, fetchOpts({
        name: `${input.template.name} — Landing Page`,
        html: input.template.landingPageHtml,
        capture_credentials: true,
        capture_passwords: true,
      }));

      const templateOk = templateRes.ok;
      const pageOk = pageRes.ok;

      return {
        success: templateOk || pageOk,
        templateDeployed: templateOk,
        landingPageDeployed: pageOk,
        message: templateOk && pageOk
          ? "Email template and landing page deployed to GoPhish"
          : templateOk
            ? "Email template deployed, landing page failed"
            : pageOk
              ? "Landing page deployed, email template failed"
              : "Both deployments failed — check GoPhish connection",
      };
    }),
});
