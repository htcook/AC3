/**
 * Client Portal Router — manages share tokens and provides public read-only
 * access to engagement reports for clients.
 */
import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "../_core/trpc";
import * as db from "../db";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";

export const clientPortalRouter = router({
  // ─── Admin: Create a share link ───────────────────────────────────
  createShare: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      expiresInDays: z.number().min(1).max(365).optional(),
      accessPassword: z.string().min(4).max(128).optional(),
      maxViews: z.number().min(1).max(100000).optional(),
      clientName: z.string().max(255).optional(),
      clientLogo: z.string().max(2048).optional(),
      brandingColor: z.string().max(32).optional(),
      customMessage: z.string().max(2000).optional(),
      includeFindings: z.boolean().default(true),
      includeRiskScores: z.boolean().default(true),
      includeRecommendations: z.boolean().default(true),
      includeExecutiveSummary: z.boolean().default(true),
      includeAssets: z.boolean().default(true),
      includeCompliance: z.boolean().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      // Verify engagement exists
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
      }

      // Hash password if provided
      let hashedPassword: string | undefined;
      if (input.accessPassword) {
        hashedPassword = crypto.createHash("sha256").update(input.accessPassword).digest("hex");
      }

      const expiresAt = input.expiresInDays
        ? new Date(Date.now() + input.expiresInDays * 24 * 60 * 60 * 1000)
        : undefined;

      const share = await db.createEngagementShare({
        engagementId: input.engagementId,
        expiresAt,
        accessPassword: hashedPassword,
        maxViews: input.maxViews,
        clientName: input.clientName,
        clientLogo: input.clientLogo,
        brandingColor: input.brandingColor,
        customMessage: input.customMessage,
        includeFindings: input.includeFindings,
        includeRiskScores: input.includeRiskScores,
        includeRecommendations: input.includeRecommendations,
        includeExecutiveSummary: input.includeExecutiveSummary,
        includeAssets: input.includeAssets,
        includeCompliance: input.includeCompliance,
        createdBy: ctx.user.id,
      });

      if (!share) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create share link" });
      }

      return share;
    }),

  // ─── Admin: List shares for an engagement ─────────────────────────
  listShares: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return db.getEngagementSharesByEngagement(input.engagementId);
    }),

  // ─── Admin: List all shares ───────────────────────────────────────
  listAllShares: protectedProcedure
    .query(async () => {
      return db.getAllEngagementShares();
    }),

  // ─── Admin: Update a share ────────────────────────────────────────
  updateShare: protectedProcedure
    .input(z.object({
      id: z.number(),
      isActive: z.boolean().optional(),
      expiresInDays: z.number().min(1).max(365).optional(),
      maxViews: z.number().min(1).max(100000).nullable().optional(),
      clientName: z.string().max(255).optional(),
      customMessage: z.string().max(2000).optional(),
    }))
    .mutation(async ({ input }) => {
      const updates: any = {};
      if (input.isActive !== undefined) updates.isActive = input.isActive;
      if (input.expiresInDays !== undefined) {
        updates.expiresAt = new Date(Date.now() + input.expiresInDays * 24 * 60 * 60 * 1000);
      }
      if (input.maxViews !== undefined) updates.maxViews = input.maxViews;
      if (input.clientName !== undefined) updates.clientName = input.clientName;
      if (input.customMessage !== undefined) updates.customMessage = input.customMessage;
      await db.updateEngagementShare(input.id, updates);
      return { success: true };
    }),

  // ─── Admin: Delete a share ────────────────────────────────────────
  deleteShare: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await db.deleteEngagementShare(input.id);
      return { success: true };
    }),

  // ─── Public: Access a shared engagement report ────────────────────
  accessReport: publicProcedure
    .input(z.object({
      token: z.string(),
      password: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const share = await db.getEngagementShareByToken(input.token);
      if (!share) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Share link not found or has been revoked" });
      }

      // Check if active
      if (!share.isActive) {
        throw new TRPCError({ code: "FORBIDDEN", message: "This share link has been deactivated" });
      }

      // Check expiration
      if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
        throw new TRPCError({ code: "FORBIDDEN", message: "This share link has expired" });
      }

      // Check view limit
      if (share.maxViews && share.viewCount >= share.maxViews) {
        throw new TRPCError({ code: "FORBIDDEN", message: "This share link has reached its view limit" });
      }

      // Check password
      if (share.accessPassword) {
        if (!input.password) {
          return { requiresPassword: true as const };
        }
        const hashedInput = crypto.createHash("sha256").update(input.password).digest("hex");
        if (hashedInput !== share.accessPassword) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Incorrect password" });
        }
      }

      // Increment view count
      await db.incrementShareViewCount(share.id);

      // Fetch engagement data
      const engagement = await db.getEngagementById(share.engagementId);
      if (!engagement) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Engagement data not found" });
      }

      // Fetch domain intel scans for this engagement
      const scans = await db.getDomainIntelScansByEngagement(share.engagementId);

      // Fetch engagement reports
      const reports = await db.getEngagementReports(share.engagementId);

      // Build the response based on what sections are included
      const response: any = {
        requiresPassword: false as const,
        engagement: {
          name: engagement.name,
          customerName: engagement.customerName,
          engagementType: engagement.engagementType,
          status: engagement.status,
          startDate: engagement.startDate,
          endDate: engagement.endDate,
          targetDomain: engagement.targetDomain,
        },
        branding: {
          clientName: share.clientName || engagement.customerName,
          clientLogo: share.clientLogo,
          brandingColor: share.brandingColor || "#14b8a6",
          customMessage: share.customMessage,
        },
        sections: {
          includeFindings: share.includeFindings,
          includeRiskScores: share.includeRiskScores,
          includeRecommendations: share.includeRecommendations,
          includeExecutiveSummary: share.includeExecutiveSummary,
          includeAssets: share.includeAssets,
          includeCompliance: share.includeCompliance,
        },
      };

      // Add scan data if available
      if (scans.length > 0) {
        const latestScan = scans[0];
        const pipelineOutput = latestScan.pipelineOutput as any;

        if (share.includeExecutiveSummary && pipelineOutput) {
          response.executiveSummary = pipelineOutput.executiveSummary || pipelineOutput.summaries?.executiveSummary;
          response.threatModelSummary = pipelineOutput.summaries?.threatModelSummary;
        }

        if (share.includeRiskScores && pipelineOutput) {
          response.riskScore = latestScan.overallRiskScore;
          response.riskBand = latestScan.overallRiskBand;
          response.assetCount = latestScan.totalAssets;
          response.findingCount = latestScan.totalFindings;
          // Aggregate risk distribution
          const analyses = pipelineOutput.analyses || [];
          const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };
          for (const a of analyses) {
            const band = (a.riskBand || "low").toLowerCase();
            if (band in riskDistribution) {
              riskDistribution[band as keyof typeof riskDistribution]++;
            }
          }
          response.riskDistribution = riskDistribution;
        }

        if (share.includeAssets && pipelineOutput) {
          const analyses = pipelineOutput.analyses || [];
          response.assets = analyses.map((a: any) => ({
            hostname: a.asset?.hostname,
            assetType: a.asset?.assetType,
            riskScore: a.hybridRiskScore,
            riskBand: a.riskBand,
            criticalityScore: a.criticalityScore,
            findingCount: a.postureFindings?.length || 0,
            technologies: a.asset?.technologies?.slice(0, 10),
          }));
        }

        if (share.includeFindings && pipelineOutput) {
          const analyses = pipelineOutput.analyses || [];
          const allFindings: any[] = [];
          for (const a of analyses) {
            for (const f of (a.postureFindings || [])) {
              allFindings.push({
                title: f.title,
                severity: f.severity,
                likelihood: f.likelihood,
                category: f.category,
                confidence: f.confidence,
                corroborationTier: f.corroborationTier,
                assetHostname: f.assetHostname || a.asset?.hostname,
                cveIds: f.cveIds,
                kevListed: f.kevListed,
                exploitAvailable: f.exploitAvailable,
                evidenceDetail: f.evidenceDetail,
              });
            }
          }
          // Sort by severity descending
          allFindings.sort((a, b) => (b.severity || 0) - (a.severity || 0));
          response.findings = allFindings;
        }

        if (share.includeRecommendations && pipelineOutput) {
          const analyses = pipelineOutput.analyses || [];
          const allRecommendations = new Set<string>();
          for (const a of analyses) {
            for (const f of (a.postureFindings || [])) {
              for (const r of (f.recommendedControls || [])) {
                allRecommendations.add(r);
              }
            }
          }
          response.recommendations = Array.from(allRecommendations).slice(0, 50);

          // Campaign recommendations if available
          if (pipelineOutput.campaigns) {
            response.campaigns = pipelineOutput.campaigns.map((c: any) => ({
              name: c.name,
              objective: c.objective,
              attackVector: c.attackVector,
              targetAssets: c.targetAssets,
              mitreTechniques: c.mitreTechniques?.slice(0, 5),
            }));
          }
        }
      }

      // Add report URLs if available
      if (reports.length > 0) {
        response.reports = reports
          .filter((r: any) => r.status === "completed" && r.reportUrl)
          .map((r: any) => ({
            title: r.title,
            reportType: r.reportType,
            reportUrl: r.reportUrl,
            generatedAt: r.generatedAt,
          }));
      }

      return response;
    }),
});
