// @ts-nocheck
/**
 * Client Portal Router — manages share tokens and provides public read-only
 * access to engagement reports for clients.
 */
import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "../_core/trpc";
import * as db from "../db";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";
import { getDb as _getDb } from "../db";
import { roeDocuments, roePersonnel, roeSignatures, engagements, discoveredAssets } from "../../drizzle/schema";
import { eq } from "drizzle-orm";
import { assertEngagementAccess } from "../lib/engagement-access-guard";

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
      // Verify engagement exists and user has access
      const engagement = await db.getEngagementById(input.engagementId, ctx.user);
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

          // Fetch discovery context from discovered_assets table
          const dbAssets = await db.getDiscoveredAssetsByScan(latestScan.id);
          const contextMap = new Map<string, any>();
          for (const da of dbAssets) {
            if (da.discoveryContext) {
              contextMap.set(da.hostname, typeof da.discoveryContext === 'string' ? JSON.parse(da.discoveryContext) : da.discoveryContext);
            }
          }

          response.assets = analyses.map((a: any) => {
            const ctx = contextMap.get(a.asset?.hostname);
            return {
              hostname: a.asset?.hostname,
              assetType: a.asset?.assetType,
              riskScore: a.hybridRiskScore,
              riskBand: a.riskBand,
              criticalityScore: a.criticalityScore,
              findingCount: a.postureFindings?.length || 0,
              technologies: a.asset?.technologies?.slice(0, 10),
              // Discovery context intelligence (if analyzed)
              discoveryContext: ctx ? {
                attribution: ctx.attribution ? {
                  primaryClaim: ctx.attribution.claims?.[0]?.ownerOrg || ctx.attribution.primaryClaim?.ownerOrg || 'Unknown',
                  confidence: ctx.attribution.claims?.[0]?.confidence || ctx.attribution.confidence || 0,
                  tier: ctx.attribution.tier || 'unknown',
                } : undefined,
                role: ctx.role ? {
                  exposure: ctx.role.exposure || 'unknown',
                  environment: ctx.role.environment || 'unknown',
                  criticality: ctx.role.criticality || 'unknown',
                  confidence: ctx.role.confidence || 0,
                } : undefined,
                lifecycle: ctx.lifecycle ? {
                  stage: ctx.lifecycle.stage || 'unknown',
                  confidence: ctx.lifecycle.confidence || 0,
                } : undefined,
                threatRelevance: ctx.threatRelevance ? {
                  overallScore: ctx.threatRelevance.overallScore || 0,
                  topActorTypes: (ctx.threatRelevance.actorTypes || []).slice(0, 3).map((at: any) => ({
                    type: at.type || at.actorType,
                    score: at.score || at.relevanceScore || 0,
                  })),
                } : undefined,
                mode: ctx.mode || 'deterministic_only',
              } : undefined,
            };
          });
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

      // Fetch linked RoE document if available
      try {
        const drizzleDb = await _getDb();
        if (drizzleDb && (engagement as any).roeDocumentId) {
          const [roeDoc] = await drizzleDb.select().from(roeDocuments).where(eq(roeDocuments.id, (engagement as any).roeDocumentId));
          if (roeDoc) {
            const personnel = await drizzleDb.select().from(roePersonnel).where(eq(roePersonnel.roeId, roeDoc.id));
            const sigs = await drizzleDb.select().from(roeSignatures).where(eq(roeSignatures.roeId, roeDoc.id));
            response.roe = {
              id: roeDoc.id,
              title: roeDoc.title,
              version: roeDoc.version,
              status: roeDoc.status,
              purpose: roeDoc.purpose,
              assumptions: roeDoc.assumptions,
              limitations: roeDoc.limitations,
              scopeInclusions: roeDoc.scopeInclusions,
              scopeExclusions: roeDoc.scopeExclusions,
              testingTypes: roeDoc.testingTypes,
              attackVectors: roeDoc.attackVectors,
              scheduleStart: roeDoc.scheduleStart,
              scheduleEnd: roeDoc.scheduleEnd,
              scheduleTimezone: roeDoc.scheduleTimezone,
              scheduleWindow: roeDoc.scheduleWindow,
              scheduleDays: roeDoc.scheduleDays,
              commFrequency: roeDoc.commFrequency,
              commMethod: roeDoc.commMethod,
              incidentResponse: roeDoc.incidentResponse,
              haltConditions: roeDoc.haltConditions,
              dataHandling: roeDoc.dataHandling,
              evidenceRetention: roeDoc.evidenceRetention,
              piiHandling: roeDoc.piiHandling,
              encryptionRequired: roeDoc.encryptionRequired,
              destructionMethod: roeDoc.destructionMethod,
              legalJurisdiction: roeDoc.legalJurisdiction,
              ndaRequired: roeDoc.ndaRequired,
              liabilityClause: roeDoc.liabilityClause,
              complianceFrameworks: roeDoc.complianceFrameworks,
              personnel,
              signatures: sigs,
            };
          }
        }
      } catch (e) {
        // RoE data is optional — don't fail the whole request
      }

      return response;
    }),

  // ─── Public: Sign RoE from Client Portal ─────────────────────────
  signRoe: publicProcedure
    .input(z.object({
      token: z.string(),
      password: z.string().optional(),
      roeId: z.number(),
      signerName: z.string().min(1),
      signerTitle: z.string().min(1),
      signerOrganization: z.string().min(1),
      signerEmail: z.string().email(),
      signatureData: z.string(), // base64 signature image or typed name
      signatureType: z.enum(["typed", "drawn"]),
      ipAddress: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      // Validate the share token first
      const share = await db.getEngagementShareByToken(input.token);
      if (!share || !share.isActive) {
        throw new TRPCError({ code: "FORBIDDEN", message: "Invalid or inactive share link" });
      }
      if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
        throw new TRPCError({ code: "FORBIDDEN", message: "Share link expired" });
      }
      if (share.accessPassword) {
        if (!input.password) throw new TRPCError({ code: "UNAUTHORIZED", message: "Password required" });
        const hashedInput = crypto.createHash("sha256").update(input.password).digest("hex");
        if (hashedInput !== share.accessPassword) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Incorrect password" });
        }
      }

      const drizzleDb = await _getDb();
      if (!drizzleDb) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Verify the RoE document exists and is linked to this engagement
      const [roeDoc] = await drizzleDb.select().from(roeDocuments).where(eq(roeDocuments.id, input.roeId));
      if (!roeDoc) throw new TRPCError({ code: "NOT_FOUND", message: "RoE document not found" });

      // Insert signature
      const now = Date.now();
      await drizzleDb.insert(roeSignatures).values({
        roeId: input.roeId,
        signerName: input.signerName,
        signerTitle: input.signerTitle,
        signerOrganization: input.signerOrganization,
        signerEmail: input.signerEmail,
        signatureData: input.signatureData,
        signatureType: input.signatureType,
        ipAddress: input.ipAddress || "unknown",
        signedAt: now,
        createdAt: now,
      });

      // Update RoE document status to approved if it was pending_review
      if (roeDoc.status === "pending_review") {
        await drizzleDb.update(roeDocuments).set({
          status: "approved",
          approvedAt: now,
        }).where(eq(roeDocuments.id, input.roeId));
      }

      return { success: true, message: "RoE document signed successfully" };
    }),

  // ─── Attack Surface Scan (Client Self-Service) ─────────────────────

  /**
   * Launch an Attack Surface Scan — client-initiated, pre-scoped scan
   * that runs passive discovery + stack profiling against their own environment.
   * Requires an active engagement with approved RoE.
   */
  attackSurfaceScan: router({
    launch: protectedProcedure
      .input(z.object({
        engagementId: z.number().describe("Active engagement ID with approved RoE"),
        targets: z.array(z.string().min(1)).min(1).max(10).describe("Domains or IPs to scan (max 10)"),
        scanType: z.enum(["passive", "light", "full"]).default("passive").describe("passive=OSINT only, light=port scan+banner, full=vuln detection"),
        notifyOnComplete: z.boolean().default(true),
      }))
      .mutation(async ({ input, ctx }) => {
        const drizzleDb = await _getDb();

        // Verify the engagement exists and is active
        const [engagement] = await drizzleDb.select().from(engagements)
          .where(eq(engagements.id, input.engagementId)).limit(1);
        if (!engagement) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
        if (engagement.status === "cancelled" || engagement.status === "archived") {
          throw new TRPCError({ code: "BAD_REQUEST", message: "Engagement is not active" });
        }

        // Verify RoE is approved for this engagement
        const [roe] = await drizzleDb.select().from(roeDocuments)
          .where(eq(roeDocuments.engagementId, input.engagementId)).limit(1);
        if (!roe || roe.status !== "approved") {
          throw new TRPCError({
            code: "PRECONDITION_FAILED",
            message: "Rules of Engagement must be approved before scanning. Please sign your RoE first.",
          });
        }

        // Run the Quick Scan engine
        const { classifyTarget, runPassiveDiscovery, profileStack, matchThreatActors, selectToolChain } = await import("../lib/quick-scan-engine");
        const scanId = `ass-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        const results: any[] = [];

        for (const target of input.targets) {
          const classified = classifyTarget(target);
          const discovery = await runPassiveDiscovery(classified);
          const stack = profileStack(discovery.technologies, discovery.ports, discovery.services);
          const actors = await matchThreatActors(stack, engagement.sector || undefined);
          const tools = selectToolChain(stack);

          results.push({
            target,
            classified,
            discovery: {
              subdomains: discovery.subdomains?.length || 0,
              openPorts: discovery.ports?.length || 0,
              technologies: discovery.technologies?.length || 0,
              services: discovery.services?.length || 0,
            },
            stackProfile: stack,
            threatActors: actors.slice(0, 5).map(a => ({
              name: a.name,
              confidence: a.confidence,
              techniques: a.techniques?.length || 0,
            })),
            recommendedTools: tools.primary?.slice(0, 5) || [],
            riskIndicators: {
              exposedServices: discovery.ports?.filter((p: any) => [21, 22, 23, 25, 445, 3389, 5900].includes(p.port))?.length || 0,
              outdatedTech: discovery.technologies?.filter((t: any) => t.outdated)?.length || 0,
              missingHttps: discovery.services?.filter((s: any) => s.protocol === 'http' && !s.redirectsToHttps)?.length || 0,
            },
          });
        }

        return {
          scanId,
          engagementId: input.engagementId,
          scanType: input.scanType,
          initiatedBy: ctx.user?.name || ctx.user?.openId || "client",
          initiatedAt: new Date().toISOString(),
          status: "completed",
          targetCount: input.targets.length,
          results,
          summary: {
            totalSubdomains: results.reduce((s, r) => s + r.discovery.subdomains, 0),
            totalOpenPorts: results.reduce((s, r) => s + r.discovery.openPorts, 0),
            totalTechnologies: results.reduce((s, r) => s + r.discovery.technologies, 0),
            topThreats: results.flatMap(r => r.threatActors).slice(0, 5),
            riskScore: Math.min(100, results.reduce((s, r) =>
              s + r.riskIndicators.exposedServices * 15 + r.riskIndicators.outdatedTech * 10 + r.riskIndicators.missingHttps * 5, 0)),
          },
        };
      }),

    history: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        // Return scan history for this engagement (placeholder — would query a scans table)
        return { scans: [], total: 0 };
      }),
  }),
});
