import * as db from "../db";
/**
 * Phishing Operations Router
 *
 * Unified backend for the AC3 phishing automation pipeline.
 * Connects domain intel scan results → APT matching → campaign materialization
 * → GoPhish deployment → Caldera post-exploitation triggering.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { buildPhishingKnowledgeContext } from "../lib/knowledge/social-engineering-templates";
import { getDb } from "../db";
import {
  phishingDrafts, InsertPhishingDraft,
  domainIntelScans,
  engagements,
  engagementPipelines,
} from "../../drizzle/schema";
import { eq, desc, and, sql, inArray } from "drizzle-orm";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

/**
 * Fetch from GoPhish API (reuse the same pattern as main routers.ts)
 */
async function fetchGophish(endpoint: string, method = "GET", data?: any) {
  const { ENV } = await import("../_core/env");
  const baseUrl = ENV.gophishBaseUrl;
  const apiKey = ENV.gophishApiKey;
  if (!baseUrl || !apiKey) {
    throw new TRPCError({ code: "PRECONDITION_FAILED", message: "GoPhish not configured" });
  }
  const url = `${baseUrl}${endpoint}`;
  const opts: RequestInit & { agent?: any } = {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    ...(typeof globalThis !== "undefined" && { signal: AbortSignal.timeout(15000) }),
  };
  if (data && method !== "GET") {
    opts.body = JSON.stringify(data);
  }
  // FIPS 140-3: Use FIPS HTTPS agent with self-signed cert support
  if (url.startsWith('https://')) {
    const { createFIPSHttpsAgent } = await import('../lib/fips-tls');
    // @ts-ignore - Node.js specific option
    opts.agent = createFIPSHttpsAgent({ rejectUnauthorized: false });
  }
  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `GoPhish ${method} ${endpoint}: ${res.status} ${text}` });
  }
  if (res.status === 204) return null;
  return res.json();
}

export const phishingOpsRouter = router({
  /**
   * getIntelFeed — Aggregate all campaign recommendations from completed domain intel scans.
   * Returns scan-derived phishing opportunities ranked by priority.
   */
  getIntelFeed: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      statusFilter: z.enum(["all", "unmaterialized", "materialized"]).default("all"),
    }).optional())
    .query(async ({ input }) => {
      const db = await requireDb();
      const opts = input || { limit: 50, statusFilter: "all" };

      // Get all completed scans with campaign recommendations
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

      // Get all existing drafts to check materialization status
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

      // Flatten all campaign recommendations into a unified feed
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

      // Sort by priority: critical > high > medium > low
      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      feed.sort((a, b) => {
        const pa = priorityOrder[a.recommendation?.priority] ?? 3;
        const pb = priorityOrder[b.recommendation?.priority] ?? 3;
        return pa - pb;
      });

      return {
        feed,
        totalScans: scans.length,
        totalRecommendations: feed.length,
      };
    }),

  /**
   * materialize — Convert a scan campaign recommendation into a phishing draft
   * with fully-formed GoPhish resources (email template, landing page, target group).
   * Uses LLM to generate realistic phishing content based on scan intelligence.
   */
  materialize: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      recommendationIndex: z.number(),
      // Optional overrides
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

      // Check if already materialized
      const existing = await db.select().from(phishingDrafts)
        .where(and(
          eq(phishingDrafts.scanId, input.scanId),
          sql`${phishingDrafts.campaignRecommendationIndex} = ${input.recommendationIndex}`
        ));
      if (existing.length > 0) {
        throw new TRPCError({ code: "CONFLICT", message: "This recommendation has already been materialized", cause: { draftId: existing[0].id } });
      }

      // Get the scan and its campaign recommendations
      const [scan] = await db.select().from(domainIntelScans)
        .where(eq(domainIntelScans.id, input.scanId));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const recs = (scan.campaignRecommendations as any[]) || [];
      const rec = recs[input.recommendationIndex];
      if (!rec) throw new TRPCError({ code: "NOT_FOUND", message: "Campaign recommendation not found at index" });

      const pipelineOut = scan.pipelineOutput as any;
      const actorMatches = pipelineOut?.threatActorMatches;
      const topActor = actorMatches?.topMatches?.[0];

      // Use LLM to generate realistic phishing email template and landing page
      const { invokeLLM } = await import("../_core/llm");

      const materializePrompt = `You are a red team phishing campaign designer for AceofCloud (AC3 platform).
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
  "smtpProfileName": "AC3 - ${scan.primaryDomain} Profile"
}

Make the phishing content highly realistic and tailored to the target domain and sector. Use professional language and branding cues from the target organization.`;

      let generatedContent: any = {};
      try {
        const llmResponse = await invokeLLM({ 
          _caller: "phishing-ops",
          messages: [
            { role: "system", content: `You are a red team phishing content generator. Output only valid JSON.

${buildPhishingKnowledgeContext({ includeLandingPages: true })}

When generating content, adapt the templates above to the specific target context. Use the pretext scripts as inspiration for realistic scenarios. Match landing page patterns to the campaign type.` },
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
        // Fall back to template-based generation
        generatedContent = {
          templateSubject: rec.gophishTemplates?.[0]?.subject || `Important: Action Required - ${scan.primaryDomain}`,
          templateHtml: `<html><body><p>Dear {{.FirstName}},</p><p>Please review the attached document regarding your ${scan.primaryDomain} account.</p><p><a href="{{.URL}}">Click here to review</a></p><p>Best regards,<br>IT Security Team</p></body></html>`,
          templateText: `Dear {{.FirstName}},\n\nPlease review the attached document regarding your ${scan.primaryDomain} account.\n\nClick here to review: {{.URL}}\n\nBest regards,\nIT Security Team`,
          landingPageHtml: `<html><body><h2>${scan.primaryDomain} - Login</h2><form method="POST"><input name="email" placeholder="Email" /><input name="password" type="password" placeholder="Password" /><button type="submit">Sign In</button></form></body></html>`,
          landingPageRedirectUrl: `https://${scan.primaryDomain}`,
          smtpProfileName: `AC3 - ${scan.primaryDomain} Profile`,
        };
      }

      const campaignName = input.campaignName || rec.name || `${scan.primaryDomain} - ${rec.type} Campaign`;
      const templateName = `[AC3] ${campaignName} - Template`;
      const landingPageName = `[AC3] ${campaignName} - Landing Page`;
      const targetGroupName = `[AC3] ${campaignName} - Targets`;

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
          campaignName: campaignName,
          status: "draft",
          message: "Draft already exists for this recommendation. Returning existing draft.",
          deduplicated: true,
        };
      }

      // Insert the draft
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

  /**
   * listDrafts — List all phishing drafts with filtering
   */
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

  /**
   * getDraft — Get a single draft by ID with full details
   */
  getDraft: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.id));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      return draft;
    }),

  /**
   * updateDraft — Edit a draft before deployment
   */
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

      // Check draft exists and is editable
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

  /**
   * deployToGophish — Push a draft's resources to the GoPhish server.
   * Creates template, landing page, and target group in GoPhish.
   * Does NOT launch the campaign — that's a separate step requiring operator approval.
   */
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

      // 1. Create Email Template in GoPhish
      if (draft.templateHtml) {
        try {
          const template = await fetchGophish("/api/templates/", "POST", {
            name: draft.templateName || `${draft.campaignName} - Template`,
            subject: draft.templateSubject || "Important Notification",
            html: draft.templateHtml,
            text: draft.templateText || "",
          });
          results.templateId = template?.id;
        } catch (e: any) {
          results.errors.push(`Template: ${e.message}`);
        }
      }

      // 2. Create Landing Page in GoPhish
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
        } catch (e: any) {
          results.errors.push(`Landing Page: ${e.message}`);
        }
      }

      // 3. Create Target Group in GoPhish
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
        } catch (e: any) {
          results.errors.push(`Target Group: ${e.message}`);
        }
      }

      // Update draft with GoPhish resource IDs
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

  /**
   * launchCampaign — Launch a deployed draft as a GoPhish campaign.
   * Requires all GoPhish resources to be deployed first.
   */
  launchCampaign: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      smtpProfileName: z.string(),
      phishingUrl: z.string(),
      launchDate: z.string().optional(),
      sendByDate: z.string().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });

      // ── ROE Scope Enforcement: validate phishing target domain is in scope ──
      if (input.engagementId && draft.targetDomain) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, draft.targetDomain, "GoPhish Campaign Launch", ctx);
      };
      if (draft.status !== "deployed") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Draft must be deployed to GoPhish before launching" });
      }
      if (!draft.gophishTemplateId || !draft.gophishGroupId) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Missing GoPhish template or target group" });
      }

      // Launch the campaign in GoPhish
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

      // Update draft with campaign ID and status
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

  /**
   * syncCampaignStats — Pull latest campaign stats from GoPhish for launched drafts
   */
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
        conditions.push(
          inArray(phishingDrafts.status, ["launched"] as any)
        );
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

  /**
   * triggerCaldera — After a phishing campaign captures credentials,
   * trigger a Cyber C2 operation for post-exploitation.
   */
  triggerCaldera: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      operationName: z.string().optional(),
      adversaryId: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();

      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });

      // Check if campaign has captured credentials
      const stats = draft.campaignStats as any;
      if (!stats || (stats.submitted || 0) === 0) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "No credentials captured yet. Wait for campaign results before triggering Caldera.",
        });
      }

      // Create a Cyber C2 operation using the linked abilities
      const { ENV } = await import("../_core/env");
      const calderaUrl = ENV.calderaBaseUrl;
      const calderaApiKey = ENV.calderaApiKey;

      if (!calderaUrl || !calderaApiKey) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Cyber C2 not configured" });
      }

      const operationName = input.operationName ||
        `[AC3] Post-Phish: ${draft.campaignName} - ${new Date().toISOString().split("T")[0]}`;

      const operationPayload: any = {
        name: operationName,
        autonomous: 0, // Manual mode for safety
        state: "paused", // Start paused so operator can review
      };

      if (input.adversaryId) {
        operationPayload.adversary = { adversary_id: input.adversaryId };
      }

      try {
        const res = await fetch(`${calderaUrl}/api/v2/operations`, {
          method: "POST",
          headers: {
            "KEY": calderaApiKey,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(operationPayload),
        });

        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error(`Caldera API error: ${res.status} ${text}`);
        }

        const operation = await res.json();

        // Update draft with Cyber C2 operation ID
        await db.update(phishingDrafts).set({
          calderaOperationId: operation.id || operation.name,
        }).where(eq(phishingDrafts.id, input.draftId));

        return {
          success: true,
          operationId: operation.id,
          operationName: operation.name,
          state: operation.state,
          message: `Cyber C2 operation "${operationName}" created in PAUSED state. Review and start manually.`,
        };
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to create Cyber C2 operation: ${e.message}`,
        });
      }
    }),

  /**
   * deleteDraft — Delete a draft (only if not launched)
   */
  deleteDraft: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.id));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });
      if (draft.status === "launched") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Cannot delete a launched campaign" });
      }
      await db.delete(phishingDrafts).where(eq(phishingDrafts.id, input.id));
      return { success: true };
    }),

  /**
   * getArsenal — Get all GoPhish resources (templates, pages, groups, profiles)
   * for the Arsenal tab
   */
  getArsenal: protectedProcedure.query(async () => {
    try {
      const [templates, pages, groups, smtp] = await Promise.all([
        fetchGophish("/api/templates/").catch(() => []),
        fetchGophish("/api/pages/").catch(() => []),
        fetchGophish("/api/groups/").catch(() => []),
        fetchGophish("/api/smtp/").catch(() => []),
      ]);

      return {
        online: true,
        templates: Array.isArray(templates) ? templates : [],
        landingPages: Array.isArray(pages) ? pages : [],
        groups: Array.isArray(groups) ? groups : [],
        sendingProfiles: Array.isArray(smtp) ? smtp : [],
      };
    } catch {
      return {
        online: false,
        templates: [],
        landingPages: [],
        groups: [],
        sendingProfiles: [],
      };
    }
  }),

  /**
   * deleteGophishTemplate — Delete a template from GoPhish
   */
  deleteGophishTemplate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/templates/${input.id}`, "DELETE");
      return { success: true };
    }),

  /**
   * deleteGophishPage — Delete a landing page from GoPhish
   */
  deleteGophishPage: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/pages/${input.id}`, "DELETE");
      return { success: true };
    }),

  /**
   * deleteGophishGroup — Delete a target group from GoPhish
   */
  deleteGophishGroup: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/groups/${input.id}`, "DELETE");
      return { success: true };
    }),

  /**
   * identifyStaleResources — Scan GoPhish for empty/test/stale resources
   * Returns resources that appear to be empty, test, or placeholder items
   */
  identifyStaleResources: protectedProcedure.query(async () => {
    const [templates, pages, groups] = await Promise.all([
      fetchGophish("/api/templates/").catch(() => []),
      fetchGophish("/api/pages/").catch(() => []),
      fetchGophish("/api/groups/").catch(() => []),
    ]);

    const staleTemplates = (Array.isArray(templates) ? templates : []).filter((t: any) => {
      const html = t.html || '';
      const subject = t.subject || '';
      const name = (t.name || '').toLowerCase();
      // Empty body or very short body
      const isEmpty = html.trim().length < 20;
      // Test/placeholder names
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(name);
      // No subject
      const noSubject = subject.trim().length === 0;
      return isEmpty || isTest || (noSubject && html.trim().length < 100);
    });

    const stalePages = (Array.isArray(pages) ? pages : []).filter((p: any) => {
      const html = p.html || '';
      const name = (p.name || '').toLowerCase();
      const isEmpty = html.trim().length < 20;
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default|^new page/i.test(name);
      return isEmpty || isTest;
    });

    const staleGroups = (Array.isArray(groups) ? groups : []).filter((g: any) => {
      const targets = g.targets || [];
      const name = (g.name || '').toLowerCase();
      const isEmpty = targets.length === 0;
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default/i.test(name);
      return isEmpty || isTest;
    });

    return {
      staleTemplates: staleTemplates.map((t: any) => ({
        id: t.id,
        name: t.name,
        subject: t.subject || '',
        htmlLength: (t.html || '').length,
        reason: (t.html || '').trim().length < 20 ? 'empty_body' :
          /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(t.name || '') ? 'test_name' : 'no_subject',
        modifiedDate: t.modified_date,
      })),
      stalePages: stalePages.map((p: any) => ({
        id: p.id,
        name: p.name,
        htmlLength: (p.html || '').length,
        reason: (p.html || '').trim().length < 20 ? 'empty_body' : 'test_name',
        modifiedDate: p.modified_date,
      })),
      staleGroups: staleGroups.map((g: any) => ({
        id: g.id,
        name: g.name,
        targetCount: (g.targets || []).length,
        reason: (g.targets || []).length === 0 ? 'no_targets' : 'test_name',
        modifiedDate: g.modified_date,
      })),
      summary: {
        totalStale: staleTemplates.length + stalePages.length + staleGroups.length,
        staleTemplateCount: staleTemplates.length,
        stalePageCount: stalePages.length,
        staleGroupCount: staleGroups.length,
      },
    };
  }),

  /**
   * bulkCleanup — Delete multiple stale GoPhish resources at once
   */
  bulkCleanup: protectedProcedure
    .input(z.object({
      templateIds: z.array(z.number()).default([]),
      pageIds: z.array(z.number()).default([]),
      groupIds: z.array(z.number()).default([]),
    }))
    .mutation(async ({ input }) => {
      const results = { deletedTemplates: 0, deletedPages: 0, deletedGroups: 0, errors: [] as string[] };

      for (const id of input.templateIds) {
        try {
          await fetchGophish(`/api/templates/${id}`, "DELETE");
          results.deletedTemplates++;
        } catch (e: any) {
          results.errors.push(`Template ${id}: ${e.message}`);
        }
      }
      for (const id of input.pageIds) {
        try {
          await fetchGophish(`/api/pages/${id}`, "DELETE");
          results.deletedPages++;
        } catch (e: any) {
          results.errors.push(`Page ${id}: ${e.message}`);
        }
      }
      for (const id of input.groupIds) {
        try {
          await fetchGophish(`/api/groups/${id}`, "DELETE");
          results.deletedGroups++;
        } catch (e: any) {
          results.errors.push(`Group ${id}: ${e.message}`);
        }
      }

      return results;
    }),

  /**
   * generateReport — Generate a branded AceofCloud post-campaign report
   * Pulls GoPhish campaign stats + Cyber C2 operation results into a structured report.
   */
  generateReport: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      includeCaldera: z.boolean().default(true),
      includeRecommendations: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();

      const [draft] = await db.select().from(phishingDrafts)
        .where(eq(phishingDrafts.id, input.draftId));
      if (!draft) throw new TRPCError({ code: "NOT_FOUND", message: "Draft not found" });

      // ── Pull compliance frameworks from the source domain intel scan ──
      let complianceFrameworks: string[] = [];
      let scanOrgProfile: any = null;
      let scanSummaries: any = null;
      if (draft.scanId) {
        const [sourceScan] = await db.select().from(domainIntelScans)
          .where(eq(domainIntelScans.id, draft.scanId));
        if (sourceScan) {
          complianceFrameworks = (sourceScan.complianceFlags as string[]) || [];
          scanOrgProfile = sourceScan.orgProfile as any;
          scanSummaries = (sourceScan as any).summaries;
          // Also check orgProfile for compliance
          if (complianceFrameworks.length === 0 && scanOrgProfile?.complianceFlags) {
            complianceFrameworks = scanOrgProfile.complianceFlags;
          }
        }
      }
      // Also check engagement pipeline orgProfile for compliance
      if (complianceFrameworks.length === 0 && draft.engagementId) {
        try {
          const [pipeline] = await db.select().from(engagementPipelines)
            .where(eq(engagementPipelines.id, draft.engagementId));
          if (pipeline) {
            const pipeOrgProfile = pipeline.orgProfile as any;
            if (pipeOrgProfile?.complianceFlags) {
              complianceFrameworks = pipeOrgProfile.complianceFlags;
            }
          }
        } catch (_) { /* ignore */ }
      }

      // Sync latest stats from GoPhish
      let campaignDetail: any = null;
      if (draft.gophishCampaignId) {
        try {
          campaignDetail = await fetchGophish(`/api/campaigns/${draft.gophishCampaignId}`);
        } catch (e: any) {
          console.warn(`[Report] Could not fetch campaign detail:`, e.message);
        }
      }

      const stats = (draft.campaignStats as any) || campaignDetail?.stats || {};
      const total = stats.total || 0;
      const sent = stats.sent || 0;
      const opened = stats.opened || 0;
      const clicked = stats.clicked || 0;
      const submitted = stats.submitted || stats.submitted_data || 0;
      const reported = stats.reported || stats.email_reported || 0;

      // Calculate rates
      const openRate = total > 0 ? ((opened / total) * 100).toFixed(1) : "0.0";
      const clickRate = total > 0 ? ((clicked / total) * 100).toFixed(1) : "0.0";
      const submitRate = total > 0 ? ((submitted / total) * 100).toFixed(1) : "0.0";
      const reportRate = total > 0 ? ((reported / total) * 100).toFixed(1) : "0.0";

      // Risk score calculation
      let riskScore = 0;
      if (total > 0) {
        riskScore = Math.round(
          (opened / total) * 15 +
          (clicked / total) * 35 +
          (submitted / total) * 50
        );
      }
      const riskLevel = riskScore >= 70 ? "Critical" :
        riskScore >= 50 ? "High" :
        riskScore >= 30 ? "Medium" : "Low";

      // Cyber C2 operation results
      let calderaResults: any = null;
      if (input.includeCaldera && draft.calderaOperationId) {
        try {
          const { ENV } = await import("../_core/env");
          const calderaUrl = ENV.calderaBaseUrl;
          const calderaApiKey = ENV.calderaApiKey;
          if (calderaUrl && calderaApiKey) {
            const opRes = await fetch(`${calderaUrl}/api/v2/operations/${draft.calderaOperationId}`, {
              headers: { "KEY": calderaApiKey },
            });
            if (opRes.ok) {
              calderaResults = await opRes.json();
            }
          }
        } catch (e: any) {
          console.warn(`[Report] Could not fetch Cyber C2 operation:`, e.message);
        }
      }

      // Get timeline events from GoPhish
      let timelineEvents: any[] = [];
      if (campaignDetail?.timeline) {
        timelineEvents = campaignDetail.timeline.map((e: any) => ({
          time: e.time,
          message: e.message,
          email: e.email,
        })).slice(0, 50); // Limit to 50 events
      }

      // ── Build compliance framework context for the LLM ──
      const FRAMEWORK_DETAILS: Record<string, { fullName: string; relevantControls: string }> = {
        "SOC2": { fullName: "SOC 2 Type II", relevantControls: "CC6.1 (Logical Access), CC6.6 (External Threats), CC7.2 (Monitoring), CC8.1 (Change Management)" },
        "HIPAA": { fullName: "HIPAA Security Rule", relevantControls: "§164.308(a)(5) Security Awareness Training, §164.312(d) Authentication, §164.308(a)(1) Risk Analysis" },
        "PCI-DSS": { fullName: "PCI DSS v4.0", relevantControls: "Req 5.4 (Anti-Phishing), Req 8.3 (MFA), Req 12.6 (Security Awareness), Req 12.10 (Incident Response)" },
        "GDPR": { fullName: "EU GDPR", relevantControls: "Art 32 (Security of Processing), Art 33 (Breach Notification), Art 39 (DPO Tasks), Art 5(1)(f) (Integrity & Confidentiality)" },
        "NIST": { fullName: "NIST CSF 2.0 / NIST 800-53", relevantControls: "PR.AT (Awareness & Training), DE.CM (Continuous Monitoring), RS.RP (Response Planning), ID.RA (Risk Assessment)" },
        "ISO27001": { fullName: "ISO/IEC 27001:2022", relevantControls: "A.6.3 (Awareness/Training), A.8.7 (Malware Protection), A.5.24 (Incident Management), A.8.16 (Monitoring)" },
        "FedRAMP": { fullName: "FedRAMP (NIST 800-53)", relevantControls: "AT-2 (Literacy Training), IR-4 (Incident Handling), SI-3 (Malicious Code Protection), CA-8 (Penetration Testing)" },
        "CMMC": { fullName: "CMMC 2.0", relevantControls: "AT.L2-3.2.1 (Role-Based Training), AT.L2-3.2.2 (Literacy Training), IR.L2-3.6.1 (Incident Handling), SI.L2-3.14.2 (Malicious Code Protection)" },
        "SOX": { fullName: "Sarbanes-Oxley Act", relevantControls: "Section 302 (Internal Controls), Section 404 (Assessment of Internal Controls), IT General Controls" },
        "CCPA": { fullName: "California Consumer Privacy Act", relevantControls: "§1798.150 (Data Security), §1798.100 (Consumer Rights), Reasonable Security Measures" },
        "FERPA": { fullName: "Family Educational Rights and Privacy Act", relevantControls: "§99.31 (Disclosure Conditions), Technical Safeguards, Access Controls" },
        "ITAR": { fullName: "International Traffic in Arms Regulations", relevantControls: "§120.17 (Defense Services), §127.1 (Violations), Access Control for Technical Data" },
      };

      const complianceContext = complianceFrameworks.length > 0
        ? complianceFrameworks.map(f => {
            const details = FRAMEWORK_DETAILS[f];
            return details
              ? `${f} (${details.fullName}): Relevant controls — ${details.relevantControls}`
              : f;
          }).join("\n")
        : "No specific compliance frameworks selected";

      // LLM-generated executive summary, recommendations, and compliance analysis
      let executiveSummary = "";
      let recommendations: string[] = [];
      let complianceAnalysis: any[] = [];
      if (input.includeRecommendations) {
        try {
          const { invokeLLM } = await import("../_core/llm");
          const reportPrompt = `You are a cybersecurity consultant at AceofCloud generating a post-campaign phishing assessment report.

CAMPAIGN: ${draft.campaignName}
TARGET DOMAIN: ${draft.targetDomain}
SECTOR: ${draft.targetSector || "Unknown"}
CAMPAIGN TYPE: ${draft.campaignType}
THREAT ACTOR SIMULATED: ${draft.threatActorName || "Generic"}

RESULTS:
- Total targets: ${total}
- Emails sent: ${sent}
- Emails opened: ${opened} (${openRate}%)
- Links clicked: ${clicked} (${clickRate}%)
- Credentials submitted: ${submitted} (${submitRate}%)
- Emails reported as phishing: ${reported} (${reportRate}%)
- Risk Score: ${riskScore}/100 (${riskLevel})

ATTACK CHAIN: ${JSON.stringify(draft.attackChain || [])}
${calderaResults ? `CALDERA POST-EXPLOITATION: Operation ran with ${calderaResults.chain?.length || 0} steps` : ""}

COMPLIANCE FRAMEWORKS SELECTED FOR THIS ENGAGEMENT:
${complianceContext}

Generate a JSON object with:
{
  "executiveSummary": "A 2-3 paragraph executive summary suitable for C-level stakeholders. Discuss the campaign objectives, key findings, and overall organizational risk posture. Be specific about what the results mean for the organization. If compliance frameworks were selected, reference how the phishing results impact compliance posture.",
  "recommendations": ["Array of 5-7 specific, actionable security recommendations based on the results. Each should be 1-2 sentences. If compliance frameworks are selected, include framework-specific remediation guidance."],
  "complianceAnalysis": [${complianceFrameworks.length > 0 ? `"For EACH selected compliance framework, provide an object with: framework (the framework ID like SOC2), fullName, status (compliant/partial/non_compliant/at_risk), impactedControls (array of specific control IDs that are impacted by the phishing results), findings (1-2 sentence description of how the phishing results affect this framework), remediationSteps (array of 2-3 specific remediation actions to address the gap)"` : `"Return empty array if no compliance frameworks selected"`}]
}

Be thorough and specific about compliance impact. Map the phishing campaign results directly to control failures or gaps in each framework.`;

          const llmResponse = await invokeLLM({ 
            _caller: "phishing-ops",
            messages: [
              { role: "system", content: "You are a cybersecurity compliance consultant. Output only valid JSON." },
              { role: "user", content: reportPrompt },
            ],
            response_format: {
              type: "json_schema",
              json_schema: {
                name: "campaign_report",
                strict: true,
                schema: {
                  type: "object",
                  properties: {
                    executiveSummary: { type: "string", description: "Executive summary" },
                    recommendations: {
                      type: "array",
                      items: { type: "string" },
                      description: "Security recommendations",
                    },
                    complianceAnalysis: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          framework: { type: "string", description: "Framework ID (e.g. SOC2, HIPAA)" },
                          fullName: { type: "string", description: "Full framework name" },
                          status: { type: "string", description: "compliant, partial, non_compliant, or at_risk" },
                          impactedControls: {
                            type: "array",
                            items: { type: "string" },
                            description: "Specific control IDs impacted",
                          },
                          findings: { type: "string", description: "How phishing results affect this framework" },
                          remediationSteps: {
                            type: "array",
                            items: { type: "string" },
                            description: "Specific remediation actions",
                          },
                        },
                        required: ["framework", "fullName", "status", "impactedControls", "findings", "remediationSteps"],
                        additionalProperties: false,
                      },
                      description: "Per-framework compliance gap analysis",
                    },
                  },
                  required: ["executiveSummary", "recommendations", "complianceAnalysis"],
                  additionalProperties: false,
                },
              },
            },
          });
          const rawContent = llmResponse?.choices?.[0]?.message?.content;
          if (rawContent && typeof rawContent === "string") {
            const parsed = JSON.parse(rawContent);
            executiveSummary = parsed.executiveSummary || "";
            recommendations = parsed.recommendations || [];
            complianceAnalysis = parsed.complianceAnalysis || [];
          }
        } catch (e: any) {
          console.warn(`[Report] LLM report generation failed:`, e.message);
          executiveSummary = `The ${draft.campaignName} phishing simulation targeting ${draft.targetDomain} has concluded. Out of ${total} targets, ${opened} opened the email (${openRate}%), ${clicked} clicked the phishing link (${clickRate}%), and ${submitted} submitted credentials (${submitRate}%). The overall risk score is ${riskScore}/100 (${riskLevel}).`;
          recommendations = [
            "Implement mandatory phishing awareness training for all employees.",
            "Deploy email authentication protocols (SPF, DKIM, DMARC) if not already in place.",
            "Consider implementing multi-factor authentication across all critical systems.",
            "Establish a clear incident reporting process for suspected phishing emails.",
            "Conduct regular phishing simulations to track improvement over time.",
          ];
          // Generate basic compliance analysis from framework details
          complianceAnalysis = complianceFrameworks.map(f => {
            const details = FRAMEWORK_DETAILS[f];
            return {
              framework: f,
              fullName: details?.fullName || f,
              status: riskScore >= 50 ? "non_compliant" : riskScore >= 30 ? "at_risk" : "partial",
              impactedControls: (details?.relevantControls || "").split(", "),
              findings: `Phishing simulation results indicate a ${riskLevel.toLowerCase()} risk to ${details?.fullName || f} compliance. ${submitRate}% credential submission rate suggests gaps in security awareness controls.`,
              remediationSteps: [
                `Implement ${details?.fullName || f}-aligned security awareness training program.`,
                "Deploy technical controls (MFA, email filtering) to reduce phishing attack surface.",
                "Establish regular phishing simulation cadence to demonstrate continuous compliance.",
              ],
            };
          });
        }
      }

      const report = {
        // Report metadata
        reportId: `ACE-RPT-${draft.id}-${Date.now().toString(36).toUpperCase()}`,
        generatedAt: new Date().toISOString(),
        generatedBy: ctx.user?.name || "AceofCloud Operator",
        branding: {
          company: "AceofCloud",
          platform: "AC3 — Command, Control, Conquer",
          author: "Harrison Cook",
          website: "https://aceofcloud.com",
        },

        // Campaign overview
        campaign: {
          name: draft.campaignName,
          type: draft.campaignType,
          targetDomain: draft.targetDomain,
          targetSector: draft.targetSector,
          priority: draft.priority,
          threatActorSimulated: draft.threatActorName || null,
          matchRationale: draft.matchRationale || null,
          launchDate: draft.launchDate?.toISOString() || null,
          status: draft.status,
        },

        // Statistics
        statistics: {
          total,
          sent,
          opened,
          clicked,
          submitted,
          reported,
          openRate: parseFloat(openRate),
          clickRate: parseFloat(clickRate),
          submitRate: parseFloat(submitRate),
          reportRate: parseFloat(reportRate),
          riskScore,
          riskLevel,
        },

        // Attack chain
        attackChain: draft.attackChain || [],

        // Caldera results
        caldera: calderaResults ? {
          operationId: draft.calderaOperationId,
          operationName: calderaResults.name,
          state: calderaResults.state,
          stepsExecuted: calderaResults.chain?.length || 0,
          abilities: (calderaResults.chain || []).map((step: any) => ({
            name: step.ability?.name || step.name,
            tactic: step.ability?.tactic || step.tactic,
            status: step.status,
          })),
        } : null,

        // Timeline (first 50 events)
        timeline: timelineEvents,

        // LLM-generated content
        executiveSummary,
        recommendations,

        // Compliance framework analysis
        compliance: {
          frameworks: complianceFrameworks,
          analysis: complianceAnalysis,
          hasFrameworks: complianceFrameworks.length > 0,
        },
      };

      return report;
    }),

  // ─── Phishing Exploit Library ──────────────────────────────────────

  /** List all available phishing exploits with optional category filter */
  listPhishingExploits: protectedProcedure
    .input(z.object({
      category: z.string().optional(),
      target: z.enum(['email', 'landing_page', 'both']).optional(),
    }).optional())
    .query(async ({ input }) => {
      const { PHISHING_EXPLOITS } = await import('../lib/phishing-exploits');
      let exploits = [...PHISHING_EXPLOITS];
      if (input?.category) {
        exploits = exploits.filter(e => e.category === input.category);
      }
      if (input?.target) {
        exploits = exploits.filter(e => e.target === input.target || e.target === 'both');
      }
      return exploits.map(e => ({
        id: e.id,
        name: e.name,
        category: e.category,
        description: e.description,
        mitreId: e.mitreId,
        mitreName: e.mitreName,
        target: e.target,
        difficulty: e.difficulty,
        effectiveness: e.effectiveness,
        enablesRemoteAccess: e.enablesRemoteAccess,
        detectionIndicators: e.detectionIndicators,
        prerequisites: e.prerequisites,
        hasInjectableCode: !!e.landingPageCode,
      }));
    }),

  /** Match phishing exploits to a specific scan's intelligence */
  matchExploitsForScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { matchPhishingExploits } = await import('../lib/phishing-exploits');
      const db = await requireDb();
      const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
      const pipelineOut = scan.pipelineOutput as any;
      const technologies = (pipelineOut?.discoveredAssets || []).flatMap((a: any) => Object.keys(a.technologyVersions || {}));
      const hasWebmail = technologies.some((t: string) => /exchange|owa|outlook|webmail|zimbra/i.test(t));
      const usesSSO = technologies.some((t: string) => /azure|okta|saml|oauth|adfs/i.test(t));
      const idpProvider = technologies.some((t: string) => /azure|microsoft|office365/i.test(t)) ? 'microsoft' :
        technologies.some((t: string) => /google|gsuite|workspace/i.test(t)) ? 'google' :
        technologies.some((t: string) => /okta/i.test(t)) ? 'okta' : undefined;
      const confirmedCves = (pipelineOut?.postureFindings || []).filter((f: any) => f.corroborationTier === 'confirmed').map((f: any) => f.cveId).filter(Boolean);
      const matches = matchPhishingExploits({
        sector: scan.sector || 'technology',
        technologies,
        hasWebmail,
        usesMfa: true,
        usesSSO,
        idpProvider,
        confirmedCves,
      });
      return matches.map(m => ({
        exploit: {
          id: m.exploit.id,
          name: m.exploit.name,
          category: m.exploit.category,
          description: m.exploit.description,
          mitreId: m.exploit.mitreId,
          mitreName: m.exploit.mitreName,
          target: m.exploit.target,
          difficulty: m.exploit.difficulty,
          effectiveness: m.exploit.effectiveness,
          enablesRemoteAccess: m.exploit.enablesRemoteAccess,
          detectionIndicators: m.exploit.detectionIndicators,
        },
        relevanceScore: m.relevanceScore,
        matchReason: m.matchReason,
      }));
    }),

  /** Enhance a draft's landing page with selected exploit injections */
  enhanceDraftWithExploits: protectedProcedure
    .input(z.object({
      draftId: z.number(),
      exploitIds: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      const { enhanceLandingPage, PHISHING_EXPLOITS } = await import('../lib/phishing-exploits');
      const db = await requireDb();
      const [draft] = await db.select().from(phishingDrafts).where(eq(phishingDrafts.id, input.draftId)).limit(1);
      if (!draft) throw new TRPCError({ code: 'NOT_FOUND', message: 'Draft not found' });
      if (!draft.landingPageHtml) throw new TRPCError({ code: 'BAD_REQUEST', message: 'Draft has no landing page HTML' });
      
      const validIds = input.exploitIds.filter(id => PHISHING_EXPLOITS.some(e => e.id === id));
      if (validIds.length === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No valid exploit IDs' });
      
      const enhanced = enhanceLandingPage(draft.landingPageHtml, validIds);
      const exploitMeta = validIds.map(id => {
        const e = PHISHING_EXPLOITS.find(ex => ex.id === id)!;
        return { id: e.id, name: e.name, category: e.category, mitreId: e.mitreId, enablesRemoteAccess: e.enablesRemoteAccess };
      });
      
      await db.update(phishingDrafts).set({
        exploitEnhancedLandingPage: enhanced,
        phishingExploits: [...(draft.phishingExploits as any[] || []), ...exploitMeta],
      }).where(eq(phishingDrafts.id, input.draftId));
      
      return { success: true, enhancedHtml: enhanced, exploitsApplied: exploitMeta.length };
    }),
});
