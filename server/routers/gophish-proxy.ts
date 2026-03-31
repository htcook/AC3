import { fetchGophishAPI, cachedFetch } from "../lib/api-helpers";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as schema from "../../drizzle/schema";

export const gophishProxyRouter = router({
    // GoPhish API helper
    getCampaigns: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/campaigns/');
    }),

    getCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}`);
      }),

    getCampaignResults: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}/results`);
      }),

    getTemplates: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/templates/');
    }),

    createTemplate: protectedProcedure
      .input(z.object({
        name: z.string(),
        subject: z.string(),
        html: z.string(),
        text: z.string().optional(),
        attachments: z.array(z.any()).optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/templates/', 'POST', input);
      }),

    getLandingPages: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/pages/');
    }),

    createLandingPage: protectedProcedure
      .input(z.object({
        name: z.string(),
        html: z.string(),
        capture_credentials: z.boolean().optional(),
        capture_passwords: z.boolean().optional(),
        redirect_url: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/pages/', 'POST', input);
      }),

    getSendingProfiles: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/smtp/');
    }),

    createSendingProfile: protectedProcedure
      .input(z.object({
        name: z.string(),
        host: z.string(),
        from_address: z.string(),
        username: z.string().optional(),
        password: z.string().optional(),
        ignore_cert_errors: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/smtp/', 'POST', input);
      }),

    getGroups: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/groups/');
    }),

    createGroup: protectedProcedure
      .input(z.object({
        name: z.string(),
        targets: z.array(z.object({
          first_name: z.string().optional(),
          last_name: z.string().optional(),
          email: z.string(),
          position: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/groups/', 'POST', input);
      }),

    launchCampaign: protectedProcedure
      .input(z.object({
        name: z.string(),
        template: z.object({ name: z.string() }),
        page: z.object({ name: z.string() }),
        smtp: z.object({ name: z.string() }),
        url: z.string(),
        groups: z.array(z.object({ name: z.string() })),
        launch_date: z.string().optional(),
        send_by_date: z.string().optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ─── ROE Enforcement (RED tier) ───
        const { enforceROE, getEngagementROE, logOffensiveAction } = await import('../lib/roe-guard');
        if (input.engagementId) {
          const roe = await getEngagementROE(input.engagementId);
          if (roe) enforceROE(roe, 'red', `Phishing campaign launch: ${input.name}`);
        }
        logOffensiveAction({
          engagementId: input.engagementId ?? null,
          operatorId: ctx.user.openId,
          operatorName: ctx.user.name ?? null,
          actionType: 'phishing_launch',
          riskTier: 'red',
          target: input.url,
          moduleOrTool: `GoPhish Campaign: ${input.name}`,
          resultStatus: 'success',
        }).catch(() => {});

        const result = await fetchGophishAPI('/api/campaigns/', 'POST', input);
        // Emit campaign launched event
        try {
          const { emitCampaignEvent } = await import('../lib/ws-event-hub');
          emitCampaignEvent({ campaignId: (result as any)?.id || 0, eventType: 'launched' });
        } catch { /* non-critical */ }
        return result;
      }),

    deleteCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}`, 'DELETE');
      }),

    completeCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}/complete`, 'GET');
      }),

    // Template CRUD
    getTemplate: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/templates/${input.id}`);
      }),

    updateTemplate: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        subject: z.string(),
        html: z.string(),
        text: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/templates/${id}`, 'PUT', { id, ...data });
      }),

    deleteTemplate: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/templates/${input.id}`, 'DELETE');
      }),

    // Landing Page CRUD
    getLandingPage: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/pages/${input.id}`);
      }),

    updateLandingPage: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        html: z.string(),
        capture_credentials: z.boolean().optional(),
        capture_passwords: z.boolean().optional(),
        redirect_url: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/pages/${id}`, 'PUT', { id, ...data });
      }),

    deleteLandingPage: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/pages/${input.id}`, 'DELETE');
      }),

    // Sending Profile CRUD
    getSendingProfile: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/smtp/${input.id}`);
      }),

    updateSendingProfile: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        host: z.string(),
        from_address: z.string(),
        username: z.string().optional(),
        password: z.string().optional(),
        ignore_cert_errors: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/smtp/${id}`, 'PUT', { id, ...data });
      }),

    deleteSendingProfile: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/smtp/${input.id}`, 'DELETE');
      }),

    // Group CRUD
    getGroup: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/groups/${input.id}`);
      }),

    updateGroup: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        targets: z.array(z.object({
          first_name: z.string().optional(),
          last_name: z.string().optional(),
          email: z.string(),
          position: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/groups/${id}`, 'PUT', { id, ...data });
      }),

    deleteGroup: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/groups/${input.id}`, 'DELETE');
      }),

    // Sync phishing templates to GoPhish
    syncTemplates: protectedProcedure
      .input(z.object({
        templates: z.array(z.object({
          name: z.string(),
          subject: z.string(),
          html: z.string(),
          text: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const results: Array<{ name: string; success: boolean; id?: number; error?: string }> = [];

        // Get existing templates to check for duplicates
        const existing = await fetchGophishAPI('/api/templates/');
        const existingNames = new Set(
          Array.isArray(existing) ? existing.map((t: any) => t.name.toLowerCase()) : []
        );

        for (const template of input.templates) {
          if (existingNames.has(template.name.toLowerCase())) {
            results.push({ name: template.name, success: true, error: 'Already exists (skipped)' });
            continue;
          }
          try {
            const result = await fetchGophishAPI('/api/templates/', 'POST', template);
            if (result && result.id) {
              results.push({ name: template.name, success: true, id: result.id });
            } else {
              results.push({ name: template.name, success: false, error: 'API returned no ID' });
            }
          } catch (err: any) {
            results.push({ name: template.name, success: false, error: err.message });
          }
        }
        return results;
      }),

    // Get detailed campaign results for engagement aggregation
    getCampaignSummary: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const campaign = await fetchGophishAPI(`/api/campaigns/${input.id}`);
        if (!campaign) return null;
        const results = await fetchGophishAPI(`/api/campaigns/${input.id}/results`);
        return {
          id: campaign.id,
          name: campaign.name,
          status: campaign.status,
          created_date: campaign.created_date,
          completed_date: campaign.completed_date,
          launch_date: campaign.launch_date,
          send_by_date: campaign.send_by_date,
          template: campaign.template ? { name: campaign.template.name } : null,
          page: campaign.page ? { name: campaign.page.name } : null,
          smtp: campaign.smtp ? { name: campaign.smtp.name, from_address: campaign.smtp.from_address } : null,
          groups: campaign.groups || [],
          url: campaign.url,
          stats: campaign.stats || {},
          timeline: campaign.timeline || [],
          results: results?.results || [],
        };
      }),

    // Get GoPhish server status
    getStatus: protectedProcedure.query(async () => {
      try {
        const campaigns = await fetchGophishAPI('/api/campaigns/');
        const templates = await fetchGophishAPI('/api/templates/');
        const pages = await fetchGophishAPI('/api/pages/');
        const groups = await fetchGophishAPI('/api/groups/');
        const smtp = await fetchGophishAPI('/api/smtp/');
        return {
          online: true,
          campaigns: Array.isArray(campaigns) ? campaigns.length : 0,
          templates: Array.isArray(templates) ? templates.length : 0,
          landingPages: Array.isArray(pages) ? pages.length : 0,
          groups: Array.isArray(groups) ? groups.length : 0,
          sendingProfiles: Array.isArray(smtp) ? smtp.length : 0,
        };
      } catch {
        return { online: false, campaigns: 0, templates: 0, landingPages: 0, groups: 0, sendingProfiles: 0 };
      }
    }),

    // Aggregated GoPhish stats for dashboard — cached for 30s
    getStats: protectedProcedure.query(async () => {
      return cachedFetch('gophish:stats', async () => {
        try {
        const [campaigns, templates, pages, groups, smtp] = await Promise.all([
          fetchGophishAPI('/api/campaigns/'),
          fetchGophishAPI('/api/templates/'),
          fetchGophishAPI('/api/pages/'),
          fetchGophishAPI('/api/groups/'),
          fetchGophishAPI('/api/smtp/'),
        ]);

        const campaignList = Array.isArray(campaigns) ? campaigns : [];
        const activeCampaigns = campaignList.filter((c: any) => c.status === 'In progress');
        const completedCampaigns = campaignList.filter((c: any) => c.status === 'Completed');

        // Aggregate email metrics across all campaigns
        let totalSent = 0;
        let totalOpened = 0;
        let totalClicked = 0;
        let totalSubmitted = 0;
        let totalReported = 0;
        let totalTargets = 0;

        const recentEvents: Array<{ time: string; message: string; campaign: string; status: string }> = [];

        for (const campaign of campaignList) {
          if (campaign.stats) {
            const s = campaign.stats;
            totalSent += s.sent || 0;
            totalOpened += s.opened || 0;
            totalClicked += s.clicked || 0;
            totalSubmitted += s.submitted_data || 0;
            totalReported += s.email_reported || 0;
            totalTargets += s.total || 0;
          }
          // Collect recent timeline events
          if (Array.isArray(campaign.timeline)) {
            for (const event of campaign.timeline.slice(-5)) {
              recentEvents.push({
                time: event.time || '',
                message: event.message || event.details || '',
                campaign: campaign.name || '',
                status: event.message || '',
              });
            }
          }
        }

        // Sort recent events by time descending, take top 10
        recentEvents.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());

        return {
          online: true,
          totalCampaigns: campaignList.length,
          activeCampaigns: activeCampaigns.length,
          completedCampaigns: completedCampaigns.length,
          totalTemplates: Array.isArray(templates) ? templates.length : 0,
          totalLandingPages: Array.isArray(pages) ? pages.length : 0,
          totalGroups: Array.isArray(groups) ? groups.length : 0,
          totalSendingProfiles: Array.isArray(smtp) ? smtp.length : 0,
          totalTargets,
          emailMetrics: {
            sent: totalSent,
            opened: totalOpened,
            clicked: totalClicked,
            submitted: totalSubmitted,
            reported: totalReported,
          },
          recentEvents: recentEvents.slice(0, 10),
          campaigns: campaignList.map((c: any) => ({
            id: c.id,
            name: c.name,
            status: c.status,
            created_date: c.created_date,
            completed_date: c.completed_date,
            stats: c.stats || {},
          })),
        };
        } catch {
          return {
            online: false,
            totalCampaigns: 0,
            activeCampaigns: 0,
            completedCampaigns: 0,
            totalTemplates: 0,
            totalLandingPages: 0,
            totalGroups: 0,
            totalSendingProfiles: 0,
            totalTargets: 0,
            emailMetrics: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 },
            recentEvents: [],
            campaigns: [],
          };
        }
      }, 30_000);
    }),
  });
