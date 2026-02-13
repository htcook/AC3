import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import * as db from "./db";
import jwt from "jsonwebtoken";

// Caldera session cookie name
const CALDERA_SESSION_COOKIE = 'caldera_session';

// JWT secret for Caldera sessions (use env var in production)
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// Admin-only procedure
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== 'admin') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Admin access required' });
  }
  return next({ ctx });
});

// GoPhish API helper
const GOPHISH_URL = 'https://gophish.aceofcloud.io';
const GOPHISH_API_KEY = '186292e5e312962ad1fdfc9ecbc21453e6073daf6554861371bd4da0fa61a5a2';

async function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  try {
    const url = `${GOPHISH_URL}${endpoint}`;
    const options: RequestInit = {
      method,
      headers: {
        'Authorization': GOPHISH_API_KEY,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    };
    if (data) options.body = JSON.stringify(data);
    
    const response = await fetch(url, options);
    if (!response.ok) {
      const errText = await response.text();
      console.error(`GoPhish API error (${endpoint}):`, response.status, errText);
      return null;
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  } catch (error) {
    console.error(`GoPhish API error (${endpoint}):`, error);
    return null;
  }
}

// Caldera API helper
async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const response = await fetch(`${url}${endpoint}`, {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(30000), // 30 second timeout for large responses
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Caldera API error (${endpoint}):`, error);
    return null;
  }
}

export const appRouter = router({
  system: systemRouter,
  
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  // Server configuration management
  server: router({
    list: protectedProcedure.query(async () => {
      return db.getServerConfigs();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getServerConfigById(input.id);
      }),

    create: adminProcedure
      .input(z.object({
        name: z.string().min(1),
        ipAddress: z.string().min(1),
        httpsUrl: z.string().optional(),
        httpUrl: z.string().optional(),
        region: z.string().optional(),
        dropletSize: z.string().optional(),
        dropletId: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createServerConfig(input);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: id,
          action: 'server_created',
          details: `Created server: ${input.name}`,
        });
        return { id };
      }),

    updateStatus: adminProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['online', 'offline', 'unknown']),
      }))
      .mutation(async ({ input }) => {
        await db.updateServerStatus(input.id, input.status);
        return { success: true };
      }),

    checkHealth: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const server = await db.getServerConfigById(input.id);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.id);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) {
          await db.updateServerStatus(input.id, 'unknown');
          return { status: 'unknown', message: 'Missing API key or URL' };
        }

        try {
          const response = await fetch(`${server.httpUrl}/api/v2/health`, {
            headers: { 'KEY': apiKey },
            signal: AbortSignal.timeout(5000),
          });
          
          const status = response.ok ? 'online' : 'offline';
          await db.updateServerStatus(input.id, status);
          return { status, message: response.ok ? 'Server is healthy' : 'Server unreachable' };
        } catch {
          await db.updateServerStatus(input.id, 'offline');
          return { status: 'offline', message: 'Connection failed' };
        }
      }),
  }),

  // Credential management
  credentials: router({
    list: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input, ctx }) => {
        // Only admins can see full credentials
        const creds = await db.getCredentialsByServerId(input.serverId);
        if (ctx.user.role !== 'admin') {
          return creds.map(c => ({
            ...c,
            password: c.password ? '••••••••' : null,
            apiKey: c.apiKey ? '••••••••' : null,
          }));
        }
        return creds;
      }),

    create: adminProcedure
      .input(z.object({
        serverId: z.number(),
        credentialType: z.enum(['admin_login', 'red_api_key', 'blue_api_key', 'ssh_key']),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.createCredential(input);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: input.serverId,
          action: 'credential_created',
          details: `Added ${input.credentialType} credential`,
        });
        return { success: true };
      }),

    update: adminProcedure
      .input(z.object({
        id: z.number(),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateCredential(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'credential_updated',
          details: `Updated credential ID: ${id}`,
        });
        return { success: true };
      }),
  }),

  // Direct Caldera API proxy (for DigitalOcean server)
  calderaProxy: router({
    // Direct stats from DigitalOcean Caldera server
    getStats: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      
      const [adversaries, abilities, operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/adversaries'),
        fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities'),
        fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/agents'),
      ]);

      return {
        totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
        totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
        activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
        totalAgents: Array.isArray(agents) ? agents.length : 0,
      };
    }),

    // Get all adversaries from DigitalOcean Caldera
    getAdversaries: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const adversaries = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/adversaries');
      return Array.isArray(adversaries) ? adversaries : [];
    }),

    // Get single adversary by ID
    getAdversary: publicProcedure
      .input(z.object({ adversaryId: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
        return fetchCalderaAPI(CALDERA_URL, API_KEY, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    // Get all abilities from DigitalOcean Caldera
    getAbilities: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const abilities = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities');
      return Array.isArray(abilities) ? abilities : [];
    }),

    // Get abilities by tactic
    getAbilitiesByTactic: publicProcedure
      .input(z.object({ tactic: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
        const abilities = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities');
        if (!Array.isArray(abilities)) return [];
        return abilities.filter((a: any) => a.tactic === input.tactic);
      }),

    // Get all tactics (derived from abilities)
    getTactics: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const abilities = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities');
      if (!Array.isArray(abilities)) return [];
      
      const tacticCounts: Record<string, number> = {};
      abilities.forEach((a: any) => {
        const tactic = a.tactic || 'unknown';
        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
      });
      
      return Object.entries(tacticCounts).map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name));
    }),

    // Get all operations from DigitalOcean Caldera
    getOperations: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const operations = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/operations');
      return Array.isArray(operations) ? operations : [];
    }),

    // Get all agents from DigitalOcean Caldera
    getAgents: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const agents = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/agents');
      return Array.isArray(agents) ? agents : [];
    }),

    // Get single agent by paw (agent ID)
    getAgent: publicProcedure
      .input(z.object({ paw: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
        return fetchCalderaAPI(CALDERA_URL, API_KEY, `/api/v2/agents/${input.paw}`);
      }),

    // Kill an agent
    killAgent: protectedProcedure
      .input(z.object({ paw: z.string() }))
      .mutation(async ({ input }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
        try {
          const response = await fetch(`${CALDERA_URL}/api/v2/agents/${input.paw}`, {
            method: 'DELETE',
            headers: { 'KEY': API_KEY },
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Update agent trust level
    updateAgentTrust: protectedProcedure
      .input(z.object({ paw: z.string(), trusted: z.boolean() }))
      .mutation(async ({ input }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
        try {
          const response = await fetch(`${CALDERA_URL}/api/v2/agents/${input.paw}`, {
            method: 'PATCH',
            headers: { 
              'KEY': API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ trusted: input.trusted }),
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Get agent deployable commands
    getDeployCommands: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      const deploy = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/deploy_commands');
      return deploy || {};
    }),

    // Check Caldera server health
    checkHealth: publicProcedure.query(async () => {
      const CALDERA_URL = 'https://caldera.aceofcloud.io';
      const API_KEY = 'cb92aba983b485cbbdf92015a7384e2e8fe7d17854adb8002bb1e36e69c5bb9e';
      try {
        const response = await fetch(`${CALDERA_URL}/api/v2/health`, {
          headers: { 'KEY': API_KEY },
          signal: AbortSignal.timeout(5000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }),
  }),

  // GoPhish API proxy
  gophishProxy: router({
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
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/campaigns/', 'POST', input);
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

    // Get GoPhish server status
    getStatus: publicProcedure.query(async () => {
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

    // Aggregated GoPhish stats for dashboard
    getStats: publicProcedure.query(async () => {
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
    }),
  }),

  // Caldera API integration (database-backed)
  caldera: router({
    getStats: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) {
          return db.getCalderaStatsByServerId(input.serverId);
        }

        const [adversaries, abilities, operations, agents] = await Promise.all([
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/adversaries'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/abilities'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/operations'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/agents'),
        ]);

        const stats = {
          serverId: input.serverId,
          totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
          totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
          activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
          totalAgents: Array.isArray(agents) ? agents.length : 0,
        };

        await db.upsertCalderaStats(stats);
        return stats;
      }),

    getAdversaries: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const adversaries = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/adversaries');
        return Array.isArray(adversaries) ? adversaries : [];
      }),

    getAdversary: protectedProcedure
      .input(z.object({ serverId: z.number(), adversaryId: z.string() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return null;
        
        return fetchCalderaAPI(server.httpUrl, apiKey, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    getAbilities: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const abilities = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/abilities');
        return Array.isArray(abilities) ? abilities : [];
      }),

    getOperations: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const operations = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/operations');
        return Array.isArray(operations) ? operations : [];
      }),
  }),

  // Team management
  team: router({
    list: adminProcedure.query(async () => {
      return db.getAllUsers();
    }),

    updateRole: adminProcedure
      .input(z.object({
        userId: z.number(),
        role: z.enum(['user', 'admin', 'viewer']),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.updateUserRole(input.userId, input.role);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'role_updated',
          details: `Updated user ${input.userId} role to ${input.role}`,
        });
        return { success: true };
      }),
  }),

  // Campaign management
  campaign: router({
    list: protectedProcedure.query(async () => {
      return db.getCampaigns();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const campaign = await db.getCampaignById(input.id);
        if (!campaign) throw new TRPCError({ code: 'NOT_FOUND' });
        const agents = await db.getCampaignAgents(input.id);
        const abilities = await db.getCampaignAbilities(input.id);
        return { ...campaign, agents, abilities };
      }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        targetEnvironment: z.string().optional(),
        adversaryId: z.string().optional(),
        adversaryName: z.string().optional(),
        serverId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createCampaign({
          ...input,
          createdBy: ctx.user.id,
          status: 'draft',
        });
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_created',
          details: `Created campaign: ${input.name}`,
        });
        return { id };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().optional(),
        description: z.string().optional(),
        targetEnvironment: z.string().optional(),
        adversaryId: z.string().optional(),
        adversaryName: z.string().optional(),
        status: z.enum(['draft', 'ready', 'active', 'paused', 'completed']).optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateCampaign(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_updated',
          details: `Updated campaign ID: ${id}`,
        });
        return { success: true };
      }),

    delete: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.deleteCampaign(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_deleted',
          details: `Deleted campaign ID: ${input.id}`,
        });
        return { success: true };
      }),

    // Agent management
    addAgent: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        agentName: z.string().min(1),
        agentPaw: z.string().optional(),
        platform: z.string().optional(),
        hostname: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const id = await db.addCampaignAgent(input);
        return { id };
      }),

    removeAgent: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteCampaignAgent(input.id);
        return { success: true };
      }),

    updateAgentStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['pending', 'deployed', 'active', 'inactive']),
      }))
      .mutation(async ({ input }) => {
        await db.updateCampaignAgentStatus(input.id, input.status);
        return { success: true };
      }),

    // Ability management
    addAbility: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilityId: z.string().min(1),
        abilityName: z.string().min(1),
        technique: z.string().optional(),
        tactic: z.string().optional(),
        description: z.string().optional(),
        executionOrder: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const id = await db.addCampaignAbility(input);
        return { id };
      }),

    addAbilities: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilities: z.array(z.object({
          abilityId: z.string().min(1),
          abilityName: z.string().min(1),
          technique: z.string().optional(),
          tactic: z.string().optional(),
          description: z.string().optional(),
          executionOrder: z.number().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const abilities = input.abilities.map((a, i) => ({
          ...a,
          campaignId: input.campaignId,
          executionOrder: a.executionOrder ?? i,
        }));
        await db.addCampaignAbilities(abilities);
        return { success: true };
      }),

    removeAbility: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteCampaignAbility(input.id);
        return { success: true };
      }),

    updateAbilityStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['pending', 'running', 'completed', 'failed', 'skipped']),
      }))
      .mutation(async ({ input }) => {
        await db.updateCampaignAbilityStatus(input.id, input.status);
        return { success: true };
      }),

    reorderAbilities: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilityIds: z.array(z.number()),
      }))
      .mutation(async ({ input }) => {
        await db.reorderCampaignAbilities(input.campaignId, input.abilityIds);
        return { success: true };
      }),
  }),

  // Activity logs
  activity: router({
    list: protectedProcedure
      .input(z.object({ limit: z.number().optional() }))
      .query(async ({ input }) => {
        return db.getActivityLogs(input.limit || 50);
      }),

    byServer: protectedProcedure
      .input(z.object({ serverId: z.number(), limit: z.number().optional() }))
      .query(async ({ input }) => {
        return db.getActivityLogsByServer(input.serverId, input.limit || 50);
      }),
  }),

  // Caldera credential authentication
  calderaAuth: router({
    // Login with Caldera credentials
    login: publicProcedure
      .input(z.object({
        username: z.string().min(1),
        password: z.string().min(1),
      }))
      .mutation(async ({ input, ctx }) => {
        const CALDERA_URL = 'https://caldera.aceofcloud.io';
        
        // Try to authenticate against Caldera API
        try {
          // Caldera uses basic auth or API key - we'll validate credentials
          // by attempting to access a protected endpoint
          const response = await fetch(`${CALDERA_URL}/api/v2/health`, {
            headers: {
              'KEY': input.password, // Caldera uses API key in KEY header
            },
            signal: AbortSignal.timeout(5000),
          });

          // Also check if it's the admin credentials
          const isValidAdmin = 
            (input.username === 'red' && input.password === 'GgL3%8mr@N5%CVhu*JoI') ||
            (input.username === 'blue' && input.password === 'GgL3%8mr@N5%CVhu*JoI') ||
            (input.username === 'admin' && input.password === 'GgL3%8mr@N5%CVhu*JoI');

          if (response.ok || isValidAdmin) {
            // Create JWT token for session
            const token = jwt.sign(
              { 
                username: input.username,
                role: input.username === 'admin' || input.username === 'red' ? 'admin' : 'user',
                loginTime: Date.now(),
              },
              CALDERA_JWT_SECRET,
              { expiresIn: '24h' }
            );

            // Set session cookie with cross-subdomain domain
            ctx.res.cookie(CALDERA_SESSION_COOKIE, token, {
              domain: '.aceofcloud.io',
              path: '/',
              httpOnly: true,
              secure: true,
              sameSite: 'lax',
              maxAge: 24 * 60 * 60 * 1000, // 24 hours
            });

            return { 
              success: true, 
              message: 'Login successful',
              user: { username: input.username, role: input.username === 'admin' || input.username === 'red' ? 'admin' : 'user' }
            };
          } else {
            return { success: false, message: 'Invalid credentials' };
          }
        } catch (error) {
          console.error('Caldera auth error:', error);
          
          // Fallback: check hardcoded credentials if Caldera is unreachable
          const isValidAdmin = 
            (input.username === 'red' && input.password === 'GgL3%8mr@N5%CVhu*JoI') ||
            (input.username === 'blue' && input.password === 'GgL3%8mr@N5%CVhu*JoI') ||
            (input.username === 'admin' && input.password === 'GgL3%8mr@N5%CVhu*JoI');

          if (isValidAdmin) {
            const token = jwt.sign(
              { 
                username: input.username,
                role: input.username === 'admin' || input.username === 'red' ? 'admin' : 'user',
                loginTime: Date.now(),
              },
              CALDERA_JWT_SECRET,
              { expiresIn: '24h' }
            );

            ctx.res.cookie(CALDERA_SESSION_COOKIE, token, {
              domain: '.aceofcloud.io',
              path: '/',
              httpOnly: true,
              secure: true,
              sameSite: 'lax',
              maxAge: 24 * 60 * 60 * 1000,
            });

            return { 
              success: true, 
              message: 'Login successful (offline mode)',
              user: { username: input.username, role: input.username === 'admin' || input.username === 'red' ? 'admin' : 'user' }
            };
          }
          
          return { success: false, message: 'Authentication failed' };
        }
      }),

    // Check current session
    session: publicProcedure.query(async ({ ctx }) => {
      const token = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      
      if (!token) {
        return { authenticated: false, user: null };
      }

      try {
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
          username: string;
          role: string;
          loginTime: number;
        };
        
        return { 
          authenticated: true, 
          user: { 
            username: decoded.username, 
            role: decoded.role,
            loginTime: decoded.loginTime,
          } 
        };
      } catch {
        return { authenticated: false, user: null };
      }
    }),

    // Logout
    logout: publicProcedure.mutation(async ({ ctx }) => {
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, {
        domain: '.aceofcloud.io',
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: -1,
      });
      return { success: true };
    }),
  }),

  // Engagement management
  engagements: router({
    list: protectedProcedure.query(async () => {
      return db.getEngagements();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementById(input.id);
      }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        customerName: z.string().min(1),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).default('red_team'),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).default('planning'),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createEngagement({
          ...input,
          createdBy: ctx.user.id,
        });
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_created',
          details: `Created engagement: ${input.name} for ${input.customerName}`,
        });
        return { id };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().min(1).optional(),
        customerName: z.string().min(1).optional(),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).optional(),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateEngagement(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_updated',
          details: `Updated engagement ID: ${id}`,
        });
        return { success: true };
      }),

    delete: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.deleteEngagement(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_deleted',
          details: `Deleted engagement ID: ${input.id}`,
        });
        return { success: true };
      }),
  }),
});

export type AppRouter = typeof appRouter;
