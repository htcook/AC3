import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import * as db from "./db";

// Admin-only procedure
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== 'admin') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Admin access required' });
  }
  return next({ ctx });
});

// Caldera API helper
async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const response = await fetch(`${url}${endpoint}`, {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(10000),
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
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      
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
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      const adversaries = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/adversaries');
      return Array.isArray(adversaries) ? adversaries : [];
    }),

    // Get single adversary by ID
    getAdversary: publicProcedure
      .input(z.object({ adversaryId: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'http://137.184.7.224:8888';
        const API_KEY = 'ADMIN123';
        return fetchCalderaAPI(CALDERA_URL, API_KEY, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    // Get all abilities from DigitalOcean Caldera
    getAbilities: publicProcedure.query(async () => {
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      const abilities = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities');
      return Array.isArray(abilities) ? abilities : [];
    }),

    // Get abilities by tactic
    getAbilitiesByTactic: publicProcedure
      .input(z.object({ tactic: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'http://137.184.7.224:8888';
        const API_KEY = 'ADMIN123';
        const abilities = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/abilities');
        if (!Array.isArray(abilities)) return [];
        return abilities.filter((a: any) => a.tactic === input.tactic);
      }),

    // Get all tactics (derived from abilities)
    getTactics: publicProcedure.query(async () => {
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
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
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      const operations = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/operations');
      return Array.isArray(operations) ? operations : [];
    }),

    // Get all agents from DigitalOcean Caldera
    getAgents: publicProcedure.query(async () => {
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      const agents = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/agents');
      return Array.isArray(agents) ? agents : [];
    }),

    // Get single agent by paw (agent ID)
    getAgent: publicProcedure
      .input(z.object({ paw: z.string() }))
      .query(async ({ input }) => {
        const CALDERA_URL = 'http://137.184.7.224:8888';
        const API_KEY = 'ADMIN123';
        return fetchCalderaAPI(CALDERA_URL, API_KEY, `/api/v2/agents/${input.paw}`);
      }),

    // Kill an agent
    killAgent: protectedProcedure
      .input(z.object({ paw: z.string() }))
      .mutation(async ({ input }) => {
        const CALDERA_URL = 'http://137.184.7.224:8888';
        const API_KEY = 'ADMIN123';
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
        const CALDERA_URL = 'http://137.184.7.224:8888';
        const API_KEY = 'ADMIN123';
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
      const CALDERA_URL = 'http://137.184.7.224:8888';
      const API_KEY = 'ADMIN123';
      const deploy = await fetchCalderaAPI(CALDERA_URL, API_KEY, '/api/v2/deploy_commands');
      return deploy || {};
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
});

export type AppRouter = typeof appRouter;
