import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { ENV } from "./_core/env";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import * as db from "./db";
import jwt from "jsonwebtoken";

// Caldera session cookie name
const CALDERA_SESSION_COOKIE = 'caldera_session';

// Helper to get cookie options for Caldera session
function getCalderaCookieOptions(req: any) {
  const host = req.hostname || req.headers?.host || '';
  // For aceofcloud.io subdomains, use cross-subdomain cookie
  // For other environments (manus.space, localhost), omit domain to use current host
  const isAceOfCloud = host.includes('aceofcloud.io');
  return {
    path: '/',
    httpOnly: true,
    secure: !host.includes('localhost'),
    sameSite: 'lax' as const,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    ...(isAceOfCloud ? { domain: '.aceofcloud.io' } : {}),
  };
}

// JWT secret for Caldera sessions (use env var in production)
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// Admin-only procedure
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== 'admin') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Admin access required' });
  }
  return next({ ctx });
});

// GoPhish & Caldera API config from environment
const GOPHISH_URL = ENV.gophishBaseUrl;
const GOPHISH_API_KEY = ENV.gophishApiKey;
const CALDERA_BASE_URL = ENV.calderaBaseUrl;
const CALDERA_API_KEY = ENV.calderaApiKey;

async function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  try {
    // GoPhish uses self-signed TLS cert
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
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
      const [adversaries, abilities, operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents'),
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
      const adversaries = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries');
      return Array.isArray(adversaries) ? adversaries : [];
    }),

    // Get single adversary by ID
    getAdversary: publicProcedure
      .input(z.object({ adversaryId: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    // Get all abilities from DigitalOcean Caldera
    getAbilities: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
      return Array.isArray(abilities) ? abilities : [];
    }),

    // Get abilities by tactic
    getAbilitiesByTactic: publicProcedure
      .input(z.object({ tactic: z.string() }))
      .query(async ({ input }) => {
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        if (!Array.isArray(abilities)) return [];
        return abilities.filter((a: any) => a.tactic === input.tactic);
      }),

    // Get all tactics (derived from abilities)
    getTactics: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
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
      const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
      return Array.isArray(operations) ? operations : [];
    }),

    // Get all agents from DigitalOcean Caldera
    getAgents: publicProcedure.query(async () => {
      const agents = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents');
      return Array.isArray(agents) ? agents : [];
    }),

    // Get single agent by paw (agent ID)
    getAgent: publicProcedure
      .input(z.object({ paw: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/agents/${input.paw}`);
      }),

    // Kill an agent
    killAgent: protectedProcedure
      .input(z.object({ paw: z.string() }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'DELETE',
            headers: { 'KEY': CALDERA_API_KEY },
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
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'PATCH',
            headers: { 
              'KEY': CALDERA_API_KEY,
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
      const deploy = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/deploy_commands');
      return deploy || {};
    }),

    // Check Caldera server health
    checkHealth: publicProcedure.query(async () => {
      try {
        const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
          headers: { 'KEY': CALDERA_API_KEY },
          signal: AbortSignal.timeout(5000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }),

    // Create a new ability on the Caldera server
    createAbility: protectedProcedure
      .input(z.object({
        ability_id: z.string(),
        name: z.string(),
        description: z.string(),
        tactic: z.string(),
        technique_id: z.string(),
        technique_name: z.string(),
        executors: z.array(z.object({
          platform: z.string(),
          name: z.string(),
          command: z.string(),
          cleanup: z.string().optional(),
          timeout: z.number().optional(),
        })),
        singleton: z.boolean().optional(),
        repeatable: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ability_id: input.ability_id,
              name: input.name,
              description: input.description,
              tactic: input.tactic,
              technique_id: input.technique_id,
              technique_name: input.technique_name,
              executors: input.executors,
              singleton: input.singleton ?? false,
              repeatable: input.repeatable ?? true,
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, ability: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Create a new adversary profile on the Caldera server
    createAdversary: protectedProcedure
      .input(z.object({
        adversary_id: z.string(),
        name: z.string(),
        description: z.string(),
        atomic_ordering: z.array(z.string()),
        objective: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              adversary_id: input.adversary_id,
              name: input.name,
              description: input.description,
              atomic_ordering: input.atomic_ordering,
              objective: input.objective || '',
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, adversary: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Deploy a full ransomware ability profile to Caldera (abilities + adversary)
    deployRansomwareProfile: protectedProcedure
      .input(z.object({
        groupId: z.string(),
        groupName: z.string(),
        adversaryId: z.string(),
        description: z.string(),
        abilities: z.array(z.object({
          ability_id: z.string(),
          name: z.string(),
          description: z.string(),
          tactic: z.string(),
          technique_id: z.string(),
          technique_name: z.string(),
          platforms: z.record(z.string(), z.record(z.string(), z.object({
            command: z.string(),
            cleanup: z.string().optional(),
            timeout: z.number().optional(),
          }))),
        })),
      }))
      .mutation(async ({ input }) => {
        const results: Array<{ ability_id: string; name: string; success: boolean; error?: string }> = [];

        // Step 1: Create each ability
        for (const ability of input.abilities) {
          const executors: Array<{ platform: string; name: string; command: string; cleanup?: string; timeout?: number }> = [];
          for (const [platform, execs] of Object.entries(ability.platforms)) {
            for (const [executor, config] of Object.entries(execs as Record<string, { command: string; cleanup?: string; timeout?: number }>)) {
              executors.push({
                platform,
                name: executor,
                command: config.command,
                cleanup: config.cleanup,
                timeout: config.timeout,
              });
            }
          }

          try {
            const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
              method: 'POST',
              headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                ability_id: ability.ability_id,
                name: `[${input.groupName}] ${ability.name}`,
                description: ability.description,
                tactic: ability.tactic,
                technique_id: ability.technique_id,
                technique_name: ability.technique_name,
                executors,
                singleton: false,
                repeatable: true,
              }),
              signal: AbortSignal.timeout(15000),
            });
            results.push({
              ability_id: ability.ability_id,
              name: ability.name,
              success: response.ok,
              error: response.ok ? undefined : `HTTP ${response.status}`,
            });
          } catch (err: any) {
            results.push({ ability_id: ability.ability_id, name: ability.name, success: false, error: err.message });
          }
        }

        // Step 2: Create the adversary profile
        let adversaryResult: { success: boolean; error?: string } = { success: false };
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              adversary_id: input.adversaryId,
              name: `${input.groupName} Simulation`,
              description: input.description,
              atomic_ordering: input.abilities.map(a => a.ability_id),
            }),
            signal: AbortSignal.timeout(15000),
          });
          adversaryResult = { success: response.ok, error: response.ok ? undefined : `HTTP ${response.status}` };
        } catch (err: any) {
          adversaryResult = { success: false, error: err.message };
        }

        return {
          abilitiesDeployed: results.filter(r => r.success).length,
          abilitiesFailed: results.filter(r => !r.success).length,
          abilityResults: results,
          adversaryCreated: adversaryResult.success,
          adversaryError: adversaryResult.error,
        };
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
        // Try to authenticate against Caldera API
        try {
          // Caldera uses basic auth or API key - we'll validate credentials
          // by attempting to access a protected endpoint
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
            headers: {
              'KEY': input.password, // Caldera uses API key in KEY header
            },
            signal: AbortSignal.timeout(5000),
          });

          // Also check if it's the admin credentials from env
          const validPassword = ENV.calderaPassword;
          const isValidAdmin = validPassword && (
            (input.username === 'red' || input.username === 'blue' || input.username === 'admin') &&
            input.password === validPassword
          );

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

            // Set session cookie
            ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCalderaCookieOptions(ctx.req));

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
          
          // Fallback: check credentials from env if Caldera is unreachable
          const validPassword = ENV.calderaPassword;
          const isValidAdmin = validPassword && (
            (input.username === 'red' || input.username === 'blue' || input.username === 'admin') &&
            input.password === validPassword
          );

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

            ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCalderaCookieOptions(ctx.req));

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
      const cookieOpts = getCalderaCookieOptions(ctx.req);
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, { ...cookieOpts, maxAge: -1 });
      return { success: true };
    }),
  }),

  // Campaign-Engagement linking
  campaignEngagements: router({
    link: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        gophishCampaignId: z.number(),
        gophishCampaignName: z.string().optional(),
        calderaOperationId: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.linkCampaignToEngagement(input);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_linked',
          details: `Linked GoPhish campaign ${input.gophishCampaignId} to engagement ${input.engagementId}`,
        });
        return { id };
      }),

    unlink: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.unlinkCampaignFromEngagement(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_unlinked',
          details: `Unlinked campaign-engagement link ID: ${input.id}`,
        });
        return { success: true };
      }),

    byEngagement: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getCampaignsByEngagement(input.engagementId);
      }),

    byCampaign: protectedProcedure
      .input(z.object({ gophishCampaignId: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementByCampaign(input.gophishCampaignId);
      }),

    listAll: protectedProcedure.query(async () => {
      return db.getAllCampaignEngagementLinks();
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

  // ==================== OSINT RECON ====================
  osint: router({
    // Start a full domain recon scan for an engagement
    startRecon: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        domain: z.string().min(3),
      }))
      .mutation(async ({ input, ctx }) => {
        const { runFullRecon } = await import('./osint');
        const { invokeLLM } = await import('./_core/llm');

        // Create recon record in pending state
        const reconId = await db.createDomainRecon({
          engagementId: input.engagementId,
          domain: input.domain,
          scanStatus: 'running',
          scanStartedAt: new Date(),
        });

        // Run the recon (async but we await it)
        try {
          const result = await runFullRecon(input.domain);

          // Generate LLM spoofability analysis
          let spoofAnalysis = '';
          try {
            const llmResponse = await invokeLLM({
              messages: [
                {
                  role: 'system',
                  content: 'You are a red team email security analyst. Analyze the DNS/email security configuration and provide a concise tactical assessment for a phishing engagement. Be specific about what attacks are possible.'
                },
                {
                  role: 'user',
                  content: `Domain: ${input.domain}\nSPF: ${result.dns.spfRecord || 'NONE'}\nDMARC: ${result.dns.dmarcRecord || 'NONE'}\nDKIM Found: ${result.dns.dkimFound}\nMX Records: ${JSON.stringify(result.dns.mxRecords)}\nSpoof Score: ${result.spoofability.score}/100\n\nProvide a 3-4 sentence tactical assessment: Can we spoof this domain directly? What email security gaps exist? What approach do you recommend for a phishing campaign?`
                }
              ]
            });
            spoofAnalysis = (llmResponse?.choices?.[0]?.message?.content as string) || '';
          } catch { /* LLM optional */ }

          // Store findings in DB
          await db.updateDomainRecon(reconId, {
            mxRecords: result.dns.mxRecords as any,
            spfRecord: result.dns.spfRecord,
            dmarcRecord: result.dns.dmarcRecord,
            nsRecords: result.dns.nsRecords as any,
            aRecords: result.dns.aRecords as any,
            subdomains: result.subdomains as any,
            spoofable: result.spoofability.spoofable,
            spoofScore: result.spoofability.score,
            spoofAnalysis,
            scanStatus: 'completed',
            scanCompletedAt: new Date(),
          });

          // Create OSINT findings for notable items
          const findings: any[] = [];

          // DNS misconfigurations
          for (const factor of result.spoofability.factors) {
            if (factor.impact === 'critical' || factor.impact === 'high') {
              findings.push({
                engagementId: input.engagementId,
                reconId,
                category: 'dns_misconfiguration',
                severity: factor.impact === 'critical' ? 'critical' : 'high',
                title: factor.factor,
                description: factor.detail,
                source: 'dns_analysis',
              });
            }
          }

          // Subdomains as findings
          if (result.subdomains.length > 0) {
            findings.push({
              engagementId: input.engagementId,
              reconId,
              category: 'subdomain',
              severity: 'info',
              title: `${result.subdomains.length} subdomains discovered via Certificate Transparency`,
              description: `Subdomains found: ${result.subdomains.slice(0, 20).join(', ')}${result.subdomains.length > 20 ? '...' : ''}`,
              rawData: result.subdomains as any,
              source: 'crt.sh',
            });
          }

          if (findings.length > 0) {
            await db.bulkCreateOsintFindings(findings);
          }

          // Store typosquat candidates
          if (result.typosquats.length > 0) {
            const typosquatRecords = result.typosquats.slice(0, 200).map(t => ({
              engagementId: input.engagementId,
              reconId,
              originalDomain: input.domain,
              permutedDomain: t.domain,
              permutationType: t.type,
            }));
            await db.bulkCreateTyposquatDomains(typosquatRecords);
          }

          await db.logActivity({
            userId: ctx.user.id,
            action: 'osint_recon_completed',
            details: `Domain recon completed for ${input.domain} (engagement ${input.engagementId}). Score: ${result.spoofability.score}/100, ${result.subdomains.length} subdomains, ${result.typosquats.length} typosquats`,
          });

          return {
            reconId,
            spoofScore: result.spoofability.score,
            spoofable: result.spoofability.spoofable,
            subdomainCount: result.subdomains.length,
            typosquatCount: result.typosquats.length,
          };
        } catch (err: any) {
          await db.updateDomainRecon(reconId, {
            scanStatus: 'failed',
            scanCompletedAt: new Date(),
          });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
      }),

    // Get recon results for an engagement
    getRecon: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconByEngagement(input.engagementId);
      }),

    // Get single recon by ID
    getReconById: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconById(input.id);
      }),

    // Get typosquat domains for an engagement
    getTyposquats: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getTyposquatsByEngagement(input.engagementId);
      }),

    // Check DNS resolution for a specific typosquat domain
    checkTyposquat: protectedProcedure
      .input(z.object({ id: z.number(), domain: z.string() }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        const result = await checkDomainRegistration(input.domain);
        await db.updateTyposquatDomain(input.id, {
          isRegistered: result.resolved,
          dnsResolved: result.resolved,
          resolvedIp: result.ip,
          mxRecords: result.mx as any,
        });
        return result;
      }),

    // Batch check typosquat domains (check top N)
    batchCheckTyposquats: protectedProcedure
      .input(z.object({ reconId: z.number(), limit: z.number().min(1).max(50).default(20) }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        const domains = await db.getTyposquatsByRecon(input.reconId);
        const toCheck = domains.slice(0, input.limit);
        const results: Array<{ id: number; domain: string; resolved: boolean; ip: string | null }> = [];

        for (const d of toCheck) {
          try {
            const result = await checkDomainRegistration(d.permutedDomain);
            await db.updateTyposquatDomain(d.id, {
              isRegistered: result.resolved,
              dnsResolved: result.resolved,
              resolvedIp: result.ip,
              mxRecords: result.mx as any,
            });
            results.push({ id: d.id, domain: d.permutedDomain, resolved: result.resolved, ip: result.ip });
          } catch {
            results.push({ id: d.id, domain: d.permutedDomain, resolved: false, ip: null });
          }
        }
        return results;
      }),

    // Update typosquat domain status (purchased, configured, etc.)
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_status_updated',
          details: `Updated typosquat domain ID ${id} to status: ${input.status}`,
        });
        return { success: true };
      }),

    // Get OSINT findings for an engagement
    getFindings: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getOsintFindingsByEngagement(input.engagementId);
      }),

    // Auto-design campaign from OSINT findings using LLM
    autoCampaignDesign: protectedProcedure
      .input(z.object({ engagementId: z.number(), reconId: z.number() }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('./_core/llm');
        const recon = await db.getDomainReconById(input.reconId);
        const findings = await db.getOsintFindingsByRecon(input.reconId);

        if (!recon) throw new TRPCError({ code: 'NOT_FOUND', message: 'Recon not found' });

        const prompt = `You are a red team campaign designer for an MSP cybersecurity assessment. Based on the following OSINT reconnaissance data, design 3 phishing campaign strategies.

Target Domain: ${recon.domain}
Spoof Score: ${recon.spoofScore}/100 (${recon.spoofable ? 'SPOOFABLE' : 'NOT EASILY SPOOFABLE'})
SPF: ${recon.spfRecord || 'NONE'}
DMARC: ${recon.dmarcRecord || 'NONE'}
Subdomains Found: ${(recon.subdomains as any[])?.length || 0}
Key Findings:
${findings.map(f => `- [${f.severity?.toUpperCase()}] ${f.title}: ${f.description}`).join('\n')}

For each campaign, provide:
1. Campaign Name
2. Attack Vector (direct spoof, lookalike domain, or compromised subdomain)
3. Phishing Pretext (what the email pretends to be)
4. Recommended Template Type (password reset, IT helpdesk, invoice, etc.)
5. Target Audience (all employees, IT staff, executives, etc.)
6. Landing Page Strategy (credential harvest, malware download, etc.)
7. Recommended Sending Domain (spoof original or use typosquat)
8. Risk Level (low/medium/high detection risk)

Respond in JSON format as an array of 3 campaign objects.`;

        try {
          const response = await invokeLLM({
            messages: [
              { role: 'system', content: 'You are an expert red team campaign designer. Always respond with valid JSON.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'campaign_designs',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    campaigns: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          attackVector: { type: 'string' },
                          pretext: { type: 'string' },
                          templateType: { type: 'string' },
                          targetAudience: { type: 'string' },
                          landingPageStrategy: { type: 'string' },
                          sendingDomain: { type: 'string' },
                          riskLevel: { type: 'string' },
                        },
                        required: ['name', 'attackVector', 'pretext', 'templateType', 'targetAudience', 'landingPageStrategy', 'sendingDomain', 'riskLevel'],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ['campaigns'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = (response?.choices?.[0]?.message?.content as string) || '{"campaigns":[]}';
          return JSON.parse(content);
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to generate campaign designs: ' + err.message });
        }
      }),
  }),

  // ==================== WHOIS & DOMAIN AVAILABILITY ====================
  whois: router({
    lookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { whoisLookup } = await import('./osint');
        return whoisLookup(input.domain);
      }),

    checkAvailability: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        return checkDomainRegistration(input.domain);
      }),

    batchCheck: protectedProcedure
      .input(z.object({ domains: z.array(z.string()).max(50) }))
      .mutation(async ({ input }) => {
        const { batchWhoisCheck } = await import('./osint');
        return batchWhoisCheck(input.domains);
      }),

    // Update a typosquat domain status after purchase/configuration
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates as any);
        return { success: true };
      }),
  }),

  // ==================== OSINT MONITORING ====================
  monitor: router({
    create: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        engagementId: z.number().optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        intervalHours: z.number().min(1).max(720).default(24),
        notifyOnChange: z.boolean().default(true),
        notifyEmail: z.string().email().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Run initial baseline scan
        const { runFullRecon } = await import('./osint');
        const recon = await runFullRecon(input.domain);
        const baseline = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        const id = await db.createOsintMonitor({
          domain: input.domain,
          engagementId: input.engagementId ?? null,
          clientType: input.clientType,
          intervalHours: input.intervalHours,
          notifyOnChange: input.notifyOnChange,
          notifyEmail: input.notifyEmail ?? null,
          baselineSnapshot: baseline,
          lastScanAt: new Date(),
          totalScans: 1,
          createdBy: ctx.user.id,
        });
        return { id, baseline };
      }),

    list: protectedProcedure.query(async () => {
      return db.getOsintMonitors();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });
        const changes = await db.getMonitorChanges(input.id);
        return { monitor, changes };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        enabled: z.boolean().optional(),
        intervalHours: z.number().min(1).max(720).optional(),
        notifyOnChange: z.boolean().optional(),
        notifyEmail: z.string().email().optional().nullable(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateOsintMonitor(id, updates as any);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteOsintMonitor(input.id);
        return { success: true };
      }),

    // Run a scan now (compare against baseline)
    scanNow: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });

        const { runFullRecon, detectDomainChanges } = await import('./osint');
        const recon = await runFullRecon(monitor.domain);

        const currentSnapshot = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        // Detect changes against baseline using the previous recon data
        const baseline = (monitor.baselineSnapshot as any) || {};
        const changeReport = await detectDomainChanges(monitor.domain, {
          spfRecord: baseline.spfRecord,
          dmarcRecord: baseline.dmarcRecord,
          mxRecords: baseline.mxRecords,
          nsRecords: baseline.nsRecords,
          aRecords: baseline.aRecords,
          subdomains: baseline.subdomains,
        });
        const changes = changeReport.changes;

        // Store changes in DB
        if (changes.length > 0) {
          await db.bulkCreateMonitorChanges(
            changes.map((c) => ({
              monitorId: monitor.id,
              domain: monitor.domain,
              changeType: c.type,
              severity: c.severity,
              previousValue: c.previousValue,
              currentValue: c.currentValue,
              description: c.description,
            }))
          );

          // Notify owner if enabled
          if (monitor.notifyOnChange) {
            try {
              const { notifyOwner } = await import('./_core/notification');
              await notifyOwner({
                title: `OSINT Alert: ${changes.length} change(s) detected on ${monitor.domain}`,
                content: changes.map((c) => `[${c.severity.toUpperCase()}] ${c.description}`).join('\n'),
              });
            } catch (e) { /* notification failure is non-fatal */ }
          }
        }

        // Update monitor
        await db.updateOsintMonitor(monitor.id, {
          lastScanAt: new Date(),
          totalScans: (monitor.totalScans || 0) + 1,
          totalChangesDetected: (monitor.totalChangesDetected || 0) + changes.length,
          baselineSnapshot: currentSnapshot,
          ...(changes.length > 0 ? { lastChangeDetectedAt: new Date() } : {}),
        });

        return { changes, currentSnapshot };
      }),

    // Get unacknowledged changes across all monitors
    alerts: protectedProcedure.query(async () => {
      return db.getUnacknowledgedChanges();
    }),

    acknowledgeChange: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.acknowledgeChange(input.id, ctx.user.id);
        return { success: true };
      }),
  }),

  // ==================== ENGAGEMENT REPORTS ====================
  reports: router({
    generate: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        reportType: z.enum(['executive_summary', 'technical_detail', 'compliance', 'phishing_results', 'osint_assessment', 'full_engagement']),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        title: z.string().min(1),
        preparedFor: z.string().optional(),
        preparedBy: z.string().optional(),
        includeSections: z.array(z.string()).optional(),
        brandingColor: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Create report record
        const reportId = await db.createEngagementReport({
          engagementId: input.engagementId,
          reportType: input.reportType,
          clientType: input.clientType,
          title: input.title,
          preparedFor: input.preparedFor ?? null,
          preparedBy: input.preparedBy ?? ctx.user.name ?? 'C3 Platform',
          includeSections: input.includeSections || [],
          brandingColor: input.brandingColor ?? '#dc2626',
          status: 'generating',
          createdBy: ctx.user.id,
        });

        // Gather all engagement data
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const reconData = await db.getDomainReconByEngagement(input.engagementId);
        const typosquats = await db.getTyposquatsByEngagement(input.engagementId);
        const findings = await db.getOsintFindingsByEngagement(input.engagementId);
        const campaignLinks = await db.getCampaignsByEngagement(input.engagementId);

        // Fetch GoPhish campaign results for linked campaigns
        let campaignResults: any[] = [];
        const gophishBaseUrl = ENV.gophishBaseUrl;
        const gophishApiKey = ENV.gophishApiKey;
        if (gophishBaseUrl && gophishApiKey) {
          for (const link of campaignLinks) {
            try {
              const resp = await fetch(`${gophishBaseUrl}/api/campaigns/${link.gophishCampaignId}/results`, {
                headers: { 'Authorization': gophishApiKey },
                ...(gophishBaseUrl.startsWith('https') ? { agent: new (await import('https')).Agent({ rejectUnauthorized: false }) } : {}),
              } as any);
              if (resp.ok) {
                const data = await resp.json();
                campaignResults.push({ ...data, campaignName: link.gophishCampaignName });
              }
            } catch (e) { /* skip failed fetches */ }
          }
        }

        // Use LLM to generate report content
        const { invokeLLM } = await import('./_core/llm');

        const clientTypeLabels: Record<string, string> = {
          msp: 'Managed Service Provider (MSP)',
          enterprise: 'Enterprise Organization',
          saas: 'SaaS Provider',
          paas: 'PaaS Provider',
          iaas: 'IaaS Provider',
          mixed_hosting: 'Mixed Hosting Provider',
          other: 'Organization',
        };

        const sectionPrompts: Record<string, string> = {
          executive_summary: 'Write a concise executive summary suitable for C-level stakeholders. Focus on business risk, key findings, and recommended actions.',
          technical_detail: 'Write a detailed technical report covering all findings, attack paths, vulnerabilities, and remediation steps with specific technical guidance.',
          compliance: 'Write a compliance-focused report mapping findings to relevant frameworks (NIST CSF, ISO 27001, SOC 2, HIPAA, PCI DSS). Include gap analysis.',
          phishing_results: 'Write a phishing campaign results report with click rates, credential capture rates, user behavior analysis, and awareness training recommendations.',
          osint_assessment: 'Write an OSINT assessment report covering domain security posture, email authentication, typosquat risks, and external attack surface findings.',
          full_engagement: 'Write a comprehensive engagement report covering all aspects: executive summary, OSINT findings, phishing results, technical findings, and recommendations.',
        };

        const reportPrompt = sectionPrompts[input.reportType] || sectionPrompts.full_engagement;

        try {
          const response = await invokeLLM({
            messages: [
              {
                role: 'system',
                content: `You are a senior cybersecurity consultant generating a professional ${input.reportType.replace(/_/g, ' ')} report for a ${clientTypeLabels[input.clientType] || 'client'}. Use formal, professional language. Include specific data points from the provided engagement data. Format the report in Markdown with clear sections, tables where appropriate, and actionable recommendations. The report should be thorough but readable.`,
              },
              {
                role: 'user',
                content: `Generate the report with the following context:

Report Title: ${input.title}
Prepared For: ${input.preparedFor || engagement.customerName}
Prepared By: ${input.preparedBy || ctx.user.name || 'C3 Platform'}
Client Type: ${clientTypeLabels[input.clientType]}
Engagement: ${engagement.name} (${engagement.engagementType})
Customer: ${engagement.customerName}
Target Domain: ${engagement.targetDomain || 'N/A'}
Status: ${engagement.status}
Date Range: ${engagement.startDate ? new Date(engagement.startDate).toLocaleDateString() : 'N/A'} - ${engagement.endDate ? new Date(engagement.endDate).toLocaleDateString() : 'Ongoing'}

OSINT Recon Data (${reconData.length} scans):
${JSON.stringify(reconData.slice(0, 3).map(r => ({
  domain: r.domain,
  spoofScore: r.spoofScore,
  spoofable: r.spoofable,
  spf: r.spfRecord ? 'Present' : 'Missing',
  dmarc: r.dmarcRecord ? 'Present' : 'Missing',
  subdomains: Array.isArray(r.subdomains) ? (r.subdomains as any[]).length : 0,
})), null, 2)}

Typosquat Domains Found: ${typosquats.length}
${typosquats.slice(0, 10).map(t => `- ${t.permutedDomain} (${t.permutationType}, registered: ${t.isRegistered})`).join('\n')}

OSINT Findings (${findings.length} total):
${findings.slice(0, 15).map(f => `- [${f.severity}] ${f.title}: ${f.description?.substring(0, 100)}`).join('\n')}

Phishing Campaign Results (${campaignResults.length} campaigns):
${JSON.stringify(campaignResults.map(c => ({
  name: c.campaignName,
  totalTargets: c.results?.length || 0,
  sent: c.results?.filter((r: any) => r.status === 'Email Sent').length || 0,
  opened: c.results?.filter((r: any) => r.status === 'Email Opened').length || 0,
  clicked: c.results?.filter((r: any) => r.status === 'Clicked Link').length || 0,
  submitted: c.results?.filter((r: any) => r.status === 'Submitted Data').length || 0,
})), null, 2)}

Instructions: ${reportPrompt}`,
              },
            ],
          });

          const reportContent = (response?.choices?.[0]?.message?.content as string) || 'Report generation failed.';

          // Store as S3 file
          try {
            const { storagePut } = await import('./storage');
            const reportKey = `reports/${input.engagementId}/${reportId}-${Date.now()}.md`;
            const { url } = await storagePut(reportKey, reportContent, 'text/markdown');

            await db.updateReport(reportId, {
              status: 'completed',
              reportUrl: url,
              reportKey,
              generatedAt: new Date(),
            });

            return { id: reportId, url, content: reportContent };
          } catch (storageErr) {
            // If S3 fails, still return the content
            await db.updateReport(reportId, {
              status: 'completed',
              generatedAt: new Date(),
            });
            return { id: reportId, url: null, content: reportContent };
          }
        } catch (err: any) {
          await db.updateReport(reportId, { status: 'failed' });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Report generation failed: ' + err.message });
        }
      }),

    list: protectedProcedure
      .input(z.object({ engagementId: z.number().optional() }).optional())
      .query(async ({ input }) => {
        if (input?.engagementId) {
          return db.getEngagementReports(input.engagementId);
        }
        return db.getAllReports();
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const report = await db.getReportById(input.id);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
        return report;
      }),
  }),

  // IOC-Driven GoPhish Template Generator
  templateGenerator: router({
    // Generate phishing email template based on threat actor IOCs and TTPs
    generateFromThreatActor: protectedProcedure
      .input(z.object({
        threatActorId: z.string(),
        threatActorName: z.string(),
        targetOrg: z.string().optional(),
        targetSector: z.string().optional(),
        phishingType: z.enum(['credential_harvest', 'malware_delivery', 'callback_phishing', 'business_email_compromise', 'mfa_fatigue']),
        sophistication: z.enum(['basic', 'intermediate', 'advanced']),
        iocs: z.array(z.object({
          type: z.string(),
          value: z.string(),
          description: z.string(),
        })).optional(),
        techniques: z.array(z.object({
          id: z.string(),
          name: z.string(),
          tactic: z.string(),
        })).optional(),
      }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('./_core/llm');

        const iocContext = input.iocs?.map(ioc => `- ${ioc.type}: ${ioc.value} (${ioc.description})`).join('\n') || 'No specific IOCs provided';
        const ttpContext = input.techniques?.map(t => `- ${t.id} ${t.name} (${t.tactic})`).join('\n') || 'No specific TTPs provided';

        const prompt = `You are a red team phishing template designer. Generate a realistic phishing email template and landing page HTML based on the following threat intelligence:

Threat Actor: ${input.threatActorName}
Target Organization: ${input.targetOrg || 'Generic enterprise'}
Target Sector: ${input.targetSector || 'Technology'}
Phishing Type: ${input.phishingType}
Sophistication Level: ${input.sophistication}

Known IOCs:
${iocContext}

Known TTPs:
${ttpContext}

Generate a JSON response with these exact fields:
{
  "emailTemplate": {
    "name": "Template name including threat actor reference",
    "subject": "Realistic email subject line",
    "senderName": "Realistic sender display name",
    "senderDomain": "Suggested sender domain",
    "html": "Full HTML email body with {{.FirstName}}, {{.URL}} GoPhish variables",
    "text": "Plain text version",
    "pretext": "Brief description of the social engineering angle"
  },
  "landingPage": {
    "name": "Landing page name",
    "html": "Full HTML landing page with credential capture form",
    "redirectUrl": "URL to redirect after credential capture"
  },
  "indicators": {
    "subjectKeywords": ["list of suspicious keywords in subject"],
    "bodyRedFlags": ["list of red flags users should spot"],
    "technicalIndicators": ["list of technical indicators"]
  },
  "trainingNotes": "Brief notes for security awareness training about this phishing type"
}

Make the email realistic and based on actual ${input.threatActorName} phishing campaigns. Include proper HTML formatting, logos, and branding that matches the phishing type. The landing page should capture credentials realistically. Use GoPhish template variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.URL}}, {{.TrackingURL}}, {{.From}}.`;

        try {
          const response = await invokeLLM({
            messages: [
              { role: 'system', content: 'You are an expert red team phishing template designer. Always respond with valid JSON only, no markdown code blocks.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'phishing_template',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    emailTemplate: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        subject: { type: 'string' },
                        senderName: { type: 'string' },
                        senderDomain: { type: 'string' },
                        html: { type: 'string' },
                        text: { type: 'string' },
                        pretext: { type: 'string' },
                      },
                      required: ['name', 'subject', 'senderName', 'senderDomain', 'html', 'text', 'pretext'],
                      additionalProperties: false,
                    },
                    landingPage: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        html: { type: 'string' },
                        redirectUrl: { type: 'string' },
                      },
                      required: ['name', 'html', 'redirectUrl'],
                      additionalProperties: false,
                    },
                    indicators: {
                      type: 'object',
                      properties: {
                        subjectKeywords: { type: 'array', items: { type: 'string' } },
                        bodyRedFlags: { type: 'array', items: { type: 'string' } },
                        technicalIndicators: { type: 'array', items: { type: 'string' } },
                      },
                      required: ['subjectKeywords', 'bodyRedFlags', 'technicalIndicators'],
                      additionalProperties: false,
                    },
                    trainingNotes: { type: 'string' },
                  },
                  required: ['emailTemplate', 'landingPage', 'indicators', 'trainingNotes'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = response.choices?.[0]?.message?.content;
          if (!content) throw new Error('No response from LLM');
          const parsed = JSON.parse(content as string);
          return { success: true, ...parsed };
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Template generation failed: ${err.message}` });
        }
      }),

    // Deploy generated template directly to GoPhish
    deployToGophish: protectedProcedure
      .input(z.object({
        template: z.object({
          name: z.string(),
          subject: z.string(),
          html: z.string(),
          text: z.string().optional(),
        }),
        landingPage: z.object({
          name: z.string(),
          html: z.string(),
          capture_credentials: z.boolean().optional(),
          capture_passwords: z.boolean().optional(),
          redirect_url: z.string().optional(),
        }).optional(),
      }))
      .mutation(async ({ input }) => {
        const results: { template?: any; landingPage?: any; errors: string[] } = { errors: [] };

        // Deploy email template
        try {
          const templateResult = await fetchGophishAPI('/api/templates/', 'POST', input.template);
          if (templateResult?.id) {
            results.template = { id: templateResult.id, name: input.template.name, success: true };
          } else {
            results.errors.push('Failed to create email template');
          }
        } catch (err: any) {
          results.errors.push(`Template error: ${err.message}`);
        }

        // Deploy landing page if provided
        if (input.landingPage) {
          try {
            const pageResult = await fetchGophishAPI('/api/pages/', 'POST', {
              ...input.landingPage,
              capture_credentials: input.landingPage.capture_credentials ?? true,
              capture_passwords: input.landingPage.capture_passwords ?? true,
            });
            if (pageResult?.id) {
              results.landingPage = { id: pageResult.id, name: input.landingPage.name, success: true };
            } else {
              results.errors.push('Failed to create landing page');
            }
          } catch (err: any) {
            results.errors.push(`Landing page error: ${err.message}`);
          }
        }

        return results;
      }),
  }),

  // Domain Intel Pipeline
  domainIntel: router({
    // Start a new domain intel scan
    startScan: protectedProcedure
      .input(z.object({
        primaryDomain: z.string().min(1),
        additionalDomains: z.array(z.string()).optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']),
        sector: z.string().min(1),
        customerName: z.string().min(1),
        criticalFunctions: z.array(z.string()),
        complianceFlags: z.array(z.string()).optional(),
        notes: z.string().optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { runDomainIntelPipeline } = await import('./domainIntel');

        // Create scan record
        const scanId = await db.createDomainIntelScan({
          primaryDomain: input.primaryDomain,
          additionalDomains: input.additionalDomains || [],
          clientType: input.clientType,
          sector: input.sector,
          engagementId: input.engagementId,
          orgProfile: {
            customerName: input.customerName,
            primaryDomain: input.primaryDomain,
            sector: input.sector,
            clientType: input.clientType,
            criticalFunctions: input.criticalFunctions,
            complianceFlags: input.complianceFlags || [],
          },
          criticalFunctions: input.criticalFunctions,
          complianceFlags: input.complianceFlags || [],
          notes: input.notes,
          status: 'discovering',
          createdBy: ctx.user.id,
        });

        // Run pipeline (async but we await it)
        try {
          await db.updateDomainIntelScan(scanId, { status: 'discovering' });

          const result = await runDomainIntelPipeline({
            customerName: input.customerName,
            primaryDomain: input.primaryDomain,
            additionalDomains: input.additionalDomains,
            sector: input.sector,
            clientType: input.clientType,
            criticalFunctions: input.criticalFunctions,
            complianceFlags: input.complianceFlags || [],
            notes: input.notes,
          });

          // Store discovered assets
          const assetRecords = result.assets.map(a => ({
            scanId,
            assetId: a.asset.assetId,
            hostname: a.asset.hostname,
            url: a.asset.url || null,
            assetType: a.asset.assetType,
            dnsRecords: a.asset.dnsRecords || null,
            dnsStatus: a.asset.dnsStatus || null,
            headers: a.asset.headers || null,
            technologies: a.asset.technologies || null,
            assetClasses: a.asset.assetClasses,
            tags: a.asset.tags,
            carverScores: a.carverScores,
            shockScores: a.shockScores,
            missionImpactScore: Math.round(a.missionImpactScore * 10),
            suggestedTier: a.suggestedTier,
            hybridRiskScore: a.hybridRiskScore,
            riskBand: a.riskBand,
            cvssEstimate: Math.round(a.cvssEstimate * 10),
            contextIndicators: a.contextIndicators,
            postureFindings: a.postureFindings,
            testVectors: a.testVectors,
            recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
            recommendedGophishTemplates: null,
            recommendedAttackChain: null,
            confidence: a.confidence,
            confidenceExplanation: a.contextIndicators,
          }));

          if (assetRecords.length > 0) {
            await db.bulkCreateDiscoveredAssets(assetRecords);
          }

          // Update scan with results
          await db.updateDomainIntelScan(scanId, {
            status: 'completed',
            totalAssets: result.totalAssets,
            totalFindings: result.totalFindings,
            overallRiskScore: result.overallRiskScore,
            overallRiskBand: result.overallRiskBand,
            executiveSummary: result.executiveSummary,
            threatModelSummary: result.threatModelSummary,
            campaignRecommendations: result.campaignRecommendations,
            pipelineOutput: result,
          });

          return { scanId, result };
        } catch (err: any) {
          await db.updateDomainIntelScan(scanId, { status: 'failed' });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Pipeline failed: ${err.message}` });
        }
      }),

    // List all scans
    listScans: protectedProcedure.query(async () => {
      return db.getDomainIntelScans();
    }),

    // Get scan by ID with assets
    getScan: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.id);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const assets = await db.getDiscoveredAssetsByScan(input.id);
        return { scan, assets };
      }),

    // Get assets for a scan
    getAssets: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return db.getDiscoveredAssetsByScan(input.scanId);
      }),

    // Get scans for an engagement
    byEngagement: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainIntelScansByEngagement(input.engagementId);
      }),
  }),
});

export type AppRouter = typeof appRouter;
