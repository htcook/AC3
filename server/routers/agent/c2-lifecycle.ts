/**
 * C2 Lifecycle Sub-Router
 *
 * Manages C2 server configuration, agent deployments, tasks, audit logs,
 * heartbeat/watchdog, and dashboard stats.
 * Extracted from agent-manager.ts for maintainability.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { publicProcedure, protectedProcedure, adminProcedure, router } from "../../_core/trpc";
import { getDb } from "../../db";
import {
  agentDeployments,
  agentTasks,
  agentAuditLog,
  c2Servers,
} from "../../../drizzle/schema";
import { eq, desc, and, sql, count } from "drizzle-orm";
import { getFIPSCrypto } from "../../lib/fips-crypto";
import { checkC2Health } from "../../lib/c2-health";
import { processHeartbeat, runWatchdogSweep, type HeartbeatPayload } from "../../lib/agent-heartbeat";

// ─── Input Schemas ────────────────────────────────────────────────────

const c2ServerInput = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(["caldera", "sliver", "metasploit"]),
  baseUrl: z.string().url(),
  authConfig: z.record(z.string(), z.unknown()),
});

const agentDeployInput = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  engagementId: z.number().optional(),
  targetPlatform: z.enum(["windows", "linux", "darwin"]),
  c2Protocol: z.enum(["caldera", "sliver", "metasploit", "native"]),
  ttlSeconds: z.number().min(300).max(604800).default(86400),
  watchdogSeconds: z.number().min(300).max(86400).default(14400),
  beaconIntervalSeconds: z.number().min(5).max(3600).default(60),
  targetHostname: z.string().optional(),
  targetIp: z.string().optional(),
  targetNetwork: z.string().optional(),
});

const taskInput = z.object({
  agentId: z.string(),
  techniqueId: z.string().optional(),
  techniqueName: z.string().optional(),
  command: z.string(),
  executor: z.string().default("sh"),
  timeoutSeconds: z.number().min(5).max(3600).default(300),
  payloadName: z.string().optional(),
});

// ─── Helper: Audit Log ────────────────────────────────────────────────

export async function logAgentEvent(
  agentId: string,
  eventType: string,
  actorId: number | null,
  actorType: "operator" | "system" | "agent",
  details: Record<string, unknown> = {},
  ipAddress?: string
) {
  const db = await getDb();
  if (!db) return;
  const fips = getFIPSCrypto();

  const lastEntry = await db
    .select({ recordHash: agentAuditLog.recordHash })
    .from(agentAuditLog)
    .where(eq(agentAuditLog.agentId, agentId))
    .orderBy(desc(agentAuditLog.id))
    .limit(1);

  const previousHash = lastEntry.length > 0 ? lastEntry[0].recordHash : "0".repeat(64);
  const record = JSON.stringify({ agentId, eventType, actorId, actorType, details, ts: Date.now() });
  const chain = fips.chainAuditRecord(record, previousHash);

  await db.insert(agentAuditLog).values({
    agentId,
    eventType: eventType as any,
    actorId,
    actorType,
    details,
    recordHash: chain.recordHash,
    previousHash: chain.previousHash,
    ipAddress: ipAddress ?? null,
    createdAt: Date.now(),
  });
}

// ─── Router ──────────────────────────────────────────────────────────

export const c2LifecycleRouter = router({
  // ─── C2 Servers ─────────────────────────────────────────────────────

  listC2Servers: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return [];
    return db.select().from(c2Servers).orderBy(desc(c2Servers.createdAt));
  }),

  addC2Server: adminProcedure.input(c2ServerInput).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const id = fips.uuid();
    const now = Date.now();
    const encrypted = fips.encrypt(JSON.stringify(input.authConfig), `c2-auth-${id}`);

    await db.insert(c2Servers).values({
      id,
      name: input.name,
      type: input.type,
      baseUrl: input.baseUrl,
      authConfigEncrypted: JSON.stringify(encrypted),
      status: "disconnected",
      createdAt: now,
      updatedAt: now,
    });

    return { id, name: input.name, type: input.type };
  }),

  testC2Connection: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [server] = await db.select().from(c2Servers).where(eq(c2Servers.id, input.id));
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "C2 server not found" });

      const result = await checkC2Health({
        id: server.id,
        name: server.name,
        type: server.type as "caldera" | "sliver" | "metasploit",
        baseUrl: server.baseUrl,
        authConfigEncrypted: server.authConfigEncrypted,
      });

      await db
        .update(c2Servers)
        .set({
          status: result.status,
          lastHealthCheck: Date.now(),
          healthDetails: {
            latencyMs: result.latencyMs,
            message: result.message,
            serverTime: result.serverTime,
          },
          version: result.version ?? server.version,
          capabilities: result.capabilities ?? server.capabilities,
          updatedAt: Date.now(),
        })
        .where(eq(c2Servers.id, input.id));

      return result;
    }),

  removeC2Server: adminProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.delete(c2Servers).where(eq(c2Servers.id, input.id));
      return { success: true };
    }),

  // ─── Agent Deployments ──────────────────────────────────────────────

  listAgents: protectedProcedure
    .input(
      z.object({
        status: z.enum([
          "pending_approval", "approved", "deploying", "active", "paused",
          "lost", "completed", "terminated", "failed",
        ]).optional(),
        limit: z.number().min(1).max(200).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { agents: [], total: 0 };

      const conditions: any[] = [];
      if (input.status) {
        conditions.push(eq(agentDeployments.status, input.status));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [agents, [{ total }]] = await Promise.all([
        db.select().from(agentDeployments).where(where)
          .orderBy(desc(agentDeployments.createdAt)).limit(input.limit).offset(input.offset),
        db.select({ total: count() }).from(agentDeployments).where(where),
      ]);

      return { agents, total };
    }),

  getAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const [agent] = await db.select().from(agentDeployments).where(eq(agentDeployments.id, input.id));
      if (!agent) throw new TRPCError({ code: "NOT_FOUND", message: "Agent not found" });
      return agent;
    }),

  requestDeployment: protectedProcedure
    .input(agentDeployInput)
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const fips = getFIPSCrypto();
      const id = fips.uuid();
      const now = Date.now();
      const keyPair = fips.generateKeyPair("P-256");
      const regToken = fips.randomBytes(32).toString("hex");
      const regTokenHash = fips.hash(regToken);

      await db.insert(agentDeployments).values({
        id,
        name: input.name,
        description: input.description ?? null,
        engagementId: input.engagementId ?? null,
        targetPlatform: input.targetPlatform,
        c2Protocol: input.c2Protocol,
        status: "pending_approval",
        publicKey: keyPair.publicKey,
        certificateHash: fips.hash(keyPair.publicKey),
        registrationTokenHash: regTokenHash,
        ttlSeconds: input.ttlSeconds,
        watchdogSeconds: input.watchdogSeconds,
        beaconIntervalSeconds: input.beaconIntervalSeconds,
        targetHostname: input.targetHostname ?? null,
        targetIp: input.targetIp ?? null,
        targetNetwork: input.targetNetwork ?? null,
        requestedBy: ctx.user?.id ?? 1,
        createdAt: now,
        updatedAt: now,
      });

      await logAgentEvent(id, "register", ctx.user?.id ?? 1, "operator", {
        action: "deployment_requested",
        name: input.name,
        c2Protocol: input.c2Protocol,
        targetPlatform: input.targetPlatform,
      });

      return { id, registrationToken: regToken, publicKey: keyPair.publicKey };
    }),

  approveDeployment: adminProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const [agent] = await db.select().from(agentDeployments).where(eq(agentDeployments.id, input.id));
      if (!agent) throw new TRPCError({ code: "NOT_FOUND" });
      if (agent.status !== "pending_approval") {
        throw new TRPCError({ code: "BAD_REQUEST", message: `Cannot approve agent in ${agent.status} state` });
      }
      await db.update(agentDeployments).set({
        status: "approved", approvedBy: ctx.user?.id ?? 1, approvedAt: Date.now(), updatedAt: Date.now(),
      }).where(eq(agentDeployments.id, input.id));
      await logAgentEvent(input.id, "approved", ctx.user?.id ?? 1, "operator", { action: "deployment_approved" });
      return { success: true };
    }),

  rejectDeployment: adminProcedure
    .input(z.object({ id: z.string(), reason: z.string().min(1) }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.update(agentDeployments).set({
        status: "failed", rejectionReason: input.reason, updatedAt: Date.now(),
      }).where(eq(agentDeployments.id, input.id));
      await logAgentEvent(input.id, "rejected", ctx.user?.id ?? 1, "operator", { action: "deployment_rejected", reason: input.reason });
      return { success: true };
    }),

  pauseAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.update(agentDeployments).set({ status: "paused", updatedAt: Date.now() }).where(eq(agentDeployments.id, input.id));
      await logAgentEvent(input.id, "paused", ctx.user?.id ?? 1, "operator");
      return { success: true };
    }),

  resumeAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.update(agentDeployments).set({ status: "active", updatedAt: Date.now() }).where(eq(agentDeployments.id, input.id));
      await logAgentEvent(input.id, "resumed", ctx.user?.id ?? 1, "operator");
      return { success: true };
    }),

  terminateAgent: adminProcedure
    .input(z.object({ id: z.string(), reason: z.string().optional() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.update(agentDeployments).set({
        status: "terminated", terminatedAt: Date.now(), updatedAt: Date.now(),
      }).where(eq(agentDeployments.id, input.id));
      await logAgentEvent(input.id, "terminated", ctx.user?.id ?? 1, "operator", { reason: input.reason ?? "Manual termination" });
      return { success: true };
    }),

  // ─── Agent Tasks ────────────────────────────────────────────────────

  assignTask: protectedProcedure.input(taskInput).mutation(async ({ input, ctx }) => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const id = fips.uuid();
    const now = Date.now();
    const encrypted = fips.encrypt(input.command, `task-cmd-${id}`);

    await db.insert(agentTasks).values({
      id,
      agentId: input.agentId,
      techniqueId: input.techniqueId ?? null,
      techniqueName: input.techniqueName ?? null,
      c2Source: "native",
      commandEncrypted: JSON.stringify(encrypted),
      executor: input.executor,
      timeoutSeconds: input.timeoutSeconds,
      payloadName: input.payloadName ?? null,
      status: "queued",
      queuedAt: now,
      assignedBy: ctx.user?.id ?? 1,
      roeVerified: false,
    });

    await logAgentEvent(input.agentId, "task_assigned", ctx.user?.id ?? 1, "operator", {
      taskId: id, techniqueId: input.techniqueId, techniqueName: input.techniqueName,
    });

    return { id };
  }),

  listTasks: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      status: z.enum(["queued", "sent", "executing", "completed", "failed", "timeout", "cancelled"]).optional(),
      limit: z.number().min(1).max(200).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const conditions: any[] = [eq(agentTasks.agentId, input.agentId)];
      if (input.status) conditions.push(eq(agentTasks.status, input.status));
      return db.select().from(agentTasks).where(and(...conditions)).orderBy(desc(agentTasks.queuedAt)).limit(input.limit);
    }),

  cancelTask: protectedProcedure
    .input(z.object({ taskId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const [task] = await db.select().from(agentTasks).where(eq(agentTasks.id, input.taskId));
      if (!task) throw new TRPCError({ code: "NOT_FOUND" });
      if (task.status !== "queued") throw new TRPCError({ code: "BAD_REQUEST", message: "Can only cancel queued tasks" });
      await db.update(agentTasks).set({ status: "cancelled", completedAt: Date.now() }).where(eq(agentTasks.id, input.taskId));
      return { success: true };
    }),

  // ─── Audit Log ──────────────────────────────────────────────────────

  getAuditLog: protectedProcedure
    .input(z.object({
      agentId: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const conditions: any[] = [];
      if (input.agentId) conditions.push(eq(agentAuditLog.agentId, input.agentId));
      return db.select().from(agentAuditLog)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(agentAuditLog.id)).limit(input.limit);
    }),

  verifyAuditChain: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const entries = await db.select().from(agentAuditLog)
        .where(eq(agentAuditLog.agentId, input.agentId)).orderBy(agentAuditLog.id);
      let valid = true;
      let brokenAt: number | null = null;
      for (let i = 1; i < entries.length; i++) {
        if (entries[i].previousHash !== entries[i - 1].recordHash) {
          valid = false;
          brokenAt = entries[i].id;
          break;
        }
      }
      return {
        valid, totalEntries: entries.length, brokenAt,
        message: valid
          ? `Audit chain verified: ${entries.length} entries, integrity intact`
          : `Audit chain BROKEN at entry ${brokenAt}`,
      };
    }),

  // ─── Heartbeat & Watchdog ────────────────────────────────────────────

  heartbeat: publicProcedure
    .input(z.object({
      agentId: z.string(),
      registrationToken: z.string().optional(),
      platform: z.string().optional(),
      architecture: z.string().optional(),
      username: z.string().optional(),
      privilege: z.enum(["user", "elevated"]).optional(),
      executors: z.array(z.string()).optional(),
      pid: z.number().optional(),
      hostname: z.string().optional(),
      internalIp: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const payload: HeartbeatPayload = {
        ...input,
        ipAddress: (ctx.req as any)?.ip || (ctx.req as any)?.headers?.["x-forwarded-for"] || undefined,
        userAgent: (ctx.req as any)?.headers?.["user-agent"] || undefined,
      };
      return processHeartbeat(payload);
    }),

  runWatchdog: adminProcedure.mutation(async () => {
    return runWatchdogSweep();
  }),

  // ─── Dashboard Stats ────────────────────────────────────────────────

  dashboardStats: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) {
      const fips = getFIPSCrypto();
      const fipsReport = fips.getComplianceReport();
      return {
        agents: { total: 0, active: 0, pending: 0, paused: 0, lost: 0, terminated: 0, completed: 0 },
        c2Servers: { total: 0, connected: 0 },
        tasks: { total: 0, queued: 0, executing: 0, completed: 0, failed: 0 },
        fips: { providerActive: fipsReport.fipsProviderActive, complianceLevel: fipsReport.complianceLevel, opensslVersion: fipsReport.opensslVersion },
      };
    }

    const [agentStats] = await db.select({
      total: count(),
      active: sql<number>`SUM(CASE WHEN agentStatus = 'active' THEN 1 ELSE 0 END)`,
      pending: sql<number>`SUM(CASE WHEN agentStatus = 'pending_approval' THEN 1 ELSE 0 END)`,
      paused: sql<number>`SUM(CASE WHEN agentStatus = 'paused' THEN 1 ELSE 0 END)`,
      lost: sql<number>`SUM(CASE WHEN agentStatus = 'lost' THEN 1 ELSE 0 END)`,
      terminated: sql<number>`SUM(CASE WHEN agentStatus = 'terminated' THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN agentStatus = 'completed' THEN 1 ELSE 0 END)`,
    }).from(agentDeployments);

    const [c2Stats] = await db.select({
      total: count(),
      connected: sql<number>`SUM(CASE WHEN c2Status = 'connected' THEN 1 ELSE 0 END)`,
    }).from(c2Servers);

    const [taskStats] = await db.select({
      total: count(),
      queued: sql<number>`SUM(CASE WHEN taskStatus = 'queued' THEN 1 ELSE 0 END)`,
      executing: sql<number>`SUM(CASE WHEN taskStatus = 'executing' THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN taskStatus = 'completed' THEN 1 ELSE 0 END)`,
      failed: sql<number>`SUM(CASE WHEN taskStatus = 'failed' THEN 1 ELSE 0 END)`,
    }).from(agentTasks);

    const fips = getFIPSCrypto();
    const fipsReport = fips.getComplianceReport();

    return {
      agents: {
        total: agentStats.total ?? 0, active: Number(agentStats.active) || 0,
        pending: Number(agentStats.pending) || 0, paused: Number(agentStats.paused) || 0,
        lost: Number(agentStats.lost) || 0, terminated: Number(agentStats.terminated) || 0,
        completed: Number(agentStats.completed) || 0,
      },
      c2Servers: { total: c2Stats.total ?? 0, connected: Number(c2Stats.connected) || 0 },
      tasks: {
        total: taskStats.total ?? 0, queued: Number(taskStats.queued) || 0,
        executing: Number(taskStats.executing) || 0, completed: Number(taskStats.completed) || 0,
        failed: Number(taskStats.failed) || 0,
      },
      fips: { providerActive: fipsReport.fipsProviderActive, complianceLevel: fipsReport.complianceLevel, opensslVersion: fipsReport.opensslVersion },
    };
  }),
});
