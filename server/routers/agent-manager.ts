import * as db from "../db";
/**
 * Agent Manager Router
 *
 * tRPC router for multi-C2 agent lifecycle management, FIPS compliance monitoring,
 * and audit-logged agent operations. Supports CALDERA, Sliver, Metasploit, and
 * native Ace C3 agent protocols.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import {
  agentDeployments,
  agentTasks,
  agentAuditLog,
  c2Servers,
  fipsComplianceRecords,
} from "../../drizzle/schema";
import { eq, desc, and, sql, count } from "drizzle-orm";
import { getFIPSCrypto } from "../lib/fips-crypto";
import { checkC2Health } from "../lib/c2-health";
import { processHeartbeat, runWatchdogSweep, type HeartbeatPayload } from "../lib/agent-heartbeat";
import { runScheduledFipsAudit } from "../lib/fips-audit-scheduler";
import { scanCredentials, runFullMigration } from "../lib/credential-migration";
import {
  ensureCA,
  issueClientCertForServer,
  listCertificates,
  revokeCertificate,
  getCertificateWithKey,
  getMTLSConfigForServer,
  type CertificateInfo,
} from "../lib/mtls-certs";

// ─── Input Schemas ────────────────────────────────────────────────────────

const c2ServerInput = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(["caldera", "sliver", "metasploit", "manjusaka"]),
  baseUrl: z.string().url(),
  authConfig: z.record(z.string(), z.unknown()),
});

const agentDeployInput = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  engagementId: z.number().optional(),
  targetPlatform: z.enum(["windows", "linux", "darwin"]),
  c2Protocol: z.enum(["caldera", "sliver", "metasploit", "manjusaka", "native"]),
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

// ─── Helper: Audit Log ────────────────────────────────────────────────────

async function logAgentEvent(
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

  // Get previous hash for chain
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

// ─── Router ───────────────────────────────────────────────────────────────

export const agentManagerRouter = router({
  // ─── FIPS Compliance ────────────────────────────────────────────────

  /** Get current FIPS 140-3 compliance report */
  fipsStatus: protectedProcedure.query(async () => {
    const fips = getFIPSCrypto();
    return fips.getComplianceReport();
  }),

  /** Run a full FIPS compliance audit and store results */
  fipsAudit: protectedProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const report = fips.getComplianceReport();

    const checks: Array<{
      checkType: "tls_cipher" | "algorithm_usage" | "key_strength" | "provider_status" | "full_audit";
      status: "compliant" | "non_compliant" | "warning";
      component: string;
      details: Record<string, unknown>;
    }> = [];

    // Provider status
    checks.push({
      checkType: "provider_status",
      status: report.fipsProviderActive ? "compliant" : "warning",
      component: "openssl-fips-provider",
      details: {
        active: report.fipsProviderActive,
        opensslVersion: report.opensslVersion,
        note: report.fipsProviderActive
          ? "FIPS provider active"
          : "FIPS provider not active — using software-only mode with FIPS-approved algorithms.",
      },
    });

    // Test AES-256-GCM
    try {
      const testData = "FIPS compliance test payload";
      const encrypted = fips.encrypt(testData, "fips-audit");
      const decrypted = fips.decrypt(encrypted, "fips-audit");
      checks.push({
        checkType: "algorithm_usage",
        status: decrypted.toString() === testData ? "compliant" : "non_compliant",
        component: "aes-256-gcm",
        details: { algorithm: "aes-256-gcm", operation: "encrypt-decrypt", result: "pass" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "aes-256-gcm",
        details: { error: e.message },
      });
    }

    // Test ECDSA P-256
    try {
      const kp = fips.generateKeyPair("P-256");
      const sig = fips.sign("test", kp.privateKey);
      const valid = fips.verify("test", sig, kp.publicKey);
      checks.push({
        checkType: "key_strength",
        status: valid ? "compliant" : "non_compliant",
        component: "ecdsa-p256",
        details: { curve: "P-256", signVerify: valid ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "key_strength",
        status: "non_compliant",
        component: "ecdsa-p256",
        details: { error: e.message },
      });
    }

    // Test HMAC-SHA256
    try {
      const hmacResult = fips.hmac("test data");
      const verified = fips.verifyHmac("test data", hmacResult);
      checks.push({
        checkType: "algorithm_usage",
        status: verified ? "compliant" : "non_compliant",
        component: "hmac-sha256",
        details: { algorithm: "hmac-sha256", result: verified ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "hmac-sha256",
        details: { error: e.message },
      });
    }

    // Test PBKDF2
    try {
      const pw = fips.hashPassword("test-password-123");
      const valid = fips.verifyPassword("test-password-123", pw);
      checks.push({
        checkType: "algorithm_usage",
        status: valid ? "compliant" : "non_compliant",
        component: "pbkdf2-sha256",
        details: { iterations: pw.iterations, result: valid ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "pbkdf2-sha256",
        details: { error: e.message },
      });
    }

    // Full audit summary
    const allCompliant = checks.every((c) => c.status === "compliant");
    const hasNonCompliant = checks.some((c) => c.status === "non_compliant");
    checks.push({
      checkType: "full_audit",
      status: hasNonCompliant ? "non_compliant" : allCompliant ? "compliant" : "warning",
      component: "platform-wide",
      details: {
        totalChecks: checks.length,
        compliant: checks.filter((c) => c.status === "compliant").length,
        warnings: checks.filter((c) => c.status === "warning").length,
        nonCompliant: checks.filter((c) => c.status === "non_compliant").length,
      },
    });

    // Store results
    const now = Date.now();
    for (const check of checks) {
      await db.insert(fipsComplianceRecords).values({
        checkType: check.checkType,
        status: check.status,
        component: check.component,
        details: check.details,
        opensslVersion: report.opensslVersion,
        fipsProviderActive: report.fipsProviderActive,
        createdAt: now,
      });
    }

    return { checks, overallStatus: hasNonCompliant ? "non_compliant" : allCompliant ? "compliant" : "warning" };
  }),

  /** Get FIPS compliance history */
  fipsHistory: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      return db
        .select()
        .from(fipsComplianceRecords)
        .orderBy(desc(fipsComplianceRecords.id))
        .limit(input.limit);
    }),

  // ─── C2 Servers ─────────────────────────────────────────────────────

  /** List all configured C2 servers */
  listC2Servers: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return [];
    return db.select().from(c2Servers).orderBy(desc(c2Servers.createdAt));
  }),

  /** Add a new C2 server configuration */
  addC2Server: protectedProcedure.input(c2ServerInput).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const id = fips.uuid();
    const now = Date.now();

    // Encrypt auth config
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

  /** Test connectivity to a C2 server with real HTTP health probes */
  testC2Connection: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [server] = await db
        .select()
        .from(c2Servers)
        .where(eq(c2Servers.id, input.id));

      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "C2 server not found" });

      // Perform real HTTP health check
      const result = await checkC2Health({
        id: server.id,
        name: server.name,
        type: server.type as "caldera" | "sliver" | "metasploit" | "manjusaka",
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

  /** Remove a C2 server */
  removeC2Server: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.delete(c2Servers).where(eq(c2Servers.id, input.id));
      return { success: true };
    }),

  // ─── Agent Deployments ──────────────────────────────────────────────

  /** List all agent deployments */
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
        conditions.push(eq(agentDeployments.agentStatus, input.status));
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [agents, [{ total }]] = await Promise.all([
        db
          .select()
          .from(agentDeployments)
          .where(where)
          .orderBy(desc(agentDeployments.createdAt))
          .limit(input.limit)
          .offset(input.offset),
        db
          .select({ total: count() })
          .from(agentDeployments)
          .where(where),
      ]);

      return { agents, total };
    }),

  /** Get agent deployment details */
  getAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [agent] = await db
        .select()
        .from(agentDeployments)
        .where(eq(agentDeployments.id, input.id));

      if (!agent) throw new TRPCError({ code: "NOT_FOUND", message: "Agent not found" });
      return agent;
    }),

  /** Request a new agent deployment (creates in pending_approval state) */
  requestDeployment: protectedProcedure
    .input(agentDeployInput)
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate target host/IP for agent deployment ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        if (input.targetIp) {
          await enforceTargetScope(input.engagementId, input.targetIp, "Agent Deployment", ctx);
        }
        if (input.targetHostname) {
          await enforceTargetScope(input.engagementId, input.targetHostname, "Agent Deployment", ctx);
        }
      }
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const fips = getFIPSCrypto();
      const id = fips.uuid();
      const now = Date.now();

      // Generate agent key pair for mTLS identity
      const keyPair = fips.generateKeyPair("P-256");

      // Generate one-time registration token
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

  /** Approve an agent deployment */
  approveDeployment: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [agent] = await db
        .select()
        .from(agentDeployments)
        .where(eq(agentDeployments.id, input.id));

      if (!agent) throw new TRPCError({ code: "NOT_FOUND" });
      if (agent.status !== "pending_approval") {
        throw new TRPCError({ code: "BAD_REQUEST", message: `Cannot approve agent in ${agent.status} state` });
      }

      await db
        .update(agentDeployments)
        .set({
          status: "approved",
          approvedBy: ctx.user?.id ?? 1,
          approvedAt: Date.now(),
          updatedAt: Date.now(),
        })
        .where(eq(agentDeployments.id, input.id));

      await logAgentEvent(input.id, "approved", ctx.user?.id ?? 1, "operator", {
        action: "deployment_approved",
      });

      return { success: true };
    }),

  /** Reject an agent deployment */
  rejectDeployment: protectedProcedure
    .input(z.object({ id: z.string(), reason: z.string().min(1) }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db
        .update(agentDeployments)
        .set({
          status: "failed",
          rejectionReason: input.reason,
          updatedAt: Date.now(),
        })
        .where(eq(agentDeployments.id, input.id));

      await logAgentEvent(input.id, "rejected", ctx.user?.id ?? 1, "operator", {
        action: "deployment_rejected",
        reason: input.reason,
      });

      return { success: true };
    }),

  /** Pause an active agent */
  pauseAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db
        .update(agentDeployments)
        .set({ agentStatus: "paused", updatedAt: Date.now() })
        .where(eq(agentDeployments.id, input.id));

      await logAgentEvent(input.id, "paused", ctx.user?.id ?? 1, "operator");
      return { success: true };
    }),

  /** Resume a paused agent */
  resumeAgent: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db
        .update(agentDeployments)
        .set({ agentStatus: "active", updatedAt: Date.now() })
        .where(eq(agentDeployments.id, input.id));

      await logAgentEvent(input.id, "resumed", ctx.user?.id ?? 1, "operator");
      return { success: true };
    }),

  /** Terminate an agent (remote kill) */
  terminateAgent: protectedProcedure
    .input(z.object({ id: z.string(), reason: z.string().optional() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db
        .update(agentDeployments)
        .set({
          status: "terminated",
          terminatedAt: Date.now(),
          updatedAt: Date.now(),
        })
        .where(eq(agentDeployments.id, input.id));

      await logAgentEvent(input.id, "terminated", ctx.user?.id ?? 1, "operator", {
        reason: input.reason ?? "Manual termination",
      });

      return { success: true };
    }),

  // ─── Agent Tasks ────────────────────────────────────────────────────

  /** Assign a task to an agent */
  assignTask: protectedProcedure.input(taskInput).mutation(async ({ input, ctx }) => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const id = fips.uuid();
    const now = Date.now();

    // Encrypt the command
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
      taskId: id,
      techniqueId: input.techniqueId,
      techniqueName: input.techniqueName,
    });

    return { id };
  }),

  /** List tasks for an agent */
  listTasks: protectedProcedure
    .input(
      z.object({
        agentId: z.string(),
        status: z.enum(["queued", "sent", "executing", "completed", "failed", "timeout", "cancelled"]).optional(),
        limit: z.number().min(1).max(200).default(50),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      const conditions: any[] = [eq(agentTasks.agentId, input.agentId)];
      if (input.status) {
        conditions.push(eq(agentTasks.taskStatus, input.status));
      }

      return db
        .select()
        .from(agentTasks)
        .where(and(...conditions))
        .orderBy(desc(agentTasks.queuedAt))
        .limit(input.limit);
    }),

  /** Cancel a queued task */
  cancelTask: protectedProcedure
    .input(z.object({ taskId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [task] = await db
        .select()
        .from(agentTasks)
        .where(eq(agentTasks.id, input.taskId));

      if (!task) throw new TRPCError({ code: "NOT_FOUND" });
      if (task.taskStatus !== "queued") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Can only cancel queued tasks" });
      }

      await db
        .update(agentTasks)
        .set({ taskStatus: "cancelled", completedAt: Date.now() })
        .where(eq(agentTasks.id, input.taskId));

      return { success: true };
    }),

  // ─── Audit Log ──────────────────────────────────────────────────────

  /** Get audit log for an agent */
  getAuditLog: protectedProcedure
    .input(
      z.object({
        agentId: z.string().optional(),
        limit: z.number().min(1).max(500).default(100),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      const conditions: any[] = [];
      if (input.agentId) {
        conditions.push(eq(agentAuditLog.agentId, input.agentId));
      }

      return db
        .select()
        .from(agentAuditLog)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(agentAuditLog.id))
        .limit(input.limit);
    }),

  /** Verify audit log integrity chain */
  verifyAuditChain: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const entries = await db
        .select()
        .from(agentAuditLog)
        .where(eq(agentAuditLog.agentId, input.agentId))
        .orderBy(agentAuditLog.id);

      let valid = true;
      let brokenAt: number | null = null;

      for (let i = 1; i < entries.length; i++) {
        const current = entries[i];
        const previous = entries[i - 1];

        if (current.previousHash !== previous.recordHash) {
          valid = false;
          brokenAt = current.id;
          break;
        }
      }

      return {
        valid,
        totalEntries: entries.length,
        brokenAt,
        message: valid
          ? `Audit chain verified: ${entries.length} entries, integrity intact`
          : `Audit chain BROKEN at entry ${brokenAt}`,
      };
    }),

  // ─── Heartbeat & Watchdog ────────────────────────────────────────────

  /** Process an agent heartbeat (public endpoint — agents authenticate via registration token) */
  heartbeat: publicProcedure
    .input(
      z.object({
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
      })
    )
    .mutation(async ({ input, ctx }) => {
      const payload: HeartbeatPayload = {
        ...input,
        ipAddress: (ctx.req as any)?.ip || (ctx.req as any)?.headers?.["x-forwarded-for"] || undefined,
        userAgent: (ctx.req as any)?.headers?.["user-agent"] || undefined,
      };
      return processHeartbeat(payload);
    }),

  /** Manually trigger a watchdog sweep (admin) */
  runWatchdog: protectedProcedure.mutation(async () => {
    return runWatchdogSweep();
  }),

  /** Manually trigger a scheduled FIPS audit (admin) */
  runScheduledFipsAudit: protectedProcedure.mutation(async () => {
    return runScheduledFipsAudit();
  }),

  // ─── Dashboard Stats ────────────────────────────────────────────────

  /** Get agent infrastructure dashboard statistics */
  dashboardStats: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) {
      const fips = getFIPSCrypto();
      const fipsReport = fips.getComplianceReport();
      return {
        agents: { total: 0, active: 0, pending: 0, paused: 0, lost: 0, terminated: 0, completed: 0 },
        c2Servers: { total: 0, connected: 0 },
        tasks: { total: 0, queued: 0, executing: 0, completed: 0, failed: 0 },
        fips: {
          providerActive: fipsReport.fipsProviderActive,
          complianceLevel: fipsReport.complianceLevel,
          opensslVersion: fipsReport.opensslVersion,
        },
      };
    }

    const [agentStats] = await db
      .select({
        total: count(),
        active: sql<number>`SUM(CASE WHEN agentStatus = 'active' THEN 1 ELSE 0 END)`,
        pending: sql<number>`SUM(CASE WHEN agentStatus = 'pending_approval' THEN 1 ELSE 0 END)`,
        paused: sql<number>`SUM(CASE WHEN agentStatus = 'paused' THEN 1 ELSE 0 END)`,
        lost: sql<number>`SUM(CASE WHEN agentStatus = 'lost' THEN 1 ELSE 0 END)`,
        terminated: sql<number>`SUM(CASE WHEN agentStatus = 'terminated' THEN 1 ELSE 0 END)`,
        completed: sql<number>`SUM(CASE WHEN agentStatus = 'completed' THEN 1 ELSE 0 END)`,
      })
      .from(agentDeployments);

    const [c2Stats] = await db
      .select({
        total: count(),
        connected: sql<number>`SUM(CASE WHEN c2Status = 'connected' THEN 1 ELSE 0 END)`,
      })
      .from(c2Servers);

    const [taskStats] = await db
      .select({
        total: count(),
        queued: sql<number>`SUM(CASE WHEN taskStatus = 'queued' THEN 1 ELSE 0 END)`,
        executing: sql<number>`SUM(CASE WHEN taskStatus = 'executing' THEN 1 ELSE 0 END)`,
        completed: sql<number>`SUM(CASE WHEN taskStatus = 'completed' THEN 1 ELSE 0 END)`,
        failed: sql<number>`SUM(CASE WHEN taskStatus = 'failed' THEN 1 ELSE 0 END)`,
      })
      .from(agentTasks);

    const fips = getFIPSCrypto();
    const fipsReport = fips.getComplianceReport();

    return {
      agents: {
        total: agentStats.total ?? 0,
        active: Number(agentStats.active) || 0,
        pending: Number(agentStats.pending) || 0,
        paused: Number(agentStats.paused) || 0,
        lost: Number(agentStats.lost) || 0,
        terminated: Number(agentStats.terminated) || 0,
        completed: Number(agentStats.completed) || 0,
      },
      c2Servers: {
        total: c2Stats.total ?? 0,
        connected: Number(c2Stats.connected) || 0,
      },
      tasks: {
        total: taskStats.total ?? 0,
        queued: Number(taskStats.queued) || 0,
        executing: Number(taskStats.executing) || 0,
        completed: Number(taskStats.completed) || 0,
        failed: Number(taskStats.failed) || 0,
      },
      fips: {
        providerActive: fipsReport.fipsProviderActive,
        complianceLevel: fipsReport.complianceLevel,
        opensslVersion: fipsReport.opensslVersion,
      },
    };
  }),

  // ─── TLS Audit ──────────────────────────────────────────────────────

  /** Audit current TLS configuration for FIPS compliance */
  auditTLS: protectedProcedure.query(async () => {
    const { auditTLSConfiguration } = await import("../lib/fips-tls");
    const { isFIPSTLSEnforced } = await import("../lib/fips-tls-global");
    const audit = auditTLSConfiguration();
    return {
      ...audit,
      globalEnforcement: isFIPSTLSEnforced(),
      timestamp: Date.now(),
    };
  }),

  /** Test a TLS connection to a remote host for FIPS compliance */
  testTLSConnection: protectedProcedure
    .input(z.object({
      hostname: z.string().min(1),
      port: z.number().min(1).max(65535).default(443),
    }))
    .mutation(async ({ input }) => {
      const { testFIPSTLSConnection } = await import("../lib/fips-tls");
      return testFIPSTLSConnection(input.hostname, input.port);
    }),

  // ─── Credential Migration ─────────────────────────────────────────────

  /** Scan all credential tables and report migration status (dry run). */
  scanCredentialMigration: protectedProcedure.query(async () => {
    const scan = await scanCredentials();
    const totalLegacy =
      scan.serverCredentials.legacy + scan.serverCredentials.plaintext +
      scan.sshKeys.legacy + scan.sshKeys.plaintext +
      scan.cloudCredentials.legacy;
    const totalFips =
      scan.serverCredentials.fips + scan.sshKeys.fips + scan.cloudCredentials.fips;
    const totalAll =
      scan.serverCredentials.total + scan.sshKeys.total + scan.cloudCredentials.total;

    return {
      ...scan,
      summary: {
        totalCredentials: totalAll,
        totalFips,
        totalLegacy,
        migrationNeeded: totalLegacy > 0,
        fipsPercentage: totalAll > 0 ? Math.round((totalFips / totalAll) * 100) : 100,
      },
      timestamp: Date.now(),
    };
  }),

  /** Run the full credential migration (re-encrypt all legacy credentials with FIPS). */
  runCredentialMigration: protectedProcedure.mutation(async () => {
    const report = await runFullMigration();
    return report;
  }),

  // ─── mTLS Certificate Management ──────────────────────────────────────

  /** Ensure the internal CA exists and return its info (without private key). */
  ensureMTLSCA: protectedProcedure.mutation(async () => {
    const ca = await ensureCA();
    const { privateKey, ...info } = ca;
    return info;
  }),

  /** Issue a client certificate for a specific C2 server. */
  issueClientCert: protectedProcedure
    .input(z.object({
      c2ServerId: z.string().min(1),
      serverName: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      const cert = await issueClientCertForServer(input.c2ServerId, input.serverName);
      const { privateKey, ...info } = cert;
      return info;
    }),

  /** List all mTLS certificates (CA + client). */
  listMTLSCerts: protectedProcedure.query(async () => {
    const certs = await listCertificates();
    return certs;
  }),

  /** Revoke a certificate by ID. */
  revokeMTLSCert: protectedProcedure
    .input(z.object({ id: z.string().min(1) }))
    .mutation(async ({ input }) => {
      const success = await revokeCertificate(input.id);
      if (!success) throw new TRPCError({ code: "NOT_FOUND", message: "Certificate not found" });
      return { success: true };
    }),

  /** Download a certificate (PEM format, no private key). */
  downloadCert: protectedProcedure
    .input(z.object({ id: z.string().min(1) }))
    .query(async ({ input }) => {
      const cert = await getCertificateWithKey(input.id);
      if (!cert) throw new TRPCError({ code: "NOT_FOUND", message: "Certificate not found" });
      return {
        certificate: cert.certificate,
        commonName: cert.commonName,
        fingerprint: cert.fingerprint,
      };
    }),

  /** Check mTLS status for a specific C2 server. */
  getMTLSStatus: protectedProcedure
    .input(z.object({ c2ServerId: z.string().min(1) }))
    .query(async ({ input }) => {
      const config = await getMTLSConfigForServer(input.c2ServerId);
      return {
        enabled: config !== null,
        hasCert: config !== null,
        hasCA: config !== null,
      };
    }),
});
