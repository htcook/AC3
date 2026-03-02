import { notifyOwner } from "../_core/notification";
/**
 * Session Alerter Router — tRPC endpoints for managing the session alerting system.
 * Controls the background polling, alert retrieval, and configuration.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { sessionAlerter, type SessionAlert } from "../lib/session-alerter";
import { eq } from "drizzle-orm";

// Initialize the alerter with server provider on first import
let initialized = false;

async function ensureInitialized() {
  if (initialized) return;
  initialized = true;

  sessionAlerter.setServerProvider(async () => {
    const { metasploitServers } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const db = await getDbRequired();

    const servers = await db
      .select()
      .from(metasploitServers)
      .where(eq(metasploitServers.status, "online"));

    return servers.map((s) => ({
      id: s.id,
      name: s.name,
      host: s.ipAddress || "",
      port: s.rpcPort || 55553,
      rpcUser: s.rpcUser || "msf",
      rpcPass: s.rpcPass || "",
      rpcSsl: s.rpcSsl ?? false,
      sshTunnelEnabled: s.sshTunnelEnabled ?? false,
      sshHost: s.ipAddress || "",
      sshPort: 22,
      sshUser: s.sshUser || "root",
      sshKeyPath: s.sshKeyPath || "",
    }));
  });
}

export const sessionAlerterRouter = router({
  // ─── Get alerter status and config ─────────────────────────────────────────
  getStatus: protectedProcedure.query(async () => {
    await ensureInitialized();
    const config = sessionAlerter.getConfig();
    const alerts = sessionAlerter.getAlerts(100);
    const unreadCount = sessionAlerter.getUnreadCount();

    return {
      ...config,
      alertCount: alerts.length,
      unreadCount,
    };
  }),

  // ─── Start the alerter ────────────────────────────────────────────────────
  start: protectedProcedure
    .input(
      z
        .object({
          pollIntervalMs: z.number().min(5000).max(300000).optional(),
          notifyOwnerEnabled: z.boolean().optional(),
        })
        .optional()
    )
    .mutation(async ({ input }) => {
      await ensureInitialized();
      sessionAlerter.start({
        pollIntervalMs: input?.pollIntervalMs,
        notifyOwnerEnabled: input?.notifyOwnerEnabled,
      });
      return { success: true, config: sessionAlerter.getConfig() };
    }),

  // ─── Stop the alerter ─────────────────────────────────────────────────────
  stop: protectedProcedure.mutation(async () => {
    sessionAlerter.stop();
    return { success: true };
  }),

  // ─── Update config ────────────────────────────────────────────────────────
  updateConfig: protectedProcedure
    .input(
      z.object({
        pollIntervalMs: z.number().min(5000).max(300000).optional(),
        enabled: z.boolean().optional(),
        notifyOwnerEnabled: z.boolean().optional(),
      })
    )
    .mutation(async ({ input }) => {
      await ensureInitialized();
      sessionAlerter.updateConfig(input);
      return { success: true, config: sessionAlerter.getConfig() };
    }),

  // ─── Get alerts ───────────────────────────────────────────────────────────
  getAlerts: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(500).default(50) }).optional())
    .query(async ({ input }) => {
      const alerts = sessionAlerter.getAlerts(input?.limit ?? 50);
      const unreadCount = sessionAlerter.getUnreadCount();
      return { alerts, unreadCount };
    }),

  // ─── Clear all alerts ─────────────────────────────────────────────────────
  clearAlerts: protectedProcedure.mutation(async () => {
    sessionAlerter.clearAlerts();
    return { success: true };
  }),

  // ─── Dismiss a specific alert ─────────────────────────────────────────────
  dismissAlert: protectedProcedure
    .input(
      z.object({
        serverId: z.number(),
        sessionId: z.string(),
      })
    )
    .mutation(async ({ input }) => {
      sessionAlerter.dismissAlert(input.serverId, input.sessionId);
      return { success: true };
    }),

  // ─── Manual poll (force check now) ────────────────────────────────────────
  pollNow: protectedProcedure.mutation(async () => {
    await ensureInitialized();
    // Temporarily start if not running, poll, then restore state
    const config = sessionAlerter.getConfig();
    if (!config.enabled) {
      sessionAlerter.start({ pollIntervalMs: 30000 });
      // Wait for the initial poll to complete
      await new Promise((r) => setTimeout(r, 3000));
      sessionAlerter.stop();
    }
    const alerts = sessionAlerter.getAlerts(50);
    return { success: true, alerts, count: alerts.length };
  }),
});
