import * as db from "../db";
/**
 * Credential Rotation Alerts Router
 * Manages alert rules, checks credential expiry, and dispatches notifications.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const credentialAlertsRouter = router({
  /** List all alert rules */
  listRules: protectedProcedure
    .input(z.object({ credentialId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { credentialAlertRules } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");

      if (input?.credentialId) {
        return db.select().from(credentialAlertRules)
          .where(eq(credentialAlertRules.credentialId, input.credentialId))
          .orderBy(desc(credentialAlertRules.createdAt));
      }
      return db.select().from(credentialAlertRules).orderBy(desc(credentialAlertRules.createdAt));
    }),

  /** Create an alert rule for a credential */
  createRule: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      alertName: z.string().min(1),
      thresholdDays: z.number().min(1).max(365).default(30),
      isEnabled: z.boolean().default(true),
      notifyOwner: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { credentialAlertRules } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(credentialAlertRules).values({
        credentialId: input.credentialId,
        alertName: input.alertName,
        thresholdDays: input.thresholdDays,
        isEnabled: input.isEnabled,
        notifyOwner: input.notifyOwner,
        createdBy: ctx.user?.name || ctx.user?.openId || null,
      });

      return { id: result.insertId, success: true };
    }),

  /** Update an alert rule */
  updateRule: protectedProcedure
    .input(z.object({
      ruleId: z.number(),
      alertName: z.string().min(1).optional(),
      thresholdDays: z.number().min(1).max(365).optional(),
      isEnabled: z.boolean().optional(),
      notifyOwner: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { credentialAlertRules } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const updates: Record<string, any> = {};
      if (input.alertName !== undefined) updates.alertName = input.alertName;
      if (input.thresholdDays !== undefined) updates.thresholdDays = input.thresholdDays;
      if (input.isEnabled !== undefined) updates.isEnabled = input.isEnabled;
      if (input.notifyOwner !== undefined) updates.notifyOwner = input.notifyOwner;

      await db.update(credentialAlertRules).set(updates).where(eq(credentialAlertRules.id, input.ruleId));
      return { success: true };
    }),

  /** Delete an alert rule */
  deleteRule: protectedProcedure
    .input(z.object({ ruleId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { credentialAlertRules } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(credentialAlertRules).where(eq(credentialAlertRules.id, input.ruleId));
      return { success: true };
    }),

  /** Run credential expiry check across all rules */
  runExpiryCheck: protectedProcedure
    .input(z.object({}).optional())
    .mutation(async () => {
      const { getDb } = await import("../db");
      const { credentialAlertRules, credentialAlertHistory, cloudCredentials } = await import("../../drizzle/schema");
      const { batchCheckCredentials, formatNotificationContent } = await import("../lib/credential-rotation-alerts");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Fetch all enabled rules
      const rules = await db.select().from(credentialAlertRules).where(eq(credentialAlertRules.isEnabled, true));
      if (rules.length === 0) return { alertsGenerated: 0, notificationsSent: 0 };

      // Fetch all credentials
      const creds = await db.select().from(cloudCredentials);
      const credInfos = creds.map(c => ({
        credentialId: c.id,
        credentialName: c.credentialName,
        provider: c.provider,
        expiresAt: c.expiresAt,
        daysUntilExpiry: null as number | null,
        status: c.status,
        lastValidatedAt: c.lastValidatedAt,
      }));

      // Run batch check
      const alerts = batchCheckCredentials(credInfos, rules.map(r => ({
        id: r.id,
        credentialId: r.credentialId,
        alertName: r.alertName,
        thresholdDays: r.thresholdDays,
        isEnabled: r.isEnabled,
        notifyOwner: r.notifyOwner,
      })));

      if (alerts.length === 0) return { alertsGenerated: 0, notificationsSent: 0 };

      // Store alert history
      for (const alert of alerts) {
        const cred = credInfos.find(c => c.credentialId === alert.credentialId);
        await db.insert(credentialAlertHistory).values({
          ruleId: alert.ruleId,
          credentialId: alert.credentialId,
          alertType: alert.alertType,
          severity: alert.severity,
          message: alert.message,
          notificationSent: false,
          credentialProvider: cred?.provider || null,
          credentialName: cred?.credentialName || null,
          expiresAt: cred?.expiresAt || null,
          daysUntilExpiry: alert.daysUntilExpiry,
        });
      }

      // Update rule last checked timestamps
      for (const rule of rules) {
        await db.update(credentialAlertRules)
          .set({ lastCheckedAt: new Date() })
          .where(eq(credentialAlertRules.id, rule.id));
      }

      // Send notification for critical/high alerts
      let notificationsSent = 0;
      const notifiableAlerts = alerts.filter(a => a.shouldNotify);
      if (notifiableAlerts.length > 0) {
        try {
          const { notifyOwner } = await import("../_core/notification");
          const { title, content } = formatNotificationContent(notifiableAlerts, credInfos);
          const sent = await notifyOwner({ title, content });
          if (sent) notificationsSent = 1;
        } catch {
          // Notification service unavailable, alerts still recorded
        }
      }

      return {
        alertsGenerated: alerts.length,
        notificationsSent,
        alerts: alerts.map(a => ({
          credentialId: a.credentialId,
          alertType: a.alertType,
          severity: a.severity,
          daysUntilExpiry: a.daysUntilExpiry,
        })),
      };
    }),

  /** Get alert history */
  getAlertHistory: protectedProcedure
    .input(z.object({
      credentialId: z.number().optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      limit: z.number().min(1).max(200).default(50),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { credentialAlertHistory } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.credentialId) conditions.push(eq(credentialAlertHistory.credentialId, input.credentialId));
      if (input?.severity) conditions.push(eq(credentialAlertHistory.severity, input.severity));

      const history = conditions.length > 0
        ? await db.select().from(credentialAlertHistory).where(and(...conditions)).orderBy(desc(credentialAlertHistory.createdAt)).limit(input?.limit || 50)
        : await db.select().from(credentialAlertHistory).orderBy(desc(credentialAlertHistory.createdAt)).limit(input?.limit || 50);

      return history;
    }),

  /** Acknowledge an alert */
  acknowledgeAlert: protectedProcedure
    .input(z.object({ alertId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { credentialAlertHistory } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.update(credentialAlertHistory)
        .set({
          acknowledgedAt: new Date(),
          acknowledgedBy: ctx.user?.name || ctx.user?.openId || null,
        })
        .where(eq(credentialAlertHistory.id, input.alertId));

      return { success: true };
    }),

  /** Get alert stats/dashboard summary */
  getStats: protectedProcedure
    .input(z.object({}).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { credentialAlertRules, credentialAlertHistory } = await import("../../drizzle/schema");
      const { count, eq, isNull } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [ruleCount] = await db.select({ count: count() }).from(credentialAlertRules);
      const [enabledRuleCount] = await db.select({ count: count() }).from(credentialAlertRules).where(eq(credentialAlertRules.isEnabled, true));
      const [totalAlerts] = await db.select({ count: count() }).from(credentialAlertHistory);
      const [unacknowledged] = await db.select({ count: count() }).from(credentialAlertHistory).where(isNull(credentialAlertHistory.acknowledgedAt));
      const [criticalAlerts] = await db.select({ count: count() }).from(credentialAlertHistory).where(eq(credentialAlertHistory.severity, "critical"));

      return {
        totalRules: ruleCount.count,
        enabledRules: enabledRuleCount.count,
        totalAlerts: totalAlerts.count,
        unacknowledgedAlerts: unacknowledged.count,
        criticalAlerts: criticalAlerts.count,
      };
    }),
});
