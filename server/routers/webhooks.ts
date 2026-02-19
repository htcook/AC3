/**
 * Webhooks & SIEM Integration Router
 * Manages outbound webhook endpoints and event delivery.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { webhookEndpoints, webhookDeliveries } from "../../drizzle/schema";
import { eq, desc, like, and, sql } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

function generateId() {
  return `wh_${crypto.randomBytes(8).toString("hex")}`;
}

// Supported webhook events
const WEBHOOK_EVENTS = [
  "scan.completed",
  "scan.failed",
  "finding.critical",
  "finding.high",
  "engagement.created",
  "engagement.completed",
  "playbook.launched",
  "playbook.completed",
  "evidence.created",
  "detection.gap_found",
  "alert.new",
] as const;

export const webhooksRouter = router({
  // ─── List webhook endpoints ───
  list: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      enabled: z.boolean().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.search) filters.push(like(webhookEndpoints.name, `%${input.search}%`));
      if (input?.enabled !== undefined) filters.push(eq(webhookEndpoints.enabled, input.enabled));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const [items, countResult] = await Promise.all([
        db.select().from(webhookEndpoints).where(where)
          .orderBy(desc(webhookEndpoints.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(webhookEndpoints).where(where),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single webhook ───
  get: protectedProcedure
    .input(z.object({ webhookId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [webhook] = await db.select().from(webhookEndpoints)
        .where(eq(webhookEndpoints.webhookId, input.webhookId));
      if (!webhook) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook not found" });

      // Get recent deliveries
      const deliveries = await db.select().from(webhookDeliveries)
        .where(eq(webhookDeliveries.webhookId, input.webhookId))
        .orderBy(desc(webhookDeliveries.deliveredAt))
        .limit(20);

      return { ...webhook, deliveries };
    }),

  // ─── Create webhook ───
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      url: z.string().url(),
      events: z.array(z.string()).min(1),
      format: z.enum(["json", "cef", "leef"]).optional(),
      headers: z.record(z.string(), z.string()).optional(),
      secret: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const webhookId = generateId();
      const secret = input.secret || crypto.randomBytes(32).toString("hex");

      await db.insert(webhookEndpoints).values({
        webhookId,
        name: input.name,
        url: input.url,
        secret,
        events: JSON.stringify(input.events),
        format: input.format || "json",
        headers: input.headers ? JSON.stringify(input.headers) : null,
        enabled: true,
        failCount: 0,
        createdBy: ctx.user.id,
      });
      return { webhookId, secret };
    }),

  // ─── Update webhook ───
  update: protectedProcedure
    .input(z.object({
      webhookId: z.string(),
      name: z.string().optional(),
      url: z.string().url().optional(),
      events: z.array(z.string()).optional(),
      format: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      enabled: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.url !== undefined) updates.url = input.url;
      if (input.events !== undefined) updates.events = JSON.stringify(input.events);
      if (input.format !== undefined) updates.format = input.format;
      if (input.headers !== undefined) updates.headers = JSON.stringify(input.headers);
      if (input.enabled !== undefined) updates.enabled = input.enabled;

      await db.update(webhookEndpoints).set(updates)
        .where(eq(webhookEndpoints.webhookId, input.webhookId));
      return { success: true };
    }),

  // ─── Delete webhook ───
  delete: protectedProcedure
    .input(z.object({ webhookId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(webhookDeliveries)
        .where(eq(webhookDeliveries.webhookId, input.webhookId));
      await db.delete(webhookEndpoints)
        .where(eq(webhookEndpoints.webhookId, input.webhookId));
      return { success: true };
    }),

  // ─── Test webhook ───
  test: protectedProcedure
    .input(z.object({ webhookId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [webhook] = await db.select().from(webhookEndpoints)
        .where(eq(webhookEndpoints.webhookId, input.webhookId));
      if (!webhook) throw new TRPCError({ code: "NOT_FOUND" });

      const testPayload = {
        event: "test.ping",
        timestamp: new Date().toISOString(),
        data: {
          message: "This is a test webhook delivery from ACE STRIKE",
          webhookId: webhook.webhookId,
        },
      };

      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "X-Webhook-Id": webhook.webhookId,
          "X-Webhook-Signature": crypto
            .createHmac("sha256", webhook.secret || "")
            .update(JSON.stringify(testPayload))
            .digest("hex"),
        };

        // Add custom headers
        const customHeaders = webhook.headers as Record<string, string> | null;
        if (customHeaders && typeof customHeaders === "object") {
          Object.assign(headers, customHeaders);
        }

        const response = await fetch(webhook.url, {
          method: "POST",
          headers,
          body: JSON.stringify(testPayload),
          signal: AbortSignal.timeout(10000),
        });

        const responseBody = await response.text().catch(() => "");

        await db.insert(webhookDeliveries).values({
          webhookId: webhook.webhookId,
          event: "test.ping",
          payload: JSON.stringify(testPayload),
          responseStatus: response.status,
          responseBody: responseBody.slice(0, 1000),
          success: response.ok,
        });

        if (response.ok) {
          await db.update(webhookEndpoints)
            .set({ failCount: 0, lastTriggered: new Date() })
            .where(eq(webhookEndpoints.webhookId, input.webhookId));
        }

        return { success: response.ok, status: response.status, body: responseBody.slice(0, 500) };
      } catch (err: any) {
        await db.insert(webhookDeliveries).values({
          webhookId: webhook.webhookId,
          event: "test.ping",
          payload: JSON.stringify(testPayload),
          responseStatus: 0,
          responseBody: err.message,
          success: false,
        });

        await db.update(webhookEndpoints)
          .set({ failCount: sql`fail_count + 1` })
          .where(eq(webhookEndpoints.webhookId, input.webhookId));

        return { success: false, status: 0, body: err.message };
      }
    }),

  // ─── Get delivery history ───
  deliveries: protectedProcedure
    .input(z.object({
      webhookId: z.string(),
      limit: z.number().min(1).max(100).default(20),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      return db.select().from(webhookDeliveries)
        .where(eq(webhookDeliveries.webhookId, input.webhookId))
        .orderBy(desc(webhookDeliveries.deliveredAt))
        .limit(input.limit);
    }),

  // ─── Available events ───
  availableEvents: protectedProcedure.query(() => {
    return WEBHOOK_EVENTS.map(event => ({
      event,
      category: event.split(".")[0],
      description: getEventDescription(event),
    }));
  }),

  // ─── Stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [totalCount] = await db.select({ count: sql<number>`count(*)` }).from(webhookEndpoints);
    const [activeCount] = await db.select({ count: sql<number>`count(*)` }).from(webhookEndpoints)
      .where(eq(webhookEndpoints.enabled, true));
    const [deliveryCount] = await db.select({ count: sql<number>`count(*)` }).from(webhookDeliveries);
    const [failedCount] = await db.select({ count: sql<number>`count(*)` }).from(webhookDeliveries)
      .where(eq(webhookDeliveries.success, false));

    return {
      totalWebhooks: Number(totalCount?.count ?? 0),
      activeWebhooks: Number(activeCount?.count ?? 0),
      totalDeliveries: Number(deliveryCount?.count ?? 0),
      failedDeliveries: Number(failedCount?.count ?? 0),
    };
  }),
});

function getEventDescription(event: string): string {
  const descriptions: Record<string, string> = {
    "scan.completed": "Fired when a domain intelligence scan completes successfully",
    "scan.failed": "Fired when a domain intelligence scan fails",
    "finding.critical": "Fired when a critical severity finding is discovered",
    "finding.high": "Fired when a high severity finding is discovered",
    "engagement.created": "Fired when a new engagement is created",
    "engagement.completed": "Fired when an engagement is marked as completed",
    "playbook.launched": "Fired when an emulation playbook is launched",
    "playbook.completed": "Fired when a playbook execution completes",
    "evidence.created": "Fired when new evidence is collected",
    "detection.gap_found": "Fired when a detection gap is identified",
    "alert.new": "Fired when a new security alert is generated",
  };
  return descriptions[event] || "No description available";
}
