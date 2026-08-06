/**
 * Webhook Management Router — tRPC API for Webhook Integration Triggers
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Full CRUD for webhook endpoints, event history, replay, and analytics.
 * Mounted alongside the integration-registry router.
 */

import { z } from "zod";
import crypto from "crypto";
import { router, protectedProcedure } from "../_core/trpc";
import { getDb } from "../db";
import { webhookEndpoints, webhookEvents } from "../../drizzle/schema";
import { eq, and, desc, gte, sql, like } from "drizzle-orm";

// ═══════════════════════════════════════════════════════════════════════
// Zod schemas
// ═══════════════════════════════════════════════════════════════════════

const categoryEnum = z.enum([
  "osint", "exploit_db", "threat_intel", "scanner", "pentest_tool",
  "phishing", "c2", "siem_soar", "cloud", "credential", "custom",
]);

const stageEnum = z.enum([
  "recon", "passive_discovery", "enumeration", "vuln_detection",
  "exploitation", "post_exploit", "reporting", "threat_intel",
  "monitoring", "c2_ops",
]);

const signatureAlgorithmEnum = z.enum(["hmac_sha256", "hmac_sha1", "hmac_sha512", "none"]);
const payloadFormatEnum = z.enum(["json", "form", "xml", "raw"]);
const endpointStatusEnum = z.enum(["active", "paused", "disabled", "error"]);

// ═══════════════════════════════════════════════════════════════════════
// Router
// ═══════════════════════════════════════════════════════════════════════

export const webhookManagementRouter = router({

  // ─── CRUD: List Endpoints ───────────────────────────────────────────

  /** List all webhook endpoints with optional filtering */
  listEndpoints: protectedProcedure
    .input(z.object({
      status: endpointStatusEnum.optional(),
      category: categoryEnum.optional(),
      limit: z.number().min(1).max(100).default(50),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions: any[] = [];

      if (input?.status) {
        conditions.push(sql`status = ${input.status}`);
      }
      if (input?.category) {
        conditions.push(sql`data_category = ${input.category}`);
      }

      let query = db.select().from(webhookEndpoints);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }

      const endpoints = await (query as any).limit(input?.limit || 50);
      return endpoints.map((ep: any) => ({
        id: ep.id,
        endpointId: ep.endpointId || ep.webhookId,
        integrationId: ep.integrationId,
        name: ep.name,
        description: ep.description,
        status: ep.status || 'active',
        signatureAlgorithm: ep.signatureAlgorithm || 'hmac_sha256',
        signatureHeader: ep.signatureHeader || 'x-webhook-signature',
        eventTypes: ep.eventTypes,
        targetPipelineStages: ep.targetPipelineStages || [],
        dataCategory: ep.dataCategory || 'custom',
        payloadFormat: ep.payloadFormat || 'json',
        rateLimitPerMinute: ep.rateLimitPerMinute || 60,
        rateLimitPerHour: ep.rateLimitPerHour || 1000,
        totalEventsReceived: ep.totalEventsReceived || 0,
        totalEventsProcessed: ep.totalEventsProcessed || 0,
        totalEventsFailed: ep.totalEventsFailed || 0,
        lastEventAt: ep.lastEventAt,
        lastErrorAt: ep.lastErrorAt,
        lastError: ep.lastError,
        createdAt: ep.createdAt,
        updatedAt: ep.updatedAt,
        // Generate the webhook URL for the customer
        webhookUrl: `/api/webhooks/${ep.endpointId || ep.webhookId}`,
      }));
    }),

  // ─── CRUD: Get Single Endpoint ──────────────────────────────────────

  getEndpoint: protectedProcedure
    .input(z.object({ endpointId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [endpoint] = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.endpointId, input.endpointId))
        .limit(1);

      if (!endpoint) return null;

      return {
        ...(endpoint as any),
        webhookUrl: `/api/webhooks/${input.endpointId}`,
        hasSecret: !!(endpoint as any).secret,
      };
    }),

  // ─── CRUD: Create Endpoint ──────────────────────────────────────────

  createEndpoint: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      integrationId: z.string().optional(),
      signatureAlgorithm: signatureAlgorithmEnum.default("hmac_sha256"),
      signatureHeader: z.string().default("x-webhook-signature"),
      eventTypes: z.array(z.string()).optional(),
      targetPipelineStages: z.array(stageEnum).min(1),
      dataCategory: categoryEnum.default("custom"),
      payloadFormat: payloadFormatEnum.default("json"),
      transformTemplate: z.string().optional(),
      rateLimitPerMinute: z.number().min(1).max(10000).default(60),
      rateLimitPerHour: z.number().min(1).max(100000).default(1000),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const endpointId = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const secret = crypto.randomBytes(32).toString('hex');
      const now = Date.now();

      await db.insert(webhookEndpoints).values({
        endpointId,
        name: input.name,
        description: input.description || null,
        integrationId: input.integrationId || null,
        secret,
        signatureHeader: input.signatureHeader,
        signatureAlgorithm: input.signatureAlgorithm,
        status: 'active',
        eventTypes: input.eventTypes || null,
        targetPipelineStages: input.targetPipelineStages,
        dataCategory: input.dataCategory,
        payloadFormat: input.payloadFormat,
        transformTemplate: input.transformTemplate || null,
        rateLimitPerMinute: input.rateLimitPerMinute,
        rateLimitPerHour: input.rateLimitPerHour,
        totalEventsReceived: 0,
        totalEventsProcessed: 0,
        totalEventsFailed: 0,
        createdBy: ctx.user?.id?.toString() || null,
        tenantId: null,
        createdAt: now,
        updatedAt: now,
        // Legacy fields (required by original schema)
        url: `/api/webhooks/${endpointId}`,
      } as any);

      return {
        endpointId,
        secret,
        webhookUrl: `/api/webhooks/${endpointId}`,
        signatureHeader: input.signatureHeader,
        signatureAlgorithm: input.signatureAlgorithm,
        message: 'Webhook endpoint created. Save the secret — it will not be shown again.',
      };
    }),

  // ─── CRUD: Update Endpoint ──────────────────────────────────────────

  updateEndpoint: protectedProcedure
    .input(z.object({
      endpointId: z.string(),
      name: z.string().min(1).max(255).optional(),
      description: z.string().optional(),
      status: endpointStatusEnum.optional(),
      eventTypes: z.array(z.string()).optional(),
      targetPipelineStages: z.array(stageEnum).optional(),
      dataCategory: categoryEnum.optional(),
      payloadFormat: payloadFormatEnum.optional(),
      transformTemplate: z.string().nullable().optional(),
      rateLimitPerMinute: z.number().min(1).max(10000).optional(),
      rateLimitPerHour: z.number().min(1).max(100000).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const { endpointId, ...updates } = input;

      const setClause: Record<string, any> = { updatedAt: Date.now() };
      if (updates.name !== undefined) setClause.name = updates.name;
      if (updates.description !== undefined) setClause.description = updates.description;
      if (updates.status !== undefined) setClause.status = updates.status;
      if (updates.eventTypes !== undefined) setClause.eventTypes = updates.eventTypes;
      if (updates.targetPipelineStages !== undefined) setClause.targetPipelineStages = updates.targetPipelineStages;
      if (updates.dataCategory !== undefined) setClause.dataCategory = updates.dataCategory;
      if (updates.payloadFormat !== undefined) setClause.payloadFormat = updates.payloadFormat;
      if (updates.transformTemplate !== undefined) setClause.transformTemplate = updates.transformTemplate;
      if (updates.rateLimitPerMinute !== undefined) setClause.rateLimitPerMinute = updates.rateLimitPerMinute;
      if (updates.rateLimitPerHour !== undefined) setClause.rateLimitPerHour = updates.rateLimitPerHour;

      await db
        .update(webhookEndpoints)
        .set(setClause as any)
        .where(eq(webhookEndpoints.endpointId, endpointId));

      return { success: true, endpointId };
    }),

  // ─── CRUD: Delete Endpoint ──────────────────────────────────────────

  deleteEndpoint: protectedProcedure
    .input(z.object({ endpointId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();

      // Delete associated events first
      await db
        .delete(webhookEvents)
        .where(eq(webhookEvents.endpointId, input.endpointId));

      // Delete the endpoint
      await db
        .delete(webhookEndpoints)
        .where(eq(webhookEndpoints.endpointId, input.endpointId));

      return { success: true, deleted: input.endpointId };
    }),

  // ─── Secret Rotation ────────────────────────────────────────────────

  /** Rotate the signing secret for an endpoint */
  rotateSecret: protectedProcedure
    .input(z.object({ endpointId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const newSecret = crypto.randomBytes(32).toString('hex');

      await db
        .update(webhookEndpoints)
        .set({ secret: newSecret, updatedAt: Date.now() } as any)
        .where(eq(webhookEndpoints.endpointId, input.endpointId));

      return {
        endpointId: input.endpointId,
        newSecret,
        message: 'Secret rotated. Update your webhook sender with the new secret. The old secret is now invalid.',
      };
    }),

  // ─── Event History ──────────────────────────────────────────────────

  /** Get recent events for an endpoint */
  getEvents: protectedProcedure
    .input(z.object({
      endpointId: z.string().optional(),
      status: z.enum(["received", "processing", "processed", "failed", "skipped", "replayed"]).optional(),
      hoursBack: z.number().min(1).max(720).default(24),
      limit: z.number().min(1).max(200).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      const since = Date.now() - input.hoursBack * 3_600_000;
      const conditions: any[] = [gte(webhookEvents.receivedAt, since)];

      if (input.endpointId) {
        conditions.push(eq(webhookEvents.endpointId, input.endpointId));
      }
      if (input.status) {
        conditions.push(eq(webhookEvents.status, input.status));
      }

      const events = await db
        .select()
        .from(webhookEvents)
        .where(and(...conditions))
        .orderBy(desc(webhookEvents.receivedAt))
        .limit(input.limit);

      return events.map((e: any) => ({
        id: e.id,
        eventId: e.eventId,
        endpointId: e.endpointId,
        eventType: e.eventType,
        status: e.status,
        sourceIp: e.sourceIp,
        processingDurationMs: e.processingDurationMs,
        routedToStage: e.routedToStage,
        error: e.error,
        resultSummary: e.resultSummary,
        retryCount: e.retryCount,
        receivedAt: e.receivedAt,
        // Don't expose raw payload in list view
        payloadPreview: e.rawPayload?.slice(0, 200),
      }));
    }),

  /** Get full event detail including raw payload */
  getEventDetail: protectedProcedure
    .input(z.object({ eventId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [event] = await db
        .select()
        .from(webhookEvents)
        .where(eq(webhookEvents.eventId, input.eventId))
        .limit(1);

      return event || null;
    }),

  // ─── Replay & Retry ────────────────────────────────────────────────

  /** Replay a specific event */
  replayEvent: protectedProcedure
    .input(z.object({ eventId: z.string() }))
    .mutation(async ({ input }) => {
      const { replayEvent } = await import("../lib/integration-registry/webhook-receiver");
      return replayEvent(input.eventId);
    }),

  /** Retry all failed events for an endpoint */
  retryFailed: protectedProcedure
    .input(z.object({ endpointId: z.string().optional() }))
    .mutation(async ({ input }) => {
      const { retryFailedEvents } = await import("../lib/integration-registry/webhook-receiver");
      return retryFailedEvents(input.endpointId);
    }),

  // ─── Analytics ──────────────────────────────────────────────────────

  /** Get webhook analytics/stats */
  getStats: protectedProcedure
    .input(z.object({
      endpointId: z.string().optional(),
      hoursBack: z.number().min(1).max(720).default(24),
    }).optional())
    .query(async ({ input }) => {
      const { getWebhookStats } = await import("../lib/integration-registry/webhook-receiver");
      return getWebhookStats(input?.endpointId, input?.hoursBack || 24);
    }),

  /** Get aggregated stats across all endpoints */
  getDashboardStats: protectedProcedure
    .query(async () => {
      const db = await getDb();

      // Total endpoints by status
      const endpointStats = await db
        .select({
          status: sql<string>`COALESCE(status, 'active')`,
          count: sql<number>`COUNT(*)`,
        })
        .from(webhookEndpoints)
        .groupBy(sql`COALESCE(status, 'active')`);

      // Events in last 24h
      const since24h = Date.now() - 24 * 3_600_000;
      const eventStats = await db
        .select({
          status: webhookEvents.status,
          count: sql<number>`COUNT(*)`,
          avgDuration: sql<number>`AVG(${webhookEvents.processingDurationMs})`,
        })
        .from(webhookEvents)
        .where(gte(webhookEvents.receivedAt, since24h))
        .groupBy(webhookEvents.status);

      // Top endpoints by volume (last 24h)
      const topEndpoints = await db
        .select({
          endpointId: webhookEvents.endpointId,
          count: sql<number>`COUNT(*)`,
        })
        .from(webhookEvents)
        .where(gte(webhookEvents.receivedAt, since24h))
        .groupBy(webhookEvents.endpointId)
        .orderBy(desc(sql`COUNT(*)`))
        .limit(10);

      return {
        endpoints: {
          total: endpointStats.reduce((sum, s) => sum + Number(s.count), 0),
          byStatus: endpointStats,
        },
        events24h: {
          total: eventStats.reduce((sum, s) => sum + Number(s.count), 0),
          byStatus: eventStats,
          avgProcessingMs: eventStats.find(s => s.status === 'processed')?.avgDuration || 0,
        },
        topEndpoints,
      };
    }),

  // ─── Test Webhook ───────────────────────────────────────────────────

  /** Send a test event to a webhook endpoint */
  sendTestEvent: protectedProcedure
    .input(z.object({
      endpointId: z.string(),
      payload: z.string().default('{"test": true, "event": "test_event", "timestamp": 0}'),
    }))
    .mutation(async ({ input }) => {
      const { receiveWebhook } = await import("../lib/integration-registry/webhook-receiver");

      // For test events, bypass signature validation by using the endpoint's own secret
      const db = await getDb();
      const [endpoint] = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.endpointId, input.endpointId))
        .limit(1);

      if (!endpoint) {
        return { success: false, message: 'Endpoint not found' };
      }

      // Generate valid signature for the test payload
      const sigAlgorithm = (endpoint as any).signatureAlgorithm || 'hmac_sha256';
      const sigHeader = ((endpoint as any).signatureHeader || 'x-webhook-signature').toLowerCase();
      let signature = '';

      if (sigAlgorithm !== 'none' && endpoint.secret) {
        const algoMap: Record<string, string> = { hmac_sha256: 'sha256', hmac_sha1: 'sha1', hmac_sha512: 'sha512' };
        const hmac = (await import('crypto')).createHmac(algoMap[sigAlgorithm] || 'sha256', endpoint.secret);
        hmac.update(input.payload, 'utf8');
        signature = hmac.digest('hex');
      }

      const testPayload = input.payload.replace('"timestamp": 0', `"timestamp": ${Date.now()}`);

      return receiveWebhook({
        endpointId: input.endpointId,
        eventId: `test_${Date.now()}`,
        eventType: 'test_event',
        rawPayload: testPayload,
        headers: {
          'content-type': 'application/json',
          [sigHeader]: signature,
          'x-event-type': 'test_event',
          'x-test-event': 'true',
        },
        sourceIp: '127.0.0.1',
        receivedAt: Date.now(),
      });
    }),
});
