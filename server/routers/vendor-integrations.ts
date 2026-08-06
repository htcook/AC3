import * as db from "../db";
/**
 * Vendor Integrations tRPC Router
 * CRUD for vendor configs, health checks, data sync, and querying cached data.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, adminProcedure, router } from "../_core/trpc";
import {
  listIntegrations,
  getIntegration,
  upsertIntegration,
  deleteIntegration,
  getClientForIntegration,
  healthCheckAll,
  updateIntegrationStatus,
  logSyncEvent,
  cacheVendorData,
  queryCachedData,
  VENDOR_METADATA,
  VendorName,
  CrowdStrikeClient,
  SentinelOneClient,
  DefenderClient,
  SplunkClient,
  XSOARClient,
} from "../lib/vendors";

const vendorEnum = z.enum(["crowdstrike", "sentinelone", "defender", "splunk", "xsoar", "sentinel", "cortex_xdr"]);

export const vendorIntegrationsRouter = router({
  // ─── List all vendor metadata (no auth needed for display) ─────────────────
  vendorCatalog: protectedProcedure.query(() => {
    return Object.entries(VENDOR_METADATA).map(([key, meta]) => ({
      vendor: key as VendorName,
      ...meta,
    }));
  }),

  // ─── List configured integrations ──────────────────────────────────────────
  list: protectedProcedure.query(async () => {
    const integrations = await listIntegrations();
    return integrations.map((i) => ({
      id: i.id,
      vendor: i.vendor,
      displayName: i.displayName,
      enabled: i.enabled,
      status: i.status,
      lastHealthCheck: i.lastHealthCheck,
      lastError: i.lastError,
      syncEnabled: i.syncEnabled,
      syncIntervalMinutes: i.syncIntervalMinutes,
      lastSyncAt: i.lastSyncAt,
      createdAt: i.createdAt,
      // Don't expose auth secrets
      hasAuthConfig: !!i.authConfig && Object.keys(i.authConfig as object).length > 0,
      connectionConfig: i.connectionConfig,
    }));
  }),

  // ─── Get single integration detail ─────────────────────────────────────────
  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const integration = await getIntegration(input.id);
      if (!integration) throw new TRPCError({ code: "NOT_FOUND", message: "Integration not found" });
      return {
        ...integration,
        // Mask auth secrets
        authConfig: maskAuthConfig(integration.authConfig as Record<string, string> | null),
      };
    }),

  // ─── Create or update integration ──────────────────────────────────────────
  upsert: adminProcedure
    .input(z.object({
      vendor: vendorEnum,
      displayName: z.string().min(1).max(255),
      authConfig: z.record(z.string(), z.string()),
      connectionConfig: z.object({
        baseUrl: z.string().min(1),
        timeout: z.number().optional(),
        verifySsl: z.boolean().optional(),
      }),
      enabled: z.boolean().optional(),
      syncEnabled: z.boolean().optional(),
      syncIntervalMinutes: z.number().min(5).max(1440).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const id = await upsertIntegration({
        vendor: input.vendor,
        displayName: input.displayName,
        authConfig: input.authConfig,
        connectionConfig: input.connectionConfig,
        enabled: input.enabled,
        syncEnabled: input.syncEnabled,
        syncIntervalMinutes: input.syncIntervalMinutes,
        createdBy: ctx.user.openId,
      });
      return { id, message: `${input.displayName} integration saved` };
    }),

  // ─── Delete integration ────────────────────────────────────────────────────
  delete: adminProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await deleteIntegration(input.id);
      return { success: true };
    }),

  // ─── Toggle enabled ────────────────────────────────────────────────────────
  toggleEnabled: adminProcedure
    .input(z.object({ id: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const integration = await getIntegration(input.id);
      if (!integration) throw new TRPCError({ code: "NOT_FOUND" });

      const { getDb } = await import("../db");
      const { vendorIntegrations } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "DB unavailable" });

      await db.update(vendorIntegrations)
        .set({ enabled: input.enabled })
        .where(eq(vendorIntegrations.id, input.id));

      return { success: true, enabled: input.enabled };
    }),

  // ─── Health check single integration ───────────────────────────────────────
  healthCheck: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const client = await getClientForIntegration(input.id);
      const result = await client.healthCheck();
      await updateIntegrationStatus(
        input.id,
        result.status,
        result.status === "error" ? result.message : undefined
      );
      return result;
    }),

  // ─── Health check all integrations ─────────────────────────────────────────
  healthCheckAll: protectedProcedure.mutation(async () => {
    return healthCheckAll();
  }),

  // ─── Sync data from vendor ─────────────────────────────────────────────────
  syncData: protectedProcedure
    .input(z.object({
      id: z.number(),
      dataTypes: z.array(z.enum([
        "hosts", "detections", "incidents", "alerts", "threats",
        "vulnerabilities", "indicators", "notable_events",
      ])),
    }))
    .mutation(async ({ input, ctx }) => {
      const integration = await getIntegration(input.id);
      if (!integration) throw new TRPCError({ code: "NOT_FOUND" });

      const client = await getClientForIntegration(input.id);
      const results: Array<{ type: string; count: number; status: string }> = [];
      const startTime = Date.now();

      for (const dataType of input.dataTypes) {
        try {
          let data: any[] = [];

          switch (integration.vendor) {
            case "crowdstrike": {
              const cs = client as CrowdStrikeClient;
              if (dataType === "hosts") data = await cs.queryHosts({ limit: 500 });
              else if (dataType === "detections") data = await cs.queryDetections({ limit: 500 });
              else if (dataType === "incidents") data = await cs.queryIncidents({ limit: 500 });
              else if (dataType === "indicators") data = await cs.queryIOCs({ limit: 500 });
              break;
            }
            case "sentinelone": {
              const s1 = client as SentinelOneClient;
              if (dataType === "hosts") data = await s1.queryAgents({ limit: 500 });
              else if (dataType === "threats") data = await s1.queryThreats({ limit: 500 });
              else if (dataType === "alerts") data = await s1.queryActivities({ limit: 500 });
              break;
            }
            case "defender": {
              const mde = client as DefenderClient;
              if (dataType === "hosts") data = await mde.queryMachines({ limit: 500 });
              else if (dataType === "alerts") data = await mde.queryAlerts({ limit: 500 });
              else if (dataType === "vulnerabilities") data = await mde.queryVulnerabilities({ limit: 500 });
              break;
            }
            case "splunk": {
              const sp = client as SplunkClient;
              if (dataType === "notable_events") data = await sp.queryNotableEvents({ limit: 500 });
              break;
            }
            case "xsoar": {
              const xsoar = client as XSOARClient;
              if (dataType === "incidents") data = await xsoar.queryIncidents({ limit: 500 });
              else if (dataType === "indicators") data = await xsoar.queryIndicators({ limit: 500 });
              break;
            }
          }

          if (data.length > 0) {
            await cacheVendorData(input.id, data);
          }

          results.push({ type: dataType, count: data.length, status: "success" });

          await logSyncEvent({
            integrationId: input.id,
            eventType: `${dataType}_sync`,
            status: "success",
            recordsProcessed: data.length,
            durationMs: Date.now() - startTime,
            triggeredBy: ctx.user.openId,
          });
        } catch (error) {
          results.push({ type: dataType, count: 0, status: `error: ${(error as Error).message}` });

          await logSyncEvent({
            integrationId: input.id,
            eventType: `${dataType}_sync`,
            status: "failed",
            errorMessage: (error as Error).message,
            durationMs: Date.now() - startTime,
            triggeredBy: ctx.user.openId,
          });
        }
      }

      return { results, totalDurationMs: Date.now() - startTime };
    }),

  // ─── Query cached vendor data ──────────────────────────────────────────────
  queryCachedData: protectedProcedure
    .input(z.object({
      integrationId: z.number().optional(),
      dataType: z.string().optional(),
      hostname: z.string().optional(),
      ipAddress: z.string().optional(),
      severity: z.string().optional(),
      limit: z.number().min(1).max(500).optional(),
    }))
    .query(async ({ input }) => {
      return queryCachedData(input);
    }),

  // ─── Run ad-hoc query against vendor ───────────────────────────────────────
  runQuery: protectedProcedure
    .input(z.object({
      id: z.number(),
      queryType: z.enum(["search", "hunt", "lookup"]),
      query: z.string().min(1).max(5000),
      limit: z.number().min(1).max(1000).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const integration = await getIntegration(input.id);
      if (!integration) throw new TRPCError({ code: "NOT_FOUND" });

      const client = await getClientForIntegration(input.id);
      const startTime = Date.now();

      try {
        let results: any[] = [];

        switch (integration.vendor) {
          case "splunk": {
            const sp = client as SplunkClient;
            results = await sp.search(input.query, { limit: input.limit ?? 100 });
            break;
          }
          case "defender": {
            const mde = client as DefenderClient;
            results = await mde.advancedHunting(input.query);
            break;
          }
          default:
            throw new TRPCError({
              code: "BAD_REQUEST",
              message: `Ad-hoc queries not supported for ${integration.vendor}. Use sync instead.`,
            });
        }

        await logSyncEvent({
          integrationId: input.id,
          eventType: "manual_query",
          status: "success",
          recordsProcessed: results.length,
          summary: { query: input.query.slice(0, 200) },
          durationMs: Date.now() - startTime,
          triggeredBy: ctx.user.openId,
        });

        return { results, count: results.length, durationMs: Date.now() - startTime };
      } catch (error) {
        if (error instanceof TRPCError) throw error;

        await logSyncEvent({
          integrationId: input.id,
          eventType: "manual_query",
          status: "failed",
          errorMessage: (error as Error).message,
          durationMs: Date.now() - startTime,
          triggeredBy: ctx.user.openId,
        });

        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: (error as Error).message,
        });
      }
    }),

  // ─── Bridge to EDR Validation ──────────────────────────────────────────────
  bridgeEDR: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { bridgeEDRDetections } = await import("../lib/vendors/vendor-bridge");
      return bridgeEDRDetections(input.id);
    }),

  // ─── Bridge to SIEM Feedback ──────────────────────────────────────────────
  bridgeSIEM: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { bridgeSIEMEvents } = await import("../lib/vendors/vendor-bridge");
      return bridgeSIEMEvents(input.id);
    }),

  // ─── Auto-bridge all enabled integrations ─────────────────────────────────
  bridgeAll: protectedProcedure.mutation(async () => {
    const { bridgeAll } = await import("../lib/vendors/vendor-bridge");
    return bridgeAll();
  }),

  // ─── Get bridged EDR detections for validation ────────────────────────────
  getBridgedEDRDetections: protectedProcedure
    .input(z.object({
      vendor: z.string().optional(),
      hostname: z.string().optional(),
      techniqueId: z.string().optional(),
      sinceDays: z.number().min(1).max(90).optional(),
      limit: z.number().min(1).max(500).optional(),
    }))
    .query(async ({ input }) => {
      const { getEDRDetectionsForValidation } = await import("../lib/vendors/vendor-bridge");
      const since = input.sinceDays ? new Date(Date.now() - input.sinceDays * 86400000) : undefined;
      return getEDRDetectionsForValidation({
        vendor: input.vendor,
        hostname: input.hostname,
        techniqueId: input.techniqueId,
        since,
        limit: input.limit,
      });
    }),

  // ─── Get bridged SIEM events for feedback ─────────────────────────────────
  getBridgedSIEMEvents: protectedProcedure
    .input(z.object({
      vendor: z.string().optional(),
      techniqueId: z.string().optional(),
      sinceDays: z.number().min(1).max(90).optional(),
      limit: z.number().min(1).max(500).optional(),
    }))
    .query(async ({ input }) => {
      const { getSIEMEventsForFeedback } = await import("../lib/vendors/vendor-bridge");
      const since = input.sinceDays ? new Date(Date.now() - input.sinceDays * 86400000) : undefined;
      return getSIEMEventsForFeedback({
        vendor: input.vendor,
        techniqueId: input.techniqueId,
        since,
        limit: input.limit,
      });
    }),

  // ─── Get sync history ──────────────────────────────────────────────────────
  syncHistory: protectedProcedure
    .input(z.object({
      integrationId: z.number(),
      limit: z.number().min(1).max(100).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vendorSyncEvents } = await import("../../drizzle/schema");
      const { eq, desc } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) return [];

      return db.select()
        .from(vendorSyncEvents)
        .where(eq(vendorSyncEvents.integrationId, input.integrationId))
        .orderBy(desc(vendorSyncEvents.createdAt))
        .limit(input.limit ?? 20);
    }),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function maskAuthConfig(config: Record<string, string> | null): Record<string, string> | null {
  if (!config) return null;
  const masked: Record<string, string> = {};
  for (const [key, value] of Object.entries(config)) {
    if (typeof value === "string" && value.length > 4) {
      masked[key] = value.slice(0, 4) + "****" + value.slice(-2);
    } else {
      masked[key] = "****";
    }
  }
  return masked;
}
