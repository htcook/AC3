import * as db from "../db";
/**
 * SIEM Connectors Router
 * ──────────────────────
 * tRPC endpoints for managing SIEM connections (Wazuh/Elastic),
 * fetching alerts, and correlating detections with campaign techniques.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { eq, desc, sql } from "drizzle-orm";
import { siemConnections } from "../../drizzle/schema";
import {
  testSiemConnection,
  fetchSiemAlerts,
  correlateDetections,
  computeDetectionStats,
  summarizeAlerts,
  type SiemConnectionConfig,
  type SiemAlertQuery,
  type NormalizedSiemAlert,
} from "../lib/siem-connectors";

async function getDbSafe() {
  const db = await _getDb();
  if (!db)
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Database unavailable",
    });
  return db;
}

const siemBackendSchema = z.enum(["wazuh", "elastic"]);

const connectionConfigSchema = z.object({
  backend: siemBackendSchema,
  baseUrl: z.string().url(),
  username: z.string().optional(),
  password: z.string().optional(),
  apiKey: z.string().optional(),
  insecure: z.boolean().optional(),
  timeout: z.number().min(1000).max(60000).optional(),
  wazuhAlertIndex: z.string().optional(),
  elasticIndex: z.string().optional(),
  useSecurityDetections: z.boolean().optional(),
});

export const siemConnectorsRouter = router({
  // ═══════════════════════════════════════════════════════════════════
  // CONNECTION MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════

  /** Save a SIEM connection configuration */
  saveConnection: protectedProcedure
    .input(
      z.object({
        name: z.string().min(1).max(255),
        config: connectionConfigSchema,
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      // Test connectivity first
      const status = await testSiemConnection(input.config as SiemConnectionConfig);

      const [result] = await db.insert(siemConnections).values({
        name: input.name,
        backend: input.config.backend,
        baseUrl: input.config.baseUrl,
        username: input.config.username,
        password: input.config.password,
        apiKey: input.config.apiKey,
        insecure: input.config.insecure ?? false,
        timeoutMs: input.config.timeout ?? 15000,
        indexPattern: input.config.elasticIndex || input.config.wazuhAlertIndex,
        useSecurityDetections: input.config.useSecurityDetections ?? false,
        connected: status.connected,
        lastTestedAt: new Date(),
        version: status.version,
        clusterName: status.clusterName,
        alertCount: status.alertCount,
        errorMessage: status.error,
        createdBy: ctx.user.id,
      });

      return {
        id: Number(result.insertId),
        connected: status.connected,
        status,
      };
    }),

  /** List saved SIEM connections */
  listConnections: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const connections = await db
      .select({
        id: siemConnections.id,
        name: siemConnections.name,
        backend: siemConnections.backend,
        baseUrl: siemConnections.baseUrl,
        connected: siemConnections.connected,
        version: siemConnections.version,
        clusterName: siemConnections.clusterName,
        alertCount: siemConnections.alertCount,
        lastTestedAt: siemConnections.lastTestedAt,
        errorMessage: siemConnections.errorMessage,
        enabled: siemConnections.enabled,
        createdAt: siemConnections.createdAt,
      })
      .from(siemConnections)
      .orderBy(desc(siemConnections.createdAt));

    return connections;
  }),

  /** Test connectivity to a saved connection */
  testConnection: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [conn] = await db
        .select()
        .from(siemConnections)
        .where(eq(siemConnections.id, input.id))
        .limit(1);

      if (!conn) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });
      }

      const config: SiemConnectionConfig = {
        backend: conn.backend as any,
        baseUrl: conn.baseUrl,
        username: conn.username || undefined,
        password: conn.password || undefined,
        apiKey: conn.apiKey || undefined,
        insecure: conn.insecure ?? false,
        timeout: conn.timeoutMs ?? 15000,
        elasticIndex: conn.indexPattern || undefined,
        wazuhAlertIndex: conn.indexPattern || undefined,
        useSecurityDetections: conn.useSecurityDetections ?? false,
      };

      const status = await testSiemConnection(config);

      // Update connection status
      await db
        .update(siemConnections)
        .set({
          connected: status.connected,
          lastTestedAt: new Date(),
          version: status.version,
          clusterName: status.clusterName,
          alertCount: status.alertCount,
          errorMessage: status.error || null,
        })
        .where(eq(siemConnections.id, input.id));

      return status;
    }),

  /** Toggle connection enabled/disabled */
  toggleConnection: protectedProcedure
    .input(z.object({ id: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db
        .update(siemConnections)
        .set({ enabled: input.enabled })
        .where(eq(siemConnections.id, input.id));
      return { success: true };
    }),

  /** Delete a connection */
  deleteConnection: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(siemConnections).where(eq(siemConnections.id, input.id));
      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════
  // ALERT QUERIES
  // ═══════════════════════════════════════════════════════════════════

  /** Fetch alerts from a specific connection */
  fetchAlerts: protectedProcedure
    .input(
      z.object({
        connectionId: z.number(),
        from: z.number().optional(),
        to: z.number().optional(),
        techniques: z.array(z.string()).optional(),
        minSeverity: z.enum(["low", "medium", "high", "critical"]).optional(),
        agentName: z.string().optional(),
        query: z.string().optional(),
        limit: z.number().min(1).max(500).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [conn] = await db
        .select()
        .from(siemConnections)
        .where(eq(siemConnections.id, input.connectionId))
        .limit(1);

      if (!conn) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });
      }

      const config: SiemConnectionConfig = {
        backend: conn.backend as any,
        baseUrl: conn.baseUrl,
        username: conn.username || undefined,
        password: conn.password || undefined,
        apiKey: conn.apiKey || undefined,
        insecure: conn.insecure ?? false,
        timeout: conn.timeoutMs ?? 15000,
        elasticIndex: conn.indexPattern || undefined,
        wazuhAlertIndex: conn.indexPattern || undefined,
        useSecurityDetections: conn.useSecurityDetections ?? false,
      };

      const alertQuery: SiemAlertQuery = {
        from: input.from,
        to: input.to,
        techniques: input.techniques,
        minSeverity: input.minSeverity,
        agentName: input.agentName,
        query: input.query,
        limit: input.limit,
        offset: input.offset,
      };

      return fetchSiemAlerts(config, alertQuery);
    }),

  /** Fetch alerts from ALL enabled connections */
  fetchAllAlerts: protectedProcedure
    .input(
      z.object({
        from: z.number().optional(),
        to: z.number().optional(),
        techniques: z.array(z.string()).optional(),
        minSeverity: z.enum(["low", "medium", "high", "critical"]).optional(),
        limit: z.number().min(1).max(500).default(100),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const connections = await db
        .select()
        .from(siemConnections)
        .where(eq(siemConnections.enabled, true));

      if (connections.length === 0) {
        return {
          alerts: [] as NormalizedSiemAlert[],
          total: 0,
          backends: [] as string[],
          errors: ["No enabled SIEM connections found"],
        };
      }

      const allAlerts: NormalizedSiemAlert[] = [];
      const allErrors: string[] = [];
      const backends: string[] = [];

      for (const conn of connections) {
        const config: SiemConnectionConfig = {
          backend: conn.backend as any,
          baseUrl: conn.baseUrl,
          username: conn.username || undefined,
          password: conn.password || undefined,
          apiKey: conn.apiKey || undefined,
          insecure: conn.insecure ?? false,
          timeout: conn.timeoutMs ?? 15000,
          elasticIndex: conn.indexPattern || undefined,
          wazuhAlertIndex: conn.indexPattern || undefined,
          useSecurityDetections: conn.useSecurityDetections ?? false,
        };

        const result = await fetchSiemAlerts(config, {
          from: input.from,
          to: input.to,
          techniques: input.techniques,
          minSeverity: input.minSeverity,
          limit: input.limit,
        });

        allAlerts.push(...result.alerts);
        allErrors.push(...result.errors);
        backends.push(conn.backend);
      }

      // Sort by timestamp descending
      allAlerts.sort((a, b) => b.timestamp - a.timestamp);

      return {
        alerts: allAlerts.slice(0, input.limit),
        total: allAlerts.length,
        backends: Array.from(new Set(backends)),
        errors: allErrors,
      };
    }),

  // ═══════════════════════════════════════════════════════════════════
  // DETECTION CORRELATION
  // ═══════════════════════════════════════════════════════════════════

  /** Correlate campaign techniques with SIEM alerts */
  correlateWithCampaign: protectedProcedure
    .input(
      z.object({
        techniques: z.array(z.string()).min(1),
        connectionId: z.number().optional(),
        from: z.number().optional(),
        to: z.number().optional(),
        campaignStartTime: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      // Get alerts from specified connection or all enabled connections
      let alerts: NormalizedSiemAlert[] = [];

      if (input.connectionId) {
        const [conn] = await db
          .select()
          .from(siemConnections)
          .where(eq(siemConnections.id, input.connectionId))
          .limit(1);

        if (!conn) {
          throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });
        }

        const config: SiemConnectionConfig = {
          backend: conn.backend as any,
          baseUrl: conn.baseUrl,
          username: conn.username || undefined,
          password: conn.password || undefined,
          apiKey: conn.apiKey || undefined,
          insecure: conn.insecure ?? false,
          timeout: conn.timeoutMs ?? 15000,
          elasticIndex: conn.indexPattern || undefined,
          wazuhAlertIndex: conn.indexPattern || undefined,
          useSecurityDetections: conn.useSecurityDetections ?? false,
        };

        const result = await fetchSiemAlerts(config, {
          from: input.from,
          to: input.to,
          techniques: input.techniques,
          limit: 500,
        });
        alerts = result.alerts;
      } else {
        // Fetch from all enabled connections
        const connections = await db
          .select()
          .from(siemConnections)
          .where(eq(siemConnections.enabled, true));

        for (const conn of connections) {
          const config: SiemConnectionConfig = {
            backend: conn.backend as any,
            baseUrl: conn.baseUrl,
            username: conn.username || undefined,
            password: conn.password || undefined,
            apiKey: conn.apiKey || undefined,
            insecure: conn.insecure ?? false,
            timeout: conn.timeoutMs ?? 15000,
            elasticIndex: conn.indexPattern || undefined,
            wazuhAlertIndex: conn.indexPattern || undefined,
            useSecurityDetections: conn.useSecurityDetections ?? false,
          };

          const result = await fetchSiemAlerts(config, {
            from: input.from,
            to: input.to,
            techniques: input.techniques,
            limit: 500,
          });
          alerts.push(...result.alerts);
        }
      }

      // Run correlation
      const correlations = correlateDetections(
        input.techniques,
        alerts,
        input.campaignStartTime
      );

      const stats = computeDetectionStats(correlations);
      const alertSummary = summarizeAlerts(alerts);

      return {
        correlations,
        stats,
        alertSummary,
        totalAlerts: alerts.length,
      };
    }),

  /** Get alert summary statistics */
  getAlertSummary: protectedProcedure
    .input(
      z.object({
        connectionId: z.number(),
        from: z.number().optional(),
        to: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [conn] = await db
        .select()
        .from(siemConnections)
        .where(eq(siemConnections.id, input.connectionId))
        .limit(1);

      if (!conn) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });
      }

      const config: SiemConnectionConfig = {
        backend: conn.backend as any,
        baseUrl: conn.baseUrl,
        username: conn.username || undefined,
        password: conn.password || undefined,
        apiKey: conn.apiKey || undefined,
        insecure: conn.insecure ?? false,
        timeout: conn.timeoutMs ?? 15000,
        elasticIndex: conn.indexPattern || undefined,
        wazuhAlertIndex: conn.indexPattern || undefined,
        useSecurityDetections: conn.useSecurityDetections ?? false,
      };

      const result = await fetchSiemAlerts(config, {
        from: input.from,
        to: input.to,
        limit: 200,
      });

      return summarizeAlerts(result.alerts);
    }),
});
