/**
 * Commercial Scanner Connectors Router
 * CRUD, test connection, trigger scans, import results for FedRAMP/NIST/DoD scanners
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { scannerConnectors, scannerScans, scannerFindings, sonarqubeWebhooks } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { createConnector, getSupportedPlatforms, PLATFORM_METADATA } from "../lib/commercial-scanners/factory";
import type { CommercialScannerConfig } from "../lib/commercial-scanners/types";
import { randomUUID } from "crypto";

async function getDbSafe() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const commercialScannersRouter = router({
  // ─── Platform Metadata ─────────────────────────────────────────────
  listPlatforms: protectedProcedure.query(() => {
    const platforms = getSupportedPlatforms();
    return platforms.map(p => ({
      id: p,
      ...PLATFORM_METADATA[p],
    }));
  }),

  // ─── Connector CRUD ────────────────────────────────────────────────
  addConnector: protectedProcedure
    .input(z.object({
      platform: z.string(),
      name: z.string().min(1).max(255),
      baseUrl: z.string().url(),
      credentials: z.record(z.string()),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const connectorId = `sc_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
      const meta = PLATFORM_METADATA[input.platform];
      if (!meta) throw new TRPCError({ code: "BAD_REQUEST", message: `Unsupported platform: ${input.platform}` });

      const encryptedCreds = Buffer.from(JSON.stringify(input.credentials)).toString("base64");

      await db.insert(scannerConnectors).values({
        connectorId,
        platform: input.platform,
        name: input.name,
        baseUrl: input.baseUrl,
        credentials: encryptedCreds,
        enabled: 1,
        healthStatus: "unknown",
        scanTypes: JSON.stringify(meta.scanTypes),
        fedRampLevel: meta.fedRampLevel,
        createdBy: ctx.user.openId,
      });

      return { connectorId, name: input.name, platform: input.platform };
    }),

  listConnectors: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const connectors = await db.select({
      id: scannerConnectors.id,
      connectorId: scannerConnectors.connectorId,
      platform: scannerConnectors.platform,
      name: scannerConnectors.name,
      baseUrl: scannerConnectors.baseUrl,
      enabled: scannerConnectors.enabled,
      lastHealthCheck: scannerConnectors.lastHealthCheck,
      healthStatus: scannerConnectors.healthStatus,
      healthMessage: scannerConnectors.healthMessage,
      scanTypes: scannerConnectors.scanTypes,
      fedRampLevel: scannerConnectors.fedRampLevel,
      createdAt: scannerConnectors.createdAt,
    }).from(scannerConnectors).orderBy(desc(scannerConnectors.createdAt));

    return connectors.map(c => ({
      ...c,
      scanTypes: c.scanTypes ? JSON.parse(c.scanTypes) : [],
    }));
  }),

  getConnector: protectedProcedure
    .input(z.object({ connectorId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [connector] = await db.select().from(scannerConnectors)
        .where(eq(scannerConnectors.connectorId, input.connectorId));
      if (!connector) throw new TRPCError({ code: "NOT_FOUND", message: "Connector not found" });
      return {
        ...connector,
        credentials: undefined,
        scanTypes: connector.scanTypes ? JSON.parse(connector.scanTypes) : [],
      };
    }),

  removeConnector: protectedProcedure
    .input(z.object({ connectorId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(scannerConnectors).where(eq(scannerConnectors.connectorId, input.connectorId));
      return { success: true };
    }),

  toggleConnector: protectedProcedure
    .input(z.object({ connectorId: z.string(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(scannerConnectors)
        .set({ enabled: input.enabled ? 1 : 0 })
        .where(eq(scannerConnectors.connectorId, input.connectorId));
      return { success: true };
    }),

  // ─── Test Connection ───────────────────────────────────────────────
  testConnection: protectedProcedure
    .input(z.object({ connectorId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [connector] = await db.select().from(scannerConnectors)
        .where(eq(scannerConnectors.connectorId, input.connectorId));
      if (!connector) throw new TRPCError({ code: "NOT_FOUND", message: "Connector not found" });

      const credentials = JSON.parse(Buffer.from(connector.credentials, "base64").toString("utf-8"));
      const config: CommercialScannerConfig = {
        id: connector.connectorId,
        platform: connector.platform,
        name: connector.name,
        baseUrl: connector.baseUrl,
        credentials,
      };

      const scannerClient = createConnector(config);
      const health = await scannerClient.testConnection();

      await db.update(scannerConnectors).set({
        lastHealthCheck: sql`CURRENT_TIMESTAMP`,
        healthStatus: health.authenticated ? "healthy" : (health.reachable ? "auth_failed" : "unreachable"),
        healthMessage: health.error || (health.authenticated ? `Connected (v${health.apiVersion || "unknown"})` : "Authentication failed"),
      }).where(eq(scannerConnectors.connectorId, input.connectorId));

      return health;
    }),

  // ─── Trigger Scan ──────────────────────────────────────────────────
  triggerScan: protectedProcedure
    .input(z.object({
      connectorId: z.string(),
      scanType: z.string(),
      target: z.string().optional(),
      options: z.record(z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [connector] = await db.select().from(scannerConnectors)
        .where(eq(scannerConnectors.connectorId, input.connectorId));
      if (!connector) throw new TRPCError({ code: "NOT_FOUND", message: "Connector not found" });

      const credentials = JSON.parse(Buffer.from(connector.credentials, "base64").toString("utf-8"));
      const config: CommercialScannerConfig = {
        id: connector.connectorId,
        platform: connector.platform,
        name: connector.name,
        baseUrl: connector.baseUrl,
        credentials,
      };

      const scannerClient = createConnector(config);
      const scanId = `scan_${randomUUID().replace(/-/g, "").slice(0, 16)}`;

      try {
        const result = await scannerClient.triggerScan({
          scanType: input.scanType,
          target: input.target,
          options: input.options,
        });

        await db.insert(scannerScans).values({
          scanId,
          connectorId: input.connectorId,
          platform: connector.platform,
          scanType: input.scanType,
          status: "running",
          targetRef: input.target || null,
          externalScanId: result.externalScanId || null,
          startedAt: sql`CURRENT_TIMESTAMP`,
        });

        return { scanId, externalScanId: result.externalScanId, status: "running" };
      } catch (err: any) {
        await db.insert(scannerScans).values({
          scanId,
          connectorId: input.connectorId,
          platform: connector.platform,
          scanType: input.scanType,
          status: "failed",
          targetRef: input.target || null,
          errorMessage: err.message,
          startedAt: sql`CURRENT_TIMESTAMP`,
          completedAt: sql`CURRENT_TIMESTAMP`,
        });
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Scan failed: ${err.message}` });
      }
    }),

  // ─── Get Scan Status ───────────────────────────────────────────────
  getScanStatus: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [scan] = await db.select().from(scannerScans)
        .where(eq(scannerScans.scanId, input.scanId));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      return scan;
    }),

  listScans: protectedProcedure
    .input(z.object({
      connectorId: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = input.connectorId
        ? eq(scannerScans.connectorId, input.connectorId)
        : undefined;

      const scans = await db.select().from(scannerScans)
        .where(conditions)
        .orderBy(desc(scannerScans.createdAt))
        .limit(input.limit);

      return scans;
    }),

  // ─── Import Results ────────────────────────────────────────────────
  importResults: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [scan] = await db.select().from(scannerScans)
        .where(eq(scannerScans.scanId, input.scanId));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const [connector] = await db.select().from(scannerConnectors)
        .where(eq(scannerConnectors.connectorId, scan.connectorId));
      if (!connector) throw new TRPCError({ code: "NOT_FOUND", message: "Connector not found" });

      const credentials = JSON.parse(Buffer.from(connector.credentials, "base64").toString("utf-8"));
      const config: CommercialScannerConfig = {
        id: connector.connectorId,
        platform: connector.platform,
        name: connector.name,
        baseUrl: connector.baseUrl,
        credentials,
      };

      const scannerClient = createConnector(config);

      try {
        const findings = await scannerClient.getFindings(scan.externalScanId || scan.scanId);

        let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
        for (const finding of findings) {
          const findingId = `sf_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
          if (finding.severity === "critical") criticalCount++;
          else if (finding.severity === "high") highCount++;
          else if (finding.severity === "medium") mediumCount++;
          else if (finding.severity === "low") lowCount++;

          await db.insert(scannerFindings).values({
            findingId,
            scanId: scan.scanId,
            connectorId: scan.connectorId,
            platform: scan.platform,
            title: finding.title,
            severity: finding.severity,
            cvssScore: finding.cvssScore?.toString() || null,
            cveId: finding.cveId || null,
            cweId: finding.cweId || null,
            description: finding.description || null,
            remediation: finding.remediation || null,
            affectedAsset: finding.affectedAsset || null,
            affectedComponent: finding.affectedComponent || null,
            evidence: finding.evidence ? JSON.stringify(finding.evidence) : null,
            externalFindingId: finding.externalId || null,
            sourceUrl: finding.sourceUrl || null,
            status: "open",
          });
        }

        await db.update(scannerScans).set({
          status: "completed",
          findingsCount: findings.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          completedAt: sql`CURRENT_TIMESTAMP`,
        }).where(eq(scannerScans.scanId, scan.scanId));

        return { imported: findings.length, critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount };
      } catch (err: any) {
        await db.update(scannerScans).set({
          status: "import_failed",
          errorMessage: err.message,
        }).where(eq(scannerScans.scanId, scan.scanId));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Import failed: ${err.message}` });
      }
    }),

  // ─── Findings ──────────────────────────────────────────────────────
  listFindings: protectedProcedure
    .input(z.object({
      connectorId: z.string().optional(),
      scanId: z.string().optional(),
      severity: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions: any[] = [];
      if (input.connectorId) conditions.push(eq(scannerFindings.connectorId, input.connectorId));
      if (input.scanId) conditions.push(eq(scannerFindings.scanId, input.scanId));
      if (input.severity) conditions.push(eq(scannerFindings.severity, input.severity));
      if (input.status) conditions.push(eq(scannerFindings.status, input.status));

      if (conditions.length > 0) {
        return db.select().from(scannerFindings)
          .where(and(...conditions))
          .orderBy(desc(scannerFindings.importedAt))
          .limit(input.limit);
      }
      return db.select().from(scannerFindings)
        .orderBy(desc(scannerFindings.importedAt))
        .limit(input.limit);
    }),

  updateFindingStatus: protectedProcedure
    .input(z.object({
      findingId: z.string(),
      status: z.enum(["open", "acknowledged", "remediated", "false_positive"]),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(scannerFindings).set({
        status: input.status,
        resolvedAt: input.status === "remediated" || input.status === "false_positive"
          ? sql`CURRENT_TIMESTAMP` : null,
      }).where(eq(scannerFindings.findingId, input.findingId));
      return { success: true };
    }),

  // ─── Dashboard Stats ───────────────────────────────────────────────
  getStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [connectorCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(scannerConnectors);
    const [scanCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(scannerScans);
    const [findingCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(scannerFindings);
    const [openFindings] = await db.select({ count: sql<number>`COUNT(*)` }).from(scannerFindings)
      .where(eq(scannerFindings.status, "open"));
    const [criticalFindings] = await db.select({ count: sql<number>`COUNT(*)` }).from(scannerFindings)
      .where(and(eq(scannerFindings.severity, "critical"), eq(scannerFindings.status, "open")));

    return {
      totalConnectors: connectorCount?.count || 0,
      totalScans: scanCount?.count || 0,
      totalFindings: findingCount?.count || 0,
      openFindings: openFindings?.count || 0,
      criticalOpen: criticalFindings?.count || 0,
    };
  }),

  // ─── SonarQube Webhook Registration ────────────────────────────────
  registerSonarQubeWebhook: protectedProcedure
    .input(z.object({
      connectorId: z.string(),
      projectKey: z.string(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const webhookId = `sqw_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
      const webhookSecret = randomUUID();

      await db.insert(sonarqubeWebhooks).values({
        webhookId,
        connectorId: input.connectorId,
        projectKey: input.projectKey,
        webhookSecret,
        enabled: 1,
      });

      return {
        webhookId,
        webhookUrl: `/api/webhooks/sonarqube/${webhookId}`,
        secret: webhookSecret,
        instructions: `Configure this webhook URL in your SonarQube project settings (Administration > Webhooks). Use the secret for HMAC validation.`,
      };
    }),

  listSonarQubeWebhooks: protectedProcedure
    .input(z.object({ connectorId: z.string().optional() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = input.connectorId
        ? eq(sonarqubeWebhooks.connectorId, input.connectorId)
        : undefined;
      return db.select().from(sonarqubeWebhooks).where(conditions).orderBy(desc(sonarqubeWebhooks.createdAt));
    }),

  // ─── MSF Instance Provisioning ─────────────────────────────────────
  provisionMsfInstance: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(128),
      instanceType: z.enum(["t3.medium", "t3.large", "c5.large", "c5.xlarge"]).default("t3.medium"),
      region: z.string().default("us-east-1"),
    }))
    .mutation(async ({ input, ctx }) => {
      const { provisionMsfServer } = await import("../lib/msf-provisioner");
      const result = await provisionMsfServer({
        name: input.name,
        instanceType: input.instanceType,
        region: input.region,
        userId: ctx.user.openId,
      });
      return result;
    }),

  validateMsfRpc: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(55553),
      token: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      try {
        const response = await fetch(`https://${input.host}:${input.port}/api/v1/msf/version`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(input.token ? { Authorization: `Bearer ${input.token}` } : {}),
          },
          body: JSON.stringify({ jsonrpc: "2.0", method: "core.version", id: 1 }),
          signal: AbortSignal.timeout(10000),
        }).catch(() => null);

        const latency = Date.now() - startTime;

        if (!response || !response.ok) {
          const msgpackResponse = await fetch(`http://${input.host}:${input.port}/api/`, {
            method: "POST",
            headers: { "Content-Type": "binary/message-pack" },
            signal: AbortSignal.timeout(10000),
          }).catch(() => null);

          if (msgpackResponse) {
            return { connected: true, protocol: "msgpack-rpc", latencyMs: latency, message: "MSF RPC (msgpack) is reachable" };
          }
          return { connected: false, protocol: null, latencyMs: latency, message: "MSF RPC is not reachable. Ensure msfrpcd is running and port is open." };
        }

        return { connected: true, protocol: "json-rpc", latencyMs: latency, message: "MSF JSON-RPC is healthy" };
      } catch (err: any) {
        return { connected: false, protocol: null, latencyMs: Date.now() - startTime, message: `Connection failed: ${err.message}` };
      }
    }),

  destroyMsfInstance: protectedProcedure
    .input(z.object({ instanceId: z.string() }))
    .mutation(async ({ input }) => {
      const { destroyMsfServer } = await import("../lib/msf-provisioner");
      await destroyMsfServer(input.instanceId);
      return { success: true, message: `Instance ${input.instanceId} termination initiated` };
    }),
});
