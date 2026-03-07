import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { eq, desc } from "drizzle-orm";
import {
  exportFindings,
  analyzeDetectionGaps,
  computeSocHealth,
  pushAlertsToSiem,
  getDetectionRuleRecommendations,
  type EngagementFinding,
  type AlertExportFormat,
  type AttackAction,
  type SocConnectorHealth,
  type SiemPushConfig,
  type DetectionGap,
  type ExportedAlert,
} from "../lib/soc-integration-hub";
import type { NormalizedSiemAlert } from "../lib/siem-connectors";
import { getDb } from "../db";
import { siemIntegrations } from "../../drizzle/schema";

/* ─── Zod schemas ─── */
const findingSchema = z.object({
  id: z.string(),
  engagementId: z.number(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  cvss: z.number().optional(),
  cveIds: z.array(z.string()).optional(),
  mitreTechniques: z.array(z.string()).optional(),
  mitreTactics: z.array(z.string()).optional(),
  targetHost: z.string().optional(),
  targetPort: z.number().optional(),
  toolUsed: z.string().optional(),
  evidence: z.string().optional(),
  timestamp: z.number(),
  phase: z.string().optional(),
});

const attackActionSchema = z.object({
  id: z.string(),
  techniqueId: z.string(),
  techniqueName: z.string(),
  tactic: z.string(),
  tool: z.string(),
  targetHost: z.string(),
  timestamp: z.number(),
  success: z.boolean(),
  description: z.string(),
});

const siemAlertSchema = z.object({
  alertId: z.string(),
  backend: z.enum(["wazuh", "splunk", "elastic", "qradar", "sentinel"]),
  timestamp: z.number(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  severityScore: z.number(),
  title: z.string(),
  description: z.string(),
  mitreTechniques: z.array(z.string()),
  mitreTactics: z.array(z.string()),
  ruleId: z.string(),
  ruleName: z.string(),
  agentName: z.string(),
  agentIp: z.string().optional(),
  rawData: z.record(z.any()),
  processName: z.string().optional(),
});

const connectorHealthSchema = z.object({
  id: z.string(),
  name: z.string(),
  backend: z.string(),
  status: z.enum(["connected", "degraded", "disconnected", "unknown"]),
  lastCheck: z.number(),
  latencyMs: z.number(),
  alertsLast24h: z.number(),
  errorMessage: z.string().optional(),
});

const siemProviderEnum = z.enum(["splunk", "elastic", "sentinel", "qradar", "custom"]);
const pushTargetEnum = z.enum(["splunk_hec", "elastic", "syslog", "qradar", "sentinel", "wazuh"]);

/* ─── Helper: map provider to push target ─── */
function providerToPushTarget(provider: string): SiemPushConfig["target"] {
  switch (provider) {
    case "splunk": return "splunk_hec";
    case "elastic": return "elastic";
    case "sentinel": return "sentinel";
    case "qradar": return "qradar";
    default: return "syslog";
  }
}

export const socIntegrationHubRouter = router({
  /* ═══════════════════════════════════════════════════════════
   * SIEM CONNECTION MANAGEMENT (CRUD)
   * ═══════════════════════════════════════════════════════════ */

  /** List all saved SIEM connections */
  listConnections: protectedProcedure
    .query(async () => {
      const db = await getDb();
      const rows = await db
        .select({
          id: siemIntegrations.id,
          name: siemIntegrations.siemName,
          provider: siemIntegrations.siemProvider,
          baseUrl: siemIntegrations.siemBaseUrl,
          hasApiKey: siemIntegrations.siemApiKeyEnc,
          isActive: siemIntegrations.siemIsActive,
          lastTested: siemIntegrations.siemLastTested,
          createdAt: siemIntegrations.siemCreatedAt,
        })
        .from(siemIntegrations)
        .orderBy(desc(siemIntegrations.siemCreatedAt));
      return rows.map(r => ({
        ...r,
        hasApiKey: !!r.hasApiKey,
      }));
    }),

  /** Create a new SIEM connection */
  createConnection: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      provider: siemProviderEnum,
      baseUrl: z.string().url().max(512),
      apiKey: z.string().max(2048).optional(),
      queryTemplate: z.string().max(4096).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const result = await db.insert(siemIntegrations).values({
        siemName: input.name,
        siemProvider: input.provider,
        siemBaseUrl: input.baseUrl,
        siemApiKeyEnc: input.apiKey || null,
        siemQueryTemplate: input.queryTemplate || null,
        siemIsActive: 1,
      });
      return { id: result[0].insertId, success: true };
    }),

  /** Update an existing SIEM connection */
  updateConnection: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().min(1).max(255).optional(),
      provider: siemProviderEnum.optional(),
      baseUrl: z.string().url().max(512).optional(),
      apiKey: z.string().max(2048).optional(),
      queryTemplate: z.string().max(4096).optional(),
      isActive: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const updates: Record<string, any> = {};
      if (input.name !== undefined) updates.siemName = input.name;
      if (input.provider !== undefined) updates.siemProvider = input.provider;
      if (input.baseUrl !== undefined) updates.siemBaseUrl = input.baseUrl;
      if (input.apiKey !== undefined) updates.siemApiKeyEnc = input.apiKey;
      if (input.queryTemplate !== undefined) updates.siemQueryTemplate = input.queryTemplate;
      if (input.isActive !== undefined) updates.siemIsActive = input.isActive ? 1 : 0;
      if (Object.keys(updates).length > 0) {
        await db.update(siemIntegrations).set(updates).where(eq(siemIntegrations.id, input.id));
      }
      return { success: true };
    }),

  /** Delete a SIEM connection */
  deleteConnection: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.delete(siemIntegrations).where(eq(siemIntegrations.id, input.id));
      return { success: true };
    }),

  /** Test connectivity to a SIEM endpoint */
  testConnection: protectedProcedure
    .input(z.object({
      provider: siemProviderEnum,
      baseUrl: z.string(),
      apiKey: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const start = Date.now();
      let status: "connected" | "degraded" | "disconnected" = "disconnected";
      let message = "";
      let version = "";

      try {
        switch (input.provider) {
          case "splunk": {
            // Test Splunk HEC by sending to /services/collector/health
            const healthUrl = input.baseUrl.replace(/\/services\/collector\/?$/, "") + "/services/collector/health";
            const resp = await fetch(healthUrl, {
              method: "GET",
              headers: input.apiKey ? { "Authorization": `Splunk ${input.apiKey}` } : {},
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) {
              status = "connected";
              message = "Splunk HEC is healthy";
            } else if (resp.status === 401 || resp.status === 403) {
              status = "disconnected";
              message = `Authentication failed (HTTP ${resp.status}). Check your HEC token.`;
            } else {
              status = "degraded";
              message = `Splunk returned HTTP ${resp.status}`;
            }
            break;
          }

          case "elastic": {
            // Test Elastic by hitting the root endpoint
            const headers: Record<string, string> = {};
            if (input.apiKey) headers["Authorization"] = `ApiKey ${input.apiKey}`;
            const resp = await fetch(input.baseUrl, {
              method: "GET",
              headers,
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) {
              const data = await resp.json();
              version = data?.version?.number || "";
              status = "connected";
              message = `Elasticsearch ${version} cluster: ${data?.cluster_name || "unknown"}`;
            } else if (resp.status === 401) {
              status = "disconnected";
              message = "Authentication failed. Check your API key.";
            } else {
              status = "degraded";
              message = `Elasticsearch returned HTTP ${resp.status}`;
            }
            break;
          }

          case "sentinel": {
            // Test Azure Sentinel Log Analytics Data Collector
            const resp = await fetch(input.baseUrl, {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${input.apiKey || ""}`,
                "Content-Type": "application/json",
                "Log-Type": "AceC3HealthCheck",
              },
              body: JSON.stringify({ healthCheck: true, timestamp: new Date().toISOString() }),
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok || resp.status === 200) {
              status = "connected";
              message = "Azure Sentinel Log Analytics endpoint is reachable";
            } else if (resp.status === 401 || resp.status === 403) {
              status = "disconnected";
              message = `Authentication failed (HTTP ${resp.status}). Check your shared key.`;
            } else {
              status = "degraded";
              message = `Sentinel returned HTTP ${resp.status}`;
            }
            break;
          }

          case "qradar": {
            // Test QRadar by hitting /api/system/about
            const resp = await fetch(`${input.baseUrl}/api/system/about`, {
              method: "GET",
              headers: { "SEC": input.apiKey || "", "Accept": "application/json" },
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) {
              const data = await resp.json();
              version = data?.build_version || "";
              status = "connected";
              message = `QRadar ${version} is reachable`;
            } else if (resp.status === 401) {
              status = "disconnected";
              message = "Authentication failed. Check your SEC token.";
            } else {
              status = "degraded";
              message = `QRadar returned HTTP ${resp.status}`;
            }
            break;
          }

          case "custom": {
            // Generic HTTP health check
            const resp = await fetch(input.baseUrl, {
              method: "GET",
              headers: input.apiKey ? { "Authorization": `Bearer ${input.apiKey}` } : {},
              signal: AbortSignal.timeout(10_000),
            });
            status = resp.ok ? "connected" : "degraded";
            message = `Endpoint returned HTTP ${resp.status}`;
            break;
          }
        }
      } catch (e: any) {
        status = "disconnected";
        message = e.message?.includes("timeout") ? "Connection timed out (10s)" :
                  e.message?.includes("ECONNREFUSED") ? "Connection refused — check the URL and port" :
                  e.message?.includes("ENOTFOUND") ? "DNS resolution failed — check the hostname" :
                  `Connection error: ${e.message}`;
      }

      const latencyMs = Date.now() - start;

      // Update the last tested timestamp in the DB if we have a matching connection
      try {
        const db = await getDb();
        // Find connections matching this URL and update lastTested
        const rows = await db.select({ id: siemIntegrations.id })
          .from(siemIntegrations)
          .where(eq(siemIntegrations.siemBaseUrl, input.baseUrl));
        if (rows.length > 0) {
          await db.update(siemIntegrations)
            .set({ siemLastTested: new Date().toISOString().slice(0, 19).replace("T", " ") })
            .where(eq(siemIntegrations.id, rows[0].id));
        }
      } catch { /* non-critical */ }

      return { status, message, latencyMs, version };
    }),

  /** Push alerts to a saved SIEM connection by ID */
  pushToConnection: protectedProcedure
    .input(z.object({
      connectionId: z.number(),
      findings: z.array(findingSchema),
      format: z.enum(["cef", "leef", "json", "syslog", "csv"]),
    }))
    .mutation(async ({ input }) => {
      // 1. Load connection from DB
      const db = await getDb();
      const [conn] = await db.select()
        .from(siemIntegrations)
        .where(eq(siemIntegrations.id, input.connectionId));
      if (!conn) throw new Error("SIEM connection not found");
      if (!conn.siemIsActive) throw new Error("SIEM connection is disabled");

      // 2. Export findings to the requested format
      const exported = exportFindings(
        input.findings as EngagementFinding[],
        input.format as AlertExportFormat,
      );

      // 3. Build push config from saved connection
      const pushConfig: SiemPushConfig = {
        target: providerToPushTarget(conn.siemProvider),
        endpoint: conn.siemBaseUrl,
        authToken: conn.siemApiKeyEnc || undefined,
      };

      // 4. Push alerts
      const result = await pushAlertsToSiem(exported as ExportedAlert[], pushConfig);
      return result;
    }),

  /* ═══════════════════════════════════════════════════════════
   * EXISTING ENDPOINTS (export, gaps, health, push, recommendations)
   * ═══════════════════════════════════════════════════════════ */

  /** Export engagement findings in various SIEM-compatible formats */
  exportFindings: protectedProcedure
    .input(z.object({
      findings: z.array(findingSchema),
      format: z.enum(["cef", "leef", "json", "syslog", "csv"]),
    }))
    .mutation(({ input }) => {
      return exportFindings(
        input.findings as EngagementFinding[],
        input.format as AlertExportFormat,
      );
    }),

  /** Analyze detection gaps between attack actions and SIEM alerts */
  analyzeGaps: protectedProcedure
    .input(z.object({
      attacks: z.array(attackActionSchema),
      siemAlerts: z.array(siemAlertSchema),
      timeWindowMs: z.number().optional(),
    }))
    .mutation(({ input }) => {
      return analyzeDetectionGaps(
        input.attacks as AttackAction[],
        input.siemAlerts as NormalizedSiemAlert[],
        input.timeWindowMs,
      );
    }),

  /** Compute SOC connector health snapshot */
  getHealth: protectedProcedure
    .input(z.object({
      connectors: z.array(connectorHealthSchema),
    }))
    .query(({ input }) => {
      return computeSocHealth(input.connectors as SocConnectorHealth[]);
    }),

  /** Push alerts to a configured SIEM platform (ad-hoc, no saved connection) */
  pushAlerts: protectedProcedure
    .input(z.object({
      alerts: z.array(z.object({
        format: z.enum(["cef", "leef", "json", "syslog", "csv"]),
        raw: z.string(),
        findingId: z.string(),
        timestamp: z.number(),
      })),
      config: z.object({
        target: pushTargetEnum,
        endpoint: z.string(),
        authToken: z.string().optional(),
        index: z.string().optional(),
        insecure: z.boolean().optional(),
      }),
    }))
    .mutation(async ({ input }) => {
      return await pushAlertsToSiem(
        input.alerts as ExportedAlert[],
        input.config as SiemPushConfig,
      );
    }),

  /** Get detection rule recommendations based on gaps */
  getDetectionRecommendations: protectedProcedure
    .input(z.object({
      gaps: z.array(z.object({
        techniqueId: z.string(),
        techniqueName: z.string(),
        tactic: z.string(),
        attackCount: z.number(),
        detectionCount: z.number(),
        detectionRate: z.number(),
        gapSeverity: z.enum(["critical", "high", "medium", "low"]),
        recommendation: z.string(),
        relatedRules: z.array(z.string()),
        sampleAttacks: z.array(z.string()),
      })),
      platforms: z.array(z.enum(["splunk", "elastic", "sigma", "sentinel_kql"])).optional(),
    }))
    .query(({ input }) => {
      return getDetectionRuleRecommendations(
        input.gaps as DetectionGap[],
        input.platforms,
      );
    }),

  /** Get sample demo data for the frontend */
  getDemoData: protectedProcedure
    .query(() => {
      const sampleFindings: EngagementFinding[] = [
        { id: "f1", engagementId: 1, title: "SQL Injection in login form", description: "Blind SQL injection via username parameter", severity: "critical", cvss: 9.8, targetHost: "10.0.1.5", targetPort: 443, toolUsed: "sqlmap", cveIds: ["CVE-2024-1234"], mitreTechniques: ["T1190"], timestamp: Date.now() - 86400000 },
        { id: "f2", engagementId: 1, title: "Exposed admin panel", description: "Admin panel accessible without auth", severity: "high", cvss: 7.5, targetHost: "10.0.1.5", targetPort: 8080, toolUsed: "nuclei", mitreTechniques: ["T1078"], timestamp: Date.now() - 43200000 },
        { id: "f3", engagementId: 1, title: "Outdated TLS 1.0", description: "Server supports deprecated TLS 1.0", severity: "medium", targetHost: "10.0.1.5", targetPort: 443, toolUsed: "nmap", timestamp: Date.now() - 21600000 },
      ];

      const sampleAttacks: AttackAction[] = [
        { id: "a1", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", tool: "sqlmap", targetHost: "10.0.1.5", timestamp: Date.now() - 60000, success: true, description: "SQL injection attempt" },
        { id: "a2", techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "persistence", tool: "hydra", targetHost: "10.0.1.5", timestamp: Date.now() - 50000, success: true, description: "Credential brute force" },
        { id: "a3", techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", tool: "caldera", targetHost: "10.0.1.5", timestamp: Date.now() - 40000, success: true, description: "PowerShell execution" },
        { id: "a4", techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", tool: "cobalt-strike", targetHost: "10.0.1.5", timestamp: Date.now() - 30000, success: true, description: "C2 over HTTPS" },
        { id: "a5", techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access", tool: "mimikatz", targetHost: "10.0.1.5", timestamp: Date.now() - 20000, success: true, description: "Credential dumping" },
      ];

      const sampleConnectors: SocConnectorHealth[] = [
        { id: "splunk-1", name: "Splunk HEC", backend: "splunk", status: "connected", lastCheck: Date.now(), latencyMs: 45, alertsLast24h: 1247 },
        { id: "sentinel-1", name: "Azure Sentinel", backend: "sentinel", status: "degraded", lastCheck: Date.now() - 120000, latencyMs: 200, alertsLast24h: 892, errorMessage: "High latency detected" },
        { id: "elastic-1", name: "Elastic SIEM", backend: "elastic", status: "connected", lastCheck: Date.now(), latencyMs: 32, alertsLast24h: 2156 },
        { id: "wazuh-1", name: "Wazuh Manager", backend: "wazuh", status: "connected", lastCheck: Date.now(), latencyMs: 18, alertsLast24h: 3421 },
        { id: "qradar-1", name: "IBM QRadar", backend: "qradar", status: "disconnected", lastCheck: Date.now() - 600000, latencyMs: 0, alertsLast24h: 0, errorMessage: "Connection refused" },
      ];

      return { sampleFindings, sampleAttacks, sampleConnectors };
    }),
});
