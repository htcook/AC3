import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
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

export const socIntegrationHubRouter = router({
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

  /** Push alerts to a configured SIEM platform */
  pushAlerts: protectedProcedure
    .input(z.object({
      alerts: z.array(z.object({
        format: z.enum(["cef", "leef", "json", "syslog", "csv"]),
        raw: z.string(),
        findingId: z.string(),
        timestamp: z.number(),
      })),
      config: z.object({
        target: z.enum(["splunk_hec", "elastic", "syslog", "qradar", "sentinel"]),
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
