import * as db from "../db";
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  exportCredentialFindings,
  exportTimelineEvents,
  exportOpsecEvents,
  exportExploitAttempts,
  exportPrivescFindings,
  exportLateralMovePaths,
  exportFullEngagement,
  generateExecutiveSummary,
  exportExecutiveSummary,
  type ExportOptions,
  type CredentialFinding,
  type TimelineEvent,
  type OpsecEvent,
  type ExploitAttempt,
  type PrivescFinding,
  type LateralMovePath,
} from "../lib/report-export";
import { getDb } from "../db";
import {
  credentialFindings,
  engagementTimelineEvents,
  opsecEvents,
  exploitationAttempts,
  privescFindings,
  lateralMovementPaths,
} from "../../drizzle/schema";
import { desc, eq, and, gte, lte } from "drizzle-orm";

const exportOptionsSchema = z.object({
  format: z.enum(["csv", "json"]),
  engagementId: z.string().optional(),
  dateFrom: z.number().optional(),
  dateTo: z.number().optional(),
  includeRawOutput: z.boolean().optional(),
});

export const reportExportRouter = router({
  // Export credential findings
  exportCredentials: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(credentialFindings).orderBy(desc(credentialFindings.createdAt)).limit(5000);

      const findings: CredentialFinding[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        tool: r.tool || "builtin",
        protocol: r.protocol || "unknown",
        target: r.target || "",
        port: r.port || 0,
        username: r.username || "",
        password: r.password || "",
        status: r.status || "found",
        validated: r.validated === true || r.validated === 1,
      }));

      return {
        content: exportCredentialFindings(findings, input as ExportOptions),
        filename: `credential_findings_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: findings.length,
      };
    }),

  // Export timeline events
  exportTimeline: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(engagementTimelineEvents).orderBy(desc(engagementTimelineEvents.createdAt)).limit(10000);

      const events: TimelineEvent[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        engagementId: r.engagementId || "",
        phase: r.phase || "",
        category: r.category || "",
        action: r.action || "",
        description: r.description || "",
        severity: r.severity || "info",
        opsecScore: r.opsecScore || undefined,
      }));

      return {
        content: exportTimelineEvents(events, input as ExportOptions),
        filename: `timeline_events_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: events.length,
      };
    }),

  // Export OPSEC events
  exportOpsec: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(opsecEvents).orderBy(desc(opsecEvents.createdAt)).limit(10000);

      const events: OpsecEvent[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        engagementId: r.engagementId || "",
        action: r.action || "",
        riskScore: r.riskScore || 0,
        detectionTech: r.detectionTech || "",
        mitigations: r.mitigations || "",
        burnIndicator: r.burnIndicator === true || r.burnIndicator === 1,
      }));

      return {
        content: exportOpsecEvents(events, input as ExportOptions),
        filename: `opsec_events_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: events.length,
      };
    }),

  // Export exploitation attempts
  exportExploits: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(exploitationAttempts).orderBy(desc(exploitationAttempts.createdAt)).limit(5000);

      const attempts: ExploitAttempt[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        cve: r.cve || "",
        target: r.target || "",
        tool: r.tool || "",
        technique: r.technique || "",
        success: r.success === true || r.success === 1,
        evidence: r.evidence || "",
        opsecRisk: r.opsecRisk || 0,
      }));

      return {
        content: exportExploitAttempts(attempts, input as ExportOptions),
        filename: `exploitation_attempts_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: attempts.length,
      };
    }),

  // Export privesc findings
  exportPrivesc: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(privescFindings).orderBy(desc(privescFindings.createdAt)).limit(5000);

      const findings: PrivescFinding[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        os: r.os || "",
        technique: r.technique || "",
        vector: r.vector || "",
        severity: r.severity || "",
        exploitability: r.exploitability || "",
        description: r.description || "",
      }));

      return {
        content: exportPrivescFindings(findings, input as ExportOptions),
        filename: `privesc_findings_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: findings.length,
      };
    }),

  // Export lateral movement paths
  exportLateral: protectedProcedure
    .input(exportOptionsSchema)
    .mutation(async ({ input }) => {
      const db = getDb();
      const rows = await db.select().from(lateralMovementPaths).orderBy(desc(lateralMovementPaths.createdAt)).limit(5000);

      const paths: LateralMovePath[] = rows.map((r: any) => ({
        id: r.id,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        sourceHost: r.sourceHost || "",
        targetHost: r.targetHost || "",
        technique: r.technique || "",
        protocol: r.protocol || "",
        credentials: r.credentials || "",
        success: r.success === true || r.success === 1,
      }));

      return {
        content: exportLateralMovePaths(paths, input as ExportOptions),
        filename: `lateral_movement_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        count: paths.length,
      };
    }),

  // Generate executive summary
  executiveSummary: protectedProcedure
    .input(z.object({ format: z.enum(["csv", "json"]), engagementId: z.string().optional() }))
    .mutation(async ({ input }) => {
      const db = getDb();

      const [creds, exploits, privesc, lateral, opsec, timeline] = await Promise.all([
        db.select().from(credentialFindings).limit(5000),
        db.select().from(exploitationAttempts).limit(5000),
        db.select().from(privescFindings).limit(5000),
        db.select().from(lateralMovementPaths).limit(5000),
        db.select().from(opsecEvents).limit(10000),
        db.select().from(engagementTimelineEvents).limit(10000),
      ]);

      const mapCred = (r: any): CredentialFinding => ({
        id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        tool: r.tool || "builtin", protocol: r.protocol || "", target: r.target || "",
        port: r.port || 0, username: r.username || "", password: r.password || "",
        status: r.status || "found", validated: r.validated === true || r.validated === 1,
      });

      const summary = generateExecutiveSummary({
        credentials: creds.map(mapCred),
        exploits: exploits.map((r: any) => ({
          id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
          cve: r.cve || "", target: r.target || "", tool: r.tool || "",
          technique: r.technique || "", success: r.success === true || r.success === 1,
          evidence: r.evidence || "", opsecRisk: r.opsecRisk || 0,
        })),
        privesc: privesc.map((r: any) => ({
          id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
          os: r.os || "", technique: r.technique || "", vector: r.vector || "",
          severity: r.severity || "", exploitability: r.exploitability || "", description: r.description || "",
        })),
        lateral: lateral.map((r: any) => ({
          id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
          sourceHost: r.sourceHost || "", targetHost: r.targetHost || "",
          technique: r.technique || "", protocol: r.protocol || "",
          credentials: r.credentials || "", success: r.success === true || r.success === 1,
        })),
        opsec: opsec.map((r: any) => ({
          id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
          engagementId: r.engagementId || "", action: r.action || "",
          riskScore: r.riskScore || 0, detectionTech: r.detectionTech || "",
          mitigations: r.mitigations || "", burnIndicator: r.burnIndicator === true || r.burnIndicator === 1,
        })),
        timeline: timeline.map((r: any) => ({
          id: r.id, timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
          engagementId: r.engagementId || "", phase: r.phase || "",
          category: r.category || "", action: r.action || "",
          description: r.description || "", severity: r.severity || "info",
        })),
        engagementId: input.engagementId,
      });

      return {
        content: exportExecutiveSummary(summary, input.format),
        filename: `executive_summary_${Date.now()}.${input.format === "csv" ? "csv" : "json"}`,
        mimeType: input.format === "csv" ? "text/csv" : "application/json",
        summary,
      };
    }),
});
