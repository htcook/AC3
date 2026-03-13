/**
 * DAST Scanners & Service Audit Router
 *
 * tRPC endpoints for:
 * - Nikto, Wapiti, Arachni web application scanning
 * - SSH and FTP service auditing
 * - Service audit pipeline (auto-follow-up after port discovery)
 * - Scan result retrieval and analysis
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { scanResults } from "../../drizzle/schema";
import { eq, and, desc, inArray } from "drizzle-orm";

export const dastScannersRouter = router({
  /**
   * Start a Nikto scan against a target URL.
   */
  startNikto: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      engagementId: z.number(),
      tuning: z.string().optional(),
      timeoutSeconds: z.number().default(300),
      ssl: z.boolean().optional(),
      port: z.number().optional(),
      evasion: z.string().optional(),
      userAgent: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ROE scope enforcement
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          const url = new URL(input.targetUrl);
          await enforceMultiTargetScope(input.engagementId, [url.hostname], "Nikto Scanner", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startNiktoScan } = await import("../lib/scanners/nikto-scanner");
      const result = await startNiktoScan({
        ...input,
        operatorId: ctx.user?.id,
      });

      // Emit WebSocket event
      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:nikto:complete", {
          scanId: result.scanId,
          target: result.target,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start a Wapiti scan against a target URL.
   */
  startWapiti: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      engagementId: z.number(),
      modules: z.string().optional(),
      scope: z.enum(["page", "folder", "domain", "punk"]).optional(),
      timeoutSeconds: z.number().default(300),
      maxUrls: z.number().optional(),
      maxDepth: z.number().optional(),
      userAgent: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          const url = new URL(input.targetUrl);
          await enforceMultiTargetScope(input.engagementId, [url.hostname], "Wapiti Scanner", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startWapitiScan } = await import("../lib/scanners/wapiti-scanner");
      const result = await startWapitiScan({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:wapiti:complete", {
          scanId: result.scanId,
          target: result.target,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an Arachni scan against a target URL.
   */
  startArachni: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      engagementId: z.number(),
      checks: z.array(z.string()).optional(),
      scope: z.enum(["page", "subdomain", "domain", "global"]).optional(),
      timeoutSeconds: z.number().default(600),
      maxPages: z.number().optional(),
      maxDepth: z.number().optional(),
      browserPoolSize: z.number().optional(),
      httpRequestConcurrency: z.number().optional(),
      userAgent: z.string().optional(),
      domChecks: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          const url = new URL(input.targetUrl);
          await enforceMultiTargetScope(input.engagementId, [url.hostname], "Arachni Scanner", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startArachniScan } = await import("../lib/scanners/arachni-scanner");
      const result = await startArachniScan({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:arachni:complete", {
          scanId: result.scanId,
          target: result.target,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an SSH audit against a host.
   */
  startSSHAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(22),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(60),
      nmapScripts: z.boolean().default(true),
      enumAuth: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "SSH Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startSSHAudit } = await import("../lib/scanners/ssh-audit-scanner");
      const result = await startSSHAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:ssh-audit:complete", {
          scanId: result.scanId,
          host: result.host,
          port: result.port,
          findingCount: result.findings.length,
          weakAlgorithms: result.stats.weakAlgorithms,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an FTP audit against a host.
   */
  startFTPAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(21),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(60),
      testAnonymous: z.boolean().default(true),
      testDefaultCreds: z.boolean().default(true),
      testBounce: z.boolean().default(true),
      nmapScripts: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "FTP Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startFTPAudit } = await import("../lib/scanners/ftp-audit-scanner");
      const result = await startFTPAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:ftp-audit:complete", {
          scanId: result.scanId,
          host: result.host,
          port: result.port,
          findingCount: result.findings.length,
          anonymousAccess: result.anonymousAccess,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Run the service audit pipeline against discovered services.
   * Auto-maps services to appropriate scanners.
   */
  runServiceAuditPipeline: protectedProcedure
    .input(z.object({
      services: z.array(z.object({
        host: z.string(),
        port: z.number(),
        service: z.string(),
        banner: z.string().optional(),
        protocol: z.string().optional(),
      })),
      engagementId: z.number(),
      concurrency: z.number().default(3),
      timeoutPerAudit: z.number().default(300),
      profile: z.enum(["quick", "standard", "deep"]).default("standard"),
      enabledScanners: z.object({
        ssh: z.boolean().default(true),
        ftp: z.boolean().default(true),
        nikto: z.boolean().default(true),
        wapiti: z.boolean().default(true),
        arachni: z.boolean().default(false), // Off by default (heavier)
      }).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement for all targets
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          const hosts = [...new Set(input.services.map(s => s.host))];
          await enforceMultiTargetScope(input.engagementId, hosts, "Service Audit Pipeline", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { runServiceAuditPipeline } = await import("../lib/scanners/service-audit-pipeline");

      const result = await runServiceAuditPipeline(input.services, {
        engagementId: input.engagementId,
        operatorId: ctx.user?.id,
        concurrency: input.concurrency,
        timeoutPerAudit: input.timeoutPerAudit,
        profile: input.profile,
        enabledScanners: input.enabledScanners,
        onEvent: (event) => {
          try {
            // Dynamic import to avoid circular deps
            import("../lib/ws-event-hub").then(({ wsHub }) => {
              wsHub.emit(`scan:pipeline:${event.type}`, event);
            });
          } catch { /* ws not critical */ }
        },
      });

      return result;
    }),

  /**
   * Get scan results for a specific tool and engagement.
   */
  getResults: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      tool: z.enum(["nikto", "wapiti", "arachni", "ssh-audit", "ftp-audit"]).optional(),
      limit: z.number().default(50),
    }))
    .query(async ({ input }) => {
      const db = getDb();
      const conditions = [eq(scanResults.engagementId, input.engagementId)];
      if (input.tool) {
        conditions.push(eq(scanResults.tool, input.tool));
      } else {
        conditions.push(
          inArray(scanResults.tool, ["nikto", "wapiti", "arachni", "ssh-audit", "ftp-audit"])
        );
      }

      const rows = await db
        .select({
          id: scanResults.id,
          tool: scanResults.tool,
          target: scanResults.target,
          findingCount: scanResults.findingCount,
          severitySummary: scanResults.severitySummary,
          durationMs: scanResults.durationMs,
          phase: scanResults.phase,
          createdAt: scanResults.createdAt,
          exitCode: scanResults.exitCode,
        })
        .from(scanResults)
        .where(and(...conditions))
        .orderBy(desc(scanResults.createdAt))
        .limit(input.limit);

      return rows.map(r => ({
        ...r,
        severitySummary: typeof r.severitySummary === "string" ? JSON.parse(r.severitySummary) : r.severitySummary,
      }));
    }),

  /**
   * Get detailed scan result with findings.
   */
  getResultDetail: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const db = getDb();
      const [row] = await db
        .select()
        .from(scanResults)
        .where(eq(scanResults.id, input.scanId))
        .limit(1);

      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "Scan result not found" });

      return {
        ...row,
        findings: typeof row.findings === "string" ? JSON.parse(row.findings) : row.findings,
        severitySummary: typeof row.severitySummary === "string" ? JSON.parse(row.severitySummary) : row.severitySummary,
      };
    }),

  /**
   * LLM-powered analysis of scan findings.
   */
  analyzeScanFindings: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      tool: z.enum(["nikto", "wapiti", "arachni"]),
    }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const [row] = await db
        .select()
        .from(scanResults)
        .where(eq(scanResults.id, input.scanId))
        .limit(1);

      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "Scan result not found" });

      const findings = typeof row.findings === "string" ? JSON.parse(row.findings) : row.findings;

      switch (input.tool) {
        case "nikto": {
          const { analyzeNiktoFindings } = await import("../lib/scanners/nikto-scanner");
          return analyzeNiktoFindings(
            Array.isArray(findings) ? findings : findings.vulnerabilities || [],
            row.target,
            null,
          );
        }
        case "wapiti": {
          const { analyzeWapitiFindings } = await import("../lib/scanners/wapiti-scanner");
          return analyzeWapitiFindings(
            Array.isArray(findings) ? findings : findings.vulnerabilities || [],
            row.target,
          );
        }
        case "arachni": {
          const { analyzeArachniFindings } = await import("../lib/scanners/arachni-scanner");
          return analyzeArachniFindings(
            Array.isArray(findings) ? findings : [],
            row.target,
          );
        }
      }
    }),

  /**
   * List available scanner tools with their status.
   */
  listScanners: protectedProcedure.query(async () => {
    return [
      {
        id: "nikto",
        name: "Nikto",
        type: "dast",
        description: "Web server scanner — 6,700+ checks for dangerous files, outdated versions, server misconfigurations",
        speed: "fast",
        depth: "surface",
        bestFor: "Quick web server audit, initial triage",
        icon: "🔍",
      },
      {
        id: "wapiti",
        name: "Wapiti",
        type: "dast",
        description: "Black-box injection tester — SQL, XSS, XXE, SSRF, command execution, file inclusion",
        speed: "medium",
        depth: "deep",
        bestFor: "Injection vulnerability discovery, parameter fuzzing",
        icon: "💉",
      },
      {
        id: "arachni",
        name: "Arachni",
        type: "dast",
        description: "Full-featured web app scanner — DOM analysis, intelligent crawling, proof-of-concept payloads",
        speed: "slow",
        depth: "comprehensive",
        bestFor: "Thorough web application assessment, DOM-based vulns",
        icon: "🕷️",
      },
      {
        id: "ssh-audit",
        name: "SSH Audit",
        type: "service",
        description: "SSH server security audit — algorithm strength, CVE detection, auth method enumeration",
        speed: "fast",
        depth: "deep",
        bestFor: "SSH hardening assessment, compliance checks",
        icon: "🔐",
      },
      {
        id: "ftp-audit",
        name: "FTP Audit",
        type: "service",
        description: "FTP server security audit — anonymous access, bounce attacks, default credentials, CVE detection",
        speed: "fast",
        depth: "deep",
        bestFor: "FTP security assessment, anonymous access detection",
        icon: "📁",
      },
    ];
  }),
});
