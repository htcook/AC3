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
   * Start an SMTP Audit against a mail server.
   */
  startSMTPAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(25),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(300),
      testRelay: z.boolean().default(true),
      checkDmarc: z.boolean().default(true),
      checkStarttls: z.boolean().default(true),
      enumerateUsers: z.boolean().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "SMTP Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startSmtpAudit } = await import("../lib/scanners/smtp-audit-scanner");
      const result = await startSmtpAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:smtp-audit:complete", {
          scanId: result.scanId,
          target: `${input.host}:${input.port}`,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an SNMP Audit against a target.
   */
  startSNMPAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(161),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(300),
      communityStrings: z.array(z.string()).optional(),
      checkWriteAccess: z.boolean().default(false),
      enumerateOids: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "SNMP Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startSnmpAudit } = await import("../lib/scanners/snmp-audit-scanner");
      const result = await startSnmpAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:snmp-audit:complete", {
          scanId: result.scanId,
          target: `${input.host}:${input.port}`,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an RDP Audit against a target.
   */
  startRDPAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(3389),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(300),
      checkNla: z.boolean().default(true),
      checkBluekeep: z.boolean().default(true),
      checkEncryption: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "RDP Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startRdpAudit } = await import("../lib/scanners/rdp-audit-scanner");
      const result = await startRdpAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:rdp-audit:complete", {
          scanId: result.scanId,
          target: `${input.host}:${input.port}`,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start a DNS Audit against a target DNS server.
   */
  startDNSAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(53),
      domain: z.string().optional(),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(60),
      checkRecursion: z.boolean().default(true),
      checkZoneTransfer: z.boolean().default(true),
      checkDnssec: z.boolean().default(true),
      checkVersion: z.boolean().default(true),
      checkAmplification: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "DNS Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startDNSAudit } = await import("../lib/scanners/dns-audit-scanner");
      const result = await startDNSAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:dns-audit:complete", {
          scanId: result.scanId,
          target: `${input.host}:${input.port}`,
          findingCount: result.findings.length,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start an HTTP Header Audit against a target web server.
   */
  startHTTPHeaderAudit: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().optional(),
      https: z.boolean().default(true),
      path: z.string().default("/"),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(30),
      checkTLS: z.boolean().default(true),
      followRedirects: z.boolean().default(true),
      userAgent: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, [input.host], "HTTP Header Audit", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startHTTPHeaderAudit } = await import("../lib/scanners/http-header-audit-scanner");
      const result = await startHTTPHeaderAudit({
        ...input,
        operatorId: ctx.user?.id,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:http-header-audit:complete", {
          scanId: result.scanId,
          target: result.url,
          findingCount: result.findings.length,
          gradeScore: result.stats.gradeScore,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Start a TLS Deep Scan against a target.
   */
  startTLSDeepScan: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number().default(443),
      engagementId: z.number(),
      timeoutSeconds: z.number().default(120),
      checkDowngrade: z.boolean().default(true),
      checkCVEs: z.boolean().default(true),
      enumerateCiphers: z.boolean().default(true),
      checkCertChain: z.boolean().default(true),
      checkOCSP: z.boolean().default(true),
      sniHostname: z.string().optional(),
      starttls: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      if (input.engagementId) {
        try {
          const { enforceScanTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceScanTargetScope(input.engagementId, input.host, "TLS Deep Scan", ctx);
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
        }
      }

      const { startTLSDeepScan } = await import("../lib/scanners/tls-deep-scanner");
      const result = await startTLSDeepScan({
        host: input.host,
        port: input.port,
        engagementId: input.engagementId,
        operatorId: ctx.user?.id,
        timeoutSeconds: input.timeoutSeconds,
        checkDowngrade: input.checkDowngrade,
        checkCVEs: input.checkCVEs,
        enumerateCiphers: input.enumerateCiphers,
        checkCertChain: input.checkCertChain,
        checkOCSP: input.checkOCSP,
        sniHostname: input.sniHostname,
        starttls: input.starttls,
      });

      try {
        const { wsHub } = await import("../lib/ws-event-hub");
        wsHub.emit("scan:tls-deep-scan:complete", {
          engagementId: input.engagementId,
          target: `${input.host}:${input.port}`,
          findingCount: result.findings.length,
          gradeScore: result.stats.gradeScore,
          gradeLetter: result.stats.gradeLetter,
          status: result.status,
        });
      } catch { /* ws not critical */ }

      return result;
    }),

  /**
   * Compute CARVER+Shock scoring adjustments from DAST/service audit results.
   */
  computeCarverScoring: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      hostname: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      // Fetch all DAST/service audit results for this engagement
      const rows = await db
        .select()
        .from(scanResults)
        .where(
          and(
            eq(scanResults.engagementId, input.engagementId),
            inArray(scanResults.tool, [
              "nikto", "wapiti", "arachni",
              "ssh-audit", "ftp-audit",
              "smtp-audit", "snmp-audit", "rdp-audit",
              "dns-audit", "http-header-audit", "tls-deep-scan",
            ]),
          ),
        );

      if (rows.length === 0) {
        return {
          adjustment: null,
          message: "No DAST/service audit results found for this engagement",
        };
      }

      // Group findings by scanner type
      const pipelineResults: Record<string, any[]> = {};
      for (const row of rows) {
        const tool = row.tool.replace("-audit", "").replace("-", "_");
        if (!pipelineResults[tool]) pipelineResults[tool] = [];
        const findings = typeof row.findings === "string" ? JSON.parse(row.findings) : row.findings;
        pipelineResults[tool].push({
          host: row.target?.split(":")[0] || "unknown",
          port: parseInt(row.target?.split(":")[1] || "0") || 0,
          service: tool,
          findings: Array.isArray(findings) ? findings : findings?.vulnerabilities || findings?.findings || [],
        });
      }

      const { computeDastCarverAdjustment } = await import("../lib/dast-carver-integration");
      const adjustment = computeDastCarverAdjustment(pipelineResults, input.hostname || "unknown");

      return {
        adjustment,
        scansAnalyzed: rows.length,
        message: `Computed CARVER+Shock adjustments from ${rows.length} scan results`,
      };
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
        smtp: z.boolean().default(true),
        snmp: z.boolean().default(true),
        rdp: z.boolean().default(true),
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
      tool: z.enum(["nikto", "wapiti", "arachni", "ssh-audit", "ftp-audit", "smtp-audit", "snmp-audit", "rdp-audit", "dns-audit", "http-header-audit", "tls-deep-scan"]).optional(),
      limit: z.number().default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions = [eq(scanResults.engagementId, input.engagementId)];
      if (input.tool) {
        conditions.push(eq(scanResults.tool, input.tool));
      } else {
        conditions.push(
          inArray(scanResults.tool, [
            "nikto", "wapiti", "arachni",
            "ssh-audit", "ftp-audit",
            "smtp-audit", "snmp-audit", "rdp-audit",
            "dns-audit", "http-header-audit", "tls-deep-scan",
          ])
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
      const db = await getDb();
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
      tool: z.enum(["nikto", "wapiti", "arachni", "ssh-audit", "ftp-audit", "smtp-audit", "snmp-audit", "rdp-audit", "dns-audit", "http-header-audit", "tls-deep-scan"]),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
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
        case "ssh-audit":
        case "ftp-audit":
        case "smtp-audit":
        case "snmp-audit":
        case "rdp-audit":
        case "dns-audit":
        case "http-header-audit":
        case "tls-deep-scan": {
          // Service audits already include analysis in their output
          return {
            analysis: `${input.tool} findings already include built-in analysis`,
            findings: Array.isArray(findings) ? findings : findings?.findings || [],
            tool: input.tool,
          };
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
      {
        id: "smtp-audit",
        name: "SMTP Audit",
        type: "service",
        description: "Mail server security audit — open relay, STARTTLS, DMARC/SPF, VRFY/EXPN user enumeration, CVE detection",
        speed: "fast",
        depth: "deep",
        bestFor: "Mail server hardening, open relay detection, email security compliance",
        icon: "📧",
      },
      {
        id: "snmp-audit",
        name: "SNMP Audit",
        type: "service",
        description: "SNMP security audit — default community strings, write access, OID enumeration, version detection",
        speed: "fast",
        depth: "deep",
        bestFor: "Network device security, community string brute-force, information disclosure",
        icon: "📡",
      },
      {
        id: "rdp-audit",
        name: "RDP Audit",
        type: "service",
        description: "Remote Desktop security audit — NLA enforcement, BlueKeep/DejaBlue CVEs, encryption level, CredSSP",
        speed: "fast",
        depth: "deep",
        bestFor: "Windows RDP hardening, BlueKeep detection, NLA compliance",
        icon: "🖥️",
      },
      {
        id: "dns-audit",
        name: "DNS Audit",
        type: "service",
        description: "DNS server security audit — zone transfer (AXFR), DNSSEC validation, open recursion, version disclosure, cache poisoning, SPF/DMARC",
        speed: "fast",
        depth: "deep",
        bestFor: "DNS hardening, zone transfer detection, DNSSEC compliance, email security",
        icon: "🌐",
      },
      {
        id: "http-header-audit",
        name: "HTTP Header Audit",
        type: "service",
        description: "HTTP security header analysis — HSTS, CSP, X-Frame-Options, CORS, cookie flags, TLS config, server disclosure",
        speed: "fast",
        depth: "deep",
        bestFor: "Web server hardening, security header compliance, OWASP best practices",
        icon: "🛡️",
      },
      {
        id: "tls-deep-scan",
        name: "TLS Deep Scan",
        type: "service",
        description: "Comprehensive SSL/TLS analysis — cipher suites, certificate chain, OCSP stapling, protocol downgrade (Heartbleed, POODLE, DROWN, FREAK, ROBOT), forward secrecy",
        speed: "medium",
        depth: "comprehensive",
        bestFor: "TLS hardening, certificate validation, compliance auditing, vulnerability detection",
        icon: "🔒",
      },
    ];
  }),
});
