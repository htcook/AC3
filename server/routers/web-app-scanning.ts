import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const webAppScanningRouter = router({
  /** Check if ZAP is reachable */
  health: protectedProcedure.query(async () => {
    const { checkZapHealth } = await import("../lib/zap-scanner");
    return checkZapHealth();
  }),

  /** Generate LLM-powered scan configuration for a target */
  generateScanConfig: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      scanMode: z.enum(["passive", "active"]),
      techStackHints: z.array(z.string()).optional(),
      authHints: z.object({
        type: z.string(),
        loginUrl: z.string().optional(),
        credentials: z.record(z.string(), z.string()).optional(),
      }).optional(),
      scopeConstraints: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { generateLLMScanConfig } = await import("../lib/zap-scanner");
      return generateLLMScanConfig(input);
    }),

  /** Import OpenAPI/Swagger spec into ZAP */
  importOpenApiSpec: protectedProcedure
    .input(z.object({
      specUrl: z.string().url(),
      targetUrl: z.string().url().optional(),
    }))
    .mutation(async ({ input }) => {
      const { importOpenApiSpec } = await import("../lib/zap-scanner");
      return importOpenApiSpec({
        specUrl: input.specUrl,
        targetUrl: input.targetUrl,
      });
    }),

  /** Import GraphQL endpoint/schema into ZAP */
  importGraphQLSpec: protectedProcedure
    .input(z.object({
      endpointUrl: z.string().url().optional(),
      schemaUrl: z.string().url().optional(),
      targetUrl: z.string().url().optional(),
      maxQueryDepth: z.number().min(1).max(20).optional(),
    }))
    .mutation(async ({ input }) => {
      const { importGraphQLSpec } = await import("../lib/zap-scanner");
      return importGraphQLSpec({
        endpointUrl: input.endpointUrl,
        schemaUrl: input.schemaUrl,
        targetUrl: input.targetUrl,
        maxQueryDepth: input.maxQueryDepth,
      });
    }),

  /** Import SOAP/WSDL spec into ZAP */
  importSoapSpec: protectedProcedure
    .input(z.object({
      wsdlUrl: z.string().url(),
    }))
    .mutation(async ({ input }) => {
      const { importSoapSpec } = await import("../lib/zap-scanner");
      return importSoapSpec({ wsdlUrl: input.wsdlUrl });
    }),

  /** Start a new dual-mode web application scan */
  startScan: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      scanType: z.enum(["spider_only", "active", "full"]).default("full"),
      scanMode: z.enum(["passive", "active"]).default("passive"),
      scanName: z.string().optional(),
      attackChainId: z.string().optional(),
      calderaOperationId: z.string().optional(),
      metasploitSessionId: z.string().optional(),
      domainIntelScanId: z.number().optional(),
      useLLMConfig: z.boolean().default(true),
      techStackHints: z.array(z.string()).optional(),
      openApiSpecUrl: z.string().url().optional(),
      graphqlEndpointUrl: z.string().url().optional(),
      graphqlSchemaUrl: z.string().url().optional(),
      soapWsdlUrl: z.string().url().optional(),
      discoveredTechnologies: z.array(z.string()).optional(),
      playbookPhase: z.enum(["crawling", "fingerprinting", "secrets_hunting", "injection_testing", "foothold_acquisition", "api_testing", "full"]).optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate target URL ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.targetUrl, "ZAP Web App Scan", ctx);
      }
      const { startScan, generateLLMScanConfig } = await import("../lib/zap-scanner");

      let llmConfig;
      if (input.useLLMConfig) {
        llmConfig = await generateLLMScanConfig({
          targetUrl: input.targetUrl,
          scanMode: input.scanMode,
          techStackHints: input.techStackHints,
        });
      }

      const scanResult = await startScan({
        targetUrl: input.targetUrl,
        scanType: input.scanType,
        scanMode: input.scanMode,
        userId: String(ctx.user.id),
        scanName: input.scanName,
        llmConfig,
        attackChainId: input.attackChainId,
        calderaOperationId: input.calderaOperationId,
        metasploitSessionId: input.metasploitSessionId,
        domainIntelScanId: input.domainIntelScanId,
        openApiSpecUrl: input.openApiSpecUrl,
        graphqlEndpointUrl: input.graphqlEndpointUrl,
        graphqlSchemaUrl: input.graphqlSchemaUrl,
        soapWsdlUrl: input.soapWsdlUrl,
        discoveredTechnologies: input.discoveredTechnologies || input.techStackHints,
        playbookPhase: input.playbookPhase,
      });
      // Auto-persist to timeline + OPSEC
      try {
        const { recordScan } = await import("../lib/auto-persistence");
        await recordScan({
          engagementId: input.engagementId ? String(input.engagementId) : undefined,
          actionName: `ZAP ${input.scanType} scan`,
          description: `${input.scanType} web app scan on ${input.targetUrl} (${input.scanMode} mode)`,
          source: "zap-scanner",
          target: input.targetUrl,
          success: true,
          resultData: { scanType: input.scanType, scanMode: input.scanMode },
        });
      } catch (e) { /* non-blocking */ }
      return scanResult;
    }),

  /** Poll scan progress */
  pollProgress: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { pollScanProgress } = await import("../lib/zap-scanner");
      return pollScanProgress(input.scanId);
    }),

  /** Stop a running scan */
  stopScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(async ({ input }) => {
      const { stopScan } = await import("../lib/zap-scanner");
      return stopScan(input.scanId);
    }),

  /** List all scans with optional mode filter */
  listScans: protectedProcedure
    .input(z.object({
      status: z.string().optional(),
      scanMode: z.string().optional(),
      limit: z.number().min(1).max(100).optional(),
    }).optional())
    .query(async ({ input }) => {
      const { listScans } = await import("../lib/zap-scanner");
      return listScans(input);
    }),

  /** Get findings for a specific scan */
  getFindings: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      severity: z.string().optional(),
      limit: z.number().min(1).max(500).optional(),
    }))
    .query(async ({ input }) => {
      const { getScanFindings } = await import("../lib/zap-scanner");
      return getScanFindings(input.scanId, { severity: input.severity, limit: input.limit });
    }),

  /** AI-powered triage for a specific finding */
  triageFinding: protectedProcedure
    .input(z.object({
      findingId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { triageFinding } = await import("../lib/zap-scanner");
      const { getDb } = await import("../db");
      const { webAppFindings } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [finding] = await db.select().from(webAppFindings).where(eq(webAppFindings.id, input.findingId));
      if (!finding) throw new TRPCError({ code: "NOT_FOUND", message: "Finding not found" });

      const result = await triageFinding({
        alertName: finding.alertName || "",
        severity: finding.severity || "info",
        url: finding.url || "",
        param: finding.param || undefined,
        evidence: finding.evidence || undefined,
        description: finding.description || undefined,
        cweId: finding.cweId || undefined,
      });

      // Update finding with triage results
      await db.update(webAppFindings).set({
        aiTriageVerdict: result.verdict,
        aiTriageReason: result.reason,
        falsePositiveScore: result.falsePositiveScore,
      }).where(eq(webAppFindings.id, input.findingId));

      return result;
    }),

  /** Batch AI triage for all findings in a scan */
  batchTriage: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(async ({ input }) => {
      const { triageFinding, getScanFindings } = await import("../lib/zap-scanner");
      const { getDb } = await import("../db");
      const { webAppFindings } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const findings = await getScanFindings(input.scanId, { limit: 100 });
      const results: { findingId: number; verdict: string }[] = [];

      // Triage high/medium findings only (skip info/low for speed)
      const priorityFindings = findings.filter((f: any) =>
        f.severity === "high" || f.severity === "medium" || f.severity === "critical"
      );

      for (const finding of priorityFindings) {
        try {
          const result = await triageFinding({
            alertName: finding.alertName || "",
            severity: finding.severity || "info",
            url: finding.url || "",
            param: finding.param || undefined,
            evidence: finding.evidence || undefined,
            description: finding.description || undefined,
            cweId: finding.cweId || undefined,
          });

          await db.update(webAppFindings).set({
            aiTriageVerdict: result.verdict,
            aiTriageReason: result.reason,
            falsePositiveScore: result.falsePositiveScore,
          }).where(eq(webAppFindings.id, finding.id));

          results.push({ findingId: finding.id, verdict: result.verdict });
        } catch {
          results.push({ findingId: finding.id, verdict: "error" });
        }
      }

      // ─── SSIL: Auto-ingest ZAP findings into observation normalizer ───
      try {
        const { ingestVulnScanImportFindings } = await import("../lib/observation-ingestor");
        const zapFindings = findings.map((f: any) => ({
          hostIp: new URL(f.url || 'http://unknown').hostname,
          port: parseInt(new URL(f.url || 'http://unknown').port) || (f.url?.startsWith('https') ? 443 : 80),
          title: f.alertName || f.name || 'ZAP Finding',
          severity: f.severity || 'info',
          description: f.description,
          solution: f.solution,
          cveId: f.cweId ? `CWE-${f.cweId}` : null,
          importId: input.scanId,
        }));
        const ingestion = await ingestVulnScanImportFindings(zapFindings);
        console.log(`[WebAppScan→SSIL] Ingested ${ingestion.observations} observations, ${ingestion.signals} signals, ${ingestion.riskCards} risk cards`);
      } catch (err: any) {
        console.error(`[WebAppScan→SSIL] Ingestion failed (non-fatal): ${err.message}`);
      }

      return { triaged: results.length, results };
    }),

  /** Get aggregate scan statistics */
  stats: protectedProcedure.query(async () => {
    const { getScanStats } = await import("../lib/zap-scanner");
    return getScanStats();
  }),

  /** Delete a scan and its findings */
  deleteScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(async ({ input }) => {
      const { deleteScan } = await import("../lib/zap-scanner");
      return deleteScan(input.scanId);
    }),

  /** Seed demo data */
  seedDemo: protectedProcedure.mutation(async () => {
    const { seedDemoData } = await import("../lib/zap-scanner");
    return seedDemoData();
  }),

  /** Clear demo data */
  clearDemo: protectedProcedure.mutation(async () => {
    const { clearDemoData } = await import("../lib/zap-scanner");
    return clearDemoData();
  }),

  /** Export scan report as HTML (for PDF printing) */
  exportReport: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { getScanFindings, listScans } = await import("../lib/zap-scanner");
      const { generateReportHtml: generateReport } = await import("../lib/pdf-report-generator");

      const scans = await listScans();
      const scan = scans.find((s: any) => s.id === input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const findings = await getScanFindings(input.scanId, { limit: 500 });
      const alertCounts = JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}');
      const techStack = scan.detectedTechStack ? JSON.parse(scan.detectedTechStack) : [];

      const sections = [
        {
          title: "Scan Summary",
          content: `
            <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Target URL</td><td style="padding:6px; border:1px solid #ddd;">${scan.targetUrl}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Scan Mode</td><td style="padding:6px; border:1px solid #ddd;">${scan.scanMode === "passive" ? "🔍 Passive Recon" : "⚡ Active DAST"}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Scan Type</td><td style="padding:6px; border:1px solid #ddd;">${scan.scanType}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Status</td><td style="padding:6px; border:1px solid #ddd;">${scan.status}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">URLs Discovered</td><td style="padding:6px; border:1px solid #ddd;">${scan.urlsDiscovered || 0}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Tech Stack</td><td style="padding:6px; border:1px solid #ddd;">${techStack.length > 0 ? techStack.join(", ") : "Not detected"}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Started</td><td style="padding:6px; border:1px solid #ddd;">${scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "N/A"}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Completed</td><td style="padding:6px; border:1px solid #ddd;">${scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "In Progress"}</td></tr>
              ${scan.attackChainId ? `<tr><td style="padding:6px; border:1px solid #ddd; font-weight:bold;">Attack Chain</td><td style="padding:6px; border:1px solid #ddd;">${scan.attackChainId}</td></tr>` : ""}
            </table>
            <h4>Alert Summary</h4>
            <table style="width:100%; border-collapse:collapse;">
              <tr style="background:#f5f5f5;"><th style="padding:6px; border:1px solid #ddd;">Severity</th><th style="padding:6px; border:1px solid #ddd;">Count</th></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; color:#dc2626;">High</td><td style="padding:6px; border:1px solid #ddd;">${alertCounts.high}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; color:#f59e0b;">Medium</td><td style="padding:6px; border:1px solid #ddd;">${alertCounts.medium}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; color:#3b82f6;">Low</td><td style="padding:6px; border:1px solid #ddd;">${alertCounts.low}</td></tr>
              <tr><td style="padding:6px; border:1px solid #ddd; color:#6b7280;">Info</td><td style="padding:6px; border:1px solid #ddd;">${alertCounts.info}</td></tr>
            </table>`,
        },
        {
          title: "MITRE ATT&CK Mapping",
          content: (() => {
            const mitreFindings = findings.filter((f: any) => f.mitreAttackId);
            if (mitreFindings.length === 0) return "<p>No MITRE ATT&CK mappings for this scan.</p>";
            const grouped = new Map<string, any[]>();
            for (const f of mitreFindings) {
              const key = `${f.mitreAttackId} — ${f.mitreAttackName}`;
              if (!grouped.has(key)) grouped.set(key, []);
              grouped.get(key)!.push(f);
            }
            return Array.from(grouped.entries()).map(([technique, items]) => `
              <div style="margin-bottom:12px; padding:8px; border-left:3px solid #dc2626;">
                <strong>${technique}</strong> <span style="color:#888;">(${items[0].mitreTactic})</span>
                <ul style="margin:4px 0; padding-left:20px;">
                  ${items.map((i: any) => `<li>${i.alertName} — ${i.url}</li>`).join("")}
                </ul>
              </div>`).join("");
          })(),
        },
        {
          title: "Findings Detail",
          content: findings.length === 0
            ? "<p>No findings recorded for this scan.</p>"
            : findings.map((f: any, i: number) => `
              <div style="margin-bottom:16px; padding:12px; border:1px solid #e5e7eb; border-radius:6px;">
                <h4 style="margin:0 0 8px;">${i + 1}. ${f.alertName || "Unknown Alert"}</h4>
                <table style="width:100%; border-collapse:collapse; font-size:13px;">
                  <tr><td style="padding:4px; width:140px; font-weight:bold;">Severity</td><td style="padding:4px;">${f.severity}</td></tr>
                  <tr><td style="padding:4px; font-weight:bold;">Confidence</td><td style="padding:4px;">${Math.round((f.confidence || 0) * 100)}%</td></tr>
                  <tr><td style="padding:4px; font-weight:bold;">URL</td><td style="padding:4px; word-break:break-all;">${f.url || "N/A"}</td></tr>
                  ${f.param ? `<tr><td style="padding:4px; font-weight:bold;">Parameter</td><td style="padding:4px;">${f.param}</td></tr>` : ""}
                  ${f.cweId ? `<tr><td style="padding:4px; font-weight:bold;">CWE</td><td style="padding:4px;">CWE-${f.cweId}</td></tr>` : ""}
                  ${f.mitreAttackId ? `<tr><td style="padding:4px; font-weight:bold;">MITRE ATT&CK</td><td style="padding:4px;">${f.mitreAttackId} — ${f.mitreAttackName}</td></tr>` : ""}
                  ${f.exploitAvailable ? `<tr><td style="padding:4px; font-weight:bold;">Exploit Module</td><td style="padding:4px; color:#dc2626;">${f.exploitModulePath}</td></tr>` : ""}
                  ${f.aiTriageVerdict ? `<tr><td style="padding:4px; font-weight:bold;">AI Triage</td><td style="padding:4px;">${f.aiTriageVerdict} (FP Score: ${Math.round((f.falsePositiveScore || 0) * 100)}%)</td></tr>` : ""}
                  ${f.description ? `<tr><td style="padding:4px; font-weight:bold;">Description</td><td style="padding:4px;">${f.description.substring(0, 500)}</td></tr>` : ""}
                  ${f.solution ? `<tr><td style="padding:4px; font-weight:bold;">Solution</td><td style="padding:4px;">${f.solution.substring(0, 500)}</td></tr>` : ""}
                </table>
              </div>`).join(""),
        },
      ];

      const { generateReportFromZapApi } = await import("../lib/zap-report-generator");
      // Use the new themed report generator
      const themedHtml = await generateReportFromZapApi(input.scanId, "full");
      return themedHtml;
      /* Legacy report generation kept as fallback:
      return generateReport({
        title: `Web Application Scan Report — ${scan.scanName || scan.targetUrl}`,
        subtitle: `OWASP ZAP ${scan.scanMode === "passive" ? "Passive Recon" : "Active DAST"} Scan`,
        generatedAt: new Date(),
        sections,
      });
      */
    }),

  // ─── ZAP Proxy Orchestration ────────────────────────────────────────────

  /** Initialize a ZAP proxy session for interactive web app testing */
  initProxySession: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      contextName: z.string().optional(),
      proxyPort: z.number().optional(),
      httpsInterception: z.boolean().optional(),
      wafVendor: z.string().optional(),
      authType: z.enum(["form_based", "json_api", "http_basic", "bearer_token", "manual_browse"]).optional(),
      loginUrl: z.string().optional(),
      usernameField: z.string().optional(),
      passwordField: z.string().optional(),
      credentials: z.array(z.object({
        username: z.string(),
        password: z.string(),
        role: z.string().optional(),
      })).optional(),
      loggedInIndicator: z.string().optional(),
      loggedOutIndicator: z.string().optional(),
      bearerToken: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { initializeProxySession } = await import("../lib/zap-proxy-orchestrator");
      return initializeProxySession({
        targetUrl: input.targetUrl,
        contextName: input.contextName,
        proxyConfig: input.proxyPort ? { listenPort: input.proxyPort, listenAddress: "0.0.0.0", httpsInterception: input.httpsInterception ?? true } : undefined,
        wafVendor: input.wafVendor,
        authConfig: input.authType ? {
          type: input.authType,
          loginUrl: input.loginUrl || input.targetUrl,
          usernameField: input.usernameField,
          passwordField: input.passwordField,
          credentials: input.credentials || [],
          loggedInIndicator: input.loggedInIndicator,
          loggedOutIndicator: input.loggedOutIndicator,
          bearerToken: input.bearerToken,
        } : undefined,
      });
    }),

  /** Start authenticated spider crawl through ZAP proxy */
  startAuthCrawl: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      useAjaxSpider: z.boolean().optional(),
      maxDepth: z.number().optional(),
      subtreeOnly: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { startAuthenticatedCrawl } = await import("../lib/zap-proxy-orchestrator");
      return startAuthenticatedCrawl(input.sessionId, {
        useAjaxSpider: input.useAjaxSpider,
        maxDepth: input.maxDepth,
        subtreeOnly: input.subtreeOnly,
      });
    }),

  /** Get proxy session status */
  getProxySessionStatus: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const { getProxySessionStatus } = await import("../lib/zap-proxy-orchestrator");
      return getProxySessionStatus(input.sessionId);
    }),

  /** Stop a proxy session */
  stopProxySession: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { stopProxySession } = await import("../lib/zap-proxy-orchestrator");
      return stopProxySession(input.sessionId);
    }),

  /** List active proxy sessions */
  listProxySessions: protectedProcedure.query(async () => {
    const { listActiveSessions } = await import("../lib/zap-proxy-orchestrator");
    return listActiveSessions();
  }),

  /** Detect login form configuration using LLM */
  detectLoginForm: protectedProcedure
    .input(z.object({ loginPageUrl: z.string().url() }))
    .mutation(async ({ input }) => {
      const { detectLoginConfiguration } = await import("../lib/zap-proxy-orchestrator");
      return detectLoginConfiguration(input.loginPageUrl);
    }),

  /** Apply WAF evasion settings based on detection results */
  applyWafEvasion: protectedProcedure
    .input(z.object({
      wafDetected: z.boolean(),
      wafVendor: z.string().optional(),
      wafConfidence: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { applyWafEvasionSettings } = await import("../lib/zap-proxy-orchestrator");
      return applyWafEvasionSettings(input);
    }),

  /** Get WAF evasion presets for UI display */
  getWafEvasionPresets: protectedProcedure.query(async () => {
    const { getWafEvasionPresets } = await import("../lib/zap-proxy-orchestrator");
    return getWafEvasionPresets();
  }),

  /** Get ZAP proxy history */
  getProxyHistory: protectedProcedure
    .input(z.object({
      start: z.number().optional(),
      count: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getProxyHistory } = await import("../lib/zap-proxy-orchestrator");
      return getProxyHistory(input);
    }),

  /** Get ZAP CA certificate for HTTPS interception */
  getCaCertificate: protectedProcedure.query(async () => {
    const { getCaCertificate } = await import("../lib/zap-proxy-orchestrator");
    return getCaCertificate();
  }),

  /** Generate themed HTML report from scan data */
  generateThemedReport: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      reportType: z.enum(["executive", "technical", "compliance", "credential", "full"]).optional(),
      engagement: z.object({
        clientName: z.string(),
        engagementName: z.string(),
        startDate: z.string(),
        endDate: z.string(),
        scopeDescription: z.string(),
        testerName: z.string(),
        testerOrg: z.string(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const { generateReportFromZapApi } = await import("../lib/zap-report-generator");
      return generateReportFromZapApi(input.scanId, input.reportType || "full", input.engagement);
    }),

  // ─── Credential Attack Engine ──────────────────────────────────────────

  /** Get available password lists */
  getPasswordLists: protectedProcedure.query(async () => {
    const { getPasswordLists } = await import("../lib/credential-attack-engine");
    return getPasswordLists();
  }),

  /** Get available username lists */
  getUsernameLists: protectedProcedure.query(async () => {
    const { getUsernameLists } = await import("../lib/credential-attack-engine");
    return getUsernameLists();
  }),

  /** Get default credentials for a specific protocol/port */
  getDefaultCredentials: protectedProcedure
    .input(z.object({
      protocol: z.string(),
      port: z.number(),
    }))
    .query(async ({ input }) => {
      const { getDefaultCredentialsForTarget } = await import("../lib/credential-attack-engine");
      return getDefaultCredentialsForTarget(input.protocol as any, input.port);
    }),

  /** Detect web login form for brute force configuration */
  detectWebLoginForm: protectedProcedure
    .input(z.object({ url: z.string().url() }))
    .mutation(async ({ input }) => {
      const { detectWebLoginForm } = await import("../lib/credential-attack-engine");
      return detectWebLoginForm(input.url);
    }),

  /** Generate targeted password list based on org info */
  generateTargetedPasswords: protectedProcedure
    .input(z.object({
      companyName: z.string(),
      domain: z.string(),
      industry: z.string().optional(),
      foundedYear: z.number().optional(),
      city: z.string().optional(),
      state: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { generateTargetedPasswordList } = await import("../lib/credential-attack-engine");
      return generateTargetedPasswordList(input);
    }),

  /** Execute a credential attack (brute force, spray, stuffing, default creds) */
  executeCredentialAttack: protectedProcedure
    .input(z.object({
      mode: z.enum(["brute_force", "password_spray", "credential_stuffing", "default_creds", "dictionary"]),
      host: z.string(),
      port: z.number(),
      protocol: z.string(),
      loginUrl: z.string().optional(),
      loginFormAction: z.string().optional(),
      usernameField: z.string().optional(),
      passwordField: z.string().optional(),
      csrfTokenName: z.string().optional(),
      successIndicator: z.string().optional(),
      failureIndicator: z.string().optional(),
      contentType: z.enum(["form", "json"]).optional(),
      usernames: z.array(z.string()).optional(),
      passwords: z.array(z.string()).optional(),
      credentialPairs: z.array(z.object({
        username: z.string(),
        password: z.string(),
        source: z.string().optional(),
      })).optional(),
      passwordListName: z.string().optional(),
      maxRequestsPerSecond: z.number().optional(),
      delayBetweenAttemptsMs: z.number().optional(),
      maxAttemptsPerUser: z.number().optional(),
      lockoutDetection: z.boolean().optional(),
      maxTotalAttempts: z.number().optional(),
      stopOnFirstSuccess: z.boolean().optional(),
      globalTimeoutSec: z.number().optional(),
      sprayDelayBetweenPasswordsSec: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { executeCredentialAttack } = await import("../lib/credential-attack-engine");
      return executeCredentialAttack({
        mode: input.mode,
        target: {
          host: input.host,
          port: input.port,
          protocol: input.protocol as any,
          loginUrl: input.loginUrl,
          loginFormAction: input.loginFormAction,
          usernameField: input.usernameField,
          passwordField: input.passwordField,
          csrfTokenName: input.csrfTokenName,
          successIndicator: input.successIndicator,
          failureIndicator: input.failureIndicator,
          contentType: input.contentType,
        },
        usernames: input.usernames,
        passwords: input.passwords,
        credentialPairs: input.credentialPairs,
        passwordListName: input.passwordListName,
        maxRequestsPerSecond: input.maxRequestsPerSecond || 5,
        delayBetweenAttemptsMs: input.delayBetweenAttemptsMs || 500,
        jitterMs: 200,
        maxAttemptsPerUser: input.maxAttemptsPerUser || 10,
        lockoutDetection: input.lockoutDetection ?? true,
        lockoutThreshold: 5,
        lockoutCooldownSec: 60,
        sprayDelayBetweenPasswordsSec: input.sprayDelayBetweenPasswordsSec,
        maxTotalAttempts: input.maxTotalAttempts || 1000,
        timeoutPerAttemptMs: 10000,
        globalTimeoutSec: input.globalTimeoutSec || 600,
        stopOnFirstSuccess: input.stopOnFirstSuccess ?? false,
      });
    }),

  // ─── Credential Finding Storage ───
  saveCredentialFindings: protectedProcedure
    .input(z.object({
      attackRunId: z.number(),
      targetHost: z.string(),
      targetPort: z.number(),
      protocol: z.string(),
      attackMode: z.string(),
      domainScanId: z.number().optional(),
      findings: z.array(z.object({
        username: z.string(),
        password: z.string(),
        success: z.boolean(),
        responseCode: z.number().optional(),
        responseTime: z.number().optional(),
        notes: z.string().optional(),
      })),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await import('../db');
      // Create attack run record
      const runId = await db.createCredentialAttackRun({
        userId: ctx.user.id,
        targetHost: input.targetHost,
        targetPort: input.targetPort,
        protocol: input.protocol,
        attackMode: input.attackMode,
        domainScanId: input.domainScanId ?? null,
        status: 'completed',
        totalAttempts: input.findings.length,
        successfulAttempts: input.findings.filter(f => f.success).length,
        startedAt: new Date(),
        completedAt: new Date(),
      });
      // Store findings
      if (input.findings.length > 0) {
        await db.createCredentialFindings(input.findings.map(f => ({
          attackRunId: runId,
          username: f.username,
          password: f.password,
          success: f.success,
          responseCode: f.responseCode ?? null,
          responseTimeMs: f.responseTime ?? null,
          notes: f.notes ?? null,
        })));
      }
      return { runId, findingsStored: input.findings.length };
    }),

  listCredentialRuns: protectedProcedure.query(async ({ ctx }) => {
    const db = await import('../db');
    return db.getCredentialAttackRuns(ctx.user.id);
  }),

  getCredentialRunFindings: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const db = await import('../db');
      return db.getCredentialFindingsByRun(input.runId);
    }),

  // ─── ZAP Proxy Session Storage ───
  saveZapSession: protectedProcedure
    .input(z.object({
      targetUrl: z.string(),
      proxyPort: z.number(),
      sessionName: z.string().optional(),
      authType: z.string().optional(),
      domainScanId: z.number().optional(),
      status: z.string().default('active'),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await import('../db');
      return db.createZapProxySession({
        userId: ctx.user.id,
        targetUrl: input.targetUrl,
        proxyPort: input.proxyPort,
        sessionName: input.sessionName ?? `ZAP-${Date.now()}`,
        authType: input.authType ?? null,
        domainScanId: input.domainScanId ?? null,
        status: input.status,
        startedAt: new Date(),
      });
    }),

  listZapSessions: protectedProcedure.query(async ({ ctx }) => {
    const db = await import('../db');
    return db.getZapProxySessions(ctx.user.id);
  }),

  // ─── Pentest Report Storage ───
  savePentestReport: protectedProcedure
    .input(z.object({
      title: z.string(),
      reportType: z.string(),
      engagementId: z.number().optional(),
      domainScanId: z.number().optional(),
      htmlContent: z.string(),
      classification: z.string().default('confidential'),
      preparedFor: z.string().optional(),
      preparedBy: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await import('../db');
      return db.createPentestReport({
        userId: ctx.user.id,
        title: input.title,
        reportType: input.reportType,
        engagementId: input.engagementId ?? null,
        domainScanId: input.domainScanId ?? null,
        htmlContent: input.htmlContent,
        classification: input.classification,
        preparedFor: input.preparedFor ?? null,
        preparedBy: input.preparedBy ?? ctx.user.name ?? 'C3 Platform',
        createdAt: new Date(),
      });
    }),

  listPentestReports: protectedProcedure.query(async ({ ctx }) => {
    const db = await import('../db');
    return db.getPentestReports(ctx.user.id);
  }),

  getPentestReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await import('../db');
      const report = await db.getPentestReportById(input.id);
      if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
      return report;
    }),

  deletePentestReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await import('../db');
      await db.deletePentestReport(input.id);
      return { success: true };
    }),

  // ─── External Credential Attack Tools (Hydra / Medusa / NetExec) ──────

  /** Detect which external credential tools are installed */
  detectExternalTools: protectedProcedure.query(async () => {
    const { detectAllTools } = await import("../lib/external-credential-tools");
    return detectAllTools();
  }),

  /** Get detailed capability info for all credential attack tools */
  getToolCapabilities: protectedProcedure.query(async () => {
    const { getToolCapabilities } = await import("../lib/external-credential-tools");
    return getToolCapabilities();
  }),

  /** Get the full tool knowledge base (for UI display and transparency) */
  getToolKnowledgeBase: protectedProcedure.query(async () => {
    const { getToolKnowledgeBase } = await import("../lib/external-credential-tools");
    const kb = getToolKnowledgeBase();
    // Serialize for transport (strip regex patterns)
    return {
      hydra: {
        fullName: kb.hydra.fullName,
        license: kb.hydra.license,
        description: kb.hydra.description,
        strengths: kb.hydra.strengths,
        weaknesses: kb.hydra.weaknesses,
        bestFor: kb.hydra.bestFor,
        avoidFor: kb.hydra.avoidFor,
        commandExamples: kb.hydra.commandExamples,
        protocols: kb.hydra.protocols.native,
      },
      medusa: {
        fullName: kb.medusa.fullName,
        license: kb.medusa.license,
        description: kb.medusa.description,
        strengths: kb.medusa.strengths,
        weaknesses: kb.medusa.weaknesses,
        bestFor: kb.medusa.bestFor,
        avoidFor: kb.medusa.avoidFor,
        commandExamples: kb.medusa.commandExamples,
        protocols: kb.medusa.protocols.native,
      },
      netexec: {
        fullName: kb.netexec.fullName,
        license: kb.netexec.license,
        description: kb.netexec.description,
        strengths: kb.netexec.strengths,
        weaknesses: kb.netexec.weaknesses,
        bestFor: kb.netexec.bestFor,
        avoidFor: kb.netexec.avoidFor,
        commandExamples: kb.netexec.commandExamples,
        protocols: kb.netexec.protocols.native,
        adAttackTypes: kb.netexec.adAttackTypes,
      },
    };
  }),

  /** LLM-powered tool recommendation for a given attack scenario */
  recommendAttackTool: protectedProcedure
    .input(z.object({
      targetHost: z.string(),
      targetPort: z.number(),
      protocol: z.string(),
      attackMode: z.string(),
      isActiveDirectory: z.boolean().optional(),
      hasNtlmHash: z.boolean().optional(),
      isMultiHost: z.boolean().optional(),
      hasWaf: z.boolean().optional(),
      targetOs: z.enum(["windows", "linux", "unknown"]).optional(),
      needsPostExploit: z.boolean().optional(),
      connectionStability: z.enum(["stable", "flaky", "unknown"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { recommendTool } = await import("../lib/external-credential-tools");
      return recommendTool(input);
    }),

  /** Quick (non-LLM) tool recommendation based on protocol */
  quickToolRecommendation: protectedProcedure
    .input(z.object({
      protocol: z.string(),
      isActiveDirectory: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      const { quickToolRecommendation } = await import("../lib/external-credential-tools");
      return { recommended: quickToolRecommendation(input.protocol, input.isActiveDirectory) };
    }),

  /** Execute a credential attack using an external tool */
  executeExternalAttack: protectedProcedure
    .input(z.object({
      tool: z.enum(["hydra", "medusa", "netexec"]),
      host: z.string(),
      port: z.number(),
      protocol: z.string(),
      loginUrl: z.string().optional(),
      httpMethod: z.enum(["GET", "POST"]).optional(),
      formParams: z.string().optional(),
      successString: z.string().optional(),
      failureString: z.string().optional(),
      domain: z.string().optional(),
      ntlmHash: z.string().optional(),
      usernames: z.array(z.string()),
      passwords: z.array(z.string()),
      threads: z.number().optional(),
      timeout: z.number().optional(),
      globalTimeout: z.number().optional(),
      stopOnFirst: z.boolean().optional(),
      delayMs: z.number().optional(),
      extraFlags: z.array(z.string()).optional(),
      netexecModule: z.enum(["smb", "winrm", "ldap", "mssql", "rdp", "ssh", "ftp", "wmi"]).optional(),
      netexecPostAuth: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { executeExternalAttack } = await import("../lib/external-credential-tools");
      const result = await executeExternalAttack({
        tool: input.tool,
        target: {
          host: input.host,
          port: input.port,
          protocol: input.protocol,
          loginUrl: input.loginUrl,
          httpMethod: input.httpMethod,
          formParams: input.formParams,
          successString: input.successString,
          failureString: input.failureString,
          domain: input.domain,
          ntlmHash: input.ntlmHash,
        },
        usernames: input.usernames,
        passwords: input.passwords,
        threads: input.threads || 8,
        timeout: input.timeout || 10,
        globalTimeout: input.globalTimeout || 600,
        stopOnFirst: input.stopOnFirst ?? false,
        delayMs: input.delayMs,
        extraFlags: input.extraFlags,
        netexecModule: input.netexecModule,
        netexecPostAuth: input.netexecPostAuth,
      });
      // Auto-persist to timeline + OPSEC
      try {
        const { recordCredentialAttack } = await import("../lib/auto-persistence");
        await recordCredentialAttack({
          actionName: `${input.tool} credential attack`,
          description: `${input.tool} attack on ${input.host}:${input.port} (${input.protocol}) — ${result.successes?.length || 0} credentials found`,
          source: input.tool,
          target: `${input.host}:${input.port}`,
          success: (result.successes?.length || 0) > 0,
          resultData: { protocol: input.protocol, credentialsFound: result.successes?.length || 0 },
        });
      } catch (e) { /* non-blocking */ }
      return result;
    }),

  /** Clear the tool detection cache (after installing new tools) */
  refreshToolDetection: protectedProcedure.mutation(async () => {
    const { clearToolDetectionCache, detectAllTools } = await import("../lib/external-credential-tools");
    clearToolDetectionCache();
    return detectAllTools();
  }),

  // ── Attack History & Persistence ─────────────────────────────────────────

  /** Get credential attack history with filters */
  getAttackHistory: protectedProcedure
    .input(z.object({
      tool: z.string().optional(),
      protocol: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ ctx, input }) => {
      const { getCredentialAttackHistory, getCredentialAttackHistoryCount } = await import("../db");
      const [runs, total] = await Promise.all([
        getCredentialAttackHistory(ctx.user.id, input),
        getCredentialAttackHistoryCount(ctx.user.id, input),
      ]);
      return { runs, total };
    }),

  /** Get a single attack run with its findings */
  getAttackRunDetail: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ ctx, input }) => {
      const { getCredentialAttackRunById, getCredentialFindingsByRun } = await import("../db");
      const run = await getCredentialAttackRunById(input.id);
      if (!run || run.userId !== ctx.user.id) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Attack run not found" });
      }
      const findings = await getCredentialFindingsByRun(input.id);
      return { run, findings };
    }),

  /** Get all credential findings with filters */
  getCredentialFindings: protectedProcedure
    .input(z.object({
      tool: z.string().optional(),
      protocol: z.string().optional(),
      validationStatus: z.string().optional(),
      limit: z.number().min(1).max(200).default(100),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ ctx, input }) => {
      const { getCredentialFindingsHistory } = await import("../db");
      return getCredentialFindingsHistory(ctx.user.id, input);
    }),

  /** Update finding validation status */
  updateFindingValidation: protectedProcedure
    .input(z.object({
      id: z.number(),
      validationStatus: z.enum(["unvalidated", "validated", "false_positive"]),
      notes: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const { updateCredentialFindingValidation } = await import("../db");
      await updateCredentialFindingValidation(input.id, input.validationStatus, ctx.user.id, input.notes);
      return { success: true };
    }),

  /** Get attack stats summary (grouped by tool) */
  getAttackStats: protectedProcedure.query(async ({ ctx }) => {
    const { getCredentialAttackStats } = await import("../db");
    return getCredentialAttackStats(ctx.user.id);
  }),

  /** Save an attack result (called automatically after attacks complete) */
  saveAttackResult: protectedProcedure
    .input(z.object({
      targetHost: z.string(),
      targetPort: z.number(),
      protocol: z.string(),
      attackMode: z.string(),
      tool: z.string().default("builtin"),
      toolVersion: z.string().optional(),
      totalAttempts: z.number().default(0),
      successfulAttempts: z.number().default(0),
      failedAttempts: z.number().default(0),
      lockoutsDetected: z.number().default(0),
      rateLimitHits: z.number().default(0),
      durationMs: z.number().optional(),
      status: z.string().default("completed"),
      stoppedReason: z.string().optional(),
      rawOutput: z.string().optional(),
      toolMetadata: z.any().optional(),
      targetDomain: z.string().optional(),
      findings: z.array(z.object({
        username: z.string(),
        password: z.string(),
        accessLevel: z.string().optional(),
        responseSnippet: z.string().optional(),
        additionalInfo: z.string().optional(),
      })).default([]),
    }))
    .mutation(async ({ ctx, input }) => {
      const { saveCredentialAttackWithTool, saveCredentialFindingWithTool } = await import("../db");
      
      // Save the attack run
      const runId = await saveCredentialAttackWithTool({
        userId: ctx.user.id,
        targetHost: input.targetHost,
        targetPort: input.targetPort,
        protocol: input.protocol,
        attackMode: input.attackMode as any,
        tool: input.tool,
        toolVersion: input.toolVersion,
        totalAttempts: input.totalAttempts,
        successfulAttempts: input.successfulAttempts,
        failedAttempts: input.failedAttempts,
        lockoutsDetected: input.lockoutsDetected,
        rateLimitHits: input.rateLimitHits,
        durationMs: input.durationMs,
        status: input.status as any,
        stoppedReason: input.stoppedReason,
        rawOutput: input.rawOutput?.substring(0, 50000), // Truncate to 50KB
        toolMetadata: input.toolMetadata,
        targetDomain: input.targetDomain,
      });
      
      // Save individual findings
      for (const finding of input.findings) {
        await saveCredentialFindingWithTool({
          attackRunId: runId,
          userId: ctx.user.id,
          targetHost: input.targetHost,
          targetPort: input.targetPort,
          protocol: input.protocol,
          username: finding.username,
          password: finding.password,
          tool: input.tool,
          accessLevel: (finding.accessLevel as any) ?? "unknown",
          responseSnippet: finding.responseSnippet,
          additionalInfo: finding.additionalInfo,
        });
      }
      
      return { runId, findingsCount: input.findings.length };
    }),
});
