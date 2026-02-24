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
        credentials: z.record(z.string()).optional(),
      }).optional(),
      scopeConstraints: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { generateLLMScanConfig } = await import("../lib/zap-scanner");
      return generateLLMScanConfig(input);
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
    }))
    .mutation(async ({ input, ctx }) => {
      const { startScan, generateLLMScanConfig } = await import("../lib/zap-scanner");

      let llmConfig;
      if (input.useLLMConfig) {
        llmConfig = await generateLLMScanConfig({
          targetUrl: input.targetUrl,
          scanMode: input.scanMode,
          techStackHints: input.techStackHints,
        });
      }

      return startScan({
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
      });
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
      const { generateReport } = await import("../lib/pdf-report-generator");

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

      return generateReport({
        title: `Web Application Scan Report — ${scan.scanName || scan.targetUrl}`,
        subtitle: `OWASP ZAP ${scan.scanMode === "passive" ? "Passive Recon" : "Active DAST"} Scan`,
        sections,
      });
    }),
});
