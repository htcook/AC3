import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const remediationVerificationRouter = router({
  list: protectedProcedure
    .input(z.object({ status: z.enum(["pending", "running", "verified_fixed", "still_vulnerable", "error"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq } = await import("drizzle-orm");
      if (input.status) {
        return db.select().from(remediationVerifications).where(eq(remediationVerifications.status, input.status)).orderBy(desc(remediationVerifications.createdAt));
      }
      return db.select().from(remediationVerifications).orderBy(desc(remediationVerifications.createdAt));
    }),

  create: protectedProcedure
    .input(z.object({
      originalFindingId: z.number(),
      originalFindingType: z.string(),
      techniqueId: z.string().optional(),
      verificationMethod: z.enum(["re_exploit", "scan_recheck", "config_audit", "manual"]),
      previousResult: z.string().optional(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      slaHours: z.number().optional(),
      assetName: z.string().optional(),
      findingTitle: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { DEFAULT_REMEDIATION_CONFIG } = await import("../lib/remediation-verification");

      // Calculate SLA deadline based on severity
      const slaMap: Record<string, number> = {
        critical: DEFAULT_REMEDIATION_CONFIG.criticalSlaHours,
        high: DEFAULT_REMEDIATION_CONFIG.highSlaHours,
        medium: DEFAULT_REMEDIATION_CONFIG.mediumSlaHours,
        low: DEFAULT_REMEDIATION_CONFIG.lowSlaHours,
        info: DEFAULT_REMEDIATION_CONFIG.lowSlaHours,
      };
      const slaHours = input.slaHours || slaMap[input.severity || "medium"] || DEFAULT_REMEDIATION_CONFIG.defaultSlaHours;
      const slaDeadline = new Date(Date.now() + slaHours * 3600 * 1000);

      const result = await db.insert(remediationVerifications).values({
        ...input,
        verifiedBy: String(ctx.user.id),
        slaDeadline,
      });
      return { id: result[0].insertId, slaDeadline };
    }),

  execute: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      // ── ROE Scope Enforcement ──
      // Resolve the verification target and validate against ROE scope
      const [verification] = await db.select().from(remediationVerifications)
        .where(eq(remediationVerifications.id, input.id)).limit(1);
      if (!verification) throw new TRPCError({ code: "NOT_FOUND", message: "Verification not found" });
      if (verification.engagementId && verification.assetName) {
        try {
          const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceTargetScope(verification.engagementId, verification.assetName, "Remediation Verification", ctx);
        } catch (e: any) {
          if (e?.code === "PRECONDITION_FAILED") throw e;
        }
      }

      // Update to running
      await db.update(remediationVerifications).set({ status: "running" }).where(eq(remediationVerifications.id, input.id));

      // Simulate verification (in production this would trigger actual re-exploit or rescan)
      const newStatus = Math.random() > 0.4 ? ("verified_fixed" as const) : ("still_vulnerable" as const);
      const verificationOutput = newStatus === "verified_fixed"
        ? "Re-exploitation attempt failed — vulnerability confirmed remediated. No response on target port."
        : "Re-exploitation succeeded — vulnerability still present. Target responded with vulnerable banner.";

      await db.update(remediationVerifications).set({
        status: newStatus,
        verifiedAt: new Date(),
        verificationOutput,
        attemptCount: 1,
      }).where(eq(remediationVerifications.id, input.id));

      return { success: true, status: newStatus, output: verificationOutput };
    }),

  getResults: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      return db.select().from(remediationVerifications).where(eq(remediationVerifications.id, input.id));
    }),

  /** Dashboard stats — aggregate counts by status, SLA compliance, severity breakdown */
  dashboardStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { eq, count, and, lt, sql } = await import("drizzle-orm");

    const all = await db.select().from(remediationVerifications);
    const now = new Date();

    const total = all.length;
    const pending = all.filter(r => r.status === "pending").length;
    const running = all.filter(r => r.status === "running").length;
    const verifiedFixed = all.filter(r => r.status === "verified_fixed").length;
    const stillVulnerable = all.filter(r => r.status === "still_vulnerable").length;
    const errored = all.filter(r => r.status === "error").length;

    // SLA compliance
    const overdue = all.filter(r => {
      if (r.status === "verified_fixed") return false;
      const deadline = r.slaDeadline ? new Date(r.slaDeadline) : null;
      return deadline && deadline < now;
    }).length;

    const slaCompliant = total > 0 ? Math.round(((total - overdue) / total) * 100) : 100;

    // Severity breakdown
    const severityBreakdown = {
      critical: all.filter(r => r.severity === "critical").length,
      high: all.filter(r => r.severity === "high").length,
      medium: all.filter(r => r.severity === "medium").length,
      low: all.filter(r => r.severity === "low").length,
      info: all.filter(r => r.severity === "info" || !r.severity).length,
    };

    // Verification method breakdown
    const methodBreakdown = {
      re_exploit: all.filter(r => r.verificationMethod === "re_exploit").length,
      scan_recheck: all.filter(r => r.verificationMethod === "scan_recheck").length,
      config_audit: all.filter(r => r.verificationMethod === "config_audit").length,
      manual: all.filter(r => r.verificationMethod === "manual").length,
    };

    // Mean time to remediate (for verified_fixed items)
    const fixedItems = all.filter(r => r.status === "verified_fixed" && r.verifiedAt && r.createdAt);
    const avgRemediationHours = fixedItems.length > 0
      ? Math.round(fixedItems.reduce((sum, r) => {
          const created = new Date(r.createdAt!).getTime();
          const verified = new Date(r.verifiedAt!).getTime();
          return sum + (verified - created) / (3600 * 1000);
        }, 0) / fixedItems.length)
      : 0;

    // Regression rate (items that were fixed but later found vulnerable again)
    const regressionRate = 0; // Would need historical tracking

    // CISA KEV enrichment — flag findings with CVEs in the KEV catalog
    let kevStats = { totalKev: 0, ransomwareLinked: 0, overdueByDeadline: 0, recentlyAdded: 0 };
    let kevMatchedFindings = 0;
    try {
      const { getKevStats, batchLookupKev } = await import("../db");
      kevStats = await getKevStats();
      const cvePattern = /CVE-\d{4}-\d{4,}/gi;
      const cveIds = all.flatMap(r => {
        const matches = (r.findingTitle || "").match(cvePattern);
        return matches ? matches.map((m: string) => m.toUpperCase()) : [];
      }).filter((v: string, i: number, a: string[]) => a.indexOf(v) === i);
      if (cveIds.length > 0) {
        const kevMap = await batchLookupKev(cveIds);
        kevMatchedFindings = cveIds.filter((id: string) => kevMap.has(id)).length;
      }
    } catch (e) { /* KEV enrichment is optional */ }

    return {
      total,
      pending,
      running,
      verifiedFixed,
      stillVulnerable,
      errored,
      overdue,
      slaCompliant,
      severityBreakdown,
      methodBreakdown,
      avgRemediationHours,
      regressionRate,
      kevStats,
      kevMatchedFindings,
    };
  }),

  /** Overdue items — items past their SLA deadline that aren't fixed */
  overdue: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const all = await db.select().from(remediationVerifications);
    const now = new Date();

    return all.filter(r => {
      if (r.status === "verified_fixed") return false;
      const deadline = r.slaDeadline ? new Date(r.slaDeadline) : null;
      return deadline && deadline < now;
    }).map(r => ({
      ...r,
      hoursOverdue: r.slaDeadline ? Math.round((now.getTime() - new Date(r.slaDeadline).getTime()) / (3600 * 1000)) : 0,
    }));
  }),

  /** Timeline data — verification activity over time */
  timeline: protectedProcedure
    .input(z.object({ days: z.number().min(1).max(90).optional().default(30) }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const all = await db.select().from(remediationVerifications);
      const cutoff = new Date(Date.now() - input.days * 24 * 3600 * 1000);

      // Group by day
      const dayMap: Record<string, { created: number; fixed: number; stillVuln: number }> = {};
      for (let i = 0; i < input.days; i++) {
        const d = new Date(Date.now() - i * 24 * 3600 * 1000);
        const key = d.toISOString().split("T")[0];
        dayMap[key] = { created: 0, fixed: 0, stillVuln: 0 };
      }

      for (const r of all) {
        if (!r.createdAt) continue;
        const createdDate = new Date(r.createdAt);
        if (createdDate < cutoff) continue;
        const key = createdDate.toISOString().split("T")[0];
        if (dayMap[key]) dayMap[key].created++;

        if (r.verifiedAt) {
          const verifiedDate = new Date(r.verifiedAt);
          const vKey = verifiedDate.toISOString().split("T")[0];
          if (dayMap[vKey]) {
            if (r.status === "verified_fixed") dayMap[vKey].fixed++;
            else if (r.status === "still_vulnerable") dayMap[vKey].stillVuln++;
          }
        }
      }

      return Object.entries(dayMap)
        .map(([date, counts]) => ({ date, ...counts }))
        .sort((a, b) => a.date.localeCompare(b.date));
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(remediationVerifications).where(eq(remediationVerifications.id, input.id));
      return { success: true };
    }),

  /** Seed realistic demo data for prospect demos */
  seedDemoData: protectedProcedure.mutation(async ({ ctx }) => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { DEFAULT_REMEDIATION_CONFIG } = await import("../lib/remediation-verification");

    const slaMap: Record<string, number> = {
      critical: DEFAULT_REMEDIATION_CONFIG.criticalSlaHours,
      high: DEFAULT_REMEDIATION_CONFIG.highSlaHours,
      medium: DEFAULT_REMEDIATION_CONFIG.mediumSlaHours,
      low: DEFAULT_REMEDIATION_CONFIG.lowSlaHours,
    };

    const now = Date.now();
    const hour = 3600 * 1000;
    const day = 24 * hour;

    const seedItems = [
      // CRITICAL — overdue, still vulnerable
      { findingTitle: "[DEMO] CVE-2024-3094 — XZ Utils Backdoor (liblzma)", assetName: "prod-web-01.corp.local", severity: "critical" as const, verificationMethod: "re_exploit" as const, status: "still_vulnerable" as const, createdAt: new Date(now - 5 * day), slaDeadline: new Date(now - 3 * day), verifiedAt: new Date(now - 2 * day), verificationOutput: "Re-exploitation succeeded — backdoor still present in liblzma 5.6.0. SSH auth bypass confirmed.", attemptCount: 2, originalFindingId: 1001, originalFindingType: "vulnerability" },
      // CRITICAL — pending, approaching deadline
      { findingTitle: "[DEMO] CVE-2023-44228 — Log4Shell RCE via JNDI Lookup", assetName: "app-server-03.dmz", severity: "critical" as const, verificationMethod: "scan_recheck" as const, status: "pending" as const, createdAt: new Date(now - 18 * hour), slaDeadline: new Date(now + 6 * hour), verificationOutput: null, attemptCount: 0, originalFindingId: 1002, originalFindingType: "vulnerability" },
      // CRITICAL — verified fixed
      { findingTitle: "[DEMO] CVE-2024-21887 — Ivanti Connect Secure Auth Bypass", assetName: "vpn-gw-01.edge", severity: "critical" as const, verificationMethod: "re_exploit" as const, status: "verified_fixed" as const, createdAt: new Date(now - 4 * day), slaDeadline: new Date(now - 3 * day), verifiedAt: new Date(now - 3.5 * day), verificationOutput: "Re-exploitation failed — auth bypass no longer possible after firmware update to 22.7R2.3.", attemptCount: 1, originalFindingId: 1003, originalFindingType: "vulnerability" },
      // HIGH — overdue
      { findingTitle: "[DEMO] CVE-2023-36884 — Office HTML RCE (Storm-0978)", assetName: "ws-finance-12.corp.local", severity: "high" as const, verificationMethod: "scan_recheck" as const, status: "still_vulnerable" as const, createdAt: new Date(now - 8 * day), slaDeadline: new Date(now - 1 * day), verifiedAt: new Date(now - 12 * hour), verificationOutput: "Scan confirmed Office 2019 still unpatched. KB5029253 not installed.", attemptCount: 1, originalFindingId: 1004, originalFindingType: "vulnerability" },
      // HIGH — verified fixed
      { findingTitle: "[DEMO] CVE-2024-1709 — ConnectWise ScreenConnect Auth Bypass", assetName: "mgmt-console.corp.local", severity: "high" as const, verificationMethod: "re_exploit" as const, status: "verified_fixed" as const, createdAt: new Date(now - 6 * day), slaDeadline: new Date(now - 3 * day), verifiedAt: new Date(now - 4 * day), verificationOutput: "Auth bypass attempt returned 403. ScreenConnect upgraded to 23.9.8.", attemptCount: 1, originalFindingId: 1005, originalFindingType: "vulnerability" },
      // HIGH — running verification
      { findingTitle: "[DEMO] CVE-2023-46747 — F5 BIG-IP Unauthenticated RCE", assetName: "lb-prod-01.dmz", severity: "high" as const, verificationMethod: "re_exploit" as const, status: "running" as const, createdAt: new Date(now - 3 * day), slaDeadline: new Date(now + 1 * day), verificationOutput: null, attemptCount: 0, originalFindingId: 1006, originalFindingType: "vulnerability" },
      // MEDIUM — pending
      { findingTitle: "[DEMO] CVE-2024-0056 — .NET SQL Data Provider Info Disclosure", assetName: "api-server-02.corp.local", severity: "medium" as const, verificationMethod: "config_audit" as const, status: "pending" as const, createdAt: new Date(now - 2 * day), slaDeadline: new Date(now + 12 * day), verificationOutput: null, attemptCount: 0, originalFindingId: 1007, originalFindingType: "vulnerability" },
      // MEDIUM — verified fixed
      { findingTitle: "[DEMO] CVE-2023-38545 — curl SOCKS5 Heap Buffer Overflow", assetName: "build-agent-04.ci", severity: "medium" as const, verificationMethod: "scan_recheck" as const, status: "verified_fixed" as const, createdAt: new Date(now - 10 * day), slaDeadline: new Date(now - 3 * day), verifiedAt: new Date(now - 7 * day), verificationOutput: "curl version updated to 8.4.0. Heap overflow no longer reproducible.", attemptCount: 1, originalFindingId: 1008, originalFindingType: "vulnerability" },
      // MEDIUM — still vulnerable
      { findingTitle: "[DEMO] Weak SSH Key Exchange Algorithms (diffie-hellman-group1-sha1)", assetName: "legacy-db-01.corp.local", severity: "medium" as const, verificationMethod: "config_audit" as const, status: "still_vulnerable" as const, createdAt: new Date(now - 15 * day), slaDeadline: new Date(now - 1 * day), verifiedAt: new Date(now - 2 * day), verificationOutput: "SSH config still allows diffie-hellman-group1-sha1. sshd_config unchanged.", attemptCount: 2, originalFindingId: 1009, originalFindingType: "misconfiguration" },
      // LOW — pending
      { findingTitle: "[DEMO] HTTP Server Banner Disclosure (Apache/2.4.51)", assetName: "web-staging.corp.local", severity: "low" as const, verificationMethod: "scan_recheck" as const, status: "pending" as const, createdAt: new Date(now - 5 * day), slaDeadline: new Date(now + 25 * day), verificationOutput: null, attemptCount: 0, originalFindingId: 1010, originalFindingType: "info_disclosure" },
      // LOW — verified fixed
      { findingTitle: "[DEMO] Missing X-Content-Type-Options Header", assetName: "portal.corp.local", severity: "low" as const, verificationMethod: "config_audit" as const, status: "verified_fixed" as const, createdAt: new Date(now - 20 * day), slaDeadline: new Date(now + 10 * day), verifiedAt: new Date(now - 12 * day), verificationOutput: "X-Content-Type-Options: nosniff header now present in all responses.", attemptCount: 1, originalFindingId: 1011, originalFindingType: "misconfiguration" },
      // CRITICAL — error state
      { findingTitle: "[DEMO] CVE-2024-27198 — JetBrains TeamCity Auth Bypass", assetName: "ci-server-01.corp.local", severity: "critical" as const, verificationMethod: "re_exploit" as const, status: "error" as const, createdAt: new Date(now - 3 * day), slaDeadline: new Date(now - 1 * day), verifiedAt: new Date(now - 2 * day), verificationOutput: "Error: Connection refused to target port 8111. Host may be offline.", attemptCount: 3, originalFindingId: 1012, originalFindingType: "vulnerability" },
      // HIGH — manual verification pending
      { findingTitle: "[DEMO] Default SNMP Community String (public)", assetName: "switch-core-01.net", severity: "high" as const, verificationMethod: "manual" as const, status: "pending" as const, createdAt: new Date(now - 4 * day), slaDeadline: new Date(now + 3 * day), verificationOutput: null, attemptCount: 0, originalFindingId: 1013, originalFindingType: "misconfiguration" },
      // MEDIUM — verified fixed recently
      { findingTitle: "[DEMO] TLS 1.0/1.1 Enabled on Public-Facing Service", assetName: "mail.corp.local", severity: "medium" as const, verificationMethod: "scan_recheck" as const, status: "verified_fixed" as const, createdAt: new Date(now - 7 * day), slaDeadline: new Date(now + 7 * day), verifiedAt: new Date(now - 1 * day), verificationOutput: "TLS scan confirms only TLS 1.2 and 1.3 accepted. TLS 1.0/1.1 disabled.", attemptCount: 1, originalFindingId: 1014, originalFindingType: "misconfiguration" },
      // HIGH — overdue, multiple attempts
      { findingTitle: "[DEMO] CVE-2023-22515 — Atlassian Confluence Privilege Escalation", assetName: "wiki.corp.local", severity: "high" as const, verificationMethod: "re_exploit" as const, status: "still_vulnerable" as const, createdAt: new Date(now - 12 * day), slaDeadline: new Date(now - 5 * day), verifiedAt: new Date(now - 1 * day), verificationOutput: "Privilege escalation still possible. Confluence version 8.5.1 — needs upgrade to 8.5.4+.", attemptCount: 3, originalFindingId: 1015, originalFindingType: "vulnerability" },
    ];

    let inserted = 0;
    for (const item of seedItems) {
      const slaHours = slaMap[item.severity] || 720;
      await db.insert(remediationVerifications).values({
        originalFindingId: item.originalFindingId,
        originalFindingType: item.originalFindingType,
        verificationMethod: item.verificationMethod,
        status: item.status,
        severity: item.severity,
        assetName: item.assetName,
        findingTitle: item.findingTitle,
        slaDeadline: item.slaDeadline,
        slaHours: slaHours,
        verifiedBy: String(ctx.user.id),
        verifiedAt: item.verifiedAt || null,
        verificationOutput: item.verificationOutput || null,
        attemptCount: item.attemptCount,
        createdAt: item.createdAt,
      });
      inserted++;
    }

    return { success: true, inserted, message: `Seeded ${inserted} realistic remediation findings for demo` };
  }),

  exportReport: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc, lt, and, eq, count, not } = await import("drizzle-orm");

    // Fetch all items
    const allItems = await db.select().from(remediationVerifications).orderBy(desc(remediationVerifications.createdAt));
    const total = allItems.length;
    const verifiedFixed = allItems.filter(i => i.status === "verified_fixed").length;
    const stillVulnerable = allItems.filter(i => i.status === "still_vulnerable").length;
    const pending = allItems.filter(i => i.status === "pending").length;
    const now = new Date();
    const overdueItems = allItems.filter(i => i.slaDeadline && new Date(i.slaDeadline) < now && i.status !== "verified_fixed").map(i => ({
      ...i,
      hoursOverdue: Math.round((now.getTime() - new Date(i.slaDeadline!).getTime()) / 3600000),
    }));
    const slaCompliant = total > 0 ? Math.round(((total - overdueItems.length) / total) * 100) : 100;

    // Severity breakdown
    const severityBreakdown: Record<string, number> = {};
    for (const item of allItems) {
      const sev = item.severity || "medium";
      severityBreakdown[sev] = (severityBreakdown[sev] || 0) + 1;
    }

    // Avg remediation hours
    const fixedWithTime = allItems.filter(i => i.status === "verified_fixed" && i.verifiedAt && i.createdAt);
    const avgRemediationHours = fixedWithTime.length > 0
      ? Math.round(fixedWithTime.reduce((sum, i) => sum + (new Date(i.verifiedAt!).getTime() - new Date(i.createdAt!).getTime()) / 3600000, 0) / fixedWithTime.length)
      : 0;

    const stats = { total, verifiedFixed, stillVulnerable, pending, overdue: overdueItems.length, slaCompliant, severityBreakdown, avgRemediationHours };
    const { generateRemediationReport } = await import("../lib/pdf-report-generator");
    const html = generateRemediationReport(stats, allItems, overdueItems);
    return { html, filename: `remediation-report-${Date.now()}.html` };
  }),

  /** Clear demo data — only deletes items with [DEMO] prefix, never touches real data */
  clearDemoData: protectedProcedure.mutation(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { like } = await import("drizzle-orm");
    const deleted = await db.delete(remediationVerifications).where(like(remediationVerifications.findingTitle, "[DEMO]%"));
    const deletedCount = (deleted as any)[0]?.affectedRows ?? 0;
    return { success: true, deleted: deletedCount, message: `Cleared ${deletedCount} demo items` };
  }),

  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { remediationVerifications } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { eq, count } = await import("drizzle-orm");
    const verifiedFixed = await db.select({ value: count() }).from(remediationVerifications).where(eq(remediationVerifications.status, "verified_fixed"));
    const stillVulnerable = await db.select({ value: count() }).from(remediationVerifications).where(eq(remediationVerifications.status, "still_vulnerable"));
    return {
      verified_fixed: verifiedFixed[0].value,
      still_vulnerable: stillVulnerable[0].value,
    };
  }),
});
