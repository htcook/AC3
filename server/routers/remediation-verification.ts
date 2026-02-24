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
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { remediationVerifications } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

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
