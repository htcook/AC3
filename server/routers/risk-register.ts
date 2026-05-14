import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import {
  riskRegisterEntries,
  riskRegisterActivityLog,
  riskRegisterAttachments,
  engagements,
} from "../../drizzle/schema";
import { eq, and, or, like, sql, desc, asc, inArray, count } from "drizzle-orm";

function generatePoamId(): string {
  const ts = Date.now().toString(36).toUpperCase();
  const rand = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `POAM-${ts}-${rand}`;
}

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const riskRegisterRouter = router({
  list: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(1).max(200).default(50),
      status: z.string().optional(),
      severity: z.string().optional(),
      source: z.string().optional(),
      search: z.string().optional(),
      sortBy: z.enum(["createdAt", "severity", "status", "scheduledCompletionDate", "originalDetectionDate"]).default("createdAt"),
      sortDir: z.enum(["asc", "desc"]).default("desc"),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const { page, pageSize, status, severity, source, search, sortBy, sortDir } = input;
      const conditions: any[] = [];
      if (status) conditions.push(eq(riskRegisterEntries.status, status as any));
      if (severity) conditions.push(eq(riskRegisterEntries.severity, severity as any));
      if (source) conditions.push(eq(riskRegisterEntries.source, source as any));
      if (search) {
        conditions.push(or(
          like(riskRegisterEntries.weaknessName, `%${search}%`),
          like(riskRegisterEntries.poamId, `%${search}%`),
          like(riskRegisterEntries.assetIdentifier, `%${search}%`),
          like(riskRegisterEntries.controls, `%${search}%`),
        ));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const sortCol = sortBy === "severity" ? riskRegisterEntries.severity :
                      sortBy === "status" ? riskRegisterEntries.status :
                      sortBy === "scheduledCompletionDate" ? riskRegisterEntries.scheduledCompletionDate :
                      sortBy === "originalDetectionDate" ? riskRegisterEntries.originalDetectionDate :
                      riskRegisterEntries.createdAt;
      const orderFn = sortDir === "asc" ? asc : desc;
      const [items, [{ total }]] = await Promise.all([
        db.select().from(riskRegisterEntries).where(where).orderBy(orderFn(sortCol)).limit(pageSize).offset((page - 1) * pageSize),
        db.select({ total: count() }).from(riskRegisterEntries).where(where),
      ]);
      return { items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
    }),

  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [entry] = await db.select().from(riskRegisterEntries).where(eq(riskRegisterEntries.id, input.id));
      if (!entry) throw new TRPCError({ code: "NOT_FOUND", message: "Risk register entry not found" });
      const [activity, attachments] = await Promise.all([
        db.select().from(riskRegisterActivityLog).where(eq(riskRegisterActivityLog.entryId, input.id)).orderBy(desc(riskRegisterActivityLog.createdAt)),
        db.select().from(riskRegisterAttachments).where(eq(riskRegisterAttachments.entryId, input.id)).orderBy(desc(riskRegisterAttachments.createdAt)),
      ]);
      return { ...entry, activityLog: activity, attachments };
    }),

  create: protectedProcedure
    .input(z.object({
      weaknessName: z.string().min(1),
      weaknessDescription: z.string().optional(),
      controls: z.string().optional(),
      weaknessDetectorSource: z.string().optional(),
      weaknessSourceIdentifier: z.string().optional(),
      assetIdentifier: z.string().optional(),
      pointOfContact: z.string().optional(),
      resourcesRequired: z.string().optional(),
      remediationPlan: z.string().optional(),
      originalDetectionDate: z.string().optional(),
      scheduledCompletionDate: z.string().optional(),
      milestones: z.string().optional(),
      vendorDependency: z.boolean().optional(),
      vendorDependentProductName: z.string().optional(),
      originalRiskRating: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
      source: z.enum(["manual", "engagement", "ctem_scan", "vulnerability_scan", "pentest", "red_team", "bug_bounty"]).default("manual"),
      sourceEngagementId: z.number().optional(),
      attackChainId: z.string().optional(),
      comments: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const poamId = generatePoamId();
      const [result] = await db.insert(riskRegisterEntries).values({
        poamId, ...input,
        vendorDependency: input.vendorDependency ? 1 : 0,
        createdBy: ctx.user.id,
      });
      await db.insert(riskRegisterActivityLog).values({
        entryId: result.insertId, action: "created",
        details: `POA&M ${poamId} created`, performedBy: ctx.user.name || ctx.user.openId,
      });
      return { id: result.insertId, poamId };
    }),

  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      weaknessName: z.string().optional(),
      weaknessDescription: z.string().optional(),
      controls: z.string().optional(),
      weaknessDetectorSource: z.string().optional(),
      weaknessSourceIdentifier: z.string().optional(),
      assetIdentifier: z.string().optional(),
      pointOfContact: z.string().optional(),
      resourcesRequired: z.string().optional(),
      remediationPlan: z.string().optional(),
      scheduledCompletionDate: z.string().nullable().optional(),
      actualCompletionDate: z.string().nullable().optional(),
      milestones: z.string().optional(),
      milestoneChanges: z.string().optional(),
      vendorDependency: z.boolean().optional(),
      vendorDependentProductName: z.string().optional(),
      lastVendorCheckinDate: z.string().nullable().optional(),
      originalRiskRating: z.enum(["critical", "high", "moderate", "low", "informational"]).optional(),
      adjustedRiskRating: z.enum(["critical", "high", "moderate", "low", "informational"]).nullable().optional(),
      riskAdjustment: z.string().optional(),
      falsePositive: z.boolean().optional(),
      operationalRequirement: z.boolean().optional(),
      deviationRationale: z.string().optional(),
      supportingDocuments: z.string().optional(),
      comments: z.string().optional(),
      status: z.enum(["open", "in_progress", "closed", "risk_accepted", "deferred", "vendor_dependent"]).optional(),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const { id, ...updates } = input;
      const updateData: any = { ...updates };
      if (updates.vendorDependency !== undefined) updateData.vendorDependency = updates.vendorDependency ? 1 : 0;
      if (updates.falsePositive !== undefined) updateData.falsePositive = updates.falsePositive ? 1 : 0;
      if (updates.operationalRequirement !== undefined) updateData.operationalRequirement = updates.operationalRequirement ? 1 : 0;
      updateData.statusDate = sql`CURRENT_TIMESTAMP`;
      await db.update(riskRegisterEntries).set(updateData).where(eq(riskRegisterEntries.id, id));
      const changes = Object.keys(updates).filter(k => (updates as any)[k] !== undefined).join(", ");
      await db.insert(riskRegisterActivityLog).values({
        entryId: id, action: "updated", details: `Updated fields: ${changes}`,
        performedBy: ctx.user.name || ctx.user.openId,
      });
      return { success: true };
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.delete(riskRegisterActivityLog).where(eq(riskRegisterActivityLog.entryId, input.id));
      await db.delete(riskRegisterAttachments).where(eq(riskRegisterAttachments.entryId, input.id));
      await db.delete(riskRegisterEntries).where(eq(riskRegisterEntries.id, input.id));
      return { success: true };
    }),

  acceptRisk: protectedProcedure
    .input(z.object({
      id: z.number(),
      decision: z.enum(["mitigate", "accept", "transfer", "defer", "avoid"]),
      justification: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const newStatus = input.decision === "accept" ? "risk_accepted" as const :
                        input.decision === "defer" ? "deferred" as const : "in_progress" as const;
      await db.update(riskRegisterEntries).set({
        riskDecision: input.decision, riskDecisionBy: ctx.user.name || ctx.user.openId,
        riskDecisionDate: sql`CURRENT_TIMESTAMP`, riskDecisionJustification: input.justification,
        status: newStatus, statusDate: sql`CURRENT_TIMESTAMP`,
      }).where(eq(riskRegisterEntries.id, input.id));
      await db.insert(riskRegisterActivityLog).values({
        entryId: input.id, action: `risk_decision_${input.decision}`,
        details: input.justification, performedBy: ctx.user.name || ctx.user.openId,
      });
      return { success: true };
    }),

  autoPopulateFromEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const [eng] = await db.select().from(engagements).where(eq(engagements.id, input.engagementId));
      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
      const existing = await db.select({ weaknessName: riskRegisterEntries.weaknessName, assetIdentifier: riskRegisterEntries.assetIdentifier })
        .from(riskRegisterEntries).where(eq(riskRegisterEntries.sourceEngagementId, input.engagementId));
      const existingKeys = new Set(existing.map(e => `${e.weaknessName}::${e.assetIdentifier}`));
      const findings: any = await db.execute(sql`
        SELECT title, description, severity, affected_asset, cve_id, cwe_id
        FROM remediation_tasks WHERE engagement_id = ${input.engagementId} AND status != 'verified_fixed' LIMIT 500
      `);
      const rows = Array.isArray(findings) ? (Array.isArray(findings[0]) ? findings[0] : findings) : [];
      let created = 0, skipped = 0;
      for (const f of rows) {
        const key = `${f.title}::${f.affected_asset || ""}`;
        if (existingKeys.has(key)) { skipped++; continue; }
        const poamId = generatePoamId();
        const sevMap: Record<string, string> = { critical: "critical", high: "high", medium: "moderate", moderate: "moderate", low: "low", info: "informational", informational: "informational" };
        const sev = sevMap[f.severity?.toLowerCase()] || "moderate";
        await db.insert(riskRegisterEntries).values({
          poamId, weaknessName: f.title || "Unnamed Finding", weaknessDescription: f.description || null,
          weaknessSourceIdentifier: f.cve_id || f.cwe_id || null, assetIdentifier: f.affected_asset || eng.targetDomain || null,
          originalRiskRating: sev as any, severity: sev as any,
          source: eng.engagementType === "red_team" ? "red_team" : eng.engagementType === "pentest" ? "pentest" : "engagement",
          sourceEngagementId: input.engagementId, originalDetectionDate: sql`CURRENT_TIMESTAMP`, createdBy: ctx.user.id,
        });
        existingKeys.add(key);
        created++;
      }
      return { created, skipped, total: created + skipped };
    }),

  ctemSync: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        weaknessName: z.string(), weaknessDescription: z.string().optional(),
        weaknessSourceIdentifier: z.string().optional(), assetIdentifier: z.string().optional(),
        severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
        detectorSource: z.string().optional(), scanId: z.number().optional(),
      })),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const existing = await db.select({ weaknessName: riskRegisterEntries.weaknessName, assetIdentifier: riskRegisterEntries.assetIdentifier })
        .from(riskRegisterEntries).where(or(eq(riskRegisterEntries.status, "open"), eq(riskRegisterEntries.status, "in_progress")));
      const existingKeys = new Set(existing.map(e => `${e.weaknessName}::${e.assetIdentifier || ""}`));
      let created = 0, skipped = 0;
      for (const f of input.findings) {
        const key = `${f.weaknessName}::${f.assetIdentifier || ""}`;
        if (existingKeys.has(key)) { skipped++; continue; }
        const poamId = generatePoamId();
        await db.insert(riskRegisterEntries).values({
          poamId, weaknessName: f.weaknessName, weaknessDescription: f.weaknessDescription || null,
          weaknessSourceIdentifier: f.weaknessSourceIdentifier || null, assetIdentifier: f.assetIdentifier || null,
          weaknessDetectorSource: f.detectorSource || null, severity: f.severity, originalRiskRating: f.severity,
          source: "ctem_scan", sourceScanId: f.scanId || null, originalDetectionDate: sql`CURRENT_TIMESTAMP`, createdBy: ctx.user.id,
        });
        existingKeys.add(key);
        created++;
      }
      return { created, skipped, total: input.findings.length };
    }),

  executiveMetrics: protectedProcedure
    .input(z.object({ days: z.number().default(90) }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const cutoff = new Date(Date.now() - input.days * 86400000).toISOString();
      const allEntries = await db.select().from(riskRegisterEntries);
      const openStatuses = ["open", "in_progress", "vendor_dependent"];
      const openEntries = allEntries.filter(e => openStatuses.includes(e.status));
      const closedInPeriod = allEntries.filter(e => e.status === "closed" && e.actualCompletionDate && e.actualCompletionDate >= cutoff);
      const newInPeriod = allEntries.filter(e => e.createdAt >= cutoff);
      const now = Date.now();
      const overdue = openEntries.filter(e => e.scheduledCompletionDate && new Date(e.scheduledCompletionDate).getTime() < now);
      const openBySeverity = ["critical", "high", "moderate", "low", "informational"].map(sev => ({
        severity: sev, count: openEntries.filter(e => e.severity === sev).length,
      }));
      const mttrBySeverity: Record<string, { avgDays: number; count: number }> = {};
      const closedAll = allEntries.filter(e => e.status === "closed" && e.actualCompletionDate && e.originalDetectionDate);
      for (const e of closedAll) {
        const days = Math.floor((new Date(e.actualCompletionDate!).getTime() - new Date(e.originalDetectionDate!).getTime()) / 86400000);
        if (!mttrBySeverity[e.severity]) mttrBySeverity[e.severity] = { avgDays: 0, count: 0 };
        mttrBySeverity[e.severity].count++;
        mttrBySeverity[e.severity].avgDays += days;
      }
      for (const sev of Object.keys(mttrBySeverity)) {
        mttrBySeverity[sev].avgDays = Math.round(mttrBySeverity[sev].avgDays / mttrBySeverity[sev].count);
      }
      const oldestOpen = openEntries
        .sort((a, b) => {
          const da = a.originalDetectionDate ? new Date(a.originalDetectionDate).getTime() : new Date(a.createdAt).getTime();
          const db2 = b.originalDetectionDate ? new Date(b.originalDetectionDate).getTime() : new Date(b.createdAt).getTime();
          return da - db2;
        }).slice(0, 10);
      return {
        summary: { totalOpen: openEntries.length, overdue: overdue.length, totalClosedInPeriod: closedInPeriod.length,
          riskAccepted: allEntries.filter(e => e.status === "risk_accepted").length,
          vendorDependent: allEntries.filter(e => e.vendorDependency === 1 || e.status === "vendor_dependent").length,
          newInPeriod: newInPeriod.length },
        openBySeverity, mttrBySeverity,
        oldestOpen: oldestOpen.map(e => ({ id: e.id, poamId: e.poamId, weaknessName: e.weaknessName,
          severity: e.severity, originalDetectionDate: e.originalDetectionDate || e.createdAt })),
      };
    }),

  trend: protectedProcedure
    .input(z.object({ months: z.number().default(6) }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const allEntries = await db.select().from(riskRegisterEntries);
      const result: { month: string; opened: number; closed: number; netOpen: number }[] = [];
      for (let i = input.months - 1; i >= 0; i--) {
        const d = new Date(); d.setMonth(d.getMonth() - i);
        const year = d.getFullYear(); const month = d.getMonth();
        const monthStr = `${year}-${String(month + 1).padStart(2, "0")}`;
        const opened = allEntries.filter(e => { const cd = new Date(e.createdAt); return cd.getFullYear() === year && cd.getMonth() === month; }).length;
        const closed = allEntries.filter(e => { if (!e.actualCompletionDate) return false; const cd = new Date(e.actualCompletionDate); return cd.getFullYear() === year && cd.getMonth() === month; }).length;
        result.push({ month: monthStr, opened, closed, netOpen: opened - closed });
      }
      return result;
    }),

  exportPoam: protectedProcedure
    .input(z.object({ status: z.string().optional(), severity: z.string().optional() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const conditions: any[] = [];
      if (input.status) conditions.push(eq(riskRegisterEntries.status, input.status as any));
      if (input.severity) conditions.push(eq(riskRegisterEntries.severity, input.severity as any));
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      return db.select().from(riskRegisterEntries).where(where).orderBy(asc(riskRegisterEntries.poamId));
    }),

  bulkUpdateStatus: protectedProcedure
    .input(z.object({
      ids: z.array(z.number()).min(1),
      status: z.enum(["open", "in_progress", "closed", "risk_accepted", "deferred", "vendor_dependent"]),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const updateData: any = { status: input.status, statusDate: sql`CURRENT_TIMESTAMP` };
      if (input.status === "closed") updateData.actualCompletionDate = sql`CURRENT_TIMESTAMP`;
      await db.update(riskRegisterEntries).set(updateData).where(inArray(riskRegisterEntries.id, input.ids));
      for (const id of input.ids) {
        await db.insert(riskRegisterActivityLog).values({
          entryId: id, action: `bulk_status_${input.status}`, details: `Bulk status change to ${input.status}`,
          performedBy: ctx.user.name || ctx.user.openId,
        });
      }
      return { updated: input.ids.length };
    }),

  exportPoamExcel: protectedProcedure
    .input(z.object({ status: z.string().optional(), severity: z.string().optional() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const ExcelJS = (await import("exceljs")).default;
      const conditions: any[] = [];
      if (input.status) conditions.push(eq(riskRegisterEntries.status, input.status));
      if (input.severity) conditions.push(eq(riskRegisterEntries.severity, input.severity));
      const entries = await db.select().from(riskRegisterEntries)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(riskRegisterEntries.createdAt));

      const wb = new ExcelJS.Workbook();
      wb.creator = "AceofCloud Caldera Dashboard";
      wb.created = new Date();
      const ws = wb.addWorksheet("POA&M");

      // FedRAMP POA&M Template columns
      ws.columns = [
        { header: "POA&M ID", key: "poamId", width: 18 },
        { header: "Controls", key: "controls", width: 15 },
        { header: "Weakness Name", key: "weaknessName", width: 35 },
        { header: "Weakness Description", key: "weaknessDescription", width: 45 },
        { header: "Weakness Detector Source", key: "weaknessDetectorSource", width: 22 },
        { header: "Weakness Source Identifier", key: "weaknessSourceIdentifier", width: 22 },
        { header: "Asset Identifier", key: "assetIdentifier", width: 25 },
        { header: "Point of Contact", key: "pointOfContact", width: 20 },
        { header: "Resources Required", key: "resourcesRequired", width: 20 },
        { header: "Overall Remediation Plan", key: "remediationPlan", width: 40 },
        { header: "Original Detection Date", key: "originalDetectionDate", width: 20 },
        { header: "Scheduled Completion Date", key: "scheduledCompletionDate", width: 22 },
        { header: "Planned Milestones", key: "milestones", width: 30 },
        { header: "Milestone Changes", key: "milestoneChanges", width: 25 },
        { header: "Status Date", key: "statusDate", width: 15 },
        { header: "Vendor Dependency", key: "vendorDependency", width: 18 },
        { header: "Vendor Dependent Product Name", key: "vendorDependentProductName", width: 28 },
        { header: "Original Risk Rating", key: "originalRiskRating", width: 18 },
        { header: "Adjusted Risk Rating", key: "severity", width: 18 },
        { header: "Risk Adjustment", key: "riskDecision", width: 18 },
        { header: "False Positive", key: "falsePositive", width: 14 },
        { header: "Operational Requirement", key: "operationalRequirement", width: 22 },
        { header: "Deviation Request", key: "deviationRequest", width: 20 },
        { header: "Supporting Documents", key: "supportingDocuments", width: 22 },
        { header: "Comments", key: "comments", width: 35 },
        { header: "Auto-Approval Status", key: "status", width: 18 },
      ];

      // Style header row
      const headerRow = ws.getRow(1);
      headerRow.font = { bold: true, color: { argb: "FFFFFFFF" }, size: 10 };
      headerRow.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1F4E79" } };
      headerRow.alignment = { vertical: "middle", wrapText: true };
      headerRow.height = 35;

      for (const entry of entries) {
        ws.addRow({
          poamId: entry.poamId,
          controls: entry.controls || "",
          weaknessName: entry.weaknessName,
          weaknessDescription: entry.weaknessDescription || "",
          weaknessDetectorSource: entry.weaknessDetectorSource || "",
          weaknessSourceIdentifier: entry.weaknessSourceIdentifier || "",
          assetIdentifier: entry.assetIdentifier || "",
          pointOfContact: entry.pointOfContact || "",
          resourcesRequired: entry.resourcesRequired || "",
          remediationPlan: entry.remediationPlan || "",
          originalDetectionDate: entry.originalDetectionDate || "",
          scheduledCompletionDate: entry.scheduledCompletionDate || "",
          milestones: entry.milestones || "",
          milestoneChanges: "",
          statusDate: entry.statusDate ? new Date(entry.statusDate).toLocaleDateString() : "",
          vendorDependency: entry.vendorDependency ? "Yes" : "No",
          vendorDependentProductName: entry.vendorDependentProductName || "",
          originalRiskRating: entry.originalRiskRating || "",
          severity: entry.severity || "",
          riskDecision: entry.riskDecision || "",
          falsePositive: "",
          operationalRequirement: "",
          deviationRequest: "",
          supportingDocuments: "",
          comments: entry.comments || "",
          status: entry.status || "",
        });
      }

      // Alternate row colors
      ws.eachRow((row, rowNum) => {
        if (rowNum > 1) {
          row.alignment = { vertical: "top", wrapText: true };
          if (rowNum % 2 === 0) {
            row.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF2F2F2" } };
          }
        }
      });

      // Add borders
      ws.eachRow(row => {
        row.eachCell(cell => {
          cell.border = { top: { style: "thin" }, left: { style: "thin" }, bottom: { style: "thin" }, right: { style: "thin" } };
        });
      });

      const buffer = await wb.xlsx.writeBuffer();
      const base64 = Buffer.from(buffer as ArrayBuffer).toString("base64");
      return { base64, filename: `FedRAMP-POAM-${new Date().toISOString().split("T")[0]}.xlsx`, count: entries.length };
    }),

  availableReports: protectedProcedure.query(async () => {
    const db = await requireDb();
    return db.select({ id: engagements.id, name: engagements.name, customerName: engagements.customerName,
      engagementType: engagements.engagementType, status: engagements.status })
      .from(engagements).orderBy(desc(engagements.createdAt)).limit(50);
  }),
});
