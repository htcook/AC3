import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import {
  riskRegisterEntries,
  riskRegisterActivityLog,
  riskRegisterAttachments,
  ac3ReportFindings,
  ac3Reports,
} from "../../drizzle/schema";
import { eq, desc, asc, and, or, like, sql, gte, lte, inArray, isNotNull } from "drizzle-orm";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

function generatePoamId(sourceType: string, index: number): string {
  const prefix = sourceType === "pentest" ? "PT" :
                 sourceType === "red_team" ? "RT" :
                 sourceType === "vulnerability_scan" ? "VS" :
                 sourceType === "cicd" ? "CI" :
                 sourceType === "ctem" ? "CT" : "MN";
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${index.toString().padStart(4, "0")}`;
}

const statusEnum = z.enum(["open", "closed", "risk_accepted", "false_positive", "operationally_required", "vendor_dependent", "deferred"]);
const severityEnum = z.enum(["critical", "high", "moderate", "low", "informational"]);
const sourceTypeEnum = z.enum(["pentest", "red_team", "vulnerability_scan", "cicd", "ctem", "manual", "import"]);

export const riskRegisterRouter = router({
  // ─── List entries with filtering, sorting, pagination ───
  list: protectedProcedure
    .input(z.object({
      status: statusEnum.optional(),
      severity: severityEnum.optional(),
      sourceType: sourceTypeEnum.optional(),
      search: z.string().optional(),
      controlFamily: z.string().optional(),
      overdue: z.boolean().optional(),
      sortBy: z.enum(["severity", "createdAt", "scheduledCompletion", "poamId"]).default("createdAt"),
      sortOrder: z.enum(["asc", "desc"]).default("desc"),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      const i = input || {};

      if (i.status) filters.push(eq(riskRegisterEntries.status, i.status));
      if (i.severity) filters.push(eq(riskRegisterEntries.severity, i.severity));
      if (i.sourceType) filters.push(eq(riskRegisterEntries.sourceType, i.sourceType));
      if (i.controlFamily) filters.push(like(riskRegisterEntries.controls, `%${i.controlFamily}%`));
      if (i.search) {
        filters.push(or(
          like(riskRegisterEntries.weaknessName, `%${i.search}%`),
          like(riskRegisterEntries.poamId, `%${i.search}%`),
          like(riskRegisterEntries.assetIdentifier, `%${i.search}%`),
          like(riskRegisterEntries.weaknessDescription, `%${i.search}%`),
          like(riskRegisterEntries.cve, `%${i.search}%`),
        ));
      }
      if (i.overdue) {
        filters.push(isNotNull(riskRegisterEntries.scheduledCompletionDate));
        filters.push(lte(riskRegisterEntries.scheduledCompletionDate, sql`NOW()`));
        filters.push(eq(riskRegisterEntries.status, "open"));
      }

      const where = filters.length > 0 ? and(...filters) : undefined;

      const orderCol = i.sortBy === "severity" ? riskRegisterEntries.severity :
                       i.sortBy === "scheduledCompletion" ? riskRegisterEntries.scheduledCompletionDate :
                       i.sortBy === "poamId" ? riskRegisterEntries.poamId :
                       riskRegisterEntries.createdAt;
      const orderFn = i.sortOrder === "asc" ? asc : desc;

      const [items, countResult] = await Promise.all([
        db.select().from(riskRegisterEntries).where(where)
          .orderBy(orderFn(orderCol))
          .limit(i.limit || 50)
          .offset(i.offset || 0),
        db.select({ count: sql<number>`count(*)` }).from(riskRegisterEntries).where(where),
      ]);

      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single entry with activity log ───
  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [entry] = await db.select().from(riskRegisterEntries)
        .where(eq(riskRegisterEntries.id, input.id));
      if (!entry) throw new TRPCError({ code: "NOT_FOUND", message: "Risk register entry not found" });

      const activity = await db.select().from(riskRegisterActivityLog)
        .where(eq(riskRegisterActivityLog.entryId, input.id))
        .orderBy(desc(riskRegisterActivityLog.createdAt))
        .limit(50);

      const attachments = await db.select().from(riskRegisterAttachments)
        .where(eq(riskRegisterAttachments.entryId, input.id))
        .orderBy(desc(riskRegisterAttachments.createdAt));

      return { entry, activity, attachments };
    }),

  // ─── Create manual entry ───
  create: protectedProcedure
    .input(z.object({
      weaknessName: z.string().min(1),
      weaknessDescription: z.string().optional(),
      controls: z.string().optional(),
      severity: severityEnum,
      category: z.string().optional(),
      assetIdentifier: z.string().optional(),
      pointOfContact: z.string().optional(),
      remediationPlan: z.string().optional(),
      scheduledCompletionDate: z.string().optional(),
      cve: z.string().optional(),
      cvssScore: z.string().optional(),
      detectorSource: z.string().optional(),
      sourceIdentifier: z.string().optional(),
      vendorDependency: z.string().optional(),
      vendorDependentProductName: z.string().optional(),
      impactLevel: z.string().optional(),
      comments: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const poamId = generatePoamId("manual", Math.floor(Math.random() * 9999));

      const result = await db.insert(riskRegisterEntries).values({
        poamId,
        controls: input.controls || null,
        weaknessName: input.weaknessName,
        weaknessDescription: input.weaknessDescription || null,
        weaknessDetectorSource: input.detectorSource || "Manual Entry",
        weaknessSourceIdentifier: input.sourceIdentifier || null,
        assetIdentifier: input.assetIdentifier || null,
        pointOfContact: input.pointOfContact || null,
        originalRiskRating: input.severity,
        adjustedRiskRating: input.severity,
        severity: input.severity,
        category: input.category || "vulnerability",
        remediationPlan: input.remediationPlan || null,
        scheduledCompletionDate: input.scheduledCompletionDate || null,
        originalDetectionDate: sql`NOW()`,
        status: "open",
        sourceType: "manual",
        cve: input.cve || null,
        cvssScore: input.cvssScore || null,
        vendorDependency: input.vendorDependency || "No",
        vendorDependentProductName: input.vendorDependentProductName || null,
        impactLevel: input.impactLevel || null,
        comments: input.comments || null,
        createdBy: ctx.user?.id ? Number(ctx.user.id) : null,
      });

      await db.insert(riskRegisterActivityLog).values({
        entryId: result[0].insertId,
        action: "created",
        performedBy: ctx.user?.id ? Number(ctx.user.id) : null,
        performedByName: ctx.user?.name || "System",
        notes: JSON.stringify({ source: "manual", severity: input.severity }),
      });

      return { id: result[0].insertId, poamId };
    }),

  // ─── Update entry ───
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      weaknessName: z.string().optional(),
      weaknessDescription: z.string().optional(),
      controls: z.string().optional(),
      severity: severityEnum.optional(),
      adjustedRiskRating: severityEnum.optional(),
      category: z.string().optional(),
      assetIdentifier: z.string().optional(),
      pointOfContact: z.string().optional(),
      remediationPlan: z.string().optional(),
      scheduledCompletionDate: z.string().nullable().optional(),
      status: statusEnum.optional(),
      vendorDependency: z.string().optional(),
      vendorDependentProductName: z.string().optional(),
      cve: z.string().optional(),
      cvssScore: z.string().optional(),
      riskDecision: z.string().optional(),
      riskDecisionJustification: z.string().optional(),
      compensatingControls: z.string().optional(),
      deviationRationale: z.string().optional(),
      comments: z.string().optional(),
      impactLevel: z.string().optional(),
      milestones: z.any().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const { id, ...updates } = input;

      const [existing] = await db.select().from(riskRegisterEntries)
        .where(eq(riskRegisterEntries.id, id));
      if (!existing) throw new TRPCError({ code: "NOT_FOUND" });

      const setValues: any = { updatedAt: sql`NOW()`, updatedBy: ctx.user?.id ? Number(ctx.user.id) : null };
      const changes: string[] = [];

      if (updates.weaknessName !== undefined) { setValues.weaknessName = updates.weaknessName; changes.push("weaknessName"); }
      if (updates.weaknessDescription !== undefined) { setValues.weaknessDescription = updates.weaknessDescription; changes.push("description"); }
      if (updates.controls !== undefined) { setValues.controls = updates.controls; changes.push("controls"); }
      if (updates.severity) { setValues.severity = updates.severity; setValues.originalRiskRating = updates.severity; changes.push(`severity→${updates.severity}`); }
      if (updates.adjustedRiskRating) { setValues.adjustedRiskRating = updates.adjustedRiskRating; changes.push(`adjustedRisk→${updates.adjustedRiskRating}`); }
      if (updates.category !== undefined) { setValues.category = updates.category; changes.push("category"); }
      if (updates.assetIdentifier !== undefined) { setValues.assetIdentifier = updates.assetIdentifier; changes.push("asset"); }
      if (updates.pointOfContact !== undefined) { setValues.pointOfContact = updates.pointOfContact; changes.push("poc"); }
      if (updates.remediationPlan !== undefined) { setValues.remediationPlan = updates.remediationPlan; changes.push("remediationPlan"); }
      if (updates.scheduledCompletionDate !== undefined) { setValues.scheduledCompletionDate = updates.scheduledCompletionDate; changes.push("scheduledCompletion"); }
      if (updates.status) {
        setValues.status = updates.status;
        setValues.statusDate = sql`NOW()`;
        changes.push(`status→${updates.status}`);
        if (updates.status === "closed") {
          setValues.closedAt = sql`NOW()`;
          setValues.actualCompletionDate = sql`NOW()`;
        }
      }
      if (updates.vendorDependency !== undefined) { setValues.vendorDependency = updates.vendorDependency; changes.push("vendorDependency"); }
      if (updates.vendorDependentProductName !== undefined) { setValues.vendorDependentProductName = updates.vendorDependentProductName; changes.push("vendorProduct"); }
      if (updates.cve !== undefined) { setValues.cve = updates.cve; changes.push("cve"); }
      if (updates.cvssScore !== undefined) { setValues.cvssScore = updates.cvssScore; changes.push("cvss"); }
      if (updates.riskDecision !== undefined) { setValues.riskDecision = updates.riskDecision; setValues.riskDecisionDate = sql`NOW()`; changes.push("riskDecision"); }
      if (updates.riskDecisionJustification !== undefined) { setValues.riskDecisionJustification = updates.riskDecisionJustification; changes.push("justification"); }
      if (updates.compensatingControls !== undefined) { setValues.compensatingControls = updates.compensatingControls; changes.push("compensatingControls"); }
      if (updates.deviationRationale !== undefined) { setValues.deviationRationale = updates.deviationRationale; changes.push("deviationRationale"); }
      if (updates.comments !== undefined) { setValues.comments = updates.comments; changes.push("comments"); }
      if (updates.impactLevel !== undefined) { setValues.impactLevel = updates.impactLevel; changes.push("impactLevel"); }
      if (updates.milestones !== undefined) { setValues.milestones = updates.milestones; changes.push("milestones"); }

      await db.update(riskRegisterEntries).set(setValues).where(eq(riskRegisterEntries.id, id));

      await db.insert(riskRegisterActivityLog).values({
        entryId: id,
        action: "updated",
        performedBy: ctx.user?.id ? Number(ctx.user.id) : null,
        performedByName: ctx.user?.name || "System",
        notes: JSON.stringify({ fields: changes }),
      });

      return { success: true, changes };
    }),

  // ─── Risk Acceptance Decision ───
  acceptRisk: protectedProcedure
    .input(z.object({
      id: z.number(),
      decision: z.enum(["risk_accepted", "false_positive", "operationally_required"]),
      justification: z.string().min(10),
      compensatingControls: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [entry] = await db.select().from(riskRegisterEntries)
        .where(eq(riskRegisterEntries.id, input.id));
      if (!entry) throw new TRPCError({ code: "NOT_FOUND" });

      const riskAdjustment = input.decision === "risk_accepted" ? "RA" :
                             input.decision === "false_positive" ? "FP" : "OR";

      await db.update(riskRegisterEntries).set({
        status: input.decision,
        riskDecision: input.decision,
        riskDecisionBy: ctx.user?.name || "System",
        riskDecisionDate: sql`NOW()`,
        riskDecisionJustification: input.justification,
        riskAdjustment,
        falsePositive: input.decision === "false_positive" ? "Yes" : "No",
        operationalRequirement: input.decision === "operationally_required" ? "Yes" : "No",
        compensatingControls: input.compensatingControls || null,
        updatedAt: sql`NOW()`,
      }).where(eq(riskRegisterEntries.id, input.id));

      await db.insert(riskRegisterActivityLog).values({
        entryId: input.id,
        action: "risk_decision",
        performedBy: ctx.user?.id ? Number(ctx.user.id) : null,
        performedByName: ctx.user?.name || "System",
        notes: JSON.stringify({ decision: input.decision, justification: input.justification }),
      });

      return { success: true };
    }),

  // ─── Auto-populate from finalized engagement ───
  autoPopulateFromEngagement: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      overridePointOfContact: z.string().optional(),
      defaultSlaMonths: z.number().default(3),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new TRPCError({ code: "NOT_FOUND", message: "Report not found" });

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));

      if (findings.length === 0) return { created: 0, updated: 0, skipped: 0, total: 0 };

      const sourceType = report.rptAssessmentType === "red_team" ? "red_team" : "pentest";
      let created = 0, updated = 0, skipped = 0;

      for (let i = 0; i < findings.length; i++) {
        const f = findings[i];
        const assets = f.rfAssets ? (Array.isArray(f.rfAssets) ? (f.rfAssets as string[]).join(", ") : String(f.rfAssets)) : "";
        const controls = f.rfControls ? (Array.isArray(f.rfControls) ? (f.rfControls as string[]).join(", ") : String(f.rfControls)) : "";

        // Dedup check
        const existingEntries = await db.select().from(riskRegisterEntries)
          .where(and(
            eq(riskRegisterEntries.weaknessName, f.rfTitle),
            like(riskRegisterEntries.assetIdentifier, `%${assets.slice(0, 50)}%`),
          ));

        if (existingEntries.length > 0) {
          await db.update(riskRegisterEntries).set({
            statusDate: sql`NOW()`,
            updatedAt: sql`NOW()`,
          }).where(eq(riskRegisterEntries.id, existingEntries[0].id));

          await db.insert(riskRegisterActivityLog).values({
            entryId: existingEntries[0].id,
            action: "re_observed",
            performedByName: "System",
            notes: JSON.stringify({ source: sourceType, reportId: input.reportId }),
          });
          updated++;
        } else {
          const poamId = generatePoamId(sourceType, i + 1);
          const slaDate = new Date();
          slaDate.setMonth(slaDate.getMonth() + input.defaultSlaMonths);

          const result = await db.insert(riskRegisterEntries).values({
            poamId,
            controls: controls || null,
            weaknessName: f.rfTitle,
            weaknessDescription: f.rfSummary || null,
            weaknessDetectorSource: `AC3 ${sourceType === "red_team" ? "Red Team" : "Penetration Test"}`,
            weaknessSourceIdentifier: f.rfFindingId,
            assetIdentifier: assets || null,
            pointOfContact: input.overridePointOfContact || null,
            originalRiskRating: f.rfSeverity || "moderate",
            adjustedRiskRating: f.rfSeverity || "moderate",
            severity: f.rfSeverity || "moderate",
            category: "vulnerability",
            originalDetectionDate: sql`NOW()`,
            scheduledCompletionDate: slaDate.toISOString().slice(0, 19).replace("T", " "),
            remediationPlan: f.rfRemediation || null,
            status: "open",
            sourceType,
            sourceFindingId: f.id || null,
            sourceEngagementId: input.reportId,
            cve: f.rfCveIds ? (Array.isArray(f.rfCveIds) ? (f.rfCveIds as string[]).join(", ") : String(f.rfCveIds)) : null,
            cvssScore: f.rfCvssScore || null,
            vendorDependency: "No",
            createdBy: ctx.user?.id ? Number(ctx.user.id) : null,
          });

          await db.insert(riskRegisterActivityLog).values({
            entryId: result[0].insertId,
            action: "auto_created",
            performedByName: "System",
            notes: JSON.stringify({ source: sourceType, reportId: input.reportId, severity: f.rfSeverity }),
          });
          created++;
        }
      }

      return { created, updated, skipped, total: findings.length };
    }),

  // ─── CTEM Sync — bulk ingest ───
  ctemSync: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        weaknessName: z.string(),
        weaknessDescription: z.string().optional(),
        severity: severityEnum,
        assetIdentifier: z.string(),
        sourceIdentifier: z.string(),
        detectorSource: z.string(),
        controls: z.string().optional(),
        cvssScore: z.string().optional(),
        cve: z.string().optional(),
        remediationPlan: z.string().optional(),
      })),
      defaultSlaMonths: z.number().default(1),
      pointOfContact: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      let created = 0, updated = 0;

      for (let i = 0; i < input.findings.length; i++) {
        const f = input.findings[i];
        const [existing] = await db.select().from(riskRegisterEntries)
          .where(and(
            eq(riskRegisterEntries.weaknessName, f.weaknessName),
            like(riskRegisterEntries.assetIdentifier, `%${f.assetIdentifier.slice(0, 50)}%`),
          ));

        if (existing) {
          await db.update(riskRegisterEntries).set({ statusDate: sql`NOW()`, updatedAt: sql`NOW()` })
            .where(eq(riskRegisterEntries.id, existing.id));
          updated++;
        } else {
          const slaDate = new Date();
          slaDate.setMonth(slaDate.getMonth() + input.defaultSlaMonths);

          await db.insert(riskRegisterEntries).values({
            poamId: generatePoamId("ctem", i + 1),
            controls: f.controls || null,
            weaknessName: f.weaknessName,
            weaknessDescription: f.weaknessDescription || null,
            weaknessDetectorSource: f.detectorSource,
            weaknessSourceIdentifier: f.sourceIdentifier,
            assetIdentifier: f.assetIdentifier,
            pointOfContact: input.pointOfContact || null,
            originalRiskRating: f.severity,
            adjustedRiskRating: f.severity,
            severity: f.severity,
            category: "vulnerability",
            originalDetectionDate: sql`NOW()`,
            scheduledCompletionDate: slaDate.toISOString().slice(0, 19).replace("T", " "),
            remediationPlan: f.remediationPlan || null,
            status: "open",
            sourceType: "ctem",
            cve: f.cve || null,
            cvssScore: f.cvssScore || null,
            vendorDependency: "No",
          });
          created++;
        }
      }

      return { created, updated, total: input.findings.length };
    }),

  // ─── Executive Dashboard Metrics ───
  executiveMetrics: protectedProcedure
    .input(z.object({ days: z.number().default(90) }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const days = input?.days || 90;

      const openBySeverity = await db.select({
        severity: riskRegisterEntries.severity,
        count: sql<number>`count(*)`,
      }).from(riskRegisterEntries)
        .where(eq(riskRegisterEntries.status, "open"))
        .groupBy(riskRegisterEntries.severity);

      const [totalOpen] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries).where(eq(riskRegisterEntries.status, "open"));

      const [totalClosed] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries)
        .where(and(eq(riskRegisterEntries.status, "closed"), gte(riskRegisterEntries.closedAt, sql`DATE_SUB(NOW(), INTERVAL ${days} DAY)`)));

      const [overdueCount] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries)
        .where(and(eq(riskRegisterEntries.status, "open"), isNotNull(riskRegisterEntries.scheduledCompletionDate), lte(riskRegisterEntries.scheduledCompletionDate, sql`NOW()`)));

      const [acceptedCount] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries).where(eq(riskRegisterEntries.riskDecision, "risk_accepted"));

      const [vendorDepCount] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries)
        .where(and(eq(riskRegisterEntries.vendorDependency, "Yes"), eq(riskRegisterEntries.status, "open")));

      const closedItems = await db.select({
        detected: riskRegisterEntries.originalDetectionDate,
        closed: riskRegisterEntries.closedAt,
        severity: riskRegisterEntries.severity,
      }).from(riskRegisterEntries)
        .where(and(eq(riskRegisterEntries.status, "closed"), isNotNull(riskRegisterEntries.closedAt), gte(riskRegisterEntries.closedAt, sql`DATE_SUB(NOW(), INTERVAL ${days} DAY)`)));

      const mttrBySeverity: Record<string, { totalDays: number; count: number; avgDays: number }> = {};
      for (const item of closedItems) {
        if (item.detected && item.closed) {
          const sev = item.severity || "unknown";
          if (!mttrBySeverity[sev]) mttrBySeverity[sev] = { totalDays: 0, count: 0, avgDays: 0 };
          const diffDays = Math.max(0, (new Date(item.closed).getTime() - new Date(item.detected).getTime()) / 86400000);
          mttrBySeverity[sev].totalDays += diffDays;
          mttrBySeverity[sev].count++;
        }
      }
      for (const sev of Object.keys(mttrBySeverity)) {
        mttrBySeverity[sev].avgDays = Math.round(mttrBySeverity[sev].totalDays / mttrBySeverity[sev].count);
      }

      const [newInPeriod] = await db.select({ count: sql<number>`count(*)` })
        .from(riskRegisterEntries).where(gte(riskRegisterEntries.createdAt, sql`DATE_SUB(NOW(), INTERVAL ${days} DAY)`));

      const oldestOpen = await db.select().from(riskRegisterEntries)
        .where(eq(riskRegisterEntries.status, "open"))
        .orderBy(asc(riskRegisterEntries.originalDetectionDate))
        .limit(10);

      const sourceDistribution = await db.select({
        sourceType: riskRegisterEntries.sourceType,
        count: sql<number>`count(*)`,
      }).from(riskRegisterEntries).groupBy(riskRegisterEntries.sourceType);

      return {
        summary: {
          totalOpen: Number(totalOpen?.count ?? 0),
          totalClosedInPeriod: Number(totalClosed?.count ?? 0),
          overdue: Number(overdueCount?.count ?? 0),
          riskAccepted: Number(acceptedCount?.count ?? 0),
          vendorDependent: Number(vendorDepCount?.count ?? 0),
          newInPeriod: Number(newInPeriod?.count ?? 0),
        },
        openBySeverity: openBySeverity.map(r => ({ severity: r.severity, count: Number(r.count) })),
        mttrBySeverity,
        oldestOpen,
        sourceDistribution: sourceDistribution.map(r => ({ source: r.sourceType, count: Number(r.count) })),
      };
    }),

  // ─── Trend data ───
  trend: protectedProcedure
    .input(z.object({ months: z.number().default(6) }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const points: { month: string; opened: number; closed: number; netOpen: number }[] = [];

      for (let i = input.months - 1; i >= 0; i--) {
        const monthLabel = new Date(Date.now() - i * 30 * 86400000).toISOString().slice(0, 7);
        const [opened] = await db.select({ count: sql<number>`count(*)` })
          .from(riskRegisterEntries)
          .where(sql`DATE_FORMAT(${riskRegisterEntries.createdAt}, '%Y-%m') = ${monthLabel}`);
        const [closed] = await db.select({ count: sql<number>`count(*)` })
          .from(riskRegisterEntries)
          .where(and(eq(riskRegisterEntries.status, "closed"), sql`DATE_FORMAT(${riskRegisterEntries.closedAt}, '%Y-%m') = ${monthLabel}`));
        points.push({ month: monthLabel, opened: Number(opened?.count ?? 0), closed: Number(closed?.count ?? 0), netOpen: Number(opened?.count ?? 0) - Number(closed?.count ?? 0) });
      }
      return points;
    }),

  // ─── POA&M Export ───
  exportPoam: protectedProcedure
    .input(z.object({ status: z.enum(["open", "closed", "all"]).default("open") }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const statusFilter = input?.status === "all" ? undefined :
                           input?.status === "closed" ? eq(riskRegisterEntries.status, "closed") :
                           eq(riskRegisterEntries.status, "open");

      const entries = await db.select().from(riskRegisterEntries)
        .where(statusFilter || undefined)
        .orderBy(asc(riskRegisterEntries.poamId));

      const poamRows = entries.map(e => ({
        "POA&M ID": e.poamId,
        "Controls": e.controls || "",
        "Weakness Name": e.weaknessName,
        "Weakness Description": e.weaknessDescription || "",
        "Weakness Detector Source": e.weaknessDetectorSource || "",
        "Weakness Source Identifier": e.weaknessSourceIdentifier || "",
        "Asset Identifier": e.assetIdentifier || "",
        "Point of Contact": e.pointOfContact || "",
        "Resources Required": e.resourcesRequired || "",
        "Overall Remediation Plan": e.remediationPlan || "",
        "Original Detection Date": e.originalDetectionDate || "",
        "Scheduled Completion Date": e.scheduledCompletionDate || "",
        "Planned Milestones": e.milestones ? JSON.stringify(e.milestones) : "",
        "Milestone Changes": e.milestoneChanges ? JSON.stringify(e.milestoneChanges) : "",
        "Status Date": e.statusDate || "",
        "Vendor Dependency": e.vendorDependency || "No",
        "Last Vendor Check-In Date": e.lastVendorCheckinDate || "",
        "Vendor Dependent Product Name": e.vendorDependentProductName || "",
        "Original Risk Rating": e.originalRiskRating || "",
        "Adjusted Risk Rating": e.adjustedRiskRating || "",
        "Risk Adjustment": e.riskAdjustment || "No",
        "False Positive": e.falsePositive || "No",
        "Operational Requirement": e.operationalRequirement || "No",
        "Deviation Rationale": e.deviationRationale || "",
        "Supporting Documents": e.supportingDocuments || "",
        "Comments": e.comments || "",
        "CVE": e.cve || "",
        "CVSS Score": e.cvssScore || "",
        "Status": e.status,
        "Actual Completion Date": e.actualCompletionDate || "",
      }));

      return { entries: poamRows, total: poamRows.length };
    }),

  // ─── Delete ───
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(riskRegisterActivityLog).where(eq(riskRegisterActivityLog.entryId, input.id));
      await db.delete(riskRegisterAttachments).where(eq(riskRegisterAttachments.entryId, input.id));
      await db.delete(riskRegisterEntries).where(eq(riskRegisterEntries.id, input.id));
      return { success: true };
    }),

  // ─── Bulk status update ───
  bulkUpdateStatus: protectedProcedure
    .input(z.object({
      ids: z.array(z.number()),
      status: statusEnum,
      justification: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const setValues: any = { status: input.status, updatedAt: sql`NOW()`, statusDate: sql`NOW()` };
      if (input.status === "closed") { setValues.closedAt = sql`NOW()`; setValues.actualCompletionDate = sql`NOW()`; }
      if (input.justification) setValues.riskDecisionJustification = input.justification;

      await db.update(riskRegisterEntries).set(setValues).where(inArray(riskRegisterEntries.id, input.ids));

      for (const id of input.ids) {
        await db.insert(riskRegisterActivityLog).values({
          entryId: id,
          action: "bulk_status_change",
          performedBy: ctx.user?.id ? Number(ctx.user.id) : null,
          performedByName: ctx.user?.name || "System",
          notes: JSON.stringify({ newStatus: input.status, justification: input.justification }),
        });
      }
      return { updated: input.ids.length };
    }),

  // ─── Available reports for auto-populate ───
  availableReports: protectedProcedure
    .query(async () => {
      const db = await getDbSafe();
      return db.select({
        reportId: ac3Reports.rptReportId,
        title: ac3Reports.rptTitle,
        assessmentType: ac3Reports.rptAssessmentType,
        status: ac3Reports.rptStatus,
        createdAt: ac3Reports.rptCreatedAt,
      }).from(ac3Reports)
        .where(eq(ac3Reports.rptStatus, "finalized"))
        .orderBy(desc(ac3Reports.rptCreatedAt))
        .limit(50);
    }),
});
