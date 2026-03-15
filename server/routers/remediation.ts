/**
 * Remediation Tracking Router
 *
 * Manages vulnerability remediation tasks — assign findings to teams,
 * set SLA deadlines, track fix rates, and verify fixes via re-scans.
 */
import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { remediationTasks, users, engagements } from "../../drizzle/schema";
import { sql, eq, and, desc, asc, gte, lte, inArray, isNull, isNotNull } from "drizzle-orm";

// ─── SLA Defaults (hours from creation) ─────────────────────────────────────
const SLA_DEFAULTS: Record<string, number> = {
  critical: 24,
  high: 72,
  medium: 168,   // 7 days
  low: 720,      // 30 days
  info: 2160,    // 90 days
};

export const remediationRouter = router({
  /**
   * List remediation tasks with filters
   */
  list: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        status: z.enum(["open", "assigned", "in_progress", "fixed", "verified", "wont_fix", "deferred"]).optional(),
        severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
        assignedTeam: z.string().optional(),
        overdueSlaOnly: z.boolean().optional(),
        limit: z.number().min(1).max(200).default(50),
        offset: z.number().min(0).default(0),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = getDbRequired();
      const filters: any[] = [];

      if (input?.engagementId) filters.push(eq(remediationTasks.engagementId, input.engagementId));
      if (input?.status) filters.push(eq(remediationTasks.status, input.status));
      if (input?.severity) filters.push(eq(remediationTasks.severity, input.severity));
      if (input?.assignedTeam) filters.push(eq(remediationTasks.assignedTeam, input.assignedTeam));
      if (input?.overdueSlaOnly) {
        filters.push(isNotNull(remediationTasks.slaDeadline));
        filters.push(lte(remediationTasks.slaDeadline, new Date().toISOString().slice(0, 19).replace("T", " ")));
        filters.push(sql`${remediationTasks.status} NOT IN ('fixed','verified','wont_fix')`);
      }

      const where = filters.length > 0 ? and(...filters) : undefined;

      const [tasks, countResult] = await Promise.all([
        db
          .select()
          .from(remediationTasks)
          .where(where)
          .orderBy(
            sql`FIELD(${remediationTasks.severity}, 'critical', 'high', 'medium', 'low', 'info')`,
            desc(remediationTasks.createdAt)
          )
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db
          .select({ count: sql<number>`COUNT(*)` })
          .from(remediationTasks)
          .where(where),
      ]);

      return {
        tasks,
        total: Number(countResult[0]?.count) || 0,
      };
    }),

  /**
   * Get a single remediation task by ID
   */
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = getDbRequired();
      const [task] = await db
        .select()
        .from(remediationTasks)
        .where(eq(remediationTasks.id, input.id))
        .limit(1);
      return task || null;
    }),

  /**
   * Create a new remediation task from a finding
   */
  create: protectedProcedure
    .input(
      z.object({
        engagementId: z.number(),
        findingId: z.number().optional(),
        scanResultId: z.number().optional(),
        title: z.string().min(1).max(512),
        description: z.string().optional(),
        severity: z.enum(["critical", "high", "medium", "low", "info"]).default("medium"),
        assignedTeam: z.string().optional(),
        assignedUserId: z.number().optional(),
        slaHours: z.number().optional(),
        cveId: z.string().optional(),
        affectedAsset: z.string().optional(),
        remediationGuidance: z.string().optional(),
        priority: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = getDbRequired();
      const slaHours = input.slaHours ?? SLA_DEFAULTS[input.severity] ?? 168;
      const slaDeadline = new Date(Date.now() + slaHours * 60 * 60 * 1000);

      const [result] = await db.insert(remediationTasks).values({
        engagementId: input.engagementId,
        findingId: input.findingId,
        scanResultId: input.scanResultId,
        title: input.title,
        description: input.description,
        severity: input.severity,
        status: input.assignedTeam || input.assignedUserId ? "assigned" : "open",
        assignedTeam: input.assignedTeam,
        assignedUserId: input.assignedUserId,
        slaDeadline: slaDeadline.toISOString().slice(0, 19).replace("T", " "),
        cveId: input.cveId,
        affectedAsset: input.affectedAsset,
        remediationGuidance: input.remediationGuidance,
        priority: input.priority ?? 0,
      });

      return { id: result.insertId, slaDeadline: slaDeadline.toISOString() };
    }),

  /**
   * Update a remediation task (assign, change status, add notes)
   */
  update: protectedProcedure
    .input(
      z.object({
        id: z.number(),
        status: z.enum(["open", "assigned", "in_progress", "fixed", "verified", "wont_fix", "deferred"]).optional(),
        assignedTeam: z.string().optional(),
        assignedUserId: z.number().optional(),
        slaDeadline: z.string().optional(),
        notes: z.string().optional(),
        priority: z.number().optional(),
        rescanId: z.number().optional(),
        rescanStatus: z.enum(["pending", "passed", "failed", "not_required"]).optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = getDbRequired();
      const updates: any = {};

      if (input.status) {
        updates.status = input.status;
        if (input.status === "fixed") {
          updates.fixedAt = new Date().toISOString().slice(0, 19).replace("T", " ");
        }
        if (input.status === "verified") {
          updates.verifiedAt = new Date().toISOString().slice(0, 19).replace("T", " ");
        }
      }
      if (input.assignedTeam !== undefined) updates.assignedTeam = input.assignedTeam;
      if (input.assignedUserId !== undefined) updates.assignedUserId = input.assignedUserId;
      if (input.slaDeadline) updates.slaDeadline = input.slaDeadline;
      if (input.notes !== undefined) updates.notes = input.notes;
      if (input.priority !== undefined) updates.priority = input.priority;
      if (input.rescanId !== undefined) updates.rescanId = input.rescanId;
      if (input.rescanStatus) updates.rescanStatus = input.rescanStatus;

      await db
        .update(remediationTasks)
        .set(updates)
        .where(eq(remediationTasks.id, input.id));

      return { success: true };
    }),

  /**
   * Bulk assign tasks to a team
   */
  bulkAssign: protectedProcedure
    .input(
      z.object({
        taskIds: z.array(z.number()).min(1),
        assignedTeam: z.string(),
        assignedUserId: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = getDbRequired();
      await db
        .update(remediationTasks)
        .set({
          assignedTeam: input.assignedTeam,
          assignedUserId: input.assignedUserId,
          status: "assigned",
        })
        .where(inArray(remediationTasks.id, input.taskIds));

      return { updated: input.taskIds.length };
    }),

  /**
   * Get remediation statistics for an engagement or globally
   */
  getStats: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const db = getDbRequired();
      const filter = input?.engagementId
        ? eq(remediationTasks.engagementId, input.engagementId)
        : undefined;

      const [stats] = await db
        .select({
          total: sql<number>`COUNT(*)`,
          open: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'open' THEN 1 ELSE 0 END)`,
          assigned: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'assigned' THEN 1 ELSE 0 END)`,
          inProgress: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'in_progress' THEN 1 ELSE 0 END)`,
          fixed: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'fixed' THEN 1 ELSE 0 END)`,
          verified: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'verified' THEN 1 ELSE 0 END)`,
          wontFix: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'wont_fix' THEN 1 ELSE 0 END)`,
          deferred: sql<number>`SUM(CASE WHEN ${remediationTasks.status} = 'deferred' THEN 1 ELSE 0 END)`,
          critical: sql<number>`SUM(CASE WHEN ${remediationTasks.severity} = 'critical' THEN 1 ELSE 0 END)`,
          high: sql<number>`SUM(CASE WHEN ${remediationTasks.severity} = 'high' THEN 1 ELSE 0 END)`,
          medium: sql<number>`SUM(CASE WHEN ${remediationTasks.severity} = 'medium' THEN 1 ELSE 0 END)`,
          low: sql<number>`SUM(CASE WHEN ${remediationTasks.severity} = 'low' THEN 1 ELSE 0 END)`,
          overdue: sql<number>`SUM(CASE WHEN ${remediationTasks.slaDeadline} < NOW() AND ${remediationTasks.status} NOT IN ('fixed','verified','wont_fix') THEN 1 ELSE 0 END)`,
          avgFixTimeHours: sql<number>`AVG(CASE WHEN ${remediationTasks.fixedAt} IS NOT NULL THEN TIMESTAMPDIFF(HOUR, ${remediationTasks.createdAt}, ${remediationTasks.fixedAt}) END)`,
          fixRate: sql<number>`CASE WHEN COUNT(*) > 0 THEN SUM(CASE WHEN ${remediationTasks.status} IN ('fixed','verified') THEN 1 ELSE 0 END) / COUNT(*) * 100 ELSE 0 END`,
          slaComplianceRate: sql<number>`CASE WHEN SUM(CASE WHEN ${remediationTasks.slaDeadline} IS NOT NULL THEN 1 ELSE 0 END) > 0 THEN SUM(CASE WHEN ${remediationTasks.fixedAt} IS NOT NULL AND ${remediationTasks.fixedAt} <= ${remediationTasks.slaDeadline} THEN 1 ELSE 0 END) / SUM(CASE WHEN ${remediationTasks.slaDeadline} IS NOT NULL THEN 1 ELSE 0 END) * 100 ELSE 0 END`,
        })
        .from(remediationTasks)
        .where(filter);

      // Get team breakdown
      const teamStats = await db
        .select({
          team: remediationTasks.assignedTeam,
          total: sql<number>`COUNT(*)`,
          fixed: sql<number>`SUM(CASE WHEN ${remediationTasks.status} IN ('fixed','verified') THEN 1 ELSE 0 END)`,
          overdue: sql<number>`SUM(CASE WHEN ${remediationTasks.slaDeadline} < NOW() AND ${remediationTasks.status} NOT IN ('fixed','verified','wont_fix') THEN 1 ELSE 0 END)`,
        })
        .from(remediationTasks)
        .where(filter)
        .groupBy(remediationTasks.assignedTeam)
        .orderBy(desc(sql`total`));

      return {
        ...stats,
        total: Number(stats.total) || 0,
        open: Number(stats.open) || 0,
        assigned: Number(stats.assigned) || 0,
        inProgress: Number(stats.inProgress) || 0,
        fixed: Number(stats.fixed) || 0,
        verified: Number(stats.verified) || 0,
        wontFix: Number(stats.wontFix) || 0,
        deferred: Number(stats.deferred) || 0,
        critical: Number(stats.critical) || 0,
        high: Number(stats.high) || 0,
        medium: Number(stats.medium) || 0,
        low: Number(stats.low) || 0,
        overdue: Number(stats.overdue) || 0,
        avgFixTimeHours: Math.round(Number(stats.avgFixTimeHours) || 0),
        fixRate: Math.round(Number(stats.fixRate) * 10) / 10,
        slaComplianceRate: Math.round(Number(stats.slaComplianceRate) * 10) / 10,
        teamBreakdown: teamStats.map((t) => ({
          team: t.team || "Unassigned",
          total: Number(t.total) || 0,
          fixed: Number(t.fixed) || 0,
          overdue: Number(t.overdue) || 0,
          fixRate: Number(t.total) > 0 ? Math.round((Number(t.fixed) / Number(t.total)) * 1000) / 10 : 0,
        })),
      };
    }),

  /**
   * Get SLA timeline — tasks approaching or past deadline
   */
  getSlaTimeline: protectedProcedure
    .input(z.object({ engagementId: z.number().optional(), daysAhead: z.number().default(7) }).optional())
    .query(async ({ input }) => {
      const db = getDbRequired();
      const filters: any[] = [
        isNotNull(remediationTasks.slaDeadline),
        sql`${remediationTasks.status} NOT IN ('fixed','verified','wont_fix')`,
      ];
      if (input?.engagementId) filters.push(eq(remediationTasks.engagementId, input.engagementId));

      const cutoff = new Date(Date.now() + (input?.daysAhead ?? 7) * 24 * 60 * 60 * 1000);
      filters.push(lte(remediationTasks.slaDeadline, cutoff.toISOString().slice(0, 19).replace("T", " ")));

      const tasks = await db
        .select()
        .from(remediationTasks)
        .where(and(...filters))
        .orderBy(asc(remediationTasks.slaDeadline))
        .limit(50);

      return tasks.map((t) => ({
        ...t,
        isOverdue: t.slaDeadline ? new Date(t.slaDeadline) < new Date() : false,
        hoursRemaining: t.slaDeadline
          ? Math.round((new Date(t.slaDeadline).getTime() - Date.now()) / (60 * 60 * 1000))
          : null,
      }));
    }),

  /**
   * Delete a remediation task (admin only)
   */
  delete: adminProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDbRequired();
      await db.delete(remediationTasks).where(eq(remediationTasks.id, input.id));
      return { success: true };
    }),

  /**
   * Get unique teams for filter dropdowns
   */
  getTeams: protectedProcedure.query(async () => {
    const db = getDbRequired();
    const teams = await db
      .selectDistinct({ team: remediationTasks.assignedTeam })
      .from(remediationTasks)
      .where(isNotNull(remediationTasks.assignedTeam));
    return teams.map((t) => t.team).filter(Boolean) as string[];
  }),
});
