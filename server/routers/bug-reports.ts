/**
 * Bug Reports Admin Router
 *
 * CRUD endpoints for managing bug reports submitted by testers via AI chatbots.
 * Admin-only triage, assignment, status tracking, and resolution notes.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { bugReports } from "../../drizzle/schema";
import { eq, desc, sql, and, inArray } from "drizzle-orm";
import { TRPCError } from "@trpc/server";

export const bugReportsRouter = router({
  /** List all bug reports with filtering and pagination */
  list: protectedProcedure
    .input(
      z.object({
        status: z.enum(["all", "open", "in_progress", "resolved", "closed", "wont_fix"]).default("all"),
        severity: z.enum(["all", "critical", "high", "medium", "low"]).default("all"),
        category: z.enum(["all", "bug", "ui", "performance", "security", "feature_request"]).default("all"),
        search: z.string().optional(),
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { reports: [], total: 0 };

      const conditions: any[] = [];
      if (input.status !== "all") {
        conditions.push(eq(bugReports.status, input.status));
      }
      if (input.severity !== "all") {
        conditions.push(eq(bugReports.severity, input.severity));
      }
      if (input.category !== "all") {
        conditions.push(eq(bugReports.category, input.category));
      }
      if (input.search) {
        conditions.push(
          sql`(${bugReports.title} LIKE ${`%${input.search}%`} OR ${bugReports.description} LIKE ${`%${input.search}%`})`
        );
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [reports, countResult] = await Promise.all([
        db
          .select()
          .from(bugReports)
          .where(where)
          .orderBy(desc(bugReports.createdAt))
          .limit(input.limit)
          .offset(input.offset),
        db
          .select({ count: sql<number>`count(*)` })
          .from(bugReports)
          .where(where),
      ]);

      return {
        reports,
        total: countResult[0]?.count ?? 0,
      };
    }),

  /** Get a single bug report by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [report] = await db
        .select()
        .from(bugReports)
        .where(eq(bugReports.id, input.id))
        .limit(1);

      if (!report) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Bug report not found" });
      }
      return report;
    }),

  /** Update bug report status */
  updateStatus: protectedProcedure
    .input(
      z.object({
        id: z.number(),
        status: z.enum(["open", "in_progress", "resolved", "closed", "wont_fix"]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin" && ctx.user.role !== "team_lead") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only admins and team leads can update bug report status" });
      }

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const updates: any = { status: input.status };
      if (input.status === "resolved" || input.status === "closed") {
        updates.resolvedAt = sql`CURRENT_TIMESTAMP`;
      }

      await db.update(bugReports).set(updates).where(eq(bugReports.id, input.id));
      return { success: true };
    }),

  /** Add admin notes to a bug report */
  addNotes: protectedProcedure
    .input(
      z.object({
        id: z.number(),
        notes: z.string().min(1),
      })
    )
    .mutation(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin" && ctx.user.role !== "team_lead") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only admins and team leads can add notes" });
      }

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [existing] = await db
        .select({ adminNotes: bugReports.adminNotes })
        .from(bugReports)
        .where(eq(bugReports.id, input.id))
        .limit(1);

      const timestamp = new Date().toISOString().slice(0, 19).replace("T", " ");
      const newNote = `[${timestamp}] ${ctx.user.name || ctx.user.openId}: ${input.notes}`;
      const updatedNotes = existing?.adminNotes
        ? `${existing.adminNotes}\n${newNote}`
        : newNote;

      await db
        .update(bugReports)
        .set({ adminNotes: updatedNotes })
        .where(eq(bugReports.id, input.id));

      return { success: true };
    }),

  /** Bulk update status for multiple bug reports */
  bulkUpdateStatus: protectedProcedure
    .input(
      z.object({
        ids: z.array(z.number()).min(1),
        status: z.enum(["open", "in_progress", "resolved", "closed", "wont_fix"]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin" && ctx.user.role !== "team_lead") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only admins and team leads can bulk update" });
      }

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const updates: any = { status: input.status };
      if (input.status === "resolved" || input.status === "closed") {
        updates.resolvedAt = sql`CURRENT_TIMESTAMP`;
      }

      await db
        .update(bugReports)
        .set(updates)
        .where(inArray(bugReports.id, input.ids));

      return { success: true, updated: input.ids.length };
    }),

  /** Get summary statistics */
  stats: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { total: 0, byStatus: { open: 0, inProgress: 0, resolved: 0, closed: 0, wontFix: 0 }, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } };

    const [result] = await db
      .select({
        total: sql<number>`count(*)`,
        open: sql<number>`SUM(CASE WHEN ${bugReports.status} = 'open' THEN 1 ELSE 0 END)`,
        inProgress: sql<number>`SUM(CASE WHEN ${bugReports.status} = 'in_progress' THEN 1 ELSE 0 END)`,
        resolved: sql<number>`SUM(CASE WHEN ${bugReports.status} = 'resolved' THEN 1 ELSE 0 END)`,
        closed: sql<number>`SUM(CASE WHEN ${bugReports.status} = 'closed' THEN 1 ELSE 0 END)`,
        wontFix: sql<number>`SUM(CASE WHEN ${bugReports.status} = 'wont_fix' THEN 1 ELSE 0 END)`,
        critical: sql<number>`SUM(CASE WHEN ${bugReports.severity} = 'critical' THEN 1 ELSE 0 END)`,
        high: sql<number>`SUM(CASE WHEN ${bugReports.severity} = 'high' THEN 1 ELSE 0 END)`,
        medium: sql<number>`SUM(CASE WHEN ${bugReports.severity} = 'medium' THEN 1 ELSE 0 END)`,
        low: sql<number>`SUM(CASE WHEN ${bugReports.severity} = 'low' THEN 1 ELSE 0 END)`,
      })
      .from(bugReports);

    return {
      total: result?.total ?? 0,
      byStatus: {
        open: result?.open ?? 0,
        inProgress: result?.inProgress ?? 0,
        resolved: result?.resolved ?? 0,
        closed: result?.closed ?? 0,
        wontFix: result?.wontFix ?? 0,
      },
      bySeverity: {
        critical: result?.critical ?? 0,
        high: result?.high ?? 0,
        medium: result?.medium ?? 0,
        low: result?.low ?? 0,
      },
    };
  }),

  /** Delete a bug report (admin only) */
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only admins can delete bug reports" });
      }
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(bugReports).where(eq(bugReports.id, input.id));
      return { success: true };
    }),
});
