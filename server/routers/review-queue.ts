/**
 * Review Queue Router — Tier 2 LLM-Assisted Approval Workflow
 *
 * Provides CRUD operations for the review queue where operators
 * approve/reject LLM-generated scan plans, vuln triage, detection rules, etc.
 */
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { getDb } from "../db";
import {
  emitReviewItemCreated,
  emitReviewItemApproved,
  emitReviewItemRejected,
  emitReviewItemDeferred,
  emitReviewBulkApproved,
} from "../lib/ws-event-hub";
import { eq, desc, and, sql, or, inArray } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const reviewQueueRouter = router({
  /** List review queue items with filters */
  list: protectedProcedure
    .input(z.object({
      status: z.enum(["pending", "approved", "rejected", "deferred", "auto_approved", "expired", "all"]).default("pending"),
      category: z.enum(["scan_plan", "vuln_triage", "detection_rule", "exploit_plan", "hunt_hypothesis", "risk_score", "report_draft", "c2_action", "all"]).default("all"),
      engagementId: z.number().optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      const filters = input || { status: "pending", category: "all", limit: 50, offset: 0 };
      const conditions = [];

      if (filters.status !== "all") {
        conditions.push(eq(schema.reviewQueueItems.rqStatus, filters.status));
      }
      if (filters.category !== "all") {
        conditions.push(eq(schema.reviewQueueItems.category, filters.category));
      }
      if (filters.engagementId) {
        conditions.push(eq(schema.reviewQueueItems.engagementId, filters.engagementId));
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [items, countResult] = await Promise.all([
        db.select()
          .from(schema.reviewQueueItems)
          .where(where)
          .orderBy(desc(schema.reviewQueueItems.createdAt))
          .limit(filters.limit)
          .offset(filters.offset),
        db.select({ count: sql<number>`count(*)` })
          .from(schema.reviewQueueItems)
          .where(where),
      ]);

      return {
        items,
        total: countResult[0]?.count || 0,
        hasMore: (filters.offset + filters.limit) < (countResult[0]?.count || 0),
      };
    }),

  /** Get a single review queue item by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      const items = await db.select()
        .from(schema.reviewQueueItems)
        .where(eq(schema.reviewQueueItems.id, input.id))
        .limit(1);

      if (items.length === 0) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Review item not found" });
      }
      return items[0];
    }),

  /** Create a new review queue item (called by LLM orchestrator) */
  create: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      category: z.enum(["scan_plan", "vuln_triage", "detection_rule", "exploit_plan", "hunt_hypothesis", "risk_score", "report_draft", "c2_action"]),
      title: z.string().min(1).max(512),
      summary: z.string().min(1),
      llmRationale: z.string().optional(),
      llmConfidence: z.number().min(0).max(100).optional(),
      payloadJson: z.any(),
      riskLevel: z.enum(["critical", "high", "medium", "low", "info"]).default("medium"),
      autoApproveEligible: z.boolean().default(false),
      expiresAt: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      // Auto-approve if eligible and confidence > 90%
      const shouldAutoApprove = input.autoApproveEligible &&
        input.llmConfidence && input.llmConfidence >= 90 &&
        input.riskLevel !== "critical" && input.riskLevel !== "high";

      const result = await db.insert(schema.reviewQueueItems).values({
        engagementId: input.engagementId,
        category: input.category,
        title: input.title,
        summary: input.summary,
        llmRationale: input.llmRationale,
        llmConfidence: input.llmConfidence?.toFixed(2),
        payloadJson: input.payloadJson,
        riskLevel: input.riskLevel,
        rqStatus: shouldAutoApprove ? "auto_approved" : "pending",
        autoApproveEligible: input.autoApproveEligible ? 1 : 0,
        expiresAt: input.expiresAt,
        reviewedAt: shouldAutoApprove ? Date.now() : undefined,
        reviewedBy: shouldAutoApprove ? "auto-approve" : undefined,
      });

      const id = (result as any)[0]?.insertId;
      // Broadcast WebSocket event for real-time UI updates
      if (id) {
        emitReviewItemCreated({
          id,
          category: input.category,
          title: input.title,
          riskLevel: input.riskLevel,
          llmConfidence: input.llmConfidence,
          engagementId: input.engagementId,
          autoApproved: shouldAutoApprove,
        });
      }
      return { id, autoApproved: shouldAutoApprove };
    }),

  /** Approve a review queue item */
  approve: protectedProcedure
    .input(z.object({
      id: z.number(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      const items = await db.select()
        .from(schema.reviewQueueItems)
        .where(eq(schema.reviewQueueItems.id, input.id))
        .limit(1);

      if (items.length === 0) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Review item not found" });
      }
      if (items[0].rqStatus !== "pending" && items[0].rqStatus !== "deferred") {
        throw new TRPCError({ code: "BAD_REQUEST", message: `Cannot approve item in ${items[0].rqStatus} status` });
      }

      await db.update(schema.reviewQueueItems)
        .set({
          rqStatus: "approved",
          reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
          reviewedAt: Date.now(),
          reviewNotes: input.notes,
        })
        .where(eq(schema.reviewQueueItems.id, input.id));

       // Broadcast approval event
      emitReviewItemApproved({
        id: input.id,
        category: items[0].category,
        title: items[0].title,
        reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
        engagementId: items[0].engagementId ?? undefined,
      });
      return { success: true, id: input.id, status: "approved" };
    }),
  /** Reject a review queue item */
  reject: protectedProcedure
    .input(z.object({
      id: z.number(),
      notes: z.string().min(1, "Rejection reason is required"),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      const items = await db.select()
        .from(schema.reviewQueueItems)
        .where(eq(schema.reviewQueueItems.id, input.id))
        .limit(1);

      if (items.length === 0) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Review item not found" });
      }

      await db.update(schema.reviewQueueItems)
        .set({
          rqStatus: "rejected",
          reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
          reviewedAt: Date.now(),
          reviewNotes: input.notes,
        })
        .where(eq(schema.reviewQueueItems.id, input.id));

      // Broadcast rejection event
      emitReviewItemRejected({
        id: input.id,
        category: items[0].category,
        title: items[0].title,
        reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
        reason: input.notes,
        engagementId: items[0].engagementId ?? undefined,
      });
      return { success: true, id: input.id, status: "rejected" };
    }),
  /** Defer a review queue item for later review */
  defer: protectedProcedure
    .input(z.object({
      id: z.number(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      await db.update(schema.reviewQueueItems)
        .set({
          rqStatus: "deferred",
          reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
          reviewNotes: input.notes,
        })
        .where(eq(schema.reviewQueueItems.id, input.id));

      // Broadcast defer event
      emitReviewItemDeferred({
        id: input.id,
        category: "unknown",
        title: "Deferred item",
        reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
      });
      return { success: true, id: input.id, status: "deferred" };
    }),
  /** Bulk approve multiple items */
  bulkApprove: protectedProcedure
    .input(z.object({
      ids: z.array(z.number()).min(1).max(50),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });

      await db.update(schema.reviewQueueItems)
        .set({
          rqStatus: "approved",
          reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
          reviewedAt: Date.now(),
          reviewNotes: input.notes || "Bulk approved",
        })
        .where(
          and(
            inArray(schema.reviewQueueItems.id, input.ids),
            or(
              eq(schema.reviewQueueItems.rqStatus, "pending"),
              eq(schema.reviewQueueItems.rqStatus, "deferred")
            )
          )
        );

      // Broadcast bulk approval event
      emitReviewBulkApproved({
        ids: input.ids,
        count: input.ids.length,
        reviewedBy: ctx.user?.name || ctx.user?.openId || "operator",
      });
      return { success: true, approvedCount: input.ids.length };
    }),

  /** Get queue statistics */
  stats: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { pending: 0, approved: 0, rejected: 0, deferred: 0, autoApproved: 0, expired: 0, byCategory: {} };

    const rows = await db
      .select({
        status: schema.reviewQueueItems.rqStatus,
        category: schema.reviewQueueItems.category,
        count: sql<number>`count(*)`,
      })
      .from(schema.reviewQueueItems)
      .groupBy(schema.reviewQueueItems.rqStatus, schema.reviewQueueItems.category);

    const stats: Record<string, number> = { pending: 0, approved: 0, rejected: 0, deferred: 0, auto_approved: 0, expired: 0 };
    const byCategory: Record<string, Record<string, number>> = {};

    for (const row of rows) {
      stats[row.status] = (stats[row.status] || 0) + row.count;
      if (!byCategory[row.category]) byCategory[row.category] = {};
      byCategory[row.category][row.status] = row.count;
    }

    return { ...stats, byCategory };
  }),
});
