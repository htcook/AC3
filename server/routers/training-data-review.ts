/**
 * Training Data Quality Review & JSONL Export Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Provides:
 *   1. Review workflow — approve, reject, flag training examples with notes
 *   2. Bulk review actions — batch approve/reject/flag
 *   3. Review analytics — review progress, quality distribution by reviewer
 *   4. JSONL export — multi-format export for fine-tuning pipelines
 */

import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { getDb } from "../db";
import { llmTrainingExamples } from "../../drizzle/schema";
import { eq, and, desc, sql, gte, lte, like, count, inArray, or } from "drizzle-orm";
import { TRPCError } from "@trpc/server";

// ─── Export Format Helpers ──────────────────────────────────────────────────

interface TrainingMessage {
  role: string;
  content: string;
}

function toOpenAIChatFormat(messages: TrainingMessage[], model: string) {
  return {
    messages: messages.map((m) => ({
      role: m.role as "system" | "user" | "assistant",
      content: m.content,
    })),
  };
}

function toAnthropicFormat(messages: TrainingMessage[], model: string) {
  const system = messages.find((m) => m.role === "system")?.content || "";
  const turns = messages
    .filter((m) => m.role !== "system")
    .map((m) => ({
      role: m.role === "assistant" ? ("assistant" as const) : ("user" as const),
      content: m.content,
    }));
  return { system, messages: turns };
}

function toRawFormat(messages: TrainingMessage[], model: string, metadata: any) {
  return { model, messages, metadata };
}

export const trainingDataReviewRouter = router({
  // ─── Review Overview Stats ────────────────────────────────────────────────
  getReviewOverview: protectedProcedure.query(async () => {
    const db = await getDb();

    const [stats] = await db
      .select({
        total: sql<number>`COUNT(*)`,
        pendingReview: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'pending_review' THEN 1 ELSE 0 END)`,
        approved: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'approved' THEN 1 ELSE 0 END)`,
        rejected: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'rejected' THEN 1 ELSE 0 END)`,
        flagged: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'flagged' THEN 1 ELSE 0 END)`,
        avgQualityScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
        highQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'high' THEN 1 ELSE 0 END)`,
        mediumQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'medium' THEN 1 ELSE 0 END)`,
        lowQuality: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'low' THEN 1 ELSE 0 END)`,
      })
      .from(llmTrainingExamples);

    // Per-model review progress
    const modelProgress = await db
      .select({
        model: llmTrainingExamples.model,
        total: sql<number>`COUNT(*)`,
        approved: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'approved' THEN 1 ELSE 0 END)`,
        rejected: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'rejected' THEN 1 ELSE 0 END)`,
        pending: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'pending_review' THEN 1 ELSE 0 END)`,
        flagged: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'flagged' THEN 1 ELSE 0 END)`,
        avgScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
      })
      .from(llmTrainingExamples)
      .groupBy(llmTrainingExamples.model)
      .orderBy(desc(sql`COUNT(*)`));

    // Per-source review progress
    const sourceProgress = await db
      .select({
        source: llmTrainingExamples.source,
        total: sql<number>`COUNT(*)`,
        approved: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'approved' THEN 1 ELSE 0 END)`,
        rejected: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'rejected' THEN 1 ELSE 0 END)`,
        pending: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.reviewStatus} = 'pending_review' THEN 1 ELSE 0 END)`,
      })
      .from(llmTrainingExamples)
      .groupBy(llmTrainingExamples.source);

    return {
      summary: {
        total: Number(stats.total) || 0,
        pendingReview: Number(stats.pendingReview) || 0,
        approved: Number(stats.approved) || 0,
        rejected: Number(stats.rejected) || 0,
        flagged: Number(stats.flagged) || 0,
        avgQualityScore: Number(Number(stats.avgQualityScore || 0).toFixed(2)),
        reviewProgress: stats.total
          ? Number(
              (
                ((Number(stats.approved) + Number(stats.rejected)) /
                  Number(stats.total)) *
                100
              ).toFixed(1)
            )
          : 0,
        qualityDistribution: {
          high: Number(stats.highQuality) || 0,
          medium: Number(stats.mediumQuality) || 0,
          low: Number(stats.lowQuality) || 0,
        },
      },
      modelProgress: modelProgress.map((m) => ({
        model: m.model,
        total: Number(m.total),
        approved: Number(m.approved),
        rejected: Number(m.rejected),
        pending: Number(m.pending),
        flagged: Number(m.flagged),
        avgScore: Number(Number(m.avgScore || 0).toFixed(2)),
        reviewProgress: m.total
          ? Number(
              (
                ((Number(m.approved) + Number(m.rejected)) / Number(m.total)) *
                100
              ).toFixed(1)
            )
          : 0,
      })),
      sourceProgress: sourceProgress.map((s) => ({
        source: s.source,
        total: Number(s.total),
        approved: Number(s.approved),
        rejected: Number(s.rejected),
        pending: Number(s.pending),
      })),
    };
  }),

  // ─── List Examples for Review ─────────────────────────────────────────────
  listForReview: protectedProcedure
    .input(
      z
        .object({
          page: z.number().min(1).default(1),
          pageSize: z.number().min(10).max(100).default(25),
          reviewStatus: z
            .enum(["pending_review", "approved", "rejected", "flagged", "all"])
            .default("pending_review"),
          quality: z
            .enum(["high", "medium", "low", "rejected", "all"])
            .default("all"),
          source: z
            .enum(["lab_scenario", "live_engagement", "manual", "synthetic", "all"])
            .default("all"),
          model: z.string().optional(),
          minScore: z.number().min(0).max(1).optional(),
          maxScore: z.number().min(0).max(1).optional(),
          search: z.string().optional(),
        })
        .optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      const page = input?.page ?? 1;
      const pageSize = input?.pageSize ?? 25;
      const offset = (page - 1) * pageSize;

      const conditions: any[] = [];
      if (input?.reviewStatus && input.reviewStatus !== "all") {
        conditions.push(
          eq(llmTrainingExamples.reviewStatus, input.reviewStatus)
        );
      }
      if (input?.quality && input.quality !== "all") {
        conditions.push(eq(llmTrainingExamples.quality, input.quality));
      }
      if (input?.source && input.source !== "all") {
        conditions.push(eq(llmTrainingExamples.source, input.source));
      }
      if (input?.model) {
        conditions.push(like(llmTrainingExamples.model, `%${input.model}%`));
      }
      if (input?.minScore !== undefined) {
        conditions.push(gte(llmTrainingExamples.qualityScore, input.minScore));
      }
      if (input?.maxScore !== undefined) {
        conditions.push(lte(llmTrainingExamples.qualityScore, input.maxScore));
      }

      const whereClause =
        conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db
        .select({ total: sql<number>`COUNT(*)` })
        .from(llmTrainingExamples)
        .where(whereClause);

      const rows = await db
        .select()
        .from(llmTrainingExamples)
        .where(whereClause)
        .orderBy(desc(llmTrainingExamples.createdAt))
        .limit(pageSize)
        .offset(offset);

      return {
        rows,
        total: Number(countResult.total) || 0,
        page,
        pageSize,
        totalPages: Math.ceil((Number(countResult.total) || 0) / pageSize),
      };
    }),

  // ─── Single Review Action ─────────────────────────────────────────────────
  reviewExample: protectedProcedure
    .input(
      z.object({
        exampleId: z.string(),
        action: z.enum(["approve", "reject", "flag", "reset"]),
        notes: z.string().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const reviewer = ctx.user?.name || ctx.user?.openId || "unknown";
      const now = new Date().toISOString().slice(0, 19).replace("T", " ");

      const statusMap: Record<string, string> = {
        approve: "approved",
        reject: "rejected",
        flag: "flagged",
        reset: "pending_review",
      };

      const newStatus = statusMap[input.action] as
        | "approved"
        | "rejected"
        | "flagged"
        | "pending_review";

      await db
        .update(llmTrainingExamples)
        .set({
          reviewStatus: newStatus,
          reviewedBy: input.action === "reset" ? null : reviewer,
          reviewedAt: input.action === "reset" ? null : now,
          reviewNotes: input.notes || null,
        })
        .where(eq(llmTrainingExamples.exampleId, input.exampleId));

      return { success: true, exampleId: input.exampleId, newStatus };
    }),

  // ─── Bulk Review Action ───────────────────────────────────────────────────
  bulkReview: protectedProcedure
    .input(
      z.object({
        exampleIds: z.array(z.string()).min(1).max(500),
        action: z.enum(["approve", "reject", "flag", "reset"]),
        notes: z.string().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const reviewer = ctx.user?.name || ctx.user?.openId || "unknown";
      const now = new Date().toISOString().slice(0, 19).replace("T", " ");

      const statusMap: Record<string, string> = {
        approve: "approved",
        reject: "rejected",
        flag: "flagged",
        reset: "pending_review",
      };

      const newStatus = statusMap[input.action] as
        | "approved"
        | "rejected"
        | "flagged"
        | "pending_review";

      // Process in chunks of 50 to avoid query limits
      let processed = 0;
      const chunkSize = 50;
      for (let i = 0; i < input.exampleIds.length; i += chunkSize) {
        const chunk = input.exampleIds.slice(i, i + chunkSize);
        await db
          .update(llmTrainingExamples)
          .set({
            reviewStatus: newStatus,
            reviewedBy: input.action === "reset" ? null : reviewer,
            reviewedAt: input.action === "reset" ? null : now,
            reviewNotes: input.notes || null,
          })
          .where(inArray(llmTrainingExamples.exampleId, chunk));
        processed += chunk.length;
      }

      return {
        success: true,
        processed,
        newStatus,
      };
    }),

  // ─── Auto-Approve by Quality Threshold ────────────────────────────────────
  autoApproveByThreshold: protectedProcedure
    .input(
      z.object({
        minQualityScore: z.number().min(0).max(1).default(0.85),
        qualityFilter: z
          .enum(["high", "medium", "all"])
          .default("high"),
        model: z.string().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const reviewer = ctx.user?.name || ctx.user?.openId || "auto-approve";
      const now = new Date().toISOString().slice(0, 19).replace("T", " ");

      const conditions: any[] = [
        eq(llmTrainingExamples.reviewStatus, "pending_review"),
        gte(llmTrainingExamples.qualityScore, input.minQualityScore),
      ];

      if (input.qualityFilter !== "all") {
        if (input.qualityFilter === "high") {
          conditions.push(eq(llmTrainingExamples.quality, "high"));
        } else {
          conditions.push(
            or(
              eq(llmTrainingExamples.quality, "high"),
              eq(llmTrainingExamples.quality, "medium")
            )
          );
        }
      }

      if (input.model) {
        conditions.push(like(llmTrainingExamples.model, `%${input.model}%`));
      }

      // Count how many will be affected
      const [countResult] = await db
        .select({ total: sql<number>`COUNT(*)` })
        .from(llmTrainingExamples)
        .where(and(...conditions));

      // Apply auto-approve
      await db
        .update(llmTrainingExamples)
        .set({
          reviewStatus: "approved",
          reviewedBy: `${reviewer} (auto)`,
          reviewedAt: now,
          reviewNotes: `Auto-approved: score >= ${input.minQualityScore}, quality = ${input.qualityFilter}`,
        })
        .where(and(...conditions));

      return {
        success: true,
        approvedCount: Number(countResult.total) || 0,
      };
    }),

  // ─── JSONL Export ─────────────────────────────────────────────────────────
  exportJsonl: protectedProcedure
    .input(
      z.object({
        format: z
          .enum(["openai_chat", "anthropic", "raw"])
          .default("openai_chat"),
        reviewStatus: z
          .enum(["approved", "pending_review", "all"])
          .default("approved"),
        quality: z
          .enum(["high", "medium", "low", "all"])
          .default("all"),
        minScore: z.number().min(0).max(1).optional(),
        model: z.string().optional(),
        source: z
          .enum(["lab_scenario", "live_engagement", "manual", "synthetic", "all"])
          .default("all"),
        limit: z.number().min(1).max(10000).default(5000),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();

      const conditions: any[] = [];
      if (input.reviewStatus !== "all") {
        conditions.push(
          eq(llmTrainingExamples.reviewStatus, input.reviewStatus)
        );
      }
      if (input.quality !== "all") {
        conditions.push(eq(llmTrainingExamples.quality, input.quality));
      }
      if (input.minScore !== undefined) {
        conditions.push(gte(llmTrainingExamples.qualityScore, input.minScore));
      }
      if (input.model) {
        conditions.push(like(llmTrainingExamples.model, `%${input.model}%`));
      }
      if (input.source !== "all") {
        conditions.push(eq(llmTrainingExamples.source, input.source));
      }

      const whereClause =
        conditions.length > 0 ? and(...conditions) : undefined;

      const rows = await db
        .select()
        .from(llmTrainingExamples)
        .where(whereClause)
        .orderBy(desc(llmTrainingExamples.qualityScore))
        .limit(input.limit);

      // Convert to selected format
      const lines = rows.map((row) => {
        const messages = (row.messages as TrainingMessage[]) || [];
        const metadata = (row.metadata as any) || {};

        switch (input.format) {
          case "openai_chat":
            return JSON.stringify(toOpenAIChatFormat(messages, row.model));
          case "anthropic":
            return JSON.stringify(toAnthropicFormat(messages, row.model));
          case "raw":
            return JSON.stringify(toRawFormat(messages, row.model, metadata));
          default:
            return JSON.stringify(toOpenAIChatFormat(messages, row.model));
        }
      });

      // Build metadata header
      const exportMeta = {
        format: input.format,
        exampleCount: lines.length,
        filters: {
          reviewStatus: input.reviewStatus,
          quality: input.quality,
          minScore: input.minScore,
          model: input.model || "all",
          source: input.source,
        },
        exportedAt: new Date().toISOString(),
        datasetVersion: `caldera-training-${Date.now()}`,
        qualityDistribution: {
          high: rows.filter((r) => r.quality === "high").length,
          medium: rows.filter((r) => r.quality === "medium").length,
          low: rows.filter((r) => r.quality === "low").length,
        },
        modelDistribution: Object.entries(
          rows.reduce(
            (acc, r) => {
              acc[r.model] = (acc[r.model] || 0) + 1;
              return acc;
            },
            {} as Record<string, number>
          )
        ).map(([model, count]) => ({ model, count })),
      };

      return {
        jsonl: lines.join("\n"),
        metadata: exportMeta,
        filename: `training-data-${input.format}-${input.reviewStatus}-${Date.now()}.jsonl`,
      };
    }),

  // ─── Export Stats (preview before download) ───────────────────────────────
  getExportPreview: protectedProcedure
    .input(
      z.object({
        reviewStatus: z
          .enum(["approved", "pending_review", "all"])
          .default("approved"),
        quality: z.enum(["high", "medium", "low", "all"]).default("all"),
        minScore: z.number().min(0).max(1).optional(),
        model: z.string().optional(),
        source: z
          .enum(["lab_scenario", "live_engagement", "manual", "synthetic", "all"])
          .default("all"),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();

      const conditions: any[] = [];
      if (input.reviewStatus !== "all") {
        conditions.push(
          eq(llmTrainingExamples.reviewStatus, input.reviewStatus)
        );
      }
      if (input.quality !== "all") {
        conditions.push(eq(llmTrainingExamples.quality, input.quality));
      }
      if (input.minScore !== undefined) {
        conditions.push(gte(llmTrainingExamples.qualityScore, input.minScore));
      }
      if (input.model) {
        conditions.push(like(llmTrainingExamples.model, `%${input.model}%`));
      }
      if (input.source !== "all") {
        conditions.push(eq(llmTrainingExamples.source, input.source));
      }

      const whereClause =
        conditions.length > 0 ? and(...conditions) : undefined;

      const [stats] = await db
        .select({
          total: sql<number>`COUNT(*)`,
          avgScore: sql<number>`AVG(${llmTrainingExamples.qualityScore})`,
          highCount: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'high' THEN 1 ELSE 0 END)`,
          mediumCount: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'medium' THEN 1 ELSE 0 END)`,
          lowCount: sql<number>`SUM(CASE WHEN ${llmTrainingExamples.quality} = 'low' THEN 1 ELSE 0 END)`,
        })
        .from(llmTrainingExamples)
        .where(whereClause);

      const models = await db
        .select({
          model: llmTrainingExamples.model,
          count: sql<number>`COUNT(*)`,
        })
        .from(llmTrainingExamples)
        .where(whereClause)
        .groupBy(llmTrainingExamples.model)
        .orderBy(desc(sql`COUNT(*)`));

      return {
        totalExamples: Number(stats.total) || 0,
        avgQualityScore: Number(Number(stats.avgScore || 0).toFixed(2)),
        qualityBreakdown: {
          high: Number(stats.highCount) || 0,
          medium: Number(stats.mediumCount) || 0,
          low: Number(stats.lowCount) || 0,
        },
        modelBreakdown: models.map((m) => ({
          model: m.model,
          count: Number(m.count),
        })),
      };
    }),
});
