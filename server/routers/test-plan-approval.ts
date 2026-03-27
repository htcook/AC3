/**
 * Test Plan Approval Gate — tRPC Router
 *
 * Manages the lifecycle of penetration test and red team exercise plans:
 *   - Generate plans from engagement context (LLM-powered)
 *   - Submit for customer review
 *   - Approve / reject / request revision
 *   - Track approval status in the pipeline
 *
 * @author Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, publicProcedure, router } from "../_core/trpc";
import { getDb, getDbRequired } from "../db";
import { testPlans, engagements } from "../../drizzle/schema";
import { eq, desc, and } from "drizzle-orm";
import { randomUUID } from "crypto";
import { createHash } from "crypto";

// ─── Input Schemas ────────────────────────────────────────────────────────

const generatePlanInput = z.object({
  engagementId: z.number(),
  planType: z.enum(["pentest", "red_team"]),
  /** Optional custom title override */
  title: z.string().optional(),
});

const submitForReviewInput = z.object({
  planId: z.string(),
  /** Optional reviewer info for external reviewers */
  reviewerName: z.string().optional(),
  reviewerEmail: z.string().email().optional(),
});

const reviewPlanInput = z.object({
  planId: z.string(),
  action: z.enum(["approve", "reject", "request_revision"]),
  comments: z.string().optional(),
  /** For rejection */
  rejectionReason: z.string().optional(),
  /** For revision request */
  revisionNotes: z.string().optional(),
});

const regeneratePlanInput = z.object({
  planId: z.string(),
  /** Optional guidance for regeneration */
  guidance: z.string().optional(),
});

// ─── Router ───────────────────────────────────────────────────────────────

export const testPlanApprovalRouter = router({
  /**
   * Generate a new test plan for an engagement.
   * Uses the test plan generator with engagement context.
   */
  generate: protectedProcedure
    .input(generatePlanInput)
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();

      // Get engagement data
      const [engagement] = await db
        .select()
        .from(engagements)
        .where(eq(engagements.id, input.engagementId))
        .limit(1);

      if (!engagement) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Engagement not found",
        });
      }

      // Import the test plan generator
      const { generateTestPlan } = await import("../lib/test-plan-generator");

      // Build generation context from engagement data
      const planTitle =
        input.title ||
        `${input.planType === "red_team" ? "Red Team Exercise" : "Penetration Test"} Plan — ${engagement.name}`;

      // Parse target domains and IPs from engagement
      const targetDomains = engagement.targetDomain
        ? engagement.targetDomain.split(",").map((d: string) => d.trim()).filter(Boolean)
        : [];
      const targetIpRanges = engagement.targetIpRange
        ? engagement.targetIpRange.split(",").map((r: string) => r.trim()).filter(Boolean)
        : [];

      // Parse RoE scope if available
      let roeScope: any = null;
      if (engagement.roeScope) {
        try {
          roeScope = typeof engagement.roeScope === "string"
            ? JSON.parse(engagement.roeScope)
            : engagement.roeScope;
        } catch {
          roeScope = null;
        }
      }

      // Generate the plan
      const plan = await generateTestPlan({
        engagementType: input.planType,
        engagementName: engagement.name,
        customerName: engagement.customerName || "Customer",
        targetDomains,
        targetIpRanges,
        roeStatus: engagement.roeStatus || "none",
        roeSigned: engagement.roeStatus === "signed",
        roeScope,
        startDate: engagement.startDate || undefined,
        endDate: engagement.endDate || undefined,
      });

      // Check for existing plans for this engagement/type
      const existing = await db
        .select()
        .from(testPlans)
        .where(
          and(
            eq(testPlans.engagementId, input.engagementId),
            eq(testPlans.planType, input.planType)
          )
        )
        .orderBy(desc(testPlans.version))
        .limit(1);

      const version = existing.length > 0 ? (existing[0].version || 1) + 1 : 1;
      const planId = `tp-${randomUUID().slice(0, 8)}`;

      // Store the plan
      await db.insert(testPlans).values({
        planId,
        engagementId: input.engagementId,
        planType: input.planType,
        title: planTitle,
        content: plan.content,
        structuredData: plan.structuredData || null,
        version,
        status: "draft",
        generatedBy: ctx.user.id,
      });

      return {
        planId,
        title: planTitle,
        version,
        status: "draft" as const,
        contentPreview: plan.content.slice(0, 500) + "...",
      };
    }),

  /**
   * Get a test plan by ID.
   */
  get: protectedProcedure
    .input(z.object({ planId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();

      const [plan] = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.planId, input.planId))
        .limit(1);

      if (!plan) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Test plan not found",
        });
      }

      return plan;
    }),

  /**
   * List test plans for an engagement.
   */
  listByEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();

      const plans = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.engagementId, input.engagementId))
        .orderBy(desc(testPlans.createdAt));

      return plans;
    }),

  /**
   * Submit a plan for customer review.
   */
  submitForReview: protectedProcedure
    .input(submitForReviewInput)
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();

      const [plan] = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.planId, input.planId))
        .limit(1);

      if (!plan) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Test plan not found",
        });
      }

      if (plan.status !== "draft" && plan.status !== "revision_requested") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `Cannot submit plan in "${plan.status}" status. Only draft or revision_requested plans can be submitted.`,
        });
      }

      await db
        .update(testPlans)
        .set({
          status: "pending_review",
          submittedAt: new Date().toISOString(),
          reviewerName: input.reviewerName || null,
          reviewerEmail: input.reviewerEmail || null,
        })
        .where(eq(testPlans.planId, input.planId));

      // Notify owner about the submission
      try {
        const { notifyOwner } = await import("../_core/notification");
        await notifyOwner({
          title: `Test Plan Submitted for Review`,
          content: `Test plan "${plan.title}" (v${plan.version}) has been submitted for customer review.${
            input.reviewerName ? ` Reviewer: ${input.reviewerName}` : ""
          }`,
        });
      } catch {
        // Notification failure is non-critical
      }

      return { success: true, status: "pending_review" as const };
    }),

  /**
   * Review a plan (approve, reject, or request revision).
   */
  review: protectedProcedure
    .input(reviewPlanInput)
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();

      const [plan] = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.planId, input.planId))
        .limit(1);

      if (!plan) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Test plan not found",
        });
      }

      if (plan.status !== "pending_review") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `Cannot review plan in "${plan.status}" status. Only pending_review plans can be reviewed.`,
        });
      }

      const now = new Date().toISOString();
      const updateData: Record<string, any> = {
        reviewedBy: ctx.user.id,
        reviewedAt: now,
        reviewComments: input.comments || null,
      };

      switch (input.action) {
        case "approve":
          updateData.status = "approved";
          updateData.approvedAt = now;
          // Generate signature hash for audit trail
          updateData.signatureHash = createHash("sha256")
            .update(`${plan.planId}:${plan.content}:${ctx.user.id}:${now}`)
            .digest("hex");
          break;

        case "reject":
          updateData.status = "rejected";
          updateData.rejectionReason = input.rejectionReason || "No reason provided";
          break;

        case "request_revision":
          updateData.status = "revision_requested";
          updateData.revisionNotes = input.revisionNotes || "Please revise the plan";
          break;
      }

      await db
        .update(testPlans)
        .set(updateData)
        .where(eq(testPlans.planId, input.planId));

      // Notify about the review outcome
      try {
        const { notifyOwner } = await import("../_core/notification");
        const actionLabel =
          input.action === "approve"
            ? "APPROVED"
            : input.action === "reject"
            ? "REJECTED"
            : "REVISION REQUESTED";
        await notifyOwner({
          title: `Test Plan ${actionLabel}`,
          content: `Test plan "${plan.title}" (v${plan.version}) has been ${actionLabel.toLowerCase()}.${
            input.comments ? ` Comments: ${input.comments}` : ""
          }`,
        });
      } catch {
        // Notification failure is non-critical
      }

      return {
        success: true,
        status: updateData.status,
        signatureHash: updateData.signatureHash || null,
      };
    }),

  /**
   * Regenerate a plan (creates a new version).
   */
  regenerate: protectedProcedure
    .input(regeneratePlanInput)
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();

      const [existingPlan] = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.planId, input.planId))
        .limit(1);

      if (!existingPlan) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Test plan not found",
        });
      }

      if (
        existingPlan.status !== "rejected" &&
        existingPlan.status !== "revision_requested" &&
        existingPlan.status !== "draft"
      ) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `Cannot regenerate plan in "${existingPlan.status}" status.`,
        });
      }

      // Get engagement for context
      const [engagement] = await db
        .select()
        .from(engagements)
        .where(eq(engagements.id, existingPlan.engagementId))
        .limit(1);

      if (!engagement) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Associated engagement not found",
        });
      }

      const { generateTestPlan } = await import("../lib/test-plan-generator");

      const targetDomains = engagement.targetDomain
        ? engagement.targetDomain.split(",").map((d: string) => d.trim()).filter(Boolean)
        : [];
      const targetIpRanges = engagement.targetIpRange
        ? engagement.targetIpRange.split(",").map((r: string) => r.trim()).filter(Boolean)
        : [];

      let roeScope: any = null;
      if (engagement.roeScope) {
        try {
          roeScope = typeof engagement.roeScope === "string"
            ? JSON.parse(engagement.roeScope)
            : engagement.roeScope;
        } catch {
          roeScope = null;
        }
      }

      // Include revision notes/rejection reason as guidance
      const additionalGuidance = [
        input.guidance,
        existingPlan.revisionNotes ? `Previous revision notes: ${existingPlan.revisionNotes}` : null,
        existingPlan.rejectionReason ? `Previous rejection reason: ${existingPlan.rejectionReason}` : null,
        existingPlan.reviewComments ? `Previous review comments: ${existingPlan.reviewComments}` : null,
      ]
        .filter(Boolean)
        .join("\n\n");

      const plan = await generateTestPlan({
        engagementType: existingPlan.planType as "pentest" | "red_team",
        engagementName: engagement.name,
        customerName: engagement.customerName || "Customer",
        targetDomains,
        targetIpRanges,
        roeStatus: engagement.roeStatus || "none",
        roeSigned: engagement.roeStatus === "signed",
        roeScope,
        startDate: engagement.startDate || undefined,
        endDate: engagement.endDate || undefined,
        additionalGuidance,
      });

      const newVersion = (existingPlan.version || 1) + 1;
      const newPlanId = `tp-${randomUUID().slice(0, 8)}`;

      await db.insert(testPlans).values({
        planId: newPlanId,
        engagementId: existingPlan.engagementId,
        planType: existingPlan.planType,
        title: existingPlan.title,
        content: plan.content,
        structuredData: plan.structuredData || null,
        version: newVersion,
        status: "draft",
        generatedBy: ctx.user.id,
      });

      return {
        planId: newPlanId,
        version: newVersion,
        status: "draft" as const,
        contentPreview: plan.content.slice(0, 500) + "...",
      };
    }),

  /**
   * Get the approval status for an engagement's pipeline gate.
   * Returns whether the engagement has an approved test plan.
   */
  getApprovalStatus: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();

      const plans = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.engagementId, input.engagementId))
        .orderBy(desc(testPlans.createdAt));

      const approved = plans.find((p) => p.status === "approved");
      const pendingReview = plans.find((p) => p.status === "pending_review");
      const revisionRequested = plans.find((p) => p.status === "revision_requested");
      const draft = plans.find((p) => p.status === "draft");

      return {
        hasApprovedPlan: !!approved,
        approvedPlanId: approved?.planId || null,
        approvedAt: approved?.approvedAt || null,
        signatureHash: approved?.signatureHash || null,
        pendingReviewPlanId: pendingReview?.planId || null,
        revisionRequestedPlanId: revisionRequested?.planId || null,
        draftPlanId: draft?.planId || null,
        totalPlans: plans.length,
        latestVersion: plans[0]?.version || 0,
        /** Whether the pipeline can proceed past the test plan gate */
        gateOpen: !!approved,
      };
    }),

  /**
   * Delete a draft plan.
   */
  deleteDraft: protectedProcedure
    .input(z.object({ planId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [plan] = await db
        .select()
        .from(testPlans)
        .where(eq(testPlans.planId, input.planId))
        .limit(1);

      if (!plan) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Test plan not found",
        });
      }

      if (plan.status !== "draft") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Only draft plans can be deleted",
        });
      }

      await db.delete(testPlans).where(eq(testPlans.planId, input.planId));

      return { success: true };
    }),
});
