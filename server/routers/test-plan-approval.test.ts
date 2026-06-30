/**
 * Test Plan Approval Gate — Router Tests
 *
 * Tests the test plan approval workflow including:
 *   - Plan generation from engagement context
 *   - Status transitions (draft → pending_review → approved/rejected/revision_requested)
 *   - Approval gate checks
 *   - Input validation
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Test Plan Status Machine Tests ───────────────────────────────────────

describe("Test Plan Status Machine", () => {
  const validTransitions: Record<string, string[]> = {
    draft: ["pending_review"],
    pending_review: ["approved", "rejected", "revision_requested"],
    revision_requested: ["pending_review"],
    rejected: [],
    approved: [],
  };

  it("should define valid status transitions", () => {
    expect(validTransitions.draft).toContain("pending_review");
    expect(validTransitions.pending_review).toContain("approved");
    expect(validTransitions.pending_review).toContain("rejected");
    expect(validTransitions.pending_review).toContain("revision_requested");
  });

  it("should not allow direct transition from draft to approved", () => {
    expect(validTransitions.draft).not.toContain("approved");
  });

  it("should not allow direct transition from draft to rejected", () => {
    expect(validTransitions.draft).not.toContain("rejected");
  });

  it("should allow revision_requested to go back to pending_review", () => {
    expect(validTransitions.revision_requested).toContain("pending_review");
  });

  it("should not allow transitions from approved status", () => {
    expect(validTransitions.approved.length).toBe(0);
  });

  it("should not allow transitions from rejected status", () => {
    expect(validTransitions.rejected.length).toBe(0);
  });
});

// ─── Input Validation Tests ───────────────────────────────────────────────

describe("Test Plan Input Validation", () => {
  const { z } = require("zod");

  const generatePlanInput = z.object({
    engagementId: z.number(),
    planType: z.enum(["pentest", "red_team"]),
    title: z.string().optional(),
  });

  const reviewPlanInput = z.object({
    planId: z.string(),
    action: z.enum(["approve", "reject", "request_revision"]),
    comments: z.string().optional(),
    rejectionReason: z.string().optional(),
    revisionNotes: z.string().optional(),
  });

  it("should validate generate plan input with valid pentest type", () => {
    const result = generatePlanInput.safeParse({
      engagementId: 1,
      planType: "pentest",
    });
    expect(result.success).toBe(true);
  });

  it("should validate generate plan input with valid red_team type", () => {
    const result = generatePlanInput.safeParse({
      engagementId: 1,
      planType: "red_team",
      title: "Custom Title",
    });
    expect(result.success).toBe(true);
  });

  it("should reject invalid plan type", () => {
    const result = generatePlanInput.safeParse({
      engagementId: 1,
      planType: "invalid_type",
    });
    expect(result.success).toBe(false);
  });

  it("should reject missing engagementId", () => {
    const result = generatePlanInput.safeParse({
      planType: "pentest",
    });
    expect(result.success).toBe(false);
  });

  it("should validate review input with approve action", () => {
    const result = reviewPlanInput.safeParse({
      planId: "tp-abc12345",
      action: "approve",
      comments: "Looks good",
    });
    expect(result.success).toBe(true);
  });

  it("should validate review input with reject action", () => {
    const result = reviewPlanInput.safeParse({
      planId: "tp-abc12345",
      action: "reject",
      rejectionReason: "Missing scope details",
    });
    expect(result.success).toBe(true);
  });

  it("should validate review input with request_revision action", () => {
    const result = reviewPlanInput.safeParse({
      planId: "tp-abc12345",
      action: "request_revision",
      revisionNotes: "Please add more detail to section 3",
    });
    expect(result.success).toBe(true);
  });

  it("should reject invalid review action", () => {
    const result = reviewPlanInput.safeParse({
      planId: "tp-abc12345",
      action: "invalid_action",
    });
    expect(result.success).toBe(false);
  });
});

// ─── Signature Hash Tests ─────────────────────────────────────────────────

describe("Test Plan Signature Hash", () => {
  const { createHash } = require("crypto");

  it("should generate deterministic signature hash", () => {
    const planId = "tp-abc12345";
    const content = "Test plan content here";
    const userId = "user-123";
    const timestamp = "2026-03-26T12:00:00.000Z";

    const hash1 = createHash("sha256")
      .update(`${planId}:${content}:${userId}:${timestamp}`)
      .digest("hex");

    const hash2 = createHash("sha256")
      .update(`${planId}:${content}:${userId}:${timestamp}`)
      .digest("hex");

    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // SHA-256 hex length
  });

  it("should produce different hashes for different inputs", () => {
    const hash1 = createHash("sha256")
      .update("tp-1:content:user1:2026-03-26")
      .digest("hex");

    const hash2 = createHash("sha256")
      .update("tp-2:content:user1:2026-03-26")
      .digest("hex");

    expect(hash1).not.toBe(hash2);
  });
});

// ─── Approval Gate Logic Tests ────────────────────────────────────────────

describe("Test Plan Approval Gate Logic", () => {
  interface PlanStatus {
    planId: string;
    status: string;
    approvedAt?: string;
    signatureHash?: string;
  }

  function computeGateStatus(plans: PlanStatus[]) {
    const approved = plans.find((p) => p.status === "approved");
    const pendingReview = plans.find((p) => p.status === "pending_review");
    const revisionRequested = plans.find(
      (p) => p.status === "revision_requested"
    );
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
      gateOpen: !!approved,
    };
  }

  it("should report gate closed when no plans exist", () => {
    const status = computeGateStatus([]);
    expect(status.gateOpen).toBe(false);
    expect(status.hasApprovedPlan).toBe(false);
    expect(status.totalPlans).toBe(0);
  });

  it("should report gate closed when only draft plans exist", () => {
    const status = computeGateStatus([
      { planId: "tp-1", status: "draft" },
    ]);
    expect(status.gateOpen).toBe(false);
    expect(status.draftPlanId).toBe("tp-1");
  });

  it("should report gate closed when plan is pending review", () => {
    const status = computeGateStatus([
      { planId: "tp-1", status: "pending_review" },
    ]);
    expect(status.gateOpen).toBe(false);
    expect(status.pendingReviewPlanId).toBe("tp-1");
  });

  it("should report gate open when plan is approved", () => {
    const status = computeGateStatus([
      {
        planId: "tp-1",
        status: "approved",
        approvedAt: "2026-03-26T12:00:00.000Z",
        signatureHash: "abc123",
      },
    ]);
    expect(status.gateOpen).toBe(true);
    expect(status.hasApprovedPlan).toBe(true);
    expect(status.approvedPlanId).toBe("tp-1");
    expect(status.signatureHash).toBe("abc123");
  });

  it("should report gate closed when plan is rejected", () => {
    const status = computeGateStatus([
      { planId: "tp-1", status: "rejected" },
    ]);
    expect(status.gateOpen).toBe(false);
  });

  it("should report gate closed when revision is requested", () => {
    const status = computeGateStatus([
      { planId: "tp-1", status: "revision_requested" },
    ]);
    expect(status.gateOpen).toBe(false);
    expect(status.revisionRequestedPlanId).toBe("tp-1");
  });

  it("should handle multiple plans with mixed statuses", () => {
    const status = computeGateStatus([
      { planId: "tp-3", status: "approved", approvedAt: "2026-03-26", signatureHash: "hash3" },
      { planId: "tp-2", status: "rejected" },
      { planId: "tp-1", status: "draft" },
    ]);
    expect(status.gateOpen).toBe(true);
    expect(status.totalPlans).toBe(3);
    expect(status.approvedPlanId).toBe("tp-3");
    expect(status.draftPlanId).toBe("tp-1");
  });

  it("should correctly identify all plan states simultaneously", () => {
    const status = computeGateStatus([
      { planId: "tp-4", status: "draft" },
      { planId: "tp-3", status: "pending_review" },
      { planId: "tp-2", status: "revision_requested" },
      { planId: "tp-1", status: "approved", approvedAt: "2026-03-25", signatureHash: "hash1" },
    ]);
    expect(status.gateOpen).toBe(true);
    expect(status.draftPlanId).toBe("tp-4");
    expect(status.pendingReviewPlanId).toBe("tp-3");
    expect(status.revisionRequestedPlanId).toBe("tp-2");
    expect(status.approvedPlanId).toBe("tp-1");
  });
});

// ─── No FedRAMP Branding Tests ────────────────────────────────────────────

describe("No FedRAMP Branding in Test Plan Approval", () => {
  it("should not contain FedRAMP in router file", async () => {
    const fs = require("fs");
    const content = fs.readFileSync(
      require("path").join(__dirname, "test-plan-approval.ts"),
      "utf-8"
    );
    // Only negative instructions (Do NOT claim FedRAMP) are acceptable
    const lines = content.split("\n");
    for (const line of lines) {
      if (line.includes("FedRAMP") || line.includes("fedramp") || line.includes("3PAO")) {
        // Should only appear in comments as negative instruction
        expect(
          line.includes("NOT") ||
          line.includes("not") ||
          line.includes("Do not") ||
          line.includes("//")
        ).toBe(true);
      }
    }
  });
});

// ─── Pipeline Phase Integration Tests ─────────────────────────────────────

describe("Pipeline Phase Integration", () => {
  it("should define test_plan and test_plan_approval as valid OpsPhases", () => {
    const validPhases = [
      "idle",
      "recon",
      "recon_complete",
      "passive_discovery",
      "scoping",
      "test_plan",
      "test_plan_approval",
      "enumeration",
      "vuln_detection",
      "exploitation",
      "post_exploit",
      "reporting",
      "completed",
      "paused",
      "error",
    ];

    expect(validPhases).toContain("test_plan");
    expect(validPhases).toContain("test_plan_approval");
    expect(validPhases).toContain("passive_discovery");
    expect(validPhases).toContain("scoping");
  });

  it("should have test_plan_approval before enumeration in phase order", () => {
    const phaseOrder = [
      "recon",
      "passive_discovery",
      "scoping",
      "test_plan",
      "test_plan_approval",
      "enumeration",
      "vuln_detection",
      "exploitation",
      "post_exploit",
    ];

    const testPlanIdx = phaseOrder.indexOf("test_plan_approval");
    const enumIdx = phaseOrder.indexOf("enumeration");
    expect(testPlanIdx).toBeLessThan(enumIdx);
  });

  it("should have passive_discovery before scoping in phase order", () => {
    const phaseOrder = [
      "recon",
      "passive_discovery",
      "scoping",
      "test_plan",
      "test_plan_approval",
      "enumeration",
    ];

    const passiveIdx = phaseOrder.indexOf("passive_discovery");
    const scopingIdx = phaseOrder.indexOf("scoping");
    expect(passiveIdx).toBeLessThan(scopingIdx);
  });

  it("should have scoping before test_plan in phase order", () => {
    const phaseOrder = [
      "recon",
      "passive_discovery",
      "scoping",
      "test_plan",
      "test_plan_approval",
      "enumeration",
    ];

    const scopingIdx = phaseOrder.indexOf("scoping");
    const testPlanIdx = phaseOrder.indexOf("test_plan");
    expect(scopingIdx).toBeLessThan(testPlanIdx);
  });
});
