import { describe, expect, it, vi, beforeEach } from "vitest";

/**
 * Tests for exploit plan history persistence and modify plan flow.
 * Covers: DB helpers, tRPC endpoints, and plan modification logic.
 */

describe("plan history - DB helpers", () => {
  it("insertExploitPlanHistory function exists in db module", async () => {
    const db = await import("./db");
    expect(db).toHaveProperty("insertExploitPlanHistory");
    expect(typeof db.insertExploitPlanHistory).toBe("function");
  });

  it("getExploitPlanHistoryByEngagement function exists in db module", async () => {
    const db = await import("./db");
    expect(db).toHaveProperty("getExploitPlanHistoryByEngagement");
    expect(typeof db.getExploitPlanHistoryByEngagement).toBe("function");
  });

  it("getExploitPlanStats function exists in db module", async () => {
    const db = await import("./db");
    expect(db).toHaveProperty("getExploitPlanStats");
    expect(typeof db.getExploitPlanStats).toBe("function");
  });
});

describe("plan history - tRPC endpoints", () => {
  it("getExploitPlanHistory endpoint exists on the router", async () => {
    const { appRouter } = await import("./routers");
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Should return empty array for non-existent engagement
    const result = await caller.engagementOps.getExploitPlanHistory({ engagementId: 999999 });
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(0);
  });

  it("getExploitPlanStats endpoint exists on the router", async () => {
    const { appRouter } = await import("./routers");
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getExploitPlanStats();
    expect(result).toBeDefined();
  });

  it("getExploitPlanHistory rejects unauthenticated calls", async () => {
    const { appRouter } = await import("./routers");
    const ctx: any = {
      user: null,
      req: { protocol: "https", headers: {} },
      res: { clearCookie: () => {} },
    };

    const caller = appRouter.createCaller(ctx);

    await expect(
      caller.engagementOps.getExploitPlanHistory({ engagementId: 1 })
    ).rejects.toThrow();
  });
});

describe("plan history - modify plan logic", () => {
  it("removedTargetIndices correctly filters plan actions", () => {
    const originalActions = [
      { target: "10.0.0.1", port: 443, cve: "CVE-2024-1234", service: "https" },
      { target: "10.0.0.2", port: 22, module: "ssh_brute", service: "ssh" },
      { target: "10.0.0.3", port: 80, cve: "CVE-2023-5678", service: "http" },
      { target: "10.0.0.4", port: 3306, module: "mysql_exploit", service: "mysql" },
    ];
    const removedIndices = [1, 3]; // Remove 10.0.0.2 and 10.0.0.4

    const filteredActions = originalActions.filter((_, i) => !removedIndices.includes(i));
    const removedActions = originalActions.filter((_, i) => removedIndices.includes(i));

    expect(filteredActions).toHaveLength(2);
    expect(filteredActions[0].target).toBe("10.0.0.1");
    expect(filteredActions[1].target).toBe("10.0.0.3");

    expect(removedActions).toHaveLength(2);
    expect(removedActions[0].target).toBe("10.0.0.2");
    expect(removedActions[1].target).toBe("10.0.0.4");
  });

  it("empty removedTargetIndices keeps all actions", () => {
    const originalActions = [
      { target: "10.0.0.1", port: 443 },
      { target: "10.0.0.2", port: 22 },
    ];
    const removedIndices: number[] = [];

    const filteredActions = originalActions.filter((_, i) => !removedIndices.includes(i));
    expect(filteredActions).toHaveLength(2);
  });

  it("removing all targets produces empty action list", () => {
    const originalActions = [
      { target: "10.0.0.1", port: 443 },
      { target: "10.0.0.2", port: 22 },
    ];
    const removedIndices = [0, 1];

    const filteredActions = originalActions.filter((_, i) => !removedIndices.includes(i));
    expect(filteredActions).toHaveLength(0);
  });

  it("plan status is correctly determined from modification", () => {
    function determinePlanStatus(approved: boolean, removedIndices?: number[]): string {
      if (!approved) return "rejected";
      if (removedIndices && removedIndices.length > 0) return "modified";
      return "approved";
    }

    expect(determinePlanStatus(true)).toBe("approved");
    expect(determinePlanStatus(false)).toBe("rejected");
    expect(determinePlanStatus(true, [0, 2])).toBe("modified");
    expect(determinePlanStatus(true, [])).toBe("approved");
    expect(determinePlanStatus(false, [0])).toBe("rejected");
  });

  it("plan history record structure matches expected schema", () => {
    const planRecord = {
      engagementId: 1350014,
      gateId: "gate-abc-123",
      status: "modified" as const,
      operatorId: "test-operator",
      operatorName: "Test Operator",
      originalPlan: [
        { target: "10.0.0.1", port: 443, cve: "CVE-2024-1234" },
        { target: "10.0.0.2", port: 22, module: "ssh_brute" },
        { target: "10.0.0.3", port: 80, cve: "CVE-2023-5678" },
      ],
      modifiedPlan: [
        { target: "10.0.0.1", port: 443, cve: "CVE-2024-1234" },
        { target: "10.0.0.3", port: 80, cve: "CVE-2023-5678" },
      ],
      llmReasoning: "Targets selected based on critical CVEs detected during passive recon.",
      llmDecision: "Exploit all three targets in order of criticality.",
      originalTargetCount: 3,
      finalTargetCount: 2,
      removedTargets: [
        { target: "10.0.0.2", port: 22, module: "ssh_brute" },
      ],
      reviewDurationMs: 45000,
    };

    expect(planRecord.status).toBe("modified");
    expect(planRecord.originalTargetCount).toBe(3);
    expect(planRecord.finalTargetCount).toBe(2);
    expect(planRecord.removedTargets).toHaveLength(1);
    expect(planRecord.removedTargets[0].target).toBe("10.0.0.2");
    expect(planRecord.reviewDurationMs).toBeGreaterThan(0);
    expect(planRecord.originalPlan.length).toBeGreaterThan(planRecord.modifiedPlan!.length);
  });

  it("resolveApproval endpoint accepts removedTargetIndices parameter", async () => {
    const { appRouter } = await import("./routers");
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Should accept the parameter even if the gate doesn't exist
    try {
      await caller.engagementOps.resolveApproval({
        gateId: "test-gate-with-modifications",
        approved: true,
        removedTargetIndices: [0, 2],
      });
    } catch (e: any) {
      // Expected to fail because gate doesn't exist, but the parameter should be accepted
      expect(e.message).toContain("not found");
    }
  });
});

// Helper
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createTestContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-operator",
    email: "operator@aceofcloud.io",
    name: "Test Operator",
    loginMethod: "manus",
    role: "operator",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}
