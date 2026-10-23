import { describe, expect, it } from "vitest";
import { evaluateAgentTenantIsolationStatus } from "./agent-tenant-isolation";

const clean = {
  deploymentsTenantColumn: 1,
  tasksTenantColumn: 1,
  unresolvedDeployments: 0,
  unresolvedTasks: 0,
  deploymentTenantMismatches: 0,
  orphanOrMismatchedTasks: 0,
  missingTenantReferences: 0,
};

describe("evaluateAgentTenantIsolationStatus", () => {
  it("permits live execution only when every schema and data condition is clean", () => {
    expect(evaluateAgentTenantIsolationStatus(clean)).toEqual({ ...clean, ready: true, reason: undefined });
  });

  it.each([
    ["missing deployment column", { ...clean, deploymentsTenantColumn: 0 }],
    ["missing task column", { ...clean, tasksTenantColumn: 0 }],
    ["unassigned deployment", { ...clean, unresolvedDeployments: 1 }],
    ["unassigned task", { ...clean, unresolvedTasks: 1 }],
    ["deployment engagement mismatch", { ...clean, deploymentTenantMismatches: 1 }],
    ["orphaned or mismatched task", { ...clean, orphanOrMismatchedTasks: 1 }],
    ["missing tenant reference", { ...clean, missingTenantReferences: 1 }],
  ])("fails closed for %s", (_label, status) => {
    const result = evaluateAgentTenantIsolationStatus(status);
    expect(result.ready).toBe(false);
    expect(result.reason).toBeTruthy();
  });
});
