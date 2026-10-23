import { TRPCError } from "@trpc/server";
import { assertAgentTenantIsolationReady } from "./agent-tenant-isolation";

/**
 * Returns true only when the explicitly opt-in production execution switch is
 * set to the literal string "true". Missing, malformed, and mixed-case values
 * are all disabled so configuration drift cannot enable external operations.
 */
export function isLiveEngagementExecutionEnabled(value = process.env.AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED): boolean {
  return value === "true";
}

/**
 * Requires both the operator-controlled execution switch and a verified tenant
 * contract for agent deployments/tasks. Call immediately before dispatching any
 * live engagement work, whether the caller is a tRPC route, worker, or resume
 * hook.
 */
export async function assertLiveEngagementExecutionAllowed(db: any): Promise<void> {
  if (!isLiveEngagementExecutionEnabled()) {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: "Live engagement execution is disabled. Set AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED=true only after tenant-isolation verification succeeds.",
    });
  }

  await assertAgentTenantIsolationReady(db);
}
