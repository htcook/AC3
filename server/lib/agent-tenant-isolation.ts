import { TRPCError } from "@trpc/server";
import { and, eq, sql } from "drizzle-orm";
import { agentDeployments, engagements } from "../../drizzle/schema";

/**
 * Runtime status for the agent deployment/task tenancy contract.
 *
 * The migration intentionally expands with nullable columns so ambiguous legacy
 * records are never guessed into a tenant. Live execution is allowed only once
 * this status is fully ready; tenant-facing reads always use exact predicates.
 */
export interface AgentTenantIsolationStatus {
  ready: boolean;
  deploymentsTenantColumn: number;
  tasksTenantColumn: number;
  unresolvedDeployments: number;
  unresolvedTasks: number;
  deploymentTenantMismatches: number;
  orphanOrMismatchedTasks: number;
  missingTenantReferences: number;
  reason?: string;
}

type StatusRow = Omit<AgentTenantIsolationStatus, "ready" | "reason">;

const numberValue = (value: unknown): number => Number(value ?? 0);

/** Build a status object from the one-row database result; exported for tests. */
export function evaluateAgentTenantIsolationStatus(row: Partial<StatusRow>): AgentTenantIsolationStatus {
  const status: Omit<AgentTenantIsolationStatus, "ready" | "reason"> = {
    deploymentsTenantColumn: numberValue(row.deploymentsTenantColumn),
    tasksTenantColumn: numberValue(row.tasksTenantColumn),
    unresolvedDeployments: numberValue(row.unresolvedDeployments),
    unresolvedTasks: numberValue(row.unresolvedTasks),
    deploymentTenantMismatches: numberValue(row.deploymentTenantMismatches),
    orphanOrMismatchedTasks: numberValue(row.orphanOrMismatchedTasks),
    missingTenantReferences: numberValue(row.missingTenantReferences),
  };

  const reasons: string[] = [];
  if (status.deploymentsTenantColumn !== 1 || status.tasksTenantColumn !== 1) {
    reasons.push("required tenant_id columns are missing");
  }
  if (status.unresolvedDeployments > 0) reasons.push(`${status.unresolvedDeployments} unassigned deployment(s)`);
  if (status.unresolvedTasks > 0) reasons.push(`${status.unresolvedTasks} unassigned task(s)`);
  if (status.deploymentTenantMismatches > 0) {
    reasons.push(`${status.deploymentTenantMismatches} deployment/engagement tenant mismatch(es)`);
  }
  if (status.orphanOrMismatchedTasks > 0) {
    reasons.push(`${status.orphanOrMismatchedTasks} orphaned or cross-tenant task(s)`);
  }
  if (status.missingTenantReferences > 0) {
    reasons.push(`${status.missingTenantReferences} record(s) reference a missing tenant`);
  }

  return {
    ...status,
    ready: reasons.length === 0,
    reason: reasons.length ? reasons.join("; ") : undefined,
  };
}

/**
 * Read physical-schema and data-integrity readiness directly from MySQL.
 * Any error, including columns not yet created, is reported as unready.
 */
export async function getAgentTenantIsolationStatus(db: any): Promise<AgentTenantIsolationStatus> {
  try {
    const [rows] = await db.execute(sql`
      SELECT
        (
          SELECT COUNT(*)
          FROM information_schema.columns
          WHERE table_schema = DATABASE()
            AND table_name = 'agent_deployments'
            AND column_name = 'tenant_id'
        ) AS deploymentsTenantColumn,
        (
          SELECT COUNT(*)
          FROM information_schema.columns
          WHERE table_schema = DATABASE()
            AND table_name = 'agent_tasks'
            AND column_name = 'tenant_id'
        ) AS tasksTenantColumn,
        (
          SELECT COUNT(*)
          FROM agent_deployments
          WHERE tenant_id IS NULL
        ) AS unresolvedDeployments,
        (
          SELECT COUNT(*)
          FROM agent_tasks
          WHERE tenant_id IS NULL
        ) AS unresolvedTasks,
        (
          SELECT COUNT(*)
          FROM agent_deployments AS deployment
          INNER JOIN engagements AS engagement
            ON engagement.id = deployment.engagementId
          WHERE deployment.tenant_id <> engagement.eng_tenant_id
             OR engagement.eng_tenant_id IS NULL
        ) AS deploymentTenantMismatches,
        (
          SELECT COUNT(*)
          FROM agent_tasks AS task
          LEFT JOIN agent_deployments AS deployment
            ON deployment.id = task.agentId
          WHERE deployment.id IS NULL
             OR task.tenant_id <> deployment.tenant_id
        ) AS orphanOrMismatchedTasks,
        (
          SELECT COUNT(*)
          FROM (
            SELECT tenant_id FROM agent_deployments WHERE tenant_id IS NOT NULL
            UNION ALL
            SELECT tenant_id FROM agent_tasks WHERE tenant_id IS NOT NULL
          ) AS tenant_references
          LEFT JOIN tenants ON tenants.id = tenant_references.tenant_id
          WHERE tenants.id IS NULL
        ) AS missingTenantReferences
    `);

    return evaluateAgentTenantIsolationStatus((rows as StatusRow[])[0] ?? {});
  } catch (error: any) {
    return {
      ready: false,
      deploymentsTenantColumn: 0,
      tasksTenantColumn: 0,
      unresolvedDeployments: 0,
      unresolvedTasks: 0,
      deploymentTenantMismatches: 0,
      orphanOrMismatchedTasks: 0,
      missingTenantReferences: 0,
      reason: `agent tenant-isolation verification failed: ${error?.message ?? "unknown database error"}`,
    };
  }
}

/** Fail closed before a tenant-facing agent operation or any live dispatch. */
export async function assertAgentTenantIsolationReady(db: any): Promise<void> {
  const status = await getAgentTenantIsolationStatus(db);
  if (!status.ready) {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: "Agent tenant isolation is not ready. Live agent operations remain unavailable until the production verification passes.",
    });
  }
}

/** Return an agent only when it belongs to the exact active tenant. */
export async function getAgentForTenant(db: any, agentId: string, tenantId: number) {
  const [agent] = await db
    .select()
    .from(agentDeployments)
    .where(and(eq(agentDeployments.id, agentId), eq(agentDeployments.tenantId, tenantId)))
    .limit(1);

  if (!agent) {
    throw new TRPCError({ code: "NOT_FOUND", message: "Agent not found" });
  }
  return agent;
}

/** Ensure an engagement association cannot cross tenant boundaries. */
export async function assertEngagementForTenant(db: any, engagementId: number, tenantId: number): Promise<void> {
  const [engagement] = await db
    .select({ id: engagements.id })
    .from(engagements)
    .where(and(eq(engagements.id, engagementId), eq(engagements.engTenantId, tenantId)))
    .limit(1);

  if (!engagement) {
    throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
  }
}
