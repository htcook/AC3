# Production Runbook: Agent Tenant Isolation (`0023` / `0024`)

## Purpose

This runbook remediates a tenant-isolation gap in `agent_deployments` and `agent_tasks`. The remediation uses two separately tracked migrations:

- `0023_agent_tenant_isolation`: additive nullable columns, deterministic backfill only, and query indexes.
- `0024_agent_tenant_isolation_contract`: `NOT NULL`, tenant foreign key, and a composite task-to-deployment foreign key. It runs only after the data-cleanliness preflight passes.

The application also denies live engagement dispatch unless `AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED` is exactly `true` **and** the database verifier reports a fully clean tenant contract.

## Immediate containment

1. In the **production ECS task secret**, set `AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED` to `false` and force a new deployment or stop/restart all running app tasks. Do this before beginning migration work.
2. Confirm the running task definition actually exposes that secret under the exact same environment-variable name. Do not rely on a local `.env` file.
3. Record the current immutable task-definition ARN and image digest for rollback.
4. Take a verified, restorable database snapshot. Do not proceed if snapshot creation or restore validation fails.
5. Confirm there are no active agent deployments, queued agent tasks, auto-resume jobs, or active-engagement worker jobs that could mutate the tables during migration.

Do **not** enable the flag merely because the two columns exist. The contract phase and readiness verification must both pass first.

## Preflight inventory (read-only)

Run these queries in the production database and retain their output in the change record:

```sql
SELECT hash, created_at
FROM __drizzle_migrations
WHERE hash IN ('0023_agent_tenant_isolation', '0024_agent_tenant_isolation_contract');

SHOW CREATE TABLE agent_deployments;
SHOW CREATE TABLE agent_tasks;

SELECT
  deployment.id,
  deployment.engagementId,
  deployment.requestedBy,
  deployment.tenant_id AS deployment_tenant_id,
  engagement.eng_tenant_id AS engagement_tenant_id
FROM agent_deployments AS deployment
LEFT JOIN engagements AS engagement ON engagement.id = deployment.engagementId
WHERE deployment.tenant_id IS NULL
   OR engagement.eng_tenant_id IS NULL
   OR deployment.tenant_id <> engagement.eng_tenant_id;

SELECT
  task.id AS task_id,
  task.agentId,
  task.tenant_id AS task_tenant_id,
  deployment.tenant_id AS deployment_tenant_id
FROM agent_tasks AS task
LEFT JOIN agent_deployments AS deployment ON deployment.id = task.agentId
WHERE task.tenant_id IS NULL
   OR deployment.id IS NULL
   OR task.tenant_id <> deployment.tenant_id;
```

A pre-existing hash with a different historical `0023_*` name is not evidence that these migrations ran. The exact names above must be present only after the new checked-in runner completes.

## Deployment sequence

1. Merge the remediation to the release branch and use the updated `Deploy to AWS` workflow. The workflow builds the image, registers it only for one-off checks, runs `run-migrations.mjs`, then runs `verify-agent-tenant-isolation.mjs`. It deploys the ECS service only if both tasks exit zero.
2. `0023` may complete while leaving ambiguous legacy records `NULL`. That is intentional. In that state, `0024` fails its preflight, no contract DDL runs, and the workflow does not deploy the new service.
3. Resolve only the records identified in the preflight inventory. For each mapping, require independent evidence—normally the linked engagement’s `eng_tenant_id` and the approved engagement/change record. A deployment without an authoritative engagement tenant, or an orphaned task, must be quarantined or deleted through a separately approved retention process; it must never be assigned to a “default” tenant.
4. After each approved mapping, validate tenant existence and parent agreement in the same transaction. Do not use `requestedBy` membership as evidence: users may belong to more than one tenant and memberships can change.
5. Rerun the release workflow. It verifies `0023`, runs the now-clean `0024` contract phase, and requires `verify-agent-tenant-isolation.mjs` to confirm the ledger records, non-null columns, indexes, foreign keys, and zero integrity exceptions.
6. Run two-tenant acceptance tests against the deployed canary while the live flag remains `false`: Tenant B must not list, retrieve, alter, audit, task, or obtain aggregate agent/task data for Tenant A. Invalid or unheld `X-Tenant-Id` values must be denied. Heartbeats without the agent registration token must not change state.
7. Check service logs for migration failures, auto-resume activity, active-scan jobs, and outbound C2/scan egress. Health-check success alone is insufficient.
8. Only after all checks pass, set `AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED=true` in the production task secret and deploy the same verified immutable image. Confirm that the final service task definition retains the secret injection.

## Rollback

If a check fails, keep the live-execution flag set to `false` and roll the ECS service back to the recorded immutable prior task definition/image. Do not roll back the additive schema automatically and do not drop tenant columns or constraints. For failed or partial DDL, restore from the snapshot or perform a reviewed forward repair. Re-run the read-only inventory and confirm no auto-resume, queued active work, or C2 egress occurs before reopening the change.
