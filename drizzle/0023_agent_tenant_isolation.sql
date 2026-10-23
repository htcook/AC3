-- AC3 tenant isolation for agent deployments and command tasks.
--
-- This is an expand/backfill migration. It intentionally leaves rows with
-- unprovable ownership unassigned. The application blocks live execution until
-- a reviewed data remediation resolves every remaining NULL or mismatch.

ALTER TABLE `agent_deployments` ADD COLUMN `tenant_id` INT NULL;
--> statement-breakpoint
ALTER TABLE `agent_tasks` ADD COLUMN `tenant_id` INT NULL;
--> statement-breakpoint

-- Only an engagement's explicit tenant assignment is authoritative. Do not
-- infer ownership from requestedBy: users can hold memberships in many tenants.
UPDATE `agent_deployments` AS `deployment`
INNER JOIN `engagements` AS `engagement`
  ON `engagement`.`id` = `deployment`.`engagementId`
SET `deployment`.`tenant_id` = `engagement`.`eng_tenant_id`
WHERE `deployment`.`tenant_id` IS NULL
  AND `engagement`.`eng_tenant_id` IS NOT NULL;
--> statement-breakpoint

-- A task inherits its tenant only from its deployment, after deployment
-- ownership has been established. Orphaned and unresolved tasks remain NULL.
UPDATE `agent_tasks` AS `task`
INNER JOIN `agent_deployments` AS `deployment`
  ON `deployment`.`id` = `task`.`agentId`
SET `task`.`tenant_id` = `deployment`.`tenant_id`
WHERE `task`.`tenant_id` IS NULL
  AND `deployment`.`tenant_id` IS NOT NULL;
--> statement-breakpoint

CREATE INDEX `agent_deployments_tenant_created_idx`
  ON `agent_deployments` (`tenant_id`, `createdAt`);
--> statement-breakpoint
CREATE INDEX `agent_tasks_tenant_status_idx`
  ON `agent_tasks` (`tenant_id`, `taskStatus`);
--> statement-breakpoint
CREATE INDEX `agent_tasks_agent_tenant_queued_idx`
  ON `agent_tasks` (`agentId`, `tenant_id`, `queuedAt`);
