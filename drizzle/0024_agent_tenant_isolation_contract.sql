-- Contract phase for AC3 agent tenant isolation.
-- The runner's requireCleanAgentTenantData preflight must pass before this file
-- is executed. It is deliberately separate from 0023 so ambiguous legacy data
-- is never forced into an arbitrary tenant.

ALTER TABLE `agent_deployments`
  MODIFY COLUMN `tenant_id` INT NOT NULL;
--> statement-breakpoint
ALTER TABLE `agent_tasks`
  MODIFY COLUMN `tenant_id` INT NOT NULL;
--> statement-breakpoint

-- MySQL requires an index whose leftmost columns match the composite FK target.
ALTER TABLE `agent_deployments`
  ADD UNIQUE KEY `agent_deployments_id_tenant_unique` (`id`, `tenant_id`);
--> statement-breakpoint
ALTER TABLE `agent_deployments`
  ADD CONSTRAINT `agent_deployments_tenant_fk`
  FOREIGN KEY (`tenant_id`) REFERENCES `tenants` (`id`) ON DELETE RESTRICT;
--> statement-breakpoint

-- This composite constraint proves that a task has the same tenant as the
-- deployment it targets, preventing cross-tenant command assignment in SQL.
ALTER TABLE `agent_tasks`
  ADD CONSTRAINT `agent_tasks_deployment_tenant_fk`
  FOREIGN KEY (`agentId`, `tenant_id`)
  REFERENCES `agent_deployments` (`id`, `tenant_id`) ON DELETE CASCADE;
