CREATE TABLE `campaign_run_states` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaign_id` int NOT NULL,
	`is_running` tinyint NOT NULL DEFAULT 0,
	`is_paused` tinyint NOT NULL DEFAULT 0,
	`current_stage_id` int,
	`started_at` bigint,
	`last_heartbeat` bigint,
	`node_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `orchestration_plans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`plan_id` varchar(128) NOT NULL,
	`engagement_id` int,
	`campaign_id` int,
	`name` varchar(255) NOT NULL,
	`description` text,
	`target_domain` varchar(512),
	`scan_mode` varchar(32),
	`op_status` enum('pending','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'pending',
	`current_phase` varchar(64),
	`steps_completed` int NOT NULL DEFAULT 0,
	`steps_failed` int NOT NULL DEFAULT 0,
	`steps_skipped` int NOT NULL DEFAULT 0,
	`max_parallel` int NOT NULL DEFAULT 3,
	`abort_on_failure` tinyint NOT NULL DEFAULT 0,
	`auto_handoff` tinyint NOT NULL DEFAULT 1,
	`phases` json,
	`steps` json,
	`framework_priority` json,
	`shared_context` json,
	`op_log` json,
	`started_at` timestamp,
	`completed_at` timestamp,
	`last_heartbeat` bigint,
	`node_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`op_tenant_id` int
);
--> statement-breakpoint
CREATE INDEX `crs_campaign_id_idx` ON `campaign_run_states` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `crs_is_running_idx` ON `campaign_run_states` (`is_running`);--> statement-breakpoint
CREATE INDEX `op_plan_id_idx` ON `orchestration_plans` (`plan_id`);--> statement-breakpoint
CREATE INDEX `op_engagement_id_idx` ON `orchestration_plans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `op_campaign_id_idx` ON `orchestration_plans` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `op_status_idx` ON `orchestration_plans` (`op_status`);