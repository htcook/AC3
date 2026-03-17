CREATE TABLE `ember_campaign_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecl_campaign_id` varchar(64) NOT NULL,
	`ecl_phase_id` varchar(64),
	`ecl_level` enum('info','warn','error','success') NOT NULL DEFAULT 'info',
	`ecl_message` text NOT NULL,
	`ecl_metadata` json,
	`ecl_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_campaign_phases` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecph_phase_id` varchar(64) NOT NULL,
	`ecph_campaign_id` varchar(64) NOT NULL,
	`ecph_phase_index` int NOT NULL,
	`ecph_name` varchar(255) NOT NULL,
	`ecph_description` text,
	`ecph_template_id` varchar(64),
	`ecph_template_name` varchar(255),
	`ecph_task_steps` json NOT NULL,
	`ecph_agent_id` varchar(64),
	`ecph_target_ip` varchar(64),
	`ecph_custom_params` json,
	`ecph_status` enum('pending','running','success','failed','skipped','timeout','aborted') NOT NULL DEFAULT 'pending',
	`ecph_on_success` enum('continue','skip_next','jump_to','complete') NOT NULL DEFAULT 'continue',
	`ecph_on_failure` enum('abort','skip','retry','continue') NOT NULL DEFAULT 'abort',
	`ecph_on_timeout` enum('abort','skip','retry','continue') NOT NULL DEFAULT 'abort',
	`ecph_jump_to` int,
	`ecph_max_retries` int DEFAULT 1,
	`ecph_retries_used` int DEFAULT 0,
	`ecph_timeout_seconds` int DEFAULT 600,
	`ecph_delay_before_ms` int DEFAULT 0,
	`ecph_condition_expr` text,
	`ecph_started_at` bigint,
	`ecph_completed_at` bigint,
	`ecph_output` mediumtext,
	`ecph_error` text,
	`ecph_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecmp_campaign_id` varchar(64) NOT NULL,
	`ecmp_name` varchar(255) NOT NULL,
	`ecmp_description` text,
	`ecmp_objective` text,
	`ecmp_status` enum('draft','ready','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'draft',
	`ecmp_target_info` json,
	`ecmp_phase_count` int DEFAULT 0,
	`ecmp_current_phase` int DEFAULT 0,
	`ecmp_phases_completed` int DEFAULT 0,
	`ecmp_phases_failed` int DEFAULT 0,
	`ecmp_phases_skipped` int DEFAULT 0,
	`ecmp_agent_ids` json,
	`ecmp_created_by` varchar(255),
	`ecmp_started_at` bigint,
	`ecmp_completed_at` bigint,
	`ecmp_created_at` bigint NOT NULL,
	`ecmp_updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_custom_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ect_template_id` varchar(64) NOT NULL,
	`ect_name` varchar(255) NOT NULL,
	`ect_description` text,
	`ect_category` enum('recon','credential','persistence','lateral','exfil','custom') NOT NULL DEFAULT 'custom',
	`ect_risk` enum('low','medium','high','critical') NOT NULL DEFAULT 'medium',
	`ect_est_duration` varchar(64),
	`ect_tags` json,
	`ect_steps` json NOT NULL,
	`ect_cloned_from` varchar(64),
	`ect_created_by` varchar(255),
	`ect_is_shared` tinyint DEFAULT 0,
	`ect_usage_count` int DEFAULT 0,
	`ect_last_used_at` bigint,
	`ect_created_at` bigint NOT NULL,
	`ect_updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ecl_campaign_id_idx` ON `ember_campaign_logs` (`ecl_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecl_level_idx` ON `ember_campaign_logs` (`ecl_level`);--> statement-breakpoint
CREATE INDEX `ecph_phase_id_idx` ON `ember_campaign_phases` (`ecph_phase_id`);--> statement-breakpoint
CREATE INDEX `ecph_campaign_id_idx` ON `ember_campaign_phases` (`ecph_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecph_status_idx` ON `ember_campaign_phases` (`ecph_status`);--> statement-breakpoint
CREATE INDEX `ecmp_campaign_id_idx` ON `ember_campaigns` (`ecmp_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecmp_status_idx` ON `ember_campaigns` (`ecmp_status`);--> statement-breakpoint
CREATE INDEX `ecmp_created_by_idx` ON `ember_campaigns` (`ecmp_created_by`);--> statement-breakpoint
CREATE INDEX `ect_template_id_idx` ON `ember_custom_templates` (`ect_template_id`);--> statement-breakpoint
CREATE INDEX `ect_category_idx` ON `ember_custom_templates` (`ect_category`);--> statement-breakpoint
CREATE INDEX `ect_created_by_idx` ON `ember_custom_templates` (`ect_created_by`);