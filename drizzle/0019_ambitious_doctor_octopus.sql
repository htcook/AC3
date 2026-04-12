CREATE TABLE `customer_integrations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`description` text,
	`category` enum('osint','exploit_db','threat_intel','scanner','pentest_tool','phishing','c2','siem_soar','cloud','credential','custom') NOT NULL,
	`license_model` enum('free','freemium','api_key','byol','platform_provided','custom') NOT NULL DEFAULT 'custom',
	`status` enum('proposed','review','approved','active','paused','rejected','error','deprecated') NOT NULL DEFAULT 'proposed',
	`auth_method` enum('none','api_key','api_key_secret','basic_auth','bearer_token','oauth2','ssh_key','custom_header','certificate') NOT NULL DEFAULT 'api_key',
	`auth_config` json,
	`endpoint_base_url` text,
	`endpoint_config` json,
	`pipeline_stages` json,
	`data_types` json,
	`input_types` json,
	`output_types` json,
	`capabilities` json,
	`pipeline_wiring` json,
	`value_assessment` json,
	`auto_discovery_result` json,
	`customer_review` json,
	`credentials` json,
	`tags` json,
	`priority` int DEFAULT 3,
	`is_built_in` tinyint NOT NULL DEFAULT 0,
	`added_by` varchar(64),
	`tenant_id` varchar(64),
	`last_health_check` bigint,
	`last_health_status` enum('healthy','degraded','unreachable','auth_failed','unknown') DEFAULT 'unknown',
	`last_error` text,
	`total_calls` int DEFAULT 0,
	`total_errors` int DEFAULT 0,
	`avg_latency_ms` int,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `integration_execution_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`engagement_id` int,
	`pipeline_stage` varchar(64) NOT NULL,
	`execution_status` enum('success','partial','failed','timeout','skipped') NOT NULL,
	`duration_ms` int,
	`records_returned` int DEFAULT 0,
	`error_message` text,
	`executed_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `integration_health_checks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`check_type` enum('connectivity','auth_validation','rate_limit','full_probe') NOT NULL DEFAULT 'connectivity',
	`status` enum('healthy','degraded','unreachable','auth_failed','rate_limited','timeout','error') NOT NULL,
	`latency_ms` int,
	`http_status` int,
	`response_snippet` text,
	`error_message` text,
	`checked_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ci_integration_id_unique` ON `customer_integrations` (`integration_id`);--> statement-breakpoint
CREATE INDEX `ci_category_idx` ON `customer_integrations` (`category`);--> statement-breakpoint
CREATE INDEX `ci_status_idx` ON `customer_integrations` (`status`);--> statement-breakpoint
CREATE INDEX `ci_tenant_idx` ON `customer_integrations` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `iel_integration_idx` ON `integration_execution_log` (`integration_id`);--> statement-breakpoint
CREATE INDEX `iel_engagement_idx` ON `integration_execution_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `iel_stage_idx` ON `integration_execution_log` (`pipeline_stage`);--> statement-breakpoint
CREATE INDEX `ihc_integration_idx` ON `integration_health_checks` (`integration_id`);--> statement-breakpoint
CREATE INDEX `ihc_checked_at_idx` ON `integration_health_checks` (`checked_at`);