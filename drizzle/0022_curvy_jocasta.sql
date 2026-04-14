CREATE TABLE `scheduled_cspm_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`credential_id` int NOT NULL,
	`engagement_id` int,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`cron_expression` varchar(64) NOT NULL,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`services` json,
	`compliance_framework` varchar(128),
	`timeout_seconds` int DEFAULT 600,
	`last_run_id` int,
	`last_run_at` bigint,
	`last_run_status` enum('pending','running','completed','error'),
	`next_run_at` bigint,
	`total_runs` int DEFAULT 0,
	`created_by` varchar(255),
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX `scs_credential_idx` ON `scheduled_cspm_scans` (`credential_id`);--> statement-breakpoint
CREATE INDEX `scs_engagement_idx` ON `scheduled_cspm_scans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `scs_active_idx` ON `scheduled_cspm_scans` (`is_active`);--> statement-breakpoint
CREATE INDEX `scs_next_run_idx` ON `scheduled_cspm_scans` (`next_run_at`);