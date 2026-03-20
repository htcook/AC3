CREATE TABLE `redteam_campaign_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rcl_campaign_id` int NOT NULL,
	`rcl_stage_id` int,
	`rcl_log_type` enum('info','warning','error','stage_start','stage_complete','stage_fail','condition_eval','branch_decision','campaign_start','campaign_complete','campaign_pause','campaign_abort','retry','timeout','ai_decision') NOT NULL,
	`rcl_title` varchar(500) NOT NULL,
	`rcl_detail` text,
	`rcl_metadata` json,
	`rcl_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `redteam_campaign_stages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rcs_campaign_id` int NOT NULL,
	`rcs_name` varchar(255) NOT NULL,
	`rcs_description` text,
	`rcs_stage_order` int NOT NULL,
	`rcs_stage_type` enum('recon','enumeration','vuln_scan','phishing','exploitation','post_exploit','lateral_move','c2_deploy','exfiltration','cleanup','custom') NOT NULL,
	`rcs_engagement_id` int,
	`rcs_config` json,
	`rcs_entry_conditions` json,
	`rcs_exit_conditions` json,
	`rcs_on_success` enum('next','skip_to','complete','pause') DEFAULT 'next',
	`rcs_on_success_target` int,
	`rcs_on_failure` enum('abort','skip','retry','pause','fallback') DEFAULT 'pause',
	`rcs_on_failure_target` int,
	`rcs_max_retries` int DEFAULT 1,
	`rcs_timeout_minutes` int DEFAULT 60,
	`rcs_status` enum('pending','waiting','running','completed','failed','skipped','timed_out','aborted') NOT NULL DEFAULT 'pending',
	`rcs_retry_count` int DEFAULT 0,
	`rcs_started_at` timestamp,
	`rcs_completed_at` timestamp,
	`rcs_results` json,
	`rcs_error_message` text,
	`rcs_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`rcs_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `redteam_campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rtc_name` varchar(255) NOT NULL,
	`rtc_description` text,
	`rtc_customer_name` varchar(255),
	`rtc_objective` text,
	`rtc_status` enum('draft','ready','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'draft',
	`rtc_current_stage_order` int DEFAULT 0,
	`rtc_started_at` timestamp,
	`rtc_completed_at` timestamp,
	`rtc_paused_at` timestamp,
	`rtc_max_duration_hours` int DEFAULT 72,
	`rtc_safety_level` enum('passive_only','low_impact','standard','full_exploitation') DEFAULT 'standard',
	`rtc_notify_on_stage` tinyint DEFAULT 1,
	`rtc_notify_on_complete` tinyint DEFAULT 1,
	`rtc_auto_advance` tinyint DEFAULT 1,
	`rtc_results_summary` json,
	`rtc_created_by` int,
	`rtc_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`rtc_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `rcl_campaign_idx` ON `redteam_campaign_logs` (`rcl_campaign_id`);--> statement-breakpoint
CREATE INDEX `rcl_stage_idx` ON `redteam_campaign_logs` (`rcl_stage_id`);--> statement-breakpoint
CREATE INDEX `rcl_type_idx` ON `redteam_campaign_logs` (`rcl_log_type`);--> statement-breakpoint
CREATE INDEX `rcl_created_at_idx` ON `redteam_campaign_logs` (`rcl_created_at`);--> statement-breakpoint
CREATE INDEX `rcs_campaign_idx` ON `redteam_campaign_stages` (`rcs_campaign_id`);--> statement-breakpoint
CREATE INDEX `rcs_stage_order_idx` ON `redteam_campaign_stages` (`rcs_campaign_id`,`rcs_stage_order`);--> statement-breakpoint
CREATE INDEX `rcs_status_idx` ON `redteam_campaign_stages` (`rcs_status`);--> statement-breakpoint
CREATE INDEX `rcs_engagement_idx` ON `redteam_campaign_stages` (`rcs_engagement_id`);--> statement-breakpoint
CREATE INDEX `rtc_status_idx` ON `redteam_campaigns` (`rtc_status`);--> statement-breakpoint
CREATE INDEX `rtc_created_by_idx` ON `redteam_campaigns` (`rtc_created_by`);