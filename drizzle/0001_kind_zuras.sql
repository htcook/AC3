CREATE TABLE `training_lab_feedback` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`finding_index` int NOT NULL,
	`feedback_type` enum('correct','incorrect','partial','missed_finding') NOT NULL,
	`operator_notes` text,
	`expected_severity` varchar(32),
	`expected_category` varchar(128),
	`operator_id` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `training_lab_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`target_preset` varchar(64),
	`scan_profile` enum('quick','standard','deep') NOT NULL DEFAULT 'standard',
	`lab_status` enum('queued','scanning','analyzing','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
	`phase` varchar(64) DEFAULT 'idle',
	`progress` int DEFAULT 0,
	`assets_json` json,
	`findings_json` json,
	`llm_analysis_json` json,
	`owasp_coverage_json` json,
	`stats_json` json,
	`scan_log_json` json,
	`operator_id` int,
	`operator_name` varchar(255),
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `training_lab_sessions_session_id_unique` ON `training_lab_sessions` (`session_id`);