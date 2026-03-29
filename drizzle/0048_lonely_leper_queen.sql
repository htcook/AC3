CREATE TABLE `benchmark_scan_plan_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rule_id` varchar(64) NOT NULL,
	`source_run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`missed_vuln_title` varchar(255) NOT NULL,
	`missed_vuln_category` varchar(128) NOT NULL,
	`missed_vuln_severity` varchar(32) NOT NULL,
	`recommended_tool` varchar(64) NOT NULL,
	`recommended_action` text NOT NULL,
	`recommended_flags` text,
	`applicable_categories` json,
	`applicable_lab_types` json,
	`confidence` double DEFAULT 0.5,
	`is_active` tinyint DEFAULT 1,
	`applied_count` int DEFAULT 0,
	`last_applied_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `benchmark_scan_plan_rules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `benchmark_tool_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`tool` varchar(64) NOT NULL,
	`detected_vulns` json,
	`missed_vulns` json,
	`false_positive_vulns` json,
	`f1_score` double,
	`precision` double,
	`recall` double,
	`finding_count` int DEFAULT 0,
	`scan_duration_ms` int,
	`exit_code` int,
	`timed_out` tinyint DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `benchmark_tool_results_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `training_benchmark_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`lab_name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`scan_profile` enum('quick','standard','deep') NOT NULL DEFAULT 'standard',
	`status` enum('pending','scanning','scoring','learning','completed','failed') NOT NULL DEFAULT 'pending',
	`overall_f1` double,
	`overall_precision` double,
	`overall_recall` double,
	`total_ground_truth` int,
	`total_detected` int,
	`true_positives` int,
	`false_positives` int,
	`false_negatives` int,
	`tool_breakdown_json` json,
	`coverage_matrix_json` json,
	`scan_plan_adjustments_json` json,
	`learning_entries_generated` int DEFAULT 0,
	`operator_id` int,
	`operator_name` varchar(255),
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `training_benchmark_runs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `bspr_rule_id_idx` ON `benchmark_scan_plan_rules` (`rule_id`);--> statement-breakpoint
CREATE INDEX `bspr_lab_id_idx` ON `benchmark_scan_plan_rules` (`lab_id`);--> statement-breakpoint
CREATE INDEX `bspr_active_idx` ON `benchmark_scan_plan_rules` (`is_active`);--> statement-breakpoint
CREATE INDEX `btr_run_id_idx` ON `benchmark_tool_results` (`run_id`);--> statement-breakpoint
CREATE INDEX `btr_lab_tool_idx` ON `benchmark_tool_results` (`lab_id`,`tool`);--> statement-breakpoint
CREATE INDEX `tbr_run_id_idx` ON `training_benchmark_runs` (`run_id`);--> statement-breakpoint
CREATE INDEX `tbr_lab_id_idx` ON `training_benchmark_runs` (`lab_id`);--> statement-breakpoint
CREATE INDEX `tbr_status_idx` ON `training_benchmark_runs` (`status`);