CREATE TABLE `exploit_learning_chains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_name` varchar(255) NOT NULL,
	`steps` json NOT NULL,
	`success_rate` float NOT NULL DEFAULT 0,
	`discovered_from` varchar(255) NOT NULL,
	`mitre_techniques` json,
	`engagement_id` int,
	`target_hostname` varchar(255),
	`times_used` int NOT NULL DEFAULT 0,
	`last_used_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_learning_outcomes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`attempt_id` varchar(128) NOT NULL,
	`engagement_id` int NOT NULL,
	`vuln_title` varchar(512) NOT NULL,
	`vuln_cve` varchar(32),
	`vuln_severity` varchar(32) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`target_hostname` varchar(255) NOT NULL,
	`target_port` int,
	`target_technologies` json,
	`language` varchar(32) NOT NULL,
	`code` mediumtext NOT NULL,
	`success` tinyint NOT NULL DEFAULT 0,
	`exit_code` int NOT NULL DEFAULT 1,
	`stdout` mediumtext,
	`stderr` mediumtext,
	`guardrail_passed` tinyint,
	`guardrail_risk_score` int,
	`guardrail_blocked_reasons` json,
	`false_positive` tinyint DEFAULT 0,
	`false_positive_reasons` json,
	`execution_time_ms` int NOT NULL DEFAULT 0,
	`attempt_number` int NOT NULL DEFAULT 1,
	`previous_attempt_ids` json,
	`correction_applied` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_learning_patterns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pattern_key` varchar(255) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack` json NOT NULL,
	`successful_approaches` json NOT NULL,
	`failed_approaches` json NOT NULL,
	`known_chain_ids` json,
	`total_successes` int NOT NULL DEFAULT 0,
	`total_failures` int NOT NULL DEFAULT 0,
	`success_rate` float NOT NULL DEFAULT 0,
	`updated_at` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `elc_chain_name_idx` ON `exploit_learning_chains` (`chain_name`);--> statement-breakpoint
CREATE INDEX `elc_engagement_idx` ON `exploit_learning_chains` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `elo_engagement_idx` ON `exploit_learning_outcomes` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `elo_vuln_class_idx` ON `exploit_learning_outcomes` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `elo_attempt_id_idx` ON `exploit_learning_outcomes` (`attempt_id`);--> statement-breakpoint
CREATE INDEX `elo_target_idx` ON `exploit_learning_outcomes` (`target_hostname`);--> statement-breakpoint
CREATE INDEX `elo_success_idx` ON `exploit_learning_outcomes` (`success`);--> statement-breakpoint
CREATE INDEX `elp_pattern_key_idx` ON `exploit_learning_patterns` (`pattern_key`);--> statement-breakpoint
CREATE INDEX `elp_vuln_class_idx` ON `exploit_learning_patterns` (`vuln_class`);