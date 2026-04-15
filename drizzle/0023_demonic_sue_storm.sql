CREATE TABLE `exploit_methodologies` (
	`id` varchar(128) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`name` varchar(512) NOT NULL,
	`tech_stack` json NOT NULL,
	`owasp_category` varchar(128),
	`mitre_techniques` json,
	`cwe_ids` json,
	`steps` json NOT NULL,
	`payloads` json NOT NULL,
	`detection_signatures` json NOT NULL,
	`escalation_paths` json,
	`success_criteria` json NOT NULL,
	`failure_modes` json,
	`weight` int NOT NULL DEFAULT 50,
	`source` enum('seed','learned','community') NOT NULL DEFAULT 'seed',
	`success_count` int NOT NULL DEFAULT 0,
	`attempt_count` int NOT NULL DEFAULT 0,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL,
	CONSTRAINT `exploit_methodologies_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `methodology_attempts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`methodology_id` varchar(128),
	`engagement_id` int,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack` json,
	`target` varchar(512),
	`port` int,
	`success` tinyint NOT NULL DEFAULT 0,
	`approach` text NOT NULL,
	`payload_used` text,
	`failure_reason` text,
	`execution_time_ms` int,
	`training_example_generated` tinyint DEFAULT 0,
	`training_example_id` varchar(128),
	`graduation_score_impact` double,
	`created_at` bigint NOT NULL,
	CONSTRAINT `methodology_attempts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `methodology_performance` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack_key` varchar(255) NOT NULL,
	`total_attempts` int NOT NULL DEFAULT 0,
	`total_successes` int NOT NULL DEFAULT 0,
	`success_rate` double NOT NULL DEFAULT 0,
	`avg_execution_time_ms` int,
	`last_attempt_at` bigint,
	`last_success_at` bigint,
	`updated_at` bigint NOT NULL,
	CONSTRAINT `methodology_performance_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `em_vuln_class_idx` ON `exploit_methodologies` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `em_source_idx` ON `exploit_methodologies` (`source`);--> statement-breakpoint
CREATE INDEX `em_weight_idx` ON `exploit_methodologies` (`weight`);--> statement-breakpoint
CREATE INDEX `ma_methodology_idx` ON `methodology_attempts` (`methodology_id`);--> statement-breakpoint
CREATE INDEX `ma_engagement_idx` ON `methodology_attempts` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ma_vuln_class_idx` ON `methodology_attempts` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `ma_success_idx` ON `methodology_attempts` (`success`);--> statement-breakpoint
CREATE INDEX `ma_created_at_idx` ON `methodology_attempts` (`created_at`);--> statement-breakpoint
CREATE INDEX `mp_vuln_class_idx` ON `methodology_performance` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `mp_tech_stack_idx` ON `methodology_performance` (`tech_stack_key`);--> statement-breakpoint
CREATE INDEX `mp_success_rate_idx` ON `methodology_performance` (`success_rate`);