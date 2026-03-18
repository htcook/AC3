CREATE TABLE `c2_execution_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`technique_id` varchar(64) NOT NULL,
	`cel_framework` varchar(64) NOT NULL,
	`cel_success` tinyint NOT NULL,
	`confidence_adjustment` double,
	`target_platform` varchar(64),
	`target_arch` varchar(32),
	`exit_code` int,
	`lessons_learned` json,
	`cel_extracted_artifacts` json,
	`observed_telemetry` json,
	`cel_constraints` json,
	`cel_engagement_id` int,
	`cel_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `c2_execution_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `llm_decision_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`dl_phase` varchar(64) NOT NULL,
	`dl_caller` varchar(128) NOT NULL,
	`dl_decision` text NOT NULL,
	`dl_reasoning` text,
	`dl_actions` json,
	`dl_outcome` enum('success','failure','partial','pending') DEFAULT 'pending',
	`outcome_detail` text,
	`stealth_score` double,
	`dl_latency_ms` int,
	`tokens_used` int,
	`context_summary` text,
	`dl_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `llm_decision_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `llm_training_examples` (
	`id` int AUTO_INCREMENT NOT NULL,
	`example_id` varchar(64) NOT NULL,
	`te_model` varchar(64) NOT NULL,
	`te_source` enum('lab_scenario','live_engagement','manual','synthetic') NOT NULL,
	`source_id` varchar(128),
	`te_quality` enum('high','medium','low','rejected') NOT NULL,
	`quality_score` double NOT NULL,
	`te_messages` json NOT NULL,
	`te_metadata` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `llm_training_examples_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `cel_technique_idx` ON `c2_execution_log` (`technique_id`);--> statement-breakpoint
CREATE INDEX `cel_framework_idx` ON `c2_execution_log` (`cel_framework`);--> statement-breakpoint
CREATE INDEX `cel_engagement_idx` ON `c2_execution_log` (`cel_engagement_id`);--> statement-breakpoint
CREATE INDEX `ldl_engagement_idx` ON `llm_decision_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ldl_phase_idx` ON `llm_decision_log` (`dl_phase`);--> statement-breakpoint
CREATE INDEX `ldl_caller_idx` ON `llm_decision_log` (`dl_caller`);--> statement-breakpoint
CREATE INDEX `ldl_outcome_idx` ON `llm_decision_log` (`dl_outcome`);--> statement-breakpoint
CREATE INDEX `lte_model_idx` ON `llm_training_examples` (`te_model`);--> statement-breakpoint
CREATE INDEX `lte_source_idx` ON `llm_training_examples` (`te_source`);--> statement-breakpoint
CREATE INDEX `lte_quality_idx` ON `llm_training_examples` (`te_quality`);--> statement-breakpoint
CREATE INDEX `lte_example_id_idx` ON `llm_training_examples` (`example_id`);