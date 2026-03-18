CREATE TABLE `nexus_shadow_configs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nsc_config_name` varchar(128) NOT NULL,
	`nsc_enabled` tinyint NOT NULL DEFAULT 0,
	`nsc_shadow_percentage` int NOT NULL DEFAULT 5,
	`nsc_primary_model` varchar(128) NOT NULL DEFAULT 'gemini-2.5-flash',
	`nsc_experimental_model` varchar(128) NOT NULL DEFAULT 'gpt-4o',
	`nsc_caller_filter` varchar(255) DEFAULT '',
	`nsc_priority_filter` enum('all','essential','standard','bulk') DEFAULT 'all',
	`nsc_max_concurrent` int NOT NULL DEFAULT 10,
	`nsc_active_shadow_tests` int NOT NULL DEFAULT 0,
	`nsc_total_runs` int NOT NULL DEFAULT 0,
	`nsc_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`nsc_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `nexus_shadow_configs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `nexus_shadow_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nst_config_id` int NOT NULL,
	`nst_caller` varchar(255) NOT NULL,
	`nst_prompt_snippet` text,
	`nst_primary_model` varchar(128) NOT NULL,
	`nst_primary_latency_ms` int,
	`nst_primary_tokens_in` int,
	`nst_primary_tokens_out` int,
	`nst_primary_score` int,
	`nst_experimental_model` varchar(128) NOT NULL,
	`nst_experimental_latency_ms` int,
	`nst_experimental_tokens_in` int,
	`nst_experimental_tokens_out` int,
	`nst_experimental_score` int,
	`nst_judge_verdict` enum('primary_better','experimental_better','tie','error') DEFAULT 'tie',
	`nst_judge_reasoning` text,
	`nst_judge_score` int,
	`nst_status` enum('running','completed','error') DEFAULT 'running',
	`nst_error_message` text,
	`nst_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`nst_completed_at` timestamp,
	CONSTRAINT `nexus_shadow_tests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `nsc_config_name_idx` ON `nexus_shadow_configs` (`nsc_config_name`);--> statement-breakpoint
CREATE INDEX `nsc_enabled_idx` ON `nexus_shadow_configs` (`nsc_enabled`);--> statement-breakpoint
CREATE INDEX `nst_config_id_idx` ON `nexus_shadow_tests` (`nst_config_id`);--> statement-breakpoint
CREATE INDEX `nst_caller_idx` ON `nexus_shadow_tests` (`nst_caller`);--> statement-breakpoint
CREATE INDEX `nst_verdict_idx` ON `nexus_shadow_tests` (`nst_judge_verdict`);--> statement-breakpoint
CREATE INDEX `nst_status_idx` ON `nexus_shadow_tests` (`nst_status`);--> statement-breakpoint
CREATE INDEX `nst_created_at_idx` ON `nexus_shadow_tests` (`nst_created_at`);