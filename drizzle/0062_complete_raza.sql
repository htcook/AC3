ALTER TABLE `credential_attack_runs` ADD `tool` varchar(32) DEFAULT 'builtin';--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `tool_version` varchar(64);--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `raw_output` mediumtext;--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `tool_metadata` json;--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `target_domain` varchar(255);--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `failed_attempts` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `credential_attack_runs` ADD `stopped_reason` varchar(255);--> statement-breakpoint
ALTER TABLE `credential_findings` ADD `tool` varchar(32) DEFAULT 'builtin';--> statement-breakpoint
ALTER TABLE `credential_findings` ADD `response_snippet` text;--> statement-breakpoint
ALTER TABLE `credential_findings` ADD `additional_info` text;--> statement-breakpoint
ALTER TABLE `credential_findings` ADD `validation_status` varchar(32) DEFAULT 'unvalidated';