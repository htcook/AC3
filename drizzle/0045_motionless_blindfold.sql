CREATE TABLE `bug_bounty_llm_training_samples` (
	`id` int AUTO_INCREMENT NOT NULL,
	`finding_id` int,
	`category` enum('vuln_pattern','exploit_chain','report_template','scope_recon','cwe_analysis','bounty_strategy','novel_finding') NOT NULL,
	`quality_score` decimal(3,2) DEFAULT '0.00',
	`bounty_amount` decimal(12,2) DEFAULT '0.00',
	`severity_rating` varchar(32),
	`cwe_id` varchar(32),
	`cve_ids` json,
	`program_handle` varchar(255),
	`program_name` varchar(512),
	`asset_type` varchar(64),
	`asset_identifier` varchar(512),
	`system_prompt` text NOT NULL,
	`user_prompt` text NOT NULL,
	`assistant_response` text NOT NULL,
	`raw_title` varchar(512),
	`raw_summary` text,
	`enrichment_status` enum('raw','enriched','reviewed','exported') DEFAULT 'raw',
	`enriched_narrative` text,
	`attack_technique` text,
	`remediation_guidance` text,
	`mitre_techniques` json,
	`tags` json,
	`exported_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bug_bounty_llm_training_samples_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `bug_bounty_findings` ADD `submitted_at` timestamp;--> statement-breakpoint
CREATE INDEX `bblts_category_idx` ON `bug_bounty_llm_training_samples` (`category`);--> statement-breakpoint
CREATE INDEX `bblts_finding_idx` ON `bug_bounty_llm_training_samples` (`finding_id`);--> statement-breakpoint
CREATE INDEX `bblts_quality_idx` ON `bug_bounty_llm_training_samples` (`quality_score`);--> statement-breakpoint
CREATE INDEX `bblts_severity_idx` ON `bug_bounty_llm_training_samples` (`severity_rating`);--> statement-breakpoint
CREATE INDEX `bblts_cwe_idx` ON `bug_bounty_llm_training_samples` (`cwe_id`);--> statement-breakpoint
CREATE INDEX `bblts_program_idx` ON `bug_bounty_llm_training_samples` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bblts_enrichment_idx` ON `bug_bounty_llm_training_samples` (`enrichment_status`);--> statement-breakpoint
CREATE INDEX `bblts_bounty_idx` ON `bug_bounty_llm_training_samples` (`bounty_amount`);