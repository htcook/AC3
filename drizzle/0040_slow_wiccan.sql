CREATE TABLE `scanforge_engagement_report` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` varchar(64) NOT NULL,
	`scanforge_findings` int DEFAULT 0,
	`nuclei_findings` int DEFAULT 0,
	`zap_findings` int DEFAULT 0,
	`shared_findings` int DEFAULT 0,
	`scanforge_only` int DEFAULT 0,
	`legacy_only` int DEFAULT 0,
	`scanforge_precision` float,
	`scanforge_recall` float,
	`scanforge_f1` float,
	`legacy_precision` float,
	`legacy_recall` float,
	`legacy_f1` float,
	`reassessment_summary` text,
	`template_improvements` json,
	`coverage_gaps` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `scanforge_engagement_report_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scanforge_finding_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` varchar(64) NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`template_version` varchar(32) DEFAULT '1.0.0',
	`target` varchar(512) NOT NULL,
	`finding_title` varchar(512) NOT NULL,
	`severity` varchar(32) NOT NULL,
	`confidence` float NOT NULL,
	`proof_verified` boolean DEFAULT false,
	`verdict` varchar(16) NOT NULL DEFAULT 'PENDING',
	`verdict_source` varchar(64),
	`verdict_reason` text,
	`finding_data` json,
	`cross_tool_matches` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`assessed_at` timestamp,
	CONSTRAINT `scanforge_finding_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scanforge_generated_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`name` varchar(256) NOT NULL,
	`generation_source` varchar(64) NOT NULL,
	`source_reference` varchar(256),
	`template_data` json NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'draft',
	`generation_confidence` float DEFAULT 0.5,
	`review_notes` text,
	`promoted_to_template_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `scanforge_generated_templates_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scanforge_research_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`feed_source` varchar(64) NOT NULL,
	`research_subject` varchar(256) NOT NULL,
	`research_type` varchar(64) NOT NULL,
	`analysis_result` json,
	`generated_template_ids` json,
	`actionable` boolean DEFAULT false,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `scanforge_research_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scanforge_template_metrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`total_scans` int NOT NULL DEFAULT 0,
	`true_positives` int NOT NULL DEFAULT 0,
	`false_positives` int NOT NULL DEFAULT 0,
	`false_negatives` int NOT NULL DEFAULT 0,
	`precision` float DEFAULT 0,
	`recall` float DEFAULT 0,
	`f1_score` float DEFAULT 0,
	`calibrated_confidence` float DEFAULT 0.5,
	`effectiveness_score` float DEFAULT 50,
	`engagement_window` json,
	`last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `scanforge_template_metrics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `ser_engagement_unique` ON `scanforge_engagement_report` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sfl_engagement_idx` ON `scanforge_finding_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sfl_template_idx` ON `scanforge_finding_log` (`template_id`);--> statement-breakpoint
CREATE INDEX `sfl_verdict_idx` ON `scanforge_finding_log` (`verdict`);--> statement-breakpoint
CREATE INDEX `sgt_template_id_unique` ON `scanforge_generated_templates` (`template_id`);--> statement-breakpoint
CREATE INDEX `sgt_status_idx` ON `scanforge_generated_templates` (`status`);--> statement-breakpoint
CREATE INDEX `sgt_source_idx` ON `scanforge_generated_templates` (`generation_source`);--> statement-breakpoint
CREATE INDEX `srl_feed_idx` ON `scanforge_research_log` (`feed_source`);--> statement-breakpoint
CREATE INDEX `srl_subject_idx` ON `scanforge_research_log` (`research_subject`);--> statement-breakpoint
CREATE INDEX `srl_type_idx` ON `scanforge_research_log` (`research_type`);--> statement-breakpoint
CREATE INDEX `stm_template_unique` ON `scanforge_template_metrics` (`template_id`);