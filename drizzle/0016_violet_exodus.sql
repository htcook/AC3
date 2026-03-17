CREATE TABLE `ac3_report_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rf_finding_id` varchar(64) NOT NULL,
	`rf_report_id` varchar(64) NOT NULL,
	`rf_sort_order` int DEFAULT 0,
	`rf_severity` enum('critical','high','moderate','low','informational') NOT NULL,
	`rf_evidence` json,
	`rf_attack_techniques` json,
	`rf_controls` json,
	`rf_assets` json,
	`rf_cvss_score` varchar(8),
	`rf_cvss_vector` varchar(128),
	`rf_title` varchar(512) NOT NULL,
	`rf_summary` text,
	`rf_business_impact` text,
	`rf_technical_details` mediumtext,
	`rf_remediation` text,
	`rf_source_task_id` varchar(64),
	`rf_source_campaign_id` varchar(64),
	`rf_source_agent_id` varchar(64),
	`rf_narrative_status` enum('pending','drafted','reviewed','approved') DEFAULT 'pending',
	`rf_reviewed_by` varchar(255),
	`rf_reviewed_at` bigint,
	`rf_created_at` bigint NOT NULL,
	`rf_updated_at` bigint NOT NULL,
	CONSTRAINT `ac3_report_findings_id` PRIMARY KEY(`id`),
	CONSTRAINT `ac3_report_findings_rf_finding_id_unique` UNIQUE(`rf_finding_id`)
);
--> statement-breakpoint
CREATE TABLE `ac3_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rpt_report_id` varchar(64) NOT NULL,
	`rpt_name` varchar(255) NOT NULL,
	`rpt_status` enum('draft','generating','review','approved','final') NOT NULL DEFAULT 'draft',
	`rpt_client_name` varchar(255),
	`rpt_system_name` varchar(255),
	`rpt_assessment_type` enum('penetration_test','red_team','purple_team','vulnerability_assessment','hybrid') DEFAULT 'penetration_test',
	`rpt_fedramp_level` enum('low','moderate','high','li-saas'),
	`rpt_cloud_provider` varchar(255),
	`rpt_service_model` varchar(128),
	`rpt_window_start` bigint,
	`rpt_window_end` bigint,
	`rpt_version` varchar(32) DEFAULT '1.0',
	`rpt_scope_domains` json,
	`rpt_scope_assets` json,
	`rpt_approved_vectors` json,
	`rpt_out_of_scope` json,
	`rpt_exec_risk_statement` text,
	`rpt_exec_rating` enum('critical','high','moderate','low','informational'),
	`rpt_exec_strengths` json,
	`rpt_exec_gaps` json,
	`rpt_exec_narrative` mediumtext,
	`rpt_qa_status` enum('pending','pass','revise') DEFAULT 'pending',
	`rpt_qa_issues` json,
	`rpt_qa_reviewed_at` bigint,
	`rpt_campaign_id` varchar(64),
	`rpt_output_url` text,
	`rpt_output_format` varchar(16),
	`rpt_created_by` varchar(255),
	`rpt_created_at` bigint NOT NULL,
	`rpt_updated_at` bigint NOT NULL,
	CONSTRAINT `ac3_reports_id` PRIMARY KEY(`id`),
	CONSTRAINT `ac3_reports_rpt_report_id_unique` UNIQUE(`rpt_report_id`)
);
--> statement-breakpoint
CREATE INDEX `rf_report_id_idx` ON `ac3_report_findings` (`rf_report_id`);--> statement-breakpoint
CREATE INDEX `rf_finding_id_idx` ON `ac3_report_findings` (`rf_finding_id`);--> statement-breakpoint
CREATE INDEX `rf_severity_idx` ON `ac3_report_findings` (`rf_severity`);--> statement-breakpoint
CREATE INDEX `rpt_report_id_idx` ON `ac3_reports` (`rpt_report_id`);--> statement-breakpoint
CREATE INDEX `rpt_status_idx` ON `ac3_reports` (`rpt_status`);--> statement-breakpoint
CREATE INDEX `rpt_campaign_idx` ON `ac3_reports` (`rpt_campaign_id`);