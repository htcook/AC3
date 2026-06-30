CREATE TABLE `risk_register_activity_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` int NOT NULL,
	`action` varchar(128) NOT NULL,
	`details` text,
	`performed_by` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `risk_register_attachments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` int NOT NULL,
	`file_name` varchar(512) NOT NULL,
	`file_url` text NOT NULL,
	`file_type` varchar(64),
	`uploaded_by` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `risk_register_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`poam_id` varchar(32) NOT NULL,
	`controls` varchar(512),
	`weakness_name` varchar(512) NOT NULL,
	`weakness_description` text,
	`weakness_detector_source` varchar(128),
	`weakness_source_identifier` varchar(255),
	`asset_identifier` varchar(512),
	`point_of_contact` varchar(255),
	`resources_required` text,
	`remediation_plan` text,
	`original_detection_date` timestamp,
	`scheduled_completion_date` timestamp,
	`actual_completion_date` timestamp,
	`milestones` text,
	`milestone_changes` text,
	`status_date` timestamp,
	`vendor_dependency` tinyint DEFAULT 0,
	`last_vendor_checkin_date` timestamp,
	`vendor_dependent_product_name` varchar(255),
	`original_risk_rating` enum('critical','high','moderate','low','informational') NOT NULL DEFAULT 'moderate',
	`adjusted_risk_rating` enum('critical','high','moderate','low','informational'),
	`risk_adjustment` text,
	`false_positive` tinyint DEFAULT 0,
	`operational_requirement` tinyint DEFAULT 0,
	`deviation_rationale` text,
	`supporting_documents` text,
	`comments` text,
	`status` enum('open','in_progress','closed','risk_accepted','deferred','vendor_dependent') NOT NULL DEFAULT 'open',
	`severity` enum('critical','high','moderate','low','informational') NOT NULL DEFAULT 'moderate',
	`source` enum('manual','engagement','ctem_scan','vulnerability_scan','pentest','red_team','bug_bounty') NOT NULL DEFAULT 'manual',
	`source_engagement_id` int,
	`source_scan_id` int,
	`attack_chain_id` varchar(100),
	`risk_decision` enum('mitigate','accept','transfer','defer','avoid'),
	`risk_decision_by` varchar(255),
	`risk_decision_date` timestamp,
	`risk_decision_justification` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vuln_attack_chain_steps` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_id` varchar(64) NOT NULL,
	`step_order` int NOT NULL,
	`title` varchar(512) NOT NULL,
	`description` text,
	`finding_type` enum('vulnerability','misconfiguration','credential','exposure','social_engineering','privilege_escalation','lateral_movement','data_access') NOT NULL DEFAULT 'vulnerability',
	`severity` enum('critical','high','moderate','low','informational') NOT NULL DEFAULT 'moderate',
	`cve_id` varchar(32),
	`cwe_id` varchar(32),
	`affected_asset` varchar(512),
	`mitre_technique` varchar(32),
	`mitre_tactic` varchar(64),
	`evidence` text,
	`source_finding_id` int,
	`source_table` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `vuln_attack_chains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_id` varchar(64) NOT NULL,
	`name` varchar(512) NOT NULL,
	`description` text,
	`composite_risk_score` double,
	`composite_severity` enum('critical','high','moderate','low','informational') NOT NULL DEFAULT 'moderate',
	`entry_point` varchar(512),
	`final_target` varchar(512),
	`impact_description` text,
	`mitre_techniques` json,
	`kill_chain_phases` json,
	`status` enum('active','mitigated','accepted','investigating') NOT NULL DEFAULT 'active',
	`engagement_id` int,
	`source_type` enum('manual','auto_correlated','pentest','red_team','ctem') NOT NULL DEFAULT 'manual',
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `rral_entry_idx` ON `risk_register_activity_log` (`entry_id`);--> statement-breakpoint
CREATE INDEX `rra_entry_idx` ON `risk_register_attachments` (`entry_id`);--> statement-breakpoint
CREATE INDEX `rre_poam_idx` ON `risk_register_entries` (`poam_id`);--> statement-breakpoint
CREATE INDEX `rre_status_idx` ON `risk_register_entries` (`status`);--> statement-breakpoint
CREATE INDEX `rre_severity_idx` ON `risk_register_entries` (`severity`);--> statement-breakpoint
CREATE INDEX `rre_source_idx` ON `risk_register_entries` (`source`);--> statement-breakpoint
CREATE INDEX `rre_attack_chain_idx` ON `risk_register_entries` (`attack_chain_id`);--> statement-breakpoint
CREATE INDEX `vacs_chain_idx` ON `vuln_attack_chain_steps` (`chain_id`);--> statement-breakpoint
CREATE INDEX `vacs_order_idx` ON `vuln_attack_chain_steps` (`chain_id`,`step_order`);--> statement-breakpoint
CREATE INDEX `vac_chain_id_idx` ON `vuln_attack_chains` (`chain_id`);--> statement-breakpoint
CREATE INDEX `vac_severity_idx` ON `vuln_attack_chains` (`composite_severity`);--> statement-breakpoint
CREATE INDEX `vac_status_idx` ON `vuln_attack_chains` (`status`);--> statement-breakpoint
CREATE INDEX `vac_engagement_idx` ON `vuln_attack_chains` (`engagement_id`);