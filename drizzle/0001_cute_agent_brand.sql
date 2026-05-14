CREATE TABLE `risk_register_activity_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` int NOT NULL,
	`tenant_id` int,
	`action` varchar(64) NOT NULL,
	`field` varchar(128),
	`previous_value` text,
	`new_value` text,
	`performed_by` int,
	`performed_by_name` varchar(255),
	`notes` text,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `risk_register_activity_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `risk_register_attachments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` int NOT NULL,
	`tenant_id` int,
	`file_name` varchar(512) NOT NULL,
	`file_url` text NOT NULL,
	`file_key` varchar(512),
	`mime_type` varchar(128),
	`file_size` int,
	`uploaded_by` int,
	`uploaded_by_name` varchar(255),
	`description` text,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `risk_register_attachments_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `risk_register_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_id` int,
	`poam_id` varchar(64) NOT NULL,
	`controls` text,
	`weakness_name` varchar(512) NOT NULL,
	`weakness_description` text,
	`weakness_detector_source` varchar(255),
	`weakness_source_identifier` varchar(255),
	`asset_identifier` text,
	`point_of_contact` varchar(255),
	`resources_required` text,
	`remediation_plan` text,
	`original_detection_date` timestamp,
	`scheduled_completion_date` timestamp,
	`actual_completion_date` timestamp,
	`status_date` timestamp,
	`vendor_dependency` varchar(10) DEFAULT 'No',
	`last_vendor_checkin_date` timestamp,
	`vendor_dependent_product_name` varchar(255),
	`original_risk_rating` varchar(32),
	`adjusted_risk_rating` varchar(32),
	`risk_adjustment` varchar(32) DEFAULT 'No',
	`false_positive` varchar(10) DEFAULT 'No',
	`operational_requirement` varchar(10) DEFAULT 'No',
	`deviation_rationale` text,
	`supporting_documents` text,
	`comments` text,
	`bod_22_01_tracking` varchar(10) DEFAULT 'No',
	`bod_22_01_due_date` timestamp,
	`cve` text,
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`category` varchar(64) DEFAULT 'vulnerability',
	`severity` varchar(32),
	`cvss_score` varchar(10),
	`source_type` varchar(32),
	`source_finding_id` int,
	`source_remediation_id` int,
	`source_engagement_id` varchar(128),
	`source_cicd_run_id` int,
	`risk_decision` varchar(32),
	`risk_decision_by` varchar(255),
	`risk_decision_date` timestamp,
	`risk_decision_justification` text,
	`risk_acceptance_expires_at` timestamp,
	`compensating_controls` text,
	`milestones` json,
	`milestone_changes` json,
	`impact_level` varchar(32),
	`cso_name` varchar(255),
	`created_by` int,
	`updated_by` int,
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	`closed_at` timestamp,
	CONSTRAINT `risk_register_entries_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `rral_entry_idx` ON `risk_register_activity_log` (`entry_id`);--> statement-breakpoint
CREATE INDEX `rral_tenant_idx` ON `risk_register_activity_log` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `rral_action_idx` ON `risk_register_activity_log` (`action`);--> statement-breakpoint
CREATE INDEX `rral_created_at_idx` ON `risk_register_activity_log` (`created_at`);--> statement-breakpoint
CREATE INDEX `rra_entry_idx` ON `risk_register_attachments` (`entry_id`);--> statement-breakpoint
CREATE INDEX `rra_tenant_idx` ON `risk_register_attachments` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `rr_tenant_idx` ON `risk_register_entries` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `rr_status_idx` ON `risk_register_entries` (`status`);--> statement-breakpoint
CREATE INDEX `rr_poam_id_idx` ON `risk_register_entries` (`poam_id`);--> statement-breakpoint
CREATE INDEX `rr_severity_idx` ON `risk_register_entries` (`severity`);--> statement-breakpoint
CREATE INDEX `rr_category_idx` ON `risk_register_entries` (`category`);--> statement-breakpoint
CREATE INDEX `rr_source_finding_idx` ON `risk_register_entries` (`source_finding_id`);--> statement-breakpoint
CREATE INDEX `rr_scheduled_completion_idx` ON `risk_register_entries` (`scheduled_completion_date`);--> statement-breakpoint
CREATE INDEX `rr_risk_decision_idx` ON `risk_register_entries` (`risk_decision`);--> statement-breakpoint
CREATE INDEX `rr_created_at_idx` ON `risk_register_entries` (`created_at`);