CREATE TABLE `engagement_comms_protocols` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`roe_document_id` int,
	`uploaded_doc_id` int,
	`reporting_cadence` varchar(128),
	`reporting_method` varchar(256),
	`reporting_recipients` json,
	`emergency_halt_procedure` text,
	`deconfliction_procedure` text,
	`deconfliction_contacts` json,
	`deconfliction_phone` varchar(64),
	`deconfliction_email` varchar(320),
	`escalation_chain` json,
	`escalation_timeframe` varchar(128),
	`critical_finding_notify_within` varchar(64),
	`critical_finding_notify_method` varchar(256),
	`critical_finding_notify_recipients` json,
	`testing_window_start` varchar(16),
	`testing_window_end` varchar(16),
	`testing_days` json,
	`test_timezone` varchar(64),
	`blackout_periods` json,
	`status_check_in_frequency` varchar(128),
	`status_check_in_method` varchar(256),
	`raw_comms_section` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ecp_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `engagement_scope_constraints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`roe_document_id` int,
	`uploaded_doc_id` int,
	`in_scope_domains` json,
	`out_of_scope_domains` json,
	`in_scope_ip_ranges` json,
	`out_of_scope_ip_ranges` json,
	`in_scope_applications` json,
	`out_of_scope_applications` json,
	`in_scope_ports` json,
	`out_of_scope_ports` json,
	`allowed_testing_types` json,
	`disallowed_testing_types` json,
	`allowed_attack_vectors` json,
	`disallowed_attack_vectors` json,
	`dos_allowed` tinyint DEFAULT 0,
	`social_engineering_allowed` tinyint DEFAULT 0,
	`physical_allowed` tinyint DEFAULT 0,
	`wireless_allowed` tinyint DEFAULT 0,
	`pivoting_allowed` tinyint DEFAULT 1,
	`exfiltration_allowed` tinyint DEFAULT 0,
	`persistence_allowed` tinyint DEFAULT 0,
	`file_modification_allowed` tinyint DEFAULT 0,
	`credentialed_testing` tinyint DEFAULT 0,
	`testing_start_date` timestamp,
	`testing_end_date` timestamp,
	`raw_scope_section` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`esc_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `uploaded_roe_documents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`filename` varchar(512) NOT NULL,
	`mime_type` varchar(128) NOT NULL,
	`file_size` int NOT NULL,
	`storage_url` varchar(1024) NOT NULL,
	`storage_key` varchar(512) NOT NULL,
	`document_type` enum('roe','pentest_plan','red_team_plan','bug_bounty_scope','purple_team_plan','unknown') NOT NULL DEFAULT 'unknown',
	`extracted_text` mediumtext,
	`extracted_text_length` int,
	`parsed_data` json,
	`parse_status` enum('pending','extracting_text','parsing','parsed','failed') NOT NULL DEFAULT 'pending',
	`parse_error` text,
	`parsed_at` timestamp,
	`created_engagement_id` int,
	`created_roe_document_id` int,
	`uploaded_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`urd_tenant_id` int
);
--> statement-breakpoint
CREATE INDEX `ecp_engagement_idx` ON `engagement_comms_protocols` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ecp_roe_doc_idx` ON `engagement_comms_protocols` (`roe_document_id`);--> statement-breakpoint
CREATE INDEX `esc_engagement_idx` ON `engagement_scope_constraints` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `esc_roe_doc_idx` ON `engagement_scope_constraints` (`roe_document_id`);--> statement-breakpoint
CREATE INDEX `urd_engagement_idx` ON `uploaded_roe_documents` (`created_engagement_id`);--> statement-breakpoint
CREATE INDEX `urd_roe_doc_idx` ON `uploaded_roe_documents` (`created_roe_document_id`);--> statement-breakpoint
CREATE INDEX `urd_status_idx` ON `uploaded_roe_documents` (`parse_status`);