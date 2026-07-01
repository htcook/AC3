CREATE TABLE `ai_audit_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_id` varchar(128) NOT NULL,
	`user_id` varchar(128) NOT NULL,
	`session_id` varchar(128) NOT NULL,
	`engagement_id` varchar(128),
	`action` varchar(64) NOT NULL,
	`severity` enum('info','warning','critical','alert') NOT NULL DEFAULT 'info',
	`details` text,
	`content_hash` varchar(128),
	`input_tokens` int,
	`output_tokens` int,
	`injection_detected` tinyint DEFAULT 0,
	`injection_patterns` text,
	`pii_detected` tinyint DEFAULT 0,
	`cross_tenant_violation` tinyint DEFAULT 0,
	`autonomy_level` int,
	`action_blocked` tinyint DEFAULT 0,
	`response_time_ms` int,
	`model_used` varchar(64),
	`ip_address` varchar(45),
	`user_agent` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `autonomy_overrides` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` varchar(128) NOT NULL,
	`override_level` int NOT NULL,
	`previous_level` int NOT NULL,
	`reason` text NOT NULL,
	`set_by` int NOT NULL,
	`set_by_name` varchar(256),
	`expires_at` timestamp,
	`active` tinyint NOT NULL DEFAULT 1,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `free_scan_requests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`email` varchar(255) NOT NULL,
	`organization` varchar(255),
	`job_title` varchar(255),
	`target_domain` varchar(255) NOT NULL,
	`verification_token` varchar(128) NOT NULL,
	`verified_at` timestamp,
	`verification_expires_at` timestamp NOT NULL,
	`scan_id` int,
	`results_token` varchar(128) NOT NULL,
	`results_expires_at` timestamp NOT NULL,
	`status` enum('pending_verification','verified','scanning','completed','expired','failed') NOT NULL DEFAULT 'pending_verification',
	`ip_address` varchar(45),
	`user_agent` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `free_scan_requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `roe_collaboration_comments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`section` varchar(64) NOT NULL,
	`field_name` varchar(128),
	`author_id` int NOT NULL,
	`author_name` varchar(256) NOT NULL,
	`author_role` enum('customer','operator') NOT NULL,
	`comment_text` text NOT NULL,
	`is_resolved` tinyint NOT NULL DEFAULT 0,
	`resolved_by` int,
	`resolved_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `roe_customer_invites` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`invite_token` varchar(128) NOT NULL,
	`customer_email` varchar(320) NOT NULL,
	`customer_name` varchar(256),
	`customer_org` varchar(256),
	`invited_by` int NOT NULL,
	`invited_by_name` varchar(256),
	`status` enum('pending','accepted','expired','revoked') NOT NULL DEFAULT 'pending',
	`accepted_at` timestamp,
	`expires_at` timestamp NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `roe_section_progress` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`section` varchar(64) NOT NULL,
	`filled_by` enum('customer','operator','llm_extracted') NOT NULL,
	`completion_percent` int NOT NULL DEFAULT 0,
	`last_edited_by` int,
	`last_edited_by_name` varchar(256),
	`last_edited_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`is_locked` tinyint NOT NULL DEFAULT 0,
	`locked_by` int,
	`locked_reason` varchar(256)
);
--> statement-breakpoint
CREATE TABLE `scanner_connectors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`connector_id` varchar(64) NOT NULL,
	`platform` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`base_url` varchar(512) NOT NULL,
	`credentials` text NOT NULL,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`last_health_check` timestamp,
	`health_status` varchar(32) DEFAULT 'unknown',
	`health_message` text,
	`scan_types` text,
	`fedramp_level` varchar(64),
	`created_by` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `scanner_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`finding_id` varchar(64) NOT NULL,
	`scan_id` varchar(64) NOT NULL,
	`connector_id` varchar(64) NOT NULL,
	`platform` varchar(64) NOT NULL,
	`title` varchar(512) NOT NULL,
	`severity` varchar(16) NOT NULL,
	`cvss_score` decimal(3,1),
	`cve_id` varchar(32),
	`cwe_id` varchar(32),
	`description` text,
	`remediation` text,
	`affected_asset` varchar(512),
	`affected_component` varchar(512),
	`evidence` text,
	`external_finding_id` varchar(256),
	`source_url` varchar(1024),
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`imported_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`resolved_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `scanner_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` varchar(64) NOT NULL,
	`connector_id` varchar(64) NOT NULL,
	`platform` varchar(64) NOT NULL,
	`scan_type` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`target_ref` varchar(512),
	`external_scan_id` varchar(256),
	`findings_count` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`started_at` timestamp,
	`completed_at` timestamp,
	`error_message` text,
	`raw_response` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `sonarqube_webhooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhook_id` varchar(64) NOT NULL,
	`connector_id` varchar(64) NOT NULL,
	`project_key` varchar(256) NOT NULL,
	`webhook_secret` varchar(128),
	`enabled` tinyint NOT NULL DEFAULT 1,
	`last_triggered_at` timestamp,
	`trigger_count` int DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `roe_engagement_type` enum('vulnerability_scanning','penetration_testing','red_purple_team','cicd_integration','phishing') DEFAULT 'penetration_testing';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `hold_harmless_clause` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `indemnification_clause` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `liability_cap` varchar(256);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `liability_cap_type` enum('fixed_amount','contract_value_multiplier','insurance_limit','unlimited') DEFAULT 'contract_value_multiplier';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `insurance_required` tinyint DEFAULT 1;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `insurance_eo_minimum` varchar(128);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `insurance_cyber_minimum` varchar(128);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `insurance_general_minimum` varchar(128);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `insurance_certificate_url` varchar(1024);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `third_party_system_disclaimer` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `service_disruption_liability` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `data_breach_notification_days` int DEFAULT 72;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `data_destruction_cert_required` tinyint DEFAULT 1;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `force_majeure_clause` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `dispute_resolution_method` enum('arbitration','mediation','litigation','negotiation') DEFAULT 'arbitration';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `governing_law` varchar(256);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `governing_law_state` varchar(128);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `emergency_stop_liability` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `customer_risk_acknowledgment` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `customer_risk_ack_signed_at` timestamp;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `operator_risk_acknowledgment` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `operator_risk_ack_signed_at` timestamp;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_pipeline_type` enum('github_actions','gitlab_ci','jenkins','azure_devops','circleci','bitbucket','custom');--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_scan_frequency` enum('every_commit','every_pr','daily','weekly','release_only');--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_failure_action` enum('block_deploy','warn_only','create_ticket','notify_security') DEFAULT 'warn_only';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_rollback_triggers` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_max_scan_duration` int DEFAULT 30;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_allowed_scan_types` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_excluded_paths` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `cicd_notification_webhook` varchar(1024);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_target_list_url` varchar(1024);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_target_count` int;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_target_departments` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_excluded_employees` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_approved_pretexts` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_prohibited_pretexts` json;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_credential_harvesting` enum('not_allowed','capture_only','capture_and_test','full_exploitation') DEFAULT 'capture_only';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_payload_type` enum('link_only','attachment_benign','attachment_macro','custom_payload','none') DEFAULT 'link_only';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_landing_page_restrictions` text;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_max_emails_per_day` int DEFAULT 50;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_campaign_duration_days` int DEFAULT 14;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_waves_count` int DEFAULT 1;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_reporting_threshold` int DEFAULT 10;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_opt_out_handling` enum('not_allowed','remove_from_campaign','flag_and_continue') DEFAULT 'remove_from_campaign';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_hr_notified` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_hr_contact_name` varchar(256);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_hr_contact_email` varchar(320);--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_legal_approval` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_union_notification` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_employee_notification_post` enum('immediate','after_campaign','never','custom') DEFAULT 'after_campaign';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_training_required` tinyint DEFAULT 1;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_smishing_allowed` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_vishing_allowed` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_usb_drop_allowed` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_brand_impersonation` enum('internal_only','external_allowed','specific_brands','not_allowed') DEFAULT 'internal_only';--> statement-breakpoint
ALTER TABLE `roe_documents` ADD `phishing_approved_brands` json;--> statement-breakpoint
ALTER TABLE `threat_alert_history` ADD `dismissed` tinyint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `threat_alert_thresholds` ADD `created_at` timestamp DEFAULT (now()) NOT NULL;--> statement-breakpoint
ALTER TABLE `threat_alert_thresholds` ADD `updated_at` timestamp DEFAULT (now()) NOT NULL ON UPDATE CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `quarantine_reason` varchar(100);--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `gate_a_passed` tinyint;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `gate_b_passed` tinyint;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `gate_c_passed` tinyint;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `active_scan_messages` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `auth_successes` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `auth_failures` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `auth_logged_in_count` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `unauth_baseline_urls` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `waf_block_ratio` double;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `passive_alert_count` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `scan_quality` varchar(30);--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `coverage_denominator_type` varchar(20);--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `coverage_spec_endpoints` int;--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `coverage_reached_endpoints` int;--> statement-breakpoint
CREATE INDEX `aal_tenant_idx` ON `ai_audit_logs` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `aal_user_idx` ON `ai_audit_logs` (`user_id`);--> statement-breakpoint
CREATE INDEX `aal_session_idx` ON `ai_audit_logs` (`session_id`);--> statement-breakpoint
CREATE INDEX `aal_engagement_idx` ON `ai_audit_logs` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `aal_action_idx` ON `ai_audit_logs` (`action`);--> statement-breakpoint
CREATE INDEX `aal_created_idx` ON `ai_audit_logs` (`created_at`);--> statement-breakpoint
CREATE INDEX `aal_injection_idx` ON `ai_audit_logs` (`injection_detected`);--> statement-breakpoint
CREATE INDEX `aal_violation_idx` ON `ai_audit_logs` (`cross_tenant_violation`);--> statement-breakpoint
CREATE INDEX `ao_engagement_idx` ON `autonomy_overrides` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ao_active_idx` ON `autonomy_overrides` (`active`);--> statement-breakpoint
CREATE INDEX `fsr_email_idx` ON `free_scan_requests` (`email`);--> statement-breakpoint
CREATE INDEX `fsr_verification_token_idx` ON `free_scan_requests` (`verification_token`);--> statement-breakpoint
CREATE INDEX `fsr_results_token_idx` ON `free_scan_requests` (`results_token`);--> statement-breakpoint
CREATE INDEX `fsr_status_idx` ON `free_scan_requests` (`status`);--> statement-breakpoint
CREATE INDEX `fsr_created_at_idx` ON `free_scan_requests` (`created_at`);--> statement-breakpoint
CREATE INDEX `rcc_roe_idx` ON `roe_collaboration_comments` (`roe_id`);--> statement-breakpoint
CREATE INDEX `rcc_section_idx` ON `roe_collaboration_comments` (`section`);--> statement-breakpoint
CREATE INDEX `rcc_author_idx` ON `roe_collaboration_comments` (`author_id`);--> statement-breakpoint
CREATE INDEX `rci_roe_idx` ON `roe_customer_invites` (`roe_id`);--> statement-breakpoint
CREATE INDEX `rci_token_idx` ON `roe_customer_invites` (`invite_token`);--> statement-breakpoint
CREATE INDEX `rci_email_idx` ON `roe_customer_invites` (`customer_email`);--> statement-breakpoint
CREATE INDEX `rsp_roe_idx` ON `roe_section_progress` (`roe_id`);--> statement-breakpoint
CREATE INDEX `rsp_section_idx` ON `roe_section_progress` (`section`);--> statement-breakpoint
CREATE INDEX `sc_connector_id_unique` ON `scanner_connectors` (`connector_id`);--> statement-breakpoint
CREATE INDEX `sc_platform_idx` ON `scanner_connectors` (`platform`);--> statement-breakpoint
CREATE INDEX `sc_enabled_idx` ON `scanner_connectors` (`enabled`);--> statement-breakpoint
CREATE INDEX `sf_finding_id_unique` ON `scanner_findings` (`finding_id`);--> statement-breakpoint
CREATE INDEX `sf_scan_id_idx` ON `scanner_findings` (`scan_id`);--> statement-breakpoint
CREATE INDEX `sf_connector_id_idx` ON `scanner_findings` (`connector_id`);--> statement-breakpoint
CREATE INDEX `sf_severity_idx` ON `scanner_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `sf_cve_idx` ON `scanner_findings` (`cve_id`);--> statement-breakpoint
CREATE INDEX `sf_status_idx` ON `scanner_findings` (`status`);--> statement-breakpoint
CREATE INDEX `ss_scan_id_unique` ON `scanner_scans` (`scan_id`);--> statement-breakpoint
CREATE INDEX `ss_connector_id_idx` ON `scanner_scans` (`connector_id`);--> statement-breakpoint
CREATE INDEX `ss_status_idx` ON `scanner_scans` (`status`);--> statement-breakpoint
CREATE INDEX `ss_platform_idx` ON `scanner_scans` (`platform`);--> statement-breakpoint
CREATE INDEX `sqw_webhook_id_unique` ON `sonarqube_webhooks` (`webhook_id`);--> statement-breakpoint
CREATE INDEX `sqw_connector_id_idx` ON `sonarqube_webhooks` (`connector_id`);--> statement-breakpoint
CREATE INDEX `sqw_project_key_idx` ON `sonarqube_webhooks` (`project_key`);--> statement-breakpoint
CREATE INDEX `ta_last_active_idx` ON `threat_actors` (`lastActive`);--> statement-breakpoint
CREATE INDEX `ta_threat_level_idx` ON `threat_actors` (`threatLevel`);--> statement-breakpoint
CREATE INDEX `ta_name_idx` ON `threat_actors` (`name`);--> statement-breakpoint
CREATE INDEX `ta_updated_at_idx` ON `threat_actors` (`updatedAt`);--> statement-breakpoint
CREATE INDEX `ta_actor_type_idx` ON `threat_actors` (`actorType`);--> statement-breakpoint
ALTER TABLE `threat_alert_thresholds` DROP COLUMN `createdAt`;--> statement-breakpoint
ALTER TABLE `threat_alert_thresholds` DROP COLUMN `updatedAt`;