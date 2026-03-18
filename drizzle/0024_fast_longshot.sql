CREATE TABLE `company_intel_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cip_tenant_id` int,
	`cip_domain` varchar(512) NOT NULL,
	`cip_company_name` varchar(512),
	`cip_industry` varchar(255),
	`cip_sector` varchar(255),
	`cip_description` text,
	`cip_employee_count` int,
	`cip_employee_range` varchar(64),
	`cip_revenue` varchar(128),
	`cip_funding_stage` varchar(64),
	`cip_publicly_traded` tinyint DEFAULT 0,
	`cip_ticker` varchar(16),
	`cip_founded_year` int,
	`cip_company_type` varchar(64),
	`cip_headquarters` json,
	`cip_locations` json,
	`cip_specialties` json,
	`cip_products` json,
	`cip_technologies` json,
	`cip_social_media` json,
	`cip_naics_code` varchar(16),
	`cip_sic_code` varchar(16),
	`cip_data_classifications` json,
	`cip_subsidiaries` json,
	`cip_parent_company` varchar(255),
	`cip_executive_team` json,
	`cip_customer_corrected` tinyint NOT NULL DEFAULT 0,
	`cip_corrected_at` timestamp,
	`cip_corrected_by` int,
	`cip_correction_notes` text,
	`cip_sources` json,
	`cip_confidence` int DEFAULT 0,
	`cip_last_enriched_at` timestamp,
	`cip_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`cip_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `company_intel_profiles_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_accounts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_id` int NOT NULL,
	`ca_email` varchar(320) NOT NULL,
	`password_hash` varchar(255) NOT NULL,
	`ca_name` varchar(255) NOT NULL,
	`ca_title` varchar(128),
	`ca_phone` varchar(32),
	`ca_role` enum('primary_contact','technical_contact','executive','viewer') NOT NULL DEFAULT 'viewer',
	`ca_status` enum('active','inactive','locked','pending_verification') NOT NULL DEFAULT 'pending_verification',
	`email_verified` tinyint NOT NULL DEFAULT 0,
	`verification_token` varchar(128),
	`reset_token` varchar(128),
	`reset_token_expiry` timestamp,
	`ca_last_login_at` timestamp,
	`login_count` int NOT NULL DEFAULT 0,
	`failed_login_attempts` int NOT NULL DEFAULT 0,
	`locked_until` timestamp,
	`mfa_enabled` tinyint NOT NULL DEFAULT 0,
	`mfa_secret` varchar(128),
	`ca_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ca_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `customer_accounts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`customer_account_id` int NOT NULL,
	`cal_tenant_id` int NOT NULL,
	`cal_action` varchar(128) NOT NULL,
	`cal_resource` varchar(128),
	`cal_resource_id` varchar(128),
	`cal_details` json,
	`cal_ip_address` varchar(45),
	`cal_user_agent` varchar(512),
	`cal_result` enum('success','failure','denied') NOT NULL DEFAULT 'success',
	`cal_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `customer_audit_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_shared_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`csr_tenant_id` int NOT NULL,
	`csr_report_type` enum('ac3','pentest','compliance','executive_summary','vulnerability','incident','dfir') NOT NULL,
	`csr_report_id` int NOT NULL,
	`csr_title` varchar(512) NOT NULL,
	`csr_description` text,
	`csr_shared_by` int NOT NULL,
	`csr_shared_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`csr_expires_at` timestamp,
	`csr_access_count` int NOT NULL DEFAULT 0,
	`csr_last_accessed_at` timestamp,
	`csr_is_active` tinyint NOT NULL DEFAULT 1,
	CONSTRAINT `customer_shared_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `engagement_credential_lists` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecl_engagement_id` int NOT NULL,
	`ecl_source` enum('dehashed','intelx','hudson_rock','leakcheck','manual','hibp','stealer_log') NOT NULL,
	`ecl_username` varchar(512) NOT NULL,
	`ecl_password` varchar(512),
	`ecl_password_hash` varchar(512),
	`ecl_hash_type` varchar(32),
	`ecl_email` varchar(320),
	`ecl_breach_name` varchar(512),
	`ecl_breach_date` varchar(32),
	`ecl_domain` varchar(512),
	`ecl_is_verified` tinyint NOT NULL DEFAULT 0,
	`ecl_is_used` tinyint NOT NULL DEFAULT 0,
	`ecl_used_at` timestamp,
	`ecl_used_result` enum('success','failure','locked','mfa_blocked','not_tested') DEFAULT 'not_tested',
	`ecl_confidence` enum('high','medium','low') NOT NULL DEFAULT 'medium',
	`ecl_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_credential_lists_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `regulatory_frameworks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rf_tenant_id` int,
	`rf_domain` varchar(512) NOT NULL,
	`rf_framework` varchar(128) NOT NULL,
	`rf_status` enum('auto_detected','customer_confirmed','customer_denied','operator_added') NOT NULL DEFAULT 'auto_detected',
	`rf_confidence` int DEFAULT 50,
	`rf_detection_method` varchar(255),
	`rf_detection_evidence` json,
	`rf_applicable_controls` json,
	`rf_notes` text,
	`rf_confirmed_by` int,
	`rf_confirmed_at` timestamp,
	`rf_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`rf_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `regulatory_frameworks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `cip_domain_idx` ON `company_intel_profiles` (`cip_domain`);--> statement-breakpoint
CREATE INDEX `cip_tenant_idx` ON `company_intel_profiles` (`cip_tenant_id`);--> statement-breakpoint
CREATE INDEX `ca_email_idx` ON `customer_accounts` (`ca_email`);--> statement-breakpoint
CREATE INDEX `ca_tenant_idx` ON `customer_accounts` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `cal_customer_idx` ON `customer_audit_log` (`customer_account_id`);--> statement-breakpoint
CREATE INDEX `cal_tenant_idx` ON `customer_audit_log` (`cal_tenant_id`);--> statement-breakpoint
CREATE INDEX `cal_action_idx` ON `customer_audit_log` (`cal_action`);--> statement-breakpoint
CREATE INDEX `csr_tenant_idx` ON `customer_shared_reports` (`csr_tenant_id`);--> statement-breakpoint
CREATE INDEX `csr_report_type_idx` ON `customer_shared_reports` (`csr_report_type`);--> statement-breakpoint
CREATE INDEX `ecl_engagement_idx` ON `engagement_credential_lists` (`ecl_engagement_id`);--> statement-breakpoint
CREATE INDEX `ecl_source_idx` ON `engagement_credential_lists` (`ecl_source`);--> statement-breakpoint
CREATE INDEX `ecl_domain_idx` ON `engagement_credential_lists` (`ecl_domain`);--> statement-breakpoint
CREATE INDEX `rf_domain_idx` ON `regulatory_frameworks` (`rf_domain`);--> statement-breakpoint
CREATE INDEX `rf_tenant_idx` ON `regulatory_frameworks` (`rf_tenant_id`);--> statement-breakpoint
CREATE INDEX `rf_framework_idx` ON `regulatory_frameworks` (`rf_framework`);