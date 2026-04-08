CREATE TABLE `burp_scan_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`credential_id` int NOT NULL,
	`user_id` varchar(128) NOT NULL,
	`scan_id` varchar(255),
	`edition` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`progress` int NOT NULL DEFAULT 0,
	`target_urls` json,
	`issue_count` int NOT NULL DEFAULT 0,
	`imported_count` int NOT NULL DEFAULT 0,
	`scan_config_name` varchar(255),
	`error` text,
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`last_poll_at` bigint,
	`poll_count` int NOT NULL DEFAULT 0,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `burp_scan_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `deployment_update_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`from_version` varchar(32) NOT NULL,
	`to_version` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`migration_log` text,
	`error` text,
	`rolled_back` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `deployment_update_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `deployment_versions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`version` varchar(32) NOT NULL,
	`release_date` bigint NOT NULL,
	`channel` varchar(32) NOT NULL DEFAULT 'stable',
	`changelog` text NOT NULL,
	`migration_script` text,
	`min_previous_version` varchar(32),
	`download_url` varchar(512),
	`checksum_sha256` varchar(64),
	`is_breaking` tinyint NOT NULL DEFAULT 0,
	`is_required` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `deployment_versions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `license_usage_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`action` varchar(64) NOT NULL,
	`resource_type` varchar(64),
	`resource_id` varchar(255),
	`metadata` json,
	`timestamp` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `license_usage_logs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `licensed_organizations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`org_name` varchar(255) NOT NULL,
	`contact_email` varchar(255),
	`contact_name` varchar(255),
	`tier` varchar(32) NOT NULL DEFAULT 'starter',
	`license_key` text NOT NULL,
	`license_key_hash` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'active',
	`issued_at` bigint NOT NULL,
	`expires_at` bigint NOT NULL,
	`revoked_at` bigint,
	`revoked_reason` text,
	`max_seats` int NOT NULL DEFAULT 5,
	`max_scans_per_period` int NOT NULL DEFAULT 50,
	`billing_period_days` int NOT NULL DEFAULT 30,
	`grace_period_days` int NOT NULL DEFAULT 7,
	`feature_overrides` json,
	`deployment_domain` varchar(255),
	`notes` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `licensed_organizations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `ransomware_groups` RENAME COLUMN `victims7d` TO `victims7D`;--> statement-breakpoint
ALTER TABLE `ransomware_groups` RENAME COLUMN `victims30d` TO `victims30D`;--> statement-breakpoint
DROP INDEX `ditd_analyst_rating_idx` ON `di_incident_training_data`;--> statement-breakpoint
ALTER TABLE `fingerprint_cache` DROP PRIMARY KEY;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `scan_id` int;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `quality_score` float NOT NULL;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `analyst_rating` enum('not_reviewed','accurate','partially_accurate','inaccurate') NOT NULL DEFAULT 'not_reviewed';--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `incident_count` int NOT NULL;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `actors_discovered` int NOT NULL;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `ttps_discovered` int NOT NULL;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` MODIFY COLUMN `created_at` bigint NOT NULL;--> statement-breakpoint
ALTER TABLE `engagements` MODIFY COLUMN `engagementType` enum('red_team','phishing','pentest','purple_team','tabletop','bug_bounty') NOT NULL DEFAULT 'red_team';--> statement-breakpoint
ALTER TABLE `ics_devices` MODIFY COLUMN `icd_discovery_source` enum('shodan','censys','nmap','protocol_scan','manual','caldera') DEFAULT 'manual';--> statement-breakpoint
ALTER TABLE `redteam_campaign_stages` MODIFY COLUMN `config` json;--> statement-breakpoint
ALTER TABLE `redteam_campaign_stages` MODIFY COLUMN `entry_conditions` json;--> statement-breakpoint
ALTER TABLE `redteam_campaign_stages` MODIFY COLUMN `exit_conditions` json;--> statement-breakpoint
ALTER TABLE `user_platform_credentials` MODIFY COLUMN `platform` enum('hackerone','bugcrowd','intigriti','synack','yeswehack','open_bug_bounty','immunefi','burpsuite_pro','burpsuite_enterprise','custom') NOT NULL;--> statement-breakpoint
ALTER TABLE `ac3_reports` ADD `rpt_tools_used` json;--> statement-breakpoint
ALTER TABLE `ac3_reports` ADD `rpt_test_phases` json;--> statement-breakpoint
ALTER TABLE `ac3_reports` ADD `engagement_id` int;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` ADD `analyst_reviewed_by` int;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` ADD `usage_count` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` ADD `updated_at` bigint NOT NULL;--> statement-breakpoint
ALTER TABLE `engagements` ADD `domain_intel_scan_id` int;--> statement-breakpoint
ALTER TABLE `llm_decision_log` ADD `knowledge_modules_used` json;--> statement-breakpoint
CREATE INDEX `bsh_engagement_idx` ON `burp_scan_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `bsh_user_idx` ON `burp_scan_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `bsh_status_idx` ON `burp_scan_history` (`status`);--> statement-breakpoint
CREATE INDEX `update_org_idx` ON `deployment_update_history` (`org_id`);--> statement-breakpoint
CREATE INDEX `update_status_idx` ON `deployment_update_history` (`status`);--> statement-breakpoint
CREATE INDEX `version_idx` ON `deployment_versions` (`version`);--> statement-breakpoint
CREATE INDEX `channel_idx` ON `deployment_versions` (`channel`);--> statement-breakpoint
CREATE INDEX `usage_org_id_idx` ON `license_usage_logs` (`org_id`);--> statement-breakpoint
CREATE INDEX `usage_action_idx` ON `license_usage_logs` (`action`);--> statement-breakpoint
CREATE INDEX `usage_timestamp_idx` ON `license_usage_logs` (`timestamp`);--> statement-breakpoint
CREATE INDEX `licensed_org_id_idx` ON `licensed_organizations` (`org_id`);--> statement-breakpoint
CREATE INDEX `licensed_status_idx` ON `licensed_organizations` (`status`);--> statement-breakpoint
CREATE INDEX `licensed_tier_idx` ON `licensed_organizations` (`tier`);--> statement-breakpoint
CREATE INDEX `ditd_rating_idx` ON `di_incident_training_data` (`analyst_rating`);--> statement-breakpoint
ALTER TABLE `di_incident_training_data` DROP COLUMN `analyst_id`;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` DROP COLUMN `rated_at`;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` DROP COLUMN `risk_score_at_scan`;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` DROP COLUMN `risk_band_at_scan`;--> statement-breakpoint
ALTER TABLE `di_incident_training_data` DROP COLUMN `used_in_prompt_count`;