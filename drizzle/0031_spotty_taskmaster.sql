CREATE TABLE `credential_alert_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alert_rule_id` int NOT NULL,
	`alert_hist_credential_id` int NOT NULL,
	`alert_type` enum('expiring_soon','expired','rotation_due','validation_failed') NOT NULL,
	`alert_severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`alert_message` text NOT NULL,
	`notification_sent` boolean NOT NULL DEFAULT false,
	`notification_result` varchar(255),
	`alert_acknowledged_at` timestamp,
	`alert_acknowledged_by` varchar(255),
	`alert_cred_provider` varchar(32),
	`alert_cred_name` varchar(255),
	`alert_expires_at` timestamp,
	`days_until_expiry` int,
	`alert_hist_created_at` timestamp DEFAULT (now()),
	CONSTRAINT `credential_alert_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `credential_alert_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cred_alert_credential_id` int NOT NULL,
	`alert_name` varchar(255) NOT NULL,
	`threshold_days` int NOT NULL DEFAULT 30,
	`alert_is_enabled` boolean NOT NULL DEFAULT true,
	`alert_notify_owner` boolean NOT NULL DEFAULT true,
	`alert_last_checked_at` timestamp,
	`alert_last_alerted_at` timestamp,
	`alert_next_alert_at` timestamp,
	`alert_created_by` varchar(255),
	`alert_created_at` timestamp DEFAULT (now()),
	CONSTRAINT `credential_alert_rules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `forest_domains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`forest_name` varchar(255) NOT NULL,
	`forest_domain_name` varchar(255) NOT NULL,
	`forest_connection_id` int,
	`parent_domain_id` int,
	`forest_engagement_id` int,
	`domain_sid` varchar(128),
	`domain_functional_level` varchar(64),
	`forest_functional_level` varchar(64),
	`is_forest_root` boolean NOT NULL DEFAULT false,
	`forest_total_users` int DEFAULT 0,
	`forest_total_groups` int DEFAULT 0,
	`forest_total_computers` int DEFAULT 0,
	`forest_privileged_users` int DEFAULT 0,
	`forest_last_enumerated_at` timestamp,
	`forest_metadata` json,
	`forest_domain_created_at` timestamp DEFAULT (now()),
	CONSTRAINT `forest_domains_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `forest_trusts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`trust_source_domain_id` int NOT NULL,
	`trust_target_domain_id` int NOT NULL,
	`trust_direction` enum('inbound','outbound','bidirectional') NOT NULL,
	`trust_type` enum('parent_child','tree_root','shortcut','forest','external','realm') NOT NULL,
	`trust_is_transitive` boolean NOT NULL DEFAULT true,
	`sid_filtering_enabled` boolean NOT NULL DEFAULT true,
	`selective_auth` boolean NOT NULL DEFAULT false,
	`trust_attributes` int DEFAULT 0,
	`trust_is_vulnerable` boolean NOT NULL DEFAULT false,
	`trust_vulnerability_notes` text,
	`trust_discovered_at` timestamp DEFAULT (now()),
	`forest_trust_created_at` timestamp DEFAULT (now()),
	CONSTRAINT `forest_trusts_id` PRIMARY KEY(`id`)
);
