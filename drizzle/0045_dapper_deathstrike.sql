CREATE TABLE `config_baseline_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`baseline_id` varchar(64) NOT NULL,
	`rule_id` varchar(64) NOT NULL,
	`benchmark` varchar(128) NOT NULL,
	`section` varchar(32) NOT NULL,
	`title` varchar(512) NOT NULL,
	`description` text,
	`cbr_severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`cbr_platform` varchar(64) NOT NULL,
	`expected_value` text,
	`remediation_guidance` text,
	`ksi_ids` json,
	`mitre_ids` json,
	`enabled` boolean NOT NULL DEFAULT true,
	`cbr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `config_baseline_rules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `config_baselines` (
	`id` int AUTO_INCREMENT NOT NULL,
	`baseline_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`platform` varchar(64) NOT NULL,
	`benchmark` varchar(128) NOT NULL,
	`rule_count` int DEFAULT 0,
	`bl_status` enum('active','draft','archived') NOT NULL DEFAULT 'active',
	`last_scan_at` timestamp,
	`last_scan_score` int,
	`created_by` int,
	`created_by_name` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `config_baselines_id` PRIMARY KEY(`id`),
	CONSTRAINT `config_baselines_baseline_id_unique` UNIQUE(`baseline_id`)
);
--> statement-breakpoint
CREATE TABLE `config_drift_alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alert_id` varchar(64) NOT NULL,
	`scan_id` varchar(64) NOT NULL,
	`baseline_id` varchar(64) NOT NULL,
	`rule_id` varchar(64) NOT NULL,
	`rule_title` varchar(512),
	`cda_severity` enum('critical','high','medium','low') DEFAULT 'medium',
	`drift_type` varchar(64),
	`cda_description` text,
	`cda_target_name` varchar(255),
	`cda_remediation_guidance` text,
	`cda_status` enum('open','acknowledged','remediated','accepted','false_positive') NOT NULL DEFAULT 'open',
	`cda_ksi_ids` json,
	`cda_mitre_ids` json,
	`resolved_at` timestamp,
	`cda_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `config_drift_alerts_id` PRIMARY KEY(`id`),
	CONSTRAINT `config_drift_alerts_alert_id_unique` UNIQUE(`alert_id`)
);
--> statement-breakpoint
CREATE TABLE `config_scan_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` varchar(64) NOT NULL,
	`baseline_id` varchar(64) NOT NULL,
	`rule_id` varchar(64) NOT NULL,
	`rule_title` varchar(512),
	`csr_severity` enum('critical','high','medium','low') DEFAULT 'medium',
	`csr_status` enum('pass','fail','warning','error') NOT NULL,
	`expected_value` text,
	`current_value` text,
	`drift_detected` boolean DEFAULT false,
	`target_name` varchar(255),
	`target_type` varchar(64),
	`scanned_by` int,
	`scanned_by_name` varchar(255),
	`scanned_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `config_scan_results_id` PRIMARY KEY(`id`)
);
