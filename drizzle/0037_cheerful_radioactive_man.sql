CREATE TABLE `attack_chain_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`acr_chain_id` varchar(128) NOT NULL,
	`acr_scan_id` int,
	`acr_chain_type` varchar(64) NOT NULL,
	`acr_pattern_name` varchar(255),
	`acr_steps` json NOT NULL,
	`acr_entry_point` varchar(255),
	`acr_final_target` varchar(255),
	`acr_overall_confidence` double,
	`acr_risk_score` double,
	`acr_mitre_techniques` json,
	`acr_validated` boolean DEFAULT false,
	`acr_validation_result` json,
	`acr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `attack_chain_records_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `exploit_feedback_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`efr_exploit_module` varchar(512) NOT NULL,
	`efr_target` varchar(255) NOT NULL,
	`efr_port` int,
	`efr_service` varchar(128),
	`efr_cve_id` varchar(32),
	`efr_success` boolean NOT NULL,
	`efr_duration_ms` int,
	`efr_error_type` varchar(128),
	`efr_error_message` text,
	`efr_output` text,
	`efr_os_type` varchar(64),
	`efr_os_version` varchar(128),
	`efr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `exploit_feedback_records_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `exploit_preflight_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eph_exploit_module` varchar(512) NOT NULL,
	`eph_target` varchar(255) NOT NULL,
	`eph_port` int,
	`eph_service` varchar(128),
	`eph_success` boolean NOT NULL,
	`eph_duration_ms` int,
	`eph_error_type` varchar(128),
	`eph_preflight_score` double,
	`eph_preflight_factors` json,
	`eph_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `exploit_preflight_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `generated_detection_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`gdr_rule_id` varchar(128) NOT NULL,
	`gdr_cve_id` varchar(32) NOT NULL,
	`gdr_format` varchar(32) NOT NULL,
	`gdr_title` varchar(512) NOT NULL,
	`gdr_content` mediumtext NOT NULL,
	`gdr_severity` varchar(16),
	`gdr_mitre_tactics` json,
	`gdr_mitre_techniques` json,
	`gdr_data_sources` json,
	`gdr_validated` boolean DEFAULT false,
	`gdr_validation_errors` json,
	`gdr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `generated_detection_rules_id` PRIMARY KEY(`id`)
);
