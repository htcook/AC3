CREATE TABLE `dns_security_assessments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain` varchar(253) NOT NULL,
	`engagement_id` int,
	`scan_id` int,
	`context` varchar(32) NOT NULL DEFAULT 'di_scan',
	`overall_risk` varchar(16) NOT NULL,
	`total_findings` int NOT NULL DEFAULT 0,
	`critical_count` int NOT NULL DEFAULT 0,
	`high_count` int NOT NULL DEFAULT 0,
	`medium_count` int NOT NULL DEFAULT 0,
	`low_count` int NOT NULL DEFAULT 0,
	`info_count` int NOT NULL DEFAULT 0,
	`total_checks` int NOT NULL DEFAULT 15,
	`passed_checks` int NOT NULL DEFAULT 0,
	`failed_checks` int NOT NULL DEFAULT 0,
	`dnssec_enabled` tinyint NOT NULL DEFAULT 0,
	`dnssec_chain_valid` tinyint NOT NULL DEFAULT 0,
	`response_time_ms` int,
	`report_json` json,
	`previous_assessment_id` int,
	`changes_since_last_json` json,
	`assessed_at` timestamp NOT NULL DEFAULT (now()),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `dns_security_assessments_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `dns_security_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`assessment_id` int NOT NULL,
	`finding_id` varchar(64) NOT NULL,
	`severity` varchar(16) NOT NULL,
	`category` varchar(64) NOT NULL,
	`title` varchar(512) NOT NULL,
	`description` text,
	`affected_record` varchar(512),
	`evidence` text,
	`remediation` text,
	`mitre_attack_id` varchar(32),
	`cvss_score` decimal(3,1),
	`cvss_vector` varchar(128),
	`cwe` varchar(32),
	`references` json,
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`resolved_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `dns_security_findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `dns_security_monitoring_config` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain` varchar(253) NOT NULL,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`interval_hours` int NOT NULL DEFAULT 24,
	`alert_on_new_critical` tinyint NOT NULL DEFAULT 1,
	`alert_on_new_high` tinyint NOT NULL DEFAULT 1,
	`alert_on_dns_change` tinyint NOT NULL DEFAULT 1,
	`last_checked_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `dns_security_monitoring_config_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `dns_assess_domain_idx` ON `dns_security_assessments` (`domain`);--> statement-breakpoint
CREATE INDEX `dns_assess_engagement_idx` ON `dns_security_assessments` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `dns_assess_scan_idx` ON `dns_security_assessments` (`scan_id`);--> statement-breakpoint
CREATE INDEX `dns_assess_risk_idx` ON `dns_security_assessments` (`overall_risk`);--> statement-breakpoint
CREATE INDEX `dns_assess_assessed_at_idx` ON `dns_security_assessments` (`assessed_at`);--> statement-breakpoint
CREATE INDEX `dns_find_assessment_idx` ON `dns_security_findings` (`assessment_id`);--> statement-breakpoint
CREATE INDEX `dns_find_severity_idx` ON `dns_security_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `dns_find_category_idx` ON `dns_security_findings` (`category`);--> statement-breakpoint
CREATE INDEX `dns_find_status_idx` ON `dns_security_findings` (`status`);--> statement-breakpoint
CREATE INDEX `dns_find_mitre_idx` ON `dns_security_findings` (`mitre_attack_id`);--> statement-breakpoint
CREATE INDEX `dns_mon_domain_idx` ON `dns_security_monitoring_config` (`domain`);--> statement-breakpoint
CREATE INDEX `dns_mon_enabled_idx` ON `dns_security_monitoring_config` (`enabled`);