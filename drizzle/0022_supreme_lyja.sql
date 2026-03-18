CREATE TABLE `dfir_report_iocs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`report_id` int NOT NULL,
	`ioc_type` enum('ip','domain','hash_md5','hash_sha1','hash_sha256','url','email','cve','filename','registry_key','mutex') NOT NULL,
	`ioc_value` varchar(1024) NOT NULL,
	`ioc_context` text,
	`ioc_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `dfir_report_iocs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `dfir_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`external_id` varchar(128) NOT NULL,
	`dfir_source` enum('dfir_report','cisa','otx','mandiant','unit42','recorded_future','manual') NOT NULL,
	`dfir_title` varchar(512) NOT NULL,
	`dfir_url` varchar(1024),
	`published_at` timestamp,
	`dfir_summary` text,
	`threat_actors` json,
	`malware_families` json,
	`mitre_attack_techniques` json,
	`diamond_model` json,
	`dfir_timeline` json,
	`dfir_detections` json,
	`kill_chain_phases` json,
	`dfir_tags` json,
	`raw_content` longtext,
	`dfir_status` enum('pending','parsed','enriched','training_ready') NOT NULL DEFAULT 'pending',
	`dfir_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`dfir_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `dfir_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `ioc_report_idx` ON `dfir_report_iocs` (`report_id`);--> statement-breakpoint
CREATE INDEX `ioc_type_idx` ON `dfir_report_iocs` (`ioc_type`);--> statement-breakpoint
CREATE INDEX `ioc_value_idx` ON `dfir_report_iocs` (`ioc_value`);--> statement-breakpoint
CREATE INDEX `dfir_source_idx` ON `dfir_reports` (`dfir_source`);--> statement-breakpoint
CREATE INDEX `dfir_status_idx` ON `dfir_reports` (`dfir_status`);--> statement-breakpoint
CREATE INDEX `dfir_external_id_idx` ON `dfir_reports` (`external_id`);