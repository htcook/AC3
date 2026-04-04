CREATE TABLE `engagement_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`result_id` int,
	`title` varchar(512) NOT NULL,
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`cve` varchar(64),
	`cwe` varchar(128),
	`description` text,
	`endpoint` text,
	`hostname` varchar(255),
	`port` int,
	`source` varchar(128),
	`tool` varchar(128),
	`corroboration_tier` enum('confirmed','corroborated','unverified') DEFAULT 'unverified',
	`raw_evidence` text,
	`screenshot_path` text,
	`exploit_attempted` tinyint DEFAULT 0,
	`exploit_succeeded` tinyint DEFAULT 0,
	`exploit_technique` varchar(255),
	`owasp_category` varchar(128),
	`mitre_technique` varchar(128),
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `engagement_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`operator_id` int,
	`operator_name` varchar(255),
	`engagement_type` varchar(64),
	`target_domain` text,
	`status` enum('completed','error','partial') NOT NULL DEFAULT 'completed',
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`hosts_scanned` int DEFAULT 0,
	`ports_found` int DEFAULT 0,
	`vulns_found` int DEFAULT 0,
	`verified_vulns` int DEFAULT 0,
	`unverified_vulns` int DEFAULT 0,
	`exploits_attempted` int DEFAULT 0,
	`exploits_succeeded` int DEFAULT 0,
	`sessions_opened` int DEFAULT 0,
	`zap_scans_run` int DEFAULT 0,
	`critical_vulns` int DEFAULT 0,
	`high_vulns` int DEFAULT 0,
	`medium_vulns` int DEFAULT 0,
	`low_vulns` int DEFAULT 0,
	`info_vulns` int DEFAULT 0,
	`owasp_coverage_score` int,
	`owasp_total_tested` int,
	`owasp_total_partial` int,
	`owasp_total_gaps` int,
	`owasp_critical_gaps` json,
	`auto_report_id` varchar(128),
	`summary_json` json,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ef_engagement_idx` ON `engagement_findings` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ef_result_idx` ON `engagement_findings` (`result_id`);--> statement-breakpoint
CREATE INDEX `ef_severity_idx` ON `engagement_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `ef_corroboration_idx` ON `engagement_findings` (`corroboration_tier`);--> statement-breakpoint
CREATE INDEX `er_engagement_idx` ON `engagement_results` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `er_operator_idx` ON `engagement_results` (`operator_id`);--> statement-breakpoint
CREATE INDEX `er_status_idx` ON `engagement_results` (`status`);