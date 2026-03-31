CREATE TABLE `ai_vuln_research_code_snippets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` int NOT NULL,
	`filename` varchar(512) NOT NULL,
	`language` varchar(64),
	`content` mediumtext NOT NULL,
	`line_count` int,
	`checksum` varchar(64),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `ai_vuln_research_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` int NOT NULL,
	`title` varchar(512) NOT NULL,
	`vuln_type` varchar(128) NOT NULL,
	`severity` enum('critical','high','medium','low','informational') NOT NULL,
	`cvss_score` float,
	`cvss_vector` varchar(256),
	`cwe_id` varchar(32),
	`cve_id` varchar(64),
	`description` text NOT NULL,
	`affected_code` mediumtext,
	`file_path` varchar(1024),
	`line_start` int,
	`line_end` int,
	`root_cause` text,
	`impact` text,
	`exploitability` enum('trivial','easy','moderate','difficult','theoretical'),
	`poc_code` mediumtext,
	`poc_language` varchar(64),
	`poc_status` enum('not_generated','generating','generated','validated','failed') DEFAULT 'not_generated',
	`remediation` text,
	`mitre_techniques` json,
	`attack_vector` varchar(256),
	`confidence_score` float,
	`llm_reasoning` mediumtext,
	`verified` tinyint DEFAULT 0,
	`exported_to_bug_bounty` tinyint DEFAULT 0,
	`bug_bounty_finding_id` int,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ai_vuln_research_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`title` varchar(512) NOT NULL,
	`description` text,
	`target_type` enum('source_code','github_repo','binary','config','protocol','firmware','custom') NOT NULL,
	`target_name` varchar(512) NOT NULL,
	`target_version` varchar(128),
	`github_url` varchar(1024),
	`language` varchar(64),
	`research_prompt` text NOT NULL,
	`status` enum('pending','analyzing','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
	`total_findings` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`llm_model` varchar(128),
	`tokens_used` int DEFAULT 0,
	`analysis_time_ms` int,
	`bug_bounty_program_id` int,
	`engagement_id` int,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `avrcs_session_idx` ON `ai_vuln_research_code_snippets` (`session_id`);--> statement-breakpoint
CREATE INDEX `avrf_session_idx` ON `ai_vuln_research_findings` (`session_id`);--> statement-breakpoint
CREATE INDEX `avrf_severity_idx` ON `ai_vuln_research_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `avrf_vuln_type_idx` ON `ai_vuln_research_findings` (`vuln_type`);--> statement-breakpoint
CREATE INDEX `avrf_cwe_idx` ON `ai_vuln_research_findings` (`cwe_id`);--> statement-breakpoint
CREATE INDEX `avrf_poc_status_idx` ON `ai_vuln_research_findings` (`poc_status`);--> statement-breakpoint
CREATE INDEX `avrs_user_idx` ON `ai_vuln_research_sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `avrs_status_idx` ON `ai_vuln_research_sessions` (`status`);--> statement-breakpoint
CREATE INDEX `avrs_target_idx` ON `ai_vuln_research_sessions` (`target_type`);--> statement-breakpoint
CREATE INDEX `avrs_program_idx` ON `ai_vuln_research_sessions` (`bug_bounty_program_id`);