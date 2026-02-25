CREATE TABLE `attack_playbook_executions` (
	`id` varchar(36) NOT NULL,
	`playbook_id` varchar(36) NOT NULL,
	`engagement_id` int,
	`current_phase` enum('pre_exploit','initial_access','execution','persistence','priv_escalation','lateral_movement','collection','exfiltration','cleanup','completed','aborted') NOT NULL DEFAULT 'pre_exploit',
	`current_step_index` int DEFAULT 0,
	`step_results` json,
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`executed_by` varchar(64),
	`status` enum('running','paused','completed','failed','aborted') NOT NULL DEFAULT 'running',
	CONSTRAINT `attack_playbook_executions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `attack_playbooks` (
	`id` varchar(36) NOT NULL,
	`engagement_id` int,
	`name` varchar(512) NOT NULL,
	`description` text,
	`target_environment` varchar(128),
	`target_platform` varchar(64),
	`kill_chain_coverage` json,
	`pre_exploit_steps` json,
	`exploit_steps` json,
	`post_exploit_steps` json,
	`cleanup_steps` json,
	`caldera_abilities` json,
	`msf_modules` json,
	`atomic_tests` json,
	`estimated_duration` varchar(64),
	`risk_level` enum('low','medium','high','critical') NOT NULL DEFAULT 'medium',
	`roe_compliant` boolean DEFAULT true,
	`status` enum('draft','approved','executing','completed','aborted') NOT NULL DEFAULT 'draft',
	`created_by` varchar(64),
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL,
	CONSTRAINT `attack_playbooks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `attack_vector_evidence` (
	`id` varchar(36) NOT NULL,
	`vector_id` varchar(36) NOT NULL,
	`source_type` enum('osint_finding','darkweb_record','vuln_scan','web_app_finding','exploit_script','credential_leak','domain_recon','threat_actor','atomic_test','cloud_misconfig') NOT NULL,
	`source_id` varchar(64) NOT NULL,
	`source_title` varchar(512),
	`relevance_score` double NOT NULL DEFAULT 0.5,
	`evidence_detail` text,
	`created_at` bigint NOT NULL,
	CONSTRAINT `attack_vector_evidence_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `attack_vectors` (
	`id` varchar(36) NOT NULL,
	`engagement_id` int,
	`name` varchar(512) NOT NULL,
	`description` text,
	`vector_type` enum('initial_access','credential_compromise','supply_chain','social_engineering','insider_threat','physical','web_application','network_exploitation','cloud_misconfiguration','wireless') NOT NULL,
	`kill_chain_phase` varchar(64) NOT NULL,
	`mitre_technique_ids` json,
	`cvss_score` double,
	`exploitability_score` double,
	`impact_score` double,
	`overall_risk_score` double NOT NULL,
	`confidence` varchar(16) NOT NULL DEFAULT 'medium',
	`status` enum('identified','validated','exploited','mitigated','accepted') NOT NULL DEFAULT 'identified',
	`target_asset` varchar(512),
	`target_platform` varchar(64),
	`target_service` varchar(255),
	`source_modules` json,
	`threat_actor_ids` json,
	`ksi_ids` json,
	`evidence_summary` text,
	`created_by` varchar(64),
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL,
	CONSTRAINT `attack_vectors_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `collection_job_history` (
	`id` varchar(36) NOT NULL,
	`schedule_id` varchar(36) NOT NULL,
	`source_type` varchar(50) NOT NULL,
	`status` enum('success','failure','running','completed','failed') NOT NULL,
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`evidence_collected` int DEFAULT 0,
	`error_message` text,
	`duration_ms` int,
	`triggered_by` varchar(255) DEFAULT 'manual',
	CONSTRAINT `collection_job_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `collection_schedules` (
	`id` varchar(36) NOT NULL,
	`source_type` varchar(50) NOT NULL,
	`display_name` varchar(200) NOT NULL,
	`enabled` boolean NOT NULL DEFAULT true,
	`cadence` enum('hourly','every_6h','every_12h','daily','weekly') NOT NULL DEFAULT 'daily',
	`last_run_at` bigint,
	`next_run_at` bigint,
	`last_status` enum('success','failure','running','never_run') NOT NULL DEFAULT 'never_run',
	`last_error` text,
	`last_evidence_count` int DEFAULT 0,
	`total_runs` int DEFAULT 0,
	`total_evidence_collected` int DEFAULT 0,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL,
	CONSTRAINT `collection_schedules_id` PRIMARY KEY(`id`)
);
