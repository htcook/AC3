CREATE TABLE `attack_chains_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`acc_actor_id` varchar(128) NOT NULL,
	`acc_actor_name` varchar(255) NOT NULL,
	`acc_chain_name` varchar(512) NOT NULL,
	`acc_description` text,
	`acc_steps` json NOT NULL,
	`acc_tactics_traversed` json,
	`acc_risk_score` int DEFAULT 50,
	`acc_target_sectors` json,
	`acc_target_technologies` json,
	`acc_exploited_cves` json,
	`acc_tools_used` json,
	`acc_typical_duration` varchar(64),
	`acc_source_type` enum('dfir_report','threat_intel','incident_response','academic_research','simulation','osint') NOT NULL,
	`acc_source_reference` varchar(1024),
	`acc_confidence` int DEFAULT 75,
	`acc_observed_date` varchar(32),
	`acc_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`acc_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `dfir_observations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`dfir_report_id` varchar(128) NOT NULL,
	`dfir_report_title` varchar(512) NOT NULL,
	`dfir_report_source` varchar(255),
	`dfir_report_url` varchar(1024),
	`dfir_report_date` varchar(32),
	`dfir_actor_id` varchar(128),
	`dfir_actor_name` varchar(255),
	`dfir_observation_type` enum('initial_access','execution','persistence','privilege_escalation','defense_evasion','credential_access','discovery','lateral_movement','collection','exfiltration','command_and_control','impact','tool_usage','malware_behavior','infrastructure','victim_profile') NOT NULL,
	`dfir_technique_id` varchar(32),
	`dfir_technique_name` varchar(255),
	`dfir_description` text NOT NULL,
	`dfir_artifacts` json,
	`dfir_tools_observed` json,
	`dfir_associated_iocs` json,
	`dfir_impact_description` text,
	`dfir_victim_sector` varchar(128),
	`dfir_victim_region` varchar(128),
	`dfir_detection_methods` json,
	`dfir_mitigations` json,
	`dfir_confidence` int DEFAULT 75,
	`dfir_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ep_actor_id` varchar(128) NOT NULL,
	`ep_actor_name` varchar(255) NOT NULL,
	`playbook_title` varchar(512) NOT NULL,
	`ep_technique_id` varchar(32) NOT NULL,
	`ep_technique_name` varchar(255),
	`ep_tactic` varchar(128) NOT NULL,
	`ep_code` text NOT NULL,
	`ep_language` varchar(64) NOT NULL,
	`ep_tool_name` varchar(255),
	`ep_target_conditions` json,
	`ep_exploited_cves` json,
	`ep_target_services` json,
	`ep_target_platforms` json,
	`ep_evasion_techniques` json,
	`ep_success_indicators` json,
	`ep_source_type` enum('dfir_report','threat_intel','malware_analysis','incident_response','academic_research','honeypot','sandbox_detonation','osint') NOT NULL,
	`ep_source_reference` varchar(1024),
	`ep_confidence` int DEFAULT 75,
	`ep_observed_date` varchar(32),
	`ep_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ep_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ioc_ttp_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`itm_ioc_type` varchar(64) NOT NULL,
	`itm_ioc_value` text NOT NULL,
	`itm_ioc_description` text,
	`itm_source_ioc_id` int,
	`itm_actor_id` varchar(128),
	`itm_actor_name` varchar(255),
	`itm_technique_id` varchar(32) NOT NULL,
	`itm_technique_name` varchar(255),
	`itm_tactic` varchar(128) NOT NULL,
	`itm_reasoning` text NOT NULL,
	`itm_inference_confidence` int DEFAULT 60,
	`itm_derivation_method` enum('pattern_match','llm_analysis','malware_analysis','behavioral_analysis','infrastructure_analysis','manual') NOT NULL,
	`itm_context` json,
	`itm_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `acc_actor_idx` ON `attack_chains_catalog` (`acc_actor_id`);--> statement-breakpoint
CREATE INDEX `acc_chain_name_idx` ON `attack_chains_catalog` (`acc_chain_name`);--> statement-breakpoint
CREATE INDEX `dfir_report_idx` ON `dfir_observations` (`dfir_report_id`);--> statement-breakpoint
CREATE INDEX `dfir_actor_idx` ON `dfir_observations` (`dfir_actor_id`);--> statement-breakpoint
CREATE INDEX `dfir_technique_idx` ON `dfir_observations` (`dfir_technique_id`);--> statement-breakpoint
CREATE INDEX `dfir_type_idx` ON `dfir_observations` (`dfir_observation_type`);--> statement-breakpoint
CREATE INDEX `ep_actor_idx` ON `exploit_playbooks` (`ep_actor_id`);--> statement-breakpoint
CREATE INDEX `ep_technique_idx` ON `exploit_playbooks` (`ep_technique_id`);--> statement-breakpoint
CREATE INDEX `ep_tool_idx` ON `exploit_playbooks` (`ep_tool_name`);--> statement-breakpoint
CREATE INDEX `itm_actor_idx` ON `ioc_ttp_mappings` (`itm_actor_id`);--> statement-breakpoint
CREATE INDEX `itm_technique_idx` ON `ioc_ttp_mappings` (`itm_technique_id`);--> statement-breakpoint
CREATE INDEX `itm_ioc_type_idx` ON `ioc_ttp_mappings` (`itm_ioc_type`);