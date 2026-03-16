CREATE TABLE `ember_agents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`agent_id` varchar(64) NOT NULL,
	`ember_name` varchar(255) NOT NULL,
	`engagement_id` int,
	`ember_profile` enum('ghost','scout','striker','sentinel','hydra') NOT NULL,
	`ember_platform` enum('windows_x64','windows_x86','linux_x64','linux_arm64','macos_x64','macos_arm64') NOT NULL,
	`ember_autonomy` enum('manual','guided','semi_auto','full_auto') NOT NULL DEFAULT 'manual',
	`ember_state` enum('initializing','dormant','active','evading','pivoting','exfiltrating','self_destruct','dead') NOT NULL DEFAULT 'initializing',
	`ember_hostname` varchar(255),
	`ember_username` varchar(255),
	`ember_domain` varchar(255),
	`os_version` varchar(255),
	`ember_arch` varchar(32),
	`is_elevated` tinyint DEFAULT 0,
	`ember_integrity` enum('low','medium','high','system') DEFAULT 'medium',
	`ember_pid` int,
	`process_name` varchar(255),
	`external_ip` varchar(64),
	`internal_ip` varchar(64),
	`primary_channel` varchar(32) DEFAULT 'https_beacon',
	`beacon_interval` int DEFAULT 60,
	`jitter_percent` int DEFAULT 20,
	`kill_date` bigint,
	`last_beacon_at` bigint,
	`beacon_count` int DEFAULT 0,
	`missed_beacons` int DEFAULT 0,
	`ember_reg_token` varchar(128),
	`ember_config_json` json,
	`ember_system_info_json` json,
	`ember_security_products` json,
	`ember_loaded_modules` json,
	`cognitive_enabled` tinyint DEFAULT 0,
	`cognitive_objective` text,
	`cognitive_actions_used` int DEFAULT 0,
	`cognitive_actions_max` int DEFAULT 20,
	`ember_swarm_id` varchar(64),
	`ember_swarm_role` enum('coordinator','worker','relay','observer'),
	`evasion_score` int DEFAULT 0,
	`ember_traffic_profile` varchar(64),
	`ember_created_at` bigint NOT NULL,
	`ember_updated_at` bigint NOT NULL,
	`ember_terminated_at` bigint
);
--> statement-breakpoint
CREATE TABLE `ember_beacons` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ember_beacon_agent_id` varchar(64) NOT NULL,
	`ember_beacon_seq` int NOT NULL,
	`ember_beacon_state` varchar(32),
	`ember_beacon_channel` varchar(32),
	`ember_beacon_sysinfo` json,
	`ember_beacon_health` json,
	`ember_beacon_intel` json,
	`ember_beacon_results` json,
	`ember_beacon_received_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_intelligence` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ember_intel_agent_id` varchar(64) NOT NULL,
	`ember_intel_engagement_id` int,
	`ember_intel_type` varchar(64) NOT NULL,
	`ember_intel_confidence` int DEFAULT 50,
	`ember_intel_data` json,
	`ember_intel_shared` tinyint DEFAULT 0,
	`ember_intel_discovered_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_payloads` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ember_payload_id` varchar(64) NOT NULL,
	`ember_payload_engagement_id` int,
	`ember_payload_profile` varchar(32) NOT NULL,
	`ember_payload_platform` varchar(32) NOT NULL,
	`ember_payload_format` varchar(32) NOT NULL,
	`ember_callback_urls` json,
	`ember_payload_channel` varchar(32),
	`ember_evasion_config` json,
	`ember_payload_beacon_config` json,
	`ember_payload_cognitive_config` json,
	`ember_payload_reg_token` varchar(128),
	`ember_payload_filename` varchar(255),
	`ember_payload_hash` varchar(64),
	`ember_payload_size` int,
	`ember_detection_rate` int,
	`ember_payload_evasion_techniques` json,
	`ember_payload_capabilities` json,
	`ember_generated_by` varchar(64),
	`ember_payload_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_swarms` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ember_swarm_sid` varchar(64) NOT NULL,
	`ember_swarm_engagement_id` int,
	`ember_swarm_name` varchar(255) NOT NULL,
	`ember_coordinator_id` varchar(64),
	`ember_member_ids` json,
	`ember_shared_intel` json,
	`ember_evasion_state` json,
	`ember_swarm_status` enum('forming','active','degraded','dissolved') NOT NULL DEFAULT 'forming',
	`ember_swarm_created_at` bigint NOT NULL,
	`ember_swarm_updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_tasks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ember_task_id` varchar(64) NOT NULL,
	`ember_task_agent_id` varchar(64) NOT NULL,
	`ember_task_engagement_id` int,
	`ember_task_type` varchar(32) NOT NULL,
	`ember_task_priority` int DEFAULT 5,
	`ember_task_params` json,
	`ember_attack_technique` varchar(32),
	`ember_timeout_seconds` int DEFAULT 300,
	`ember_requires_elevation` tinyint DEFAULT 0,
	`ember_assigned_by` varchar(64) DEFAULT 'operator',
	`ember_cognitive_reasoning` text,
	`ember_safety_allowed` tinyint DEFAULT 1,
	`ember_safety_risk_score` int DEFAULT 0,
	`ember_safety_reason` text,
	`ember_task_status` enum('pending','sent','running','success','failed','timeout','blocked','partial') NOT NULL DEFAULT 'pending',
	`ember_task_output` mediumtext,
	`ember_task_error` text,
	`ember_artifacts_json` json,
	`ember_duration_ms` int,
	`ember_sent_at` bigint,
	`ember_completed_at` bigint,
	`ember_task_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ember_agent_id_idx` ON `ember_agents` (`agent_id`);--> statement-breakpoint
CREATE INDEX `ember_engagement_idx` ON `ember_agents` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ember_state_idx` ON `ember_agents` (`ember_state`);--> statement-breakpoint
CREATE INDEX `ember_profile_idx` ON `ember_agents` (`ember_profile`);--> statement-breakpoint
CREATE INDEX `ember_swarm_idx` ON `ember_agents` (`ember_swarm_id`);--> statement-breakpoint
CREATE INDEX `eb_agent_idx` ON `ember_beacons` (`ember_beacon_agent_id`);--> statement-breakpoint
CREATE INDEX `eb_received_idx` ON `ember_beacons` (`ember_beacon_received_at`);--> statement-breakpoint
CREATE INDEX `ei_agent_idx` ON `ember_intelligence` (`ember_intel_agent_id`);--> statement-breakpoint
CREATE INDEX `ei_engagement_idx` ON `ember_intelligence` (`ember_intel_engagement_id`);--> statement-breakpoint
CREATE INDEX `ei_type_idx` ON `ember_intelligence` (`ember_intel_type`);--> statement-breakpoint
CREATE INDEX `ep_engagement_idx` ON `ember_payloads` (`ember_payload_engagement_id`);--> statement-breakpoint
CREATE INDEX `ep_payload_id_idx` ON `ember_payloads` (`ember_payload_id`);--> statement-breakpoint
CREATE INDEX `ep_token_idx` ON `ember_payloads` (`ember_payload_reg_token`);--> statement-breakpoint
CREATE INDEX `es_swarm_id_idx` ON `ember_swarms` (`ember_swarm_sid`);--> statement-breakpoint
CREATE INDEX `es_engagement_idx` ON `ember_swarms` (`ember_swarm_engagement_id`);--> statement-breakpoint
CREATE INDEX `et_agent_idx` ON `ember_tasks` (`ember_task_agent_id`);--> statement-breakpoint
CREATE INDEX `et_engagement_idx` ON `ember_tasks` (`ember_task_engagement_id`);--> statement-breakpoint
CREATE INDEX `et_status_idx` ON `ember_tasks` (`ember_task_status`);--> statement-breakpoint
CREATE INDEX `et_task_id_idx` ON `ember_tasks` (`ember_task_id`);