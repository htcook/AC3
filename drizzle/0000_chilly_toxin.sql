CREATE TABLE `ability_graph_edges` (
	`id` int AUTO_INCREMENT NOT NULL,
	`edge_id` varchar(64) NOT NULL,
	`graph_id` varchar(64) NOT NULL,
	`source_node_id` varchar(64) NOT NULL,
	`target_node_id` varchar(64) NOT NULL,
	`condition` varchar(32) NOT NULL DEFAULT 'on_success',
	`condition_expression` text,
	`output_match_pattern` varchar(512),
	`weight` int DEFAULT 1,
	`label` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ability_graph_nodes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`node_id` varchar(64) NOT NULL,
	`graph_id` varchar(64) NOT NULL,
	`label` varchar(255) NOT NULL,
	`description` text,
	`technique_id` varchar(32) NOT NULL,
	`technique_name` varchar(255) NOT NULL,
	`tactic` varchar(128) NOT NULL,
	`caldera_ability_id` varchar(128),
	`executor` varchar(32),
	`platform` varchar(32),
	`command` text,
	`cleanup_command` text,
	`payload` text,
	`preconditions` json,
	`exit_criteria` json,
	`safety_tier` varchar(32) NOT NULL DEFAULT 'medium_impact',
	`timeout` int DEFAULT 300,
	`retry_count` int DEFAULT 1,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`execution_order` int DEFAULT 0,
	`layer` int DEFAULT 0,
	`execution_result` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ability_graphs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`graph_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`source_type` varchar(64) NOT NULL,
	`source_id` varchar(128),
	`actor_name` varchar(255),
	`tactics` json,
	`technique_count` int DEFAULT 0,
	`node_count` int DEFAULT 0,
	`edge_count` int DEFAULT 0,
	`status` varchar(32) NOT NULL DEFAULT 'draft',
	`safety_tier` varchar(32) NOT NULL DEFAULT 'medium_impact',
	`scan_mode` varchar(32) NOT NULL DEFAULT 'active-standard',
	`execution_id` varchar(128),
	`started_at` timestamp,
	`completed_at` timestamp,
	`nodes_completed` int DEFAULT 0,
	`nodes_failed` int DEFAULT 0,
	`nodes_skipped` int DEFAULT 0,
	`created_by` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `access_broker_listings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`brokerId` varchar(128) NOT NULL,
	`brokerName` varchar(255) NOT NULL,
	`aliases` json,
	`listingType` enum('vpn_access','rdp_access','citrix_access','webshell','domain_admin','cloud_access','email_access','database_access','zero_day','exploit_kit','credential_dump','other') NOT NULL DEFAULT 'other',
	`accessType` varchar(128),
	`victimSector` varchar(128),
	`victimCountry` varchar(128),
	`victimRevenue` varchar(64),
	`victimEmployeeCount` varchar(64),
	`askingPrice` varchar(64),
	`currency` varchar(16) DEFAULT 'USD',
	`forumSource` varchar(128),
	`forumPostUrl` text,
	`brokerReputation` enum('established','rising','new','unknown') DEFAULT 'unknown',
	`totalListings` int DEFAULT 0,
	`successfulSales` int DEFAULT 0,
	`activeForums` json,
	`linkedActorIds` json,
	`linkedRansomwareGroups` json,
	`accessLevel` enum('domain_admin','local_admin','user','service_account','unknown') DEFAULT 'unknown',
	`persistenceMechanism` varchar(255),
	`mitreTechniques` json,
	`iabStatus` enum('active','sold','expired','removed','law_enforcement') DEFAULT 'active',
	`iabFirstSeen` varchar(32),
	`iabLastActive` varchar(32),
	`postedAt` timestamp,
	`iabDataSource` varchar(128),
	`iabConfidence` int DEFAULT 75,
	`iabDescription` text,
	`iabRawData` json,
	`iabCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`iabUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `active_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`account_id` int NOT NULL,
	`session_token` varchar(255) NOT NULL,
	`ip_address` varchar(45),
	`user_agent` text,
	`device_info` varchar(255),
	`last_activity_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`expires_at` timestamp NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `activity_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`serverId` int,
	`action` varchar(255) NOT NULL,
	`details` text,
	`ipAddress` varchar(45),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`alog_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `ad_attack_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`environment_id` int NOT NULL,
	`path_name` varchar(255) NOT NULL,
	`source_node` varchar(512) NOT NULL,
	`target_node` varchar(512) NOT NULL,
	`path_length` int,
	`path_nodes` json,
	`path_edges` json,
	`risk_score` double,
	`is_shortest_path` tinyint DEFAULT 0,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ad_attack_simulations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`environment_id` int NOT NULL,
	`engagement_id` int,
	`ad_attack_type` enum('kerberoasting','as_rep_roasting','dcsync','golden_ticket','silver_ticket','pass_the_hash','pass_the_ticket','overpass_the_hash','skeleton_key','dcshadow','sid_history_injection','gpo_abuse','certificate_abuse','constrained_delegation','unconstrained_delegation','resource_based_constrained_delegation','ad_enumeration') NOT NULL,
	`target_object` varchar(512),
	`source_object` varchar(512),
	`sim_status` enum('pending','running','success','failed','blocked') NOT NULL DEFAULT 'pending',
	`risk_score` double,
	`ad_severity` enum('critical','high','medium','low') DEFAULT 'high',
	`description` text,
	`attack_path` json,
	`prerequisites` json,
	`mitre_techniques` json,
	`evidence` json,
	`remediation_steps` json,
	`detected_by` json,
	`executed_at` timestamp,
	`completed_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ad_domain_connections` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ad_environment_id` int,
	`ad_conn_engagement_id` int,
	`connection_name` varchar(255) NOT NULL,
	`server_host` varchar(255) NOT NULL,
	`server_port` int NOT NULL DEFAULT 389,
	`use_tls` tinyint DEFAULT 0,
	`tls_reject_unauthorized` tinyint DEFAULT 1,
	`base_dn` varchar(1024) NOT NULL,
	`bind_dn` varchar(1024),
	`encrypted_bind_password` text,
	`bind_password_iv` varchar(64),
	`bind_password_tag` varchar(64),
	`ldap_domain_name` varchar(255) NOT NULL,
	`search_scope` enum('base','one','sub') DEFAULT 'sub',
	`conn_status` enum('connected','disconnected','testing','error') NOT NULL DEFAULT 'disconnected',
	`last_connected_at` timestamp,
	`last_enumeration_at` timestamp,
	`conn_error_message` text,
	`conn_created_by` varchar(255),
	`conn_created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`conn_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ad_enumeration_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ad_connection_id` int NOT NULL,
	`ad_enum_environment_id` int,
	`ad_enum_engagement_id` int,
	`ad_enum_status` enum('pending','running','completed','error','partial') NOT NULL DEFAULT 'pending',
	`ad_enum_scope` enum('full','users','groups','computers','gpos','ous','trusts','spns','certificates') DEFAULT 'full',
	`ad_total_users_found` int DEFAULT 0,
	`ad_total_groups_found` int DEFAULT 0,
	`ad_total_computers_found` int DEFAULT 0,
	`ad_total_gpos_found` int DEFAULT 0,
	`ad_total_ous_found` int DEFAULT 0,
	`ad_total_trusts_found` int DEFAULT 0,
	`ad_total_spns_found` int DEFAULT 0,
	`privileged_users_found` int DEFAULT 0,
	`kerberoastable_found` int DEFAULT 0,
	`asrep_roastable_found` int DEFAULT 0,
	`ad_enum_results` json,
	`ad_enum_error_log` json,
	`ad_enum_started_at` timestamp,
	`ad_enum_completed_at` timestamp,
	`ad_enum_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ad_environments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`domain_name` varchar(255) NOT NULL,
	`domain_controller` varchar(255),
	`forest_name` varchar(255),
	`functional_level` varchar(64),
	`ad_status` enum('connected','disconnected','scanning','error') NOT NULL DEFAULT 'disconnected',
	`last_enum_at` timestamp,
	`connection_config` json,
	`stats` json,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ad_objects` (
	`id` int AUTO_INCREMENT NOT NULL,
	`environment_id` int NOT NULL,
	`object_type` enum('user','group','computer','gpo','ou','trust','spn','certificate_template') NOT NULL,
	`distinguished_name` varchar(1024),
	`sam_account_name` varchar(255),
	`display_name` varchar(255),
	`is_privileged` tinyint DEFAULT 0,
	`is_enabled` tinyint DEFAULT 1,
	`member_of` json,
	`members` json,
	`properties` json,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `agent_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`agentId` varchar(36) NOT NULL,
	`eventType` enum('register','heartbeat','task_assigned','task_sent','task_completed','task_failed','artifact_uploaded','payload_downloaded','paused','resumed','terminated','lost','reconnected','deregistered','approved','rejected') NOT NULL,
	`actorId` int,
	`actorType` enum('operator','system','agent') NOT NULL,
	`details` json,
	`recordHash` varchar(128) NOT NULL DEFAULT '',
	`previousHash` varchar(64) NOT NULL,
	`ipAddress` varchar(45),
	`userAgent` varchar(512),
	`createdAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `agent_deployments` (
	`id` varchar(36) NOT NULL,
	`engagementId` int,
	`name` varchar(255) NOT NULL,
	`description` text,
	`targetPlatform` enum('windows','linux','darwin') NOT NULL,
	`c2Protocol` enum('caldera','sliver','metasploit','native') NOT NULL,
	`agentStatus` enum('pending_approval','approved','deploying','active','paused','lost','completed','terminated','failed') DEFAULT 'pending_approval',
	`publicKey` text,
	`certificateHash` varchar(128),
	`registrationTokenHash` varchar(128),
	`ttlSeconds` int NOT NULL DEFAULT 86400,
	`watchdogSeconds` int NOT NULL DEFAULT 14400,
	`beaconIntervalSeconds` int NOT NULL DEFAULT 60,
	`calderaPaw` varchar(64),
	`sliverImplantId` varchar(64),
	`msfSessionId` varchar(64),
	`targetHostname` varchar(255),
	`targetIp` varchar(45),
	`targetNetwork` varchar(255),
	`agentPlatform` varchar(64),
	`agentArchitecture` varchar(32),
	`agentUsername` varchar(128),
	`agentPrivilege` enum('user','elevated') DEFAULT 'user',
	`agentExecutors` json,
	`agentPid` int,
	`requestedBy` int NOT NULL,
	`approvedBy` int,
	`approvedAt` bigint,
	`rejectionReason` text,
	`deployedAt` bigint,
	`lastHeartbeat` bigint,
	`terminatedAt` bigint,
	`createdAt` bigint NOT NULL,
	`updatedAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `agent_tasks` (
	`id` varchar(36) NOT NULL,
	`agentId` varchar(36) NOT NULL,
	`techniqueId` varchar(32),
	`techniqueName` varchar(255),
	`c2Source` enum('caldera','sliver','metasploit','native') NOT NULL,
	`commandEncrypted` text,
	`executor` varchar(32),
	`timeoutSeconds` int DEFAULT 300,
	`payloadName` varchar(255),
	`taskStatus` enum('queued','sent','executing','completed','failed','timeout','cancelled') DEFAULT 'queued',
	`outputEncrypted` text,
	`stderrEncrypted` text,
	`exitCode` int,
	`pid` int,
	`queuedAt` bigint NOT NULL,
	`sentAt` bigint,
	`startedAt` bigint,
	`completedAt` bigint,
	`assignedBy` int NOT NULL,
	`roeVerified` tinyint DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE `agentless_bas_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`abt_tenant_id` int,
	`abt_name` varchar(255) NOT NULL,
	`abt_type` enum('cloud_api','network_probe','email_payload','dns_exfil','http_c2_sim') NOT NULL,
	`abt_target_desc` text,
	`abt_technique_id` varchar(32),
	`abt_technique_name` varchar(255),
	`abt_status` enum('pending','running','completed','failed') NOT NULL DEFAULT 'pending',
	`abt_result` enum('blocked','detected','missed','error'),
	`abt_result_details` json,
	`abt_executed_at` timestamp,
	`abt_duration_ms` int,
	`abt_created_by` varchar(255),
	`abt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ai_attack_plans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`aap_tenant_id` int,
	`aap_name` varchar(255) NOT NULL,
	`aap_target_desc` text NOT NULL,
	`aap_threat_actor` varchar(255),
	`aap_env_context` json,
	`aap_generated_plan` json,
	`aap_attack_steps` json,
	`aap_risk_score` double,
	`aap_status` enum('generating','ready','executing','completed') NOT NULL DEFAULT 'generating',
	`aap_accepted_at` timestamp,
	`aap_created_by` varchar(255),
	`aap_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `api_endpoints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`target_id` int NOT NULL,
	`http_method` enum('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS') NOT NULL,
	`endpoint_path` varchar(1024) NOT NULL,
	`operation_id` varchar(255),
	`summary` text,
	`parameters` json,
	`request_body` json,
	`response_schemas` json,
	`auth_required` tinyint DEFAULT 0,
	`rate_limited` tinyint DEFAULT 0,
	`deprecated` tinyint DEFAULT 0,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `api_fuzzing_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`target_id` int NOT NULL,
	`engagement_id` int,
	`fuzz_type` enum('parameter_mutation','injection','auth_bypass','rate_limit','schema_violation') NOT NULL,
	`fuzz_status` enum('pending','running','completed','error') NOT NULL DEFAULT 'pending',
	`total_requests` int DEFAULT 0,
	`anomalies_found` int DEFAULT 0,
	`errors_found` int DEFAULT 0,
	`fuzz_config` json,
	`fuzz_results` json,
	`started_at` timestamp,
	`completed_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `api_security_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`api_test_name` varchar(255) NOT NULL,
	`owasp_category` enum('API1_BOLA','API2_BROKEN_AUTH','API3_OBJECT_PROPERTY','API4_UNRESTRICTED_CONSUMPTION','API5_BROKEN_FUNCTION_AUTH','API6_SERVER_SIDE_REQUEST_FORGERY','API7_SECURITY_MISCONFIGURATION','API8_LACK_OF_PROTECTION','API9_IMPROPER_INVENTORY','API10_UNSAFE_API_CONSUMPTION') NOT NULL,
	`api_test_description` text,
	`test_type` enum('automated','semi_automated','manual') DEFAULT 'automated',
	`test_payload` json,
	`expected_result` text,
	`api_test_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`is_builtin` tinyint DEFAULT 1,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `api_targets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`api_name` varchar(255) NOT NULL,
	`base_url` varchar(1024) NOT NULL,
	`spec_type` enum('openapi_3','openapi_2','swagger','graphql','grpc','manual') DEFAULT 'manual',
	`spec_url` varchar(1024),
	`spec_content` json,
	`auth_type` enum('none','api_key','bearer','basic','oauth2','custom') DEFAULT 'none',
	`auth_config` json,
	`total_endpoints` int DEFAULT 0,
	`api_status` enum('active','inactive','scanning') NOT NULL DEFAULT 'active',
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `api_test_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`endpoint_id` int NOT NULL,
	`test_id` int NOT NULL,
	`engagement_id` int,
	`test_result` enum('vulnerable','secure','error','inconclusive','skipped') NOT NULL DEFAULT 'inconclusive',
	`result_severity` enum('critical','high','medium','low','info'),
	`request_sent` json,
	`response_received` json,
	`api_evidence` json,
	`api_notes` text,
	`api_false_positive` tinyint DEFAULT 0,
	`executed_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `apt_ics_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`aim_apt_group_name` varchar(255) NOT NULL,
	`aim_aliases` json,
	`aim_attribution` varchar(128),
	`aim_targeted_vendors` json,
	`aim_targeted_protocols` json,
	`aim_targeted_device_types` json,
	`aim_targeted_sectors` json,
	`aim_targeted_countries` json,
	`aim_mitre_attack_ics_techniques` json,
	`aim_mitre_attack_enterprise_techniques` json,
	`aim_malware_tools` json,
	`aim_initial_access_methods` json,
	`aim_known_campaigns` json,
	`aim_threat_level` enum('critical','high','medium','low') DEFAULT 'medium',
	`aim_active_status` enum('active','dormant','disbanded','unknown') DEFAULT 'active',
	`aim_last_known_activity` varchar(255),
	`aim_description` text,
	`aim_references` json,
	`aim_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`aim_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `archetype_actor_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`archetypeId` int NOT NULL,
	`actorId` varchar(128) NOT NULL,
	`actorTechniques` json,
	`actorAbilities` json,
	`confidence` int DEFAULT 50,
	`evidence` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `atomic_test_executions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`atomic_test_id` int NOT NULL,
	`guid` varchar(64) NOT NULL,
	`technique_id` varchar(20) NOT NULL,
	`test_name` varchar(512) NOT NULL,
	`executed_by` varchar(64) NOT NULL,
	`target_host` varchar(255),
	`target_platform` varchar(64),
	`status` enum('queued','running','success','failed','blocked','cleanup') NOT NULL DEFAULT 'queued',
	`executor_type` varchar(64),
	`command_executed` text,
	`input_args` text,
	`stdout` text,
	`stderr` text,
	`exit_code` int,
	`detection_triggered` tinyint DEFAULT 0,
	`detection_details` text,
	`cleanup_ran` tinyint DEFAULT 0,
	`cleanup_output` text,
	`attack_chain_id` varchar(100),
	`caldera_operation_id` varchar(100),
	`duration_ms` int,
	`started_at` timestamp,
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `atomic_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`guid` varchar(64) NOT NULL,
	`technique_id` varchar(20) NOT NULL,
	`technique_name` varchar(512) NOT NULL,
	`test_name` varchar(512) NOT NULL,
	`description` text,
	`supported_platforms` varchar(128),
	`executor_type` varchar(64),
	`executor_command` text,
	`cleanup_command` text,
	`elevation_required` tinyint DEFAULT 0,
	`input_arguments` text,
	`dependencies` text,
	`mitre_tactic` varchar(255),
	`last_synced_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
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
	`acr_validated` tinyint DEFAULT 0,
	`acr_validation_result` json,
	`acr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `attack_path_graph_edges` (
	`id` int AUTO_INCREMENT NOT NULL,
	`apge_tenant_id` int,
	`apge_source_node_id` int NOT NULL,
	`apge_target_node_id` int NOT NULL,
	`apge_edge_type` varchar(128) NOT NULL,
	`apge_technique` varchar(32),
	`apge_probability` double,
	`apge_properties` json,
	`apge_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `attack_path_graph_nodes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`apgn_tenant_id` int,
	`apgn_type` enum('user','computer','group','service','cloud_identity','vulnerability','crown_jewel') NOT NULL,
	`apgn_name` varchar(512) NOT NULL,
	`apgn_properties` json,
	`apgn_risk_score` double,
	`apgn_is_crown_jewel` tinyint DEFAULT 0,
	`apgn_source` varchar(64),
	`apgn_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `attack_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pathId` varchar(64) NOT NULL,
	`engagementId` varchar(64),
	`name` varchar(255) NOT NULL,
	`description` text,
	`nodes` json,
	`edges` json,
	`riskScore` int,
	`status` varchar(50) DEFAULT 'draft',
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`atp_tenant_id` int
);
--> statement-breakpoint
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
	`status` enum('running','paused','completed','failed','aborted') NOT NULL DEFAULT 'running'
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
	`roe_compliant` tinyint DEFAULT 1,
	`status` enum('draft','approved','executing','completed','aborted') NOT NULL DEFAULT 'draft',
	`created_by` varchar(64),
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `attack_sequence_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`templateId` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`sourceIncidentIds` json,
	`sourceActors` json,
	`phases` json,
	`totalPhases` int,
	`attackType` varchar(64),
	`ast_complexity` enum('basic','intermediate','advanced','nation-state') DEFAULT 'intermediate',
	`targetEnvironment` varchar(128),
	`ast_targetSectors` json,
	`ast_calderaAbilities` json,
	`calderaAdversaryProfile` json,
	`detectionDifficulty` int,
	`commonDetections` json,
	`evasionTechniques` json,
	`avgDwellTime` varchar(64),
	`successRate` double,
	`useCount` int DEFAULT 0,
	`ast_confidence` int,
	`ast_status` enum('draft','validated','production') DEFAULT 'draft',
	`ast_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ast_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`created_at` bigint NOT NULL
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
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_correlations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`finding_id` int NOT NULL,
	`correlation_type` varchar(64) NOT NULL,
	`matched_entity_type` varchar(64) NOT NULL,
	`matched_entity_id` int NOT NULL,
	`matched_entity_name` varchar(512),
	`confidence_score` double,
	`details` json,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`program_id` int,
	`platform` varchar(32) NOT NULL,
	`external_id` varchar(128),
	`title` varchar(1024) NOT NULL,
	`severity_rating` varchar(32),
	`cve_ids` json,
	`cwe_id` varchar(32),
	`cwe_name` varchar(512),
	`substate` varchar(64),
	`report_url` varchar(1024),
	`disclosed_at` timestamp,
	`awarded_amount` double,
	`currency` varchar(16),
	`reporter_username` varchar(255),
	`reporter_reputation` int,
	`program_handle` varchar(255),
	`program_name` varchar(512),
	`asset_identifier` varchar(512),
	`asset_type` varchar(64),
	`votes` int,
	`summary` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_programs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`platform` varchar(32) NOT NULL,
	`handle` varchar(255) NOT NULL,
	`name` varchar(512) NOT NULL,
	`url` varchar(1024),
	`logo_url` varchar(1024),
	`state` varchar(64),
	`submission_state` varchar(64),
	`currency` varchar(16),
	`min_bounty` double,
	`max_bounty` double,
	`avg_bounty` double,
	`total_paid` double,
	`resolved_count` int,
	`hacker_count` int,
	`scope_assets` json,
	`policy_url` varchar(1024),
	`last_synced_at` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_sync_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`platform` varchar(32) NOT NULL,
	`sync_type` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL,
	`items_synced` int DEFAULT 0,
	`error_message` text,
	`started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `c2_servers` (
	`id` varchar(36) NOT NULL,
	`name` varchar(255) NOT NULL,
	`c2Type` enum('caldera','sliver','metasploit') NOT NULL,
	`baseUrl` varchar(512) NOT NULL,
	`authConfigEncrypted` text NOT NULL,
	`c2Status` enum('connected','disconnected','error') DEFAULT 'disconnected',
	`lastHealthCheck` bigint,
	`healthDetails` json,
	`version` varchar(64),
	`capabilities` json,
	`createdAt` bigint NOT NULL,
	`updatedAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `caldera_accounts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`email` varchar(255) NOT NULL,
	`password_hash` varchar(255) NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`account_role` enum('admin','operator','analyst','team_lead','executive','client','soc','viewer') NOT NULL DEFAULT 'viewer',
	`account_status` enum('active','invited','suspended','deactivated') NOT NULL DEFAULT 'invited',
	`last_login_at` timestamp,
	`invited_by` int,
	`invite_token` varchar(128),
	`invite_expires_at` timestamp,
	`password_reset_token` varchar(128),
	`password_reset_expires_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`totp_secret` varchar(255),
	`totp_enabled` tinyint NOT NULL DEFAULT 0,
	`backup_codes` text,
	`failed_login_attempts` int NOT NULL DEFAULT 0,
	`locked_until` timestamp
);
--> statement-breakpoint
CREATE TABLE `caldera_stats` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serverId` int NOT NULL,
	`totalAdversaries` int DEFAULT 0,
	`totalAbilities` int DEFAULT 0,
	`activeOperations` int DEFAULT 0,
	`totalAgents` int DEFAULT 0,
	`lastUpdated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `campaign_abilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaignId` int NOT NULL,
	`abilityId` varchar(255) NOT NULL,
	`abilityName` varchar(255) NOT NULL,
	`technique` varchar(32),
	`tactic` varchar(64),
	`description` text,
	`executionOrder` int DEFAULT 0,
	`status` enum('pending','running','completed','failed','skipped') NOT NULL DEFAULT 'pending',
	`executedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `campaign_agents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaignId` int NOT NULL,
	`agentName` varchar(255) NOT NULL,
	`agentPaw` varchar(64),
	`platform` varchar(64),
	`hostname` varchar(255),
	`status` enum('pending','deployed','active','inactive') NOT NULL DEFAULT 'pending',
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `campaign_archetypes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`slug` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`archetypeCategory` enum('saas_oauth_compromise','token_abuse','cloud_lateral_movement','supply_chain','credential_harvesting','ransomware_deployment','data_exfiltration','persistence_implant','custom') NOT NULL,
	`description` text,
	`killChainPhases` json,
	`defaultTechniques` json,
	`defaultAbilities` json,
	`targetPlatforms` json,
	`targetServices` json,
	`prerequisites` json,
	`detectionGuidance` text,
	`archetypeComplexity` enum('low','medium','high','expert') DEFAULT 'medium',
	`isBuiltIn` tinyint DEFAULT 1,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `campaign_engagements` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`gophishCampaignId` int NOT NULL,
	`gophishCampaignName` varchar(255),
	`calderaOperationId` varchar(255),
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`targetEnvironment` varchar(255),
	`adversaryId` varchar(255),
	`adversaryName` varchar(255),
	`status` enum('draft','ready','active','paused','completed') NOT NULL DEFAULT 'draft',
	`serverId` int,
	`createdBy` int,
	`startDate` timestamp,
	`endDate` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`cmp_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `carver_risk_cards` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain` varchar(512) NOT NULL,
	`scan_title` varchar(512),
	`domain_intel_scan_id` int,
	`inferred_sector` varchar(128),
	`sector_confidence` varchar(32),
	`naics_code` varchar(16),
	`naics_label` varchar(256),
	`industry` varchar(256),
	`regulatory_tags` json,
	`country` varchar(8),
	`carver_scores` json,
	`shock_scores` json,
	`hybrid_score` json,
	`priority_tier` varchar(8),
	`confidence_band` varchar(32),
	`top_drivers` json,
	`recommended_actions` json,
	`caldera_ops` json,
	`threat_likelihood` json,
	`fedramp_profile` varchar(32),
	`fips_199_category` json,
	`full_risk_card` json,
	`source` varchar(64) DEFAULT 'manual',
	`batch_id` varchar(128),
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `chain_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_id` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`progress` int NOT NULL DEFAULT 0,
	`current_stage` varchar(32),
	`cancelled` tinyint NOT NULL DEFAULT 0,
	`domains` json NOT NULL,
	`seed_ips` json,
	`seed_urls` json,
	`engagement_id` int,
	`operator_id` varchar(64),
	`skip_stages` json,
	`stage_config` json,
	`max_duration_sec` int DEFAULT 3600,
	`continue_on_partial_failure` tinyint DEFAULT 0,
	`total_findings` int DEFAULT 0,
	`total_subdomains` int DEFAULT 0,
	`total_hosts` int DEFAULT 0,
	`total_open_ports` int DEFAULT 0,
	`total_services` int DEFAULT 0,
	`total_vulnerabilities` int DEFAULT 0,
	`findings_by_severity` json,
	`findings_by_stage` json,
	`stages_completed` int DEFAULT 0,
	`stages_total` int DEFAULT 4,
	`stages_failed` int DEFAULT 0,
	`stages_skipped` int DEFAULT 0,
	`unique_cves` json,
	`attack_techniques` json,
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`duration_ms` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `chain_stage_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_id` varchar(64) NOT NULL,
	`stage_id` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`input_target_count` int DEFAULT 0,
	`output_count` int DEFAULT 0,
	`finding_count` int DEFAULT 0,
	`errors` json,
	`findings` json,
	`raw_output` mediumtext,
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `chat_messages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chat_msg_session_id` int NOT NULL,
	`chat_msg_role` enum('user','assistant','system','tool') NOT NULL,
	`chat_msg_content` text NOT NULL,
	`chat_msg_tool_name` varchar(128),
	`chat_msg_tool_result` json,
	`chat_msg_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `chat_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chat_session_user_id` int NOT NULL,
	`chat_session_title` varchar(255) DEFAULT 'New Chat',
	`chat_session_role` varchar(64) NOT NULL DEFAULT 'operator',
	`chat_session_message_count` int DEFAULT 0,
	`chat_session_last_message_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`chat_session_archived` tinyint DEFAULT 0,
	`chat_session_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`chat_session_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`cs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `cicd_pipelines` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cicd_tenant_id` int,
	`cicd_name` varchar(255) NOT NULL,
	`cicd_provider` enum('github_actions','jenkins','gitlab_ci','azure_devops','custom') NOT NULL,
	`cicd_webhook_url` varchar(512),
	`cicd_webhook_secret` text,
	`cicd_trigger` enum('push','pull_request','release','manual','schedule') NOT NULL DEFAULT 'manual',
	`cicd_validation_profile_id` int,
	`cicd_fail_threshold` double DEFAULT 7,
	`cicd_is_active` tinyint NOT NULL DEFAULT 1,
	`cicd_last_triggered` timestamp,
	`cicd_created_by` varchar(255),
	`cicd_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cicd_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cicd_run_pipeline_id` int NOT NULL,
	`cicd_run_tenant_id` int,
	`cicd_commit_sha` varchar(64),
	`cicd_branch` varchar(255),
	`cicd_run_status` enum('pending','running','passed','failed','error') NOT NULL DEFAULT 'pending',
	`cicd_total_tests` int DEFAULT 0,
	`cicd_passed_tests` int DEFAULT 0,
	`cicd_failed_tests` int DEFAULT 0,
	`cicd_risk_score` double,
	`cicd_report_url` varchar(512),
	`cicd_started_at` timestamp,
	`cicd_completed_at` timestamp,
	`cicd_run_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_attack_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int NOT NULL,
	`engagement_id` int,
	`path_name` varchar(255) NOT NULL,
	`attack_type` enum('privilege_escalation','role_chaining','cross_account','service_account_impersonation','org_policy_bypass','consent_grant_abuse','app_registration_abuse','pim_escalation','s3_public_access','storage_misconfiguration','iam_misconfiguration','lateral_movement','data_exfiltration') NOT NULL,
	`cloud_provider` enum('aws','azure','gcp') NOT NULL,
	`source_identity` varchar(512),
	`target_resource` varchar(512),
	`path_nodes` json,
	`risk_score` double,
	`severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`description` text,
	`mitre_techniques` json,
	`remediation_steps` json,
	`path_status` enum('open','exploited','mitigated','accepted') DEFAULT 'open',
	`exploited_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int,
	`engagement_id` int,
	`cred_provider` enum('aws','azure','gcp') NOT NULL,
	`credential_name` varchar(255) NOT NULL,
	`credential_type` enum('aws_access_key','aws_assume_role','aws_session_token','azure_client_secret','azure_managed_identity','azure_cli','gcp_service_account_key','gcp_workload_identity','gcp_oauth') NOT NULL,
	`encrypted_data` text NOT NULL,
	`encryption_iv` varchar(64) NOT NULL,
	`encryption_tag` varchar(64) NOT NULL,
	`cred_account_id` varchar(255),
	`cred_region` varchar(64),
	`role_arn` varchar(512),
	`external_id` varchar(255),
	`tenant_id` varchar(255),
	`subscription_id` varchar(255),
	`project_id` varchar(255),
	`cred_status` enum('active','expired','revoked','testing','error') NOT NULL DEFAULT 'active',
	`last_validated_at` timestamp,
	`last_used_at` timestamp,
	`expires_at` timestamp,
	`cred_created_by` varchar(255),
	`cred_created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`cred_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_enumeration_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`credential_id` int NOT NULL,
	`enum_provider_id` int,
	`enum_engagement_id` int,
	`enum_provider` enum('aws','azure','gcp') NOT NULL,
	`enum_status` enum('pending','running','completed','error','partial') NOT NULL DEFAULT 'pending',
	`enum_scope` json,
	`total_users_found` int DEFAULT 0,
	`total_roles_found` int DEFAULT 0,
	`total_policies_found` int DEFAULT 0,
	`total_groups_found` int DEFAULT 0,
	`total_service_accounts_found` int DEFAULT 0,
	`total_misconfigs_found` int DEFAULT 0,
	`enum_results` json,
	`enum_error_log` json,
	`enum_started_at` timestamp,
	`enum_completed_at` timestamp,
	`enum_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_identities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int NOT NULL,
	`identity_type` enum('user','role','service_account','group','app_registration') NOT NULL,
	`arn` varchar(512),
	`name` varchar(255) NOT NULL,
	`email` varchar(320),
	`is_privileged` tinyint DEFAULT 0,
	`last_activity` timestamp,
	`permissions` json,
	`policies` json,
	`metadata` json,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_misconfigurations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int NOT NULL,
	`resource_type` varchar(128) NOT NULL,
	`resource_arn` varchar(512),
	`resource_name` varchar(255),
	`misconfig_type` varchar(128) NOT NULL,
	`misconfig_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`description` text,
	`current_value` text,
	`expected_value` text,
	`remediation_steps` text,
	`compliance_frameworks` json,
	`misconfig_status` enum('open','remediated','accepted','false_positive') DEFAULT 'open',
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `cloud_providers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`provider` enum('aws','azure','gcp') NOT NULL,
	`account_id` varchar(255) NOT NULL,
	`account_alias` varchar(255),
	`region` varchar(64),
	`status` enum('active','inactive','scanning') NOT NULL DEFAULT 'active',
	`last_scan_at` timestamp,
	`config` json,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
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
	`triggered_by` varchar(255) DEFAULT 'manual'
);
--> statement-breakpoint
CREATE TABLE `collection_schedules` (
	`id` varchar(36) NOT NULL,
	`source_type` varchar(50) NOT NULL,
	`display_name` varchar(200) NOT NULL,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`cadence` enum('hourly','every_6h','every_12h','daily','weekly') NOT NULL DEFAULT 'daily',
	`last_run_at` bigint,
	`next_run_at` bigint,
	`last_status` enum('success','failure','running','never_run') NOT NULL DEFAULT 'never_run',
	`last_error` text,
	`last_evidence_count` int DEFAULT 0,
	`total_runs` int DEFAULT 0,
	`total_evidence_collected` int DEFAULT 0,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `compliance_controls` (
	`id` int AUTO_INCREMENT NOT NULL,
	`framework_id` int NOT NULL,
	`control_id` varchar(64) NOT NULL,
	`control_name` varchar(512) NOT NULL,
	`control_description` text,
	`parent_control_id` varchar(64),
	`category` varchar(255),
	`subcategory` varchar(255),
	`implementation_guidance` text,
	`test_procedures` json,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `compliance_frameworks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`framework_name` varchar(128) NOT NULL,
	`framework_version` varchar(32),
	`framework_type` enum('soc2','iso27001','nist_csf','pci_dss','hipaa','cis','fedramp','dod_stig','cmmc','custom') NOT NULL,
	`description` text,
	`total_controls` int,
	`control_hierarchy` json,
	`is_active` tinyint DEFAULT 1,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `compliance_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`control_id` int NOT NULL,
	`engagement_id` int,
	`finding_type` varchar(128),
	`finding_id` int,
	`finding_source` enum('vulnerability','misconfiguration','attack_path','edr_test','pentest','manual') NOT NULL,
	`mapping_status` enum('covered','gap','partial','not_applicable','compensating') NOT NULL DEFAULT 'gap',
	`evidence_notes` text,
	`compensating_control` text,
	`risk_acceptance` text,
	`assessed_by` varchar(255),
	`assessed_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `compliance_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`framework_id` int NOT NULL,
	`report_name` varchar(255) NOT NULL,
	`total_controls` int DEFAULT 0,
	`covered_controls` int DEFAULT 0,
	`gap_controls` int DEFAULT 0,
	`partial_controls` int DEFAULT 0,
	`na_controls` int DEFAULT 0,
	`overall_score` double,
	`report_data` json,
	`generated_by` varchar(255),
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
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
	`enabled` tinyint NOT NULL DEFAULT 1,
	`cbr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	`cda_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	`drift_detected` tinyint DEFAULT 0,
	`target_name` varchar(255),
	`target_type` varchar(64),
	`scanned_by` int,
	`scanned_by_name` varchar(255),
	`scanned_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `container_image_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`registry_id` int NOT NULL,
	`engagement_id` int,
	`user_id` int NOT NULL,
	`repository` varchar(512) NOT NULL,
	`tag` varchar(255) NOT NULL,
	`digest` varchar(128),
	`image_size` bigint,
	`architecture` varchar(32),
	`os` varchar(32),
	`scan_status` enum('queued','pulling','scanning','complete','error') NOT NULL DEFAULT 'queued',
	`total_vulnerabilities` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`negligible_count` int DEFAULT 0,
	`fixed_available` int DEFAULT 0,
	`vulnerabilities` json,
	`packages` json,
	`base_image` varchar(512),
	`layers` json,
	`compliance_issues` json,
	`malware_detected` tinyint DEFAULT 0,
	`secrets_detected` int DEFAULT 0,
	`scan_duration_ms` int,
	`scan_engine` varchar(64) DEFAULT 'built-in',
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `container_registries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`engagement_id` int,
	`registry_type` enum('docker_hub','ecr','acr','gcr','harbor','artifactory','nexus','gitlab','ghcr','quay','custom') NOT NULL,
	`name` varchar(255) NOT NULL,
	`registry_url` varchar(512) NOT NULL,
	`auth_config` text NOT NULL,
	`registry_status` enum('active','inactive','error','pending_validation') NOT NULL DEFAULT 'pending_validation',
	`last_validated` timestamp,
	`last_error` text,
	`repo_count` int DEFAULT 0,
	`image_count` int DEFAULT 0,
	`last_sync_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `corroboration_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cr_import_id` int NOT NULL,
	`cr_finding_id` int NOT NULL,
	`cr_original_confidence` int NOT NULL,
	`cr_adjusted_confidence` int NOT NULL,
	`cr_corroborating_count` int DEFAULT 0,
	`cr_contradicting_count` int DEFAULT 0,
	`cr_corroborating_sources` text,
	`cr_contradicting_sources` text,
	`cr_verdict` varchar(32) NOT NULL,
	`cr_reasoning` text,
	`cr_suppress_recommendation` tinyint DEFAULT 0,
	`cr_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `credential_alert_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alert_rule_id` int NOT NULL,
	`alert_hist_credential_id` int NOT NULL,
	`alert_type` enum('expiring_soon','expired','rotation_due','validation_failed') NOT NULL,
	`alert_severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`alert_message` text NOT NULL,
	`notification_sent` tinyint NOT NULL DEFAULT 0,
	`notification_result` varchar(255),
	`alert_acknowledged_at` timestamp,
	`alert_acknowledged_by` varchar(255),
	`alert_cred_provider` varchar(32),
	`alert_cred_name` varchar(255),
	`alert_expires_at` timestamp,
	`days_until_expiry` int,
	`alert_hist_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `credential_alert_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cred_alert_credential_id` int NOT NULL,
	`alert_name` varchar(255) NOT NULL,
	`threshold_days` int NOT NULL DEFAULT 30,
	`alert_is_enabled` tinyint NOT NULL DEFAULT 1,
	`alert_notify_owner` tinyint NOT NULL DEFAULT 1,
	`alert_last_checked_at` timestamp,
	`alert_last_alerted_at` timestamp,
	`alert_next_alert_at` timestamp,
	`alert_created_by` varchar(255),
	`alert_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `credential_attack_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`target_host` varchar(512) NOT NULL,
	`target_port` int NOT NULL,
	`protocol` varchar(32) NOT NULL,
	`attack_mode` enum('brute_force','password_spray','credential_stuffing','default_credentials','dictionary') NOT NULL,
	`status` enum('running','completed','stopped','error') NOT NULL DEFAULT 'running',
	`total_attempts` int DEFAULT 0,
	`successful_attempts` int DEFAULT 0,
	`lockouts_detected` int DEFAULT 0,
	`rate_limit_hits` int DEFAULT 0,
	`password_list_used` varchar(128),
	`username_list_used` varchar(128),
	`duration_ms` int,
	`config` json,
	`error_message` text,
	`domain_intel_scan_id` int,
	`started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`tool` varchar(32) DEFAULT 'builtin',
	`tool_version` varchar(64),
	`raw_output` mediumtext,
	`tool_metadata` json,
	`target_domain` varchar(255),
	`failed_attempts` int DEFAULT 0,
	`stopped_reason` varchar(255)
);
--> statement-breakpoint
CREATE TABLE `credential_exposures` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ce_source` varchar(128) NOT NULL,
	`ce_breach_name` varchar(512) NOT NULL,
	`ce_breach_date` timestamp,
	`ce_domain` varchar(512),
	`ce_email_count` int DEFAULT 0,
	`ce_total_records` int DEFAULT 0,
	`ce_data_classes` json,
	`ce_actor_name` varchar(255),
	`ce_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`ce_is_verified` tinyint DEFAULT 0,
	`ce_is_sensitive` tinyint DEFAULT 0,
	`ce_is_retired` tinyint DEFAULT 0,
	`ce_is_spam_list` tinyint DEFAULT 0,
	`ce_source_url` varchar(1024),
	`ce_description` text,
	`ce_tags` json,
	`ce_raw_data` json,
	`ce_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ce_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ce_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `credential_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`attack_run_id` int NOT NULL,
	`user_id` int NOT NULL,
	`target_host` varchar(512) NOT NULL,
	`target_port` int NOT NULL,
	`protocol` varchar(32) NOT NULL,
	`username` varchar(256) NOT NULL,
	`password` varchar(256) NOT NULL,
	`is_default` tinyint DEFAULT 0,
	`vendor` varchar(128),
	`product` varchar(128),
	`access_level` enum('admin','user','read_only','unknown') DEFAULT 'unknown',
	`response_code` int,
	`response_time_ms` int,
	`banner_info` text,
	`verified` tinyint DEFAULT 0,
	`domain_intel_scan_id` int,
	`notes` text,
	`discovered_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`tool` varchar(32) DEFAULT 'builtin',
	`response_snippet` text,
	`additional_info` text,
	`validation_status` varchar(32) DEFAULT 'unvalidated'
);
--> statement-breakpoint
CREATE TABLE `credential_rotation_audit` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rotation_audit_policy_id` int NOT NULL,
	`rotation_audit_credential_id` int NOT NULL,
	`rotation_audit_provider` enum('aws','azure','gcp') NOT NULL,
	`rotation_status` enum('pending','in_progress','success','failed','rollback') NOT NULL,
	`old_key_identifier` varchar(255),
	`new_key_identifier` varchar(255),
	`rotation_error_message` text,
	`rotation_duration_ms` int NOT NULL DEFAULT 0,
	`rotation_initiated_by` varchar(255) NOT NULL,
	`rotation_audit_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `credential_rotation_policies` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rotation_credential_id` int NOT NULL,
	`rotation_provider` enum('aws','azure','gcp') NOT NULL,
	`rotation_cred_name` varchar(255) NOT NULL,
	`rotation_enabled` tinyint NOT NULL DEFAULT 0,
	`rotation_interval_days` int NOT NULL DEFAULT 90,
	`last_rotated_at` timestamp,
	`next_rotation_at` timestamp,
	`rotation_max_retries` int NOT NULL DEFAULT 3,
	`rotation_retry_count` int NOT NULL DEFAULT 0,
	`rotation_created_by` varchar(255),
	`rotation_policy_created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`rotation_policy_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `darkweb_enriched_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`der_source_event_id` int,
	`der_source_table` varchar(128),
	`der_summary` text,
	`der_threat_assessment` text,
	`der_risk_score` int DEFAULT 0,
	`der_impact_analysis` text,
	`der_recommended_actions` json,
	`der_related_actors` json,
	`der_related_campaigns` json,
	`der_related_cves` json,
	`der_related_iocs` json,
	`der_mitre_tactics` json,
	`der_mitre_techniques` json,
	`der_affected_sectors` json,
	`der_affected_countries` json,
	`der_enrichment_model` varchar(128),
	`der_enrichment_version` varchar(32),
	`der_processing_time_ms` int,
	`der_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`der_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `darkweb_feed_registry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`dfr_feed_name` varchar(255) NOT NULL,
	`dfr_feed_url` varchar(1024) NOT NULL,
	`dfr_feed_type` enum('ioc','malware','ransomware','credential','phishing','botnet','c2','blocklist','vulnerability','influence','other') NOT NULL,
	`dfr_provider` varchar(255),
	`dfr_description` text,
	`dfr_requires_auth` tinyint DEFAULT 0,
	`dfr_auth_type` enum('none','api_key','bearer','basic','custom') DEFAULT 'none',
	`dfr_auth_env_var` varchar(128),
	`dfr_sync_interval` varchar(32) DEFAULT 'daily',
	`dfr_last_sync_at` timestamp,
	`dfr_next_sync_at` timestamp,
	`dfr_status` enum('active','degraded','down','disabled','pending') DEFAULT 'pending',
	`dfr_last_error` text,
	`dfr_consecutive_failures` int DEFAULT 0,
	`dfr_total_syncs` int DEFAULT 0,
	`dfr_total_records_fetched` int DEFAULT 0,
	`dfr_avg_response_time_ms` int,
	`dfr_is_built_in` tinyint DEFAULT 1,
	`dfr_enabled` tinyint DEFAULT 1,
	`dfr_config` json,
	`dfr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`dfr_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `defense_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`score_id` varchar(64) NOT NULL,
	`organization_name` varchar(255) NOT NULL,
	`threat_actor_id` int,
	`threat_actor_name` varchar(255),
	`overall_score` int,
	`detection_score` int,
	`vulnerability_score` int,
	`surface_score` int,
	`response_score` int,
	`breakdown` json,
	`recommendations` json,
	`engagement_id` varchar(128),
	`created_by` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`dfs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `detection_feedback_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`dfr_tenant_id` int,
	`dfr_siem_id` int NOT NULL,
	`dfr_technique_id` varchar(32) NOT NULL,
	`dfr_technique_name` varchar(255),
	`dfr_campaign_id` int,
	`dfr_executed_at` timestamp NOT NULL,
	`dfr_query_window_sec` int NOT NULL DEFAULT 300,
	`dfr_alerts_found` int NOT NULL DEFAULT 0,
	`dfr_result` enum('detected','missed','partial','error') NOT NULL,
	`dfr_alert_details` json,
	`dfr_query_used` text,
	`dfr_latency_ms` int,
	`dfr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `detection_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`testId` varchar(64) NOT NULL,
	`engagementId` varchar(64),
	`techniqueId` varchar(32) NOT NULL,
	`techniqueName` varchar(255),
	`tactic` varchar(100),
	`abilityId` varchar(64),
	`abilityName` varchar(255),
	`executedAt` timestamp,
	`executionResult` varchar(50) DEFAULT 'pending',
	`detected` tinyint DEFAULT 0,
	`detectionTime` int,
	`detectionSource` varchar(255),
	`detectionRule` varchar(500),
	`alertSeverity` varchar(50),
	`isGap` tinyint DEFAULT 0,
	`gapSeverity` varchar(50),
	`recommendation` text,
	`mitigationStatus` varchar(50) DEFAULT 'open',
	`notes` text,
	`evidence` json,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`blueTeamOutcome` varchar(32) DEFAULT 'not_tested',
	`blueTeamNotes` text,
	`blueTeamAnalyst` varchar(255),
	`detectionMethod` varchar(128),
	`responseAction` varchar(128),
	`timeToDetect` int,
	`timeToRespond` int,
	`blueTeamUpdatedAt` timestamp
);
--> statement-breakpoint
CREATE TABLE `discovered_assets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`assetId` varchar(128),
	`hostname` varchar(255) NOT NULL,
	`url` text,
	`assetType` varchar(64),
	`dnsRecords` json,
	`dnsStatus` varchar(32),
	`headers` text,
	`technologies` json,
	`assetClasses` json,
	`tags` json,
	`carverScores` json,
	`shockScores` json,
	`missionImpactScore` int,
	`suggestedTier` varchar(32),
	`hybridRiskScore` int,
	`riskBand` varchar(32),
	`cvssEstimate` int,
	`contextIndicators` json,
	`postureFindings` json,
	`testVectors` json,
	`recommendedCalderaAbilities` json,
	`recommendedGophishTemplates` json,
	`recommendedAttackChain` json,
	`confidence` int,
	`confidenceExplanation` json,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`excluded` tinyint NOT NULL DEFAULT 0,
	`exclusionReason` varchar(512),
	`excludedAt` timestamp,
	`impactScore` int,
	`likelihoodScore` int,
	`assetCriticalityScore` int,
	`assetCriticalityBand` varchar(32),
	`vulnRiskScore` int,
	`vulnRiskBand` varchar(32),
	`missionFunction` varchar(128),
	`essentialService` varchar(128),
	`assetPurpose` text,
	`businessImpactLevel` varchar(32),
	`missionDependencies` json,
	`llmClassification` json,
	`scoringVersion` int DEFAULT 1,
	`lastScoredAt` timestamp,
	`scoringProfileId` int,
	`cvssV4Vector` varchar(512),
	`fips199Category` json,
	`criticalityTier` int,
	`deviceType` varchar(64),
	`platformType` varchar(64),
	`da_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `discovered_attack_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`dap_tenant_id` int,
	`dap_name` varchar(512),
	`dap_path_nodes` json NOT NULL,
	`dap_path_edges` json NOT NULL,
	`dap_total_hops` int NOT NULL,
	`dap_risk_score` double NOT NULL,
	`dap_crown_jewel` varchar(255),
	`dap_choke_points` json,
	`dap_status` enum('active','mitigated','accepted') NOT NULL DEFAULT 'active',
	`dap_discovered_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `domain_intel_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int,
	`primaryDomain` varchar(255) NOT NULL,
	`additionalDomains` json,
	`clientType` enum('msp','enterprise','saas','paas','iaas','mixed_hosting','other') NOT NULL DEFAULT 'enterprise',
	`sector` varchar(128),
	`criticalFunctions` json,
	`complianceFlags` json,
	`notes` text,
	`orgProfile` json,
	`status` enum('pending','passive_recon','discovering','analyzing','scoring','recommending','scan_complete','completed','failed') NOT NULL DEFAULT 'pending',
	`totalAssets` int DEFAULT 0,
	`totalFindings` int DEFAULT 0,
	`overallRiskScore` int,
	`overallRiskBand` varchar(32),
	`executiveSummary` text,
	`threatModelSummary` text,
	`campaignRecommendations` json,
	`pipelineOutput` json,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`confirmedFindings` int DEFAULT 0,
	`probableFindings` int DEFAULT 0,
	`potentialFindings` int DEFAULT 0,
	`discoveryCoverageScore` int DEFAULT 0,
	`discoveryCoverageBand` varchar(32)
);
--> statement-breakpoint
CREATE TABLE `domain_recon` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`mxRecords` json,
	`spfRecord` text,
	`dmarcRecord` text,
	`dkimSelector` text,
	`nsRecords` json,
	`aRecords` json,
	`spoofable` tinyint DEFAULT 0,
	`spoofScore` int DEFAULT 0,
	`spoofAnalysis` text,
	`subdomains` json,
	`whoisData` json,
	`techStack` json,
	`breachData` json,
	`discoveredEmails` json,
	`scanStatus` enum('pending','running','completed','failed') NOT NULL DEFAULT 'pending',
	`scanStartedAt` timestamp,
	`scanCompletedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `edr_coverage_matrix` (
	`id` int AUTO_INCREMENT NOT NULL,
	`edr_product_id` int NOT NULL,
	`mitre_tactic_id` varchar(32) NOT NULL,
	`mitre_technique_id` varchar(32) NOT NULL,
	`total_tests` int DEFAULT 0,
	`detected` int DEFAULT 0,
	`missed` int DEFAULT 0,
	`partial` int DEFAULT 0,
	`blocked` int DEFAULT 0,
	`avg_detection_time_ms` int,
	`coverage_score` double,
	`last_tested_at` timestamp,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `edr_products` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`product_name` varchar(255) NOT NULL,
	`vendor` varchar(255) NOT NULL,
	`version` varchar(64),
	`deployment_type` enum('endpoint','network','cloud','hybrid') DEFAULT 'endpoint',
	`agent_count` int,
	`config` json,
	`edr_status` enum('active','inactive','testing') NOT NULL DEFAULT 'active',
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `edr_test_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`test_name` varchar(255) NOT NULL,
	`test_category` enum('process_injection','credential_access','defense_evasion','lateral_movement','persistence','privilege_escalation','command_and_control','exfiltration','execution','discovery','collection','impact') NOT NULL,
	`mitre_technique_id` varchar(32),
	`mitre_technique_name` varchar(255),
	`description` text,
	`binary_type` enum('safe_mimikatz','safe_injection','safe_dump','safe_lateral','safe_persist','safe_c2','safe_exfil','custom') DEFAULT 'custom',
	`test_payload` json,
	`expected_behavior` text,
	`test_risk` enum('safe','low','medium','high') DEFAULT 'safe',
	`is_builtin` tinyint DEFAULT 1,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `edr_test_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`edr_product_id` int NOT NULL,
	`test_catalog_id` int NOT NULL,
	`engagement_id` int,
	`execution_status` enum('pending','running','completed','error') NOT NULL DEFAULT 'pending',
	`detection_result` enum('detected','missed','partial','delayed','blocked'),
	`detection_time_ms` int,
	`alert_severity` varchar(32),
	`alert_title` varchar(512),
	`response_action` varchar(255),
	`false_positive` tinyint DEFAULT 0,
	`evidence` json,
	`notes` text,
	`executed_at` timestamp,
	`detected_at` timestamp,
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `email_security_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`est_tenant_id` int,
	`est_name` varchar(255) NOT NULL,
	`est_gateway` enum('proofpoint','mimecast','defender','barracuda','custom') NOT NULL,
	`est_target_email` varchar(320) NOT NULL,
	`est_payload_type` enum('phishing_link','malware_attachment','credential_harvest','bec_impersonation','macro_doc') NOT NULL,
	`est_status` enum('pending','sent','delivered','blocked','quarantined','error') NOT NULL DEFAULT 'pending',
	`est_delivery_result` enum('blocked','quarantined','delivered','unknown'),
	`est_gateway_response` text,
	`est_sent_at` timestamp,
	`est_result_received_at` timestamp,
	`est_created_by` varchar(255),
	`est_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `emulation_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`actorId` varchar(128),
	`actorName` varchar(255),
	`status` enum('draft','ready','deployed','archived') NOT NULL DEFAULT 'draft',
	`difficulty` enum('basic','intermediate','advanced','expert') DEFAULT 'intermediate',
	`estimatedDuration` int,
	`targetPlatforms` json,
	`phases` json,
	`tacticsUsed` json,
	`techniquesUsed` json,
	`totalAbilities` int DEFAULT 0,
	`calderaAdversaryId` varchar(128),
	`calderaDeployedAt` timestamp,
	`tags` json,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_ops_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`state_json` json NOT NULL,
	`phase` varchar(64),
	`is_running` tinyint DEFAULT 0,
	`asset_count` int DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_pipelines` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`pipelineName` varchar(255) NOT NULL,
	`pipelineStatus` enum('pending','intel_scan','risk_scoring','campaign_design','caldera_setup','gophish_setup','ready','running','completed','failed') NOT NULL DEFAULT 'pending',
	`targetDomains` json,
	`pipelineClientType` varchar(64),
	`orgProfile` json,
	`intelScanId` int,
	`riskSummary` json,
	`recommendedActors` json,
	`calderaOperationId` varchar(128),
	`calderaAdversaryId` varchar(128),
	`calderaAbilitiesDeployed` int,
	`gophishCampaignId` int,
	`gophishTemplateId` int,
	`gophishLandingPageId` int,
	`engagementId` int,
	`currentStep` int DEFAULT 0,
	`totalSteps` int DEFAULT 6,
	`stepLog` json,
	`errorMessage` text,
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`reportType` enum('executive_summary','technical_detail','compliance','phishing_results','osint_assessment','full_engagement','purple_team','red_team_assessment','detection_gap_analysis') NOT NULL,
	`clientType` enum('msp','enterprise','saas','paas','iaas','mixed_hosting','other') NOT NULL DEFAULT 'enterprise',
	`title` varchar(512) NOT NULL,
	`preparedFor` varchar(255),
	`preparedBy` varchar(255),
	`includeSections` json,
	`reportUrl` text,
	`reportKey` varchar(512),
	`status` enum('pending','generating','completed','failed') NOT NULL DEFAULT 'pending',
	`generatedAt` timestamp,
	`brandingLogo` text,
	`brandingColor` varchar(32),
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_shares` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`token` varchar(64) NOT NULL,
	`expiresAt` timestamp,
	`accessPassword` varchar(255),
	`maxViews` int,
	`viewCount` int NOT NULL DEFAULT 0,
	`isActive` tinyint NOT NULL DEFAULT 1,
	`includeSections` json,
	`includeFindings` tinyint NOT NULL DEFAULT 1,
	`includeRiskScores` tinyint NOT NULL DEFAULT 1,
	`includeRecommendations` tinyint NOT NULL DEFAULT 1,
	`includeExecutiveSummary` tinyint NOT NULL DEFAULT 1,
	`includeAssets` tinyint NOT NULL DEFAULT 1,
	`includeCompliance` tinyint NOT NULL DEFAULT 0,
	`clientName` varchar(255),
	`clientLogo` text,
	`brandingColor` varchar(32),
	`customMessage` text,
	`createdBy` int,
	`lastAccessedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_timeline_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`phase` varchar(64) NOT NULL,
	`event_type` enum('phase_started','phase_completed','finding_discovered','exploit_attempted','exploit_succeeded','shell_obtained','credential_found','pivot_established','data_collected','data_exfiltrated','opsec_alert','note_added','handoff_triggered','objective_completed','tool_executed','scan_completed') NOT NULL,
	`severity` enum('info','low','medium','high','critical') DEFAULT 'info',
	`title` varchar(512) NOT NULL,
	`description` text,
	`metadata` json,
	`source_module` varchar(128),
	`source_id` varchar(128),
	`target_host` varchar(256),
	`target_port` int,
	`attack_technique` varchar(64),
	`operator_id` int,
	`timestamp` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_workflow_states` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`current_phase` enum('pre_engagement','reconnaissance','threat_modeling','vulnerability_analysis','exploitation','post_exploitation','lateral_movement','collection_exfiltration','reporting','completed') NOT NULL DEFAULT 'pre_engagement',
	`phase_progress` json,
	`phase_started_at` json,
	`phase_completed_at` json,
	`auto_handoff_enabled` tinyint DEFAULT 1,
	`handoff_rules` json,
	`objectives_completed` json,
	`objectives_total` json,
	`overall_progress` int DEFAULT 0,
	`notes` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagements` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`customerName` varchar(255) NOT NULL,
	`description` text,
	`engagementType` enum('red_team','phishing','pentest','purple_team','tabletop') NOT NULL DEFAULT 'red_team',
	`status` enum('planning','active','paused','completed','archived') NOT NULL DEFAULT 'planning',
	`startDate` timestamp,
	`endDate` timestamp,
	`targetDomain` varchar(255),
	`targetIpRange` varchar(255),
	`phishingDomain` varchar(255),
	`calderaOperationId` varchar(255),
	`calderaAdversaryId` varchar(255),
	`gophishCampaignId` int,
	`notes` text,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`roe_status` enum('none','pending','signed','expired') NOT NULL DEFAULT 'none',
	`roe_signed_date` timestamp,
	`roe_expiry_date` timestamp,
	`roe_document_url` text,
	`roe_scope` json,
	`roe_signer_name` varchar(255),
	`roe_signer_email` varchar(320),
	`roe_document_id` int,
	`eng_tenant_id` int,
	`scan_mode` enum('strict_passive','standard','active') DEFAULT 'strict_passive'
);
--> statement-breakpoint
CREATE TABLE `error_incidents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`incidentId` varchar(64),
	`scope` varchar(128) DEFAULT 'global',
	`errorName` varchar(255),
	`errorMessage` text,
	`errorStack` text,
	`componentStack` text,
	`url` varchar(2048),
	`userAgent` varchar(1024),
	`timestamp` varchar(64),
	`viewportWidth` int,
	`viewportHeight` int,
	`createdAt` bigint
);
--> statement-breakpoint
CREATE TABLE `evasion_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaign_id` varchar(255),
	`session_type` enum('mutation_test','pipeline_config','scorecard','purple_cycle') NOT NULL,
	`techniques` json,
	`evasion_profile` enum('none','low','medium','high') DEFAULT 'none',
	`stealth_score` int,
	`stealth_band` varchar(20),
	`detection_coverage` int,
	`evasion_success_rate` int,
	`scorecard_data` json,
	`mutation_data` json,
	`pipeline_data` json,
	`purple_cycle_data` json,
	`total_techniques` int,
	`detected_count` int,
	`evaded_count` int,
	`partial_count` int,
	`untested_count` int,
	`total_rules` int,
	`robust_rules` int,
	`fragile_rules` int,
	`critical_gaps` int,
	`status` enum('running','completed','failed') NOT NULL DEFAULT 'running',
	`error_message` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp,
	`evs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `evidence_chain_of_custody` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidenceId` varchar(64) NOT NULL,
	`action` varchar(50) NOT NULL,
	`performedBy` varchar(255) NOT NULL,
	`performedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`details` text,
	`ipAddress` varchar(45),
	`userAgent` varchar(500),
	`integrityHash` varchar(64),
	`previousHash` varchar(64)
);
--> statement-breakpoint
CREATE TABLE `evidence_items` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidenceId` varchar(64) NOT NULL,
	`engagementId` varchar(64),
	`operationId` varchar(64),
	`title` varchar(500) NOT NULL,
	`description` text,
	`type` varchar(50) NOT NULL DEFAULT 'screenshot',
	`category` varchar(50) DEFAULT 'general',
	`fileUrl` text,
	`fileKey` varchar(500),
	`fileName` varchar(500),
	`fileSize` int,
	`mimeType` varchar(100),
	`sha256Hash` varchar(64),
	`md5Hash` varchar(32),
	`tags` json,
	`metadata` json,
	`classification` varchar(50) DEFAULT 'confidential',
	`collectedBy` varchar(255),
	`collectedAt` timestamp,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`evi_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `exploit_feedback_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`efr_exploit_module` varchar(512) NOT NULL,
	`efr_target` varchar(255) NOT NULL,
	`efr_port` int,
	`efr_service` varchar(128),
	`efr_cve_id` varchar(32),
	`efr_success` tinyint NOT NULL,
	`efr_duration_ms` int,
	`efr_error_type` varchar(128),
	`efr_error_message` text,
	`efr_output` text,
	`efr_os_type` varchar(64),
	`efr_os_version` varchar(128),
	`efr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_ingestion_jobs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eij_source` enum('exploitdb','metasploit','github_poc','nuclei_template','mixed') NOT NULL,
	`eij_query` varchar(512),
	`eij_scope` enum('single_cve','cve_batch','module_path','keyword_search','full_sync') NOT NULL,
	`eij_status` enum('pending','running','completed','partial','failed') NOT NULL DEFAULT 'pending',
	`eij_total_found` int DEFAULT 0,
	`eij_total_ingested` int DEFAULT 0,
	`eij_total_skipped` int DEFAULT 0,
	`eij_total_errors` int DEFAULT 0,
	`eij_error_log` json,
	`eij_script_ids` json,
	`eij_caldera_generated` int DEFAULT 0,
	`eij_triggered_by` varchar(255),
	`eij_started_at` timestamp,
	`eij_completed_at` timestamp,
	`eij_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_intelligence` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cveId` varchar(32) NOT NULL,
	`exploitType` varchar(64),
	`targetProduct` varchar(255),
	`targetVersion` varchar(128),
	`weaponized` tinyint DEFAULT 0,
	`publicExploitUrl` text,
	`metasploitModule` varchar(255),
	`nucleiTemplate` varchar(255),
	`usedByActors` json,
	`usedInIncidents` json,
	`firstExploitedInWild` varchar(64),
	`attackPhase` varchar(64),
	`ei_prerequisites` json,
	`postExploitActions` json,
	`cvssScore` double,
	`epssScore` double,
	`cisaKev` tinyint DEFAULT 0,
	`ei_source` varchar(64),
	`ei_confidence` int,
	`ei_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ei_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_jobs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`msfServerId` int NOT NULL,
	`targetIp` varchar(45) NOT NULL,
	`targetPort` int,
	`targetDomain` varchar(255),
	`exploitScanId` int,
	`exploitModule` varchar(512) NOT NULL,
	`payloadModule` varchar(512),
	`exploitCveId` varchar(32),
	`exploitOptions` json,
	`calderaStagerUrl` text,
	`calderaAgentPaw` varchar(64),
	`exploitJobStatus` enum('pending','approved','running','success','failed','aborted','timeout') NOT NULL DEFAULT 'pending',
	`msfJobId` int,
	`msfSessionId` int,
	`sessionType` varchar(32),
	`exploitResult` text,
	`exploitErrorMessage` text,
	`exploitStartedAt` timestamp,
	`exploitCompletedAt` timestamp,
	`approvedBy` varchar(255),
	`approvedAt` timestamp,
	`scopeVerified` tinyint DEFAULT 0,
	`exploitJobCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`exploitJobUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_plan_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`gate_id` varchar(64) NOT NULL,
	`plan_status` enum('approved','rejected','modified') NOT NULL,
	`operator_id` int,
	`operator_name` varchar(255),
	`original_plan` json NOT NULL,
	`modified_plan` json,
	`llm_reasoning` text,
	`llm_decision` text,
	`original_target_count` int NOT NULL DEFAULT 0,
	`final_target_count` int NOT NULL DEFAULT 0,
	`removed_targets` json,
	`review_duration_ms` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`resolved_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `exploit_preflight_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eph_exploit_module` varchar(512) NOT NULL,
	`eph_target` varchar(255) NOT NULL,
	`eph_port` int,
	`eph_service` varchar(128),
	`eph_success` tinyint NOT NULL,
	`eph_duration_ms` int,
	`eph_error_type` varchar(128),
	`eph_preflight_score` double,
	`eph_preflight_factors` json,
	`eph_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_scripts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`es_source_type` enum('exploitdb','metasploit','github_poc','nuclei_template','custom','packetstorm') NOT NULL,
	`es_source_id` varchar(255) NOT NULL,
	`es_source_url` text,
	`es_cve_id` varchar(32),
	`es_additional_cves` json,
	`es_filename` varchar(512) NOT NULL,
	`es_language` enum('ruby','python','c','cpp','perl','bash','powershell','javascript','go','java','yaml','html','php','csharp','other') NOT NULL,
	`es_code` mediumtext NOT NULL,
	`es_code_hash` varchar(64) NOT NULL,
	`es_code_size` int NOT NULL,
	`es_title` varchar(512) NOT NULL,
	`es_description` text,
	`es_author` varchar(255),
	`es_date_published` varchar(32),
	`es_platform` varchar(64),
	`es_architecture` varchar(32),
	`es_exploit_type` varchar(64),
	`es_verified` tinyint DEFAULT 0,
	`es_reliability` enum('excellent','great','good','normal','average','low','unknown') DEFAULT 'unknown',
	`es_destructive` tinyint DEFAULT 0,
	`es_requires_auth` tinyint DEFAULT 0,
	`es_requires_interaction` tinyint DEFAULT 0,
	`es_mitre_id` varchar(32),
	`es_mitre_tactic` varchar(64),
	`es_mitre_technique` varchar(255),
	`es_caldera_generated` tinyint DEFAULT 0,
	`es_caldera_ability_yaml` text,
	`es_caldera_executor` varchar(32),
	`es_caldera_command` text,
	`es_caldera_cleanup` text,
	`es_caldera_platform` varchar(32),
	`es_catalog_id` int,
	`es_times_deployed` int DEFAULT 0,
	`es_last_deployed` timestamp,
	`es_success_rate` double,
	`es_tags` json,
	`es_dependencies` json,
	`es_target_products` json,
	`es_ingested_by` varchar(255),
	`es_ingested_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`es_last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploitation_attempts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`target_host` varchar(256) NOT NULL,
	`target_port` int,
	`target_service` varchar(128),
	`vulnerability_id` varchar(128),
	`vulnerability_cve` varchar(32),
	`exploit_source` enum('metasploit','nuclei','manual','custom','hydra','netexec','caldera') NOT NULL,
	`exploit_module` varchar(512),
	`exploit_config` json,
	`ea_status` enum('queued','running','succeeded','failed','error','blocked') DEFAULT 'queued',
	`result_type` enum('shell','credential','info_leak','dos','rce','file_access','none'),
	`result_output` mediumtext,
	`shell_obtained` tinyint DEFAULT 0,
	`ea_shell_type` varchar(64),
	`ea_access_level` enum('none','user','admin','system','root'),
	`ea_evidence` json,
	`ea_attack_technique` varchar(32),
	`match_confidence` int,
	`ea_opsec_risk` int,
	`duration_ms` int,
	`ea_operator_id` int,
	`ea_attempted_at` bigint NOT NULL,
	`ea_completed_at` bigint,
	`ea_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`expa_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `false_positive_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`assetId` int NOT NULL,
	`findingIndex` int NOT NULL,
	`findingHash` varchar(64) NOT NULL,
	`findingTitle` varchar(512) NOT NULL,
	`findingType` varchar(128),
	`findingSeverity` varchar(32),
	`reason` text NOT NULL,
	`fpStatus` enum('false_positive','under_review','reinstated') NOT NULL DEFAULT 'false_positive',
	`markedBy` varchar(255),
	`markedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`reinstatedBy` varchar(255),
	`reinstatedAt` timestamp,
	`reinstatedReason` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `file_transfers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`transferServerId` int NOT NULL,
	`transferSessionId` varchar(64) NOT NULL,
	`transferDirection` enum('upload','download') NOT NULL,
	`remotePath` varchar(1024) NOT NULL,
	`transferFileName` varchar(255) NOT NULL,
	`fileSize` int,
	`transferMimeType` varchar(128),
	`s3Key` varchar(512),
	`s3Url` text,
	`transferStatus` enum('pending','in_progress','completed','failed') NOT NULL DEFAULT 'pending',
	`transferErrorMessage` text,
	`transferCreatedBy` varchar(64),
	`transferCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`transferCompletedAt` timestamp
);
--> statement-breakpoint
CREATE TABLE `fips_compliance_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`checkType` enum('tls_cipher','algorithm_usage','key_strength','certificate_validation','provider_status','full_audit') NOT NULL,
	`complianceStatus` enum('compliant','non_compliant','warning') NOT NULL,
	`component` varchar(128) NOT NULL,
	`details` json,
	`opensslVersion` varchar(64),
	`fipsProviderActive` tinyint DEFAULT 0,
	`createdAt` bigint NOT NULL
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
	`is_forest_root` tinyint NOT NULL DEFAULT 0,
	`forest_total_users` int DEFAULT 0,
	`forest_total_groups` int DEFAULT 0,
	`forest_total_computers` int DEFAULT 0,
	`forest_privileged_users` int DEFAULT 0,
	`forest_last_enumerated_at` timestamp,
	`forest_metadata` json,
	`forest_domain_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `forest_trusts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`trust_source_domain_id` int NOT NULL,
	`trust_target_domain_id` int NOT NULL,
	`trust_direction` enum('inbound','outbound','bidirectional') NOT NULL,
	`trust_type` enum('parent_child','tree_root','shortcut','forest','external','realm') NOT NULL,
	`trust_is_transitive` tinyint NOT NULL DEFAULT 1,
	`sid_filtering_enabled` tinyint NOT NULL DEFAULT 1,
	`selective_auth` tinyint NOT NULL DEFAULT 0,
	`trust_attributes` int DEFAULT 0,
	`trust_is_vulnerable` tinyint NOT NULL DEFAULT 0,
	`trust_vulnerability_notes` text,
	`trust_discovered_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`forest_trust_created_at` timestamp DEFAULT CURRENT_TIMESTAMP
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
	`gdr_validated` tinyint DEFAULT 0,
	`gdr_validation_errors` json,
	`gdr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `generated_payloads` (
	`id` int AUTO_INCREMENT NOT NULL,
	`server_id` int NOT NULL,
	`name` varchar(255) NOT NULL,
	`payload_type` varchar(255) NOT NULL,
	`format` varchar(50) NOT NULL,
	`lhost` varchar(255) NOT NULL,
	`lport` int NOT NULL,
	`encoder` varchar(255),
	`iterations` int DEFAULT 1,
	`arch` varchar(50),
	`platform` varchar(50),
	`extra_options` text,
	`msfvenom_command` text,
	`status` enum('pending','generating','completed','failed') NOT NULL DEFAULT 'pending',
	`error_message` text,
	`file_key` varchar(500),
	`file_url` varchar(1000),
	`file_size` int,
	`file_sha256` varchar(64),
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `guardrail_violations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`violationId` varchar(128) NOT NULL,
	`guardrailContext` varchar(64) NOT NULL,
	`triggerPattern` varchar(256),
	`guardrailAction` enum('blocked','sanitized','warned') NOT NULL,
	`guardrailReason` text NOT NULL,
	`promptSnippet` text,
	`guardrailCreatedAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `hunt_hypotheses` (
	`id` int AUTO_INCREMENT NOT NULL,
	`hunt_session_id` int NOT NULL,
	`hypothesis_statement` text NOT NULL,
	`hypothesis_status` enum('pending','investigating','confirmed','refuted','inconclusive') NOT NULL DEFAULT 'pending',
	`hypothesis_confidence` enum('high','medium','low') NOT NULL DEFAULT 'medium',
	`mitre_technique_id` varchar(32),
	`mitre_technique_name` varchar(255),
	`mitre_tactic` varchar(64),
	`required_data_sources` json,
	`sigma_rule` text,
	`spl_query` text,
	`kql_query` text,
	`evidence` json,
	`analysis_notes` text,
	`detection_rule` text,
	`remediation` text,
	`attack_chain_ref` varchar(64),
	`bug_bounty_pattern_ref` varchar(64),
	`hypothesis_priority` int NOT NULL DEFAULT 0,
	`investigated_at` timestamp,
	`evaluated_at` timestamp,
	`hyp_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`hyp_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `hunt_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`hunt_name` varchar(255) NOT NULL,
	`hunt_description` text,
	`hunt_phase` enum('prepare','execute','act','completed','cancelled') NOT NULL DEFAULT 'prepare',
	`hunt_type` enum('hypothesis_driven','baseline','model_assisted') NOT NULL DEFAULT 'hypothesis_driven',
	`target_environment` text,
	`siem_platform` varchar(64),
	`data_sources` json,
	`threat_actor_id` varchar(128),
	`threat_actor_name` varchar(255),
	`mitre_techniques` json,
	`scope_constraints` json,
	`findings_summary` text,
	`hypothesis_count` int NOT NULL DEFAULT 0,
	`confirmed_findings` int NOT NULL DEFAULT 0,
	`detection_rules_generated` int NOT NULL DEFAULT 0,
	`hunt_priority` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`created_by_id` int,
	`created_by_name` varchar(255),
	`started_at` timestamp,
	`completed_at` timestamp,
	`hunt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`hunt_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `iab_activity` (
	`id` int AUTO_INCREMENT NOT NULL,
	`iab_broker_id` varchar(128) NOT NULL,
	`iab_broker_name` varchar(255) NOT NULL,
	`iab_listing_type` enum('vpn_access','rdp_access','citrix_access','webshell','domain_admin','cloud_access','email_access','database_access','zero_day','exploit_kit','credential_dump','other') NOT NULL,
	`iab_access_type` varchar(255),
	`iab_description` text,
	`iab_victim_name` varchar(512),
	`iab_victim_sector` varchar(128),
	`iab_victim_country` varchar(128),
	`iab_victim_revenue` varchar(64),
	`iab_asking_price` varchar(64),
	`iab_currency` varchar(16) DEFAULT 'USD',
	`iab_forum_source` varchar(255),
	`iab_linked_rw_groups` json,
	`iab_mitre_techniques` json,
	`iab_status` enum('active','sold','expired','removed','law_enforcement') DEFAULT 'active',
	`iab_confidence` int DEFAULT 75,
	`iab_first_seen` timestamp,
	`iab_last_active` timestamp,
	`iab_tags` json,
	`iab_raw_data` json,
	`iab_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`iab_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ics_assessments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ica_user_id` int NOT NULL,
	`ica_name` varchar(255) NOT NULL,
	`ica_description` text,
	`ica_target_network` varchar(255),
	`ica_target_sector` varchar(128),
	`ica_devices_discovered` int DEFAULT 0,
	`ica_vulnerabilities_found` int DEFAULT 0,
	`ica_critical_findings` int DEFAULT 0,
	`ica_apt_groups_matched` int DEFAULT 0,
	`ica_overall_risk_score` double,
	`ica_risk_level` enum('critical','high','medium','low') DEFAULT 'medium',
	`ica_protocol_analysis` json,
	`ica_status` enum('pending','running','completed','failed') DEFAULT 'pending',
	`ica_started_at` timestamp,
	`ica_completed_at` timestamp,
	`ica_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ics_devices` (
	`id` int AUTO_INCREMENT NOT NULL,
	`icd_user_id` int NOT NULL,
	`icd_assessment_id` int,
	`icd_ip_address` varchar(45) NOT NULL,
	`icd_hostname` varchar(255),
	`icd_mac_address` varchar(17),
	`icd_device_type` enum('plc','rtu','hmi','dcs','scada_server','historian','engineering_workstation','safety_system','gateway','switch','sensor','actuator','iot_device','camera','building_automation','medical_device','smart_meter','unknown') NOT NULL DEFAULT 'unknown',
	`icd_vendor` varchar(255),
	`icd_model` varchar(255),
	`icd_firmware_version` varchar(128),
	`icd_serial_number` varchar(128),
	`icd_protocols` json,
	`icd_open_ports` json,
	`icd_purdue_level` enum('level_0','level_1','level_2','level_3','level_3_5','level_4','level_5'),
	`icd_network_segment` varchar(255),
	`icd_facility_name` varchar(255),
	`icd_sector` enum('energy','water','oil_gas','manufacturing','transportation','chemical','nuclear','building_automation','healthcare','food_agriculture','mining','telecom','defense','other'),
	`icd_geolocation` json,
	`icd_criticality` enum('critical','high','medium','low') DEFAULT 'medium',
	`icd_exposed_to_internet` tinyint DEFAULT 0,
	`icd_has_default_creds` tinyint DEFAULT 0,
	`icd_has_known_vulns` tinyint DEFAULT 0,
	`icd_risk_score` double,
	`icd_discovery_source` enum('shodan','censys','nmap','protocol_scan','manual','caldera') DEFAULT 'manual',
	`icd_shodan_data` json,
	`icd_censys_data` json,
	`icd_last_seen` timestamp,
	`icd_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`icd_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ics_exploits` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ice_cve_id` varchar(20),
	`ice_ics_cert_advisory_id` varchar(30),
	`ice_title` varchar(500) NOT NULL,
	`ice_description` text,
	`ice_affected_vendor` varchar(255),
	`ice_affected_product` varchar(255),
	`ice_affected_versions` json,
	`ice_affected_protocols` json,
	`ice_affected_device_types` json,
	`ice_cvss_score` double,
	`ice_cvss_vector` varchar(128),
	`ice_safety_impact` enum('none','low','medium','high','critical') DEFAULT 'none',
	`ice_availability_impact` enum('none','low','medium','high','critical') DEFAULT 'none',
	`ice_process_integrity_impact` enum('none','low','medium','high','critical') DEFAULT 'none',
	`ice_physical_impact` tinyint DEFAULT 0,
	`ice_exploit_available` tinyint DEFAULT 0,
	`ice_exploit_source` varchar(255),
	`ice_exploit_script_id` int,
	`ice_published_date` timestamp,
	`ice_sector` json,
	`ice_references` json,
	`ice_mitigations` text,
	`ice_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `incident_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sourceId` varchar(255) NOT NULL,
	`source` varchar(64) NOT NULL,
	`title` text NOT NULL,
	`url` text,
	`publishedAt` varchar(64),
	`summary` text,
	`fullContent` text,
	`attackSequence` json,
	`ttpsExtracted` json,
	`iocsExtracted` json,
	`actorsIdentified` json,
	`malwareIdentified` json,
	`cvesMentioned` json,
	`targetSectors` json,
	`targetCountries` json,
	`attackNarrative` text,
	`lessonsLearned` text,
	`emulationGuidance` text,
	`exploitContext` json,
	`incidentType` varchar(64),
	`ir_severity` enum('critical','high','medium','low') DEFAULT 'medium',
	`ir_status` enum('raw','extracted','enriched','training_ready') DEFAULT 'raw',
	`ir_enriched_at` timestamp,
	`ir_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ir_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `influence_operations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`io_operation_name` varchar(512) NOT NULL,
	`io_attributed_to` varchar(255),
	`io_nation_state` varchar(128),
	`io_description` text,
	`io_target_countries` json,
	`io_target_sectors` json,
	`io_target_narratives` json,
	`io_platforms` json,
	`io_techniques` json,
	`io_mitre_techniques` json,
	`io_accounts_identified` int DEFAULT 0,
	`io_content_pieces` int DEFAULT 0,
	`io_source` varchar(255),
	`io_source_url` varchar(1024),
	`io_report_date` timestamp,
	`io_status` enum('active','disrupted','dormant','attributed') DEFAULT 'active',
	`io_confidence` int DEFAULT 75,
	`io_tags` json,
	`io_raw_data` json,
	`io_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`io_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `info_ops_campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ioCampaignId` varchar(128) NOT NULL,
	`ioCampaignName` varchar(255) NOT NULL,
	`ioAliases` json,
	`attributedTo` varchar(255),
	`sponsorState` varchar(128),
	`operatorGroup` varchar(255),
	`ioLinkedActorIds` json,
	`operationType` enum('disinformation','influence','hack_and_leak','astroturfing','election_interference','propaganda','cyber_espionage_io','economic_coercion','diplomatic_pressure','other') NOT NULL DEFAULT 'other',
	`ioStatus` enum('active','disrupted','dormant','attributed','ongoing') DEFAULT 'active',
	`ioTargetCountries` json,
	`targetAudiences` json,
	`ioTargetPlatforms` json,
	`targetNarratives` json,
	`estimatedReach` varchar(128),
	`accountsIdentified` int DEFAULT 0,
	`contentPiecesIdentified` int DEFAULT 0,
	`platformActionsTaken` json,
	`ioTechniques` json,
	`cyberComponent` tinyint DEFAULT 0,
	`linkedCyberOps` json,
	`ioMitreTechniques` json,
	`primarySource` varchar(255),
	`sourceUrls` json,
	`reportTitle` varchar(512),
	`ioStartDate` varchar(32),
	`ioEndDate` varchar(32),
	`discoveredDate` varchar(32),
	`ioThreatLevel` enum('critical','high','medium','low') DEFAULT 'medium',
	`ioConfidence` int DEFAULT 75,
	`ioDescription` text,
	`ioDataSource` varchar(128),
	`ioLastEnriched` timestamp,
	`ioCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ioUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ioc_feeds` (
	`id` int AUTO_INCREMENT NOT NULL,
	`feedSource` varchar(64) NOT NULL,
	`feedType` varchar(64) NOT NULL,
	`title` text,
	`description` text,
	`feedSeverity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`feedIocType` varchar(64),
	`iocValue` text,
	`cveId` varchar(32),
	`vendorProduct` varchar(255),
	`knownRansomware` tinyint DEFAULT 0,
	`dateAdded` varchar(32),
	`dueDate` varchar(32),
	`linkedActors` json,
	`feedTags` json,
	`rawData` json,
	`fetchedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ioc_sync_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`syncType` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL,
	`results` json,
	`totalFetched` int DEFAULT 0,
	`errorMessage` text,
	`startedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `job_queue_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`job_id` varchar(128) NOT NULL,
	`engagement_id` int,
	`job_type` enum('scan','recon','feed','c2') NOT NULL,
	`jq_priority` enum('critical','high','normal','low') NOT NULL DEFAULT 'normal',
	`jq_status` enum('queued','dispatched','running','completed','failed','timeout','cancelled') NOT NULL DEFAULT 'queued',
	`worker_host` varchar(255),
	`worker_region` varchar(64),
	`payload_json` json,
	`result_json` json,
	`fips_compliant` tinyint DEFAULT 1,
	`dispatched_by` varchar(255),
	`dispatched_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_control_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`control_id` varchar(32) NOT NULL,
	`control_family` varchar(64),
	`control_title` varchar(512),
	`mapping_strength` enum('direct','supporting','partial') NOT NULL DEFAULT 'direct',
	`ace_c3_module` varchar(256),
	`automation_level` enum('full','partial','manual') NOT NULL DEFAULT 'manual',
	`notes` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_definitions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`theme_code` varchar(8) NOT NULL,
	`theme_name` varchar(128) NOT NULL,
	`title` varchar(512) NOT NULL,
	`requirement` text,
	`validation_type` enum('machine','human','mixed','tbd') NOT NULL DEFAULT 'tbd',
	`frequency` varchar(64),
	`impact_level` enum('low','moderate','high','all') NOT NULL DEFAULT 'all',
	`sp800_53_controls` json,
	`ace_c3_module` varchar(256),
	`coverage_status` enum('direct','supporting','planned','not_applicable') NOT NULL DEFAULT 'planned',
	`coverage_notes` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_evidence` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidence_id` varchar(64) NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`engagement_id` varchar(128),
	`title` varchar(512) NOT NULL,
	`description` text,
	`evidence_type` enum('scan_result','configuration_check','log_entry','screenshot','document','api_response','test_result','attestation','policy_document','training_record','incident_report','audit_log') NOT NULL,
	`source_module` varchar(128) NOT NULL,
	`source_id` varchar(256),
	`collection_method` enum('automated','manual','hybrid') NOT NULL DEFAULT 'automated',
	`raw_data` json,
	`metadata` json,
	`integrity_hash` varchar(128) NOT NULL,
	`previous_hash` varchar(128),
	`hash_algorithm` varchar(16) NOT NULL DEFAULT 'SHA-256',
	`status` enum('collected','verified','validated','expired','rejected') NOT NULL DEFAULT 'collected',
	`validated_by` varchar(256),
	`validated_at` timestamp,
	`expires_at` timestamp,
	`collected_by` int,
	`collected_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_evidence_chains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_id` varchar(64) NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`engagement_id` varchar(128),
	`name` varchar(256) NOT NULL,
	`description` text,
	`evidence_count` int NOT NULL DEFAULT 0,
	`chain_hash` varchar(128),
	`chain_valid` tinyint NOT NULL DEFAULT 1,
	`last_verified_at` timestamp,
	`status` enum('active','complete','broken','archived') NOT NULL DEFAULT 'active',
	`created_by` int,
	`created_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_validation_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` varchar(64) NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`engagement_id` varchar(128),
	`validation_type` enum('machine','human','mixed') NOT NULL,
	`trigger_type` enum('scheduled','manual','event_driven') NOT NULL DEFAULT 'scheduled',
	`status` enum('pending','running','passed','failed','warning','error','skipped') NOT NULL DEFAULT 'pending',
	`result` json,
	`score` int,
	`max_score` int,
	`evidence_ids` json,
	`error_message` text,
	`started_at` timestamp,
	`completed_at` timestamp,
	`next_scheduled_at` timestamp,
	`run_by` int,
	`run_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ksi_validation_schedules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`schedule_id` varchar(64) NOT NULL,
	`ksi_id` varchar(32) NOT NULL,
	`engagement_id` varchar(128),
	`frequency_hours` int NOT NULL,
	`cron_expression` varchar(100),
	`enabled` tinyint NOT NULL DEFAULT 1,
	`last_run_id` varchar(64),
	`last_run_status` varchar(32),
	`last_run_at` timestamp,
	`next_run_at` timestamp,
	`consecutive_failures` int NOT NULL DEFAULT 0,
	`alert_threshold` int NOT NULL DEFAULT 3,
	`config` json,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `lateral_movement_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`source_host_id` int NOT NULL,
	`target_ip` varchar(64) NOT NULL,
	`target_hostname` varchar(256),
	`target_port` int,
	`technique` varchar(128) NOT NULL,
	`attack_id` varchar(32),
	`lm_status` enum('planned','attempted','succeeded','failed','blocked') DEFAULT 'planned',
	`credential_used` json,
	`tunnel_config` json,
	`result_output` text,
	`evidence` json,
	`opsec_risk` int,
	`attempted_at` bigint,
	`lm_completed_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `llm_telemetry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`called_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`caller` varchar(255) NOT NULL DEFAULT 'unknown',
	`model` varchar(128) NOT NULL DEFAULT 'gemini-2.5-flash',
	`llm_status` enum('success','error','timeout','retried_success') NOT NULL DEFAULT 'success',
	`http_status` int,
	`latency_ms` int NOT NULL DEFAULT 0,
	`retry_count` int NOT NULL DEFAULT 0,
	`tokens_in` int DEFAULT 0,
	`tokens_out` int DEFAULT 0,
	`has_response_format` tinyint DEFAULT 0,
	`error_message` text,
	`engagement_id` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `lolbin_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`lolbin_name` varchar(128) NOT NULL,
	`binary_path` varchar(512) NOT NULL,
	`lolbin_os` enum('windows','linux','macos') NOT NULL,
	`lolbin_category` enum('execute','download','upload','copy','compile','encode_decode','reconnaissance','credential_access','persistence','lateral_movement','defense_evasion','exfiltration') NOT NULL,
	`lolbin_description` text NOT NULL,
	`usage_example` text NOT NULL,
	`attack_techniques` json,
	`detection_guidance` text,
	`lolbin_references` json,
	`is_built_in` tinyint DEFAULT 1,
	`lolbin_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `metasploit_servers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`dropletId` varchar(64),
	`ipAddress` varchar(45),
	`region` varchar(32) DEFAULT 'nyc1',
	`dropletSize` varchar(32) DEFAULT 's-2vcpu-4gb',
	`rpcPort` int DEFAULT 55553,
	`rpcUser` varchar(64) DEFAULT 'msf',
	`rpcPass` text,
	`rpcSsl` tinyint DEFAULT 0,
	`rpcToken` text,
	`msfStatus` enum('provisioning','installing','online','offline','error','destroying') NOT NULL DEFAULT 'provisioning',
	`msfStatusMessage` text,
	`msfLastHealthCheck` timestamp,
	`msfVersion` varchar(64),
	`moduleCount` int,
	`activeSessionCount` int DEFAULT 0,
	`autoDestroy` tinyint DEFAULT 0,
	`engagementId` int,
	`msfCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`msfUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`sshTunnelEnabled` tinyint DEFAULT 1,
	`sshUser` varchar(64) DEFAULT 'root',
	`sshKeyPath` text,
	`tunnelLocalPort` int,
	`tunnelStatus` enum('disconnected','connecting','connected','reconnecting','error') DEFAULT 'disconnected',
	`msfSshKeyPath` text,
	`msfTunnelStatus` enum('connected','connecting','disconnected','reconnecting','error') DEFAULT 'disconnected'
);
--> statement-breakpoint
CREATE TABLE `mtls_certificates` (
	`id` varchar(36) NOT NULL,
	`type` enum('ca','client') NOT NULL,
	`commonName` varchar(255) NOT NULL,
	`serialNumber` varchar(64) NOT NULL,
	`issuer` varchar(255) NOT NULL,
	`subject` varchar(255) NOT NULL,
	`validFrom` bigint NOT NULL,
	`validTo` bigint NOT NULL,
	`fingerprint` varchar(128) NOT NULL,
	`certificate` text NOT NULL,
	`encryptedPrivateKey` text NOT NULL,
	`c2ServerId` varchar(36),
	`status` enum('active','revoked','expired') NOT NULL DEFAULT 'active',
	`createdAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `network_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ne_event_type` enum('c2_server','botnet_controller','malicious_ip','tor_exit_node','proxy_node','vpn_endpoint','dns_sinkhole','fast_flux','ssl_blacklist','spam_source','scanner','other') NOT NULL,
	`ne_source` varchar(128) NOT NULL,
	`ne_ip_address` varchar(45),
	`ne_port` int,
	`ne_hostname` varchar(512),
	`ne_protocol` varchar(32),
	`ne_malware_family` varchar(255),
	`ne_description` text,
	`ne_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`ne_confidence` int DEFAULT 75,
	`ne_country` varchar(128),
	`ne_asn` varchar(64),
	`ne_asn_org` varchar(255),
	`ne_status` enum('active','inactive','sinkholed','takedown') DEFAULT 'active',
	`ne_first_seen` timestamp,
	`ne_last_seen` timestamp,
	`ne_tags` json,
	`ne_raw_data` json,
	`ne_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ne_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ngfw_validation_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nvt_tenant_id` int,
	`nvt_name` varchar(255) NOT NULL,
	`nvt_type` enum('port_probe','protocol_test','lateral_movement','exfiltration','c2_callback','segmentation') NOT NULL,
	`nvt_source_ip` varchar(45),
	`nvt_target_ip` varchar(45),
	`nvt_target_port` int,
	`nvt_protocol` varchar(16),
	`nvt_expected` enum('blocked','allowed') NOT NULL,
	`nvt_actual` enum('blocked','allowed','timeout','error'),
	`nvt_status` enum('pending','running','completed','error') NOT NULL DEFAULT 'pending',
	`nvt_fw_vendor` varchar(128),
	`nvt_rule_matched` varchar(255),
	`nvt_executed_at` timestamp,
	`nvt_duration_ms` int,
	`nvt_created_by` varchar(255),
	`nvt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `nuclei_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`template_id` varchar(255) NOT NULL,
	`template_name` varchar(512),
	`severity` varchar(20) NOT NULL,
	`finding_type` varchar(100),
	`host` varchar(512) NOT NULL,
	`matched_at` varchar(1024),
	`extracted_results` text,
	`curl_command` text,
	`description` text,
	`reference` text,
	`tags` text,
	`cve_id` varchar(20),
	`cwe_id` varchar(20),
	`cvss_score` varchar(10),
	`cvss_metrics` varchar(255),
	`attack_technique` varchar(20),
	`verified` tinyint DEFAULT 0,
	`false_positive` tinyint DEFAULT 0,
	`remediation` text,
	`engagement_id` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `nuclei_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`targets` text NOT NULL,
	`template_categories` text,
	`severity_filter` text,
	`tags` text,
	`exclude_tags` text,
	`custom_templates` text,
	`rate_limit` int DEFAULT 150,
	`concurrency` int DEFAULT 25,
	`status` varchar(50) NOT NULL DEFAULT 'pending',
	`progress` int DEFAULT 0,
	`total_templates` int DEFAULT 0,
	`matched_templates` int DEFAULT 0,
	`total_requests` int DEFAULT 0,
	`findings_count` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`info_count` int DEFAULT 0,
	`error_message` text,
	`engagement_id` int,
	`domain_scan_id` int,
	`started_by` varchar(100),
	`started_at` timestamp,
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `observation_alert_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`obs_alert_id` varchar(128) NOT NULL,
	`obs_alert_rule_id` varchar(128) NOT NULL,
	`obs_alert_rule_name` varchar(255) NOT NULL,
	`obs_alert_trigger_type` varchar(64) NOT NULL,
	`obs_alert_severity` enum('info','low','medium','high','critical') NOT NULL DEFAULT 'medium',
	`obs_alert_title` varchar(512) NOT NULL,
	`obs_alert_message` text NOT NULL,
	`obs_alert_matched_obs` json,
	`obs_alert_matched_signals` json,
	`obs_alert_asset_id` varchar(128),
	`obs_alert_asset_host` varchar(512),
	`obs_alert_details` json,
	`obs_alert_notif_sent` tinyint NOT NULL DEFAULT 0,
	`obs_alert_notif_result` varchar(255),
	`obs_alert_ack_at` bigint,
	`obs_alert_ack_by` varchar(255),
	`obs_alert_dismissed_at` bigint,
	`obs_alert_triggered_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `observation_alert_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`obs_rule_id` varchar(128) NOT NULL,
	`obs_rule_name` varchar(255) NOT NULL,
	`obs_rule_description` text,
	`obs_rule_enabled` tinyint NOT NULL DEFAULT 1,
	`obs_trigger_type` enum('critical_cve','new_open_port','high_severity_signal','risk_score_threshold','observation_count','new_vulnerability','tls_expiry','misconfiguration','custom') NOT NULL,
	`obs_rule_conditions` json NOT NULL,
	`obs_rule_notify_owner` tinyint NOT NULL DEFAULT 1,
	`obs_rule_cooldown` int NOT NULL DEFAULT 60,
	`obs_rule_last_triggered` bigint,
	`obs_rule_trigger_count` int NOT NULL DEFAULT 0,
	`obs_rule_created_by` varchar(255),
	`obs_rule_created_at` bigint NOT NULL,
	`obs_rule_updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `obtained_shells` (
	`id` int AUTO_INCREMENT NOT NULL,
	`os_engagement_id` int,
	`exploit_attempt_id` int,
	`os_pivot_host_id` int,
	`os_target_host` varchar(256) NOT NULL,
	`os_target_port` int,
	`os_shell_type` enum('reverse_tcp','bind_tcp','web_shell','ssh','rdp','winrm','agent','other') NOT NULL,
	`os_access_level` enum('user','admin','system','root') DEFAULT 'user',
	`os_username` varchar(128),
	`os_c2_framework` varchar(64),
	`os_session_id` varchar(128),
	`callback_ip` varchar(64),
	`callback_port` int,
	`is_alive` tinyint DEFAULT 1,
	`promoted_to_pivot` tinyint DEFAULT 0,
	`os_notes` text,
	`os_obtained_at` bigint NOT NULL,
	`os_last_checked_at` bigint,
	`os_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`os_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `oem_default_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vendor` varchar(128) NOT NULL,
	`product` varchar(256) NOT NULL,
	`version` varchar(128),
	`protocol` varchar(64) NOT NULL,
	`port` int,
	`username` varchar(256) NOT NULL,
	`password` varchar(512) NOT NULL,
	`access_level` varchar(64),
	`notes` text,
	`cve_reference` varchar(64),
	`source` varchar(256),
	`tags` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `offensive_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`operator_id` varchar(64) NOT NULL,
	`operator_name` varchar(255),
	`action_type` enum('active_probe','msf_check','msf_auxiliary','msf_exploit','phishing_launch','caldera_operation','payload_delivery','session_interaction') NOT NULL,
	`risk_tier` enum('yellow','orange','red') NOT NULL,
	`target` varchar(512) NOT NULL,
	`target_port` int,
	`module_or_tool` varchar(512),
	`roe_status` varchar(32),
	`roe_document_url` text,
	`action_detail` json,
	`result_status` enum('success','failure','blocked','pending_approval') NOT NULL DEFAULT 'pending_approval',
	`result_detail` text,
	`ip_address` varchar(45),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `opsec_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`opsec_engagement_id` int NOT NULL,
	`opsec_action_type` varchar(128) NOT NULL,
	`opsec_action_description` text NOT NULL,
	`risk_score` int NOT NULL,
	`detection_probability` int,
	`triggers_siem_rules` json,
	`triggers_edr_alerts` json,
	`network_noise` enum('silent','low','moderate','loud','very_loud') DEFAULT 'moderate',
	`opsec_source_host` varchar(256),
	`opsec_target_host` varchar(256),
	`opsec_protocol` varchar(32),
	`opsec_attack_technique` varchar(32),
	`safer_alternative` text,
	`was_detected` tinyint,
	`detection_details` text,
	`opsec_operator_id` int,
	`opsec_timestamp` bigint NOT NULL,
	`opsec_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`opse_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `opsec_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`opsec_score_engagement_id` int NOT NULL,
	`cumulative_risk` int NOT NULL,
	`current_noise_level` enum('stealth','low','moderate','elevated','critical') DEFAULT 'stealth',
	`opsec_events_count` int DEFAULT 0,
	`high_risk_events_count` int DEFAULT 0,
	`estimated_detection_chance` int DEFAULT 0,
	`infrastructure_health` json,
	`burned_assets` json,
	`opsec_recommendations` json,
	`opsec_last_updated_at` bigint NOT NULL,
	`opsec_score_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`opsec_score_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `oscal_exports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`export_id` varchar(64) NOT NULL,
	`document_type` enum('ssp','sar','poam','component_definition','assessment_plan') NOT NULL,
	`title` varchar(512) NOT NULL,
	`description` text,
	`engagement_id` varchar(128),
	`ksi_scope` json,
	`oscal_version` varchar(16) NOT NULL DEFAULT '1.1.2',
	`status` enum('pending','generating','complete','failed') NOT NULL DEFAULT 'pending',
	`output_format` enum('json','xml','yaml') NOT NULL DEFAULT 'json',
	`output_url` text,
	`output_hash` varchar(128),
	`metadata` json,
	`error_message` text,
	`generated_by` int,
	`generated_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `osint_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`reconId` int,
	`category` enum('subdomain','email','credential_leak','tech_stack','social_media','dark_web','dns_misconfiguration','certificate','open_port','other') NOT NULL,
	`severity` enum('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
	`title` varchar(512) NOT NULL,
	`description` text,
	`rawData` json,
	`source` varchar(255),
	`campaignRelevance` text,
	`usedInCampaign` tinyint DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `osint_monitor_changes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`monitorId` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`changeType` varchar(64) NOT NULL,
	`severity` enum('info','warning','critical') NOT NULL DEFAULT 'info',
	`previousValue` text,
	`currentValue` text,
	`description` text,
	`acknowledged` tinyint DEFAULT 0,
	`acknowledgedBy` int,
	`acknowledgedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `osint_monitors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int,
	`domain` varchar(255) NOT NULL,
	`intervalHours` int NOT NULL DEFAULT 24,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`clientType` enum('msp','enterprise','saas','paas','iaas','mixed_hosting','other') NOT NULL DEFAULT 'enterprise',
	`lastScanAt` timestamp,
	`lastChangeDetectedAt` timestamp,
	`totalScans` int DEFAULT 0,
	`totalChangesDetected` int DEFAULT 0,
	`notifyOnChange` tinyint DEFAULT 1,
	`notifyEmail` varchar(320),
	`baselineSnapshot` json,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ot_networks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`otn_user_id` int NOT NULL,
	`otn_name` varchar(255) NOT NULL,
	`otn_description` text,
	`otn_cidr` varchar(45),
	`otn_vlan` int,
	`otn_purdue_level` enum('level_0','level_1','level_2','level_3','level_3_5','level_4','level_5'),
	`otn_network_type` enum('process_control','safety','supervisory','dmz','enterprise','field_bus','iot_segment'),
	`otn_parent_network_id` int,
	`otn_connected_network_ids` json,
	`otn_protocol_distribution` json,
	`otn_device_count` int DEFAULT 0,
	`otn_has_firewall` tinyint DEFAULT 0,
	`otn_has_data_diode` tinyint DEFAULT 0,
	`otn_has_ids` tinyint DEFAULT 0,
	`otn_segmentation_score` double,
	`otn_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `pentest_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`report_title` varchar(512) NOT NULL,
	`report_type` enum('executive','technical','compliance','full') NOT NULL DEFAULT 'full',
	`classification` enum('CONFIDENTIAL','INTERNAL','PUBLIC') NOT NULL DEFAULT 'CONFIDENTIAL',
	`status` enum('draft','generating','completed','error') NOT NULL DEFAULT 'draft',
	`client_name` varchar(256),
	`engagement_name` varchar(256),
	`tester_name` varchar(256),
	`tester_org` varchar(256),
	`scope_description` text,
	`engagement_start_date` varchar(32),
	`engagement_end_date` varchar(32),
	`domain_intel_scan_ids` json,
	`zap_session_ids` json,
	`credential_attack_run_ids` json,
	`total_findings` int DEFAULT 0,
	`critical_findings` int DEFAULT 0,
	`high_findings` int DEFAULT 0,
	`medium_findings` int DEFAULT 0,
	`low_findings` int DEFAULT 0,
	`info_findings` int DEFAULT 0,
	`credentials_found` int DEFAULT 0,
	`mitre_attack_coverage` json,
	`executive_summary` mediumtext,
	`report_html` mediumtext,
	`generated_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ptr_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `phishing_drafts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int,
	`engagementId` int,
	`campaignRecommendationIndex` int,
	`draftStatus` enum('draft','approved','deployed','launched','completed','archived') NOT NULL DEFAULT 'draft',
	`campaignName` varchar(255) NOT NULL,
	`campaignType` varchar(64),
	`draftPriority` enum('critical','high','medium','low') DEFAULT 'medium',
	`targetDomain` varchar(255),
	`targetSector` varchar(128),
	`templateName` varchar(255),
	`templateSubject` varchar(500),
	`templateHtml` text,
	`templateText` text,
	`landingPageName` varchar(255),
	`landingPageHtml` text,
	`landingPageRedirectUrl` varchar(500),
	`captureCredentials` tinyint DEFAULT 1,
	`capturePasswords` tinyint DEFAULT 0,
	`targetGroupName` varchar(255),
	`targetEmails` json,
	`smtpProfileName` varchar(255),
	`phishingUrl` varchar(500),
	`attackChain` json,
	`calderaAbilities` json,
	`calderaOperationId` varchar(128),
	`autoTriggerCaldera` tinyint DEFAULT 0,
	`triggerCondition` json,
	`threatActorId` varchar(128),
	`threatActorName` varchar(255),
	`matchRationale` text,
	`gophishTemplateId` int,
	`gophishPageId` int,
	`gophishGroupId` int,
	`gophishCampaignId` int,
	`launchDate` timestamp,
	`sendByDate` timestamp,
	`campaignStats` json,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`phishingExploits` json,
	`exploitEnhancedLandingPage` text,
	`pd_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `pivot_hosts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`hostname` varchar(256),
	`ip_address` varchar(64) NOT NULL,
	`os` varchar(128),
	`access_level` enum('user','admin','system','root') DEFAULT 'user',
	`access_method` varchar(128),
	`credentials` json,
	`is_active` tinyint DEFAULT 1,
	`agent_id` varchar(128),
	`c2_framework` varchar(64),
	`network_interfaces` json,
	`discovered_services` json,
	`notes` text,
	`obtained_at` bigint NOT NULL,
	`last_seen_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `platform_errors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`source` varchar(32) NOT NULL,
	`severity` varchar(16) NOT NULL DEFAULT 'error',
	`message` text NOT NULL,
	`stack` mediumtext,
	`page` varchar(512),
	`endpoint` varchar(256),
	`status_code` int,
	`user_id` int,
	`engagement_context` json,
	`client_meta` json,
	`resolved` tinyint NOT NULL DEFAULT 0,
	`resolved_note` text,
	`resolved_at` timestamp,
	`retry_count` int DEFAULT 0,
	`auto_recovered` tinyint DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`perr_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `playbook_executions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`playbookId` int NOT NULL,
	`playbookName` varchar(255) NOT NULL,
	`calderaOperationId` varchar(128),
	`calderaOperationName` varchar(255),
	`execStatus` enum('pending','running','paused','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
	`targetGroup` varchar(128),
	`targetAgentCount` int DEFAULT 0,
	`abilitiesTotal` int DEFAULT 0,
	`abilitiesSucceeded` int DEFAULT 0,
	`abilitiesFailed` int DEFAULT 0,
	`abilitiesSkipped` int DEFAULT 0,
	`startedAt` timestamp,
	`completedAt` timestamp,
	`launchedBy` int,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `post_exploit_executions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pePlaybookId` int NOT NULL,
	`peServerId` int NOT NULL,
	`peSessionId` varchar(64) NOT NULL,
	`peStatus` enum('pending','running','completed','failed','aborted') NOT NULL DEFAULT 'pending',
	`peCurrentStep` int NOT NULL DEFAULT 0,
	`peTotalSteps` int NOT NULL,
	`peOutput` json,
	`peErrorMessage` text,
	`peStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`peCompletedAt` timestamp,
	`peTriggeredBy` enum('manual','auto') NOT NULL DEFAULT 'manual',
	`peCreatedBy` varchar(64)
);
--> statement-breakpoint
CREATE TABLE `post_exploit_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`playbookName` varchar(255) NOT NULL,
	`playbookDescription` text,
	`playbookCategory` enum('recon','credential','persistence','lateral','exfil','cleanup','custom') NOT NULL DEFAULT 'custom',
	`targetSessionType` enum('shell','meterpreter','both') NOT NULL DEFAULT 'both',
	`playbookCommands` json NOT NULL,
	`autoTrigger` tinyint NOT NULL DEFAULT 0,
	`autoTriggerFilter` json,
	`isBuiltIn` tinyint NOT NULL DEFAULT 0,
	`playbookEnabled` tinyint NOT NULL DEFAULT 1,
	`playbookCreatedBy` varchar(64),
	`playbookCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`playbookUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `privesc_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pe_engagement_id` int,
	`pe_pivot_host_id` int,
	`pe_target_host` varchar(256) NOT NULL,
	`pe_os` enum('windows','linux','macos','cloud_aws','cloud_azure','cloud_gcp') NOT NULL,
	`check_name` varchar(256) NOT NULL,
	`check_category` enum('kernel_exploit','suid_sgid','cron_jobs','writable_paths','sudo_misconfig','service_misconfig','registry_keys','scheduled_tasks','dll_hijack','token_abuse','uac_bypass','kerberos','ad_delegation','gpo_abuse','certificate_abuse','iam_misconfig','role_assumption','storage_access','metadata_service') NOT NULL,
	`pe_severity` enum('info','low','medium','high','critical') NOT NULL,
	`pe_description` text NOT NULL,
	`exploit_path` text,
	`pe_attack_technique` varchar(32),
	`pe_tool_used` varchar(128),
	`pe_raw_output` mediumtext,
	`is_exploitable` tinyint DEFAULT 0,
	`was_exploited` tinyint DEFAULT 0,
	`resulting_access` varchar(64),
	`pe_evidence` json,
	`pe_discovered_at` bigint NOT NULL,
	`pe_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `protocol_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pf_assessment_id` int NOT NULL,
	`pf_device_id` int,
	`pf_protocol` varchar(50) NOT NULL,
	`pf_finding_type` enum('unauthenticated_access','default_credentials','cleartext_protocol','firmware_vulnerability','configuration_weakness','exposed_service','information_disclosure','command_injection','denial_of_service','replay_attack','man_in_the_middle','unauthorized_write','safety_bypass','logic_manipulation','other') NOT NULL,
	`pf_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`pf_title` varchar(500) NOT NULL,
	`pf_description` text,
	`pf_evidence` text,
	`pf_safety_impact` tinyint DEFAULT 0,
	`pf_process_impact` tinyint DEFAULT 0,
	`pf_remediation` text,
	`pf_compensating_controls` text,
	`pf_relevant_apt_groups` json,
	`pf_relevant_mitre_techniques` json,
	`pf_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ransomware_affiliates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ra_affiliate_id` varchar(128) NOT NULL,
	`ra_affiliate_name` varchar(255) NOT NULL,
	`ra_aliases` json,
	`ra_description` text,
	`ra_primary_group` varchar(255),
	`ra_affiliated_groups` json,
	`ra_activity_score` int DEFAULT 0,
	`ra_total_victims` int DEFAULT 0,
	`ra_top_sectors` json,
	`ra_top_countries` json,
	`ra_mitre_techniques` json,
	`ra_preferred_access` varchar(255),
	`ra_tools_used` json,
	`ra_status` enum('active','inactive','arrested','unknown') DEFAULT 'active',
	`ra_confidence` int DEFAULT 75,
	`ra_first_seen` varchar(32),
	`ra_last_active` varchar(32),
	`ra_tags` json,
	`ra_raw_data` json,
	`ra_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ra_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ransomware_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`reGroupName` varchar(255) NOT NULL,
	`victimName` varchar(512) NOT NULL,
	`victimUrl` varchar(512),
	`reCountry` varchar(128),
	`reSector` varchar(128),
	`reDescription` text,
	`publishedAt` timestamp,
	`reSource` varchar(128),
	`verified` tinyint DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ransomware_groups` (
	`id` int AUTO_INCREMENT NOT NULL,
	`groupName` varchar(255) NOT NULL,
	`aliases` json,
	`description` text,
	`activityScore` int DEFAULT 0,
	`trend` enum('surging','active','declining','dormant') DEFAULT 'active',
	`rwThreatLevel` enum('critical','high','medium','low') DEFAULT 'medium',
	`victims7D` int DEFAULT 0,
	`victims30D` int DEFAULT 0,
	`totalVictims` int DEFAULT 0,
	`topSectors` json,
	`topCountries` json,
	`associatedMalware` json,
	`mitreTechniques` json,
	`ransomwareFamily` varchar(255),
	`extortionModel` enum('single','double','triple','unknown') DEFAULT 'unknown',
	`affiliateProgram` tinyint DEFAULT 0,
	`knownInfrastructure` json,
	`notableAttacks` json,
	`rwFirstSeen` varchar(32),
	`rwLastActive` varchar(32),
	`calderaActorId` varchar(128),
	`rwDataSource` varchar(128),
	`rwConfidence` int DEFAULT 75,
	`lastEnriched` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `recording_chunks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`recordingId` int NOT NULL,
	`chunkIndex` int NOT NULL,
	`chunkType` enum('input','output','system') NOT NULL DEFAULT 'output',
	`chunkContent` text NOT NULL,
	`timestampMs` int NOT NULL,
	`chunkCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `remediation_verifications` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rv_tenant_id` int,
	`rv_original_finding_id` int NOT NULL,
	`rv_finding_type` varchar(64) NOT NULL,
	`rv_technique_id` varchar(32),
	`rv_method` enum('re_exploit','scan_recheck','config_audit','manual') NOT NULL,
	`rv_status` enum('pending','running','verified_fixed','still_vulnerable','error') NOT NULL DEFAULT 'pending',
	`rv_previous_result` text,
	`rv_current_result` text,
	`rv_verified_at` timestamp,
	`rv_verified_by` varchar(255),
	`rv_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`rv_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`rv_sla_deadline` timestamp,
	`rv_sla_hours` int,
	`rv_verification_output` text,
	`rv_attempt_count` int DEFAULT 0,
	`rv_asset_name` varchar(255),
	`rv_finding_title` varchar(512)
);
--> statement-breakpoint
CREATE TABLE `report_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rt_tenant_id` int,
	`rt_name` varchar(255) NOT NULL,
	`rt_description` text,
	`rt_type` enum('engagement','executive','compliance','vulnerability','custom') NOT NULL,
	`rt_content` text NOT NULL,
	`rt_header_html` text,
	`rt_footer_html` text,
	`rt_css_overrides` text,
	`rt_logo_url` varchar(512),
	`rt_primary_color` varchar(16),
	`rt_is_default` tinyint DEFAULT 0,
	`rt_created_by` varchar(255),
	`rt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`rt_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `review_queue_items` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`category` enum('scan_plan','vuln_triage','detection_rule','exploit_plan','hunt_hypothesis','risk_score','report_draft','c2_action') NOT NULL,
	`title` varchar(512) NOT NULL,
	`summary` text NOT NULL,
	`llm_rationale` text,
	`llm_confidence` decimal(5,2),
	`payload_json` json NOT NULL,
	`risk_level` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`rq_status` enum('pending','approved','rejected','deferred','auto_approved','expired') NOT NULL DEFAULT 'pending',
	`reviewed_by` varchar(255),
	`reviewed_at` bigint,
	`review_notes` text,
	`auto_approve_eligible` tinyint DEFAULT 0,
	`expires_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `risk_trend_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rts_tenant_id` int,
	`rts_snapshot_date` timestamp NOT NULL,
	`rts_overall_score` double NOT NULL,
	`rts_detection_coverage` double,
	`rts_prevention_coverage` double,
	`rts_critical_vulns` int DEFAULT 0,
	`rts_open_findings` int DEFAULT 0,
	`rts_mttd_ms` int,
	`rts_mttr_ms` int,
	`rts_tactic_scores` json,
	`rts_source` varchar(64),
	`rts_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `roe_documents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`title` varchar(512) NOT NULL,
	`version` varchar(32) NOT NULL DEFAULT '1.0',
	`status` enum('draft','pending_review','approved','active','completed','archived') NOT NULL DEFAULT 'draft',
	`organization_name` varchar(512),
	`organization_address` text,
	`testing_firm_name` varchar(512),
	`testing_firm_address` text,
	`purpose` text,
	`scope_description` text,
	`assumptions` text,
	`limitations` text,
	`risks` text,
	`test_schedule_start` timestamp,
	`test_schedule_end` timestamp,
	`testing_window_start` varchar(16),
	`testing_window_end` varchar(16),
	`testing_days` json,
	`test_timezone` varchar(64),
	`test_site_locations` json,
	`remote_testing_allowed` tinyint DEFAULT 1,
	`vpn_required` tinyint DEFAULT 0,
	`badge_escort_required` tinyint DEFAULT 0,
	`test_equipment` json,
	`communication_frequency` enum('daily','weekly','bi-weekly','as-needed') DEFAULT 'daily',
	`communication_method` enum('email','phone','secure_portal','encrypted_email') DEFAULT 'secure_portal',
	`status_report_frequency` enum('daily','weekly','milestone-based') DEFAULT 'daily',
	`incident_definition` text,
	`incident_response_procedure` text,
	`emergency_halt_criteria` text,
	`resumption_procedure` text,
	`in_scope_assets` json,
	`out_of_scope_assets` json,
	`in_scope_ip_ranges` json,
	`out_of_scope_ip_ranges` json,
	`in_scope_domains` json,
	`out_of_scope_domains` json,
	`in_scope_applications` json,
	`cloud_environments` json,
	`wireless_networks` json,
	`physical_locations` json,
	`testing_types` json,
	`attack_vectors` json,
	`social_engineering_pretexts` json,
	`dos_testing_allowed` tinyint DEFAULT 0,
	`physical_testing_allowed` tinyint DEFAULT 0,
	`wireless_testing_allowed` tinyint DEFAULT 0,
	`social_engineering_allowed` tinyint DEFAULT 0,
	`credentialed_testing` tinyint DEFAULT 0,
	`credential_accounts` json,
	`file_modification_allowed` tinyint DEFAULT 0,
	`file_installation_allowed` tinyint DEFAULT 0,
	`pivoting_allowed` tinyint DEFAULT 1,
	`exfiltration_allowed` tinyint DEFAULT 0,
	`persistence_allowed` tinyint DEFAULT 0,
	`shunning_policy` enum('allowed','not_allowed','notify_first') DEFAULT 'notify_first',
	`fedramp_compliant` tinyint DEFAULT 0,
	`fedramp_attack_vectors` json,
	`fedramp_impact_level` enum('low','moderate','high','not_applicable') DEFAULT 'not_applicable',
	`service_model` enum('iaas','paas','saas','hybrid','not_applicable') DEFAULT 'not_applicable',
	`data_handling_procedure` text,
	`evidence_retention_days` int DEFAULT 90,
	`evidence_encryption_required` tinyint DEFAULT 1,
	`pii_handling_policy` text,
	`evidence_destruction_method` enum('secure_delete','physical_destruction','crypto_erase') DEFAULT 'secure_delete',
	`report_deliverables` json,
	`report_frequency` enum('daily','weekly','final_only') DEFAULT 'final_only',
	`critical_finding_notification` text,
	`legal_jurisdiction` varchar(256),
	`third_party_agreements` json,
	`liability_waiver` text,
	`nda_required` tinyint DEFAULT 1,
	`nda_reference` varchar(256),
	`compliance_frameworks` json,
	`created_by` int,
	`approved_by` int,
	`approved_at` timestamp,
	`last_modified_by` int,
	`pdf_url` varchar(1024),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`roe_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `roe_personnel` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`role` enum('system_owner','ciso','cio','isso','authorizing_official','trusted_agent','test_lead','test_member','emergency_contact','legal_counsel','third_party_poc','incident_response_lead','customer_poc','project_manager') NOT NULL,
	`name` varchar(256) NOT NULL,
	`title` varchar(256),
	`organization` varchar(256),
	`email` varchar(320),
	`phone` varchar(32),
	`alternate_phone` varchar(32),
	`clearance_level` varchar(64),
	`is_primary` tinyint DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `roe_signatures` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`signer_name` varchar(256) NOT NULL,
	`signer_title` varchar(256),
	`signer_organization` varchar(256),
	`signer_role` enum('customer_executive','customer_technical','testing_lead','authorizing_official','legal_counsel') NOT NULL,
	`signed_at` timestamp,
	`signature_data` text,
	`ip_address` varchar(45),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `roe_versions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`version_number` varchar(32) NOT NULL,
	`change_type` enum('created','updated','status_change','approved','restored') NOT NULL DEFAULT 'updated',
	`change_summary` text,
	`changed_fields` json,
	`previous_snapshot` json,
	`current_snapshot` json,
	`changed_by` int,
	`changed_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `rule_robustness_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` int NOT NULL,
	`rule_id` varchar(255) NOT NULL,
	`rule_title` varchar(500),
	`original_command` text,
	`detection_pattern` text,
	`robustness_score` int,
	`robustness_class` enum('robust','moderate','fragile','bypassed'),
	`total_variants` int,
	`detected_count` int,
	`evaded_count` int,
	`weakest_categories` json,
	`hardening_tips` json,
	`variant_details` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `saml_auth_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`saml_event_type` enum('login_success','login_failure','logout','jit_provision','assertion_error','signature_invalid') NOT NULL,
	`saml_event_idp_config_id` int,
	`saml_event_user_id` int,
	`saml_event_name_id` varchar(512),
	`saml_event_ip_address` varchar(45),
	`saml_event_error_details` text,
	`saml_event_assertion_id` varchar(256),
	`saml_event_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `saml_idp_configs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`saml_idp_name` varchar(256) NOT NULL,
	`saml_idp_provider_type` enum('okta','azure_ad','ping_federate','google_workspace','onelogin','generic') NOT NULL DEFAULT 'generic',
	`saml_idp_entity_id` varchar(512) NOT NULL,
	`saml_idp_sso_url` varchar(1024) NOT NULL,
	`saml_idp_slo_url` varchar(1024),
	`saml_idp_certificate` text NOT NULL,
	`saml_idp_metadata_xml` mediumtext,
	`saml_idp_name_id_format` varchar(256) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
	`saml_idp_attribute_mapping` json,
	`saml_idp_default_role` enum('user','admin','viewer','operator','team_lead','analyst','executive','client') NOT NULL DEFAULT 'operator',
	`saml_idp_is_active` tinyint NOT NULL DEFAULT 1,
	`saml_idp_jit_provisioning` tinyint NOT NULL DEFAULT 1,
	`saml_idp_force_authn` tinyint NOT NULL DEFAULT 0,
	`saml_idp_want_assertions_signed` tinyint NOT NULL DEFAULT 1,
	`saml_idp_want_response_signed` tinyint NOT NULL DEFAULT 1,
	`saml_idp_created_by` int,
	`saml_idp_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`saml_idp_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `scan_observations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`observationId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`assetHost` varchar(512) NOT NULL,
	`assetPort` int NOT NULL,
	`assetProtocol` varchar(32),
	`assetTags` json,
	`scannerName` varchar(64) NOT NULL,
	`scannerVersion` varchar(64),
	`scannerAdapter` varchar(64) NOT NULL,
	`scannerMode` enum('passive','active-low','active-standard','active-aggressive') DEFAULT 'passive',
	`observationType` enum('service_banner','tls','http_headers','dns','vulnerability_finding','misconfiguration','exposure_surface','cloud_fingerprint') NOT NULL,
	`severity` enum('info','low','medium','high','critical') DEFAULT 'info',
	`confidence` double NOT NULL,
	`evidenceSummary` text NOT NULL,
	`evidenceTemplateId` varchar(256),
	`evidenceCve` varchar(32),
	`evidenceCvss` double,
	`evidenceRequestFingerprint` varchar(128),
	`evidenceResponseFingerprint` varchar(128),
	`evidenceArtifacts` json,
	`scanRunId` varchar(128),
	`policyProfile` varchar(64),
	`rateLimitBucket` varchar(64),
	`notes` text,
	`rawDataHash` varchar(128),
	`observedAt` bigint NOT NULL,
	`ingestedAt` bigint NOT NULL,
	`sobs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `scan_policies` (
	`id` int AUTO_INCREMENT NOT NULL,
	`profileId` varchar(64) NOT NULL,
	`policyName` varchar(128) NOT NULL,
	`policyDescription` text,
	`isActive` tinyint NOT NULL DEFAULT 0,
	`profileData` json NOT NULL,
	`escalationRules` json,
	`policyCreatedAt` bigint NOT NULL,
	`policyUpdatedAt` bigint NOT NULL,
	`sp_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `scan_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`tool` varchar(64) NOT NULL,
	`target` varchar(255) NOT NULL,
	`command` text,
	`raw_output` mediumtext,
	`raw_stderr` mediumtext,
	`exit_code` int,
	`duration_ms` int,
	`timed_out` tinyint DEFAULT 0,
	`findings` json,
	`finding_count` int DEFAULT 0,
	`severity_summary` json,
	`phase` varchar(64),
	`operator_id` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `scan_risk_cards` (
	`id` int AUTO_INCREMENT NOT NULL,
	`riskId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`finalScore` double NOT NULL,
	`componentCvss` double NOT NULL,
	`componentCarver` double NOT NULL,
	`componentBia` double NOT NULL,
	`confidenceWeight` double NOT NULL,
	`summary` text NOT NULL,
	`whyItMatters` text,
	`evidence` json,
	`recommendations` json NOT NULL,
	`riskCardCreatedAt` bigint NOT NULL,
	`signalIds` json,
	`riskCardUpdatedAt` bigint
);
--> statement-breakpoint
CREATE TABLE `scan_signals` (
	`id` int AUTO_INCREMENT NOT NULL,
	`signalId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`signalType` enum('vulnerability','exposure','weak_signal','intel','hygiene','misconfiguration') NOT NULL,
	`category` varchar(128) NOT NULL,
	`signalSeverity` enum('info','low','medium','high','critical') DEFAULT 'info',
	`signalConfidence` double NOT NULL,
	`rationale` text NOT NULL,
	`sourceObservations` json NOT NULL,
	`enrichmentCvss` double,
	`enrichmentCve` varchar(32),
	`enrichmentReferences` json,
	`signalCreatedAt` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `scoring_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`assetId` int NOT NULL,
	`scanId` int,
	`profileId` int,
	`carverScores` json,
	`shockScores` json,
	`cvssEstimate` double,
	`missionImpactScore` double,
	`impactScore` double,
	`likelihoodScore` double,
	`hybridRiskScore` double,
	`riskBand` varchar(32),
	`weightsSnapshot` json,
	`computedBy` varchar(255),
	`computedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`triggerType` varchar(64),
	`previousScore` double,
	`delta` double,
	`changeDescription` text,
	`factorChanges` json,
	`pipelinePhase` varchar(64)
);
--> statement-breakpoint
CREATE TABLE `scoring_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`engagementId` int,
	`isDefault` tinyint DEFAULT 0,
	`wCriticality` double NOT NULL DEFAULT 2,
	`wAccessibility` double NOT NULL DEFAULT 1.5,
	`wRecuperability` double NOT NULL DEFAULT 1,
	`wVulnerability` double NOT NULL DEFAULT 1.5,
	`wEffect` double NOT NULL DEFAULT 1.5,
	`wRecognizability` double NOT NULL DEFAULT 0.5,
	`wScope` double NOT NULL DEFAULT 1.5,
	`wHandling` double NOT NULL DEFAULT 1,
	`wOperationalImpact` double NOT NULL DEFAULT 2,
	`wCascadingEffects` double NOT NULL DEFAULT 1.5,
	`wKnowledge` double NOT NULL DEFAULT 1,
	`carverWeight` double NOT NULL DEFAULT 0.4,
	`shockWeight` double NOT NULL DEFAULT 0.3,
	`cvssWeight` double NOT NULL DEFAULT 0.3,
	`criticalThreshold` int NOT NULL DEFAULT 85,
	`highThreshold` int NOT NULL DEFAULT 65,
	`mediumThreshold` int NOT NULL DEFAULT 40,
	`createdBy` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `server_configs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`ipAddress` varchar(45) NOT NULL,
	`httpsUrl` varchar(512),
	`httpUrl` varchar(512),
	`region` varchar(64),
	`dropletSize` varchar(64),
	`dropletId` varchar(64),
	`status` enum('online','offline','unknown') NOT NULL DEFAULT 'unknown',
	`lastHealthCheck` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `server_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serverId` int NOT NULL,
	`credentialType` enum('admin_login','red_api_key','blue_api_key','ssh_key') NOT NULL,
	`username` varchar(255),
	`password` text,
	`apiKey` text,
	`sshKeyPath` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `session_recordings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serverId` int NOT NULL,
	`sessionId` varchar(64) NOT NULL,
	`sessionType` enum('shell','meterpreter') NOT NULL,
	`targetHost` varchar(255),
	`recordingUsername` varchar(255),
	`recordingPlatform` varchar(128),
	`viaExploit` varchar(512),
	`recordingStatus` enum('recording','completed','error') NOT NULL DEFAULT 'recording',
	`totalChunks` int NOT NULL DEFAULT 0,
	`totalBytes` int NOT NULL DEFAULT 0,
	`durationMs` int DEFAULT 0,
	`recordingStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`recordingCompletedAt` timestamp,
	`recordingCreatedBy` varchar(64)
);
--> statement-breakpoint
CREATE TABLE `siem_connections` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`backend` enum('wazuh','elastic') NOT NULL,
	`base_url` varchar(512) NOT NULL,
	`username` varchar(255),
	`password` varchar(512),
	`api_key` varchar(512),
	`insecure` tinyint DEFAULT 0,
	`timeout_ms` int DEFAULT 15000,
	`index_pattern` varchar(512),
	`use_security_detections` tinyint DEFAULT 0,
	`connected` tinyint DEFAULT 0,
	`enabled` tinyint DEFAULT 1,
	`last_tested_at` timestamp,
	`version` varchar(64),
	`cluster_name` varchar(255),
	`alert_count` int,
	`error_message` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `siem_integrations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`siem_tenant_id` int,
	`siem_name` varchar(255) NOT NULL,
	`siem_provider` enum('splunk','elastic','sentinel','qradar','custom') NOT NULL,
	`siem_base_url` varchar(512) NOT NULL,
	`siem_api_key_enc` text,
	`siem_query_template` text,
	`siem_is_active` tinyint NOT NULL DEFAULT 1,
	`siem_last_tested` timestamp,
	`siem_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `sliver_implants` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`implant_id` varchar(100),
	`os` varchar(50) NOT NULL,
	`arch` varchar(50) NOT NULL,
	`transport` varchar(50) NOT NULL,
	`implant_type` varchar(50) NOT NULL,
	`format` varchar(50) DEFAULT 'exe',
	`c2_urls` text,
	`beacon_interval` int,
	`beacon_jitter` int,
	`evasion_options` text,
	`status` varchar(50) NOT NULL DEFAULT 'generated',
	`download_url` text,
	`engagement_id` int,
	`created_by` varchar(100),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `sliver_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(100) NOT NULL,
	`implant_id` varchar(100),
	`name` varchar(255),
	`hostname` varchar(255),
	`username` varchar(255),
	`os` varchar(50),
	`arch` varchar(50),
	`transport` varchar(50),
	`remote_address` varchar(255),
	`pid` int,
	`filename` varchar(255),
	`active_c2` varchar(512),
	`reconnect_interval` int,
	`proxy_url` varchar(512),
	`is_dead` tinyint DEFAULT 0,
	`last_checkin` timestamp,
	`first_seen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`engagement_id` int,
	`notes` text
);
--> statement-breakpoint
CREATE TABLE `sliver_tasks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(100) NOT NULL,
	`task_type` varchar(100) NOT NULL,
	`command` text,
	`args` text,
	`status` varchar(50) NOT NULL DEFAULT 'pending',
	`output` text,
	`error_message` text,
	`attack_technique` varchar(20),
	`engagement_id` int,
	`executed_by` varchar(100),
	`started_at` timestamp,
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `soar_connectors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`soar_tenant_id` int,
	`soar_name` varchar(255) NOT NULL,
	`soar_platform` enum('splunk_soar','cortex_xsoar','swimlane','tines','custom') NOT NULL,
	`soar_webhook_url` varchar(512) NOT NULL,
	`soar_api_key_enc` text,
	`soar_inbound` tinyint NOT NULL DEFAULT 1,
	`soar_outbound` tinyint NOT NULL DEFAULT 1,
	`soar_event_types` json,
	`soar_is_active` tinyint NOT NULL DEFAULT 1,
	`soar_last_sync` timestamp,
	`soar_created_by` varchar(255),
	`soar_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `soar_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`soar_evt_connector_id` int NOT NULL,
	`soar_evt_tenant_id` int,
	`soar_evt_direction` enum('inbound','outbound') NOT NULL,
	`soar_evt_type` varchar(128) NOT NULL,
	`soar_evt_payload` json,
	`soar_evt_status` enum('pending','delivered','failed') NOT NULL DEFAULT 'pending',
	`soar_evt_response_code` int,
	`soar_evt_error` text,
	`soar_evt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ssh_keys` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`fingerprint` varchar(255) NOT NULL,
	`publicKey` text NOT NULL,
	`privateKey` text NOT NULL,
	`keyType` enum('ed25519','rsa','ecdsa') NOT NULL DEFAULT 'ed25519',
	`bitLength` int,
	`passphrase` text,
	`isDefault` tinyint NOT NULL DEFAULT 0,
	`associatedServerId` int,
	`createdBy` varchar(64),
	`lastUsedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `team_invitations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`invite_email` varchar(320) NOT NULL,
	`invite_role` enum('user','admin','viewer','operator','team_lead','analyst','executive','client','soc') NOT NULL DEFAULT 'operator',
	`token_hash` varchar(128) NOT NULL,
	`invited_by` int NOT NULL,
	`invited_by_name` varchar(255),
	`invite_status` enum('pending','accepted','expired','revoked') NOT NULL DEFAULT 'pending',
	`expires_at` timestamp NOT NULL,
	`accepted_at` timestamp,
	`accepted_by_user_id` int,
	`invite_message` text,
	`invite_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`invite_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `tenant_memberships` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tm_tenant_id` int NOT NULL,
	`tm_user_id` int NOT NULL,
	`tm_role` enum('owner','admin','operator','viewer') NOT NULL DEFAULT 'viewer',
	`tm_joined_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_name` varchar(255) NOT NULL,
	`tenant_slug` varchar(128) NOT NULL,
	`tenant_logo_url` varchar(512),
	`tenant_primary_color` varchar(16),
	`tenant_is_active` tinyint NOT NULL DEFAULT 1,
	`tenant_max_users` int NOT NULL DEFAULT 50,
	`tenant_plan` enum('free','pro','enterprise') NOT NULL DEFAULT 'free',
	`tenant_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`tenant_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `threat_actor_abilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actorId` varchar(128) NOT NULL,
	`abilityId` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`tactic` varchar(128) NOT NULL,
	`techniqueId` varchar(32) NOT NULL,
	`techniqueName` varchar(255),
	`platforms` json,
	`singleton` tinyint DEFAULT 0,
	`repeatable` tinyint DEFAULT 1,
	`requirements` json,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `threat_actor_iocs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actorId` varchar(128) NOT NULL,
	`iocType` varchar(64) NOT NULL,
	`value` text NOT NULL,
	`description` text,
	`iocConfidence` enum('high','medium','low') DEFAULT 'medium',
	`iocFirstSeen` varchar(32),
	`iocLastSeen` varchar(32),
	`source` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `threat_actors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actorId` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`aliases` json,
	`actorType` enum('apt','cybercrime','ransomware','hacktivist','access_broker','influence_ops','unknown') NOT NULL,
	`origin` varchar(128),
	`description` text,
	`motivation` varchar(255),
	`firstSeen` varchar(32),
	`lastActive` varchar(32),
	`threatLevel` enum('critical','high','medium','low') DEFAULT 'medium',
	`sophistication` enum('nation-state','advanced','intermediate','basic') DEFAULT 'intermediate',
	`targetSectors` json,
	`targetRegions` json,
	`techniques` json,
	`tools` json,
	`malware` json,
	`calderaProfile` json,
	`activityTimeline` json,
	`stixId` varchar(128),
	`dataSource` varchar(128),
	`confidence` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ta_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `threat_group_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tgeActorId` varchar(128) NOT NULL,
	`eventType` enum('attack','campaign','infrastructure_change','malware_update','law_enforcement','affiliate_change','data_leak','ttp_evolution','group_merger','group_rebrand','new_tool','zero_day') NOT NULL,
	`tgeTitle` varchar(512) NOT NULL,
	`tgeDescription` text,
	`tgeSeverity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`tgeVictimName` varchar(512),
	`tgeVictimSector` varchar(128),
	`tgeVictimCountry` varchar(128),
	`tgeMitreTechniques` json,
	`tgeIocs` json,
	`tgeSource` varchar(255),
	`tgeSourceUrl` varchar(1024),
	`tgeConfidence` int DEFAULT 75,
	`eventDate` timestamp,
	`discoveredAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`tgeCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `threat_intel_updates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sweepType` enum('scheduled','manual','triggered') DEFAULT 'manual',
	`tiuStatus` enum('running','completed','failed') DEFAULT 'running',
	`groupsScanned` int DEFAULT 0,
	`updatesApplied` int DEFAULT 0,
	`newEventsFound` int DEFAULT 0,
	`newIocsFound` int DEFAULT 0,
	`newTtpsFound` int DEFAULT 0,
	`tiuSummary` text,
	`tiuDetails` json,
	`tiuErrors` json,
	`tiuStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`tiuCompletedAt` timestamp,
	`durationMs` int
);
--> statement-breakpoint
CREATE TABLE `ttp_knowledge` (
	`id` int AUTO_INCREMENT NOT NULL,
	`techniqueId` varchar(32) NOT NULL,
	`techniqueName` varchar(255) NOT NULL,
	`tactic` varchar(128) NOT NULL,
	`description` text,
	`executionMethods` json,
	`toolsUsed` json,
	`iocPatterns` json,
	`artifacts` json,
	`detectionRules` json,
	`eventLogSources` json,
	`calderaAbilities` json,
	`attackChainPosition` varchar(64),
	`prerequisiteTechniques` json,
	`followUpTechniques` json,
	`defensiveGaps` json,
	`redTeamValue` int,
	`blueTeamPriority` int,
	`purpleTeamNotes` text,
	`dataSource` varchar(128),
	`confidence` int,
	`lastEnriched` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`environmentalConstraints` json,
	`expectedTelemetry` json
);
--> statement-breakpoint
CREATE TABLE `typosquat_domains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`reconId` int NOT NULL,
	`originalDomain` varchar(255) NOT NULL,
	`permutedDomain` varchar(255) NOT NULL,
	`permutationType` varchar(64) NOT NULL,
	`isRegistered` tinyint DEFAULT 0,
	`dnsResolved` tinyint DEFAULT 0,
	`resolvedIp` varchar(45),
	`mxRecords` json,
	`spoofable` tinyint DEFAULT 0,
	`status` enum('discovered','recommended','purchased','configured','in_use','transferred','released') NOT NULL DEFAULT 'discovered',
	`registrar` varchar(255),
	`purchaseDate` timestamp,
	`expiryDate` timestamp,
	`annualCost` varchar(32),
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `underground_intel_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`uie_category` enum('ransomware','credential','iab','malware','influence','botnet','phishing','exploit','data_leak','other') NOT NULL,
	`uie_source` varchar(128) NOT NULL,
	`uie_source_url` varchar(1024),
	`uie_title` varchar(512) NOT NULL,
	`uie_description` text,
	`uie_severity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`uie_confidence` int DEFAULT 75,
	`uie_ioc_type` varchar(64),
	`uie_ioc_value` text,
	`uie_actor_name` varchar(255),
	`uie_actor_aliases` json,
	`uie_victim_name` varchar(512),
	`uie_victim_sector` varchar(128),
	`uie_victim_country` varchar(128),
	`uie_mitre_techniques` json,
	`uie_enriched` tinyint DEFAULT 0,
	`uie_enrichment_data` json,
	`uie_tags` json,
	`uie_raw_data` json,
	`uie_event_date` timestamp,
	`uie_ingested_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`uie_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`uie_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `unified_exploit_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`catalogId` varchar(128) NOT NULL,
	`exploitName` varchar(512) NOT NULL,
	`exploitDescription` text,
	`tier` enum('initial_access','post_access') NOT NULL,
	`exploitCategory` varchar(64) NOT NULL,
	`exploitSource` varchar(32) NOT NULL,
	`exploitCveIds` json,
	`exploitCvssScore` double,
	`exploitSeverity` varchar(16),
	`exploitMitreId` varchar(32),
	`exploitMitreName` varchar(255),
	`exploitMitreTactic` varchar(64),
	`exploitPlatform` varchar(64),
	`exploitType` varchar(32),
	`exploitReliability` varchar(16),
	`exploitDifficulty` varchar(16),
	`exploitEffectiveness` int,
	`msfModule` varchar(512),
	`msfRank` int,
	`edbId` varchar(32),
	`edbUrl` varchar(512),
	`phishingExploitId` varchar(64),
	`calderaAbilityId` varchar(128),
	`calderaAbilityPayload` json,
	`calderaSynced` tinyint DEFAULT 0,
	`calderaSyncedAt` timestamp,
	`agentStagerType` varchar(32),
	`agentStagerCommand` text,
	`agentStagerPayload` text,
	`agentCallbackUrl` text,
	`landingPageCode` text,
	`emailTemplateCode` text,
	`exploitTags` json,
	`exploitDetectionIndicators` json,
	`exploitPrerequisites` json,
	`exploitVerified` tinyint DEFAULT 0,
	`exploitLastVerifiedAt` timestamp,
	`exploitEnabled` tinyint DEFAULT 1,
	`exploitAuthor` varchar(255),
	`exploitDatePublished` varchar(32),
	`catalogCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`catalogUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `user_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_hash` varchar(64) NOT NULL,
	`session_user_id` int NOT NULL,
	`session_login_method` enum('oauth','saml','api_key') NOT NULL DEFAULT 'oauth',
	`session_saml_idp_id` int,
	`session_device_fingerprint` varchar(64),
	`session_ip_address` varchar(45),
	`session_geo_city` varchar(128),
	`session_geo_region` varchar(128),
	`session_geo_country` varchar(64),
	`session_geo_lat` double,
	`session_geo_lon` double,
	`session_user_agent` text,
	`session_browser_name` varchar(64),
	`session_browser_version` varchar(32),
	`session_os_name` varchar(64),
	`session_os_version` varchar(32),
	`session_device_type` varchar(32),
	`session_is_current` tinyint DEFAULT 0,
	`session_status` enum('active','expired','revoked') NOT NULL DEFAULT 'active',
	`session_last_activity_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`session_expires_at` timestamp NOT NULL,
	`session_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` int AUTO_INCREMENT NOT NULL,
	`openId` varchar(64) NOT NULL,
	`name` text,
	`email` varchar(320),
	`loginMethod` varchar(64),
	`role` enum('user','admin','viewer','operator','team_lead','analyst','executive','client','soc') NOT NULL DEFAULT 'operator',
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`lastSignedIn` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`avatar_url` text,
	`title` varchar(128),
	`department` varchar(128),
	`phone` varchar(32),
	`timezone` varchar(64) DEFAULT 'America/New_York',
	`status` enum('active','inactive','suspended','pending') NOT NULL DEFAULT 'active',
	`invited_by` int,
	`last_password_change` timestamp,
	`mfa_enabled` tinyint DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE `validation_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`validationRunId` int NOT NULL,
	`validationAssetId` int NOT NULL,
	`validationCveId` varchar(32) NOT NULL,
	`validationHostname` varchar(255) NOT NULL,
	`validationMsfModule` varchar(512),
	`resultMode` enum('check_only','auxiliary_scan','safe_exploit') NOT NULL,
	`validationResultStatus` enum('pending','running','validated','not_vulnerable','inconclusive','error','skipped','approved_pending') NOT NULL DEFAULT 'pending',
	`exploitable` tinyint NOT NULL DEFAULT 0,
	`validationRawOutput` text,
	`validationEvidence` json,
	`scoreAdjustment` double,
	`previousRiskScore` double,
	`newRiskScore` double,
	`validationDurationMs` int,
	`validationResultError` text,
	`validationResultCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`evidenceUrl` text,
	`evidenceArtifacts` json
);
--> statement-breakpoint
CREATE TABLE `validation_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`validationScanId` int NOT NULL,
	`validationMsfServerId` int NOT NULL,
	`validationEngagementId` int,
	`validationMode` enum('check_only','auxiliary_scan','safe_exploit') NOT NULL,
	`maxCandidates` int NOT NULL DEFAULT 10,
	`timeoutPerCandidate` int NOT NULL DEFAULT 60,
	`requireApproval` tinyint NOT NULL DEFAULT 1,
	`scopeRestrictions` json,
	`validationRunStatus` enum('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
	`totalCandidates` int NOT NULL DEFAULT 0,
	`validatedCount` int NOT NULL DEFAULT 0,
	`notVulnerableCount` int NOT NULL DEFAULT 0,
	`inconclusiveCount` int NOT NULL DEFAULT 0,
	`errorCount` int NOT NULL DEFAULT 0,
	`skippedCount` int NOT NULL DEFAULT 0,
	`avgScoreAdjustment` double,
	`validationOperatorId` varchar(255) NOT NULL,
	`validationStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`validationCompletedAt` timestamp,
	`totalDurationMs` int,
	`validationRunError` text
);
--> statement-breakpoint
CREATE TABLE `validation_schedules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`schedule_type` varchar(50) NOT NULL,
	`target_id` varchar(255),
	`target_label` varchar(255),
	`interval_hours` int NOT NULL DEFAULT 168,
	`cron_expression` varchar(100),
	`enabled` tinyint NOT NULL DEFAULT 1,
	`last_run_at` timestamp,
	`next_run_at` timestamp,
	`last_status` varchar(50),
	`last_error` text,
	`run_count` int NOT NULL DEFAULT 0,
	`config` json,
	`created_by` varchar(255),
	`created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vendor_cached_data` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integrationId` int NOT NULL,
	`dataType` enum('host','detection','incident','alert','threat','vulnerability','indicator','search_result') NOT NULL,
	`externalId` varchar(255),
	`title` varchar(512),
	`dataSeverity` enum('critical','high','medium','low','informational'),
	`dataStatus` varchar(64),
	`rawData` json,
	`normalizedData` json,
	`hostname` varchar(255),
	`ipAddress` varchar(45),
	`domain` varchar(255),
	`mitreAttackId` varchar(32),
	`detectedAt` bigint,
	`lastUpdatedAt` bigint,
	`cachedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vendor_integrations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vendor` enum('crowdstrike','sentinelone','defender','splunk','xsoar','sentinel','cortex_xdr') NOT NULL,
	`displayName` varchar(255) NOT NULL,
	`enabled` tinyint NOT NULL DEFAULT 0,
	`authConfig` json,
	`connectionConfig` json,
	`integrationStatus` enum('connected','disconnected','error','unconfigured') NOT NULL DEFAULT 'unconfigured',
	`lastHealthCheck` bigint,
	`lastError` text,
	`syncEnabled` tinyint NOT NULL DEFAULT 0,
	`syncIntervalMinutes` int DEFAULT 60,
	`lastSyncAt` bigint,
	`createdBy` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vendor_sync_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integrationId` int NOT NULL,
	`eventType` enum('hosts_sync','detections_sync','incidents_sync','alerts_sync','threats_sync','vulnerabilities_sync','search_sync','indicators_sync','health_check','manual_query') NOT NULL,
	`syncStatus` enum('success','partial','failed') NOT NULL,
	`recordsProcessed` int DEFAULT 0,
	`recordsFailed` int DEFAULT 0,
	`summary` json,
	`errorMessage` text,
	`durationMs` int,
	`triggeredBy` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vuln_scan_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vsf_import_id` int NOT NULL,
	`vsf_tenant_id` int,
	`vsf_cve_id` varchar(32),
	`vsf_title` varchar(512) NOT NULL,
	`vsf_severity` enum('critical','high','medium','low','info') NOT NULL,
	`vsf_cvss_score` double,
	`vsf_host_ip` varchar(45),
	`vsf_host_name` varchar(255),
	`vsf_port` int,
	`vsf_protocol` varchar(16),
	`vsf_description` text,
	`vsf_solution` text,
	`vsf_plugin_id` varchar(64),
	`vsf_exploit_available` tinyint DEFAULT 0,
	`vsf_attack_path_linked` tinyint DEFAULT 0,
	`vsf_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`vsf_corroboration_score` int,
	`vsf_corroboration_verdict` varchar(32),
	`vsf_corroboration_sources` int DEFAULT 0,
	`vsf_suppress_recommended` tinyint DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE `vuln_scan_imports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vsi_tenant_id` int,
	`vsi_scanner_type` enum('nessus','qualys','rapid7','openvas','custom') NOT NULL,
	`vsi_file_name` varchar(512) NOT NULL,
	`vsi_imported_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`vsi_total_hosts` int NOT NULL DEFAULT 0,
	`vsi_total_vulns` int NOT NULL DEFAULT 0,
	`vsi_critical` int NOT NULL DEFAULT 0,
	`vsi_high` int NOT NULL DEFAULT 0,
	`vsi_medium` int NOT NULL DEFAULT 0,
	`vsi_low` int NOT NULL DEFAULT 0,
	`vsi_imported_by` varchar(255)
);
--> statement-breakpoint
CREATE TABLE `web_app_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`alert_name` varchar(512),
	`severity` varchar(50) DEFAULT 'info',
	`confidence` double DEFAULT 0.5,
	`description` text,
	`solution` text,
	`reference_links` text,
	`cwe_id` int,
	`wasc_id` int,
	`url` varchar(2048),
	`method` varchar(10),
	`param` varchar(512),
	`attack` text,
	`evidence` text,
	`zap_plugin_id` varchar(50),
	`zap_alert_ref` varchar(50),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`mitre_attack_id` varchar(20),
	`mitre_attack_name` varchar(255),
	`mitre_tactic` varchar(100),
	`exploit_available` tinyint DEFAULT 0,
	`exploit_module_path` varchar(512),
	`caldera_ability_id` varchar(100),
	`ai_triage_verdict` varchar(50),
	`ai_triage_reason` text,
	`false_positive_score` double
);
--> statement-breakpoint
CREATE TABLE `web_app_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`target_url` varchar(2048) NOT NULL,
	`scan_name` varchar(255),
	`scan_type` varchar(50) NOT NULL DEFAULT 'full',
	`status` varchar(50) NOT NULL DEFAULT 'starting',
	`started_by` varchar(255),
	`started_at` timestamp,
	`completed_at` timestamp,
	`zap_spider_scan_id` varchar(100),
	`zap_active_scan_id` varchar(100),
	`spider_progress` int DEFAULT 0,
	`active_scan_progress` int DEFAULT 0,
	`urls_discovered` int DEFAULT 0,
	`total_alerts` int DEFAULT 0,
	`alert_counts` text,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`scan_mode` varchar(30) NOT NULL DEFAULT 'passive',
	`zap_ajax_spider_scan_id` varchar(100),
	`detected_tech_stack` text,
	`llm_scan_config` text,
	`scan_policy_name` varchar(100),
	`auth_configured` tinyint DEFAULT 0,
	`ajax_spider_used` tinyint DEFAULT 0,
	`attack_chain_id` varchar(100),
	`caldera_operation_id` varchar(100),
	`metasploit_session_id` varchar(100),
	`domain_intel_scan_id` int,
	`was_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `web_crawl_jobs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`jobId` varchar(64) NOT NULL,
	`scanId` int,
	`engagementId` int,
	`targetDomain` varchar(255) NOT NULL,
	`seedUrls` json,
	`maxDepth` int NOT NULL DEFAULT 2,
	`maxPages` int NOT NULL DEFAULT 50,
	`timeoutMs` int NOT NULL DEFAULT 30000,
	`respectRobotsTxt` tinyint NOT NULL DEFAULT 1,
	`jobStatus` enum('queued','running','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
	`totalUrlsQueued` int DEFAULT 0,
	`totalUrlsCrawled` int DEFAULT 0,
	`totalUrlsFailed` int DEFAULT 0,
	`totalFindings` int DEFAULT 0,
	`findingSummary` json,
	`technologiesSummary` json,
	`securityGrade` varchar(4),
	`startedBy` varchar(64),
	`startedAt` bigint,
	`completedAt` bigint,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `web_crawl_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int,
	`assetId` int,
	`engagementId` int,
	`targetUrl` varchar(2048) NOT NULL,
	`finalUrl` varchar(2048),
	`domain` varchar(255) NOT NULL,
	`crawlStatus` enum('queued','crawling','completed','failed','timeout') NOT NULL DEFAULT 'queued',
	`httpStatus` int,
	`responseTimeMs` int,
	`contentType` varchar(128),
	`contentLength` int,
	`depth` int NOT NULL DEFAULT 0,
	`parentCrawlId` int,
	`securityHeaders` json,
	`securityHeaderGrade` varchar(4),
	`detectedTechnologies` json,
	`serverHeader` varchar(255),
	`poweredBy` varchar(255),
	`pageTitle` varchar(512),
	`metaDescription` text,
	`internalLinks` json,
	`externalLinks` json,
	`resourceUrls` json,
	`forms` json,
	`exposedPaths` json,
	`robotsTxt` text,
	`securityTxt` text,
	`sitemapUrls` json,
	`cookies` json,
	`tlsInfo` json,
	`findings` json,
	`findingCounts` json,
	`totalFindings` int DEFAULT 0,
	`rawHeaders` json,
	`crawlConfig` json,
	`crawledBy` varchar(64),
	`startedAt` bigint,
	`completedAt` bigint,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `webhook_deliveries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhookId` varchar(64) NOT NULL,
	`event` varchar(100) NOT NULL,
	`payload` json,
	`responseStatus` int,
	`responseBody` text,
	`success` tinyint DEFAULT 0,
	`deliveredAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `webhook_endpoints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhookId` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`url` text NOT NULL,
	`secret` varchar(255),
	`events` json,
	`format` varchar(50) DEFAULT 'json',
	`headers` json,
	`enabled` tinyint DEFAULT 1,
	`lastTriggered` timestamp,
	`failCount` int DEFAULT 0,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `workflow_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` varchar(64) NOT NULL,
	`workflow_id` varchar(64) NOT NULL,
	`workflow_name` varchar(255) NOT NULL,
	`current_step_index` int NOT NULL DEFAULT 0,
	`total_steps` int NOT NULL,
	`status` enum('in_progress','completed','abandoned') NOT NULL DEFAULT 'in_progress',
	`step_data` json,
	`context_data` json,
	`started_at` bigint NOT NULL,
	`last_activity_at` bigint NOT NULL,
	`completed_at` bigint
);
--> statement-breakpoint
CREATE TABLE `workflow_step_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` int NOT NULL,
	`step_index` int NOT NULL,
	`step_id` varchar(64) NOT NULL,
	`step_name` varchar(255) NOT NULL,
	`status` enum('pending','in_progress','completed','skipped','failed') NOT NULL DEFAULT 'pending',
	`input_data` json,
	`output_data` json,
	`linked_entity_type` varchar(64),
	`linked_entity_id` varchar(255),
	`started_at` bigint,
	`completed_at` bigint
);
--> statement-breakpoint
CREATE TABLE `zap_proxy_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`session_name` varchar(256) NOT NULL,
	`target_url` varchar(1024) NOT NULL,
	`status` enum('initializing','active','crawling','scanning','paused','completed','error') NOT NULL DEFAULT 'initializing',
	`proxy_port` int,
	`auth_type` enum('none','form_login','bearer_token','session_cookie','basic_auth') DEFAULT 'none',
	`auth_config` json,
	`waf_evasion_vendor` varchar(64),
	`urls_discovered` int DEFAULT 0,
	`requests_intercepted` int DEFAULT 0,
	`alerts_found` int DEFAULT 0,
	`alerts_critical` int DEFAULT 0,
	`alerts_high` int DEFAULT 0,
	`alerts_medium` int DEFAULT 0,
	`alerts_low` int DEFAULT 0,
	`alerts_info` int DEFAULT 0,
	`scan_progress` int DEFAULT 0,
	`domain_intel_scan_id` int,
	`report_html` mediumtext,
	`started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
ALTER TABLE `agent_audit_log` ADD CONSTRAINT `agent_audit_log_agentId_agent_deployments_id_fk` FOREIGN KEY (`agentId`) REFERENCES `agent_deployments`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `agent_tasks` ADD CONSTRAINT `agent_tasks_agentId_agent_deployments_id_fk` FOREIGN KEY (`agentId`) REFERENCES `agent_deployments`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `campaign_engagements` ADD CONSTRAINT `campaign_engagements_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD CONSTRAINT `discovered_assets_scanId_domain_intel_scans_id_fk` FOREIGN KEY (`scanId`) REFERENCES `domain_intel_scans`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `domain_recon` ADD CONSTRAINT `domain_recon_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `engagement_reports` ADD CONSTRAINT `engagement_reports_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD CONSTRAINT `evidence_chain_of_custody_evidenceId_evidence_items_evidenceId_fk` FOREIGN KEY (`evidenceId`) REFERENCES `evidence_items`(`evidenceId`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `osint_findings` ADD CONSTRAINT `osint_findings_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `server_credentials` ADD CONSTRAINT `server_credentials_serverId_server_configs_id_fk` FOREIGN KEY (`serverId`) REFERENCES `server_configs`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `ability_graph_edges_edge_id_unique` ON `ability_graph_edges` (`edge_id`);--> statement-breakpoint
CREATE INDEX `ability_graph_nodes_node_id_unique` ON `ability_graph_nodes` (`node_id`);--> statement-breakpoint
CREATE INDEX `ability_graphs_graph_id_unique` ON `ability_graphs` (`graph_id`);--> statement-breakpoint
CREATE INDEX `active_sessions_session_token_unique` ON `active_sessions` (`session_token`);--> statement-breakpoint
CREATE INDEX `idx_technique_id` ON `atomic_test_executions` (`technique_id`);--> statement-breakpoint
CREATE INDEX `idx_status` ON `atomic_test_executions` (`status`);--> statement-breakpoint
CREATE INDEX `idx_executed_by` ON `atomic_test_executions` (`executed_by`);--> statement-breakpoint
CREATE INDEX `idx_attack_chain` ON `atomic_test_executions` (`attack_chain_id`);--> statement-breakpoint
CREATE INDEX `idx_technique_id` ON `atomic_tests` (`technique_id`);--> statement-breakpoint
CREATE INDEX `idx_mitre_tactic` ON `atomic_tests` (`mitre_tactic`);--> statement-breakpoint
CREATE INDEX `idx_executor_type` ON `atomic_tests` (`executor_type`);--> statement-breakpoint
CREATE INDEX `idx_supported_platforms` ON `atomic_tests` (`supported_platforms`);--> statement-breakpoint
CREATE INDEX `guid` ON `atomic_tests` (`guid`);--> statement-breakpoint
CREATE INDEX `pathId` ON `attack_paths` (`pathId`);--> statement-breakpoint
CREATE INDEX `templateId` ON `attack_sequence_templates` (`templateId`);--> statement-breakpoint
CREATE INDEX `caldera_accounts_email_unique` ON `caldera_accounts` (`email`);--> statement-breakpoint
CREATE INDEX `campaign_archetypes_slug_unique` ON `campaign_archetypes` (`slug`);--> statement-breakpoint
CREATE INDEX `chain_runs_chain_id_unique` ON `chain_runs` (`chain_id`);--> statement-breakpoint
CREATE INDEX `idx_chain_stage_chain_id` ON `chain_stage_results` (`chain_id`);--> statement-breakpoint
CREATE INDEX `baseline_id` ON `config_baselines` (`baseline_id`);--> statement-breakpoint
CREATE INDEX `alert_id` ON `config_drift_alerts` (`alert_id`);--> statement-breakpoint
CREATE INDEX `dfr_feed_name` ON `darkweb_feed_registry` (`dfr_feed_name`);--> statement-breakpoint
CREATE INDEX `defense_scores_score_id_unique` ON `defense_scores` (`score_id`);--> statement-breakpoint
CREATE INDEX `testId` ON `detection_tests` (`testId`);--> statement-breakpoint
CREATE INDEX `engagement_shares_token_unique` ON `engagement_shares` (`token`);--> statement-breakpoint
CREATE INDEX `idx_incident_id` ON `error_incidents` (`incidentId`);--> statement-breakpoint
CREATE INDEX `idx_scope` ON `error_incidents` (`scope`);--> statement-breakpoint
CREATE INDEX `idx_created` ON `error_incidents` (`createdAt`);--> statement-breakpoint
CREATE INDEX `evidenceId` ON `evidence_items` (`evidenceId`);--> statement-breakpoint
CREATE INDEX `idx_cveId` ON `exploit_intelligence` (`cveId`);--> statement-breakpoint
CREATE INDEX `idx_ei_source` ON `exploit_intelligence` (`ei_source`);--> statement-breakpoint
CREATE INDEX `idx_engagement` ON `exploit_plan_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `idx_gate` ON `exploit_plan_history` (`gate_id`);--> statement-breakpoint
CREATE INDEX `violationId` ON `guardrail_violations` (`violationId`);--> statement-breakpoint
CREATE INDEX `idx_source_sourceId` ON `incident_reports` (`source`,`sourceId`);--> statement-breakpoint
CREATE INDEX `info_ops_campaigns_ioCampaignId_unique` ON `info_ops_campaigns` (`ioCampaignId`);--> statement-breakpoint
CREATE INDEX `ksi_definitions_ksi_id_unique` ON `ksi_definitions` (`ksi_id`);--> statement-breakpoint
CREATE INDEX `ksi_evidence_evidence_id_unique` ON `ksi_evidence` (`evidence_id`);--> statement-breakpoint
CREATE INDEX `ksi_evidence_chains_chain_id_unique` ON `ksi_evidence_chains` (`chain_id`);--> statement-breakpoint
CREATE INDEX `ksi_validation_runs_run_id_unique` ON `ksi_validation_runs` (`run_id`);--> statement-breakpoint
CREATE INDEX `ksi_validation_schedules_schedule_id_unique` ON `ksi_validation_schedules` (`schedule_id`);--> statement-breakpoint
CREATE INDEX `idx_type_status` ON `mtls_certificates` (`type`,`status`);--> statement-breakpoint
CREATE INDEX `idx_c2server` ON `mtls_certificates` (`c2ServerId`,`status`);--> statement-breakpoint
CREATE INDEX `obs_alert_id` ON `observation_alert_history` (`obs_alert_id`);--> statement-breakpoint
CREATE INDEX `obs_rule_id` ON `observation_alert_rules` (`obs_rule_id`);--> statement-breakpoint
CREATE INDEX `idx_engagement` ON `offensive_audit_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `idx_operator` ON `offensive_audit_log` (`operator_id`);--> statement-breakpoint
CREATE INDEX `idx_action_type` ON `offensive_audit_log` (`action_type`);--> statement-breakpoint
CREATE INDEX `idx_risk_tier` ON `offensive_audit_log` (`risk_tier`);--> statement-breakpoint
CREATE INDEX `idx_created_at` ON `offensive_audit_log` (`created_at`);--> statement-breakpoint
CREATE INDEX `oscal_exports_export_id_unique` ON `oscal_exports` (`export_id`);--> statement-breakpoint
CREATE INDEX `ransomware_groups_groupName_unique` ON `ransomware_groups` (`groupName`);--> statement-breakpoint
CREATE INDEX `observationId` ON `scan_observations` (`observationId`);--> statement-breakpoint
CREATE INDEX `profileId` ON `scan_policies` (`profileId`);--> statement-breakpoint
CREATE INDEX `riskId` ON `scan_risk_cards` (`riskId`);--> statement-breakpoint
CREATE INDEX `signalId` ON `scan_signals` (`signalId`);--> statement-breakpoint
CREATE INDEX `team_invitations_token_hash_unique` ON `team_invitations` (`token_hash`);--> statement-breakpoint
CREATE INDEX `threat_actors_actorId_unique` ON `threat_actors` (`actorId`);--> statement-breakpoint
CREATE INDEX `ttp_knowledge_techniqueId_unique` ON `ttp_knowledge` (`techniqueId`);--> statement-breakpoint
CREATE INDEX `unified_exploit_catalog_catalogId_unique` ON `unified_exploit_catalog` (`catalogId`);--> statement-breakpoint
CREATE INDEX `user_sessions_session_hash_unique` ON `user_sessions` (`session_hash`);--> statement-breakpoint
CREATE INDEX `users_openId_unique` ON `users` (`openId`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_integration` ON `vendor_cached_data` (`integrationId`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_type` ON `vendor_cached_data` (`dataType`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_hostname` ON `vendor_cached_data` (`hostname`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_ip` ON `vendor_cached_data` (`ipAddress`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_mitre` ON `vendor_cached_data` (`mitreAttackId`);--> statement-breakpoint
CREATE INDEX `web_crawl_jobs_jobId_unique` ON `web_crawl_jobs` (`jobId`);--> statement-breakpoint
CREATE INDEX `webhookId` ON `webhook_endpoints` (`webhookId`);