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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `ac3_report_artifacts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`artifact_id` varchar(64) NOT NULL,
	`report_id` varchar(64) NOT NULL,
	`finding_id` varchar(64),
	`artifact_type` varchar(32) NOT NULL DEFAULT 'screenshot',
	`label` varchar(32) NOT NULL,
	`filename` varchar(255),
	`url` text,
	`description` text,
	`mime_type` varchar(128),
	`file_size` int,
	`captured_at` bigint,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ac3_report_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rf_finding_id` varchar(64) NOT NULL,
	`rf_report_id` varchar(64) NOT NULL,
	`rf_sort_order` int DEFAULT 0,
	`rf_severity` enum('critical','high','moderate','low','informational') NOT NULL,
	`rf_evidence` json,
	`rf_attack_techniques` json,
	`rf_controls` json,
	`rf_assets` json,
	`rf_cvss_score` varchar(8),
	`rf_cvss_vector` varchar(128),
	`rf_title` varchar(512) NOT NULL,
	`rf_summary` text,
	`rf_business_impact` text,
	`rf_technical_details` mediumtext,
	`rf_remediation` text,
	`rf_source_task_id` varchar(64),
	`rf_source_campaign_id` varchar(64),
	`rf_source_agent_id` varchar(64),
	`rf_narrative_status` enum('pending','drafted','reviewed','approved') DEFAULT 'pending',
	`rf_reviewed_by` varchar(255),
	`rf_reviewed_at` bigint,
	`rf_created_at` bigint NOT NULL,
	`rf_updated_at` bigint NOT NULL,
	`rf_source_module` varchar(128),
	`rf_source_event_id` varchar(128),
	`rf_risk_owner` enum('customer','vendor','shared') DEFAULT 'customer',
	`rf_vendor_name` varchar(128)
);
--> statement-breakpoint
CREATE TABLE `ac3_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rpt_report_id` varchar(64) NOT NULL,
	`rpt_name` varchar(255) NOT NULL,
	`rpt_status` enum('draft','generating','review','approved','final') NOT NULL DEFAULT 'draft',
	`rpt_client_name` varchar(255),
	`rpt_system_name` varchar(255),
	`rpt_assessment_type` enum('penetration_test','red_team','purple_team','vulnerability_assessment','hybrid') DEFAULT 'penetration_test',
	`rpt_fedramp_level` enum('low','moderate','high','li-saas'),
	`rpt_cloud_provider` varchar(255),
	`rpt_service_model` varchar(128),
	`rpt_window_start` bigint,
	`rpt_window_end` bigint,
	`rpt_version` varchar(32) DEFAULT '1.0',
	`rpt_scope_domains` json,
	`rpt_scope_assets` json,
	`rpt_approved_vectors` json,
	`rpt_out_of_scope` json,
	`rpt_exec_risk_statement` text,
	`rpt_exec_rating` enum('critical','high','moderate','low','informational'),
	`rpt_exec_strengths` json,
	`rpt_exec_gaps` json,
	`rpt_exec_narrative` mediumtext,
	`rpt_qa_status` enum('pending','pass','revise') DEFAULT 'pending',
	`rpt_qa_issues` json,
	`rpt_qa_reviewed_at` bigint,
	`rpt_campaign_id` varchar(64),
	`rpt_output_url` text,
	`rpt_output_format` varchar(16),
	`rpt_created_by` varchar(255),
	`rpt_created_at` bigint NOT NULL,
	`rpt_updated_at` bigint NOT NULL,
	`rpt_docx_url` text,
	`compliance_framework` varchar(32) NOT NULL DEFAULT 'nist_800_53_r5',
	`rpt_scope_exclusions` json,
	`rpt_tools_used` json,
	`rpt_test_phases` json,
	`engagement_id` int,
	`rpt_intelligence_gaps` json
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
	`iabCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`iabUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`priority_tags` json,
	`priority_score` int DEFAULT 0,
	`targets_us_gov` tinyint DEFAULT 0,
	`targets_ics_scada` tinyint DEFAULT 0,
	`priority_reason` text,
	`priority_level` varchar(16)
);
--> statement-breakpoint
CREATE TABLE `accuracy_comparisons` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(128) NOT NULL,
	`engagement_id` varchar(128),
	`target_preset` varchar(128) NOT NULL,
	`target_url` varchar(512),
	`scan_type` varchar(64),
	`precision` double,
	`recall` double,
	`f1_score` double,
	`true_positives` int DEFAULT 0,
	`false_positives` int DEFAULT 0,
	`false_negatives` int DEFAULT 0,
	`total_findings` int DEFAULT 0,
	`total_ground_truth` int DEFAULT 0,
	`matched_findings` json,
	`missed_vulns` json,
	`false_positive_findings` json,
	`f1_delta` double,
	`precision_delta` double,
	`recall_delta` double,
	`knowledge_modules_used` json,
	`scan_duration_ms` int,
	`scored_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `active_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`account_id` int NOT NULL,
	`session_token` varchar(255) NOT NULL,
	`ip_address` varchar(45),
	`user_agent` text,
	`device_info` varchar(255),
	`last_activity_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`expires_at` timestamp NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `activity_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`serverId` int,
	`action` varchar(255) NOT NULL,
	`details` text,
	`ipAddress` varchar(45),
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`conn_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`conn_updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`ad_enum_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `adjustment_effectiveness` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ae_adjustment_type` varchar(64) NOT NULL,
	`ae_failure_category` varchar(64) NOT NULL,
	`ae_service` varchar(128) NOT NULL,
	`ae_engagement_id` int,
	`ae_target` varchar(255),
	`ae_port` int,
	`ae_success` tinyint NOT NULL,
	`ae_retry_number` int,
	`ae_base_priority` int,
	`ae_adjusted_priority` int,
	`ae_exec_duration_ms` int,
	`ae_exploit_output` text,
	`ae_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
CREATE TABLE `agent_definitions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ad_agent_id` varchar(64) NOT NULL,
	`ad_name` varchar(255) NOT NULL,
	`ad_category` enum('osint_analyst','pentester','social_engineer','red_team_operator','report_writer','recon_analyst','exploit_selector','evasion_optimizer','lateral_planner','persistence_engineer','scan_analyst','attack_planner','vuln_verifier','threat_mapper','ops_decider','caldera_builder','custom') NOT NULL,
	`ad_persona` text NOT NULL,
	`ad_mission` text NOT NULL,
	`ad_core_rules` json NOT NULL,
	`ad_evidence_tags` json,
	`ad_deliverable_templates` json,
	`ad_workflow_steps` json,
	`ad_tool_access` json,
	`ad_mitre_tactics` json,
	`ad_llm_caller_prefix` varchar(128),
	`ad_priority` enum('essential','standard','bulk') DEFAULT 'standard',
	`ad_status` enum('active','draft','deprecated','testing') DEFAULT 'draft',
	`ad_version` int NOT NULL DEFAULT 1,
	`ad_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ad_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`abt_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`aap_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `approved_exploit_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`catalog_entry_id` varchar(128) NOT NULL,
	`quarantine_id` varchar(128) NOT NULL,
	`exploit_title` varchar(512) NOT NULL,
	`exploit_description` text,
	`exploit_code` text,
	`exploit_language` varchar(64),
	`exploit_platform` varchar(64),
	`exploit_service` varchar(128),
	`exploit_cve_ids` json,
	`exploit_tags` json,
	`exploit_source` varchar(32) NOT NULL DEFAULT 'ac3_history',
	`reliability_score` int DEFAULT 90,
	`approved_by` varchar(255) NOT NULL,
	`approval_notes` text,
	`source_pipeline` varchar(128) NOT NULL,
	`original_engagement_id` int,
	`approved_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`aim_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`aim_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`last_synced_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`acr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
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
	`acc_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`acc_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`apge_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`apgn_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`ast_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
CREATE TABLE `benchmark_scan_plan_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rule_id` varchar(64) NOT NULL,
	`source_run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`missed_vuln_title` varchar(255) NOT NULL,
	`missed_vuln_category` varchar(128) NOT NULL,
	`missed_vuln_severity` varchar(32) NOT NULL,
	`recommended_tool` varchar(64) NOT NULL,
	`recommended_action` text NOT NULL,
	`recommended_flags` text,
	`applicable_categories` json,
	`applicable_lab_types` json,
	`confidence` double DEFAULT 0.5,
	`is_active` tinyint DEFAULT 1,
	`applied_count` int DEFAULT 0,
	`last_applied_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `benchmark_tool_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`tool` varchar(64) NOT NULL,
	`detected_vulns` json,
	`missed_vulns` json,
	`false_positive_vulns` json,
	`f1_score` double,
	`precision` double,
	`recall` double,
	`finding_count` int DEFAULT 0,
	`scan_duration_ms` int,
	`exit_code` int,
	`timed_out` tinyint DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`submitted_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_llm_training_samples` (
	`id` int AUTO_INCREMENT NOT NULL,
	`finding_id` int,
	`category` enum('vuln_pattern','exploit_chain','report_template','scope_recon','cwe_analysis','bounty_strategy','novel_finding') NOT NULL,
	`quality_score` decimal(3,2) DEFAULT '0.00',
	`bounty_amount` decimal(12,2) DEFAULT '0.00',
	`severity_rating` varchar(32),
	`cwe_id` varchar(32),
	`cve_ids` json,
	`program_handle` varchar(255),
	`program_name` varchar(512),
	`asset_type` varchar(64),
	`asset_identifier` varchar(512),
	`system_prompt` text NOT NULL,
	`user_prompt` text NOT NULL,
	`assistant_response` text NOT NULL,
	`raw_title` varchar(512),
	`raw_summary` text,
	`enrichment_status` enum('raw','enriched','reviewed','exported') DEFAULT 'raw',
	`enriched_narrative` text,
	`attack_technique` text,
	`remediation_guidance` text,
	`mitre_techniques` json,
	`tags` json,
	`exported_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_program_scopes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`program_id` int,
	`platform` varchar(32) NOT NULL,
	`program_handle` varchar(255) NOT NULL,
	`external_id` varchar(128),
	`asset_type` varchar(64) NOT NULL,
	`asset_identifier` varchar(1024) NOT NULL,
	`eligible_for_bounty` tinyint DEFAULT 0,
	`eligible_for_submission` tinyint DEFAULT 1,
	`max_severity` varchar(32),
	`confidentiality_requirement` varchar(32),
	`integrity_requirement` varchar(32),
	`availability_requirement` varchar(32),
	`instruction` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_program_weaknesses` (
	`id` int AUTO_INCREMENT NOT NULL,
	`program_id` int,
	`platform` varchar(32) NOT NULL,
	`program_handle` varchar(255) NOT NULL,
	`external_id` varchar(128),
	`cwe_id` varchar(32),
	`name` varchar(512) NOT NULL,
	`description` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`started_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`completed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `bug_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`user_name` varchar(255),
	`title` varchar(512) NOT NULL,
	`description` text NOT NULL,
	`page` varchar(512),
	`severity` varchar(32) NOT NULL DEFAULT 'medium',
	`category` varchar(64) NOT NULL DEFAULT 'bug',
	`steps_to_reproduce` text,
	`expected_behavior` text,
	`actual_behavior` text,
	`browser_info` varchar(512),
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`admin_notes` text,
	`resolved_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `burp_scan_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`credential_id` int NOT NULL,
	`user_id` varchar(128) NOT NULL,
	`scan_id` varchar(255),
	`edition` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`progress` int NOT NULL DEFAULT 0,
	`target_urls` json,
	`issue_count` int NOT NULL DEFAULT 0,
	`imported_count` int NOT NULL DEFAULT 0,
	`scan_config_name` varchar(255),
	`error` text,
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`last_poll_at` bigint,
	`poll_count` int NOT NULL DEFAULT 0,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `c2_execution_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`technique_id` varchar(64) NOT NULL,
	`cel_framework` varchar(64) NOT NULL,
	`cel_success` tinyint NOT NULL,
	`confidence_adjustment` double,
	`target_platform` varchar(64),
	`target_arch` varchar(32),
	`exit_code` int,
	`lessons_learned` json,
	`cel_extracted_artifacts` json,
	`observed_telemetry` json,
	`cel_constraints` json,
	`cel_engagement_id` int,
	`cel_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`lastUpdated` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `campaign_run_states` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaign_id` int NOT NULL,
	`is_running` tinyint NOT NULL DEFAULT 0,
	`is_paused` tinyint NOT NULL DEFAULT 0,
	`current_stage_id` int,
	`started_at` bigint,
	`last_heartbeat` bigint,
	`node_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`chat_msg_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `chat_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chat_session_user_id` int NOT NULL,
	`chat_session_title` varchar(255) DEFAULT 'New Chat',
	`chat_session_role` varchar(64) NOT NULL DEFAULT 'operator',
	`chat_session_message_count` int DEFAULT 0,
	`chat_session_last_message_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`chat_session_archived` tinyint DEFAULT 0,
	`chat_session_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`chat_session_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`cs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `cicd_baselines` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`commit_sha` varchar(64) NOT NULL,
	`branch` varchar(255),
	`finding_hashes` json NOT NULL,
	`total_findings` int NOT NULL DEFAULT 0,
	`created_at` bigint NOT NULL,
	`created_by` varchar(255)
);
--> statement-breakpoint
CREATE TABLE `cicd_compliance_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`run_id` int NOT NULL,
	`framework` varchar(50) NOT NULL,
	`compliance_score` decimal(5,2) NOT NULL DEFAULT '0',
	`total_controls` int NOT NULL DEFAULT 0,
	`passed` int NOT NULL DEFAULT 0,
	`failed` int NOT NULL DEFAULT 0,
	`partial_count` int NOT NULL DEFAULT 0,
	`not_tested` int NOT NULL DEFAULT 0,
	`risk_level` varchar(20) NOT NULL DEFAULT 'medium',
	`category_scores` json,
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `cicd_pipeline_access` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`user_id` int NOT NULL,
	`role` enum('owner','editor','viewer') NOT NULL DEFAULT 'viewer',
	`granted_by` int NOT NULL,
	`granted_at` datetime DEFAULT 'CURRENT_TIMESTAMP'
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
	`cicd_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`cicd_allowed_domains` json,
	`cicd_scan_types` json,
	`cicd_last_baseline_id` int,
	`cicd_engagement_id` int,
	`cicd_sector_context` varchar(128),
	`cicd_schedule_cron` varchar(128),
	`cicd_schedule_enabled` tinyint DEFAULT 0,
	`cicd_schedule_target_url` varchar(512),
	`cicd_schedule_last_run` timestamp,
	`cicd_schedule_next_run` timestamp,
	`cicd_baseline_run_id` int
);
--> statement-breakpoint
CREATE TABLE `cicd_run_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` int NOT NULL,
	`pipeline_id` int NOT NULL,
	`title` varchar(512) NOT NULL,
	`title_hash` varchar(64) NOT NULL,
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`cvss` double,
	`scanner` varchar(64) NOT NULL,
	`url` varchar(1024),
	`description` text,
	`cwe_id` varchar(32),
	`is_new` tinyint NOT NULL DEFAULT 1,
	`created_at` bigint NOT NULL
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
	`cicd_report_url` text,
	`cicd_started_at` timestamp,
	`cicd_completed_at` timestamp,
	`cicd_run_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`cicd_new_findings` int DEFAULT 0,
	`cicd_fixed_findings` int DEFAULT 0,
	`cicd_run_engagement_id` int,
	`cicd_threat_context` json
);
--> statement-breakpoint
CREATE TABLE `cicd_sbom_artifacts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` int NOT NULL,
	`pipeline_id` int NOT NULL,
	`image_ref` varchar(512) NOT NULL,
	`format` enum('cyclonedx','spdx') NOT NULL DEFAULT 'cyclonedx',
	`storage_url` varchar(1024) NOT NULL,
	`storage_key` varchar(512) NOT NULL,
	`package_count` int DEFAULT 0,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `cicd_webhook_deliveries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`run_id` int,
	`event_type` varchar(128) NOT NULL,
	`payload_summary` text,
	`response_status` int,
	`response_body` text,
	`delivery_status` enum('pending','delivered','failed','retrying') NOT NULL DEFAULT 'pending',
	`attempt_count` int NOT NULL DEFAULT 0,
	`max_retries` int NOT NULL DEFAULT 3,
	`next_retry_at` timestamp,
	`last_attempt_at` timestamp,
	`delivered_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`webhook_url` varchar(512),
	`error_message` text,
	`duration_ms` int
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `cloud_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int,
	`engagement_id` int,
	`cred_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL,
	`credential_name` varchar(255) NOT NULL,
	`credential_type` enum('aws_access_key','aws_assume_role','aws_session_token','azure_client_secret','azure_managed_identity','azure_cli','gcp_service_account_key','gcp_workload_identity','gcp_oauth','do_api_token','alibaba_access_key','oracle_api_key') NOT NULL,
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
	`cred_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`cred_updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `cloud_enumeration_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`credential_id` int NOT NULL,
	`enum_provider_id` int,
	`enum_engagement_id` int,
	`enum_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL,
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
	`enum_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `cloud_providers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL,
	`account_id` varchar(255) NOT NULL,
	`account_alias` varchar(255),
	`region` varchar(64),
	`status` enum('active','inactive','scanning') NOT NULL DEFAULT 'active',
	`last_scan_at` timestamp,
	`config` json,
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
CREATE TABLE `company_intel_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cip_tenant_id` int,
	`cip_domain` varchar(512) NOT NULL,
	`cip_company_name` varchar(512),
	`cip_industry` varchar(255),
	`cip_sector` varchar(255),
	`cip_description` text,
	`cip_employee_count` int,
	`cip_employee_range` varchar(64),
	`cip_revenue` varchar(128),
	`cip_funding_stage` varchar(64),
	`cip_publicly_traded` tinyint DEFAULT 0,
	`cip_ticker` varchar(16),
	`cip_founded_year` int,
	`cip_company_type` varchar(64),
	`cip_headquarters` json,
	`cip_locations` json,
	`cip_specialties` json,
	`cip_products` json,
	`cip_technologies` json,
	`cip_social_media` json,
	`cip_naics_code` varchar(16),
	`cip_sic_code` varchar(16),
	`cip_data_classifications` json,
	`cip_subsidiaries` json,
	`cip_parent_company` varchar(255),
	`cip_executive_team` json,
	`cip_customer_corrected` tinyint NOT NULL DEFAULT 0,
	`cip_corrected_at` timestamp,
	`cip_corrected_by` int,
	`cip_correction_notes` text,
	`cip_sources` json,
	`cip_confidence` int DEFAULT 0,
	`cip_last_enriched_at` timestamp,
	`cip_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`cip_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`cbr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`cda_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`scanned_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `connector_performance_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`connector` varchar(128) NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`scan_id` int NOT NULL,
	`observations` int NOT NULL DEFAULT 0,
	`duration_ms` int NOT NULL DEFAULT 0,
	`status` enum('completed','failed','skipped','timeout') NOT NULL DEFAULT 'completed',
	`rate_limited` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `container_vulnerabilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_run_id` int NOT NULL,
	`image_name` varchar(512) NOT NULL,
	`image_tag` varchar(128),
	`image_digest` varchar(128),
	`vuln_id` varchar(64) NOT NULL,
	`severity` enum('critical','high','medium','low','unknown') NOT NULL DEFAULT 'unknown',
	`pkg_name` varchar(255) NOT NULL,
	`installed_version` varchar(128),
	`fixed_version` varchar(128),
	`title` text,
	`description` text,
	`primary_url` text,
	`data_source` varchar(128),
	`published_date` varchar(32),
	`cvss_score` varchar(10),
	`created_at` bigint NOT NULL
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
	`cr_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`alert_hist_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`alert_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`started_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`ce_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`discovered_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`rotation_audit_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`rotation_policy_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`rotation_policy_updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `cspm_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_run_id` int NOT NULL,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`finding_uid` varchar(512),
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`status` enum('fail','pass','warning','manual','not_available') NOT NULL DEFAULT 'fail',
	`provider` varchar(64) NOT NULL,
	`service` varchar(128),
	`region` varchar(64),
	`resource_arn` varchar(512),
	`resource_name` varchar(255),
	`resource_type` varchar(128),
	`check_id` varchar(255),
	`check_title` varchar(512),
	`description` text,
	`risk_details` text,
	`remediation` text,
	`compliance_frameworks` json,
	`categories` json,
	`raw_finding` json,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `cspm_scan_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`credential_id` int,
	`engagement_id` int,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`scan_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle','kubernetes','docker','filesystem') NOT NULL,
	`scan_status` enum('pending','running','completed','error','cancelled') NOT NULL DEFAULT 'pending',
	`scan_scope` json,
	`total_findings` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`info_count` int DEFAULT 0,
	`pass_count` int DEFAULT 0,
	`fail_count` int DEFAULT 0,
	`compliance_score` int,
	`compliance_framework` varchar(128),
	`scan_duration_ms` int,
	`raw_output_url` text,
	`error_message` text,
	`triggered_by` varchar(255),
	`scan_started_at` bigint,
	`scan_completed_at` bigint,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `customer_accounts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_id` int NOT NULL,
	`ca_email` varchar(320) NOT NULL,
	`password_hash` varchar(255) NOT NULL,
	`ca_name` varchar(255) NOT NULL,
	`ca_title` varchar(128),
	`ca_phone` varchar(32),
	`ca_role` enum('primary_contact','technical_contact','executive','viewer') NOT NULL DEFAULT 'viewer',
	`ca_status` enum('active','inactive','locked','pending_verification') NOT NULL DEFAULT 'pending_verification',
	`email_verified` tinyint NOT NULL DEFAULT 0,
	`verification_token` varchar(128),
	`reset_token` varchar(128),
	`reset_token_expiry` timestamp,
	`ca_last_login_at` timestamp,
	`login_count` int NOT NULL DEFAULT 0,
	`failed_login_attempts` int NOT NULL DEFAULT 0,
	`locked_until` timestamp,
	`mfa_enabled` tinyint NOT NULL DEFAULT 0,
	`mfa_secret` varchar(128),
	`ca_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ca_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `customer_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`customer_account_id` int NOT NULL,
	`cal_tenant_id` int NOT NULL,
	`cal_action` varchar(128) NOT NULL,
	`cal_resource` varchar(128),
	`cal_resource_id` varchar(128),
	`cal_details` json,
	`cal_ip_address` varchar(45),
	`cal_user_agent` varchar(512),
	`cal_result` enum('success','failure','denied') NOT NULL DEFAULT 'success',
	`cal_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `customer_integrations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`description` text,
	`category` enum('osint','exploit_db','threat_intel','scanner','pentest_tool','phishing','c2','siem_soar','cloud','credential','custom') NOT NULL,
	`license_model` enum('free','freemium','api_key','byol','platform_provided','custom') NOT NULL DEFAULT 'custom',
	`status` enum('proposed','review','approved','active','paused','rejected','error','deprecated') NOT NULL DEFAULT 'proposed',
	`auth_method` enum('none','api_key','api_key_secret','basic_auth','bearer_token','oauth2','ssh_key','custom_header','certificate') NOT NULL DEFAULT 'api_key',
	`auth_config` json,
	`endpoint_base_url` text,
	`endpoint_config` json,
	`pipeline_stages` json,
	`data_types` json,
	`input_types` json,
	`output_types` json,
	`capabilities` json,
	`pipeline_wiring` json,
	`value_assessment` json,
	`auto_discovery_result` json,
	`customer_review` json,
	`credentials` json,
	`tags` json,
	`priority` int DEFAULT 3,
	`is_built_in` tinyint NOT NULL DEFAULT 0,
	`added_by` varchar(64),
	`tenant_id` varchar(64),
	`last_health_check` bigint,
	`last_health_status` enum('healthy','degraded','unreachable','auth_failed','unknown') DEFAULT 'unknown',
	`last_error` text,
	`total_calls` int DEFAULT 0,
	`total_errors` int DEFAULT 0,
	`avg_latency_ms` int,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `customer_intelligence_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`customer_id` varchar(255) NOT NULL,
	`customer_name` varchar(255) NOT NULL,
	`overall_posture_score` double,
	`posture_grade` varchar(8),
	`posture_trend` varchar(16) DEFAULT 'stable',
	`total_engagements` int DEFAULT 0,
	`total_di_scans` int DEFAULT 0,
	`total_findings` int DEFAULT 0,
	`total_critical` int DEFAULT 0,
	`total_high` int DEFAULT 0,
	`total_medium` int DEFAULT 0,
	`total_low` int DEFAULT 0,
	`posture_trend_data` json,
	`findings_trend_data` json,
	`recurring_weaknesses` json,
	`persistent_gaps` json,
	`known_technologies` json,
	`technology_changes` json,
	`attack_surface_size` int,
	`attack_surface_trend` json,
	`strategic_recommendations` json,
	`open_gaps_count` int DEFAULT 0,
	`resolved_gaps_count` int DEFAULT 0,
	`last_engagement_date` timestamp,
	`last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `customer_intelligence_profiles_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_shared_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`csr_tenant_id` int NOT NULL,
	`csr_report_type` enum('ac3','pentest','compliance','executive_summary','vulnerability','incident','dfir') NOT NULL,
	`csr_report_id` int NOT NULL,
	`csr_title` varchar(512) NOT NULL,
	`csr_description` text,
	`csr_shared_by` int NOT NULL,
	`csr_shared_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`csr_expires_at` timestamp,
	`csr_access_count` int NOT NULL DEFAULT 0,
	`csr_last_accessed_at` timestamp,
	`csr_is_active` tinyint NOT NULL DEFAULT 1
);
--> statement-breakpoint
CREATE TABLE `customer_stack_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`customer_name` varchar(255) NOT NULL,
	`languages` json,
	`web_frameworks` json,
	`data_and_ml` json,
	`genai_and_llm` json,
	`cloud_services` json,
	`security_tools` json,
	`devops_and_ci` json,
	`databases_list` json,
	`infrastructure` json,
	`other_techs` json,
	`auto_detected` json,
	`technology_versions` json,
	`generated_test_plan` json,
	`matched_scanners` json,
	`coverage_percent` int,
	`gaps` json,
	`notes` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `customer_stack_profiles_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cve_enrichment` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve_id` varchar(32) NOT NULL,
	`description` text,
	`cwes` json,
	`cvss_v3_score` float,
	`cvss_v3_vector` varchar(128),
	`published_date` varchar(64),
	`last_modified_date` varchar(64),
	`references` json,
	`enriched_at` bigint NOT NULL,
	`error` text
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
	`der_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`dfr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`dfs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `demo_requests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`email` varchar(255) NOT NULL,
	`organization` varchar(255) NOT NULL,
	`job_title` varchar(255),
	`use_case` text NOT NULL,
	`status` enum('new','contacted','scheduled','completed','declined') NOT NULL DEFAULT 'new',
	`notes` text,
	`ip_address` varchar(45),
	`user_agent` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `demo_requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `deployment_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`deployment_id` varchar(64) NOT NULL,
	`user_id` int NOT NULL,
	`environment` enum('dev','staging','prod') NOT NULL,
	`region` varchar(32) NOT NULL,
	`stack_name` varchar(255) NOT NULL,
	`stack_version` varchar(64),
	`status` enum('pending','in_progress','success','failed','rolled_back') NOT NULL DEFAULT 'pending',
	`config_snapshot` json NOT NULL,
	`resource_count` int,
	`alarms_created` int,
	`cfn_outputs` json,
	`error_message` text,
	`notes` text,
	`started_at` timestamp NOT NULL DEFAULT (now()),
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `deployment_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `deployment_update_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`from_version` varchar(32) NOT NULL,
	`to_version` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`started_at` bigint NOT NULL,
	`completed_at` bigint,
	`migration_log` text,
	`error` text,
	`rolled_back` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `deployment_versions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`version` varchar(32) NOT NULL,
	`release_date` bigint NOT NULL,
	`channel` varchar(32) NOT NULL DEFAULT 'stable',
	`changelog` text NOT NULL,
	`migration_script` text,
	`min_previous_version` varchar(32),
	`download_url` varchar(512),
	`checksum_sha256` varchar(64),
	`is_breaking` tinyint NOT NULL DEFAULT 0,
	`is_required` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`dfr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`dfir_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `dfir_report_iocs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`report_id` int NOT NULL,
	`ioc_type` enum('ip','domain','hash_md5','hash_sha1','hash_sha256','url','email','cve','filename','registry_key','mutex') NOT NULL,
	`ioc_value` varchar(1024) NOT NULL,
	`ioc_context` text,
	`ioc_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`dfir_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`dfir_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `di_incident_training_data` (
	`id` int AUTO_INCREMENT NOT NULL,
	`example_id` varchar(64) NOT NULL,
	`scan_id` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`example_type` enum('incident_context','actor_attribution','breach_pattern','ransomware_profile','attack_surface_map') NOT NULL,
	`training_messages` json NOT NULL,
	`quality_score` double NOT NULL DEFAULT 0.5,
	`quality_band` enum('high','medium','low','rejected') NOT NULL DEFAULT 'medium',
	`analyst_rating` enum('accurate','partially_accurate','inaccurate','not_reviewed') NOT NULL DEFAULT 'not_reviewed',
	`analyst_notes` text,
	`analyst_id` int,
	`rated_at` bigint,
	`incident_count` int DEFAULT 0,
	`actors_discovered` int DEFAULT 0,
	`ttps_discovered` int DEFAULT 0,
	`risk_score_at_scan` int,
	`risk_band_at_scan` varchar(32),
	`used_in_prompt_count` int DEFAULT 0,
	`last_used_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`da_tenant_id` int,
	`discovery_context` json,
	`discovery_context_history` json,
	`discovery_context_analyzed_at` timestamp
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
	`dap_discovered_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`est_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
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
CREATE TABLE `ember_campaign_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecl_campaign_id` varchar(64) NOT NULL,
	`ecl_phase_id` varchar(64),
	`ecl_level` enum('info','warn','error','success') NOT NULL DEFAULT 'info',
	`ecl_message` text NOT NULL,
	`ecl_metadata` json,
	`ecl_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_campaign_phases` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecph_phase_id` varchar(64) NOT NULL,
	`ecph_campaign_id` varchar(64) NOT NULL,
	`ecph_phase_index` int NOT NULL,
	`ecph_name` varchar(255) NOT NULL,
	`ecph_description` text,
	`ecph_template_id` varchar(64),
	`ecph_template_name` varchar(255),
	`ecph_task_steps` json NOT NULL,
	`ecph_agent_id` varchar(64),
	`ecph_target_ip` varchar(64),
	`ecph_custom_params` json,
	`ecph_status` enum('pending','running','success','failed','skipped','timeout','aborted') NOT NULL DEFAULT 'pending',
	`ecph_on_success` enum('continue','skip_next','jump_to','complete') NOT NULL DEFAULT 'continue',
	`ecph_on_failure` enum('abort','skip','retry','continue') NOT NULL DEFAULT 'abort',
	`ecph_on_timeout` enum('abort','skip','retry','continue') NOT NULL DEFAULT 'abort',
	`ecph_jump_to` int,
	`ecph_max_retries` int DEFAULT 1,
	`ecph_retries_used` int DEFAULT 0,
	`ecph_timeout_seconds` int DEFAULT 600,
	`ecph_delay_before_ms` int DEFAULT 0,
	`ecph_condition_expr` text,
	`ecph_started_at` bigint,
	`ecph_completed_at` bigint,
	`ecph_output` mediumtext,
	`ecph_error` text,
	`ecph_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecmp_campaign_id` varchar(64) NOT NULL,
	`ecmp_name` varchar(255) NOT NULL,
	`ecmp_description` text,
	`ecmp_objective` text,
	`ecmp_status` enum('draft','ready','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'draft',
	`ecmp_target_info` json,
	`ecmp_phase_count` int DEFAULT 0,
	`ecmp_current_phase` int DEFAULT 0,
	`ecmp_phases_completed` int DEFAULT 0,
	`ecmp_phases_failed` int DEFAULT 0,
	`ecmp_phases_skipped` int DEFAULT 0,
	`ecmp_agent_ids` json,
	`ecmp_created_by` varchar(255),
	`ecmp_started_at` bigint,
	`ecmp_completed_at` bigint,
	`ecmp_created_at` bigint NOT NULL,
	`ecmp_updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `ember_custom_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ect_template_id` varchar(64) NOT NULL,
	`ect_name` varchar(255) NOT NULL,
	`ect_description` text,
	`ect_category` enum('recon','credential','persistence','lateral','exfil','custom') NOT NULL DEFAULT 'custom',
	`ect_risk` enum('low','medium','high','critical') NOT NULL DEFAULT 'medium',
	`ect_est_duration` varchar(64),
	`ect_tags` json,
	`ect_steps` json NOT NULL,
	`ect_cloned_from` varchar(64),
	`ect_created_by` varchar(255),
	`ect_is_shared` tinyint DEFAULT 0,
	`ect_usage_count` int DEFAULT 0,
	`ect_last_used_at` bigint,
	`ect_created_at` bigint NOT NULL,
	`ect_updated_at` bigint NOT NULL
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_approved_targets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`target` varchar(512) NOT NULL,
	`hostname` varchar(255) NOT NULL,
	`status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
	`approved_by` int,
	`approved_by_name` varchar(255),
	`justification` text,
	`roe_reference` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_approved_targets_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `engagement_comms_protocols` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`roe_document_id` int,
	`uploaded_doc_id` int,
	`reporting_cadence` varchar(128),
	`reporting_method` varchar(256),
	`reporting_recipients` json,
	`emergency_halt_procedure` text,
	`deconfliction_procedure` text,
	`deconfliction_contacts` json,
	`deconfliction_phone` varchar(64),
	`deconfliction_email` varchar(320),
	`escalation_chain` json,
	`escalation_timeframe` varchar(128),
	`critical_finding_notify_within` varchar(64),
	`critical_finding_notify_method` varchar(256),
	`critical_finding_notify_recipients` json,
	`testing_window_start` varchar(16),
	`testing_window_end` varchar(16),
	`testing_days` json,
	`test_timezone` varchar(64),
	`blackout_periods` json,
	`status_check_in_frequency` varchar(128),
	`status_check_in_method` varchar(256),
	`raw_comms_section` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ecp_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `engagement_credential_lists` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ecl_engagement_id` int NOT NULL,
	`ecl_source` enum('dehashed','intelx','hudson_rock','leakcheck','manual','hibp','stealer_log') NOT NULL,
	`ecl_username` varchar(512) NOT NULL,
	`ecl_password` varchar(512),
	`ecl_password_hash` varchar(512),
	`ecl_hash_type` varchar(32),
	`ecl_email` varchar(320),
	`ecl_breach_name` varchar(512),
	`ecl_breach_date` varchar(32),
	`ecl_domain` varchar(512),
	`ecl_is_verified` tinyint NOT NULL DEFAULT 0,
	`ecl_is_used` tinyint NOT NULL DEFAULT 0,
	`ecl_used_at` timestamp,
	`ecl_used_result` enum('success','failure','locked','mfa_blocked','not_tested') DEFAULT 'not_tested',
	`ecl_confidence` enum('high','medium','low') NOT NULL DEFAULT 'medium',
	`ecl_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
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
	`source_type` enum('scanner','llm_inference','manual') DEFAULT 'scanner',
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
CREATE TABLE `engagement_ops_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`state_json` json NOT NULL,
	`phase` varchar(64),
	`is_running` tinyint DEFAULT 0,
	`asset_count` int DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`interrupt_count` int DEFAULT 0,
	`last_interrupted_at` timestamp,
	`server_instance_id` varchar(64)
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`reportType` enum('executive_summary','technical_detail','compliance','phishing_results','osint_assessment','full_engagement','purple_team','red_team_assessment','detection_gap_analysis','pentest_assessment') NOT NULL,
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
CREATE TABLE `engagement_scope_constraints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`roe_document_id` int,
	`uploaded_doc_id` int,
	`in_scope_domains` json,
	`out_of_scope_domains` json,
	`in_scope_ip_ranges` json,
	`out_of_scope_ip_ranges` json,
	`in_scope_applications` json,
	`out_of_scope_applications` json,
	`in_scope_ports` json,
	`out_of_scope_ports` json,
	`allowed_testing_types` json,
	`disallowed_testing_types` json,
	`allowed_attack_vectors` json,
	`disallowed_attack_vectors` json,
	`dos_allowed` tinyint DEFAULT 0,
	`social_engineering_allowed` tinyint DEFAULT 0,
	`physical_allowed` tinyint DEFAULT 0,
	`wireless_allowed` tinyint DEFAULT 0,
	`pivoting_allowed` tinyint DEFAULT 1,
	`exfiltration_allowed` tinyint DEFAULT 0,
	`persistence_allowed` tinyint DEFAULT 0,
	`file_modification_allowed` tinyint DEFAULT 0,
	`credentialed_testing` tinyint DEFAULT 0,
	`testing_start_date` timestamp,
	`testing_end_date` timestamp,
	`raw_scope_section` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`esc_tenant_id` int
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagement_telemetry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`phase` varchar(64) NOT NULL,
	`step` varchar(128) NOT NULL,
	`event_type` enum('tool_call','tool_response','llm_request','llm_response','decision','error','retry','phase_transition','approval_request','approval_response','evidence_captured','evidence_validated') NOT NULL,
	`input_summary` text,
	`output_summary` text,
	`full_payload_ref` varchar(512),
	`duration_ms` int,
	`exit_code` int,
	`success` tinyint NOT NULL DEFAULT 1,
	`error_class` enum('none','timeout','auth_failure','connection_refused','api_error','parse_failure','llm_hallucination','knowledge_gap','logic_error','evidence_integrity','infrastructure','rate_limit','unknown') NOT NULL DEFAULT 'none',
	`error_message` text,
	`retry_count` int NOT NULL DEFAULT 0,
	`context_snapshot` json,
	`storage_provider` enum('do_spaces','aws_s3','local','none') NOT NULL DEFAULT 'none',
	`correlation_id` varchar(64),
	`operator_id` varchar(64),
	`target_host` varchar(255),
	`source_module` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	CONSTRAINT `engagement_telemetry_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `engagement_timeline_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`phase` varchar(64) NOT NULL,
	`event_type` enum('phase_started','phase_completed','finding_discovered','exploit_attempted','exploit_succeeded','shell_obtained','credential_found','pivot_established','data_collected','data_exfiltrated','opsec_alert','note_added','handoff_triggered','objective_completed','tool_executed','scan_completed','phase_start','scope_asset','target_approval','safety_override','launched','test_event') NOT NULL,
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `engagements` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`customerName` varchar(255) NOT NULL,
	`description` text,
	`engagementType` enum('red_team','phishing','pentest','purple_team','tabletop','bug_bounty','vulnerability_assessment') NOT NULL DEFAULT 'red_team',
	`status` enum('planning','active','paused','completed','archived') NOT NULL DEFAULT 'planning',
	`startDate` timestamp,
	`endDate` timestamp,
	`targetDomain` text,
	`targetIpRange` text,
	`phishingDomain` varchar(255),
	`calderaOperationId` varchar(255),
	`calderaAdversaryId` varchar(255),
	`gophishCampaignId` int,
	`notes` text,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`scan_mode` enum('strict_passive','standard','active') DEFAULT 'strict_passive',
	`auto_resume_on_restart` tinyint DEFAULT 0,
	`domain_intel_scan_id` int,
	`roe_catalog_consent` tinyint DEFAULT 0,
	`fedramp_impact_level` enum('none','low','moderate','high') DEFAULT 'none',
	`active_scan_override` tinyint DEFAULT 0,
	`license_tier` enum('standard','professional','enterprise') DEFAULT 'standard',
	`bug_bounty_program_url` text,
	`bug_bounty_platform` enum('hackerone','bugcrowd','intigriti','synack','yeswehack','custom'),
	`selected_frameworks` json
);
--> statement-breakpoint
CREATE TABLE `enrichment_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actor_id` varchar(128) NOT NULL,
	`actor_name` varchar(255),
	`triggered_by` enum('manual','bulk','scheduled') NOT NULL DEFAULT 'manual',
	`fields_updated` json,
	`fields_discovered` json,
	`sources_used` json,
	`keywords_used` json,
	`data_quality_before` int,
	`data_quality_after` int,
	`summary` text,
	`status` enum('success','failed','partial','pending_review') NOT NULL DEFAULT 'success',
	`error_message` text,
	`duration_ms` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `entity_profile_overrides` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`org_name` varchar(255),
	`industry` varchar(128),
	`sub_sector` varchar(128),
	`company_size` enum('startup','small','medium','large','enterprise','unknown'),
	`estimated_revenue` bigint,
	`estimated_employees` int,
	`headquarters` varchar(255),
	`founded_year` int,
	`is_public_company` tinyint,
	`stock_ticker` varchar(16),
	`key_products` json,
	`override_reason` text,
	`overridden_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `entity_profile_overrides_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`completed_at` timestamp,
	`evs_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `evidence_chain_of_custody` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidenceId` varchar(64) NOT NULL,
	`action` varchar(50) NOT NULL,
	`performedBy` varchar(255) NOT NULL,
	`performedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`details` text,
	`ipAddress` varchar(45),
	`userAgent` varchar(500),
	`integrityHash` varchar(64),
	`previousHash` varchar(64)
);
--> statement-breakpoint
CREATE TABLE `evidence_guardrail_audit` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ega_engagement_id` varchar(64) NOT NULL,
	`ega_evidence_id` varchar(128),
	`ega_specialist` varchar(100) NOT NULL,
	`ega_check_type` enum('hallucination','provenance','chain_integrity','evidence_gate') NOT NULL,
	`ega_passed` tinyint NOT NULL,
	`ega_score` int,
	`ega_recommendation` enum('accept','review','reject','quarantine') NOT NULL,
	`ega_grounded_claims` int DEFAULT 0,
	`ega_ungrounded_claims` int DEFAULT 0,
	`ega_critical_issues` int DEFAULT 0,
	`ega_was_sanitized` tinyint DEFAULT 0,
	`ega_details` json,
	`ega_content_hash` varchar(64),
	`ega_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `evidence_integrity_anchors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eia_engagement_id` varchar(64) NOT NULL,
	`eia_merkle_root` varchar(64) NOT NULL,
	`eia_hmac_signature` varchar(64) NOT NULL,
	`eia_chain_length` int NOT NULL,
	`eia_anchored_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`eia_anchored_by` varchar(255) NOT NULL,
	`eia_status` enum('active','superseded','invalidated') NOT NULL DEFAULT 'active',
	`eia_notes` text
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`efr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`eij_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`ei_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`exploitJobCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`exploitJobUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_learning_chains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chain_name` varchar(255) NOT NULL,
	`steps` json NOT NULL,
	`success_rate` float NOT NULL,
	`discovered_from` varchar(255) NOT NULL,
	`mitre_techniques` json,
	`engagement_id` int,
	`target_hostname` varchar(255),
	`times_used` int NOT NULL DEFAULT 0,
	`last_used_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_learning_outcomes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`attempt_id` varchar(128) NOT NULL,
	`engagement_id` int NOT NULL,
	`vuln_title` varchar(512) NOT NULL,
	`vuln_cve` varchar(32),
	`vuln_severity` varchar(32) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`target_hostname` varchar(255) NOT NULL,
	`target_port` int,
	`target_technologies` json,
	`language` varchar(32) NOT NULL,
	`code` mediumtext NOT NULL,
	`success` tinyint NOT NULL DEFAULT 0,
	`exit_code` int NOT NULL DEFAULT 1,
	`stdout` mediumtext,
	`stderr` mediumtext,
	`guardrail_passed` tinyint,
	`guardrail_risk_score` int,
	`guardrail_blocked_reasons` json,
	`false_positive` tinyint DEFAULT 0,
	`false_positive_reasons` json,
	`execution_time_ms` int NOT NULL DEFAULT 0,
	`attempt_number` int NOT NULL DEFAULT 1,
	`previous_attempt_ids` json,
	`correction_applied` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_learning_patterns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pattern_key` varchar(255) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack` json NOT NULL,
	`successful_approaches` json NOT NULL,
	`failed_approaches` json NOT NULL,
	`known_chain_ids` json,
	`total_successes` int NOT NULL DEFAULT 0,
	`total_failures` int NOT NULL DEFAULT 0,
	`success_rate` float NOT NULL,
	`updated_at` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_methodologies` (
	`id` varchar(128) NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`name` varchar(512) NOT NULL,
	`tech_stack` json NOT NULL,
	`owasp_category` varchar(128),
	`mitre_techniques` json,
	`cwe_ids` json,
	`steps` json NOT NULL,
	`payloads` json NOT NULL,
	`detection_signatures` json NOT NULL,
	`escalation_paths` json,
	`success_criteria` json NOT NULL,
	`failure_modes` json,
	`weight` int NOT NULL DEFAULT 50,
	`source` enum('seed','learned','community') NOT NULL DEFAULT 'seed',
	`success_count` int NOT NULL DEFAULT 0,
	`attempt_count` int NOT NULL DEFAULT 0,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`resolved_at` timestamp
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
	`ep_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ep_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`eph_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_quarantine_queue` (
	`id` int AUTO_INCREMENT NOT NULL,
	`quarantine_id` varchar(128) NOT NULL,
	`exploit_title` varchar(512) NOT NULL,
	`exploit_description` text,
	`exploit_code` text,
	`exploit_language` varchar(64),
	`exploit_platform` varchar(64),
	`exploit_service` varchar(128),
	`exploit_cve_ids` json,
	`exploit_tags` json,
	`exploit_source` varchar(32) NOT NULL,
	`submitted_by` varchar(255) NOT NULL,
	`source_pipeline` varchar(128) NOT NULL,
	`status` enum('pending_review','approved','rejected') NOT NULL DEFAULT 'pending_review',
	`engagement_id` int,
	`meta_cve_id` varchar(32),
	`meta_success` tinyint NOT NULL DEFAULT 1,
	`reviewed_at` timestamp,
	`reviewed_by` varchar(255),
	`review_notes` text,
	`quarantined_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`es_ingested_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`es_last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `exploit_selection_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`snapshot_id` varchar(128) NOT NULL,
	`engagement_id` int NOT NULL,
	`selection_event` varchar(255) NOT NULL,
	`catalog_state_hash` varchar(128) NOT NULL,
	`catalog_entry_count` int NOT NULL,
	`selected_exploit_ids` json,
	`rag_query_used` text,
	`rag_result_count` int,
	`rag_result_ids` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`screenshot_urls` json,
	`ea_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`markedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`reinstatedBy` varchar(255),
	`reinstatedAt` timestamp,
	`reinstatedReason` text,
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`transferCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`transferCompletedAt` timestamp
);
--> statement-breakpoint
CREATE TABLE `fingerprint_cache` (
	`fc_id` int AUTO_INCREMENT NOT NULL,
	`fc_host` varchar(255) NOT NULL,
	`fc_port` int NOT NULL,
	`fc_protocol` varchar(64),
	`fc_product` varchar(255),
	`fc_version` varchar(128),
	`fc_banner` text,
	`fc_os` varchar(255),
	`fc_security_flags` json,
	`fc_risk_indicators` json,
	`fc_potential_cves` json,
	`fc_error` tinyint DEFAULT 0,
	`fc_confidence` int DEFAULT 0,
	`fc_fingerprinted_at` bigint NOT NULL,
	`fc_expires_at` bigint NOT NULL,
	`fc_engagement_id` varchar(64),
	`fc_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`forest_domain_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`trust_discovered_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
	`forest_trust_created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`gdr_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`hyp_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`hunt_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`iab_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`ica_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`icd_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`icd_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`ice_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`ir_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`io_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`ioCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ioUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `integration_execution_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`engagement_id` int,
	`pipeline_stage` varchar(64) NOT NULL,
	`execution_status` enum('success','partial','failed','timeout','skipped') NOT NULL,
	`duration_ms` int,
	`records_returned` int DEFAULT 0,
	`error_message` text,
	`executed_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `integration_health_checks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integration_id` varchar(128) NOT NULL,
	`check_type` enum('connectivity','auth_validation','rate_limit','full_probe') NOT NULL DEFAULT 'connectivity',
	`status` enum('healthy','degraded','unreachable','auth_failed','rate_limited','timeout','error') NOT NULL,
	`latency_ms` int,
	`http_status` int,
	`response_snippet` text,
	`error_message` text,
	`checked_at` bigint NOT NULL,
	CONSTRAINT `integration_health_checks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `intelligence_gaps` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`scan_id` int,
	`customer_id` varchar(255),
	`category` varchar(64) NOT NULL,
	`subcategory` varchar(128),
	`title` varchar(512) NOT NULL,
	`description` text,
	`reason` text NOT NULL,
	`risk_implication` text,
	`potential_impact` varchar(32) DEFAULT 'unknown',
	`recommendation` text,
	`estimated_effort` varchar(64),
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`resolved_at` timestamp,
	`resolved_by` int,
	`resolution_note` text,
	`detected_by` varchar(64) DEFAULT 'system',
	`confidence` double,
	`affected_assets` json,
	`affected_scope` json,
	`related_findings` json,
	`tags` json,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `intelligence_gaps_id` PRIMARY KEY(`id`)
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
	`fetchedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `ioc_sync_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`syncType` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL,
	`results` json,
	`totalFetched` int DEFAULT 0,
	`errorMessage` text,
	`startedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`itm_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `ir_runbook_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` varchar(64) NOT NULL,
	`alarm_name` varchar(255) NOT NULL,
	`alarm_pattern` varchar(255),
	`trigger_description` text NOT NULL,
	`severity` enum('critical','high','medium','low','informational') NOT NULL,
	`category` enum('infrastructure','application','security','performance','availability') NOT NULL,
	`response_steps` json NOT NULL,
	`escalation_path` json NOT NULL,
	`related_alarms` json,
	`mitigation_actions` json,
	`prevention_measures` json,
	`owner` varchar(255),
	`last_tested_at` timestamp,
	`last_triggered_at` timestamp,
	`trigger_count` int NOT NULL DEFAULT 0,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `ir_runbook_entries_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `knowledge_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`category` varchar(64) NOT NULL,
	`subcategory` varchar(64),
	`description` text NOT NULL,
	`mitre_technique_ids` json,
	`phase` varchar(64) NOT NULL,
	`target_platform` varchar(32) DEFAULT 'both',
	`required_privilege` varchar(32),
	`tools` json,
	`code` text,
	`language` varchar(32),
	`prerequisites` json,
	`detection_indicators` json,
	`post_exploit_actions` json,
	`verification_steps` json,
	`opsec_risk` int,
	`confidence` int,
	`source` varchar(255),
	`source_url` varchar(512),
	`tags` json,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`created_by` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `license_usage_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`action` varchar(64) NOT NULL,
	`resource_type` varchar(64),
	`resource_id` varchar(255),
	`metadata` json,
	`timestamp` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `licensed_organizations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`org_id` varchar(128) NOT NULL,
	`org_name` varchar(255) NOT NULL,
	`contact_email` varchar(255),
	`contact_name` varchar(255),
	`tier` varchar(32) NOT NULL DEFAULT 'starter',
	`license_key` text NOT NULL,
	`license_key_hash` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'active',
	`issued_at` bigint NOT NULL,
	`expires_at` bigint NOT NULL,
	`revoked_at` bigint,
	`revoked_reason` text,
	`max_seats` int NOT NULL DEFAULT 5,
	`max_scans_per_period` int NOT NULL DEFAULT 50,
	`billing_period_days` int NOT NULL DEFAULT 30,
	`grace_period_days` int NOT NULL DEFAULT 7,
	`feature_overrides` json,
	`deployment_domain` varchar(255),
	`notes` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `llm_accuracy_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`target_preset` varchar(64) NOT NULL,
	`total_ground_truth` int DEFAULT 0,
	`true_positives` int DEFAULT 0,
	`false_positives` int DEFAULT 0,
	`false_negatives` int DEFAULT 0,
	`precision_score` decimal(5,4) DEFAULT '0',
	`recall_score` decimal(5,4) DEFAULT '0',
	`f1_score` decimal(5,4) DEFAULT '0',
	`severity_accuracy` decimal(5,4) DEFAULT '0',
	`overall_score` decimal(5,4) DEFAULT '0',
	`scored_at` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `llm_decision_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`dl_phase` varchar(64) NOT NULL,
	`dl_caller` varchar(128) NOT NULL,
	`dl_decision` text NOT NULL,
	`dl_reasoning` text,
	`dl_actions` json,
	`dl_outcome` enum('success','failure','partial','pending') DEFAULT 'pending',
	`outcome_detail` text,
	`stealth_score` double,
	`dl_latency_ms` int,
	`tokens_used` int,
	`context_summary` text,
	`knowledge_modules_used` json,
	`dl_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `llm_learning_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`target_preset` varchar(64) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`finding_title` varchar(512) NOT NULL,
	`llm_severity` varchar(32),
	`correct_severity` varchar(32),
	`llm_category` varchar(128),
	`correct_category` varchar(128),
	`feedback_type` enum('correct','incorrect','partial','missed_finding','false_positive') NOT NULL,
	`operator_notes` text,
	`correction_context` text,
	`operator_id` int,
	`applied_count` int DEFAULT 0,
	`last_applied_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `llm_telemetry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`called_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `llm_training_examples` (
	`id` int AUTO_INCREMENT NOT NULL,
	`example_id` varchar(64) NOT NULL,
	`te_model` varchar(64) NOT NULL,
	`te_source` enum('lab_scenario','live_engagement','manual','synthetic') NOT NULL,
	`source_id` varchar(128),
	`te_quality` enum('high','medium','low','rejected') NOT NULL,
	`quality_score` double NOT NULL,
	`te_messages` json NOT NULL,
	`te_metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`te_review_status` enum('pending_review','approved','rejected','flagged') NOT NULL DEFAULT 'pending_review',
	`te_reviewed_by` varchar(128),
	`te_reviewed_at` timestamp,
	`te_review_notes` text
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
	`lolbin_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`msfCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
CREATE TABLE `methodology_attempts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`methodology_id` varchar(128),
	`engagement_id` int,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack` json,
	`target` varchar(512),
	`port` int,
	`success` tinyint NOT NULL DEFAULT 0,
	`approach` text NOT NULL,
	`payload_used` text,
	`failure_reason` text,
	`execution_time_ms` int,
	`training_example_generated` tinyint DEFAULT 0,
	`training_example_id` varchar(128),
	`graduation_score_impact` double,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `methodology_performance` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vuln_class` varchar(64) NOT NULL,
	`tech_stack_key` varchar(255) NOT NULL,
	`total_attempts` int NOT NULL DEFAULT 0,
	`total_successes` int NOT NULL DEFAULT 0,
	`success_rate` double NOT NULL,
	`avg_execution_time_ms` int,
	`last_attempt_at` bigint,
	`last_success_at` bigint,
	`updated_at` bigint NOT NULL
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
	`ne_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ne_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `nexus_pipeline_executions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`npe_execution_id` varchar(64) NOT NULL,
	`npe_caller_name` varchar(255) NOT NULL,
	`npe_graduation_tier` int NOT NULL,
	`npe_trigger_type` enum('auto','manual','scheduled') DEFAULT 'auto',
	`npe_current_stage` enum('requirement_analysis','architecture','code_generation','qa_validation','security_review','integration_test','completed','failed','rolled_back') DEFAULT 'requirement_analysis',
	`npe_stage_history` json,
	`npe_requirement_spec` json,
	`npe_generated_code` text,
	`npe_generated_tests` text,
	`npe_qa_score` int,
	`npe_security_score` int,
	`npe_integration_score` int,
	`npe_overall_score` int,
	`npe_cost_saved` decimal(10,4),
	`npe_tokens_consumed` int DEFAULT 0,
	`npe_llm_calls_count` int DEFAULT 0,
	`npe_status` enum('running','completed','failed','rolled_back','paused') DEFAULT 'running',
	`npe_error_message` text,
	`npe_started_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`npe_completed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `nexus_quality_gates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nqg_execution_id` varchar(64) NOT NULL,
	`nqg_gate_name` varchar(128) NOT NULL,
	`nqg_gate_type` enum('llm_judge','unit_test','type_check','security_scan','performance_bench','integration_test') NOT NULL,
	`nqg_passed` tinyint NOT NULL,
	`nqg_score` int,
	`nqg_max_score` int DEFAULT 100,
	`nqg_evidence` json,
	`nqg_retry_attempt` int DEFAULT 0,
	`nqg_evaluated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `nexus_shadow_configs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nsc_config_name` varchar(128) NOT NULL,
	`nsc_enabled` tinyint NOT NULL DEFAULT 0,
	`nsc_shadow_percentage` int NOT NULL DEFAULT 5,
	`nsc_primary_model` varchar(128) NOT NULL DEFAULT 'gemini-2.5-flash',
	`nsc_experimental_model` varchar(128) NOT NULL DEFAULT 'gpt-4o',
	`nsc_caller_filter` varchar(255) DEFAULT '',
	`nsc_priority_filter` enum('all','essential','standard','bulk') DEFAULT 'all',
	`nsc_max_concurrent` int NOT NULL DEFAULT 10,
	`nsc_active_shadow_tests` int NOT NULL DEFAULT 0,
	`nsc_total_runs` int NOT NULL DEFAULT 0,
	`nsc_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`nsc_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `nexus_shadow_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`nst_config_id` int NOT NULL,
	`nst_caller` varchar(255) NOT NULL,
	`nst_prompt_snippet` text,
	`nst_primary_model` varchar(128) NOT NULL,
	`nst_primary_latency_ms` int,
	`nst_primary_tokens_in` int,
	`nst_primary_tokens_out` int,
	`nst_primary_score` int,
	`nst_experimental_model` varchar(128) NOT NULL,
	`nst_experimental_latency_ms` int,
	`nst_experimental_tokens_in` int,
	`nst_experimental_tokens_out` int,
	`nst_experimental_score` int,
	`nst_judge_verdict` enum('primary_better','experimental_better','tie','error') DEFAULT 'tie',
	`nst_judge_reasoning` text,
	`nst_judge_score` int,
	`nst_status` enum('running','completed','error') DEFAULT 'running',
	`nst_error_message` text,
	`nst_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`nst_completed_at` timestamp
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
	`nvt_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`access_level` varchar(64),
	`confidence` int,
	`execution_context` varchar(32),
	`nuclei_command` text,
	`finding_hash` varchar(64),
	`port` int,
	`nuclei_verified` tinyint DEFAULT 0
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `nuclei_template_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve_id` varchar(32) NOT NULL,
	`template_path` varchar(512) NOT NULL,
	`vuln_class` varchar(64),
	`service` varchar(128),
	`success_count` int DEFAULT 1,
	`last_used_at` bigint NOT NULL,
	`discovered_from` enum('exploit_success','manual','knowledge_store') DEFAULT 'exploit_success',
	`created_at` bigint NOT NULL
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
	`os_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`opsec_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`opsec_score_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`opsec_score_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `orchestration_plans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`plan_id` varchar(128) NOT NULL,
	`engagement_id` int,
	`campaign_id` int,
	`name` varchar(255) NOT NULL,
	`description` text,
	`target_domain` varchar(512),
	`scan_mode` varchar(32),
	`op_status` enum('pending','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'pending',
	`current_phase` varchar(64),
	`steps_completed` int NOT NULL DEFAULT 0,
	`steps_failed` int NOT NULL DEFAULT 0,
	`steps_skipped` int NOT NULL DEFAULT 0,
	`max_parallel` int NOT NULL DEFAULT 3,
	`abort_on_failure` tinyint NOT NULL DEFAULT 0,
	`auto_handoff` tinyint NOT NULL DEFAULT 1,
	`phases` json,
	`steps` json,
	`framework_priority` json,
	`shared_context` json,
	`op_log` json,
	`started_at` timestamp,
	`completed_at` timestamp,
	`last_heartbeat` bigint,
	`node_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`op_tenant_id` int
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`otn_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `parsed_policy_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cache_key` varchar(255) NOT NULL,
	`platform` varchar(32) NOT NULL,
	`program_slug` varchar(255) NOT NULL,
	`program_url` varchar(1024) NOT NULL,
	`parsed_result` json NOT NULL,
	`expires_at` timestamp NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`peStartedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`playbookCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`pe_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`pf_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`ra_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`chunkCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `redteam_campaign_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaign_id` int NOT NULL,
	`stage_id` int,
	`log_type` enum('info','warning','error','success','action','decision','metric') NOT NULL DEFAULT 'info',
	`title` varchar(255) NOT NULL,
	`detail` text,
	`metadata` json,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `redteam_campaign_stages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaign_id` int NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`stage_order` int NOT NULL,
	`stage_type` enum('recon','enumeration','vuln_scan','phishing','exploitation','post_exploit','lateral_move','c2_deploy','exfiltration','cleanup','custom') NOT NULL,
	`engagement_id` int,
	`config` json,
	`entry_conditions` json,
	`exit_conditions` json,
	`on_success` enum('next','skip','goto','complete','pause') DEFAULT 'next',
	`on_success_target` int,
	`on_failure` enum('pause','retry','skip','abort','goto') DEFAULT 'pause',
	`on_failure_target` int,
	`max_retries` int DEFAULT 1,
	`timeout_minutes` int DEFAULT 60,
	`status` enum('pending','running','completed','failed','skipped','paused') NOT NULL DEFAULT 'pending',
	`result` json,
	`error` text,
	`started_at` bigint,
	`completed_at` bigint,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `redteam_campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`customer_name` varchar(255),
	`objective` text,
	`safety_level` enum('low','medium','high','critical') DEFAULT 'medium',
	`max_duration_hours` int DEFAULT 24,
	`auto_advance` tinyint DEFAULT 1,
	`notify_on_stage_complete` tinyint DEFAULT 1,
	`notify_on_campaign_complete` tinyint DEFAULT 1,
	`created_by` int,
	`status` enum('draft','ready','running','paused','completed','failed','aborted') NOT NULL DEFAULT 'draft',
	`total_stages` int DEFAULT 0,
	`completed_stages` int DEFAULT 0,
	`failed_stages` int DEFAULT 0,
	`skipped_stages` int DEFAULT 0,
	`current_stage_order` int,
	`results_summary` json,
	`started_at` bigint,
	`completed_at` bigint,
	`paused_at` bigint,
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `regulatory_frameworks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rf_tenant_id` int,
	`rf_domain` varchar(512) NOT NULL,
	`rf_framework` varchar(128) NOT NULL,
	`rf_status` enum('auto_detected','customer_confirmed','customer_denied','operator_added') NOT NULL DEFAULT 'auto_detected',
	`rf_confidence` int DEFAULT 50,
	`rf_detection_method` varchar(255),
	`rf_detection_evidence` json,
	`rf_applicable_controls` json,
	`rf_notes` text,
	`rf_confirmed_by` int,
	`rf_confirmed_at` timestamp,
	`rf_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`rf_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `remediation_tasks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`finding_id` int,
	`scan_result_id` int,
	`title` varchar(512) NOT NULL,
	`description` text,
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`status` enum('open','assigned','in_progress','fixed','verified','wont_fix','deferred') NOT NULL DEFAULT 'open',
	`assigned_team` varchar(128),
	`assigned_user_id` int,
	`sla_deadline` timestamp,
	`fixed_at` timestamp,
	`verified_at` timestamp,
	`rescan_id` int,
	`rescan_status` enum('pending','passed','failed','not_required') DEFAULT 'not_required',
	`priority` int DEFAULT 0,
	`notes` text,
	`cve_id` varchar(32),
	`affected_asset` varchar(255),
	`remediation_guidance` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`rv_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`rt_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`rts_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `roe_acknowledgments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`operator_id` int NOT NULL,
	`operator_name` varchar(255) NOT NULL,
	`target_id` varchar(128) NOT NULL,
	`target_name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`rules_accepted` json NOT NULL,
	`enforced_rules` json NOT NULL,
	`scan_profile` varchar(32) NOT NULL,
	`session_id` varchar(128),
	`ip_address` varchar(64),
	`acknowledged_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`saml_event_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`saml_idp_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`saml_idp_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `scan_graduation_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`scan_id` int,
	`engagement_id` int,
	`pipeline_type` varchar(32) NOT NULL DEFAULT 'di_scan',
	`recon_analyst` int NOT NULL,
	`exploit_selector` int NOT NULL,
	`evasion_optimizer` int NOT NULL,
	`cognitive_core` int NOT NULL,
	`cloud_assessor` int NOT NULL,
	`supply_chain_analyst` int NOT NULL,
	`overall_score` int NOT NULL,
	`summary` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
CREATE TABLE `scan_schedules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`engagement_id` int,
	`ss_scanner_type` enum('nessus','qualys','rapid7','openvas','burp','zap') NOT NULL,
	`connection_config` json NOT NULL,
	`cron_expression` varchar(100) NOT NULL,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`last_run_at` timestamp,
	`last_run_status` enum('success','failed','running','never') NOT NULL DEFAULT 'never',
	`last_run_stats` json,
	`total_runs` int NOT NULL DEFAULT 0,
	`total_findings` int NOT NULL DEFAULT 0,
	`ss_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`ss_updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
CREATE TABLE `scanforge_engagement_report` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` varchar(64) NOT NULL,
	`scanforge_findings` int DEFAULT 0,
	`nuclei_findings` int DEFAULT 0,
	`zap_findings` int DEFAULT 0,
	`shared_findings` int DEFAULT 0,
	`scanforge_only` int DEFAULT 0,
	`legacy_only` int DEFAULT 0,
	`scanforge_precision` float,
	`scanforge_recall` float,
	`scanforge_f1` float,
	`legacy_precision` float,
	`legacy_recall` float,
	`legacy_f1` float,
	`reassessment_summary` text,
	`template_improvements` json,
	`coverage_gaps` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`auth_context` json
);
--> statement-breakpoint
CREATE TABLE `scanforge_finding_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` varchar(64) NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`template_version` varchar(32) DEFAULT '1.0.0',
	`target` varchar(512) NOT NULL,
	`finding_title` varchar(512) NOT NULL,
	`severity` varchar(32) NOT NULL,
	`confidence` float NOT NULL,
	`proof_verified` tinyint DEFAULT 0,
	`verdict` varchar(16) NOT NULL DEFAULT 'PENDING',
	`verdict_source` varchar(64),
	`verdict_reason` text,
	`finding_data` json,
	`cross_tool_matches` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`assessed_at` timestamp
);
--> statement-breakpoint
CREATE TABLE `scanforge_generated_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`name` varchar(256) NOT NULL,
	`generation_source` varchar(64) NOT NULL,
	`source_reference` varchar(256),
	`template_data` json NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'draft',
	`generation_confidence` float DEFAULT 0.5,
	`review_notes` text,
	`promoted_to_template_id` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `scanforge_promotion_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`generated_template_db_id` int NOT NULL,
	`decision` varchar(32) NOT NULL,
	`reason` text NOT NULL,
	`metrics_snapshot` json NOT NULL,
	`rules_evaluated` json NOT NULL,
	`trigger_engagement_id` varchar(64),
	`previous_status` varchar(32) NOT NULL,
	`new_status` varchar(32) NOT NULL,
	`evaluated_by` varchar(64) NOT NULL DEFAULT 'auto',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `scanforge_research_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`feed_source` varchar(64) NOT NULL,
	`research_subject` varchar(256) NOT NULL,
	`research_type` varchar(64) NOT NULL,
	`analysis_result` json,
	`generated_template_ids` json,
	`actionable` tinyint DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `scanforge_template_metrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`total_scans` int NOT NULL DEFAULT 0,
	`true_positives` int NOT NULL DEFAULT 0,
	`false_positives` int NOT NULL DEFAULT 0,
	`false_negatives` int NOT NULL DEFAULT 0,
	`precision` float,
	`recall` float,
	`f1_score` float,
	`calibrated_confidence` float DEFAULT 0.5,
	`effectiveness_score` float DEFAULT 50,
	`engagement_window` json,
	`last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `scheduled_cspm_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`credential_id` int NOT NULL,
	`engagement_id` int,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`cron_expression` varchar(64) NOT NULL,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`services` json,
	`compliance_framework` varchar(128),
	`timeout_seconds` int DEFAULT 600,
	`last_run_id` int,
	`last_run_at` bigint,
	`last_run_status` enum('pending','running','completed','error'),
	`next_run_at` bigint,
	`total_runs` int DEFAULT 0,
	`created_by` varchar(255),
	`created_at` bigint NOT NULL,
	`updated_at` bigint NOT NULL
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
	`computedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`recordingStartedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`siem_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`first_seen` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`soar_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`soar_evt_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `submission_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`user_id` int NOT NULL,
	`platform` varchar(64) NOT NULL,
	`program_name` varchar(255),
	`vuln_class` varchar(128) NOT NULL,
	`severity` enum('critical','high','medium','low','informational') NOT NULL,
	`title` varchar(512) NOT NULL,
	`body` mediumtext,
	`affected_endpoint` varchar(1024),
	`status` enum('draft','exported','submitted','accepted','rejected','duplicate','informative','not_applicable') NOT NULL DEFAULT 'draft',
	`rejection_reason` text,
	`rejection_category` varchar(128),
	`bounty_amount_cents` int,
	`source_hypothesis_id` varchar(128),
	`confidence_at_generation` double,
	`is_auto_generated` tinyint NOT NULL DEFAULT 0,
	`export_format` varchar(64),
	`exported_at` timestamp,
	`submitted_at` timestamp,
	`outcome_recorded_at` timestamp,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `submission_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `system_settings` (
	`setting_key` varchar(255) NOT NULL,
	`setting_value` longtext,
	`updated_at` timestamp DEFAULT 'CURRENT_TIMESTAMP'
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
	`invite_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`invite_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `telemetry_diagnostics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`report_type` enum('post_engagement','phase_complete','error_burst','manual') NOT NULL,
	`total_events` int NOT NULL DEFAULT 0,
	`event_type_breakdown` json,
	`failure_rate_by_category` json,
	`slowest_operations` json,
	`knowledge_gaps` json,
	`retry_storms` json,
	`total_duration_ms` int,
	`llm_tokens_total` int DEFAULT 0,
	`llm_cost_estimate` double,
	`health_score` int,
	`diagnostic_markdown` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	CONSTRAINT `telemetry_diagnostics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `telemetry_llm_quality` (
	`id` int AUTO_INCREMENT NOT NULL,
	`telemetry_event_id` int NOT NULL,
	`engagement_id` int NOT NULL,
	`prompt_hash` varchar(64) NOT NULL,
	`tokens_in` int NOT NULL DEFAULT 0,
	`tokens_out` int NOT NULL DEFAULT 0,
	`total_tokens` int NOT NULL DEFAULT 0,
	`parsed_successfully` tinyint NOT NULL DEFAULT 1,
	`schema_valid` tinyint NOT NULL DEFAULT 1,
	`hallucination_detected` tinyint NOT NULL DEFAULT 0,
	`hallucination_confidence` double,
	`knowledge_gap` tinyint NOT NULL DEFAULT 0,
	`knowledge_gap_topic` varchar(255),
	`model` varchar(128),
	`response_format` varchar(64),
	`grounding_check_passed` tinyint,
	`prompt_payload_ref` varchar(512),
	`response_payload_ref` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	CONSTRAINT `telemetry_llm_quality_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `tenant_memberships` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tm_tenant_id` int NOT NULL,
	`tm_user_id` int NOT NULL,
	`tm_role` enum('owner','admin','operator','viewer') NOT NULL DEFAULT 'viewer',
	`tm_joined_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`tenant_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`tenant_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `test_lab_environments` (
	`id` varchar(64) NOT NULL,
	`tl_env_name` varchar(255) NOT NULL,
	`tl_env_type` varchar(32) NOT NULL,
	`tl_env_status` varchar(32) NOT NULL DEFAULT 'provisioning',
	`tl_env_platform` varchar(32) NOT NULL,
	`tl_env_target_ip` varchar(64),
	`tl_env_target_port` int,
	`tl_env_droplet_id` varchar(64),
	`tl_env_snapshot_id` varchar(64),
	`tl_env_vulnerabilities` json,
	`tl_env_services` json,
	`tl_env_config` json,
	`tl_env_created_at` bigint NOT NULL,
	`tl_env_destroyed_at` bigint,
	`tl_env_cost_cents` int DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE `test_lab_implant_tests` (
	`id` varchar(64) NOT NULL,
	`tl_it_environment_id` varchar(64),
	`tl_it_agent_id` varchar(64),
	`tl_it_exploit_vector` varchar(128),
	`tl_it_payload_format` varchar(64),
	`tl_it_delivery_method` varchar(64),
	`tl_it_status` varchar(32) NOT NULL DEFAULT 'pending',
	`tl_it_deploy_ok` tinyint,
	`tl_it_first_beacon_at` bigint,
	`tl_it_beacon_count` int DEFAULT 0,
	`tl_it_c2_tested` json,
	`tl_it_c2_passed` json,
	`tl_it_task_results` json,
	`tl_it_opsec_score` int,
	`tl_it_detection_events` json,
	`tl_it_created_at` bigint NOT NULL,
	`tl_it_completed_at` bigint
);
--> statement-breakpoint
CREATE TABLE `test_lab_scenario_runs` (
	`id` varchar(64) NOT NULL,
	`tl_sr_scenario_id` varchar(128) NOT NULL,
	`tl_sr_environment_id` varchar(64),
	`tl_sr_specialist_model` varchar(64),
	`tl_sr_status` varchar(32) NOT NULL DEFAULT 'pending',
	`tl_sr_score` int,
	`tl_sr_max_score` int,
	`tl_sr_passed` tinyint,
	`tl_sr_steps_completed` int DEFAULT 0,
	`tl_sr_total_steps` int,
	`tl_sr_results` json,
	`tl_sr_training_data` tinyint DEFAULT 0,
	`tl_sr_started_at` bigint,
	`tl_sr_completed_at` bigint,
	`tl_sr_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `test_lab_training_runs` (
	`id` varchar(64) NOT NULL,
	`tl_tr_specialist_model` varchar(64) NOT NULL,
	`tl_tr_dataset_id` varchar(64),
	`tl_tr_ft_job_id` varchar(64),
	`tl_tr_openai_job_id` varchar(128),
	`tl_tr_status` varchar(32) NOT NULL DEFAULT 'pending',
	`tl_tr_base_model` varchar(128),
	`tl_tr_result_model_id` varchar(256),
	`tl_tr_example_count` int DEFAULT 0,
	`tl_tr_training_loss` double,
	`tl_tr_validation_loss` double,
	`tl_tr_epochs` int DEFAULT 3,
	`tl_tr_benchmark_score` double,
	`tl_tr_promoted` tinyint DEFAULT 0,
	`tl_tr_started_at` bigint,
	`tl_tr_completed_at` bigint,
	`tl_tr_created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `test_plans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`plan_id` varchar(64) NOT NULL,
	`engagement_id` int NOT NULL,
	`plan_type` enum('pentest','red_team') NOT NULL DEFAULT 'pentest',
	`title` varchar(512) NOT NULL,
	`content` longtext NOT NULL,
	`structured_data` json,
	`version` int NOT NULL DEFAULT 1,
	`status` enum('draft','pending_review','approved','rejected','revision_requested') NOT NULL DEFAULT 'draft',
	`generated_by` int,
	`reviewed_by` int,
	`reviewer_name` varchar(255),
	`reviewer_email` varchar(320),
	`review_comments` text,
	`rejection_reason` text,
	`revision_notes` text,
	`submitted_at` timestamp,
	`reviewed_at` timestamp,
	`approved_at` timestamp,
	`signature_hash` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`ta_tenant_id` int,
	`logoUrl` varchar(512),
	`conflicts` text,
	`enrichment_sources` json
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
	`discoveredAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`tgeCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`tiuStartedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`tiuCompletedAt` timestamp,
	`durationMs` int
);
--> statement-breakpoint
CREATE TABLE `training_benchmark_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` varchar(64) NOT NULL,
	`lab_id` varchar(64) NOT NULL,
	`lab_name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`scan_profile` enum('quick','standard','deep') NOT NULL DEFAULT 'standard',
	`status` enum('pending','scanning','scoring','learning','completed','failed') NOT NULL DEFAULT 'pending',
	`overall_f1` double,
	`overall_precision` double,
	`overall_recall` double,
	`total_ground_truth` int,
	`total_detected` int,
	`true_positives` int,
	`false_positives` int,
	`false_negatives` int,
	`tool_breakdown_json` json,
	`coverage_matrix_json` json,
	`scan_plan_adjustments_json` json,
	`learning_entries_generated` int DEFAULT 0,
	`operator_id` int,
	`operator_name` varchar(255),
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `training_ground_truth` (
	`id` int AUTO_INCREMENT NOT NULL,
	`target_preset` varchar(64) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`vuln_title` varchar(512) NOT NULL,
	`vuln_category` varchar(128) NOT NULL,
	`owasp_category` varchar(32),
	`severity` varchar(32) NOT NULL,
	`cve` varchar(32),
	`description` text,
	`detection_hint` text,
	`is_active` tinyint DEFAULT 1,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `training_lab_feedback` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`finding_index` int NOT NULL,
	`feedback_type` enum('correct','incorrect','partial','missed_finding') NOT NULL,
	`operator_notes` text,
	`expected_severity` varchar(32),
	`expected_category` varchar(128),
	`operator_id` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `training_lab_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`target_preset` varchar(64),
	`scan_profile` enum('quick','standard','deep') NOT NULL DEFAULT 'standard',
	`lab_status` enum('queued','scanning','analyzing','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
	`phase` varchar(64) DEFAULT 'idle',
	`progress` int DEFAULT 0,
	`assets_json` json,
	`findings_json` json,
	`llm_analysis_json` json,
	`owasp_coverage_json` json,
	`stats_json` json,
	`scan_log_json` json,
	`operator_id` int,
	`operator_name` varchar(255),
	`started_at` bigint,
	`completed_at` bigint,
	`duration_ms` int,
	`error_message` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`uie_ingested_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`uie_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`catalogCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`catalogUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `uploaded_roe_documents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`filename` varchar(512) NOT NULL,
	`mime_type` varchar(128) NOT NULL,
	`file_size` int NOT NULL,
	`storage_url` varchar(1024) NOT NULL,
	`storage_key` varchar(512) NOT NULL,
	`document_type` enum('roe','pentest_plan','red_team_plan','bug_bounty_scope','purple_team_plan','unknown') NOT NULL DEFAULT 'unknown',
	`extracted_text` mediumtext,
	`extracted_text_length` int,
	`parsed_data` json,
	`parse_status` enum('pending','extracting_text','parsing','parsed','failed') NOT NULL DEFAULT 'pending',
	`parse_error` text,
	`parsed_at` timestamp,
	`created_engagement_id` int,
	`created_roe_document_id` int,
	`uploaded_by` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`urd_tenant_id` int
);
--> statement-breakpoint
CREATE TABLE `user_platform_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`platform` enum('hackerone','bugcrowd','intigriti','synack','yeswehack','open_bug_bounty','immunefi','burpsuite_pro','burpsuite_enterprise','custom') NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`api_username` varchar(512),
	`api_key_encrypted` text NOT NULL,
	`base_url` varchar(512),
	`is_active` tinyint NOT NULL DEFAULT 1,
	`last_verified_at` timestamp,
	`last_sync_at` timestamp,
	`sync_status` enum('idle','syncing','success','failed') DEFAULT 'idle',
	`error_message` text,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
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
	`session_last_activity_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`session_expires_at` timestamp NOT NULL,
	`session_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` int AUTO_INCREMENT NOT NULL,
	`openId` varchar(64) NOT NULL,
	`name` text,
	`email` varchar(320),
	`loginMethod` varchar(64),
	`role` enum('user','admin','viewer','operator','team_lead','analyst','executive','client','soc') NOT NULL DEFAULT 'operator',
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`lastSignedIn` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`validationResultCreatedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`validationStartedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp DEFAULT 'CURRENT_TIMESTAMP',
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
	`cachedAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`vsf_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`vsf_corroboration_score` int,
	`vsf_corroboration_verdict` varchar(32),
	`vsf_corroboration_sources` int DEFAULT 0,
	`vsf_suppress_recommended` tinyint DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE `vuln_scan_imports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vsi_tenant_id` int,
	`vsi_scanner_type` enum('nessus','qualys','rapid7','openvas','burp','zap','custom') NOT NULL,
	`vsi_file_name` varchar(512) NOT NULL,
	`vsi_imported_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`vsi_total_hosts` int NOT NULL DEFAULT 0,
	`vsi_total_vulns` int NOT NULL DEFAULT 0,
	`vsi_critical` int NOT NULL DEFAULT 0,
	`vsi_high` int NOT NULL DEFAULT 0,
	`vsi_medium` int NOT NULL DEFAULT 0,
	`vsi_low` int NOT NULL DEFAULT 0,
	`vsi_imported_by` varchar(255)
);
--> statement-breakpoint
CREATE TABLE `vuln_scan_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`snapshot_type` enum('passive','active','llm_synthesis','full_pipeline','resynthesis') NOT NULL,
	`total_assets` int NOT NULL DEFAULT 0,
	`total_vulns` int NOT NULL DEFAULT 0,
	`critical_count` int NOT NULL DEFAULT 0,
	`high_count` int NOT NULL DEFAULT 0,
	`medium_count` int NOT NULL DEFAULT 0,
	`low_count` int NOT NULL DEFAULT 0,
	`total_ports` int NOT NULL DEFAULT 0,
	`total_exploits` int NOT NULL DEFAULT 0,
	`avg_confidence` int DEFAULT 0,
	`new_vulns_found` int DEFAULT 0,
	`resolved_vulns` int DEFAULT 0,
	`categories` json,
	`asset_breakdown` json,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `vuln_trend_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`snapshot_id` int NOT NULL,
	`engagement_id` int NOT NULL,
	`hostname` varchar(255) NOT NULL,
	`vuln_title` varchar(512) NOT NULL,
	`severity` varchar(32) NOT NULL,
	`category` varchar(128),
	`confidence` int,
	`cve` varchar(64),
	`tool` varchar(64),
	`status` enum('new','existing','resolved','regressed') NOT NULL DEFAULT 'new',
	`first_seen_snapshot_id` int,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `vuln_type_accuracy` (
	`id` int AUTO_INCREMENT NOT NULL,
	`comparison_id` int NOT NULL,
	`vuln_type` varchar(128) NOT NULL,
	`detection_rate` double,
	`false_positive_rate` double,
	`times_found` int DEFAULT 0,
	`times_missed` int DEFAULT 0,
	`times_false_positive` int DEFAULT 0,
	`target_preset` varchar(128) NOT NULL,
	`scored_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
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
	`was_tenant_id` int,
	`auth_credential_source` varchar(50),
	`auth_username` varchar(100),
	`auth_method` varchar(30)
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
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
	`deliveredAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `webhook_endpoints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhookId` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`endpoint_id` varchar(64) NOT NULL DEFAULT '',
	`integration_id` varchar(128),
	`url` text NOT NULL,
	`secret` varchar(255),
	`signature_header` varchar(128) NOT NULL DEFAULT 'x-webhook-signature',
	`signature_algorithm` enum('hmac_sha256','hmac_sha1','hmac_sha512','none') NOT NULL DEFAULT 'hmac_sha256',
	`status` enum('active','paused','disabled','error') NOT NULL DEFAULT 'active',
	`event_types` json,
	`target_pipeline_stages` json,
	`data_category` enum('osint','exploit_db','threat_intel','scanner','pentest_tool','phishing','c2','siem_soar','cloud','credential','custom') NOT NULL DEFAULT 'custom',
	`payload_format` enum('json','form','xml','raw') NOT NULL DEFAULT 'json',
	`transform_template` text,
	`rate_limit_per_minute` int DEFAULT 60,
	`rate_limit_per_hour` int DEFAULT 1000,
	`total_events_received` int DEFAULT 0,
	`total_events_processed` int DEFAULT 0,
	`total_events_failed` int DEFAULT 0,
	`last_event_at` bigint,
	`last_error_at` bigint,
	`last_error` text,
	`events` json,
	`format` varchar(50) DEFAULT 'json',
	`headers` json,
	`enabled` tinyint DEFAULT 1,
	`lastTriggered` timestamp,
	`failCount` int DEFAULT 0,
	`createdBy` int,
	`tenant_id` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `webhook_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`endpoint_id` varchar(64) NOT NULL,
	`event_id` varchar(64) NOT NULL,
	`event_type` varchar(128),
	`raw_payload` text,
	`normalized_payload` json,
	`headers` json,
	`source_ip` varchar(45),
	`status` enum('received','processing','processed','failed','skipped','replayed') NOT NULL DEFAULT 'received',
	`processing_started_at` bigint,
	`processing_completed_at` bigint,
	`processing_duration_ms` int,
	`error` text,
	`routed_to_stage` varchar(64),
	`routed_to_engagement` int,
	`result_summary` json,
	`retry_count` int DEFAULT 0,
	`max_retries` int DEFAULT 3,
	`next_retry_at` bigint,
	`received_at` bigint NOT NULL,
	`created_at` bigint NOT NULL
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
	`started_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`completed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `zero_day_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve` varchar(32) NOT NULL,
	`vendor` varchar(128) NOT NULL DEFAULT '',
	`product` varchar(128) NOT NULL DEFAULT '',
	`vuln_type` varchar(128) NOT NULL DEFAULT '',
	`description` text NOT NULL,
	`date_discovered` varchar(32),
	`date_patched` varchar(32),
	`advisory_url` text,
	`analysis_url` text,
	`root_cause_analysis` text,
	`reported_by` varchar(512),
	`source` enum('project_zero','cisa_kev') NOT NULL DEFAULT 'project_zero',
	`year` int,
	`fetched_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `zero_day_scan_matches` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`engagement_id` varchar(64),
	`domain` varchar(255) NOT NULL,
	`cve` varchar(32) NOT NULL,
	`vendor` varchar(128) NOT NULL DEFAULT '',
	`product` varchar(128) NOT NULL DEFAULT '',
	`match_type` enum('cve_exact','vendor_product','product_fuzzy') NOT NULL DEFAULT 'product_fuzzy',
	`confidence` enum('high','medium','low') NOT NULL DEFAULT 'low',
	`severity` enum('critical','high','medium') NOT NULL DEFAULT 'medium',
	`matched_asset` varchar(255) NOT NULL,
	`zero_day_description` text,
	`zero_day_type` varchar(128),
	`advisory_url` text,
	`dismissed` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
ALTER TABLE `agent_audit_log` ADD CONSTRAINT `agent_audit_log_agentId_agent_deployments_id_fk` FOREIGN KEY (`agentId`) REFERENCES `agent_deployments`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `agent_tasks` ADD CONSTRAINT `agent_tasks_agentId_agent_deployments_id_fk` FOREIGN KEY (`agentId`) REFERENCES `agent_deployments`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `campaign_engagements` ADD CONSTRAINT `campaign_engagements_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `deployment_history` ADD CONSTRAINT `deployment_history_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD CONSTRAINT `discovered_assets_scanId_domain_intel_scans_id_fk` FOREIGN KEY (`scanId`) REFERENCES `domain_intel_scans`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `domain_recon` ADD CONSTRAINT `domain_recon_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `engagement_reports` ADD CONSTRAINT `engagement_reports_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entity_profile_overrides` ADD CONSTRAINT `entity_profile_overrides_scan_id_domain_intel_scans_id_fk` FOREIGN KEY (`scan_id`) REFERENCES `domain_intel_scans`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entity_profile_overrides` ADD CONSTRAINT `entity_profile_overrides_overridden_by_users_id_fk` FOREIGN KEY (`overridden_by`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD CONSTRAINT `evidence_chain_of_custody_evidenceId_evidence_items_evidenceId_fk` FOREIGN KEY (`evidenceId`) REFERENCES `evidence_items`(`evidenceId`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `ir_runbook_entries` ADD CONSTRAINT `ir_runbook_entries_created_by_users_id_fk` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `osint_findings` ADD CONSTRAINT `osint_findings_engagementId_engagements_id_fk` FOREIGN KEY (`engagementId`) REFERENCES `engagements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `server_credentials` ADD CONSTRAINT `server_credentials_serverId_server_configs_id_fk` FOREIGN KEY (`serverId`) REFERENCES `server_configs`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `submission_history` ADD CONSTRAINT `submission_history_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `ability_graph_edges_edge_id_unique` ON `ability_graph_edges` (`edge_id`);--> statement-breakpoint
CREATE INDEX `ability_graph_nodes_node_id_unique` ON `ability_graph_nodes` (`node_id`);--> statement-breakpoint
CREATE INDEX `ability_graphs_graph_id_unique` ON `ability_graphs` (`graph_id`);--> statement-breakpoint
CREATE INDEX `art_report_idx` ON `ac3_report_artifacts` (`report_id`);--> statement-breakpoint
CREATE INDEX `art_finding_idx` ON `ac3_report_artifacts` (`finding_id`);--> statement-breakpoint
CREATE INDEX `art_label_idx` ON `ac3_report_artifacts` (`label`);--> statement-breakpoint
CREATE INDEX `artifact_id` ON `ac3_report_artifacts` (`artifact_id`);--> statement-breakpoint
CREATE INDEX `ac3_report_findings_rf_finding_id_unique` ON `ac3_report_findings` (`rf_finding_id`);--> statement-breakpoint
CREATE INDEX `rf_report_id_idx` ON `ac3_report_findings` (`rf_report_id`);--> statement-breakpoint
CREATE INDEX `rf_finding_id_idx` ON `ac3_report_findings` (`rf_finding_id`);--> statement-breakpoint
CREATE INDEX `rf_severity_idx` ON `ac3_report_findings` (`rf_severity`);--> statement-breakpoint
CREATE INDEX `ac3_reports_rpt_report_id_unique` ON `ac3_reports` (`rpt_report_id`);--> statement-breakpoint
CREATE INDEX `rpt_report_id_idx` ON `ac3_reports` (`rpt_report_id`);--> statement-breakpoint
CREATE INDEX `rpt_status_idx` ON `ac3_reports` (`rpt_status`);--> statement-breakpoint
CREATE INDEX `rpt_campaign_idx` ON `ac3_reports` (`rpt_campaign_id`);--> statement-breakpoint
CREATE INDEX `acc_comp_session_idx` ON `accuracy_comparisons` (`session_id`);--> statement-breakpoint
CREATE INDEX `acc_comp_target_idx` ON `accuracy_comparisons` (`target_preset`);--> statement-breakpoint
CREATE INDEX `acc_comp_engagement_idx` ON `accuracy_comparisons` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `acc_comp_scored_idx` ON `accuracy_comparisons` (`scored_at`);--> statement-breakpoint
CREATE INDEX `active_sessions_session_token_unique` ON `active_sessions` (`session_token`);--> statement-breakpoint
CREATE INDEX `ae_adj_type_idx` ON `adjustment_effectiveness` (`ae_adjustment_type`);--> statement-breakpoint
CREATE INDEX `ae_fail_cat_idx` ON `adjustment_effectiveness` (`ae_failure_category`);--> statement-breakpoint
CREATE INDEX `ae_service_idx` ON `adjustment_effectiveness` (`ae_service`);--> statement-breakpoint
CREATE INDEX `ae_composite_idx` ON `adjustment_effectiveness` (`ae_adjustment_type`,`ae_failure_category`,`ae_service`);--> statement-breakpoint
CREATE INDEX `ad_agent_id_idx` ON `agent_definitions` (`ad_agent_id`);--> statement-breakpoint
CREATE INDEX `ad_category_idx` ON `agent_definitions` (`ad_category`);--> statement-breakpoint
CREATE INDEX `ad_status_idx` ON `agent_definitions` (`ad_status`);--> statement-breakpoint
CREATE INDEX `avrcs_session_idx` ON `ai_vuln_research_code_snippets` (`session_id`);--> statement-breakpoint
CREATE INDEX `avrf_session_idx` ON `ai_vuln_research_findings` (`session_id`);--> statement-breakpoint
CREATE INDEX `avrf_severity_idx` ON `ai_vuln_research_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `avrf_vuln_type_idx` ON `ai_vuln_research_findings` (`vuln_type`);--> statement-breakpoint
CREATE INDEX `avrf_cwe_idx` ON `ai_vuln_research_findings` (`cwe_id`);--> statement-breakpoint
CREATE INDEX `avrf_poc_status_idx` ON `ai_vuln_research_findings` (`poc_status`);--> statement-breakpoint
CREATE INDEX `avrs_user_idx` ON `ai_vuln_research_sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `avrs_status_idx` ON `ai_vuln_research_sessions` (`status`);--> statement-breakpoint
CREATE INDEX `avrs_target_idx` ON `ai_vuln_research_sessions` (`target_type`);--> statement-breakpoint
CREATE INDEX `avrs_program_idx` ON `ai_vuln_research_sessions` (`bug_bounty_program_id`);--> statement-breakpoint
CREATE INDEX `aec_catalog_entry_id_unique` ON `approved_exploit_catalog` (`catalog_entry_id`);--> statement-breakpoint
CREATE INDEX `aec_quarantine_id_idx` ON `approved_exploit_catalog` (`quarantine_id`);--> statement-breakpoint
CREATE INDEX `idx_technique_id` ON `atomic_test_executions` (`technique_id`);--> statement-breakpoint
CREATE INDEX `idx_status` ON `atomic_test_executions` (`status`);--> statement-breakpoint
CREATE INDEX `idx_executed_by` ON `atomic_test_executions` (`executed_by`);--> statement-breakpoint
CREATE INDEX `idx_attack_chain` ON `atomic_test_executions` (`attack_chain_id`);--> statement-breakpoint
CREATE INDEX `idx_technique_id` ON `atomic_tests` (`technique_id`);--> statement-breakpoint
CREATE INDEX `idx_mitre_tactic` ON `atomic_tests` (`mitre_tactic`);--> statement-breakpoint
CREATE INDEX `idx_executor_type` ON `atomic_tests` (`executor_type`);--> statement-breakpoint
CREATE INDEX `idx_supported_platforms` ON `atomic_tests` (`supported_platforms`);--> statement-breakpoint
CREATE INDEX `guid` ON `atomic_tests` (`guid`);--> statement-breakpoint
CREATE INDEX `acc_actor_idx` ON `attack_chains_catalog` (`acc_actor_id`);--> statement-breakpoint
CREATE INDEX `acc_chain_name_idx` ON `attack_chains_catalog` (`acc_chain_name`);--> statement-breakpoint
CREATE INDEX `pathId` ON `attack_paths` (`pathId`);--> statement-breakpoint
CREATE INDEX `templateId` ON `attack_sequence_templates` (`templateId`);--> statement-breakpoint
CREATE INDEX `bspr_rule_id_idx` ON `benchmark_scan_plan_rules` (`rule_id`);--> statement-breakpoint
CREATE INDEX `bspr_lab_id_idx` ON `benchmark_scan_plan_rules` (`lab_id`);--> statement-breakpoint
CREATE INDEX `bspr_active_idx` ON `benchmark_scan_plan_rules` (`is_active`);--> statement-breakpoint
CREATE INDEX `btr_run_id_idx` ON `benchmark_tool_results` (`run_id`);--> statement-breakpoint
CREATE INDEX `btr_lab_tool_idx` ON `benchmark_tool_results` (`lab_id`,`tool`);--> statement-breakpoint
CREATE INDEX `bblts_category_idx` ON `bug_bounty_llm_training_samples` (`category`);--> statement-breakpoint
CREATE INDEX `bblts_finding_idx` ON `bug_bounty_llm_training_samples` (`finding_id`);--> statement-breakpoint
CREATE INDEX `bblts_quality_idx` ON `bug_bounty_llm_training_samples` (`quality_score`);--> statement-breakpoint
CREATE INDEX `bblts_severity_idx` ON `bug_bounty_llm_training_samples` (`severity_rating`);--> statement-breakpoint
CREATE INDEX `bblts_cwe_idx` ON `bug_bounty_llm_training_samples` (`cwe_id`);--> statement-breakpoint
CREATE INDEX `bblts_program_idx` ON `bug_bounty_llm_training_samples` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bblts_enrichment_idx` ON `bug_bounty_llm_training_samples` (`enrichment_status`);--> statement-breakpoint
CREATE INDEX `bblts_bounty_idx` ON `bug_bounty_llm_training_samples` (`bounty_amount`);--> statement-breakpoint
CREATE INDEX `bbps_program_idx` ON `bug_bounty_program_scopes` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bbps_asset_type_idx` ON `bug_bounty_program_scopes` (`asset_type`);--> statement-breakpoint
CREATE INDEX `bbpw_program_idx` ON `bug_bounty_program_weaknesses` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bbpw_cwe_idx` ON `bug_bounty_program_weaknesses` (`cwe_id`);--> statement-breakpoint
CREATE INDEX `br_user_idx` ON `bug_reports` (`user_id`);--> statement-breakpoint
CREATE INDEX `br_status_idx` ON `bug_reports` (`status`);--> statement-breakpoint
CREATE INDEX `br_severity_idx` ON `bug_reports` (`severity`);--> statement-breakpoint
CREATE INDEX `br_created_idx` ON `bug_reports` (`created_at`);--> statement-breakpoint
CREATE INDEX `bsh_engagement_idx` ON `burp_scan_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `bsh_user_idx` ON `burp_scan_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `bsh_status_idx` ON `burp_scan_history` (`status`);--> statement-breakpoint
CREATE INDEX `cel_technique_idx` ON `c2_execution_log` (`technique_id`);--> statement-breakpoint
CREATE INDEX `cel_framework_idx` ON `c2_execution_log` (`cel_framework`);--> statement-breakpoint
CREATE INDEX `cel_engagement_idx` ON `c2_execution_log` (`cel_engagement_id`);--> statement-breakpoint
CREATE INDEX `caldera_accounts_email_unique` ON `caldera_accounts` (`email`);--> statement-breakpoint
CREATE INDEX `campaign_archetypes_slug_unique` ON `campaign_archetypes` (`slug`);--> statement-breakpoint
CREATE INDEX `crs_campaign_id_idx` ON `campaign_run_states` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `crs_is_running_idx` ON `campaign_run_states` (`is_running`);--> statement-breakpoint
CREATE INDEX `chain_runs_chain_id_unique` ON `chain_runs` (`chain_id`);--> statement-breakpoint
CREATE INDEX `idx_chain_stage_chain_id` ON `chain_stage_results` (`chain_id`);--> statement-breakpoint
CREATE INDEX `cicd_bl_pipeline_idx` ON `cicd_baselines` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `cicd_bl_commit_idx` ON `cicd_baselines` (`commit_sha`);--> statement-breakpoint
CREATE INDEX `idx_pipeline_framework` ON `cicd_compliance_scores` (`pipeline_id`,`framework`);--> statement-breakpoint
CREATE INDEX `idx_run_id` ON `cicd_compliance_scores` (`run_id`);--> statement-breakpoint
CREATE INDEX `idx_created_at` ON `cicd_compliance_scores` (`created_at`);--> statement-breakpoint
CREATE INDEX `uq_pipeline_user` ON `cicd_pipeline_access` (`pipeline_id`,`user_id`);--> statement-breakpoint
CREATE INDEX `cicd_rf_run_idx` ON `cicd_run_findings` (`run_id`);--> statement-breakpoint
CREATE INDEX `cicd_rf_pipeline_idx` ON `cicd_run_findings` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `cicd_rf_hash_idx` ON `cicd_run_findings` (`title_hash`);--> statement-breakpoint
CREATE INDEX `cicd_rf_severity_idx` ON `cicd_run_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `cicd_sbom_run_idx` ON `cicd_sbom_artifacts` (`run_id`);--> statement-breakpoint
CREATE INDEX `cicd_sbom_pipeline_idx` ON `cicd_sbom_artifacts` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `idx_pipeline_id` ON `cicd_webhook_deliveries` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `idx_delivery_status` ON `cicd_webhook_deliveries` (`delivery_status`);--> statement-breakpoint
CREATE INDEX `idx_next_retry` ON `cicd_webhook_deliveries` (`next_retry_at`);--> statement-breakpoint
CREATE INDEX `cip_domain_idx` ON `company_intel_profiles` (`cip_domain`);--> statement-breakpoint
CREATE INDEX `cip_tenant_idx` ON `company_intel_profiles` (`cip_tenant_id`);--> statement-breakpoint
CREATE INDEX `baseline_id` ON `config_baselines` (`baseline_id`);--> statement-breakpoint
CREATE INDEX `alert_id` ON `config_drift_alerts` (`alert_id`);--> statement-breakpoint
CREATE INDEX `cph_connector_domain_idx` ON `connector_performance_history` (`connector`,`domain`);--> statement-breakpoint
CREATE INDEX `cph_sector_idx` ON `connector_performance_history` (`sector`);--> statement-breakpoint
CREATE INDEX `cph_scan_id_idx` ON `connector_performance_history` (`scan_id`);--> statement-breakpoint
CREATE INDEX `cph_connector_sector_idx` ON `connector_performance_history` (`connector`,`sector`);--> statement-breakpoint
CREATE INDEX `cph_created_at_idx` ON `connector_performance_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `cv_scan_run_idx` ON `container_vulnerabilities` (`scan_run_id`);--> statement-breakpoint
CREATE INDEX `cv_severity_idx` ON `container_vulnerabilities` (`severity`);--> statement-breakpoint
CREATE INDEX `cv_vuln_id_idx` ON `container_vulnerabilities` (`vuln_id`);--> statement-breakpoint
CREATE INDEX `cv_image_idx` ON `container_vulnerabilities` (`image_name`);--> statement-breakpoint
CREATE INDEX `cspmf_scan_run_idx` ON `cspm_findings` (`scan_run_id`);--> statement-breakpoint
CREATE INDEX `cspmf_severity_idx` ON `cspm_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `cspmf_status_idx` ON `cspm_findings` (`status`);--> statement-breakpoint
CREATE INDEX `cspmf_check_id_idx` ON `cspm_findings` (`check_id`);--> statement-breakpoint
CREATE INDEX `cspmf_provider_idx` ON `cspm_findings` (`provider`);--> statement-breakpoint
CREATE INDEX `cspm_scan_tool_idx` ON `cspm_scan_runs` (`scan_tool`);--> statement-breakpoint
CREATE INDEX `cspm_scan_provider_idx` ON `cspm_scan_runs` (`scan_provider`);--> statement-breakpoint
CREATE INDEX `cspm_scan_status_idx` ON `cspm_scan_runs` (`scan_status`);--> statement-breakpoint
CREATE INDEX `cspm_credential_idx` ON `cspm_scan_runs` (`credential_id`);--> statement-breakpoint
CREATE INDEX `cspm_created_idx` ON `cspm_scan_runs` (`created_at`);--> statement-breakpoint
CREATE INDEX `cspm_engagement_idx` ON `cspm_scan_runs` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ca_email_idx` ON `customer_accounts` (`ca_email`);--> statement-breakpoint
CREATE INDEX `ca_tenant_idx` ON `customer_accounts` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `cal_customer_idx` ON `customer_audit_log` (`customer_account_id`);--> statement-breakpoint
CREATE INDEX `cal_tenant_idx` ON `customer_audit_log` (`cal_tenant_id`);--> statement-breakpoint
CREATE INDEX `cal_action_idx` ON `customer_audit_log` (`cal_action`);--> statement-breakpoint
CREATE INDEX `ci_integration_id_unique` ON `customer_integrations` (`integration_id`);--> statement-breakpoint
CREATE INDEX `ci_category_idx` ON `customer_integrations` (`category`);--> statement-breakpoint
CREATE INDEX `ci_status_idx` ON `customer_integrations` (`status`);--> statement-breakpoint
CREATE INDEX `ci_tenant_idx` ON `customer_integrations` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `cip_customer_id_idx` ON `customer_intelligence_profiles` (`customer_id`);--> statement-breakpoint
CREATE INDEX `cip_customer_name_idx` ON `customer_intelligence_profiles` (`customer_name`);--> statement-breakpoint
CREATE INDEX `csr_tenant_idx` ON `customer_shared_reports` (`csr_tenant_id`);--> statement-breakpoint
CREATE INDEX `csr_report_type_idx` ON `customer_shared_reports` (`csr_report_type`);--> statement-breakpoint
CREATE INDEX `csp_engagement_idx` ON `customer_stack_profiles` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `csp_customer_idx` ON `customer_stack_profiles` (`customer_name`);--> statement-breakpoint
CREATE INDEX `cve_enrichment_cve_id_unique` ON `cve_enrichment` (`cve_id`);--> statement-breakpoint
CREATE INDEX `dfr_feed_name` ON `darkweb_feed_registry` (`dfr_feed_name`);--> statement-breakpoint
CREATE INDEX `defense_scores_score_id_unique` ON `defense_scores` (`score_id`);--> statement-breakpoint
CREATE INDEX `dr_email_idx` ON `demo_requests` (`email`);--> statement-breakpoint
CREATE INDEX `dr_status_idx` ON `demo_requests` (`status`);--> statement-breakpoint
CREATE INDEX `dr_created_at_idx` ON `demo_requests` (`created_at`);--> statement-breakpoint
CREATE INDEX `dh_deployment_id_idx` ON `deployment_history` (`deployment_id`);--> statement-breakpoint
CREATE INDEX `dh_user_id_idx` ON `deployment_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `dh_environment_idx` ON `deployment_history` (`environment`);--> statement-breakpoint
CREATE INDEX `dh_status_idx` ON `deployment_history` (`status`);--> statement-breakpoint
CREATE INDEX `dh_created_at_idx` ON `deployment_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `update_org_idx` ON `deployment_update_history` (`org_id`);--> statement-breakpoint
CREATE INDEX `update_status_idx` ON `deployment_update_history` (`status`);--> statement-breakpoint
CREATE INDEX `version_idx` ON `deployment_versions` (`version`);--> statement-breakpoint
CREATE INDEX `channel_idx` ON `deployment_versions` (`channel`);--> statement-breakpoint
CREATE INDEX `testId` ON `detection_tests` (`testId`);--> statement-breakpoint
CREATE INDEX `dfir_report_idx` ON `dfir_observations` (`dfir_report_id`);--> statement-breakpoint
CREATE INDEX `dfir_actor_idx` ON `dfir_observations` (`dfir_actor_id`);--> statement-breakpoint
CREATE INDEX `dfir_technique_idx` ON `dfir_observations` (`dfir_technique_id`);--> statement-breakpoint
CREATE INDEX `dfir_type_idx` ON `dfir_observations` (`dfir_observation_type`);--> statement-breakpoint
CREATE INDEX `ioc_report_idx` ON `dfir_report_iocs` (`report_id`);--> statement-breakpoint
CREATE INDEX `ioc_type_idx` ON `dfir_report_iocs` (`ioc_type`);--> statement-breakpoint
CREATE INDEX `ioc_value_idx` ON `dfir_report_iocs` (`ioc_value`);--> statement-breakpoint
CREATE INDEX `dfir_source_idx` ON `dfir_reports` (`dfir_source`);--> statement-breakpoint
CREATE INDEX `dfir_status_idx` ON `dfir_reports` (`dfir_status`);--> statement-breakpoint
CREATE INDEX `dfir_external_id_idx` ON `dfir_reports` (`external_id`);--> statement-breakpoint
CREATE INDEX `ditd_example_id_idx` ON `di_incident_training_data` (`example_id`);--> statement-breakpoint
CREATE INDEX `ditd_scan_id_idx` ON `di_incident_training_data` (`scan_id`);--> statement-breakpoint
CREATE INDEX `ditd_domain_idx` ON `di_incident_training_data` (`domain`);--> statement-breakpoint
CREATE INDEX `ditd_sector_idx` ON `di_incident_training_data` (`sector`);--> statement-breakpoint
CREATE INDEX `ditd_type_idx` ON `di_incident_training_data` (`example_type`);--> statement-breakpoint
CREATE INDEX `ditd_quality_idx` ON `di_incident_training_data` (`quality_band`);--> statement-breakpoint
CREATE INDEX `ditd_analyst_rating_idx` ON `di_incident_training_data` (`analyst_rating`);--> statement-breakpoint
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
CREATE INDEX `dns_mon_enabled_idx` ON `dns_security_monitoring_config` (`enabled`);--> statement-breakpoint
CREATE INDEX `ember_agent_id_idx` ON `ember_agents` (`agent_id`);--> statement-breakpoint
CREATE INDEX `ember_engagement_idx` ON `ember_agents` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ember_state_idx` ON `ember_agents` (`ember_state`);--> statement-breakpoint
CREATE INDEX `ember_profile_idx` ON `ember_agents` (`ember_profile`);--> statement-breakpoint
CREATE INDEX `ember_swarm_idx` ON `ember_agents` (`ember_swarm_id`);--> statement-breakpoint
CREATE INDEX `eb_agent_idx` ON `ember_beacons` (`ember_beacon_agent_id`);--> statement-breakpoint
CREATE INDEX `eb_received_idx` ON `ember_beacons` (`ember_beacon_received_at`);--> statement-breakpoint
CREATE INDEX `ecl_campaign_id_idx` ON `ember_campaign_logs` (`ecl_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecl_level_idx` ON `ember_campaign_logs` (`ecl_level`);--> statement-breakpoint
CREATE INDEX `ecph_phase_id_idx` ON `ember_campaign_phases` (`ecph_phase_id`);--> statement-breakpoint
CREATE INDEX `ecph_campaign_id_idx` ON `ember_campaign_phases` (`ecph_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecph_status_idx` ON `ember_campaign_phases` (`ecph_status`);--> statement-breakpoint
CREATE INDEX `ecmp_campaign_id_idx` ON `ember_campaigns` (`ecmp_campaign_id`);--> statement-breakpoint
CREATE INDEX `ecmp_status_idx` ON `ember_campaigns` (`ecmp_status`);--> statement-breakpoint
CREATE INDEX `ecmp_created_by_idx` ON `ember_campaigns` (`ecmp_created_by`);--> statement-breakpoint
CREATE INDEX `ect_template_id_idx` ON `ember_custom_templates` (`ect_template_id`);--> statement-breakpoint
CREATE INDEX `ect_category_idx` ON `ember_custom_templates` (`ect_category`);--> statement-breakpoint
CREATE INDEX `ect_created_by_idx` ON `ember_custom_templates` (`ect_created_by`);--> statement-breakpoint
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
CREATE INDEX `et_task_id_idx` ON `ember_tasks` (`ember_task_id`);--> statement-breakpoint
CREATE INDEX `eat_engagement_idx` ON `engagement_approved_targets` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `eat_hostname_idx` ON `engagement_approved_targets` (`engagement_id`,`hostname`);--> statement-breakpoint
CREATE INDEX `ecp_engagement_idx` ON `engagement_comms_protocols` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ecp_roe_doc_idx` ON `engagement_comms_protocols` (`roe_document_id`);--> statement-breakpoint
CREATE INDEX `ecl_engagement_idx` ON `engagement_credential_lists` (`ecl_engagement_id`);--> statement-breakpoint
CREATE INDEX `ecl_source_idx` ON `engagement_credential_lists` (`ecl_source`);--> statement-breakpoint
CREATE INDEX `ecl_domain_idx` ON `engagement_credential_lists` (`ecl_domain`);--> statement-breakpoint
CREATE INDEX `ef_engagement_idx` ON `engagement_findings` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ef_result_idx` ON `engagement_findings` (`result_id`);--> statement-breakpoint
CREATE INDEX `ef_severity_idx` ON `engagement_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `ef_corroboration_idx` ON `engagement_findings` (`corroboration_tier`);--> statement-breakpoint
CREATE INDEX `er_engagement_idx` ON `engagement_results` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `er_operator_idx` ON `engagement_results` (`operator_id`);--> statement-breakpoint
CREATE INDEX `er_status_idx` ON `engagement_results` (`status`);--> statement-breakpoint
CREATE INDEX `esc_engagement_idx` ON `engagement_scope_constraints` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `esc_roe_doc_idx` ON `engagement_scope_constraints` (`roe_document_id`);--> statement-breakpoint
CREATE INDEX `engagement_shares_token_unique` ON `engagement_shares` (`token`);--> statement-breakpoint
CREATE INDEX `et_engagement_idx` ON `engagement_telemetry` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `et_phase_idx` ON `engagement_telemetry` (`phase`);--> statement-breakpoint
CREATE INDEX `et_event_type_idx` ON `engagement_telemetry` (`event_type`);--> statement-breakpoint
CREATE INDEX `et_error_class_idx` ON `engagement_telemetry` (`error_class`);--> statement-breakpoint
CREATE INDEX `et_correlation_idx` ON `engagement_telemetry` (`correlation_id`);--> statement-breakpoint
CREATE INDEX `et_created_at_idx` ON `engagement_telemetry` (`created_at`);--> statement-breakpoint
CREATE INDEX `et_success_idx` ON `engagement_telemetry` (`success`);--> statement-breakpoint
CREATE INDEX `et_source_module_idx` ON `engagement_telemetry` (`source_module`);--> statement-breakpoint
CREATE INDEX `eh_actor_id_idx` ON `enrichment_history` (`actor_id`);--> statement-breakpoint
CREATE INDEX `eh_created_at_idx` ON `enrichment_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `eh_triggered_by_idx` ON `enrichment_history` (`triggered_by`);--> statement-breakpoint
CREATE INDEX `epo_scan_id_idx` ON `entity_profile_overrides` (`scan_id`);--> statement-breakpoint
CREATE INDEX `epo_domain_idx` ON `entity_profile_overrides` (`domain`);--> statement-breakpoint
CREATE INDEX `idx_incident_id` ON `error_incidents` (`incidentId`);--> statement-breakpoint
CREATE INDEX `idx_scope` ON `error_incidents` (`scope`);--> statement-breakpoint
CREATE INDEX `idx_created` ON `error_incidents` (`createdAt`);--> statement-breakpoint
CREATE INDEX `ega_engagement_idx` ON `evidence_guardrail_audit` (`ega_engagement_id`);--> statement-breakpoint
CREATE INDEX `ega_specialist_idx` ON `evidence_guardrail_audit` (`ega_specialist`);--> statement-breakpoint
CREATE INDEX `ega_passed_idx` ON `evidence_guardrail_audit` (`ega_passed`);--> statement-breakpoint
CREATE INDEX `ega_recommendation_idx` ON `evidence_guardrail_audit` (`ega_recommendation`);--> statement-breakpoint
CREATE INDEX `ega_created_at_idx` ON `evidence_guardrail_audit` (`ega_created_at`);--> statement-breakpoint
CREATE INDEX `eia_engagement_idx` ON `evidence_integrity_anchors` (`eia_engagement_id`);--> statement-breakpoint
CREATE INDEX `eia_status_idx` ON `evidence_integrity_anchors` (`eia_status`);--> statement-breakpoint
CREATE INDEX `evidenceId` ON `evidence_items` (`evidenceId`);--> statement-breakpoint
CREATE INDEX `idx_cveId` ON `exploit_intelligence` (`cveId`);--> statement-breakpoint
CREATE INDEX `idx_ei_source` ON `exploit_intelligence` (`ei_source`);--> statement-breakpoint
CREATE INDEX `elc_chain_name_idx` ON `exploit_learning_chains` (`chain_name`);--> statement-breakpoint
CREATE INDEX `elc_engagement_idx` ON `exploit_learning_chains` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `elo_engagement_idx` ON `exploit_learning_outcomes` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `elo_vuln_class_idx` ON `exploit_learning_outcomes` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `elo_attempt_id_idx` ON `exploit_learning_outcomes` (`attempt_id`);--> statement-breakpoint
CREATE INDEX `elo_target_idx` ON `exploit_learning_outcomes` (`target_hostname`);--> statement-breakpoint
CREATE INDEX `elo_success_idx` ON `exploit_learning_outcomes` (`success`);--> statement-breakpoint
CREATE INDEX `elp_pattern_key_idx` ON `exploit_learning_patterns` (`pattern_key`);--> statement-breakpoint
CREATE INDEX `elp_vuln_class_idx` ON `exploit_learning_patterns` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `em_vuln_class_idx` ON `exploit_methodologies` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `em_source_idx` ON `exploit_methodologies` (`source`);--> statement-breakpoint
CREATE INDEX `em_weight_idx` ON `exploit_methodologies` (`weight`);--> statement-breakpoint
CREATE INDEX `idx_engagement` ON `exploit_plan_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `idx_gate` ON `exploit_plan_history` (`gate_id`);--> statement-breakpoint
CREATE INDEX `ep_actor_idx` ON `exploit_playbooks` (`ep_actor_id`);--> statement-breakpoint
CREATE INDEX `ep_technique_idx` ON `exploit_playbooks` (`ep_technique_id`);--> statement-breakpoint
CREATE INDEX `ep_tool_idx` ON `exploit_playbooks` (`ep_tool_name`);--> statement-breakpoint
CREATE INDEX `eqq_quarantine_id_unique` ON `exploit_quarantine_queue` (`quarantine_id`);--> statement-breakpoint
CREATE INDEX `eqq_status_idx` ON `exploit_quarantine_queue` (`status`);--> statement-breakpoint
CREATE INDEX `eqq_engagement_idx` ON `exploit_quarantine_queue` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ess_snapshot_id_unique` ON `exploit_selection_snapshots` (`snapshot_id`);--> statement-breakpoint
CREATE INDEX `ess_engagement_idx` ON `exploit_selection_snapshots` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `fc_host_port_idx` ON `fingerprint_cache` (`fc_host`,`fc_port`);--> statement-breakpoint
CREATE INDEX `fc_expires_idx` ON `fingerprint_cache` (`fc_expires_at`);--> statement-breakpoint
CREATE INDEX `violationId` ON `guardrail_violations` (`violationId`);--> statement-breakpoint
CREATE INDEX `idx_source_sourceId` ON `incident_reports` (`source`,`sourceId`);--> statement-breakpoint
CREATE INDEX `info_ops_campaigns_ioCampaignId_unique` ON `info_ops_campaigns` (`ioCampaignId`);--> statement-breakpoint
CREATE INDEX `iel_integration_idx` ON `integration_execution_log` (`integration_id`);--> statement-breakpoint
CREATE INDEX `iel_engagement_idx` ON `integration_execution_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `iel_stage_idx` ON `integration_execution_log` (`pipeline_stage`);--> statement-breakpoint
CREATE INDEX `ihc_integration_idx` ON `integration_health_checks` (`integration_id`);--> statement-breakpoint
CREATE INDEX `ihc_checked_at_idx` ON `integration_health_checks` (`checked_at`);--> statement-breakpoint
CREATE INDEX `ig_engagement_idx` ON `intelligence_gaps` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ig_scan_idx` ON `intelligence_gaps` (`scan_id`);--> statement-breakpoint
CREATE INDEX `ig_customer_idx` ON `intelligence_gaps` (`customer_id`);--> statement-breakpoint
CREATE INDEX `ig_status_idx` ON `intelligence_gaps` (`status`);--> statement-breakpoint
CREATE INDEX `ig_category_idx` ON `intelligence_gaps` (`category`);--> statement-breakpoint
CREATE INDEX `itm_actor_idx` ON `ioc_ttp_mappings` (`itm_actor_id`);--> statement-breakpoint
CREATE INDEX `itm_technique_idx` ON `ioc_ttp_mappings` (`itm_technique_id`);--> statement-breakpoint
CREATE INDEX `itm_ioc_type_idx` ON `ioc_ttp_mappings` (`itm_ioc_type`);--> statement-breakpoint
CREATE INDEX `irr_entry_id_idx` ON `ir_runbook_entries` (`entry_id`);--> statement-breakpoint
CREATE INDEX `irr_alarm_name_idx` ON `ir_runbook_entries` (`alarm_name`);--> statement-breakpoint
CREATE INDEX `irr_severity_idx` ON `ir_runbook_entries` (`severity`);--> statement-breakpoint
CREATE INDEX `irr_category_idx` ON `ir_runbook_entries` (`category`);--> statement-breakpoint
CREATE INDEX `irr_is_active_idx` ON `ir_runbook_entries` (`is_active`);--> statement-breakpoint
CREATE INDEX `ke_entry_id_unique` ON `knowledge_entries` (`entry_id`);--> statement-breakpoint
CREATE INDEX `ke_category_idx` ON `knowledge_entries` (`category`);--> statement-breakpoint
CREATE INDEX `ke_phase_idx` ON `knowledge_entries` (`phase`);--> statement-breakpoint
CREATE INDEX `ksi_definitions_ksi_id_unique` ON `ksi_definitions` (`ksi_id`);--> statement-breakpoint
CREATE INDEX `ksi_evidence_evidence_id_unique` ON `ksi_evidence` (`evidence_id`);--> statement-breakpoint
CREATE INDEX `ksi_evidence_chains_chain_id_unique` ON `ksi_evidence_chains` (`chain_id`);--> statement-breakpoint
CREATE INDEX `ksi_validation_runs_run_id_unique` ON `ksi_validation_runs` (`run_id`);--> statement-breakpoint
CREATE INDEX `ksi_validation_schedules_schedule_id_unique` ON `ksi_validation_schedules` (`schedule_id`);--> statement-breakpoint
CREATE INDEX `usage_org_id_idx` ON `license_usage_logs` (`org_id`);--> statement-breakpoint
CREATE INDEX `usage_action_idx` ON `license_usage_logs` (`action`);--> statement-breakpoint
CREATE INDEX `usage_timestamp_idx` ON `license_usage_logs` (`timestamp`);--> statement-breakpoint
CREATE INDEX `licensed_org_id_idx` ON `licensed_organizations` (`org_id`);--> statement-breakpoint
CREATE INDEX `licensed_status_idx` ON `licensed_organizations` (`status`);--> statement-breakpoint
CREATE INDEX `licensed_tier_idx` ON `licensed_organizations` (`tier`);--> statement-breakpoint
CREATE INDEX `idx_accuracy_target` ON `llm_accuracy_scores` (`target_preset`);--> statement-breakpoint
CREATE INDEX `idx_accuracy_session` ON `llm_accuracy_scores` (`session_id`);--> statement-breakpoint
CREATE INDEX `ldl_engagement_idx` ON `llm_decision_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ldl_phase_idx` ON `llm_decision_log` (`dl_phase`);--> statement-breakpoint
CREATE INDEX `ldl_caller_idx` ON `llm_decision_log` (`dl_caller`);--> statement-breakpoint
CREATE INDEX `ldl_outcome_idx` ON `llm_decision_log` (`dl_outcome`);--> statement-breakpoint
CREATE INDEX `idx_learning_target` ON `llm_learning_entries` (`target_preset`);--> statement-breakpoint
CREATE INDEX `idx_learning_feedback` ON `llm_learning_entries` (`feedback_type`);--> statement-breakpoint
CREATE INDEX `lte_model_idx` ON `llm_training_examples` (`te_model`);--> statement-breakpoint
CREATE INDEX `lte_source_idx` ON `llm_training_examples` (`te_source`);--> statement-breakpoint
CREATE INDEX `lte_quality_idx` ON `llm_training_examples` (`te_quality`);--> statement-breakpoint
CREATE INDEX `lte_example_id_idx` ON `llm_training_examples` (`example_id`);--> statement-breakpoint
CREATE INDEX `ma_methodology_idx` ON `methodology_attempts` (`methodology_id`);--> statement-breakpoint
CREATE INDEX `ma_engagement_idx` ON `methodology_attempts` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ma_vuln_class_idx` ON `methodology_attempts` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `ma_success_idx` ON `methodology_attempts` (`success`);--> statement-breakpoint
CREATE INDEX `ma_created_at_idx` ON `methodology_attempts` (`created_at`);--> statement-breakpoint
CREATE INDEX `mp_vuln_class_idx` ON `methodology_performance` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `mp_tech_stack_idx` ON `methodology_performance` (`tech_stack_key`);--> statement-breakpoint
CREATE INDEX `mp_success_rate_idx` ON `methodology_performance` (`success_rate`);--> statement-breakpoint
CREATE INDEX `idx_type_status` ON `mtls_certificates` (`type`,`status`);--> statement-breakpoint
CREATE INDEX `idx_c2server` ON `mtls_certificates` (`c2ServerId`,`status`);--> statement-breakpoint
CREATE INDEX `npe_execution_id_idx` ON `nexus_pipeline_executions` (`npe_execution_id`);--> statement-breakpoint
CREATE INDEX `npe_caller_name_idx` ON `nexus_pipeline_executions` (`npe_caller_name`);--> statement-breakpoint
CREATE INDEX `npe_status_idx` ON `nexus_pipeline_executions` (`npe_status`);--> statement-breakpoint
CREATE INDEX `npe_tier_idx` ON `nexus_pipeline_executions` (`npe_graduation_tier`);--> statement-breakpoint
CREATE INDEX `nqg_execution_id_idx` ON `nexus_quality_gates` (`nqg_execution_id`);--> statement-breakpoint
CREATE INDEX `nqg_gate_type_idx` ON `nexus_quality_gates` (`nqg_gate_type`);--> statement-breakpoint
CREATE INDEX `nsc_config_name_idx` ON `nexus_shadow_configs` (`nsc_config_name`);--> statement-breakpoint
CREATE INDEX `nsc_enabled_idx` ON `nexus_shadow_configs` (`nsc_enabled`);--> statement-breakpoint
CREATE INDEX `nst_config_id_idx` ON `nexus_shadow_tests` (`nst_config_id`);--> statement-breakpoint
CREATE INDEX `nst_caller_idx` ON `nexus_shadow_tests` (`nst_caller`);--> statement-breakpoint
CREATE INDEX `nst_verdict_idx` ON `nexus_shadow_tests` (`nst_judge_verdict`);--> statement-breakpoint
CREATE INDEX `nst_status_idx` ON `nexus_shadow_tests` (`nst_status`);--> statement-breakpoint
CREATE INDEX `nst_created_at_idx` ON `nexus_shadow_tests` (`nst_created_at`);--> statement-breakpoint
CREATE INDEX `nf_engagement_idx` ON `nuclei_findings` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `nf_cve_idx` ON `nuclei_findings` (`cve_id`);--> statement-breakpoint
CREATE INDEX `nf_template_idx` ON `nuclei_findings` (`template_id`);--> statement-breakpoint
CREATE INDEX `nf_severity_idx` ON `nuclei_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `nf_host_idx` ON `nuclei_findings` (`host`);--> statement-breakpoint
CREATE INDEX `nf_hash_idx` ON `nuclei_findings` (`finding_hash`);--> statement-breakpoint
CREATE INDEX `ntm_cve_idx` ON `nuclei_template_mappings` (`cve_id`);--> statement-breakpoint
CREATE INDEX `ntm_template_idx` ON `nuclei_template_mappings` (`template_path`);--> statement-breakpoint
CREATE INDEX `ntm_vuln_class_idx` ON `nuclei_template_mappings` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `obs_alert_id` ON `observation_alert_history` (`obs_alert_id`);--> statement-breakpoint
CREATE INDEX `obs_rule_id` ON `observation_alert_rules` (`obs_rule_id`);--> statement-breakpoint
CREATE INDEX `idx_engagement` ON `offensive_audit_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `idx_operator` ON `offensive_audit_log` (`operator_id`);--> statement-breakpoint
CREATE INDEX `idx_action_type` ON `offensive_audit_log` (`action_type`);--> statement-breakpoint
CREATE INDEX `idx_risk_tier` ON `offensive_audit_log` (`risk_tier`);--> statement-breakpoint
CREATE INDEX `idx_created_at` ON `offensive_audit_log` (`created_at`);--> statement-breakpoint
CREATE INDEX `op_plan_id_idx` ON `orchestration_plans` (`plan_id`);--> statement-breakpoint
CREATE INDEX `op_engagement_id_idx` ON `orchestration_plans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `op_campaign_id_idx` ON `orchestration_plans` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `op_status_idx` ON `orchestration_plans` (`op_status`);--> statement-breakpoint
CREATE INDEX `oscal_exports_export_id_unique` ON `oscal_exports` (`export_id`);--> statement-breakpoint
CREATE INDEX `ppc_cache_key_idx` ON `parsed_policy_cache` (`cache_key`);--> statement-breakpoint
CREATE INDEX `ppc_platform_slug_idx` ON `parsed_policy_cache` (`platform`,`program_slug`);--> statement-breakpoint
CREATE INDEX `ransomware_groups_groupName_unique` ON `ransomware_groups` (`groupName`);--> statement-breakpoint
CREATE INDEX `rtcl_campaign_id_idx` ON `redteam_campaign_logs` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `rtcl_stage_id_idx` ON `redteam_campaign_logs` (`stage_id`);--> statement-breakpoint
CREATE INDEX `rtcl_log_type_idx` ON `redteam_campaign_logs` (`log_type`);--> statement-breakpoint
CREATE INDEX `rtcs_campaign_id_idx` ON `redteam_campaign_stages` (`campaign_id`);--> statement-breakpoint
CREATE INDEX `rtcs_stage_order_idx` ON `redteam_campaign_stages` (`stage_order`);--> statement-breakpoint
CREATE INDEX `rtcs_status_idx` ON `redteam_campaign_stages` (`status`);--> statement-breakpoint
CREATE INDEX `rtc_status_idx` ON `redteam_campaigns` (`status`);--> statement-breakpoint
CREATE INDEX `rtc_created_by_idx` ON `redteam_campaigns` (`created_by`);--> statement-breakpoint
CREATE INDEX `rf_domain_idx` ON `regulatory_frameworks` (`rf_domain`);--> statement-breakpoint
CREATE INDEX `rf_tenant_idx` ON `regulatory_frameworks` (`rf_tenant_id`);--> statement-breakpoint
CREATE INDEX `rf_framework_idx` ON `regulatory_frameworks` (`rf_framework`);--> statement-breakpoint
CREATE INDEX `rt_engagement_idx` ON `remediation_tasks` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `rt_status_idx` ON `remediation_tasks` (`status`);--> statement-breakpoint
CREATE INDEX `rt_severity_idx` ON `remediation_tasks` (`severity`);--> statement-breakpoint
CREATE INDEX `rt_assigned_team_idx` ON `remediation_tasks` (`assigned_team`);--> statement-breakpoint
CREATE INDEX `rt_sla_idx` ON `remediation_tasks` (`sla_deadline`);--> statement-breakpoint
CREATE INDEX `roe_ack_operator_idx` ON `roe_acknowledgments` (`operator_id`);--> statement-breakpoint
CREATE INDEX `roe_ack_target_idx` ON `roe_acknowledgments` (`target_id`);--> statement-breakpoint
CREATE INDEX `roe_ack_time_idx` ON `roe_acknowledgments` (`acknowledged_at`);--> statement-breakpoint
CREATE INDEX `sgs_domain_idx` ON `scan_graduation_scores` (`domain`);--> statement-breakpoint
CREATE INDEX `sgs_sector_idx` ON `scan_graduation_scores` (`sector`);--> statement-breakpoint
CREATE INDEX `sgs_scan_id_idx` ON `scan_graduation_scores` (`scan_id`);--> statement-breakpoint
CREATE INDEX `sgs_created_at_idx` ON `scan_graduation_scores` (`created_at`);--> statement-breakpoint
CREATE INDEX `observationId` ON `scan_observations` (`observationId`);--> statement-breakpoint
CREATE INDEX `profileId` ON `scan_policies` (`profileId`);--> statement-breakpoint
CREATE INDEX `riskId` ON `scan_risk_cards` (`riskId`);--> statement-breakpoint
CREATE INDEX `ss_engagement_idx` ON `scan_schedules` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ss_active_idx` ON `scan_schedules` (`is_active`);--> statement-breakpoint
CREATE INDEX `signalId` ON `scan_signals` (`signalId`);--> statement-breakpoint
CREATE INDEX `ser_engagement_unique` ON `scanforge_engagement_report` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sfl_engagement_idx` ON `scanforge_finding_log` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sfl_template_idx` ON `scanforge_finding_log` (`template_id`);--> statement-breakpoint
CREATE INDEX `sfl_verdict_idx` ON `scanforge_finding_log` (`verdict`);--> statement-breakpoint
CREATE INDEX `sgt_template_id_unique` ON `scanforge_generated_templates` (`template_id`);--> statement-breakpoint
CREATE INDEX `sgt_status_idx` ON `scanforge_generated_templates` (`status`);--> statement-breakpoint
CREATE INDEX `sgt_source_idx` ON `scanforge_generated_templates` (`generation_source`);--> statement-breakpoint
CREATE INDEX `sph_template_idx` ON `scanforge_promotion_history` (`template_id`);--> statement-breakpoint
CREATE INDEX `sph_decision_idx` ON `scanforge_promotion_history` (`decision`);--> statement-breakpoint
CREATE INDEX `sph_trigger_idx` ON `scanforge_promotion_history` (`trigger_engagement_id`);--> statement-breakpoint
CREATE INDEX `srl_feed_idx` ON `scanforge_research_log` (`feed_source`);--> statement-breakpoint
CREATE INDEX `srl_subject_idx` ON `scanforge_research_log` (`research_subject`);--> statement-breakpoint
CREATE INDEX `srl_type_idx` ON `scanforge_research_log` (`research_type`);--> statement-breakpoint
CREATE INDEX `stm_template_unique` ON `scanforge_template_metrics` (`template_id`);--> statement-breakpoint
CREATE INDEX `scs_credential_idx` ON `scheduled_cspm_scans` (`credential_id`);--> statement-breakpoint
CREATE INDEX `scs_engagement_idx` ON `scheduled_cspm_scans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `scs_active_idx` ON `scheduled_cspm_scans` (`is_active`);--> statement-breakpoint
CREATE INDEX `scs_next_run_idx` ON `scheduled_cspm_scans` (`next_run_at`);--> statement-breakpoint
CREATE INDEX `sh_engagement_id_idx` ON `submission_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sh_user_id_idx` ON `submission_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `sh_platform_idx` ON `submission_history` (`platform`);--> statement-breakpoint
CREATE INDEX `sh_status_idx` ON `submission_history` (`status`);--> statement-breakpoint
CREATE INDEX `sh_vuln_class_idx` ON `submission_history` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `sh_severity_idx` ON `submission_history` (`severity`);--> statement-breakpoint
CREATE INDEX `sh_created_at_idx` ON `submission_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `team_invitations_token_hash_unique` ON `team_invitations` (`token_hash`);--> statement-breakpoint
CREATE INDEX `td_engagement_idx` ON `telemetry_diagnostics` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `td_report_type_idx` ON `telemetry_diagnostics` (`report_type`);--> statement-breakpoint
CREATE INDEX `td_health_score_idx` ON `telemetry_diagnostics` (`health_score`);--> statement-breakpoint
CREATE INDEX `td_created_at_idx` ON `telemetry_diagnostics` (`created_at`);--> statement-breakpoint
CREATE INDEX `tlq_telemetry_event_idx` ON `telemetry_llm_quality` (`telemetry_event_id`);--> statement-breakpoint
CREATE INDEX `tlq_engagement_idx` ON `telemetry_llm_quality` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `tlq_prompt_hash_idx` ON `telemetry_llm_quality` (`prompt_hash`);--> statement-breakpoint
CREATE INDEX `tlq_knowledge_gap_idx` ON `telemetry_llm_quality` (`knowledge_gap`);--> statement-breakpoint
CREATE INDEX `tlq_hallucination_idx` ON `telemetry_llm_quality` (`hallucination_detected`);--> statement-breakpoint
CREATE INDEX `tlq_created_at_idx` ON `telemetry_llm_quality` (`created_at`);--> statement-breakpoint
CREATE INDEX `tl_env_type_idx` ON `test_lab_environments` (`tl_env_type`);--> statement-breakpoint
CREATE INDEX `tl_env_status_idx` ON `test_lab_environments` (`tl_env_status`);--> statement-breakpoint
CREATE INDEX `tl_it_env_idx` ON `test_lab_implant_tests` (`tl_it_environment_id`);--> statement-breakpoint
CREATE INDEX `tl_it_agent_idx` ON `test_lab_implant_tests` (`tl_it_agent_id`);--> statement-breakpoint
CREATE INDEX `tl_it_status_idx` ON `test_lab_implant_tests` (`tl_it_status`);--> statement-breakpoint
CREATE INDEX `tl_sr_scenario_idx` ON `test_lab_scenario_runs` (`tl_sr_scenario_id`);--> statement-breakpoint
CREATE INDEX `tl_sr_model_idx` ON `test_lab_scenario_runs` (`tl_sr_specialist_model`);--> statement-breakpoint
CREATE INDEX `tl_sr_status_idx` ON `test_lab_scenario_runs` (`tl_sr_status`);--> statement-breakpoint
CREATE INDEX `tl_tr_model_idx` ON `test_lab_training_runs` (`tl_tr_specialist_model`);--> statement-breakpoint
CREATE INDEX `tl_tr_status_idx` ON `test_lab_training_runs` (`tl_tr_status`);--> statement-breakpoint
CREATE INDEX `test_plans_plan_id_unique` ON `test_plans` (`plan_id`);--> statement-breakpoint
CREATE INDEX `test_plans_engagement_id_idx` ON `test_plans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `test_plans_status_idx` ON `test_plans` (`status`);--> statement-breakpoint
CREATE INDEX `threat_actors_actorId_unique` ON `threat_actors` (`actorId`);--> statement-breakpoint
CREATE INDEX `tbr_run_id_idx` ON `training_benchmark_runs` (`run_id`);--> statement-breakpoint
CREATE INDEX `tbr_lab_id_idx` ON `training_benchmark_runs` (`lab_id`);--> statement-breakpoint
CREATE INDEX `tbr_status_idx` ON `training_benchmark_runs` (`status`);--> statement-breakpoint
CREATE INDEX `idx_gt_target` ON `training_ground_truth` (`target_preset`);--> statement-breakpoint
CREATE INDEX `idx_gt_unique` ON `training_ground_truth` (`target_preset`,`vuln_title`);--> statement-breakpoint
CREATE INDEX `training_lab_sessions_session_id_unique` ON `training_lab_sessions` (`session_id`);--> statement-breakpoint
CREATE INDEX `ttp_knowledge_techniqueId_unique` ON `ttp_knowledge` (`techniqueId`);--> statement-breakpoint
CREATE INDEX `unified_exploit_catalog_catalogId_unique` ON `unified_exploit_catalog` (`catalogId`);--> statement-breakpoint
CREATE INDEX `urd_engagement_idx` ON `uploaded_roe_documents` (`created_engagement_id`);--> statement-breakpoint
CREATE INDEX `urd_roe_doc_idx` ON `uploaded_roe_documents` (`created_roe_document_id`);--> statement-breakpoint
CREATE INDEX `urd_status_idx` ON `uploaded_roe_documents` (`parse_status`);--> statement-breakpoint
CREATE INDEX `upc_user_idx` ON `user_platform_credentials` (`user_id`);--> statement-breakpoint
CREATE INDEX `upc_platform_idx` ON `user_platform_credentials` (`platform`);--> statement-breakpoint
CREATE INDEX `user_sessions_session_hash_unique` ON `user_sessions` (`session_hash`);--> statement-breakpoint
CREATE INDEX `users_openId_unique` ON `users` (`openId`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_integration` ON `vendor_cached_data` (`integrationId`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_type` ON `vendor_cached_data` (`dataType`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_hostname` ON `vendor_cached_data` (`hostname`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_ip` ON `vendor_cached_data` (`ipAddress`);--> statement-breakpoint
CREATE INDEX `idx_vendor_cached_mitre` ON `vendor_cached_data` (`mitreAttackId`);--> statement-breakpoint
CREATE INDEX `vuln_snap_engagement_idx` ON `vuln_scan_snapshots` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `vuln_snap_created_idx` ON `vuln_scan_snapshots` (`created_at`);--> statement-breakpoint
CREATE INDEX `vuln_trend_engagement_idx` ON `vuln_trend_entries` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `vuln_trend_snapshot_idx` ON `vuln_trend_entries` (`snapshot_id`);--> statement-breakpoint
CREATE INDEX `vuln_trend_hostname_idx` ON `vuln_trend_entries` (`hostname`);--> statement-breakpoint
CREATE INDEX `vta_comparison_idx` ON `vuln_type_accuracy` (`comparison_id`);--> statement-breakpoint
CREATE INDEX `vta_vuln_type_idx` ON `vuln_type_accuracy` (`vuln_type`);--> statement-breakpoint
CREATE INDEX `vta_target_idx` ON `vuln_type_accuracy` (`target_preset`);--> statement-breakpoint
CREATE INDEX `web_crawl_jobs_jobId_unique` ON `web_crawl_jobs` (`jobId`);--> statement-breakpoint
CREATE INDEX `webhookId` ON `webhook_endpoints` (`webhookId`);--> statement-breakpoint
CREATE INDEX `wh_endpoint_id_idx` ON `webhook_endpoints` (`endpoint_id`);--> statement-breakpoint
CREATE INDEX `wh_integration_idx` ON `webhook_endpoints` (`integration_id`);--> statement-breakpoint
CREATE INDEX `wh_status_idx` ON `webhook_endpoints` (`status`);--> statement-breakpoint
CREATE INDEX `wh_tenant_idx` ON `webhook_endpoints` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `we_endpoint_idx` ON `webhook_events` (`endpoint_id`);--> statement-breakpoint
CREATE INDEX `we_event_id_idx` ON `webhook_events` (`event_id`);--> statement-breakpoint
CREATE INDEX `we_status_idx` ON `webhook_events` (`status`);--> statement-breakpoint
CREATE INDEX `we_received_idx` ON `webhook_events` (`received_at`);--> statement-breakpoint
CREATE INDEX `zdc_cve_idx` ON `zero_day_cache` (`cve`);--> statement-breakpoint
CREATE INDEX `zdc_vendor_idx` ON `zero_day_cache` (`vendor`);--> statement-breakpoint
CREATE INDEX `zdc_product_idx` ON `zero_day_cache` (`product`);--> statement-breakpoint
CREATE INDEX `zdc_year_idx` ON `zero_day_cache` (`year`);--> statement-breakpoint
CREATE INDEX `zdc_source_idx` ON `zero_day_cache` (`source`);--> statement-breakpoint
CREATE INDEX `zdsm_scan_id_idx` ON `zero_day_scan_matches` (`scan_id`);--> statement-breakpoint
CREATE INDEX `zdsm_engagement_id_idx` ON `zero_day_scan_matches` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `zdsm_domain_idx` ON `zero_day_scan_matches` (`domain`);--> statement-breakpoint
CREATE INDEX `zdsm_cve_idx` ON `zero_day_scan_matches` (`cve`);--> statement-breakpoint
CREATE INDEX `zdsm_severity_idx` ON `zero_day_scan_matches` (`severity`);--> statement-breakpoint
CREATE INDEX `zdsm_created_at_idx` ON `zero_day_scan_matches` (`created_at`);