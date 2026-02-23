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
	`is_shortest_path` boolean DEFAULT false,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `ad_attack_paths_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `ad_attack_simulations_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `ad_environments_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `ad_objects` (
	`id` int AUTO_INCREMENT NOT NULL,
	`environment_id` int NOT NULL,
	`object_type` enum('user','group','computer','gpo','ou','trust','spn','certificate_template') NOT NULL,
	`distinguished_name` varchar(1024),
	`sam_account_name` varchar(255),
	`display_name` varchar(255),
	`is_privileged` boolean DEFAULT false,
	`is_enabled` boolean DEFAULT true,
	`member_of` json,
	`members` json,
	`properties` json,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `ad_objects_id` PRIMARY KEY(`id`)
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
	`auth_required` boolean DEFAULT false,
	`rate_limited` boolean DEFAULT false,
	`deprecated` boolean DEFAULT false,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `api_endpoints_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `api_fuzzing_runs_id` PRIMARY KEY(`id`)
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
	`is_builtin` boolean DEFAULT true,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `api_security_tests_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `api_targets_id` PRIMARY KEY(`id`)
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
	`api_false_positive` boolean DEFAULT false,
	`executed_at` timestamp,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `api_test_results_id` PRIMARY KEY(`id`)
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
	`ast_created_at` timestamp NOT NULL DEFAULT (now()),
	`ast_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `attack_sequence_templates_id` PRIMARY KEY(`id`),
	CONSTRAINT `attack_sequence_templates_templateId_unique` UNIQUE(`templateId`)
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
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `bug_bounty_correlations_id` PRIMARY KEY(`id`)
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
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bug_bounty_findings_id` PRIMARY KEY(`id`)
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
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bug_bounty_programs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_sync_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`platform` varchar(32) NOT NULL,
	`sync_type` varchar(64) NOT NULL,
	`status` varchar(32) NOT NULL,
	`items_synced` int DEFAULT 0,
	`error_message` text,
	`started_at` timestamp NOT NULL DEFAULT (now()),
	`completed_at` timestamp,
	CONSTRAINT `bug_bounty_sync_logs_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `cloud_attack_paths_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cloud_identities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`provider_id` int NOT NULL,
	`identity_type` enum('user','role','service_account','group','app_registration') NOT NULL,
	`arn` varchar(512),
	`name` varchar(255) NOT NULL,
	`email` varchar(320),
	`is_privileged` boolean DEFAULT false,
	`last_activity` timestamp,
	`permissions` json,
	`policies` json,
	`metadata` json,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `cloud_identities_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `cloud_misconfigurations_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `cloud_providers_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `compliance_controls_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `compliance_frameworks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`framework_name` varchar(128) NOT NULL,
	`framework_version` varchar(32),
	`framework_type` enum('soc2','iso27001','nist_csf','pci_dss','hipaa','cis','custom') NOT NULL,
	`description` text,
	`total_controls` int,
	`control_hierarchy` json,
	`is_active` boolean DEFAULT true,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `compliance_frameworks_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `compliance_mappings_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `compliance_reports_id` PRIMARY KEY(`id`)
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
	`ce_is_verified` boolean DEFAULT false,
	`ce_is_sensitive` boolean DEFAULT false,
	`ce_is_retired` boolean DEFAULT false,
	`ce_is_spam_list` boolean DEFAULT false,
	`ce_source_url` varchar(1024),
	`ce_description` text,
	`ce_tags` json,
	`ce_raw_data` json,
	`ce_created_at` timestamp NOT NULL DEFAULT (now()),
	`ce_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `credential_exposures_id` PRIMARY KEY(`id`)
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
	`der_created_at` timestamp NOT NULL DEFAULT (now()),
	`der_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `darkweb_enriched_records_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `darkweb_feed_registry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`dfr_feed_name` varchar(255) NOT NULL,
	`dfr_feed_url` varchar(1024) NOT NULL,
	`dfr_feed_type` enum('ioc','malware','ransomware','credential','phishing','botnet','c2','blocklist','vulnerability','influence','other') NOT NULL,
	`dfr_provider` varchar(255),
	`dfr_description` text,
	`dfr_requires_auth` boolean DEFAULT false,
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
	`dfr_is_built_in` boolean DEFAULT true,
	`dfr_enabled` boolean DEFAULT true,
	`dfr_config` json,
	`dfr_created_at` timestamp NOT NULL DEFAULT (now()),
	`dfr_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `darkweb_feed_registry_id` PRIMARY KEY(`id`),
	CONSTRAINT `darkweb_feed_registry_dfr_feed_name_unique` UNIQUE(`dfr_feed_name`)
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
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `edr_coverage_matrix_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `edr_products_id` PRIMARY KEY(`id`)
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
	`is_builtin` boolean DEFAULT true,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `edr_test_catalog_id` PRIMARY KEY(`id`)
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
	`false_positive` boolean DEFAULT false,
	`evidence` json,
	`notes` text,
	`executed_at` timestamp,
	`detected_at` timestamp,
	`created_at` timestamp DEFAULT (now()),
	CONSTRAINT `edr_test_results_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`completed_at` timestamp,
	CONSTRAINT `evasion_sessions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `exploit_intelligence` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cveId` varchar(32) NOT NULL,
	`exploitType` varchar(64),
	`targetProduct` varchar(255),
	`targetVersion` varchar(128),
	`weaponized` boolean DEFAULT false,
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
	`cisaKev` boolean DEFAULT false,
	`ei_source` varchar(64),
	`ei_confidence` int,
	`ei_created_at` timestamp NOT NULL DEFAULT (now()),
	`ei_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `exploit_intelligence_id` PRIMARY KEY(`id`)
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
	`transferCreatedAt` timestamp NOT NULL DEFAULT (now()),
	`transferCompletedAt` timestamp,
	CONSTRAINT `file_transfers_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`completed_at` timestamp,
	CONSTRAINT `generated_payloads_id` PRIMARY KEY(`id`)
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
	`iab_created_at` timestamp NOT NULL DEFAULT (now()),
	`iab_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `iab_activity_id` PRIMARY KEY(`id`)
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
	`ir_created_at` timestamp NOT NULL DEFAULT (now()),
	`ir_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `incident_reports_id` PRIMARY KEY(`id`)
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
	`io_created_at` timestamp NOT NULL DEFAULT (now()),
	`io_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `influence_operations_id` PRIMARY KEY(`id`)
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
	`ne_created_at` timestamp NOT NULL DEFAULT (now()),
	`ne_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `network_events_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `offensive_audit_log_id` PRIMARY KEY(`id`)
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
	`peStartedAt` timestamp NOT NULL DEFAULT (now()),
	`peCompletedAt` timestamp,
	`peTriggeredBy` enum('manual','auto') NOT NULL DEFAULT 'manual',
	`peCreatedBy` varchar(64),
	CONSTRAINT `post_exploit_executions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `post_exploit_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`playbookName` varchar(255) NOT NULL,
	`playbookDescription` text,
	`playbookCategory` enum('recon','credential','persistence','lateral','exfil','cleanup','custom') NOT NULL DEFAULT 'custom',
	`targetSessionType` enum('shell','meterpreter','both') NOT NULL DEFAULT 'both',
	`playbookCommands` json NOT NULL,
	`autoTrigger` boolean NOT NULL DEFAULT false,
	`autoTriggerFilter` json,
	`isBuiltIn` boolean NOT NULL DEFAULT false,
	`playbookEnabled` boolean NOT NULL DEFAULT true,
	`playbookCreatedBy` varchar(64),
	`playbookCreatedAt` timestamp NOT NULL DEFAULT (now()),
	`playbookUpdatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `post_exploit_playbooks_id` PRIMARY KEY(`id`)
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
	`ra_created_at` timestamp NOT NULL DEFAULT (now()),
	`ra_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `ransomware_affiliates_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `recording_chunks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`recordingId` int NOT NULL,
	`chunkIndex` int NOT NULL,
	`chunkType` enum('input','output','system') NOT NULL DEFAULT 'output',
	`chunkContent` text NOT NULL,
	`timestampMs` int NOT NULL,
	`chunkCreatedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `recording_chunks_id` PRIMARY KEY(`id`)
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
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `rule_robustness_results_id` PRIMARY KEY(`id`)
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
	`triggerType` varchar(64),
	`previousScore` double,
	`delta` double,
	`changeDescription` text,
	`factorChanges` json,
	`pipelinePhase` varchar(64),
	`computedBy` varchar(255),
	`computedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scoring_audit_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scoring_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`engagementId` int,
	`isDefault` boolean DEFAULT false,
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
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scoring_profiles_id` PRIMARY KEY(`id`)
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
	`recordingStartedAt` timestamp NOT NULL DEFAULT (now()),
	`recordingCompletedAt` timestamp,
	`recordingCreatedBy` varchar(64),
	CONSTRAINT `session_recordings_id` PRIMARY KEY(`id`)
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
	`insecure` boolean DEFAULT false,
	`timeout_ms` int DEFAULT 15000,
	`index_pattern` varchar(512),
	`use_security_detections` boolean DEFAULT false,
	`connected` boolean DEFAULT false,
	`enabled` boolean DEFAULT true,
	`last_tested_at` timestamp,
	`version` varchar(64),
	`cluster_name` varchar(255),
	`alert_count` int,
	`error_message` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `siem_connections_id` PRIMARY KEY(`id`)
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
	`isDefault` boolean NOT NULL DEFAULT false,
	`associatedServerId` int,
	`createdBy` varchar(64),
	`lastUsedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `ssh_keys_id` PRIMARY KEY(`id`)
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
	`uie_enriched` boolean DEFAULT false,
	`uie_enrichment_data` json,
	`uie_tags` json,
	`uie_raw_data` json,
	`uie_event_date` timestamp,
	`uie_ingested_at` timestamp NOT NULL DEFAULT (now()),
	`uie_created_at` timestamp NOT NULL DEFAULT (now()),
	`uie_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `underground_intel_events_id` PRIMARY KEY(`id`)
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
	`exploitable` boolean NOT NULL DEFAULT false,
	`validationRawOutput` text,
	`validationEvidence` json,
	`scoreAdjustment` double DEFAULT 0,
	`previousRiskScore` double,
	`newRiskScore` double,
	`validationDurationMs` int,
	`validationResultError` text,
	`evidenceUrl` text,
	`evidenceArtifacts` json,
	`validationResultCreatedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `validation_results_id` PRIMARY KEY(`id`)
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
	`requireApproval` boolean NOT NULL DEFAULT true,
	`scopeRestrictions` json,
	`validationRunStatus` enum('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
	`totalCandidates` int NOT NULL DEFAULT 0,
	`validatedCount` int NOT NULL DEFAULT 0,
	`notVulnerableCount` int NOT NULL DEFAULT 0,
	`inconclusiveCount` int NOT NULL DEFAULT 0,
	`errorCount` int NOT NULL DEFAULT 0,
	`skippedCount` int NOT NULL DEFAULT 0,
	`avgScoreAdjustment` double DEFAULT 0,
	`validationOperatorId` varchar(255) NOT NULL,
	`validationStartedAt` timestamp NOT NULL DEFAULT (now()),
	`validationCompletedAt` timestamp,
	`totalDurationMs` int,
	`validationRunError` text,
	CONSTRAINT `validation_runs_id` PRIMARY KEY(`id`)
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
	`enabled` boolean NOT NULL DEFAULT true,
	`last_run_at` timestamp,
	`next_run_at` timestamp,
	`last_status` varchar(50),
	`last_error` text,
	`run_count` int NOT NULL DEFAULT 0,
	`config` json,
	`created_by` varchar(255),
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `validation_schedules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `attack_paths` DROP INDEX `attack_paths_path_id_unique`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP INDEX `detection_tests_test_id_unique`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP INDEX `emulation_playbooks_playbook_id_unique`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP INDEX `evidence_items_evidence_id_unique`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP INDEX `playbook_executions_execution_id_unique`;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` DROP INDEX `webhook_endpoints_webhook_id_unique`;--> statement-breakpoint
ALTER TABLE `metasploit_servers` MODIFY COLUMN `rpcSsl` boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE `attack_paths` ADD `pathId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `attack_paths` ADD `engagementId` varchar(128);--> statement-breakpoint
ALTER TABLE `attack_paths` ADD `riskScore` int;--> statement-breakpoint
ALTER TABLE `attack_paths` ADD `createdBy` int;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `testId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `engagementId` varchar(128);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `techniqueId` varchar(32) NOT NULL;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `techniqueName` varchar(255);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `abilityId` varchar(128);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `abilityName` varchar(255);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `executedAt` timestamp;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `executionResult` varchar(32) DEFAULT 'pending';--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `detectionTime` int;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `detectionSource` varchar(255);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `detectionRule` varchar(255);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `alertSeverity` varchar(32);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `isGap` boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `gapSeverity` varchar(32);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `mitigationStatus` varchar(32) DEFAULT 'open';--> statement-breakpoint
ALTER TABLE `detection_tests` ADD `evidence` json;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `missionFunction` varchar(128);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `essentialService` varchar(128);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `assetPurpose` text;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `businessImpactLevel` varchar(32);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `missionDependencies` json;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `llmClassification` json;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `scoringVersion` int DEFAULT 1;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `lastScoredAt` timestamp;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `scoringProfileId` int;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `cvssV4Vector` varchar(512);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `fips199Category` json;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `criticalityTier` int;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `deviceType` varchar(64);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `platformType` varchar(64);--> statement-breakpoint
ALTER TABLE `domain_intel_scans` ADD `confirmedFindings` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `domain_intel_scans` ADD `probableFindings` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `domain_intel_scans` ADD `potentialFindings` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `domain_intel_scans` ADD `discoveryCoverageScore` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `domain_intel_scans` ADD `discoveryCoverageBand` varchar(32);--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `actorId` varchar(128);--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `actorName` varchar(255);--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `estimatedDuration` int;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `targetPlatforms` json;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `tacticsUsed` json;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `techniquesUsed` json;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `totalAbilities` int;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `calderaAdversaryId` varchar(128);--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `calderaDeployedAt` timestamp;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` ADD `createdBy` int;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_status` enum('none','pending','signed','expired') DEFAULT 'none' NOT NULL;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_signed_date` timestamp;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_expiry_date` timestamp;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_document_url` text;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_scope` json;--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_signer_name` varchar(255);--> statement-breakpoint
ALTER TABLE `engagements` ADD `roe_signer_email` varchar(320);--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `evidenceId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `performedBy` varchar(128) NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `performedAt` timestamp DEFAULT (now()) NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `ipAddress` varchar(64);--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `userAgent` varchar(255);--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `integrityHash` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` ADD `previousHash` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `evidenceId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `engagementId` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `operationId` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `fileUrl` text;--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `fileKey` varchar(512);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `fileName` varchar(255);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `fileSize` int;--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `mimeType` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `sha256Hash` varchar(128);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `md5Hash` varchar(64);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `collectedBy` varchar(255);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD `collectedAt` timestamp;--> statement-breakpoint
ALTER TABLE `metasploit_servers` ADD `sshTunnelEnabled` boolean DEFAULT true;--> statement-breakpoint
ALTER TABLE `metasploit_servers` ADD `sshUser` varchar(64) DEFAULT 'root';--> statement-breakpoint
ALTER TABLE `metasploit_servers` ADD `msfSshKeyPath` text;--> statement-breakpoint
ALTER TABLE `metasploit_servers` ADD `msfTunnelStatus` enum('connected','connecting','disconnected','reconnecting','error') DEFAULT 'disconnected';--> statement-breakpoint
ALTER TABLE `metasploit_servers` ADD `tunnelLocalPort` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `playbookId` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `playbookName` varchar(255);--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `calderaOperationId` varchar(128);--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `calderaOperationName` varchar(255);--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `execStatus` varchar(32) DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `targetGroup` varchar(128);--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `targetAgentCount` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `abilitiesTotal` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `abilitiesSucceeded` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `abilitiesFailed` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `abilitiesSkipped` int;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `startedAt` timestamp;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `completedAt` timestamp;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `launchedBy` varchar(128);--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `notes` text;--> statement-breakpoint
ALTER TABLE `playbook_executions` ADD `updatedAt` timestamp DEFAULT (now()) NOT NULL ON UPDATE CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` ADD `webhookId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` ADD `responseStatus` int;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` ADD `responseBody` text;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` ADD `deliveredAt` timestamp DEFAULT (now()) NOT NULL;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` ADD `webhookId` varchar(64) NOT NULL;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` ADD `lastTriggered` timestamp;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` ADD `failCount` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` ADD `createdBy` int;--> statement-breakpoint
ALTER TABLE `attack_paths` ADD CONSTRAINT `attack_paths_pathId_unique` UNIQUE(`pathId`);--> statement-breakpoint
ALTER TABLE `detection_tests` ADD CONSTRAINT `detection_tests_testId_unique` UNIQUE(`testId`);--> statement-breakpoint
ALTER TABLE `evidence_items` ADD CONSTRAINT `evidence_items_evidenceId_unique` UNIQUE(`evidenceId`);--> statement-breakpoint
ALTER TABLE `webhook_endpoints` ADD CONSTRAINT `webhook_endpoints_webhookId_unique` UNIQUE(`webhookId`);--> statement-breakpoint
ALTER TABLE `attack_paths` DROP COLUMN `path_id`;--> statement-breakpoint
ALTER TABLE `attack_paths` DROP COLUMN `engagement_id`;--> statement-breakpoint
ALTER TABLE `attack_paths` DROP COLUMN `risk_score`;--> statement-breakpoint
ALTER TABLE `attack_paths` DROP COLUMN `created_by`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `test_id`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `technique_id`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `technique_name`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `ability_id`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `ability_name`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `engagement_id`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `execution_result`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `executed_at`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `detection_time`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `detection_source`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `detection_rule`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `alert_severity`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `is_gap`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `gap_severity`;--> statement-breakpoint
ALTER TABLE `detection_tests` DROP COLUMN `mitigation_status`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `playbook_id`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `threat_actor_id`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `threat_actor_name`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `ability_ids`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `adversary_profile`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `caldera_adversary_id`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `estimated_duration`;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` DROP COLUMN `created_by`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `evidence_id`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `performed_by`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `performed_at`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `ip_address`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `previous_hash`;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` DROP COLUMN `new_hash`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `evidence_id`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `engagement_id`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `operation_id`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `file_url`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `file_key`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `file_name`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `file_size`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `mime_type`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `hash`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `collected_by`;--> statement-breakpoint
ALTER TABLE `evidence_items` DROP COLUMN `collected_at`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `execution_id`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `playbook_id`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `operation_id`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `engagement_id`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `status`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `started_at`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `completed_at`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `results`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `agent_paw`;--> statement-breakpoint
ALTER TABLE `playbook_executions` DROP COLUMN `executed_by`;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` DROP COLUMN `webhook_id`;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` DROP COLUMN `response_status`;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` DROP COLUMN `response_body`;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` DROP COLUMN `delivered_at`;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` DROP COLUMN `webhook_id`;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` DROP COLUMN `fail_count`;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` DROP COLUMN `last_triggered`;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` DROP COLUMN `created_by`;