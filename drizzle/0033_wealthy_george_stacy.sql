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
	`abt_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `agentless_bas_tests_id` PRIMARY KEY(`id`)
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
	`aap_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ai_attack_plans_id` PRIMARY KEY(`id`)
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
	`apge_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `attack_path_graph_edges_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `attack_path_graph_nodes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`apgn_tenant_id` int,
	`apgn_type` enum('user','computer','group','service','cloud_identity','vulnerability','crown_jewel') NOT NULL,
	`apgn_name` varchar(512) NOT NULL,
	`apgn_properties` json,
	`apgn_risk_score` double,
	`apgn_is_crown_jewel` boolean DEFAULT false,
	`apgn_source` varchar(64),
	`apgn_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `attack_path_graph_nodes_id` PRIMARY KEY(`id`)
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
	`cicd_is_active` boolean NOT NULL DEFAULT true,
	`cicd_last_triggered` timestamp,
	`cicd_created_by` varchar(255),
	`cicd_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `cicd_pipelines_id` PRIMARY KEY(`id`)
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
	`cicd_run_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `cicd_runs_id` PRIMARY KEY(`id`)
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
	`dfr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `detection_feedback_results_id` PRIMARY KEY(`id`)
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
	`dap_discovered_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `discovered_attack_paths_id` PRIMARY KEY(`id`)
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
	`est_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `email_security_tests_id` PRIMARY KEY(`id`)
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
	`nvt_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ngfw_validation_tests_id` PRIMARY KEY(`id`)
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
	`rv_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `remediation_verifications_id` PRIMARY KEY(`id`)
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
	`rt_is_default` boolean DEFAULT false,
	`rt_created_by` varchar(255),
	`rt_created_at` timestamp NOT NULL DEFAULT (now()),
	`rt_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `report_templates_id` PRIMARY KEY(`id`)
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
	`rts_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `risk_trend_snapshots_id` PRIMARY KEY(`id`)
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
	`siem_is_active` boolean NOT NULL DEFAULT true,
	`siem_last_tested` timestamp,
	`siem_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `siem_integrations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `soar_connectors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`soar_tenant_id` int,
	`soar_name` varchar(255) NOT NULL,
	`soar_platform` enum('splunk_soar','cortex_xsoar','swimlane','tines','custom') NOT NULL,
	`soar_webhook_url` varchar(512) NOT NULL,
	`soar_api_key_enc` text,
	`soar_inbound` boolean NOT NULL DEFAULT true,
	`soar_outbound` boolean NOT NULL DEFAULT true,
	`soar_event_types` json,
	`soar_is_active` boolean NOT NULL DEFAULT true,
	`soar_last_sync` timestamp,
	`soar_created_by` varchar(255),
	`soar_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `soar_connectors_id` PRIMARY KEY(`id`)
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
	`soar_evt_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `soar_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `tenant_memberships` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tm_tenant_id` int NOT NULL,
	`tm_user_id` int NOT NULL,
	`tm_role` enum('owner','admin','operator','viewer') NOT NULL DEFAULT 'viewer',
	`tm_joined_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `tenant_memberships_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tenant_name` varchar(255) NOT NULL,
	`tenant_slug` varchar(128) NOT NULL,
	`tenant_logo_url` varchar(512),
	`tenant_primary_color` varchar(16),
	`tenant_is_active` boolean NOT NULL DEFAULT true,
	`tenant_max_users` int NOT NULL DEFAULT 50,
	`tenant_plan` enum('free','pro','enterprise') NOT NULL DEFAULT 'free',
	`tenant_created_at` timestamp NOT NULL DEFAULT (now()),
	`tenant_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `tenants_id` PRIMARY KEY(`id`)
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
	`vsf_exploit_available` boolean DEFAULT false,
	`vsf_attack_path_linked` boolean DEFAULT false,
	`vsf_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vuln_scan_findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vuln_scan_imports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vsi_tenant_id` int,
	`vsi_scanner_type` enum('nessus','qualys','rapid7','openvas','custom') NOT NULL,
	`vsi_file_name` varchar(512) NOT NULL,
	`vsi_imported_at` timestamp NOT NULL DEFAULT (now()),
	`vsi_total_hosts` int NOT NULL DEFAULT 0,
	`vsi_total_vulns` int NOT NULL DEFAULT 0,
	`vsi_critical` int NOT NULL DEFAULT 0,
	`vsi_high` int NOT NULL DEFAULT 0,
	`vsi_medium` int NOT NULL DEFAULT 0,
	`vsi_low` int NOT NULL DEFAULT 0,
	`vsi_imported_by` varchar(255),
	CONSTRAINT `vuln_scan_imports_id` PRIMARY KEY(`id`)
);
