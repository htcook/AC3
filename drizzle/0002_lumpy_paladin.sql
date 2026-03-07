ALTER TABLE `ability_graph_edges` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ability_graph_nodes` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ability_graphs` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `access_broker_listings` MODIFY COLUMN `iabCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `active_sessions` MODIFY COLUMN `last_activity_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `active_sessions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `activity_logs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_attack_paths` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_attack_simulations` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_domain_connections` MODIFY COLUMN `conn_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_domain_connections` MODIFY COLUMN `conn_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_enumeration_runs` MODIFY COLUMN `ad_enum_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_environments` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_environments` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ad_objects` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `agentless_bas_tests` MODIFY COLUMN `abt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ai_attack_plans` MODIFY COLUMN `aap_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_endpoints` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_fuzzing_runs` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_security_tests` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_targets` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_targets` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `api_test_results` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `apt_ics_mappings` MODIFY COLUMN `aim_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `apt_ics_mappings` MODIFY COLUMN `aim_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `archetype_actor_mappings` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `atomic_test_executions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `atomic_tests` MODIFY COLUMN `last_synced_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `atomic_tests` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `attack_chain_records` MODIFY COLUMN `acr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `attack_path_graph_edges` MODIFY COLUMN `apge_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `attack_path_graph_nodes` MODIFY COLUMN `apgn_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `attack_paths` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `attack_sequence_templates` MODIFY COLUMN `ast_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `bug_bounty_correlations` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `bug_bounty_findings` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `bug_bounty_programs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `bug_bounty_sync_logs` MODIFY COLUMN `started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `caldera_accounts` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `caldera_accounts` MODIFY COLUMN `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `caldera_stats` MODIFY COLUMN `lastUpdated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `campaign_abilities` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `campaign_agents` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `campaign_archetypes` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `campaign_engagements` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `campaigns` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `carver_risk_cards` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `chain_runs` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `chain_stage_results` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `chat_messages` MODIFY COLUMN `chat_msg_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `chat_sessions` MODIFY COLUMN `chat_session_last_message_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `chat_sessions` MODIFY COLUMN `chat_session_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cicd_pipelines` MODIFY COLUMN `cicd_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cicd_runs` MODIFY COLUMN `cicd_run_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_attack_paths` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_attack_paths` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_credentials` MODIFY COLUMN `cred_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_credentials` MODIFY COLUMN `cred_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_enumeration_runs` MODIFY COLUMN `enum_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_identities` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_misconfigurations` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_providers` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `cloud_providers` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `compliance_controls` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `compliance_frameworks` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `compliance_mappings` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `compliance_mappings` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `compliance_reports` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `config_baseline_rules` MODIFY COLUMN `cbr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `config_baselines` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `config_drift_alerts` MODIFY COLUMN `cda_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `config_scan_results` MODIFY COLUMN `scanned_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `container_image_scans` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `container_registries` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `corroboration_results` MODIFY COLUMN `cr_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_alert_history` MODIFY COLUMN `alert_hist_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_alert_rules` MODIFY COLUMN `alert_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_attack_runs` MODIFY COLUMN `started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_attack_runs` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_exposures` MODIFY COLUMN `ce_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_findings` MODIFY COLUMN `discovered_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_findings` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_rotation_audit` MODIFY COLUMN `rotation_audit_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_rotation_policies` MODIFY COLUMN `rotation_policy_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `credential_rotation_policies` MODIFY COLUMN `rotation_policy_updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `darkweb_enriched_records` MODIFY COLUMN `der_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `darkweb_feed_registry` MODIFY COLUMN `dfr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `defense_scores` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `detection_feedback_results` MODIFY COLUMN `dfr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `detection_tests` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `discovered_assets` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `discovered_attack_paths` MODIFY COLUMN `dap_discovered_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `domain_intel_scans` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `domain_recon` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `edr_coverage_matrix` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `edr_products` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `edr_products` MODIFY COLUMN `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `edr_test_catalog` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `edr_test_results` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `email_security_tests` MODIFY COLUMN `est_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `emulation_playbooks` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_ops_snapshots` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_pipelines` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_reports` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_shares` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_timeline_events` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagement_workflow_states` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `engagements` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `evasion_sessions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `evidence_chain_of_custody` MODIFY COLUMN `performedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `evidence_items` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_feedback_records` MODIFY COLUMN `efr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_ingestion_jobs` MODIFY COLUMN `eij_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_intelligence` MODIFY COLUMN `ei_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_jobs` MODIFY COLUMN `exploitJobCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_plan_history` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_preflight_history` MODIFY COLUMN `eph_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploit_scripts` MODIFY COLUMN `es_ingested_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `exploitation_attempts` MODIFY COLUMN `ea_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `false_positive_findings` MODIFY COLUMN `markedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `false_positive_findings` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `file_transfers` MODIFY COLUMN `transferCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `forest_domains` MODIFY COLUMN `forest_domain_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `forest_trusts` MODIFY COLUMN `trust_discovered_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `forest_trusts` MODIFY COLUMN `forest_trust_created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `generated_detection_rules` MODIFY COLUMN `gdr_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `generated_payloads` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `hunt_hypotheses` MODIFY COLUMN `hyp_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `hunt_sessions` MODIFY COLUMN `hunt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `iab_activity` MODIFY COLUMN `iab_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ics_assessments` MODIFY COLUMN `ica_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ics_devices` MODIFY COLUMN `icd_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ics_devices` MODIFY COLUMN `icd_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ics_exploits` MODIFY COLUMN `ice_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `incident_reports` MODIFY COLUMN `ir_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `influence_operations` MODIFY COLUMN `io_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `info_ops_campaigns` MODIFY COLUMN `ioCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ioc_feeds` MODIFY COLUMN `fetchedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ioc_feeds` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ioc_sync_logs` MODIFY COLUMN `startedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ioc_sync_logs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `job_queue_entries` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_control_mappings` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_definitions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_evidence` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_evidence_chains` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_validation_runs` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ksi_validation_schedules` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `lateral_movement_paths` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `llm_telemetry` MODIFY COLUMN `called_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `llm_telemetry` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `lolbin_catalog` MODIFY COLUMN `lolbin_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `metasploit_servers` MODIFY COLUMN `msfCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `network_events` MODIFY COLUMN `ne_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ngfw_validation_tests` MODIFY COLUMN `nvt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `nuclei_findings` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `nuclei_scans` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `obtained_shells` MODIFY COLUMN `os_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `oem_default_credentials` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `offensive_audit_log` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `opsec_events` MODIFY COLUMN `opsec_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `opsec_scores` MODIFY COLUMN `opsec_score_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `oscal_exports` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `osint_findings` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `osint_monitor_changes` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `osint_monitors` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ot_networks` MODIFY COLUMN `otn_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `pentest_reports` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `phishing_drafts` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `pivot_hosts` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `platform_errors` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `playbook_executions` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `post_exploit_executions` MODIFY COLUMN `peStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `post_exploit_playbooks` MODIFY COLUMN `playbookCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `privesc_findings` MODIFY COLUMN `pe_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `protocol_findings` MODIFY COLUMN `pf_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ransomware_affiliates` MODIFY COLUMN `ra_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ransomware_events` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ransomware_groups` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `recording_chunks` MODIFY COLUMN `chunkCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `remediation_verifications` MODIFY COLUMN `rv_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `report_templates` MODIFY COLUMN `rt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `review_queue_items` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `risk_trend_snapshots` MODIFY COLUMN `rts_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `roe_documents` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `roe_personnel` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `roe_signatures` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `roe_versions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `rule_robustness_results` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `saml_auth_events` MODIFY COLUMN `saml_event_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `saml_idp_configs` MODIFY COLUMN `saml_idp_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `scan_results` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `scoring_audit_log` MODIFY COLUMN `computedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `scoring_profiles` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `scoring_profiles` MODIFY COLUMN `updatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `server_configs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `server_credentials` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `session_recordings` MODIFY COLUMN `recordingStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `siem_connections` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `siem_integrations` MODIFY COLUMN `siem_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `sliver_implants` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `sliver_sessions` MODIFY COLUMN `first_seen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `sliver_tasks` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `soar_connectors` MODIFY COLUMN `soar_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `soar_events` MODIFY COLUMN `soar_evt_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ssh_keys` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `team_invitations` MODIFY COLUMN `invite_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `tenant_memberships` MODIFY COLUMN `tm_joined_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `tenants` MODIFY COLUMN `tenant_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_actor_abilities` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_actor_iocs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_actors` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_group_events` MODIFY COLUMN `discoveredAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_group_events` MODIFY COLUMN `tgeCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `threat_intel_updates` MODIFY COLUMN `tiuStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `training_lab_feedback` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `training_lab_sessions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `ttp_knowledge` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `typosquat_domains` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `underground_intel_events` MODIFY COLUMN `uie_ingested_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `underground_intel_events` MODIFY COLUMN `uie_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `unified_exploit_catalog` MODIFY COLUMN `catalogCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `user_sessions` MODIFY COLUMN `session_last_activity_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `user_sessions` MODIFY COLUMN `session_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `users` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `users` MODIFY COLUMN `lastSignedIn` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `validation_results` MODIFY COLUMN `validationResultCreatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `validation_runs` MODIFY COLUMN `validationStartedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `validation_schedules` MODIFY COLUMN `created_at` timestamp DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `vendor_cached_data` MODIFY COLUMN `cachedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `vendor_integrations` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `vendor_sync_events` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `vuln_scan_findings` MODIFY COLUMN `vsf_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `vuln_scan_imports` MODIFY COLUMN `vsi_imported_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `web_app_findings` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `web_app_scans` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `web_crawl_jobs` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `web_crawl_results` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `webhook_deliveries` MODIFY COLUMN `deliveredAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `webhook_endpoints` MODIFY COLUMN `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `zap_proxy_sessions` MODIFY COLUMN `started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `zap_proxy_sessions` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;