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
	`ad_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ad_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `agent_definitions_id` PRIMARY KEY(`id`)
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
	`npe_started_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`npe_completed_at` timestamp,
	CONSTRAINT `nexus_pipeline_executions_id` PRIMARY KEY(`id`)
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
	`nqg_evaluated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `nexus_quality_gates_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `ad_agent_id_idx` ON `agent_definitions` (`ad_agent_id`);--> statement-breakpoint
CREATE INDEX `ad_category_idx` ON `agent_definitions` (`ad_category`);--> statement-breakpoint
CREATE INDEX `ad_status_idx` ON `agent_definitions` (`ad_status`);--> statement-breakpoint
CREATE INDEX `npe_execution_id_idx` ON `nexus_pipeline_executions` (`npe_execution_id`);--> statement-breakpoint
CREATE INDEX `npe_caller_name_idx` ON `nexus_pipeline_executions` (`npe_caller_name`);--> statement-breakpoint
CREATE INDEX `npe_status_idx` ON `nexus_pipeline_executions` (`npe_status`);--> statement-breakpoint
CREATE INDEX `npe_tier_idx` ON `nexus_pipeline_executions` (`npe_graduation_tier`);--> statement-breakpoint
CREATE INDEX `nqg_execution_id_idx` ON `nexus_quality_gates` (`nqg_execution_id`);--> statement-breakpoint
CREATE INDEX `nqg_gate_type_idx` ON `nexus_quality_gates` (`nqg_gate_type`);