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
	`tl_env_cost_cents` int DEFAULT 0,
	CONSTRAINT `test_lab_environments_id` PRIMARY KEY(`id`)
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
	`tl_it_completed_at` bigint,
	CONSTRAINT `test_lab_implant_tests_id` PRIMARY KEY(`id`)
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
	`tl_sr_created_at` bigint NOT NULL,
	CONSTRAINT `test_lab_scenario_runs_id` PRIMARY KEY(`id`)
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
	`tl_tr_created_at` bigint NOT NULL,
	CONSTRAINT `test_lab_training_runs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `tl_env_type_idx` ON `test_lab_environments` (`tl_env_type`);--> statement-breakpoint
CREATE INDEX `tl_env_status_idx` ON `test_lab_environments` (`tl_env_status`);--> statement-breakpoint
CREATE INDEX `tl_it_env_idx` ON `test_lab_implant_tests` (`tl_it_environment_id`);--> statement-breakpoint
CREATE INDEX `tl_it_agent_idx` ON `test_lab_implant_tests` (`tl_it_agent_id`);--> statement-breakpoint
CREATE INDEX `tl_it_status_idx` ON `test_lab_implant_tests` (`tl_it_status`);--> statement-breakpoint
CREATE INDEX `tl_sr_scenario_idx` ON `test_lab_scenario_runs` (`tl_sr_scenario_id`);--> statement-breakpoint
CREATE INDEX `tl_sr_model_idx` ON `test_lab_scenario_runs` (`tl_sr_specialist_model`);--> statement-breakpoint
CREATE INDEX `tl_sr_status_idx` ON `test_lab_scenario_runs` (`tl_sr_status`);--> statement-breakpoint
CREATE INDEX `tl_tr_model_idx` ON `test_lab_training_runs` (`tl_tr_specialist_model`);--> statement-breakpoint
CREATE INDEX `tl_tr_status_idx` ON `test_lab_training_runs` (`tl_tr_status`);