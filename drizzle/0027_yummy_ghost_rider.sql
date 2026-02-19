CREATE TABLE `attack_paths` (
	`id` int AUTO_INCREMENT NOT NULL,
	`path_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`engagement_id` varchar(128),
	`nodes` json,
	`edges` json,
	`risk_score` int,
	`status` varchar(32) DEFAULT 'draft',
	`created_by` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `attack_paths_id` PRIMARY KEY(`id`),
	CONSTRAINT `attack_paths_path_id_unique` UNIQUE(`path_id`)
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
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `defense_scores_id` PRIMARY KEY(`id`),
	CONSTRAINT `defense_scores_score_id_unique` UNIQUE(`score_id`)
);
--> statement-breakpoint
CREATE TABLE `detection_tests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`test_id` varchar(64) NOT NULL,
	`technique_id` varchar(32) NOT NULL,
	`technique_name` varchar(255),
	`tactic` varchar(64),
	`ability_id` varchar(128),
	`ability_name` varchar(255),
	`engagement_id` varchar(128),
	`execution_result` varchar(32) DEFAULT 'pending',
	`executed_at` timestamp,
	`detected` boolean DEFAULT false,
	`detection_time` int,
	`detection_source` varchar(255),
	`detection_rule` varchar(255),
	`alert_severity` varchar(32),
	`is_gap` boolean DEFAULT false,
	`gap_severity` varchar(32),
	`mitigation_status` varchar(32) DEFAULT 'open',
	`recommendation` text,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `detection_tests_id` PRIMARY KEY(`id`),
	CONSTRAINT `detection_tests_test_id_unique` UNIQUE(`test_id`)
);
--> statement-breakpoint
CREATE TABLE `emulation_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`playbook_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`threat_actor_id` int,
	`threat_actor_name` varchar(255),
	`phases` json,
	`ability_ids` json,
	`adversary_profile` json,
	`caldera_adversary_id` varchar(128),
	`status` varchar(32) NOT NULL DEFAULT 'draft',
	`difficulty` varchar(32),
	`estimated_duration` int,
	`tags` json,
	`created_by` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `emulation_playbooks_id` PRIMARY KEY(`id`),
	CONSTRAINT `emulation_playbooks_playbook_id_unique` UNIQUE(`playbook_id`)
);
--> statement-breakpoint
CREATE TABLE `evidence_chain_of_custody` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidence_id` varchar(64) NOT NULL,
	`action` varchar(64) NOT NULL,
	`performed_by` varchar(128) NOT NULL,
	`performed_at` timestamp NOT NULL DEFAULT (now()),
	`details` text,
	`ip_address` varchar(64),
	`previous_hash` varchar(128),
	`new_hash` varchar(128),
	CONSTRAINT `evidence_chain_of_custody_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `evidence_items` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidence_id` varchar(64) NOT NULL,
	`title` varchar(255) NOT NULL,
	`type` varchar(64) NOT NULL,
	`category` varchar(64),
	`description` text,
	`engagement_id` varchar(128),
	`operation_id` varchar(128),
	`file_url` text,
	`file_key` varchar(512),
	`file_name` varchar(255),
	`file_size` int,
	`mime_type` varchar(128),
	`hash` varchar(128),
	`classification` varchar(32) DEFAULT 'confidential',
	`tags` json,
	`metadata` json,
	`notes` text,
	`collected_by` varchar(128),
	`collected_at` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `evidence_items_id` PRIMARY KEY(`id`),
	CONSTRAINT `evidence_items_evidence_id_unique` UNIQUE(`evidence_id`)
);
--> statement-breakpoint
CREATE TABLE `playbook_executions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`execution_id` varchar(64) NOT NULL,
	`playbook_id` varchar(64) NOT NULL,
	`operation_id` varchar(128),
	`engagement_id` varchar(128),
	`status` varchar(32) NOT NULL DEFAULT 'pending',
	`started_at` timestamp,
	`completed_at` timestamp,
	`results` json,
	`agent_paw` varchar(128),
	`executed_by` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `playbook_executions_id` PRIMARY KEY(`id`),
	CONSTRAINT `playbook_executions_execution_id_unique` UNIQUE(`execution_id`)
);
--> statement-breakpoint
CREATE TABLE `webhook_deliveries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhook_id` varchar(64) NOT NULL,
	`event` varchar(128) NOT NULL,
	`payload` json,
	`response_status` int,
	`response_body` text,
	`success` boolean DEFAULT false,
	`delivered_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `webhook_deliveries_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `webhook_endpoints` (
	`id` int AUTO_INCREMENT NOT NULL,
	`webhook_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`url` text NOT NULL,
	`secret` varchar(255),
	`events` json,
	`format` varchar(32) DEFAULT 'json',
	`headers` json,
	`enabled` boolean DEFAULT true,
	`fail_count` int DEFAULT 0,
	`last_triggered` timestamp,
	`created_by` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `webhook_endpoints_id` PRIMARY KEY(`id`),
	CONSTRAINT `webhook_endpoints_webhook_id_unique` UNIQUE(`webhook_id`)
);
