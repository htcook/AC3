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
ALTER TABLE `deployment_history` ADD CONSTRAINT `deployment_history_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `ir_runbook_entries` ADD CONSTRAINT `ir_runbook_entries_created_by_users_id_fk` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `dh_deployment_id_idx` ON `deployment_history` (`deployment_id`);--> statement-breakpoint
CREATE INDEX `dh_user_id_idx` ON `deployment_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `dh_environment_idx` ON `deployment_history` (`environment`);--> statement-breakpoint
CREATE INDEX `dh_status_idx` ON `deployment_history` (`status`);--> statement-breakpoint
CREATE INDEX `dh_created_at_idx` ON `deployment_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `irr_entry_id_idx` ON `ir_runbook_entries` (`entry_id`);--> statement-breakpoint
CREATE INDEX `irr_alarm_name_idx` ON `ir_runbook_entries` (`alarm_name`);--> statement-breakpoint
CREATE INDEX `irr_severity_idx` ON `ir_runbook_entries` (`severity`);--> statement-breakpoint
CREATE INDEX `irr_category_idx` ON `ir_runbook_entries` (`category`);--> statement-breakpoint
CREATE INDEX `irr_is_active_idx` ON `ir_runbook_entries` (`is_active`);