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
	`completed_at` bigint,
	CONSTRAINT `workflow_sessions_id` PRIMARY KEY(`id`)
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
	`completed_at` bigint,
	CONSTRAINT `workflow_step_history_id` PRIMARY KEY(`id`)
);
