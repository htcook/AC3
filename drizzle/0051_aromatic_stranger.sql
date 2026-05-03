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
ALTER TABLE `submission_history` ADD CONSTRAINT `submission_history_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `sh_engagement_id_idx` ON `submission_history` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `sh_user_id_idx` ON `submission_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `sh_platform_idx` ON `submission_history` (`platform`);--> statement-breakpoint
CREATE INDEX `sh_status_idx` ON `submission_history` (`status`);--> statement-breakpoint
CREATE INDEX `sh_vuln_class_idx` ON `submission_history` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `sh_severity_idx` ON `submission_history` (`severity`);--> statement-breakpoint
CREATE INDEX `sh_created_at_idx` ON `submission_history` (`created_at`);