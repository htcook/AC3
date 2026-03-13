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
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bug_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `br_user_idx` ON `bug_reports` (`user_id`);--> statement-breakpoint
CREATE INDEX `br_status_idx` ON `bug_reports` (`status`);--> statement-breakpoint
CREATE INDEX `br_severity_idx` ON `bug_reports` (`severity`);--> statement-breakpoint
CREATE INDEX `br_created_idx` ON `bug_reports` (`created_at`);