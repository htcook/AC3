CREATE TABLE `test_plans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`plan_id` varchar(64) NOT NULL,
	`engagement_id` int NOT NULL,
	`plan_type` enum('pentest','red_team') NOT NULL DEFAULT 'pentest',
	`title` varchar(512) NOT NULL,
	`content` longtext NOT NULL,
	`structured_data` json,
	`version` int NOT NULL DEFAULT 1,
	`status` enum('draft','pending_review','approved','rejected','revision_requested') NOT NULL DEFAULT 'draft',
	`generated_by` int,
	`reviewed_by` int,
	`reviewer_name` varchar(255),
	`reviewer_email` varchar(320),
	`review_comments` text,
	`rejection_reason` text,
	`revision_notes` text,
	`submitted_at` timestamp,
	`reviewed_at` timestamp,
	`approved_at` timestamp,
	`signature_hash` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `test_plans_plan_id_unique` ON `test_plans` (`plan_id`);--> statement-breakpoint
CREATE INDEX `test_plans_engagement_id_idx` ON `test_plans` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `test_plans_status_idx` ON `test_plans` (`status`);