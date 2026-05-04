CREATE TABLE `demo_requests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`email` varchar(255) NOT NULL,
	`organization` varchar(255) NOT NULL,
	`job_title` varchar(255),
	`use_case` text NOT NULL,
	`status` enum('new','contacted','scheduled','completed','declined') NOT NULL DEFAULT 'new',
	`notes` text,
	`ip_address` varchar(45),
	`user_agent` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `demo_requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `dr_email_idx` ON `demo_requests` (`email`);--> statement-breakpoint
CREATE INDEX `dr_status_idx` ON `demo_requests` (`status`);--> statement-breakpoint
CREATE INDEX `dr_created_at_idx` ON `demo_requests` (`created_at`);