CREATE TABLE `engagement_approved_targets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`target` varchar(512) NOT NULL,
	`hostname` varchar(255) NOT NULL,
	`status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
	`approved_by` int,
	`approved_by_name` varchar(255),
	`justification` text,
	`roe_reference` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_approved_targets_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `eat_engagement_idx` ON `engagement_approved_targets` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `eat_hostname_idx` ON `engagement_approved_targets` (`engagement_id`,`hostname`);