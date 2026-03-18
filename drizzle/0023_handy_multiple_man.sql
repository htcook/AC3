CREATE TABLE `scan_schedules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`engagement_id` int,
	`ss_scanner_type` enum('nessus','qualys','rapid7','openvas','burp','zap') NOT NULL,
	`connection_config` json NOT NULL,
	`cron_expression` varchar(100) NOT NULL,
	`is_active` boolean NOT NULL DEFAULT true,
	`last_run_at` timestamp,
	`last_run_status` enum('success','failed','running','never') NOT NULL DEFAULT 'never',
	`last_run_stats` json,
	`total_runs` int NOT NULL DEFAULT 0,
	`total_findings` int NOT NULL DEFAULT 0,
	`ss_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`ss_updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `scan_schedules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `ss_engagement_idx` ON `scan_schedules` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ss_active_idx` ON `scan_schedules` (`is_active`);