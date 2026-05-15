CREATE TABLE `threat_alert_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`threshold_id` int NOT NULL,
	`scan_id` int,
	`actor_id` varchar(128) NOT NULL,
	`actor_name` varchar(255),
	`relevance_score` int NOT NULL,
	`threat_level` varchar(32),
	`trigger_reason` varchar(255) NOT NULL,
	`notification_sent` tinyint NOT NULL DEFAULT 0,
	`notification_error` text,
	`created_at` bigint NOT NULL,
	CONSTRAINT `threat_alert_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `threat_alert_thresholds` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int,
	`label` varchar(255) NOT NULL DEFAULT 'Default Alert',
	`relevance_threshold` int NOT NULL DEFAULT 80,
	`threat_level_filter` enum('any','critical','high','medium') DEFAULT 'any',
	`enabled` tinyint NOT NULL DEFAULT 1,
	`notify_on_new` tinyint NOT NULL DEFAULT 1,
	`notify_on_rising` tinyint NOT NULL DEFAULT 1,
	`created_by` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_alert_thresholds_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `tah_threshold_idx` ON `threat_alert_history` (`threshold_id`);--> statement-breakpoint
CREATE INDEX `tah_actor_idx` ON `threat_alert_history` (`actor_id`);--> statement-breakpoint
CREATE INDEX `tah_scan_idx` ON `threat_alert_history` (`scan_id`);--> statement-breakpoint
CREATE INDEX `tah_created_idx` ON `threat_alert_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `tat_scan_idx` ON `threat_alert_thresholds` (`scan_id`);--> statement-breakpoint
CREATE INDEX `tat_enabled_idx` ON `threat_alert_thresholds` (`enabled`);