CREATE TABLE `roe_acknowledgments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`operator_id` int NOT NULL,
	`operator_name` varchar(255) NOT NULL,
	`target_id` varchar(128) NOT NULL,
	`target_name` varchar(255) NOT NULL,
	`target_url` varchar(512) NOT NULL,
	`rules_accepted` json NOT NULL,
	`enforced_rules` json NOT NULL,
	`scan_profile` varchar(32) NOT NULL,
	`session_id` varchar(128),
	`ip_address` varchar(64),
	`acknowledged_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `roe_acknowledgments_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `roe_ack_operator_idx` ON `roe_acknowledgments` (`operator_id`);--> statement-breakpoint
CREATE INDEX `roe_ack_target_idx` ON `roe_acknowledgments` (`target_id`);--> statement-breakpoint
CREATE INDEX `roe_ack_time_idx` ON `roe_acknowledgments` (`acknowledged_at`);