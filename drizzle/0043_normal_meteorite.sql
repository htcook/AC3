CREATE TABLE `user_platform_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`user_id` int NOT NULL,
	`platform` enum('hackerone','bugcrowd','intigriti','synack','yeswehack','custom') NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`api_username` varchar(512),
	`api_key_encrypted` text NOT NULL,
	`base_url` varchar(512),
	`is_active` tinyint NOT NULL DEFAULT 1,
	`last_verified_at` timestamp,
	`last_sync_at` timestamp,
	`sync_status` enum('idle','syncing','success','failed') DEFAULT 'idle',
	`error_message` text,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `user_platform_credentials_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `upc_user_idx` ON `user_platform_credentials` (`user_id`);--> statement-breakpoint
CREATE INDEX `upc_platform_idx` ON `user_platform_credentials` (`platform`);