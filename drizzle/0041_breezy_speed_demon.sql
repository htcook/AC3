CREATE TABLE `parsed_policy_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cache_key` varchar(255) NOT NULL,
	`platform` varchar(32) NOT NULL,
	`program_slug` varchar(255) NOT NULL,
	`program_url` varchar(1024) NOT NULL,
	`parsed_result` json NOT NULL,
	`expires_at` timestamp NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `ppc_cache_key_idx` ON `parsed_policy_cache` (`cache_key`);--> statement-breakpoint
CREATE INDEX `ppc_platform_slug_idx` ON `parsed_policy_cache` (`platform`,`program_slug`);