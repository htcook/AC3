ALTER TABLE `discovered_assets` ADD `excluded` boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `exclusionReason` varchar(512);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `excludedAt` timestamp;