CREATE TABLE `entity_profile_overrides` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`org_name` varchar(255),
	`industry` varchar(128),
	`sub_sector` varchar(128),
	`company_size` enum('startup','small','medium','large','enterprise','unknown'),
	`estimated_revenue` bigint,
	`estimated_employees` int,
	`headquarters` varchar(255),
	`founded_year` int,
	`is_public_company` tinyint,
	`stock_ticker` varchar(16),
	`key_products` json,
	`override_reason` text,
	`overridden_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `entity_profile_overrides_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `entity_profile_overrides` ADD CONSTRAINT `entity_profile_overrides_scan_id_domain_intel_scans_id_fk` FOREIGN KEY (`scan_id`) REFERENCES `domain_intel_scans`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entity_profile_overrides` ADD CONSTRAINT `entity_profile_overrides_overridden_by_users_id_fk` FOREIGN KEY (`overridden_by`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `epo_scan_id_idx` ON `entity_profile_overrides` (`scan_id`);--> statement-breakpoint
CREATE INDEX `epo_domain_idx` ON `entity_profile_overrides` (`domain`);