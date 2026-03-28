CREATE TABLE `bug_bounty_program_scopes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`program_id` int,
	`platform` varchar(32) NOT NULL,
	`program_handle` varchar(255) NOT NULL,
	`external_id` varchar(128),
	`asset_type` varchar(64) NOT NULL,
	`asset_identifier` varchar(1024) NOT NULL,
	`eligible_for_bounty` tinyint DEFAULT 0,
	`eligible_for_submission` tinyint DEFAULT 1,
	`max_severity` varchar(32),
	`confidentiality_requirement` varchar(32),
	`integrity_requirement` varchar(32),
	`availability_requirement` varchar(32),
	`instruction` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bug_bounty_program_scopes_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `bug_bounty_program_weaknesses` (
	`id` int AUTO_INCREMENT NOT NULL,
	`program_id` int,
	`platform` varchar(32) NOT NULL,
	`program_handle` varchar(255) NOT NULL,
	`external_id` varchar(128),
	`cwe_id` varchar(32),
	`name` varchar(512) NOT NULL,
	`description` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `bug_bounty_program_weaknesses_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `bbps_program_idx` ON `bug_bounty_program_scopes` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bbps_asset_type_idx` ON `bug_bounty_program_scopes` (`asset_type`);--> statement-breakpoint
CREATE INDEX `bbpw_program_idx` ON `bug_bounty_program_weaknesses` (`program_handle`);--> statement-breakpoint
CREATE INDEX `bbpw_cwe_idx` ON `bug_bounty_program_weaknesses` (`cwe_id`);