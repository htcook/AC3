CREATE TABLE `oem_default_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vendor` varchar(128) NOT NULL,
	`product` varchar(256) NOT NULL,
	`version` varchar(128),
	`protocol` varchar(64) NOT NULL,
	`port` int,
	`username` varchar(256) NOT NULL,
	`password` varchar(512) NOT NULL,
	`access_level` varchar(64),
	`notes` text,
	`cve_reference` varchar(64),
	`source` varchar(256),
	`tags` json,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `oem_default_credentials_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `platform_errors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`source` varchar(32) NOT NULL,
	`severity` varchar(16) NOT NULL DEFAULT 'error',
	`message` text NOT NULL,
	`stack` mediumtext,
	`page` varchar(512),
	`endpoint` varchar(256),
	`status_code` int,
	`user_id` int,
	`engagement_context` json,
	`client_meta` json,
	`resolved` boolean NOT NULL DEFAULT false,
	`resolved_note` text,
	`resolved_at` timestamp,
	`retry_count` int DEFAULT 0,
	`auto_recovered` boolean DEFAULT false,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `platform_errors_id` PRIMARY KEY(`id`)
);
