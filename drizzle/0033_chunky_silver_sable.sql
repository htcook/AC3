CREATE TABLE `jarm_community_signatures` (
	`id` int AUTO_INCREMENT NOT NULL,
	`signature_id` varchar(128) NOT NULL,
	`jarm_hash` varchar(128) NOT NULL,
	`provider` varchar(128) NOT NULL,
	`match_type` varchar(32) NOT NULL,
	`confidence` float NOT NULL DEFAULT 0.7,
	`description` text,
	`feed_source` varchar(128) NOT NULL,
	`feed_url` text,
	`is_prefix` tinyint NOT NULL DEFAULT 0,
	`tags` json,
	`last_seen_at` bigint,
	`first_seen_at` bigint,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `jarm_feed_sources` (
	`id` int AUTO_INCREMENT NOT NULL,
	`feed_id` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`feed_type` varchar(32) NOT NULL,
	`url` text NOT NULL,
	`description` text,
	`enabled` tinyint NOT NULL DEFAULT 1,
	`auto_refresh` tinyint NOT NULL DEFAULT 1,
	`refresh_interval_hours` int NOT NULL DEFAULT 24,
	`last_refresh_at` bigint,
	`last_refresh_status` varchar(32),
	`last_refresh_error` text,
	`total_signatures` int NOT NULL DEFAULT 0,
	`last_signature_count` int DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `jarm_scan_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`host` varchar(255) NOT NULL,
	`port` int NOT NULL DEFAULT 443,
	`jarm_hash` varchar(128) NOT NULL,
	`matched_provider` varchar(128),
	`match_type` varchar(32),
	`match_confidence` float,
	`source` varchar(64) NOT NULL,
	`cert_issuer` varchar(255),
	`cert_subject` varchar(255),
	`protocol` varchar(32),
	`previous_hash` varchar(128),
	`change_detected` tinyint NOT NULL DEFAULT 0,
	`change_type` varchar(64),
	`change_severity` varchar(16),
	`scanned_at` bigint NOT NULL,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `jcs_signature_id_unique` ON `jarm_community_signatures` (`signature_id`);--> statement-breakpoint
CREATE INDEX `jcs_jarm_hash_idx` ON `jarm_community_signatures` (`jarm_hash`);--> statement-breakpoint
CREATE INDEX `jcs_provider_idx` ON `jarm_community_signatures` (`provider`);--> statement-breakpoint
CREATE INDEX `jcs_match_type_idx` ON `jarm_community_signatures` (`match_type`);--> statement-breakpoint
CREATE INDEX `jcs_feed_source_idx` ON `jarm_community_signatures` (`feed_source`);--> statement-breakpoint
CREATE INDEX `jcs_enabled_idx` ON `jarm_community_signatures` (`enabled`);--> statement-breakpoint
CREATE INDEX `jfs_feed_id_unique` ON `jarm_feed_sources` (`feed_id`);--> statement-breakpoint
CREATE INDEX `jfs_enabled_idx` ON `jarm_feed_sources` (`enabled`);--> statement-breakpoint
CREATE INDEX `jsh_scan_id_idx` ON `jarm_scan_history` (`scan_id`);--> statement-breakpoint
CREATE INDEX `jsh_domain_idx` ON `jarm_scan_history` (`domain`);--> statement-breakpoint
CREATE INDEX `jsh_host_port_idx` ON `jarm_scan_history` (`host`,`port`);--> statement-breakpoint
CREATE INDEX `jsh_jarm_hash_idx` ON `jarm_scan_history` (`jarm_hash`);--> statement-breakpoint
CREATE INDEX `jsh_change_detected_idx` ON `jarm_scan_history` (`change_detected`);--> statement-breakpoint
CREATE INDEX `jsh_scanned_at_idx` ON `jarm_scan_history` (`scanned_at`);