CREATE TABLE `fingerprint_cache` (
	`fc_id` int AUTO_INCREMENT NOT NULL,
	`fc_host` varchar(255) NOT NULL,
	`fc_port` int NOT NULL,
	`fc_protocol` varchar(64),
	`fc_product` varchar(255),
	`fc_version` varchar(128),
	`fc_banner` text,
	`fc_os` varchar(255),
	`fc_security_flags` json,
	`fc_risk_indicators` json,
	`fc_potential_cves` json,
	`fc_error` tinyint DEFAULT 0,
	`fc_confidence` int DEFAULT 0,
	`fc_fingerprinted_at` bigint NOT NULL,
	`fc_expires_at` bigint NOT NULL,
	`fc_engagement_id` varchar(64),
	`fc_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	CONSTRAINT `fingerprint_cache_fc_id` PRIMARY KEY(`fc_id`)
);
--> statement-breakpoint
CREATE INDEX `fc_host_port_idx` ON `fingerprint_cache` (`fc_host`,`fc_port`);--> statement-breakpoint
CREATE INDEX `fc_expires_idx` ON `fingerprint_cache` (`fc_expires_at`);