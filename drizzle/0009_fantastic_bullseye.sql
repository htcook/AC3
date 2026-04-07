CREATE TABLE `zero_day_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve` varchar(32) NOT NULL,
	`vendor` varchar(128) NOT NULL DEFAULT '',
	`product` varchar(128) NOT NULL DEFAULT '',
	`vuln_type` varchar(128) NOT NULL DEFAULT '',
	`description` text NOT NULL,
	`date_discovered` varchar(32),
	`date_patched` varchar(32),
	`advisory_url` text,
	`analysis_url` text,
	`root_cause_analysis` text,
	`reported_by` varchar(512),
	`source` enum('project_zero','cisa_kev') NOT NULL DEFAULT 'project_zero',
	`year` int,
	`fetched_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `zero_day_scan_matches` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_id` int NOT NULL,
	`engagement_id` varchar(64),
	`domain` varchar(255) NOT NULL,
	`cve` varchar(32) NOT NULL,
	`vendor` varchar(128) NOT NULL DEFAULT '',
	`product` varchar(128) NOT NULL DEFAULT '',
	`match_type` enum('cve_exact','vendor_product','product_fuzzy') NOT NULL DEFAULT 'product_fuzzy',
	`confidence` enum('high','medium','low') NOT NULL DEFAULT 'low',
	`severity` enum('critical','high','medium') NOT NULL DEFAULT 'medium',
	`matched_asset` varchar(255) NOT NULL,
	`zero_day_description` text,
	`zero_day_type` varchar(128),
	`advisory_url` text,
	`dismissed` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `zdc_cve_idx` ON `zero_day_cache` (`cve`);--> statement-breakpoint
CREATE INDEX `zdc_vendor_idx` ON `zero_day_cache` (`vendor`);--> statement-breakpoint
CREATE INDEX `zdc_product_idx` ON `zero_day_cache` (`product`);--> statement-breakpoint
CREATE INDEX `zdc_year_idx` ON `zero_day_cache` (`year`);--> statement-breakpoint
CREATE INDEX `zdc_source_idx` ON `zero_day_cache` (`source`);--> statement-breakpoint
CREATE INDEX `zdsm_scan_id_idx` ON `zero_day_scan_matches` (`scan_id`);--> statement-breakpoint
CREATE INDEX `zdsm_engagement_id_idx` ON `zero_day_scan_matches` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `zdsm_domain_idx` ON `zero_day_scan_matches` (`domain`);--> statement-breakpoint
CREATE INDEX `zdsm_cve_idx` ON `zero_day_scan_matches` (`cve`);--> statement-breakpoint
CREATE INDEX `zdsm_severity_idx` ON `zero_day_scan_matches` (`severity`);--> statement-breakpoint
CREATE INDEX `zdsm_created_at_idx` ON `zero_day_scan_matches` (`created_at`);