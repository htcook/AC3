CREATE TABLE `connector_performance_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`connector` varchar(128) NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`scan_id` int NOT NULL,
	`observations` int NOT NULL DEFAULT 0,
	`duration_ms` int NOT NULL DEFAULT 0,
	`status` enum('completed','failed','skipped','timeout') NOT NULL DEFAULT 'completed',
	`rate_limited` tinyint NOT NULL DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `scan_graduation_scores` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`scan_id` int,
	`engagement_id` int,
	`pipeline_type` varchar(32) NOT NULL DEFAULT 'di_scan',
	`recon_analyst` int NOT NULL,
	`exploit_selector` int NOT NULL,
	`evasion_optimizer` int NOT NULL,
	`cognitive_core` int NOT NULL,
	`cloud_assessor` int NOT NULL,
	`supply_chain_analyst` int NOT NULL,
	`overall_score` int NOT NULL,
	`summary` text,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `cph_connector_domain_idx` ON `connector_performance_history` (`connector`,`domain`);--> statement-breakpoint
CREATE INDEX `cph_sector_idx` ON `connector_performance_history` (`sector`);--> statement-breakpoint
CREATE INDEX `cph_scan_id_idx` ON `connector_performance_history` (`scan_id`);--> statement-breakpoint
CREATE INDEX `cph_connector_sector_idx` ON `connector_performance_history` (`connector`,`sector`);--> statement-breakpoint
CREATE INDEX `cph_created_at_idx` ON `connector_performance_history` (`created_at`);--> statement-breakpoint
CREATE INDEX `sgs_domain_idx` ON `scan_graduation_scores` (`domain`);--> statement-breakpoint
CREATE INDEX `sgs_sector_idx` ON `scan_graduation_scores` (`sector`);--> statement-breakpoint
CREATE INDEX `sgs_scan_id_idx` ON `scan_graduation_scores` (`scan_id`);--> statement-breakpoint
CREATE INDEX `sgs_created_at_idx` ON `scan_graduation_scores` (`created_at`);