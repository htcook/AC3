CREATE TABLE `di_incident_training_data` (
	`id` int AUTO_INCREMENT NOT NULL,
	`example_id` varchar(64) NOT NULL,
	`scan_id` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`sector` varchar(128),
	`example_type` enum('incident_context','actor_attribution','breach_pattern','ransomware_profile','attack_surface_map') NOT NULL,
	`training_messages` json NOT NULL,
	`quality_score` double NOT NULL DEFAULT 0.5,
	`quality_band` enum('high','medium','low','rejected') NOT NULL DEFAULT 'medium',
	`analyst_rating` enum('accurate','partially_accurate','inaccurate','not_reviewed') NOT NULL DEFAULT 'not_reviewed',
	`analyst_notes` text,
	`analyst_id` int,
	`rated_at` bigint,
	`incident_count` int DEFAULT 0,
	`actors_discovered` int DEFAULT 0,
	`ttps_discovered` int DEFAULT 0,
	`risk_score_at_scan` int,
	`risk_band_at_scan` varchar(32),
	`used_in_prompt_count` int DEFAULT 0,
	`last_used_at` bigint,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `ditd_example_id_idx` ON `di_incident_training_data` (`example_id`);--> statement-breakpoint
CREATE INDEX `ditd_scan_id_idx` ON `di_incident_training_data` (`scan_id`);--> statement-breakpoint
CREATE INDEX `ditd_domain_idx` ON `di_incident_training_data` (`domain`);--> statement-breakpoint
CREATE INDEX `ditd_sector_idx` ON `di_incident_training_data` (`sector`);--> statement-breakpoint
CREATE INDEX `ditd_type_idx` ON `di_incident_training_data` (`example_type`);--> statement-breakpoint
CREATE INDEX `ditd_quality_idx` ON `di_incident_training_data` (`quality_band`);--> statement-breakpoint
CREATE INDEX `ditd_analyst_rating_idx` ON `di_incident_training_data` (`analyst_rating`);