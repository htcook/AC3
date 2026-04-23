CREATE TABLE `approved_exploit_catalog` (
	`id` int AUTO_INCREMENT NOT NULL,
	`catalog_entry_id` varchar(128) NOT NULL,
	`quarantine_id` varchar(128) NOT NULL,
	`exploit_title` varchar(512) NOT NULL,
	`exploit_description` text,
	`exploit_code` text,
	`exploit_language` varchar(64),
	`exploit_platform` varchar(64),
	`exploit_service` varchar(128),
	`exploit_cve_ids` json,
	`exploit_tags` json,
	`exploit_source` varchar(32) NOT NULL DEFAULT 'ac3_history',
	`reliability_score` int DEFAULT 90,
	`approved_by` varchar(255) NOT NULL,
	`approval_notes` text,
	`source_pipeline` varchar(128) NOT NULL,
	`original_engagement_id` int,
	`approved_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_quarantine_queue` (
	`id` int AUTO_INCREMENT NOT NULL,
	`quarantine_id` varchar(128) NOT NULL,
	`exploit_title` varchar(512) NOT NULL,
	`exploit_description` text,
	`exploit_code` text,
	`exploit_language` varchar(64),
	`exploit_platform` varchar(64),
	`exploit_service` varchar(128),
	`exploit_cve_ids` json,
	`exploit_tags` json,
	`exploit_source` varchar(32) NOT NULL,
	`submitted_by` varchar(255) NOT NULL,
	`source_pipeline` varchar(128) NOT NULL,
	`status` enum('pending_review','approved','rejected') NOT NULL DEFAULT 'pending_review',
	`engagement_id` int,
	`meta_cve_id` varchar(32),
	`meta_success` tinyint NOT NULL DEFAULT 1,
	`reviewed_at` timestamp,
	`reviewed_by` varchar(255),
	`review_notes` text,
	`quarantined_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE TABLE `exploit_selection_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`snapshot_id` varchar(128) NOT NULL,
	`engagement_id` int NOT NULL,
	`selection_event` varchar(255) NOT NULL,
	`catalog_state_hash` varchar(128) NOT NULL,
	`catalog_entry_count` int NOT NULL,
	`selected_exploit_ids` json,
	`rag_query_used` text,
	`rag_result_count` int,
	`rag_result_ids` json,
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `aec_catalog_entry_id_unique` ON `approved_exploit_catalog` (`catalog_entry_id`);--> statement-breakpoint
CREATE INDEX `aec_quarantine_id_idx` ON `approved_exploit_catalog` (`quarantine_id`);--> statement-breakpoint
CREATE INDEX `eqq_quarantine_id_unique` ON `exploit_quarantine_queue` (`quarantine_id`);--> statement-breakpoint
CREATE INDEX `eqq_status_idx` ON `exploit_quarantine_queue` (`status`);--> statement-breakpoint
CREATE INDEX `eqq_engagement_idx` ON `exploit_quarantine_queue` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ess_snapshot_id_unique` ON `exploit_selection_snapshots` (`snapshot_id`);--> statement-breakpoint
CREATE INDEX `ess_engagement_idx` ON `exploit_selection_snapshots` (`engagement_id`);