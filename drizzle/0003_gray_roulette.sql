CREATE TABLE `vuln_scan_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`snapshot_type` enum('passive','active','llm_synthesis','full_pipeline','resynthesis') NOT NULL,
	`total_assets` int NOT NULL DEFAULT 0,
	`total_vulns` int NOT NULL DEFAULT 0,
	`critical_count` int NOT NULL DEFAULT 0,
	`high_count` int NOT NULL DEFAULT 0,
	`medium_count` int NOT NULL DEFAULT 0,
	`low_count` int NOT NULL DEFAULT 0,
	`total_ports` int NOT NULL DEFAULT 0,
	`total_exploits` int NOT NULL DEFAULT 0,
	`avg_confidence` int DEFAULT 0,
	`new_vulns_found` int DEFAULT 0,
	`resolved_vulns` int DEFAULT 0,
	`categories` json,
	`asset_breakdown` json,
	`metadata` json,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vuln_trend_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`snapshot_id` int NOT NULL,
	`engagement_id` int NOT NULL,
	`hostname` varchar(255) NOT NULL,
	`vuln_title` varchar(512) NOT NULL,
	`severity` varchar(32) NOT NULL,
	`category` varchar(128),
	`confidence` int,
	`cve` varchar(64),
	`tool` varchar(64),
	`status` enum('new','existing','resolved','regressed') NOT NULL DEFAULT 'new',
	`first_seen_snapshot_id` int,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `vuln_snap_engagement_idx` ON `vuln_scan_snapshots` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `vuln_snap_created_idx` ON `vuln_scan_snapshots` (`created_at`);--> statement-breakpoint
CREATE INDEX `vuln_trend_engagement_idx` ON `vuln_trend_entries` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `vuln_trend_snapshot_idx` ON `vuln_trend_entries` (`snapshot_id`);--> statement-breakpoint
CREATE INDEX `vuln_trend_hostname_idx` ON `vuln_trend_entries` (`hostname`);